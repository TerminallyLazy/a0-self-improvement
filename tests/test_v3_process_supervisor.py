from __future__ import annotations

from pathlib import Path
import signal

import pytest

from usr.plugins.dspy_rlm.helpers.v3.process_supervisor import (
    AuthoritySnapshot,
    LaunchContract,
    LaunchRequest,
    ObservedProcess,
    PROCESS_NONCE_ENV,
    ProcessIdentity,
    ProcessSupervisor,
    StagedOutput,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class FakeInspector:
    def __init__(self) -> None:
        self.processes: dict[int, ObservedProcess] = {}

    def inspect(self, pid: int) -> ObservedProcess | None:
        return self.processes.get(pid)

    def group_members(self, process_group_id: int) -> tuple[ObservedProcess, ...]:
        return tuple(
            process
            for process in self.processes.values()
            if process.process_group_id == process_group_id
        )


class FakeHandle:
    pid = 4101

    def __init__(self, inspector: FakeInspector, *, clean_exit: bool) -> None:
        self.inspector = inspector
        self.clean_exit = clean_exit
        self.exit_code: int | None = None

    def poll(self) -> int | None:
        if self.clean_exit and self.exit_code is None:
            self.exit_code = 0
            self.inspector.processes.clear()
        return self.exit_code


class FakeLauncher:
    def __init__(self, inspector: FakeInspector, *, clean_exit: bool = False) -> None:
        self.inspector = inspector
        self.handle = FakeHandle(inspector, clean_exit=clean_exit)
        self.contract: LaunchContract | None = None

    def launch(self, contract: LaunchContract) -> FakeHandle:
        self.contract = contract
        nonce = contract.environment[PROCESS_NONCE_ENV]
        self.inspector.processes[self.handle.pid] = ObservedProcess(
            pid=self.handle.pid,
            process_group_id=self.handle.pid,
            session_id=self.handle.pid,
            start_identity="boot-a:9921",
            process_nonce=nonce,
        )
        assert contract.stdin_handle.read() == b"frozen invocation"
        contract.stdout_handle.write(b"untrusted candidate bytes")
        contract.stdout_handle.flush()
        return self.handle


class FakeSignals:
    def __init__(
        self,
        inspector: FakeInspector,
        handle: FakeHandle | None = None,
        *,
        stubborn: bool = False,
    ) -> None:
        self.inspector = inspector
        self.handle = handle
        self.stubborn = stubborn
        self.sent: list[int] = []

    def send_group(self, process_group_id: int, signal_number: int) -> None:
        self.sent.append(signal_number)
        if signal_number == signal.SIGTERM and self.stubborn:
            return
        self.inspector.processes = {
            pid: process
            for pid, process in self.inspector.processes.items()
            if process.process_group_id != process_group_id
        }
        if self.handle is not None:
            self.handle.exit_code = -signal_number


def _request(tmp_path: Path) -> LaunchRequest:
    stdin_path = tmp_path / "attempt.input"
    stdin_path.write_bytes(b"frozen invocation")
    return LaunchRequest(
        command=("/worker/python", "-m", "isolated_worker"),
        cwd=tmp_path,
        environment={"PATH": "/worker/bin"},
        stdin_path=stdin_path,
        stdout_staging_path=tmp_path / "attempt.output",
    )


def _supervisor(
    launcher: FakeLauncher,
    inspector: FakeInspector,
    signals: FakeSignals,
    clock: FakeClock,
) -> ProcessSupervisor:
    return ProcessSupervisor(
        launcher=launcher,
        inspector=inspector,
        signal_adapter=signals,
        clock=clock,
        nonce_factory=lambda: "attempt_nonce_0001",
        poll_interval=0.1,
        term_grace=0.2,
        kill_grace=0.2,
        identity_capture_timeout=0.2,
    )


def test_clean_exit_reports_exact_process_and_bounded_launch_contract(tmp_path: Path) -> None:
    inspector = FakeInspector()
    launcher = FakeLauncher(inspector, clean_exit=True)
    supervisor = _supervisor(launcher, inspector, FakeSignals(inspector), FakeClock())

    result = supervisor.run(
        _request(tmp_path),
        lambda _identity: AuthoritySnapshot(deadline_monotonic=10.0),
    )

    assert result.exit_code == 0
    assert result.stop_reason is None
    assert result.process_absent and result.process_group_absent
    assert result.identity.pid == result.identity.process_group_id == result.identity.session_id
    assert result.identity.process_nonce == "attempt_nonce_0001"
    assert launcher.contract is not None
    assert dict(launcher.contract.environment) == {
        "PATH": "/worker/bin",
        PROCESS_NONCE_ENV: "attempt_nonce_0001",
    }
    assert launcher.contract.start_new_session and launcher.contract.close_fds


def test_authority_loss_terms_exact_group_and_discards_staging(tmp_path: Path) -> None:
    inspector = FakeInspector()
    launcher = FakeLauncher(inspector)
    signals = FakeSignals(inspector, launcher.handle)
    supervisor = _supervisor(launcher, inspector, signals, FakeClock())
    request = _request(tmp_path)

    result = supervisor.run(
        request,
        lambda _identity: AuthoritySnapshot(
            deadline_monotonic=10.0, cancellation_requested=True
        ),
    )

    assert result.stop_reason == "cancellation_requested"
    assert signals.sent == [signal.SIGTERM]
    assert result.cleanup is not None
    assert result.cleanup.identity_matched
    assert result.cleanup.term_sent and not result.cleanup.kill_sent
    assert result.cleanup.process_absent and result.cleanup.process_group_absent
    assert result.staged_output.discarded and not request.stdout_staging_path.exists()


def test_stubborn_group_is_killed_after_bounded_term_grace(tmp_path: Path) -> None:
    inspector = FakeInspector()
    launcher = FakeLauncher(inspector)
    clock = FakeClock()
    signals = FakeSignals(inspector, launcher.handle, stubborn=True)
    supervisor = _supervisor(launcher, inspector, signals, clock)

    result = supervisor.run(
        _request(tmp_path),
        lambda _identity: AuthoritySnapshot(deadline_monotonic=0.0),
    )

    assert signals.sent == [signal.SIGTERM, signal.SIGKILL]
    assert clock.now == pytest.approx(0.2)
    assert result.cleanup is not None and result.cleanup.kill_sent
    assert result.cleanup.process_group_absent


def test_identity_mismatch_blocks_unsafe_signal(tmp_path: Path) -> None:
    inspector = FakeInspector()
    stored = ProcessIdentity(4101, 4101, 4101, "boot-a:9921", "attempt_nonce_0001")
    inspector.processes[4101] = ObservedProcess(
        4101, 4101, 4101, "boot-a:DIFFERENT", "attempt_nonce_0001"
    )
    staging = tmp_path / "orphan.output"
    staging.write_bytes(b"untrusted")
    signals = FakeSignals(inspector)
    supervisor = ProcessSupervisor(
        launcher=FakeLauncher(inspector),
        inspector=inspector,
        signal_adapter=signals,
        clock=FakeClock(),
        nonce_factory=lambda: "attempt_nonce_0001",
    )

    report = supervisor.cleanup_orphan(stored, staging)

    assert not report.identity_matched
    assert report.unsafe_signal_blocked
    assert signals.sent == []
    assert not report.process_group_absent
    assert report.output_discarded and report.staging_removed


def test_orphan_cleanup_uses_stored_identity_without_domain_writes(tmp_path: Path) -> None:
    inspector = FakeInspector()
    stored = ProcessIdentity(4101, 4101, 4101, "boot-a:9921", "attempt_nonce_0001")
    inspector.processes[4101] = ObservedProcess(
        4101, 4101, 4101, "boot-a:9921", "attempt_nonce_0001"
    )
    staging = tmp_path / "orphan.output"
    staging.write_bytes(b"untrusted")
    signals = FakeSignals(inspector)
    supervisor = ProcessSupervisor(
        launcher=FakeLauncher(inspector),
        inspector=inspector,
        signal_adapter=signals,
        clock=FakeClock(),
        nonce_factory=lambda: "attempt_nonce_0001",
    )

    report = supervisor.cleanup_orphan(stored, staging)

    assert report.identity_matched
    assert report.term_sent and not report.kill_sent
    assert report.process_absent and report.process_group_absent
    assert signals.sent == [signal.SIGTERM]


def test_staged_output_can_never_be_marked_authoritative(tmp_path: Path) -> None:
    staged = StagedOutput(path=tmp_path / "attempt.output", discarded=False)

    assert staged.authoritative is False
    with pytest.raises((AttributeError, TypeError)):
        staged.authoritative = True  # type: ignore[misc]
