"""Killable child-process supervision for isolated v3 work attempts.

The supervisor is intentionally outside every persistence and publication
boundary.  It launches a child with only explicit byte-stream handles, watches
an injected authority snapshot, and returns facts about the process and its
staging output.  Callers must not interpret a staged result as authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time
from typing import BinaryIO, Callable, Mapping, Protocol, Sequence


PROCESS_NONCE_ENV = "A0_V3_PROCESS_NONCE"
MAX_ENVIRONMENT_ITEMS = 32
MAX_ENVIRONMENT_BYTES = 16 * 1024
MAX_ENVIRONMENT_VALUE_BYTES = 4 * 1024
_ENVIRONMENT_KEY = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")


class ProcessSupervisionError(RuntimeError):
    """Raised when an attempt cannot be supervised safely."""


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """Stable identity recorded with a lease for later orphan cleanup."""

    pid: int
    process_group_id: int
    session_id: int
    start_identity: str
    process_nonce: str


@dataclass(frozen=True, slots=True)
class ObservedProcess:
    pid: int
    process_group_id: int
    session_id: int
    start_identity: str
    process_nonce: str | None


@dataclass(frozen=True, slots=True)
class AuthoritySnapshot:
    """All parent-side authorities that must remain live for an attempt."""

    deadline_monotonic: float
    cancellation_requested: bool = False
    lease_valid: bool = True
    fence_valid: bool = True
    dependency_valid: bool = True
    grant_valid: bool = True
    budget_valid: bool = True

    def loss_reason(self, now_monotonic: float) -> str | None:
        if now_monotonic >= self.deadline_monotonic:
            return "deadline_expired"
        if self.cancellation_requested:
            return "cancellation_requested"
        for valid, reason in (
            (self.lease_valid, "lease_lost"),
            (self.fence_valid, "fence_lost"),
            (self.dependency_valid, "dependency_lost"),
            (self.grant_valid, "grant_lost"),
            (self.budget_valid, "budget_lost"),
        ):
            if not valid:
                return reason
        return None


@dataclass(frozen=True, slots=True)
class LaunchRequest:
    command: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    stdin_path: Path
    stdout_staging_path: Path


@dataclass(frozen=True, slots=True)
class LaunchContract:
    request: LaunchRequest
    environment: Mapping[str, str]
    stdin_handle: BinaryIO
    stdout_handle: BinaryIO
    start_new_session: bool = True
    close_fds: bool = True


@dataclass(frozen=True, slots=True)
class StagedOutput:
    path: Path
    discarded: bool

    @property
    def authoritative(self) -> bool:
        """Staging bytes never carry domain authority."""

        return False


@dataclass(frozen=True, slots=True)
class CleanupReport:
    """Facts only; this report never decides retry, publication, or terminal state."""

    identity_matched: bool
    process_absent: bool
    process_group_absent: bool
    term_sent: bool
    kill_sent: bool
    unsafe_signal_blocked: bool
    output_discarded: bool
    staging_removed: bool
    observation_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SupervisionResult:
    identity: ProcessIdentity
    exit_code: int | None
    stop_reason: str | None
    process_absent: bool
    process_group_absent: bool
    staged_output: StagedOutput
    cleanup: CleanupReport | None


class ProcessHandle(Protocol):
    pid: int

    def poll(self) -> int | None: ...


class ProcessLauncher(Protocol):
    def launch(self, contract: LaunchContract) -> ProcessHandle: ...


class ProcessInspector(Protocol):
    def inspect(self, pid: int) -> ObservedProcess | None: ...

    def group_members(self, process_group_id: int) -> tuple[ObservedProcess, ...]: ...


class SignalAdapter(Protocol):
    def send_group(self, process_group_id: int, signal_number: int) -> None: ...


class Clock(Protocol):
    def monotonic(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


AuthorityProbe = Callable[[ProcessIdentity], AuthoritySnapshot]
NonceFactory = Callable[[], str]


class SubprocessLauncher:
    """Production launcher: no inherited descriptors or ambient environment."""

    def launch(self, contract: LaunchContract) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            contract.request.command,
            cwd=str(contract.request.cwd),
            env=dict(contract.environment),
            stdin=contract.stdin_handle,
            stdout=contract.stdout_handle,
            stderr=subprocess.STDOUT,
            start_new_session=contract.start_new_session,
            close_fds=contract.close_fds,
        )


class PosixSignalAdapter:
    def send_group(self, process_group_id: int, signal_number: int) -> None:
        os.killpg(process_group_id, signal_number)


class SystemClock:
    monotonic = staticmethod(time.monotonic)
    sleep = staticmethod(time.sleep)


class LinuxProcInspector:
    """Read Linux process start identity, group, session, and attempt nonce."""

    def __init__(self, proc_root: Path = Path("/proc")) -> None:
        if sys.platform != "linux" and proc_root == Path("/proc"):
            raise ProcessSupervisionError("Linux /proc process inspection is unavailable")
        self._proc_root = proc_root
        try:
            self._boot_id = (proc_root / "sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()
        except OSError as exc:
            raise ProcessSupervisionError("Linux boot identity is unavailable") from exc

    def inspect(self, pid: int) -> ObservedProcess | None:
        if pid <= 0:
            return None
        process_root = self._proc_root / str(pid)
        try:
            stat_text = (process_root / "stat").read_text(encoding="ascii")
            fields = stat_text[stat_text.rfind(")") + 2 :].split()
            process_group_id = int(fields[2])
            session_id = int(fields[3])
            start_ticks = fields[19]
            environment = (process_root / "environ").read_bytes().split(b"\0")
        except (FileNotFoundError, ProcessLookupError):
            return None
        except (IndexError, OSError, UnicodeError, ValueError) as exc:
            raise ProcessSupervisionError(f"cannot inspect process {pid}") from exc

        nonce_prefix = f"{PROCESS_NONCE_ENV}=".encode("ascii")
        nonce: str | None = None
        for entry in environment:
            if entry.startswith(nonce_prefix):
                try:
                    nonce = entry[len(nonce_prefix) :].decode("ascii")
                except UnicodeError:
                    nonce = None
                break
        return ObservedProcess(
            pid=pid,
            process_group_id=process_group_id,
            session_id=session_id,
            start_identity=f"{self._boot_id}:{start_ticks}",
            process_nonce=nonce,
        )

    def group_members(self, process_group_id: int) -> tuple[ObservedProcess, ...]:
        members: list[ObservedProcess] = []
        try:
            candidates = self._proc_root.iterdir()
        except OSError as exc:
            raise ProcessSupervisionError("cannot enumerate Linux processes") from exc
        for candidate in candidates:
            if not candidate.name.isdigit():
                continue
            observed = self.inspect(int(candidate.name))
            if observed is not None and observed.process_group_id == process_group_id:
                members.append(observed)
        return tuple(sorted(members, key=lambda item: item.pid))


class ProcessSupervisor:
    """Run one child and revoke its exact process group on authority loss."""

    def __init__(
        self,
        *,
        launcher: ProcessLauncher | None = None,
        inspector: ProcessInspector | None = None,
        signal_adapter: SignalAdapter | None = None,
        clock: Clock | None = None,
        nonce_factory: NonceFactory | None = None,
        poll_interval: float = 0.05,
        term_grace: float = 1.0,
        kill_grace: float = 1.0,
        identity_capture_timeout: float = 1.0,
    ) -> None:
        self._launcher = launcher or SubprocessLauncher()
        self._inspector = inspector or LinuxProcInspector()
        self._signals = signal_adapter or PosixSignalAdapter()
        self._clock = clock or SystemClock()
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(16))
        for name, value in (
            ("poll_interval", poll_interval),
            ("term_grace", term_grace),
            ("kill_grace", kill_grace),
            ("identity_capture_timeout", identity_capture_timeout),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        self._poll_interval = poll_interval
        self._term_grace = term_grace
        self._kill_grace = kill_grace
        self._identity_capture_timeout = identity_capture_timeout

    def run(self, request: LaunchRequest, authority_probe: AuthorityProbe) -> SupervisionResult:
        """Launch and watch one attempt; returned output is staging only."""

        environment = _bounded_environment(request.environment)
        nonce = self._nonce_factory()
        _validate_nonce(nonce)
        environment[PROCESS_NONCE_ENV] = nonce
        handle = self._launch(request, environment)
        identity = self._capture_identity(handle, nonce, request.stdout_staging_path)

        while True:
            exit_code = handle.poll()
            if exit_code is not None:
                process_absent, group_absent = self._absence(identity)
                return SupervisionResult(
                    identity=identity,
                    exit_code=exit_code,
                    stop_reason=None,
                    process_absent=process_absent,
                    process_group_absent=group_absent,
                    staged_output=StagedOutput(request.stdout_staging_path, discarded=False),
                    cleanup=None,
                )

            try:
                snapshot = authority_probe(identity)
                if not isinstance(snapshot, AuthoritySnapshot):
                    raise TypeError("authority probe returned an invalid snapshot")
                stop_reason = snapshot.loss_reason(self._clock.monotonic())
            except Exception:
                stop_reason = "authority_probe_unavailable"

            if stop_reason is not None:
                cleanup = self._cleanup(identity, request.stdout_staging_path, handle=handle)
                return SupervisionResult(
                    identity=identity,
                    exit_code=handle.poll(),
                    stop_reason=stop_reason,
                    process_absent=cleanup.process_absent,
                    process_group_absent=cleanup.process_group_absent,
                    staged_output=StagedOutput(request.stdout_staging_path, discarded=True),
                    cleanup=cleanup,
                )
            self._clock.sleep(self._poll_interval)

    def cleanup_orphan(
        self,
        stored_identity: ProcessIdentity,
        stdout_staging_path: Path,
    ) -> CleanupReport:
        """Perform only phase-two process/staging cleanup for a stored lease identity."""

        return self._cleanup(stored_identity, stdout_staging_path)

    def _launch(self, request: LaunchRequest, environment: Mapping[str, str]) -> ProcessHandle:
        if not request.command or not all(isinstance(part, str) and part for part in request.command):
            raise ProcessSupervisionError("command must contain non-empty strings")
        if not Path(request.command[0]).is_absolute():
            raise ProcessSupervisionError("worker executable path must be absolute")
        if not request.cwd.is_dir():
            raise ProcessSupervisionError("working directory does not exist")
        stdout_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            stdout_flags |= os.O_NOFOLLOW
        stdin_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            stdin_flags |= os.O_NOFOLLOW
        try:
            stdin_fd = os.open(request.stdin_path, stdin_flags)
            try:
                stdout_fd = os.open(request.stdout_staging_path, stdout_flags, 0o600)
            except Exception:
                os.close(stdin_fd)
                raise
            with os.fdopen(stdin_fd, "rb", closefd=True) as stdin_handle, os.fdopen(
                stdout_fd, "wb", closefd=True
            ) as stdout_handle:
                return self._launcher.launch(
                    LaunchContract(
                        request=request,
                        environment=environment,
                        stdin_handle=stdin_handle,
                        stdout_handle=stdout_handle,
                    )
                )
        except (OSError, subprocess.SubprocessError) as exc:
            _discard_staging(request.stdout_staging_path)
            raise ProcessSupervisionError("child launch failed") from exc

    def _capture_identity(
        self,
        handle: ProcessHandle,
        nonce: str,
        stdout_staging_path: Path,
    ) -> ProcessIdentity:
        deadline = self._clock.monotonic() + self._identity_capture_timeout
        while self._clock.monotonic() < deadline:
            observed = self._inspector.inspect(handle.pid)
            if observed is not None:
                if (
                    observed.pid != handle.pid
                    or observed.process_group_id != handle.pid
                    or observed.session_id != handle.pid
                    or observed.process_nonce != nonce
                ):
                    _discard_staging(stdout_staging_path)
                    raise ProcessSupervisionError("launched child identity contract mismatch")
                return ProcessIdentity(
                    pid=observed.pid,
                    process_group_id=observed.process_group_id,
                    session_id=observed.session_id,
                    start_identity=observed.start_identity,
                    process_nonce=nonce,
                )
            if handle.poll() is not None:
                break
            self._clock.sleep(self._poll_interval)
        _discard_staging(stdout_staging_path)
        raise ProcessSupervisionError("unable to capture launched child identity")

    def _cleanup(
        self,
        identity: ProcessIdentity,
        staging_path: Path,
        *,
        handle: ProcessHandle | None = None,
    ) -> CleanupReport:
        codes: list[str] = []
        term_sent = False
        kill_sent = False
        unsafe_signal_blocked = False

        process_observed, observed = self._safe_inspect(identity.pid, codes)
        group_observed, members = self._safe_group_members(identity.process_group_id, codes)
        identity_matched = (
            process_observed
            and observed is not None
            and _identity_matches(identity, observed)
        )
        if not process_observed or not group_observed:
            unsafe_signal_blocked = True
        elif members and not (identity_matched and _members_match_nonce(identity, members)):
            unsafe_signal_blocked = True
            codes.append("identity_unverified")
        elif members:
            term_sent = self._send(identity.process_group_id, signal.SIGTERM, codes)
            members = self._wait_for_group(
                identity.process_group_id, self._term_grace, codes, handle=handle
            )
            if members:
                if _members_match_nonce(identity, members):
                    kill_sent = self._send(identity.process_group_id, signal.SIGKILL, codes)
                    members = self._wait_for_group(
                        identity.process_group_id, self._kill_grace, codes, handle=handle
                    )
                else:
                    unsafe_signal_blocked = True
                    codes.append("post_term_identity_unverified")

        final_process_observed, final_process = self._safe_inspect(identity.pid, codes)
        final_group_observed, final_members = self._safe_group_members(
            identity.process_group_id, codes
        )
        staging_removed = _discard_staging(staging_path)
        return CleanupReport(
            identity_matched=identity_matched,
            process_absent=final_process_observed and final_process is None,
            process_group_absent=final_group_observed and not final_members,
            term_sent=term_sent,
            kill_sent=kill_sent,
            unsafe_signal_blocked=unsafe_signal_blocked,
            output_discarded=True,
            staging_removed=staging_removed,
            observation_codes=tuple(codes),
        )

    def _wait_for_group(
        self,
        process_group_id: int,
        grace: float,
        codes: list[str],
        *,
        handle: ProcessHandle | None,
    ) -> tuple[ObservedProcess, ...]:
        deadline = self._clock.monotonic() + grace
        if handle is not None:
            handle.poll()
        available, members = self._safe_group_members(process_group_id, codes)
        if not available:
            return ()
        while members and self._clock.monotonic() < deadline:
            self._clock.sleep(min(self._poll_interval, deadline - self._clock.monotonic()))
            if handle is not None:
                handle.poll()
            available, members = self._safe_group_members(process_group_id, codes)
            if not available:
                return members
        return members

    def _absence(self, identity: ProcessIdentity) -> tuple[bool, bool]:
        codes: list[str] = []
        process_observed, process = self._safe_inspect(identity.pid, codes)
        group_observed, members = self._safe_group_members(identity.process_group_id, codes)
        return (
            process_observed and process is None,
            group_observed and not members,
        )

    def _safe_inspect(
        self, pid: int, codes: list[str]
    ) -> tuple[bool, ObservedProcess | None]:
        try:
            return True, self._inspector.inspect(pid)
        except Exception:
            codes.append("process_inspection_unavailable")
            return False, None

    def _safe_group_members(
        self, process_group_id: int, codes: list[str]
    ) -> tuple[bool, tuple[ObservedProcess, ...]]:
        try:
            return True, self._inspector.group_members(process_group_id)
        except Exception:
            codes.append("group_inspection_unavailable")
            return False, ()

    def _send(self, process_group_id: int, signal_number: int, codes: list[str]) -> bool:
        try:
            self._signals.send_group(process_group_id, signal_number)
            return True
        except ProcessLookupError:
            codes.append("process_group_already_absent")
        except Exception:
            codes.append("signal_failed")
        return False


def _bounded_environment(environment: Mapping[str, str]) -> dict[str, str]:
    if len(environment) > MAX_ENVIRONMENT_ITEMS:
        raise ProcessSupervisionError("environment contains too many entries")
    bounded: dict[str, str] = {}
    byte_count = 0
    for key, value in environment.items():
        if not isinstance(key, str) or not _ENVIRONMENT_KEY.fullmatch(key):
            raise ProcessSupervisionError("environment contains an invalid key")
        if key == PROCESS_NONCE_ENV:
            raise ProcessSupervisionError("process nonce is supervisor-owned")
        if not isinstance(value, str) or "\x00" in value:
            raise ProcessSupervisionError("environment contains an invalid value")
        value_bytes = value.encode("utf-8")
        if len(value_bytes) > MAX_ENVIRONMENT_VALUE_BYTES:
            raise ProcessSupervisionError("environment value is too large")
        byte_count += len(key.encode("ascii")) + len(value_bytes) + 2
        if byte_count > MAX_ENVIRONMENT_BYTES:
            raise ProcessSupervisionError("environment is too large")
        bounded[key] = value
    return bounded


def _validate_nonce(nonce: str) -> None:
    if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):
        raise ProcessSupervisionError("nonce factory returned an invalid process nonce")


def _identity_matches(expected: ProcessIdentity, observed: ObservedProcess) -> bool:
    return (
        observed.pid == expected.pid
        and observed.process_group_id == expected.process_group_id
        and observed.session_id == expected.session_id
        and observed.start_identity == expected.start_identity
        and observed.process_nonce == expected.process_nonce
    )


def _members_match_nonce(
    expected: ProcessIdentity, members: Sequence[ObservedProcess]
) -> bool:
    return bool(members) and all(
        member.process_group_id == expected.process_group_id
        and member.session_id == expected.session_id
        and member.process_nonce == expected.process_nonce
        for member in members
    )


def _discard_staging(path: Path) -> bool:
    try:
        path.unlink()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True
