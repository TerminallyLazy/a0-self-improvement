from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from pathlib import Path
import sys
from types import ModuleType

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def _namespace(name: str) -> ModuleType:
    module = sys.modules.get(name)
    if module is None:
        module = ModuleType(name)
        module.__path__ = []  # type: ignore[attr-defined]
        sys.modules[name] = module
    return module


def _install_standalone_plugin_namespace() -> bool:
    """Expose this checkout under Agent Zero's runtime plugin import name."""
    if PLUGIN_ROOT.parts[-3:] == ("usr", "plugins", "dspy_rlm"):
        repository_root = PLUGIN_ROOT.parents[2]
        if str(repository_root) not in sys.path:
            sys.path.insert(0, str(repository_root))
        return False

    usr = _namespace("usr")
    plugins = _namespace("usr.plugins")
    setattr(usr, "plugins", plugins)

    package_name = "usr.plugins.dspy_rlm"
    if package_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            package_name,
            PLUGIN_ROOT / "__init__.py",
            submodule_search_locations=[str(PLUGIN_ROOT)],
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("Unable to create standalone plugin import spec")
        plugin = importlib.util.module_from_spec(spec)
        sys.modules[package_name] = plugin
        setattr(plugins, "dspy_rlm", plugin)
        spec.loader.exec_module(plugin)
    return True


def _install_framework_contract_stubs() -> None:
    """Provide only the pinned Agent Zero import contracts used by unit tests."""
    import yaml as pyyaml

    helpers = ModuleType("helpers")
    helpers.__path__ = []  # type: ignore[attr-defined]
    sys.modules["helpers"] = helpers

    api = ModuleType("helpers.api")

    class ApiHandler:
        def __init__(self, app: object, thread_lock: object) -> None:
            self.app = app
            self.thread_lock = thread_lock

        @classmethod
        def requires_auth(cls) -> bool:
            return True

        @classmethod
        def requires_csrf(cls) -> bool:
            return cls.requires_auth()

        @classmethod
        def get_methods(cls) -> list[str]:
            return ["POST"]

    class Request:
        pass

    class Response:
        def __init__(
            self,
            response: object = None,
            *,
            status: int = 200,
            mimetype: str | None = None,
        ) -> None:
            self.response = response
            self.status = status
            self.mimetype = mimetype

    api.ApiHandler = ApiHandler
    api.Request = Request
    api.Response = Response
    sys.modules["helpers.api"] = api
    setattr(helpers, "api", api)

    extension = ModuleType("helpers.extension")

    class Extension:
        def __init__(self, agent: object = None, **kwargs: object) -> None:
            self.agent = agent

    extension.Extension = Extension
    sys.modules["helpers.extension"] = extension
    setattr(helpers, "extension", extension)

    print_style = ModuleType("helpers.print_style")

    class PrintStyle:
        debug = staticmethod(lambda *_args, **_kwargs: None)
        error = staticmethod(lambda *_args, **_kwargs: None)

    print_style.PrintStyle = PrintStyle
    sys.modules["helpers.print_style"] = print_style
    setattr(helpers, "print_style", print_style)

    tool = ModuleType("helpers.tool")

    @dataclass
    class ToolResponse:
        message: str
        break_loop: bool
        additional: dict[str, object] | None = None

    tool.Response = ToolResponse
    sys.modules["helpers.tool"] = tool
    setattr(helpers, "tool", tool)

    yaml = ModuleType("helpers.yaml")
    yaml.loads = pyyaml.safe_load
    yaml.dumps = pyyaml.safe_dump
    sys.modules["helpers.yaml"] = yaml
    setattr(helpers, "yaml", yaml)

    if "agent" not in sys.modules:
        agent = ModuleType("agent")

        class AgentContext:
            @staticmethod
            def get(_context_id: str) -> None:
                return None

        agent.AgentContext = AgentContext
        sys.modules["agent"] = agent


if _install_standalone_plugin_namespace():
    _install_framework_contract_stubs()


@pytest.fixture
def isolated_plugin_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Keep plugin-path globals and future state/config caches isolated per test."""
    import usr.plugins.dspy_rlm.helpers.paths as paths
    import usr.plugins.dspy_rlm.helpers.state as state

    state_dir = tmp_path / "state"
    monkeypatch.setattr(paths, "PLUGIN_ROOT", tmp_path)
    monkeypatch.setattr(paths, "STATE_DIR", state_dir)
    monkeypatch.setattr(paths, "SAFE_STORE_FILE", state_dir / "dspy_rlm_v3.sqlite")
    monkeypatch.setattr(paths, "SAFE_GENERATIONS_DIR", state_dir / "safe-generations")
    monkeypatch.setattr(paths, "STORE_AUTHORITY_MANIFEST_FILE", state_dir / "store-authority-manifest.json")
    monkeypatch.setattr(paths, "STORE_AUTHORITY_LOCK_FILE", state_dir / "store-authority-manifest.lock")
    monkeypatch.setattr(paths, "AUTHORITY_DIR", state_dir / "authority")
    monkeypatch.setattr(paths, "AUTHORITY_SECRET_FILE", state_dir / "authority" / "issuer-root.secret")
    monkeypatch.setattr(paths, "AUTHORITY_PROFILE_FILE", state_dir / "authority" / "issuer-profile.json")
    monkeypatch.setattr(paths, "AUTHORITY_REVOCATIONS_DIR", state_dir / "authority" / "revocations")
    monkeypatch.setattr(paths, "MIGRATION_DIR", state_dir / "migration")
    monkeypatch.setattr(paths, "MIGRATION_AUTHORITY_FILE", state_dir / "migration" / "migration-authority.sqlite")
    monkeypatch.setattr(paths, "MIGRATION_LOCK_FILE", state_dir / "migration" / "migration.lock")
    monkeypatch.setattr(paths, "QUARANTINES_DIR", state_dir / "migration" / "quarantines")
    monkeypatch.setattr(paths, "QUARANTINE_KEYWRAPS_DIR", state_dir / "migration" / "keywraps")
    monkeypatch.setattr(paths, "TRACE_FILE", state_dir / "traces.jsonl")
    monkeypatch.setattr(paths, "STATE_FILE", state_dir / "runtime_state.json")
    monkeypatch.setattr(paths, "COMPILED_STATE_FILE", state_dir / "compiled_guidance.json")
    monkeypatch.setattr(state, "STATE_FILE", state_dir / "runtime_state.json")
    monkeypatch.setattr(state, "COMPILED_STATE_FILE", state_dir / "compiled_guidance.json")
    return tmp_path
