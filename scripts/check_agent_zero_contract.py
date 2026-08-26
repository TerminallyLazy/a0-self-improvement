#!/usr/bin/env python3
"""Verify pinned Agent Zero plugin seams by parsing source without importing it."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
from typing import Iterable, Sequence


PINNED_AGENT_ZERO_COMMIT = "b22a144bf59f15b1516084c9e7b88133ba92c8a9"


class ContractError(RuntimeError):
    """Raised when pinned source no longer exposes a required plugin seam."""


@dataclass(frozen=True)
class SourceTree:
    root: Path

    def parse(self, relative_path: str) -> ast.Module:
        path = self.root / relative_path
        if not path.is_file():
            raise ContractError(f"missing required source file: {relative_path}")
        try:
            return ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)
        except (OSError, SyntaxError, UnicodeError) as exc:
            raise ContractError(f"cannot parse {relative_path}: {exc}") from exc


def _named_node(tree: ast.Module | ast.ClassDef, name: str, kinds: tuple[type[ast.AST], ...]) -> ast.AST:
    for node in tree.body:
        if isinstance(node, kinds) and getattr(node, "name", None) == name:
            return node
    kind_names = ", ".join(kind.__name__ for kind in kinds)
    raise ContractError(f"missing {name!r} ({kind_names})")


def _class(tree: ast.Module, name: str) -> ast.ClassDef:
    node = _named_node(tree, name, (ast.ClassDef,))
    assert isinstance(node, ast.ClassDef)
    return node


def _function(tree: ast.Module | ast.ClassDef, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    node = _named_node(tree, name, (ast.FunctionDef, ast.AsyncFunctionDef))
    assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    return node


def _argument_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [argument.arg for argument in (*function.args.posonlyargs, *function.args.args)]


def _require_arguments(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    expected: Sequence[str],
    *,
    var_keyword: str | None = None,
) -> None:
    actual = _argument_names(function)
    if actual != list(expected):
        raise ContractError(f"{function.name} arguments changed: expected {list(expected)!r}, got {actual!r}")
    actual_var_keyword = function.args.kwarg.arg if function.args.kwarg else None
    if actual_var_keyword != var_keyword:
        raise ContractError(
            f"{function.name} **kwargs changed: expected {var_keyword!r}, got {actual_var_keyword!r}"
        )


def _decorator_names(node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name):
            names.add(decorator.id)
        elif isinstance(decorator, ast.Attribute):
            names.add(decorator.attr)
        elif isinstance(decorator, ast.Call):
            target = decorator.func
            if isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, ast.Attribute):
                names.add(target.attr)
    return names


def _single_return(function: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.expr:
    returns = [node for node in function.body if isinstance(node, ast.Return)]
    if len(returns) != 1 or returns[0].value is None:
        raise ContractError(f"{function.name} no longer has one explicit return contract")
    return returns[0].value


def _require_literal_return(function: ast.FunctionDef | ast.AsyncFunctionDef, expected: object) -> None:
    try:
        actual = ast.literal_eval(_single_return(function))
    except (TypeError, ValueError) as exc:
        raise ContractError(f"{function.name} no longer returns a fixed literal") from exc
    if actual != expected:
        raise ContractError(f"{function.name} return changed: expected {expected!r}, got {actual!r}")


def _class_assignments(node: ast.ClassDef) -> dict[str, object]:
    assignments: dict[str, object] = {}
    for statement in node.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if not isinstance(target, ast.Name):
            continue
        try:
            assignments[target.id] = ast.literal_eval(statement.value)
        except (TypeError, ValueError):
            continue
    return assignments


def _instance_attributes(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    attributes: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets: Iterable[ast.expr]
        if isinstance(node, ast.Assign):
            targets = node.targets
        else:
            targets = (node.target,)
        for target in targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                attributes.add(target.attr)
    return attributes


def _extension_calls(tree: ast.Module) -> dict[str, list[tuple[str, set[str]]]]:
    calls: dict[str, list[tuple[str, set[str]]]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in {
            "call_extensions_async",
            "call_extensions_sync",
        }:
            continue
        point = node.args[0]
        if not isinstance(point, ast.Constant) or not isinstance(point.value, str):
            continue
        calls.setdefault(point.value, []).append(
            (node.func.attr, {keyword.arg for keyword in node.keywords if keyword.arg is not None})
        )
    return calls


def _require_extension_call(
    calls: dict[str, list[tuple[str, set[str]]]],
    point: str,
    function_name: str,
    required_keywords: set[str],
) -> None:
    matches = calls.get(point, [])
    if not any(name == function_name and required_keywords <= keywords for name, keywords in matches):
        raise ContractError(
            f"extension point {point!r} no longer calls {function_name} with {sorted(required_keywords)!r}"
        )


def _verify_agent_contract(source: SourceTree) -> None:
    tree = source.parse("agent.py")
    context = _class(tree, "AgentContext")
    get_context = _function(context, "get")
    _require_arguments(get_context, ["id"])
    if "staticmethod" not in _decorator_names(get_context):
        raise ContractError("AgentContext.get is no longer a static method")

    context_type = _class(tree, "AgentContextType")
    if _class_assignments(context_type) != {"USER": "user", "TASK": "task", "BACKGROUND": "background"}:
        raise ContractError("AgentContextType members changed")

    loop_data = _class(tree, "LoopData")
    loop_init = _function(loop_data, "__init__")
    required_loop_fields = {"iteration", "user_message", "last_response", "current_tool"}
    missing_loop_fields = required_loop_fields - _instance_attributes(loop_init)
    if missing_loop_fields:
        raise ContractError(f"LoopData fields changed; missing {sorted(missing_loop_fields)!r}")

    calls = _extension_calls(tree)
    _require_extension_call(calls, "system_prompt", "call_extensions_async", {"system_prompt", "loop_data"})
    _require_extension_call(calls, "message_loop_end", "call_extensions_async", {"loop_data"})
    _require_extension_call(calls, "tool_execute_after", "call_extensions_async", {"response", "tool_name"})


def _verify_model_contract(source: SourceTree) -> None:
    tree = source.parse("models.py")
    model_type = _class(tree, "ModelType")
    if _class_assignments(model_type) != {"CHAT": "Chat", "EMBEDDING": "Embedding"}:
        raise ContractError("models.ModelType members changed")

    providers = source.parse("helpers/providers.py")
    provider_alias = next(
        (
            node
            for node in providers.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "ModelType" for target in node.targets)
        ),
        None,
    )
    if not isinstance(provider_alias, ast.Assign) or not isinstance(provider_alias.value, ast.Subscript):
        raise ContractError("helpers.providers.ModelType alias changed")
    try:
        provider_types = set(ast.literal_eval(provider_alias.value.slice))
    except (TypeError, ValueError) as exc:
        raise ContractError("helpers.providers.ModelType is no longer a literal string contract") from exc
    if provider_types != {"chat", "embedding"}:
        raise ContractError(f"provider model types changed: {sorted(provider_types)!r}")
    _require_arguments(_function(providers, "get_provider_config"), ["provider_type", "provider_id"])


def _verify_api_and_extension_contract(source: SourceTree) -> None:
    api = source.parse("helpers/api.py")
    api_handler = _class(api, "ApiHandler")
    _require_arguments(_function(api_handler, "process"), ["self", "input", "request"])
    if not isinstance(_function(api_handler, "process"), ast.AsyncFunctionDef):
        raise ContractError("ApiHandler.process is no longer async")
    for method_name in ("requires_auth", "requires_csrf", "get_methods"):
        method = _function(api_handler, method_name)
        _require_arguments(method, ["cls"])
        if "classmethod" not in _decorator_names(method):
            raise ContractError(f"ApiHandler.{method_name} is no longer a classmethod")
    _require_literal_return(_function(api_handler, "requires_auth"), True)
    _require_literal_return(_function(api_handler, "get_methods"), ["POST"])
    csrf_return = _single_return(_function(api_handler, "requires_csrf"))
    if not (
        isinstance(csrf_return, ast.Call)
        and isinstance(csrf_return.func, ast.Attribute)
        and isinstance(csrf_return.func.value, ast.Name)
        and csrf_return.func.value.id == "cls"
        and csrf_return.func.attr == "requires_auth"
        and not csrf_return.args
        and not csrf_return.keywords
    ):
        raise ContractError("ApiHandler.requires_csrf no longer delegates to requires_auth")

    extension = source.parse("helpers/extension.py")
    extension_class = _class(extension, "Extension")
    _require_arguments(_function(extension_class, "__init__"), ["self", "agent"], var_keyword="kwargs")
    _require_arguments(_function(extension_class, "execute"), ["self"], var_keyword="kwargs")

    tool = source.parse("helpers/tool.py")
    response = _class(tool, "Response")
    if "dataclass" not in _decorator_names(response):
        raise ContractError("helpers.tool.Response is no longer a dataclass")
    fields = {
        node.target.id
        for node in response.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    if fields != {"message", "break_loop", "additional"}:
        raise ContractError(f"helpers.tool.Response fields changed: {sorted(fields)!r}")

    migration_calls = _extension_calls(source.parse("helpers/migration.py"))
    _require_extension_call(migration_calls, "startup_migration", "call_extensions_sync", set())


def _git_head(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ContractError(f"cannot resolve Agent Zero checkout commit: {exc}") from exc
    return completed.stdout.strip()


def verify(root: Path, expected_commit: str) -> None:
    resolved_root = root.resolve()
    actual_commit = _git_head(resolved_root)
    if actual_commit != expected_commit:
        raise ContractError(f"Agent Zero commit mismatch: expected {expected_commit}, got {actual_commit}")
    source = SourceTree(resolved_root)
    _verify_agent_contract(source)
    _verify_model_contract(source)
    _verify_api_and_extension_contract(source)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-zero-root", required=True, type=Path)
    parser.add_argument("--expected-commit", default=PINNED_AGENT_ZERO_COMMIT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        verify(args.agent_zero_root, args.expected_commit)
    except ContractError as exc:
        print(f"Agent Zero contract check failed: {exc}", file=sys.stderr)
        return 1
    print(f"Agent Zero contract verified at {args.expected_commit} using AST-only source checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
