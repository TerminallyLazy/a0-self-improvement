"""Credential-safe DSPy model resolution for isolated plugin workers."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class DSPyModelResolution:
    selector: str
    source: str

    @property
    def configured(self) -> bool:
        return bool(self.selector)


def _section(cfg: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = cfg.get(name)
    return value if isinstance(value, Mapping) else {}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _agent_zero_model(slot: str = "utility") -> tuple[str, Mapping[str, Any]]:
    """Return a DSPy/LiteLLM selector and Agent Zero model-slot metadata."""
    try:
        from helpers.providers import get_provider_config
        from plugins._model_config.helpers.model_config import get_chat_model_config, get_utility_model_config

        model = get_utility_model_config() if slot == "utility" else get_chat_model_config()
        if not isinstance(model, Mapping):
            return "", {}
        provider = _text(model.get("provider")).lower()
        name = _text(model.get("name"))
        if not provider or not name:
            return "", {}
        provider_config = get_provider_config("chat", provider)
        litellm_provider = _text(
            provider_config.get("litellm_provider") if isinstance(provider_config, Mapping) else provider
        ).lower() or provider
        if provider == "other":
            litellm_provider = "openai"
        prefix = name.split("/", 1)[0].lower() if "/" in name else ""
        selector = name if prefix in {provider, litellm_provider} else f"{litellm_provider}/{name}"
        return selector, model
    except Exception:
        return "", {}


def resolve_dspy_model(cfg: Mapping[str, Any], purpose: str = "rlm") -> DSPyModelResolution:
    """Resolve an LM selector without persisting or returning credentials."""
    rlm = _section(cfg, "rlm")
    evaluator = _section(cfg, "evaluator")
    if purpose == "rlm":
        candidates = (
            (_text(rlm.get("model_ref")), "rlm.model_ref"),
            (_text(evaluator.get("preferred_dspy_model")), "evaluator.preferred_dspy_model"),
        )
    else:
        candidates = (
            (_text(evaluator.get("preferred_dspy_model")), "evaluator.preferred_dspy_model"),
            (_text(rlm.get("model_ref")), "rlm.model_ref"),
        )
    for selector, source in candidates:
        if selector:
            return DSPyModelResolution(selector=selector, source=source)
    for variable in ("DSPY_RLM_MODEL", "DSPY_MODEL"):
        selector = _text(os.environ.get(variable))
        if selector:
            return DSPyModelResolution(selector=selector, source=f"env:{variable}")
    selector, _model = _agent_zero_model("utility")
    return DSPyModelResolution(
        selector=selector,
        source="agent_zero.utility_model" if selector else "unresolved",
    )


def dspy_lm_kwargs(selector: str) -> dict[str, Any]:
    """Resolve credentials at call time without exposing them to plugin state."""
    selector = _text(selector)
    provider = selector.split("/", 1)[0].lower() if "/" in selector else ""
    utility_selector, utility_model = _agent_zero_model("utility")
    chat_selector, chat_model = _agent_zero_model("chat")
    selected_model: Mapping[str, Any] = {}
    if selector == utility_selector:
        selected_model = utility_model
    elif selector == chat_selector:
        selected_model = chat_model
    selected_provider = _text(selected_model.get("provider")).lower()
    kwargs: dict[str, Any] = {}
    try:
        import models

        key = ""
        if selected_model:
            key = _text(selected_model.get("api_key"))
        key = key or _text(models.get_api_key(selected_provider or provider))
        if key and key not in {"None", "NA"}:
            kwargs["api_key"] = key
    except Exception:
        pass
    if selected_model:
        api_base = _text(selected_model.get("api_base"))
        if api_base:
            kwargs["api_base"] = api_base
    return kwargs


def build_dspy_lm(api: Any, selector: str) -> Any:
    """Construct the real DSPy LM with Agent Zero credentials when available."""
    return api.LM(selector, **dspy_lm_kwargs(selector))


__all__ = ["DSPyModelResolution", "build_dspy_lm", "dspy_lm_kwargs", "resolve_dspy_model"]
