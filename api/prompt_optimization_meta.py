"""Context-free public metadata for the advanced prompt optimization UI."""
from helpers.api import ApiHandler, Request

from usr.plugins.dspy_rlm.helpers.prompt_artifacts import ACTIVATION_MODES, PROTECTED_INVENTORY, TARGET_MODES


class PromptOptimizationMeta(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        return {
            "plugin": "dspy_rlm",
            "target_modes": sorted(TARGET_MODES),
            "activation_modes": sorted(ACTIVATION_MODES),
            "protected_components": [dict(item) for item in PROTECTED_INVENTORY],
            "automatic_requires_canary": True,
        }
