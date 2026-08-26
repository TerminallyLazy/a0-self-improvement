"""Inert compatibility seam retained after v3 unified prompt composition."""
from __future__ import annotations

from typing import Any

from helpers.extension import Extension


class DspyRlmPromptController(Extension):
    """Legacy hook name; prompt capture and split promotion are unavailable."""

    async def execute(self, system_prompt: list[str] = [], **kwargs: Any) -> None:
        return None
