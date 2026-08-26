from __future__ import annotations

import pytest

from usr.plugins.dspy_rlm.extensions.python.message_loop_end._90_dspy_rlm_optimize import (
    DspyRlmOptimizationScheduler,
)
from usr.plugins.dspy_rlm.extensions.python.tool_execute_after._40_dspy_rlm_trace import (
    DspyRlmToolTrace,
)


@pytest.mark.asyncio
async def test_loop_hook_without_certified_runtime_inputs_remains_inert() -> None:
    hook = object.__new__(DspyRlmOptimizationScheduler)

    assert await hook.execute(
        loop_data=object(),
        raw_prompt="must not be retained",
        response_text="must not be retained",
    ) is None


@pytest.mark.asyncio
async def test_tool_hook_without_certified_response_remains_inert() -> None:
    hook = object.__new__(DspyRlmToolTrace)

    assert await hook.execute(
        tool_name="shell",
        tool_args={"secret": "must not be retained"},
        response=object(),
    ) is None
