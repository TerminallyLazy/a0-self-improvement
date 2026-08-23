"""Prepare ephemeral DSPy worker dependencies after container recreation."""
from __future__ import annotations

from helpers.extension import Extension
from usr.plugins.dspy_rlm import hooks


class DspyRlmDependencyStartup(Extension):
    def execute(self, **kwargs):
        hooks.ensure_dependencies_background()
