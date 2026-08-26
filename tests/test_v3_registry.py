"""The runtime reader admits every durable v3 schema through one authority."""
from __future__ import annotations

from usr.plugins.dspy_rlm.helpers.v3.activation_transition import (
    ACTIVATION_TRANSITION_RECEIPT_SCHEMA_ID,
)
from usr.plugins.dspy_rlm.helpers.v3.candidate_publication import (
    OPTIMIZATION_RUN_RECEIPT_SCHEMA_ID,
)
from usr.plugins.dspy_rlm.helpers.v3.deterministic_analysis import (
    GUIDANCE_RULE_CATALOG_SCHEMA_ID,
)
from usr.plugins.dspy_rlm.helpers.v3.migration import MIGRATION_RECEIPT_SCHEMA_ID
from usr.plugins.dspy_rlm.helpers.v3.model_routes import MODEL_USE_GRANT_SCHEMA_ID
from usr.plugins.dspy_rlm.helpers.v3.outcome_gepa import GEPA_ADMISSION_RECEIPT_SCHEMA_ID
from usr.plugins.dspy_rlm.helpers.v3.registry import V3_REGISTRY
from usr.plugins.dspy_rlm.helpers.v3.replay_adapter import REPLAY_PAIR_RECEIPT_SCHEMA_ID


def test_master_registry_contains_each_authority_slice() -> None:
    required = {
        MIGRATION_RECEIPT_SCHEMA_ID,
        GUIDANCE_RULE_CATALOG_SCHEMA_ID,
        MODEL_USE_GRANT_SCHEMA_ID,
        GEPA_ADMISSION_RECEIPT_SCHEMA_ID,
        REPLAY_PAIR_RECEIPT_SCHEMA_ID,
        OPTIMIZATION_RUN_RECEIPT_SCHEMA_ID,
        ACTIVATION_TRANSITION_RECEIPT_SCHEMA_ID,
    }
    assert required <= V3_REGISTRY.schemas.keys()
