"""One closed schema authority for the complete v3 Safe Projection Store."""
from __future__ import annotations

from .activation_transition import ACTIVATION_TRANSITION_REGISTRY
from .calibration_authority import CALIBRATION_AUTHORITY_REGISTRY
from .canary import CANARY_REGISTRY
from .canary_command_adapter import CANARY_COMMAND_REGISTRY
from .canary_conclusion_repository import CANARY_CONCLUSION_REPOSITORY_REGISTRY
from .canary_outcome_reducer import CANARY_OUTCOME_REDUCER_REGISTRY
from .canary_runtime import CANARY_RUNTIME_REGISTRY
from .candidate_publication import CANDIDATE_PUBLICATION_REGISTRY
from .closed_loop import CLOSED_LOOP_REGISTRY
from .closed_loop_repository import CLOSED_LOOP_REPOSITORY_REGISTRY
from .closed_loop_runner import CLOSED_LOOP_RUNNER_REGISTRY
from .deterministic_analysis import DETERMINISTIC_ANALYSIS_REGISTRY
from .feedback import FEEDBACK_REGISTRY
from .fixture_repository import FIXTURE_REPOSITORY_REGISTRY
from .migration import MIGRATION_REGISTRY
from .model_routes import MODEL_ROUTE_REGISTRY
from .observation import OBSERVATION_REGISTRY
from .observation_bridge import OBSERVATION_BRIDGE_REGISTRY
from .outcome_gepa import OUTCOME_GEPA_REGISTRY
from .post_activation_repository import POST_ACTIVATION_REPOSITORY_REGISTRY
from .replay_adapter import REPLAY_REGISTRY
from .replay_repository import REPLAY_REPOSITORY_REGISTRY
from .schemas import merge_schema_registries
from .work_authority import WORK_AUTHORITY_REGISTRY


V3_REGISTRY = merge_schema_registries(
    MIGRATION_REGISTRY,
    CANDIDATE_PUBLICATION_REGISTRY,
    REPLAY_REGISTRY,
    REPLAY_REPOSITORY_REGISTRY,
    CANARY_REGISTRY,
    CANARY_COMMAND_REGISTRY,
    CANARY_CONCLUSION_REPOSITORY_REGISTRY,
    CANARY_OUTCOME_REDUCER_REGISTRY,
    CANARY_RUNTIME_REGISTRY,
    DETERMINISTIC_ANALYSIS_REGISTRY,
    FEEDBACK_REGISTRY,
    CALIBRATION_AUTHORITY_REGISTRY,
    MODEL_ROUTE_REGISTRY,
    OBSERVATION_REGISTRY,
    OBSERVATION_BRIDGE_REGISTRY,
    OUTCOME_GEPA_REGISTRY,
    POST_ACTIVATION_REPOSITORY_REGISTRY,
    ACTIVATION_TRANSITION_REGISTRY,
    CLOSED_LOOP_REGISTRY,
    CLOSED_LOOP_REPOSITORY_REGISTRY,
    CLOSED_LOOP_RUNNER_REGISTRY,
    WORK_AUTHORITY_REGISTRY,
    FIXTURE_REPOSITORY_REGISTRY,
)


__all__ = ["V3_REGISTRY"]
