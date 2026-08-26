from pathlib import Path

PLUGIN_NAME = "dspy_rlm"

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = PLUGIN_ROOT / "state"

# Durable state is authoritative. JSON files are compatibility/read-cache artifacts only.
STORE_FILE = STATE_DIR / "dspy_rlm_runtime.sqlite"
# Slice 1 pre-cutover authority. Once a Store Authority Manifest exists, its
# selected generation is authoritative and this compatibility path is ignored.
SAFE_STORE_FILE = STATE_DIR / "dspy_rlm_v3.sqlite"
SAFE_GENERATIONS_DIR = STATE_DIR / "safe-generations"
STORE_AUTHORITY_MANIFEST_FILE = STATE_DIR / "store-authority-manifest.json"
STORE_AUTHORITY_LOCK_FILE = STATE_DIR / "store-authority-manifest.lock"
AUTHORITY_DIR = STATE_DIR / "authority"
AUTHORITY_SECRET_FILE = AUTHORITY_DIR / "issuer-root.secret"
AUTHORITY_PROFILE_FILE = AUTHORITY_DIR / "issuer-profile.json"
AUTHORITY_REVOCATIONS_DIR = AUTHORITY_DIR / "revocations"
MIGRATION_DIR = STATE_DIR / "migration"
MIGRATION_AUTHORITY_FILE = MIGRATION_DIR / "migration-authority.sqlite"
MIGRATION_LOCK_FILE = MIGRATION_DIR / "migration.lock"
QUARANTINES_DIR = MIGRATION_DIR / "quarantines"
QUARANTINE_KEYWRAPS_DIR = MIGRATION_DIR / "keywraps"
TRACE_FILE = STATE_DIR / "traces.jsonl"
STATE_FILE = STATE_DIR / "runtime_state.json"
COMPILED_STATE_FILE = STATE_DIR / "compiled_guidance.json"
