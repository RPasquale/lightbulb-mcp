"""Read-only Project Learning Lab training-pack contract constants.

Only internal, scope-bound agent workers may pair a verified Training Arena
match with an authenticated human-admitted mission lesson. Public SDK and MCP
callers may inspect the resulting candidate pack, which is neither a published
dataset nor a created, admitted, claimable, or executed learning run.
"""

PROJECT_TRAINING_PACK_REQUEST_SCHEMA = (
    "lightbulb.project_training_pack_record_request.v1"
)
PROJECT_TRAINING_PACK_RECEIPT_SCHEMA = "lightbulb.project_training_pack_receipt.v1"
PROJECT_TRAINING_PACK_SCHEMA = "lightbulb.project_training_pack.v1"
PROJECT_LEARNING_RUN_ADMISSION_PLAN_SCHEMA = (
    "lightbulb.project_learning_run_admission_plan.v1"
)
PROJECT_TRAINING_PACK_LEDGER_SCHEMA = "lightbulb.project_training_pack_ledger.v1"


__all__ = [
    "PROJECT_LEARNING_RUN_ADMISSION_PLAN_SCHEMA",
    "PROJECT_TRAINING_PACK_LEDGER_SCHEMA",
    "PROJECT_TRAINING_PACK_RECEIPT_SCHEMA",
    "PROJECT_TRAINING_PACK_REQUEST_SCHEMA",
    "PROJECT_TRAINING_PACK_SCHEMA",
]
