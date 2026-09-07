"""Read-only Project Training Arena contract constants.

Only internal, scope-bound agent workers may record a match. The public SDK and
MCP surface intentionally expose the ledger as read-only context: a saved match
does not authorize training, confidence updates, routing, promotion, policy
activation, actions, or production writes.
"""

PROJECT_SKILL_MATCH_REQUEST_SCHEMA = (
    "lightbulb.project_skill_match_record_request.v1"
)
PROJECT_SKILL_MATCH_RECEIPT_SCHEMA = "lightbulb.project_skill_match_receipt.v1"
PROJECT_SKILL_MATCH_LEDGER_SCHEMA = "lightbulb.project_skill_match_ledger.v1"


__all__ = [
    "PROJECT_SKILL_MATCH_LEDGER_SCHEMA",
    "PROJECT_SKILL_MATCH_RECEIPT_SCHEMA",
    "PROJECT_SKILL_MATCH_REQUEST_SCHEMA",
]
