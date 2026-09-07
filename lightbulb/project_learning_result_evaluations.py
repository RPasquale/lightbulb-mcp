"""Independent Project Learning result and human-admission contracts.

The public SDK may inspect independently replayed technical results and let an
authenticated human admit or reject one exact candidate. It cannot construct
or sign worker replay captures. Admission only permits a future bounded shadow
update request; it does not mutate a learner or authorize production promotion.
"""

from __future__ import annotations

from typing import Any


PROJECT_LEARNING_RESULT_EVALUATION_RECEIPT_SCHEMA = (
    "lightbulb.project_learning_result_evaluation_record_receipt.v1"
)
PROJECT_LEARNING_RESULT_EVALUATION_LEDGER_SCHEMA = (
    "lightbulb.project_learning_result_evaluation_ledger.v1"
)
PROJECT_LEARNING_RESULT_ADMISSION_REQUEST_SCHEMA = (
    "lightbulb.project_learning_result_admission_request.v1"
)
PROJECT_LEARNING_RESULT_ADMISSION_RECEIPT_SCHEMA = (
    "lightbulb.project_learning_result_admission_receipt.v1"
)
PROJECT_LEARNING_RESULT_ADMISSION_CONFIRMATION = (
    "decide_shadow_learning_candidate_admission"
)
PROJECT_LEARNING_RESULT_ADMISSION_DECISIONS = frozenset(
    {"admit_shadow_learning_candidate", "reject_learning_candidate"}
)


def _text(value: Any, field: str, maximum: int) -> str:
    normalized = str(value or "").strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(ord(character) < 32 for character in normalized)
    ):
        raise ValueError(
            f"{field} must be printable text between 1 and {maximum} characters"
        )
    return normalized


def build_project_learning_result_admission_request(
    decision: Any,
    rationale: Any,
    *,
    confirm_admission: bool = False,
) -> dict[str, Any]:
    """Build one immutable human decision over an eligible technical result."""

    if confirm_admission is not True:
        raise ValueError(
            "confirm_admission=True is required because this records an immutable "
            "human learning-admission decision"
        )
    normalized_decision = _text(decision, "decision", 80)
    if normalized_decision not in PROJECT_LEARNING_RESULT_ADMISSION_DECISIONS:
        raise ValueError(
            "decision must admit or reject the shadow learning candidate"
        )
    return {
        "schema": PROJECT_LEARNING_RESULT_ADMISSION_REQUEST_SCHEMA,
        "decision": normalized_decision,
        "rationale": _text(rationale, "rationale", 2_000),
        "confirmation": PROJECT_LEARNING_RESULT_ADMISSION_CONFIRMATION,
    }


__all__ = [
    "PROJECT_LEARNING_RESULT_ADMISSION_CONFIRMATION",
    "PROJECT_LEARNING_RESULT_ADMISSION_DECISIONS",
    "PROJECT_LEARNING_RESULT_ADMISSION_RECEIPT_SCHEMA",
    "PROJECT_LEARNING_RESULT_ADMISSION_REQUEST_SCHEMA",
    "PROJECT_LEARNING_RESULT_EVALUATION_LEDGER_SCHEMA",
    "PROJECT_LEARNING_RESULT_EVALUATION_RECEIPT_SCHEMA",
    "build_project_learning_result_admission_request",
]
