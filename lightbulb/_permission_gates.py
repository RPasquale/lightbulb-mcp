"""Replay permission sources at the consuming lifecycle's clock and scope."""
from typing import Any

from lightbulb.company_engine_core import require


def channel_name(channel: str) -> str:
    return {"email_lifecycle": "email", "sms_lifecycle": "sms"}.get(channel, channel)


def eligibility(receipt: Any, suppression: Any, *, channel: str, at: str, company_ref: Any, scope: Any, endpoints: Any = None) -> Any:
    from lightbulb.permission_register import verify_eligibility
    require(receipt is not None and suppression is not None, "SEND_WITHOUT_ELIGIBILITY", "messaging requires current eligibility and the exact suppression commitment")
    try:
        return verify_eligibility(receipt, suppression_digest=suppression, channel=channel_name(channel), at=at, company_ref=company_ref, expected_scope=scope, endpoints=endpoints)
    except ValueError as exc:
        require(False, getattr(exc, "code", "SEND_WITHOUT_ELIGIBILITY"), str(exc))


def claims(projections: Any, refs: Any, *, channel: str, jurisdiction: Any, product: Any, at: str, company_ref: Any, scope: Any) -> tuple[dict, ...]:
    from lightbulb.permission_register import verify_claim_projection
    by_ref = {item.get("claim_ref"): item for item in projections}
    require(len(by_ref) == len(projections), "CLAIM_NOT_APPROVED", "each claim projection is unique")
    result = []
    for ref in refs:
        require(ref in by_ref and jurisdiction is not None and product is not None, "CLAIM_NOT_APPROVED", "each creative claim requires its independently approved scoped register projection")
        try:
            result.append(verify_claim_projection(by_ref[ref], channel=channel, jurisdiction=jurisdiction, product=product, at=at, company_ref=company_ref, expected_scope=scope))
        except ValueError as exc:
            require(False, "CLAIM_NOT_APPROVED", str(exc), "manual_reconciliation")
    return tuple(result)
