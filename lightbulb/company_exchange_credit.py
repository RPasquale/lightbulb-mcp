"""Credit limits: how much a customer may owe this company before its orders go to the owner.

A company that sells on terms lends each customer what it ships before the customer pays, and an agent that takes on
customers it has never met (``take_new_customer``) could lend a stranger without bound. The owner sets a credit
policy: a limit for new customers, a larger one for customers that have paid, and how many paid trades make a
customer one that has. From then on the agent accepts an order alone only while the customer's exposure, what it owes
on the orders this company accepted and it has not paid, stays within its limit with the order added; an order past
it waits for the owner, who may still accept it.

A trade counts as paid once the books show its invoice paid (the revenue case settled by the payment the platform
observed) or the customer remitted it through the exchange. Exposure is counted in the policy's currency; an order in
another goes to the owner anyway, since the mandate's caps are in the company's own.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any

from pydantic import Field, ValidationError, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    CurrencyCode,
    OpaqueRef,
    Sha256Digest,
    StrictModel,
    decimal_value,
    detached,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)

CREDIT_POLICY_SCHEMA = "lightbulb.exchange_credit_policy.v1"
CREDIT_VIEW_SCHEMA = "lightbulb.exchange_credit.v1"
CREDIT_ENTITY = "credit:policy"
# a trade the buyer still owes on: this company accepted the order and the money has not come in
OWED_STATUSES: frozenset[str] = frozenset({"accepted", "invoiced"})


class CreditError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CreditError(code, message)


class CreditPolicy(StrictModel):
    """The owner's limits on what a customer may owe, sealed."""

    schema_id: str = Field(default=CREDIT_POLICY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    new_customer_limit: Decimal
    customer_limit: Decimal
    trusted_after_paid: int = Field(default=2, ge=1, le=24)
    set_by: OpaqueRef
    set_at: str
    policy_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("new_customer_limit", "customer_limit", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("set_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="set_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "CreditPolicy":
        if self.new_customer_limit < 0 or self.customer_limit < self.new_customer_limit:
            raise ValueError("the limits are not negative, and a customer that has paid may owe at least what a new one may")
        if not skip_digests(info) and self.policy_digest != sealed_digest(CreditPolicy, self, "policy_digest"):
            raise ValueError("policy_digest must commit the exact policy")
        return self

    def render(self) -> str:
        return (f"a new customer may owe up to {self.new_customer_limit} {self.currency}; after {self.trusted_after_paid} paid trade(s), up to {self.customer_limit} {self.currency}; "
                f"set by {self.set_by} on {self.set_at[:10]}")


def verify_credit_policy(value: Any) -> CreditPolicy:
    return value if isinstance(value, CreditPolicy) else CreditPolicy.model_validate(dict(detached(value)))


def current_credit_policy(console: Any) -> CreditPolicy | None:
    from lightbulb.company_exchange_surface import EXCHANGE_ENGINE

    record = console.store.get(EXCHANGE_ENGINE, CREDIT_ENTITY)
    return None if record is None else verify_credit_policy(dict(record["state"])["policy"])


def set_credit_policy(console: Any, *, now: str, new_customer_limit: Any, customer_limit: Any, owner_ref: str | None = None, trusted_after_paid: Any = 2) -> dict[str, Any]:
    """The owner's credit limits: what a new customer may owe, what a customer that has paid may owe, and after how many paid trades."""

    from lightbulb.company_exchange_sourcing import _owner_approves
    from lightbulb.company_exchange_surface import EXCHANGE_ENGINE, _put

    at = timestamp(now, field_name="now")
    _require(owner_ref is not None, "OWNER_APPROVAL_REQUIRED", "credit limits are the owner's to set: give the owner's owner_ref")
    _owner_approves(console, owner_ref)
    try:
        policy = seal(CreditPolicy, {"company_ref": console.bundle.company_ref, "currency": console.bundle.operating_plan.blueprint.currency, "new_customer_limit": str(new_customer_limit),
                                     "customer_limit": str(customer_limit), "trusted_after_paid": int(trusted_after_paid), "set_by": str(owner_ref), "set_at": at}, "policy_digest")
    except ValidationError as exc:
        raise CreditError("CREDIT_POLICY_INVALID", "; ".join(str(error["msg"]).removeprefix("Value error, ") for error in exc.errors())[:300]) from exc
    existing = console.store.get(EXCHANGE_ENGINE, CREDIT_ENTITY)
    stored = _put(console, CREDIT_ENTITY, key="policy", document=policy.to_dict(), digest=policy.policy_digest, now=at, status="in_force", existing=existing)
    return {**credit_document(console, now=at), "stored": stored}


def _paid(console: Any, thread: Any) -> bool:
    """The money for this sale is in, as far as this company knows: its revenue case settled, or the customer remitted it."""

    from lightbulb.company_exchange_surface import BOOKS_ENGINE_FOR, _books_entity

    if thread.status == "remitted":
        return True
    record = console.store.get(BOOKS_ENGINE_FOR["seller"], _books_entity("seller", thread.exchange_ref))
    return record is not None and str(dict(record["state"]).get("status")) in ("payment_applied", "cash_settled", "receivable_cleared")


def customer_credit(console: Any, customer: str, *, policy: CreditPolicy | None = None, excluding: str | None = None) -> dict[str, Any]:
    """What a customer owes this company on the exchange and the limit it trades under: new or trusted, by the trades it has paid."""

    from lightbulb.company_exchange_surface import _exchange_threads, current_card

    card = current_card(console)
    parsed_policy = policy or current_credit_policy(console)
    owed, paid, open_refs = Decimal("0"), 0, []
    for thread, _delivery in _exchange_threads(console):
        if card is None or thread.seller != card.party_ref or thread.buyer != customer or thread.exchange_ref == excluding:
            continue
        if _paid(console, thread):
            paid += 1
        elif thread.status in OWED_STATUSES and (parsed_policy is None or thread.currency == parsed_policy.currency) and thread.value is not None:
            owed += thread.value
            open_refs.append(thread.exchange_ref)
    trusted = parsed_policy is not None and paid >= parsed_policy.trusted_after_paid
    limit = None if parsed_policy is None else (parsed_policy.customer_limit if trusted else parsed_policy.new_customer_limit)
    return {"customer": customer, "owed": str(owed), "paid_trades": paid, "open": open_refs, "tier": "trusted" if trusted else "new", "limit": None if limit is None else str(limit),
            "headroom": None if limit is None else str(limit - owed)}


def credit_hold(console: Any, *, customer: str, money: Any, currency: str, exchange_ref: str) -> str | None:
    """Why this order goes to the owner under the credit policy, or None when the customer may owe it (or no policy is set)."""

    policy = current_credit_policy(console)
    if policy is None or currency != policy.currency:
        return None
    standing = customer_credit(console, customer, policy=policy, excluding=exchange_ref)
    after = Decimal(standing["owed"]) + Decimal(str(money))
    if after <= Decimal(str(standing["limit"])):
        return None
    return (f"{customer} would owe {after} {policy.currency} with this order, over the {standing['limit']} {policy.currency} credit limit for a {standing['tier']} customer "
            f"({standing['paid_trades']} paid trade(s)); the owner decides")


def credit_document(console: Any, *, now: str) -> dict[str, Any]:
    """The credit policy and every customer's exposure under it."""

    from lightbulb.company_exchange_surface import _exchange_threads, current_card

    at = timestamp(now, field_name="now")
    policy = current_credit_policy(console)
    card = current_card(console)
    customers = sorted({thread.buyer for thread, _delivery in _exchange_threads(console) if card is not None and thread.seller == card.party_ref})
    rows = [customer_credit(console, customer, policy=policy) for customer in customers]
    lines = [f"**Credit** ({console.bundle.company_ref}): " + (policy.render() if policy is not None else "no credit policy: the agent accepts orders under the mandate's cap alone (company_exchange credit sets one)")]
    lines.extend(f"- {row['customer']}: owes {row['owed']}" + (f" of {row['limit']} ({row['tier']}, {row['paid_trades']} paid)" if row["limit"] is not None else "") for row in rows[:30])
    return {"schema": CREDIT_VIEW_SCHEMA, "company_ref": console.bundle.company_ref, "as_of": at, "policy": None if policy is None else policy.to_dict(), "customers": rows,
            "summary": "\n".join(lines), "provider_effect_executed": False}


__all__ = [
    "CREDIT_POLICY_SCHEMA",
    "CREDIT_VIEW_SCHEMA",
    "CreditError",
    "CreditPolicy",
    "credit_document",
    "credit_hold",
    "current_credit_policy",
    "customer_credit",
    "set_credit_policy",
    "verify_credit_policy",
]
