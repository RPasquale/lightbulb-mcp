"""ServiceEngagement: one immutable thread from quote to cash.

A service engagement links, by digest, the artifacts produced by the
commercial lifecycle, the commercial-legal handoff, the contract-obligation
loop, contract-bound delivery, and finance: quote → legal review packet →
executed agreement custody → delivery plan → deliverable bindings → accepted
value → invoice candidates → payments → close.  It stores no copies of those
artifacts, only their exact identities and digests, and every transition is
replay-fenced like the other lifecycles in this SDK.

The engagement never issues an invoice, moves money, records acceptance, or
changes any linked artifact.  It proposes invoice candidates shaped for the
existing ``finance.create_invoice`` primitive and reports engagement health.
Spring owns the engagement of record, approvals, invoicing, and settlement.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)


SERVICE_ENGAGEMENT_GOLDEN_LOOP = "service.marketing_to_cash_engagement@0.1.0"
ENGAGEMENT_SCOPE_SCHEMA = "lightbulb.service_engagement_scope.v1"
ENGAGEMENT_COMMAND_SCHEMA = "lightbulb.service_engagement_transition_command.v1"
ENGAGEMENT_SNAPSHOT_SCHEMA = "lightbulb.service_engagement_snapshot.v1"
ENGAGEMENT_RESULT_SCHEMA = "lightbulb.service_engagement_transition_result.v1"
ENGAGEMENT_ASSESSMENT_SCHEMA = "lightbulb.service_engagement_assessment.v1"
INVOICE_CANDIDATE_SCHEMA = "lightbulb.service_engagement_invoice_candidate.v1"

GENESIS_STATE_DIGEST = "0" * 64
MAX_ENGAGEMENT_TRANSITIONS = 200

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_MONEY_QUANTUM = Decimal("0.000001")
_SECRET_LIKE_KEYS = (
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "client_secret",
    "tenant_id",
    "company_id",
    "user_id",
)
_SECRET_LIKE_VALUE_PATTERNS = (
    re.compile(r"^(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
    re.compile(r"^(xox[abprs]-|ghp_|gho_|github_pat_|glpat-)[A-Za-z0-9_-]{8,}"),
    re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"^(Bearer|Basic) [A-Za-z0-9._~+/=-]{8,}$", re.IGNORECASE),
)


def _reject_secret_like_text(value: str, *, label: str) -> None:
    for pattern in _SECRET_LIKE_VALUE_PATTERNS:
        if pattern.search(value):
            raise ValueError(f"{label} must not carry credential-like material")


def _reject_secret_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_LIKE_KEYS) and not lowered.endswith("_tokens"):
                raise ValueError(f"{path}.{key} is a credential-like or authority-like field and is never accepted")
            _reject_secret_like_payload(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_like_payload(item, path=f"{path}[{index}]")
    elif isinstance(value, str):
        _reject_secret_like_text(value, label=path)


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    _reject_secret_like_text(value, label="reference")
    return value


OpaqueRef = Annotated[str, StringConstraints(pattern=_REF_PATTERN), AfterValidator(_visible_ref)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=500)]

EngagementStage = Literal[
    "opened",
    "quote_proposed",
    "quote_approved",
    "legal_review",
    "agreement_executed",
    "delivery_planned",
    "delivery_in_progress",
    "accepted",
    "invoiced",
    "paid",
    "closed",
    "cancelled",
]
TransitionKind = Literal[
    "link_quote",
    "approve_quote",
    "link_legal_review_packet",
    "link_executed_agreement",
    "link_delivery_plan",
    "link_deliverable_binding",
    "link_accepted_value",
    "propose_invoice",
    "link_issued_invoice",
    "link_payment",
    "close",
    "cancel",
]
TERMINAL_STAGES: frozenset[str] = frozenset({"closed", "cancelled"})
RecoveryDisposition = Literal["not_required", "do_not_replay", "refresh_snapshot", "correct_input", "manual_reconciliation"]
InvoiceStatus = Literal["proposed", "issued", "paid"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )

    @model_validator(mode="before")
    @classmethod
    def _portable_payload(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if not isinstance(value, Mapping):
            return value
        _reject_secret_like_payload(value)
        return {str(key): (tuple(item) if isinstance(item, list) else item) for key, item in value.items()}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _detached(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {key: _detached(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_detached(item) for item in value]
    return value


def _timestamp(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _decimal(value: Any, *, field_name: str) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{field_name} must be a decimal string or integer")
    try:
        parsed = value if isinstance(value, Decimal) else Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a canonical decimal string") from exc
    if not parsed.is_finite() or parsed < 0 or parsed.as_tuple().exponent < -6:
        raise ValueError(f"{field_name} must be a finite non-negative decimal with at most six places")
    return parsed.quantize(_MONEY_QUANTUM)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _digest_without(payload: Mapping[str, Any], *fields: str) -> str:
    return _stable_digest({key: value for key, value in payload.items() if key not in fields})


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _skip(info: ValidationInfo) -> bool:
    return bool((info.context or {}).get("skip_engagement_digests"))


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, GENESIS_STATE_DIGEST)
    parsed = model.model_validate(raw, context={"skip_engagement_digests": True})
    return _digest_without(parsed.to_dict(), field)


# --------------------------------------------------------------------------- #
# Scope, packages, command
# --------------------------------------------------------------------------- #


class ServiceEngagementScope(_StrictModel):
    schema_id: Literal["lightbulb.service_engagement_scope.v1"] = Field(default=ENGAGEMENT_SCOPE_SCHEMA, alias="schema")
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str
    engagement_ref: OpaqueRef
    customer_ref: OpaqueRef
    currency: CurrencyCode

    @field_validator("project_id")
    @classmethod
    def _project_id(cls, value: str) -> str:
        from uuid import UUID

        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("project_id must be a canonical UUID") from exc
        if str(parsed) != value:
            raise ValueError("project_id must be a canonical UUID")
        return value


class LinkQuotePackage(_StrictModel):
    kind: Literal["link_quote"] = "link_quote"
    quote_ref: OpaqueRef
    quote_revision: int = Field(ge=1)
    commercial_snapshot_digest: Sha256Digest
    total: Decimal

    @field_validator("total", mode="before")
    @classmethod
    def _total(cls, value: Any) -> Any:
        return _decimal(value, field_name="total")


class ApproveQuotePackage(_StrictModel):
    kind: Literal["approve_quote"] = "approve_quote"
    quote_ref: OpaqueRef
    quote_revision: int = Field(ge=1)
    approved_by_ref: OpaqueRef
    approval_evidence_ref: OpaqueRef


class LinkLegalReviewPacketPackage(_StrictModel):
    kind: Literal["link_legal_review_packet"] = "link_legal_review_packet"
    packet_digest: Sha256Digest
    quote_ref: OpaqueRef
    quote_revision: int = Field(ge=1)


class LinkExecutedAgreementPackage(_StrictModel):
    kind: Literal["link_executed_agreement"] = "link_executed_agreement"
    custody_candidate_digest: Sha256Digest
    contract_ref: OpaqueRef
    agreement_version: int = Field(ge=1)
    executed_agreement_digest: Sha256Digest
    packet_digest: Sha256Digest
    custody_record_ref: OpaqueRef


class LinkDeliveryPlanPackage(_StrictModel):
    kind: Literal["link_delivery_plan"] = "link_delivery_plan"
    plan_digest: Sha256Digest
    custody_candidate_digest: Sha256Digest
    total_allocated: Decimal
    deliverable_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=500)

    @field_validator("total_allocated", mode="before")
    @classmethod
    def _total(cls, value: Any) -> Any:
        return _decimal(value, field_name="total_allocated")

    @field_validator("deliverable_refs", mode="before")
    @classmethod
    def _refs(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            items = tuple(value)
            _unique(list(items), label="deliverable refs")
            return tuple(sorted(items))
        return value


class LinkDeliverableBindingPackage(_StrictModel):
    kind: Literal["link_deliverable_binding"] = "link_deliverable_binding"
    binding_digest: Sha256Digest
    plan_digest: Sha256Digest
    obligation_ref: OpaqueRef
    packet_ref: OpaqueRef


class LinkAcceptedValuePackage(_StrictModel):
    kind: Literal["link_accepted_value"] = "link_accepted_value"
    accepted_value_digest: Sha256Digest
    binding_digest: Sha256Digest
    obligation_ref: OpaqueRef
    acceptance_state: Literal["accepted_full", "accepted_partial", "rejected"]
    accepted_amount: Decimal
    invoice_eligible: bool
    spring_acceptance_record_ref: OpaqueRef

    @field_validator("accepted_amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Any:
        return _decimal(value, field_name="accepted_amount")

    @model_validator(mode="after")
    def _eligibility_is_coherent(self) -> "LinkAcceptedValuePackage":
        if self.acceptance_state == "rejected" and (self.invoice_eligible or self.accepted_amount != 0):
            raise ValueError("rejected acceptance carries no invoiceable value")
        return self


class ProposeInvoicePackage(_StrictModel):
    kind: Literal["propose_invoice"] = "propose_invoice"
    invoice_candidate_ref: OpaqueRef
    accepted_value_digests: tuple[Sha256Digest, ...] = Field(min_length=1, max_length=200)
    amount: Decimal
    due_days: int = Field(ge=0, le=365)

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Any:
        return _decimal(value, field_name="amount")

    @field_validator("accepted_value_digests", mode="before")
    @classmethod
    def _digests(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            items = tuple(value)
            _unique(list(items), label="accepted value digests")
            return tuple(sorted(items))
        return value


class LinkIssuedInvoicePackage(_StrictModel):
    kind: Literal["link_issued_invoice"] = "link_issued_invoice"
    invoice_candidate_ref: OpaqueRef
    invoice_ref: OpaqueRef
    issued_amount: Decimal
    issued_at: str

    @field_validator("issued_amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Any:
        return _decimal(value, field_name="issued_amount")

    @field_validator("issued_at")
    @classmethod
    def _issued(cls, value: str) -> str:
        return _timestamp(value, field_name="issued_at")


class LinkPaymentPackage(_StrictModel):
    kind: Literal["link_payment"] = "link_payment"
    invoice_ref: OpaqueRef
    payment_ref: OpaqueRef
    amount: Decimal
    settled_at: str

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Any:
        return _decimal(value, field_name="amount")

    @field_validator("settled_at")
    @classmethod
    def _settled(cls, value: str) -> str:
        return _timestamp(value, field_name="settled_at")


class ClosePackage(_StrictModel):
    kind: Literal["close"] = "close"
    closed_by_ref: OpaqueRef
    note: BoundedText | None = None


class CancelPackage(_StrictModel):
    kind: Literal["cancel"] = "cancel"
    cancelled_by_ref: OpaqueRef
    reason: Literal["customer_withdrew", "lost_to_competitor", "no_agreement", "change_order_cancellation", "internal"]
    note: BoundedText | None = None


TransitionPackage = Annotated[
    LinkQuotePackage
    | ApproveQuotePackage
    | LinkLegalReviewPacketPackage
    | LinkExecutedAgreementPackage
    | LinkDeliveryPlanPackage
    | LinkDeliverableBindingPackage
    | LinkAcceptedValuePackage
    | ProposeInvoicePackage
    | LinkIssuedInvoicePackage
    | LinkPaymentPackage
    | ClosePackage
    | CancelPackage,
    Field(discriminator="kind"),
]


class ServiceEngagementTransitionCommand(_StrictModel):
    schema_id: Literal["lightbulb.service_engagement_transition_command.v1"] = Field(default=ENGAGEMENT_COMMAND_SCHEMA, alias="schema")
    kind: TransitionKind
    scope: ServiceEngagementScope
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_ENGAGEMENT_TRANSITIONS)
    expected_state_digest: Sha256Digest
    occurred_at: str
    host_outcome_report: Literal["reported_certain", "reported_in_doubt", "unreported"] = "reported_certain"
    requested_by_ref: OpaqueRef
    package: TransitionPackage
    request_digest: Sha256Digest = GENESIS_STATE_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def _occurred(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _command_is_exact(self, info: ValidationInfo) -> "ServiceEngagementTransitionCommand":
        if self.kind != self.package.kind:
            raise ValueError("command kind must exactly match its tagged package")
        if _skip(info):
            return self
        if self.request_digest != service_engagement_command_digest(self):
            raise ValueError("request_digest must commit the exact normalized command")
        return self


def service_engagement_command_digest(command: ServiceEngagementTransitionCommand | Mapping[str, Any]) -> str:
    raw = dict(_detached(command))
    raw.setdefault("request_digest", GENESIS_STATE_DIGEST)
    parsed = ServiceEngagementTransitionCommand.model_validate(raw, context={"skip_engagement_digests": True})
    return _digest_without(parsed.to_dict(), "request_digest")


def seal_service_engagement_command(command: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(command))
    raw["request_digest"] = service_engagement_command_digest(raw)
    return ServiceEngagementTransitionCommand.model_validate(raw).to_dict()


# --------------------------------------------------------------------------- #
# Derived state and snapshot
# --------------------------------------------------------------------------- #


class InvoiceLedgerEntry(_StrictModel):
    invoice_candidate_ref: OpaqueRef
    invoice_ref: OpaqueRef | None = None
    status: InvoiceStatus
    amount: Decimal
    paid_amount: Decimal
    accepted_value_digests: tuple[Sha256Digest, ...] = Field(min_length=1, max_length=200)

    @field_validator("amount", "paid_amount", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return _decimal(value, field_name=str(info.field_name))


class EngagementLinks(_StrictModel):
    quote_ref: OpaqueRef | None = None
    quote_revision: int | None = None
    quote_total: Decimal | None = None
    commercial_snapshot_digest: Sha256Digest | None = None
    quote_approved: bool = False
    packet_digest: Sha256Digest | None = None
    custody_candidate_digest: Sha256Digest | None = None
    contract_ref: OpaqueRef | None = None
    agreement_version: int | None = None
    executed_agreement_digest: Sha256Digest | None = None
    custody_record_ref: OpaqueRef | None = None
    plan_digest: Sha256Digest | None = None
    total_allocated: Decimal | None = None
    deliverable_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)
    binding_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=500)
    bound_obligation_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)
    accepted_value_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=500)
    accepted_obligation_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)
    accepted_total: Decimal = Decimal(0)
    invoiceable_total: Decimal = Decimal(0)
    invoices: tuple[InvoiceLedgerEntry, ...] = Field(default_factory=tuple, max_length=200)
    invoiced_total: Decimal = Decimal(0)
    paid_total: Decimal = Decimal(0)

    @field_validator("quote_total", "total_allocated", "accepted_total", "invoiceable_total", "invoiced_total", "paid_total", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))


class _Rejected(ValueError):
    def __init__(self, code: str, instructions: str, recovery: RecoveryDisposition, *, in_doubt: bool = False) -> None:
        super().__init__(instructions)
        self.code = code
        self.instructions = instructions
        self.recovery = recovery
        self.in_doubt = in_doubt


def _apply(stage: str, links: EngagementLinks, command: ServiceEngagementTransitionCommand) -> tuple[str, EngagementLinks]:
    """Deterministic engagement state machine; raises _Rejected on illegal moves."""

    package = command.package
    data = links.to_dict()
    if stage in TERMINAL_STAGES:
        raise _Rejected("ENGAGEMENT_TERMINAL", f"engagement is {stage}; no further transitions", "do_not_replay")
    kind = command.kind
    if kind == "cancel":
        assert isinstance(package, CancelPackage)
        return "cancelled", links
    if kind == "link_quote":
        assert isinstance(package, LinkQuotePackage)
        if stage not in {"opened", "quote_proposed"}:
            raise _Rejected("ILLEGAL_TRANSITION", "a quote can be linked only before approval", "correct_input")
        if links.quote_ref is not None and links.quote_ref != package.quote_ref:
            raise _Rejected("QUOTE_REF_CHANGED", "an engagement tracks one quote reference", "correct_input")
        if links.quote_revision is not None and package.quote_revision <= links.quote_revision:
            raise _Rejected("QUOTE_REVISION_NOT_ADVANCED", "linked quote revision must advance", "correct_input")
        data.update({"quote_ref": package.quote_ref, "quote_revision": package.quote_revision, "quote_total": str(package.total), "commercial_snapshot_digest": package.commercial_snapshot_digest, "quote_approved": False})
        return "quote_proposed", EngagementLinks.model_validate(data)
    if kind == "approve_quote":
        assert isinstance(package, ApproveQuotePackage)
        if stage != "quote_proposed":
            raise _Rejected("ILLEGAL_TRANSITION", "only a proposed quote can be approved", "correct_input")
        if package.quote_ref != links.quote_ref or package.quote_revision != links.quote_revision:
            raise _Rejected("QUOTE_MISMATCH", "approval must cite the linked quote revision", "correct_input")
        data["quote_approved"] = True
        return "quote_approved", EngagementLinks.model_validate(data)
    if kind == "link_legal_review_packet":
        assert isinstance(package, LinkLegalReviewPacketPackage)
        if stage not in {"quote_approved", "legal_review"}:
            raise _Rejected("ILLEGAL_TRANSITION", "legal review requires an approved quote", "correct_input")
        if package.quote_ref != links.quote_ref or package.quote_revision != links.quote_revision:
            raise _Rejected("QUOTE_MISMATCH", "packet must cite the approved quote revision", "correct_input")
        data["packet_digest"] = package.packet_digest
        return "legal_review", EngagementLinks.model_validate(data)
    if kind == "link_executed_agreement":
        assert isinstance(package, LinkExecutedAgreementPackage)
        if stage != "legal_review":
            raise _Rejected("ILLEGAL_TRANSITION", "an executed agreement requires a linked legal review packet", "correct_input")
        if package.packet_digest != links.packet_digest:
            raise _Rejected("PACKET_MISMATCH", "custody candidate must derive from the linked packet", "correct_input")
        data.update({"custody_candidate_digest": package.custody_candidate_digest, "contract_ref": package.contract_ref, "agreement_version": package.agreement_version, "executed_agreement_digest": package.executed_agreement_digest, "custody_record_ref": package.custody_record_ref})
        return "agreement_executed", EngagementLinks.model_validate(data)
    if kind == "link_delivery_plan":
        assert isinstance(package, LinkDeliveryPlanPackage)
        if stage not in {"agreement_executed", "delivery_planned"}:
            raise _Rejected("ILLEGAL_TRANSITION", "a delivery plan requires an executed agreement", "correct_input")
        if package.custody_candidate_digest != links.custody_candidate_digest:
            raise _Rejected("CUSTODY_MISMATCH", "plan must derive from the linked custody candidate", "correct_input")
        data.update({"plan_digest": package.plan_digest, "total_allocated": str(package.total_allocated), "deliverable_refs": list(package.deliverable_refs)})
        return "delivery_planned", EngagementLinks.model_validate(data)
    if kind == "link_deliverable_binding":
        assert isinstance(package, LinkDeliverableBindingPackage)
        if stage not in {"delivery_planned", "delivery_in_progress", "accepted"}:
            raise _Rejected("ILLEGAL_TRANSITION", "bindings require a linked delivery plan", "correct_input")
        if package.plan_digest != links.plan_digest:
            raise _Rejected("PLAN_MISMATCH", "binding must derive from the linked plan", "correct_input")
        if package.obligation_ref not in links.deliverable_refs:
            raise _Rejected("UNKNOWN_DELIVERABLE", "binding cites a deliverable outside the plan", "correct_input")
        if package.binding_digest in links.binding_digests:
            raise _Rejected("BINDING_ALREADY_LINKED", "binding is already linked", "do_not_replay")
        data.update({"binding_digests": sorted([*links.binding_digests, package.binding_digest]), "bound_obligation_refs": sorted(set([*links.bound_obligation_refs, package.obligation_ref]))})
        return ("delivery_in_progress" if stage != "accepted" else "accepted"), EngagementLinks.model_validate(data)
    if kind == "link_accepted_value":
        assert isinstance(package, LinkAcceptedValuePackage)
        if stage not in {"delivery_in_progress", "accepted", "invoiced"}:
            raise _Rejected("ILLEGAL_TRANSITION", "accepted value requires work in progress", "correct_input")
        if package.binding_digest not in links.binding_digests:
            raise _Rejected("BINDING_NOT_LINKED", "accepted value must cite a linked deliverable binding", "correct_input")
        if package.accepted_value_digest in links.accepted_value_digests:
            raise _Rejected("ACCEPTANCE_ALREADY_LINKED", "accepted value is already linked", "do_not_replay")
        accepted_total = links.accepted_total + package.accepted_amount
        invoiceable = links.invoiceable_total + (package.accepted_amount if package.invoice_eligible else Decimal(0))
        if links.total_allocated is not None and accepted_total > links.total_allocated:
            raise _Rejected("ACCEPTED_EXCEEDS_ALLOCATION", "accepted value cannot exceed the plan allocation", "correct_input")
        data.update({"accepted_value_digests": sorted([*links.accepted_value_digests, package.accepted_value_digest]), "accepted_obligation_refs": sorted(set([*links.accepted_obligation_refs, package.obligation_ref])), "accepted_total": str(accepted_total), "invoiceable_total": str(invoiceable)})
        return ("accepted" if stage == "delivery_in_progress" else stage), EngagementLinks.model_validate(data)
    if kind == "propose_invoice":
        assert isinstance(package, ProposeInvoicePackage)
        if stage not in {"accepted", "invoiced"}:
            raise _Rejected("ILLEGAL_TRANSITION", "an invoice requires linked accepted value", "correct_input")
        unknown = [d for d in package.accepted_value_digests if d not in links.accepted_value_digests]
        if unknown:
            raise _Rejected("ACCEPTED_VALUE_NOT_LINKED", "invoice cites accepted value that is not linked", "correct_input")
        already = {d for entry in links.invoices for d in entry.accepted_value_digests}
        if set(package.accepted_value_digests) & already:
            raise _Rejected("ACCEPTED_VALUE_ALREADY_INVOICED", "accepted value can be invoiced once", "correct_input")
        if any(entry.invoice_candidate_ref == package.invoice_candidate_ref for entry in links.invoices):
            raise _Rejected("INVOICE_CANDIDATE_EXISTS", "invoice candidate reference is already used", "do_not_replay")
        remaining = links.invoiceable_total - links.invoiced_total
        if package.amount > remaining:
            raise _Rejected("INVOICE_EXCEEDS_INVOICEABLE", f"invoice amount exceeds uninvoiced accepted value ({remaining})", "correct_input")
        entry = InvoiceLedgerEntry(invoice_candidate_ref=package.invoice_candidate_ref, status="proposed", amount=package.amount, paid_amount=Decimal(0), accepted_value_digests=package.accepted_value_digests)
        data.update({"invoices": [*[e.to_dict() for e in links.invoices], entry.to_dict()], "invoiced_total": str(links.invoiced_total + package.amount)})
        return "invoiced", EngagementLinks.model_validate(data)
    if kind == "link_issued_invoice":
        assert isinstance(package, LinkIssuedInvoicePackage)
        if stage not in {"invoiced", "paid"}:
            raise _Rejected("ILLEGAL_TRANSITION", "issuance requires a proposed invoice", "correct_input")
        entries = [e for e in links.invoices]
        index = next((i for i, e in enumerate(entries) if e.invoice_candidate_ref == package.invoice_candidate_ref), None)
        if index is None or entries[index].status != "proposed":
            raise _Rejected("INVOICE_NOT_PROPOSED", "issued invoice must cite a proposed candidate", "correct_input")
        if package.issued_amount != entries[index].amount:
            raise _Rejected("ISSUED_AMOUNT_MISMATCH", "issued amount must equal the proposed amount", "correct_input")
        updated = entries[index].to_dict()
        updated.update({"invoice_ref": package.invoice_ref, "status": "issued"})
        entries[index] = InvoiceLedgerEntry.model_validate(updated)
        data["invoices"] = [e.to_dict() for e in entries]
        return stage, EngagementLinks.model_validate(data)
    if kind == "link_payment":
        assert isinstance(package, LinkPaymentPackage)
        if stage not in {"invoiced", "paid"}:
            raise _Rejected("ILLEGAL_TRANSITION", "payments require an issued invoice", "correct_input")
        entries = [e for e in links.invoices]
        index = next((i for i, e in enumerate(entries) if e.invoice_ref == package.invoice_ref and e.status in {"issued", "paid"}), None)
        if index is None:
            raise _Rejected("INVOICE_NOT_ISSUED", "payment must cite an issued invoice", "correct_input")
        paid = entries[index].paid_amount + package.amount
        if paid > entries[index].amount:
            raise _Rejected("PAYMENT_EXCEEDS_INVOICE", "payments cannot exceed the invoice amount", "correct_input")
        updated = entries[index].to_dict()
        updated.update({"paid_amount": str(paid), "status": "paid" if paid == entries[index].amount else "issued"})
        entries[index] = InvoiceLedgerEntry.model_validate(updated)
        paid_total = links.paid_total + package.amount
        data.update({"invoices": [e.to_dict() for e in entries], "paid_total": str(paid_total)})
        all_paid = all(e.status == "paid" for e in entries)
        return ("paid" if all_paid else "invoiced"), EngagementLinks.model_validate(data)
    if kind == "close":
        assert isinstance(package, ClosePackage)
        if stage != "paid":
            raise _Rejected("ILLEGAL_TRANSITION", "an engagement closes only when every invoice is paid", "correct_input")
        return "closed", links
    raise _Rejected("ILLEGAL_TRANSITION", f"{kind} is not a known transition", "correct_input")


class ServiceEngagementTransitionCandidate(_StrictModel):
    to_version: int = Field(ge=1, le=MAX_ENGAGEMENT_TRANSITIONS)
    prior_state_digest: Sha256Digest
    to_stage: EngagementStage
    transition_digest: Sha256Digest
    command: ServiceEngagementTransitionCommand

    @model_validator(mode="after")
    def _candidate_is_self_proving(self) -> "ServiceEngagementTransitionCandidate":
        if self.command.expected_version != self.to_version - 1:
            raise ValueError("candidate version must match command revision fence")
        if self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("candidate prior digest must match command state fence")
        if self.transition_digest != _transition_digest(self.to_version, self.prior_state_digest, self.to_stage, self.command):
            raise ValueError("transition digest must commit the exact candidate")
        return self


def _transition_digest(to_version: int, prior: str, to_stage: str, command: ServiceEngagementTransitionCommand) -> str:
    return _stable_digest({"to_version": to_version, "prior_state_digest": prior, "to_stage": to_stage, "request_digest": command.request_digest, "transition_ref": command.transition_ref, "idempotency_key": command.idempotency_key, "kind": command.kind})


def _state_digest(scope: ServiceEngagementScope, history: Sequence[ServiceEngagementTransitionCandidate]) -> str:
    return _stable_digest({"scope": scope.to_dict(), "transitions": [item.transition_digest for item in history]})


def genesis_engagement_state_digest(scope: ServiceEngagementScope | Mapping[str, Any]) -> str:
    return _state_digest(ServiceEngagementScope.model_validate(_detached(scope)), ())


class ServiceEngagementSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.service_engagement_snapshot.v1"] = Field(default=ENGAGEMENT_SNAPSHOT_SCHEMA, alias="schema")
    scope: ServiceEngagementScope
    stage: EngagementStage
    version: int = Field(ge=1, le=MAX_ENGAGEMENT_TRANSITIONS)
    transition_history: tuple[ServiceEngagementTransitionCandidate, ...] = Field(min_length=1, max_length=MAX_ENGAGEMENT_TRANSITIONS)
    links: EngagementLinks
    state_digest: Sha256Digest

    @model_validator(mode="after")
    def _snapshot_is_exact(self) -> "ServiceEngagementSnapshot":
        history = self.transition_history
        if self.version != len(history):
            raise ValueError("snapshot version must equal transition count")
        if [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("transition candidate versions must be contiguous")
        for field_name in ("transition_ref", "idempotency_key", "request_digest"):
            _unique([str(getattr(item.command, field_name)) for item in history], label=f"historical {field_name} values")
        stage: str = "opened"
        links = EngagementLinks()
        prefix: tuple[ServiceEngagementTransitionCandidate, ...] = ()
        for index, candidate in enumerate(history):
            if candidate.command.scope != self.scope:
                raise ValueError("every retained transition must match snapshot scope")
            if candidate.prior_state_digest != _state_digest(self.scope, prefix):
                raise ValueError("historical transition has a discontinuous state digest")
            if index > 0 and _parsed_timestamp(candidate.command.occurred_at) < _parsed_timestamp(history[index - 1].command.occurred_at):
                raise ValueError("historical transitions must be chronological")
            try:
                stage, links = _apply(stage, links, candidate.command)
            except _Rejected as exc:
                raise ValueError(f"historical transition {index + 1} is invalid: {exc.code}") from exc
            if stage != candidate.to_stage:
                raise ValueError("historical transition stage does not match its candidate")
            prefix = (*prefix, candidate)
        if self.stage != stage or self.links != links:
            raise ValueError("snapshot stage and links must be derived from history")
        if self.state_digest != _state_digest(self.scope, history):
            raise ValueError("state_digest must commit the exact snapshot")
        return self


class ServiceEngagementTransitionInput(_StrictModel):
    scope: ServiceEngagementScope
    command: ServiceEngagementTransitionCommand
    current_snapshot: ServiceEngagementSnapshot | None = None

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ServiceEngagementTransitionInput":
        if self.command.scope != self.scope:
            raise ValueError("command scope must exactly match input scope")
        if self.current_snapshot is not None and self.current_snapshot.scope != self.scope:
            raise ValueError("snapshot scope must exactly match input scope")
        return self


class ServiceEngagementRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: BoundedText | None = None

    @model_validator(mode="after")
    def _recovery_is_bounded(self) -> "ServiceEngagementRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match recovery disposition")
        return self


class ServiceEngagementEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    invoice_issued: Literal[False] = False
    payment_moved: Literal[False] = False
    acceptance_recorded: Literal[False] = False
    linked_artifact_mutated: Literal[False] = False
    persistence_written: Literal[False] = False
    connector_effect_executed: Literal[False] = False


class ServiceEngagementTransitionReceipt(_StrictModel):
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    command_kind: TransitionKind
    status: Literal["candidate_materialized", "rejected", "in_doubt"]
    from_version: int = Field(ge=0, le=MAX_ENGAGEMENT_TRANSITIONS)
    to_version: int = Field(ge=0, le=MAX_ENGAGEMENT_TRANSITIONS)
    from_stage: EngagementStage
    to_stage: EngagementStage
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: ServiceEngagementRecovery
    effect_boundary: ServiceEngagementEffectBoundary = Field(default_factory=ServiceEngagementEffectBoundary)

    @model_validator(mode="after")
    def _receipt_is_coherent(self) -> "ServiceEngagementTransitionReceipt":
        if self.status == "candidate_materialized":
            if self.to_version != self.from_version + 1 or self.to_state_digest == self.from_state_digest:
                raise ValueError("materialized candidate must advance exactly one version")
            if self.rejection_code is not None or self.recovery.disposition != "not_required":
                raise ValueError("materialized candidate cannot carry rejection recovery")
        else:
            if self.to_version != self.from_version or self.to_state_digest != self.from_state_digest or self.to_stage != self.from_stage:
                raise ValueError("rejected or in-doubt transition cannot advance")
            if self.rejection_code is None or self.recovery.disposition == "not_required":
                raise ValueError("rejected transition requires a code and recovery route")
        if self.status == "in_doubt" and self.recovery.disposition != "manual_reconciliation":
            raise ValueError("in-doubt transition requires manual reconciliation")
        return self


class ServiceEngagementTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.service_engagement_transition_result.v1"] = Field(default=ENGAGEMENT_RESULT_SCHEMA, alias="schema")
    candidate_validated: bool
    snapshot: ServiceEngagementSnapshot | None = None
    transition_receipt: ServiceEngagementTransitionReceipt
    effect_boundary: ServiceEngagementEffectBoundary = Field(default_factory=ServiceEngagementEffectBoundary)

    @model_validator(mode="after")
    def _result_is_coherent(self) -> "ServiceEngagementTransitionResult":
        receipt = self.transition_receipt
        if self.candidate_validated != (receipt.status == "candidate_materialized"):
            raise ValueError("candidate flag must match transition receipt")
        if self.candidate_validated and self.snapshot is None:
            raise ValueError("validated candidate requires a resulting snapshot")
        if self.snapshot is not None and (self.snapshot.version != receipt.to_version or self.snapshot.state_digest != receipt.to_state_digest or self.snapshot.stage != receipt.to_stage):
            raise ValueError("result snapshot must match transition receipt")
        return self


def materialize_service_engagement_transition(
    inputs: ServiceEngagementTransitionInput | Mapping[str, Any],
) -> ServiceEngagementTransitionResult:
    """Materialize exactly one replay-fenced engagement transition candidate."""

    parsed = ServiceEngagementTransitionInput.model_validate(_detached(inputs))
    snapshot = parsed.current_snapshot
    command = parsed.command
    history = snapshot.transition_history if snapshot is not None else ()
    from_version = snapshot.version if snapshot is not None else 0
    from_stage: str = snapshot.stage if snapshot is not None else "opened"
    from_digest = snapshot.state_digest if snapshot is not None else _state_digest(parsed.scope, ())

    def rejected(exc: _Rejected) -> ServiceEngagementTransitionResult:
        receipt = ServiceEngagementTransitionReceipt(
            transition_ref=command.transition_ref, idempotency_key=command.idempotency_key, request_digest=command.request_digest,
            command_kind=command.kind, status="in_doubt" if exc.in_doubt else "rejected", from_version=from_version, to_version=from_version,
            from_stage=from_stage, to_stage=from_stage, from_state_digest=from_digest, to_state_digest=from_digest,  # type: ignore[arg-type]
            rejection_code=exc.code, recovery=ServiceEngagementRecovery(disposition=exc.recovery, instructions=exc.instructions),
        )
        return ServiceEngagementTransitionResult(candidate_validated=False, snapshot=None, transition_receipt=receipt)

    try:
        if command.host_outcome_report != "reported_certain":
            raise _Rejected("OUTCOME_IN_DOUBT", "Host reported an uncertain outcome; reconcile in Spring before replay.", "manual_reconciliation", in_doubt=True)
        for candidate in history:
            prior = candidate.command
            if prior.request_digest == command.request_digest:
                raise _Rejected("TRANSITION_ALREADY_APPLIED", "This exact transition is already retained; do not replay it.", "do_not_replay")
            if prior.transition_ref == command.transition_ref or prior.idempotency_key == command.idempotency_key:
                raise _Rejected("IDEMPOTENCY_CONFLICT", "A different transition already used this reference or idempotency key.", "manual_reconciliation")
        if command.expected_version != from_version or command.expected_state_digest != from_digest:
            raise _Rejected("STALE_SNAPSHOT", "Command revision or state fence does not match the current snapshot.", "refresh_snapshot")
        if from_version >= MAX_ENGAGEMENT_TRANSITIONS:
            raise _Rejected("TRANSITION_BOUND_REACHED", "This engagement reached its bounded transition count.", "manual_reconciliation")
        if snapshot is not None and _parsed_timestamp(command.occurred_at) < _parsed_timestamp(history[-1].command.occurred_at):
            raise _Rejected("NON_CHRONOLOGICAL_TRANSITION", "Transition time precedes the last retained transition.", "correct_input")
        links = snapshot.links if snapshot is not None else EngagementLinks()
        next_stage, next_links = _apply(from_stage, links, command)
    except _Rejected as exc:
        return rejected(exc)

    candidate = ServiceEngagementTransitionCandidate(
        to_version=from_version + 1, prior_state_digest=from_digest, to_stage=next_stage,  # type: ignore[arg-type]
        transition_digest=_transition_digest(from_version + 1, from_digest, next_stage, command), command=command,
    )
    new_history = (*history, candidate)
    resulting = ServiceEngagementSnapshot(scope=parsed.scope, stage=next_stage, version=from_version + 1, transition_history=new_history, links=next_links, state_digest=_state_digest(parsed.scope, new_history))  # type: ignore[arg-type]
    receipt = ServiceEngagementTransitionReceipt(
        transition_ref=command.transition_ref, idempotency_key=command.idempotency_key, request_digest=command.request_digest, command_kind=command.kind,
        status="candidate_materialized", from_version=from_version, to_version=resulting.version, from_stage=from_stage, to_stage=resulting.stage,  # type: ignore[arg-type]
        from_state_digest=from_digest, to_state_digest=resulting.state_digest, recovery=ServiceEngagementRecovery(disposition="not_required"),
    )
    return ServiceEngagementTransitionResult(candidate_validated=True, snapshot=resulting, transition_receipt=receipt)


# --------------------------------------------------------------------------- #
# Invoice candidate and assessment
# --------------------------------------------------------------------------- #


class InvoiceCandidateLine(_StrictModel):
    description: ShortText
    quantity: Decimal
    unit_amount: Decimal
    accepted_value_digest: Sha256Digest
    obligation_ref: OpaqueRef

    @field_validator("quantity", "unit_amount", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return _decimal(value, field_name=str(info.field_name))


class ServiceEngagementInvoiceCandidate(_StrictModel):
    """An invoice proposal shaped for the existing finance.create_invoice primitive."""

    schema_id: Literal["lightbulb.service_engagement_invoice_candidate.v1"] = Field(default=INVOICE_CANDIDATE_SCHEMA, alias="schema")
    scope: ServiceEngagementScope
    engagement_state_digest: Sha256Digest
    invoice_candidate_ref: OpaqueRef
    customer_ref: OpaqueRef
    currency: CurrencyCode
    lines: tuple[InvoiceCandidateLine, ...] = Field(min_length=1, max_length=200)
    total: Decimal
    due_days: int = Field(ge=0, le=365)
    reference: ShortText
    authoritative: Literal[False] = False
    candidate_digest: Sha256Digest = GENESIS_STATE_DIGEST

    @field_validator("total", mode="before")
    @classmethod
    def _total(cls, value: Any) -> Any:
        return _decimal(value, field_name="total")

    @model_validator(mode="after")
    def _candidate_is_exact(self, info: ValidationInfo) -> "ServiceEngagementInvoiceCandidate":
        if sum((line.quantity * line.unit_amount for line in self.lines), Decimal(0)).quantize(_MONEY_QUANTUM) != self.total:
            raise ValueError("invoice lines must sum to the total")
        if _skip(info):
            return self
        if self.candidate_digest != _sealed_digest(ServiceEngagementInvoiceCandidate, self, "candidate_digest"):
            raise ValueError("candidate_digest must commit the exact candidate")
        return self

    def to_create_invoice_input(self) -> dict[str, Any]:
        return {
            "customer_id": self.customer_ref,
            "line_items": [{"description": line.description, "quantity": str(line.quantity), "unit_amount": str(line.unit_amount)} for line in self.lines],
            "currency": self.currency,
            "reference": self.reference,
            "commit": False,
        }


class AcceptedValueLine(_StrictModel):
    accepted_value_digest: Sha256Digest
    obligation_ref: OpaqueRef
    description: ShortText
    accepted_amount: Decimal

    @field_validator("accepted_amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Any:
        return _decimal(value, field_name="accepted_amount")


class ServiceEngagementInvoiceInput(_StrictModel):
    scope: ServiceEngagementScope
    snapshot: ServiceEngagementSnapshot
    invoice_candidate_ref: OpaqueRef
    accepted_values: tuple[AcceptedValueLine, ...] = Field(min_length=1, max_length=200)
    due_days: int = Field(default=30, ge=0, le=365)
    requested_by_ref: OpaqueRef

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ServiceEngagementInvoiceInput":
        if self.snapshot.scope != self.scope:
            raise ValueError("snapshot scope must exactly match input scope")
        _unique([item.accepted_value_digest for item in self.accepted_values], label="accepted values")
        return self


def propose_service_engagement_invoice(inputs: ServiceEngagementInvoiceInput | Mapping[str, Any]) -> ServiceEngagementInvoiceCandidate:
    """Shape uninvoiced, invoice-eligible accepted value into a finance.create_invoice candidate."""

    parsed = ServiceEngagementInvoiceInput.model_validate(_detached(inputs))
    links = parsed.snapshot.links
    invoiced = {d for entry in links.invoices for d in entry.accepted_value_digests}
    for item in parsed.accepted_values:
        if item.accepted_value_digest not in links.accepted_value_digests:
            raise ValueError(f"accepted value {item.accepted_value_digest[:12]} is not linked to the engagement")
        if item.accepted_value_digest in invoiced:
            raise ValueError(f"accepted value {item.accepted_value_digest[:12]} is already invoiced")
    total = sum((item.accepted_amount for item in parsed.accepted_values), Decimal(0)).quantize(_MONEY_QUANTUM)
    if total > links.invoiceable_total - links.invoiced_total:
        raise ValueError("invoice candidate exceeds uninvoiced invoice-eligible accepted value")
    candidate = {
        "scope": parsed.scope.to_dict(),
        "engagement_state_digest": parsed.snapshot.state_digest,
        "invoice_candidate_ref": parsed.invoice_candidate_ref,
        "customer_ref": parsed.scope.customer_ref,
        "currency": parsed.scope.currency,
        "lines": [
            {"description": item.description, "quantity": "1", "unit_amount": str(item.accepted_amount), "accepted_value_digest": item.accepted_value_digest, "obligation_ref": item.obligation_ref}
            for item in sorted(parsed.accepted_values, key=lambda item: item.accepted_value_digest)
        ],
        "total": str(total),
        "due_days": parsed.due_days,
        "reference": f"{parsed.scope.engagement_ref}:{parsed.invoice_candidate_ref}",
    }
    candidate["candidate_digest"] = _sealed_digest(ServiceEngagementInvoiceCandidate, candidate, "candidate_digest")
    return ServiceEngagementInvoiceCandidate.model_validate(candidate)


class ServiceEngagementAssessment(_StrictModel):
    schema_id: Literal["lightbulb.service_engagement_assessment.v1"] = Field(default=ENGAGEMENT_ASSESSMENT_SCHEMA, alias="schema")
    scope: ServiceEngagementScope
    state_digest: Sha256Digest
    stage: EngagementStage
    version: int = Field(ge=0, le=MAX_ENGAGEMENT_TRANSITIONS)
    quote_total: Decimal | None = None
    total_allocated: Decimal | None = None
    accepted_total: Decimal
    invoiceable_total: Decimal
    invoiced_total: Decimal
    paid_total: Decimal
    uninvoiced_accepted_value: Decimal
    outstanding_receivable: Decimal
    bound_deliverables: int = Field(ge=0)
    accepted_deliverables: int = Field(ge=0)
    unbound_deliverable_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)
    next_actions: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    effect_boundary: ServiceEngagementEffectBoundary = Field(default_factory=ServiceEngagementEffectBoundary)
    assessment_digest: Sha256Digest = GENESIS_STATE_DIGEST

    @field_validator("quote_total", "total_allocated", "accepted_total", "invoiceable_total", "invoiced_total", "paid_total", "uninvoiced_accepted_value", "outstanding_receivable", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _assessment_is_exact(self, info: ValidationInfo) -> "ServiceEngagementAssessment":
        if _skip(info):
            return self
        if self.assessment_digest != _sealed_digest(ServiceEngagementAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


class ServiceEngagementAssessmentInput(_StrictModel):
    scope: ServiceEngagementScope
    snapshot: ServiceEngagementSnapshot | None = None
    requested_by_ref: OpaqueRef

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ServiceEngagementAssessmentInput":
        if self.snapshot is not None and self.snapshot.scope != self.scope:
            raise ValueError("snapshot scope must exactly match input scope")
        return self


_NEXT_ACTION: dict[str, str] = {
    "opened": "link the proposed quote from the commercial lifecycle",
    "quote_proposed": "record quote approval with its approval evidence",
    "quote_approved": "compile the legal review packet (commercial.compile_legal_review_packet)",
    "legal_review": "reconcile the executed agreement into a custody candidate and record Spring custody",
    "agreement_executed": "compile the contract delivery plan (project.compile_contract_delivery_plan)",
    "delivery_planned": "bind deliverables to work packets",
    "delivery_in_progress": "submit builder results for independent acceptance",
    "accepted": "propose an invoice for uninvoiced accepted value",
    "invoiced": "issue the proposed invoice through finance.create_invoice and link payments",
    "paid": "close the engagement",
    "closed": "no action; engagement is closed",
    "cancelled": "no action; engagement is cancelled",
}


def assess_service_engagement(inputs: ServiceEngagementAssessmentInput | Mapping[str, Any]) -> ServiceEngagementAssessment:
    parsed = ServiceEngagementAssessmentInput.model_validate(_detached(inputs))
    snapshot = parsed.snapshot
    links = snapshot.links if snapshot is not None else EngagementLinks()
    stage = snapshot.stage if snapshot is not None else "opened"
    unbound = tuple(sorted(set(links.deliverable_refs) - set(links.bound_obligation_refs)))
    next_actions = [_NEXT_ACTION[stage]]
    if unbound and stage in {"delivery_planned", "delivery_in_progress", "accepted"}:
        next_actions.append(f"bind remaining deliverables: {', '.join(unbound)}")
    uninvoiced = (links.invoiceable_total - links.invoiced_total).quantize(_MONEY_QUANTUM)
    if uninvoiced > 0 and stage in {"accepted", "invoiced", "paid"}:
        next_actions.append(f"uninvoiced accepted value of {uninvoiced} {parsed.scope.currency} is available to invoice")
    assessment = {
        "scope": parsed.scope.to_dict(),
        "state_digest": snapshot.state_digest if snapshot is not None else _state_digest(parsed.scope, ()),
        "stage": stage,
        "version": snapshot.version if snapshot is not None else 0,
        "quote_total": str(links.quote_total) if links.quote_total is not None else None,
        "total_allocated": str(links.total_allocated) if links.total_allocated is not None else None,
        "accepted_total": str(links.accepted_total),
        "invoiceable_total": str(links.invoiceable_total),
        "invoiced_total": str(links.invoiced_total),
        "paid_total": str(links.paid_total),
        "uninvoiced_accepted_value": str(uninvoiced),
        "outstanding_receivable": str((links.invoiced_total - links.paid_total).quantize(_MONEY_QUANTUM)),
        "bound_deliverables": len(links.bound_obligation_refs),
        "accepted_deliverables": len(links.accepted_obligation_refs),
        "unbound_deliverable_refs": list(unbound),
        "next_actions": next_actions,
    }
    assessment["assessment_digest"] = _sealed_digest(ServiceEngagementAssessment, assessment, "assessment_digest")
    return ServiceEngagementAssessment.model_validate(assessment)


__all__ = [
    "ENGAGEMENT_ASSESSMENT_SCHEMA",
    "ENGAGEMENT_COMMAND_SCHEMA",
    "ENGAGEMENT_RESULT_SCHEMA",
    "ENGAGEMENT_SCOPE_SCHEMA",
    "ENGAGEMENT_SNAPSHOT_SCHEMA",
    "GENESIS_STATE_DIGEST",
    "INVOICE_CANDIDATE_SCHEMA",
    "MAX_ENGAGEMENT_TRANSITIONS",
    "SERVICE_ENGAGEMENT_GOLDEN_LOOP",
    "TERMINAL_STAGES",
    "AcceptedValueLine",
    "EngagementLinks",
    "InvoiceCandidateLine",
    "InvoiceLedgerEntry",
    "ServiceEngagementAssessment",
    "ServiceEngagementAssessmentInput",
    "ServiceEngagementEffectBoundary",
    "ServiceEngagementInvoiceCandidate",
    "ServiceEngagementInvoiceInput",
    "ServiceEngagementRecovery",
    "ServiceEngagementScope",
    "ServiceEngagementSnapshot",
    "ServiceEngagementTransitionCandidate",
    "ServiceEngagementTransitionCommand",
    "ServiceEngagementTransitionInput",
    "ServiceEngagementTransitionReceipt",
    "ServiceEngagementTransitionResult",
    "assess_service_engagement",
    "genesis_engagement_state_digest",
    "materialize_service_engagement_transition",
    "propose_service_engagement_invoice",
    "seal_service_engagement_command",
    "service_engagement_command_digest",
]
