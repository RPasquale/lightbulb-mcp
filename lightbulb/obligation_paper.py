"""Replayable agreement clocks and company standing, with effect-dark paper gates.

Legal review packets bind commercial terms; executed custody records bind the
signed document and its two read journals; obligation registers and schedules
bind contractual dates. Standing consumes provenance-bound registry extracts,
explicit operator policy schedules and replayed paid payables. Every consuming
hop revalidates the retained source, including its source plan for engine state.
The platform remains the authority for fetching records, identity and execution.
No registry or insurer connector is implied by these local proofs.
"""

from __future__ import annotations

from calendar import monthrange
from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal
import re

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, LifecycleSpec, OpaqueRef,
    Rejected, Sha256Digest, ShortText, StrictModel, decimal_value, detached,
    iso, parsed, require, seal, sealed_digest, skip_digests, stable_digest, timestamp,
)

OBLIGATION_PAPER_KIND = "obligation_paper"
OBLIGATION_PAPER_GOLDEN_LOOP = "company.blueprint_to_governed_operating_cadence@0.1.0"
OBLIGATION_PAPER_PLAN_SCHEMA = "lightbulb.obligation_paper_plan.v1"
ItemKind = Literal["trade_licence", "business_registration", "annual_return", "director_register", "share_register", "registered_office", "public_liability", "professional_indemnity", "cyber", "workers_compensation", "product_liability", "technician_certification", "right_to_work", "police_check"]
ITEM_KINDS = tuple(ItemKind.__args__)
INSURANCE_KINDS = frozenset({"public_liability", "professional_indemnity", "cyber", "workers_compensation", "product_liability"})
HOLDER_KINDS = frozenset({"technician_certification", "right_to_work", "police_check"})
AGREEMENT_STATUSES = ("executed", "registered", "in_force", "notice_window", "notice_given", "renewed", "amended", "expired", "terminated", "superseded", "reconciliation_required")
AGREEMENT_EVENTS = ("execute", "register_obligations", "activate", "open_notice_window", "give_notice", "renew", "amend", "expire", "terminate", "supersede", "require_reconciliation")
STANDING_STATUSES = ("recorded", "verified", "current", "renewal_due", "action_prepared", "lodged", "lapsed", "surrendered", "superseded")
STANDING_EVENTS = ("record", "verify", "activate", "mark_renewal_due", "prepare_action", "lodge", "confirm_current", "mark_lapsed", "reinstate", "surrender", "supersede")


class ObligationPaperError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code, self.message = code, message
        super().__init__(f"{code}: {message}")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ObligationPaperError(code, message)


def _recovery(code: str) -> str:
    if code in {"NOTICE_NOT_APPROVED", "AUTO_RENEW_ABOVE_THRESHOLD", "UPLIFT_ABOVE_CAP", "COVER_BELOW_CONTRACTED_MINIMUM", "REINSTATE_NOT_AUTHORIZED"}:
        return "await_approval"
    if code in {"SIGNED_DIGEST_MISMATCH", "REGISTRATION_TOO_LATE", "NOTICE_TOO_LATE", "RENEWAL_TERM_MISMATCH", "EVIDENCE_DIGEST_MISMATCH", "RENEWAL_LEAD_MISSED", "COVER_GAP"}:
        return "manual_reconciliation"
    return "correct_input"


def _read(model: Any, source: Any, code: str = "PAPER_SOURCE_INVALID") -> Any:
    try:
        return model.model_validate(detached(source))
    except (ValueError, TypeError) as exc:
        raise ObligationPaperError(code, f"the retained {model.__name__} is invalid") from exc


class RequiredItem(StrictModel):
    kind: ItemKind
    minimum_sum_insured: Decimal | None = None
    renewal_lead_days: int = Field(default=30, ge=0, le=365)
    statutory: bool = False

    @field_validator("minimum_sum_insured", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="minimum_sum_insured")


class ObligationPaperPlan(StrictModel):
    schema_id: Literal["lightbulb.obligation_paper_plan.v1"] = Field(default=OBLIGATION_PAPER_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    jurisdiction: Literal["AU", "CA", "US", "UK", "NZ"]
    required_items: tuple[RequiredItem, ...] = Field(min_length=1, max_length=30)
    min_notice_days_floor: int = Field(default=30, ge=0, le=365)
    auto_renew_threshold: Decimal = Field(default=Decimal("5000.00"), validate_default=True)
    require_review_before_activation: bool = True
    max_days_execution_to_registration: int = Field(default=14, ge=0, le=365)
    workforce_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("auto_renew_threshold", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="auto_renew_threshold")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Any:
        if len({item.kind for item in self.required_items}) != len(self.required_items):
            raise ValueError("required item kinds must be unique")
        if not skip_digests(info) and self.plan_digest != sealed_digest(type(self), self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact paper policy")
        return self


def compile_obligation_paper(company_ref: str, *, currency: str, jurisdiction: str, workforce_plan: Any | None = None, overrides: Mapping[str, Any] | None = None) -> ObligationPaperPlan:
    # Operational defaults, not a claim that every item is legally mandatory.
    items = [{"kind": kind, "renewal_lead_days": 60 if kind in INSURANCE_KINDS else 45 if kind == "annual_return" else 30, "statutory": kind in {"business_registration", "annual_return"}} for kind in ("business_registration", "annual_return", "registered_office", "public_liability", "professional_indemnity", "cyber", "workers_compensation")]
    binding = {}
    if workforce_plan is not None:
        from lightbulb.company_workforce import WorkforcePlan
        binding["workforce_plan_digest"] = _read(WorkforcePlan, workforce_plan).plan_digest
    return seal(ObligationPaperPlan, {"company_ref": company_ref, "currency": currency.upper(), "jurisdiction": jurisdiction, "required_items": items, **binding, **dict(overrides or {})}, "plan_digest")


class _ExecutedFacts(StrictModel):
    agreement_ref: OpaqueRef
    signed_document_sha256: Sha256Digest
    observed_completed_at: str
    project_id: str
    envelope_journal_ref: OpaqueRef
    document_journal_ref: OpaqueRef
    envelope_receipt_digest: Sha256Digest
    document_receipt_digest: Sha256Digest

    @field_validator("observed_completed_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="observed_completed_at")


class _FormationFacts(StrictModel):
    company_ref: OpaqueRef
    name: ShortText
    country: Literal["AU", "CA"]
    region: ShortText
    provisioning: ShortText
    certificate_sha256: Sha256Digest


class PaperArtifact(StrictModel):
    """Safe custody projection; platform identities never enter engine history."""
    schema_id: Literal["lightbulb.paper_artifact.v1"] = Field(default="lightbulb.paper_artifact.v1", alias="schema")
    kind: Literal["executed_record", "formation"]
    source_schema: ShortText
    facts: dict[str, Any]
    source_digest: Sha256Digest
    artifact_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Any:
        (_ExecutedFacts if self.kind == "executed_record" else _FormationFacts).model_validate(self.facts)
        expected_schema = "lightbulb.executed_commercial_agreement_record.v1" if self.kind == "executed_record" else "lightbulb.company_formation_result"
        if self.source_schema != expected_schema or self.source_digest == GENESIS_DIGEST:
            raise ValueError("paper source must name the exact non-genesis custody artifact")
        if not skip_digests(info) and self.artifact_digest != sealed_digest(type(self), self, "artifact_digest"):
            raise ValueError("artifact_digest must commit the exact custody projection")
        return self


class PolicyScheduleInput(StrictModel):
    schema_id: Literal["lightbulb.operator_policy_schedule.v1"] = Field(default="lightbulb.operator_policy_schedule.v1", alias="schema")
    operator_supplied: Literal[True] = True
    company_ref: OpaqueRef
    policy_ref: OpaqueRef
    insurer_ref: OpaqueRef
    kind: ItemKind
    currency: CurrencyCode
    limit: Decimal
    excess: Decimal
    period_start: str
    period_end: str
    premium: Decimal
    document_sha256: Sha256Digest
    holder_ref: OpaqueRef | None = None

    @field_validator("limit", "excess", "premium", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("period_start", "period_end")
    @classmethod
    def _stamp(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self) -> Any:
        if parsed(self.period_end) <= parsed(self.period_start):
            raise ValueError("policy end must follow its start")
        return self


class RegistryExtract(StrictModel):
    company_ref: OpaqueRef
    item_ref: OpaqueRef
    kind: ItemKind
    registration_ref: OpaqueRef
    jurisdiction: Literal["AU", "CA", "US", "UK", "NZ"]
    current: bool
    period_start: str
    period_end: str
    holder_ref: OpaqueRef | None = None
    lodgement_ref: OpaqueRef | None = None

    @field_validator("period_start", "period_end")
    @classmethod
    def _stamp(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _dates(self) -> Any:
        if parsed(self.period_end) <= parsed(self.period_start):
            raise ValueError("registry end must follow start")
        return self


class PaperReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=60)
    entity_ref: OpaqueRef | None = None
    paper_scope: dict[str, Any] | None = None
    execution: dict[str, Any] | None = None
    packet: dict[str, Any] | None = None
    review: dict[str, Any] | None = None
    validation: dict[str, Any] | None = None
    obligation_register: dict[str, Any] | None = Field(default=None, alias="register")
    schedule: dict[str, Any] | None = None
    notice_execution: dict[str, Any] | None = None
    notice_request: dict[str, Any] | None = None
    policy: dict[str, Any] | None = None
    registry_provenance: dict[str, Any] | None = None
    registry_extract: dict[str, Any] | None = None
    formation: dict[str, Any] | None = None
    premium_state: dict[str, Any] | None = None
    premium_plan: dict[str, Any] | None = None
    workforce_plan: dict[str, Any] | None = None
    agreements: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    authorization_proof: dict[str, Any] | None = None
    lodgement_ref: OpaqueRef | None = None
    lodged_at: str | None = None
    lodged_amount: Decimal | None = None
    lodged_by: OpaqueRef | None = None
    detail: ShortText | None = None

    @field_validator("lodged_amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="lodged_amount")

    @field_validator("lodged_at")
    @classmethod
    def _stamp(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="lodged_at")


class AgreementLedger(StrictModel):
    agreement_ref: OpaqueRef | None = None
    contract_ref: OpaqueRef | None = None
    company_ref: OpaqueRef | None = None
    counterparty_ref: OpaqueRef | None = None
    entity_ref: OpaqueRef | None = None
    project_id: str | None = None
    tenant_ref: OpaqueRef | None = None
    project_ref: OpaqueRef | None = None
    signed_document_sha256: Sha256Digest | None = None
    executed_at: str | None = None
    effective_at: str | None = None
    expires_at: str | None = None
    notice_window_opens_at: str | None = None
    notice_due_at: str | None = None
    notice_channel: str | None = None
    notice_address_ref: OpaqueRef | None = None
    notice_sent_at: str | None = None
    term_months: int | None = None
    notice_days: int | None = None
    invoicing_trigger: str | None = None
    termination_for_convenience: bool = False
    termination_notice_days: int | None = None
    auto_renew: bool = False
    amount: Decimal = Decimal("0.00")
    uplift_cap_percent: Decimal | None = None
    review_digest: Sha256Digest | None = None
    packet_digest: Sha256Digest | None = None
    register_digest: Sha256Digest | None = None
    schedule_digest: Sha256Digest | None = None
    insurance_minima: dict[str, Decimal] = Field(default_factory=dict)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple)
    outcome: str = "open"

    @field_validator("amount", "uplift_cap_percent", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("insurance_minima", mode="before")
    @classmethod
    def _minima(cls, value: Any) -> dict[str, Decimal]:
        return {key: decimal_value(item, field_name=key) for key, item in dict(value or {}).items()}


class StandingLedger(StrictModel):
    company_ref: OpaqueRef | None = None
    tenant_ref: OpaqueRef | None = None
    project_ref: OpaqueRef | None = None
    project_id: str | None = None
    entity_ref: OpaqueRef | None = None
    item_ref: OpaqueRef | None = None
    kind: ItemKind | None = None
    holder_ref: OpaqueRef | None = None
    insurer_ref: OpaqueRef | None = None
    registration_ref: OpaqueRef | None = None
    jurisdiction: str | None = None
    period_start: str | None = None
    period_end: str | None = None
    previous_period_end: str | None = None
    renewal_due_at: str | None = None
    limit: Decimal = Decimal("0.00")
    premium: Decimal = Decimal("0.00")
    excess: Decimal = Decimal("0.00")
    document_sha256: Sha256Digest | None = None
    registry_digest: Sha256Digest | None = None
    premium_digest: Sha256Digest | None = None
    premium_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple)
    lodgement_ref: OpaqueRef | None = None
    lodged_amount: Decimal = Decimal("0.00")
    lapsed_at: str | None = None
    gap_recorded: bool = False
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple)
    outcome: str = "open"

    @field_validator("limit", "premium", "excess", "lodged_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class PaperEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    provider_read: Literal[False] = False
    message_sent: Literal[False] = False
    filing_lodged: Literal[False] = False
    policy_issued: Literal[False] = False


def execute_receipt(executed_agreement_record: Any) -> dict[str, Any]:
    """Project a fetched platform record; its opaque custody ref remains authoritative.

    The platform record has no contract_ref and no portable digest algorithm.
    Contract binding is therefore supplied by the reviewed packet at registration.
    Platform identities are deliberately not retained in portable engine state.
    """
    from lightbulb.executed_commercial_agreement_custody import ExecutedCommercialAgreementRecord
    source = _read(ExecutedCommercialAgreementRecord, executed_agreement_record)
    facts = {key: getattr(source, key) for key in ("agreement_ref", "signed_document_sha256", "observed_completed_at", "project_id")}
    facts.update({"envelope_journal_ref": source.envelope_observation_journal_id, "document_journal_ref": source.document_observation_journal_id, "envelope_receipt_digest": source.envelope_observation_receipt_sha256, "document_receipt_digest": source.document_observation_receipt_sha256})
    artifact = seal(PaperArtifact, {"kind": "executed_record", "source_schema": source.schema_id, "source_digest": source.record_digest, "facts": facts}, "artifact_digest")
    return {"execution": artifact.to_dict(), "evidence_refs": [source.agreement_ref, f"read:{facts['envelope_journal_ref']}", f"read:{facts['document_journal_ref']}"]}


def review_clearance(legal_review_outcome: Any, validation: Any) -> dict[str, Any]:
    from lightbulb.commercial_legal_handoff import LegalReviewOutcome, LegalReviewOutcomeValidation
    review = _read(LegalReviewOutcome, legal_review_outcome)
    checked = _read(LegalReviewOutcomeValidation, validation)
    _require(not review.unresolved_deviations, "UNRESOLVED_DEVIATION", "all deviations must be resolved before activation")
    _require(checked.outcome_digest == review.outcome_digest and checked.packet_digest == review.packet_digest and checked.accepted and not checked.commercial_revision_required and not checked.outstanding_approvals and review.signature_readiness == "ready" and review.disposition in {"approved", "approved_with_deviations"}, "UNRESOLVED_DEVIATION", "the exact legal outcome requires accepted clearance with no outstanding revision or approval")
    return {"review": review.to_dict(), "validation": checked.to_dict(), "evidence_refs": [f"review:{review.outcome_digest[:16]}"]}


def terms_receipt(commercial_term_sheet: Any, *, packet: Any) -> dict[str, Any]:
    """An unsealed term sheet is accepted only when an exact sealed packet retains it."""
    from lightbulb.commercial_legal_handoff import CommercialTermSheet, LegalReviewPacket
    terms, source = _read(CommercialTermSheet, commercial_term_sheet), _read(LegalReviewPacket, packet)
    _require(terms == source.commercial_terms, "RENEWAL_TERM_MISMATCH", "terms must be the exact reviewed packet terms")
    return {"packet": source.to_dict(), "evidence_refs": [f"terms:{source.packet_digest[:16]}"]}


def obligations_receipt(register: Any, schedule: Any) -> dict[str, Any]:
    from lightbulb.contract_obligations import ObligationRegister, ObligationSchedule
    source, dates = _read(ObligationRegister, register, "OBLIGATIONS_NOT_REGISTERED"), _read(ObligationSchedule, schedule, "OBLIGATIONS_NOT_REGISTERED")
    _require(dates.register_digest == source.register_digest and dates.scope == source.scope and dates.agreement_version == source.agreement.version and not source.rejections and not dates.truncations, "OBLIGATIONS_NOT_REGISTERED", "register and complete schedule must bind the same agreement and scope")
    definitions = {item.obligation_ref: item for item in source.definitions}
    _require(all(item.obligation_ref in definitions and item.definition_digest == definitions[item.obligation_ref].definition_digest for item in dates.instances), "OBLIGATIONS_NOT_REGISTERED", "each scheduled instance must bind its registered definition")
    return {"register": source.to_dict(), "schedule": dates.to_dict(), "evidence_refs": [f"register:{source.register_digest[:16]}", f"schedule:{dates.schedule_digest[:16]}"]}


def notice_receipt(execution_receipt: Any, *, request: Any) -> dict[str, Any]:
    from lightbulb.company_execution_bridge import ExecutionReceipt
    from lightbulb.connector_execution import ConnectorExecutionRequest
    raw = dict(detached(execution_receipt))
    _require(bool(raw.get("approval_ref") and raw.get("approval_receipt_digest")), "NOTICE_NOT_APPROVED", "notice requires the platform-approved write")
    execution = _read(ExecutionReceipt, raw, "NOTICE_NOT_SENT")
    call = _read(ConnectorExecutionRequest, request, "NOTICE_NOT_SENT")
    _require(execution.schema_id == "lightbulb.engine_execution_receipt.v1" and execution.effect == "write" and execution.tool in {"gmail.send_email", "microsoft.send_email"}, "NOTICE_NOT_SENT", "a completed supported email write must prove notice was sent")
    _require(call.custody_fingerprint() == execution.request_digest and call.tool == execution.tool and str(call.scope.project_id) == execution.project_id and call.approval_required and (call.approval_ref is None or call.approval_ref == execution.approval_ref), "NOTICE_NOT_SENT", "the exact approved notice request must bind the execution")
    # Request arguments carry only opaque recipient/document refs, never message bodies.
    _require(set(call.arguments) <= {"agreement_ref", "document_sha256", "recipient_ref"} and all(call.arguments.get(key) for key in ("agreement_ref", "document_sha256", "recipient_ref")), "NOTICE_NOT_SENT", "notice requests retain exact agreement, document and recipient references")
    return {"notice_execution": execution.to_dict(), "notice_request": call.model_dump(mode="json", by_alias=True, exclude_none=True), "evidence_refs": [f"notice:{execution.journal_ref}"]}


def formation_receipt(company_formation_result: Any, certificate_digest: str) -> dict[str, Any]:
    from lightbulb.company_formation import CompanyFormationResult, EXPECTED_RESIDENCY_REGION
    _require(isinstance(company_formation_result, CompanyFormationResult), "PAPER_SOURCE_INVALID", "formation must be the parsed platform formation result")
    source = company_formation_result
    _require(bool(source.company_id) and source.region_matches_country and source.region == EXPECTED_RESIDENCY_REGION.get(source.country) and source.provisioning in {"COMPLETE", "COMPLETED", "READY", "complete", "completed", "ready", "provisioned"} and source.workspace_ready, "REGISTRY_CONFIRMATION_MISSING", "formation must prove the expected region and completed provisioning")
    facts = {"company_ref": f"formed:{stable_digest(source.company_id)[:32]}", "name": source.name, "country": source.country, "region": source.region, "provisioning": source.provisioning, "certificate_sha256": certificate_digest}
    artifact = seal(PaperArtifact, {"kind": "formation", "source_schema": "lightbulb.company_formation_result", "facts": facts, "source_digest": stable_digest(source.to_dict())}, "artifact_digest")
    return {"formation": artifact.to_dict(), "evidence_refs": [f"formation:{artifact.artifact_digest[:16]}"]}


def cover_receipt(policy_schedule_input: Any) -> dict[str, Any]:
    source = _read(PolicyScheduleInput, policy_schedule_input)
    _require(source.kind in INSURANCE_KINDS, "PAPER_SOURCE_INVALID", "a policy schedule names an insurance cover kind")
    return {"policy": source.to_dict(), "evidence_refs": [f"operator-policy:{source.policy_ref}"]}


def premium_proof(payable_case_state: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE
    try:
        plan, state = PAYABLES_CHAIN_LIFECYCLE.bind(source_plan, payable_case_state)
    except (ValueError, TypeError) as exc:
        raise ObligationPaperError("PREMIUM_NOT_PAID", "premium requires a replayable payables case and its plan") from exc
    _require(state.status in {"paid", "cleared"} and state.ledger.applied_amount == state.ledger.amount and state.ledger.applied_amount > 0, "PREMIUM_NOT_PAID", "an invoice or partial payment does not prove premium paid")
    return {"premium_state": state.to_dict(), "premium_plan": plan.to_dict(), "evidence_refs": [f"premium:{state.state_digest[:16]}"]}


def registry_receipt(provenance: Any, extract: Any) -> dict[str, Any]:
    from lightbulb.company_execution_bridge import ObservationProvenance
    read = _read(ObservationProvenance, provenance, "REGISTRY_CONFIRMATION_MISSING")
    source = _read(RegistryExtract, extract, "REGISTRY_CONFIRMATION_MISSING")
    _require((read.source_tool == "host.registry_extract" and read.lane == "host_read") or (read.source_tool == "gmail.get_thread" and read.lane == "governed_read"), "REGISTRY_CONFIRMATION_MISSING", "registry confirmations arrive through the named host lane or governed registry email")
    _require(read.output_digest == stable_digest(detached(extract)) and read.provenance_digest != GENESIS_DIGEST, "EVIDENCE_DIGEST_MISMATCH", "the extract must be the exact read output")
    _require(source.current, "REGISTRY_CONFIRMATION_MISSING", "the registry must confirm current standing")
    return {"registry_provenance": read.to_dict(), "registry_extract": source.to_dict(), "evidence_refs": [f"registry:{read.observation_ref}"]}


def filing_receipt(*, lodgement_ref: str, lodged_at: str, amount: Any, lodged_by: str, evidence_refs: Sequence[str] = ()) -> dict[str, Any]:
    """Operator-held lodgement evidence; the platform holds no filing write."""
    from lightbulb.compliance_calendar import filing_receipt as filing
    _require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{3,199}", lodgement_ref.strip())), "LODGEMENT_REF_INVALID", "lodgement reference must be a portable authority receipt number")
    return filing(lodgement_ref=lodgement_ref, lodged_at=lodged_at, amount=amount, lodged_by=lodged_by, evidence_refs=evidence_refs)


def _authority(plan: Any, data: dict[str, Any], command: Any, category: str, amount: Any, code: str) -> None:
    from lightbulb.authority_matrix import verify_authorization
    require(command.receipt.authorization_proof is not None, code, "fetch an authorization proof for this exact paper transition", "await_approval")
    try:
        verify_authorization(command.receipt.authorization_proof, category=category, amount=amount, currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=data.get("entity_ref"))
    except (ValueError, TypeError) as exc:
        raise Rejected(code, "the proof must authorize the exact paper transition", "await_approval") from exc


def _month_end(start: str, months: int) -> str:
    date = parsed(start)
    year, month = divmod(date.year * 12 + date.month - 1 + months, 12)
    return iso(date.replace(year=year, month=month + 1, day=min(date.day, monthrange(year, month + 1)[1])))


def _registration(plan: Any, data: dict[str, Any], r: Any, at: str) -> dict[str, Any]:
    from lightbulb.commercial_legal_handoff import LegalReviewPacket
    require(r.packet is not None and r.obligation_register is not None and r.schedule is not None, "OBLIGATIONS_NOT_REGISTERED", "register the sealed obligations, schedule and reviewed terms")
    packet = _read(LegalReviewPacket, r.packet, "OBLIGATIONS_NOT_REGISTERED")
    obligations_receipt(r.obligation_register, r.schedule)
    register, schedule, terms = r.obligation_register, r.schedule, packet.commercial_terms
    agreement = register["agreement"]
    require(register["scope"]["company_ref"] == plan.company_ref and agreement["agreement_ref"] == data["agreement_ref"] and agreement["agreement_digest"] == data["signed_document_sha256"], "OBLIGATIONS_NOT_REGISTERED", "the register must bind this signed agreement and company")
    require(packet.scope.commercial.company_ref == plan.company_ref and terms.billing.currency == plan.currency, "PAPER_SCOPE_MISMATCH", "the packet must bind the paper company and currency")
    require(all(str(register["scope"][key]) == str(data.get(key)) == str(getattr(packet.scope.commercial, key)) for key in ("tenant_ref", "project_ref", "project_id")), "PAPER_SCOPE_MISMATCH", "the contract sources must share the paper tenant and project scope")
    require(not terms.renewal.auto_renew or terms.renewal.notice_days >= plan.min_notice_days_floor, "NOTICE_TOO_LATE", "the signed auto-renewal notice period is shorter than the paper policy permits; review the contract without replacing its clock", "manual_reconciliation")
    require(parsed(at) >= parsed(data["executed_at"]) and parsed(at) <= parsed(data["executed_at"]) + timedelta(days=plan.max_days_execution_to_registration), "REGISTRATION_TOO_LATE", "register the agreement within the execution-to-registration window", "manual_reconciliation")
    expiry = agreement.get("expires_at")
    require(expiry is not None and expiry == _month_end(agreement["effective_at"], terms.renewal.term_months), "RENEWAL_TERM_MISMATCH", "the agreement dates must match the contractual term months", "manual_reconciliation")
    reviewed_digest = None
    if r.review is not None and r.validation is not None:
        review_clearance(r.review, r.validation)
        require(r.review["packet_digest"] == packet.packet_digest, "SIGNED_DIGEST_MISMATCH", "review and terms must bind the same packet", "manual_reconciliation")
        require(any(item["artifact_digest"] == data["signed_document_sha256"] for item in r.review["reviewed_documents"]), "SIGNED_DIGEST_MISMATCH", "the signed document must equal a retained reviewed document digest", "manual_reconciliation")
        reviewed_digest = r.review["outcome_digest"]
    notice_due = iso(parsed(expiry) - timedelta(days=terms.renewal.notice_days))
    notices = [item for item in schedule.get("instances", ()) if item.get("kind") == "notice"]
    if not notices:
        notice_refs = {item["obligation_ref"] for item in register["definitions"] if item["kind"] == "notice"}
        notices = [item for item in schedule.get("instances", ()) if item["obligation_ref"] in notice_refs]
    require(bool(notices) and all(item.get("notice_window_opens_at") is not None and parsed(item["due_at"]) <= parsed(notice_due) for item in notices), "OBLIGATIONS_NOT_REGISTERED", "the schedule must retain the contractual notice deadline and opening window")
    scheduled_due, window_opens = min(item["due_at"] for item in notices), min(item["notice_window_opens_at"] for item in notices)
    counterparties = {definition["counterparty_ref"] for definition in register["definitions"]}
    require(len(counterparties) == 1, "OBLIGATIONS_NOT_REGISTERED", "a registered agreement binds exactly one counterparty")
    minima: dict[str, str] = {}
    for definition in register["definitions"]:
        for criterion in definition["criteria"]:
            kind = criterion["evidence_kind"].removeprefix("insurance:")
            if definition["direction"] == "owed_by_company" and kind in INSURANCE_KINDS and criterion.get("required", True) and criterion.get("measure") == "quantity":
                require(criterion.get("unit") == plan.currency, "PAPER_SCOPE_MISMATCH", "contractual cover minima must use the plan currency")
                minima[kind] = str(max(Decimal(minima.get(kind, "0")), decimal_value(criterion["target_quantity"], field_name="contracted cover")))
    return {"contract_ref": packet.contract_ref, "counterparty_ref": counterparties.pop(), "effective_at": agreement["effective_at"], "expires_at": expiry, "notice_due_at": scheduled_due, "notice_window_opens_at": window_opens, "notice_days": terms.renewal.notice_days, "notice_channel": terms.notice.channel, "notice_address_ref": terms.notice.address_ref, "invoicing_trigger": terms.billing.invoicing_trigger, "termination_for_convenience": terms.termination.for_convenience, "termination_notice_days": terms.termination.notice_days, "term_months": terms.renewal.term_months, "amount": str(decimal_value(terms.billing.total, field_name="contract amount")), "auto_renew": terms.renewal.auto_renew, "uplift_cap_percent": None if terms.renewal.price_change_cap_ratio is None else str(terms.renewal.price_change_cap_ratio * 100), "packet_digest": packet.packet_digest, "review_digest": reviewed_digest, "register_digest": register["register_digest"], "schedule_digest": schedule["schedule_digest"], "insurance_minima": minima}


def _apply_agreement(plan: Any, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    try:
        if event == "execute":
            source = _read(PaperArtifact, r.execution)
            require(source.kind == "executed_record" and source.source_schema == "lightbulb.executed_commercial_agreement_record.v1", "PAPER_SOURCE_INVALID", "execution must retain a projected executed agreement record")
            facts = source.facts
            require(bool(facts.get("envelope_journal_ref") and facts.get("document_journal_ref") and facts.get("envelope_receipt_digest") and facts.get("document_receipt_digest")), "PAPER_SOURCE_INVALID", "execution must retain both governed read journals")
            require(parsed(facts["observed_completed_at"]) <= parsed(at), "PAPER_SOURCE_INVALID", "execution observation cannot be in the future")
            require(r.paper_scope is not None, "PAPER_SCOPE_MISMATCH", "open paper through its scoped wrapper")
            data.update({"tenant_ref": r.paper_scope["tenant_ref"], "project_ref": r.paper_scope["project_ref"], "entity_ref": r.entity_ref, "agreement_ref": facts["agreement_ref"], "signed_document_sha256": facts["signed_document_sha256"], "executed_at": facts["observed_completed_at"], "company_ref": plan.company_ref, "project_id": facts["project_id"], "source_digests": [source.artifact_digest]})
        elif event == "register_obligations":
            data.update(_registration(plan, data, r, at))
        elif event == "activate":
            require(bool(data.get("register_digest") and data.get("schedule_digest")), "OBLIGATIONS_NOT_REGISTERED", "activation needs a sealed obligation register and schedule")
            require(not plan.require_review_before_activation or bool(data.get("review_digest")), "UNRESOLVED_DEVIATION", "activation requires accepted legal review")
            require(parsed(data["effective_at"]) <= parsed(at) < parsed(data["expires_at"]), "EXPIRY_IN_PAST", "activation must be within the signed term")
        elif event == "open_notice_window":
            require(parsed(at) >= parsed(data["notice_window_opens_at"]), "RENEWAL_TOO_EARLY", "the contract's scheduled notice window has not opened")
            require(parsed(at) <= parsed(data["notice_due_at"]), "NOTICE_TOO_LATE", "the contractual notice deadline has passed", "manual_reconciliation")
        elif event == "give_notice":
            require(data["notice_channel"] == "email", "NOTICE_CHANNEL_MISMATCH", "email execution cannot satisfy another contractual channel")
            require(r.notice_execution is not None, "NOTICE_NOT_SENT", "notice requires completed execution evidence")
            notice_receipt(r.notice_execution, request=r.notice_request)
            execution, args = r.notice_execution, r.notice_request["arguments"]
            require(args["agreement_ref"] == data["agreement_ref"] and args["document_sha256"] == data["signed_document_sha256"] and args["recipient_ref"] == data["notice_address_ref"] and execution["project_id"] == data["project_id"], "NOTICE_NOT_SENT", "notice must target this agreement, signed document, project and contractual recipient")
            require(all(str(r.notice_request["scope"][key]) == str(data[key]) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")), "NOTICE_NOT_SENT", "notice request must bind the exact paper scope")
            require(parsed(execution["completed_at"]) <= parsed(at) and parsed(data["notice_window_opens_at"]) <= parsed(execution["completed_at"]) <= parsed(data["notice_due_at"]), "NOTICE_TOO_LATE", "sent notice must fall in the contractual window", "manual_reconciliation")
            _authority(plan, data, command, "commitment", data["amount"], "NOTICE_NOT_APPROVED")
            data["notice_sent_at"] = execution["completed_at"]
        elif event in {"renew", "amend"}:
            require(r.execution is not None, "SIGNED_DIGEST_MISMATCH", "the revised signed agreement must be retained", "manual_reconciliation")
            source = _read(PaperArtifact, r.execution)
            require(source.kind == "executed_record" and source.artifact_digest not in data["source_digests"] and source.facts["signed_document_sha256"] != data["signed_document_sha256"], "SIGNED_DIGEST_MISMATCH", "a renewal or amendment needs distinct signed custody", "manual_reconciliation")
            candidate = {**data, "agreement_ref": source.facts["agreement_ref"], "signed_document_sha256": source.facts["signed_document_sha256"], "executed_at": source.facts["observed_completed_at"]}
            revised = _registration(plan, candidate, r, at)
            require(revised["contract_ref"] == data["contract_ref"], "RENEWAL_TERM_MISMATCH", "a renewal or amendment must retain its original contract", "manual_reconciliation")
            if event == "renew":
                require(revised["term_months"] == data["term_months"] and revised["effective_at"] == data["expires_at"] and revised["notice_days"] == data["notice_days"], "RENEWAL_TERM_MISMATCH", "renewal dates and notice terms must agree with the original contract", "manual_reconciliation")
                if data["auto_renew"] and Decimal(revised["amount"]) > plan.auto_renew_threshold:
                    _authority(plan, data, command, "commitment", revised["amount"], "AUTO_RENEW_ABOVE_THRESHOLD")
                cap = Decimal(data.get("uplift_cap_percent") or "0")
                if Decimal(revised["amount"]) > (Decimal(data["amount"]) * (1 + cap / 100)).quantize(MONEY_QUANTUM):
                    _authority(plan, data, command, "commitment", revised["amount"], "UPLIFT_ABOVE_CAP")
            else:
                _authority(plan, data, command, "commitment", revised["amount"], "AUTO_RENEW_ABOVE_THRESHOLD")
            data.update(candidate)
            data.update(revised)
            data["source_digests"] = [*data["source_digests"], source.artifact_digest]
        elif event == "expire":
            require(parsed(at) >= parsed(data["expires_at"]), "RENEWAL_TOO_EARLY", "an agreement cannot expire before its signed expiry")
            data["outcome"] = "expired"
        elif event == "terminate":
            require(bool(data.get("notice_sent_at")), "NOTICE_NOT_SENT", "termination follows notice proven sent through the contractual channel")
            effective = parsed(data["expires_at"])
            if data.get("termination_for_convenience"):
                effective = min(effective, parsed(data["notice_sent_at"]) + timedelta(days=data.get("termination_notice_days") or 0))
            require(parsed(at) >= effective, "RENEWAL_TOO_EARLY", "termination takes effect at expiry, or after the contract's own convenience notice period")
            data["outcome"] = "terminated"
        elif event in {"supersede", "require_reconciliation"}:
            data["outcome"] = next_status
    except ObligationPaperError as exc:
        raise Rejected(exc.code, exc.message, _recovery(exc.code)) from exc
    return next_status, data


def _item(plan: Any, kind: str) -> RequiredItem:
    return next((item for item in plan.required_items if item.kind == kind), RequiredItem(kind=kind, renewal_lead_days=60 if kind in INSURANCE_KINDS else 30))


def _standing_source(plan: Any, r: Any, at: str) -> dict[str, Any]:
    if r.policy is not None:
        cover_receipt(r.policy)
        source = _read(PolicyScheduleInput, r.policy)
        require(source.company_ref == plan.company_ref and source.currency == plan.currency, "PAPER_SCOPE_MISMATCH", "cover must belong to the company and currency")
        result = {"item_ref": source.policy_ref, "kind": source.kind, "holder_ref": source.holder_ref, "insurer_ref": source.insurer_ref, "period_start": source.period_start, "period_end": source.period_end, "limit": str(source.limit), "premium": str(source.premium), "excess": str(source.excess), "document_sha256": source.document_sha256, "registry_digest": None}
    else:
        require(r.registry_provenance is not None and r.registry_extract is not None, "REGISTRY_CONFIRMATION_MISSING", "standing needs a registry confirmation")
        registry_receipt(r.registry_provenance, r.registry_extract)
        source = _read(RegistryExtract, r.registry_extract)
        require(source.company_ref == plan.company_ref and source.jurisdiction == plan.jurisdiction, "PAPER_SCOPE_MISMATCH", "registry jurisdiction and company must match the plan")
        require(parsed(r.registry_provenance["completed_at"]) <= parsed(at), "REGISTRY_CONFIRMATION_MISSING", "registry evidence cannot be from the future")
        result = {"item_ref": source.item_ref, "kind": source.kind, "holder_ref": source.holder_ref, "registration_ref": source.registration_ref, "jurisdiction": source.jurisdiction, "period_start": source.period_start, "period_end": source.period_end, "document_sha256": r.registry_provenance["output_digest"], "registry_digest": r.registry_provenance["provenance_digest"]}
        if r.formation is not None:
            formation = _read(PaperArtifact, r.formation)
            require(formation.kind == "formation" and formation.facts["country"] == plan.jurisdiction and formation.facts["certificate_sha256"] == result["document_sha256"], "EVIDENCE_DIGEST_MISMATCH", "formation certificate must equal the registry read output digest", "manual_reconciliation")
    require(parsed(result["period_end"]) > parsed(at), "EXPIRY_IN_PAST", "paper expires after the transition time")
    result["renewal_due_at"] = iso(parsed(result["period_end"]) - timedelta(days=_item(plan, result["kind"]).renewal_lead_days))
    return result


def _check_holder(plan: Any, data: dict[str, Any], r: Any) -> None:
    if data["kind"] not in HOLDER_KINDS:
        return
    from lightbulb.company_workforce import WorkforcePlan
    require(r.workforce_plan is not None and data.get("holder_ref") is not None, "HOLDER_NOT_ON_ROSTER", "person-held paper must bind a sealed workforce roster")
    workforce = _read(WorkforcePlan, r.workforce_plan, "HOLDER_NOT_ON_ROSTER")
    require(workforce.currency == plan.currency and workforce.plan_digest == plan.workforce_plan_digest and workforce.roster.worker(data["holder_ref"]) is not None, "HOLDER_NOT_ON_ROSTER", "certificate holder must be on the exact roster adopted by the paper plan")


def _check_cover(plan: Any, data: dict[str, Any], r: Any, at: str) -> None:
    if data["kind"] not in INSURANCE_KINDS:
        return
    minimum = _item(plan, data["kind"]).minimum_sum_insured or Decimal("0")
    for source in r.agreements:
        agreement = verify_agreement_in_force(source.get("state"), source_plan=source.get("plan"), company_ref=plan.company_ref, currency=plan.currency, at=at)
        require(all(getattr(agreement.scope, key) == data.get(key) for key in ("tenant_ref", "project_ref", "project_id")), "PAPER_SCOPE_MISMATCH", "contracted cover minima must come from this execution scope")
        minimum = max(minimum, agreement.ledger.insurance_minima.get(data["kind"], Decimal("0")))
    require(Decimal(data["limit"]) >= minimum, "COVER_BELOW_CONTRACTED_MINIMUM", "cover must meet policy and retained in-force contractual minima", "await_approval")
    require(r.premium_state is not None and r.premium_plan is not None, "PREMIUM_NOT_PAID", "current cover requires the replayable paid premium")
    premium_proof(r.premium_state, source_plan=r.premium_plan)
    paid, ledger = r.premium_state, r.premium_state["ledger"]
    require(r.premium_plan["company_ref"] == plan.company_ref and paid["scope"]["company_ref"] in ("selected", plan.company_ref) and all(paid["scope"][key] == data.get(key) for key in ("tenant_ref", "project_ref", "project_id")) and paid["scope"]["currency"] == plan.currency and Decimal(ledger["applied_amount"]) == Decimal(data["premium"]) and ledger.get("supplier_ref") == data["insurer_ref"] and ledger.get("invoice_number") == data["item_ref"] and parsed(ledger["paid_at"]) <= parsed(at), "PREMIUM_NOT_PAID", "premium must match this insurer, policy reference, amount, company, currency and date")
    require(paid["state_digest"] not in data.get("premium_digests", ()) or paid["state_digest"] == data.get("premium_digest"), "PREMIUM_NOT_PAID", "a prior policy premium cannot fund a renewal")
    data["premium_digest"] = paid["state_digest"]
    if paid["state_digest"] not in data.get("premium_digests", ()):
        data["premium_digests"] = [*data.get("premium_digests", ()), paid["state_digest"]]


def _apply_standing(plan: Any, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    try:
        if event == "record":
            require(r.paper_scope is not None, "PAPER_SCOPE_MISMATCH", "open standing through its scoped wrapper")
            data.update(_standing_source(plan, r, at))
            data.update({key: r.paper_scope[key] for key in ("tenant_ref", "project_ref", "project_id")})
            data["company_ref"] = plan.company_ref
            data["entity_ref"] = r.entity_ref
        elif event == "verify":
            require(r.registry_provenance is not None and r.registry_extract is not None, "REGISTRY_CONFIRMATION_MISSING", "verification must retain a confirming registry read")
            registry_receipt(r.registry_provenance, r.registry_extract)
            source = r.registry_extract
            require(source["company_ref"] == plan.company_ref and source["jurisdiction"] == plan.jurisdiction and source.get("holder_ref") == data.get("holder_ref") and source["kind"] == data["kind"] and source["item_ref"] == data["item_ref"] and source["period_start"] == data["period_start"] and source["period_end"] == data["period_end"], "REGISTRY_CONFIRMATION_MISSING", "confirmation must bind this item, jurisdiction, holder and exact term")
            require(data["document_sha256"] == r.registry_provenance["output_digest"], "EVIDENCE_DIGEST_MISMATCH", "the certificate sha256 must equal the read output digest", "manual_reconciliation")
            require(parsed(r.registry_provenance["completed_at"]) <= parsed(at), "REGISTRY_CONFIRMATION_MISSING", "verification cannot use a future read")
            data["registry_digest"] = r.registry_provenance["provenance_digest"]
            _check_holder(plan, data, r)
        elif event in {"activate", "confirm_current"}:
            require(parsed(data["period_start"]) <= parsed(at) < parsed(data["period_end"]), "EXPIRY_IN_PAST", "current paper must cover the transition date")
            if event == "confirm_current":
                require(r.registry_provenance is not None and r.registry_extract is not None, "REGISTRY_CONFIRMATION_MISSING", "renewed standing requires registry confirmation")
                registry_receipt(r.registry_provenance, r.registry_extract)
                source = r.registry_extract
                require(source.get("lodgement_ref") == data["lodgement_ref"] and source["company_ref"] == plan.company_ref and source["jurisdiction"] == plan.jurisdiction and source.get("holder_ref") == data.get("holder_ref") and source["item_ref"] == data["item_ref"] and source["kind"] == data["kind"] and source["period_start"] == data["period_start"] and source["period_end"] == data["period_end"] and parsed(r.registry_provenance["completed_at"]) <= parsed(at), "REGISTRY_CONFIRMATION_MISSING", "registry must confirm the exact lodged renewal")
                require(data["document_sha256"] == r.registry_provenance["output_digest"], "EVIDENCE_DIGEST_MISMATCH", "renewed certificate must equal its registry output", "manual_reconciliation")
                data["registry_digest"] = r.registry_provenance["provenance_digest"]
            require(bool(data.get("registry_digest")), "REGISTRY_CONFIRMATION_MISSING", "current paper needs registry verification")
            _check_cover(plan, data, r, at)
            _check_holder(plan, data, r)
            data["outcome"] = "current"
        elif event == "mark_renewal_due":
            require(parsed(at) >= parsed(data["renewal_due_at"]), "RENEWAL_TOO_EARLY", "the configured renewal lead has not begun")
            # Detecting a late renewal remains possible: the action preparation guard escalates it.
        elif event in {"prepare_action", "reinstate"}:
            if event == "prepare_action":
                require(parsed(at) <= parsed(data["period_end"]), "RENEWAL_LEAD_MISSED", "renewal was not prepared before expiry", "manual_reconciliation")
            else:
                _authority(plan, data, command, "insurance", data["premium"], "REINSTATE_NOT_AUTHORIZED")
            candidate = _standing_source(plan, r, at)
            require(candidate["kind"] == data["kind"] and candidate.get("holder_ref") == data.get("holder_ref"), "REGISTRY_CONFIRMATION_MISSING", "a renewal retains its kind and holder")
            prior_end = (data.get("previous_period_end") or data["period_end"]) if event == "reinstate" else data["period_end"]
            require(parsed(candidate["period_start"]) <= parsed(prior_end), "COVER_GAP", "renewal cannot conceal an uninsured gap", "manual_reconciliation")
            require(parsed(candidate["period_end"]) > parsed(prior_end), "EXPIRY_IN_PAST", "renewal must extend the prior term")
            data["previous_period_end"] = prior_end
            data.update(candidate)
            data["premium_digest"] = None
            data["gap_recorded"] = data.get("gap_recorded", False) or event == "reinstate"
        elif event == "lodge":
            require(r.lodgement_ref is not None and r.lodged_at is not None and r.lodged_by is not None and r.lodged_amount is not None and r.detail == "operator-supplied filing evidence; the platform holds no filing write", "LODGEMENT_REF_INVALID", "retain the operator-held filing evidence")
            filing_receipt(lodgement_ref=r.lodgement_ref, lodged_at=r.lodged_at, amount=r.lodged_amount, lodged_by=r.lodged_by)
            require(parsed(r.lodged_at) <= parsed(at), "LODGEMENT_REF_INVALID", "lodgement cannot be in the future")
            data.update({"lodgement_ref": r.lodgement_ref, "lodged_amount": str(r.lodged_amount)})
        elif event == "mark_lapsed":
            deadline = data.get("previous_period_end") or data["period_end"]
            require(parsed(at) >= parsed(deadline), "EXPIRY_IN_PAST", "paper lapses only when prior cover expires")
            data.update({"lapsed_at": at, "outcome": "lapsed"})
        elif event in {"surrender", "supersede"}:
            data["outcome"] = next_status
    except ObligationPaperError as exc:
        raise Rejected(exc.code, exc.message, _recovery(exc.code)) from exc
    return next_status, data


_AGREEMENT_TABLE = {("new", "execute"): "executed", ("executed", "register_obligations"): "registered", ("registered", "activate"): "in_force", ("in_force", "open_notice_window"): "notice_window", ("notice_window", "give_notice"): "notice_given", ("notice_window", "renew"): "renewed", ("renewed", "activate"): "in_force", ("amended", "activate"): "in_force", ("notice_given", "terminate"): "terminated", ("in_force", "supersede"): "superseded", **{(s, "amend"): "amended" for s in ("in_force", "notice_window")}, **{(s, "expire"): "expired" for s in ("notice_window", "in_force")}, **{(s, "require_reconciliation"): "reconciliation_required" for s in ("in_force", "notice_window")}}
_STANDING_TABLE = {("new", "record"): "recorded", ("recorded", "verify"): "verified", ("verified", "activate"): "current", ("current", "mark_renewal_due"): "renewal_due", ("renewal_due", "prepare_action"): "action_prepared", ("action_prepared", "lodge"): "lodged", ("lodged", "confirm_current"): "current", ("lapsed", "reinstate"): "action_prepared", ("current", "supersede"): "superseded", **{(s, "mark_lapsed"): "lapsed" for s in ("renewal_due", "action_prepared", "lodged")}, **{(s, "surrender"): "surrendered" for s in ("current", "lapsed")}}
AGREEMENT_LIFECYCLE = LifecycleSpec(entity="agreement", schema_prefix="agreement_chain", statuses=AGREEMENT_STATUSES, terminal=("expired", "terminated", "superseded", "reconciliation_required"), events=AGREEMENT_EVENTS, table=_AGREEMENT_TABLE, opening_event="execute", reason_events=("terminate", "supersede", "require_reconciliation"), apply=_apply_agreement, ledger_model=AgreementLedger, receipt_model=PaperReceipt, effect_boundary_model=PaperEffectBoundary, plan_model=ObligationPaperPlan, max_transitions=32)
STANDING_LIFECYCLE = LifecycleSpec(entity="standing_item", schema_prefix="company_standing", statuses=STANDING_STATUSES, terminal=("surrendered", "superseded"), events=STANDING_EVENTS, table=_STANDING_TABLE, opening_event="record", reason_events=("mark_lapsed", "reinstate", "surrender", "supersede"), apply=_apply_standing, ledger_model=StandingLedger, receipt_model=PaperReceipt, effect_boundary_model=PaperEffectBoundary, plan_model=ObligationPaperPlan, max_transitions=32)
AgreementState, AgreementCommand, AgreementTransitionResult = AGREEMENT_LIFECYCLE.State, AGREEMENT_LIFECYCLE.Command, AGREEMENT_LIFECYCLE.TransitionResult
StandingItemState, StandingItemCommand, StandingItemTransitionResult = STANDING_LIFECYCLE.State, STANDING_LIFECYCLE.Command, STANDING_LIFECYCLE.TransitionResult


def _open(spec: Any, plan: Any, scope: Any, **kwargs: Any) -> Any:
    from lightbulb.company_engine_core import EngineScope
    policy, bound = _read(ObligationPaperPlan, plan), _read(EngineScope, scope)
    _require((bound.company_ref == "selected" or policy.company_ref == bound.company_ref) and policy.currency == bound.currency, "PAPER_SCOPE_MISMATCH", "paper plan must bind the scoped company or selected-company alias and currency")
    receipt = kwargs.get("receipt") or {}
    kwargs["receipt"] = {**receipt, "entity_ref": bound.entity_ref, "paper_scope": bound.to_dict()}
    if spec is AGREEMENT_LIFECYCLE:
        artifact = _read(PaperArtifact, receipt.get("execution"))
        _require(artifact.facts["project_id"] == bound.project_id, "PAPER_SCOPE_MISMATCH", "execution belongs to another project")
    return spec.open(policy, bound, **kwargs)


def open_agreement(plan: Any, scope: Any, *, receipt: Any, opened_at: str, actor_ref: str) -> Any:
    return _open(AGREEMENT_LIFECYCLE, plan, scope, receipt=receipt, opened_at=opened_at, actor_ref=actor_ref)


def advance_agreement(plan: Any, state: Any, command: Any) -> Any:
    return AGREEMENT_LIFECYCLE.advance(plan, state, command)


def open_standing_item(plan: Any, scope: Any, *, receipt: Any, opened_at: str, actor_ref: str) -> Any:
    return _open(STANDING_LIFECYCLE, plan, scope, receipt=receipt, opened_at=opened_at, actor_ref=actor_ref)


def advance_standing_item(plan: Any, state: Any, command: Any) -> Any:
    return STANDING_LIFECYCLE.advance(plan, state, command)


def _gate(spec: Any, state: Any, source_plan: Any, company_ref: str, currency: str, at: str, code: str, expected_scope: Any = None) -> Any:
    try:
        plan, proven = spec.bind(source_plan, state)
        valid = plan.company_ref == company_ref and plan.currency == proven.scope.currency == currency and parsed(at) >= parsed(proven.transition_history[-1].command.occurred_at)
        valid = valid and proven.ledger.company_ref == plan.company_ref and (proven.scope.company_ref == "selected" or proven.scope.company_ref == plan.company_ref)
        valid = valid and all(getattr(proven.ledger, key) == getattr(proven.scope, key) for key in ("tenant_ref", "project_ref", "project_id", "entity_ref"))
        if expected_scope is not None:
            scope = dict(detached(expected_scope))
            valid = valid and all(scope.get(key) == getattr(proven.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency"))
    except (ValueError, TypeError) as exc:
        raise ObligationPaperError(code, "paper requires its replayable sealed state and source plan") from exc
    _require(valid, code, "paper scope, currency and evidence time must match this consuming hop")
    return proven


def verify_agreement_in_force(state: Any, *, source_plan: Any, company_ref: str, currency: str, at: str, agreement_ref: str | None = None, contract_ref: str | None = None, expected_scope: Any = None) -> Any:
    proven = _gate(AGREEMENT_LIFECYCLE, state, source_plan, company_ref, currency, at, "AGREEMENT_NOT_IN_FORCE", expected_scope)
    ledger = proven.ledger
    _require(proven.status in {"in_force", "notice_window", "notice_given"} and parsed(ledger.effective_at) <= parsed(at) < parsed(ledger.expires_at) and (agreement_ref is None or ledger.agreement_ref == agreement_ref) and (contract_ref is None or ledger.contract_ref == contract_ref), "AGREEMENT_NOT_IN_FORCE", "the exact agreement must remain in force at the protected money hop")
    return proven


def verify_paper_current(state: Any, *, source_plan: Any, company_ref: str, currency: str, at: str, kind: str | None = None, holder_ref: str | None = None, expected_scope: Any = None) -> Any:
    proven = _gate(STANDING_LIFECYCLE, state, source_plan, company_ref, currency, at, "LICENCE_NOT_CURRENT", expected_scope)
    ledger = proven.ledger
    _require(proven.status in {"current", "renewal_due"} and parsed(ledger.period_start) <= parsed(at) < parsed(ledger.period_end) and (kind is None or ledger.kind == kind) and (holder_ref is None or ledger.holder_ref == holder_ref), "LICENCE_NOT_CURRENT", "current paper must cover the requested date, kind and holder")
    return proven


def verify_cover_current(state: Any, *, source_plan: Any, company_ref: str, currency: str, at: str, kind: str | None = None, required_limit: Any = Decimal("0"), expected_scope: Any = None) -> Any:
    try:
        proven = verify_paper_current(state, source_plan=source_plan, company_ref=company_ref, currency=currency, at=at, kind=kind, expected_scope=expected_scope)
    except ObligationPaperError as exc:
        raise ObligationPaperError("COI_NOT_CURRENT", exc.message) from exc
    _require(proven.ledger.kind in INSURANCE_KINDS and proven.ledger.premium_digest is not None and proven.ledger.limit >= decimal_value(required_limit, field_name="required_limit"), "COI_NOT_CURRENT", "current paid cover must meet the contracted certificate limit")
    return proven


def verify_invoice_paper(revenue_case_state: Any, *, source_plan: Any, agreement_state: Any, agreement_plan: Any, at: str, cover_state: Any = None, cover_plan: Any = None, required_limit: Any = None, expected_scope: Any = None) -> Any:
    """The gate ``revenue_chain.issue_invoice`` must pass: the exact agreement still in force, and the certificate of currency many customers make a condition precedent to paying."""
    from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE
    try:
        plan, case = REVENUE_CHAIN_LIFECYCLE.bind(source_plan, revenue_case_state)
    except (ValueError, TypeError) as exc:
        raise ObligationPaperError("AGREEMENT_NOT_IN_FORCE", "the invoice hop requires its replayable revenue case and source plan") from exc
    _require(case.status == "agreement_executed" and case.ledger.agreement_ref is not None and case.ledger.contract_ref is not None, "AGREEMENT_NOT_IN_FORCE", "an invoice is issued only from an executed agreement naming its contract")
    proven = verify_agreement_in_force(agreement_state, source_plan=agreement_plan, company_ref=plan.company_ref, currency=plan.currency, at=at, agreement_ref=case.ledger.agreement_ref, contract_ref=case.ledger.contract_ref, expected_scope=expected_scope)
    _require(proven.ledger.invoicing_trigger != "signature" or parsed(at) >= parsed(proven.ledger.executed_at), "AGREEMENT_NOT_IN_FORCE", "an invoice the contract triggers on signature cannot precede execution")
    if required_limit is not None:
        _require(cover_state is not None and cover_plan is not None, "COI_NOT_CURRENT", "a contracted certificate of currency requires the replayable cover state and its source plan")
        verify_cover_current(cover_state, source_plan=cover_plan, company_ref=plan.company_ref, currency=plan.currency, at=at, required_limit=required_limit, expected_scope=expected_scope)
    return proven


def verify_vendor_paper(payable_case_state: Any, *, source_plan: Any, agreement_state: Any, agreement_plan: Any, at: str | None = None, expected_scope: Any = None) -> Any:
    """The gate ``payables_chain.approve`` must pass: a vendor bill is approved only under that vendor's own in-force paper, and only up to what was contracted."""
    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE
    try:
        plan, case = PAYABLES_CHAIN_LIFECYCLE.bind(source_plan, payable_case_state)
    except (ValueError, TypeError) as exc:
        raise ObligationPaperError("VENDOR_PAPER_MISSING", "the approval hop requires its replayable payable case and source plan") from exc
    _require(case.ledger.supplier_ref is not None and case.ledger.amount > 0, "VENDOR_PAPER_MISSING", "an approved bill names its supplier and its amount")
    moment = at or case.ledger.received_at or case.transition_history[-1].command.occurred_at
    try:
        proven = verify_agreement_in_force(agreement_state, source_plan=agreement_plan, company_ref=plan.company_ref, currency=plan.currency, at=moment, expected_scope=expected_scope)
    except ObligationPaperError as exc:
        raise ObligationPaperError("VENDOR_PAPER_MISSING", exc.message) from exc
    _require(proven.ledger.counterparty_ref == case.ledger.supplier_ref, "VENDOR_PAPER_MISSING", "the in-force agreement must bind the billing supplier")
    _require(case.ledger.amount <= proven.ledger.amount, "VENDOR_PAPER_MISSING", "a bill above the contracted amount is not covered by the vendor's paper")
    return proven


def certificate_request(state: Any, *, source_plan: Any, required_limit: Any, at: str | None = None) -> dict[str, Any]:
    """Preview only: issuing a certificate needs the insurer lane the platform lacks."""
    from lightbulb.connector_execution import ConnectorExecutionRequest
    plan, source = STANDING_LIFECYCLE.bind(source_plan, state)
    verify_cover_current(source, source_plan=plan, company_ref=plan.company_ref, currency=plan.currency, at=at or source.transition_history[-1].command.occurred_at, required_limit=required_limit)
    request = ConnectorExecutionRequest(tool="host.issue_certificate_of_currency", scope={"project_id": source.scope.project_id, "project_ref": source.scope.project_ref}, effect="write", approval_required=True, preview_only=True, idempotency_key=f"certificate:{source.state_digest[:32]}", arguments={"policy_ref": source.ledger.item_ref, "document_sha256": source.ledger.document_sha256, "required_limit": str(decimal_value(required_limit, field_name="required_limit"))}, metadata={"source_state_digest": source.state_digest, "missing_connector": "No insurer connector is installed; host/operator action is required"})
    return request.model_dump(mode="json", by_alias=True, exclude_none=True)


def agreements(state: Any, *, source_plan: Any) -> dict[str, Any]:
    _, proven = AGREEMENT_LIFECYCLE.bind(source_plan, state)
    return {"agreement_ref": proven.ledger.agreement_ref, "status": proven.status, "state_digest": proven.state_digest, **proven.ledger.to_dict()}


def standing(state: Any, *, source_plan: Any) -> dict[str, Any]:
    _, proven = STANDING_LIFECYCLE.bind(source_plan, state)
    return {"status": proven.status, "state_digest": proven.state_digest, **proven.ledger.to_dict()}


def cover(state: Any, *, source_plan: Any) -> dict[str, Any]:
    summary = standing(state, source_plan=source_plan)
    _require(summary.get("kind") in INSURANCE_KINDS, "COI_NOT_CURRENT", "the standing item must be insurance")
    return summary


def paper_clock(state: Any, *, source_plan: Any) -> tuple[dict[str, Any], ...]:
    """Dated cadence proposals; no job is scheduled or executed here."""
    spec = AGREEMENT_LIFECYCLE if dict(detached(state)).get("entity") == "agreement" else STANDING_LIFECYCLE
    _, proven = spec.bind(source_plan, state)
    if proven.status in spec.terminal:
        return ()
    dates = (("open_notice_window", proven.ledger.notice_window_opens_at), ("expire", proven.ledger.expires_at)) if spec is AGREEMENT_LIFECYCLE else (("mark_renewal_due", proven.ledger.renewal_due_at), ("mark_lapsed", proven.ledger.period_end))
    return tuple({"engine": OBLIGATION_PAPER_KIND, "entity": proven.entity, "entity_ref": proven.scope.entity_ref, "event": event, "at": at, "source_digest": proven.state_digest, "approval_required": True} for event, at in dates if at is not None)


def _observed_paper(state: Any, source_plan: Any, at: str) -> Any:
    spec = AGREEMENT_LIFECYCLE if detached(state).get("entity") == "agreement" else STANDING_LIFECYCLE
    _, source = spec.bind(source_plan, state)
    _require(parsed(source.transition_history[-1].command.occurred_at) <= parsed(at), "EVIDENCE_DIGEST_MISMATCH", "paper observation cannot precede its source history")
    return source


def agreement_expiring_signal(state: Any, *, source_plan: Any, emitted_at: str) -> dict[str, Any]:
    from lightbulb.company_operating_system import CompanySignal
    at = timestamp(emitted_at, field_name="emitted_at")
    source = _observed_paper(state, source_plan, at)
    _require(source.entity == "agreement" and source.status in {"in_force", "notice_window"} and parsed(source.ledger.notice_window_opens_at) <= parsed(at) < parsed(source.ledger.expires_at), "RENEWAL_TOO_EARLY", "agreement expiry is signalled inside its actual contractual notice window")
    return CompanySignal(name="signals.agreement_expiring", producer=OBLIGATION_PAPER_KIND, emitted_at=at,
        payload={"agreement_ref": source.ledger.agreement_ref, "expires_at": source.ledger.expires_at, "notice_due_at": source.ledger.notice_due_at, "source_digest": source.state_digest}).to_dict()


def paper_lapsed_signal(state: Any, *, source_plan: Any, emitted_at: str) -> dict[str, Any]:
    from lightbulb.company_operating_system import CompanySignal
    at = timestamp(emitted_at, field_name="emitted_at")
    source = _observed_paper(state, source_plan, at)
    _require(source.status in {"lapsed", "expired"}, "EXPIRY_IN_PAST", "a lapse signal requires the replayed lapse or expiry transition")
    return CompanySignal(name="signals.paper_lapsed", producer=OBLIGATION_PAPER_KIND, emitted_at=at,
        payload={"paper_ref": source.scope.entity_ref, "status": source.status, "source_digest": source.state_digest}).to_dict()


def paper_exceptions(states: Sequence[Any], *, source_plans: Mapping[str, Any], now: str) -> tuple[dict[str, Any], ...]:
    """Open real exceptions from observed missed deadlines and expiring cover."""
    at = timestamp(now, field_name="now")
    result = []
    for state in states:
        source = _observed_paper(state, source_plans[detached(state)["plan_digest"]], at)
        code = None
        if source.entity == "agreement":
            if source.status in {"in_force", "notice_window"} and parsed(source.ledger.notice_due_at) < parsed(at):
                code = "NOTICE_WINDOW_MISSED"
        elif source.status not in {"surrendered", "superseded"}:
            if source.ledger.kind in INSURANCE_KINDS and parsed(source.ledger.renewal_due_at) <= parsed(at):
                code = "COVER_EXPIRING" if parsed(at) < parsed(source.ledger.period_end) else "COVER_LAPSED"
            elif source.status == "lapsed" or parsed(source.ledger.period_end) <= parsed(at):
                code = "LAPSED_REGISTRATION"
        if code:
            result.append({"kind": "overdue_obligation", "source_engine": OBLIGATION_PAPER_KIND, "source_ref": source.scope.entity_ref,
                "source_digest": source.state_digest, "code": code, "detail": "Resolve the proven paper deadline before another gated action.", "evidence_refs": [f"paper:{source.state_digest}"]})
    return tuple(result)


def annual_return_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The compliance handoff retains the exact operator-held filing and standing history."""
    from lightbulb.compliance_calendar import filing_receipt as compliance_filing_receipt
    plan, source = STANDING_LIFECYCLE.bind(source_plan, state)
    _require(source.ledger.kind == "annual_return" and source.status in {"lodged", "current"} and source.ledger.lodgement_ref is not None, "LODGEMENT_REF_INVALID", "annual return requires its replayed lodgement")
    filing = next((item.command.receipt for item in reversed(source.transition_history) if item.command.event == "lodge" and item.command.receipt.lodgement_ref == source.ledger.lodgement_ref), None)
    _require(filing is not None, "LODGEMENT_REF_INVALID", "the original filing receipt must be retained")
    receipt = compliance_filing_receipt(lodgement_ref=filing.lodgement_ref, lodged_at=filing.lodged_at, amount=filing.lodged_amount, lodged_by=filing.lodged_by, evidence_refs=[f"standing:{source.state_digest}"])
    return {**receipt, "standing_source": {"state": source.to_dict(), "source_plan": plan.to_dict(), "period_end": source.ledger.previous_period_end or source.ledger.period_end}}


def renewal_flows(state: Any, *, source_plan: Any, at: str, agreement_kind: Literal["receivable", "payable"] | None = None) -> tuple[Any, ...]:
    """Forecast known renewal terms; expiry reminders remain non-monetary paper_clock events.

    The host must name whether an agreement is a customer receivable or vendor
    payable because signed paper alone does not identify its accounting role.
    An insurance schedule contributes only its observed premium, without uplift.
    """
    from lightbulb.company_treasury import ScheduledFlow
    source = _observed_paper(state, source_plan, timestamp(at, field_name="at"))
    if source.entity == "agreement":
        _require(agreement_kind in {"receivable", "payable"}, "RENEWAL_TERM_MISMATCH", "name the agreement's accounting role explicitly")
        if not source.ledger.auto_renew or source.status not in {"in_force", "notice_window"}:
            return ()
        kind, amount, due = agreement_kind, source.ledger.amount, source.ledger.expires_at
    else:
        if source.ledger.kind not in INSURANCE_KINDS or source.status not in {"current", "renewal_due", "action_prepared", "lodged"}:
            return ()
        kind, amount, due = "fixed_cost", -source.ledger.premium, source.ledger.period_end
    if parsed(due) <= parsed(at) or amount == 0:
        return ()
    if kind == "payable":
        amount = -amount
    return (ScheduledFlow(kind=kind, ref=f"paper-renewal:{source.scope.entity_ref}:{source.state_digest[:16]}", due_at=due, amount=str(amount), source=f"observed paper renewal terms:{source.state_digest}"),)


OBLIGATION_PAPER_MANIFEST = {"schema": "lightbulb.company_engine_manifest.v1", "engine": OBLIGATION_PAPER_KIND, "golden_loop": OBLIGATION_PAPER_GOLDEN_LOOP, "stages": ["execute", "register", "activate", "renew", "restore"], "statuses": list(AGREEMENT_STATUSES + STANDING_STATUSES), "events": list(AGREEMENT_EVENTS + STANDING_EVENTS), "hops": ["signed document -> reviewed obligations -> in-force paper", "registry evidence + paid premium -> current cover"], "gates": {"revenue_chain.issue_invoice": ["AGREEMENT_NOT_IN_FORCE", "COI_NOT_CURRENT"], "payables_chain.approve": ["VENDOR_PAPER_MISSING"], "company_workforce.plan_dispatch": ["LICENCE_NOT_CURRENT"], "company_bring_up.verify_paper": ["LICENCE_NOT_CURRENT"]}, "required_connectors": ["docusign", "gmail", "microsoft"], "missing_reads": ["companies registry: host.registry_extract or governed registry email", "insurer: explicit operator policy schedule; certificate issuance remains a host preview"], "hard_rules": ["a contract has a clock; the clock comes from the contract, not from a default", "notice is proof a message was sent through the contractual channel", "cover is renewed by a paid premium, never by an invoice", "a certificate is bound to the read that produced it by output digest", "a lapse is curable; it is never terminal and never silent", "engine source ledgers are replayed with their retained source plans", "a bill is approved only under the billing counterparty's own in-force paper, and only up to what was contracted"]}

__all__ = ["AGREEMENT_LIFECYCLE", "STANDING_LIFECYCLE", "AGREEMENT_STATUSES", "AGREEMENT_EVENTS", "STANDING_STATUSES", "STANDING_EVENTS", "ITEM_KINDS", "INSURANCE_KINDS", "OBLIGATION_PAPER_KIND", "OBLIGATION_PAPER_GOLDEN_LOOP", "OBLIGATION_PAPER_PLAN_SCHEMA", "OBLIGATION_PAPER_MANIFEST", "ObligationPaperError", "RequiredItem", "ObligationPaperPlan", "PaperArtifact", "PolicyScheduleInput", "RegistryExtract", "PaperReceipt", "AgreementLedger", "StandingLedger", "PaperEffectBoundary", "AgreementState", "AgreementCommand", "AgreementTransitionResult", "StandingItemState", "StandingItemCommand", "StandingItemTransitionResult", "compile_obligation_paper", "execute_receipt", "review_clearance", "terms_receipt", "obligations_receipt", "notice_receipt", "formation_receipt", "cover_receipt", "premium_proof", "registry_receipt", "filing_receipt", "certificate_request", "open_agreement", "advance_agreement", "open_standing_item", "advance_standing_item", "verify_agreement_in_force", "verify_cover_current", "verify_invoice_paper", "verify_paper_current", "verify_vendor_paper", "agreements", "standing", "cover", "paper_clock", "agreement_expiring_signal", "paper_lapsed_signal", "paper_exceptions", "annual_return_receipt", "renewal_flows"]
