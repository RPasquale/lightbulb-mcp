"""Consent and marketing claims proved from retained platform evidence.

The register stores platform-keyed endpoint digests, never addresses or keys.
Consent observations and completed connector effects retain their provenance
and committed output. Claims require dated substantiation and an independent
bound human approval; a successful workforce review only corroborates it.
Eligibility and claim projections retain source plans and replayable states.
The SDK neither sends messages nor establishes legal compliance or authority.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST, BoundedText, CurrencyCode, EngineScope, LifecycleSpec, OpaqueRef,
    Rejected, Sha256Digest, ShortText, StrictModel, detached, iso, parsed,
    require, seal, sealed_digest, skip_digests, stable_digest, timestamp, unique,
)
from lightbulb.company_execution_bridge import ExecutionReceipt, ObservationProvenance

PERMISSION_REGISTER_KIND = "permission_register"
PERMISSION_PLAN_SCHEMA = "lightbulb.permission_register_plan.v1"
PERMISSION_GOLDEN_LOOP = "company.blueprint_to_governed_operating_cadence@0.1.0"
CONSENT_STATUSES = ("captured", "pending_confirmation", "express", "implied", "lapsing", "withdrawn", "suppressed")
CONSENT_EVENTS = ("capture", "confirm", "record_send", "mark_lapsing", "expire_implied", "withdraw", "honour", "purge")
CLAIM_STATUSES = ("proposed", "evidenced", "in_review", "approved", "in_use", "resubstantiation_due", "withdrawn", "retired", "rejected")
CLAIM_EVENTS = ("propose", "substantiate", "submit_review", "approve", "publish", "mark_resubstantiation_due", "renew_evidence", "withdraw", "complete_cascade", "retire", "reject")
Channel = Literal["email", "sms", "voice", "linkedin"]
RECOVERY_BY_CODE = {
    **{code: "correct_input" for code in ("SOURCE_NOT_EVIDENCED", "CHANNEL_NOT_COVERED", "CONFIRMATION_MISSING", "IMPLIED_CONSENT_EXPIRED", "SEND_WITHOUT_ELIGIBILITY", "FREQUENCY_CAP_EXCEEDED", "QUIET_HOURS_VIOLATION", "IDENTIFICATION_MISSING", "ENDPOINT_NOT_HASHED", "EVIDENCE_MISSING", "EVIDENCE_EXPIRED", "SCOPE_MISMATCH", "PROHIBITED_TERM", "CONSENT_NOT_EXPIRED")},
    **{code: "manual_reconciliation" for code in ("WITHDRAWAL_NOT_HONOURED", "REVIEWER_NOT_INDEPENDENT", "RESUBSTANTIATION_OVERDUE", "WITHDRAWAL_CASCADE_INCOMPLETE")},
    "REINSTATE_REQUIRES_NEW_CONSENT": "do_not_replay", "REVIEW_MISSING": "await_approval",
}
PERMISSION_CODES = tuple(sorted(RECOVERY_BY_CODE))


class PermissionRegisterError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message
        self.recovery = RECOVERY_BY_CODE.get(code, "correct_input")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PermissionRegisterError(code, message)


def _parse(model: Any, value: Any, code: str) -> Any:
    try:
        return model.model_validate(detached(value))
    except (ValueError, TypeError) as exc:
        raise PermissionRegisterError(code, f"a valid sealed {model.__name__} is required") from exc


def _months(at: str, months: int) -> str:
    from calendar import monthrange
    value = parsed(at)
    year, month = divmod(value.year * 12 + value.month - 1 + months, 12)
    return iso(value.replace(year=year, month=month + 1, day=min(value.day, monthrange(year, month + 1)[1])))


class PermissionPlan(StrictModel):
    schema_id: Literal["lightbulb.permission_register_plan.v1"] = Field(default=PERMISSION_PLAN_SCHEMA, alias="schema")
    operator_supplied: Literal[True] = True
    company_ref: OpaqueRef
    jurisdiction: Literal["CA", "AU"]
    currency: CurrencyCode
    source_operating_plan: dict[str, Any]
    source_growth_plan: dict[str, Any] | None = None
    implied_consent_days: dict[str, int] = Field(default_factory=lambda: {"transaction": 730, "enquiry": 183})
    honour_days: int = Field(default=10, ge=1, le=90)
    non_working_dates: tuple[str, ...] = Field(default_factory=tuple, max_length=366)
    double_opt_in_required: bool = True
    frequency_caps: dict[str, int] = Field(default_factory=lambda: {"email": 4, "sms": 2})
    quiet_hours: tuple[tuple[int, int], ...] = ((21, 8),)
    claim_review_months: int = Field(default=12, ge=1, le=60)
    claim_scopes: tuple[str, ...] = ("channel", "jurisdiction", "product")
    prohibited_terms: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=200)
    eligibility_minutes: int = Field(default=15, ge=1, le=60)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("quiet_hours", mode="before")
    @classmethod
    def _quiet(cls, value: Any) -> Any:
        return tuple(tuple(item) for item in value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PermissionPlan:
        from lightbulb.company_operating_system import CompanyOperatingPlan
        operating = CompanyOperatingPlan.model_validate(self.source_operating_plan)
        if (self.jurisdiction, self.currency) != (operating.blueprint.country, operating.blueprint.currency):
            raise ValueError("jurisdiction and currency must match the sealed company's operating plan")
        if self.source_growth_plan is not None:
            from lightbulb.growth_engine_loop import GrowthEngineLoopPlan
            growth = GrowthEngineLoopPlan.model_validate(self.source_growth_plan)
            if self.prohibited_terms != growth.blueprint.prohibited_terms:
                raise ValueError("prohibited terms must be inherited from the supplied growth blueprint")
        if set(self.implied_consent_days) != {"transaction", "enquiry"} or any(isinstance(v, bool) or not 1 <= v <= 730 for v in self.implied_consent_days.values()):
            raise ValueError("implied consent clocks must name transaction and enquiry with bounded days")
        if not self.frequency_caps or any(k not in {"email", "sms", "voice", "linkedin"} or isinstance(v, bool) or not 1 <= v <= 100 for k, v in self.frequency_caps.items()):
            raise ValueError("frequency caps must cover known channels with bounded counts")
        if any(not 0 <= start <= 23 or not 0 <= end <= 23 or start == end for start, end in self.quiet_hours):
            raise ValueError("quiet hours must be distinct hours in the day")
        if set(self.claim_scopes) != {"channel", "jurisdiction", "product"}:
            raise ValueError("claim scopes must retain channel, jurisdiction and product")
        for day in self.non_working_dates:
            timestamp(day + "T00:00:00Z", field_name="non_working_dates")
        if not skip_digests(info) and self.plan_digest != sealed_digest(PermissionPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact permission plan")
        return self


def compile_permission_register(company_ref: str, *, operating_plan: Any, growth_plan: Any = None, overrides: Mapping[str, Any] | None = None) -> PermissionPlan:
    from lightbulb.company_operating_system import CompanyOperatingPlan
    operating = _parse(CompanyOperatingPlan, operating_plan, "SOURCE_NOT_EVIDENCED")
    prohibited: Sequence[str] = ()
    if growth_plan is not None:
        from lightbulb.growth_engine_loop import GrowthEngineLoopPlan
        growth_plan = _parse(GrowthEngineLoopPlan, growth_plan, "SOURCE_NOT_EVIDENCED").to_dict()
        prohibited = growth_plan["blueprint"]["prohibited_terms"]
    return seal(PermissionPlan, {"company_ref": company_ref, "jurisdiction": operating.blueprint.country, "currency": operating.blueprint.currency, "source_operating_plan": operating.to_dict(), "source_growth_plan": growth_plan, "prohibited_terms": list(prohibited), **dict(overrides or {})}, "plan_digest")


class PermissionObservation(StrictModel):
    schema_id: Literal["lightbulb.permission_source_observation.v1"] = Field(default="lightbulb.permission_source_observation.v1", alias="schema")
    provenance: ObservationProvenance
    payload: dict[str, Any]
    observation_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PermissionObservation:
        if self.provenance.output_digest != stable_digest(self.payload) or self.provenance.provenance_digest == GENESIS_DIGEST:
            raise ValueError("provenance must commit the exact normalized source payload")
        if not skip_digests(info) and self.observation_digest != sealed_digest(PermissionObservation, self, "observation_digest"):
            raise ValueError("observation_digest must commit the source observation")
        return self


def permission_observation(provenance: Any, payload: Mapping[str, Any]) -> PermissionObservation:
    """Seal an already redacted platform read whose output digest commits its payload."""
    return seal(PermissionObservation, {"provenance": detached(provenance), "payload": dict(detached(payload))}, "observation_digest")


class ConsentFacts(StrictModel):
    company_ref: OpaqueRef
    endpoint_digest: Sha256Digest
    digest_method: Literal["hmac_sha256"]
    key_ref: OpaqueRef
    channel: Channel
    event: Literal["capture", "confirm", "withdraw"]
    occurred_at: str
    basis: Literal["express", "transaction", "enquiry"] = "express"
    confirmed: bool = False
    explicit_choice: bool = False
    operator_import: bool = False

    @field_validator("occurred_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="occurred_at")


_CONSENT_TOOLS = {"ecommerce.get_customer", "ecommerce.search_customers", "gmail.get_thread", "host.consent_export", "twilio.lookup_message_status"}


def _consent_observation(value: Any, event: str) -> tuple[PermissionObservation, ConsentFacts]:
    raw = detached(value)
    payload = raw.get("payload", {}) if isinstance(raw, Mapping) else {}
    try:
        endpoint = payload.get("endpoint_digest", "")
        _require(isinstance(endpoint, str) and len(endpoint) == 64 and all(c in "0123456789abcdef" for c in endpoint) and payload.get("digest_method") == "hmac_sha256" and bool(payload.get("key_ref")), "ENDPOINT_NOT_HASHED", "the platform must supply a keyed endpoint digest and opaque key reference, never an address")
        observation = _parse(PermissionObservation, value, "SOURCE_NOT_EVIDENCED")
        facts = _parse(ConsentFacts, observation.payload, "SOURCE_NOT_EVIDENCED")
        provenance = observation.provenance
        _require(provenance.source_tool in _CONSENT_TOOLS and facts.event == event, "SOURCE_NOT_EVIDENCED", "the source must prove this consent event")
        _require(parsed(facts.occurred_at) <= parsed(provenance.completed_at), "SOURCE_NOT_EVIDENCED", "a consent fact cannot postdate its observation")
        if provenance.source_tool == "host.consent_export":
            _require(provenance.lane == "host_read" and facts.operator_import, "SOURCE_NOT_EVIDENCED", "a consent export names itself as an operator import")
        else:
            _require(provenance.lane == "governed_read", "SOURCE_NOT_EVIDENCED", "consent provider reads require governed provenance")
        if event == "capture":
            _require(provenance.source_tool in _CONSENT_TOOLS - {"twilio.lookup_message_status"}, "SOURCE_NOT_EVIDENCED", "a delivery lookup is not a fresh consent capture")
            _require(facts.basis != "express" or facts.explicit_choice, "SOURCE_NOT_EVIDENCED", "express consent requires an explicit opt-in recorded by the source")
        if event == "confirm":
            _require(provenance.source_tool == "gmail.get_thread" and facts.explicit_choice and facts.confirmed, "CONFIRMATION_MISSING", "confirmation requires a governed explicit opt-in reply")
        if event == "withdraw":
            _require(provenance.source_tool in {"gmail.get_thread", "twilio.lookup_message_status"} and facts.explicit_choice, "SOURCE_NOT_EVIDENCED", "withdrawal requires an observed unsubscribe or STOP")
        return observation, facts
    except PermissionRegisterError:
        raise


def capture_receipt(source_observation: Any) -> dict[str, Any]:
    source, _ = _consent_observation(source_observation, "capture")
    return {"source": source.to_dict(), "evidence_refs": [f"consent:{source.observation_digest[:24]}"]}


def confirm_receipt(thread_observation: Any) -> dict[str, Any]:
    source, _ = _consent_observation(thread_observation, "confirm")
    return {"source": source.to_dict(), "evidence_refs": [f"confirmation:{source.observation_digest[:24]}"]}


def withdrawal_receipt(observation: Any) -> dict[str, Any]:
    source, _ = _consent_observation(observation, "withdraw")
    return {"source": source.to_dict(), "evidence_refs": [f"withdrawal:{source.observation_digest[:24]}"]}


class PermissionExecution(StrictModel):
    schema_id: Literal["lightbulb.permission_execution.v1"] = Field(default="lightbulb.permission_execution.v1", alias="schema")
    execution: ExecutionReceipt
    payload: dict[str, Any]
    effect_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PermissionExecution:
        if self.execution.schema_id != "lightbulb.engine_execution_receipt.v1" or self.execution.effect != "write" or self.execution.output_digest != stable_digest(self.payload):
            raise ValueError("a completed approved write must commit the exact effect output")
        if not skip_digests(info) and self.effect_digest != sealed_digest(PermissionExecution, self, "effect_digest"):
            raise ValueError("effect_digest must commit the execution and its output")
        return self


def permission_execution(execution_receipt: Any, payload: Mapping[str, Any]) -> PermissionExecution:
    return seal(PermissionExecution, {"execution": detached(execution_receipt), "payload": dict(detached(payload))}, "effect_digest")


class EffectFacts(StrictModel):
    company_ref: OpaqueRef
    event: Literal["send", "honour", "purge", "publish", "cascade"]
    endpoint_digest: Sha256Digest | None = None
    key_ref: OpaqueRef | None = None
    channel: ShortText | None = None
    eligibility_digest: Sha256Digest | None = None
    suppression_digest: Sha256Digest | None = None
    creative_digest: Sha256Digest | None = None
    sender_identified: bool = False
    unsubscribe_mechanism: bool = False
    local_hour: int | None = Field(default=None, ge=0, le=23)
    claim_ref: OpaqueRef | None = None
    jurisdiction: ShortText | None = None
    product: OpaqueRef | None = None
    asset_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    campaign_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    live_claim_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)


_SEND_CHANNELS = {"gmail.send_email": "email", "microsoft.send_email": "email", "twilio.send_sms_turn": "sms", "twilio.place_call_turn": "voice"}
_EFFECT_TOOLS = {"send": set(_SEND_CHANNELS), "honour": {"shopify.tag_customers_bulk"}, "purge": {"host.purge_consent_record"}, "publish": {"shopify.create_page", "shopify.update_page", "shopify.publish_product"}, "cascade": {"shopify.update_page", "shopify.publish_product"}}


def _effect(value: Any, event: str, *, code: str = "SOURCE_NOT_EVIDENCED") -> tuple[PermissionExecution, EffectFacts]:
    effect = _parse(PermissionExecution, value, code)
    facts = _parse(EffectFacts, effect.payload, code)
    _require(facts.event == event and effect.execution.tool in _EFFECT_TOOLS[event], code, "the bound write must prove the requested permission effect")
    if event == "send":
        _require(_SEND_CHANNELS[effect.execution.tool] == facts.channel, "CHANNEL_MISMATCH", "the executed provider tool must send on the consented channel")
    return effect, facts


def honour_receipt(execution_receipt: Any) -> dict[str, Any]:
    effect, _ = _effect(execution_receipt, "honour")
    return {"effect": effect.to_dict()}


def purge_receipt(execution_receipt: Any) -> dict[str, Any]:
    effect, _ = _effect(execution_receipt, "purge")
    return {"effect": effect.to_dict()}


class PermissionEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False
    consent_granted: Literal[False] = False
    claim_approved: Literal[False] = False
    asset_published: Literal[False] = False


class ConsentReceipt(StrictModel):
    register_scope: dict[str, Any] | None = None
    source: dict[str, Any] | None = None
    effect: dict[str, Any] | None = None
    eligibility: dict[str, Any] | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)


class ConsentLedger(StrictModel):
    register_scope: dict[str, Any] | None = None
    endpoint_digest: Sha256Digest | None = None
    key_ref: OpaqueRef | None = None
    channel: Channel | None = None
    basis: str | None = None
    granted_at: str | None = None
    expires_at: str | None = None
    confirmed_at: str | None = None
    withdrawn_at: str | None = None
    honoured_at: str | None = None
    purged_at: str | None = None
    consent_ref: OpaqueRef | None = None
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple)
    send_times: tuple[str, ...] = Field(default_factory=tuple)
    send_execution_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple)
    last_eligibility_digest: Sha256Digest | None = None
    last_suppression_digest: Sha256Digest | None = None


def _consent_check(plan: PermissionPlan, status: str, data: Mapping[str, Any], *, channel: str, at: str) -> None:
    require(data.get("channel") == channel and channel in plan.frequency_caps, "CHANNEL_NOT_COVERED", "consent and policy must cover the requested channel")
    require(status not in {"withdrawn", "suppressed"}, "SEND_WITHOUT_ELIGIBILITY", "withdrawn or suppressed endpoints are ineligible")
    require(parsed(at) >= parsed(str(data["granted_at"])), "SOURCE_NOT_EVIDENCED", "consent cannot be used before its source grant")
    if data.get("basis") in plan.implied_consent_days and data.get("confirmed_at") is None:
        require(parsed(at) < parsed(str(data["expires_at"])), "IMPLIED_CONSENT_EXPIRED", "implied consent has expired under the sealed plan's clock")
    else:
        require(data.get("confirmed_at") is not None or not plan.double_opt_in_required, "CONFIRMATION_MISSING", "express messaging needs the required confirmation")
        require(data.get("confirmed_at") is None or parsed(at) >= parsed(str(data["confirmed_at"])), "CONFIRMATION_MISSING", "the send must follow the actual confirmation")
    require(not data.get("send_times") or parsed(at) >= max(parsed(value) for value in data["send_times"]), "SOURCE_NOT_EVIDENCED", "out-of-order send effects require reconciliation before frequency accounting")
    recent = [value for value in data.get("send_times", ()) if parsed(at) - timedelta(days=7) < parsed(value) <= parsed(at)]
    require(len(recent) < plan.frequency_caps[channel], "FREQUENCY_CAP_EXCEEDED", "the endpoint has reached its seven-day channel cap")


def _business_deadline(at: str, plan: PermissionPlan) -> str:
    value, remaining = parsed(at), plan.honour_days
    while remaining:
        value += timedelta(days=1)
        if value.weekday() < 5 and value.date().isoformat() not in plan.non_working_dates:
            remaining -= 1
    return iso(value)


def _apply_consent(plan: PermissionPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    try:
        if event in {"capture", "confirm", "withdraw"}:
            source, facts = _consent_observation(r.source, event)
            require(facts.company_ref == plan.company_ref and parsed(source.provenance.completed_at) <= parsed(at), "SOURCE_NOT_EVIDENCED", "the observed consent must belong to the company and predate this transition")
            if event == "capture":
                scope = _parse(EngineScope, r.register_scope, "SOURCE_NOT_EVIDENCED")
                require(scope.currency == plan.currency, "SOURCE_NOT_EVIDENCED", "consent scope currency must match its permission plan")
                data["register_scope"] = scope.to_dict()
                require(facts.channel in plan.frequency_caps, "CHANNEL_NOT_COVERED", "the plan does not cover this channel")
                expiry = iso(parsed(facts.occurred_at) + timedelta(days=plan.implied_consent_days[facts.basis])) if facts.basis in plan.implied_consent_days else None
                data.update(endpoint_digest=facts.endpoint_digest, key_ref=facts.key_ref, channel=facts.channel, basis=facts.basis, granted_at=facts.occurred_at, expires_at=expiry, consent_ref=f"consent:{source.observation_digest[:24]}")
            else:
                require((facts.endpoint_digest, facts.key_ref) == (data.get("endpoint_digest"), data.get("key_ref")), "SOURCE_NOT_EVIDENCED", "the observation names a different endpoint or key namespace")
                require(facts.channel == data.get("channel"), "CHANNEL_NOT_COVERED", "consent on another channel does not cover this endpoint")
                require(parsed(facts.occurred_at) >= parsed(str(data["granted_at"])), "SOURCE_NOT_EVIDENCED", "the observation predates the consent being changed")
                if event == "confirm":
                    data.update(confirmed_at=facts.occurred_at, expires_at=None, basis="express")
                else:
                    data["withdrawn_at"] = facts.occurred_at
            require(source.observation_digest not in data.get("source_digests", ()), "SOURCE_NOT_EVIDENCED", "a consent observation cannot be recorded twice")
            data["source_digests"] = [*data.get("source_digests", ()), source.observation_digest]
        elif event == "record_send":
            effect, facts = _effect(r.effect, "send")
            require(effect.execution.project_id == data["register_scope"]["project_id"], "SOURCE_NOT_EVIDENCED", "the send belongs to another project")
            require(facts.company_ref == plan.company_ref and (facts.endpoint_digest, facts.key_ref) == (data.get("endpoint_digest"), data.get("key_ref")), "SOURCE_NOT_EVIDENCED", "the send belongs to another company or endpoint")
            _consent_check(plan, status, data, channel=str(facts.channel), at=effect.execution.completed_at)
            require(status != "captured" or data.get("basis") in plan.implied_consent_days, "CONFIRMATION_MISSING", "captured express consent must be confirmed before a send")
            require(facts.creative_digest is not None and facts.sender_identified and facts.unsubscribe_mechanism, "IDENTIFICATION_MISSING", "the executed creative must identify its sender and an unsubscribe mechanism")
            require(facts.local_hour is not None, "QUIET_HOURS_VIOLATION", "the platform output must attest the recipient-local send hour")
            require(not any(start <= facts.local_hour < end if start < end else facts.local_hour >= start or facts.local_hour < end for start, end in plan.quiet_hours), "QUIET_HOURS_VIOLATION", "the send occurred during quiet hours")
            commitment = _parse(EligibilityCommitment, r.eligibility, "SEND_WITHOUT_ELIGIBILITY")
            require((commitment.endpoint_digest, commitment.channel, commitment.plan_digest, commitment.state_digest) == (data["endpoint_digest"], data["channel"], plan.plan_digest, command.expected_state_digest), "SEND_WITHOUT_ELIGIBILITY", "eligibility must bind this endpoint's current state and plan")
            require((facts.eligibility_digest, facts.suppression_digest) == (commitment.eligibility_digest, commitment.suppression_digest), "SEND_WITHOUT_ELIGIBILITY", "the executed send must commit the checked eligibility and suppression set")
            require(parsed(commitment.as_of) <= parsed(effect.execution.completed_at) < parsed(commitment.valid_until) and parsed(effect.execution.completed_at) <= parsed(at), "SEND_WITHOUT_ELIGIBILITY", "the send must occur within its eligibility window")
            require(parsed(commitment.valid_until) - parsed(commitment.as_of) <= timedelta(minutes=plan.eligibility_minutes), "SEND_WITHOUT_ELIGIBILITY", "eligibility cannot extend the plan's freshness interval")
            require(effect.execution.execution_digest not in data.get("send_execution_digests", ()), "SEND_WITHOUT_ELIGIBILITY", "one send execution is counted once")
            data.update(send_times=[*data.get("send_times", ()), effect.execution.completed_at], send_execution_digests=[*data.get("send_execution_digests", ()), effect.execution.execution_digest], last_eligibility_digest=commitment.eligibility_digest, last_suppression_digest=commitment.suppression_digest)
            next_status = "implied" if status == "captured" else status
        elif event == "mark_lapsing":
            require(data.get("expires_at") is not None, "SOURCE_NOT_EVIDENCED", "only dated implied consent can lapse")
        elif event == "expire_implied":
            require(data.get("expires_at") is not None and parsed(at) >= parsed(str(data["expires_at"])), "CONSENT_NOT_EXPIRED", "implied consent may expire only after its policy clock")
        elif event in {"honour", "purge"}:
            effect, facts = _effect(r.effect, event)
            require(effect.execution.project_id == data["register_scope"]["project_id"], "SOURCE_NOT_EVIDENCED", "the suppression write belongs to another project")
            require(facts.company_ref == plan.company_ref and (facts.endpoint_digest, facts.key_ref) == (data.get("endpoint_digest"), data.get("key_ref")), "SOURCE_NOT_EVIDENCED", "suppression evidence must name this company and keyed endpoint")
            require(parsed(effect.execution.completed_at) <= parsed(at), "SOURCE_NOT_EVIDENCED", "the completed effect cannot postdate its recording")
            if event == "honour":
                require(parsed(str(data["withdrawn_at"])) <= parsed(effect.execution.completed_at) <= parsed(_business_deadline(str(data["withdrawn_at"]), plan)), "WITHDRAWAL_NOT_HONOURED", "suppression must materialize within the policy's business-day deadline", "manual_reconciliation")
                data["honoured_at"] = effect.execution.completed_at
            else:
                require(data.get("purged_at") is None, "SOURCE_NOT_EVIDENCED", "a completed purge is recorded only once")
                data["purged_at"] = effect.execution.completed_at
    except PermissionRegisterError as exc:
        raise Rejected(exc.code, exc.message, exc.recovery) from exc
    return next_status, data


class _ConsentLifecycle(LifecycleSpec):
    def step(self, plan: Any, status: str, ledger: Any, command: Any) -> tuple[str, Any]:
        if status == "suppressed":
            require(command.event == "purge", "REINSTATE_REQUIRES_NEW_CONSENT", "a suppressed endpoint requires a fresh captured entity; only purge is permitted here", "do_not_replay")
            next_status, data = self.apply(plan, "suppressed", status, ledger.to_dict(), command)
            return next_status, self.ledger_model.model_validate(data)
        return super().step(plan, status, ledger, command)


_CONSENT_TABLE = {("new", "capture"): "captured", ("captured", "confirm"): "express", ("captured", "record_send"): "implied", ("express", "record_send"): "express", ("implied", "record_send"): "implied", ("implied", "mark_lapsing"): "lapsing", ("lapsing", "confirm"): "express", ("lapsing", "expire_implied"): "suppressed", **{(status, "withdraw"): "withdrawn" for status in ("express", "implied", "lapsing", "captured")}, ("withdrawn", "honour"): "suppressed", ("suppressed", "purge"): "suppressed"}
CONSENT_LIFECYCLE = _ConsentLifecycle(entity="contact_endpoint", schema_prefix="marketing_consent", statuses=CONSENT_STATUSES, terminal={"suppressed"}, events=CONSENT_EVENTS, table=_CONSENT_TABLE, opening_event="capture", reason_events=(), apply=_apply_consent, ledger_model=ConsentLedger, receipt_model=ConsentReceipt, effect_boundary_model=PermissionEffectBoundary, plan_model=PermissionPlan, max_transitions=24)
ConsentState = CONSENT_LIFECYCLE.State


def open_contact_endpoint(plan: Any, scope: Any, *, receipt: Any, opened_at: str, actor_ref: str) -> Any:
    scope = _parse(EngineScope, scope, "SOURCE_NOT_EVIDENCED")
    _require("@" not in scope.entity_ref, "ENDPOINT_NOT_HASHED", "an endpoint entity uses an opaque alias, never a contact address")
    return CONSENT_LIFECYCLE.open(plan, scope, receipt={**detached(receipt), "register_scope": scope.to_dict()}, opened_at=opened_at, actor_ref=actor_ref)


def advance_contact_endpoint(plan: Any, state: Any, command: Any) -> Any:
    return CONSENT_LIFECYCLE.advance(plan, state, command)


class RegisterSnapshot(StrictModel):
    kind: Literal["consent", "claim"]
    source_plan: PermissionPlan
    state: dict[str, Any]

    @model_validator(mode="after")
    def _guard(self) -> RegisterSnapshot:
        spec = CONSENT_LIFECYCLE if self.kind == "consent" else CLAIM_LIFECYCLE
        _, state = spec.bind(self.source_plan, self.state)
        if state.ledger.register_scope != state.scope.to_dict():
            raise ValueError("the register's retained scope must match its source state scope")
        return self


def register_snapshot(state: Any, source_plan: Any, *, kind: Literal["consent", "claim"] = "consent") -> RegisterSnapshot:
    return RegisterSnapshot(kind=kind, source_plan=_parse(PermissionPlan, source_plan, "SOURCE_NOT_EVIDENCED"), state=dict(detached(state)))


def _snapshots(states: Sequence[Any], kind: str) -> tuple[RegisterSnapshot, ...]:
    result = tuple(_parse(RegisterSnapshot, value, "SOURCE_NOT_EVIDENCED") for value in states)
    _require(bool(result) and len(result) <= 500, "SOURCE_NOT_EVIDENCED", "a bounded set of source states and their plans is required")
    _require(all(item.kind == kind for item in result), "SOURCE_NOT_EVIDENCED", "the projection requires the named register lifecycle")
    _require(len({(item.source_plan.company_ref, item.source_plan.currency, item.source_plan.plan_digest) for item in result}) == 1, "SOURCE_NOT_EVIDENCED", "register projections cannot mix company scope or permission plans")
    _require(len({stable_digest({key: value for key, value in item.state["scope"].items() if key != "entity_ref"}) for item in result}) == 1, "SOURCE_NOT_EVIDENCED", "register projections cannot combine different authenticated scope bindings")
    return result


class SuppressionDigest(StrictModel):
    schema_id: Literal["lightbulb.permission_suppression_digest.v1"] = Field(default="lightbulb.permission_suppression_digest.v1", alias="schema")
    company_ref: OpaqueRef
    channel: Channel
    endpoints: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=500)
    source_digests: tuple[Sha256Digest, ...] = Field(max_length=500)
    as_of: str
    suppression_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> SuppressionDigest:
        unique(self.endpoints, label="suppressed endpoints")
        if not skip_digests(info) and self.suppression_digest != sealed_digest(SuppressionDigest, self, "suppression_digest"):
            raise ValueError("suppression_digest must commit the exact suppression set")
        return self


class EligibilityReceipt(StrictModel):
    schema_id: Literal["lightbulb.permission_eligibility_receipt.v1"] = Field(default="lightbulb.permission_eligibility_receipt.v1", alias="schema")
    company_ref: OpaqueRef
    plan_digest: Sha256Digest
    channel: Channel
    endpoints: tuple[Sha256Digest, ...] = Field(min_length=1, max_length=500)
    eligible_endpoints: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=500)
    as_of: str
    valid_until: str
    suppression_digest: Sha256Digest
    source_states: tuple[RegisterSnapshot, ...] = Field(min_length=1, max_length=500)
    rejections: dict[str, str] = Field(default_factory=dict)
    eligibility_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("as_of", "valid_until")
    @classmethod
    def _stamp(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> EligibilityReceipt:
        unique(self.endpoints, label="eligibility endpoints")
        if not set(self.eligible_endpoints) <= set(self.endpoints) or parsed(self.valid_until) <= parsed(self.as_of):
            raise ValueError("eligible endpoints and validity must be within the requested set and window")
        if not skip_digests(info) and self.eligibility_digest != sealed_digest(EligibilityReceipt, self, "eligibility_digest"):
            raise ValueError("eligibility_digest must commit the exact projection")
        return self


def eligibility_receipt(states: Sequence[Any], *, channel: str, endpoints: Sequence[str], now: str) -> tuple[EligibilityReceipt, SuppressionDigest]:
    snapshots = _snapshots(states, "consent")
    at = timestamp(now, field_name="now")
    plan = snapshots[0].source_plan
    requested = tuple(sorted(endpoints))
    _require(bool(requested) and len(set(requested)) == len(requested), "ENDPOINT_NOT_HASHED", "eligibility requires unique keyed endpoint digests")
    _require(all(isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value) for value in requested), "ENDPOINT_NOT_HASHED", "eligibility accepts keyed digests, never addresses")
    records: dict[str, Any] = {}
    eligible, denied, suppress = [], {}, []
    for item in snapshots:
        _, state = CONSENT_LIFECYCLE.bind(item.source_plan, item.state)
        endpoint = str(state.ledger.endpoint_digest)
        _require(endpoint not in records, "SOURCE_NOT_EVIDENCED", "each keyed endpoint must have one authoritative current consent state")
        _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_NOT_EVIDENCED", "eligibility cannot use future state")
        records[endpoint] = state
    valid_until = iso(parsed(at) + timedelta(minutes=plan.eligibility_minutes))
    for endpoint in requested:
        state = records.get(endpoint)
        if state is None:
            denied[endpoint] = "SOURCE_NOT_EVIDENCED"
            suppress.append(endpoint)
            continue
        try:
            _consent_check(plan, state.status, state.ledger.to_dict(), channel=channel, at=at)
            if state.status == "captured" and state.ledger.basis == "express":
                raise Rejected("CONFIRMATION_MISSING", "captured express consent must be confirmed")
            eligible.append(endpoint)
            if state.ledger.expires_at:
                valid_until = min((valid_until, state.ledger.expires_at), key=parsed)
        except Rejected as exc:
            denied[endpoint] = exc.code
            suppress.append(endpoint)
    suppression = seal(SuppressionDigest, {"company_ref": plan.company_ref, "channel": channel, "endpoints": suppress, "source_digests": sorted(item.state["state_digest"] for item in snapshots), "as_of": at}, "suppression_digest")
    receipt = seal(EligibilityReceipt, {"company_ref": plan.company_ref, "plan_digest": plan.plan_digest, "channel": channel, "endpoints": requested, "eligible_endpoints": eligible, "as_of": at, "valid_until": valid_until, "suppression_digest": suppression.suppression_digest, "source_states": snapshots, "rejections": denied}, "eligibility_digest")
    return receipt, suppression


def verify_eligibility(receipt: Any, *, suppression_digest: str, channel: str, at: str, endpoints: Sequence[str] | None = None, company_ref: str | None = None, expected_scope: Any = None) -> EligibilityReceipt:
    proof = _parse(EligibilityReceipt, receipt, "SEND_WITHOUT_ELIGIBILITY")
    rebuilt, suppressed = eligibility_receipt(proof.source_states, channel=proof.channel, endpoints=proof.endpoints, now=proof.as_of)
    _require(rebuilt.eligibility_digest == proof.eligibility_digest and suppressed.suppression_digest == suppression_digest == proof.suppression_digest, "SEND_WITHOUT_ELIGIBILITY", "eligibility and suppression must rederive from the retained register states")
    _require(proof.channel == channel, "CHANNEL_NOT_COVERED", "email consent is not permission for another channel")
    _require(company_ref is None or company_ref == proof.company_ref, "SOURCE_NOT_EVIDENCED", "eligibility belongs to another company")
    if expected_scope is not None:
        scope = dict(detached(expected_scope))
        _require(all(proof.source_states[0].state["scope"].get(key) == scope.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "SOURCE_NOT_EVIDENCED", "eligibility belongs to another authenticated execution scope")
    requested = tuple(endpoints) if endpoints is not None else proof.endpoints
    for endpoint in requested:
        _require(endpoint in proof.eligible_endpoints, proof.rejections.get(endpoint, "SEND_WITHOUT_ELIGIBILITY"), "the requested endpoint is not eligible under the retained register")
    _require(parsed(proof.as_of) <= parsed(timestamp(at, field_name="at")) < parsed(proof.valid_until), "SEND_WITHOUT_ELIGIBILITY", "eligibility has expired or is from the future")
    return proof


class EligibilityCommitment(StrictModel):
    """A send's compact commitment; the engine independently checks its own ledger."""
    schema_id: Literal["lightbulb.permission_send_eligibility.v1"] = Field(default="lightbulb.permission_send_eligibility.v1", alias="schema")
    endpoint_digest: Sha256Digest
    channel: Channel
    plan_digest: Sha256Digest
    state_digest: Sha256Digest
    eligibility_digest: Sha256Digest
    suppression_digest: Sha256Digest
    as_of: str
    valid_until: str
    commitment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("as_of", "valid_until")
    @classmethod
    def _stamp(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> EligibilityCommitment:
        if not skip_digests(info) and self.commitment_digest != sealed_digest(EligibilityCommitment, self, "commitment_digest"):
            raise ValueError("commitment_digest must commit the exact send eligibility")
        return self


def send_receipt(execution_receipt: Any, *, eligibility: Any = None) -> dict[str, Any]:
    effect, facts = _effect(execution_receipt, "send")
    proof = verify_eligibility(eligibility, suppression_digest=str(facts.suppression_digest), channel=str(facts.channel), endpoints=[str(facts.endpoint_digest)], at=effect.execution.completed_at, company_ref=facts.company_ref)
    source = next(item for item in proof.source_states if item.state["ledger"]["endpoint_digest"] == facts.endpoint_digest)
    commitment = seal(EligibilityCommitment, {"endpoint_digest": facts.endpoint_digest, "channel": proof.channel, "plan_digest": proof.plan_digest, "state_digest": source.state["state_digest"], "eligibility_digest": proof.eligibility_digest, "suppression_digest": proof.suppression_digest, "as_of": proof.as_of, "valid_until": proof.valid_until}, "commitment_digest")
    return {"effect": effect.to_dict(), "eligibility": commitment.to_dict(), "evidence_refs": [f"send:{effect.execution.execution_digest[:24]}"]}


class ClaimProposal(StrictModel):
    schema_id: Literal["lightbulb.marketing_claim_proposal.v1"] = Field(default="lightbulb.marketing_claim_proposal.v1", alias="schema")
    operator_supplied: Literal[True] = True
    company_ref: OpaqueRef
    claim_ref: OpaqueRef
    text: ShortText
    requester_ref: OpaqueRef
    channels: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    jurisdictions: tuple[ShortText, ...] = Field(min_length=1, max_length=20)
    products: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)
    proposal_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ClaimProposal:
        if not skip_digests(info) and self.proposal_digest != sealed_digest(ClaimProposal, self, "proposal_digest"):
            raise ValueError("proposal_digest must commit the operator's proposed claim")
        return self


def propose_receipt(proposal: Any) -> dict[str, Any]:
    return {"proposal": _parse(ClaimProposal, proposal, "EVIDENCE_MISSING").to_dict()}


class DocumentFacts(StrictModel):
    company_ref: OpaqueRef
    artifact_ref: OpaqueRef
    sha256: Sha256Digest
    valid_until: str
    source_kind: Literal["audit_report", "substantiating_document"]

    @field_validator("valid_until")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="valid_until")


class Substantiation(StrictModel):
    schema_id: Literal["lightbulb.marketing_claim_substantiation.v1"] = Field(default="lightbulb.marketing_claim_substantiation.v1", alias="schema")
    artifact_ref: OpaqueRef
    sha256: Sha256Digest
    valid_until: str
    source: dict[str, Any]
    substantiation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("valid_until")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="valid_until")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Substantiation:
        if not skip_digests(info) and self.substantiation_digest != sealed_digest(Substantiation, self, "substantiation_digest"):
            raise ValueError("substantiation_digest must commit its retained source")
        return self


def _substantiation(value: Any, *, company_ref: str | None = None, currency: str | None = None, at: str | None = None, expected_scope: Any = None) -> Substantiation:
    evidence = _parse(Substantiation, value, "EVIDENCE_MISSING")
    if "state" in evidence.source and "source_plan" in evidence.source:
        from lightbulb.obligation_paper import INSURANCE_KINDS, verify_paper_current, verify_cover_current
        source_plan = evidence.source["source_plan"]
        # The verifier parses its canonical plan itself; no ledger field is trusted here.
        try:
            options = {"source_plan": source_plan, "company_ref": company_ref or source_plan["company_ref"], "currency": currency or source_plan["currency"], "at": at or evidence.source["state"]["transition_history"][-1]["command"]["occurred_at"], "expected_scope": expected_scope}
            state = verify_paper_current(evidence.source["state"], **options)
            if state.ledger.kind in INSURANCE_KINDS:
                state = verify_cover_current(evidence.source["state"], **options)
        except (ValueError, TypeError, KeyError) as exc:
            raise PermissionRegisterError("EVIDENCE_EXPIRED", "the substantiating standing item is not currently valid") from exc
        expected = (state.ledger.item_ref, state.ledger.document_sha256, state.ledger.period_end)
    else:
        observation = _parse(PermissionObservation, evidence.source, "EVIDENCE_MISSING")
        facts = _parse(DocumentFacts, observation.payload, "EVIDENCE_MISSING")
        _require(observation.provenance.source_tool in {"host.audit_report", "host.document_metadata"} and observation.provenance.lane == "host_read", "EVIDENCE_MISSING", "substantiation requires a provenance-bound audit or document metadata read")
        _require(company_ref is None or facts.company_ref == company_ref, "EVIDENCE_MISSING", "the document belongs to another company")
        if at is not None:
            _require(parsed(observation.provenance.completed_at) <= parsed(at), "EVIDENCE_MISSING", "the document read cannot be from the future")
        expected = (facts.artifact_ref, facts.sha256, facts.valid_until)
    _require((evidence.artifact_ref, evidence.sha256, evidence.valid_until) == expected, "EVIDENCE_MISSING", "the document reference, hash and expiry must come from the retained source")
    if at is not None:
        _require(parsed(at) < parsed(evidence.valid_until), "EVIDENCE_EXPIRED", "the substantiating document has expired")
    return evidence


def substantiation_receipt(artifact_ref: str, sha256: str, valid_until: str, source: Any) -> dict[str, Any]:
    evidence = seal(Substantiation, {"artifact_ref": artifact_ref, "sha256": sha256, "valid_until": valid_until, "source": dict(detached(source))}, "substantiation_digest")
    return {"substantiation": _substantiation(evidence).to_dict()}


class ReviewDispatchEvidence(StrictModel):
    schema_id: Literal["lightbulb.marketing_claim_review_dispatch.v1"] = Field(default="lightbulb.marketing_claim_review_dispatch.v1", alias="schema")
    source_plan: dict[str, Any]
    worker_state: dict[str, Any]
    dispatch_request: dict[str, Any]
    review_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ReviewDispatchEvidence:
        if not skip_digests(info) and self.review_digest != sealed_digest(ReviewDispatchEvidence, self, "review_digest"):
            raise ValueError("review_digest must commit the worker evidence")
        return self


def _review(value: Any, *, claim_ref: str, at: str, expected_scope: Any = None, operating_digest: str | None = None) -> ReviewDispatchEvidence:
    from lightbulb.company_workforce import DispatchRequest, WORKER_LIFECYCLE
    evidence = _parse(ReviewDispatchEvidence, value, "REVIEW_MISSING")
    try:
        plan, state = WORKER_LIFECYCLE.bind(evidence.source_plan, evidence.worker_state)
        request = DispatchRequest.model_validate(evidence.dispatch_request)
    except (ValueError, TypeError) as exc:
        raise PermissionRegisterError("REVIEW_MISSING", "review must retain the actual workforce plan, state, and dispatch request") from exc
    action = request.action if "." in request.action else f"{request.domain}.{request.action}"
    _require(operating_digest is None or plan.operating_plan_digest == operating_digest, "REVIEW_MISSING", "the workforce must belong to the permission plan's operating plan")
    _require(expected_scope is None or all(state.scope.to_dict().get(key) == expected_scope.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "REVIEW_MISSING", "review evidence belongs to another authenticated scope")
    _require(action in {"legal.contract_review", "grc.policy_gap_analysis"} and request.inputs.get("claim_ref") == claim_ref, "REVIEW_MISSING", "a legal or GRC review must name this claim")
    dispatches = [item.command for item in state.transition_history if item.command.event == "dispatch" and item.command.receipt.evidence_ref == f"dispatch:{request.request_digest[:24]}" and item.command.receipt.action == request.action and item.command.receipt.worker_ref == request.worker_ref]
    _require(len(dispatches) == 1, "REVIEW_MISSING", "the worker history must retain the matching dispatched request")
    succeeded = [item.command for item in state.transition_history if item.command.event == "record_outcome" and item.command.receipt.dispatch_ref == dispatches[0].receipt.dispatch_ref and item.command.receipt.outcome == "succeeded" and parsed(item.command.occurred_at) <= parsed(at)]
    _require(len(succeeded) == 1, "REVIEW_MISSING", "the review must have completed successfully before approval")
    return evidence


def review_dispatch_receipt(worker_state: Any, *, source_plan: Any, dispatch_request: Any) -> ReviewDispatchEvidence:
    evidence = seal(ReviewDispatchEvidence, {"worker_state": detached(worker_state), "source_plan": detached(source_plan), "dispatch_request": detached(dispatch_request)}, "review_digest")
    request = evidence.dispatch_request
    return _review(evidence, claim_ref=str(request.get("inputs", {}).get("claim_ref", "")), at=evidence.worker_state["transition_history"][-1]["command"]["occurred_at"])


def review_receipt(dispatch_receipt: Any, authorization_proof: Any) -> dict[str, Any]:
    from lightbulb.authority_matrix import AuthorizationProof
    proof = _parse(AuthorizationProof, authorization_proof, "REVIEW_MISSING")
    review = _review(dispatch_receipt, claim_ref=proof.entity_ref, at=proof.decided_at)
    return {"review_source": review.to_dict(), "authorization_proof": proof.to_dict()}


def publication_receipt(execution_receipt: Any) -> dict[str, Any]:
    effect, facts = _effect(execution_receipt, "publish", code="EVIDENCE_MISSING")
    _require(bool(facts.asset_refs) and facts.claim_ref in facts.live_claim_refs, "EVIDENCE_MISSING", "publication must prove the assets that now cite the claim")
    return {"publication": effect.to_dict()}


class ClaimReceipt(StrictModel):
    register_scope: dict[str, Any] | None = None
    proposal: dict[str, Any] | None = None
    substantiation: dict[str, Any] | None = None
    review_source: dict[str, Any] | None = None
    authorization_proof: dict[str, Any] | None = None
    publication: dict[str, Any] | None = None
    cascade: dict[str, Any] | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=30)


class ClaimLedger(StrictModel):
    register_scope: dict[str, Any] | None = None
    claim_ref: OpaqueRef | None = None
    text: ShortText | None = None
    requester_ref: OpaqueRef | None = None
    channels: tuple[ShortText, ...] = Field(default_factory=tuple)
    jurisdictions: tuple[ShortText, ...] = Field(default_factory=tuple)
    products: tuple[OpaqueRef, ...] = Field(default_factory=tuple)
    substantiation: dict[str, Any] | None = None
    evidence_valid_until: str | None = None
    review_due_at: str | None = None
    review_digest: Sha256Digest | None = None
    approval_ref: OpaqueRef | None = None
    approver_ref: OpaqueRef | None = None
    approved_at: str | None = None
    usage_assets: tuple[OpaqueRef, ...] = Field(default_factory=tuple)
    usage_campaigns: tuple[OpaqueRef, ...] = Field(default_factory=tuple)
    publication_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple)
    withdrawn_at: str | None = None
    cascade_digest: Sha256Digest | None = None
    outcome: str | None = None


def _claim_current(plan: PermissionPlan, data: Mapping[str, Any], at: str) -> None:
    _substantiation(data.get("substantiation"), company_ref=plan.company_ref, currency=plan.currency, at=at, expected_scope=data.get("register_scope"))
    require(data.get("review_due_at") is not None and parsed(at) < parsed(str(data["review_due_at"])), "RESUBSTANTIATION_OVERDUE", "the claim must be independently resubstantiated before further use", "manual_reconciliation")


def _apply_claim(plan: PermissionPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    try:
        if event == "propose":
            proposal = _parse(ClaimProposal, r.proposal, "EVIDENCE_MISSING")
            scope = _parse(EngineScope, r.register_scope, "EVIDENCE_MISSING")
            require(scope.currency == plan.currency and scope.entity_ref == proposal.claim_ref, "EVIDENCE_MISSING", "claim scope must match the proposed claim and plan currency")
            data["register_scope"] = scope.to_dict()
            require(proposal.company_ref == plan.company_ref, "EVIDENCE_MISSING", "the proposed claim belongs to another company")
            require(not any(term.casefold() in proposal.text.casefold() for term in plan.prohibited_terms), "PROHIBITED_TERM", "the claim contains a prohibited term from the growth policy")
            data.update(claim_ref=proposal.claim_ref, text=proposal.text, requester_ref=proposal.requester_ref, channels=proposal.channels, jurisdictions=proposal.jurisdictions, products=proposal.products)
        elif event in {"substantiate", "renew_evidence"}:
            evidence = _substantiation(r.substantiation, company_ref=plan.company_ref, currency=plan.currency, at=at, expected_scope=data.get("register_scope"))
            if event == "renew_evidence":
                _approve_claim(plan, data, command)
            data.update(substantiation=evidence.to_dict(), evidence_valid_until=evidence.valid_until)
        elif event == "submit_review":
            review = _review(r.review_source, claim_ref=str(data["claim_ref"]), at=at, expected_scope=data.get("register_scope"), operating_digest=plan.source_operating_plan["plan_digest"])
            _substantiation(data.get("substantiation"), company_ref=plan.company_ref, currency=plan.currency, at=at, expected_scope=data.get("register_scope"))
            data["review_digest"] = review.review_digest
        elif event == "approve":
            _substantiation(data.get("substantiation"), company_ref=plan.company_ref, currency=plan.currency, at=at, expected_scope=data.get("register_scope"))
            _approve_claim(plan, data, command)
        elif event == "publish":
            _claim_current(plan, data, at)
            effect, facts = _effect(r.publication, "publish", code="EVIDENCE_MISSING")
            require(effect.execution.project_id == data["register_scope"]["project_id"], "EVIDENCE_MISSING", "publication belongs to another project")
            require(facts.company_ref == plan.company_ref and facts.claim_ref == data.get("claim_ref") and facts.claim_ref in facts.live_claim_refs and bool(facts.asset_refs), "EVIDENCE_MISSING", "publication must name this claim and its live assets")
            require(facts.channel in data["channels"] and facts.jurisdiction in data["jurisdictions"] and facts.product in data["products"], "SCOPE_MISMATCH", "the published claim is outside its approved channel, jurisdiction or product scope")
            require(parsed(str(data["approved_at"])) <= parsed(effect.execution.completed_at) <= parsed(at), "EVIDENCE_MISSING", "publication must follow approval and precede its recording")
            require(effect.execution.execution_digest not in data.get("publication_digests", ()), "EVIDENCE_MISSING", "one publication execution is indexed once")
            data.update(usage_assets=sorted(set(data.get("usage_assets", ())) | set(facts.asset_refs)), usage_campaigns=sorted(set(data.get("usage_campaigns", ())) | set(facts.campaign_refs)), publication_digests=[*data.get("publication_digests", ()), effect.execution.execution_digest])
        elif event == "mark_resubstantiation_due":
            require(parsed(at) >= parsed(str(data["review_due_at"])) or parsed(at) >= parsed(str(data["evidence_valid_until"])), "EVIDENCE_MISSING", "resubstantiation is due only on the review or document clock")
        elif event == "withdraw":
            data.update(withdrawn_at=at, outcome="withdrawn")
        elif event in {"complete_cascade", "retire"}:
            cascade = _verify_cascade(r.cascade, data=data, at=at, company_ref=plan.company_ref)
            data.update(cascade_digest=cascade.cascade_digest, outcome="retired")
        elif event == "reject":
            data["outcome"] = "rejected"
    except PermissionRegisterError as exc:
        raise Rejected(exc.code, exc.message, exc.recovery) from exc
    return next_status, data


def _approve_claim(plan: PermissionPlan, data: dict[str, Any], command: Any) -> None:
    from lightbulb.authority_matrix import AuthorizationProof, require_authorization_proof
    r = command.receipt
    review = _review(r.review_source, claim_ref=str(data["claim_ref"]), at=command.occurred_at, expected_scope=data.get("register_scope"), operating_digest=plan.source_operating_plan["plan_digest"])
    proof = _parse(AuthorizationProof, r.authorization_proof, "REVIEW_MISSING")
    require(proof.approver_ref != data["requester_ref"], "REVIEWER_NOT_INDEPENDENT", "the claim requester cannot approve the claim", "manual_reconciliation")
    proof = require_authorization_proof(proof, category="commitment", amount=Decimal("0.00"), currency=plan.currency, company_ref=plan.company_ref, plan_digest=plan.plan_digest, entity_ref=data["claim_ref"], requester_ref=data["requester_ref"], command=command)
    data.update(review_digest=review.review_digest, approval_ref=proof.approval_task_id, approver_ref=proof.approver_ref, approved_at=proof.decided_at, review_due_at=_months(proof.decided_at, plan.claim_review_months))


_CLAIM_TABLE = {("new", "propose"): "proposed", ("proposed", "substantiate"): "evidenced", ("evidenced", "submit_review"): "in_review", ("in_review", "approve"): "approved", ("in_review", "reject"): "rejected", ("approved", "publish"): "in_use", ("in_use", "mark_resubstantiation_due"): "resubstantiation_due", ("resubstantiation_due", "renew_evidence"): "in_use", ("in_use", "withdraw"): "withdrawn", ("resubstantiation_due", "withdraw"): "withdrawn", ("withdrawn", "complete_cascade"): "retired", ("in_use", "retire"): "retired"}
CLAIM_LIFECYCLE = LifecycleSpec(entity="claim", schema_prefix="marketing_claim", statuses=CLAIM_STATUSES, terminal={"retired", "rejected"}, events=CLAIM_EVENTS, table=_CLAIM_TABLE, opening_event="propose", reason_events=("withdraw", "retire", "reject"), apply=_apply_claim, ledger_model=ClaimLedger, receipt_model=ClaimReceipt, effect_boundary_model=PermissionEffectBoundary, plan_model=PermissionPlan, max_transitions=32)
ClaimState = CLAIM_LIFECYCLE.State


def open_claim(plan: Any, scope: Any, *, receipt: Any, opened_at: str, actor_ref: str) -> Any:
    scope = _parse(EngineScope, scope, "EVIDENCE_MISSING")
    return CLAIM_LIFECYCLE.open(plan, scope, receipt={**detached(receipt), "register_scope": scope.to_dict()}, opened_at=opened_at, actor_ref=actor_ref)


def advance_claim(plan: Any, state: Any, command: Any) -> Any:
    return CLAIM_LIFECYCLE.advance(plan, state, command)


class CascadeEvidence(StrictModel):
    schema_id: Literal["lightbulb.marketing_claim_cascade.v1"] = Field(default="lightbulb.marketing_claim_cascade.v1", alias="schema")
    campaign_states: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    asset_effects: tuple[PermissionExecution, ...] = Field(default_factory=tuple, max_length=100)
    cascade_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CascadeEvidence:
        if not skip_digests(info) and self.cascade_digest != sealed_digest(CascadeEvidence, self, "cascade_digest"):
            raise ValueError("cascade_digest must commit all campaign and asset evidence")
        return self


def cascade_receipt(campaign_states: Sequence[Any], asset_refs: Sequence[Any]) -> dict[str, Any]:
    """Asset entries are bound republishing effects, never loose names of assets."""
    effects = [_effect(item, "cascade", code="WITHDRAWAL_CASCADE_INCOMPLETE")[0] for item in asset_refs]
    source = seal(CascadeEvidence, {"campaign_states": [detached(item) for item in campaign_states], "asset_effects": effects}, "cascade_digest")
    return {"cascade": source.to_dict()}


def _verify_cascade(value: Any, *, data: Mapping[str, Any], at: str, company_ref: str) -> CascadeEvidence:
    from lightbulb.growth_engine_loop import CAMPAIGN_LIFECYCLE
    evidence = _parse(CascadeEvidence, value, "WITHDRAWAL_CASCADE_INCOMPLETE")
    assets, campaigns = set(), set()
    for item in evidence.asset_effects:
        effect, facts = _effect(item, "cascade", code="WITHDRAWAL_CASCADE_INCOMPLETE")
        _require(effect.execution.project_id == data["register_scope"]["project_id"], "WITHDRAWAL_CASCADE_INCOMPLETE", "asset cascade belongs to another project")
        _require(facts.company_ref == company_ref and data["claim_ref"] not in facts.live_claim_refs and parsed(effect.execution.completed_at) <= parsed(at), "WITHDRAWAL_CASCADE_INCOMPLETE", "republished assets must prove the company's withdrawn claim is absent")
        if data.get("withdrawn_at"):
            _require(parsed(effect.execution.completed_at) >= parsed(str(data["withdrawn_at"])), "WITHDRAWAL_CASCADE_INCOMPLETE", "cascade effects must follow withdrawal")
        assets.update(facts.asset_refs)
    for item in evidence.campaign_states:
        try:
            _, state = CAMPAIGN_LIFECYCLE.bind(item["source_plan"], item["state"])
        except (ValueError, TypeError, KeyError) as exc:
            raise PermissionRegisterError("WITHDRAWAL_CASCADE_INCOMPLETE", "campaign cascade evidence must retain a replayable state and source plan") from exc
        _require(state.status in {"paused", "completed", "halted"} and parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "WITHDRAWAL_CASCADE_INCOMPLETE", "a campaign still live or unproven cannot complete withdrawal")
        _require(all(state.scope.to_dict().get(key) == data["register_scope"].get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "WITHDRAWAL_CASCADE_INCOMPLETE", "campaign cascade belongs to another authenticated scope")
        campaigns.add(state.scope.entity_ref)
    _require(set(data.get("usage_assets", ())) <= assets and set(data.get("usage_campaigns", ())) <= campaigns, "WITHDRAWAL_CASCADE_INCOMPLETE", "every asset and campaign in the claim usage index must be paused or republished")
    return evidence


def approved_claims(states: Sequence[Any], *, channel: str, jurisdiction: str, product: str, at: str) -> tuple[dict[str, Any], ...]:
    snapshots = _snapshots(states, "claim")
    out = []
    for item in snapshots:
        plan, state = CLAIM_LIFECYCLE.bind(item.source_plan, item.state)
        _require(state.status in {"approved", "in_use"}, "REVIEW_MISSING", "only independently approved current claims may be projected")
        _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(timestamp(at, field_name="at")), "REVIEW_MISSING", "claim projections cannot use future register state")
        try:
            _claim_current(plan, state.ledger.to_dict(), timestamp(at, field_name="at"))
        except Rejected as exc:
            raise PermissionRegisterError(exc.code, exc.instructions) from exc
        _require(channel in state.ledger.channels and jurisdiction in state.ledger.jurisdictions and product in state.ledger.products, "SCOPE_MISMATCH", "claim projection must remain in its approved channel, jurisdiction and product scope")
        out.append({"claim_ref": state.ledger.claim_ref, "text": state.ledger.text, "evidence_ref": f"claim:{state.state_digest[:24]}", "expires_at": min((state.ledger.evidence_valid_until, state.ledger.review_due_at), key=parsed), "source_state": item.to_dict()})
    return tuple(out)


def verify_claim_projection(projection: Mapping[str, Any], *, channel: str, jurisdiction: str, product: str, at: str, company_ref: str | None = None, expected_scope: Any = None) -> dict[str, Any]:
    raw = dict(detached(projection))
    snapshot = _parse(RegisterSnapshot, raw.get("source_state"), "REVIEW_MISSING")
    _require(company_ref is None or snapshot.source_plan.company_ref == company_ref, "EVIDENCE_MISSING", "the claim projection belongs to another company")
    if expected_scope is not None:
        scope = dict(detached(expected_scope))
        _require(all(snapshot.state["scope"].get(key) == scope.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "EVIDENCE_MISSING", "claim projection belongs to another authenticated execution scope")
    rebuilt = approved_claims([snapshot], channel=channel, jurisdiction=jurisdiction, product=product, at=at)[0]
    _require(raw == rebuilt, "EVIDENCE_MISSING", "the approved claim projection must match its replayed register state")
    return rebuilt


class ConsentRegistry(StrictModel):
    schema_id: Literal["lightbulb.permission_consent_registry.v1"] = Field(default="lightbulb.permission_consent_registry.v1", alias="schema")
    company_ref: OpaqueRef
    as_of: str
    source_states: tuple[RegisterSnapshot, ...] = Field(min_length=1, max_length=500)
    registry_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ConsentRegistry:
        sources = _snapshots(self.source_states, "consent")
        if sources[0].source_plan.company_ref != self.company_ref:
            raise ValueError("registry company must match its retained consent sources")
        if not skip_digests(info) and self.registry_digest != sealed_digest(ConsentRegistry, self, "registry_digest"):
            raise ValueError("registry_digest must commit the consent sources")
        return self


def consent_registry(states: Sequence[Any], *, now: str) -> ConsentRegistry:
    snapshots = _snapshots(states, "consent")
    return seal(ConsentRegistry, {"company_ref": snapshots[0].source_plan.company_ref, "as_of": now, "source_states": snapshots}, "registry_digest")


def permission_obligations(states: Sequence[Any], *, now: str) -> tuple[dict[str, Any], ...]:
    """Exact unsubscribe deadlines; record-retention policy stays platform-owned."""
    out = []
    for snapshot in _snapshots(states, "consent"):
        state = snapshot.state
        if state["status"] == "withdrawn":
            deadline = _business_deadline(state["ledger"]["withdrawn_at"], snapshot.source_plan)
            out.append({"kind": "unsubscribe_sla", "source_ref": state["scope"]["entity_ref"], "source_digest": state["state_digest"], "due_at": deadline, "overdue": parsed(timestamp(now, field_name="now")) > parsed(deadline)})
    return tuple(out)


_EXCEPTION_KIND_BY_CODE = {"WITHDRAWAL_NOT_HONOURED": "overdue_obligation", "RESUBSTANTIATION_OVERDUE": "overdue_obligation", "WITHDRAWAL_CASCADE_INCOMPLETE": "chain_reconciliation"}


def permission_exception(error: PermissionRegisterError | Rejected, *, source_ref: str, source_digest: str | None = None) -> dict[str, Any]:
    """An exceptions-desk opening receipt for a refused permission transition."""
    code = str(getattr(error, "code", "SOURCE_NOT_EVIDENCED"))
    detail = str(getattr(error, "message", None) or getattr(error, "instructions", None) or error)
    digest = source_digest or stable_digest({"source_ref": source_ref, "code": code, "detail": detail})
    return {"kind": _EXCEPTION_KIND_BY_CODE.get(code, "tick_rejection"), "source_engine": PERMISSION_REGISTER_KIND, "source_ref": source_ref, "source_digest": digest, "code": code, "detail": detail[:900], "evidence_refs": [f"permission:{code.lower()}"]}


def permission_exceptions(states: Sequence[Any], *, now: str, kind: Literal["consent", "claim"] = "consent") -> tuple[dict[str, Any], ...]:
    """The desk's own openings from retained state: an unsubscribe past its deadline, a withdrawal still cited."""
    at, out = timestamp(now, field_name="now"), []
    for snapshot in _snapshots(states, kind):
        state, ledger = snapshot.state, snapshot.state["ledger"]
        if state["status"] != "withdrawn":
            continue
        source_ref, digest = state["scope"]["entity_ref"], state["state_digest"]
        if kind == "consent":
            deadline = _business_deadline(ledger["withdrawn_at"], snapshot.source_plan)
            if parsed(at) > parsed(deadline):
                out.append(permission_exception(PermissionRegisterError("WITHDRAWAL_NOT_HONOURED", f"suppression for {source_ref} was due at {deadline} and is not proven materialized"), source_ref=source_ref, source_digest=digest))
        elif ledger.get("usage_assets") or ledger.get("usage_campaigns"):
            cited = [*ledger.get("usage_assets", ()), *ledger.get("usage_campaigns", ())]
            out.append(permission_exception(PermissionRegisterError("WITHDRAWAL_CASCADE_INCOMPLETE", f"{ledger['claim_ref']} is withdrawn while {len(cited)} indexed assets and campaigns still cite it"), source_ref=source_ref, source_digest=digest))
    return tuple(out)


def permission_summary(state: Any, *, source_plan: Any, kind: Literal["consent", "claim"] = "consent") -> dict[str, Any]:
    snapshot = register_snapshot(state, source_plan, kind=kind)
    return {"kind": kind, "status": snapshot.state["status"], "entity_ref": snapshot.state["scope"]["entity_ref"], "state_digest": snapshot.state["state_digest"], **snapshot.state["ledger"]}


def claim_withdrawn_signal(state: Any, *, source_plan: Any) -> dict[str, Any]:
    snapshot = register_snapshot(state, source_plan, kind="claim")
    _require(snapshot.state["status"] == "withdrawn", "WITHDRAWAL_CASCADE_INCOMPLETE", "the signal must come from an actually withdrawn claim")
    return {"name": "signals.claim_withdrawn", "source_engine": PERMISSION_REGISTER_KIND, "source_ref": snapshot.state["scope"]["entity_ref"], "evidence_ref": f"claim:{snapshot.state['state_digest'][:24]}", "payload": {"claim_ref": snapshot.state["ledger"]["claim_ref"], "withdrawn_at": snapshot.state["ledger"]["withdrawn_at"]}}


PERMISSION_REGISTER_MANIFEST = {
    "schema": "lightbulb.company_engine_manifest.v1", "engine": PERMISSION_REGISTER_KIND, "golden_loop": PERMISSION_GOLDEN_LOOP,
    "stages": ["capture", "confirm", "check_eligibility", "record_send", "suppress", "substantiate", "review", "publish", "withdraw"],
    "statuses": list(CONSENT_STATUSES + CLAIM_STATUSES), "events": list(CONSENT_EVENTS + CLAIM_EVENTS),
    "hops": {"eligibility": "growth_execution.plan_launch / pipeline_execution.plan_next_touch", "claims": "growth_engine_loop.compose", "retained_consent": "service_delivery", "obligations": "compliance_calendar", "exceptions": "exceptions_desk"},
    "required_connectors": ["ecommerce.get_customer", "ecommerce.search_customers", "gmail.get_thread", "gmail.send_email", "microsoft.send_email", "twilio.lookup_message_status", "shopify.tag_customers_bulk", "shopify.update_page"],
    "hard_rules": ["the register holds keyed endpoint digests; the SDK proves a send committed to a suppression set, never that a given address was eligible", "implied consent expires on a clock the plan states", "a claim is approved by an independent human against a dated document, never by an agent", "withdrawing a claim is not complete until everything citing it is down"],
}

__all__ = ["PERMISSION_REGISTER_KIND", "PERMISSION_PLAN_SCHEMA", "PERMISSION_GOLDEN_LOOP", "PERMISSION_REGISTER_MANIFEST", "PERMISSION_CODES", "RECOVERY_BY_CODE", "CONSENT_STATUSES", "CONSENT_EVENTS", "CLAIM_STATUSES", "CLAIM_EVENTS", "PermissionRegisterError", "PermissionPlan", "PermissionObservation", "PermissionExecution", "PermissionEffectBoundary", "ConsentFacts", "EffectFacts", "ConsentReceipt", "ConsentLedger", "ConsentState", "CONSENT_LIFECYCLE", "ClaimProposal", "DocumentFacts", "Substantiation", "ReviewDispatchEvidence", "ClaimReceipt", "ClaimLedger", "ClaimState", "CLAIM_LIFECYCLE", "RegisterSnapshot", "EligibilityReceipt", "EligibilityCommitment", "SuppressionDigest", "CascadeEvidence", "ConsentRegistry", "compile_permission_register", "permission_observation", "permission_execution", "capture_receipt", "confirm_receipt", "withdrawal_receipt", "honour_receipt", "purge_receipt", "send_receipt", "eligibility_receipt", "verify_eligibility", "register_snapshot", "propose_receipt", "substantiation_receipt", "review_dispatch_receipt", "review_receipt", "publication_receipt", "cascade_receipt", "approved_claims", "verify_claim_projection", "consent_registry", "permission_obligations", "permission_exception", "permission_exceptions", "permission_summary", "claim_withdrawn_signal", "open_contact_endpoint", "advance_contact_endpoint", "open_claim", "advance_claim"]
