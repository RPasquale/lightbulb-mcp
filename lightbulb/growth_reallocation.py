"""Evidence-bound incremental allocation and governed advertising budget proposals.

Money is held in currency units. Google writes integral micros; Meta writes
integral minor units. These are proposals: the host resolves committed targets,
revalidates current account policy, obtains approval, and executes canonical Tools.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal, ROUND_DOWN
from typing import Any, ClassVar, Literal
import re
from pydantic import Field, ValidationInfo, field_validator, model_validator
from lightbulb.company_engine_core import (StrictModel, OpaqueRef, ShortText, Sha256Digest,
    CurrencyCode, GENESIS_DIGEST, MONEY_QUANTUM, detached, seal, sealed_digest, skip_digests,
    decimal_value, stable_digest, timestamp, parsed)
from lightbulb.company_execution_bridge import ObservationProvenance, ExecutionReceipt
from lightbulb.growth_engine_loop import CHANNELS, Channel, CampaignPortfolio, GrowthEngineLoopPlan

OBJECT_MAP_SCHEMA = "lightbulb.growth_envelope_object_map.v1"
WRITE_PLAN_SCHEMA = "lightbulb.growth_budget_write_plan.v1"
WRITE_PROOF_SCHEMA = "lightbulb.growth_budget_write_proof.v1"
FORBIDDEN_WRITE_CAPABILITIES = frozenset({"google_ads.enable_campaign", "google_ads.create_campaign",
    "meta_ads.activate_campaign", "meta_ads.create_campaign", "meta_ads.create_adset"})
_CHANNEL_WRITE_CAPABILITIES = {
    "paid_search_google": {"set_budget": "google_ads.update_budget", "stop": "google_ads.pause_campaign"},
    "paid_social_meta": {"set_budget": "meta_ads.update_budget", "stop": "meta_ads.pause_campaign"},
}
WRITE_UNSUPPORTED_CHANNELS = tuple(channel for channel in CHANNELS if channel not in _CHANNEL_WRITE_CAPABILITIES)
_IDENTIFIERS = frozenset({"customer_id", "ad_account_id", "object_id", "campaign_id", "adset_id",
    "resource_name", "campaign_resource_name", "campaign_budget_resource_name", "account_id"})

class GrowthReallocationError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")

def _require(condition, code, message):
    if not condition:
        raise GrowthReallocationError(code, message)

class _Sealed(StrictModel):
    digest_field: ClassVar[str]
    @model_validator(mode="after")
    def exact(self, info: ValidationInfo):
        if not skip_digests(info) and getattr(self, self.digest_field) != sealed_digest(type(self), self, self.digest_field):
            raise ValueError(f"{self.digest_field} must commit the complete document")
        return self

def _read(provenance, output, tool, schema):
    provenance = ObservationProvenance.model_validate(detached(provenance))
    output = dict(detached(output))
    _require(provenance.source_tool == tool and provenance.lane in ("governed_read", "observation_read_receipt"),
        "OBJECT_TOOL_MISMATCH", "only the exact governed provider read proves the target")
    _require(output.get("schema") == schema and provenance.output_digest == stable_digest(output),
        "OBJECT_READ_MISMATCH", "retain the exact provider output and its provenance")
    return provenance, output

class ProviderObjectBinding(StrictModel):
    channel: Channel
    object_kind: Literal["campaign"] = "campaign"
    object_commitment: Sha256Digest
    account_commitment: Sha256Digest
    resource_commitment: Sha256Digest | None = None
    budget_commitment: Sha256Digest | None = None
    budget_shared: bool | None = None
    name_tag: ShortText | None = None
    status: Literal["ENABLED", "PAUSED"]
    current_budget_micros: int | None = Field(default=None, ge=0, strict=True)
    current_daily_budget_minor: int | None = Field(default=None, ge=0, strict=True)
    observed_at: str
    provenance: ObservationProvenance
    output: dict[str, Any]

    @field_validator("observed_at")
    @classmethod
    def stamp(cls, value):
        return timestamp(value, field_name="observed_at")


def object_bindings(provenance, payload, *, channel):
    _require(channel in _CHANNEL_WRITE_CAPABILITIES, "OBJECT_CHANNEL_UNSUPPORTED", "no governed campaign read exists for this channel")
    google = channel == "paid_search_google"
    provider = "google_ads" if google else "meta_ads"
    provenance, raw = _read(provenance, payload, provider + ".list_campaigns", f"lightbulb.{provider}_campaign_page.v1")
    rows = raw.get("campaigns")
    _require(raw.get("exhaustive_read") is True and isinstance(rows, list) and 0 < len(rows) <= 200,
        "OBJECT_PAGE_TRUNCATED", "only a complete bounded campaign page proves target uniqueness")
    _require(type(raw.get("campaign_count")) is int and raw["campaign_count"] == len(rows),
        "OBJECT_PAGE_TRUNCATED", "the complete campaign count must match the retained rows")
    result, refs = [], set()
    for row in rows:
        ref = row.get("campaign_id_sha256")
        _require(ref not in refs, "OBJECT_COMMITMENT_DUPLICATE", "campaign commitments must be unique")
        refs.add(ref)
        status = row.get("status") if google else {"ACTIVE": "ENABLED", "PAUSED": "PAUSED"}.get(row.get("status"))
        _require(status in ("ENABLED", "PAUSED"), "OBJECT_STATUS_UNMAPPED", "unmapped campaign status cannot authorize a proposal")
        result.append(ProviderObjectBinding(channel=channel, object_commitment=ref,
            account_commitment=raw.get("customer_id_sha256" if google else "ad_account_id_sha256"),
            resource_commitment=row.get("campaign_resource_name_sha256") if google else ref,
            budget_commitment=row.get("budget_resource_name_sha256") if google else ref,
            budget_shared=row.get("budget_explicitly_shared") if google else False,
            name_tag=row.get("name_tag"), status=status,
            current_budget_micros=row.get("budget_amount_micros") if google else None,
            current_daily_budget_minor=row.get("daily_budget_minor") if not google else None,
            observed_at=raw.get("observed_at"), provenance=provenance, output=raw))
    return tuple(result)


def _verify_binding(value):
    binding = ProviderObjectBinding.model_validate(detached(value))
    candidates = object_bindings(binding.provenance, binding.output, channel=binding.channel)
    _require(any(candidate == binding for candidate in candidates), "OBJECT_READ_MISMATCH", "the binding must be reproduced from its retained read")
    return binding

class EnvelopeObjectEntry(StrictModel):
    envelope_ref: OpaqueRef
    channel: Channel
    object_commitment: Sha256Digest
    object_kind: Literal["campaign"] = "campaign"
    name_tag: ShortText | None = None

class EnvelopeObjectMap(_Sealed):
    digest_field: ClassVar[str] = "map_digest"
    schema_id: Literal["lightbulb.growth_envelope_object_map.v1"] = Field(default=OBJECT_MAP_SCHEMA, alias="schema")
    input_kind: Literal["operator_declared_envelope_object_map"]
    portfolio_digest: Sha256Digest
    entries: tuple[EnvelopeObjectEntry, ...] = Field(min_length=1, max_length=64)
    bindings: tuple[ProviderObjectBinding, ...] = Field(min_length=1, max_length=400)
    declared_by_ref: OpaqueRef
    declared_at: str
    map_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("declared_at")
    @classmethod
    def stamp(cls, value):
        return timestamp(value, field_name="declared_at")


def envelope_object_map(portfolio, entries, *, declared_by_ref, declared_at, bindings):
    portfolio = CampaignPortfolio.model_validate(detached(portfolio))
    bindings = tuple(_verify_binding(value) for value in bindings)
    by_ref = {(value.channel, value.object_commitment): value for value in bindings}
    envelope_refs = {row.envelope_ref: row for row in portfolio.envelopes}
    parsed_entries, used, targets = [], set(), set()
    for raw in entries:
        raw = detached(raw)
        _require(not any(key in raw for key in ("provenance_digest", "output_digest", "evidence_sha256", "tool_invocation_id")),
            "MAP_CLAIMS_PROVENANCE", "an operator declaration cannot claim a provider read's provenance")
        entry = EnvelopeObjectEntry.model_validate(raw)
        envelope = envelope_refs.get(entry.envelope_ref)
        _require(envelope is not None and envelope.channel == entry.channel, "ENVELOPE_UNKNOWN", "the map must name a portfolio envelope on the same channel")
        key = entry.channel, entry.object_commitment
        _require(entry.envelope_ref not in used and key not in targets, "ENVELOPE_OBJECT_DUPLICATE", "one target may back only one envelope")
        binding = by_ref.get(key)
        _require(binding is not None and entry.name_tag == binding.name_tag, "OBJECT_COMMITMENT_UNOBSERVED", "the map must refer to the exact observed campaign")
        if entry.name_tag is not None:
            prefix = "GA" if entry.channel == "paid_search_google" else "MA"
            _require(re.fullmatch("LB-" + prefix + "-[0-9A-F]{18}", entry.name_tag) is not None,
                "NAME_TAG_UNRECOGNISED", "provider names must use the governed deterministic tag")
        _require(parsed(binding.observed_at) <= parsed(declared_at), "OBJECT_FROM_FUTURE", "the declaration must follow its target observation")
        used.add(entry.envelope_ref); targets.add(key); parsed_entries.append(entry)
    return seal(EnvelopeObjectMap, {"input_kind": "operator_declared_envelope_object_map", "portfolio_digest": portfolio.portfolio_digest,
        "entries": parsed_entries, "bindings": bindings, "declared_by_ref": declared_by_ref, "declared_at": declared_at}, "map_digest")

class BudgetWriteUnit(StrictModel):
    ordinal: int = Field(ge=1, le=16, strict=True)
    unit_ref: OpaqueRef
    envelope_ref: OpaqueRef
    channel: Channel
    intent: Literal["increase_budget", "decrease_budget", "pause_campaign"]
    capability: ShortText
    object_commitment: Sha256Digest
    target_commitment: Sha256Digest
    account_commitment: Sha256Digest
    arguments: dict[str, Any]
    identifier_fields_supplied_by_platform: tuple[ShortText, ...] = Field(min_length=1, max_length=3)
    period_days: int = Field(ge=1, le=366, strict=True)
    currency_minor_exponent: int = Field(ge=0, le=6, strict=True)
    period_amount: Decimal
    daily_amount: Decimal
    rounding_residue: Decimal
    approval_required: Literal[True] = True
    status: Literal["proposal_only_not_executed"] = "proposal_only_not_executed"
    content_digest: Sha256Digest
    approval_unit: OpaqueRef

    @field_validator("period_amount", "daily_amount", "rounding_residue", mode="before")
    @classmethod
    def money(cls, value, info):
        return decimal_value(value, field_name=info.field_name)

    @model_validator(mode="after")
    def exact(self):
        _require(self.capability in _CHANNEL_WRITE_CAPABILITIES.get(self.channel, {}).values(), "CAPABILITY_FORBIDDEN", "a budget proposal can only update or pause its channel")
        _require(not set(self.arguments).intersection(_IDENTIFIERS), "IDENTIFIER_IN_ARGUMENTS", "the host resolves identifiers from committed targets")
        _require(not any(isinstance(value, str) and re.match(r"^(?:act_[0-9]+|customers/|[0-9]{6,})", value) for value in self.arguments.values()),
            "IDENTIFIER_IN_ARGUMENTS", "raw provider identifiers cannot cross in proposal arguments")
        _require(self.daily_amount * self.period_days + self.rounding_residue == self.period_amount,
            "BUDGET_NOT_CONSERVED", "daily limits and unspent rounding residue must conserve the period amount")
        google = self.channel == "paid_search_google"
        pause = self.intent == "pause_campaign"
        expected_identifiers = ("customer_id", "resource_name") if google else ("ad_account_id", "campaign_id" if pause else "object_id")
        amount = self.daily_amount * Decimal(10) ** self.currency_minor_exponent
        expected_arguments = {} if pause else {"amount_micros" if google else "daily_budget_minor": int(amount)}
        _require((not google or self.currency_minor_exponent == 6) and amount == amount.to_integral_value()
            and self.arguments == expected_arguments and all(type(value) is int for value in self.arguments.values())
            and self.identifier_fields_supplied_by_platform == expected_identifiers
            and self.capability == _CHANNEL_WRITE_CAPABILITIES[self.channel]["stop" if pause else "set_budget"],
            "WRITE_UNIT_NOT_BOUND", "provider arguments must be derived from the exact daily amount")
        expected = stable_digest({"capability": self.capability, "arguments": self.arguments,
            "target_commitment": self.target_commitment, "account_commitment": self.account_commitment,
            "identifier_fields_supplied_by_platform": list(self.identifier_fields_supplied_by_platform)})
        _require(self.content_digest == expected and self.approval_unit == f"approval_budget_{self.envelope_ref}_{expected}",
            "WRITE_UNIT_NOT_BOUND", "approval must bind exact arguments, account and target")
        return self

class BudgetWritePlan(_Sealed):
    digest_field: ClassVar[str] = "write_plan_digest"
    schema_id: Literal["lightbulb.growth_budget_write_plan.v1"] = Field(default=WRITE_PLAN_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    portfolio_digest: Sha256Digest
    proposal_digest: Sha256Digest
    map_digest: Sha256Digest
    # Optional prior business review; exact provider approvals remain mandatory.
    approval_ref: OpaqueRef | None = None
    currency: CurrencyCode
    period_start: str
    period_end: str
    period_days: int = Field(ge=1, le=366, strict=True)
    units: tuple[BudgetWriteUnit, ...] = Field(min_length=1, max_length=16)
    unmapped_envelope_refs: tuple[OpaqueRef, ...] = ()
    unsupported_channels: tuple[Channel, ...] = ()
    rationale: tuple[ShortText, ...] = Field(max_length=16)
    enables_nothing: Literal[True] = True
    creates_nothing_live: Literal[True] = True
    executes_nothing: Literal[True] = True
    compiled_at: str
    evidence_expires_at: str | None = None
    write_plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("period_start", "period_end", "compiled_at", "evidence_expires_at")
    @classmethod
    def stamp(cls, value, info):
        return None if value is None else timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def ordinals(self):
        _require([unit.ordinal for unit in self.units] == list(range(1, len(self.units) + 1)), "WRITE_UNITS_INVALID", "unit ordinals must be contiguous")
        _require(len({unit.approval_unit for unit in self.units}) == len(self.units)
            and len({(unit.channel, unit.target_commitment) for unit in self.units}) == len(self.units),
            "WRITE_UNITS_INVALID", "each target and approval unit must be unique")
        return self


def _account(observation, binding, currency, compiled_at):
    provider = "google_ads" if binding.channel == "paid_search_google" else "meta_ads"
    provenance, output = _read(observation["provenance"], observation["output"], provider + ".get_account", f"lightbulb.{provider}_account.v1")
    _require(output.get("currency_code" if provider == "google_ads" else "currency") == currency,
        "ACCOUNT_CURRENCY_MISMATCH", "the observed provider account must use the portfolio currency")
    _require(output.get("customer_id_sha256" if provider == "google_ads" else "ad_account_id_sha256") == binding.account_commitment,
        "ACCOUNT_TARGET_MISMATCH", "the currency observation must belong to the target's account")
    _require(parsed(output["observed_at"]) <= parsed(provenance.completed_at) <= parsed(compiled_at),
        "ACCOUNT_FROM_FUTURE", "account currency must be observed before compilation")
    exponent = 6 if provider == "google_ads" else output.get("currency_minor_exponent")
    _require(type(exponent) is int and 0 <= exponent <= 6, "CURRENCY_EXPONENT_UNKNOWN", "minor-unit exponent must come from the governed account read")
    return exponent


def compile_budget_write_plan(plan, portfolio, proposal, object_map, *, approval_ref=None, compiled_at,
                              account_observations, allow_pause_on_floor=True, require_all_channels=False, scope=None, scope_keyring=None):
    from lightbulb.growth_execution import apply_reallocation, preview_reallocation
    plan = GrowthEngineLoopPlan.model_validate(detached(plan))
    portfolio = CampaignPortfolio.model_validate(detached(portfolio))
    mapping = EnvelopeObjectMap.model_validate(detached(object_map))
    _require(mapping.portfolio_digest == portfolio.portfolio_digest, "MAP_NOT_BOUND", "map must bind the current portfolio")
    rebuilt = envelope_object_map(portfolio, mapping.entries, declared_by_ref=mapping.declared_by_ref,
        declared_at=mapping.declared_at, bindings=mapping.bindings)
    _require(rebuilt == mapping, "MAP_NOT_BOUND", "map must replay every observed target")
    _require(parsed(mapping.declared_at) <= parsed(compiled_at), "MAP_FROM_FUTURE", "compile after the target map was declared")
    next_portfolio = (preview_reallocation(plan, portfolio, proposal, scope=scope, scope_keyring=scope_keyring) if approval_ref is None else apply_reallocation(plan, portfolio, proposal, approval_ref=approval_ref, scope=scope, scope_keyring=scope_keyring))
    proposed = detached(proposal)
    by_ref = {entry.envelope_ref: entry for entry in mapping.entries}
    bindings = {(binding.channel, binding.object_commitment): binding for binding in mapping.bindings}
    old = {envelope.envelope_ref: envelope.budget for envelope in portfolio.envelopes}
    duration = parsed(portfolio.period_end) - parsed(portfolio.period_start)
    days = duration.days
    _require(1 <= days <= 366 and duration.total_seconds() == days * 86400, "PERIOD_DAYS_INVALID", "daily limits require a whole-day period")
    units, unmapped, unsupported, rationale = [], [], set(), []
    source_times = []
    for envelope in next_portfolio.envelopes:
        if envelope.budget == old[envelope.envelope_ref]:
            continue
        if envelope.channel not in _CHANNEL_WRITE_CAPABILITIES:
            _require(not require_all_channels, "CHANNEL_WRITE_UNSUPPORTED", "no governed budget Tool exists for a changed channel")
            unsupported.add(envelope.channel); continue
        entry = by_ref.get(envelope.envelope_ref)
        if entry is None:
            unmapped.append(envelope.envelope_ref); continue
        binding = bindings[(entry.channel, entry.object_commitment)]
        account = account_observations.get(envelope.channel)
        _require(account is not None, "ACCOUNT_OBSERVATION_REQUIRED", "read the exact account currency before compiling amounts")
        exponent = _account(account, binding, plan.blueprint.currency, compiled_at)
        source_times.extend((parsed(binding.observed_at),parsed(detached(account)["provenance"]["completed_at"])))
        _require(parsed(binding.observed_at) <= parsed(compiled_at), "OBJECT_FROM_FUTURE", "compile after observing the target")
        daily = (envelope.budget / days).quantize(MONEY_QUANTUM, rounding=ROUND_DOWN)
        residue = envelope.budget - daily * days
        amount = daily * (Decimal(10) ** exponent)
        _require(amount == amount.to_integral_value(), "MINOR_UNITS_NOT_INTEGER", "daily amount cannot be represented in exact provider units")
        google = envelope.channel == "paid_search_google"
        floor, ceiling = (1_000_000, 5_000_000_000) if google else (100, 500_000)
        _require(amount <= ceiling, "BUDGET_OUT_OF_PROVIDER_RANGE", "daily amount exceeds the connector limit")
        pause = amount < floor
        _require(not pause or allow_pause_on_floor, "BUDGET_BELOW_PROVIDER_FLOOR", "daily amount requires pausing the campaign")
        target = binding.resource_commitment if pause else binding.budget_commitment
        _require(target is not None, "TARGET_COMMITMENT_MISSING", "observe the exact campaign or budget resource before proposing a mutation")
        if google and not pause:
            _require(binding.budget_shared is False and sum(other.budget_commitment == target for other in object_bindings(binding.provenance, binding.output, channel=binding.channel)) == 1,
                "SHARED_BUDGET_UNSUPPORTED", "changing a shared budget would affect other campaign envelopes")
        capability = _CHANNEL_WRITE_CAPABILITIES[envelope.channel]["stop" if pause else "set_budget"]
        # Argument names mirror the actual Connector Runtime. Adapters own
        # status/update masks; they reject caller-supplied masks and statuses.
        arguments = {} if pause else {"amount_micros" if google else "daily_budget_minor": int(amount)}
        identifiers = ("customer_id", "resource_name") if google else ("ad_account_id", "campaign_id" if pause else "object_id")
        content = stable_digest({"capability": capability, "arguments": arguments, "target_commitment": target,
            "account_commitment": binding.account_commitment, "identifier_fields_supplied_by_platform": list(identifiers)})
        ordinal = len(units) + 1
        units.append(BudgetWriteUnit(ordinal=ordinal, unit_ref=f"realloc-{proposed['proposal_digest'][:12]}-{ordinal:02d}",
            envelope_ref=envelope.envelope_ref, channel=envelope.channel,
            intent="pause_campaign" if pause else "increase_budget" if envelope.budget > old[envelope.envelope_ref] else "decrease_budget",
            capability=capability, object_commitment=binding.object_commitment, target_commitment=target,
            account_commitment=binding.account_commitment, arguments=arguments, identifier_fields_supplied_by_platform=identifiers,
            period_days=days, currency_minor_exponent=exponent, period_amount=envelope.budget, daily_amount=daily, rounding_residue=residue,
            content_digest=content, approval_unit=f"approval_budget_{envelope.envelope_ref}_{content}"))
        if pause:
            rationale.append(f"{envelope.envelope_ref}: pause because the daily amount is below the provider floor")
    _require(bool(units), "NO_MAPPED_ENVELOPES", "no changed envelope has an executable mapped target")
    from datetime import timedelta
    expires = min(source_times) + timedelta(hours=24)
    _require(parsed(compiled_at) <= expires,"BUDGET_TARGET_READ_STALE","refresh provider target and currency observations before compiling approval candidates")
    return seal(BudgetWritePlan, {"plan_digest": plan.plan_digest, "portfolio_digest": portfolio.portfolio_digest,
        "proposal_digest": proposed["proposal_digest"], "map_digest": mapping.map_digest, "approval_ref": approval_ref,
        "currency": plan.blueprint.currency, "period_start": portfolio.period_start, "period_end": portfolio.period_end,
        "period_days": days, "units": units, "unmapped_envelope_refs": unmapped, "unsupported_channels": sorted(unsupported),
        "rationale": [*rationale, f"{len(units)} exact budget proposals; provider execution remains governed"],
        "compiled_at": compiled_at,"evidence_expires_at":expires.isoformat().replace("+00:00","Z")}, "write_plan_digest")

def write_plan_requests(write_plan, *, scope, connector_account_refs):
    """Unresolved intents for the host's governed request compiler.

    The host must resolve the exact committed account and target, inject only
    the named identifier fields, then obtain approval for that resolved request.
    These documents are not executable ConnectorExecutionRequests.
    """
    plan = BudgetWritePlan.model_validate(detached(write_plan))
    return tuple({"schema": "lightbulb.growth_budget_write_intent.v1", "scope": detached(scope),
        "connector_account_ref": connector_account_refs[unit.channel], "unit": unit.to_dict(),
        "write_plan_digest": plan.write_plan_digest, "approval_ref": plan.approval_ref,
        "requires_host_resolution": True, "provider_effect_executed": False} for unit in plan.units)


def _resolved_request(plan, unit, request):
    from hashlib import sha256
    from lightbulb.connector_execution import ConnectorExecutionRequest, ConnectorEffect
    request = ConnectorExecutionRequest.model_validate(detached(request))
    _require(request.tool == unit.capability and request.effect == ConnectorEffect.WRITE
        and request.approval_required and not request.preview_only,
        "WRITE_REQUEST_MISMATCH", "retain the exact approval-controlled budget request")
    _require(request.scope.project_id is not None and bool(request.connector_account_ref)
        and request.idempotency_key == f"{plan.write_plan_digest}:{unit.unit_ref}",
        "WRITE_REQUEST_SCOPE_MISSING", "the request must bind a project, connector account and plan unit identity")
    fields = unit.identifier_fields_supplied_by_platform
    _require(set(request.arguments) == set(unit.arguments) | set(fields),
        "WRITE_REQUEST_ARGUMENTS_MISMATCH", "only reviewed arguments and named provider identifiers may be supplied")
    _require(stable_digest({key: request.arguments[key] for key in unit.arguments}) == stable_digest(unit.arguments),
        "WRITE_REQUEST_ARGUMENTS_MISMATCH", "resolved requests cannot change reviewed daily limits")
    for field, commitment in zip(fields, (unit.account_commitment, unit.target_commitment)):
        value = request.arguments[field]
        _require(isinstance(value, str) and 0 < len(value) <= 256 and value == value.strip()
            and sha256(value.encode("utf-8")).hexdigest() == commitment,
            "WRITE_IDENTIFIER_MISMATCH", "provider identifiers must reproduce the observed account and target commitments")
    return request


def resolve_write_plan_requests(write_plan, *, scope, connector_account_refs, identifiers_by_unit, approvals_by_unit=None):
    """Compile canonical requests from host-held identifiers; no provider call is made.

    Raw identifiers stay in the host's request journal. Portable SDK proofs keep
    only commitments, and callers supply the journaled requests again on replay.
    The plan's business approval is not a provider execution approval. Initial
    requests omit approval_ref; pass the host-issued approval for each unit on
    resumption. Approval references do not change request custody fingerprints.
    """
    from lightbulb.connector_execution import ConnectorExecutionRequest
    plan = BudgetWritePlan.model_validate(detached(write_plan))
    _require(set(identifiers_by_unit) == {unit.unit_ref for unit in plan.units},
        "WRITE_IDENTIFIERS_INCOMPLETE", "resolve every plan unit exactly once")
    approvals_by_unit = dict(approvals_by_unit or {})
    _require(set(approvals_by_unit) <= {unit.unit_ref for unit in plan.units},
        "UNIT_UNKNOWN", "provider approvals must name units in this plan")
    result = []
    for unit in plan.units:
        identifiers = identifiers_by_unit[unit.unit_ref]
        _require(isinstance(identifiers, Mapping)
            and set(identifiers) == set(unit.identifier_fields_supplied_by_platform),
            "WRITE_REQUEST_ARGUMENTS_MISMATCH", "the host supplies only the unit's named identifier fields")
        request = ConnectorExecutionRequest(tool=unit.capability,
            arguments={**unit.arguments, **identifiers}, scope=scope,
            connector_account_ref=connector_account_refs.get(unit.channel), effect="write",
            approval_required=True, approval_ref=approvals_by_unit.get(unit.unit_ref),
            idempotency_key=f"{plan.write_plan_digest}:{unit.unit_ref}")
        result.append(_resolved_request(plan, unit, request))
    return tuple(result)

class BudgetWriteProof(_Sealed):
    digest_field: ClassVar[str] = "proof_digest"
    schema_id: Literal["lightbulb.growth_budget_write_proof.v1"] = Field(default=WRITE_PROOF_SCHEMA, alias="schema")
    write_plan_digest: Sha256Digest
    unit_ref: OpaqueRef
    capability: ShortText
    approval_unit: OpaqueRef
    journal_ref: OpaqueRef
    approval_ref: OpaqueRef
    completed_at: str
    source_execution: ExecutionReceipt
    source_output: dict[str, Any]
    applied: Literal[True] = True
    proof_digest: Sha256Digest = GENESIS_DIGEST


def write_plan_proof(write_plan, unit_ref, execution, *, output, request):
    plan = BudgetWritePlan.model_validate(detached(write_plan))
    unit = next((unit for unit in plan.units if unit.unit_ref == unit_ref), None)
    _require(unit is not None, "UNIT_UNKNOWN", "the write plan must contain the named unit")
    request = _resolved_request(plan, unit, request)
    execution = ExecutionReceipt.model_validate(detached(execution))
    _require(execution.request_digest == request.custody_fingerprint()
        and execution.project_id == str(request.scope.project_id)
        and execution.connector_account_ref == request.connector_account_ref,
        "WRITE_EXECUTION_REQUEST_MISMATCH", "execution must commit the exact scoped and resolved request")
    raw = dict(detached(output))
    _require(execution.tool == unit.capability and execution.effect == "write"
        and request.approval_ref is not None and execution.approval_ref == request.approval_ref,
        "WRITE_PROOF_MISMATCH", "the execution must name this exact approved provider capability")
    _require(execution.output_digest == stable_digest(raw) and parsed(execution.completed_at) >= parsed(plan.compiled_at),
        "WRITE_OUTPUT_MISMATCH", "the complete write output must be bound by the execution after compilation")
    google = unit.channel == "paid_search_google"
    pause = unit.intent == "pause_campaign"
    _require(raw.get("schema") == ("lightbulb.google_ads_write_result.v1" if google else "lightbulb.meta_ads_write_result.v1")
        and raw.get("status") == ("paused" if pause else "updated"),
        "WRITE_NOT_APPLIED", "the provider must acknowledge the intended update or pause")
    _require(raw.get("resource_name_sha256" if google else "object_id_sha256") == unit.target_commitment,
        "WRITE_TARGET_MISMATCH", "the mutation must affect the exact target committed by this unit")
    if google:
        _require(type(raw.get("mutated_count")) is int and raw["mutated_count"] == 1,
            "WRITE_NOT_APPLIED", "validation-only or partial Google responses do not prove one applied mutation")
    amount_key = "amount_micros" if google else "daily_budget_minor"
    _require((pause and raw.get(amount_key) is None) or (not pause and type(raw.get(amount_key)) is int and raw[amount_key] == unit.arguments[amount_key]),
        "WRITE_AMOUNT_MISMATCH", "the applied amount must equal this exact unit's daily limit")
    return seal(BudgetWriteProof, {"write_plan_digest": plan.write_plan_digest, "unit_ref": unit.unit_ref,
        "capability": unit.capability, "approval_unit": unit.approval_unit, "journal_ref": execution.journal_ref,
        "approval_ref": execution.approval_ref, "completed_at": execution.completed_at,
        "source_execution": execution, "source_output": raw}, "proof_digest")


def applied_write_plan(write_plan, proofs, *, requests_by_unit):
    plan = BudgetWritePlan.model_validate(detached(write_plan))
    applied, journals, approvals = set(), set(), set()
    for value in proofs:
        proof = BudgetWriteProof.model_validate(detached(value))
        _require(proof.unit_ref in requests_by_unit, "WRITE_REQUEST_MISSING", "replay requires the host-journaled request for every proof")
        expected = write_plan_proof(plan, proof.unit_ref, proof.source_execution,
            output=proof.source_output, request=requests_by_unit[proof.unit_ref])
        _require(expected == proof, "WRITE_PROOF_MISMATCH", "the proof must replay against this complete write plan")
        _require(proof.unit_ref not in applied and proof.journal_ref not in journals
            and proof.approval_ref not in approvals, "WRITE_PROOF_DUPLICATE", "a provider mutation or request approval cannot prove two write units")
        applied.add(proof.unit_ref); journals.add(proof.journal_ref); approvals.add(proof.approval_ref)
    pending = tuple(unit.unit_ref for unit in plan.units if unit.unit_ref not in applied)
    return {"units": len(plan.units), "applied": len(applied), "pending": len(pending),
        "unapplied_unit_refs": pending, "all_applied": not pending,
        "verdict": "fully_applied" if not pending else "partially_applied" if applied else "unapplied"}


GROWTH_REALLOCATION_MANIFEST = {"schema": "lightbulb.company_engine_manifest.v1", "engine": "growth_reallocation",
    "golden_loop": "growth.store_truth_to_attributed_revenue@0.1.0", "stages": ["map_observed_targets", "compile_budget_write_plan"],
    "required_connectors": ["google_ads", "meta_ads"], "hard_rules": ["daily provider units conserve the period budget with explicit rounding residue",
    "only exact observed account and target commitments may enter a write proposal", "budget proposals update or pause; they never activate campaigns"]}
__all__ = ["GrowthReallocationError", "ProviderObjectBinding", "EnvelopeObjectEntry", "EnvelopeObjectMap", "BudgetWriteUnit", "BudgetWritePlan",
    "object_bindings", "envelope_object_map", "compile_budget_write_plan", "BudgetWriteProof", "write_plan_requests", "resolve_write_plan_requests", "write_plan_proof", "applied_write_plan", "GROWTH_REALLOCATION_MANIFEST", "FORBIDDEN_WRITE_CAPABILITIES", "WRITE_UNSUPPORTED_CHANNELS"]

# The statistical engine owns HMAC verification. A field claiming to be sealed
# is never a substitute for executing that verifier with the host keyring.
class IncrementalReadout(StrictModel):
    channel: Channel
    source_readout: dict[str, Any]
    source_design: dict[str, Any]


def incremental_readout(readout, *, design, channel, scope, scope_keyring):
    from lightbulb.growth_experiments import verify_growth_experiment_readout, verify_growth_experiment_design
    _require(channel in CHANNELS, "CHANNEL_UNKNOWN", "use a declared growth channel")
    result = verify_growth_experiment_readout(readout, scope=scope, scope_keyring=scope_keyring)
    registered = verify_growth_experiment_design(design, scope=scope, scope_keyring=scope_keyring)
    _require(result.design_digest == registered.design_digest, "READOUT_DESIGN_MISMATCH", "readout must bind the preregistration")
    _require(result.causal and not result.underpowered and result.sample_ratio_check.passed,
             "READOUT_NOT_CAUSAL", "only powered, correctly assigned experiments price incremental returns")
    _require(result.metric_name == "revenue_per_session" and result.metric_kind == "continuous",
             "READOUT_METRIC_UNSUPPORTED", "only revenue per session can be converted to incremental money")
    _require(result.verdict in {"win", "loss", "inconclusive"} and not result.guardrail_breaches,
             "READOUT_VERDICT_UNUSABLE", "invalid assignments and breached guardrails cannot allocate budget")
    _require(all(value is not None for value in (result.effect_estimate, result.ci_low, result.ci_high, result.p_value))
             and result.test_used != "none" and all(arm.sample_count for arm in result.arms),
             "READOUT_STATISTICS_MISSING", "retain both sampled arms and their confidence interval")
    _require(result.ci_low <= result.effect_estimate <= result.ci_high,
             "READOUT_INTERVAL_INVALID", "the interval must contain the effect estimate")
    return IncrementalReadout(channel=channel, source_readout=result.to_dict(), source_design=registered.to_dict())


MARGINAL_RETURN_SCHEMA = "lightbulb.growth_marginal_return.v1"
_RETURN_DOMAIN = "lightbulb.growth_marginal_return.authority.v1"

class MarginalReturn(_Sealed):
    schema_id: Literal["lightbulb.growth_marginal_return.v1"] = Field(default=MARGINAL_RETURN_SCHEMA, alias="schema")
    digest_field: ClassVar[str] = "return_digest"
    channel: Channel
    readout: IncrementalReadout
    spend_statement: dict[str, Any]
    window_start: str
    window_end: str
    currency: CurrencyCode
    spend: Decimal = Field(gt=0)
    exposed_units: int = Field(gt=0, strict=True)
    incremental_revenue: Decimal
    incremental_revenue_low: Decimal
    incremental_revenue_high: Decimal
    marginal_roas: Decimal
    marginal_roas_low: Decimal
    marginal_roas_high: Decimal
    analysis_as_of: str
    receipt_key_id: ShortText
    exact_scope_digest: Sha256Digest
    # The host attests that this experiment's monetary measurement uses the
    # statement currency, and binds the opaque engine scope to its actor scope.
    measurement_currency_attested: Literal[True] = True
    return_hmac: Sha256Digest
    return_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("spend", "incremental_revenue", "incremental_revenue_low", "incremental_revenue_high",
                     "marginal_roas", "marginal_roas_low", "marginal_roas_high", mode="before")
    @classmethod
    def decimals(cls, value):
        result = Decimal(str(value))
        if not result.is_finite():
            raise ValueError("incremental measurements must be finite")
        return result


def _return_payload(item):
    return {k: v for k, v in detached(item).items() if k not in {"return_digest", "return_hmac"}}


def marginal_return(readout, spend, *, scope, scope_keyring, measurement_currency):
    from lightbulb.channel_spend_statements import verify_statement
    from lightbulb.dynamic_workflows import DynamicWorkflowScope
    parsed_readout = IncrementalReadout.model_validate(detached(readout))
    verified = incremental_readout(parsed_readout.source_readout, design=parsed_readout.source_design,
        channel=parsed_readout.channel, scope=scope, scope_keyring=scope_keyring)
    statement = verify_statement(spend)
    _require(statement.basis == "governed_read", "SPEND_NOT_GOVERNED", "causal pricing requires a complete governed spend read")
    _require(statement.channel == verified.channel, "CHANNEL_MISMATCH", "experiment and spend must name the same channel")
    _require(statement.currency == measurement_currency, "MEASUREMENT_CURRENCY_MISMATCH", "the host must bind the experiment's measured money currency")
    design = verified.source_design; raw = verified.source_readout
    _require(parsed(statement.window_start) == parsed(design["exposure_start"])
             and parsed(statement.window_end) == parsed(design["readout_horizon"]),
             "SPEND_WINDOW_MISALIGNED", "the spend denominator must exactly cover the experiment exposure window")
    _require(parsed(raw["analysis_as_of"]) >= parsed(statement.window_end), "READOUT_PRECEDES_SPEND", "readout must follow the complete spend window")
    amount = Decimal(statement.cost_micros) / Decimal(1000000)
    _require(amount > 0, "MARGINAL_ROAS_UNDEFINED", "zero spend cannot establish a marginal return")
    exposed = next(arm["sample_count"] for arm in raw["arms"] if not arm["is_control"])
    money = [(Decimal(raw[key]) * exposed).quantize(MONEY_QUANTUM) for key in ("effect_estimate", "ci_low", "ci_high")]
    key_id = scope_keyring.active_key_id
    payload = {"schema": MARGINAL_RETURN_SCHEMA, "channel": verified.channel, "readout": verified.to_dict(),
        "spend_statement": statement.to_dict(), "window_start": statement.window_start, "window_end": statement.window_end,
        "currency": statement.currency, "spend": str(amount), "exposed_units": exposed,
        "analysis_as_of": raw["analysis_as_of"], "receipt_key_id": key_id,
        "exact_scope_digest": scope_keyring.exact_scope_digest(key_id=key_id, scope=DynamicWorkflowScope.model_validate(scope)),
        "measurement_currency_attested": True}
    for name, value in zip(("incremental_revenue", "incremental_revenue_low", "incremental_revenue_high"), money):
        payload[name] = str(value)
    for name, value in zip(("marginal_roas", "marginal_roas_low", "marginal_roas_high"), money):
        payload[name] = str((value / amount).quantize(Decimal("0.0001")))
    # Normalize through the actual model before signing, so decimal JSON shape
    # is identical at creation and replay.
    draft = seal(MarginalReturn, {**payload, "return_hmac": GENESIS_DIGEST}, "return_digest")
    signature = scope_keyring.sign(key_id, _RETURN_DOMAIN, _return_payload(draft)).hex()
    return seal(MarginalReturn, {**draft.to_dict(), "return_hmac": signature}, "return_digest")


def verify_marginal_return(value, *, scope, scope_keyring):
    import hmac
    from lightbulb.dynamic_workflows import DynamicWorkflowScope
    result = MarginalReturn.model_validate(detached(value))
    expected_scope = scope_keyring.exact_scope_digest(key_id=result.receipt_key_id, scope=DynamicWorkflowScope.model_validate(scope))
    signature = scope_keyring.sign(result.receipt_key_id, _RETURN_DOMAIN, _return_payload(result)).hex()
    _require(hmac.compare_digest(expected_scope, result.exact_scope_digest)
             and hmac.compare_digest(signature, result.return_hmac), "RETURN_ATTESTATION_INVALID", "return must bind the exact host scope and retained evidence")
    rebuilt = marginal_return(result.readout, result.spend_statement, scope=scope, scope_keyring=scope_keyring,
        measurement_currency=result.currency)
    # Key rotation may change the attestation, but never the economic facts.
    ignored = {"receipt_key_id", "exact_scope_digest"}
    _require({k:v for k,v in _return_payload(rebuilt).items() if k not in ignored}
             == {k:v for k,v in _return_payload(result).items() if k not in ignored},
             "RETURN_SOURCE_MISMATCH", "incremental money must reproduce canonical statistics and spend")
    return result


INCREMENTAL_PROPOSAL_SCHEMA = "lightbulb.growth_incremental_reallocation_proposal.v1"
_PROPOSAL_DOMAIN = "lightbulb.growth_incremental_reallocation.authority.v1"

class ChannelIncrementalRow(StrictModel):
    channel: Channel
    allocated_budget: Decimal
    spend: Decimal
    observed_attributed_revenue: Decimal
    observed_conversions: int = Field(ge=0, strict=True)
    observed_verdict: Literal["above_target", "below_target", "insufficient_evidence", "no_target"]
    incremental_basis: Literal["holdout_readout", "unmeasured"]
    marginal_roas_low: Decimal | None = None
    marginal_roas_high: Decimal | None = None
    target_roas: Decimal
    eligibility: Literal["may_receive", "may_lose", "hold", "frozen_holdout_active"]
    cap_headroom: Decimal = Field(ge=0)

    @field_validator("allocated_budget", "spend", "observed_attributed_revenue", "marginal_roas_low",
                     "marginal_roas_high", "target_roas", "cap_headroom", mode="before")
    @classmethod
    def decimals(cls, value):
        if value is None:
            return None
        result = Decimal(str(value))
        if not result.is_finite():
            raise ValueError("channel measurements must be finite")
        return result


class EnvelopeBudgetShift(StrictModel):
    from_envelope_ref: OpaqueRef
    to_envelope_ref: OpaqueRef
    from_channel: Channel
    to_channel: Channel
    amount: Decimal = Field(gt=0)
    from_basis: Literal["holdout_readout", "unmeasured"]
    to_basis: Literal["holdout_readout"] = "holdout_readout"
    reason: ShortText

    @field_validator("amount", mode="before")
    @classmethod
    def money(cls, value):
        return decimal_value(value, field_name="amount")


class IncrementalReallocationProposal(_Sealed):
    schema_id: Literal["lightbulb.growth_incremental_reallocation_proposal.v1"] = Field(default=INCREMENTAL_PROPOSAL_SCHEMA, alias="schema")
    digest_field: ClassVar[str] = "proposal_digest"
    plan_digest: Sha256Digest
    portfolio_digest: Sha256Digest
    performance: tuple[ChannelIncrementalRow, ...] = Field(min_length=1, max_length=8)
    shifts: tuple[EnvelopeBudgetShift, ...] = Field(default=(), max_length=16)
    returns: tuple[MarginalReturn, ...] = Field(default=(), max_length=8)
    designs: tuple[dict[str, Any], ...] = Field(default=(), max_length=32)
    allocated_budget: Decimal
    unallocated_budget: Decimal
    max_shift_allowed: Decimal
    total_shifted: Decimal
    net_change: Decimal
    max_shift_percent: Decimal
    frozen_channels: tuple[Channel, ...] = ()
    requires_human_approval: Literal[True] = True
    executes_nothing: Literal[True] = True
    rationale: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    proposed_at: str
    receipt_key_id: ShortText
    exact_scope_digest: Sha256Digest
    proposal_hmac: Sha256Digest
    proposal_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("allocated_budget", "unallocated_budget", "max_shift_allowed", "total_shifted", "net_change", "max_shift_percent", mode="before")
    @classmethod
    def money(cls, value):
        return decimal_value(value, field_name="proposal amount")

    @model_validator(mode="after")
    def conserves(self):
        if self.total_shifted != sum((item.amount for item in self.shifts), Decimal(0)) or self.total_shifted > self.max_shift_allowed or self.net_change != 0:
            raise ValueError("shifts must conserve allocated money inside the ceiling")
        pairs = {(s.from_envelope_ref, s.to_envelope_ref) for s in self.shifts}
        if len(pairs) != len(self.shifts) or {s.from_envelope_ref for s in self.shifts} & {s.to_envelope_ref for s in self.shifts}:
            raise ValueError("shift pairs must be unique and envelopes cannot both give and receive")
        if any(s.from_channel == s.to_channel or s.from_envelope_ref == s.to_envelope_ref for s in self.shifts):
            raise ValueError("shifts must move between different channel envelopes")
        return self


def _proposal_payload(item):
    return {k:v for k,v in detached(item).items() if k not in {"proposal_hmac", "proposal_digest"}}


def propose_incremental_reallocation(plan, portfolio, campaigns, *, returns, scope, scope_keyring,
        engine_scope, company_ref, designs=(), proposed_at, max_shift_percent=None, max_evidence_age_days=45):
    from datetime import timedelta
    from lightbulb.company_engine_core import EngineScope, same_scope, pct, percent_value
    from lightbulb.growth_engine_loop import CAMPAIGN_LIFECYCLE, _channel_rows
    from lightbulb.growth_experiments import verify_growth_experiment_design
    from lightbulb.dynamic_workflows import DynamicWorkflowScope
    from lightbulb.channel_spend_statements import verify_statement
    plan = GrowthEngineLoopPlan.model_validate(detached(plan))
    portfolio = CampaignPortfolio.model_validate(detached(portfolio))
    engine_scope = EngineScope.model_validate(detached(engine_scope))
    _require(portfolio.plan_digest == plan.plan_digest, "PORTFOLIO_NOT_BOUND", "use the exact portfolio plan")
    _require(type(max_evidence_age_days) is int and 1 <= max_evidence_age_days <= 365,
             "EVIDENCE_AGE_INVALID", "evidence age must be a bounded number of days")
    at = parsed(timestamp(proposed_at, field_name="proposed_at")); bp = plan.blueprint
    bound = [CAMPAIGN_LIFECYCLE.bind(plan, item)[1] for item in campaigns]
    _require(all(item.ledger.portfolio_digest == portfolio.portfolio_digest for item in bound),
             "CAMPAIGN_NOT_IN_PORTFOLIO", "all observations must belong to this portfolio")
    _require(len({item.scope.entity_ref for item in bound}) == len(bound), "CAMPAIGN_DUPLICATED", "a campaign may be counted only once")
    for item in bound:
        _require(same_scope(item.scope, engine_scope), "SOURCE_SCOPE_MISMATCH", "campaign belongs to another company or project")
        _require(all(parsed(t.command.occurred_at) <= at for t in item.transition_history),
                 "CAMPAIGN_FROM_FUTURE", "campaign observations must precede the proposal")
    percent = bp.max_shift_percent_per_cycle if max_shift_percent is None else percent_value(max_shift_percent, field_name="max_shift_percent")
    _require(percent <= bp.max_shift_percent_per_cycle, "SHIFT_LIMIT_EXCEEDED", "operator limit cannot exceed blueprint policy")
    allocated = portfolio.total_budget - portfolio.unallocated
    _require(allocated == sum((e.budget for e in portfolio.envelopes), Decimal(0)), "PORTFOLIO_ALLOCATION_INCONSISTENT", "envelope sums must conserve money")
    maximum = pct(allocated, percent)
    policies = {p.channel:p for p in bp.channels if p.enabled}
    measured = {}
    for value in returns:
        ret = verify_marginal_return(value, scope=scope, scope_keyring=scope_keyring)
        _require(ret.channel in policies, "CHANNEL_NOT_ENABLED", "return channel is not enabled")
        _require(ret.channel not in measured, "DUPLICATE_MARGINAL_RETURN", "one current return per channel")
        statement = verify_statement(ret.spend_statement)
        _require(statement.company_ref == company_ref and same_scope(statement.scope, engine_scope),
                 "SOURCE_SCOPE_MISMATCH", "return belongs to another company or project")
        _require(ret.currency == bp.currency == engine_scope.currency, "RETURN_CURRENCY_MISMATCH", "returns must use the portfolio currency")
        _require(parsed(ret.analysis_as_of) <= at and parsed(ret.window_end) <= at <= parsed(ret.window_end) + timedelta(days=max_evidence_age_days),
                 "MARGINAL_RETURN_STALE", "returns must be completed, not future-dated, and fresh")
        measured[ret.channel] = ret
    frozen = set(); retained_designs = []
    for row in designs:
        _require(isinstance(row, Mapping) and row.get("channel") in policies and "design" in row,
                 "DESIGN_CHANNEL_MISSING", "provide an enabled channel and its preregistration")
        design = verify_growth_experiment_design(row["design"], scope=scope, scope_keyring=scope_keyring)
        _require(parsed(design.designed_at) <= at, "DESIGN_FROM_FUTURE", "a preregistration cannot be from the future")
        retained_designs.append({"channel":row["channel"], "design":design.to_dict()})
        if parsed(design.exposure_start) <= at < parsed(design.readout_horizon):
            frozen.add(row["channel"])
    _require(not frozen.intersection(measured), "HOLDOUT_ACTIVE", "changing spend during an active holdout invalidates its readout")
    observed = {r["channel"]:r for r in _channel_rows(bp, bound)}
    days = (parsed(portfolio.period_end) - parsed(portfolio.period_start)).days
    proration = (Decimal(days) / Decimal(30)).quantize(Decimal("0.0001"))
    performance = []
    for channel, policy in sorted(policies.items()):
        row = observed[channel]; ret = measured.get(channel)
        budget = sum((e.budget for e in portfolio.envelopes if e.channel == channel), Decimal(0))
        target = policy.target_roas if policy.target_roas is not None else bp.target_blended_roas
        eligibility = ("frozen_holdout_active" if channel in frozen else
            "may_receive" if ret is not None and ret.marginal_roas_low >= target else
            "may_lose" if ret is not None and ret.marginal_roas_high < target else
            "may_lose" if ret is None and row["verdict"] == "below_target" else "hold")
        performance.append(ChannelIncrementalRow(channel=channel, allocated_budget=budget, spend=Decimal(row["spend"]),
            observed_attributed_revenue=Decimal(row["attributed_revenue"]), observed_conversions=row["conversions"], observed_verdict=row["verdict"],
            incremental_basis="holdout_readout" if ret else "unmeasured", marginal_roas_low=ret.marginal_roas_low if ret else None,
            marginal_roas_high=ret.marginal_roas_high if ret else None, target_roas=target, eligibility=eligibility,
            cap_headroom=max(Decimal(0), (policy.monthly_budget_cap * proration).quantize(MONEY_QUANTUM) - budget)))
    receivers = sorted((r for r in performance if r.eligibility == "may_receive" and r.cap_headroom > 0), key=lambda r:(-r.marginal_roas_low, r.channel))
    losers = sorted((r for r in performance if r.eligibility == "may_lose" and r.allocated_budget > 0), key=lambda r:(r.incremental_basis != "holdout_readout", -r.allocated_budget, r.channel))
    remaining = maximum; shifts = []; budgets = {e.envelope_ref:e.budget for e in portfolio.envelopes}
    headroom = {r.channel:r.cap_headroom for r in receivers}
    for loser in losers:
        capacity = pct(loser.allocated_budget, percent)
        giving = sorted((e for e in portfolio.envelopes if e.channel == loser.channel), key=lambda e:(-e.budget, e.envelope_ref))
        for receiver in receivers:
            targets = sorted((e for e in portfolio.envelopes if e.channel == receiver.channel), key=lambda e:(-e.budget, e.envelope_ref))
            if not targets:
                continue
            target = targets[0]
            for source in giving:
                amount = min(remaining, capacity, budgets[source.envelope_ref], headroom[receiver.channel]).quantize(MONEY_QUANTUM)
                if amount <= 0 or len(shifts) >= 16:
                    continue
                shifts.append(EnvelopeBudgetShift(from_envelope_ref=source.envelope_ref, to_envelope_ref=target.envelope_ref,
                    from_channel=loser.channel, to_channel=receiver.channel, amount=amount, from_basis=loser.incremental_basis,
                    reason="Receiving channel has verified incremental return above its target"))
                remaining -= amount; capacity -= amount; budgets[source.envelope_ref] -= amount; headroom[receiver.channel] -= amount
    rationale = [f"{len(shifts)} shifts inside the {percent}% ceiling on {allocated} allocated"]
    if not receivers:
        rationale.append("No channel has sufficient causal evidence to receive budget")
    rationale.extend(f"{c} is frozen during its active holdout" for c in sorted(frozen))
    key_id = scope_keyring.active_key_id
    payload = {"plan_digest":plan.plan_digest, "portfolio_digest":portfolio.portfolio_digest,
        "performance":[r.to_dict() for r in performance], "shifts":[s.to_dict() for s in shifts],
        "returns":[measured[c].to_dict() for c in sorted(measured)], "designs":retained_designs,
        "allocated_budget":allocated, "unallocated_budget":portfolio.unallocated, "max_shift_allowed":maximum,
        "total_shifted":maximum-remaining, "net_change":Decimal(0), "max_shift_percent":percent,
        "frozen_channels":sorted(frozen), "rationale":rationale, "proposed_at":timestamp(proposed_at,field_name="proposed_at"),
        "receipt_key_id":key_id, "exact_scope_digest":scope_keyring.exact_scope_digest(key_id=key_id,scope=DynamicWorkflowScope.model_validate(scope)),
        "proposal_hmac":GENESIS_DIGEST}
    draft = seal(IncrementalReallocationProposal, payload, "proposal_digest")
    return seal(IncrementalReallocationProposal, {**draft.to_dict(), "proposal_hmac":scope_keyring.sign(key_id,_PROPOSAL_DOMAIN,_proposal_payload(draft)).hex()}, "proposal_digest")


def verify_incremental_reallocation(value, *, scope, scope_keyring):
    import hmac
    from lightbulb.dynamic_workflows import DynamicWorkflowScope
    result = IncrementalReallocationProposal.model_validate(detached(value))
    _require(scope is not None and scope_keyring is not None, "PROPOSAL_AUTHORITY_REQUIRED", "the host must verify incremental proposal authority")
    expected = scope_keyring.exact_scope_digest(key_id=result.receipt_key_id, scope=DynamicWorkflowScope.model_validate(scope))
    signature = scope_keyring.sign(result.receipt_key_id, _PROPOSAL_DOMAIN, _proposal_payload(result)).hex()
    _require(hmac.compare_digest(expected,result.exact_scope_digest) and hmac.compare_digest(signature,result.proposal_hmac),
             "PROPOSAL_ATTESTATION_INVALID", "proposal must bind the exact scope and reviewed economic inputs")
    for ret in result.returns:
        verify_marginal_return(ret, scope=scope, scope_keyring=scope_keyring)
    return result


__all__ += [
    "IncrementalReadout", "MarginalReturn", "ChannelIncrementalRow", "EnvelopeBudgetShift",
    "IncrementalReallocationProposal", "incremental_readout", "marginal_return", "verify_marginal_return",
    "propose_incremental_reallocation", "verify_incremental_reallocation", "MARGINAL_RETURN_SCHEMA",
    "INCREMENTAL_PROPOSAL_SCHEMA",
]
GROWTH_REALLOCATION_MANIFEST["stages"] = ["verify_incremental_return", "freeze_active_holdouts",
    "propose_neutral_envelope_shifts", "map_observed_targets", "compile_budget_write_plan", "verify_applied_units"]
