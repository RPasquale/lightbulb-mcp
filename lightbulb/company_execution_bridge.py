"""Execution bridge: close the loop between the company engines and the platform.

The engines (growth, pipeline, SaaS operating, company operating system)
advance on typed receipts.  Three things had to be hand-typed until now:

1. **Execution receipts** — what the Connector Runtime returns after Spring
   authorized and performed an effect (a launched campaign, a sent touch, a
   canary deployment).  :class:`ExecutionReceipt` accepts only a ``COMPLETED``
   :class:`~lightbulb.connector_execution.ConnectorExecutionResult` whose
   provenance commits the exact request (``request_digest`` equals the
   request's custody fingerprint); :func:`bind_execution` turns it into the
   receipt fields of one engine event (``launch_ref``, ``touch_ref``,
   ``canary_ref`` ...), so an engine command carries the journal reference
   the platform issued rather than a value a model typed.

2. **Observation adapters** — pure mappers from provider payloads that arrived
   through a sealed read (an observation read receipt, a completed governed
   read, or a host observation read) into engine observation receipts:
   Shopify analytics and Google Analytics into growth ``observe``; a Gmail
   thread into pipeline ``observe`` or ``reply``; Stripe balance transactions
   into period evidence; PostHog usage rows into SaaS usage accounts; GitHub
   deployments into release canary, roll-out, and roll-back events.  Every
   adapter refuses a payload without provenance and every output is sealed
   with the provenance digest it was derived from.

3. **Approval bridge** — an engine rejection with code ``APPROVAL_REQUIRED``
   (recovery ``await_approval``) becomes a typed platform approval request
   bound to the exact sealed command; the platform's decision becomes an
   :class:`ApprovalBinding` only when the task is ``APPROVED``, its context
   commits the same ``request_digest`` and ``transition_ref``, and the
   decider is not the acting actor.  The bound ``approval_ref`` is then placed
   on a fresh command for the same transition.

Nothing here performs an effect.  Provenance is checked, never minted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.connector_execution import ConnectorEffect, ConnectorExecutionRequest, ConnectorExecutionResult, ConnectorExecutionStatus

EXECUTION_RECEIPT_SCHEMA = "lightbulb.engine_execution_receipt.v1"
BOUND_EXECUTION_SCHEMA = "lightbulb.engine_bound_execution.v1"
OBSERVATION_PROVENANCE_SCHEMA = "lightbulb.engine_observation_provenance.v1"
ENGINE_OBSERVATION_SCHEMA = "lightbulb.engine_observation.v1"
APPROVAL_REQUEST_SCHEMA = "lightbulb.engine_approval_request.v1"
APPROVAL_BINDING_SCHEMA = "lightbulb.engine_approval_binding.v1"
ENGINE_APPROVAL_TYPE = "sdk_engine_transition"
ENGINE_APPROVALS_PATH = "/api/workflows/approvals/engine-transitions"
APPROVED_TASK_STATUSES: frozenset[str] = frozenset({"APPROVED"})
_TASK_STATUSES: frozenset[str] = frozenset({"PENDING", "IN_REVIEW", "APPROVED", "REJECTED", "MODIFIED", "EXPIRED", "CANCELLED"})
HUMAN_ONLY_CATEGORIES: frozenset[str] = frozenset({"people_change", "wind_down", "write_off"})

# Spring's ENGINE_PATTERN: any engine the SDK seals a state for may open an approval.  A closed
# Literal would have refused every engine added after the first four (company_launch first), and
# nothing introspects the members - the four originals still validate exactly as before.
EngineKind = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{2,79}$")]
ObservationLane = Literal["observation_read_receipt", "governed_read", "host_read"]
_HUNDRED = Decimal("100")


class BridgeError(ValueError):
    """A receipt, payload, or approval task does not prove what the caller claims; carries a code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BridgeError(code, message)


# --------------------------------------------------------------------------- #
# 1. Execution receipts
# --------------------------------------------------------------------------- #


class ExecutionReceipt(StrictModel):
    """A Spring-authorized, connector-performed effect, proven by its provenance."""

    schema_id: str = Field(default=EXECUTION_RECEIPT_SCHEMA, alias="schema")
    tool: ShortText
    effect: Literal["read", "draft", "write"]
    journal_ref: OpaqueRef
    request_digest: Sha256Digest
    receipt_digest: Sha256Digest
    route_digest: Sha256Digest
    connector_account_ref: OpaqueRef
    project_id: str
    approval_ref: OpaqueRef | None = None
    approval_receipt_digest: Sha256Digest | None = None
    completed_at: str
    output_digest: Sha256Digest
    execution_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("completed_at")
    @classmethod
    def _completed(cls, value: str) -> str:
        return timestamp(value, field_name="completed_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ExecutionReceipt:
        if self.effect == "write" and (self.approval_ref is None or self.approval_receipt_digest is None):
            raise ValueError("a write execution carries its approval reference and approval receipt digest")
        if self.effect != "write" and self.approval_receipt_digest is not None:
            raise ValueError("only writes carry an approval receipt digest")
        if not skip_digests(info) and self.execution_digest != sealed_digest(ExecutionReceipt, self, "execution_digest"):
            raise ValueError("execution_digest must commit the exact receipt")
        return self


def execution_receipt_from_connector(result: ConnectorExecutionResult | Mapping[str, Any], request: ConnectorExecutionRequest | Mapping[str, Any]) -> ExecutionReceipt:
    """Accept only a completed result whose provenance commits this exact request."""

    parsed_result = result if isinstance(result, ConnectorExecutionResult) else ConnectorExecutionResult.model_validate(dict(result))
    parsed_request = request if isinstance(request, ConnectorExecutionRequest) else ConnectorExecutionRequest.model_validate(dict(request))
    _require(parsed_result.status == ConnectorExecutionStatus.COMPLETED, "EXECUTION_NOT_COMPLETED", f"connector result is {parsed_result.status.value}; only completed effects become execution receipts")
    provenance = parsed_result.provenance
    _require(provenance is not None, "EXECUTION_PROVENANCE_MISSING", "a completed result without provenance is not evidence of an effect")
    assert provenance is not None
    _require(provenance.tool == parsed_request.tool == parsed_result.tool, "EXECUTION_TOOL_MISMATCH", "result, request, and provenance must name the same tool")
    _require(provenance.request_digest == parsed_request.custody_fingerprint(), "EXECUTION_REQUEST_MISMATCH", "provenance does not commit this request's custody fingerprint")
    _require(provenance.server_effect == parsed_request.effect, "EXECUTION_EFFECT_MISMATCH", f"provenance effect {provenance.server_effect.value} differs from the requested {parsed_request.effect.value}")
    if parsed_request.effect == ConnectorEffect.WRITE:
        _require(provenance.approval_ref is not None and provenance.approval_receipt_digest is not None, "EXECUTION_APPROVAL_MISSING", "a write effect proves its approval")
        _require(parsed_request.approval_ref is None or parsed_request.approval_ref == provenance.approval_ref, "EXECUTION_APPROVAL_MISMATCH", "the approval on the provenance differs from the request")
    payload = {
        "tool": provenance.tool,
        "effect": provenance.server_effect.value,
        "journal_ref": provenance.journal_ref,
        "request_digest": provenance.request_digest,
        "receipt_digest": provenance.receipt_digest,
        "route_digest": provenance.route_digest,
        "connector_account_ref": provenance.connector_account_ref,
        "project_id": str(provenance.project_id),
        "approval_ref": provenance.approval_ref,
        "approval_receipt_digest": provenance.approval_receipt_digest,
        "completed_at": provenance.completed_at,
        "output_digest": stable_digest(dict(parsed_result.output)),
    }
    return seal(ExecutionReceipt, payload, "execution_digest")


class ExecutionBinding(StrictModel):
    engine: EngineKind
    event: ShortText
    ref_field: ShortText
    effect: Literal["read", "draft", "write"]
    carries_approval: bool = False
    extra_fields: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=16)


EXECUTION_BINDINGS: Mapping[tuple[str, str], ExecutionBinding] = {
    (item.engine, item.event): item
    for item in (
        ExecutionBinding(engine="growth_engine", event="launch", ref_field="launch_ref", effect="write", carries_approval=True, extra_fields=("eligibility_receipt", "suppression_digest", "claim_projections")),
        ExecutionBinding(engine="growth_engine", event="pause", ref_field="launch_ref", effect="write"),
        ExecutionBinding(engine="growth_engine", event="resume", ref_field="launch_ref", effect="write"),
        ExecutionBinding(engine="pipeline_engine", event="enrich", ref_field="enrichment_ref", effect="read", extra_fields=("suppression_check_ref",)),
        ExecutionBinding(engine="pipeline_engine", event="touch", ref_field="touch_ref", effect="write", carries_approval=True, extra_fields=("step", "channel", "subject", "body", "claim_refs", "consent_ref", "intent", "eligibility_receipt", "suppression_digest")),
        ExecutionBinding(engine="pipeline_engine", event="book_meeting", ref_field="meeting_ref", effect="write", extra_fields=("meeting_at",)),
        ExecutionBinding(engine="pipeline_engine", event="hand_off", ref_field="deal_ref", effect="write", extra_fields=("deal_value",)),
        ExecutionBinding(engine="saas_operating_engine", event="start_canary", ref_field="canary_ref", effect="write", carries_approval=True, extra_fields=("canary_percent",)),
        ExecutionBinding(engine="saas_operating_engine", event="roll_out", ref_field="rollout_ref", effect="write"),
        ExecutionBinding(engine="saas_operating_engine", event="roll_back", ref_field="rollback_ref", effect="write"),
        ExecutionBinding(engine="company_operating_system", event="dispatch", ref_field="dispatch_refs", effect="write", extra_fields=("engine",)),
    )
}


class BoundExecution(StrictModel):
    schema_id: str = Field(default=BOUND_EXECUTION_SCHEMA, alias="schema")
    engine: EngineKind
    event: ShortText
    execution_digest: Sha256Digest
    journal_ref: OpaqueRef
    receipt_fields: dict[str, Any]
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=4)
    binding_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> BoundExecution:
        if not skip_digests(info) and self.binding_digest != sealed_digest(BoundExecution, self, "binding_digest"):
            raise ValueError("binding_digest must commit the exact bound execution")
        return self


def bind_execution(receipt: ExecutionReceipt | Mapping[str, Any], *, engine: str, event: str, fields: Mapping[str, Any] | None = None) -> BoundExecution:
    """Turn a proven execution into the receipt fields of one engine event."""

    parsed_receipt = receipt if isinstance(receipt, ExecutionReceipt) else ExecutionReceipt.model_validate(dict(detached(receipt)))
    binding = EXECUTION_BINDINGS.get((engine, event))
    _require(binding is not None, "EXECUTION_EVENT_UNBOUND", f"{engine}.{event} does not consume an execution receipt")
    assert binding is not None
    _require(parsed_receipt.effect == binding.effect, "EXECUTION_EFFECT_MISMATCH", f"{engine}.{event} needs a {binding.effect} effect; the receipt proves a {parsed_receipt.effect}")
    extras = dict(detached(fields or {}))
    unknown = sorted(set(extras) - set(binding.extra_fields))
    _require(not unknown, "EXECUTION_FIELDS_UNKNOWN", f"{engine}.{event} does not take {unknown}")
    receipt_fields: dict[str, Any] = dict(extras)
    receipt_fields[binding.ref_field] = (parsed_receipt.journal_ref,) if binding.ref_field == "dispatch_refs" else parsed_receipt.journal_ref
    if binding.carries_approval and parsed_receipt.approval_ref is not None:
        receipt_fields["approval_ref"] = parsed_receipt.approval_ref
    evidence_refs = (f"execution:{parsed_receipt.journal_ref}", f"receipt:{parsed_receipt.receipt_digest[:24]}")
    if "evidence_refs" in extras:
        raise BridgeError("EXECUTION_FIELDS_UNKNOWN", "evidence_refs are derived from the receipt")
    receipt_fields["evidence_refs"] = evidence_refs
    if engine == "company_operating_system":
        receipt_fields.pop("evidence_refs")
    return seal(BoundExecution, {"engine": engine, "event": event, "execution_digest": parsed_receipt.execution_digest, "journal_ref": parsed_receipt.journal_ref, "receipt_fields": receipt_fields, "evidence_refs": evidence_refs}, "binding_digest")


# --------------------------------------------------------------------------- #
# 2. Observation adapters
# --------------------------------------------------------------------------- #


class ObservationProvenance(StrictModel):
    """Where a payload came from and the digest that seals it, across the three read lanes."""

    schema_id: str = Field(default=OBSERVATION_PROVENANCE_SCHEMA, alias="schema")
    lane: ObservationLane
    source_tool: ShortText
    observation_ref: OpaqueRef
    provenance_digest: Sha256Digest
    output_digest: Sha256Digest
    completed_at: str
    window_start: str | None = None
    window_end: str | None = None

    @field_validator("completed_at")
    @classmethod
    def _completed(cls, value: str) -> str:
        return timestamp(value, field_name="completed_at")

    @field_validator("window_start", "window_end")
    @classmethod
    def _window(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self) -> ObservationProvenance:
        if (self.window_start is None) != (self.window_end is None):
            raise ValueError("window bounds travel together")
        if self.window_start is not None and self.window_end is not None and parsed(self.window_end) <= parsed(self.window_start):
            raise ValueError("window_end must follow window_start")
        return self

    @property
    def observed_through(self) -> str:
        return self.window_end or self.completed_at


def provenance_from_read_receipt(receipt: Mapping[str, Any] | Any) -> ObservationProvenance:
    raw = dict(detached(receipt))
    _require(raw.get("schema") == "lightbulb.observation_read_receipt.v1", "OBSERVATION_RECEIPT_INVALID", "expected an observation read receipt")
    for key in ("receipt_digest", "raw_output_digest", "source_capability", "receipt_ref", "observed_at", "window_start", "window_end"):
        _require(bool(raw.get(key)), "OBSERVATION_RECEIPT_INVALID", f"observation read receipt lacks {key}")
    _require(raw["receipt_digest"] != GENESIS_DIGEST, "OBSERVATION_RECEIPT_UNSEALED", "the read receipt is not sealed")
    return ObservationProvenance(lane="observation_read_receipt", source_tool=str(raw["source_capability"]), observation_ref=str(raw["receipt_ref"]), provenance_digest=str(raw["receipt_digest"]), output_digest=str(raw["raw_output_digest"]), completed_at=str(raw["observed_at"]), window_start=str(raw["window_start"]), window_end=str(raw["window_end"]))


def provenance_from_execution_receipt(receipt: ExecutionReceipt | Mapping[str, Any], *, window_start: str | None = None, window_end: str | None = None) -> ObservationProvenance:
    parsed_receipt = receipt if isinstance(receipt, ExecutionReceipt) else ExecutionReceipt.model_validate(dict(detached(receipt)))
    _require(parsed_receipt.effect == "read", "OBSERVATION_NOT_A_READ", "observations come from read effects")
    return ObservationProvenance(lane="governed_read", source_tool=parsed_receipt.tool, observation_ref=parsed_receipt.journal_ref, provenance_digest=parsed_receipt.receipt_digest, output_digest=parsed_receipt.output_digest, completed_at=parsed_receipt.completed_at, window_start=window_start, window_end=window_end)


def provenance_from_host_read(result: Mapping[str, Any] | Any, *, window_start: str | None = None, window_end: str | None = None) -> ObservationProvenance:
    raw = dict(detached(result))
    _require(raw.get("status") == "completed", "HOST_READ_NOT_COMPLETED", "only completed host reads carry provenance")
    provenance = raw.get("provenance")
    _require(isinstance(provenance, Mapping), "HOST_READ_PROVENANCE_MISSING", "host read carries no provenance")
    assert isinstance(provenance, Mapping)
    for key in ("provenance_digest", "output_digest", "source_capability", "journal_ref", "completed_at"):
        _require(bool(provenance.get(key)), "HOST_READ_PROVENANCE_MISSING", f"host provenance lacks {key}")
    _require(provenance["provenance_digest"] != GENESIS_DIGEST, "HOST_READ_UNSEALED", "the host provenance is not sealed")
    return ObservationProvenance(lane="host_read", source_tool=str(provenance["source_capability"]), observation_ref=str(provenance["journal_ref"]), provenance_digest=str(provenance["provenance_digest"]), output_digest=str(provenance["output_digest"]), completed_at=str(provenance["completed_at"]), window_start=window_start, window_end=window_end)


class EngineObservation(StrictModel):
    schema_id: str = Field(default=ENGINE_OBSERVATION_SCHEMA, alias="schema")
    engine: EngineKind
    event: ShortText
    source_tool: ShortText
    lane: ObservationLane
    provenance_digest: Sha256Digest
    observed_through: str
    receipt_fields: dict[str, Any]
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=4)
    synthetic: Literal[False] = False
    observation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("observed_through")
    @classmethod
    def _through(cls, value: str) -> str:
        return timestamp(value, field_name="observed_through")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> EngineObservation:
        if not skip_digests(info) and self.observation_digest != sealed_digest(EngineObservation, self, "observation_digest"):
            raise ValueError("observation_digest must commit the exact observation")
        return self


def _seal_observation(provenance: ObservationProvenance, *, engine: str, event: str, receipt_fields: Mapping[str, Any]) -> EngineObservation:
    evidence_refs = (f"observation:{provenance.observation_ref}", f"provenance:{provenance.provenance_digest[:24]}")
    fields = dict(receipt_fields)
    if engine != "company_operating_system":
        fields["evidence_refs"] = evidence_refs
    return seal(EngineObservation, {"engine": engine, "event": event, "source_tool": provenance.source_tool, "lane": provenance.lane, "provenance_digest": provenance.provenance_digest, "observed_through": provenance.observed_through, "receipt_fields": fields, "evidence_refs": evidence_refs}, "observation_digest")


def _int(value: Any, name: str, *, minimum: int = 0) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool) and value >= minimum, "PAYLOAD_FIELD_INVALID", f"{name} must be an integer >= {minimum}")
    return value


def _money(value: Any, name: str) -> Decimal:
    try:
        result = decimal_value(value, field_name=name)
    except ValueError as exc:
        raise BridgeError("PAYLOAD_FIELD_INVALID", str(exc)) from exc
    return result.quantize(MONEY_QUANTUM)


def _expect_tool(provenance: ObservationProvenance, *tools: str) -> None:
    _require(provenance.source_tool in tools, "OBSERVATION_TOOL_MISMATCH", f"this adapter reads {tools}; provenance names {provenance.source_tool}")


def shopify_analytics_to_growth_observation(provenance: ObservationProvenance, payload: Mapping[str, Any], *, spend: Any) -> EngineObservation:
    """Shopify analytics (sessions, checkouts, orders, sales) into a growth-engine ``observe`` receipt."""

    _expect_tool(provenance, "shopify.analytics_query")
    raw = dict(detached(payload))
    _require(raw.get("schema") in (None, "lightbulb.shopify_analytics_observation.v1"), "PAYLOAD_SCHEMA_MISMATCH", "expected a Shopify analytics observation payload")
    sessions = _int(raw.get("sessions"), "sessions")
    reached = _int(raw.get("sessions_that_reached_checkout", 0), "sessions_that_reached_checkout")
    orders = _int(raw.get("orders", raw.get("sessions_that_completed_checkout", 0)), "orders")
    _require(reached <= sessions and orders <= sessions, "PAYLOAD_INCONSISTENT", "checkouts and orders cannot exceed sessions")
    revenue = _money(raw.get("total_sales", "0"), "total_sales")
    fields: dict[str, Any] = {"measurement_source": "shopify_analytics", "observation_ref": provenance.observation_ref, "observed_through": provenance.observed_through, "spend": str(_money(spend, "spend")), "impressions": sessions, "clicks": reached, "conversions": orders, "revenue": str(revenue)}
    return _seal_observation(provenance, engine="growth_engine", event="observe", receipt_fields=fields)


def google_analytics_to_growth_observation(provenance: ObservationProvenance, payload: Mapping[str, Any], *, spend: Any, revenue: Any = "0") -> EngineObservation:
    """Google Analytics (impressions, clicks, conversions) into a growth-engine ``observe`` receipt."""

    _expect_tool(provenance, "google_analytics.fetch_metrics", "ga4.run_report")
    raw = dict(detached(payload))
    _require(raw.get("schema") in (None, "lightbulb.google_analytics_observation.v1"), "PAYLOAD_SCHEMA_MISMATCH", "expected a Google Analytics observation payload")
    impressions = _int(raw.get("impressions"), "impressions")
    clicks = _int(raw.get("clicks"), "clicks")
    conversions = _int(raw.get("conversions"), "conversions")
    _require(clicks <= impressions or impressions == 0, "PAYLOAD_INCONSISTENT", "clicks cannot exceed impressions")
    fields = {"measurement_source": "ga4", "observation_ref": provenance.observation_ref, "observed_through": provenance.observed_through, "spend": str(_money(spend, "spend")), "impressions": impressions, "clicks": clicks, "conversions": conversions, "revenue": str(_money(revenue, "revenue"))}
    return _seal_observation(provenance, engine="growth_engine", event="observe", receipt_fields=fields)


_BOUNCE_MARKERS = ("delivery status notification", "undeliverable", "mail delivery failed", "address not found")


def gmail_thread_to_pipeline_event(provenance: ObservationProvenance, thread: Mapping[str, Any], *, our_addresses: Sequence[str], classified_disposition: str | None = None, classification_ref: str | None = None) -> EngineObservation:
    """A Gmail thread into a pipeline ``reply`` (prospect wrote back) or ``observe`` (no reply yet, bounce detection)."""

    _expect_tool(provenance, "gmail.get_thread")
    raw = dict(detached(thread))
    _require(raw.get("schema") in (None, "lightbulb.gmail_thread.v1"), "PAYLOAD_SCHEMA_MISMATCH", "expected a Gmail thread payload")
    messages = raw.get("messages")
    _require(isinstance(messages, (list, tuple)) and len(messages) >= 1, "PAYLOAD_INCONSISTENT", "a thread carries at least one message")
    ours = {item.strip().lower() for item in our_addresses if item and item.strip()}
    _require(bool(ours), "PAYLOAD_FIELD_INVALID", "our_addresses must name at least one sender address")
    bounced = False
    inbound: Mapping[str, Any] | None = None
    for message in messages:  # type: ignore[union-attr]
        headers = dict((message or {}).get("headers") or {})
        sender = str(headers.get("from") or headers.get("From") or "").lower()
        subject = str(headers.get("subject") or headers.get("Subject") or "").lower()
        if any(marker in subject for marker in _BOUNCE_MARKERS) or "mailer-daemon" in sender:
            bounced = True
            continue
        if sender and not any(address in sender for address in ours):
            inbound = message
    if inbound is not None:
        _require(classified_disposition is not None and classification_ref is not None, "REPLY_CLASSIFICATION_MISSING", "a reply needs the classified disposition and the classification reference from communication.classify_reply")
        fields = {"reply_ref": provenance.observation_ref, "disposition": classified_disposition, "engagement_ref": classification_ref}
        return _seal_observation(provenance, engine="pipeline_engine", event="reply", receipt_fields=fields)
    fields = {"engagement_ref": provenance.observation_ref, "bounced": bounced}
    return _seal_observation(provenance, engine="pipeline_engine", event="observe", receipt_fields=fields)


def stripe_balance_to_period_evidence(provenance: ObservationProvenance, transactions: Sequence[Mapping[str, Any]], *, engine: str, currency: str, evidence_signals: Sequence[str] = ()) -> EngineObservation:
    """Stripe balance transactions into a company ``record_evidence`` receipt: net revenue for one engine."""

    _expect_tool(provenance, "stripe.list_balance_transactions")
    net = Decimal("0")
    counted = 0
    for row in transactions:
        item = dict(detached(row))
        kind = str(item.get("type", ""))
        if kind not in ("charge", "payment"):
            continue
        _require(str(item.get("currency", "")).upper() == currency.upper(), "PAYLOAD_CURRENCY_MISMATCH", f"transaction currency differs from {currency}")
        amount = _int(item.get("amount"), "amount")
        fee = _int(item.get("fee", 0), "fee")
        net += Decimal(amount - fee) / _HUNDRED
        counted += 1
    fields = {"engine": engine, "evidence_ref": provenance.observation_ref, "revenue": str(net.quantize(MONEY_QUANTUM)), "signals": tuple(evidence_signals)}
    _require(counted > 0, "PAYLOAD_INCONSISTENT", "no charge or payment transactions in the read")
    return _seal_observation(provenance, engine="company_operating_system", event="record_evidence", receipt_fields=fields)


def posthog_usage_to_accounts(provenance: ObservationProvenance, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """PostHog per-account usage rows (host lane) into the ``accounts`` input of ``saas_ops.observe_usage``."""

    _expect_tool(provenance, "posthog.query_events", "host.posthog_usage")
    accounts: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        item = dict(detached(row))
        ref = str(item.get("account_ref") or item.get("distinct_id") or "")
        _require(bool(ref), "PAYLOAD_FIELD_INVALID", "each usage row names an account_ref")
        _require(ref not in seen, "PAYLOAD_INCONSISTENT", f"duplicate account {ref}")
        seen.add(ref)
        account: dict[str, Any] = {"account_ref": ref, "plan_ref": str(item.get("plan_ref", "")), "signed_up_at": str(item.get("signed_up_at", "")), "last_active_at": str(item.get("last_active_at", provenance.completed_at)), "events": tuple(str(event) for event in item.get("events", ()) or ()), "mrr": str(_money(item.get("mrr", "0"), "mrr"))}
        for key in ("seats_used", "seats_last_period", "usage_units"):
            if item.get(key) is not None:
                account[key] = _int(item.get(key), key)
        if item.get("activated_at"):
            account["activated_at"] = str(item["activated_at"])
        accounts.append(account)
    return {"accounts": tuple(accounts), "observed_at": provenance.observed_through, "provenance_digest": provenance.provenance_digest, "observation_ref": provenance.observation_ref}


def github_deployments_to_release_event(provenance: ObservationProvenance, deployments: Sequence[Mapping[str, Any]], *, canary_environment: str = "canary", production_environment: str = "production", canary_percent: Any = "10") -> EngineObservation:
    """The latest GitHub deployment into a release ``start_canary``, ``roll_out``, or ``roll_back`` receipt."""

    _expect_tool(provenance, "github.list_deployments", "host.github_deployments")
    _require(len(deployments) >= 1, "PAYLOAD_INCONSISTENT", "no deployments to observe")
    latest = dict(detached(deployments[0]))
    environment = str(latest.get("environment", "")).lower()
    state = str(latest.get("state", latest.get("status", ""))).lower()
    ref = str(latest.get("id") or latest.get("deployment_id") or "")
    _require(bool(ref), "PAYLOAD_FIELD_INVALID", "a deployment names its id")
    _require(state in ("success", "active", "inactive", "failure", "error"), "PAYLOAD_FIELD_INVALID", f"unknown deployment state {state!r}")
    deployment_ref = f"github:{ref}"
    if environment == canary_environment.lower() and state in ("success", "active"):
        fields: dict[str, Any] = {"canary_ref": deployment_ref, "canary_percent": str(_money(canary_percent, "canary_percent"))}
        return _seal_observation(provenance, engine="saas_operating_engine", event="start_canary", receipt_fields=fields)
    if environment == production_environment.lower() and state in ("success", "active"):
        return _seal_observation(provenance, engine="saas_operating_engine", event="roll_out", receipt_fields={"rollout_ref": deployment_ref})
    if state in ("failure", "error", "inactive"):
        return _seal_observation(provenance, engine="saas_operating_engine", event="roll_back", receipt_fields={"rollback_ref": deployment_ref})
    raise BridgeError("DEPLOYMENT_UNMAPPED", f"deployment to {environment!r} in state {state!r} maps to no release event")


OBSERVATION_ADAPTERS: Mapping[str, str] = {
    "shopify.analytics_query": "shopify_analytics_to_growth_observation",
    "google_analytics.fetch_metrics": "google_analytics_to_growth_observation",
    "ga4.run_report": "google_analytics_to_growth_observation",
    "gmail.get_thread": "gmail_thread_to_pipeline_event",
    "stripe.list_balance_transactions": "stripe_balance_to_period_evidence",
    "posthog.query_events": "posthog_usage_to_accounts",
    "github.list_deployments": "github_deployments_to_release_event",
}


# --------------------------------------------------------------------------- #
# 3. Approval bridge
# --------------------------------------------------------------------------- #


class EngineApprovalRequest(StrictModel):
    """A platform approval request bound to one exact sealed engine command."""

    schema_id: str = Field(default=APPROVAL_REQUEST_SCHEMA, alias="schema")
    engine: EngineKind
    entity_ref: OpaqueRef
    event: ShortText
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    expected_version: int = Field(ge=0)
    expected_state_digest: Sha256Digest
    plan_digest: Sha256Digest
    actor_ref: OpaqueRef
    rejection_code: ShortText
    summary: ShortText
    description: BoundedText
    risk_level: int = Field(ge=1, le=10)
    expires_in_hours: int = Field(default=72, ge=1, le=720)
    approval_request_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> EngineApprovalRequest:
        if not skip_digests(info) and self.approval_request_digest != sealed_digest(EngineApprovalRequest, self, "approval_request_digest"):
            raise ValueError("approval_request_digest must commit the exact request")
        return self

    def to_platform_body(self) -> dict[str, Any]:
        """The body for ``POST /api/workflows/approvals/engine-transitions``; scope comes from the session, never the body."""

        binding = {"engine": self.engine, "entity_ref": self.entity_ref, "event": self.event, "transition_ref": self.transition_ref, "idempotency_key": self.idempotency_key, "request_digest": self.request_digest, "expected_version": self.expected_version, "expected_state_digest": self.expected_state_digest, "plan_digest": self.plan_digest, "actor_ref": self.actor_ref, "approval_request_digest": self.approval_request_digest}
        return {"approvalType": ENGINE_APPROVAL_TYPE, "summary": self.summary, "description": self.description, "riskLevel": self.risk_level, "expiresInHours": self.expires_in_hours, "proposedAction": binding, "contextData": {**binding, "rejection_code": self.rejection_code}}


def engine_approval_request(result: Mapping[str, Any] | Any, command: Mapping[str, Any] | Any, *, engine: str, entity_ref: str, plan_digest: str, summary: str, description: str, risk_level: int, expires_in_hours: int = 72) -> EngineApprovalRequest:
    """Build the approval request for a transition the engine rejected with ``APPROVAL_REQUIRED``."""

    raw_result = dict(detached(result))
    receipt = dict(raw_result.get("receipt") or {})
    _require(raw_result.get("candidate_validated") is False and receipt.get("status") == "rejected", "APPROVAL_NOT_NEEDED", "only a rejected transition asks for approval")
    approval_gate = str(receipt.get("rejection_code", "")) == "APPROVAL_NOT_BOUND"
    _require(approval_gate or dict(receipt.get("recovery") or {}).get("disposition") == "await_approval", "APPROVAL_NOT_NEEDED", "the rejection does not require a bound approval")
    raw_command = dict(detached(command))
    for key in ("transition_ref", "idempotency_key", "request_digest", "expected_state_digest", "actor_ref", "event"):
        _require(bool(raw_command.get(key)), "COMMAND_INCOMPLETE", f"the sealed command lacks {key}")
    _require(raw_command["request_digest"] == receipt.get("request_digest") and raw_command["transition_ref"] == receipt.get("transition_ref"), "COMMAND_RECEIPT_MISMATCH", "the command is not the one the receipt rejected")
    payload = {"engine": engine, "entity_ref": entity_ref, "event": str(raw_command["event"]), "transition_ref": str(raw_command["transition_ref"]), "idempotency_key": str(raw_command["idempotency_key"]), "request_digest": str(raw_command["request_digest"]), "expected_version": int(raw_command.get("expected_version", 0)), "expected_state_digest": str(raw_command["expected_state_digest"]), "plan_digest": plan_digest, "actor_ref": str(raw_command["actor_ref"]), "rejection_code": str(receipt["rejection_code"]), "summary": summary, "description": description, "risk_level": risk_level, "expires_in_hours": expires_in_hours}
    return seal(EngineApprovalRequest, payload, "approval_request_digest")


class DecoratedApprovalRequest(StrictModel):
    """An approval request carrying the authority the caller is asking for.

    ``proposedAction`` is untouched, so the platform's validated binding and the
    request's own ``approval_request_digest`` are byte-identical to an
    undecorated request; the category, the money, and the human-only flag ride
    in ``contextData``, where the platform's ceiling matcher reads them.
    """

    request: EngineApprovalRequest
    category: ShortText | None = None
    amount_cents: int | None = Field(default=None, ge=0)
    currency: CurrencyCode | None = None
    human_only: bool = False

    def to_platform_body(self) -> dict[str, Any]:
        body = self.request.to_platform_body()
        return {**body, "contextData": {**body["contextData"], "category": self.category, "amount_cents": self.amount_cents, "currency": self.currency, "human_only": self.human_only}}


def decorate_request(request: EngineApprovalRequest | Mapping[str, Any], *, category: str | None, amount: Any, currency: str | None, human_only: bool = False) -> DecoratedApprovalRequest:
    """Stamp one request with its authority category and money; human-only categories are forced human-only."""

    parsed_request = request if isinstance(request, EngineApprovalRequest) else EngineApprovalRequest.model_validate(dict(detached(request)))
    cents = None if amount is None else int(decimal_value(amount, field_name="amount") * _HUNDRED)
    forced = bool(human_only) or (category in HUMAN_ONLY_CATEGORIES)
    return DecoratedApprovalRequest(request=parsed_request, category=category, amount_cents=cents, currency=None if currency is None else str(currency).upper(), human_only=forced)


class ApprovalBinding(StrictModel):
    """A platform decision proven to bind one exact engine command."""

    schema_id: str = Field(default=APPROVAL_BINDING_SCHEMA, alias="schema")
    approval_ref: OpaqueRef
    engine: EngineKind
    entity_ref: OpaqueRef
    event: ShortText
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef | None = None
    request_digest: Sha256Digest
    plan_digest: Sha256Digest
    actor_ref: OpaqueRef
    decided_by_ref: OpaqueRef
    decided_at: str
    task_status: Literal["APPROVED"]
    approval_receipt_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("decided_at")
    @classmethod
    def _decision_time(cls, value: str) -> str:
        return timestamp(value, field_name="decided_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ApprovalBinding:
        if self.decided_by_ref == self.actor_ref:
            raise ValueError("the decider cannot be the acting actor")
        if not skip_digests(info) and self.approval_receipt_digest != sealed_digest(ApprovalBinding, self, "approval_receipt_digest"):
            raise ValueError("approval_receipt_digest must commit the exact binding")
        return self


def bind_approval(task: Mapping[str, Any], request: EngineApprovalRequest | Mapping[str, Any]) -> ApprovalBinding:
    """Accept a platform approval task only when it is approved and commits this exact request."""

    parsed_request = EngineApprovalRequest.model_validate(dict(detached(request)))
    raw = dict(detached(task))
    status = str(raw.get("status", "")).upper()
    _require(status in _TASK_STATUSES, "APPROVAL_TASK_INVALID", f"unknown approval status {status!r}")
    _require(status in APPROVED_TASK_STATUSES, "APPROVAL_NOT_GRANTED", f"approval task is {status}, not APPROVED")
    _require(str(raw.get("approvalType", ENGINE_APPROVAL_TYPE)) == ENGINE_APPROVAL_TYPE, "APPROVAL_TYPE_MISMATCH", "the task is not an engine transition approval")
    task_id = str(raw.get("id") or raw.get("approvalRef") or raw.get("approval_ref") or "")
    _require(bool(task_id), "APPROVAL_TASK_INVALID", "the task carries no id")
    context = dict(raw.get("contextData") or raw.get("context") or {})
    for key in ("request_digest", "transition_ref", "idempotency_key", "engine", "entity_ref", "event", "plan_digest", "actor_ref", "expected_version", "expected_state_digest"):
        _require(str(context.get(key, "")) == str(getattr(parsed_request, key)), "APPROVAL_BINDING_MISMATCH", f"task context {key} does not commit the requested transition")
    decided_by = str(raw.get("decidedByRef") or raw.get("decided_by_ref") or raw.get("decidedBy") or raw.get("decided_by") or "")
    decided_at = str(raw.get("decidedAt") or raw.get("decided_at") or "")
    _require(bool(decided_by) and bool(decided_at), "APPROVAL_DECISION_UNATTRIBUTED", "an approval names who decided and when")
    decided_at = timestamp(decided_at, field_name="decided_at")
    payload = {"approval_ref": task_id, "engine": parsed_request.engine, "entity_ref": parsed_request.entity_ref, "event": parsed_request.event, "transition_ref": parsed_request.transition_ref, "idempotency_key": parsed_request.idempotency_key, "request_digest": parsed_request.request_digest, "plan_digest": parsed_request.plan_digest, "actor_ref": parsed_request.actor_ref, "decided_by_ref": decided_by, "decided_at": decided_at, "task_status": "APPROVED"}
    return seal(ApprovalBinding, payload, "approval_receipt_digest")


def command_with_approval(binding: ApprovalBinding | Mapping[str, Any], command: Mapping[str, Any], *, state: Mapping[str, Any] | Any, occurred_at: str) -> dict[str, Any]:
    """Re-issue the rejected command against the current state with the bound ``approval_ref`` on its receipt (unsealed; seal with the engine)."""

    parsed_binding = binding if isinstance(binding, ApprovalBinding) else ApprovalBinding.model_validate(dict(detached(binding)))
    raw_command = dict(detached(command))
    raw_state = dict(detached(state))
    _require(raw_command.get("transition_ref") == parsed_binding.transition_ref and raw_command.get("request_digest") == parsed_binding.request_digest, "COMMAND_BINDING_MISMATCH", "the approval binds a different command")
    _require(raw_state.get("plan_digest") == parsed_binding.plan_digest, "STATE_BINDING_MISMATCH", "the approval binds a different plan")
    _require(parsed(timestamp(occurred_at, field_name="occurred_at")) >= parsed(str(raw_command["occurred_at"])), "NON_CHRONOLOGICAL_REISSUE", "the re-issued command cannot predate the rejected one")
    receipt = dict(raw_command.get("receipt") or {})
    receipt["approval_ref"] = parsed_binding.approval_ref
    reissued = {**raw_command, "expected_version": int(raw_state["version"]), "expected_state_digest": str(raw_state["state_digest"]), "occurred_at": occurred_at, "receipt": receipt}
    reissued.pop("request_digest", None)
    return reissued


__all__ = [
    "APPROVAL_BINDING_SCHEMA",
    "APPROVAL_REQUEST_SCHEMA",
    "BOUND_EXECUTION_SCHEMA",
    "ENGINE_APPROVALS_PATH",
    "ENGINE_APPROVAL_TYPE",
    "ENGINE_OBSERVATION_SCHEMA",
    "EXECUTION_BINDINGS",
    "EXECUTION_RECEIPT_SCHEMA",
    "HUMAN_ONLY_CATEGORIES",
    "OBSERVATION_ADAPTERS",
    "OBSERVATION_PROVENANCE_SCHEMA",
    "ApprovalBinding",
    "BoundExecution",
    "BridgeError",
    "DecoratedApprovalRequest",
    "EngineApprovalRequest",
    "EngineObservation",
    "ExecutionBinding",
    "ExecutionReceipt",
    "ObservationProvenance",
    "bind_approval",
    "bind_execution",
    "command_with_approval",
    "decorate_request",
    "engine_approval_request",
    "execution_receipt_from_connector",
    "github_deployments_to_release_event",
    "gmail_thread_to_pipeline_event",
    "google_analytics_to_growth_observation",
    "posthog_usage_to_accounts",
    "provenance_from_execution_receipt",
    "provenance_from_host_read",
    "provenance_from_read_receipt",
    "shopify_analytics_to_growth_observation",
    "stripe_balance_to_period_evidence",
]
