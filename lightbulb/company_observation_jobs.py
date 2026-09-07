"""Scheduled observation jobs: the reads a cadence tick needs, and the receipts they come back as.

The cadence runner raises ``collect_evidence`` work items but never invents
the evidence.  This module closes that gap without executing anything:

* ``plan_observation_jobs`` turns one tick plan into the exact platform reads
  that would satisfy its evidence items (Stripe balance transactions per
  dispatched engine) plus the engine-level observations the bundle's engines
  consume (Shopify or Google Analytics for growth, PostHog usage for SaaS
  accounts, GitHub deployments for releases).  Each job names its tool, the
  lane the platform admits it on (governed read or host read), the adapter
  that converts its payload, and the observation window.
* ``observation_inputs`` takes the completed reads back (provenance plus
  payload, as the platform returned them), runs them through the bridge
  adapters, and yields the sealed cadence inputs and engine observations the
  runner and the engines accept.  A receipt that does not match a planned job,
  names a different tool, or fails an adapter guard is reported, never
  guessed around.

Lanes are derived from the SDK's governed-read allowlist: a tool Spring has
not admitted stays on the host lane, where the harness performs the read and
the SDK only seals what it was handed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_cadence_runner import CadenceBundle, CadenceInput, CadenceTickPlan, build_bundle
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.company_execution_bridge import (
    BridgeError,
    EngineObservation,
    ObservationProvenance,
    github_deployments_to_release_event,
    google_analytics_to_growth_observation,
    posthog_usage_to_accounts,
    shopify_analytics_to_growth_observation,
    stripe_balance_to_period_evidence,
)
from lightbulb.governed_connector_contracts import GOVERNED_CONNECTOR_READ_TOOLS
from lightbulb.inference_cost_register import PROVIDER_COST_LANES

JOB_PLAN_SCHEMA = "lightbulb.company_observation_job_plan.v1"
JOB_BATCH_SCHEMA = "lightbulb.company_observation_batch.v1"
JobLane = Literal["governed_read", "host_read"]
JobKind = Literal["period_evidence", "growth_observation", "usage_observation", "release_observation", "chain_observation", "inference_cost", "recurring_observation"]

# Which read feeds which engine event, and the adapter that converts it.
OBSERVATION_SOURCES: Mapping[str, Mapping[str, str]] = {
    "stripe.list_balance_transactions": {"adapter": "stripe_balance_to_period_evidence", "engine": "company_operating_system", "event": "record_evidence", "kind": "period_evidence"},
    "shopify.analytics_query": {"adapter": "shopify_analytics_to_growth_observation", "engine": "growth_engine", "event": "observe", "kind": "growth_observation"},
    "google_analytics.fetch_metrics": {"adapter": "google_analytics_to_growth_observation", "engine": "growth_engine", "event": "observe", "kind": "growth_observation"},
    "posthog.query_events": {"adapter": "posthog_usage_to_accounts", "engine": "saas_operating_engine", "event": "observe_usage", "kind": "usage_observation"},
    "github.list_deployments": {"adapter": "github_deployments_to_release_event", "engine": "saas_operating_engine", "event": "release", "kind": "release_observation"},
    "anthropic_admin.get_cost_report": {"adapter": "inference_cost_observation_to_register", "engine": "company_cost_centres", "event": "record_source", "kind": "inference_cost"},
    "anthropic_admin.get_usage_report": {"adapter": "inference_cost_observation_to_register", "engine": "company_cost_centres", "event": "record_source", "kind": "inference_cost"},
    "openai_admin.get_costs": {"adapter": "inference_cost_observation_to_register", "engine": "company_cost_centres", "event": "record_source", "kind": "inference_cost"},
    "openai_admin.get_usage": {"adapter": "inference_cost_observation_to_register", "engine": "company_cost_centres", "event": "record_source", "kind": "inference_cost"},
    "google_cloud_billing.query_ai_costs": {"adapter": "inference_cost_observation_to_register", "engine": "company_cost_centres", "event": "record_source", "kind": "inference_cost"},
}
# The monthly cost read per connected provider; usage reads are priced externally and are not planned as bills.
_INFERENCE_COST_TOOL_BY_PROVIDER: Mapping[str, str] = {"anthropic": "anthropic_admin.get_cost_report", "openai": "openai_admin.get_costs"}
_INFERENCE_COST_GROUP_BY: Mapping[str, list[str]] = {"anthropic": ["description", "workspace_id"], "openai": ["line_item", "project_id"]}
_GROWTH_SOURCE_BY_ARCHETYPE: Mapping[str, str] = {"dtc_commerce": "shopify.analytics_query", "marketplace": "shopify.analytics_query", "b2b_saas": "google_analytics.fetch_metrics", "services_firm": "google_analytics.fetch_metrics"}
CHAIN_OBSERVATION_SOURCES = {
    ("bank_reconciliation", "load_lines"): ("xero.list_bank_transactions", "bank_lines"),
    ("payroll_run_chain", "draft"): ("xero.list_payroll_au_payruns", "payroll_draft"),
    ("payroll_run_chain", "attach_timesheets"): ("xero.list_payroll_au_timesheets", "payroll_timesheets"),
    ("payroll_run_chain", "cost_run"): ("xero.payroll_summary_report", "payroll_cost"),
    ("people_engine", "staff"): ("host.people_capacity", "people_capacity"),
    ("spend_control_chain", "capture"): ("ramp.list_transactions", "spend_capture"),
    ("spend_control_chain", "attach_receipt"): ("ramp.list_receipts", "spend_receipt"),
    ("spend_control_chain", "flag_policy_exception"): ("expensify.list_policies", "spend_policy"),
}


def lane_for(tool: str) -> JobLane:
    return "governed_read" if tool in GOVERNED_CONNECTOR_READ_TOOLS else "host_read"


class ObservationJob(StrictModel):
    job_ref: OpaqueRef
    kind: JobKind
    engine: ShortText
    event: ShortText
    tool: ShortText
    lane: JobLane
    adapter: ShortText
    arguments: dict[str, Any] = Field(default_factory=dict)
    adapter_inputs: dict[str, Any] = Field(default_factory=dict)
    action_id: OpaqueRef | None = None
    window_start: str
    window_end: str
    summary: BoundedText
    job_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("window_start", "window_end")
    @classmethod
    def _window(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ObservationJob:
        if parsed(self.window_end) <= parsed(self.window_start):
            raise ValueError("window_end must follow window_start")
        if self.lane != lane_for(self.tool):
            raise ValueError(f"{self.tool} is admitted on the {lane_for(self.tool)} lane")
        if not skip_digests(info) and self.job_digest != sealed_digest(ObservationJob, self, "job_digest"):
            raise ValueError("job_digest must commit the exact job")
        return self


class ObservationJobPlan(StrictModel):
    schema_id: str = Field(default=JOB_PLAN_SCHEMA, alias="schema")
    bundle_digest: Sha256Digest
    tick_plan_digest: Sha256Digest
    window_start: str
    window_end: str
    jobs: tuple[ObservationJob, ...] = Field(default_factory=tuple, max_length=512)
    unsupported: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=512)
    needs_input: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ObservationJobPlan:
        refs = [job.job_ref for job in self.jobs]
        if len(refs) != len(set(refs)):
            raise ValueError("job refs must be unique")
        if not skip_digests(info) and self.plan_digest != sealed_digest(ObservationJobPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact job plan")
        return self

    @property
    def governed(self) -> tuple[ObservationJob, ...]:
        return tuple(job for job in self.jobs if job.lane == "governed_read")

    @property
    def host(self) -> tuple[ObservationJob, ...]:
        return tuple(job for job in self.jobs if job.lane == "host_read")

    def job(self, job_ref: str) -> ObservationJob | None:
        return next((job for job in self.jobs if job.job_ref == job_ref), None)


def _job(*, job_ref: str, tool: str, arguments: Mapping[str, Any], adapter_inputs: Mapping[str, Any], action_id: str | None, window_start: str, window_end: str, summary: str) -> ObservationJob:
    source = OBSERVATION_SOURCES[tool]
    return seal(ObservationJob, {"job_ref": job_ref, "kind": source["kind"], "engine": source["engine"], "event": source["event"], "tool": tool, "lane": lane_for(tool), "adapter": source["adapter"], "arguments": dict(arguments), "adapter_inputs": dict(adapter_inputs), "action_id": action_id, "window_start": window_start, "window_end": window_end, "summary": summary}, "job_digest")


def _completed_month(start: str, end: str) -> tuple[str, str] | None:
    """The calendar month whose boundary falls inside (start, end]: a daily cost read against a monthly bill is noise."""

    end_at = parsed(end)
    boundary = end_at.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if not parsed(start) < boundary <= end_at:
        return None
    previous = (boundary - timedelta(days=1)).replace(day=1)
    return previous.isoformat().replace("+00:00", "Z"), boundary.isoformat().replace("+00:00", "Z")


def plan_observation_jobs(bundle: CadenceBundle | Mapping[str, Any], tick_plan: CadenceTickPlan | Mapping[str, Any], *, window_start: str, window_end: str | None = None, connected_providers: Sequence[str] = (), recurring_sources: Sequence[Any] = ()) -> ObservationJobPlan:
    """The reads that would satisfy this tick's evidence items and feed the bundle's engines; nothing is executed.

    ``connected_providers`` names the inference providers the tenant has connected (the SDK never reads that
    itself). Providers on the governed-read lane get one cost-report job per completed calendar month; providers
    on the billing-export or operator-invoice lane produce a ``needs_input`` work item, never an invented read.
    """

    parsed_bundle = build_bundle(bundle)
    plan = tick_plan if isinstance(tick_plan, CadenceTickPlan) else CadenceTickPlan.model_validate(dict(detached(tick_plan)))
    if plan.bundle_digest != parsed_bundle.plan_digest:
        raise ValueError("tick plan belongs to a different cadence bundle")
    start = timestamp(window_start, field_name="window_start")
    end = timestamp(window_end or plan.now, field_name="window_end")
    if parsed(end) <= parsed(start):
        raise ValueError("window_end must follow window_start")
    bp = parsed_bundle.operating_plan.blueprint
    currency = bp.currency
    jobs: list[ObservationJob] = []
    unsupported: list[str] = []
    for action in plan.actions:
        if action.kind in {"advance_chain", "run_payroll", "assemble_disbursement", "code_spend", "reconcile_bank", "triage_exception", "advance_obligation"}:
            source = CHAIN_OBSERVATION_SOURCES.get((action.engine, action.event))
            if source is None:
                unsupported.append(f"{action.action_id}: retrieve the retained source plans/states, bound executions or approved task named by {', '.join(action.satisfied_by)}; required receipt fields: {', '.join(action.required_receipt_fields)}. No provider read is executed or inferred.")
                continue
            tool, adapter = source
            jobs.append(seal(ObservationJob, {"job_ref": f"chain:{stable_digest(action.to_dict())[:32]}", "kind": "chain_observation", "engine": action.engine, "event": action.event,
                "tool": tool, "lane": lane_for(tool), "adapter": adapter, "arguments": {"entity_ref": action.entity_ref, "window_start": start, "window_end": end},
                "adapter_inputs": {"currency": currency, "scope": parsed_bundle.engine_scope(action.entity_ref)}, "action_id": action.action_id,
                "window_start": start, "window_end": end, "summary": f"Read {tool}; derive {action.engine}.{action.event} through its receipt builder. Source supplements remain mandatory."}, "job_digest"))
            continue
        if action.kind != "collect_evidence":
            continue
        engine = str(action.prepared.get("engine") or "")
        if not engine:
            unsupported.append(f"{action.action_id}: the evidence item does not name its engine")
            continue
        if parsed_bundle.require_cost_evidence:
            jobs.append(seal(ObservationJob, {"job_ref": f"evidence:{action.entity_ref}:{engine}", "kind": "period_evidence", "engine": "company_operating_system", "event": "record_evidence",
                "tool": "host.company_cost_register", "lane": "host_read", "adapter": "cost_register_evidence", "arguments": {"period_ref": action.entity_ref, "engine": engine},
                "adapter_inputs": {"engine": engine, "period_ref": action.entity_ref, "scope": parsed_bundle.engine_scope(action.entity_ref)}, "action_id": action.action_id,
                "window_start": start, "window_end": end, "summary": "Host contract: retrieve the scoped closed cost register and its retained plan; the SDK replays every economic source. This is not a hosted adapter claim."}, "job_digest"))
        else:
            jobs.append(_job(job_ref=f"evidence:{action.entity_ref}:{engine}", tool="stripe.list_balance_transactions", arguments={"created_gte": start, "created_lte": end, "currency": currency.lower(), "type": "charge", "limit": 100}, adapter_inputs={"engine": engine, "currency": currency}, action_id=action.action_id, window_start=start, window_end=end, summary=f"Net {currency} revenue for {engine} in {action.entity_ref} from Stripe balance transactions"))
    if "growth_engine" in bp.engine_kinds:
        tool = _GROWTH_SOURCE_BY_ARCHETYPE.get(bp.archetype, "google_analytics.fetch_metrics")
        arguments = {"period_start": start, "period_end": end, "metrics": ["sessions", "sessions_that_reached_checkout", "orders", "total_sales"]} if tool == "shopify.analytics_query" else {"start_date": start[:10], "end_date": end[:10], "metrics": ["impressions", "clicks", "conversions"]}
        jobs.append(_job(job_ref=f"growth:{parsed_bundle.company_ref}:{start[:10]}", tool=tool, arguments=arguments, adapter_inputs={"spend_required": True}, action_id=None, window_start=start, window_end=end, summary=f"Growth funnel observation from {tool}; ad spend is supplied with the receipt"))
    if "saas_operating_engine" in bp.engine_kinds:
        jobs.append(_job(job_ref=f"usage:{parsed_bundle.company_ref}:{start[:10]}", tool="posthog.query_events", arguments={"window_start": start, "window_end": end, "group_by": "account_ref"}, adapter_inputs={}, action_id=None, window_start=start, window_end=end, summary="Per-account product usage for saas_ops.observe_usage"))
        jobs.append(_job(job_ref=f"releases:{parsed_bundle.company_ref}:{start[:10]}", tool="github.list_deployments", arguments={"since": start, "until": end, "per_page": 20}, adapter_inputs={"canary_environment": "canary", "production_environment": "production"}, action_id=None, window_start=start, window_end=end, summary="Latest deployment for the release lifecycle"))
    needs_input: list[str] = []
    month = _completed_month(start, end)
    for provider in connected_providers:
        lane = PROVIDER_COST_LANES.get(provider)
        if lane is None:
            unsupported.append(f"{provider}: not an inference provider this planner knows")
            continue
        label = month[0][:7] if month else "the last completed month"
        if lane == "operator_invoice":
            needs_input.append(f"{provider}: no usage or cost API; supply the operator invoice for {label} as an operator_supplied_invoice")
            continue
        if lane == "billing_export":
            needs_input.append(f"{provider}: confirm the Cloud Billing export table for google_cloud_billing.query_ai_costs over {label}, then plan the read")
            continue
        if month is None:
            continue
        tool = _INFERENCE_COST_TOOL_BY_PROVIDER[provider]
        jobs.append(_job(job_ref=f"inference_cost:{provider}:{month[0][:7]}", tool=tool, arguments={"window_start": month[0], "window_end": month[1], "bucket_width": "1d", "group_by": list(_INFERENCE_COST_GROUP_BY[provider])}, adapter_inputs={"provider": provider}, action_id=None, window_start=month[0], window_end=month[1], summary=f"{provider} cost report for {month[0][:7]}: the provider's money as the second party to metered cost"))
    from lightbulb.company_recurring_observations import RecurringObservationBinding
    bindings = [RecurringObservationBinding.model_validate(detached(item)) for item in recurring_sources]
    if len(bindings) > 100 or len({item.source_ref for item in bindings}) != len(bindings):
        raise ValueError("RECURRING_SOURCE_CONFIGURATION_INVALID")
    jobs.extend(binding.job(start=start, end=end) for binding in bindings)
    return seal(ObservationJobPlan, {"bundle_digest": parsed_bundle.plan_digest, "tick_plan_digest": plan.plan_digest, "window_start": start, "window_end": end, "jobs": [job.to_dict() for job in jobs], "unsupported": unsupported, "needs_input": needs_input}, "plan_digest")


class ObservationReceipt(StrictModel):
    """One completed read handed back: the planned job it answers, its provenance, and the payload as returned."""

    job_ref: OpaqueRef
    provenance: ObservationProvenance
    payload: Any
    supplements: dict[str, Any] = Field(default_factory=dict)


class ObservationFailure(StrictModel):
    job_ref: OpaqueRef
    code: ShortText
    detail: BoundedText


class ObservationBatch(StrictModel):
    schema_id: str = Field(default=JOB_BATCH_SCHEMA, alias="schema")
    job_plan_digest: Sha256Digest
    inputs: tuple[CadenceInput, ...] = Field(default_factory=tuple, max_length=512)
    observations: tuple[EngineObservation, ...] = Field(default_factory=tuple, max_length=512)
    usage: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10)
    failures: tuple[ObservationFailure, ...] = Field(default_factory=tuple, max_length=512)
    unanswered: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=512)
    batch_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ObservationBatch:
        if not skip_digests(info) and self.batch_digest != sealed_digest(ObservationBatch, self, "batch_digest"):
            raise ValueError("batch_digest must commit the exact batch")
        return self


def _convert(job: ObservationJob, receipt: ObservationReceipt) -> EngineObservation | dict[str, Any]:
    provenance = receipt.provenance
    payload = receipt.payload
    if job.kind == "recurring_observation":
        raise BridgeError("TRUSTED_HOST_INGESTION_REQUIRED", "execute recurring jobs through CompanyObservationHost; caller-supplied provenance cannot mint trusted source evidence")
    if job.kind == "inference_cost":
        from lightbulb.inference_cost_register import statement_from_observation
        if stable_digest(payload) != provenance.output_digest:
            raise BridgeError("OBSERVATION_DIGEST_MISMATCH", "the provider statement must retain its exact read")
        statement = statement_from_observation(provenance, payload)
        if (statement.window_start, statement.window_end) != (job.window_start, job.window_end):
            raise BridgeError("WINDOW_MISMATCH", "the statement must cover the planned complete billing window")
        return {"kind": "inference_cost", "statement": statement.to_dict(),
            "requires_metered_reconciliation": True, "protected_register_recorded": False}
    if job.kind == "chain_observation" or job.adapter == "cost_register_evidence":
        if stable_digest(payload) != provenance.output_digest:
            raise BridgeError("OBSERVATION_DIGEST_MISMATCH", "the original chain read must match its provenance")
        fields = _chain_receipt(job, receipt)
        return seal(EngineObservation, {"engine": job.engine, "event": job.event, "source_tool": provenance.source_tool, "lane": provenance.lane,
            "provenance_digest": provenance.provenance_digest, "observed_through": provenance.observed_through, "receipt_fields": fields,
            "evidence_refs": [f"observation:{provenance.observation_ref}"]}, "observation_digest")
    if job.adapter == "stripe_balance_to_period_evidence":
        rows = payload.get("data") if isinstance(payload, Mapping) and "data" in payload else payload
        if not isinstance(rows, Sequence) or isinstance(rows, str):
            raise BridgeError("PAYLOAD_INCONSISTENT", "Stripe balance transactions arrive as a list (or {data: [...]})")
        return stripe_balance_to_period_evidence(provenance, list(rows), engine=str(job.adapter_inputs["engine"]), currency=str(job.adapter_inputs["currency"]), evidence_signals=tuple(receipt.supplements.get("signals", ())))
    if job.adapter == "shopify_analytics_to_growth_observation":
        if "spend" not in receipt.supplements:
            raise BridgeError("SPEND_REQUIRED", "a growth observation needs the period's ad spend supplied with the receipt")
        return shopify_analytics_to_growth_observation(provenance, payload, spend=receipt.supplements["spend"])
    if job.adapter == "google_analytics_to_growth_observation":
        if "spend" not in receipt.supplements:
            raise BridgeError("SPEND_REQUIRED", "a growth observation needs the period's ad spend supplied with the receipt")
        return google_analytics_to_growth_observation(provenance, payload, spend=receipt.supplements["spend"], revenue=receipt.supplements.get("revenue", "0"))
    if job.adapter == "posthog_usage_to_accounts":
        rows = payload.get("results") if isinstance(payload, Mapping) and "results" in payload else payload
        if not isinstance(rows, Sequence) or isinstance(rows, str):
            raise BridgeError("PAYLOAD_INCONSISTENT", "PostHog usage rows arrive as a list (or {results: [...]})")
        return posthog_usage_to_accounts(provenance, list(rows))
    if job.adapter == "github_deployments_to_release_event":
        rows = payload if isinstance(payload, Sequence) and not isinstance(payload, str) else [payload]
        return github_deployments_to_release_event(provenance, list(rows), canary_environment=str(job.adapter_inputs.get("canary_environment", "canary")), production_environment=str(job.adapter_inputs.get("production_environment", "production")), canary_percent=receipt.supplements.get("canary_percent", "10"))
    raise BridgeError("ADAPTER_UNKNOWN", f"no adapter named {job.adapter}")


def _chain_receipt(job: ObservationJob, receipt: ObservationReceipt) -> dict[str, Any]:
    from lightbulb import bank_reconciliation as bank, payroll_run_chain as payroll, people_engine as people, spend_control_chain as spend
    provenance, payload, extra = receipt.provenance, receipt.payload, receipt.supplements
    if job.adapter == "cost_register_evidence":
        from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE, period_evidence_receipt
        source_plan, state = COST_REGISTER_LIFECYCLE.bind(payload["source_plan"], payload["source_state"])
        scope = job.adapter_inputs["scope"]
        if any(getattr(state.scope, key) != scope[key] for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")):
            raise BridgeError("SCOPE_MISMATCH", "the cost register belongs to another company or project")
        return period_evidence_receipt(state, source_plan=source_plan, engine=job.adapter_inputs["engine"], period_ref=job.adapter_inputs["period_ref"])
    if job.adapter == "bank_lines":
        return bank.lines_receipt(provenance, payload, currency=job.adapter_inputs["currency"], position=extra.get("position"))
    if job.adapter == "payroll_draft":
        return payroll.draft_receipt(provenance, payload, paid_runs=extra.get("paid_runs", ()), paid_plans=extra.get("paid_plans"))
    if job.adapter == "payroll_timesheets":
        return payroll.timesheet_receipt(provenance, payload)
    if job.adapter == "payroll_cost":
        return payroll.cost_receipt(provenance, payload, prior_run=extra.get("prior_run"), prior_plan=extra.get("prior_plan"), close_state=extra.get("close_state"), close_plan=extra.get("close_plan"))
    if job.adapter == "people_capacity":
        return people.capacity_receipt(provenance, payload)
    if job.adapter == "spend_capture":
        return spend.capture_receipt(provenance, payload, prior_states=extra.get("prior_states", ()), source_plans=extra.get("source_plans"))
    if job.adapter == "spend_receipt":
        return spend.receipt_match(provenance, payload)
    if job.adapter == "spend_policy":
        return spend.policy_receipt(provenance, payload)
    raise BridgeError("ADAPTER_UNKNOWN", f"no chain adapter named {job.adapter}")


def observation_inputs(job_plan: ObservationJobPlan | Mapping[str, Any], receipts: Sequence[ObservationReceipt | Mapping[str, Any]]) -> ObservationBatch:
    """Convert completed reads into cadence inputs and engine observations; report what did not convert."""

    plan = job_plan if isinstance(job_plan, ObservationJobPlan) else ObservationJobPlan.model_validate(dict(detached(job_plan)))
    inputs: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    usage: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    answered: set[str] = set()
    for raw in receipts:
        receipt = raw if isinstance(raw, ObservationReceipt) else ObservationReceipt.model_validate(dict(detached(raw)))
        job = plan.job(receipt.job_ref)
        if job is None:
            failures.append({"job_ref": receipt.job_ref, "code": "JOB_UNPLANNED", "detail": "no planned job carries this ref"})
            continue
        if receipt.job_ref in answered:
            failures.append({"job_ref": receipt.job_ref, "code": "JOB_DUPLICATE", "detail": "this job was already answered in the batch"})
            continue
        if receipt.provenance.source_tool != job.tool:
            failures.append({"job_ref": receipt.job_ref, "code": "TOOL_MISMATCH", "detail": f"planned {job.tool}; the read came from {receipt.provenance.source_tool}"})
            continue
        if receipt.provenance.lane != job.lane and receipt.provenance.lane != "observation_read_receipt":
            failures.append({"job_ref": receipt.job_ref, "code": "LANE_MISMATCH", "detail": f"planned the {job.lane} lane; the read came through {receipt.provenance.lane}"})
            continue
        try:
            converted = _convert(job, receipt)
        except (BridgeError, ValueError, KeyError, TypeError) as exc:
            failures.append({"job_ref": receipt.job_ref, "code": getattr(exc, "code", "ADAPTER_REFUSED"), "detail": str(exc)[:900]})
            continue
        answered.add(receipt.job_ref)
        if isinstance(converted, EngineObservation):
            if job.action_id is not None:
                inputs.append({"action_id": job.action_id, "receipt": dict(converted.receipt_fields), "source_digest": converted.observation_digest, "reason": f"sealed {converted.source_tool} observation {receipt.provenance.observation_ref}"})
            observations.append(converted.to_dict())
        else:
            usage.append({"job_ref": receipt.job_ref, **converted})
    unanswered = [job.job_ref for job in plan.jobs if job.job_ref not in answered]
    return seal(ObservationBatch, {"job_plan_digest": plan.plan_digest, "inputs": inputs, "observations": observations, "usage": usage, "failures": failures, "unanswered": unanswered}, "batch_digest")


def job_request_digest(job: ObservationJob) -> str:
    """Stable digest of the read request (tool + arguments + window) for idempotent scheduling."""

    return stable_digest({"tool": job.tool, "arguments": job.arguments, "window_start": job.window_start, "window_end": job.window_end})


OBSERVATION_JOBS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_observation_jobs",
    "golden_loop": "company_operating_system",
    "stages": ["plan_reads", "perform_reads_on_admitted_lane", "seal_provenance", "convert", "feed_cadence"],
    "sources": {tool: dict(spec) for tool, spec in OBSERVATION_SOURCES.items()},
    "lanes": {tool: lane_for(tool) for tool in OBSERVATION_SOURCES},
    "required_connectors": sorted(OBSERVATION_SOURCES),
    "hard_rules": [
        "a job names the exact tool, lane, adapter, and window; planning executes none of them",
        "the lane comes from the governed-read allowlist: unadmitted tools stay on the host lane",
        "a receipt converts only for the job it answers, from the tool it planned, through the bridge adapter's guards",
        "ad spend and reply classifications are supplied with the receipt, never inferred from the read",
        "inference cost is read once per completed calendar month per connected provider; a daily cost read against a monthly bill is noise",
        "a provider with no cost API produces a needs_input work item, never an invented read",
        "recurring source bindings assemble media, trusted touches, local presence, content and first-purchase intake",
        "recurring jobs execute only through the authenticated company host; caller-supplied provenance cannot mint source trust",
    ],
}

__all__ = [
    "CHAIN_OBSERVATION_SOURCES",
    "JOB_BATCH_SCHEMA",
    "JOB_PLAN_SCHEMA",
    "OBSERVATION_JOBS_MANIFEST",
    "OBSERVATION_SOURCES",
    "ObservationBatch",
    "ObservationFailure",
    "ObservationJob",
    "ObservationJobPlan",
    "ObservationReceipt",
    "job_request_digest",
    "lane_for",
    "observation_inputs",
    "plan_observation_jobs",
]
