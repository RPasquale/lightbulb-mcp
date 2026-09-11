"""Durable expansion and win-back intake into the canonical prospect lifecycle.

Usage is explicitly an operator observation, rederived from declared account
facts. A win-back requires a persisted, replayed churned retention case. Neither
source creates consent or verifies revenue. Spring-backed stores and the host's
authenticated checkpoint gateway own scope, persistence and retry custody.
"""
from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from lightbulb.company_engine_core import OpaqueRef, StrictModel, detached, parsed, stable_digest, timestamp
from lightbulb.company_engine_store import EngineStateConflictError
from lightbulb.company_host_journal import AuthenticatedCheckpointGateway
from lightbulb.company_hosted_scheduler import CheckpointConflict
from lightbulb.company_operating_system import CompanySignal
from lightbulb.company_sales_playbooks import SalesPlaybook, SalesProspectBinding, bind_sales_playbook
from lightbulb.company_signal_consumers import consume_signal
from lightbulb.connector_execution import ExecutionScope
from lightbulb.permission_register import eligibility_receipt, register_snapshot, verify_eligibility
from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE, ProspectFacts, evaluate_icp_fit, open_prospect
from lightbulb.saas_operating_loop import AccountUsage, SaasOperatingLoopPlan, UsageSnapshot, observe_usage


INTAKE_SCHEMA = "lightbulb.company_sales_intake.v1"
MAX_INTAKE_BYTES = 512 * 1024


class SalesIntakeError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise SalesIntakeError(code)


class SalesUsageEvidence(StrictModel):
    """Declared host facts, never a claim that the SDK polled a usage provider."""
    source_kind: Literal["operator_observation"] = "operator_observation"
    source_ref: OpaqueRef
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    scope: ExecutionScope
    source_plan: SaasOperatingLoopPlan
    accounts: tuple[AccountUsage, ...] = Field(min_length=1, max_length=100)
    snapshot: UsageSnapshot
    provider_verified: Literal[False] = False

    @model_validator(mode="after")
    def _rederived(self):
        _require(self.scope.project_id is not None and bool(self.scope.actor_ref), "SALES_USAGE_SCOPE_REQUIRED")
        _require(self.snapshot == observe_usage(self.source_plan, self.accounts, observed_at=self.snapshot.observed_at),
                 "SALES_USAGE_SNAPSHOT_MISMATCH")
        for account in self.accounts:
            _require(all(stamp is None or parsed(stamp) <= parsed(self.snapshot.observed_at)
                         for stamp in (account.signed_up_at, account.last_active_at, account.activated_at)),
                     "SALES_USAGE_FROM_FUTURE")
        return self


class SalesIntakeCandidate(StrictModel):
    candidate_ref: OpaqueRef
    kind: Literal["expansion", "winback", "verified_event"]
    binding: SalesProspectBinding
    facts: ProspectFacts
    facts_evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    observed_at: str
    expires_at: str
    signal: CompanySignal | None = None
    usage_evidence: SalesUsageEvidence | None = None
    retention_case_ref: OpaqueRef | None = None
    customer_event_ref: OpaqueRef | None = None
    customer_event_digest: str | None = Field(default=None,pattern=r"^[a-f0-9]{64}$")

    @field_validator("observed_at", "expires_at")
    @classmethod
    def _time(cls, value: str, info: Any) -> str:
        return timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _exact(self):
        _require(parsed(self.observed_at) < parsed(self.expires_at), "SALES_CANDIDATE_WINDOW_INVALID")
        _require((self.binding.prospect_ref, self.binding.account_ref) == (self.facts.prospect_ref, self.facts.account_ref),
                 "SALES_CANDIDATE_ACCOUNT_MISMATCH")
        _require(self.kind == "verified_event" or self.binding.purpose == self.kind, "SALES_CANDIDATE_PURPOSE_MISMATCH")
        if self.kind == "verified_event":
            _require(self.customer_event_ref is not None and self.customer_event_digest is not None
                and self.signal is None and self.usage_evidence is None and self.retention_case_ref is None,
                "SALES_CUSTOMER_EVENT_REQUIRED")
            return self
        _require(self.customer_event_ref is None and self.customer_event_digest is None,"SALES_CUSTOMER_EVENT_UNEXPECTED")
        if self.kind == "expansion":
            _require(self.signal is not None and self.usage_evidence is not None and self.retention_case_ref is None,
                     "SALES_EXPANSION_EVIDENCE_REQUIRED")
            _require(self.signal.name == "signals.expansion_candidate"
                     and self.signal.producer == "saas_operating_engine", "SALES_EXPANSION_SIGNAL_REQUIRED")
            _require(self.observed_at == self.usage_evidence.snapshot.observed_at
                     and parsed(self.signal.emitted_at) >= parsed(self.observed_at), "SALES_EXPANSION_TIME_MISMATCH")
        else:
            _require(self.retention_case_ref is not None and self.signal is None and self.usage_evidence is None,
                     "SALES_WINBACK_SOURCE_REQUIRED")
        return self


def parse_sales_intake_candidates(values: Any) -> tuple[SalesIntakeCandidate, ...]:
    _require(isinstance(values, (list, tuple)) and len(values) <= 100, "SALES_CANDIDATES_INVALID")
    candidates = tuple(SalesIntakeCandidate.model_validate(detached(value)) for value in values)
    _require(len({candidate.candidate_ref for candidate in candidates}) == len(candidates), "SALES_CANDIDATE_DUPLICATE")
    return candidates


class CompanySalesIntake:
    def __init__(self, runner: Any, gateway: Any, playbooks: Any):
        _require(isinstance(gateway, AuthenticatedCheckpointGateway), "SALES_AUTHENTICATED_JOURNAL_REQUIRED")
        _require(gateway.bundle_digest == runner.bundle.plan_digest, "SALES_BUNDLE_MISMATCH")
        _require(isinstance(playbooks, (list, tuple)) and len(playbooks) <= 100, "SALES_PLAYBOOKS_INVALID")
        parsed_books = tuple(SalesPlaybook.model_validate(detached(book)) for book in playbooks)
        _require(len({book.spec.playbook_ref for book in parsed_books}) == len(parsed_books), "SALES_PLAYBOOK_DUPLICATE")
        self.runner, self.gateway = runner, gateway
        self.playbooks = {book.spec.playbook_ref: book for book in parsed_books}

    def _identity(self, candidate: SalesIntakeCandidate, playbook: SalesPlaybook) -> str:
        source = candidate.usage_evidence.snapshot.snapshot_digest if candidate.kind == "expansion" else candidate.customer_event_ref if candidate.kind == "verified_event" else candidate.retention_case_ref
        return "sales-intake-" + stable_digest({"bundle_digest": self.runner.bundle.plan_digest,
            "scope": self.runner.bundle.scope, "kind": candidate.kind, "source": source,
            "account_ref": candidate.binding.account_ref, "offer_ref": playbook.spec.offer.offer_ref})

    def _read(self, ref: str) -> dict[str, Any] | None:
        journal = self.gateway.get(ref)
        if journal is not None:
            _require(journal.get("schema") == INTAKE_SCHEMA and journal.get("scope") == self.runner.bundle.scope
                     and journal.get("bundle_digest") == self.runner.bundle.plan_digest
                     and journal.get("intake_ref") == ref, "SALES_INTAKE_SCOPE_MISMATCH")
        return journal

    def _write(self, ref: str, document: Any, previous: Any, fence: Any):
        _require(len(json.dumps(detached(document), ensure_ascii=True).encode("utf-8")) + 4096 <= MAX_INTAKE_BYTES,
                 "SALES_INTAKE_TOO_LARGE")
        fence()
        return self.gateway.put(ref, document, expected_revision=previous["revision"] if previous else 0)

    def _scoped_state(self, runtime: Any, ref: str):
        state = runtime.load(ref)
        _require(state.scope.to_dict() == self.runner.bundle.engine_scope(ref), "SALES_SOURCE_SCOPE_MISMATCH")
        return state

    def _permission(self, binding: SalesProspectBinding, *, now: str):
        runtime = self.runner.runtimes.get("contact_endpoint")
        _require(runtime is not None, "SALES_PERMISSION_RUNTIME_REQUIRED")
        state = self._scoped_state(runtime, binding.permission_entity_ref)
        _require(state.ledger.endpoint_digest == binding.endpoint_digest and state.ledger.key_ref == binding.endpoint_key_ref,
                 "SALES_CONTACT_PERMISSION_MISMATCH")
        receipt, suppression = eligibility_receipt([register_snapshot(state, runtime.plan)],
            channel="email", endpoints=[binding.endpoint_digest], now=now)
        verify_eligibility(receipt, suppression_digest=suppression.suppression_digest, channel="email", at=now,
            endpoints=[binding.endpoint_digest], company_ref=self.runner.bundle.company_ref,
            expected_scope=self.runner.bundle.engine_scope(binding.prospect_ref))
        return state, receipt

    def _source(self, candidate: SalesIntakeCandidate, playbook: SalesPlaybook, *, now: str):
        bundle = self.runner.bundle
        if candidate.kind == "verified_event":
            from lightbulb.company_customer_events import CompanyCustomerEvents, CustomerEvent
            source = CompanyCustomerEvents(self.runner,self.gateway).read(candidate.customer_event_ref)
            _require(source is not None and "event" in source,"SALES_CUSTOMER_EVENT_NOT_RETAINED")
            event = CustomerEvent.model_validate(source["event"])
            allowed = {"renewal":{"renewal_due"},"activation":{"signed_up"},"expansion":{"capacity_reached","upgrade_requested"},"acquisition":{"demo_requested","inquiry_received"}}
            _require(event.account_ref==candidate.binding.account_ref and event.kind in allowed.get(candidate.binding.purpose,set())
                and stable_digest(event.to_dict())==candidate.customer_event_digest and event.occurred_at==candidate.observed_at,
                "SALES_CUSTOMER_EVENT_MISMATCH")
            return {"kind":"verified_customer_event","event":event.to_dict(),"proof":source["proof"],"provider_verified":"receipt" in source["proof"],"platform_verified":source["proof"].get("source_kind")=="authenticated_crm_accepted_proposal"}
        if candidate.kind == "expansion":
            usage = candidate.usage_evidence
            _require(usage.scope.model_dump(mode="json") == {**bundle.scope, "actor_ref": bundle.actor_ref},
                     "SALES_SOURCE_SCOPE_MISMATCH")
            _require(bundle.saas_plan is not None and usage.source_plan.plan_digest == bundle.saas_plan.plan_digest,
                     "SALES_USAGE_PLAN_MISMATCH")
            matches = [row for row in usage.snapshot.expansion_candidates
                       if row.account_ref == candidate.binding.account_ref]
            _require(len(matches) == 1 and matches[0].suggested_plan_ref is not None,
                     "SALES_EXPANSION_NOT_OBSERVED")
            row = matches[0]
            _require(candidate.signal.payload.get("account_ref") == row.account_ref
                     and candidate.signal.payload.get("suggested_plan_ref") == row.suggested_plan_ref
                     and playbook.spec.offer.offer_ref == row.suggested_plan_ref, "SALES_EXPANSION_OFFER_MISMATCH")
            _require(parsed(candidate.signal.emitted_at) <= parsed(now), "SALES_SIGNAL_FROM_FUTURE")
            consumption = consume_signal(bundle.operating_plan, candidate.signal, now=now)
            intents = [intent for intent in consumption.intents if intent.kind == "source_expansion_prospect"]
            _require(len(intents) == 1 and not intents[0].requires_consent, "SALES_EXPANSION_CONSENT_REQUIRED")
            return {"kind": "operator_observation", "usage": usage.to_dict(), "consumption": consumption.to_dict(),
                    "provider_verified": False}
        runtime = self.runner.runtimes.get("retention_chain")
        _require(runtime is not None, "SALES_RETENTION_RUNTIME_REQUIRED")
        state = self._scoped_state(runtime, candidate.retention_case_ref)
        _require(state.status == "churned" and state.ledger.account_ref == candidate.binding.account_ref,
                 "SALES_WINBACK_CHURN_REQUIRED")
        _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(candidate.observed_at),
                 "SALES_WINBACK_FROM_FUTURE")
        return {"kind": "persisted_retention_case", "source_plan": runtime.plan.to_dict(), "state": state.to_dict(),
                "provider_verified": False}

    def _plan(self, ref: str, candidate: SalesIntakeCandidate, playbook: SalesPlaybook, *, now: str):
        permission, eligibility = self._permission(candidate.binding, now=now)
        source = self._source(candidate, playbook, now=now)
        if candidate.kind == "expansion":
            _require(candidate.signal.payload.get("consent_ref") == permission.ledger.consent_ref,
                     "SALES_EXPANSION_CONSENT_MISMATCH")
        pipeline = self.runner.runtimes.get("pipeline_engine")
        _require(pipeline is not None, "SALES_PIPELINE_RUNTIME_REQUIRED")
        state = open_prospect(pipeline.plan, self.runner.bundle.engine_scope(candidate.binding.prospect_ref),
            facts=candidate.facts, fit=evaluate_icp_fit(pipeline.plan, candidate.facts),
            opened_at=now, actor_ref=self.runner.bundle.actor_ref)
        opening, steps = state.to_dict(), []
        receipts = [("enrich", {"enrichment_ref": candidate.facts.source_ref,
                     "suppression_check_ref": "permission:" + eligibility.suppression_digest,
                     "evidence_refs": [ref, *candidate.facts_evidence_refs]}),
                    ("sequence", {"sequence_ref": candidate.binding.sequence.sequence_ref,
                     "sequence_plan_digest": candidate.binding.sequence.sequence_plan_digest,
                     "sequence_channel_daily_caps": {policy.channel: policy.daily_cap
                         for policy in pipeline.plan.blueprint.channels if policy.enabled},
                     "sequence_plan": candidate.binding.sequence.to_dict(), "evidence_refs": [ref]})]
        for event, receipt in receipts:
            command = pipeline.command(state, event=event, transition_ref=ref + ":" + event,
                idempotency_key=ref + ":" + event, occurred_at=now, actor_ref=self.runner.bundle.actor_ref, receipt=receipt)
            result = pipeline.advance(pipeline.plan, state, command)
            _require(result.candidate_validated, "SALES_INTAKE_TRANSITION_REFUSED")
            steps.append({"command": command, "source_digest": state.state_digest,
                          "source_version": state.version, "result_digest": result.state.state_digest})
            state = result.state
        return {"schema": INTAKE_SCHEMA, "status": "RUNNING", "phase": "planned", "intake_ref": ref,
                "bundle_digest": self.runner.bundle.plan_digest, "scope": detached(self.runner.bundle.scope),
                "candidate": candidate.to_dict(), "playbook_digest": playbook.playbook_digest,
                "source": source, "permission": permission.to_dict(), "opening_state": opening, "steps": steps,
                "provider_effect_executed": False, "revenue_verified": False}

    def ingest(self, candidate: Any, *, now: str, fence: Any) -> dict[str, Any]:
        candidate = SalesIntakeCandidate.model_validate(detached(candidate))
        now = timestamp(now, field_name="now")
        playbook = self.playbooks.get(candidate.binding.playbook_ref)
        _require(playbook is not None, "SALES_PLAYBOOK_REQUIRED")
        playbook, binding = bind_sales_playbook(playbook, candidate.binding, self.runner.bundle)
        ref = self._identity(candidate, playbook)
        journal = self._read(ref)
        if journal is not None:
            _require(SalesIntakeCandidate.model_validate(journal["candidate"]).to_dict() == candidate.to_dict() and journal["playbook_digest"] == playbook.playbook_digest,
                     "SALES_INTAKE_INTENT_CHANGED")
            if journal["phase"] == "completed":
                return detached(journal["summary"])
        _require(parsed(candidate.observed_at) <= parsed(now) < parsed(candidate.expires_at), "SALES_CANDIDATE_EXPIRED")
        if journal is None:
            proposed = self._plan(ref, candidate, playbook, now=now)
            try:
                journal = self._write(ref, proposed, None, fence)
            except CheckpointConflict:
                journal = self._read(ref)
                _require(journal is not None and SalesIntakeCandidate.model_validate(journal["candidate"]).to_dict() == candidate.to_dict()
                         and journal["playbook_digest"] == playbook.playbook_digest, "SALES_INTAKE_INTENT_CHANGED")
        runtime = self.runner.runtimes["pipeline_engine"]
        self._permission(binding, now=now)
        record = runtime.store.get("pipeline_engine", binding.prospect_ref)
        if record is None:
            fence()
            try:
                runtime.open(binding.prospect_ref, journal["opening_state"])
            except EngineStateConflictError:
                _require(runtime.store.get("pipeline_engine", binding.prospect_ref) is not None,
                         "SALES_INTAKE_OPEN_CONFLICT")
        state = self._scoped_state(runtime, binding.prospect_ref)
        _require(detached(state.transition_history[0]) == journal["opening_state"]["transition_history"][0],
                 "SALES_INTAKE_ORIGIN_MISMATCH")
        for step in journal["steps"]:
            command = step["command"]
            retained = [detached(item.command) for item in state.transition_history
                        if item.command.idempotency_key == command["idempotency_key"]]
            if retained:
                _require(retained == [command], "SALES_INTAKE_COMMAND_CHANGED")
                continue
            _require((state.version, state.state_digest) == (step["source_version"], step["source_digest"]),
                     "SALES_INTAKE_SOURCE_CHANGED")
            self._permission(binding, now=now)
            fence()
            try:
                result = runtime.advance_and_persist(binding.prospect_ref, command)
                _require(result.persisted, "SALES_INTAKE_TRANSITION_REFUSED")
            except EngineStateConflictError:
                pass
            state = self._scoped_state(runtime, binding.prospect_ref)
            _require(any(detached(item.command) == command for item in state.transition_history),
                     "SALES_INTAKE_SOURCE_CHANGED")
        summary = {"intake_ref": ref, "candidate_ref": candidate.candidate_ref, "kind": candidate.kind,
                   "prospect_ref": binding.prospect_ref, "status": state.status, "state_digest": state.state_digest,
                   "binding": binding.to_dict(), "provider_effect_executed": False, "revenue_verified": False}
        try:
            self._write(ref, {**journal, "phase": "completed", "status": "COMPLETED", "summary": summary}, journal, fence)
        except CheckpointConflict:
            current = self._read(ref)
            _require(current is not None and current.get("phase") == "completed"
                     and current.get("summary") == summary, "SALES_INTAKE_JOURNAL_CHANGED")
        return summary


__all__ = ["SalesIntakeError", "SalesUsageEvidence", "SalesIntakeCandidate", "parse_sales_intake_candidates", "CompanySalesIntake"]
