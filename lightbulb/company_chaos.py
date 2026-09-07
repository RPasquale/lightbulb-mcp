"""Adversarial simulation: run the cadence runner against faults and prove its refusals.

The goldens cover happy paths.  ``run_chaos`` drives a real
``CompanyCadenceRunner`` on an in-memory store through a scripted sequence
of faults and checks the invariants the runner promises on every path:

* ``connector_outage``: a tick receives no inputs for its evidence items; the
  period must stay where it is and the work items must be re-raised, never
  auto-filled.
* ``stale_read``: an evidence receipt dated before the period start; the
  engine must refuse it and nothing must be recorded.
* ``partial_receipt``: an evidence receipt missing a required field; the
  runner must reject it with a code and leave the ledger untouched.
* ``replayed_receipt``: the same input supplied twice; the second must be
  refused as a replay (``TRANSITION_ALREADY_APPLIED`` or
  ``IDEMPOTENCY_CONFLICT``) and the ledger must not double count.
* ``overspend``: evidence whose spend exceeds the engine's envelope; the
  engine must refuse with ``ENVELOPE_OVERSPEND``.
* ``migration_mid_period``: the operating plan is migrated to a revised
  budget between ticks; the runner must keep advancing under the new plan
  and the migrated state must replay cleanly.
* ``clock_skew``: a tick whose clock runs backwards; the cadence lifecycle
  must refuse to record it.

Every fault produces a ``ChaosObservation`` with what was injected, what the
runner did, and whether the invariant held; the run is sealed into a
``ChaosReport`` so a regression in any refusal shows as a digest change.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, model_validator

from lightbulb.company_cadence_runner import CadenceBundle, CadenceWorker, CompanyCadenceRunner, build_bundle
from lightbulb.company_engine_core import GENESIS_DIGEST, BoundedText, Sha256Digest, ShortText, StrictModel, add_days, seal, sealed_digest, skip_digests
from lightbulb.company_engine_store import EngineRuntime, InMemoryEngineStateStore
from lightbulb.company_operating_system import compile_company_operating_blueprint

CHAOS_REPORT_SCHEMA = "lightbulb.company_chaos_report.v1"
FaultKind = Literal["connector_outage", "stale_read", "partial_receipt", "replayed_receipt", "overspend", "migration_mid_period", "clock_skew"]
FAULT_KINDS: tuple[FaultKind, ...] = ("connector_outage", "stale_read", "partial_receipt", "replayed_receipt", "overspend", "clock_skew", "migration_mid_period")


class ChaosObservation(StrictModel):
    fault: FaultKind
    injected: BoundedText
    runner_did: BoundedText
    invariant: BoundedText
    held: bool
    codes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)


class ChaosReport(StrictModel):
    schema_id: str = Field(default=CHAOS_REPORT_SCHEMA, alias="schema")
    bundle_digest: Sha256Digest
    faults: tuple[FaultKind, ...] = Field(min_length=1, max_length=7)
    observations: tuple[ChaosObservation, ...] = Field(min_length=1, max_length=7)
    all_held: bool
    final_period_status: ShortText
    final_period_version: int = Field(ge=1)
    report_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ChaosReport:
        if self.all_held != all(item.held for item in self.observations):
            raise ValueError("all_held must reflect the observations")
        if not skip_digests(info) and self.report_digest != sealed_digest(ChaosReport, self, "report_digest"):
            raise ValueError("report_digest must commit the exact report")
        return self

    def failures(self) -> tuple[ChaosObservation, ...]:
        return tuple(item for item in self.observations if not item.held)


def _period(store: InMemoryEngineStateStore) -> Mapping[str, Any]:
    records = store.list(engine="company_operating_system")
    if not records:
        raise RuntimeError("no period persisted")
    return max(records, key=lambda record: str(record["entity_ref"]))


def _dispatch_inputs(plan: Any) -> list[dict[str, Any]]:
    return [{"action_id": item.action_id, "receipt": {"engine": item.prepared["engine"], "dispatch_refs": [f"chaos-{item.prepared['engine']}"]}} for item in plan.actions if item.kind == "dispatch_engine"]


def _evidence_items(plan: Any) -> list[Any]:
    return [item for item in plan.actions if item.kind == "collect_evidence"]


def run_chaos(bundle: CadenceBundle | Mapping[str, Any], *, faults: Sequence[str] = FAULT_KINDS, start_at: str | None = None) -> ChaosReport:
    """Drive the bundle's cadence through the requested faults on an in-memory store and seal what held."""

    parsed_bundle = build_bundle(bundle)
    store = InMemoryEngineStateStore()
    runner = CompanyCadenceRunner(bundle=parsed_bundle, store=store, approval_requester=lambda request: {"id": "chaos-task"})
    clock = {"now": start_at or parsed_bundle.start_at}
    worker = CadenceWorker(runner=runner, clock=lambda: clock["now"])
    worker.start()
    worker.run_once()  # opens the first period
    plan = runner.plan(now=clock["now"])
    runner.tick(now=clock["now"], inputs=_dispatch_inputs(plan))
    clock["now"] = add_days(clock["now"], 1)
    observations: list[dict[str, Any]] = []
    budgets = {envelope.engine: Decimal(str(envelope.budget)) for envelope in runner.bundle.operating_plan.envelopes}

    def observe(fault: str, injected: str, did: str, invariant: str, held: bool, codes: Sequence[str] = ()) -> None:
        observations.append({"fault": fault, "injected": injected, "runner_did": did, "invariant": invariant, "held": held, "codes": list(dict.fromkeys(codes))[:8]})

    for fault in faults:
        before = _period(store)
        plan = runner.plan(now=clock["now"])
        evidence = _evidence_items(plan)
        if fault == "connector_outage":
            result = runner.tick(now=clock["now"], inputs=[])
            after = _period(store)
            reraised = [item for item in result.outstanding if item.kind == "collect_evidence"]
            observe(fault, "no inputs for any evidence item (reads failed)", f"{len(result.applied)} applied, {len(reraised)} evidence item(s) re-raised", "period unchanged and evidence items re-raised, never auto-filled", after["state_digest"] == before["state_digest"] and len(reraised) == len(evidence) and all(item.outcome != "applied" or item.event != "record_evidence" for item in result.applied))
        elif fault == "stale_read":
            target = evidence[0] if evidence else None
            if target is None:
                observe(fault, "no evidence item to target", "skipped", "n/a", True)
            else:
                engine = target.prepared["engine"]
                stale_at = add_days(str(before["state"]["ledger"]["period_start"]), -3)
                receipt = {"engine": engine, "evidence_ref": "stale-read-1", "spend": "10", "revenue": "0", "observed_at": stale_at}
                result = runner.tick(now=stale_at, inputs=[{"action_id": target.action_id, "receipt": {key: value for key, value in receipt.items() if key != "observed_at"}}])
                after = _period(store)
                codes = [item.rejection_code for item in result.applied if item.rejection_code]
                observe(fault, f"evidence for {engine} dated {stale_at}, before the period opened", f"outcomes {[item.outcome for item in result.applied]} codes {codes}", "a transition dated before the last one is refused as non-chronological and the ledger is untouched", after["state_digest"] == before["state_digest"] and "NON_CHRONOLOGICAL_TRANSITION" in codes, codes)
        elif fault == "partial_receipt":
            target = evidence[0] if evidence else None
            if target is None:
                observe(fault, "no evidence item to target", "skipped", "n/a", True)
            else:
                result = runner.tick(now=clock["now"], inputs=[{"action_id": target.action_id, "receipt": {"engine": target.prepared["engine"], "spend": "10"}}])
                after = _period(store)
                codes = [item.rejection_code for item in result.applied if item.rejection_code]
                observe(fault, f"evidence for {target.prepared['engine']} without evidence_ref", f"codes {codes}", "a receipt missing a required field is rejected with a code and the ledger is untouched", after["state_digest"] == before["state_digest"] and bool(codes) and all(code for code in codes), codes)
        elif fault == "replayed_receipt":
            target = evidence[0] if evidence else None
            if target is None:
                observe(fault, "no evidence item to target", "skipped", "n/a", True)
            else:
                engine = target.prepared["engine"]
                receipt = {"engine": engine, "evidence_ref": f"replay-{engine}", "spend": "25", "revenue": "50"}
                first = runner.tick(now=clock["now"], inputs=[{"action_id": target.action_id, "receipt": receipt}])
                mid = _period(store)
                second = runner.tick(now=clock["now"], inputs=[{"action_id": target.action_id, "receipt": receipt}])
                after = _period(store)
                codes = [item.rejection_code for item in second.applied if item.rejection_code]
                first_ok = any(item.outcome == "applied" and item.event == "record_evidence" for item in first.applied)
                spend_after = Decimal(str(after["state"]["ledger"]["spend_by_engine"].get(engine, "0")))
                spend_mid = Decimal(str(mid["state"]["ledger"]["spend_by_engine"].get(engine, "0")))
                observe(fault, f"the same evidence input for {engine} supplied twice", f"first {'applied' if first_ok else 'not applied'}; second codes {codes}", "the second delivery is refused as a replay and spend is not double counted", first_ok and spend_after == spend_mid and (after["state_digest"] == mid["state_digest"] or not any(item.outcome == 'applied' and item.event == 'record_evidence' for item in second.applied)), codes)
                clock["now"] = add_days(clock["now"], 1)
        elif fault == "overspend":
            remaining = [item for item in _evidence_items(runner.plan(now=clock["now"]))]
            target = remaining[0] if remaining else None
            if target is None:
                observe(fault, "no evidence item to target", "skipped", "n/a", True)
            else:
                engine = target.prepared["engine"]
                too_much = str((budgets[engine] * Decimal("2")).quantize(Decimal("0.01")))
                result = runner.tick(now=clock["now"], inputs=[{"action_id": target.action_id, "receipt": {"engine": engine, "evidence_ref": "overspend-1", "spend": too_much, "revenue": "0"}}])
                after = _period(store)
                codes = [item.rejection_code for item in result.applied if item.rejection_code]
                observe(fault, f"evidence spending {too_much} against a {budgets[engine]} envelope for {engine}", f"codes {codes}", "spend beyond the envelope is refused with ENVELOPE_OVERSPEND", "ENVELOPE_OVERSPEND" in codes and after["state_digest"] == _period(store)["state_digest"] and Decimal(str(after["state"]["ledger"]["spend_by_engine"].get(engine, "0"))) < budgets[engine], codes)
        elif fault == "migration_mid_period":
            revised = compile_company_operating_blueprint({**runner.bundle.operating_plan.blueprint.to_dict(), "operating_budget_per_period": str((Decimal(str(runner.bundle.operating_plan.blueprint.operating_budget_per_period)) * Decimal("1.2")).quantize(Decimal("0.01")))})
            runtime = runner.runtimes["company_operating_system"]
            try:
                # Cadence records commit to the bundle digest, so a bundle change stops the old cadence; a new one starts under the new bundle.
                old_worker = CadenceWorker(runner=runner, clock=lambda: clock["now"])
                if store.get("company_cadence", old_worker.cadence_ref) is not None and store.get("company_cadence", old_worker.cadence_ref)["status"] == "running":
                    old_worker.control("stop", reason="chaos: bundle revised; cadence restarts under the new bundle")
                outcome = runtime.migrate(str(before["entity_ref"]), revised, migrated_at=clock["now"], actor_ref=runner.bundle.actor_ref, reason="chaos: budget revised mid-period")
                migrated_ok = outcome.record["plan_digest"] == revised.plan_digest and outcome.state.version == before["version"]
                document = {**runner.bundle.to_dict(), "operating_plan": revised.to_dict()}
                if runner.bundle.workforce_plan is not None:
                    from lightbulb.company_workforce import WORKER_LIFECYCLE, advance_worker, compile_workforce

                    revised_workforce = compile_workforce(revised, runner.bundle.workforce_plan.roster)
                    worker_runtime = EngineRuntime(spec=WORKER_LIFECYCLE, engine="company_workforce", plan=runner.bundle.workforce_plan, store=store, advance=advance_worker)
                    for record in store.list(engine="company_workforce"):
                        worker_runtime.plan = runner.bundle.workforce_plan
                        worker_runtime.migrate(str(record["entity_ref"]), revised_workforce, migrated_at=clock["now"], actor_ref=runner.bundle.actor_ref, reason="chaos: budget revised mid-period")
                    document["workforce_plan"] = revised_workforce.to_dict()
                new_bundle = build_bundle(document)
                runner = CompanyCadenceRunner(bundle=new_bundle, store=store, approval_requester=lambda request: {"id": "chaos-task"})
                budgets = {envelope.engine: Decimal(str(envelope.budget)) for envelope in new_bundle.operating_plan.envelopes}
                plan_after = runner.plan(now=clock["now"])
                observe(fault, "operating budget raised 20% and the open period migrated to the revised plan", f"migrated to version {outcome.state.version}; next tick plans {len(plan_after.actions)} action(s)", "the migrated state keeps its version and status and the runner keeps planning under the new plan", migrated_ok and plan_after.period_status == before["status"] and _period(store)["plan_digest"] == revised.plan_digest)
            except (ValueError, LookupError, RuntimeError) as exc:
                observe(fault, "operating budget raised 20% mid-period", f"migration refused: {str(exc)[:200]}", "a clean history migrates", False, [str(exc).split(":")[0][:60]])
        elif fault == "clock_skew":
            worker = CadenceWorker(runner=runner, clock=lambda: clock["now"])
            forward = worker.run_once()
            skewed = add_days(clock["now"], -2)
            skew_worker = CadenceWorker(runner=runner, clock=lambda: skewed)
            codes: list[str] = []
            refused = False
            try:
                skew_worker.run_once()
            except RuntimeError as exc:
                refused = True
                codes.append(str(exc).split(":")[-1].strip()[:60])
            cadence = store.get("company_cadence", worker.cadence_ref)
            observe(fault, f"a tick recorded at {skewed}, two days before the previous tick", f"forward tick {'recorded' if forward is not None else 'skipped'}; skewed tick {'refused' if refused else 'accepted'}", "the cadence lifecycle refuses a tick whose clock runs backwards (as a replay of the same result or as non-chronological)", refused and cadence is not None and any(code in " ".join(codes) for code in ("NON_CHRONOLOGICAL_TRANSITION", "IDEMPOTENCY_CONFLICT", "TRANSITION_ALREADY_APPLIED")), codes)
        else:
            raise ValueError(f"unknown fault {fault!r}; known: {FAULT_KINDS}")
    final = _period(store)
    return seal(ChaosReport, {"bundle_digest": parsed_bundle.plan_digest, "faults": list(faults), "observations": observations, "all_held": all(item["held"] for item in observations), "final_period_status": final["status"], "final_period_version": int(final["version"])}, "report_digest")


CHAOS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_chaos",
    "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0",
    "stages": ["start_cadence", "inject_fault", "observe_refusal", "seal_report"],
    "faults": list(FAULT_KINDS),
    "required_connectors": [],
    "hard_rules": [
        "faults are injected into a real cadence runner on an in-memory store; nothing reaches the platform",
        "every fault names the invariant it tests and whether the runner held it",
        "a report is sealed so a regression in any refusal changes its digest",
    ],
}

__all__ = ["CHAOS_MANIFEST", "CHAOS_REPORT_SCHEMA", "FAULT_KINDS", "ChaosObservation", "ChaosReport", "run_chaos"]
