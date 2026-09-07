"""Blueprint changes mid-flight: migrate a persisted engine state from one plan to another.

Every engine state commits to the digest of the plan it runs under, and every
transition in its history is fenced by digests derived from that plan.  When a
company's blueprint is revised (a budget envelope moves, a stage is added, a
guard is tightened) an entity that is still in flight cannot simply be
re-pointed at the new plan: the core would refuse it as belonging to a
different loop plan.

``migrate_state`` replays the entity's whole retained history under the new
plan, transition by transition, through the same ``step`` function the engine
uses live.  If any historical transition would be refused under the new plan
(a tightened guard, a removed engine, a currency change) the migration is
refused with the exact rejection code and the offending version; nothing is
partially migrated.  A migration that replays cleanly yields a new
self-proving state whose ledger and status were re-derived from history, plus
a sealed ``PlanMigration`` proof that names both plan digests, both state
digests, and the per-transition re-keying.  The proof is what the store
requires to accept a same-version write under a different plan digest.

Nothing here executes an effect or reaches the platform; persisting the
migrated state goes through the engine state store's ``migrate`` fence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    LifecycleSpec,
    OpaqueRef,
    Rejected,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)
from lightbulb.company_operating_system import PERIOD_LIFECYCLE, CompanyOperatingPlan, advance_period
from lightbulb.company_workforce import WORKER_LIFECYCLE, WorkforcePlan, advance_worker
from lightbulb.finance_close_engine import CLOSE_LIFECYCLE, FinanceCloseLoopPlan, advance_period_close
from lightbulb.growth_engine_loop import CAMPAIGN_LIFECYCLE, GrowthEngineLoopPlan, advance_campaign
from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE, PipelineEngineLoopPlan, advance_prospect
from lightbulb.saas_operating_loop import RELEASE_LIFECYCLE, SaasOperatingLoopPlan, advance_release
from lightbulb.service_delivery_engine import CASE_LIFECYCLE, ServiceDeliveryLoopPlan, advance_case

MIGRATION_SCHEMA = "lightbulb.company_plan_migration.v1"
MAX_HISTORY = 4096


class MigrationRefused(ValueError):
    """The history cannot be replayed under the new plan; nothing was migrated."""

    def __init__(self, code: str, message: str, *, version: int | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.version = version


@dataclass(frozen=True)
class EngineLifecycle:
    """One engine kind's lifecycle spec, plan model, and advance function."""

    engine: str
    spec: LifecycleSpec
    plan_model: type[Any]
    advance: Callable[[Any, Any, Any], Any]


ENGINE_LIFECYCLES: dict[str, EngineLifecycle] = {
    item.engine: item
    for item in (
        EngineLifecycle("company_operating_system", PERIOD_LIFECYCLE, CompanyOperatingPlan, advance_period),
        EngineLifecycle("growth_engine", CAMPAIGN_LIFECYCLE, GrowthEngineLoopPlan, advance_campaign),
        EngineLifecycle("pipeline_engine", PROSPECT_LIFECYCLE, PipelineEngineLoopPlan, advance_prospect),
        EngineLifecycle("saas_operating_engine", RELEASE_LIFECYCLE, SaasOperatingLoopPlan, advance_release),
        EngineLifecycle("finance_close", CLOSE_LIFECYCLE, FinanceCloseLoopPlan, advance_period_close),
        EngineLifecycle("service_delivery", CASE_LIFECYCLE, ServiceDeliveryLoopPlan, advance_case),
        EngineLifecycle("company_workforce", WORKER_LIFECYCLE, WorkforcePlan, advance_worker),
    )
}


# Public registry keys are distinct from approval-engine names for modules
# with multiple entities. Resolve shared module plans through these targets.
ROUND5_LIFECYCLE_TARGETS: Mapping[str, tuple[str, str, str]] = {
    "company_cost_centres": ("company_cost_centres", "COST_REGISTER_LIFECYCLE", "advance_cost_register"),
    "payroll_run_chain": ("payroll_run_chain", "PAYROLL_LIFECYCLE", "advance_pay_run"),
    "bank_reconciliation": ("bank_reconciliation", "BANK_REC_LIFECYCLE", "advance_bank_reconciliation"),
    "subscription_chain": ("subscription_chain", "SUBSCRIPTION_CHAIN_LIFECYCLE", "advance_subscription_case"),
    "storefront_settlement_chain": ("storefront_settlement_chain", "STOREFRONT_SETTLEMENT_LIFECYCLE", "advance_settlement_batch"),
    "collections_chain": ("collections_chain", "COLLECTIONS_LIFECYCLE", "advance_receivable"),
    "spend_control_chain": ("spend_control_chain", "SPEND_LIFECYCLE", "advance_spend_item"),
    "vendor_commitment": ("spend_control_chain", "COMMITMENT_LIFECYCLE", "advance_vendor_commitment"),
    "disbursement_run": ("disbursement_run", "DISBURSEMENT_LIFECYCLE", "advance_disbursement_run"),
    "agreement_chain": ("obligation_paper", "AGREEMENT_LIFECYCLE", "advance_agreement"),
    "company_standing": ("obligation_paper", "STANDING_LIFECYCLE", "advance_standing_item"),
    "deal_desk_engine": ("deal_desk_engine", "DEAL_DESK_LIFECYCLE", "advance_deal"),
    "contact_endpoint": ("permission_register", "CONSENT_LIFECYCLE", "advance_contact_endpoint"),
    "claim_register": ("permission_register", "CLAIM_LIFECYCLE", "advance_claim"),
    "people_engine": ("people_engine", "PEOPLE_LIFECYCLE", "advance_people"),
    "marketplace_seller": ("marketplace_supply_engine", "SELLER_LIFECYCLE", "advance_seller"),
    "marketplace_listing": ("marketplace_supply_engine", "LISTING_LIFECYCLE", "advance_listing"),
    "marketplace_supply_engine": ("marketplace_supply_engine", "TRANSACTION_LIFECYCLE", "advance_transaction"),
    "engagement_engine": ("engagement_engine", "ENGAGEMENT_LIFECYCLE", "advance_engagement"),
    "wip_billing": ("wip_billing", "WIP_BILLING_LIFECYCLE", "advance_wip_invoice"),
    "payout_chain": ("payout_chain", "PAYOUT_LIFECYCLE", "advance_payout"),
    "custodial_funds": ("custodial_funds", "CUSTODY_LIFECYCLE", "advance_custody"),
    "refund_and_dispute_chain": ("refund_and_dispute_chain", "REFUND_LIFECYCLE", "advance_refund_case"),
}


INTEGRATED_LIFECYCLE_TARGETS = {"content_asset_lifecycle": ("content_asset_lifecycle", "CONTENT_ASSET_LIFECYCLE", "advance_content_asset"), "demand_envelope": ("growth_paced_envelope", "DEMAND_LIFECYCLE", "advance_demand_registry"), 'company_provisioning': ('company_provisioning', 'INSTRUMENT_LIFECYCLE', 'advance_instrument'), 'employment_chain': ('employment_chain', 'EMPLOYMENT_LIFECYCLE', 'advance_employee'), 'job_chain': ('job_chain', 'JOB_LIFECYCLE', 'advance_job'), 'wind_down_chain': ('wind_down_chain', 'WIND_DOWN_LIFECYCLE', 'advance_wind_down'), 'company_launch': ('launch_plan', 'LAUNCH_LIFECYCLE', 'advance_launch'), 'local_presence_engine': ('local_presence_engine', 'LISTING_LIFECYCLE', 'advance_listing'), 'local_presence_review': ('local_presence_engine', 'REVIEW_LIFECYCLE', 'advance_review')}


def _register_late_lifecycles() -> None:
    """Lifecycles that import this module register themselves here to avoid an import cycle."""

    from lightbulb.company_operating_memory import MEMORY_LIFECYCLE, MemoryPlan, advance_memory
    from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE, RevenueChainPlan, advance_revenue_case

    registry = dict(ENGINE_LIFECYCLES)
    registry.setdefault("revenue_chain", EngineLifecycle("revenue_chain", REVENUE_CHAIN_LIFECYCLE, RevenueChainPlan, advance_revenue_case))
    registry.setdefault("company_operating_memory", EngineLifecycle("company_operating_memory", MEMORY_LIFECYCLE, MemoryPlan, advance_memory))
    from lightbulb.compliance_calendar import COMPLIANCE_LIFECYCLE, ComplianceCalendarPlan, advance_obligation
    from lightbulb.exceptions_desk import EXCEPTIONS_LIFECYCLE, ExceptionsDeskPlan, advance_exception
    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE, PayablesChainPlan, advance_payable_case
    from lightbulb.retention_chain import RETENTION_LIFECYCLE, RetentionChainPlan, advance_renewal_case

    registry.setdefault("payables_chain", EngineLifecycle("payables_chain", PAYABLES_CHAIN_LIFECYCLE, PayablesChainPlan, advance_payable_case))
    registry.setdefault("retention_chain", EngineLifecycle("retention_chain", RETENTION_LIFECYCLE, RetentionChainPlan, advance_renewal_case))
    registry.setdefault("compliance_obligation", EngineLifecycle("compliance_obligation", COMPLIANCE_LIFECYCLE, ComplianceCalendarPlan, advance_obligation))
    registry.setdefault("exception_case", EngineLifecycle("exception_case", EXCEPTIONS_LIFECYCLE, ExceptionsDeskPlan, advance_exception))
    import importlib

    for engine, (module_name, spec_name, advance_name) in {**ROUND5_LIFECYCLE_TARGETS, **INTEGRATED_LIFECYCLE_TARGETS}.items():
        module = importlib.import_module(f"lightbulb.{module_name}")
        spec = getattr(module, spec_name)
        registry.setdefault(engine, EngineLifecycle(engine, spec, spec.plan_model, getattr(module, advance_name)))
    # Preserve references held by imported runtime callers.
    ENGINE_LIFECYCLES.update(registry)
    if "PLAN_MIGRATION_MANIFEST" in globals():
        PLAN_MIGRATION_MANIFEST["migratable_engines"] = sorted(registry)



def lifecycle_for(engine: str) -> EngineLifecycle:
    if engine not in ENGINE_LIFECYCLES:
        _register_late_lifecycles()
    lifecycle = ENGINE_LIFECYCLES.get(engine)
    if lifecycle is None:
        raise MigrationRefused("ENGINE_UNKNOWN", f"{engine!r} is not a migratable engine; known: {sorted(ENGINE_LIFECYCLES)}")
    return lifecycle


class TransitionRekey(StrictModel):
    to_version: int = Field(ge=1, le=MAX_HISTORY)
    event: ShortText
    from_transition_digest: Sha256Digest
    to_transition_digest: Sha256Digest


class PlanMigration(StrictModel):
    """Sealed proof that a state was replayed from one plan to another without loss."""

    schema_id: str = Field(default=MIGRATION_SCHEMA, alias="schema")
    entity: ShortText
    entity_ref: OpaqueRef
    from_plan_digest: Sha256Digest
    to_plan_digest: Sha256Digest
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    version: int = Field(ge=1, le=MAX_HISTORY)
    status: ShortText
    migrated_at: str
    actor_ref: OpaqueRef
    reason: BoundedText
    transition_map: tuple[TransitionRekey, ...] = Field(min_length=1, max_length=MAX_HISTORY)
    migration_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("migrated_at")
    @classmethod
    def _migrated(cls, value: str) -> str:
        return timestamp(value, field_name="migrated_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PlanMigration:
        if self.from_plan_digest == self.to_plan_digest:
            raise ValueError("a migration changes the plan digest")
        if self.from_state_digest == self.to_state_digest:
            raise ValueError("a migration changes the state digest")
        if len(self.transition_map) != self.version or [item.to_version for item in self.transition_map] != list(range(1, self.version + 1)):
            raise ValueError("transition_map must cover every retained version in order")
        if not skip_digests(info) and self.migration_digest != sealed_digest(PlanMigration, self, "migration_digest"):
            raise ValueError("migration_digest must commit the exact migration")
        return self


@dataclass(frozen=True)
class MigrationResult:
    migration: PlanMigration
    state: Any
    plan: Any


def migrate_state(spec: LifecycleSpec, *, state: Mapping[str, Any] | Any, from_plan: Mapping[str, Any] | Any, to_plan: Mapping[str, Any] | Any, migrated_at: str, actor_ref: str, reason: str) -> MigrationResult:
    """Replay ``state``'s history under ``to_plan``; refuse on the first transition the new plan would not accept."""

    migrated_at = timestamp(migrated_at, field_name="migrated_at")
    if not reason or not reason.strip():
        raise MigrationRefused("REASON_REQUIRED", "a migration records why the plan changed")
    from_parsed, bound = spec.bind(from_plan, state)
    to_parsed = spec.plan_model.model_validate(detached(to_plan))
    if to_parsed.plan_digest == from_parsed.plan_digest:
        raise MigrationRefused("PLAN_UNCHANGED", "the target plan is the plan the state already runs under")
    blueprint_currency = getattr(getattr(to_parsed, "blueprint", None), "currency", None)
    if blueprint_currency is not None and bound.scope.currency != blueprint_currency:
        raise MigrationRefused("CURRENCY_MISMATCH", f"the state is scoped in {bound.scope.currency}; the target plan runs in {blueprint_currency}")
    last_at = bound.transition_history[-1].command.occurred_at
    if parsed(migrated_at) < parsed(last_at):
        raise MigrationRefused("NON_CHRONOLOGICAL_MIGRATION", f"migrated_at precedes the last retained transition at {last_at}")

    status, ledger = "new", spec.ledger_model()
    prefix: tuple[Any, ...] = ()
    rekeys: list[TransitionRekey] = []
    for transition in bound.transition_history:
        prior = spec.state_digest(to_parsed.plan_digest, bound.scope, prefix)
        raw_command = dict(transition.command.to_dict())
        raw_command["expected_state_digest"] = prior
        raw_command.pop("request_digest", None)
        command = spec.Command.model_validate(spec.seal_command(raw_command))
        try:
            status, ledger = spec.step(to_parsed, status, ledger, command)
        except Rejected as exc:
            raise MigrationRefused("HISTORY_INCOMPATIBLE", f"transition {transition.to_version} ({command.event}) is refused under the target plan: {exc.code}", version=transition.to_version) from exc
        if status != transition.to_status:
            raise MigrationRefused("STATUS_DIVERGED", f"transition {transition.to_version} ({command.event}) lands on {status} under the target plan, not {transition.to_status}", version=transition.to_version)
        rekeyed = spec.Transition(to_version=transition.to_version, prior_state_digest=prior, to_status=status, transition_digest=spec.transition_digest(transition.to_version, prior, status, command), command=command)
        rekeys.append(TransitionRekey(to_version=transition.to_version, event=command.event, from_transition_digest=transition.transition_digest, to_transition_digest=rekeyed.transition_digest))
        prefix = (*prefix, rekeyed)

    state_digest = spec.state_digest(to_parsed.plan_digest, bound.scope, prefix)
    new_state = spec.State.model_validate(
        {"plan_digest": to_parsed.plan_digest, "scope": bound.scope.to_dict(), "status": status, "version": bound.version, "transition_history": [item.to_dict() for item in prefix], "ledger": ledger.to_dict(), "state_digest": state_digest},
        context={spec.plan_context_key: to_parsed},
    )
    migration = seal(
        PlanMigration,
        {
            "entity": spec.entity,
            "entity_ref": bound.scope.entity_ref,
            "from_plan_digest": from_parsed.plan_digest,
            "to_plan_digest": to_parsed.plan_digest,
            "from_state_digest": bound.state_digest,
            "to_state_digest": state_digest,
            "version": bound.version,
            "status": status,
            "migrated_at": migrated_at,
            "actor_ref": actor_ref,
            "reason": reason.strip(),
            "transition_map": [item.to_dict() for item in rekeys],
        },
        "migration_digest",
    )
    return MigrationResult(migration=migration, state=new_state, plan=to_parsed)


def verify_migration(spec: LifecycleSpec, migration: PlanMigration | Mapping[str, Any], *, from_state: Mapping[str, Any] | Any, to_state: Mapping[str, Any] | Any, to_plan: Mapping[str, Any] | Any) -> PlanMigration:
    """Check a proof against the states it claims to connect; raises ``MigrationRefused`` on any mismatch."""

    proof = migration if isinstance(migration, PlanMigration) else PlanMigration.model_validate(dict(detached(migration)))
    before = spec.State.model_validate(detached(from_state))
    _, after = spec.bind(to_plan, to_state)
    checks = (
        (proof.entity == spec.entity, "entity"),
        (proof.from_state_digest == before.state_digest, "from_state_digest"),
        (proof.to_state_digest == after.state_digest, "to_state_digest"),
        (proof.from_plan_digest == before.plan_digest, "from_plan_digest"),
        (proof.to_plan_digest == after.plan_digest, "to_plan_digest"),
        (proof.version == before.version == after.version, "version"),
        (proof.status == before.status == after.status, "status"),
        (str(proof.entity_ref) == str(after.scope.entity_ref), "entity_ref"),
        (all(item.from_transition_digest == old.transition_digest and item.to_transition_digest == new.transition_digest for item, old, new in zip(proof.transition_map, before.transition_history, after.transition_history, strict=True)), "transition_map"),
    )
    for ok, label in checks:
        if not ok:
            raise MigrationRefused("MIGRATION_PROOF_MISMATCH", f"the migration proof does not connect these states ({label})")
    return proof


PLAN_MIGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_plan_migration",
    "golden_loop": "company_operating_system",
    "stages": ["bind_old_plan", "replay_under_new_plan", "prove", "persist_with_fence"],
    "migratable_engines": sorted(ENGINE_LIFECYCLES),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a migration replays every retained transition through the engine's own step function under the new plan",
        "the first transition the new plan refuses aborts the migration with its rejection code; nothing is partially migrated",
        "the migrated state keeps its version and status; only plan-derived digests change and the proof maps every transition",
        "the store accepts a same-version write under a new plan digest only with a proof whose from_state_digest matches the persisted state",
    ],
}

__all__ = [
    "ENGINE_LIFECYCLES",
    "ROUND5_LIFECYCLE_TARGETS",
    "MIGRATION_SCHEMA",
    "PLAN_MIGRATION_MANIFEST",
    "EngineLifecycle",
    "MigrationRefused",
    "MigrationResult",
    "PlanMigration",
    "TransitionRekey",
    "lifecycle_for",
    "migrate_state",
    "verify_migration",
]
