"""Prepare a controlled period-close consolidation package candidate.

The primitive binds a reviewed consolidation workpaper to the exact retained
version-five period-close snapshot. It derives entity, currency, and prior
transition fences instead of accepting them from a caller. For the initial
single-entity lighthouse it proves an explicit no-intercompany-activity stage;
the same contract also validates balanced elimination entries for a future
consolidation-group workspace. Spring still owns actor authentication, evidence
custody, elimination settlement, persistence, and lifecycle admission. No
connector, provider, ledger, or journal effect occurs here.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.finance_close_lifecycle import (
    ConsolidationPackage,
    EliminationEntry,
    Money,
    PeriodCloseLifecycleSnapshot,
    materialize_period_close_candidate,
)
from lightbulb.finance_close_workspace import FinanceCloseWorkspace
from lightbulb.finance_subledger_lock_transition import (
    PrepareSubledgerLockTransitionCommandInput,
    PrepareSubledgerLockTransitionCommandPrimitive,
    prepare_subledger_lock_transition_command,
)
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

CONSOLIDATION_PACKAGE_CANDIDATE_INPUT_SCHEMA = (
    "lightbulb.finance_consolidation_package_candidate_input.v1"
)
CONSOLIDATION_PACKAGE_CANDIDATE_RESULT_SCHEMA = (
    "lightbulb.finance_consolidation_package_candidate_result.v1"
)

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field_name} must be a trimmed UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class PrepareConsolidationPackageInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_consolidation_package_candidate_input.v1"] = (
        Field(default=CONSOLIDATION_PACKAGE_CANDIDATE_INPUT_SCHEMA, alias="schema")
    )
    workspace: FinanceCloseWorkspace
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot
    consolidation_workpaper_ref: OpaqueRef
    evidence_use_refs: tuple[OpaqueRef, OpaqueRef]
    no_intercompany_activity: bool
    elimination_entries: tuple[EliminationEntry, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
    )
    intercompany_input_balance: Money
    eliminated_amount: Money
    residual_balance: Money
    residual_materiality_threshold: Money
    consolidated_at: str
    prepared_at: str
    consolidator_ref: OpaqueRef
    reviewed_by_ref: OpaqueRef

    @field_validator("workspace", "lifecycle_snapshot", mode="before")
    @classmethod
    def _detached_sources(cls, value: Any, info: Any) -> Any:
        model_type: type[BaseModel] = {
            "workspace": FinanceCloseWorkspace,
            "lifecycle_snapshot": PeriodCloseLifecycleSnapshot,
        }[info.field_name]
        if isinstance(value, model_type):
            return value
        if isinstance(value, dict):
            return model_type.model_validate_json(json.dumps(value, default=str))
        return value

    @field_validator("evidence_use_refs", mode="before")
    @classmethod
    def _evidence_refs_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("elimination_entries", mode="before")
    @classmethod
    def _canonical_entries(cls, value: Any) -> Any:
        values = tuple(value) if isinstance(value, list) else value
        if isinstance(values, tuple):
            return tuple(
                sorted(
                    values,
                    key=lambda item: (
                        item.elimination_ref
                        if isinstance(item, EliminationEntry)
                        else str(item["elimination_ref"])
                    ),
                )
            )
        return values

    @field_validator("consolidated_at", "prepared_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _exact_locked_sources(self) -> "PrepareConsolidationPackageInput":
        workspace = self.workspace
        snapshot = self.lifecycle_snapshot
        scope = workspace.close_scope
        if (
            snapshot.scope != scope
            or snapshot.version != 5
            or snapshot.status != "subledger_locks_validated"
            or snapshot.period_open != workspace.open_period_package
            or snapshot.trial_balance != workspace.trial_balance_package
            or snapshot.reconciliations is None
            or snapshot.adjusting_entries is None
            or snapshot.subledger_locks is None
            or snapshot.consolidation is not None
        ):
            raise ValueError("the exact retained subledger-lock snapshot is required")
        if (
            tuple(sorted(self.evidence_use_refs)) != self.evidence_use_refs
            or len(set(self.evidence_use_refs)) != 2
        ):
            raise ValueError(
                "exactly two canonical evidence use references are required"
            )
        if self.consolidator_ref == self.reviewed_by_ref:
            raise ValueError("consolidation preparer and reviewer must be distinct")
        if _parsed_timestamp(self.consolidated_at) < _parsed_timestamp(
            snapshot.subledger_locks.locked_at
        ):
            raise ValueError("consolidation cannot precede subledger locking")
        if _parsed_timestamp(self.consolidated_at) > _parsed_timestamp(
            self.prepared_at
        ):
            raise ValueError("consolidation cannot postdate package preparation")
        if self.residual_materiality_threshold > scope.materiality_threshold:
            raise ValueError("consolidation threshold exceeds scoped materiality")
        scoped_entities = set(scope.entity_refs)
        trial_accounts = {line.account_ref for line in snapshot.trial_balance.lines}
        if any(
            entry.from_entity_ref not in scoped_entities
            or entry.to_entity_ref not in scoped_entities
            or entry.currency != scope.functional_currency
            for entry in self.elimination_entries
        ):
            raise ValueError(
                "elimination entries must retain exact entity and currency scope"
            )
        if any(
            line.account_ref not in trial_accounts
            for entry in self.elimination_entries
            for line in entry.lines
        ):
            raise ValueError(
                "elimination entry references an account outside trial balance"
            )
        line_refs = [
            line.line_ref for entry in self.elimination_entries for line in entry.lines
        ]
        if len(line_refs) != len(set(line_refs)):
            raise ValueError("elimination line references must be globally unique")
        if scope.scope_kind == "entity" and (
            not self.no_intercompany_activity
            or self.elimination_entries
            or any(
                amount != Decimal(0)
                for amount in (
                    self.intercompany_input_balance,
                    self.eliminated_amount,
                    self.residual_balance,
                )
            )
        ):
            raise ValueError(
                "single-entity consolidation must report exact zero intercompany activity"
            )
        return self


class ConsolidationPackageCandidateResult(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_consolidation_package_candidate_result.v1"
    ] = Field(default=CONSOLIDATION_PACKAGE_CANDIDATE_RESULT_SCHEMA, alias="schema")
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    lifecycle_version: Literal[5] = 5
    lifecycle_state_digest: Sha256Digest
    adjustment_transition_digest: Sha256Digest
    lock_transition_digest: Sha256Digest
    prepared_at: str
    package: ConsolidationPackage
    package_digest: Sha256Digest
    elimination_entry_digests: tuple[Sha256Digest, ...] = Field(max_length=1_000)
    candidate_digest: Sha256Digest = _ZERO_DIGEST
    elimination_settlement_state: Literal[
        "not_applicable", "spring_revalidation_required"
    ]
    actor_identity_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    evidence_custody_state: Literal["spring_retention_required"] = (
        "spring_retention_required"
    )
    consolidation_package_authority: Literal[False] = False
    elimination_posting_authority: Literal[False] = False
    lifecycle_transition_authority: Literal[False] = False
    persistence_authorized: Literal[False] = False

    @field_validator("prepared_at")
    @classmethod
    def _prepared_at(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    @field_validator("elimination_entry_digests", mode="before")
    @classmethod
    def _digests_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _sealed_candidate(self) -> "ConsolidationPackageCandidateResult":
        if self.package_digest != _stable_digest(self.package.to_dict()):
            raise ValueError(
                "package_digest must commit the exact consolidation package"
            )
        if len(self.elimination_entry_digests) != len(self.package.elimination_entries):
            raise ValueError(
                "elimination entry digests must exactly match package entries"
            )
        expected_settlement = (
            "not_applicable"
            if self.package.no_intercompany_activity
            else "spring_revalidation_required"
        )
        if self.elimination_settlement_state != expected_settlement:
            raise ValueError("elimination settlement state must match package activity")
        expected = _stable_digest(self.digest_payload())
        if self.candidate_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("candidate_digest does not match consolidation evidence")
        object.__setattr__(self, "candidate_digest", expected)
        return self


def prepare_consolidation_package(
    inputs: PrepareConsolidationPackageInput,
) -> ConsolidationPackageCandidateResult:
    workspace = inputs.workspace
    snapshot = inputs.lifecycle_snapshot
    adjustment_transition = snapshot.transition_history[3]
    lock_transition = snapshot.transition_history[4]
    package = ConsolidationPackage(
        evidence_use_refs=inputs.evidence_use_refs,
        consolidation_workpaper_ref=inputs.consolidation_workpaper_ref,
        adjustment_transition_digest=adjustment_transition.transition_digest,
        lock_transition_digest=lock_transition.transition_digest,
        entity_refs=workspace.close_scope.entity_refs,
        currency=workspace.close_scope.functional_currency,
        no_intercompany_activity=inputs.no_intercompany_activity,
        elimination_entries=inputs.elimination_entries,
        intercompany_input_balance=inputs.intercompany_input_balance,
        eliminated_amount=inputs.eliminated_amount,
        residual_balance=inputs.residual_balance,
        residual_materiality_threshold=inputs.residual_materiality_threshold,
        consolidated_at=inputs.consolidated_at,
        consolidator_ref=inputs.consolidator_ref,
        reviewed_by_ref=inputs.reviewed_by_ref,
    )
    return ConsolidationPackageCandidateResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        lifecycle_state_digest=snapshot.state_digest,
        adjustment_transition_digest=adjustment_transition.transition_digest,
        lock_transition_digest=lock_transition.transition_digest,
        prepared_at=inputs.prepared_at,
        package=package,
        package_digest=_stable_digest(package.to_dict()),
        elimination_entry_digests=tuple(
            _stable_digest(entry.to_dict()) for entry in inputs.elimination_entries
        ),
        elimination_settlement_state=(
            "not_applicable"
            if inputs.no_intercompany_activity
            else "spring_revalidation_required"
        ),
    )


def _example_inputs() -> dict[str, Any]:
    lock_inputs = PrepareSubledgerLockTransitionCommandInput.model_validate(
        deepcopy(PrepareSubledgerLockTransitionCommandPrimitive.example_inputs)
    )
    lock_command = prepare_subledger_lock_transition_command(lock_inputs)
    lifecycle = materialize_period_close_candidate(lock_command.lifecycle_input)
    if lifecycle.snapshot is None:  # pragma: no cover - invariant guard
        raise RuntimeError("example subledger-lock transition was not materialized")
    return {
        "workspace": lock_inputs.workspace.to_dict(),
        "lifecycle_snapshot": lifecycle.snapshot.to_dict(),
        "consolidation_workpaper_ref": "consolidation-workpaper:2026-08",
        "evidence_use_refs": (
            "evidence-use:consolidation-workpaper",
            "evidence-use:intercompany-elimination-attestation",
        ),
        "no_intercompany_activity": True,
        "elimination_entries": (),
        "intercompany_input_balance": "0.00",
        "eliminated_amount": "0.00",
        "residual_balance": "0.00",
        "residual_materiality_threshold": str(
            lock_inputs.workspace.close_scope.materiality_threshold
        ),
        "consolidated_at": "2026-09-01T14:10:00Z",
        "prepared_at": "2026-09-01T14:12:00Z",
        "consolidator_ref": "controller:consolidation-preparer",
        "reviewed_by_ref": "reviewer:consolidation-controller",
    }


class PrepareConsolidationPackagePrimitive(
    BusinessProcessPrimitive[
        PrepareConsolidationPackageInput,
        ConsolidationPackageCandidateResult,
    ]
):
    primitive_ref = "finance.prepare_consolidation_package"
    version = "1.0.0"
    title = "Prepare controlled consolidation package candidate"
    description = (
        "Validate exact no-activity or balanced intercompany-elimination workpaper "
        "facts against retained subledger locks before preparing a ConsolidationPackage "
        "candidate without posting eliminations or advancing period close."
    )
    input_model = PrepareConsolidationPackageInput
    output_model = ConsolidationPackageCandidateResult
    connector_tools = ()
    risk_level = "high"
    approval_required = False
    example_inputs = _example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["effect_boundary"] = {
            "connector_operations": 0,
            "provider_calls": 0,
            "journal_posts": 0,
            "elimination_posts": 0,
            "review_decisions": 0,
            "evidence_writes": 0,
            "lifecycle_transitions": 0,
            "persistence_writes": 0,
        }
        contract["consolidation_evidence"] = (
            "exact retained lock state plus canonical workpaper arithmetic; Spring "
            "authentication, elimination settlement, and retention remain required"
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PrepareConsolidationPackageInput,
    ) -> PrimitiveExecutionResult[ConsolidationPackageCandidateResult]:
        scope = inputs.workspace.close_scope
        if (
            context.scope.tenant_ref != scope.tenant_ref
            or context.scope.company_ref != scope.company_ref
            or context.scope.project_ref != scope.project_ref
            or context.scope.project_id != scope.project_id
        ):
            blocker = PrimitiveBlocker(
                code="consolidation_package_scope_mismatch",
                message=(
                    "The workspace tenant, company, project, and project UUID must "
                    "exactly match the active runtime scope."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        output = prepare_consolidation_package(inputs)
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Prepared a structural consolidation package candidate; Spring actor, "
                "elimination-settlement, evidence, and lifecycle authority remain."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.consolidation_package_candidate_prepared",
                    payload={
                        "workspace_ref": output.workspace_ref,
                        "consolidation_workpaper_ref": (
                            output.package.consolidation_workpaper_ref
                        ),
                        "entity_count": len(output.package.entity_refs),
                        "elimination_entry_count": len(
                            output.package.elimination_entries
                        ),
                        "package_digest": output.package_digest,
                        "candidate_digest": output.candidate_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_consolidation_package_candidate",
                    summary=(
                        "Exact entity, currency, lock-transition, workpaper, and "
                        "elimination arithmetic are structurally bound."
                    ),
                    labels=[
                        "monthly_close",
                        "structural_candidate_only",
                        "spring_elimination_revalidation_required",
                    ],
                    refs={"candidate_digest": output.candidate_digest},
                )
            ],
        )


FINANCE_CONSOLIDATION_PACKAGE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (PrepareConsolidationPackagePrimitive(),)


__all__ = [
    "CONSOLIDATION_PACKAGE_CANDIDATE_INPUT_SCHEMA",
    "CONSOLIDATION_PACKAGE_CANDIDATE_RESULT_SCHEMA",
    "ConsolidationPackageCandidateResult",
    "FINANCE_CONSOLIDATION_PACKAGE_EXECUTABLE_PRIMITIVES",
    "PrepareConsolidationPackageInput",
    "PrepareConsolidationPackagePrimitive",
    "prepare_consolidation_package",
]
