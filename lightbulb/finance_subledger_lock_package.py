"""Prepare a controlled period-close subledger-lock package candidate.

The primitive binds one exact reported lock observation for every scoped
subledger to the retained version-four period-close snapshot. It derives the
existing ``SubledgerLockPackage`` transition digests and completion time while
leaving lock-state authentication, actor authority, evidence custody,
persistence, and lifecycle admission to Spring. No connector, provider, ledger,
or subledger effect occurs here.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
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

from lightbulb.finance_adjusting_entries_transition import (
    PrepareAdjustingEntriesTransitionCommandInput,
    PrepareAdjustingEntriesTransitionCommandPrimitive,
    prepare_adjusting_entries_transition_command,
)
from lightbulb.finance_close_lifecycle import (
    PeriodCloseLifecycleSnapshot,
    SubledgerLockPackage,
    materialize_period_close_candidate,
)
from lightbulb.finance_close_workspace import FinanceCloseWorkspace
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

SUBLEDGER_LOCK_PACKAGE_CANDIDATE_INPUT_SCHEMA = (
    "lightbulb.finance_subledger_lock_package_candidate_input.v1"
)
SUBLEDGER_LOCK_PACKAGE_CANDIDATE_RESULT_SCHEMA = (
    "lightbulb.finance_subledger_lock_package_candidate_result.v1"
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


class SubledgerLockObservation(_StrictModel):
    subledger_ref: OpaqueRef
    control_account_ref: OpaqueRef
    lock_record_ref: OpaqueRef
    source_revision_ref: OpaqueRef
    evidence_ref: OpaqueRef
    issuer_ref: OpaqueRef
    lock_receipt_digest: Sha256Digest
    lock_state: Literal["reported_locked"] = "reported_locked"
    locked_at: str
    observed_at: str
    locked_by_ref: OpaqueRef

    @field_validator("locked_at", "observed_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _observation_is_causal(self) -> "SubledgerLockObservation":
        if _parsed_timestamp(self.observed_at) < _parsed_timestamp(self.locked_at):
            raise ValueError("subledger lock observation cannot predate its lock fact")
        return self

    def evidence_digest(self) -> str:
        return _stable_digest(self.to_dict())


class PrepareSubledgerLockPackageInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_subledger_lock_package_candidate_input.v1"
    ] = Field(default=SUBLEDGER_LOCK_PACKAGE_CANDIDATE_INPUT_SCHEMA, alias="schema")
    workspace: FinanceCloseWorkspace
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot
    lock_set_ref: OpaqueRef
    evidence_use_refs: tuple[OpaqueRef, OpaqueRef]
    lock_observations: tuple[SubledgerLockObservation, ...] = Field(
        min_length=1, max_length=100
    )
    prepared_at: str
    lock_owner_ref: OpaqueRef
    lock_reviewer_ref: OpaqueRef

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

    @field_validator("lock_observations", mode="before")
    @classmethod
    def _canonical_observations(cls, value: Any) -> Any:
        values = tuple(value) if isinstance(value, list) else value
        if isinstance(values, tuple):
            return tuple(
                sorted(
                    values,
                    key=lambda item: (
                        item.subledger_ref
                        if isinstance(item, SubledgerLockObservation)
                        else str(item["subledger_ref"])
                    ),
                )
            )
        return values

    @field_validator("prepared_at")
    @classmethod
    def _prepared_at(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    @model_validator(mode="after")
    def _exact_adjusted_sources(self) -> "PrepareSubledgerLockPackageInput":
        workspace = self.workspace
        snapshot = self.lifecycle_snapshot
        scope = workspace.close_scope
        if (
            snapshot.scope != scope
            or snapshot.version != 4
            or snapshot.status != "adjustments_validated"
            or snapshot.period_open != workspace.open_period_package
            or snapshot.trial_balance != workspace.trial_balance_package
            or snapshot.reconciliations is None
            or snapshot.adjusting_entries is None
        ):
            raise ValueError("the exact retained adjustments snapshot is required")
        if (
            tuple(sorted(self.evidence_use_refs)) != self.evidence_use_refs
            or len(set(self.evidence_use_refs)) != 2
        ):
            raise ValueError(
                "exactly two canonical evidence use references are required"
            )
        if self.lock_owner_ref == self.lock_reviewer_ref:
            raise ValueError("subledger lock owner and reviewer must be distinct")
        expected_pairs = tuple(
            (item.subledger_ref, item.control_account_ref)
            for item in scope.required_subledgers
        )
        actual_pairs = tuple(
            (item.subledger_ref, item.control_account_ref)
            for item in self.lock_observations
        )
        if actual_pairs != expected_pairs:
            raise ValueError(
                "every exact scoped subledger and control account must be reported locked"
            )
        if any(
            item.issuer_ref not in scope.authorized_evidence_issuer_refs
            for item in self.lock_observations
        ):
            raise ValueError("subledger lock observation issuer is not scoped")
        if any(
            item.locked_by_ref != self.lock_owner_ref for item in self.lock_observations
        ):
            raise ValueError("every lock observation must bind the exact lock owner")
        count = len(self.lock_observations)
        identities = (
            {item.lock_record_ref for item in self.lock_observations},
            {item.source_revision_ref for item in self.lock_observations},
            {item.evidence_ref for item in self.lock_observations},
            {item.lock_receipt_digest for item in self.lock_observations},
        )
        if any(len(values) != count for values in identities):
            raise ValueError("subledger lock evidence identities must be unique")
        adjustment_time = _parsed_timestamp(
            snapshot.adjusting_entries.reported_posted_at
        )
        prepared_time = _parsed_timestamp(self.prepared_at)
        for item in self.lock_observations:
            locked_time = _parsed_timestamp(item.locked_at)
            observed_time = _parsed_timestamp(item.observed_at)
            if locked_time < adjustment_time:
                raise ValueError(
                    "subledger lock cannot precede adjustment posting evidence"
                )
            if observed_time > prepared_time:
                raise ValueError(
                    "subledger lock observation cannot postdate package preparation"
                )
        return self


class SubledgerLockPackageCandidateResult(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_subledger_lock_package_candidate_result.v1"
    ] = Field(default=SUBLEDGER_LOCK_PACKAGE_CANDIDATE_RESULT_SCHEMA, alias="schema")
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    lifecycle_version: Literal[4] = 4
    lifecycle_state_digest: Sha256Digest
    reconciliation_transition_digest: Sha256Digest
    adjustment_transition_digest: Sha256Digest
    prepared_at: str
    package: SubledgerLockPackage
    package_digest: Sha256Digest
    lock_observation_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1, max_length=100
    )
    candidate_digest: Sha256Digest = _ZERO_DIGEST
    lock_state_authentication: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    actor_identity_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    evidence_custody_state: Literal["spring_retention_required"] = (
        "spring_retention_required"
    )
    subledger_lock_package_authority: Literal[False] = False
    lifecycle_transition_authority: Literal[False] = False
    persistence_authorized: Literal[False] = False

    @field_validator("prepared_at")
    @classmethod
    def _prepared_at(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    @field_validator("lock_observation_digests", mode="before")
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
    def _sealed_candidate(self) -> "SubledgerLockPackageCandidateResult":
        if self.package_digest != _stable_digest(self.package.to_dict()):
            raise ValueError(
                "package_digest must commit the exact subledger lock package"
            )
        if len(self.lock_observation_digests) != len(
            self.package.locked_subledger_refs
        ):
            raise ValueError(
                "lock observation digests must exactly match locked subledgers"
            )
        expected = _stable_digest(self.digest_payload())
        if self.candidate_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("candidate_digest does not match subledger lock evidence")
        object.__setattr__(self, "candidate_digest", expected)
        return self


def prepare_subledger_lock_package(
    inputs: PrepareSubledgerLockPackageInput,
) -> SubledgerLockPackageCandidateResult:
    snapshot = inputs.lifecycle_snapshot
    workspace = inputs.workspace
    reconciliation_transition = snapshot.transition_history[2]
    adjustment_transition = snapshot.transition_history[3]
    locked_at = max(
        inputs.lock_observations,
        key=lambda item: _parsed_timestamp(item.locked_at),
    ).locked_at
    package = SubledgerLockPackage(
        evidence_use_refs=inputs.evidence_use_refs,
        lock_set_ref=inputs.lock_set_ref,
        reconciliation_transition_digest=reconciliation_transition.transition_digest,
        adjustment_transition_digest=adjustment_transition.transition_digest,
        locked_subledger_refs=tuple(
            item.subledger_ref for item in inputs.lock_observations
        ),
        locked_at=locked_at,
        lock_owner_ref=inputs.lock_owner_ref,
        lock_reviewer_ref=inputs.lock_reviewer_ref,
    )
    return SubledgerLockPackageCandidateResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        lifecycle_state_digest=snapshot.state_digest,
        reconciliation_transition_digest=reconciliation_transition.transition_digest,
        adjustment_transition_digest=adjustment_transition.transition_digest,
        prepared_at=inputs.prepared_at,
        package=package,
        package_digest=_stable_digest(package.to_dict()),
        lock_observation_digests=tuple(
            item.evidence_digest() for item in inputs.lock_observations
        ),
    )


def _example_inputs() -> dict[str, Any]:
    adjustment_inputs = PrepareAdjustingEntriesTransitionCommandInput.model_validate(
        deepcopy(PrepareAdjustingEntriesTransitionCommandPrimitive.example_inputs)
    )
    adjustment_command = prepare_adjusting_entries_transition_command(adjustment_inputs)
    lifecycle = materialize_period_close_candidate(adjustment_command.lifecycle_input)
    if lifecycle.snapshot is None:  # pragma: no cover - invariant guard
        raise RuntimeError("example adjusting-entries transition was not materialized")
    return {
        "workspace": adjustment_inputs.workspace.to_dict(),
        "lifecycle_snapshot": lifecycle.snapshot.to_dict(),
        "lock_set_ref": "subledger-lock-set:2026-08",
        "evidence_use_refs": (
            "evidence-use:subledger-lock-attestation",
            "evidence-use:subledger-lock-record",
        ),
        "lock_observations": (
            {
                "subledger_ref": "stripe:settlements",
                "control_account_ref": "quickbooks-account:cash",
                "lock_record_ref": "subledger-lock:stripe:settlements:2026-08",
                "source_revision_ref": "stripe-balance-ledger:2026-08:final",
                "evidence_ref": "evidence:subledger-lock:stripe:settlements:2026-08",
                "issuer_ref": "controller:independent-review",
                "lock_receipt_digest": _stable_digest(
                    {
                        "subledger_ref": "stripe:settlements",
                        "period_ref": "fiscal-period:2026-08",
                        "state": "locked",
                    }
                ),
                "locked_at": "2026-09-01T13:50:00Z",
                "observed_at": "2026-09-01T13:52:00Z",
                "locked_by_ref": "operator:subledger-lock-owner",
            },
        ),
        "prepared_at": "2026-09-01T13:55:00Z",
        "lock_owner_ref": "operator:subledger-lock-owner",
        "lock_reviewer_ref": "reviewer:subledger-lock-controller",
    }


class PrepareSubledgerLockPackagePrimitive(
    BusinessProcessPrimitive[
        PrepareSubledgerLockPackageInput,
        SubledgerLockPackageCandidateResult,
    ]
):
    primitive_ref = "finance.prepare_subledger_lock_package"
    version = "1.0.0"
    title = "Prepare controlled subledger-lock package candidate"
    description = (
        "Validate one exact reported lock observation for every scoped subledger "
        "before preparing a SubledgerLockPackage candidate without authenticating "
        "lock state or advancing the period-close lifecycle."
    )
    input_model = PrepareSubledgerLockPackageInput
    output_model = SubledgerLockPackageCandidateResult
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
            "subledger_locks": 0,
            "review_decisions": 0,
            "evidence_writes": 0,
            "lifecycle_transitions": 0,
            "persistence_writes": 0,
        }
        contract["lock_evidence"] = (
            "one exact causal receipt per scoped subledger and control account; "
            "Spring authentication and current-state revalidation remain required"
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PrepareSubledgerLockPackageInput,
    ) -> PrimitiveExecutionResult[SubledgerLockPackageCandidateResult]:
        scope = inputs.workspace.close_scope
        if (
            context.scope.tenant_ref != scope.tenant_ref
            or context.scope.company_ref != scope.company_ref
            or context.scope.project_ref != scope.project_ref
            or context.scope.project_id != scope.project_id
        ):
            blocker = PrimitiveBlocker(
                code="subledger_lock_package_scope_mismatch",
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
        output = prepare_subledger_lock_package(inputs)
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Prepared a structural subledger-lock package candidate; Spring lock "
                "authentication, actor, evidence, and lifecycle authority remain."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.subledger_lock_package_candidate_prepared",
                    payload={
                        "workspace_ref": output.workspace_ref,
                        "lock_set_ref": output.package.lock_set_ref,
                        "locked_subledger_count": len(
                            output.package.locked_subledger_refs
                        ),
                        "package_digest": output.package_digest,
                        "candidate_digest": output.candidate_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_subledger_lock_package_candidate",
                    summary=(
                        "Every scoped subledger and control account is structurally "
                        "bound to a distinct causal lock observation."
                    ),
                    labels=[
                        "monthly_close",
                        "structural_candidate_only",
                        "spring_lock_revalidation_required",
                    ],
                    refs={"candidate_digest": output.candidate_digest},
                )
            ],
        )


FINANCE_SUBLEDGER_LOCK_PACKAGE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (PrepareSubledgerLockPackagePrimitive(),)


__all__ = [
    "FINANCE_SUBLEDGER_LOCK_PACKAGE_EXECUTABLE_PRIMITIVES",
    "PrepareSubledgerLockPackageInput",
    "PrepareSubledgerLockPackagePrimitive",
    "SUBLEDGER_LOCK_PACKAGE_CANDIDATE_INPUT_SCHEMA",
    "SUBLEDGER_LOCK_PACKAGE_CANDIDATE_RESULT_SCHEMA",
    "SubledgerLockObservation",
    "SubledgerLockPackageCandidateResult",
    "prepare_subledger_lock_package",
]
