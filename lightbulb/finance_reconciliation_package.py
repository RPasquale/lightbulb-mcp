"""Prepare a structural period-close ReconciliationPackage candidate.

The candidate binds reviewed account and subledger ending-balance records to a
sealed close workspace and an exact reconciliation-readiness result. Reviewer
identities remain unauthenticated claims until Spring revalidates RBAC and
retains the two required evidence envelopes. No lifecycle transition occurs.
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
    AccountReconciliationRecord,
    ReconciliationPackage,
    SubledgerReconciliationRecord,
)
from lightbulb.finance_close_reconciliation_readiness import (
    CloseReconciliationReadinessResult,
)
from lightbulb.finance_close_workspace import (
    FinanceCloseChecklistItem,
    FinanceCloseWorkspace,
    FinanceCloseWorkspaceInput,
    PrepareCloseWorkspacePrimitive,
    prepare_close_workspace,
)
from lightbulb.finance_settlement_reconciliation import (
    ReconcileStripeSettlementsPrimitive,
    StripeLedgerReconciliationInput,
    reconcile_stripe_settlements,
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

RECONCILIATION_PACKAGE_CANDIDATE_INPUT_SCHEMA = (
    "lightbulb.finance_reconciliation_package_candidate_input.v1"
)
RECONCILIATION_PACKAGE_CANDIDATE_RESULT_SCHEMA = (
    "lightbulb.finance_reconciliation_package_candidate_result.v1"
)

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_REQUIRED_EVIDENCE_KINDS = (
    "account_subledger_reconciliations",
    "reconciliation_review_attestation",
)


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


class PrepareReconciliationPackageInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_reconciliation_package_candidate_input.v1"
    ] = Field(default=RECONCILIATION_PACKAGE_CANDIDATE_INPUT_SCHEMA, alias="schema")
    workspace: FinanceCloseWorkspace
    readiness: CloseReconciliationReadinessResult
    reconciliation_set_ref: OpaqueRef
    evidence_use_refs: tuple[OpaqueRef, OpaqueRef]
    account_reconciliations: tuple[AccountReconciliationRecord, ...] = Field(
        min_length=2, max_length=5_000
    )
    subledger_reconciliations: tuple[SubledgerReconciliationRecord, ...] = Field(
        min_length=1, max_length=100
    )
    review_completed_at: str

    @field_validator("workspace", "readiness", mode="before")
    @classmethod
    def _detached_models(cls, value: Any, info: Any) -> Any:
        model_type: type[BaseModel] = {
            "workspace": FinanceCloseWorkspace,
            "readiness": CloseReconciliationReadinessResult,
        }[info.field_name]
        if isinstance(value, model_type):
            return value
        if isinstance(value, dict):
            return model_type.model_validate_json(json.dumps(value, default=str))
        return value

    @field_validator(
        "evidence_use_refs",
        "account_reconciliations",
        "subledger_reconciliations",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("review_completed_at")
    @classmethod
    def _review_time(cls, value: str) -> str:
        return _timestamp(value, field_name="review_completed_at")

    @model_validator(mode="after")
    def _exact_ready_sources(self) -> "PrepareReconciliationPackageInput":
        readiness = self.readiness
        workspace = self.workspace
        if (
            not readiness.account_reconciliation_ready
            or readiness.blockers
            or readiness.next_transition != "reconcile_accounts"
            or readiness.lifecycle_version != 2
            or readiness.lifecycle_state_digest is None
            or readiness.trial_balance_transition_digest is None
        ):
            raise ValueError("a ready exact two-transition projection is required")
        if (
            readiness.workspace_ref != workspace.workspace_ref
            or readiness.workspace_revision != workspace.workspace_revision
            or readiness.workspace_digest != workspace.content_digest
        ):
            raise ValueError("readiness must bind the exact close workspace")
        if readiness.required_evidence_kinds != _REQUIRED_EVIDENCE_KINDS:
            raise ValueError("readiness does not require the exact review evidence")
        if tuple(sorted(self.evidence_use_refs)) != self.evidence_use_refs:
            raise ValueError("evidence use references must be unique and canonical")
        if len(set(self.evidence_use_refs)) != 2:
            raise ValueError(
                "exactly two distinct evidence use references are required"
            )
        if datetime.fromisoformat(
            self.review_completed_at.replace("Z", "+00:00")
        ) < datetime.fromisoformat(readiness.evaluated_at.replace("Z", "+00:00")):
            raise ValueError("review cannot precede reconciliation readiness")
        return self


class ReconciliationPackageCandidateResult(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_reconciliation_package_candidate_result.v1"
    ] = Field(default=RECONCILIATION_PACKAGE_CANDIDATE_RESULT_SCHEMA, alias="schema")
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    readiness_result_digest: Sha256Digest
    settlement_result_digest: Sha256Digest
    lifecycle_state_digest: Sha256Digest
    package: ReconciliationPackage
    package_digest: Sha256Digest
    candidate_digest: Sha256Digest = _ZERO_DIGEST
    reviewer_identity_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    evidence_custody_state: Literal["spring_retention_required"] = (
        "spring_retention_required"
    )
    reconciliation_package_authority: Literal[False] = False
    lifecycle_transition_authority: Literal[False] = False
    persistence_authorized: Literal[False] = False

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _sealed_candidate(self) -> "ReconciliationPackageCandidateResult":
        expected_package = _stable_digest(self.package.to_dict())
        if self.package_digest != expected_package:
            raise ValueError("package_digest must commit the exact package")
        expected = _stable_digest(self.digest_payload())
        if self.candidate_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("candidate_digest does not match package evidence")
        object.__setattr__(self, "candidate_digest", expected)
        return self


def prepare_reconciliation_package(
    inputs: PrepareReconciliationPackageInput,
) -> ReconciliationPackageCandidateResult:
    workspace = inputs.workspace
    readiness = inputs.readiness
    trial = workspace.trial_balance_package
    account_records = tuple(
        sorted(inputs.account_reconciliations, key=lambda item: item.account_ref)
    )
    subledger_records = tuple(
        sorted(inputs.subledger_reconciliations, key=lambda item: item.subledger_ref)
    )
    expected_accounts = tuple(line.account_ref for line in trial.lines)
    if tuple(item.account_ref for item in account_records) != expected_accounts:
        raise ValueError("every exact trial-balance account must be reconciled")
    balances = {line.account_ref: line.debit - line.credit for line in trial.lines}
    if any(
        item.ledger_balance != balances[item.account_ref] for item in account_records
    ):
        raise ValueError("account records must bind exact trial-balance balances")
    expected_subledgers = tuple(
        sorted(
            (
                item.subledger_ref,
                item.control_account_ref,
            )
            for item in workspace.close_scope.required_subledgers
        )
    )
    actual_subledgers = tuple(
        (item.subledger_ref, item.control_account_ref) for item in subledger_records
    )
    if actual_subledgers != expected_subledgers:
        raise ValueError("every exact scoped subledger must be reconciled")
    if any(item.control_account_ref not in balances for item in subledger_records):
        raise ValueError(
            "every subledger control account must exist in the Trial Balance"
        )
    if any(
        item.general_ledger_balance != balances[item.control_account_ref]
        for item in subledger_records
    ):
        raise ValueError("subledger records must bind exact control-account balances")
    all_records = (*account_records, *subledger_records)
    if any(
        item.materiality_threshold > workspace.close_scope.materiality_threshold
        for item in all_records
    ):
        raise ValueError("record materiality exceeds the exact close scope")
    preparers = {item.prepared_by_ref for item in all_records}
    reviewers = {item.reviewed_by_ref for item in all_records}
    if preparers & reviewers:
        raise ValueError("reviewers must be globally separate from record preparers")
    aggregate = sum(
        (abs(item.unexplained_variance) for item in all_records), Decimal(0)
    )
    if aggregate > workspace.close_scope.materiality_threshold:
        raise ValueError("aggregate unexplained variance exceeds scoped materiality")
    package = ReconciliationPackage(
        evidence_use_refs=inputs.evidence_use_refs,
        reconciliation_set_ref=inputs.reconciliation_set_ref,
        trial_balance_transition_digest=readiness.trial_balance_transition_digest,
        account_reconciliations=account_records,
        subledger_reconciliations=subledger_records,
        aggregate_unexplained_variance=aggregate,
        review_completed_at=inputs.review_completed_at,
    )
    package_digest = _stable_digest(package.to_dict())
    return ReconciliationPackageCandidateResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        readiness_result_digest=readiness.result_digest,
        settlement_result_digest=readiness.settlement_result_digest,
        lifecycle_state_digest=readiness.lifecycle_state_digest,
        package=package,
        package_digest=package_digest,
    )


def _example_inputs() -> dict[str, Any]:
    workspace_input = FinanceCloseWorkspaceInput.model_validate(
        deepcopy(PrepareCloseWorkspacePrimitive.example_inputs)
    )
    workspace = prepare_close_workspace(workspace_input).workspace
    reconciliation_input = StripeLedgerReconciliationInput.model_validate(
        ReconcileStripeSettlementsPrimitive.example_inputs
    )
    settlement = reconcile_stripe_settlements(reconciliation_input)
    statuses = ("complete", "complete", "complete", "complete", "ready")
    checklist = tuple(
        FinanceCloseChecklistItem(
            sequence=item.sequence,
            stage=item.stage,
            status=statuses[index] if index < len(statuses) else "blocked",
            blocker_code=(
                None
                if index < len(statuses)
                else item.blocker_code or "awaiting_prior_close_stage"
            ),
        )
        for index, item in enumerate(workspace.checklist)
    )
    readiness = CloseReconciliationReadinessResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        settlement_result_digest=settlement.result_digest,
        lifecycle_version=2,
        lifecycle_state_digest=_stable_digest("example-lifecycle-state"),
        trial_balance_transition_digest=_stable_digest("example-trial-transition"),
        evaluated_at="2026-09-01T12:40:00Z",
        blockers=(),
        checklist=checklist,
        account_reconciliation_ready=True,
        next_transition="reconcile_accounts",
    )
    account_records = []
    for line in workspace.trial_balance_package.lines:
        balance = line.debit - line.credit
        account_records.append(
            AccountReconciliationRecord(
                account_ref=line.account_ref,
                reconciliation_ref=f"reconciliation:{line.account_ref}",
                ledger_balance=balance,
                source_balance=balance,
                reconciling_items_total=Decimal(0),
                unexplained_variance=Decimal(0),
                materiality_threshold=Decimal("1.00"),
                prepared_by_ref=f"preparer:{line.account_ref}",
                reviewed_by_ref=f"reviewer:{line.account_ref}",
            )
        )
    control_balance = next(
        item.ledger_balance
        for item in account_records
        if item.account_ref == workspace.stripe_control_account_ref
    )
    subledger = SubledgerReconciliationRecord(
        subledger_ref=workspace.stripe_subledger_ref,
        control_account_ref=workspace.stripe_control_account_ref,
        reconciliation_ref="reconciliation:stripe:settlements",
        subledger_balance=control_balance,
        general_ledger_balance=control_balance,
        reconciling_items_total=Decimal(0),
        unexplained_variance=Decimal(0),
        materiality_threshold=Decimal("1.00"),
        prepared_by_ref="preparer:stripe:settlements",
        reviewed_by_ref="reviewer:stripe:settlements",
    )
    return {
        "workspace": workspace.model_dump(
            mode="python", by_alias=True, exclude_none=True
        ),
        "readiness": readiness.model_dump(
            mode="python", by_alias=True, exclude_none=True
        ),
        "reconciliation_set_ref": "reconciliation-set:2026-08",
        "evidence_use_refs": (
            "evidence-use:account-subledger-reconciliations",
            "evidence-use:reconciliation-review-attestation",
        ),
        "account_reconciliations": tuple(item.to_dict() for item in account_records),
        "subledger_reconciliations": (subledger.to_dict(),),
        "review_completed_at": "2026-09-01T13:00:00Z",
    }


class PrepareReconciliationPackagePrimitive(
    BusinessProcessPrimitive[
        PrepareReconciliationPackageInput,
        ReconciliationPackageCandidateResult,
    ]
):
    primitive_ref = "finance.prepare_reconciliation_package"
    version = "1.0.0"
    title = "Prepare reviewed reconciliation package candidate"
    description = (
        "Validate exact trial-balance account and scoped subledger ending-balance "
        "records and prepare a digest-bound ReconciliationPackage candidate without "
        "authenticating reviewers or advancing the close lifecycle."
    )
    input_model = PrepareReconciliationPackageInput
    output_model = ReconciliationPackageCandidateResult
    connector_tools = ()
    risk_level = "medium"
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
            "review_decisions": 0,
            "evidence_writes": 0,
            "lifecycle_transitions": 0,
            "persistence_writes": 0,
        }
        contract["review_authority"] = "spring_rbac_revalidation_required"
        contract["evidence_authority"] = "spring_custody_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PrepareReconciliationPackageInput,
    ) -> PrimitiveExecutionResult[ReconciliationPackageCandidateResult]:
        scope = inputs.workspace.close_scope
        if (
            context.scope.tenant_ref != scope.tenant_ref
            or context.scope.company_ref != scope.company_ref
            or context.scope.project_ref != scope.project_ref
            or context.scope.project_id != scope.project_id
        ):
            blocker = PrimitiveBlocker(
                code="reconciliation_package_scope_mismatch",
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
        output = prepare_reconciliation_package(inputs)
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Prepared a structural reconciliation package candidate; Spring "
                "review and evidence authority remain required."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.reconciliation_package_candidate_prepared",
                    payload={
                        "workspace_ref": output.workspace_ref,
                        "reconciliation_set_ref": output.package.reconciliation_set_ref,
                        "package_digest": output.package_digest,
                        "candidate_digest": output.candidate_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_reconciliation_package_candidate",
                    summary=(
                        "Exact balance records were structurally validated; reviewer "
                        "identity and retained evidence still require Spring authority."
                    ),
                    labels=[
                        "monthly_close",
                        "structural_candidate_only",
                        "spring_review_required",
                    ],
                    refs={"candidate_digest": output.candidate_digest},
                )
            ],
        )


FINANCE_RECONCILIATION_PACKAGE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (PrepareReconciliationPackagePrimitive(),)


__all__ = [
    "FINANCE_RECONCILIATION_PACKAGE_EXECUTABLE_PRIMITIVES",
    "PrepareReconciliationPackageInput",
    "PrepareReconciliationPackagePrimitive",
    "RECONCILIATION_PACKAGE_CANDIDATE_INPUT_SCHEMA",
    "RECONCILIATION_PACKAGE_CANDIDATE_RESULT_SCHEMA",
    "ReconciliationPackageCandidateResult",
    "prepare_reconciliation_package",
]
