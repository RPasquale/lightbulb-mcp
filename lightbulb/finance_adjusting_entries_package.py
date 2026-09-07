"""Prepare a controlled period-close adjusting-entries package candidate.

The primitive converts exact, controlled journal preparations with successful
governed post receipts and independent readback evaluations into the existing
``AdjustingEntriesPackage`` contract.  A no-adjustment conclusion is also
represented explicitly.  Spring still owns approval authenticity, provider
effects, execution-journal settlement, evidence custody, persistence, and the
period-close transition.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import date, datetime, timezone
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

from lightbulb.finance_accounting import JournalEntryControlInput
from lightbulb.finance_close_lifecycle import (
    AdjustingEntriesPackage,
    AdjustingJournalEntry,
    JournalEntryLine,
    PeriodCloseLifecycleSnapshot,
    materialize_period_close_candidate,
)
from lightbulb.finance_close_workspace import FinanceCloseWorkspace
from lightbulb.finance_journal_lifecycle import (
    JournalEntryPreparation,
    PostJournalEntryResult,
    PrepareJournalEntryInput,
    ReconcileJournalPostInput,
    ReconcileJournalPostResult,
    prepare_journal_entry,
    quickbooks_journal_effect_sha256,
    reconcile_journal_post,
)
from lightbulb.finance_reconciliation_transition import (
    PrepareReconciliationTransitionCommandInput,
    PrepareReconciliationTransitionCommandPrimitive,
    prepare_reconciliation_transition_command,
)
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationStatus,
)

ADJUSTING_ENTRIES_PACKAGE_CANDIDATE_INPUT_SCHEMA = (
    "lightbulb.finance_adjusting_entries_package_candidate_input.v2"
)
ADJUSTING_ENTRIES_PACKAGE_CANDIDATE_RESULT_SCHEMA = (
    "lightbulb.finance_adjusting_entries_package_candidate_result.v2"
)
ADJUSTMENT_JOURNAL_EVIDENCE_BINDING_SCHEMA = (
    "lightbulb.finance_adjustment_journal_evidence_binding.v1"
)

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_REQUIRED_EVIDENCE_KINDS = (
    "adjusting_entry_batch",
    "adjustment_posting_attestation",
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


class AdjustmentJournalPostingEvidence(_StrictModel):
    effective_at: str
    provider: Literal["quickbooks", "xero"]
    journal: JournalEntryControlInput
    preparation: JournalEntryPreparation
    post_result: PostJournalEntryResult
    reconciliation_input: ReconcileJournalPostInput
    reconciliation_result: ReconcileJournalPostResult

    @field_validator("effective_at")
    @classmethod
    def _effective_at(cls, value: str) -> str:
        return _timestamp(value, field_name="effective_at")

    @field_validator(
        "journal",
        "preparation",
        "post_result",
        "reconciliation_input",
        "reconciliation_result",
        mode="before",
    )
    @classmethod
    def _detached_models(cls, value: Any, info: Any) -> Any:
        model_type: type[BaseModel] = {
            "journal": JournalEntryControlInput,
            "preparation": JournalEntryPreparation,
            "post_result": PostJournalEntryResult,
            "reconciliation_input": ReconcileJournalPostInput,
            "reconciliation_result": ReconcileJournalPostResult,
        }[info.field_name]
        if isinstance(value, model_type):
            return value
        if isinstance(value, dict):
            return model_type.model_validate_json(json.dumps(value, default=str))
        return value

    @model_validator(mode="after")
    def _exact_controlled_post_and_readback(
        self,
    ) -> "AdjustmentJournalPostingEvidence":
        if self.provider == "xero":
            raise ValueError(
                "non-empty Xero adjustment packages require a certified semantic effect fingerprint"
            )
        expected_preparation = prepare_journal_entry(
            PrepareJournalEntryInput(provider=self.provider, journal=self.journal)
        )
        if self.preparation != expected_preparation:
            raise ValueError(
                "journal preparation is not the exact canonical evaluation"
            )
        if expected_preparation.provider_payload is None:
            raise ValueError("adjustment journal requires a canonical provider payload")
        expected_effect_digest = quickbooks_journal_effect_sha256(
            expected_preparation.provider_payload
        )
        receipt = self.reconciliation_input.post_receipt
        external = receipt.external_refs
        if (
            self.post_result.provider != self.provider
            or self.post_result.tool != self.preparation.tool
            or self.post_result.entry_ref != self.journal.entry_ref
            or self.post_result.preparation_digest
            != self.preparation.preparation_digest
            or self.post_result.state != "posted"
            or receipt.status != PrimitiveOperationStatus.COMPLETED
            or receipt.spec.tool != self.preparation.tool
            or receipt.approval_ref is None
            or receipt.provenance_receipt_digest is None
            or receipt.provenance_receipt_digest
            != self.post_result.provenance_receipt_digest
            or external.get("tool_version") != str(self.post_result.tool_version)
            or external.get("project_id") != str(self.post_result.project_id)
            or external.get("tenant_connector_id")
            != str(self.post_result.tenant_connector_id)
            or external.get("connector_account_ref")
            != self.post_result.connector_account_ref
            or external.get("route_digest") != self.post_result.route_digest
            or external.get("entry_ref") != self.journal.entry_ref
            or external.get("preparation_digest") != self.preparation.preparation_digest
            or external.get("provider_record_ref")
            != self.post_result.provider_record_ref
            or external.get("write_provider_output_sha256")
            != self.post_result.write_provider_output_sha256
            or external.get("expected_effect_sha256")
            != self.post_result.expected_effect_sha256
            or self.post_result.expected_effect_sha256 != expected_effect_digest
            or external.get("execution_journal_ref")
            != self.post_result.execution_journal_ref
        ):
            raise ValueError("posted journal does not match the exact governed receipt")
        expected_reconciliation = reconcile_journal_post(self.reconciliation_input)
        if self.reconciliation_result != expected_reconciliation:
            raise ValueError(
                "journal readback result is not the exact canonical evaluation"
            )
        if (
            self.reconciliation_result.provider != self.provider
            or self.reconciliation_result.entry_ref != self.journal.entry_ref
            or self.reconciliation_result.disposition != "effect_confirmed_candidate"
            or not self.reconciliation_result.readback_matches
        ):
            raise ValueError(
                "adjustment journal requires matching independent provider readback"
            )
        if (
            date.fromisoformat(self.journal.entry_date)
            != datetime.fromisoformat(self.effective_at.replace("Z", "+00:00")).date()
        ):
            raise ValueError("adjustment effective date must match journal entry_date")
        return self

    def evidence_digest(self) -> str:
        return _stable_digest(self.to_dict())


class AdjustmentJournalEvidenceBinding(_StrictModel):
    schema_id: Literal["lightbulb.finance_adjustment_journal_evidence_binding.v1"] = (
        Field(default=ADJUSTMENT_JOURNAL_EVIDENCE_BINDING_SCHEMA, alias="schema")
    )
    journal_entry_ref: OpaqueRef
    journal_evidence_digest: Sha256Digest
    journal_evidence: AdjustmentJournalPostingEvidence

    @field_validator("journal_evidence", mode="before")
    @classmethod
    def _detached_evidence(cls, value: Any) -> Any:
        if isinstance(value, AdjustmentJournalPostingEvidence):
            return value
        if isinstance(value, dict):
            return AdjustmentJournalPostingEvidence.model_validate_json(
                json.dumps(value, default=str)
            )
        return value

    @model_validator(mode="after")
    def _binding_is_exact(self) -> "AdjustmentJournalEvidenceBinding":
        if self.journal_entry_ref != self.journal_evidence.journal.entry_ref:
            raise ValueError(
                "journal evidence binding must name the exact journal entry"
            )
        if self.journal_evidence_digest != self.journal_evidence.evidence_digest():
            raise ValueError(
                "journal evidence binding digest must commit the exact evidence"
            )
        return self


def _adjusting_entry_from_evidence(
    evidence: AdjustmentJournalPostingEvidence,
) -> AdjustingJournalEntry:
    return AdjustingJournalEntry(
        journal_entry_ref=evidence.journal.entry_ref,
        currency=evidence.journal.transaction_currency,
        effective_at=evidence.effective_at,
        lines=tuple(
            JournalEntryLine(
                line_ref=line.line_ref,
                account_ref=line.account_ref,
                debit=line.debit,
                credit=line.credit,
            )
            for line in sorted(evidence.journal.lines, key=lambda line: line.line_ref)
        ),
        total_debit=evidence.preparation.control_evaluation.debit_total,
        total_credit=evidence.preparation.control_evaluation.credit_total,
    )


class PrepareAdjustingEntriesPackageInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_adjusting_entries_package_candidate_input.v2"
    ] = Field(default=ADJUSTING_ENTRIES_PACKAGE_CANDIDATE_INPUT_SCHEMA, alias="schema")
    workspace: FinanceCloseWorkspace
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot
    adjustment_batch_ref: OpaqueRef
    evidence_use_refs: tuple[OpaqueRef, OpaqueRef]
    no_adjustments_required: bool
    journals: tuple[AdjustmentJournalPostingEvidence, ...] = Field(
        default_factory=tuple, max_length=500
    )
    reported_posted_at: str
    prepared_by_ref: OpaqueRef
    posted_by_ref: OpaqueRef
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

    @field_validator("evidence_use_refs", "journals", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("no_adjustments_required", mode="before")
    @classmethod
    def _strict_bool(cls, value: Any) -> bool:
        if type(value) is not bool:
            raise ValueError("no_adjustments_required must be a boolean literal")
        return value

    @field_validator("reported_posted_at")
    @classmethod
    def _reported_posted_at(cls, value: str) -> str:
        return _timestamp(value, field_name="reported_posted_at")

    @model_validator(mode="after")
    def _exact_reconciled_sources(self) -> "PrepareAdjustingEntriesPackageInput":
        workspace = self.workspace
        snapshot = self.lifecycle_snapshot
        scope = workspace.close_scope
        if (
            snapshot.scope != scope
            or snapshot.version != 3
            or snapshot.status != "reconciliations_validated"
            or snapshot.period_open != workspace.open_period_package
            or snapshot.trial_balance != workspace.trial_balance_package
            or snapshot.reconciliations is None
        ):
            raise ValueError("the exact retained reconciliations snapshot is required")
        if (
            tuple(sorted(self.evidence_use_refs)) != self.evidence_use_refs
            or len(set(self.evidence_use_refs)) != 2
        ):
            raise ValueError(
                "exactly two canonical evidence use references are required"
            )
        if self.no_adjustments_required != (not self.journals):
            raise ValueError(
                "no_adjustments_required must exactly match an empty journal batch"
            )
        if len({self.prepared_by_ref, self.posted_by_ref, self.reviewed_by_ref}) != 3:
            raise ValueError(
                "adjustment preparation, posting, and review actors must be distinct"
            )
        reconciliation_time = datetime.fromisoformat(
            snapshot.reconciliations.review_completed_at.replace("Z", "+00:00")
        )
        reported_time = datetime.fromisoformat(
            self.reported_posted_at.replace("Z", "+00:00")
        )
        if reported_time < reconciliation_time:
            raise ValueError(
                "adjustment conclusion cannot precede reconciliation review"
            )
        trial_accounts = {
            item.account_ref for item in workspace.trial_balance_package.lines
        }
        entry_refs: set[str] = set()
        provider_records: set[str] = set()
        execution_journals: set[str] = set()
        read_execution_journals: set[str] = set()
        governed_read_sources: set[str] = set()
        custody_refs: set[str] = set()
        post_requests: set[str] = set()
        evidence_by_ref: dict[str, str] = {}
        evidence_digests: set[str] = set()
        provenance_receipt_digests: set[str] = set()
        period_start = date.fromisoformat(scope.period_started_at[:10])
        period_end = date.fromisoformat(scope.period_ended_at[:10])
        for item in self.journals:
            journal = item.journal
            if (
                journal.company.company_ref != scope.company_ref
                or journal.period.company_ref != scope.company_ref
                or journal.period.period_ref != scope.fiscal_period_ref
                or journal.company.functional_currency != scope.functional_currency
                or journal.period.functional_currency != scope.functional_currency
                or journal.transaction_currency != scope.functional_currency
                or journal.period.start_date != period_start.isoformat()
                or journal.period.end_date != period_end.isoformat()
                or journal.period.state != "open"
            ):
                raise ValueError("adjustment journal does not match exact close scope")
            if any(line.account_ref not in trial_accounts for line in journal.lines):
                raise ValueError(
                    "adjustment journal references an account outside the Trial Balance"
                )
            approval = journal.approval
            if (
                not approval.required
                or approval.status != "approved"
                or approval.prepared_by_ref != self.prepared_by_ref
                or approval.approved_by_ref != self.reviewed_by_ref
            ):
                raise ValueError(
                    "every adjustment journal requires exact independent batch approval"
                )
            readback_time = datetime.fromisoformat(
                item.reconciliation_input.readback.observed_at.replace("Z", "+00:00")
            )
            if readback_time < reconciliation_time or readback_time > reported_time:
                raise ValueError(
                    "adjustment readback must follow reconciliation and precede reporting"
                )
            entry_refs.add(journal.entry_ref)
            provider_records.add(item.post_result.provider_record_ref or "")
            execution_journals.add(item.post_result.execution_journal_ref or "")
            read_execution_journals.add(
                item.reconciliation_input.readback.read_execution_journal_ref
            )
            governed_read_sources.add(
                item.reconciliation_input.readback.governed_read_source_ref
            )
            custody_refs.update(
                {
                    item.post_result.execution_journal_ref or "",
                    item.reconciliation_input.readback.read_execution_journal_ref,
                    item.reconciliation_input.readback.governed_read_source_ref,
                }
            )
            post_requests.add(item.reconciliation_input.post_receipt.request_digest)
            provenance_receipt_digests.update(
                {
                    item.post_result.provenance_receipt_digest or "",
                    item.reconciliation_input.readback.provenance_receipt_digest,
                }
            )
            for evidence in item.reconciliation_input.readback.evidence_refs:
                retained_digest = evidence_by_ref.get(evidence.evidence_ref)
                if retained_digest is not None:
                    if retained_digest != evidence.sha256:
                        raise ValueError(
                            "one retained evidence_ref cannot bind multiple digests across adjustment journals"
                        )
                    raise ValueError(
                        "readback evidence references must be globally unique across adjustment journals"
                    )
                if evidence.sha256 in evidence_digests:
                    raise ValueError(
                        "readback evidence digests must be globally unique across adjustment journals"
                    )
                evidence_by_ref[evidence.evidence_ref] = evidence.sha256
                evidence_digests.add(evidence.sha256)
        count = len(self.journals)
        if any(
            len(values) != count
            for values in (
                entry_refs,
                provider_records,
                execution_journals,
                read_execution_journals,
                governed_read_sources,
                post_requests,
            )
        ):
            raise ValueError("adjustment journal evidence identities must be unique")
        if len(custody_refs) != count * 3:
            raise ValueError(
                "WRITE journals, READ execution journals, and governed read sources must be globally distinct across adjustment journals"
            )
        if len(provenance_receipt_digests) != count * 2:
            raise ValueError(
                "WRITE and READ provenance receipt digests must be globally distinct across adjustment journals"
            )
        return self


class AdjustingEntriesPackageCandidateResult(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_adjusting_entries_package_candidate_result.v2"
    ] = Field(default=ADJUSTING_ENTRIES_PACKAGE_CANDIDATE_RESULT_SCHEMA, alias="schema")
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    lifecycle_version: Literal[3] = 3
    lifecycle_state_digest: Sha256Digest
    reconciliation_transition_digest: Sha256Digest
    package: AdjustingEntriesPackage
    package_digest: Sha256Digest
    journal_evidence_bindings: tuple[AdjustmentJournalEvidenceBinding, ...] = Field(
        max_length=500
    )
    candidate_digest: Sha256Digest = _ZERO_DIGEST
    journal_post_state: Literal["spring_settlement_required", "not_applicable"]
    actor_identity_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    evidence_custody_state: Literal["spring_retention_required"] = (
        "spring_retention_required"
    )
    adjusting_entries_package_authority: Literal[False] = False
    lifecycle_transition_authority: Literal[False] = False
    persistence_authorized: Literal[False] = False

    @field_validator("journal_evidence_bindings", mode="before")
    @classmethod
    def _bindings_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _sealed_candidate(self) -> "AdjustingEntriesPackageCandidateResult":
        if self.package_digest != _stable_digest(self.package.to_dict()):
            raise ValueError("package_digest must commit the exact adjustment package")
        if self.journal_post_state != (
            "not_applicable"
            if self.package.no_adjustments_required
            else "spring_settlement_required"
        ):
            raise ValueError("journal post state does not match adjustment package")
        package_refs = tuple(item.journal_entry_ref for item in self.package.entries)
        binding_refs = tuple(
            item.journal_entry_ref for item in self.journal_evidence_bindings
        )
        if binding_refs != package_refs:
            raise ValueError(
                "canonical journal evidence bindings must exactly match package entries"
            )
        expected_entries = tuple(
            _adjusting_entry_from_evidence(item.journal_evidence)
            for item in self.journal_evidence_bindings
        )
        if self.package.entries != expected_entries:
            raise ValueError(
                "adjustment package entries must be the exact evidence projection"
            )
        expected = _stable_digest(self.digest_payload())
        if self.candidate_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("candidate_digest does not match adjustment evidence")
        object.__setattr__(self, "candidate_digest", expected)
        return self


def prepare_adjusting_entries_package(
    inputs: PrepareAdjustingEntriesPackageInput,
) -> AdjustingEntriesPackageCandidateResult:
    snapshot = inputs.lifecycle_snapshot
    workspace = inputs.workspace
    trial_transition = snapshot.transition_history[1]
    reconciliation_transition = snapshot.transition_history[2]
    canonical_evidence = tuple(
        sorted(inputs.journals, key=lambda item: item.journal.entry_ref)
    )
    entries = tuple(_adjusting_entry_from_evidence(item) for item in canonical_evidence)
    batch_debit = sum((item.total_debit for item in entries), Decimal(0))
    batch_credit = sum((item.total_credit for item in entries), Decimal(0))
    package = AdjustingEntriesPackage(
        evidence_use_refs=inputs.evidence_use_refs,
        adjustment_batch_ref=inputs.adjustment_batch_ref,
        trial_balance_transition_digest=trial_transition.transition_digest,
        reconciliation_transition_digest=reconciliation_transition.transition_digest,
        no_adjustments_required=inputs.no_adjustments_required,
        entries=entries,
        batch_total_debit=batch_debit,
        batch_total_credit=batch_credit,
        posting_status=(
            "reported_not_required"
            if inputs.no_adjustments_required
            else "reported_posted"
        ),
        reported_posted_at=inputs.reported_posted_at,
        prepared_by_ref=inputs.prepared_by_ref,
        posted_by_ref=inputs.posted_by_ref,
        reviewed_by_ref=inputs.reviewed_by_ref,
    )
    return AdjustingEntriesPackageCandidateResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        lifecycle_state_digest=snapshot.state_digest,
        reconciliation_transition_digest=reconciliation_transition.transition_digest,
        package=package,
        package_digest=_stable_digest(package.to_dict()),
        journal_evidence_bindings=tuple(
            AdjustmentJournalEvidenceBinding(
                journal_entry_ref=item.journal.entry_ref,
                journal_evidence_digest=item.evidence_digest(),
                journal_evidence=item,
            )
            for item in canonical_evidence
        ),
        journal_post_state=(
            "not_applicable"
            if inputs.no_adjustments_required
            else "spring_settlement_required"
        ),
    )


def _example_inputs() -> dict[str, Any]:
    reconciliation_inputs = PrepareReconciliationTransitionCommandInput.model_validate(
        deepcopy(PrepareReconciliationTransitionCommandPrimitive.example_inputs)
    )
    reconciliation_command = prepare_reconciliation_transition_command(
        reconciliation_inputs
    )
    lifecycle = materialize_period_close_candidate(
        reconciliation_command.lifecycle_input
    )
    if lifecycle.snapshot is None:  # pragma: no cover - invariant guard
        raise RuntimeError("example reconciliation transition was not materialized")
    return {
        "workspace": reconciliation_inputs.workspace.to_dict(),
        "lifecycle_snapshot": lifecycle.snapshot.to_dict(),
        "adjustment_batch_ref": "adjustment-batch:2026-08",
        "evidence_use_refs": (
            "evidence-use:adjusting-entry-batch",
            "evidence-use:adjustment-posting-attestation",
        ),
        "no_adjustments_required": True,
        "journals": (),
        "reported_posted_at": "2026-09-01T13:30:00Z",
        "prepared_by_ref": "operator:adjustment-preparer",
        "posted_by_ref": "operator:posting-controller",
        "reviewed_by_ref": "reviewer:adjustment-controller",
    }


class PrepareAdjustingEntriesPackagePrimitive(
    BusinessProcessPrimitive[
        PrepareAdjustingEntriesPackageInput,
        AdjustingEntriesPackageCandidateResult,
    ]
):
    primitive_ref = "finance.prepare_adjusting_entries_package"
    version = "2.0.0"
    title = "Prepare controlled adjusting-entries package candidate"
    description = (
        "Validate either an explicit no-adjustment conclusion or exact controlled "
        "journal preparations, governed post receipts, and independent readback "
        "evaluations before preparing an AdjustingEntriesPackage candidate."
    )
    input_model = PrepareAdjustingEntriesPackageInput
    output_model = AdjustingEntriesPackageCandidateResult
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
            "review_decisions": 0,
            "evidence_writes": 0,
            "lifecycle_transitions": 0,
            "persistence_writes": 0,
        }
        contract["journal_evidence"] = (
            "canonical controls + completed governed post receipt + independent "
            "matching readback; Spring settlement remains required"
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PrepareAdjustingEntriesPackageInput,
    ) -> PrimitiveExecutionResult[AdjustingEntriesPackageCandidateResult]:
        scope = inputs.workspace.close_scope
        if (
            context.scope.tenant_ref != scope.tenant_ref
            or context.scope.company_ref != scope.company_ref
            or context.scope.project_ref != scope.project_ref
            or context.scope.project_id != scope.project_id
        ):
            blocker = PrimitiveBlocker(
                code="adjusting_entries_package_scope_mismatch",
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
        output = prepare_adjusting_entries_package(inputs)
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Prepared a structural adjusting-entries package candidate; Spring "
                "post settlement, actor, evidence, and lifecycle authority remain."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.adjusting_entries_package_candidate_prepared",
                    payload={
                        "workspace_ref": output.workspace_ref,
                        "adjustment_batch_ref": output.package.adjustment_batch_ref,
                        "entry_count": len(output.package.entries),
                        "package_digest": output.package_digest,
                        "candidate_digest": output.candidate_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_adjusting_entries_package_candidate",
                    summary=(
                        "Adjustment journals were structurally tied to canonical "
                        "controls, governed post receipts, and independent readback."
                    ),
                    labels=[
                        "monthly_close",
                        "structural_candidate_only",
                        "spring_settlement_required",
                    ],
                    refs={"candidate_digest": output.candidate_digest},
                )
            ],
        )


FINANCE_ADJUSTING_ENTRIES_PACKAGE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (PrepareAdjustingEntriesPackagePrimitive(),)


__all__ = [
    "ADJUSTMENT_JOURNAL_EVIDENCE_BINDING_SCHEMA",
    "ADJUSTING_ENTRIES_PACKAGE_CANDIDATE_INPUT_SCHEMA",
    "ADJUSTING_ENTRIES_PACKAGE_CANDIDATE_RESULT_SCHEMA",
    "AdjustmentJournalEvidenceBinding",
    "AdjustmentJournalPostingEvidence",
    "AdjustingEntriesPackageCandidateResult",
    "FINANCE_ADJUSTING_ENTRIES_PACKAGE_EXECUTABLE_PRIMITIVES",
    "PrepareAdjustingEntriesPackageInput",
    "PrepareAdjustingEntriesPackagePrimitive",
    "prepare_adjusting_entries_package",
]
