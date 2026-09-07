"""Executable business process primitive runtime for custom Lightbulb projects."""

from __future__ import annotations

import hashlib
import logging
import re
import time
from copy import deepcopy
from functools import lru_cache
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Generic,
    Iterable,
    Literal,
    Mapping,
    TYPE_CHECKING,
    TypeVar,
)
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError as PydanticValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticSerializationError

from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorErrorKind,
    ConnectorExecutionRequest,
    ConnectorExecutionResult,
    ConnectorExecutionStatus,
    ConnectorExecutor,
    ExecutionScope,
)
from lightbulb.runtime_outcomes import RuntimeOutcome, RuntimeOutcomeRecorder


if TYPE_CHECKING:
    from lightbulb.project_runtime import LightbulbProject


logger = logging.getLogger(__name__)


PRIMITIVE_IMPLEMENTATION_SCHEMA = "lightbulb.business_process_primitive.v1"
PRIMITIVE_EXECUTION_RESULT_SCHEMA = "lightbulb.primitive_execution_result.v1"
PRIMITIVE_EVIDENCE_REF_SCHEMA = "lightbulb.primitive_evidence_ref.v1"
PRIMITIVE_OPERATION_SPEC_SCHEMA = "lightbulb.primitive_operation_spec.v1"
PRIMITIVE_RECOVERY_PLAN_SCHEMA = "lightbulb.primitive_recovery_plan.v1"
PRIMITIVE_OPERATION_RECEIPT_SCHEMA = "lightbulb.primitive_operation_receipt.v1"
PRIMITIVE_RECOVERY_ATTESTATION_SCHEMA = "lightbulb.primitive_recovery_attestation.v1"
_OPERATION_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$")


class PrimitiveExecutionStatus(str, Enum):
    COMPLETED = "completed"
    PREVIEW = "preview"
    PENDING_APPROVAL = "pending_approval"
    NEEDS_INPUT = "needs_input"
    BLOCKED = "blocked"
    FAILED = "failed"


class PrimitiveRunMode(str, Enum):
    PREVIEW = "preview"
    APPLY = "apply"


class PrimitiveEvidenceVerificationGrade(str, Enum):
    UNVERIFIED = "unverified"
    ASSERTED = "asserted"
    ATTESTED = "attested"
    VERIFIED = "verified"


class PrimitiveEvidenceClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class PrimitiveOperationReplayClass(str, Enum):
    SAFE = "safe"
    PROBE_BEFORE_RETRY = "probe_before_retry"
    NEVER = "never"


class PrimitiveOperationFreshnessClass(str, Enum):
    CURRENT = "current"
    BOUNDED = "bounded"
    HISTORICAL = "historical"


class PrimitiveOperationRecoveryPolicy(str, Enum):
    NONE = "none"
    RETRY = "retry"
    STATUS_PROBE = "status_probe"
    COMPENSATE = "compensate"
    MANUAL_RECONCILIATION = "manual_reconciliation"


class PrimitiveOperationStatus(str, Enum):
    PLANNED = "planned"
    PREVIEW = "preview"
    PENDING_APPROVAL = "pending_approval"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    IN_DOUBT = "in_doubt"
    COMPENSATED = "compensated"


class PrimitiveRecoveryDisposition(str, Enum):
    NOT_REQUIRED = "not_required"
    RETRY_ALLOWED = "retry_allowed"
    STATUS_PROBE_REQUIRED = "status_probe_required"
    COMPENSATION_REQUIRED = "compensation_required"
    MANUAL_RECONCILIATION_REQUIRED = "manual_reconciliation_required"
    RESOLVED = "resolved"


class PrimitiveRecoveryOutcome(str, Enum):
    EFFECT_NOT_APPLIED = "effect_not_applied"
    EFFECT_CONFIRMED = "effect_confirmed"
    MANUALLY_RECONCILED = "manually_reconciled"
    COMPENSATED = "compensated"


def _normalized_utc_timestamp(value: str, *, field_name: str) -> str:
    clean = value.strip()
    if clean != value:
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class _StrictPrimitiveContract(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class PrimitiveEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: str = Field(min_length=1, max_length=160)
    payload: Dict[str, Any] = Field(default_factory=dict)


class PrimitiveEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str = Field(min_length=1, max_length=80)
    summary: str = Field(min_length=1, max_length=500)
    labels: list[str] = Field(default_factory=list)
    refs: Dict[str, str] = Field(default_factory=dict)


class PrimitiveEvidenceRef(_StrictPrimitiveContract):
    """Portable, content-bound reference to evidence retained outside a result."""

    schema_id: Literal["lightbulb.primitive_evidence_ref.v1"] = Field(
        default=PRIMITIVE_EVIDENCE_REF_SCHEMA,
        alias="schema",
    )
    evidence_ref: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=80)
    issuer_ref: str = Field(min_length=1, max_length=200)
    subject_ref: str | None = Field(default=None, min_length=1, max_length=200)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: str
    effective_at: str | None = None
    verification_grade: PrimitiveEvidenceVerificationGrade
    classification: PrimitiveEvidenceClassification
    retention_policy: str | None = Field(default=None, min_length=1, max_length=160)
    jurisdiction: str | None = Field(default=None, min_length=2, max_length=80)

    @field_validator("evidence_ref", "issuer_ref", "subject_ref")
    @classmethod
    def _visible_refs(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value != value.strip() or any(ord(character) < 33 for character in value):
            raise ValueError("evidence references must contain visible characters only")
        return value

    @field_validator("observed_at")
    @classmethod
    def _observed_at_is_utc(cls, value: str) -> str:
        return _normalized_utc_timestamp(value, field_name="observed_at")

    @field_validator("effective_at")
    @classmethod
    def _effective_at_is_utc(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_utc_timestamp(value, field_name="effective_at")


class PrimitiveBlocker(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(min_length=1, max_length=120)
    message: str = Field(min_length=1, max_length=500)
    field: str | None = Field(default=None, max_length=200)
    retryable: bool = False


class PrimitiveRecoveryAttestation(_StrictPrimitiveContract):
    """Evidence-bound resolution of an ambiguous operation outcome.

    Only ``effect_not_applied`` may express ``replay_permitted=True``. This
    portable model is structural evidence, not execution authority: the generic
    durable runtime never accepts a caller-authored instance to authorize replay.
    Spring's hosted connector journal must verify and settle recovery before a
    provider-specific continuation can run.
    """

    schema_id: Literal["lightbulb.primitive_recovery_attestation.v1"] = Field(
        default=PRIMITIVE_RECOVERY_ATTESTATION_SCHEMA,
        alias="schema",
    )
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_ref: str = Field(min_length=1, max_length=160)
    outcome: PrimitiveRecoveryOutcome
    replay_permitted: bool
    evidence_refs: list[PrimitiveEvidenceRef] = Field(min_length=1, max_length=20)
    attested_by_ref: str = Field(min_length=1, max_length=200)
    attested_at: str
    notes: str | None = Field(default=None, min_length=1, max_length=1000)

    @field_validator("operation_ref")
    @classmethod
    def _portable_operation_ref(cls, value: str) -> str:
        if not _OPERATION_REF_RE.fullmatch(value):
            raise ValueError("operation_ref must be a portable operation key")
        return value

    @field_validator("attested_by_ref")
    @classmethod
    def _visible_attestor_ref(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 33 for character in value):
            raise ValueError("attested_by_ref must contain visible characters only")
        return value

    @field_validator("attested_at")
    @classmethod
    def _attested_at_is_utc(cls, value: str) -> str:
        return _normalized_utc_timestamp(value, field_name="attested_at")

    @model_validator(mode="after")
    def _attestation_is_evidence_bound(self) -> "PrimitiveRecoveryAttestation":
        if self.replay_permitted != (
            self.outcome == PrimitiveRecoveryOutcome.EFFECT_NOT_APPLIED
        ):
            raise ValueError(
                "replay_permitted is true only when evidence proves the effect was not applied"
            )
        if any(
            evidence.verification_grade
            not in {
                PrimitiveEvidenceVerificationGrade.ATTESTED,
                PrimitiveEvidenceVerificationGrade.VERIFIED,
            }
            for evidence in self.evidence_refs
        ):
            raise ValueError(
                "recovery evidence must be attested or independently verified"
            )
        return self


class PrimitiveOperationSpec(_StrictPrimitiveContract):
    """Exact effect, replay, freshness, and recovery contract for one operation."""

    schema_id: Literal["lightbulb.primitive_operation_spec.v1"] = Field(
        default=PRIMITIVE_OPERATION_SPEC_SCHEMA,
        alias="schema",
    )
    operation_ref: str = Field(min_length=1, max_length=160)
    tool: str = Field(min_length=3, max_length=192)
    effect: ConnectorEffect
    approval_required: bool
    atomicity_group: str | None = Field(default=None, min_length=1, max_length=160)
    replay_class: PrimitiveOperationReplayClass
    freshness_class: PrimitiveOperationFreshnessClass
    recovery_policy: PrimitiveOperationRecoveryPolicy

    @field_validator("operation_ref", "atomicity_group")
    @classmethod
    def _portable_operation_refs(cls, value: str | None) -> str | None:
        if value is not None and not _OPERATION_REF_RE.fullmatch(value):
            raise ValueError(
                "operation references must be portable 1 to 160 character keys"
            )
        return value

    @field_validator("tool")
    @classmethod
    def _exact_tool_name(cls, value: str) -> str:
        if not _TOOL_NAME_RE.fullmatch(value):
            raise ValueError("tool must be an exact lowercase dotted Tool name")
        return value

    @model_validator(mode="after")
    def _effect_and_recovery_are_sound(self) -> "PrimitiveOperationSpec":
        if self.effect == ConnectorEffect.WRITE and not self.approval_required:
            raise ValueError("write operations require approval")
        if (
            self.effect != ConnectorEffect.WRITE
            and self.recovery_policy == PrimitiveOperationRecoveryPolicy.COMPENSATE
        ):
            raise ValueError("only write operations may declare compensation")
        if (
            self.recovery_policy == PrimitiveOperationRecoveryPolicy.RETRY
            and self.replay_class != PrimitiveOperationReplayClass.SAFE
        ):
            raise ValueError("retry recovery requires a safe replay class")
        if (
            self.replay_class == PrimitiveOperationReplayClass.NEVER
            and self.recovery_policy == PrimitiveOperationRecoveryPolicy.RETRY
        ):
            raise ValueError("never-replay operations cannot use retry recovery")
        return self


class PrimitiveRecoveryPlan(_StrictPrimitiveContract):
    """Bounded next action for an operation that did not reach a certain outcome."""

    schema_id: Literal["lightbulb.primitive_recovery_plan.v1"] = Field(
        default=PRIMITIVE_RECOVERY_PLAN_SCHEMA,
        alias="schema",
    )
    policy: PrimitiveOperationRecoveryPolicy
    disposition: PrimitiveRecoveryDisposition
    status_probe_tool: str | None = Field(default=None, min_length=3, max_length=192)
    compensation_operation_ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
    )
    retry_at: str | None = None
    instructions: str | None = Field(default=None, min_length=1, max_length=1000)

    @field_validator("status_probe_tool")
    @classmethod
    def _valid_status_probe_tool(cls, value: str | None) -> str | None:
        if value is not None and not _TOOL_NAME_RE.fullmatch(value):
            raise ValueError(
                "status_probe_tool must be an exact lowercase dotted Tool name"
            )
        return value

    @field_validator("compensation_operation_ref")
    @classmethod
    def _valid_compensation_ref(cls, value: str | None) -> str | None:
        if value is not None and not _OPERATION_REF_RE.fullmatch(value):
            raise ValueError("compensation_operation_ref must be portable")
        return value

    @field_validator("retry_at")
    @classmethod
    def _retry_at_is_utc(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_utc_timestamp(value, field_name="retry_at")

    @model_validator(mode="after")
    def _policy_has_required_route(self) -> "PrimitiveRecoveryPlan":
        expected_dispositions = {
            PrimitiveOperationRecoveryPolicy.NONE: PrimitiveRecoveryDisposition.NOT_REQUIRED,
            PrimitiveOperationRecoveryPolicy.RETRY: PrimitiveRecoveryDisposition.RETRY_ALLOWED,
            PrimitiveOperationRecoveryPolicy.STATUS_PROBE: PrimitiveRecoveryDisposition.STATUS_PROBE_REQUIRED,
            PrimitiveOperationRecoveryPolicy.COMPENSATE: PrimitiveRecoveryDisposition.COMPENSATION_REQUIRED,
            PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION: PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED,
        }
        if self.disposition not in {
            expected_dispositions[self.policy],
            PrimitiveRecoveryDisposition.RESOLVED,
        }:
            raise ValueError("recovery disposition does not match the recovery policy")
        if (
            self.policy == PrimitiveOperationRecoveryPolicy.STATUS_PROBE
            and self.status_probe_tool is None
        ):
            raise ValueError("status_probe recovery requires status_probe_tool")
        if (
            self.policy == PrimitiveOperationRecoveryPolicy.COMPENSATE
            and self.compensation_operation_ref is None
        ):
            raise ValueError(
                "compensation recovery requires compensation_operation_ref"
            )
        if (
            self.policy == PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION
            and self.instructions is None
        ):
            raise ValueError("manual reconciliation requires bounded instructions")
        return self


class PrimitiveOperationReceipt(_StrictPrimitiveContract):
    """Sanitized, replay-aware result for one exact primitive operation."""

    schema_id: Literal["lightbulb.primitive_operation_receipt.v1"] = Field(
        default=PRIMITIVE_OPERATION_RECEIPT_SCHEMA,
        alias="schema",
    )
    spec: PrimitiveOperationSpec
    status: PrimitiveOperationStatus
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_ref: str | None = Field(default=None, min_length=1, max_length=200)
    provenance_receipt_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    external_refs: Dict[str, str] = Field(default_factory=dict)
    evidence_refs: list[PrimitiveEvidenceRef] = Field(default_factory=list)
    attempt: int = Field(default=1, ge=1)
    replayed: bool = False
    recovery_disposition: PrimitiveRecoveryDisposition = (
        PrimitiveRecoveryDisposition.NOT_REQUIRED
    )
    recovery_plan: PrimitiveRecoveryPlan | None = None
    error: PrimitiveBlocker | None = None

    @field_validator("approval_ref")
    @classmethod
    def _visible_approval_ref(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip() or any(ord(character) < 33 for character in value)
        ):
            raise ValueError("approval_ref must contain visible characters only")
        return value

    @field_validator("external_refs")
    @classmethod
    def _bounded_external_refs(cls, value: Dict[str, str]) -> Dict[str, str]:
        if len(value) > 100:
            raise ValueError("external_refs supports at most 100 entries")
        for key, item in value.items():
            if (
                not key
                or len(key) > 80
                or not item
                or len(item) > 500
                or key != key.strip()
                or item != item.strip()
                or any(ord(character) < 33 for character in key)
                or any(ord(character) < 33 for character in item)
            ):
                raise ValueError(
                    "external_refs must contain bounded visible keys and values"
                )
        return value

    @model_validator(mode="after")
    def _receipt_proves_or_recovers_the_effect(self) -> "PrimitiveOperationReceipt":
        if (
            self.status == PrimitiveOperationStatus.COMPLETED
            and self.spec.effect == ConnectorEffect.WRITE
            and self.provenance_receipt_digest is None
        ):
            raise ValueError("completed writes require a provenance receipt digest")
        if (
            self.status == PrimitiveOperationStatus.COMPLETED
            and self.spec.effect == ConnectorEffect.WRITE
            and self.approval_ref is None
        ):
            raise ValueError("completed writes require an approval reference")
        if self.recovery_plan is not None:
            if self.recovery_plan.policy != self.spec.recovery_policy:
                raise ValueError("recovery plan policy must match the operation spec")
            if self.recovery_disposition != self.recovery_plan.disposition:
                raise ValueError("receipt and recovery plan dispositions must match")
        elif self.recovery_disposition != PrimitiveRecoveryDisposition.NOT_REQUIRED:
            raise ValueError("a recovery disposition requires a recovery plan")
        if self.status == PrimitiveOperationStatus.IN_DOUBT:
            if (
                self.recovery_plan is None
                or self.recovery_plan.disposition
                not in {
                    PrimitiveRecoveryDisposition.STATUS_PROBE_REQUIRED,
                    PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED,
                }
                or self.recovery_plan.policy
                not in {
                    PrimitiveOperationRecoveryPolicy.STATUS_PROBE,
                    PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
                }
            ):
                raise ValueError(
                    "in_doubt operations require status-probe or manual recovery"
                )
        if self.status in {
            PrimitiveOperationStatus.COMPLETED,
            PrimitiveOperationStatus.COMPENSATED,
        } and self.recovery_disposition not in {
            PrimitiveRecoveryDisposition.NOT_REQUIRED,
            PrimitiveRecoveryDisposition.RESOLVED,
        }:
            raise ValueError(
                "completed or compensated operations cannot require unresolved recovery"
            )
        return self


OutputT = TypeVar("OutputT", bound=BaseModel)
InputT = TypeVar("InputT", bound=BaseModel)
BoundaryModelT = TypeVar("BoundaryModelT", bound=BaseModel)


_MODEL_BOUNDARY_SERIALIZER = TypeAdapter(Any)


def detach_model_boundary_value(value: Any) -> Any:
    """Serialize an arbitrary graph so nested Pydantic instances cannot bypass validation."""

    if isinstance(value, Mapping) and not isinstance(value, BaseModel):
        value = dict(value)
    return _MODEL_BOUNDARY_SERIALIZER.dump_python(
        value,
        mode="python",
        by_alias=True,
        exclude_computed_fields=True,
        round_trip=True,
        warnings=False,
        serialize_as_any=True,
    )


def revalidate_model_boundary(
    model_type: type[BoundaryModelT],
    value: BoundaryModelT | Mapping[str, Any],
) -> BoundaryModelT:
    """Detach and reconstruct a complete typed graph at a public SDK boundary."""

    return model_type.model_validate(detach_model_boundary_value(value))


class PrimitiveExecutionResult(BaseModel, Generic[OutputT]):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: str = Field(default=PRIMITIVE_EXECUTION_RESULT_SCHEMA, alias="schema")
    status: PrimitiveExecutionStatus
    primitive_ref: str
    primitive_version: str
    summary: str
    output: OutputT | None = None
    events: list[PrimitiveEvent] = Field(default_factory=list)
    evidence: list[PrimitiveEvidence] = Field(default_factory=list)
    evidence_refs: list[PrimitiveEvidenceRef] = Field(default_factory=list)
    operation_receipts: list[PrimitiveOperationReceipt] = Field(default_factory=list)
    recovery_plan: PrimitiveRecoveryPlan | None = None
    blockers: list[PrimitiveBlocker] = Field(default_factory=list)
    approval_ref: str | None = None
    approval_refs: Dict[str, str] = Field(default_factory=dict)
    connector_tool: str | None = None
    retryable: bool = False

    @model_validator(mode="after")
    def _top_level_status_matches_operation_receipts(
        self,
    ) -> "PrimitiveExecutionResult[OutputT]":
        if self.status == PrimitiveExecutionStatus.COMPLETED and any(
            receipt.status
            not in {
                PrimitiveOperationStatus.COMPLETED,
                PrimitiveOperationStatus.COMPENSATED,
            }
            for receipt in self.operation_receipts
        ):
            raise ValueError(
                "a completed primitive cannot contain unresolved operation receipts"
            )
        if self.status == PrimitiveExecutionStatus.PREVIEW and any(
            receipt.status
            not in {
                PrimitiveOperationStatus.PLANNED,
                PrimitiveOperationStatus.PREVIEW,
            }
            for receipt in self.operation_receipts
        ):
            raise ValueError(
                "a preview primitive can contain only planned or preview receipts"
            )
        return self

    def unresolved_operation_receipts(self) -> list[PrimitiveOperationReceipt]:
        unresolved_dispositions = {
            PrimitiveRecoveryDisposition.RETRY_ALLOWED,
            PrimitiveRecoveryDisposition.STATUS_PROBE_REQUIRED,
            PrimitiveRecoveryDisposition.COMPENSATION_REQUIRED,
            PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED,
        }
        return [
            receipt
            for receipt in self.operation_receipts
            if receipt.status == PrimitiveOperationStatus.IN_DOUBT
            or receipt.recovery_disposition in unresolved_dispositions
        ]

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


EventSink = Callable[[PrimitiveEvent], None]


@dataclass(frozen=True)
class PrimitiveExecutionContext:
    scope: ExecutionScope
    connectors: ConnectorExecutor
    preview_only: bool = True
    run_ref: str = field(default_factory=lambda: f"run-{uuid4()}")
    idempotency_key: str | None = None
    approval_refs: Mapping[str, str] = field(default_factory=dict)
    connector_account_refs: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    event_sink: EventSink | None = None
    outcome_recorder: RuntimeOutcomeRecorder | None = None
    writes_require_approval: bool = True
    primitive_version: str | None = None
    step_id: str | None = None
    step_execution_ref: str | None = None

    def approval_ref_for(
        self,
        primitive_ref: str,
        *,
        operation_ref: str | None = None,
    ) -> str | None:
        key = str(primitive_ref).strip().lower()
        if operation_ref is not None:
            clean_operation_ref = str(operation_ref).strip().lower()
            if not _OPERATION_REF_RE.fullmatch(clean_operation_ref):
                raise ValueError(
                    "operation_ref must be a portable 1 to 160 character key"
                )
            key = f"{key}#{clean_operation_ref}"
        value = self.approval_refs.get(key)
        return str(value).strip() if value is not None and str(value).strip() else None

    def step_context(
        self,
        step_id: str,
        *,
        execution_ref: str | None = None,
    ) -> "PrimitiveExecutionContext":
        clean_step = str(step_id).strip()
        if not clean_step:
            raise ValueError("step_id is required")
        clean_execution_ref = (
            str(execution_ref).strip() if execution_ref is not None else None
        )
        if execution_ref is not None and (
            not clean_execution_ref or len(clean_execution_ref) > 200
        ):
            raise ValueError("execution_ref must contain 1 to 200 characters")
        return replace(
            self,
            step_id=clean_step,
            step_execution_ref=clean_execution_ref,
            metadata={**dict(self.metadata), "step_id": clean_step},
        )

    def connector_request(
        self,
        *,
        primitive_ref: str,
        tool: str,
        arguments: Mapping[str, Any],
        effect: ConnectorEffect,
        approval_required: bool,
        operation_ref: str | None = None,
        connector_account_ref: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ConnectorExecutionRequest:
        if operation_ref is not None and not isinstance(operation_ref, str):
            raise ValueError("operation_ref must be a portable 1 to 160 character key")
        clean_operation_ref = (
            operation_ref.strip().lower() if operation_ref is not None else None
        )
        if clean_operation_ref is not None and not _OPERATION_REF_RE.fullmatch(
            clean_operation_ref
        ):
            raise ValueError("operation_ref must be a portable 1 to 160 character key")
        idempotency_key = None
        if effect == ConnectorEffect.WRITE:
            operation_parts = (
                (clean_operation_ref,) if clean_operation_ref is not None else ()
            )
            idempotency_key = self._derived_key(
                "connector",
                primitive_ref,
                self.primitive_version or "unknown",
                tool.strip().lower(),
                *operation_parts,
            )
        effective_approval_required = bool(
            approval_required
            or (self.writes_require_approval and effect == ConnectorEffect.WRITE)
        )
        resolved_account_ref = connector_account_ref
        if resolved_account_ref is None:
            account_keys = [tool.strip().lower()]
            if clean_operation_ref is not None:
                account_keys.insert(0, clean_operation_ref)
            account_keys.append(tool.split(".", 1)[0].strip().lower())
            for account_key in account_keys:
                candidate = self.connector_account_refs.get(account_key)
                if candidate is not None and str(candidate).strip():
                    resolved_account_ref = str(candidate).strip()
                    break
        return ConnectorExecutionRequest(
            tool=tool,
            arguments=dict(arguments),
            scope=self.scope,
            connector_account_ref=resolved_account_ref,
            effect=effect,
            approval_required=effective_approval_required,
            approval_ref=self.approval_ref_for(
                primitive_ref,
                operation_ref=clean_operation_ref,
            ),
            preview_only=self.preview_only,
            idempotency_key=idempotency_key,
            metadata={
                "primitive_ref": primitive_ref,
                **(
                    {"operation_ref": clean_operation_ref}
                    if clean_operation_ref is not None
                    else {}
                ),
                **dict(metadata or {}),
            },
        )

    def emit(self, events: Iterable[PrimitiveEvent]) -> None:
        if self.event_sink is None:
            return
        for event in events:
            self.event_sink(event)

    def _derived_key(self, *parts: str) -> str:
        root = self.idempotency_key or self.run_ref
        material = "|".join(
            [
                root,
                self.scope.project_ref,
                str(self.scope.project_id or ""),
                self.step_execution_ref or self.step_id or "",
                *parts,
            ]
        ).encode("utf-8")
        return "lb-" + hashlib.sha256(material).hexdigest()


class _SchemaRevision:
    """Retain the schema object so identity cannot be reused after a rebuild."""
    def __init__(self, schema):
        self.schema = schema

    def __hash__(self):
        return id(self.schema)

    def __eq__(self, other):
        return isinstance(other, _SchemaRevision) and self.schema is other.schema


@lru_cache(maxsize=2048)
def _cached_implementation_schema(model, core_schema_revision, schema_factory):
    # Pydantic replaces the core schema on model_rebuild. Including both that
    # revision and the factory preserves explicit schema customizations.
    return model.model_json_schema()


def _implementation_schema(model):
    factory = model.model_json_schema
    return deepcopy(_cached_implementation_schema(model, _SchemaRevision(model.__pydantic_core_schema__),
        getattr(factory, "__func__", factory)))


class BusinessProcessPrimitive(ABC, Generic[InputT, OutputT]):
    primitive_ref: ClassVar[str]
    version: ClassVar[str] = "1.0.0"
    title: ClassVar[str]
    description: ClassVar[str] = ""
    input_model: ClassVar[type[BaseModel]]
    output_model: ClassVar[type[BaseModel]]
    connector_tools: ClassVar[tuple[str, ...]] = ()
    risk_level: ClassVar[str] = "low"
    approval_required: ClassVar[bool] = False
    example_inputs: ClassVar[Mapping[str, Any]] = {}
    mcp_read_only: ClassVar[bool] = False
    mcp_destructive: ClassVar[bool] = True
    mcp_idempotent: ClassVar[bool] = False
    mcp_open_world: ClassVar[bool] = True

    def execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: InputT | Mapping[str, Any],
    ) -> PrimitiveExecutionResult[OutputT]:
        started = time.monotonic()
        try:
            parsed = revalidate_model_boundary(self.input_model, inputs)
        except (PydanticValidationError, PydanticSerializationError) as exc:
            if isinstance(exc, PydanticValidationError):
                blockers = [
                    PrimitiveBlocker(
                        code=str(error.get("type") or "invalid_input"),
                        message=str(error.get("msg") or "Invalid primitive input")[
                            :500
                        ],
                        field=".".join(str(part) for part in error.get("loc", ()))
                        or None,
                    )
                    for error in exc.errors(include_input=False, include_url=False)
                ]
            else:
                blockers = [
                    PrimitiveBlocker(
                        code="invalid_input",
                        message="Primitive input could not be normalized for validation.",
                    )
                ]
            result = PrimitiveExecutionResult[OutputT](
                status=PrimitiveExecutionStatus.NEEDS_INPUT,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Primitive input validation failed.",
                blockers=blockers,
            )
            self._record_outcome(context, result, started)
            return result

        try:
            result = self._execute(context, parsed)  # type: ignore[arg-type]
            if result.output is not None:
                result = result.model_copy(
                    update={
                        "output": revalidate_model_boundary(
                            self.output_model, result.output
                        )
                    }
                )
            if (
                result.primitive_ref != self.primitive_ref
                or result.primitive_version != self.version
            ):
                result = result.model_copy(
                    update={
                        "primitive_ref": self.primitive_ref,
                        "primitive_version": self.version,
                    }
                )
            context.emit(result.events)
        except Exception as exc:
            self._record_outcome(context, None, started, exception=exc)
            raise
        self._record_outcome(context, result, started)
        return result

    def _record_outcome(
        self,
        context: PrimitiveExecutionContext,
        result: PrimitiveExecutionResult[OutputT] | None,
        started: float,
        *,
        exception: Exception | None = None,
    ) -> None:
        recorder = context.outcome_recorder
        if recorder is None:
            return
        status = result.status.value if result is not None else "failed"
        if result is not None and result.approval_ref:
            approval_state = "approved"
        elif status == PrimitiveExecutionStatus.PENDING_APPROVAL.value:
            approval_state = "pending"
        elif status == PrimitiveExecutionStatus.PREVIEW.value:
            approval_state = "preview"
        elif self.approval_required:
            approval_state = "not_requested"
        else:
            approval_state = "not_required"
        error_kind = type(exception).__name__ if exception is not None else None
        if error_kind is None and result is not None and result.blockers:
            error_kind = result.blockers[0].code
        try:
            recorder.record(
                RuntimeOutcome(
                    primitive_ref=self.primitive_ref,
                    status=status,
                    latency_ms=round((time.monotonic() - started) * 1000.0, 3),
                    approval_state=approval_state,
                    error_kind=error_kind,
                    harness=str(context.metadata.get("source") or "lightbulb_sdk"),
                    project_ref=context.scope.project_ref,
                    workflow_key=(
                        str(context.metadata.get("workflow_key"))
                        if context.metadata.get("workflow_key")
                        else None
                    ),
                    run_ref=context.run_ref,
                    step_id=(
                        str(context.metadata.get("step_id"))
                        if context.metadata.get("step_id")
                        else None
                    ),
                )
            )
        except Exception as exc:  # telemetry is fail-open for business execution
            logger.warning("runtime outcome recorder failed: %s", exc)

    @abstractmethod
    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: InputT,
    ) -> PrimitiveExecutionResult[OutputT]: ...

    def implementation_contract(self) -> Dict[str, Any]:
        return {
            "schema": PRIMITIVE_IMPLEMENTATION_SCHEMA,
            "primitive_ref": self.primitive_ref,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "risk_level": self.risk_level,
            "approval_required": self.approval_required,
            "connector_tools": list(self.connector_tools),
            "example_inputs": dict(self.example_inputs),
            "input_schema": _implementation_schema(self.input_model),
            "output_schema": _implementation_schema(self.output_model),
            "mcp_annotations": {
                "readOnlyHint": self.mcp_read_only,
                "destructiveHint": self.mcp_destructive,
                "idempotentHint": self.mcp_idempotent,
                "openWorldHint": self.mcp_open_world,
            },
            "runtime_guarantees": {
                "project_scope_required": True,
                "writes_require_idempotency": True,
                "preview_writes_have_no_side_effects": True,
                "writes_require_approval": True,
                "connector_tools_are_declared": True,
                "events_are_structured": True,
                "typed_evidence_refs": True,
                "typed_operation_receipts": True,
                "typed_recovery_plans": True,
                "completed_writes_require_provenance": True,
                "in_doubt_requires_recovery": True,
            },
        }


PrimitiveHandler = Callable[
    [PrimitiveExecutionContext, BaseModel],
    PrimitiveExecutionResult[Any] | BaseModel | Mapping[str, Any],
]


class FunctionBusinessProcessPrimitive(BusinessProcessPrimitive[BaseModel, BaseModel]):
    def __init__(
        self,
        *,
        primitive_ref: str,
        title: str,
        input_model: type[BaseModel],
        output_model: type[BaseModel],
        handler: PrimitiveHandler,
        version: str = "1.0.0",
        description: str = "",
        connector_tools: Iterable[str] = (),
        risk_level: str = "low",
        approval_required: bool = False,
    ) -> None:
        self.primitive_ref = primitive_ref
        self.title = title
        self.input_model = input_model
        self.output_model = output_model
        self._handler = handler
        self.version = version
        self.description = description
        self.connector_tools = tuple(connector_tools)
        self.risk_level = risk_level
        self.approval_required = approval_required

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: BaseModel,
    ) -> PrimitiveExecutionResult[BaseModel]:
        value = self._handler(context, inputs)
        if isinstance(value, PrimitiveExecutionResult):
            return value
        output = (
            value
            if isinstance(value, self.output_model)
            else self.output_model.model_validate(value)
        )
        return PrimitiveExecutionResult[BaseModel](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=f"{self.title} completed.",
            output=output,
        )


def business_process_primitive(
    *,
    primitive_ref: str,
    title: str,
    input_model: type[BaseModel],
    output_model: type[BaseModel],
    version: str = "1.0.0",
    description: str = "",
    connector_tools: Iterable[str] = (),
    risk_level: str = "low",
    approval_required: bool = False,
) -> Callable[[PrimitiveHandler], FunctionBusinessProcessPrimitive]:
    """Turn a typed function into a registry-ready custom primitive."""

    def decorate(handler: PrimitiveHandler) -> FunctionBusinessProcessPrimitive:
        return FunctionBusinessProcessPrimitive(
            primitive_ref=primitive_ref,
            title=title,
            input_model=input_model,
            output_model=output_model,
            handler=handler,
            version=version,
            description=description,
            connector_tools=connector_tools,
            risk_level=risk_level,
            approval_required=approval_required,
        )

    return decorate


class PrimitiveRegistry:
    def __init__(
        self, primitives: Iterable[BusinessProcessPrimitive[Any, Any]] = ()
    ) -> None:
        self._primitives: Dict[str, BusinessProcessPrimitive[Any, Any]] = {}
        for primitive in primitives:
            self.register(primitive)

    def register(
        self,
        primitive: BusinessProcessPrimitive[Any, Any],
        *,
        replace_existing: bool = False,
    ) -> None:
        primitive_ref = str(primitive.primitive_ref).strip().lower()
        if not primitive_ref or "." not in primitive_ref:
            raise ValueError("primitive_ref must be a dotted business capability name")
        if primitive_ref in self._primitives and not replace_existing:
            raise ValueError(f"Primitive already registered: {primitive_ref}")
        self._primitives[primitive_ref] = primitive

    def get(self, primitive_ref: str) -> BusinessProcessPrimitive[Any, Any]:
        normalized = str(primitive_ref).strip().lower()
        try:
            return self._primitives[normalized]
        except KeyError as exc:
            raise KeyError(
                f"No executable primitive is registered for {primitive_ref}"
            ) from exc

    def supports(self, primitive_ref: str) -> bool:
        return str(primitive_ref).strip().lower() in self._primitives

    def execute(
        self,
        primitive_ref: str,
        context: PrimitiveExecutionContext,
        inputs: Mapping[str, Any] | BaseModel,
    ) -> PrimitiveExecutionResult[Any]:
        return self.get(primitive_ref).execute(context, inputs)

    def catalog(self) -> list[Dict[str, Any]]:
        return [
            self._primitives[key].implementation_contract()
            for key in sorted(self._primitives)
        ]

    def copy(self) -> "PrimitiveRegistry":
        return PrimitiveRegistry(self._primitives.values())


@dataclass(frozen=True)
class PrimitiveCall:
    """One typed request inside an opened Primitive Run Session."""

    primitive_ref: str
    inputs: Mapping[str, Any] | BaseModel
    step_id: str | None = None
    execution_ref: str | None = None
    primitive_version: str | None = None


@dataclass(frozen=True)
class PrimitiveCorrelation:
    """Governed, non-payload correlation fields emitted with runtime outcomes."""

    source: str = "lightbulb_sdk"
    workflow_key: str | None = None


@dataclass(frozen=True)
class StandalonePrimitiveRun:
    """Semantic profile for a primitive that is not owned by a Project Runtime."""

    scope: ExecutionScope
    run_ref: str
    mode: PrimitiveRunMode = PrimitiveRunMode.PREVIEW
    approval_refs: Mapping[str, str] = field(default_factory=dict)
    connector_account_refs: Mapping[str, str] = field(default_factory=dict)
    correlation: PrimitiveCorrelation = field(default_factory=PrimitiveCorrelation)
    idempotency_key: str | None = None


@dataclass(frozen=True)
class ProjectPrimitiveRun:
    """Semantic profile whose capabilities and policy come from a Lightbulb Project."""

    project: "LightbulbProject"
    scope: ExecutionScope
    run_ref: str
    mode: PrimitiveRunMode | None = None
    approval_refs: Mapping[str, str] = field(default_factory=dict)
    connector_account_refs: Mapping[str, str] = field(default_factory=dict)
    correlation: PrimitiveCorrelation = field(default_factory=PrimitiveCorrelation)
    idempotency_key: str | None = None


@dataclass(frozen=True)
class _OpenedPrimitiveRun:
    scope: ExecutionScope
    run_ref: str
    preview_only: bool
    idempotency_key: str | None
    approval_refs: Mapping[str, str]
    connector_account_refs: Mapping[str, str]
    metadata: Mapping[str, Any]
    allowed_primitive_refs: frozenset[str] | None = None
    allowed_connector_tools: frozenset[str] | None = None


class _DeclaredConnectorExecutor:
    """Intersect primitive and optional Project Tool contracts with clear receipts."""

    def __init__(
        self,
        inner: ConnectorExecutor,
        primitive_tools: frozenset[str],
        project_tools: frozenset[str] | None,
    ) -> None:
        self._inner = inner
        self._primitive_tools = primitive_tools
        self._project_tools = project_tools

    def supports(self, tool: str) -> bool:
        normalized = str(tool).strip().lower()
        return bool(
            normalized in self._primitive_tools
            and (self._project_tools is None or normalized in self._project_tools)
            and self._inner.supports(normalized)
        )

    def execute(self, request: ConnectorExecutionRequest) -> ConnectorExecutionResult:
        if request.tool not in self._primitive_tools:
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.BLOCKED,
                tool=request.tool,
                message="The Tool is not declared by this Executable Primitive.",
                error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                error_code="primitive_tool_not_declared",
            )
        if self._project_tools is not None and request.tool not in self._project_tools:
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.BLOCKED,
                tool=request.tool,
                message="The Tool is not declared by this Lightbulb Project.",
                error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                error_code="project_tool_not_allowed",
            )
        return self._inner.execute(request)


class PrimitiveRunSession:
    """Deep execution interface for every call in one immutable scoped run."""

    def __init__(
        self,
        runtime: "ExecutablePrimitiveRuntime",
        run: _OpenedPrimitiveRun,
    ) -> None:
        self._runtime = runtime
        self._run = run
        self._events: list[PrimitiveEvent] = []

    @property
    def events(self) -> tuple[PrimitiveEvent, ...]:
        return tuple(self._events)

    def execute(self, call: PrimitiveCall) -> PrimitiveExecutionResult[Any]:
        primitive_ref = str(call.primitive_ref).strip().lower()
        if not primitive_ref or "." not in primitive_ref:
            return self._blocked(
                primitive_ref or "unknown",
                "invalid_primitive_ref",
                "primitive_ref must be a dotted business capability name.",
            )
        if (
            self._run.allowed_primitive_refs is not None
            and primitive_ref not in self._run.allowed_primitive_refs
        ):
            return self._blocked(
                primitive_ref,
                "project_primitive_not_allowed",
                "The Executable Primitive is not declared by this Lightbulb Project.",
            )
        try:
            primitive = self._runtime._registry.get(primitive_ref)
        except KeyError:
            return self._blocked(
                primitive_ref,
                "primitive_not_registered",
                "No executable implementation is registered.",
            )

        requested_version = str(call.primitive_version or "").strip()
        if requested_version and requested_version != primitive.version:
            return self._blocked(
                primitive_ref,
                "primitive_version_mismatch",
                "The requested primitive version is not the registered implementation version.",
                primitive_version=primitive.version,
            )

        declared_tools = frozenset(
            str(tool).strip().lower()
            for tool in primitive.connector_tools
            if str(tool).strip()
        )
        connectors = _DeclaredConnectorExecutor(
            self._runtime._connectors,
            declared_tools,
            self._run.allowed_connector_tools,
        )
        context = PrimitiveExecutionContext(
            scope=self._run.scope,
            connectors=connectors,
            preview_only=self._run.preview_only,
            run_ref=self._run.run_ref,
            idempotency_key=self._run.idempotency_key,
            approval_refs=self._run.approval_refs,
            connector_account_refs=self._run.connector_account_refs,
            metadata=self._run.metadata,
            event_sink=self._publish_event,
            outcome_recorder=self._runtime._outcome_recorder,
            writes_require_approval=True,
            primitive_version=primitive.version,
        )
        if call.execution_ref is not None and call.step_id is None:
            return self._blocked(
                primitive_ref,
                "invalid_execution_ref",
                "execution_ref requires a step_id.",
                primitive_version=primitive.version,
            )
        if call.step_id is not None:
            try:
                context = context.step_context(
                    call.step_id,
                    execution_ref=call.execution_ref,
                )
            except ValueError:
                return self._blocked(
                    primitive_ref,
                    "invalid_step_id",
                    "step_id must not be blank.",
                    primitive_version=primitive.version,
                )
        try:
            return primitive.execute(context, call.inputs)
        except Exception:
            logger.exception(
                "Executable Primitive failed: primitive_ref=%s run_ref=%s",
                primitive_ref,
                self._run.run_ref,
            )
            return PrimitiveExecutionResult[Any](
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=primitive_ref,
                primitive_version=primitive.version,
                summary="Executable Primitive failed.",
                blockers=[
                    PrimitiveBlocker(
                        code="primitive_execution_failed",
                        message="The primitive implementation failed safely.",
                        retryable=True,
                    )
                ],
                retryable=True,
            )

    def _publish_event(self, event: PrimitiveEvent) -> None:
        parsed = PrimitiveEvent.model_validate(event)
        self._events.append(parsed)
        publisher = self._runtime._event_publisher
        if publisher is None:
            return
        try:
            publisher(parsed)
        except Exception as exc:  # event telemetry must not alter business execution
            logger.warning("primitive event publisher failed: %s", exc)

    @staticmethod
    def _blocked(
        primitive_ref: str,
        code: str,
        message: str,
        *,
        primitive_version: str = "unknown",
    ) -> PrimitiveExecutionResult[Any]:
        return PrimitiveExecutionResult[Any](
            status=PrimitiveExecutionStatus.BLOCKED,
            primitive_ref=primitive_ref,
            primitive_version=primitive_version,
            summary=message,
            blockers=[PrimitiveBlocker(code=code, message=message)],
        )


class ExecutablePrimitiveRuntime:
    """Open governed Primitive Run Sessions over stable runtime dependencies."""

    def __init__(
        self,
        registry: PrimitiveRegistry,
        connectors: ConnectorExecutor,
        *,
        outcome_recorder: RuntimeOutcomeRecorder | None = None,
        event_publisher: EventSink | None = None,
    ) -> None:
        self._registry = registry
        self._connectors = connectors
        self._outcome_recorder = outcome_recorder
        self._event_publisher = event_publisher

    def open(
        self,
        run: StandalonePrimitiveRun | ProjectPrimitiveRun,
    ) -> PrimitiveRunSession:
        run_ref = str(run.run_ref).strip()
        if not run_ref:
            raise ValueError("run_ref is required")
        idempotency_key = None
        if run.idempotency_key is not None:
            if not isinstance(run.idempotency_key, str):
                raise TypeError("idempotency_key must be a string")
            idempotency_key = run.idempotency_key.strip()
            if (
                not idempotency_key
                or len(idempotency_key) > 200
                or any(ord(character) < 33 for character in idempotency_key)
            ):
                raise ValueError(
                    "idempotency_key must contain 1 to 200 visible characters"
                )
        approvals = {
            str(key).strip().lower(): str(value).strip()
            for key, value in run.approval_refs.items()
            if str(key).strip() and str(value).strip()
        }
        connector_accounts: Dict[str, str] = {}
        for raw_key, raw_value in run.connector_account_refs.items():
            key = str(raw_key).strip().lower()
            value = str(raw_value).strip()
            if not key or not value:
                raise ValueError(
                    "connector_account_refs cannot contain blank keys or values"
                )
            if not _OPERATION_REF_RE.fullmatch(key):
                raise ValueError(
                    "connector_account_refs keys must be portable operation, Tool, or provider names"
                )
            if len(value) > 200 or any(ord(character) < 33 for character in value):
                raise ValueError(
                    "connector_account_refs values must be 1-200 visible characters"
                )
            if key in connector_accounts:
                raise ValueError(
                    "connector_account_refs keys must remain unique after normalization"
                )
            connector_accounts[key] = value
        source = str(run.correlation.source).strip() or "lightbulb_sdk"
        workflow_key = (
            str(run.correlation.workflow_key).strip()
            if run.correlation.workflow_key is not None
            else None
        )
        metadata: Dict[str, Any] = {"source": source}
        if workflow_key:
            metadata["workflow_key"] = workflow_key

        allowed_primitives: frozenset[str] | None = None
        allowed_tools: frozenset[str] | None = None
        mode = run.mode
        if isinstance(run, ProjectPrimitiveRun):
            project = run.project
            if run.scope.project_ref != project.project_ref:
                raise ValueError(
                    "ExecutionScope project_ref does not match the Lightbulb Project"
                )
            if run.scope.project_id != project.hosted_project_id:
                raise ValueError(
                    "ExecutionScope project_id does not match the Lightbulb Project"
                )
            allowed_primitives = frozenset(project.primitive_refs)
            allowed_tools = frozenset(project.connector_tools)
            metadata["project_version"] = project.version
            if mode is None:
                mode = (
                    PrimitiveRunMode.PREVIEW
                    if project.policy.default_preview_only
                    else PrimitiveRunMode.APPLY
                )
        if mode is None:
            mode = PrimitiveRunMode.PREVIEW
        try:
            normalized_mode = PrimitiveRunMode(mode)
        except ValueError as exc:
            raise ValueError("mode must be 'preview' or 'apply'") from exc

        opened = _OpenedPrimitiveRun(
            scope=run.scope,
            run_ref=run_ref,
            preview_only=normalized_mode == PrimitiveRunMode.PREVIEW,
            idempotency_key=idempotency_key,
            approval_refs=approvals,
            connector_account_refs=connector_accounts,
            metadata=metadata,
            allowed_primitive_refs=allowed_primitives,
            allowed_connector_tools=allowed_tools,
        )
        return PrimitiveRunSession(self, opened)


__all__ = [
    "PRIMITIVE_EVIDENCE_REF_SCHEMA",
    "PRIMITIVE_EXECUTION_RESULT_SCHEMA",
    "PRIMITIVE_IMPLEMENTATION_SCHEMA",
    "PRIMITIVE_OPERATION_RECEIPT_SCHEMA",
    "PRIMITIVE_OPERATION_SPEC_SCHEMA",
    "PRIMITIVE_RECOVERY_ATTESTATION_SCHEMA",
    "PRIMITIVE_RECOVERY_PLAN_SCHEMA",
    "BusinessProcessPrimitive",
    "ExecutablePrimitiveRuntime",
    "FunctionBusinessProcessPrimitive",
    "PrimitiveCall",
    "PrimitiveBlocker",
    "PrimitiveCorrelation",
    "PrimitiveEvent",
    "PrimitiveEvidence",
    "PrimitiveEvidenceClassification",
    "PrimitiveEvidenceRef",
    "PrimitiveEvidenceVerificationGrade",
    "PrimitiveExecutionContext",
    "PrimitiveExecutionResult",
    "PrimitiveExecutionStatus",
    "PrimitiveRunMode",
    "PrimitiveRunSession",
    "PrimitiveRegistry",
    "PrimitiveOperationFreshnessClass",
    "PrimitiveOperationReceipt",
    "PrimitiveOperationRecoveryPolicy",
    "PrimitiveOperationReplayClass",
    "PrimitiveOperationSpec",
    "PrimitiveOperationStatus",
    "PrimitiveRecoveryAttestation",
    "PrimitiveRecoveryDisposition",
    "PrimitiveRecoveryOutcome",
    "PrimitiveRecoveryPlan",
    "ProjectPrimitiveRun",
    "StandalonePrimitiveRun",
    "business_process_primitive",
    "detach_model_boundary_value",
    "revalidate_model_boundary",
]
