"""Typed projections of Spring-owned Golden Operating Loop runs.

This module is deliberately a client contract, not a workflow runtime.  It
normalizes the small amount of state every access surface must preserve while
leaving tenant scope, RBAC, approval, connector custody, persistence, and live
effects with the Spring Control Plane.

The detailed authority response models are strict and versioned.  Their
``projection`` property removes internal database identifiers and produces the
same canonical run identity/state envelope used by SDK, MCP, managed-agent, and
optional ChatGPT projections.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Mapping

from typing_extensions import Self

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

GOLDEN_LOOP_RUN_PROJECTION_SCHEMA = "lightbulb.golden_loop_run_projection.v1"
GOLDEN_LOOP_ECONOMIC_CLOSURE_PROJECTION_SCHEMA = (
    "lightbulb.golden_loop_economic_closure_projection.v2"
)
PROJECT_WORK_PACKET_START_SCHEMA = "lightbulb.project_work_packet_start.v1"
PROJECT_WORK_PACKET_RUN_SCHEMA = "lightbulb.project_work_packet_run.v1"
GOVERNED_COMMUNICATION_RUN_SCHEMA = "lightbulb.governed_communication_run.v1"
GOVERNED_COMMUNICATION_ADMISSION_SCHEMA = (
    "lightbulb.governed_communication_admission.v1"
)
SERVICE_CASE_RESOLUTION_CANDIDATE_SCHEMA = (
    "lightbulb.service_case_resolution_candidate.v1"
)
SERVICE_CASE_RESOLUTION_RUN_SCHEMA = "lightbulb.service_case_resolution_run.v1"
SERVICE_CASE_RESOLUTION_RECEIPT_SCHEMA = (
    "lightbulb.service_case_customer_verified_resolution_receipt.v1"
)
GOVERNED_COMMUNICATION_SOURCE_PAGE_SCHEMA = (
    "lightbulb.governed_communication_source_page.v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_MODEL_EXECUTION_RUN_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_PORTABLE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$")
_ACCOUNT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,199}$")
_SEMVER_PATTERN = (
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_RUN_PATTERNS = {
    "finance.journal_post_readback_settlement": re.compile(r"^fjr_[a-f0-9]{32}$"),
    "revenue.governed_crm_turn_verified_reply": re.compile(r"^gcr_[a-f0-9]{32}$"),
    "project.work_packet_independent_acceptance": re.compile(
        r"^dwr_[A-Za-z0-9_-]{16,64}$"
    ),
    "service.case_customer_verified_resolution": re.compile(r"^scr_[a-f0-9]{32}$"),
    "finance.contract_to_cash_collected_cash": re.compile(r"^ctr_[a-f0-9]{32}$"),
    "procurement.approved_commitment_to_matched_close": re.compile(
        r"^ppr_[a-f0-9]{32}$"
    ),
    "finance.period_reconciliation_approved_close_candidate": re.compile(
        r"^pcr_[a-f0-9]{32}$"
    ),
    "workflow.verified_evidence_to_publish_approval": re.compile(
        r"^wir_[a-f0-9]{32}$"
    ),
}
_ECONOMIC_BASE_REQUIRED_SOURCES = ("MODEL_PROVIDER", "CONNECTOR_RUNTIME")
_ECONOMIC_WITH_HARNESS_REQUIRED_SOURCES = (
    *_ECONOMIC_BASE_REQUIRED_SOURCES,
    "CODING_HARNESS",
)
_SENSITIVE_KEY_PARTS = {
    "access_token",
    "api_key",
    "authorization",
    "client_secret",
    "credential",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session_receipt",
    "signing_key",
}


class GoldenLoopProjectionError(ValueError):
    """A projection did not match the exact reviewed authority contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class GoldenLoopRef(str, Enum):
    FINANCE_JOURNAL = "finance.journal_post_readback_settlement"
    PROJECT_WORK_PACKET = "project.work_packet_independent_acceptance"
    REVENUE_VERIFIED_REPLY = "revenue.governed_crm_turn_verified_reply"
    SERVICE_VERIFIED_RESOLUTION = "service.case_customer_verified_resolution"
    CONTRACT_TO_CASH = "finance.contract_to_cash_collected_cash"
    PROCUREMENT_MATCHED_CLOSE = "procurement.approved_commitment_to_matched_close"
    PERIOD_RECONCILIATION = (
        "finance.period_reconciliation_approved_close_candidate"
    )
    VERIFIED_IMPROVEMENT = "workflow.verified_evidence_to_publish_approval"


_RUN_PREFIX_TO_LOOP = {
    "fjr_": GoldenLoopRef.FINANCE_JOURNAL,
    "dwr_": GoldenLoopRef.PROJECT_WORK_PACKET,
    "gcr_": GoldenLoopRef.REVENUE_VERIFIED_REPLY,
    "scr_": GoldenLoopRef.SERVICE_VERIFIED_RESOLUTION,
    "ctr_": GoldenLoopRef.CONTRACT_TO_CASH,
    "ppr_": GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE,
    "pcr_": GoldenLoopRef.PERIOD_RECONCILIATION,
    "wir_": GoldenLoopRef.VERIFIED_IMPROVEMENT,
}


def canonical_golden_loop_run_ref(value: object) -> str:
    """Validate one exact run identity accepted by Spring's eight loop authorities."""

    exact = str(value or "").strip()
    if not any(pattern.fullmatch(exact) for pattern in _RUN_PATTERNS.values()):
        raise ValueError("run_ref must be a canonical Golden Loop reference")
    return exact


class GoldenLoopOperation(str, Enum):
    START = "start"
    GET = "get"
    ADVANCE = "advance"
    CANCEL = "cancel"
    STEP = "step"


class GoldenLoopOperationAvailability(str, Enum):
    PUBLIC = "PUBLIC"
    ROLE_PROTOCOL_ONLY = "ROLE_PROTOCOL_ONLY"
    WORKER_ONLY = "WORKER_ONLY"
    BLOCKED = "BLOCKED"


class GoldenLoopProjectionParticipation(str, Enum):
    CALLABLE = "CALLABLE"
    CANDIDATE_ONLY = "CANDIDATE_ONLY"
    BLOCKED = "BLOCKED"


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


def _normalize_timestamp(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ValueError(f"{label} must be a nonblank ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _reject_sensitive_keys(value: Any, *, path: str = "response") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_")
            if normalized in _SENSITIVE_KEY_PARTS or any(
                normalized.endswith(f"_{part}") for part in _SENSITIVE_KEY_PARTS
            ):
                raise GoldenLoopProjectionError(
                    "golden_loop.sensitive_field_rejected",
                    f"{path}.{key} is not permitted in a Golden Loop projection",
                )
            _reject_sensitive_keys(child, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive_keys(child, path=f"{path}[{index}]")


class GoldenLoopOperationContract(_StrictModel):
    operation: GoldenLoopOperation
    availability: GoldenLoopOperationAvailability
    endpoint_template: str | None = Field(default=None, min_length=1, max_length=300)
    sdk_entrypoint_ref: str | None = Field(default=None, min_length=1, max_length=300)
    authority_run_extraction_path: Literal["$", "$.run"] | None = None
    response_schema: str | None = Field(
        default=None,
        pattern=r"^lightbulb\.[a-z][a-z0-9_.]{0,158}\.v[1-9][0-9]*$",
    )
    blocker_code: str | None = Field(default=None, min_length=1, max_length=200)

    @model_validator(mode="after")
    def _availability_is_explicit(self) -> Self:
        available = self.availability in {
            GoldenLoopOperationAvailability.PUBLIC,
            GoldenLoopOperationAvailability.ROLE_PROTOCOL_ONLY,
        }
        if available != (self.endpoint_template is not None):
            raise ValueError(
                "callable operations require an endpoint; non-public operations must not "
                "advertise one"
            )
        if available != (self.sdk_entrypoint_ref is not None):
            raise ValueError(
                "callable operations require one exact SDK entrypoint; non-public "
                "operations must not advertise one"
            )
        if available != (self.authority_run_extraction_path is not None):
            raise ValueError(
                "callable operations require one exact authority run extraction path"
            )
        if self.sdk_entrypoint_ref is not None and not re.fullmatch(
            r"lightbulb\.client\.LightbulbClient\.[a-z][a-z0-9_]{0,99}",
            self.sdk_entrypoint_ref,
        ):
            raise ValueError("SDK entrypoint must name one LightbulbClient method")
        if (self.blocker_code is None) != available:
            raise ValueError(
                "non-public operations require an exact blocker_code; callable operations "
                "must not declare one"
            )
        if not available and self.response_schema is not None:
            raise ValueError("blocked operations must not advertise a response schema")
        return self


class GoldenLoopProjectionDescriptor(_StrictModel):
    loop_ref: GoldenLoopRef
    loop_version: str = Field(
        max_length=32,
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$",
    )
    run_ref_prefix: Literal[
        "fjr_", "dwr_", "gcr_", "scr_", "ctr_", "ppr_", "pcr_", "wir_"
    ]
    lifecycle: Literal["QUARANTINED"] = "QUARANTINED"
    operations: tuple[GoldenLoopOperationContract, ...] = Field(
        min_length=4,
        max_length=5,
    )

    @field_validator("operations", mode="before")
    @classmethod
    def _operations_tuple(cls, value: Any) -> Any:
        return tuple(value)

    @model_validator(mode="after")
    def _operations_are_complete_and_unique(self) -> Self:
        operation_names = tuple(item.operation for item in self.operations)
        if len(operation_names) != len(set(operation_names)):
            raise ValueError("Golden Loop projection operations must be unique")
        if not {
            GoldenLoopOperation.START,
            GoldenLoopOperation.GET,
            GoldenLoopOperation.ADVANCE,
            GoldenLoopOperation.CANCEL,
        }.issubset(operation_names):
            raise ValueError(
                "Golden Loop projection must classify four lifecycle operations"
            )
        if self.loop_ref is not _RUN_PREFIX_TO_LOOP[self.run_ref_prefix]:
            raise ValueError("run_ref prefix does not match the Golden Loop")
        return self

    def operation(
        self, operation: GoldenLoopOperation | str
    ) -> GoldenLoopOperationContract:
        selected = GoldenLoopOperation(operation)
        for item in self.operations:
            if item.operation == selected:
                return item
        raise GoldenLoopProjectionError(
            "golden_loop.operation_not_classified",
            f"{selected.value} is not classified for {self.loop_ref.value}",
        )

    @property
    def canonical_run_ref_pattern(self) -> str:
        """Return the canonical public run-reference pattern for this loop."""

        return _RUN_PATTERNS[self.loop_ref.value].pattern


def _operation(
    operation: GoldenLoopOperation,
    availability: GoldenLoopOperationAvailability,
    *,
    endpoint: str | None = None,
    sdk_entrypoint: str | None = None,
    extraction_path: Literal["$", "$.run"] | None = None,
    response_schema: str | None = None,
    blocker: str | None = None,
) -> GoldenLoopOperationContract:
    return GoldenLoopOperationContract(
        operation=operation,
        availability=availability,
        endpoint_template=endpoint,
        sdk_entrypoint_ref=sdk_entrypoint,
        authority_run_extraction_path=(
            extraction_path if extraction_path is not None else "$" if endpoint else None
        ),
        response_schema=response_schema,
        blocker_code=blocker,
    )


FINANCE_JOURNAL_PROJECTION = GoldenLoopProjectionDescriptor(
    loop_ref=GoldenLoopRef.FINANCE_JOURNAL,
    loop_version="0.2.0",
    run_ref_prefix="fjr_",
    operations=(
        _operation(
            GoldenLoopOperation.START,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _operation(
            GoldenLoopOperation.GET,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _operation(
            GoldenLoopOperation.ADVANCE,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _operation(
            GoldenLoopOperation.CANCEL,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _operation(
            GoldenLoopOperation.STEP,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.finance.canonical_runtime_not_bound",
        ),
    ),
)

PROJECT_WORK_PACKET_PROJECTION = GoldenLoopProjectionDescriptor(
    loop_ref=GoldenLoopRef.PROJECT_WORK_PACKET,
    loop_version="0.1.0",
    run_ref_prefix="dwr_",
    operations=(
        _operation(
            GoldenLoopOperation.START,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint="/api/projects/{project_id}/work-packet-runs",
            sdk_entrypoint="lightbulb.client.LightbulbClient.start_project_work_packet",
            response_schema=PROJECT_WORK_PACKET_START_SCHEMA,
        ),
        _operation(
            GoldenLoopOperation.GET,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint="/api/projects/{project_id}/work-packet-runs/{run_ref}",
            sdk_entrypoint=(
                "lightbulb.client.LightbulbClient.get_project_work_packet_run"
            ),
            response_schema=PROJECT_WORK_PACKET_RUN_SCHEMA,
        ),
        _operation(
            GoldenLoopOperation.ADVANCE,
            GoldenLoopOperationAvailability.ROLE_PROTOCOL_ONLY,
            endpoint="/api/dynamic-workflows/next-assignment",
            sdk_entrypoint=(
                "lightbulb.client.LightbulbClient.dynamic_workflow_next_assignment"
            ),
        ),
        _operation(
            GoldenLoopOperation.CANCEL,
            GoldenLoopOperationAvailability.ROLE_PROTOCOL_ONLY,
            endpoint="/api/dynamic-workflows/cancel",
            sdk_entrypoint="lightbulb.client.LightbulbClient.cancel_project_work_packet",
        ),
    ),
)

REVENUE_VERIFIED_REPLY_PROJECTION = GoldenLoopProjectionDescriptor(
    loop_ref=GoldenLoopRef.REVENUE_VERIFIED_REPLY,
    loop_version="0.1.0",
    run_ref_prefix="gcr_",
    operations=(
        _operation(
            GoldenLoopOperation.START,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint=(
                "/api/tenants/{tenant_id}/companies/{company_id}/projects/"
                "{project_id}/governed-communication-runs"
            ),
            sdk_entrypoint=(
                "lightbulb.client.LightbulbClient.start_governed_communication_run"
            ),
            extraction_path="$.run",
        ),
        _operation(
            GoldenLoopOperation.GET,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint=(
                "/api/tenants/{tenant_id}/companies/{company_id}/projects/"
                "{project_id}/governed-communication-runs/{run_ref}"
            ),
            sdk_entrypoint=(
                "lightbulb.client.LightbulbClient.get_governed_communication_run"
            ),
        ),
        _operation(
            GoldenLoopOperation.ADVANCE,
            GoldenLoopOperationAvailability.WORKER_ONLY,
            blocker="golden_loop.revenue.advance_worker_only",
        ),
        _operation(
            GoldenLoopOperation.CANCEL,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint=(
                "/api/tenants/{tenant_id}/companies/{company_id}/projects/"
                "{project_id}/governed-communication-runs/{run_ref}/actions/cancel"
            ),
            sdk_entrypoint=(
                "lightbulb.client.LightbulbClient.cancel_governed_communication_run"
            ),
        ),
    ),
)

SERVICE_VERIFIED_RESOLUTION_PROJECTION = GoldenLoopProjectionDescriptor(
    loop_ref=GoldenLoopRef.SERVICE_VERIFIED_RESOLUTION,
    loop_version="0.2.0",
    run_ref_prefix="scr_",
    operations=(
        _operation(
            GoldenLoopOperation.START,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint="/api/projects/{project_id}/service/case-resolution-runs",
            sdk_entrypoint=(
                "lightbulb.client.LightbulbClient.start_service_case_resolution"
            ),
        ),
        _operation(
            GoldenLoopOperation.GET,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint=(
                "/api/projects/{project_id}/service/case-resolution-runs/{run_ref}"
            ),
            sdk_entrypoint=(
                "lightbulb.client.LightbulbClient.get_service_case_resolution"
            ),
        ),
        _operation(
            GoldenLoopOperation.ADVANCE,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint=(
                "/api/projects/{project_id}/service/case-resolution-runs/"
                "{run_ref}/advance"
            ),
            sdk_entrypoint=(
                "lightbulb.client.LightbulbClient.advance_service_case_resolution"
            ),
        ),
        _operation(
            GoldenLoopOperation.CANCEL,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint=(
                "/api/projects/{project_id}/service/case-resolution-runs/"
                "{run_ref}/cancel"
            ),
            sdk_entrypoint=(
                "lightbulb.client.LightbulbClient.cancel_service_case_resolution"
            ),
        ),
    ),
)

CONTRACT_TO_CASH_PROJECTION = GoldenLoopProjectionDescriptor(
    loop_ref=GoldenLoopRef.CONTRACT_TO_CASH,
    loop_version="0.1.0",
    run_ref_prefix="ctr_",
    operations=(
        _operation(
            GoldenLoopOperation.START,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint="/api/projects/{project_id}/contract-to-cash/runs",
            sdk_entrypoint="lightbulb.client.LightbulbClient.start_contract_to_cash_run",
        ),
        _operation(
            GoldenLoopOperation.GET,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint=(
                "/api/projects/{project_id}/contract-to-cash/runs/{run_ref}"
            ),
            sdk_entrypoint="lightbulb.client.LightbulbClient.get_contract_to_cash_run",
        ),
        _operation(
            GoldenLoopOperation.ADVANCE,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.contract_to_cash.advance_transition_specific",
        ),
        _operation(
            GoldenLoopOperation.CANCEL,
            GoldenLoopOperationAvailability.PUBLIC,
            endpoint=(
                "/api/projects/{project_id}/contract-to-cash/runs/{run_ref}/cancel"
            ),
            sdk_entrypoint=(
                "lightbulb.client.LightbulbClient.cancel_contract_to_cash_before_invoice"
            ),
        ),
    ),
)

PROCUREMENT_MATCHED_CLOSE_PROJECTION = GoldenLoopProjectionDescriptor(
    loop_ref=GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE,
    loop_version="0.1.0",
    run_ref_prefix="ppr_",
    operations=(
        _operation(
            GoldenLoopOperation.START,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _operation(
            GoldenLoopOperation.GET,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _operation(
            GoldenLoopOperation.ADVANCE,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _operation(
            GoldenLoopOperation.CANCEL,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.procurement.derived_match_authority_not_bound",
        ),
    ),
)

PERIOD_RECONCILIATION_PROJECTION = GoldenLoopProjectionDescriptor(
    loop_ref=GoldenLoopRef.PERIOD_RECONCILIATION,
    loop_version="0.2.0",
    run_ref_prefix="pcr_",
    operations=(
        _operation(
            GoldenLoopOperation.START,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _operation(
            GoldenLoopOperation.GET,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _operation(
            GoldenLoopOperation.ADVANCE,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _operation(
            GoldenLoopOperation.CANCEL,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.finance.canonical_runtime_not_bound",
        ),
    ),
)

VERIFIED_IMPROVEMENT_PROJECTION = GoldenLoopProjectionDescriptor(
    loop_ref=GoldenLoopRef.VERIFIED_IMPROVEMENT,
    loop_version="0.1.0",
    run_ref_prefix="wir_",
    operations=(
        _operation(
            GoldenLoopOperation.START,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.verified_improvement.source_authority_quarantined",
        ),
        _operation(
            GoldenLoopOperation.GET,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.verified_improvement.source_authority_quarantined",
        ),
        _operation(
            GoldenLoopOperation.ADVANCE,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.verified_improvement.source_authority_quarantined",
        ),
        _operation(
            GoldenLoopOperation.CANCEL,
            GoldenLoopOperationAvailability.BLOCKED,
            blocker="golden_loop.verified_improvement.source_authority_quarantined",
        ),
    ),
)

REFERENCE_GOLDEN_LOOP_PROJECTIONS = (
    CONTRACT_TO_CASH_PROJECTION,
    FINANCE_JOURNAL_PROJECTION,
    PERIOD_RECONCILIATION_PROJECTION,
    PROCUREMENT_MATCHED_CLOSE_PROJECTION,
    PROJECT_WORK_PACKET_PROJECTION,
    REVENUE_VERIFIED_REPLY_PROJECTION,
    SERVICE_VERIFIED_RESOLUTION_PROJECTION,
    VERIFIED_IMPROVEMENT_PROJECTION,
)


class GoldenLoopEvidenceProjection(_StrictModel):
    candidate_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    request_commitment_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    approval_receipt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    write_request_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    settlement_receipt_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    terminal_evidence_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    classification_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    routing_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    resolution_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    provider_contract_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    resolution_receipt_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )


class GoldenLoopRunProjection(_StrictModel):
    schema_id: Literal["lightbulb.golden_loop_run_projection.v1"] = Field(
        default=GOLDEN_LOOP_RUN_PROJECTION_SCHEMA,
        alias="schema",
    )
    authority_schema: str = Field(min_length=1, max_length=200)
    loop_ref: GoldenLoopRef
    loop_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    lifecycle: Literal["QUARANTINED"] = "QUARANTINED"
    run_ref: str = Field(min_length=20, max_length=80)
    state: str = Field(min_length=1, max_length=100)
    revision: int = Field(ge=0)
    terminal: bool
    success: bool
    evidence: GoldenLoopEvidenceProjection
    deadline_at: str | None = None
    terminal_at: str | None = None
    next_action_kind: str | None = Field(default=None, min_length=1, max_length=100)
    idempotent_replay: bool = False

    @field_validator("deadline_at", "terminal_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return _normalize_timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _identity_and_terminal_are_consistent(self) -> Self:
        pattern = _RUN_PATTERNS[self.loop_ref.value]
        if pattern.fullmatch(self.run_ref) is None:
            raise ValueError("run_ref prefix/shape does not match loop_ref")
        if self.success and not self.terminal:
            raise ValueError("a successful Golden Loop projection must be terminal")
        if self.terminal_at is not None and not self.terminal:
            raise ValueError("terminal_at is allowed only for a terminal run")
        return self


class GoldenLoopEconomicSourceProjection(_StrictModel):
    source: Literal["MODEL_PROVIDER", "CONNECTOR_RUNTIME", "CODING_HARNESS"]
    state: Literal["MISSING", "VERIFIED_COST", "VERIFIED_NO_PAID_WORK", "AMBIGUOUS"]
    source_revision: int | None = Field(ge=0)
    actual_cost_micros: int | None = Field(ge=0)
    evidence_ref: str | None = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9:/._#@~\-]{0,255}$",
    )
    evidence_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    recorded_at: str | None

    @field_validator("recorded_at")
    @classmethod
    def _recorded_timestamp(cls, value: str | None) -> str | None:
        return _normalize_timestamp(value, label="recorded_at")

    @model_validator(mode="after")
    def _evidence_shape_matches_state(self) -> Self:
        absent = self.state == "MISSING"
        if absent != (self.source_revision is None):
            raise ValueError("only a missing source may omit source_revision")
        evidence_values = (self.evidence_ref, self.evidence_sha256, self.recorded_at)
        if absent != all(value is None for value in evidence_values):
            raise ValueError("source evidence identity must be complete or entirely missing")
        if absent and self.actual_cost_micros is not None:
            raise ValueError("a missing source cannot assert cost")
        if self.state == "AMBIGUOUS" and self.actual_cost_micros is not None:
            raise ValueError("ambiguous source cost must remain unknown")
        if self.state == "VERIFIED_NO_PAID_WORK" and self.actual_cost_micros != 0:
            raise ValueError("no-paid-work source must have zero cost")
        if self.state == "VERIFIED_COST" and self.actual_cost_micros is None:
            raise ValueError("verified source cost is required")
        return self


class GoldenLoopEconomicClosureProjection(_StrictModel):
    """Read-only projection of Spring's whole-run economic authority."""

    schema_id: Literal[
        "lightbulb.golden_loop_economic_closure_projection.v2"
    ] = Field(default=GOLDEN_LOOP_ECONOMIC_CLOSURE_PROJECTION_SCHEMA, alias="schema")
    lifecycle: Literal["QUARANTINED"]
    loop_ref: GoldenLoopRef
    loop_version: str = Field(
        max_length=32,
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$",
    )
    declaration_version: str = Field(
        max_length=64,
        pattern=_SEMVER_PATTERN,
    )
    workflow_binding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    start_portfolio_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_ref: str = Field(min_length=20, max_length=80)
    admission_ref: str = Field(pattern=r"^gla_[0-9a-f]{32}$")
    admission_state: Literal["ACCEPTED", "RECONCILIATION_REQUIRED", "SETTLED", "RELEASED"]
    economic_decision: Literal[
        "INCOMPLETE", "RECONCILIATION_REQUIRED", "READY_TO_SETTLE", "SETTLED", "RELEASED"
    ]
    cost_completeness: Literal["INCOMPLETE", "AMBIGUOUS", "PROVEN_COMPLETE"]
    cost_unit: Literal["USD_MICROS"]
    declared_max_cost_micros: int = Field(gt=0)
    actual_cost_micros: int | None = Field(ge=0)
    settlement_basis: Literal["whole_run_cost_manifest_v2"] | None
    manifest_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    missing_sources: tuple[
        Literal["MODEL_PROVIDER", "CONNECTOR_RUNTIME", "CODING_HARNESS"], ...
    ]
    ambiguous_sources: tuple[
        Literal["MODEL_PROVIDER", "CONNECTOR_RUNTIME", "CODING_HARNESS"], ...
    ]
    required_sources: tuple[
        Literal["MODEL_PROVIDER", "CONNECTOR_RUNTIME", "CODING_HARNESS"], ...
    ]
    components: tuple[GoldenLoopEconomicSourceProjection, ...]
    revision: int = Field(ge=0)
    accepted_at: str
    settled_at: str | None
    released_at: str | None
    updated_at: str

    @field_validator("loop_ref", mode="before")
    @classmethod
    def _wire_loop_ref(cls, value: Any) -> Any:
        return GoldenLoopRef(value) if isinstance(value, str) else value

    @field_validator(
        "missing_sources",
        "ambiguous_sources",
        "required_sources",
        "components",
        mode="before",
    )
    @classmethod
    def _arrays_are_frozen(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("accepted_at", "settled_at", "released_at", "updated_at")
    @classmethod
    def _closure_timestamps(cls, value: str | None, info: Any) -> str | None:
        return _normalize_timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _closure_is_consistent(self) -> Self:
        if _RUN_PATTERNS[self.loop_ref.value].fullmatch(self.run_ref) is None:
            raise ValueError("run_ref prefix/shape does not match loop_ref")
        if self.required_sources not in {
            _ECONOMIC_BASE_REQUIRED_SOURCES,
            _ECONOMIC_WITH_HARNESS_REQUIRED_SOURCES,
        }:
            raise ValueError("required_sources is not a canonical retained source policy")
        required = set(self.required_sources)
        by_source = {component.source: component for component in self.components}
        if (
            tuple(component.source for component in self.components)
            != self.required_sources
            or set(by_source) != required
            or len(by_source) != len(self.components)
        ):
            raise ValueError(
                "economic components must exactly cover the retained required sources in order"
            )
        missing = tuple(
            source
            for source in self.required_sources
            if by_source[source].state == "MISSING"
        )
        ambiguous = tuple(
            source
            for source in self.required_sources
            if by_source[source].state == "AMBIGUOUS"
        )
        if self.missing_sources != missing or self.ambiguous_sources != ambiguous:
            raise ValueError("source summaries must match component states")
        accepted_at = datetime.fromisoformat(self.accepted_at.replace("Z", "+00:00"))
        updated_at = datetime.fromisoformat(self.updated_at.replace("Z", "+00:00"))
        if updated_at < accepted_at:
            raise ValueError("updated_at cannot precede accepted_at")
        for component in self.components:
            if component.recorded_at is None:
                continue
            recorded_at = datetime.fromisoformat(
                component.recorded_at.replace("Z", "+00:00")
            )
            if recorded_at < accepted_at or recorded_at > updated_at:
                raise ValueError(
                    "source evidence timestamp must fall within the admission window"
                )
        expected_completeness = (
            "INCOMPLETE" if missing else "AMBIGUOUS" if ambiguous else "PROVEN_COMPLETE"
        )
        if self.cost_completeness != expected_completeness:
            raise ValueError("cost_completeness does not match source evidence")
        expected_decision = {
            "ACCEPTED": (
                "INCOMPLETE"
                if missing
                else "RECONCILIATION_REQUIRED"
                if ambiguous
                else "READY_TO_SETTLE"
            ),
            "RECONCILIATION_REQUIRED": "RECONCILIATION_REQUIRED",
            "SETTLED": "SETTLED",
            "RELEASED": "RELEASED",
        }[self.admission_state]
        if self.economic_decision != expected_decision:
            raise ValueError("admission_state and economic_decision must agree exactly")
        final = self.admission_state in {"SETTLED", "RELEASED"}
        if final != (self.manifest_sha256 is not None):
            raise ValueError("only final closure may expose a manifest digest")
        if final and self.cost_completeness != "PROVEN_COMPLETE":
            raise ValueError("final closure requires complete source evidence")
        if self.admission_state == "SETTLED":
            if (
                self.actual_cost_micros is None
                or self.settlement_basis is None
                or self.settled_at is None
                or self.released_at is not None
            ):
                raise ValueError("settled closure requires exact cost, basis, and timestamp")
            component_total = sum(
                component.actual_cost_micros or 0 for component in self.components
            )
            if self.actual_cost_micros != component_total:
                raise ValueError("settled cost must equal the exact source aggregation")
            if self.actual_cost_micros > self.declared_max_cost_micros:
                raise ValueError("settled cost exceeds its authorized ceiling")
            if self.settlement_basis != "whole_run_cost_manifest_v2":
                raise ValueError("settled closure must use the retained-identity manifest")
            settled_at = datetime.fromisoformat(self.settled_at.replace("Z", "+00:00"))
            if settled_at < accepted_at or settled_at > updated_at:
                raise ValueError("settled_at must fall within the admission window")
        elif self.actual_cost_micros is not None or self.settlement_basis is not None:
            raise ValueError("non-settled closure must not expose settlement cost or basis")
        if self.admission_state == "RELEASED" and (
            self.released_at is None or self.settled_at is not None
        ):
            raise ValueError("released closure requires only released_at")
        if self.admission_state == "RELEASED" and any(
            component.state != "VERIFIED_NO_PAID_WORK" for component in self.components
        ):
            raise ValueError("released closure requires every source to prove no paid work")
        if self.admission_state == "RELEASED":
            released_at = datetime.fromisoformat(self.released_at.replace("Z", "+00:00"))
            if released_at < accepted_at or released_at > updated_at:
                raise ValueError("released_at must fall within the admission window")
        if self.admission_state in {"ACCEPTED", "RECONCILIATION_REQUIRED"} and (
            self.settled_at is not None or self.released_at is not None
        ):
            raise ValueError("non-final closure cannot expose final timestamps")
        return self

    def to_exact_dict(self) -> dict[str, Any]:
        """Serialize the closed projection without dropping required nullable evidence."""

        return self.model_dump(mode="json", by_alias=True, exclude_none=False)

    def to_dict(self) -> dict[str, Any]:
        """Preserve the exact v2 wire shape for normal SDK serialization too."""

        return self.to_exact_dict()


class ProjectWorkPacketStartResult(_StrictModel):
    """Exact START outcome for Spring's approved Project work-packet authority."""

    schema_id: Literal["lightbulb.project_work_packet_start.v1"] = Field(
        default=PROJECT_WORK_PACKET_START_SCHEMA,
        alias="schema",
    )
    loop_ref: Literal["project.work_packet_independent_acceptance"]
    loop_version: Literal["0.1.0"]
    lifecycle: Literal["QUARANTINED"]
    status: Literal["approval_required", "ready_for_selected_hosted_adapter"]
    run_ref: str | None = Field(
        default=None,
        pattern=r"^dwr_[A-Za-z0-9_-]{16,64}$",
    )
    model_execution_run_id: str | None = Field(
        default=None,
        pattern=_MODEL_EXECUTION_RUN_ID.pattern,
        description="Spring-owned Model Call Runtime identity; absent before approval.",
    )
    revision: int | None = Field(default=None, ge=0)
    workflow_status: str | None = Field(default=None, min_length=1, max_length=100)
    selected_harness: Literal["codex", "claude_code", "cursor"]
    required_harness: Literal["codex", "claude_code", "cursor"]
    handoff_payload_id: str = Field(pattern=r"^pwh_[a-f0-9]{64}$")
    work_packet_ref: str = Field(pattern=_PORTABLE_REF.pattern)
    work_packet_digest: str = Field(pattern=_SHA256.pattern)
    acceptance_contract_digest: str = Field(pattern=_SHA256.pattern)
    repository_binding_ref: str = Field(min_length=1, max_length=500)
    repository_binding_digest: str = Field(pattern=_SHA256.pattern)
    workspace_binding_ref: str = Field(min_length=1, max_length=500)
    workspace_binding_digest: str = Field(pattern=_SHA256.pattern)
    source_material_digest: str = Field(pattern=_SHA256.pattern)
    binding_digest: str = Field(pattern=_SHA256.pattern)
    approval_task_ref: str = Field(min_length=1, max_length=200)
    approval_proposal_digest: str = Field(pattern=_SHA256.pattern)
    approval_receipt_digest: str | None = Field(
        default=None,
        pattern=_SHA256.pattern,
    )
    execution_started: bool
    builder_custody_issued: Literal[False]
    idempotent_replay: bool
    next_step: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def _state_is_exact(self) -> Self:
        if self.selected_harness != self.required_harness:
            raise ValueError("selected_harness and required_harness must match")
        if self.status == "approval_required":
            if any(
                value is not None
                for value in (
                    self.run_ref,
                    self.model_execution_run_id,
                    self.revision,
                    self.workflow_status,
                    self.approval_receipt_digest,
                )
            ):
                raise ValueError("approval_required must not claim a canonical run")
            if self.execution_started or self.idempotent_replay:
                raise ValueError("approval_required must not claim execution or replay")
        else:
            if any(
                value is None
                for value in (
                    self.run_ref,
                    self.model_execution_run_id,
                    self.revision,
                    self.workflow_status,
                    self.approval_receipt_digest,
                )
            ):
                raise ValueError("ready Project START requires its canonical run and approval")
            if not self.execution_started:
                raise ValueError("ready Project START must report execution_started")
        return self


class ProjectWorkPacketRunRead(ProjectWorkPacketStartResult):
    """Owner-scoped oversight read without coding-harness continuation custody."""

    schema_id: Literal["lightbulb.project_work_packet_run.v1"] = Field(
        default=PROJECT_WORK_PACKET_RUN_SCHEMA,
        alias="schema",
    )
    status: Literal["ready_for_selected_hosted_adapter", "terminal"]
    run_ref: str = Field(pattern=r"^dwr_[A-Za-z0-9_-]{16,64}$")
    model_execution_run_id: str = Field(
        pattern=_MODEL_EXECUTION_RUN_ID.pattern,
        description="Spring-owned Model Call Runtime identity.",
    )
    revision: int = Field(ge=0)
    workflow_status: str = Field(min_length=1, max_length=100)
    approval_receipt_digest: str = Field(pattern=_SHA256.pattern)
    execution_started: Literal[True]
    idempotent_replay: Literal[True]
    terminal: bool

    @model_validator(mode="after")
    def _read_state_is_exact(self) -> Self:
        if self.terminal != (self.status == "terminal"):
            raise ValueError("Project run terminal marker and status must agree")
        if self.terminal != (self.next_step == "none"):
            raise ValueError("Project run terminal state and next_step must agree")
        return self

    @property
    def projection(self) -> GoldenLoopRunProjection:
        return project_dynamic_workflow_run(
            {
                "run_ref": self.run_ref,
                "revision": self.revision,
                "status": self.workflow_status,
                "terminal": self.terminal,
            }
        )


class ServiceCaseResolutionStart(_StrictModel):
    """Exact candidate accepted by Spring's customer-verified resolution authority."""

    schema_id: Literal["lightbulb.service_case_resolution_candidate.v1"] = Field(
        default=SERVICE_CASE_RESOLUTION_CANDIDATE_SCHEMA,
        alias="schema",
    )
    candidate_ref: str = Field(pattern=_PORTABLE_REF.pattern)
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    connector_account_ref: str = Field(pattern=_PORTABLE_REF.pattern)
    ticket_ref: str = Field(pattern=r"^[1-9][0-9]{0,18}$")
    requester_ref: str = Field(pattern=r"^[1-9][0-9]{0,18}$")
    classification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    routing_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    resolution_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contact_policy_decision_ref: str = Field(pattern=_PORTABLE_REF.pattern)
    contact_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contact_policy_expires_at: str
    reply_body: str = Field(min_length=1, max_length=7_000)
    idempotency_key: str = Field(min_length=1, max_length=240)

    @field_validator("contact_policy_expires_at")
    @classmethod
    def _contact_policy_expiry(cls, value: str) -> str:
        normalized = _normalize_timestamp(
            value,
            label="contact_policy_expires_at",
        )
        assert normalized is not None
        return normalized

    @field_validator("reply_body")
    @classmethod
    def _bounded_reply_body(cls, value: str) -> str:
        if value != value.strip() or "\x00" in value:
            raise ValueError("reply_body must be trimmed and contain no NUL")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def _visible_idempotency_key(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 33 or ord(character) > 126 for character in value
        ):
            raise ValueError("idempotency_key must contain visible ASCII only")
        return value

    @model_validator(mode="after")
    def _candidate_digest_is_exact(self) -> Self:
        expected = _canonical_json_digest(
            {
                "schema": SERVICE_CASE_RESOLUTION_CANDIDATE_SCHEMA,
                "candidate_ref": self.candidate_ref,
                "connector_account_ref": self.connector_account_ref,
                "ticket_ref": self.ticket_ref,
                "requester_ref": self.requester_ref,
                "classification_sha256": self.classification_sha256,
                "routing_sha256": self.routing_sha256,
                "resolution_sha256": self.resolution_sha256,
                "contact_policy_decision_ref": self.contact_policy_decision_ref,
                "contact_policy_sha256": self.contact_policy_sha256,
                "contact_policy_expires_at": self.contact_policy_expires_at,
                "reply_body_sha256": hashlib.sha256(
                    self.reply_body.encode("utf-8")
                ).hexdigest(),
            }
        )
        if self.candidate_sha256 != expected:
            raise ValueError(
                "candidate_sha256 must bind the exact service-case candidate"
            )
        return self


class ServiceCaseResolutionCancel(_StrictModel):
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("reason")
    @classmethod
    def _bounded_reason(cls, value: str) -> str:
        clean = value.strip()
        if (
            not clean
            or "\x00" in clean
            or any(
                ord(character) < 32 and character not in "\t\n\r" for character in clean
            )
        ):
            raise ValueError("service-case cancellation reason must be visible text")
        return clean


ServiceCaseResolutionState = Literal[
    "TICKET_READ_PENDING",
    "REPLY_APPROVAL_PENDING",
    "CUSTOMER_CONFIRMATION_PENDING",
    "CLOSURE_APPROVAL_PENDING",
    "CLOSE_READBACK_PENDING",
    "CLOSED_VERIFIED",
    "RESOLUTION_REJECTED",
    "CLOSURE_REJECTED",
    "CUSTOMER_UNREACHABLE",
    "FAILED_BEFORE_EFFECT",
    "MANUAL_RECONCILIATION_REQUIRED",
    "CANCELLED_BEFORE_EFFECT",
    "REOPENED",
]

_SERVICE_TERMINAL_STATES = {
    "CLOSED_VERIFIED",
    "RESOLUTION_REJECTED",
    "CLOSURE_REJECTED",
    "CUSTOMER_UNREACHABLE",
    "FAILED_BEFORE_EFFECT",
    "MANUAL_RECONCILIATION_REQUIRED",
    "CANCELLED_BEFORE_EFFECT",
    "REOPENED",
}


class ServiceCaseResolutionNextAction(_StrictModel):
    kind: Literal[
        "RESUME_SERVER_TICKET_READ",
        "AWAIT_REPLY_APPROVAL_THEN_ADVANCE_SERVER_EFFECT",
        "ADVANCE_SERVER_CUSTOMER_CONFIRMATION_OBSERVER",
        "AWAIT_CLOSURE_APPROVAL_THEN_ADVANCE_SERVER_EFFECT",
        "ADVANCE_SERVER_PROVIDER_CLOSE_READBACK",
        "TERMINAL",
    ]
    approval_ref: str | None = Field(default=None, pattern=_UUID.pattern)
    not_before: str | None = None

    @field_validator("not_before")
    @classmethod
    def _not_before(cls, value: str | None) -> str | None:
        return _normalize_timestamp(value, label="not_before")

    @model_validator(mode="after")
    def _fields_match_kind(self) -> Self:
        present = {
            name
            for name in ("approval_ref", "not_before")
            if getattr(self, name) is not None
        }
        expected = {
            "RESUME_SERVER_TICKET_READ": set(),
            "AWAIT_REPLY_APPROVAL_THEN_ADVANCE_SERVER_EFFECT": {"approval_ref"},
            "ADVANCE_SERVER_CUSTOMER_CONFIRMATION_OBSERVER": {"not_before"},
            "AWAIT_CLOSURE_APPROVAL_THEN_ADVANCE_SERVER_EFFECT": {"approval_ref"},
            "ADVANCE_SERVER_PROVIDER_CLOSE_READBACK": {"not_before"},
            "TERMINAL": set(),
        }[self.kind]
        if present != expected:
            raise ValueError(
                "service-case next_action fields do not match its exact kind"
            )
        return self


class ServiceCaseResolutionReceipt(_StrictModel):
    schema_id: Literal[
        "lightbulb.service_case_customer_verified_resolution_receipt.v1"
    ] = Field(alias="schema")
    lifecycle: Literal["QUARANTINED"]
    loop_ref: Literal["service.case_customer_verified_resolution"]
    loop_version: Literal["0.2.0"]
    run_ref: str = Field(pattern=r"^scr_[a-f0-9]{32}$")
    candidate_ref: str = Field(pattern=_PORTABLE_REF.pattern)
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: ServiceCaseResolutionState
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,99}$")
    provider: Literal["freshservice"]
    provider_contract_ref: str = Field(min_length=1, max_length=240)
    provider_contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deployment_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reply_approval_ref: str = Field(pattern=_UUID.pattern)
    reply_journal_ref: str | None = Field(default=None, pattern=_UUID.pattern)
    reply_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    reply_effect_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    confirmation_observation_journal_ref: str | None = Field(
        default=None,
        pattern=_UUID.pattern,
    )
    confirmation_observation_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    confirmation_conversation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    customer_confirmation_observed_at: str | None = None
    closure_approval_ref: str | None = Field(default=None, pattern=_UUID.pattern)
    close_journal_ref: str | None = Field(default=None, pattern=_UUID.pattern)
    close_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    close_effect_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    closure_observation_journal_ref: str | None = Field(
        default=None,
        pattern=_UUID.pattern,
    )
    closure_observation_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    closure_observed_at: str | None = None
    terminal_at: str
    certified: Literal[False]

    @field_validator(
        "customer_confirmation_observed_at",
        "closure_observed_at",
        "terminal_at",
    )
    @classmethod
    def _receipt_timestamps(cls, value: str | None, info: Any) -> str | None:
        return _normalize_timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _terminal_evidence_is_exact(self) -> Self:
        if self.state not in _SERVICE_TERMINAL_STATES:
            raise ValueError("service-case receipt state must be terminal")

        reply_effect = (
            self.reply_journal_ref is not None
            and self.reply_receipt_sha256 is not None
            and self.reply_effect_sha256 is not None
        )
        if (self.reply_receipt_sha256 is None) != (
            self.reply_effect_sha256 is None
        ) or (self.reply_receipt_sha256 is not None and self.reply_journal_ref is None):
            raise ValueError("service-case reply evidence is incomplete")

        confirmation = (
            self.confirmation_observation_journal_ref is not None
            and self.confirmation_observation_receipt_sha256 is not None
            and self.confirmation_conversation_sha256 is not None
            and self.customer_confirmation_observed_at is not None
        )
        if (self.confirmation_conversation_sha256 is None) != (
            self.customer_confirmation_observed_at is None
        ) or (
            self.confirmation_conversation_sha256 is not None
            and (
                self.confirmation_observation_journal_ref is None
                or self.confirmation_observation_receipt_sha256 is None
            )
        ):
            raise ValueError(
                "service-case customer-confirmation evidence is incomplete"
            )

        close_effect = (
            self.close_journal_ref is not None
            and self.close_receipt_sha256 is not None
            and self.close_effect_sha256 is not None
        )
        if (self.close_receipt_sha256 is None) != (
            self.close_effect_sha256 is None
        ) or (self.close_receipt_sha256 is not None and self.close_journal_ref is None):
            raise ValueError("service-case close evidence is incomplete")

        closure_readback = (
            self.closure_observation_journal_ref is not None
            and self.closure_observation_receipt_sha256 is not None
            and self.closure_observed_at is not None
        )
        closure_parts = (
            self.closure_observation_journal_ref,
            self.closure_observation_receipt_sha256,
            self.closure_observed_at,
        )
        if any(value is not None for value in closure_parts) and not closure_readback:
            raise ValueError("service-case closure-readback evidence is incomplete")

        if self.state in {"CLOSED_VERIFIED", "REOPENED"} and not (
            reply_effect
            and confirmation
            and self.closure_approval_ref is not None
            and close_effect
            and closure_readback
        ):
            raise ValueError(
                "provider-closed terminal state requires exact reply, confirmation, close, and readback evidence"
            )
        if self.state == "RESOLUTION_REJECTED" and not (reply_effect and confirmation):
            raise ValueError(
                "customer rejection requires exact reply and confirmation evidence"
            )
        if self.state == "CLOSURE_REJECTED" and not (
            reply_effect and confirmation and self.closure_approval_ref is not None
        ):
            raise ValueError(
                "closure rejection requires exact reply, confirmation, and approval evidence"
            )
        if self.state == "CUSTOMER_UNREACHABLE" and not reply_effect:
            raise ValueError("customer-unreachable state requires exact reply evidence")
        if self.state == "CANCELLED_BEFORE_EFFECT" and any(
            value is not None
            for value in (
                self.reply_journal_ref,
                self.reply_receipt_sha256,
                self.reply_effect_sha256,
                self.confirmation_observation_journal_ref,
                self.confirmation_observation_receipt_sha256,
                self.confirmation_conversation_sha256,
                self.customer_confirmation_observed_at,
                self.closure_approval_ref,
                self.close_journal_ref,
                self.close_receipt_sha256,
                self.close_effect_sha256,
                self.closure_observation_journal_ref,
                self.closure_observation_receipt_sha256,
                self.closure_observed_at,
            )
        ):
            raise ValueError(
                "cancelled-before-effect receipt contains provider evidence"
            )
        return self


class ServiceCaseResolutionRun(_StrictModel):
    schema_id: Literal["lightbulb.service_case_resolution_run.v1"] = Field(
        alias="schema"
    )
    lifecycle: Literal["QUARANTINED"]
    run_ref: str = Field(pattern=r"^scr_[a-f0-9]{32}$")
    loop_ref: Literal["service.case_customer_verified_resolution"]
    loop_version: Literal["0.2.0"]
    model_execution_run_id: str | None = Field(
        pattern=_MODEL_EXECUTION_RUN_ID.pattern,
    )
    tenant_id: str = Field(pattern=_UUID.pattern)
    company_id: str = Field(pattern=_UUID.pattern)
    project_id: str = Field(pattern=_UUID.pattern)
    user_id: str = Field(pattern=_UUID.pattern)
    provider: Literal["freshservice"]
    candidate_ref: str = Field(pattern=_PORTABLE_REF.pattern)
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    connector_account_ref: str = Field(pattern=_PORTABLE_REF.pattern)
    ticket_ref_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requester_ref_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    classification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    routing_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    resolution_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contact_policy_decision_ref: str = Field(pattern=_PORTABLE_REF.pattern)
    contact_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contact_policy_expires_at: str
    reply_body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    confirmation_code_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_contract_ref: str = Field(min_length=1, max_length=240)
    provider_contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deployment_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: ServiceCaseResolutionState
    terminal: bool
    revision: int = Field(ge=0)
    ticket_read_journal_ref: str | None = Field(default=None, pattern=_UUID.pattern)
    ticket_read_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    reply_approval_ref: str | None = Field(default=None, pattern=_UUID.pattern)
    reply_approval_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    reply_journal_ref: str | None = Field(default=None, pattern=_UUID.pattern)
    reply_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    reply_effect_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    confirmation_observation_journal_ref: str | None = Field(
        default=None,
        pattern=_UUID.pattern,
    )
    confirmation_observation_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    closure_approval_ref: str | None = Field(default=None, pattern=_UUID.pattern)
    closure_approval_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    close_journal_ref: str | None = Field(default=None, pattern=_UUID.pattern)
    close_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    close_effect_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    closure_observation_journal_ref: str | None = Field(
        default=None,
        pattern=_UUID.pattern,
    )
    closure_observation_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    observation_attempts: int = Field(ge=0, le=24)
    max_observation_attempts: Literal[24]
    next_observation_at: str | None = None
    confirmation_deadline_at: str
    closure_deadline_at: str
    terminal_reason_code: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_]{2,99}$",
    )
    resolution_receipt: Mapping[str, Any]
    resolution_receipt_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    terminal_at: str | None = None
    created_at: str
    updated_at: str
    certified: Literal[False]
    next_action: ServiceCaseResolutionNextAction

    @field_validator(
        "contact_policy_expires_at",
        "next_observation_at",
        "confirmation_deadline_at",
        "closure_deadline_at",
        "terminal_at",
        "created_at",
        "updated_at",
    )
    @classmethod
    def _time_fields(cls, value: str | None, info: Any) -> str | None:
        return _normalize_timestamp(value, label=info.field_name)

    @model_validator(mode="before")
    @classmethod
    def _no_sensitive_response_fields(cls, value: Any) -> Any:
        _reject_sensitive_keys(value)
        return value

    @model_validator(mode="after")
    def _authority_shape_is_exact(self) -> Self:
        terminal = self.state in _SERVICE_TERMINAL_STATES
        if self.terminal != terminal:
            raise ValueError("service-case terminal flag must match its exact state")
        if not terminal and self.model_execution_run_id is None:
            raise ValueError(
                "nonterminal service-case run requires model execution binding"
            )
        expected_action = {
            "TICKET_READ_PENDING": "RESUME_SERVER_TICKET_READ",
            "REPLY_APPROVAL_PENDING": (
                "AWAIT_REPLY_APPROVAL_THEN_ADVANCE_SERVER_EFFECT"
            ),
            "CUSTOMER_CONFIRMATION_PENDING": (
                "ADVANCE_SERVER_CUSTOMER_CONFIRMATION_OBSERVER"
            ),
            "CLOSURE_APPROVAL_PENDING": (
                "AWAIT_CLOSURE_APPROVAL_THEN_ADVANCE_SERVER_EFFECT"
            ),
            "CLOSE_READBACK_PENDING": ("ADVANCE_SERVER_PROVIDER_CLOSE_READBACK"),
        }.get(self.state, "TERMINAL")
        if self.next_action.kind != expected_action:
            raise ValueError("service-case next_action does not match authority state")
        start_bindings = (
            self.ticket_read_journal_ref,
            self.ticket_read_receipt_sha256,
            self.reply_approval_ref,
            self.reply_approval_receipt_sha256,
        )
        if self.state == "TICKET_READ_PENDING" and any(
            value is not None for value in start_bindings
        ):
            raise ValueError(
                "service-case pending START cannot claim ticket or approval custody"
            )
        if self.state != "TICKET_READ_PENDING" and any(
            value is None for value in start_bindings
        ):
            raise ValueError(
                "service-case post-START authority requires exact ticket and approval custody"
            )
        if (
            self.state == "REPLY_APPROVAL_PENDING"
            and self.next_action.approval_ref != self.reply_approval_ref
        ):
            raise ValueError(
                "service-case reply next_action is not bound to its exact approval"
            )
        if (
            self.state == "CLOSURE_APPROVAL_PENDING"
            and self.next_action.approval_ref != self.closure_approval_ref
        ):
            raise ValueError(
                "service-case close next_action is not bound to its exact approval"
            )
        if (
            self.state
            in {
                "CUSTOMER_CONFIRMATION_PENDING",
                "CLOSE_READBACK_PENDING",
            }
            and self.next_action.not_before != self.next_observation_at
        ):
            raise ValueError(
                "service-case observation next_action is not bound to its exact due time"
            )
        if terminal:
            receipt = ServiceCaseResolutionReceipt.model_validate(
                dict(self.resolution_receipt)
            )
            if (
                self.terminal_at is None
                or self.terminal_reason_code is None
                or self.resolution_receipt_sha256 is None
                or receipt.run_ref != self.run_ref
                or receipt.candidate_ref != self.candidate_ref
                or receipt.candidate_sha256 != self.candidate_sha256
                or receipt.state != self.state
                or receipt.reason_code != self.terminal_reason_code
                or receipt.terminal_at != self.terminal_at
                or receipt.provider != self.provider
                or receipt.provider_contract_ref != self.provider_contract_ref
                or receipt.provider_contract_sha256 != self.provider_contract_sha256
                or receipt.deployment_artifact_sha256 != self.deployment_artifact_sha256
                or receipt.reply_approval_ref != self.reply_approval_ref
                or receipt.reply_journal_ref != self.reply_journal_ref
                or receipt.reply_receipt_sha256 != self.reply_receipt_sha256
                or receipt.reply_effect_sha256 != self.reply_effect_sha256
                or receipt.confirmation_observation_journal_ref
                != self.confirmation_observation_journal_ref
                or receipt.confirmation_observation_receipt_sha256
                != self.confirmation_observation_receipt_sha256
                or receipt.closure_approval_ref != self.closure_approval_ref
                or receipt.close_journal_ref != self.close_journal_ref
                or receipt.close_receipt_sha256 != self.close_receipt_sha256
                or receipt.close_effect_sha256 != self.close_effect_sha256
                or receipt.closure_observation_journal_ref
                != self.closure_observation_journal_ref
                or receipt.closure_observation_receipt_sha256
                != self.closure_observation_receipt_sha256
                or self.resolution_receipt_sha256
                != _canonical_json_digest(receipt.to_dict())
            ):
                raise ValueError(
                    "service-case terminal receipt is not bound to the exact run"
                )
        elif (
            dict(self.resolution_receipt)
            or self.resolution_receipt_sha256 is not None
            or self.terminal_reason_code is not None
            or self.terminal_at is not None
        ):
            raise ValueError("nonterminal service-case run contains terminal evidence")
        return self

    @property
    def projection(self) -> GoldenLoopRunProjection:
        return GoldenLoopRunProjection(
            authority_schema=self.schema_id,
            loop_ref=GoldenLoopRef.SERVICE_VERIFIED_RESOLUTION,
            loop_version=self.loop_version,
            run_ref=self.run_ref,
            state=self.state,
            revision=self.revision,
            terminal=self.terminal,
            success=self.state == "CLOSED_VERIFIED",
            evidence=GoldenLoopEvidenceProjection(
                candidate_sha256=self.candidate_sha256,
                approval_receipt_sha256=self.reply_approval_receipt_sha256,
                classification_sha256=self.classification_sha256,
                routing_sha256=self.routing_sha256,
                resolution_sha256=self.resolution_sha256,
                provider_contract_sha256=self.provider_contract_sha256,
                resolution_receipt_sha256=self.resolution_receipt_sha256,
            ),
            deadline_at=self.closure_deadline_at,
            terminal_at=self.terminal_at,
            next_action_kind=self.next_action.kind,
        )


def parse_service_case_resolution_run(
    value: Mapping[str, Any],
) -> ServiceCaseResolutionRun:
    if not isinstance(value, Mapping):
        raise GoldenLoopProjectionError(
            "golden_loop.service.response_not_object",
            "service-case resolution response must be an object",
        )
    try:
        return ServiceCaseResolutionRun.model_validate(value)
    except Exception as exc:
        raise GoldenLoopProjectionError(
            "golden_loop.service.response_contract_invalid",
            "service-case resolution response failed its exact contract",
        ) from exc


class GovernedCommunicationAdmission(_StrictModel):
    source_ref: str = Field(pattern=r"^gcs_v1_[0-9a-f]{64}$")
    source_surface: Literal["agent", "sdk", "mcp", "chatgpt", "ui"]


class GovernedCommunicationSource(_StrictModel):
    source_ref: str = Field(
        pattern=r"^gcs_v1_[0-9a-f]{64}$",
        validation_alias=AliasChoices("source_ref", "sourceRef"),
    )
    source_ref_version: Literal["gcs_v1"] = Field(
        validation_alias=AliasChoices("source_ref_version", "sourceRefVersion")
    )
    purpose: Literal[
        "transactional",
        "service",
        "support",
        "sales",
        "marketing",
        "collections",
        "operations",
        "security",
        "legal",
        "internal_collaboration",
        "human_approval",
    ]
    created_at: str = Field(validation_alias=AliasChoices("created_at", "createdAt"))
    expires_at: str = Field(validation_alias=AliasChoices("expires_at", "expiresAt"))

    @field_validator("created_at", "expires_at")
    @classmethod
    def _source_timestamps(cls, value: str, info: Any) -> str:
        normalized = _normalize_timestamp(value, label=info.field_name)
        assert normalized is not None
        return normalized

    @model_validator(mode="after")
    def _source_window_is_forward(self) -> Self:
        if datetime.fromisoformat(
            self.expires_at.replace("Z", "+00:00")
        ) <= datetime.fromisoformat(self.created_at.replace("Z", "+00:00")):
            raise ValueError("communication source expiry must follow creation")
        return self


class GovernedCommunicationSourcePage(_StrictModel):
    schema_id: Literal["lightbulb.governed_communication_source_page.v1"] = Field(
        validation_alias=AliasChoices("schema", "schema_id"),
        serialization_alias="schema",
    )
    sources: tuple[GovernedCommunicationSource, ...] = Field(max_length=50)
    next_cursor: str | None = Field(
        default=None,
        pattern=r"^gcs_v1_[0-9a-f]{64}$",
        validation_alias=AliasChoices("next_cursor", "nextCursor"),
    )

    @field_validator("sources", mode="before")
    @classmethod
    def _json_array_is_frozen(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def _cursor_is_last_visible_source(self) -> Self:
        if self.next_cursor is not None and (
            not self.sources or self.next_cursor != self.sources[-1].source_ref
        ):
            raise ValueError(
                "communication source cursor must equal the last visible source"
            )
        return self


class GovernedCommunicationRun(_StrictModel):
    schema_id: Literal["lightbulb.governed_communication_run.v1"] = Field(
        validation_alias=AliasChoices("schema", "schema_id"),
        serialization_alias="schema",
    )
    run_ref: str = Field(
        pattern=r"^gcr_[a-f0-9]{32}$",
        validation_alias=AliasChoices("run_ref", "runRef"),
    )
    workflow_key: Literal["revenue.governed_crm_turn_verified_reply"] = Field(
        validation_alias=AliasChoices("workflow_key", "workflowKey")
    )
    workflow_version: Literal["0.1.0"] = Field(
        validation_alias=AliasChoices("workflow_version", "workflowVersion")
    )
    model_execution_run_id: str | None = Field(
        default=None,
        pattern=_MODEL_EXECUTION_RUN_ID.pattern,
        validation_alias=AliasChoices(
            "model_execution_run_id", "modelExecutionRunId"
        ),
    )
    lifecycle: Literal["QUARANTINED"]
    provider: Literal["gmail"]
    state: str = Field(min_length=1, max_length=100)
    execution_authorized: Literal[False] = Field(
        validation_alias=AliasChoices("execution_authorized", "executionAuthorized")
    )
    terminal: bool
    success: bool
    tenant_id: str = Field(
        pattern=_UUID.pattern,
        validation_alias=AliasChoices("tenant_id", "tenantId"),
    )
    company_id: str = Field(
        pattern=_UUID.pattern,
        validation_alias=AliasChoices("company_id", "companyId"),
    )
    actor_user_id: str = Field(
        pattern=_UUID.pattern,
        validation_alias=AliasChoices("actor_user_id", "actorUserId"),
    )
    project_id: str = Field(
        pattern=_UUID.pattern,
        validation_alias=AliasChoices("project_id", "projectId"),
    )
    request_commitment_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        validation_alias=AliasChoices(
            "request_commitment_sha256", "requestCommitmentSha256"
        ),
    )
    deadline_at: str = Field(validation_alias=AliasChoices("deadline_at", "deadlineAt"))
    terminal_at: str | None = Field(
        default=None, validation_alias=AliasChoices("terminal_at", "terminalAt")
    )
    terminal_evidence_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        validation_alias=AliasChoices(
            "terminal_evidence_sha256", "terminalEvidenceSha256"
        ),
    )
    revision: int = Field(ge=0)

    @field_validator("deadline_at", "terminal_at")
    @classmethod
    def _communication_timestamps(cls, value: str | None, info: Any) -> str | None:
        return _normalize_timestamp(value, label=info.field_name)

    @model_validator(mode="before")
    @classmethod
    def _no_sensitive_response_fields(cls, value: Any) -> Any:
        _reject_sensitive_keys(value)
        return value

    @model_validator(mode="after")
    def _outcome_is_consistent(self) -> Self:
        if not self.terminal and self.model_execution_run_id is None:
            raise ValueError(
                "nonterminal communication runs require the retained model execution identity"
            )
        if self.success != (self.state == "VERIFIED_REPLY_RECORDED"):
            raise ValueError("communication success must match verified reply state")
        if self.success and not self.terminal:
            raise ValueError("verified reply must be terminal")
        if (self.terminal_at is None) != (not self.terminal):
            raise ValueError("terminal_at presence must match terminal")
        if (self.terminal_evidence_sha256 is None) != (not self.terminal):
            raise ValueError("terminal evidence presence must match terminal")
        return self

    @property
    def projection(self) -> GoldenLoopRunProjection:
        return GoldenLoopRunProjection(
            authority_schema=self.schema_id,
            loop_ref=GoldenLoopRef.REVENUE_VERIFIED_REPLY,
            loop_version=self.workflow_version,
            run_ref=self.run_ref,
            state=self.state,
            revision=self.revision,
            terminal=self.terminal,
            success=self.success,
            evidence=GoldenLoopEvidenceProjection(
                request_commitment_sha256=self.request_commitment_sha256,
                terminal_evidence_sha256=self.terminal_evidence_sha256,
            ),
            deadline_at=self.deadline_at,
            terminal_at=self.terminal_at,
        )


class GovernedCommunicationAdmissionResult(_StrictModel):
    idempotent_replay: bool = Field(
        validation_alias=AliasChoices("idempotent_replay", "idempotentReplay")
    )
    run: GovernedCommunicationRun

    @property
    def projection(self) -> GoldenLoopRunProjection:
        payload = self.run.projection.model_dump(mode="python")
        payload["idempotent_replay"] = self.idempotent_replay
        return GoldenLoopRunProjection.model_validate(payload)


def parse_golden_loop_economic_closure(
    value: Mapping[str, Any],
) -> GoldenLoopEconomicClosureProjection:
    if not isinstance(value, Mapping):
        raise GoldenLoopProjectionError(
            "golden_loop.economic_closure.response_not_object",
            "Golden Loop economic closure response must be an object",
        )
    _reject_sensitive_keys(value)
    try:
        return GoldenLoopEconomicClosureProjection.model_validate(value)
    except Exception as exc:
        raise GoldenLoopProjectionError(
            "golden_loop.economic_closure.response_contract_invalid",
            "Golden Loop economic closure response failed its exact contract",
        ) from exc


def parse_governed_communication_run(
    value: Mapping[str, Any],
) -> GovernedCommunicationRun:
    if not isinstance(value, Mapping):
        raise GoldenLoopProjectionError(
            "golden_loop.revenue.response_not_object",
            "governed communication response must be an object",
        )
    try:
        return GovernedCommunicationRun.model_validate(value)
    except Exception as exc:
        raise GoldenLoopProjectionError(
            "golden_loop.revenue.response_contract_invalid",
            "governed communication response failed its exact contract",
        ) from exc


def parse_governed_communication_sources(
    value: Mapping[str, Any],
) -> GovernedCommunicationSourcePage:
    if not isinstance(value, Mapping):
        raise GoldenLoopProjectionError(
            "golden_loop.revenue.source_page_not_object",
            "governed communication source page must be an object",
        )
    try:
        return GovernedCommunicationSourcePage.model_validate(value)
    except Exception as exc:
        raise GoldenLoopProjectionError(
            "golden_loop.revenue.source_page_contract_invalid",
            "governed communication source page failed its exact contract",
        ) from exc


def parse_governed_communication_admission(
    value: Mapping[str, Any],
) -> GovernedCommunicationAdmissionResult:
    if not isinstance(value, Mapping):
        raise GoldenLoopProjectionError(
            "golden_loop.revenue.admission_not_object",
            "governed communication admission must be an object",
        )
    try:
        return GovernedCommunicationAdmissionResult.model_validate(value)
    except Exception as exc:
        raise GoldenLoopProjectionError(
            "golden_loop.revenue.admission_contract_invalid",
            "governed communication admission failed its exact contract",
        ) from exc


def parse_project_work_packet_start(
    value: Mapping[str, Any],
) -> ProjectWorkPacketStartResult:
    if not isinstance(value, Mapping):
        raise GoldenLoopProjectionError(
            "golden_loop.project.start_not_object",
            "Project work-packet START response must be an object",
        )
    _reject_sensitive_keys(value)
    try:
        return ProjectWorkPacketStartResult.model_validate(value)
    except Exception as exc:
        raise GoldenLoopProjectionError(
            "golden_loop.project.start_contract_invalid",
            "Project work-packet START response failed its exact contract",
        ) from exc


def parse_project_work_packet_run(
    value: Mapping[str, Any],
) -> ProjectWorkPacketRunRead:
    if not isinstance(value, Mapping):
        raise GoldenLoopProjectionError(
            "golden_loop.project.run_not_object",
            "Project work-packet GET response must be an object",
        )
    _reject_sensitive_keys(value)
    try:
        return ProjectWorkPacketRunRead.model_validate(value)
    except Exception as exc:
        raise GoldenLoopProjectionError(
            "golden_loop.project.run_contract_invalid",
            "Project work-packet GET response failed its exact contract",
        ) from exc


def project_dynamic_workflow_run(
    value: Mapping[str, Any],
    *,
    terminal: bool | None = None,
) -> GoldenLoopRunProjection:
    """Project an already protocol-validated Dynamic Workflow response."""

    if not isinstance(value, Mapping):
        raise GoldenLoopProjectionError(
            "golden_loop.project.response_not_object",
            "Dynamic Workflow response must be an object",
        )
    allowed = {
        "run_ref",
        "revision",
        "status",
        "terminal",
        "cancelled",
    }
    selected = {key: value[key] for key in allowed if key in value}
    if not {"run_ref", "revision", "status"}.issubset(selected):
        raise GoldenLoopProjectionError(
            "golden_loop.project.response_contract_invalid",
            "Dynamic Workflow response is missing canonical run fields",
        )
    actual_terminal = (
        bool(selected.get("terminal")) if terminal is None else bool(terminal)
    )
    if bool(selected.get("cancelled")):
        actual_terminal = True
    status = str(selected["status"])
    return GoldenLoopRunProjection(
        authority_schema="lightbulb.dynamic_workflow_mcp.v1.5",
        loop_ref=GoldenLoopRef.PROJECT_WORK_PACKET,
        loop_version="0.1.0",
        run_ref=str(selected["run_ref"]),
        state=status,
        revision=selected["revision"],
        terminal=actual_terminal,
        success=actual_terminal and status == "accepted",
        evidence=GoldenLoopEvidenceProjection(),
    )


__all__ = [
    "CONTRACT_TO_CASH_PROJECTION",
    "FINANCE_JOURNAL_PROJECTION",
    "GOLDEN_LOOP_RUN_PROJECTION_SCHEMA",
    "GOLDEN_LOOP_ECONOMIC_CLOSURE_PROJECTION_SCHEMA",
    "PROJECT_WORK_PACKET_RUN_SCHEMA",
    "PROJECT_WORK_PACKET_START_SCHEMA",
    "GOVERNED_COMMUNICATION_ADMISSION_SCHEMA",
    "GOVERNED_COMMUNICATION_RUN_SCHEMA",
    "GOVERNED_COMMUNICATION_SOURCE_PAGE_SCHEMA",
    "SERVICE_CASE_RESOLUTION_CANDIDATE_SCHEMA",
    "SERVICE_CASE_RESOLUTION_RECEIPT_SCHEMA",
    "SERVICE_CASE_RESOLUTION_RUN_SCHEMA",
    "GoldenLoopEvidenceProjection",
    "GoldenLoopEconomicClosureProjection",
    "GoldenLoopEconomicSourceProjection",
    "GoldenLoopOperation",
    "GoldenLoopOperationAvailability",
    "GoldenLoopOperationContract",
    "GoldenLoopProjectionDescriptor",
    "GoldenLoopProjectionError",
    "GoldenLoopProjectionParticipation",
    "GoldenLoopRef",
    "GoldenLoopRunProjection",
    "canonical_golden_loop_run_ref",
    "ProjectWorkPacketStartResult",
    "ProjectWorkPacketRunRead",
    "GovernedCommunicationAdmission",
    "GovernedCommunicationAdmissionResult",
    "GovernedCommunicationRun",
    "GovernedCommunicationSource",
    "GovernedCommunicationSourcePage",
    "ServiceCaseResolutionCancel",
    "ServiceCaseResolutionNextAction",
    "ServiceCaseResolutionReceipt",
    "ServiceCaseResolutionRun",
    "ServiceCaseResolutionStart",
    "PROJECT_WORK_PACKET_PROJECTION",
    "PERIOD_RECONCILIATION_PROJECTION",
    "PROCUREMENT_MATCHED_CLOSE_PROJECTION",
    "REFERENCE_GOLDEN_LOOP_PROJECTIONS",
    "REVENUE_VERIFIED_REPLY_PROJECTION",
    "SERVICE_VERIFIED_RESOLUTION_PROJECTION",
    "VERIFIED_IMPROVEMENT_PROJECTION",
    "parse_golden_loop_economic_closure",
    "parse_governed_communication_admission",
    "parse_governed_communication_run",
    "parse_governed_communication_sources",
    "parse_project_work_packet_start",
    "parse_project_work_packet_run",
    "parse_service_case_resolution_run",
    "project_dynamic_workflow_run",
]
