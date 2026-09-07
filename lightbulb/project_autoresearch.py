"""Typed facade for Spring-owned Project AutoResearch runs.

Project AutoResearch derives its objective, domain, connected inputs, actor,
tenant, company, provider, and immutable budgets from authenticated Spring
state.  This facade deliberately accepts none of those values.  It can only
start research for one project in the client's selected company, read one run,
or explicitly cancel one run.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal, TypeVar
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError as PydanticValidationError,
    field_validator,
    model_validator,
)

from lightbulb.client import LightbulbClient
from lightbulb.errors import raise_if_error


PROJECT_AUTORESEARCH_RUN_RECEIPT_SCHEMA = (
    "lightbulb.project_autoresearch_run_receipt.v1"
)
PROJECT_AUTORESEARCH_ARTIFACT_TYPE = "MARKET_FINANCE_REPORT"
PROJECT_AUTORESEARCH_BASE_PATH = "/api/domain-agent/project-autoresearch"
PROJECT_AUTORESEARCH_USAGE_ACCOUNTING = "cumulative_acknowledged_attempt_receipts"

ProjectAutoResearchRunState = Literal[
    "queued",
    "running",
    "retry_wait",
    "succeeded",
    "failed",
    "cancelled",
]
ProjectAutoResearchObservationState = Literal[
    "not_created",
    "pending",
    "accepted",
    "failed",
]

_IDEMPOTENCY_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"
_MONEY_QUANTUM = Decimal("0.0001")
_TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled"})


class ProjectAutoResearchContractError(ValueError):
    """A Spring response did not satisfy the public AutoResearch contract."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


def _canonical_uuid(value: Any, field: str) -> UUID:
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field} must be a UUID without surrounding whitespace")
    try:
        return UUID(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a UUID") from exc


def _aware_datetime(value: Any, field: str) -> datetime:
    if isinstance(value, str):
        if value != value.strip():
            raise ValueError(f"{field} must not contain surrounding whitespace")
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            value = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field} must be a timezone-aware timestamp")
    if value.utcoffset() is None:
        raise ValueError(f"{field} must be a timezone-aware timestamp")
    return value


def _money4(value: Any, field: str) -> Decimal:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a decimal")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(
            f"{field} must be a finite decimal with at most four places"
        ) from exc
    if not parsed.is_finite() or parsed != parsed.quantize(_MONEY_QUANTUM):
        raise ValueError(f"{field} must be a finite decimal with at most four places")
    return parsed.quantize(_MONEY_QUANTUM)


class ProjectAutoResearchStartRequest(_StrictModel):
    """Exact Spring start body; all research context remains server-owned."""

    project_id: UUID
    confirm_paid_run: StrictBool
    idempotency_key: (
        Annotated[
            StrictStr,
            Field(min_length=1, max_length=128, pattern=_IDEMPOTENCY_PATTERN),
        ]
        | None
    ) = None

    @field_validator("project_id", mode="before")
    @classmethod
    def _project_uuid(cls, value: Any) -> UUID:
        return _canonical_uuid(value, "project_id")

    @field_validator("confirm_paid_run")
    @classmethod
    def _paid_run_confirmation(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("confirm_paid_run must be literal true")
        return value

    def to_http_body(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


class ProjectAutoResearchCancelRequest(_StrictModel):
    """Exact Spring cancellation body, including server-checked confirmation."""

    confirm_cancel: StrictBool
    reason: Annotated[StrictStr, Field(max_length=1_000)] | None = None
    idempotency_key: (
        Annotated[
            StrictStr,
            Field(min_length=1, max_length=128, pattern=_IDEMPOTENCY_PATTERN),
        ]
        | None
    ) = None

    @field_validator("reason", mode="before")
    @classmethod
    def _bounded_reason(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("reason must be text")
        normalized = value.strip()
        return normalized or None

    @field_validator("confirm_cancel")
    @classmethod
    def _cancel_confirmation(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("confirm_cancel must be literal true")
        return value

    def to_http_body(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


class _ProjectAutoResearchReceipt(_StrictModel):
    schema_id: Literal[PROJECT_AUTORESEARCH_RUN_RECEIPT_SCHEMA] = Field(alias="schema")
    run_id: UUID
    project_id: UUID
    outcome_status: Annotated[StrictStr, Field(min_length=1, max_length=64)] | None
    attempts: Annotated[StrictInt, Field(ge=0, le=10)]
    max_attempts: Annotated[StrictInt, Field(ge=1, le=10)]
    timeout_seconds: Annotated[StrictInt, Field(ge=10, le=1_800)]
    max_tokens: Annotated[StrictInt, Field(ge=1, le=1_000_000)]
    max_cost_usd: Annotated[Decimal, Field(gt=0, le=10_000)]
    tokens_used: Annotated[StrictInt, Field(ge=0, le=10_000_000_000)]
    cost_usd: Annotated[Decimal, Field(ge=0, le=10_000_000)]
    budget_overage: StrictBool
    usage_accounting: Literal[PROJECT_AUTORESEARCH_USAGE_ACCOUNTING]
    artifact_version: Annotated[StrictInt, Field(ge=1)]
    artifact_type: Literal[PROJECT_AUTORESEARCH_ARTIFACT_TYPE]
    observation_status: ProjectAutoResearchObservationState
    last_error: Annotated[StrictStr, Field(max_length=2_000)] | None
    created_at: AwareDatetime
    updated_at: AwareDatetime
    completed_at: AwareDatetime | None
    replayed: StrictBool
    status_url: StrictStr

    @field_validator("run_id", "project_id", mode="before")
    @classmethod
    def _receipt_uuids(cls, value: Any, info: Any) -> UUID:
        return _canonical_uuid(value, info.field_name)

    @field_validator("max_cost_usd", "cost_usd", mode="before")
    @classmethod
    def _receipt_money(cls, value: Any, info: Any) -> Decimal:
        return _money4(value, info.field_name)

    @field_validator("created_at", "updated_at", "completed_at", mode="before")
    @classmethod
    def _receipt_timestamps(cls, value: Any, info: Any) -> datetime | None:
        if value is None and info.field_name == "completed_at":
            return None
        return _aware_datetime(value, info.field_name)

    @model_validator(mode="after")
    def _validate_receipt_semantics(self) -> "_ProjectAutoResearchReceipt":
        expected_status_url = f"{PROJECT_AUTORESEARCH_BASE_PATH}/{self.run_id}"
        if self.status_url != expected_status_url:
            raise ValueError("status_url does not match run_id")
        if self.attempts > self.max_attempts:
            raise ValueError("attempts cannot exceed max_attempts")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if self.completed_at is not None and (
            self.completed_at < self.created_at or self.completed_at > self.updated_at
        ):
            raise ValueError("completed_at must fall between created_at and updated_at")

        run_state = getattr(self, "run_status", None) or getattr(self, "status", None)
        if run_state in _TERMINAL_STATES and self.completed_at is None:
            raise ValueError("terminal runs require completed_at")
        if run_state not in _TERMINAL_STATES and self.completed_at is not None:
            raise ValueError("non-terminal runs must not contain completed_at")
        if run_state == "succeeded" and self.outcome_status is None:
            raise ValueError("succeeded runs require outcome_status")
        if run_state == "succeeded" and self.attempts < 1:
            raise ValueError("succeeded runs require at least one attempt")
        if run_state == "succeeded" and self.budget_overage:
            raise ValueError("succeeded runs cannot report a budget overage")
        if run_state == "cancelled" and self.outcome_status != "cancelled":
            raise ValueError("cancelled runs require outcome_status='cancelled'")
        if run_state in {"queued", "running", "retry_wait", "failed"} and (
            self.outcome_status is not None
        ):
            raise ValueError(f"{run_state} runs must not contain outcome_status")
        cumulative_ceiling_exceeded = (
            self.tokens_used > self.max_tokens or self.cost_usd > self.max_cost_usd
        )
        if cumulative_ceiling_exceeded and not self.budget_overage:
            raise ValueError(
                "usage above a cumulative run ceiling requires budget_overage=true"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class ProjectAutoResearchStartReceipt(_ProjectAutoResearchReceipt):
    """The 202 start variant, including the durable state as ``run_status``."""

    status: Literal["started"]
    run_status: ProjectAutoResearchRunState


class ProjectAutoResearchStatusReceipt(_ProjectAutoResearchReceipt):
    """The GET variant, whose ``status`` is the durable run state."""

    status: ProjectAutoResearchRunState


class ProjectAutoResearchCancelReceipt(_ProjectAutoResearchReceipt):
    """The 202 cancellation variant returned after the canonical fence commits."""

    status: Literal["cancelled"]


ReceiptT = TypeVar("ReceiptT", bound=_ProjectAutoResearchReceipt)


def _parse_receipt(
    response: Any,
    model: type[ReceiptT],
    *,
    operation: str,
) -> ReceiptT:
    try:
        payload = response.json()
    except Exception:
        raise ProjectAutoResearchContractError(
            f"Project AutoResearch {operation} response was not valid JSON"
        ) from None
    if not isinstance(payload, dict):
        raise ProjectAutoResearchContractError(
            f"Project AutoResearch {operation} response must be a JSON object"
        )
    try:
        return model.model_validate(payload)
    except PydanticValidationError:
        raise ProjectAutoResearchContractError(
            f"Project AutoResearch {operation} response violated its receipt contract"
        ) from None


def _require_http_status(
    response: Any,
    *,
    expected: int,
    operation: str,
) -> None:
    if response.status_code != expected:
        raise ProjectAutoResearchContractError(
            "Project AutoResearch "
            f"{operation} expected HTTP {expected}, received "
            f"{response.status_code}"
        )


@dataclass(frozen=True, slots=True)
class ProjectAutoResearchClient:
    """Company-pinned facade over the real ``LightbulbClient`` session path."""

    inner: LightbulbClient

    def __post_init__(self) -> None:
        if not isinstance(self.inner, LightbulbClient):
            raise TypeError("inner must be a LightbulbClient")

    def start(
        self,
        project_id: UUID | str,
        *,
        idempotency_key: str | None = None,
        confirm_paid_run: bool = False,
    ) -> ProjectAutoResearchStartReceipt:
        """Start one server-resolved paid run after literal confirmation."""

        if confirm_paid_run is not True:
            raise ValueError(
                "confirm_paid_run=True is required to start paid Project AutoResearch"
            )
        request = ProjectAutoResearchStartRequest(
            project_id=project_id,
            confirm_paid_run=True,
            idempotency_key=idempotency_key,
        )
        headers = self._selected_company_headers()
        response = self.inner._get_session().post(
            f"{self.inner._base_url}{PROJECT_AUTORESEARCH_BASE_PATH}",
            json=request.to_http_body(),
            headers=headers,
        )
        raise_if_error(response)
        _require_http_status(response, expected=202, operation="start")
        receipt = _parse_receipt(
            response,
            ProjectAutoResearchStartReceipt,
            operation="start",
        )
        if receipt.project_id != request.project_id:
            raise ProjectAutoResearchContractError(
                "Project AutoResearch start receipt project binding mismatch"
            )
        return receipt

    def status(
        self,
        run_id: UUID | str,
    ) -> ProjectAutoResearchStatusReceipt:
        """Read one run through its exact current selected-company scope."""

        expected_run_id = _canonical_uuid(run_id, "run_id")
        headers = self._selected_company_headers()
        response = self.inner._get_session().get(
            (
                f"{self.inner._base_url}{PROJECT_AUTORESEARCH_BASE_PATH}/"
                f"{expected_run_id}"
            ),
            headers=headers,
        )
        raise_if_error(response)
        _require_http_status(response, expected=200, operation="status")
        receipt = _parse_receipt(
            response,
            ProjectAutoResearchStatusReceipt,
            operation="status",
        )
        if receipt.run_id != expected_run_id:
            raise ProjectAutoResearchContractError(
                "Project AutoResearch status receipt run binding mismatch"
            )
        return receipt

    def cancel(
        self,
        run_id: UUID | str,
        *,
        reason: str | None = None,
        idempotency_key: str | None = None,
        confirm_cancel: bool = False,
    ) -> ProjectAutoResearchCancelReceipt:
        """Commit the canonical cancellation fence after literal confirmation."""

        if confirm_cancel is not True:
            raise ValueError(
                "confirm_cancel=True is required to cancel Project AutoResearch"
            )
        expected_run_id = _canonical_uuid(run_id, "run_id")
        request = ProjectAutoResearchCancelRequest(
            confirm_cancel=True,
            reason=reason,
            idempotency_key=idempotency_key,
        )
        headers = self._selected_company_headers()
        response = self.inner._get_session().post(
            (
                f"{self.inner._base_url}{PROJECT_AUTORESEARCH_BASE_PATH}/"
                f"{expected_run_id}/cancel"
            ),
            json=request.to_http_body(),
            headers=headers,
        )
        raise_if_error(response)
        _require_http_status(response, expected=202, operation="cancel")
        receipt = _parse_receipt(
            response,
            ProjectAutoResearchCancelReceipt,
            operation="cancel",
        )
        if receipt.run_id != expected_run_id:
            raise ProjectAutoResearchContractError(
                "Project AutoResearch cancel receipt run binding mismatch"
            )
        return receipt

    def _selected_company_headers(self) -> dict[str, str]:
        company_id = self.inner._require_marketplace_company()
        return self.inner._exact_company_headers(company_id)


__all__ = [
    "PROJECT_AUTORESEARCH_ARTIFACT_TYPE",
    "PROJECT_AUTORESEARCH_BASE_PATH",
    "PROJECT_AUTORESEARCH_RUN_RECEIPT_SCHEMA",
    "PROJECT_AUTORESEARCH_USAGE_ACCOUNTING",
    "ProjectAutoResearchCancelReceipt",
    "ProjectAutoResearchCancelRequest",
    "ProjectAutoResearchClient",
    "ProjectAutoResearchContractError",
    "ProjectAutoResearchObservationState",
    "ProjectAutoResearchRunState",
    "ProjectAutoResearchStartReceipt",
    "ProjectAutoResearchStartRequest",
    "ProjectAutoResearchStatusReceipt",
]
