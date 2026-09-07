"""Trusted-host materialization for exact actions in profit workflow plans.

The profit planners deliberately perform zero external effects.  This module is
the separate execution boundary: it authenticates a host-HMAC plan, validates a
closed connector payload, consumes one exact platform approval, delegates the
effect to ``ConnectorExecutor``, verifies server-owned execution provenance, and
mints the existing profit action receipt.

Only explicitly modelled connector Tools are accepted.  A plan must contain the
SHA-256 digest of the canonical connector payload in an
``connector_arguments_digest`` intent parameter.  This keeps secrets such as an
email recipient or one-time discount code out of the immutable plan while still
binding the approved effect to the plan content.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Iterable, Literal, Mapping

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorErrorKind,
    ConnectorExecutionRequest,
    ConnectorExecutionResult,
    ConnectorExecutionStatus,
    ConnectorExecutor,
    ExecutionScope,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope
from lightbulb.profit_workflow_blueprints import ProfitScopeKeyRing
from lightbulb.profit_workflow_runtime import (
    GovernedProfitAction,
    ProfitActionExecutionReceipt,
    ProfitWorkflowPlan,
    mint_profit_action_execution_receipt,
    verify_profit_action_execution_receipt,
    verify_profit_workflow_plan,
)


PROFIT_ACTION_APPROVAL_GRANT_SCHEMA = "lightbulb.profit_action_approval_grant.v1"
PROFIT_ACTION_MATERIALIZATION_RESULT_SCHEMA = (
    "lightbulb.profit_action_materialization_result.v1"
)

_APPROVAL_GRANT_HMAC_DOMAIN = PROFIT_ACTION_APPROVAL_GRANT_SCHEMA
_ARGUMENTS_DIGEST_PARAMETER = "connector_arguments_digest"
_MATERIALIZER_ISSUER = "lightbulb-profit-materializer"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VISIBLE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,239}$")
_PRODUCT_ID_RE = re.compile(
    r"^(?:[0-9]+|gid://shopify/(?:Product|ProductVariant)/[0-9]+)$"
)
_DISCOUNT_CODE_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{3,63}$")
_LINKEDIN_TEXT_LIMIT = 3_000

ProfitMaterializationStatus = Literal[
    "preview",
    "pending_approval",
    "completed",
    "blocked",
    "failed",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )


def _visible(value: str, *, label: str, maximum: int = 240) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    if value != value.strip() or not value or len(value) > maximum:
        raise ValueError(f"{label} must contain 1 to {maximum} visible characters")
    if any(ord(character) < 33 for character in value):
        raise ValueError(f"{label} must contain visible characters only")
    return value


def _body(value: str, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be non-blank without surrounding whitespace")
    if len(value) > maximum or any(
        ord(character) < 32 and character not in {"\t", "\n", "\r"}
        for character in value
    ):
        raise ValueError(f"{label} contains unsupported or excessive content")
    return value


def _timestamp(value: str, *, label: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _stable_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


class GmailSendEmailArguments(_StrictModel):
    to: str = Field(min_length=3, max_length=998)
    subject: str = Field(min_length=1, max_length=998)
    body: str = Field(min_length=1, max_length=50_000)
    cc: str | None = Field(default=None, min_length=3, max_length=998)
    html: bool = False

    @field_validator("to", "cc")
    @classmethod
    def _mailbox(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = _visible(value, label="email recipient", maximum=998)
        if "@" not in clean or "\n" in clean or "\r" in clean:
            raise ValueError("email recipient is not a bounded mailbox list")
        return clean

    @field_validator("subject")
    @classmethod
    def _subject(cls, value: str) -> str:
        clean = _body(value, label="email subject", maximum=998)
        if "\n" in clean or "\r" in clean:
            raise ValueError("email subject must not contain line breaks")
        return clean

    @field_validator("body")
    @classmethod
    def _message(cls, value: str) -> str:
        return _body(value, label="email body", maximum=50_000)


class EcommerceCreateDiscountArguments(_StrictModel):
    title: str = Field(min_length=1, max_length=255)
    code: str = Field(pattern=r"^[A-Z0-9][A-Z0-9_-]{3,63}$")
    percentage: Decimal = Field(gt=0, le=50)
    starts_at: str
    ends_at: str
    usage_limit: int = Field(ge=1, le=100)

    @field_validator("title")
    @classmethod
    def _title(cls, value: str) -> str:
        return _body(value, label="discount title", maximum=255)

    @field_validator("percentage", mode="before")
    @classmethod
    def _percentage(cls, value: Any) -> Decimal:
        if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
            raise ValueError("discount percentage must be numeric")
        try:
            parsed = Decimal(str(value)).quantize(Decimal("0.01"))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("discount percentage must be finite") from exc
        if not parsed.is_finite():
            raise ValueError("discount percentage must be finite")
        return parsed

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _time(cls, value: str, info: Any) -> str:
        return _timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _bounded_window(self) -> "EcommerceCreateDiscountArguments":
        start = datetime.fromisoformat(self.starts_at.replace("Z", "+00:00"))
        end = datetime.fromisoformat(self.ends_at.replace("Z", "+00:00"))
        duration = (end - start).total_seconds()
        if duration <= 0 or duration > 30 * 24 * 3_600:
            raise ValueError("discount window must be positive and at most 30 days")
        return self


class EcommerceUpdateProductArguments(_StrictModel):
    product_id: str = Field(min_length=1, max_length=200)
    variant_id: str | None = Field(default=None, min_length=1, max_length=200)
    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None, min_length=1, max_length=10_000)
    vendor: str | None = Field(default=None, min_length=1, max_length=300)
    product_type: str | None = Field(default=None, min_length=1, max_length=300)
    status: Literal["ACTIVE", "DRAFT", "ARCHIVED"] | None = None
    tags: tuple[str, ...] | None = Field(default=None, max_length=50)
    price: str | None = Field(
        default=None,
        pattern=r"^(?:0|[1-9][0-9]{0,8})\.[0-9]{2}$",
    )
    sku: str | None = Field(default=None, min_length=1, max_length=100)
    taxable: bool | None = None
    requires_shipping: bool | None = None

    @field_validator("product_id", "variant_id")
    @classmethod
    def _product_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _PRODUCT_ID_RE.fullmatch(value):
            raise ValueError("Shopify product reference is invalid")
        return value

    @field_validator("tags", mode="before")
    @classmethod
    def _tags(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("title", "vendor", "product_type", "sku")
    @classmethod
    def _text(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _body(value, label=info.field_name, maximum=300)

    @field_validator("description")
    @classmethod
    def _description(cls, value: str | None) -> str | None:
        return (
            None if value is None else _body(value, label="description", maximum=10_000)
        )

    @model_validator(mode="after")
    def _has_update(self) -> "EcommerceUpdateProductArguments":
        updates = self.model_dump(
            mode="python",
            exclude={"product_id", "variant_id"},
            exclude_none=True,
        )
        if not updates:
            raise ValueError("ecommerce.update_product requires an updated field")
        variant_updates = {"price", "sku", "taxable", "requires_shipping"}.intersection(
            updates
        )
        if variant_updates and self.variant_id is None:
            raise ValueError("variant updates require variant_id")
        return self


class FacebookPublishPostArguments(_StrictModel):
    page_id: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=10_000)
    image_url: str | None = Field(default=None, max_length=2_048)

    @field_validator("page_id")
    @classmethod
    def _page(cls, value: str) -> str:
        return _visible(value, label="page_id", maximum=200)

    @field_validator("message")
    @classmethod
    def _message(cls, value: str) -> str:
        return _body(value, label="Facebook message", maximum=10_000)

    @field_validator("image_url")
    @classmethod
    def _image(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("https://"):
            raise ValueError("Facebook image_url must use public HTTPS")
        return value


class InstagramPublishPostArguments(_StrictModel):
    instagram_business_account_id: str = Field(min_length=1, max_length=200)
    caption: str = Field(min_length=1, max_length=10_000)
    image_url: str = Field(min_length=9, max_length=2_048)

    @field_validator("instagram_business_account_id")
    @classmethod
    def _account(cls, value: str) -> str:
        return _visible(value, label="instagram_business_account_id", maximum=200)

    @field_validator("caption")
    @classmethod
    def _caption(cls, value: str) -> str:
        return _body(value, label="Instagram caption", maximum=10_000)

    @field_validator("image_url")
    @classmethod
    def _image(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("Instagram image_url must use public HTTPS")
        return value


class LinkedInPublishPostArguments(_StrictModel):
    author_urn: str = Field(min_length=1, max_length=300)
    text: str = Field(min_length=1, max_length=_LINKEDIN_TEXT_LIMIT)
    url: str | None = Field(default=None, max_length=2_048)
    image_url: str | None = Field(default=None, max_length=2_048)

    @field_validator("author_urn")
    @classmethod
    def _author(cls, value: str) -> str:
        return _visible(value, label="author_urn", maximum=300)

    @field_validator("text")
    @classmethod
    def _text(cls, value: str) -> str:
        return _body(value, label="LinkedIn text", maximum=_LINKEDIN_TEXT_LIMIT)

    @field_validator("url", "image_url")
    @classmethod
    def _url(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("https://"):
            raise ValueError("LinkedIn URLs must use public HTTPS")
        return value


_ARGUMENT_MODELS: dict[str, type[_StrictModel]] = {
    "gmail.send_email": GmailSendEmailArguments,
    "ecommerce.create_discount": EcommerceCreateDiscountArguments,
    "ecommerce.update_product": EcommerceUpdateProductArguments,
    "facebook.publish_post": FacebookPublishPostArguments,
    "instagram.publish_post": InstagramPublishPostArguments,
    "linkedin.publish_post": LinkedInPublishPostArguments,
}


def canonical_profit_connector_arguments(
    capability: str,
    value: Mapping[str, Any] | BaseModel,
) -> dict[str, Any]:
    """Validate and canonicalize one code-owned connector payload."""

    try:
        model_type = _ARGUMENT_MODELS[capability]
    except KeyError:
        raise ValueError(
            "profit materializer does not support this connector Tool"
        ) from None
    raw = (
        value.model_dump(mode="python", exclude_none=True)
        if isinstance(value, BaseModel)
        else value
    )
    try:
        parsed = model_type.model_validate(raw)
    except ValidationError:
        raise ValueError("connector arguments failed closed-world validation") from None
    return parsed.model_dump(mode="json", exclude_none=True)


def profit_connector_arguments_digest(
    capability: str,
    value: Mapping[str, Any] | BaseModel,
) -> str:
    """Return the digest a candidate must commit to before materialization."""

    return _stable_digest(
        {
            "capability": capability,
            "arguments": canonical_profit_connector_arguments(capability, value),
        }
    )


class ProfitActionApprovalGrant(_StrictModel):
    schema_id: Literal["lightbulb.profit_action_approval_grant.v1"] = Field(
        default=PROFIT_ACTION_APPROVAL_GRANT_SCHEMA,
        alias="schema",
    )
    workflow_id: str = Field(min_length=3, max_length=160)
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_ref: str = Field(min_length=1, max_length=180)
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability: str = Field(min_length=3, max_length=200)
    connector_account_ref: str = Field(min_length=1, max_length=200)
    connector_arguments_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_unit: str = Field(min_length=1, max_length=500)
    approval_ref: str = Field(min_length=1, max_length=200)
    approval_receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    grant_key_id: str = Field(min_length=8, max_length=80)
    grant_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "workflow_id",
        "operation_ref",
        "capability",
        "connector_account_ref",
        "approval_unit",
        "approval_ref",
        "grant_key_id",
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, label=info.field_name, maximum=500)

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"grant_hmac"},
        )


class ProfitActionMaterializationResult(_StrictModel):
    schema_id: Literal["lightbulb.profit_action_materialization_result.v1"] = Field(
        default=PROFIT_ACTION_MATERIALIZATION_RESULT_SCHEMA,
        alias="schema",
    )
    status: ProfitMaterializationStatus
    workflow_id: str
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_ref: str
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability: str
    connector_account_ref: str
    connector_arguments_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_ref: str
    iteration: int = Field(ge=1, le=4)
    idempotency_key: str = Field(min_length=1, max_length=240)
    connector_status: ConnectorExecutionStatus | None = None
    connector_error_kind: ConnectorErrorKind | None = None
    connector_error_code: str | None = Field(default=None, max_length=160)
    approval_ref: str | None = Field(default=None, max_length=200)
    approval_receipt_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    execution_receipt_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    receipt: ProfitActionExecutionReceipt | None = None
    live_systems_changed: bool | None = False
    summary: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def _status_contract(self) -> "ProfitActionMaterializationResult":
        completed = self.status == "completed"
        if completed != (
            self.connector_status == ConnectorExecutionStatus.COMPLETED
            and self.approval_ref is not None
            and self.approval_receipt_digest is not None
            and self.execution_receipt_digest is not None
            and self.receipt is not None
            and self.live_systems_changed is True
        ):
            raise ValueError(
                "completed action requires complete governed effect evidence"
            )
        if not completed and any(
            value is not None for value in (self.execution_receipt_digest, self.receipt)
        ):
            raise ValueError("non-completed action cannot expose completion evidence")
        if self.status == "pending_approval" and (
            self.connector_status != ConnectorExecutionStatus.PENDING_APPROVAL
            or self.approval_ref is None
            or self.approval_receipt_digest is None
            or self.live_systems_changed is not False
        ):
            raise ValueError(
                "pending action requires a durable approval reference and receipt"
            )
        if (
            self.status in {"preview", "blocked"}
            and self.live_systems_changed is not False
        ):
            raise ValueError("preview and blocked actions cannot claim an effect")
        if self.status == "failed" and self.live_systems_changed not in {False, None}:
            raise ValueError(
                "failed action may report no effect or unknown effect only"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _scope(value: DynamicWorkflowScope | Mapping[str, Any]) -> DynamicWorkflowScope:
    return (
        value
        if isinstance(value, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(value)
    )


def _execution_scope(value: ExecutionScope | Mapping[str, Any]) -> ExecutionScope:
    return (
        value
        if isinstance(value, ExecutionScope)
        else ExecutionScope.model_validate(value)
    )


def _validate_execution_scope(
    runtime_scope: ExecutionScope,
    workflow_scope: DynamicWorkflowScope,
) -> None:
    if runtime_scope.project_id is None:
        raise ValueError(
            "profit action materialization requires an authenticated project UUID"
        )
    expected = (
        workflow_scope.tenant_id,
        workflow_scope.company_id,
        workflow_scope.project_ref,
        workflow_scope.user_id,
    )
    actual = (
        runtime_scope.tenant_ref,
        runtime_scope.company_ref,
        runtime_scope.project_ref,
        runtime_scope.actor_ref,
    )
    if actual != expected:
        raise ValueError(
            "execution scope does not match the authenticated workflow scope"
        )


def _action(plan: ProfitWorkflowPlan, operation_ref: str) -> GovernedProfitAction:
    matches = [item for item in plan.actions if item.operation_ref == operation_ref]
    if len(matches) != 1:
        raise ValueError("operation_ref does not identify one planned action")
    action = matches[0]
    if (
        action.disposition != "proposal"
        or action.execution_kind != "connector_tool"
        or action.effect != "WRITE"
        or not action.approval_required
        or action.approval_unit is None
        or action.target_account_ref is None
    ):
        raise ValueError("planned action is not an approval-gated connector write")
    if action.capability not in _ARGUMENT_MODELS:
        raise ValueError("planned connector Tool has no trusted materializer adapter")
    return action


def _parameter_map(action: GovernedProfitAction) -> dict[str, str]:
    return {item.name: item.value for item in action.intent_parameters}


def _verify_arguments_commitment(
    action: GovernedProfitAction,
    arguments: Mapping[str, Any],
) -> str:
    digest = profit_connector_arguments_digest(action.capability, arguments)
    committed = _parameter_map(action).get(_ARGUMENTS_DIGEST_PARAMETER)
    if committed is None or not _SHA256_RE.fullmatch(committed):
        raise ValueError(
            "planned action has no canonical connector arguments commitment"
        )
    if not hmac.compare_digest(committed, digest):
        raise ValueError("connector arguments do not match the authenticated action")
    return digest


def _grant(
    value: ProfitActionApprovalGrant | Mapping[str, Any] | None,
    *,
    scope_keyring: ProfitScopeKeyRing,
) -> ProfitActionApprovalGrant | None:
    if value is None:
        return None
    try:
        grant = ProfitActionApprovalGrant.model_validate(
            value.model_dump(mode="python", by_alias=True)
            if isinstance(value, ProfitActionApprovalGrant)
            else value
        )
    except ValidationError:
        raise ValueError("profit action approval grant failed validation") from None
    try:
        expected = scope_keyring.sign(
            grant.grant_key_id,
            _APPROVAL_GRANT_HMAC_DOMAIN,
            grant.hmac_payload(),
        ).hex()
    except Exception:
        raise ValueError("profit approval grant signing key is unavailable") from None
    if not hmac.compare_digest(grant.grant_hmac, expected):
        raise ValueError("profit action approval grant HMAC is invalid")
    return grant


def bind_profit_action_approval(
    plan_value: ProfitWorkflowPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
    operation_ref: str,
    connector_arguments: Mapping[str, Any] | BaseModel,
    approval_ref: str,
    approval_receipt_digest: str,
) -> ProfitActionApprovalGrant:
    """Bind one platform approval proof to one exact plan/action/payload."""

    workflow_scope = _scope(scope)
    plan = verify_profit_workflow_plan(
        plan_value,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    action = _action(plan, operation_ref)
    arguments = canonical_profit_connector_arguments(
        action.capability, connector_arguments
    )
    arguments_digest = _verify_arguments_commitment(action, arguments)
    if plan.receipt_key_id is None or plan.exact_scope_digest is None:
        raise ValueError("authenticated plan has no receipt binding")
    if not _SHA256_RE.fullmatch(approval_receipt_digest):
        raise ValueError("approval_receipt_digest must be lowercase SHA-256")
    clean_approval_ref = _visible(approval_ref, label="approval_ref", maximum=200)
    draft = ProfitActionApprovalGrant(
        workflow_id=plan.workflow_id,
        plan_digest=plan.plan_digest,
        exact_scope_digest=plan.exact_scope_digest,
        operation_ref=action.operation_ref,
        operation_digest=action.operation_digest,
        capability=action.capability,
        connector_account_ref=action.target_account_ref,
        connector_arguments_digest=arguments_digest,
        approval_unit=action.approval_unit,
        approval_ref=clean_approval_ref,
        approval_receipt_digest=approval_receipt_digest,
        grant_key_id=plan.receipt_key_id,
        grant_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        draft.grant_key_id,
        _APPROVAL_GRANT_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    return ProfitActionApprovalGrant.model_validate(
        {**draft.model_dump(mode="python", by_alias=True), "grant_hmac": signature}
    )


def _run_ref(value: str) -> str:
    clean = _visible(value, label="run_ref", maximum=160)
    if not _VISIBLE_REF_RE.fullmatch(clean):
        raise ValueError("run_ref contains unsupported characters")
    return clean


def _idempotency_key(
    plan: ProfitWorkflowPlan,
    action: GovernedProfitAction,
    *,
    run_ref: str,
    iteration: int,
    arguments_digest: str,
    dependency_execution_digests: tuple[str, ...],
) -> str:
    digest = _stable_digest(
        {
            "issuer": _MATERIALIZER_ISSUER,
            "plan_digest": plan.plan_digest,
            "operation_digest": action.operation_digest,
            "run_ref": run_ref,
            "iteration": iteration,
            "arguments_digest": arguments_digest,
            "dependency_execution_digests": dependency_execution_digests,
        }
    )
    return f"profit:{action.capability}:{digest}"


def _result(
    *,
    status: ProfitMaterializationStatus,
    plan: ProfitWorkflowPlan,
    action: GovernedProfitAction,
    arguments_digest: str,
    run_ref: str,
    iteration: int,
    idempotency_key: str,
    summary: str,
    connector_status: ConnectorExecutionStatus | None = None,
    connector_error_kind: ConnectorErrorKind | None = None,
    connector_error_code: str | None = None,
    approval_ref: str | None = None,
    approval_receipt_digest: str | None = None,
    execution_receipt_digest: str | None = None,
    receipt: ProfitActionExecutionReceipt | None = None,
    live_systems_changed: bool | None = False,
) -> ProfitActionMaterializationResult:
    return ProfitActionMaterializationResult(
        status=status,
        workflow_id=plan.workflow_id,
        plan_digest=plan.plan_digest,
        operation_ref=action.operation_ref,
        operation_digest=action.operation_digest,
        capability=action.capability,
        connector_account_ref=action.target_account_ref,
        connector_arguments_digest=arguments_digest,
        run_ref=run_ref,
        iteration=iteration,
        idempotency_key=idempotency_key,
        connector_status=connector_status,
        connector_error_kind=connector_error_kind,
        connector_error_code=connector_error_code,
        approval_ref=approval_ref,
        approval_receipt_digest=approval_receipt_digest,
        execution_receipt_digest=execution_receipt_digest,
        receipt=receipt,
        live_systems_changed=live_systems_changed,
        summary=summary,
    )


def _same_shopify_resource_id(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return left.strip().rsplit("/", 1)[-1] == right.strip().rsplit("/", 1)[-1]


def _same_decimal(left: Any, right: Any, *, quantum: Decimal) -> bool:
    try:
        return Decimal(str(left)).quantize(quantum) == Decimal(str(right)).quantize(
            quantum
        )
    except (InvalidOperation, TypeError, ValueError):
        return False


def _same_timestamp(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return _timestamp(left, label="provider timestamp") == _timestamp(
            right, label="requested timestamp"
        )
    except ValueError:
        return False


def _discount_code_proof_matches(value: Any, expected: str) -> bool:
    if isinstance(value, str):
        return hmac.compare_digest(value, expected)
    if not isinstance(value, Mapping) or set(value) != {
        "redacted",
        "sha256",
        "size",
    }:
        return False
    digest = value.get("sha256")
    size = value.get("size")
    return (
        value.get("redacted") is True
        and isinstance(digest, str)
        and _SHA256_RE.fullmatch(digest) is not None
        and isinstance(size, int)
        and not isinstance(size, bool)
        and size == len(expected)
        and hmac.compare_digest(digest, _stable_digest(expected))
    )


def _discount_output_proves(
    payload: Mapping[str, Any], arguments: Mapping[str, Any]
) -> bool:
    if payload.get("success") is not True:
        return False
    node = payload.get("discount_node")
    if not isinstance(node, Mapping):
        return False
    node_id = node.get("id")
    discount = node.get("codeDiscount")
    if (
        not isinstance(node_id, str)
        or re.fullmatch(r"gid://shopify/DiscountCodeNode/[1-9][0-9]{0,30}", node_id)
        is None
        or not isinstance(discount, Mapping)
    ):
        return False
    codes_count = discount.get("codesCount")
    codes = discount.get("codes")
    code_nodes = codes.get("nodes") if isinstance(codes, Mapping) else None
    if (
        not isinstance(codes_count, Mapping)
        or codes_count.get("count") != 1
        or isinstance(codes_count.get("count"), bool)
        or not isinstance(code_nodes, (list, tuple))
        or len(code_nodes) != 1
        or not isinstance(code_nodes[0], Mapping)
    ):
        return False
    expected_code = arguments.get("code")
    if not isinstance(expected_code, str) or not all(
        _discount_code_proof_matches(value, expected_code)
        for value in (payload.get("code"), code_nodes[0].get("code"))
    ):
        return False
    expected_title = arguments.get("title")
    if (
        payload.get("title") != expected_title
        or discount.get("title") != expected_title
    ):
        return False
    if discount.get("status") not in {"ACTIVE", "SCHEDULED"}:
        return False
    expected_start = arguments.get("starts_at")
    expected_end = arguments.get("ends_at")
    if not (
        _same_timestamp(payload.get("starts_at"), expected_start)
        and _same_timestamp(discount.get("startsAt"), expected_start)
        and _same_timestamp(payload.get("ends_at"), expected_end)
        and _same_timestamp(discount.get("endsAt"), expected_end)
    ):
        return False
    expected_usage = arguments.get("usage_limit")
    if (
        isinstance(expected_usage, bool)
        or not isinstance(expected_usage, int)
        or payload.get("usage_limit") != expected_usage
        or discount.get("usageLimit") != expected_usage
    ):
        return False
    provider_value = discount.get("customerGets")
    if isinstance(provider_value, Mapping):
        provider_value = provider_value.get("value")
    provider_percentage = (
        provider_value.get("percentage")
        if isinstance(provider_value, Mapping)
        else None
    )
    try:
        normalized_provider_percentage = Decimal(str(provider_percentage)) * 100
    except (InvalidOperation, TypeError, ValueError):
        return False
    return _same_decimal(
        payload.get("percentage"),
        arguments.get("percentage"),
        quantum=Decimal("0.01"),
    ) and _same_decimal(
        normalized_provider_percentage,
        arguments.get("percentage"),
        quantum=Decimal("0.01"),
    )


def _product_update_payload_proves(
    payload: Mapping[str, Any],
    arguments: Mapping[str, Any],
) -> bool:
    if payload.get("success") is not True or not _same_shopify_resource_id(
        payload.get("product_id"), arguments.get("product_id")
    ):
        return False
    if any(
        key in payload and payload.get(key) not in (None, {})
        for key in ("variant_error", "price_error")
    ):
        return False

    product_fields = (
        "title",
        "description",
        "vendor",
        "product_type",
        "status",
        "tags",
    )
    requested_product_fields = tuple(
        field for field in product_fields if arguments.get(field) is not None
    )
    if requested_product_fields:
        product = payload.get("product")
        if not isinstance(product, Mapping):
            return False
        for field in requested_product_fields:
            observed = product.get(field)
            expected = arguments[field]
            if field == "tags":
                if not isinstance(observed, (list, tuple)) or tuple(observed) != tuple(
                    expected
                ):
                    return False
            elif field == "status":
                if (
                    not isinstance(observed, str)
                    or observed.upper() != str(expected).upper()
                ):
                    return False
            elif observed != expected:
                return False

    variant_fields = ("price", "sku", "taxable", "requires_shipping")
    requested_variant_fields = tuple(
        field for field in variant_fields if arguments.get(field) is not None
    )
    if not requested_variant_fields:
        return True
    if payload.get("variant_updated") is not True:
        return False
    if "price" in requested_variant_fields and payload.get("price_applied") is not True:
        return False
    variant_id = arguments.get("variant_id")
    if not _same_shopify_resource_id(payload.get("variant_id"), variant_id):
        return False
    variants = payload.get("variants")
    if not isinstance(variants, (list, tuple)):
        return False
    matching = [
        item
        for item in variants
        if isinstance(item, Mapping)
        and _same_shopify_resource_id(item.get("variant_id"), variant_id)
    ]
    if len(matching) != 1:
        return False
    variant = matching[0]
    for field in requested_variant_fields:
        if field == "price":
            if not _same_decimal(
                variant.get(field), arguments[field], quantum=Decimal("0.01")
            ):
                return False
        elif variant.get(field) != arguments[field]:
            return False
    return True


def _output_proves_effect(
    capability: str,
    output: Mapping[str, Any],
    arguments: Mapping[str, Any],
) -> bool:
    payloads: list[Mapping[str, Any]] = [output]
    for key in ("output", "result", "data"):
        nested = output.get(key)
        if isinstance(nested, Mapping):
            payloads.append(nested)
    if capability == "gmail.send_email":
        return any(
            isinstance(payload.get(key), str) and str(payload.get(key)).strip()
            for payload in payloads
            for key in ("messageId", "message_id", "id")
        )
    if capability == "ecommerce.create_discount":
        return any(_discount_output_proves(payload, arguments) for payload in payloads)
    if capability == "ecommerce.update_product":
        return any(
            _product_update_payload_proves(payload, arguments) for payload in payloads
        )
    if capability in {
        "facebook.publish_post",
        "instagram.publish_post",
        "linkedin.publish_post",
    }:
        target_field = {
            "facebook.publish_post": "page_id",
            "instagram.publish_post": "instagram_business_account_id",
            "linkedin.publish_post": "author_urn",
        }[capability]
        expected_target = arguments.get(target_field)
        return any(
            str(payload.get("status") or "").casefold() == "published"
            and isinstance(expected_target, str)
            and payload.get(target_field) == expected_target
            and any(
                isinstance(payload.get(key), str) and str(payload.get(key)).strip()
                for key in ("post_id", "id", "media_id")
            )
            for payload in payloads
        )
    return False


@dataclass(frozen=True, slots=True)
class _ProfitActionDispatchPreflight:
    workflow_scope: DynamicWorkflowScope
    runtime_scope: ExecutionScope
    plan: ProfitWorkflowPlan
    action: GovernedProfitAction
    arguments: dict[str, Any]
    arguments_digest: str
    clean_run_ref: str
    iteration: int
    dependency_receipts: tuple[ProfitActionExecutionReceipt, ...]
    dependency_digests: tuple[str, ...]
    grant: ProfitActionApprovalGrant | None
    idempotency_key: str
    request: ConnectorExecutionRequest | None
    preview_only: bool


def _prepare_profit_action_dispatch(
    plan_value: ProfitWorkflowPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
    execution_scope: ExecutionScope | Mapping[str, Any],
    operation_ref: str,
    connector_arguments: Mapping[str, Any] | BaseModel,
    run_ref: str,
    iteration: int,
    preview_only: bool,
    approval_grant: ProfitActionApprovalGrant | Mapping[str, Any] | None,
    dependency_receipts: Iterable[ProfitActionExecutionReceipt | Mapping[str, Any]],
    allow_recovery: bool,
) -> _ProfitActionDispatchPreflight:
    """Validate and bind one dispatch without reserving or performing external I/O."""

    workflow_scope = _scope(scope)
    runtime_scope = _execution_scope(execution_scope)
    _validate_execution_scope(runtime_scope, workflow_scope)
    plan = verify_profit_workflow_plan(
        plan_value,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    is_recovery = plan.workflow_id == "commerce.recover_abandoned_revenue"
    if is_recovery and not allow_recovery:
        raise ValueError(
            "abandoned-revenue actions require run_abandoned_revenue_recovery "
            "and a fresh dispatch safety attestation"
        )
    if allow_recovery and not is_recovery:
        raise ValueError("recovery materialization requires the recovery workflow")
    action = _action(plan, operation_ref)
    arguments = canonical_profit_connector_arguments(
        action.capability, connector_arguments
    )
    arguments_digest = _verify_arguments_commitment(action, arguments)
    clean_run_ref = _run_ref(run_ref)
    if isinstance(iteration, bool) or not isinstance(iteration, int):
        raise ValueError("iteration must be an integer")
    if not 1 <= iteration <= plan.evaluation_loop.max_iterations:
        raise ValueError("iteration exceeds the authenticated workflow loop")
    parsed_dependencies: list[ProfitActionExecutionReceipt] = []
    for raw_receipt in dependency_receipts:
        if len(parsed_dependencies) >= len(action.depends_on):
            raise ValueError("too many dependency execution receipts")
        receipt = verify_profit_action_execution_receipt(
            raw_receipt,
            plan=plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        if receipt.run_ref != clean_run_ref or receipt.iteration != iteration:
            raise ValueError("dependency receipt run or iteration mismatch")
        parsed_dependencies.append(receipt)
    if not preview_only and {item.operation_ref for item in parsed_dependencies} != set(
        action.depends_on
    ):
        raise ValueError("action requires one exact receipt for every dependency")
    dependency_digests = tuple(
        item.execution_digest
        for item in sorted(parsed_dependencies, key=lambda item: item.operation_ref)
    )
    grant = _grant(approval_grant, scope_keyring=scope_keyring)
    if grant is not None:
        expected = (
            plan.workflow_id,
            plan.plan_digest,
            plan.exact_scope_digest,
            action.operation_ref,
            action.operation_digest,
            action.capability,
            action.target_account_ref,
            arguments_digest,
            action.approval_unit,
            plan.receipt_key_id,
        )
        actual = (
            grant.workflow_id,
            grant.plan_digest,
            grant.exact_scope_digest,
            grant.operation_ref,
            grant.operation_digest,
            grant.capability,
            grant.connector_account_ref,
            grant.connector_arguments_digest,
            grant.approval_unit,
            grant.grant_key_id,
        )
        if actual != expected:
            raise ValueError(
                "profit action approval grant does not match plan/action/payload"
            )
    key = _idempotency_key(
        plan,
        action,
        run_ref=clean_run_ref,
        iteration=iteration,
        arguments_digest=arguments_digest,
        dependency_execution_digests=dependency_digests,
    )
    request = None
    if not preview_only:
        request = ConnectorExecutionRequest(
            tool=action.capability,
            arguments=arguments,
            scope=runtime_scope,
            effect=ConnectorEffect.WRITE,
            approval_required=True,
            approval_ref=grant.approval_ref if grant is not None else None,
            preview_only=False,
            idempotency_key=key,
            connector_account_ref=action.target_account_ref,
            metadata={
                "workflow_id": plan.workflow_id,
                "plan_digest": plan.plan_digest,
                "operation_ref": action.operation_ref,
                "operation_digest": action.operation_digest,
                "run_ref": clean_run_ref,
                "iteration": iteration,
                "approval_unit": action.approval_unit,
                "approval_receipt_digest": (
                    grant.approval_receipt_digest if grant is not None else None
                ),
                "dependency_execution_digests": list(dependency_digests),
            },
        )
    return _ProfitActionDispatchPreflight(
        workflow_scope=workflow_scope,
        runtime_scope=runtime_scope,
        plan=plan,
        action=action,
        arguments=arguments,
        arguments_digest=arguments_digest,
        clean_run_ref=clean_run_ref,
        iteration=iteration,
        dependency_receipts=tuple(parsed_dependencies),
        dependency_digests=dependency_digests,
        grant=grant,
        idempotency_key=key,
        request=request,
        preview_only=preview_only,
    )


def _materialize_profit_action(
    plan_value: ProfitWorkflowPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
    execution_scope: ExecutionScope | Mapping[str, Any],
    executor: ConnectorExecutor,
    operation_ref: str,
    connector_arguments: Mapping[str, Any] | BaseModel,
    run_ref: str,
    iteration: int = 1,
    preview_only: bool = True,
    approval_grant: ProfitActionApprovalGrant | Mapping[str, Any] | None = None,
    dependency_receipts: Iterable[
        ProfitActionExecutionReceipt | Mapping[str, Any]
    ] = (),
    allow_recovery: bool,
    before_connector_dispatch: Callable[[ConnectorExecutionRequest], None] | None,
) -> ProfitActionMaterializationResult:
    """Shared materializer; every route performs the same deterministic preflight."""

    prepared = _prepare_profit_action_dispatch(
        plan_value,
        scope=scope,
        scope_keyring=scope_keyring,
        execution_scope=execution_scope,
        operation_ref=operation_ref,
        connector_arguments=connector_arguments,
        run_ref=run_ref,
        iteration=iteration,
        preview_only=preview_only,
        approval_grant=approval_grant,
        dependency_receipts=dependency_receipts,
        allow_recovery=allow_recovery,
    )
    workflow_scope = prepared.workflow_scope
    runtime_scope = prepared.runtime_scope
    plan = prepared.plan
    action = prepared.action
    arguments = prepared.arguments
    arguments_digest = prepared.arguments_digest
    clean_run_ref = prepared.clean_run_ref
    iteration = prepared.iteration
    parsed_dependencies = prepared.dependency_receipts
    grant = prepared.grant
    key = prepared.idempotency_key
    if preview_only:
        return _result(
            status="preview",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            connector_status=ConnectorExecutionStatus.PREVIEW,
            summary="Validated one exact profit action; preview performed no connector call.",
        )
    request = prepared.request
    if request is None:
        raise ValueError("live profit action dispatch requires a preflighted request")
    if (
        allow_recovery
        and action.capability == "gmail.send_email"
        and grant is not None
        and before_connector_dispatch is None
    ):
        raise ValueError(
            "approved recovery email requires pre-dispatch contact custody"
        )
    if before_connector_dispatch is not None:
        if not allow_recovery or action.capability != "gmail.send_email":
            raise ValueError(
                "before-dispatch hooks are reserved for recovery contact custody"
            )
        before_connector_dispatch(request)
    try:
        connector_result = executor.execute(request)
    except Exception:
        return _result(
            status="failed",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="Connector execution raised; external effect state is unknown.",
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="connector_execute_failed",
            approval_ref=grant.approval_ref if grant is not None else None,
            approval_receipt_digest=(
                grant.approval_receipt_digest if grant is not None else None
            ),
            live_systems_changed=None,
        )
    if not isinstance(connector_result, ConnectorExecutionResult):
        return _result(
            status="failed",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="Connector returned an invalid result contract.",
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="invalid_connector_result",
            approval_ref=grant.approval_ref if grant is not None else None,
            approval_receipt_digest=(
                grant.approval_receipt_digest if grant is not None else None
            ),
            live_systems_changed=None,
        )
    if connector_result.tool != action.capability:
        return _result(
            status="failed",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="Connector result named a different Tool.",
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="connector_tool_mismatch",
            approval_ref=grant.approval_ref if grant is not None else None,
            approval_receipt_digest=(
                grant.approval_receipt_digest if grant is not None else None
            ),
            live_systems_changed=None,
        )
    if connector_result.status == ConnectorExecutionStatus.PENDING_APPROVAL:
        if (
            grant is not None
            or not connector_result.approval_ref
            or connector_result.approval_receipt_digest is None
        ):
            return _result(
                status="failed",
                plan=plan,
                action=action,
                arguments_digest=arguments_digest,
                run_ref=clean_run_ref,
                iteration=iteration,
                idempotency_key=key,
                summary="Connector did not accept or persist the expected approval state.",
                connector_status=connector_result.status,
                connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                connector_error_code="approval_state_invalid",
                approval_ref=grant.approval_ref if grant is not None else None,
                approval_receipt_digest=(
                    grant.approval_receipt_digest if grant is not None else None
                ),
            )
        return _result(
            status="pending_approval",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="The exact profit action is pending platform approval; no write completed.",
            connector_status=connector_result.status,
            approval_ref=connector_result.approval_ref,
            approval_receipt_digest=connector_result.approval_receipt_digest,
        )
    if connector_result.status == ConnectorExecutionStatus.BLOCKED:
        return _result(
            status="blocked",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="The governed connector blocked the action before a verified effect.",
            connector_status=connector_result.status,
            connector_error_kind=connector_result.error_kind,
            connector_error_code=connector_result.error_code,
            approval_ref=grant.approval_ref if grant is not None else None,
            approval_receipt_digest=(
                grant.approval_receipt_digest if grant is not None else None
            ),
        )
    if connector_result.status != ConnectorExecutionStatus.COMPLETED:
        return _result(
            status="failed",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="Connector did not return a trustworthy completed effect.",
            connector_status=connector_result.status,
            connector_error_kind=(
                connector_result.error_kind or ConnectorErrorKind.INTERNAL_ERROR
            ),
            connector_error_code=(
                connector_result.error_code or "connector_not_completed"
            ),
            approval_ref=grant.approval_ref if grant is not None else None,
            approval_receipt_digest=(
                grant.approval_receipt_digest if grant is not None else None
            ),
            live_systems_changed=(
                False
                if connector_result.status == ConnectorExecutionStatus.PREVIEW
                else None
            ),
        )
    if grant is None:
        return _result(
            status="failed",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="Connector claimed completion without the exact approval proof.",
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
            connector_error_code="completed_without_approval",
            live_systems_changed=None,
        )
    if (
        connector_result.error_kind is not None
        or connector_result.error_code is not None
        or connector_result.retryable
    ):
        return _result(
            status="failed",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="Connector completion carried contradictory failure metadata.",
            connector_status=connector_result.status,
            connector_error_kind=(
                connector_result.error_kind or ConnectorErrorKind.INTERNAL_ERROR
            ),
            connector_error_code=(
                connector_result.error_code or "contradictory_completion"
            ),
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    provenance = connector_result.provenance
    if provenance is None:
        return _result(
            status="failed",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="Connector completion lacked immutable execution provenance.",
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="execution_provenance_missing",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    if (
        provenance.tool != action.capability
        or provenance.server_effect != ConnectorEffect.WRITE
        or provenance.connector_account_ref != action.target_account_ref
        or provenance.project_id != runtime_scope.project_id
        or provenance.approval_ref != grant.approval_ref
        or provenance.approval_receipt_digest != grant.approval_receipt_digest
        or provenance.request_digest != request.custody_fingerprint()
    ):
        return _result(
            status="failed",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="Connector provenance did not match Tool, project, account, request, and approval.",
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
            connector_error_code="execution_provenance_mismatch",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    try:
        completed_at = datetime.fromisoformat(
            provenance.completed_at.replace("Z", "+00:00")
        )
        if completed_at <= datetime.fromisoformat(
            plan.analysis_as_of.replace("Z", "+00:00")
        ):
            raise ValueError
        if any(
            completed_at
            < datetime.fromisoformat(item.completed_at.replace("Z", "+00:00"))
            for item in parsed_dependencies
        ):
            raise ValueError
    except ValueError:
        return _result(
            status="failed",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="Connector completion time did not follow the authenticated plan.",
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="completion_time_invalid",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    if not _output_proves_effect(
        action.capability,
        connector_result.output,
        arguments,
    ):
        return _result(
            status="failed",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="Connector output did not prove the exact expected provider effect.",
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="effect_output_invalid",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    try:
        receipt = mint_profit_action_execution_receipt(
            plan,
            operation_ref=action.operation_ref,
            effect_receipt_digest=provenance.receipt_digest,
            approval_receipt_digest=provenance.approval_receipt_digest,
            completed_at=completed_at,
            run_ref=clean_run_ref,
            iteration=iteration,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
    except Exception:
        return _result(
            status="failed",
            plan=plan,
            action=action,
            arguments_digest=arguments_digest,
            run_ref=clean_run_ref,
            iteration=iteration,
            idempotency_key=key,
            summary="Connector completed but trusted action receipt minting failed.",
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="receipt_mint_failed",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    return _result(
        status="completed",
        plan=plan,
        action=action,
        arguments_digest=arguments_digest,
        run_ref=clean_run_ref,
        iteration=iteration,
        idempotency_key=key,
        summary="Completed one approved, exact-scoped profit action and minted its receipt.",
        connector_status=connector_result.status,
        approval_ref=grant.approval_ref,
        approval_receipt_digest=provenance.approval_receipt_digest,
        execution_receipt_digest=provenance.receipt_digest,
        receipt=receipt,
        live_systems_changed=True,
    )


def materialize_profit_action(
    plan_value: ProfitWorkflowPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
    execution_scope: ExecutionScope | Mapping[str, Any],
    executor: ConnectorExecutor,
    operation_ref: str,
    connector_arguments: Mapping[str, Any] | BaseModel,
    run_ref: str,
    iteration: int = 1,
    preview_only: bool = True,
    approval_grant: ProfitActionApprovalGrant | Mapping[str, Any] | None = None,
    dependency_receipts: Iterable[
        ProfitActionExecutionReceipt | Mapping[str, Any]
    ] = (),
) -> ProfitActionMaterializationResult:
    """Preview, propose, resume, or complete one exact profit connector write."""

    return _materialize_profit_action(
        plan_value,
        scope=scope,
        scope_keyring=scope_keyring,
        execution_scope=execution_scope,
        executor=executor,
        operation_ref=operation_ref,
        connector_arguments=connector_arguments,
        run_ref=run_ref,
        iteration=iteration,
        preview_only=preview_only,
        approval_grant=approval_grant,
        dependency_receipts=dependency_receipts,
        allow_recovery=False,
        before_connector_dispatch=None,
    )


def _materialize_recovery_profit_action(
    plan_value: ProfitWorkflowPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
    execution_scope: ExecutionScope | Mapping[str, Any],
    executor: ConnectorExecutor,
    operation_ref: str,
    connector_arguments: Mapping[str, Any] | BaseModel,
    run_ref: str,
    iteration: int = 1,
    preview_only: bool = True,
    approval_grant: ProfitActionApprovalGrant | Mapping[str, Any] | None = None,
    dependency_receipts: Iterable[
        ProfitActionExecutionReceipt | Mapping[str, Any]
    ] = (),
    before_connector_dispatch: Callable[[ConnectorExecutionRequest], None]
    | None = None,
) -> ProfitActionMaterializationResult:
    """Materialize an attested recovery action through the shared preflight rail."""

    return _materialize_profit_action(
        plan_value,
        scope=scope,
        scope_keyring=scope_keyring,
        execution_scope=execution_scope,
        executor=executor,
        operation_ref=operation_ref,
        connector_arguments=connector_arguments,
        run_ref=run_ref,
        iteration=iteration,
        preview_only=preview_only,
        approval_grant=approval_grant,
        dependency_receipts=dependency_receipts,
        allow_recovery=True,
        before_connector_dispatch=before_connector_dispatch,
    )


__all__ = [
    "PROFIT_ACTION_APPROVAL_GRANT_SCHEMA",
    "PROFIT_ACTION_MATERIALIZATION_RESULT_SCHEMA",
    "EcommerceCreateDiscountArguments",
    "EcommerceUpdateProductArguments",
    "FacebookPublishPostArguments",
    "GmailSendEmailArguments",
    "InstagramPublishPostArguments",
    "LinkedInPublishPostArguments",
    "ProfitActionApprovalGrant",
    "ProfitActionMaterializationResult",
    "ProfitMaterializationStatus",
    "bind_profit_action_approval",
    "canonical_profit_connector_arguments",
    "materialize_profit_action",
    "profit_connector_arguments_digest",
]
