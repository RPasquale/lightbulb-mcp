"""Host-side materialization for one governed Shopify DRAFT product.

This module is intentionally a narrow tracer bullet.  It authenticates an
existing omnichannel launch plan and may materialize only its canonical
``ecommerce.create_product`` operation.  It does not activate or publish the
product, create a CRM campaign, publish social content, verify a landing page,
or claim that the omnichannel launch completed.

Hosted writes remain subject to the platform's Governed Connector Execution
feature gate.  Keeping this orchestration in the SDK makes the approval,
idempotency, and receipt contract executable in local/in-memory hosts while a
disabled hosted authority continues to fail closed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

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
from lightbulb.gtm_primitives import (
    ExactScopeDigestProvider,
    OmnichannelProductLaunchPlan,
    ProductLaunchOperation,
    ProductLaunchReceipt,
    RequiredLaunchReceipt,
    ShopifyDraftProductArguments,
    mint_product_launch_receipt,
    verify_product_launch_plan,
)


PRODUCT_LAUNCH_APPROVAL_GRANT_SCHEMA = "lightbulb.product_launch_approval_grant.v1"
PRODUCT_LAUNCH_MATERIALIZATION_RESULT_SCHEMA = (
    "lightbulb.product_launch_materialization_result.v1"
)

_CREATE_PRODUCT_TOOL = "ecommerce.create_product"
_APPROVAL_GRANT_HMAC_DOMAIN = "lightbulb.product_launch_approval_grant.v1"
_MATERIALIZER_ISSUER_REF = "lightbulb-gtm-materializer"
_SHOPIFY_PRODUCT_ID_RE = re.compile(r"^(?:[0-9]+|gid://shopify/Product/[0-9]+)$")

MaterializationStatus = Literal[
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


class ProductLaunchApprovalGrant(_StrictModel):
    """Exact binding for one platform-governed approval reference."""

    schema_id: Literal["lightbulb.product_launch_approval_grant.v1"] = Field(
        default=PRODUCT_LAUNCH_APPROVAL_GRANT_SCHEMA,
        alias="schema",
    )
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_id: str = Field(min_length=1, max_length=200)
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    connector_account_ref: str = Field(min_length=1, max_length=200)
    approval_unit: str = Field(min_length=1, max_length=200)
    approval_ref: str = Field(min_length=1, max_length=200)
    approval_receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    grant_key_id: str = Field(min_length=1, max_length=100)
    grant_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "operation_id",
        "connector_account_ref",
        "approval_unit",
        "approval_ref",
        "grant_key_id",
    )
    @classmethod
    def _bounded_text(cls, value: str) -> str:
        clean = value.strip()
        if clean != value or any(ord(character) < 33 for character in clean):
            raise ValueError("approval values must contain visible characters only")
        return clean

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"grant_hmac"},
        )


class ProductLaunchMaterializationResult(_StrictModel):
    """Bounded result for the single DRAFT-product materialization step."""

    schema_id: Literal["lightbulb.product_launch_materialization_result.v1"] = Field(
        default=PRODUCT_LAUNCH_MATERIALIZATION_RESULT_SCHEMA,
        alias="schema",
    )
    status: MaterializationStatus
    launch_ref: str
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_id: str
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    connector_account_ref: str
    approval_unit: str
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
    product_id: str | None = Field(default=None, max_length=512)
    receipt: ProductLaunchReceipt | None = None
    draft_product_created: bool = False
    live_systems_changed: bool | None = False
    omnichannel_launch_completed: Literal[False] = False
    summary: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def _status_matches_evidence(self) -> "ProductLaunchMaterializationResult":
        completed = self.status == "completed"
        if completed != (
            self.connector_status == ConnectorExecutionStatus.COMPLETED
            and self.product_id is not None
            and self.receipt is not None
            and self.draft_product_created
            and self.live_systems_changed is True
            and self.approval_ref is not None
            and self.approval_receipt_digest is not None
            and self.execution_receipt_digest is not None
        ):
            raise ValueError(
                "completed materialization requires complete effect evidence"
            )
        if not completed and any(
            value is not None
            for value in (
                self.product_id,
                self.receipt,
                self.execution_receipt_digest,
            )
        ):
            raise ValueError(
                "non-completed materialization cannot expose effect evidence"
            )
        if not completed and self.draft_product_created:
            raise ValueError("only completed materialization may claim a DRAFT product")
        if self.status == "pending_approval" and (
            self.connector_status != ConnectorExecutionStatus.PENDING_APPROVAL
            or self.approval_ref is None
            or self.approval_receipt_digest is None
            or self.live_systems_changed is not False
        ):
            raise ValueError(
                "pending approval requires a durable approval reference and receipt"
            )
        if (
            self.status in {"preview", "blocked"}
            and self.live_systems_changed is not False
        ):
            raise ValueError(
                "preview and blocked results cannot claim an external effect"
            )
        if self.status == "failed" and self.live_systems_changed not in {False, None}:
            raise ValueError(
                "failed results may only report no effect or unknown effect"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _workflow_scope(
    value: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
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
    execution_scope: ExecutionScope,
    workflow_scope: DynamicWorkflowScope,
) -> None:
    if execution_scope.project_id is None:
        raise ValueError(
            "Shopify materialization requires an authenticated project UUID"
        )
    if execution_scope.project_ref != workflow_scope.project_ref:
        raise ValueError(
            "execution project_ref does not match the authenticated plan scope"
        )
    if execution_scope.tenant_ref != workflow_scope.tenant_id:
        raise ValueError(
            "execution tenant_ref does not match the authenticated plan scope"
        )
    if execution_scope.company_ref != workflow_scope.company_id:
        raise ValueError(
            "execution company_ref does not match the authenticated plan scope"
        )
    if execution_scope.actor_ref != workflow_scope.user_id:
        raise ValueError(
            "execution actor_ref does not match the authenticated plan scope"
        )


def _canonical_create_operation(
    plan: OmnichannelProductLaunchPlan,
) -> tuple[ProductLaunchOperation, RequiredLaunchReceipt]:
    matches = [
        operation
        for operation in plan.operations
        if operation.capability == _CREATE_PRODUCT_TOOL
    ]
    if len(matches) != 1:
        raise ValueError(
            "launch plan must contain one canonical DRAFT product operation"
        )
    operation = matches[0]
    if (
        operation.ordinal != 1
        or operation.stage != "catalog_materialization"
        or operation.execution_kind != "connector_tool"
        or operation.effect != "write"
        or not operation.approval_required
        or operation.approval_unit is None
        or operation.depends_on
        or operation.input_bindings
        or not isinstance(operation.arguments, ShopifyDraftProductArguments)
        or operation.arguments.status != "DRAFT"
    ):
        raise ValueError("launch plan DRAFT product operation is not canonical")
    requirements = [
        requirement
        for requirement in plan.required_receipts
        if requirement.operation_id == operation.operation_id
    ]
    if (
        len(requirements) != 1
        or requirements[0].operation_digest != operation.operation_digest
        or requirements[0].approval_unit != operation.approval_unit
    ):
        raise ValueError("launch plan DRAFT receipt obligation is not canonical")
    return operation, requirements[0]


def _verify_shopify_account(
    plan: OmnichannelProductLaunchPlan,
    operation: ProductLaunchOperation,
) -> None:
    matches = [
        binding
        for binding in plan.connector_account_bindings
        if binding.provider == "shopify"
        and binding.connector_account_ref == operation.connector_account_ref
    ]
    if len(matches) != 1:
        raise ValueError(
            "DRAFT product operation is not bound to one authenticated Shopify account"
        )


def _run_ref(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("run_ref must be a string")
    clean = value.strip()
    if (
        not clean
        or clean != value
        or len(clean) > 200
        or any(ord(character) < 32 for character in clean)
    ):
        raise ValueError("run_ref must contain 1 to 200 printable characters")
    return clean


def _iteration(value: int, plan: OmnichannelProductLaunchPlan) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("iteration must be an integer")
    if not 1 <= value <= plan.evaluation_loop.max_iterations:
        raise ValueError("iteration is outside the authenticated launch loop")
    if value != 1:
        raise ValueError(
            "the DRAFT tracer supports iteration 1 only; revised plans require "
            "a fresh approval/materialization contract"
        )
    return value


def _approval_grant(
    value: ProductLaunchApprovalGrant | Mapping[str, Any] | None,
    *,
    scope_keyring: ExactScopeDigestProvider,
) -> ProductLaunchApprovalGrant | None:
    if value is None:
        return None
    try:
        grant = ProductLaunchApprovalGrant.model_validate(
            value.model_dump(mode="python", by_alias=True)
            if isinstance(value, ProductLaunchApprovalGrant)
            else value
        )
    except ValidationError:
        raise ValueError("approval grant failed exact-binding validation") from None
    try:
        expected = scope_keyring.sign(
            grant.grant_key_id,
            _APPROVAL_GRANT_HMAC_DOMAIN,
            grant.hmac_payload(),
        ).hex()
    except Exception:
        raise ValueError("approval grant signing key is unavailable") from None
    if not hmac.compare_digest(grant.grant_hmac, expected):
        raise ValueError("approval grant HMAC verification failed")
    return grant


def _completed_at(
    value: datetime | None,
    *,
    plan: OmnichannelProductLaunchPlan,
) -> tuple[datetime, str]:
    if not isinstance(value, datetime):
        raise ValueError("approved dispatch requires an authoritative completed_at")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("completed_at must include a UTC offset")
    normalized = value.astimezone(timezone.utc)
    analysis_time = datetime.fromisoformat(plan.analysis_as_of.replace("Z", "+00:00"))
    if normalized <= analysis_time:
        raise ValueError("completed_at must follow the authenticated plan")
    return normalized, normalized.isoformat().replace("+00:00", "Z")


def _issuer_ref(value: str) -> str:
    if value != _MATERIALIZER_ISSUER_REF:
        raise ValueError(
            "issuer_ref is fixed for replay-stable materialization receipts"
        )
    return _MATERIALIZER_ISSUER_REF


def _stable_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def bind_product_launch_operation_approval(
    plan_value: OmnichannelProductLaunchPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    operation_id: str,
    approval_ref: str,
    approval_receipt_digest: str,
) -> ProductLaunchApprovalGrant:
    """Bind one opaque governed approval ref to one exact launch write.

    The platform remains authoritative for whether the ApprovalTask is approved
    and consumable.  This deterministic binding prevents SDK callers from
    changing the plan, account, operation, or alleged approval proof while
    replaying the same connector effect.
    """

    workflow_scope = _workflow_scope(scope)
    plan = verify_product_launch_plan(
        plan_value,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    matches = [
        candidate
        for candidate in plan.operations
        if candidate.operation_id == operation_id
    ]
    if len(matches) != 1:
        raise ValueError("operation_id does not identify one launch operation")
    operation = matches[0]
    if (
        operation.effect != "write"
        or not operation.approval_required
        or operation.approval_unit is None
    ):
        raise ValueError("only an approval-required launch write may be bound")
    if plan.analytics_scope.exact_scope_digest is None:
        raise ValueError("launch plan has no exact scope digest")
    key_id = plan.analytics_scope.receipt_key_id
    if key_id is None:
        raise ValueError("launch plan has no receipt signing key")
    unsigned = ProductLaunchApprovalGrant(
        plan_digest=plan.plan_digest,
        exact_scope_digest=plan.analytics_scope.exact_scope_digest,
        operation_id=operation.operation_id,
        operation_digest=operation.operation_digest,
        connector_account_ref=operation.connector_account_ref,
        approval_unit=operation.approval_unit,
        approval_ref=approval_ref,
        approval_receipt_digest=approval_receipt_digest,
        grant_key_id=key_id,
        grant_hmac="0" * 64,
    )
    grant_hmac = scope_keyring.sign(
        key_id,
        _APPROVAL_GRANT_HMAC_DOMAIN,
        unsigned.hmac_payload(),
    ).hex()
    return ProductLaunchApprovalGrant.model_validate(
        {
            **unsigned.model_dump(mode="python", by_alias=True),
            "grant_hmac": grant_hmac,
        }
    )


def bind_shopify_draft_product_approval(
    plan_value: OmnichannelProductLaunchPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    approval_ref: str,
    approval_receipt_digest: str,
) -> ProductLaunchApprovalGrant:
    """Bind one governed approval to the canonical Shopify DRAFT operation."""

    workflow_scope = _workflow_scope(scope)
    plan = verify_product_launch_plan(
        plan_value,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    operation, _ = _canonical_create_operation(plan)
    _verify_shopify_account(plan, operation)
    return bind_product_launch_operation_approval(
        plan,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        operation_id=operation.operation_id,
        approval_ref=approval_ref,
        approval_receipt_digest=approval_receipt_digest,
    )


def _idempotency_key(
    plan: OmnichannelProductLaunchPlan,
    operation: ProductLaunchOperation,
    *,
    run_ref: str,
    iteration: int,
) -> str:
    digest = _stable_digest(
        {
            "schema": "lightbulb.product_launch_materialization_identity.v1",
            "plan_digest": plan.plan_digest,
            "exact_scope_digest": plan.analytics_scope.exact_scope_digest,
            "run_ref": run_ref,
            "iteration": iteration,
            "operation_id": operation.operation_id,
            "operation_digest": operation.operation_digest,
            "approval_unit": operation.approval_unit,
            "connector_account_ref": operation.connector_account_ref,
        }
    )
    return f"lb-gtm-draft-{digest}"


def _normalized_product_id(output: Mapping[str, Any]) -> str | None:
    candidates: list[Any] = []
    if "product_id" in output:
        candidates.append(output.get("product_id"))
    nested = output.get("output")
    if isinstance(nested, Mapping) and "product_id" in nested:
        candidates.append(nested.get("product_id"))
    normalized: set[str] = set()
    for candidate in candidates:
        if isinstance(candidate, bool) or not isinstance(candidate, (str, int)):
            return None
        clean = str(candidate).strip()
        if (
            not clean
            or len(clean) > 512
            or any(ord(character) < 33 for character in clean)
            or _SHOPIFY_PRODUCT_ID_RE.fullmatch(clean) is None
        ):
            return None
        normalized.add(clean)
    if len(normalized) != 1:
        return None
    return next(iter(normalized))


def _normalized_product_status(output: Mapping[str, Any]) -> str | None:
    payloads: list[Mapping[str, Any]] = [output]
    nested_output = output.get("output")
    if isinstance(nested_output, Mapping):
        payloads.append(nested_output)

    statuses: set[str] = set()
    for payload in payloads:
        for key in ("product", "raw"):
            product = payload.get(key)
            if not isinstance(product, Mapping) or "status" not in product:
                continue
            status = product.get("status")
            if not isinstance(status, str):
                return None
            clean = status.strip().upper()
            if not clean or any(ord(character) < 33 for character in clean):
                return None
            statuses.add(clean)
    if statuses != {"DRAFT"}:
        return None
    return "DRAFT"


def _reported_approval_refs(output: Mapping[str, Any]) -> set[str]:
    values: list[Any] = [
        output.get("approvalRef"),
        output.get("approval_ref"),
        output.get("approvalTaskId"),
        output.get("approval_task_id"),
    ]
    metadata = output.get("metadata")
    if isinstance(metadata, Mapping):
        values.extend(
            [
                metadata.get("approvalRef"),
                metadata.get("approval_ref"),
                metadata.get("approvalTaskId"),
                metadata.get("approval_task_id"),
            ]
        )
    return {
        str(value).strip()
        for value in values
        if value is not None and str(value).strip()
    }


def _base_result(
    *,
    status: MaterializationStatus,
    plan: OmnichannelProductLaunchPlan,
    operation: ProductLaunchOperation,
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
    product_id: str | None = None,
    receipt: ProductLaunchReceipt | None = None,
    live_systems_changed: bool | None = False,
) -> ProductLaunchMaterializationResult:
    return ProductLaunchMaterializationResult(
        status=status,
        launch_ref=plan.launch_ref,
        plan_digest=plan.plan_digest,
        operation_id=operation.operation_id,
        operation_digest=operation.operation_digest,
        connector_account_ref=operation.connector_account_ref,
        approval_unit=operation.approval_unit,
        run_ref=run_ref,
        iteration=iteration,
        idempotency_key=idempotency_key,
        connector_status=connector_status,
        connector_error_kind=connector_error_kind,
        connector_error_code=connector_error_code,
        approval_ref=approval_ref,
        approval_receipt_digest=approval_receipt_digest,
        execution_receipt_digest=execution_receipt_digest,
        product_id=product_id,
        receipt=receipt,
        draft_product_created=status == "completed",
        live_systems_changed=live_systems_changed,
        summary=summary,
    )


def materialize_shopify_draft_product(
    plan_value: OmnichannelProductLaunchPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    execution_scope: ExecutionScope | Mapping[str, Any],
    executor: ConnectorExecutor,
    run_ref: str,
    iteration: int = 1,
    preview_only: bool = True,
    approval_grant: ProductLaunchApprovalGrant | Mapping[str, Any] | None = None,
    completed_at: datetime | None = None,
    issuer_ref: str = "lightbulb-gtm-materializer",
) -> ProductLaunchMaterializationResult:
    """Preview, propose, or execute the plan's one Shopify DRAFT create.

    ``preview_only=True`` stops before even querying the executor.  Apply mode
    with no approval grant submits the exact connector request so a governed
    executor can return a durable approval reference.  Apply mode with a grant
    dispatches only when the sealed grant exactly matches the authenticated
    plan, scope, account, operation, and approval unit.  The connector authority
    remains responsible for validating and consuming the human approval.
    """

    workflow_scope = _workflow_scope(scope)
    plan = verify_product_launch_plan(
        plan_value,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    runtime_scope = _execution_scope(execution_scope)
    _validate_execution_scope(runtime_scope, workflow_scope)
    operation, requirement = _canonical_create_operation(plan)
    _verify_shopify_account(plan, operation)
    clean_run_ref = _run_ref(run_ref)
    clean_iteration = _iteration(iteration, plan)
    grant = _approval_grant(approval_grant, scope_keyring=scope_keyring)
    if grant is not None and (
        grant.plan_digest != plan.plan_digest
        or grant.exact_scope_digest != plan.analytics_scope.exact_scope_digest
        or grant.operation_id != operation.operation_id
        or grant.operation_digest != operation.operation_digest
        or grant.connector_account_ref != operation.connector_account_ref
        or grant.approval_unit != operation.approval_unit
        or grant.grant_key_id != plan.analytics_scope.receipt_key_id
    ):
        raise ValueError("approval grant does not match the exact DRAFT operation")
    clean_issuer_ref = _issuer_ref(issuer_ref)
    key = _idempotency_key(
        plan,
        operation,
        run_ref=clean_run_ref,
        iteration=clean_iteration,
    )

    if preview_only:
        return _base_result(
            status="preview",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "Previewed the authenticated Shopify DRAFT product operation. "
                "The executor was not queried and no external system changed."
            ),
        )

    try:
        supported = executor.supports(_CREATE_PRODUCT_TOOL)
    except Exception:
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary="Connector capability discovery failed safely.",
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="connector_support_check_failed",
            live_systems_changed=False,
        )
    if not supported:
        return _base_result(
            status="blocked",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary="The configured project does not expose ecommerce.create_product.",
            connector_error_kind=ConnectorErrorKind.UNSUPPORTED_OPERATION,
            connector_error_code="tool_not_available",
        )

    request = ConnectorExecutionRequest(
        tool=_CREATE_PRODUCT_TOOL,
        arguments=operation.connector_inputs(),
        scope=runtime_scope,
        connector_account_ref=operation.connector_account_ref,
        effect=ConnectorEffect.WRITE,
        approval_required=True,
        approval_ref=grant.approval_ref if grant is not None else None,
        preview_only=False,
        idempotency_key=key,
        metadata={
            "primitive_ref": plan.primitive_ref,
            "plan_digest": plan.plan_digest,
            "launch_ref": plan.launch_ref,
            "operation_ref": operation.operation_id,
            "operation_digest": operation.operation_digest,
            "approval_unit": operation.approval_unit,
            "approval_receipt_digest": (
                grant.approval_receipt_digest if grant is not None else None
            ),
            "connector_account_ref": operation.connector_account_ref,
            "run_ref": clean_run_ref,
            "iteration": clean_iteration,
        },
    )
    try:
        connector_result = executor.execute(request)
    except Exception:
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "Connector execution raised after dispatch began; external effect "
                "state is unknown and automatic success was not claimed."
            ),
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="connector_execute_failed",
            approval_ref=grant.approval_ref if grant is not None else None,
            approval_receipt_digest=(
                grant.approval_receipt_digest if grant is not None else None
            ),
            live_systems_changed=None,
        )
    if not isinstance(connector_result, ConnectorExecutionResult):
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary="Connector returned an invalid result contract; no success was claimed.",
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="invalid_connector_result",
            approval_ref=grant.approval_ref if grant is not None else None,
            approval_receipt_digest=(
                grant.approval_receipt_digest if grant is not None else None
            ),
            live_systems_changed=None,
        )
    if connector_result.tool != _CREATE_PRODUCT_TOOL:
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary="Connector result named a different Tool; no success was claimed.",
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
        if grant is not None:
            return _base_result(
                status="failed",
                plan=plan,
                operation=operation,
                run_ref=clean_run_ref,
                iteration=clean_iteration,
                idempotency_key=key,
                summary="The supplied approval did not authorize connector dispatch.",
                connector_status=connector_result.status,
                connector_error_kind=connector_result.error_kind,
                connector_error_code=(
                    connector_result.error_code or "approval_not_authorized"
                ),
                approval_ref=grant.approval_ref,
                approval_receipt_digest=grant.approval_receipt_digest,
                live_systems_changed=False,
            )
        pending_ref = (
            connector_result.approval_ref.strip()
            if connector_result.approval_ref is not None
            else ""
        )
        pending_digest = connector_result.approval_receipt_digest
        if not pending_ref or pending_digest is None:
            return _base_result(
                status="failed",
                plan=plan,
                operation=operation,
                run_ref=clean_run_ref,
                iteration=clean_iteration,
                idempotency_key=key,
                summary=(
                    "Connector approval proposal returned no durable reference "
                    "and receipt."
                ),
                connector_status=connector_result.status,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="approval_evidence_missing",
                live_systems_changed=False,
            )
        return _base_result(
            status="pending_approval",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "A durable approval is pending for the exact Shopify DRAFT "
                "product operation; no connector write completed."
            ),
            connector_status=connector_result.status,
            approval_ref=pending_ref,
            approval_receipt_digest=pending_digest,
        )

    if connector_result.status == ConnectorExecutionStatus.BLOCKED:
        return _base_result(
            status="blocked",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary="Shopify DRAFT materialization was blocked before a verified effect.",
            connector_status=connector_result.status,
            connector_error_kind=connector_result.error_kind,
            connector_error_code=connector_result.error_code,
            approval_ref=grant.approval_ref if grant is not None else None,
            approval_receipt_digest=(
                grant.approval_receipt_digest if grant is not None else None
            ),
        )

    if connector_result.status == ConnectorExecutionStatus.PREVIEW:
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary="Apply mode received a preview receipt; no write success was claimed.",
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="unexpected_connector_preview",
            approval_ref=grant.approval_ref if grant is not None else None,
            approval_receipt_digest=(
                grant.approval_receipt_digest if grant is not None else None
            ),
            live_systems_changed=False,
        )

    if connector_result.status == ConnectorExecutionStatus.FAILED:
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "Connector execution failed; external effect state is unknown "
                "and no completion receipt was minted."
            ),
            connector_status=connector_result.status,
            connector_error_kind=connector_result.error_kind,
            connector_error_code=connector_result.error_code,
            approval_ref=grant.approval_ref if grant is not None else None,
            approval_receipt_digest=(
                grant.approval_receipt_digest if grant is not None else None
            ),
            live_systems_changed=None,
        )

    if grant is None:
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "Connector claimed completion without the exact approval proof; "
                "external effect state is unknown and no receipt was minted."
            ),
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
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "Connector completion carried contradictory failure metadata; "
                "external effect state is unknown and no receipt was minted."
            ),
            connector_status=connector_result.status,
            connector_error_kind=(
                connector_result.error_kind or ConnectorErrorKind.INTERNAL_ERROR
            ),
            connector_error_code=(
                connector_result.error_code or "contradictory_connector_completion"
            ),
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )

    provenance = connector_result.provenance
    if provenance is None:
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "Connector completion lacked immutable request, account, approval, "
                "and completion provenance; no trusted receipt was minted."
            ),
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="execution_provenance_missing",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    if (
        provenance.tool != operation.capability
        or provenance.server_effect != ConnectorEffect.WRITE
        or provenance.connector_account_ref != operation.connector_account_ref
        or provenance.project_id != runtime_scope.project_id
        or provenance.approval_ref != grant.approval_ref
        or provenance.approval_receipt_digest != grant.approval_receipt_digest
        or provenance.request_digest != request.custody_fingerprint()
    ):
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "Connector execution provenance did not match the exact Tool, "
                "project, account, request, effect, and approval binding."
            ),
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
            connector_error_code="execution_provenance_mismatch",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=provenance.approval_receipt_digest,
            live_systems_changed=None,
        )
    try:
        provenance_completed_at, completed_at_text = _completed_at(
            datetime.fromisoformat(provenance.completed_at.replace("Z", "+00:00")),
            plan=plan,
        )
        if completed_at is not None:
            supplied_completed_at, _ = _completed_at(completed_at, plan=plan)
            if supplied_completed_at != provenance_completed_at:
                raise ValueError(
                    "completed_at does not match authoritative connector provenance"
                )
    except ValueError:
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "Connector completion time was not authoritative for this effect; "
                "no trusted receipt was minted."
            ),
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="completion_time_mismatch",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )

    reported_approval_refs = _reported_approval_refs(connector_result.output)
    if reported_approval_refs and reported_approval_refs != {grant.approval_ref}:
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "Connector completion receipt did not match the supplied approval "
                "reference; no trusted completion receipt was minted."
            ),
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
            connector_error_code="approval_ref_mismatch",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    product_id = _normalized_product_id(connector_result.output)
    if product_id is None:
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "Connector completion did not contain one unambiguous product_id; "
                "external effect state is unknown and no receipt was minted."
            ),
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="product_id_missing_or_ambiguous",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    if _normalized_product_status(connector_result.output) != "DRAFT":
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "Connector completion did not prove that the returned Shopify "
                "product remained DRAFT; external effect state is unknown and no "
                "receipt was minted."
            ),
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="product_status_not_draft",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )

    evidence_digest = provenance.receipt_digest
    receipt_seed = _stable_digest(
        {
            "plan_digest": plan.plan_digest,
            "run_ref": clean_run_ref,
            "iteration": clean_iteration,
            "operation_digest": operation.operation_digest,
        }
    )
    try:
        receipt = mint_product_launch_receipt(
            plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
            criterion_id=requirement.criterion_id,
            receipt_ref=f"materialized_{receipt_seed[:32]}",
            issuer_ref=clean_issuer_ref,
            evidence_digest=evidence_digest,
            issued_at=completed_at_text,
            effective_at=completed_at_text,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            approval_receipt_digest=provenance.approval_receipt_digest,
        )
    except Exception:
        return _base_result(
            status="failed",
            plan=plan,
            operation=operation,
            run_ref=clean_run_ref,
            iteration=clean_iteration,
            idempotency_key=key,
            summary=(
                "The connector completed but trusted receipt minting failed; "
                "external effect state is unknown and launch completion was not claimed."
            ),
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="receipt_mint_failed",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    return _base_result(
        status="completed",
        plan=plan,
        operation=operation,
        run_ref=clean_run_ref,
        iteration=clean_iteration,
        idempotency_key=key,
        summary=(
            "Created one approved Shopify DRAFT product and minted its exact "
            "operation receipt. The product was not activated or published; no "
            "CRM campaign, social post, landing verification, or omnichannel "
            "launch completion is claimed."
        ),
        connector_status=connector_result.status,
        approval_ref=grant.approval_ref,
        approval_receipt_digest=provenance.approval_receipt_digest,
        execution_receipt_digest=provenance.receipt_digest,
        product_id=product_id,
        receipt=receipt,
        live_systems_changed=True,
    )


__all__ = [
    "PRODUCT_LAUNCH_APPROVAL_GRANT_SCHEMA",
    "PRODUCT_LAUNCH_MATERIALIZATION_RESULT_SCHEMA",
    "MaterializationStatus",
    "ProductLaunchApprovalGrant",
    "ProductLaunchMaterializationResult",
    "bind_product_launch_operation_approval",
    "bind_shopify_draft_product_approval",
    "materialize_shopify_draft_product",
]
