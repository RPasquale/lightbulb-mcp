"""Resumable, fail-closed Shopify go-live runner for signed GTM plans.

The runner deliberately stops at storefront readiness.  It never dispatches a
CRM or social operation.  Those downstream operations become eligible only
after a trusted verifier proves the exact product, publications, landing URL,
price, currency, and checkout surface.

Resumption does not trust caller-owned checkpoints.  Earlier writes are
replayed through stable per-operation idempotency keys and their connector
outputs/provenance are verified again before an output binding can cross into
the next operation.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Literal, Mapping, Protocol, runtime_checkable
from uuid import UUID

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
from lightbulb.gtm_materializer import (
    ProductLaunchApprovalGrant,
    _approval_grant,
    _completed_at,
    _execution_scope,
    _idempotency_key,
    _issuer_ref,
    _normalized_product_id,
    _reported_approval_refs,
    _run_ref,
    _stable_digest,
    _validate_execution_scope,
    _workflow_scope,
    materialize_shopify_draft_product,
)
from lightbulb.gtm_primitives import (
    ExactScopeDigestProvider,
    LandingReadinessArguments,
    OmnichannelProductLaunchPlan,
    ProductLaunchOperation,
    ProductLaunchReceipt,
    RequiredLaunchReceipt,
    ShopifyActivateProductArguments,
    ShopifyPublishProductArguments,
    mint_product_launch_receipt,
    verify_product_launch_plan,
)


LANDING_READINESS_REQUEST_SCHEMA = "lightbulb.landing_readiness_request.v1"
LANDING_READINESS_OBSERVATION_SCHEMA = "lightbulb.landing_readiness_observation.v1"
SHOPIFY_PRODUCT_READINESS_PAYLOAD_SCHEMA = "lightbulb.shopify_product_readiness.v1"
SHOPIFY_LAUNCH_OPERATION_RESULT_SCHEMA = "lightbulb.shopify_launch_operation_result.v1"
SHOPIFY_LAUNCH_RUN_RESULT_SCHEMA = "lightbulb.shopify_launch_run_result.v1"

_ACTIVATE_TOOL = "ecommerce.update_product"
_PUBLISH_TOOL = "shopify.publish_product"
_READINESS_TOOL = "gtm.verify_landing_readiness"
_READINESS_CONNECTOR_TOOL = "shopify.verify_product_readiness"
_SHOPIFY_CAPABILITIES = (
    "ecommerce.create_product",
    _ACTIVATE_TOOL,
    _PUBLISH_TOOL,
    _READINESS_TOOL,
)
_PRODUCT_ID_RE = re.compile(r"^(?:[0-9]+|gid://shopify/Product/[0-9]+)$")
_PUBLICATION_ID_RE = re.compile(r"^(?:[0-9]+|gid://shopify/Publication/[0-9]+)$")
_TOOL_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$")

ShopifyLaunchStatus = Literal[
    "preview",
    "pending_approval",
    "storefront_ready",
    "blocked",
    "failed",
]
ShopifyLaunchOperationStatus = Literal[
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


def _canonical_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _normalized_utc(value: str, *, label: str) -> str:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class LandingReadinessRequest(_StrictModel):
    """Exact storefront state a trusted read implementation must observe."""

    schema_id: Literal["lightbulb.landing_readiness_request.v1"] = Field(
        default=LANDING_READINESS_REQUEST_SCHEMA,
        alias="schema",
    )
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_ref: str = Field(min_length=1, max_length=200)
    iteration: int = Field(ge=1, le=4)
    operation_id: str = Field(min_length=1, max_length=200)
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    connector_account_ref: str = Field(min_length=1, max_length=200)
    project_id: UUID
    product_id: str = Field(min_length=1, max_length=512)
    expected_title: str = Field(min_length=1, max_length=500)
    landing_url: str = Field(min_length=8, max_length=2_000)
    expected_price: str = Field(pattern=r"^(?:0|[1-9][0-9]{0,8})\.[0-9]{2}$")
    expected_currency: str = Field(pattern=r"^[A-Z]{3}$")
    expected_publication_ids: tuple[str, ...] = Field(min_length=1, max_length=50)
    publication_completed_at: str
    required_checks: tuple[
        Literal[
            "page_reachable",
            "product_visible",
            "price_and_currency_match",
            "checkout_available",
        ],
        ...,
    ] = (
        "page_reachable",
        "product_visible",
        "price_and_currency_match",
        "checkout_available",
    )
    request_digest: str = ""

    @field_validator("expected_publication_ids", "required_checks", mode="before")
    @classmethod
    def _immutable_sequences(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("publication_completed_at")
    @classmethod
    def _valid_completed_at(cls, value: str) -> str:
        return _normalized_utc(value, label="publication_completed_at")

    @field_validator("product_id")
    @classmethod
    def _valid_product_id(cls, value: str) -> str:
        clean = value.strip()
        if clean != value or _PRODUCT_ID_RE.fullmatch(clean) is None:
            raise ValueError("product_id must be a Shopify product ID")
        return clean

    @model_validator(mode="after")
    def _seal_request(self) -> "LandingReadinessRequest":
        if len(set(self.expected_publication_ids)) != len(
            self.expected_publication_ids
        ):
            raise ValueError("expected publication IDs must be unique")
        if self.required_checks != (
            "page_reachable",
            "product_visible",
            "price_and_currency_match",
            "checkout_available",
        ):
            raise ValueError("readiness request must retain all canonical checks")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"request_digest"},
        )
        expected = _canonical_digest(payload)
        if self.request_digest and self.request_digest != expected:
            raise ValueError("readiness request_digest does not match its payload")
        object.__setattr__(self, "request_digest", expected)
        return self


class LandingReadinessObservation(_StrictModel):
    """Typed evidence returned by a trusted live-storefront reader."""

    schema_id: Literal["lightbulb.landing_readiness_observation.v1"] = Field(
        default=LANDING_READINESS_OBSERVATION_SCHEMA,
        alias="schema",
    )
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_capability: str = Field(min_length=3, max_length=160)
    connector_account_ref: str = Field(min_length=1, max_length=200)
    project_id: UUID
    landing_url: str = Field(min_length=8, max_length=2_000)
    product_id: str = Field(min_length=1, max_length=512)
    observed_title: str = Field(min_length=1, max_length=500)
    observed_price: str = Field(pattern=r"^(?:0|[1-9][0-9]{0,8})\.[0-9]{2}$")
    observed_currency: str = Field(pattern=r"^[A-Z]{3}$")
    published_publication_ids: tuple[str, ...] = Field(min_length=1, max_length=50)
    page_reachable: bool
    product_visible: bool
    price_and_currency_match: bool
    checkout_available: bool
    observed_at: str
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("published_publication_ids", mode="before")
    @classmethod
    def _immutable_publications(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("source_capability")
    @classmethod
    def _valid_capability(cls, value: str) -> str:
        clean = value.strip().lower()
        if _TOOL_RE.fullmatch(clean) is None or ".." in clean:
            raise ValueError("source_capability must be a dotted Tool name")
        return clean

    @field_validator("observed_at")
    @classmethod
    def _valid_observed_at(cls, value: str) -> str:
        return _normalized_utc(value, label="observed_at")

    @field_validator("product_id")
    @classmethod
    def _valid_product_id(cls, value: str) -> str:
        clean = value.strip()
        if clean != value or _PRODUCT_ID_RE.fullmatch(clean) is None:
            raise ValueError("product_id must be a Shopify product ID")
        return clean

    @model_validator(mode="after")
    def _unique_publications(self) -> "LandingReadinessObservation":
        if len(set(self.published_publication_ids)) != len(
            self.published_publication_ids
        ):
            raise ValueError("published publication IDs must be unique")
        return self


class ShopifyProductReadinessPayload(_StrictModel):
    """Closed Spring/provider envelope for the governed readiness read."""

    schema_id: Literal["lightbulb.shopify_product_readiness.v1"] = Field(
        default=SHOPIFY_PRODUCT_READINESS_PAYLOAD_SCHEMA,
        alias="schema",
    )
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    product_id: str = Field(pattern=r"^[1-9][0-9]{0,30}$")
    publication_ids: tuple[str, ...] = Field(min_length=1, max_length=50)
    publication_completed_at: str
    expected_title: str = Field(min_length=1, max_length=255)
    expected_price: str = Field(pattern=r"^(?:0|[1-9][0-9]{0,11})\.[0-9]{2}$")
    expected_currency: str = Field(pattern=r"^[A-Z]{3}$")
    landing_url: str = Field(min_length=8, max_length=2_000)
    admin_status: str = Field(min_length=1, max_length=40)
    admin_title: str = Field(min_length=1, max_length=255)
    title_matches: bool
    online_store_url: str = Field(min_length=8, max_length=2_000)
    variant_id: str = Field(pattern=r"^[1-9][0-9]{0,30}$")
    variant_price: str = Field(pattern=r"^(?:0|[1-9][0-9]{0,11})\.[0-9]{2}$")
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    available_for_sale: bool
    publication_statuses: dict[str, bool]
    published_on_all_requested_publications: bool
    landing_url_matches_admin: bool
    landing_http_status: int = Field(ge=0, le=599)
    landing_body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    landing_title_present: bool
    landing_price_present: bool
    landing_currency_present: bool
    landing_variant_present: bool
    add_to_cart_form_present: bool
    cart_http_status: int = Field(ge=0, le=599)
    cart_readable: bool
    ready: bool
    verified_at: str

    @field_validator("publication_ids", mode="before")
    @classmethod
    def _immutable_publication_ids(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("publication_completed_at", "verified_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _normalized_utc(value, label=info.field_name)

    @model_validator(mode="after")
    def _closed_evidence(self) -> "ShopifyProductReadinessPayload":
        if len(set(self.publication_ids)) != len(self.publication_ids):
            raise ValueError("readiness publication_ids must be unique")
        if set(self.publication_statuses) != set(self.publication_ids):
            raise ValueError("readiness publication statuses must match the request")
        derived_ready = all(
            (
                self.admin_status == "ACTIVE",
                self.title_matches,
                self.admin_title == self.expected_title,
                self.variant_price == self.expected_price,
                self.currency == self.expected_currency,
                self.available_for_sale,
                self.published_on_all_requested_publications,
                all(self.publication_statuses.values()),
                self.landing_url_matches_admin,
                self.online_store_url == self.landing_url,
                self.landing_http_status == 200,
                self.landing_title_present,
                self.landing_price_present,
                self.landing_currency_present,
                self.landing_variant_present,
                self.add_to_cart_form_present,
                self.cart_http_status == 200,
                self.cart_readable,
            )
        )
        if self.ready != derived_ready:
            raise ValueError("readiness ready flag contradicts its exact evidence")
        verified = datetime.fromisoformat(self.verified_at.replace("Z", "+00:00"))
        published = datetime.fromisoformat(
            self.publication_completed_at.replace("Z", "+00:00")
        )
        if verified < published:
            raise ValueError("readiness evidence predates publication")
        return self


@runtime_checkable
class LandingReadinessVerifier(Protocol):
    """Trusted host seam that performs live, read-only storefront verification."""

    def verify(
        self,
        request: LandingReadinessRequest,
    ) -> LandingReadinessObservation: ...


class ConnectorLandingReadinessVerifier:
    """Turn one exact governed Shopify read into the launch evidence contract."""

    def __init__(
        self,
        executor: ConnectorExecutor,
        *,
        execution_scope: ExecutionScope | Mapping[str, Any],
        tenant_connector_id: UUID,
        expected_tool_version: int,
        expected_route_digest: str,
    ) -> None:
        scope = (
            execution_scope
            if isinstance(execution_scope, ExecutionScope)
            else ExecutionScope.model_validate(execution_scope)
        )
        if scope.project_id is None:
            raise ValueError(
                "readiness verifier requires an authenticated project UUID"
            )
        if expected_tool_version < 1:
            raise ValueError("expected_tool_version must be positive")
        if re.fullmatch(r"[0-9a-f]{64}", expected_route_digest) is None:
            raise ValueError("expected_route_digest must be lowercase SHA-256")
        self.executor = executor
        self.execution_scope = scope
        self.tenant_connector_id = tenant_connector_id
        self.expected_tool_version = expected_tool_version
        self.expected_route_digest = expected_route_digest

    @staticmethod
    def _numeric_id(value: str, *, resource: str) -> str:
        clean = value.strip()
        prefix = f"gid://shopify/{resource}/"
        numeric = clean[len(prefix) :] if clean.startswith(prefix) else clean
        if re.fullmatch(r"[1-9][0-9]{0,30}", numeric) is None:
            raise ValueError(f"invalid Shopify {resource} identifier")
        return numeric

    def verify(
        self,
        request: LandingReadinessRequest,
    ) -> LandingReadinessObservation:
        if request.project_id != self.execution_scope.project_id:
            raise ValueError("readiness request project does not match verifier scope")
        product_id = self._numeric_id(request.product_id, resource="Product")
        publication_ids = tuple(
            self._numeric_id(value, resource="Publication")
            for value in request.expected_publication_ids
        )
        arguments = {
            "product_id": product_id,
            "publication_ids": list(publication_ids),
            "expected_title": request.expected_title,
            "expected_price": request.expected_price,
            "expected_currency": request.expected_currency,
            "landing_url": request.landing_url,
            "publication_completed_at": request.publication_completed_at,
        }
        connector_request = ConnectorExecutionRequest(
            tool=_READINESS_CONNECTOR_TOOL,
            arguments=arguments,
            scope=self.execution_scope,
            connector_account_ref=request.connector_account_ref,
            effect=ConnectorEffect.READ,
            metadata={
                "plan_digest": request.plan_digest,
                "run_ref": request.run_ref,
                "iteration": request.iteration,
                "operation_id": request.operation_id,
            },
        )
        if not self.executor.supports(_READINESS_CONNECTOR_TOOL):
            raise ValueError("governed readiness Tool is unavailable")
        result = self.executor.execute(connector_request)
        provenance = result.provenance
        if result.status != ConnectorExecutionStatus.COMPLETED or provenance is None:
            raise ValueError("governed readiness read did not complete with provenance")
        if (
            provenance.tool != _READINESS_CONNECTOR_TOOL
            or provenance.tool_version != self.expected_tool_version
            or provenance.server_effect != ConnectorEffect.READ
            or provenance.connector_account_ref != request.connector_account_ref
            or provenance.tenant_connector_id != self.tenant_connector_id
            or provenance.project_id != request.project_id
            or provenance.route_digest != self.expected_route_digest
            or provenance.request_digest != connector_request.custody_fingerprint()
        ):
            raise ValueError("governed readiness provenance does not match the request")
        payload = ShopifyProductReadinessPayload.model_validate(result.output)
        if (
            payload.request_digest != provenance.request_digest
            or payload.input_digest != _canonical_digest(arguments)
            or payload.product_id != product_id
            or payload.publication_ids != publication_ids
            or payload.publication_completed_at != request.publication_completed_at
            or payload.expected_title != request.expected_title
            or payload.expected_price != request.expected_price
            or payload.expected_currency != request.expected_currency
            or payload.landing_url != request.landing_url
        ):
            raise ValueError("governed readiness output is not bound to the request")
        return LandingReadinessObservation(
            request_digest=request.request_digest,
            source_capability=_READINESS_CONNECTOR_TOOL,
            connector_account_ref=request.connector_account_ref,
            project_id=request.project_id,
            landing_url=request.landing_url,
            product_id=request.product_id,
            observed_title=payload.admin_title,
            observed_price=payload.variant_price,
            observed_currency=payload.currency,
            published_publication_ids=request.expected_publication_ids,
            page_reachable=payload.landing_http_status == 200,
            product_visible=all(
                (
                    payload.admin_status == "ACTIVE",
                    payload.title_matches,
                    payload.published_on_all_requested_publications,
                    payload.landing_url_matches_admin,
                    payload.landing_title_present,
                    payload.landing_variant_present,
                )
            ),
            price_and_currency_match=(
                payload.variant_price == request.expected_price
                and payload.currency == request.expected_currency
                and payload.landing_price_present
                and payload.landing_currency_present
            ),
            checkout_available=all(
                (
                    payload.available_for_sale,
                    payload.add_to_cart_form_present,
                    payload.cart_readable,
                )
            ),
            observed_at=payload.verified_at,
            evidence_digest=provenance.receipt_digest,
        )


class ShopifyLaunchOperationResult(_StrictModel):
    schema_id: Literal["lightbulb.shopify_launch_operation_result.v1"] = Field(
        default=SHOPIFY_LAUNCH_OPERATION_RESULT_SCHEMA,
        alias="schema",
    )
    status: ShopifyLaunchOperationStatus
    operation_id: str
    operation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability: str
    connector_account_ref: str
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
    product_status: Literal["DRAFT", "ACTIVE"] | None = None
    publication_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=50)
    receipt: ProductLaunchReceipt | None = None
    live_systems_changed: bool | None = False
    summary: str = Field(min_length=1, max_length=1_000)

    @field_validator("publication_ids", mode="before")
    @classmethod
    def _immutable_publications(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def _status_matches_evidence(self) -> "ShopifyLaunchOperationResult":
        if self.status == "completed":
            if self.receipt is None or self.execution_receipt_digest is None:
                raise ValueError("completed launch operation requires exact evidence")
            if (
                self.capability != _READINESS_TOOL
                and self.live_systems_changed is not True
            ):
                raise ValueError("completed connector write must report an effect")
            if (
                self.capability == _READINESS_TOOL
                and self.live_systems_changed is not False
            ):
                raise ValueError("readiness verification is read-only")
        elif any(
            value is not None for value in (self.receipt, self.execution_receipt_digest)
        ):
            raise ValueError("incomplete launch operation cannot expose evidence")
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
            raise ValueError("preview and blocked operations cannot claim effects")
        return self


class ShopifyLaunchRunResult(_StrictModel):
    """Bounded storefront result; this is not omnichannel completion."""

    schema_id: Literal["lightbulb.shopify_launch_run_result.v1"] = Field(
        default=SHOPIFY_LAUNCH_RUN_RESULT_SCHEMA,
        alias="schema",
    )
    status: ShopifyLaunchStatus
    launch_ref: str
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_ref: str
    iteration: int = Field(ge=1, le=4)
    operation_results: tuple[ShopifyLaunchOperationResult, ...] = Field(max_length=4)
    receipts: tuple[ProductLaunchReceipt, ...] = Field(max_length=4)
    product_id: str | None = None
    product_status: Literal["DRAFT", "ACTIVE"] | None = None
    publication_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=50)
    next_operation_id: str | None = None
    storefront_ready: bool = False
    downstream_release_ready: bool = False
    eligible_downstream_operation_ids: tuple[str, ...] = Field(
        default_factory=tuple,
        max_length=4,
    )
    held_downstream_operation_ids: tuple[str, ...] = Field(
        default_factory=tuple,
        max_length=4,
    )
    omnichannel_launch_completed: Literal[False] = False
    summary: str = Field(min_length=1, max_length=1_000)

    @field_validator(
        "operation_results",
        "receipts",
        "publication_ids",
        "eligible_downstream_operation_ids",
        "held_downstream_operation_ids",
        mode="before",
    )
    @classmethod
    def _immutable_sequences(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def _readiness_controls_release(self) -> "ShopifyLaunchRunResult":
        ready = self.status == "storefront_ready"
        if ready != (
            self.storefront_ready
            and self.downstream_release_ready
            and self.product_id is not None
            and self.product_status == "ACTIVE"
            and bool(self.publication_ids)
            and len(self.receipts) == 4
            and len(self.operation_results) == 4
            and all(item.status == "completed" for item in self.operation_results)
        ):
            raise ValueError("storefront readiness requires the complete Shopify chain")
        if not ready and (
            self.storefront_ready
            or self.downstream_release_ready
            or self.eligible_downstream_operation_ids
        ):
            raise ValueError("downstream operations must remain held before readiness")
        if set(self.eligible_downstream_operation_ids) & set(
            self.held_downstream_operation_ids
        ):
            raise ValueError("downstream operations cannot be both eligible and held")
        if len({receipt.criterion_id for receipt in self.receipts}) != len(
            self.receipts
        ):
            raise ValueError("launch receipts must be unique by criterion")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _shopify_graph(
    plan: OmnichannelProductLaunchPlan,
) -> tuple[
    tuple[ProductLaunchOperation, RequiredLaunchReceipt],
    tuple[ProductLaunchOperation, RequiredLaunchReceipt],
    tuple[ProductLaunchOperation, RequiredLaunchReceipt],
    tuple[ProductLaunchOperation, RequiredLaunchReceipt],
]:
    pairs: list[tuple[ProductLaunchOperation, RequiredLaunchReceipt]] = []
    for capability in _SHOPIFY_CAPABILITIES:
        operations = [
            operation
            for operation in plan.operations
            if operation.capability == capability
        ]
        if len(operations) != 1:
            raise ValueError(f"launch plan must contain one canonical {capability}")
        operation = operations[0]
        requirements = [
            receipt
            for receipt in plan.required_receipts
            if receipt.operation_id == operation.operation_id
        ]
        if (
            len(requirements) != 1
            or requirements[0].operation_digest != operation.operation_digest
            or requirements[0].approval_unit != operation.approval_unit
        ):
            raise ValueError(f"{capability} receipt obligation is not canonical")
        pairs.append((operation, requirements[0]))
    create, activate, publish, readiness = pairs
    if (
        activate[0].depends_on != (create[0].operation_id,)
        or publish[0].depends_on != (activate[0].operation_id,)
        or readiness[0].depends_on != (publish[0].operation_id,)
        or any(
            operation.connector_account_ref != create[0].connector_account_ref
            for operation, _ in pairs
        )
    ):
        raise ValueError("Shopify launch graph is not one exact linear account chain")
    if not isinstance(activate[0].arguments, ShopifyActivateProductArguments):
        raise ValueError("Shopify activation arguments are not canonical")
    if not isinstance(publish[0].arguments, ShopifyPublishProductArguments):
        raise ValueError("Shopify publication arguments are not canonical")
    if any(
        _PUBLICATION_ID_RE.fullmatch(publication_id) is None
        for publication_id in publish[0].arguments.publication_ids
    ):
        raise ValueError("Shopify publication IDs must be numeric IDs or GIDs")
    canonical_publication_ids = tuple(
        publication_id.rsplit("/", 1)[-1]
        for publication_id in publish[0].arguments.publication_ids
    )
    if len(canonical_publication_ids) != len(set(canonical_publication_ids)):
        raise ValueError("Shopify publication IDs must be canonically unique")
    if not isinstance(readiness[0].arguments, LandingReadinessArguments):
        raise ValueError("landing readiness arguments are not canonical")
    return create, activate, publish, readiness  # type: ignore[return-value]


def _operation_key(
    plan: OmnichannelProductLaunchPlan,
    operation: ProductLaunchOperation,
    *,
    run_ref: str,
    iteration: int,
) -> str:
    digest = _stable_digest(
        {
            "schema": "lightbulb.shopify_launch_operation_identity.v1",
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
    return f"lb-gtm-shopify-{digest}"


def _grant_map(
    values: Iterable[ProductLaunchApprovalGrant | Mapping[str, Any]],
    *,
    plan: OmnichannelProductLaunchPlan,
    allowed_operations: Mapping[str, ProductLaunchOperation],
    scope_keyring: ExactScopeDigestProvider,
) -> dict[str, ProductLaunchApprovalGrant]:
    result: dict[str, ProductLaunchApprovalGrant] = {}
    for index, value in enumerate(values, start=1):
        if index > len(allowed_operations):
            raise ValueError("approval grant set exceeds Shopify launch writes")
        grant = _approval_grant(value, scope_keyring=scope_keyring)
        if grant is None:  # pragma: no cover - iterable cannot contain None by type
            raise ValueError("approval grant cannot be null")
        operation = allowed_operations.get(grant.operation_id)
        if operation is None:
            raise ValueError("approval grant is not for a Shopify launch write")
        if grant.operation_id in result:
            raise ValueError("approval grants must be unique by operation")
        if (
            grant.plan_digest != plan.plan_digest
            or grant.exact_scope_digest != plan.analytics_scope.exact_scope_digest
            or grant.operation_digest != operation.operation_digest
            or grant.connector_account_ref != operation.connector_account_ref
            or grant.approval_unit != operation.approval_unit
            or grant.grant_key_id != plan.analytics_scope.receipt_key_id
        ):
            raise ValueError("approval grant does not match its exact launch write")
        result[grant.operation_id] = grant
    return result


def _payloads(output: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    values: list[Mapping[str, Any]] = [output]
    nested = output.get("output")
    if isinstance(nested, Mapping):
        values.append(nested)
    return tuple(values)


def _product_status(output: Mapping[str, Any], expected: str) -> str | None:
    statuses: set[str] = set()
    for payload in _payloads(output):
        for key in ("product", "raw"):
            value = payload.get(key)
            if not isinstance(value, Mapping) or "status" not in value:
                continue
            raw_status = value.get("status")
            if not isinstance(raw_status, str):
                return None
            statuses.add(raw_status.strip().upper())
    return expected if statuses == {expected} else None


def _publication_ids(output: Mapping[str, Any]) -> tuple[str, ...] | None:
    candidates: list[Any] = []
    for payload in _payloads(output):
        for key in ("published_publication_ids", "publication_ids"):
            if key in payload:
                candidates.append(payload.get(key))
        product = payload.get("product")
        if isinstance(product, Mapping):
            for key in ("published_publication_ids", "publication_ids"):
                if key in product:
                    candidates.append(product.get(key))
    if not candidates:
        return None
    normalized: set[tuple[str, ...]] = set()
    for candidate in candidates:
        if not isinstance(candidate, (list, tuple)) or not candidate:
            return None
        clean: list[str] = []
        for raw in candidate:
            if not isinstance(raw, str) or not raw.strip() or raw != raw.strip():
                return None
            match = _PUBLICATION_ID_RE.fullmatch(raw)
            if match is None:
                return None
            # The native Shopify adapter deliberately returns the numeric tail
            # of a GraphQL GID.  Canonicalize both request and response forms so
            # exact publication identity remains comparable across that wire
            # boundary.
            clean.append(raw.rsplit("/", 1)[-1])
        if len(clean) != len(set(clean)):
            return None
        normalized.add(tuple(sorted(clean)))
    if len(normalized) != 1:
        return None
    return next(iter(normalized))


def _publication_success(output: Mapping[str, Any]) -> bool:
    values: set[bool] = set()
    for payload in _payloads(output):
        if "success" not in payload:
            continue
        value = payload.get("success")
        if not isinstance(value, bool):
            return False
        values.add(value)
    return values == {True}


def _same_product_identity(left: str | None, right: str) -> bool:
    if left is None:
        return False
    if (
        _PRODUCT_ID_RE.fullmatch(left) is None
        or _PRODUCT_ID_RE.fullmatch(right) is None
    ):
        return False
    return left.rsplit("/", 1)[-1] == right.rsplit("/", 1)[-1]


def _operation_result(
    operation: ProductLaunchOperation,
    *,
    status: ShopifyLaunchOperationStatus,
    idempotency_key: str,
    summary: str,
    connector_status: ConnectorExecutionStatus | None = None,
    connector_error_kind: ConnectorErrorKind | None = None,
    connector_error_code: str | None = None,
    approval_ref: str | None = None,
    approval_receipt_digest: str | None = None,
    execution_receipt_digest: str | None = None,
    product_id: str | None = None,
    product_status: Literal["DRAFT", "ACTIVE"] | None = None,
    publication_ids: tuple[str, ...] = (),
    receipt: ProductLaunchReceipt | None = None,
    live_systems_changed: bool | None = False,
) -> ShopifyLaunchOperationResult:
    return ShopifyLaunchOperationResult(
        status=status,
        operation_id=operation.operation_id,
        operation_digest=operation.operation_digest,
        capability=operation.capability,
        connector_account_ref=operation.connector_account_ref,
        idempotency_key=idempotency_key,
        connector_status=connector_status,
        connector_error_kind=connector_error_kind,
        connector_error_code=connector_error_code,
        approval_ref=approval_ref,
        approval_receipt_digest=approval_receipt_digest,
        execution_receipt_digest=execution_receipt_digest,
        product_id=product_id,
        product_status=product_status,
        publication_ids=publication_ids,
        receipt=receipt,
        live_systems_changed=live_systems_changed,
        summary=summary,
    )


def _execute_write(
    *,
    plan: OmnichannelProductLaunchPlan,
    workflow_scope: DynamicWorkflowScope,
    scope_keyring: ExactScopeDigestProvider,
    runtime_scope: ExecutionScope,
    executor: ConnectorExecutor,
    operation: ProductLaunchOperation,
    requirement: RequiredLaunchReceipt,
    arguments: Mapping[str, Any],
    grant: ProductLaunchApprovalGrant | None,
    run_ref: str,
    iteration: int,
    expected_product_id: str,
    expected_status: Literal["ACTIVE"],
    not_before: str,
    expected_publications: tuple[str, ...] = (),
) -> ShopifyLaunchOperationResult:
    key = _operation_key(plan, operation, run_ref=run_ref, iteration=iteration)
    try:
        supported = executor.supports(operation.capability)
    except Exception:
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Connector capability discovery failed safely.",
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="connector_support_check_failed",
        )
    if not supported:
        return _operation_result(
            operation,
            status="blocked",
            idempotency_key=key,
            summary=f"The project does not expose {operation.capability}.",
            connector_error_kind=ConnectorErrorKind.UNSUPPORTED_OPERATION,
            connector_error_code="tool_not_available",
        )
    request = ConnectorExecutionRequest(
        tool=operation.capability,
        arguments=dict(arguments),
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
            "run_ref": run_ref,
            "iteration": iteration,
        },
    )
    try:
        result = executor.execute(request)
    except Exception:
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary=(
                "Connector execution raised after dispatch began; effect state is "
                "unknown and no receipt was minted."
            ),
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="connector_execute_failed",
            approval_ref=grant.approval_ref if grant else None,
            approval_receipt_digest=(grant.approval_receipt_digest if grant else None),
            live_systems_changed=None,
        )
    if (
        not isinstance(result, ConnectorExecutionResult)
        or result.tool != operation.capability
    ):
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Connector returned a mismatched result contract.",
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="invalid_connector_result",
            approval_ref=grant.approval_ref if grant else None,
            approval_receipt_digest=(grant.approval_receipt_digest if grant else None),
            live_systems_changed=None,
        )
    if result.status == ConnectorExecutionStatus.PENDING_APPROVAL:
        if grant is not None:
            return _operation_result(
                operation,
                status="failed",
                idempotency_key=key,
                summary="The supplied approval did not authorize connector dispatch.",
                connector_status=result.status,
                connector_error_kind=result.error_kind,
                connector_error_code=result.error_code or "approval_not_authorized",
                approval_ref=grant.approval_ref,
                approval_receipt_digest=grant.approval_receipt_digest,
            )
        pending_ref = result.approval_ref.strip() if result.approval_ref else ""
        pending_digest = result.approval_receipt_digest
        if not pending_ref or pending_digest is None:
            return _operation_result(
                operation,
                status="failed",
                idempotency_key=key,
                summary=(
                    "Connector approval proposal returned no durable reference "
                    "and receipt."
                ),
                connector_status=result.status,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="approval_evidence_missing",
            )
        return _operation_result(
            operation,
            status="pending_approval",
            idempotency_key=key,
            summary=f"Approval is pending for the exact {operation.capability} write.",
            connector_status=result.status,
            approval_ref=pending_ref,
            approval_receipt_digest=pending_digest,
        )
    if result.status == ConnectorExecutionStatus.BLOCKED:
        return _operation_result(
            operation,
            status="blocked",
            idempotency_key=key,
            summary=f"{operation.capability} was blocked before a verified effect.",
            connector_status=result.status,
            connector_error_kind=result.error_kind,
            connector_error_code=result.error_code,
            approval_ref=grant.approval_ref if grant else None,
            approval_receipt_digest=(grant.approval_receipt_digest if grant else None),
        )
    if result.status != ConnectorExecutionStatus.COMPLETED:
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary=f"{operation.capability} did not return a verified completion.",
            connector_status=result.status,
            connector_error_kind=result.error_kind or ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code=result.error_code or "connector_not_completed",
            approval_ref=grant.approval_ref if grant else None,
            approval_receipt_digest=(grant.approval_receipt_digest if grant else None),
            live_systems_changed=(
                False if result.status == ConnectorExecutionStatus.PREVIEW else None
            ),
        )
    if grant is None:
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Connector claimed completion without exact approval proof.",
            connector_status=result.status,
            connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
            connector_error_code="completed_without_approval",
            live_systems_changed=None,
        )
    if (
        result.error_kind is not None
        or result.error_code is not None
        or result.retryable
    ):
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Connector completion carried contradictory failure metadata.",
            connector_status=result.status,
            connector_error_kind=result.error_kind or ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code=result.error_code
            or "contradictory_connector_completion",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    provenance = result.provenance
    if provenance is None:
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Connector completion lacked immutable execution provenance.",
            connector_status=result.status,
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
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Execution provenance did not match the exact launch write.",
            connector_status=result.status,
            connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
            connector_error_code="execution_provenance_mismatch",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    if _reported_approval_refs(result.output) not in (set(), {grant.approval_ref}):
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Connector output reported a different approval reference.",
            connector_status=result.status,
            connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
            connector_error_code="approval_ref_mismatch",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    product_id = _normalized_product_id(result.output)
    status = _product_status(result.output, expected_status)
    publications = _publication_ids(result.output) if expected_publications else ()
    # ecommerce.update_product returns the product payload and therefore must
    # prove ACTIVE directly.  shopify.publish_product has a narrower native
    # contract: product_id, publication_ids, success.  Its ACTIVE prerequisite
    # is already proven by the dependency receipt and chronology check below.
    status_proven = status == expected_status if not expected_publications else True
    if not _same_product_identity(product_id, expected_product_id) or not status_proven:
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Connector output did not prove the exact product and ACTIVE state.",
            connector_status=result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="product_state_mismatch",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    expected_publication_set = tuple(
        sorted(
            publication_id.rsplit("/", 1)[-1]
            for publication_id in expected_publications
        )
    )
    if expected_publications and (
        publications != expected_publication_set
        or not _publication_success(result.output)
    ):
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Connector output did not prove every explicit publication ID.",
            connector_status=result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="publication_ids_mismatch",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    try:
        completed_time, completed_at = _completed_at(
            datetime.fromisoformat(provenance.completed_at.replace("Z", "+00:00")),
            plan=plan,
        )
        dependency_time = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
        if completed_time < dependency_time.astimezone(timezone.utc):
            return _operation_result(
                operation,
                status="failed",
                idempotency_key=key,
                summary="Connector completion predates its verified dependency.",
                connector_status=result.status,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="operation_chronology_mismatch",
                approval_ref=grant.approval_ref,
                approval_receipt_digest=grant.approval_receipt_digest,
                live_systems_changed=None,
            )
        seed = _stable_digest(
            {
                "plan_digest": plan.plan_digest,
                "run_ref": run_ref,
                "iteration": iteration,
                "operation_digest": operation.operation_digest,
            }
        )
        receipt = mint_product_launch_receipt(
            plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
            criterion_id=requirement.criterion_id,
            receipt_ref=f"materialized_{seed[:32]}",
            issuer_ref=_issuer_ref("lightbulb-gtm-materializer"),
            evidence_digest=provenance.receipt_digest,
            issued_at=completed_at,
            effective_at=completed_at,
            run_ref=run_ref,
            iteration=iteration,
            approval_receipt_digest=provenance.approval_receipt_digest,
        )
    except Exception:
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Connector completed but trusted receipt minting failed.",
            connector_status=result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="receipt_mint_failed",
            approval_ref=grant.approval_ref,
            approval_receipt_digest=grant.approval_receipt_digest,
            live_systems_changed=None,
        )
    return _operation_result(
        operation,
        status="completed",
        idempotency_key=key,
        summary=f"Completed and verified the approved {operation.capability} write.",
        connector_status=result.status,
        approval_ref=grant.approval_ref,
        approval_receipt_digest=provenance.approval_receipt_digest,
        execution_receipt_digest=provenance.receipt_digest,
        product_id=expected_product_id,
        product_status="ACTIVE",
        publication_ids=publications or (),
        receipt=receipt,
        live_systems_changed=True,
    )


def _verify_readiness(
    *,
    plan: OmnichannelProductLaunchPlan,
    workflow_scope: DynamicWorkflowScope,
    scope_keyring: ExactScopeDigestProvider,
    runtime_scope: ExecutionScope,
    verifier: LandingReadinessVerifier | None,
    operation: ProductLaunchOperation,
    requirement: RequiredLaunchReceipt,
    run_ref: str,
    iteration: int,
    product_id: str,
    publication_ids: tuple[str, ...],
    publication_completed_at: str,
) -> ShopifyLaunchOperationResult:
    key = _operation_key(plan, operation, run_ref=run_ref, iteration=iteration)
    if verifier is None or not isinstance(verifier, LandingReadinessVerifier):
        return _operation_result(
            operation,
            status="blocked",
            idempotency_key=key,
            summary="No trusted live-storefront readiness verifier is configured.",
            connector_error_kind=ConnectorErrorKind.UNSUPPORTED_OPERATION,
            connector_error_code="landing_readiness_verifier_unavailable",
        )
    if (
        plan.analytics_scope.exact_scope_digest is None
        or runtime_scope.project_id is None
    ):
        raise ValueError("landing readiness requires exact scope and project UUID")
    request = LandingReadinessRequest(
        plan_digest=plan.plan_digest,
        exact_scope_digest=plan.analytics_scope.exact_scope_digest,
        run_ref=run_ref,
        iteration=iteration,
        operation_id=operation.operation_id,
        operation_digest=operation.operation_digest,
        connector_account_ref=operation.connector_account_ref,
        project_id=runtime_scope.project_id,
        product_id=product_id,
        expected_title=plan.product.title,
        landing_url=operation.arguments.landing_url,
        expected_price=f"{plan.product.price.amount:.2f}",
        expected_currency=plan.product.price.currency,
        expected_publication_ids=publication_ids,
        publication_completed_at=publication_completed_at,
        required_checks=operation.arguments.required_checks,
    )
    try:
        raw = verifier.verify(request)
        observation = LandingReadinessObservation.model_validate(
            raw.model_dump(mode="python", by_alias=True)
            if isinstance(raw, LandingReadinessObservation)
            else raw
        )
    except (Exception, ValidationError):
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Live-storefront readiness verification failed safely.",
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="landing_readiness_verification_failed",
        )
    expected_publications = tuple(sorted(publication_ids))
    exact_values_match = (
        observation.request_digest == request.request_digest
        and observation.connector_account_ref == request.connector_account_ref
        and observation.project_id == request.project_id
        and observation.landing_url == request.landing_url
        and observation.product_id == request.product_id
        and observation.observed_title == request.expected_title
        and observation.observed_price == request.expected_price
        and observation.observed_currency == request.expected_currency
        and tuple(sorted(observation.published_publication_ids))
        == expected_publications
    )
    checks_passed = all(
        (
            observation.page_reachable,
            observation.product_visible,
            observation.price_and_currency_match,
            observation.checkout_available,
        )
    )
    observed_at = datetime.fromisoformat(observation.observed_at.replace("Z", "+00:00"))
    published_at = datetime.fromisoformat(
        request.publication_completed_at.replace("Z", "+00:00")
    )
    if not exact_values_match or not checks_passed or observed_at <= published_at:
        return _operation_result(
            operation,
            status="blocked",
            idempotency_key=key,
            summary=(
                "Live evidence did not prove the exact page, product, price, currency, "
                "publications, and checkout readiness."
            ),
            connector_error_kind=ConnectorErrorKind.VALIDATION_ERROR,
            connector_error_code="landing_readiness_not_proven",
        )
    try:
        _, observed_at_text = _completed_at(observed_at, plan=plan)
        seed = _stable_digest(
            {
                "plan_digest": plan.plan_digest,
                "run_ref": run_ref,
                "iteration": iteration,
                "operation_digest": operation.operation_digest,
            }
        )
        receipt = mint_product_launch_receipt(
            plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
            criterion_id=requirement.criterion_id,
            receipt_ref=f"verified_{seed[:32]}",
            issuer_ref=_issuer_ref("lightbulb-gtm-materializer"),
            evidence_digest=observation.evidence_digest,
            issued_at=observed_at_text,
            effective_at=observed_at_text,
            run_ref=run_ref,
            iteration=iteration,
        )
    except Exception:
        return _operation_result(
            operation,
            status="failed",
            idempotency_key=key,
            summary="Readiness passed but trusted receipt minting failed.",
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="readiness_receipt_mint_failed",
        )
    return _operation_result(
        operation,
        status="completed",
        idempotency_key=key,
        summary="The exact live storefront and checkout readiness gates passed.",
        execution_receipt_digest=observation.evidence_digest,
        product_id=product_id,
        product_status="ACTIVE",
        publication_ids=expected_publications,
        receipt=receipt,
        live_systems_changed=False,
    )


def _downstream_operations(
    plan: OmnichannelProductLaunchPlan,
) -> tuple[ProductLaunchOperation, ...]:
    return tuple(
        operation
        for operation in plan.operations
        if operation.stage in {"crm_campaign_container", "social_publish"}
    )


def _run_result(
    *,
    status: ShopifyLaunchStatus,
    plan: OmnichannelProductLaunchPlan,
    run_ref: str,
    iteration: int,
    operation_results: Iterable[ShopifyLaunchOperationResult],
    next_operation_id: str | None,
    product_id: str | None,
    product_status: Literal["DRAFT", "ACTIVE"] | None,
    publication_ids: tuple[str, ...],
    summary: str,
) -> ShopifyLaunchRunResult:
    results = tuple(operation_results)
    receipts = tuple(result.receipt for result in results if result.receipt is not None)
    downstream = _downstream_operations(plan)
    ready = status == "storefront_ready"
    if ready:
        campaign_ids = tuple(
            operation.operation_id
            for operation in downstream
            if operation.stage == "crm_campaign_container"
        )
        # Social is immediately eligible only when there is no CRM dependency.
        eligible = campaign_ids or tuple(
            operation.operation_id
            for operation in downstream
            if operation.stage == "social_publish" and len(operation.depends_on) == 1
        )
        held = tuple(
            operation.operation_id
            for operation in downstream
            if operation.operation_id not in eligible
        )
    else:
        eligible = ()
        held = tuple(operation.operation_id for operation in downstream)
    return ShopifyLaunchRunResult(
        status=status,
        launch_ref=plan.launch_ref,
        plan_digest=plan.plan_digest,
        run_ref=run_ref,
        iteration=iteration,
        operation_results=results,
        receipts=receipts,
        product_id=product_id,
        product_status=product_status,
        publication_ids=publication_ids,
        next_operation_id=next_operation_id,
        storefront_ready=ready,
        downstream_release_ready=ready,
        eligible_downstream_operation_ids=eligible,
        held_downstream_operation_ids=held,
        summary=summary,
    )


def run_shopify_product_launch(
    plan_value: OmnichannelProductLaunchPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    execution_scope: ExecutionScope | Mapping[str, Any],
    executor: ConnectorExecutor,
    run_ref: str,
    iteration: int = 1,
    preview_only: bool = True,
    approval_grants: Iterable[ProductLaunchApprovalGrant | Mapping[str, Any]] = (),
    readiness_verifier: LandingReadinessVerifier | None = None,
) -> ShopifyLaunchRunResult:
    """Run or resume DRAFT → ACTIVE → publish → live-readiness.

    Each write consumes a different grant sealed to its operation.  On replay,
    the same per-operation idempotency key is used and all returned output and
    provenance are revalidated.  CRM/social execution is outside this runner;
    it is held until the readiness receipt exists.
    """

    workflow_scope = _workflow_scope(scope)
    plan = verify_product_launch_plan(
        plan_value,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    runtime_scope = _execution_scope(execution_scope)
    _validate_execution_scope(runtime_scope, workflow_scope)
    if plan.product.variants:
        raise ValueError(
            "Shopify launch materialization cannot omit requested product variants"
        )
    clean_run_ref = _run_ref(run_ref)
    if isinstance(iteration, bool) or not isinstance(iteration, int) or iteration != 1:
        raise ValueError(
            "Shopify launch materialization supports iteration 1 only; revisions "
            "require a newly signed plan"
        )
    create_pair, activate_pair, publish_pair, readiness_pair = _shopify_graph(plan)
    writes = {
        operation.operation_id: operation
        for operation, _ in (create_pair, activate_pair, publish_pair)
    }
    grants = _grant_map(
        approval_grants,
        plan=plan,
        allowed_operations=writes,
        scope_keyring=scope_keyring,
    )
    shopify_pairs = (create_pair, activate_pair, publish_pair, readiness_pair)
    if preview_only:
        previews = tuple(
            _operation_result(
                operation,
                status="preview",
                idempotency_key=(
                    _idempotency_key(
                        plan,
                        operation,
                        run_ref=clean_run_ref,
                        iteration=iteration,
                    )
                    if operation.capability == "ecommerce.create_product"
                    else _operation_key(
                        plan,
                        operation,
                        run_ref=clean_run_ref,
                        iteration=iteration,
                    )
                ),
                summary=f"Previewed {operation.capability}; nothing was dispatched.",
            )
            for operation, _ in shopify_pairs
        )
        return _run_result(
            status="preview",
            plan=plan,
            run_ref=clean_run_ref,
            iteration=iteration,
            operation_results=previews,
            next_operation_id=create_pair[0].operation_id,
            product_id=None,
            product_status=None,
            publication_ids=(),
            summary="Previewed the complete Shopify storefront chain with no reads or writes.",
        )

    results: list[ShopifyLaunchOperationResult] = []
    create_operation, _ = create_pair
    create_result = materialize_shopify_draft_product(
        plan,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        execution_scope=runtime_scope,
        executor=executor,
        run_ref=clean_run_ref,
        iteration=iteration,
        preview_only=False,
        approval_grant=grants.get(create_operation.operation_id),
    )
    create_stage = _operation_result(
        create_operation,
        status=create_result.status,
        idempotency_key=create_result.idempotency_key,
        summary=create_result.summary,
        connector_status=create_result.connector_status,
        connector_error_kind=create_result.connector_error_kind,
        connector_error_code=create_result.connector_error_code,
        approval_ref=create_result.approval_ref,
        approval_receipt_digest=create_result.approval_receipt_digest,
        execution_receipt_digest=create_result.execution_receipt_digest,
        product_id=create_result.product_id,
        product_status=("DRAFT" if create_result.status == "completed" else None),
        receipt=create_result.receipt,
        live_systems_changed=create_result.live_systems_changed,
    )
    results.append(create_stage)
    if create_stage.status != "completed":
        return _run_result(
            status=create_stage.status,
            plan=plan,
            run_ref=clean_run_ref,
            iteration=iteration,
            operation_results=results,
            next_operation_id=create_operation.operation_id,
            product_id=None,
            product_status=None,
            publication_ids=(),
            summary="Shopify launch stopped safely at DRAFT materialization.",
        )
    product_id = create_stage.product_id
    if product_id is None:  # model invariant, defensive for type narrowing
        raise RuntimeError("completed DRAFT result omitted product_id")
    if create_stage.receipt is None:  # model invariant, defensive for type narrowing
        raise RuntimeError("completed DRAFT result omitted receipt")

    activate_operation, activate_requirement = activate_pair
    activate = _execute_write(
        plan=plan,
        workflow_scope=workflow_scope,
        scope_keyring=scope_keyring,
        runtime_scope=runtime_scope,
        executor=executor,
        operation=activate_operation,
        requirement=activate_requirement,
        arguments=activate_operation.connector_inputs(
            {create_operation.operation_id: {"product_id": product_id}}
        ),
        grant=grants.get(activate_operation.operation_id),
        run_ref=clean_run_ref,
        iteration=iteration,
        expected_product_id=product_id,
        expected_status="ACTIVE",
        not_before=create_stage.receipt.effective_at,
    )
    results.append(activate)
    if activate.status != "completed":
        return _run_result(
            status=activate.status,
            plan=plan,
            run_ref=clean_run_ref,
            iteration=iteration,
            operation_results=results,
            next_operation_id=activate_operation.operation_id,
            product_id=product_id,
            product_status=(
                "DRAFT" if activate.live_systems_changed is False else None
            ),
            publication_ids=(),
            summary="Shopify launch stopped safely before verified activation.",
        )
    if activate.receipt is None:  # model invariant, defensive for type narrowing
        raise RuntimeError("completed activation omitted receipt")

    publish_operation, publish_requirement = publish_pair
    publication_ids = tuple(sorted(publish_operation.arguments.publication_ids))
    publish = _execute_write(
        plan=plan,
        workflow_scope=workflow_scope,
        scope_keyring=scope_keyring,
        runtime_scope=runtime_scope,
        executor=executor,
        operation=publish_operation,
        requirement=publish_requirement,
        arguments=publish_operation.connector_inputs(
            {activate_operation.operation_id: {"product_id": product_id}}
        ),
        grant=grants.get(publish_operation.operation_id),
        run_ref=clean_run_ref,
        iteration=iteration,
        expected_product_id=product_id,
        expected_status="ACTIVE",
        not_before=activate.receipt.effective_at,
        expected_publications=publication_ids,
    )
    results.append(publish)
    if publish.status != "completed":
        return _run_result(
            status=publish.status,
            plan=plan,
            run_ref=clean_run_ref,
            iteration=iteration,
            operation_results=results,
            next_operation_id=publish_operation.operation_id,
            product_id=product_id,
            product_status="ACTIVE",
            publication_ids=(),
            summary="Shopify launch stopped safely before verified publication.",
        )
    if publish.receipt is None:  # model invariant, defensive for type narrowing
        raise RuntimeError("completed publication omitted receipt")

    readiness_operation, readiness_requirement = readiness_pair
    readiness = _verify_readiness(
        plan=plan,
        workflow_scope=workflow_scope,
        scope_keyring=scope_keyring,
        runtime_scope=runtime_scope,
        verifier=readiness_verifier,
        operation=readiness_operation,
        requirement=readiness_requirement,
        run_ref=clean_run_ref,
        iteration=iteration,
        product_id=product_id,
        publication_ids=publication_ids,
        publication_completed_at=publish.receipt.effective_at,
    )
    results.append(readiness)
    if readiness.status != "completed":
        return _run_result(
            status=readiness.status,
            plan=plan,
            run_ref=clean_run_ref,
            iteration=iteration,
            operation_results=results,
            next_operation_id=readiness_operation.operation_id,
            product_id=product_id,
            product_status="ACTIVE",
            publication_ids=publication_ids,
            summary="Shopify writes completed, but downstream launch remains held by readiness.",
        )
    return _run_result(
        status="storefront_ready",
        plan=plan,
        run_ref=clean_run_ref,
        iteration=iteration,
        operation_results=results,
        next_operation_id=None,
        product_id=product_id,
        product_status="ACTIVE",
        publication_ids=publication_ids,
        summary=(
            "The approved Shopify product is ACTIVE, explicitly published, and "
            "live-storefront readiness is proven. Omnichannel completion is not claimed."
        ),
    )


__all__ = [
    "LANDING_READINESS_OBSERVATION_SCHEMA",
    "LANDING_READINESS_REQUEST_SCHEMA",
    "SHOPIFY_PRODUCT_READINESS_PAYLOAD_SCHEMA",
    "SHOPIFY_LAUNCH_OPERATION_RESULT_SCHEMA",
    "SHOPIFY_LAUNCH_RUN_RESULT_SCHEMA",
    "ConnectorLandingReadinessVerifier",
    "LandingReadinessObservation",
    "LandingReadinessRequest",
    "LandingReadinessVerifier",
    "ShopifyProductReadinessPayload",
    "ShopifyLaunchOperationResult",
    "ShopifyLaunchOperationStatus",
    "ShopifyLaunchRunResult",
    "ShopifyLaunchStatus",
    "run_shopify_product_launch",
]
