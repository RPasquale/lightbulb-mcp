"""Closed-world, proposal-only Shopify storefront planning.

The planner names only documented connector tools, but it never resolves a
connector, reads a shop, performs a write, publishes a resource, or claims a
deployment. Current governed connector write custody remains unavailable.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Mapping

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)


SHOPIFY_STOREFRONT_PLAN_SCHEMA = "lightbulb.shopify_storefront_plan.v1"
SHOPIFY_STOREFRONT_PRIMITIVE_REF = "commerce.plan_shopify_storefront"

SHOPIFY_PROPOSAL_TOOLS = frozenset(
    {
        "ecommerce.create_product",
        "shopify.create_collection",
        "shopify.create_page",
    }
)
SHOPIFY_BLOCKED_GO_LIVE_TOOLS = frozenset(
    {
        "shopify.publish_product",
        "shopify.update_page",
        "shopify.publish_theme",
    }
)

_MONEY_QUANTUM = Decimal("0.01")
_MAX_PRODUCTS = 25
_MAX_PAGES = 20
_MAX_VARIANTS_PER_PRODUCT = 20
_MAX_TOTAL_VARIANTS = 100
_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,47}$"
_OPERATION_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,159}$"
_HANDLE_PATTERN = r"^[a-z0-9][a-z0-9-]{0,254}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_LOCALE_PATTERN = r"^[a-z]{2}(?:-[A-Z]{2})?$"


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("text must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("text must contain printable characters only")
    return value


def _bounded_html(value: str) -> str:
    if value != value.strip():
        raise ValueError("HTML must not contain surrounding whitespace")
    if any(
        ord(character) < 32 and character not in {"\t", "\n", "\r"}
        for character in value
    ):
        raise ValueError("HTML contains an unsupported control character")
    return value


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
LongText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=10_000),
    AfterValidator(_bounded_text),
]
HtmlText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=100_000),
    AfterValidator(_bounded_html),
]
PortableRef = Annotated[str, StringConstraints(pattern=_REF_PATTERN)]
OperationRef = Annotated[str, StringConstraints(pattern=_OPERATION_REF_PATTERN)]
Handle = Annotated[str, StringConstraints(pattern=_HANDLE_PATTERN)]
Currency = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
Locale = Annotated[str, StringConstraints(pattern=_LOCALE_PATTERN)]
PriceAmount = Annotated[
    str,
    StringConstraints(pattern=r"^(?:0|[1-9][0-9]{0,8})\.[0-9]{2}$"),
]

ProposedTool = Literal[
    "ecommerce.create_product",
    "shopify.create_collection",
    "shopify.create_page",
]
BlockedGoLiveTool = Literal[
    "shopify.publish_product",
    "shopify.update_page",
    "shopify.publish_theme",
]
CapabilityGapCode = Literal[
    "governed_connector_write_custody_unavailable",
    "custom_theme_creation_tool_unavailable",
    "connected_shop_currency_unverified",
    "typed_create_product_variant_gap",
]
BlockedReasonCode = Literal[
    "governed_connector_write_custody_unavailable",
    "typed_create_product_variant_gap",
    "materialized_resource_id_unavailable",
    "collection_publish_after_creation_tool_unavailable",
    "existing_theme_id_unresolved",
    "separate_go_live_approval_required",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        strict=True,
    )


class ShopifyStorefrontPlanValidationError(ValueError):
    """A storefront brief cannot be safely converted into a proposal."""


class ShopifyMoney(_StrictModel):
    amount: Decimal = Field(gt=0, le=100_000_000)
    currency: Currency

    @field_validator("amount", mode="before")
    @classmethod
    def _exact_currency_amount(cls, value: Any) -> Decimal:
        if not isinstance(value, (str, Decimal)) or isinstance(value, bool):
            raise ValueError("money amount must be a decimal string")
        try:
            parsed = Decimal(value)
            normalized = parsed.quantize(_MONEY_QUANTUM)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("money amount must be a finite decimal") from exc
        if not parsed.is_finite() or parsed != normalized:
            raise ValueError("money amount supports at most two decimal places")
        return normalized


class ShopifyVariantOption(_StrictModel):
    name: ShortText
    value: ShortText


class ShopifyProductVariantBrief(_StrictModel):
    variant_ref: PortableRef
    title: ShortText
    price: ShopifyMoney
    sku: (
        Annotated[
            str,
            StringConstraints(min_length=1, max_length=64),
            AfterValidator(_bounded_text),
        ]
        | None
    ) = None
    options: list[ShopifyVariantOption] = Field(default_factory=list, max_length=3)

    @model_validator(mode="after")
    def _unique_option_names(self) -> "ShopifyProductVariantBrief":
        names = [option.name.casefold() for option in self.options]
        if len(names) != len(set(names)):
            raise ValueError("variant option names must be unique")
        return self


class ShopifyProductBrief(_StrictModel):
    product_ref: PortableRef
    title: ShortText
    description: HtmlText | None = None
    vendor: ShortText | None = None
    product_type: ShortText | None = None
    tags: list[ShortText] = Field(default_factory=list, max_length=50)
    price: ShopifyMoney
    variants: list[ShopifyProductVariantBrief] = Field(
        default_factory=list,
        max_length=_MAX_VARIANTS_PER_PRODUCT,
    )

    @model_validator(mode="after")
    def _unique_product_metadata(self) -> "ShopifyProductBrief":
        folded_tags = [tag.casefold() for tag in self.tags]
        if len(folded_tags) != len(set(folded_tags)):
            raise ValueError("product tags must be unique")
        variant_refs = [variant.variant_ref for variant in self.variants]
        if len(variant_refs) != len(set(variant_refs)):
            raise ValueError("variant_ref values must be unique within a product")
        skus = [
            variant.sku.casefold()
            for variant in self.variants
            if variant.sku is not None
        ]
        if len(skus) != len(set(skus)):
            raise ValueError("variant SKU values must be unique within a product")
        return self


class ShopifyPageBrief(_StrictModel):
    page_ref: PortableRef
    title: ShortText
    body_html: HtmlText
    handle: Handle | None = None


class ShopifyCollectionBrief(_StrictModel):
    collection_ref: PortableRef
    title: ShortText
    description_html: HtmlText | None = None
    handle: Handle | None = None
    product_refs: list[PortableRef] = Field(min_length=1, max_length=_MAX_PRODUCTS)

    @field_validator("product_refs")
    @classmethod
    def _unique_product_refs(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("collection product_refs must be unique")
        return values


class ExistingShopifyThemeBrief(_StrictModel):
    strategy: Literal["retain_existing"] = "retain_existing"
    reference_name: ShortText | None = None
    desired_adjustments: list[LongText] = Field(default_factory=list, max_length=20)


class ShopifyStorefrontBrief(_StrictModel):
    storefront_name: ShortText
    brand_summary: LongText
    target_audience: LongText
    business_goal: LongText
    default_currency: Currency
    locale: Locale = "en-US"


class PlanShopifyStorefrontInput(_StrictModel):
    """Business content only; authority, scope, credentials, and actions are absent."""

    brief: ShopifyStorefrontBrief
    products: list[ShopifyProductBrief] = Field(
        min_length=1,
        max_length=_MAX_PRODUCTS,
    )
    collection: ShopifyCollectionBrief
    pages: list[ShopifyPageBrief] = Field(default_factory=list, max_length=_MAX_PAGES)
    existing_theme: ExistingShopifyThemeBrief

    @model_validator(mode="after")
    def _closed_world_references_and_currency(self) -> "PlanShopifyStorefrontInput":
        product_refs = [product.product_ref for product in self.products]
        if len(product_refs) != len(set(product_refs)):
            raise ValueError("product_ref values must be unique")
        product_titles = [product.title.casefold() for product in self.products]
        if len(product_titles) != len(set(product_titles)):
            raise ValueError("product titles must be unique")
        unknown_refs = sorted(set(self.collection.product_refs) - set(product_refs))
        if unknown_refs:
            raise ValueError("collection product_refs must reference declared products")

        page_refs = [page.page_ref for page in self.pages]
        if len(page_refs) != len(set(page_refs)):
            raise ValueError("page_ref values must be unique")
        page_handles = [
            page.handle.casefold() for page in self.pages if page.handle is not None
        ]
        if len(page_handles) != len(set(page_handles)):
            raise ValueError("page handles must be unique")

        currencies = {product.price.currency for product in self.products} | {
            variant.price.currency
            for product in self.products
            for variant in product.variants
        }
        if currencies != {self.brief.default_currency}:
            raise ValueError(
                "all product and variant prices must use brief.default_currency"
            )
        total_variants = sum(len(product.variants) for product in self.products)
        if total_variants > _MAX_TOTAL_VARIANTS:
            raise ValueError(
                f"a storefront plan supports at most {_MAX_TOTAL_VARIANTS} variants"
            )
        return self


class ShopifyCreateProductArguments(_StrictModel):
    title: ShortText
    description: HtmlText | None = None
    vendor: ShortText | None = None
    product_type: ShortText | None = None
    status: Literal["DRAFT"] = "DRAFT"
    tags: list[ShortText] = Field(default_factory=list, max_length=50)
    price: PriceAmount


class ShopifyCreateCollectionArguments(_StrictModel):
    title: ShortText
    description_html: HtmlText | None = None
    handle: Handle | None = None
    publish: Literal[False] = False


class ShopifyCreatePageArguments(_StrictModel):
    title: ShortText
    body_html: HtmlText
    handle: Handle | None = None
    is_published: Literal[False] = False


ProposedArguments = (
    ShopifyCreateProductArguments
    | ShopifyCreateCollectionArguments
    | ShopifyCreatePageArguments
)


class ShopifyOperationBinding(_StrictModel):
    target_argument: Literal["product_ids"]
    source_operation_ids: list[OperationRef] = Field(
        min_length=1,
        max_length=_MAX_PRODUCTS,
    )
    source_output_field: Literal["product_id"] = "product_id"
    cardinality: Literal["list"] = "list"
    resolution_status: Literal["unresolved_until_materialization"] = (
        "unresolved_until_materialization"
    )


class ShopifyProposedOperation(_StrictModel):
    ordinal: int = Field(ge=1, le=_MAX_PRODUCTS + _MAX_PAGES + 1)
    operation_id: OperationRef
    tool: ProposedTool
    effect: Literal["write"] = "write"
    arguments: ProposedArguments
    depends_on: list[OperationRef] = Field(
        default_factory=list, max_length=_MAX_PRODUCTS
    )
    bindings: list[ShopifyOperationBinding] = Field(default_factory=list, max_length=1)
    status: Literal["proposal_only_not_executed"] = "proposal_only_not_executed"
    requires_separate_approval: Literal[True] = True
    approval_unit: OperationRef

    @model_validator(mode="after")
    def _arguments_match_tool(self) -> "ShopifyProposedOperation":
        expected = {
            "ecommerce.create_product": ShopifyCreateProductArguments,
            "shopify.create_collection": ShopifyCreateCollectionArguments,
            "shopify.create_page": ShopifyCreatePageArguments,
        }[self.tool]
        if not isinstance(self.arguments, expected):
            raise ValueError("operation arguments do not match the documented tool")
        if self.tool == "shopify.create_collection":
            if len(self.bindings) != 1:
                raise ValueError("collection creation requires one product_ids binding")
            if self.depends_on != self.bindings[0].source_operation_ids:
                raise ValueError(
                    "collection dependencies must match its product-id binding"
                )
        elif self.bindings or self.depends_on:
            raise ValueError(
                "only collection creation accepts product dependencies or bindings"
            )
        return self


class ShopifyCapabilityGap(_StrictModel):
    code: CapabilityGapCode
    affected_tools: list[ProposedTool] = Field(default_factory=list, max_length=3)
    required_read_tool: Literal["shopify.get_shop_info"] | None = None
    blocks_materialization: Literal[True] = True
    message: LongText


class ShopifyBlockedAction(_StrictModel):
    ordinal: int = Field(ge=1, le=_MAX_PRODUCTS + _MAX_PAGES + 2)
    action_id: OperationRef
    action: Literal[
        "publish_product",
        "publish_collection",
        "publish_page",
        "publish_existing_theme",
    ]
    tool: BlockedGoLiveTool | None
    source_operation_id: OperationRef | None = None
    status: Literal["blocked"] = "blocked"
    reason_codes: list[BlockedReasonCode] = Field(min_length=1, max_length=6)
    requires_separate_approval: Literal[True] = True
    approval_unit: OperationRef
    message: LongText

    @field_validator("reason_codes")
    @classmethod
    def _unique_reason_codes(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("blocked action reason codes must be unique")
        return values


class ShopifyExistingThemeDisposition(_StrictModel):
    strategy: Literal["retain_existing"]
    reference_name: ShortText | None = None
    desired_adjustments: list[LongText] = Field(default_factory=list, max_length=20)
    inventory_read_tool: Literal["shopify.list_themes"] = "shopify.list_themes"
    inventory_read_performed: Literal[False] = False
    custom_theme_creation_supported: Literal[False] = False
    theme_publish_planned: Literal[False] = False


class ShopifyEffectBoundary(_StrictModel):
    connector_calls_made: Literal[0] = 0
    writes_executed: Literal[0] = 0
    resources_created: Literal[0] = 0
    resources_updated: Literal[0] = 0
    resources_published: Literal[0] = 0


class ShopifyStorefrontPlanOutput(_StrictModel):
    schema_id: Literal["lightbulb.shopify_storefront_plan.v1"] = Field(
        default=SHOPIFY_STOREFRONT_PLAN_SCHEMA,
        alias="schema",
    )
    primitive_ref: Literal["commerce.plan_shopify_storefront"] = (
        SHOPIFY_STOREFRONT_PRIMITIVE_REF
    )
    status: Literal["planned_with_blockers"] = "planned_with_blockers"
    proposal_only: Literal[True] = True
    materialization_supported: Literal[False] = False
    live_store_changed: Literal[False] = False
    deployment_guarantee: Literal["none"] = "none"
    storefront_brief: ShopifyStorefrontBrief
    proposed_operations: list[ShopifyProposedOperation] = Field(
        min_length=2,
        max_length=_MAX_PRODUCTS + _MAX_PAGES + 1,
    )
    blocked_actions: list[ShopifyBlockedAction] = Field(
        min_length=3,
        max_length=_MAX_PRODUCTS + _MAX_PAGES + 2,
    )
    capability_gaps: list[ShopifyCapabilityGap] = Field(min_length=3, max_length=4)
    existing_theme: ShopifyExistingThemeDisposition
    effect_boundary: ShopifyEffectBoundary = Field(
        default_factory=ShopifyEffectBoundary
    )
    summary: LongText
    plan_digest: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _parse_plan_input(
    value: PlanShopifyStorefrontInput | Mapping[str, Any],
) -> PlanShopifyStorefrontInput:
    if isinstance(value, PlanShopifyStorefrontInput):
        return value
    try:
        return PlanShopifyStorefrontInput.model_validate(value)
    except ValidationError:
        raise ShopifyStorefrontPlanValidationError(
            "Shopify storefront brief failed closed-world validation"
        ) from None


def _operation_id(ordinal: int, resource: str, reference: str) -> str:
    return f"op_{ordinal:03d}_{resource}_{reference}"


def _approval_unit(prefix: str, reference: str) -> str:
    return f"approval_{prefix}_{reference}"


def _proposed_operations(
    inputs: PlanShopifyStorefrontInput,
) -> tuple[list[ShopifyProposedOperation], dict[str, str], str, dict[str, str]]:
    operations: list[ShopifyProposedOperation] = []
    product_operations: dict[str, str] = {}
    page_operations: dict[str, str] = {}
    ordinal = 1

    for product in inputs.products:
        operation_id = _operation_id(ordinal, "product", product.product_ref)
        product_operations[product.product_ref] = operation_id
        operations.append(
            ShopifyProposedOperation(
                ordinal=ordinal,
                operation_id=operation_id,
                tool="ecommerce.create_product",
                arguments=ShopifyCreateProductArguments(
                    title=product.title,
                    description=product.description,
                    vendor=product.vendor,
                    product_type=product.product_type,
                    status="DRAFT",
                    tags=product.tags,
                    price=f"{product.price.amount:.2f}",
                ),
                approval_unit=_approval_unit("create_product", product.product_ref),
            )
        )
        ordinal += 1

    collection_operation = _operation_id(
        ordinal,
        "collection",
        inputs.collection.collection_ref,
    )
    operations.append(
        ShopifyProposedOperation(
            ordinal=ordinal,
            operation_id=collection_operation,
            tool="shopify.create_collection",
            arguments=ShopifyCreateCollectionArguments(
                title=inputs.collection.title,
                description_html=inputs.collection.description_html,
                handle=inputs.collection.handle,
                publish=False,
            ),
            depends_on=[
                product_operations[product_ref]
                for product_ref in inputs.collection.product_refs
            ],
            bindings=[
                ShopifyOperationBinding(
                    target_argument="product_ids",
                    source_operation_ids=[
                        product_operations[product_ref]
                        for product_ref in inputs.collection.product_refs
                    ],
                )
            ],
            approval_unit=_approval_unit(
                "create_collection",
                inputs.collection.collection_ref,
            ),
        )
    )
    ordinal += 1

    for page in inputs.pages:
        operation_id = _operation_id(ordinal, "page", page.page_ref)
        page_operations[page.page_ref] = operation_id
        operations.append(
            ShopifyProposedOperation(
                ordinal=ordinal,
                operation_id=operation_id,
                tool="shopify.create_page",
                arguments=ShopifyCreatePageArguments(
                    title=page.title,
                    body_html=page.body_html,
                    handle=page.handle,
                    is_published=False,
                ),
                approval_unit=_approval_unit("create_page", page.page_ref),
            )
        )
        ordinal += 1

    return operations, product_operations, collection_operation, page_operations


def _blocked_actions(
    inputs: PlanShopifyStorefrontInput,
    *,
    product_operations: Mapping[str, str],
    collection_operation: str,
    page_operations: Mapping[str, str],
) -> list[ShopifyBlockedAction]:
    actions: list[ShopifyBlockedAction] = []
    ordinal = 1
    for product in inputs.products:
        reason_codes: list[BlockedReasonCode] = [
            "governed_connector_write_custody_unavailable",
            "materialized_resource_id_unavailable",
            "separate_go_live_approval_required",
        ]
        if product.variants:
            reason_codes.insert(1, "typed_create_product_variant_gap")
        actions.append(
            ShopifyBlockedAction(
                ordinal=ordinal,
                action_id=f"blocked_{ordinal:03d}_publish_{product.product_ref}",
                action="publish_product",
                tool="shopify.publish_product",
                source_operation_id=product_operations[product.product_ref],
                reason_codes=reason_codes,
                approval_unit=_approval_unit(
                    "publish_product",
                    product.product_ref,
                ),
                message=(
                    "Product publication is blocked: no materialized product ID "
                    "exists and publication requires separate governed approval."
                    + (
                        " Additional requested variants are not represented by "
                        "the typed create-product operation."
                        if product.variants
                        else ""
                    )
                ),
            )
        )
        ordinal += 1

    actions.append(
        ShopifyBlockedAction(
            ordinal=ordinal,
            action_id=f"blocked_{ordinal:03d}_publish_{inputs.collection.collection_ref}",
            action="publish_collection",
            tool=None,
            source_operation_id=collection_operation,
            reason_codes=[
                "governed_connector_write_custody_unavailable",
                "collection_publish_after_creation_tool_unavailable",
                "materialized_resource_id_unavailable",
                "separate_go_live_approval_required",
            ],
            approval_unit=_approval_unit(
                "publish_collection",
                inputs.collection.collection_ref,
            ),
            message=(
                "Collection publication is blocked. The documented create tool "
                "can create it unpublished, but no typed tool publishes that "
                "existing collection later."
            ),
        )
    )
    ordinal += 1

    for page in inputs.pages:
        actions.append(
            ShopifyBlockedAction(
                ordinal=ordinal,
                action_id=f"blocked_{ordinal:03d}_publish_{page.page_ref}",
                action="publish_page",
                tool="shopify.update_page",
                source_operation_id=page_operations[page.page_ref],
                reason_codes=[
                    "governed_connector_write_custody_unavailable",
                    "materialized_resource_id_unavailable",
                    "separate_go_live_approval_required",
                ],
                approval_unit=_approval_unit("publish_page", page.page_ref),
                message=(
                    "Page publication is blocked until an unpublished page exists, "
                    "its ID is observed, and a separate governed approval is available."
                ),
            )
        )
        ordinal += 1

    actions.append(
        ShopifyBlockedAction(
            ordinal=ordinal,
            action_id=f"blocked_{ordinal:03d}_publish_existing_theme",
            action="publish_existing_theme",
            tool="shopify.publish_theme",
            reason_codes=[
                "governed_connector_write_custody_unavailable",
                "existing_theme_id_unresolved",
                "separate_go_live_approval_required",
            ],
            approval_unit=_approval_unit("publish_theme", "existing"),
            message=(
                "Existing-theme publication is blocked. This planner accepts no "
                "theme ID, performs no theme inventory read, and cannot consume "
                "governed write approval."
            ),
        )
    )
    return actions


def _capability_gaps(
    proposed_tools: list[ProposedTool],
    inputs: PlanShopifyStorefrontInput,
) -> list[ShopifyCapabilityGap]:
    gaps = [
        ShopifyCapabilityGap(
            code="governed_connector_write_custody_unavailable",
            affected_tools=list(dict.fromkeys(proposed_tools)),
            message=(
                "Governed connector write custody is staged but unavailable to "
                "this SDK primitive; proposed operations cannot be materialized."
            ),
        ),
        ShopifyCapabilityGap(
            code="custom_theme_creation_tool_unavailable",
            affected_tools=[],
            message=(
                "No documented Shopify tool creates, uploads, or edits a custom "
                "theme. Only existing-theme inventory and publication tools exist."
            ),
        ),
        ShopifyCapabilityGap(
            code="connected_shop_currency_unverified",
            affected_tools=["ecommerce.create_product"],
            required_read_tool="shopify.get_shop_info",
            message=(
                "The proposal preserves the requested storefront currency, but "
                "the connected Shopify shop currency was not read or verified. "
                "Materialization must verify it before applying default-variant prices."
            ),
        ),
    ]
    if any(product.variants for product in inputs.products):
        gaps.append(
            ShopifyCapabilityGap(
                code="typed_create_product_variant_gap",
                affected_tools=["ecommerce.create_product"],
                message=(
                    "The ecommerce.create_product adapter and typed SDK descriptor "
                    "support the default variant price, but not creation of the "
                    "additional requested variants."
                ),
            )
        )
    return gaps


def plan_shopify_storefront(
    value: PlanShopifyStorefrontInput | Mapping[str, Any],
) -> ShopifyStorefrontPlanOutput:
    """Compile a deterministic storefront proposal with zero connector effects."""

    inputs = _parse_plan_input(value)
    (
        operations,
        product_operations,
        collection_operation,
        page_operations,
    ) = _proposed_operations(inputs)
    blocked_actions = _blocked_actions(
        inputs,
        product_operations=product_operations,
        collection_operation=collection_operation,
        page_operations=page_operations,
    )
    gaps = _capability_gaps(
        [operation.tool for operation in operations],
        inputs,
    )
    theme = ShopifyExistingThemeDisposition(
        strategy=inputs.existing_theme.strategy,
        reference_name=inputs.existing_theme.reference_name,
        desired_adjustments=inputs.existing_theme.desired_adjustments,
    )
    core = {
        "schema": SHOPIFY_STOREFRONT_PLAN_SCHEMA,
        "primitive_ref": SHOPIFY_STOREFRONT_PRIMITIVE_REF,
        "status": "planned_with_blockers",
        "proposal_only": True,
        "materialization_supported": False,
        "live_store_changed": False,
        "deployment_guarantee": "none",
        "storefront_brief": inputs.brief.model_dump(mode="json"),
        "proposed_operations": [
            operation.model_dump(mode="json", exclude_none=True)
            for operation in operations
        ],
        "blocked_actions": [
            action.model_dump(mode="json", exclude_none=True)
            for action in blocked_actions
        ],
        "capability_gaps": [
            gap.model_dump(mode="json", exclude_none=True) for gap in gaps
        ],
        "existing_theme": theme.model_dump(mode="json", exclude_none=True),
        "effect_boundary": ShopifyEffectBoundary().model_dump(mode="json"),
        "summary": (
            f"Prepared {len(operations)} ordered proposal-only operation(s). "
            "No connector was called, no live store changed, and no deployment "
            "is guaranteed."
        ),
    }
    plan_digest = hashlib.sha256(
        json.dumps(
            core,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    return ShopifyStorefrontPlanOutput(
        storefront_brief=inputs.brief,
        proposed_operations=operations,
        blocked_actions=blocked_actions,
        capability_gaps=gaps,
        existing_theme=theme,
        summary=core["summary"],
        plan_digest=plan_digest,
    )


class PlanShopifyStorefrontPrimitive(
    BusinessProcessPrimitive[
        PlanShopifyStorefrontInput,
        ShopifyStorefrontPlanOutput,
    ]
):
    """Plan a draft Shopify storefront without reading or changing a shop."""

    primitive_ref = SHOPIFY_STOREFRONT_PRIMITIVE_REF
    version = "1.0.0"
    title = "Plan Shopify storefront"
    description = (
        "Compile a typed, deterministic proposal for draft Shopify products, "
        "an unpublished collection, and unpublished pages without connector calls."
    )
    input_model = PlanShopifyStorefrontInput
    output_model = ShopifyStorefrontPlanOutput
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "brief": {
            "storefront_name": "North Star Goods",
            "brand_summary": "Practical tools for focused teams.",
            "target_audience": "Small professional-services teams.",
            "business_goal": "Prepare a reviewable storefront proposal.",
            "default_currency": "CAD",
            "locale": "en-CA",
        },
        "products": [
            {
                "product_ref": "focus-kit",
                "title": "Focus Kit",
                "description": "<p>A practical planning kit.</p>",
                "vendor": "North Star Goods",
                "product_type": "Planning kit",
                "tags": ["planning", "teams"],
                "price": {"amount": "49.00", "currency": "CAD"},
            }
        ],
        "collection": {
            "collection_ref": "featured",
            "title": "Featured",
            "product_refs": ["focus-kit"],
        },
        "pages": [
            {
                "page_ref": "about",
                "title": "About",
                "body_html": "<p>About North Star Goods.</p>",
                "handle": "about",
            }
        ],
        "existing_theme": {
            "strategy": "retain_existing",
            "reference_name": "Current storefront theme",
            "desired_adjustments": ["Use the supplied brand copy and imagery."],
        },
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PlanShopifyStorefrontInput,
    ) -> PrimitiveExecutionResult[ShopifyStorefrontPlanOutput]:
        output = plan_shopify_storefront(inputs)
        return PrimitiveExecutionResult[ShopifyStorefrontPlanOutput](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=output.summary,
            output=output,
            events=[
                PrimitiveEvent(
                    type="commerce.shopify_storefront_proposal_compiled",
                    payload={
                        "plan_digest": output.plan_digest,
                        "proposed_operation_count": len(output.proposed_operations),
                        "blocked_action_count": len(output.blocked_actions),
                        "live_store_changed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="proposal",
                    summary=(
                        "The SDK compiled a local storefront proposal without "
                        "resolving or invoking a connector."
                    ),
                )
            ],
        )


__all__ = [
    "SHOPIFY_BLOCKED_GO_LIVE_TOOLS",
    "SHOPIFY_PROPOSAL_TOOLS",
    "SHOPIFY_STOREFRONT_PLAN_SCHEMA",
    "SHOPIFY_STOREFRONT_PRIMITIVE_REF",
    "ExistingShopifyThemeBrief",
    "PlanShopifyStorefrontInput",
    "PlanShopifyStorefrontPrimitive",
    "ShopifyBlockedAction",
    "ShopifyCapabilityGap",
    "ShopifyCollectionBrief",
    "ShopifyEffectBoundary",
    "ShopifyMoney",
    "ShopifyPageBrief",
    "ShopifyProductBrief",
    "ShopifyProductVariantBrief",
    "ShopifyProposedOperation",
    "ShopifyStorefrontBrief",
    "ShopifyStorefrontPlanOutput",
    "ShopifyStorefrontPlanValidationError",
    "ShopifyVariantOption",
    "plan_shopify_storefront",
]
