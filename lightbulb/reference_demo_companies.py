"""Realistic, non-sensitive demo instances of the reference Company Blueprint.

These are effect-dark provisioning inputs, not claims that a company was operated.
They prove that one canonical Blueprint can be instantiated repeatedly with a
complete ten-stage spine, without inventing connector or coding-harness authority.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator

from lightbulb.company_blueprints import EconomicSpineStage
from lightbulb.reference_company_blueprints import AI_NATIVE_SERVICES_STUDIO_BLUEPRINT


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, serialize_by_alias=True)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class DemoEconomicSpineInput(_StrictModel):
    stage: EconomicSpineStage
    synthetic_trigger_ref: str = Field(
        pattern=r"^demo:[a-z0-9][a-z0-9._:-]{0,119}$"
    )
    fixture_record_ref: str = Field(
        pattern=r"^demo-record:[a-z0-9][a-z0-9._:-]{0,159}$"
    )
    input_summary: str = Field(min_length=20, max_length=320)
    required_input_artifact_refs: tuple[str, ...] = Field(min_length=1, max_length=20)
    expected_terminal_artifact_ref: str = Field(min_length=1, max_length=200)
    expected_evidence_kind: str = Field(min_length=1, max_length=200)
    business_values: Mapping[str, str | int | bool] = Field(
        min_length=4, max_length=16
    )
    fixture_sha256: str = Field(default="", pattern=r"^(?:[0-9a-f]{64})?$")
    contains_personal_data: Literal[False] = False
    authorizes_external_effect: Literal[False] = False

    @field_serializer("business_values")
    def _serialize_business_values(
        self, value: Mapping[str, str | int | bool]
    ) -> dict[str, str | int | bool]:
        return dict(value)

    @model_validator(mode="after")
    def _fixture_is_bounded_and_secret_free(self) -> "DemoEconomicSpineInput":
        forbidden_keys = ("secret", "password", "credential", "api_key", "token")
        for key, value in self.business_values.items():
            normalized_key = key.strip().lower()
            if not normalized_key or any(marker in normalized_key for marker in forbidden_keys):
                raise ValueError("demo business_values cannot contain credential fields")
            if isinstance(value, str):
                if value != value.strip() or not value or len(value) > 240:
                    raise ValueError("demo business value strings must be bounded")
                if "@" in value:
                    raise ValueError("demo business values cannot contain email addresses")
        payload = self.model_dump(mode="json", exclude={"fixture_sha256"})
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if self.fixture_sha256 and self.fixture_sha256 != digest:
            raise ValueError("fixture_sha256 must bind the exact stage fixture")
        object.__setattr__(
            self, "business_values", MappingProxyType(dict(self.business_values))
        )
        object.__setattr__(self, "fixture_sha256", digest)
        return self


class ReferenceDemoCompany(_StrictModel):
    schema_id: Literal["lightbulb.reference_demo_company.v1"] = Field(
        default="lightbulb.reference_demo_company.v1", alias="schema"
    )
    demo_company_ref: str = Field(pattern=r"^demo-company:[a-z0-9][a-z0-9._-]{0,79}$")
    display_name: str = Field(min_length=1, max_length=120)
    scenario: str = Field(min_length=1, max_length=500)
    blueprint_ref: Literal["company.ai_native_services_studio"] = (
        "company.ai_native_services_studio"
    )
    blueprint_version: Literal["0.7.0"] = "0.7.0"
    blueprint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    economic_spine_inputs: tuple[DemoEconomicSpineInput, ...] = Field(
        min_length=10, max_length=10
    )
    preview_only: Literal[True] = True
    credentials_embedded: Literal[False] = False
    personal_data_embedded: Literal[False] = False
    external_effects_authorized: Literal[False] = False
    company_operated: Literal[False] = False
    scenario_digest: str = Field(default="", pattern=r"^(?:[0-9a-f]{64})?$")

    @model_validator(mode="after")
    def _exact_blueprint_instance(self) -> "ReferenceDemoCompany":
        blueprint = AI_NATIVE_SERVICES_STUDIO_BLUEPRINT
        if self.blueprint_version != blueprint.version:
            raise ValueError("demo company must bind the exact Blueprint version")
        if self.blueprint_digest != blueprint.blueprint_digest:
            raise ValueError("demo company must bind the exact reference Blueprint")
        expected_stages = tuple(stage.stage for stage in blueprint.economic_spine.stages)
        actual_stages = tuple(item.stage for item in self.economic_spine_inputs)
        if actual_stages != expected_stages:
            raise ValueError("demo company must cover the exact ten-stage economic spine")
        expected_artifacts = tuple(
            stage.terminal_outcome_ref for stage in blueprint.economic_spine.stages
        )
        actual_artifacts = tuple(
            item.expected_terminal_artifact_ref for item in self.economic_spine_inputs
        )
        if actual_artifacts != expected_artifacts:
            raise ValueError("demo company terminal artifacts drift from the Blueprint")
        expected_inputs = tuple(
            stage.required_artifact_refs for stage in blueprint.economic_spine.stages
        )
        actual_inputs = tuple(
            item.required_input_artifact_refs for item in self.economic_spine_inputs
        )
        if actual_inputs != expected_inputs:
            raise ValueError("demo company inputs drift from the Blueprint")
        expected_evidence = tuple(
            stage.required_evidence_kind for stage in blueprint.economic_spine.stages
        )
        actual_evidence = tuple(
            item.expected_evidence_kind for item in self.economic_spine_inputs
        )
        if actual_evidence != expected_evidence:
            raise ValueError("demo company evidence kinds drift from the Blueprint")
        fixture_digests = tuple(item.fixture_sha256 for item in self.economic_spine_inputs)
        if len(set(fixture_digests)) != len(fixture_digests):
            raise ValueError("every demo stage must have distinct source-bound fixture data")
        payload = self.model_dump(mode="json", by_alias=True, exclude={"scenario_digest"})
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if self.scenario_digest and self.scenario_digest != digest:
            raise ValueError("scenario_digest must bind the exact demo company")
        object.__setattr__(self, "scenario_digest", digest)
        return self


def _fixture_digest(slug: str, label: str) -> str:
    return hashlib.sha256(f"lightbulb-demo:{slug}:{label}".encode()).hexdigest()


_DEMO_COMPANY_FACTS: dict[str, dict[str, str | int]] = {
    "northstar": {
        "customer_ref": "demo-customer:alder-legal-operations",
        "opportunity_ref": "demo-opportunity:northstar-alder-2026q3",
        "agreement_ref": "demo-agreement:northstar-1042",
        "invoice_ref": "demo-invoice:ns-1042",
        "cash_ref": "demo-settlement:ns-1042",
        "case_ref": "demo-case:ns-731",
        "supplier_ref": "demo-supplier:harbor-cloud-hosting",
        "purchase_order_ref": "demo-po:ns-209",
        "period": "2026-07",
        "currency": "AUD",
        "contract_value_minor": 1_850_000,
        "supplier_value_minor": 129_900,
        "delivery_criteria": 9,
    },
    "harbor": {
        "customer_ref": "demo-customer:cedar-community-services",
        "opportunity_ref": "demo-opportunity:harbor-cedar-2026q3",
        "agreement_ref": "demo-agreement:harbor-2088",
        "invoice_ref": "demo-invoice:hb-2088",
        "cash_ref": "demo-settlement:hb-2088",
        "case_ref": "demo-case:hb-882",
        "supplier_ref": "demo-supplier:meridian-data-quality",
        "purchase_order_ref": "demo-po:hb-318",
        "period": "2026-07",
        "currency": "AUD",
        "contract_value_minor": 2_740_000,
        "supplier_value_minor": 248_000,
        "delivery_criteria": 12,
    },
    "beacon": {
        "customer_ref": "demo-customer:elm-field-services",
        "opportunity_ref": "demo-opportunity:beacon-elm-2026q3",
        "agreement_ref": "demo-agreement:beacon-3017",
        "invoice_ref": "demo-invoice:bc-3017",
        "cash_ref": "demo-settlement:bc-3017",
        "case_ref": "demo-case:bc-954",
        "supplier_ref": "demo-supplier:summit-service-desk",
        "purchase_order_ref": "demo-po:bc-427",
        "period": "2026-07",
        "currency": "AUD",
        "contract_value_minor": 1_260_000,
        "supplier_value_minor": 86_500,
        "delivery_criteria": 7,
    },
}


def _stage_business_values(
    slug: str, stage: EconomicSpineStage
) -> dict[str, str | int | bool]:
    facts = _DEMO_COMPANY_FACTS[slug]
    common = {
        "customer_ref": str(facts["customer_ref"]),
        "currency": str(facts["currency"]),
    }
    by_stage: dict[EconomicSpineStage, dict[str, str | int | bool]] = {
        EconomicSpineStage.ACQUIRE_DEMAND: {
            **common,
            "opportunity_ref": str(facts["opportunity_ref"]),
            "crm_lead_ref": f"demo-crm-lead:{slug}-001",
            "inbound_reply_ref": f"demo-reply:{slug}-qualified-interest",
            "reply_causally_matched": True,
        },
        EconomicSpineStage.AGREE_WORK: {
            **common,
            "agreement_ref": str(facts["agreement_ref"]),
            "signed_document_sha256": _fixture_digest(slug, "signed-agreement"),
            "contract_value_minor": int(facts["contract_value_minor"]),
            "agreement_effective": True,
        },
        EconomicSpineStage.DELIVER_VALUE: {
            **common,
            "work_packet_ref": f"demo-work-packet:{slug}-delivery-01",
            "repository_ref": f"demo-repository:{slug}-company-automation",
            "artifact_package_ref": f"demo-artifact-package:{slug}-01",
            "acceptance_criteria_count": int(facts["delivery_criteria"]),
        },
        EconomicSpineStage.ACCEPT_VALUE: {
            **common,
            "work_packet_ref": f"demo-work-packet:{slug}-delivery-01",
            "evaluator_run_ref": f"demo-evaluator:{slug}-independent-01",
            "acceptance_contract_sha256": _fixture_digest(slug, "acceptance-contract"),
            "evaluator_score_basis_points": 9_400,
            "independent_verdict": "accepted",
        },
        EconomicSpineStage.INVOICE_CUSTOMER: {
            **common,
            "agreement_ref": str(facts["agreement_ref"]),
            "invoice_ref": str(facts["invoice_ref"]),
            "invoice_amount_minor": int(facts["contract_value_minor"]),
            "provider_readback_matched": True,
        },
        EconomicSpineStage.COLLECT_CASH: {
            **common,
            "invoice_ref": str(facts["invoice_ref"]),
            "settlement_ref": str(facts["cash_ref"]),
            "settled_amount_minor": int(facts["contract_value_minor"]),
            "provider_settlement_matched": True,
        },
        EconomicSpineStage.SUPPORT_CUSTOMER: {
            **common,
            "service_case_ref": str(facts["case_ref"]),
            "customer_confirmation_ref": f"demo-confirmation:{slug}-resolved",
            "provider_status": "closed",
            "closure_readback_matched": True,
        },
        EconomicSpineStage.CONTROL_SPEND: {
            "supplier_ref": str(facts["supplier_ref"]),
            "purchase_order_ref": str(facts["purchase_order_ref"]),
            "currency": str(facts["currency"]),
            "gross_amount_minor": int(facts["supplier_value_minor"]),
            "goods_receipt_ref": f"demo-goods-receipt:{slug}-01",
            "supplier_invoice_ref": f"demo-supplier-invoice:{slug}-01",
            "three_way_match": "matched",
        },
        EconomicSpineStage.RECONCILE_BOOKS: {
            "accounting_period": str(facts["period"]),
            "report_bundle_ref": f"demo-report-bundle:{slug}-2026-07",
            "report_count": 5,
            "unexplained_variance_minor": 0,
            "close_candidate_approval_ref": f"demo-approval:{slug}-close-candidate",
        },
        EconomicSpineStage.IMPROVE_FROM_EVIDENCE: {
            "measurement_set_ref": f"demo-measurements:{slug}-outcomes-01",
            "improvement_work_packet_ref": f"demo-work-packet:{slug}-improvement-01",
            "independent_evaluator_ref": f"demo-evaluator:{slug}-improvement-01",
            "staging_canary_result": "passed",
            "publication_candidate_ref": f"demo-publication-candidate:{slug}-01",
            "published": False,
        },
    }
    return by_stage[stage]


def _spine_inputs(slug: str) -> tuple[DemoEconomicSpineInput, ...]:
    return tuple(
        DemoEconomicSpineInput(
            stage=binding.stage,
            synthetic_trigger_ref=f"demo:{slug}:{binding.stage.value}",
            fixture_record_ref=f"demo-record:{slug}:{binding.stage.value}:v1",
            input_summary=(
                f"Synthetic {binding.stage.value.replace('_', ' ')} fixture for the "
                f"{slug} effect-dark company rehearsal; no provider operation is authorized."
            ),
            required_input_artifact_refs=binding.required_artifact_refs,
            expected_terminal_artifact_ref=binding.terminal_outcome_ref,
            expected_evidence_kind=binding.required_evidence_kind,
            business_values=_stage_business_values(slug, binding.stage),
        )
        for binding in AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.economic_spine.stages
    )


REFERENCE_DEMO_COMPANIES = (
    ReferenceDemoCompany(
        demo_company_ref="demo-company:northstar-revops-studio",
        display_name="Northstar RevOps Studio",
        scenario=(
            "A five-person AI-native revenue-operations studio acquiring demand, "
            "delivering accepted automation work, collecting cash, and supporting clients."
        ),
        blueprint_digest=AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.blueprint_digest,
        economic_spine_inputs=_spine_inputs("northstar"),
    ),
    ReferenceDemoCompany(
        demo_company_ref="demo-company:harbor-finance-ops",
        display_name="Harbor Finance Operations",
        scenario=(
            "An AI-native finance-operations company emphasizing contract-to-cash, "
            "controlled procurement, reconciliation, and evidence-led improvement."
        ),
        blueprint_digest=AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.blueprint_digest,
        economic_spine_inputs=_spine_inputs("harbor"),
    ),
    ReferenceDemoCompany(
        demo_company_ref="demo-company:beacon-customer-operations",
        display_name="Beacon Customer Operations",
        scenario=(
            "An AI-native customer-operations partner coupling verified service outcomes "
            "to revenue, accounting, spend control, and governed software improvements."
        ),
        blueprint_digest=AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.blueprint_digest,
        economic_spine_inputs=_spine_inputs("beacon"),
    ),
)

__all__ = [
    "DemoEconomicSpineInput",
    "REFERENCE_DEMO_COMPANIES",
    "ReferenceDemoCompany",
]
