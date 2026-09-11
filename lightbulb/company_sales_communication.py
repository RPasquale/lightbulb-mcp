"""Exact sales-touch proposals and evidence from the canonical Communication authority.

The adapter never invokes a provider. A sent result requires a bound, successful
execution journal and approved source; a run's lifecycle status is insufficient.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from lightbulb.company_engine_core import OpaqueRef, Sha256Digest, detached, seal, timestamp
from lightbulb.company_execution_bridge import ExecutionReceipt, bind_execution
from lightbulb.pipeline_execution import TouchRequest


class SalesCommunicationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _sales_proposal(value: Mapping[str, Any], idempotency_key: str) -> dict[str, Any]:
    payload = detached(dict(value))
    required = {"binding", "touch", "allow_dispatch", "expected_state_version", "expected_state_digest", "plan_digest"}
    if set(payload) != required or not isinstance(payload["allow_dispatch"], bool):
        raise SalesCommunicationError("SALES_PROPOSAL_INVALID", "sales proposal fields are invalid")
    touch = TouchRequest.model_validate(payload["touch"])
    if idempotency_key != "sales:" + touch.request_digest:
        raise SalesCommunicationError("SALES_IDEMPOTENCY_INVALID", "sales idempotency differs from the exact touch")
    if (not isinstance(payload["binding"], dict) or set(payload["binding"]) != set(_BINDING_FIELDS)
            or type(payload["expected_state_version"]) is not int
            or not 1 <= payload["expected_state_version"] <= 10000):
        raise SalesCommunicationError("SALES_PROPOSAL_INVALID", "sales proposal authority binding is invalid")
    import re
    for name in ("expected_state_digest", "plan_digest"):
        if not isinstance(payload[name], str) or not re.fullmatch(r"[a-f0-9]{64}", payload[name]):
            raise SalesCommunicationError("SALES_PROPOSAL_INVALID", "sales proposal state commitment is invalid")
    return payload


def _sales_result(value: Any, touch_digest: str) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or value.get("schema") != "lightbulb.communication_sales_touch_result.v1"
            or value.get("status") not in {"pending_approval", "admitted", "pending", "sent", "blocked", "stopped"}
            or value.get("touch_request_digest") != touch_digest):
        raise SalesCommunicationError("SALES_RESULT_INVALID", "sales communication returned an invalid result")
    if value["status"] == "sent":
        effect = SalesTouchEffect.model_validate(value.get("effect"))
        if (effect.touch_request_digest != touch_digest or effect.source_ref != value.get("source_ref")
                or effect.run_ref != value.get("run_ref") or effect.completed_at != value.get("completed_at")):
            raise SalesCommunicationError("SALES_EFFECT_RESULT_MISMATCH", "sales result differs from its execution evidence")
    return detached(value)


class SalesTouchEffect(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, populate_by_name=True,
                              serialize_by_alias=True, allow_inf_nan=False)
    schema_id: Literal["lightbulb.communication_sales_touch_effect.v1"] = Field(
        default="lightbulb.communication_sales_touch_effect.v1", alias="schema")
    tenant_id: str
    company_id: str
    user_id: str
    project_id: str
    project_ref: OpaqueRef
    binding_ref: OpaqueRef
    prospect_ref: OpaqueRef
    account_ref: OpaqueRef
    sequence_ref: OpaqueRef
    step: int = Field(ge=1, le=20)
    touch_request_digest: Sha256Digest
    source_ref: str = Field(pattern=r"^gcs_v1_[a-f0-9]{64}$")
    source_commitment_digest: Sha256Digest
    run_ref: str = Field(pattern=r"^gcr_[a-f0-9]{32}$")
    tool: Literal["gmail.send_email"]
    effect: Literal["write"]
    journal_ref: OpaqueRef
    request_digest: Sha256Digest
    receipt_digest: Sha256Digest
    route_digest: Sha256Digest
    connector_account_ref: OpaqueRef
    approval_ref: OpaqueRef
    approval_receipt_digest: Sha256Digest
    completed_at: str
    output_digest: Sha256Digest

    @field_validator("tenant_id", "company_id", "user_id", "project_id")
    @classmethod
    def _uuid(cls, value: str) -> str:
        if str(UUID(value)) != value:
            raise ValueError("sales evidence scope UUIDs must be canonical")
        return value

    @field_validator("completed_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return timestamp(value, field_name="completed_at")

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


_BINDING_FIELDS = (
    "binding_ref", "prospect_ref", "account_ref", "connector_account_ref",
    "crm_contact_id", "crm_conversation_id", "crm_channel_identity_id",
    "to_address", "from_address", "thread_ref", "parent_message_id", "purpose",
    "permission_entity_ref", "endpoint_digest",
)


def _mapping(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    elif hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", by_alias=True)
    if not isinstance(value, Mapping):
        raise ValueError("sales communication requires a structured binding")
    return dict(detached(value))


def _effect(touch: TouchRequest, result: Mapping[str, Any], *, binding: Any,
            scope: Mapping[str, Any]) -> SalesTouchEffect:
    if result.get("status") != "sent" or not isinstance(result.get("effect"), Mapping):
        raise SalesCommunicationError("SALES_EFFECT_MISSING", "a sales touch requires actual sent execution evidence")
    try:
        effect = SalesTouchEffect.model_validate(dict(result["effect"]))
    except ValueError as error:
        raise SalesCommunicationError("SALES_EFFECT_INVALID", "sales execution evidence is invalid") from error
    bound = _mapping(binding)
    expected = {
        "tenant_id": str(scope["tenant_id"]), "company_id": str(scope["company_id"]),
        "user_id": str(scope["user_id"]), "project_id": str(scope["project_id"]),
        "project_ref": str(scope["project_ref"]), "binding_ref": bound["binding_ref"],
        "prospect_ref": touch.prospect_ref, "account_ref": bound["account_ref"],
        "connector_account_ref": bound["connector_account_ref"],
        "sequence_ref": touch.sequence_ref, "step": touch.step,
        "touch_request_digest": touch.request_digest,
    }
    if any(getattr(effect, key) != value for key, value in expected.items()):
        raise SalesCommunicationError("SALES_EFFECT_SCOPE_MISMATCH", "sales effect differs from the frozen touch or exact scope")
    if bound["prospect_ref"] != touch.prospect_ref or touch.tool != effect.tool:
        raise SalesCommunicationError("SALES_TOUCH_BINDING_MISMATCH", "sales binding differs from the exact touch")
    if (result.get("source_ref") != effect.source_ref
            or result.get("run_ref") != effect.run_ref
            or timestamp(str(result.get("completed_at")), field_name="completed_at") != effect.completed_at):
        raise SalesCommunicationError("SALES_EFFECT_RESULT_MISMATCH", "sales result differs from its execution evidence")
    return effect


def sales_touch_receipt(touch: TouchRequest | Mapping[str, Any], result: Mapping[str, Any],
                        *, binding: Any, scope: Mapping[str, Any]) -> dict[str, Any]:
    """Bind authenticated source/journal evidence to its original pipeline request.

    The source commits the original touch; the execution request separately
    commits the server's approval and custody fields. Neither is rebased.
    """
    parsed = TouchRequest.model_validate(_mapping(touch))
    effect = _effect(parsed, result, binding=binding, scope=scope)
    fields = effect.to_dict()
    receipt = seal(ExecutionReceipt, {key: fields[key] for key in (
        "tool", "effect", "journal_ref", "request_digest", "receipt_digest", "route_digest",
        "connector_account_ref", "project_id", "approval_ref", "approval_receipt_digest",
        "completed_at", "output_digest",
    )}, "execution_digest")
    return bind_execution(receipt, engine="pipeline_engine", event="touch",
                          fields=parsed.receipt_fields()).receipt_fields


class HostedSalesCommunication:
    """Synchronous, scoped client over Communication sales proposal/approval runs."""

    def __init__(self, client: Any, company_id: str, *, authority_scope: Any = None) -> None:
        self.client = client
        self.company_id = str(UUID(str(company_id)))
        self.authority_scope = None if authority_scope is None else _mapping(authority_scope)

    def step(self, binding: Any, touch: TouchRequest | Mapping[str, Any], *,
             state: Mapping[str, Any], now: str, allow_dispatch: bool = True) -> dict[str, Any]:
        parsed = TouchRequest.model_validate(_mapping(touch))
        bound = _mapping(binding)
        state_value = _mapping(state)
        engine_scope = _mapping(state_value.get("scope", state_value))
        if self.authority_scope is None:
            raise SalesCommunicationError("SALES_AUTHORITY_REQUIRED", "sales communication requires authenticated authority_scope")
        scope = dict(self.authority_scope)
        if (str(engine_scope.get("project_ref")) != str(scope.get("project_ref"))
                or not engine_scope.get("project_id")
                or (scope.get("project_id") is not None
                    and str(scope["project_id"]) != str(engine_scope["project_id"]))):
            raise SalesCommunicationError("SALES_PROJECT_SCOPE_MISMATCH", "sales engine project differs from authenticated authority")
        scope["project_id"] = str(engine_scope["project_id"])
        for field in ("tenant_id", "company_id", "user_id", "project_id", "project_ref"):
            if not scope.get(field):
                raise SalesCommunicationError("SALES_AUTHORITY_REQUIRED", f"sales communication state requires exact scope.{field}")
        if str(scope["company_id"]) != self.company_id:
            raise SalesCommunicationError("SALES_COMPANY_SCOPE_MISMATCH", "sales communication company differs from the worker")
        if str(scope["tenant_id"]) != str(self.client._auth.tenant_id):
            raise SalesCommunicationError("SALES_TENANT_SCOPE_MISMATCH", "sales communication tenant differs from authentication")
        project_id = str(UUID(str(scope["project_id"])))
        if not isinstance(allow_dispatch, bool):
            raise ValueError("allow_dispatch must be boolean")
        timestamp(now, field_name="now")
        proposal = {key: bound.get(key) for key in _BINDING_FIELDS}
        if any(proposal.get(key) is None for key in _BINDING_FIELDS):
            raise SalesCommunicationError("SALES_CRM_BINDING_REQUIRED", "sales communication requires exact CRM and existing-thread bindings")
        value = self.client.step_governed_sales_touch(project_id,
            {"binding": proposal, "touch": parsed.to_dict(), "allow_dispatch": allow_dispatch,
                  "expected_state_version": state_value["version"],
                  "expected_state_digest": state_value["state_digest"], "plan_digest": state_value["plan_digest"]},
            company_id=self.company_id, idempotency_key="sales:" + parsed.request_digest)
        if value["status"] == "sent":
            _effect(parsed, value, binding=bound, scope=scope)
        return value


__all__ = ["HostedSalesCommunication", "SalesCommunicationError", "SalesTouchEffect", "sales_touch_receipt"]
