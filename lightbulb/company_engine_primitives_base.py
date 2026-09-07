"""Shared primitive scaffolding for the company engine packs.

Every engine primitive is read-only, PREVIEW-only, scope-fenced, and carries an
operation contract; the runtime scope and acting actor must match the request
exactly whenever the runtime asserts them.  Effects belong to Spring and the
Connector Runtime.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from copy import deepcopy
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from lightbulb.company_engine_core import EngineScope, OpaqueRef, StrictModel, canonical_uuid
from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationReceipt,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
    PrimitiveOperationStatus,
)

InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)

EXAMPLE_PROJECT_ID = "40100000-0000-4000-8000-000000000001"
EXAMPLE_ACTOR = "actor-requester-example"
EXAMPLE_SCOPE = {"tenant_ref": "authenticated", "company_ref": "selected", "project_ref": "workflow-improvement", "project_id": EXAMPLE_PROJECT_ID}


def read_spec(operation_ref: str, tool: str) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(operation_ref=operation_ref, tool=tool, effect=ConnectorEffect.READ, approval_required=False, replay_class=PrimitiveOperationReplayClass.SAFE, freshness_class=PrimitiveOperationFreshnessClass.CURRENT, recovery_policy=PrimitiveOperationRecoveryPolicy.NONE)


class RequestScope(StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str

    @classmethod
    def from_engine_scope(cls, scope: EngineScope) -> "RequestScope":
        return cls(tenant_ref=scope.tenant_ref, company_ref=scope.company_ref, project_ref=scope.project_ref, project_id=scope.project_id)


def request_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def scope_matches(scope: RequestScope, requesting_ref: str, context: PrimitiveExecutionContext) -> bool:
    runtime = context.scope
    try:
        canonical_uuid(scope.project_id)
    except ValueError:
        return False
    matched = scope.tenant_ref == runtime.tenant_ref and scope.company_ref == runtime.company_ref and scope.project_ref == runtime.project_ref and runtime.project_id is not None and scope.project_id == str(runtime.project_id)
    if runtime.actor_ref is not None:
        matched = matched and requesting_ref == runtime.actor_ref
    return matched


class LazyExample(Mapping[str, Any]):
    """Example inputs built on first access so import stays cheap."""

    def __init__(self, builder: Any, key: str) -> None:
        self._builder, self._key = builder, key
        self._built_payload: dict[str, Any] | None = None

    def _payload(self) -> dict[str, Any]:
        if self._built_payload is None:
            self._built_payload = deepcopy(self._builder.get()[self._key])
        return self._built_payload

    def __getitem__(self, key: str) -> Any:
        return deepcopy(self._payload()[key])

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self._payload())

    def __len__(self) -> int:
        return len(self._payload())

    def keys(self):  # type: ignore[no-untyped-def]
        return self._payload().keys()

    def items(self):  # type: ignore[no-untyped-def]
        return deepcopy(self._payload()).items()

    def values(self):  # type: ignore[no-untyped-def]
        return deepcopy(self._payload()).values()


class EnginePrimitive(BusinessProcessPrimitive[InputT, OutputT], Generic[InputT, OutputT]):
    connector_tools = ()
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    operation_spec: PrimitiveOperationSpec
    golden_loop: str = ""
    engine: str = ""
    loop_stages: tuple[str, ...] = ()
    profiles: tuple[str, ...] = ()
    hard_rules: Mapping[str, bool] = {}
    authority_boundary: Mapping[str, str] = {"agent": "proposes", "sdk": "types, fences, and measures", "spring": "authorizes and persists", "connectors": "execute provider operations under approval", "mcp": "projects these primitives and the loop"}

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = self.operation_spec.to_dict()
        contract["golden_loop"] = self.golden_loop
        contract["engine"] = self.engine
        contract["loop_stages"] = list(self.loop_stages)
        contract["profiles"] = list(self.profiles)
        contract["hard_rules"] = dict(self.hard_rules)
        contract["authority_boundary"] = dict(self.authority_boundary)
        return contract

    def blocked(self, *, digest: str, code: str, message: str) -> PrimitiveExecutionResult[OutputT]:
        blocker = PrimitiveBlocker(code=code, message=message[:500], field="scope" if code == "SCOPE_MISMATCH" else None, retryable=False)
        return PrimitiveExecutionResult[OutputT](status=PrimitiveExecutionStatus.BLOCKED, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=f"{self.title} blocked: {code}.", blockers=[blocker], operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED, request_digest=digest, error=blocker)])

    def preview(self, *, output: OutputT, digest: str, external_refs: Mapping[str, str], event_type: str, event_payload: Mapping[str, Any], evidence_kind: str, evidence_summary: str, summary: str, blocker: PrimitiveBlocker | None = None) -> PrimitiveExecutionResult[OutputT]:
        status = PrimitiveExecutionStatus.BLOCKED if blocker else PrimitiveExecutionStatus.PREVIEW
        return PrimitiveExecutionResult[OutputT](
            status=status, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=summary, output=output,
            events=[PrimitiveEvent(type=event_type, payload={**dict(event_payload), "request_digest": digest, "connector_effect_executed": False})],
            evidence=[PrimitiveEvidence(kind=evidence_kind, summary=evidence_summary, refs={"request_digest": digest, **dict(external_refs)})],
            operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED if blocker else PrimitiveOperationStatus.PREVIEW, request_digest=digest, external_refs=dict(external_refs), error=blocker)],
            blockers=[blocker] if blocker else [],
        )

    def transition_preview(self, *, result: Any, digest: str, entity_ref: str, event_prefix: str) -> PrimitiveExecutionResult[OutputT]:
        receipt = result.receipt
        blocker = None if result.candidate_validated else PrimitiveBlocker(code=str(receipt.rejection_code), message=str(receipt.recovery.instructions)[:500], retryable=receipt.recovery.disposition in {"refresh_state", "await_approval"})
        summary = f"{receipt.entity} {receipt.event}: {receipt.from_status} -> {receipt.to_status} (v{receipt.to_version})." if result.candidate_validated else f"{receipt.entity} {receipt.event} rejected: {receipt.rejection_code} ({receipt.recovery.disposition})."
        return self.preview(output=result, digest=digest, external_refs={"entity_ref": entity_ref, "transition_ref": receipt.transition_ref, "to_state_digest": receipt.to_state_digest}, event_type=f"{event_prefix}.{receipt.entity}_advanced", event_payload={"entity": receipt.entity, "event": receipt.event, "transition_status": receipt.status, "from_status": receipt.from_status, "to_status": receipt.to_status, "rejection_code": receipt.rejection_code, "recovery": receipt.recovery.disposition}, evidence_kind=f"{event_prefix}_{receipt.entity}_transition", evidence_summary="Replay-fenced transition; candidate until Spring retains it.", summary=summary, blocker=blocker)


__all__ = ["EXAMPLE_ACTOR", "EXAMPLE_PROJECT_ID", "EXAMPLE_SCOPE", "EnginePrimitive", "LazyExample", "RequestScope", "read_spec", "request_digest", "scope_matches"]
