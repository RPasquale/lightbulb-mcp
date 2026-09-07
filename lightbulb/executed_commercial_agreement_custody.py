"""Typed projection of Spring's immutable executed-agreement custody.

The SDK nominates two already-completed governed READ journals. Spring verifies a
completed DocuSign envelope and its signed document, then stores only opaque
content commitments. This contract cannot dispatch DocuSign, deploy software, or
authorize an invoice or payment.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

EXECUTED_AGREEMENT_CUSTODY_CANDIDATE_SCHEMA = (
    "lightbulb.executed_commercial_agreement_custody_candidate.v1"
)
EXECUTED_AGREEMENT_RECORD_SCHEMA = (
    "lightbulb.executed_commercial_agreement_record.v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONNECTOR_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_AGREEMENT_REF = re.compile(r"^agreement:docusign:[0-9a-f]{32}$")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


def _uuid(value: str, *, field: str) -> str:
    clean = str(value or "").strip().lower()
    try:
        parsed = UUID(clean)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{field} must be a canonical UUID") from exc
    if str(parsed) != clean:
        raise ValueError(f"{field} must be a canonical UUID")
    return clean


def _timestamp(value: str, *, field: str) -> str:
    clean = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include an offset")
    return clean


class ExecutedCommercialAgreementCustodyCandidate(_StrictModel):
    schema_id: Literal[
        "lightbulb.executed_commercial_agreement_custody_candidate.v1"
    ] = Field(default=EXECUTED_AGREEMENT_CUSTODY_CANDIDATE_SCHEMA, alias="schema")
    connector_account_ref: str = Field(min_length=1, max_length=200)
    envelope_observation_journal_id: str
    document_observation_journal_id: str

    @field_validator("connector_account_ref")
    @classmethod
    def _connector(cls, value: str) -> str:
        if not _CONNECTOR_REF.fullmatch(value):
            raise ValueError("connector_account_ref must be a portable opaque alias")
        return value

    @field_validator(
        "envelope_observation_journal_id", "document_observation_journal_id"
    )
    @classmethod
    def _journal_ids(cls, value: str, info: Any) -> str:
        return _uuid(value, field=info.field_name)

    def to_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class ExecutedCommercialAgreementRecord(_StrictModel):
    schema_id: Literal["lightbulb.executed_commercial_agreement_record.v1"] = Field(
        alias="schema"
    )
    record_id: str
    tenant_id: str
    company_id: str
    project_id: str
    agreement_ref: str
    provider: Literal["docusign"]
    connector_account_ref: str = Field(min_length=1, max_length=200)
    envelope_observation_journal_id: str
    document_observation_journal_id: str
    envelope_observation_receipt_sha256: str
    document_observation_receipt_sha256: str
    envelope_id_sha256: str
    document_id_sha256: str
    signed_document_sha256: str
    record_digest: str
    observed_completed_at: str
    registered_by_user_id: str
    audit_event_id: int = Field(ge=1)
    created_at: str
    agreement_executed: Literal[True]
    deployment_authorized: Literal[False]
    external_effect_authorized: Literal[False]

    @field_validator(
        "record_id",
        "tenant_id",
        "company_id",
        "project_id",
        "envelope_observation_journal_id",
        "document_observation_journal_id",
        "registered_by_user_id",
    )
    @classmethod
    def _ids(cls, value: str, info: Any) -> str:
        return _uuid(value, field=info.field_name)

    @field_validator("agreement_ref")
    @classmethod
    def _agreement_ref(cls, value: str) -> str:
        if not _AGREEMENT_REF.fullmatch(value):
            raise ValueError("agreement_ref is invalid")
        return value

    @field_validator("connector_account_ref")
    @classmethod
    def _connector(cls, value: str) -> str:
        if not _CONNECTOR_REF.fullmatch(value):
            raise ValueError("connector_account_ref is invalid")
        return value

    @field_validator(
        "envelope_observation_receipt_sha256",
        "document_observation_receipt_sha256",
        "envelope_id_sha256",
        "document_id_sha256",
        "signed_document_sha256",
        "record_digest",
    )
    @classmethod
    def _digests(cls, value: str, info: Any) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError(f"{info.field_name} must be lowercase SHA-256")
        return value

    @field_validator("observed_completed_at", "created_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field=info.field_name)


def parse_executed_commercial_agreement_record(
    value: dict[str, Any],
) -> ExecutedCommercialAgreementRecord:
    return ExecutedCommercialAgreementRecord.model_validate(value)


__all__ = [
    "EXECUTED_AGREEMENT_CUSTODY_CANDIDATE_SCHEMA",
    "EXECUTED_AGREEMENT_RECORD_SCHEMA",
    "ExecutedCommercialAgreementCustodyCandidate",
    "ExecutedCommercialAgreementRecord",
    "parse_executed_commercial_agreement_record",
]
