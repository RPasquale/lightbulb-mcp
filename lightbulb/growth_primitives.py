"""Executable primitives promoted by the continuous improvement catalog."""

from __future__ import annotations

import hashlib
import json
from datetime import date
from decimal import Decimal
from typing import Any, Dict, Literal, Mapping

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.connector_bindings import resolve_connector_tool
from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorExecutionResult,
    ConnectorExecutionStatus,
)
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)


def _external_ref(output: Mapping[str, Any]) -> str | None:
    for key in (
        "id",
        "externalId",
        "external_id",
        "paymentId",
        "payment_id",
        "documentId",
        "document_id",
        "spreadsheetId",
        "spreadsheet_id",
        "presentationId",
        "presentation_id",
        "url",
    ):
        value = output.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _connector_blocker(result: ConnectorExecutionResult) -> PrimitiveBlocker:
    return PrimitiveBlocker(
        code=result.error_code
        or (result.error_kind.value if result.error_kind is not None else "connector_blocked"),
        message=result.message or "Connector Execution did not complete.",
        retryable=result.retryable,
    )


def _primitive_status(result: ConnectorExecutionResult) -> PrimitiveExecutionStatus:
    return {
        ConnectorExecutionStatus.COMPLETED: PrimitiveExecutionStatus.COMPLETED,
        ConnectorExecutionStatus.PREVIEW: PrimitiveExecutionStatus.PREVIEW,
        ConnectorExecutionStatus.PENDING_APPROVAL: PrimitiveExecutionStatus.PENDING_APPROVAL,
        ConnectorExecutionStatus.BLOCKED: PrimitiveExecutionStatus.BLOCKED,
        ConnectorExecutionStatus.FAILED: PrimitiveExecutionStatus.FAILED,
    }[result.status]


class CollectPaymentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invoice_id: str = Field(min_length=1, max_length=200)
    account_id: str = Field(min_length=1, max_length=200)
    amount: Decimal = Field(gt=0)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    payment_date: str = Field(default_factory=lambda: date.today().isoformat())
    reference: str = Field(default="", max_length=300)
    commit: bool = False

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, value: str) -> str:
        clean = value.strip().upper()
        if not clean.isalpha():
            raise ValueError("currency must be a three-letter code")
        return clean

    @field_validator("payment_date")
    @classmethod
    def _valid_payment_date(cls, value: str) -> str:
        clean = value.strip()
        try:
            date.fromisoformat(clean)
        except ValueError as exc:
            raise ValueError("payment_date must be a valid YYYY-MM-DD date") from exc
        return clean


class CollectPaymentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["xero"] = "xero"
    invoice_id: str
    account_id: str
    amount: Decimal
    currency: str
    payment_date: str
    state: Literal["proposal", "preview", "pending_approval", "recorded", "blocked", "failed"]
    payment_ref: str | None = None


class CollectPaymentPrimitive(BusinessProcessPrimitive[CollectPaymentInput, CollectPaymentOutput]):
    primitive_ref = "finance.collect_payment"
    version = "1.0.0"
    title = "Collect approved payment"
    description = "Propose and record an approved invoice payment through governed Xero execution."
    input_model = CollectPaymentInput
    output_model = CollectPaymentOutput
    connector_tools = ("xero.create_payment",)
    risk_level = "high"
    approval_required = True
    example_inputs = {
        "invoice_id": "invoice-example-1",
        "account_id": "bank-example-1",
        "amount": "125.00",
        "currency": "USD",
        "payment_date": "2026-07-09",
        "commit": False,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CollectPaymentInput,
    ) -> PrimitiveExecutionResult[CollectPaymentOutput]:
        output = CollectPaymentOutput(
            invoice_id=inputs.invoice_id,
            account_id=inputs.account_id,
            amount=inputs.amount,
            currency=inputs.currency,
            payment_date=inputs.payment_date,
            state="proposal",
        )
        if not inputs.commit:
            return PrimitiveExecutionResult[CollectPaymentOutput](
                status=PrimitiveExecutionStatus.COMPLETED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Payment proposal validated; no accounting write requested.",
                output=output,
                events=[PrimitiveEvent(type="payment.proposed")],
                evidence=[
                    PrimitiveEvidence(
                        kind="payment_proposal",
                        summary="Invoice, account, amount, currency, and date were validated locally.",
                    )
                ],
            )

        connector_result = context.connectors.execute(
            context.connector_request(
                primitive_ref=self.primitive_ref,
                tool="xero.create_payment",
                arguments={
                    "invoice_id": inputs.invoice_id,
                    "account_id": inputs.account_id,
                    "amount": str(inputs.amount),
                    "currency": inputs.currency,
                    "date": inputs.payment_date,
                    "reference": inputs.reference,
                },
                effect=ConnectorEffect.WRITE,
                approval_required=True,
            )
        )
        state = {
            ConnectorExecutionStatus.COMPLETED: "recorded",
            ConnectorExecutionStatus.PREVIEW: "preview",
            ConnectorExecutionStatus.PENDING_APPROVAL: "pending_approval",
            ConnectorExecutionStatus.BLOCKED: "blocked",
            ConnectorExecutionStatus.FAILED: "failed",
        }[connector_result.status]
        event_type = {
            "recorded": "payment.recorded",
            "preview": "payment.proposed",
            "pending_approval": "payment.pending_approval",
            "blocked": "payment.failed",
            "failed": "payment.failed",
            "proposal": "payment.proposed",
        }[state]
        blockers = (
            [_connector_blocker(connector_result)]
            if connector_result.status
            in {ConnectorExecutionStatus.BLOCKED, ConnectorExecutionStatus.FAILED}
            else []
        )
        return PrimitiveExecutionResult[CollectPaymentOutput](
            status=_primitive_status(connector_result),
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=connector_result.message or f"Payment state: {state}.",
            output=output.model_copy(
                update={
                    "state": state,
                    "payment_ref": _external_ref(connector_result.output),
                }
            ),
            events=[PrimitiveEvent(type=event_type)],
            evidence=[
                PrimitiveEvidence(
                    kind="connector_execution",
                    summary="Payment write was routed through xero.create_payment.",
                )
            ],
            blockers=blockers,
            approval_ref=connector_result.approval_ref,
            connector_tool="xero.create_payment",
            retryable=connector_result.retryable,
        )


class RequestDecisionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1, max_length=300)
    question: str = Field(min_length=1, max_length=5_000)
    options: list[str] = Field(min_length=2, max_length=20)
    owner: str = Field(default="workflow_owner", min_length=1, max_length=200)
    due_at: str = Field(default="", max_length=80)
    context: Dict[str, Any] = Field(default_factory=dict)
    submit: bool = False
    decision: str = Field(default="", max_length=300)

    @field_validator("options")
    @classmethod
    def _normalize_options(cls, values: list[str]) -> list[str]:
        normalized = [str(value).strip() for value in values if str(value).strip()]
        if len(normalized) < 2:
            raise ValueError("at least two non-empty decision options are required")
        if len({value.lower() for value in normalized}) != len(normalized):
            raise ValueError("decision options must be unique")
        return normalized

    @model_validator(mode="after")
    def _decision_must_be_an_option(self) -> "RequestDecisionInput":
        if self.decision and self.decision.lower() not in {value.lower() for value in self.options}:
            raise ValueError("decision must match one of options")
        return self


class RequestDecisionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str
    question: str
    options: list[str]
    owner: str
    state: Literal["draft", "pending", "decided"]
    decision: str | None = None


class RequestDecisionPrimitive(BusinessProcessPrimitive[RequestDecisionInput, RequestDecisionOutput]):
    primitive_ref = "approval.request_decision"
    version = "1.0.0"
    title = "Request governed decision"
    description = "Create a typed decision request that pauses until a verified approval reference is supplied."
    input_model = RequestDecisionInput
    output_model = RequestDecisionOutput
    connector_tools = ()
    risk_level = "medium"
    approval_required = True
    example_inputs = {
        "subject": "Select launch date",
        "question": "Which approved launch window should the workflow use?",
        "options": ["2026-08-01", "2026-08-15"],
        "submit": False,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: RequestDecisionInput,
    ) -> PrimitiveExecutionResult[RequestDecisionOutput]:
        output = RequestDecisionOutput(
            subject=inputs.subject,
            question=inputs.question,
            options=inputs.options,
            owner=inputs.owner,
            state="draft",
        )
        if not inputs.submit:
            return PrimitiveExecutionResult[RequestDecisionOutput](
                status=PrimitiveExecutionStatus.COMPLETED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Decision request drafted; no workflow pause requested.",
                output=output,
                events=[PrimitiveEvent(type="approval.draft_created")],
                evidence=[
                    PrimitiveEvidence(
                        kind="decision_request",
                        summary="Decision owner, question, and allowed options were validated.",
                    )
                ],
            )

        approval_ref = context.approval_ref_for(self.primitive_ref)
        if not approval_ref:
            return PrimitiveExecutionResult[RequestDecisionOutput](
                status=PrimitiveExecutionStatus.PENDING_APPROVAL,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Decision request is waiting for a governed response.",
                output=output.model_copy(update={"state": "pending"}),
                events=[
                    PrimitiveEvent(
                        type="approval.requested",
                        payload={"subject": inputs.subject, "owner": inputs.owner},
                    )
                ],
                evidence=[
                    PrimitiveEvidence(
                        kind="decision_request",
                        summary="Workflow paused without treating an unverified response as approval.",
                    )
                ],
            )
        if not inputs.decision:
            return PrimitiveExecutionResult[RequestDecisionOutput](
                status=PrimitiveExecutionStatus.NEEDS_INPUT,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="An approval reference exists, but the selected decision is missing.",
                output=output.model_copy(update={"state": "pending"}),
                blockers=[
                    PrimitiveBlocker(
                        code="decision_required",
                        message="Resume with a decision matching one of the allowed options.",
                        field="decision",
                    )
                ],
                approval_ref=approval_ref,
            )
        return PrimitiveExecutionResult[RequestDecisionOutput](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary="Governed decision recorded for downstream routing.",
            output=output.model_copy(update={"state": "decided", "decision": inputs.decision}),
            events=[
                PrimitiveEvent(
                    type="approval.decided",
                    payload={"decision": inputs.decision, "owner": inputs.owner},
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="approval_reference",
                    summary="Decision was accepted only with a verified approval reference.",
                    refs={"approval_ref": approval_ref},
                )
            ],
            approval_ref=approval_ref,
        )


ArtifactType = Literal["docx", "pdf", "xlsx", "pptx", "markdown"]


class GenerateBusinessArtifactInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_type: ArtifactType
    title: str = Field(min_length=1, max_length=300)
    content: Any
    destination: str = Field(default="", max_length=500)
    create: bool = False

    @field_validator("content")
    @classmethod
    def _bounded_content(cls, value: Any) -> Any:
        rendered = json.dumps(value, default=str)
        if len(rendered.encode("utf-8")) > 1_000_000:
            raise ValueError("artifact content must be 1 MB or smaller")
        return value


class GenerateBusinessArtifactOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_type: ArtifactType
    title: str
    state: Literal["draft", "preview", "pending_approval", "created", "blocked", "failed"]
    artifact_ref: str | None = None


class GenerateBusinessArtifactPrimitive(
    BusinessProcessPrimitive[GenerateBusinessArtifactInput, GenerateBusinessArtifactOutput]
):
    primitive_ref = "documents.generate_business_artifact"
    version = "1.0.0"
    title = "Generate business artifact"
    description = "Prepare inspectable document, spreadsheet, presentation, PDF, or Markdown output."
    input_model = GenerateBusinessArtifactInput
    output_model = GenerateBusinessArtifactOutput
    connector_tools = (
        "docs.create_document",
        "sheets.create_spreadsheet",
        "slides.create_presentation",
    )
    risk_level = "medium"
    approval_required = True
    example_inputs = {
        "artifact_type": "docx",
        "title": "Example operating review",
        "content": {"summary": "Synthetic example content"},
        "create": False,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: GenerateBusinessArtifactInput,
    ) -> PrimitiveExecutionResult[GenerateBusinessArtifactOutput]:
        output = GenerateBusinessArtifactOutput(
            artifact_type=inputs.artifact_type,
            title=inputs.title,
            state="draft",
        )
        if not inputs.create:
            return PrimitiveExecutionResult[GenerateBusinessArtifactOutput](
                status=PrimitiveExecutionStatus.COMPLETED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Business artifact draft validated; no file write requested.",
                output=output,
                events=[PrimitiveEvent(type="artifact.draft_created")],
                evidence=[
                    PrimitiveEvidence(
                        kind="artifact_draft",
                        summary="Artifact type, title, and bounded content were validated locally.",
                    )
                ],
            )

        tool = resolve_connector_tool(self.primitive_ref, inputs.artifact_type)
        connector_result = context.connectors.execute(
            context.connector_request(
                primitive_ref=self.primitive_ref,
                tool=tool,
                arguments={
                    "title": inputs.title,
                    "content": inputs.content,
                    "body": inputs.content,
                    "format": inputs.artifact_type,
                    "destination": inputs.destination,
                },
                effect=ConnectorEffect.WRITE,
                approval_required=True,
            )
        )
        state = {
            ConnectorExecutionStatus.COMPLETED: "created",
            ConnectorExecutionStatus.PREVIEW: "preview",
            ConnectorExecutionStatus.PENDING_APPROVAL: "pending_approval",
            ConnectorExecutionStatus.BLOCKED: "blocked",
            ConnectorExecutionStatus.FAILED: "failed",
        }[connector_result.status]
        blockers = (
            [_connector_blocker(connector_result)]
            if connector_result.status
            in {ConnectorExecutionStatus.BLOCKED, ConnectorExecutionStatus.FAILED}
            else []
        )
        event_type = {
            "created": "artifact.created",
            "preview": "artifact.previewed",
            "pending_approval": "artifact.pending_approval",
            "blocked": "artifact.blocked",
            "failed": "artifact.failed",
        }[state]
        return PrimitiveExecutionResult[GenerateBusinessArtifactOutput](
            status=_primitive_status(connector_result),
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=connector_result.message or f"Business artifact state: {state}.",
            output=output.model_copy(
                update={
                    "state": state,
                    "artifact_ref": _external_ref(connector_result.output),
                }
            ),
            events=[
                PrimitiveEvent(
                    type=event_type,
                    payload={"artifact_type": inputs.artifact_type},
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="connector_execution",
                    summary=f"Artifact write was routed through {tool}.",
                )
            ],
            blockers=blockers,
            approval_ref=connector_result.approval_ref,
            connector_tool=tool,
            retryable=connector_result.retryable,
        )


class CreateWorkPacketInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    implementation_objective: str = Field(
        min_length=1,
        max_length=5_000,
        validation_alias=AliasChoices("implementation_objective", "objective"),
    )
    scope: list[str] = Field(min_length=1, max_length=100)
    acceptance_criteria: list[str] = Field(min_length=1, max_length=100)
    target_files: list[str] = Field(default_factory=list, max_length=500)
    dependencies: list[str] = Field(default_factory=list, max_length=100)
    risk_level: Literal["low", "medium", "high"] = "medium"
    submit_for_approval: bool = False

    @field_validator("scope", "acceptance_criteria", "target_files", "dependencies")
    @classmethod
    def _normalize_lists(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))


class CreateWorkPacketOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    packet_ref: str
    title: str
    objective: str
    scope: list[str]
    acceptance_criteria: list[str]
    target_files: list[str]
    dependencies: list[str]
    risk_level: Literal["low", "medium", "high"]
    state: Literal["draft", "pending_approval", "approved"]


class CreateWorkPacketPrimitive(
    BusinessProcessPrimitive[CreateWorkPacketInput, CreateWorkPacketOutput]
):
    primitive_ref = "project.create_work_packet"
    version = "1.0.0"
    title = "Create implementation work packet"
    description = "Create a bounded implementation packet with acceptance and approval contracts."
    input_model = CreateWorkPacketInput
    output_model = CreateWorkPacketOutput
    connector_tools = ()
    risk_level = "high"
    approval_required = True
    example_inputs = {
        "title": "Add customer health event",
        "implementation_objective": "Emit a typed customer health event from the CRM workflow.",
        "scope": ["SDK contract", "runtime implementation", "focused tests"],
        "acceptance_criteria": ["Typed event is emitted", "Cross-company access remains blocked"],
        "submit_for_approval": False,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CreateWorkPacketInput,
    ) -> PrimitiveExecutionResult[CreateWorkPacketOutput]:
        material = json.dumps(
            {
                "title": inputs.title,
                "objective": inputs.implementation_objective,
                "scope": inputs.scope,
                "acceptance": inputs.acceptance_criteria,
                "targets": inputs.target_files,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        packet_ref = "work-packet-" + hashlib.sha256(material).hexdigest()[:16]
        output = CreateWorkPacketOutput(
            packet_ref=packet_ref,
            title=inputs.title,
            objective=inputs.implementation_objective,
            scope=inputs.scope,
            acceptance_criteria=inputs.acceptance_criteria,
            target_files=inputs.target_files,
            dependencies=inputs.dependencies,
            risk_level=inputs.risk_level,
            state="draft",
        )
        if not inputs.submit_for_approval:
            return PrimitiveExecutionResult[CreateWorkPacketOutput](
                status=PrimitiveExecutionStatus.COMPLETED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Implementation work packet drafted; execution remains blocked until approval.",
                output=output,
                events=[PrimitiveEvent(type="project.work_packet_created", payload={"packet_ref": packet_ref})],
                evidence=[
                    PrimitiveEvidence(
                        kind="work_packet",
                        summary="Scope, acceptance criteria, dependencies, and target files were normalized.",
                        refs={"packet_ref": packet_ref},
                    )
                ],
            )
        approval_ref = context.approval_ref_for(self.primitive_ref)
        if not approval_ref:
            return PrimitiveExecutionResult[CreateWorkPacketOutput](
                status=PrimitiveExecutionStatus.PENDING_APPROVAL,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Work packet is waiting for implementation approval.",
                output=output.model_copy(update={"state": "pending_approval"}),
                events=[PrimitiveEvent(type="project.work_packet_pending_approval", payload={"packet_ref": packet_ref})],
                evidence=[
                    PrimitiveEvidence(
                        kind="work_packet",
                        summary="No implementation or connector action was started before approval.",
                        refs={"packet_ref": packet_ref},
                    )
                ],
            )
        return PrimitiveExecutionResult[CreateWorkPacketOutput](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary="Work packet approved for a separately governed implementation step.",
            output=output.model_copy(update={"state": "approved"}),
            events=[PrimitiveEvent(type="project.work_packet_approved", payload={"packet_ref": packet_ref})],
            evidence=[
                PrimitiveEvidence(
                    kind="approval_reference",
                    summary="Implementation approval was attached without starting publish or deploy.",
                    refs={"packet_ref": packet_ref, "approval_ref": approval_ref},
                )
            ],
            approval_ref=approval_ref,
        )


__all__ = [
    "CollectPaymentInput",
    "CollectPaymentOutput",
    "CollectPaymentPrimitive",
    "CreateWorkPacketInput",
    "CreateWorkPacketOutput",
    "CreateWorkPacketPrimitive",
    "GenerateBusinessArtifactInput",
    "GenerateBusinessArtifactOutput",
    "GenerateBusinessArtifactPrimitive",
    "RequestDecisionInput",
    "RequestDecisionOutput",
    "RequestDecisionPrimitive",
]
