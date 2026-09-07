"""Built-in executable primitives for finance, legal, CRM, and HR workflows."""

from __future__ import annotations

import re
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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


_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_MONEY_RE = re.compile(r"(?:USD|CAD|AUD|GBP|EUR|\$|\u00a3|\u20ac)?\s*(-?[0-9][0-9,]*(?:\.[0-9]{1,2})?)", re.I)


def _external_ref(output: Mapping[str, Any]) -> str | None:
    for key in (
        "id",
        "externalId",
        "external_id",
        "billId",
        "bill_id",
        "documentId",
        "document_id",
        "employeeId",
        "employee_id",
        "userId",
        "user_id",
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


def _first_match(text: str, patterns: tuple[str, ...]) -> str:
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.I | re.M)
        if match and match.group(1).strip():
            return match.group(1).strip()
    return ""


def _decimal(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    match = _MONEY_RE.search(str(value).replace(" ", ""))
    if not match:
        return None
    try:
        return Decimal(match.group(1).replace(",", ""))
    except InvalidOperation:
        return None


class SupplierInvoiceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invoice_url: str = Field(default="", max_length=2_048)
    invoice_text: str = Field(default="", max_length=500_000)
    expected_vendor: str = Field(default="", max_length=300)
    extracted_fields: Dict[str, Any] = Field(default_factory=dict)
    known_invoice_numbers: list[str] = Field(default_factory=list, max_length=10_000)
    provider: Literal["xero", "quickbooks"] = "xero"
    create_bill: bool = False

    @model_validator(mode="after")
    def _requires_invoice_material(self) -> "SupplierInvoiceInput":
        if not self.invoice_url.strip() and not self.invoice_text.strip() and not self.extracted_fields:
            raise ValueError("invoice_url, invoice_text, or extracted_fields is required")
        return self


class SupplierInvoiceOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor: str
    invoice_number: str
    invoice_date: str
    due_date: str
    currency: str
    subtotal: Decimal | None = None
    tax: Decimal | None = None
    total: Decimal | None = None
    duplicate: bool
    exceptions: list[str]
    confidence: float = Field(ge=0, le=1)
    state: Literal[
        "extracted",
        "exception",
        "preview",
        "pending_approval",
        "bill_created",
        "blocked",
        "failed",
    ]
    bill_ref: str | None = None


class IngestSupplierInvoicePrimitive(
    BusinessProcessPrimitive[SupplierInvoiceInput, SupplierInvoiceOutput]
):
    primitive_ref = "finance.ingest_supplier_invoice"
    version = "1.0.0"
    title = "Ingest supplier invoice"
    description = "Extract and validate AP invoice facts before an optional governed bill write."
    input_model = SupplierInvoiceInput
    output_model = SupplierInvoiceOutput
    connector_tools = ("xero.create_bill", "quickbooks.create_bill")
    risk_level = "medium"
    approval_required = False
    example_inputs = {
        "invoice_text": (
            "Example Supplies Ltd\nInvoice #: EX-1042\nInvoice Date: 2026-07-01\n"
            "Due Date: 2026-07-31\nSubtotal: $900.00\nTax: $90.00\nTotal: $990.00"
        ),
        "expected_vendor": "Example Supplies Ltd",
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: SupplierInvoiceInput,
    ) -> PrimitiveExecutionResult[SupplierInvoiceOutput]:
        source = inputs.invoice_text.strip()
        fields = dict(inputs.extracted_fields)
        nonempty_lines = [line.strip() for line in source.splitlines() if line.strip()]
        vendor = str(fields.get("vendor") or inputs.expected_vendor or (nonempty_lines[0] if nonempty_lines else "")).strip()
        invoice_number = str(fields.get("invoice_number") or _first_match(
            source,
            (r"(?:invoice\s*(?:number|no\.?|#))\s*[:#-]?\s*([^\s,;]+)",),
        )).strip()
        invoice_date = str(fields.get("invoice_date") or _first_match(
            source,
            (r"(?:invoice\s+date|date)\s*[:#-]?\s*([0-9]{4}-[0-9]{2}-[0-9]{2})",),
        )).strip()
        due_date = str(fields.get("due_date") or _first_match(
            source,
            (r"due\s+date\s*[:#-]?\s*([0-9]{4}-[0-9]{2}-[0-9]{2})",),
        )).strip()
        subtotal = _decimal(fields.get("subtotal") or _first_match(source, (r"^\s*subtotal\s*[:#-]?\s*([^\r\n]+)",)))
        tax = _decimal(fields.get("tax") or _first_match(source, (r"^\s*(?:tax|vat)\s*[:#-]?\s*([^\r\n]+)",)))
        total = _decimal(fields.get("total") or _first_match(source, (r"^\s*(?:amount\s+due|total)\s*[:#-]?\s*([^\r\n]+)",)))
        currency = str(fields.get("currency") or "").strip().upper()
        if not currency:
            currency = "GBP" if "\u00a3" in source else "EUR" if "\u20ac" in source else "USD"

        known_numbers = {str(value).strip().lower() for value in inputs.known_invoice_numbers}
        duplicate = bool(invoice_number and invoice_number.lower() in known_numbers)
        exceptions: list[str] = []
        if not vendor:
            exceptions.append("vendor_missing")
        if inputs.expected_vendor and vendor.lower() != inputs.expected_vendor.strip().lower():
            exceptions.append("vendor_mismatch")
        if not invoice_number:
            exceptions.append("invoice_number_missing")
        if total is None:
            exceptions.append("total_missing")
        if duplicate:
            exceptions.append("possible_duplicate")
        if total is not None and subtotal is not None and tax is not None:
            if abs(total - subtotal - tax) > Decimal("0.01"):
                exceptions.append("totals_do_not_reconcile")

        populated = sum(bool(value) for value in (vendor, invoice_number, invoice_date, due_date, total))
        confidence = round(populated / 5, 2)
        output = SupplierInvoiceOutput(
            vendor=vendor,
            invoice_number=invoice_number,
            invoice_date=invoice_date,
            due_date=due_date,
            currency=currency,
            subtotal=subtotal,
            tax=tax,
            total=total,
            duplicate=duplicate,
            exceptions=exceptions,
            confidence=confidence,
            state="exception" if exceptions else "extracted",
        )
        event_type = "supplier_invoice.exception_found" if exceptions else "supplier_invoice.extracted"
        if not inputs.create_bill:
            return PrimitiveExecutionResult[SupplierInvoiceOutput](
                status=PrimitiveExecutionStatus.COMPLETED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=("Supplier invoice extracted with exceptions." if exceptions else "Supplier invoice extracted and validated."),
                output=output,
                events=[PrimitiveEvent(type=event_type, payload={"exception_codes": exceptions, "confidence": confidence})],
                evidence=[PrimitiveEvidence(kind="invoice_extraction", summary="AP fields were normalized without retaining invoice text in evidence.", labels=exceptions)],
            )
        if exceptions:
            return PrimitiveExecutionResult[SupplierInvoiceOutput](
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Bill creation blocked until invoice exceptions are resolved.",
                output=output,
                events=[PrimitiveEvent(type="supplier_invoice.exception_found", payload={"exception_codes": exceptions})],
                evidence=[PrimitiveEvidence(kind="invoice_validation", summary="Invoice exceptions prevented a provider write.", labels=exceptions)],
                blockers=[PrimitiveBlocker(code="supplier_invoice_exception", message="Resolve invoice exceptions before creating a bill.")],
            )

        tool = resolve_connector_tool(self.primitive_ref, inputs.provider)
        connector_result = context.connectors.execute(
            context.connector_request(
                primitive_ref=self.primitive_ref,
                tool=tool,
                arguments={
                    "vendor": vendor,
                    "invoice_number": invoice_number,
                    "invoice_date": invoice_date,
                    "due_date": due_date,
                    "currency": currency,
                    "subtotal": str(subtotal) if subtotal is not None else None,
                    "tax": str(tax) if tax is not None else None,
                    "total": str(total) if total is not None else None,
                    "invoice_url": inputs.invoice_url,
                },
                effect=ConnectorEffect.WRITE,
                approval_required=True,
            )
        )
        state = {
            ConnectorExecutionStatus.COMPLETED: "bill_created",
            ConnectorExecutionStatus.PREVIEW: "preview",
            ConnectorExecutionStatus.PENDING_APPROVAL: "pending_approval",
            ConnectorExecutionStatus.BLOCKED: "blocked",
            ConnectorExecutionStatus.FAILED: "failed",
        }[connector_result.status]
        connector_event = {
            "bill_created": "supplier_invoice.ready_for_payment",
            "preview": "supplier_invoice.pending_approval",
            "pending_approval": "supplier_invoice.pending_approval",
            "blocked": "supplier_invoice.exception_found",
            "failed": "supplier_invoice.exception_found",
        }[state]
        final_output = output.model_copy(update={"state": state, "bill_ref": _external_ref(connector_result.output)})
        blockers = [_connector_blocker(connector_result)] if connector_result.status in {ConnectorExecutionStatus.BLOCKED, ConnectorExecutionStatus.FAILED} else []
        return PrimitiveExecutionResult[SupplierInvoiceOutput](
            status=_primitive_status(connector_result),
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=connector_result.message or f"Supplier invoice state: {state}.",
            output=final_output,
            events=[PrimitiveEvent(type=connector_event, payload={"provider": inputs.provider})],
            evidence=[PrimitiveEvidence(kind="connector_execution", summary=f"Bill routed through {tool}.")],
            blockers=blockers,
            approval_ref=connector_result.approval_ref,
            connector_tool=tool,
            retryable=connector_result.retryable,
        )


class DraftContractInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_type: str = Field(min_length=1, max_length=120)
    brief: str = Field(min_length=1, max_length=100_000)
    counterparty: str = Field(default="", max_length=300)
    jurisdiction: str = Field(default="", max_length=160)
    playbook: str = Field(default="", max_length=200)
    provider: Literal["docs", "microsoft"] = "docs"
    save_document: bool = False


class DraftContractOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_type: str
    title: str
    draft_text: str
    sections: list[str]
    review_required: bool
    state: Literal["draft", "preview", "pending_approval", "saved", "blocked", "failed"]
    document_ref: str | None = None


class DraftContractPrimitive(BusinessProcessPrimitive[DraftContractInput, DraftContractOutput]):
    primitive_ref = "legal.draft_contract"
    version = "1.0.0"
    title = "Draft contract"
    description = "Create a review-ready contract draft and save it only through governed document writes."
    input_model = DraftContractInput
    output_model = DraftContractOutput
    connector_tools = ("docs.create_document", "microsoft.create_document")
    risk_level = "high"
    approval_required = True
    example_inputs = {
        "document_type": "Mutual NDA",
        "brief": "Protect confidential product and commercial information shared during evaluation.",
        "counterparty": "Example Company",
        "jurisdiction": "Delaware",
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: DraftContractInput,
    ) -> PrimitiveExecutionResult[DraftContractOutput]:
        document_type = " ".join(inputs.document_type.split())
        counterparty = inputs.counterparty.strip() or "Counterparty"
        jurisdiction = inputs.jurisdiction.strip() or "the mutually agreed jurisdiction"
        title = f"Draft {document_type} - {counterparty}"
        normalized_type = document_type.lower()
        if "nda" in normalized_type or "confidential" in normalized_type:
            clauses = [
                ("Purpose", f"The parties may exchange information for this purpose: {inputs.brief.strip()}"),
                ("Confidential Information", "Confidential Information means non-public business, technical, and commercial information disclosed for the stated purpose."),
                ("Use and Protection", "Each party will use Confidential Information only for the stated purpose and protect it with reasonable safeguards."),
                ("Exclusions", "The final agreement should address public information, prior knowledge, independent development, and lawful third-party receipt."),
                ("Term and Return", "The parties will confirm the term, survival period, and return or destruction obligations during legal review."),
            ]
        elif "sow" in normalized_type or "statement of work" in normalized_type:
            clauses = [
                ("Scope", inputs.brief.strip()),
                ("Deliverables and Milestones", "The parties must define each deliverable, owner, dependency, and target milestone before signature."),
                ("Fees and Expenses", "The final SOW must state pricing, invoicing cadence, reimbursable expenses, taxes, and payment terms."),
                ("Acceptance", "The parties must define objective acceptance criteria, review periods, and the process for rejected deliverables."),
                ("Change Control", "Changes to scope, schedule, staffing, or fees require a written change order approved by authorized representatives."),
            ]
        else:
            clauses = [
                ("Purpose and Services", inputs.brief.strip()),
                ("Responsibilities", "The final agreement must allocate customer and provider responsibilities, dependencies, and cooperation duties."),
                ("Fees and Payment", "The parties must confirm pricing, invoicing, taxes, payment timing, and disputed-charge handling."),
                ("Intellectual Property and Data", "The final agreement must address ownership, licenses, confidentiality, privacy, and security obligations."),
                ("Warranties, Liability, and Indemnity", "Counsel must negotiate warranties, liability caps and carve-outs, and appropriately scoped indemnities."),
                ("Term and Termination", "The parties must confirm term, renewal, termination rights, and transition obligations."),
            ]
        clauses.extend(
            [
                ("Governing Law", f"The parties intend the governing law to be {jurisdiction}, subject to legal approval and negotiated terms."),
                ("Signatures", "Authorized representatives of each party must approve and sign the final agreement."),
            ]
        )
        sections = [heading for heading, _ in clauses]
        draft_text = "\n\n".join(
            [f"{title}\n\nDRAFT FOR LEGAL REVIEW"]
            + [f"{heading}\n{body}" for heading, body in clauses]
        )
        output = DraftContractOutput(
            document_type=document_type,
            title=title,
            draft_text=draft_text,
            sections=sections,
            review_required=True,
            state="draft",
        )
        if not inputs.save_document:
            return PrimitiveExecutionResult[DraftContractOutput](
                status=PrimitiveExecutionStatus.COMPLETED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Contract draft created for legal review; no document write requested.",
                output=output,
                events=[PrimitiveEvent(type="contract.draft_created", payload={"review_required": True})],
                evidence=[PrimitiveEvidence(kind="contract_draft", summary="A labeled draft was generated from the supplied brief and remains subject to legal review.")],
            )

        tool = resolve_connector_tool(self.primitive_ref, inputs.provider)
        connector_result = context.connectors.execute(
            context.connector_request(
                primitive_ref=self.primitive_ref,
                tool=tool,
                arguments={"title": title, "content": draft_text, "metadata": {"document_type": document_type, "playbook": inputs.playbook, "review_required": True}},
                effect=ConnectorEffect.WRITE,
                approval_required=True,
            )
        )
        state = {
            ConnectorExecutionStatus.COMPLETED: "saved",
            ConnectorExecutionStatus.PREVIEW: "preview",
            ConnectorExecutionStatus.PENDING_APPROVAL: "pending_approval",
            ConnectorExecutionStatus.BLOCKED: "blocked",
            ConnectorExecutionStatus.FAILED: "failed",
        }[connector_result.status]
        final_output = output.model_copy(update={"state": state, "document_ref": _external_ref(connector_result.output)})
        blockers = [_connector_blocker(connector_result)] if connector_result.status in {ConnectorExecutionStatus.BLOCKED, ConnectorExecutionStatus.FAILED} else []
        return PrimitiveExecutionResult[DraftContractOutput](
            status=_primitive_status(connector_result),
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=connector_result.message or f"Contract draft state: {state}.",
            output=final_output,
            events=[PrimitiveEvent(type=("contract.pending_legal_review" if state in {"saved", "pending_approval"} else "contract.draft_created"))],
            evidence=[PrimitiveEvidence(kind="connector_execution", summary=f"Contract draft routed through {tool}.")],
            blockers=blockers,
            approval_ref=connector_result.approval_ref,
            connector_tool=tool,
            retryable=connector_result.retryable,
        )


class ContractRiskFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    severity: Literal["low", "medium", "high"]
    summary: str
    recommendation: str


class ReviewContractInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_url: str = Field(default="", max_length=2_048)
    contract_text: str = Field(default="", max_length=1_000_000)
    playbook: str = Field(default="", max_length=200)
    counterparty_name: str = Field(default="", max_length=300)
    focus: str = Field(default="", max_length=2_000)
    provider: Literal["docs", "drive", "microsoft"] = "docs"

    @model_validator(mode="after")
    def _requires_contract(self) -> "ReviewContractInput":
        if not self.contract_url.strip() and not self.contract_text.strip():
            raise ValueError("contract_url or contract_text is required")
        return self


class ReviewContractOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    counterparty_name: str
    playbook: str
    risk_level: Literal["low", "medium", "high"]
    findings: list[ContractRiskFinding]
    summary: str
    state: Literal["reviewed", "blocked", "failed"]


class ReviewContractPrimitive(BusinessProcessPrimitive[ReviewContractInput, ReviewContractOutput]):
    primitive_ref = "legal.review_contract"
    version = "1.0.0"
    title = "Review contract"
    description = "Review contract text against transparent baseline checks or a supplied playbook context."
    input_model = ReviewContractInput
    output_model = ReviewContractOutput
    connector_tools = ("docs.read_document", "drive.download_file", "microsoft.download_file")
    risk_level = "medium"
    approval_required = False
    example_inputs = {
        "contract_text": (
            "Services Agreement. Liability is capped at fees paid in the prior twelve months. "
            "Either party may terminate on thirty days notice. Delaware law governs."
        ),
        "playbook": "Enterprise sales baseline",
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ReviewContractInput,
    ) -> PrimitiveExecutionResult[ReviewContractOutput]:
        text = inputs.contract_text.strip()
        connector_tool: str | None = None
        if not text:
            connector_tool = resolve_connector_tool(
                self.primitive_ref,
                inputs.provider,
            )
            connector_result = context.connectors.execute(
                context.connector_request(
                    primitive_ref=self.primitive_ref,
                    tool=connector_tool,
                    arguments={"url": inputs.contract_url},
                    effect=ConnectorEffect.READ,
                    approval_required=False,
                )
            )
            if connector_result.status != ConnectorExecutionStatus.COMPLETED:
                blockers = [_connector_blocker(connector_result)] if connector_result.status in {ConnectorExecutionStatus.BLOCKED, ConnectorExecutionStatus.FAILED} else []
                return PrimitiveExecutionResult[ReviewContractOutput](
                    status=_primitive_status(connector_result),
                    primitive_ref=self.primitive_ref,
                    primitive_version=self.version,
                    summary=connector_result.message or "Contract source could not be read.",
                    events=[PrimitiveEvent(type="contract.revision_requested")],
                    evidence=[PrimitiveEvidence(kind="connector_execution", summary=f"Contract read routed through {connector_tool}.")],
                    blockers=blockers,
                    connector_tool=connector_tool,
                    retryable=connector_result.retryable,
                )
            for key in ("text", "content", "body", "document_text"):
                value = connector_result.output.get(key)
                if value is not None and str(value).strip():
                    text = str(value).strip()
                    break
            if not text:
                return PrimitiveExecutionResult[ReviewContractOutput](
                    status=PrimitiveExecutionStatus.BLOCKED,
                    primitive_ref=self.primitive_ref,
                    primitive_version=self.version,
                    summary="The contract connector returned no readable text.",
                    blockers=[PrimitiveBlocker(code="contract_text_missing", message="Provide OCR/text content or a connector result containing document text.")],
                    connector_tool=connector_tool,
                )

        normalized = " ".join(text.lower().split())
        findings: list[ContractRiskFinding] = []
        checks = (
            ("unlimited_liability", "high", "unlimited liability" in normalized, "The agreement appears to include unlimited liability.", "Negotiate a defined liability cap and appropriate carve-outs."),
            ("broad_indemnity", "high", "indemnify" in normalized and ("all claims" in normalized or "any and all" in normalized), "The indemnity language appears broad.", "Limit indemnity to defined third-party claims and controllable breaches."),
            ("automatic_renewal", "medium", "automatic renewal" in normalized or "automatically renew" in normalized, "The agreement appears to renew automatically.", "Confirm notice periods, renewal term, and operational ownership."),
            ("liability_cap_missing", "medium", "liability" in normalized and not any(term in normalized for term in ("liability is capped", "aggregate liability", "liability shall not exceed")), "No clear liability cap was detected.", "Add a negotiated aggregate liability cap."),
            ("governing_law_missing", "low", not any(term in normalized for term in ("governing law", "law governs", "laws of")), "No governing-law clause was detected.", "Confirm governing law and venue during legal review."),
            ("termination_missing", "medium", "terminate" not in normalized and "termination" not in normalized, "No termination right was detected.", "Add termination rights, notice, and post-termination obligations."),
        )
        for code, severity, matched, summary, recommendation in checks:
            if matched:
                findings.append(ContractRiskFinding(code=code, severity=severity, summary=summary, recommendation=recommendation))
        if inputs.focus and inputs.focus.lower() not in normalized:
            findings.append(ContractRiskFinding(code="focus_not_found", severity="low", summary="The requested review focus was not located by the baseline analyzer.", recommendation="Have counsel inspect the source and playbook manually for this focus area."))
        risk_level: Literal["low", "medium", "high"] = "low"
        if any(item.severity == "high" for item in findings):
            risk_level = "high"
        elif any(item.severity == "medium" for item in findings):
            risk_level = "medium"
        summary = f"Contract review completed with {len(findings)} finding(s); overall risk is {risk_level}."
        output = ReviewContractOutput(
            counterparty_name=inputs.counterparty_name,
            playbook=inputs.playbook or "baseline review standard",
            risk_level=risk_level,
            findings=findings,
            summary=summary,
            state="reviewed",
        )
        event_type = "contract.risk_flagged" if risk_level in {"medium", "high"} else "contract.review_completed"
        return PrimitiveExecutionResult[ReviewContractOutput](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=summary,
            output=output,
            events=[PrimitiveEvent(type=event_type, payload={"risk_level": risk_level, "finding_count": len(findings)})],
            evidence=[PrimitiveEvidence(kind="contract_review", summary="Transparent baseline checks ran without retaining source contract text in evidence.", labels=[item.code for item in findings])],
            connector_tool=connector_tool,
        )


class LeadQualificationRules(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preferred_industries: list[str] = Field(default_factory=list, max_length=100)
    target_titles: list[str] = Field(default_factory=list, max_length=100)
    min_employees: int | None = Field(default=None, ge=1)
    max_employees: int | None = Field(default=None, ge=1)
    qualified_threshold: int = Field(default=70, ge=1, le=100)

    @model_validator(mode="after")
    def _valid_range(self) -> "LeadQualificationRules":
        if self.min_employees and self.max_employees and self.min_employees > self.max_employees:
            raise ValueError("min_employees must not exceed max_employees")
        return self


class QualifyLeadInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lead_id: str = Field(default="", max_length=200)
    lead_email: str = Field(default="", max_length=320)
    company_domain: str = Field(default="", max_length=253)
    provider: Literal["hubspot", "salesforce"] = "hubspot"
    profile: Dict[str, Any] = Field(default_factory=dict)
    rules: LeadQualificationRules = Field(default_factory=LeadQualificationRules)

    @field_validator("lead_email")
    @classmethod
    def _valid_email(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _EMAIL_RE.fullmatch(clean):
            raise ValueError("lead_email must be a valid email address")
        return clean

    @model_validator(mode="after")
    def _requires_lead(self) -> "QualifyLeadInput":
        if not self.lead_id.strip() and not self.lead_email and not self.company_domain.strip() and not self.profile:
            raise ValueError("lead_id, lead_email, company_domain, or profile is required")
        return self


class QualifyLeadOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: int = Field(ge=0, le=100)
    qualification: Literal["qualified", "disqualified", "needs_research"]
    reasons: list[str]
    missing_data: list[str]
    next_action: str
    profile_source: Literal["input", "hubspot", "salesforce"]


class QualifyLeadPrimitive(BusinessProcessPrimitive[QualifyLeadInput, QualifyLeadOutput]):
    primitive_ref = "crm.qualify_lead"
    version = "1.0.0"
    title = "Qualify lead"
    description = "Score a lead against explicit ICP rules and emit a governed next-action event."
    input_model = QualifyLeadInput
    output_model = QualifyLeadOutput
    connector_tools = ("hubspot.get_contact", "salesforce.get_contact")
    risk_level = "low"
    approval_required = False
    example_inputs = {
        "profile": {"industry": "software", "employee_count": 250, "title": "VP Operations", "engagement": "high"},
        "rules": {"preferred_industries": ["software"], "target_titles": ["vp", "director"], "min_employees": 50, "max_employees": 2_000},
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: QualifyLeadInput,
    ) -> PrimitiveExecutionResult[QualifyLeadOutput]:
        profile = dict(inputs.profile)
        source: Literal["input", "hubspot", "salesforce"] = "input"
        connector_tool: str | None = None
        if not profile:
            connector_tool = resolve_connector_tool(
                self.primitive_ref,
                inputs.provider,
            )
            connector_result = context.connectors.execute(
                context.connector_request(
                    primitive_ref=self.primitive_ref,
                    tool=connector_tool,
                    arguments={"lead_id": inputs.lead_id, "email": inputs.lead_email, "company_domain": inputs.company_domain},
                    effect=ConnectorEffect.READ,
                    approval_required=False,
                )
            )
            if connector_result.status != ConnectorExecutionStatus.COMPLETED:
                blockers = [_connector_blocker(connector_result)] if connector_result.status in {ConnectorExecutionStatus.BLOCKED, ConnectorExecutionStatus.FAILED} else []
                return PrimitiveExecutionResult[QualifyLeadOutput](
                    status=_primitive_status(connector_result),
                    primitive_ref=self.primitive_ref,
                    primitive_version=self.version,
                    summary=connector_result.message or "Lead profile could not be loaded.",
                    blockers=blockers,
                    connector_tool=connector_tool,
                    retryable=connector_result.retryable,
                )
            nested = connector_result.output.get("contact") or connector_result.output.get("profile")
            profile = dict(nested) if isinstance(nested, Mapping) else dict(connector_result.output)
            source = inputs.provider

        score = 10 if any((inputs.lead_id, inputs.lead_email, inputs.company_domain, profile)) else 0
        reasons: list[str] = []
        missing: list[str] = []
        industry = str(profile.get("industry") or "").strip().lower()
        preferred = {value.strip().lower() for value in inputs.rules.preferred_industries if value.strip()}
        if industry:
            if not preferred or industry in preferred:
                score += 25
                reasons.append("industry_fit")
            else:
                reasons.append("industry_outside_icp")
        else:
            missing.append("industry")

        employee_value = profile.get("employee_count") or profile.get("employees")
        try:
            employees = int(employee_value) if employee_value is not None else None
        except (TypeError, ValueError):
            employees = None
        if employees is None:
            missing.append("employee_count")
        else:
            minimum = inputs.rules.min_employees or 1
            maximum = inputs.rules.max_employees or 10**9
            if minimum <= employees <= maximum:
                score += 20
                reasons.append("company_size_fit")
            else:
                reasons.append("company_size_outside_icp")

        title = str(profile.get("title") or profile.get("job_title") or "").strip().lower()
        titles = [value.strip().lower() for value in inputs.rules.target_titles if value.strip()]
        if title:
            if not titles or any(value in title for value in titles):
                score += 20
                reasons.append("role_fit")
            else:
                reasons.append("role_outside_icp")
        else:
            missing.append("title")

        engagement = str(profile.get("engagement") or profile.get("intent") or "").strip().lower()
        if engagement in {"high", "meeting_requested", "demo_requested", "positive"}:
            score += 25
            reasons.append("high_intent")
        elif engagement in {"medium", "engaged", "replied"}:
            score += 15
            reasons.append("active_engagement")
        elif engagement:
            score += 5
            reasons.append("low_engagement")
        else:
            missing.append("engagement")
        score = min(score, 100)

        if score >= inputs.rules.qualified_threshold:
            qualification: Literal["qualified", "disqualified", "needs_research"] = "qualified"
            event_type = "lead.qualified"
            next_action = "personalized_follow_up"
        elif score < 30 and len(missing) <= 1:
            qualification = "disqualified"
            event_type = "lead.disqualified"
            next_action = "record_disqualification_reason"
        else:
            qualification = "needs_research"
            event_type = "lead.needs_research"
            next_action = "enrich_missing_profile_fields"
        output = QualifyLeadOutput(
            score=score,
            qualification=qualification,
            reasons=reasons,
            missing_data=sorted(set(missing)),
            next_action=next_action,
            profile_source=source,
        )
        return PrimitiveExecutionResult[QualifyLeadOutput](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=f"Lead scored {score}/100 and classified as {qualification}.",
            output=output,
            events=[PrimitiveEvent(type=event_type, payload={"score": score, "next_action": next_action}), PrimitiveEvent(type="lead.next_action_recommended", payload={"action": next_action})],
            evidence=[PrimitiveEvidence(kind="lead_qualification", summary="Lead scored against explicit ICP fields without storing raw contact data in evidence.", labels=reasons)],
            connector_tool=connector_tool,
        )


OnboardingSystem = Literal["bamboohr", "google_workspace", "microsoft"]


class OnboardingTask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str
    title: str
    owner: str
    due: str
    approval_required: bool


class OnboardEmployeeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    employee_name: str = Field(min_length=1, max_length=300)
    role_title: str = Field(min_length=1, max_length=300)
    start_date: str
    manager_email: str = Field(default="", max_length=320)
    department: str = Field(default="", max_length=200)
    location: str = Field(default="", max_length=300)
    systems: list[OnboardingSystem] = Field(default_factory=lambda: ["bamboohr", "google_workspace"], min_length=1, max_length=3)
    provision: bool = False

    @field_validator("start_date")
    @classmethod
    def _valid_start_date(cls, value: str) -> str:
        clean = value.strip()
        try:
            date.fromisoformat(clean)
        except ValueError as exc:
            raise ValueError("start_date must be a valid YYYY-MM-DD date") from exc
        return clean

    @field_validator("manager_email")
    @classmethod
    def _valid_manager_email(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _EMAIL_RE.fullmatch(clean):
            raise ValueError("manager_email must be a valid email address")
        return clean

    @field_validator("systems")
    @classmethod
    def _deduplicate_systems(cls, value: list[OnboardingSystem]) -> list[OnboardingSystem]:
        return list(dict.fromkeys(value))


class OnboardEmployeeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    employee_name: str
    role_title: str
    start_date: str
    tasks: list[OnboardingTask]
    systems: list[OnboardingSystem]
    state: Literal["plan", "preview", "pending_approval", "provisioned", "blocked", "failed"]
    system_refs: Dict[str, str] = Field(default_factory=dict)


class OnboardEmployeePrimitive(BusinessProcessPrimitive[OnboardEmployeeInput, OnboardEmployeeOutput]):
    primitive_ref = "hr.onboard_employee"
    version = "1.0.0"
    title = "Onboard employee"
    description = "Build a complete onboarding plan before optional approval-gated account provisioning."
    input_model = OnboardEmployeeInput
    output_model = OnboardEmployeeOutput
    connector_tools = ("bamboohr.create_employee", "google_workspace.create_user", "microsoft.create_user")
    risk_level = "high"
    approval_required = True
    example_inputs = {
        "employee_name": "Jordan Lee",
        "role_title": "Operations Manager",
        "start_date": "2026-07-15",
        "manager_email": "manager@example.test",
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: OnboardEmployeeInput,
    ) -> PrimitiveExecutionResult[OnboardEmployeeOutput]:
        owner = inputs.manager_email or "hiring_manager"
        tasks = [
            OnboardingTask(key="employee_record", title="Create employee record", owner="hr", due=inputs.start_date, approval_required=True),
            OnboardingTask(key="identity_access", title="Provision approved identity and application access", owner="it", due=inputs.start_date, approval_required=True),
            OnboardingTask(key="equipment", title="Prepare role-appropriate equipment", owner="it", due=inputs.start_date, approval_required=False),
            OnboardingTask(key="documents", title="Complete required employment documents", owner="hr", due=inputs.start_date, approval_required=True),
            OnboardingTask(key="day_one", title="Schedule manager and team introductions", owner=owner, due=inputs.start_date, approval_required=False),
        ]
        output = OnboardEmployeeOutput(
            employee_name=inputs.employee_name,
            role_title=inputs.role_title,
            start_date=inputs.start_date,
            tasks=tasks,
            systems=inputs.systems,
            state="plan",
        )
        if not inputs.provision:
            return PrimitiveExecutionResult[OnboardEmployeeOutput](
                status=PrimitiveExecutionStatus.COMPLETED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Onboarding plan created; no accounts or employee records were provisioned.",
                output=output,
                events=[PrimitiveEvent(type="employee.onboarding_plan_created", payload={"task_count": len(tasks)})],
                evidence=[PrimitiveEvidence(kind="onboarding_plan", summary="HR, access, equipment, document, and day-one tasks were planned locally.")],
            )

        results: list[tuple[OnboardingSystem, ConnectorExecutionResult]] = []
        for system in inputs.systems:
            tool = resolve_connector_tool(self.primitive_ref, system)
            operation_ref = f"system.{system}"
            result = context.connectors.execute(
                context.connector_request(
                    primitive_ref=self.primitive_ref,
                    tool=tool,
                    arguments={
                        "employee_name": inputs.employee_name,
                        "role_title": inputs.role_title,
                        "start_date": inputs.start_date,
                        "manager_email": inputs.manager_email,
                        "department": inputs.department,
                        "location": inputs.location,
                    },
                    effect=ConnectorEffect.WRITE,
                    approval_required=True,
                    operation_ref=operation_ref,
                    metadata={"onboarding_system": system},
                )
            )
            results.append((system, result))

        statuses = {result.status for _, result in results}
        if ConnectorExecutionStatus.FAILED in statuses:
            state = "failed"
            status = PrimitiveExecutionStatus.FAILED
        elif ConnectorExecutionStatus.BLOCKED in statuses:
            state = "blocked"
            status = PrimitiveExecutionStatus.BLOCKED
        elif ConnectorExecutionStatus.PENDING_APPROVAL in statuses:
            state = "pending_approval"
            status = PrimitiveExecutionStatus.PENDING_APPROVAL
        elif ConnectorExecutionStatus.PREVIEW in statuses:
            state = "preview"
            status = PrimitiveExecutionStatus.PREVIEW
        else:
            state = "provisioned"
            status = PrimitiveExecutionStatus.COMPLETED
        refs = {
            system: ref
            for system, result in results
            if (ref := _external_ref(result.output)) is not None
        }
        blockers = [
            _connector_blocker(result)
            for _, result in results
            if result.status in {ConnectorExecutionStatus.BLOCKED, ConnectorExecutionStatus.FAILED}
        ]
        final_output = output.model_copy(update={"state": state, "system_refs": refs})
        event_type = {
            "provisioned": "employee.accounts_provisioned",
            "preview": "employee.access_pending_approval",
            "pending_approval": "employee.access_pending_approval",
            "blocked": "employee.access_pending_approval",
            "failed": "employee.access_pending_approval",
            "plan": "employee.onboarding_plan_created",
        }[state]
        approval_refs = {
            f"{self.primitive_ref}#system.{system}": result.approval_ref
            for system, result in results
            if (
                result.status == ConnectorExecutionStatus.PENDING_APPROVAL
                and result.approval_ref
            )
        }
        approval_ref = next(iter(approval_refs.values()), None)
        return PrimitiveExecutionResult[OnboardEmployeeOutput](
            status=status,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=f"Onboarding provisioning state: {state}.",
            output=final_output,
            events=[PrimitiveEvent(type=event_type, payload={"systems": inputs.systems})],
            evidence=[PrimitiveEvidence(kind="connector_execution", summary="Onboarding writes were routed through governed Connector Execution.", refs=refs)],
            blockers=blockers,
            approval_ref=approval_ref,
            approval_refs=approval_refs,
            connector_tool=",".join(
                resolve_connector_tool(self.primitive_ref, system)
                for system in inputs.systems
            ),
            retryable=any(result.retryable for _, result in results),
        )


__all__ = [
    "ContractRiskFinding",
    "DraftContractInput",
    "DraftContractOutput",
    "DraftContractPrimitive",
    "IngestSupplierInvoicePrimitive",
    "LeadQualificationRules",
    "OnboardEmployeeInput",
    "OnboardEmployeeOutput",
    "OnboardEmployeePrimitive",
    "OnboardingTask",
    "QualifyLeadInput",
    "QualifyLeadOutput",
    "QualifyLeadPrimitive",
    "ReviewContractInput",
    "ReviewContractOutput",
    "ReviewContractPrimitive",
    "SupplierInvoiceInput",
    "SupplierInvoiceOutput",
]
