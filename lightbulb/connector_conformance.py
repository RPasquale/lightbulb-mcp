"""Executable connector contracts for every provider used by SDK primitives."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field

from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorErrorKind,
    ConnectorExecutionRequest,
    ConnectorExecutionStatus,
    ExecutionScope,
    InMemoryConnectorExecutor,
)
from lightbulb.executable_primitives import default_primitive_registry


CONNECTOR_CONFORMANCE_SCHEMA = "lightbulb.connector_conformance_report.v1"


class ConnectorToolContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str
    effect: ConnectorEffect
    approval_required: bool = False
    supplied_arguments: tuple[str, ...]
    output_ref_fields: tuple[str, ...] = ("id", "externalId", "external_id")

    @property
    def provider(self) -> str:
        return self.tool.split(".", 1)[0]

    def fixture(self) -> dict[str, Any]:
        return {
            name: _fixture_value(name, tool=self.tool)
            for name in self.supplied_arguments
        }


class ConnectorConformanceResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str
    provider: str
    primitive_refs: tuple[str, ...]
    passed: bool
    checks: Mapping[str, bool]
    failures: tuple[str, ...] = ()


class ConnectorConformanceReport(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: str = Field(default=CONNECTOR_CONFORMANCE_SCHEMA, alias="schema")
    passed: bool
    contract_count: int
    provider_count: int
    live_schema_checked: bool
    missing_contracts: list[str] = Field(default_factory=list)
    stale_contracts: list[str] = Field(default_factory=list)
    failed_tools: list[str] = Field(default_factory=list)
    failed_providers: list[str] = Field(default_factory=list)
    results: list[ConnectorConformanceResult] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


def _fixture_value(name: str, *, tool: str = "") -> Any:
    lowered = name.lower()
    if lowered == "max_results":
        return 500
    if lowered == "start_position":
        return 1
    if lowered == "offset":
        return 0
    if lowered == "page":
        return 1
    if lowered == "limit":
        return 100
    if lowered == "created":
        return {"gte": 4_070_908_800, "lte": 4_073_587_199}
    if lowered == "payload" and tool == "quickbooks.create_journal_entry":
        return {
            "Line": [
                {
                    "Amount": 1,
                    "DetailType": "JournalEntryLineDetail",
                    "JournalEntryLineDetail": {
                        "PostingType": "Debit",
                        "AccountRef": {"value": "synthetic-debit"},
                    },
                },
                {
                    "Amount": 1,
                    "DetailType": "JournalEntryLineDetail",
                    "JournalEntryLineDetail": {
                        "PostingType": "Credit",
                        "AccountRef": {"value": "synthetic-credit"},
                    },
                },
            ]
        }
    if lowered == "payload" and tool == "xero.create_manual_journal":
        return {
            "Narration": "Synthetic conformance journal",
            "JournalLines": [
                {"AccountCode": "100", "LineAmount": 1},
                {"AccountCode": "200", "LineAmount": -1},
            ],
        }
    if lowered == "to" and tool == "gmail.send_email":
        return "synthetic@example.test"
    if lowered in {"to", "attendees"}:
        return ["synthetic@example.test"]
    if lowered in {"line_items"}:
        return [{"description": "Synthetic", "quantity": 1, "unit_amount": "1.00"}]
    if lowered in {"content", "body", "context", "metadata"}:
        return {"synthetic": True} if lowered in {"content", "context", "metadata"} else "Synthetic body"
    if lowered in {"amount", "subtotal", "tax", "total"}:
        return "1.00"
    if lowered in {"duration_minutes"}:
        return 30
    if lowered == "start_date":
        return "2099-01-01"
    if lowered == "end_date":
        return "2099-01-31"
    if "date" in lowered:
        return "2099-01-01"
    if lowered in {"start_time"}:
        return "2099-01-01T12:00:00Z"
    if "email" in lowered:
        return "synthetic@example.test"
    if lowered in {"url", "invoice_url"}:
        return "https://example.test/synthetic"
    if lowered == "currency":
        return "USD"
    return f"synthetic-{name.replace('_', '-')}"


def _contract(
    tool: str,
    effect: ConnectorEffect,
    arguments: Iterable[str],
    *,
    approval_required: bool = False,
    output_refs: Iterable[str] = ("id", "externalId", "external_id"),
) -> ConnectorToolContract:
    return ConnectorToolContract(
        tool=tool,
        effect=effect,
        approval_required=approval_required,
        supplied_arguments=tuple(arguments),
        output_ref_fields=tuple(output_refs),
    )


_READ = ConnectorEffect.READ
_WRITE = ConnectorEffect.WRITE
_APPROVED = {"approval_required": True}


CONNECTOR_TOOL_CONTRACTS: tuple[ConnectorToolContract, ...] = (
    _contract("calendar.get_availability", _READ, ("attendees", "time_window", "duration_minutes")),
    _contract("calendar.create_event", _WRITE, ("attendees", "title", "start_time", "duration_minutes", "agenda"), **_APPROVED),
    _contract("microsoft.create_event", _WRITE, ("attendees", "title", "start_time", "duration_minutes", "agenda"), **_APPROVED),
    _contract("gmail.get_thread", _READ, ("thread_id",)),
    _contract("gmail.send_email", _WRITE, ("to", "subject", "body"), approval_required=True, output_refs=("messageId", "message_id", "id")),
    _contract("microsoft.send_email", _WRITE, ("to", "subject", "body", "context"), approval_required=True, output_refs=("messageId", "message_id", "id")),
    _contract("notifications.send_email", _WRITE, ("to", "subject", "body", "context"), approval_required=True, output_refs=("messageId", "message_id", "id")),
    _contract("ses.send_email", _WRITE, ("to", "subject", "body", "context"), approval_required=True, output_refs=("messageId", "message_id", "id")),
    _contract("hubspot.get_contact", _READ, ("lead_id", "email", "company_domain")),
    _contract("salesforce.get_contact", _READ, ("lead_id", "email", "company_domain")),
    _contract("docs.create_document", _WRITE, ("title", "content", "body", "format", "destination", "metadata"), approval_required=True, output_refs=("documentId", "document_id", "id", "url")),
    _contract("sheets.create_spreadsheet", _WRITE, ("title", "content", "format", "destination"), approval_required=True, output_refs=("spreadsheetId", "spreadsheet_id", "id", "url")),
    _contract("slides.create_presentation", _WRITE, ("title", "content", "format", "destination"), approval_required=True, output_refs=("presentationId", "presentation_id", "id", "url")),
    _contract("xero.create_payment", _WRITE, ("invoice_id", "account_id", "amount", "currency", "date", "reference"), approval_required=True, output_refs=("paymentId", "payment_id", "id")),
    _contract(
        "quickbooks.list_accounts",
        _READ,
        ("max_results", "start_position"),
        output_refs=("QueryResponse",),
    ),
    _contract(
        "xero.list_accounts",
        _READ,
        (),
        output_refs=("records",),
    ),
    _contract(
        "quickbooks.trial_balance_report",
        _READ,
        ("start_date", "end_date"),
        output_refs=("Rows",),
    ),
    _contract(
        "xero.trial_balance_report",
        _READ,
        ("start_date", "end_date"),
        output_refs=("lines",),
    ),
    _contract(
        "quickbooks.general_ledger_report",
        _READ,
        ("start_date", "end_date"),
        output_refs=("Rows",),
    ),
    _contract(
        "xero.list_journals",
        _READ,
        ("offset",),
        output_refs=("journals",),
    ),
    _contract(
        "quickbooks.get_period_status",
        _READ,
        (),
        output_refs=("locks",),
    ),
    _contract(
        "xero.get_period_status",
        _READ,
        (),
        output_refs=("locks",),
    ),
    _contract(
        "quickbooks.list_invoices",
        _READ,
        ("start_date", "end_date", "start_position"),
        output_refs=("records",),
    ),
    _contract(
        "quickbooks.list_bills",
        _READ,
        ("start_date", "end_date", "start_position"),
        output_refs=("records",),
    ),
    _contract(
        "quickbooks.list_payments",
        _READ,
        ("start_date", "end_date", "start_position"),
        output_refs=("records",),
    ),
    _contract(
        "xero.list_invoices",
        _READ,
        ("start_date", "end_date", "page"),
        output_refs=("records",),
    ),
    _contract(
        "xero.list_bills",
        _READ,
        ("start_date", "end_date", "page"),
        output_refs=("records",),
    ),
    _contract(
        "xero.list_payments",
        _READ,
        ("start_date", "end_date", "page"),
        output_refs=("records",),
    ),
    _contract(
        "stripe.list_balance_transactions",
        _READ,
        ("limit", "created"),
        output_refs=("data",),
    ),
    _contract(
        "quickbooks.create_journal_entry",
        _WRITE,
        ("payload",),
        approval_required=True,
        output_refs=("provider_record_ref",),
    ),
    _contract(
        "xero.create_manual_journal",
        _WRITE,
        ("payload",),
        approval_required=True,
        output_refs=("provider_record_ref",),
    ),
    _contract("xero.create_invoice", _WRITE, ("customer_name", "customer_id", "line_items", "amount", "currency", "due_date", "reference", "memo"), approval_required=True, output_refs=("invoiceId", "invoice_id", "id")),
    _contract("quickbooks.observe_invoice_issued", _READ, ("correlation_ref",)),
    _contract("quickbooks.observe_invoice_payment_applied", _READ, ("correlation_ref",)),
    _contract(
        "stripe.observe_cash_settlement",
        _READ,
        (
            "correlation_ref",
            "charge_id",
            "payout_id",
            "expected_amount_minor",
            "expected_currency",
            "reversal_window_days",
        ),
    ),
    _contract("quickbooks.create_invoice", _WRITE, ("customer_name", "customer_id", "line_items", "amount", "currency", "due_date", "reference", "memo"), approval_required=True, output_refs=("invoiceId", "invoice_id", "id")),
    _contract("stripe.create_invoice", _WRITE, ("customer_name", "customer_id", "line_items", "amount", "currency", "due_date", "reference", "memo"), approval_required=True, output_refs=("invoiceId", "invoice_id", "id")),
    _contract("square.create_invoice", _WRITE, ("customer_name", "customer_id", "line_items", "amount", "currency", "due_date", "reference", "memo"), approval_required=True, output_refs=("invoiceId", "invoice_id", "id")),
    _contract("xero.create_bill", _WRITE, ("vendor", "invoice_number", "invoice_date", "due_date", "currency", "subtotal", "tax", "total", "invoice_url"), approval_required=True, output_refs=("billId", "bill_id", "id")),
    _contract("quickbooks.create_bill", _WRITE, ("vendor", "invoice_number", "invoice_date", "due_date", "currency", "subtotal", "tax", "total", "invoice_url"), approval_required=True, output_refs=("billId", "bill_id", "id")),
    _contract("bamboohr.create_employee", _WRITE, ("employee_name", "role_title", "start_date", "manager_email", "department", "location"), approval_required=True, output_refs=("employeeId", "employee_id", "id")),
    _contract("google_workspace.create_user", _WRITE, ("employee_name", "role_title", "start_date", "manager_email", "department", "location"), approval_required=True, output_refs=("userId", "user_id", "id")),
    _contract("microsoft.create_user", _WRITE, ("employee_name", "role_title", "start_date", "manager_email", "department", "location"), approval_required=True, output_refs=("userId", "user_id", "id")),
    _contract("microsoft.create_document", _WRITE, ("title", "content", "metadata"), approval_required=True, output_refs=("documentId", "document_id", "id", "url")),
    _contract("docs.read_document", _READ, ("url",), output_refs=("content", "text", "body")),
    _contract("drive.download_file", _READ, ("url",), output_refs=("content", "text", "body")),
    _contract("microsoft.download_file", _READ, ("url",), output_refs=("content", "text", "body")),
)


def _primitive_tools() -> dict[str, set[str]]:
    by_tool: dict[str, set[str]] = defaultdict(set)
    for implementation in default_primitive_registry().catalog():
        for tool in implementation["connector_tools"]:
            by_tool[tool].add(implementation["primitive_ref"])
    return by_tool


def _tool_schema_by_name(values: Iterable[Mapping[str, Any]] | None) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for value in values or ():
        name = str(value.get("name") or value.get("toolName") or value.get("tool_name") or "").strip().lower()
        if name:
            result[name] = value
    return result


def _schema_checks(
    contract: ConnectorToolContract,
    live: Mapping[str, Any] | None,
    *,
    live_schema_checked: bool,
) -> tuple[dict[str, bool], list[str]]:
    if not live_schema_checked:
        return {}, []
    if live is None:
        return {"live_tool_present": False}, ["tool is missing from the hosted catalog"]
    checks = {"live_tool_present": True}
    failures: list[str] = []
    input_schema = live.get("inputSchema") or live.get("input_schema") or {}
    if isinstance(input_schema, Mapping):
        properties = input_schema.get("properties")
        if isinstance(properties, Mapping) and properties:
            missing_properties = sorted(set(contract.supplied_arguments) - set(properties))
            checks["sdk_arguments_supported"] = not missing_properties
            if missing_properties:
                failures.append("hosted input schema dropped SDK arguments: " + ", ".join(missing_properties))
        required = input_schema.get("required")
        if isinstance(required, list):
            missing_required = sorted(set(str(value) for value in required) - set(contract.supplied_arguments))
            checks["hosted_required_arguments_supplied"] = not missing_required
            if missing_required:
                failures.append("hosted schema added required arguments: " + ", ".join(missing_required))
    output_schema = live.get("outputSchema") or live.get("output_schema") or {}
    if isinstance(output_schema, Mapping):
        output_properties = output_schema.get("properties")
        if isinstance(output_properties, Mapping) and output_properties:
            has_ref = bool(set(contract.output_ref_fields) & set(output_properties))
            checks["output_reference_supported"] = has_ref
            if not has_ref:
                failures.append("hosted output schema has no supported result/reference field")
    return checks, failures


def _run_contract(
    contract: ConnectorToolContract,
    primitive_refs: set[str],
    live: Mapping[str, Any] | None,
    *,
    live_schema_checked: bool,
) -> ConnectorConformanceResult:
    calls: list[ConnectorExecutionRequest] = []
    output_key = contract.output_ref_fields[0]

    def handler(request: ConnectorExecutionRequest) -> Mapping[str, Any]:
        calls.append(request)
        return {output_key: f"synthetic-{contract.provider}-ref"}

    executor = InMemoryConnectorExecutor({contract.tool: handler})
    arguments = contract.fixture()
    base = {
        "tool": contract.tool,
        "arguments": arguments,
        "scope": ExecutionScope(project_ref="connector-conformance"),
        "effect": contract.effect,
        "approval_required": contract.approval_required,
        "idempotency_key": (
            f"conformance-{contract.tool}" if contract.effect == ConnectorEffect.WRITE else None
        ),
    }
    checks: dict[str, bool] = {
        "adapter_supports_tool": executor.supports(contract.tool),
        "fixture_covers_sdk_arguments": set(arguments) == set(contract.supplied_arguments),
    }
    failures: list[str] = []
    if contract.effect == ConnectorEffect.WRITE:
        preview = executor.execute(ConnectorExecutionRequest(**base, preview_only=True))
        checks["preview_is_side_effect_free"] = (
            preview.status == ConnectorExecutionStatus.PREVIEW and not calls
        )
        pending = executor.execute(ConnectorExecutionRequest(**base))
        if contract.approval_required:
            checks["missing_approval_pauses"] = (
                pending.status == ConnectorExecutionStatus.PENDING_APPROVAL and not calls
            )
        approved_request = ConnectorExecutionRequest(
            **base,
            approval_ref="conformance-approval" if contract.approval_required else None,
        )
        completed = executor.execute(approved_request)
        replay = executor.execute(approved_request)
        conflict = executor.execute(
            approved_request.model_copy(
                update={"arguments": {**arguments, "conformance_nonce": "changed"}}
            )
        )
        checks["approved_execution_completes"] = completed.status == ConnectorExecutionStatus.COMPLETED
        checks["idempotent_replay_is_cached"] = replay.cached and len(calls) == 1
        checks["idempotency_conflict_fails"] = (
            conflict.error_kind == ConnectorErrorKind.IDEMPOTENCY_CONFLICT
        )
    else:
        completed = executor.execute(ConnectorExecutionRequest(**base))
        checks["read_execution_completes"] = (
            completed.status == ConnectorExecutionStatus.COMPLETED and len(calls) == 1
        )
    schema_checks, schema_failures = _schema_checks(
        contract,
        live,
        live_schema_checked=live_schema_checked,
    )
    checks.update(schema_checks)
    failures.extend(schema_failures)
    failures.extend(name for name, passed in checks.items() if not passed and name not in schema_checks)
    return ConnectorConformanceResult(
        tool=contract.tool,
        provider=contract.provider,
        primitive_refs=tuple(sorted(primitive_refs)),
        passed=all(checks.values()),
        checks=checks,
        failures=tuple(failures),
    )


def run_connector_conformance(
    *,
    live_tool_schemas: Iterable[Mapping[str, Any]] | None = None,
    contracts: Iterable[ConnectorToolContract] = CONNECTOR_TOOL_CONTRACTS,
) -> ConnectorConformanceReport:
    """Run deterministic policy checks and optional hosted-schema drift checks."""
    contract_values = tuple(contracts)
    contract_by_tool = {contract.tool: contract for contract in contract_values}
    primitive_tools = _primitive_tools()
    live_schema_checked = live_tool_schemas is not None
    live_by_name = _tool_schema_by_name(live_tool_schemas)
    missing = sorted(set(primitive_tools) - set(contract_by_tool))
    stale = sorted(set(contract_by_tool) - set(primitive_tools))
    results = [
        _run_contract(
            contract,
            primitive_tools.get(contract.tool, set()),
            live_by_name.get(contract.tool),
            live_schema_checked=live_schema_checked,
        )
        for contract in sorted(contract_values, key=lambda value: value.tool)
    ]
    failed_tools = [result.tool for result in results if not result.passed]
    failed_providers = sorted({result.provider for result in results if not result.passed})
    return ConnectorConformanceReport(
        passed=not missing and not stale and not failed_tools,
        contract_count=len(contract_values),
        provider_count=len({contract.provider for contract in contract_values}),
        live_schema_checked=live_schema_checked,
        missing_contracts=missing,
        stale_contracts=stale,
        failed_tools=failed_tools,
        failed_providers=failed_providers,
        results=results,
    )


__all__ = [
    "CONNECTOR_CONFORMANCE_SCHEMA",
    "CONNECTOR_TOOL_CONTRACTS",
    "ConnectorConformanceReport",
    "ConnectorConformanceResult",
    "ConnectorToolContract",
    "run_connector_conformance",
]
