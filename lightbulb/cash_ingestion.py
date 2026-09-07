"""Cash evidence ingestion: the front door to the runway engine.

Turns a raw cash-report response into an UNSEALED
:class:`~lightbulb.cash_runway.CashLedgerEvidence` body that a trusted host
then seals with :func:`lightbulb.mint_cash_ledger_evidence`. Nothing here does
I/O, holds a keyring, or fabricates trust — it only maps a known response shape
onto the canonical cash-basis envelope.

Shares the money-ingestion honesty rules (see
:mod:`lightbulb.growth_money_ingestion`):

- **Only recognized fields map.** Any other numeric field is *reported* in the
  coverage result, never silently absorbed and never guessed.
- **Missing metric = absent, never zero.** A flow the response does not carry is
  simply not set (unknown is not zero, all the way down to the runway).
- **Shape mismatches fail loudly**, naming the provider and the expectation.
- **Provenance-bound digest.** ``evidence_digest`` binds the SHA-256 of the
  canonical raw response.

Producer status (2026-08-21). The platform has **no bank/Plaid connector**, so
the truest and most complete cash source — inflows, outflows, and the ending
balance from one statement — arrives as an operator/accountant *import*
(``bank.statement_import``), whose shape is defined right here and therefore
pinned. The governed ``stripe.list_balance_transactions`` response now has a
separate, strict monthly settlement-observation primitive, but it is
intentionally not mapped into this cash envelope: Stripe sees revenue and fees,
not complete bank inflows, payroll, rent, operating outflows, or ending cash,
so it cannot establish business burn. The Xero and QuickBooks cash-report
response shapes remain unpinned. All three capabilities therefore fail loudly
here rather than being guessed into complete cash evidence.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .cash_runway import CashFlowMetrics, CashLedgerEvidence, CashProvider

CASH_INGESTION_RESULT_SCHEMA = "lightbulb.cash_ingestion_result.v1"

_MONEY_QUANTUM = Decimal("0.01")

# Capability -> provider. Connector-side reports are listed with producer=None so
# discovery is honest about exactly what is refused and why.
SUPPORTED_CASH_CAPABILITIES: dict[str, str | None] = {
    "bank.statement_import": "bank",
    "stripe.list_balance_transactions": None,
    "xero.cash_flow_report": None,
    "quickbooks.cash_flow_report": None,
}

# bank.statement_import field -> canonical cash metric. A period bank statement
# summary carries total credits (inflows), total debits (outflows), and the
# closing balance. Synonyms are accepted; anything else numeric is reported.
_BANK_STATEMENT_FIELDS: dict[str, str] = {
    "cash_inflows": "cash_inflows",
    "total_credits": "cash_inflows",
    "credits": "cash_inflows",
    "deposits": "cash_inflows",
    "cash_outflows": "cash_outflows",
    "total_debits": "cash_outflows",
    "debits": "cash_outflows",
    "withdrawals": "cash_outflows",
    "ending_cash_balance": "ending_cash_balance",
    "closing_balance": "ending_cash_balance",
    "ending_balance": "ending_cash_balance",
}


class CashIngestionError(ValueError):
    """A connector response cannot be normalized into cash evidence."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _as_decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, Decimal):
        return value if value.is_finite() else None
    if isinstance(value, (int, float, str)):
        lexical = str(value).strip()
        if not lexical or len(lexical) > 48:
            return None
        try:
            parsed = Decimal(lexical)
        except (InvalidOperation, ValueError):
            return None
        return parsed if parsed.is_finite() else None
    return None


def _as_money(value: Any) -> Decimal | None:
    parsed = _as_decimal(value)
    if parsed is None or parsed < 0:
        return None
    return parsed.quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class CashCoverage(_StrictModel):
    """An honest account of what cash ingestion did and did not map."""

    provider: CashProvider
    source_capability: str
    populated_metrics: tuple[str, ...]
    source_fields_used: tuple[str, ...]
    unrecognized_response_fields: tuple[str, ...]


class CashIngestionResult(_StrictModel):
    schema_id: Literal["lightbulb.cash_ingestion_result.v1"] = Field(
        default=CASH_INGESTION_RESULT_SCHEMA,
        alias="schema",
    )
    evidence: CashLedgerEvidence
    coverage: CashCoverage

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _refuse_unpinned(capability: str) -> str:
    if capability not in SUPPORTED_CASH_CAPABILITIES:
        raise CashIngestionError(
            f"no cash-ingestion adapter for capability {capability!r}; "
            f"supported: {sorted(SUPPORTED_CASH_CAPABILITIES)}"
        )
    producer = SUPPORTED_CASH_CAPABILITIES[capability]
    if producer is None:
        if capability == "stripe.list_balance_transactions":
            raise CashIngestionError(
                "the governed Stripe settlement observation is not available as "
                "complete cash-ingestion evidence; it excludes bank balance and "
                "non-Stripe operating outflows (unknown is not zero)"
            )
        raise CashIngestionError(
            f"the {capability!r} response shape is not pinned in-repo yet; "
            "refusing to guess at a cash envelope (unknown is not zero). The bank "
            "statement (bank.statement_import) is the recommended, complete cash "
            "source; pin the connector shape and add its map to enable it"
        )
    return producer


def normalize_cash_response(
    *,
    source_capability: str,
    response: Mapping[str, Any],
    observation_ref: str,
    connector_account_ref: str,
    currency: str,
    window_start: str,
    window_end: str,
    observed_at: str,
) -> CashIngestionResult:
    """Normalize one raw cash response into sealable cash evidence.

    Returns an UNSEALED :class:`CashLedgerEvidence` body (no attestation trio)
    ready for :func:`lightbulb.mint_cash_ledger_evidence`, plus an honest
    coverage report. ``currency`` is caller-supplied: the governed route knows
    the account currency, and this module must not guess it.
    """

    provider = _refuse_unpinned(source_capability)
    if not isinstance(response, Mapping):
        raise CashIngestionError(
            f"cash response must be an object, got {type(response).__name__}"
        )

    metrics: dict[str, Any] = {}
    used: set[str] = set()
    unrecognized: list[str] = []
    for key, value in response.items():
        canonical = _BANK_STATEMENT_FIELDS.get(str(key))
        if canonical is None:
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                unrecognized.append(str(key))
            continue
        money = _as_money(value)
        if money is None:
            # Recognized field, but the value is unusable (e.g. a signed/negative
            # debit total). Do not silently swallow it — surface it as unmapped so
            # the operator sees a cash field was seen and dropped.
            if isinstance(value, (int, float, str)) and not isinstance(value, bool):
                unrecognized.append(str(key))
            continue
        if canonical in metrics:
            # A statement should not carry two synonyms for the same metric with
            # different values; that is an ambiguous response, not a sum.
            if metrics[canonical] != money:
                raise CashIngestionError(
                    f"cash response carries conflicting values for {canonical!r}"
                )
            continue
        metrics[canonical] = money
        used.add(str(key))

    if not metrics:
        raise CashIngestionError(
            "the bank statement carried no recognized cash field "
            "(inflows / outflows / ending balance); nothing to ingest "
            "(unknown is not zero)"
        )

    evidence = CashLedgerEvidence.model_validate(
        {
            "observation_ref": observation_ref,
            "connector_account_ref": connector_account_ref,
            "provider": provider,
            "source_capability": source_capability,
            "currency": currency,
            "observed_at": observed_at,
            "window_start": window_start,
            "window_end": window_end,
            "metrics": CashFlowMetrics.model_validate(metrics).model_dump(
                mode="python", exclude_none=True
            ),
            "evidence_digest": _stable_digest(dict(response)),
        }
    )
    coverage = CashCoverage(
        provider=provider,
        source_capability=source_capability,
        populated_metrics=tuple(sorted(metrics)),
        source_fields_used=tuple(sorted(used)),
        unrecognized_response_fields=tuple(unrecognized),
    )
    return CashIngestionResult(evidence=evidence, coverage=coverage)


def cash_ingestion_capabilities() -> tuple[dict[str, Any], ...]:
    """Discoverable list of cash-ingestion capabilities and their status."""

    return tuple(
        {
            "source_capability": capability,
            "producer": producer,
            "status": "available" if producer else "shape_not_pinned",
        }
        for capability, producer in sorted(SUPPORTED_CASH_CAPABILITIES.items())
    )


__all__ = [
    "CASH_INGESTION_RESULT_SCHEMA",
    "SUPPORTED_CASH_CAPABILITIES",
    "CashCoverage",
    "CashIngestionError",
    "CashIngestionResult",
    "cash_ingestion_capabilities",
    "normalize_cash_response",
]
