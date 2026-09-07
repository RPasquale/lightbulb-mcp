"""Metered dispatch receipts: settle a worker's open dispatch from the platform's own cost record.

A workforce dispatch is opened with an *estimated* cost and the trace id the
platform returned (``dispatch_receipt_from_result``).  What the dispatch
actually cost lives with the platform: every dispatch runs as a workflow
instance whose telemetry carries the metered USD spend and whose status says
whether it completed, failed, or was cancelled.  ``meter_dispatch`` turns
that instance record into a ``MeteredDispatch`` and ``outcome_receipt`` turns
the metered dispatch into the exact ``record_outcome`` receipt the worker
lifecycle accepts, converting USD into the blueprint currency at a rate the
caller states explicitly.

Nothing here invents a cost: a still-running instance yields no outcome, a
missing cost yields no outcome, and a rate is required whenever the
blueprint currency is not USD.  The worker lifecycle's own guards (the open
dispatch must match, the actual cost must stay inside the overrun tolerance)
still decide whether the outcome is accepted.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    CurrencyCode,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)

METERED_DISPATCH_SCHEMA = "lightbulb.company_metered_dispatch.v1"
DispatchOutcome = Literal["succeeded", "failed", "running"]

_MICRO = Decimal("1000000")
_MICRO_QUANTUM = Decimal("0.000001")
_TERMINAL_SUCCESS = frozenset({"COMPLETED", "SUCCEEDED", "SUCCESS", "DONE"})
_TERMINAL_FAILURE = frozenset({"FAILED", "CANCELLED", "CANCELED", "ERROR", "TIMED_OUT", "TIMEOUT"})


class MeteringError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise MeteringError(code, message)


class MeteredDispatch(StrictModel):
    """One dispatch as the platform recorded it: status, metered USD, and the digest of the record it came from."""

    schema_id: str = Field(default=METERED_DISPATCH_SCHEMA, alias="schema")
    dispatch_ref: OpaqueRef
    trace_id: ShortText
    workflow_status: ShortText
    outcome: DispatchOutcome
    cost_micro_usd: int | None = Field(default=None, ge=0)
    model_input_units: int | None = Field(default=None, ge=0)
    model_output_units: int | None = Field(default=None, ge=0)
    completed_at: str | None = None
    waiting_for_approval: bool = False
    record_digest: Sha256Digest
    metered_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("completed_at")
    @classmethod
    def _completed(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="completed_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> MeteredDispatch:
        if self.outcome != "running" and self.cost_micro_usd is None:
            raise ValueError("a settled dispatch carries its metered cost")
        if not skip_digests(info) and self.metered_digest != sealed_digest(MeteredDispatch, self, "metered_digest"):
            raise ValueError("metered_digest must commit the exact metered dispatch")
        return self

    @property
    def settled(self) -> bool:
        return self.outcome != "running"

    @property
    def cost_usd(self) -> Decimal | None:
        return None if self.cost_micro_usd is None else (Decimal(self.cost_micro_usd) / _MICRO).quantize(_MICRO_QUANTUM)


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is not None and str(value).strip() != "":
            return value
    return None


def _status_outcome(status: str, *, error: Any) -> DispatchOutcome:
    upper = status.strip().upper()
    if upper in _TERMINAL_SUCCESS:
        return "failed" if error else "succeeded"
    if upper in _TERMINAL_FAILURE:
        return "failed"
    return "running"


def _timestamp_or_none(value: Any) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    if text.endswith("Z") or "+" in text[10:] or (len(text) > 19 and text[19] in "-+"):
        return timestamp(text, field_name="completed_at")
    return timestamp(text + "Z", field_name="completed_at")


def meter_dispatch(instance: Mapping[str, Any], *, dispatch_ref: str) -> MeteredDispatch:
    """The platform's workflow instance record (``get_workflow_instance``) as a sealed metered dispatch."""

    raw = dict(detached(instance))
    trace = str(raw.get("traceId") or raw.get("trace_id") or "").strip()
    _require(bool(trace), "INSTANCE_TRACE_MISSING", "the workflow instance names its trace id")
    _require(dispatch_ref == f"trace:{trace}", "DISPATCH_TRACE_MISMATCH", f"dispatch {dispatch_ref} was not opened for trace {trace}")
    status = str(raw.get("status") or raw.get("state") or "").strip()
    _require(bool(status), "INSTANCE_STATUS_MISSING", "the workflow instance names its status")
    telemetry = raw.get("telemetry") if isinstance(raw.get("telemetry"), Mapping) else {}
    cost_raw = telemetry.get("cost", telemetry.get("totalCostUsd", raw.get("totalCostUsd")))
    cost = None if cost_raw is None else int((Decimal(str(cost_raw)) * _MICRO).to_integral_value())
    _require(cost is None or cost >= 0, "INSTANCE_COST_INVALID", "a metered cost is never negative")
    outcome = _status_outcome(status, error=raw.get("error") or raw.get("errorCode"))
    if outcome != "running":
        _require(cost is not None, "INSTANCE_COST_MISSING", f"instance {trace} settled as {status} without a metered cost; do not record an outcome")
    # The workflow-instance endpoint returns the raw JPA entity (totalTokensIn / totalTokensOut) with no
    # telemetry object, so the telemetry names alone were permanently None.
    model_input_units = _first_present(telemetry.get("tokensIn"), raw.get("totalTokensIn"), raw.get("total_tokens_in"))
    model_output_units = _first_present(telemetry.get("tokensOut"), raw.get("totalTokensOut"), raw.get("total_tokens_out"))
    total_tokens = _first_present(raw.get("totalTokens"), raw.get("total_tokens"))
    if outcome != "running" and cost == 0:
        # WorkflowInstance.totalCostUsd defaults to 0.0, indistinguishable from a free dispatch: refuse when nothing was metered.
        tokens_known = sum(int(value) for value in (model_input_units, model_output_units, total_tokens) if value is not None)
        _require(tokens_known > 0, "INSTANCE_COST_MISSING", f"instance {trace} settled as {status} with cost 0 and no tokens; the cost was never metered, do not record an outcome")
    return seal(
        MeteredDispatch,
        {
            "dispatch_ref": dispatch_ref,
            "trace_id": trace,
            "workflow_status": status,
            "outcome": outcome,
            "cost_micro_usd": cost,
            "model_input_units": None if model_input_units is None else int(model_input_units),
            "model_output_units": None if model_output_units is None else int(model_output_units),
            "completed_at": _timestamp_or_none(raw.get("completedAt") or raw.get("completed_at")),
            "waiting_for_approval": bool(raw.get("waitingForApproval", False)),
            "record_digest": stable_digest({"trace_id": trace, "status": status, "cost_micro_usd": cost, "completed_at": raw.get("completedAt") or raw.get("completed_at")}),
        },
        "metered_digest",
    )


def outcome_receipt(metered: MeteredDispatch | Mapping[str, Any], *, currency: str, usd_rate: Any = None) -> dict[str, Any]:
    """The worker ``record_outcome`` receipt for a settled dispatch, with the cost converted into ``currency``."""

    parsed = metered if isinstance(metered, MeteredDispatch) else MeteredDispatch.model_validate(dict(detached(metered)))
    _require(parsed.settled, "DISPATCH_STILL_RUNNING", f"{parsed.trace_id} is {parsed.workflow_status}; no outcome to record yet")
    code = CurrencyCode(currency) if not isinstance(currency, str) else currency.strip().upper()
    _require(len(code) == 3 and code.isalpha(), "CURRENCY_INVALID", "currency is a three-letter code")
    cost_usd = parsed.cost_usd
    assert cost_usd is not None
    if code == "USD":
        rate = Decimal("1") if usd_rate is None else decimal_value(usd_rate, field_name="usd_rate")
        _require(rate == Decimal("1"), "RATE_NOT_APPLICABLE", "USD costs are not converted")
    else:
        _require(usd_rate is not None, "RATE_REQUIRED", f"converting USD into {code} needs an explicit usd_rate")
        rate = decimal_value(usd_rate, field_name="usd_rate")
        _require(rate > 0, "RATE_INVALID", "usd_rate must be positive")
    actual = (cost_usd * rate).quantize(MONEY_QUANTUM)
    return {"dispatch_ref": parsed.dispatch_ref, "outcome": parsed.outcome, "actual_cost": str(actual)}


def settle_dispatch(runtime: Any, *, worker_ref: str, instance: Mapping[str, Any], currency: str, occurred_at: str, actor_ref: str, usd_rate: Any = None) -> tuple[MeteredDispatch, Any | None]:
    """Meter the worker's open dispatch and, if settled, record its outcome through the worker runtime.

    Returns the metered dispatch and the runtime outcome (``None`` while the
    instance is still running).  ``runtime`` is an ``EngineRuntime`` over the
    worker lifecycle; the dispatch ref is read from the persisted worker
    ledger so the receipt can only settle the dispatch that is actually open.
    """

    state = runtime.load(worker_ref)
    open_ref = getattr(state.ledger, "open_dispatch_ref", None)
    _require(open_ref is not None, "NO_OPEN_DISPATCH", f"{worker_ref} has no dispatch awaiting an outcome")
    metered = meter_dispatch(instance, dispatch_ref=str(open_ref))
    if not metered.settled:
        return metered, None
    receipt = outcome_receipt(metered, currency=currency, usd_rate=usd_rate)
    command = runtime.command(state, event="record_outcome", transition_ref=f"outcome:{metered.trace_id}", idempotency_key=f"outcome:{metered.trace_id}", occurred_at=occurred_at, actor_ref=actor_ref, receipt=receipt)
    return metered, runtime.advance_and_persist(worker_ref, command)


DISPATCH_METERING_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_dispatch_metering",
    "golden_loop": "company_workforce",
    "stages": ["read_workflow_instance", "meter", "convert", "record_outcome"],
    "required_connectors": ["lightbulb.workflow_instances", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the metered cost comes from the platform's workflow instance telemetry, never from an estimate",
        "a running instance yields no outcome; a settled instance without a cost refuses to settle",
        "USD is converted into the blueprint currency only at an explicitly supplied rate",
        "only the dispatch the persisted worker ledger holds open can be settled",
    ],
}

__all__ = [
    "DISPATCH_METERING_MANIFEST",
    "METERED_DISPATCH_SCHEMA",
    "MeteredDispatch",
    "MeteringError",
    "meter_dispatch",
    "outcome_receipt",
    "settle_dispatch",
]
