"""Intelligence history: the headline figures of every recorded window kept as a series, the trends they show, and thresholds calibrated from the company's own past.

The figures an owner watches (revenue, net margin, cash, overdue
receivables, the cash conversion cycle, break-even margin of safety, hours
short) exist, but each only inside the document that computed it for one
window.  Nothing lined them up.  ``extract_metrics`` pulls a fixed set of
headline metrics from one window's documents, and ``build_history`` seals
the series across windows: per metric the latest value, the change on the
previous window, the direction over the last three, and a flag when a
figure has moved the wrong way three windows running.  A metric a window
could not build is a gap in the series, never a zero.

``calibrate_thresholds`` proposes plan settings from the series by plain
percentiles: the concentration ceiling at the 75th percentile of observed
top-customer share, the minimum cost share at half the observed median,
the receivable target at the 25th percentile of the cash cycle.  Proposals
only: they are returned for the owner to accept into the bundle, never
applied, and each states the observations it rests on and is declined
when there are fewer than the minimum.  Nothing here reads a provider; the
console assembles the windows from the documents it has persisted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp

INTELLIGENCE_HISTORY_SCHEMA = "lightbulb.intelligence_history.v1"
THRESHOLD_CALIBRATION_SCHEMA = "lightbulb.threshold_calibration.v1"
HISTORY_MANIFEST: dict[str, Any] = {"engine": "intelligence_history", "kind": "intelligence_document", "reads": ("books_snapshot", "customer_ledger", "working_capital", "break_even", "cash_calendar", "ledger_tie_out", "job_assignment"), "writes": ()}
# metric -> (document kind, field, unit, the direction that is good)
METRICS: dict[str, tuple[str, str, str, str]] = {
    "revenue": ("books_snapshot", "revenue", "money", "up"),
    "net_margin_percent": ("books_snapshot", "net_margin_percent", "percent", "up"),
    "cash": ("books_snapshot", "cash", "money", "up"),
    "cash_net_of_tax": ("books_snapshot", "cash_net_of_tax", "money", "up"),
    "cost_share_percent": ("books_snapshot", None, "percent", "flat"),
    "cash_conversion_days": ("working_capital", "cash_conversion_days", "days", "down"),
    "overdue_receivables": ("customer_ledger", "overdue", "money", "down"),
    "top_customer_share_percent": ("customer_ledger", "top_customer_share_percent", "percent", "down"),
    "margin_of_safety_percent": ("break_even", "margin_of_safety_percent", "percent", "up"),
    "lowest_cash_13_weeks": ("cash_calendar", "lowest_cash", "money", "up"),
    "hours_short": ("job_assignment", "hours_short", "hours", "down"),
    "tie_out_differences": ("ledger_tie_out", "outside_tolerance", "count", "down"),
    "open_actions": (None, None, "count", "down"),
}
Direction = Literal["up", "down", "flat", "unknown"]
_PCT = Decimal("0.01")


class HistoryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise HistoryError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _num(value: Any) -> Decimal | None:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except Exception:
        return None


def extract_metrics(documents: Mapping[str, Mapping[str, Any] | None], *, open_actions: int | None = None) -> dict[str, Decimal | None]:
    """The headline metrics from one window's documents by kind; a document missing from the mapping leaves its metrics ``None``."""

    out: dict[str, Decimal | None] = {}
    for metric, (kind, field, _unit, _good) in METRICS.items():
        if kind is None:
            out[metric] = None if open_actions is None else Decimal(open_actions)
            continue
        document = documents.get(kind)
        if not document:
            out[metric] = None
            continue
        document = dict(detached(document))
        if metric == "cost_share_percent":
            revenue = _num(document.get("revenue"))
            costs = sum((_num(document.get(key)) or Decimal("0") for key in ("cost_of_sales", "operating_expenses", "other_expenses")), Decimal("0"))
            out[metric] = None if not revenue or revenue <= 0 else (costs / revenue * 100).quantize(_PCT, rounding=ROUND_HALF_UP)
            continue
        out[metric] = _num(document.get(field))
    return out


class MetricSeries(StrictModel):
    metric: ShortText
    unit: ShortText
    good_direction: ShortText
    observations: int = Field(ge=0)
    latest: Decimal | None = None
    latest_window_ref: OpaqueRef | None = None
    previous: Decimal | None = None
    change: Decimal | None = None
    direction: Direction
    declining_windows: int = Field(ge=0)
    values: tuple[Decimal, ...] = Field(default_factory=tuple, max_length=104)

    @field_validator("values", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(decimal_value(item, field_name="values", allow_negative=True) for item in value) if isinstance(value, (list, tuple)) else value

    @field_validator("latest", "previous", "change", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class IntelligenceHistory(StrictModel):
    schema_id: str = Field(default=INTELLIGENCE_HISTORY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    windows: int = Field(ge=0)
    window_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=104)
    series: tuple[MetricSeries, ...] = Field(max_length=40)
    warnings: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    verdict: ShortText
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=104)
    history_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("window_refs", "series", "warnings", "notes", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "IntelligenceHistory":
        for row in self.series:
            if row.observations != len(row.values) or (row.latest is not None and row.values and row.latest != row.values[-1]):
                raise ValueError(f"{row.metric}: the observations count the values and the latest is the last")
        if not skip_digests(info) and self.history_digest != sealed_digest(IntelligenceHistory, self, "history_digest"):
            raise ValueError("history_digest must commit the exact history")
        return self

    def metric(self, name: str) -> MetricSeries:
        found = next((row for row in self.series if row.metric == name), None)
        if found is None:
            raise LookupError(f"{name} is not a tracked metric")
        return found

    def render(self) -> str:
        lines = [f"**Intelligence history** ({self.company_ref}, {self.windows} window(s) to {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- {row.metric}: {row.latest} ({row.direction}" + (f", {row.change:+} on the previous window" if row.change is not None else "") + ")" for row in self.series if row.latest is not None)
        lines.extend(f"- warning: {item}" for item in self.warnings)
        lines.extend(f"- note: {item}" for item in self.notes)
        return "\n".join(lines)


def build_history(windows: Sequence[Mapping[str, Any]], *, company_ref: str, currency: str, as_of: str) -> IntelligenceHistory:
    """The sealed series across windows, oldest first; each window is ``{window_ref, as_of, documents: {kind: document}, open_actions?}``."""

    ordered = sorted((dict(detached(item)) for item in windows), key=lambda item: str(item.get("as_of", "")))
    _require(bool(ordered), "WINDOWS_MISSING", "a history needs at least one window of recorded documents")
    per_window: list[tuple[str, dict[str, Decimal | None]]] = []
    lengths: list[tuple[str, int]] = []
    digests: list[str] = []
    for item in ordered:
        _require(bool(item.get("window_ref")) and bool(item.get("as_of")), "WINDOW_INCOMPLETE", "each window names a window_ref and an as_of")
        documents = dict(item.get("documents") or {})
        for kind, document in documents.items():
            if document is None:
                continue
            document = dict(detached(document))
            _require(document.get("company_ref") == company_ref and document.get("currency") == currency, "SOURCE_SCOPE_MISMATCH", f"the {kind} document in {item['window_ref']} names another company or currency")
            digest = next((value for key, value in document.items() if key.endswith("_digest") and key not in {"plan_digest", "books_digest", "margin_report_digest", "match_report_digest"} and isinstance(value, str) and len(value) == 64), None)
            if digest:
                digests.append(digest)
        per_window.append((str(item["window_ref"]), extract_metrics(documents, open_actions=item.get("open_actions"))))
        books = documents.get("books_snapshot")
        if books and books.get("window_start") and books.get("window_end"):
            lengths.append((str(item["window_ref"]), (parsed(str(books["window_end"])) - parsed(str(books["window_start"]))).days))
    series: list[dict[str, Any]] = []
    warnings: list[str] = []
    notes: list[str] = []
    if lengths and max(days for _ref, days in lengths) > 0 and min(days for _ref, days in lengths) * 2 < max(days for _ref, days in lengths):
        shortest = min(lengths, key=lambda item: item[1])
        longest = max(lengths, key=lambda item: item[1])
        notes.append(f"the windows are uneven ({shortest[0]} covers {shortest[1]} day(s), {longest[0]} {longest[1]}): money figures are not like for like across them, percentages and days are")
    for metric, (_kind, _field, unit, good) in METRICS.items():
        points = [(ref, values[metric]) for ref, values in per_window if values.get(metric) is not None]
        values = [value for _ref, value in points]
        latest = values[-1] if values else None
        previous = values[-2] if len(values) > 1 else None
        change = None if latest is None or previous is None else latest - previous
        last_three = values[-3:]
        if len(last_three) >= 2 and all(last_three[index] > last_three[index - 1] for index in range(1, len(last_three))):
            direction = "up"
        elif len(last_three) >= 2 and all(last_three[index] < last_three[index - 1] for index in range(1, len(last_three))):
            direction = "down"
        elif len(last_three) >= 2:
            direction = "flat"
        else:
            direction = "unknown"
        declining = 0
        if good in ("up", "down") and len(values) >= 2:
            for index in range(len(values) - 1, 0, -1):
                worse = values[index] < values[index - 1] if good == "up" else values[index] > values[index - 1]
                if worse:
                    declining += 1
                else:
                    break
        if declining >= 3:
            warnings.append(f"{metric} has moved the wrong way {declining} window(s) running: {values[-declining - 1]} -> {latest}")
        series.append({"metric": metric, "unit": unit, "good_direction": good, "observations": len(values), "latest": None if latest is None else str(latest), "latest_window_ref": points[-1][0] if points else None, "previous": None if previous is None else str(previous), "change": None if change is None else str(change), "direction": direction, "declining_windows": declining, "values": [str(value) for value in values]})
    tracked = sum(1 for row in series if row["observations"] > 0)
    verdict = f"{len(ordered)} window(s), {tracked} of {len(METRICS)} metric(s) observed" + (f"; {len(warnings)} warning(s), first: {warnings[0]}" if warnings else "; nothing has moved the wrong way three windows running")
    payload = {"company_ref": company_ref, "currency": str(currency).upper(), "as_of": timestamp(as_of, field_name="as_of"), "windows": len(ordered), "window_refs": [ref for ref, _values in per_window], "series": series, "warnings": [item[:300] for item in warnings][:24], "notes": [item[:300] for item in notes][:8], "verdict": verdict[:300], "source_digests": digests[:104]}
    return seal(IntelligenceHistory, {key: value for key, value in payload.items() if value is not None}, "history_digest")


def verify_intelligence_history(value: Any) -> IntelligenceHistory:
    return value if isinstance(value, IntelligenceHistory) else IntelligenceHistory.model_validate(dict(detached(value)))


# --------------------------------------------------------------------------- #
# Calibration
# --------------------------------------------------------------------------- #


def _percentile(values: Sequence[Decimal], percent: int) -> Decimal:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (Decimal(percent) / 100) * (len(ordered) - 1)
    lower = int(position)
    fraction = position - lower
    upper = min(lower + 1, len(ordered) - 1)
    return (ordered[lower] + (ordered[upper] - ordered[lower]) * fraction).quantize(_PCT, rounding=ROUND_HALF_UP)


# plan key, setting, the metric it rests on, the percentile, and how the proposal is derived
CALIBRATIONS: tuple[dict[str, Any], ...] = (
    {"plan": "customer_ledger", "setting": "concentration_ceiling_percent", "metric": "top_customer_share_percent", "percentile": 75, "basis": "the 75th percentile of the top customer's observed share, so the flag marks a genuinely unusual dependence"},
    {"plan": "books_snapshot", "setting": "minimum_cost_share_percent", "metric": "cost_share_percent", "percentile": 50, "scale": Decimal("0.5"), "basis": "half the median observed cost share, so the books are called thin only well below their own norm"},
    {"plan": "working_capital", "setting": "receivable_days_target", "metric": "cash_conversion_days", "percentile": 25, "integer": True, "basis": "the 25th percentile of the observed cash conversion cycle, so the target is the company's own good weeks"},
)


class ThresholdProposal(StrictModel):
    plan: ShortText
    setting: ShortText
    proposed: Decimal
    observations: int = Field(ge=1)
    basis: ShortText
    metric: ShortText

    @field_validator("proposed", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="proposed", allow_negative=True)


class ThresholdCalibration(StrictModel):
    schema_id: str = Field(default=THRESHOLD_CALIBRATION_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    history_digest: Sha256Digest
    minimum_observations: int = Field(ge=1)
    proposals: tuple[ThresholdProposal, ...] = Field(default_factory=tuple, max_length=12)
    declined: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    verdict: ShortText
    calibration_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("proposals", "declined", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ThresholdCalibration":
        if any(item.observations < self.minimum_observations for item in self.proposals):
            raise ValueError("a proposal rests on at least the minimum observations")
        if not skip_digests(info) and self.calibration_digest != sealed_digest(ThresholdCalibration, self, "calibration_digest"):
            raise ValueError("calibration_digest must commit the exact calibration")
        return self


def calibrate_thresholds(history: Mapping[str, Any] | Any, *, as_of: str, minimum_observations: int = 6) -> ThresholdCalibration:
    """Plan settings proposed from the company's own series by percentile; proposals only, for the owner to accept into the bundle."""

    parsed = verify_intelligence_history(history)
    _require(1 <= minimum_observations <= 52, "MINIMUM_INVALID", "the minimum is 1 to 52 observations")
    proposals: list[dict[str, Any]] = []
    declined: list[str] = []
    for rule in CALIBRATIONS:
        row = parsed.metric(rule["metric"])
        if row.observations < minimum_observations:
            declined.append(f"{rule['plan']}.{rule['setting']}: {row.observations} observation(s) of {rule['metric']}, fewer than the {minimum_observations} needed")
            continue
        value = _percentile(list(row.values), rule["percentile"]) * rule.get("scale", Decimal("1"))
        if rule.get("integer"):
            value = Decimal(int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP)))
        proposals.append({"plan": rule["plan"], "setting": rule["setting"], "proposed": str(value.quantize(_PCT, rounding=ROUND_HALF_UP)), "observations": row.observations, "basis": rule["basis"][:300], "metric": rule["metric"]})
    verdict = f"{len(proposals)} setting(s) proposed from {parsed.windows} window(s), {len(declined)} declined for too few observations; nothing is applied until accepted into the bundle"
    return seal(ThresholdCalibration, {"company_ref": parsed.company_ref, "as_of": timestamp(as_of, field_name="as_of"), "history_digest": parsed.history_digest, "minimum_observations": minimum_observations, "proposals": proposals, "declined": [item[:300] for item in declined], "verdict": verdict[:300]}, "calibration_digest")


__all__ = ["CALIBRATIONS", "HISTORY_MANIFEST", "INTELLIGENCE_HISTORY_SCHEMA", "METRICS", "THRESHOLD_CALIBRATION_SCHEMA", "HistoryError", "IntelligenceHistory", "MetricSeries", "ThresholdCalibration", "ThresholdProposal", "build_history", "calibrate_thresholds", "extract_metrics", "verify_intelligence_history"]
