"""App signals: what a generated app reports back about itself, and what the company makes of it.

An app the factory built runs somewhere with people using it.  Its
server-side bridge module reports signals: a user's feedback, an error with
its signature, usage, the release it is running.  Each signal is data
routed by the app's key; it carries no authority, no secret, no identity
beyond an opaque reporter reference, and it is bounded in size.  A batch is
the sealed set the platform hands over; the same signal twice is one signal.

From the batches the company reads three things: the summary (what each
app's users did and hit in the window), the error rollup (each error
signature counted across releases, with the ones past the threshold marked),
and change candidates for the errors that crossed it, so a spike becomes
work through the same joint as a user's feedback.  Nothing here reaches the
app, the platform, or a provider; deterministic.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationError, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, BoundedText, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, reject_secret_like_payload, seal, sealed_digest, skip_digests, stable_digest, timestamp

APP_SIGNAL_SCHEMA = "lightbulb.app_signal.v1"
APP_SIGNAL_BATCH_SCHEMA = "lightbulb.app_signal_batch.v1"
APP_ERROR_ROLLUP_SCHEMA = "lightbulb.app_error_rollup.v1"
APP_SIGNALS_SUMMARY_SCHEMA = "lightbulb.app_signals_summary.v1"
APP_SIGNALS_MANIFEST: dict[str, Any] = {"engine": "app_signals", "kind": "observation", "reads": ("app_signal_batch",), "writes": ("app_signal_batch", "change_candidate")}
SignalKind = Literal["feedback", "error", "usage", "release"]
SIGNAL_KINDS: tuple[str, ...] = ("feedback", "error", "usage", "release")
MAX_BATCH = 500
DEFAULT_WINDOW_DAYS = 7
DEFAULT_ERROR_THRESHOLD = 3


class AppSignalError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AppSignalError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class _SignalJsonModel(StrictModel):
    @classmethod
    def model_validate_json(cls, json_data: Any, **kwargs: Any):
        try:
            return super().model_validate_json(json_data, **kwargs)
        except ValidationError as error:
            # Invalid JSON fails before model validators can recognize support
            # data (including escaped keys). Never echo an unparsed document.
            # Valid non-support signals retain their existing diagnostics.
            if any(item["type"] == "json_invalid" for item in error.errors(include_input=False)):
                from lightbulb.support_validation import support_validation_error
                raise support_validation_error(error) from None
            raise


class AppSignal(_SignalJsonModel):
    schema_id: str = Field(default=APP_SIGNAL_SCHEMA, alias="schema")
    signal_ref: OpaqueRef
    app_ref: OpaqueRef
    kind: SignalKind
    occurred_at: str
    release_ref: OpaqueRef | None = None
    page: ShortText | None = None
    text: BoundedText | None = None
    error_signature: ShortText | None = None
    error_message: BoundedText | None = None
    count: int = Field(default=1, ge=1, le=1_000_000)
    reporter_ref: OpaqueRef | None = None
    support_fix_brief: dict[str, Any] | None = None

    @field_validator("occurred_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="occurred_at")

    @field_validator("page", "text", "error_signature", "error_message")
    @classmethod
    def _plain(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is not None:
            reject_secret_like_payload(value, path=str(info.field_name))
        return value

    @model_validator(mode="after")
    def _shape(self) -> "AppSignal":
        if self.support_fix_brief is not None:
            from lightbulb.support_reports import SupportFixBrief
            brief = SupportFixBrief.model_validate(self.support_fix_brief)
            if self.kind != "feedback" or brief.app_ref != self.app_ref or self.signal_ref != "support:" + brief.brief_digest or self.occurred_at != brief.report.received_at:
                raise ValueError("SUPPORT_SIGNAL_BINDING_MISMATCH")
        if self.kind == "feedback" and not (self.text or "").strip():
            raise ValueError("a feedback signal carries the user's words")
        if self.kind == "error" and not (self.error_signature or "").strip():
            raise ValueError("an error signal carries its signature")
        if self.kind == "release" and self.release_ref is None:
            raise ValueError("a release signal names the release")
        if self.kind != "error" and (self.error_signature or self.error_message):
            raise ValueError("only an error signal carries an error")
        return self

    @model_validator(mode="wrap")
    @classmethod
    def _support_diagnostics(cls, value: Any, handler: Any) -> Any:
        support = value.get("support_fix_brief") if isinstance(value, Mapping) else getattr(value, "support_fix_brief", None)
        if support is not None:
            from lightbulb.support_validation import safe_support_validation
            return safe_support_validation(handler)(value)
        return handler(value)


class AppSignalBatch(_SignalJsonModel):
    schema_id: str = Field(default=APP_SIGNAL_BATCH_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    app_ref: OpaqueRef
    received_at: str
    signals: tuple[AppSignal, ...] = Field(min_length=1, max_length=MAX_BATCH)
    counts: dict[str, int]
    batch_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("signals", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("received_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="received_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "AppSignalBatch":
        refs = [signal.signal_ref for signal in self.signals]
        if len(set(refs)) != len(refs):
            raise ValueError("a signal appears once in a batch")
        if any(signal.app_ref != self.app_ref for signal in self.signals):
            raise ValueError("every signal in a batch belongs to the batch's app")
        if [(signal.occurred_at, signal.signal_ref) for signal in self.signals] != sorted((signal.occurred_at, signal.signal_ref) for signal in self.signals):
            raise ValueError("signals are ordered by when they occurred, then by reference")
        expected = {kind: sum(signal.count for signal in self.signals if signal.kind == kind) for kind in SIGNAL_KINDS if any(signal.kind == kind for signal in self.signals)}
        if self.counts != expected:
            raise ValueError("counts are the signals summed per kind")
        if not skip_digests(info) and self.batch_digest != sealed_digest(AppSignalBatch, self, "batch_digest"):
            raise ValueError("batch_digest must commit the exact batch")
        return self

    @model_validator(mode="wrap")
    @classmethod
    def _support_diagnostics(cls, value: Any, handler: Any) -> Any:
        signals = value.get("signals") if isinstance(value, Mapping) else getattr(value, "signals", None)
        if isinstance(signals, (tuple, list)) and any(
            (signal.get("support_fix_brief") if isinstance(signal, Mapping) else getattr(signal, "support_fix_brief", None)) is not None
            for signal in signals
        ):
            from lightbulb.support_validation import safe_support_validation
            return safe_support_validation(handler)(value)
        return handler(value)

    def render(self) -> str:
        return f"**App signals** {self.app_ref} ({self.company_ref}, received {self.received_at[:10]}): " + ", ".join(f"{count} {kind}" for kind, count in self.counts.items())


def compile_app_signal_batch(company_ref: str, *, app_ref: str, signals: Sequence[Mapping[str, Any]], received_at: str) -> AppSignalBatch:
    """The sealed batch: the same signal reference twice is one signal (the first wins), a signal from another app is refused, and the batch is ordered by time."""

    _require(len(tuple(signals)) >= 1, "BATCH_EMPTY", "a batch carries at least one signal")
    _require(len(tuple(signals)) <= MAX_BATCH, "BATCH_TOO_LARGE", f"a batch carries at most {MAX_BATCH} signals; split it")
    seen: dict[str, AppSignal] = {}
    for raw in signals:
        signal = AppSignal.model_validate({key: value for key, value in dict(detached(raw)).items() if key != "schema"} | {"schema": APP_SIGNAL_SCHEMA})
        _require(signal.app_ref == app_ref, "APP_MISMATCH", f"signal {signal.signal_ref} belongs to {signal.app_ref}, not {app_ref}")
        seen.setdefault(signal.signal_ref, signal)
    ordered = sorted(seen.values(), key=lambda signal: (signal.occurred_at, signal.signal_ref))
    counts = {kind: sum(signal.count for signal in ordered if signal.kind == kind) for kind in SIGNAL_KINDS if any(signal.kind == kind for signal in ordered)}
    return seal(AppSignalBatch, {"company_ref": company_ref, "app_ref": app_ref, "received_at": timestamp(received_at, field_name="received_at"), "signals": [signal.to_dict() for signal in ordered], "counts": counts}, "batch_digest")


def verify_app_signal_batch(value: Any) -> AppSignalBatch:
    return value if isinstance(value, AppSignalBatch) else AppSignalBatch.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "version", "entity_ref", "unchanged"}})


def _in_window(batches: Sequence[Mapping[str, Any]], *, company_ref: str, as_of: str, window_days: int) -> list[tuple[AppSignalBatch, AppSignal]]:
    at = parsed(as_of)
    rows: list[tuple[AppSignalBatch, AppSignal]] = []
    seen: set[tuple[str, str]] = set()
    for raw in batches:
        batch = verify_app_signal_batch(raw)
        _require(batch.company_ref == company_ref, "SOURCE_SCOPE_MISMATCH", f"a batch for {batch.company_ref} is not this company's")
        for signal in batch.signals:
            key = (batch.app_ref, signal.signal_ref)
            if key in seen or (at - parsed(signal.occurred_at)).days >= window_days or parsed(signal.occurred_at) > at:
                continue
            seen.add(key)
            rows.append((batch, signal))
    return rows


class ErrorRollupRow(StrictModel):
    app_ref: OpaqueRef
    error_signature: ShortText
    count: int = Field(ge=1)
    first_seen: str
    last_seen: str
    releases: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    pages: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    sample_message: BoundedText | None = None
    over_threshold: bool

    @field_validator("releases", "pages", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)


class ErrorRollup(StrictModel):
    schema_id: str = Field(default=APP_ERROR_ROLLUP_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    window_days: int = Field(ge=1, le=365)
    threshold: int = Field(ge=1)
    rows: tuple[ErrorRollupRow, ...] = Field(default_factory=tuple, max_length=500)
    errors_total: int = Field(ge=0)
    over_threshold: int = Field(ge=0)
    verdict: ShortText
    rollup_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ErrorRollup":
        if not skip_digests(info) and self.rollup_digest != sealed_digest(ErrorRollup, self, "rollup_digest"):
            raise ValueError("rollup_digest must commit the exact rollup")
        return self

    def render(self) -> str:
        lines = [f"**App errors** ({self.company_ref}, {self.window_days} days to {self.as_of[:10]}): {self.verdict}"]
        for row in self.rows:
            if row.over_threshold:
                lines.append(f"- {row.app_ref}: {row.error_signature} x{row.count} ({row.first_seen[:10]} to {row.last_seen[:10]}" + (f", releases {', '.join(row.releases)}" if row.releases else "") + ")")
        return "\n".join(lines)


def rollup_errors(company_ref: str, *, batches: Sequence[Mapping[str, Any]], as_of: str, window_days: int = DEFAULT_WINDOW_DAYS, threshold: int = DEFAULT_ERROR_THRESHOLD) -> ErrorRollup:
    """Every error signature seen in the window, counted across batches and releases, most seen first; the ones at or past the threshold are marked."""

    at = timestamp(as_of, field_name="as_of")
    _require(int(threshold) >= 1, "THRESHOLD_INVALID", "the threshold is at least one")
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for batch, signal in _in_window(batches, company_ref=company_ref, as_of=at, window_days=int(window_days)):
        if signal.kind != "error":
            continue
        entry = groups.setdefault((batch.app_ref, str(signal.error_signature)), {"app_ref": batch.app_ref, "error_signature": signal.error_signature, "count": 0, "first_seen": signal.occurred_at, "last_seen": signal.occurred_at, "releases": set(), "pages": set(), "sample_message": None})
        entry["count"] += signal.count
        entry["first_seen"] = min(entry["first_seen"], signal.occurred_at)
        entry["last_seen"] = max(entry["last_seen"], signal.occurred_at)
        if signal.release_ref:
            entry["releases"].add(signal.release_ref)
        if signal.page:
            entry["pages"].add(signal.page)
        if entry["sample_message"] is None and signal.error_message:
            entry["sample_message"] = signal.error_message
    rows = sorted(({**entry, "releases": sorted(entry["releases"])[:50], "pages": sorted(entry["pages"])[:20], "over_threshold": entry["count"] >= int(threshold)} for entry in groups.values()), key=lambda row: (-row["count"], row["app_ref"], row["error_signature"]))
    total = sum(row["count"] for row in rows)
    over = sum(1 for row in rows if row["over_threshold"])
    verdict = "no error reported" if not rows else f"{total} error(s) across {len(rows)} signature(s); {over} at or past {threshold} in {window_days} day(s)"
    return seal(ErrorRollup, {"company_ref": company_ref, "as_of": at, "window_days": int(window_days), "threshold": int(threshold), "rows": rows[:500], "errors_total": total, "over_threshold": over, "verdict": verdict[:300]}, "rollup_digest")


def verify_error_rollup(value: Any) -> ErrorRollup:
    return value if isinstance(value, ErrorRollup) else ErrorRollup.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed"}})


def candidate_from_error_rollup(company_ref: str, *, project_id: str, row: Mapping[str, Any]) -> Any:
    """An error signature past the threshold as a defect candidate; its reference is stable per app and signature, so the same spike next week is the same candidate."""

    from lightbulb.change_candidate import compile_change_candidate, safe_ref

    parsed_row = ErrorRollupRow.model_validate(dict(detached(row)))
    _require(parsed_row.over_threshold, "UNDER_THRESHOLD", f"{parsed_row.error_signature} was seen {parsed_row.count} time(s), under the threshold")
    text = f"{parsed_row.error_signature}\nSeen {parsed_row.count} time(s) between {parsed_row.first_seen[:16]}Z and {parsed_row.last_seen[:16]}Z" + (f" on release(s) {', '.join(parsed_row.releases)}" if parsed_row.releases else "") + (f", on {', '.join(parsed_row.pages)}" if parsed_row.pages else "") + "." + (f"\nSample: {parsed_row.sample_message}" if parsed_row.sample_message else "")
    evidence = [safe_ref(parsed_row.error_signature, prefix="error:")] + [safe_ref(page, prefix="page:") for page in parsed_row.pages]
    return compile_change_candidate(company_ref, project_id=project_id, source="error_signal", source_ref=safe_ref(f"{parsed_row.app_ref}:{parsed_row.error_signature}", prefix="error:"), text=text, received_at=parsed_row.last_seen, app_ref=parsed_row.app_ref, evidence_refs=evidence, kind="defect")


class AppSummaryRow(StrictModel):
    app_ref: OpaqueRef
    feedback: int = Field(ge=0)
    errors: int = Field(ge=0)
    error_signatures: int = Field(ge=0)
    usage: int = Field(ge=0)
    releases: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    latest_release: OpaqueRef | None = None
    first_signal: str
    last_signal: str

    @field_validator("releases", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)


class AppSignalsSummary(StrictModel):
    schema_id: str = Field(default=APP_SIGNALS_SUMMARY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    window_days: int = Field(ge=1, le=365)
    apps: tuple[AppSummaryRow, ...] = Field(default_factory=tuple, max_length=200)
    verdict: ShortText
    summary_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("apps", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "AppSignalsSummary":
        if not skip_digests(info) and self.summary_digest != sealed_digest(AppSignalsSummary, self, "summary_digest"):
            raise ValueError("summary_digest must commit the exact summary")
        return self

    def render(self) -> str:
        lines = [f"**App signals** ({self.company_ref}, {self.window_days} days to {self.as_of[:10]}): {self.verdict}"]
        for row in self.apps:
            lines.append(f"- {row.app_ref}: {row.feedback} feedback, {row.errors} error(s) in {row.error_signatures} signature(s), {row.usage} usage" + (f", running {row.latest_release}" if row.latest_release else ""))
        return "\n".join(lines)


def summarise_app_signals(company_ref: str, *, batches: Sequence[Mapping[str, Any]], as_of: str, window_days: int = DEFAULT_WINDOW_DAYS) -> AppSignalsSummary:
    """What each app's users did and hit in the window, from the batches on record; a signal is counted once however many batches carry it."""

    at = timestamp(as_of, field_name="as_of")
    apps: dict[str, dict[str, Any]] = {}
    for batch, signal in _in_window(batches, company_ref=company_ref, as_of=at, window_days=int(window_days)):
        entry = apps.setdefault(batch.app_ref, {"app_ref": batch.app_ref, "feedback": 0, "errors": 0, "signatures": set(), "usage": 0, "releases": {}, "first_signal": signal.occurred_at, "last_signal": signal.occurred_at})
        entry["first_signal"] = min(entry["first_signal"], signal.occurred_at)
        entry["last_signal"] = max(entry["last_signal"], signal.occurred_at)
        if signal.kind == "feedback":
            entry["feedback"] += signal.count
        elif signal.kind == "error":
            entry["errors"] += signal.count
            entry["signatures"].add(signal.error_signature)
        elif signal.kind == "usage":
            entry["usage"] += signal.count
        if signal.release_ref:
            entry["releases"][signal.release_ref] = max(entry["releases"].get(signal.release_ref, ""), signal.occurred_at)
    rows = []
    for entry in sorted(apps.values(), key=lambda item: item["app_ref"]):
        releases = entry["releases"]
        latest = max(releases, key=lambda ref: (releases[ref], ref)) if releases else None
        rows.append({"app_ref": entry["app_ref"], "feedback": entry["feedback"], "errors": entry["errors"], "error_signatures": len(entry["signatures"]), "usage": entry["usage"], "releases": sorted(releases)[:50], "latest_release": latest, "first_signal": entry["first_signal"], "last_signal": entry["last_signal"]})
    verdict = "no app has reported in the window" if not rows else f"{len(rows)} app(s): {sum(row['feedback'] for row in rows)} feedback, {sum(row['errors'] for row in rows)} error(s), {sum(row['usage'] for row in rows)} usage"
    return seal(AppSignalsSummary, {"company_ref": company_ref, "as_of": at, "window_days": int(window_days), "apps": rows[:200], "verdict": verdict[:300]}, "summary_digest")


def verify_app_signals_summary(value: Any) -> AppSignalsSummary:
    return value if isinstance(value, AppSignalsSummary) else AppSignalsSummary.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed"}})


def feedback_signals(company_ref: str, *, batches: Sequence[Mapping[str, Any]], as_of: str, window_days: int = DEFAULT_WINDOW_DAYS) -> list[AppSignal]:
    """Every feedback signal in the window, each once, oldest first."""

    at = timestamp(as_of, field_name="as_of")
    return [signal for _batch, signal in _in_window(batches, company_ref=company_ref, as_of=at, window_days=int(window_days)) if signal.kind == "feedback"]


def candidate_from_feedback_signal(company_ref: str, *, project_id: str, signal: Mapping[str, Any] | AppSignal) -> Any:
    """A user's feedback from inside an app as a change candidate, through the same joint as a submission; its reference is stable per app and signal."""

    from lightbulb.change_candidate import compile_change_candidate, safe_ref

    parsed_signal = signal if isinstance(signal, AppSignal) else AppSignal.model_validate({**dict(detached(signal)), "schema": APP_SIGNAL_SCHEMA})
    _require(parsed_signal.kind == "feedback", "NOT_FEEDBACK", f"signal {parsed_signal.signal_ref} is {parsed_signal.kind}, not feedback")
    evidence = [safe_ref(parsed_signal.page, prefix="page:")] if parsed_signal.page else []
    if parsed_signal.release_ref:
        evidence.append(safe_ref(parsed_signal.release_ref, prefix="release:"))
    return compile_change_candidate(company_ref, project_id=project_id, source="feedback", source_ref=safe_ref(f"{parsed_signal.app_ref}:{parsed_signal.signal_ref}", prefix="signal:"), text=str(parsed_signal.text), received_at=parsed_signal.occurred_at, reporter_ref=parsed_signal.reporter_ref, app_ref=parsed_signal.app_ref, evidence_refs=evidence)


RELEASE_HEALTH_SCHEMA = "lightbulb.release_health.v1"
# the least use a release needs before its error rate says anything; a quiet app's three errors are not evidence
DEFAULT_MIN_USAGE = 200
# a release whose error rate is this many times its predecessor's, with at least this many errors, has regressed
DEFAULT_REGRESSION_FACTOR = Decimal("1.5")
DEFAULT_MIN_ERRORS = 3
ReleaseVerdict = Literal["healthy", "regressed", "insufficient_evidence", "no_baseline"]


class ReleaseReading(StrictModel):
    release_ref: OpaqueRef
    released_at: str | None = None
    usage: int = Field(ge=0)
    errors: int = Field(ge=0)
    errors_per_thousand: Decimal | None = None
    signatures: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("signatures", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("errors_per_thousand", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="errors_per_thousand")


class ReleaseHealth(StrictModel):
    schema_id: str = Field(default=RELEASE_HEALTH_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    app_ref: OpaqueRef
    as_of: str
    release: ReleaseReading
    baseline: ReleaseReading | None = None
    new_signatures: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=100)
    verdict: ReleaseVerdict
    reason: ShortText
    rollback_to: OpaqueRef | None = None
    health_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("new_signatures", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ReleaseHealth":
        if (self.verdict == "regressed") != (self.rollback_to is not None):
            raise ValueError("a rollback target is named exactly when the release regressed")
        if not skip_digests(info) and self.health_digest != sealed_digest(ReleaseHealth, self, "health_digest"):
            raise ValueError("health_digest must commit the exact reading")
        return self

    def render(self) -> str:
        head = f"**Release {self.release.release_ref}** ({self.app_ref}, {self.as_of[:10]}): {self.verdict.replace('_', ' ')}; {self.reason}"
        return head + (f"\n- the owner decides whether to roll back to {self.rollback_to} (a deploy the factory does not execute alone)" if self.rollback_to else "")


def _per_thousand(errors: int, usage: int) -> Decimal | None:
    return None if usage <= 0 else (Decimal(errors) * Decimal(1000) / Decimal(usage)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def release_health(company_ref: str, *, app_ref: str, batches: Sequence[Mapping[str, Any]], as_of: str, release_ref: str | None = None, window_days: int = 30, min_usage: int = DEFAULT_MIN_USAGE, min_errors: int = DEFAULT_MIN_ERRORS, regression_factor: Any = DEFAULT_REGRESSION_FACTOR) -> ReleaseHealth:
    """How a release is doing against the one before it: the error rate per thousand uses, never the raw count; below the usage floor the verdict is that there is not enough evidence yet. A regressed release names the release to roll back to; rolling back is the owner's decision."""

    at = timestamp(as_of, field_name="as_of")
    factor = Decimal(str(regression_factor))
    readings: dict[str, dict[str, Any]] = {}
    for _batch, signal in _in_window(batches, company_ref=company_ref, as_of=at, window_days=int(window_days)):
        if signal.app_ref != app_ref or signal.release_ref is None:
            continue
        entry = readings.setdefault(signal.release_ref, {"release_ref": signal.release_ref, "released_at": None, "usage": 0, "errors": 0, "signatures": set()})
        if signal.kind == "release":
            entry["released_at"] = signal.occurred_at if entry["released_at"] is None else min(entry["released_at"], signal.occurred_at)
        elif signal.kind == "usage":
            entry["usage"] += signal.count
        elif signal.kind == "error":
            entry["errors"] += signal.count
            entry["signatures"].add(str(signal.error_signature))
    _require(bool(readings), "NO_RELEASE", f"{app_ref} has reported no release in the window")
    order = sorted(readings.values(), key=lambda row: (row["released_at"] or "9999", row["release_ref"]))
    if release_ref is None:
        current = order[-1]
    else:
        _require(release_ref in readings, "NO_RELEASE", f"{app_ref} has reported nothing for {release_ref} in the window")
        current = readings[release_ref]
    position = order.index(current)
    previous = order[position - 1] if position > 0 else None

    def reading(row: dict[str, Any]) -> dict[str, Any]:
        rate = _per_thousand(row["errors"], row["usage"])
        return {"release_ref": row["release_ref"], "released_at": row["released_at"], "usage": row["usage"], "errors": row["errors"], "errors_per_thousand": None if rate is None else str(rate), "signatures": sorted(row["signatures"])[:100]}

    new_signatures = sorted(current["signatures"] - (previous["signatures"] if previous else set()))[:100]
    rate = _per_thousand(current["errors"], current["usage"])
    rollback_to = None
    if current["usage"] < int(min_usage):
        verdict, reason = "insufficient_evidence", f"{current['usage']} use(s) so far, under the {min_usage} a verdict needs; {current['errors']} error(s) are not evidence yet"
    elif previous is None:
        verdict, reason = "no_baseline", f"{rate} errors per thousand uses; there is no earlier release in the window to compare with"
    else:
        base_rate = _per_thousand(previous["errors"], previous["usage"])
        if previous["usage"] < int(min_usage) or base_rate is None:
            verdict, reason = "no_baseline", f"{rate} errors per thousand uses; {previous['release_ref']} had too little use ({previous['usage']}) to compare with"
        elif current["errors"] >= int(min_errors) and rate is not None and rate > max(base_rate, Decimal("0.01")) * factor:
            verdict, reason, rollback_to = "regressed", f"{rate} errors per thousand uses against {base_rate} on {previous['release_ref']}" + (f"; new: {', '.join(new_signatures[:3])}" if new_signatures else ""), previous["release_ref"]
        else:
            verdict, reason = "healthy", f"{rate} errors per thousand uses against {base_rate} on {previous['release_ref']}"
    return seal(ReleaseHealth, {"company_ref": company_ref, "app_ref": app_ref, "as_of": at, "release": reading(current), "baseline": None if previous is None else reading(previous), "new_signatures": new_signatures, "verdict": verdict, "reason": reason[:300], "rollback_to": rollback_to}, "health_digest")


def verify_release_health(value: Any) -> ReleaseHealth:
    return value if isinstance(value, ReleaseHealth) else ReleaseHealth.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed"}})


__all__ = ["APP_ERROR_ROLLUP_SCHEMA", "APP_SIGNALS_MANIFEST", "APP_SIGNALS_SUMMARY_SCHEMA", "APP_SIGNAL_BATCH_SCHEMA", "APP_SIGNAL_SCHEMA", "DEFAULT_ERROR_THRESHOLD", "DEFAULT_WINDOW_DAYS", "MAX_BATCH", "SIGNAL_KINDS", "AppSignal", "AppSignalBatch", "AppSignalError", "AppSignalsSummary", "AppSummaryRow", "ErrorRollup", "ErrorRollupRow", "candidate_from_error_rollup", "compile_app_signal_batch", "rollup_errors", "summarise_app_signals", "verify_app_signal_batch", "verify_app_signals_summary", "verify_error_rollup", "RELEASE_HEALTH_SCHEMA", "DEFAULT_MIN_USAGE", "ReleaseHealth", "ReleaseReading", "candidate_from_feedback_signal", "feedback_signals", "release_health", "verify_release_health"]
