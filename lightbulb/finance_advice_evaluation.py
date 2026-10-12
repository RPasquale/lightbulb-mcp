"""Evaluation: golden shortlists the engine must keep producing, and the monitoring service's own numbers.

Two things are measured. First, a set of golden cases: a client state per vertical with the
shortlist the engine produced when a person last checked it. The harness reruns every case
against the current catalogs and reports each difference by name, so a change to a ranking rule,
a projection, a freshness policy or a pack shows up as a named diff and not as a surprise in an
adviser's inbox. Second, the monitoring service's own health: how many sources were checked
within their cadence, how much of the published view is fresh, how old the oldest unresolved
change is, and how long detection took to reach publication. Both are deterministic, both are
read from sealed objects, neither ranks anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, StrictModel, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_catalog import ProductCatalog
from lightbulb.finance_advice_engine import AdviceError, client_state, compile_advice_plan, shortlist_products
from lightbulb.finance_advice_observations import Observation, ProposedChange, field_role
from lightbulb.finance_advice_sources import DEFAULT_FRESHNESS_HOURS, MonitoredSource, SourceRegistry

GOLDEN_SCHEMA = "lightbulb.finance_advice_golden_case.v1"
EVALUATION_SCHEMA = "lightbulb.finance_advice_evaluation_report.v1"
METRICS_SCHEMA = "lightbulb.finance_advice_monitoring_metrics.v1"
EVALUATION_CLIENT_COMMITMENT = "e0" * 32


class GoldenCase(StrictModel):
    """A client state and the shortlist a person accepted for it."""

    schema_id: Literal["lightbulb.finance_advice_golden_case.v1"] = GOLDEN_SCHEMA
    case_ref: str = Field(min_length=1)
    jurisdiction: Literal["AU", "CA"]
    vertical_id: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    facts: dict[str, Any] = Field(default_factory=dict)
    expected_top: tuple[str, ...] = Field(default_factory=tuple)
    expected_exclusion_reasons: tuple[str, ...] = Field(default_factory=tuple)
    note: str | None = None

    @field_validator("expected_top", "expected_exclusion_reasons", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class CaseResult(StrictModel):
    case_ref: str
    vertical_id: str
    outcome: Literal["matched", "differs", "error"]
    top: tuple[str, ...] = Field(default_factory=tuple)
    excluded: dict[str, int] = Field(default_factory=dict)
    differences: tuple[str, ...] = Field(default_factory=tuple)
    shortlist_digest: Sha256Digest | None = None
    error: str | None = None

    @field_validator("top", "differences", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class EvaluationReport(StrictModel):
    schema_id: Literal["lightbulb.finance_advice_evaluation_report.v1"] = EVALUATION_SCHEMA
    as_of: str
    cases: int
    matched: int
    differing: int
    errors: int
    results: tuple[CaseResult, ...] = Field(default_factory=tuple)
    report_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("results", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> EvaluationReport:
        if not skip_digests(info) and self.report_digest != sealed_digest(EvaluationReport, self, "report_digest"):
            raise ValueError("report_digest does not match the report")
        return self

    @property
    def clean(self) -> bool:
        return self.differing == 0 and self.errors == 0


def golden_cases(payload: Sequence[Mapping[str, Any]] | Mapping[str, Any]) -> tuple[GoldenCase, ...]:
    """Golden cases from a list, or from a file payload with a ``cases`` list."""
    items = payload["cases"] if isinstance(payload, Mapping) else payload
    return tuple(GoldenCase.model_validate(dict(item)) for item in items)


def run_case(case: GoldenCase, catalog: ProductCatalog, *, as_of: str, limit: int = 5) -> CaseResult:
    """Run one golden case against one catalog and name every difference."""
    try:
        plan = compile_advice_plan("evaluation", jurisdiction=case.jurisdiction, mode="general_information", verticals=[case.vertical_id], remuneration_disclosure="Evaluation run; no remuneration.", overrides={"project_costs": True})
        state = client_state(f"eval-{case.case_ref}", jurisdiction=case.jurisdiction, vertical_id=case.vertical_id, objective=case.objective, personal_data_sha256=EVALUATION_CLIENT_COMMITMENT, disclosed_at=as_of, fact_find_complete=True, **dict(case.facts))
        shortlist = shortlist_products(plan, state, catalog, as_of=as_of, limit=limit)
    except (AdviceError, ValueError) as exc:
        return CaseResult(case_ref=case.case_ref, vertical_id=case.vertical_id, outcome="error", error=str(exc)[:400])
    top = [entry.product_name for entry in shortlist.entries]
    excluded = {str(key): int(value) for key, value in dict(shortlist.excluded).items()}
    differences: list[str] = []
    expected = list(case.expected_top)
    if top[: len(expected)] != expected:
        differences.append(f"top {len(expected)} expected {expected}; got {top[: len(expected)]}")
    for reason in case.expected_exclusion_reasons:
        if reason not in excluded:
            differences.append(f"expected exclusions for {reason}; none were made")
    return CaseResult(case_ref=case.case_ref, vertical_id=case.vertical_id, outcome="differs" if differences else "matched", top=top, excluded=excluded, differences=differences, shortlist_digest=shortlist.shortlist_digest)


def evaluate_shortlists(cases: Sequence[GoldenCase | Mapping[str, Any]], catalogs: Mapping[str, ProductCatalog], *, as_of: str, limit: int = 5) -> EvaluationReport:
    """Every golden case against the catalog of its vertical; a missing catalog is an error, not a pass."""
    stamp = timestamp(as_of, field_name="as_of")
    results: list[CaseResult] = []
    for item in cases:
        case = item if isinstance(item, GoldenCase) else GoldenCase.model_validate(dict(item))
        catalog = catalogs.get(case.vertical_id)
        if catalog is None:
            results.append(CaseResult(case_ref=case.case_ref, vertical_id=case.vertical_id, outcome="error", error=f"no catalog for {case.vertical_id}"))
            continue
        results.append(run_case(case, catalog, as_of=stamp, limit=limit))
    return seal(EvaluationReport, {"as_of": stamp, "cases": len(results), "matched": sum(1 for r in results if r.outcome == "matched"), "differing": sum(1 for r in results if r.outcome == "differs"), "errors": sum(1 for r in results if r.outcome == "error"), "results": [r.to_dict() for r in results]}, "report_digest")


def with_observed_expectations(cases: Sequence[GoldenCase], report: EvaluationReport, *, top_n: int = 3) -> tuple[GoldenCase, ...]:
    """Golden cases with their expectations replaced by what the engine produced; a person reviews the diff before it is kept."""
    by_ref = {r.case_ref: r for r in report.results}
    out: list[GoldenCase] = []
    for case in cases:
        result = by_ref.get(case.case_ref)
        if result is None or result.outcome == "error":
            out.append(case)
            continue
        raw = case.to_dict()
        raw["expected_top"] = list(result.top[:top_n])
        raw["expected_exclusion_reasons"] = sorted(result.excluded)
        out.append(GoldenCase.model_validate(raw))
    return tuple(out)


def _hours(later: str, earlier: str) -> float:
    return round((parsed(later) - parsed(earlier)).total_seconds() / 3600, 1)


def monitoring_metrics(registry: SourceRegistry | Mapping[str, Any], observations: Sequence[Observation | Mapping[str, Any]], pending_changes: Sequence[ProposedChange | Mapping[str, Any]], *, as_of: str) -> dict[str, Any]:
    """The monitoring service's own numbers at one moment, from its sealed objects."""
    stamp = timestamp(as_of, field_name="as_of")
    now = parsed(stamp)
    reg = registry if isinstance(registry, SourceRegistry) else SourceRegistry.model_validate(dict(registry))
    sources: list[MonitoredSource] = list(reg.sources)
    within = never = failing = 0
    for source in sources:
        if source.consecutive_failures:
            failing += 1
        if source.last_success_at is None:
            never += 1
        elif now - parsed(source.last_success_at) <= timedelta(hours=source.cadence_hours):
            within += 1
    accepted = [o if isinstance(o, Observation) else Observation.model_validate(dict(o)) for o in observations]
    accepted = [o for o in accepted if o.status == "accepted"]
    fresh = 0
    detection: list[float] = []
    for o in accepted:
        role = field_role(o.field)
        allowed = DEFAULT_FRESHNESS_HOURS.get(role, DEFAULT_FRESHNESS_HOURS["other"])
        basis = o.last_revalidated_at or o.accepted_at or o.observed_at
        if basis and now - parsed(basis) <= timedelta(hours=allowed) and not o.hold:
            fresh += 1
        if o.accepted_at and o.observed_at:
            detection.append(_hours(o.accepted_at, o.observed_at))
    ages = []
    for item in pending_changes:
        change = item if isinstance(item, ProposedChange) else ProposedChange.model_validate(dict(item))
        ages.append(_hours(stamp, change.proposed_at))
    return {
        "schema": METRICS_SCHEMA,
        "as_of": stamp,
        "sources": {"total": len(sources), "checked_within_cadence": within, "never_checked": never, "failing": failing, "share_within_cadence": round(within / len(sources), 3) if sources else None},
        "published_view": {"accepted_observations": len(accepted), "fresh": fresh, "share_fresh": round(fresh / len(accepted), 3) if accepted else None},
        "unresolved_changes": {"count": len(ages), "oldest_hours": max(ages) if ages else None, "mean_hours": round(sum(ages) / len(ages), 1) if ages else None},
        "detection_to_publication_hours": {"count": len(detection), "mean": round(sum(detection) / len(detection), 1) if detection else None, "max": max(detection) if detection else None},
    }


EVALUATION_MANIFEST: dict[str, Any] = {
    "schemas": {"golden_case": GOLDEN_SCHEMA, "report": EVALUATION_SCHEMA, "metrics": METRICS_SCHEMA},
    "golden_file": "research/financial_products/evaluation/golden_shortlists.json",
    "harness": "scripts/evaluate_finance_advice_shortlists.py (rerun every case; --write replaces expectations with the observed shortlist for a person to review)",
    "metrics": ["share of sources checked within cadence", "share of the published view within its freshness window", "age of the oldest unresolved change", "detection-to-publication hours"],
    "not_claimed": "the golden set is a regression fence, not a measure of advice quality; a licensed adviser judges that",
}

__all__ = ["EVALUATION_CLIENT_COMMITMENT", "EVALUATION_MANIFEST", "EVALUATION_SCHEMA", "GOLDEN_SCHEMA", "METRICS_SCHEMA", "CaseResult", "EvaluationReport", "GoldenCase", "evaluate_shortlists", "golden_cases", "monitoring_metrics", "run_case", "with_observed_expectations"]
