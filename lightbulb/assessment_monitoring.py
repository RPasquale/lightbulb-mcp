"""Period review of declared customer outcomes; no scheduling or hosted effects."""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.business_artifact_production import GeneratedBusinessArtifact, prepare_business_artifact_generation, validate_generated_business_artifact
from lightbulb.productised_assessment import AssessmentEvidence, ProductisedAssessmentDossier, _sealed_digest
from lightbulb.productised_assessment_presentation import AssessmentPresentationStyle, _CSS, _h, _md
from lightbulb.project_outcomes import build_project_business_outcome_observation
from lightbulb.service_engagement import BoundedText, OpaqueRef, Sha256Digest, ShortText, _StrictModel, _detached, _parsed_timestamp, _timestamp


def _number(value: Any) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, (bool, float)):
        raise ValueError("measurements require decimal strings or integers")
    try:
        result = Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("measurement must be a finite decimal") from exc
    if not result.is_finite() or abs(result) > Decimal("1e30") or result.as_tuple().exponent < -6:
        raise ValueError("measurement must be finite, bounded, with at most six decimal places")
    return result


class MonitoringMeasurement(_StrictModel):
    value: Decimal
    observed_at: str
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=16)
    period_start: str | None = None
    period_end: str | None = None

    @field_validator("value", mode="before")
    @classmethod
    def _value(cls, value: Any) -> Decimal:
        result = _number(value)
        if result is None:
            raise ValueError("measurement value is required")
        return result

    @field_validator("observed_at", "period_start", "period_end")
    @classmethod
    def _time(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _window(self) -> "MonitoringMeasurement":
        if (self.period_start is None) != (self.period_end is None):
            raise ValueError("measurement period bounds must be supplied together")
        if self.period_start and _parsed_timestamp(self.period_end) <= _parsed_timestamp(self.period_start):
            raise ValueError("measurement period must have positive duration")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("measurement evidence references must be unique")
        return self


class MonitoringMetric(_StrictModel):
    metric_ref: OpaqueRef
    goal_ref: OpaqueRef
    label: str = Field(min_length=1, max_length=160)
    unit: str = Field(min_length=1, max_length=40)
    direction: Literal["maximize", "minimize"]
    aggregation: Literal["snapshot", "average", "total"] = "snapshot"
    baseline: MonitoringMeasurement | None = None
    current: MonitoringMeasurement | None = None
    target_value: Decimal | None = None
    agreement_evidence_ref: OpaqueRef | None = None
    next_action: BoundedText | None = None

    @field_validator("target_value", mode="before")
    @classmethod
    def _target(cls, value: Any) -> Decimal | None:
        return _number(value)


class AssessmentMonitoringInput(_StrictModel):
    dossier: ProductisedAssessmentDossier
    requested_by_ref: OpaqueRef
    offer_ref: OpaqueRef
    review_ref: OpaqueRef
    as_of: str
    period_start: str
    period_end: str
    next_review_due_at: str | None = None
    metrics: tuple[MonitoringMetric, ...] = Field(default_factory=tuple, max_length=30)
    evidence: tuple[AssessmentEvidence, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("as_of", "period_start", "period_end", "next_review_due_at")
    @classmethod
    def _time(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _exact(self) -> "AssessmentMonitoringInput":
        offers = [offer for offer in self.dossier.inputs.offers if offer.offer_ref == self.offer_ref]
        if not offers or offers[0].kind not in {"managed_monitoring", "software_access"}:
            raise ValueError("offer_ref must select the exact monitoring or software-access offer")
        if _parsed_timestamp(self.period_end) <= _parsed_timestamp(self.period_start):
            raise ValueError("review period must have positive duration")
        for evidence in self.evidence:
            if evidence.scope != self.dossier.inputs.scope:
                raise ValueError("monitoring evidence must match the exact tenant/company/project/customer/engagement scope")
        for values in ([item.metric_ref for item in self.metrics], [item.evidence_ref for item in self.evidence]):
            if len(values) != len(set(values)):
                raise ValueError("metric and evidence references must be unique")
        return self


class MonitoringBlocker(_StrictModel):
    code: ShortText
    field: ShortText
    message: BoundedText


class MonitoringComparison(_StrictModel):
    metric_ref: OpaqueRef
    label: ShortText
    unit: str
    baseline_value: Decimal | None = None
    observed_value: Decimal | None = None
    target_value: Decimal | None = None
    delta: Decimal | None = None
    target_shortfall: Decimal | None = None
    movement: Literal["improved", "regressed", "unchanged", "unassessed"]
    next_action: BoundedText

    @field_validator("baseline_value", "observed_value", "target_value", "delta", "target_shortfall", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal | None:
        return None if value is None else Decimal(value)


class AssessmentMonitoringReview(_StrictModel):
    inputs: AssessmentMonitoringInput
    status: Literal["incomplete_draft", "ready_for_review"]
    comparisons: tuple[MonitoringComparison, ...]
    blockers: tuple[MonitoringBlocker, ...]
    outcome_requests: tuple[dict[str, Any], ...]
    markdown: str
    html: str
    markdown_digest: Sha256Digest
    proposed_next_review_due_at: str | None = None
    causality_status: Literal["observed_not_proven"] = "observed_not_proven"
    evidence_status: Literal["caller_supplied_unverified"] = "caller_supplied_unverified"
    recorded: Literal[False] = False
    delivered: Literal[False] = False
    accepted: Literal[False] = False
    scheduled: Literal[False] = False
    external_write_performed: Literal[False] = False
    review_digest: Sha256Digest = "0" * 64

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> "AssessmentMonitoringReview":
        if self.markdown_digest != hashlib.sha256(self.markdown.encode("utf-8")).hexdigest():
            raise ValueError("markdown_digest must match the review content")
        if not (info.context or {}).get("skip_productised_assessment_digests"):
            derived = _review_payload(self.inputs)
            for key in ("status", "comparisons", "blockers", "outcome_requests", "markdown", "html", "proposed_next_review_due_at"):
                if _detached(getattr(self, key)) != _detached(derived[key]):
                    raise ValueError(f"{key} must be derived from the exact monitoring input")
            if self.review_digest != _sealed_digest(AssessmentMonitoringReview, self, "review_digest"):
                raise ValueError("review_digest must commit the exact review")
        return self


def _display(value: Decimal | None) -> str:
    return "Not supplied" if value is None else format(value, "f")


def compile_assessment_monitoring_review(inputs: AssessmentMonitoringInput | Mapping[str, Any]) -> AssessmentMonitoringReview:
    """Compare declared measurements and prepare a customer review without writes."""
    return AssessmentMonitoringReview.model_validate(_review_payload(inputs))


def _review_payload(inputs: AssessmentMonitoringInput | Mapping[str, Any]) -> dict[str, Any]:
    source = AssessmentMonitoringInput.model_validate(_detached(inputs))
    blockers: list[MonitoringBlocker] = []
    comparisons: list[MonitoringComparison] = []
    requests: list[dict[str, Any]] = []
    evidence = {item.evidence_ref: item for item in source.evidence}
    as_of = _parsed_timestamp(source.as_of)
    start, end = _parsed_timestamp(source.period_start), _parsed_timestamp(source.period_end)

    def block(code: str, field: str, message: str) -> None:
        blockers.append(MonitoringBlocker(code=code, field=field, message=message))

    if end > as_of:
        block("open_period", "period_end", "Close the reporting period before reviewing its results.")
    if _parsed_timestamp(source.dossier.inputs.prepared_at) > as_of:
        block("future_assessment", "dossier", "The source assessment must precede this review.")
    if source.dossier.status == "blocked":
        block("incomplete_assessment", "dossier", "Complete the source assessment before delivering this review.")
    if not source.metrics:
        block("missing_metrics", "metrics", "Supply the agreed customer metrics, targets, and period observations.")
    if source.next_review_due_at is not None and _parsed_timestamp(source.next_review_due_at) <= as_of:
        block("past_next_review", "next_review_due_at", "The proposed next review must follow this review timestamp.")
    global_blocked = bool(blockers)
    for index, metric in enumerate(source.metrics):
        path = f"metrics[{index}]"
        first_blocker = len(blockers)
        if metric.goal_ref not in {goal.goal_ref for goal in source.dossier.inputs.goals}:
            block("unknown_goal", path + ".goal_ref", f"Link {metric.label} to an agreed assessment goal.")
        if metric.target_value is None:
            block("missing_target", path + ".target_value", f"Supply the agreed target for {metric.label}.")
        refs = [metric.agreement_evidence_ref] if metric.agreement_evidence_ref else []
        if not metric.agreement_evidence_ref:
            block("missing_agreement", path + ".agreement_evidence_ref", f"Supply evidence of the customer's agreement to the baseline and target for {metric.label}.")
        for key in ("baseline", "current"):
            measurement = getattr(metric, key)
            if measurement is None:
                block("missing_measurement", path + "." + key, f"Supply the {key} measurement for {metric.label}.")
                continue
            if not measurement.evidence_refs:
                block("missing_evidence", path + "." + key, f"Attach source evidence for the {key} measurement of {metric.label}.")
            refs.extend(measurement.evidence_refs)
            if Decimal(str(float(measurement.value))) != measurement.value:
                block("outcome_precision_loss", path + "." + key, f"The canonical outcome request cannot preserve the exact numeric precision of {metric.label}; do not record a rounded observation.")
            observed = _parsed_timestamp(measurement.observed_at)
            if observed > as_of:
                block("future_measurement", path + "." + key, f"The {key} measurement of {metric.label} is from after this review.")
            if key == "baseline" and observed > start:
                block("late_baseline", path + ".baseline", f"The baseline for {metric.label} must be established before the reporting period.")
            if key == "current" and observed < end:
                block("incomplete_observation", path + ".current", f"Observe {metric.label} after the reporting period closes.")
            if measurement.period_end and _parsed_timestamp(measurement.period_end) > observed:
                block("observation_before_period_end", path + "." + key, f"The {key} observation for {metric.label} precedes its declared period end.")
        for ref in dict.fromkeys(refs):
            item = evidence.get(ref)
            if item is None:
                block("unknown_evidence", path, f"Supply the referenced evidence for {metric.label}.")
            elif _parsed_timestamp(item.observed_at) > as_of or _parsed_timestamp(item.valid_until) <= as_of:
                block("stale_or_future_evidence", path, f"Refresh the evidence for {metric.label} before using this comparison.")
        if len(set(refs)) > 16:
            block("outcome_evidence_limit", path, f"The outcome request for {metric.label} exceeds the canonical sixteen-source limit; select a bounded evidence package without dropping its provenance.")
        if metric.aggregation in {"average", "total"}:
            baseline, current = metric.baseline, metric.current
            if not baseline or not current or not baseline.period_start or not current.period_start:
                block("missing_measurement_period", path, f"Supply both observation periods for {metric.label}.")
            elif current.period_start != source.period_start or current.period_end != source.period_end:
                block("period_mismatch", path, f"The current measurement period for {metric.label} must match this review.")
            elif metric.aggregation == "total" and _parsed_timestamp(baseline.period_end) - _parsed_timestamp(baseline.period_start) != end - start:
                block("incomparable_totals", path, f"Compare equal-duration totals for {metric.label}; do not infer a normalized result.")
        ready = not global_blocked and len(blockers) == first_blocker
        old = metric.baseline.value if metric.baseline else None
        current = metric.current.value if metric.current else None
        delta = current - old if ready else None
        directional = delta if metric.direction == "maximize" else -delta if delta is not None else None
        shortfall = max(Decimal(0), metric.target_value - current if metric.direction == "maximize" else current - metric.target_value) if ready else None
        movement = "unassessed" if not ready else "improved" if directional > 0 else "regressed" if directional < 0 else "unchanged"
        action = f"Complete the missing evidence for {metric.label}." if not ready else metric.next_action or (f"Review {metric.label}: the target shortfall is {_display(shortfall)} {metric.unit}." if shortfall > 0 else f"Confirm that {metric.label} continues to meet its agreed target at the next review.")
        comparisons.append(MonitoringComparison(metric_ref=metric.metric_ref, label=metric.label, unit=metric.unit, baseline_value=old, observed_value=current, target_value=metric.target_value, delta=delta, target_shortfall=shortfall, movement=movement, next_action=action))
        if ready:
            identity = str(uuid5(NAMESPACE_URL, "lightbulb-monitoring:" + source.dossier.dossier_digest + ":" + source.review_ref + ":" + metric.metric_ref + ":" + source.period_start + ":" + source.period_end))
            requests.append(build_project_business_outcome_observation(observation_id=identity, metric_id="monitoring-" + hashlib.sha256(metric.metric_ref.encode()).hexdigest()[:24], metric_label=metric.label, direction=metric.direction, baseline_value=old, observed_value=current, unit=metric.unit, observed_at=metric.current.observed_at, source_kind="human_attestation", evidence_refs=tuple(dict.fromkeys(refs)), note="Draft request for human attestation; measurements and causation have not been independently verified. An agent event-bound write requires an actual project source event."))
    payload = {"inputs": source, "status": "incomplete_draft" if blockers else "ready_for_review", "comparisons": comparisons, "blockers": blockers, "outcome_requests": requests, "proposed_next_review_due_at": source.next_review_due_at if source.next_review_due_at and _parsed_timestamp(source.next_review_due_at) > as_of else None}
    markdown, rendered_html = _render(source, comparisons, blockers, payload["proposed_next_review_due_at"])
    payload.update(markdown=markdown, html=rendered_html, markdown_digest=hashlib.sha256(markdown.encode()).hexdigest())
    payload["review_digest"] = _sealed_digest(AssessmentMonitoringReview, payload, "review_digest")
    return payload


def _render(source: AssessmentMonitoringInput, comparisons: list[MonitoringComparison], blockers: list[MonitoringBlocker], due: str | None) -> tuple[str, str]:
    company = source.dossier.inputs.brand.brand_name if source.dossier.inputs.brand else "Company awaiting confirmation"
    customer = source.dossier.inputs.customer.customer_display_name if source.dossier.inputs.customer else "Customer awaiting confirmation"
    title = "Your progress and next actions"
    status = "Incomplete draft" if blockers else "Draft for review"
    sections = [f"# {title}", f"{_md(company)} · Prepared for {_md(customer)}", f"**{status}** · As of {source.as_of}", f"Reporting period: {source.period_start} to {source.period_end} (end exclusive)."]
    body = f'<section class="hero"><p class="eyebrow">Customer progress review</p><span class="badge">{status}</span><h1>{title}</h1><p>Prepared for <strong>{_h(customer)}</strong> by {_h(company)}</p><p class="quiet">As of {_h(source.as_of)}<br>Period: {_h(source.period_start)} to {_h(source.period_end)} (end exclusive)</p></section>'
    if blockers:
        sections.append("## Outstanding inputs\n\n" + "\n".join("- " + _md(item.message) for item in blockers))
        body += '<section class="section"><div class="notice"><h2>Outstanding inputs</h2><ul>' + "".join("<li>" + _h(item.message) + "</li>" for item in blockers) + "</ul></div></section>"
    body += '<section class="section"><div class="grid">'
    evidence_numbers = {item.evidence_ref: index for index, item in enumerate(source.evidence, 1)}
    for index, row in enumerate(comparisons):
        metric = source.metrics[index]
        refs = [metric.agreement_evidence_ref] + list(metric.baseline.evidence_refs if metric.baseline else ()) + list(metric.current.evidence_refs if metric.current else ())
        citations = ", ".join(f"Evidence {evidence_numbers[ref]}" for ref in dict.fromkeys(refs) if ref in evidence_numbers) or "Supporting evidence is missing."
        facts = f"Baseline: {_display(row.baseline_value)} {row.unit}. Current: {_display(row.observed_value)} {row.unit}. Target: {_display(row.target_value)} {row.unit}."
        movement = f"Movement: {row.movement}. Delta: {_display(row.delta)} {row.unit}. Target shortfall: {_display(row.target_shortfall)} {row.unit}."
        sections.append(f"## {_md(row.label)}\n\n{_md(facts)}\n\n{_md(movement)}\n\n**Next action:** {_md(row.next_action)}\n\n{citations}")
        body += f'<article class="card"><p class="label">{_h(row.movement)}</p><h2>{_h(row.label)}</h2><p>{_h(facts)}</p><p>{_h(movement)}</p><div class="recommendation"><p class="label">Next action</p><p>{_h(row.next_action)}</p></div><p class="evidence-note">{_h(citations)}</p></article>'
    body += '</div></section><section class="section"><h2>Evidence supplied</h2>'
    evidence_lines = []
    for index, item in enumerate(source.evidence, 1):
        text = f"Evidence {index}: {item.summary} Observed {item.observed_at}; valid until {item.valid_until}."
        evidence_lines.append("- " + _md(text))
        body += "<p>" + _h(text) + "</p>"
    sections.append("## Evidence supplied\n\n" + ("\n".join(evidence_lines) or "No source evidence supplied."))
    notice = "Measurements and customer agreement are supplied evidence, not independently verified facts. Changes do not establish that the service caused the result. No report has been delivered, observation recorded, or next review scheduled."
    next_review = f"Proposed next review: {due}." if due else "Next review date requires agreement."
    sections.extend(["## Next review\n\n" + next_review, notice])
    body += f'</section><section class="section"><h2>Next review</h2><p>{_h(next_review)}</p></section><footer class="foot"><p>{_h(notice)}</p></footer>'
    css = _CSS.replace("ACCENT", AssessmentPresentationStyle().accent_color)
    rendered_html = f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>{title} — {_h(company)}</title><style>{css}</style></head><body><main class="page">{body}</main></body></html>'
    return "\n\n".join(sections) + "\n", rendered_html


def prepare_assessment_monitoring_document(review: AssessmentMonitoringReview | Mapping[str, Any], *, artifact_ref: str) -> GeneratedBusinessArtifact:
    """Prepare the canonical Markdown candidate; no file write or client delivery."""
    supplied = AssessmentMonitoringReview.model_validate(_detached(review))
    exact = compile_assessment_monitoring_review(supplied.inputs)
    if supplied.to_dict() != exact.to_dict():
        raise ValueError("review must equal the comparison derived from its exact inputs")
    if exact.blockers:
        raise ValueError("complete monitoring prerequisites before preparing the document")
    source = exact.inputs.dossier.inputs
    scope = source.scope
    request = prepare_business_artifact_generation({"scope": {key: getattr(scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "customer_ref", "engagement_ref")}, "artifact_kind": "one_pager", "artifact_format": "markdown", "title": "Customer progress and next actions", "purpose": "Review observed customer progress and agree the next actions.", "generation_mode": "template", "brand": source.brand, "customer": source.customer, "engagement": {"engagement_ref": scope.engagement_ref, "stage": exact.inputs.dossier.engagement_assessment.stage, "linked_artifact_digests": [exact.review_digest]}, "source_artifact_refs": [source.assessment_ref, exact.inputs.review_ref], "requested_at": exact.inputs.as_of, "requested_by_ref": exact.inputs.requested_by_ref})
    return validate_generated_business_artifact({"request": request, "submission": {"brief_digest": request.brief.brief_digest, "sections": {"headline": "Customer progress review", "value_proposition": "Review measured progress against the agreed baselines and targets.", "proof_points": exact.markdown, "call_to_action": "Review the findings and agree the next actions and review date."}, "provenance": {"generator_kind": "template", "generated_at": exact.inputs.as_of}}, "artifact_ref": artifact_ref, "validated_at": exact.inputs.as_of, "requested_by_ref": exact.inputs.requested_by_ref})
