"""Deterministic client presentations of a productised assessment candidate.

HTML is a self-contained preview; Markdown can be validated into the existing
governed business-artifact contract. Neither path persists, publishes, approves,
collects payment, nor activates software access.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.business_artifact_production import (
    GeneratedBusinessArtifact,
    prepare_business_artifact_generation,
    validate_generated_business_artifact,
)
from lightbulb.productised_assessment import ProductisedAssessmentDossier


class AssessmentPresentationStyle(BaseModel):
    """Presentation choices only; company and customer facts come from the dossier."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, revalidate_instances="always")
    accent_color: str = "#0f766e"
    contact_url: str | None = Field(default=None, max_length=2048)

    @field_validator("accent_color")
    @classmethod
    def _color(cls, value: str) -> str:
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", value):
            raise ValueError("accent_color must be a six-digit hex color")
        channels = [int(value[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [part / 12.92 if part <= 0.04045 else ((part + 0.055) / 1.055) ** 2.4 for part in channels]
        luminance = sum(part * weight for part, weight in zip(linear, (0.2126, 0.7152, 0.0722)))
        if 1.05 / (luminance + 0.05) < 4.5:
            raise ValueError("accent_color must provide at least 4.5:1 contrast with white")
        return value.lower()

    @field_validator("contact_url")
    @classmethod
    def _url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(ord(char) <= 32 for char in value) or "\\" in value:
            raise ValueError("contact_url must be an HTTPS URL without control characters")
        try:
            parsed = urlsplit(value)
            valid = parsed.scheme == "https" and parsed.hostname and parsed.username is None and parsed.password is None
            parsed.port
        except ValueError as exc:
            raise ValueError("contact_url must be an HTTPS URL") from exc
        if not valid:
            raise ValueError("contact_url must be an HTTPS URL without credentials")
        return value


class AssessmentDocumentPreview(BaseModel):
    """Presentation of an exact dossier, never an approval or hosted artifact receipt."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, revalidate_instances="always")
    document_kind: Literal["report", "proposal"]
    title: str
    html: str
    markdown: str
    dossier_digest: str
    content_digest: str
    markdown_digest: str
    disposition: Literal["draft_for_review", "incomplete_draft"]
    authoritative: Literal[False] = False
    external_write_performed: Literal[False] = False

    @model_validator(mode="after")
    def _content_is_exact(self) -> "AssessmentDocumentPreview":
        if self.content_digest != _content_digest(self.html, self.markdown, self.dossier_digest):
            raise ValueError("content_digest must commit the exact HTML, Markdown, and dossier")
        if self.markdown_digest != hashlib.sha256(self.markdown.encode("utf-8")).hexdigest():
            raise ValueError("markdown_digest must commit the exact Markdown bytes")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


_CSS = """
:root{--accent:ACCENT;--ink:#18272c;--muted:#52646b;--line:#dce4e4;--paper:#fff;--wash:#f1f5f4}
*{box-sizing:border-box}body{margin:0;background:#e9eeed;color:var(--ink);font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:1.6}
a{color:var(--accent);text-underline-offset:3px}a:focus-visible{outline:3px solid var(--accent);outline-offset:4px}
.page{max-width:1120px;margin:40px auto;background:var(--paper);box-shadow:0 8px 48px #16343212}
.masthead{padding:28px 56px;display:flex;justify-content:space-between;align-items:center;gap:20px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:12px;font-weight:700;letter-spacing:-.02em}.mark{display:grid;place-items:center;background:var(--accent);color:white;width:38px;height:38px;border-radius:9px;font-size:22px}
.edition{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em}.hero{padding:54px 56px 40px;background:linear-gradient(135deg,#f1f7f5,#fff 78%)}
.eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase;font-weight:700;color:var(--accent);margin:0 0 14px}
h1{font-size:clamp(30px,4.6vw,52px);line-height:1.1;letter-spacing:-.045em;margin:16px 0 24px;max-width:850px;overflow-wrap:anywhere}
h2{font-size:26px;line-height:1.25;letter-spacing:-.025em;margin:0 0 22px}h3{font-size:19px;line-height:1.35;letter-spacing:-.015em;margin:8px 0 12px}
p{margin:0 0 14px;overflow-wrap:anywhere}.subline{font-size:15px;color:var(--muted)}.badge{display:inline-block;padding:5px 10px;border-radius:5px;font-size:12px;font-weight:700;background:#fff0cf;color:#694500}
.section{padding:34px 56px;border-top:1px solid var(--line)}.section-head{display:flex;align-items:baseline;justify-content:space-between;gap:16px}.count{font-size:13px;color:var(--muted)}
.lead{font-size:20px;line-height:1.6;max-width:900px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}.card{border:1px solid var(--line);padding:24px;border-radius:10px;break-inside:avoid}
.card p:last-child,.section p:last-child{margin-bottom:0}.label{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-weight:700}.number{font-size:13px;font-weight:700;color:var(--accent)}
.recommendation{border-left:3px solid var(--accent);padding-left:16px;margin:20px 0 14px}.evidence-note{font-size:13px;color:var(--muted)}.list{padding-left:21px;margin:10px 0 0}.list li{padding:3px 0;overflow-wrap:anywhere}
.price{font-size:26px;font-weight:700;letter-spacing:-.03em;margin:16px 0 4px}.price small{font-size:14px;font-weight:400;letter-spacing:0;color:var(--muted)}
.action{padding:32px;background:var(--accent);color:white;border-radius:12px}.action .eyebrow{color:white;opacity:.85}.action h2{margin:4px 0 14px}.action a{color:white}.action .list{margin-bottom:18px}
.evidence{padding:18px 0;border-bottom:1px solid var(--line);break-inside:avoid}.evidence:last-child{border-bottom:0}.evidence p{margin:6px 0}.notice{background:#fff8e9;border:1px solid #eed6a6;padding:20px 24px;border-radius:8px;margin-bottom:22px}
.foot{padding:26px 56px;background:var(--wash);font-size:12px;color:var(--muted);display:flex;justify-content:space-between;gap:30px}.foot p{max-width:680px;margin:0}.quiet{color:var(--muted);font-size:14px}
@media(max-width:680px){body{background:white}.page{margin:0;box-shadow:none}.masthead,.hero,.section,.foot{padding:24px}.edition{display:none}.grid{grid-template-columns:1fr}.hero{padding-top:32px}.section-head,.foot{display:block}.action{padding:24px}.foot p+p{margin-top:12px}}
@media print{@page{size:A4;margin:14mm}body{background:white;font-size:10pt}.page{margin:0;max-width:none;box-shadow:none}.masthead{padding:0 0 18px}.hero{padding:24px 0;background:white}.section{padding:24px 0}.foot{padding:18px 0;background:white}h1{font-size:30pt}h2{font-size:17pt}h3{font-size:13pt}.lead{font-size:12pt}.grid{gap:12px}.card{padding:16px}.action{background:white;color:var(--ink);border:2px solid var(--accent);padding:20px}.action .eyebrow,.action a{color:var(--accent)}.mark{print-color-adjust:exact;-webkit-print-color-adjust:exact}.badge{border:1px solid #bca26a}h1,h2,h3{break-after:avoid}a{overflow-wrap:anywhere}}
"""

_OFFER_LABELS = {
    "assessment": "Assessment",
    "implementation": "Done for you",
    "managed_monitoring": "Managed monitoring",
    "software_access": "Software access",
}


def _parse(dossier: ProductisedAssessmentDossier | Mapping[str, Any]) -> ProductisedAssessmentDossier:
    payload = dossier.to_dict() if isinstance(dossier, ProductisedAssessmentDossier) else dict(dossier)
    return ProductisedAssessmentDossier.model_validate(payload)


def _h(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _md(value: Any) -> str:
    return re.sub(r"([\\`*_{}\[\]()#+!|>\-])", r"\\\1", html.escape(str(value), quote=True))


def _paragraph(value: str) -> str:
    return "<p>" + _h(value).replace("\n", "<br>") + "</p>"


def _list(values: Any) -> str:
    return '<ul class="list">' + "".join(f"<li>{_h(value)}</li>" for value in values) + "</ul>"


def _bullets(values: Any) -> str:
    return "\n".join(f"- {_md(value)}" for value in values)


def _date(value: str) -> str:
    return value[:10]


def _money(value: Decimal, currency: str) -> str:
    # Preserve every declared decimal place of commercial significance.
    formatted = format(value, ",.6f").rstrip("0").rstrip(".")
    if "." not in formatted:
        formatted += ".00"
    elif len(formatted.rsplit(".", 1)[1]) == 1:
        formatted += "0"
    return f"{currency} {formatted}"


def _price(offer: Any) -> str:
    if offer.pricing is None:
        return "Price to be agreed"
    period = {"one_off": "one-off", "month": "per month", "year": "per year"}[offer.billing_period]
    return f"{_money(offer.pricing.total, offer.pricing.currency)} · {period}"


def _selected_offer(dossier: ProductisedAssessmentDossier, offer_ref: str) -> Any:
    for offer in dossier.inputs.offers:
        if offer.offer_ref == offer_ref:
            return offer
    raise ValueError("offer_ref must identify an offer in the exact assessment dossier")


def _next_step(dossier: ProductisedAssessmentDossier) -> str:
    if dossier.status == "blocked":
        return "Complete the outstanding assessment inputs before reviewing the proposed work."
    return "Review the findings and choose the scope you want to discuss. Confirm terms and approvals before work begins."


def _report_sections(dossier: ProductisedAssessmentDossier) -> dict[str, str]:
    source = dossier.inputs
    evidence_numbers = {item.evidence_ref: index for index, item in enumerate(source.evidence, 1)}
    findings = []
    for finding in source.findings:
        citations = ", ".join(f"Evidence {evidence_numbers[ref]}" for ref in finding.evidence_refs if ref in evidence_numbers)
        findings.append(f"### {_md(finding.title)}\n\n{_md(finding.observation)}\n\n**Proposed action:** {_md(finding.recommendation)}\n\n{citations or 'Supporting evidence is missing.'}")
    sections = {
        "headline": _md(source.title),
        "value_proposition": _md(source.executive_summary or "The assessment summary is awaiting completion."),
        "goals": "\n\n".join(f"{_md(goal.description)}\n\n**Success criteria:**\n\n{_bullets(goal.success_criteria)}" for goal in source.goals) or "Goals are awaiting completion.",
        "proof_points": "\n\n".join(findings) or "Findings are awaiting completion.",
        "options": "\n\n".join(f"### {_md(offer.title)}\n\n{_OFFER_LABELS[offer.kind]}: {_md(offer.outcome)}" for offer in source.offers) or "Commercial options are awaiting completion.",
        "evidence": "Evidence supplied for this assessment; source records have not been independently verified.\n\n" + ("\n\n".join(f"**Evidence {index}** — {_md(item.summary)}\n\nObserved {_date(item.observed_at)}; valid until {_date(item.valid_until)}." for index, item in enumerate(source.evidence, 1)) or "No evidence supplied."),
        "call_to_action": _next_step(dossier),
        "document_status": "Draft for review. No work is approved, no payment is recorded, and no software access is activated by this document.",
        "assessment_cutoff": "Assessment as of " + source.prepared_at + ". Refresh evidence and pricing before later use.",
    }
    if dossier.blockers:
        sections["outstanding_inputs"] = _bullets(item.message for item in dossier.blockers)
    return sections


def _proposal_sections(dossier: ProductisedAssessmentDossier, offer: Any) -> dict[str, str]:
    pricing = offer.pricing
    price_lines = [_price(offer)]
    if pricing is not None:
        price_lines.extend(f"{line.description}: {_money(line.line_total, pricing.currency)}" for line in pricing.lines)
        if pricing.payment_terms_days is not None:
            price_lines.append(f"Payment terms: {pricing.payment_terms_days} days.")
        if pricing.valid_until is not None:
            price_lines.append(f"Quote valid until {_date(pricing.valid_until)}.")
    sections = {
        "executive_summary": _md(offer.outcome),
        "scope": _bullets(offer.scope_of_work),
        "pricing": _bullets(price_lines),
        "timeline": "Start date and delivery schedule must be agreed before work begins.",
        "acceptance": _bullets(offer.acceptance_criteria),
        "exclusions": _bullets(offer.exclusions) or "No exclusions have been supplied; confirm scope boundaries during review.",
        "next_steps": "Review this proposed scope and its quote. Confirm commercial terms and the required approvals before arranging implementation or access.",
        "document_status": "Draft proposal for review. This document does not record agreement, collect payment, or activate access.",
        "assessment_cutoff": "Assessment as of " + dossier.inputs.prepared_at + ". Refresh evidence and pricing before later use.",
    }
    if dossier.blockers:
        sections["outstanding_inputs"] = _bullets(item.message for item in dossier.blockers)
    return sections


def _markdown(title: str, dossier: ProductisedAssessmentDossier, sections: Mapping[str, str]) -> str:
    source = dossier.inputs
    brand = source.brand.brand_name if source.brand else "Company brand awaiting completion"
    customer = source.customer.customer_display_name if source.customer else "Customer awaiting completion"
    headings = {"headline": "Assessment", "value_proposition": "Executive summary", "proof_points": "Findings", "call_to_action": "Next step", "executive_summary": "Proposed outcome"}
    content = [f"# {_md(title)}", f"{_md(brand)} · Prepared for {_md(customer)} · Assessment as of {source.prepared_at}", "**Incomplete draft**" if dossier.status == "blocked" else "**Draft for review**"]
    content.extend(f"## {headings.get(key, key.replace('_', ' ').capitalize())}\n\n{value}" for key, value in sections.items())
    return "\n\n".join(content) + "\n"


def _shell(dossier: ProductisedAssessmentDossier, style: AssessmentPresentationStyle, title: str, kind: str, body: str) -> str:
    source = dossier.inputs
    brand = source.brand.brand_name if source.brand else "Company brand awaiting completion"
    customer = source.customer.customer_display_name if source.customer else "Customer awaiting completion"
    status = "Incomplete draft" if dossier.status == "blocked" else "Draft for review"
    contact = f'<p><a href="{_h(style.contact_url)}" rel="noopener noreferrer">Discuss your next step</a></p>' if style.contact_url else ""
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{_h(title)} — {_h(brand)}</title><style>{_CSS.replace("ACCENT", style.accent_color)}</style></head>
<body><main class="page"><header class="masthead"><div class="brand"><span class="mark" aria-hidden="true">{_h(brand[0])}</span>{_h(brand)}</div><span class="edition">Assessment / {kind}</span></header>
<section class="hero"><p class="eyebrow">A clearer next step</p><span class="badge">{status}</span><h1>{_h(title)}</h1><p class="subline">Prepared for <strong>{_h(customer)}</strong><br>Assessment as of {_h(source.prepared_at)}</p></section>
{body}<section class="section"><div class="action"><p class="eyebrow">Your next step</p><h2>{"Complete the assessment" if dossier.status == "blocked" else "Review, choose, confirm"}</h2>{_paragraph(_next_step(dossier))}{contact}</div></section>
<footer class="foot"><p>Prepared from the evidence supplied. Findings and commercial options require review. Refresh evidence and pricing before later use. This document does not approve work, record payment, or activate software access.</p><p>{_h(brand)}<br>{status}</p></footer></main></body></html>'''


def _content_digest(rendered_html: str, markdown: str, dossier_digest: str) -> str:
    return hashlib.sha256(json.dumps({"html": rendered_html, "markdown": markdown, "dossier_digest": dossier_digest}, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _preview(dossier: ProductisedAssessmentDossier, style: AssessmentPresentationStyle, title: str, kind: Literal["report", "proposal"], body: str, sections: Mapping[str, str]) -> AssessmentDocumentPreview:
    rendered_html = _shell(dossier, style, title, kind, body)
    markdown = _markdown(title, dossier, sections)
    digest = _content_digest(rendered_html, markdown, dossier.dossier_digest)
    return AssessmentDocumentPreview(document_kind=kind, title=title, html=rendered_html, markdown=markdown, dossier_digest=dossier.dossier_digest, content_digest=digest, markdown_digest=hashlib.sha256(markdown.encode("utf-8")).hexdigest(), disposition="incomplete_draft" if dossier.status == "blocked" else "draft_for_review")


def render_productised_assessment_report(dossier: ProductisedAssessmentDossier | Mapping[str, Any], *, style: AssessmentPresentationStyle | Mapping[str, Any] | None = None) -> AssessmentDocumentPreview:
    """Render evidence, proposed findings, and ways to buy from the exact candidate."""

    parsed = _parse(dossier)
    presentation = AssessmentPresentationStyle.model_validate(style or {})
    source = parsed.inputs
    body = '<section class="section">'
    if parsed.blockers:
        body += '<div class="notice"><h3>Outstanding inputs</h3>' + _list(item.message for item in parsed.blockers) + "</div>"
    body += '<p class="eyebrow">The assessment</p><h2>Executive summary</h2><div class="lead">' + _paragraph(source.executive_summary or "The assessment summary is awaiting completion.") + "</div></section>"
    goals = "".join(f'<article class="card"><span class="number">Goal {index:02d}</span><h3>{_h(goal.description)}</h3><p class="label">Success criteria</p>{_list(goal.success_criteria)}</article>' for index, goal in enumerate(source.goals, 1))
    body += '<section class="section"><h2>What success looks like</h2><div class="grid">' + (goals or _paragraph("Goals are awaiting completion.")) + "</div></section>"
    evidence_numbers = {item.evidence_ref: index for index, item in enumerate(source.evidence, 1)}
    findings = []
    for index, finding in enumerate(source.findings, 1):
        citations = ", ".join(f"Evidence {evidence_numbers[ref]}" for ref in finding.evidence_refs if ref in evidence_numbers)
        findings.append(f'<article class="card"><span class="number">Finding {index:02d}</span><h3>{_h(finding.title)}</h3>{_paragraph(finding.observation)}<div class="recommendation"><p class="label">Proposed action</p>{_paragraph(finding.recommendation)}</div><p class="evidence-note">{_h(citations or "Supporting evidence is missing.")} · Assessed {_date(finding.assessed_at)}</p></article>')
    body += f'<section class="section"><div class="section-head"><h2>Findings and proposed actions</h2><span class="count">{len(findings)} findings</span></div><div class="grid">' + ("".join(findings) or _paragraph("Findings are awaiting completion.")) + "</div></section>"
    offers = "".join(f'<article class="card"><span class="label">{_OFFER_LABELS[offer.kind]}</span><h3>{_h(offer.title)}</h3>{_paragraph(offer.outcome)}{_list(offer.scope_of_work)}<p class="quiet">Scope and commercial terms require review.</p></article>' for offer in source.offers)
    body += '<section class="section"><h2>Ways to move forward</h2><p class="quiet">Choose the delivery model that fits your team. Each option has its own scope and quote.</p><div class="grid">' + (offers or _paragraph("Commercial options are awaiting completion.")) + "</div></section>"
    evidence = "".join(f'<article class="evidence"><span class="number">Evidence {index:02d}</span>{_paragraph(item.summary)}<p class="evidence-note">Observed {_date(item.observed_at)} · Valid until {_date(item.valid_until)}</p></article>' for index, item in enumerate(source.evidence, 1))
    body += '<section class="section"><h2>Evidence behind the assessment</h2><p class="quiet">Evidence supplied for this assessment; source records have not been independently verified.</p>' + (evidence or _paragraph("No evidence supplied.")) + "</section>"
    return _preview(parsed, presentation, source.title, "report", body, _report_sections(parsed))


def render_productised_assessment_proposal(dossier: ProductisedAssessmentDossier | Mapping[str, Any], *, offer_ref: str, style: AssessmentPresentationStyle | Mapping[str, Any] | None = None) -> AssessmentDocumentPreview:
    """Render one quoted option, preserving its exact price and billing period."""

    parsed = _parse(dossier)
    presentation = AssessmentPresentationStyle.model_validate(style or {})
    offer = _selected_offer(parsed, offer_ref)
    sections = _proposal_sections(parsed, offer)
    body = '<section class="section"><p class="eyebrow">' + _OFFER_LABELS[offer.kind] + '</p><h2>The proposed outcome</h2><div class="lead">' + _paragraph(offer.outcome) + "</div></section>"
    if parsed.blockers:
        body += '<section class="section"><div class="notice"><h3>Outstanding inputs</h3>' + _list(item.message for item in parsed.blockers) + "</div></section>"
    body += '<section class="section"><div class="grid"><article class="card"><h2>Included in the scope</h2>' + _list(offer.scope_of_work) + '</article><article class="card"><h2>How you will accept the work</h2>' + _list(offer.acceptance_criteria) + "</article></div></section>"
    pricing = offer.pricing
    body += '<section class="section"><h2>Your proposed investment</h2><span class="badge">Quote requires review</span><p class="price">' + _h(_price(offer)) + "</p>"
    if pricing is not None:
        body += _list(f"{line.description}: {_money(line.line_total, pricing.currency)}" for line in pricing.lines)
        if pricing.payment_terms_days is not None:
            body += _paragraph(f"Payment terms: {pricing.payment_terms_days} days.")
        if pricing.valid_until is not None:
            body += '<p class="quiet">Quote valid until ' + _date(pricing.valid_until) + ".</p>"
    body += '</section><section class="section"><div class="grid"><article class="card"><h3>Scope boundaries</h3>' + (_list(offer.exclusions) if offer.exclusions else _paragraph("No exclusions have been supplied; confirm scope boundaries during review.")) + '</article><article class="card"><h3>Timing and agreement</h3>' + _paragraph(sections["timeline"]) + _paragraph("Confirm commercial terms and required approvals before implementation or access is arranged.") + "</article></div></section>"
    return _preview(parsed, presentation, offer.title, "proposal", body, sections)


def prepare_productised_assessment_document(dossier: ProductisedAssessmentDossier | Mapping[str, Any], *, artifact_ref: str, offer_ref: str | None = None) -> GeneratedBusinessArtifact:
    """Validate a Markdown candidate through canonical business-artifact production.

    The returned candidate can project to ``documents.generate_business_artifact``
    with ``create=False``. Spring still owns approval, persistence, and any effect.
    """

    parsed = _parse(dossier)
    source = parsed.inputs
    if parsed.status == "blocked":
        raise ValueError("complete the assessment blockers before preparing a document candidate")
    if source.brand is None or source.customer is None:
        raise ValueError("document preparation requires the scoped brand and customer context")
    offer = _selected_offer(parsed, offer_ref) if offer_ref is not None else None
    if offer is not None and offer.pricing is None:
        raise ValueError("a proposal requires exact commercial pricing")
    scope = source.scope
    request = prepare_business_artifact_generation({
        "scope": {key: getattr(scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "engagement_ref", "customer_ref")},
        "artifact_kind": "proposal" if offer is not None else "one_pager",
        "artifact_format": "markdown",
        "title": offer.title if offer is not None else source.title,
        "purpose": "Prepare the exact assessment and proposed next action for client review.",
        "generation_mode": "template",
        "brand": source.brand.to_dict(),
        "commercial": offer.pricing.to_dict() if offer is not None else None,
        "customer": source.customer.to_dict(),
        "engagement": {"engagement_ref": scope.engagement_ref, "stage": parsed.engagement_assessment.stage, "linked_artifact_digests": [parsed.dossier_digest]},
        "source_artifact_refs": [source.assessment_ref],
        "requested_at": source.prepared_at,
        "requested_by_ref": source.requested_by_ref,
    })
    return validate_generated_business_artifact({
        "request": request.to_dict(),
        "submission": {
            "brief_digest": request.brief.brief_digest,
            "sections": _proposal_sections(parsed, offer) if offer is not None else _report_sections(parsed),
            "provenance": {"generator_kind": "template", "generated_at": source.prepared_at},
        },
        "artifact_ref": artifact_ref,
        "validated_at": source.prepared_at,
        "requested_by_ref": source.requested_by_ref,
    })
