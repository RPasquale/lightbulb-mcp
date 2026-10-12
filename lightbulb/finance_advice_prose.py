"""Prose pinned to the record: the constraint validator, the template explanation and grounded answers.

A client asks "what does it cost, what changes, what must I do", and the adviser's record answers
in evidence, not in sentences. This module lets sentences exist under one rule: every paragraph
cites a fact ref from the record, every number in a paragraph appears in a cited fact, every product
named is in the record, no forbidden phrase and no identity token appears, and the output is sealed
against the record and recommendation digests. The default path is model-free: templates that pass
the validator by construction. The same validator is the single door a worker-side model draft
passes through, so no model sits on the critical path and none is called here. Nothing in this
module advises: an explanation carries the record digest and the recommendation digest and a
watermark until the licensed adviser approves the recommendation it explains.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field, ValidationError, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, BoundedText, OpaqueRef, Sha256Digest, ShortText, StrictModel, detached, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_catalog import reject_credential_payload
from lightbulb.finance_advice_document import AdviceDocument, html_from_markdown
from lightbulb.finance_advice_record import RecordOfAdviceEvidence
from lightbulb.finance_advice_identity import identity_markers, reject_identity_payload

PROSE_SCHEMA = "lightbulb.finance_advice_prose_draft.v1"
PROSE_VALIDATION_SCHEMA = "lightbulb.finance_advice_prose_validation.v1"
EXPLANATION_SCHEMA = "lightbulb.finance_advice_client_explanation.v1"
ANSWER_SCHEMA = "lightbulb.finance_advice_grounded_answer.v1"

FORBIDDEN_PHRASES: tuple[str, ...] = ("guaranteed", "risk-free", "cannot lose", "best on the market", "no fees", "tax-free", "you must buy", "apply now", "we will submit")
REQUIRED_SECTIONS: tuple[str, ...] = ("what_we_recommend", "why", "what_it_costs", "what_changes", "what_you_must_do", "risks_and_warnings", "how_we_are_paid")
ANSWER_TOPICS: tuple[str, ...] = ("cost", "fees", "rate", "switching_cost", "cover_amount", "waiting_period", "why_this_product", "why_not_alternative", "remuneration", "next_steps", "review_when", "risks")
MAX_PARAGRAPHS = 60
MAX_PARAGRAPH_CHARS = 1200
NOT_IN_RECORD = "The record does not state this; the adviser will answer"
EXPLANATION_WATERMARK = "Explanation of the record {digest}; not advice until the licensed adviser approves the recommendation it explains"

RefKind = Literal["fact", "eligibility", "rationale", "disclosure", "requirement", "fact_find", "needs", "switch", "rule", "remuneration", "cashflow", "serviceability", "approval", "authority"]
FindingCode = Literal["uncited", "unknown_ref", "number_not_in_cited_facts", "product_not_in_record", "forbidden_phrase", "section_missing", "record_mismatch", "recommendation_without_recommendation", "too_long", "prose_carries_identity"]
Drafter = Literal["person", "model", "template"]
StepActor = Literal["client", "adviser", "worker"]
ObjectionKind = Literal["cost", "switching_hassle", "why_this_provider", "why_not_cheaper", "do_nothing", "too_much_cover"]

_SECTION_TITLES = {"what_we_recommend": "What we recommend", "why": "Why", "what_it_costs": "What it costs", "what_changes": "What changes", "what_you_must_do": "What you must do", "risks_and_warnings": "Risks and warnings", "how_we_are_paid": "How we are paid"}
_TOPIC_QUESTIONS = {"cost": "What does it cost?", "fees": "What fees apply?", "rate": "What is the rate?", "switching_cost": "What does switching cost?", "cover_amount": "How much cover does the record assess?", "waiting_period": "What is the waiting period?", "why_this_product": "Why this product?", "why_not_alternative": "Why not one of the alternatives?", "remuneration": "How is the adviser paid?", "next_steps": "What happens next?", "review_when": "When is this reviewed?", "risks": "What are the risks and warnings?"}
_JURISDICTION_TERMS: dict[str, dict[str, str]] = {"AU": {"adviser": "adviser", "licence": "licence"}, "CA": {"adviser": "advisor", "licence": "licence"}}
_COVER_ITEMS = ("cover", "sum insured", "benefit")
_NUMBER = re.compile(r"(?<![A-Za-z])[-+]?\d[\d,]*(?:\.\d+)?")
_TITLE_RUN = re.compile(r"\b[A-Z][A-Za-z'&-]+(?:\s+[A-Z][A-Za-z'&-]+)+")
_RECOMMENDS = re.compile(r"\b(?:we recommend|recommended product|our recommendation|the recommendation)\b")
_IDENTITY: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("an email address", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
    ("a phone number", re.compile(r"(?:\+\d{1,3}[\s-]?\d[\d\s-]{7,}\d)|(?:\b0\d{1,3}[\s-]?\d{3,4}[\s-]?\d{3,4}\b)")),
    ("a name-like token", re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Dear)\.?\s+[A-Z][a-z]+")),
    ("a date of birth", re.compile(r"\b(?:date of birth|DOB|born on)\b", re.IGNORECASE)),
    ("a nine-digit identifier", re.compile(r"\b\d{3}[ -]\d{3}[ -]\d{3}\b")),
)


class AdviceProseError(ValueError):
    """A refusal with a code, and the validator's findings when prose was refused."""

    def __init__(self, code: str, message: str, findings: Sequence[ProseFinding] = ()) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.findings = tuple(findings)


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #


class FactRef(StrictModel):
    """One thing the record states, addressable by ref, with the text a paragraph may draw its words and numbers from."""

    ref: str = Field(min_length=1)
    kind: RefKind
    text: str = Field(min_length=1)
    value: str | None = None
    unit: str | None = None
    source_url: str | None = None
    product_ref: OpaqueRef | None = None


class Paragraph(StrictModel):
    section: str = Field(min_length=1)
    text: BoundedText
    cited: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("cited", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class ProseDraft(StrictModel):
    """Words someone or something drafted against one record; nothing about a draft is trusted until validated."""

    schema_id: str = Field(default=PROSE_SCHEMA, alias="schema")
    record_digest: Sha256Digest
    recommendation_digest: Sha256Digest | None = None
    paragraphs: tuple[Paragraph, ...] = Field(default_factory=tuple)
    drafted_by_ref: OpaqueRef
    drafted_at: str
    drafter: Drafter = "person"
    model_ref: OpaqueRef | None = None
    draft_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("paragraphs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> ProseDraft:
        if self.drafter == "model" and self.model_ref is None:
            raise ValueError("MODEL_REF_REQUIRED: a model draft names the model as an opaque ref")
        if not skip_digests(info) and self.draft_digest != sealed_digest(ProseDraft, self, "draft_digest"):
            raise ValueError("draft_digest does not match the draft")
        return self


class ProseFinding(StrictModel):
    paragraph_index: int
    code: FindingCode
    detail: ShortText


class ProseValidation(StrictModel):
    schema_id: str = Field(default=PROSE_VALIDATION_SCHEMA, alias="schema")
    draft_digest: Sha256Digest
    record_digest: Sha256Digest
    findings: tuple[ProseFinding, ...] = Field(default_factory=tuple)
    sections_covered: tuple[str, ...] = Field(default_factory=tuple)
    valid: bool
    validation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("findings", "sections_covered", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> ProseValidation:
        if self.valid and self.findings:
            raise ValueError("a validation with findings is not valid")
        if not skip_digests(info) and self.validation_digest != sealed_digest(ProseValidation, self, "validation_digest"):
            raise ValueError("validation_digest does not match the validation")
        return self


class ClientExplanation(StrictModel):
    """A validated explanation of one record, sealed against the record, the recommendation, the draft and its validation."""

    schema_id: str = Field(default=EXPLANATION_SCHEMA, alias="schema")
    title: str = Field(min_length=1)
    jurisdiction: str
    vertical_id: str
    mode: str
    record_digest: Sha256Digest
    recommendation_digest: Sha256Digest
    record_complete: bool = False
    draft_digest: Sha256Digest
    validation_digest: Sha256Digest
    drafter: Drafter
    paragraphs: tuple[Paragraph, ...] = Field(min_length=1)
    footnotes: tuple[FactRef, ...] = Field(default_factory=tuple)
    markdown: str = Field(min_length=1)
    prepared_at: str
    explanation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("paragraphs", "footnotes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> ClientExplanation:
        if not skip_digests(info) and self.explanation_digest != sealed_digest(ClientExplanation, self, "explanation_digest"):
            raise ValueError("explanation_digest does not match the explanation")
        return self


class GroundedAnswer(StrictModel):
    """An answer to one question made only of paragraphs the validator passed, or a refusal naming what the record does not say."""

    schema_id: str = Field(default=ANSWER_SCHEMA, alias="schema")
    record_digest: Sha256Digest
    question: BoundedText
    topic: str | None = None
    paragraphs: tuple[Paragraph, ...] = Field(default_factory=tuple)
    footnotes: tuple[FactRef, ...] = Field(default_factory=tuple)
    refused: bool = False
    refusal_reason: ShortText | None = None
    omitted: int = 0
    draft_digest: Sha256Digest | None = None
    validation_digest: Sha256Digest | None = None
    answered_by_ref: OpaqueRef
    answered_at: str
    answer_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("paragraphs", "footnotes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> GroundedAnswer:
        if self.refused and self.paragraphs:
            raise ValueError("a refused answer carries no paragraphs")
        if self.refused and not self.refusal_reason:
            raise ValueError("a refused answer names what the record does not say")
        if not self.refused and not self.paragraphs:
            raise ValueError("an answer that is not refused carries at least one paragraph")
        if not skip_digests(info) and self.answer_digest != sealed_digest(GroundedAnswer, self, "answer_digest"):
            raise ValueError("answer_digest does not match the answer")
        return self


class NextStep(StrictModel):
    who: StepActor
    what: ShortText
    due: str | None = None
    refs: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class ObjectionResponse(StrictModel):
    kind: ObjectionKind
    paragraphs: tuple[Paragraph, ...] = Field(min_length=1)
    footnotes: tuple[FactRef, ...] = Field(default_factory=tuple)

    @field_validator("paragraphs", "footnotes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


# --------------------------------------------------------------------------- #
# Reading the record
# --------------------------------------------------------------------------- #


def _view(record: RecordOfAdviceEvidence | Mapping[str, Any]) -> dict[str, Any]:
    """The record as plain data; a Mapping is read duck-typed so fields other blocks add (strategy, serviceability, remuneration) are seen."""
    raw = dict(detached(record))
    digest = raw.get("record_digest")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise AdviceProseError("RECORD_UNSEALED", "prose is pinned to a sealed record; the record carries no record_digest")
    return raw


def _text(value: Any) -> str:
    if isinstance(value, Mapping):
        return "; ".join(f"{key} {_text(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return ", ".join(_text(item) for item in value)
    return str(value)


def _products(view: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(item) for item in [view.get("recommended"), *(view.get("alternatives") or ())] if item]


def _product_name(product: Mapping[str, Any]) -> str:
    return f"{product.get('provider_name')} — {product.get('product_name')}"


def _product_refs(product: Mapping[str, Any]) -> list[FactRef]:
    ref = str(product["product_ref"])
    name = _product_name(product)
    facts = [dict(item) for item in product.get("facts") or ()]
    first_url = next((fact.get("source_url") for fact in facts if fact.get("source_url")), None)
    identity = f"{name} ({product.get('taxonomy_class')}); suitability {product.get('suitability')}; confidence {product.get('confidence')}; pricing {product.get('pricing_kind')}"
    if product.get("score") is not None:
        identity += f"; score {product['score']}"
    if product.get("projected_cost") is not None:
        identity += f"; projected cost {product['projected_cost']} over {product.get('projection_horizon_years')} years"
    out = [FactRef(ref=f"fact:{ref}#product", kind="fact", text=identity, source_url=first_url, product_ref=ref)]
    for fact in facts:
        text = f"{name}: {fact.get('item')} {fact.get('value') if fact.get('value') is not None else 'unstated'} {fact.get('unit') or ''}".rstrip()
        if fact.get("document_title"):
            text += f" (from {fact['document_title']})"
        if fact.get("retrieved_at"):
            text += f" (retrieved {fact['retrieved_at']})"
        if fact.get("quote"):
            text += f" quote: {fact['quote']}"
        out.append(FactRef(ref=f"fact:{ref}#{fact.get('item')}", kind="fact", text=text, value=None if fact.get("value") is None else str(fact["value"]), unit=fact.get("unit"), source_url=fact.get("source_url"), product_ref=ref))
    if product.get("projected_cost") is not None:
        out.append(FactRef(ref=f"fact:{ref}#projected cost", kind="fact", text=f"{name}: projected cost {product['projected_cost']} over {product.get('projection_horizon_years')} years", value=str(product["projected_cost"]), source_url=first_url, product_ref=ref))
    for index, line in enumerate(product.get("eligibility") or ()):
        out.append(FactRef(ref=f"eligibility:{ref}#{index}", kind="eligibility", text=f"{name}: {line}", source_url=first_url, product_ref=ref))
    return out


def _switch_text(item: Mapping[str, Any]) -> str:
    costs = ", ".join(f"{_text(cost.get('label') if isinstance(cost, Mapping) else cost)} {cost.get('amount') if isinstance(cost, Mapping) else ''}".strip() for cost in item.get("one_off_costs") or ())
    text = f"stay or switch ({item.get('candidate_product_name')}): staying costs {item.get('stay_total')} against switching {item.get('switch_total')} over {item.get('horizon_years')} years; verdict {item.get('verdict')}"
    if costs:
        text += f"; one-off costs: {costs}"
    if item.get("breakeven_months") is not None:
        text += f"; breakeven {item['breakeven_months']} months"
    if item.get("saving_over_horizon") is not None:
        text += f"; saving over the horizon {item['saving_over_horizon']}"
    for key in ("features_lost", "features_gained", "reasons", "assumptions", "missing"):
        if item.get(key):
            text += f"; {key.replace('_', ' ')}: {_text(item[key])}"
    return text


def _needs_text(needs: Mapping[str, Any]) -> str:
    text = f"assessed need ({needs.get('kind')}): {needs.get('need') if needs.get('need') is not None else 'incomplete'} {needs.get('unit') or ''}".rstrip()
    if needs.get("components"):
        text += "; components: " + ", ".join(f"{key} {value}" for key, value in dict(needs["components"]).items())
    if needs.get("existing_cover") not in (None, "0", 0):
        text += f"; existing cover {needs['existing_cover']}"
    if needs.get("waiting_period_days") is not None:
        text += f"; waiting period {needs['waiting_period_days']} days"
    if needs.get("benefit_period_years") is not None:
        text += f"; benefit period {needs['benefit_period_years']} years"
    if needs.get("assumptions"):
        text += "; assumptions: " + "; ".join(str(item) for item in needs["assumptions"])
    if needs.get("missing"):
        text += "; missing: " + ", ".join(str(item) for item in needs["missing"])
    return text


def _strategy_lines(strategy: Any) -> list[str]:
    if not strategy:
        return []
    if isinstance(strategy, str):
        return [strategy]
    if isinstance(strategy, Mapping):
        items = strategy.get("goal_lines") or strategy.get("goals_in_order") or strategy.get("goals") or ()
    else:
        items = strategy
    return [item if isinstance(item, str) else _text(item) for item in items]


def fact_refs(record: RecordOfAdviceEvidence | Mapping[str, Any]) -> tuple[FactRef, ...]:
    """Every ref a paragraph may cite, with the text the paragraph's words and numbers must come from."""
    r = _view(record)
    out: list[FactRef] = []
    for product in _products(r):
        out.extend(_product_refs(product))
    for index, line in enumerate(r.get("rationale") or ()):
        out.append(FactRef(ref=f"rationale:{index}", kind="rationale", text=str(line)))
    for index, line in enumerate(r.get("disclosures") or ()):
        out.append(FactRef(ref=f"disclosure:{index}", kind="disclosure", text=str(line)))
    for item in r.get("requirements") or ():
        req = dict(item)
        out.append(FactRef(ref=f"requirement:{req.get('key')}", kind="requirement", text=f"{req.get('label')}: {req.get('status')} — {req.get('evidence')}", value=str(req.get("status"))))
    for key, value in sorted((r.get("fact_find") or {}).items()):
        out.append(FactRef(ref=f"fact_find:{key}", kind="fact_find", text=f"{key}: {_text(value)}", value=_text(value)))
    needs = dict(r.get("needs") or {})
    if needs.get("kind"):
        out.append(FactRef(ref=f"needs:{needs['kind']}", kind="needs", text=_needs_text(needs), value=None if needs.get("need") is None else str(needs["need"]), unit=needs.get("unit")))
    for item in r.get("switching") or ():
        switch = dict(item)
        out.append(FactRef(ref=f"switch:{switch.get('holding_ref')}", kind="switch", text=_switch_text(switch), value=None if switch.get("switch_total") is None else str(switch["switch_total"]), product_ref=switch.get("candidate_product_ref") if isinstance(switch.get("candidate_product_ref"), str) else None))
    for index, line in enumerate(r.get("rule_disclosures") or ()):
        out.append(FactRef(ref=f"rule:{index}", kind="rule", text=str(line)))
    if r.get("remuneration_disclosure"):
        out.append(FactRef(ref="remuneration:0", kind="remuneration", text=str(r["remuneration_disclosure"])))
    remuneration = r.get("remuneration")
    if isinstance(remuneration, Mapping):
        for index, line in enumerate(remuneration.get("statements") or ()):
            out.append(FactRef(ref=f"remuneration:{index + 1}", kind="remuneration", text=str(line)))
    for index, line in enumerate(_strategy_lines(r.get("strategy"))):
        out.append(FactRef(ref=f"cashflow:{index}", kind="cashflow", text=line))
    verdicts = r.get("serviceability")
    for item in ([verdicts] if isinstance(verdicts, Mapping) else list(verdicts or ())):
        verdict = dict(item)
        if verdict.get("product_ref"):
            text = f"serviceability of {verdict['product_ref']}: {verdict.get('verdict')}; assessed rate {verdict.get('assessed_rate_percent')} percent; monthly repayment {verdict.get('monthly_repayment')}; monthly surplus after {verdict.get('monthly_surplus_after')}"
            if verdict.get("reasons"):
                text += "; " + "; ".join(str(reason) for reason in verdict["reasons"])
            out.append(FactRef(ref=f"serviceability:{verdict['product_ref']}", kind="serviceability", text=text, value=str(verdict.get("verdict")), product_ref=str(verdict["product_ref"]) if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}", str(verdict["product_ref"])) else None))
    approval = dict(r.get("approval") or {})
    if approval.get("approval_ref"):
        out.append(FactRef(ref="approval", kind="approval", text=f"approval {approval.get('approval_ref')}: adviser {approval.get('adviser_ref')} approved this recommendation under {approval.get('authority_kind')} at {approval.get('approved_at')}", value=str(approval.get("approval_ref"))))
    for index, line in enumerate(r.get("authorities") or ()):
        out.append(FactRef(ref=f"authority:{index}", kind="authority", text=f"advice given under {line}"))
    return tuple(out)


# --------------------------------------------------------------------------- #
# The validator
# --------------------------------------------------------------------------- #


def numbers_in(text: str) -> tuple[str, ...]:
    """The numeric tokens of a text, normalised: commas dropped, trailing zeros after a point dropped, leading zeros of the integer part dropped.

    A minus sign is kept when it opens the token (start of text, after a space, a bracket or a colon), so a figure the
    record states as -2100.00 is not quotable as 2100.00; a minus between characters (2026-09-05, 5.79-5.99) is a hyphen.
    """
    out: list[str] = []
    for match in _NUMBER.finditer(text):
        raw = match.group(0)
        negative = raw.startswith("-") and (match.start() == 0 or text[match.start() - 1] in " \t\n(:=[")
        token = raw.lstrip("+-").replace(",", "")
        whole, point, fraction = token.partition(".")
        whole = whole.lstrip("0") or "0"
        fraction = fraction.rstrip("0")
        token = f"{whole}.{fraction}" if fraction else whole
        if negative and token != "0":
            token = f"-{token}"
        if token not in out:
            out.append(token)
    return tuple(out)


def _known_names(view: Mapping[str, Any]) -> list[str]:
    names: list[str] = []
    for product in _products(view):
        names.extend(str(product.get(key)) for key in ("provider_name", "product_name") if product.get(key))
    for item in view.get("switching") or ():
        switch = dict(item)
        names.extend(str(switch.get(key)) for key in ("candidate_product_name", "current_product_name", "current_provider_name") if switch.get(key))
    for item in view.get("benefit_fit") or ():
        if dict(item).get("product_name"):
            names.append(str(dict(item)["product_name"]))
    return names


def _phrase_excused(phrase: str, cited: Sequence[FactRef]) -> bool:
    if phrase == "no fees":
        return any(("no fee" in ref.text.lower()) or ("fee" in ref.ref.lower() and ref.value is not None and numbers_in(ref.value) == ("0",)) for ref in cited)
    if phrase == "tax-free":
        return any(ref.kind == "rule" for ref in cited)
    return False


def _inside_known_name(phrase: str, lower: str, names: Sequence[str]) -> bool:
    """True when every occurrence of the phrase lies inside a product or provider name the record carries (a product called 'Guaranteed Renewable Term' may be named); a use outside the name is still refused."""
    spans = [(match.start(), match.end()) for name in names if phrase in name.lower() for match in re.finditer(re.escape(name.lower()), lower)]
    if not spans:
        return False
    return all(any(start <= match.start() and match.end() <= end for start, end in spans) for match in re.finditer(re.escape(phrase), lower))


def _identity_markers(text: str) -> list[str]:
    found = list(dict.fromkeys([*identity_markers(text), *[label for label, pattern in _IDENTITY if pattern.search(text)]]))
    try:
        reject_credential_payload(text)
    except ValueError:
        found.append("a credential-like value")
    return found


def _draft(draft: ProseDraft | Mapping[str, Any]) -> ProseDraft:
    return draft if isinstance(draft, ProseDraft) else ProseDraft.model_validate(dict(detached(draft)))


def validate_prose(record: RecordOfAdviceEvidence | Mapping[str, Any], draft: ProseDraft | Mapping[str, Any], *, require_sections: bool = True) -> ProseValidation:
    """Every paragraph cites the record, every number is a cited figure, every product named is in the record, no forbidden phrase, no identity."""
    r = _view(record)
    d = _draft(draft)
    refs = {ref.ref: ref for ref in fact_refs(r)}
    ref_texts = [ref.text.lower() for ref in refs.values()]
    names = _known_names(r)
    findings: list[ProseFinding] = []
    if d.record_digest != r["record_digest"]:
        findings.append(ProseFinding(paragraph_index=-1, code="record_mismatch", detail=f"the draft was written against record {d.record_digest[:16]}, not {r['record_digest'][:16]}"))
    if len(d.paragraphs) > MAX_PARAGRAPHS:
        findings.append(ProseFinding(paragraph_index=-1, code="too_long", detail=f"{len(d.paragraphs)} paragraphs; at most {MAX_PARAGRAPHS}"))
    covered: list[str] = []
    for index, paragraph in enumerate(d.paragraphs):
        local: list[ProseFinding] = []
        markers = _identity_markers(paragraph.text)
        if markers:
            findings.extend(ProseFinding(paragraph_index=index, code="prose_carries_identity", detail=f"the paragraph carries {marker}; prose names no person") for marker in markers)
            continue
        lower = paragraph.text.lower()
        if len(paragraph.text) > MAX_PARAGRAPH_CHARS:
            local.append(ProseFinding(paragraph_index=index, code="too_long", detail=f"{len(paragraph.text)} characters; at most {MAX_PARAGRAPH_CHARS}"))
        if not paragraph.cited:
            local.append(ProseFinding(paragraph_index=index, code="uncited", detail="the paragraph cites no fact ref from the record"))
        unknown = [ref for ref in paragraph.cited if ref not in refs]
        for ref in unknown:
            local.append(ProseFinding(paragraph_index=index, code="unknown_ref", detail=f"{ref[:120]} is not a ref the record has"))
        cited = [refs[ref] for ref in paragraph.cited if ref in refs]
        allowed: set[str] = set()
        for ref in cited:
            allowed.update(numbers_in(ref.text))
            if ref.value is not None:
                allowed.update(numbers_in(ref.value))
        stray = [token for token in numbers_in(paragraph.text) if token not in allowed]
        if stray:
            local.append(ProseFinding(paragraph_index=index, code="number_not_in_cited_facts", detail=("no cited fact states " + ", ".join(stray))[:300]))
        for match in _TITLE_RUN.finditer(paragraph.text):
            run = match.group(0).lower()
            if not any(name.lower() in run or run in name.lower() for name in names) and not any(run in text for text in ref_texts):
                local.append(ProseFinding(paragraph_index=index, code="product_not_in_record", detail=f"{match.group(0)[:120]} is not a product, provider or statement in the record"))
        for phrase in FORBIDDEN_PHRASES:
            if phrase in lower and not _phrase_excused(phrase, cited) and not _inside_known_name(phrase, lower, names):
                local.append(ProseFinding(paragraph_index=index, code="forbidden_phrase", detail=f"'{phrase}' is never written unless the record states it"))
        if r.get("recommendation_digest") is None and (paragraph.section == "what_we_recommend" or _RECOMMENDS.search(lower)):
            local.append(ProseFinding(paragraph_index=index, code="recommendation_without_recommendation", detail="the record carries no recommendation; nothing is recommended in words"))
        if not local and paragraph.section not in covered:
            covered.append(paragraph.section)
        findings.extend(local)
    if require_sections:
        for section in REQUIRED_SECTIONS:
            if section not in covered:
                findings.append(ProseFinding(paragraph_index=-1, code="section_missing", detail=f"no valid paragraph covers {section}"))
    ordered = [section for section in REQUIRED_SECTIONS if section in covered] + [section for section in covered if section not in REQUIRED_SECTIONS]
    return seal(ProseValidation, {"draft_digest": d.draft_digest, "record_digest": r["record_digest"], "findings": [item.to_dict() for item in findings], "sections_covered": ordered, "valid": not findings}, "validation_digest")


def prose_draft(record: RecordOfAdviceEvidence | Mapping[str, Any], paragraphs: Sequence[Paragraph | Mapping[str, Any]], *, drafted_by_ref: str, drafted_at: str, drafter: Drafter = "person", model_ref: str | None = None) -> ProseDraft:
    """Seal a draft against the record it was written for; the validator decides whether any of it stands."""
    r = _view(record)
    items = [item if isinstance(item, Paragraph) else Paragraph.model_validate(dict(detached(item))) for item in paragraphs]
    return seal(ProseDraft, {"record_digest": r["record_digest"], "recommendation_digest": r.get("recommendation_digest"), "paragraphs": [item.to_dict() for item in items], "drafted_by_ref": drafted_by_ref, "drafted_at": timestamp(drafted_at, field_name="drafted_at"), "drafter": drafter, "model_ref": model_ref}, "draft_digest")


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _footnotes(paragraphs: Sequence[Paragraph], refs: Mapping[str, FactRef]) -> list[FactRef]:
    out: list[FactRef] = []
    seen: set[str] = set()
    for paragraph in paragraphs:
        for ref in paragraph.cited:
            if ref in refs and ref not in seen:
                seen.add(ref)
                out.append(refs[ref])
    return out


def _section_title(section: str) -> str:
    return _SECTION_TITLES.get(section) or section.replace("_", " ").capitalize()


def _markdown(title: str, header: Sequence[str], paragraphs: Sequence[Paragraph], footnotes: Sequence[FactRef]) -> str:
    numbers = {ref.ref: index + 1 for index, ref in enumerate(footnotes)}
    lines = [f"# {title}", "", *header, ""]
    current: str | None = None
    for paragraph in paragraphs:
        if paragraph.section != current:
            current = paragraph.section
            lines += [f"## {_section_title(current)}", ""]
        marks = " ".join(f"[{numbers[ref]}]" for ref in paragraph.cited if ref in numbers)
        lines += [f"{paragraph.text} {marks}".rstrip(), ""]
    if footnotes:
        lines += ["## Sources", ""]
        for ref in footnotes:
            lines.append(f"- [{numbers[ref.ref]}] {ref.ref} — {ref.text}" + (f" ({ref.source_url})" if ref.source_url else ""))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def explanation_watermark(explanation: ClientExplanation | Mapping[str, Any]) -> str:
    """What the explanation says about itself; the same words the document module writes once it knows this kind."""
    digest = explanation.record_digest if isinstance(explanation, ClientExplanation) else str(dict(explanation).get("record_digest"))
    return EXPLANATION_WATERMARK.format(digest=digest)


def client_explanation(record: RecordOfAdviceEvidence | Mapping[str, Any], draft: ProseDraft | Mapping[str, Any], *, prepared_at: str, title: str | None = None) -> ClientExplanation:
    """Seal a validated draft as the explanation of one record; an invalid draft is refused with its findings."""
    r = _view(record)
    d = _draft(draft)
    validation = validate_prose(r, d, require_sections=True)
    if not validation.valid:
        raise AdviceProseError("PROSE_INVALID", "; ".join(f"[{item.paragraph_index}] {item.code}: {item.detail}" for item in validation.findings)[:1500], validation.findings)
    if r.get("recommendation_digest") is None:
        raise AdviceProseError("INCOMPLETE_RECORD", "the record carries no recommendation to explain")
    refs = {ref.ref: ref for ref in fact_refs(r)}
    footnotes = _footnotes(d.paragraphs, refs)
    stamp = timestamp(prepared_at, field_name="prepared_at")
    name = title or f"Explanation of the record: {r.get('vertical_name')} ({r.get('jurisdiction')})"
    header = [f"Explanation of record {r['record_digest'][:16]}… and recommendation {str(r['recommendation_digest'])[:16]}…; drafted by {d.drafter} ({d.drafted_by_ref}); prepared {stamp}.", "", "Every paragraph cites the record and every figure is one the record states. It is not advice until the licensed adviser approves the recommendation it explains."]
    markdown = _markdown(name, header, d.paragraphs, footnotes)
    return seal(ClientExplanation, {"title": name, "jurisdiction": r["jurisdiction"], "vertical_id": r["vertical_id"], "mode": r.get("mode") or "unstated", "record_digest": r["record_digest"], "recommendation_digest": r["recommendation_digest"], "record_complete": bool(r.get("complete")), "draft_digest": d.draft_digest, "validation_digest": validation.validation_digest, "drafter": d.drafter, "paragraphs": [item.to_dict() for item in d.paragraphs], "footnotes": [item.to_dict() for item in footnotes], "markdown": markdown, "prepared_at": stamp}, "explanation_digest")


def explanation_document(explanation: ClientExplanation | Mapping[str, Any], *, prepared_at: str, retain_until: str | None = None) -> AdviceDocument:
    """The explanation as a document of kind client_explanation, watermarked and sealed; needs the document module to know the kind."""
    e = explanation if isinstance(explanation, ClientExplanation) else ClientExplanation.model_validate(dict(detached(explanation)))
    stamp = timestamp(prepared_at, field_name="prepared_at")
    mark = explanation_watermark(e)
    how = "rendered from the platform's templates" if e.drafter == "template" else f"drafted by a {e.drafter} and validated against the record"
    footer = f"Prepared {stamp} from record {e.record_digest} and explanation {e.explanation_digest}. The words were {how}; the recommendation is the licensed adviser's." + (f" Retain until {retain_until}." if retain_until else "")
    html = html_from_markdown(e.markdown, title=e.title, watermark=mark, approved=False, footer=footer)
    try:
        return seal(AdviceDocument, {"kind": "client_explanation", "title": e.title, "jurisdiction": e.jurisdiction, "vertical_id": e.vertical_id, "mode": e.mode, "record_digest": e.record_digest, "complete": e.record_complete, "watermark": mark, "markdown": e.markdown, "html": html, "retain_until": retain_until, "prepared_at": stamp}, "document_digest")
    except ValidationError as exc:
        raise AdviceProseError("DOCUMENT_KIND_UNSUPPORTED", "finance_advice_document.DocumentKind does not yet include client_explanation; apply scratch_patches/prose.py") from exc


# --------------------------------------------------------------------------- #
# The template explanation: model-free, valid by construction
# --------------------------------------------------------------------------- #


def _para(section: str, text: str, *cited: str) -> Paragraph:
    return Paragraph(section=section, text=text[:MAX_PARAGRAPH_CHARS], cited=tuple(cited))


def _cost_paragraphs(section: str, product: Mapping[str, Any], *, family: str) -> list[Paragraph]:
    ref = str(product["product_ref"])
    name = str(product.get("product_name"))
    facts = [dict(item) for item in product.get("facts") or ()]
    out: list[Paragraph] = []
    lead = {"credit": "what the loan costs", "insurance": "what the cover costs", "deposits": "what the account costs and pays", "investments": "what the investment costs"}.get(family, "what it costs")
    for fact in facts:
        stated = f"{fact.get('value')} {fact.get('unit') or ''}".strip() if fact.get("value") is not None else "not stated as a figure"
        retrieved = f" (document retrieved {fact['retrieved_at']})" if fact.get("retrieved_at") else ""
        out.append(_para(section, f"On {lead}, the provider's own document states {fact.get('item')} of {stated} for {name}{retrieved}.", f"fact:{ref}#{fact.get('item')}"))
    if product.get("projected_cost") is not None:
        out.append(_para(section, f"Over {product.get('projection_horizon_years')} years the record projects a cost of {product['projected_cost']} for {name}.", f"fact:{ref}#projected cost"))
    if not out:
        out.append(_para(section, f"The record carries no priced fact for {name}; the cost is not stated and the adviser confirms it.", f"fact:{ref}#product"))
    return out


def _changes_paragraphs(section: str, view: Mapping[str, Any], requirement_status: Mapping[str, str]) -> list[Paragraph]:
    out: list[Paragraph] = []
    for item in view.get("switching") or ():
        switch = dict(item)
        text = f"If the client switches to {switch.get('candidate_product_name')}, staying costs {switch.get('stay_total')} and switching costs {switch.get('switch_total')} over {switch.get('horizon_years')} years; the record's verdict is {switch.get('verdict')}."
        if switch.get("breakeven_months") is not None:
            text += f" Switching pays for itself after {switch['breakeven_months']} months."
        if switch.get("features_lost"):
            text += " Features the client would lose: " + ", ".join(str(feature) for feature in switch["features_lost"]) + "."
        out.append(_para(section, text, f"switch:{switch.get('holding_ref')}"))
    if out:
        return out
    status = requirement_status.get("replacement")
    if status == "missing":
        out.append(_para(section, "The client holds a product the record has not yet compared with the recommended one; the adviser completes that comparison before anything changes.", "requirement:replacement"))
    elif status == "satisfied":
        out.append(_para(section, "The record notes that the products the client already holds were compared; what changes is set out in the record's comparison.", "requirement:replacement"))
    else:
        out.append(_para(section, "Nothing the client already holds is replaced: the record names no existing product.", "requirement:replacement"))
    return out


def _risk_paragraphs(section: str, view: Mapping[str, Any], product: Mapping[str, Any] | None) -> list[Paragraph]:
    out: list[Paragraph] = []
    if product:
        ref = str(product["product_ref"])
        for index, line in enumerate(product.get("eligibility") or ()):
            out.append(_para(section, f"The provider states: {line}", f"eligibility:{ref}#{index}"))
    for index, line in enumerate(view.get("disclosures") or ()):
        out.append(_para(section, f"Disclosure: {line}", f"disclosure:{index}"))
    for index, line in enumerate(view.get("rule_disclosures") or ()):
        out.append(_para(section, f"The jurisdiction's rules: {line}", f"rule:{index}"))
    return out


def _paid_paragraphs(section: str, view: Mapping[str, Any]) -> list[Paragraph]:
    out: list[Paragraph] = []
    if view.get("remuneration_disclosure"):
        out.append(_para(section, f"How the business is paid: {view['remuneration_disclosure']}", "remuneration:0"))
    remuneration = view.get("remuneration")
    if isinstance(remuneration, Mapping):
        for index, line in enumerate(remuneration.get("statements") or ()):
            out.append(_para(section, str(line), f"remuneration:{index + 1}"))
    return out


def _valid_only(view: Mapping[str, Any], paragraphs: Sequence[Paragraph], *, drafted_at: str) -> list[Paragraph]:
    """Keep the paragraphs the validator passes; a disclosure the operator wrote with a forbidden phrase drops out rather than fails the whole explanation."""
    if not paragraphs:
        return []
    draft = prose_draft(view, paragraphs, drafted_by_ref="template", drafted_at=drafted_at, drafter="template")
    bad = {item.paragraph_index for item in validate_prose(view, draft, require_sections=False).findings}
    return [paragraph for index, paragraph in enumerate(paragraphs) if index not in bad]


def _pack(paragraphs: Sequence[Paragraph]) -> list[Paragraph]:
    """When the record states more lines than MAX_PARAGRAPHS, join neighbouring paragraphs of one section, keeping every citation; nothing the record states is dropped to fit."""
    if len(paragraphs) <= MAX_PARAGRAPHS:
        return list(paragraphs)
    out: list[Paragraph] = []
    for paragraph in paragraphs:
        last = out[-1] if out else None
        if last is not None and last.section == paragraph.section and len(last.text) + 1 + len(paragraph.text) <= MAX_PARAGRAPH_CHARS:
            out[-1] = Paragraph(section=paragraph.section, text=f"{last.text} {paragraph.text}", cited=tuple(dict.fromkeys([*last.cited, *paragraph.cited])))
        else:
            out.append(paragraph)
    return out


def deterministic_explanation(record: RecordOfAdviceEvidence | Mapping[str, Any], *, prepared_at: str, jurisdiction_terms: Mapping[str, str] | None = None) -> ClientExplanation:
    """The model-free explanation: one template per section per family, every sentence built from a cited ref."""
    r = _view(record)
    product = r.get("recommended")
    if not product or r.get("recommendation_digest") is None:
        raise AdviceProseError("INCOMPLETE_RECORD", "the record carries no recommendation; nothing is explained and nothing is invented")
    terms = {**_JURISDICTION_TERMS.get(str(r.get("jurisdiction")), _JURISDICTION_TERMS["AU"]), **dict(jurisdiction_terms or {})}
    adviser = terms["adviser"]
    family = str(r.get("family") or "unknown")
    ref = str(product["product_ref"])
    name = str(product.get("product_name"))
    provider = str(product.get("provider_name"))
    status = {str(dict(item).get("key")): str(dict(item).get("status")) for item in r.get("requirements") or ()}
    stamp = timestamp(prepared_at, field_name="prepared_at")
    paragraphs: list[Paragraph] = []
    paragraphs.append(_para("what_we_recommend", f"The record names {name} by {provider} ({str(product.get('taxonomy_class')).replace('_', ' ')}) as the recommended product; its suitability check reads {product.get('suitability')}.", f"fact:{ref}#product"))
    for index, line in enumerate(r.get("rationale") or ()):
        paragraphs.append(_para("why", f"Why: {line}", f"rationale:{index}"))
    needs = dict(r.get("needs") or {})
    if needs.get("kind"):
        paragraphs.append(_para("why", f"The record's needs assessment: {_needs_text(needs)}.", f"needs:{needs['kind']}"))
    if not any(item.section == "why" for item in paragraphs):
        paragraphs.append(_para("why", f"The record states no rationale line yet; the {adviser} writes the basis before approval.", "requirement:rationale"))
    paragraphs.extend(_cost_paragraphs("what_it_costs", product, family=family))
    paragraphs.extend(_changes_paragraphs("what_changes", r, status))
    approval = dict(r.get("approval") or {})
    if approval.get("approval_ref"):
        paragraphs.append(_para("what_you_must_do", f"The licensed {adviser} {approval.get('adviser_ref')} approved this recommendation under {approval.get('authority_kind')} at {approval.get('approved_at')}; the client reads the record and decides.", "approval"))
    else:
        paragraphs.append(_para("what_you_must_do", f"Nothing proceeds until a licensed {adviser} approves this exact recommendation; the record marks that approval as outstanding.", "requirement:approval"))
    gaps = list(r.get("fact_find_gaps") or ())
    if gaps:
        paragraphs.append(_para("what_you_must_do", "The fact find still needs: " + ", ".join(str(gap) for gap in gaps) + ".", "requirement:situation"))
    paragraphs.append(_para("what_you_must_do", f"Read the record, ask the {adviser} about anything that is unclear, and decide; the {adviser} implements nothing without the client's instruction.", "requirement:scope"))
    paragraphs.extend(_risk_paragraphs("risks_and_warnings", r, product))
    if not any(item.section == "risks_and_warnings" for item in paragraphs):
        paragraphs.append(_para("risks_and_warnings", "The record carries no disclosure line; the coverage warning requirement records whether the catalog is complete.", "requirement:coverage_warning"))
    paragraphs.extend(_paid_paragraphs("how_we_are_paid", r))
    if not any(item.section == "how_we_are_paid" for item in paragraphs):
        paragraphs.append(_para("how_we_are_paid", "The record states no remuneration disclosure; the remuneration requirement records that gap.", "requirement:remuneration"))
    kept = _pack(_valid_only(r, paragraphs, drafted_at=stamp))
    draft = prose_draft(r, kept, drafted_by_ref="template", drafted_at=stamp, drafter="template")
    validation = validate_prose(r, draft, require_sections=True)
    if not validation.valid:
        raise AdviceProseError("TEMPLATE_INVALID", "; ".join(f"{item.code}: {item.detail}" for item in validation.findings)[:1500], validation.findings)
    return client_explanation(r, draft, prepared_at=stamp)


# --------------------------------------------------------------------------- #
# Grounded answers
# --------------------------------------------------------------------------- #


def _find_product(view: Mapping[str, Any], product_ref: str | None) -> dict[str, Any] | None:
    products = _products(view)
    if product_ref is None:
        return products[0] if view.get("recommended") else None
    return next((item for item in products if str(item.get("product_ref")) == product_ref), None)


def _fact_paragraphs(product: Mapping[str, Any], *, match: Sequence[str]) -> list[Paragraph]:
    ref = str(product["product_ref"])
    name = str(product.get("product_name"))
    out: list[Paragraph] = []
    for item in product.get("facts") or ():
        fact = dict(item)
        if any(term in str(fact.get("item")).lower() for term in match):
            stated = f"{fact.get('value')} {fact.get('unit') or ''}".strip() if fact.get("value") is not None else "not stated as a figure"
            out.append(_para("answer", f"For {name} the provider's document states {fact.get('item')} of {stated}.", f"fact:{ref}#{fact.get('item')}"))
    return out


def _topic_paragraphs(view: Mapping[str, Any], topic: str, product: Mapping[str, Any] | None) -> list[Paragraph]:
    needs = dict(view.get("needs") or {})
    if topic == "cost":
        return _cost_paragraphs("answer", product, family=str(view.get("family") or "unknown")) if product else []
    if topic == "fees":
        return _fact_paragraphs(product, match=("fee",)) if product else []
    if topic == "rate":
        return _fact_paragraphs(product, match=("rate", "apr")) if product else []
    if topic == "switching_cost":
        out: list[Paragraph] = []
        for item in view.get("switching") or ():
            switch = dict(item)
            costs = ", ".join(f"{dict(cost).get('label')} {dict(cost).get('amount')}" if isinstance(cost, Mapping) else str(cost) for cost in switch.get("one_off_costs") or ())
            text = f"Switching to {switch.get('candidate_product_name')} costs {switch.get('switch_total')} over {switch.get('horizon_years')} years against {switch.get('stay_total')} for staying" + (f"; the one-off costs are {costs}" if costs else "") + f"; the record's verdict is {switch.get('verdict')}."
            out.append(_para("answer", text, f"switch:{switch.get('holding_ref')}"))
        return out
    if topic == "cover_amount":
        out = _fact_paragraphs(product, match=_COVER_ITEMS) if product else []
        if needs.get("kind") and needs.get("need") is not None:
            out.append(_para("answer", f"The record assesses the need at {needs['need']} {needs.get('unit') or ''}".rstrip() + f" for {needs['kind'].replace('_', ' ')} cover.", f"needs:{needs['kind']}"))
        return out
    if topic == "waiting_period":
        out = _fact_paragraphs(product, match=("waiting",)) if product else []
        if needs.get("kind") and needs.get("waiting_period_days") is not None:
            out.append(_para("answer", f"The record's needs assessment fits a waiting period of {needs['waiting_period_days']} days.", f"needs:{needs['kind']}"))
        return out
    if topic == "why_this_product":
        return [_para("answer", f"The record's basis: {line}", f"rationale:{index}") for index, line in enumerate(view.get("rationale") or ())]
    if topic == "why_not_alternative":
        out = []
        for alternative in _products(view)[1:] if view.get("recommended") else []:
            aref = str(alternative["product_ref"])
            text = f"{alternative.get('product_name')} by {alternative.get('provider_name')} was considered; its suitability check reads {alternative.get('suitability')}"
            if alternative.get("projected_cost") is not None:
                text += f" and the record projects a cost of {alternative['projected_cost']} over {alternative.get('projection_horizon_years')} years"
            out.append(_para("answer", text + ".", f"fact:{aref}#product"))
        return out
    if topic == "remuneration":
        return _paid_paragraphs("answer", view)
    if topic == "next_steps":
        return [_para("answer", f"Next step ({step.who}): {step.what}.", *step.refs) for step in next_step_prompts(view) if step.refs]
    if topic == "risks":
        return _risk_paragraphs("answer", view, product)
    return []


def answer_from_record(record: RecordOfAdviceEvidence | Mapping[str, Any], *, topic: str, product_ref: str | None = None, asked_at: str, answered_by_ref: str) -> GroundedAnswer:
    """A deterministic answer per topic from the record's own refs; a topic the record is silent on is refused, never guessed."""
    r = _view(record)
    stamp = timestamp(asked_at, field_name="asked_at")
    question = _TOPIC_QUESTIONS.get(topic, topic)
    product = _find_product(r, product_ref)
    paragraphs = _topic_paragraphs(r, topic, product) if topic in ANSWER_TOPICS and (product_ref is None or product is not None) else []
    kept = _pack(_valid_only(r, paragraphs, drafted_at=stamp))
    base = {"record_digest": r["record_digest"], "question": question, "topic": topic, "answered_by_ref": answered_by_ref, "answered_at": stamp}
    if not kept:
        return seal(GroundedAnswer, {**base, "refused": True, "refusal_reason": NOT_IN_RECORD}, "answer_digest")
    refs = {ref.ref: ref for ref in fact_refs(r)}
    return seal(GroundedAnswer, {**base, "paragraphs": [item.to_dict() for item in kept], "footnotes": [item.to_dict() for item in _footnotes(kept, refs)], "omitted": len(paragraphs) - len(kept)}, "answer_digest")


def grounded_answer(record: RecordOfAdviceEvidence | Mapping[str, Any], *, question: str, draft: ProseDraft | Mapping[str, Any], answered_by_ref: str, answered_at: str) -> GroundedAnswer:
    """A free-text draft through the validator: the paragraphs that pass become the answer; none passing becomes a refusal naming what the record does not say."""
    reject_identity_payload(question)
    r = _view(record)
    d = _draft(draft)
    validation = validate_prose(r, d, require_sections=False)
    fatal = [item for item in validation.findings if item.paragraph_index < 0]
    if fatal:
        raise AdviceProseError("PROSE_INVALID", "; ".join(f"{item.code}: {item.detail}" for item in fatal), fatal)
    bad = {item.paragraph_index for item in validation.findings}
    kept = [paragraph for index, paragraph in enumerate(d.paragraphs) if index not in bad]
    stamp = timestamp(answered_at, field_name="answered_at")
    base = {"record_digest": r["record_digest"], "question": question, "answered_by_ref": answered_by_ref, "answered_at": stamp, "draft_digest": d.draft_digest, "validation_digest": validation.validation_digest}
    if not kept:
        why = "; ".join(f"{item.code}: {item.detail}" for item in validation.findings)
        reason = (f"{NOT_IN_RECORD}. {why}" if why else f"{NOT_IN_RECORD}. The draft carried no paragraph")[:300]
        return seal(GroundedAnswer, {**base, "refused": True, "refusal_reason": reason, "omitted": len(d.paragraphs)}, "answer_digest")
    refs = {ref.ref: ref for ref in fact_refs(r)}
    return seal(GroundedAnswer, {**base, "paragraphs": [item.to_dict() for item in kept], "footnotes": [item.to_dict() for item in _footnotes(kept, refs)], "omitted": len(d.paragraphs) - len(kept)}, "answer_digest")


# --------------------------------------------------------------------------- #
# Next steps and objections: tables over the record
# --------------------------------------------------------------------------- #


def next_step_prompts(record: RecordOfAdviceEvidence | Mapping[str, Any], case_summary: Mapping[str, Any] | None = None) -> tuple[NextStep, ...]:
    """What happens next, from the case status and the record's own gaps; a table, not advice."""
    r = _view(record)
    summary = dict(case_summary or {})
    approval = dict(r.get("approval") or {})
    approval_ref = "approval" if approval.get("approval_ref") else "requirement:approval"
    status = str(summary.get("status") or ("adviser_approved" if approval.get("approval_ref") else ("recommended" if r.get("recommendation_digest") else "intake")))
    gaps = ", ".join(str(gap) for gap in r.get("fact_find_gaps") or ()) or "the required facts"
    review_due = summary.get("review_due_at")
    table: dict[str, NextStep] = {
        "intake": NextStep(who="client", what=f"complete the fact find: {gaps}"[:300], refs=("requirement:situation",)),
        "fact_find": NextStep(who="client", what=f"complete the fact find: {gaps}"[:300], refs=("requirement:situation",)),
        "shortlisted": NextStep(who="adviser", what="prepare the recommendation from the shortlist", refs=("requirement:alternatives",)),
        "recommended": NextStep(who="adviser", what="awaiting the adviser's approval", refs=("requirement:approval",)),
        "adviser_approved": NextStep(who="client", what="read and acknowledge the document", refs=(approval_ref,)),
        "presented": NextStep(who="client", what="sign the application items", refs=(approval_ref,)),
        "implemented": NextStep(who="adviser", what=f"review due {review_due or '(date not stated)'}", due=str(review_due) if review_due else None, refs=(approval_ref,)),
    }
    out: list[NextStep] = []
    if status in table:
        out.append(table[status])
    for item in r.get("requirements") or ():
        req = dict(item)
        if req.get("status") == "missing":
            out.append(NextStep(who="adviser", what=f"complete the record: {req.get('label')}"[:300], refs=(f"requirement:{req.get('key')}",)))
    return tuple(out)


def objection_responses(record: RecordOfAdviceEvidence | Mapping[str, Any]) -> tuple[ObjectionResponse, ...]:
    """Fixed objection kinds, each answered only with refs the record has; a kind with nothing to cite is omitted."""
    r = _view(record)
    product = r.get("recommended")
    if not product:
        return ()
    refs = {ref.ref: ref for ref in fact_refs(r)}
    ref = str(product["product_ref"])
    name = str(product.get("product_name"))
    needs = dict(r.get("needs") or {})
    candidates: dict[str, list[Paragraph]] = {}
    cost = [item for item in _cost_paragraphs("objection", product, family=str(r.get("family") or "unknown")) if item.cited != (f"fact:{ref}#product",)]
    if cost:
        candidates["cost"] = [_para("objection", "On cost, the record states the figures the provider's own documents give:", f"fact:{ref}#product"), *cost]
    switches = [dict(item) for item in r.get("switching") or ()]
    if switches:
        candidates["switching_hassle"] = [_para("objection", f"On the effort of switching, the record puts staying at {switch.get('stay_total')} against switching at {switch.get('switch_total')} over {switch.get('horizon_years')} years" + (f", with breakeven after {switch['breakeven_months']} months" if switch.get("breakeven_months") is not None else "") + f"; the verdict is {switch.get('verdict')}.", f"switch:{switch.get('holding_ref')}") for switch in switches]
        candidates["do_nothing"] = [_para("objection", f"On doing nothing, the record costs staying at {switch.get('stay_total')} over {switch.get('horizon_years')} years against {switch.get('switch_total')} for switching; the verdict is {switch.get('verdict')}.", f"switch:{switch.get('holding_ref')}") for switch in switches]
    rationale = list(r.get("rationale") or ())
    if rationale:
        candidates["why_this_provider"] = [_para("objection", f"The record names {name} by {product.get('provider_name')}; its basis: {rationale[0]}", f"fact:{ref}#product", "rationale:0")]
    alternatives = _products(r)[1:]
    cheaper = [alt for alt in alternatives if alt.get("projected_cost") is not None or alt.get("score") is not None]
    if cheaper:
        candidates["why_not_cheaper"] = [_para("objection", f"{alt.get('product_name')} by {alt.get('provider_name')} was on the shortlist with suitability {alt.get('suitability')}" + (f" and a projected cost of {alt['projected_cost']} over {alt.get('projection_horizon_years')} years" if alt.get("projected_cost") is not None else "") + f"; the record names {name} ahead of it.", f"fact:{alt['product_ref']}#product", f"fact:{ref}#product") for alt in cheaper]
    if needs.get("kind") and needs.get("need") is not None:
        candidates.setdefault("do_nothing", []).append(_para("objection", f"On doing nothing, the record assesses the need at {needs['need']} {needs.get('unit') or ''}".rstrip() + f" for {needs['kind'].replace('_', ' ')} cover.", f"needs:{needs['kind']}"))
        fits = [index for index, line in enumerate(rationale) if str(line).startswith("benefit fit")]
        candidates["too_much_cover"] = [_para("objection", f"On whether the cover is too much, the record assesses the need at {needs['need']} {needs.get('unit') or ''}".rstrip() + "." + (f" {rationale[fits[0]]}" if fits else ""), f"needs:{needs['kind']}", *(f"rationale:{fits[0]}",) if fits else ())]
    out: list[ObjectionResponse] = []
    for kind in ("cost", "switching_hassle", "why_this_provider", "why_not_cheaper", "do_nothing", "too_much_cover"):
        kept = _valid_only(r, candidates.get(kind, []), drafted_at="1970-01-01T00:00:00Z")
        if kept:
            out.append(ObjectionResponse(kind=kind, paragraphs=tuple(kept), footnotes=tuple(_footnotes(kept, refs))))
    return tuple(out)


PROSE_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_prose.v1",
    "schemas": {"draft": PROSE_SCHEMA, "validation": PROSE_VALIDATION_SCHEMA, "explanation": EXPLANATION_SCHEMA, "answer": ANSWER_SCHEMA},
    "sections": list(REQUIRED_SECTIONS),
    "topics": list(ANSWER_TOPICS),
    "ref_kinds": ["fact", "eligibility", "rationale", "disclosure", "requirement", "fact_find", "needs", "switch", "rule", "remuneration", "cashflow", "serviceability", "approval", "authority"],
    "codes": ["uncited", "unknown_ref", "number_not_in_cited_facts", "product_not_in_record", "forbidden_phrase", "section_missing", "record_mismatch", "recommendation_without_recommendation", "too_long", "prose_carries_identity"],
    "forbidden_phrases": list(FORBIDDEN_PHRASES),
    "limits": {"max_paragraphs": MAX_PARAGRAPHS, "max_paragraph_chars": MAX_PARAGRAPH_CHARS},
    "hard_rules": [
        "every paragraph cites a fact ref from the record; every number in a paragraph appears in a cited fact; every product named is in the record",
        "a model may only draft; the validator decides; nothing seals unless valid; the default path is the template and calls no model",
        "the explanation carries the record digest and the recommendation digest and a watermark until the licensed adviser approves",
        "prose names no person: identity tokens are refused and the drafter is an opaque ref",
        "a question the record does not answer is refused with the reason, never guessed",
    ],
    "not_claimed": "nothing here advises; the words describe the record and the licensed adviser's approval is the only act",
}

__all__ = [
    "ANSWER_SCHEMA",
    "ANSWER_TOPICS",
    "EXPLANATION_SCHEMA",
    "EXPLANATION_WATERMARK",
    "FORBIDDEN_PHRASES",
    "MAX_PARAGRAPHS",
    "MAX_PARAGRAPH_CHARS",
    "NOT_IN_RECORD",
    "PROSE_MANIFEST",
    "PROSE_SCHEMA",
    "PROSE_VALIDATION_SCHEMA",
    "REQUIRED_SECTIONS",
    "AdviceProseError",
    "ClientExplanation",
    "FactRef",
    "GroundedAnswer",
    "NextStep",
    "ObjectionResponse",
    "Paragraph",
    "ProseDraft",
    "ProseFinding",
    "ProseValidation",
    "answer_from_record",
    "client_explanation",
    "deterministic_explanation",
    "explanation_document",
    "explanation_watermark",
    "fact_refs",
    "grounded_answer",
    "next_step_prompts",
    "numbers_in",
    "objection_responses",
    "prose_draft",
    "validate_prose",
]
