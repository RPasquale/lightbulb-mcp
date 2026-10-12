"""The record of advice as a document: the evidence rendered to Markdown and HTML with its status written on it.

The record module builds the evidence; this module turns one record into something a person
reads, files and hands to the client once the licensed adviser has approved. Every document carries
the record's digest, the jurisdiction and vertical, and a watermark that says plainly what it is:
draft evidence that is not advice while the approval is missing, or the approved record with the
adviser, the authority kind and the time of approval. The HTML is built here from the Markdown with
every value escaped, so nothing a source document said can become markup.

PDF rendering belongs to the worker, which has the fonts and the renderer; the SDK produces the
text and the structure and the digest the PDF is checked against.
"""

from __future__ import annotations

from collections.abc import Mapping
from html import escape
from typing import Any, Literal

from pydantic import Field, ValidationInfo, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, StrictModel, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_record import RecordOfAdviceEvidence, record_markdown

DOCUMENT_SCHEMA = "lightbulb.finance_advice_document.v1"
DocumentKind = Literal["record_of_advice_evidence", "client_explanation", "grounded_answer"]

_STYLE = "article.advice{font-family:Georgia,serif;max-width:46rem;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#1c1c1c}article.advice .watermark{border:2px solid #8a6d00;background:#fff7d6;padding:.6rem 1rem;font-family:sans-serif;font-size:.95rem;margin-bottom:1.5rem}article.advice .watermark.approved{border-color:#245a2f;background:#e8f5ea}article.advice h1{font-size:1.6rem}article.advice h2{font-size:1.2rem;margin-top:1.6rem;border-bottom:1px solid #ccc}article.advice ul{padding-left:1.4rem}article.advice li.done::before{content:'\\2713 ';color:#245a2f}article.advice li.open::before{content:'\\25a1 ';color:#8a6d00}article.advice footer{margin-top:2rem;font-family:sans-serif;font-size:.8rem;color:#555}"


class AdviceDocument(StrictModel):
    """One rendering of one record, sealed with the record's digest and its own."""

    schema_id: Literal["lightbulb.finance_advice_document.v1"] = DOCUMENT_SCHEMA
    kind: DocumentKind = "record_of_advice_evidence"
    title: str = Field(min_length=1)
    jurisdiction: str
    vertical_id: str
    mode: str
    record_digest: Sha256Digest
    complete: bool
    watermark: str
    markdown: str
    html: str
    retain_until: str | None = None
    prepared_at: str
    document_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> AdviceDocument:
        if not skip_digests(info) and self.document_digest != sealed_digest(AdviceDocument, self, "document_digest"):
            raise ValueError("document_digest does not match the document")
        return self


def watermark_for(record: RecordOfAdviceEvidence | Mapping[str, Any]) -> str:
    """What the document says about itself: draft evidence, the approved record, or an explanation of a record."""
    if isinstance(record, Mapping) and "explanation_digest" in record:
        return f"Explanation of the record {record.get('record_digest')}; not advice until the licensed adviser approves the recommendation it explains"
    if isinstance(record, Mapping):
        record = RecordOfAdviceEvidence.model_validate(dict(record))
    if record.complete and record.approval:
        approval = dict(record.approval)
        return f"Approved record. Adviser {approval.get('adviser_ref')} approved this recommendation under {approval.get('authority_kind')} at {approval.get('approved_at')}; record digest {record.record_digest}."
    missing = record.missing()
    what = "; ".join(missing) if missing else "the record is not complete"
    return f"Draft evidence, not advice. No licensed adviser has approved this record. Outstanding: {what}. Record digest {record.record_digest}."


def _inline(text: str) -> str:
    return escape(text, quote=True)


def html_from_markdown(markdown: str, *, title: str, watermark: str, approved: bool = False, footer: str | None = None) -> str:
    """A small, exact renderer for the Markdown the record writes: headings, lists, checkboxes, paragraphs. Everything is escaped."""
    out: list[str] = [f"<article class=\"advice\"><style>{_STYLE}</style>", f"<div class=\"watermark{' approved' if approved else ''}\">{_inline(watermark)}</div>"]
    depth = 0
    paragraph: list[str] = []

    def flush() -> None:
        nonlocal paragraph
        if paragraph:
            out.append(f"<p>{_inline(' '.join(paragraph))}</p>")
            paragraph = []

    def close_lists(to_depth: int) -> None:
        nonlocal depth
        while depth > to_depth:
            out.append("</ul>")
            depth -= 1

    for raw in markdown.splitlines():
        line = raw.rstrip()
        if not line.strip():
            flush()
            close_lists(0)
            continue
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if stripped.startswith("#"):
            flush()
            close_lists(0)
            level = min(len(stripped) - len(stripped.lstrip("#")), 4)
            out.append(f"<h{level}>{_inline(stripped[level:].strip())}</h{level}>")
            continue
        if stripped.startswith("- ") or stripped == "-":
            flush()
            wanted = indent // 2 + 1
            while depth < wanted:
                out.append("<ul>")
                depth += 1
            close_lists(wanted)
            body = stripped[2:]
            cls = ""
            if body.startswith("[x] ") or body.startswith("[X] "):
                cls, body = " class=\"done\"", body[4:]
            elif body.startswith("[ ] "):
                cls, body = " class=\"open\"", body[4:]
            out.append(f"<li{cls}>{_inline(body)}</li>")
            continue
        if stripped == "---":
            flush()
            close_lists(0)
            out.append("<hr>")
            continue
        paragraph.append(stripped)
    flush()
    close_lists(0)
    if footer:
        out.append(f"<footer>{_inline(footer)}</footer>")
    out.append("</article>")
    return "\n".join(out)


def advice_document(record: RecordOfAdviceEvidence | Mapping[str, Any], *, prepared_at: str, title: str | None = None, retain_until: str | None = None) -> AdviceDocument:
    """Render one record to a sealed document with its watermark."""
    r = record if isinstance(record, RecordOfAdviceEvidence) else RecordOfAdviceEvidence.model_validate(dict(record))
    stamp = timestamp(prepared_at, field_name="prepared_at")
    name = title or f"Record of advice evidence: {r.vertical_name} ({r.jurisdiction})"
    mark = watermark_for(r)
    markdown = record_markdown(r)
    footer = f"Prepared {stamp} from record {r.record_digest}. The evidence was assembled by the platform's engine; the recommendation is the licensed adviser's." + (f" Retain until {retain_until}." if retain_until else "")
    html = html_from_markdown(markdown, title=name, watermark=mark, approved=r.complete, footer=footer)
    return seal(AdviceDocument, {"title": name, "jurisdiction": r.jurisdiction, "vertical_id": r.vertical_id, "mode": r.mode, "record_digest": r.record_digest, "complete": r.complete, "watermark": mark, "markdown": markdown, "html": html, "retain_until": retain_until, "prepared_at": stamp}, "document_digest")


DOCUMENT_MANIFEST: dict[str, Any] = {
    "schema": DOCUMENT_SCHEMA,
    "kinds": ["record_of_advice_evidence", "client_explanation", "grounded_answer"],
    "explanation_watermark": "an explanation of a record is not advice until the licensed adviser approves the recommendation it explains; its footer cites the record digest and the explanation digest",
    "renderings": ["markdown", "html"],
    "pdf": "rendered by the worker from the sealed markdown; the PDF cites the document digest",
    "watermark": "draft evidence, not advice, until the record is complete; the approved record names the adviser, the authority kind and the time",
    "escaping": "every value is HTML-escaped; source text never becomes markup",
}

__all__ = ["DOCUMENT_MANIFEST", "DOCUMENT_SCHEMA", "AdviceDocument", "advice_document", "html_from_markdown", "watermark_for"]
