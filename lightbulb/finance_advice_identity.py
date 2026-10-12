"""Reject recognisable personal identifiers in advice free text without retaining a match.

This is a deterministic boundary guard, not a claim to recognise every person's name.
Identity belongs in the operator's identity store. Advice carries opaque references and
commitments. Bare amounts, dates, product names and public evidence URLs remain decision facts.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, model_validator

from lightbulb.company_engine_core import StrictModel

IDENTITY_REFUSAL = "ADVICE_CARRIES_IDENTITY: advice carries decision facts and identity commitments only"
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
_PATTERNS = (
    ("an email address", r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    ("a personal identifier", r"\b(?:account|policy|passport|licen[cs]e|registration|driver'?s?\s+licen[cs]e|tax\s+file|social\s+insurance|social\s+security)\s*(?:number|no\.?|#)\s*(?:is\s*)?[:=]?\s*(?=[A-Z0-9 -]{0,40}\d)[A-Z0-9][A-Z0-9 -]{3,40}\b"),
    ("a tax identifier", r"\b(?:TFN|SIN|SSN)\s*(?:number|no\.?|#)?\s*(?:is\s*)?[:=]?\s*\d[\d -]{6,16}\d\b"),
    ("a phone number", r"\b(?:phone|mobile|telephone|tel|call\s+me)\s*(?:number|no\.?|#)?\s*(?:is|on|at)?\s*[:=]?\s*\+?\d[\d ()-]{6,20}\d\b"),
    ("a phone number", r"(?<![\w\d])\+\d{1,3}[ ()-]*\d(?:[ ()-]*\d){7,11}(?!\d)"),
    ("a phone number", r"\b0[2-478](?:[ ()-]*\d){8}\b"),
    ("a phone number", r"(?<!\d)(?:\([2-9]\d{2}\)[ -]*|[2-9]\d{2}[ -])[2-9]\d{2}[ -]\d{4}\b"),
    ("a date of birth", r"\b(?:date\s+of\s+birth|DOB|born\s+on)\s*(?:is\s*)?[:=]?\s*(?:\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4}|\d{1,2}\s+[A-Z]{3,9}\s+\d{4}|[A-Z]{3,9}\s+\d{1,2},?\s+\d{4})\b"),
    ("a personal address", r"\b(?:(?:my|home|residential|postal|street)\s+address|I\s+live\s+at|address)\s*(?:is\s*)?[:=]?\s*\d{1,6}[A-Z]?(?:[/ -]\d{1,6})?\s+[A-Z][A-Z .'-]{1,70}\b"),
    ("a personal name", r"\b(?:my\s+name\s+is|client(?:'s)?\s+(?:full\s+)?name\s*[:=]|full\s+name\s*[:=])\s*[A-Z][A-Z'-]+(?:\s+[A-Z][A-Z'-]+){1,4}\b"),
)
_COMPILED = tuple((label, re.compile(pattern, re.IGNORECASE)) for label, pattern in _PATTERNS)


def identity_markers(text: str) -> tuple[str, ...]:
    """Return categories only; a match, field path or supplied value is never returned."""
    normalized = _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    return tuple(dict.fromkeys(label for label, pattern in _COMPILED if pattern.search(normalized)))


def reject_identity_payload(value: Any, *, code: str = "ADVICE_CARRIES_IDENTITY") -> None:
    """Refuse recognisable identity at every mapping/list depth without rewriting the payload."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, str):
        markers = identity_markers(value)
        if markers:
            raise ValueError(f"{code}: advice carries decision facts and identity commitments only; carries {', '.join(markers)}")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            reject_identity_payload(str(key), code=code)
            reject_identity_payload(item, code=code)
    elif isinstance(value, (list, tuple)):
        for item in value:
            reject_identity_payload(item, code=code)


class AdviceIdentityModel(StrictModel):
    """Private advice artifacts retain StrictModel's guards and refuse free-text identity."""

    model_config = ConfigDict(hide_input_in_errors=True)
    identity_refusal_code: ClassVar[str] = "ADVICE_CARRIES_IDENTITY"

    @model_validator(mode="before")
    @classmethod
    def _no_free_text_identity(cls, value: Any) -> Any:
        reject_identity_payload(value, code=cls.identity_refusal_code)
        return value


__all__ = ["AdviceIdentityModel", "IDENTITY_REFUSAL", "identity_markers", "reject_identity_payload"]
