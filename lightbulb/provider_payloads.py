"""Provider payload reading: the date forms and page envelopes the platform's reads really arrive in.

The chains and the adoption planner were written against tidy pages: ISO
dates ending in ``Z``, plain rows.  Real reads are not tidy.  Xero sends
``/Date(1788220800000+0000)/`` beside a zone-less ``DateString``, Stripe
sends Unix seconds, QuickBooks sends a bare date on a document and an
offset timestamp in its metadata, and a governed Xero month page is not the
provider's body at all but Spring's canonical
``lightbulb.xero_close_source_page.v1`` projection.  A parser that accepts
only the tidy form does not fail loudly on the real one; it rejects every
row, or finds no rows and reports an empty page.

This module is the one place those forms are read.  Every function is pure
and refuses what it cannot read with the field's name, so a caller can turn
the refusal into a row-level rejection.  Nothing here guesses a time zone:
a zone-less provider time is UTC because both Xero and the platform's own
projections state it so, and an offset is converted, never dropped.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date, datetime, timedelta, timezone
from typing import Any

XERO_CLOSE_SOURCE_PAGE_SCHEMA = "lightbulb.xero_close_source_page.v1"

_XERO_MS_DATE = re.compile(r"^/Date\((-?[0-9]{1,17})(?:[+-][0-9]{4})?\)/$")
_UNIX_SECONDS = re.compile(r"^[0-9]{9,11}$")
_DATE_ONLY = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
# Seconds are bounded to years 1990..2200: outside it the value is milliseconds or not a time at all.
_MIN_UNIX_SECONDS, _MAX_UNIX_SECONDS = 631_152_000, 7_258_118_400


class ProviderPayloadError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _canonical(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def provider_timestamp(value: Any, *, field_name: str) -> str:
    """One provider time as the canonical UTC ``...Z`` timestamp the chains accept.

    Accepted: an ISO timestamp ending in ``Z`` or carrying an offset; a
    zone-less ISO timestamp (Xero ``DateString``, read as UTC); a bare
    ``YYYY-MM-DD`` (midnight UTC); Xero's ``/Date(ms+0000)/``; and Unix
    seconds as an integer or a digit string (Stripe).  Anything else is
    refused with the field's name.
    """

    if isinstance(value, bool) or value is None or value == "":
        raise ProviderPayloadError("PROVIDER_TIME_UNREADABLE", f"{field_name} carries no time")
    if isinstance(value, int):
        if not _MIN_UNIX_SECONDS <= value <= _MAX_UNIX_SECONDS:
            raise ProviderPayloadError("PROVIDER_TIME_UNREADABLE", f"{field_name} is not Unix seconds between 1990 and 2200")
        return _canonical(_EPOCH + timedelta(seconds=value))
    if not isinstance(value, str):
        raise ProviderPayloadError("PROVIDER_TIME_UNREADABLE", f"{field_name} must be text or Unix seconds")
    text = value.strip()
    matched = _XERO_MS_DATE.fullmatch(text)
    if matched:
        return _canonical(_EPOCH + timedelta(milliseconds=int(matched.group(1))))
    if _UNIX_SECONDS.fullmatch(text):
        return provider_timestamp(int(text), field_name=field_name)
    try:
        if _DATE_ONLY.fullmatch(text):
            return _canonical(datetime.combine(date.fromisoformat(text), datetime.min.time(), tzinfo=timezone.utc))
        moment = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError as exc:
        raise ProviderPayloadError("PROVIDER_TIME_UNREADABLE", f"{field_name} is not a provider date or time: {text[:40]!r}") from exc
    return _canonical(moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc))


def provider_date(value: Any, *, field_name: str) -> str:
    """The UTC calendar date of one provider time, as ``YYYY-MM-DD``."""

    return provider_timestamp(value, field_name=field_name)[:10]


def first_present(row: Mapping[str, Any], *keys: str) -> Any:
    """The first key whose value is stated; an empty string or ``None`` is not a statement."""

    for key in keys:
        found = row.get(key)
        if found not in (None, ""):
            return found
    return None


def governed_schema(payload: Any) -> str | None:
    """The canonical schema a governed projection declares, or ``None`` for a provider body."""

    if isinstance(payload, Mapping):
        schema = payload.get("schema")
        if isinstance(schema, str) and schema.startswith("lightbulb."):
            return schema
    return None


__all__ = ["XERO_CLOSE_SOURCE_PAGE_SCHEMA", "ProviderPayloadError", "first_present", "governed_schema", "provider_date", "provider_timestamp"]
