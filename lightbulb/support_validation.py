"""Validation diagnostics for untrusted support intake never retain payloads."""
from __future__ import annotations

from functools import wraps
from typing import Any

from pydantic import ValidationError, model_validator

from lightbulb.company_engine_core import StrictModel


_SAFE_CODES = frozenset((
    "SUPPORT_STEPS_INVALID", "SUPPORT_ATTACHMENT_REF_REQUIRED",
    "SUPPORT_REPORT_NOT_REDACTED", "SUPPORT_CLASSIFICATION_MISMATCH",
    "SUPPORT_SECRET_FLAG_MISMATCH", "SUPPORT_SCREENING_MISMATCH",
    "SUPPORT_REPORT_DIGEST_MISMATCH", "SUPPORT_POLICY_MISMATCH",
    "SUPPORT_BRIEF_DIGEST_MISMATCH", "SUPPORT_BRIEF_REQUIRED",
    "SUPPORT_SCOPE_MISMATCH", "SUPPORT_REPORT_FROM_FUTURE",
    "SUPPORT_SIGNAL_BINDING_MISMATCH",
))


def support_validation_error(error: Exception) -> ValidationError:
    """Build diagnostics that cannot retain untrusted input or exception context."""
    reasons = [error]
    if isinstance(error, ValidationError):
        reasons = [item.get("ctx", {}).get("error") for item in error.errors(include_input=False)]
    code = next((str(reason) for reason in reasons if str(reason) in _SAFE_CODES), "SUPPORT_INPUT_INVALID")
    return ValidationError.from_exception_data("Support intake", [
        {"type": "value_error", "loc": (), "input": None, "ctx": {"error": ValueError(code)}}
    ])


def safe_support_validation(function):
    """Keep only known policy codes, including in errors()/json() diagnostics.

    Pydantic's hide_input_in_errors only affects str(error); its structured
    diagnostics still retain inputs and exception context. Rebuild the error
    with no input, field locations, or untrusted exception objects instead.
    """
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (ValueError, TypeError) as error:
            raise support_validation_error(error) from None
    return checked


class SafeSupportModel(StrictModel):
    """Sanitize every supported public model validation entry point."""

    @model_validator(mode="wrap")
    @classmethod
    @safe_support_validation
    def _safe_fields(cls, value: Any, handler: Any) -> Any:
        return handler(value)

    @classmethod
    @safe_support_validation
    def model_validate(cls, obj: Any, **kwargs: Any):
        return super().model_validate(obj, **kwargs)

    @classmethod
    @safe_support_validation
    def model_validate_json(cls, json_data: Any, **kwargs: Any):
        return super().model_validate_json(json_data, **kwargs)

    @classmethod
    @safe_support_validation
    def model_validate_strings(cls, obj: Any, **kwargs: Any):
        return super().model_validate_strings(obj, **kwargs)
