"""Company formation through the user's own Lightbulb account.

The SDK never mints a tenant, a company, or a user.  A company is created
through the authenticated user's account (``POST /api/companies/guided``):
Spring authorizes the caller as a tenant admin of the tenant carried by the
session credential, provisions the company, and returns it.  The SDK's job is
to type the request, restrict formation to the jurisdictions the platform
supports today (Australia and Canada), and parse the guided response.

Nothing here talks to the network; :meth:`lightbulb.client.LightbulbClient.create_company`
and its async twin do, under the user's credential.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from pydantic import Field, field_validator

from lightbulb.company_engine_core import BoundedText, ShortText, StrictModel

SUPPORTED_FORMATION_COUNTRIES: Mapping[str, str] = {"AU": "Australia", "CA": "Canada"}
EXPECTED_RESIDENCY_REGION: Mapping[str, str] = {"AU": "ap-southeast-2", "CA": "ca-central-1"}
GUIDED_COMPANY_PATH = "/api/companies/guided"
NEXT_STEP_OPEN_WORKSPACE = "open_company_workspace"
_COUNTRY_ALIASES: Mapping[str, str] = {"AU": "AU", "AUS": "AU", "AUSTRALIA": "AU", "CA": "CA", "CAN": "CA", "CANADA": "CA"}
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class UnsupportedFormationCountryError(ValueError):
    """Raised when formation is requested outside Australia or Canada."""

    def __init__(self, value: str) -> None:
        self.value = value
        super().__init__(f"UNSUPPORTED_FORMATION_COUNTRY: company formation through the SDK is available in Australia (AU) and Canada (CA) only; got {value!r}")


def normalize_formation_country(value: Any) -> str:
    """Return ``"AU"`` or ``"CA"`` for any accepted spelling; raise otherwise."""

    text = str(value or "").strip()
    code = _COUNTRY_ALIASES.get(text.upper())
    if code is None:
        raise UnsupportedFormationCountryError(text)
    return code


class CompanyFormationRequest(StrictModel):
    """What the user wants to form.  Tenant identity is never a field: it comes from the credential."""

    name: str = Field(min_length=1, max_length=160)
    country: str = Field(min_length=2, max_length=80)
    industry: ShortText | None = Field(default=None, max_length=120)
    purpose: BoundedText | None = Field(default=None, max_length=2000)
    contact_email: str | None = Field(default=None, max_length=254)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("company name is required")
        return stripped

    @field_validator("country")
    @classmethod
    def _country(cls, value: str) -> str:
        return normalize_formation_country(value)

    @field_validator("contact_email")
    @classmethod
    def _email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not _EMAIL.match(stripped):
            raise ValueError("contact_email must be a valid email address")
        return stripped

    @property
    def country_name(self) -> str:
        return SUPPORTED_FORMATION_COUNTRIES[self.country]

    @property
    def expected_region(self) -> str:
        return EXPECTED_RESIDENCY_REGION[self.country]

    def to_guided_payload(self, tenant_id: str) -> dict[str, Any]:
        """Body for ``POST /api/companies/guided``; ``tenant_id`` is the credential's tenant, never a caller value."""

        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("TENANT_NOT_RESOLVED: the authenticated credential carries no tenant id")
        payload: dict[str, Any] = {"tenantId": tenant_id, "name": self.name, "country": self.country}
        if self.industry is not None:
            payload["industry"] = self.industry
        if self.purpose is not None:
            payload["purpose"] = self.purpose
        if self.contact_email is not None:
            payload["contactEmail"] = self.contact_email
        return payload


@dataclass(frozen=True)
class CompanyFormationResult:
    """The guided response, typed.  ``company`` is Spring's CompanyResponse as returned."""

    company: Mapping[str, Any]
    company_id: str | None
    name: str
    country: str
    region: str | None
    region_matches_country: bool
    provisioning: str | None
    next_step: str | None
    message: str | None

    @property
    def workspace_ready(self) -> bool:
        return self.next_step == NEXT_STEP_OPEN_WORKSPACE

    def to_dict(self) -> dict[str, Any]:
        return {"company": dict(self.company), "company_id": self.company_id, "name": self.name, "country": self.country, "region": self.region, "region_matches_country": self.region_matches_country, "provisioning": self.provisioning, "next_step": self.next_step, "message": self.message}


def parse_guided_response(data: Any, request: CompanyFormationRequest) -> CompanyFormationResult:
    if not isinstance(data, Mapping):
        raise ValueError("FORMATION_RESPONSE_INVALID: guided company response must be an object")
    company = data.get("company")
    if not isinstance(company, Mapping):
        raise ValueError("FORMATION_RESPONSE_INVALID: guided company response carries no company")
    region = company.get("region")
    region_text = str(region) if region is not None else None
    return CompanyFormationResult(
        company=dict(company),
        company_id=str(company["id"]) if company.get("id") is not None else None,
        name=str(company.get("name") or request.name),
        country=request.country,
        region=region_text,
        region_matches_country=region_text == request.expected_region,
        provisioning=str(data["provisioning"]) if data.get("provisioning") is not None else None,
        next_step=str(data["nextStep"]) if data.get("nextStep") is not None else None,
        message=str(data["message"]) if data.get("message") is not None else None,
    )


__all__ = [
    "EXPECTED_RESIDENCY_REGION",
    "GUIDED_COMPANY_PATH",
    "NEXT_STEP_OPEN_WORKSPACE",
    "SUPPORTED_FORMATION_COUNTRIES",
    "CompanyFormationRequest",
    "CompanyFormationResult",
    "UnsupportedFormationCountryError",
    "normalize_formation_country",
    "parse_guided_response",
]
