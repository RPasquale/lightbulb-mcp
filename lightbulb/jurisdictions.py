"""The jurisdictions the SDK runs companies in, and what each one implies.

Five: Australia, Canada, the United States, the United Kingdom and New
Zealand.  Every module that needs a country's facts reads them here: its home
currency, the residency region the platform keeps its data in, its usual
financial year end, the revenue authority and the registrar, what its sales
tax is called and when registering for it becomes compulsory, and the law its
marketing consent follows.

The SDK's code for the United Kingdom is ``UK``, the name its tax and legal
rules use; the ISO code ``GB`` (Xero's and Stripe's) and the names people use
are accepted and read as ``UK``.  A company runs its books in its
jurisdiction's home currency.

The platform's incorporation guide covers Australia and Canada only: in the
United States, the United Kingdom and New Zealand the operator incorporates
directly with the registrar named here.  Nothing here reads, files or forms
anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class Jurisdiction:
    code: str
    iso_code: str
    name: str
    currency: str
    residency_region: str
    fiscal_year_end_month: int
    revenue_authority: str
    revenue_authority_name: str
    registrar: str
    # The registration a director makes first once the company is incorporated.
    business_number: str
    sales_tax: str
    # The name a ledger usually gives the sales tax liability account.
    sales_tax_account: str
    # The turnover a year above which registering for the sales tax is compulsory, in the home currency.
    # The United States has no national sales tax: each state sets its own economic-nexus threshold.
    sales_tax_threshold: str | None
    subdivision: str
    incorporation_guide: bool
    consent_law: str

    def to_dict(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in self.__dataclass_fields__}


JURISDICTIONS: Mapping[str, Jurisdiction] = {
    "AU": Jurisdiction("AU", "AU", "Australia", "AUD", "ap-southeast-2", 6, "ato", "Australian Taxation Office", "ASIC", "ABN", "GST", "GST", "75000", "state or territory", True, "Spam Act 2003"),
    "CA": Jurisdiction("CA", "CA", "Canada", "CAD", "ca-central-1", 12, "cra", "Canada Revenue Agency", "Corporations Canada", "CRA BN", "GST/HST", "GST/HST Payable", "30000", "province or territory", True, "CASL"),
    "US": Jurisdiction("US", "US", "United States", "USD", "us-east-1", 12, "irs", "Internal Revenue Service", "the state's Secretary of State", "EIN", "sales tax", "Sales Tax Payable", None, "state", False, "CAN-SPAM Act and TCPA"),
    "UK": Jurisdiction("UK", "GB", "United Kingdom", "GBP", "eu-west-2", 3, "hmrc", "HM Revenue & Customs", "Companies House", "Corporation Tax (UTR)", "VAT", "VAT", "90000", "nation", False, "PECR and UK GDPR"),
    "NZ": Jurisdiction("NZ", "NZ", "New Zealand", "NZD", "ap-southeast-6", 3, "ird", "Inland Revenue", "New Zealand Companies Office", "IRD number", "GST", "GST", "60000", "region", False, "Unsolicited Electronic Messages Act 2007"),
}
JURISDICTION_CODES: tuple[str, ...] = tuple(JURISDICTIONS)
HOME_CURRENCIES: Mapping[str, str] = {code: item.currency for code, item in JURISDICTIONS.items()}

_ALIASES: dict[str, str] = {
    **{code: code for code in JURISDICTIONS},
    **{item.name.upper(): code for code, item in JURISDICTIONS.items()},
    "AUS": "AU", "CAN": "CA",
    "USA": "US", "UNITED STATES OF AMERICA": "US", "THE UNITED STATES": "US",
    "GB": "UK", "GBR": "UK", "GREAT BRITAIN": "UK", "BRITAIN": "UK", "THE UNITED KINGDOM": "UK", "ENGLAND": "UK", "SCOTLAND": "UK", "WALES": "UK", "NORTHERN IRELAND": "UK", "ENGLAND AND WALES": "UK",
    "NZL": "NZ", "AOTEAROA": "NZ", "AOTEAROA NEW ZEALAND": "NZ",
}
_SPACES = re.compile(r"\s+")


def describe_jurisdictions() -> str:
    """The five, named for a message: ``Australia (AU), Canada (CA), ... and New Zealand (NZ)``."""

    names = [f"{'the ' if code in ('US', 'UK') else ''}{item.name} ({code})" for code, item in JURISDICTIONS.items()]
    return ", ".join(names[:-1]) + f" and {names[-1]}"


class UnsupportedJurisdictionError(ValueError):
    """Raised when a company is asked to run somewhere the SDK does not."""

    code = "JURISDICTION_UNSUPPORTED"

    def __init__(self, value: str, message: str | None = None) -> None:
        self.value = value
        super().__init__(message or f"JURISDICTION_UNSUPPORTED: the SDK runs companies in {describe_jurisdictions()}; got {value!r}")


def _folded(value: Any) -> str:
    return _SPACES.sub(" ", str(value or "").replace(".", "").strip().upper())


def normalize_jurisdiction(value: Any) -> str:
    """The SDK's code (``AU``, ``CA``, ``US``, ``UK`` or ``NZ``) for any accepted spelling; raise otherwise."""

    code = _ALIASES.get(_folded(value))
    if code is None:
        raise UnsupportedJurisdictionError(str(value or "").strip())
    return code


def jurisdiction_facts(value: Any) -> Jurisdiction:
    return JURISDICTIONS[normalize_jurisdiction(value)]


def home_currency(value: Any) -> str:
    return JURISDICTIONS[normalize_jurisdiction(value)].currency


def jurisdiction_for_currency(currency: Any) -> str | None:
    """The jurisdiction whose home currency this is, when it is one of the five."""

    text = str(currency or "").strip().upper()
    return next((code for code, item in JURISDICTIONS.items() if item.currency == text), None)


def country_key(value: Any) -> str:
    """A comparable key for a free-text country: the SDK's code when the text names one of the five, else the folded text.

    ``GB``, ``United Kingdom`` and ``UK`` compare equal; a region the SDK does not run in still compares with itself.
    """

    folded = _folded(value)
    return _ALIASES.get(folded, folded.casefold())


__all__ = [
    "HOME_CURRENCIES",
    "JURISDICTIONS",
    "JURISDICTION_CODES",
    "Jurisdiction",
    "UnsupportedJurisdictionError",
    "country_key",
    "describe_jurisdictions",
    "home_currency",
    "jurisdiction_facts",
    "jurisdiction_for_currency",
    "normalize_jurisdiction",
]
