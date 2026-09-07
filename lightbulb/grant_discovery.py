"""Grant discovery: the AI accountant's non-dilutive capital finder.

A fast-growing startup's cheapest capital is the money it does not have to give
equity for. This module is the part of the SDK's accountant that hunts it:
given a company profile it matches against a curated registry of real, flagship
non-dilutive programs (Canada and Australia to start) and composes a live search
plan for the openings a static registry cannot know. It pairs naturally with the
runway engine — when :func:`lightbulb.assess_runway` says ``raise_capital``,
non-dilutive grants are the first place a disciplined accountant looks.

Honesty rules, enforced hard because this is where fabrication would do real
damage:

- **Real programs only, each sourced.** Every registry entry names its
  administering body and an official URL, and carries a ``last_verified`` stamp.
  Nothing is invented.
- **Never a promise.** Program terms — rates, caps, deadlines, thresholds —
  change constantly. The engine states eligibility *signals* and headline
  benefits as **indicative**, always attaches the official source, and every
  result carries ``verification_required`` and a standing disclaimer. It never
  says "you will receive $X"; it says "you may be eligible; verify at <source>".
- **Match, don't gatekeep silently.** Programs whose hard signals a profile does
  not meet are returned in ``not_matched`` *with the reason*, never dropped, so
  the operator sees what was considered and why.
- **Live search reaches past the registry, honestly.** ``search_grants`` runs
  the platform's own web-research capability to find new, regional, and
  round-based openings the registry cannot know, and returns the findings
  verbatim as leads to confirm at source — never as verified programs, never
  fabricated. (``compose_grant_search_plan`` still emits the query set + portals
  for a human or a different search surface to run.)

The registry is deliberately small and flagship-only; regional and niche
programs are surfaced through the search plan, not asserted here. This module
holds no keyring, does no I/O, and depends only on stdlib + pydantic.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

GRANT_MATCH_RESULT_SCHEMA = "lightbulb.grant_match_result.v1"
GRANT_SEARCH_REQUEST_SCHEMA = "lightbulb.grant_search_request.v1"
GRANT_SEARCH_FINDINGS_SCHEMA = "lightbulb.grant_search_findings.v1"

# The platform's web-research capability — a DOMAIN-AGENT action (not a connector
# tool). SDK primitives reach connectors through the connector executor, which
# this action does not go through, so a primitive cannot invoke it directly.
# Instead `search_grants` composes a machine-runnable request targeting this
# tool, the agent runtime (which has domain-agent access) runs it, and
# `normalize_grant_findings` structures what comes back. The system does the
# searching; the SDK owns the query and the honesty layer.
_SEARCH_TOOL = "deep_research.research_query"
GRANT_SEARCH_PLAN_SCHEMA = "lightbulb.grant_search_plan.v1"

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"

Jurisdiction = Literal["CA", "AU"]
FundingType = Literal[
    "tax_credit", "grant", "contribution", "reimbursement", "loan", "voucher"
]
GrantCategory = Literal[
    "rnd", "export", "commercialisation", "hiring", "digital_adoption", "general"
]

# The standing disclaimer attached to every result. This is a factual statement
# about how grant programs work, not legalese to be skipped.
_DISCLAIMER = (
    "Indicative matches only. Program eligibility, rates, caps, and deadlines "
    "change frequently and are set by the administering body — confirm current "
    "terms at each official source before relying on them. This is not tax, "
    "legal, or financial advice."
)


class GrantDiscoveryError(ValueError):
    """A profile or program registry entry violates the contract."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("content must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("content contains an unsupported control character")
    return value


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
LongText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=600),
    AfterValidator(_bounded_text),
]
def _findings_text(value: str) -> str:
    # Live research output carries newlines/tabs; forbid only other control chars.
    if any(ord(character) < 32 and character not in "\n\t\r" for character in value):
        raise ValueError("findings contain an unsupported control character")
    return value


FindingsText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=8000),
    AfterValidator(_findings_text),
]
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
HttpsUrl = Annotated[
    str, StringConstraints(pattern=r"^https://[^\s]{5,300}$")
]
SectorTag = Annotated[
    str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,39}$")
]


def _decimal(value: Any) -> Decimal:
    if not isinstance(value, (str, Decimal, int, float)) or isinstance(value, bool):
        raise ValueError("decimal values must be supplied as strings or JSON numbers")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite decimal") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("value must be a finite, non-negative decimal")
    return parsed


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class EligibilitySignals(_StrictModel):
    """Structural eligibility signals — not the program's full fine print.

    Only signals stable enough to match on live here; dollar thresholds that
    drift (turnover caps, minimum spend) are described in ``indicative_notes``
    and must be checked at the source, never treated as hard gates.
    """

    requires_incorporation: bool = False
    requires_rnd: bool = False
    requires_export_intent: bool = False
    for_smes: bool = False
    sectors: tuple[SectorTag, ...] = Field(default_factory=tuple)
    indicative_notes: LongText

    @field_validator("sectors", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value


class GrantProgram(_StrictModel):
    """One real, sourced non-dilutive funding program."""

    program_ref: PortableRef
    name: ShortText
    jurisdiction: Jurisdiction
    region: ShortText = "federal"
    administering_body: ShortText
    funding_type: FundingType
    non_dilutive: Literal[True] = True
    category: GrantCategory
    official_source_url: HttpsUrl
    last_verified: str
    headline_benefit: LongText
    eligibility: EligibilitySignals

    @field_validator("last_verified")
    @classmethod
    def _valid_month(cls, value: str) -> str:
        clean = value.strip()
        try:
            datetime.strptime(clean, "%Y-%m")
        except ValueError as exc:
            raise ValueError("last_verified must be a YYYY-MM month") from exc
        return clean


# ---------------------------------------------------------------------------
# Curated registry — flagship, real, sourced. Small on purpose.
#
# last_verified reflects the author's knowledge as of that month; the engine's
# whole contract is that the operator re-verifies at official_source_url. Do NOT
# add a program without a real administering body and official URL, and do NOT
# assert a specific rate/cap/deadline as fact anywhere but headline_benefit
# (labeled indicative).
# ---------------------------------------------------------------------------

_REGISTRY: tuple[GrantProgram, ...] = (
    GrantProgram(
        program_ref="ca-sred",
        name="Scientific Research & Experimental Development (SR&ED)",
        jurisdiction="CA",
        administering_body="Canada Revenue Agency (CRA)",
        funding_type="tax_credit",
        category="rnd",
        official_source_url="https://www.canada.ca/en/revenue-agency/services/scientific-research-experimental-development-tax-incentive-program.html",
        last_verified="2026-01",
        headline_benefit=(
            "Investment tax credit on eligible R&D carried out in Canada; "
            "Canadian-controlled private corporations may qualify for an "
            "enhanced refundable credit. Rate and expenditure limit are set by "
            "the CRA and change — verify at source."
        ),
        eligibility=EligibilitySignals(
            requires_rnd=True,
            indicative_notes=(
                "Open to corporations, individuals, and partnerships performing "
                "eligible experimental development or applied research in Canada. "
                "The enhanced refundable rate targets CCPCs within an expenditure "
                "limit; confirm your entity type and eligible work with the CRA."
            ),
        ),
    ),
    GrantProgram(
        program_ref="ca-nrc-irap",
        name="NRC Industrial Research Assistance Program (IRAP)",
        jurisdiction="CA",
        administering_body="National Research Council Canada (NRC)",
        funding_type="contribution",
        category="rnd",
        official_source_url="https://nrc.canada.ca/en/support-technology-innovation",
        last_verified="2026-01",
        headline_benefit=(
            "Advisory services and cost-shared contributions for R&D and "
            "technology-innovation projects at growth-oriented small and "
            "medium enterprises. Funding is project-assessed — verify at source."
        ),
        eligibility=EligibilitySignals(
            requires_incorporation=True,
            requires_rnd=True,
            for_smes=True,
            indicative_notes=(
                "Typically an incorporated, profit-oriented Canadian SME (often "
                "cited as up to 500 full-time employees) pursuing technology "
                "innovation. Engagement usually starts with an NRC IRAP advisor."
            ),
        ),
    ),
    GrantProgram(
        program_ref="ca-canexport-sme",
        name="CanExport SMEs",
        jurisdiction="CA",
        administering_body="Global Affairs Canada — Trade Commissioner Service",
        funding_type="reimbursement",
        category="export",
        official_source_url="https://www.tradecommissioner.gc.ca/campaign-campagne/ATCM-MCAC/canexport-sme-pme.aspx",
        last_verified="2026-01",
        headline_benefit=(
            "Cost-shared reimbursement of expenses to develop new export "
            "markets (market research, trade shows, adaptation of marketing). "
            "Share and caps are set by the program — verify at source."
        ),
        eligibility=EligibilitySignals(
            requires_incorporation=True,
            requires_export_intent=True,
            for_smes=True,
            indicative_notes=(
                "For-profit incorporated Canadian SME with some annual revenue, "
                "targeting export markets where it has little or no sales. "
                "Confirm current revenue and employee thresholds at source."
            ),
        ),
    ),
    GrantProgram(
        program_ref="au-rnd-tax-incentive",
        name="Research & Development Tax Incentive (R&DTI)",
        jurisdiction="AU",
        administering_body="AusIndustry & the Australian Taxation Office",
        funding_type="tax_credit",
        category="rnd",
        official_source_url="https://business.gov.au/grants-and-programs/research-and-development-tax-incentive",
        last_verified="2026-01",
        headline_benefit=(
            "Tax offset for eligible R&D activities; companies below the "
            "turnover threshold may receive a refundable offset. Rates, the "
            "turnover threshold, and the minimum spend are set by government — "
            "verify at source."
        ),
        eligibility=EligibilitySignals(
            requires_incorporation=True,
            requires_rnd=True,
            indicative_notes=(
                "A company incorporated in (or eligible under) Australia "
                "conducting eligible core/supporting R&D, usually above a "
                "minimum annual R&D spend. The refundable offset targets "
                "companies under an aggregated-turnover cap — confirm both."
            ),
        ),
    ),
    GrantProgram(
        program_ref="au-emdg",
        name="Export Market Development Grants (EMDG)",
        jurisdiction="AU",
        administering_body="Austrade",
        funding_type="reimbursement",
        category="export",
        official_source_url="https://www.austrade.gov.au/australian/export/export-grants",
        last_verified="2026-01",
        headline_benefit=(
            "Support toward eligible export promotion activities for Australian "
            "businesses growing into overseas markets, delivered in tiers with "
            "grant agreements and rounds — verify current round and caps at source."
        ),
        eligibility=EligibilitySignals(
            requires_export_intent=True,
            for_smes=True,
            indicative_notes=(
                "An Australian business promoting eligible products/services to "
                "export markets, under a turnover ceiling, ready-to-export. "
                "Grants are competitive and round-based — check the open round."
            ),
        ),
    ),
    GrantProgram(
        program_ref="au-industry-growth-program",
        name="Industry Growth Program",
        jurisdiction="AU",
        administering_body="Department of Industry, Science and Resources",
        funding_type="grant",
        category="commercialisation",
        official_source_url="https://business.gov.au/grants-and-programs/industry-growth-program",
        last_verified="2026-01",
        headline_benefit=(
            "Advice and matched grant funding to help innovative SMEs "
            "commercialise novel products, processes, or services and scale, "
            "focused on national priority areas — verify scope and caps at source."
        ),
        eligibility=EligibilitySignals(
            requires_incorporation=True,
            for_smes=True,
            indicative_notes=(
                "An innovative Australian SME with a novel offering aligned to a "
                "national priority area, seeking commercialisation or growth "
                "support. Advisor engagement typically precedes a grant."
            ),
        ),
    ),
)

GRANT_REGISTRY: dict[str, GrantProgram] = {p.program_ref: p for p in _REGISTRY}


# ---------------------------------------------------------------------------
# Company profile + matching
# ---------------------------------------------------------------------------


class CompanyGrantProfile(_StrictModel):
    """What the accountant knows about the company, for matching."""

    profile_ref: PortableRef
    country: Jurisdiction
    region: ShortText | None = None
    is_incorporated: bool
    conducts_rnd: bool
    export_intent: bool
    is_sme: bool = True
    sectors: tuple[SectorTag, ...] = Field(default_factory=tuple)
    annual_revenue: Decimal | None = None
    employee_count: int | None = Field(default=None, ge=0, le=10_000_000)

    @field_validator("annual_revenue", mode="before")
    @classmethod
    def _revenue(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value)

    @field_validator("sectors", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value


class MatchedGrant(_StrictModel):
    program_ref: PortableRef
    name: ShortText
    jurisdiction: Jurisdiction
    funding_type: FundingType
    category: GrantCategory
    fit_score: int = Field(ge=1, le=100)
    match_reasons: tuple[ShortText, ...] = Field(min_length=1)
    headline_benefit: LongText
    official_source_url: HttpsUrl
    last_verified: str
    verification_required: Literal[True] = True

    @field_validator("match_reasons", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value


class UnmatchedGrant(_StrictModel):
    program_ref: PortableRef
    name: ShortText
    reason: ShortText


class GrantMatchResult(_StrictModel):
    schema_id: Literal["lightbulb.grant_match_result.v1"] = Field(
        default=GRANT_MATCH_RESULT_SCHEMA,
        alias="schema",
    )
    profile_ref: PortableRef
    country: Jurisdiction
    matched: tuple[MatchedGrant, ...] = Field(default_factory=tuple)
    not_matched: tuple[UnmatchedGrant, ...] = Field(default_factory=tuple)
    disclaimer: LongText = _DISCLAIMER
    result_digest: str = "0" * 64

    @field_validator("matched", "not_matched", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _evaluate(
    program: GrantProgram, profile: CompanyGrantProfile
) -> tuple[list[str], str | None]:
    """Return (match_reasons, disqualifier). disqualifier None => matched."""

    reasons: list[str] = [f"available in {program.jurisdiction}"]
    signals = program.eligibility

    if signals.requires_incorporation and not profile.is_incorporated:
        return reasons, "program requires an incorporated entity"
    if signals.requires_rnd and not profile.conducts_rnd:
        return reasons, "program requires eligible R&D activity"
    if signals.requires_export_intent and not profile.export_intent:
        return reasons, "program requires export activity or intent"
    if signals.for_smes and not profile.is_sme:
        return reasons, "program targets SMEs"
    if signals.sectors and profile.sectors:
        if not (set(signals.sectors) & set(profile.sectors)):
            return reasons, "program targets sectors outside the profile"

    if signals.requires_rnd and profile.conducts_rnd:
        reasons.append("company conducts R&D")
    if signals.requires_export_intent and profile.export_intent:
        reasons.append("company is export-oriented")
    if signals.requires_incorporation and profile.is_incorporated:
        reasons.append("company is incorporated")
    if signals.for_smes and profile.is_sme:
        reasons.append("company is an SME")
    if signals.sectors and profile.sectors and (set(signals.sectors) & set(profile.sectors)):
        reasons.append("sector aligns with the program focus")
    return reasons, None


def match_grant_programs(
    inputs: CompanyGrantProfile | Mapping[str, Any],
) -> GrantMatchResult:
    """Match a company profile against the flagship non-dilutive registry."""

    profile = (
        inputs
        if isinstance(inputs, CompanyGrantProfile)
        else CompanyGrantProfile.model_validate(inputs)
    )

    matched: list[MatchedGrant] = []
    not_matched: list[UnmatchedGrant] = []
    for program in _REGISTRY:
        if program.jurisdiction != profile.country:
            continue
        reasons, disqualifier = _evaluate(program, profile)
        if disqualifier is not None:
            not_matched.append(
                UnmatchedGrant(
                    program_ref=program.program_ref,
                    name=program.name,
                    reason=disqualifier,
                )
            )
            continue
        # Fit score: more satisfied signals => higher, capped, deterministic.
        fit = min(100, 40 + 15 * (len(reasons) - 1))
        matched.append(
            MatchedGrant(
                program_ref=program.program_ref,
                name=program.name,
                jurisdiction=program.jurisdiction,
                funding_type=program.funding_type,
                category=program.category,
                fit_score=fit,
                match_reasons=tuple(reasons),
                headline_benefit=program.headline_benefit,
                official_source_url=program.official_source_url,
                last_verified=program.last_verified,
            )
        )

    # Rank by fit desc, then program_ref for a stable, deterministic order.
    matched.sort(key=lambda m: (-m.fit_score, m.program_ref))
    not_matched.sort(key=lambda m: m.program_ref)

    result = GrantMatchResult(
        profile_ref=profile.profile_ref,
        country=profile.country,
        matched=tuple(matched),
        not_matched=tuple(not_matched),
    )
    digest = _stable_digest(result.model_dump(mode="json", exclude={"result_digest"}))
    return result.model_copy(update={"result_digest": digest})


# ---------------------------------------------------------------------------
# Live search plan (for openings a static registry cannot know)
# ---------------------------------------------------------------------------


_OFFICIAL_PORTALS: dict[str, tuple[str, ...]] = {
    "CA": (
        "https://innovation.canada.ca/en",
        "https://www.canada.ca/en/services/business/grants.html",
    ),
    "AU": (
        "https://business.gov.au/grants-and-programs",
        "https://www.grants.gov.au",
    ),
}


class GrantSearchPlan(_StrictModel):
    """A plan to find current openings — queries and portals, not results."""

    schema_id: Literal["lightbulb.grant_search_plan.v1"] = Field(
        default=GRANT_SEARCH_PLAN_SCHEMA,
        alias="schema",
    )
    profile_ref: PortableRef
    country: Jurisdiction
    queries: tuple[ShortText, ...] = Field(min_length=1, max_length=30)
    official_portals: tuple[HttpsUrl, ...] = Field(min_length=1)
    guidance: LongText
    disclaimer: LongText = _DISCLAIMER
    plan_digest: str = "0" * 64

    @field_validator("queries", "official_portals", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def compose_grant_search_plan(
    inputs: CompanyGrantProfile | Mapping[str, Any],
    *,
    year: int | None = None,
) -> GrantSearchPlan:
    """Compose structured queries + portals to find current grant openings.

    Returns a search PLAN for a human or a web-search connector to run; it does
    not fabricate current programs or openings. ``year`` biases queries toward a
    given cycle when supplied (the module cannot read the clock).
    """

    profile = (
        inputs
        if isinstance(inputs, CompanyGrantProfile)
        else CompanyGrantProfile.model_validate(inputs)
    )
    country_name = "Canada" if profile.country == "CA" else "Australia"
    where = profile.region.strip() if profile.region else country_name
    cycle = f" {year}" if year is not None else ""

    queries: list[str] = [
        f"non-dilutive grants for startups in {where}{cycle}",
        f"government funding programs {where} small business{cycle}",
    ]
    if profile.conducts_rnd:
        queries.append(f"R&D grants and tax credits {where} technology company{cycle}")
    if profile.export_intent:
        queries.append(f"export market development grant {country_name}{cycle}")
    for sector in profile.sectors[:4]:
        pretty = sector.replace("-", " ").replace("_", " ")
        queries.append(f"{pretty} innovation grant {country_name}{cycle}")
    if profile.region:
        queries.append(f"{profile.region} provincial state innovation funding{cycle}")

    guidance = (
        "Run these against a web search or the official portals, then verify "
        "each candidate's current eligibility, open round, and deadline at its "
        "administering body before applying. Prioritise non-dilutive programs "
        "(tax credits, contributions, reimbursements) and confirm you are not "
        "already claiming a mutually exclusive one."
    )

    plan = GrantSearchPlan(
        profile_ref=profile.profile_ref,
        country=profile.country,
        queries=tuple(dict.fromkeys(queries))[:30],
        official_portals=_OFFICIAL_PORTALS[profile.country],
        guidance=guidance,
    )
    digest = _stable_digest(plan.model_dump(mode="json", exclude={"plan_digest"}))
    return plan.model_copy(update={"plan_digest": digest})


def grant_registry() -> tuple[dict[str, Any], ...]:
    """Discoverable list of the flagship programs in the registry."""

    return tuple(
        {
            "program_ref": p.program_ref,
            "name": p.name,
            "jurisdiction": p.jurisdiction,
            "funding_type": p.funding_type,
            "category": p.category,
            "official_source_url": p.official_source_url,
            "last_verified": p.last_verified,
        }
        for p in _REGISTRY
    )


# ---------------------------------------------------------------------------
# Executable primitives (the accountant's agent-invocable grant tools)
# ---------------------------------------------------------------------------


_EXAMPLE_PROFILE: dict[str, Any] = {
    "profile_ref": "example-startup",
    "country": "CA",
    "region": "Ontario",
    "is_incorporated": True,
    "conducts_rnd": True,
    "export_intent": True,
    "is_sme": True,
    "sectors": ["software"],
    "employee_count": 18,
}


class MatchGrantsPrimitive(
    BusinessProcessPrimitive[CompanyGrantProfile, GrantMatchResult]
):
    """Match a company to flagship non-dilutive programs (Canada / Australia)."""

    primitive_ref = "accounting.match_grants"
    version = "1.0.0"
    title = "Match non-dilutive grant programs"
    description = (
        "Match a company profile against a curated registry of real, sourced "
        "non-dilutive funding programs in Canada and Australia (R&D tax "
        "incentives, innovation contributions, export reimbursements). Returns "
        "ranked matches with the reasons each fit and the official source to "
        "verify, plus the programs that did not match and why. Every match is "
        "indicative and carries verification_required — program terms change and "
        "must be confirmed at source. Not tax or financial advice."
    )
    input_model = CompanyGrantProfile
    output_model = GrantMatchResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = _EXAMPLE_PROFILE

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CompanyGrantProfile,
    ) -> PrimitiveExecutionResult[GrantMatchResult]:
        try:
            result = match_grant_programs(inputs)
        except ValueError as exc:
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=f"grant match rejected: {exc}",
                output=None,
            )
        return PrimitiveExecutionResult[GrantMatchResult](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"{len(result.matched)} program(s) matched for {result.profile_ref} "
                f"in {result.country}; verify each at source."
            ),
            output=result,
            events=[
                PrimitiveEvent(
                    type="accounting.grants_matched",
                    payload={
                        "profile_ref": result.profile_ref,
                        "matched": len(result.matched),
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Indicative matches only; verify current terms at each "
                    "official source.",
                )
            ],
        )


GrantSearchStatus = Literal["completed", "empty"]


class GrantSearchRequest(_StrictModel):
    """A machine-runnable request to search for grants via the platform tool.

    The SDK cannot invoke the platform's web-research action from a deterministic
    primitive (it is a domain-agent action, not a connector tool), so it emits
    this request instead: a profile-tailored query aimed at ``target_tool`` that
    the agent runtime runs, then feeds the raw output to
    :func:`normalize_grant_findings`. This is the system searching automatically
    — not a human to-do list — with the SDK owning the query and the honesty bar.
    """

    schema_id: Literal["lightbulb.grant_search_request.v1"] = Field(
        default=GRANT_SEARCH_REQUEST_SCHEMA,
        alias="schema",
    )
    profile_ref: PortableRef
    country: Jurisdiction
    target_tool: ShortText
    query: LongText
    guidance: LongText
    disclaimer: LongText = _DISCLAIMER
    request_digest: str = "0" * 64

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class GrantSearchFindings(_StrictModel):
    """Normalized grant-search findings — what the platform search returned.

    The findings are raw research output, captured verbatim (bounded). They are
    leads to confirm at source, not registry-confirmed programs: a static
    registry cannot know new or regional openings, so this reaches past it via
    the platform's own search — but the honesty bar is unchanged, so every lead
    is verification_required.
    """

    schema_id: Literal["lightbulb.grant_search_findings.v1"] = Field(
        default=GRANT_SEARCH_FINDINGS_SCHEMA,
        alias="schema",
    )
    profile_ref: PortableRef
    country: Jurisdiction
    source_tool: ShortText
    query: LongText
    status: GrantSearchStatus
    findings: FindingsText | None = None
    verification_required: Literal[True] = True
    disclaimer: LongText = _DISCLAIMER
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=10)
    findings_digest: str = "0" * 64

    @field_validator("notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        if isinstance(value, list):
            return tuple(value)
        return value

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _search_query(profile: CompanyGrantProfile) -> str:
    country_name = "Canada" if profile.country == "CA" else "Australia"
    plan = compose_grant_search_plan(profile)
    signals: list[str] = []
    if profile.is_incorporated:
        signals.append("incorporated")
    if profile.conducts_rnd:
        signals.append("performs R&D")
    if profile.export_intent:
        signals.append("export-oriented")
    if profile.is_sme:
        signals.append("SME")
    for sector in profile.sectors[:4]:
        signals.append(sector.replace("-", " ").replace("_", " "))
    region = f" Region: {profile.region}." if profile.region else ""
    query = (
        "Find current, open non-dilutive government grant and funding programs "
        f"for a company in {country_name}.{region} Prioritise R&D tax incentives, "
        "innovation grants/contributions, and export support. For each program "
        "return its official name, administering body, official source URL, "
        "eligibility summary, and any current deadline or open round. Company "
        f"signals: {', '.join(signals) or 'none supplied'}. Suggested search "
        f"terms: {' | '.join(plan.queries)}."
    )
    # Truncate to the LongText budget on a clean boundary: a hard [:600] can land
    # on a space and leave trailing whitespace that the strict validator rejects.
    return query[:600].rstrip()


def _stringify_findings(output: Any) -> str | None:
    if output is None:
        return None
    if isinstance(output, str):
        text = output
    elif isinstance(output, Mapping):
        for key in ("text", "result", "output", "answer", "summary", "content"):
            value = output.get(key)
            if isinstance(value, str) and value.strip():
                text = value
                break
        else:
            text = json.dumps(output, ensure_ascii=True, default=str)
    else:
        text = json.dumps(output, ensure_ascii=True, default=str)
    # Verbatim research output can carry ANSI escapes / form feeds that the
    # strict FindingsText validator forbids; neutralize disallowed control chars
    # (keep \n\t\r) rather than let "capture verbatim" crash the normalizer.
    text = "".join(
        character if ord(character) >= 32 or character in "\n\t\r" else " "
        for character in text
    ).strip()
    if not text:
        return None
    return text[:8000]


def normalize_grant_findings(
    *,
    profile_ref: str,
    country: str,
    query: str,
    raw_response: Any,
    source_tool: str = _SEARCH_TOOL,
) -> GrantSearchFindings:
    """Structure the raw output of a grant search into verify-flagged leads.

    Call this with whatever the agent got back from running a
    :class:`GrantSearchRequest` against the platform's research tool. The raw
    text is captured verbatim (bounded); nothing is asserted as a verified
    program, and every lead stays ``verification_required``.
    """

    findings_text = _stringify_findings(raw_response)
    notes = ["leads are unverified; confirm each program at its official source"]
    status: GrantSearchStatus = "completed" if findings_text else "empty"
    if findings_text is None:
        notes.insert(0, "the research tool returned no readable findings")
    findings = GrantSearchFindings(
        profile_ref=profile_ref,
        country=country,  # type: ignore[arg-type]
        source_tool=source_tool,
        query=query,
        status=status,
        findings=findings_text,
        notes=tuple(dict.fromkeys(notes))[:10],
    )
    digest = _stable_digest(
        findings.model_dump(mode="json", exclude={"findings_digest"})
    )
    return findings.model_copy(update={"findings_digest": digest})


class SearchGrantsPrimitive(
    BusinessProcessPrimitive[CompanyGrantProfile, GrantSearchRequest]
):
    """Compose a machine-runnable grant search for the platform to execute."""

    primitive_ref = "accounting.search_grants"
    version = "1.0.0"
    title = "Search live for grant programs"
    description = (
        "Compose a profile-tailored search for current, open non-dilutive grant "
        "programs, aimed at the platform's own web-research tool "
        "(deep_research.research_query), reaching past the flagship registry to "
        "new, regional, and round-based openings a static list cannot track. The "
        "agent runtime runs the request and feeds the result to "
        "normalize_grant_findings; findings are always leads to confirm at "
        "source, never verified programs, never fabricated."
    )
    input_model = CompanyGrantProfile
    output_model = GrantSearchRequest
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = _EXAMPLE_PROFILE

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CompanyGrantProfile,
    ) -> PrimitiveExecutionResult[GrantSearchRequest]:
        query = _search_query(inputs)
        request = GrantSearchRequest(
            profile_ref=inputs.profile_ref,
            country=inputs.country,
            target_tool=_SEARCH_TOOL,
            query=query,
            guidance=(
                "Run target_tool with this query, then pass the raw result to "
                "normalize_grant_findings. Treat every hit as a lead to confirm "
                "at its official source — not a verified program."
            ),
        )
        digest = _stable_digest(
            request.model_dump(mode="json", exclude={"request_digest"})
        )
        request = request.model_copy(update={"request_digest": digest})
        return PrimitiveExecutionResult[GrantSearchRequest](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Grant search request for {request.profile_ref} in "
                f"{request.country}, aimed at {request.target_tool}."
            ),
            output=request,
            events=[
                PrimitiveEvent(
                    type="accounting.grant_search_composed",
                    payload={
                        "profile_ref": request.profile_ref,
                        "target_tool": request.target_tool,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Machine-runnable search request; the agent executes it.",
                )
            ],
        )


__all__ = [
    "GRANT_MATCH_RESULT_SCHEMA",
    "GRANT_SEARCH_FINDINGS_SCHEMA",
    "GRANT_SEARCH_PLAN_SCHEMA",
    "GRANT_SEARCH_REQUEST_SCHEMA",
    "GRANT_REGISTRY",
    "CompanyGrantProfile",
    "EligibilitySignals",
    "GrantDiscoveryError",
    "GrantMatchResult",
    "GrantProgram",
    "GrantSearchFindings",
    "GrantSearchPlan",
    "GrantSearchRequest",
    "MatchGrantsPrimitive",
    "MatchedGrant",
    "SearchGrantsPrimitive",
    "UnmatchedGrant",
    "compose_grant_search_plan",
    "grant_registry",
    "match_grant_programs",
    "normalize_grant_findings",
]
