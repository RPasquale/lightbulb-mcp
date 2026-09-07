"""Growth mandate: bounded autonomy the human can actually grant.

Everything else in the Growth Engine measures, prices, and plans; this
module is where the human converts trust into throughput. A
:class:`GrowthMandate` is a sealed delegation contract: which action
kinds an agent may take without asking, a money ceiling per action and a
rolling-window ceiling per kind, guardrail conditions pinned to sealed
evidence, and a mandatory expiry. :func:`authorize_growth_action` is the
gate: given the mandate, a proposed action, the prior receipts, and
current evidence, it mints a sealed :class:`ActionAuthorization` whose
verdict is ``authorized``, ``escalate``, or ``refused`` — and every
verdict, including the ones that say no, leaves a receipt.

The honesty rules that make delegation safe:

- **Silence never authorizes.** A guardrail that cannot be evaluated —
  missing evidence, stale evidence, an absent assessment — escalates. The
  gate authorizes only what it can affirmatively check.
- **The receipt is the accountability.** Escalations and refusals are
  sealed exactly like approvals, so the audit trail shows what the agent
  asked for and what the gate said, not just what went through.
- **Ceilings count what the gate is shown.** Window arithmetic sums the
  prior authorized receipts supplied to the call; the workspace path
  supplies the complete stored set, and every receipt is HMAC-verified
  before it counts. A prior receipt that fails verification escalates —
  a budget that cannot be honestly computed cannot approve new spend.
- **Delegation expires.** A mandate must carry an expiry (at most a year
  out); renewal is a human act. Amending or revoking is a new mandate
  naming ``supersedes`` — the gate itself always judges against the
  mandate it is handed, so callers must hand it the latest one (the
  workspace path does).
- **Authorization is not execution.** A receipt says the action was
  within delegated bounds at decision time; whether it happened, and what
  it did, is the rail bridge's story.

The executable-primitive projection is deliberately the *preflight*: a
dry-run advisory check that never mints a receipt and says so, because
sealing authority requires the host-held keyring the primitive surface
does not carry.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Protocol

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .dynamic_workflows import DynamicWorkflowScope
from .growth_objectives import (
    GrowthObjective,
    assess_objective_progress,
    verify_growth_objective,
)
from .growth_profit import (
    UnitEconomicsSnapshot,
    verify_unit_economics_snapshot,
)
from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

GROWTH_MANDATE_SCHEMA = "lightbulb.growth_mandate.v1"
ACTION_AUTHORIZATION_SCHEMA = "lightbulb.action_authorization.v1"
MANDATE_CHECK_SCHEMA = "lightbulb.mandate_check.v1"

_MANDATE_HMAC_DOMAIN = GROWTH_MANDATE_SCHEMA
_AUTHORIZATION_HMAC_DOMAIN = ACTION_AUTHORIZATION_SCHEMA

_RATE_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.01")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

_MAX_GRANTS = 8
_MAX_GUARDRAILS = 5
_MAX_PRIOR_AUTHORIZATIONS = 500
_MAX_REASONS = 10
_MAX_CHECKS = 10
_MAX_MANDATE_DAYS = 366

MandateActionKind = Literal[
    "adjust_channel_budget",
    "launch_experiment",
    "publish_content",
    "price_move",
]
AuthorizationVerdict = Literal["authorized", "escalate", "refused"]
GuardrailStatus = Literal["passed", "failed", "unevaluable"]

# Mirrors growth_profit.EconomicsComponentName; asserted equal by the test
# suite so a new component cannot silently diverge the guardrail vocabulary.
GuardrailMetric = Literal[
    "net_revenue",
    "variable_cost_total",
    "contribution_profit",
    "contribution_margin",
    "average_order_value",
    "contribution_per_order",
    "customer_acquisition_cost",
    "breakeven_roas",
    "cac_payback_orders",
]
ObjectiveVerdictName = Literal[
    "on_track",
    "at_risk",
    "off_track",
    "achieved",
    "expired_missed",
]


class GrowthMandateValidationError(ValueError):
    """Mandate, action, or receipt content violates the delegation contract."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
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
    StringConstraints(min_length=1, max_length=10_000),
    AfterValidator(_bounded_text),
]
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]


def _parse_timestamp(value: str) -> datetime:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _normalized_timestamp(value: str) -> str:
    return _parse_timestamp(value).isoformat().replace("+00:00", "Z")


def _render_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _one_line(value: str) -> str:
    return " ".join(value.split())[:300].rstrip()


def _decimal(value: Any, *, quantum: Decimal | None = None) -> Decimal:
    if not isinstance(value, (str, Decimal, int, float)) or isinstance(value, bool):
        raise ValueError("decimal values must be supplied as strings or JSON numbers")
    lexical = str(value)
    if len(lexical) > 48 or lexical != lexical.strip():
        raise ValueError("value must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValueError("value must be a finite decimal")
    if quantum is not None:
        try:
            normalized = parsed.quantize(quantum)
        except InvalidOperation as exc:
            raise ValueError(
                "value cannot be represented at the required precision"
            ) from exc
        if parsed != normalized:
            raise ValueError(
                f"value supports at most {-quantum.as_tuple().exponent} decimal places"
            )
        return normalized
    return parsed


def _immutable_sequence(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class ExactScopeDigestProvider(Protocol):
    """Host-held keyed scope digester; raw authority never enters artifacts."""

    active_key_id: str

    def exact_scope_digest(
        self,
        *,
        key_id: str,
        scope: DynamicWorkflowScope,
    ) -> str: ...

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes: ...


def _keyring_signature(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    domain: str,
    payload: Any,
) -> str:
    try:
        return scope_keyring.sign(key_id, domain, payload).hex()
    except GrowthMandateValidationError:
        raise
    except Exception as exc:
        raise GrowthMandateValidationError(
            "the mandate signing key is unavailable"
        ) from exc


def _keyring_scope_digest(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    scope: DynamicWorkflowScope,
) -> str:
    try:
        return scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    except GrowthMandateValidationError:
        raise
    except Exception as exc:
        raise GrowthMandateValidationError(
            "the mandate signing key is unavailable"
        ) from exc


def _workflow_scope(
    scope: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(scope, DynamicWorkflowScope):
        return scope
    return DynamicWorkflowScope.model_validate(scope)


# ---------------------------------------------------------------------------
# The sealed mandate
# ---------------------------------------------------------------------------


class EconomicsGuardrail(_StrictModel):
    """The action is allowed only while a sealed economics component holds.

    ``floor`` requires the component at or above the threshold; ``ceiling``
    requires it at or below. Evidence older than ``max_evidence_age_hours``
    at decision time — or a snapshot missing the component — makes the
    check unevaluable, which escalates.
    """

    kind: Literal["economics_bound"] = "economics_bound"
    metric: GuardrailMetric
    bound: Literal["floor", "ceiling"]
    threshold: Decimal
    max_evidence_age_hours: int = Field(default=720, ge=1, le=8_760)

    @field_validator("threshold", mode="before")
    @classmethod
    def _threshold_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)


class ObjectiveVerdictGuardrail(_StrictModel):
    """The action is allowed only while the objective's verdict is listed.

    The gate NEVER trusts a caller-supplied verdict: advisory assessments
    carry no seal, so it derives the verdict itself at decision time — the
    same deterministic :func:`assess_objective_progress` computation, fed
    only the VERIFIED objective and VERIFIED current economics. A missing
    objective or economics, economics older than
    ``max_evidence_age_hours``, or a derivation the objectives engine
    refuses makes the check unevaluable, which escalates — silence about
    the objective never authorizes spend against it.
    """

    kind: Literal["objective_verdict"] = "objective_verdict"
    allowed_verdicts: tuple[ObjectiveVerdictName, ...] = Field(
        min_length=1, max_length=5
    )
    max_evidence_age_hours: int = Field(default=336, ge=1, le=8_760)

    @field_validator("allowed_verdicts", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _unique_verdicts(self) -> "ObjectiveVerdictGuardrail":
        if len(self.allowed_verdicts) != len(set(self.allowed_verdicts)):
            raise ValueError("allowed_verdicts must be unique")
        return self


MandateGuardrail = Annotated[
    EconomicsGuardrail | ObjectiveVerdictGuardrail,
    Field(discriminator="kind"),
]


class MandateGrant(_StrictModel):
    """One delegated action kind with its money ceilings and guardrails."""

    action_kind: MandateActionKind
    per_action_limit: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    window_limit: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    window_days: int = Field(ge=1, le=366)
    guardrails: tuple[MandateGuardrail, ...] = Field(
        default_factory=tuple, max_length=_MAX_GUARDRAILS
    )

    @field_validator("per_action_limit", "window_limit", mode="before")
    @classmethod
    def _money_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("guardrails", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _ordered_limits(self) -> "MandateGrant":
        if self.per_action_limit > self.window_limit:
            raise ValueError(
                "a single action cannot be allowed to exceed the window limit"
            )
        return self


class GrowthMandate(_StrictModel):
    """A sealed delegation of bounded authority. The HMAC is the grant."""

    schema_id: Literal["lightbulb.growth_mandate.v1"] = Field(
        default=GROWTH_MANDATE_SCHEMA,
        alias="schema",
    )
    mandate_ref: PortableRef
    granted_by: ShortText
    granted_to: ShortText
    currency: CurrencyCode
    granted_at: str
    expires_at: str
    grants: tuple[MandateGrant, ...] = Field(min_length=1, max_length=_MAX_GRANTS)
    rationale: LongText
    supersedes: Sha256Digest | None = None
    mandate_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    mandate_hmac: Sha256Digest | None = None

    @field_validator("granted_at", "expires_at")
    @classmethod
    def _valid_timestamps(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("grants", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _delegation_shape(self) -> "GrowthMandate":
        granted_at = _parse_timestamp(self.granted_at)
        expires_at = _parse_timestamp(self.expires_at)
        if expires_at <= granted_at:
            raise ValueError("expires_at must follow granted_at")
        if expires_at - granted_at > timedelta(days=_MAX_MANDATE_DAYS):
            raise ValueError(
                "delegation must expire within "
                f"{_MAX_MANDATE_DAYS} days; open-ended authority is not a "
                "thing that can honestly exist"
            )
        kinds = [grant.action_kind for grant in self.grants]
        if len(kinds) != len(set(kinds)):
            raise ValueError("at most one grant per action kind")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.mandate_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError("mandate attestation fields must be supplied together")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"mandate_digest", "mandate_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.mandate_digest != "0" * 64 and self.mandate_digest != expected:
            raise ValueError("mandate_digest does not match the canonical payload")
        object.__setattr__(self, "mandate_digest", expected)
        return self

    @property
    def is_sealed(self) -> bool:
        return self.mandate_hmac is not None

    def grant_for(self, action_kind: str) -> MandateGrant | None:
        for grant in self.grants:
            if grant.action_kind == action_kind:
                return grant
        return None

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"mandate_hmac", "mandate_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class GrantGrowthMandateInput(_StrictModel):
    mandate_ref: PortableRef
    granted_by: ShortText
    granted_to: ShortText
    currency: CurrencyCode
    granted_at: str
    expires_at: str
    grants: tuple[MandateGrant, ...] = Field(min_length=1, max_length=_MAX_GRANTS)
    rationale: LongText
    supersedes: Sha256Digest | None = None

    @field_validator("granted_at", "expires_at")
    @classmethod
    def _valid_timestamps(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("grants", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)


def grant_growth_mandate(
    inputs: GrantGrowthMandateInput | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> GrowthMandate:
    """Seal a delegation of bounded authority.

    Holding the scope keyring IS the granting authority: this call runs on
    the host path where the human's key lives, never on the primitive/MCP
    surface. Amending or revoking is a new mandate naming ``supersedes``.
    """

    parsed = (
        inputs
        if isinstance(inputs, GrantGrowthMandateInput)
        else GrantGrowthMandateInput.model_validate(inputs)
    )
    workflow_scope = _workflow_scope(scope)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    draft = GrowthMandate.model_validate(
        {
            "mandate_ref": parsed.mandate_ref,
            "granted_by": parsed.granted_by,
            "granted_to": parsed.granted_to,
            "currency": parsed.currency,
            "granted_at": parsed.granted_at,
            "expires_at": parsed.expires_at,
            "grants": tuple(
                grant.model_dump(mode="python", by_alias=True, exclude_none=True)
                for grant in parsed.grants
            ),
            "rationale": parsed.rationale,
            **(
                {"supersedes": parsed.supersedes}
                if parsed.supersedes is not None
                else {}
            ),
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "mandate_hmac": "0" * 64,
        }
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_MANDATE_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"mandate_digest"},
        exclude_none=True,
    )
    sealed["mandate_hmac"] = signature
    return GrowthMandate.model_validate(sealed)


def verify_growth_mandate(
    value: GrowthMandate | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> GrowthMandate:
    """Re-validate and verify one sealed mandate; raise on failure."""

    mandate = GrowthMandate.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, GrowthMandate)
        else value
    )
    if (
        mandate.receipt_key_id is None
        or mandate.exact_scope_digest is None
        or mandate.mandate_hmac is None
    ):
        raise GrowthMandateValidationError("the mandate carries no delegation seal")
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=mandate.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(mandate.exact_scope_digest, expected_scope_digest):
        raise GrowthMandateValidationError("mandate attestation failed verification")
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=mandate.receipt_key_id,
        domain=_MANDATE_HMAC_DOMAIN,
        payload=mandate.hmac_payload(),
    )
    if not hmac.compare_digest(mandate.mandate_hmac, expected_hmac):
        raise GrowthMandateValidationError("mandate attestation failed verification")
    return mandate


# ---------------------------------------------------------------------------
# The proposed action and the sealed receipt
# ---------------------------------------------------------------------------


class ProposedAction(_StrictModel):
    """What the agent wants to do, stated in money before it happens."""

    action_ref: PortableRef
    action_kind: MandateActionKind
    amount: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    currency: CurrencyCode
    description: LongText
    plan_digest: Sha256Digest | None = None

    @field_validator("amount", mode="before")
    @classmethod
    def _money_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)


class GuardrailCheck(_StrictModel):
    """One guardrail's evaluation, pinned to the evidence it consulted."""

    description: ShortText
    status: GuardrailStatus
    observed: ShortText | None = None
    threshold: ShortText | None = None
    evidence_digest: Sha256Digest | None = None
    note: ShortText | None = None


class ActionAuthorization(_StrictModel):
    """One sealed gate decision. Approvals and denials leave the same trail."""

    schema_id: Literal["lightbulb.action_authorization.v1"] = Field(
        default=ACTION_AUTHORIZATION_SCHEMA,
        alias="schema",
    )
    authorization_ref: PortableRef
    mandate_ref: PortableRef
    mandate_digest: Sha256Digest
    decided_at: str
    action_ref: PortableRef
    action_kind: MandateActionKind
    amount: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    currency: CurrencyCode
    description: LongText
    plan_digest: Sha256Digest | None = None
    verdict: AuthorizationVerdict
    reasons: tuple[ShortText, ...] = Field(min_length=1, max_length=_MAX_REASONS)
    checks: tuple[GuardrailCheck, ...] = Field(
        default_factory=tuple, max_length=_MAX_CHECKS
    )
    per_action_limit: Decimal | None = Field(
        default=None, ge=0, multiple_of=_MONEY_QUANTUM
    )
    window_limit: Decimal | None = Field(
        default=None, ge=0, multiple_of=_MONEY_QUANTUM
    )
    window_days: int | None = Field(default=None, ge=1, le=366)
    window_spent_before: Decimal | None = Field(
        default=None, ge=0, multiple_of=_MONEY_QUANTUM
    )
    window_remaining_after: Decimal | None = Field(
        default=None, ge=0, multiple_of=_MONEY_QUANTUM
    )
    prior_receipts_counted: int = Field(ge=0, le=_MAX_PRIOR_AUTHORIZATIONS)
    authorization_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    authorization_hmac: Sha256Digest | None = None

    @field_validator("decided_at")
    @classmethod
    def _valid_decided_at(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "amount",
        "per_action_limit",
        "window_limit",
        "window_spent_before",
        "window_remaining_after",
        mode="before",
    )
    @classmethod
    def _money_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("reasons", "checks", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _decision_shape(self) -> "ActionAuthorization":
        if self.verdict == "authorized":
            if any(check.status != "passed" for check in self.checks):
                raise ValueError(
                    "an authorized receipt cannot carry failed or "
                    "unevaluable guardrail checks"
                )
            if self.window_remaining_after is None:
                raise ValueError(
                    "an authorized receipt must state the remaining window budget"
                )
        elif self.window_remaining_after is not None:
            raise ValueError(
                "only an authorized receipt states a remaining window budget"
            )
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.authorization_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "authorization attestation fields must be supplied together"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authorization_digest", "authorization_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if (
            self.authorization_digest != "0" * 64
            and self.authorization_digest != expected
        ):
            raise ValueError(
                "authorization_digest does not match the canonical payload"
            )
        object.__setattr__(self, "authorization_digest", expected)
        return self

    @property
    def is_sealed(self) -> bool:
        return self.authorization_hmac is not None

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authorization_hmac", "authorization_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def verify_action_authorization(
    value: ActionAuthorization | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> ActionAuthorization:
    """Re-validate and verify one sealed authorization; raise on failure."""

    receipt = ActionAuthorization.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, ActionAuthorization)
        else value
    )
    if (
        receipt.receipt_key_id is None
        or receipt.exact_scope_digest is None
        or receipt.authorization_hmac is None
    ):
        raise GrowthMandateValidationError(
            "the authorization carries no decision seal"
        )
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=receipt.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(receipt.exact_scope_digest, expected_scope_digest):
        raise GrowthMandateValidationError(
            "authorization attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=receipt.receipt_key_id,
        domain=_AUTHORIZATION_HMAC_DOMAIN,
        payload=receipt.hmac_payload(),
    )
    if not hmac.compare_digest(receipt.authorization_hmac, expected_hmac):
        raise GrowthMandateValidationError(
            "authorization attestation failed verification"
        )
    return receipt


# ---------------------------------------------------------------------------
# The decision core (shared by the sealed gate and the preflight)
# ---------------------------------------------------------------------------


class _Decision:
    __slots__ = (
        "verdict",
        "reasons",
        "checks",
        "spent_before",
        "remaining_after",
        "counted",
    )

    def __init__(self) -> None:
        self.verdict: AuthorizationVerdict = "escalate"
        self.reasons: list[str] = []
        self.checks: list[GuardrailCheck] = []
        self.spent_before: Decimal | None = None
        self.remaining_after: Decimal | None = None
        self.counted: int = 0


def _check_economics_guardrail(
    guardrail: EconomicsGuardrail,
    economics: UnitEconomicsSnapshot | None,
    as_of_at: datetime,
) -> GuardrailCheck:
    description = (
        f"economics {guardrail.metric} {guardrail.bound} {guardrail.threshold}"
    )
    if economics is None:
        return GuardrailCheck(
            description=description,
            status="unevaluable",
            note="no unit economics snapshot was supplied",
        )
    age = as_of_at - _parse_timestamp(economics.analysis_as_of)
    if age > timedelta(hours=guardrail.max_evidence_age_hours):
        return GuardrailCheck(
            description=description,
            status="unevaluable",
            evidence_digest=economics.economics_digest,
            note=(
                "the economics snapshot is older than the guardrail's "
                f"{guardrail.max_evidence_age_hours}h evidence bound"
            ),
        )
    component = economics.component(guardrail.metric)
    if component is None:
        return GuardrailCheck(
            description=description,
            status="unevaluable",
            evidence_digest=economics.economics_digest,
            note=(
                "the economics snapshot carries no "
                f"{guardrail.metric} component"
            ),
        )
    if guardrail.bound == "floor":
        passed = component.value >= guardrail.threshold
    else:
        passed = component.value <= guardrail.threshold
    note = None
    if not component.complete:
        note = (
            "the component excludes unknown costs: "
            + ", ".join(component.missing_inputs)
        )[:300].rstrip()
    return GuardrailCheck(
        description=description,
        status="passed" if passed else "failed",
        observed=str(component.value),
        threshold=str(guardrail.threshold),
        evidence_digest=economics.economics_digest,
        note=note,
    )


def _check_objective_guardrail(
    guardrail: ObjectiveVerdictGuardrail,
    objective: GrowthObjective | None,
    economics: UnitEconomicsSnapshot | None,
    as_of_at: datetime,
) -> GuardrailCheck:
    description = "objective verdict in {" + ", ".join(guardrail.allowed_verdicts) + "}"
    if objective is None:
        return GuardrailCheck(
            description=description,
            status="unevaluable",
            note="no growth objective was supplied",
        )
    if economics is None:
        return GuardrailCheck(
            description=description,
            status="unevaluable",
            evidence_digest=objective.objective_digest,
            note=(
                "the verdict is derived in-gate from the current sealed "
                "economics; none were supplied"
            ),
        )
    age = as_of_at - _parse_timestamp(economics.analysis_as_of)
    if age > timedelta(hours=guardrail.max_evidence_age_hours):
        return GuardrailCheck(
            description=description,
            status="unevaluable",
            evidence_digest=economics.economics_digest,
            note=(
                "the economics evidence backing the verdict derivation is "
                f"older than the guardrail's "
                f"{guardrail.max_evidence_age_hours}h bound"
            ),
        )
    # Advisory assessments are caller-forgeable (they carry no seal), so
    # the gate re-derives the verdict itself from the two verified inputs.
    try:
        derived = assess_objective_progress(
            {
                "as_of": _render_timestamp(as_of_at),
                "objective": objective,
                "current_economics": economics,
            }
        )
    except ValueError as exc:
        return GuardrailCheck(
            description=description,
            status="unevaluable",
            evidence_digest=objective.objective_digest,
            note=_one_line(f"the verdict derivation was refused: {exc}"),
        )
    passed = derived.verdict in guardrail.allowed_verdicts
    return GuardrailCheck(
        description=description,
        status="passed" if passed else "failed",
        observed=derived.verdict,
        evidence_digest=derived.assessment_digest,
        note=(
            "verdict derived in-gate from the verified objective and "
            "economics; caller-supplied assessments are never consulted"
        ),
    )


def _decide(
    mandate: GrowthMandate,
    action: ProposedAction,
    priors: Sequence[ActionAuthorization],
    *,
    as_of_at: datetime,
    economics: UnitEconomicsSnapshot | None,
    objective: GrowthObjective | None,
    prior_verification_failures: int,
) -> _Decision:
    decision = _Decision()

    if action.currency != mandate.currency:
        decision.verdict = "refused"
        decision.reasons.append(
            f"the action is stated in {action.currency} against the "
            f"mandate's {mandate.currency}; cross-currency authority is "
            "not a thing that can honestly exist"
        )
        return decision
    granted_at = _parse_timestamp(mandate.granted_at)
    expires_at = _parse_timestamp(mandate.expires_at)
    if as_of_at < granted_at:
        decision.verdict = "refused"
        decision.reasons.append(
            f"the mandate is not effective until {mandate.granted_at}"
        )
        return decision
    if as_of_at >= expires_at:
        decision.verdict = "refused"
        decision.reasons.append(
            f"the mandate expired at {mandate.expires_at}; renewal is the "
            "human's call"
        )
        return decision

    grant = mandate.grant_for(action.action_kind)
    if grant is None:
        decision.verdict = "escalate"
        decision.reasons.append(
            f"the mandate does not delegate {action.action_kind}; a human "
            "decision is required"
        )
        return decision

    escalations: list[str] = []
    if prior_verification_failures > 0:
        escalations.append(
            f"{prior_verification_failures} prior authorization(s) failed "
            "verification; the remaining window budget cannot be honestly "
            "computed"
        )

    window_start = as_of_at - timedelta(days=grant.window_days)
    spent = Decimal("0")
    counted = 0
    for prior in priors:
        if prior.verdict != "authorized":
            continue
        if prior.action_kind != action.action_kind:
            continue
        decided = _parse_timestamp(prior.decided_at)
        # CLOSED window [as_of - window_days, as_of]: a spend at exactly the
        # boundary still counts, so two full-limit actions exactly
        # window_days apart cannot both authorize.
        if window_start <= decided <= as_of_at:
            spent += prior.amount
            counted += 1
    decision.spent_before = spent.quantize(_MONEY_QUANTUM)
    decision.counted = counted

    if action.amount > grant.per_action_limit:
        escalations.append(
            f"the action commits {action.amount} {mandate.currency} against "
            f"a per-action limit of {grant.per_action_limit}"
        )
    if spent + action.amount > grant.window_limit:
        escalations.append(
            f"window spend would reach {spent + action.amount} of the "
            f"{grant.window_limit} {mandate.currency} allowed per "
            f"{grant.window_days} days"
        )

    for guardrail in grant.guardrails:
        if isinstance(guardrail, EconomicsGuardrail):
            check = _check_economics_guardrail(guardrail, economics, as_of_at)
        else:
            check = _check_objective_guardrail(
                guardrail, objective, economics, as_of_at
            )
        decision.checks.append(check)
        if check.status == "failed":
            escalations.append(
                f"guardrail failed: {check.description}"
                + (f" (observed {check.observed})" if check.observed else "")
            )
        elif check.status == "unevaluable":
            escalations.append(
                f"guardrail could not be evaluated: {check.description}"
                + (f" ({check.note})" if check.note else "")
            )

    if escalations:
        decision.verdict = "escalate"
        decision.reasons.extend(escalations[:_MAX_REASONS])
        return decision

    decision.verdict = "authorized"
    decision.remaining_after = (
        grant.window_limit - spent - action.amount
    ).quantize(_MONEY_QUANTUM)
    decision.reasons.append(
        f"within the {action.action_kind} grant: {action.amount} of "
        f"{grant.per_action_limit} per action; window spend "
        f"{(spent + action.amount).quantize(_MONEY_QUANTUM)} of "
        f"{grant.window_limit} {mandate.currency} per {grant.window_days} days"
    )
    if decision.checks:
        decision.reasons.append(
            f"all {len(decision.checks)} guardrail check(s) passed against "
            "pinned evidence"
        )
    return decision


# ---------------------------------------------------------------------------
# The sealed gate (host path)
# ---------------------------------------------------------------------------


class AuthorizeActionInput(_StrictModel):
    """Gate inputs. Deliberately NO assessment field: advisory verdicts are
    caller-forgeable, so the objective guardrail derives its own."""

    as_of: str
    authorization_ref: PortableRef
    mandate: GrowthMandate
    action: ProposedAction
    prior_authorizations: tuple[ActionAuthorization, ...] = Field(
        default_factory=tuple, max_length=_MAX_PRIOR_AUTHORIZATIONS
    )
    current_economics: UnitEconomicsSnapshot | None = None
    objective: GrowthObjective | None = None

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("prior_authorizations", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _coherent_members(self) -> "AuthorizeActionInput":
        refs = [prior.authorization_ref for prior in self.prior_authorizations]
        if len(refs) != len(set(refs)):
            raise ValueError(
                "prior authorizations must be unique per authorization_ref; "
                "a re-decision takes a new ref"
            )
        if self.authorization_ref in set(refs):
            raise ValueError(
                "the new authorization_ref collides with a prior receipt"
            )
        as_of_at = _parse_timestamp(self.as_of)
        for prior in self.prior_authorizations:
            if prior.mandate_digest != self.mandate.mandate_digest:
                raise ValueError(
                    "every prior authorization must cite the mandate being "
                    "decided under; window budgets are per mandate"
                )
            if _parse_timestamp(prior.decided_at) > as_of_at:
                raise ValueError(
                    "a prior authorization is from the future of this decision"
                )
        return self


def authorize_growth_action(
    inputs: AuthorizeActionInput | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> ActionAuthorization:
    """Decide one proposed action against the mandate; mint a sealed receipt.

    This mints authority, so everything sealed is verified before it
    counts: the mandate, every prior receipt, the economics snapshot, and
    the objective. A prior receipt that fails verification degrades the
    verdict to ``escalate`` — never to silence — because a window budget
    computed over unverifiable receipts is not a number this module will
    sign its name to. Advisory artifacts are never consulted: the
    objective-verdict guardrail derives its verdict in-gate from the two
    verified inputs, so there is no assessment to forge.

    The gate judges against the mandate it is handed. Supersession is the
    caller's responsibility: hand it the latest mandate (the workspace
    path does exactly that).
    """

    parsed = (
        inputs
        if isinstance(inputs, AuthorizeActionInput)
        else AuthorizeActionInput.model_validate(inputs)
    )
    workflow_scope = _workflow_scope(scope)
    mandate = verify_growth_mandate(
        parsed.mandate, scope=workflow_scope, scope_keyring=scope_keyring
    )
    economics = parsed.current_economics
    if economics is not None:
        economics = verify_unit_economics_snapshot(
            economics, scope=workflow_scope, scope_keyring=scope_keyring
        )
    objective = parsed.objective
    if objective is not None:
        objective = verify_growth_objective(
            objective, scope=workflow_scope, scope_keyring=scope_keyring
        )
    verified_priors: list[ActionAuthorization] = []
    verification_failures = 0
    for prior in parsed.prior_authorizations:
        try:
            verified_priors.append(
                verify_action_authorization(
                    prior, scope=workflow_scope, scope_keyring=scope_keyring
                )
            )
        except GrowthMandateValidationError:
            verification_failures += 1

    as_of_at = _parse_timestamp(parsed.as_of)
    decision = _decide(
        mandate,
        parsed.action,
        verified_priors,
        as_of_at=as_of_at,
        economics=economics,
        objective=objective,
        prior_verification_failures=verification_failures,
    )
    grant = mandate.grant_for(parsed.action.action_kind)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    draft = ActionAuthorization.model_validate(
        {
            "authorization_ref": parsed.authorization_ref,
            "mandate_ref": mandate.mandate_ref,
            "mandate_digest": mandate.mandate_digest,
            "decided_at": parsed.as_of,
            "action_ref": parsed.action.action_ref,
            "action_kind": parsed.action.action_kind,
            "amount": parsed.action.amount,
            "currency": parsed.action.currency,
            "description": parsed.action.description,
            **(
                {"plan_digest": parsed.action.plan_digest}
                if parsed.action.plan_digest is not None
                else {}
            ),
            "verdict": decision.verdict,
            "reasons": tuple(decision.reasons[:_MAX_REASONS]),
            "checks": tuple(
                check.model_dump(mode="python", by_alias=True, exclude_none=True)
                for check in decision.checks[:_MAX_CHECKS]
            ),
            **(
                {
                    "per_action_limit": grant.per_action_limit,
                    "window_limit": grant.window_limit,
                    "window_days": grant.window_days,
                }
                if grant is not None
                else {}
            ),
            **(
                {"window_spent_before": decision.spent_before}
                if decision.spent_before is not None
                else {}
            ),
            **(
                {"window_remaining_after": decision.remaining_after}
                if decision.remaining_after is not None
                else {}
            ),
            "prior_receipts_counted": decision.counted,
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "authorization_hmac": "0" * 64,
        }
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_AUTHORIZATION_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"authorization_digest"},
        exclude_none=True,
    )
    sealed["authorization_hmac"] = signature
    return ActionAuthorization.model_validate(sealed)


# ---------------------------------------------------------------------------
# Spend summary (advisory; the briefing's view of remaining authority)
# ---------------------------------------------------------------------------


class MandateSpendSummary(_StrictModel):
    """One grant's window arithmetic over the receipts supplied. Advisory."""

    action_kind: MandateActionKind
    per_action_limit: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    window_limit: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    window_days: int = Field(ge=1, le=366)
    window_spent: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    window_remaining: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    receipts_counted: int = Field(ge=0)

    @field_validator(
        "per_action_limit",
        "window_limit",
        "window_spent",
        "window_remaining",
        mode="before",
    )
    @classmethod
    def _money_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)


def summarize_mandate_spend(
    mandate: GrowthMandate,
    prior_authorizations: Sequence[ActionAuthorization],
    *,
    as_of: str,
) -> tuple[MandateSpendSummary, ...]:
    """Per-grant spent/remaining over the SAME closed window the gate uses.

    Advisory arithmetic for briefings and dashboards: receipts are counted
    as supplied, unverified, and the summary is only as complete as the
    receipt set shown to it — the sealed gate (which verifies every
    receipt) remains the only authority on whether a new action fits. A
    test pins this function's numbers to the gate's own receipts so the
    two computations cannot drift.
    """

    as_of_at = _parse_timestamp(as_of)
    summaries: list[MandateSpendSummary] = []
    for grant in mandate.grants:
        window_start = as_of_at - timedelta(days=grant.window_days)
        spent = Decimal("0")
        counted = 0
        for prior in prior_authorizations:
            if prior.verdict != "authorized":
                continue
            if prior.action_kind != grant.action_kind:
                continue
            decided = _parse_timestamp(prior.decided_at)
            if window_start <= decided <= as_of_at:
                spent += prior.amount
                counted += 1
        spent = spent.quantize(_MONEY_QUANTUM)
        summaries.append(
            MandateSpendSummary(
                action_kind=grant.action_kind,
                per_action_limit=grant.per_action_limit,
                window_limit=grant.window_limit,
                window_days=grant.window_days,
                window_spent=spent,
                window_remaining=max(
                    grant.window_limit - spent, Decimal("0")
                ).quantize(_MONEY_QUANTUM),
                receipts_counted=counted,
            )
        )
    return tuple(summaries)


# ---------------------------------------------------------------------------
# The preflight (advisory; the primitive projection)
# ---------------------------------------------------------------------------


class MandateCheck(_StrictModel):
    """What the gate WOULD say. Advisory; no receipt was minted."""

    schema_id: Literal["lightbulb.mandate_check.v1"] = Field(
        default=MANDATE_CHECK_SCHEMA,
        alias="schema",
    )
    as_of: str
    mandate_digest: Sha256Digest
    action_ref: PortableRef
    action_kind: MandateActionKind
    amount: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    currency: CurrencyCode
    predicted_verdict: AuthorizationVerdict
    reasons: tuple[ShortText, ...] = Field(min_length=1, max_length=_MAX_REASONS)
    checks: tuple[GuardrailCheck, ...] = Field(
        default_factory=tuple, max_length=_MAX_CHECKS
    )
    window_spent_before: Decimal | None = Field(
        default=None, ge=0, multiple_of=_MONEY_QUANTUM
    )
    label: Literal["preflight_no_receipt_minted"] = "preflight_no_receipt_minted"
    data_quality_notes: tuple[ShortText, ...] = Field(
        default_factory=tuple, max_length=10
    )
    check_digest: Sha256Digest = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("amount", "window_spent_before", mode="before")
    @classmethod
    def _money_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("reasons", "checks", "data_quality_notes", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _pinned_digest(self) -> "MandateCheck":
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"check_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.check_digest != "0" * 64 and self.check_digest != expected:
            raise ValueError("check_digest does not match the canonical payload")
        object.__setattr__(self, "check_digest", expected)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class PreflightActionInput(_StrictModel):
    as_of: str
    mandate: GrowthMandate
    action: ProposedAction
    prior_authorizations: tuple[ActionAuthorization, ...] = Field(
        default_factory=tuple, max_length=_MAX_PRIOR_AUTHORIZATIONS
    )
    current_economics: UnitEconomicsSnapshot | None = None
    objective: GrowthObjective | None = None

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("prior_authorizations", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _coherent_members(self) -> "PreflightActionInput":
        as_of_at = _parse_timestamp(self.as_of)
        for prior in self.prior_authorizations:
            if prior.mandate_digest != self.mandate.mandate_digest:
                raise ValueError(
                    "every prior authorization must cite the mandate being "
                    "checked; window budgets are per mandate"
                )
            if _parse_timestamp(prior.decided_at) > as_of_at:
                raise ValueError(
                    "a prior authorization is from the future of this check"
                )
        return self


def preflight_growth_action(
    inputs: PreflightActionInput | Mapping[str, Any],
) -> MandateCheck:
    """Dry-run the gate. Advisory: nothing is verified, nothing is minted.

    The predicted verdict is what the sealed gate would say IF every
    supplied artifact verifies against the scope keyring — the preflight
    cannot check that, and says so. Use it to plan; use
    :func:`authorize_growth_action` on the host path to act.
    """

    parsed = (
        inputs
        if isinstance(inputs, PreflightActionInput)
        else PreflightActionInput.model_validate(inputs)
    )
    as_of_at = _parse_timestamp(parsed.as_of)
    decision = _decide(
        parsed.mandate,
        parsed.action,
        parsed.prior_authorizations,
        as_of_at=as_of_at,
        economics=parsed.current_economics,
        objective=parsed.objective,
        prior_verification_failures=0,
    )
    notes = [
        "no seals were verified on this path; the sealed gate re-verifies "
        "the mandate, priors, economics, and objective before deciding",
        "prior authorizations were counted as supplied, unverified",
    ]
    return MandateCheck(
        as_of=parsed.as_of,
        mandate_digest=parsed.mandate.mandate_digest,
        action_ref=parsed.action.action_ref,
        action_kind=parsed.action.action_kind,
        amount=parsed.action.amount,
        currency=parsed.action.currency,
        predicted_verdict=decision.verdict,
        reasons=tuple(decision.reasons[:_MAX_REASONS]),
        checks=tuple(decision.checks[:_MAX_CHECKS]),
        window_spent_before=decision.spent_before,
        data_quality_notes=tuple(notes),
    )


# ---------------------------------------------------------------------------
# Executable primitive (read-only preflight; unverified path by design)
# ---------------------------------------------------------------------------

_EXAMPLE_MANDATE: dict[str, Any] = {
    "mandate_ref": "weekly-growth-ops",
    "granted_by": "founder",
    "granted_to": "growth-agent",
    "currency": "USD",
    "granted_at": "2026-08-19T00:00:00Z",
    "expires_at": "2026-11-17T00:00:00Z",
    "grants": (
        {
            "action_kind": "adjust_channel_budget",
            "per_action_limit": "250.00",
            "window_limit": "1000.00",
            "window_days": 7,
            "guardrails": (
                {
                    "kind": "economics_bound",
                    "metric": "contribution_margin",
                    "bound": "floor",
                    "threshold": "0.25",
                },
            ),
        },
        {
            "action_kind": "publish_content",
            "per_action_limit": "0.00",
            "window_limit": "0.00",
            "window_days": 7,
        },
    ),
    "rationale": (
        "Delegate routine channel-budget moves and content publishing while "
        "contribution margin holds above 25%; everything larger escalates."
    ),
}

_EXAMPLE_ACTION: dict[str, Any] = {
    "action_ref": "raise-search-budget",
    "action_kind": "adjust_channel_budget",
    "amount": "150.00",
    "currency": "USD",
    "description": "Raise paid-search daily budget for the winning ad set.",
}


def _planner_failure(
    primitive_ref: str,
    version: str,
    exc: ValueError,
) -> PrimitiveExecutionResult[Any]:
    return PrimitiveExecutionResult(
        status=PrimitiveExecutionStatus.FAILED,
        primitive_ref=primitive_ref,
        primitive_version=version,
        summary="The mandate engine rejected the inputs.",
        blockers=[
            PrimitiveBlocker(
                code="growth_mandate_invalid",
                message=str(exc)[:500],
            )
        ],
        retryable=False,
    )


class PreflightActionPrimitive(
    BusinessProcessPrimitive[PreflightActionInput, MandateCheck]
):
    """Dry-run a proposed action against a growth mandate."""

    primitive_ref = "growth.preflight_action"
    version = "1.0.0"
    title = "Preflight action against mandate"
    description = (
        "Check what the mandate gate would say about a proposed action — "
        "authorized, escalate, or refused — against the mandate's per-action "
        "and rolling-window money ceilings and its evidence-pinned "
        "guardrails. Advisory and read-only: no receipt is minted and no "
        "seal is verified here; the sealed gate (authorize_growth_action, "
        "host path) re-verifies everything before deciding. A guardrail "
        "that cannot be evaluated escalates — silence never authorizes."
    )
    input_model = PreflightActionInput
    output_model = MandateCheck
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "as_of": "2026-08-21T00:00:00Z",
        "mandate": _EXAMPLE_MANDATE,
        "action": _EXAMPLE_ACTION,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PreflightActionInput,
    ) -> PrimitiveExecutionResult[MandateCheck]:
        try:
            check = preflight_growth_action(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[MandateCheck](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Preflight {check.action_ref}: {check.predicted_verdict} "
                "(no receipt minted)."
            ),
            output=check,
            events=[
                PrimitiveEvent(
                    type="growth.action_preflighted",
                    payload={
                        "action_ref": check.action_ref,
                        "predicted_verdict": check.predicted_verdict,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Preflight bound to mandate "
                    + check.mandate_digest[:16]
                    + "…; advisory only, no receipt minted",
                )
            ],
        )


__all__ = [
    "ACTION_AUTHORIZATION_SCHEMA",
    "GROWTH_MANDATE_SCHEMA",
    "MANDATE_CHECK_SCHEMA",
    "ActionAuthorization",
    "AuthorizeActionInput",
    "EconomicsGuardrail",
    "GrantGrowthMandateInput",
    "GrowthMandate",
    "GrowthMandateValidationError",
    "GuardrailCheck",
    "MandateCheck",
    "MandateGrant",
    "MandateSpendSummary",
    "ObjectiveVerdictGuardrail",
    "PreflightActionInput",
    "PreflightActionPrimitive",
    "ProposedAction",
    "authorize_growth_action",
    "grant_growth_mandate",
    "preflight_growth_action",
    "summarize_mandate_spend",
    "verify_action_authorization",
    "verify_growth_mandate",
]
