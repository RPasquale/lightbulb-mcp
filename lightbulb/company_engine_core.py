"""Shared core for the company engine packs (growth, pipeline, SaaS operating, company OS).

Every engine pack in this family shares one contract:

* strict, frozen, portable models that refuse credential-, bank-, and
  identity-like keys and values at the boundary;
* sealed payloads whose ``*_digest`` commits the exact normalized content;
* replay-fenced lifecycles: sealed commands carry a transition reference, an
  idempotency key, the expected revision and state digest, and an occurrence
  time; every transition is self-proving and the state's ledger is re-derived
  from history whenever the loop plan is supplied in validation context;
* effect boundaries stating that nothing here moved money, published
  anything, sent anything, or persisted anything.  Spring authorizes effects
  and the Connector Runtime executes them.

The SDK never accepts tenant, company, or user identifiers, credentials, raw
sessions, or model-minted authority through these models.
"""

from __future__ import annotations

import hashlib
import json
import re
from contextvars import ContextVar
from copy import deepcopy
from functools import wraps
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationInfo, field_validator, model_validator

GENESIS_DIGEST = "0" * 64
MONEY_QUANTUM = Decimal("0.01")
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SECRET_LIKE_KEYS = (
    "secret", "password", "passwd", "token", "api_key", "apikey", "authorization", "credential", "private_key",
    "client_secret", "tenant_id", "company_id", "user_id", "card_number", "cvc", "iban", "routing_number",
    "date_of_birth", "national_id", "passport", "access_key", "refresh_key",
)
_SECRET_LIKE_VALUES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"(?<![0-9A-Za-z-])\d{13,19}(?![0-9A-Za-z-])"),
)

OpaqueRef = Annotated[str, StringConstraints(pattern=_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=300)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=4000)]
CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]
RecoveryDisposition = Literal["not_required", "do_not_replay", "refresh_state", "correct_input", "manual_reconciliation", "await_approval"]
SKIP_CONTEXT_KEY = "skip_company_engine_digests"


# --------------------------------------------------------------------------- #
# Boundary guards and strict models
# --------------------------------------------------------------------------- #


def reject_secret_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, str):
        if any(pattern.search(value) for pattern in _SECRET_LIKE_VALUES):
            raise ValueError(f"{path} carries a secret-like, card-like, or identity-like value and is never accepted")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            proof_field = lowered in {"authorization_proof", "pricing_authorization_proof"} and (item is None or isinstance(item, Mapping) and item.get("schema") == "lightbulb.company_authorization_proof.v1")
            proof_digest = lowered == "authorization_proof_digest" and (item is None or isinstance(item, str) and re.fullmatch(_SHA256_PATTERN, item) is not None)
            channel_status = lowered == "authorization_status" and value.get("schema") == "lightbulb.commercial_channel_authorization_snapshot.v1" and item in ("not_applicable", "authorized", "conditional", "unauthorized", "suspended", "expired", "unknown")
            # Native inference billing counters are numeric usage, never credential strings.
            usage_counter = lowered in {"uncached_input_tokens", "cache_write_tokens", "cache_read_tokens", "output_tokens"} and type(item) is int and 0 <= item <= 10**15
            usage_kind = lowered == "token_type" and isinstance(item, str) and item in {"uncached_input", "cache_write", "cache_read", "output", "tool_use", "other"}
            if not (proof_field or proof_digest or channel_status or usage_counter or usage_kind) and any(marker in lowered for marker in _SECRET_LIKE_KEYS):
                raise ValueError(f"{path}.{key} is a credential-, bank-, or personal-identity field and is never accepted")
            if key in {"PaymentDate", "Date", "PayRunPeriodStartDate", "PayRunPeriodEndDate", "StartDate", "EndDate"} and isinstance(item, str):
                provider_date = re.fullmatch(r"/Date\(([0-9]{13})(?:[+-][0-9]{4})?\)/", item)
                if provider_date is not None and datetime(2000, 1, 1, tzinfo=timezone.utc).timestamp() * 1000 <= int(provider_date[1]) <= datetime(2200, 1, 1, tzinfo=timezone.utc).timestamp() * 1000:
                    continue
            reject_secret_like_payload(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            reject_secret_like_payload(item, path=f"{path}[{index}]")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True, revalidate_instances="always", serialize_by_alias=True, strict=True)

    @model_validator(mode="before")
    @classmethod
    def _portable_payload(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if not isinstance(value, Mapping):
            return value
        reject_secret_like_payload(value)
        return {str(key): (tuple(item) if isinstance(item, list) else item) for key, item in value.items()}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def detached(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {str(key): detached(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [detached(item) for item in value]
    return value


def timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field_name} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed_value = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 UTC timestamp ending in Z") from exc
    return parsed_value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parsed(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def add_days(value: str, days: int) -> str:
    return iso(parsed(value) + timedelta(days=days))


def decimal_value(value: Any, *, field_name: str, allow_negative: bool = False) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{field_name} must be a decimal string, integer, or Decimal")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a decimal") from exc
    if not result.is_finite() or (result < 0 and not allow_negative) or abs(result) > Decimal("1000000000000"):
        raise ValueError(f"{field_name} must be a finite {'bounded' if allow_negative else 'non-negative bounded'} decimal")
    return result.quantize(MONEY_QUANTUM)


def percent_value(value: Any, *, field_name: str) -> Decimal:
    result = decimal_value(value, field_name=field_name)
    if result > 100:
        raise ValueError(f"{field_name} must be between 0 and 100")
    return result


def pct(amount: Decimal, percent: Decimal) -> Decimal:
    return (amount * percent / Decimal(100)).quantize(MONEY_QUANTUM)


def ratio_percent(numerator: Decimal | int, denominator: Decimal | int) -> Decimal | None:
    if Decimal(denominator) == 0:
        return None
    return (Decimal(numerator) * 100 / Decimal(denominator)).quantize(MONEY_QUANTUM)


def stable_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def skip_digests(info: ValidationInfo) -> bool:
    return bool((info.context or {}).get(SKIP_CONTEXT_KEY))


def sealed_digest(model: type[StrictModel], payload: Any, field: str) -> str:
    raw = dict(detached(payload))
    raw.setdefault(field, GENESIS_DIGEST)
    parsed_model = model.model_validate(raw, context={SKIP_CONTEXT_KEY: True})
    return stable_digest({key: value for key, value in parsed_model.to_dict().items() if key != field})


def seal(model: type[StrictModel], payload: Mapping[str, Any], field: str) -> Any:
    raw = dict(detached(payload))
    raw[field] = sealed_digest(model, raw, field)
    return model.model_validate(raw)


def unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def canonical_uuid(value: str, *, field_name: str = "project_id") -> str:
    from uuid import UUID

    try:
        parsed_uuid = UUID(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a canonical UUID") from exc
    if str(parsed_uuid) != value:
        raise ValueError(f"{field_name} must be a canonical UUID")
    return value


class EngineScope(StrictModel):
    """Opaque scope aliases only: never tenant, company, or user identifiers."""

    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str
    entity_ref: OpaqueRef
    currency: CurrencyCode = "USD"

    @field_validator("project_id")
    @classmethod
    def _project_id(cls, value: str) -> str:
        return canonical_uuid(value)


def same_scope(scope: EngineScope, other: EngineScope) -> bool:
    return (scope.tenant_ref, scope.company_ref, scope.project_ref, scope.project_id, scope.currency) == (other.tenant_ref, other.company_ref, other.project_ref, other.project_id, other.currency)


# --------------------------------------------------------------------------- #
# Replay-fenced lifecycle engine
# --------------------------------------------------------------------------- #


class Rejected(ValueError):
    """A transition that cannot be applied; carries a code and a recovery disposition."""

    def __init__(self, code: str, instructions: str, recovery: RecoveryDisposition = "correct_input") -> None:
        super().__init__(instructions)
        self.code, self.instructions, self.recovery = code, instructions, recovery


def require(condition: bool, code: str, instructions: str, recovery: RecoveryDisposition = "correct_input") -> None:
    if not condition:
        raise Rejected(code, instructions, recovery)


class Recovery(StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: BoundedText | None = None

    @model_validator(mode="after")
    def _bounded(self) -> "Recovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match the disposition")
        return self


_REPLAY_MEMO: ContextVar[dict[Any, Any] | None] = ContextVar("company_replay_memo", default=None)


def _replay_session(function: Callable[..., Any]) -> Callable[..., Any]:
    """Share successful nested proof replays only within one synchronous operation."""
    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if _REPLAY_MEMO.get() is not None:
            return function(*args, **kwargs)
        token = _REPLAY_MEMO.set({})
        try:
            return function(*args, **kwargs)
        finally:
            _REPLAY_MEMO.reset(token)
    return wrapped


class LifecycleSpec:
    """Declarative lifecycle: statuses, events, transition table, and the apply rule.

    ``apply(plan, status, ledger_dict, command) -> (next_status, ledger_dict)`` is
    given the table's next status and may override it; it raises ``Rejected``
    for guard failures.  ``opening_events`` map the opening event to the
    pseudo-status ``"new"`` in the table.
    """

    def __init__(
        self,
        *,
        entity: str,
        schema_prefix: str,
        statuses: Sequence[str],
        terminal: Sequence[str],
        events: Sequence[str],
        table: Mapping[tuple[str, str], str],
        opening_event: str,
        reason_events: Sequence[str],
        apply: Callable[[Any, str, str, dict[str, Any], Any], tuple[str, dict[str, Any]]],
        ledger_model: type[StrictModel],
        receipt_model: type[StrictModel],
        effect_boundary_model: type[StrictModel],
        plan_model: type[StrictModel],
        max_transitions: int = 120,
    ) -> None:
        self.entity = entity
        self.schema_prefix = schema_prefix
        self.statuses = frozenset(statuses)
        self.terminal = frozenset(terminal)
        self.events = frozenset(events)
        self.table = dict(table)
        self.opening_event = opening_event
        self.reason_events = frozenset(reason_events)
        self.apply = apply
        self.ledger_model = ledger_model
        self.receipt_model = receipt_model
        self.effect_boundary_model = effect_boundary_model
        self.plan_model = plan_model
        self.max_transitions = max_transitions
        self.plan_context_key = f"{schema_prefix}_plan"
        if ("new", opening_event) not in self.table:
            raise ValueError("the transition table must map ('new', opening_event)")
        self._build_models()

    # -- model construction ------------------------------------------------ #

    def _build_models(self) -> None:
        spec = self
        receipt_model, ledger_model = self.receipt_model, self.ledger_model
        command_schema = f"lightbulb.{self.schema_prefix}_command.v1"
        state_schema = f"lightbulb.{self.schema_prefix}_state.v1"
        result_schema = f"lightbulb.{self.schema_prefix}_transition_result.v1"

        class Command(StrictModel):
            schema_id: str = Field(default=command_schema, alias="schema")
            event: str
            transition_ref: OpaqueRef
            idempotency_key: OpaqueRef
            expected_version: int = Field(ge=0, le=spec.max_transitions)
            expected_state_digest: Sha256Digest
            occurred_at: str
            actor_ref: OpaqueRef
            receipt: receipt_model = Field(default_factory=receipt_model)  # type: ignore[valid-type]
            reason: BoundedText | None = None
            request_digest: Sha256Digest = GENESIS_DIGEST

            @field_validator("schema_id")
            @classmethod
            def _schema(cls, value: str) -> str:
                if value != command_schema:
                    raise ValueError(f"schema must be {command_schema}")
                return value

            @field_validator("occurred_at")
            @classmethod
            def _occurred(cls, value: str) -> str:
                return timestamp(value, field_name="occurred_at")

            @model_validator(mode="after")
            def _command_is_exact(self, info: ValidationInfo) -> "Command":
                if self.event not in spec.events:
                    raise ValueError(f"{self.event} is not a {spec.entity} event")
                if self.event in spec.reason_events and self.reason is None:
                    raise ValueError(f"{self.event} requires a reason")
                if skip_digests(info):
                    return self
                if self.request_digest != sealed_digest(Command, self, "request_digest"):
                    raise ValueError("request_digest must commit the exact normalized command")
                return self

        class Transition(StrictModel):
            to_version: int = Field(ge=1, le=spec.max_transitions)
            prior_state_digest: Sha256Digest
            to_status: str
            transition_digest: Sha256Digest
            command: Command

            @model_validator(mode="after")
            def _self_proving(self) -> "Transition":
                if self.to_status not in spec.statuses:
                    raise ValueError(f"{self.to_status} is not a {spec.entity} status")
                if self.command.expected_version != self.to_version - 1 or self.command.expected_state_digest != self.prior_state_digest:
                    raise ValueError("transition must match the command's revision and state fences")
                if self.transition_digest != spec.transition_digest(self.to_version, self.prior_state_digest, self.to_status, self.command):
                    raise ValueError("transition digest must commit the exact transition")
                return self

        class State(StrictModel):
            schema_id: str = Field(default=state_schema, alias="schema")
            entity: str = spec.entity
            plan_digest: Sha256Digest
            scope: EngineScope
            status: str
            version: int = Field(ge=1, le=spec.max_transitions)
            transition_history: tuple[Transition, ...] = Field(min_length=1, max_length=spec.max_transitions)
            ledger: ledger_model  # type: ignore[valid-type]
            state_digest: Sha256Digest

            @field_validator("schema_id")
            @classmethod
            def _schema(cls, value: str) -> str:
                if value != state_schema:
                    raise ValueError(f"schema must be {state_schema}")
                return value

            @field_validator("entity")
            @classmethod
            def _entity(cls, value: str) -> str:
                if value != spec.entity:
                    raise ValueError(f"entity must be {spec.entity}")
                return value

            @model_validator(mode="after")
            @_replay_session
            def _state_is_exact(self, info: ValidationInfo) -> "State":
                history = self.transition_history
                if self.status not in spec.statuses:
                    raise ValueError(f"{self.status} is not a {spec.entity} status")
                if self.version != len(history) or [item.to_version for item in history] != list(range(1, self.version + 1)):
                    raise ValueError("version must equal a contiguous transition history")
                if history[0].command.event != spec.opening_event:
                    raise ValueError(f"history must open with {spec.opening_event}")
                if self.status != history[-1].to_status:
                    raise ValueError("status must equal the last retained transition status")
                for field_name in ("transition_ref", "idempotency_key", "request_digest"):
                    unique([str(getattr(item.command, field_name)) for item in history], label=f"historical {field_name} values")
                prefix: tuple[Any, ...] = ()
                for transition in history:
                    if transition.prior_state_digest != spec.state_digest(self.plan_digest, self.scope, prefix):
                        raise ValueError("historical transition has a discontinuous state digest")
                    prefix = (*prefix, transition)
                if self.state_digest != spec.state_digest(self.plan_digest, self.scope, history):
                    raise ValueError("state_digest must commit the exact state")
                plan = (info.context or {}).get(spec.plan_context_key)
                if plan is not None:
                    if plan.plan_digest != self.plan_digest:
                        raise ValueError(f"{spec.entity} belongs to a different loop plan")
                    status, ledger = "new", ledger_model()
                    for transition in history:
                        try:
                            status, ledger = spec.step(plan, status, ledger, transition.command)
                        except Rejected as exc:
                            raise ValueError(f"historical transition {transition.to_version} is invalid: {exc.code}") from exc
                        if status != transition.to_status:
                            raise ValueError("historical transition status does not match the transition table")
                    if self.status != status or self.ledger != ledger:
                        raise ValueError("status and ledger must be derived from history")
                return self

        class TransitionReceipt(StrictModel):
            entity: str = spec.entity
            transition_ref: OpaqueRef
            idempotency_key: OpaqueRef
            request_digest: Sha256Digest
            event: str
            status: Literal["candidate_materialized", "rejected"]
            from_version: int = Field(ge=0)
            to_version: int = Field(ge=0)
            from_status: str
            to_status: str
            from_state_digest: Sha256Digest
            to_state_digest: Sha256Digest
            rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
            recovery: Recovery

        class TransitionResult(StrictModel):
            schema_id: str = Field(default=result_schema, alias="schema")
            candidate_validated: bool
            state: State | None = None
            receipt: TransitionReceipt
            effect_boundary: spec.effect_boundary_model = Field(default_factory=spec.effect_boundary_model)  # type: ignore[valid-type]

            @field_validator("schema_id")
            @classmethod
            def _schema(cls, value: str) -> str:
                if value != result_schema:
                    raise ValueError(f"schema must be {result_schema}")
                return value

            @model_validator(mode="after")
            def _coherent(self) -> "TransitionResult":
                if self.candidate_validated != (self.receipt.status == "candidate_materialized") or (self.candidate_validated and self.state is None):
                    raise ValueError("result must carry a state exactly when a candidate was materialized")
                return self

        Command.__name__ = f"{self.entity.title().replace('_', '')}Command"
        State.__name__ = f"{self.entity.title().replace('_', '')}State"
        Transition.__name__ = f"{self.entity.title().replace('_', '')}Transition"
        TransitionResult.__name__ = f"{self.entity.title().replace('_', '')}TransitionResult"
        self.Command, self.Transition, self.State, self.TransitionReceipt, self.TransitionResult = Command, Transition, State, TransitionReceipt, TransitionResult

    # -- digests ------------------------------------------------------------- #

    def transition_digest(self, to_version: int, prior: str, to_status: str, command: Any) -> str:
        return stable_digest({"to_version": to_version, "prior_state_digest": prior, "to_status": to_status, "request_digest": command.request_digest, "transition_ref": command.transition_ref, "idempotency_key": command.idempotency_key})

    def state_digest(self, plan_digest: str, scope: EngineScope, history: Sequence[Any]) -> str:
        return stable_digest({"plan_digest": plan_digest, "entity": self.entity, "scope": scope.to_dict(), "transitions": [item.transition_digest for item in history]})

    def command_digest(self, command: Mapping[str, Any] | Any) -> str:
        return sealed_digest(self.Command, command, "request_digest")

    def seal_command(self, command: Mapping[str, Any]) -> dict[str, Any]:
        raw = dict(detached(command))
        raw["request_digest"] = self.command_digest(raw)
        return self.Command.model_validate(raw).to_dict()

    # -- stepping ------------------------------------------------------------ #

    def step(self, plan: Any, status: str, ledger: Any, command: Any) -> tuple[str, Any]:
        if status in self.terminal:
            raise Rejected(f"{self.entity.upper()}_TERMINAL", f"{self.entity} is {status}; no further transitions", "do_not_replay")
        next_status = self.table.get((status, command.event))
        if next_status is None:
            raise Rejected("ILLEGAL_TRANSITION", f"{command.event} is not a legal {self.entity} transition from {status}", "correct_input")
        data = ledger.to_dict()
        next_status, data = self.apply(plan, next_status, status, data, command)
        return next_status, self.ledger_model.model_validate({key: value for key, value in data.items() if value is not None})

    @_replay_session
    def bind(self, plan: Mapping[str, Any] | Any, state: Mapping[str, Any] | Any) -> tuple[Any, Any]:
        raw_plan, raw_state = detached(plan), detached(state)
        # A state digest excludes the ledger: it is never a sufficient cache key.
        # Commit every input field, and isolate both stored and returned models.
        try:
            canonical = json.dumps({"plan": raw_plan, "state": raw_state}, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        except (TypeError, ValueError):
            # Stringifying an arbitrary Python object can collide with a valid
            # wire string and bypass its strict validation on a warm cache.
            canonical = None
        memo = _REPLAY_MEMO.get()
        key = None if canonical is None else (id(self), hashlib.sha256(canonical.encode("utf-8")).hexdigest())
        if memo is not None and key is not None and key in memo:
            return deepcopy(memo[key])
        parsed_plan = self.plan_model.model_validate(raw_plan)
        unbound = self.State.model_validate(raw_state)
        if unbound.plan_digest != parsed_plan.plan_digest:
            raise ValueError(f"{self.entity} belongs to a different loop plan")
        bound = self.State.model_validate(unbound.to_dict(), context={self.plan_context_key: parsed_plan})
        if memo is not None and key is not None and len(memo) < 32 and len(canonical) <= 2_000_000:
            memo[key] = deepcopy((parsed_plan, bound))
        return parsed_plan, bound

    @_replay_session
    def open(self, plan: Mapping[str, Any] | Any, scope: Mapping[str, Any] | EngineScope, *, opened_at: str, actor_ref: str, receipt: Mapping[str, Any] | None = None, reason: str | None = None) -> Any:
        parsed_plan = self.plan_model.model_validate(detached(plan))
        parsed_scope = EngineScope.model_validate(detached(scope))
        blueprint_currency = getattr(getattr(parsed_plan, "blueprint", None), "currency", None) or getattr(parsed_plan, "currency", None)
        if blueprint_currency is not None and parsed_scope.currency != blueprint_currency:
            raise ValueError("scope currency must match the blueprint currency")
        genesis = self.state_digest(parsed_plan.plan_digest, parsed_scope, ())
        command = self.Command.model_validate(self.seal_command({"event": self.opening_event, "transition_ref": f"{self.opening_event}:{parsed_scope.entity_ref}", "idempotency_key": f"{parsed_scope.entity_ref}:{self.opening_event}", "expected_version": 0, "expected_state_digest": genesis, "occurred_at": opened_at, "actor_ref": actor_ref, "receipt": detached(receipt or {}), "reason": reason}))
        try:
            status, ledger = self.step(parsed_plan, "new", self.ledger_model(), command)
        except Rejected as exc:
            raise ValueError(f"{exc.code}: {exc.instructions}") from exc
        transition = self.Transition(to_version=1, prior_state_digest=genesis, to_status=status, transition_digest=self.transition_digest(1, genesis, status, command), command=command)
        return self.State.model_validate({"plan_digest": parsed_plan.plan_digest, "scope": parsed_scope.to_dict(), "status": status, "version": 1, "transition_history": [transition.to_dict()], "ledger": ledger.to_dict(), "state_digest": self.state_digest(parsed_plan.plan_digest, parsed_scope, (transition,))}, context={self.plan_context_key: parsed_plan})

    @_replay_session
    def advance(self, plan: Mapping[str, Any] | Any, state: Mapping[str, Any] | Any, command: Mapping[str, Any] | Any) -> Any:
        parsed_plan, parsed_state = self.bind(plan, state)
        parsed_command = self.Command.model_validate(detached(command))
        from_version, from_status, from_digest = parsed_state.version, parsed_state.status, parsed_state.state_digest

        def rejected(exc: Rejected) -> Any:
            receipt = self.TransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="rejected", from_version=from_version, to_version=from_version, from_status=from_status, to_status=from_status, from_state_digest=from_digest, to_state_digest=from_digest, rejection_code=exc.code, recovery=Recovery(disposition=exc.recovery, instructions=exc.instructions))
            return self.TransitionResult(candidate_validated=False, receipt=receipt)

        try:
            for prior in parsed_state.transition_history:
                if prior.command.request_digest == parsed_command.request_digest:
                    raise Rejected("TRANSITION_ALREADY_APPLIED", "this exact transition is already retained; duplicate delivery ignored", "do_not_replay")
                if prior.command.transition_ref == parsed_command.transition_ref or prior.command.idempotency_key == parsed_command.idempotency_key:
                    raise Rejected("IDEMPOTENCY_CONFLICT", "a different transition already used this reference or idempotency key", "manual_reconciliation")
            if parsed_command.expected_version != from_version or parsed_command.expected_state_digest != from_digest:
                raise Rejected("STALE_STATE", "revision or state fence does not match; refresh and retry with the current state", "refresh_state")
            if parsed(parsed_command.occurred_at) < parsed(parsed_state.transition_history[-1].command.occurred_at):
                raise Rejected("NON_CHRONOLOGICAL_TRANSITION", "transition precedes the last retained transition", "correct_input")
            if from_version >= self.max_transitions:
                raise Rejected("TRANSITION_BOUND_REACHED", f"the {self.entity} reached its bounded transition count", "manual_reconciliation")
            next_status, ledger = self.step(parsed_plan, from_status, parsed_state.ledger, parsed_command)
        except Rejected as exc:
            return rejected(exc)
        transition = self.Transition(to_version=from_version + 1, prior_state_digest=from_digest, to_status=next_status, transition_digest=self.transition_digest(from_version + 1, from_digest, next_status, parsed_command), command=parsed_command)
        history = (*parsed_state.transition_history, transition)
        new_state = self.State.model_validate({"plan_digest": parsed_state.plan_digest, "scope": parsed_state.scope.to_dict(), "status": next_status, "version": from_version + 1, "transition_history": [item.to_dict() for item in history], "ledger": ledger.to_dict(), "state_digest": self.state_digest(parsed_state.plan_digest, parsed_state.scope, history)}, context={self.plan_context_key: parsed_plan})
        receipt = self.TransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="candidate_materialized", from_version=from_version, to_version=new_state.version, from_status=from_status, to_status=next_status, from_state_digest=from_digest, to_state_digest=new_state.state_digest, recovery=Recovery(disposition="not_required"))
        return self.TransitionResult(candidate_validated=True, state=new_state, receipt=receipt)


__all__ = [
    "GENESIS_DIGEST",
    "MONEY_QUANTUM",
    "SKIP_CONTEXT_KEY",
    "BoundedText",
    "CurrencyCode",
    "EngineScope",
    "LifecycleSpec",
    "OpaqueRef",
    "Recovery",
    "RecoveryDisposition",
    "Rejected",
    "Sha256Digest",
    "ShortText",
    "StrictModel",
    "add_days",
    "canonical_uuid",
    "decimal_value",
    "detached",
    "iso",
    "parsed",
    "pct",
    "percent_value",
    "ratio_percent",
    "reject_secret_like_payload",
    "require",
    "same_scope",
    "seal",
    "sealed_digest",
    "skip_digests",
    "stable_digest",
    "timestamp",
    "unique",
]
