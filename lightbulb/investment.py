"""Governed SDK facade for Lightbulb investment and trading workflows.

The facade keeps tenant and user scope inside the authenticated client, accepts
only registered investment actions, and adds a local acknowledgement gate for
provider spend, model promotion, broker orders, and cash movement. That gate is
defence in depth only: it never replaces server-side RBAC, approvals, risk
certificates, provider receipts, broker idempotency, or cash controls.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, Mapping

if TYPE_CHECKING:
    from lightbulb.async_client import AsyncLightbulbClient
    from lightbulb.client import DispatchResult, LightbulbClient


class InvestmentAction(str, Enum):
    """Registered finance actions that make up the investment agent system."""

    TRADING_AGENT = "investment_trading_agent"
    TRADING_SIGNAL = "investment_trading_signal"
    TRADING_MODEL_LIFECYCLE = "investment_trading_model_lifecycle"
    PORTFOLIO_BACKTEST = "investment_portfolio_backtest"
    FEATURE_ENGINEERING = "investment_feature_engineering"
    ALPHA_DISCOVERY = "investment_alpha_discovery"
    ALPHA_TRAINING_PIPELINE = "investment_alpha_training_pipeline"
    AGENT_CAPITAL_PORTFOLIO = "investment_agent_capital_portfolio"
    CAPITAL_COMPUTE_REBALANCE = "investment_capital_compute_rebalance"
    FINANCIAL_INTELLIGENCE_TEAM = "investment_financial_intelligence_team"
    TRADER_ORCHESTRATION_LOOP = "investment_trader_orchestration_loop"
    TRADE_EXECUTION_GATE = "investment_trade_execution_gate"
    TRADE_EXECUTION_RECONCILIATION = "investment_trade_execution_reconciliation"
    PAPER_TRADE_RUNBOOK = "investment_paper_trade_runbook"
    PAPER_OBSERVATION_PROGRAM = "investment_paper_observation_program"
    TRADING_SYSTEM_CANARY = "investment_trading_system_canary"
    BROKER_ACCOUNT_SNAPSHOT = "investment_broker_account_snapshot"
    MARKET_DATA_SNAPSHOT = "investment_market_data_snapshot"
    BROKER_READINESS_CHECK = "investment_broker_readiness_check"
    CASH_MOVEMENT_REQUEST = "investment_cash_movement_request"


class InvestmentEffect(str, Enum):
    """External effects acknowledged by the SDK caller, never authorized by it."""

    PROVIDER_SPEND = "provider_spend"
    MODEL_PROMOTION = "model_promotion"
    BROKER_EXECUTION = "broker_execution"
    CASH_MOVEMENT = "cash_movement"


@dataclass(frozen=True)
class InvestmentEffectIntent:
    """Explicit caller intent for effect-capable investment requests.

    These booleans only unlock the local SDK guard. The platform still requires
    its normal scoped approvals and runtime controls.
    """

    provider_spend: bool = False
    model_promotion: bool = False
    broker_execution: bool = False
    cash_movement: bool = False

    def __post_init__(self) -> None:
        for name in (
            "provider_spend",
            "model_promotion",
            "broker_execution",
            "cash_movement",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"Investment effect intent {name!r} must be a boolean")

    def permits(self, effect: InvestmentEffect) -> bool:
        return bool(getattr(self, effect.value))


class InvestmentSafetyError(ValueError):
    """Raised before an effect-capable request leaves the SDK process."""


_SAFE_DEFAULTS: Dict[InvestmentAction, Dict[str, bool]] = {
    InvestmentAction.TRADING_AGENT: {"execute": False},
    InvestmentAction.TRADING_SIGNAL: {"execute": False},
    InvestmentAction.TRADING_MODEL_LIFECYCLE: {"request_deployment": False},
    InvestmentAction.ALPHA_TRAINING_PIPELINE: {"execute_training": False},
    InvestmentAction.FINANCIAL_INTELLIGENCE_TEAM: {"execute_specialists": False},
    InvestmentAction.TRADER_ORCHESTRATION_LOOP: {
        "execute_specialists": False,
        "run_alpha_discovery": False,
    },
    InvestmentAction.TRADE_EXECUTION_GATE: {"execute": False},
    InvestmentAction.CASH_MOVEMENT_REQUEST: {"execute": False},
}

_CONDITIONAL_EFFECTS = (
    (InvestmentAction.TRADING_AGENT, "execute", InvestmentEffect.BROKER_EXECUTION),
    (InvestmentAction.TRADING_SIGNAL, "execute", InvestmentEffect.BROKER_EXECUTION),
    (
        InvestmentAction.TRADING_MODEL_LIFECYCLE,
        "request_deployment",
        InvestmentEffect.MODEL_PROMOTION,
    ),
    (
        InvestmentAction.ALPHA_TRAINING_PIPELINE,
        "execute_training",
        InvestmentEffect.PROVIDER_SPEND,
    ),
    (
        InvestmentAction.FINANCIAL_INTELLIGENCE_TEAM,
        "execute_specialists",
        InvestmentEffect.PROVIDER_SPEND,
    ),
    (
        InvestmentAction.TRADER_ORCHESTRATION_LOOP,
        "execute_specialists",
        InvestmentEffect.PROVIDER_SPEND,
    ),
    (
        InvestmentAction.TRADER_ORCHESTRATION_LOOP,
        "run_alpha_discovery",
        InvestmentEffect.PROVIDER_SPEND,
    ),
    (
        InvestmentAction.TRADE_EXECUTION_GATE,
        "execute",
        InvestmentEffect.BROKER_EXECUTION,
    ),
    (
        InvestmentAction.CASH_MOVEMENT_REQUEST,
        "execute",
        InvestmentEffect.CASH_MOVEMENT,
    ),
)


def _coerce_action(action: InvestmentAction | str) -> InvestmentAction:
    if isinstance(action, InvestmentAction):
        return action
    try:
        return InvestmentAction(str(action).strip())
    except ValueError as exc:
        raise ValueError(f"Unsupported investment action: {action!r}") from exc


def _boolean_flag(inputs: Mapping[str, Any], key: str) -> bool:
    if key not in inputs:
        return False
    value = inputs[key]
    if not isinstance(value, bool):
        raise InvestmentSafetyError(f"Investment effect flag {key!r} must be a boolean")
    return value


def _prepare_dispatch(
    action: InvestmentAction | str,
    inputs: Mapping[str, Any] | None,
    effect_intent: InvestmentEffectIntent | None,
) -> tuple[InvestmentAction, Dict[str, Any]]:
    resolved = _coerce_action(action)
    payload = dict(inputs or {})
    for key, value in _SAFE_DEFAULTS.get(resolved, {}).items():
        payload.setdefault(key, value)

    if resolved is InvestmentAction.TRADE_EXECUTION_GATE:
        legacy_live_fields = {
            "live_execution_authority",
            "live_execution_enabled",
        }.intersection(payload)
        if legacy_live_fields:
            raise InvestmentSafetyError(
                "Live execution does not trust caller-supplied authority or enablement flags; "
                "pass the persisted live_execution_authority_packet_id issued by Lightbulb."
            )

    if resolved is InvestmentAction.CASH_MOVEMENT_REQUEST and _boolean_flag(payload, "execute"):
        raise InvestmentSafetyError(
            "Programmatic cash_movement is not available to agents. Stage the request and "
            "complete the approved deposit or withdrawal in the broker-hosted flow."
        )

    required_effects: set[InvestmentEffect] = set()
    if resolved is InvestmentAction.PAPER_TRADE_RUNBOOK:
        required_effects.add(InvestmentEffect.BROKER_EXECUTION)
    for candidate_action, key, effect in _CONDITIONAL_EFFECTS:
        if resolved is candidate_action and _boolean_flag(payload, key):
            required_effects.add(effect)

    missing = sorted(
        effect.value
        for effect in required_effects
        if effect_intent is None or not effect_intent.permits(effect)
    )
    if missing:
        joined = ", ".join(missing)
        raise InvestmentSafetyError(
            f"Investment action {resolved.value!r} requests {joined}; pass an "
            "InvestmentEffectIntent that explicitly acknowledges each effect. "
            "This acknowledgement is not a platform approval."
        )
    return resolved, payload


def _force_false(inputs: Mapping[str, Any] | None, *keys: str) -> Dict[str, Any]:
    payload = dict(inputs or {})
    for key in keys:
        payload[key] = False
    return payload


@dataclass(frozen=True)
class InvestmentAgentClient:
    """Synchronous facade over the authenticated finance domain dispatcher."""

    inner: "LightbulbClient"

    def dispatch(
        self,
        action: InvestmentAction | str,
        *,
        inputs: Mapping[str, Any] | None = None,
        message: str = "",
        company_id: str | None = None,
        effect_intent: InvestmentEffectIntent | None = None,
    ) -> "DispatchResult":
        resolved, payload = _prepare_dispatch(action, inputs, effect_intent)
        return self.inner.dispatch(
            "finance",
            action=resolved.value,
            message=message,
            inputs=payload or None,
            company_id=company_id,
        )

    def feature_engineering(self, inputs: Mapping[str, Any], **kwargs: Any) -> "DispatchResult":
        return self.dispatch(InvestmentAction.FEATURE_ENGINEERING, inputs=inputs, **kwargs)

    def alpha_discovery(self, inputs: Mapping[str, Any], **kwargs: Any) -> "DispatchResult":
        return self.dispatch(InvestmentAction.ALPHA_DISCOVERY, inputs=inputs, **kwargs)

    def portfolio_backtest(self, inputs: Mapping[str, Any], **kwargs: Any) -> "DispatchResult":
        return self.dispatch(InvestmentAction.PORTFOLIO_BACKTEST, inputs=inputs, **kwargs)

    def plan_alpha_training(
        self, inputs: Mapping[str, Any] | None = None, **kwargs: Any
    ) -> "DispatchResult":
        return self.dispatch(
            InvestmentAction.ALPHA_TRAINING_PIPELINE,
            inputs=_force_false(inputs, "execute_training"),
            **kwargs,
        )

    def capital_compute_portfolio(
        self, inputs: Mapping[str, Any], **kwargs: Any
    ) -> "DispatchResult":
        return self.dispatch(InvestmentAction.AGENT_CAPITAL_PORTFOLIO, inputs=inputs, **kwargs)

    def trader_orchestration(
        self, inputs: Mapping[str, Any], **kwargs: Any
    ) -> "DispatchResult":
        return self.dispatch(InvestmentAction.TRADER_ORCHESTRATION_LOOP, inputs=inputs, **kwargs)

    def trading_system_canary(
        self, inputs: Mapping[str, Any] | None = None, **kwargs: Any
    ) -> "DispatchResult":
        return self.dispatch(InvestmentAction.TRADING_SYSTEM_CANARY, inputs=inputs, **kwargs)

    def broker_readiness(self, inputs: Mapping[str, Any], **kwargs: Any) -> "DispatchResult":
        return self.dispatch(InvestmentAction.BROKER_READINESS_CHECK, inputs=inputs, **kwargs)

    def broker_account_snapshot(
        self, inputs: Mapping[str, Any], **kwargs: Any
    ) -> "DispatchResult":
        return self.dispatch(InvestmentAction.BROKER_ACCOUNT_SNAPSHOT, inputs=inputs, **kwargs)

    def market_data_snapshot(
        self, inputs: Mapping[str, Any], **kwargs: Any
    ) -> "DispatchResult":
        return self.dispatch(InvestmentAction.MARKET_DATA_SNAPSHOT, inputs=inputs, **kwargs)

    def stage_cash_movement(
        self, inputs: Mapping[str, Any], **kwargs: Any
    ) -> "DispatchResult":
        return self.dispatch(
            InvestmentAction.CASH_MOVEMENT_REQUEST,
            inputs=_force_false(inputs, "execute"),
            **kwargs,
        )

    def paper_trade_runbook(
        self,
        inputs: Mapping[str, Any],
        *,
        effect_intent: InvestmentEffectIntent,
        **kwargs: Any,
    ) -> "DispatchResult":
        return self.dispatch(
            InvestmentAction.PAPER_TRADE_RUNBOOK,
            inputs=inputs,
            effect_intent=effect_intent,
            **kwargs,
        )


@dataclass(frozen=True)
class AsyncInvestmentAgentClient:
    """Native-async facade over the authenticated finance domain dispatcher."""

    inner: "AsyncLightbulbClient"

    async def dispatch(
        self,
        action: InvestmentAction | str,
        *,
        inputs: Mapping[str, Any] | None = None,
        message: str = "",
        company_id: str | None = None,
        effect_intent: InvestmentEffectIntent | None = None,
    ) -> "DispatchResult":
        resolved, payload = _prepare_dispatch(action, inputs, effect_intent)
        return await self.inner.dispatch(
            "finance",
            action=resolved.value,
            message=message,
            inputs=payload or None,
            company_id=company_id,
        )

    async def feature_engineering(self, inputs: Mapping[str, Any], **kwargs: Any) -> "DispatchResult":
        return await self.dispatch(InvestmentAction.FEATURE_ENGINEERING, inputs=inputs, **kwargs)

    async def alpha_discovery(self, inputs: Mapping[str, Any], **kwargs: Any) -> "DispatchResult":
        return await self.dispatch(InvestmentAction.ALPHA_DISCOVERY, inputs=inputs, **kwargs)

    async def portfolio_backtest(self, inputs: Mapping[str, Any], **kwargs: Any) -> "DispatchResult":
        return await self.dispatch(InvestmentAction.PORTFOLIO_BACKTEST, inputs=inputs, **kwargs)

    async def plan_alpha_training(
        self, inputs: Mapping[str, Any] | None = None, **kwargs: Any
    ) -> "DispatchResult":
        return await self.dispatch(
            InvestmentAction.ALPHA_TRAINING_PIPELINE,
            inputs=_force_false(inputs, "execute_training"),
            **kwargs,
        )

    async def capital_compute_portfolio(
        self, inputs: Mapping[str, Any], **kwargs: Any
    ) -> "DispatchResult":
        return await self.dispatch(InvestmentAction.AGENT_CAPITAL_PORTFOLIO, inputs=inputs, **kwargs)

    async def trader_orchestration(
        self, inputs: Mapping[str, Any], **kwargs: Any
    ) -> "DispatchResult":
        return await self.dispatch(InvestmentAction.TRADER_ORCHESTRATION_LOOP, inputs=inputs, **kwargs)

    async def trading_system_canary(
        self, inputs: Mapping[str, Any] | None = None, **kwargs: Any
    ) -> "DispatchResult":
        return await self.dispatch(InvestmentAction.TRADING_SYSTEM_CANARY, inputs=inputs, **kwargs)

    async def broker_readiness(self, inputs: Mapping[str, Any], **kwargs: Any) -> "DispatchResult":
        return await self.dispatch(InvestmentAction.BROKER_READINESS_CHECK, inputs=inputs, **kwargs)

    async def broker_account_snapshot(
        self, inputs: Mapping[str, Any], **kwargs: Any
    ) -> "DispatchResult":
        return await self.dispatch(InvestmentAction.BROKER_ACCOUNT_SNAPSHOT, inputs=inputs, **kwargs)

    async def market_data_snapshot(
        self, inputs: Mapping[str, Any], **kwargs: Any
    ) -> "DispatchResult":
        return await self.dispatch(InvestmentAction.MARKET_DATA_SNAPSHOT, inputs=inputs, **kwargs)

    async def stage_cash_movement(
        self, inputs: Mapping[str, Any], **kwargs: Any
    ) -> "DispatchResult":
        return await self.dispatch(
            InvestmentAction.CASH_MOVEMENT_REQUEST,
            inputs=_force_false(inputs, "execute"),
            **kwargs,
        )

    async def paper_trade_runbook(
        self,
        inputs: Mapping[str, Any],
        *,
        effect_intent: InvestmentEffectIntent,
        **kwargs: Any,
    ) -> "DispatchResult":
        return await self.dispatch(
            InvestmentAction.PAPER_TRADE_RUNBOOK,
            inputs=inputs,
            effect_intent=effect_intent,
            **kwargs,
        )


__all__ = [
    "AsyncInvestmentAgentClient",
    "InvestmentAction",
    "InvestmentAgentClient",
    "InvestmentEffect",
    "InvestmentEffectIntent",
    "InvestmentSafetyError",
]
