"""Typed client for the Stripe Orchestration Agent.

Wraps the orchestrator's HTTP surface so external code (your own scripts,
LangChain tools, OpenAI Agents SDK skills) can drive the orchestrator
without rebuilding the request/response shapes from scratch.

Two ways to use:

    >>> from lightbulb import LightbulbClient
    >>> from lightbulb.stripe import StripeOrchestratorClient
    >>> stripe = StripeOrchestratorClient(LightbulbClient(api_key="..."))
    >>> stripe.dispatch("customers", "list", {"limit": 10})

Or directly via the convenience helpers — they all route through
``LightbulbClient.invoke_tool`` so existing auth / retry / logging applies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from .client import LightbulbClient


__all__ = [
    "StripeOrchestratorClient",
    "StripeWorkflow",
]


class StripeWorkflow:
    """Names of the high-level composite workflows the orchestrator exposes."""

    FAILED_PAYMENT_RECOVERY = "workflow.failed_payment_recovery"
    CHURN_SAVE_OUTREACH = "workflow.churn_save_outreach"
    DISPUTE_EVIDENCE_DRAFTING = "workflow.dispute_evidence_drafting"
    SUBSCRIPTION_HEALTH_AUDIT = "workflow.subscription_health_audit"

    @classmethod
    def all(cls) -> List[str]:
        return [
            cls.FAILED_PAYMENT_RECOVERY,
            cls.CHURN_SAVE_OUTREACH,
            cls.DISPUTE_EVIDENCE_DRAFTING,
            cls.SUBSCRIPTION_HEALTH_AUDIT,
        ]


@dataclass
class StripeOrchestratorClient:
    """Thin wrapper over LightbulbClient that drives the Stripe orchestration
    agent through the platform's standard tool-invocation surface."""

    inner: LightbulbClient

    # ── Generic resource dispatch ─────────────────────────────────────

    def dispatch(
        self,
        resource: str,
        verb: str,
        op_inputs: Optional[Dict[str, Any]] = None,
        *,
        stripe_account_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send any (resource, verb) combination through the orchestrator.

        Examples:
            >>> sd.dispatch("customers", "list", {"limit": 25})
            >>> sd.dispatch("refunds", "create", {"charge": "ch_...", "amount": 500})
        """
        args: Dict[str, Any] = {
            "resource": resource,
            "verb": verb,
            "inputs": op_inputs or {},
        }
        if stripe_account_id:
            args["stripe_account_id"] = stripe_account_id
        return self.inner.invoke_tool("stripe.dispatch", args)

    # ── Convenience: per-resource shortcuts ────────────────────────────

    def list_customers(self, **filters: Any) -> Dict[str, Any]:
        return self.dispatch("customers", "list", filters)

    def list_subscriptions(self, **filters: Any) -> Dict[str, Any]:
        return self.dispatch("subscriptions", "list", filters)

    def retrieve_charge(self, charge_id: str) -> Dict[str, Any]:
        return self.dispatch("charges", "retrieve", {"charge_id": charge_id})

    def create_refund(self, charge_id: str, amount: int, **extra: Any) -> Dict[str, Any]:
        return self.dispatch("refunds", "create", {
            "charge": charge_id,
            "amount": amount,
            **extra,
        })

    def raw_api_request(
        self,
        api_path: str,
        *,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        stripe_account_id: Optional[str] = None,
        base_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Governed long-tail Stripe API request.

        The backend only accepts Stripe API paths beginning with ``/v1/`` or
        ``/v2/`` and routes non-GET calls through the normal simulator, audit,
        idempotency, and HITL approval path.
        """
        inputs: Dict[str, Any] = {
            "api_path": api_path,
            "method": method,
            "params": params or {},
        }
        if base_address:
            inputs["base_address"] = base_address
        return self.dispatch(
            "api",
            "request",
            inputs,
            stripe_account_id=stripe_account_id,
        )

    # ── Twin (fast Postgres-backed reads) ─────────────────────────────

    def twin_list(self, resource_kind: str, *, limit: int = 50) -> Dict[str, Any]:
        return self.inner.invoke_tool("stripe.twin.list", {
            "resource_kind": resource_kind,
            "limit": limit,
        })

    def twin_retrieve(self, *, stripe_account_id: str, resource_kind: str,
                       external_id: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("stripe.twin.retrieve", {
            "stripe_account_id": stripe_account_id,
            "resource_kind": resource_kind,
            "external_id": external_id,
        })

    # ── Approvals (mission-control feed) ──────────────────────────────

    def list_pending_approvals(self) -> Dict[str, Any]:
        return self.inner.invoke_tool("stripe.approvals.list_pending", {})

    def approve(self, approval_id: str, **extra: Any) -> Dict[str, Any]:
        return self.inner.invoke_tool("stripe.approvals.approve", {
            "approval_id": approval_id,
            **extra,
        })

    def reject(self, approval_id: str, reason: str = "") -> Dict[str, Any]:
        return self.inner.invoke_tool("stripe.approvals.reject", {
            "approval_id": approval_id,
            "reason": reason,
        })

    def execute(self, approval_id: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("stripe.approvals.execute", {
            "approval_id": approval_id,
        })

    # ── Analytic surfaces (Pillars 5 / 8 / 10) ───────────────────────

    def forecast_snapshot(self) -> Dict[str, Any]:
        return self.inner.invoke_tool("stripe.forecasts.snapshot", {})

    def account_health(self) -> Dict[str, Any]:
        return self.inner.invoke_tool("stripe.connect.account_health", {})

    def run_preference_learner(self) -> Dict[str, Any]:
        return self.inner.invoke_tool("stripe.preferences.run_learner", {})

    # ── Workflows (Phase 7) ───────────────────────────────────────────

    def run_workflow(self, workflow: str) -> Dict[str, Any]:
        if workflow not in StripeWorkflow.all():
            raise ValueError(
                f"Unknown workflow: {workflow!r}. Known: {StripeWorkflow.all()}"
            )
        return self.inner.invoke_tool("stripe.workflows.run", {"workflow": workflow})

    # ── MCP bridge — proxy to https://mcp.stripe.com ──────────────────

    def mcp_invoke(self, tool: str, arguments: Optional[Dict[str, Any]] = None,
                    *, stripe_account_id: Optional[str] = None) -> Dict[str, Any]:
        args: Dict[str, Any] = {"tool": tool, "arguments": arguments or {}}
        if stripe_account_id:
            args["stripe_account_id"] = stripe_account_id
        return self.inner.invoke_tool("stripe.mcp.invoke", args)

    # ── agent-toolkit-style adapter ───────────────────────────────────

    def as_agent_toolkit_tools(self) -> List[Dict[str, Any]]:
        """Return tool descriptors compatible with stripe-agent-toolkit shape.

        Each entry has ``name``, ``description``, and a ``call`` callable that
        takes a dict and returns a dict. Drop-in for any agent framework that
        accepts named tools with a structured schema (OpenAI Agents SDK,
        LangChain ``StructuredTool.from_function``, CrewAI ``Tool``, etc.)."""
        descriptors: List[Dict[str, Any]] = []
        for resource, verb, desc in _AGENT_TOOLKIT_DESCRIPTORS:
            name = f"stripe_{resource}_{verb}"
            descriptors.append({
                "name": name,
                "description": desc,
                "call": _bind(self, resource, verb),
            })
        # Add the high-level workflow shortcut.
        for wf in StripeWorkflow.all():
            descriptors.append({
                "name": wf.replace(".", "_"),
                "description": f"Run the {wf} composite. HITL — produces an approval row.",
                "call": (lambda args, _wf=wf: self.run_workflow(_wf)),
            })
        return descriptors


def _bind(client: StripeOrchestratorClient, resource: str, verb: str):
    """Return a callable that the agent framework can invoke as ``fn(args)``."""

    def call(arguments: Dict[str, Any]) -> Dict[str, Any]:
        return client.dispatch(resource, verb, arguments or {})

    return call


# Curated shortlist for the agent-toolkit shim. Full surface stays available
# via ``StripeOrchestratorClient.dispatch``; this list is the "discoverable"
# subset that LLMs can reasonably reason about without fishing.
_AGENT_TOOLKIT_DESCRIPTORS: Iterable[tuple] = (
    ("customers", "list", "List Stripe customers."),
    ("customers", "retrieve", "Retrieve a Stripe customer by id."),
    ("customers", "create", "Create a Stripe customer."),
    ("subscriptions", "list", "List Stripe subscriptions."),
    ("subscriptions", "retrieve", "Retrieve a Stripe subscription by id."),
    ("subscriptions", "update", "Update a Stripe subscription."),
    ("subscriptions", "cancel", "Cancel a Stripe subscription."),
    ("invoices", "list", "List Stripe invoices."),
    ("invoices", "retrieve", "Retrieve a Stripe invoice by id."),
    ("invoices", "send", "Send a finalized Stripe invoice."),
    ("invoices", "void", "Void a Stripe invoice."),
    ("refunds", "create", "Issue a Stripe refund."),
    ("refunds", "list", "List recent Stripe refunds."),
    ("payment_intents", "list", "List Stripe PaymentIntents."),
    ("payment_intents", "retrieve", "Retrieve a Stripe PaymentIntent."),
    ("payment_intents", "confirm", "Confirm a Stripe PaymentIntent (e.g. retry a failed PI)."),
    ("disputes", "list", "List Stripe disputes."),
    ("disputes", "update", "Update a Stripe dispute (submit evidence, etc)."),
    ("payouts", "list", "List Stripe payouts."),
    ("payouts", "create", "Create a Stripe payout."),
    ("products", "list", "List Stripe products."),
    ("prices", "list", "List Stripe prices."),
    ("coupons", "list", "List Stripe coupons."),
    ("promotion_codes", "list", "List Stripe promotion codes."),
    ("api", "request", "Governed long-tail Stripe API request for /v1 or /v2 endpoints."),
)
