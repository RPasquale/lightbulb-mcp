"""Typed client for the Xero deep-integration agent.

Wraps /api/finance/xero/agent/* and /api/finance/xero/intake/* so external
code can drive the Xero controller without rebuilding request/response shapes.

Usage::

    >>> from lightbulb import LightbulbClient
    >>> from lightbulb.xero import XeroAgentClient, XeroPlaybook
    >>> xero = XeroAgentClient(LightbulbClient(...))
    >>> snapshot = xero.snapshot()
    >>> proposals = xero.proposals(kind="bank_reconciliation")
    >>> xero.run_playbook(XeroPlaybook.MONTH_END_CLOSE)

All operations route through the platform's HITL gate — proposals must be
approved before execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from lightbulb.errors import raise_if_error

from .client import LightbulbClient


__all__ = [
    "XeroAgentClient",
    "XeroPlaybook",
]


class XeroPlaybook:
    """Well-known Xero playbook IDs."""

    MONTH_END_CLOSE = "month_end_close"
    AR_FOLLOWUP = "ar_followup"
    AP_INTAKE_TO_PAY = "ap_intake_to_pay"
    BANK_RECONCILIATION = "bank_reconciliation"
    PAYROLL_TRUEUP = "payroll_trueup"
    REPORTING_PACK = "reporting_pack"
    CONSOLIDATION = "consolidation"

    @classmethod
    def all(cls) -> List[str]:
        return [
            cls.MONTH_END_CLOSE,
            cls.AR_FOLLOWUP,
            cls.AP_INTAKE_TO_PAY,
            cls.BANK_RECONCILIATION,
            cls.PAYROLL_TRUEUP,
            cls.REPORTING_PACK,
            cls.CONSOLIDATION,
        ]


@dataclass
class XeroAgentClient:
    """Thin wrapper over LightbulbClient that targets ``/api/finance/xero``."""

    inner: LightbulbClient

    # ── Snapshot & proposals ─────────────────────────────────────────

    def snapshot(self, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Fetch a multi-org Xero financial snapshot (cash, AR, AP, payroll, taxes)."""
        session = self.inner._get_session()
        resp = session.post(
            f"{self.inner._base_url}/api/finance/xero/agent/snapshot",
            json=body or {},
            headers=self.inner._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def proposals(self, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate proposals (reconciliation, AP, payroll, etc.) for the org."""
        session = self.inner._get_session()
        resp = session.post(
            f"{self.inner._base_url}/api/finance/xero/agent/proposals",
            json=body or {},
            headers=self.inner._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def create_proposal(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a proposal (queues an HITL approval)."""
        session = self.inner._get_session()
        resp = session.post(
            f"{self.inner._base_url}/api/finance/xero/agent/proposals/create",
            json=body,
            headers=self.inner._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def approve_proposal(self, proposal_id: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Approve a proposal so it can execute against Xero."""
        session = self.inner._get_session()
        resp = session.post(
            f"{self.inner._base_url}/api/finance/xero/agent/proposals/{proposal_id}/approve",
            json=body or {},
            headers=self.inner._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def reject_proposal(self, proposal_id: str, *, reason: str = "") -> Dict[str, Any]:
        """Reject a Xero proposal."""
        session = self.inner._get_session()
        resp = session.post(
            f"{self.inner._base_url}/api/finance/xero/agent/proposals/{proposal_id}/reject",
            json={"reason": reason},
            headers=self.inner._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Sync & playbooks ─────────────────────────────────────────────

    def run_sync(self, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Trigger a Xero data sync (org rosters, AR/AP, payroll, ledger)."""
        session = self.inner._get_session()
        resp = session.post(
            f"{self.inner._base_url}/api/finance/xero/agent/sync/run",
            json=body or {},
            headers=self.inner._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def run_playbook(self, playbook_id: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run a Xero playbook (e.g. month_end_close, ar_followup)."""
        session = self.inner._get_session()
        resp = session.post(
            f"{self.inner._base_url}/api/finance/xero/agent/playbook/{playbook_id}/run",
            json=body or {},
            headers=self.inner._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def org_profile(self, xero_tenant_id: str) -> Dict[str, Any]:
        """Get the Xero org profile (chart of accounts, tax rates, branding)."""
        session = self.inner._get_session()
        resp = session.get(
            f"{self.inner._base_url}/api/finance/xero/agent/orgs/{xero_tenant_id}/profile",
            headers=self.inner._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Intake (proposing data into Xero) ────────────────────────────

    def propose_invoice(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Propose an AR invoice entry into Xero (HITL-gated)."""
        return self._post_intake("invoice-proposal", body)

    def propose_bill(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Propose an AP bill entry into Xero (HITL-gated)."""
        return self._post_intake("bill-proposal", body)

    def propose_journal(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Propose a manual journal entry into Xero (HITL-gated)."""
        return self._post_intake("journal-proposal", body)

    def propose_payroll_trueup(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Propose a payroll true-up adjustment into Xero (HITL-gated)."""
        return self._post_intake("payroll-trueup-proposal", body)

    def _post_intake(self, leaf: str, body: Dict[str, Any]) -> Dict[str, Any]:
        session = self.inner._get_session()
        resp = session.post(
            f"{self.inner._base_url}/api/finance/xero/intake/{leaf}",
            json=body,
            headers=self.inner._headers(),
        )
        raise_if_error(resp)
        return resp.json()
