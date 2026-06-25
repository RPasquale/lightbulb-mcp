"""Typed clients for the deep connector integrations exposed by the platform.

These wrap the user-facing tool surface (``invoke_tool``) and the dedicated
HR-live endpoints, so callers don't have to remember tool keys or argument
shapes. Patterned after :class:`lightbulb.stripe.StripeOrchestratorClient`.

Usage::

    >>> from lightbulb import LightbulbClient, SlackClient, JiraClient
    >>> client = LightbulbClient(...)
    >>> SlackClient(client).post_message(channel="#deals", text="Hello")
    >>> JiraClient(client).create_issue(project_key="ENG", summary="Bug", issue_type="Bug")

For HR connectors, ``BambooHRClient``, ``GreenhouseClient`` and ``MondayClient``
hit the dedicated ``/api/hr/live`` surface (which the SDK already wraps).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .client import LightbulbClient


__all__ = [
    "SlackClient",
    "JiraClient",
    "BambooHRClient",
    "GreenhouseClient",
    "MondayClient",
]


# ── Slack ────────────────────────────────────────────────────────────


@dataclass
class SlackClient:
    """Thin wrapper over LightbulbClient for Slack operations.

    All operations route through the platform's tool surface, which enforces
    OAuth scope, rate limits, and audit logging.
    """

    inner: LightbulbClient

    def post_message(
        self,
        *,
        channel: str,
        text: str,
        thread_ts: Optional[str] = None,
        blocks: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Post a message to a Slack channel or thread."""
        args: Dict[str, Any] = {"channel": channel, "text": text}
        if thread_ts:
            args["thread_ts"] = thread_ts
        if blocks:
            args["blocks"] = blocks
        return self.inner.invoke_tool("slack.post_message", args)

    def update_message(self, *, channel: str, ts: str, text: str) -> Dict[str, Any]:
        """Edit a previously-posted message."""
        return self.inner.invoke_tool("slack.update_message", {
            "channel": channel, "ts": ts, "text": text,
        })

    def add_reaction(self, *, channel: str, ts: str, name: str) -> Dict[str, Any]:
        """Add an emoji reaction (e.g. name='thumbsup')."""
        return self.inner.invoke_tool("slack.add_reaction", {
            "channel": channel, "ts": ts, "name": name,
        })

    def list_channels(self, *, types: str = "public_channel,private_channel", limit: int = 200) -> Dict[str, Any]:
        return self.inner.invoke_tool("slack.list_channels", {"types": types, "limit": limit})

    def create_channel(self, *, name: str, is_private: bool = False) -> Dict[str, Any]:
        return self.inner.invoke_tool("slack.create_channel", {"name": name, "is_private": is_private})

    def join_channel(self, channel: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("slack.join_channel", {"channel": channel})

    def set_channel_topic(self, *, channel: str, topic: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("slack.set_channel_topic", {"channel": channel, "topic": topic})

    def invite_to_channel(self, *, channel: str, users: List[str]) -> Dict[str, Any]:
        return self.inner.invoke_tool("slack.invite_to_channel", {"channel": channel, "users": users})

    def archive_channel(self, channel: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("slack.archive_channel", {"channel": channel})

    def get_channel_history(self, channel: str, *, limit: int = 100, cursor: str = "") -> Dict[str, Any]:
        args: Dict[str, Any] = {"channel": channel, "limit": limit}
        if cursor:
            args["cursor"] = cursor
        return self.inner.invoke_tool("slack.get_channel_history", args)

    def get_thread_replies(self, *, channel: str, ts: str, limit: int = 100) -> Dict[str, Any]:
        return self.inner.invoke_tool("slack.get_thread_replies", {
            "channel": channel, "ts": ts, "limit": limit,
        })

    def search_messages(self, query: str, *, count: int = 20) -> Dict[str, Any]:
        return self.inner.invoke_tool("slack.search_messages", {"query": query, "count": count})

    def lookup_user(self, *, email: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("slack.lookup_user", {"email": email})

    def list_users(self, *, limit: int = 200, cursor: str = "") -> Dict[str, Any]:
        args: Dict[str, Any] = {"limit": limit}
        if cursor:
            args["cursor"] = cursor
        return self.inner.invoke_tool("slack.list_users", args)


# ── Jira ─────────────────────────────────────────────────────────────


@dataclass
class JiraClient:
    """Thin wrapper over LightbulbClient for Atlassian Jira operations."""

    inner: LightbulbClient

    def create_issue(
        self,
        *,
        project_key: str,
        summary: str,
        issue_type: str = "Task",
        description: str = "",
        assignee: Optional[str] = None,
        labels: Optional[List[str]] = None,
        priority: Optional[str] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        args: Dict[str, Any] = {
            "project_key": project_key,
            "summary": summary,
            "issue_type": issue_type,
        }
        if description:
            args["description"] = description
        if assignee:
            args["assignee"] = assignee
        if labels:
            args["labels"] = labels
        if priority:
            args["priority"] = priority
        if custom_fields:
            args["custom_fields"] = custom_fields
        return self.inner.invoke_tool("jira.create_issue", args)

    def search_issues(self, jql: str, *, max_results: int = 50) -> Dict[str, Any]:
        """Run a JQL search."""
        return self.inner.invoke_tool("jira.search_issues", {"jql": jql, "max_results": max_results})

    def get_issue(self, issue_key: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("jira.get_issue", {"issue_key": issue_key})

    def update_issue(self, issue_key: str, fields: Dict[str, Any]) -> Dict[str, Any]:
        return self.inner.invoke_tool("jira.update_issue", {"issue_key": issue_key, "fields": fields})

    def transition_issue(self, issue_key: str, transition: str, *, comment: str = "") -> Dict[str, Any]:
        args: Dict[str, Any] = {"issue_key": issue_key, "transition": transition}
        if comment:
            args["comment"] = comment
        return self.inner.invoke_tool("jira.transition_issue", args)

    def add_comment(self, issue_key: str, body: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("jira.add_comment", {"issue_key": issue_key, "body": body})

    def link_issues(self, *, inward_key: str, outward_key: str, link_type: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("jira.link_issues", {
            "inward_key": inward_key, "outward_key": outward_key, "link_type": link_type,
        })

    def get_sprint_issues(self, sprint_id: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("jira.get_sprint_issues", {"sprint_id": sprint_id})

    def get_board_sprints(self, board_id: str, *, state: str = "active") -> Dict[str, Any]:
        return self.inner.invoke_tool("jira.get_board_sprints", {"board_id": board_id, "state": state})


# ── BambooHR ─────────────────────────────────────────────────────────


@dataclass
class BambooHRClient:
    """BambooHR client.

    Read endpoints route through the platform's HR-live surface (no rebuild of
    tokens, scopes, or rate limits). Write operations route through the tool
    surface so they pass through HITL approvals where required.
    """

    inner: LightbulbClient

    def whos_out(self, **filters: Any) -> Dict[str, Any]:
        """Roster of employees currently or upcoming OOO."""
        return self.inner.hr_live_whos_out(**filters)

    def leave_balance(self, employee_id: str) -> Dict[str, Any]:
        return self.inner.hr_live_leave_balance(employee_id)

    def health(self) -> Dict[str, Any]:
        return self.inner.hr_live_health()

    def get_employee(self, employee_id: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("bamboohr.get_employee", {"employee_id": employee_id})

    def list_employees(self, **filters: Any) -> Dict[str, Any]:
        return self.inner.invoke_tool("bamboohr.list_employees", dict(filters))

    def create_leave_request(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.inner.invoke_tool("bamboohr.create_leave_request", body)


# ── Greenhouse ───────────────────────────────────────────────────────


@dataclass
class GreenhouseClient:
    """Greenhouse ATS client (recruiting)."""

    inner: LightbulbClient

    def list_jobs(self, **filters: Any) -> Dict[str, Any]:
        return self.inner.hr_live_recruiting_jobs(**filters)

    def list_applications(self, **filters: Any) -> Dict[str, Any]:
        return self.inner.hr_live_recruiting_applications(**filters)

    def advance_application(self, application_id: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """HITL-gated: advance a candidate to the next stage."""
        return self.inner.hr_live_advance_application(application_id, body=body)

    def reject_application(self, application_id: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """HITL-gated: reject a candidate."""
        return self.inner.hr_live_reject_application(application_id, body=body)

    def get_candidate(self, candidate_id: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("greenhouse.get_candidate", {"candidate_id": candidate_id})

    def list_candidates(self, **filters: Any) -> Dict[str, Any]:
        return self.inner.invoke_tool("greenhouse.list_candidates", dict(filters))


# ── Monday.com ───────────────────────────────────────────────────────


@dataclass
class MondayClient:
    """Monday.com client used by the HR engagement and onboarding flows."""

    inner: LightbulbClient

    def onboarding_board(self, checklist_id: str) -> Dict[str, Any]:
        """Read the Monday board for an HR onboarding checklist."""
        return self.inner.hr_live_monday_onboarding_board(checklist_id)

    def cases(self, **filters: Any) -> Dict[str, Any]:
        return self.inner.hr_live_cases(**filters)

    def list_boards(self, **filters: Any) -> Dict[str, Any]:
        return self.inner.invoke_tool("monday.list_boards", dict(filters))

    def get_board(self, board_id: str) -> Dict[str, Any]:
        return self.inner.invoke_tool("monday.get_board", {"board_id": board_id})

    def create_item(self, *, board_id: str, group_id: str, item_name: str, column_values: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        args: Dict[str, Any] = {
            "board_id": board_id,
            "group_id": group_id,
            "item_name": item_name,
        }
        if column_values:
            args["column_values"] = column_values
        return self.inner.invoke_tool("monday.create_item", args)

    def update_item(self, *, item_id: str, column_values: Dict[str, Any]) -> Dict[str, Any]:
        return self.inner.invoke_tool("monday.update_item", {
            "item_id": item_id, "column_values": column_values,
        })
