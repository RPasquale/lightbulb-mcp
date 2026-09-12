"""Customer application integration: identity-only SQL and invitation delivery.

The identity connection is a customer backend dependency. It cannot provision
workspaces or grant plans; those effects still require canonical Lightbulb Tools.
"""
from __future__ import annotations

import hashlib
import json
import smtplib
import ssl
from email.message import EmailMessage
from importlib.resources import files
from typing import Callable, Literal
from urllib.parse import quote, urlsplit
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from lightbulb.company_engine_core import StrictModel
from lightbulb.connector_execution import ExecutionScope


class CustomerSaasPricePolicy(StrictModel):
    price_id: str = Field(pattern=r"^price_[A-Za-z0-9]+$")
    plan_ref: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
    features: tuple[str, ...] = Field(max_length=20)
    seat_limit: int = Field(ge=1, le=100000)
    quantity: int = Field(ge=1, le=1000)
    unit_amount_minor: int = Field(ge=1, le=1000000000)
    currency: str = Field(pattern=r"^[a-z]{3}$")
    interval: Literal["day", "week", "month", "year"]
    interval_count: int = Field(ge=1, le=12)

    @field_validator("features")
    @classmethod
    def feature_names(cls, value):
        import re
        if len(set(value)) != len(value) or any(not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", name) for name in value):
            raise ValueError("unique valid feature names required")
        return value


class CustomerSelfServiceBinding(StrictModel):
    workspace_ref: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
    customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]+$")
    subscription_id: str = Field(pattern=r"^sub_[A-Za-z0-9]+$")
    configuration_id: str = Field(pattern=r"^bpc_[A-Za-z0-9]+$")
    allowed_price_ids: tuple[str, ...] = Field(min_length=1, max_length=20)
    price_policies: tuple[CustomerSaasPricePolicy, ...] = Field(default=(), max_length=20)

    @field_validator("allowed_price_ids")
    @classmethod
    def prices(cls, value):
        import re
        if len(set(value)) != len(value) or any(not re.fullmatch(r"price_[A-Za-z0-9]+", p) for p in value):
            raise ValueError("unique Stripe price IDs required")
        return value

    @model_validator(mode="after")
    def policy_prices(self):
        policies = [p.price_id for p in self.price_policies]
        if len(set(policies)) != len(policies) or any(p not in self.allowed_price_ids for p in policies):
            raise ValueError("price policies must map unique allowed prices")
        return self


class CustomerSaasKit(StrictModel):
    application_id: UUID
    public_origin: str
    auth0_issuer: str
    auth0_client_id: str = Field(min_length=1, max_length=200)
    scope: ExecutionScope
    destination_account_ref: str = Field(min_length=1, max_length=200)
    billing_account_ref: str = Field(min_length=1, max_length=200)
    bindings: tuple[CustomerSelfServiceBinding, ...] = Field(min_length=1, max_length=1000)

    @field_validator("scope")
    @classmethod
    def project_scope(cls, value):
        if value.project_id is None:
            raise ValueError("a governed project UUID is required")
        return value

    @field_validator("application_id", mode="before")
    @classmethod
    def application_uuid(cls, value):
        return UUID(str(value))

    @field_validator("public_origin", "auth0_issuer")
    @classmethod
    def origin(cls, value):
        u = urlsplit(value)
        if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ("", "/") or u.port not in (None, 443):
            raise ValueError("an HTTPS origin is required")
        return value.rstrip("/")

    @field_validator("bindings")
    @classmethod
    def unique_bindings(cls, value):
        for key in ("workspace_ref", "customer_id", "subscription_id"):
            if len({getattr(b, key) for b in value}) != len(value):
                raise ValueError("bindings must have unique customer, subscription and workspace identities")
        return value

    @staticmethod
    def application_schema() -> str:
        return files("lightbulb").joinpath("sql/customer_saas_v1.sql").read_text(encoding="utf-8")

    @staticmethod
    def integration_schema() -> str:
        return "\n".join(files("lightbulb").joinpath("sql", name).read_text(encoding="utf-8")
                         for name in ("customer_saas_kit_v1.sql", "customer_self_service_recovery_v1.sql"))

    def binding(self, workspace: str) -> CustomerSelfServiceBinding:
        return next(b for b in self.bindings if b.workspace_ref == workspace)


class CustomerSaasIdentityStore:
    """Fixed SQL operations through the separately granted application identity role."""

    def __init__(self, application_id: UUID, connect: Callable):
        self.application_id, self.connect = str(application_id), connect

    def _query(self, statement, *args):
        with self.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(statement, (self.application_id, *args))
                return cursor.fetchone()[0]

    def accept(self, workspace, email, subject):
        return self._query("select lightbulb_saas.accept_invitation_v1(%s::uuid,%s,%s,%s)", workspace, email, subject)

    def authorize(self, workspace, subject):
        return self._query("select lightbulb_saas.authorize_subject_v1(%s::uuid,%s,%s)", workspace, subject)

    def context(self, workspace, subject):
        return self._query("select lightbulb_saas.customer_context_v1(%s::uuid,%s,%s)", workspace, subject)

    def action(self, workspace, subject, action_ref, version=0, state=None):
        return self._query("select lightbulb_saas.self_service_state_v1(%s::uuid,%s,%s,%s::uuid,%s,%s::jsonb)",
                           workspace, subject, str(UUID(str(action_ref))), version, None if state is None else json.dumps(state))

    def actions(self, workspace, subject, *, after=None, limit=26):
        cursor = None if after is None else str(UUID(str(after)))
        return self._query("select lightbulb_saas.self_service_history_v1(%s::uuid,%s,%s,%s::uuid,%s)",
                           workspace, subject, cursor, limit)

    def pending(self, after_workspace="", after_email=""):
        return self._query("select lightbulb_saas.pending_invitations_v1(%s::uuid,%s,%s)", after_workspace, after_email)

    def claim_delivery(self, workspace, email, expires_at):
        return self._query("select lightbulb_saas.claim_invitation_delivery_v1(%s::uuid,%s,%s,%s::timestamptz)", workspace, email, expires_at)

    def finish_delivery(self, workspace, email, expires_at, result):
        return self._query("select lightbulb_saas.finish_invitation_delivery_v1(%s::uuid,%s,%s,%s::timestamptz,%s)", workspace, email, expires_at, result)


class CustomerInvitationDelivery:
    def __init__(self, kit: CustomerSaasKit, store: CustomerSaasIdentityStore, send: Callable[[EmailMessage], None], sender: str):
        if "\n" in sender or "\r" in sender or "@" not in sender:
            raise ValueError("valid sender required")
        self.kit, self.store, self.send, self.sender = kit, store, send, sender

    def deliver(self, invitation: dict) -> str:
        workspace, email, expiry = (invitation[k] for k in ("workspace_ref", "email", "expires_at"))
        if not self.store.claim_delivery(workspace, email, expiry):
            return "already_claimed_or_ineligible"
        message = EmailMessage()
        message["From"], message["To"], message["Subject"] = self.sender, email, "Your workspace invitation"
        digest = hashlib.sha256(json.dumps([str(self.kit.application_id), workspace, email, expiry]).encode()).hexdigest()
        message["Message-ID"] = f"<{digest}@{urlsplit(self.kit.public_origin).hostname}>"
        message.set_content(f"Sign in with this email address to accept your invitation:\n{self.kit.public_origin}/invite/{quote(workspace, safe='')}\n\nThis link grants no access without verified sign-in.")
        try:
            self.send(message)
        except Exception:
            self.store.finish_delivery(workspace, email, expiry, "unknown")
            return "unknown"
        self.store.finish_delivery(workspace, email, expiry, "sent")
        return "sent"

    @staticmethod
    def smtp_sender(host, port, username, password):
        def send(message):
            with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=20) as smtp:
                smtp.login(username, password)
                smtp.send_message(message)
        return send
