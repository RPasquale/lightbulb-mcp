"""Authenticated application requests composed with canonical Lightbulb approvals.

Call only from a backend after verified identity and CSRF checks. Stored actions
retain immutable requests, never customer portal bearer URLs or authentication tokens.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from uuid import uuid4

from lightbulb.company_sales_progression import scoped_receipt
from lightbulb.company_saas_kit import CustomerSaasIdentityStore, CustomerSaasKit
from lightbulb.connector_execution import ConnectorEffect, ConnectorExecutionRequest, HostedConnectorExecutor


class CustomerSelfServiceError(ValueError):
    pass


class CustomerSelfService:
    def __init__(self, kit: CustomerSaasKit, store: CustomerSaasIdentityStore, client, *, executor=None):
        self.kit, self.store, self.client = kit, store, client
        self.executor = executor if executor is not None else HostedConnectorExecutor(client)

    def _context(self, workspace, subject):
        context = self.store.context(workspace, subject)
        binding = self.kit.binding(workspace)
        if context.get("can_manage") is not True or context.get("customer_identity") != binding.customer_id:
            raise CustomerSelfServiceError("CUSTOMER_OWNER_MAPPING_REQUIRED")
        return context, binding

    def prepare(self, workspace: str, subject: str, action: str, *, email: str | None = None) -> dict:
        context, binding = self._context(workspace, subject)
        action_ref = str(uuid4())
        if action == "reconcile_access":
            arguments = self._access_arguments(workspace, subject, action_ref)
            if arguments is None:
                return {"action_ref": action_ref, "phase": "completed"}
            tool, account = "postgresql.apply_customer_workspace", self.kit.destination_account_ref
        elif action == "remove_member":
            if not isinstance(email, str) or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254 or email != email.lower() or email == context["member_email"]:
                raise CustomerSelfServiceError("ANOTHER_MEMBER_EMAIL_REQUIRED")
            arguments = dict(application_id=str(self.kit.application_id),workspace_ref=workspace,customer_ref=binding.customer_id,
                             email=email,action_ref=action_ref,expected_revision=context["revision"])
            tool, account = "postgresql.remove_customer_member", self.kit.destination_account_ref
        elif action == "invite":
            if context.get("access_active") is not True or not isinstance(email, str) or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254 or email != email.lower():
                raise CustomerSelfServiceError("ACTIVE_WORKSPACE_AND_EMAIL_REQUIRED")
            arguments = dict(application_id=str(self.kit.application_id), workspace_ref=workspace,
                             customer_ref=binding.customer_id, email=email, action="invite", action_ref=action_ref,
                             plan_ref=context["plan_ref"], features=context["features"], seat_limit=context["seat_limit"],
                             expected_revision=context["revision"], invitation_expires_at=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat())
            tool, account = "postgresql.apply_customer_workspace", self.kit.destination_account_ref
        elif action in {"overview", "plan", "cancel", "payment_method"}:
            arguments = dict(customer_id=binding.customer_id, subscription_id=binding.subscription_id,
                             configuration_id=binding.configuration_id, allowed_price_ids=list(binding.allowed_price_ids),
                             return_url=f"{self.kit.public_origin}/workspaces/{workspace}", action=action)
            tool, account = "stripe.create_customer_portal_session", self.kit.billing_account_ref
        else:
            raise CustomerSelfServiceError("UNSUPPORTED_CUSTOMER_ACTION")
        request = ConnectorExecutionRequest(tool=tool, arguments=arguments, scope=self.kit.scope,
                                            connector_account_ref=account, effect=ConnectorEffect.WRITE,
                                            approval_required=True, idempotency_key=f"customer-self-service:{action_ref}",
                                            metadata={"customer_action": action})
        state = {"phase": "prepared", "request": request.model_dump(mode="json", by_alias=True)}
        self.store.action(workspace, subject, action_ref, state=state)
        return {"action_ref": action_ref, "phase": "prepared"}

    def advance(self, workspace: str, subject: str, action_ref: str) -> dict:
        context, binding = self._context(workspace, subject)
        record = self.store.action(workspace, subject, action_ref)
        state, version = record["state"], record["version"]
        phase = state["phase"]
        if phase not in {"prepared", "pending_approval"}:
            return {"action_ref": action_ref, "phase": "unknown" if phase == "posting" else phase}
        request = ConnectorExecutionRequest.model_validate(state["request"])
        if request.scope != self.kit.scope:
            raise CustomerSelfServiceError("RETAINED_SCOPE_CHANGED")
        if request.tool == "stripe.create_customer_portal_session":
            expected = dict(customer_id=binding.customer_id,subscription_id=binding.subscription_id,configuration_id=binding.configuration_id,
                            allowed_price_ids=list(binding.allowed_price_ids),return_url=f"{self.kit.public_origin}/workspaces/{workspace}",action=request.arguments.get("action"))
            if request.arguments != expected or request.connector_account_ref != self.kit.billing_account_ref:
                raise CustomerSelfServiceError("RETAINED_BILLING_MAPPING_CHANGED")
        elif request.tool not in {"postgresql.apply_customer_workspace","postgresql.remove_customer_member"} or request.connector_account_ref != self.kit.destination_account_ref or request.arguments.get("customer_ref") != binding.customer_id or request.arguments.get("application_id") != str(self.kit.application_id) or request.arguments.get("workspace_ref") != workspace:
            raise CustomerSelfServiceError("RETAINED_APPLICATION_MAPPING_CHANGED")
        if request.metadata.get("customer_action") == "reconcile_access":
            try:
                current = self._access_arguments(workspace, subject, action_ref)
            except CustomerSelfServiceError:
                return {"action_ref": action_ref, "phase": "review_required"}
            if current != request.arguments:
                return {"action_ref": action_ref, "phase": "review_required"}
        if phase == "pending_approval":
            approval = self.client.get_approval(state["approval_ref"])
            if str(approval.get("status", "")).upper() != "APPROVED":
                return {"action_ref": action_ref, "phase": "pending_approval"}
            request = request.model_copy(update={"approval_ref": state["approval_ref"]})
        posting = {**state, "phase": "posting"}
        record = self.store.action(workspace, subject, action_ref, version, posting)
        version = record["version"]
        try:
            result = self.executor.execute(request)
            if result.status.value == "pending_approval" and result.approval_ref:
                next_state = {**state, "phase": "pending_approval", "approval_ref": result.approval_ref}
                self.store.action(workspace, subject, action_ref, version, next_state)
                return {"action_ref": action_ref, "phase": "pending_approval"}
            if result.status.value != "completed":
                self.store.action(workspace, subject, action_ref, version, {**state, "phase": "unknown"})
                return {"action_ref": action_ref, "phase": "unknown"}
            receipt = scoped_receipt(result, request)
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(receipt.completed_at.replace("Z", "+00:00"))).total_seconds()
            if not request.approval_ref or receipt.approval_ref != request.approval_ref or receipt.approval_receipt_digest != result.provenance.approval_receipt_digest or not 0 <= age <= 60 or result.cached:
                raise CustomerSelfServiceError("FRESH_APPROVED_RECEIPT_REQUIRED")
            private_url = None
            if request.tool == "stripe.create_customer_portal_session":
                out, a = result.output, request.arguments
                if any(out.get(k) != a.get(v) for k, v in (("customer", "customer_id"), ("subscription_id", "subscription_id"), ("configuration", "configuration_id"), ("action", "action"))):
                    raise CustomerSelfServiceError("PORTAL_IDENTITY_MISMATCH")
                u = urlsplit(out.get("url", ""))
                if u.scheme != "https" or u.hostname != "billing.stripe.com" or u.username or u.password or u.port not in (None, 443) or not (u.path == "/p/session" or u.path.startswith("/p/session/")) or u.fragment:
                    raise CustomerSelfServiceError("PORTAL_URL_INVALID")
                private_url = out["url"]
            else:
                out = result.output
                if out.get("id") != workspace or out.get("member_email") != request.arguments["email"] or out.get("customer_identity") != request.arguments["customer_ref"]:
                    raise CustomerSelfServiceError("INVITATION_READBACK_MISMATCH")
                if request.tool == "postgresql.remove_customer_member" and (out.get("member_status") != "absent" or out.get("access_active") is not False):
                    raise CustomerSelfServiceError("MEMBER_REMOVAL_READBACK_MISMATCH")
                if request.arguments.get("action") == "invite" and out.get("member_status") != "pending":
                    raise CustomerSelfServiceError("INVITATION_READBACK_MISMATCH")
                if request.tool != "postgresql.remove_customer_member" and request.arguments["action"] != "invite" and any(out.get(key) != request.arguments[key] for key in ("plan_ref", "features", "seat_limit")):
                    raise CustomerSelfServiceError("ENTITLEMENT_READBACK_MISMATCH")
            self.store.action(workspace, subject, action_ref, version, {**state, "phase": "completed"})
            response = {"action_ref": action_ref, "phase": "completed"}
            if private_url:
                response["url"] = private_url
            return response
        except Exception:
            # Includes a lost HTTP response or process boundary after posting. Never retry effects.
            latest = self.store.action(workspace, subject, action_ref)
            if latest["version"] == version and latest["state"]["phase"] == "posting":
                self.store.action(workspace, subject, action_ref, version, {**state, "phase": "unknown"})
            return {"action_ref": action_ref, "phase": "unknown"}

    def _access_arguments(self, workspace, subject, action_ref):
        context, binding = self._context(workspace, subject)
        sub = self.reconcile_subscription(workspace, subject)["subscription"]
        plan, features, seats = context["plan_ref"], context["features"], context["seat_limit"]
        if sub.get("status") in {"canceled", "unpaid", "incomplete_expired"}:
            if context["status"] == "suspended":
                return None
            action = "suspend"
        else:
            if sub.get("status") != "active" or sub.get("latest_invoice_paid") is not True or sub.get("pending_update") is not False or type(sub.get("current_period_end")) is not int or sub["current_period_end"] <= int(datetime.now(timezone.utc).timestamp()):
                raise CustomerSelfServiceError("VERIFIED_PAID_SUBSCRIPTION_REQUIRED")
            policies = [p for p in binding.price_policies if all(sub.get(key) == getattr(p, key) for key in ("price_id", "quantity", "unit_amount_minor", "currency", "interval", "interval_count"))]
            if len(policies) != 1 or policies[0].price_id not in binding.allowed_price_ids:
                raise CustomerSelfServiceError("REVIEWED_PRICE_POLICY_REQUIRED")
            policy = policies[0]
            plan, features, seats = policy.plan_ref, list(policy.features), policy.seat_limit
            if (plan, features, seats) != (context["plan_ref"], context["features"], context["seat_limit"]):
                action = "configure"
            elif context["status"] == "suspended":
                action = "reactivate"
            else:
                return None
        # Stable inert timestamp: configuration/suspension do not create invitations.
        return dict(application_id=str(self.kit.application_id),workspace_ref=workspace,customer_ref=binding.customer_id,
                    email=context["member_email"],action=action,action_ref=action_ref,plan_ref=plan,features=features,
                    seat_limit=seats,expected_revision=context["revision"],invitation_expires_at="2099-01-01T00:00:00Z")

    def reconcile_subscription(self, workspace: str, subject: str) -> dict:
        _, binding = self._context(workspace, subject)
        request = ConnectorExecutionRequest(tool="stripe.get_customer_subscription", scope=self.kit.scope,
                    connector_account_ref=self.kit.billing_account_ref,
                    arguments={"customer_id": binding.customer_id, "subscription_id": binding.subscription_id})
        result = self.executor.execute(request)
        receipt = scoped_receipt(result, request)
        self._fresh_read(result, receipt)
        out = result.output
        if out.get("id") != binding.subscription_id or out.get("customer") != binding.customer_id:
            raise CustomerSelfServiceError("SUBSCRIPTION_IDENTITY_MISMATCH")
        return {"subscription": out, "observed_at": receipt.completed_at,
                "entitlements_changed": False}

    def check_setup(self) -> dict:
        request = ConnectorExecutionRequest(tool="postgresql.get_customer_app_setup", scope=self.kit.scope,
                    connector_account_ref=self.kit.destination_account_ref, arguments={"application_id": str(self.kit.application_id)})
        result = self.executor.execute(request)
        receipt = scoped_receipt(result, request)
        self._fresh_read(result, receipt)
        if result.output.get("schema") != "lightbulb.customer_saas_setup.v1" or result.output.get("application_id") != str(self.kit.application_id):
            raise CustomerSelfServiceError("SETUP_APPLICATION_MISMATCH")
        return {"destination": result.output, "observed_at": receipt.completed_at,
                "identity_provider_configured": True, "customer_login_verified": False,
                "invitation_delivery_verified": False}

    @staticmethod
    def _fresh_read(result, receipt):
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(receipt.completed_at.replace("Z", "+00:00"))).total_seconds()
        if result.cached or not 0 <= age <= 60:
            raise CustomerSelfServiceError("FRESH_PROVIDER_READ_REQUIRED")
