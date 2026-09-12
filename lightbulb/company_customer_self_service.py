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
from lightbulb.connector_execution import ConnectorEffect, ConnectorExecutionRequest, ConnectorExecutionResult, HostedConnectorExecutor


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
        self._validate_retained(request, workspace, binding, action_ref)
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
            receipt = self._approved_receipt(result, request, fresh=True)
            private_url = self._validated_output(result, request, workspace, include_url=True)
            self.store.action(workspace, subject, action_ref, version,
                              {**state, "phase": "completed", "receipt": receipt.to_dict()})
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

    def inspect_action(self, workspace: str, subject: str, action_ref: str) -> dict:
        """Return a safe status projection; never return requests or portal URLs."""
        self._context(workspace, subject)
        record = self.store.action(workspace, subject, action_ref)
        return self._summary(action_ref, record["state"])

    def history(self, workspace: str, subject: str, *, after: str | None = None, limit: int = 25) -> dict:
        """Bounded owner history, paged in stable action-reference order."""
        self._context(workspace, subject)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise CustomerSelfServiceError("ACTION_HISTORY_LIMIT_INVALID")
        rows = self.store.actions(workspace, subject, after=after, limit=limit + 1)
        return {"actions": rows[:limit],
                "next_cursor": rows[limit - 1]["action_ref"] if len(rows) > limit else None}

    @staticmethod
    def _summary(action_ref, state):
        return {"action_ref": action_ref,
                "action": state["request"].get("metadata", {}).get("customer_action"),
                "phase": "unknown" if state["phase"] == "posting" else state["phase"]}

    def synchronize_support(self, workspace: str, subject: str, action_ref: str) -> dict:
        """Retry-safe projection to the existing owner task inbox, with server-owned closure."""
        _, binding = self._context(workspace, subject)
        state = self.store.action(workspace, subject, action_ref)["state"]
        if state["phase"] not in {"review_required", "completed"}:
            return {"status": "not_escalated"}
        request = ConnectorExecutionRequest.model_validate(state["request"])
        self._validate_retained(request, workspace, binding, action_ref)
        if state.get("approval_ref"):
            request = request.model_copy(update={"approval_ref": state["approval_ref"]})
        result = self.client.sync_customer_recovery_task(request, application_id=self.kit.application_id,
                workspace_ref=workspace, action_ref=action_ref, completed=state["phase"] == "completed")
        if state["phase"] == "review_required" and result.get("receipt_available") is True:
            receipt = self.executor.lookup_receipt(request)
            self.reconcile_action(workspace, subject, action_ref, receipt)
        return result

    def _support_summary(self, workspace, subject, action_ref, state):
        summary = self._summary(action_ref, state)
        if state["phase"] in {"review_required", "completed"}:
            try:
                self.synchronize_support(workspace, subject, action_ref)
                summary = self._summary(action_ref, self.store.action(workspace, subject, action_ref)["state"])
            except Exception:
                # State remains discoverable. Cadence retries the same immutable task identity.
                summary["support_sync_pending"] = True
        return summary

    def recover_action(self, workspace: str, subject: str, action_ref: str) -> dict:
        """Perform at most one journal lookup; never dispatch an external write.

        Attempts and the next-check time survive restarts. Call again from an
        authenticated owner action or the existing durable cadence; no local timer.
        """
        _, binding = self._context(workspace, subject)
        record = self.store.action(workspace, subject, action_ref)
        state = record["state"]
        if state["phase"] not in {"posting", "unknown"}:
            return self._support_summary(workspace, subject, action_ref, state)
        request = ConnectorExecutionRequest.model_validate(state["request"])
        self._validate_retained(request, workspace, binding, action_ref)
        now = datetime.now(timezone.utc)
        if state.get("next_recovery_at") and now < datetime.fromisoformat(state["next_recovery_at"]):
            return self._summary(action_ref, state)
        attempts = state.get("recovery_attempts", 0)
        if not state.get("approval_ref") or attempts >= 3:
            self.store.action(workspace, subject, action_ref, record["version"],
                              {**state, "phase": "review_required"})
            return self._support_summary(workspace, subject, action_ref, {**state, "phase": "review_required"})
        request = request.model_copy(update={"approval_ref": state["approval_ref"]})
        claimed = {**state, "phase": "unknown", "recovery_attempts": attempts + 1,
                   "next_recovery_at": (now + timedelta(minutes=1)).isoformat()}
        self.store.action(workspace, subject, action_ref, record["version"], claimed)
        try:
            result = self.executor.lookup_receipt(request)
            if result.status.value == "completed":
                return self.reconcile_action(workspace, subject, action_ref, result)
        except Exception:
            # Includes uncertain lookup responses. The durable budget is already consumed.
            pass
        if attempts + 1 >= 3:
            latest = self.store.action(workspace, subject, action_ref)
            if latest["state"]["phase"] == "unknown":
                self.store.action(workspace, subject, action_ref, latest["version"],
                                  {**latest["state"], "phase": "review_required"})
        latest = self.store.action(workspace, subject, action_ref)["state"]
        return self._support_summary(workspace, subject, action_ref, latest)

    def tick_recovery(self, workspace: str, subject: str, *, after: str | None = None) -> dict:
        """Bounded cadence step: scan one page, recover due actions, return its cursor."""
        page = self.history(workspace, subject, after=after, limit=25)
        return {"actions": [self.recover_action(workspace, subject, row["action_ref"])
                            if row["phase"] in {"unknown", "review_required", "completed"} else row for row in page["actions"]],
                "next_cursor": page["next_cursor"]}

    def reconcile_action(self, workspace: str, subject: str, action_ref: str,
                         result: ConnectorExecutionResult) -> dict:
        """Consume a trusted, authenticated governed execution result without dispatch.

        Backend-only, like the existing referral reconciliation contract. Never accept
        receipt JSON from a customer or model. The caller retrieves the original result
        from its trusted execution infrastructure; provider state alone is insufficient.
        Historical receipts prove the original effect, not current access or billing.
        """
        _, binding = self._context(workspace, subject)
        record = self.store.action(workspace, subject, action_ref)
        state = record["state"]
        request = ConnectorExecutionRequest.model_validate(state["request"])
        self._validate_retained(request, workspace, binding, action_ref)
        if state["phase"] not in {"posting", "unknown", "review_required", "completed"}:
            raise CustomerSelfServiceError("ACTION_NOT_AWAITING_RECONCILIATION")
        if not state.get("approval_ref"):
            raise CustomerSelfServiceError("RETAINED_APPROVAL_REQUIRED")
        request = request.model_copy(update={"approval_ref": state["approval_ref"]})
        result = ConnectorExecutionResult.model_validate(result)
        receipt = self._approved_receipt(result, request, fresh=False)
        self._validated_output(result, request, workspace, include_url=False)
        if state["phase"] == "completed":
            if state.get("receipt") != receipt.to_dict():
                raise CustomerSelfServiceError("COMPLETED_RECEIPT_CHANGED")
        else:
            self.store.action(workspace, subject, action_ref, record["version"],
                              {**state, "phase": "completed", "receipt": receipt.to_dict()})
        return self._support_summary(workspace, subject, action_ref, {**state, "phase": "completed"})

    def _validate_retained(self, request, workspace, binding, action_ref):
        if request.idempotency_key != f"customer-self-service:{action_ref}":
            raise CustomerSelfServiceError("RETAINED_ACTION_IDENTITY_CHANGED")
        if request.scope != self.kit.scope:
            raise CustomerSelfServiceError("RETAINED_SCOPE_CHANGED")
        if request.tool == "stripe.create_customer_portal_session":
            expected = dict(customer_id=binding.customer_id,subscription_id=binding.subscription_id,configuration_id=binding.configuration_id,
                            allowed_price_ids=list(binding.allowed_price_ids),return_url=f"{self.kit.public_origin}/workspaces/{workspace}",action=request.arguments.get("action"))
            if request.arguments != expected or request.connector_account_ref != self.kit.billing_account_ref:
                raise CustomerSelfServiceError("RETAINED_BILLING_MAPPING_CHANGED")
        elif request.tool not in {"postgresql.apply_customer_workspace","postgresql.remove_customer_member"} or request.connector_account_ref != self.kit.destination_account_ref or request.arguments.get("customer_ref") != binding.customer_id or request.arguments.get("application_id") != str(self.kit.application_id) or request.arguments.get("workspace_ref") != workspace:
            raise CustomerSelfServiceError("RETAINED_APPLICATION_MAPPING_CHANGED")

    @staticmethod
    def _approved_receipt(result, request, *, fresh):
        receipt = scoped_receipt(result, request)
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(receipt.completed_at.replace("Z", "+00:00"))).total_seconds()
        if not request.approval_ref or receipt.approval_ref != request.approval_ref or age < 0:
            raise CustomerSelfServiceError("APPROVED_RECEIPT_REQUIRED")
        if fresh and (age > 60 or result.cached):
            raise CustomerSelfServiceError("FRESH_APPROVED_RECEIPT_REQUIRED")
        return receipt

    @staticmethod
    def _validated_output(result, request, workspace, *, include_url):
        private_url = None
        if request.tool == "stripe.create_customer_portal_session":
            out, a = result.output, request.arguments
            if not include_url and out.get("schema") == "lightbulb.governed_connector_output_commitment.v1":
                digest = out.get("provider_output_sha256")
                if set(out) != {"schema", "provider_output_sha256"} or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) or digest == "0" * 64:
                    raise CustomerSelfServiceError("PORTAL_COMMITMENT_INVALID")
                return None
            if any(out.get(k) != a.get(v) for k, v in (("customer", "customer_id"), ("subscription_id", "subscription_id"), ("configuration", "configuration_id"), ("action", "action"))):
                raise CustomerSelfServiceError("PORTAL_IDENTITY_MISMATCH")
            if not include_url:
                return None
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
            if request.arguments.get("action") in {"suspend", "reactivate"}:
                expected_status = "suspended" if request.arguments["action"] == "suspend" else "active"
                if out.get("status") != expected_status:
                    raise CustomerSelfServiceError("ENTITLEMENT_STATUS_MISMATCH")
            if request.arguments.get("action") == "invite" and out.get("member_status") != "pending":
                raise CustomerSelfServiceError("INVITATION_READBACK_MISMATCH")
            if request.tool != "postgresql.remove_customer_member" and request.arguments["action"] != "invite" and any(out.get(key) != request.arguments[key] for key in ("plan_ref", "features", "seat_limit")):
                raise CustomerSelfServiceError("ENTITLEMENT_READBACK_MISMATCH")
        return private_url

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
