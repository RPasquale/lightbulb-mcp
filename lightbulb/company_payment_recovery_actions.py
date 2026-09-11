"""Governed payment-update sessions and invoice readback on the billing journal."""

from urllib.parse import urlsplit
from pydantic import Field, field_validator
from lightbulb.company_engine_core import (
    StrictModel,
    OpaqueRef,
    stable_digest,
    detached,
    parsed,
    timestamp,
)
from lightbulb.billing_followup import _require
from lightbulb.connector_execution import (
    ConnectorExecutionRequest,
    ConnectorExecutionResult,
    ExecutionScope,
)
from lightbulb.company_execution_bridge import execution_receipt_from_connector

TOOL = "stripe.create_payment_update_session"
SCHEMA = "lightbulb.company_payment_update.v1"


class PaymentUpdateRequest(StrictModel):
    request_ref: OpaqueRef
    invoice_ref: str = Field(pattern=r"^in_[A-Za-z0-9]{1,128}$")
    configuration_id: str = Field(pattern=r"^bpc_[A-Za-z0-9]{1,128}$")
    return_url: str = Field(max_length=2048)

    @field_validator("return_url")
    @classmethod
    def approved_destination(cls, value):
        url = urlsplit(value)
        _require(
            url.scheme == "https"
            and bool(url.hostname)
            and url.username is None
            and url.password is None
            and url.port in (None, 443)
            and not url.query
            and not url.fragment,
            "PAYMENT_UPDATE_RETURN_URL_INVALID",
        )
        return value


class CompanyPaymentRecoveryActions:
    """No card retries or sends. Exact session creation requires hosted human approval.

    The live URL is private response data. Replay returns its commitment, never a
    retained bearer link. Unknown writes require original-result reconciliation.
    """

    def __init__(self, coordinator, executor):
        self.coordinator, self.recovery, self.executor = coordinator, coordinator.recovery, executor

    def _ref(self, spec):
        return "payment-update-" + stable_digest(
            {"binding": self.recovery.binding_digest, "request_ref": spec.request_ref}
        )

    def _current(self, spec, now):
        snapshot, disposition, reason = self.coordinator._facts(spec.invoice_ref, now)
        _require(disposition in {"eligible", "native_owned"}, "PAYMENT_UPDATE_" + reason.upper())
        return snapshot

    def step(self, spec, *, now, fence):
        spec = PaymentUpdateRequest.model_validate(spec)
        now = timestamp(now, field_name="now")
        ref = self._ref(spec)
        old = self.recovery._read(ref, SCHEMA)
        _require(not old or old["spec"] == spec.to_dict(), "PAYMENT_UPDATE_REQUEST_CHANGED")
        if old and old["phase"] in {"posting", "completed"}:
            return self.status(spec, now=now)
        snapshot = self._current(spec, now)
        request = ConnectorExecutionRequest(
            tool=TOOL,
            effect="write",
            approval_required=True,
            connector_account_ref=self.recovery.source.connector_account_ref,
            scope=ExecutionScope(
                **self.recovery.runner.bundle.scope, actor_ref=self.recovery.runner.bundle.actor_ref
            ),
            arguments={
                "customer_id": self.recovery.source.arguments["customer_id"],
                "invoice_id": spec.invoice_ref,
                "configuration_id": spec.configuration_id,
                "return_url": spec.return_url,
            },
            idempotency_key=ref,
        )
        _require(
            not old or old["request"] == request.model_dump(mode="json", by_alias=True),
            "PAYMENT_UPDATE_REQUEST_CHANGED",
        )
        doc = {
            **(old or {}),
            "schema": SCHEMA,
            "binding": self.recovery.binding,
            "status": "RUNNING",
            "phase": "posting",
            "spec": spec.to_dict(),
            "request": request.model_dump(mode="json", by_alias=True),
            "invoice_observation_digest": snapshot["observation"]["observation_digest"],
        }
        self.recovery._write(ref, doc, old, fence)
        try:
            result = ConnectorExecutionResult.model_validate(
                detached(self.executor.execute(request))
            )
        except Exception:
            return {
                "status": "reconciliation_required",
                "request_ref": spec.request_ref,
                "payment_confirmed": False,
            }
        return self.reconcile(spec, result, now=now, fence=fence)

    def reconcile(self, spec, result, *, now, fence):
        spec = PaymentUpdateRequest.model_validate(spec)
        ref = self._ref(spec)
        old = self.recovery._read(ref, SCHEMA)
        _require(
            old is not None and old["spec"] == spec.to_dict(), "PAYMENT_UPDATE_REQUEST_NOT_RETAINED"
        )
        request = ConnectorExecutionRequest.model_validate(old["request"])
        result = ConnectorExecutionResult.model_validate(detached(result))
        _require(result.tool == TOOL, "PAYMENT_UPDATE_TOOL_MISMATCH")
        if result.status.value != "completed":
            if result.status.value == "pending_approval":
                _require(old["phase"] != "completed", "PAYMENT_UPDATE_RESULT_CHANGED")
                self.recovery._write(
                    ref,
                    {**old, "phase": "awaiting_approval", "approval_ref": result.approval_ref},
                    old,
                    fence,
                )
                return {
                    "status": "pending_approval",
                    "approval_ref": result.approval_ref,
                    "payment_confirmed": False,
                }
            return {
                "status": "reconciliation_required",
                "request_ref": spec.request_ref,
                "payment_confirmed": False,
            }
        receipt = execution_receipt_from_connector(result, request)
        _require(
            receipt.effect == "write"
            and receipt.connector_account_ref == request.connector_account_ref
            and receipt.project_id == str(request.scope.project_id)
            and bool(receipt.approval_ref)
            and bool(receipt.approval_receipt_digest)
            and receipt.receipt_digest != "0" * 64
            and receipt.route_digest != "0" * 64
            and parsed(receipt.completed_at) <= parsed(now),
            "PAYMENT_UPDATE_APPROVED_RECEIPT_REQUIRED",
        )
        output = result.output
        if output.get("schema") == "lightbulb.governed_connector_output_commitment.v1":
            digest = output.get("provider_output_sha256")
            _require(
                set(output) == {"schema", "provider_output_sha256"}
                and isinstance(digest, str)
                and len(digest) == 64
                and set(digest) <= set("0123456789abcdef"),
                "PAYMENT_UPDATE_COMMITMENT_INVALID",
            )
            self._retain_completion(ref, old, receipt, digest, fence)
            return self.status(spec, now=now)
        url = urlsplit(output.get("url", ""))
        _require(
            output.get("schema") == "lightbulb.stripe_payment_update_session.v1"
            and output.get("customer") == request.arguments["customer_id"]
            and output.get("invoice_id") == spec.invoice_ref
            and output.get("configuration") == spec.configuration_id
            and output.get("flow_type") == "payment_method_update"
            and output.get("payment_confirmed") is False
            and url.scheme == "https"
            and url.hostname == "billing.stripe.com"
            and url.port in (None, 443)
            and url.username is None
            and url.password is None
            and not url.fragment
            and (url.path == "/p/session" or url.path.startswith("/p/session/"))
            and len(output["url"]) <= 2048,
            "PAYMENT_UPDATE_RESULT_MISMATCH",
        )
        self._retain_completion(ref, old, receipt, stable_digest(output), fence)
        # Reconcile even after an invoice changes, but withhold the private link.
        status = self.status(spec, now=now)
        if status["invoice_status"] == "open":
            self._current(spec, now)
            if 0 <= (parsed(now) - parsed(receipt.completed_at)).total_seconds() <= 600:
                return {
                    **status,
                    "private_payment_update_url": output["url"],
                    "retention": "ephemeral_response_only",
                }
        return status

    def _retain_completion(self, ref, old, receipt, output_digest, fence):
        commitment = {"receipt": receipt.to_dict(), "output_digest": output_digest}
        if old.get("verified"):
            previous = old["verified"]
            core = lambda value: {
                k: v for k, v in value.items() if k not in {"output_digest", "execution_digest"}
            }
            _require(
                previous["output_digest"] == output_digest
                and core(previous["receipt"]) == core(receipt.to_dict()),
                "PAYMENT_UPDATE_RESULT_CHANGED",
            )
            return
        self.recovery._write(
            ref,
            {**old, "phase": "completed", "status": "COMPLETED", "verified": commitment},
            old,
            fence,
        )

    def status(self, spec, *, now):
        spec = PaymentUpdateRequest.model_validate(spec)
        old = self.recovery._read(self._ref(spec), SCHEMA)
        _require(not old or old["spec"] == spec.to_dict(), "PAYMENT_UPDATE_REQUEST_CHANGED")
        snapshot = self.recovery.invoice_snapshot(spec.invoice_ref)
        current = bool(
            snapshot
            and snapshot["present"]
            and 0
            <= (parsed(now) - parsed(snapshot["observation"]["observed_at"])).total_seconds()
            <= self.coordinator.policy.max_observation_age_seconds
        )
        invoice_status = snapshot["invoice"]["status"] if current else "unverified"
        return {
            "request_ref": spec.request_ref,
            "status": (
                "not_started"
                if not old
                else (
                    "session_created"
                    if old["phase"] == "completed"
                    else (
                        "pending_approval"
                        if old["phase"] == "awaiting_approval"
                        else "reconciliation_required"
                    )
                )
            ),
            "invoice_status": invoice_status,
            "payment_confirmed": invoice_status == "paid",
            "payment_evidence_digest": (
                snapshot["observation"]["observation_digest"] if invoice_status == "paid" else None
            ),
            "retries_owner": "stripe",
            "automatic_send_authorized": False,
        }
