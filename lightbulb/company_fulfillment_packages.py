"""Concrete fulfillment recipes that use the existing approved commerce journal."""

from typing import Literal
import re
from importlib.resources import files
from datetime import timezone
from uuid import UUID
from pydantic import model_validator
from lightbulb.company_engine_core import StrictModel, parsed
from lightbulb.company_customer_commerce import (
    CustomerFulfillmentPlan,
    CustomerDestinationIdentityReview,
)


class CustomerFulfillmentPackage(StrictModel):
    kind: Literal["repository_access", "digital_file", "service_onboarding", "saas_workspace"]
    plan: CustomerFulfillmentPlan
    identity_attribution: Literal["operator_reviewed", "provider_customer_reference"]

    @classmethod
    def repository_access(
        cls,
        *,
        connector_account_ref,
        account_ref,
        username,
        owner,
        repository,
        evidence_refs,
        deadline_at,
    ):
        """Invite an existing GitHub identity to read a repository; activation requires acceptance."""
        username = username.lower()
        args = {"owner": owner, "repository": repository, "username": username}
        return cls._mapped(
            "repository_access",
            "github.provision_repository_access",
            "github.get_repository_access",
            connector_account_ref,
            account_ref,
            username,
            evidence_refs,
            deadline_at,
            args,
            {"permission": "read"},
        )

    @classmethod
    def digital_file(
        cls, *, connector_account_ref, account_ref, email, file_id, evidence_refs, deadline_at
    ):
        """Grant a named Google Drive user reader access without sending notification mail."""
        email = email.lower()
        return cls._mapped(
            "digital_file",
            "drive.deliver_file_access",
            "drive.get_delivered_file_access",
            connector_account_ref,
            account_ref,
            email,
            evidence_refs,
            deadline_at,
            {"file_id": file_id, "email": email},
            {"file_id": file_id, "permission": "reader"},
        )

    @classmethod
    def repository_revocation(cls, **arguments):
        package = cls.repository_access(**arguments)
        plan = package.plan.to_dict()
        plan["write_tool"] = "github.revoke_repository_access"
        plan["expected_fields"].update(permission="none", access_active=False)
        return cls(kind="repository_access", identity_attribution="operator_reviewed", plan=plan)

    @staticmethod
    def saas_application_schema() -> str:
        """Versioned SQL for installation in the customer's application database.

        The application must integrate authenticated invitation acceptance and
        per-request feature authorization; these are not Lightbulb login accounts.
        """
        return files("lightbulb").joinpath("sql/customer_saas_v1.sql").read_text(encoding="utf-8")

    @classmethod
    def saas_workspace(
        cls,
        *,
        connector_account_ref,
        account_ref,
        application_id,
        customer_ref,
        workspace_ref,
        email,
        plan_ref,
        features,
        seat_limit,
        action_ref,
        invitation_expires_at,
        deadline_at,
        evidence_refs,
        expected_revision=0,
        action: Literal["create", "configure", "invite", "suspend", "reactivate"] = "create",
    ):
        """Propose an exact app workspace change; fulfillment requires member readback.

        Creation/invitation queues an application-owned invitation record. Only the
        application's trusted identity service can accept it for a verified email.
        No bearer token or notification delivery is created by this package.
        Every subsequent change requires the destination's current revision.
        """
        application_id = str(UUID(str(application_id)))
        if not isinstance(features, (list, tuple)) or any(not isinstance(f, str) for f in features):
            raise ValueError("SAAS_FEATURES_INVALID")
        features = sorted(features)
        if action not in {"create", "configure", "invite", "suspend", "reactivate"}:
            raise ValueError("SAAS_ACTION_INVALID")
        if any(
            not isinstance(value, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}", value)
            for value in (customer_ref, workspace_ref, plan_ref, action_ref)
        ):
            raise ValueError("SAAS_REFERENCE_INVALID")
        if (
            type(seat_limit) is not int
            or not 1 <= seat_limit <= 100000
            or type(expected_revision) is not int
            or not 0 <= expected_revision <= 9223372036854775807
            or (action == "create") != (expected_revision == 0)
        ):
            raise ValueError("SAAS_LIMIT_OR_REVISION_INVALID")
        if (
            len(features) > 20
            or len(set(features)) != len(features)
            or any(
                not isinstance(feature, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", feature)
                for feature in features
            )
        ):
            raise ValueError("SAAS_FEATURES_INVALID")
        if not isinstance(email, str):
            raise ValueError("SAAS_EMAIL_INVALID")
        email = email.lower()
        if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("SAAS_EMAIL_INVALID")
        expires = parsed(invitation_expires_at).astimezone(timezone.utc).isoformat()
        arguments = dict(
            application_id=application_id,
            action=action,
            action_ref=action_ref,
            customer_ref=customer_ref,
            workspace_ref=workspace_ref,
            email=email,
            plan_ref=plan_ref,
            features=features,
            seat_limit=seat_limit,
            expected_revision=expected_revision,
            invitation_expires_at=expires,
        )
        return cls(
            kind="saas_workspace",
            identity_attribution="operator_reviewed",
            plan=CustomerFulfillmentPlan(
                connector_account_ref=connector_account_ref,
                write_tool="postgresql.apply_customer_workspace",
                write_arguments=arguments,
                verification_tool="postgresql.get_customer_workspace",
                verification_arguments=dict(
                    application_id=application_id,
                    workspace_ref=workspace_ref,
                    customer_ref=customer_ref,
                    email=email,
                ),
                customer_identity_field="customer_identity",
                customer_identity_value=customer_ref,
                expected_fields=dict(
                    application_id=application_id,
                    customer_identity=customer_ref,
                    member_email=email,
                    plan_ref=plan_ref,
                    features=features,
                    seat_limit=seat_limit,
                    status="suspended" if action == "suspend" else "active",
                    access_active=action != "suspend",
                ),
                destination_identity_review=CustomerDestinationIdentityReview(
                    account_ref=account_ref,
                    provider_identity=customer_ref,
                    evidence_refs=evidence_refs,
                ),
                deadline_at=deadline_at,
            ),
        )

    @classmethod
    def service_onboarding(
        cls, *, connector_account_ref, customer_ref, data_source_id, title, due_at, deadline_at
    ):
        """Create a Notion service page with persisted customer, title and delivery due date."""
        source = str(UUID(str(data_source_id)))
        due = (
            parsed(due_at)
            .astimezone(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        return cls(
            kind="service_onboarding",
            identity_attribution="provider_customer_reference",
            plan=CustomerFulfillmentPlan(
                connector_account_ref=connector_account_ref,
                write_tool="notion.create_service_onboarding",
                write_arguments={
                    "data_source_id": source,
                    "customer_ref": customer_ref,
                    "title": title,
                    "due_at": due,
                },
                verification_tool="notion.get_service_onboarding",
                verification_arguments={"data_source_id": source, "customer_ref": customer_ref},
                customer_identity_field="customer_identity",
                customer_identity_value=customer_ref,
                expected_fields={
                    "customer_identity": customer_ref,
                    "data_source_id": source,
                    "title": title,
                    "due_at": due,
                    "access_active": True,
                },
                deadline_at=deadline_at,
            ),
        )

    @classmethod
    def _mapped(
        cls, kind, write, read, connector, account, identity, evidence, deadline, args, expected
    ):
        return cls(
            kind=kind,
            identity_attribution="operator_reviewed",
            plan=CustomerFulfillmentPlan(
                connector_account_ref=connector,
                write_tool=write,
                write_arguments=args,
                verification_tool=read,
                verification_arguments=args,
                customer_identity_field="customer_identity",
                customer_identity_value=identity,
                expected_fields={**expected, "customer_identity": identity, "access_active": True},
                destination_identity_review=CustomerDestinationIdentityReview(
                    account_ref=account, provider_identity=identity, evidence_refs=evidence
                ),
                deadline_at=deadline,
            ),
        )

    @model_validator(mode="after")
    def deadline(self):
        if self.plan.deadline_at is None:
            raise ValueError("FULFILLMENT_PACKAGE_DEADLINE_REQUIRED")
        parsed(self.plan.deadline_at)
        return self


class CompanyCustomerFulfillment:
    """Observe deadlines and retry only authoritative readback, never an uncertain write."""

    def __init__(self, commerce):
        self.commerce = commerce

    def observe(self, offer_ref, *, now, fence):
        row = self.commerce.events.read(self.commerce.ref(offer_ref))
        if not row:
            raise ValueError("CUSTOMER_OFFER_REQUIRED")
        plan = CustomerFulfillmentPlan.model_validate(row["offer"]["fulfillment"])
        phase = row.get("fulfillment", {}).get("phase")
        overdue = plan.deadline_at is not None and parsed(now) >= parsed(plan.deadline_at)
        if phase == "written":
            # Reconciliation remains available after the delivery deadline.
            self.commerce.verify_fulfillment(offer_ref, now=now, fence=fence)
        status = self.commerce.status(offer_ref)
        phase = status.get("fulfillment_status", phase)
        return {
            "commerce": status,
            "deadline_at": plan.deadline_at,
            "deadline_passed": overdue,
            "recovery": (
                "reconcile_receipt"
                if phase == "posting"
                else "readback" if phase == "written" else "none"
            ),
            "identity_attribution": (
                "operator_reviewed"
                if plan.destination_identity_review
                else "provider_customer_reference"
            ),
        }
