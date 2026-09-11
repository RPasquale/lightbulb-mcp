"""Evidence-bound customer turns through canonical Communication approval and delivery."""

from typing import Literal
from pydantic import Field
from lightbulb.company_engine_core import (
    StrictModel,
    OpaqueRef,
    Sha256Digest,
    stable_digest,
    seal,
    parsed,
)
from lightbulb.company_sales_progression import require, scoped_receipt
from lightbulb.company_sales_observations import sales_thread_observation, _addresses
from lightbulb.connector_execution import ConnectorExecutionRequest
from lightbulb.pipeline_execution import TouchRequest
from lightbulb.company_sales_communication import _effect


class CustomerConversationAction(StrictModel):
    action_ref: OpaqueRef
    binding_ref: OpaqueRef
    reply_proposal_ref: OpaqueRef
    reply_proposal_digest: Sha256Digest
    preparation_ref: OpaqueRef
    kind: Literal["answer", "objection", "question", "book", "purchase", "escalate"]
    subject: str = Field(min_length=1, max_length=998)
    body: str = Field(min_length=1, max_length=5000)
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    target_ref: OpaqueRef | None = None
    review_ref: OpaqueRef


class CustomerProgramMessage(StrictModel):
    action_ref: OpaqueRef
    preparation_ref: OpaqueRef
    review_ref: OpaqueRef
    subject: str = Field(min_length=1, max_length=998)


class CompanyCustomerConversations:
    """Agent proposes copy; exact source approval in Spring is always still required."""

    def __init__(self, progression):
        self.p, self.host = progression, progression.host

    def _program(self, kind):
        require(kind in {"trial_assistance", "referral_invitation"}, "CUSTOMER_PROGRAM_UNKNOWN")
        return self.p.trials if kind == "trial_assistance" else self.p.referrals

    def _program_thread(self, kind, program_ref, *, now, fence):
        evidence = self._program(kind).evaluate(program_ref, now=now, fence=fence)
        require(
            evidence["status"] in {"assistance_eligible", "invitation_eligible"},
            "CUSTOMER_PROGRAM_HELD",
        )
        binding = self.p.binding(evidence["binding_ref"])
        thread = self._thread(
            binding, now=now, fence=fence, recovery=True, since=evidence["baseline"]
        )
        return binding, thread, evidence

    def prepare_program(self, kind, program_ref, message, *, now, fence):
        message = CustomerProgramMessage.model_validate(message)
        binding, thread, evidence = self._program_thread(kind, program_ref, now=now, fence=fence)
        self.p.no_pending_delivery(binding)
        prepared = self.p.read(message.preparation_ref)
        require(
            prepared
            and prepared.get("review_required") is True
            and prepared.get("binding_digest") == stable_digest(binding.to_dict()),
            "CUSTOMER_PROGRAM_PREPARATION_REQUIRED",
        )
        draft = prepared.get("preparation", {}).get("response_draft")
        require(
            isinstance(draft, str)
            and 0 < len(draft) <= 5000
            and "\0" not in draft
            and "checkout.stripe.com" not in draft.lower()
            and not any(c in message.subject for c in "\r\n\0"),
            "CUSTOMER_PROGRAM_CONTENT_INVALID",
        )
        action = dict(
            kind=kind,
            program_ref=program_ref,
            binding_ref=binding.binding_ref,
            **message.to_dict(),
            body=draft,
            evidence_refs=[message.preparation_ref, self._program(kind).ref(program_ref)],
            program_evidence_digest=stable_digest(evidence)
        )
        ref = self.p.ref(binding, "conversation_action", message.action_ref)
        old = self.p.read(ref)
        if old:
            comparable = {k: v for k, v in action.items() if k != "program_evidence_digest"}
            require(
                comparable
                == {k: v for k, v in old["action"].items() if k != "program_evidence_digest"},
                "CUSTOMER_PROGRAM_MESSAGE_CHANGED",
            )
            return self._track(binding, ref, old, fence=fence)
        return self._freeze(binding, action, ref, thread, now=now, fence=fence, program=True)

    def _thread(self, binding, *, now, fence, recovery=False, since=None):
        request = ConnectorExecutionRequest(
            tool="gmail.get_thread",
            scope=self.host.scope,
            connector_account_ref=binding.connector_account_ref,
            arguments={"thread_id": binding.thread_ref, "max_messages": 10},
        )
        fence()
        result = self.host.executor.execute(request)
        now = self.host._now(now)
        scoped_receipt(result, request)
        observation = sales_thread_observation(
            request, result, binding=binding, scope=self.host.scope.model_dump(mode="json"), now=now
        )
        require(
            observation.disposition in ({"reply", "no_reply"} if recovery else {"reply"}),
            "CUSTOMER_CONVERSATION_REPLY_REQUIRED",
        )
        messages = result.output["messages"]
        last = messages[-1]
        headers = {k.lower(): v for k, v in last["headers"].items()}
        if recovery:
            require(since is not None, "CHECKOUT_RECOVERY_BASELINE_REQUIRED")
            require(
                all(
                    int(message["internalDate"]) <= since * 1000
                    for message in messages
                    if _addresses({k.lower(): v for k, v in message["headers"].items()}.get("from"))
                    == (binding.to_address.lower(),)
                ),
                "CHECKOUT_RECOVERY_NEW_REPLY",
            )
        else:
            require(
                _addresses(headers.get("from")) == (binding.to_address.lower(),)
                and _addresses(headers.get("to")) == (binding.from_address.lower(),),
                "CUSTOMER_CONVERSATION_CUSTOMER_TURN_REQUIRED",
            )
        parent = headers.get("messageid")
        import re

        require(
            isinstance(parent, str) and re.fullmatch(r"<[^<>@\s]+@[^<>@\s]+>", parent),
            "CUSTOMER_CONVERSATION_PARENT_REQUIRED",
        )
        if not recovery:
            self.host.customer_actions.observe(binding, observation, fence=fence)
        return {
            "conversation_digest": stable_digest({"messages": messages}),
            "reply_identity": stable_digest(
                {"thread_ref": binding.thread_ref, "message_id": last["id"]}
            ),
            "parent_message_id": parent,
        }

    def from_preparation(self, binding_ref, preparation_ref, *, action_ref, review_ref, now, fence):
        """Turn retained agent judgment into the exact proposal a user can review."""
        binding = self.p.binding(binding_ref)
        prepared = self.p.read(preparation_ref)
        require(
            prepared and prepared.get("binding_digest") == stable_digest(binding.to_dict()),
            "CUSTOMER_CONVERSATION_PREPARATION_REQUIRED",
        )
        draft = prepared.get("preparation", {})
        reply = self.p.propose_reply(binding_ref, now=now, fence=fence)
        action = CustomerConversationAction(
            action_ref=action_ref,
            binding_ref=binding_ref,
            reply_proposal_ref=reply["proposal_ref"],
            reply_proposal_digest=reply["proposal_digest"],
            preparation_ref=preparation_ref,
            kind=draft.get("response_kind", "answer"),
            subject="Re: Your inquiry",
            body=draft.get("response_draft", ""),
            evidence_refs=(preparation_ref, reply["proposal_ref"]),
            target_ref=draft.get("response_target_ref"),
            review_ref=review_ref,
        )
        return self.prepare(action, now=now, fence=fence)

    def prepare(self, action, *, now, fence):
        action = CustomerConversationAction.model_validate(action)
        binding = self.p.binding(action.binding_ref)
        self.p.no_pending_delivery(binding)
        require(
            not any(c in action.subject for c in "\r\n\0")
            and "\0" not in action.body
            and "checkout.stripe.com" not in action.body.lower(),
            "CUSTOMER_CONVERSATION_CONTENT_INVALID",
        )
        ref = self.p.ref(binding, "conversation_action", action.action_ref)
        old = self.p.read(ref)
        if old:
            require(old["action"] == action.to_dict(), "CUSTOMER_CONVERSATION_ACTION_CHANGED")
            return self._track(binding, ref, old, fence=fence)
        reply = self.p.propose_reply(binding.binding_ref, now=now, fence=fence)
        require(
            reply["proposal_ref"] == action.reply_proposal_ref
            and reply["proposal_digest"] == action.reply_proposal_digest,
            "CUSTOMER_CONVERSATION_REPLY_CHANGED",
        )
        prepared = self.p.read(action.preparation_ref)
        require(
            prepared and prepared.get("binding_digest") == stable_digest(binding.to_dict()),
            "CUSTOMER_CONVERSATION_PREPARATION_REQUIRED",
        )
        # Copy must be the retained agent-authored response; review refs cannot invent source evidence.
        draft = prepared.get("preparation", prepared.get("prepared", {})) or {}
        require(draft.get("response_draft") == action.body, "CUSTOMER_CONVERSATION_DRAFT_CHANGED")
        known = {action.reply_proposal_ref, action.preparation_ref}
        known.update(ref for f in draft.get("findings", []) for ref in f.get("source_refs", []))
        require(set(action.evidence_refs) <= known, "CUSTOMER_CONVERSATION_UNKNOWN_EVIDENCE")
        self._target(binding, action, now=now)
        thread = self._thread(binding, now=now, fence=fence)
        return self._freeze(binding, action.to_dict(), ref, thread, now=now, fence=fence)

    def _target(self, binding, action, *, now):
        if action.kind in {"book", "purchase", "escalate"}:
            require(action.target_ref is not None, "CUSTOMER_CONVERSATION_TARGET_REQUIRED")
        if action.kind == "book":
            target = self.p.read(action.target_ref)
            require(
                target
                and target.get("binding_digest") == stable_digest(binding.to_dict())
                and target.get("proposal_ref") == action.target_ref
                and target.get("phase") == "proposed"
                and target.get("customer_agreement_required") is True
                and bool(target.get("slots"))
                and all(parsed(slot) > parsed(now) for slot in target["slots"])
                and self.p.ref(binding, "meeting", target.get("request", {}).get("request_ref"))
                == action.target_ref,
                "CUSTOMER_CONVERSATION_MEETING_REQUIRED",
            )
        if action.kind == "purchase":
            candidates = [
                service.events.read(service.ref(action.target_ref))
                for service in (self.p.commerce, self.p.subscriptions)
            ]
            candidates = [candidate for candidate in candidates if candidate is not None]
            require(len(candidates) == 1, "CUSTOMER_CONVERSATION_OFFER_AMBIGUOUS")
            target = candidates[0]
            require(
                target
                and target.get("account_ref") == binding.account_ref
                and target.get("offer", {}).get("binding_ref") == binding.binding_ref
                and parsed(target["offer"]["expires_at"]) > parsed(now)
                and target.get("phase") in {"prepared", "awaiting_approval", "checkout_created"},
                "CUSTOMER_CONVERSATION_OFFER_REQUIRED",
            )

    def _freeze(self, binding, action, ref, thread, *, now, fence, recovery=False, program=False):
        state = self.host._state(binding)
        require(
            state.status in {"replied", "qualified", "meeting_booked", "handed_off"},
            "CUSTOMER_CONVERSATION_REVIEW_REQUIRED",
        )
        _, permission = self.host.intake._permission(binding, now=self.host._now(now))
        touch = seal(
            TouchRequest,
            dict(
                schema=(
                    "lightbulb.customer_program_touch.v1"
                    if program
                    else (
                        "lightbulb.customer_checkout_recovery_touch.v1"
                        if recovery or program
                        else "lightbulb.customer_conversation_touch.v1"
                    )
                ),
                prospect_ref=binding.prospect_ref,
                sequence_ref="conversation:" + thread["reply_identity"],
                step=1,
                channel="email",
                intent="ask",
                tool="gmail.send_email",
                not_before=now,
                subject=action["subject"],
                body=action["body"],
                claim_refs=list(action["evidence_refs"]),
                consent_ref=None,
                requires_approval=True,
                idempotency_key="conversation:" + thread["reply_identity"],
                arguments={
                    "to": binding.to_address,
                    "subject": action["subject"],
                    "body": action["body"],
                    "thread_id": binding.thread_ref,
                    "conversation_digest": thread["conversation_digest"],
                    "reply_identity": thread["reply_identity"],
                    "permission": {
                        "endpoint_digest": binding.endpoint_digest,
                        "eligibility_digest": permission.eligibility_digest,
                        "suppression_digest": permission.suppression_digest,
                    },
                },
                eligibility_receipt=permission.to_dict(),
                suppression_digest=permission.suppression_digest,
            ),
            "request_digest",
        )
        effective = binding.model_copy(update={"parent_message_id": thread["parent_message_id"]})
        row = self.p.write(
            ref,
            {
                "action": action,
                "binding_digest": stable_digest(binding.to_dict()),
                "effective_binding": effective.to_dict(),
                "thread": thread,
                "touch": touch.to_dict(),
                "source_state": state.to_dict(),
                "phase": "prepared",
                "review_required": True,
                "execution_authorized": False,
            },
            None,
            fence,
        )
        return self._track(binding, ref, row, fence=fence)

    def _track(self, binding, ref, row, *, fence):
        pointer = self.p.ref(binding, "active_conversation", "one")
        old = self.p.read(pointer)
        if old and old["action_ref"] != row["action"]["action_ref"]:
            prior = self.p.read(old["source_ref"])
            require(
                prior and prior.get("phase") in {"sent", "escalated"},
                "CUSTOMER_CONVERSATION_PENDING_ACTION",
            )
        if not old or old["source_ref"] != ref:
            self.p.write(
                pointer,
                {
                    "action_ref": row["action"]["action_ref"],
                    "source_ref": ref,
                    "binding_digest": stable_digest(binding.to_dict()),
                },
                old,
                fence,
            )
        return row

    def status(self, binding):
        pointer = self.p.read(self.p.ref(binding, "active_conversation", "one"))
        if pointer is None:
            return None
        require(
            pointer["binding_digest"] == stable_digest(binding.to_dict()),
            "CUSTOMER_CONVERSATION_BINDING_CHANGED",
        )
        row = self.p.read(pointer["source_ref"])
        require(row is not None, "CUSTOMER_CONVERSATION_PENDING_ACTION")
        return {
            "action_ref": pointer["action_ref"],
            "phase": row["phase"],
            "kind": row["action"]["kind"],
            "owner_ref": row.get("owner_ref"),
        }

    def advance_pending(self, binding, *, now, fence):
        status = self.status(binding)
        if status is None or status["phase"] == "escalated":
            return None
        if status["phase"] == "sent":
            ref = self.p.ref(binding, "conversation_action", status["action_ref"])
            journal = (
                self.host.customer_actions.events.read(self.host.customer_actions.ref(binding))
                or {}
            )
            if journal.get("slots", {}).get(ref, {}).get("phase") != "completed":
                self.step(status["action_ref"], binding.binding_ref, now=now, fence=fence)
            return None
        row = self.step(status["action_ref"], binding.binding_ref, now=now, fence=fence)
        return {
            "prospect_ref": binding.prospect_ref,
            "action_ref": status["action_ref"],
            "status": "sent" if row["phase"] == "sent" else row.get("last_status", "pending"),
            "conversation_phase": row["phase"],
        }

    def step(self, action_ref, binding_ref, *, now, fence):
        binding = self.p.binding(binding_ref)
        ref = self.p.ref(binding, "conversation_action", action_ref)
        row = self.p.read(ref)
        require(
            row and row["binding_digest"] == stable_digest(binding.to_dict()),
            "CUSTOMER_CONVERSATION_UNKNOWN",
        )
        if row["phase"] == "sent":
            from lightbulb.company_sales_communication import SalesTouchEffect

            self.host.customer_actions.complete_conversation(
                binding, ref, SalesTouchEffect.model_validate(row["effect"]), fence=fence
            )
            return row
        if row["action"]["kind"] == "escalate":
            if row["phase"] != "escalated":
                row = self.p.write(
                    ref,
                    {
                        **row,
                        "phase": "escalated",
                        "owner_ref": row["action"]["target_ref"],
                        "handoff_state": "awaiting_owner",
                        "external_dispatch": False,
                    },
                    row,
                    fence,
                )
            return row
        allow = True
        try:
            self.p.no_pending_delivery(binding)
            if self.host.customer_lifecycle:
                self.host.customer_lifecycle.guard(binding, now=self.host._now(now), fence=fence)
            is_program = row["action"]["kind"] in {"trial_assistance", "referral_invitation"}
            if row["action"]["kind"] != "checkout_recovery" and not is_program:
                self._target(
                    binding,
                    CustomerConversationAction.model_validate(row["action"]),
                    now=self.host._now(now),
                )
            current_thread = (
                self._program_thread(
                    row["action"]["kind"], row["action"]["program_ref"], now=now, fence=fence
                )[1]
                if is_program
                else (
                    self.p.checkout_recovery.evaluate(
                        row["action"]["recovery"], now=now, fence=fence
                    )[2]
                    if row["action"]["kind"] == "checkout_recovery"
                    else self._thread(binding, now=now, fence=fence)
                )
            )
            require(current_thread == row["thread"], "CUSTOMER_CONVERSATION_REPLY_CHANGED")
            require(
                self.host._state(binding).state_digest == row["source_state"]["state_digest"],
                "CUSTOMER_CONVERSATION_STATE_CHANGED",
            )
            self.host.intake._permission(binding, now=self.host._now(now))
            contact = (
                self.host.customer_actions.events.read(self.host.customer_actions.ref(binding))
                or {}
            )
            if (
                row["action"]["kind"] == "checkout_recovery"
                or is_program
                and not contact.get("hold")
            ):
                self.host.customer_actions.reserve(
                    binding, ref, now=self.host._now(now), fence=fence
                )
            else:
                self.host.customer_actions.reserve_conversation(
                    binding, ref, now=self.host._now(now), fence=fence
                )
        except ValueError as error:
            from lightbulb.company_host_journal import HostAuthorityError

            if isinstance(error, HostAuthorityError):
                raise
            allow = False
        effective = binding.model_copy(
            update={"parent_message_id": row["thread"]["parent_message_id"]}
        )
        touch = TouchRequest.model_validate(row["touch"])
        # Freeze before a network request; retries reuse the same canonical admitted source.
        row = self.p.write(ref, {**row, "phase": "reconciling"}, row, fence)
        try:
            result = self.host.communication.step(
                effective,
                touch,
                state=row["source_state"],
                now=self.host._now(now),
                allow_dispatch=allow,
            )
        except Exception:
            return row
        if result["status"] == "sent":
            effect = _effect(touch, result, binding=effective, scope=self.host.authority_scope)
            require(
                parsed(effect.completed_at) <= parsed(self.host._now(now)),
                "CUSTOMER_CONVERSATION_FUTURE_EFFECT",
            )
            row = self.p.write(
                ref, {**row, "phase": "sent", "effect": effect.to_dict()}, row, fence
            )
            self.host.customer_actions.complete_conversation(binding, ref, effect, fence=fence)
        else:
            row = self.p.write(
                ref, {**row, "last_status": result["status"], "dispatch_allowed": allow}, row, fence
            )
        return row
