"""Coordinate customer communication across the owners in one company worker."""

from datetime import timedelta
from pydantic import Field
from lightbulb.company_engine_core import StrictModel, parsed, stable_digest
from lightbulb.company_customer_events import CompanyCustomerEvents, require


class CustomerActionPolicy(StrictModel):
    max_touches_per_day: int = Field(default=1, ge=1, le=10, strict=True)
    minimum_gap_seconds: int = Field(default=86400, ge=60, le=604800, strict=True)
    priorities: tuple[str, ...] = (
        "billing_recovery",
        "renewal",
        "activation",
        "acquisition",
        "expansion",
        "winback",
    )

    def validate_priorities(self):
        require(
            set(self.priorities)
            == {
                "billing_recovery",
                "renewal",
                "activation",
                "acquisition",
                "expansion",
                "winback",
            }
            and len(self.priorities) == 6,
            "CUSTOMER_ACTION_PRIORITIES_INVALID",
        )
        return self


class CompanyCustomerActions:
    def __init__(self, sales):
        self.sales = sales
        self.events = CompanyCustomerEvents(sales.runner, sales.gateway)
        self.policy = sales.configuration.customer_actions.validate_priorities()

    def ref(self, binding):
        return self.events.prefix + "-contact-" + stable_digest(binding.account_ref)

    def ordered(self, bindings):
        return sorted(
            bindings,
            key=lambda b: (self.policy.priorities.index(b.purpose), b.binding_ref),
        )

    def observe(self, binding, observation, *, fence):
        # Only called with the minimized result of the host's governed thread read.
        require(
            observation.binding_digest == stable_digest(binding.to_dict()),
            "CUSTOMER_REPLY_BINDING_MISMATCH",
        )
        if observation.disposition == "no_reply":
            return

        def retain(doc):
            if not doc.get("hold"):
                doc["hold"] = {
                    "owner_binding_ref": binding.binding_ref,
                    "thread_ref": binding.thread_ref,
                    "disposition": observation.disposition,
                    "observed_at": observation.observed_at,
                    "evidence_digest": observation.execution_digest,
                }

        self.events.change(self.ref(binding), retain, fence)

    def reserve(self, binding, touch_ref, *, now, fence):
        existing = self.events.read(self.ref(binding)) or {}
        require(not existing.get("hold"), "CUSTOMER_ACTION_REPLY_OWNED")
        require(
            all(
                ref == touch_ref or slot["phase"] == "completed"
                for ref, slot in existing.get("slots", {}).items()
            ),
            "CUSTOMER_ACTION_UNRESOLVED",
        )
        siblings = [
            b
            for b in self.sales.configuration.all_bindings()
            if b.account_ref == binding.account_ref
        ]
        legacy = self._retained_touches(siblings, now=now)
        if len(siblings) > 1:
            observations = []
            for sibling in siblings:
                observation = self.sales._observe(
                    sibling, now=self.sales._now(now), fence=fence
                )
                self.observe(sibling, observation, fence=fence)
                observations.append(observation)
            now = self.sales._now(now)
            require(
                all(
                    0 <= (parsed(now) - parsed(o.observed_at)).total_seconds() <= 60
                    for o in observations
                ),
                "CUSTOMER_ACTION_THREAD_READ_STALE",
            )

        def update(doc):
            require(not doc.get("hold"), "CUSTOMER_ACTION_REPLY_OWNED")
            digest = stable_digest(self.policy.to_dict())
            require(
                not doc.get("policy_digest") or doc["policy_digest"] == digest,
                "CUSTOMER_ACTION_POLICY_CHANGED",
            )
            slots = dict(doc.get("slots", {}))
            for ref, slot in legacy.items():
                slots.setdefault(ref, slot)
            if touch_ref in slots:
                require(
                    slots[touch_ref]["binding_digest"]
                    == stable_digest(binding.to_dict()),
                    "CUSTOMER_ACTION_CHANGED",
                )
                doc["slots"] = slots
                return
            for slot in slots.values():
                require(slot["phase"] == "completed", "CUSTOMER_ACTION_UNRESOLVED")
                elapsed = (parsed(now) - parsed(slot["completed_at"])).total_seconds()
                require(
                    elapsed >= self.policy.minimum_gap_seconds,
                    "CUSTOMER_ACTION_COOLDOWN",
                )
            recent = [
                slot
                for slot in slots.values()
                if parsed(slot["completed_at"]) > parsed(now) - timedelta(days=1)
            ]
            require(
                len(recent) < self.policy.max_touches_per_day,
                "CUSTOMER_ACTION_DAILY_LIMIT",
            )
            # Only completed slots outside every configured window may be compacted.
            slots = {
                ref: slot
                for ref, slot in slots.items()
                if parsed(slot["completed_at"]) > parsed(now) - timedelta(days=7)
            }
            require(len(slots) < 100, "CUSTOMER_ACTION_CAPACITY")
            slots[touch_ref] = {
                "binding_digest": stable_digest(binding.to_dict()),
                "binding_ref": binding.binding_ref,
                "purpose": binding.purpose,
                "phase": "reserved",
                "reserved_at": now,
            }
            doc.update(slots=slots, policy_digest=digest)

        return self.events.change(self.ref(binding), update, fence)

    def _retained_touches(self, bindings, *, now):
        """Adopt canonical applied history without counting an existing slot twice."""
        from lightbulb.company_sales_host import TOUCH_SCHEMA

        slots = {}
        for binding in bindings:
            if (
                self.sales.runner.store.get("pipeline_engine", binding.prospect_ref)
                is None
            ):
                continue
            state = self.sales._state(
                binding
            )  # validates exact plan, scope and sequence
            for transition in state.transition_history:
                command = transition.command
                if command.event != "touch":
                    continue
                if parsed(command.occurred_at) <= parsed(now) - timedelta(days=7):
                    continue
                ref = self.sales._ref(binding) + "-" + str(command.receipt.step)
                record = self.sales._read(ref, TOUCH_SCHEMA)
                if record:
                    require(
                        record["binding"] == binding.to_dict()
                        and record.get("command") == command.to_dict(),
                        "CUSTOMER_ACTION_APPLIED_EFFECT_MISMATCH",
                    )
                slots[ref] = {
                    "binding_digest": stable_digest(binding.to_dict()),
                    "binding_ref": binding.binding_ref,
                    "purpose": binding.purpose,
                    "phase": "completed",
                    "completed_at": command.occurred_at,
                    "effect_digest": stable_digest(
                        record["effect"] if record else command.to_dict()
                    ),
                    "basis": "retained_pipeline_applied_touch",
                }
        return slots

    def complete(self, binding, touch_ref, *, fence):
        from lightbulb.company_sales_host import TOUCH_SCHEMA

        record = self.sales._read(touch_ref, TOUCH_SCHEMA)
        require(
            record and record.get("phase") == "applied",
            "CUSTOMER_ACTION_APPLIED_EFFECT_REQUIRED",
        )

        def update(doc):
            slots = dict(doc.get("slots", {}))
            # Historical applied effects may predate this coordinator.
            if touch_ref in slots:
                slot = dict(slots[touch_ref])
                slot.update(
                    phase="completed",
                    completed_at=record["effect"]["completed_at"],
                    effect_digest=stable_digest(record["effect"]),
                )
                slots[touch_ref] = slot
                doc["slots"] = slots

        self.events.change(self.ref(binding), update, fence)

    def reserve_conversation(self, binding, touch_ref, *, now, fence):
        """A reply owner may respond without releasing its account-wide hold."""
        legacy = self._retained_touches([b for b in self.sales.configuration.all_bindings()
            if b.account_ref == binding.account_ref], now=now)
        def update(doc):
            hold = doc.get("hold")
            require(hold and hold["owner_binding_ref"] == binding.binding_ref
                and hold["disposition"] == "reply", "CUSTOMER_ACTION_REPLY_OWNED")
            digest = stable_digest(self.policy.to_dict())
            require(not doc.get("policy_digest") or doc["policy_digest"] == digest,
                "CUSTOMER_ACTION_POLICY_CHANGED")
            slots = dict(doc.get("slots", {}))
            for key, value in legacy.items():
                slots.setdefault(key, value)
            if touch_ref in slots:
                require(slots[touch_ref]["binding_digest"] == stable_digest(binding.to_dict()), "CUSTOMER_ACTION_CHANGED")
                return
            for slot in slots.values():
                require(slot["phase"] == "completed", "CUSTOMER_ACTION_UNRESOLVED")
                require((parsed(now) - parsed(slot["completed_at"])).total_seconds() >= self.policy.minimum_gap_seconds,
                    "CUSTOMER_ACTION_COOLDOWN")
            require(sum(parsed(slot["completed_at"]) > parsed(now) - timedelta(days=1) for slot in slots.values())
                < self.policy.max_touches_per_day, "CUSTOMER_ACTION_DAILY_LIMIT")
            slots = {key: slot for key, slot in slots.items() if parsed(slot["completed_at"]) > parsed(now) - timedelta(days=7)}
            require(len(slots) < 100, "CUSTOMER_ACTION_CAPACITY")
            slots[touch_ref] = dict(binding_digest=stable_digest(binding.to_dict()), binding_ref=binding.binding_ref,
                purpose=binding.purpose, phase="reserved", reserved_at=now)
            doc.update(slots=slots, policy_digest=digest)
        return self.events.change(self.ref(binding), update, fence)

    def complete_conversation(self, binding, touch_ref, effect, *, fence):
        record = self.sales.progression.read(touch_ref)
        require(record and record.get("phase") == "sent" and record.get("effect") == effect.to_dict(),
            "CUSTOMER_ACTION_APPLIED_EFFECT_REQUIRED")
        def update(doc):
            slots = dict(doc.get("slots", {}))
            require(touch_ref in slots, "CUSTOMER_ACTION_RESERVATION_REQUIRED")
            slots[touch_ref] = {**slots[touch_ref], "phase": "completed", "completed_at": effect.completed_at,
                "effect_digest": stable_digest(effect.to_dict())}
            doc["slots"] = slots
        self.events.change(self.ref(binding), update, fence)

    def report(self):
        return {
            binding.account_ref: self.events.read(self.ref(binding))
            for binding in self.sales.configuration.all_bindings()
        }
