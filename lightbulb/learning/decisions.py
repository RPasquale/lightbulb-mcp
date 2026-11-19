"""Cost-sensitive recommendations bounded by a developer's explicit local policy.

These values may select a local workflow branch. They never authorize a Tool,
connector write, hosted operation, or change a Spring approval decision.
"""

import hashlib
import json
import math
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class BinaryDecisionPolicy:
    negative_action: str
    positive_action: str
    false_positive_cost: float
    false_negative_cost: float
    use: str = "context"
    approved_routes: tuple[str, ...] = ()
    pinned_model_version: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "approved_routes", tuple(self.approved_routes))
        if (
            not self.negative_action
            or not self.positive_action
            or self.negative_action == self.positive_action
        ):
            raise ValueError("Two distinct explicit actions required")
        for cost in (self.false_positive_cost, self.false_negative_cost):
            if isinstance(cost, bool) or not math.isfinite(cost) or cost < 0:
                raise ValueError("Nonnegative finite costs required")
        if self.false_positive_cost + self.false_negative_cost <= 0:
            raise ValueError("At least one error must have a positive cost")
        if self.use not in ("context", "recommend", "route"):
            raise ValueError("Unknown permitted use")
        if self.use == "route" and set(self.approved_routes) != {
            self.negative_action,
            self.positive_action,
        }:
            raise ValueError("Routing needs an explicit approved local route allowlist")

    def decide(self, prediction):
        p = prediction["value"]
        if isinstance(p, bool) or not math.isfinite(p) or not 0 <= p <= 1:
            raise ValueError("Finite binary probability required")
        digest = hashlib.sha256(
            json.dumps(asdict(self), sort_keys=True).encode()
        ).hexdigest()
        negative_loss = p * self.false_negative_cost
        positive_loss = (1 - p) * self.false_positive_cost
        action = (
            self.positive_action
            if positive_loss < negative_loss
            else self.negative_action
        )
        valid = prediction.get("status") == "learned" and bool(
            prediction.get("version")
        )
        if self.pinned_model_version is not None:
            valid = valid and prediction.get("version") == self.pinned_model_version
        return {
            "policy": digest,
            "probability": p,
            "threshold": self.false_positive_cost
            / (self.false_positive_cost + self.false_negative_cost),
            "expected_costs": {
                self.negative_action: negative_loss,
                self.positive_action: positive_loss,
            },
            "recommendation": action if self.use != "context" and valid else None,
            "route": action if self.use == "route" and valid else None,
            "model_version": prediction.get("version"),
            "external_action_authorized": False,
            "reason": "Cost-sensitive classification, not an estimated causal treatment effect",
        }
