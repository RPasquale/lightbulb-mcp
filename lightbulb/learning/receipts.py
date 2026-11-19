"""Explicit outcome joins to canonical Project Runtime receipts.

The caller supplies trusted runtime scope, not scope extracted by an LLM. A
completed software step is not automatically a successful business outcome.
"""

from dataclasses import dataclass

from .engine import fingerprint


@dataclass(frozen=True)
class ReceiptBinding:
    project_ref: str
    workflow_key: str
    definition_digest: str
    decision_step: str
    outcome_step: str
    outcome_field: str

    @classmethod
    def from_project(
        cls, project, *, workflow_key, decision_step, outcome_step, outcome_field
    ):
        workflows = [w for w in project.workflows if w.key == workflow_key]
        if len(workflows) != 1:
            raise ValueError("Expected one declared workflow")
        steps = {s.id for s in workflows[0].steps}
        if decision_step not in steps or outcome_step not in steps:
            raise ValueError("Learning steps must belong to the declared workflow")
        if not isinstance(outcome_field, str) or not outcome_field:
            raise ValueError("An explicit numeric business outcome field is required")
        return cls(
            project.project_ref,
            workflow_key,
            fingerprint(project.model_dump(mode="json", by_alias=True)),
            decision_step,
            outcome_step,
            outcome_field,
        )

    def decision_id(self, run_ref, *, visit=1):
        if (
            not isinstance(run_ref, str)
            or not run_ref
            or type(visit) is not int
            or visit < 1
        ):
            raise ValueError("Run identity and positive visit required")
        return fingerprint({"binding": self.__dict__, "run": run_ref, "visit": visit})

    def observe(self, learner, *, scope, run_ref, unit, features, at, visit=1):
        self._scope(learner, scope)
        return learner.observe(
            self.decision_id(run_ref, visit=visit),
            unit=unit,
            features=features,
            at=at,
            action={"binding": self.__dict__, "run": run_ref, "visit": visit},
        )

    def _scope(self, learner, scope):
        expected = learner.identity
        if (scope.tenant_ref, scope.company_ref, scope.project_ref) != (
            expected["tenant"],
            expected["company"],
            self.project_ref,
        ) or expected["workflow"] != self.project_ref:
            raise ValueError("Trusted execution scope differs from the learner binding")

    def resolve(
        self,
        learner,
        receipt,
        *,
        scope,
        project,
        at,
        preview_only,
        decision_visit=1,
        outcome_visit=1,
    ):
        """Join only an explicit completed outcome; paused/preview runs stay unresolved.

        Visits are explicit because a looping workflow may produce several valid
        outcomes. Retries within a visit use the latest completed attempt.
        """
        self._scope(learner, scope)
        # Pure computation primitives may report completed even during a preview.
        # The runtime invocation mode is therefore mandatory trusted context.
        if type(preview_only) is not bool:
            raise ValueError("Explicit runtime preview mode required")
        if preview_only:
            return False
        if (
            fingerprint(project.model_dump(mode="json", by_alias=True))
            != self.definition_digest
        ):
            raise ValueError(
                "Workflow definition changed; create a new binding/task version"
            )
        if (receipt.project_ref, receipt.workflow_key) != (
            self.project_ref,
            self.workflow_key,
        ):
            raise ValueError("Receipt belongs to another project or workflow")
        if receipt.status.value != "completed":
            return False
        decisions = [
            s
            for s in receipt.step_runs
            if s.step_id == self.decision_step
            and s.step_visit == decision_visit
            and s.status.value == "completed"
        ]
        outcomes = [
            s
            for s in receipt.step_runs
            if s.step_id == self.outcome_step
            and s.step_visit == outcome_visit
            and s.status.value == "completed"
        ]
        if not decisions or not outcomes:
            return False
        selected = max(outcomes, key=lambda s: (s.attempt, s.invocation))
        if selected.result.unresolved_operation_receipts():
            return False
        output = selected.result.output
        payload = (
            output.model_dump(mode="json") if hasattr(output, "model_dump") else output
        )
        if not isinstance(payload, dict) or self.outcome_field not in payload:
            raise ValueError("Completed receipt lacks the declared outcome field")
        return learner.resolve(
            self.decision_id(receipt.run_ref, visit=decision_visit),
            payload[self.outcome_field],
            at=at,
            source="project-receipt:" + fingerprint(receipt.to_dict()),
        )
