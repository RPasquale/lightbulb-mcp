import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from pydantic import BaseModel
from lightbulb.primitive_runtime import (
    FunctionBusinessProcessPrimitive,
    PrimitiveRegistry,
)
from lightbulb.project_runtime import (
    LightbulbProject,
    ProjectWorkflow,
    ProjectWorkflowStep,
    ProjectRuntime,
)
from lightbulb.connector_execution import InMemoryConnectorExecutor
from test_workflow_learning import task, populate
from lightbulb.learning import WorkflowLearner


class IntegrationTests(unittest.TestCase):
    def test_concrete_output_survives_chained_runtime_binding(self):
        class Value(BaseModel):
            value: int

        a = FunctionBusinessProcessPrimitive(
            primitive_ref="test.a",
            title="A",
            input_model=Value,
            output_model=Value,
            handler=lambda ctx, x: Value(value=x.value + 1),
        )
        b = FunctionBusinessProcessPrimitive(
            primitive_ref="test.b",
            title="B",
            input_model=Value,
            output_model=Value,
            handler=lambda ctx, x: Value(value=x.value * 2),
        )
        project = LightbulbProject(
            project_ref="test",
            name="Binding regression",
            primitive_refs=["test.a", "test.b"],
            workflows=[
                ProjectWorkflow(
                    key="run",
                    title="Run",
                    entry_step="a",
                    steps=[
                        ProjectWorkflowStep(
                            id="a", primitive_ref="test.a", next_step="b"
                        ),
                        ProjectWorkflowStep(
                            id="b",
                            primitive_ref="test.b",
                            input_mapping={"*": "$steps.a.output"},
                        ),
                    ],
                )
            ],
        )
        receipt = ProjectRuntime(
            project, PrimitiveRegistry([a, b]), InMemoryConnectorExecutor()
        ).run_workflow(
            "run",
            {"value": 3},
            tenant_ref="test",
            company_ref="test",
            preview_only=False,
        )
        self.assertEqual(receipt.status.value, "completed")
        self.assertEqual(receipt.step_runs[-1].result.output.value, 8)

    def test_late_feedback_and_recovery(self):
        with tempfile.TemporaryDirectory() as folder:
            with WorkflowLearner(
                Path(folder) / "db",
                tenant="t",
                company="c",
                workflow="w",
                task=task(max_rows=400),
            ) as l:
                populate(l)
                r = l.learn()
                l.promote(r["version"], approved=True)
                f = {"size": 1, "tier": "normal"}
                self.assertEqual(l.predict(f)["nominal_coverage"], 0.9)
                self.assertEqual(l.predict(f)["interval_type"], "prediction")
                for i in range(40):
                    p = l.observe(
                        "late" + str(i), unit="late" + str(i), features=f, at=5000 + i
                    )
                populate(l, n=40, start=600)
                self.assertEqual(l.monitor()["status"], "healthy")
                # Older decisions resolving after the previous monitoring tick must count.
                for i in range(40):
                    l.resolve(
                        "late" + str(i),
                        p["value"] + 100,
                        at=10000 + i,
                        source="late fixture",
                    )
                self.assertEqual(l.monitor()["status"], "suspended")
                populate(l, n=400, start=1100, shift=100)
                replacement = l.learn()
                self.assertTrue(replacement["passed"])
                l.promote(replacement["version"], approved=True)
                self.assertGreater(l.predict(f)["value"], 100)
                with self.assertRaises(ValueError):
                    l.rollback(r["version"], approved=True)

    def test_estimator_failures_keep_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            with WorkflowLearner(
                Path(folder) / "db", tenant="t", company="c", workflow="w", task=task()
            ) as l:
                populate(l)
                with patch(
                    "lightbulb.learning.models.fit",
                    side_effect=ValueError("fixture failure"),
                ):
                    r = l.learn()
                self.assertEqual(r["selected"], "baseline")
                self.assertFalse(r["passed"])
                self.assertEqual(len(r["failures"]), 4)
                self.assertEqual(
                    l.predict({"size": 1, "tier": "normal"})["status"], "fallback"
                )

    def test_synthetic_data_reproducible_and_outcomes_separate(self):
        path = Path(__file__).parents[1] / "examples/workflow_learning/synthetic.py"
        spec = importlib.util.spec_from_file_location("synthetic_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            a = module.generate(Path(folder) / "a", n=30)
            b = module.generate(Path(folder) / "b", n=30)
            self.assertEqual(a["files"], b["files"])
            self.assertEqual(len(a["workflows"]), 6)
            events = [
                json.loads(x)
                for x in (Path(folder) / "a/events.jsonl").read_text().splitlines()
            ]
            for e in events:
                if e["type"] == "decision":
                    self.assertNotIn("value", e)


if __name__ == "__main__":
    unittest.main()
