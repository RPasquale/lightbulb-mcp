import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
import numpy as np
from lightbulb.learning import Feature, LearningTask, WorkflowLearner
from lightbulb.learning import models


def task(kind="regression", **kw):
    return LearningTask(
        "delivery",
        "1",
        kind,
        (Feature("size"), Feature("tier", "category")),
        "actual_hours" if kind == "regression" else "failed",
        0,
        **kw,
    )


def populate(
    learner, n=400, start=0, shift=0, kind="regression", unit_count=None, delay=1
):
    rng = np.random.default_rng(51 + start)
    for i in range(start, start + n):
        x = float(rng.uniform(-3, 3))
        tier = "urgent" if i % 2 else "normal"
        y = 10 + 5 * x + 3 * (tier == "urgent") + shift + float(rng.normal(0, 0.25))
        if kind == "binary":
            y = int(x > 0)
        learner.observe(
            str(i),
            unit=str(i if unit_count is None else i % unit_count),
            at=i * 10,
            features={"size": x, "tier": tier},
            llm="provider-A" if i % 2 else "provider-B",
        )
        learner.resolve(str(i), y, at=i * 10 + delay, source="synthetic fixture")


class WorkflowLearningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "learning.sqlite"
        self.opened = []

    def learner(self, t=None, company="one"):
        l = WorkflowLearner(
            self.path,
            tenant="tenant",
            company=company,
            workflow="delivery",
            task=t or task(),
        )
        self.opened.append(l)
        return l

    def tearDown(self):
        for l in self.opened:
            try:
                l.close()
            except Exception:
                pass
        self.tmp.cleanup()

    def test_full_cycle_restart_provider_independence_and_drift(self):
        l = self.learner()
        populate(l)
        report = l.learn()
        self.assertTrue(report["passed"])
        self.assertEqual(report["status"], "evaluated")
        self.assertFalse(l.promote(report["version"]))
        self.assertTrue(l.promote(report["version"], approved=True))
        before = l.predict({"size": 1, "tier": "urgent"})
        self.assertAlmostEqual(before["value"], 18, delta=1)
        l.close()
        l = self.learner()
        self.assertEqual(before, l.predict({"size": 1, "tier": "urgent"}))
        self.assertEqual(
            l.learn()["reason"],
            "Fresh holdout required; prior test window cannot select another candidate",
        )
        populate(l, n=40, start=400, shift=100)
        self.assertEqual(l.monitor()["status"], "suspended")
        self.assertEqual(l.predict({"size": 1, "tier": "urgent"})["status"], "fallback")
        with self.assertRaisesRegex(ValueError, "Suspended"):
            l.promote(report["version"], approved=True)

    def test_binary_and_auto_promotion(self):
        l = self.learner(task("binary", auto_promote=True))
        populate(l, kind="binary")
        r = l.learn()
        self.assertEqual(r["status"], "promoted")
        self.assertLess(l.predict({"size": -2, "tier": "normal"})["value"], 0.2)
        self.assertGreater(l.predict({"size": 2, "tier": "urgent"})["value"], 0.8)

    def test_rate_prior_and_idempotent_collection(self):
        t = LearningTask("success", "1", "rate", (), "success", 0.5)
        l = self.learner(t)
        self.assertEqual(l.rate()["status"], "prior_only")
        for i, y in enumerate([1, 1, 0]):
            l.observe(str(i), unit=str(i), features={}, at=i * 2)
            l.resolve(str(i), y, at=i * 2 + 1, source="test")
        r = l.cycle()["learning"]
        self.assertEqual(r["posterior"], [3.0, 2.0])
        self.assertEqual(r["mean"], 0.6)
        self.assertFalse(l.resolve("0", 1, at=1, source="test"))
        with self.assertRaises(ValueError):
            l.resolve("0", 0, at=1, source="test")

    def test_small_repeated_and_rare_data_collects(self):
        l = self.learner()
        populate(l, n=50)
        self.assertEqual(l.plan()["status"], "collecting")
        repeated = self.learner(company="repeated")
        populate(repeated, n=400, unit_count=10)
        self.assertEqual(repeated.plan()["units"], 10)
        self.assertEqual(repeated.learn()["status"], "collecting")
        rare = self.learner(task("binary"), company="rare")
        for i in range(240):
            rare.observe(
                str(i), unit=str(i), at=i * 10, features={"size": i, "tier": "a"}
            )
            rare.resolve(str(i), int(i == 0), at=i * 10 + 1, source="test")
        self.assertIn("minority", rare.plan()["reason"])

    def test_strict_inputs_isolation_and_schema_version(self):
        l = self.learner()
        for values in [
            {"size": float("nan"), "tier": "x"},
            {"size": 1, "tier": "x", "actual_hours": 4},
            {"size": True, "tier": "x"},
        ]:
            with self.assertRaises(ValueError):
                l.predict(values)
        a = l.observe(
            "a", unit="customer", features={"size": None, "tier": None}, at=10
        )
        self.assertEqual(
            a,
            l.observe(
                "a", unit="customer", features={"size": None, "tier": None}, at=10
            ),
        )
        with self.assertRaises(ValueError):
            l.observe("a", unit="customer", features={"size": 2, "tier": None}, at=10)
        with self.assertRaises(ValueError):
            l.resolve("a", 5, at=9, source="test")
        with self.assertRaises(ValueError):
            self.learner(company="other").resolve("a", 5, at=11, source="test")
        with self.assertRaisesRegex(ValueError, "contract changed"):
            self.learner(replace(task(), fallback=5))

    def test_bounded_rows_categories_and_temporal_purge(self):
        l = self.learner(task(max_rows=100))
        populate(l)
        self.assertEqual(l.plan()["rows"], 100)
        self.assertEqual(l.plan()["status"], "collecting")
        delayed = self.learner(company="delay")
        populate(delayed, delay=10000)
        self.assertEqual(
            delayed.learn()["reason"],
            "insufficient_resolved_units_after_temporal_purge",
        )
        cats = self.learner(task(max_categories=1), company="cats")
        populate(cats)
        self.assertEqual(cats.learn()["reason"], "category_budget_exceeded")
        wide = self.learner(task(max_encoded_features=1), company="wide")
        populate(wide)
        self.assertEqual(wide.learn()["reason"], "encoded_feature_budget_exceeded")

    def test_corrupt_artifacts_never_load(self):
        l = self.learner()
        populate(l)
        r = l.learn()
        l.promote(r["version"], approved=True)
        l.db.execute("update wl_candidates set payload='{}'")
        l.db.commit()
        with self.assertRaisesRegex(ValueError, "integrity"):
            l.predict({"size": 1, "tier": "normal"})

    def test_unknown_categories_and_missing_values(self):
        l = self.learner()
        populate(l)
        r = l.learn()
        l.promote(r["version"], approved=True)
        self.assertTrue(
            np.isfinite(l.predict({"size": None, "tier": "unseen"})["value"])
        )
        self.assertIsNotNone(l.predict({"size": None, "tier": None})["interval"])

    def test_portable_tree_predictions_match_sklearn(self):
        from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier

        rng = np.random.default_rng(3)
        x = rng.normal(size=(250, 3))
        for kind, cls, y in [
            ("regression", RandomForestRegressor, x[:, 0] ** 2),
            ("binary", RandomForestClassifier, (x[:, 0] > 0).astype(int)),
        ]:
            m = models.fit("forest", x, y, kind)
            reference = cls(
                n_estimators=40,
                max_depth=8,
                min_samples_leaf=5,
                random_state=17,
                n_jobs=1,
            ).fit(x, y)
            expected = (
                reference.predict_proba(x)[:, 1]
                if kind == "binary"
                else reference.predict(x)
            )
            np.testing.assert_allclose(models.predict(m, x), expected, atol=1e-12)

    def test_runtime_primitive_records_and_preview_does_not(self):
        from lightbulb.primitive_runtime import PrimitiveRegistry
        from lightbulb.project_runtime import (
            LightbulbProject,
            ProjectWorkflow,
            ProjectWorkflowStep,
            ProjectRuntime,
        )
        from lightbulb.connector_execution import InMemoryConnectorExecutor

        l = self.learner()
        primitive = l.primitive()
        project = LightbulbProject(
            project_ref="delivery",
            name="Delivery",
            primitive_refs=[primitive.primitive_ref],
            workflows=[
                ProjectWorkflow(
                    key="estimate",
                    title="Estimate",
                    entry_step="learn",
                    steps=[
                        ProjectWorkflowStep(
                            id="learn",
                            primitive_ref=primitive.primitive_ref,
                            input_mapping={"*": "$input"},
                        )
                    ],
                )
            ],
        )
        runtime = ProjectRuntime(
            project, PrimitiveRegistry([primitive]), InMemoryConnectorExecutor()
        )
        inputs = dict(
            decision_id="sdk-1",
            unit="customer-1",
            at=10,
            features={"size": 1, "tier": "normal"},
            llm="any-provider",
        )
        preview = runtime.run_workflow(
            "estimate",
            inputs,
            tenant_ref="tenant",
            company_ref="one",
            preview_only=True,
        )
        self.assertEqual(preview.status.value, "completed")
        self.assertEqual(
            l.db.execute("select count(*) from wl_observations").fetchone()[0], 0
        )
        receipt = runtime.run_workflow(
            "estimate",
            inputs,
            tenant_ref="tenant",
            company_ref="one",
            preview_only=False,
        )
        self.assertEqual(receipt.status.value, "completed")
        self.assertEqual(
            l.db.execute("select count(*) from wl_observations").fetchone()[0], 1
        )
        bad = runtime.run_workflow(
            "estimate",
            inputs,
            tenant_ref="tenant",
            company_ref="other",
            preview_only=False,
        )
        self.assertNotEqual(bad.status.value, "completed")

    def test_unsupported_task_returns_explicit_status(self):
        l = self.learner(replace(task(), kind="survival"))
        self.assertEqual(l.learn()["status"], "unsupported")


if __name__ == "__main__":
    unittest.main()
