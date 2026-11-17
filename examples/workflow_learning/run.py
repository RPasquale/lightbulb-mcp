"""Run learning over six synthetic workflows and optionally invoke local Qwen.

python run.py --out /fresh/directory --local-model qwen3:14b
"""

import argparse
import json
from pathlib import Path
import numpy as np
from pydantic import BaseModel
from lightbulb.learning import Feature, LearningTask, WorkflowLearner
from lightbulb.local_llm import LocalLLM
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
from synthetic import generate, SCENARIOS

FEATURES = (
    Feature("complexity"),
    Feature("load"),
    Feature("connections"),
    Feature("channel", "category"),
    Feature("priority", "category"),
)


def run(folder, local_model=None):
    out = Path(folder)
    out.mkdir(parents=True, exist_ok=True)
    if (out / "report.json").exists():
        raise ValueError("Choose a fresh experiment output directory")
    data = out / "data"
    generate(data)
    summary = {}
    learners = []
    model = None
    try:
        for workflow, (kind, outcome, fallback) in SCENARIOS.items():
            learner = WorkflowLearner(
                out / "learning.sqlite",
                tenant="synthetic",
                company="demo",
                workflow=workflow,
                task=LearningTask(
                    workflow, "1", kind, FEATURES, outcome, fallback, max_rows=600
                ),
            )
            learners.append(learner)
            for line in (data / (workflow + ".jsonl")).read_text().splitlines():
                r = json.loads(line)
                learner.observe(
                    r["id"],
                    unit=r["unit"],
                    features=r["features"],
                    at=r["at"],
                    action=r["action"],
                    llm=r["llm"],
                )
                if r["value"] is not None:
                    learner.resolve(
                        r["id"], r["value"], at=r["resolved_at"], source=r["source"]
                    )
            result = learner.learn()
            if result.get("passed"):
                learner.promote(result["version"], approved=True)
            summary[workflow] = {
                k: result.get(k)
                for k in [
                    "status",
                    "selected",
                    "metric",
                    "holdout_loss",
                    "baseline_loss",
                    "passed",
                    "reason",
                    "comparison",
                ]
            }
            (out / (workflow + "-evaluation.json")).write_text(
                json.dumps(result, indent=2), encoding="utf-8"
            )
        delivery = learners[0]
        example = dict(
            complexity=7.0, load=0.6, connections=3.0, channel="web", priority="urgent"
        )
        before = delivery.context(example)
        # Use SDK primitives for both prediction and actual local-model explanation.
        primitives = [delivery.primitive("demo.estimate")]
        steps = [
            ProjectWorkflowStep(
                id="estimate",
                primitive_ref="demo.estimate",
                input_mapping={"*": "$input"},
                next_step="explain-input" if local_model else None,
            )
        ]
        model = None
        if local_model:
            model = LocalLLM(local_model, max_tokens=400, timeout=180, keep_alive="5m")

            class Evidence(BaseModel):
                prediction: dict

            class Messages(BaseModel):
                messages: list[dict[str, str]]

            def explain_input(ctx, inputs):
                return Messages(
                    messages=[
                        dict(
                            role="system",
                            content="Explain supplied statistical evidence in three sentences. This is synthetic data. Do not invent business results or authorize spending. The interval is a 90% prediction interval for an individual outcome, NOT a confidence interval for a mean. Nominal coverage depends on exchangeable independent units; do not claim guaranteed coverage.",
                        ),
                        dict(role="user", content=json.dumps(inputs.prediction)),
                    ]
                )

            primitives.extend(
                [
                    FunctionBusinessProcessPrimitive(
                        primitive_ref="demo.explain_input",
                        title="Evidence to model context",
                        input_model=Evidence,
                        output_model=Messages,
                        handler=explain_input,
                    ),
                    model.primitive("demo.local_model"),
                ]
            )
            steps.extend(
                [
                    ProjectWorkflowStep(
                        id="explain-input",
                        primitive_ref="demo.explain_input",
                        input_mapping={"*": "$steps.estimate.output"},
                        next_step="explain",
                    ),
                    ProjectWorkflowStep(
                        id="explain",
                        primitive_ref="demo.local_model",
                        input_mapping={"*": "$steps.explain-input.output"},
                    ),
                ]
            )
        project = LightbulbProject(
            project_ref="software_delivery",
            name="Learning with a local model",
            primitive_refs=[p.primitive_ref for p in primitives],
            workflows=[
                ProjectWorkflow(
                    key="quote",
                    title="Estimate and explain",
                    entry_step="estimate",
                    steps=steps,
                )
            ],
        )
        runtime = ProjectRuntime(
            project, PrimitiveRegistry(primitives), InMemoryConnectorExecutor()
        )
        receipt = runtime.run_workflow(
            "quote",
            dict(
                decision_id="live-example",
                unit="new-customer",
                at=1800020000,
                features=example,
                llm=local_model,
            ),
            tenant_ref="synthetic",
            company_ref="demo",
            preview_only=False,
            run_ref="local-learning-example",
        )
        if model:
            model.close()
        if receipt.status.value != "completed":
            raise RuntimeError(receipt.model_dump_json())
        (out / "sdk-receipt.json").write_text(
            receipt.model_dump_json(indent=2), encoding="utf-8"
        )
        # Frozen model is exercised prospectively, then outcomes reveal a 50-hour shift.
        for i in range(40):
            at = 1800030000 + i * 10
            prediction = delivery.observe(
                f"drift-{i}", unit=f"drift-unit-{i}", features=example, at=at
            )
            delivery.resolve(
                f"drift-{i}",
                prediction["value"] + 50,
                at=at + 1,
                source="synthetic workload shift",
            )
        alarm = delivery.monitor()
        # Fully new independent outcomes; bounded rolling window now contains only the new regime.
        rng = np.random.default_rng(913)
        for i in range(600):
            at = 1800040000 + i * 10
            x = float(rng.uniform(0, 10))
            load = float(rng.random())
            connections = int(rng.integers(0, 6))
            f = dict(
                complexity=x,
                load=load,
                connections=connections,
                channel=["web", "email", "partner"][i % 3],
                priority="urgent" if i % 4 == 0 else "normal",
            )
            delivery.observe(f"new-{i}", unit=f"new-unit-{i}", features=f, at=at)
            delivery.resolve(
                f"new-{i}",
                55 + x * x * 0.8 + connections * 3 + load * 8 + float(rng.normal(0, 2)),
                at=at + 1,
                source="synthetic new regime",
            )
        replacement = delivery.learn()
        if replacement.get("passed"):
            delivery.promote(replacement["version"], approved=True)
        (out / "replacement-evaluation.json").write_text(
            json.dumps(replacement, indent=2), encoding="utf-8"
        )
        report = dict(
            synthetic=True,
            workflow_results=summary,
            before=before,
            drift=alarm,
            after=delivery.context(example),
            replacement={
                k: replacement.get(k)
                for k in [
                    "selected",
                    "holdout_loss",
                    "baseline_loss",
                    "passed",
                    "status",
                ]
            },
            sdk_status=receipt.status.value,
            local_model=local_model,
            explanation=receipt.step_runs[-1].result.output.model_dump()
            if local_model
            else None,
            limitations=[
                "Synthetic evidence is not customer ROI",
                "No external connector writes or autonomous tools",
                "Local model output is explanatory, not ground truth or approval",
            ],
        )
        (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return report
    finally:
        if model:
            model.close()
        for l in learners:
            l.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--local-model")
    a = p.parse_args()
    run(a.out, a.local_model)
