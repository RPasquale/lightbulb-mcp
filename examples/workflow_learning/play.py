"""Interactive local experiment. Reads the dataset produced by run.py."""

import argparse
import json
from pathlib import Path
from lightbulb.learning import LearningTask, WorkflowLearner
from lightbulb.local_llm import LocalLLM
from run import FEATURES
from synthetic import SCENARIOS


def inspect(folder, workflow, features, model=None):
    if workflow not in SCENARIOS:
        raise ValueError("Unknown workflow")
    path = Path(folder) / "learning.sqlite"
    if not path.is_file():
        raise ValueError("Run the experiment first")
    kind, outcome, fallback = SCENARIOS[workflow]
    with WorkflowLearner(
        path,
        tenant="synthetic",
        company="demo",
        workflow=workflow,
        task=LearningTask(
            workflow, "1", kind, FEATURES, outcome, fallback, max_rows=600
        ),
    ) as learner:
        evidence = learner.context(features)
        result = dict(plan=learner.plan(), evidence=evidence)
        if model:
            with LocalLLM(model, max_tokens=400) as local:
                result["unverified_model_explanation"] = local.complete(
                    [
                        dict(
                            role="system",
                            content="Explain this synthetic evidence. Preserve interval_type and nominal_coverage exactly. A prediction interval is not a confidence interval. Do not authorize actions or invent outcomes.",
                        ),
                        dict(role="user", content=json.dumps(evidence)),
                    ]
                ).content
        return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--local-model")
    p.add_argument("--once", action="store_true")
    a = p.parse_args()
    features = dict(
        complexity=7.0, load=0.6, connections=3.0, channel="web", priority="urgent"
    )
    if a.once:
        print(
            json.dumps(
                inspect(a.out, "software_delivery", features, a.local_model), indent=2
            )
        )
    else:
        print("Synthetic workflow playground. No external writes. Enter q to quit.")
        print("Workflows:", ", ".join(SCENARIOS))
        print("Feature example:", json.dumps(features))
        while True:
            try:
                workflow = (
                    input("Workflow [software_delivery]: ").strip()
                    or "software_delivery"
                )
                if workflow == "q":
                    break
                raw = input("Features JSON [example]: ").strip()
                print(
                    json.dumps(
                        inspect(
                            a.out,
                            workflow,
                            json.loads(raw) if raw else features,
                            a.local_model,
                        ),
                        indent=2,
                    )
                )
            except (EOFError, KeyboardInterrupt):
                break
            except Exception as exc:
                print(type(exc).__name__ + ": " + str(exc))
