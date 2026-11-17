# Workflow learning and local models

This optional module learns numerical predictions from workflow outcomes, independently
of the language model. It does not train LLM weights. A workflow can use the prediction
directly for routing or supply `learner.context(features)` to a model as evidence.
Changing LLMs does not erase learned parameters. If a replacement extractor changes
feature meanings, create a new task version and evaluate again.

Install this branch's checkout with `python -m pip install -e ".[workflow-learning]"`.
The default SDK import does not load NumPy, SciPy or scikit-learn. Training uses those
libraries; pandas is not required. Models are stored as checksummed JSON, never pickle.

## Small working example

```python
from lightbulb.learning import Feature, LearningTask, WorkflowLearner

task = LearningTask(
    name="delivery", version="1", kind="regression",
    features=(Feature("estimated_size"), Feature("service", "category")),
    outcome="actual_hours", fallback=40.0, auto_promote=False,
)
with WorkflowLearner("learning.sqlite", tenant="my-tenant", company="my-company",
                     workflow="delivery", task=task) as learner:
    prediction = learner.observe(
        "job-001", unit="customer-001", at=1800000000,
        features={"estimated_size": 3, "service": "implementation"},
        action="standard_delivery", llm="my-local-model",
    )
    # Later, from the actual delivery system, not from an LLM's estimate:
    learner.resolve("job-001", 28.5, at=1800102600, source="timesheet:job-001")
    print(learner.plan())
    print(learner.cycle())  # insufficient data -> collecting, fallback retained
```

`unit` identifies the independent customer/case used for splitting and uncertainty.
Retries are not new samples. Choose this unit deliberately; the SDK cannot infer
statistical independence from an arbitrary identifier. Decision inputs and outcomes
are immutable and idempotent; conflicting retries fail. Missing outcomes remain
unresolved. Inputs must be available before the decision; do not put future outcomes
or target proxies into features. Source and timestamps are caller attestations.

## Automatic planner and complete lifecycle

| Task kind | Candidate estimators | Evaluation |
| --- | --- | --- |
| `regression` | median baseline, ridge, elastic net, bounded random forest | MAE; split-conformal prediction interval |
| `binary` | prevalence baseline, regularized logistic regression, bounded random forest | Brier score; probabilities, no fabricated confidence interval |
| `rate` | Beta-Bernoulli posterior with explicit prior | posterior mean and credible interval, including prior-only state |

Predictive tasks default to at least 220 independent units, with at least 30 surviving
units in each partition and 20 minority-class units overall for classification.
There is no universal small-data guarantee. The planner returns `collecting` when
evidence is inadequate. Unsupported tasks return `unsupported`; they are not silently
treated as regression. Numeric and categorical features are supported, with missing
indicators and unknown-category encoding. Preprocessing is fitted only on training data.

The lifecycle is collect -> plan -> train -> select -> calibrate -> evaluate -> promote
-> monitor -> suspend/retrain. Time-ordered, disjoint groups are split 50/20/15/15.
Outcomes not yet available at the next partition's start are purged. Validation selects
the candidate; calibration constructs regression intervals; the final holdout evaluates
it against the baseline and active incumbent. Another evaluation needs a fresh holdout.
An equal-unit paired bootstrap describes improvement; it is **not** a sequential
hypothesis-testing guarantee. Predictive improvement is not proof of causal business ROI.

`learn()` persists a candidate and its split IDs, dataset digest, failures and metrics.
`promote(version, approved=True)` activates only a passing, current candidate.
`auto_promote=True` is an explicit task policy that performs that step automatically.
`monitor()` evaluates subsequent resolved decisions against an operational error
threshold. It can retire the active model and return to the configured fallback.
`cycle()` runs monitoring followed by learning. Schedule this tick in your existing
worker; the SDK does not spawn a daemon. Failed fits and budget excesses preserve the
current model/fallback. `history()` records transitions; approved rollback can restore
a previously promoted model that has not been suspended.

The default training window is the latest 20,000 resolved decisions, with at most 128
encoded features and 32 levels per categorical feature. These are configurable budgets,
not an out-of-core trainer or a hard CPU deadline. SQLite preserves historical evidence;
storage retention remains the application's responsibility. One learner/connection per
thread. Scope IDs partition data but are not authentication. Protect the database file
and authenticate callers in the host application. A checksum detects accidental artifact
corruption, not an attacker who can rewrite the database and its checksums.

## Native SDK workflows and local LLMs

`learner.primitive()` is a normal `FunctionBusinessProcessPrimitive`: preview predicts
without recording, execution records the decision, and tenant/company/project must
match the learner. Bind its `prediction` output into another step. The complete example
does this with a local language-model step.

```python
from lightbulb import LocalLLM
from pydantic import BaseModel

class Summary(BaseModel):
    explanation: str

with LocalLLM("qwen3:14b") as model:
    answer = model.structured(
        [{"role": "user", "content": "Explain why predictions have uncertainty."}],
        Summary,
    )
    print(answer.explanation)
```

Ollama defaults to `http://127.0.0.1:11434`; use an already installed model. For a local
OpenAI-compatible server, supply `protocol="openai", base_url="http://127.0.0.1:1234"`.
Use a literal loopback IP, not a hostname. No model download, cloud fallback, redirects,
ambient proxy or automatic retry is performed. The server itself must use local weights;
this client cannot prevent a server from proxying requests elsewhere. Ollama context
defaults to 8,192 tokens. The OpenAI-compatible server controls its own context budget.
Both paths bound output and request/response bytes, apply HTTP timeouts, reject incomplete
generation and validate structured responses. They do not execute model-suggested tools.
`model.primitive()` provides a governed workflow step; preview makes no inference call.

LLM explanations are untrusted prose. Always show authoritative numerical evidence
separately. Schema validation is not factual verification. In particular, a prediction
interval for an outcome is not a confidence interval for a mean.

## Reproducible six-workflow experiment

From the repository root, choose a fresh output directory:

```text
python examples/workflow_learning/run.py --out ./learning-experiment --local-model qwen3:14b
python examples/workflow_learning/play.py --out ./learning-experiment --local-model qwen3:14b
python -m unittest discover -s tests -p "test_*learning*.py"
python -m unittest discover -s tests -p "test_local_llm.py"
```

The generator creates 3,600 fictional cases across delivery, collections, support,
sales, procurement and fulfilment. It supplies numeric/categorical inputs, missing
inputs and unresolved outcomes, timestamps, provenance, linked case IDs, separate
decision/outcome events and a reproducibility manifest. These are representative tasks,
not simulations of every SDK primitive. Relationships are deliberately planted.

The runner trains/evaluates all six tasks, runs actual SDK prediction -> evidence ->
local-model steps, saves the receipt, injects a performance shift, suspends the stale
model and evaluates a replacement on fresh data. It does not call external connectors.
The interactive playground changes features, inspects plans/evidence and optionally asks
the local model to explain them. Synthetic results must never be marketed as customer ROI.

This initial module does not provide causal policy optimization, bandits, arbitrary
multiclass/survival/time-series estimation, neural-network training or universal
automatic feature discovery. Those require separate contracts and validation. Start
with one measurable outcome per node and retain normal approvals for external actions.
