"""Reproducible fictional workflow evidence. Never import customer data.

Not a simulator of all Lightbulb business primitives: these are six representative
learning tasks connected by company/case IDs and a common event contract.
"""

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

SCENARIOS = {
    "software_delivery": ("regression", "delivery_hours", 40.0),
    "invoice_collection": ("binary", "paid_late", 0.25),
    "support_resolution": ("binary", "reopened", 0.2),
    "sales_qualification": ("binary", "converted", 0.3),
    "procurement_matching": ("binary", "match_exception", 0.1),
    "order_fulfilment": ("regression", "elapsed_hours", 24.0),
}


def generate(folder, *, n=600, seed=812, drift=False, missing=0.05):
    if type(n) is not int or not 1 <= n <= 100000 or not 0 <= missing <= 1:
        raise ValueError(
            "Use 1..100000 rows per workflow and a missing fraction in [0,1]"
        )
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    if (folder / "manifest.json").exists():
        raise ValueError("Choose a fresh dataset directory")
    rng = np.random.default_rng(seed)
    events = []
    counts = {}
    for workflow, (kind, outcome, fallback) in SCENARIOS.items():
        rows = []
        for i in range(n):
            complexity = float(rng.uniform(0, 10))
            load = float(rng.uniform(0, 1))
            connections = int(rng.integers(0, 6))
            channel = ["web", "email", "partner"][i % 3]
            priority = "urgent" if i % 4 == 0 else "normal"
            shift = 30.0 if drift and i >= n // 2 else 0.0
            if kind == "regression":
                y = (
                    5
                    + complexity**2 * 0.8
                    + connections * 3
                    + load * 8
                    + float(rng.normal(0, 2))
                    + shift
                )
            else:
                score = (
                    -3
                    + complexity * 0.6
                    + load * 1.5
                    + connections * 0.15
                    + (priority == "urgent") * 0.4
                )
                if workflow == "sales_qualification":
                    score = -score
                y = int(rng.random() < 1 / (1 + np.exp(-score)))
                if drift and i >= n // 2:
                    y = 1 - y
            # Every field is known before the decision; the target is stored separately.
            features = {
                "complexity": None if rng.random() < missing else complexity,
                "load": load,
                "connections": connections,
                "channel": channel,
                "priority": priority,
            }
            id = f"{workflow}-{i:05d}"
            at = 1800000000 + i * 10
            record = {
                "id": id,
                "company": "synthetic-company",
                "workflow": workflow,
                "workflow_version": "1",
                "unit": f"customer-{i:05d}",
                "case": f"case-{i:05d}",
                "at": at,
                "features": features,
                "action": "standard_process",
                "llm": "synthetic-provider-tag",
                "kind": kind,
                "outcome_name": outcome,
                "resolved_at": at + 2,
                "value": float(y),
                "source": "seeded synthetic generator",
                "regime": "shifted" if shift or (drift and i >= n // 2) else "stable",
            }
            if rng.random() < missing:
                record.update(value=None, resolved_at=None)
            rows.append(record)
            events.append(
                {
                    "id": id + ":decision",
                    "type": "decision",
                    "decision_id": id,
                    "workflow": workflow,
                    "at": at,
                    "unit": record["unit"],
                    "features": features,
                    "action": record["action"],
                }
            )
            if record["value"] is not None:
                events.append(
                    {
                        "id": id + ":outcome",
                        "type": "outcome",
                        "decision_id": id,
                        "workflow": workflow,
                        "at": at + 2,
                        "outcome": outcome,
                        "value": record["value"],
                    }
                )
        file = folder / (workflow + ".jsonl")
        file.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        counts[workflow] = {
            "rows": len(rows),
            "resolved": sum(r["value"] is not None for r in rows),
            "kind": kind,
            "outcome": outcome,
        }
    (folder / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in sorted(events, key=lambda e: e["at"])) + "\n",
        encoding="utf-8",
    )
    manifest = {
        "schema": "lightbulb.synthetic_workflow_evidence.v1",
        "seed": seed,
        "synthetic": True,
        "drift": drift,
        "workflows": counts,
        "coverage": "Six representative tasks, not every SDK business process",
        "assumptions": [
            "Independent synthetic customers; shared IDs link workflow cases",
            "Missing outcomes are unresolved, never negative labels",
            "Planted relationships demonstrate execution, not business efficacy",
        ],
        "files": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in folder.glob("*.jsonl")
        },
    }
    (folder / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--rows", type=int, default=600)
    p.add_argument("--drift", action="store_true")
    a = p.parse_args()
    print(json.dumps(generate(a.out, n=a.rows, drift=a.drift), indent=2))
