"""Deterministic data diagnostics; no target inference or effect authorization."""

from collections import Counter

import numpy as np


def assess(rows, features, kind):
    """Describe the bounded decision-time dataset used by the planner.

    Correlations are diagnostics only. Any fitting/feature selection still belongs
    inside the training partition, never across this diagnostic dataset.
    """
    n = len(rows)
    units = len({r["unit"] for r in rows})
    missing = {
        f.name: sum(r["features"][f.name] is None for r in rows) for f in features
    }
    numeric = [f for f in features if f.kind == "number"]
    constants, redundant = [], []
    for f in features:
        values = {
            r["features"][f.name] for r in rows if r["features"][f.name] is not None
        }
        if len(values) <= 1:
            constants.append(f.name)
    # Bound the diagnostic pair search; never allocate a quadratic feature matrix.
    for i, f in enumerate(numeric[:32]):
        for g in numeric[:i]:
            pairs = [
                (r["features"][f.name], r["features"][g.name])
                for r in rows
                if r["features"][f.name] is not None
                and r["features"][g.name] is not None
            ]
            if len(pairs) >= 3 and f.name not in constants and g.name not in constants:
                a = np.asarray(pairs, dtype=float)
                with np.errstate(over="ignore", invalid="ignore", divide="ignore"):
                    correlation = float(np.corrcoef(a.T)[0, 1])
                if np.isfinite(correlation) and abs(correlation) > 0.98:
                    redundant.append([f.name, g.name])
    counts = Counter(str(r["y"]) for r in rows) if kind == "binary" else {}
    ys = np.asarray([r["y"] for r in rows], dtype=float)
    mean = float(np.mean(ys)) if n else None
    variance = float(np.var(ys)) if n else None
    return {
        "rows": n,
        "independent_units": units,
        "repeated_rows": n - units,
        "raw_features": len(features),
        "missing_inputs": missing,
        "constant_features": constants,
        "highly_correlated_pairs": redundant,
        "correlation_feature_limit": 32,
        "outcome_counts": dict(counts),
        "outcome_mean": mean,
        "outcome_variance": variance,
        "overdispersed": bool(kind == "count" and mean and variance > mean * 1.5),
        "resolved_delay_max": max(
            (r["resolved"] - r["at"] for r in rows), default=None
        ),
        "evaluation": "chronological disjoint independent-unit partitions; delayed-label purge",
        "note": "Diagnostics do not establish independence, causality or feature validity",
    }
