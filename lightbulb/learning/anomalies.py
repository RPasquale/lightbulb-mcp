"""Robust univariate diagnostics; anomalies are review signals, not labels."""

import math

import numpy as np


def robust_anomalies(reference, values, *, threshold=3.5, max_rows=20000):
    if (
        not math.isfinite(threshold)
        or threshold <= 0
        or type(max_rows) is not int
        or max_rows < 1
    ):
        raise ValueError("Positive finite threshold and row budget required")
    if len(reference) > max_rows or len(values) > max_rows:
        raise ValueError("Row budget exceeded")
    ref = np.asarray(reference, dtype=float)
    x = np.asarray(values, dtype=float)
    if (
        ref.ndim != 1
        or x.ndim != 1
        or not np.isfinite(ref).all()
        or not np.isfinite(x).all()
    ):
        raise ValueError("Finite one-dimensional observations required")
    if len(ref) < 3:
        return {
            "status": "collecting",
            "flags": [None] * len(x),
            "reason": "At least three reference observations required",
        }
    median = float(np.median(ref))
    mad = float(np.median(np.abs(ref - median)))
    if mad == 0:
        return {
            "status": "degenerate_reference",
            "median": median,
            "scale": 0.0,
            "flags": [bool(v != median) for v in x],
            "reason": "Zero median absolute deviation; changed values require review, no calibrated anomaly probability",
        }
    scores = 0.67448975 * (x - median) / mad
    return {
        "status": "assessed",
        "median": median,
        "scale": mad,
        "scores": scores.tolist(),
        "flags": (np.abs(scores) > threshold).tolist(),
        "reason": "Robust deviation diagnostic, not a hypothesis test or automatic customer treatment",
    }
