"""Right-censored time-to-event estimates using SciPy's Kaplan-Meier ECDF."""

import math

import numpy as np
from scipy.stats import CensoredData, ecdf


def estimate_event_time(rows, *, horizon, alpha=0.1):
    if not math.isfinite(horizon) or horizon <= 0 or not 0 < alpha < 1:
        raise ValueError("Positive finite horizon and valid alpha required")
    if len({r["unit"] for r in rows}) != len(rows):
        raise ValueError("Use one survival observation per independent unit")
    for r in rows:
        if type(r["event"]) is not bool or not math.isfinite(r["y"]) or r["y"] < 0:
            raise ValueError(
                "Nonnegative duration and explicit event/censor flag required"
            )
    base = {
        "units": len(rows),
        "events": sum(r["event"] for r in rows),
        "horizon": horizon,
        "method": "Kaplan-Meier; right censoring",
        "nominal_coverage": 1 - alpha,
        "assumptions": "Independent units and non-informative right censoring; no extrapolation beyond follow-up",
    }
    if not rows or base["events"] == 0:
        return dict(
            base,
            status="collecting",
            event_probability=None,
            interval=[0.0, 1.0],
            reason="No observed events; censored observations are not negative labels",
        )
    if horizon > max(r["y"] for r in rows):
        return dict(
            base,
            status="collecting",
            event_probability=None,
            interval=None,
            reason="Horizon exceeds observed follow-up; no supported extrapolation",
        )
    observed = [r["y"] for r in rows if r["event"]]
    censored = [r["y"] for r in rows if not r["event"]]
    result = ecdf(CensoredData(uncensored=observed, right=censored)).sf
    # Greenwood intervals can be undefined at complete survival collapse. Keep
    # uncertainty explicit rather than turning NaN into a false zero-width interval.
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        ci = result.confidence_interval(confidence_level=1 - alpha)
    lo, hi = float(ci.low.evaluate(horizon)), float(ci.high.evaluate(horizon))
    interval = (
        [max(0.0, 1 - hi), min(1.0, 1 - lo)] if np.isfinite([lo, hi]).all() else None
    )
    return dict(
        base,
        status="estimated",
        event_probability=1 - float(result.evaluate(horizon)),
        interval=interval,
        interval_type="pointwise_confidence",
        median_event_time=next(
            (
                float(t)
                for t, s in zip(result.quantiles, result.probabilities)
                if s <= 0.5
            ),
            None,
        ),
        curve=[
            {"duration": float(t), "survival": float(s)}
            for t, s in zip(result.quantiles, result.probabilities)
        ],
    )
