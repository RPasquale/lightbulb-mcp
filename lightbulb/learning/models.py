"""Bounded sklearn training, portable JSON inference; never load pickle."""

import math

import numpy as np
from scipy.special import expit
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.linear_model import (
    ElasticNet,
    Lasso,
    LinearRegression,
    LogisticRegression,
    PoissonRegressor,
    Ridge,
)


def preprocessing(rows, features, max_categories):
    result = []
    for f in features:
        values = [
            r["features"][f.name] for r in rows if r["features"][f.name] is not None
        ]
        if f.kind == "number":
            a = np.asarray(values or [0.0], float)
            result.append(
                {
                    "name": f.name,
                    "kind": f.kind,
                    "median": float(np.median(a)),
                    "mean": float(a.mean()),
                    "scale": max(float(a.std()), 1e-8),
                }
            )
        else:
            levels = sorted(set(values))
            if len(levels) > max_categories:
                raise ValueError("category_budget_exceeded")
            result.append({"name": f.name, "kind": f.kind, "levels": levels})
    return result


def transform(rows, prep):
    matrix = []
    for row in rows:
        output = []
        for p in prep:
            v = row[p["name"]]
            if p["kind"] == "number":
                output.extend(
                    [
                        ((p["median"] if v is None else v) - p["mean"]) / p["scale"],
                        float(v is None),
                    ]
                )
            else:
                output.extend(float(v == level) for level in p["levels"])
                output.extend(
                    [float(v is None), float(v is not None and v not in p["levels"])]
                )
        matrix.append(output)
    result = np.asarray(matrix, float)
    if not np.isfinite(result).all():
        raise ValueError("Feature transformation overflowed; check feature units/range")
    return result


def fit(name, x, y, kind):
    if name == "poisson":
        estimator = PoissonRegressor(alpha=1.0, max_iter=1000)
    elif name == "linear":
        estimator = LinearRegression()
    elif name == "lasso":
        estimator = Lasso(alpha=0.1, max_iter=5000)
    elif name.startswith("ridge"):
        estimator = Ridge(alpha=float(name.split(":")[1]))
    elif name == "elastic_net":
        estimator = ElasticNet(alpha=0.1, l1_ratio=0.5, max_iter=5000)
    elif name.startswith("logistic"):
        estimator = LogisticRegression(
            C=float(name.split(":")[1]), max_iter=1000, random_state=17
        )
    else:
        cls = RandomForestClassifier if kind == "binary" else RandomForestRegressor
        estimator = cls(
            n_estimators=40, max_depth=8, min_samples_leaf=5, random_state=17, n_jobs=1
        )
    import warnings

    from sklearn.exceptions import ConvergenceWarning

    with warnings.catch_warnings():
        warnings.simplefilter("error", ConvergenceWarning)
        estimator.fit(x, y)
    if hasattr(estimator, "coef_"):
        return {
            "type": "linear",
            "coefficients": np.asarray(estimator.coef_).reshape(-1).tolist(),
            "intercept": float(np.asarray(estimator.intercept_).reshape(-1)[0]),
            "binary": kind == "binary",
            "link": "log" if name == "poisson" else "identity",
        }
    trees = []
    for item in estimator.estimators_:
        t = item.tree_
        values = t.value[:, 0, :]
        if kind == "binary":
            # sklearn versions differ in whether values are counts or proportions.
            values = values[:, 1] / values.sum(axis=1)
        else:
            values = values[:, 0]
        trees.append(
            {
                "left": t.children_left.tolist(),
                "right": t.children_right.tolist(),
                "feature": t.feature.tolist(),
                "threshold": t.threshold.tolist(),
                "value": values.tolist(),
            }
        )
    return {"type": "forest", "trees": trees, "binary": kind == "binary"}


def predict(model, x):
    if model["type"] == "calibrated":
        raw = np.clip(predict(model["base"], x), 1e-6, 1 - 1e-6)
        return expit(model["slope"] * np.log(raw / (1 - raw)) + model["intercept"])
    if model["type"] == "constant":
        return np.full(len(x), model["value"], float)
    if model["type"] == "linear":
        values = x @ model["coefficients"] + model["intercept"]
        if model.get("link") == "log":
            with np.errstate(over="raise", invalid="raise"):
                try:
                    return np.exp(values)
                except FloatingPointError as exc:
                    raise ValueError("Prediction outside finite range") from exc
        return expit(values) if model["binary"] else values
    output = np.zeros(len(x))
    for tree in model["trees"]:
        for i, row in enumerate(x):
            node = 0
            while tree["left"][node] != -1:
                node = (
                    tree["left"][node]
                    if row[tree["feature"][node]] <= tree["threshold"][node]
                    else tree["right"][node]
                )
            output[i] += tree["value"][node]
    return output / len(model["trees"])


def calibrate_probability(model, x, y):
    """Fit bounded sigmoid calibration on a separate calibration partition.

    Never inspect the final test partition. Calibration may hurt a candidate;
    final promotion must still pass the untouched holdout against the baseline
    and incumbent. Leave small or one-class windows uncalibrated explicitly.
    """
    y = np.asarray(y)
    if len(y) < 100 or min(np.sum(y == 0), np.sum(y == 1)) < 25:
        return model, {
            "status": "deferred",
            "reason": "insufficient_separate_calibration_units",
        }
    raw = np.clip(predict(model, x), 1e-6, 1 - 1e-6)
    logits = np.log(raw / (1 - raw)).reshape(-1, 1)
    fitted = fit("logistic:1", logits, y, "binary")
    return {
        "type": "calibrated",
        "base": model,
        "slope": fitted["coefficients"][0],
        "intercept": fitted["intercept"],
    }, {"status": "fitted", "method": "sigmoid", "units": len(y)}


def loss(kind, actual, predicted):
    actual, predicted = np.asarray(actual), np.asarray(predicted)
    return (actual - predicted) ** 2 if kind == "binary" else np.abs(actual - predicted)


def comparison(rows, base, candidate, seed=17):
    # Resample independent units rather than treating retries/repeated customers as independent.
    units = {}
    for r, delta in zip(rows, np.asarray(base) - candidate):
        units.setdefault(r["unit"], []).append(float(delta))
    means = np.array([np.mean(v) for v in units.values()])
    if len(means) < 30:
        return {
            "passes": False,
            "units": len(means),
            "reason": "insufficient_independent_holdout_units",
        }
    rng = np.random.default_rng(seed)
    samples = [
        float(rng.choice(means, len(means), replace=True).mean()) for _ in range(1000)
    ]
    lo, hi = np.quantile(samples, [0.025, 0.975])
    return {
        "passes": bool(lo > 0),
        "units": len(means),
        "mean_improvement": float(means.mean()),
        "interval95": [float(lo), float(hi)],
        "method": "equal-unit paired bootstrap; descriptive, not sequential inference",
    }


def conformal(errors, alpha):
    rank = math.ceil((len(errors) + 1) * (1 - alpha))
    if rank > len(errors):
        return None
    return float(np.sort(errors)[rank - 1])
