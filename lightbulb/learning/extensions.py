"""Trusted, opt-in estimator extensions; artifacts never contain executable code."""

from typing import Protocol


class EstimatorExtension(Protocol):
    """Implement for a regression, binary or count target.

    Register an explicit versioned key, e.g. ``acme.spline:v1``, in the task and
    supply the implementation to each learner process. Fit receives only the
    training partition. Return finite JSON data, not pickle or Python objects.
    Prediction must return one finite number per row (probabilities for binary,
    nonnegative counts for count). Host applications own execution/resource
    trust for extensions; the SDK does not download or import plugins from an
    artifact. A new statistical target needs a separately validated task adapter,
    never silently reinterpret it as regression.
    """

    def fit(self, x, y, *, kind: str) -> dict: ...

    def predict(self, artifact: dict, x): ...
