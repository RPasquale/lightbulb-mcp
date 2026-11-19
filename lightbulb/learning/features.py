"""Explicit, versioned feature extraction at the decision boundary."""

from dataclasses import dataclass
from datetime import datetime, timezone

from .engine import Feature, finite


@dataclass(frozen=True)
class EmbeddingFeature:
    """Use existing embeddings; never download or run an embedding provider.

    Include model, preprocessing and revision in version. The resulting feature
    descriptions enter the learner contract, so changing versions requires a new
    task version even when vector width is unchanged.
    """

    name: str
    version: str
    dimensions: int

    def __post_init__(self):
        if not self.name.strip() or not self.version.strip():
            raise ValueError("Embedding name and model/preprocessing version required")
        if type(self.dimensions) is not int or not 1 <= self.dimensions <= 4096:
            raise ValueError("Embedding dimensions must be between 1 and 4096")

    def schema(self):
        return tuple(
            Feature(
                f"{self.name}_{i}",
                description=f"embedding:{self.version}:{self.dimensions}",
            )
            for i in range(self.dimensions)
        )

    def extract(self, vector, *, version):
        if version != self.version:
            raise ValueError("Embedding version mismatch")
        if vector is None:
            return {f.name: None for f in self.schema()}
        if isinstance(vector, (str, bytes)) or len(vector) != self.dimensions:
            raise ValueError("Embedding shape mismatch")
        return {f.name: finite(v) for f, v in zip(self.schema(), vector)}


def timestamp_features(value: datetime, *, prefix="time"):
    """UTC epoch plus cyclic time features; reject ambiguous naive datetimes.

    Use only timestamps known before the decision, never completion timestamps
    when predicting completion. Explicit caller-selected business timezone
    features should use a separately versioned extractor.
    """
    import math

    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("Timezone-aware datetime required")
    utc = value.astimezone(timezone.utc)
    day = (utc.hour * 3600 + utc.minute * 60 + utc.second) / 86400
    week = (utc.weekday() + day) / 7
    return {
        f"{prefix}_epoch": utc.timestamp(),
        f"{prefix}_day_sin": math.sin(2 * math.pi * day),
        f"{prefix}_day_cos": math.cos(2 * math.pi * day),
        f"{prefix}_week_sin": math.sin(2 * math.pi * week),
        f"{prefix}_week_cos": math.cos(2 * math.pi * week),
    }
