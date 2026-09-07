"""Typed metadata for distributed arrays, tensors, and hash maps."""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


DISTRIBUTED_ARRAY_METADATA_SCHEMA = "lightbulb.distributed_array_metadata.v1"
DISTRIBUTED_TENSOR_METADATA_SCHEMA = "lightbulb.distributed_tensor_metadata.v1"
DISTRIBUTED_HASHMAP_METADATA_SCHEMA = "lightbulb.distributed_hashmap_metadata.v1"

_DTYPE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.<>\[\],:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class PartitionStrategy(str, Enum):
    SINGLE = "single"
    BLOCK = "block"
    RANGE = "range"
    HASH = "hash"
    REPLICATED = "replicated"


class TensorOrder(str, Enum):
    C = "C"
    FORTRAN = "F"


class MapConsistency(str, Enum):
    EVENTUAL = "eventual"
    SESSION = "session"
    STRONG = "strong"


class PartitionSpec(BaseModel):
    """Logical partitioning independent of any particular compute engine."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    strategy: PartitionStrategy
    partition_count: int = Field(ge=1)
    axis: int | None = Field(default=None, ge=0)
    keys: tuple[str, ...] = ()
    replication_factor: int = Field(default=1, ge=1)

    @field_validator("keys")
    @classmethod
    def _keys_are_nonblank_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(key.strip() for key in value)
        if any(not key for key in normalized):
            raise ValueError("partition keys must not be blank")
        if len(set(normalized)) != len(normalized):
            raise ValueError("partition keys must be unique")
        return normalized

    @model_validator(mode="after")
    def _strategy_fields_are_coherent(self) -> "PartitionSpec":
        if self.strategy == PartitionStrategy.SINGLE:
            if self.partition_count != 1 or self.axis is not None or self.keys:
                raise ValueError("single partitioning requires one partition and no axis or keys")
        elif self.strategy == PartitionStrategy.BLOCK:
            if self.axis is None or self.keys:
                raise ValueError("block partitioning requires an axis and no keys")
        elif self.strategy == PartitionStrategy.HASH:
            if not self.keys or self.axis is not None:
                raise ValueError("hash partitioning requires keys and no axis")
        elif self.strategy == PartitionStrategy.RANGE:
            if (self.axis is None) == (not self.keys):
                raise ValueError("range partitioning requires exactly one of axis or keys")
        elif self.axis is not None or self.keys:
            raise ValueError("replicated partitioning does not accept an axis or keys")

        if self.strategy == PartitionStrategy.REPLICATED:
            if self.replication_factor < 2:
                raise ValueError("replicated partitioning requires replication_factor >= 2")
        elif self.replication_factor != 1:
            raise ValueError("replication_factor is only valid for replicated partitioning")
        return self


class LineageInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_ref: str = Field(min_length=1, max_length=500)
    version: str | None = Field(default=None, min_length=1, max_length=160)
    content_sha256: str | None = Field(default=None, min_length=64, max_length=64)

    @field_validator("asset_ref", "version")
    @classmethod
    def _strip_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if not clean:
            raise ValueError("lineage text must not be blank")
        return clean

    @field_validator("content_sha256")
    @classmethod
    def _digest_is_lowercase_sha256(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256_PATTERN.fullmatch(value):
            raise ValueError("content_sha256 must be a lowercase SHA-256 digest")
        return value


class DataLineage(BaseModel):
    """Reproducible operation and immutable references that produced a dataset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: str = Field(min_length=1, max_length=240)
    inputs: tuple[LineageInput, ...] = ()
    run_ref: str | None = Field(default=None, min_length=1, max_length=240)

    @field_validator("operation", "run_ref")
    @classmethod
    def _strip_lineage_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if not clean:
            raise ValueError("lineage fields must not be blank")
        return clean


class _DistributedMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    shape: tuple[int | None, ...]
    dtype: str = Field(min_length=1, max_length=128)
    partition: PartitionSpec
    lineage: DataLineage

    @field_validator("shape")
    @classmethod
    def _shape_has_valid_dimensions(
        cls,
        value: tuple[int | None, ...],
    ) -> tuple[int | None, ...]:
        if not value:
            raise ValueError("shape must contain at least one dimension")
        if any(dimension is not None and dimension < 0 for dimension in value):
            raise ValueError("shape dimensions must be non-negative or unknown")
        return value

    @field_validator("dtype")
    @classmethod
    def _dtype_is_canonical(cls, value: str) -> str:
        clean = value.strip()
        if not _DTYPE_PATTERN.fullmatch(clean):
            raise ValueError("dtype must be a canonical type identifier")
        return clean

    @model_validator(mode="after")
    def _partition_axis_exists(self) -> "_DistributedMetadata":
        if self.partition.axis is not None and self.partition.axis >= len(self.shape):
            raise ValueError("partition axis must exist in shape")
        if self.partition.strategy == PartitionStrategy.HASH or self.partition.keys:
            raise ValueError("dense arrays and tensors require axis-based partitioning")
        return self


class DistributedArrayMetadata(_DistributedMetadata):
    schema_id: str = Field(default=DISTRIBUTED_ARRAY_METADATA_SCHEMA, alias="schema")
    order: TensorOrder = TensorOrder.C


class DistributedTensorMetadata(_DistributedMetadata):
    schema_id: str = Field(default=DISTRIBUTED_TENSOR_METADATA_SCHEMA, alias="schema")
    order: TensorOrder = TensorOrder.C
    device: str | None = Field(default=None, min_length=1, max_length=160)

    @field_validator("device")
    @classmethod
    def _device_is_not_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if not clean:
            raise ValueError("device must not be blank")
        return clean


class DistributedHashMapMetadata(BaseModel):
    """Typed key/value and partition metadata for a distributed hash map."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=DISTRIBUTED_HASHMAP_METADATA_SCHEMA, alias="schema")
    key_dtype: str = Field(min_length=1, max_length=128)
    value_dtype: str = Field(min_length=1, max_length=128)
    partition: PartitionSpec
    lineage: DataLineage
    estimated_entries: int | None = Field(default=None, ge=0)
    consistency: MapConsistency = MapConsistency.SESSION

    @field_validator("key_dtype", "value_dtype")
    @classmethod
    def _map_dtype_is_canonical(cls, value: str) -> str:
        clean = value.strip()
        if not _DTYPE_PATTERN.fullmatch(clean):
            raise ValueError("map dtypes must be canonical type identifiers")
        return clean

    @model_validator(mode="after")
    def _partitioning_is_key_based(self) -> "DistributedHashMapMetadata":
        if self.partition.axis is not None or self.partition.strategy == PartitionStrategy.BLOCK:
            raise ValueError("hash maps require key-based partitioning")
        if self.partition.strategy in {PartitionStrategy.HASH, PartitionStrategy.RANGE}:
            if self.partition.keys != ("key",):
                raise ValueError("distributed hash maps must partition on the logical key")
        return self


__all__ = [
    "DISTRIBUTED_ARRAY_METADATA_SCHEMA",
    "DISTRIBUTED_HASHMAP_METADATA_SCHEMA",
    "DISTRIBUTED_TENSOR_METADATA_SCHEMA",
    "DataLineage",
    "DistributedArrayMetadata",
    "DistributedHashMapMetadata",
    "DistributedTensorMetadata",
    "LineageInput",
    "MapConsistency",
    "PartitionSpec",
    "PartitionStrategy",
    "TensorOrder",
]
