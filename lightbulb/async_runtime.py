"""Reusable async execution and partitioned streaming contracts.

The helpers in this module are transport independent.  They let SDK workflows
bound concurrency, adapt synchronous callables without blocking the event loop,
and consume cursor-bearing streams under an explicit replay and backpressure
policy.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import (
    Any,
    Generic,
    Literal,
    ParamSpec,
    Protocol,
    TypeVar,
    overload,
    runtime_checkable,
)

from pydantic import BaseModel, ConfigDict, Field, model_validator


STREAM_CURSOR_SCHEMA = "lightbulb.stream_cursor.v1"
STREAM_CONTRACT_SCHEMA = "lightbulb.partitioned_stream_contract.v1"

P = ParamSpec("P")
T = TypeVar("T")
R = TypeVar("R")


def _is_async_callable(operation: Callable[..., Any]) -> bool:
    return inspect.iscoroutinefunction(operation) or inspect.iscoroutinefunction(
        getattr(operation, "__call__", None)
    )


async def _invoke_without_blocking(
    operation: Callable[[T], R | Awaitable[R]],
    item: T,
) -> R:
    if _is_async_callable(operation):
        return await operation(item)  # type: ignore[misc, return-value]

    result = await asyncio.to_thread(operation, item)
    if inspect.isawaitable(result):
        return await result
    return result


def asyncify(
    operation: Callable[P, R] | Callable[P, Awaitable[R]],
) -> Callable[P, Awaitable[R]]:
    """Return an async callable, offloading synchronous work to a worker thread.

    Native coroutine functions remain on the event loop.  Synchronous functions
    run through :func:`asyncio.to_thread`, including callable objects whose
    ``__call__`` method is synchronous.  A synchronous factory that returns an
    awaitable is offloaded first and its returned awaitable is then awaited.
    """

    @functools.wraps(operation)
    async def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        if _is_async_callable(operation):
            return await operation(*args, **kwargs)  # type: ignore[misc, return-value]
        result = await asyncio.to_thread(operation, *args, **kwargs)
        if inspect.isawaitable(result):
            return await result
        return result

    return wrapped


class BatchExecutionError(RuntimeError):
    """One item failed during bounded batch execution."""

    def __init__(self, index: int, item: object, cause: Exception) -> None:
        super().__init__(f"batch item {index} failed: {cause}")
        self.index = index
        self.item = item
        self.cause = cause


@dataclass(frozen=True, slots=True)
class BatchItemResult(Generic[T, R]):
    """Per-item result returned when ``return_exceptions`` is enabled."""

    index: int
    item: T
    value: R | None = None
    error: Exception | None = None

    def __post_init__(self) -> None:
        if self.index < 0:
            raise ValueError("batch result index must be non-negative")
        if self.value is not None and self.error is not None:
            raise ValueError("a batch result cannot contain both value and error")

    @property
    def succeeded(self) -> bool:
        return self.error is None


@overload
async def bounded_map(
    operation: Callable[[T], R | Awaitable[R]],
    items: Iterable[T],
    *,
    concurrency: int = 8,
    return_exceptions: Literal[False] = False,
) -> list[R]: ...


@overload
async def bounded_map(
    operation: Callable[[T], R | Awaitable[R]],
    items: Iterable[T],
    *,
    concurrency: int = 8,
    return_exceptions: Literal[True],
) -> list[BatchItemResult[T, R]]: ...


async def bounded_map(
    operation: Callable[[T], R | Awaitable[R]],
    items: Iterable[T],
    *,
    concurrency: int = 8,
    return_exceptions: bool = False,
) -> list[R] | list[BatchItemResult[T, R]]:
    """Apply ``operation`` with bounded concurrency while preserving input order.

    Only ``concurrency`` worker tasks are created, regardless of batch size.
    Native async callables are awaited directly.  Synchronous callables are
    executed in worker threads so they cannot stall the event loop.
    """

    if isinstance(concurrency, bool) or not isinstance(concurrency, int):
        raise TypeError("concurrency must be an integer")
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")

    batch = list(items)
    if not batch:
        return []

    outcomes: list[Any] = [None] * len(batch)
    next_index = 0

    async def worker() -> None:
        nonlocal next_index
        while next_index < len(batch):
            index = next_index
            next_index += 1
            item = batch[index]
            try:
                value = await _invoke_without_blocking(operation, item)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if not return_exceptions:
                    raise BatchExecutionError(index, item, exc) from exc
                outcomes[index] = BatchItemResult(
                    index=index,
                    item=item,
                    error=exc,
                )
            else:
                outcomes[index] = (
                    BatchItemResult(index=index, item=item, value=value)
                    if return_exceptions
                    else value
                )

    tasks = [
        asyncio.create_task(worker())
        for _ in range(min(concurrency, len(batch)))
    ]
    try:
        await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    return outcomes


class ReplayMode(str, Enum):
    LIVE = "live"
    BEGINNING = "beginning"
    AFTER_CURSOR = "after_cursor"


class BackpressureStrategy(str, Enum):
    BLOCK = "block"
    ERROR = "error"
    DROP_OLDEST = "drop_oldest"


class StreamCursor(BaseModel):
    """Monotonic offset within exactly one logical stream partition."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=STREAM_CURSOR_SCHEMA, alias="schema")
    partition: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    offset: int = Field(ge=0)


class StreamPartition(BaseModel):
    """Stable identity and placement of one partition in a partition set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    partition_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    ordinal: int = Field(ge=0)
    partition_count: int = Field(ge=1)

    @model_validator(mode="after")
    def _ordinal_is_in_partition_set(self) -> "StreamPartition":
        if self.ordinal >= self.partition_count:
            raise ValueError("ordinal must be smaller than partition_count")
        return self


class ReplayPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: ReplayMode = ReplayMode.LIVE
    after: StreamCursor | None = None

    @model_validator(mode="after")
    def _cursor_matches_mode(self) -> "ReplayPolicy":
        if self.mode == ReplayMode.AFTER_CURSOR and self.after is None:
            raise ValueError("after_cursor replay requires an after cursor")
        if self.mode != ReplayMode.AFTER_CURSOR and self.after is not None:
            raise ValueError("an after cursor is only valid for after_cursor replay")
        return self


class BackpressurePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_buffered_records: int = Field(default=64, ge=1, le=100_000)
    strategy: BackpressureStrategy = BackpressureStrategy.BLOCK


class PartitionedStreamContract(BaseModel):
    """Consumer-visible contract for replayable, cursor-bearing delivery."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=STREAM_CONTRACT_SCHEMA, alias="schema")
    partition: StreamPartition
    replay: ReplayPolicy = Field(default_factory=ReplayPolicy)
    backpressure: BackpressurePolicy = Field(default_factory=BackpressurePolicy)
    cursor_monotonic: Literal[True] = True

    @model_validator(mode="after")
    def _replay_cursor_matches_partition(self) -> "PartitionedStreamContract":
        cursor = self.replay.after
        if cursor is not None and cursor.partition != self.partition.partition_id:
            raise ValueError("replay cursor must belong to the selected partition")
        return self


class StreamRecord(BaseModel, Generic[T]):
    """A payload bound to its durable partition cursor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cursor: StreamCursor
    value: T


@runtime_checkable
class PartitionedAsyncStream(Protocol[T]):
    """Protocol implemented by transports that honor a stream contract."""

    def read(
        self,
        contract: PartitionedStreamContract,
    ) -> AsyncIterator[StreamRecord[T]]: ...


class StreamContractError(ValueError):
    """A source record violates its declared partition or cursor contract."""


class StreamBackpressureError(RuntimeError):
    """The producer exceeded an error-on-overflow buffer policy."""


class _StreamFailure:
    def __init__(self, error: BaseException) -> None:
        self.error = error


_STREAM_END = object()


async def buffered_stream(
    source: AsyncIterable[StreamRecord[T]],
    contract: PartitionedStreamContract,
) -> AsyncIterator[StreamRecord[T]]:
    """Validate and buffer a partitioned stream under its backpressure policy.

    ``AFTER_CURSOR`` replay discards records through the supplied cursor and
    yields only later offsets.  Sources used with ``LIVE`` are expected to begin
    at their live edge; sources used with ``BEGINNING`` are expected to expose
    retained history from offset zero.
    """

    queue: asyncio.Queue[StreamRecord[T] | _StreamFailure | object] = asyncio.Queue(
        maxsize=contract.backpressure.max_buffered_records
    )
    selected_partition = contract.partition.partition_id
    replay_after = contract.replay.after
    previous_offset: int | None = None
    source_record_count = 0

    async def enqueue(record: StreamRecord[T]) -> None:
        strategy = contract.backpressure.strategy
        if strategy == BackpressureStrategy.BLOCK:
            await queue.put(record)
            return
        if strategy == BackpressureStrategy.ERROR:
            try:
                queue.put_nowait(record)
            except asyncio.QueueFull as exc:
                raise StreamBackpressureError(
                    "stream buffer is full under the error backpressure policy"
                ) from exc
            return
        if queue.full():
            queue.get_nowait()
        queue.put_nowait(record)

    async def produce() -> None:
        nonlocal previous_offset, source_record_count
        try:
            async for record in source:
                if record.cursor.partition != selected_partition:
                    raise StreamContractError(
                        "source record cursor does not match the selected partition"
                    )
                if (
                    source_record_count == 0
                    and contract.replay.mode == ReplayMode.BEGINNING
                    and record.cursor.offset != 0
                ):
                    raise StreamContractError(
                        "beginning replay must start at partition offset zero"
                    )
                source_record_count += 1
                if (
                    contract.cursor_monotonic
                    and previous_offset is not None
                    and record.cursor.offset <= previous_offset
                ):
                    raise StreamContractError(
                        "source cursor offsets must increase monotonically"
                    )
                previous_offset = record.cursor.offset
                if replay_after is not None and record.cursor.offset <= replay_after.offset:
                    continue
                await enqueue(record)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await queue.put(_StreamFailure(exc))
        await queue.put(_STREAM_END)

    producer = asyncio.create_task(produce())
    try:
        while True:
            item = await queue.get()
            if item is _STREAM_END:
                break
            if isinstance(item, _StreamFailure):
                raise item.error
            yield item  # type: ignore[misc]
    finally:
        if not producer.done():
            producer.cancel()
        await asyncio.gather(producer, return_exceptions=True)


__all__ = [
    "STREAM_CURSOR_SCHEMA",
    "STREAM_CONTRACT_SCHEMA",
    "BackpressurePolicy",
    "BackpressureStrategy",
    "BatchExecutionError",
    "BatchItemResult",
    "PartitionedAsyncStream",
    "PartitionedStreamContract",
    "ReplayMode",
    "ReplayPolicy",
    "StreamBackpressureError",
    "StreamContractError",
    "StreamCursor",
    "StreamPartition",
    "StreamRecord",
    "asyncify",
    "bounded_map",
    "buffered_stream",
]
