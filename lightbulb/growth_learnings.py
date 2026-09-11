"""Durable, integrity-sealed growth learnings ledger (growth memory).

Slice 3 of the Lightbulb Growth Engine. The ledger is what makes a portfolio
compound: verified experiment readouts and observational findings accumulate
per scope, and future plans query them instead of rediscovering (or worse,
re-guessing) the same lessons store by store.

Contract:

- **Append-only and hash-chained.** Every entry pins its predecessor's digest
  and sequence number; mutation, reordering, or interior removal is detected
  on every load, and loads fail closed. The chain alone canNOT detect tail
  truncation or wholesale rollback to an earlier valid snapshot — any valid
  prefix verifies. Callers who need rollback detection must persist
  ``head_digest()`` (and length) somewhere the ledger file's writer cannot
  reach and pass them to ``verify_chain(expected_head_digest=...,
  expected_length=...)``.
- **Grades are structural.** ``experimental`` entries can only be recorded
  from a verified, sealed, causal experiment readout — effect sizes are copied
  from the readout, never caller-supplied. ``observational`` entries require
  evidence digests and cannot carry confidence intervals or causal flags.
  ``heuristic`` entries carry no provenance and rank last.
- **Supersession, not deletion.** Wrong or outdated learnings are superseded
  by later entries; history remains auditable.
- **No wall clocks.** Callers supply ``recorded_at`` and query ``as_of``;
  sealed payload construction never reads the system clock.

Persistence follows the SDK's local-store idioms (exclusive lock file,
atomic private write, compare-and-set revisions). Sealing follows
``docs/growth-engine-build-contract-map.md``.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import os
import threading
import time
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .dynamic_workflows import DynamicWorkflowScope
from .growth_experiments import (
    GrowthExperimentDesign,
    GrowthExperimentReadout,
    verify_growth_experiment_design,
    verify_growth_experiment_readout,
)
from .growth_funnel import GrowthFunnelSnapshot, verify_growth_funnel_snapshot

GROWTH_LEARNING_ENTRY_SCHEMA = "lightbulb.growth_learning_entry.v1"
GROWTH_LEARNINGS_LEDGER_SCHEMA = "lightbulb.growth_learnings_ledger.v1"

_ENTRY_HMAC_DOMAIN = GROWTH_LEARNING_ENTRY_SCHEMA

_RATE_QUANTUM = Decimal("0.000001")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"

_MAX_LEDGER_ENTRIES = 10_000
_MAX_EVIDENCE_DIGESTS = 20
_MAX_QUERY_LIMIT = 100

FunnelStage = Literal[
    "audience",
    "traffic",
    "engagement",
    "conversion",
    "revenue",
    "retention",
]

LearningMetricName = Literal[
    "workflow_completion",
    "reach_to_visit",
    "visit_to_engage",
    "visit_to_purchase",
    "lead_capture",
    "purchase_to_repeat",
    "revenue_per_session",
    "average_order_value",
]

_METRIC_STAGE: dict[str, FunnelStage] = {
    "workflow_completion": "engagement",
    "reach_to_visit": "traffic",
    "visit_to_engage": "engagement",
    "visit_to_purchase": "conversion",
    "lead_capture": "conversion",
    "purchase_to_repeat": "retention",
    "revenue_per_session": "revenue",
    "average_order_value": "revenue",
}

LearningGrade = Literal["experimental", "observational", "heuristic"]
_GRADE_RANK: dict[str, int] = {
    "experimental": 0,
    "observational": 1,
    "heuristic": 2,
}


class GrowthLearningsValidationError(ValueError):
    """Learning content violates the ledger contract."""


class GrowthLearningsConflictError(RuntimeError):
    """A concurrent append advanced the ledger first; reload and retry."""


class GrowthLearningsPersistenceError(RuntimeError):
    """The ledger store is unavailable, corrupt, or tampered."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("content must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("content contains an unsupported control character")
    return value


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
LongText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=10_000),
    AfterValidator(_bounded_text),
]
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


def _parse_timestamp(value: str) -> datetime:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _normalized_timestamp(value: str) -> str:
    return _parse_timestamp(value).isoformat().replace("+00:00", "Z")


def _decimal(value: Any, *, quantum: Decimal | None = None) -> Decimal:
    if not isinstance(value, (str, Decimal, int, float)) or isinstance(value, bool):
        raise ValueError("decimal values must be supplied as strings or JSON numbers")
    lexical = str(value)
    if len(lexical) > 48 or lexical != lexical.strip():
        raise ValueError("value must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValueError("value must be a finite decimal")
    if quantum is not None:
        try:
            normalized = parsed.quantize(quantum)
        except InvalidOperation as exc:
            raise ValueError(
                "value cannot be represented at the required precision"
            ) from exc
        if parsed != normalized:
            raise ValueError(
                f"value supports at most {-quantum.as_tuple().exponent} decimal places"
            )
        return normalized
    return parsed


def _immutable_sequence(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class ExactScopeDigestProvider(Protocol):
    """Host-held keyed scope digester; raw authority never enters artifacts."""

    active_key_id: str

    def exact_scope_digest(
        self,
        *,
        key_id: str,
        scope: DynamicWorkflowScope,
    ) -> str: ...

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes: ...


def _keyring_signature(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    domain: str,
    payload: Any,
) -> str:
    try:
        return scope_keyring.sign(key_id, domain, payload).hex()
    except GrowthLearningsValidationError:
        raise
    except Exception as exc:
        raise GrowthLearningsValidationError(
            "the learnings signing key is unavailable"
        ) from exc


def _keyring_scope_digest(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    scope: DynamicWorkflowScope,
) -> str:
    try:
        return scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    except GrowthLearningsValidationError:
        raise
    except Exception as exc:
        raise GrowthLearningsValidationError(
            "the learnings signing key is unavailable"
        ) from exc


def _workflow_scope(
    scope: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(scope, DynamicWorkflowScope):
        return scope
    return DynamicWorkflowScope.model_validate(scope)


class GrowthLearningEntry(_StrictModel):
    """One sealed, chained fact in the growth memory."""

    schema_id: Literal["lightbulb.growth_learning_entry.v1"] = Field(
        default=GROWTH_LEARNING_ENTRY_SCHEMA,
        alias="schema",
    )
    entry_ref: PortableRef
    sequence: int = Field(ge=1, le=_MAX_LEDGER_ENTRIES)
    prev_entry_digest: Sha256Digest | None = None
    recorded_at: str
    stage: FunnelStage
    lever: PortableRef
    audience: ShortText | None = None
    metric_name: LearningMetricName
    claim: LongText
    grade: LearningGrade
    causal: bool
    effect_estimate: Decimal | None = None
    ci_low: Decimal | None = None
    ci_high: Decimal | None = None
    p_value: Decimal | None = Field(default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM)
    design_digest: Sha256Digest | None = None
    readout_digest: Sha256Digest | None = None
    evidence_digests: tuple[Sha256Digest, ...] = Field(
        default_factory=tuple, max_length=_MAX_EVIDENCE_DIGESTS
    )
    valid_until: str | None = None
    supersedes: Sha256Digest | None = None
    entry_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    entry_hmac: Sha256Digest | None = None

    @field_validator("recorded_at")
    @classmethod
    def _valid_recorded_at(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("valid_until")
    @classmethod
    def _valid_valid_until(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value)

    @field_validator("effect_estimate", "ci_low", "ci_high", "p_value", mode="before")
    @classmethod
    def _rate_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("evidence_digests", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _grade_shape(self) -> "GrowthLearningEntry":
        if (self.sequence == 1) != (self.prev_entry_digest is None):
            raise ValueError("only the first ledger entry may omit prev_entry_digest")
        if _METRIC_STAGE[self.metric_name] != self.stage:
            raise ValueError("learning stage does not match its metric")
        if self.causal != (self.grade == "experimental"):
            raise ValueError("causal learnings require experimental grade")
        interval = (self.ci_low, self.ci_high)
        if self.grade == "experimental":
            required = (
                self.effect_estimate,
                self.ci_low,
                self.ci_high,
                self.p_value,
                self.design_digest,
                self.readout_digest,
            )
            if any(value is None for value in required):
                raise ValueError(
                    "experimental learnings require effect statistics and "
                    "design and readout provenance"
                )
            if self.evidence_digests:
                raise ValueError(
                    "experimental provenance is the design and readout digests"
                )
            if not (self.ci_low <= self.effect_estimate <= self.ci_high):
                raise ValueError("effect estimates must fall inside their interval")
        elif self.grade == "observational":
            if not self.evidence_digests:
                raise ValueError(
                    "observational learnings require at least one evidence digest"
                )
            if len(set(self.evidence_digests)) != len(self.evidence_digests):
                raise ValueError("evidence digests must be unique")
            forbidden = (
                self.ci_low,
                self.ci_high,
                self.p_value,
                self.design_digest,
                self.readout_digest,
            )
            if any(value is not None for value in forbidden):
                raise ValueError(
                    "observational learnings cannot carry experimental statistics"
                )
        else:
            forbidden = (
                self.ci_low,
                self.ci_high,
                self.p_value,
                self.design_digest,
                self.readout_digest,
            )
            if any(value is not None for value in forbidden) or self.evidence_digests:
                raise ValueError("heuristic learnings carry no provenance")
        if any(value is not None for value in interval) and self.grade != (
            "experimental"
        ):
            raise ValueError("confidence intervals require an experimental readout")
        if self.valid_until is not None and _parse_timestamp(
            self.valid_until
        ) <= _parse_timestamp(self.recorded_at):
            raise ValueError("valid_until must follow recorded_at")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.entry_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "learning entry attestation fields must be supplied together"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"entry_digest", "entry_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.entry_digest != "0" * 64 and self.entry_digest != expected:
            raise ValueError("entry_digest does not match the canonical payload")
        object.__setattr__(self, "entry_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"entry_hmac", "entry_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def mint_growth_learning_entry(
    value: GrowthLearningEntry | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> GrowthLearningEntry:
    entry = (
        value
        if isinstance(value, GrowthLearningEntry)
        else GrowthLearningEntry.model_validate(value)
    )
    if entry.entry_hmac is not None or entry.receipt_key_id is not None:
        raise GrowthLearningsValidationError("learning entry is already attested")
    workflow_scope = _workflow_scope(scope)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    payload = entry.model_dump(
        mode="python",
        by_alias=True,
        exclude={"entry_digest"},
        exclude_none=True,
    )
    payload.update(
        {
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "entry_hmac": "0" * 64,
        }
    )
    draft = GrowthLearningEntry.model_validate(payload)
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_ENTRY_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"entry_digest"},
        exclude_none=True,
    )
    sealed["entry_hmac"] = signature
    return GrowthLearningEntry.model_validate(sealed)


def verify_growth_learning_entry(
    value: GrowthLearningEntry | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> GrowthLearningEntry:
    entry = GrowthLearningEntry.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, GrowthLearningEntry)
        else value
    )
    if (
        entry.receipt_key_id is None
        or entry.exact_scope_digest is None
        or entry.entry_hmac is None
    ):
        raise GrowthLearningsValidationError(
            "learning entry carries no host attestation"
        )
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=entry.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(entry.exact_scope_digest, expected_scope_digest):
        raise GrowthLearningsValidationError(
            "learning entry attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=entry.receipt_key_id,
        domain=_ENTRY_HMAC_DOMAIN,
        payload=entry.hmac_payload(),
    )
    if not hmac.compare_digest(entry.entry_hmac, expected_hmac):
        raise GrowthLearningsValidationError(
            "learning entry attestation failed verification"
        )
    return entry


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------


class LedgerStore(Protocol):
    """Revisioned storage for the serialized ledger chain."""

    def load(self) -> tuple[int, tuple[dict[str, Any], ...]]: ...

    def save(
        self,
        *,
        expected_revision: int,
        entries: tuple[dict[str, Any], ...],
    ) -> int: ...


class InMemoryLedgerStore:
    def __init__(self) -> None:
        self._revision = 0
        self._entries: tuple[dict[str, Any], ...] = ()
        self._lock = threading.Lock()

    def load(self) -> tuple[int, tuple[dict[str, Any], ...]]:
        with self._lock:
            return self._revision, tuple(
                json.loads(json.dumps(entry)) for entry in self._entries
            )

    def save(
        self,
        *,
        expected_revision: int,
        entries: tuple[dict[str, Any], ...],
    ) -> int:
        with self._lock:
            if expected_revision != self._revision:
                raise GrowthLearningsConflictError(
                    "the learnings ledger advanced concurrently; reload and retry"
                )
            self._entries = tuple(json.loads(json.dumps(entry)) for entry in entries)
            self._revision += 1
            return self._revision


_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_STALE_SECONDS = 30.0
_LOCK_TOKEN_COUNTER = itertools.count(1)


@contextmanager
def _exclusive_file_lock(path: Path):
    """Token-identified advisory lock with rename-based stale takeover.

    Each acquirer writes a unique token into its lock file. A stale lock is
    broken by atomically renaming it aside first — os.rename has exactly one
    winner, so two waiters can never both remove the stale file and then
    both believe they created the replacement. Release unlinks the lock only
    after confirming it still contains our token, so a holder can never
    delete a lock created by someone else.
    """

    lock_path = path.with_suffix(path.suffix + ".lock")
    token = f"{os.getpid()}:{threading.get_ident()}:{next(_LOCK_TOKEN_COUNTER)}"
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    descriptor: int | None = None
    while descriptor is None:
        if lock_path.is_symlink():
            raise GrowthLearningsPersistenceError(
                f"refusing symlinked lock file: {lock_path}"
            )
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                stale = time.time() - lock_path.stat().st_mtime > _LOCK_STALE_SECONDS
            except OSError:
                stale = False
            if stale:
                takeover = lock_path.with_name(
                    f"{lock_path.name}.stale.{os.getpid()}.{threading.get_ident()}"
                )
                try:
                    os.rename(lock_path, takeover)
                except OSError:
                    pass  # someone else won the takeover; retry the loop
                else:
                    takeover.unlink(missing_ok=True)
                continue
            if time.monotonic() >= deadline:
                raise GrowthLearningsPersistenceError(
                    "the learnings ledger store is busy"
                )
            time.sleep(0.05)
    try:
        os.write(descriptor, token.encode("ascii"))
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        try:
            still_ours = lock_path.read_text(encoding="ascii") == token
        except OSError:
            still_ours = False
        if still_ours:
            lock_path.unlink(missing_ok=True)


def _atomic_write_private(path: Path, content: str) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise GrowthLearningsPersistenceError(f"unsafe ledger target: {path}")
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    if temporary.is_symlink():
        raise GrowthLearningsPersistenceError(f"unsafe ledger temporary: {temporary}")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        handle = os.fdopen(descriptor, "w", encoding="utf-8", newline="")
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    # From here the handle owns the descriptor; never close it twice — a
    # recycled fd number could belong to another thread by the time an
    # exception handler runs.
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


class JsonFileLedgerStore:
    """Atomic local persistence for one scope's ledger file.

    Cross-process safety comes from the exclusive lock held across the
    read-check-write in :meth:`save`; loads outside the lock are safe because
    writes are atomic replacements.
    """

    def __init__(self, path: str | Path) -> None:
        requested = Path(path).expanduser()
        if requested.is_symlink():
            raise GrowthLearningsPersistenceError(
                f"refusing symlinked ledger file: {requested}"
            )
        self.path = requested
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read(self) -> tuple[int, tuple[dict[str, Any], ...]]:
        if not self.path.exists():
            return 0, ()
        if self.path.is_symlink() or not self.path.is_file():
            raise GrowthLearningsPersistenceError(f"unsafe ledger target: {self.path}")
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise GrowthLearningsPersistenceError(
                "the learnings ledger file is unreadable or corrupt"
            ) from exc
        if (
            not isinstance(raw, dict)
            or raw.get("schema") != GROWTH_LEARNINGS_LEDGER_SCHEMA
            or not isinstance(raw.get("revision"), int)
            or not isinstance(raw.get("entries"), list)
        ):
            raise GrowthLearningsPersistenceError(
                "the learnings ledger file does not match the ledger schema"
            )
        return raw["revision"], tuple(raw["entries"])

    def load(self) -> tuple[int, tuple[dict[str, Any], ...]]:
        return self._read()

    def save(
        self,
        *,
        expected_revision: int,
        entries: tuple[dict[str, Any], ...],
    ) -> int:
        with _exclusive_file_lock(self.path):
            current_revision, _ = self._read()
            if expected_revision != current_revision:
                raise GrowthLearningsConflictError(
                    "the learnings ledger advanced concurrently; reload and retry"
                )
            revision = current_revision + 1
            content = json.dumps(
                {
                    "schema": GROWTH_LEARNINGS_LEDGER_SCHEMA,
                    "revision": revision,
                    "entries": list(entries),
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            _atomic_write_private(self.path, content)
            return revision


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class GrowthLearningsLedger:
    """Scope-bound view over one verified learning chain."""

    def __init__(
        self,
        store: LedgerStore,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        scope_keyring: ExactScopeDigestProvider,
        scope_key_id: str | None = None,
    ) -> None:
        self._store = store
        self._scope = _workflow_scope(scope)
        self._keyring = scope_keyring
        self._key_id = scope_key_id

    @property
    def scope(self) -> DynamicWorkflowScope:
        """This ledger's authority scope (a frozen, immutable model)."""

        return self._scope

    def _load_verified(
        self,
    ) -> tuple[int, tuple[GrowthLearningEntry, ...]]:
        revision, raw_entries = self._store.load()
        entries: list[GrowthLearningEntry] = []
        seen_digests: set[str] = set()
        previous: GrowthLearningEntry | None = None
        for index, raw in enumerate(raw_entries, start=1):
            entry = verify_growth_learning_entry(
                raw, scope=self._scope, scope_keyring=self._keyring
            )
            if entry.sequence != index:
                raise GrowthLearningsPersistenceError(
                    "the learnings chain sequence is broken; the ledger was "
                    "reordered or truncated"
                )
            expected_prev = previous.entry_digest if previous is not None else None
            if entry.prev_entry_digest != expected_prev:
                raise GrowthLearningsPersistenceError(
                    "the learnings chain linkage is broken; an entry was "
                    "mutated, inserted, or removed"
                )
            if entry.supersedes is not None and entry.supersedes not in seen_digests:
                raise GrowthLearningsPersistenceError(
                    "a learning supersedes an entry absent from its chain"
                )
            seen_digests.add(entry.entry_digest)
            entries.append(entry)
            previous = entry
        return revision, tuple(entries)

    def entries(self) -> tuple[GrowthLearningEntry, ...]:
        _, verified = self._load_verified()
        return verified

    def head_digest(self) -> str | None:
        _, verified = self._load_verified()
        return verified[-1].entry_digest if verified else None

    def verify_chain(
        self,
        *,
        expected_head_digest: str | None = None,
        expected_length: int | None = None,
    ) -> int:
        """Fully re-verify the chain; return the entry count.

        The chain itself proves that no entry was mutated, reordered, or
        removed from the interior. It CANNOT prove the tail was not truncated
        or the whole file rolled back to an earlier valid snapshot — any valid
        prefix verifies. Callers who need rollback detection must persist the
        head digest (and optionally the length) somewhere the file's writer
        cannot reach, and pass them here as the anchor.
        """

        _, verified = self._load_verified()
        if expected_length is not None and len(verified) != expected_length:
            raise GrowthLearningsPersistenceError(
                "the learnings chain length does not match the external "
                "anchor; the ledger tail was truncated or rolled back"
            )
        actual_head = verified[-1].entry_digest if verified else None
        if expected_head_digest is not None and actual_head != (expected_head_digest):
            raise GrowthLearningsPersistenceError(
                "the learnings chain head does not match the external "
                "anchor; the ledger tail was truncated or rolled back"
            )
        return len(verified)

    def _append(self, body: dict[str, Any]) -> GrowthLearningEntry:
        revision, verified = self._load_verified()
        if len(verified) >= _MAX_LEDGER_ENTRIES:
            raise GrowthLearningsValidationError(
                "the learnings ledger is full; archive before appending"
            )
        if body.get("supersedes") is not None:
            known = {entry.entry_digest for entry in verified}
            if body["supersedes"] not in known:
                raise GrowthLearningsValidationError(
                    "supersedes must reference an existing ledger entry"
                )
        body = dict(body)
        body["sequence"] = len(verified) + 1
        body["prev_entry_digest"] = verified[-1].entry_digest if verified else None
        if body["prev_entry_digest"] is None:
            body.pop("prev_entry_digest")
        sealed = mint_growth_learning_entry(
            body,
            scope=self._scope,
            scope_keyring=self._keyring,
            scope_key_id=self._key_id,
        )
        serialized = tuple([*(entry.to_dict() for entry in verified), sealed.to_dict()])
        self._store.save(expected_revision=revision, entries=serialized)
        return sealed

    def record_experiment_learning(
        self,
        *,
        design: GrowthExperimentDesign | Mapping[str, Any],
        readout: GrowthExperimentReadout | Mapping[str, Any],
        entry_ref: str,
        lever: str,
        claim: str,
        recorded_at: str,
        audience: str | None = None,
        valid_until: str | None = None,
        supersedes: str | None = None,
    ) -> GrowthLearningEntry:
        """Record a causal learning; effect statistics come from the readout."""

        verified_design = verify_growth_experiment_design(
            design, scope=self._scope, scope_keyring=self._keyring
        )
        verified_readout = verify_growth_experiment_readout(
            readout, scope=self._scope, scope_keyring=self._keyring
        )
        if verified_readout.design_digest != verified_design.design_digest:
            raise GrowthLearningsValidationError(
                "the readout is bound to a different design"
            )
        if not verified_readout.causal:
            raise GrowthLearningsValidationError(
                "only causal readouts can be recorded as experimental; record "
                "an observational learning instead"
            )
        body: dict[str, Any] = {
            "entry_ref": entry_ref,
            "recorded_at": recorded_at,
            "stage": _METRIC_STAGE[verified_readout.metric_name],
            "lever": lever,
            "metric_name": verified_readout.metric_name,
            "claim": claim,
            "grade": "experimental",
            "causal": True,
            "effect_estimate": verified_readout.effect_estimate,
            "ci_low": verified_readout.ci_low,
            "ci_high": verified_readout.ci_high,
            "p_value": verified_readout.p_value,
            "design_digest": verified_design.design_digest,
            "readout_digest": verified_readout.readout_digest,
        }
        if audience is not None:
            body["audience"] = audience
        if valid_until is not None:
            body["valid_until"] = valid_until
        if supersedes is not None:
            body["supersedes"] = supersedes
        return self._append(body)

    def record_observational_learning(
        self,
        *,
        entry_ref: str,
        lever: str,
        metric_name: LearningMetricName,
        claim: str,
        recorded_at: str,
        funnel_snapshot: GrowthFunnelSnapshot | Mapping[str, Any] | None = None,
        evidence_digests: tuple[str, ...] | list[str] | None = None,
        effect_estimate: str | Decimal | None = None,
        audience: str | None = None,
        valid_until: str | None = None,
        supersedes: str | None = None,
    ) -> GrowthLearningEntry:
        """Record a non-causal finding backed by named evidence digests."""

        digests: list[str] = list(evidence_digests or ())
        if funnel_snapshot is not None:
            verified_snapshot = verify_growth_funnel_snapshot(
                funnel_snapshot, scope=self._scope, scope_keyring=self._keyring
            )
            digests.append(verified_snapshot.funnel_digest)
        body: dict[str, Any] = {
            "entry_ref": entry_ref,
            "recorded_at": recorded_at,
            "stage": _METRIC_STAGE[metric_name],
            "lever": lever,
            "metric_name": metric_name,
            "claim": claim,
            "grade": "observational",
            "causal": False,
            "evidence_digests": tuple(digests),
        }
        if effect_estimate is not None:
            body["effect_estimate"] = effect_estimate
        if audience is not None:
            body["audience"] = audience
        if valid_until is not None:
            body["valid_until"] = valid_until
        if supersedes is not None:
            body["supersedes"] = supersedes
        return self._append(body)

    def record_heuristic_learning(
        self,
        *,
        entry_ref: str,
        lever: str,
        metric_name: LearningMetricName,
        claim: str,
        recorded_at: str,
        effect_estimate: str | Decimal | None = None,
        audience: str | None = None,
        valid_until: str | None = None,
        supersedes: str | None = None,
    ) -> GrowthLearningEntry:
        """Record an assumption; ranks last and carries no provenance."""

        body: dict[str, Any] = {
            "entry_ref": entry_ref,
            "recorded_at": recorded_at,
            "stage": _METRIC_STAGE[metric_name],
            "lever": lever,
            "metric_name": metric_name,
            "claim": claim,
            "grade": "heuristic",
            "causal": False,
        }
        if effect_estimate is not None:
            body["effect_estimate"] = effect_estimate
        if audience is not None:
            body["audience"] = audience
        if valid_until is not None:
            body["valid_until"] = valid_until
        if supersedes is not None:
            body["supersedes"] = supersedes
        return self._append(body)

    def query(
        self,
        *,
        as_of: str,
        stage: FunnelStage | None = None,
        lever: str | None = None,
        metric_name: LearningMetricName | None = None,
        include_superseded: bool = False,
        limit: int = 20,
    ) -> tuple[GrowthLearningEntry, ...]:
        """Return the learnings applicable AS OF the given instant.

        Point-in-time semantics are consistent in both directions: entries
        recorded after ``as_of`` do not exist yet (no look-ahead), and
        supersession only counts if the superseding entry itself existed at
        ``as_of``.
        """

        if not 1 <= limit <= _MAX_QUERY_LIMIT:
            raise GrowthLearningsValidationError(
                f"query limit must be between 1 and {_MAX_QUERY_LIMIT}"
            )
        as_of_at = _parse_timestamp(_normalized_timestamp(as_of))
        _, verified = self._load_verified()
        existing = [
            entry
            for entry in verified
            if _parse_timestamp(entry.recorded_at) <= as_of_at
        ]
        superseded = {
            entry.supersedes for entry in existing if entry.supersedes is not None
        }
        results = []
        for entry in existing:
            if not include_superseded and entry.entry_digest in superseded:
                continue
            if entry.valid_until is not None and (
                _parse_timestamp(entry.valid_until) <= as_of_at
            ):
                continue
            if stage is not None and entry.stage != stage:
                continue
            if lever is not None and entry.lever != lever:
                continue
            if metric_name is not None and entry.metric_name != metric_name:
                continue
            results.append(entry)
        results.sort(key=lambda entry: (_GRADE_RANK[entry.grade], -entry.sequence))
        return tuple(results[:limit])


__all__ = [
    "GROWTH_LEARNING_ENTRY_SCHEMA",
    "GROWTH_LEARNINGS_LEDGER_SCHEMA",
    "GrowthLearningEntry",
    "GrowthLearningsConflictError",
    "GrowthLearningsLedger",
    "GrowthLearningsPersistenceError",
    "GrowthLearningsValidationError",
    "InMemoryLedgerStore",
    "JsonFileLedgerStore",
    "LedgerStore",
    "mint_growth_learning_entry",
    "verify_growth_learning_entry",
]
