"""Durable growth workspace: one scope's persistent home for growth work.

Everything the Growth Engine produces — funnel snapshots, preregistered
experiment designs, arm evidence, readouts, demand-gen plans, portfolio
rollups, diagnoses — lived only in memory until now; only the learnings
ledger persisted. This module gives an agent working across sessions a
durable, scope-bound workspace: seal a design today, come back at the
horizon weeks later, and the readout can proceed against the exact sealed
preregistration.

Contract:

- **Verified in, verified out.** Sealed artifact kinds are HMAC-verified
  against the workspace scope on save AND on every load; a workspace never
  returns an artifact it cannot re-verify, and it refuses to persist unsealed
  artifacts (if it is worth keeping, build it with the keyring). Diagnoses
  are the exception: they are re-derivable digest-pinned advice, stored as
  ``advisory`` records with model validation only.
- **Content-addressed.** An artifact's storage identity is the SHA-256 of its
  canonical serialization; saving the same artifact twice is a no-op, and a
  mutated artifact file can never be returned under its old identity.
- **Coherent.** Arm evidence and readouts require their design to be stored
  first, and a design gets exactly one readout, ever — fixed-horizon
  preregistration means there is exactly one truth per experiment.
- **Deterministic lifecycle.** ``experiment_status(as_of)``,
  ``pending_readouts(as_of)``, and ``status(as_of)`` answer "what is in
  flight and what is due" from caller-supplied time; nothing reads the wall
  clock, and ``saved_at`` stamps are caller-supplied.
- **Honest about integrity.** Sealed artifact kinds carry cryptographic
  (HMAC) integrity, re-verified on load and in the lifecycle queries. Advisory
  diagnoses are content-addressed and model-validated but NOT HMAC-sealed
  (they are re-derivable advice), so an actor with file access could inject a
  fabricated diagnosis — never a fabricated sealed artifact. The INVENTORY is
  a local convenience: an actor with file access can also hide rows (like
  ledger tail truncation); persist ``index_revision`` externally to detect
  that.

The workspace also owns the scope's learnings ledger
(:meth:`GrowthWorkspace.ledger`), so the full loop — measure, preregister,
read out, learn — lives under one directory. Persistence reuses the audited
lock/atomic-write helpers from :mod:`lightbulb.growth_learnings` so those
fixes live in exactly one place.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

from .demand_gen_primitives import (
    AudienceGrowthPlan,
    ContentCalendarPlan,
    verify_audience_growth_plan,
    verify_content_calendar_plan,
)
from .dynamic_workflows import DynamicWorkflowScope
from .growth_cockpit import GrowthDiagnosis
from .growth_experiments import (
    ExperimentArmEvidence,
    GrowthExperimentDesign,
    GrowthExperimentReadout,
    verify_experiment_arm_evidence,
    verify_growth_experiment_design,
    verify_growth_experiment_readout,
)
from .growth_funnel import GrowthFunnelSnapshot, verify_growth_funnel_snapshot
from .growth_learnings import (
    GrowthLearningsLedger,
    GrowthLearningsPersistenceError,
    JsonFileLedgerStore,
    _atomic_write_private,
    _exclusive_file_lock,
)
from .growth_portfolio import (
    PortfolioDiagnosis,
    PortfolioFunnelRollup,
    verify_portfolio_funnel_rollup,
)
from .growth_customers import (
    CustomerValueReview,
    CustomerValueSnapshot,
    verify_customer_value_snapshot,
)
from .growth_briefing import GrowthBriefing, compile_growth_briefing
from .growth_mandate import (
    ActionAuthorization,
    GrowthMandate,
    ProposedAction,
    authorize_growth_action,
    verify_action_authorization,
    verify_growth_mandate,
)
from .growth_objectives import (
    GrowthObjective,
    ObjectiveAssessment,
    verify_growth_objective,
)
from .growth_operating import (
    FunnelDelta,
    GrowthAgenda,
    GrowthAgendaInput,
    GrowthCadencePolicy,
    compile_growth_agenda,
)
from .growth_profit import (
    PriceElasticityEstimate,
    PricePlan,
    ProfitReview,
    UnitEconomicsSnapshot,
    verify_price_plan,
    verify_unit_economics_snapshot,
)
from .growth_rail_bridge import (
    GrowthRailBridgeValidationError,
    RailDispatchPackage,
    RailExecutionReceipt,
    reconcile_dispatch_receipts,
    verify_rail_dispatch_package,
    verify_rail_execution_receipt,
)

GROWTH_WORKSPACE_INDEX_SCHEMA = "lightbulb.growth_workspace_index.v1"

_MAX_WORKSPACE_ARTIFACTS = 5_000
_MAX_ARTIFACT_BYTES = 10 * 1024 * 1024

_SHA256_PATTERN = r"^[0-9a-f]{64}$"

WorkspaceKind = Literal[
    "funnel_snapshot",
    "experiment_design",
    "arm_evidence",
    "experiment_readout",
    "content_calendar_plan",
    "audience_growth_plan",
    "portfolio_rollup",
    "growth_diagnosis",
    "portfolio_diagnosis",
    "rail_dispatch",
    "rail_receipt",
    "unit_economics",
    "price_plan",
    "profit_review",
    "price_elasticity",
    "growth_agenda",
    "funnel_delta",
    "customer_value",
    "customer_value_review",
    "growth_objective",
    "objective_assessment",
    "growth_mandate",
    "action_authorization",
]

ExperimentState = Literal["designed", "running", "awaiting_readout", "read_out"]


class GrowthWorkspaceValidationError(ValueError):
    """Workspace content violates the coherence or custody contract."""


class GrowthWorkspacePersistenceError(RuntimeError):
    """The workspace store is unavailable, corrupt, or tampered."""


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


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class WorkspaceRecord(_StrictModel):
    kind: WorkspaceKind
    ref: ShortText
    storage_digest: Sha256Digest
    saved_at: str
    advisory: bool

    @field_validator("saved_at")
    @classmethod
    def _valid_saved_at(cls, value: str) -> str:
        return _normalized_timestamp(value)


class ExperimentStatusRecord(_StrictModel):
    design_ref: ShortText
    design_digest: Sha256Digest
    state: ExperimentState
    exposure_start: str
    readout_horizon: str
    readout_digest: Sha256Digest | None = None
    verdict: ShortText | None = None

    @field_validator("exposure_start", "readout_horizon")
    @classmethod
    def _valid_timestamps(cls, value: str) -> str:
        return _normalized_timestamp(value)


class WorkspaceStatus(_StrictModel):
    as_of: str
    scope_project_ref: ShortText
    artifact_counts: dict[str, int] = Field(default_factory=dict)
    experiments: tuple[ExperimentStatusRecord, ...] = Field(default_factory=tuple)
    pending_readout_refs: tuple[ShortText, ...] = Field(default_factory=tuple)
    index_revision: int = Field(ge=0)

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)


@dataclass(frozen=True)
class _KindSpec:
    kind: str
    model: type[BaseModel]
    ref_field: str
    verify: Callable[..., Any] | None  # None => advisory record


_KIND_SPECS: dict[str, _KindSpec] = {
    spec.kind: spec
    for spec in (
        _KindSpec(
            "funnel_snapshot",
            GrowthFunnelSnapshot,
            "snapshot_ref",
            verify_growth_funnel_snapshot,
        ),
        _KindSpec(
            "experiment_design",
            GrowthExperimentDesign,
            "design_ref",
            verify_growth_experiment_design,
        ),
        _KindSpec(
            "arm_evidence",
            ExperimentArmEvidence,
            "observation_ref",
            verify_experiment_arm_evidence,
        ),
        _KindSpec(
            "experiment_readout",
            GrowthExperimentReadout,
            "readout_ref",
            verify_growth_experiment_readout,
        ),
        _KindSpec(
            "content_calendar_plan",
            ContentCalendarPlan,
            "calendar_ref",
            verify_content_calendar_plan,
        ),
        _KindSpec(
            "audience_growth_plan",
            AudienceGrowthPlan,
            "plan_ref",
            verify_audience_growth_plan,
        ),
        _KindSpec(
            "portfolio_rollup",
            PortfolioFunnelRollup,
            "portfolio_ref",
            verify_portfolio_funnel_rollup,
        ),
        _KindSpec("growth_diagnosis", GrowthDiagnosis, "funnel_digest", None),
        _KindSpec("portfolio_diagnosis", PortfolioDiagnosis, "portfolio_ref", None),
        _KindSpec(
            "rail_dispatch",
            RailDispatchPackage,
            "dispatch_ref",
            verify_rail_dispatch_package,
        ),
        _KindSpec(
            "rail_receipt",
            RailExecutionReceipt,
            "receipt_ref",
            verify_rail_execution_receipt,
        ),
        _KindSpec(
            "unit_economics",
            UnitEconomicsSnapshot,
            "economics_ref",
            verify_unit_economics_snapshot,
        ),
        _KindSpec(
            "price_plan",
            PricePlan,
            "plan_ref",
            verify_price_plan,
        ),
        _KindSpec("profit_review", ProfitReview, "economics_digest", None),
        _KindSpec(
            "price_elasticity", PriceElasticityEstimate, "estimate_ref", None
        ),
        _KindSpec("growth_agenda", GrowthAgenda, "as_of", None),
        _KindSpec("funnel_delta", FunnelDelta, "current_digest", None),
        _KindSpec(
            "customer_value",
            CustomerValueSnapshot,
            "value_ref",
            verify_customer_value_snapshot,
        ),
        _KindSpec(
            "customer_value_review", CustomerValueReview, "value_digest", None
        ),
        _KindSpec(
            "growth_objective",
            GrowthObjective,
            "objective_ref",
            verify_growth_objective,
        ),
        _KindSpec(
            "objective_assessment", ObjectiveAssessment, "objective_ref", None
        ),
        _KindSpec(
            "growth_mandate",
            GrowthMandate,
            "mandate_ref",
            verify_growth_mandate,
        ),
        _KindSpec(
            "action_authorization",
            ActionAuthorization,
            "authorization_ref",
            verify_action_authorization,
        ),
    )
}


def _canonical_artifact_dict(artifact: BaseModel) -> dict[str, Any]:
    return artifact.model_dump(mode="json", by_alias=True, exclude_none=True)


class GrowthWorkspace:
    """One scope's durable, verified store of Growth Engine artifacts."""

    def __init__(
        self,
        directory: str | Path,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        scope_keyring: Any,
        scope_key_id: str | None = None,
    ) -> None:
        requested = Path(directory).expanduser()
        if requested.is_symlink():
            raise GrowthWorkspacePersistenceError(
                f"refusing symlinked workspace directory: {requested}"
            )
        self.directory = requested
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass
        self._scope = (
            scope
            if isinstance(scope, DynamicWorkflowScope)
            else DynamicWorkflowScope.model_validate(scope)
        )
        self._keyring = scope_keyring
        self._key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
        self._index_path = self.directory / "index.json"
        self._bind_scope()

    # -- scope binding ----------------------------------------------------

    def _scope_digest(self, key_id: str) -> str:
        try:
            return self._keyring.exact_scope_digest(key_id=key_id, scope=self._scope)
        except Exception as exc:
            raise GrowthWorkspaceValidationError(
                "the workspace signing key is unavailable"
            ) from exc

    def _assert_scope_binding(self, index: dict[str, Any] | None) -> None:
        """Raise if ``index`` is bound to a different scope than this workspace."""

        if index is None:
            return
        stored_key_id = index.get("scope_key_id")
        stored_digest = index.get("scope_digest")
        if not isinstance(stored_key_id, str) or not isinstance(stored_digest, str):
            raise GrowthWorkspacePersistenceError(
                "the workspace index does not carry its scope binding"
            )
        if self._scope_digest(stored_key_id) != stored_digest:
            raise GrowthWorkspaceValidationError(
                "this directory belongs to a different workspace scope"
            )

    def _bind_scope(self) -> None:
        self._assert_scope_binding(self._read_index())

    # -- index ------------------------------------------------------------

    def _read_index(self) -> dict[str, Any] | None:
        if not self._index_path.exists():
            return None
        if self._index_path.is_symlink() or not self._index_path.is_file():
            raise GrowthWorkspacePersistenceError(
                f"unsafe workspace index: {self._index_path}"
            )
        try:
            raw = json.loads(self._index_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise GrowthWorkspacePersistenceError(
                "the workspace index is unreadable or corrupt"
            ) from exc
        if (
            not isinstance(raw, dict)
            or raw.get("schema") != GROWTH_WORKSPACE_INDEX_SCHEMA
            or not isinstance(raw.get("revision"), int)
            or not isinstance(raw.get("artifacts"), list)
        ):
            raise GrowthWorkspacePersistenceError(
                "the workspace index does not match the workspace schema"
            )
        return raw

    def _records(self, raw: dict[str, Any] | None) -> list[WorkspaceRecord]:
        if raw is None:
            return []
        return [WorkspaceRecord.model_validate(row) for row in raw["artifacts"]]

    def _write_index(self, *, revision: int, records: list[WorkspaceRecord]) -> None:
        content = json.dumps(
            {
                "schema": GROWTH_WORKSPACE_INDEX_SCHEMA,
                "revision": revision,
                "scope_key_id": self._key_id,
                "scope_digest": self._scope_digest(self._key_id),
                "artifacts": [
                    record.model_dump(mode="json", by_alias=True) for record in records
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        try:
            _atomic_write_private(self._index_path, content)
        except GrowthWorkspacePersistenceError:
            raise
        except Exception as exc:
            raise GrowthWorkspacePersistenceError(
                "cannot write the workspace index"
            ) from exc

    def _artifact_path(self, kind: str, storage_digest: str) -> Path:
        return self.directory / f"{kind}-{storage_digest}.json"

    # -- verification -----------------------------------------------------

    def _verify(self, spec: _KindSpec, value: Any) -> BaseModel:
        if spec.verify is None:
            return spec.model.model_validate(
                _canonical_artifact_dict(value)
                if isinstance(value, BaseModel)
                else value
            )
        return spec.verify(value, scope=self._scope, scope_keyring=self._keyring)

    # -- save -------------------------------------------------------------

    def _save(
        self, kind: WorkspaceKind, value: Any, *, saved_at: str
    ) -> WorkspaceRecord:
        with self._index_lock():
            return self._save_under_lock(kind, value, saved_at=saved_at)

    def _save_under_lock(
        self, kind: WorkspaceKind, value: Any, *, saved_at: str
    ) -> WorkspaceRecord:
        """The save body; the caller MUST already hold the index lock."""

        spec = _KIND_SPECS[kind]
        artifact = self._verify(spec, value)
        payload = _canonical_artifact_dict(artifact)
        storage_digest = _stable_digest(payload)
        ref = str(payload.get(spec.ref_field, "")) or storage_digest[:16]
        record = WorkspaceRecord(
            kind=kind,
            ref=ref,
            storage_digest=storage_digest,
            saved_at=saved_at,
            advisory=spec.verify is None,
        )
        content = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        artifact_path = self._artifact_path(kind, storage_digest)
        raw = self._read_index()
        # Re-check the scope binding UNDER THE LOCK: a concurrent instance
        # with a different scope could have written the index between our
        # open and now, and _write_index below would otherwise silently
        # rebind the directory to our scope.
        self._assert_scope_binding(raw)
        records = self._records(raw)
        revision = raw["revision"] if raw is not None else 0
        existing = {row.storage_digest: row for row in records if row.kind == kind}
        if storage_digest in existing:
            # Idempotent hit — but heal the store if the content-addressed
            # file went missing, so a re-save cannot silently vouch for an
            # artifact that is no longer on disk.
            if not artifact_path.is_file():
                self._write_artifact(artifact_path, content)
            return existing[storage_digest]
        if len(records) >= _MAX_WORKSPACE_ARTIFACTS:
            raise GrowthWorkspaceValidationError(
                "the workspace is full; archive before saving more"
            )
        self._enforce_coherence(kind, payload, records)
        self._write_artifact(artifact_path, content)
        records.append(record)
        self._write_index(revision=revision + 1, records=records)
        return record

    @contextmanager
    def _index_lock(self):
        """Hold the index lock, re-wrapping the ledger helper's error so a
        workspace caller never sees a 'learnings ledger' message."""

        try:
            with _exclusive_file_lock(self._index_path):
                yield
        except GrowthLearningsPersistenceError as exc:
            raise GrowthWorkspacePersistenceError(
                "the workspace store is busy or unavailable"
            ) from exc

    def _write_artifact(self, path: Path, content: str) -> None:
        try:
            _atomic_write_private(path, content)
        except GrowthWorkspacePersistenceError:
            raise
        except Exception as exc:
            raise GrowthWorkspacePersistenceError(
                "cannot write the workspace artifact"
            ) from exc

    def _enforce_coherence(
        self,
        kind: str,
        payload: Mapping[str, Any],
        records: list[WorkspaceRecord],
    ) -> None:
        if kind in {"arm_evidence", "experiment_readout"}:
            design_digest = str(payload.get("design_digest", ""))
            designs = [
                self._load_payload(row)
                for row in records
                if row.kind == "experiment_design"
            ]
            if not any(
                design.get("design_digest") == design_digest for design in designs
            ):
                raise GrowthWorkspaceValidationError(
                    "store the sealed experiment design before its evidence or readout"
                )
        if kind == "experiment_readout":
            design_digest = str(payload.get("design_digest", ""))
            for row in records:
                if row.kind != "experiment_readout":
                    continue
                stored = self._load_payload(row)
                if stored.get("design_digest") == design_digest:
                    raise GrowthWorkspaceValidationError(
                        "this design already has its fixed-horizon readout; "
                        "a second readout is not a thing that can honestly "
                        "exist"
                    )
        if kind == "price_plan":
            economics_digest = str(
                (payload.get("operation") or {}).get("economics_digest", "")
            )
            stored_economics = [
                self._load_payload(row)
                for row in records
                if row.kind == "unit_economics"
            ]
            if not any(
                economics.get("economics_digest") == economics_digest
                for economics in stored_economics
            ):
                raise GrowthWorkspaceValidationError(
                    "store the sealed unit economics before the price plan "
                    "they informed"
                )
        if kind == "objective_assessment":
            objective_digest = str(payload.get("objective_digest", ""))
            stored_objectives = [
                self._load_payload(row)
                for row in records
                if row.kind == "growth_objective"
            ]
            if not any(
                objective.get("objective_digest") == objective_digest
                for objective in stored_objectives
            ):
                raise GrowthWorkspaceValidationError(
                    "store the sealed objective before assessments of it"
                )
        if kind == "growth_objective":
            supersedes = payload.get("supersedes")
            if supersedes is not None:
                stored_objectives = [
                    self._load_payload(row)
                    for row in records
                    if row.kind == "growth_objective"
                ]
                if not any(
                    objective.get("objective_digest") == str(supersedes)
                    for objective in stored_objectives
                ):
                    raise GrowthWorkspaceValidationError(
                        "an objective may only supersede an objective this "
                        "workspace actually holds; a fabricated audit chain "
                        "is not a thing that can honestly exist"
                    )
        if kind == "action_authorization":
            mandate_digest = str(payload.get("mandate_digest", ""))
            stored_mandates = [
                self._load_payload(row)
                for row in records
                if row.kind == "growth_mandate"
            ]
            if not any(
                mandate.get("mandate_digest") == mandate_digest
                for mandate in stored_mandates
            ):
                raise GrowthWorkspaceValidationError(
                    "store the sealed mandate before authorizations decided "
                    "under it"
                )
            # A second, DIFFERENT receipt under the same ref and mandate
            # would brick every later agenda compile (the conductor requires
            # unique refs per mandate) — refuse the defective write at the
            # door instead. Idempotent re-saves never reach this branch.
            authorization_ref = str(payload.get("authorization_ref", ""))
            for row in records:
                if row.kind != "action_authorization":
                    continue
                stored = self._load_payload(row)
                if (
                    stored.get("authorization_ref") == authorization_ref
                    and stored.get("mandate_digest") == mandate_digest
                ):
                    raise GrowthWorkspaceValidationError(
                        "this mandate already holds a different receipt "
                        f"under authorization_ref {authorization_ref!r}; a "
                        "re-decision takes a new ref"
                    )
        if kind == "growth_mandate":
            supersedes = payload.get("supersedes")
            if supersedes is not None:
                stored_mandates = [
                    self._load_payload(row)
                    for row in records
                    if row.kind == "growth_mandate"
                ]
                if not any(
                    mandate.get("mandate_digest") == str(supersedes)
                    for mandate in stored_mandates
                ):
                    raise GrowthWorkspaceValidationError(
                        "a mandate may only supersede a mandate this "
                        "workspace actually holds; a fabricated audit chain "
                        "is not a thing that can honestly exist"
                    )
        if kind == "rail_receipt":
            package_digest = str(payload.get("plan_digest", ""))
            dispatches = [
                self._load_payload(row)
                for row in records
                if row.kind == "rail_dispatch"
            ]
            if not any(
                dispatch.get("package_digest") == package_digest
                for dispatch in dispatches
            ):
                raise GrowthWorkspaceValidationError(
                    "store the sealed rail dispatch package before its receipts"
                )

    # -- load -------------------------------------------------------------

    def _load_payload(self, record: WorkspaceRecord) -> dict[str, Any]:
        path = self._artifact_path(record.kind, record.storage_digest)
        if not path.exists() or path.is_symlink() or not path.is_file():
            raise GrowthWorkspacePersistenceError(
                f"workspace artifact missing or unsafe: {path.name}"
            )
        if path.stat().st_size > _MAX_ARTIFACT_BYTES:
            raise GrowthWorkspacePersistenceError(
                f"workspace artifact exceeds the size bound: {path.name}"
            )
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise GrowthWorkspacePersistenceError(
                f"workspace artifact is unreadable or corrupt: {path.name}"
            ) from exc
        if _stable_digest(payload) != record.storage_digest:
            raise GrowthWorkspacePersistenceError(
                "workspace artifact content does not match its storage "
                "digest; the file was modified"
            )
        return payload

    def _load_verified_payload(self, record: WorkspaceRecord) -> dict[str, Any]:
        """Content-check AND scope-verify one artifact; return its payload.

        Sealed kinds run their HMAC verification here, so any surface that
        reads artifact fields (the lifecycle queries included) upholds the
        "verified out" guarantee, not just content-addressing.
        """

        payload = self._load_payload(record)
        self._verify(_KIND_SPECS[record.kind], payload)
        return payload

    def load(self, kind: WorkspaceKind, storage_digest: str) -> BaseModel:
        """Load one artifact by identity; re-verifies before returning."""

        spec = _KIND_SPECS[kind]
        raw = self._read_index()
        for record in self._records(raw):
            if record.kind == kind and record.storage_digest == storage_digest:
                payload = self._load_payload(record)
                return self._verify(spec, payload)
        raise GrowthWorkspaceValidationError(
            f"no {kind} artifact with that storage digest is indexed"
        )

    def latest(self, kind: WorkspaceKind, ref: str) -> BaseModel | None:
        """Latest artifact of one kind for one ref (by saved_at, then digest)."""

        spec = _KIND_SPECS[kind]
        candidates = [
            record
            for record in self._records(self._read_index())
            if record.kind == kind and record.ref == ref
        ]
        if not candidates:
            return None
        candidates.sort(
            key=lambda row: (_parse_timestamp(row.saved_at), row.storage_digest)
        )
        payload = self._load_payload(candidates[-1])
        return self._verify(spec, payload)

    def list(
        self,
        *,
        kind: WorkspaceKind | None = None,
        ref: str | None = None,
    ) -> tuple[WorkspaceRecord, ...]:
        records = self._records(self._read_index())
        return tuple(
            record
            for record in sorted(
                records,
                key=lambda row: (row.kind, row.saved_at, row.storage_digest),
            )
            if (kind is None or record.kind == kind)
            and (ref is None or record.ref == ref)
        )

    # -- typed save wrappers ----------------------------------------------

    def save_funnel_snapshot(
        self, snapshot: GrowthFunnelSnapshot | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("funnel_snapshot", snapshot, saved_at=saved_at)

    def save_experiment_design(
        self,
        design: GrowthExperimentDesign | Mapping[str, Any],
        *,
        saved_at: str,
    ) -> WorkspaceRecord:
        return self._save("experiment_design", design, saved_at=saved_at)

    def save_arm_evidence(
        self,
        evidence: ExperimentArmEvidence | Mapping[str, Any],
        *,
        saved_at: str,
    ) -> WorkspaceRecord:
        return self._save("arm_evidence", evidence, saved_at=saved_at)

    def save_experiment_readout(
        self,
        readout: GrowthExperimentReadout | Mapping[str, Any],
        *,
        saved_at: str,
    ) -> WorkspaceRecord:
        return self._save("experiment_readout", readout, saved_at=saved_at)

    def save_content_calendar_plan(
        self, plan: ContentCalendarPlan | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("content_calendar_plan", plan, saved_at=saved_at)

    def save_audience_growth_plan(
        self, plan: AudienceGrowthPlan | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("audience_growth_plan", plan, saved_at=saved_at)

    def save_portfolio_rollup(
        self, rollup: PortfolioFunnelRollup | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("portfolio_rollup", rollup, saved_at=saved_at)

    def save_rail_dispatch(
        self, package: RailDispatchPackage | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("rail_dispatch", package, saved_at=saved_at)

    def save_rail_receipt(
        self, receipt: RailExecutionReceipt | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("rail_receipt", receipt, saved_at=saved_at)

    def save_unit_economics(
        self, snapshot: UnitEconomicsSnapshot | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("unit_economics", snapshot, saved_at=saved_at)

    def save_price_plan(
        self, plan: PricePlan | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("price_plan", plan, saved_at=saved_at)

    def save_profit_review(
        self, review: ProfitReview | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("profit_review", review, saved_at=saved_at)

    def save_price_elasticity(
        self,
        estimate: PriceElasticityEstimate | Mapping[str, Any],
        *,
        saved_at: str,
    ) -> WorkspaceRecord:
        return self._save("price_elasticity", estimate, saved_at=saved_at)

    def save_growth_agenda(
        self, agenda: GrowthAgenda | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("growth_agenda", agenda, saved_at=saved_at)

    def save_funnel_delta(
        self, delta: FunnelDelta | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("funnel_delta", delta, saved_at=saved_at)

    def save_customer_value(
        self,
        snapshot: CustomerValueSnapshot | Mapping[str, Any],
        *,
        saved_at: str,
    ) -> WorkspaceRecord:
        return self._save("customer_value", snapshot, saved_at=saved_at)

    def save_customer_value_review(
        self, review: CustomerValueReview | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("customer_value_review", review, saved_at=saved_at)

    def save_growth_objective(
        self, objective: GrowthObjective | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("growth_objective", objective, saved_at=saved_at)

    def save_objective_assessment(
        self,
        assessment: ObjectiveAssessment | Mapping[str, Any],
        *,
        saved_at: str,
    ) -> WorkspaceRecord:
        return self._save("objective_assessment", assessment, saved_at=saved_at)

    def save_growth_mandate(
        self, mandate: GrowthMandate | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("growth_mandate", mandate, saved_at=saved_at)

    def save_action_authorization(
        self,
        authorization: ActionAuthorization | Mapping[str, Any],
        *,
        saved_at: str,
    ) -> WorkspaceRecord:
        return self._save("action_authorization", authorization, saved_at=saved_at)

    def save_growth_diagnosis(
        self, diagnosis: GrowthDiagnosis | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("growth_diagnosis", diagnosis, saved_at=saved_at)

    def save_portfolio_diagnosis(
        self, diagnosis: PortfolioDiagnosis | Mapping[str, Any], *, saved_at: str
    ) -> WorkspaceRecord:
        return self._save("portfolio_diagnosis", diagnosis, saved_at=saved_at)

    # -- lifecycle --------------------------------------------------------

    def experiment_status(
        self,
        as_of: str,
        *,
        _records: list[WorkspaceRecord] | None = None,
    ) -> tuple[ExperimentStatusRecord, ...]:
        """Deterministic state of every stored experiment at ``as_of``.

        Designs and readouts are HMAC-verified before their fields are
        surfaced, so a forged verdict with no valid key cannot appear here.
        """

        as_of_at = _parse_timestamp(as_of)
        records = (
            _records if _records is not None else self._records(self._read_index())
        )
        readouts_by_design: dict[str, dict[str, Any]] = {}
        for record in records:
            if record.kind != "experiment_readout":
                continue
            payload = self._load_verified_payload(record)
            readouts_by_design[str(payload.get("design_digest", ""))] = payload
        statuses: list[ExperimentStatusRecord] = []
        for record in sorted(
            (row for row in records if row.kind == "experiment_design"),
            key=lambda row: (row.ref, row.storage_digest),
        ):
            design = self._load_verified_payload(record)
            design_digest = str(design.get("design_digest", ""))
            readout = readouts_by_design.get(design_digest)
            if readout is not None:
                state: ExperimentState = "read_out"
            elif as_of_at < _parse_timestamp(str(design["exposure_start"])):
                state = "designed"
            elif as_of_at < _parse_timestamp(str(design["readout_horizon"])):
                state = "running"
            else:
                state = "awaiting_readout"
            statuses.append(
                ExperimentStatusRecord(
                    design_ref=str(design["design_ref"]),
                    design_digest=design_digest,
                    state=state,
                    exposure_start=str(design["exposure_start"]),
                    readout_horizon=str(design["readout_horizon"]),
                    readout_digest=(
                        str(readout["readout_digest"]) if readout is not None else None
                    ),
                    verdict=(str(readout["verdict"]) if readout is not None else None),
                )
            )
        return tuple(statuses)

    def pending_readouts(self, as_of: str) -> tuple[ExperimentStatusRecord, ...]:
        """Experiments past their horizon that still lack a readout."""

        return tuple(
            status
            for status in self.experiment_status(as_of)
            if status.state == "awaiting_readout"
        )

    def status(self, as_of: str) -> WorkspaceStatus:
        """One cross-session answer to "where is this scope's growth work"."""

        raw = self._read_index()
        records = self._records(raw)
        counts: dict[str, int] = {}
        for record in records:
            counts[record.kind] = counts.get(record.kind, 0) + 1
        # Single index snapshot: counts, revision, and experiment states all
        # come from the same revision, so a concurrent write cannot make them
        # disagree.
        experiments = self.experiment_status(as_of, _records=records)
        return WorkspaceStatus(
            as_of=_normalized_timestamp(as_of),
            scope_project_ref=self._scope.project_ref,
            artifact_counts=counts,
            experiments=experiments,
            pending_readout_refs=tuple(
                status.design_ref
                for status in experiments
                if status.state == "awaiting_readout"
            ),
            index_revision=raw["revision"] if raw is not None else 0,
        )

    # -- operating loop ---------------------------------------------------

    def compile_agenda(
        self,
        as_of: str,
        *,
        policy: GrowthCadencePolicy | None = None,
    ) -> GrowthAgenda:
        """One call, one ordered answer: what does this scope need from me now.

        Gathers the workspace's artifacts through the verified-out path
        (sealed kinds are HMAC-verified before any field is consulted),
        reconciles every dispatched package that has receipts, queries the
        ledger as of ``as_of``, and hands everything to
        :func:`lightbulb.growth_operating.compile_growth_agenda`. The agenda
        is advice — persist it with :meth:`save_growth_agenda` if the
        session's reasoning should be auditable later.
        """

        return compile_growth_agenda(
            self._gather_agenda_inputs(as_of, policy=policy),
            inputs_verified_by_host=True,
        )

    def compile_briefing(
        self,
        as_of: str,
        *,
        budget_chars: int = 4_000,
        max_agenda_items: int = 10,
        policy: GrowthCadencePolicy | None = None,
    ) -> GrowthBriefing:
        """The cold-start call: one budgeted, digest-pinned rehydration.

        Gathers exactly what :meth:`compile_agenda` gathers — every sealed
        artifact HMAC-verified on the way out — and renders it through
        :func:`lightbulb.growth_briefing.compile_growth_briefing` with the
        host trust assertion. Sections that do not fit the budget are
        dropped whole and named in ``sections_omitted``.
        """

        return compile_growth_briefing(
            {
                "budget_chars": budget_chars,
                "max_agenda_items": max_agenda_items,
                "scope_label": self._scope.project_ref,
                "agenda": self._gather_agenda_inputs(as_of, policy=policy),
            },
            inputs_verified_by_host=True,
        )

    def _gather_agenda_inputs(
        self,
        as_of: str,
        *,
        policy: GrowthCadencePolicy | None = None,
    ) -> GrowthAgendaInput:
        records = self._records(self._read_index())

        def _rows(kind: str) -> list[WorkspaceRecord]:
            return sorted(
                (row for row in records if row.kind == kind),
                key=lambda row: (_parse_timestamp(row.saved_at), row.storage_digest),
            )

        def _artifacts(kind: str) -> list[BaseModel]:
            return [
                self._verify(_KIND_SPECS[kind], self._load_payload(row))
                for row in _rows(kind)
            ]

        def _latest(kind: str) -> BaseModel | None:
            rows = _rows(kind)
            if not rows:
                return None
            return self._verify(_KIND_SPECS[kind], self._load_payload(rows[-1]))

        def _latest_per_ref(kind: str) -> list[BaseModel]:
            newest: dict[str, WorkspaceRecord] = {}
            for row in _rows(kind):
                newest[row.ref] = row
            return [
                self._verify(_KIND_SPECS[kind], self._load_payload(row))
                for _, row in sorted(newest.items())
            ]

        designs = _artifacts("experiment_design")
        readouts = _artifacts("experiment_readout")
        dispatches = _artifacts("rail_dispatch")
        receipts = _artifacts("rail_receipt")
        calendar_plans = _latest_per_ref("content_calendar_plan")
        audience_plans = _latest_per_ref("audience_growth_plan")
        for kind, count, bound in (
            ("experiment_design", len(designs), 50),
            ("experiment_readout", len(readouts), 50),
            ("rail_dispatch", len(dispatches), 20),
            ("content_calendar_plan", len(calendar_plans), 10),
            ("audience_growth_plan", len(audience_plans), 10),
        ):
            if count > bound:
                raise GrowthWorkspaceValidationError(
                    f"the workspace holds {count} {kind} artifacts; the agenda "
                    f"consults at most {bound} — archive before compiling"
                )
        receipts_by_package: dict[str, list[RailExecutionReceipt]] = {}
        for receipt in receipts:
            receipts_by_package.setdefault(receipt.plan_digest, []).append(receipt)
        reconciliations = []
        reconciliation_errors: list[str] = []
        for package in dispatches:
            if package.package_digest not in receipts_by_package:
                continue
            try:
                reconciliations.append(
                    reconcile_dispatch_receipts(
                        package,
                        receipts_by_package[package.package_digest],
                        scope=self._scope,
                        scope_keyring=self._keyring,
                    )
                )
            except GrowthRailBridgeValidationError as exc:
                # A defective stored receipt must degrade to a visible note
                # and a standing dispatch_unreconciled duty, never brick the
                # agenda forever.
                reason = " ".join(str(exc).split())[:180]
                reconciliation_errors.append(
                    f"receipts for dispatch {package.dispatch_ref} fail "
                    f"reconciliation ({reason}); the package stays "
                    "unreconciled until corrected"[:300]
                )
        # "Was this readout ever banked" must consult the FULL chain —
        # superseded and expired entries included — or a retired learning
        # resurrects a false recording duty.
        recorded = sorted(
            {
                entry.readout_digest
                for entry in self.ledger().entries()
                if entry.readout_digest is not None
            }
        )
        if len(recorded) > 500:
            raise GrowthWorkspaceValidationError(
                f"the ledger cites {len(recorded)} readouts; the agenda "
                "consults at most 500 — archive before compiling"
            )
        # The latest assessment may belong to a SUPERSEDED objective (the
        # designed supersede flow makes this normal); only an assessment of
        # the current objective travels — otherwise the agenda correctly
        # demands a fresh one instead of the compile erroring forever.
        latest_objective = _latest("growth_objective")
        matching_assessment = None
        if latest_objective is not None:
            for row in reversed(_rows("objective_assessment")):
                candidate = self._verify(
                    _KIND_SPECS["objective_assessment"], self._load_payload(row)
                )
                if candidate.objective_digest == latest_objective.objective_digest:
                    matching_assessment = candidate
                    break
        # Only receipts decided under the CURRENT mandate travel: receipts
        # from superseded mandates are their own closed audit trail, and the
        # agenda's escalation view is per delegation contract.
        latest_mandate = _latest("growth_mandate")
        mandate_receipts: list[BaseModel] = []
        if latest_mandate is not None:
            mandate_receipts = [
                receipt
                for receipt in _artifacts("action_authorization")
                if receipt.mandate_digest == latest_mandate.mandate_digest
            ]
            if len(mandate_receipts) > 200:
                raise GrowthWorkspaceValidationError(
                    f"the workspace holds {len(mandate_receipts)} "
                    "authorizations for the current mandate; the agenda "
                    "consults at most 200 — archive before compiling"
                )
        return GrowthAgendaInput(
            as_of=_normalized_timestamp(as_of),
            policy=policy if policy is not None else GrowthCadencePolicy(),
            designs=tuple(designs),
            readouts=tuple(readouts),
            learnings=self.ledger().query(as_of=as_of, limit=100),
            funnel_snapshot=_latest("funnel_snapshot"),
            unit_economics=_latest("unit_economics"),
            customer_value=_latest("customer_value"),
            diagnosis=_latest("growth_diagnosis"),
            profit_review=_latest("profit_review"),
            customer_value_review=_latest("customer_value_review"),
            objective=latest_objective,
            objective_assessment=matching_assessment,
            mandate=latest_mandate,
            authorizations=tuple(mandate_receipts),
            calendar_plans=tuple(calendar_plans),
            audience_plans=tuple(audience_plans),
            dispatches=tuple(dispatches),
            reconciliations=tuple(reconciliations),
            recorded_readout_digests=tuple(recorded),
            reconciliation_errors=tuple(reconciliation_errors[:20]),
        )

    def authorize_action(
        self,
        action: ProposedAction | Mapping[str, Any],
        *,
        as_of: str,
        authorization_ref: str,
    ) -> ActionAuthorization:
        """Decide one proposed action under the current mandate; keep the receipt.

        The one-call gate for an operating agent: gathers the LATEST stored
        mandate, every stored receipt decided under it (the complete window
        arithmetic), the latest unit economics, and the current objective
        with its matching assessment — all through the verified-out path —
        then calls :func:`lightbulb.growth_mandate.authorize_growth_action`
        and saves the sealed receipt before returning it, whatever the
        verdict. No stored mandate is not an error state the agent can fix:
        the human grants one with ``grant_growth_mandate``.
        """

        proposed = (
            action
            if isinstance(action, ProposedAction)
            else ProposedAction.model_validate(action)
        )
        # Gather, decide, AND save under one index lock: a decision computed
        # against a stale prior-receipt set is a double-spend vector — two
        # concurrent callers would each see the other's spend missing and
        # both authorize. The lock makes read-decide-write atomic.
        with self._index_lock():
            records = self._records(self._read_index())

            def _rows(kind: str) -> list[WorkspaceRecord]:
                return sorted(
                    (row for row in records if row.kind == kind),
                    key=lambda row: (
                        _parse_timestamp(row.saved_at),
                        row.storage_digest,
                    ),
                )

            def _latest(kind: str) -> BaseModel | None:
                rows = _rows(kind)
                if not rows:
                    return None
                return self._verify(_KIND_SPECS[kind], self._load_payload(rows[-1]))

            mandate = _latest("growth_mandate")
            if mandate is None:
                raise GrowthWorkspaceValidationError(
                    "no mandate is stored in this workspace; bounded autonomy "
                    "starts with the human granting one (grant_growth_mandate)"
                )
            priors = [
                self._verify(
                    _KIND_SPECS["action_authorization"], self._load_payload(row)
                )
                for row in _rows("action_authorization")
            ]
            priors = [
                receipt
                for receipt in priors
                if receipt.mandate_digest == mandate.mandate_digest
            ]
            if len(priors) >= 500:
                raise GrowthWorkspaceValidationError(
                    f"the workspace holds {len(priors)} authorizations for the "
                    "current mandate; the gate consults at most 500 — archive "
                    "before authorizing more"
                )
            latest_objective = _latest("growth_objective")
            receipt = authorize_growth_action(
                {
                    "as_of": _normalized_timestamp(as_of),
                    "authorization_ref": authorization_ref,
                    "mandate": mandate.to_dict(),
                    "action": proposed.model_dump(
                        mode="json", by_alias=True, exclude_none=True
                    ),
                    "prior_authorizations": tuple(
                        prior.to_dict() for prior in priors
                    ),
                    **(
                        {"current_economics": economics.to_dict()}
                        if (economics := _latest("unit_economics")) is not None
                        else {}
                    ),
                    **(
                        {"objective": latest_objective.to_dict()}
                        if latest_objective is not None
                        else {}
                    ),
                },
                scope=self._scope,
                scope_keyring=self._keyring,
                scope_key_id=self._key_id,
            )
            self._save_under_lock(
                "action_authorization", receipt, saved_at=receipt.decided_at
            )
        return receipt

    # -- ledger -----------------------------------------------------------

    def ledger(self) -> GrowthLearningsLedger:
        """The scope's learnings ledger, persisted inside the workspace."""

        return GrowthLearningsLedger(
            JsonFileLedgerStore(self.directory / "ledger.json"),
            scope=self._scope,
            scope_keyring=self._keyring,
            scope_key_id=self._key_id,
        )


__all__ = [
    "GROWTH_WORKSPACE_INDEX_SCHEMA",
    "ExperimentStatusRecord",
    "GrowthWorkspace",
    "GrowthWorkspacePersistenceError",
    "GrowthWorkspaceValidationError",
    "WorkspaceRecord",
    "WorkspaceStatus",
]
