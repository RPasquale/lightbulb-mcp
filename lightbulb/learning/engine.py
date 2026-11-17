"""Durable local learning lifecycle with explicit schemas and conservative promotion.

Scope identifiers partition records; callers remain responsible for authentication.
One learner owns one SQLite connection. Use separate instances in separate threads.
"""

from dataclasses import dataclass, asdict
import hashlib
import json
import math
import sqlite3
import time
import numpy as np
from scipy.stats import beta
from . import models


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def finite(value):
    if (
        isinstance(value, bool)
        or not isinstance(value, (float, int))
        or not math.isfinite(value)
    ):
        raise ValueError("Expected a finite number")
    return float(value)


@dataclass(frozen=True)
class Feature:
    name: str
    kind: str = "number"
    description: str = ""

    def __post_init__(self):
        if not self.name.strip() or self.kind not in ("number", "category"):
            raise ValueError("Features require a name and number/category type")


@dataclass(frozen=True)
class LearningTask:
    name: str
    version: str
    kind: str
    features: tuple[Feature, ...]
    outcome: str
    fallback: float
    max_rows: int = 20000
    max_encoded_features: int = 128
    max_categories: int = 32
    min_units: int = 220
    alpha: float = 0.1
    prior: tuple[float, float] = (1.0, 1.0)
    auto_promote: bool = False
    drift_multiplier: float = 2.0
    drift_floor: float = 0.05
    monitor_units: int = 30

    def __post_init__(self):
        object.__setattr__(self, "features", tuple(self.features))
        object.__setattr__(self, "prior", tuple(self.prior))
        if (
            not self.name.strip()
            or not self.version.strip()
            or not self.outcome.strip()
        ):
            raise ValueError("Task name, version and outcome definition required")
        names = [f.name for f in self.features]
        if len(names) != len(set(names)) or self.outcome in names:
            raise ValueError("Feature names must be unique and exclude the outcome")
        finite(self.fallback)
        if self.kind in ("binary", "rate") and not 0 <= self.fallback <= 1:
            raise ValueError("Probability fallback must be in [0,1]")
        if self.kind == "rate" and self.features:
            raise ValueError(
                "Rate tasks describe an unconditional rate and have no features"
            )
        if self.kind in ("regression", "binary") and not self.features:
            raise ValueError("Predictive tasks need features")
        if (
            not 0 < self.alpha < 1
            or len(self.prior) != 2
            or any(finite(x) <= 0 for x in self.prior)
        ):
            raise ValueError("Invalid coverage or prior")
        if any(
            type(x) is not int or x < 1
            for x in (
                self.max_rows,
                self.max_encoded_features,
                self.max_categories,
                self.min_units,
                self.monitor_units,
            )
        ):
            raise ValueError("Resource and sample limits must be positive integers")
        if finite(self.drift_multiplier) <= 1 or finite(self.drift_floor) < 0:
            raise ValueError("Invalid monitoring thresholds")


class WorkflowLearner:
    def __init__(self, path, *, tenant, company, workflow, task: LearningTask):
        if not all(
            isinstance(v, str) and v.strip() for v in (tenant, company, workflow)
        ):
            raise ValueError("Explicit tenant, company and workflow required")
        self.task = task
        self.identity = dict(tenant=tenant, company=company, workflow=workflow)
        self.key = fingerprint(
            {**self.identity, "task": task.name, "version": task.version}
        )
        self.contract = fingerprint(asdict(task))
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute("pragma foreign_keys=on")
        self.db.execute("pragma journal_mode=WAL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS wl_tasks(scope TEXT PRIMARY KEY,contract TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS wl_observations(scope TEXT,id TEXT,unit TEXT,at REAL,payload TEXT,PRIMARY KEY(scope,id));
        CREATE TABLE IF NOT EXISTS wl_outcomes(scope TEXT,id TEXT,at REAL,value REAL,source TEXT,PRIMARY KEY(scope,id),
          FOREIGN KEY(scope,id) REFERENCES wl_observations(scope,id));
        CREATE TABLE IF NOT EXISTS wl_candidates(scope TEXT,version TEXT,payload TEXT,digest TEXT,PRIMARY KEY(scope,version));
        CREATE TABLE IF NOT EXISTS wl_state(scope TEXT PRIMARY KEY,active TEXT,used_until REAL NOT NULL DEFAULT -1,monitor_until REAL NOT NULL DEFAULT -1);
        CREATE TABLE IF NOT EXISTS wl_audit(sequence INTEGER PRIMARY KEY,scope TEXT,at REAL,event TEXT,payload TEXT);
        CREATE TABLE IF NOT EXISTS wl_retired(scope TEXT,version TEXT,reason TEXT,PRIMARY KEY(scope,version));
        CREATE INDEX IF NOT EXISTS wl_observation_time ON wl_observations(scope,at);
        """)
        with self.db:
            self.db.execute(
                "insert or ignore into wl_tasks values(?,?)", (self.key, self.contract)
            )
            self.db.execute(
                "insert or ignore into wl_state(scope) values(?)", (self.key,)
            )
        if (
            self.db.execute(
                "select contract from wl_tasks where scope=?", (self.key,)
            ).fetchone()[0]
            != self.contract
        ):
            self.db.close()
            raise ValueError("Task contract changed; use a new task version")

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _audit(self, event, payload):
        self.db.execute(
            "insert into wl_audit(scope,at,event,payload) values(?,?,?,?)",
            (self.key, time.time(), event, encode(payload)),
        )

    def _features(self, values):
        if set(values) != {f.name for f in self.task.features}:
            raise ValueError("Input must match the exact named feature contract")
        result = {}
        for f in self.task.features:
            value = values[f.name]
            if value is not None:
                if f.kind == "number":
                    value = finite(value)
                elif not isinstance(value, str) or len(value) > 256:
                    raise ValueError(
                        "Categories must be strings of at most 256 characters"
                    )
            result[f.name] = value
        return result

    def predict(self, features):
        features = self._features(features)
        if self.task.kind == "rate":
            r = self.rate()
            return dict(
                value=r["mean"],
                version=None,
                status=r["status"],
                interval=r["credible_interval"],
                interval_type="credible",
                nominal_coverage=1 - self.task.alpha,
                contract=self.contract,
                evidence=r,
            )
        version = self.db.execute(
            "select active from wl_state where scope=?", (self.key,)
        ).fetchone()[0]
        if version is None:
            return dict(
                value=self.task.fallback,
                version=None,
                status="fallback",
                interval=None,
                reason="No active evaluated model",
                contract=self.contract,
            )
        artifact = self.candidate(version)
        x = models.transform([features], artifact["preprocessing"])
        value = float(models.predict(artifact["model"], x)[0])
        radius = artifact.get("radius")
        return dict(
            value=value,
            version=version,
            status="learned",
            contract=self.contract,
            interval=None if radius is None else [value - radius, value + radius],
            interval_type=None if radius is None else "prediction",
            nominal_coverage=None if radius is None else 1 - self.task.alpha,
            uncertainty_assumption="Marginal split-conformal coverage requires exchangeable independent units",
        )

    def observe(self, id, *, unit, features, at, action=None, llm=None):
        """Snapshot decision-time inputs. Retry returns the original prediction.

        at is a caller-supplied epoch timestamp; source truth must be enforced upstream.
        llm is optional provenance and never a model dependency.
        """
        if not isinstance(id, str) or not id or not isinstance(unit, str) or not unit:
            raise ValueError("Identified run/decision and independent unit required")
        features = self._features(features)
        base = dict(features=features, unit=unit, at=finite(at), action=action, llm=llm)
        encode(base)
        with self.db:
            self.db.execute("begin immediate")
            old = self.db.execute(
                "select payload from wl_observations where scope=? and id=?",
                (self.key, id),
            ).fetchone()
            if old:
                saved = json.loads(old[0])
                if saved["input"] != base:
                    raise ValueError("Conflicting retry of immutable observation")
                return saved["prediction"]
            prediction = self.predict(features)
            self.db.execute(
                "insert into wl_observations values(?,?,?,?,?)",
                (
                    self.key,
                    id,
                    unit,
                    at,
                    encode(dict(input=base, prediction=prediction)),
                ),
            )
            return prediction

    def resolve(self, id, value, *, at, source):
        value, at = finite(value), finite(at)
        if self.task.kind in ("binary", "rate") and value not in (0.0, 1.0):
            raise ValueError("Binary outcomes must be zero or one")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("Outcome evidence source required")
        with self.db:
            self.db.execute("begin immediate")
            observation = self.db.execute(
                "select at from wl_observations where scope=? and id=?", (self.key, id)
            ).fetchone()
            if not observation or at < observation[0]:
                raise ValueError(
                    "Outcome must follow a recorded decision in this scope"
                )
            old = self.db.execute(
                "select value,at,source from wl_outcomes where scope=? and id=?",
                (self.key, id),
            ).fetchone()
            if old:
                if old != (value, at, source):
                    raise ValueError("Conflicting retry of immutable outcome")
                return False
            self.db.execute(
                "insert into wl_outcomes values(?,?,?,?,?)",
                (self.key, id, at, value, source),
            )
            return True

    def _rows(self):
        # Read no more than the declared budget. Do not load the whole event table first.
        records = self.db.execute(
            """select o.id,o.payload,y.at,y.value,y.rowid from wl_observations o
            join wl_outcomes y on o.scope=y.scope and o.id=y.id where o.scope=?
            order by o.at desc,o.id desc limit ?""",
            (self.key, self.task.max_rows),
        ).fetchall()
        rows = []
        for id, payload, resolved, y, sequence in reversed(records):
            p = json.loads(payload)
            rows.append(
                dict(
                    id=id,
                    **p["input"],
                    resolved=resolved,
                    y=y,
                    prediction=p["prediction"],
                    outcome_sequence=sequence,
                )
            )
        return rows

    def plan(self):
        rows = self._rows()
        n = len({r["unit"] for r in rows})
        report = dict(
            task=self.task.name,
            kind=self.task.kind,
            rows=len(rows),
            units=n,
            max_rows=self.task.max_rows,
            status="ready",
            candidates=[],
        )
        if self.task.kind not in ("regression", "binary", "rate"):
            return {
                **report,
                "status": "unsupported",
                "reason": "Use a supported task or an external estimator integration",
            }
        if self.task.kind == "rate":
            return {
                **report,
                "status": "ready" if n else "collecting",
                "candidates": ["beta_binomial"],
                "reason": "One latest resolved outcome per independent unit; prior remains explicit",
            }
        if n < self.task.min_units:
            return {
                **report,
                "status": "collecting",
                "reason": "Insufficient independent units for train/select/calibrate/test",
            }
        if self.task.kind == "binary":
            minority = min(
                len({r["unit"] for r in rows if r["y"] == v}) for v in [0, 1]
            )
            if minority < 20:
                return {
                    **report,
                    "status": "collecting",
                    "reason": "Too few independent minority-class units",
                }
        report["candidates"] = (
            ["ridge:1", "ridge:10", "elastic_net", "forest"]
            if self.task.kind == "regression"
            else ["logistic:0.1", "logistic:1", "forest"]
        )
        return report

    def rate(self):
        if self.task.kind != "rate":
            raise ValueError("Use a rate task")
        by_unit = {r["unit"]: r for r in self._rows()}
        successes = sum(r["y"] for r in by_unit.values())
        n = len(by_unit)
        a, b = self.task.prior
        posterior = beta(a + successes, b + n - successes)
        return dict(
            status="prior_only" if n == 0 else "posterior",
            units=n,
            successes=successes,
            prior=[a, b],
            posterior=[a + successes, b + n - successes],
            mean=float(posterior.mean()),
            credible_interval=posterior.ppf(
                [self.task.alpha / 2, 1 - self.task.alpha / 2]
            ).tolist(),
            assumptions="Independent comparable Bernoulli units; explicit prior; latest outcome per unit",
        )

    def _split(self, rows):
        first = {}
        for r in rows:
            first.setdefault(r["unit"], r["at"])
        units = sorted(first, key=lambda u: (first[u], u))
        n = len(units)
        groups = [
            units[: int(n * 0.5)],
            units[int(n * 0.5) : int(n * 0.7)],
            units[int(n * 0.7) : int(n * 0.85)],
            units[int(n * 0.85) :],
        ]
        parts = []
        for i, g in enumerate(groups):
            selected = set(g)
            end = (
                min((first[u] for u in groups[i + 1]), default=math.inf)
                if i < 3
                else math.inf
            )
            parts.append(
                [r for r in rows if r["unit"] in selected and r["resolved"] < end]
            )
        if any(len({r["unit"] for r in p}) < 30 for p in parts):
            raise ValueError("insufficient_resolved_units_after_temporal_purge")
        return parts

    def learn(self):
        plan = self.plan()
        if plan["status"] != "ready":
            return plan
        if self.task.kind == "rate":
            return self.rate()
        rows = self._rows()
        previous, used_until = self.db.execute(
            "select active,used_until from wl_state where scope=?", (self.key,)
        ).fetchone()
        try:
            train, validation, calibration, test = self._split(rows)
            if min(r["at"] for r in test) <= used_until:
                return {
                    **plan,
                    "status": "collecting",
                    "reason": "Fresh holdout required; prior test window cannot select another candidate",
                }
            prep = models.preprocessing(
                train, self.task.features, self.task.max_categories
            )
            columns = sum(
                2 if p["kind"] == "number" else len(p["levels"]) + 2 for p in prep
            )
            if columns > self.task.max_encoded_features:
                raise ValueError("encoded_feature_budget_exceeded")
            x = models.transform([r["features"] for r in train], prep)
            y = np.array([r["y"] for r in train])
            if x.shape[1] > self.task.max_encoded_features:
                raise ValueError("encoded_feature_budget_exceeded")
            if self.task.kind == "binary" and len(set(y)) < 2:
                raise ValueError("training_window_has_one_class")
            baseline = dict(
                type="constant",
                value=float(y.mean() if self.task.kind == "binary" else np.median(y)),
            )
            vx = models.transform([r["features"] for r in validation], prep)
            vy = [r["y"] for r in validation]
            candidates = [("baseline", baseline)]
            failures = {}
            for name in plan["candidates"]:
                try:
                    candidates.append((name, models.fit(name, x, y, self.task.kind)))
                except (
                    ValueError,
                    np.linalg.LinAlgError,
                    RuntimeError,
                    Warning,
                ) as exc:
                    failures[name] = str(exc)
            scores = [
                float(models.loss(self.task.kind, vy, models.predict(m, vx)).mean())
                for _, m in candidates
            ]
            index = int(np.argmin(scores))
            name, model = candidates[index]
            tx = models.transform([r["features"] for r in test], prep)
            ty = np.array([r["y"] for r in test])
            predictions = models.predict(model, tx)
            candidate_loss = models.loss(self.task.kind, ty, predictions)
            base_loss = models.loss(self.task.kind, ty, models.predict(baseline, tx))
            evaluation = models.comparison(test, base_loss, candidate_loss)
            comparisons = {"baseline": evaluation}
            if previous:
                incumbent = self.candidate(previous)
                ip = models.predict(
                    incumbent["model"],
                    models.transform(
                        [r["features"] for r in test], incumbent["preprocessing"]
                    ),
                )
                comparisons["incumbent"] = models.comparison(
                    test, models.loss(self.task.kind, ty, ip), candidate_loss
                )
            radius = None
            if self.task.kind == "regression":
                # One calibration residual per independent unit avoids treating repeated cases as independent.
                unique = list({r["unit"]: r for r in calibration}.values())
                cp = models.predict(
                    model, models.transform([r["features"] for r in unique], prep)
                )
                radius = models.conformal(
                    np.abs(np.array([r["y"] for r in unique]) - cp), self.task.alpha
                )
            artifact = dict(
                schema=1,
                contract=self.contract,
                selected=name,
                preprocessing=prep,
                model=model,
                radius=radius,
                comparison=comparisons,
                passed=name != "baseline"
                and all(v["passes"] for v in comparisons.values()),
                validation_scores=dict(zip([n for n, _ in candidates], scores)),
                failures=failures,
                metric="Brier" if self.task.kind == "binary" else "MAE",
                holdout_loss=float(candidate_loss.mean()),
                baseline_loss=float(base_loss.mean()),
                dataset=fingerprint(rows),
                previous=previous,
                splits={
                    k: [r["id"] for r in p]
                    for k, p in zip(
                        ["train", "validation", "calibration", "test"],
                        [train, validation, calibration, test],
                    )
                },
                holdout_end=max(r["at"] for r in test),
                latest_outcome=max(r["outcome_sequence"] for r in rows),
                limits=[
                    "Temporal separation is not proof of exchangeability or causal improvement",
                    "Bootstrap intervals are descriptive; repeated automatic searches are not a sequential significance guarantee",
                ],
            )
        except (ValueError, np.linalg.LinAlgError) as exc:
            with self.db:
                self._audit("learning_deferred", {"reason": str(exc)})
            return {**plan, "status": "deferred", "reason": str(exc)}
        version = fingerprint(artifact)
        with self.db:
            self.db.execute("begin immediate")
            state = self.db.execute(
                "select active,used_until from wl_state where scope=?", (self.key,)
            ).fetchone()
            if state != (previous, used_until):
                return {
                    **plan,
                    "status": "deferred",
                    "reason": "Concurrent lifecycle change; retry",
                }
            self.db.execute(
                "insert or ignore into wl_candidates values(?,?,?,?)",
                (self.key, version, encode(artifact), version),
            )
            self.db.execute(
                "update wl_state set used_until=? where scope=?",
                (artifact["holdout_end"], self.key),
            )
            self._audit(
                "candidate_evaluated",
                {"version": version, "selected": name, "passed": artifact["passed"]},
            )
        promoted = (
            self.promote(version, approved=True)
            if self.task.auto_promote and artifact["passed"]
            else False
        )
        return dict(
            status="promoted" if promoted else "evaluated", version=version, **artifact
        )

    def candidate(self, version):
        row = self.db.execute(
            "select payload,digest from wl_candidates where scope=? and version=?",
            (self.key, version),
        ).fetchone()
        if not row:
            raise ValueError("Candidate not found in this task scope")
        artifact = json.loads(row[0])
        if (
            fingerprint(artifact) != row[1]
            or row[1] != version
            or artifact["contract"] != self.contract
        ):
            raise ValueError("Candidate integrity/contract failure")
        return artifact

    def promote(self, version, *, approved=False):
        with self.db:
            self.db.execute("begin immediate")
            a = self.candidate(version)
            if self.db.execute(
                "select 1 from wl_retired where scope=? and version=?",
                (self.key, version),
            ).fetchone():
                raise ValueError("Suspended model requires a newly evaluated candidate")
            current, used = self.db.execute(
                "select active,used_until from wl_state where scope=?", (self.key,)
            ).fetchone()
            if not approved or not a["passed"]:
                return False
            if current == version:
                return True
            if current != a["previous"] or used != a["holdout_end"]:
                raise ValueError("Stale candidate; reevaluate against current state")
            self.db.execute(
                "update wl_state set active=?,monitor_until=? where scope=?",
                (version, a["latest_outcome"], self.key),
            )
            self._audit(
                "promoted",
                {
                    "version": version,
                    "approval": "configured automatic"
                    if self.task.auto_promote
                    else "explicit",
                },
            )
            return True

    def suspend(self, reason):
        if not reason:
            raise ValueError("Reason required")
        with self.db:
            self.db.execute("begin immediate")
            version = self.db.execute(
                "select active from wl_state where scope=?", (self.key,)
            ).fetchone()[0]
            if version:
                self.db.execute(
                    "insert or ignore into wl_retired values(?,?,?)",
                    (self.key, version, reason),
                )
            self.db.execute(
                "update wl_state set active=NULL where scope=?", (self.key,)
            )
            self._audit("suspended", {"reason": reason})

    def monitor(self):
        version, watermark = self.db.execute(
            "select active,monitor_until from wl_state where scope=?", (self.key,)
        ).fetchone()
        if not version:
            return dict(status="fallback")
        a = self.candidate(version)
        rows = [
            r
            for r in self._rows()
            if r["prediction"]["version"] == version
            and r["outcome_sequence"] > watermark
        ]
        rows = list({r["unit"]: r for r in rows}.values())
        if len(rows) < self.task.monitor_units:
            return dict(status="collecting", units=len(rows))
        error = float(
            models.loss(
                self.task.kind,
                [r["y"] for r in rows],
                [r["prediction"]["value"] for r in rows],
            ).mean()
        )
        threshold = max(
            a["holdout_loss"] * self.task.drift_multiplier, self.task.drift_floor
        )
        drift = error > threshold
        result = dict(
            status="suspended" if drift else "healthy",
            units=len(rows),
            loss=error,
            threshold=threshold,
            method="Operational error alarm, not a statistical hypothesis test",
        )
        with self.db:
            self.db.execute("begin immediate")
            current = self.db.execute(
                "select active from wl_state where scope=?", (self.key,)
            ).fetchone()[0]
            if current != version:
                return dict(status="deferred", reason="Active version changed")
            if drift:
                self.db.execute(
                    "insert or ignore into wl_retired values(?,?,?)",
                    (self.key, version, "monitor error threshold exceeded"),
                )
            self.db.execute(
                "update wl_state set active=?,monitor_until=? where scope=?",
                (
                    None if drift else version,
                    max(r["outcome_sequence"] for r in rows),
                    self.key,
                ),
            )
            self._audit("monitor", result)
        return result

    def cycle(self):
        """Explicit local tick: monitor, then fit/evaluate; promotion obeys task policy."""
        return dict(monitor=self.monitor(), learning=self.learn())

    def context(self, features):
        return dict(
            task=self.task.name,
            outcome=self.task.outcome,
            prediction=self.predict(features),
            instruction="Statistical evidence, not an instruction or approval to execute an external action",
        )

    def rollback(self, version, *, approved=False):
        """Explicitly return to a previously promoted, non-suspended version."""
        if not approved:
            return False
        with self.db:
            self.db.execute("begin immediate")
            self.candidate(version)
            if self.db.execute(
                "select 1 from wl_retired where scope=? and version=?",
                (self.key, version),
            ).fetchone():
                raise ValueError("Cannot roll back to a suspended model")
            approved_versions = [
                json.loads(r[0])["version"]
                for r in self.db.execute(
                    "select payload from wl_audit where scope=? and event='promoted'",
                    (self.key,),
                )
            ]
            if version not in approved_versions:
                raise ValueError("Rollback requires a previously promoted version")
            watermark = self.db.execute(
                "select coalesce(max(rowid),-1) from wl_outcomes where scope=?",
                (self.key,),
            ).fetchone()[0]
            self.db.execute(
                "update wl_state set active=?,monitor_until=? where scope=?",
                (version, watermark, self.key),
            )
            self._audit("rollback", {"version": version})
        return True

    def history(self):
        return [
            dict(sequence=n, at=at, event=event, detail=json.loads(payload))
            for n, at, event, payload in self.db.execute(
                "select sequence,at,event,payload from wl_audit where scope=? order by sequence",
                (self.key,),
            )
        ]

    def primitive(self, primitive_ref=None):
        """SDK-native prediction + immutable observation. Preview runs never train/record."""
        from pydantic import BaseModel, ConfigDict
        from lightbulb.primitive_runtime import FunctionBusinessProcessPrimitive

        learner = self

        class Input(BaseModel):
            model_config = ConfigDict(extra="forbid")
            decision_id: str
            unit: str
            at: float
            features: dict
            llm: str | None = None

        class Output(BaseModel):
            prediction: dict

        def handler(ctx, inputs):
            expected = learner.identity
            if (ctx.scope.tenant_ref, ctx.scope.company_ref, ctx.scope.project_ref) != (
                expected["tenant"],
                expected["company"],
                expected["workflow"],
            ):
                raise ValueError("Runtime scope differs from learning task scope")
            result = (
                learner.predict(inputs.features)
                if ctx.preview_only
                else learner.observe(
                    inputs.decision_id,
                    unit=inputs.unit,
                    features=inputs.features,
                    at=inputs.at,
                    llm=inputs.llm,
                    action={
                        "primitive": primitive_ref or "learning.predict",
                        "step": ctx.step_id,
                    },
                )
            )
            return Output(prediction=result)

        return FunctionBusinessProcessPrimitive(
            primitive_ref=primitive_ref or "learning.predict",
            title="Learned workflow prediction",
            input_model=Input,
            output_model=Output,
            handler=handler,
        )
