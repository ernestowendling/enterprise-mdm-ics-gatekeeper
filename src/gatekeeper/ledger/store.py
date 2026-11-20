"""Embedded DuckDB control store.

Holds staging feeds, rule executions, findings, attribute-level lineage edges, maker/checker
events and an append-only, SHA-256 hash-chained audit log. DuckDB offers neither triggers nor
row-level grants, so immutability is enforced by an append-only API and made tamper-evident by
the hash chain (see docs/ADR-002-duckdb-immutable-audit-trail.md).
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any

import duckdb

from gatekeeper.models import (
    AuditEvent,
    ChainVerification,
    Finding,
    FindingScope,
    GateDecision,
    LineageEdge,
    LineageEdgeType,
    PackId,
    RuleExecution,
    RunRecord,
    Severity,
    WorkflowAction,
    WorkflowEvent,
    WorkflowState,
)

GENESIS_HASH = "0" * 64

_CORE_SCHEMA: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS runs (
        run_id          VARCHAR PRIMARY KEY,
        pack_id         VARCHAR NOT NULL,
        maker_id        VARCHAR NOT NULL,
        source_name     VARCHAR NOT NULL,
        input_sha256    VARCHAR NOT NULL,
        config_sha256   VARCHAR NOT NULL,
        record_count    INTEGER NOT NULL,
        rejected_count  INTEGER NOT NULL,
        blocker_count   INTEGER NOT NULL,
        warning_count   INTEGER NOT NULL,
        gate_decision   VARCHAR NOT NULL,
        engine_version  VARCHAR NOT NULL,
        created_at      VARCHAR NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS rule_executions (
        run_id             VARCHAR NOT NULL,
        rule_id            VARCHAR NOT NULL,
        title              VARCHAR NOT NULL,
        records_evaluated  INTEGER NOT NULL,
        blocker_count      INTEGER NOT NULL,
        warning_count      INTEGER NOT NULL,
        outcome            VARCHAR NOT NULL,
        PRIMARY KEY (run_id, rule_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS rule_results (
        run_id        VARCHAR NOT NULL,
        finding_id    VARCHAR NOT NULL,
        rule_id       VARCHAR NOT NULL,
        check_code    VARCHAR NOT NULL,
        severity      VARCHAR NOT NULL,
        scope         VARCHAR NOT NULL,
        record_key    VARCHAR NOT NULL,
        message       VARCHAR NOT NULL,
        attributes    VARCHAR NOT NULL,
        details_json  VARCHAR NOT NULL,
        PRIMARY KEY (run_id, finding_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS lineage_edges (
        run_id                 VARCHAR NOT NULL,
        from_node              VARCHAR NOT NULL,
        to_node                VARCHAR NOT NULL,
        edge_type              VARCHAR NOT NULL,
        rule_id                VARCHAR,
        critical_data_element  BOOLEAN NOT NULL,
        PRIMARY KEY (run_id, from_node, to_node, edge_type)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS workflow_events (
        run_id            VARCHAR NOT NULL,
        seq               INTEGER NOT NULL,
        from_state        VARCHAR,
        to_state          VARCHAR NOT NULL,
        action            VARCHAR NOT NULL,
        actor_id          VARCHAR NOT NULL,
        justification     VARCHAR,
        created_at        VARCHAR NOT NULL,
        audit_event_hash  VARCHAR NOT NULL,
        PRIMARY KEY (run_id, seq)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        seq           BIGINT PRIMARY KEY,
        event_id      VARCHAR NOT NULL,
        run_id        VARCHAR,
        event_type    VARCHAR NOT NULL,
        actor_id      VARCHAR NOT NULL,
        payload_json  VARCHAR NOT NULL,
        created_at    VARCHAR NOT NULL,
        prev_hash     VARCHAR NOT NULL,
        event_hash    VARCHAR NOT NULL
    )
    """,
)


def _json_default(value: object) -> object:
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, set | frozenset):
        return sorted(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serialisable")


def canonical_json(value: object) -> str:
    """Deterministic JSON encoding used for every hash in the platform."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def compute_event_hash(
    *,
    seq: int,
    event_id: str,
    run_id: str | None,
    event_type: str,
    actor_id: str,
    payload_json: str,
    created_at: str,
    prev_hash: str,
) -> str:
    """Hash of an audit event, binding it to its predecessor via ``prev_hash``."""
    return sha256_hex(
        canonical_json(
            {
                "seq": seq,
                "event_id": event_id,
                "run_id": run_id,
                "event_type": event_type,
                "actor_id": actor_id,
                "payload_json": payload_json,
                "created_at": created_at,
                "prev_hash": prev_hash,
            }
        )
    )


class RunNotFoundError(LookupError):
    """Raised when a run identifier is unknown to the control store."""


class ControlStore:
    """Thread-safe facade over a single DuckDB connection.

    The public API is append-only: there is no method that updates or deletes control
    evidence. Direct SQL access via :attr:`connection` exists for diagnostics and for the
    tamper-detection tests.
    """

    def __init__(self, database: str = ":memory:") -> None:
        self._database = database
        self._con = duckdb.connect(database)
        self._lock = threading.RLock()
        self._tx_depth = 0
        for ddl in _CORE_SCHEMA:
            self.execute(ddl)

    # -- low level ---------------------------------------------------------------------

    @property
    def connection(self) -> Any:
        return self._con

    @contextmanager
    def atomic(self) -> Iterator[None]:
        """Serialise writers and wrap the block in a single DuckDB transaction."""
        with self._lock:
            if self._tx_depth:
                self._tx_depth += 1
                try:
                    yield
                finally:
                    self._tx_depth -= 1
                return
            self._con.execute("BEGIN TRANSACTION")
            self._tx_depth = 1
            try:
                yield
            except BaseException:
                self._tx_depth = 0
                self._con.execute("ROLLBACK")
                raise
            self._tx_depth = 0
            self._con.execute("COMMIT")

    def execute(self, sql: str, params: Sequence[object] | None = None) -> None:
        with self._lock:
            if params is None:
                self._con.execute(sql)
            else:
                self._con.execute(sql, list(params))

    def executemany(self, sql: str, rows: Iterable[Sequence[object]]) -> None:
        batch = [list(row) for row in rows]
        if not batch:
            return
        with self._lock:
            self._con.executemany(sql, batch)

    def query(self, sql: str, params: Sequence[object] | None = None) -> list[tuple[Any, ...]]:
        with self._lock:
            cursor = (
                self._con.execute(sql) if params is None else self._con.execute(sql, list(params))
            )
            return [tuple(row) for row in cursor.fetchall()]

    def close(self) -> None:
        with self._lock:
            self._con.close()

    # -- runs, executions and findings ----------------------------------------------------

    def insert_run(self, run: RunRecord) -> None:
        self.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                run.run_id,
                run.pack_id.value,
                run.maker_id,
                run.source_name,
                run.input_sha256,
                run.config_sha256,
                run.record_count,
                run.rejected_count,
                run.blocker_count,
                run.warning_count,
                run.gate_decision.value,
                run.engine_version,
                run.created_at,
            ],
        )

    def fetch_run(self, run_id: str) -> RunRecord:
        rows = self.query(
            "SELECT run_id, pack_id, maker_id, source_name, input_sha256, config_sha256, "
            "record_count, rejected_count, blocker_count, warning_count, gate_decision, "
            "engine_version, created_at FROM runs WHERE run_id = ?",
            [run_id],
        )
        if not rows:
            raise RunNotFoundError(run_id)
        return self._run_from_row(rows[0])

    def list_runs(self, pack_id: PackId | None = None) -> list[RunRecord]:
        sql = (
            "SELECT run_id, pack_id, maker_id, source_name, input_sha256, config_sha256, "
            "record_count, rejected_count, blocker_count, warning_count, gate_decision, "
            "engine_version, created_at FROM runs"
        )
        params: list[object] = []
        if pack_id is not None:
            sql += " WHERE pack_id = ?"
            params.append(pack_id.value)
        sql += " ORDER BY created_at, run_id"
        return [self._run_from_row(row) for row in self.query(sql, params)]

    @staticmethod
    def _run_from_row(row: tuple[Any, ...]) -> RunRecord:
        return RunRecord(
            run_id=str(row[0]),
            pack_id=PackId(str(row[1])),
            maker_id=str(row[2]),
            source_name=str(row[3]),
            input_sha256=str(row[4]),
            config_sha256=str(row[5]),
            record_count=int(row[6]),
            rejected_count=int(row[7]),
            blocker_count=int(row[8]),
            warning_count=int(row[9]),
            gate_decision=GateDecision(str(row[10])),
            engine_version=str(row[11]),
            created_at=str(row[12]),
        )

    def insert_rule_executions(self, executions: Sequence[RuleExecution]) -> None:
        self.executemany(
            "INSERT INTO rule_executions VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    e.run_id,
                    e.rule_id,
                    e.title,
                    e.records_evaluated,
                    e.blocker_count,
                    e.warning_count,
                    e.outcome.value,
                )
                for e in executions
            ],
        )

    def fetch_rule_executions(self, run_id: str) -> list[RuleExecution]:
        rows = self.query(
            "SELECT run_id, rule_id, title, records_evaluated, blocker_count, warning_count, "
            "outcome FROM rule_executions WHERE run_id = ? ORDER BY rule_id",
            [run_id],
        )
        return [
            RuleExecution(
                run_id=str(r[0]),
                rule_id=str(r[1]),
                title=str(r[2]),
                records_evaluated=int(r[3]),
                blocker_count=int(r[4]),
                warning_count=int(r[5]),
                outcome=Severity(str(r[6])),
            )
            for r in rows
        ]

    def insert_findings(self, findings: Sequence[Finding]) -> None:
        self.executemany(
            "INSERT INTO rule_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    f.run_id,
                    f.finding_id,
                    f.rule_id,
                    f.check_code,
                    f.severity.value,
                    f.scope.value,
                    f.record_key,
                    f.message,
                    "|".join(f.attributes),
                    canonical_json(f.details),
                )
                for f in findings
            ],
        )

    def fetch_findings(self, run_id: str) -> list[Finding]:
        rows = self.query(
            "SELECT r.run_id, r.finding_id, r.rule_id, r.check_code, r.severity, r.scope, "
            "r.record_key, r.message, r.attributes, r.details_json, u.pack_id "
            "FROM rule_results r JOIN runs u ON u.run_id = r.run_id "
            "WHERE r.run_id = ? "
            "ORDER BY CASE r.severity WHEN 'BLOCKER' THEN 0 ELSE 1 END, r.rule_id, r.record_key",
            [run_id],
        )
        return [
            Finding(
                run_id=str(r[0]),
                finding_id=str(r[1]),
                rule_id=str(r[2]),
                check_code=str(r[3]),
                severity=Severity(str(r[4])),
                scope=FindingScope(str(r[5])),
                record_key=str(r[6]),
                message=str(r[7]),
                attributes=tuple(a for a in str(r[8]).split("|") if a),
                details=json.loads(str(r[9])),
                pack_id=PackId(str(r[10])),
            )
            for r in rows
        ]

    # -- lineage -------------------------------------------------------------------------

    def insert_lineage_edges(self, edges: Sequence[LineageEdge]) -> None:
        unique: dict[tuple[str, str, str, str], LineageEdge] = {}
        for edge in edges:
            unique.setdefault((edge.run_id, edge.from_node, edge.to_node, edge.edge_type), edge)
        self.executemany(
            "INSERT INTO lineage_edges VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    e.run_id,
                    e.from_node,
                    e.to_node,
                    e.edge_type.value,
                    e.rule_id,
                    e.critical_data_element,
                )
                for e in unique.values()
            ],
        )

    def fetch_lineage(self, run_id: str) -> list[LineageEdge]:
        rows = self.query(
            "SELECT run_id, from_node, to_node, edge_type, rule_id, critical_data_element "
            "FROM lineage_edges WHERE run_id = ? ORDER BY edge_type, from_node, to_node",
            [run_id],
        )
        return [self._edge_from_row(r) for r in rows]

    def lineage_targets(self, run_id: str) -> list[str]:
        rows = self.query(
            "SELECT DISTINCT to_node FROM lineage_edges "
            "WHERE run_id = ? AND edge_type = 'PUBLISH' ORDER BY to_node",
            [run_id],
        )
        return [str(r[0]) for r in rows]

    def trace_upstream(
        self, run_id: str, target_node: str, max_depth: int = 8
    ) -> list[LineageEdge]:
        """Walk the lineage graph upstream from a target attribute with a recursive CTE."""
        rows = self.query(
            """
            WITH RECURSIVE upstream(node, depth) AS (
                SELECT CAST(? AS VARCHAR), 0
                UNION ALL
                SELECT e.from_node, u.depth + 1
                FROM lineage_edges e
                JOIN upstream u ON e.to_node = u.node
                WHERE e.run_id = ? AND u.depth < ?
            )
            SELECT DISTINCT e.run_id, e.from_node, e.to_node, e.edge_type, e.rule_id,
                   e.critical_data_element
            FROM lineage_edges e
            WHERE e.run_id = ? AND e.to_node IN (SELECT node FROM upstream)
            ORDER BY e.edge_type, e.from_node, e.to_node
            """,
            [target_node, run_id, max_depth, run_id],
        )
        return [self._edge_from_row(r) for r in rows]

    @staticmethod
    def _edge_from_row(row: tuple[Any, ...]) -> LineageEdge:
        return LineageEdge(
            run_id=str(row[0]),
            from_node=str(row[1]),
            to_node=str(row[2]),
            edge_type=LineageEdgeType(str(row[3])),
            rule_id=None if row[4] is None else str(row[4]),
            critical_data_element=bool(row[5]),
        )

    # -- hash-chained audit log -------------------------------------------------------------

    def append_audit_event(
        self,
        *,
        event_type: str,
        actor_id: str,
        payload: dict[str, Any],
        run_id: str | None = None,
    ) -> AuditEvent:
        with self.atomic():
            head = self.query("SELECT seq, event_hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            prev_seq, prev_hash = (int(head[0][0]), str(head[0][1])) if head else (0, GENESIS_HASH)
            seq = prev_seq + 1
            event_id = uuid.uuid4().hex
            created_at = utc_now_iso()
            payload_json = canonical_json(payload)
            event_hash = compute_event_hash(
                seq=seq,
                event_id=event_id,
                run_id=run_id,
                event_type=event_type,
                actor_id=actor_id,
                payload_json=payload_json,
                created_at=created_at,
                prev_hash=prev_hash,
            )
            self.execute(
                "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    seq,
                    event_id,
                    run_id,
                    event_type,
                    actor_id,
                    payload_json,
                    created_at,
                    prev_hash,
                    event_hash,
                ],
            )
        return AuditEvent(
            seq=seq,
            event_id=event_id,
            run_id=run_id,
            event_type=event_type,
            actor_id=actor_id,
            payload=json.loads(payload_json),
            created_at=created_at,
            prev_hash=prev_hash,
            event_hash=event_hash,
        )

    def fetch_audit_events(self, run_id: str | None = None) -> list[AuditEvent]:
        sql = (
            "SELECT seq, event_id, run_id, event_type, actor_id, payload_json, created_at, "
            "prev_hash, event_hash FROM audit_log"
        )
        params: list[object] = []
        if run_id is not None:
            sql += " WHERE run_id = ?"
            params.append(run_id)
        sql += " ORDER BY seq"
        return [
            AuditEvent(
                seq=int(r[0]),
                event_id=str(r[1]),
                run_id=None if r[2] is None else str(r[2]),
                event_type=str(r[3]),
                actor_id=str(r[4]),
                payload=json.loads(str(r[5])),
                created_at=str(r[6]),
                prev_hash=str(r[7]),
                event_hash=str(r[8]),
            )
            for r in self.query(sql, params)
        ]

    def verify_chain(self, expected_head_hash: str | None = None) -> ChainVerification:
        """Recompute every hash in sequence order.

        Detects payload edits, re-hashed edits (the successor's ``prev_hash`` breaks),
        deletions (sequence gaps) and, when an externally anchored head hash is supplied,
        truncation of the most recent events.
        """
        rows = self.query(
            "SELECT seq, event_id, run_id, event_type, actor_id, payload_json, created_at, "
            "prev_hash, event_hash FROM audit_log ORDER BY seq"
        )
        expected_prev = GENESIS_HASH
        expected_seq = 1
        for row in rows:
            seq = int(row[0])
            if seq != expected_seq:
                return ChainVerification(
                    valid=False,
                    events_checked=expected_seq - 1,
                    head_hash=expected_prev,
                    broken_at_seq=seq,
                    reason=f"sequence gap: expected {expected_seq}, found {seq}",
                )
            if str(row[7]) != expected_prev:
                return ChainVerification(
                    valid=False,
                    events_checked=expected_seq - 1,
                    head_hash=expected_prev,
                    broken_at_seq=seq,
                    reason="prev_hash does not match the hash of the preceding event",
                )
            recomputed = compute_event_hash(
                seq=seq,
                event_id=str(row[1]),
                run_id=None if row[2] is None else str(row[2]),
                event_type=str(row[3]),
                actor_id=str(row[4]),
                payload_json=str(row[5]),
                created_at=str(row[6]),
                prev_hash=str(row[7]),
            )
            if recomputed != str(row[8]):
                return ChainVerification(
                    valid=False,
                    events_checked=expected_seq - 1,
                    head_hash=expected_prev,
                    broken_at_seq=seq,
                    reason="event content does not match its stored hash",
                )
            expected_prev = recomputed
            expected_seq += 1
        if expected_head_hash is not None and expected_head_hash != expected_prev:
            return ChainVerification(
                valid=False,
                events_checked=expected_seq - 1,
                head_hash=expected_prev,
                broken_at_seq=expected_seq,
                reason="chain head differs from the externally anchored head hash",
            )
        return ChainVerification(
            valid=True, events_checked=expected_seq - 1, head_hash=expected_prev
        )

    # -- workflow events ------------------------------------------------------------------

    def insert_workflow_event(self, event: WorkflowEvent) -> None:
        self.execute(
            "INSERT INTO workflow_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                event.run_id,
                event.seq,
                None if event.from_state is None else event.from_state.value,
                event.to_state.value,
                event.action.value,
                event.actor_id,
                event.justification,
                event.created_at,
                event.audit_event_hash,
            ],
        )

    def fetch_workflow_events(self, run_id: str) -> list[WorkflowEvent]:
        rows = self.query(
            "SELECT run_id, seq, from_state, to_state, action, actor_id, justification, "
            "created_at, audit_event_hash FROM workflow_events WHERE run_id = ? ORDER BY seq",
            [run_id],
        )
        return [
            WorkflowEvent(
                run_id=str(r[0]),
                seq=int(r[1]),
                from_state=None if r[2] is None else WorkflowState(str(r[2])),
                to_state=WorkflowState(str(r[3])),
                action=WorkflowAction(str(r[4])),
                actor_id=str(r[5]),
                justification=None if r[6] is None else str(r[6]),
                created_at=str(r[7]),
                audit_event_hash=str(r[8]),
            )
            for r in rows
        ]
