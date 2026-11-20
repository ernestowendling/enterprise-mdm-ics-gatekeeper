"""Deterministic validation engine.

For a submitted batch the engine (1) fingerprints input and policy, (2) enforces the record
contract, (3) stages valid records in DuckDB, (4) executes every rule of the pack, (5) derives
the gate decision and (6) persists results, attribute-level lineage and an audit event in one
transaction. Identical input and identical policy always yield identical findings.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from gatekeeper.ledger.store import ControlStore, utc_now_iso
from gatekeeper.models import (
    Finding,
    FindingScope,
    GateDecision,
    LineageEdge,
    LineageEdgeType,
    PackId,
    RuleExecution,
    RunRecord,
    Severity,
)
from gatekeeper.rules.base import (
    LoadedConfig,
    Rule,
    RuleContext,
    RulePack,
    fingerprint_rows,
    get_pack_class,
    load_config,
)

ENGINE_VERSION = "0.1.0"
SCHEMA_RULE_ID = "SCHEMA-001"
SCHEMA_RULE_TITLE = "Ingestion record contract"


@dataclass(frozen=True)
class EngineResult:
    run: RunRecord
    findings: tuple[Finding, ...]
    executions: tuple[RuleExecution, ...]


def gate_decision(findings: Sequence[Finding]) -> GateDecision:
    """BLOCKER anywhere stops the gate; warnings alone require four-eyes sign-off."""
    if any(f.severity is Severity.BLOCKER for f in findings):
        return GateDecision.BLOCKED
    if any(f.severity is Severity.WARNING for f in findings):
        return GateDecision.REQUIRES_FOUR_EYES
    return GateDecision.CLEAR


def _outcome(blockers: int, warnings: int) -> Severity:
    if blockers:
        return Severity.BLOCKER
    if warnings:
        return Severity.WARNING
    return Severity.PASS


def source_node(source_name: str, column: str) -> str:
    return f"source://{source_name}/{column}"


def staging_node(table: str, column: str) -> str:
    return f"staging://{table}/{column}"


def control_node(rule_id: str) -> str:
    return f"control://{rule_id}"


def target_node(attribute: str) -> str:
    return f"target://{attribute}"


class ValidationEngine:
    """Runs rule packs against batches and records the evidence in the control store."""

    def __init__(self, store: ControlStore, config_dir: Path) -> None:
        self._store = store
        self._config_dir = config_dir
        self._packs: dict[PackId, tuple[RulePack[Any], LoadedConfig]] = {}

    @property
    def store(self) -> ControlStore:
        return self._store

    def pack(self, pack_id: PackId) -> RulePack[Any]:
        return self._load(pack_id)[0]

    def config(self, pack_id: PackId) -> LoadedConfig:
        return self._load(pack_id)[1]

    def _load(self, pack_id: PackId) -> tuple[RulePack[Any], LoadedConfig]:
        if pack_id not in self._packs:
            pack_cls = get_pack_class(pack_id)
            loaded = load_config(self._config_dir / pack_cls.config_file)
            pack = pack_cls(loaded.data)
            self._store.execute(pack.staging.ddl)
            self._packs[pack_id] = (pack, loaded)
        return self._packs[pack_id]

    def validate(
        self,
        pack_id: PackId,
        rows: Sequence[Mapping[str, object]],
        *,
        maker_id: str,
        source_name: str,
    ) -> EngineResult:
        pack, loaded = self._load(pack_id)
        now = datetime.now(UTC)
        run_id = f"{pack.run_prefix}-{now:%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:8]}"

        records, schema_findings = self._parse(pack, rows, run_id)
        self._stage(pack, run_id, records)

        ctx: RuleContext[Any] = RuleContext(
            run_id=run_id,
            pack_id=pack_id,
            store=self._store,
            config=loaded.data,
            records=records,
            staging_table=pack.staging.table,
        )
        findings: list[Finding] = list(schema_findings)
        executions: list[RuleExecution] = [
            self._execution(run_id, SCHEMA_RULE_ID, SCHEMA_RULE_TITLE, len(rows), schema_findings)
        ]
        for rule in pack.rules:
            rule_findings = rule.evaluate(ctx)
            findings.extend(rule_findings)
            executions.append(
                self._execution(run_id, rule.rule_id, rule.title, len(records), rule_findings)
            )

        blockers = sum(1 for f in findings if f.severity is Severity.BLOCKER)
        warnings = sum(1 for f in findings if f.severity is Severity.WARNING)
        run = RunRecord(
            run_id=run_id,
            pack_id=pack_id,
            maker_id=maker_id,
            source_name=source_name,
            input_sha256=fingerprint_rows(rows),
            config_sha256=loaded.sha256,
            record_count=len(rows),
            rejected_count=len(rows) - len(records),
            blocker_count=blockers,
            warning_count=warnings,
            gate_decision=gate_decision(findings),
            engine_version=ENGINE_VERSION,
            created_at=utc_now_iso(),
        )

        with self._store.atomic():
            self._store.insert_run(run)
            self._store.insert_rule_executions(executions)
            self._store.insert_findings(findings)
            self._store.insert_lineage_edges(self._lineage(pack, run_id, source_name))
            self._store.append_audit_event(
                event_type="VALIDATION_COMPLETED",
                actor_id=maker_id,
                run_id=run_id,
                payload={
                    "pack_id": pack_id.value,
                    "source_name": source_name,
                    "input_sha256": run.input_sha256,
                    "config_sha256": run.config_sha256,
                    "engine_version": ENGINE_VERSION,
                    "record_count": run.record_count,
                    "rejected_count": run.rejected_count,
                    "blocker_count": blockers,
                    "warning_count": warnings,
                    "gate_decision": run.gate_decision.value,
                    "finding_ids": sorted(f.finding_id for f in findings),
                },
            )
        return EngineResult(run=run, findings=tuple(findings), executions=tuple(executions))

    # -- steps ---------------------------------------------------------------------------

    @staticmethod
    def _parse(
        pack: RulePack[Any], rows: Sequence[Mapping[str, object]], run_id: str
    ) -> tuple[list[Any], list[Finding]]:
        records: list[Any] = []
        findings: list[Finding] = []
        seen: set[str] = set()
        for position, row in enumerate(rows, start=1):
            key = pack.raw_record_key(row, position)
            try:
                record = pack.parse_record(row)
            except ValidationError as exc:
                problems = "; ".join(
                    f"{'.'.join(str(p) for p in err['loc']) or 'record'}: {err['msg']}"
                    for err in exc.errors()
                )
                findings.append(
                    Finding(
                        run_id=run_id,
                        pack_id=pack.pack_id,
                        rule_id=SCHEMA_RULE_ID,
                        check_code="CONTRACT_VIOLATION",
                        severity=Severity.BLOCKER,
                        scope=FindingScope.SCHEMA,
                        record_key=key,
                        message=f"Record rejected at ingestion: {problems}",
                        attributes=tuple(
                            sorted({str(err["loc"][0]) for err in exc.errors() if err["loc"]})
                        ),
                        details={"error_count": exc.error_count(), "row_position": position},
                    )
                )
                continue
            record_key = pack.record_key(record)
            if record_key in seen:
                findings.append(
                    Finding(
                        run_id=run_id,
                        pack_id=pack.pack_id,
                        rule_id=SCHEMA_RULE_ID,
                        check_code="DUPLICATE_KEY",
                        severity=Severity.BLOCKER,
                        scope=FindingScope.SCHEMA,
                        record_key=f"{record_key}@row-{position}",
                        message=(
                            f"Duplicate {pack.staging.key_column} {record_key}; "
                            "only the first occurrence was staged"
                        ),
                        attributes=(pack.staging.key_column,),
                        details={"row_position": position},
                    )
                )
                continue
            seen.add(record_key)
            records.append(record)
        return records, findings

    def _stage(self, pack: RulePack[Any], run_id: str, records: Sequence[Any]) -> None:
        placeholders = ", ".join(["?"] * (len(pack.staging.columns) + 1))
        columns = ", ".join(("run_id", *pack.staging.columns))
        self._store.executemany(
            f"INSERT INTO {pack.staging.table} ({columns}) VALUES ({placeholders})",
            [(run_id, *pack.to_staging_row(record)) for record in records],
        )

    @staticmethod
    def _execution(
        run_id: str, rule_id: str, title: str, evaluated: int, findings: Sequence[Finding]
    ) -> RuleExecution:
        blockers = sum(1 for f in findings if f.severity is Severity.BLOCKER)
        warnings = sum(1 for f in findings if f.severity is Severity.WARNING)
        return RuleExecution(
            run_id=run_id,
            rule_id=rule_id,
            title=title,
            records_evaluated=evaluated,
            blocker_count=blockers,
            warning_count=warnings,
            outcome=_outcome(blockers, warnings),
        )

    @staticmethod
    def _lineage(pack: RulePack[Any], run_id: str, source_name: str) -> list[LineageEdge]:
        table = pack.staging.table
        targets = {spec.source_column: spec for spec in pack.lineage}
        edges: list[LineageEdge] = []
        for spec in pack.lineage:
            edges.append(
                LineageEdge(
                    run_id=run_id,
                    from_node=source_node(source_name, spec.source_column),
                    to_node=staging_node(table, spec.source_column),
                    edge_type=LineageEdgeType.INGEST,
                    critical_data_element=spec.critical_data_element,
                )
            )
            edges.append(
                LineageEdge(
                    run_id=run_id,
                    from_node=staging_node(table, spec.source_column),
                    to_node=target_node(spec.target_attribute),
                    edge_type=LineageEdgeType.PUBLISH,
                    critical_data_element=spec.critical_data_element,
                )
            )
        rule: Rule[Any]
        for rule in pack.rules:
            for attribute in rule.input_attributes:
                mapped = targets.get(attribute)
                if mapped is None:
                    edges.append(
                        LineageEdge(
                            run_id=run_id,
                            from_node=source_node(source_name, attribute),
                            to_node=staging_node(table, attribute),
                            edge_type=LineageEdgeType.INGEST,
                        )
                    )
                edges.append(
                    LineageEdge(
                        run_id=run_id,
                        from_node=staging_node(table, attribute),
                        to_node=control_node(rule.rule_id),
                        edge_type=LineageEdgeType.CONTROL_INPUT,
                        rule_id=rule.rule_id,
                        critical_data_element=mapped.critical_data_element if mapped else False,
                    )
                )
                if mapped is not None:
                    edges.append(
                        LineageEdge(
                            run_id=run_id,
                            from_node=control_node(rule.rule_id),
                            to_node=target_node(mapped.target_attribute),
                            edge_type=LineageEdgeType.GATES,
                            rule_id=rule.rule_id,
                            critical_data_element=mapped.critical_data_element,
                        )
                    )
        return edges
