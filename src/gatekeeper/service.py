"""Application service shared by the FastAPI endpoints and the Streamlit cockpit."""

from __future__ import annotations

import csv
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from gatekeeper.advisor.bedrock_explainer import RemediationAdvisor
from gatekeeper.engine import ValidationEngine
from gatekeeper.evidence.exporter import EvidencePack, build_evidence_pack, signing_key_from_env
from gatekeeper.ledger.four_eyes import AccessDirectory, FourEyesPolicy, FourEyesWorkflow
from gatekeeper.ledger.store import ControlStore, RunNotFoundError
from gatekeeper.models import (
    ChainVerification,
    GateDecision,
    LineageTrace,
    PackId,
    RemediationAdvice,
    RuleDescriptor,
    RunRecord,
    RunSummary,
    WorkflowState,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value) if value else default


class GatekeeperService:
    """Orchestrates validation, maker/checker workflow, lineage, advice and evidence."""

    def __init__(
        self,
        database: str = ":memory:",
        *,
        config_dir: Path | None = None,
        data_dir: Path | None = None,
        advisor: RemediationAdvisor | None = None,
    ) -> None:
        self.store = ControlStore(database)
        self.config_dir = config_dir or _env_path("GATEKEEPER_CONFIG_DIR", PROJECT_ROOT / "configs")
        self.data_dir = data_dir or _env_path(
            "GATEKEEPER_DATA_DIR", PROJECT_ROOT / "data" / "synthetic"
        )
        self.engine = ValidationEngine(self.store, self.config_dir)
        self.advisor = advisor or RemediationAdvisor.from_environment()
        self._workflows: dict[PackId, FourEyesWorkflow] = {}

    @classmethod
    def from_environment(cls) -> GatekeeperService:
        return cls(os.environ.get("GATEKEEPER_DB_PATH", ":memory:"))

    def close(self) -> None:
        self.store.close()

    # -- pack metadata -------------------------------------------------------------------

    def packs(self) -> list[tuple[PackId, str, list[RuleDescriptor]]]:
        return [
            (pid, self.engine.pack(pid).display_name, self.engine.pack(pid).descriptors())
            for pid in PackId
        ]

    def demo_actors(self, pack_id: PackId) -> tuple[str, str]:
        cfg: Mapping[str, Any] = self.engine.config(pack_id).data["four_eyes"]
        return str(cfg["demo_maker"]), str(cfg["demo_checker"])

    def workflow(self, pack_id: PackId) -> FourEyesWorkflow:
        if pack_id not in self._workflows:
            cfg = self.engine.config(pack_id).data
            self._workflows[pack_id] = FourEyesWorkflow(
                self.store,
                FourEyesPolicy.from_config(cfg["four_eyes"]),
                AccessDirectory.from_config(cfg["access_directory"]),
            )
        return self._workflows[pack_id]

    def sample_rows(self, pack_id: PackId) -> list[dict[str, str]]:
        path = self.data_dir / self.engine.pack(pack_id).default_source
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    # -- validation ----------------------------------------------------------------------

    def validate(
        self,
        pack_id: PackId,
        rows: Sequence[Mapping[str, object]],
        *,
        maker_id: str,
        source_name: str = "api",
    ) -> RunSummary:
        workflow = self.workflow(pack_id)
        workflow.assert_can_submit(maker_id)
        result = self.engine.validate(pack_id, rows, maker_id=maker_id, source_name=source_name)
        run_id = result.run.run_id
        workflow.open_draft(run_id, maker_id)
        workflow.submit(run_id, maker_id)
        if result.run.gate_decision is not GateDecision.CLEAR:
            workflow.quarantine(run_id)
        return self.run_summary(run_id)

    def validate_sample(self, pack_id: PackId, maker_id: str | None = None) -> RunSummary:
        maker = maker_id or self.demo_actors(pack_id)[0]
        pack = self.engine.pack(pack_id)
        return self.validate(
            pack_id, self.sample_rows(pack_id), maker_id=maker, source_name=pack.default_source
        )

    # -- queries -------------------------------------------------------------------------

    def run_summary(self, run_id: str) -> RunSummary:
        run = self.store.fetch_run(run_id)
        state = self.workflow(run.pack_id).current_state(run_id)
        return RunSummary(
            run=run,
            workflow_state=state or WorkflowState.DRAFT,
            rule_executions=tuple(self.store.fetch_rule_executions(run_id)),
            findings=tuple(self.store.fetch_findings(run_id)),
        )

    def runs(self, pack_id: PackId | None = None) -> list[tuple[RunRecord, WorkflowState | None]]:
        return [
            (run, self.workflow(run.pack_id).current_state(run.run_id))
            for run in self.store.list_runs(pack_id)
        ]

    def quarantined(self, pack_id: PackId | None = None) -> list[RunRecord]:
        return [run for run, state in self.runs(pack_id) if state is WorkflowState.QUARANTINED]

    # -- four-eyes sign-off ----------------------------------------------------------------

    def release(self, run_id: str, checker_id: str) -> RunSummary:
        run = self.store.fetch_run(run_id)
        self.workflow(run.pack_id).release(run_id, checker_id)
        return self.run_summary(run_id)

    def approve_with_exception(
        self, run_id: str, checker_id: str, justification: str | None
    ) -> RunSummary:
        run = self.store.fetch_run(run_id)
        self.workflow(run.pack_id).approve_with_exception(run_id, checker_id, justification)
        return self.run_summary(run_id)

    # -- lineage -------------------------------------------------------------------------

    def lineage_targets(self, run_id: str) -> list[str]:
        self.store.fetch_run(run_id)
        return [t.removeprefix("target://") for t in self.store.lineage_targets(run_id)]

    def trace_lineage(self, run_id: str, target: str) -> LineageTrace:
        self.store.fetch_run(run_id)
        node = target if target.startswith("target://") else f"target://{target}"
        edges = self.store.trace_upstream(run_id, node)
        if not edges:
            raise RunNotFoundError(f"no lineage recorded for {node} in run {run_id}")
        controls = sorted(
            {
                e.from_node.removeprefix("control://")
                for e in edges
                if e.from_node.startswith("control://")
            }
        )
        sources = sorted(
            {
                e.from_node.removeprefix("source://")
                for e in edges
                if e.from_node.startswith("source://")
            }
        )
        open_by_control = dict.fromkeys(controls, 0)
        for finding in self.store.fetch_findings(run_id):
            if finding.rule_id in open_by_control:
                open_by_control[finding.rule_id] += 1
        return LineageTrace(
            run_id=run_id,
            target_node=node,
            edges=tuple(edges),
            controls=tuple(controls),
            source_attributes=tuple(sources),
            open_findings_by_control=open_by_control,
        )

    # -- advice and evidence ----------------------------------------------------------------

    def advise(self, run_id: str) -> list[RemediationAdvice]:
        run = self.store.fetch_run(run_id)
        hints = self.engine.pack(run.pack_id).remediation_hints()
        return self.advisor.advise(self.store.fetch_findings(run_id), hints)

    def evidence_pack(self, run_id: str) -> EvidencePack:
        run = self.store.fetch_run(run_id)
        key, key_id = signing_key_from_env()
        return build_evidence_pack(
            run=run,
            workflow_state=self.workflow(run.pack_id).current_state(run_id),
            control_catalogue=self.engine.pack(run.pack_id).descriptors(),
            rule_executions=self.store.fetch_rule_executions(run_id),
            findings=self.store.fetch_findings(run_id),
            workflow_events=self.store.fetch_workflow_events(run_id),
            audit_events=self.store.fetch_audit_events(run_id),
            audit_chain=self.store.verify_chain(),
            lineage_edges=self.store.fetch_lineage(run_id),
            signing_key=key,
            key_id=key_id,
        )

    def verify_audit_chain(self, expected_head_hash: str | None = None) -> ChainVerification:
        return self.store.verify_chain(expected_head_hash)
