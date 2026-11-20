"""ICS/SOX control evidence pack.

The pack bundles, for one run: the run header with input and policy fingerprints, the control
catalogue with framework mapping, rule executions (population and exception counts), findings,
maker/checker events, the run's audit events with chain verification, and as-run lineage.

Integrity: ``content_sha256`` is the SHA-256 of the canonical JSON body. When a key is
configured the digest is additionally signed with HMAC-SHA256; production deployments replace
HMAC with an asymmetric KMS/HSM signature so that verifiers do not need the signing secret.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import os
from collections.abc import Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from gatekeeper.ledger.store import canonical_json, sha256_hex, utc_now_iso
from gatekeeper.models import (
    AuditEvent,
    ChainVerification,
    Finding,
    LineageEdge,
    RuleDescriptor,
    RuleExecution,
    RunRecord,
    WorkflowEvent,
    WorkflowState,
)

SCHEMA_VERSION = "1.0"
KEY_ENV = "GATEKEEPER_EVIDENCE_HMAC_KEY"
KEY_ID_ENV = "GATEKEEPER_EVIDENCE_KEY_ID"


class EvidenceSignature(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: Literal["HMAC-SHA256", "NONE"]
    key_id: str | None = None
    value: str | None = None


class EvidencePack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    generated_at: str
    run: RunRecord
    workflow_state: WorkflowState | None
    control_catalogue: list[RuleDescriptor]
    rule_executions: list[RuleExecution]
    findings: list[Finding]
    workflow_events: list[WorkflowEvent]
    audit_events: list[AuditEvent]
    audit_chain: ChainVerification
    lineage_edges: list[LineageEdge]
    content_sha256: str
    signature: EvidenceSignature


def signing_key_from_env() -> tuple[bytes | None, str | None]:
    raw = os.environ.get(KEY_ENV)
    if not raw:
        return None, None
    return raw.encode("utf-8"), os.environ.get(KEY_ID_ENV, "local-hmac")


def evidence_body(pack: EvidencePack) -> dict[str, Any]:
    """The signed portion of the pack: everything except the integrity block."""
    return pack.model_dump(mode="json", exclude={"content_sha256", "signature"})


def _sign(digest: str, key: bytes) -> str:
    return hmac.new(key, digest.encode("utf-8"), hashlib.sha256).hexdigest()


def build_evidence_pack(
    *,
    run: RunRecord,
    workflow_state: WorkflowState | None,
    control_catalogue: Sequence[RuleDescriptor],
    rule_executions: Sequence[RuleExecution],
    findings: Sequence[Finding],
    workflow_events: Sequence[WorkflowEvent],
    audit_events: Sequence[AuditEvent],
    audit_chain: ChainVerification,
    lineage_edges: Sequence[LineageEdge],
    signing_key: bytes | None = None,
    key_id: str | None = None,
) -> EvidencePack:
    unsigned = EvidencePack(
        schema_version=SCHEMA_VERSION,
        generated_at=utc_now_iso(),
        run=run,
        workflow_state=workflow_state,
        control_catalogue=list(control_catalogue),
        rule_executions=list(rule_executions),
        findings=list(findings),
        workflow_events=list(workflow_events),
        audit_events=list(audit_events),
        audit_chain=audit_chain,
        lineage_edges=list(lineage_edges),
        content_sha256="",
        signature=EvidenceSignature(algorithm="NONE"),
    )
    digest = sha256_hex(canonical_json(evidence_body(unsigned)))
    signature = (
        EvidenceSignature(algorithm="HMAC-SHA256", key_id=key_id, value=_sign(digest, signing_key))
        if signing_key
        else EvidenceSignature(algorithm="NONE")
    )
    return unsigned.model_copy(update={"content_sha256": digest, "signature": signature})


def verify_evidence_pack(pack: EvidencePack, signing_key: bytes | None = None) -> bool:
    """Recompute the content digest and, for signed packs, the HMAC signature."""
    digest = sha256_hex(canonical_json(evidence_body(pack)))
    if not hmac.compare_digest(digest, pack.content_sha256):
        return False
    if pack.signature.algorithm == "NONE":
        return True
    if signing_key is None or pack.signature.value is None:
        return False
    return hmac.compare_digest(_sign(digest, signing_key), pack.signature.value)


def findings_csv(pack: EvidencePack) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "run_id",
            "finding_id",
            "rule_id",
            "check_code",
            "severity",
            "scope",
            "record_key",
            "attributes",
            "message",
        ]
    )
    for f in pack.findings:
        writer.writerow(
            [
                f.run_id,
                f.finding_id,
                f.rule_id,
                f.check_code,
                f.severity.value,
                f.scope.value,
                f.record_key,
                "|".join(f.attributes),
                f.message,
            ]
        )
    return buffer.getvalue()


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(pack: EvidencePack) -> str:
    run = pack.run
    state = pack.workflow_state.value if pack.workflow_state else "NOT_STARTED"
    lines = [
        f"# Control Evidence Pack: {run.run_id}",
        "",
        "| Item | Value |",
        "| --- | --- |",
        f"| Rule pack | {run.pack_id.value} |",
        f"| Gate decision | {run.gate_decision.value} |",
        f"| Workflow state | {state} |",
        f"| Maker | {run.maker_id} |",
        f"| Source | {_cell(run.source_name)} |",
        f"| Records submitted / rejected | {run.record_count} / {run.rejected_count} |",
        f"| Blockers / warnings | {run.blocker_count} / {run.warning_count} |",
        f"| Input SHA-256 | `{run.input_sha256}` |",
        f"| Policy SHA-256 | `{run.config_sha256}` |",
        f"| Engine version | {run.engine_version} |",
        f"| Run created (UTC) | {run.created_at} |",
        f"| Pack generated (UTC) | {pack.generated_at} |",
        "",
        "## Control operation",
        "",
        "| Control | Title | Population | Blockers | Warnings | Outcome |",
        "| --- | --- | ---: | ---: | ---: | --- |",
    ]
    lines += [
        f"| {e.rule_id} | {_cell(e.title)} | {e.records_evaluated} | {e.blocker_count} | "
        f"{e.warning_count} | {e.outcome.value} |"
        for e in pack.rule_executions
    ]
    lines += [
        "",
        "## Exceptions",
        "",
        "| Severity | Control | Check | Record | Message |",
        "| --- | --- | --- | --- | --- |",
    ]
    lines += [
        f"| {f.severity.value} | {f.rule_id} | {f.check_code} | {_cell(f.record_key)} | "
        f"{_cell(f.message)} |"
        for f in pack.findings
    ] or ["| - | - | - | - | No exceptions |"]
    lines += [
        "",
        "## Maker/checker history",
        "",
        "| Seq | Action | From | To | Actor | Justification | Audit hash |",
        "| ---: | --- | --- | --- | --- | --- | --- |",
    ]
    lines += [
        f"| {w.seq} | {w.action.value} | {w.from_state.value if w.from_state else '-'} | "
        f"{w.to_state.value} | {w.actor_id} | {_cell(w.justification or '-')} | "
        f"`{w.audit_event_hash[:16]}` |"
        for w in pack.workflow_events
    ]
    chain = pack.audit_chain
    chain_status = (
        f"VALID ({chain.events_checked} events, head `{chain.head_hash[:16]}`)"
        if chain.valid
        else f"BROKEN at seq {chain.broken_at_seq}: {chain.reason}"
    )
    lines += [
        "",
        "## Integrity",
        "",
        f"- Audit hash chain: {chain_status}",
        f"- Content SHA-256: `{pack.content_sha256}`",
        f"- Signature: {pack.signature.algorithm}"
        + (f" (key `{pack.signature.key_id}`)" if pack.signature.key_id else ""),
        "",
    ]
    return "\n".join(lines)
