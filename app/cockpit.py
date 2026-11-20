"""Executive control cockpit (Streamlit).

Run with ``streamlit run app/cockpit.py``. The cockpit uses the same service layer as the API
and an in-memory DuckDB control store, so no external services or keys are required.
"""

from __future__ import annotations

import json

import streamlit as st

from gatekeeper.evidence.exporter import findings_csv, render_markdown
from gatekeeper.ledger.four_eyes import FourEyesError
from gatekeeper.models import GateDecision, LineageEdgeType, PackId, RunSummary, Severity
from gatekeeper.service import GatekeeperService

PACK_LABELS: dict[PackId, str] = {
    PackId.FINANCE_PRECLOSE_ICS: "Pack A: Finance Sub-Ledger-to-GL & ICS Pre-Close",
    PackId.TRAVEL_RETAIL_GDSN: "Pack B: Travel Retail GS1/GDSN & HAZMAT Gatekeeper",
}

GATE_COPY: dict[GateDecision, str] = {
    GateDecision.BLOCKED: "Hard gate stop. Remediate at source and resubmit as a new run.",
    GateDecision.REQUIRES_FOUR_EYES: (
        "Warnings only. Release requires a documented checker exception."
    ),
    GateDecision.CLEAR: "No exceptions. Eligible for checker release.",
}

STYLE = """
<style>
  .block-container { padding-top: 1.6rem; max-width: 1280px; }
  h1, h2, h3 { font-weight: 600; letter-spacing: -0.01em; }
  div[data-testid="stMetricValue"] { font-size: 1.5rem; }
  .gk-caption { color: #5b6470; font-size: 0.85rem; }
</style>
"""


@st.cache_resource
def get_service() -> GatekeeperService:
    return GatekeeperService()


def _state_key(pack_id: PackId) -> str:
    return f"run_id::{pack_id.value}"


def _render_header(summary: RunSummary) -> None:
    run = summary.run
    cols = st.columns(5)
    cols[0].metric("Gate decision", run.gate_decision.value)
    cols[1].metric("Workflow state", summary.workflow_state.value)
    cols[2].metric("Records", f"{run.record_count - run.rejected_count} / {run.record_count}")
    cols[3].metric("Blockers", run.blocker_count)
    cols[4].metric("Warnings", run.warning_count)
    st.markdown(
        f"<p class='gk-caption'>Run {run.run_id} | maker {run.maker_id} | input SHA-256 "
        f"{run.input_sha256[:16]} | policy SHA-256 {run.config_sha256[:16]} | "
        f"{GATE_COPY[run.gate_decision]}</p>",
        unsafe_allow_html=True,
    )


def _render_controls(summary: RunSummary) -> None:
    st.subheader("Control operation")
    st.dataframe(
        [
            {
                "Control": e.rule_id,
                "Title": e.title,
                "Population": e.records_evaluated,
                "Blockers": e.blocker_count,
                "Warnings": e.warning_count,
                "Outcome": e.outcome.value,
            }
            for e in summary.rule_executions
        ],
        hide_index=True,
    )


def _render_exceptions(summary: RunSummary) -> None:
    st.subheader("Blocked and flagged records")
    severities = st.multiselect(
        "Severity",
        options=[Severity.BLOCKER.value, Severity.WARNING.value],
        default=[Severity.BLOCKER.value, Severity.WARNING.value],
    )
    rows = [
        {
            "Severity": f.severity.value,
            "Control": f.rule_id,
            "Check": f.check_code,
            "Record": f.record_key,
            "Message": f.message,
            "Attributes": ", ".join(f.attributes),
        }
        for f in summary.findings
        if f.severity.value in severities
    ]
    if rows:
        st.dataframe(rows, hide_index=True)
    else:
        st.write("No exceptions for the selected severities.")


def _dot(edges: list[tuple[str, str, str]]) -> str:
    def node(name: str) -> str:
        return name.replace('"', "'")

    lines = [
        "digraph lineage {",
        "rankdir=LR;",
        'node [shape=box, style="rounded", fontname="Helvetica", fontsize=10];',
    ]
    for source, target, kind in edges:
        style = "dashed" if kind == LineageEdgeType.CONTROL_INPUT.value else "solid"
        lines.append(f'"{node(source)}" -> "{node(target)}" [style={style}, label="{kind}"];')
    lines.append("}")
    return "\n".join(lines)


def _render_lineage(service: GatekeeperService, summary: RunSummary) -> None:
    st.subheader("Attribute-level lineage (as executed)")
    targets = service.lineage_targets(summary.run.run_id)
    if not targets:
        st.write("No lineage recorded for this run.")
        return
    target = st.selectbox("Downstream attribute", options=targets)
    trace = service.trace_lineage(summary.run.run_id, target)
    st.graphviz_chart(_dot([(e.from_node, e.to_node, e.edge_type.value) for e in trace.edges]))
    st.dataframe(
        [
            {
                "Control": control,
                "Open findings in run": trace.open_findings_by_control.get(control, 0),
            }
            for control in trace.controls
        ],
        hide_index=True,
    )
    st.markdown(
        "<p class='gk-caption'>Sources: " + ", ".join(trace.source_attributes) + "</p>",
        unsafe_allow_html=True,
    )


def _render_signoff(service: GatekeeperService, summary: RunSummary, pack_id: PackId) -> None:
    st.subheader("Four-eyes sign-off")
    history = service.workflow(pack_id).history(summary.run.run_id)
    st.dataframe(
        [
            {
                "Seq": e.seq,
                "Action": e.action.value,
                "From": e.from_state.value if e.from_state else "",
                "To": e.to_state.value,
                "Actor": e.actor_id,
                "Justification": e.justification or "",
                "Audit hash": e.audit_event_hash[:16],
            }
            for e in history
        ],
        hide_index=True,
    )
    _, demo_checker = service.demo_actors(pack_id)
    checker = st.text_input("Checker ID", value=demo_checker, key=f"checker::{pack_id.value}")
    justification = st.text_area(
        "Exception justification (required for approval with exception)",
        key=f"justification::{pack_id.value}",
    )
    left, right = st.columns(2)
    try:
        if left.button("Release (clean run)", key=f"release::{pack_id.value}"):
            service.release(summary.run.run_id, checker)
            st.rerun()
        if right.button("Approve with exception", key=f"approve::{pack_id.value}"):
            service.approve_with_exception(summary.run.run_id, checker, justification)
            st.rerun()
    except FourEyesError as exc:
        st.error(f"{type(exc).__name__}: {exc}")


def _render_advisor(service: GatekeeperService, summary: RunSummary) -> None:
    st.subheader("Remediation advisor")
    st.markdown(
        f"<p class='gk-caption'>Mode: {service.advisor.mode}. Advisory output only; gate "
        "decisions are produced exclusively by deterministic rules.</p>",
        unsafe_allow_html=True,
    )
    advice = service.advise(summary.run.run_id)
    if not advice:
        st.write("No exceptions to remediate.")
        return
    st.dataframe(
        [
            {
                "Finding": a.finding_id,
                "Severity": a.severity.value,
                "Suggested action": a.suggested_action,
                "Rationale": a.rationale,
                "Source": a.source,
            }
            for a in advice
        ],
        hide_index=True,
    )


def _render_evidence(service: GatekeeperService, summary: RunSummary) -> None:
    st.subheader("SOX/ICS control evidence pack")
    pack = service.evidence_pack(summary.run.run_id)
    st.markdown(
        f"<p class='gk-caption'>Content SHA-256 {pack.content_sha256} | signature "
        f"{pack.signature.algorithm} | audit chain "
        f"{'valid' if pack.audit_chain.valid else 'broken'}</p>",
        unsafe_allow_html=True,
    )
    run_id = summary.run.run_id
    cols = st.columns(3)
    cols[0].download_button(
        "Evidence pack (JSON)",
        data=json.dumps(pack.model_dump(mode="json"), indent=2, ensure_ascii=False),
        file_name=f"evidence_{run_id}.json",
        mime="application/json",
    )
    cols[1].download_button(
        "Findings (CSV)",
        data=findings_csv(pack),
        file_name=f"findings_{run_id}.csv",
        mime="text/csv",
    )
    cols[2].download_button(
        "Summary (Markdown)",
        data=render_markdown(pack),
        file_name=f"evidence_{run_id}.md",
        mime="text/markdown",
    )


def main() -> None:
    st.set_page_config(page_title="Control Gatekeeper Cockpit", layout="wide")
    st.markdown(STYLE, unsafe_allow_html=True)
    service = get_service()

    st.sidebar.title("Control Gatekeeper")
    pack_id = st.sidebar.radio(
        "Rule pack", options=list(PACK_LABELS), format_func=lambda p: PACK_LABELS[p]
    )
    demo_maker, _ = service.demo_actors(pack_id)
    maker = st.sidebar.text_input("Maker (preparer) ID", value=demo_maker, key=f"maker::{pack_id}")
    if st.sidebar.button("Run pre-flight validation", type="primary"):
        try:
            summary = service.validate_sample(pack_id, maker)
            st.session_state[_state_key(pack_id)] = summary.run.run_id
        except FourEyesError as exc:
            st.sidebar.error(f"{type(exc).__name__}: {exc}")
    chain = service.verify_audit_chain()
    st.sidebar.caption(
        f"Audit chain: {'valid' if chain.valid else 'BROKEN'} ({chain.events_checked} events)"
    )

    st.title(PACK_LABELS[pack_id])
    run_id = st.session_state.get(_state_key(pack_id))
    if run_id is None:
        st.write(
            "Run the pre-flight validation on the bundled synthetic batch to inspect the gate "
            "decision, exceptions, lineage, sign-off and evidence."
        )
        return

    summary = service.run_summary(str(run_id))
    _render_header(summary)
    tabs = st.tabs(
        ["Gate", "Exceptions", "Lineage", "Four-eyes", "Remediation advisor", "Evidence pack"]
    )
    with tabs[0]:
        _render_controls(summary)
    with tabs[1]:
        _render_exceptions(summary)
    with tabs[2]:
        _render_lineage(service, summary)
    with tabs[3]:
        _render_signoff(service, summary, pack_id)
    with tabs[4]:
        _render_advisor(service, summary)
    with tabs[5]:
        _render_evidence(service, summary)


main()
