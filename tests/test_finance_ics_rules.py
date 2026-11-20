from __future__ import annotations

import pytest

from gatekeeper.models import (
    Finding,
    GateDecision,
    PackId,
    RunSummary,
    Severity,
    WorkflowState,
)
from gatekeeper.service import GatekeeperService

FIN = PackId.FINANCE_PRECLOSE_ICS
B = Severity.BLOCKER
W = Severity.WARNING


@pytest.fixture
def summary(service: GatekeeperService) -> RunSummary:
    return service.validate_sample(FIN)


def by_id(summary: RunSummary) -> dict[str, Finding]:
    return {f.finding_id: f for f in summary.findings}


def test_sample_batch_is_blocked_and_quarantined(summary: RunSummary) -> None:
    assert summary.run.record_count == 40
    assert summary.run.rejected_count == 0
    assert summary.run.gate_decision is GateDecision.BLOCKED
    assert summary.workflow_state is WorkflowState.QUARANTINED


@pytest.mark.parametrize(
    ("finding_id", "severity"),
    [
        ("FIN-TB-001:JOURNAL_NOT_BALANCED:JE-2026-11-0018", B),
        ("FIN-TB-002:TB_NOT_NET_ZERO:CH10", B),
        ("FIN-TB-002:TB_NOT_NET_ZERO:SE10", B),
        ("FIN-TB-003:SUBLEDGER_GL_DIFFERENCE:SE10/200000", B),
        ("FIN-TB-004:SUSPENSE_NOT_CLEARED:LV10/199999", B),
        ("FIN-IC-001:IC_NOT_NET_ZERO:CH10<>SE10", B),
        ("FIN-FX-001:FX_RATE_STALE:SL-0015", B),
        ("FIN-FX-001:FX_RATE_DEVIATION:SL-0017", B),
        ("FIN-FX-001:FX_RATE_DEVIATION:SL-0019", W),
        ("FIN-FX-001:FX_TRANSLATION_MISMATCH:SL-0021", B),
        ("FIN-MD-001:COST_CENTRE_UNMAPPED:SL-0025", B),
        ("FIN-MD-001:GL_ACCOUNT_UNMAPPED:SL-0027", B),
        ("FIN-PER-001:POSTING_DATE_OUTSIDE_PERIOD:SL-0039", B),
        ("FIN-SOD-001:SELF_APPROVAL:SL-0029", B),
        ("FIN-SOD-002:TOXIC_PAIR_P2P-01:SL-0031", B),
        ("FIN-SOD-002:TOXIC_PAIR_O2C-01:SL-0033", W),
    ],
)
def test_planted_defect_is_detected(
    summary: RunSummary, finding_id: str, severity: Severity
) -> None:
    findings = by_id(summary)
    assert finding_id in findings
    assert findings[finding_id].severity is severity


def test_exception_population_is_exact(summary: RunSummary) -> None:
    assert len(summary.findings) == 23
    assert summary.run.blocker_count == 19
    assert summary.run.warning_count == 4


def test_journal_imbalance_reports_transaction_currency_difference(summary: RunSummary) -> None:
    finding = by_id(summary)["FIN-TB-001:JOURNAL_NOT_BALANCED:JE-2026-11-0018"]
    assert finding.details["net_txn"] == "450.00"
    assert finding.details["currency"] == "CHF"


def test_trial_balance_net_zero_aggregation_in_group_currency(summary: RunSummary) -> None:
    findings = by_id(summary)
    assert findings["FIN-TB-002:TB_NOT_NET_ZERO:CH10"].details["net_group"] == "479.25"
    assert findings["FIN-TB-002:TB_NOT_NET_ZERO:SE10"].details["net_group"] == "90.00"
    assert "FIN-TB-002:TB_NOT_NET_ZERO:LV10" not in findings


def test_subledger_to_gl_tie_out_names_the_direct_posting(summary: RunSummary) -> None:
    finding = by_id(summary)["FIN-TB-003:SUBLEDGER_GL_DIFFERENCE:SE10/200000"]
    assert finding.details["difference_group"] == "1,218.00"
    assert finding.details["direct_postings"] == "SL-0037"


def test_intercompany_net_zero_reports_both_sides(summary: RunSummary) -> None:
    finding = by_id(summary)["FIN-IC-001:IC_NOT_NET_ZERO:CH10<>SE10"]
    assert finding.details == {
        "side_a_group": "50,055.00",
        "side_b_group": "-48,554.70",
        "net_group": "1,500.30",
    }
    assert "FIN-IC-001:IC_NOT_NET_ZERO:CH10<>LV10" not in by_id(summary)


def test_clean_journals_raise_no_findings(summary: RunSummary) -> None:
    keys = {f.record_key for f in summary.findings}
    clean_entries = {f"SL-{n:04d}" for n in range(1, 11)}
    clean_journals = {f"JE-2026-11-{n:04d}" for n in range(1, 6)}
    assert keys.isdisjoint(clean_entries | clean_journals)


def test_clean_subset_clears_the_gate(
    service: GatekeeperService, clean_finance_rows: list[dict[str, str]]
) -> None:
    summary = service.validate(FIN, clean_finance_rows, maker_id="U20117", source_name="clean")
    assert summary.findings == ()
    assert summary.run.gate_decision is GateDecision.CLEAR
    assert summary.workflow_state is WorkflowState.SUBMITTED
    assert all(e.outcome is Severity.PASS for e in summary.rule_executions)
    assert all(e.records_evaluated == 10 for e in summary.rule_executions)


def test_missing_cost_centre_and_missing_approval(
    service: GatekeeperService, clean_finance_rows: list[dict[str, str]]
) -> None:
    rows = [dict(r) for r in clean_finance_rows]
    rows[0]["cost_centre"] = ""  # SL-0001, account 610000 requires a cost centre
    for row in rows:
        if row["journal_id"] == "JE-2026-11-0005":  # intercompany journal needs approval
            row["approver_id"] = ""
    findings = by_id(service.validate(FIN, rows, maker_id="U20117"))
    assert "FIN-MD-001:COST_CENTRE_MISSING:SL-0001" in findings
    assert "FIN-SOD-001:APPROVAL_MISSING:SL-0009" in findings
    assert "FIN-SOD-001:APPROVAL_MISSING:SL-0010" in findings


def test_rate_dated_after_posting_is_a_lookahead_breach(
    service: GatekeeperService, clean_finance_rows: list[dict[str, str]]
) -> None:
    rows = [dict(r) for r in clean_finance_rows]
    rows[0]["fx_rate_date"] = "2026-11-04"  # posting date 2026-11-03
    findings = by_id(service.validate(FIN, rows, maker_id="U20117"))
    assert findings["FIN-FX-001:FX_RATE_LOOKAHEAD:SL-0001"].severity is B


def test_schema_contract_rejects_malformed_record_without_crashing(
    service: GatekeeperService, clean_finance_rows: list[dict[str, str]]
) -> None:
    rows = [dict(r) for r in clean_finance_rows]
    rows[1]["amount_txn"] = "twelve thousand"
    summary = service.validate(FIN, rows, maker_id="U20117")
    findings = by_id(summary)
    assert summary.run.rejected_count == 1
    assert findings["SCHEMA-001:CONTRACT_VIOLATION:SL-0002"].attributes == ("amount_txn",)
    # The surviving half of the journal no longer balances: rejection is not silent.
    assert "FIN-TB-001:JOURNAL_NOT_BALANCED:JE-2026-11-0001" in findings


def test_duplicate_entry_key_is_rejected(
    service: GatekeeperService, clean_finance_rows: list[dict[str, str]]
) -> None:
    rows = [*clean_finance_rows, dict(clean_finance_rows[0])]
    summary = service.validate(FIN, rows, maker_id="U20117")
    assert "SCHEMA-001:DUPLICATE_KEY:SL-0001@row-11" in by_id(summary)
    assert summary.run.rejected_count == 1


def test_identical_input_and_policy_yield_identical_findings(
    service: GatekeeperService, finance_rows: list[dict[str, str]]
) -> None:
    first = service.validate(FIN, finance_rows, maker_id="U20117")
    second = service.validate(FIN, finance_rows, maker_id="U20188")
    assert first.run.run_id != second.run.run_id
    assert first.run.input_sha256 == second.run.input_sha256
    assert first.run.config_sha256 == second.run.config_sha256
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]


def test_bcbs239_lineage_traces_group_amount_to_source_and_controls(
    service: GatekeeperService, summary: RunSummary
) -> None:
    run_id = summary.run.run_id
    assert "SAP_S4HANA/ACDOCA.KSL" in service.lineage_targets(run_id)
    trace = service.trace_lineage(run_id, "SAP_S4HANA/ACDOCA.KSL")
    assert {"FIN-FX-001", "FIN-TB-002", "FIN-IC-001"} <= set(trace.controls)
    assert "finance_subledger_batch.csv/amount_group" in trace.source_attributes
    assert "finance_subledger_batch.csv/fx_rate" in trace.source_attributes
    assert trace.open_findings_by_control["FIN-FX-001"] == 7
    assert any(e.critical_data_element for e in trace.edges)
