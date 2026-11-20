from __future__ import annotations

import pytest

from gatekeeper.ledger.four_eyes import (
    HardGateError,
    InvalidTransitionError,
    JustificationRequiredError,
    SegregationOfDutiesError,
    SelfApprovalError,
)
from gatekeeper.ledger.store import compute_event_hash
from gatekeeper.models import GateDecision, PackId, RunSummary, WorkflowAction, WorkflowState
from gatekeeper.service import GatekeeperService

FIN = PackId.FINANCE_PRECLOSE_ICS
GDSN = PackId.TRAVEL_RETAIL_GDSN
MAKER = "U20117"
CHECKER = "U30452"
JUSTIFICATION = "Accepted for release: IMDG scope not required, air freight only this cycle."


@pytest.fixture
def clean_run(service: GatekeeperService, clean_finance_rows: list[dict[str, str]]) -> RunSummary:
    return service.validate(FIN, clean_finance_rows, maker_id=MAKER, source_name="clean")


@pytest.fixture
def warning_run(service: GatekeeperService, travel_rows: list[dict[str, str]]) -> RunSummary:
    rows = [r for r in travel_rows if r["listing_id"] <= "L-0022" or r["sku_id"] == "S-10016"]
    return service.validate(GDSN, rows, maker_id="S11003", source_name="warnings-only")


# -- maker/checker -------------------------------------------------------------------------


def test_independent_checker_releases_clean_run(
    service: GatekeeperService, clean_run: RunSummary
) -> None:
    released = service.release(clean_run.run.run_id, CHECKER)
    assert released.workflow_state is WorkflowState.RELEASED
    history = service.workflow(FIN).history(clean_run.run.run_id)
    assert [e.action for e in history] == [
        WorkflowAction.OPEN,
        WorkflowAction.SUBMIT,
        WorkflowAction.RELEASE,
    ]
    assert history[-1].actor_id == CHECKER


def test_maker_cannot_approve_own_run(service: GatekeeperService, clean_run: RunSummary) -> None:
    with pytest.raises(SelfApprovalError):
        service.release(clean_run.run.run_id, MAKER)
    assert service.run_summary(clean_run.run.run_id).workflow_state is WorkflowState.SUBMITTED


def test_checker_without_approver_role_is_rejected(
    service: GatekeeperService, clean_run: RunSummary
) -> None:
    with pytest.raises(SegregationOfDutiesError, match="does not hold approver role"):
        service.release(clean_run.run.run_id, "U20188")


def test_checker_with_incompatible_role_is_rejected(
    service: GatekeeperService, clean_run: RunSummary
) -> None:
    with pytest.raises(SegregationOfDutiesError, match="incompatible"):
        service.release(clean_run.run.run_id, "U30477")


def test_unauthorised_maker_leaves_no_run_behind(
    service: GatekeeperService, clean_finance_rows: list[dict[str, str]]
) -> None:
    with pytest.raises(SegregationOfDutiesError, match="submitter role"):
        service.validate(FIN, clean_finance_rows, maker_id="U40901")
    assert service.store.list_runs() == []


def test_blocker_cannot_be_overridden(service: GatekeeperService) -> None:
    run_id = service.validate_sample(FIN).run.run_id
    with pytest.raises(HardGateError, match="BLOCKER"):
        service.approve_with_exception(run_id, CHECKER, JUSTIFICATION)
    with pytest.raises(HardGateError):
        service.release(run_id, CHECKER)
    assert service.run_summary(run_id).workflow_state is WorkflowState.QUARANTINED


def test_warning_only_run_needs_documented_exception(
    service: GatekeeperService, warning_run: RunSummary
) -> None:
    run_id = warning_run.run.run_id
    assert warning_run.run.gate_decision is GateDecision.REQUIRES_FOUR_EYES
    assert warning_run.run.blocker_count == 0
    assert warning_run.workflow_state is WorkflowState.QUARANTINED
    with pytest.raises(HardGateError):
        service.release(run_id, "S22014")
    with pytest.raises(JustificationRequiredError):
        service.approve_with_exception(run_id, "S22014", "ok")
    approved = service.approve_with_exception(run_id, "S22014", JUSTIFICATION)
    assert approved.workflow_state is WorkflowState.APPROVED_WITH_EXCEPTION
    assert service.workflow(GDSN).history(run_id)[-1].justification == JUSTIFICATION


def test_terminal_state_rejects_further_actions(
    service: GatekeeperService, clean_run: RunSummary
) -> None:
    service.release(clean_run.run.run_id, CHECKER)
    with pytest.raises(InvalidTransitionError):
        service.release(clean_run.run.run_id, CHECKER)
    with pytest.raises(InvalidTransitionError):
        service.approve_with_exception(clean_run.run.run_id, CHECKER, JUSTIFICATION)


# -- hash chain ----------------------------------------------------------------------------


def test_every_workflow_event_is_bound_to_the_audit_chain(
    service: GatekeeperService, clean_run: RunSummary
) -> None:
    service.release(clean_run.run.run_id, CHECKER)
    audit = {e.event_hash: e for e in service.store.fetch_audit_events(clean_run.run.run_id)}
    for event in service.workflow(FIN).history(clean_run.run.run_id):
        assert audit[event.audit_event_hash].event_type == f"WORKFLOW_{event.action.value}"
    verification = service.verify_audit_chain()
    assert verification.valid
    assert verification.events_checked == 4  # validation + OPEN + SUBMIT + RELEASE


def test_payload_tampering_is_detected(service: GatekeeperService, clean_run: RunSummary) -> None:
    service.release(clean_run.run.run_id, CHECKER)
    service.store.connection.execute(
        "UPDATE audit_log SET payload_json = ? WHERE seq = ?",
        ['{"to_state":"RELEASED","tampered":true}', 2],
    )
    verification = service.verify_audit_chain()
    assert not verification.valid
    assert verification.broken_at_seq == 2
    assert "stored hash" in (verification.reason or "")


def test_rehashed_tampering_breaks_the_successor_link(
    service: GatekeeperService, clean_run: RunSummary
) -> None:
    service.release(clean_run.run.run_id, CHECKER)
    row = service.store.query(
        "SELECT seq, event_id, run_id, event_type, actor_id, created_at, prev_hash "
        "FROM audit_log WHERE seq = 2"
    )[0]
    forged_payload = '{"forged":true}'
    forged_hash = compute_event_hash(
        seq=int(row[0]),
        event_id=str(row[1]),
        run_id=str(row[2]),
        event_type=str(row[3]),
        actor_id="U99999",
        payload_json=forged_payload,
        created_at=str(row[5]),
        prev_hash=str(row[6]),
    )
    service.store.connection.execute(
        "UPDATE audit_log SET actor_id = ?, payload_json = ?, event_hash = ? WHERE seq = 2",
        ["U99999", forged_payload, forged_hash],
    )
    verification = service.verify_audit_chain()
    assert not verification.valid
    assert verification.broken_at_seq == 3
    assert "prev_hash" in (verification.reason or "")


def test_deleted_event_is_detected_as_sequence_gap(
    service: GatekeeperService, clean_run: RunSummary
) -> None:
    service.store.connection.execute("DELETE FROM audit_log WHERE seq = 2")
    verification = service.verify_audit_chain()
    assert not verification.valid
    assert verification.broken_at_seq == 3
    assert "sequence gap" in (verification.reason or "")


def test_truncation_is_detected_against_anchored_head(
    service: GatekeeperService, clean_run: RunSummary
) -> None:
    anchored_head = service.verify_audit_chain().head_hash
    last_seq = service.store.query("SELECT MAX(seq) FROM audit_log")[0][0]
    service.store.connection.execute("DELETE FROM audit_log WHERE seq = ?", [last_seq])
    assert service.verify_audit_chain().valid  # undetectable without an external anchor
    verification = service.verify_audit_chain(expected_head_hash=anchored_head)
    assert not verification.valid
    assert "anchored" in (verification.reason or "")
