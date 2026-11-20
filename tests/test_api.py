from __future__ import annotations

from collections.abc import Iterator

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from gatekeeper.api.main import create_app
from gatekeeper.service import GatekeeperService

MAKER = "U20117"
CHECKER = "U30452"


@pytest.fixture
def client(service: GatekeeperService) -> Iterator[TestClient]:
    with TestClient(create_app(service)) as test_client:
        yield test_client


def _validate_sample(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/validate/finance_preclose_ics",
        json={"maker_id": MAKER, "use_synthetic_sample": True},
    )
    assert response.status_code == 200, response.text
    body: dict[str, object] = response.json()
    return body


def test_health_reports_packs_and_chain(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["audit_chain_valid"] is True
    assert body["packs"] == ["finance_preclose_ics", "travel_retail_gdsn"]
    assert body["advisor_mode"] == "DETERMINISTIC_FALLBACK"


def test_pack_catalogue_lists_rules(client: TestClient) -> None:
    packs = client.get("/packs").json()
    finance = next(p for p in packs if p["pack_id"] == "finance_preclose_ics")
    assert len(finance["rules"]) == 10
    assert all(rule["framework_refs"] for rule in finance["rules"])


def test_sample_validation_is_quarantined(client: TestClient) -> None:
    body = _validate_sample(client)
    run = body["run"]
    assert isinstance(run, dict)
    assert run["gate_decision"] == "BLOCKED"
    assert body["workflow_state"] == "QUARANTINED"
    quarantined = client.get("/quarantine", params={"pack_id": "finance_preclose_ics"}).json()
    assert run["run_id"] in [r["run_id"] for r in quarantined]


def test_self_approval_is_forbidden(client: TestClient) -> None:
    run = _validate_sample(client)["run"]
    assert isinstance(run, dict)
    response = client.post(
        "/approve",
        json={"run_id": run["run_id"], "checker_id": MAKER, "decision": "RELEASE"},
    )
    assert response.status_code == 403
    assert response.json()["error"] == "SelfApprovalError"


def test_blocker_override_is_a_conflict(client: TestClient) -> None:
    run = _validate_sample(client)["run"]
    assert isinstance(run, dict)
    response = client.post(
        "/approve",
        json={
            "run_id": run["run_id"],
            "checker_id": CHECKER,
            "decision": "APPROVE_WITH_EXCEPTION",
            "justification": "Business insists on releasing before the cut-off.",
        },
    )
    assert response.status_code == 409
    assert response.json()["error"] == "HardGateError"


def test_clean_records_payload_can_be_released(
    client: TestClient, clean_finance_rows: list[dict[str, str]]
) -> None:
    response = client.post(
        "/validate/finance_preclose_ics",
        json={"maker_id": MAKER, "records": clean_finance_rows, "source_name": "erp-extract"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["run"]["gate_decision"] == "CLEAR"
    released = client.post(
        "/approve",
        json={"run_id": body["run"]["run_id"], "checker_id": CHECKER, "decision": "RELEASE"},
    )
    assert released.status_code == 200
    assert released.json()["workflow_state"] == "RELEASED"


def test_request_validation_errors(client: TestClient) -> None:
    assert client.post("/validate/general_ledger", json={"maker_id": MAKER}).status_code == 422
    assert (
        client.post("/validate/travel_retail_gdsn", json={"maker_id": "S11003"}).status_code == 422
    )
    assert client.get("/runs/UNKNOWN-RUN").status_code == 404


def test_lineage_and_evidence_endpoints(client: TestClient) -> None:
    run = _validate_sample(client)["run"]
    assert isinstance(run, dict)
    run_id = run["run_id"]
    targets = client.get(f"/lineage/{run_id}/targets").json()
    assert "SAP_S4HANA/ACDOCA.KSL" in targets
    trace = client.get(f"/lineage/{run_id}", params={"target": "SAP_S4HANA/ACDOCA.KSL"}).json()
    assert "FIN-FX-001" in trace["controls"]
    evidence = client.get(f"/evidence/{run_id}").json()
    assert len(evidence["content_sha256"]) == 64
    assert evidence["run"]["run_id"] == run_id
    summary = client.get(f"/evidence/{run_id}/summary.md")
    assert summary.status_code == 200
    assert run_id in summary.text
    advice = client.get(f"/advice/{run_id}").json()
    assert all(item["gate_effect"] == "NONE" for item in advice)
    assert client.get("/audit/verify").json()["valid"] is True


def test_openapi_schema_exposes_contract(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    for path in ("/validate/{pack_id}", "/quarantine", "/approve", "/evidence/{run_id}"):
        assert path in paths
