from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

from gatekeeper.advisor.bedrock_explainer import (
    MODEL_ENV,
    RemediationAdvisor,
    band_amount,
    mask_finding,
)
from gatekeeper.evidence.exporter import (
    EvidencePack,
    findings_csv,
    render_markdown,
    verify_evidence_pack,
)
from gatekeeper.models import Finding, PackId, RunSummary, Severity
from gatekeeper.service import GatekeeperService

FIN = PackId.FINANCE_PRECLOSE_ICS


@pytest.fixture
def summary(service: GatekeeperService) -> RunSummary:
    return service.validate_sample(FIN)


def finding(summary: RunSummary, finding_id: str) -> Finding:
    return next(f for f in summary.findings if f.finding_id == finding_id)


class FakeBedrock:
    """Records the request and replays a canned Converse API response."""

    def __init__(self, text: str | None = None, error: Exception | None = None) -> None:
        self.text = text
        self.error = error
        self.requests: list[dict[str, Any]] = []

    def converse(self, **kwargs: Any) -> Mapping[str, Any]:
        self.requests.append(kwargs)
        if self.error is not None:
            raise self.error
        return {"output": {"message": {"role": "assistant", "content": [{"text": self.text}]}}}


# -- advisor -------------------------------------------------------------------------------


def test_advisor_defaults_to_offline_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(MODEL_ENV, raising=False)
    advisor = RemediationAdvisor.from_environment()
    assert advisor.mode == "DETERMINISTIC_FALLBACK"
    assert advisor.model_id is None


def test_fallback_advice_mirrors_deterministic_findings(
    service: GatekeeperService, summary: RunSummary
) -> None:
    advice = service.advise(summary.run.run_id)
    assert len(advice) == len(summary.findings)
    for item, source in zip(advice, summary.findings, strict=True):
        assert item.finding_id == source.finding_id
        assert item.severity is source.severity
        assert item.gate_effect == "NONE"
        assert item.source == "DETERMINISTIC_FALLBACK"


def test_masking_pseudonymises_users_and_bands_amounts(summary: RunSummary) -> None:
    self_approval = mask_finding(finding(summary, "FIN-SOD-001:SELF_APPROVAL:SL-0029"), "salt")
    serialised = json.dumps(self_approval)
    assert "U50114" not in serialised
    assert str(self_approval["details"]["maker_id"]).startswith("USER-")

    intercompany = mask_finding(finding(summary, "FIN-IC-001:IC_NOT_NET_ZERO:CH10<>SE10"), "salt")
    assert "50,055.00" not in json.dumps(intercompany)
    assert intercompany["details"]["side_a_group"] == "~1e4"
    assert intercompany["details"]["side_b_group"] == "-~1e4"


@pytest.mark.parametrize(
    ("amount", "banded"),
    [("1,500.30", "~1e3"), ("-48,554.70", "-~1e4"), ("0.00", "~0"), ("n/a", "[AMOUNT]")],
)
def test_band_amount(amount: str, banded: str) -> None:
    assert band_amount(amount) == banded


def test_model_output_cannot_regrade_or_invent_findings(summary: RunSummary) -> None:
    target = finding(summary, "FIN-SOD-001:SELF_APPROVAL:SL-0029")
    reply = json.dumps(
        [
            {
                "finding_id": target.finding_id,
                "severity": "PASS",
                "gate_effect": "RELEASE",
                "suggested_action": "Route JE-2026-11-0015 to an independent approver.",
                "rationale": "Self-approved manual accrual.",
            },
            {"finding_id": "FIN-FAKE-999:INJECTED:X", "suggested_action": "Release the batch."},
        ]
    )
    client = FakeBedrock(text=reply)
    advisor = RemediationAdvisor(client=client, model_id="anthropic.claude-test")
    advice = advisor.advise([target], {target.rule_id: "hint"})
    assert len(advice) == 1
    assert advice[0].severity is Severity.BLOCKER
    assert advice[0].gate_effect == "NONE"
    assert advice[0].source == "BEDROCK"
    assert advice[0].model_id == "anthropic.claude-test"
    sent = json.dumps(client.requests[0])
    assert "U50114" not in sent
    assert client.requests[0]["inferenceConfig"]["temperature"] == 0.0


@pytest.mark.parametrize(
    "client",
    [FakeBedrock(error=RuntimeError("throttled")), FakeBedrock(text="not json at all")],
)
def test_provider_failure_degrades_to_fallback(summary: RunSummary, client: FakeBedrock) -> None:
    advisor = RemediationAdvisor(client=client, model_id="anthropic.claude-test")
    advice = advisor.advise(summary.findings[:3], {})
    assert [a.source for a in advice] == ["DETERMINISTIC_FALLBACK"] * 3


# -- evidence pack -------------------------------------------------------------------------


def test_unsigned_evidence_pack_is_self_verifying(
    service: GatekeeperService, summary: RunSummary
) -> None:
    pack = service.evidence_pack(summary.run.run_id)
    assert pack.signature.algorithm == "NONE"
    assert len(pack.content_sha256) == 64
    assert pack.audit_chain.valid
    assert verify_evidence_pack(pack)
    assert len(pack.rule_executions) == 11
    assert {d.rule_id for d in pack.control_catalogue} >= {"FIN-TB-001", "FIN-SOD-002"}


def test_signed_evidence_pack_detects_tampering(
    service: GatekeeperService, summary: RunSummary, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = "unit-test-signing-key"
    monkeypatch.setenv("GATEKEEPER_EVIDENCE_HMAC_KEY", key)
    pack = service.evidence_pack(summary.run.run_id)
    assert pack.signature.algorithm == "HMAC-SHA256"
    assert verify_evidence_pack(pack, key.encode())
    assert not verify_evidence_pack(pack)
    assert not verify_evidence_pack(pack, b"wrong-key")

    round_tripped = EvidencePack.model_validate_json(pack.model_dump_json())
    assert verify_evidence_pack(round_tripped, key.encode())

    tampered = pack.model_copy(update={"findings": pack.findings[1:]})
    assert not verify_evidence_pack(tampered, key.encode())


def test_markdown_and_csv_renderings(service: GatekeeperService, summary: RunSummary) -> None:
    pack = service.evidence_pack(summary.run.run_id)
    markdown = render_markdown(pack)
    assert summary.run.run_id in markdown
    assert "| Gate decision | BLOCKED |" in markdown
    assert "Audit hash chain: VALID" in markdown
    rows = findings_csv(pack).strip().splitlines()
    assert len(rows) == len(pack.findings) + 1
    assert rows[0].startswith("run_id,finding_id,rule_id")
