from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from gatekeeper.models import (
    Finding,
    GateDecision,
    PackId,
    RunSummary,
    Severity,
    SkuListing,
)
from gatekeeper.rules.travel_retail_mdm import assess_class3, gs1_check_digit, is_valid_gtin
from gatekeeper.service import GatekeeperService

GDSN = PackId.TRAVEL_RETAIL_GDSN
B = Severity.BLOCKER
W = Severity.WARNING


@pytest.fixture
def summary(service: GatekeeperService) -> RunSummary:
    return service.validate_sample(GDSN)


@pytest.fixture
def dg_config(service: GatekeeperService) -> Any:
    return service.engine.config(GDSN).data["dangerous_goods"]


def by_id(summary: RunSummary) -> dict[str, Finding]:
    return {f.finding_id: f for f in summary.findings}


# -- GS1 Modulo-10 -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "check_digit"),
    [
        ("400638133393", 1),  # EAN-13 4006381333931
        ("03600029145", 2),  # UPC-A 036000291452
        ("0952010100011", 8),  # GTIN-14 09520101000118 (GS1 prefix 952: demonstration range)
        ("1952010100011", 5),  # case-level variant of the same item, indicator digit 1
    ],
)
def test_gs1_check_digit_known_vectors(body: str, check_digit: int) -> None:
    assert gs1_check_digit(body) == check_digit


@pytest.mark.parametrize(
    ("gtin", "valid"),
    [
        ("09520101000118", True),
        ("09520101000119", False),
        ("0952010100011", False),
        ("0952010100011X", False),
        ("", False),
    ],
)
def test_gtin14_validation(gtin: str, valid: bool) -> None:
    assert is_valid_gtin(gtin) is valid


def test_check_digit_rejects_non_numeric_body() -> None:
    with pytest.raises(ValueError, match="digits only"):
        gs1_check_digit("95201A")


# -- sample assortment -----------------------------------------------------------------------


def test_sample_assortment_is_blocked(summary: RunSummary) -> None:
    assert summary.run.record_count == 40
    assert summary.run.gate_decision is GateDecision.BLOCKED
    assert len(summary.findings) == 24
    assert summary.run.blocker_count == 16
    assert summary.run.warning_count == 8


@pytest.mark.parametrize(
    ("finding_id", "severity"),
    [
        ("TR-GTIN-001:UNIT_GTIN_CHECK_DIGIT:S-10004", B),
        ("TR-GTIN-001:UNIT_GTIN_CHECK_DIGIT:S-30004", B),
        ("TR-GTIN-001:CASE_GTIN_CHECK_DIGIT:S-10007", B),
        ("TR-GTIN-002:UNIT_GTIN_DUPLICATE:09520103000352", B),
        ("TR-MDM-001:GOLDEN_RECORD_CONFLICT:S-10002", B),
        ("TR-DG-001:DG_FLASHPOINT_MISSING:S-10013", B),
        ("TR-DG-001:DG_FLASHPOINT_MISSING:S-10014", B),
        ("TR-DG-001:DG_PACKING_GROUP_MISMATCH:S-10015", B),
        ("TR-DG-001:DG_SDS_MISSING:S-10016", W),
        ("TR-DG-001:DG_REGULATION_SCOPE:S-10016", W),
        ("TR-DG-001:DG_OVER_CLASSIFIED:S-20008", W),
        ("TR-HIER-001:UNIT_GROSS_BELOW_NET:S-20006", B),
        ("TR-HIER-001:CASE_WEIGHT_BELOW_CONTENTS:S-20007", B),
        ("TR-HIER-002:CASE_VOLUME_INSUFFICIENT:S-30005", B),
        ("TR-HIER-002:CASE_FILL_RATIO_LOW:S-40003", W),
        ("TR-HIER-002:PALLET_HEIGHT_EXCEEDED:S-40003", W),
        ("TR-MKT-001:MARKET_NOT_AUTHORISED:L-0026", B),
        ("TR-MKT-001:SOLD_TO_BLOCKED:L-0028", B),
        ("TR-MKT-001:SOLD_TO_CATEGORY_RESTRICTED:L-0029", B),
        ("TR-MKT-001:DG_NOT_ACCEPTED_AT_SHIP_TO:L-0030", B),
        ("TR-MKT-001:SHIP_TO_NOT_LINKED_TO_SOLD_TO:L-0031", B),
        ("TR-CUS-001:HS_HEADING_MISMATCH:S-20008", W),
        ("TR-CUS-001:ORIGIN_MISSING:S-40003", W),
    ],
)
def test_planted_defect_is_detected(
    summary: RunSummary, finding_id: str, severity: Severity
) -> None:
    findings = by_id(summary)
    assert finding_id in findings
    assert findings[finding_id].severity is severity


def test_check_digit_finding_reports_expected_digit(summary: RunSummary) -> None:
    finding = by_id(summary)["TR-GTIN-001:UNIT_GTIN_CHECK_DIGIT:S-10004"]
    gtin = str(finding.details["gtin"])
    assert finding.details["expected_check_digit"] == gs1_check_digit(gtin[:-1])
    assert not is_valid_gtin(gtin)


def test_duplicate_gtin_names_both_owners(summary: RunSummary) -> None:
    finding = by_id(summary)["TR-GTIN-002:UNIT_GTIN_DUPLICATE:09520103000352"]
    assert finding.details["sku_ids"] == "S-20007,S-30005"


def test_golden_record_conflict_names_the_attribute(summary: RunSummary) -> None:
    finding = by_id(summary)["TR-MDM-001:GOLDEN_RECORD_CONFLICT:S-10002"]
    assert finding.attributes == ("unit_gross_weight_g",)


def test_low_alcohol_and_non_dg_listings_pass_where_dg_is_refused(summary: RunSummary) -> None:
    keys = {f.record_key for f in summary.findings}
    assert "L-0022" not in keys  # 18% ABV facial mist to an inflight Ship-To that refuses DG
    assert "L-0020" not in keys  # skincare to a Sold-To restricted for fragrance only
    assert "S-40001" not in keys  # 20% ABV hair mist stays below the screening threshold


def test_clean_listings_clear_the_gate(
    service: GatekeeperService, clean_travel_rows: list[dict[str, str]]
) -> None:
    summary = service.validate(GDSN, clean_travel_rows, maker_id="S11003")
    assert summary.findings == ()
    assert summary.run.gate_decision is GateDecision.CLEAR


# -- Class 3 screening ---------------------------------------------------------------------


@pytest.fixture
def fragrance(clean_travel_rows: list[dict[str, str]]) -> SkuListing:
    return SkuListing.model_validate(clean_travel_rows[0])


@pytest.mark.parametrize(
    ("abv", "flashpoint", "in_scope", "is_class3", "packing_group"),
    [
        ("82", "12", True, True, "II"),
        ("82", "22.9", True, True, "II"),
        ("82", "23", True, True, "III"),
        ("82", "60", True, True, "III"),
        ("82", "61", True, False, None),
        ("82", None, True, False, None),
        ("24", "36", False, False, None),
        ("0", "40", True, True, "III"),
        ("0", None, False, False, None),
    ],
)
def test_class3_screening_and_packing_group(
    fragrance: SkuListing,
    dg_config: Any,
    abv: str,
    flashpoint: str | None,
    in_scope: bool,
    is_class3: bool,
    packing_group: str | None,
) -> None:
    item = fragrance.model_copy(
        update={
            "alcohol_by_volume_pct": Decimal(abv),
            "flashpoint_c": None if flashpoint is None else Decimal(flashpoint),
        }
    )
    assessment = assess_class3(item, dg_config)
    assert assessment.in_scope is in_scope
    assert assessment.is_class3 is is_class3
    assert assessment.expected_packing_group == packing_group


def test_gtin_supplied_as_number_is_rejected_at_ingestion(
    service: GatekeeperService, clean_travel_rows: list[dict[str, str]]
) -> None:
    rows: list[dict[str, object]] = [dict(r) for r in clean_travel_rows[:2]]
    rows[0]["unit_gtin"] = 9520101000118  # leading zero lost by a numeric parser
    summary = service.validate(GDSN, rows, maker_id="S11003")
    finding = by_id(summary)["SCHEMA-001:CONTRACT_VIOLATION:L-0001"]
    assert finding.severity is B
    assert finding.attributes == ("unit_gtin",)


def test_norway_market_code_survives_yaml_parsing(service: GatekeeperService) -> None:
    locations = service.engine.config(GDSN).data["market_eligibility"]["ship_to_locations"]
    assert locations["OSL-T2-AS01"]["country"] == "NO"


def test_lineage_trace_for_flashpoint(service: GatekeeperService, summary: RunSummary) -> None:
    trace = service.trace_lineage(
        summary.run.run_id, "GS1_GDSN/BASE_UNIT_OR_EACH.flashPointTemperature"
    )
    assert {"TR-DG-001", "TR-MDM-001"} <= set(trace.controls)
    assert trace.open_findings_by_control["TR-DG-001"] == 6
