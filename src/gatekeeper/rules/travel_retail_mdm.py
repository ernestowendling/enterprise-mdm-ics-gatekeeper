"""Pack B: travel retail GS1/GDSN product master data gatekeeper.

Validates prestige beauty trade items and their duty-free listings before they are published
to the GDSN data pool or released to Sold-To / Ship-To customers: GS1 key integrity, Class 3
dangerous goods classification of alcohol-based perfumery (UN1266), packaging hierarchy
physics and market eligibility.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, ClassVar

from gatekeeper.models import Finding, FindingScope, PackId, Severity, SkuListing
from gatekeeper.rules.base import (
    LineageSpec,
    RecordRule,
    Rule,
    RuleContext,
    RulePack,
    SqlRule,
    StagingSpec,
    register_pack,
    to_decimal,
)

Ctx = RuleContext[SkuListing]

GTIN_LENGTH = 14

# ---------------------------------------------------------------------------
# GS1 key arithmetic
# ---------------------------------------------------------------------------


def gs1_check_digit(body: str) -> int:
    """GS1 Modulo-10 check digit for any GS1 key body (GTIN-8/12/13/14, GLN, SSCC).

    Weights 3 and 1 alternate from the rightmost digit of the body, starting with 3.
    """
    if not body.isdigit():
        raise ValueError("GS1 key body must contain digits only")
    total = sum(
        int(digit) * (3 if index % 2 == 0 else 1) for index, digit in enumerate(reversed(body))
    )
    return (10 - total % 10) % 10


def is_valid_gtin(value: str, length: int = GTIN_LENGTH) -> bool:
    """True when ``value`` has the expected length, is numeric and carries a valid check digit."""
    if len(value) != length or not value.isdigit():
        return False
    return gs1_check_digit(value[:-1]) == int(value[-1])


# ---------------------------------------------------------------------------
# Dangerous goods screening
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Class3Assessment:
    """Deterministic Class 3 (flammable liquid) screening outcome for a trade item."""

    in_scope: bool
    reason: str
    flashpoint_known: bool
    is_class3: bool
    expected_packing_group: str | None


def assess_class3(record: SkuListing, dg_cfg: Mapping[str, Any]) -> Class3Assessment:
    """Screen a trade item for Class 3 using the configured thresholds.

    Alcohol-based formulations above the screening threshold (ABV) are in scope; aqueous
    solutions at or below it are treated as outside scope. Non-alcoholic formulations are in
    scope when a flashpoint at or below the flammable-liquid limit is declared. Packing group
    follows the flashpoint criteria for Class 3 (II below 23 °C, III from 23 °C up to the
    limit), assuming an initial boiling point above 35 °C as is the case for perfumery.
    """
    threshold = to_decimal(dg_cfg["alcohol_screening_threshold_pct_abv"])
    max_flashpoint = to_decimal(dg_cfg["flammable_liquid_max_flashpoint_c"])
    pg2_below = to_decimal(dg_cfg["packing_group_ii_below_flashpoint_c"])
    abv = record.alcohol_by_volume_pct
    flashpoint = record.flashpoint_c
    if abv > threshold:
        reason = f"ABV {abv}% exceeds the {threshold}% screening threshold"
    elif abv == 0 and flashpoint is not None and flashpoint <= max_flashpoint:
        reason = f"declared flashpoint {flashpoint} °C is at or below {max_flashpoint} °C"
    else:
        return Class3Assessment(False, "outside Class 3 screening scope", True, False, None)
    if flashpoint is None:
        return Class3Assessment(True, reason, False, False, None)
    if flashpoint > max_flashpoint:
        return Class3Assessment(True, reason, True, False, None)
    packing_group = "II" if flashpoint < pg2_below else "III"
    return Class3Assessment(True, reason, True, True, packing_group)


def _volume_mm3(height: Decimal, width: Decimal, depth: Decimal) -> Decimal:
    return height * width * depth


# ---------------------------------------------------------------------------
# Rule styles
# ---------------------------------------------------------------------------


class SkuLevelRule(RecordRule[SkuListing]):
    """Trade item master data rule evaluated once per SKU (first listing in the batch).

    Divergent master attributes across listings of one SKU are caught by TR-MDM-001, so the
    first listing is representative whenever that control passes.
    """

    def evaluate(self, ctx: Ctx) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for record in ctx.records:
            if record.sku_id in seen:
                continue
            seen.add(record.sku_id)
            findings.extend(self.check(record, ctx))
        return findings


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


class GtinCheckDigitRule(SkuLevelRule):
    rule_id = "TR-GTIN-001"
    title = "GTIN-14 format, indicator and Modulo-10 check digit"
    control_objective = (
        "Consumer unit and case GTINs are 14-digit GS1 keys with a valid check digit and a "
        "packaging indicator consistent with their hierarchy level."
    )
    framework_refs = ("GS1 General Specifications 7.9", "GS1 GDSN 3.1 Validation Rules")
    input_attributes = ("unit_gtin", "case_gtin")
    remediation_hint = (
        "Re-issue the GTIN from the brand's GS1 Company Prefix allocation (never hand-type the "
        "check digit) and correct it in the PIM before republishing to the data pool."
    )

    def check(self, record: SkuListing, ctx: Ctx) -> list[Finding]:
        gtin_cfg: Mapping[str, Any] = ctx.config["gtin"]
        findings: list[Finding] = []
        levels = (
            ("UNIT", "unit_gtin", record.unit_gtin, gtin_cfg["allowed_unit_indicators"]),
            ("CASE", "case_gtin", record.case_gtin, gtin_cfg["allowed_case_indicators"]),
        )
        for level, attribute, value, indicators in levels:
            if len(value) != GTIN_LENGTH or not value.isdigit():
                findings.append(
                    self.finding(
                        ctx,
                        check_code=f"{level}_GTIN_FORMAT",
                        severity=Severity.BLOCKER,
                        record_key=record.sku_id,
                        message=f"{attribute} '{value}' is not a 14-digit numeric GTIN",
                        attributes=(attribute,),
                    )
                )
                continue
            expected = gs1_check_digit(value[:-1])
            if expected != int(value[-1]):
                findings.append(
                    self.finding(
                        ctx,
                        check_code=f"{level}_GTIN_CHECK_DIGIT",
                        severity=Severity.BLOCKER,
                        record_key=record.sku_id,
                        message=(
                            f"{attribute} {value} has check digit {value[-1]}, "
                            f"Modulo-10 requires {expected}"
                        ),
                        attributes=(attribute,),
                        details={"gtin": value, "expected_check_digit": expected},
                    )
                )
            if value[0] not in {str(i) for i in indicators}:
                findings.append(
                    self.finding(
                        ctx,
                        check_code=f"{level}_GTIN_INDICATOR",
                        severity=Severity.BLOCKER,
                        record_key=record.sku_id,
                        message=(
                            f"{attribute} {value} uses indicator digit {value[0]}, not "
                            f"permitted for the {level.lower()} level"
                        ),
                        attributes=(attribute,),
                    )
                )
        if record.unit_gtin == record.case_gtin:
            findings.append(
                self.finding(
                    ctx,
                    check_code="HIERARCHY_GTIN_REUSED",
                    severity=Severity.BLOCKER,
                    record_key=record.sku_id,
                    message="Case and consumer unit share the same GTIN",
                    attributes=("unit_gtin", "case_gtin"),
                )
            )
        return findings


class GtinUniquenessRule(SqlRule[SkuListing]):
    rule_id = "TR-GTIN-002"
    title = "GTIN uniqueness across the assortment"
    control_objective = "A GTIN identifies exactly one trade item (SKU) at each hierarchy level."
    framework_refs = ("GS1 GTIN Management Standard", "GS1 GDSN 3.1 Validation Rules")
    input_attributes = ("sku_id", "unit_gtin", "case_gtin")
    remediation_hint = (
        "Determine which SKU legitimately owns the GTIN, allocate a new GTIN to the other "
        "and merge or retire any duplicate item record in the PIM."
    )

    def evaluate(self, ctx: Ctx) -> list[Finding]:
        findings: list[Finding] = []
        for attribute in ("unit_gtin", "case_gtin"):
            rows = ctx.store.query(
                f"""
                SELECT DISTINCT {attribute}, sku_id
                FROM {ctx.staging_table}
                WHERE run_id = ?
                  AND {attribute} IN (
                      SELECT {attribute}
                      FROM {ctx.staging_table}
                      WHERE run_id = ?
                      GROUP BY {attribute}
                      HAVING COUNT(DISTINCT sku_id) > 1
                  )
                ORDER BY {attribute}, sku_id
                """,
                [ctx.run_id, ctx.run_id],
            )
            owners: dict[str, list[str]] = {}
            for gtin, sku in rows:
                owners.setdefault(str(gtin), []).append(str(sku))
            for gtin, skus in owners.items():
                findings.append(
                    self.finding(
                        ctx,
                        check_code=f"{attribute.upper()}_DUPLICATE",
                        severity=Severity.BLOCKER,
                        record_key=gtin,
                        message=f"{attribute} {gtin} is assigned to {len(skus)} SKUs: "
                        + ", ".join(skus),
                        attributes=(attribute, "sku_id"),
                        details={"sku_ids": ",".join(skus)},
                        scope=FindingScope.AGGREGATE,
                    )
                )
        return findings


class GoldenRecordConsistencyRule(SqlRule[SkuListing]):
    rule_id = "TR-MDM-001"
    title = "Golden record consistency across listings"
    control_objective = (
        "Master attributes of a trade item are identical in every Sold-To / Ship-To listing "
        "(single version of the truth)."
    )
    framework_refs = ("GS1 GDSN 3.1 data synchronisation", "DAMA-DMBOK MDM")
    input_attributes = (
        "sku_id",
        "unit_gtin",
        "case_gtin",
        "unit_net_weight_g",
        "unit_gross_weight_g",
        "units_per_case",
        "case_gross_weight_kg",
        "alcohol_by_volume_pct",
        "flashpoint_c",
        "un_number",
        "packing_group",
        "hs_code",
    )
    remediation_hint = (
        "Resolve the conflicting values against the brand's specification sheet, correct the "
        "golden record in the PIM and let listings inherit rather than override it."
    )

    golden_attributes: ClassVar[tuple[str, ...]] = (
        "brand",
        "description",
        "category",
        "unit_gtin",
        "case_gtin",
        "unit_net_weight_g",
        "unit_gross_weight_g",
        "units_per_case",
        "case_gross_weight_kg",
        "alcohol_by_volume_pct",
        "flashpoint_c",
        "un_number",
        "packing_group",
        "hs_code",
        "country_of_origin",
    )

    def evaluate(self, ctx: Ctx) -> list[Finding]:
        counts = ",\n".join(
            f"COUNT(DISTINCT COALESCE(CAST({a} AS VARCHAR), '<null>')) AS n_{a}"
            for a in self.golden_attributes
        )
        rows = ctx.store.query(
            f"""
            SELECT sku_id, COUNT(*) AS listings,
                   {counts}
            FROM {ctx.staging_table}
            WHERE run_id = ?
            GROUP BY sku_id
            HAVING COUNT(*) > 1
            ORDER BY sku_id
            """,
            [ctx.run_id],
        )
        findings: list[Finding] = []
        for row in rows:
            sku_id, listings, *distinct_counts = row
            conflicting = [
                attribute
                for attribute, count in zip(self.golden_attributes, distinct_counts, strict=True)
                if int(count) > 1
            ]
            if conflicting:
                findings.append(
                    self.finding(
                        ctx,
                        check_code="GOLDEN_RECORD_CONFLICT",
                        severity=Severity.BLOCKER,
                        record_key=str(sku_id),
                        message=(
                            f"SKU {sku_id} has conflicting master values across {listings} "
                            f"listings: {', '.join(conflicting)}"
                        ),
                        attributes=tuple(conflicting),
                        details={"listings": int(listings), "attributes": ",".join(conflicting)},
                        scope=FindingScope.AGGREGATE,
                    )
                )
        return findings


class DangerousGoodsRule(SkuLevelRule):
    rule_id = "TR-DG-001"
    title = "UN1266 perfumery Class 3 classification completeness"
    control_objective = (
        "Alcohol-based perfumery in Class 3 scope carries a flashpoint, the expected UN number, "
        "class and packing group, an SDS reference and IATA/IMDG regulation codes before air "
        "or sea shipment."
    )
    framework_refs = (
        "IATA DGR Class 3",
        "IMDG Code Class 3",
        "UN Model Regulations 2.3.2",
        "GS1 GDSN 3.1 dangerous goods attributes",
    )
    input_attributes = (
        "category",
        "alcohol_by_volume_pct",
        "flashpoint_c",
        "un_number",
        "dg_class",
        "packing_group",
        "dg_regulations",
        "sds_reference",
    )
    remediation_hint = (
        "Obtain the closed-cup flashpoint from the supplier SDS, have the DG-qualified "
        "function confirm UN number and packing group, and publish the dangerous goods "
        "attributes before the item is released for air freight."
    )

    def check(self, record: SkuListing, ctx: Ctx) -> list[Finding]:
        dg_cfg: Mapping[str, Any] = ctx.config["dangerous_goods"]
        assessment = assess_class3(record, dg_cfg)
        key = record.sku_id
        if not assessment.in_scope:
            declared = [v for v in (record.un_number, record.dg_class, record.packing_group) if v]
            if declared:
                return [
                    self.finding(
                        ctx,
                        check_code="DG_OVER_CLASSIFIED",
                        severity=Severity.WARNING,
                        record_key=key,
                        message=(
                            "Dangerous goods attributes declared for an item outside Class 3 "
                            f"screening scope ({', '.join(declared)}); causes unnecessary DG "
                            "handling surcharges"
                        ),
                        attributes=("un_number", "dg_class", "packing_group"),
                    )
                ]
            return []
        if not assessment.flashpoint_known:
            return [
                self.finding(
                    ctx,
                    check_code="DG_FLASHPOINT_MISSING",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=(
                        f"{assessment.reason}; flashpoint is required to confirm Class 3 and "
                        "derive the packing group"
                    ),
                    attributes=("alcohol_by_volume_pct", "flashpoint_c"),
                    details={"alcohol_by_volume_pct": str(record.alcohol_by_volume_pct)},
                )
            ]
        if not assessment.is_class3:
            return [
                self.finding(
                    ctx,
                    check_code="DG_FLASHPOINT_IMPLAUSIBLE",
                    severity=Severity.WARNING,
                    record_key=key,
                    message=(
                        f"{assessment.reason} but declared flashpoint {record.flashpoint_c} °C "
                        "is above the Class 3 limit; verify the SDS"
                    ),
                    attributes=("alcohol_by_volume_pct", "flashpoint_c"),
                )
            ]
        findings: list[Finding] = []
        expected_un = dg_cfg["expected_un_number_by_category"].get(record.category)
        if record.un_number is None:
            findings.append(
                self.finding(
                    ctx,
                    check_code="DG_UN_NUMBER_MISSING",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=f"Class 3 item has no UN number (expected {expected_un or 'one'})",
                    attributes=("un_number",),
                )
            )
        elif expected_un is not None and record.un_number != expected_un:
            findings.append(
                self.finding(
                    ctx,
                    check_code="DG_UN_NUMBER_MISMATCH",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=f"UN number {record.un_number} declared, {expected_un} expected",
                    attributes=("un_number", "category"),
                )
            )
        expected_class = str(dg_cfg["expected_class"])
        if record.dg_class != expected_class:
            findings.append(
                self.finding(
                    ctx,
                    check_code="DG_CLASS_MISMATCH",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=(
                        f"Hazard class {record.dg_class or 'missing'}, expected {expected_class}"
                    ),
                    attributes=("dg_class",),
                )
            )
        if record.packing_group is None:
            findings.append(
                self.finding(
                    ctx,
                    check_code="DG_PACKING_GROUP_MISSING",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=(
                        f"Packing group missing; flashpoint {record.flashpoint_c} °C requires "
                        f"PG {assessment.expected_packing_group}"
                    ),
                    attributes=("packing_group", "flashpoint_c"),
                )
            )
        elif record.packing_group != assessment.expected_packing_group:
            findings.append(
                self.finding(
                    ctx,
                    check_code="DG_PACKING_GROUP_MISMATCH",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=(
                        f"Packing group {record.packing_group} declared; flashpoint "
                        f"{record.flashpoint_c} °C requires PG {assessment.expected_packing_group}"
                    ),
                    attributes=("packing_group", "flashpoint_c"),
                    details={"expected_packing_group": assessment.expected_packing_group},
                )
            )
        required = {str(r) for r in dg_cfg["required_regulations"]}
        missing = sorted(required - set(record.dg_regulations))
        if missing:
            findings.append(
                self.finding(
                    ctx,
                    check_code="DG_REGULATION_SCOPE",
                    severity=Severity.WARNING,
                    record_key=key,
                    message=f"Regulation codes missing for transport modes: {', '.join(missing)}",
                    attributes=("dg_regulations",),
                )
            )
        if record.sds_reference is None:
            findings.append(
                self.finding(
                    ctx,
                    check_code="DG_SDS_MISSING",
                    severity=Severity.WARNING,
                    record_key=key,
                    message="Class 3 item has no safety data sheet reference",
                    attributes=("sds_reference",),
                )
            )
        return findings


class PackagingWeightRule(SkuLevelRule):
    rule_id = "TR-HIER-001"
    title = "Packaging hierarchy weight integrity (unit, case, pallet)"
    control_objective = (
        "Gross weight is never below net weight, and case and pallet gross weights are "
        "consistent with the quantity of next lower level times its gross weight."
    )
    framework_refs = ("GS1 Package Measurement Rules", "GS1 GDSN 3.1 Validation Rules")
    input_attributes = (
        "unit_net_weight_g",
        "unit_gross_weight_g",
        "units_per_case",
        "case_gross_weight_kg",
        "cases_per_pallet",
        "pallet_gross_weight_kg",
    )
    remediation_hint = (
        "Re-measure the packaging level under GS1 Package Measurement Rules and correct the "
        "weight in the PIM; carrier charges and DG quantity limits depend on it."
    )

    def check(self, record: SkuListing, ctx: Ctx) -> list[Finding]:
        cfg: Mapping[str, Any] = ctx.config["packaging"]
        key = record.sku_id
        findings: list[Finding] = []
        if record.unit_gross_weight_g < record.unit_net_weight_g:
            findings.append(
                self.finding(
                    ctx,
                    check_code="UNIT_GROSS_BELOW_NET",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=(
                        f"Unit gross weight {record.unit_gross_weight_g} g is below net weight "
                        f"{record.unit_net_weight_g} g"
                    ),
                    attributes=("unit_gross_weight_g", "unit_net_weight_g"),
                )
            )
        contents_kg = record.units_per_case * record.unit_gross_weight_g / 1000
        lower = contents_kg * (1 - to_decimal(cfg["case_weight_tolerance_pct"]) / 100)
        upper = contents_kg * (1 + to_decimal(cfg["case_overhead_max_pct"]) / 100)
        if record.case_gross_weight_kg < lower:
            findings.append(
                self.finding(
                    ctx,
                    check_code="CASE_WEIGHT_BELOW_CONTENTS",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=(
                        f"Case gross weight {record.case_gross_weight_kg} kg is below its contents "
                        f"({record.units_per_case} x {record.unit_gross_weight_g} g = "
                        f"{contents_kg.quantize(Decimal('0.001'))} kg)"
                    ),
                    attributes=("case_gross_weight_kg", "units_per_case", "unit_gross_weight_g"),
                    details={"contents_kg": str(contents_kg.quantize(Decimal("0.001")))},
                )
            )
        elif record.case_gross_weight_kg > upper:
            findings.append(
                self.finding(
                    ctx,
                    check_code="CASE_WEIGHT_OVERHEAD",
                    severity=Severity.WARNING,
                    record_key=key,
                    message=(
                        f"Case gross weight {record.case_gross_weight_kg} kg exceeds contents "
                        f"by more than {cfg['case_overhead_max_pct']}%"
                    ),
                    attributes=("case_gross_weight_kg", "units_per_case", "unit_gross_weight_g"),
                )
            )
        pallet_contents = record.cases_per_pallet * record.case_gross_weight_kg
        expected_pallet = pallet_contents + to_decimal(cfg["pallet_tare_kg"])
        deviation_pct = abs(record.pallet_gross_weight_kg - expected_pallet) / expected_pallet * 100
        if record.pallet_gross_weight_kg < pallet_contents:
            findings.append(
                self.finding(
                    ctx,
                    check_code="PALLET_WEIGHT_BELOW_CONTENTS",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=(
                        f"Pallet gross weight {record.pallet_gross_weight_kg} kg is below its "
                        f"{record.cases_per_pallet} cases ({pallet_contents} kg)"
                    ),
                    attributes=("pallet_gross_weight_kg", "cases_per_pallet"),
                )
            )
        elif deviation_pct > to_decimal(cfg["pallet_weight_tolerance_pct"]):
            findings.append(
                self.finding(
                    ctx,
                    check_code="PALLET_WEIGHT_DEVIATION",
                    severity=Severity.WARNING,
                    record_key=key,
                    message=(
                        f"Pallet gross weight {record.pallet_gross_weight_kg} kg deviates "
                        f"{deviation_pct.quantize(Decimal('0.1'))}% from expected "
                        f"{expected_pallet.quantize(Decimal('0.1'))} kg"
                    ),
                    attributes=(
                        "pallet_gross_weight_kg",
                        "cases_per_pallet",
                        "case_gross_weight_kg",
                    ),
                )
            )
        return findings


class PackagingDimensionRule(SkuLevelRule):
    rule_id = "TR-HIER-002"
    title = "Packaging hierarchy dimensional integrity"
    control_objective = (
        "A case can physically hold its consumer units without excessive void, and pallet "
        "height respects the configured build limit."
    )
    framework_refs = ("GS1 Package Measurement Rules", "GS1 GDSN 3.1 Validation Rules")
    input_attributes = (
        "unit_height_mm",
        "unit_width_mm",
        "unit_depth_mm",
        "units_per_case",
        "case_height_mm",
        "case_width_mm",
        "case_depth_mm",
        "pallet_height_mm",
    )
    remediation_hint = (
        "Re-measure the case and unit dimensions (height, width, depth per GS1 orientation) "
        "and correct the hierarchy; review case configuration if void fill is excessive."
    )

    def check(self, record: SkuListing, ctx: Ctx) -> list[Finding]:
        cfg: Mapping[str, Any] = ctx.config["packaging"]
        key = record.sku_id
        findings: list[Finding] = []
        unit_volume = _volume_mm3(record.unit_height_mm, record.unit_width_mm, record.unit_depth_mm)
        case_volume = _volume_mm3(record.case_height_mm, record.case_width_mm, record.case_depth_mm)
        fill_ratio = record.units_per_case * unit_volume / case_volume
        rendered = str(fill_ratio.quantize(Decimal("0.01")))
        if fill_ratio > 1:
            findings.append(
                self.finding(
                    ctx,
                    check_code="CASE_VOLUME_INSUFFICIENT",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=(
                        f"{record.units_per_case} units need {rendered}x the case volume; the "
                        "declared case cannot contain them"
                    ),
                    attributes=(
                        "units_per_case",
                        "case_height_mm",
                        "case_width_mm",
                        "case_depth_mm",
                    ),
                    details={"fill_ratio": rendered},
                )
            )
        elif fill_ratio < to_decimal(cfg["case_min_fill_ratio"]):
            findings.append(
                self.finding(
                    ctx,
                    check_code="CASE_FILL_RATIO_LOW",
                    severity=Severity.WARNING,
                    record_key=key,
                    message=(
                        f"Case fill ratio {rendered} is below {cfg['case_min_fill_ratio']}; "
                        "volumetric weight will drive air freight cost"
                    ),
                    attributes=(
                        "units_per_case",
                        "case_height_mm",
                        "case_width_mm",
                        "case_depth_mm",
                    ),
                    details={"fill_ratio": rendered},
                )
            )
        max_height = to_decimal(cfg["max_pallet_height_mm"])
        if record.pallet_height_mm > max_height:
            findings.append(
                self.finding(
                    ctx,
                    check_code="PALLET_HEIGHT_EXCEEDED",
                    severity=Severity.WARNING,
                    record_key=key,
                    message=(
                        f"Pallet height {record.pallet_height_mm} mm exceeds the "
                        f"{max_height} mm build limit"
                    ),
                    attributes=("pallet_height_mm",),
                )
            )
        return findings


class MarketEligibilityRule(RecordRule[SkuListing]):
    rule_id = "TR-MKT-001"
    title = "Sold-To / Ship-To duty-free market eligibility"
    control_objective = (
        "A listing is released only to an active Sold-To, through a Ship-To that belongs to "
        "it, in a market the item is authorised for, and to a location able to receive "
        "dangerous goods where the item is Class 3."
    )
    framework_refs = (
        "GS1 GDSN 3.1 target market",
        "Customer master governance",
        "IATA DGR Class 3",
    )
    input_attributes = (
        "sold_to_code",
        "ship_to_code",
        "target_markets",
        "category",
        "alcohol_by_volume_pct",
    )
    remediation_hint = (
        "Delist the item for the affected Ship-To, or resolve the customer master block or "
        "market authorisation with Commercial Compliance before re-releasing."
    )

    def check(self, record: SkuListing, ctx: Ctx) -> list[Finding]:
        cfg: Mapping[str, Any] = ctx.config["market_eligibility"]
        key = record.listing_id
        findings: list[Finding] = []
        account = cfg["sold_to_accounts"].get(record.sold_to_code)
        if account is None:
            findings.append(
                self._blocker(ctx, key, "SOLD_TO_UNKNOWN", f"Sold-To {record.sold_to_code} unknown")
            )
        elif account["status"] == "BLOCKED":
            reason = account.get("reason")
            findings.append(
                self._blocker(
                    ctx,
                    key,
                    "SOLD_TO_BLOCKED",
                    f"Sold-To {record.sold_to_code} is blocked" + (f": {reason}" if reason else ""),
                )
            )
        elif account["status"] == "RESTRICTED" and record.category in account.get(
            "restricted_categories", []
        ):
            findings.append(
                self._blocker(
                    ctx,
                    key,
                    "SOLD_TO_CATEGORY_RESTRICTED",
                    f"Sold-To {record.sold_to_code} is restricted for {record.category}: "
                    f"{account.get('reason', '')}",
                )
            )
        location = cfg["ship_to_locations"].get(record.ship_to_code)
        if location is None:
            findings.append(
                self._blocker(ctx, key, "SHIP_TO_UNKNOWN", f"Ship-To {record.ship_to_code} unknown")
            )
            return findings
        if location["sold_to"] != record.sold_to_code:
            findings.append(
                self._blocker(
                    ctx,
                    key,
                    "SHIP_TO_NOT_LINKED_TO_SOLD_TO",
                    f"Ship-To {record.ship_to_code} belongs to Sold-To {location['sold_to']}, "
                    f"not {record.sold_to_code}",
                )
            )
        if location["country"] not in record.target_markets:
            findings.append(
                self._blocker(
                    ctx,
                    key,
                    "MARKET_NOT_AUTHORISED",
                    f"{record.sku_id} is not authorised for {location['country']} "
                    f"(target markets: {', '.join(record.target_markets) or 'none'})",
                )
            )
        dangerous = assess_class3(record, ctx.config["dangerous_goods"]).in_scope or bool(
            record.un_number
        )
        if dangerous and not location.get("accepts_dangerous_goods", False):
            findings.append(
                self._blocker(
                    ctx,
                    key,
                    "DG_NOT_ACCEPTED_AT_SHIP_TO",
                    f"Ship-To {record.ship_to_code} ({location['channel']}) does not accept "
                    f"dangerous goods; {record.sku_id} is in Class 3 scope",
                )
            )
        return findings

    def _blocker(self, ctx: Ctx, key: str, code: str, message: str) -> Finding:
        return self.finding(
            ctx,
            check_code=code,
            severity=Severity.BLOCKER,
            record_key=key,
            message=message,
            attributes=("sold_to_code", "ship_to_code", "target_markets"),
        )


class CustomsClassificationRule(SkuLevelRule):
    rule_id = "TR-CUS-001"
    title = "Customs tariff classification and origin"
    control_objective = (
        "Each item carries an HS code under the heading expected for its category and a "
        "country of origin, as required for duty-free customs declarations."
    )
    framework_refs = ("WCO HS Nomenclature Chapter 33", "Union Customs Code Art. 60")
    input_attributes = ("category", "hs_code", "country_of_origin")
    remediation_hint = (
        "Confirm the tariff classification with Customs (binding tariff information where "
        "needed) and complete the origin from the supplier declaration."
    )

    def check(self, record: SkuListing, ctx: Ctx) -> list[Finding]:
        headings: Mapping[str, str] = ctx.config["customs"]["hs_heading_by_category"]
        key = record.sku_id
        findings: list[Finding] = []
        if record.hs_code is None:
            findings.append(self._warning(ctx, key, "HS_CODE_MISSING", "HS code missing"))
        elif not (record.hs_code.isdigit() and len(record.hs_code) >= 6):
            findings.append(
                self._warning(
                    ctx, key, "HS_CODE_FORMAT", f"HS code {record.hs_code} is not a 6+ digit code"
                )
            )
        else:
            expected = str(headings.get(record.category, ""))
            if expected and not record.hs_code.startswith(expected):
                findings.append(
                    self._warning(
                        ctx,
                        key,
                        "HS_HEADING_MISMATCH",
                        f"HS code {record.hs_code} is outside heading {expected} expected for "
                        f"{record.category}",
                    )
                )
        if record.country_of_origin is None:
            findings.append(self._warning(ctx, key, "ORIGIN_MISSING", "Country of origin missing"))
        return findings

    def _warning(self, ctx: Ctx, key: str, code: str, message: str) -> Finding:
        return self.finding(
            ctx,
            check_code=code,
            severity=Severity.WARNING,
            record_key=key,
            message=message,
            attributes=("hs_code", "country_of_origin", "category"),
        )


# ---------------------------------------------------------------------------
# Pack definition
# ---------------------------------------------------------------------------

_STAGING_COLUMNS: tuple[str, ...] = (
    "listing_id",
    "sku_id",
    "brand",
    "description",
    "category",
    "unit_gtin",
    "case_gtin",
    "net_content_ml",
    "unit_net_weight_g",
    "unit_gross_weight_g",
    "unit_height_mm",
    "unit_width_mm",
    "unit_depth_mm",
    "units_per_case",
    "case_gross_weight_kg",
    "case_height_mm",
    "case_width_mm",
    "case_depth_mm",
    "cases_per_pallet",
    "pallet_gross_weight_kg",
    "pallet_height_mm",
    "alcohol_by_volume_pct",
    "flashpoint_c",
    "un_number",
    "dg_class",
    "packing_group",
    "dg_regulations",
    "sds_reference",
    "hs_code",
    "country_of_origin",
    "target_markets",
    "sold_to_code",
    "ship_to_code",
)

_STAGING_DDL = """
CREATE TABLE IF NOT EXISTS stg_travel_retail_sku (
    run_id                  VARCHAR NOT NULL,
    listing_id              VARCHAR NOT NULL,
    sku_id                  VARCHAR NOT NULL,
    brand                   VARCHAR NOT NULL,
    description             VARCHAR NOT NULL,
    category                VARCHAR NOT NULL,
    unit_gtin               VARCHAR NOT NULL,
    case_gtin               VARCHAR NOT NULL,
    net_content_ml          DECIMAL(10, 2),
    unit_net_weight_g       DECIMAL(12, 3) NOT NULL,
    unit_gross_weight_g     DECIMAL(12, 3) NOT NULL,
    unit_height_mm          DECIMAL(10, 1) NOT NULL,
    unit_width_mm           DECIMAL(10, 1) NOT NULL,
    unit_depth_mm           DECIMAL(10, 1) NOT NULL,
    units_per_case          INTEGER NOT NULL,
    case_gross_weight_kg    DECIMAL(12, 3) NOT NULL,
    case_height_mm          DECIMAL(10, 1) NOT NULL,
    case_width_mm           DECIMAL(10, 1) NOT NULL,
    case_depth_mm           DECIMAL(10, 1) NOT NULL,
    cases_per_pallet        INTEGER NOT NULL,
    pallet_gross_weight_kg  DECIMAL(12, 3) NOT NULL,
    pallet_height_mm        DECIMAL(10, 1) NOT NULL,
    alcohol_by_volume_pct   DECIMAL(5, 2) NOT NULL,
    flashpoint_c            DECIMAL(6, 1),
    un_number               VARCHAR,
    dg_class                VARCHAR,
    packing_group           VARCHAR,
    dg_regulations          VARCHAR NOT NULL,
    sds_reference           VARCHAR,
    hs_code                 VARCHAR,
    country_of_origin       VARCHAR,
    target_markets          VARCHAR NOT NULL,
    sold_to_code            VARCHAR NOT NULL,
    ship_to_code            VARCHAR NOT NULL,
    PRIMARY KEY (run_id, listing_id)
)
"""


@register_pack
class TravelRetailGdsnPack(RulePack[SkuListing]):
    pack_id = PackId.TRAVEL_RETAIL_GDSN
    display_name = "Pack B: Travel Retail GS1/GDSN & HAZMAT Gatekeeper"
    run_prefix = "GDSN"
    default_source = "travel_retail_sku_assortment.csv"
    config_file = "travel_retail_gdsn.yaml"
    staging = StagingSpec(
        table="stg_travel_retail_sku",
        ddl=_STAGING_DDL,
        columns=_STAGING_COLUMNS,
        key_column="listing_id",
    )
    lineage = (
        LineageSpec("unit_gtin", "GS1_GDSN/BASE_UNIT_OR_EACH.gtin", critical_data_element=True),
        LineageSpec("case_gtin", "GS1_GDSN/CASE.gtin", critical_data_element=True),
        LineageSpec("brand", "GS1_GDSN/BASE_UNIT_OR_EACH.brandName"),
        LineageSpec("description", "GS1_GDSN/BASE_UNIT_OR_EACH.descriptionShort"),
        LineageSpec("net_content_ml", "GS1_GDSN/BASE_UNIT_OR_EACH.netContent"),
        LineageSpec(
            "unit_net_weight_g", "GS1_GDSN/BASE_UNIT_OR_EACH.netWeight", critical_data_element=True
        ),
        LineageSpec(
            "unit_gross_weight_g",
            "GS1_GDSN/BASE_UNIT_OR_EACH.grossWeight",
            critical_data_element=True,
        ),
        LineageSpec("unit_height_mm", "GS1_GDSN/BASE_UNIT_OR_EACH.height"),
        LineageSpec("unit_width_mm", "GS1_GDSN/BASE_UNIT_OR_EACH.width"),
        LineageSpec("unit_depth_mm", "GS1_GDSN/BASE_UNIT_OR_EACH.depth"),
        LineageSpec(
            "units_per_case",
            "GS1_GDSN/CASE.quantityOfNextLowerLevelTradeItem",
            critical_data_element=True,
        ),
        LineageSpec(
            "case_gross_weight_kg", "GS1_GDSN/CASE.grossWeight", critical_data_element=True
        ),
        LineageSpec("case_height_mm", "GS1_GDSN/CASE.height"),
        LineageSpec("case_width_mm", "GS1_GDSN/CASE.width"),
        LineageSpec("case_depth_mm", "GS1_GDSN/CASE.depth"),
        LineageSpec("cases_per_pallet", "GS1_GDSN/PALLET.quantityOfNextLowerLevelTradeItem"),
        LineageSpec("pallet_gross_weight_kg", "GS1_GDSN/PALLET.grossWeight"),
        LineageSpec("pallet_height_mm", "GS1_GDSN/PALLET.height"),
        LineageSpec(
            "alcohol_by_volume_pct",
            "GS1_GDSN/BASE_UNIT_OR_EACH.percentageOfAlcoholByVolume",
            critical_data_element=True,
        ),
        LineageSpec(
            "flashpoint_c",
            "GS1_GDSN/BASE_UNIT_OR_EACH.flashPointTemperature",
            critical_data_element=True,
        ),
        LineageSpec(
            "un_number",
            "GS1_GDSN/BASE_UNIT_OR_EACH.unitedNationsDangerousGoodsNumber",
            critical_data_element=True,
        ),
        LineageSpec(
            "dg_class",
            "GS1_GDSN/BASE_UNIT_OR_EACH.classOfDangerousGoods",
            critical_data_element=True,
        ),
        LineageSpec(
            "packing_group",
            "GS1_GDSN/BASE_UNIT_OR_EACH.dangerousGoodsPackingGroup",
            critical_data_element=True,
        ),
        LineageSpec("dg_regulations", "GS1_GDSN/BASE_UNIT_OR_EACH.dangerousGoodsRegulationCode"),
        LineageSpec("hs_code", "GS1_GDSN/BASE_UNIT_OR_EACH.importClassificationValue"),
        LineageSpec("country_of_origin", "GS1_GDSN/BASE_UNIT_OR_EACH.countryOfOrigin"),
        LineageSpec(
            "target_markets",
            "GS1_GDSN/BASE_UNIT_OR_EACH.targetMarketCountryCode",
            critical_data_element=True,
        ),
        LineageSpec("sold_to_code", "ERP_SD/ASSORTMENT_LISTING.sold_to"),
        LineageSpec("ship_to_code", "ERP_SD/ASSORTMENT_LISTING.ship_to"),
    )

    def build_rules(self) -> Sequence[Rule[SkuListing]]:
        return (
            GtinCheckDigitRule(),
            GtinUniquenessRule(),
            GoldenRecordConsistencyRule(),
            DangerousGoodsRule(),
            PackagingWeightRule(),
            PackagingDimensionRule(),
            MarketEligibilityRule(),
            CustomsClassificationRule(),
        )

    def parse_record(self, row: Mapping[str, object]) -> SkuListing:
        return SkuListing.model_validate(dict(row))

    def to_staging_row(self, record: SkuListing) -> tuple[object, ...]:
        values: list[object] = []
        for column in _STAGING_COLUMNS:
            value = getattr(record, column)
            values.append("|".join(value) if isinstance(value, tuple) else value)
        return tuple(values)
