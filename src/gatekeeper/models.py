"""Pydantic v2 schemas shared by the control core, the rule packs and the delivery layers.

Records are validated at the ingestion boundary (schema contract). Business policy is
evaluated afterwards by deterministic rules, so a record that is structurally valid but
commercially wrong is still loaded and receives a finding rather than being silently dropped.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DetailValue = str | int | float | bool | None


class PackId(StrEnum):
    """Identifiers of the pluggable domain rule packs."""

    FINANCE_PRECLOSE_ICS = "finance_preclose_ics"
    TRAVEL_RETAIL_GDSN = "travel_retail_gdsn"


class Severity(StrEnum):
    """Outcome classification of a control."""

    BLOCKER = "BLOCKER"
    WARNING = "WARNING"
    PASS = "PASS"


class FindingScope(StrEnum):
    """Granularity at which a finding was raised."""

    SCHEMA = "SCHEMA"
    RECORD = "RECORD"
    AGGREGATE = "AGGREGATE"


class GateDecision(StrEnum):
    """Release gate verdict derived exclusively from deterministic findings."""

    BLOCKED = "BLOCKED"
    REQUIRES_FOUR_EYES = "REQUIRES_FOUR_EYES"
    CLEAR = "CLEAR"


class WorkflowState(StrEnum):
    """Maker/checker lifecycle of a validated batch."""

    DRAFT = "DRAFT"
    SUBMITTED = "SUBMITTED"
    QUARANTINED = "QUARANTINED"
    APPROVED_WITH_EXCEPTION = "APPROVED_WITH_EXCEPTION"
    RELEASED = "RELEASED"


class WorkflowAction(StrEnum):
    """Actions that move a batch between workflow states."""

    OPEN = "OPEN"
    SUBMIT = "SUBMIT"
    QUARANTINE = "QUARANTINE"
    RELEASE = "RELEASE"
    APPROVE_WITH_EXCEPTION = "APPROVE_WITH_EXCEPTION"


class LineageEdgeType(StrEnum):
    """Edge semantics of the attribute-level lineage graph."""

    INGEST = "INGEST"
    PUBLISH = "PUBLISH"
    CONTROL_INPUT = "CONTROL_INPUT"
    GATES = "GATES"


def _blank_to_none(value: object) -> object:
    if isinstance(value, str) and not value.strip():
        return None
    return value


def _split_pipe(value: object) -> object:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split("|") if part.strip())
    return value


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------------------
# Domain records
# ---------------------------------------------------------------------------


class SubLedgerEntry(_Frozen):
    """One line of a sub-ledger interface batch destined for the ERP general ledger.

    Amounts are signed: debit positive, credit negative. ``fx_rate`` expresses group
    currency per one unit of transaction currency.
    """

    entry_id: str = Field(min_length=1)
    batch_id: str = Field(min_length=1)
    journal_id: str = Field(min_length=1)
    company_code: str = Field(pattern=r"^[A-Z]{2}\d{2}$")
    posting_date: date
    fiscal_period: str = Field(pattern=r"^\d{4}-\d{2}$")
    source_ledger: Literal["AP", "AR", "GL", "IC"]
    gl_account: str = Field(pattern=r"^\d{6}$")
    cost_centre: str | None = None
    partner_company: str | None = None
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    amount_txn: Decimal
    fx_rate: Decimal = Field(gt=0)
    fx_rate_date: date
    amount_group: Decimal
    maker_id: str = Field(min_length=1)
    approver_id: str | None = None
    maker_roles: tuple[str, ...] = ()
    description: str = ""

    @field_validator("cost_centre", "partner_company", "approver_id", mode="before")
    @classmethod
    def _optional_text(cls, value: object) -> object:
        return _blank_to_none(value)

    @field_validator("maker_roles", mode="before")
    @classmethod
    def _roles(cls, value: object) -> object:
        return _split_pipe(_blank_to_none(value))


class SkuListing(_Frozen):
    """A trade item listed for a Sold-To / Ship-To combination in the travel retail channel.

    Attributes follow the GS1 GDSN trade item model, flattened to one row per listing:
    consumer unit, case and pallet levels of the packaging hierarchy, dangerous goods
    classification, customs data and commercial eligibility.
    """

    listing_id: str = Field(min_length=1)
    sku_id: str = Field(min_length=1)
    brand: str = Field(min_length=1)
    description: str = Field(min_length=1)
    category: Literal["FRAGRANCE", "SKINCARE", "MAKEUP", "HAIRCARE"]
    unit_gtin: str
    case_gtin: str
    net_content_ml: Decimal | None = Field(default=None, ge=0)
    unit_net_weight_g: Decimal = Field(gt=0)
    unit_gross_weight_g: Decimal = Field(gt=0)
    unit_height_mm: Decimal = Field(gt=0)
    unit_width_mm: Decimal = Field(gt=0)
    unit_depth_mm: Decimal = Field(gt=0)
    units_per_case: int = Field(gt=0)
    case_gross_weight_kg: Decimal = Field(gt=0)
    case_height_mm: Decimal = Field(gt=0)
    case_width_mm: Decimal = Field(gt=0)
    case_depth_mm: Decimal = Field(gt=0)
    cases_per_pallet: int = Field(gt=0)
    pallet_gross_weight_kg: Decimal = Field(gt=0)
    pallet_height_mm: Decimal = Field(gt=0)
    alcohol_by_volume_pct: Decimal = Field(ge=0, le=100)
    flashpoint_c: Decimal | None = None
    un_number: str | None = None
    dg_class: str | None = None
    packing_group: Literal["I", "II", "III"] | None = None
    dg_regulations: tuple[str, ...] = ()
    sds_reference: str | None = None
    hs_code: str | None = None
    country_of_origin: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    target_markets: tuple[str, ...] = ()
    sold_to_code: str = Field(min_length=1)
    ship_to_code: str = Field(min_length=1)

    @field_validator(
        "net_content_ml",
        "flashpoint_c",
        "un_number",
        "dg_class",
        "packing_group",
        "sds_reference",
        "hs_code",
        "country_of_origin",
        mode="before",
    )
    @classmethod
    def _optional(cls, value: object) -> object:
        return _blank_to_none(value)

    @field_validator("dg_regulations", "target_markets", mode="before")
    @classmethod
    def _lists(cls, value: object) -> object:
        return _split_pipe(_blank_to_none(value))

    @field_validator("unit_gtin", "case_gtin", mode="before")
    @classmethod
    def _gtin_text(cls, value: object) -> object:
        # GTINs are identifiers, not numbers: never let a numeric parser strip leading zeros.
        if isinstance(value, int):
            raise ValueError("GTIN must be supplied as text to preserve leading zeros")
        return value


# ---------------------------------------------------------------------------
# Control results
# ---------------------------------------------------------------------------


class Finding(_Frozen):
    """A deterministic control exception. ``finding_id`` is stable for identical inputs."""

    finding_id: str = ""
    run_id: str
    pack_id: PackId
    rule_id: str
    check_code: str
    severity: Severity
    scope: FindingScope
    record_key: str
    message: str
    attributes: tuple[str, ...] = ()
    details: dict[str, DetailValue] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _derive_identifier(cls, data: Any) -> Any:
        if isinstance(data, dict) and not data.get("finding_id"):
            data = {
                **data,
                "finding_id": f"{data['rule_id']}:{data['check_code']}:{data['record_key']}",
            }
        return data

    @field_validator("severity")
    @classmethod
    def _no_pass_findings(cls, value: Severity) -> Severity:
        if value is Severity.PASS:
            raise ValueError("PASS is a rule outcome, not a finding severity")
        return value


class RuleExecution(_Frozen):
    """Evidence that a control operated over a population, including zero-exception runs."""

    run_id: str
    rule_id: str
    title: str
    records_evaluated: int
    blocker_count: int
    warning_count: int
    outcome: Severity


class RuleDescriptor(_Frozen):
    """Catalogue entry describing a control and its regulatory mapping."""

    rule_id: str
    title: str
    control_objective: str
    framework_refs: tuple[str, ...]
    input_attributes: tuple[str, ...]
    remediation_hint: str


class RunRecord(_Frozen):
    """Immutable header of a validation run."""

    run_id: str
    pack_id: PackId
    maker_id: str
    source_name: str
    input_sha256: str
    config_sha256: str
    record_count: int
    rejected_count: int
    blocker_count: int
    warning_count: int
    gate_decision: GateDecision
    engine_version: str
    created_at: str


class RunSummary(_Frozen):
    """Run header plus current workflow state, executions and findings."""

    run: RunRecord
    workflow_state: WorkflowState
    rule_executions: tuple[RuleExecution, ...]
    findings: tuple[Finding, ...]


class LineageEdge(_Frozen):
    """Directed attribute-level lineage edge recorded for a specific run."""

    run_id: str
    from_node: str
    to_node: str
    edge_type: LineageEdgeType
    rule_id: str | None = None
    critical_data_element: bool = False


class LineageTrace(_Frozen):
    """Upstream trace of a downstream target attribute."""

    run_id: str
    target_node: str
    edges: tuple[LineageEdge, ...]
    controls: tuple[str, ...]
    source_attributes: tuple[str, ...]
    open_findings_by_control: dict[str, int]


class AuditEvent(_Frozen):
    """Entry of the SHA-256 hash-chained audit log."""

    seq: int
    event_id: str
    run_id: str | None
    event_type: str
    actor_id: str
    payload: dict[str, Any]
    created_at: str
    prev_hash: str
    event_hash: str


class ChainVerification(_Frozen):
    """Result of recomputing the audit hash chain."""

    valid: bool
    events_checked: int
    head_hash: str
    broken_at_seq: int | None = None
    reason: str | None = None


class WorkflowEvent(_Frozen):
    """Maker/checker sign-off event, bound to the audit chain by ``audit_event_hash``."""

    run_id: str
    seq: int
    from_state: WorkflowState | None
    to_state: WorkflowState
    action: WorkflowAction
    actor_id: str
    justification: str | None
    created_at: str
    audit_event_hash: str


class RemediationAdvice(_Frozen):
    """Advisory remediation text. It never changes a gate decision."""

    finding_id: str
    rule_id: str
    severity: Severity
    suggested_action: str
    rationale: str
    source: Literal["BEDROCK", "DETERMINISTIC_FALLBACK"]
    model_id: str | None = None
    gate_effect: Literal["NONE"] = "NONE"
