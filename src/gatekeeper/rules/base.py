"""Rule and rule-pack abstractions plus the pack registry.

A rule pack bundles a record contract, a DuckDB staging table, an attribute-level lineage map
and a list of deterministic rules. Two rule styles are supported:

* :class:`RecordRule` evaluates each validated record in Python (format, arithmetic and
  policy checks that are clearest as code).
* :class:`SqlRule` evaluates set-based controls in DuckDB SQL over the staged population
  (balances, net-zero aggregations, uniqueness and cross-record consistency).
"""

from __future__ import annotations

import importlib
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any, ClassVar, Generic, TypeVar

import yaml
from pydantic import BaseModel

from gatekeeper.ledger.store import ControlStore, canonical_json, sha256_hex
from gatekeeper.models import (
    DetailValue,
    Finding,
    FindingScope,
    PackId,
    RuleDescriptor,
    Severity,
)

RecordT = TypeVar("RecordT", bound=BaseModel)

CENT = Decimal("0.01")


def to_decimal(value: object) -> Decimal:
    """Normalise DuckDB DECIMAL/DOUBLE results and config numbers to ``Decimal``."""
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))


def money(value: Decimal) -> str:
    """Render an amount with two decimals using commercial rounding."""
    return format(value.quantize(CENT, rounding=ROUND_HALF_UP), ",.2f")


@dataclass(frozen=True)
class RuleContext(Generic[RecordT]):
    """Everything a rule may read. Rules never write to the store."""

    run_id: str
    pack_id: PackId
    store: ControlStore
    config: Mapping[str, Any]
    records: Sequence[RecordT]
    staging_table: str


class Rule(ABC, Generic[RecordT]):
    """A deterministic control with its regulatory mapping."""

    rule_id: ClassVar[str]
    title: ClassVar[str]
    control_objective: ClassVar[str]
    framework_refs: ClassVar[tuple[str, ...]]
    input_attributes: ClassVar[tuple[str, ...]]
    remediation_hint: ClassVar[str]

    @abstractmethod
    def evaluate(self, ctx: RuleContext[RecordT]) -> list[Finding]:
        """Return all findings for the population in ``ctx``."""

    @classmethod
    def descriptor(cls) -> RuleDescriptor:
        return RuleDescriptor(
            rule_id=cls.rule_id,
            title=cls.title,
            control_objective=cls.control_objective,
            framework_refs=cls.framework_refs,
            input_attributes=cls.input_attributes,
            remediation_hint=cls.remediation_hint,
        )

    def finding(
        self,
        ctx: RuleContext[RecordT],
        *,
        check_code: str,
        severity: Severity,
        record_key: str,
        message: str,
        attributes: Sequence[str] = (),
        details: Mapping[str, DetailValue] | None = None,
        scope: FindingScope = FindingScope.RECORD,
    ) -> Finding:
        return Finding(
            run_id=ctx.run_id,
            pack_id=ctx.pack_id,
            rule_id=self.rule_id,
            check_code=check_code,
            severity=severity,
            scope=scope,
            record_key=record_key,
            message=message,
            attributes=tuple(attributes),
            details=dict(details or {}),
        )


class RecordRule(Rule[RecordT]):
    """Rule evaluated independently for every validated record."""

    def evaluate(self, ctx: RuleContext[RecordT]) -> list[Finding]:
        findings: list[Finding] = []
        for record in ctx.records:
            findings.extend(self.check(record, ctx))
        return findings

    @abstractmethod
    def check(self, record: RecordT, ctx: RuleContext[RecordT]) -> list[Finding]:
        """Return the findings raised by a single record."""


class SqlRule(Rule[RecordT]):
    """Rule evaluated as a set-based query over the run's staging table in DuckDB."""


@dataclass(frozen=True)
class StagingSpec:
    """DuckDB staging table for a pack. ``columns`` excludes the leading ``run_id``."""

    table: str
    ddl: str
    columns: tuple[str, ...]
    key_column: str


@dataclass(frozen=True)
class LineageSpec:
    """Maps a source attribute to the downstream system attribute it populates."""

    source_column: str
    target_attribute: str
    critical_data_element: bool = False


class RulePack(ABC, Generic[RecordT]):
    """A pluggable domain rule pack on top of the shared control core."""

    pack_id: ClassVar[PackId]
    display_name: ClassVar[str]
    run_prefix: ClassVar[str]
    default_source: ClassVar[str]
    config_file: ClassVar[str]
    staging: ClassVar[StagingSpec]
    lineage: ClassVar[tuple[LineageSpec, ...]]

    def __init__(self, config: Mapping[str, Any]) -> None:
        self.config = config
        self.rules: tuple[Rule[RecordT], ...] = tuple(self.build_rules())

    @abstractmethod
    def build_rules(self) -> Sequence[Rule[RecordT]]:
        """Instantiate the pack's rules in evaluation order."""

    @abstractmethod
    def parse_record(self, row: Mapping[str, object]) -> RecordT:
        """Validate a raw row against the pack's record contract."""

    @abstractmethod
    def to_staging_row(self, record: RecordT) -> tuple[object, ...]:
        """Project a record onto ``staging.columns``."""

    def record_key(self, record: RecordT) -> str:
        return str(getattr(record, self.staging.key_column))

    def raw_record_key(self, row: Mapping[str, object], position: int) -> str:
        value = row.get(self.staging.key_column)
        text = "" if value is None else str(value).strip()
        return text or f"row-{position}"

    def descriptors(self) -> list[RuleDescriptor]:
        return [rule.descriptor() for rule in self.rules]

    def remediation_hints(self) -> dict[str, str]:
        return {rule.rule_id: rule.remediation_hint for rule in self.rules}


# ---------------------------------------------------------------------------
# Registry and configuration
# ---------------------------------------------------------------------------

_BUILTIN_PACK_MODULES: Mapping[PackId, str] = {
    PackId.FINANCE_PRECLOSE_ICS: "gatekeeper.rules.finance_ics",
    PackId.TRAVEL_RETAIL_GDSN: "gatekeeper.rules.travel_retail_mdm",
}

_REGISTRY: dict[PackId, type[RulePack[Any]]] = {}

PackT = TypeVar("PackT", bound=type[RulePack[Any]])


def register_pack(cls: PackT) -> PackT:
    """Class decorator registering a rule pack under its ``pack_id``."""
    _REGISTRY[cls.pack_id] = cls
    return cls


def get_pack_class(pack_id: PackId) -> type[RulePack[Any]]:
    if pack_id not in _REGISTRY and pack_id in _BUILTIN_PACK_MODULES:
        importlib.import_module(_BUILTIN_PACK_MODULES[pack_id])
    try:
        return _REGISTRY[pack_id]
    except KeyError as exc:
        raise KeyError(f"no rule pack registered for {pack_id.value}") from exc


def available_packs() -> tuple[PackId, ...]:
    return tuple(PackId)


@dataclass(frozen=True)
class LoadedConfig:
    """Parsed YAML policy and the SHA-256 of its exact bytes."""

    data: Mapping[str, Any]
    sha256: str
    path: Path


def load_config(path: Path) -> LoadedConfig:
    raw = path.read_bytes()
    data = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} does not contain a YAML mapping")
    return LoadedConfig(data=data, sha256=sha256_hex(raw.decode("utf-8")), path=path)


def fingerprint_rows(rows: Sequence[Mapping[str, object]]) -> str:
    """SHA-256 over the canonical JSON of the submitted rows (input integrity evidence)."""
    return sha256_hex(canonical_json([dict(r) for r in rows]))
