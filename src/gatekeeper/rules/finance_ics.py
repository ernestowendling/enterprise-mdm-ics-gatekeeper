"""Pack A: finance pre-close internal control system (ICS/SOX) rule pack.

Validates a sub-ledger interface batch before it is posted to the ERP general ledger
(SAP S/4HANA Universal Journal, table ACDOCA). Set-based controls run as DuckDB SQL over the
staged population; record-level controls run in Python.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from gatekeeper.models import Finding, FindingScope, PackId, Severity, SubLedgerEntry
from gatekeeper.rules.base import (
    CENT,
    LineageSpec,
    RecordRule,
    Rule,
    RuleContext,
    RulePack,
    SqlRule,
    StagingSpec,
    money,
    register_pack,
    to_decimal,
)

Ctx = RuleContext[SubLedgerEntry]

_STAGING_COLUMNS: tuple[str, ...] = (
    "entry_id",
    "batch_id",
    "journal_id",
    "company_code",
    "posting_date",
    "fiscal_period",
    "source_ledger",
    "gl_account",
    "cost_centre",
    "partner_company",
    "currency",
    "amount_txn",
    "fx_rate",
    "fx_rate_date",
    "amount_group",
    "maker_id",
    "approver_id",
    "maker_roles",
    "description",
)

_STAGING_DDL = """
CREATE TABLE IF NOT EXISTS stg_finance_subledger (
    run_id           VARCHAR NOT NULL,
    entry_id         VARCHAR NOT NULL,
    batch_id         VARCHAR NOT NULL,
    journal_id       VARCHAR NOT NULL,
    company_code     VARCHAR NOT NULL,
    posting_date     DATE NOT NULL,
    fiscal_period    VARCHAR NOT NULL,
    source_ledger    VARCHAR NOT NULL,
    gl_account       VARCHAR NOT NULL,
    cost_centre      VARCHAR,
    partner_company  VARCHAR,
    currency         VARCHAR NOT NULL,
    amount_txn       DECIMAL(18, 2) NOT NULL,
    fx_rate          DECIMAL(18, 8) NOT NULL,
    fx_rate_date     DATE NOT NULL,
    amount_group     DECIMAL(18, 2) NOT NULL,
    maker_id         VARCHAR NOT NULL,
    approver_id      VARCHAR,
    maker_roles      VARCHAR NOT NULL,
    description      VARCHAR NOT NULL,
    PRIMARY KEY (run_id, entry_id)
)
"""


def _tolerance(ctx: Ctx, key: str) -> float:
    return float(ctx.config["tolerances"][key])


def _accounts_where(ctx: Ctx, flag: str) -> list[str]:
    chart: Mapping[str, Mapping[str, Any]] = ctx.config["chart_of_accounts"]
    return sorted(account for account, meta in chart.items() if meta.get(flag))


def _placeholders(values: Sequence[object]) -> str:
    return ", ".join(["?"] * len(values))


# ---------------------------------------------------------------------------
# Set-based controls (DuckDB SQL)
# ---------------------------------------------------------------------------


class JournalBalanceRule(SqlRule[SubLedgerEntry]):
    rule_id = "FIN-TB-001"
    title = "Journal double-entry balance"
    control_objective = (
        "Every journal nets to zero in transaction currency, uses one currency and belongs "
        "to one company code before it is posted."
    )
    framework_refs = ("SOX 404 ITGC/ITAC", "Swiss CO Art. 957a", "BCBS 239 P3")
    input_attributes = ("journal_id", "company_code", "currency", "amount_txn")
    remediation_hint = (
        "Correct the unbalanced line in the source sub-ledger and re-extract the journal; "
        "do not force-balance with a manual plug in the GL."
    )

    def evaluate(self, ctx: Ctx) -> list[Finding]:
        rows = ctx.store.query(
            f"""
            SELECT journal_id,
                   MIN(company_code)            AS first_company,
                   COUNT(DISTINCT company_code) AS companies,
                   COUNT(DISTINCT currency)     AS currencies,
                   MIN(currency)                AS first_currency,
                   SUM(amount_txn)              AS net_txn,
                   COUNT(*)                     AS line_count
            FROM {ctx.staging_table}
            WHERE run_id = ?
            GROUP BY journal_id
            HAVING COUNT(DISTINCT company_code) > 1
                OR COUNT(DISTINCT currency) > 1
                OR ABS(SUM(amount_txn)) > ?
            ORDER BY journal_id
            """,
            [ctx.run_id, _tolerance(ctx, "journal_balance_txn")],
        )
        findings: list[Finding] = []
        for journal_id, company, companies, currencies, currency, net_txn, lines in rows:
            attrs = ("journal_id", "company_code", "currency", "amount_txn")
            if int(companies) > 1:
                findings.append(
                    self.finding(
                        ctx,
                        check_code="CROSS_COMPANY_JOURNAL",
                        severity=Severity.BLOCKER,
                        record_key=str(journal_id),
                        message=f"Journal {journal_id} spans {companies} company codes",
                        attributes=attrs,
                        scope=FindingScope.AGGREGATE,
                    )
                )
            if int(currencies) > 1:
                findings.append(
                    self.finding(
                        ctx,
                        check_code="MULTI_CURRENCY_JOURNAL",
                        severity=Severity.BLOCKER,
                        record_key=str(journal_id),
                        message=f"Journal {journal_id} mixes {currencies} transaction currencies",
                        attributes=attrs,
                        scope=FindingScope.AGGREGATE,
                    )
                )
            net = to_decimal(net_txn)
            if abs(net) > Decimal(str(_tolerance(ctx, "journal_balance_txn"))):
                findings.append(
                    self.finding(
                        ctx,
                        check_code="JOURNAL_NOT_BALANCED",
                        severity=Severity.BLOCKER,
                        record_key=str(journal_id),
                        message=(
                            f"Journal {journal_id} ({company}) does not balance: "
                            f"net {money(net)} {currency} across {lines} lines"
                        ),
                        attributes=attrs,
                        details={
                            "company_code": str(company),
                            "currency": str(currency),
                            "net_txn": money(net),
                            "line_count": int(lines),
                        },
                        scope=FindingScope.AGGREGATE,
                    )
                )
        return findings


class TrialBalanceNetZeroRule(SqlRule[SubLedgerEntry]):
    rule_id = "FIN-TB-002"
    title = "Trial balance net-zero by company code (group currency)"
    control_objective = (
        "The batch leaves each company code's trial balance in balance after translation "
        "into group currency."
    )
    framework_refs = ("SOX 404 financial close", "Swiss CO Art. 958c", "BCBS 239 P3/P7")
    input_attributes = ("company_code", "amount_group")
    remediation_hint = (
        "Reconcile the translated amounts line by line against amount_txn x fx_rate and "
        "correct the source; translation differences must not be absorbed in suspense."
    )

    def evaluate(self, ctx: Ctx) -> list[Finding]:
        rows = ctx.store.query(
            f"""
            SELECT company_code,
                   SUM(amount_group) AS net_group,
                   SUM(CASE WHEN amount_group > 0 THEN amount_group ELSE 0 END) AS debits,
                   SUM(CASE WHEN amount_group < 0 THEN amount_group ELSE 0 END) AS credits,
                   COUNT(*) AS line_count
            FROM {ctx.staging_table}
            WHERE run_id = ?
            GROUP BY company_code
            HAVING ABS(SUM(amount_group)) > ?
            ORDER BY company_code
            """,
            [ctx.run_id, _tolerance(ctx, "trial_balance_group")],
        )
        group_ccy = str(ctx.config["group_currency"])
        return [
            self.finding(
                ctx,
                check_code="TB_NOT_NET_ZERO",
                severity=Severity.BLOCKER,
                record_key=str(company),
                message=(
                    f"Company code {company} trial balance impact is "
                    f"{money(to_decimal(net))} {group_ccy}, expected 0.00"
                ),
                attributes=("company_code", "amount_group"),
                details={
                    "net_group": money(to_decimal(net)),
                    "debits_group": money(to_decimal(debits)),
                    "credits_group": money(to_decimal(credits)),
                    "line_count": int(lines),
                },
                scope=FindingScope.AGGREGATE,
            )
            for company, net, debits, credits, lines in rows
        ]


class SubledgerReconciliationRule(SqlRule[SubLedgerEntry]):
    rule_id = "FIN-TB-003"
    title = "Sub-ledger to GL reconciliation account tie-out"
    control_objective = (
        "Reconciliation (control) accounts are posted only from their sub-ledger so that "
        "sub-ledger totals tie to the GL balance."
    )
    framework_refs = ("SOX 404 account reconciliation", "Swiss CO Art. 728a", "BCBS 239 P3")
    input_attributes = ("company_code", "gl_account", "source_ledger", "amount_group")
    remediation_hint = (
        "Reverse the direct GL posting on the reconciliation account and re-post it through "
        "the owning sub-ledger (AP or AR) so the open-item detail exists."
    )

    def evaluate(self, ctx: Ctx) -> list[Finding]:
        chart: Mapping[str, Mapping[str, Any]] = ctx.config["chart_of_accounts"]
        tolerance = _tolerance(ctx, "reconciliation_group")
        findings: list[Finding] = []
        for account in _accounts_where(ctx, "reconciliation_for"):
            ledger = str(chart[account]["reconciliation_for"])
            rows = ctx.store.query(
                f"""
                SELECT company_code,
                       SUM(amount_group) AS gl_total,
                       SUM(CASE WHEN source_ledger = ? THEN amount_group ELSE 0 END)
                           AS subledger_total
                FROM {ctx.staging_table}
                WHERE run_id = ? AND gl_account = ?
                GROUP BY company_code
                HAVING ABS(SUM(amount_group)
                           - SUM(CASE WHEN source_ledger = ? THEN amount_group ELSE 0 END)) > ?
                ORDER BY company_code
                """,
                [ledger, ctx.run_id, account, ledger, tolerance],
            )
            for company, gl_total, subledger_total in rows:
                entries = ctx.store.query(
                    f"""
                    SELECT entry_id FROM {ctx.staging_table}
                    WHERE run_id = ? AND company_code = ? AND gl_account = ?
                      AND source_ledger <> ?
                    ORDER BY entry_id
                    """,
                    [ctx.run_id, company, account, ledger],
                )
                difference = to_decimal(gl_total) - to_decimal(subledger_total)
                findings.append(
                    self.finding(
                        ctx,
                        check_code="SUBLEDGER_GL_DIFFERENCE",
                        severity=Severity.BLOCKER,
                        record_key=f"{company}/{account}",
                        message=(
                            f"{company} account {account} ({ledger} reconciliation): GL "
                            f"{money(to_decimal(gl_total))} vs {ledger} sub-ledger "
                            f"{money(to_decimal(subledger_total))}, difference "
                            f"{money(difference)} from direct GL postings"
                        ),
                        attributes=("company_code", "gl_account", "source_ledger"),
                        details={
                            "gl_total_group": money(to_decimal(gl_total)),
                            "subledger_total_group": money(to_decimal(subledger_total)),
                            "difference_group": money(difference),
                            "direct_postings": ",".join(str(e[0]) for e in entries),
                        },
                        scope=FindingScope.AGGREGATE,
                    )
                )
        return findings


class SuspenseClearanceRule(SqlRule[SubLedgerEntry]):
    rule_id = "FIN-TB-004"
    title = "Suspense and clearing account clearance"
    control_objective = "Suspense accounts carry a nil balance per company code at pre-close."
    framework_refs = ("SOX 404 financial close", "Swiss CO Art. 957a", "BCBS 239 P4")
    input_attributes = ("company_code", "gl_account", "amount_group")
    remediation_hint = (
        "Identify the counterparty of the suspense item, post the clearing entry to the "
        "correct account and attach the supporting evidence."
    )

    def evaluate(self, ctx: Ctx) -> list[Finding]:
        accounts = _accounts_where(ctx, "suspense")
        if not accounts:
            return []
        rows = ctx.store.query(
            f"""
            SELECT company_code, gl_account, SUM(amount_group) AS balance, COUNT(*) AS lines
            FROM {ctx.staging_table}
            WHERE run_id = ? AND gl_account IN ({_placeholders(accounts)})
            GROUP BY company_code, gl_account
            HAVING ABS(SUM(amount_group)) > ?
            ORDER BY company_code, gl_account
            """,
            [ctx.run_id, *accounts, _tolerance(ctx, "trial_balance_group")],
        )
        return [
            self.finding(
                ctx,
                check_code="SUSPENSE_NOT_CLEARED",
                severity=Severity.BLOCKER,
                record_key=f"{company}/{account}",
                message=(
                    f"Suspense account {account} in {company} carries "
                    f"{money(to_decimal(balance))} {ctx.config['group_currency']} "
                    f"across {lines} line(s)"
                ),
                attributes=("company_code", "gl_account", "amount_group"),
                details={"balance_group": money(to_decimal(balance)), "line_count": int(lines)},
                scope=FindingScope.AGGREGATE,
            )
            for company, account, balance, lines in rows
        ]


class IntercompanyNetZeroRule(SqlRule[SubLedgerEntry]):
    rule_id = "FIN-IC-001"
    title = "Intercompany net-zero (elimination readiness)"
    control_objective = (
        "Intercompany receivables and payables between each pair of entities offset in "
        "group currency so that consolidation eliminations net to zero."
    )
    framework_refs = ("SOX 404 consolidation", "IFRS 10 B86", "BCBS 239 P3/P8")
    input_attributes = ("company_code", "partner_company", "gl_account", "amount_group")
    remediation_hint = (
        "Agree the intercompany balance with the counterparty entity, align the transaction "
        "date and rate, and post the matching entry in the entity that is out of line."
    )

    def evaluate(self, ctx: Ctx) -> list[Finding]:
        accounts = _accounts_where(ctx, "intercompany")
        if not accounts:
            return []
        findings: list[Finding] = []
        orphans = ctx.store.query(
            f"""
            SELECT entry_id, company_code, gl_account FROM {ctx.staging_table}
            WHERE run_id = ? AND gl_account IN ({_placeholders(accounts)})
              AND (partner_company IS NULL OR partner_company = company_code)
            ORDER BY entry_id
            """,
            [ctx.run_id, *accounts],
        )
        for entry_id, company, account in orphans:
            findings.append(
                self.finding(
                    ctx,
                    check_code="IC_PARTNER_INVALID",
                    severity=Severity.BLOCKER,
                    record_key=str(entry_id),
                    message=(
                        f"Intercompany account {account} in {company} posted without a valid "
                        "trading partner"
                    ),
                    attributes=("partner_company", "gl_account"),
                )
            )
        rows = ctx.store.query(
            f"""
            SELECT entity_a,
                   entity_b,
                   SUM(amount_group) AS net_group,
                   SUM(CASE WHEN company_code = entity_a THEN amount_group ELSE 0 END) AS side_a,
                   SUM(CASE WHEN company_code = entity_b THEN amount_group ELSE 0 END) AS side_b
            FROM (
                SELECT CASE WHEN company_code < partner_company
                            THEN company_code ELSE partner_company END AS entity_a,
                       CASE WHEN company_code < partner_company
                            THEN partner_company ELSE company_code END AS entity_b,
                       company_code,
                       amount_group
                FROM {ctx.staging_table}
                WHERE run_id = ?
                  AND gl_account IN ({_placeholders(accounts)})
                  AND partner_company IS NOT NULL
                  AND partner_company <> company_code
            ) ic
            GROUP BY entity_a, entity_b
            HAVING ABS(SUM(amount_group)) > ?
            ORDER BY entity_a, entity_b
            """,
            [ctx.run_id, *accounts, _tolerance(ctx, "intercompany_group")],
        )
        group_ccy = str(ctx.config["group_currency"])
        for entity_a, entity_b, net, side_a, side_b in rows:
            findings.append(
                self.finding(
                    ctx,
                    check_code="IC_NOT_NET_ZERO",
                    severity=Severity.BLOCKER,
                    record_key=f"{entity_a}<>{entity_b}",
                    message=(
                        f"Intercompany position {entity_a} <> {entity_b} does not eliminate: "
                        f"{entity_a} {money(to_decimal(side_a))}, {entity_b} "
                        f"{money(to_decimal(side_b))}, net {money(to_decimal(net))} {group_ccy}"
                    ),
                    attributes=("company_code", "partner_company", "amount_group"),
                    details={
                        "side_a_group": money(to_decimal(side_a)),
                        "side_b_group": money(to_decimal(side_b)),
                        "net_group": money(to_decimal(net)),
                    },
                    scope=FindingScope.AGGREGATE,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Record-level controls (Python)
# ---------------------------------------------------------------------------


class FxRateRule(RecordRule[SubLedgerEntry]):
    rule_id = "FIN-FX-001"
    title = "FX rate cut-off, staleness and translation integrity"
    control_objective = (
        "Foreign currency lines use a current rate consistent with the reference closing "
        "rate, and the group currency amount equals amount_txn x fx_rate."
    )
    framework_refs = ("IAS 21.21-22", "SOX 404 ITAC", "BCBS 239 P3/P7")
    input_attributes = (
        "currency",
        "fx_rate",
        "fx_rate_date",
        "posting_date",
        "amount_txn",
        "amount_group",
    )
    remediation_hint = (
        "Re-derive the rate from the approved rate table for the posting date (rate type M) "
        "and re-translate the line in the source system."
    )

    def check(self, record: SubLedgerEntry, ctx: Ctx) -> list[Finding]:
        fx_cfg: Mapping[str, Any] = ctx.config["fx"]
        group_ccy = str(ctx.config["group_currency"])
        findings: list[Finding] = []
        key = record.entry_id
        if record.currency == group_ccy:
            if record.fx_rate != Decimal(1):
                findings.append(
                    self.finding(
                        ctx,
                        check_code="FX_GROUP_RATE_NOT_UNITY",
                        severity=Severity.BLOCKER,
                        record_key=key,
                        message=f"Group currency line carries rate {record.fx_rate}, expected 1",
                        attributes=("currency", "fx_rate"),
                    )
                )
        else:
            reference = fx_cfg["reference_rates"].get(record.currency)
            if reference is None:
                findings.append(
                    self.finding(
                        ctx,
                        check_code="FX_NO_REFERENCE_RATE",
                        severity=Severity.BLOCKER,
                        record_key=key,
                        message=f"No approved reference rate for {record.currency}",
                        attributes=("currency",),
                    )
                )
            else:
                ref = to_decimal(reference)
                deviation = abs(record.fx_rate / ref - 1) * 100
                severity: Severity | None = None
                if deviation > to_decimal(fx_cfg["deviation_blocker_pct"]):
                    severity = Severity.BLOCKER
                elif deviation > to_decimal(fx_cfg["deviation_warning_pct"]):
                    severity = Severity.WARNING
                if severity is not None:
                    findings.append(
                        self.finding(
                            ctx,
                            check_code="FX_RATE_DEVIATION",
                            severity=severity,
                            record_key=key,
                            message=(
                                f"{record.currency} rate {record.fx_rate} deviates "
                                f"{deviation.quantize(CENT)}% from reference {ref}"
                            ),
                            attributes=("currency", "fx_rate"),
                            details={
                                "fx_rate": str(record.fx_rate),
                                "reference_rate": str(ref),
                                "deviation_pct": str(deviation.quantize(CENT)),
                            },
                        )
                    )
            age = (record.posting_date - record.fx_rate_date).days
            if age < 0:
                findings.append(
                    self.finding(
                        ctx,
                        check_code="FX_RATE_LOOKAHEAD",
                        severity=Severity.BLOCKER,
                        record_key=key,
                        message=(
                            f"Rate dated {record.fx_rate_date} is later than posting date "
                            f"{record.posting_date}"
                        ),
                        attributes=("fx_rate_date", "posting_date"),
                    )
                )
            elif age > int(fx_cfg["max_rate_age_days"]):
                findings.append(
                    self.finding(
                        ctx,
                        check_code="FX_RATE_STALE",
                        severity=Severity.BLOCKER,
                        record_key=key,
                        message=(
                            f"Rate dated {record.fx_rate_date} is {age} days older than posting "
                            f"date {record.posting_date} (limit {fx_cfg['max_rate_age_days']})"
                        ),
                        attributes=("fx_rate_date", "posting_date"),
                        details={"rate_age_days": age},
                    )
                )
        expected = (record.amount_txn * record.fx_rate).quantize(CENT, rounding=ROUND_HALF_UP)
        difference = record.amount_group - expected
        if abs(difference) > Decimal(str(_tolerance(ctx, "fx_translation_group"))):
            findings.append(
                self.finding(
                    ctx,
                    check_code="FX_TRANSLATION_MISMATCH",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=(
                        f"Group amount {money(record.amount_group)} differs from "
                        f"{money(record.amount_txn)} x {record.fx_rate} = {money(expected)} "
                        f"by {money(difference)}"
                    ),
                    attributes=("amount_txn", "fx_rate", "amount_group"),
                    details={
                        "expected_group": money(expected),
                        "recorded_group": money(record.amount_group),
                        "difference_group": money(difference),
                    },
                )
            )
        return findings


class MasterDataMappingRule(RecordRule[SubLedgerEntry]):
    rule_id = "FIN-MD-001"
    title = "Chart of accounts and cost centre mapping"
    control_objective = (
        "Every line maps to a known company code, an active GL account and, where the account "
        "requires it, a cost centre assigned to the same company code."
    )
    framework_refs = ("SOX 404 ITGC master data", "BCBS 239 P2/P4")
    input_attributes = ("company_code", "gl_account", "cost_centre")
    remediation_hint = (
        "Map the account or cost centre in the ERP master data (or correct the derivation "
        "rule in the interface) and re-run the batch; do not post to a default object."
    )

    def check(self, record: SubLedgerEntry, ctx: Ctx) -> list[Finding]:
        findings: list[Finding] = []
        key = record.entry_id
        companies: Mapping[str, Any] = ctx.config["companies"]
        if record.company_code not in companies:
            findings.append(
                self.finding(
                    ctx,
                    check_code="COMPANY_CODE_UNKNOWN",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=f"Company code {record.company_code} is not in the close scope",
                    attributes=("company_code",),
                )
            )
        chart: Mapping[str, Mapping[str, Any]] = ctx.config["chart_of_accounts"]
        account = chart.get(record.gl_account)
        if account is None:
            findings.append(
                self.finding(
                    ctx,
                    check_code="GL_ACCOUNT_UNMAPPED",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=f"GL account {record.gl_account} is not in the group chart of accounts",
                    attributes=("gl_account",),
                )
            )
            return findings
        valid_centres = set(ctx.config["cost_centres"].get(record.company_code, []))
        if account.get("requires_cost_centre") and record.cost_centre is None:
            findings.append(
                self.finding(
                    ctx,
                    check_code="COST_CENTRE_MISSING",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=f"Account {record.gl_account} requires a cost centre",
                    attributes=("gl_account", "cost_centre"),
                )
            )
        elif record.cost_centre is not None and record.cost_centre not in valid_centres:
            findings.append(
                self.finding(
                    ctx,
                    check_code="COST_CENTRE_UNMAPPED",
                    severity=Severity.BLOCKER,
                    record_key=key,
                    message=(
                        f"Cost centre {record.cost_centre} is not assigned to company code "
                        f"{record.company_code}"
                    ),
                    attributes=("company_code", "cost_centre"),
                )
            )
        return findings


class PostingPeriodRule(RecordRule[SubLedgerEntry]):
    rule_id = "FIN-PER-001"
    title = "Posting period cut-off"
    control_objective = "Lines fall inside the open fiscal period being closed (cut-off)."
    framework_refs = ("SOX 404 cut-off assertion", "Swiss CO Art. 958b")
    input_attributes = ("posting_date", "fiscal_period")
    remediation_hint = (
        "Move the line to the correct period batch or obtain a documented period-end "
        "accrual decision from the controller."
    )

    def check(self, record: SubLedgerEntry, ctx: Ctx) -> list[Finding]:
        period: Mapping[str, Any] = ctx.config["fiscal_period"]
        start = date.fromisoformat(str(period["start"]))
        end = date.fromisoformat(str(period["end"]))
        findings: list[Finding] = []
        if record.fiscal_period != str(period["id"]):
            findings.append(
                self.finding(
                    ctx,
                    check_code="PERIOD_MISMATCH",
                    severity=Severity.BLOCKER,
                    record_key=record.entry_id,
                    message=(
                        f"Fiscal period {record.fiscal_period} is not the period in close "
                        f"({period['id']})"
                    ),
                    attributes=("fiscal_period",),
                )
            )
        if not start <= record.posting_date <= end:
            findings.append(
                self.finding(
                    ctx,
                    check_code="POSTING_DATE_OUTSIDE_PERIOD",
                    severity=Severity.BLOCKER,
                    record_key=record.entry_id,
                    message=(
                        f"Posting date {record.posting_date} lies outside period "
                        f"{period['id']} ({start} to {end})"
                    ),
                    attributes=("posting_date", "fiscal_period"),
                )
            )
        return findings


class SelfApprovalRule(RecordRule[SubLedgerEntry]):
    rule_id = "FIN-SOD-001"
    title = "Posting approval present and independent of the maker"
    control_objective = (
        "Manual and intercompany journals carry an approver, and no user approves their own "
        "posting."
    )
    framework_refs = ("SOX 404 SoD", "Swiss CO Art. 728a", "COSO 2013 Principle 10")
    input_attributes = ("maker_id", "approver_id", "source_ledger")
    remediation_hint = (
        "Route the journal to an independent approver from the authorisation matrix and "
        "review whether the posting user's approval authority should be withdrawn."
    )

    def check(self, record: SubLedgerEntry, ctx: Ctx) -> list[Finding]:
        required: set[str] = set(ctx.config["sod"]["approval_required_sources"])
        if record.approver_id is None:
            if record.source_ledger in required:
                return [
                    self.finding(
                        ctx,
                        check_code="APPROVAL_MISSING",
                        severity=Severity.BLOCKER,
                        record_key=record.entry_id,
                        message=f"{record.source_ledger} journal line has no approver",
                        attributes=("approver_id", "source_ledger"),
                        details={"maker_id": record.maker_id},
                    )
                ]
            return []
        if record.approver_id == record.maker_id:
            return [
                self.finding(
                    ctx,
                    check_code="SELF_APPROVAL",
                    severity=Severity.BLOCKER,
                    record_key=record.entry_id,
                    message=(
                        f"User {record.maker_id} posted and approved journal {record.journal_id}"
                    ),
                    attributes=("maker_id", "approver_id"),
                    details={"maker_id": record.maker_id, "approver_id": record.approver_id},
                )
            ]
        return []


class ToxicRoleCombinationRule(RecordRule[SubLedgerEntry]):
    rule_id = "FIN-SOD-002"
    title = "Toxic role combinations of the posting user"
    control_objective = (
        "No posting is made by a user whose role assignment combines incompatible duties "
        "defined in the SoD conflict matrix."
    )
    framework_refs = ("SOX 404 SoD", "COSO 2013 Principle 10", "Swiss CO Art. 728a")
    input_attributes = ("maker_id", "maker_roles")
    remediation_hint = (
        "Remove one of the conflicting roles in the identity and access system, or document "
        "a time-bound mitigating control with compensating review of this user's postings."
    )

    def check(self, record: SubLedgerEntry, ctx: Ctx) -> list[Finding]:
        roles = set(record.maker_roles)
        findings: list[Finding] = []
        for pair in ctx.config["sod"]["toxic_role_pairs"]:
            first, second = (str(r) for r in pair["roles"])
            if first in roles and second in roles:
                findings.append(
                    self.finding(
                        ctx,
                        check_code=f"TOXIC_PAIR_{pair['id']}",
                        severity=Severity(str(pair["severity"])),
                        record_key=record.entry_id,
                        message=(
                            f"User {record.maker_id} holds {first} and {second}: {pair['risk']}"
                        ),
                        attributes=("maker_id", "maker_roles"),
                        details={"maker_id": record.maker_id, "conflict_id": str(pair["id"])},
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Pack definition
# ---------------------------------------------------------------------------


@register_pack
class FinancePreCloseIcsPack(RulePack[SubLedgerEntry]):
    pack_id = PackId.FINANCE_PRECLOSE_ICS
    display_name = "Pack A: Finance Sub-Ledger-to-GL & ICS Pre-Close"
    run_prefix = "FIN"
    default_source = "finance_subledger_batch.csv"
    config_file = "finance_preclose_ics.yaml"
    staging = StagingSpec(
        table="stg_finance_subledger",
        ddl=_STAGING_DDL,
        columns=_STAGING_COLUMNS,
        key_column="entry_id",
    )
    lineage = (
        LineageSpec("journal_id", "SAP_S4HANA/ACDOCA.BELNR"),
        LineageSpec("company_code", "SAP_S4HANA/ACDOCA.RBUKRS", critical_data_element=True),
        LineageSpec("posting_date", "SAP_S4HANA/ACDOCA.BUDAT", critical_data_element=True),
        LineageSpec("fiscal_period", "SAP_S4HANA/ACDOCA.POPER", critical_data_element=True),
        LineageSpec("gl_account", "SAP_S4HANA/ACDOCA.RACCT", critical_data_element=True),
        LineageSpec("cost_centre", "SAP_S4HANA/ACDOCA.RCNTR"),
        LineageSpec("partner_company", "SAP_S4HANA/ACDOCA.RASSC", critical_data_element=True),
        LineageSpec("currency", "SAP_S4HANA/ACDOCA.RWCUR", critical_data_element=True),
        LineageSpec("amount_txn", "SAP_S4HANA/ACDOCA.WSL", critical_data_element=True),
        LineageSpec("fx_rate", "SAP_S4HANA/BKPF.KURSF", critical_data_element=True),
        LineageSpec("fx_rate_date", "SAP_S4HANA/BKPF.WWERT"),
        LineageSpec("amount_group", "SAP_S4HANA/ACDOCA.KSL", critical_data_element=True),
        LineageSpec("maker_id", "SAP_S4HANA/BKPF.USNAM"),
    )

    def build_rules(self) -> Sequence[Rule[SubLedgerEntry]]:
        return (
            JournalBalanceRule(),
            TrialBalanceNetZeroRule(),
            SubledgerReconciliationRule(),
            SuspenseClearanceRule(),
            IntercompanyNetZeroRule(),
            FxRateRule(),
            MasterDataMappingRule(),
            PostingPeriodRule(),
            SelfApprovalRule(),
            ToxicRoleCombinationRule(),
        )

    def parse_record(self, row: Mapping[str, object]) -> SubLedgerEntry:
        return SubLedgerEntry.model_validate(dict(row))

    def to_staging_row(self, record: SubLedgerEntry) -> tuple[object, ...]:
        return (
            record.entry_id,
            record.batch_id,
            record.journal_id,
            record.company_code,
            record.posting_date,
            record.fiscal_period,
            record.source_ledger,
            record.gl_account,
            record.cost_centre,
            record.partner_company,
            record.currency,
            record.amount_txn,
            record.fx_rate,
            record.fx_rate_date,
            record.amount_group,
            record.maker_id,
            record.approver_id,
            "|".join(record.maker_roles),
            record.description,
        )
