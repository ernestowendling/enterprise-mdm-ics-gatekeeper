# Control matrix mapping

Every control is automated, preventive (it runs before posting or publication) and operates on
each submitted batch. Each run records the population tested and the exceptions raised
(`rule_executions`), so a zero-exception run is evidence of operation, not an absence of
evidence.

Severity semantics:

- `BLOCKER`: hard gate stop. No actor can approve the run; remediation produces a new run.
- `WARNING`: release requires an independent checker's documented exception (four-eyes).

## Shared control core

| Control | Objective | Framework mapping | Evidence |
| --- | --- | --- | --- |
| SCHEMA-001 Ingestion record contract | Records conform to the Pydantic contract; duplicate keys rejected; rejections are findings, never silent drops | SOX 404 ITAC (input completeness and accuracy), BCBS 239 P4 | `rule_results`, `runs.rejected_count` |
| Four-eyes workflow | Maker cannot approve own run; checker holds approver role and no incompatible role; BLOCKER runs cannot be approved; exceptions need written justification | SOX 404 SoD, Swiss CO Art. 728a (ICS existence), COSO 2013 Principle 10, EU AI Act Art. 14 (human oversight) | `workflow_events` bound to `audit_log` hashes |
| Audit hash chain | Evidence is tamper-evident; edits, re-hashed edits, deletions and truncation are detectable | SOX 404 ITGC (change and access), BCBS 239 P3, GeBüV (Swiss accounting records ordinance) integrity | `ControlStore.verify_chain()`, evidence pack `audit_chain` |
| Run fingerprinting | Runs are re-performable: input and policy are hashed | BCBS 239 P3/P6, external audit re-performance | `runs.input_sha256`, `runs.config_sha256` |
| Attribute-level lineage | Each downstream attribute traces to its source column and the controls that gate it | BCBS 239 P2 (data architecture), P3 (accuracy), P6 (adaptability) | `lineage_edges`, `/lineage/{run_id}` |

## Pack A: Finance sub-ledger-to-GL pre-close (ICS/SOX)

| Control | Check codes | Severity | Objective | Framework mapping | Accountable role |
| --- | --- | --- | --- | --- | --- |
| FIN-TB-001 Journal double-entry balance | `JOURNAL_NOT_BALANCED`, `MULTI_CURRENCY_JOURNAL`, `CROSS_COMPANY_JOURNAL` | BLOCKER | Each journal nets to zero in transaction currency within one company code | SOX 404, Swiss CO Art. 957a, BCBS 239 P3 | GL accountant |
| FIN-TB-002 Trial balance net-zero | `TB_NOT_NET_ZERO` | BLOCKER | Batch leaves each company code's trial balance balanced in group currency (DuckDB SQL aggregation) | SOX 404 financial close, Swiss CO Art. 958c, BCBS 239 P3/P7 | Close manager |
| FIN-TB-003 Sub-ledger to GL tie-out | `SUBLEDGER_GL_DIFFERENCE` | BLOCKER | Reconciliation accounts are posted only from their sub-ledger; difference and offending entries reported | SOX 404 account reconciliation, Swiss CO Art. 728a, BCBS 239 P3 | AP/AR team lead |
| FIN-TB-004 Suspense clearance | `SUSPENSE_NOT_CLEARED` | BLOCKER | Suspense accounts carry a nil balance per company code at pre-close | SOX 404 financial close, Swiss CO Art. 957a, BCBS 239 P4 | GL accountant |
| FIN-IC-001 Intercompany net-zero | `IC_NOT_NET_ZERO`, `IC_PARTNER_INVALID` | BLOCKER | Intercompany receivables and payables per entity pair eliminate in group currency | SOX 404 consolidation, IFRS 10 B86, BCBS 239 P3/P8 | Group consolidation |
| FIN-FX-001 FX cut-off and translation | `FX_RATE_STALE`, `FX_RATE_LOOKAHEAD`, `FX_RATE_DEVIATION`, `FX_NO_REFERENCE_RATE`, `FX_GROUP_RATE_NOT_UNITY`, `FX_TRANSLATION_MISMATCH` | BLOCKER; deviation between warning and blocker thresholds is WARNING | Rates are current, consistent with the approved reference rate, and translation arithmetic holds | IAS 21.21-22, SOX 404 ITAC, BCBS 239 P3/P7 | Treasury / GL accountant |
| FIN-MD-001 CoA and cost centre mapping | `COMPANY_CODE_UNKNOWN`, `GL_ACCOUNT_UNMAPPED`, `COST_CENTRE_MISSING`, `COST_CENTRE_UNMAPPED` | BLOCKER | Lines map to in-scope company codes, active accounts and company-assigned cost centres | SOX 404 ITGC master data, BCBS 239 P2/P4 | Finance master data |
| FIN-PER-001 Posting period cut-off | `PERIOD_MISMATCH`, `POSTING_DATE_OUTSIDE_PERIOD` | BLOCKER | Lines belong to the period in close | SOX 404 cut-off assertion, Swiss CO Art. 958b | Close manager |
| FIN-SOD-001 Independent approval | `SELF_APPROVAL`, `APPROVAL_MISSING` | BLOCKER | Manual and intercompany journals are approved by someone other than the poster | SOX 404 SoD, Swiss CO Art. 728a, COSO 2013 Principle 10 | Controller |
| FIN-SOD-002 Toxic role combinations | `TOXIC_PAIR_P2P-01`, `TOXIC_PAIR_R2R-01`, `TOXIC_PAIR_O2C-01` | Per conflict matrix (BLOCKER or WARNING) | Postings by users holding incompatible duties are stopped or escalated | SOX 404 SoD, COSO 2013 Principle 10, Swiss CO Art. 728a | IAM owner / Controller |

### Target attribute lineage (SAP S/4HANA)

| Source column | Target | Critical data element |
| --- | --- | --- |
| `journal_id` | `ACDOCA.BELNR` | No |
| `company_code` | `ACDOCA.RBUKRS` | Yes |
| `posting_date` | `ACDOCA.BUDAT` | Yes |
| `fiscal_period` | `ACDOCA.POPER` | Yes |
| `gl_account` | `ACDOCA.RACCT` | Yes |
| `cost_centre` | `ACDOCA.RCNTR` | No |
| `partner_company` | `ACDOCA.RASSC` | Yes |
| `currency` | `ACDOCA.RWCUR` | Yes |
| `amount_txn` | `ACDOCA.WSL` | Yes |
| `amount_group` | `ACDOCA.KSL` | Yes |
| `fx_rate` | `BKPF.KURSF` | Yes |
| `fx_rate_date` | `BKPF.WWERT` | No |
| `maker_id` | `BKPF.USNAM` | No |

## Pack B: Travel retail GS1/GDSN and dangerous goods

| Control | Check codes | Severity | Objective | Framework mapping | Accountable role |
| --- | --- | --- | --- | --- | --- |
| TR-GTIN-001 GTIN-14 integrity | `UNIT_GTIN_FORMAT`, `UNIT_GTIN_CHECK_DIGIT`, `UNIT_GTIN_INDICATOR`, `CASE_GTIN_*`, `HIERARCHY_GTIN_REUSED` | BLOCKER | 14-digit GS1 keys with valid Modulo-10 check digit and level-appropriate indicator | GS1 General Specifications 7.9, GS1 GDSN 3.1 Validation Rules | Master data steward |
| TR-GTIN-002 GTIN uniqueness | `UNIT_GTIN_DUPLICATE`, `CASE_GTIN_DUPLICATE` | BLOCKER | One GTIN identifies one trade item per level (DuckDB SQL) | GS1 GTIN Management Standard | Master data steward |
| TR-MDM-001 Golden record consistency | `GOLDEN_RECORD_CONFLICT` | BLOCKER | Master attributes identical across all listings of a SKU (DuckDB SQL) | GS1 GDSN 3.1 synchronisation, DAMA-DMBOK MDM | MDM product owner |
| TR-DG-001 UN1266 Class 3 completeness | `DG_FLASHPOINT_MISSING`, `DG_UN_NUMBER_*`, `DG_CLASS_MISMATCH`, `DG_PACKING_GROUP_*` (BLOCKER); `DG_REGULATION_SCOPE`, `DG_SDS_MISSING`, `DG_OVER_CLASSIFIED`, `DG_FLASHPOINT_IMPLAUSIBLE` (WARNING) | Mixed | Alcohol-based perfumery above the ABV screening threshold carries flashpoint, UN1266, Class 3, derived packing group, SDS and IATA/IMDG codes | IATA DGR Class 3, IMDG Code Class 3, UN Model Regulations 2.3.2 | DG specialist |
| TR-HIER-001 Hierarchy weights | `UNIT_GROSS_BELOW_NET`, `CASE_WEIGHT_BELOW_CONTENTS`, `PALLET_WEIGHT_BELOW_CONTENTS` (BLOCKER); `CASE_WEIGHT_OVERHEAD`, `PALLET_WEIGHT_DEVIATION` (WARNING) | Mixed | Unit, case and pallet weights are physically consistent | GS1 Package Measurement Rules, GS1 GDSN 3.1 Validation Rules | Packaging engineer |
| TR-HIER-002 Hierarchy dimensions | `CASE_VOLUME_INSUFFICIENT` (BLOCKER); `CASE_FILL_RATIO_LOW`, `PALLET_HEIGHT_EXCEEDED` (WARNING) | Mixed | A case can hold its units; void fill and pallet height within limits | GS1 Package Measurement Rules | Packaging engineer |
| TR-MKT-001 Market eligibility | `SOLD_TO_UNKNOWN`, `SOLD_TO_BLOCKED`, `SOLD_TO_CATEGORY_RESTRICTED`, `SHIP_TO_UNKNOWN`, `SHIP_TO_NOT_LINKED_TO_SOLD_TO`, `MARKET_NOT_AUTHORISED`, `DG_NOT_ACCEPTED_AT_SHIP_TO` | BLOCKER | Listings go only to active Sold-Tos, through linked Ship-Tos, in authorised markets, and DG only where accepted | GS1 GDSN 3.1 target market, customer master governance, IATA DGR Class 3 | Commercial compliance |
| TR-CUS-001 Customs classification | `HS_CODE_MISSING`, `HS_CODE_FORMAT`, `HS_HEADING_MISMATCH`, `ORIGIN_MISSING` | WARNING | HS code under the heading expected for the category; origin present | WCO HS Chapter 33, Union Customs Code Art. 60 | Customs specialist |

### Dangerous goods screening logic

| Condition | Outcome |
| --- | --- |
| ABV above the configured screening threshold (24.0%) | In Class 3 scope |
| ABV equal to 0 and declared flashpoint at or below 60 °C | In Class 3 scope (solvent-based formulation) |
| Aqueous alcohol at or below the threshold | Outside screening scope |
| In scope, flashpoint missing | BLOCKER `DG_FLASHPOINT_MISSING` |
| In scope, flashpoint below 23 °C | Packing group II required |
| In scope, flashpoint from 23 °C up to 60 °C | Packing group III required |

Packing group I (initial boiling point at or below 35 °C) is not expected for perfumery and is
therefore not derived. Thresholds are policy settings; legal classification remains with the
DG-qualified function.

### Target attribute lineage (GS1 GDSN)

Targets use `tradeItemUnitDescriptorCode` levels (`BASE_UNIT_OR_EACH`, `CASE`, `PALLET`) with
GDSN attribute names. Verify names against the GDSN Trade Item BMS release in use before
productive mapping.

| Source column | Target | Critical data element |
| --- | --- | --- |
| `unit_gtin` | `BASE_UNIT_OR_EACH.gtin` | Yes |
| `case_gtin` | `CASE.gtin` | Yes |
| `unit_net_weight_g` | `BASE_UNIT_OR_EACH.netWeight` | Yes |
| `unit_gross_weight_g` | `BASE_UNIT_OR_EACH.grossWeight` | Yes |
| `units_per_case` | `CASE.quantityOfNextLowerLevelTradeItem` | Yes |
| `case_gross_weight_kg` | `CASE.grossWeight` | Yes |
| `cases_per_pallet` | `PALLET.quantityOfNextLowerLevelTradeItem` | No |
| `pallet_gross_weight_kg` | `PALLET.grossWeight` | No |
| `alcohol_by_volume_pct` | `BASE_UNIT_OR_EACH.percentageOfAlcoholByVolume` | Yes |
| `flashpoint_c` | `BASE_UNIT_OR_EACH.flashPointTemperature` | Yes |
| `un_number` | `BASE_UNIT_OR_EACH.unitedNationsDangerousGoodsNumber` | Yes |
| `dg_class` | `BASE_UNIT_OR_EACH.classOfDangerousGoods` | Yes |
| `packing_group` | `BASE_UNIT_OR_EACH.dangerousGoodsPackingGroup` | Yes |
| `dg_regulations` | `BASE_UNIT_OR_EACH.dangerousGoodsRegulationCode` | No |
| `hs_code` | `BASE_UNIT_OR_EACH.importClassificationValue` | No |
| `country_of_origin` | `BASE_UNIT_OR_EACH.countryOfOrigin` | No |
| `target_markets` | `BASE_UNIT_OR_EACH.targetMarketCountryCode` | Yes |
| `sold_to_code`, `ship_to_code` | `ERP_SD/ASSORTMENT_LISTING` | No |
