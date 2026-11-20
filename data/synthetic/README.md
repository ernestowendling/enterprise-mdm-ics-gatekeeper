# Synthetic datasets

Both datasets are synthetic. Company names, brands, users, Sold-To and Ship-To codes are
fictitious; airport codes are used only as location identifiers. All GTINs use the GS1 prefix
952, which GS1 reserves for demonstrations and examples.

Each file has 40 rows: clean records plus planted defects. The tables below are the expected
findings and act as the test oracle for `tests/`.

## `finance_subledger_batch.csv`

November 2026 pre-close interface batch for three company codes: `CH10` (CHF), `SE10` (SEK) and
`LV10` (EUR). Group currency is EUR. Amounts are signed (debit positive). Journals
`JE-2026-11-0001` to `JE-2026-11-0005` (entries `SL-0001` to `SL-0010`) are clean, including an
intercompany pair `CH10`/`LV10` that eliminates exactly.

| Journal | Planted defect | Expected findings |
| --- | --- | --- |
| 0006 / 0007 | `CH10` books 50,055.00 EUR receivable from `SE10`; `SE10` books 48,554.70 EUR payable | `FIN-IC-001` `IC_NOT_NET_ZERO` on `CH10<>SE10` (net 1,500.30) |
| 0008 | Rate dated 16 days before posting | `FIN-FX-001` `FX_RATE_STALE` on `SL-0015`, `SL-0016` |
| 0009 | SEK rate 0.0905 vs reference 0.0870 (4.02%) | `FIN-FX-001` `FX_RATE_DEVIATION` BLOCKER on `SL-0017`, `SL-0018` |
| 0010 | CHF rate 1.0745 vs reference 1.0650 (0.89%) | `FIN-FX-001` `FX_RATE_DEVIATION` WARNING on `SL-0019`, `SL-0020` |
| 0011 | Group amount 1,656.00 instead of 1,566.00 (transposed digits) | `FIN-FX-001` `FX_TRANSLATION_MISMATCH` on `SL-0021`; `FIN-TB-002` on `SE10` (net 90.00) |
| 0012 | Unidentified receipt parked in suspense | `FIN-TB-004` `SUSPENSE_NOT_CLEARED` on `LV10/199999` |
| 0013 | Cost centre `CC-CH-9999` not assigned to `CH10` | `FIN-MD-001` `COST_CENTRE_UNMAPPED` on `SL-0025` |
| 0014 | Account 655000 not in the chart of accounts | `FIN-MD-001` `GL_ACCOUNT_UNMAPPED` on `SL-0027` |
| 0015 | Maker approves own manual accrual | `FIN-SOD-001` `SELF_APPROVAL` on `SL-0029`, `SL-0030` |
| 0016 | Maker holds `VENDOR_MASTER_MAINTAIN` and `AP_PAYMENT_RELEASE` | `FIN-SOD-002` `TOXIC_PAIR_P2P-01` BLOCKER on `SL-0031`, `SL-0032` |
| 0017 | Maker holds `AR_CREDIT_NOTE_ISSUE` and `AR_CASH_APPLICATION` | `FIN-SOD-002` `TOXIC_PAIR_O2C-01` WARNING on `SL-0033`, `SL-0034` |
| 0018 | Debit 6,500.00 vs credit 6,050.00 (transposed digits) | `FIN-TB-001` `JOURNAL_NOT_BALANCED` (450.00 CHF); `FIN-TB-002` on `CH10` (479.25 EUR) |
| 0019 | Manual GL posting to the AP reconciliation account | `FIN-TB-003` `SUBLEDGER_GL_DIFFERENCE` on `SE10/200000` (1,218.00, entry `SL-0037`) |
| 0020 | December posting date in the November batch | `FIN-PER-001` `POSTING_DATE_OUTSIDE_PERIOD` on `SL-0039`, `SL-0040` |

Totals: 23 findings (19 BLOCKER, 4 WARNING). Gate decision: `BLOCKED`.

## `travel_retail_sku_assortment.csv`

Prestige beauty assortment listed to airside duty-free, arrivals duty-free and inflight
Ship-Tos in Switzerland, the Nordics and the Baltics. Listings `L-0001` to `L-0022` are clean,
including an 18% ABV facial mist to an inflight Ship-To that refuses dangerous goods and a 20%
ABV hair mist, both below the screening threshold.

| Listing | SKU | Planted defect | Expected findings |
| --- | --- | --- | --- |
| L-0023 | S-10004 | Unit GTIN check digit altered | `TR-GTIN-001` `UNIT_GTIN_CHECK_DIGIT` |
| L-0024 | S-30004 | Unit GTIN check digit altered | `TR-GTIN-001` `UNIT_GTIN_CHECK_DIGIT` |
| L-0025 | S-10007 | Case GTIN check digit altered | `TR-GTIN-001` `CASE_GTIN_CHECK_DIGIT` |
| L-0026 | S-10010 | Target markets `CH`, `SE`; listed in Riga (`LV`) | `TR-MKT-001` `MARKET_NOT_AUTHORISED` |
| L-0027 | S-10002 | Second listing carries unit gross weight 340 g instead of 310 g | `TR-MDM-001` `GOLDEN_RECORD_CONFLICT` |
| L-0028 | S-10005 | Sold-To `ST-4409` on compliance hold | `TR-MKT-001` `SOLD_TO_BLOCKED` |
| L-0029 | S-10008 | Sold-To `ST-5120` restricted for fragrance | `TR-MKT-001` `SOLD_TO_CATEGORY_RESTRICTED` |
| L-0030 | S-10009 | Class 3 fragrance to inflight Ship-To without DG acceptance | `TR-MKT-001` `DG_NOT_ACCEPTED_AT_SHIP_TO` |
| L-0031 | S-10011 | Ship-To `ARN-T5-AS02` billed to the wrong Sold-To | `TR-MKT-001` `SHIP_TO_NOT_LINKED_TO_SOLD_TO` |
| L-0032 | S-10013 | 80% ABV, flashpoint missing | `TR-DG-001` `DG_FLASHPOINT_MISSING` |
| L-0033 | S-10014 | 77% ABV, flashpoint missing | `TR-DG-001` `DG_FLASHPOINT_MISSING` |
| L-0034 | S-10015 | Flashpoint 18 °C declared with packing group III | `TR-DG-001` `DG_PACKING_GROUP_MISMATCH` |
| L-0035 | S-10016 | No SDS reference; IATA only, IMDG missing | `TR-DG-001` `DG_SDS_MISSING`, `DG_REGULATION_SCOPE` (WARNING) |
| L-0036 | S-20006 | Unit gross weight 40 g below net weight 52 g | `TR-HIER-001` `UNIT_GROSS_BELOW_NET` |
| L-0037 | S-20007 | Case 0.950 kg holds 24 x 48 g = 1.152 kg | `TR-HIER-001` `CASE_WEIGHT_BELOW_CONTENTS`; `PALLET_WEIGHT_DEVIATION` (WARNING) as the measured pallet no longer reconciles |
| L-0038 | S-30005 | Case too small for 12 units; reuses the unit GTIN of S-20007 | `TR-HIER-002` `CASE_VOLUME_INSUFFICIENT`; `TR-GTIN-002` `UNIT_GTIN_DUPLICATE` |
| L-0039 | S-40003 | Oversized case, 1,720 mm pallet, origin missing | `TR-HIER-002` `CASE_FILL_RATIO_LOW`, `PALLET_HEIGHT_EXCEEDED`; `TR-CUS-001` `ORIGIN_MISSING` (all WARNING) |
| L-0040 | S-20008 | Skincare declared as UN1266 Class 3 with fragrance HS code | `TR-DG-001` `DG_OVER_CLASSIFIED`; `TR-CUS-001` `HS_HEADING_MISMATCH` (WARNING) |

Totals: 24 findings (16 BLOCKER, 8 WARNING). Gate decision: `BLOCKED`.
