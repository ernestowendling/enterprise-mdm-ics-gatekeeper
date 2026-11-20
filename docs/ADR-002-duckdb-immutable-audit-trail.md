# ADR-002: Embedded DuckDB control store with a SHA-256 hash-chained audit trail

| Field | Value |
| --- | --- |
| Status | Accepted |
| Date | 2026-11-20 |
| Decision owner | Enterprise Architecture (Data and AI) |
| TOGAF ADM | Phase C (Data Architecture), Phase D (Technology Architecture) |
| Architecture principles | Evidence by default; Portability; Least infrastructure for the job |

## Context

The gate needs an analytical engine for set-based controls (trial balance net-zero by company
code, intercompany elimination, GTIN uniqueness, golden record consistency) and a store for
control evidence: findings, rule executions, attribute-level lineage, maker/checker events and
an audit log that an auditor can trust.

The reference implementation must run on a laptop and in CI without external services, while
mapping cleanly onto the lakehouse platforms used in regulated institutions (Microsoft Fabric,
Databricks, Snowflake).

## Decision

1. Use embedded DuckDB as both the analytical engine and the control store.
2. Expose only an append-only API (`ControlStore`): there is no method that updates or deletes
   evidence. Workflow state is event-sourced from `workflow_events`, never updated in place.
3. Make the audit log tamper-evident with a SHA-256 hash chain. Each event hash covers its
   sequence number, identifiers, actor, canonical JSON payload, timestamp and the previous
   event's hash, starting from a 64-zero genesis hash.
4. Bind every maker/checker event to the chain by storing the audit event hash on the workflow
   event, and write both in one DuckDB transaction.
5. Fingerprint every run with the SHA-256 of its canonical input and of the exact policy bytes.

## Verification semantics

`ControlStore.verify_chain()` recomputes the chain in sequence order and reports the first
broken sequence number:

| Tampering | Detection |
| --- | --- |
| Payload or actor edited in place | Recomputed hash differs from stored hash at that event |
| Event edited and re-hashed | Successor's `prev_hash` no longer matches |
| Event deleted | Sequence gap |
| Most recent events truncated | Head hash differs from an externally anchored head (`expected_head_hash`) |

## Consequences

| Trade-off | Position taken |
| --- | --- |
| Preventive vs detective immutability | DuckDB has no triggers or row-level grants, so immutability here is detective (tamper-evident), not preventive. |
| Concurrency vs simplicity | Single writer per database file, serialised by a re-entrant lock. Adequate for batch gates; not a multi-tenant OLTP store. |
| Portability vs platform features | Plain SQL (no DuckDB-only syntax in rules) keeps the controls portable to Spark SQL, T-SQL and Snowflake SQL. |
| Lock-in | None: the database is a single file; evidence exports as JSON, CSV and Markdown. |

## Production target mapping

| Concern | Reference implementation | Regulated production target |
| --- | --- | --- |
| Staging and controls | DuckDB tables | Fabric Lakehouse (Delta) with Spark SQL / Warehouse T-SQL, Databricks Delta with Unity Catalog, or Snowflake |
| Immutability | Hash chain, detective | Hash chain plus WORM storage (S3 Object Lock in compliance mode, Azure immutable blob policies) |
| Chain anchoring | `expected_head_hash` parameter | Daily head hash published to an independent system (GRC tool or a signed ticket) |
| Evidence signature | HMAC-SHA256 | Asymmetric signature via AWS KMS or Azure Key Vault (HSM-backed) |
| Lineage | `lineage_edges` with recursive CTE trace | OpenLineage events into Microsoft Purview, Unity Catalog lineage or Collibra |
| Identity and roles | YAML access snapshot | Entra ID / SAP GRC role extract refreshed per run |

## Alternatives considered

| Alternative | Reason not chosen |
| --- | --- |
| PostgreSQL with triggers and revoked UPDATE/DELETE | Preventive immutability, but adds a server dependency and is not columnar for set-based controls. |
| SQLite | No columnar execution; weaker analytical SQL. |
| Blockchain or distributed ledger | Disproportionate operational cost; a hash chain with external anchoring delivers the same tamper evidence for a single-organisation audit trail. |
