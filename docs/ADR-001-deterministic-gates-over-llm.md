# ADR-001: Deterministic gates decide; the language model only advises

| Field | Value |
| --- | --- |
| Status | Accepted |
| Date | 2026-11-20 |
| Decision owner | Enterprise Architecture (Data and AI) |
| TOGAF ADM | Phase C (Data and Application Architecture), Phase G (Implementation Governance) |
| Architecture principles | Control by design; Explainability; Data minimisation; Reproducibility |

## Context

The platform decides whether a finance sub-ledger batch may be posted to the general ledger and
whether product master data may be published to the GDSN data pool or released to duty-free
customers. Both decisions are in scope of statutory and supervisory regimes:

- SOX 404 and the Swiss internal control system (Swiss CO Art. 728a) require controls whose
  operation can be re-performed by an auditor with the same result.
- BCBS 239 Principles 3 and 6 require accuracy and integrity of risk data and adaptability
  without loss of control.
- The EU AI Act (Art. 13 and Art. 14) sets transparency and human-oversight obligations for
  high-risk AI systems, and dangerous goods classification errors carry safety consequences
  under IATA DGR and the IMDG Code.

Large language models are useful for explaining an exception and drafting remediation steps.
They are not deterministic, cannot be re-performed bit-for-bit, and are exposed to prompt
injection from the very data they evaluate.

## Decision

1. Every gate decision (`BLOCKED`, `REQUIRES_FOUR_EYES`, `CLEAR`) is computed exclusively from
   deterministic rules: Python record rules and DuckDB SQL set-based rules, parameterised by
   version-controlled YAML policy.
2. The remediation advisor (`gatekeeper.advisor.bedrock_explainer`) consumes findings that
   already exist and returns `RemediationAdvice` with `gate_effect = "NONE"`. Severity is copied
   from the deterministic finding; any severity or decision proposed by the model is discarded.
3. No code path reads advisor output when computing gate decisions or workflow transitions.
4. Before any text leaves the process, user identifiers are pseudonymised (salted SHA-256),
   monetary amounts are reduced to an order of magnitude and e-mail addresses and IBANs are
   redacted. Inputs are wrapped as data and the model is instructed to treat them as such.
5. The advisor runs with `temperature = 0`, a bounded output size and strict JSON parsing.
   Any provider, transport or parsing failure degrades to the deterministic playbook.
6. Without `boto3`, AWS credentials or `GATEKEEPER_BEDROCK_MODEL_ID`, the advisor runs in
   offline fallback mode, so the full platform operates and is testable with zero keys.

## Consequences

| Dimension | Effect |
| --- | --- |
| Auditability | Identical input and policy produce identical findings; `input_sha256` and `config_sha256` let an auditor re-perform any run. |
| Regulatory posture | The model is an assistive component outside the decision path. The gate itself contains no AI system, which simplifies AI Act classification and keeps human oversight meaningful. |
| Security | Prompt injection in source data can at worst degrade advice quality; it cannot release a batch. |
| Velocity | Remediation drafting accelerates triage for data stewards and GL accountants without reopening control design. |
| Cost | Model calls are made only on demand for existing exceptions, in chunks of at most 25 findings. |

## Alternatives considered

| Alternative | Reason not chosen |
| --- | --- |
| LLM classifies records directly (for example DG classification) | Not re-performable, no stable error profile, conflicts with SOX evidence expectations and DG safety obligations. |
| LLM proposes severity, human confirms | Anchors the reviewer on model output and weakens the four-eyes control into a rubber stamp. |
| No AI layer | Forgoes measurable triage time savings on high-volume exception queues. |

## Production hardening

- Route Bedrock calls through a VPC endpoint with Amazon Bedrock Guardrails for PII filtering as
  a second, provider-side layer.
- Log prompts and responses (masked) to the same evidence store under a retention policy.
- Pin the model identifier per release and re-baseline advice quality on model upgrades.
