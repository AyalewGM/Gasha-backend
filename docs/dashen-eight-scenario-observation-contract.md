# Dashen eight-scenario observation contract — Issue #48

Version: `dashen-synthetic-observation-v1`  
Status: **inactive synthetic coverage adapter contract; NOT Bank source authorization, detection, historical validation, or deployment approval.**

## Why this exists

Product Owner's [eight-scenario decision in Issue #41](https://github.com/AyalewGM/Gasha-backend/issues/41#issuecomment-6580565195) prioritizes eight representative fraud scenarios within a potential 16-week Dashen Bank PoC. Seven are partially represented by existing journey/graph/velocity primitives; MM-05's dormancy/change detector is missing. This first increment only makes **data dependencies explicit** before any scenario detector is written.

The `gasha.poc.scenario_observations` module adds a fixed scenario-ID → required/optional **evidence-presence key** mapping. It never consumes bank payment values or customer IDs, scores fraud, changes the decision service, calls the protected API, creates cases or flips a readiness flag. A key represented by a digest is **not** proof of its value, bank origin, correctness, currency unit, consent or authorized use.

## Versioned scope and semantics

Each synthetic `ScenarioObservation` records an installation reference, tenant reference, pseudonymous event UUID, dataset SHA-256 digest, source/schema/mapping/config versions, occurred/received/decision-cutoff instants, scenario ID, and a tuple of per-field `FieldEvidence`. An observed field has only its canonical field name, opaque source reference/version, evidence digest, observed/as-of time and first-available time; **raw customer, account, device, beneficiary or payment values are not accepted by this contract.**

Unobserved optional data remains **unavailable**, never numeric zero. Missing or explicitly unavailable required keys produce `blocked_by_data`; only complete synthetic field-presence coverage produces `synthetic_coverage_only`, **not** a scenario finding or `ready`. Source timestamps after decision cutoff, impossible occurred/receipt/cutoff order, duplicate/unknown fields, malformed digests and tenant/installation/dataset substitution fail closed. UTC instant normalization covers timezone offset and DST folds. Stable SHA-256 fingerprinting is shape identity **not source attestation**.

`ScenarioCoverage.to_dict()` deliberately emits `bank_verified=false`, `detection_executed=false`, `readiness_authorized=false`, `enforcement_activated=false`. This is not consumed by merged PR #54's caller-asserted, advisory-only evaluator.

## Required Bank-neutral source domains and missing decisions

| Scenario | Source domains and required semantic inputs | Currently unresolved Bank-owned mapping / business policy |
|---|---|---|
| **ATO-02** new device + abnormal activity | Authentication outcome, device pseudonym, known/first-seen status and lookback, session anomaly | Authorized device/auth history, reset/re-enrollment exceptions, lookback and anomaly definition |
| **ATO-06** beneficiary addition → rapid transfer | Beneficiary identity, lifecycle creation/status and baseline, payment attempt/status/amount/currency; execution/settlement clocks when present | Beneficiary feed and history completeness, unusualness baseline, transfer status truth, rapid window |
| **MM-01** receipt → onward transfer | Account identity, inbound credit and outbound debit references/status, direction, value/currency and flow window | Credit-debit linkage, settlement/reversal mapping, own-account exclusion, flow ratio/window |
| **MM-02** sender fan-in | Sender and beneficiary identities, transfer status, observation-window completeness, dedup event set, external-institution flag | Complete multi-source counterparty feed, payroll/merchant exclusion, unique sender threshold |
| **MM-05** dormant → activity surge | Account lifecycle status, prior/current window count and value aggregates, dormancy policy version | Dormancy definition, closed/frozen accounts, scheduled bulk activity and documented reactivation |
| **APP-01** first beneficiary + unusual amount | Beneficiary first-seen/history, payment value/currency/status, account amount baseline, baseline currency, FX source | Bank-approved FX snapshot and baseline windows, recurring-payment exceptions, beneficiary-history completeness |
| **APP-02** account/device change → payment | Authorized profile/credential/device change source/type/time, payment reference/status/amount/currency and baseline | Change-source authority, approved maintenance/reset reason, unusual-payment baseline |
| **APP-05** escalating attempts | Attempt correlation, times/amounts/currencies/statuses, complete window and deduplication | Technical retries vs separate attempts, declined/abandoned/reversed semantics, escalation and time thresholds |

The module verifies the **presence** of these domain keys, not that they satisfy the scenario definitions or that every required Bank event and relationship has been observed. The Bank's approved adapter must define individual fields, direction/currency/status normalization, observation-window completeness, permission, source of truth and immutable provenance. **Missing telemetry must block an affected scenario; it must not be inferred as a safe score, a fraud event, deception or remote coaching.**

### Data governance dependencies (not supplied by this commit)

- **Bank sources and permissions:** source-system owner, approved purpose, secure install/tenant binding, bank-selected identity and field schema; mapping adapters must authenticate these outside this contract. Retention, deletion, residency and data-controller approval remain Bank-owned.
- **Point-in-time evidence:** independently attested collection/receipt/feature as-of/decision clocks, event/transfer state, lifecycle history and revisions. Later confirmation labels/outcomes may be used only in separate evaluation reconciliation, never as model features.
- **Evaluation:** immutable tenant/dataset/cohort binding, label maturity and source, event-level dedup, complete TP/FP/TN/FN denominators, same-cohort incumbent comparisons, Bank-approved KPI thresholds and alert budgets. Undefined metrics cannot pass.
- **Detection:** Backend and Fraud ML reuse existing journey/graph/velocity; implement explicit MM-05 dormancy-change, APP-01 first-time/currency normalization and APP-05 status/amount escalation, then the smaller ATO/MM/APP gaps. Matched legitimate negative and time/threshold boundary cases remain mandatory for each.
- **Case / analyst:** existing #45 append-only protected case integration and authenticated analyst queue only after #42 Bank identity/source contracts. Synthetic UX must remain separate.
- **Readiness:** existing #49 trusted source/verifier/approver/expiry/revocation and approved release authority are missing; the merged #54 module is **advisory only**. Outcome endpoints remain disabled and no HOLD/BLOCK or funds action is authorized.

## Executable synthetic regression matrix

`tests/test_poc_scenario_observations.py` checks all eight complete-coverage shape fixtures, one missing field at a time across **every required key**, explicit unavailable vs omission, wrong tenant/installation/dataset, future data after cutoff, UTC/DST-fold equivalence, malformed provenance/digests, invalid fields including labels/RAT, duplicate/mutable evidence, order-independent fingerprinting and no production-path import.

This first PR is a **contract and synthetic coverage milestone only**. It does not implement eight fraud detectors, validate Bank data, or constitute a completed eight-scenario demo. Independent PO → Security/Architecture → Fraud ML (for detector semantics) → QA exact-head findings are required before internal integration. Bank-selected field sources and requirements remain prerequisites for any Bank-facing delivery.
