# Issue #48 — Synthetic reference data-quality inventory (inactive)

This additive, **non-authoritative** module reports aggregate data quality for caller-supplied, pseudonymized InboundBankEvent reference-json rows. It never invokes scoring, normalizes a risk decision, writes evidence, accesses the Bank, accepts a stage, calls readiness.py (#54), or grants an enforcement action. Dataset SHA-256 and schema/config/mapping versions are **unverified strings supplied by the caller**, not trusted Bank provenance. Unknown labels and signals do not silently count as negatives or measured zero-risk.

## Versioned provisional UC field and coverage matrix

Matrix **synthetic-uc-coverage-v2**, report schema **gasha-synthetic-data-quality-2**.
These are illustrative synthetic-coverage fields only; none is an attested CBE
source, a CBE-mandated signal or a Bank-approved requiredness rule.

| Reference scenario | Required reference-json fields | Optional/coverage-only signals (exact set) |
| --- | --- | --- |
| UC-01 new-beneficiary / unfamiliar-relationship social engineering payment | event_id, occurred_at, channel, transaction_type, amount, currency, sender_customer_id, sender_account_id, beneficiary_id, beneficiary_type, correlation_id; destination_institution_id if external | beneficiary_risk, relationship_risk |
| UC-02 beneficiary/network concentration or mule aggregation payment | Same payment reference fields | beneficiary_risk, network_risk, velocity_risk |
| UC-03 device/session journey anomaly | event_id, occurred_at, kind, subtype, customer_id | device_session_risk, journey_risk; account/session/device references remain optional |

InboundBankEvent envelope additionally supplies tenant_id, schema_version, received_at and the source label. These groupings are illustrative only, **not CBE requirements**, per-use-case Bank contracts, or completeness claims. UC-03 terminal payments and joins, device/call/RAT provider fields, identity relationships and UC overlap need separately approved adapter definitions. Bank payload fields, identities and source-specific mappings remain in bank adapters; this module neither stores nor exports their values.

## Machine-readable aggregate report

inspect_reference_quality(scope, observations).to_dict() emits a schema-tagged, explicitly **not verified / not authorized** object with tenant+dataset+source-schema+mapping+config and UTC collection/label cutoffs, total/accepted/quarantined populations per UC, non-identifying check counts, accepted-population optional-signal coverage with unavailable counters, mature positive/negative/unlabelled denominators, observed alert/no-alert/unknown counts, undefined rate reasons and limitations. confirmed_at after the label cutoff is unlabelled, not negative; impossible label-before-event, receipt-before-event, wrong tenant/schema/window, duplicate event ID, malformed UUID/clock/amount/currency and missing required fields are rejected. Duplicate tracking is per UC within the supplied batch and reserves only otherwise valid in-scope observations; a quarantined wrong-tenant, wrong-schema or malformed row cannot poison an accepted event ID. A signal that is absent, invalid or not provided remains unavailable even if the existing numeric-only scoring model elsewhere defaults it to 0.0.

The provisional coverage-matrix version is included in every report; missing or invalid optional signals remain unavailable, not numeric zero. Additional supportive signals outside the exact per-UC matrix are not reported as required coverage and must be independently versioned and agreed before use.

No event ID, customer/account/beneficiary/device reference, raw payload, label source, source filename, exception text or arbitrary check key is serialized. Check names are fixed reference schema keys. Scope tokens must be canonical opaque identifiers; pseudonymization and actual source authentication are the Bank adapter's responsibility. Missing optional telemetry is recorded as unavailable even when a record is otherwise structurally accepted. **Accepted here never means evaluable for a bank KPI**.

## Remaining Bank and independent acceptance

- Approved per-UC required/optional source mapping, purpose/location/retention and deletion ownership, identity joins, permitted source clocks, processing latency and reference/schema versions.
- Bank-authenticated dataset/cohort identity and time-separated labels, historical point-in-time artifact binding (PR #71 is separately inactive), immutable source and exact selected config/policy versions, quality threshold agreements.
- Relationship/orphan and out-of-order provenance checks, alert/label maturity and use-case-level evaluability, actual bank data-quality sampling and independent Security/Fraud/QA review.
- Trusted #49 evidence registry and revocation-safe approvals; #54 remains **caller-asserted and advisory only**. Bank staging, deployment, payment enforcement and CBE acceptance remain blocked.

The module is purposefully **not wired into** replay, scoring, protected API, worker, risk-list or readiness paths. A hash or green CI run does not attest source authenticity or accept historical KPI evidence. Only synthetic data is used in tests.

## Synthetic source and malformed optional telemetry guard

The reference inspector now rejects an empty, missing, noncanonical or malformed `source_system` as `invalid.source_system` even when an unchecked synthetic model copy bypassed the ingestion model validation. Such a quarantined row cannot reserve a same-UC event ID or affect accepted labels, alerts or signal-coverage denominators. A valid canonical source token establishes **shape, not source authentication**.

An explicitly present `intelligence` value that is not a mapping records `invalid_optional.intelligence`, including explicit null; its provisional per-UC signals remain unavailable. Absence of the optional container is not a quality warning. This extends the existing report v2 check-code vocabulary without changing the machine-readable structure, use-case coverage matrix or Bank-readiness authority. No new bank adapter, historical replay, policy evaluation or deployment wiring is added.


## Report export ownership and integrity (synthetic-only)

The retained `DataQualityReport.use_cases` now contains independent, recursively
frozen mapping snapshots rather than caller-owned mutable dictionaries. Direct
report construction also copies its input, rejects non-JSON/non-finite leaf
values and revalidates the dataset scope. `to_dict()` allocates new nested
maps and lists on every call, including accepted/rejected counts, checks,
labels, alerts, acceptance and per-signal coverage. Regression tests mutate
every exported level and the constructor's source maps and verify the
retained report does not change.

This corrects **in-process aggregate output aliasing only**; Python
immutability does not authenticate evidence, independently verify a dataset
digest, protect against privileged runtime mutation or authorize UC-04/UC-05
metrics. The existing provisional UC matrix and non-authoritative flags
remain unchanged. In particular #54 is still advisory and #49 still
requires trusted verifier/approver provenance and revocation.
