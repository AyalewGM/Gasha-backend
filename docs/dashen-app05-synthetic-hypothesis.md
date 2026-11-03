# APP-05 synthetic repeated OR rapidly escalating attempt hypothesis — Issue #48

**Inactive, untrusted, offline only.** This is a bounded proof of sequence semantics for the Product Owner's [Dashen eight-scenario tranche](https://github.com/AyalewGM/Gasha-backend/issues/41#issuecomment-6580565195). It is not an operational fraud detector, Bank-authorized payment action, analyst case, readiness/approval service, or claim that APP-05 is Bank-ready.

The separate merged PR #86 field-presence contract supplies APP-05 required evidence keys: attempt correlation, times, amounts, currencies, statuses, window and deduplication. This implementation uses only caller-proposed sequence data and thresholds. Previously merged PRs #52/#53 and internal-only readiness evaluator #54 are unchanged.

## Proposed semantics — not a Bank-approved policy

- Require a tenant/install/dataset-scoped, versioned, point-in-time ScenarioObservation with all mandatory APP-05 evidence keys observed. Matching digest binds the untrusted sequence to observation shape, not authenticated source contents.
- Require a claimed-complete, bounded tuple of uniquely identified correlated attempts. Duplicate event identifiers reject; out-of-order input is sorted by UTC event instant. Ambiguous equal-instant ordering blocks.
- Every attempt requires aware occurrence/availability timestamps, positive finite strict-Decimal amount, canonical currency, typed status, and an explicit caller-only customer-initiation claim. Missing/false/ill-typed initiation cannot qualify. Evidence must be available by decision cutoff. The latest attempt must match the observation event UUID and time.
- At least the proposed minimum number of claimed customer-initiated attempted, approved or declined attempts must fall within the proposed window, inclusive. Declined is eligible only with an explicit customer-initiation claim; technical failures, reversed, unknown or abandoned statuses are blocked, including mixed sequences. The claim never establishes Bank intent.
- **Repeated branch:** sufficient unique correlated customer-initiated attempts within the inclusive window, including equal/falling/nonmonotonic amounts. **Escalating branch:** additionally strict rise by minimum step and final-to-initial minimum multiple. The single result emits `rapid_repeated_attempts` and, when qualified, `rapid_escalating_attempts` first; never double counts an event. Currency mismatch blocks; no invented FX normalization.
- Technical retry exception context is three-state: UNKNOWN requests review; REPORTED suppresses a synthetic candidate without proving legitimacy; REPORTED_ABSENT can produce only a synthetic hypothesis if the optional technical_retry_indicator evidence key is observed. Non-UNKNOWN assertions are validated before every evaluated scenario-negative outcome.
- At consumption time revalidate all policy, sequence and nested attempt invariants against low-level mutation. Reject malformed version, tenant/dataset/cutoff identity and timestamps.

Output contains only status/reason, observation/configuration/policy versions and synthetic provenance. It omits IDs, correlation, amounts, currencies, customer/account details and risk scores. bank_verified, fraud_determined, readiness_authorized and enforcement_activated are always false.

## Unresolved Bank acceptance and trust boundaries

Field-presence keys and digests do not establish authentic Bank event sourcing, customer initiation, decline reason family, authorized attempt correlation or complete history. No canonical trusted digest currently binds effective amounts/statuses/thresholds to the exported observation fingerprint; historical or shadow metrics must not consume this output without authenticated evidence identity. Status, actual retries across channels, declined/abandoned/reversal semantics, FX, deduplication, out-of-order Bank delivery, policy thresholds, labels/cohorts, cutoff-safe adapters, case workflow, Bank identity/RBAC, performance acceptance, and #49 trusted evidence/verifier/approver/revocation remain unverified. APP-05 anomalies never prove fraud, deception, remote coaching or prevented loss.

No production decision/worker/protected FastAPI/readiness/payment import is introduced. The current Docker synthetic API exclusion test does not prove that every offline POC helper is omitted from the bank image.

## Verification and independent handoff

tests/test_app05_synthetic.py covers positive, legitimate/technical negatives, count/window/amount boundaries, duplicate/ordering, UTC DST fold, post-cutoff, wrong-tenant/dataset/version, missing evidence, and mutated frozen objects. CI is implementer evidence, not independent Bank acceptance.

Review sequence: Product Owner → Security & Architecture → Fraud Intelligence → Independent QA at the exact source head, then separate Unified Engineering Lead internal-only integration decision. Keep draft/unmerged. No self-approval, stage promotion, deployment, Bank activation or HOLD/BLOCK action.
