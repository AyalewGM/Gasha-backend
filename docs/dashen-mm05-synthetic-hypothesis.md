# MM-05 synthetic dormancy/activity-surge hypothesis — Issue #48

**Status: inactive, non-authoritative, synthetic-only. No Bank detector, alert, readiness gate, case write, intervention, or deployment.**

## Scope and integration dependency

Product Owner selected MM-05 for the Dashen representative PoC tranche in [Issue #41](https://github.com/AyalewGM/Gasha-backend/issues/41#issuecomment-6580565195). This candidate imports the versioned eight-scenario evidence-presence contract in draft [PR #86](https://github.com/AyalewGM/Gasha-backend/pull/86) and must be integrated **after #86**. This is a separate, stacked development PR rather than duplicate evidence mapping. Merged PRs #52/#53/#54 and production decision, protected API, Kafka, case, and outcome paths remain unchanged.

The module evaluates two nonoverlapping synthetic aggregate windows with explicitly supplied dormant-baseline and activity-surge policy thresholds. It demands both low prior transaction count/value and minimum current count/value plus absolute count/value increases. It does not infer a ratio when prior activity is zero, silently choose thresholds, infer a missing status or normalize mixed currencies. Thresholds, references, amounts, window completeness, lifecycle status and optional context are **caller assertions**, not Bank-authenticated data or policy.

## Fail-closed boundaries

- Revalidates #48 scenario evidence at the consumption boundary; wrong installation, tenant or dataset, stale/future field, malformed digest and missing mandatory evidence fail closed. A source fingerprint is syntactic binding, not authentication.
- Requires exact typed aggregate and policy objects, strict nonnegative integer counts excluding booleans, finite Decimal values excluding floats, one currency, canonical opaque reference, aware UTC-normalized timestamps and a current aggregate available no later than the decision cutoff. Current event must be within its current window.
- Enforces explicit baseline duration and maximum current window/gap. Closed, frozen or unknown lifecycle states do not produce a hypothesis.
- Optional reactivation and scheduled-bulk context has three states: UNKNOWN, REPORTED and REPORTED_ABSENT. Missing optional evidence cannot become reported-absent. Unknown context on a plausible surge yields context_review_required, not a stronger fraud inference; caller-reported exception yields context_exclusion_reported, not verified legitimacy.
- Only two explicitly observed reported-absent exceptions and matching low-prior/high-current arithmetic permit synthetic_change_hypothesis. This is **not a fraud finding**. All exported results omit account references/raw values and fix bank_verified, fraud_determined, readiness_authorized and enforcement_activated to false.

## Regression scope

The focused tests cover missing evidence and metrics/policy, tenant/dataset/policy binding, zero baseline, positive and legitimate negatives, inclusive threshold behavior, contextual uncertainty, lifecycle exclusions, temporal windows and DST folds, late availability, wrong event window, malformed type/value/currency, forged frozen dataclasses, redacted output and non-wiring of bank-facing paths. No raw PII or Bank data is used.

## Pending Bank/Security/Fraud decisions

Bank-approved source-system and account lifecycle semantics, transaction status/direction, deduplication, baseline window completeness, currency/FX treatment, reactivation/bulk exclusions, point-in-time collector and field provenance, pseudonymization, consent/retention, valid alert budget, matched legitimate cohort, human review, labels, KPI thresholds, operational performance and protected installation remain unresolved. An external Bank adapter must resolve accepted installation, tenant, policy, source/config/data versions server-side; the current caller-controlled scope and threshold declarations cannot be trusted in an operational path.

Review dependency is Product Owner → Security & Architecture → Fraud Intelligence → Independent QA → Unified Engineering Lead for a later internal-only decision. No self-approval, automatic merge, Bank activation or payment action. Merged #54 is a side-effect-free advisory evaluator, never evidence authority under open Issue #49.

## Integration ancestry correction

The stacked parent #86 branch was synchronized with backend main including the inactive, internally integrated #85 PostgreSQL writer. No bank code or behavior was changed by that branch-only ancestry update. This allows the unchanged production non-wiring assertions in the parent observation contract and this MM-05 regression to run against the *complete* current repository tree, rather than a parent branch whose source snapshot predated #85.
