# APP-01 synthetic first-beneficiary/large-payment candidate — Issue #48

**Status: inactive, offline, non-authoritative.** No Bank source, operational detector, fraud conclusion, alert, authenticated API route, case write, readiness authorization, deployment, or HOLD/BLOCK integration.

This candidate follows the Product Owner's eight-scenario Dashen PoC tranche in [Issue #41](https://github.com/AyalewGM/Gasha-backend/issues/41#issuecomment-6580565195), reuses the **merged** versioned APP-01 observation-presence mapping from PR #86, and does not change the separate draft MM-05 PR #87 or merged #52/#53/#54. This is a bounded synthetic hypothesis, not a claim that APP-01 is completed for the Bank.

## What the function checks

`gasha.poc.app01_synthetic.evaluate_app01_synthetic` consumes a syntactically valid, scope-checked `ScenarioObservation` and *caller-asserted* policy and aggregate metrics. It requires:

- All APP-01 required field-presence keys, a matching tenant/install/dataset shape, observation digest, policy/config version and pre-cutoff availability. These are **not** Bank-authenticated claims.
- A beneficiary history window ending at the payment event, covering at least the proposed minimum history duration, explicitly claimed complete, with no earlier transfer to that beneficiary in that window.
- A strictly positive historical typical customer payment amount, sufficient historical baseline samples, and a payment meeting **both** a minimum absolute amount and a minimum multiple of that baseline.
- One matching currency for transfer and baseline. A different currency returns `blocked_currency`, even when an FX source *key* exists, because source presence does not prove a valid point-in-time FX rate.
- Eligible attempted/posted payment state. Reversed, rejected and unknown statuses do not yield candidates. Missing or incomplete history, missing metrics, insufficient baseline, invalid versions or post-cutoff evidence fail closed.
- Three-state optional recurring-payment context: `UNKNOWN` requires human review; `REPORTED` suppresses the synthetic candidate **without proving legitimacy**; `REPORTED_ABSENT` can yield a *synthetic hypothesis* only if the optional field was observed. None of these caller assertions can operate as Bank suppression authority.

The result exports status, machine-readable reasons and version references, but never account, beneficiary, amount, customer identifiers or thresholds. All reports fix `bank_verified=false`, `fraud_determined=false`, `readiness_authorized=false` and `enforcement_activated=false`. Repeated identical inputs yield identical reports.

## Critical distinctions for the Bank and Fraud Intelligence

Here, *first-time* means **zero prior transfers in the asserted, complete comparison window**, not first-ever in the account lifetime. Neither an observed evidence key nor a self-declared history-complete enum proves actual beneficiary-history completeness. The historical Bank lifecycle, account/beneficiary identity matching, other channels, source status, dedup/retries/reversals, purpose/consent and source availability have **not** been validated.

A proposed `min_baseline_multiple` is not a calibrated model or accepted Bank policy. Choosing a transfer amount and a customer median/typical amount from different cohorts, currencies, payment directions or clock windows can produce false signals. The trusted adapter and Bank must establish source status/direction, history completeness, lookback, typical baseline computation, included population, FX/currency alignment, data minimization, timestamps and versioned policy ownership before any shadow scenario integration.

No synthetic output can be used as independent #49 evidence or interpreted as `ready` from merged PR #54, whose evaluator remains advisory/caller-asserted. Bank-authenticated principal/tenant/RBAC under #42, evidence/approver revocation under #49, installed deployment tests under #46/#47 and Bank-approved labeled KPIs remain **open**.

## Verification and handoff

`tests/test_app01_synthetic.py` covers positive and boundary examples, context outcomes, partial history, weak baselines, cross-currency without FX fabrication, invalid status, wrong scope/config/digest, missing mandatory field, future availability, forged frozen objects, strict Decimal/count types and no operational imports. It uses only pseudonymous synthetic fixtures.

**Required independent handoff:** Product Owner (APP-01 semantics/priority) → Security & Architecture (isolation, scope and authority) → Fraud Intelligence (history/FX/legitimate counterexamples) → Independent QA (exact-head execution) → Unified Engineering Lead (separate internal-only integration decision). No implementer self-approval or merge, stage promotion, Bank activation, deployment or payment action.
