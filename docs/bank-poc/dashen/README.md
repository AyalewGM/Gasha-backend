# Dashen Bank Gasha PoC — knowledge base (draft)

**Status:** Internal working index; NOT an approved contractual baseline.  
**Source documents:** "GASHA — AI-Powered Fraud Detection & Transaction Monitoring — Proof-of-Concept Proposal" (November 2026, 171 PDF pages) and "ANNEXES" (November 2026, 46 PDF pages), provided by the owner in ChatGPT. The original confidential PDFs have **not** been uploaded to this repository. Do not claim this index replaces them.

## Source map
- Main proposal §4: five use cases, scope and scenario selection.
- §5: FR-01–FR-52 functional requirements.
- §6: INT-01–INT-12 integration requirements.
- §7: AI-01–AI-08 analytical requirements.
- §8: SEC-01–SEC-34 security/privacy/governance requirements.
- §9: 16-week plan and D01–D13 deliverables.
- §10: KPIs, AC-01–AC-12 acceptance criteria, MG-01–MG-08 mandatory gates.
- §13: commercial, legal and intellectual-property framework.
- Annex A: 25 **candidate**, not committed, scenarios across UC-01–UC-05.
- Annex B: candidate data sources, logical dictionary and DR-01–DR-12 readiness checklist.
- Annex C: ten proposed interfaces IF-01–IF-10 and technical verification IT-01–IT-16.
- Annex D: baseline, KPI and evidence registers; values pending validation.
- Annex E: six milestones M1–M6, RACI, schedule and deliverable tracker.
- Annex F: risks, assumptions and dependencies.
- Annex G: proposed 106-requirement verification register, not yet individually prioritized.

## Use cases
| ID | Purpose | Source | Data caveat |
|---|---|---|---|
| UC-01 | Account takeover and digital channel fraud | §4.4; Annex A ATO-01–ATO-06 | Authentication/device/profile signals may be unavailable |
| UC-02 | Money-mule and suspicious fund movement | §4.4; Annex A MM-01–MM-06 | Counterparty linkage and confirmed outcomes required for strong claims |
| UC-03 | Authorized push payment/social-engineering risk | §4.4; Annex A APP-01–APP-05 | Transaction anomalies do not prove customer coercion |
| UC-04 | Fraud alert prioritization | §4.4; Annex A AP-01–AP-04 | Depends on alert populations and investigator capacity |
| UC-05 | False-positive reduction | §4.4; Annex A FP-01–FP-04 | Must evaluate recall alongside alert reductions |

## Delivery and verification rules
1. **Inspect live main, open issues and PRs first.** Never classify a capability as missing or implemented solely from this index.
2. For each scenario/requirement record: source ID, current implementation evidence (commit/PR/test), status (verified/partial/missing/data-blocked/deferred), priority, owner, negative tests, and acceptance evidence.
3. Reuse existing GitHub issues and PRs; no duplicate development. Product Owner proposes scoped additions, Engineering implements, Security and independent QA verify.
4. Prioritize a *proposed* 6–8 representative detection scenarios only after feasibility review; this is not a contractual commitment. UC-04/05 can evaluate detection outputs.
5. Initial PoC is historical-data-first and advisory. Shadow mode requires separate authorization. No live blocking, bank deployment, external hosting or production access is authorized by this document.
6. Baseline comparisons and performance targets remain unverified until Dashen data/labels and evaluation protocol are approved. Unknown outcomes are not legitimate labels.
7. M2 at Week 5 is the recommended formal data-readiness decision gate; schedule depends on Bank inputs and security approvals.
8. Protect tenant isolation, fail-closed authorization, audit evidence, versioned server-side policies and negative security tests. No self-approval.
9. Do not copy Dashen-specific confidential details into public research, other bank documentation, or unapproved services.

## Editorial reconciliation items (verify before final proposal)
- Main proposal Table 9.3: D07 at M4; Annex E Table E.3: D07 at M3.
- Annex D §D5 points to §10.7 for weighted scorecard; main proposal lists §10.5.
- Annex D §D6 points to §10.8 for mandatory gates; main proposal lists §10.7.
- Annex G summarizes all 106 requirements in grouped rows; individual applicability and evidence records are still needed.

## Next steps
- Confirm authorization to store original confidential PDFs and upload them through an approved binary-capable route.
- Expand each of the 106 requirement IDs and 25 candidate scenarios into individually traceable records, grounded in the original files.
- Perform exact-head implementation gap analysis across backend/frontend; create only missing bounded feature issues.
- Obtain Bank agreement on scope, data readiness, measurable acceptance, and commercial terms before treating this as a delivery commitment.
