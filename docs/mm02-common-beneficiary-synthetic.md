# MM-02 — multiple senders to a common beneficiary (synthetic-only)

Issue #41's Product Owner tranche identifies MM-02 as the remaining selected
scenario without a scenario-specific synthetic evaluator. This bounded #48
candidate uses the existing `ScenarioObservation` coverage contract and does
**not** implement an operational fraud engine, a live bank event adapter, or a
bank-approved risk/alert threshold.

The proposed, non-bank policy is a 3,600-second closed observation interval
and three distinct pseudonymous senders. The target transaction must be
posted/settled and linked to the coverage packet. Only posted/settled transfers
for the same beneficiary inside the interval count. Event IDs are deduplicated;
contradictory duplicate evidence rejects. Required claims of complete coverage,
deduplication and known internal/external institution must be explicit.
Payroll/merchant and historical baseline exceptions require observed optional
evidence; unknown exceptions result in review, not a positive hypothesis.

**These are all caller assertions, not bank-verified facts.** The fixture
`sha256` strings are shape identifiers, not signatures or source
attestation. In particular, transaction-level values are *not yet
cryptographically bound* to the source fields of the observation packet. The
future Security/Architecture and #49 trusted source/approval work must validate
tenant, event identity, completeness, source/digest/value binding, permissions,
time-window provenance, status finality and policy approval before this can
inform an authenticated scenario finding. Do not promote this result to risk,
case, readiness, prevention, or payment authorization.

The deterministic unit matrix covers unique-sender threshold at 2/3/4,
duplicate retries/conflicting IDs, payroll or baseline exclusions, missing
optional context, failed/reversed/pending transfers, exact window bounds,
out-of-window and other-beneficiary transfers, non-UTC instants, input order,
scope/version mismatch, future evidence and mutated immutable objects.
No labelled cohort, accepted Bank KPI, actual counterparty completeness,
Bank source, operational event transport, or performance test is claimed.

Unwired and non-authoritative: `bank_verified`, `fraud_determined`,
`funds_traced`, `readiness_authorized` and `enforcement_activated` are
always false. Existing #54 evaluator remains advisory. Existing #52/#53
persistence/transport code is untouched. Independent Product Owner,
Security/Architecture, Fraud Intelligence, and QA review required at exact
commit before any internal integration; separate Bank release controls remain.

## Synthetic value binding and snapshot revision

This revision requires exact immutable input types before any dataclass copy,
including post-construction mutations of frozen slotted records. Malformed or
deleted members raise a redacted ScenarioContractError rather than a raw
TypeError/AttributeError. Every observed transfer and any claimed optional
context must be available by the metrics snapshot timestamp, itself no later
than the decision cutoff. Exact equality is permitted; a later fact rejects.

Required MM-02 field semantics and any claimed optional baseline/payroll
context now carry snapshot-scoped field claims with source ref/version,
evidence digest, canonical semantic value digest, dataset/mapping/tenant/
installation references and observed/available times. Transfer source metadata
must match the observed transfer-status source. Missing, duplicate, spliced,
stale-value, wrong-scope and late claims reject before classification.
The output includes a deterministic effective-input digest over policy,
snapshot, canonical deduplicated transfer facts, context, field claims and
window. Equivalent ordering or UTC offsets do not change the digest;
material changes do. No raw sender/beneficiary refs are included in results.

All these values, their source metadata and their digests remain **synthetic
caller-created assertions**, not authenticated Bank evidence or verification.
Bank-approved thresholds/cohorts, actual source integrity, tenant identity,
installed adapter/CI readiness, #49 approval and enforcement remain blocked.
