# MM-01 rapid receipt and onward transfer — inactive synthetic candidate

**Scope:** Issue #41 / #48 and Dashen Annex A's **candidate** MM-01 (UC-02).
This module is not a Bank-verified detection rule and does not alter Gasha's
existing mule-risk fusion, event ingestion, historical replay, readiness gate,
protected API, case management, audit or payment processing.

## Data contract and proposed hypothesis

The existing `ScenarioObservation` MM-01 mapping is required and bound to a
specific installation, tenant, dataset digest, event ID, source/schema/mapping
versions and point-in-time cutoff. `MM01SyntheticMetrics` holds a caller-asserted
pair of pseudonymous account credit/debit events, directional type, unique
references, event and source-availability times, reported POSTED/SETTLED or
failed/attempted/reversed states, positive same-currency Decimal amounts,
and two separately claimed exception contexts.

The debit event reference and timestamp must match the observation's event
identity/time; account references must match, credit must precede debit, and
credit evidence must be available by the debit time. Distinct credit and debit
events are required. Only posted/settled statuses qualify for the *synthetic
pattern*, not proof of settlement or funds movement. All claimed observations
must be available by the decision cutoff. A candidate is classified after a
versioned proposed maximum elapsed time, a credit amount floor and a minimum
debit/credit ratio. Time/rate/amount thresholds are inclusive; no FX conversion
or cross-currency comparison is inferred. The ratio is only an arithmetic
relationship between untrusted amounts, **not** a traced-funds fraction or a
recovered-loss/confirmed-mule metric.

A reported own-account transfer or reported reversal suppresses the
hypothesis; absent exception evidence requires manual context review.
To assert either context as present or absent requires a separately OBSERVED
optional field. Unknown/missing optional context cannot be treated as
explicitly negative. Missing required coverage and missing metrics/policy
block evaluation rather than substituting zero risk. An invalid event/source
clock, malformed type, tenant/dataset substitution, future observation,
wrong currency or policy mismatch rejects or blocks.

`effective_input_digest` hashes a canonical snapshot of all caller-supplied
policy and metric fields, independently of the observation's field-presence
digest. It is **not** Bank attestation, authenticated source lineage, trusted
evidence approval, an immutable historical cohort or fraud evidence.

## Deliberate limitations / next owner gates

- **Bank/data owners:** authorize and document debit/credit ledger feed,
  booked/attempted/reversed/settled semantics, posting/receipt/observation
  clocks, directed account and counterparty relationships, join coverage,
  synthetic own-account/payroll/merchant exceptions and retention purpose.
  A temporal account match cannot establish actual onward movement of the
  credited funds.
- **Fraud Intelligence + Product Owner:** define exclusion semantics and
  Bank-approved window, units, floor and ratio. Do not use synthetic fixture
  values to claim fraud or an accepted Bank alert budget.
- **#48 historical evaluator:** independent point-in-time-safe source
  attestations, immutable dataset/cohorts and mature positive/negative labels
  are needed for TP/FP/TN/FN, precision, recall and alert-budget evidence.
  Unknown/missing telemetries are unavailable; no favorable denominator.
- **#42/#49 + QA:** retain the protected API trust boundary and non-authoritative
  PR #54. This module is not imported by operational API, workers, replay,
  readiness, analyst cases, payments or enforcement. Independent exact-head
  PO, Security/Architecture, Fraud Intelligence and QA review is required
  before the Unified Engineering Lead decides any internal-only merge.

No Bank data, tenant credentials, bank-facing deployment, stage promotion,
automatic case/alert/action, actual funds tracing, prevented-loss or live
payment intervention is provided.

## Synthetic-v1 bounded correction (QA / PO / Security)

The prototype now validates both caller-asserted optional context claims
before linkage, status, chronological, window, floor, ratio or context
classifications. A reported absent/present exception without separately
OBSERVED optional evidence is rejected, including low-value and otherwise
negative cases. This does not authenticate the claimed observation.

Synthetic-money-v1 allows finite strictly positive Decimal amounts from
0.000001 to 1e18 inclusive, no more than six fractional decimal places,
a bounded 25-digit coefficient and exponent at most 18. The ratio policy is
strictly greater than zero and at most one, with up to six fractional digits.
These are conservative, bank-neutral synthetic test domains, not approved
currency minor units, FX behavior or Bank policy. Values outside this domain
reject before evaluation. Ratio comparison uses bounded 64-digit Decimal
multiplication instead of potentially overflowing division.

Not yet closed in this correction: PO/Security requested explicit
authorized same-owner relationship evidence and field-level semantic
source/digest/snapshot binding. Counterparty-pseudonym presence remains only
identifier presence; this PR must not be merged until those separate
corrections, regression tests and independent exact-head reviews pass.
