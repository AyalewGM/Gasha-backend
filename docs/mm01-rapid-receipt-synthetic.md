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

The subsequent synthetic relationship and field-value/source/snapshot
consistency corrections are now implemented below; they are not a trusted
Bank source/authorization service. They do not by themselves close Issues
#42/#48/#49 or permit a merge without exact-head independent review.

## Explicit synthetic ownership relationship (bounded correction)

`counterparty_pseudonym` is an identifier-presence signal, **not** an
authorized same-owner relationship. Own-account exclusion requires the new
optional `own_account_relationship` field to be OBSERVED, plus a typed
`MM01RelationshipEvidence` assertion with explicit same-owner vs distinct-
owner classification, permitted-purpose token, source/version, field evidence
digest, observed/available instants, dataset/tenant/installation scope, and
exact observation snapshot fingerprint. Source or purpose substitutions,
post-cutoff claims, absent evidence and classification contradictions reject.

All assertions remain synthetic and caller-originated. In particular, a
claimed purpose token does not constitute a Bank-granted permission, and even
an internally consistent claim does not independently verify beneficial
ownership. Missing relationships stay UNKNOWN; no safe inference from missing
data. **PO/Security correction #4 now has a bounded synthetic implementation**:
required account, inbound, outbound, amount, currency and window fields plus
claimed exceptions must carry typed per-field source/version/evidence digests,
canonical semantic-value digest, availability, dataset/tenant/installation,
mapping version and exact snapshot identity. Inbound reference and status,
and outbound reference and status must retain one source/version per pair.
Missing, duplicated, late, substituted or inconsistent claims reject before
any result classification. This is a claim-consistency guard only, not an
authenticated ledger value, Bank attestation, signed source record, trusted
source approval or proof of funds movement. Independent exact-head review and
Bank evidence authority remain mandatory.

## Synthetic field-claim value and source bindings

Each required MM-01 field is bound to a snapshot-scoped `MM01FieldClaim`
claim with observed/available timestamps, dataset/tenant/mapping scope,
evidence source/version/digest and a canonical domain-tagged digest over the
corresponding semantic metric attributes. Claimed reversal or own-account
exceptions must also include the appropriate optional field binding.
At every evaluation, the code revalidates the frozen objects and compares
claims against the current observation fields and effective metric values.
Unbound, duplicated, cross-source/status, changed-value and cross-snapshot
packets reject *before* linkage/status/threshold outcomes.

The field-claim value digest is constructed from **untrusted synthetic claims**,
not independently extracted or verified ledger values. Both source claims and
their digests may originate with the same caller. This addresses internal
consistency and stale/substituted claims; a separately authenticated Bank
adapter, authorized source registry and immutable evidence provenance are
still required before replay or Bank acceptance. No operational wiring.

## Event-specific causal evidence timing (synthetic event-clock-v1)

For an inbound credit at `inbound_occurred_at`, an OBSERVED
`inbound_credit_status` may not have `observed_at` before the credit
event. For an outbound debit at `outbound_occurred_at`, the OBSERVED
`outbound_debit_status`, combined direction, amount, currency and flow-window
claims may not precede the debit event. A claimed reversal context likewise
cannot be observed before the debit. Both POSTED and SETTLED statuses obey
this rule; it also prevents falsely knowing another transfer status before
its event. Observations must still be available no earlier than their
observation and no later than the decision cutoff.

Pre-existing account identities and pre-issued credit/debit reference
identifiers **may** legitimately be observed before the event; the code does
not infer that an identifier's presence proves a posted transfer. The inbound
reference and status fields must be available by the debit event. Claimed
`inbound_available_at` also must not exceed that debit time. Violations are
rejected as `ScenarioContractError` before any negative, exclusion, review
or favorable hypothesis classification; they are **not** treated as safe or
counted as verified alerts. Positive synthetic fixtures now use per-field,
causally ordered clocks instead of assigning all evidence pre-debit times.
Tests cover one second before, equal to, and after the event for both status
types; late inbound and post-cutoff sources; and event-derived joined fields.

This version is deliberately an internal consistency contract. Even a
causally valid field digest can be manufactured by a caller: it is not
authenticated Bank posting evidence, independent source provenance, proof
that the credited funds were forwarded, or authorization to activate
historical/shadow/inline readiness. Independent PO, Security/Architecture,
Fraud Intelligence and QA exact-head assessment remains required.
