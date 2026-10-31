# Internal POC report schema v2 (Issue #48, draft PR #58)

The `build_poc_report` output is a **non-authoritative internal POC measurement**.
It is not proof of bank data provenance, an approved KPI, a verified readiness
artifact or permission to enforce a transaction.

## Version contract

- Schema `poc-report-1` had numeric rate fields that could represent undefined
  zero-denominator populations as measured 0 or 1. Its meaning is retired for
  new reports; do not relabel a historical v1 payload as v2.
- Schema `poc-report-2` changes recall, precision, F1, false-positive and
  false-negative rates, explainability coverage, signal-family shares and
  ablation recall deltas to nullable values where undefined. It requires
  numerator, denominator and reason evidence for applicable rates.
- `POCReport.model_validate` / `model_validate_json` accept only the literal
  `poc-report-2` identifier and require the new evidence fields. The report
  builder rejects caller-selected v1, blank and unknown version overrides.
  Consumers must validate the payload before using rates or displaying claims.
  Unknown or missing versions **fail closed**, not silently downgraded.
- A value of `null` means **not measurable for this cohort**. It is not zero,
  pass, a perfect score, or a substitute for an agreed Bank threshold.
  Where a denominator is positive, `value = numerator / denominator`.
  Previous archived v1 reports require separate legacy readers and explicit
  provenance; no automatic migration is included here.

## Integration and authority limits

Version matching verifies payload shape only, not collection source, verified
labels, tenant/dataset fingerprint, maturity cutoff, point-in-time feature
lineage or the independence of a reviewer. No report emitted by this code can
satisfy #49's trusted readiness evidence registry. Combined #56 historical
timing, #57 reconciled incumbent cohorts and #58 report-v2 semantics must be
independently tested on the integrated code before bank-facing export.

The versioned consumer checks in `tests/test_poc_report_schema_version.py`
cover valid round trip; missing, legacy and unknown versions; required new
evidence fields; and rejected builder version overrides. Existing #58 rate
tests cover zero and nonzero population semantics.


## Arithmetic-integrity checks (bounded internal consumer)

The v2 Pydantic consumer now rejects inconsistent or non-finite rate evidence,
missing/contradictory zero-denominator reasons, wrong confusion populations,
negative counts, mismatched headline rates, false event totals/prevalence,
explainability alert denominators, signal-family share denominators, ablation
recall deltas and incumbent comparison partitions. These are *arithmetic*
invariants, not authentication, signatures or verified data provenance. A
consistent but fabricated payload can still pass; #42/#49 trusted collection
and independent verification remain mandatory before any bank-facing use.

## Numeric evidence and timing integrity (bounded JSON consumer)

Count-bearing report fields, including incumbent joint-alert partitions, signal
attribution, ablation confusion counts, unique detections and multi-signal map
values, are **strict nonnegative integers**. JSON booleans, numeric strings,
fractional/float encodings and negative counts are rejected rather than
coerced. The exception is `ablation.false_positive_delta`: it is a **strict
signed integer**, because a negative difference is meaningful. Nullable
ablation recall deltas are signed rates, separately checked against computed
recall; they are not counts.

All non-null decision, detection and processing *duration* fields must be
finite, nonnegative numbers, not numeric strings, NaN or infinities. Processing
summary statistics require `median <= p95 <= p99 <= max` and `mean <= max`
where values exist. Missing original observation clocks produce `null`, not
zero; replay-derived negative detection lead times are also treated as unknown
rather than reported as observed elapsed time. This does not independently
prove original bank event-time, feature or label provenance.

These constraints are checked through `POCReport.model_validate_json` negative
regressions; they do **not** verify bank identity, tenant authority, dataset
fingerprints, reviewer approvals or the #49 evidence registry.
