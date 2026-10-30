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
