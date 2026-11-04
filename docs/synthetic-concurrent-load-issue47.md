# Issue #47 — threaded, isolated synthetic shadow profiling

This is an **opt-in developer measurement harness**, not a deployment adapter, a
bank-performance/SOW result or a candidate authority to enable payment action.
It extends the existing, already-integrated sequential synthetic benchmark
(#60/#66); it does not rewrite it, the protected API, Kafka workers, or the
merged #52/#53/#54 infrastructure.

Run on an editable installation with pinned repository dependencies:

```sh
python -m gasha.poc.concurrent_load --workers 2 --iterations 2 --warmup 1 > synthetic-concurrent.json
pytest -q tests/test_poc_concurrent_load.py
```

The threaded runner launches independent instances of the **existing**
`run_synthetic_shadow_baseline`. Every worker executes the existing UC-01/
UC-02/UC-03 mixture, including one duplicate payment per iteration, with
fresh, isolated in-memory event, journey and evaluation repositories.
Warm-up iterations are excluded from sample counts. A worker crash stops
the entire run; no successful partial result is emitted.

The aggregation reuses the existing strict `SyntheticLoadReport` validator:
all accepted journeys, payments, transport duplicates, failures, and latency
samples must reconcile to *one measured attempted-event population*.
Failure labels are sanitized exception class names only. The outer process
wall clock spans thread dispatch through join. **With warm-up enabled**, it
includes warm-up time even though the event population excludes warm-up.
Therefore `observed_events_per_second` and `measured_window_elapsed_seconds`
are **null** for every `warmup_per_worker > 0` run: the numerator must not be
divided by a mismatched full-run denominator. The machine-readable
`throughput_undefined_reason=warmup_not_separately_timed` and
`measurement_window=unavailable_warmup_not_isolated` explain this block.
`whole_run_elapsed_seconds` (also the legacy `elapsed_seconds`) is
diagnostic only in that case, not a measured-throughput denominator.

With zero warm-up, the full overlapping wall-clock interval is the
approximate measured concurrent run duration, including thread dispatch
overhead, and may be used for a synthetic rate. A zero interval yields null
throughput and `throughput_undefined_reason=zero_elapsed_window`.
Mean and nearest-rank P95/P99/max are computed over **all individual event
latencies, including failed attempts**; no averaging of worker percentiles.
JSON serialization is
strict (no NaN/Infinity), and no transaction/account/customer IDs appear.

The JSON schema is `gasha-synthetic-concurrent-load-1`; it always reports
`source=synthetic_only`, `bank_kpi_approved=false`,
`bank_delivery_accepted=false`, `enforcement_activated=false`, and
`assessment=BLOCKED_EXTERNAL_BANK_WORKLOAD_AND_DEPLOYMENT`.
Local cycle/worker caps prevent accidental unbounded CI workloads.

**Correction scope:** This deliberately chooses the PO/QA-approved *null-rate*
fallback rather than misrepresenting a mixed-duration measurement as a
post-warm-up concurrent throughput. A future true measured-window rate
requires a separately reviewed synchronized post-warm-up measurement boundary.
Deterministic tests cover one/two workers, no/short/slow warm-up, null-rate
semantics and aborted workers. No Bank acceptance should use a null rate.

**Critical limitations:** Python threads and isolated in-memory repositories do
not establish sustained peak arrival rate, CPU scaling, shared-state concurrency,
real Kafka/PostgreSQL recovery, secure proxy/IdP behavior, real payment-adapter
failure isolation or a representative Bank P95/P99/SLA. This test is an
intermediate instrumentation step only.

Full #47 remains open until PO/Bank approve workload mix, arrival profile,
timeout budget and KPI thresholds, Security/Architecture approve the actual
shadow integration boundary, and Independent QA execute combined installed
synthetic tests with resource telemetry, real failure/recovery, duplicate/retry
reconciliation and proof that incumbent processing is never delayed or
blocked by shadow failures. The #49 caller-asserted readiness evaluator remains
non-authoritative. No bank deployment, stage advancement or enforcement is
implemented.
