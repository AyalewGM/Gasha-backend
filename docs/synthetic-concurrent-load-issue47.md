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
Failure labels are sanitized exception class names only. Thread results
are accumulated with an overlapping **process wall-clock window** for
observed events/sec, not the sum of each worker's elapsed seconds.
Mean and nearest-rank P95/P99/max are computed over **all individual event
latencies, including failed attempts**; no averaging of worker percentiles.
A zero measurement window produces null throughput. JSON serialization is
strict (no NaN/Infinity), and no transaction/account/customer IDs appear.

The JSON schema is `gasha-synthetic-concurrent-load-1`; it always reports
`source=synthetic_only`, `bank_kpi_approved=false`,
`bank_delivery_accepted=false`, `enforcement_activated=false`, and
`assessment=BLOCKED_EXTERNAL_BANK_WORKLOAD_AND_DEPLOYMENT`.
Local cycle/worker caps prevent accidental unbounded CI workloads.

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
