# Issue #47 — synthetic shadow load baseline (not bank acceptance)

Run from an editable development install with the repository's pinned dependencies:

```sh
python -m gasha.poc.load_baseline --iterations 20 --warmup 2 > synthetic-load.json
pytest -q tests/test_poc_load_baseline.py
```

The runner uses the existing reference-json ingestion, journey ingestion and
tenant-scoped journey repository, then the **existing** `ShadowOrchestrator`
and decision engine. Each local iteration processes the synthetic account-
takeover journey (UC-03), the simulated coached-payment/remote-access signals
(UC-01), mule/beneficiary signals (UC-02), and normal/ambiguous cases. An
identical payment is resent once per cycle to observe idempotent ingestion.
Fresh in-memory dependencies per cycle avoid cross-cycle identifier collision.
Warm-up cycles are deliberately excluded from the measured sample set.

The JSON reports actual sequential local event attempts, accepted journey
events, payment evaluations, duplicates, exception-class counts, total measured
wall time, observed event rate and per-event mean/nearest-rank P95/P99/max
processing time. Nonpositive elapsed windows yield **null throughput**.
No customer identifiers or raw event payloads appear in the output. If an
evaluation unexpectedly produces an enforcing effective action, the attempt
is marked failed, never counted as an accepted decision.

**This is engineering instrumentation, not a CBE SOW performance result.**
It uses a synthetic distribution, one sequential process, in-memory state
and no real bank adapter, auth, PostgreSQL, Kafka, proxy, TLS, worker failover,
parallel sustained/peak arrival profile or real resource telemetry. The report
therefore hard-codes `bank_kpi_approved=false`,
`bank_delivery_accepted=false`, and `enforcement_activated=false` and
reports `BLOCKED_EXTERNAL_BANK_WORKLOAD_AND_DEPLOYMENT` regardless of measured
latency or error count.

Before a bank-facing PASS can even be considered, the Bank and PO must
approve the workload, UC mix, concurrency, size/duration, timeout and KPI
thresholds. Security/Architecture must approve the real shadow adapter's
failure isolation. Independent QA must then measure the combined installed
path behind the approved bank ingress, inject database/broker/process failures,
record resource/error/latency tails and reconcile all terminal/pending
outcomes, pinned to the exact SHA/image/config/dependencies. Nothing in this
baseline authorizes HOLD/BLOCK execution, protected API deployment, evidence
registry approval or a merge.
