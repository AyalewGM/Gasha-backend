# Synthetic Redis feature history

The opt-in Redis adapter stores point-in-time observations for the existing
one-hour transfer, distinct sender and device features. It shares the offline
calculator and preserves its event-time and availability cutoffs. The adapter
takes a synchronous Redis client. Configure bounded connection and command
timeouts on that client.

A server-owned producer creates a unique tenant/epoch, declares the covered
event-time start, appends observations, then seals the latest availability
cutoff for which it has complete upstream coverage. An exact duplicate can
replay after sealing. Conflicting duplicates fail closed.
A previously unseen in-range event at or before the sealed availability cutoff
invalidates the whole epoch atomically. Its reads and writes remain unavailable
until the producer rebuilds the history under a fresh epoch identifier. The
producer owns the truth of its coverage claim.

Reads require a complete one-hour window and a sealed cutoff. A prior
relationship observed within the retained evidence is returned as known.
Absent evidence of a relationship is returned as unavailable, since a bounded
history cannot establish first-ever interaction. An epoch has a fixed TTL and
a capacity of 4,096 observations. All events expire together. Missing, expired,
malformed and over-capacity epochs fail closed. The producer must use a fresh
epoch identifier for a rebuild.

Run the synthetic integration suite against a dedicated local Redis instance.

```bash
pip install -e '.[dev,redis]'
GASHA_TEST_REDIS_URL=redis://127.0.0.1:6379/0 pytest -q \
  tests/test_feature_set_v1.py tests/test_redis_feature_history.py
```

The API and worker still need an authorized source adapter, broker progress and
rebuild semantics, Redis credentials and scoped permissions, operational sizing,
and a reviewed mapping from features to decision inputs before deployment.

## Coverage semantics for the next synthetic MVE wiring

The historical *first-ever sender/beneficiary relationship* and a sealed,
complete *one-hour beneficiary fan-in window* are different claims. The
opt-in synthetic assessor now accepts `beneficiary_window_complete=True`
independently of `relationship_history_complete=False`; this allows a
window-local sender count while preserving an unavailable relationship
absence. A missing or unverified one-hour coverage assertion still yields
unavailable fan-in, not zero. The separate coverage claim changes the
computation fingerprint, even if its numeric count matches the fully
covered fixture. Existing callers retain their previous defaults.

This is **contract preparation only**. An in-process boolean is **not**
evidence of a real source's completeness. The runtime has not yet been
wired to authenticate a Redis producer, bind the epoch/receipt cutoff to
the pending event, prove the Redis seal, or pass this coverage scope to
the pending-worker evaluator. Do not set this flag from a Bank payload,
browser input, arbitrary precomputed number, or an unverified Redis
watermark. The existing single-command MVE still uses in-process
synthetic observations; Redis-to-worker composition and offline/Redis
equivalence remain separate required checks under #145.

No Bank data, model activation, payment enforcement, installed IdP or
NetGuardians action is introduced by this bounded source change.

## Opt-in worker composition (synthetic-only)

`RedisSyntheticHistorySource` is now an explicitly constructed
`SyntheticShadowWorkerEvaluator` history source for the **existing**
`IngestionWorker` pending-ledger, `ShadowOrchestrator`, PostgreSQL evaluation
writer and protected analyst evidence path. The source receives a
process-configured `RedisFeatureHistory` (tenant and fresh epoch), permitted
synthetic `source_system` and versioned graph policy. The worker supplies
only its trusted, normalized pending envelope. Redis is read as one validated,
sealed snapshot at that envelope's **receipt cutoff**, with the full one-hour
event-time window required. The computed features are prior-only; the
one-hour fan-in is available, but historical first-ever relationship **absence**
remains unavailable. Neither a copy payload nor the analyst browser can
supply the seal, epoch, coverage assertion or a precomputed score.

The Redis snapshot's opaque tenant/epoch fingerprint is included in the
assessment's hashed source lineage. It is **not** producer authentication, a
Bank watermark, or evidence that all upstream observations were delivered.
The source uses the existing worker's retry/terminal-dead-letter handling
for missing, expired, contradictory or unavailable coverage; no alert,
case or evaluation is written from a partial snapshot. On crash recovery,
the normalized event comes from the existing durable PostgreSQL pending
ledger, not an in-memory per-event fixture map.

The dedicated PostgreSQL+Redis CI job runs both stores and repeats the
existing synthetic worker-outage → durable alert/deduped case → protected
FastAPI analyst evidence and lifecycle regression in Redis mode. Test
fixtures create and seal an invented epoch before allowing evaluation.
This is **not installed Bank/NetGuardians integration**, a certified
bank-origin clock/seal, a representative throughput test, approved
Bank identity/CSRF or an authoritative #49 readiness assessment.
The live worker's default configuration remains unchanged and this source is
not registered as a Bank adapter or enabled by default.

Additional release blockers: provision authenticated producer/watermark
authority, reconstructible epoch lifecycle and durable producer checkpoints,
Redis ACLs/credentials/expiry operations, immutable mapping to versioned
policy and source identity, installed frontend repin/verification,
Bank-approved workload and fault injection, and independent PO,
Security/Architecture, Fraud ML and QA review. No enforcement is enabled.
