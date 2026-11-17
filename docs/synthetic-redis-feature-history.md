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
