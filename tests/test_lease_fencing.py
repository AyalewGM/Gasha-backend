from datetime import timedelta

from test_postgres_evaluations import T0, envelope

from gasha.ingestion.pending import InMemoryPendingEvaluationStore


def test_expired_and_reused_owner_cannot_mutate_new_claim():
    store = InMemoryPendingEvaluationStore(worker_id='same-worker')
    env = envelope()
    old = store.enqueue(env, enqueued_at=T0)
    expired = T0 + timedelta(minutes=6)
    assert store.reschedule(
        env.tenant_id, env.event_id, owner='same-worker', claim_token=old.claim_token,
        error='late', next_attempt_at=expired, now=expired,
    ) is None
    store.complete(env.tenant_id, env.event_id, owner='same-worker',
                   claim_token=old.claim_token, now=expired)
    new = store.due(expired)[0]
    assert new.claim_token != old.claim_token
    assert store.due(expired) == ()  # even the same worker cannot reclaim an active lease
    store.complete(env.tenant_id, env.event_id, owner='same-worker',
                   claim_token=old.claim_token, now=expired)
    assert store.reschedule(
        env.tenant_id, env.event_id, owner='same-worker', claim_token=old.claim_token,
        error='late', next_attempt_at=expired, now=expired,
    ) is None
    store.complete(env.tenant_id, env.event_id, owner='same-worker',
                   claim_token=new.claim_token, now=expired)
    assert store.due(expired) == ()


def test_worker_persistence_rejects_missing_claim_context():
    import pytest
    from test_postgres_evaluations import POLICY, FakeConnection

    from gasha.ingestion.lease import LeaseLostError, current_evaluation_lease
    from gasha.orchestration import ShadowOrchestrator
    from gasha.postgres_evaluations import PostgresEvaluationPersistence

    connection = FakeConnection()
    orchestrator = ShadowOrchestrator(
        {'tenant-a': POLICY},
        persistence=PostgresEvaluationPersistence(connection, require_lease=True),
    )
    assert current_evaluation_lease.get() is None
    with pytest.raises(LeaseLostError):
        orchestrator.evaluate(envelope(), POLICY)
    assert not connection.rows
    assert not connection.audit_rows
