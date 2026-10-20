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


def test_terminal_transition_is_idempotent_and_blocks_redelivery():
    from gasha.ingestion.errors import RejectionReason, RejectionRecord
    from gasha.ingestion.service import InMemoryDeadLetterSink
    store = InMemoryPendingEvaluationStore(worker_id='a')
    env = envelope()
    claim = store.enqueue(env, enqueued_at=T0)
    sink = InMemoryDeadLetterSink()
    rejection = RejectionRecord(tenant_id=env.tenant_id, event_id=str(env.event_id),
                                reason=RejectionReason.EVALUATION_FAILURE, detail='synthetic')
    assert store.terminate(claim, rejection, dead_letters=sink, owner='a', now=T0)
    assert not store.terminate(claim, rejection, dead_letters=sink, owner='a', now=T0)
    assert store.enqueue(env, enqueued_at=T0).terminal
    assert store.due(T0 + timedelta(days=1)) == ()
    assert len(sink.records) == 1


def test_late_worker_terminal_branches_do_not_emit_after_takeover():
    from test_postgres_evaluations import _StubConsumer

    from gasha.ingestion.errors import RejectionReason
    from gasha.ingestion.service import IngestionService, InMemoryDeadLetterSink
    from gasha.ingestion.worker import IngestionWorker
    store = InMemoryPendingEvaluationStore(worker_id='same-worker')
    env = envelope()
    old = store.enqueue(env, enqueued_at=T0)
    new = store.due(T0 + timedelta(minutes=6))[0]
    sink = InMemoryDeadLetterSink()
    worker = IngestionWorker(_StubConsumer([]), IngestionService({}),
                             pending=store, dead_letters=sink,
                             worker_id='same-worker', clock=lambda: T0)
    for reason in (RejectionReason.EVALUATION_FAILURE,
                   RejectionReason.TENANT_CONFIGURATION_UNAVAILABLE):
        worker._terminal_failure(old, reason, 'late synthetic failure')
        assert not sink.records
    store.complete(env.tenant_id, env.event_id, owner='same-worker',
                   claim_token=new.claim_token, now=T0 + timedelta(minutes=6))
    worker._terminal_failure(old, RejectionReason.EVALUATION_FAILURE, 'late after success')
    assert not sink.records
