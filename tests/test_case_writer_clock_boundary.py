"""#45 opt-in transition writer clock guard; no Bank install or DB required.

These tests exercise the internal writer boundary directly. The protected HTTP
integration and actual PostgreSQL transactional path have separate tests.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone, tzinfo
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.api.main import CaseTransitionInput
from gasha.cases.postgres_writer_bridge import ExplicitPostgresCaseTransitionWriter
from gasha.cases.timeline import CaseOperation, CaseReason, CaseRejected
from gasha.security.access import Capability, TrustedPrincipal


class CallbackTimezone(tzinfo):
    """Adversarial in-process clock: reading its offset executes code."""

    def __init__(self) -> None:
        self.callbacks = 0

    def utcoffset(self, _dt: datetime | None) -> timedelta:
        self.callbacks += 1
        return timedelta(0)

    def dst(self, _dt: datetime | None) -> timedelta:
        return timedelta(0)

    def tzname(self, _dt: datetime | None) -> str:
        return "untrusted"


class CallbackDatetime(datetime):
    """A subclass must not override writer time checks."""

    callbacks = 0

    def utcoffset(self) -> timedelta:
        self.callbacks += 1
        return timedelta(0)


class ForbiddenDependency:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        raise AssertionError("database boundary reached")

    def resolve(self, **_kwargs: object) -> object:
        self.calls += 1
        raise AssertionError("directory boundary reached")


def _principal() -> TrustedPrincipal:
    return TrustedPrincipal(
        subject="fictional-analyst",
        issuer="synthetic-test",
        credential_ref="fictional-credential",
        tenant_ids=frozenset({"tenant-a"}),
        capabilities=frozenset({
            Capability.CASE_CREATE, Capability.CASE_TRIAGE, Capability.CASE_ASSIGN,
            Capability.CASE_DISPOSITION, Capability.CASE_CORRECT,
            Capability.CASE_FEEDBACK,
        }),
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
    )


def _proposal() -> CaseTransitionInput:
    return CaseTransitionInput(
        source_event_id=UUID(int=2),
        expected_revision=0,
        idempotency_key="a" * 32,
        reason_code=CaseReason.SOURCE_EVALUATION,
    )


def _writer() -> tuple[
    ExplicitPostgresCaseTransitionWriter, ForbiddenDependency, ForbiddenDependency,
]:
    database = ForbiddenDependency()
    directory = ForbiddenDependency()
    return (
        ExplicitPostgresCaseTransitionWriter(
            connections=database, evaluations=directory, assignees=directory,
        ),
        database,
        directory,
    )


@pytest.mark.parametrize("operation", list(CaseOperation))
def test_reject_custom_tzinfo_without_callback_or_any_dependency(
    operation: CaseOperation,
) -> None:
    writer, database, directory = _writer()
    custom = CallbackTimezone()
    untrusted = datetime(2026, 11, 7, 12, tzinfo=custom)
    with pytest.raises(CaseRejected, match="typed protected case transition"):
        writer.apply(
            principal=_principal(), tenant_id="tenant-a",
            case_id=UUID(int=1), operation=operation,
            proposal=_proposal(), at=untrusted,
        )
    assert custom.callbacks == 0
    assert database.calls == directory.calls == 0


@pytest.mark.parametrize("operation", list(CaseOperation))
def test_reject_datetime_subclass_without_callback_or_any_dependency(
    operation: CaseOperation,
) -> None:
    writer, database, directory = _writer()
    untrusted = CallbackDatetime(2026, 11, 7, 12, tzinfo=UTC)
    with pytest.raises(CaseRejected, match="typed protected case transition"):
        writer.apply(
            principal=_principal(), tenant_id="tenant-a",
            case_id=UUID(int=1), operation=operation,
            proposal=_proposal(), at=untrusted,
        )
    assert untrusted.callbacks == 0
    assert database.calls == directory.calls == 0


@pytest.mark.parametrize("instant", [
    datetime(2026, 11, 7, 12, tzinfo=UTC),
    datetime(2026, 11, 7, 8, tzinfo=timezone(timedelta(hours=-4))),
    datetime(2026, 11, 1, 1, 15, tzinfo=ZoneInfo("America/New_York"), fold=1),
])
def test_trusted_utc_fixed_offset_and_dst_fold_reach_installed_boundary(
    instant: datetime,
) -> None:
    writer, database, directory = _writer()
    with pytest.raises(AssertionError, match="database boundary reached"):
        writer.apply(
            principal=_principal(), tenant_id="tenant-a",
            case_id=UUID(int=1), operation=CaseOperation.CREATE,
            proposal=_proposal(), at=instant,
        )
    assert database.calls == 1
    assert directory.calls == 0
