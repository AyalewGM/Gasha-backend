"""Synthetic-only Issue #48 device-flow contract / point-in-time negatives."""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.poc.device_flow_evidence import (
    DeviceFlowEvidenceBundleV1,
    DeviceFlowObservationV1,
    DeviceFlowRejected,
    DeviceFlowScopeV1,
    ObservationKind,
    SettlementStatus,
    build_device_flow_bundle_v1,
)

T = datetime(2026, 1, 1, 10, tzinfo=UTC)
TENANT = "fictional-tenant-a"
ACCOUNT = UUID(int=1)
JOURNEY = UUID(int=2)
CASE = UUID(int=3)


def scope(**changes: Any) -> DeviceFlowScopeV1:
    values: dict[str, Any] = {
        "tenant_id": TENANT, "account_ref": ACCOUNT, "journey_ref": JOURNEY,
        "case_ref": CASE, "window_start": T, "cutoff": T + timedelta(hours=1),
        "correlation_seconds": 300, "dataset_digest": "a" * 64,
        "code_version": "b1", "mapping_version": "m1", "config_version": "c1",
        "policy_version": "p1", "rule_version": "r1", "model_version": "ml1",
    }
    values.update(changes)
    return DeviceFlowScopeV1(**values)


def obs(
    number: int, kind: ObservationKind, minute: int, **changes: Any,
) -> DeviceFlowObservationV1:
    values: dict[str, Any] = {
        "tenant_id": TENANT, "account_ref": ACCOUNT, "journey_ref": JOURNEY,
        "event_ref": UUID(int=number), "scenario_id": "ATO-02" if kind is ObservationKind.DEVICE
        else "MM-01", "kind": kind, "occurred_at": T + timedelta(minutes=minute),
        "received_at": T + timedelta(minutes=minute, seconds=1),
        "source_system": "fictional-bank", "source_version": "source-1",
    }
    if kind is ObservationKind.DEVICE:
        values["device_new"] = True
    else:
        values.update({
            "settlement": SettlementStatus.SETTLED,
            "amount_minor": 10000, "currency": "ETB",
            "counterparty_ref": UUID(int=number + 20),
        })
    values.update(changes)
    return DeviceFlowObservationV1(**values)


def build(*events: DeviceFlowObservationV1, s: DeviceFlowScopeV1 | None = None
          ) -> DeviceFlowEvidenceBundleV1:
    return build_device_flow_bundle_v1(s or scope(), events)


def test_new_device_settled_credit_and_debit_at_inclusive_window() -> None:
    device = obs(10, ObservationKind.DEVICE, 5)
    credit = obs(11, ObservationKind.CREDIT, 10)
    debit = obs(12, ObservationKind.DEBIT, 15)
    bundle = build(debit, device, credit)
    data = bundle.to_dict()
    assert data["schema_version"] == "DeviceFlowEvidenceBundleV1"
    assert data["scenario_ids"] == ["ATO-02", "MM-01"]
    assert data["device_new_assertion"] is True
    assert data["credit_to_debit_window_pairs"] == 1
    assert data["settled_amounts_by_currency"] == {
        "ETB": {"credit_minor": 10000, "debit_minor": 10000}
    }
    assert data["rank_components"] == []
    assert data["fraud_confirmed"] == "unknown"
    assert data["deception_inferred"] is False
    assert data["bank_execution"] == "unknown"
    assert data["enforcement_activated"] is False
    assert len(str(data["digest"])) == 64
    assert build(credit, device, debit, debit).digest == bundle.digest


def test_multisender_fanin_is_fact_not_fraud_label() -> None:
    events = (
        obs(10, ObservationKind.DEVICE, 5),
        obs(11, ObservationKind.CREDIT, 10, scenario_id="MM-02"),
        obs(12, ObservationKind.CREDIT, 11, scenario_id="MM-02"),
    )
    data = build(*events).to_dict()
    assert data["scenario_ids"] == ["ATO-02", "MM-02"]
    assert data["distinct_inbound_counterparties"] == 2
    assert data["credit_to_debit_window_pairs"] == 0
    assert data["fraud_confirmed"] == "unknown"
    assert "settled_debit_evidence_unavailable" in data["missing_signals"]


@pytest.mark.parametrize("status", [
    SettlementStatus.POSTED, SettlementStatus.REVERSED,
    SettlementStatus.DECLINED, SettlementStatus.ABANDONED,
])
def test_nonsettled_flow_is_visible_but_not_counted(status: SettlementStatus) -> None:
    data = build(obs(11, ObservationKind.CREDIT, 10, settlement=status)).to_dict()
    assert data["settled_inbound_count"] == 0
    assert data["settled_amounts_by_currency"] == {}
    assert data["events"][0]["settlement"] == status.value
    assert "bank_device_assertion_unavailable" in data["missing_signals"]


def test_window_boundary_outside_and_cross_currency_do_not_infer_link() -> None:
    credit = obs(11, ObservationKind.CREDIT, 10)
    debit = obs(12, ObservationKind.DEBIT, 15, currency="USD")
    assert build(credit, debit).to_dict()["credit_to_debit_window_pairs"] == 0
    assert "bank_fx_normalization_unavailable" in build(credit, debit).to_dict()["missing_signals"]
    debit = replace(debit, currency="ETB", occurred_at=T + timedelta(minutes=15, seconds=1),
                    received_at=T + timedelta(minutes=15, seconds=2))
    assert build(credit, debit).to_dict()["credit_to_debit_window_pairs"] == 0


def test_out_of_order_and_offset_equivalence_have_same_digest() -> None:
    credit = obs(11, ObservationKind.CREDIT, 10)
    debit = obs(12, ObservationKind.DEBIT, 12)
    shifted = replace(credit, occurred_at=credit.occurred_at.astimezone(
        timezone(timedelta(hours=3))), received_at=credit.received_at.astimezone(
        timezone(timedelta(hours=3))))
    assert build(credit, debit).digest == build(debit, shifted).digest
    assert build(credit, debit).digest != build(
        replace(credit, source_version="source-2"), debit
    ).digest
    assert build(credit, debit).digest != build(
        credit, debit, s=scope(policy_version="p2")
    ).digest


def test_same_source_duplicate_deduplicated_conflict_rejected() -> None:
    a = obs(11, ObservationKind.CREDIT, 10)
    assert len(build(a, a).to_dict()["events"]) == 1
    with pytest.raises(DeviceFlowRejected, match="conflicting event"):
        build(a, replace(a, amount_minor=123))


@pytest.mark.parametrize("change", [
    {"tenant_id": "fictional-tenant-b"}, {"account_ref": UUID(int=999)},
    {"journey_ref": UUID(int=999)}, {"scenario_id": "APP-01"},
    {"settlement": "settled"}, {"amount_minor": True},
    {"currency": "US$"}, {"counterparty_ref": "raw-account-number"},
    {"source_version": "invalid\nversion"},
])
def test_invalid_scope_or_observation_rejected(change: dict[str, Any]) -> None:
    with pytest.raises(DeviceFlowRejected):
        build(replace(obs(11, ObservationKind.CREDIT, 10), **change))


@pytest.mark.parametrize("field", ["occurred_at", "received_at"])
def test_future_and_bad_temporal_order_rejected(field: str) -> None:
    event = obs(11, ObservationKind.CREDIT, 10)
    with pytest.raises(DeviceFlowRejected):
        build(replace(event, **{field: T + timedelta(hours=2)}))
    with pytest.raises(DeviceFlowRejected):
        build(replace(event, **{field: T - timedelta(minutes=1)}))


def test_no_device_signal_is_unknown_not_known() -> None:
    data = build(obs(11, ObservationKind.CREDIT, 10)).to_dict()
    assert data["device_new_assertion"] is None
    assert "bank_device_assertion_unavailable" in data["missing_signals"]
    with pytest.raises(DeviceFlowRejected, match="conflicting device"):
        build(obs(10, ObservationKind.DEVICE, 2),
              obs(15, ObservationKind.DEVICE, 3, device_new=False))


class HostileZone(tzinfo):
    calls = 0

    def utcoffset(self, dt: datetime | None) -> timedelta:
        self.calls += 1
        return timedelta(0)

    def dst(self, dt: datetime | None) -> timedelta:
        return timedelta(0)


class PretendDatetime:
    calls = 0

    @property
    def __class__(self) -> type[datetime]:
        self.calls += 1
        return datetime


@pytest.mark.parametrize("field", ["occurred_at", "received_at"])
@pytest.mark.parametrize("variant", ["forged", "custom_zone", "subclass"])
def test_no_hostile_clock_callbacks(field: str, variant: str) -> None:
    class DerivedDateTime(datetime):
        pass

    hostile = PretendDatetime()
    zone = HostileZone()
    value: Any = (
        hostile if variant == "forged" else
        datetime(2026, 1, 1, 10, 10, tzinfo=zone) if variant == "custom_zone" else
        DerivedDateTime(2026, 1, 1, 10, 10, tzinfo=UTC)
    )
    with pytest.raises(DeviceFlowRejected):
        build(replace(obs(11, ObservationKind.CREDIT, 10), **{field: value}))
    assert hostile.calls == 0
    assert zone.calls == 0


def test_zoneinfo_and_detached_json_response() -> None:
    a = obs(11, ObservationKind.CREDIT, 10)
    at = a.occurred_at.astimezone(ZoneInfo("America/New_York"))
    received = a.received_at.astimezone(ZoneInfo("America/New_York"))
    bundle = build(replace(a, occurred_at=at, received_at=received))
    out = bundle.to_dict()
    out["events"].clear()
    assert len(bundle.to_dict()["events"]) == 1


def test_malformed_scope_rejected_before_reading_events() -> None:
    with pytest.raises(DeviceFlowRejected):
        build(s=scope(dataset_digest="unsafe"))
    with pytest.raises(DeviceFlowRejected):
        build(s=scope(correlation_seconds=True))
    with pytest.raises(DeviceFlowRejected):
        build(s=scope(window_start=T + timedelta(days=2)))
