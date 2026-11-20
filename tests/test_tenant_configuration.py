"""Issue #147 inert tenant configuration kernel tests; never bank authority."""

from dataclasses import replace
from json import dumps, loads
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any

import pytest

from gasha.domain.models import DecisionPolicy

from gasha.configuration.kernel import (
    ConfigKind,
    ConfigLifecycle,
    TenantConfigEntry,
    TenantConfigRejected,
    canonical_content,
    content_digest,
    decode_row,
    new_draft,
    plan_activation,
    plan_retirement,
    resolve_active,
)

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
PROVISIONER = "a" * 64

POLICY = {
    "configuration_version": "cfg-1",
    "policy_version": "policy-1",
    "rule_version": "rules-1",
    "model_version": None,
    "monitor_threshold": 0.5,
    "review_threshold": 0.7,
    "hold_threshold": 0.85,
    "block_threshold": 0.95,
}

BUNDLE = {
    "social_engineering": {"policy_version": "se-1", "new_beneficiary_risk": 0.72},
    "journey": {"policy_version": "j-1", "window_minutes": 60},
}


def draft(version: int = 1, *, tenant: str = "tenant-a", **kwargs: Any) -> TenantConfigEntry:
    return new_draft(
        tenant_id=tenant,
        config_kind=kwargs.get("kind", ConfigKind.DECISION_POLICY),
        version=version,
        payload=kwargs.get("payload", POLICY),
        created_at=kwargs.get("created_at", NOW),
        created_by_ref=kwargs.get("created_by_ref", PROVISIONER),
    )


def activate(candidate: TenantConfigEntry, incumbent=None, at=None):
    return plan_activation(
        candidate=candidate, incumbent=incumbent, at=at or NOW + timedelta(hours=1)
    )


def row_of(entry: TenantConfigEntry) -> dict[str, object]:
    return {
        "tenant_id": entry.tenant_id,
        "config_kind": entry.config_kind.value,
        "version": entry.version,
        "lifecycle": entry.lifecycle.value,
        "content_json": entry.content_json,
        "content_digest": entry.content_digest,
        "created_at": entry.created_at,
        "created_by_ref": entry.created_by_ref,
        "activated_at": entry.activated_at,
        "retired_at": entry.retired_at,
        "supersedes_version": entry.supersedes_version,
    }


def test_draft_is_deterministic_and_digest_bound() -> None:
    first, second = draft(), draft()
    assert first == second
    assert first.lifecycle is ConfigLifecycle.DRAFT
    assert first.content_digest == content_digest(ConfigKind.DECISION_POLICY, first.content_json)
    assert len(first.content_digest) == 64
    assert not hasattr(first, "authority")
    assert not hasattr(first, "enforcement")


def test_policy_payload_requires_exact_fields_and_ordered_thresholds() -> None:
    with pytest.raises(TenantConfigRejected):
        canonical_content(ConfigKind.DECISION_POLICY, {**POLICY, "extra": 1})
    with pytest.raises(TenantConfigRejected):
        canonical_content(
            ConfigKind.DECISION_POLICY,
            {**POLICY, "hold_threshold": 0.6},
        )
    with pytest.raises(TenantConfigRejected):
        canonical_content(
            ConfigKind.DECISION_POLICY,
            {**POLICY, "monitor_threshold": True},
        )
    with pytest.raises(TenantConfigRejected):
        canonical_content(
            ConfigKind.DECISION_POLICY,
            {**POLICY, "policy_version": ""},
        )


def test_bundle_rejects_unknown_detectors_and_nested_params() -> None:
    assert canonical_content(ConfigKind.DETECTOR_POLICY_BUNDLE, BUNDLE)
    with pytest.raises(TenantConfigRejected):
        canonical_content(
            ConfigKind.DETECTOR_POLICY_BUNDLE,
            {**BUNDLE, "mystery": {"policy_version": "x", "k": 1}},
        )
    with pytest.raises(TenantConfigRejected):
        canonical_content(
            ConfigKind.DETECTOR_POLICY_BUNDLE,
            {"journey": {"policy_version": "j-1", "nested": {"a": 1}}},
        )
    with pytest.raises(TenantConfigRejected):
        canonical_content(ConfigKind.DETECTOR_POLICY_BUNDLE, {})


def test_activation_retires_incumbent_atomically_in_plan() -> None:
    _, active_v1 = activate(draft(1))
    candidate_v2 = draft(2)
    retired, activated = plan_activation(
        candidate=candidate_v2,
        incumbent=active_v1,
        at=NOW + timedelta(hours=2),
    )
    assert retired is not None and retired.lifecycle is ConfigLifecycle.RETIRED
    assert activated.lifecycle is ConfigLifecycle.ACTIVE
    assert activated.supersedes_version == 1
    assert retired.retired_at == activated.activated_at


def test_activation_rules() -> None:
    _, active_v1 = activate(draft(1))
    with pytest.raises(TenantConfigRejected):
        plan_activation(candidate=active_v1, incumbent=None, at=NOW)
    with pytest.raises(TenantConfigRejected):
        plan_activation(candidate=draft(2), incumbent=None, at=NOW)
    with pytest.raises(TenantConfigRejected):
        plan_activation(candidate=draft(1, tenant="tenant-b"), incumbent=active_v1, at=NOW)
    with pytest.raises(TenantConfigRejected):
        plan_activation(candidate=draft(1), incumbent=active_v1, at=NOW)
    stale = draft(1, created_at=NOW + timedelta(hours=5))
    with pytest.raises(TenantConfigRejected):
        plan_activation(candidate=stale, incumbent=None, at=NOW)


def test_retirement_only_from_active() -> None:
    _, active = activate(draft(1))
    retired = plan_retirement(entry=active, at=NOW + timedelta(hours=3))
    assert retired.lifecycle is ConfigLifecycle.RETIRED
    with pytest.raises(TenantConfigRejected):
        plan_retirement(entry=draft(), at=NOW)
    with pytest.raises(TenantConfigRejected):
        plan_retirement(entry=retired, at=NOW + timedelta(hours=4))
    with pytest.raises(TenantConfigRejected):
        plan_retirement(entry=active, at=NOW - timedelta(hours=1))


def test_resolve_active_unique_covering_version() -> None:
    _, v1 = activate(draft(1))
    v1_retired, v2 = plan_activation(candidate=draft(2), incumbent=v1, at=NOW + timedelta(hours=2))
    rows = [row_of(v1_retired), row_of(v2), row_of(draft(3))]
    resolved = resolve_active(
        rows,
        tenant_id="tenant-a",
        config_kind=ConfigKind.DECISION_POLICY,
        at=NOW + timedelta(hours=3),
    )
    assert resolved.version == 2
    # Historical instant resolves the retired row.
    past = resolve_active(
        rows,
        tenant_id="tenant-a",
        config_kind=ConfigKind.DECISION_POLICY,
        at=NOW + timedelta(hours=1, minutes=30),
    )
    assert past.version == 1
    # Retirement boundary: instant at retirement resolves the successor.
    boundary = resolve_active(
        rows,
        tenant_id="tenant-a",
        config_kind=ConfigKind.DECISION_POLICY,
        at=NOW + timedelta(hours=2),
    )
    assert boundary.version == 2


def test_resolve_active_fails_closed() -> None:
    _, active = activate(draft(1))
    rows = [row_of(active)]
    with pytest.raises(TenantConfigRejected):
        resolve_active(
            [],
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            at=NOW,
        )
    with pytest.raises(TenantConfigRejected):
        resolve_active(
            rows,
            tenant_id="tenant-b",
            config_kind=ConfigKind.DECISION_POLICY,
            at=NOW + timedelta(hours=2),
        )
    with pytest.raises(TenantConfigRejected):
        resolve_active(
            rows,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DETECTOR_POLICY_BUNDLE,
            at=NOW + timedelta(hours=2),
        )
    duplicate = rows + [row_of(replace(active, version=9))]
    with pytest.raises(TenantConfigRejected):
        resolve_active(
            duplicate,
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            at=NOW + timedelta(hours=2),
        )
    # Before any activation: nothing covers the instant.
    with pytest.raises(TenantConfigRejected):
        resolve_active(
            [row_of(draft())],
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            at=NOW,
        )
    # A later activation is ignored for a historical instant but is corrupt
    # when it post-dates the caller's trusted horizon.
    future = replace(
        active,
        version=9,
        activated_at=NOW + timedelta(days=30),
        supersedes_version=1,
    )
    resolved = resolve_active(
        rows + [row_of(future)],
        tenant_id="tenant-a",
        config_kind=ConfigKind.DECISION_POLICY,
        at=NOW + timedelta(hours=2),
    )
    assert resolved.version == 1
    with pytest.raises(TenantConfigRejected):
        resolve_active(
            rows + [row_of(future)],
            tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY,
            at=NOW + timedelta(hours=2),
            horizon=NOW + timedelta(hours=2),
        )


def test_decode_row_revalidates_store_bytes() -> None:
    _, active = activate(draft(1))
    entry = decode_row(row_of(active))
    assert entry == active
    # JSONB drivers return objects; canonicalization still binds the digest.
    jsonb_row = row_of(active)
    jsonb_row["content_json"] = {
        "policy_version": "policy-1",
        "block_threshold": 0.95,
        "configuration_version": "cfg-1",
        "rule_version": "rules-1",
        "model_version": None,
        "monitor_threshold": 0.5,
        "hold_threshold": 0.85,
        "review_threshold": 0.7,
    }
    assert decode_row(jsonb_row) == active
    # Tampered digest or content is rejected.
    bad = row_of(active)
    bad["content_digest"] = "f" * 64
    with pytest.raises(TenantConfigRejected):
        decode_row(bad)
    bad2 = row_of(active)
    bad2["lifecycle"] = "executing"
    with pytest.raises(TenantConfigRejected):
        decode_row(bad2)
    with pytest.raises(TenantConfigRejected):
        decode_row({"tenant_id": "tenant-a"})
    with pytest.raises(TenantConfigRejected):
        decode_row("not a row")


class CallbackTZ(tzinfo):
    def utcoffset(self, dt):
        return timedelta(0)


def test_hostile_clocks_rejected_before_callbacks() -> None:
    with pytest.raises(TenantConfigRejected):
        draft(created_at=datetime(2026, 11, 14, 12, 0, tzinfo=CallbackTZ()))
    _, active = activate(draft(1))
    with pytest.raises(TenantConfigRejected):
        plan_retirement(entry=active, at=datetime(2026, 11, 15, tzinfo=CallbackTZ()))
    # Naive datetime is not a trusted clock either.
    with pytest.raises(TenantConfigRejected):
        draft(created_at=datetime(2026, 11, 14, 12, 0))


def test_entry_coherence_rules() -> None:
    base = draft()
    with pytest.raises(TenantConfigRejected):
        replace(base, lifecycle=ConfigLifecycle.ACTIVE)
    with pytest.raises(TenantConfigRejected):
        replace(base, version=0)
    with pytest.raises(TenantConfigRejected):
        replace(base, content_digest="0" * 64)
    with pytest.raises(TenantConfigRejected):
        replace(base, tenant_id="bad tenant!")
    # Draft pretending history fields is rejected.
    with pytest.raises(TenantConfigRejected):
        replace(base, activated_at=NOW)



def test_stored_rows_revalidate_kind_schema_even_with_valid_digest() -> None:
    base = draft()
    for kind, content in (
        (ConfigKind.DECISION_POLICY, "{}"),
        (ConfigKind.DETECTOR_POLICY_BUNDLE, base.content_json),
    ):
        digest = content_digest(kind, content)
        with pytest.raises(TenantConfigRejected):
            replace(base, config_kind=kind, content_json=content, content_digest=digest)
        row = row_of(base)
        row["config_kind"] = kind.value
        row["content_json"] = content
        row["content_digest"] = digest
        with pytest.raises(TenantConfigRejected):
            decode_row(row)


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_detector_parameters_rejected_before_digest_or_storage(invalid: float) -> None:
    payload = {"journey": {"policy_version": "j-1", "window_minutes": invalid}}
    with pytest.raises(TenantConfigRejected):
        canonical_content(ConfigKind.DETECTOR_POLICY_BUNDLE, payload)
    with pytest.raises(TenantConfigRejected):
        draft(kind=ConfigKind.DETECTOR_POLICY_BUNDLE, payload=payload)


def test_nonfinite_stored_json_rejected_even_with_matching_digest() -> None:
    entry = draft()
    # Python's JSON parser accepts nonstandard NaN, but durable configuration
    # and canonical digests must never accept it.
    content = '{"block_threshold":NaN,"configuration_version":"cfg-1","hold_threshold":0.85,"model_version":null,"monitor_threshold":0.5,"policy_version":"policy-1","review_threshold":0.7,"rule_version":"rules-1"}'
    row = row_of(entry)
    row["content_json"] = content
    row["content_digest"] = content_digest(ConfigKind.DECISION_POLICY, content)
    with pytest.raises(TenantConfigRejected):
        decode_row(row)


def test_legacy_and_default_off_expanded_policy_keep_distinct_stable_digests() -> None:
    legacy = canonical_content(ConfigKind.DECISION_POLICY, POLICY)
    assert legacy == dumps(POLICY, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    original = draft()
    assert original.content_json == legacy
    assert original.content_digest == content_digest(ConfigKind.DECISION_POLICY, legacy)
    assert decode_row(row_of(original)) == original

    expanded = DecisionPolicy(
        configuration_version="cfg-1", policy_version="policy-1", rule_version="rules-1"
    ).model_dump(mode="json")
    assert expanded["challenge_threshold"] is None
    assert expanded["challenge_supported_channels"] == []
    assert expanded["challenge_policy_ref"] is None
    copy = draft(payload=expanded)
    assert loads(copy.content_json) == expanded
    assert copy.content_digest != original.content_digest
    assert decode_row(row_of(copy)) == copy
    assert draft().content_json == original.content_json
    assert draft().content_digest == original.content_digest


def test_enabled_challenge_policy_draft_activation_retirement_and_replay_identity() -> None:
    expanded = DecisionPolicy(
        configuration_version="cfg-2", policy_version="policy-2", rule_version="rules-2",
        challenge_threshold=0.6,
        challenge_supported_channels=("atm", "mobile"),
        challenge_policy_ref="policy-lineage:step-up-v1",
    ).model_dump(mode="json")
    old = draft()
    _, v1 = activate(old)
    new = draft(2, payload=expanded)
    assert loads(new.content_json) == expanded
    assert new.content_digest == content_digest(ConfigKind.DECISION_POLICY, new.content_json)
    retired_v1, v2 = plan_activation(
        candidate=new, incumbent=v1, at=NOW + timedelta(hours=2)
    )
    assert retired_v1 is not None
    assert retired_v1.content_json == old.content_json
    assert retired_v1.content_digest == old.content_digest
    assert decode_row(row_of(retired_v1)) == retired_v1
    assert decode_row(row_of(v2)) == v2
    rows = [row_of(retired_v1), row_of(v2)]
    for instant, expected in (
        (NOW + timedelta(hours=1), retired_v1),
        (NOW + timedelta(hours=2), v2),
        (NOW + timedelta(hours=3), v2),
    ):
        resolved = resolve_active(
            rows, tenant_id="tenant-a", config_kind=ConfigKind.DECISION_POLICY,
            at=instant, horizon=NOW + timedelta(hours=3),
        )
        assert resolved.content_digest == expected.content_digest
        assert resolved.version == expected.version
    retired_v2 = plan_retirement(entry=v2, at=NOW + timedelta(hours=4))
    assert decode_row(row_of(retired_v2)) == retired_v2
    with pytest.raises(TenantConfigRejected):
        resolve_active(
            [row_of(retired_v1), row_of(retired_v2)], tenant_id="tenant-a",
            config_kind=ConfigKind.DECISION_POLICY, at=NOW + timedelta(hours=4),
        )


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("challenge_threshold", True),
        ("challenge_threshold", "0.6"),
        ("challenge_threshold", float("nan")),
        ("challenge_threshold", float("inf")),
        ("challenge_threshold", 10**400),
        ("challenge_threshold", 0.5),
        ("challenge_threshold", 0.7),
        ("challenge_supported_channels", None),
        ("challenge_supported_channels", ("mobile",)),
        ("challenge_supported_channels", "mobile"),
        ("challenge_supported_channels", ["mobile", "atm"]),
        ("challenge_supported_channels", ["mobile", "mobile"]),
        ("challenge_supported_channels", [""]),
        ("challenge_supported_channels", [" mobile"]),
        ("challenge_supported_channels", ["mobile bank"]),
        ("challenge_supported_channels", [1]),
        ("challenge_supported_channels", []),
        ("challenge_supported_channels", [f"channel{i:02d}" for i in range(33)]),
        ("challenge_policy_ref", None),
        ("challenge_policy_ref", ""),
        ("challenge_policy_ref", " ref"),
        ("challenge_policy_ref", 7),
    ],
)
def test_enabled_challenge_rejects_invalid_field(field: str, invalid: object) -> None:
    valid = DecisionPolicy(
        configuration_version="cfg-2", policy_version="policy-2", rule_version="rules-2",
        challenge_threshold=0.6, challenge_supported_channels=("mobile",),
        challenge_policy_ref="step-up-v1",
    ).model_dump(mode="json")
    valid[field] = invalid
    with pytest.raises(TenantConfigRejected):
        canonical_content(ConfigKind.DECISION_POLICY, valid)
    with pytest.raises(TenantConfigRejected):
        draft(payload=valid)


@pytest.mark.parametrize(
    "invalid",
    [
        {"challenge_threshold": None, "challenge_supported_channels": ["mobile"],
         "challenge_policy_ref": None},
        {"challenge_threshold": None, "challenge_supported_channels": [],
         "challenge_policy_ref": "step-up-v1"},
        {"challenge_threshold": 0.6, "challenge_supported_channels": [],
         "challenge_policy_ref": "step-up-v1"},
        {"challenge_threshold": 0.6, "challenge_supported_channels": ["mobile"],
         "challenge_policy_ref": None},
    ],
)
def test_expanded_policy_rejects_contradictory_optional_state(
    invalid: dict[str, object],
) -> None:
    full = {**POLICY, **invalid}
    with pytest.raises(TenantConfigRejected):
        canonical_content(ConfigKind.DECISION_POLICY, full)


def test_expanded_policy_rejects_partial_fields_and_unknown_keys() -> None:
    expanded = DecisionPolicy(
        configuration_version="cfg-1", policy_version="policy-1", rule_version="rules-1"
    ).model_dump(mode="json")
    for field in (
        "challenge_threshold", "challenge_supported_channels", "challenge_policy_ref"
    ):
        partial = dict(expanded)
        partial.pop(field)
        with pytest.raises(TenantConfigRejected):
            canonical_content(ConfigKind.DECISION_POLICY, partial)
    with pytest.raises(TenantConfigRejected):
        canonical_content(ConfigKind.DECISION_POLICY, {**expanded, "bank_approved": True})
    # A payload cannot quietly replace a legacy entry with enabled fields,
    # even if its stored digest was recomputed to match the substituted content.
    original = draft()
    bad = row_of(original)
    bad["content_json"] = canonical_content(ConfigKind.DECISION_POLICY, expanded)
    bad["content_digest"] = content_digest(
        ConfigKind.DECISION_POLICY, bad["content_json"]
    )
    assert decode_row(bad) != original
    bad["content_digest"] = original.content_digest
    with pytest.raises(TenantConfigRejected):
        decode_row(bad)
