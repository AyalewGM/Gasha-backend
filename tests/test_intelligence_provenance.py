from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from gasha.intelligence.provenance import (
    IntelligenceScope,
    IntelligenceSource,
    SignalProvenance,
)


def test_tenant_observed_source_has_explicit_version_and_confidence() -> None:
    provenance = SignalProvenance(
        source=IntelligenceSource.TENANT_NETWORK,
        scope=IntelligenceScope.TENANT_OBSERVED,
        observed_at=datetime.now(UTC),
        source_version="network-features-3",
        confidence=0.82,
    )

    assert provenance.scope == IntelligenceScope.TENANT_OBSERVED
    assert provenance.source_version == "network-features-3"
    assert provenance.confidence == 0.82


def test_tenant_source_cannot_claim_authorized_shared_scope() -> None:
    with pytest.raises(ValidationError, match="explicitly authorized source"):
        SignalProvenance(
            source=IntelligenceSource.TENANT_BENEFICIARY,
            scope=IntelligenceScope.AUTHORIZED_SHARED,
            observed_at=datetime.now(UTC),
            source_version="beneficiary-features-2",
        )


def test_authorized_source_cannot_be_labeled_tenant_observed() -> None:
    with pytest.raises(ValidationError, match="authorized_shared scope"):
        SignalProvenance(
            source=IntelligenceSource.AUTHORIZED_CONSORTIUM,
            scope=IntelligenceScope.TENANT_OBSERVED,
            observed_at=datetime.now(UTC),
            source_version="consortium-feed-1",
        )


def test_authorized_rail_intelligence_is_explicitly_scoped() -> None:
    provenance = SignalProvenance(
        source=IntelligenceSource.AUTHORIZED_RAIL,
        scope=IntelligenceScope.AUTHORIZED_SHARED,
        observed_at=datetime.now(UTC),
        source_version="rail-risk-feed-4",
        confidence=0.91,
    )

    assert provenance.scope == IntelligenceScope.AUTHORIZED_SHARED
