from __future__ import annotations

from typing import Protocol

from gasha.ingestion.contracts import FraudEventEnvelope, InboundBankEvent


class BankEventAdapter(Protocol):
    """Boundary between provider-specific payloads and Gasha's canonical model.

    Implementations validate and normalize a provider payload into a
    `FraudEventEnvelope`. They must not make fraud decisions, apply fraud
    thresholds, assign risk scores, or contain tenant-specific decision
    logic — bank-specific field mappings only.
    """

    @property
    def adapter_type(self) -> str: ...

    @property
    def adapter_version(self) -> str: ...

    @property
    def supported_schema_versions(self) -> frozenset[str]: ...

    def adapt(self, event: InboundBankEvent) -> FraudEventEnvelope:
        """Normalize ``event`` or raise ``EventRejection``."""
        ...
