from __future__ import annotations


def require_tenant(tenant_id: str, tenant_ids: tuple[str, ...] | None) -> None:
    """Enforce trusted worker configuration before any tenant data access."""
    if tenant_ids is not None and tenant_id not in tenant_ids:
        raise PermissionError("tenant outside authorized worker scope")
