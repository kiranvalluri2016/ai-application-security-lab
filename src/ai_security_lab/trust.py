from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TrustedExecutionContext:
    subject: str
    tenant_id: str
    role: str


LOCAL_CONTEXT = TrustedExecutionContext("local-analyst-alpha", "tenant-alpha", "reader")
TRUSTED_APPROVER = "synthetic-approver-alpha"


def authorize_tenant(tenant_id: str, context: TrustedExecutionContext = LOCAL_CONTEXT) -> None:
    if context.tenant_id != tenant_id:
        raise PermissionError("trusted execution context is not authorized for the requested tenant")
