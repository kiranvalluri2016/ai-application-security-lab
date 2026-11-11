from __future__ import annotations

import hashlib

from .contracts import Approval, ModelProposal, SecurityRequest
from .budgets import RequestBudget
from .policy import PolicyDecision, decide
from .storage import SecurityStore


def enforce_privileged_noop(request: SecurityRequest, proposal: ModelProposal, decision: PolicyDecision, approval: Approval, retrieved_ids: list[str], store: SecurityStore, budget: RequestBudget) -> str:
    if approval.tenant_id != request.tenant_id or approval.request_id != request.request_id or approval.action != proposal.proposed_action:
        raise PermissionError("approval is not bound to the current tenant, request, and action")
    expected = decide(request, proposal, retrieved_ids, budget_ok=True)
    if decision != expected or decision.outcome != "REQUIRE_HUMAN_APPROVAL" or proposal.proposed_action != "PRIVILEGED_NOOP" or decision.authorization_hash != approval.parameter_hash:
        raise PermissionError("policy authorization is forged or unsupported")
    if not budget.consume_tool():
        raise PermissionError("tool invocation budget exceeded")
    effect_key = hashlib.sha256(f"{request.tenant_id}:{request.request_id}:{proposal.proposed_action}:{approval.parameter_hash}".encode()).hexdigest()
    store.consume_and_effect(approval, effect_key)
    return effect_key
