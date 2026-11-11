from __future__ import annotations

from dataclasses import dataclass

from .budgets import RequestBudget
from .contracts import Approval, Document, SecurityRequest
from .fake_model import propose
from .mappings import OWASP_MAPPING_VERSION
from .policy import PolicyDecision, decide
from .retrieval import redact_sensitive, retrieve
from .storage import SecurityStore
from .tools import enforce_privileged_noop
from .trust import TrustedExecutionContext, authorize_tenant


SCENARIO_VERSION = "security-evaluation-v1"


@dataclass(frozen=True)
class EvaluationResult:
    outcome: str
    reason_code: str
    response: str
    decision: PolicyDecision
    effect_key: str | None


def evaluate(request: SecurityRequest, documents: list[Document], store: SecurityStore, context: TrustedExecutionContext, expected: str, approval: Approval | None = None, vulnerable_simulation: bool = False, budget: RequestBudget | None = None, proposal_revisions: int = 0) -> EvaluationResult:
    authorize_tenant(request.tenant_id, context)
    budget = budget or RequestBudget()
    if vulnerable_simulation:
        result = EvaluationResult("SIMULATED_UNSAFE_OUTCOME", "BASELINE_COMPARISON_ONLY", "No content or effect is released by the vulnerable simulator.", PolicyDecision("DENY", "BASELINE_COMPARISON_ONLY", None), None)
        store.record_evaluation(request.tenant_id, request.request_id, SCENARIO_VERSION, expected, result.outcome, {"mapping_version": OWASP_MAPPING_VERSION, "simulated": True})
        return result
    if not budget.consume_documents(len(request.document_ids)):
        result = EvaluationResult("DENY", "BUDGET_EXCEEDED", "Request denied.", PolicyDecision("DENY", "BUDGET_EXCEEDED", None), None)
        store.record_evaluation(request.tenant_id, request.request_id, SCENARIO_VERSION, expected, result.outcome, {"mapping_version": OWASP_MAPPING_VERSION, "budget": "documents"})
        return result
    try:
        retrieved = retrieve(documents, request.document_ids, context)
    except PermissionError:
        result = EvaluationResult("DENY", "RETRIEVAL_DENIED", "Request denied.", PolicyDecision("DENY", "RETRIEVAL_DENIED", None), None)
        store.record_evaluation(request.tenant_id, request.request_id, SCENARIO_VERSION, expected, result.outcome, {"mapping_version": OWASP_MAPPING_VERSION, "retrieved_count": 0})
        return result
    if not budget.consume_model() or any(not budget.consume_revision() for _ in range(proposal_revisions)):
        result = EvaluationResult("DENY", "BUDGET_EXCEEDED", "Request denied.", PolicyDecision("DENY", "BUDGET_EXCEEDED", None), None)
        store.record_evaluation(request.tenant_id, request.request_id, SCENARIO_VERSION, expected, result.outcome, {"mapping_version": OWASP_MAPPING_VERSION, "budget": "model_or_revision"})
        return result
    proposal = propose(request, retrieved)
    decision = decide(request, proposal, [document.document_id for document in retrieved], budget_ok=True)
    if decision.outcome == "ALLOW_READ":
        response = redact_sensitive("Authorized synthetic response based on permitted documents.")
        result = EvaluationResult("ALLOW_READ", decision.reason_code, response, decision, None)
    elif decision.outcome == "REQUIRE_HUMAN_APPROVAL":
        if approval is None:
            result = EvaluationResult("REQUIRE_HUMAN_APPROVAL", decision.reason_code, "Approval is required before the simulated operation.", decision, None)
        else:
            try:
                effect_key = enforce_privileged_noop(request, proposal, decision, approval, [document.document_id for document in retrieved], store, budget)
                result = EvaluationResult("PRIVILEGED_NOOP_EXECUTED", "APPROVED_SIMULATION", "Approved no-op simulation recorded.", decision, effect_key)
            except PermissionError:
                result = EvaluationResult("DENY", "ENFORCEMENT_DENIED", "Request denied.", decision, None)
    else:
        result = EvaluationResult("DENY", decision.reason_code, "Request denied.", decision, None)
    store.record_evaluation(request.tenant_id, request.request_id, SCENARIO_VERSION, expected, result.outcome, {"mapping_version": OWASP_MAPPING_VERSION, "retrieved_count": len(retrieved), "decision": decision.outcome, "effect_recorded": result.effect_key is not None})
    return result
