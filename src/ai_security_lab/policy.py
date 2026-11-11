from __future__ import annotations

from dataclasses import dataclass

from .contracts import ModelProposal, SecurityRequest, parameter_hash


@dataclass(frozen=True)
class PolicyDecision:
    outcome: str
    reason_code: str
    authorization_hash: str | None


def decide(request: SecurityRequest, proposal: ModelProposal, retrieved_ids: list[str], budget_ok: bool) -> PolicyDecision:
    if not budget_ok:
        return PolicyDecision("DENY", "BUDGET_EXCEEDED", None)
    if proposal.answer_kind == "ABSTAIN":
        return PolicyDecision("DENY", "UNTRUSTED_INSTRUCTION", None)
    if any(source_id not in retrieved_ids for source_id in proposal.allowed_source_ids):
        return PolicyDecision("DENY", "UNKNOWN_SOURCE_REFERENCE", None)
    if proposal.answer_kind == "ANSWER" and request.requested_operation == "READ":
        return PolicyDecision("ALLOW_READ", "READ_AUTHORIZED", None)
    if proposal.answer_kind == "PROPOSE_ACTION" and proposal.proposed_action == "PRIVILEGED_NOOP":
        return PolicyDecision("REQUIRE_HUMAN_APPROVAL", "PRIVILEGED_ACTION", parameter_hash(proposal.parameters))
    return PolicyDecision("DENY", "UNSUPPORTED_PROPOSAL", None)
