from __future__ import annotations

from .contracts import Document, ModelProposal, SecurityRequest
from .retrieval import contains_untrusted_instruction


def propose(request: SecurityRequest, documents: list[Document]) -> ModelProposal:
    if contains_untrusted_instruction(documents, request.question):
        return ModelProposal(answer_kind="ABSTAIN", allowed_source_ids=[], rationale_code="INJECTION_DETECTED")
    if request.requested_operation == "PRIVILEGED_SIMULATION":
        return ModelProposal(answer_kind="PROPOSE_ACTION", allowed_source_ids=[document.document_id for document in documents], proposed_action="PRIVILEGED_NOOP", parameters={"scope": "synthetic"}, rationale_code="PRIVILEGED_REQUEST")
    return ModelProposal(answer_kind="ANSWER", allowed_source_ids=[document.document_id for document in documents], rationale_code="SAFE_ANSWER")
