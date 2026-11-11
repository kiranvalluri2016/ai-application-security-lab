from __future__ import annotations

from .contracts import Document
from .trust import TrustedExecutionContext


SENSITIVE_MARKER = "SYNTHETIC_SENSITIVE_TOKEN"
UNTRUSTED_MARKER = "UNTRUSTED_CONTENT_MARKER"


def retrieve(documents: list[Document], requested_ids: list[str], context: TrustedExecutionContext) -> list[Document]:
    allowed = {document.document_id: document for document in documents if document.tenant_id == context.tenant_id and context.role in document.authorized_roles}
    missing = [document_id for document_id in requested_ids if document_id not in allowed]
    if missing:
        raise PermissionError("requested document is unavailable in the trusted tenant scope")
    return [allowed[document_id] for document_id in requested_ids]


def contains_untrusted_instruction(documents: list[Document], question: str) -> bool:
    return UNTRUSTED_MARKER in question or any(UNTRUSTED_MARKER in document.content for document in documents)


def redact_sensitive(text: str) -> str:
    return text.replace(SENSITIVE_MARKER, "[REDACTED_SYNTHETIC_SENSITIVE]")
