from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RequestBudget:
    max_documents: int = 3
    max_model_invocations: int = 1
    max_revision_attempts: int = 0
    max_tool_invocations: int = 1
    documents_used: int = 0
    model_invocations_used: int = 0
    revision_attempts_used: int = 0
    tool_invocations_used: int = 0

    def _consume(self, used_name: str, limit_name: str, amount: int = 1) -> bool:
        used = getattr(self, used_name)
        limit = getattr(self, limit_name)
        if used + amount > limit:
            return False
        setattr(self, used_name, used + amount)
        return True

    def consume_documents(self, amount: int) -> bool:
        return self._consume("documents_used", "max_documents", amount)

    def consume_model(self) -> bool:
        return self._consume("model_invocations_used", "max_model_invocations")

    def consume_revision(self) -> bool:
        return self._consume("revision_attempts_used", "max_revision_attempts")

    def consume_tool(self) -> bool:
        return self._consume("tool_invocations_used", "max_tool_invocations")
