from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SecurityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(pattern=r"^req-[a-z0-9-]{3,64}$")
    tenant_id: str = Field(pattern=r"^tenant-[a-z]+$")
    question: str = Field(min_length=1, max_length=500)
    requested_operation: Literal["READ", "PRIVILEGED_SIMULATION"] = "READ"
    document_ids: list[str] = Field(min_length=1, max_length=3)


class Document(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: str = Field(pattern=r"^doc-[a-z0-9-]+$")
    tenant_id: str = Field(pattern=r"^tenant-[a-z]+$")
    classification: Literal["internal", "synthetic-sensitive"]
    authorized_roles: list[Literal["reader", "privileged"]]
    content: str

    def digest(self) -> str:
        return hashlib.sha256(self.content.encode()).hexdigest()


class ModelProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer_kind: Literal["ANSWER", "ABSTAIN", "PROPOSE_ACTION"]
    allowed_source_ids: list[str] = Field(max_length=3)
    proposed_action: Literal["READ_DOCUMENTS", "PRIVILEGED_NOOP"] | None = None
    parameters: dict[str, str] = Field(default_factory=dict)
    rationale_code: Literal["SAFE_ANSWER", "INJECTION_DETECTED", "PRIVILEGED_REQUEST", "MALFORMED_SIMULATION"]


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(pattern=r"^approval-[a-z0-9-]+$")
    tenant_id: str
    request_id: str
    action: Literal["PRIVILEGED_NOOP"]
    parameter_hash: str
    approver_subject: Literal["synthetic-approver-alpha"]
    decision: Literal["APPROVE", "REJECT"]
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval expiry must include a timezone")
        return value


def parameter_hash(parameters: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
