from __future__ import annotations

import json
from pathlib import Path

from .contracts import Document, SecurityRequest


def load_documents(path: Path) -> list[Document]:
    return [Document.model_validate(item) for item in json.loads(path.read_text())]


def load_scenario(path: Path) -> tuple[SecurityRequest, str, bool]:
    payload = json.loads(path.read_text())
    return SecurityRequest.model_validate(payload["request"]), payload["expected_outcome"], bool(payload.get("vulnerable_simulation", False))
