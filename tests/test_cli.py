from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "sample_data/documents/documents.json"


def test_all_cli_contracts_and_no_caller_selector(tmp_path: Path) -> None:
    state = tmp_path / "state.sqlite"
    base = [sys.executable, "-m", "ai_security_lab.cli"]
    validate = subprocess.run(base + ["validate-fixtures", "--documents", str(DOCS), "--scenario", str(ROOT / "sample_data/scenarios/safe-read.json")], check=True, capture_output=True, text=True)
    assert json.loads(validate.stdout)["fixture_valid"] is True
    evaluated = subprocess.run(base + ["evaluate", "--documents", str(DOCS), "--scenario", str(ROOT / "sample_data/scenarios/safe-read.json"), "--state", str(state)], check=True, capture_output=True, text=True)
    assert json.loads(evaluated.stdout)["actual"] == "ALLOW_READ"
    inspected = subprocess.run(base + ["inspect", "--request-id", "req-safe-001", "--state", str(state)], check=True, capture_output=True, text=True)
    assert json.loads(inspected.stdout)["audit_valid"] is True
    explained = subprocess.run(base + ["explain-decision", "--request-id", "req-safe-001", "--state", str(state)], check=True, capture_output=True, text=True)
    assert json.loads(explained.stdout)["mapping_version"] == "owasp-llm-top10-2025-mapping-v1"
    impersonation = subprocess.run(base + ["inspect", "--caller", "synthetic-approver-alpha", "--request-id", "req-safe-001", "--state", str(state)], capture_output=True, text=True)
    assert impersonation.returncode == 2
