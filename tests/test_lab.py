from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_security_lab.contracts import Approval, ModelProposal, SecurityRequest, parameter_hash
from ai_security_lab.budgets import RequestBudget
from ai_security_lab.evaluator import evaluate
from ai_security_lab.fake_model import propose
from ai_security_lab.fixtures import load_documents, load_scenario
from ai_security_lab.policy import PolicyDecision, decide
from ai_security_lab.retrieval import SENSITIVE_MARKER, redact_sensitive
from ai_security_lab.storage import SecurityStore
from ai_security_lab.tools import enforce_privileged_noop
from ai_security_lab.trust import LOCAL_CONTEXT, TRUSTED_APPROVER, authorize_tenant


ROOT = Path(__file__).resolve().parents[1]


def docs():
    return load_documents(ROOT / "sample_data/documents/documents.json")


def scenario(name: str):
    return load_scenario(ROOT / f"sample_data/scenarios/{name}.json")


def test_safe_read_direct_indirect_and_cross_tenant_outcomes(tmp_path: Path) -> None:
    store = SecurityStore(tmp_path / "state.sqlite")
    for name, expected in [("safe-read", "ALLOW_READ"), ("direct-injection", "DENY"), ("indirect-injection", "DENY"), ("cross-tenant", "DENY")]:
        request, scenario_expected, vulnerable = scenario(name)
        result = evaluate(request, docs(), store, LOCAL_CONTEXT, scenario_expected, vulnerable_simulation=vulnerable)
        assert result.outcome == expected
    assert store.verify()


def test_sensitive_marker_is_not_released_by_retrieval_or_response(tmp_path: Path) -> None:
    request = SecurityRequest(request_id="req-sensitive-001", tenant_id="tenant-alpha", question="Summarize permitted content.", document_ids=["doc-alpha-sensitive"])
    state = tmp_path / "state.sqlite"
    result = evaluate(request, docs(), SecurityStore(state), LOCAL_CONTEXT, "ALLOW_READ")
    assert result.outcome == "ALLOW_READ"
    assert SENSITIVE_MARKER not in result.response
    assert SENSITIVE_MARKER not in redact_sensitive(SENSITIVE_MARKER)
    with sqlite3.connect(state) as connection:
        assert SENSITIVE_MARKER not in "".join(str(value) for row in connection.execute("select payload from audit") for value in row)


def test_approval_is_action_bound_single_use_and_atomic_with_effect(tmp_path: Path) -> None:
    request, expected, _ = scenario("privileged")
    store = SecurityStore(tmp_path / "state.sqlite")
    proposal = propose(request, [docs()[0]])
    decision = decide(request, proposal, ["doc-alpha-internal"], budget_ok=True)
    approval = Approval(approval_id="approval-001", tenant_id=request.tenant_id, request_id=request.request_id, action="PRIVILEGED_NOOP", parameter_hash=parameter_hash(proposal.parameters), approver_subject=TRUSTED_APPROVER, decision="APPROVE", expires_at=datetime.now(UTC) + timedelta(minutes=5))
    store.issue_approval(approval)
    result = evaluate(request, docs(), store, LOCAL_CONTEXT, expected, approval=approval)
    assert result.outcome == "PRIVILEGED_NOOP_EXECUTED"
    assert result.effect_key is not None
    with pytest.raises(PermissionError):
        enforce_privileged_noop(request, proposal, decision, approval, ["doc-alpha-internal"], store, RequestBudget())
    restarted = SecurityStore(tmp_path / "state.sqlite")
    assert restarted.verify()
    with sqlite3.connect(tmp_path / "state.sqlite") as connection:
        assert connection.execute("select consumed from approvals where approval_id = ?", (approval.approval_id,)).fetchone() == (1,)
        assert connection.execute("select count(*) from effects").fetchone() == (1,)
        connection.execute("update effects set action = ? where effect_key = ?", ("FORGED", result.effect_key))
    assert not SecurityStore(tmp_path / "state.sqlite").verify()


def test_expired_mismatched_and_forged_authorization_fail_closed(tmp_path: Path) -> None:
    request, _, _ = scenario("privileged")
    store = SecurityStore(tmp_path / "state.sqlite")
    proposal = propose(request, [docs()[0]])
    decision = decide(request, proposal, ["doc-alpha-internal"], budget_ok=True)
    expired = Approval(approval_id="approval-expired", tenant_id=request.tenant_id, request_id=request.request_id, action="PRIVILEGED_NOOP", parameter_hash=parameter_hash(proposal.parameters), approver_subject=TRUSTED_APPROVER, decision="APPROVE", expires_at=datetime.now(UTC) - timedelta(minutes=1))
    store.issue_approval(expired)
    with pytest.raises(PermissionError):
        enforce_privileged_noop(request, proposal, decision, expired, ["doc-alpha-internal"], store, RequestBudget())
    valid = Approval(approval_id="approval-valid", tenant_id=request.tenant_id, request_id=request.request_id, action="PRIVILEGED_NOOP", parameter_hash=parameter_hash(proposal.parameters), approver_subject=TRUSTED_APPROVER, decision="APPROVE", expires_at=datetime.now(UTC) + timedelta(minutes=5))
    store.issue_approval(valid)
    forged = PolicyDecision("REQUIRE_HUMAN_APPROVAL", "FORGED", decision.authorization_hash)
    with pytest.raises(PermissionError):
        enforce_privileged_noop(request, proposal, forged, valid, ["doc-alpha-internal"], store, RequestBudget())
    mismatched = Approval(approval_id="approval-mismatch", tenant_id="tenant-alpha", request_id=request.request_id, action="PRIVILEGED_NOOP", parameter_hash=parameter_hash({"scope": "changed"}), approver_subject=TRUSTED_APPROVER, decision="APPROVE", expires_at=datetime.now(UTC) + timedelta(minutes=5))
    store.issue_approval(mismatched)
    with pytest.raises(PermissionError):
        enforce_privileged_noop(request, proposal, decision, mismatched, ["doc-alpha-internal"], store, RequestBudget())


def test_approval_for_request_a_or_another_tenant_cannot_authorize_request_b(tmp_path: Path) -> None:
    request_a, _, _ = scenario("privileged")
    request_b = request_a.model_copy(update={"request_id": "req-privileged-002"})
    proposal_b = propose(request_b, [docs()[0]])
    decision_b = decide(request_b, proposal_b, ["doc-alpha-internal"], budget_ok=True)
    approval_a = Approval(approval_id="approval-request-a", tenant_id="tenant-alpha", request_id=request_a.request_id, action="PRIVILEGED_NOOP", parameter_hash=parameter_hash(proposal_b.parameters), approver_subject=TRUSTED_APPROVER, decision="APPROVE", expires_at=datetime.now(UTC) + timedelta(minutes=5))
    store = SecurityStore(tmp_path / "state.sqlite")
    store.issue_approval(approval_a)
    with pytest.raises(PermissionError, match="current tenant, request, and action"):
        enforce_privileged_noop(request_b, proposal_b, decision_b, approval_a, ["doc-alpha-internal"], store, RequestBudget())
    cross_tenant = approval_a.model_copy(update={"approval_id": "approval-tenant-beta", "tenant_id": "tenant-beta", "request_id": request_b.request_id})
    store.issue_approval(cross_tenant)
    with pytest.raises(PermissionError, match="current tenant, request, and action"):
        enforce_privileged_noop(request_b, proposal_b, decision_b, cross_tenant, ["doc-alpha-internal"], store, RequestBudget())
    with sqlite3.connect(tmp_path / "state.sqlite") as connection:
        assert connection.execute("select count(*) from effects").fetchone() == (0,)


def test_evaluator_rejects_unauthorized_tenant_before_any_state_mutation(tmp_path: Path) -> None:
    unauthorized = SecurityRequest(request_id="req-tenant-beta-001", tenant_id="tenant-beta", question="Read document.", document_ids=["doc-beta-internal"])
    for vulnerable in (False, True):
        state = tmp_path / f"{vulnerable}.sqlite"
        store = SecurityStore(state)
        with pytest.raises(PermissionError, match="trusted execution context"):
            evaluate(unauthorized, docs(), store, LOCAL_CONTEXT, "DENY", vulnerable_simulation=vulnerable)
        with sqlite3.connect(state) as connection:
            assert connection.execute("select count(*) from evaluations").fetchone() == (0,)
            assert connection.execute("select count(*) from effects").fetchone() == (0,)
            assert connection.execute("select count(*) from audit").fetchone() == (0,)


def test_each_budget_dimension_exhaustion_prevents_further_simulation(tmp_path: Path) -> None:
    safe, _, _ = scenario("safe-read")
    for suffix, budget, revisions in [
        ("docs", RequestBudget(max_documents=0), 0),
        ("model", RequestBudget(max_model_invocations=0), 0),
        ("revision", RequestBudget(max_revision_attempts=0), 1),
    ]:
        result = evaluate(safe.model_copy(update={"request_id": f"req-budget-{suffix}"}), docs(), SecurityStore(tmp_path / f"{suffix}.sqlite"), LOCAL_CONTEXT, "DENY", budget=budget, proposal_revisions=revisions)
        assert result.outcome == "DENY"
        assert result.reason_code == "BUDGET_EXCEEDED"
    request, expected, _ = scenario("privileged")
    proposal = propose(request, [docs()[0]])
    approval = Approval(approval_id="approval-tool-budget", tenant_id=request.tenant_id, request_id=request.request_id, action="PRIVILEGED_NOOP", parameter_hash=parameter_hash(proposal.parameters), approver_subject=TRUSTED_APPROVER, decision="APPROVE", expires_at=datetime.now(UTC) + timedelta(minutes=5))
    store = SecurityStore(tmp_path / "tool.sqlite")
    store.issue_approval(approval)
    result = evaluate(request, docs(), store, LOCAL_CONTEXT, expected, approval=approval, budget=RequestBudget(max_tool_invocations=0))
    assert result.outcome == "DENY"
    assert result.reason_code == "ENFORCEMENT_DENIED"
    with sqlite3.connect(tmp_path / "tool.sqlite") as connection:
        assert connection.execute("select count(*) from effects").fetchone() == (0,)


def test_same_tenant_document_authorization_and_expected_actual_are_persisted(tmp_path: Path) -> None:
    request = SecurityRequest(request_id="req-doc-auth-001", tenant_id="tenant-alpha", question="Read document.", document_ids=["doc-alpha-privileged"])
    state = tmp_path / "state.sqlite"
    result = evaluate(request, docs(), SecurityStore(state), LOCAL_CONTEXT, expected="ALLOW_READ")
    assert result.outcome == "DENY"
    record = SecurityStore(state).inspect("tenant-alpha", request.request_id)
    assert record is not None
    assert record["expected"] == "ALLOW_READ"
    assert record["actual"] == "DENY"


def test_output_schema_budget_tenant_and_audit_tampering_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        ModelProposal.model_validate({"answer_kind": "PROPOSE_ACTION", "allowed_source_ids": [], "proposed_action": "ARBITRARY", "rationale_code": "SAFE_ANSWER"})
    with pytest.raises(ValidationError):
        SecurityRequest(request_id="req-budget-001", tenant_id="tenant-alpha", question="x", document_ids=["doc-alpha-internal"] * 4)
    with pytest.raises(PermissionError):
        authorize_tenant("tenant-beta")
    state = tmp_path / "tamper.sqlite"
    request, expected, vulnerable = scenario("safe-read")
    store = SecurityStore(state)
    evaluate(request, docs(), store, LOCAL_CONTEXT, expected, vulnerable_simulation=vulnerable)
    assert SecurityStore(state).inspect("tenant-alpha", request.request_id) is not None
    with sqlite3.connect(state) as connection:
        connection.execute("update evaluations set actual = ? where request_id = ?", ("FORGED", request.request_id))
    restarted = SecurityStore(state)
    assert not restarted.verify()
    with pytest.raises(ValueError, match="integrity"):
        restarted.inspect("tenant-alpha", request.request_id)


def test_vulnerable_simulation_is_labeled_and_has_no_effect(tmp_path: Path) -> None:
    request, expected, _ = scenario("safe-read")
    result = evaluate(request, docs(), SecurityStore(tmp_path / "state.sqlite"), LOCAL_CONTEXT, expected="SIMULATED_UNSAFE_OUTCOME", vulnerable_simulation=True)
    assert result.outcome == "SIMULATED_UNSAFE_OUTCOME"
    assert result.effect_key is None
