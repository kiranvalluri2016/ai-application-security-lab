from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from .contracts import Approval
from .trust import TRUSTED_APPROVER


def _canonical(value: dict[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _hash(previous: str, envelope: dict[str, object]) -> str:
    return hashlib.sha256((previous + _canonical(envelope)).encode()).hexdigest()


def _digest(value: dict[str, object]) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


class SecurityStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as connection:
            connection.execute("create table if not exists audit (seq integer primary key, tenant_id text not null, request_id text not null, payload text not null, prior_hash text not null, record_hash text not null)")
            connection.execute("create table if not exists evaluations (request_id text primary key, tenant_id text not null, scenario_version text not null, expected text not null, actual text not null, evidence text not null)")
            connection.execute("create table if not exists approvals (approval_id text primary key, tenant_id text not null, request_id text not null, action text not null, parameter_hash text not null, expires_at text not null, consumed integer not null default 0)")
            connection.execute("create table if not exists effects (effect_key text primary key, tenant_id text not null, request_id text not null, action text not null)")

    def _append(self, connection: sqlite3.Connection, tenant_id: str, request_id: str, event: str, metadata: dict[str, object]) -> None:
        previous_row = connection.execute("select seq, record_hash from audit order by seq desc limit 1").fetchone()
        seq = previous_row[0] + 1 if previous_row else 1
        previous = previous_row[1] if previous_row else "0" * 64
        payload = {"event": event, "metadata": metadata}
        envelope = {"seq": seq, "tenant_id": tenant_id, "request_id": request_id, "payload": payload}
        connection.execute("insert into audit values (?, ?, ?, ?, ?, ?)", (seq, tenant_id, request_id, _canonical(payload), previous, _hash(previous, envelope)))

    def record_evaluation(self, tenant_id: str, request_id: str, scenario_version: str, expected: str, actual: str, evidence: dict[str, object]) -> None:
        serialized_evidence = _canonical(evidence)
        evaluation = {"tenant_id": tenant_id, "request_id": request_id, "scenario_version": scenario_version, "expected": expected, "actual": actual, "evidence": serialized_evidence}
        digest = hashlib.sha256(_canonical(evaluation).encode()).hexdigest()
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("insert into evaluations values (?, ?, ?, ?, ?, ?)", (request_id, tenant_id, scenario_version, expected, actual, serialized_evidence))
            self._append(connection, tenant_id, request_id, "evaluation_recorded", {"expected": expected, "actual": actual, "evaluation_digest": digest})

    def issue_approval(self, approval: Approval) -> None:
        if approval.approver_subject != TRUSTED_APPROVER or approval.decision != "APPROVE":
            raise PermissionError("approval is not issued by the trusted synthetic authority")
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("insert into approvals values (?, ?, ?, ?, ?, ?, 0)", (approval.approval_id, approval.tenant_id, approval.request_id, approval.action, approval.parameter_hash, approval.expires_at.isoformat()))
            approval_record = {"approval_id": approval.approval_id, "tenant_id": approval.tenant_id, "request_id": approval.request_id, "action": approval.action, "parameter_hash": approval.parameter_hash, "expires_at": approval.expires_at.isoformat()}
            self._append(connection, approval.tenant_id, approval.request_id, "approval_issued", {"approval_id": approval.approval_id, "action": approval.action, "approval_digest": _digest(approval_record)})

    def consume_and_effect(self, approval: Approval, effect_key: str) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("select tenant_id, request_id, action, parameter_hash, expires_at, consumed from approvals where approval_id = ?", (approval.approval_id,)).fetchone()
            if row is None or tuple(row[:4]) != (approval.tenant_id, approval.request_id, approval.action, approval.parameter_hash) or row[5] or approval.decision != "APPROVE" or approval.approver_subject != TRUSTED_APPROVER or approval.expires_at.isoformat() != row[4] or approval.expires_at <= datetime.now(UTC):
                raise PermissionError("approval is invalid, expired, mismatched, or already consumed")
            existing = connection.execute("select effect_key from effects where effect_key = ?", (effect_key,)).fetchone()
            if existing:
                raise PermissionError("privileged effect already exists")
            connection.execute("update approvals set consumed = 1 where approval_id = ?", (approval.approval_id,))
            connection.execute("insert into effects values (?, ?, ?, ?)", (effect_key, approval.tenant_id, approval.request_id, approval.action))
            effect_record = {"effect_key": effect_key, "tenant_id": approval.tenant_id, "request_id": approval.request_id, "action": approval.action}
            self._append(connection, approval.tenant_id, approval.request_id, "privileged_noop_effect", {"effect_key": effect_key, "action": approval.action, "effect_digest": _digest(effect_record)})

    def verify(self) -> bool:
        previous = "0" * 64
        expected_seq = 1
        with sqlite3.connect(self.path) as connection:
            for seq, tenant_id, request_id, payload_text, prior_hash, record_hash in connection.execute("select * from audit order by seq"):
                payload = json.loads(payload_text)
                envelope = {"seq": seq, "tenant_id": tenant_id, "request_id": request_id, "payload": payload}
                if seq != expected_seq or prior_hash != previous or _hash(previous, envelope) != record_hash:
                    return False
                if payload.get("event") == "evaluation_recorded":
                    metadata = payload.get("metadata")
                    row = connection.execute("select tenant_id, scenario_version, expected, actual, evidence from evaluations where request_id = ?", (request_id,)).fetchone()
                    if not isinstance(metadata, dict) or row is None:
                        return False
                    evaluation = {"tenant_id": row[0], "request_id": request_id, "scenario_version": row[1], "expected": row[2], "actual": row[3], "evidence": row[4]}
                    if row[0] != tenant_id or metadata.get("evaluation_digest") != hashlib.sha256(_canonical(evaluation).encode()).hexdigest():
                        return False
                if payload.get("event") == "approval_issued":
                    metadata = payload.get("metadata")
                    row = connection.execute("select tenant_id, request_id, action, parameter_hash, expires_at from approvals where approval_id = ?", (metadata.get("approval_id") if isinstance(metadata, dict) else None,)).fetchone()
                    if not isinstance(metadata, dict) or row is None:
                        return False
                    approval_record = {"approval_id": metadata["approval_id"], "tenant_id": row[0], "request_id": row[1], "action": row[2], "parameter_hash": row[3], "expires_at": row[4]}
                    if row[0] != tenant_id or row[1] != request_id or metadata.get("approval_digest") != _digest(approval_record):
                        return False
                if payload.get("event") == "privileged_noop_effect":
                    metadata = payload.get("metadata")
                    row = connection.execute("select tenant_id, request_id, action from effects where effect_key = ?", (metadata.get("effect_key") if isinstance(metadata, dict) else None,)).fetchone()
                    if not isinstance(metadata, dict) or row is None:
                        return False
                    effect_record = {"effect_key": metadata["effect_key"], "tenant_id": row[0], "request_id": row[1], "action": row[2]}
                    if row[0] != tenant_id or row[1] != request_id or metadata.get("effect_digest") != _digest(effect_record):
                        return False
                previous = record_hash
                expected_seq += 1
        return True

    def inspect(self, tenant_id: str, request_id: str) -> dict[str, object] | None:
        if not self.verify():
            raise ValueError("audit integrity verification failed")
        with sqlite3.connect(self.path) as connection:
            row = connection.execute("select scenario_version, expected, actual, evidence from evaluations where tenant_id = ? and request_id = ?", (tenant_id, request_id)).fetchone()
        return {"scenario_version": row[0], "expected": row[1], "actual": row[2], "evidence": json.loads(row[3])} if row else None
