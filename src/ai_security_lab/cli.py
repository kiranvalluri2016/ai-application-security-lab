from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evaluator import evaluate
from .fixtures import load_documents, load_scenario
from .storage import SecurityStore
from .trust import LOCAL_CONTEXT, authorize_tenant


def main() -> None:
    parser = argparse.ArgumentParser(prog="ai-security-lab")
    parser.add_argument("--version", action="version", version="ai-security-lab 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-fixtures")
    validate.add_argument("--documents", type=Path, required=True)
    validate.add_argument("--scenario", type=Path, required=True)
    evaluate_parser = commands.add_parser("evaluate")
    evaluate_parser.add_argument("--documents", type=Path, required=True)
    evaluate_parser.add_argument("--scenario", type=Path, required=True)
    evaluate_parser.add_argument("--state", type=Path, required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--request-id", required=True)
    inspect.add_argument("--state", type=Path, required=True)
    explain = commands.add_parser("explain-decision")
    explain.add_argument("--request-id", required=True)
    explain.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command in {"validate-fixtures", "evaluate"}:
            documents = load_documents(args.documents)
            request, expected, vulnerable = load_scenario(args.scenario)
            authorize_tenant(request.tenant_id)
            if args.command == "validate-fixtures":
                print(json.dumps({"fixture_valid": True, "tenant_id": request.tenant_id, "document_count": len(documents), "expected_outcome": expected}, sort_keys=True))
                return
            result = evaluate(request, documents, SecurityStore(args.state), LOCAL_CONTEXT, expected, vulnerable_simulation=vulnerable)
            print(json.dumps({"request_id": request.request_id, "expected": expected, "actual": result.outcome, "reason_code": result.reason_code, "audit_valid": SecurityStore(args.state).verify()}, sort_keys=True))
            return
        store = SecurityStore(args.state)
        item = store.inspect(LOCAL_CONTEXT.tenant_id, args.request_id)
        if item is None:
            raise ValueError("evaluation is unavailable in the trusted tenant scope")
        if args.command == "inspect":
            print(json.dumps({"request_id": args.request_id, "evaluation": item, "audit_valid": store.verify()}, sort_keys=True))
        else:
            evidence = item["evidence"]
            print(json.dumps({"request_id": args.request_id, "expected": item["expected"], "actual": item["actual"], "mapping_version": evidence["mapping_version"], "decision": evidence.get("decision"), "audit_valid": store.verify()}, sort_keys=True))
    except (PermissionError, ValueError, OSError) as error:
        print(json.dumps({"error": "request_rejected", "detail": str(error)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
