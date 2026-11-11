# AI Application Security & LLM Vulnerability Lab

A local-only defensive reference POC for evaluating trust boundaries, deterministic policy enforcement, retrieval authorization, approval integrity, and AI-security controls using synthetic fixtures and a fake model.

It is a reference project, not a production security gateway or penetration-testing tool.

## Verified local baseline

- Python 3.12.11
- SQLite 3.50.3
- Pydantic 2.14.3
- pytest 8.4.2

## What it demonstrates

- Direct and indirect prompt-injection detection using neutral synthetic markers.
- Tenant-scoped, document-authorized retrieval before untrusted content is read.
- Strict typed model proposals, deterministic policy decisions, and independent no-op tool enforcement.
- Trusted, action-bound, expiring, single-use synthetic approval.
- Synthetic-sensitive-token redaction and privacy-safe audit evidence.
- Request budgets for documents, fake-model calls, proposal revisions, and tool attempts; tamper-evident SQLite audit history, restart verification, and repeatable evaluations.
- A frozen `owasp-llm-top10-2025-mapping-v1` with selected OWASP Agentic Top 10 2026 supplemental categories.

The newer OWASP LLM Top 10 2026 is intentionally not mixed into this V1 mapping.

## Run locally

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
PYTHON_COMMAND=.venv/bin/python ./scripts/validate-local.sh

.venv/bin/ai-security-lab validate-fixtures \
  --documents sample_data/documents/documents.json \
  --scenario sample_data/scenarios/safe-read.json

.venv/bin/ai-security-lab evaluate \
  --documents sample_data/documents/documents.json \
  --scenario sample_data/scenarios/safe-read.json \
  --state /tmp/ai-security-lab.sqlite

.venv/bin/ai-security-lab inspect \
  --request-id req-safe-001 \
  --state /tmp/ai-security-lab.sqlite

.venv/bin/ai-security-lab explain-decision \
  --request-id req-safe-001 \
  --state /tmp/ai-security-lab.sqlite
```

The local CLI uses a source-bound synthetic execution context for `tenant-alpha`; it deliberately has no caller-selection argument. Tests inject only trusted synthetic approval records and no privileged operation has a real external effect.

## Boundaries

There are no real LLMs, browser automation, external networks, credentials, cloud resources, threat feeds, SIEM/SOAR connections, live scanning, or remediation actions. The vulnerable baseline is a labelled simulator that never returns sensitive content or performs an effect.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [OWASP mapping](docs/owasp-mapping.md), [policy contracts](docs/policy-contracts.md), and the [evaluation catalog](docs/evaluation-catalog.md).
