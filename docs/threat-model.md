# Threat model

The attacker controls synthetic question text, untrusted document content, document identifiers, model-like output fixtures, and approval-like inputs. The attacker does not control the source-bound local execution context, deterministic policy, trusted approval issuer, SQLite transaction boundary, or tool registry.

The lab tests prompt injection, sensitive disclosure, cross-tenant retrieval, forged output, excessive agency, forged approval, approval replay, budget exhaustion, and persistence tampering. All fixtures are neutral and synthetic; no exploit code, real secrets, or external target is included.
