# Architecture

```mermaid
flowchart LR
    Request[Local request] --> Context[Source-bound synthetic context]
    Context --> Validate[Typed validation and budget]
    Validate --> Retrieval[Tenant/document authorization]
    Retrieval --> Boundary[Untrusted-content boundary]
    Boundary --> Model[Deterministic fake model]
    Model --> Output[Strict output validation]
    Output --> PDP[Deterministic policy decision point]
    PDP -->|ALLOW_READ| Response[Safe response]
    PDP -->|REQUIRE_HUMAN_APPROVAL| Approval[Trusted synthetic approval]
    Approval --> Enforcement[Independent no-op enforcement]
    Enforcement --> Effect[Atomic simulated effect record]
    Response --> Audit[(SQLite audit and evaluation chain)]
    Enforcement --> Audit
```

User questions and retrieved document content are untrusted data. Trusted instructions, policy, approvals, and tool enforcement are code-owned. A model proposal can never grant authorization.

Audit envelopes bind sequence, tenant, request, sanitized metadata, and prior hash. Evaluation records are digest-bound to their audit event. A tampered audit or evaluation record blocks `inspect` and `explain-decision`.
