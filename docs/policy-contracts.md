# Policy and approval contracts

The model may produce only `ANSWER`, `ABSTAIN`, or `PROPOSE_ACTION`. The policy decision point returns `ALLOW_READ`, `DENY`, or `REQUIRE_HUMAN_APPROVAL`. Tool enforcement recomputes the policy decision and rejects forged decisions, unsupported actions, and parameter mismatches.

Approvals are issued only by the trusted synthetic authority and bind tenant, request, action, canonical parameter hash, approver, decision, and expiry. SQLite consumes the approval and records the no-op privileged effect in one transaction. Approval replay, expiry, tenant mismatch, action mismatch, changed parameters, and duplicate effects fail closed.

Each request owns a deterministic budget: at most three documents, one fake-model invocation, zero proposal revisions, and one tool invocation by default. Document, model, revision, and tool exhaustion independently terminates further simulated processing with a deny outcome.
