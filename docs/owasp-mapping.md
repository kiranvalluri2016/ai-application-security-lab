# OWASP mapping

Primary frozen mapping: `owasp-llm-top10-2025-mapping-v1`.

| Risk | V1 control |
|---|---|
| LLM01:2025 Prompt Injection | Untrusted-content markers and abstention |
| LLM02:2025 Sensitive Information Disclosure | Authorization, redaction, minimized audit |
| LLM05:2025 Improper Output Handling | Strict Pydantic proposal validation |
| LLM06:2025 Excessive Agency | Policy decision and independent enforcement |
| LLM07:2025 System Prompt Leakage | Trusted instructions are never retrievable |
| LLM08:2025 Vector and Embedding Weaknesses | Tenant/document filter before content access |
| LLM10:2025 Unbounded Consumption | Bounded document and proposal budgets |

Supplementary agentic categories use `owasp-agentic-top10-2026-supplement-v1`: ASI01 goal hijack, ASI02 tool misuse, ASI03 identity and privilege abuse, and ASI09 human-agent trust exploitation. The newer LLM Top 10 2026 is documented for later review but is not mixed with this frozen V1 identifier set.
