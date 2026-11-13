# ADR 0002: Explicit Opt-In LLM Analysis and Local-First RAG

- **Status:** Accepted
- **Date:** 2026-11-13

## Context
Sending proprietary source code to an external LLM whenever an API key happens to exist in the environment violates local-first expectations and surprises users.

## Decision
Run deterministic static rules offline by default. External calls to `gemini-2.5-pro` require explicit opt-in (`--allow-llm`, `DATAPULSE_ALLOW_LLM=1`, or the dashboard toggle) and pass through `redact_sensitive()` before leaving the machine. Local RAG recurrence detection uses ChromaDB with semantic distance gating (`< 0.5`) or exact structural `ast_hash` matching.

## Consequences
- **Positive:** Safe default for sensitive repositories; predictable offline behavior; fast CI execution.
- **Negative:** Deep semantic reasoning via LLM is inactive unless explicitly enabled by the user.
