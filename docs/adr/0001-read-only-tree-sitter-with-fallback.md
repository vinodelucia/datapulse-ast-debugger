# ADR 0001: Read-Only Tree-sitter Parsing with Deterministic Fallback

- **Status:** Accepted
- **Date:** 2026-11-13

## Context
Auditing third-party or untrusted data pipelines requires zero code execution. Dynamic linters and reflection-based tools import modules, which can trigger top-level side effects.

## Decision
Parse target repositories strictly as raw bytes using `Tree-sitter` across Python, SQL, R, and JavaScript/TypeScript, backed by a deterministic per-language fallback (`ast.parse` for Python and structural regex scanners for SQL, R, and JS/TS) when native bindings are unavailable.

## Consequences
- **Positive:** Zero execution risk; resilient to partial syntax errors; uniform `AccessPoint` model across four languages.
- **Negative:** Cross-file type inference and runtime-resolved imports are out of scope by design.
- **Reversibility:** High effort to replace with an LSP/compiler-based backend without breaking zero-execution guarantees.
