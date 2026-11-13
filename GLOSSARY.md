# DataPulse Domain Glossary

Canonical domain terminology used across documentation, diagnostics, and tests.

## Access Point
A discrete logical block extracted from a source file (such as a Python function, SQL query, R function assignment, or JavaScript/TypeScript method) without executing or importing the code.

## Structural AST Signature
A sequence of syntax node types and depths derived solely from the Abstract Syntax Tree, excluding identifiers, variable names, and literal values. Its SHA-256 digest is the **AST Hash**.

## Diagnostic Record
A validated finding attached to a single Access Point, carrying severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), category, summary, redacted code snippet, and suggested refactoring.

## Local Diagnostic Memory
The machine-local store holding past Diagnostic Records and their embeddings so subsequent scans can surface recurring issues.

## Recurrence
A match between a newly scanned Access Point and a stored Diagnostic Record that shares the same AST Hash or falls within the semantic distance threshold.

## Sanitization
The deterministic redaction of local file paths, IP addresses, emails, and credential literals applied before persistence, opt-in LLM calls, or global telemetry.

## Opt-In Telemetry
An explicit, user-authorized export of anonymized AST Hashes and error categories containing zero source code or personally identifiable information.
