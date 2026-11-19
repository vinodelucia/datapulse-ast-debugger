# ADR 0003: SQLGlot Multi-Dialect SQL AST and SARIF 2.1.0 Output

- **Status:** Accepted
- **Date:** 2026-11-19

## Context
Generic `tree-sitter-sql` grammars fail on warehouse-specific SQL dialects (BigQuery, Snowflake, DuckDB, Postgres, Spark SQL, T-SQL), causing false positives and missed semantic anti-patterns. Separately, CI/CD pipelines need a standard interchange format to surface findings directly in GitHub Code Scanning pull-request annotations.

## Decision
1. Adopt `sqlglot` (`tobymao/sqlglot`) as the primary Read-Only SQL AST parser and semantic rule engine, retaining Tree-sitter and structural regex as deterministic fallbacks for oversized inputs (`> 25 KB` per snippet / `> 250 KB` per file).
2. Add native OASIS **SARIF 2.1.0** export (`--format sarif`, `src/sarif_exporter.py`, and dashboard download) with CVSS-aligned `security-severity` scores and `datapulseAstHash/v1` fingerprints.

## Consequences
- **Positive:** Accurate SQL AST analysis across 30+ dialects; zero-config GitHub Code Scanning compatibility; multi-finding support per Access Point.
- **Negative:** Adds one pure-Python dependency (`sqlglot`) to `requirements.txt`.
