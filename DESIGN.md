# DataPulse AST Debugger — Design System (`DESIGN.md`)

## 1. Visual Principles
- **Clarity over decoration:** No decorative gradients, glow effects, or background animations.
- **Zero-Execution Trust:** Every surface communicates `100% Read-Only` and local-first state explicitly.
- **Accessible by default:** Severity is always paired with a text label (`[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`) so color is never the sole signal.

## 2. Severity Color Tokens (High-Contrast)
| Severity | Hex | Usage |
| :--- | :--- | :--- |
| `CRITICAL` | `#dc2626` | Injection, destructive SQL without `WHERE`, `eval()` |
| `HIGH` | `#ea580c` | `.iterrows()`, `concat` in loop, ReDoS, hardcoded secrets |
| `MEDIUM` | `#ca8a04` | Sync I/O in event loop, `apply(axis=1)`, unhandled promises |
| `LOW` | `#2563eb` | `inplace=True`, `read_csv` hints, silent `except` |

## 3. Typography & Layout
- **Metrics:** `font-variant-numeric: tabular-nums` for aligned counts and recurrences.
- **Side-by-Side Inspector:** Two equal columns (`Original Code (Read-Only)` vs. `Suggested Refactoring (Not Auto-Applied)`).
- **Empty State:** Single clear next action directing the user to `Map AST & Diagnose`.
