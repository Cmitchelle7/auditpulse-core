---
title: Expression-level source locations for findings (columns at the offending call)
labels: enhancement
---
## Context

AP-006 gave findings AST-verified `fn`-keyword line/column plus function name (`src/parser/rust.ts` returns `ScannedFunction` with `column` and `bodyColumn`). Whole-file rules point at their own match line with the enclosing function attached. What no rule provides today: the column of the specific expression that triggered the finding (for example the `client.transfer(` call itself, or the exact arithmetic operator).

## What is missing

- Tree-sitter nodes carry exact positions, but the parser module only exposes function-level data.
- Rules match on sanitized text and need a reliable way to map a text match back to original-source coordinates.

## Proposed scope

- Extend `src/parser/rust.ts` with a small helper that, given a function's body and a needle (regex or literal), returns the 1-based line/column of the first unambiguous match in original source coordinates (the body text is a slice of the original, so offsets compose arithmetically).
- Apply it first to AP-CALL-001 and AP-ARITH-001, where the match is a concrete call or expression; only when the mapping is exact — otherwise keep the current location. Never invent precision.
- Keep the finding model unchanged (`SourceLocation.column` already exists); reporting already renders columns end to end.

## Why it is useful

GitHub Code Scanning annotations and the human report would point reviewers at the exact call site instead of the function signature.

## Acceptance criteria

- [ ] Parser helper mapping body-relative matches to source positions
- [ ] AP-CALL-001 and AP-ARITH-001 emit expression columns when the mapping is exact
- [ ] Fallback keeps current locations when the mapping is ambiguous
- [ ] Unit tests with multi-line expressions, strings, and comments
- [ ] Existing reporting tests pass unchanged
