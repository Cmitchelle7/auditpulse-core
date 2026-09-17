---
title: New rule candidate: unsafe integer casts and truncation on amount-like values
labels: enhancement
---
## Context

AuditPulse has no rule for narrowing casts. In Soroban contracts, patterns like `amount as u64` or `balance as i64` silently truncate `i128` values (Soroban's native amount type), which is a real loss-of-funds class closely related to the overflow class AP-ARITH-001 already covers.

## What is missing

- No plugin in `src/plugins/` looks at `as` casts between amount-like values and narrower integer types.
- Everything the rule needs already exists: the `FunctionRule` capability for per-function analysis and `ScannedFunction` bodies from the shared AST extraction.

## Proposed scope

- New plugin `unsafeCasts.ts` with a rule id following the existing convention (for example `AP-CAST-001`, subject to maintainer approval).
- Flag `<amount-like identifier> as <narrower numeric type>`; the amount-like name list can be shared with AP-ARITH-001.
- Remediation text should suggest checked conversions (`try_into()` with error handling, `u64::try_from(...)`).
- Severity medium, confidence medium, matching AP-ARITH-001's posture of preferring silence over noise.

## Why it is useful

Truncation bugs in Soroban tokens share root causes with overflow bugs; covering both makes the arithmetic family complete.

## Acceptance criteria

- [ ] New plugin registered in `src/registry.ts`
- [ ] Unit tests: flagged casts, safe `try_into` patterns, non-amount casts ignored
- [ ] One vulnerable and one safe fixture
- [ ] README Checks section and severity/confidence table updated
- [ ] `disabled_rules` integration verified for the new rule id
