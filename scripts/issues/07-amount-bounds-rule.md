---
title: New rule candidate: unvalidated deposit/withdraw amount bounds
labels: enhancement
---
## Context

Amount heuristics exist for arithmetic (AP-ARITH-001) but not for bounds: deposits and withdrawals that accept zero or negative amounts, or unbounded withdrawals without a cap check. Real Soroban vaults commonly require `assert!(amount > 0)` or an equivalent bound check before moving funds.

## What is missing

- No rule notices a deposit/withdraw-shaped function that moves an amount-like value without any bound or positivity assertion. `src/plugins/` has no validation-bounds plugin.

## Proposed scope

- New plugin with a name-based entrypoint heuristic, same posture as AP-UPG-001: only well-known entrypoint shapes are considered (`deposit`, `withdraw`, `mint`, `burn`, `transfer`).
- Report only when the function both moves an amount-like value and has no `assert!` / `require!` / comparison bound involving the amount.
- Severity low, confidence low: explicitly a hygiene signal, tuned to prefer silence over noise like the rest of the rule set.

## Why it is useful

Zero/negative amount bugs are a recurring low-severity finding class in real audits and complement the existing arithmetic rule.

## Acceptance criteria

- [ ] New plugin registered in `src/registry.ts`
- [ ] Unit tests: bounded functions stay silent, unbounded entrypoints flagged, non-entrypoint names ignored
- [ ] One vulnerable and one safe fixture
- [ ] README Checks section updated
- [ ] No findings on any existing safe fixture
