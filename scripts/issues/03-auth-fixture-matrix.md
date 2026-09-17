---
title: Broaden the auth fixture matrix (receiver-form auth, multi-op functions, sub-contract calls)
labels: enhancement, good first issue
---
## Context

The AP-AUTH-001 test matrix (`tests/authOrdering.test.ts`, fixtures under `fixtures/`) grew in AP-007 but remains far from exhaustive for realistic Soroban authorization idioms. Fixtures are the executable specification of rule behavior: gaps there become unnoticed behavior changes later.

## Patterns not yet covered by fixtures

- `to.require_auth()` receiver form on non-`env` receivers combined with nested blocks and loops.
- Functions with several sensitive operations of different kinds (transfer + storage write + burn) all gated once.
- Sub-contract client calls (`sub_client.some_method(...)`) alongside token client calls in the same function.
- Auth performed inside `match` arms.
- Sensitive operations contained in closures (`iter().for_each(|x| ...)`).

## Proposed scope

- New files under `fixtures/safe/` and `fixtures/edge-cases/` only.
- Register each in `tests/fixtures.test.ts` (per-file assertions and the well-formedness sweep).

## Why it is useful

Pure specification lock-in: no rule changes needed, and any fixture that exposes a genuine rule bug becomes a separately filed issue with a reproducing case.

## Acceptance criteria

- [ ] At least four new fixture files covering the patterns above
- [ ] Each registered in `tests/fixtures.test.ts` with expected rule outcomes
- [ ] Full `npm test` passes without rule changes
- [ ] If a fixture exposes a rule bug, file it separately instead of changing rules silently
