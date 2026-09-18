---
title: Contributor documentation: CONTRIBUTING.md and a rule-authoring guide
labels: documentation, good first issue
---
## Context

The README covers usage well but says little about contributing: there is no `CONTRIBUTING.md` and no description of how a rule is structured, tested, and registered.

## What is missing

- Setup and the three commands that gate every change: `npm test`, `npm run typecheck`, `npm run build`.
- The shape of a rule: the `Rule` interface (`src/types.ts`) and the optional `FunctionRule` / `AstAwareRule` capabilities (`src/engine.ts`), including when to choose each.
- The `ScannedFunction` model: what the AST guarantees and what it does not.
- Fixture conventions (`fixtures/safe`, `fixtures/vulnerable`, `fixtures/edge-cases`) and the well-formedness sweep every finding must pass.
- The repository's commit style (`feat:`, `fix:`, `test:`, `docs:`, ...).

## Proposed scope

- `CONTRIBUTING.md` at the repository root, linked from the README.
- A short "Writing a rule" walkthrough in `docs/` that adds one small example rule end to end: plugin file, registry entry, tests, fixtures.
- No scanner code changes required.

## Why it is useful

Most roadmap issues (new rules, new fixtures) require exactly this knowledge; this document lowers the barrier for every other issue in the roadmap.

## Acceptance criteria

- [ ] `CONTRIBUTING.md` with setup, commands, and PR expectations
- [ ] `docs/writing-a-rule.md` walkthrough
- [ ] README Development section links both
- [ ] Every command in the docs verified to work as written
