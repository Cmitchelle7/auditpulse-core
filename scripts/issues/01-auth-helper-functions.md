---
title: Auth analysis: reason about require_auth inside helper functions (AP-AUTH-001)
labels: enhancement
---
## Context

AP-AUTH-001 (`src/plugins/missingRequireAuth.ts`) reasons only within a single function body: a sensitive operation is reported unless a `require_auth` / `require_auth_for_args` call appears before it in the same function. The rule's doc comment documents the limitation: a require_auth inside a helper — e.g. `Self::authorize(&env, &to);` followed by `client.transfer(...)` — is invisible, so the rule reports that pattern.

## What is missing

- No call graph, not even a shallow intra-file one.
- A helper whose entire body is an auth check cannot currently "prove" the caller is gated.

## Proposed scope

Deliberately small:

- Reuse the `ScannedFunction` extractions the engine already produces once per file (`src/engine.ts`, `src/parser/rust.ts`) — no new parsing.
- Build a shallow intra-file map: helpers whose bodies consist solely of auth checks, matched by simple name reference (`Self::helper(`, `helper(`).
- Gate only when the helper reference precedes the sensitive operation, consistent with the ordering semantics introduced in AP-007.
- Document in the README Limitations section whatever remains out of scope (argument identity not checked, cross-file helpers, trait methods).

## Why it is useful

Helper-based auth wrappers are a common real Soroban pattern; the current documented false positive weakens trust in the rule's signal.

## Acceptance criteria

- [ ] Shallow helper-auth resolution implemented in `src/plugins/missingRequireAuth.ts`
- [ ] Unit tests: helper-gated caller stays silent; helper defined after use works; helper containing non-auth statements does not gate
- [ ] New safe fixture demonstrating the helper-gated pattern
- [ ] Existing behavior preserved (all current fixtures and tests unchanged)
- [ ] README Limitations updated
