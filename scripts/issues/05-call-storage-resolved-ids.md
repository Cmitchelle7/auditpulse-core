---
title: AP-CALL-001: treat storage-resolved token/contract ids as a documented boundary tier
labels: enhancement
---
## Context

AP-CALL-001 (`src/plugins/unvalidatedExternalCall.ts`) accepts a `*_id`-named argument or a `try_*` call as a validation boundary. A common real pattern is not covered explicitly: the token/contract address is loaded from the contract's own storage (`env.storage()...get(&TOKEN_KEY)`) rather than passed in as an argument. Such a function is reported today even though the target is admin-controlled, not user-supplied — the rule's noisiest false-positive class on well-written contracts.

## What is missing

- No recognition of storage-resolved ids as a (weaker) validation boundary.
- The confidence model does not distinguish user-supplied targets from storage-resolved ones.

## Proposed scope

- Detect functions where the client target comes from `env.storage()...get(` and no user-supplied `*_id` argument feeds the call.
- Preferred semantics: keep reporting but lower confidence one tier (high to medium) with a message noting the storage-resolved target; document whichever semantics are chosen in the README Limitations section.
- Keep the rule id and severity unchanged.

## Why it is useful

Reduces noise on admin-controlled token configurations while preserving the signal for genuinely user-supplied targets.

## Acceptance criteria

- [ ] Storage-resolved target detection implemented
- [ ] Chosen confidence semantics applied and tested in both directions
- [ ] New safe fixture using storage-resolved token ids (or updated expectations, documented)
- [ ] Existing fixtures and expectations unchanged
- [ ] README Limitations updated
