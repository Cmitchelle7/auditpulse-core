---
title: Configuration: per-rule severity overrides and inline suppressions
labels: enhancement
---
## Context

`auditpulse.toml` (`src/config.ts`) supports `disabled_rules`, `min_severity`, and `exclude`. Two common workflows are not possible today:

1. Keeping a rule enabled but downgrading its severity for a given project (for example AP-STORAGE-001 as medium in a codebase that handles TTLs in a wrapper).
2. Suppressing a single finding at a specific location without disabling the rule file-wide.

## What is missing

- No `severity_overrides` configuration key.
- No inline suppression comment consumed by the scanner.

## Proposed scope

- Add `severity_overrides` parsing to `src/config.ts`. The parser is hand-rolled for a flat `key = value` subset; extend it deliberately and keep the line-numbered error messages.
- Apply overrides after findings are aggregated and before threshold filtering, so JSON/SARIF/exit-code semantics stay consistent.
- For inline suppressions, support an `auditpulse-ignore <RULE-ID>` comment on the finding's line or the line above; rules check the suppression map before reporting. Exact rule-id matching only — no `all` shorthand unless explicitly decided.
- Document both mechanisms in the README Configuration section.

## Why it is useful

Matches how teams actually adopt scanners: tune severity and acknowledge specific findings without losing the rule's signal elsewhere.

## Acceptance criteria

- [ ] `severity_overrides` parsing and validation (unknown rule ids rejected)
- [ ] Inline suppression format implemented and tested
- [ ] JSON/SARIF output remains valid when overrides apply
- [ ] Config error paths tested (bad severity value, unknown rule id)
- [ ] README Configuration section updated
