---
title: AP-UPG-001: detect upgrade/admin patterns beyond function-name matching
labels: enhancement
---
## Context

AP-UPG-001 (`src/plugins/unprotectedUpgrade.ts`) decides which functions are upgrade/admin entrypoints purely by name (`upgrade`, `set_admin`, `migrate`, ...). The README documents that unusual naming evades the rule.

## What is missing

- Structural signals are unused: a function that writes a `BytesN<32>` wasm hash to instance storage performs an upgrade regardless of its name.
- Admin-change functions exposed through wrapper names are missed.

## Proposed scope

- Add structural secondary signals on top of the existing name heuristic, using the `ScannedFunction` bodies already available: writes of `BytesN<32>` / wasm-hash-shaped values to storage; storage keys whose names follow admin/upgrade conventions.
- Require a structural signal plus the absence of the existing authorization checks, so ordinary state changes are never flagged.
- Keep the name-based path exactly as-is: the new signals only add findings, and the rule id, severity, confidence, and finding model stay unchanged.

## Why it is useful

Upgradeability is the highest-severity class AuditPulse flags; name-only matching is the weakest link in that coverage.

## Acceptance criteria

- [ ] Structural upgrade signals implemented alongside the existing name check
- [ ] Vulnerable fixture with a non-conventional upgrade function name
- [ ] Safe fixture where structural signals exist but authorization is present
- [ ] No new findings on any existing safe fixture
- [ ] README Limitations entry updated
