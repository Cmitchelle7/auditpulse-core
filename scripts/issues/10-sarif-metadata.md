---
title: SARIF metadata enrichment (help URIs, rule properties, fingerprints)
labels: enhancement
---
## Context

`src/reporting/sarif.ts` emits valid SARIF 2.1.0 with rule ids, descriptions, levels, and precise locations (including `startColumn` since AP-006). Several optional SARIF fields that improve the GitHub Code Scanning experience are not emitted.

## What is missing

- `helpUri` per rule (a documentation anchor per rule id).
- Rule `properties` such as tags, and SARIF `precision` derived from the confidence already present in the finding model.
- `partialFingerprints` so re-run deltas stay stable when code shifts lines.
- `automationDetails` to distinguish scan runs.

## Proposed scope

- Extend `SarifOptions` with optional per-rule help URIs, defaulting to README anchors derived from rule ids — no fabricated external URLs.
- Map `confidence` to SARIF `precision` (high/medium/low pass through).
- Add a deterministic `partialFingerprints.primaryLocationLineHash` computed from file, rule id, and message (no new dependencies).
- Add `automationDetails` carrying the tool version.
- Keep every existing output field unchanged so current consumers are unaffected.

## Why it is useful

Better Code Scanning triage: help links, precision hints, and stable fingerprints reduce duplicate-alert churn across runs.

## Acceptance criteria

- [ ] `helpUri`, `precision`, `partialFingerprints`, and `automationDetails` implemented
- [ ] Existing SARIF tests extended, not replaced; schema shape still valid
- [ ] Fingerprint determinism covered by a test
- [ ] Output for consumers ignoring the new fields differs only by the additions
- [ ] README SARIF section updated
