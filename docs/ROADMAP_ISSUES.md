# Roadmap issues (AP-007)

The repository tracks future development through GitHub issues. This file
summarizes the currently planned improvements and how they were derived;
nothing here claims community requests — these are maintainer-planned
technical items, each backed by the actual repository state.

The authoritative, self-contained payloads (titles, labels, full bodies)
live in `scripts/publish-issues.mjs`. To publish or re-check them:

```bash
# Print what would be created (default, no token needed)
node scripts/publish-issues.mjs

# Create the issues (requires GITHUB_TOKEN with repo scope)
GITHUB_TOKEN=... node scripts/publish-issues.mjs --execute
```

The script skips issues whose titles already exist, so re-running is safe
and duplicates are avoided.

## Planned improvements

Published as GitHub issues #9–#18 on 2026-09-17.

| Issue | Topic | Labels |
|-------|-------|--------|
| [#9](https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/issues/9) | Cross-function authorization analysis for AP-AUTH-001 (helper callees) | enhancement |
| [#10](https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/issues/10) | Expression-level source locations (columns at the offending call, not just the `fn` keyword) | enhancement |
| [#11](https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/issues/11) | Broaden the Soroban auth fixture matrix (receiver-form auth, multi-op functions, sub-contract calls) | enhancement, good first issue |
| [#12](https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/issues/12) | Upgrade/admin detection beyond function-name matching (AP-UPG-001) | enhancement |
| [#13](https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/issues/13) | AP-CALL-001: treat storage-resolved token/contract ids as a documented validation boundary tier | enhancement |
| [#14](https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/issues/14) | New rule candidate: unsafe integer casts/truncation on amount-like values | enhancement |
| [#15](https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/issues/15) | New rule candidate: missing amount/range validation on deposits and withdrawals | enhancement |
| [#16](https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/issues/16) | Contributor documentation: CONTRIBUTING.md and a rule-authoring guide | documentation, good first issue |
| [#17](https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/issues/17) | Configuration: per-rule severity overrides and inline suppressions | enhancement |
| [#18](https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/issues/18) | SARIF metadata enrichment (help URIs, rule properties, fingerprints) | enhancement |

## Existing issues already covering related work

- #2 — detection across complex Soroban macro expansions (open PR targets it)
- #3 — edge-case TTL/storage expiration fixtures (open PRs target it)
- #1 — SARIF output format: the feature already exists (`auditpulse sarif`,
  `src/reporting/sarif.ts`); consider closing it as completed.

No issue here intentionally duplicates the above topics.
