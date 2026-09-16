# auditpulse-core

Lightweight static analysis security scanner for Soroban (Stellar) smart contracts written in Rust.

## Checks

* **`missingRequireAuth`** (`AP-AUTH-001`): Flags authorization-sensitive operations (token transfers, balance updates, ledger writes) inside functions that omit `env.require_auth()`.
* **`unwrapUsage`** (`AP-ERROR-001`): Detects explicit `.unwrap()`, `.expect()`, or `panic!()` calls that cause runtime panics; encourages returning `Result<_, ContractError>`.
* **`missingExtendTtl`** (`AP-STORAGE-001`): Identifies persistent or temporary ledger storage access that lacks an accompanying `.extend_ttl()` call, preventing silent data expiry.
* **`uncheckedArithmetic`** (`AP-ARITH-001`): Flags add/subtract/multiply/divide on amount-like values (amounts, balances, supplies, fees) with no checked math (`checked_add`, `saturating_sub`, bounds) that can overflow, underflow, or divide by zero.
* **`unvalidatedExternalCall`** (`AP-CALL-001`): Flags cross-contract/token operations (transfers, burns, mints, admin changes) performed with no `require_auth` and no validated address argument.
* **`unprotectedUpgrade`** (`AP-UPG-001`): Flags upgrade/migration/admin-configuration functions (recognized by name) that contain no `require_auth` or admin check.
* **`debugStatements`** (`AP-DEBUG-001`): Flags debug/development-only macros (`log!`, `dbg!`, `println!`, `print!`, `eprint(ln)!`) left in production contract code.

### Severity and confidence

Severity expresses potential impact; confidence expresses how likely the
detected pattern is actually problematic. The two are independent:

| Rule | Severity | Confidence |
|------|----------|------------|
| `AP-AUTH-001` | critical | high |
| `AP-ERROR-001` | high | high |
| `AP-STORAGE-001` | high | medium |
| `AP-ARITH-001` | medium | medium |
| `AP-CALL-001` | high | low |
| `AP-UPG-001` | critical | medium |
| `AP-DEBUG-001` | low | high |

### Fixtures

`fixtures/` holds small Rust examples used by the regression suite
(`tests/fixtures.test.ts`):

```
fixtures/
  vulnerable/    # each file triggers at least one rule
  safe/          # each file must produce zero findings
  edge-cases/    # comments/strings, odd formatting, nested blocks, coexisting findings
  workspaces/    # multi-module examples (per-file scanning semantics)
```

### Limitations

AuditPulse performs conservative source-text analysis, **not** Rust AST
analysis. Known consequences:

* `AP-ARITH-001` evaluates arithmetic line-by-line; checked math in a helper
  called from another line is not connected, and complex expression chains may
  be missed. It prefers silence over noise.
* `AP-CALL-001` accepts a `*_id` argument name or a `require_auth` call as a
  validation boundary; it does not verify the address is actually checked.
* `AP-UPG-001` recognizes admin/upgrade functions by name, so unusual naming
  can evade it.
* Directory scans evaluate each Rust file independently; there is no
  cross-file dataflow analysis.

## Quickstart

```bash
# Install dependencies
npm install

# Run the test suite
npm test

# Build the CLI
npm run build

# Scan a single contract file
node dist/index.js scan contracts/SampleVault.rs

# Scan a whole directory/workspace
node dist/index.js scan contracts/

```

## CLI

The package ships a small dependency-free CLI:

```text
auditpulse scan <path>        Scan a Rust file or a directory tree
auditpulse report <path>      Scan and print the human-readable report
auditpulse sarif <path>       Scan and print SARIF 2.1.0 output
auditpulse init               Write a starter auditpulse.toml
auditpulse help               Show help
```

Options:

| Option | Meaning |
|--------|---------|
| `--format human\|json\|sarif` | Output format for `scan` (default: human) |
| `--min-severity <level>` | Drop findings below `low`/`medium`/`high`/`critical` |
| `--config <file>` | Explicit config file (default: nearest `auditpulse.toml`, else defaults) |

### Scanning

Give `scan` a single `.rs` file or a directory. Directories are walked
recursively for Rust files, skipping `node_modules`, `dist`, `target`, `.git`
and similar generated/unrelated directories, plus anything listed under
`exclude` in the configuration. Files are visited in deterministic (sorted)
order and each file is scanned independently; there is no cross-file
dataflow. Findings always identify their file and line; column and function
details appear only when the rule can compute them reliably.

### JSON output

```bash
node dist/index.js scan contracts/SampleVault.rs --format json
```

```json
{
  "tool": { "name": "auditpulse", "version": "2.0.0" },
  "summary": {
    "filesScanned": 1,
    "findingCount": 3,
    "bySeverity": { "critical": 1, "high": 2 }
  },
  "findings": [
    {
      "ruleId": "AP-AUTH-001",
      "severity": "critical",
      "message": "Authorization-sensitive operations in function 'withdraw' ...",
      "location": {
        "file": "contracts/SampleVault.rs",
        "line": 23,
        "function": "withdraw"
      },
      "confidence": "high",
      "remediation": "Add env.require_auth(&account) ..."
    }
  ]
}
```

Optional fields (`confidence`, `remediation`, `column`, `function`) are
omitted when the rule does not provide them.

### SARIF output

```bash
node dist/index.js sarif contracts/SampleVault.rs > auditpulse.sarif
```

Emits SARIF 2.1.0 with the tool driver, rule metadata (ids, descriptions,
levels) and one result per finding with file URI and start line, ready for
upload to GitHub Code Scanning.

## Configuration

An optional `auditpulse.toml` is discovered in the scan target's directory or
any parent, or can be given explicitly with `--config`:

```toml
disabled_rules = ["AP-DEBUG-001"]
min_severity = "low"          # low | medium | high | critical
exclude = ["vendor", "generated"]
```

Without a config file, defaults apply: all rules enabled, `min_severity =
"low"`, no extra exclusions. Invalid values are rejected with exit code 2.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the configured threshold |
| `1` | Findings at or above the threshold |
| `2` | Usage, configuration, or input error |

The same semantics apply in `--format json` and `sarif` modes, so CI pipelines
can rely on the exit code regardless of the chosen output format.

## Example Output

```text
============================================================
AuditPulse Security Scanner Report
Target: contracts/SampleVault.rs
Files scanned: 1
============================================================

contracts/SampleVault.rs
  Line 23: [AP-AUTH-001] [CRITICAL] [confidence: HIGH]
    Authorization-sensitive operations in function 'withdraw' are not gated by require_auth. ...
    Function: withdraw
    Remediation: Add env.require_auth(&account) for the account authorized to perform the sensitive operation.
  Line 33: [AP-ERROR-001] [HIGH] [confidence: HIGH]
    Direct use of .unwrap() will panic and abort the contract invocation. ...
    Remediation: Replace the panicking call with error propagation, ...

============================================================
Total findings: 3 (1 critical, 2 high)
============================================================

```

## Development

Built with TypeScript, powered by source-text pattern rules, and tested via Vitest.

```bash
# Type check
npx tsc --noEmit

# Run unit tests
npm test

```