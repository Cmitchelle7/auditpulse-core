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
* Multi-file workspace analysis is not performed; each file is scanned
  independently.

## Quickstart

```bash
# Install dependencies
npm install

# Run the test suite
npm test

# Scan a target Soroban contract
npx tsx src/index.ts contracts/SampleVault.rs

```

## Example Output

```text
============================================================
AuditPulse Security Scanner Report
File: contracts/SampleVault.rs
============================================================

[MISSING REQUIRE AUTH]
Description: Detects authorization-sensitive operations in functions that never call env.require_auth()
Vulnerabilities found: 1
  Line 23: [CRITICAL] Authorization-sensitive operations in function 'withdraw' are not gated by require_auth.

[UNWRAP USAGE]
Description: Detects .unwrap(), .expect(), and panic!() calls in Soroban contracts
Vulnerabilities found: 2
  Line 33: [HIGH] Direct use of .unwrap() will panic and abort the contract invocation.
  Line 49: [HIGH] Direct use of panic! will panic and abort the contract invocation.

[MISSING EXTEND TTL]
Description: Detects ledger storage access that is never accompanied by an extend_ttl call
Status: ✓ No vulnerabilities found

```

## Development

Built with TypeScript, powered by custom AST/pattern plugins, and tested via Vitest.

```bash
# Type check
npx tsc --noEmit

# Run unit tests
npm test

```