# auditpulse-core

Lightweight static analysis security scanner for Soroban (Stellar) smart contracts written in Rust.

## Checks

* **`missingRequireAuth`**: Flags authorization-sensitive operations (token transfers, balance updates, ledger writes) inside functions that omit `env.require_auth()`.
* **`unwrapUsage`**: Detects explicit `.unwrap()`, `.expect()`, or `panic!()` calls that cause runtime panics; encourages returning `Result<_, ContractError>`.
* **`missingExtendTtl`**: Identifies persistent or temporary ledger storage access that lacks an accompanying `.extend_ttl()` call, preventing silent data expiry.

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