//! Edge-case fixture: structure that defeats naive brace counting.
//!
//! Expected findings: AP-AUTH-001 (payout: storage write, no require_auth)
//! and AP-ARITH-001 (balance - amount); AP-STORAGE-001 fires file-level for
//! persistent storage without extend_ttl. Braces inside doc comments and
//! string literals must never shift a function boundary or invent a
//! phantom function.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct StructuralVault;

#[contractimpl]
impl StructuralVault {
    /// Braces in docs: fn fake() { if x { } }
    pub fn describe() -> &'static str {
        "raw braces } { and a nested { example } in a string"
    }

    pub fn payout(env: Env, to: Address, amount: i128) -> i128 {
        let balance: i128 = env.storage().persistent().get(&to).unwrap_or(0);
        if amount > 0 {
            let remaining = balance - amount;
            env.storage().persistent().set(&to, &remaining);
            return remaining;
        }
        balance
    }
}
