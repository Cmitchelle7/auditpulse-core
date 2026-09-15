//! Safe fixture: arithmetic that must NOT be flagged by AP-ARITH-001.
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SafeVault;

#[contractimpl]
impl SafeVault {
    /// Subtraction guarded by checked math and error propagation.
    pub fn withdraw(env: Env, user: Address, amount: i128) -> Result<(), Error> {
        env.require_auth(&user);
        let balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        let remaining = balance
            .checked_sub(amount)
            .ok_or(Error::Underflow)?;
        env.storage().persistent().set(&user, &remaining);
        env.storage().persistent().extend_ttl(&user, 100, 200);
        Ok(())
    }

    /// Addition bounded by explicit saturating/clamped math.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        env.require_auth(&user);
        let balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        let capped = balance.saturating_add(amount.min(MAX_STEP));
        env.storage().persistent().set(&user, &capped);
        env.storage().persistent().extend_ttl(&user, 100, 200);
    }

    /// Plain local counter: not amount-like, so not flagged.
    pub fn tick() -> u32 {
        let mut calls: u32 = 0;
        calls = calls + 1;
        calls
    }
}
