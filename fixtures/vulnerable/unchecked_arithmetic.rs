//! Vulnerable fixture: unchecked arithmetic on amount-like values.
//! Expected findings: AP-ARITH-001 (one per arithmetic line).
//!
//! The auth/upgrade rules stay silent here: no token client calls, no
//! admin-shaped function names. Note that ledger writes via .set( are
//! auth-sensitive for AP-AUTH-001; this fixture deliberately avoids storage
//! writes to keep the arithmetic findings isolated.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct RiskyVault;

#[contractimpl]
impl RiskyVault {
    /// Balance subtraction without checked math.
    pub fn withdraw(env: Env, user: Address, amount: i128) -> i128 {
        let balance: i128 = get_balance(&env, &user);
        balance - amount
    }

    /// Balance addition without checked math.
    pub fn deposit(env: Env, user: Address, amount: i128) -> i128 {
        let balance: i128 = get_balance(&env, &user);
        balance + amount
    }

    /// Reward shares computed with plain multiplication.
    pub fn claim_rewards(env: Env, user: Address) -> i128 {
        let rewards: i128 = get_rewards(&env, &user);
        rewards * 2
    }
}

fn get_balance(env: &Env, user: &Address) -> i128 {
    env.storage().persistent().get(user).unwrap_or(0)
}

fn get_rewards(env: &Env, user: &Address) -> i128 {
    env.storage().persistent().get(user).unwrap_or(0)
}
