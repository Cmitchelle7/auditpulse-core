//! Vulnerable fixture: debug macros left in production code.
//! Expected findings: AP-DEBUG-001 (one per debug statement).

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct DebuggyVault;

#[contractimpl]
impl DebuggyVault {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        env.require_auth(&user);
        println!("deposit from user");
        log!(env, "amount: {}", amount);
        env.storage().persistent().set(&user, &amount);
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        let value: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        dbg!(value);
        value
    }
}
