//! Safe fixture: no debug macros. Must NOT be flagged by AP-DEBUG-001.
//! Expected findings: none.

use soroban_sdk::{contract, contractimpl, Address, Env, symbol_short};

#[contract]
pub struct QuietVault;

#[contractimpl]
impl QuietVault {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        env.require_auth(&user);
        env.storage()
            .persistent()
            .set(&symbol_short!("deposit"), &amount);
        env.storage()
            .persistent()
            .extend_ttl(&symbol_short!("deposit"), 100, 200);
    }
}
