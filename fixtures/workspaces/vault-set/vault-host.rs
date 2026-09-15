//! Workspace member: entrypoint contract delegating to vault-core helpers.
//! The transfer logic (and the missing auth) lives in the helper above.

mod vault_core;

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct VaultHost;

#[contractimpl]
impl VaultHost {
    pub fn payout(env: Env, token: Address, to: Address, amount: i128) {
        vault_core::send(&env, token, to, amount);
    }
}
