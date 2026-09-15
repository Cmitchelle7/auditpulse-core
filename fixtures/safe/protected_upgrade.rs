//! Safe fixture: upgrade/admin functions that must NOT be flagged by
//! AP-UPG-001. Expected findings: none.
//!
//! The stored admin is loaded with unwrap_or_default() rather than .unwrap()
//! so AP-ERROR-001 stays silent as well.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SafePool;

#[contractimpl]
impl SafePool {
    /// Upgrade gated by the stored admin.
    pub fn upgrade(env: Env, new_wasm_hash: soroban_sdk::BytesN<32>) {
        let admin: Address = env.storage().instance().get(&KEY_ADMIN).unwrap_or_default();
        env.require_auth(&admin);
        env.storage().instance().set(&KEY_WASM, &new_wasm_hash);
    }

    /// Admin reassignment gated by the current admin.
    pub fn set_admin(env: Env, new_admin: Address) {
        let admin: Address = env.storage().instance().get(&KEY_ADMIN).unwrap_or_default();
        admin.require_auth();
        env.storage().instance().set(&KEY_ADMIN, &new_admin);
    }

    /// Ordinary state change: not admin-shaped, and properly gated.
    pub fn record(env: Env, value: i128) {
        env.require_auth(&env.current_contract_address());
        env.storage().instance().set(&KEY_LAST, &value);
        env.storage().instance().extend_ttl(&KEY_LAST, 100, 200);
    }
}
