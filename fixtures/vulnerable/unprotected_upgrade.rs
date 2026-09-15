//! Vulnerable fixture: upgrade/admin functions without authorization.
//! Expected findings: AP-UPG-001 (one per unprotected function).
//!
//! AP-AUTH-001 also reports the two storage-writing functions (ledger-entry
//! writes are auth-sensitive by its contract), and AP-STORAGE-001 reports the
//! missing extend_ttl once at file level. AP-UPG-001 stays scoped to the
//! admin-shaped names below.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct RiskyPool;

#[contractimpl]
impl RiskyPool {
    /// Contract upgrade with no admin check at all.
    pub fn upgrade(env: Env, new_wasm_hash: soroban_sdk::BytesN<32>) {
        env.storage()
            .instance()
            .set(&KEY_WASM, &new_wasm_hash);
    }

    /// Admin reassignment with no require_auth on the stored admin.
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&KEY_ADMIN, &new_admin);
    }

    /// Correctly gated: not flagged by AP-UPG-001.
    pub fn set_fee(env: Env, new_fee: u32) {
        let admin: Address = env.storage().instance().get(&KEY_ADMIN).unwrap();
        env.require_auth(&admin);
        env.storage().instance().set(&KEY_FEE, &new_fee);
    }
}
