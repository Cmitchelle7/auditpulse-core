//! Safe fixture: the well-written admin pattern from GitHub issue #13 —
//! the token/contract target is resolved from the contract's own storage
//! and the function is admin-gated. Expected findings: none.
//!
//! Under the pre-AP-008 rule this class was the noisiest false positive
//! (reported as "no boundary" whenever require_auth was absent, or
//! silenced only by a lucky *_id mention). With the tiered model, an
//! admin-gated function whose target comes from storage needs no
//! user-supplied id to justify, and AP-CALL-001 stays silent.

use soroban_sdk::{contract, contractimpl, token, Address, Env, Symbol};

#[contract]
pub struct AdminTokenVault;

#[contractimpl]
impl AdminTokenVault {
    /// Storage-resolved, admin-gated payout: require_auth is the boundary,
    /// storage is the trusted source of the token address, and the entry is
    /// kept alive with extend_ttl.
    pub fn configure_token(env: Env, admin: Address, to: Address, amount: i128) {
        admin.require_auth();
        let token_id: Address = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "token"))
            .unwrap_or_default();
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
        env.storage().persistent().extend_ttl(&token_id, 100, 200);
    }
}
