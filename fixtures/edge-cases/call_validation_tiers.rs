//! Edge-case fixture: AP-CALL-001 validation tiers in isolation.
//!
//! Expected findings, all on storage_token: AP-CALL-001 at low confidence
//! with the storage-resolved message (GitHub issue #13), plus AP-AUTH-001
//! because the rule only reports when no require_auth boundary exists —
//! the storage tier describes WHAT was unresolved in a function that is
//! already flagged, it never grants silence. checked_token (explicit check
//! before the call) and no_tier (no id-named value at all) stay fully
//! silent. AP-ERROR-001 stays quiet (no unwrap/expect/panic) and
//! AP-STORAGE-001 stays quiet (every storage entry is bumped via
//! extend_ttl).

use soroban_sdk::{contract, contractimpl, token, Address, Env, Symbol};

#[contract]
pub struct StorageTierVault;

#[contractimpl]
impl StorageTierVault {
    /// Storage-resolved id with no auth and no visible check: the
    /// storage-resolved tier of AP-CALL-001.
    pub fn storage_token(env: Env, to: Address, amount: i128) {
        let token_id: Address = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "token"))
            .unwrap_or_default();
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
        env.storage().persistent().extend_ttl(&token_id, 100, 200);
    }

    /// Explicitly checked id before the call: not reported by AP-CALL-001,
    /// and require_auth keeps every other rule quiet.
    pub fn checked_token(env: Env, token_id: Address, to: Address, amount: i128) {
        env.require_auth(&to);
        assert!(token_id == &expected_token);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// No id-named value at all: no tier applies, so AP-CALL-001 reports
    /// nothing; require_auth keeps the rest of the registry quiet.
    pub fn no_tier(env: Env, token: Address, to: Address, amount: i128) {
        env.require_auth(&to);
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
