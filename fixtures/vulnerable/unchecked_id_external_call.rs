//! Vulnerable fixture: user-supplied token id passed to a sensitive call
//! with no visible validation. Expected findings: AP-CALL-001 (medium
//! confidence, user-supplied tier) plus AP-AUTH-001 (no require_auth).
//!
//! The argument NAME looks validated; the body proves it is not. Under the
//! pre-AP-008 rule this file scanned clean — that was the false negative.

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct UncheckedBridge;

#[contractimpl]
impl UncheckedBridge {
    /// token_id is never checked: naming alone is not a boundary.
    pub fn sweep(env: Env, token_id: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
