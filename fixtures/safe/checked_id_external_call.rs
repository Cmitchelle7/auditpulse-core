//! Safe fixture: sensitive external call gated only by an explicitly checked
//! id (assert! before the call). Expected findings: none.
//!
//! Deliberately no require_auth: AP-AUTH-001 still fires on the transfer, so
//! this fixture is only scanned with the auth rule disabled (see
//! tests/fixtures.test.ts).

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct CheckedBridge;

#[contractimpl]
impl CheckedBridge {
    /// The token id is explicitly validated before the call: the naming
    /// convention is backed by real evidence, so AP-CALL-001 stays silent.
    pub fn sweep(env: Env, token_id: Address, to: Address, amount: i128) {
        assert!(token_id == &expected_token);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
