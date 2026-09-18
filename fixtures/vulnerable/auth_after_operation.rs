//! Vulnerable fixture: authorization that is missing or applied too late.
//! Expected findings: AP-AUTH-001 on both functions; AP-CALL-001 only on
//! no_auth (late_auth's require_auth exists, so the call rule stays silent).
//!
//! Isolated to token transfers: no storage access, no amount-like
//! arithmetic, no debug macros.

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct LateGateVault;

#[contractimpl]
impl LateGateVault {
    /// No authorization at all before the transfer.
    pub fn no_auth(env: Env, token: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// The transfer executes before the auth check: gating arrives too late.
    pub fn late_auth(env: Env, token: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
        env.require_auth(&to);
    }
}
