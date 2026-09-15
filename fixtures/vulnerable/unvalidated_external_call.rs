//! Vulnerable fixture: cross-contract token transfer with no validation or
//! auth boundary. Expected findings: AP-CALL-001.

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct RiskyBridge;

#[contractimpl]
impl RiskyBridge {
    /// Transfers out of the contract with no require_auth and no validated
    /// token address argument.
    pub fn payout(env: Env, token: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
