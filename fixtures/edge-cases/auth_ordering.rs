//! Edge-case fixture: authorization ordering within one function.
//!
//! Expected findings: exactly one AP-AUTH-001, on `gated_last` — its token
//! transfer executes before the function's require_auth, so the check does
//! not gate the operation. `gated_first` authorizes before transferring and
//! must stay silent. No storage access: AP-STORAGE-001 stays out of this
//! file; no arithmetic on amount-like values: AP-ARITH-001 stays silent.

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct OrderingVault;

#[contractimpl]
impl OrderingVault {
    /// Correctly ordered: auth before the sensitive transfer.
    pub fn gated_first(env: Env, token: Address, to: Address, amount: i128) {
        env.require_auth(&to);
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// Ordered wrong: the transfer executes before any auth check.
    pub fn gated_last(env: Env, token: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
        env.require_auth(&to);
    }
}
