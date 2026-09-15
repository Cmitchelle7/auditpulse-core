//! Edge-case fixture: several rules fire on the same small contract.
//!
//! Expected findings: AP-AUTH-001 (transfer, no require_auth), AP-ARITH-001
//! (balance - amount), AP-CALL-001 (token transfer via client, no boundary),
//! AP-STORAGE-001 (file-level: persistent storage without extend_ttl), and
//! AP-DEBUG-001 (log!). AP-UPG-001 must stay silent: no admin-shaped
//! function names here.

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct MixedVault;

#[contractimpl]
impl MixedVault {
    pub fn payout(env: Env, token: Address, to: Address, amount: i128) {
        let balance: i128 = env.storage().persistent().get(&to).unwrap_or(0);
        let remaining = balance - amount;
        env.storage().persistent().set(&to, &remaining);

        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);

        log!(env, "payout sent");
    }
}
