//! Edge-case fixture: findings inside nested blocks.
//!
//! Expected findings: AP-ARITH-001 (balance - amount inside the if block).
//! The transfer helper at the bottom is not part of a #[contractimpl] impl
//! but is still scanned; AP-AUTH-001 reports it (transfer without
//! require_auth), and AP-STORAGE-001 fires file-level for the missing
//! extend_ttl.

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct NestedVault;

#[contractimpl]
impl NestedVault {
    pub fn payout(env: Env, to: Address, amount: i128) -> i128 {
        let mut balance: i128 = env.storage().persistent().get(&to).unwrap_or(0);
        if amount > 0 {
            if balance > amount {
                balance = balance - amount;
                env.storage().persistent().set(&to, &balance);
            }
        }
        balance
    }
}

fn transfer_out(env: &Env, to: &Address, amount: i128) {
    let client = token::Client::new(env, &token_id);
    client.transfer(&env.current_contract_address(), to, &amount);
}
