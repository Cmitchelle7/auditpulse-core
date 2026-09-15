//! Workspace member: transfer helper shared by the other members.
//! This helper is the vulnerable one: transfer without require_auth.

use soroban_sdk::{token, Address, Env};

pub fn send(env: &Env, token: Address, to: Address, amount: i128) {
    let client = token::Client::new(env, &token);
    client.transfer(&env.current_contract_address(), &to, &amount);
}

pub fn add(a: i128, b: i128) -> i128 {
    a + b
}
