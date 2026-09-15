//! Edge-case fixture: unusual formatting must not hide real findings.
//!
//! Expected findings: AP-AUTH-001 (fn send_now: transfer without
//! require_auth), AP-ARITH-001 (amount / divisor), AP-DEBUG-001 (dbg!),
//! AP-STORAGE-001 (file-level). No blank lines or tidy indentation: the
//! scanner must cope with compressed code.

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct WeirdFormat;
#[contract]
pub struct WeirdFormat2;

#[contractimpl]
impl WeirdFormat {
    pub fn send_now(env:Env,to:Address,amount:i128){
let client = token::Client::new(&env, &token);
client.transfer(&to, &amount);}}
#[contractimpl]
impl WeirdFormat2 {
    pub fn ratio(amount:i128,divisor:i128)->i128{amount / divisor}
    pub fn probe(v:i128)->i128{dbg!(v)}
}
