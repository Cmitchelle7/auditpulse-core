//! Edge-case fixture: suspicious text confined to comments and strings.
//!
//! Expected findings: none. Every rule strips comments before scanning, and
//! string contents are blanked, so none of the text below is executable.

use soroban_sdk::{contract, contractimpl};

// AP-AUTH-001 style: client.transfer(&to, &amount); without require_auth
// AP-ARITH-001 style: balance - amount with no checked math
// AP-CALL-001 style: token::Client::new(&env, &token); payout(...)
// AP-UPG-001 style: pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) { ... }
// AP-DEBUG-001 style: log!(env, "debug output");
// AP-ERROR-001 style: env.storage().get(&K).unwrap()

/// Doc comment mentioning `dbg!` and `.unwrap()` and `balance - amount`.
#[contract]
pub struct CommentOnly;

#[contractimpl]
impl CommentOnly {
    /// The suspicious text lives only inside this string literal.
    pub fn note() -> &'static str {
        "client.transfer(&to, &amount) without require_auth; balance - amount; dbg!(); .unwrap()"
    }
}
