//! Sample Soroban smart contract used as a scan target for AuditPulse.
//!
//! This contract intentionally contains patterns flagged by the scanner
//! (missing require_auth, .unwrap(), missing extend_ttl) so it can serve as
//! a demo input: `npx ts-node src/index.ts contracts/SampleVault.rs`

use soroban_sdk::{
    contract, contractimpl, contracttype, token, Address, Env, String, Symbol,
};

#[contracttype]
pub struct DataKey {
    pub admin: Symbol,
    pub balances: Symbol,
}

#[contract]
pub struct SampleVault;

#[contractimpl]
impl SampleVault {
    /// Intentionally missing require_auth: flagged by the scanner.
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &Self::token_id(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// Intentionally using unwrap: flagged by the scanner.
    pub fn admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey { admin: Symbol::new(&env, "admin"), balances: Symbol::new(&env, "balances") })
            .unwrap()
    }

    /// Properly protected function: not flagged.
    pub fn deposit(env: Env, from: Address, amount: i128) {
        env.require_auth(&from);
        let client = token::Client::new(&env, &Self::token_id(&env));
        client.transfer(&from, &env.current_contract_address(), &amount);
        let entry = env.storage().persistent();
        entry.extend_ttl(&Self::key(&env), 100, 200);
    }

    fn token_id(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&Symbol::new(env, "token"))
            .unwrap_or_else(|| panic!("token not set"))
    }

    fn key(env: &Env) -> Symbol {
        Symbol::new(env, "balances")
    }
}

fn placeholder(_: String) -> i128 {
    0
}
