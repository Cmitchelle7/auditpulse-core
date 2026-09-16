//! Deliberately vulnerable Soroban-style vault used as the demo scan target.
//!
//! Run: node dist/index.js scan examples/vulnerable_vault.rs   (exits 1)
//! Every function below trips at least one rule; the file exercises most of
//! the registry so a single scan shows a realistic spread of findings.

use soroban_sdk::{
    contract, contractimpl, contracttype, token, Address, Env, Symbol,
};

#[contracttype]
pub struct DataKey {
    pub admin: Symbol,
    pub balances: Symbol,
}

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    /// AP-AUTH-001: token transfer with no require_auth gate.
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &Self::token_id(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// AP-CALL-001: cross-contract payout using an unvalidated token address.
    pub fn payout(env: Env, token: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    /// AP-ARITH-001 (unchecked addition) and AP-STORAGE-001 (persistent
    /// storage write with no extend_ttl anywhere in the file).
    pub fn credit(env: Env, user: Address, amount: i128) {
        let mut balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        balance = balance + amount;
        env.storage().persistent().set(&user, &balance);
    }

    /// AP-UPG-001: admin reassignment without require_auth or admin check.
    pub fn set_admin(env: Env, new_admin: Address) {
        let key = DataKey {
            admin: Symbol::new(&env, "admin"),
            balances: Symbol::new(&env, "balances"),
        };
        env.storage().instance().set(&key, &new_admin);
    }

    /// AP-ERROR-001: .unwrap() panics on unset storage.
    pub fn admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&Self::admin_key(&env))
            .unwrap()
    }

    /// AP-DEBUG-001: debug macro left in production contract code.
    pub fn debug_balance(env: Env, user: Address) -> i128 {
        let balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        println!("balance for user: {}", balance);
        balance
    }

    fn token_id(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&Symbol::new(env, "token"))
            .unwrap_or_else(|| panic!("token not set"))
    }

    fn admin_key(env: &Env) -> Symbol {
        Symbol::new(env, "admin")
    }
}
