import { describe, it, expect } from "vitest";
import MissingRequireAuthPlugin from "../src/plugins/missingRequireAuth";
import UnwrapUsagePlugin from "../src/plugins/unwrapUsage";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";

describe("AuditPulse Scanner Tests (Soroban)", () => {
  describe("MissingRequireAuthPlugin", () => {
    it("should detect token transfer without require_auth", () => {
      const code = `
        fn withdraw(env: Env, to: Address, amount: i128) {
          let client = token::Client::new(&env, &token_id);
          client.transfer(&to, &amount);
        }
      `;

      const vulnerabilities = MissingRequireAuthPlugin.scan(code);
      expect(vulnerabilities.length).toBeGreaterThan(0);
      expect(vulnerabilities[0]?.message).toContain("require_auth");
      expect(vulnerabilities[0]?.severity).toBe("critical");
    });

    it("should detect balance update without require_auth", () => {
      const code = `
        fn debit(env: Env, user: Address, amount: i128) {
          let mut balances = get_balances(env.clone());
          balances.set(&user, &(balances.get(&user).unwrap_or(0) - amount));
        }
      `;

      const vulnerabilities = MissingRequireAuthPlugin.scan(code);
      expect(vulnerabilities.length).toBeGreaterThan(0);
      expect(vulnerabilities[0]?.severity).toBe("critical");
    });

    it("should not flag functions with require_auth", () => {
      const code = `
        fn withdraw(env: Env, to: Address, amount: i128) {
          env.require_auth(&to);
          let client = token::Client::new(&env, &token_id);
          client.transfer(&to, &amount);
        }
      `;

      const vulnerabilities = MissingRequireAuthPlugin.scan(code);
      expect(vulnerabilities.length).toBe(0);
    });

    it("should not flag functions with require_auth_for_args", () => {
      const code = `
        fn swap(env: Env, args: Vec<Val>) {
          env.require_auth_for_args(&user, &args);
          client.transfer(&to, &amount);
        }
      `;

      const vulnerabilities = MissingRequireAuthPlugin.scan(code);
      expect(vulnerabilities.length).toBe(0);
    });

    it("should not flag functions without auth-sensitive operations", () => {
      const code = `
        fn name(env: Env) -> String {
          env.storage().instance().get(&NAME).unwrap_or_default()
        }
      `;

      const vulnerabilities = MissingRequireAuthPlugin.scan(code);
      expect(vulnerabilities.length).toBe(0);
    });

    it("should handle multiple functions independently", () => {
      const code = `
        fn safe_transfer(env: Env, to: Address, amount: i128) {
          env.require_auth(&to);
          client.transfer(&to, &amount);
        }

        fn unsafe_transfer(env: Env, to: Address, amount: i128) {
          client.transfer(&to, &amount);
        }
      `;

      const vulnerabilities = MissingRequireAuthPlugin.scan(code);
      expect(vulnerabilities.length).toBe(1);
      expect(vulnerabilities[0]?.message).toContain("unsafe_transfer");
    });
  });

  describe("UnwrapUsagePlugin", () => {
    it("should detect direct .unwrap()", () => {
      const code = `
        fn balance(env: Env, user: Address) -> i128 {
          env.storage().persistent().get(&user).unwrap()
        }
      `;

      const vulnerabilities = UnwrapUsagePlugin.scan(code);
      expect(vulnerabilities.length).toBeGreaterThan(0);
      expect(vulnerabilities[0]?.message).toContain(".unwrap()");
      expect(vulnerabilities[0]?.severity).toBe("high");
    });

    it("should detect .expect()", () => {
      const code = `
        fn admin(env: Env) -> Address {
          env.storage().instance().get(&ADMIN).expect("admin not set")
        }
      `;

      const vulnerabilities = UnwrapUsagePlugin.scan(code);
      expect(vulnerabilities.length).toBeGreaterThan(0);
      expect(vulnerabilities[0]?.message).toContain(".expect()");
    });

    it("should detect panic!()", () => {
      const code = `
        fn do_thing(env: Env) {
          if bad {
            panic!("bad state");
          }
        }
      `;

      const vulnerabilities = UnwrapUsagePlugin.scan(code);
      expect(vulnerabilities.length).toBeGreaterThan(0);
      expect(vulnerabilities[0]?.message).toContain("panic!");
    });

    it("should not flag ?-based error propagation", () => {
      const code = `
        fn withdraw(env: Env, to: Address, amount: i128) -> Result<(), ContractError> {
          client.transfer(&to, &amount)?;
          Ok(())
        }
      `;

      const vulnerabilities = UnwrapUsagePlugin.scan(code);
      expect(vulnerabilities.length).toBe(0);
    });

    it("should not flag commented code", () => {
      const code = `
        // fn balance(env: Env) -> i128 {
        //   env.storage().persistent().get(&user).unwrap()
        // }
      `;

      const vulnerabilities = UnwrapUsagePlugin.scan(code);
      expect(vulnerabilities.length).toBe(0);
    });
  });

  describe("MissingExtendTtlPlugin", () => {
    it("should detect storage access without extend_ttl", () => {
      const code = `
        fn save(env: Env, key: Symbol, value: i128) {
          env.storage().persistent().set(&key, &value);
        }
      `;

      const vulnerabilities = MissingExtendTtlPlugin.scan(code);
      expect(vulnerabilities.length).toBeGreaterThan(0);
      expect(vulnerabilities[0]?.message).toContain("extend_ttl");
      expect(vulnerabilities[0]?.severity).toBe("high");
    });

    it("should not flag storage access with extend_ttl", () => {
      const code = `
        fn save(env: Env, key: Symbol, value: i128) {
          env.storage().persistent().set(&key, &value);
          env.storage().persistent().extend_ttl(&key, 100, 200);
        }
      `;

      const vulnerabilities = MissingExtendTtlPlugin.scan(code);
      expect(vulnerabilities.length).toBe(0);
    });

    it("should not flag extend_ttl_to_threshold usage", () => {
      const code = `
        fn save(env: Env, key: Symbol, value: i128) {
          env.storage().persistent().set(&key, &value);
          env.storage().persistent().extend_ttl_to_threshold(&key, Threshold::Persistent);
        }
      `;

      const vulnerabilities = MissingExtendTtlPlugin.scan(code);
      expect(vulnerabilities.length).toBe(0);
    });

    it("should not flag contracts that do not touch storage", () => {
      const code = `
        fn add(a: i128, b: i128) -> i128 {
          a + b
        }
      `;

      const vulnerabilities = MissingExtendTtlPlugin.scan(code);
      expect(vulnerabilities.length).toBe(0);
    });

    it("should not flag commented code", () => {
      const code = `
        // env.storage().persistent().set(&key, &value);
      `;

      const vulnerabilities = MissingExtendTtlPlugin.scan(code);
      expect(vulnerabilities.length).toBe(0);
    });
  });

  describe("Integration tests", () => {
    it("should process a complex Soroban contract", () => {
      const code = `
        #[contractimpl]
        impl Vault {
          pub fn deposit(env: Env, user: Address, amount: i128) {
            env.require_auth(&user);
            let client = token::Client::new(&env, &token_id);
            client.transfer(&user, &contract, &amount);
            let mut balances = env.storage().persistent().get(&BALANCES).unwrap_or_default();
          }

          pub fn withdraw(env: Env, user: Address, amount: i128) {
            let client = token::Client::new(&env, &token_id);
            client.transfer(&contract, &user, &amount);
            env.storage().persistent().remove(&user);
          }
        }
      `;

      const authVulns = MissingRequireAuthPlugin.scan(code);
      const unwrapVulns = UnwrapUsagePlugin.scan(code);
      const ttlVulns = MissingExtendTtlPlugin.scan(code);

      expect(authVulns.length).toBe(1);
      expect(unwrapVulns.length).toBe(0);
      expect(ttlVulns.length).toBe(1);
    });

    it("should handle empty code", () => {
      const code = "";

      expect(MissingRequireAuthPlugin.scan(code).length).toBe(0);
      expect(UnwrapUsagePlugin.scan(code).length).toBe(0);
      expect(MissingExtendTtlPlugin.scan(code).length).toBe(0);
    });

    it("should handle a clean contract with no findings", () => {
      const code = `
        fn transfer(env: Env, from: Address, to: Address, amount: i128) {
          env.require_auth(&from);
          let client = token::Client::new(&env, &token_id);
          client.transfer(&to, &amount);
          env.storage().persistent().extend_ttl(&from, 100, 200);
        }
      `;

      expect(MissingRequireAuthPlugin.scan(code).length).toBe(0);
      expect(UnwrapUsagePlugin.scan(code).length).toBe(0);
      expect(MissingExtendTtlPlugin.scan(code).length).toBe(0);
    });
  });
});
