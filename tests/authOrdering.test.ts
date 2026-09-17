import { describe, it, expect } from "vitest";
import MissingRequireAuthPlugin from "../src/plugins/missingRequireAuth";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

/**
 * Structural auth analysis for AP-AUTH-001 (AP-007).
 *
 * Intended behavior, defined before implementation:
 * - The function body from the AST is checked operation by operation.
 * - A sensitive operation is gated when a require_auth (or
 *   require_auth_for_args) call precedes it in the same function body.
 * - A require_auth that appears only AFTER the sensitive operation does not
 *   gate it: the finding survives (ordering matters).
 * - Everything else (which operations count as sensitive, severities,
 *   messages, rule id) stays exactly as before.
 */

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("AP-AUTH-001 authorization ordering", () => {
  it("reports a sensitive operation that precedes require_auth", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  let client = token::Client::new(&env, &token);",
      "  client.transfer(&to, &amount);",
      "  env.require_auth(&to);",
      "}",
    ].join("\n");

    const findings = MissingRequireAuthPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("payout");
  });

  it("stays silent when require_auth precedes the sensitive operation", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  env.require_auth(&to);",
      "  let client = token::Client::new(&env, &token);",
      "  client.transfer(&to, &amount);",
      "}",
    ].join("\n");

    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(0);
  });

  it("require_auth_for_args before the operation still gates it", () => {
    const code = [
      "fn swap(env: Env, args: Vec<Val>) {",
      "  env.require_auth_for_args(&user, &args);",
      "  client.transfer(&to, &amount);",
      "}",
    ].join("\n");

    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(0);
  });

  it("judges each function independently", () => {
    const code = [
      "fn gated_first(env: Env, to: Address, amount: i128) {",
      "  env.require_auth(&to);",
      "  client.transfer(&to, &amount);",
      "}",
      "",
      "fn gated_last(env: Env, to: Address, amount: i128) {",
      "  client.transfer(&to, &amount);",
      "  env.require_auth(&to);",
      "}",
    ].join("\n");

    const findings = MissingRequireAuthPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("gated_last");
  });

  it("keeps fallback behavior on malformed source (no crash, finding survives)", () => {
    const code = [
      "impl Vault {",
      "  fn payout(env: Env, to: Address) {",
      "    client.transfer(&to, &amount);",
      "    env.require_auth(&to);",
      "  }",
    ].join("\n"); // unclosed brace: tree has errors, text fallback applies

    const findings = MissingRequireAuthPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("payout");
  });

  it("fixture: only gated_last is reported in the ordering fixture", () => {
    const code = fs.readFileSync(
      path.join(ROOT, "fixtures", "edge-cases", "auth_ordering.rs"),
      "utf-8",
    );

    const findings = new AuditEngine(createDefaultRegistry()).run(code);
    const auth = findings.filter((f) => f.id === "AP-AUTH-001");

    expect(auth).toHaveLength(1);
    expect(auth[0]?.location.function).toBe("gated_last");
    expect(auth[0]?.location.column).toBeGreaterThan(0);
    // No other rule may fire on this fixture.
    expect(findings).toHaveLength(1);
  });
});
