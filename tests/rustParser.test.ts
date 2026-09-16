import { describe, it, expect } from "vitest";
import { parseRust, extractFunctions } from "../src/parser/rust";

describe("parseRust", () => {
  it("parses valid Rust without syntax errors", () => {
    const result = parseRust("fn main() { let x = 1; }");

    expect(result).not.toBeNull();
    expect(result!.hasError).toBe(false);
    expect(result!.tree.rootNode.type).toBe("source_file");
  });

  it("flags syntax errors on malformed source", () => {
    const result = parseRust("fn broken( {");

    expect(result).not.toBeNull();
    expect(result!.hasError).toBe(true);
  });

  it("detects a missing closing brace as an error", () => {
    const result = parseRust("fn f() {\n  let x = 1;\n");

    expect(result!.hasError).toBe(true);
  });

  it("treats empty and whitespace-only input as error-free", () => {
    expect(parseRust("")!.hasError).toBe(false);
    expect(parseRust("\n\n  \n")!.hasError).toBe(false);
  });

  it("caches the parser across calls without leaking state", () => {
    const first = parseRust("fn a() {}");
    const second = parseRust("fn b() {}");

    expect(first!.hasError).toBe(false);
    expect(second!.hasError).toBe(false);
  });
});

describe("extractFunctions", () => {
  it("extracts a normal function with correct boundaries", () => {
    const code = "fn add(a: i128, b: i128) -> i128 {\n  a + b\n}\n";
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns).toHaveLength(1);
    expect(fns[0]?.name).toBe("add");
    expect(fns[0]?.line).toBe(1);
    expect(fns[0]?.endLine).toBe(3);
    expect(fns[0]?.body.startsWith("fn add")).toBe(true);
    expect(fns[0]?.bodyInner).toContain("a + b");
  });

  it("handles nested braces inside the body", () => {
    const code = [
      "fn pick(x: bool, a: i128, b: i128) -> i128 {",
      "  if x {",
      "    if a > b { a } else { b }",
      "  } else {",
      "    0",
      "  }",
      "}",
    ].join("\n");
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns).toHaveLength(1);
    expect(fns[0]?.name).toBe("pick");
    expect(fns[0]?.endLine).toBe(7);
    expect(fns[0]?.bodyInner).toContain("else");
  });

  it("does not let comments shift function boundaries", () => {
    const code = [
      "// a leading comment { with a brace",
      "fn f() { /* inline } comment */",
      "  1",
      "}",
      "// trailing } comment",
      "fn g() {}",
    ].join("\n");
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns.map((fn) => fn.name)).toEqual(["f", "g"]);
    expect(fns[0]?.line).toBe(2);
    expect(fns[0]?.endLine).toBe(4);
    expect(fns[1]?.line).toBe(6);
  });

  it("does not let braces in strings end a function body", () => {
    const code = [
      "fn message() -> &'static str {",
      "  \"} { not a boundary \"",
      "}",
      "fn after() {}",
    ].join("\n");
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns.map((fn) => fn.name)).toEqual(["message", "after"]);
    expect(fns[0]?.endLine).toBe(3);
    expect(fns[0]?.bodyInner).toContain("not a boundary");
  });

  it("extracts multiple top-level functions in order", () => {
    const code = "fn a() {}\nfn b() {}\nfn c() {}\n";
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns.map((fn) => fn.name)).toEqual(["a", "b", "c"]);
    expect(fns.map((fn) => fn.line)).toEqual([1, 2, 3]);
  });

  it("extracts functions declared inside impl blocks", () => {
    const code = [
      "impl Vault {",
      "  pub fn deposit(env: Env) {",
      "    env.require_auth(&user);",
      "  }",
      "",
      "  pub fn withdraw(env: Env) {",
      "    client.transfer(&to, &amount);",
      "  }",
      "}",
    ].join("\n");
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns.map((fn) => fn.name)).toEqual(["deposit", "withdraw"]);
    expect(fns[0]?.line).toBe(2);
    expect(fns[1]?.endLine).toBe(8);
    expect(fns.every((fn) => fn.body.startsWith("pub fn"))).toBe(true);
  });

  it("skips bodyless trait signatures and is stable for empty source", () => {
    const code = "trait Pay {\n  fn price(&self) -> i128;\n}\n";
    expect(extractFunctions(parseRust(code)!.tree)).toEqual([]);
    expect(extractFunctions(parseRust("")!.tree)).toEqual([]);
  });

  it("still extracts functions from error-recovered trees", () => {
    const code = "fn ok() {}\nfn broken( {\nfn also_ok() {}\n";
    const result = parseRust(code)!;

    expect(result.hasError).toBe(true);
    const names = extractFunctions(result.tree).map((fn) => fn.name);
    expect(names).toContain("ok");
    expect(names).toContain("also_ok");
  });
});
