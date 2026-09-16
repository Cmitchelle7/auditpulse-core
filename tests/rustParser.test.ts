import { describe, it, expect } from "vitest";
import { parseRust } from "../src/parser/rust";

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
