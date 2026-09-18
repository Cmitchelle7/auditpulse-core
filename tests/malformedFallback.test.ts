import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { parseRust, extractRustFunctionsAst } from "../src/parser/rust";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { scanTarget } from "../src/scanner";
import { defaultConfig } from "../src/config";
import { scanSource } from "../src/web/scan";

/**
 * Malformed Rust must never crash AuditPulse or silently lose findings:
 * the engine falls back to the source-text function extraction, which is
 * exactly the pre-AST behavior.
 */

function engine(): AuditEngine {
  return new AuditEngine(createDefaultRegistry());
}

/** Vulnerable but textually well-formed: braces balance line by line. */
const VULNERABLE = [
  "fn unsafe_transfer(env: Env, to: Address, amount: i128) {",
  "  let client = token::Client::new(&env, &token);",
  "  client.transfer(&to, &amount);",
  "}",
].join("\n");

/**
 * Same finding, but the file also has a brace-balanced broken section above
 * it (dangling params, missing return type). Realistic for in-progress
 * edits; a dangling-`{`-never-closed variant is separately covered below.
 */
const BROKEN_THEN_VULNERABLE = [
  "fn broken( { }",
  ...VULNERABLE.split("\n"),
].join("\n");

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "auditpulse-malformed-"));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("parser behavior on malformed input", () => {
  it("parseRust reports the error but still returns a usable tree", () => {
    const result = parseRust("fn broken( {");

    expect(result).not.toBeNull();
    expect(result!.hasError).toBe(true);
    expect(result!.tree.rootNode.type).toBe("source_file");
  });

  it("extractRustFunctionsAst returns null instead of trusting a broken tree", () => {
    expect(extractRustFunctionsAst("fn broken( {")).toBeNull();
    expect(extractRustFunctionsAst("fn f() {")).toBeNull();
  });

  it("still returns functions for clean input", () => {
    const fns = extractRustFunctionsAst("fn ok() {}");

    expect(fns?.map((fn) => fn.name)).toEqual(["ok"]);
  });
});

describe("engine fallback on malformed input", () => {
  it("does not throw when the whole file is malformed", () => {
    expect(() => engine().run("fn broken( {")).not.toThrow();
  });

  it("recovers findings that follow a malformed section", () => {
    const findings = engine().run(BROKEN_THEN_VULNERABLE);
    const ids = findings.map((f) => f.id);

    expect(ids).toContain("AP-AUTH-001");
    expect(ids).toContain("AP-CALL-001");
  });

  it("does not invent findings from garbage", () => {
    const findings = engine().run("fn broken( { garbage }");

    expect(findings).toEqual([]);
  });

  it("falls back without finding functions in an unclosed-brace file", () => {
    // Neither the AST tree nor the text fallback can bound a function whose
    // opening brace never closes; the important behavior is no crash and no
    // invented findings.
    const findings = engine().run("fn broken( {\n  garbage\n");

    expect(findings).toEqual([]);
  });

  it("handles unterminated block comments without crashing", () => {
    const unterminated = "/* fn real() { client.transfer(&a, &b); }";
    expect(() => engine().run(unterminated)).not.toThrow();
  });

  it("handles an empty file", () => {
    expect(engine().run("")).toEqual([]);
  });
});

describe("scanTarget fallback on malformed files", () => {
  it("scans a malformed file without crashing and reports findings after the broken section", () => {
    const file = path.join(tmp, "broken.rs");
    fs.writeFileSync(file, BROKEN_THEN_VULNERABLE);

    const report = scanTarget(file, engine(), defaultConfig());
    const ids = report.findings.map((f) => f.id);

    expect(report.filesScanned).toBe(1);
    expect(ids).toContain("AP-AUTH-001");
    expect(ids).toContain("AP-CALL-001");
  });

  it("scans a tree containing a malformed file without losing other files' findings", () => {
    fs.writeFileSync(path.join(tmp, "broken.rs"), "fn broken( {");
    fs.writeFileSync(path.join(tmp, "bad.rs"), VULNERABLE);

    const report = scanTarget(tmp, engine(), defaultConfig());

    // Out-of-cwd targets report absolute display paths; group by basename.
    const idsByFile = new Map<string, string[]>();
    for (const finding of report.findings) {
      const key = path.basename(finding.file);
      idsByFile.set(key, [...(idsByFile.get(key) ?? []), finding.id]);
    }

    expect(report.filesScanned).toBe(2);
    expect(idsByFile.get("broken.rs")).toBeUndefined();
    expect(idsByFile.get("bad.rs")).toContain("AP-AUTH-001");
    expect(idsByFile.get("bad.rs")).toContain("AP-CALL-001");
  });
});

describe("web scan fallback on malformed input", () => {
  it("returns a valid empty report for malformed source", () => {
    const report = scanSource("fn broken( {");

    expect(report.summary.findingCount).toBe(0);
    expect(report.findings).toEqual([]);
  });

  it("keeps findings when malformed code precedes a vulnerable function", () => {
    const report = scanSource(BROKEN_THEN_VULNERABLE);

    expect(report.summary.findingCount).toBeGreaterThan(0);
    expect(report.findings.map((f) => f.ruleId)).toContain("AP-AUTH-001");
  });
});
