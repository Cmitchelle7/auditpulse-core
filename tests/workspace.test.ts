import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import {
  discoverRustFiles,
  isExcluded,
  comparePosix,
} from "../src/workspace";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "auditpulse-ws-"));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(relPath: string, contents = "// rust"): void {
  const abs = path.join(tmp, relPath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, contents);
}

describe("discoverRustFiles", () => {
  it("finds nested .rs files with relative paths", () => {
    write("src/lib.rs");
    write("src/sub/inner.rs");
    write("top.rs");
    write("notes.txt");

    expect(discoverRustFiles(tmp)).toEqual([
      "src/lib.rs",
      "src/sub/inner.rs",
      "top.rs",
    ]);
  });

  it("skips generated and unrelated directories", () => {
    write("node_modules/pkg/x.rs");
    write("target/debug/x.rs");
    write("dist/x.rs");
    write(".git/x.rs");
    write("keep.rs");
    write("src/keep.rs");

    expect(discoverRustFiles(tmp)).toEqual(["keep.rs", "src/keep.rs"]);
  });

  it("sorts deterministically regardless of creation order", () => {
    write("zeta.rs");
    write("alpha.rs");
    write("mid.rs");

    expect(discoverRustFiles(tmp)).toEqual([
      "alpha.rs",
      "mid.rs",
      "zeta.rs",
    ]);
  });

  it("honors extra exclusions by segment and by path prefix", () => {
    write("generated/out.rs");
    write("src/generated/out.rs");
    write("src/keep.rs");

    expect(discoverRustFiles(tmp, ["generated"])).toEqual(["src/keep.rs"]);
    expect(discoverRustFiles(tmp, ["src/generated"])).toEqual([
      "generated/out.rs",
      "src/keep.rs",
    ]);
  });

  it("returns an empty list for an empty directory", () => {
    expect(discoverRustFiles(tmp)).toEqual([]);
  });
});

describe("isExcluded", () => {
  it("matches segments with backslashes normalized", () => {
    expect(isExcluded("src\\target\\out.rs", ["target"])).toBe(true);
    expect(isExcluded("src/target/out.rs", ["target"])).toBe(true);
    expect(isExcluded("src/attic/out.rs", ["target"])).toBe(false);
  });

  it("matches a path prefix when the exclusion contains a slash", () => {
    expect(isExcluded("src/gen/out.rs", ["src/gen"])).toBe(true);
    expect(isExcluded("src/gen.rs", ["src/gen"])).toBe(false);
  });

  it("ignores empty and ./-style fragments", () => {
    expect(isExcluded("a.rs", [""])).toBe(false);
    expect(isExcluded("a.rs", ["./"])).toBe(false);
  });
});

describe("comparePosix", () => {
  it("orders paths byte-wise, locale independent", () => {
    expect(comparePosix("a.rs", "b.rs")).toBeLessThan(0);
    expect(comparePosix("b.rs", "a.rs")).toBeGreaterThan(0);
    expect(comparePosix("a.rs", "a.rs")).toBe(0);
  });
});
