import { createRequire } from "module";

/**
 * Isolated Tree-sitter Rust parser (AP-005).
 *
 * tree-sitter is a native module and can fail to load on machines without a
 * prebuilt binary. The failure is contained here: `parseRust` returns null
 * instead of throwing, so callers can keep using their source-text analysis.
 * Nothing outside this module imports tree-sitter.
 *
 * This is structural parsing only: it yields syntax trees and syntax-error
 * detection, not Rust semantics or types.
 */

type ParserCtor = typeof import("tree-sitter");
type ParserInstance = InstanceType<ParserCtor>;

/** A parsed Rust source tree plus a syntax-error flag. */
export interface RustParseResult {
  tree: import("tree-sitter").Tree;
  /** True when the source has syntax errors; the tree is still usable. */
  hasError: boolean;
}

const nodeRequire = createRequire(import.meta.url);

let cachedParser: ParserInstance | null | undefined;

function getParser(): ParserInstance | null {
  if (cachedParser !== undefined) {
    return cachedParser;
  }
  try {
    const Parser = nodeRequire("tree-sitter") as ParserCtor;
    const Rust =
      nodeRequire("tree-sitter-rust") as Parameters<ParserInstance["setLanguage"]>[0];
    const parser = new Parser();
    parser.setLanguage(Rust);
    cachedParser = parser;
  } catch {
    cachedParser = null;
  }
  return cachedParser;
}

/**
 * Parses Rust source with tree-sitter. Returns null when the parser cannot
 * be loaded. Parsing never throws: tree-sitter recovers from syntax errors
 * and still produces a tree, with `hasError` set.
 */
export function parseRust(code: string): RustParseResult | null {
  const parser = getParser();
  if (parser === null) {
    return null;
  }

  const tree = parser.parse(code);
  return { tree, hasError: tree.rootNode.hasError };
}
