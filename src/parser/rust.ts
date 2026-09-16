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

/** A function declaration found in the syntax tree. */
export interface RustAstFunction {
  /** Function name from the declaration's `name` field. */
  name: string;
  /** 1-based line of the first token of the declaration (attributes excluded). */
  line: number;
  /** 1-based line of the closing brace of the body. */
  endLine: number;
  /** Full declaration text, from the first token through the closing brace. */
  body: string;
  /** Text after the opening brace of the body, closing brace included. */
  bodyInner: string;
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

/**
 * Extracts function declarations from a parsed tree: name, start line, end
 * line, and body boundaries. Declared function bodies are not descended into
 * (nested `function_item`s cannot occur inside a body), so each declaration
 * is visited exactly once.
 */
export function extractFunctions(tree: import("tree-sitter").Tree): RustAstFunction[] {
  return collectFunctions(tree.rootNode, []);
}

function collectFunctions(
  node: import("tree-sitter").SyntaxNode,
  out: RustAstFunction[],
): RustAstFunction[] {
  for (const child of node.children) {
    if (child.type === "function_item") {
      const fn = toAstFunction(child);
      if (fn) out.push(fn);
      continue; // declarations cannot nest inside declared bodies
    }
    collectFunctions(child, out);
  }
  return out;
}

function toAstFunction(node: import("tree-sitter").SyntaxNode): RustAstFunction | null {
  const nameNode = node.childForFieldName("name");
  const bodyNode = node.childForFieldName("body");
  if (nameNode === null || bodyNode === null) {
    return null;
  }

  const body = node.text;
  const open = body.indexOf("{");
  return {
    name: nameNode.text,
    line: node.startPosition.row + 1,
    endLine: node.endPosition.row + 1,
    body,
    bodyInner: open >= 0 ? body.slice(open + 1) : "",
  };
}
