import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { AstAwareRule } from "../engine.js";
import { locateLine, sanitizeKeepLines } from "../utils/rust.js";

/**
 * Development-only patterns that should not remain in production contract
 * code. `console.log!` is the Soroban SDK logging macro; `dbg!` and
 * `print(ln)!` are plain Rust debug macros. Matched per line on sanitized
 * source so string contents and comments never trigger it.
 */
const DEBUG_PATTERN =
  /\bconsole\s*\.\s*log\s*\(|\b(?:log|dbg|println|eprintln|print|eprint)!\s*\(/;

export class DebugStatementsPlugin implements Rule, AstAwareRule {
  id = "AP-DEBUG-001";
  name = "Debug Statements";
  description =
    "Detects debug/development-only output macros (log!, dbg!, println!) left in production contract code";

  scan(code: string): Vulnerability[] {
    return this.scanCode(code, null);
  }

  /**
   * Whole-file scan with the shared AST extraction: each finding keeps its
   * own macro line, with the enclosing function and fn-keyword column
   * attached when the extraction is available.
   */
  scanCode(code: string, functions: ScannedFunction[] | null): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const lines = sanitizeKeepLines(code).split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const match = /\b(log|dbg|println|eprintln|print|eprint)!/.exec(line);
      if (!match) {
        continue;
      }

      findings.push({
        id: "AP-DEBUG-001",
        message: `Debug macro '${match[1]}!' found on line ${i + 1}; development-only output should not remain in production contract code.`,
        severity: "low",
        confidence: "high",
        location: locateLine(functions, i + 1),
        remediation:
          "Remove the debug macro, or gate it behind #[cfg(any(test, feature = \"debug\"))] so it is compiled out of production builds.",
      });
    }

    return findings;
  }
}

export default new DebugStatementsPlugin();
