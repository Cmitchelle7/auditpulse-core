import type { Rule, Vulnerability } from "../types";
import { extractRustFunctions, sanitizeKeepLines } from "../utils/rust.js";

/** Amount-like identifiers that may be attacker- or contract-relevant. */
const AMOUNT_IDENTIFIER =
  /\b(?:amount|amt|balance|balances|supply|total_supply|value|fee|price|deposit|withdraw|stake|unstake|reward|rewards|share|shares|quota|limit|cap)\w*\b/i;

/**
 * Binary-operator-shaped arithmetic: `operand <op> operand` with an operand
 * (word char, `)` or `]`) before the operator and a word char after any
 * `=`/whitespace. This shape deliberately excludes:
 * - `->` return arrows (`-` followed by `>`, not a word char)
 * - dereferences like `*balance` (`*` with no operand on its left)
 * - unary negation like `= -amount` (`=` is not an operand)
 * Compound assignment (`+=`, `-=`, ...) is covered by the optional `=`.
 */
const BINARY_ARITH = /[\w)\]]\s*[+\-*/]\s*=?\s*[\w]/;

/** Checked/bounded math; a line using these is not reported. */
const GUARDED_MATH =
  /\.(?:checked|overflowing)_(?:add|sub|mul|div)\s*\(|\.saturating_(?:add|sub|mul|div)\s*\(|\.min\s*\(|\.max\s*\(|\.clamp\s*\(/;

/**
 * AP-ARITH-001 — flags binary arithmetic on amount-like identifiers with no
 * checked math on the same line. This is a text heuristic, not an AST walk:
 * it prefers silence over noise, so untouched helpers, counters, and bounded
 * constants produce no findings.
 */
export class UncheckedArithmeticPlugin implements Rule {
  id = "AP-ARITH-001";
  name = "Unchecked Arithmetic";
  description =
    "Detects add/subtract/multiply/divide on amount-like values (amounts, balances, supplies, fees) without checked math, which can overflow, underflow, or divide by zero";

  scan(code: string): Vulnerability[] {
    const findings: Vulnerability[] = [];
    // Sanitized input: comments and string contents blanked but line
    // structure preserved, so brace matching and line numbers stay correct.
    const fns = extractRustFunctions(sanitizeKeepLines(code));

    for (const fn of fns) {
      // The signature is skipped (generic bounds like `T: Add + Sub` are not
      // arithmetic), so realign body lines through the opening brace.
      const open = fn.body.indexOf("{");
      const braceOffset =
        open >= 0 ? fn.body.slice(0, open).split("\n").length - 1 : 0;
      const bodyLines = fn.bodyInner.split("\n");

      for (let i = 0; i < bodyLines.length; i++) {
        const line = bodyLines[i] ?? "";
        if (!AMOUNT_IDENTIFIER.test(line) || !BINARY_ARITH.test(line)) {
          continue;
        }
        if (GUARDED_MATH.test(line)) {
          continue;
        }

        const lineNo = fn.line + braceOffset + i;
        findings.push({
          id: "AP-ARITH-001",
          message: `Function '${fn.name}' performs unchecked arithmetic on an amount-like value: verify it cannot overflow, underflow, or divide by zero.`,
          severity: "medium",
          confidence: "medium",
          location: {
            line: lineNo,
            function: fn.name,
          },
          remediation:
            "Use checked math and handle the error explicitly, e.g. balance.checked_sub(amount).ok_or(Error::Underflow)?; prefer checked_add/checked_sub over + and - for i128/u64 amounts.",
        });
      }
    }

    return findings;
  }
}

export default new UncheckedArithmeticPlugin();
