import type { Rule, Vulnerability } from "../types";
import type { RustAstFunction } from "../parser/rust";
import type { FunctionRule } from "../engine.js";
import { extractRustFunctions, sanitizeKeepLines } from "../utils/rust.js";

export class MissingRequireAuthPlugin implements Rule, FunctionRule {
  id = "AP-AUTH-001";
  name = "Missing Require Auth";
  description =
    "Detects authorization-sensitive operations (token transfers, balance updates, ledger entry writes) in functions that never call env.require_auth()";

  scan(code: string): Vulnerability[] {
    return extractRustFunctions(sanitizeKeepLines(code)).flatMap((fn) =>
      this.scanFunction(fn),
    );
  }

  /**
   * The engine passes functions extracted from raw source; comments and
   * string contents are blanked here so only executable text is judged.
   */
  scanFunction(fn: RustAstFunction): Vulnerability[] {
    const clean = sanitizeKeepLines(fn.body);
    const brace = clean.indexOf("{");
    const body = brace >= 0 ? clean.slice(brace) : clean;

    const sensitive =
      /client\.|\btransfer\b|\btransfer_from\b|\bburn\b|\bbump_arc\b|\bput_arc\b|\bdel_arc\b|\bget_arc\b|\.set\s*\(/.test(
        body,
      );
    if (!sensitive) {
      return [];
    }

    if (/require_auth(?:_for_args)?\s*\(/.test(body)) {
      return [];
    }

    return [
      {
        id: "AP-AUTH-001",
        message: `Authorization-sensitive operations in function '${fn.name}' are not gated by require_auth. Add env.require_auth(&...) so only the intended account can invoke it.`,
        severity: "critical",
        confidence: "high",
        location: {
          line: fn.line,
          function: fn.name,
        },
        remediation:
          "Add env.require_auth(&account) for the account authorized to perform the sensitive operation.",
      },
    ];
  }
}

export default new MissingRequireAuthPlugin();
