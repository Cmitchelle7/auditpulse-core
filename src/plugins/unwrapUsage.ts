import type { IRulePlugin, Vulnerability } from "../types";

export class UnwrapUsagePlugin implements IRulePlugin {
  name = "Unwrap Usage";
  description =
    "Detects .unwrap(), .expect(), and panic!() calls in Soroban contracts; prefer returning Result<_, ContractError> instead";

  private removeComments(code: string): string {
    return code.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
  }

  // TODO: Use Soroban AST expression spans to distinguish executable calls from strings and macros.
  scan(code: string): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const lines = this.removeComments(code).split("\n");
    const pattern = /\.unwrap\s*\(|\.expect\s*\(|\bpanic!\s*\(/;

    lines.forEach((line, index) => {
      const text = line.trim();
      if (!text || !pattern.test(text)) {
        return;
      }

      if (/fn\s+unwrap\s*\(/.test(text)) {
        return;
      }

      const kind = /panic!\s*\(/.test(text)
        ? "panic!"
        : /\.expect\s*\(/.test(text)
          ? ".expect()"
          : ".unwrap()";
      findings.push({
        id: "AP-ERROR-001",
        message: `Direct use of ${kind} will panic and abort the contract invocation. Return Result<T, ContractError> and handle the error case instead.`,
        severity: "high",
        confidence: "high",
        location: {
          line: index + 1,
        },
        remediation:
          "Replace the panicking call with error propagation, e.g. .ok_or(ContractError::X)?, so callers receive a Result instead of aborting the invocation.",
      });
    });

    return findings;
  }
}

export default new UnwrapUsagePlugin();
