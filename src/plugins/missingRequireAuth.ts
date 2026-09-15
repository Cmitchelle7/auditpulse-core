import type { IRulePlugin, Vulnerability } from "../types";

export class MissingRequireAuthPlugin implements IRulePlugin {
  name = "Missing Require Auth";
  description =
    "Detects authorization-sensitive operations (token transfers, balance updates, ledger entry writes) in functions that never call env.require_auth()";

  private removeComments(code: string): string {
    return code.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
  }

  // TODO: Replace brace counting with a Soroban Rust AST walk to isolate nested function spans.
  private extractFunctions(
    code: string,
  ): Array<{ line: number; body: string }> {
    const lines = code.split("\n");
    const fns: Array<{ line: number; body: string }> = [];
    let fn: { line: number; body: string[]; depth: number } | null = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      if (fn === null && /\bfn\s+\w+\s*\(/.test(line)) {
        fn = { line: i + 1, body: [], depth: 0 };
      }
      if (fn === null) {
        continue;
      }

      fn.body.push(line);
      fn.depth +=
        (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
      if (fn.depth <= 0) {
        fns.push({ line: fn.line, body: fn.body.join("\n") });
        fn = null;
      }
    }

    return fns;
  }

  scan(code: string): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const fns = this.extractFunctions(this.removeComments(code));

    for (const fn of fns) {
      const brace = fn.body.indexOf("{");
      const body = brace >= 0 ? fn.body.slice(brace) : fn.body;
      const sensitive =
        /client\.|\btransfer\b|\btransfer_from\b|\bburn\b|\bbump_arc\b|\bput_arc\b|\bdel_arc\b|\bget_arc\b|\.set\s*\(/.test(
          body,
        );
      if (!sensitive) {
        continue;
      }

      const authorized = /require_auth(?:_for_args)?\s*\(/.test(body);
      if (!authorized) {
        const name = /\bfn\s+(\w+)\s*\(/.exec(fn.body)?.[1] ?? "<anonymous>";
        findings.push({
          id: "AP-AUTH-001",
          message: `Authorization-sensitive operations in function '${name}' are not gated by require_auth. Add env.require_auth(&...) so only the intended account can invoke it.`,
          severity: "critical",
          confidence: "high",
          location: {
            line: fn.line,
            function: name,
          },
          remediation:
            "Add env.require_auth(&account) for the account authorized to perform the sensitive operation.",
        });
      }
    }

    return findings;
  }
}

export default new MissingRequireAuthPlugin();
