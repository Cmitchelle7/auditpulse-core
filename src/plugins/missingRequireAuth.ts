import type { IRulePlugin, Vulnerability } from '../types';

/**
 * Soroban rule: flag host functions that touch authorization-sensitive
 * operations (token transfers, balance moves, ledger entry writes) without
 * any call to `require_auth` / `require_auth_for_args`.
 *
 * In Soroban, `env.storage()` is not an access-control mechanism: any
 * contract invocation may read and write entries. Only `require_auth` gates
 * an operation behind the signature of the account (or contract) that owns
 * the involved addresses, so missing calls here mean anyone can move funds.
 */
export class MissingRequireAuthPlugin implements IRulePlugin {
  name = 'Missing Require Auth';
  description =
    'Detects authorization-sensitive operations (token transfers, balance updates, ledger entry writes) in functions that never call env.require_auth()';

  /** Strip // line and /* block *​/ comments so commented code is not scanned. */
  private removeComments(code: string): string {
    let result = code.replace(/\/\/.*$/gm, '');
    result = result.replace(/\/\*[\s\S]*?\*\//g, '');
    return result;
  }

  /** Body of a `fn name(...) -> ... {` function, keyed by reported line number (1-based). */
  private extractFunctions(code: string): Array<{ line: number; body: string }> {
    const lines = code.split('\n');
    const functions: Array<{ line: number; body: string }> = [];
    let current: { line: number; body: string[]; depth: number } | null = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (current === null && /\bfn\s+\w+\s*\(/.test(line)) {
        current = { line: i + 1, body: [], depth: 0 };
      }
      if (current !== null) {
        current.body.push(line);
        // Count braces outside of char/string literals (line-level; good enough for linting).
        const opens = (line.match(/\{/g) ?? []).length;
        const closes = (line.match(/\}/g) ?? []).length;
        current.depth += opens - closes;
        if (current.depth <= 0 && current.body.length > 0) {
          functions.push({ line: current.line, body: current.body.join('\n') });
          current = null;
        }
      }
    }

    return functions;
  }

  scan(code: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const cleanCode = this.removeComments(code);
    const functions = this.extractFunctions(cleanCode);

    for (const func of functions) {
      const body = func.body;
      const firstBrace = body.indexOf('{');
      const fnBody = firstBrace >= 0 ? body.slice(firstBrace) : body;

      const isAuthSensitive =
        /client\.|\btransfer\b|\btransfer_from\b|\bburn\b|\bbump_arc\b|\bput_arc\b|\bdel_arc\b|\bget_arc\b|\.set\s*\(/.test(
          fnBody
        );
      if (!isAuthSensitive) {
        continue;
      }

      const hasRequireAuth =
        /require_auth\s*\(/.test(fnBody) || /require_auth_for_args\s*\(/.test(fnBody);

      if (!hasRequireAuth) {
        const fnName = /\bfn\s+(\w+)\s*\(/.exec(func.body)?.[1] ?? '<anonymous>';
        vulnerabilities.push({
          line: func.line,
          message: `Authorization-sensitive operations in function '${fnName}' are not gated by require_auth. Add env.require_auth(&...) so only the intended account can invoke it.`,
          severity: 'critical',
        });
      }
    }

    return vulnerabilities;
  }
}

export default new MissingRequireAuthPlugin();
