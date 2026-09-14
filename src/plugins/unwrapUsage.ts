import type { IRulePlugin, Vulnerability } from '../types';

/**
 * Soroban rule: flag direct uses of `.unwrap()`, `.expect()`, and `panic!()`.
 *
 * In a Soroban contract a panic aborts the whole invocation and gives callers
 * no structured error; idiomatic Soroban returns `Result<T, ContractError>`
 * so failures surface as typed, handleable errors.
 */
export class UnwrapUsagePlugin implements IRulePlugin {
  name = 'Unwrap Usage';
  description =
    'Detects .unwrap(), .expect(), and panic!() calls in Soroban contracts; prefer returning Result<_, ContractError> instead';

  /** Strip // line and /* block *​/ comments so commented code is not scanned. */
  private removeComments(code: string): string {
    let result = code.replace(/\/\/.*$/gm, '');
    result = result.replace(/\/\*[\s\S]*?\*\//g, '');
    return result;
  }

  scan(code: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const cleanCode = this.removeComments(code);
    const lines = cleanCode.split('\n');

    // Detects direct `.unwrap()`, `.expect(...)`, or `panic!(...)` invocations.
    const pattern = /\.unwrap\s*\(|\.expect\s*\(|\bpanic!\s*\(/;

    lines.forEach((line, index) => {
      const trimmedLine = line.trim();
      if (trimmedLine.length === 0) {
        return;
      }

      if (pattern.test(trimmedLine)) {
        const isDefinition = /fn\s+unwrap\s*\(/.test(trimmedLine);
        if (isDefinition) {
          return;
        }

        const kind = /panic!\s*\(/.test(trimmedLine)
          ? 'panic!'
          : /\.expect\s*\(/.test(trimmedLine)
            ? '.expect()'
            : '.unwrap()';

        vulnerabilities.push({
          line: index + 1,
          message: `Direct use of ${kind} will panic and abort the contract invocation. Return Result<T, ContractError> and handle the error case instead.`,
          severity: 'high',
        });
      }
    });

    return vulnerabilities;
  }
}

export default new UnwrapUsagePlugin();
