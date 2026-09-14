import type { IRulePlugin, Vulnerability } from '../types';

/**
 * Plugin to detect unhandled .send(), .call(), and .delegatecall() methods
 * These methods return boolean values that should be checked for success
 */
export class UncheckedReturnPlugin implements IRulePlugin {
  name = 'Unchecked Return Value';
  description = 'Detects unhandled .send(), .call(), and .delegatecall() methods that should check return values';

  private removeComments(code: string): string {
    // Remove single-line comments
    let result = code.replace(/\/\/.*$/gm, '');
    // Remove multi-line comments
    result = result.replace(/\/\*[\s\S]*?\*\//g, '');
    return result;
  }

  scan(code: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const cleanCode = this.removeComments(code);
    const lines = cleanCode.split('\n');

    // Regex patterns to detect unchecked calls
    const uncheckedPatterns = [
      /\.send\s*\(/,      // .send()
      /\.call\s*[\({]/,   // .call{} or .call(
      /\.delegatecall\s*[\({]/, // .delegatecall{}
    ];

    lines.forEach((line, index) => {
      // Check if line contains send, call, or delegatecall
      if (/\.send\s*\(|\.call\s*[\({]|\.delegatecall\s*[\({]/.test(line)) {
        // Check if the return value is not being checked (no require, assert, or assignment)
        const trimmedLine = line.trim();
        const hasReturnCheck = /^require\s*\(|^assert\s*\(|=\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*(send|call|delegatecall)/.test(trimmedLine);

        if (!hasReturnCheck && trimmedLine.length > 0) {
          vulnerabilities.push({
            line: index + 1,
            message: 'Unchecked return value from send/call/delegatecall. Return value should be checked.',
            severity: 'high',
          });
        }
      }
    });

    return vulnerabilities;
  }
}

export default new UncheckedReturnPlugin();
