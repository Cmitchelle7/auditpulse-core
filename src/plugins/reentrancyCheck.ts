import { IRulePlugin, Vulnerability } from '../types';

/**
 * Plugin to detect reentrancy vulnerabilities
 * Detects external calls made before state variable assignments
 */
export class ReentrancyCheckPlugin implements IRulePlugin {
  name = 'Reentrancy';
  description = 'Detects external calls made before state variable assignments which could enable reentrancy attacks';

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

    // Look for patterns where external calls occur before state changes
    let inFunction = false;
    let functionStartLine = 0;
    const externalCallLines: number[] = [];
    const stateChangeLines: number[] = [];

    lines.forEach((line, index) => {
      const trimmedLine = line.trim();

      // Detect function declaration
      if (/function\s+\w+\s*\(/.test(trimmedLine) && trimmedLine.length > 0) {
        inFunction = true;
        functionStartLine = index;
        externalCallLines.length = 0;
        stateChangeLines.length = 0;
      }

      // Detect end of function
      if (inFunction && trimmedLine === '}' && index > functionStartLine) {
        // Check if external calls occur before state changes
        if (externalCallLines.length > 0 && stateChangeLines.length > 0) {
          const firstCall = Math.min(...externalCallLines);
          const firstStateChange = Math.min(...stateChangeLines);

          if (firstCall < firstStateChange) {
            vulnerabilities.push({
              line: firstCall + 1,
              message: 'Potential reentrancy: external call occurs before state variable assignment',
              severity: 'critical',
            });
          }
        }

        inFunction = false;
      }

      if (inFunction && trimmedLine.length > 0) {
        // Detect external calls (send, call, delegatecall, transfer)
        if (/\.send\s*\(|\.call\s*[\({]|\.delegatecall\s*[\({]|\.transfer\s*\(/.test(trimmedLine)) {
          externalCallLines.push(index);
        }

        // Detect state variable assignments (non-local)
        // Look for patterns like "variable = ", "variable[x] = ", "variable += ", etc.
        if (/\w+\s*[\[\]]?\s*[+\-*/]?=|^(?!.*var\s|.*let\s|.*const\s)\s*\w+\s*[\[\]]?\s*[+\-*/]?=/.test(trimmedLine) && !trimmedLine.startsWith('function')) {
          stateChangeLines.push(index);
        }
      }
    });

    return vulnerabilities;
  }
}

export default new ReentrancyCheckPlugin();
