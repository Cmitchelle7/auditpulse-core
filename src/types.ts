/**
 * Core types for the AuditPulse Soroban (Stellar) scanner.
 *
 * Rule plugins scan Soroban Rust smart contract source code for
 * vulnerabilities.
 */

/** A single finding reported by a rule plugin. */
export interface Vulnerability {
  /** 1-based line number in the scanned source. */
  line: number;
  /** Human-readable description of the issue. */
  message: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

/** Interface for rule plugins that scan code for vulnerabilities. */
export interface IRulePlugin {
  name: string;
  description: string;
  /** Scan a string of Soroban Rust contract source for vulnerabilities. */
  scan(code: string): Vulnerability[];
}
