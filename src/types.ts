export type Severity = "critical" | "high" | "medium" | "low";

export type Confidence = "high" | "medium" | "low";

export interface SourceLocation {
  line: number;
  column?: number;
  function?: string;
}

export interface Vulnerability {
  id: string;
  message: string;
  severity: Severity;
  confidence?: Confidence;
  location: SourceLocation;
  remediation?: string;
}

/** Stable, machine-readable rule identifier, e.g. "AP-AUTH-001". */
export type RuleId = string;

/**
 * A single security check over Soroban (Rust) source code.
 *
 * Implementations must be reusable: calling `scan` repeatedly with the
 * same input must return the same findings.
 */
export interface Rule {
  /** Stable id stamped on every finding the rule emits. */
  id: RuleId;
  /** Short human-readable name. */
  name: string;
  /** One-line description of what the rule detects. */
  description: string;
  /** Returns the findings for the given source code. */
  scan(code: string): Vulnerability[];
}