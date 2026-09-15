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

export interface IRulePlugin {
  name: string;
  description: string;
  scan(code: string): Vulnerability[];
}