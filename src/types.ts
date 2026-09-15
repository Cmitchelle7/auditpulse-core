export interface Vulnerability {
  line: number;
  message: string;
  severity: "critical" | "high" | "medium" | "low";
  id: string;
}

export interface IRulePlugin {
  name: string;
  description: string;
  scan(code: string): Vulnerability[];
}
