/**
 * Interface for rule plugins that scan code for vulnerabilities
 */
export interface Vulnerability {
  line: number;
  message: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface IRulePlugin {
  name: string;
  description: string;
  scan(code: string): Vulnerability[];
}
