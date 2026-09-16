import type { FileFinding, ScanReport } from "../scanner";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";

/**
 * Machine-readable JSON output for AuditPulse scans.
 *
 * Reuses the existing Vulnerability model (rule id, severity, confidence,
 * message, location, remediation); FileFinding adds the file path. No new
 * finding model is introduced.
 */

export interface JsonLocation {
  file: string;
  line: number;
  /** Included only when a rule actually provides it. */
  column?: number;
  /** Included only when a rule actually provides it. */
  "function"?: string;
}

export interface JsonFinding {
  ruleId: string;
  severity: string;
  confidence?: string;
  message: string;
  location: JsonLocation;
  /** Included only when the rule provides remediation text. */
  remediation?: string;
}

export interface JsonReport {
  tool: { name: string; version: string };
  summary: {
    filesScanned: number;
    findingCount: number;
    bySeverity: Record<string, number>;
  };
  findings: JsonFinding[];
}

export function toJsonReport(report: ScanReport): JsonReport {
  return {
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    summary: {
      filesScanned: report.filesScanned,
      findingCount: report.findings.length,
      bySeverity: countBySeverity(report.findings),
    },
    findings: report.findings.map(toJsonFinding),
  };
}

export function renderJson(report: ScanReport): string {
  return `${JSON.stringify(toJsonReport(report), null, 2)}\n`;
}

function toJsonFinding(finding: FileFinding): JsonFinding {
  const location: JsonLocation = { file: finding.file, line: finding.location.line };
  if (finding.location.column !== undefined) location.column = finding.location.column;
  if (finding.location.function !== undefined) {
    location["function"] = finding.location["function"];
  }

  const out: JsonFinding = {
    ruleId: finding.id,
    severity: finding.severity,
    message: finding.message,
    location,
  };

  if (finding.confidence !== undefined) out.confidence = finding.confidence;
  if (finding.remediation !== undefined) out.remediation = finding.remediation;

  return out;
}

function countBySeverity(findings: FileFinding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  }
  return counts;
}
