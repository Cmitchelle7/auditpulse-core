import type { FileFinding, ScanReport } from "../scanner";
import { SEVERITY_ORDER } from "../config.js";

/**
 * Terminal-friendly report rendering. Grouped by file, one line per finding,
 * with a summary at the end. Findings are sorted so output is stable.
 */

const bar = "=".repeat(60);

export function renderHuman(report: ScanReport): string {
  const lines: string[] = [];

  lines.push("");
  lines.push(bar);
  lines.push("AuditPulse Security Scanner Report");
  lines.push(`Target: ${report.target}`);
  lines.push(`Files scanned: ${report.filesScanned}`);
  lines.push(bar);
  lines.push("");

  let currentFile: string | null = null;
  for (const finding of report.findings) {
    if (finding.file !== currentFile) {
      currentFile = finding.file;
      lines.push(`${currentFile}`);
    }
    lines.push(...findingLines(finding));
  }

  lines.push(...summaryLines(report));
  return lines.join("\n");
}

function findingLines(finding: FileFinding): string[] {
  const severity = finding.severity.toUpperCase();
  const confidence = finding.confidence?.toUpperCase() ?? "UNKNOWN";

  const lines = [
    `  Line ${finding.location.line}: [${finding.id}] [${severity}] [confidence: ${confidence}]`,
    `    ${finding.message}`,
  ];

  if (finding.location.function) {
    lines.push(`    Function: ${finding.location.function}`);
  }
  if (finding.remediation) {
    lines.push(`    Remediation: ${finding.remediation}`);
  }

  return lines;
}

function summaryLines(report: ScanReport): string[] {
  const bySeverity = new Map<string, number>();
  for (const finding of report.findings) {
    bySeverity.set(finding.severity, (bySeverity.get(finding.severity) ?? 0) + 1);
  }

  const parts = [...bySeverity.entries()]
    .sort(
      (a, b) =>
        (SEVERITY_ORDER[b[0] as keyof typeof SEVERITY_ORDER] ?? 0) -
        (SEVERITY_ORDER[a[0] as keyof typeof SEVERITY_ORDER] ?? 0),
    )
    .map(([severity, count]) => `${count} ${severity}`);

  const lines = [
    "",
    bar,
    `Total findings: ${report.findings.length}${parts.length > 0 ? ` (${parts.join(", ")})` : ""}`,
  ];

  if (report.findings.length === 0) {
    lines.push("No findings at or above the configured severity threshold.");
  }

  lines.push(bar, "");
  return lines;
}
