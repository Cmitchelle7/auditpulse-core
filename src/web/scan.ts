import { AuditEngine } from "../engine.js";
import { createDefaultRegistry } from "../registry.js";
import { sortFindings, type FileFinding } from "../scanner.js";
import { toJsonReport, type JsonReport } from "../reporting/json.js";

/**
 * Scans Rust source text in memory with the existing AuditPulse engine.
 * This is the same rule set and finding model the CLI uses — the web layer
 * adds no scanning logic of its own.
 */
export function scanSource(source: string): JsonReport {
  const engine = new AuditEngine(createDefaultRegistry());
  const findings: FileFinding[] = engine.run(source).map((finding) => ({
    ...finding,
    file: "submitted-source.rs",
  }));

  return toJsonReport({
    target: "submitted-source.rs",
    findings: sortFindings(findings),
    filesScanned: 1,
  });
}
