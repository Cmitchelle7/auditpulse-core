import fs from "fs";
import path from "path";
import { AuditEngine } from "./engine.js";
import type { RuleId, Severity, SourceLocation, Vulnerability } from "./types";
import type { AuditPulseConfig } from "./config";
import { SEVERITY_ORDER, findConfigFile, parseConfig, resolveConfig } from "./config.js";
import { discoverRustFiles } from "./workspace.js";

/**
 * Scans a single file or a whole directory tree with the existing engine,
 * applies configuration filtering, and returns per-file findings.
 *
 * Every file is scanned independently; there is no cross-file dataflow.
 */
export interface FileFinding extends Vulnerability {
  /** Path as passed by the user, joined with the file's relative path. */
  file: string;
}

export interface ScanReport {
  /** Path exactly as given on the command line. */
  target: string;
  findings: FileFinding[];
  /** Number of Rust files examined (1 for single-file scans). */
  filesScanned: number;
}

/**
 * Loads configuration for a scan target: auditpulse.toml is looked up in the
 * target directory (or its parents). Returns the config plus the path it came
 * from, or null when no file exists (defaults apply).
 */
export function loadConfig(
  targetPath: string,
  knownRuleIds: RuleId[],
  readFile: (path: string) => string | null = readOrNull,
): { config: AuditPulseConfig; path: string | null } {
  const configPath = findConfigFile(targetPath, readFile);
  if (configPath === null) {
    return { config: resolveConfig({}, knownRuleIds), path: null };
  }

  const parsed = parseConfig(readFile(configPath) ?? "");
  return { config: resolveConfig(parsed, knownRuleIds), path: configPath };
}

/**
 * Scans `target` (a file or directory) and returns a report. Throws
 * InputError when the path does not exist or is not a file/directory.
 */
export function scanTarget(
  target: string,
  engine: AuditEngine,
  config: AuditPulseConfig,
): ScanReport {
  if (!fs.existsSync(target)) {
    throw new InputError(`Path not found: ${target}`);
  }

  const stat = fs.statSync(target);
  if (stat.isFile()) {
    if (!target.endsWith(".rs")) {
      throw new InputError(`Not a Rust source file: ${target}`);
    }
    // The file is the target itself: report it under the path the user gave.
    const findings = scanFile("", target, engine, config);
    return { target, findings, filesScanned: 1 };
  }

  if (!stat.isDirectory()) {
    throw new InputError(`Not a file or directory: ${target}`);
  }

  const files = discoverRustFiles(target, config.exclude);
  const findings: FileFinding[] = [];
  for (const relPath of files) {
    findings.push(...scanFile(target, relPath, engine, config));
  }

  return { target, findings, filesScanned: files.length };
}

/** Scans one file and attaches its path to every finding. */
function scanFile(
  root: string,
  relPath: string,
  engine: AuditEngine,
  config: AuditPulseConfig,
): FileFinding[] {
  const code = fs.readFileSync(path.join(root, relPath), "utf-8");
  const findings: FileFinding[] = [];

  for (const rule of engine.rules()) {
    if (config.disabledRules.includes(rule.id)) continue;
    for (const finding of engine.runRule(rule.id, code)) {
      if (SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[config.minSeverity]) {
        continue;
      }
      findings.push({ ...finding, file: relPath });
    }
  }

  return sortFindings(findings);
}

/** Deterministic order: file path, then line, then rule id. */
export function sortFindings(findings: FileFinding[]): FileFinding[] {
  return [...findings].sort((a, b) => {
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    if (a.location.line !== b.location.line) return a.location.line - b.location.line;
    if (a.id !== b.id) return a.id < b.id ? -1 : 1;
    return compareMessages(a, b);
  });
}

function compareMessages(a: FileFinding, b: FileFinding): number {
  if (a.message === b.message) return 0;
  return a.message < b.message ? -1 : 1;
}

/** Error for bad user input: wrong path type, missing file, etc. */
export class InputError extends Error {}

function readOrNull(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}

/**
 * Only reports column/function when the plugin provided them; here we expose
 * the location untouched so unreliable data is never invented.
 */
export function locationOf(finding: FileFinding): SourceLocation {
  return finding.location;
}
