import type { Severity } from "./types";

/**
 * Lightweight AuditPulse configuration.
 *
 * Loads `auditpulse.toml` when present (no dependencies: only the flat
 * `key = "value"` subset described below is understood) and falls back to
 * sensible defaults when no file exists.
 *
 * Supported keys:
 *   disabled_rules = ["AP-DEBUG-001", ...]
 *   min_severity   = "low" | "medium" | "high" | "critical"
 *   exclude        = ["node_modules", ...]  (path fragments, forward slashes)
 *
 * Unknown keys are ignored. Invalid values are reported as errors rather
 * than guessed at.
 */
export interface AuditPulseConfig {
  /** Rule ids that must not run. */
  disabledRules: string[];
  /** Findings below this severity are dropped. Default: "low" (report all). */
  minSeverity: Severity;
  /** Path fragments (forward-slash separated) to skip during discovery. */
  exclude: string[];
}

/** Severity ranking used for both filtering and sorting. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

export const MIN_SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

/** Configuration used when no file exists or nothing is overridden. */
export function defaultConfig(): AuditPulseConfig {
  return {
    disabledRules: [],
    minSeverity: "low",
    exclude: [],
  };
}

/** Error thrown when the configuration file is malformed. */
export class ConfigError extends Error {}

/**
 * Locates `auditpulse.toml` for `startPath`: the start path itself (when it
 * is a directory), then walking up its parent directories. Returns null when
 * nothing is found.
 */
export function findConfigFile(
  startPath: string,
  readFile: (path: string) => string | null,
): string | null {
  let dir = startPath;
  for (;;) {
    if (dir === "") return null;
    const candidate = joinPath(dir, "auditpulse.toml");
    const contents = readFile(candidate);
    if (contents !== null) return candidate;

    const parent = parentDir(dir);
    if (parent === dir || parent === "") return null;
    dir = parent;
  }
}

/**
 * Parses auditpulse.toml contents. Throws ConfigError on structural
 * problems; the returned config contains only the keys actually present.
 */
export function parseConfig(text: string): Partial<AuditPulseConfig> {
  const result: Partial<AuditPulseConfig> = {};
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = stripComment(lines[i] ?? "").trim();
    if (line === "") continue;

    const eq = line.indexOf("=");
    const key = eq <= 0 ? "" : line.slice(0, eq).trim();
    if (key === "" || /\s/.test(key)) {
      throw new ConfigError(
        `auditpulse.toml line ${i + 1}: expected "key = value", got: ${line}`,
      );
    }
    const rawValue = line.slice(eq + 1).trim();
    switch (key) {
      case "disabled_rules":
        result.disabledRules = parseStringArray(rawValue, i + 1);
        break;
      case "exclude":
        result.exclude = parseStringArray(rawValue, i + 1);
        break;
      case "min_severity":
        result.minSeverity = parseSeverity(rawValue, i + 1);
        break;
      default:
        // Unknown keys are ignored so the file can carry project metadata.
        break;
    }
  }

  return result;
}

/**
 * Merges parsed file values over the defaults, validating rule ids and
 * severity levels along the way.
 */
export function resolveConfig(
  parsed: Partial<AuditPulseConfig>,
  knownRuleIds: string[],
): AuditPulseConfig {
  const config = defaultConfig();

  for (const ruleId of parsed.disabledRules ?? []) {
    if (!knownRuleIds.includes(ruleId)) {
      throw new ConfigError(`Unknown rule id in configuration: ${ruleId}`);
    }
    config.disabledRules.push(ruleId);
  }

  if (parsed.minSeverity !== undefined) {
    config.minSeverity = parsed.minSeverity;
  }

  config.exclude.push(...(parsed.exclude ?? []));

  return config;
}

function parseStringArray(raw: string, lineNo: number): string[] {
  if (!raw.startsWith("[") || !raw.endsWith("]")) {
    throw new ConfigError(
      `auditpulse.toml line ${lineNo}: expected an array like ["a", "b"], got: ${raw}`,
    );
  }

  const inner = raw.slice(1, -1).trim();
  if (inner === "") return [];

  const items: string[] = [];
  // Simple split: TOML string arrays in a config file are comma separated.
  for (const item of inner.split(",")) {
    const value = item.trim();
    const match = /^"([^"]*)"$/.exec(value) ?? /^'([^']*)'$/.exec(value);
    if (!match) {
      throw new ConfigError(
        `auditpulse.toml line ${lineNo}: array items must be quoted strings, got: ${value}`,
      );
    }
    items.push(match[1] ?? "");
  }

  return items;
}

function parseSeverity(raw: string, lineNo: number): Severity {
  const value = stripQuotes(raw);
  if (!MIN_SEVERITIES.includes(value as Severity)) {
    throw new ConfigError(
      `auditpulse.toml line ${lineNo}: min_severity must be one of ${MIN_SEVERITIES.join(", ")}, got: ${raw}`,
    );
  }
  return value as Severity;
}

function stripComment(line: string): string {
  // Quoted strings may contain '#'; only strip when # is outside quotes.
  const inQuote = /^([^"#]*"[^"]*"[^"#]*)#/.exec(line);
  return inQuote ? line.slice(0, inQuote[1]!.length) : line.split("#")[0]!;
}

function stripQuotes(raw: string): string {
  const match = /^"([^"]*)"$/.exec(raw) ?? /^'([^']*)'$/.exec(raw);
  return match ? (match[1] ?? "") : raw;
}

function joinPath(dir: string, file: string): string {
  return dir.endsWith("/") || dir.endsWith("\\")
    ? `${dir}${file}`
    : `${dir}/${file}`;
}

function parentDir(dir: string): string {
  // Strip trailing slashes but keep a lone root "/" intact.
  const normalized = dir === "/" ? dir : dir.replace(/[\\/]+$/, "");
  const cut = Math.max(
    normalized.lastIndexOf("/"),
    normalized.lastIndexOf("\\"),
  );
  if (cut < 0) return ""; // bare name like "fixtures" or "C:" -> no parent
  if (cut === 0) return "/"; // parent of "/home" is "/"
  return normalized.slice(0, cut);
}
