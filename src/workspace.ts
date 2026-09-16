import fs from "fs";
import path from "path";

/**
 * Safe discovery of Rust source files under a start directory.
 *
 * This is file discovery only — it does not parse Rust and performs no
 * cross-file analysis. Files are returned in deterministic order (sorted
 * relative path) so scans are reproducible.
 */

/** Directory names never scanned, regardless of configuration. */
const BUILTIN_EXCLUDES = [
  "node_modules",
  "dist",
  "build",
  "out",
  "target",
  ".git",
  ".github",
  ".hg",
  ".svn",
  ".vscode",
  ".idea",
  "vendor",
  "venv",
  ".venv",
  "__pycache__",
  "coverage",
  ".next",
  ".cache",
];

/** Sorted relative paths (forward slashes) of every .rs file under root. */
export function discoverRustFiles(
  root: string,
  extraExcludes: string[] = [],
): string[] {
  const files: string[] = [];
  walk(root, "", extraExcludes, files);
  return files.sort(comparePosix);
}

function walk(
  root: string,
  prefix: string,
  excludes: string[],
  files: string[],
): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    // Unreadable directory: skip silently, scanning continues elsewhere.
    return;
  }

  for (const entry of entries) {
    const name = entry.name;
    const relPath = prefix === "" ? name : `${prefix}/${name}`;
    const absPath = path.join(root, name);

    if (entry.isDirectory()) {
      if (BUILTIN_EXCLUDES.includes(name) || isExcluded(relPath, excludes)) {
        continue;
      }
      walk(absPath, relPath, excludes, files);
    } else if (entry.isFile() && name.endsWith(".rs")) {
      if (isExcluded(relPath, excludes)) continue;
      files.push(relPath);
    }
  }
}

/**
 * True when `relPath` or any of its segments matches an exclusion. Exclusions
 * are path fragments in forward-slash form and match either a full segment or
 * the beginning of the path.
 */
export function isExcluded(relPath: string, excludes: string[]): boolean {
  const normalized = relPath.replace(/\\/g, "/");

  for (const exclude of excludes) {
    const frag = exclude.replace(/\\/g, "/").replace(/^\.?\//, "").replace(/\/$/, "");
    if (frag === "") continue;

    if (normalized === frag || normalized.startsWith(`${frag}/`)) return true;

    // Also treat an exact segment name as an exclusion ("target", "src/gen").
    for (const segment of normalized.split("/")) {
      if (segment === frag) return true;
    }
  }

  return false;
}

/** Locale-independent comparison so file order never depends on the machine. */
export function comparePosix(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
