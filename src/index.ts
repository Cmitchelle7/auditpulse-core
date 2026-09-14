import fs from "fs";
import type { IRulePlugin } from "./types";
import MissingRequireAuthPlugin from "./plugins/missingRequireAuth";
import UnwrapUsagePlugin from "./plugins/unwrapUsage";
import MissingExtendTtlPlugin from "./plugins/missingExtendTtl";

const rules: IRulePlugin[] = [
  MissingRequireAuthPlugin,
  UnwrapUsagePlugin,
  MissingExtendTtlPlugin,
];

// TODO: Add AST-based macro expansion for complex Soroban attributes
function main(filePath: string): void {
  if (!fs.existsSync(filePath)) {
    console.error(`Error: File not found: ${filePath}`);
    process.exit(1);
  }

  const code = fs.readFileSync(filePath, "utf-8");
  console.log(`\n${"=".repeat(60)}`);
  console.log("AuditPulse Security Scanner Report");
  console.log(`File: ${filePath}`);
  console.log(`${"=".repeat(60)}\n`);

  let total = 0;
  for (const rule of rules) {
    const findings = rule.scan(code);
    total += findings.length;

    console.log(`\n[${rule.name.toUpperCase()}]`);
    console.log(`Description: ${rule.description}`);

    if (findings.length === 0) {
      console.log("Status: ✓ No vulnerabilities found");
      continue;
    }

    console.log(`Vulnerabilities found: ${findings.length}\n`);
    for (const f of findings) {
      console.log(`  Line ${f.line}: [${f.severity.toUpperCase()}] ${f.message}`);
    }
  }

  console.log(`\n${"=".repeat(60)}`);
  console.log(`Total Vulnerabilities: ${total}`);
  console.log(`${"=".repeat(60)}\n`);

  if (total > 0) process.exit(1);
}

const targetFile = process.argv[2];
if (!targetFile) {
  console.error("Usage: npx ts-node src/index.ts <file-path>");
  process.exit(1);
}

main(targetFile);
