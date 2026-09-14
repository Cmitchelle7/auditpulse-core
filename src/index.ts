import fs from "fs";
import type { IRulePlugin } from "./types";
import MissingRequireAuthPlugin from "./plugins/missingRequireAuth";
import UnwrapUsagePlugin from "./plugins/unwrapUsage";
import MissingExtendTtlPlugin from "./plugins/missingExtendTtl";

class AuditPulseCLI {
  private rules: IRulePlugin[] = [
    MissingRequireAuthPlugin,
    UnwrapUsagePlugin,
    MissingExtendTtlPlugin,
  ];

  run(args: string[]): void {
    if (args.length < 2) {
      console.error("Usage: npx ts-node src/index.ts <file-path>");
      process.exit(1);
    }

    const file = args[args.length - 1]!;
    if (!fs.existsSync(file)) {
      console.error(`Error: File not found: ${file}`);
      process.exit(1);
    }

    this.scan(fs.readFileSync(file, "utf-8"), file);
  }

  private scan(code: string, file: string): void {
    console.log(`\n${"=".repeat(60)}`);
    console.log("AuditPulse Security Scanner Report");
    console.log(`File: ${file}`);
    console.log(`${"=".repeat(60)}\n`);

    let total = 0;
    for (const rule of this.rules) {
      const findings = rule.scan(code);
      total += findings.length;

      console.log(`\n[${rule.name.toUpperCase()}]`);
      console.log(`Description: ${rule.description}`);
      if (findings.length === 0) {
        console.log("Status: ✓ No vulnerabilities found");
        continue;
      }

      console.log(`Vulnerabilities found: ${findings.length}\n`);
      for (const finding of findings) {
        console.log(
          `  Line ${finding.line}: [${finding.severity.toUpperCase()}] ${finding.message}`,
        );
      }
    }

    console.log(`\n${"=".repeat(60)}`);
    console.log("Summary:");
    console.log(`Total Vulnerabilities: ${total}`);
    console.log(`${"=".repeat(60)}\n`);

    if (total > 0) {
      process.exit(1);
    }
  }
}

new AuditPulseCLI().run(process.argv);
