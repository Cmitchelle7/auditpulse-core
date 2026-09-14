import fs from 'fs';
import path from 'path';
import { IRulePlugin } from './types';
import UncheckedReturnPlugin from './plugins/uncheckedReturn';
import ReentrancyCheckPlugin from './plugins/reentrancyCheck';

/**
 * AuditPulse CLI Engine
 * Main entry point for scanning Solidity files for vulnerabilities
 */
class AuditPulseCLI {
  private rules: IRulePlugin[] = [UncheckedReturnPlugin, ReentrancyCheckPlugin];

  /**
   * Main CLI entry point
   */
  run(args: string[]): void {
    if (args.length < 2) {
      console.error('Usage: npx ts-node src/index.ts <file-path>');
      process.exit(1);
    }

    const filePath = args[args.length - 1];

    if (!fs.existsSync(filePath)) {
      console.error(`Error: File not found: ${filePath}`);
      process.exit(1);
    }

    const code = fs.readFileSync(filePath, 'utf-8');
    this.scanCode(code, filePath);
  }

  /**
   * Scan code using all registered rules
   */
  private scanCode(code: string, filePath: string): void {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`AuditPulse Security Scanner Report`);
    console.log(`File: ${filePath}`);
    console.log(`${'='.repeat(60)}\n`);

    let totalWarnings = 0;
    const allVulnerabilities = [];

    // Run all rules
    for (const rule of this.rules) {
      const vulnerabilities = rule.scan(code);
      totalWarnings += vulnerabilities.length;

      if (vulnerabilities.length > 0) {
        console.log(`\n[${rule.name.toUpperCase()}]`);
        console.log(`Description: ${rule.description}`);
        console.log(`Vulnerabilities found: ${vulnerabilities.length}\n`);

        vulnerabilities.forEach((vuln) => {
          console.log(
            `  Line ${vuln.line}: [${vuln.severity.toUpperCase()}] ${vuln.message}`
          );
          allVulnerabilities.push({ rule: rule.name, ...vuln });
        });
      } else {
        console.log(`\n[${rule.name.toUpperCase()}]`);
        console.log(`Description: ${rule.description}`);
        console.log(`Status: ✓ No vulnerabilities found`);
      }
    }

    // Print summary
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Summary:`);
    console.log(`Total Vulnerabilities: ${totalWarnings}`);
    console.log(`${'='.repeat(60)}\n`);

    if (totalWarnings > 0) {
      process.exit(1);
    }
  }
}

// CLI Entry point
const cli = new AuditPulseCLI();
cli.run(process.argv);
