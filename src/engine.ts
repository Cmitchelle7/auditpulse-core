import type { Rule, RuleId, Vulnerability } from "./types";
import type { RuleRegistry } from "./registry";

/**
 * Runs registered rules over source code and aggregates their findings.
 * Holds no state beyond the registry, so one engine can scan many files.
 */
export class AuditEngine {
  constructor(private readonly registry: RuleRegistry) {}

  /** All rules the engine will execute, in registration order. */
  rules(): Rule[] {
    return this.registry.all();
  }

  /** Runs a single registered rule by id. */
  runRule(id: RuleId, code: string): Vulnerability[] {
    const rule = this.registry.get(id);
    if (!rule) {
      throw new Error(`Unknown rule id: ${id}`);
    }
    return rule.scan(code).map((finding) => stampRuleId(rule, finding));
  }

  /** Runs every registered rule over `code`, in registration order. */
  run(code: string): Vulnerability[] {
    const findings: Vulnerability[] = [];
    for (const rule of this.rules()) {
      findings.push(...this.runRule(rule.id, code));
    }
    return findings;
  }
}

/** Ensures every finding reports the id of the rule that produced it. */
function stampRuleId(rule: Rule, finding: Vulnerability): Vulnerability {
  return finding.id === rule.id ? finding : { ...finding, id: rule.id };
}
