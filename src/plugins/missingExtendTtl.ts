import type { Rule, Vulnerability } from "../types";
import { removeComments } from "../utils/rust.js";

export class MissingExtendTtlPlugin implements Rule {
  id = "AP-STORAGE-001";
  name = "Missing Extend TTL";
  description =
    "Detects ledger storage access (persistent/temporary instance storage) that is never accompanied by an extend_ttl call, which risks silent data expiry";

  scan(code: string): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const clean = removeComments(code);
    const storage = /storage\s*\(\s*\)\s*\./;

    if (!storage.test(clean)) {
      return findings;
    }

    const extended =
      /\.extend_ttl\s*\(/.test(clean) ||
      /extend_ttl_to_threshold\s*\(/.test(clean) ||
      /get_extended\s*\(/.test(clean);
    if (extended) {
      return findings;
    }

    const line = clean.split("\n").findIndex((value) => storage.test(value));
    if (line >= 0) {
      findings.push({
        id: "AP-STORAGE-001",
        message:
          "Ledger entries accessed here are never bumped via extend_ttl; expired persistent/temporary entries read back as None. Add env.storage().extend_ttl(...) to keep required entries alive.",
        severity: "high",
        confidence: "medium",
        location: {
          line: line + 1,
        },
        remediation:
          "After reading or writing persistent/temporary storage, call env.storage().persistent().extend_ttl(&key, threshold, extend_to) or extend_ttl_to_threshold to keep entries alive.",
      });
    }

    return findings;
  }
}

export default new MissingExtendTtlPlugin();
