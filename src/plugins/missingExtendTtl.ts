import type { IRulePlugin, Vulnerability } from "../types";

export class MissingExtendTtlPlugin implements IRulePlugin {
  name = "Missing Extend TTL";
  description =
    "Detects ledger storage access (persistent/temporary instance storage) that is never accompanied by an extend_ttl call, which risks silent data expiry";

  private removeComments(code: string): string {
    return code.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
  }

  scan(code: string): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const clean = this.removeComments(code);
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
        line: line + 1,
        message:
          "Ledger entries accessed here are never bumped via extend_ttl; expired persistent/temporary entries read back as None. Add env.storage().extend_ttl(...) to keep required entries alive.",
        severity: "high",
      });
    }

    return findings;
  }
}

export default new MissingExtendTtlPlugin();
