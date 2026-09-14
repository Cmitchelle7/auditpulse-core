import type { IRulePlugin, Vulnerability } from '../types';

/**
 * Soroban rule: flag storage access that is not accompanied by an
 * `extend_ttl` / `extend_ttl_to_threshold` call on the environment.
 *
 * Soroban ledger entries expire: persistent and temporary entries have
 * time-based TTLs and, once expired, reads return `None` as if the data
 * never existed. Contracts that assume storage values live forever produce
 * silent fund loss or broken invariants. Storage touching code should bump
 * the TTL of the entries it relies on.
 */
export class MissingExtendTtlPlugin implements IRulePlugin {
  name = 'Missing Extend TTL';
  description =
    'Detects ledger storage access (persistent/temporary instance storage) that is never accompanied by an extend_ttl call, which risks silent data expiry';

  /** Strip // line and /* block *​/ comments so commented code is not scanned. */
  private removeComments(code: string): string {
    let result = code.replace(/\/\/.*$/gm, '');
    result = result.replace(/\/\*[\s\S]*?\*\//g, '');
    return result;
  }

  scan(code: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const cleanCode = this.removeComments(code);

    // `env.storage()` followed by any accessor chain (instance/persistent/temporary).
    const touchesStorage = /storage\s*\(\s*\)\s*\./.test(cleanCode);

    if (!touchesStorage) {
      return vulnerabilities;
    }

    // Any explicit TTL bump anywhere in the contract satisfies the rule.
    const hasExtendTtl =
      /\.extend_ttl\s*\(/.test(cleanCode) ||
      /extend_ttl_to_threshold\s*\(/.test(cleanCode) ||
      /get_extended\s*\(/.test(cleanCode);

    if (hasExtendTtl) {
      return vulnerabilities;
    }

    // Report the first storage-touching line so the report is actionable.
    const lines = cleanCode.split('\n');
    const storageLine = lines.findIndex((line) => /storage\s*\(\s*\)\s*\./.test(line));

    if (storageLine >= 0) {
      vulnerabilities.push({
        line: storageLine + 1,
        message:
          'Ledger entries accessed here are never bumped via extend_ttl; expired persistent/temporary entries read back as None. Add env.storage().extend_ttl(...) to keep required entries alive.',
        severity: 'high',
      });
    }

    return vulnerabilities;
  }
}

export default new MissingExtendTtlPlugin();
