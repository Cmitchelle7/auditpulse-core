/**
 * Shared text helpers for scanning Rust/Soroban source code.
 * Kept here so every rule strips comments in exactly the same way.
 */

/**
 * Removes `//` line comments and `/* ... *&#47;` block comments.
 *
 * Rules must compute findings on comment-free code so commented-out
 * examples never trigger them.
 */
export function removeComments(code: string): string {
  return code.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
}
