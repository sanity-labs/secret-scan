/**
 * Shannon entropy calculation.
 *
 * Measures the randomness of a string. Higher entropy = more random = more
 * likely to be a real secret. Gitleaks uses entropy thresholds on many rules
 * to reduce false positives.
 *
 * Formula: H = -Σ p(x) * log2(p(x)) for each unique character x
 */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0

  const freq = new Map<string, number>()
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1)
  }

  let entropy = 0
  const len = s.length
  for (const count of freq.values()) {
    const p = count / len
    entropy -= p * Math.log2(p)
  }

  return entropy
}
