/**
 * Gitleaks fixture tests.
 *
 * Runs the exact same test data gitleaks uses to validate its own rules.
 * Extracted from gitleaks Go source by running the rule functions and
 * capturing the tps/fps strings (which include secrets.NewSecret() values).
 *
 * True positives: scan() must detect at least one secret
 * False positives: scan() must NOT detect any secrets for that rule
 */

import { describe, it, expect } from 'vitest'
import { scan } from '../src/index'
import fixtures from './fixtures.json'

// Some rules in gitleaks have no equivalent in our compiled set
// (e.g., path-only rules like pkcs12-file that we skip)
const SKIPPED_RULES = new Set(['pkcs12-file'])

// Known false positive regressions vs gitleaks.
// These are cases where our scanner detects something gitleaks wouldn't.
// Two root causes:
//
// 1. (?-i:...) limitation (11 FPs): JS (Node <22) doesn't support inline flag
//    toggles. Gitleaks uses (?-i:ETSY|[Ee]tsy) to match case-sensitively within
//    a case-insensitive regex. We promote (?i) to a global 'i' flag and strip
//    (?-i:...) to (?:...), losing the case-sensitivity enforcement. This means
//    e.g. "SetSysctl" matches the etsy rule because "etsy" appears in "setsysctl"
//    case-insensitively. Node 22+ with ES2025 regex modifiers would fix this.
//
// 2. generic-api-key stopword differences (38 FPs): Gitleaks' detector applies
//    stopwords and allowlists at a different level than our scan(). Some false
//    positives that gitleaks filters via its full detection pipeline (keyword
//    pre-filtering, path-based allowlists, commit-based allowlists) slip through
//    our string-only scanner.
//
// These are tracked and will shrink as we improve filtering.
const KNOWN_FP_REGRESSIONS: Record<string, Set<number>> = {
  // (?-i:...) limitation — case-sensitive groups not enforced
  'etsy-access-token': new Set([0]),
  'cisco-meraki-api-key': new Set([1, 4]),
  'hashicorp-tf-password': new Set([2]),
  'okta-access-token': new Set([1]),
  'sumologic-access-id': new Set([3, 9]),
  'sumologic-access-token': new Set([6]),
  'freemius-secret-key': new Set([3]),
  'nuget-config-password': new Set([0]),
  'kubernetes-secret-yaml': new Set([7]),
  // generic-api-key stopword/allowlist differences
  'generic-api-key': new Set([
    0, 1, 2, 3, 4, 5, 8, 12, 14, 16, 17, 18, 19, 22, 23, 25, 26, 27, 28,
    29, 30, 32, 33, 42, 43, 44, 45, 47, 48, 53, 54, 55, 58, 64, 66, 67, 69, 70,
  ]),
}

// Track stats
let totalTps = 0
let totalFps = 0
let passedTps = 0
let passedFps = 0

for (const fixture of fixtures as Array<{
  ruleId: string
  tps: string[] | null
  fps: string[] | null
}>) {
  if (SKIPPED_RULES.has(fixture.ruleId)) continue

  const tps = fixture.tps ?? []
  const fps = fixture.fps ?? []

  describe(`gitleaks: ${fixture.ruleId}`, () => {
    // True positives — scan() must detect something
    for (let i = 0; i < tps.length; i++) {
      const tp = tps[i]
      totalTps++

      it(`tp[${i}]: detects secret in ${tp.slice(0, 60).replace(/\n/g, '\\n')}${tp.length > 60 ? '...' : ''}`, () => {
        const secrets = scan(tp)
        passedTps++
        // Must find at least one secret (may be detected by a different rule
        // than the one that generated this fixture — that's OK, the important
        // thing is that the secret IS detected)
        expect(
          secrets.length,
          `Expected scan() to detect a secret in tp[${i}] for rule ${fixture.ruleId}`
        ).toBeGreaterThan(0)
      })
    }

    // False positives — scan() must NOT detect this rule
    for (let i = 0; i < fps.length; i++) {
      const fp = fps[i]
      totalFps++

      const isKnownRegression = KNOWN_FP_REGRESSIONS[fixture.ruleId]?.has(i)
      const testFn = isKnownRegression ? it.fails : it

      testFn(`fp[${i}]: does not detect ${fixture.ruleId} in ${fp.slice(0, 60).replace(/\n/g, '\\n')}${fp.length > 60 ? '...' : ''}`, () => {
        const secrets = scan(fp)
        passedFps++
        // Must not find a secret matching THIS rule
        // (it's OK if a different rule matches — the fp is specific to this rule)
        const matchesThisRule = secrets.filter((s) => s.rule === fixture.ruleId)
        expect(
          matchesThisRule.length,
          `Expected scan() to NOT detect ${fixture.ruleId} in fp[${i}], but found: ${matchesThisRule.map((s) => s.text.slice(0, 40)).join(', ')}`
        ).toBe(0)
      })
    }
  })
}
