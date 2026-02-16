/**
 * @sanity-labs/secret-scan
 *
 * Detect and redact secrets in strings. Works in browser and Node.js.
 * Zero runtime dependencies. Rules derived from TruffleHog detectors (Apache 2.0).
 */

import { rules as trufflehogRules, globalAllowlist, type Rule } from './rules.js'
import { customRules } from './custom-rules.js'
import { shannonEntropy } from './entropy.js'

// TruffleHog rules first (more specific vendor patterns), custom rules after
// (broader safety net). Overlap detection prefers the first match.
const rules: Rule[] = [...trufflehogRules, ...customRules]

// --- Public types ---

export interface Secret {
  /** Rule ID, e.g. 'openai' */
  rule: string
  /** Human-readable label, e.g. 'Openai' */
  label: string
  /** The matched secret value */
  text: string
  /** Match confidence: 'high' for provider-specific patterns, 'medium' for generic/entropy-based */
  confidence: 'high' | 'medium'
  /** Start index of the secret in the input string */
  start: number
  /** End index (exclusive) of the secret in the input string */
  end: number
}

// --- Keyword index ---

// Build a map from keyword → rules that use it, for fast pre-filtering.
// Most rules have keywords; we only run a rule's regex if the input contains
// one of its keywords (case-insensitive).
const keywordIndex = new Map<string, Rule[]>()
const rulesWithoutKeywords: Rule[] = []

for (const rule of rules) {
  if (rule.keywords.length === 0) {
    rulesWithoutKeywords.push(rule)
  } else {
    for (const kw of rule.keywords) {
      const lower = kw.toLowerCase()
      let list = keywordIndex.get(lower)
      if (!list) {
        list = []
        keywordIndex.set(lower, list)
      }
      list.push(rule)
    }
  }
}

// --- Global allowlist ---

function isGlobalAllowlisted(secret: string): boolean {
  // Check global allowlist regexes against the secret value
  for (const { regex } of globalAllowlist.regexes) {
    if (regex.test(secret)) return true
  }

  // Check global stopwords
  const lower = secret.toLowerCase()
  for (const stopword of globalAllowlist.stopwords) {
    if (lower === stopword.toLowerCase()) return true
  }

  return false
}

// --- Rule allowlist ---

function isRuleAllowlisted(rule: Rule, secret: string, fullMatch: string, line: string): boolean {
  if (!rule.allowlist) return false

  // Check rule-specific regexes
  if (rule.allowlist.regexes) {
    for (const { regex, target } of rule.allowlist.regexes) {
      const testStr = target === 'line' ? line : (target === 'match' ? fullMatch : secret)
      if (regex.test(testStr)) return true
    }
  }

  // Check rule-specific stopwords (matched against the secret value)
  if (rule.allowlist.stopwords) {
    const lower = secret.toLowerCase()
    for (const stopword of rule.allowlist.stopwords) {
      if (lower.includes(stopword.toLowerCase())) return true
    }
  }

  return false
}

// --- Core scanning ---

function getCandidateRules(inputLower: string): Set<Rule> {
  const candidates = new Set<Rule>()

  // Always include rules without keywords
  for (const rule of rulesWithoutKeywords) {
    candidates.add(rule)
  }

  // Check which keywords appear in the input
  for (const [keyword, kwRules] of keywordIndex) {
    if (inputLower.includes(keyword)) {
      for (const rule of kwRules) {
        candidates.add(rule)
      }
    }
  }

  return candidates
}

function getLineForIndex(input: string, index: number): string {
  const lineStart = input.lastIndexOf('\n', index - 1) + 1
  let lineEnd = input.indexOf('\n', index)
  if (lineEnd === -1) lineEnd = input.length
  return input.slice(lineStart, lineEnd)
}

function extractSecret(match: RegExpExecArray, rule: Rule): string {
  // Use secretGroup if specified, otherwise use first capture group, otherwise full match
  const groupIndex = rule.secretGroup ?? 1
  // Try the specified group, fall back through groups, then full match
  if (match[groupIndex] !== undefined) return match[groupIndex]
  // If the specified group didn't match (e.g., alternation), try other groups
  for (let i = 1; i < match.length; i++) {
    if (match[i] !== undefined) return match[i]
  }
  return match[0]
}

const GENERIC_RULE_IDS = new Set(['generic-sk-secret', 'bearer-token'])

/**
 * Scan a string for secrets.
 *
 * Returns an array of every secret found in the input. Uses keyword
 * pre-filtering for performance — most of the 1,100+ regexes are skipped
 * for any given input.
 */
export function scan(input: string): Secret[] {
  if (!input) return []

  const inputLower = input.toLowerCase()
  const candidates = getCandidateRules(inputLower)
  const secrets: Secret[] = []

  // Track matched ranges to avoid overlapping detections
  const matchedRanges: Array<{ start: number; end: number }> = []

  for (const rule of candidates) {
    // Reset regex lastIndex for global-like iteration
    const regex = new RegExp(rule.regex.source, rule.regex.flags.replace('g', '') + 'g')

    let match: RegExpExecArray | null
    while ((match = regex.exec(input)) !== null) {
      const secret = extractSecret(match, rule)
      if (!secret) continue

      // Find the secret's position in the input
      const secretStart = input.indexOf(secret, match.index)
      const start = secretStart >= 0 ? secretStart : match.index
      const end = start + secret.length

      // Skip if this range overlaps with an already-detected secret
      // (prefer the first/more specific match)
      const overlaps = matchedRanges.some(
        (r) => start < r.end && end > r.start
      )
      if (overlaps) continue

      // Check entropy threshold
      if (rule.entropy !== undefined) {
        const entropy = shannonEntropy(secret)
        if (entropy < rule.entropy) continue
      }

      // Check global allowlist
      if (isGlobalAllowlisted(secret)) continue

      // Check rule-specific allowlist
      const line = getLineForIndex(input, match.index)
      if (isRuleAllowlisted(rule, secret, match[0], line)) continue

      const confidence = GENERIC_RULE_IDS.has(rule.id) ? 'medium' : 'high'

      secrets.push({
        rule: rule.id,
        label: rule.label,
        text: secret,
        confidence,
        start,
        end,
      })

      matchedRanges.push({ start, end })

      // Prevent infinite loop on zero-length matches
      if (match[0].length === 0) regex.lastIndex++
    }
  }

  // Sort by position in input
  secrets.sort((a, b) => a.start - b.start)

  return secrets
}

/**
 * Find and replace secrets in a string.
 *
 * Calls `replacer` for each detected secret. The return value replaces
 * the secret in the output string. The caller owns all state — `redact`
 * just does string replacement.
 *
 * Replacements are applied from right to left to preserve string indices.
 */
export function redact(
  input: string,
  replacer: (secret: Secret) => string
): string {
  const secrets = scan(input)
  if (secrets.length === 0) return input

  // Apply replacements right-to-left to preserve indices
  let result = input
  for (let i = secrets.length - 1; i >= 0; i--) {
    const secret = secrets[i]
    const replacement = replacer(secret)
    result = result.slice(0, secret.start) + replacement + result.slice(secret.end)
  }

  return result
}

// Re-export types and utilities
export { shannonEntropy } from './entropy.js'
export type { Rule } from './rules.js'
