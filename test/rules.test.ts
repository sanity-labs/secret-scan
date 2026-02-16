/**
 * Tests that all TruffleHog rules compiled correctly and are functional.
 * Validates the Go→JS regex conversion pipeline.
 */

import { describe, it, expect } from 'vitest'
import { rules, globalAllowlist } from '../src/rules'

describe('rules compilation', () => {
  it('has >1000 compiled rules', () => {
    expect(rules.length).toBeGreaterThan(1000)
  })

  it('all rules have required fields', () => {
    for (const rule of rules) {
      expect(rule.id).toBeTruthy()
      expect(rule.label).toBeTruthy()
      expect(rule.regex).toBeInstanceOf(RegExp)
      expect(Array.isArray(rule.keywords)).toBe(true)
    }
  })

  it('all rule IDs are unique', () => {
    const ids = rules.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('all regexes can execute without error', () => {
    for (const rule of rules) {
      // Just verify the regex can run without throwing
      expect(() => rule.regex.test('test string')).not.toThrow()
    }
  })

  it('most rules have keywords for pre-filtering', () => {
    const withKeywords = rules.filter((r) => r.keywords.length > 0)
    // At least 95% should have keywords
    expect(withKeywords.length / rules.length).toBeGreaterThan(0.95)
  })

  it('keywords are lowercase', () => {
    for (const rule of rules) {
      for (const kw of rule.keywords) {
        expect(kw).toBe(kw.toLowerCase())
      }
    }
  })

  it('includes key vendor detectors', () => {
    const ids = new Set(rules.map((r) => r.id))
    expect(ids.has('openai')).toBe(true)
    expect(ids.has('anthropic')).toBe(true)
    expect(ids.has('aws-access_keys')).toBe(true)
    expect(ids.has('github-v2')).toBe(true)
    expect(ids.has('stripe')).toBe(true)
    expect(ids.has('groq')).toBe(true)
    expect(ids.has('replicate')).toBe(true)
    expect(ids.has('jwt')).toBe(true)
    expect(ids.has('sendgrid')).toBe(true)
  })
})

describe('global allowlist', () => {
  it('has regex patterns', () => {
    expect(globalAllowlist.regexes.length).toBeGreaterThan(0)
  })

  it('has stopwords', () => {
    expect(globalAllowlist.stopwords.length).toBeGreaterThan(0)
  })

  it('all allowlist regexes can execute', () => {
    for (const { regex } of globalAllowlist.regexes) {
      expect(() => regex.test('test')).not.toThrow()
    }
  })

  it('filters template variables', () => {
    const templatePatterns = [
      '$GITHUB_TOKEN',
      '${API_KEY}',
      '{{ secrets.TOKEN }}',
      '%API_KEY%',
    ]
    for (const pattern of templatePatterns) {
      const matches = globalAllowlist.regexes.some(({ regex }) => regex.test(pattern))
      expect(matches).toBe(true)
    }
  })
})
