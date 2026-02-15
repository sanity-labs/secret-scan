/**
 * Tests that all gitleaks rules compiled correctly and are functional.
 * Validates the Go→JS regex conversion.
 */

import { describe, it, expect } from 'vitest'
import { rules, globalAllowlist } from '../src/rules'

describe('rules compilation', () => {
  it('has 221 compiled rules', () => {
    expect(rules.length).toBe(221)
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

  it('all allowlist regexes can execute', () => {
    for (const rule of rules) {
      if (rule.allowlist?.regexes) {
        for (const { regex } of rule.allowlist.regexes) {
          expect(() => regex.test('test')).not.toThrow()
        }
      }
    }
  })

  it('global allowlist has regexes and stopwords', () => {
    expect(globalAllowlist.regexes.length).toBeGreaterThan(0)
    expect(globalAllowlist.stopwords.length).toBeGreaterThan(0)
  })

  it('all global allowlist regexes can execute', () => {
    for (const { regex } of globalAllowlist.regexes) {
      expect(() => regex.test('test')).not.toThrow()
    }
  })

  it('rules with entropy have numeric thresholds', () => {
    const withEntropy = rules.filter((r) => r.entropy !== undefined)
    expect(withEntropy.length).toBeGreaterThan(100) // most rules have entropy
    for (const rule of withEntropy) {
      expect(typeof rule.entropy).toBe('number')
      expect(rule.entropy).toBeGreaterThan(0)
    }
  })

  it('generic-api-key has stopwords', () => {
    const generic = rules.find((r) => r.id === 'generic-api-key')
    expect(generic).toBeTruthy()
    expect(generic!.allowlist?.stopwords?.length).toBeGreaterThan(1000)
  })
})

describe('known rule patterns', () => {
  // Test specific rules with known-good patterns to validate regex conversion

  const testCases: Array<{ ruleId: string; shouldMatch: string[]; shouldNotMatch: string[] }> = [
    {
      ruleId: 'openai-api-key',
      shouldMatch: [
        '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',
        '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',
      ],
      shouldNotMatch: ['sk-not-a-real-key', 'sk-proj-short'],
    },
    {
      ruleId: 'aws-access-token',
      shouldMatch: ['AKIAIOSFODNN7XYZABCD'],
      // Note: AKIAIOSFODNN7EXAMPLE matches the regex — it's filtered by the
      // rule's allowlist (.+EXAMPLE$) in scan(), not at the regex level
      shouldNotMatch: ['not-an-aws-key', 'AKIA_too_short'],
    },
    {
      ruleId: 'github-pat',
      shouldMatch: ['ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'],
      shouldNotMatch: ['ghp_short', 'not_a_github_token'],
    },
    {
      ruleId: 'stripe-access-token',
      shouldMatch: [
        'sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs',
        'rk_prod_51OuEMLAlTWGaDypquDn9aZigaJOsa9NR1w1BxZXs9JlYsVVkv5XDu6aLmAxwt5Tgun5WcSwQMKzQyqV16c9iD4sx00BRijuoon',
      ],
      shouldNotMatch: ['sk_test_short', 'pk_test_not_secret'],
    },
    {
      ruleId: 'slack-bot-token',
      // Slack bot tokens have format: xoxb-{10-13 digits}-{10-13 digits}{alphanumeric}
      shouldMatch: ['xoxb-263594206564-2963137677872-FGqddMF8t08v8N7Oq4i57vs1MF'],
      shouldNotMatch: ['xoxb-short', 'xoxb-123-456'],
    },
    {
      ruleId: 'private-key',
      shouldMatch: [
        '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy5AHBcdkCYAfMzRaBqGFoPE1234567890abcdefghijklmnopqrstuvwxyz-----END RSA PRIVATE KEY-----',
      ],
      shouldNotMatch: ['-----BEGIN PUBLIC KEY-----'],
    },
    {
      ruleId: 'generic-api-key',
      shouldMatch: [
        'API_KEY=a8f3k9d2m5n7p1q4r6s8t0u2v4w6x8y0z1',
        'secret = "x7k2m9p4q1r8s5t0u3v6w9y2z5a8b1c4"',
      ],
      shouldNotMatch: [],
    },
  ]

  for (const tc of testCases) {
    const rule = rules.find((r) => r.id === tc.ruleId)
    if (!rule) {
      it.skip(`${tc.ruleId} — rule not found`, () => {})
      continue
    }

    describe(tc.ruleId, () => {
      for (const s of tc.shouldMatch) {
        it(`matches: ${s.slice(0, 50)}${s.length > 50 ? '...' : ''}`, () => {
          expect(rule.regex.test(s)).toBe(true)
        })
      }
      for (const s of tc.shouldNotMatch) {
        it(`rejects: ${s.slice(0, 50)}`, () => {
          expect(rule.regex.test(s)).toBe(false)
        })
      }
    })
  }
})
