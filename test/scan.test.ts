import { describe, it, expect } from 'vitest'
import { scan, redact, shannonEntropy } from '../src/index'

describe('scan', () => {
  it('detects OpenAI API key', () => {
    const input = 'OPENAI_API_KEY=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'
    const secrets = scan(input)
    expect(secrets).toHaveLength(1)
    expect(secrets[0].rule).toBe('openai-api-key')
    expect(secrets[0].confidence).toBe('high')
  })

  it('detects AWS access key', () => {
    const secrets = scan('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7XYZABCD')
    expect(secrets).toHaveLength(1)
    expect(secrets[0].rule).toBe('aws-access-token')
    expect(secrets[0].text).toBe('AKIAIOSFODNN7XYZABCD')
  })

  it('skips AWS example key (allowlisted)', () => {
    const secrets = scan('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE')
    expect(secrets).toHaveLength(0)
  })

  it('detects Stripe access token', () => {
    const secrets = scan('sk_live_abc123def456ghi789jkl012mno345pqr678')
    expect(secrets.length).toBeGreaterThanOrEqual(1)
    // Could be stripe-access-token or generic-api-key depending on context
  })

  it('detects GitHub PAT', () => {
    const secrets = scan('ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8')
    expect(secrets).toHaveLength(1)
    expect(secrets[0].rule).toBe('github-pat')
  })

  it('detects multiple secrets', () => {
    const input = [
      'OPENAI_KEY=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',
      'AWS_KEY=AKIAIOSFODNN7XYZABCD',
    ].join('\n')
    const secrets = scan(input)
    expect(secrets.length).toBeGreaterThanOrEqual(2)
  })

  it('returns empty array for no secrets', () => {
    const secrets = scan('MODE=production\nDEBUG=false\nPORT=3000')
    expect(secrets).toHaveLength(0)
  })

  it('returns empty array for empty input', () => {
    expect(scan('')).toHaveLength(0)
  })

  it('returns secrets sorted by position', () => {
    const input = 'first=AKIAIOSFODNN7XYZABCD second=ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8'
    const secrets = scan(input)
    for (let i = 1; i < secrets.length; i++) {
      expect(secrets[i].start).toBeGreaterThan(secrets[i - 1].start)
    }
  })

  it('includes start and end positions', () => {
    const key = 'ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8'
    const input = `token=${key}`
    const secrets = scan(input)
    expect(secrets.length).toBeGreaterThanOrEqual(1)
    const s = secrets[0]
    expect(input.slice(s.start, s.end)).toBe(s.text)
  })

  it('detects generic API key with high entropy', () => {
    const secrets = scan('API_KEY=a8f3k9d2m5n7p1q4r6s8t0u2v4w6x8y0z1')
    expect(secrets).toHaveLength(1)
    expect(secrets[0].rule).toBe('generic-api-key')
    expect(secrets[0].confidence).toBe('medium')
  })

  it('skips low-entropy generic values', () => {
    const secrets = scan('API_KEY=aaaaaaaaaaaaaaaaaaaaaa')
    expect(secrets).toHaveLength(0)
  })

  it('skips template variables', () => {
    const secrets = scan('API_KEY=${API_KEY}')
    expect(secrets).toHaveLength(0)
  })

  it('skips boolean/null values', () => {
    const secrets = scan('SECRET=true\nTOKEN=false\nKEY=null')
    expect(secrets).toHaveLength(0)
  })
})

describe('redact', () => {
  it('replaces secrets with custom replacer', () => {
    let id = 0
    const result = redact(
      'my key is ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8 ok',
      () => `[secret:${id++}]`
    )
    expect(result).toContain('[secret:0]')
    expect(result).not.toContain('ghp_')
  })

  it('preserves non-secret text', () => {
    const result = redact('hello world', () => '[REDACTED]')
    expect(result).toBe('hello world')
  })

  it('handles multiple secrets', () => {
    const input = 'a=AKIAIOSFODNN7XYZABCD b=ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8'
    const result = redact(input, (s) => `[${s.rule}]`)
    expect(result).not.toContain('AKIA')
    expect(result).not.toContain('ghp_')
  })

  it('passes Secret object to replacer', () => {
    const secrets: Array<{ rule: string; text: string }> = []
    redact('key=ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8', (s) => {
      secrets.push({ rule: s.rule, text: s.text })
      return '[REDACTED]'
    })
    expect(secrets.length).toBeGreaterThanOrEqual(1)
    expect(secrets[0].text).toBeTruthy()
  })
})

describe('shannonEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0)
  })

  it('returns 0 for single character repeated', () => {
    expect(shannonEntropy('aaaaaaa')).toBe(0)
  })

  it('returns 1 for two equally distributed characters', () => {
    expect(shannonEntropy('ab')).toBeCloseTo(1, 5)
  })

  it('returns higher entropy for more random strings', () => {
    const low = shannonEntropy('aaabbb')
    const high = shannonEntropy('a8f3k9d2')
    expect(high).toBeGreaterThan(low)
  })

  it('calculates correctly for known value', () => {
    // "abcd" has 4 unique chars, each with p=0.25
    // H = -4 * (0.25 * log2(0.25)) = -4 * (0.25 * -2) = 2
    expect(shannonEntropy('abcd')).toBeCloseTo(2, 5)
  })
})
