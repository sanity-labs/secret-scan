import { describe, it, expect } from 'vitest'
import { scan, redact, shannonEntropy } from '../src/index'

describe('scan', () => {
  it('detects OpenAI API key', () => {
    const input = 'OPENAI_API_KEY=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'
    const secrets = scan(input)
    expect(secrets).toHaveLength(1)
    expect(secrets[0].rule).toBe('openai')
    expect(secrets[0].confidence).toBe('high')
  })

  it('detects AWS access key', () => {
    const secrets = scan('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7XYZABCD')
    expect(secrets).toHaveLength(1)
    expect(secrets[0].rule).toBe('aws-access_keys')
    expect(secrets[0].text).toBe('AKIAIOSFODNN7XYZABCD')
  })

  it('detects Stripe access token', () => {
    const secrets = scan('sk_live_abc123def456ghi789jkl012mno345pqr678')
    expect(secrets.length).toBeGreaterThanOrEqual(1)
    expect(secrets[0].rule).toBe('stripe')
  })

  it('returns empty array for no secrets', () => {
    expect(scan('hello world')).toHaveLength(0)
    expect(scan('')).toHaveLength(0)
  })

  it('returns correct start/end positions', () => {
    const prefix = 'key is '
    const key = 'AKIAIOSFODNN7XYZABCD'
    const secrets = scan(prefix + key)
    expect(secrets).toHaveLength(1)
    expect(secrets[0].start).toBe(prefix.length)
    expect(secrets[0].end).toBe(prefix.length + key.length)
  })

  it('detects multiple secrets in one input', () => {
    const input = 'AKIAIOSFODNN7XYZABCD and xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx'
    const secrets = scan(input)
    expect(secrets.length).toBeGreaterThanOrEqual(2)
  })

  it('does not overlap detections', () => {
    const input = 'sk_live_abc123def456ghi789jkl012mno345pqr678'
    const secrets = scan(input)
    // Should not have overlapping ranges
    for (let i = 1; i < secrets.length; i++) {
      expect(secrets[i].start).toBeGreaterThanOrEqual(secrets[i - 1].end)
    }
  })
})

describe('redact', () => {
  it('replaces detected secrets', () => {
    const input = 'key=AKIAIOSFODNN7XYZABCD'
    const result = redact(input, () => '[REDACTED]')
    expect(result).toBe('key=[REDACTED]')
    expect(result).not.toContain('AKIAIOSFODNN7XYZABCD')
  })

  it('preserves non-secret text', () => {
    const result = redact('hello world', () => '[REDACTED]')
    expect(result).toBe('hello world')
  })

  it('handles multiple secrets', () => {
    const input = 'AKIAIOSFODNN7XYZABCD and xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx'
    const result = redact(input, (s, i) => `[secret:${i}]`)
    expect(result).not.toContain('AKIAIOSFODNN7XYZABCD')
    expect(result).not.toContain('xoxb-')
  })

  it('calls replacer with Secret object', () => {
    const input = 'AKIAIOSFODNN7XYZABCD'
    redact(input, (secret) => {
      expect(secret.rule).toBe('aws-access_keys')
      expect(secret.text).toBe('AKIAIOSFODNN7XYZABCD')
      expect(secret.start).toBe(0)
      expect(secret.end).toBe(20)
      return '[REDACTED]'
    })
  })
})

describe('shannonEntropy', () => {
  it('returns 0 for empty string', () => {
    expect(shannonEntropy('')).toBe(0)
  })

  it('returns 0 for single char', () => {
    expect(shannonEntropy('aaaa')).toBe(0)
  })

  it('returns higher entropy for random strings', () => {
    const low = shannonEntropy('aaaa')
    const high = shannonEntropy('a8f3k9d2m5n7p1q4')
    expect(high).toBeGreaterThan(low)
  })

  it('returns ~4.7 for alphanumeric random', () => {
    const entropy = shannonEntropy('a8f3k9d2m5n7p1q4r6s8t0u2v4w6x8y0z1')
    expect(entropy).toBeGreaterThan(4)
    expect(entropy).toBeLessThan(6)
  })
})
