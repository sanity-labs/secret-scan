/**
 * Tests for custom detection rules (src/custom-rules.ts).
 *
 * These rules supplement TruffleHog with patterns for chat-specific contexts.
 * Biased toward over-detection: false positives are a 1-second revert,
 * missed secrets are a security failure.
 */

import { describe, it, expect } from 'vitest'
import { scan, shannonEntropy } from '../src/index.js'

function randomChars(n: number, charset?: string): string {
  const chars = charset || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let result = ''
  for (let i = 0; i < n; i++) result += chars[Math.floor(Math.random() * chars.length)]
  return result
}

// ─── Generic sk- catch-all ──────────────────────────────────────────────

describe('generic-sk-secret', () => {
  it('detects long sk- keys with high entropy', () => {
    const key = 'sk-' + randomChars(50)
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    // Could be caught by openai, anthropic, or generic-sk-secret
    expect(results[0].text).toContain('sk-')
  })

  it('does not detect short sk- strings', () => {
    const results = scan('sk-project-name')
    expect(results).toHaveLength(0)
  })

  it('does not detect low-entropy sk- strings', () => {
    // Repeated pattern = low entropy
    const results = scan('sk-' + 'abcabc'.repeat(10))
    // May or may not match depending on entropy threshold
    if (results.length > 0) {
      const entropy = shannonEntropy(results[0].text)
      expect(entropy).toBeGreaterThan(3)
    }
  })
})

// ─── Database connection strings ────────────────────────────────────────

describe('database-connection-string', () => {
  it('detects postgres:// with credentials', () => {
    const results = scan('postgres://admin:s3cretP4ss@db.example.com:5432/mydb')
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/postgres|database/)
  })

  it('detects mysql:// with credentials', () => {
    const results = scan('mysql://root:password@mysql.example.com:3306/mydb')
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/mysql|database/)
  })

  it('detects mongodb+srv:// with credentials', () => {
    const results = scan('mongodb+srv://user:pass@cluster0.abc123.mongodb.net/mydb')
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/mongodb|database/)
  })

  it('detects redis:// with credentials', () => {
    const results = scan('redis://default:mypassword@redis-12345.c1.us-east-1-2.ec2.cloud.redislabs.com:12345')
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/redis|database/)
  })

  it('detects amqp:// with credentials', () => {
    const results = scan('amqp://user:pass@rabbitmq.example.com:5672/vhost')
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/amqp|rabbitmq|database/)
  })
})

// ─── Bearer tokens ──────────────────────────────────────────────────────

describe('bearer-token', () => {
  it('detects "Bearer <token>"', () => {
    const token = randomChars(40)
    const results = scan(`Bearer ${token}`)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('bearer-token')
  })

  it('detects "Authorization: Bearer <token>"', () => {
    const token = randomChars(40)
    const results = scan(`Authorization: Bearer ${token}`)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('bearer-token')
  })

  it('detects Bearer with JWT', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789'
    const results = scan(`Bearer ${jwt}`)
    expect(results.length).toBeGreaterThan(0)
    // Could be caught by jwt or bearer-token
  })

  it('does not detect "Bearer" alone', () => {
    const results = scan('Bearer')
    expect(results).toHaveLength(0)
  })

  it('does not detect "Bearer <short>"', () => {
    const results = scan('Bearer abc')
    expect(results).toHaveLength(0)
  })
})
