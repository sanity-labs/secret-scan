/**
 * Integration tests with realistic chat messages containing secrets.
 *
 * These test the scanner against the kinds of messages users actually paste
 * in chat — bare secrets, secrets with context, multi-line pastes, etc.
 * This is the primary test suite for the chat scanning use case.
 */

import { describe, it, expect } from 'vitest'
import { scan, redact } from '../src/index.js'

// Helper to generate realistic-length test strings
const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const hex = '0123456789abcdef'
const fill = (n: number, charset = alpha) =>
  Array.from({ length: n }, (_, i) => charset[i % charset.length]).join('')

describe('bare paste — no surrounding context', () => {
  it('detects OpenAI API key with T3BlbkFJ marker', () => {
    const key = `sk-proj-${fill(20)}T3BlbkFJ${fill(20)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('openai')
  })

  it('detects GitHub PAT (ghp_)', () => {
    const key = `ghp_${fill(36)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('github-v2')
  })

  it('detects GitHub fine-grained PAT (github_pat_)', () => {
    const key = `github_pat_${fill(82)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('github-v2')
  })

  it('detects Anthropic API key', () => {
    const key = `sk-ant-api03-${fill(93)}AA`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('anthropic')
  })

  it('detects AWS access key (AKIA)', () => {
    const results = scan('AKIAIOSFODNN7EXAMPLE')
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('aws-access_keys')
  })

  it('detects Stripe live key', () => {
    const key = `sk_live_${fill(24)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('stripe')
  })

  it('detects Slack bot token', () => {
    const results = scan('xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx')
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/^slack/)
  })

  it('detects Groq API key', () => {
    const key = `gsk_${fill(52)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('groq')
  })

  it('detects Replicate API key', () => {
    const key = `r8_${fill(37)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('replicate')
  })

  it('detects SendGrid API key', () => {
    const key = `SG.${fill(22)}.${fill(43)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('sendgrid')
  })

  it('detects JWT', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
    const results = scan(jwt)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('jwt')
  })

  it('detects Supabase management token', () => {
    const key = `sbp_${fill(40, hex)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('supabasetoken')
  })

  it('detects NPM v2 token', () => {
    const key = `npm_${fill(36)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('npmtokenv2')
  })

  it('detects Linear API key', () => {
    const key = `lin_api_${fill(40)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('linearapi')
  })

  it('detects GitLab PAT (glpat-)', () => {
    const key = `glpat-${fill(20)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/gitlab/)
  })

  it('detects Postman API key', () => {
    const key = `PMAK-${fill(59)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toBe('postman')
  })

  it('detects Grafana service account token', () => {
    const key = `glsa_${fill(32)}_${fill(8, hex)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/grafana/)
  })

  it('detects Doppler token', () => {
    const key = `dp.pt.${fill(43)}`
    const results = scan(key)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/doppler/)
  })
})

describe('connection strings', () => {
  it('detects postgres:// with credentials', () => {
    const results = scan('postgres://admin:s3cretP4ss@db.example.com:5432/mydb')
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/postgres|database/)
  })

  it('detects mongodb+srv:// with credentials', () => {
    const results = scan('mongodb+srv://user:password123@cluster0.abc123.mongodb.net/mydb')
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/mongodb|database/)
  })

  it('detects redis:// with credentials', () => {
    const results = scan('redis://default:mypassword@redis-12345.c1.us-east-1-2.ec2.cloud.redislabs.com:12345')
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].rule).toMatch(/redis|database/)
  })
})

describe('secrets with surrounding chat context', () => {
  it('detects secret in "here is my key: <secret>"', () => {
    const key = `ghp_${fill(36)}`
    const results = scan(`here is my key: ${key}`)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].text).toBe(key)
  })

  it('detects secret in "OPENAI_API_KEY=<secret>"', () => {
    const key = `sk-proj-${fill(20)}T3BlbkFJ${fill(20)}`
    const results = scan(`OPENAI_API_KEY=${key}`)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].text).toBe(key)
  })

  it('detects secret in multi-line .env paste', () => {
    const input = `
DATABASE_URL=postgres://admin:s3cretP4ss@db.example.com:5432/mydb
REDIS_URL=redis://default:mypassword@redis-12345.c1.us-east-1-2.ec2.cloud.redislabs.com:12345
NODE_ENV=production
`.trim()
    const results = scan(input)
    expect(results.length).toBeGreaterThanOrEqual(2)
  })

  it('detects secret in code block', () => {
    const key = `ghp_${fill(36)}`
    const input = `\`\`\`
const token = "${key}"
\`\`\``
    const results = scan(input)
    expect(results.length).toBeGreaterThan(0)
    expect(results[0].text).toBe(key)
  })

  it('detects secret in curl command', () => {
    const key = `ghp_${fill(36)}`
    const input = `curl -H "Authorization: Bearer ${key}" https://api.github.com/user`
    const results = scan(input)
    expect(results.length).toBeGreaterThan(0)
    // Should detect either the GitHub token or the bearer token
    expect(results.some(r => r.text.includes(key.substring(0, 20)))).toBe(true)
  })
})

describe('negative tests — should NOT match', () => {
  it('does not match normal text', () => {
    expect(scan('this is just a normal message with no secrets')).toHaveLength(0)
  })

  it('does not match short sk- prefix', () => {
    expect(scan('sk-project-name')).toHaveLength(0)
  })

  it('does not match template variables', () => {
    expect(scan('${GITHUB_TOKEN}')).toHaveLength(0)
    expect(scan('$OPENAI_API_KEY')).toHaveLength(0)
    expect(scan('{{ secrets.API_KEY }}')).toHaveLength(0)
  })

  it('does not match placeholder values', () => {
    expect(scan('your-api-key-here')).toHaveLength(0)
    expect(scan('xxxxxxxxxxxxxxxxxxxx')).toHaveLength(0)
  })
})

describe('redact function', () => {
  it('replaces secrets with placeholders', () => {
    const key = `ghp_${fill(36)}`
    const input = `my token is ${key} please use it`
    const result = redact(input, (s) => `[${s.rule}]`)
    expect(result).toBe('my token is [github-v2] please use it')
    expect(result).not.toContain(key)
  })

  it('replaces multiple secrets', () => {
    const ghKey = `ghp_${fill(36)}`
    const awsKey = 'AKIAIOSFODNN7EXAMPLE'
    const input = `github: ${ghKey}\naws: ${awsKey}`
    const result = redact(input, (_, i) => `[secret:${i}]`)
    expect(result).not.toContain(ghKey)
    expect(result).not.toContain(awsKey)
  })

  it('returns input unchanged when no secrets found', () => {
    const input = 'just a normal message'
    expect(redact(input, () => '[REDACTED]')).toBe(input)
  })
})

describe('performance', () => {
  it('scans short messages quickly (<10ms)', () => {
    const input = `here is my key: ghp_${fill(36)}`
    const start = performance.now()
    for (let i = 0; i < 100; i++) {
      scan(input)
    }
    const elapsed = performance.now() - start
    const perCall = elapsed / 100
    expect(perCall).toBeLessThan(10) // <10ms per call
    console.log(`  Short message: ${perCall.toFixed(2)}ms per scan`)
  })

  it('scans long messages in reasonable time (<50ms)', () => {
    // Simulate a long paste with multiple secrets
    const lines = []
    for (let i = 0; i < 50; i++) {
      lines.push(`line ${i}: ${fill(80)}`)
    }
    lines[10] = `SECRET_KEY=ghp_${fill(36)}`
    lines[30] = `DATABASE_URL=postgres://admin:pass@db.example.com:5432/mydb`
    const input = lines.join('\n')

    const start = performance.now()
    for (let i = 0; i < 10; i++) {
      scan(input)
    }
    const elapsed = performance.now() - start
    const perCall = elapsed / 10
    expect(perCall).toBeLessThan(50) // <50ms per call
    console.log(`  Long message (${input.length} chars): ${perCall.toFixed(2)}ms per scan`)
  })
})
