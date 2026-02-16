/**
 * Realistic chat integration tests.
 *
 * Each test simulates a real chat message that a user might paste.
 * These are the ground truth for the scanner — if these fail, the
 * scanner is broken for real-world use.
 *
 * Focus areas:
 * 1. Multi-secret messages (overlap resolution)
 * 2. Secrets embedded in realistic context (env files, curl, code)
 * 3. Edge cases (adjacent secrets, secrets in URLs, mixed providers)
 * 4. False positive resistance (code that looks like secrets but isn't)
 *
 * Provider coverage based on real-world usage:
 * Inngest, OpenAI, Anthropic, Groq, ElevenLabs, Daytona, AWS,
 * Sanity, Fly.io, Postgres, GitHub, Stripe, Slack
 */

import { describe, it, expect } from 'vitest'
import { scan, redact } from '../src/index.js'

// Helpers for generating realistic-length test keys
const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const hex = '0123456789abcdef'
const fill = (n: number, charset = alpha) =>
  Array.from({ length: n }, (_, i) => charset[i % charset.length]).join('')

// Realistic fake keys — correct format per provider docs
const KEYS = {
  // OpenAI: sk-proj-<var>T3BlbkFJ<var> (T3BlbkFJ = base64 of "OpenAI")
  openai: `sk-proj-${fill(20)}T3BlbkFJ${fill(20)}`,
  // Anthropic: sk-ant-api03-<93 word chars>AA
  anthropic: `sk-ant-api03-${fill(93)}AA`,
  // GitHub: ghp_ + 36+ alphanumeric
  github: `ghp_${fill(36)}`,
  githubFineGrained: `github_pat_${fill(82)}`,
  // Stripe: sk_live_ + 24 alphanumeric
  stripe: `sk_live_${fill(24)}`,
  // AWS: AKIA + 16 uppercase
  aws: 'AKIAIOSFODNN7EXAMPLE',
  // Slack: xoxb-<numbers>-<numbers>-<alphanumeric>
  slack: 'xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx',
  // Groq: gsk_ + exactly 52 alphanumeric
  groq: `gsk_${fill(52)}`,
  // Replicate: r8_ + 37 alphanumeric
  replicate: `r8_${fill(37)}`,
  // SendGrid: SG.<22>.<43>
  sendgrid: `SG.${fill(22)}.${fill(43)}`,
  // Supabase: sbp_ + 40 hex
  supabase: `sbp_${fill(40, hex)}`,
  // Linear: lin_api_ + 40 alphanumeric
  linear: `lin_api_${fill(40)}`,
  // NPM: npm_ + 36 alphanumeric
  npm: `npm_${fill(36)}`,
  // GitLab: glpat- + 20 alphanumeric
  gitlab: `glpat-${fill(20)}`,
  // Postgres connection string
  postgres: 'postgres://admin:s3cretP4ss@db.example.com:5432/mydb',
  // Redis connection string
  redis: 'redis://default:mypassword@redis-12345.c1.us-east-1-2.ec2.cloud.redislabs.com:12345',
  // MongoDB connection string
  mongodb: 'mongodb+srv://user:password123@cluster0.abc123.mongodb.net/mydb',
  // JWT (Supabase anon/service_role keys are JWTs)
  jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  // Inngest signing key: signkey-prod-<hex>
  inngest: `signkey-prod-${fill(64, hex)}`,
  // ElevenLabs: sk_ + 48 hex chars
  elevenlabs: `sk_${fill(48, hex)}`,
  // Sanity: sk + capital letter + 78+ alphanumeric
  sanity: `skE5UXUmBEy7U50jcG4In4v4xoHZTlduDxQYet8Y84tsTqAZxp2reIPJsA1JzqXJno2qcpauGwPfjHpU`,
  // Fly.io: FlyV1 fm2_ + 500-700 base64
  fly: `FlyV1 fm2_${fill(550)}`,
}

// ─── Multi-secret messages ──────────────────────────────────────────

describe('multi-secret messages', () => {
  it('chat 1: full-stack .env with AI + infra keys', () => {
    const input = `here's the .env for the new project:

OPENAI_API_KEY=${KEYS.openai}
ANTHROPIC_API_KEY=${KEYS.anthropic}
GROQ_API_KEY=${KEYS.groq}
INNGEST_SIGNING_KEY=${KEYS.inngest}
ELEVENLABS_API_KEY=${KEYS.elevenlabs}
GITHUB_TOKEN=${KEYS.github}
DATABASE_URL=${KEYS.postgres}
SANITY_TOKEN=${KEYS.sanity}
AWS_ACCESS_KEY_ID=${KEYS.aws}
NODE_ENV=production
PORT=3000`

    const results = scan(input)
    const rules = results.map(r => r.rule)

    // Should find all 9 secrets (NODE_ENV and PORT are not secrets)
    expect(results.length).toBe(9)
    expect(rules).toContain('openai')
    expect(rules).toContain('anthropic')
    expect(rules).toContain('groq')
    expect(rules).toContain('inngest-signing-key')
    expect(rules.some(r => r.includes('elevenlabs'))).toBe(true)
    expect(rules).toContain('github-v2')
    expect(rules.some(r => r.includes('database') || r.includes('postgres'))).toBe(true)
    expect(rules.some(r => r.includes('sanity'))).toBe(true)
    expect(rules).toContain('aws-access_keys')

    // Each secret should be the full key, not a substring
    const openai = results.find(r => r.rule === 'openai')!
    expect(openai.text).toBe(KEYS.openai)
  })

  it('chat 2: sharing database credentials for a project', () => {
    const input = `@team here are the staging credentials:

Database: ${KEYS.postgres}
Cache: ${KEYS.redis}
Mongo: ${KEYS.mongodb}

Don't commit these to git!`

    const results = scan(input)
    expect(results.length).toBeGreaterThanOrEqual(3)

    // Each connection string should be detected as a complete unit
    for (const result of results) {
      expect(result.text.length).toBeGreaterThan(20)
    }
  })

  it('chat 3: curl commands with multiple auth headers', () => {
    const input = `# Test the GitHub API
curl -H "Authorization: Bearer ${KEYS.github}" https://api.github.com/user

# Then test Stripe
curl https://api.stripe.com/v1/charges \\
  -u ${KEYS.stripe}:`

    const results = scan(input)
    expect(results.length).toBeGreaterThanOrEqual(2)

    const ghResult = results.find(r => r.text.includes('ghp_'))
    expect(ghResult).toBeDefined()
    expect(ghResult!.text).toBe(KEYS.github)
  })

  it('chat 4: code snippet with multiple API clients', () => {
    const input = `\`\`\`typescript
const openai = new OpenAI({ apiKey: "${KEYS.openai}" })
const anthropic = new Anthropic({ apiKey: "${KEYS.anthropic}" })
const stripe = new Stripe("${KEYS.stripe}")
\`\`\``

    const results = scan(input)
    expect(results.length).toBe(3)
    expect(results.find(r => r.rule === 'openai')!.text).toBe(KEYS.openai)
    expect(results.find(r => r.rule === 'anthropic')!.text).toBe(KEYS.anthropic)
    expect(results.find(r => r.rule === 'stripe')!.text).toBe(KEYS.stripe)
  })

  it('chat 5: docker-compose.yml paste with mixed secrets', () => {
    const input = `version: '3.8'
services:
  api:
    environment:
      - DATABASE_URL=${KEYS.postgres}
      - REDIS_URL=${KEYS.redis}
      - OPENAI_API_KEY=${KEYS.openai}
      - GITHUB_TOKEN=${KEYS.github}
      - SENDGRID_API_KEY=${KEYS.sendgrid}
  worker:
    environment:
      - DATABASE_URL=${KEYS.postgres}
      - SLACK_BOT_TOKEN=${KEYS.slack}`

    const results = scan(input)
    const uniqueTexts = new Set(results.map(r => r.text))
    expect(uniqueTexts.size).toBeGreaterThanOrEqual(6)
  })

  it('chat 6: Vercel/deployment config with JWT and API keys', () => {
    const input = `I need help debugging my Vercel deployment. Here's my config:

SUPABASE_URL=https://abc123.supabase.co
SUPABASE_SERVICE_ROLE_KEY=${KEYS.jwt}
LINEAR_API_KEY=${KEYS.linear}
NPM_TOKEN=${KEYS.npm}

The deploy keeps failing with a 500 error.`

    const results = scan(input)
    expect(results.length).toBeGreaterThanOrEqual(3)

    const rules = results.map(r => r.rule)
    expect(rules).toContain('jwt')
    expect(rules).toContain('linearapi')
    expect(rules).toContain('npmtokenv2')
  })

  it('chat 7: CI/CD pipeline config with GitLab + AWS', () => {
    const input = `Our GitLab CI needs these variables:

GITLAB_TOKEN=${KEYS.gitlab}
AWS_ACCESS_KEY_ID=${KEYS.aws}
GROQ_API_KEY=${KEYS.groq}
REPLICATE_API_TOKEN=${KEYS.replicate}

Can someone add these to the CI settings?`

    const results = scan(input)
    expect(results.length).toBeGreaterThanOrEqual(4)

    const rules = results.map(r => r.rule)
    expect(rules.some(r => r.includes('gitlab'))).toBe(true)
    expect(rules).toContain('aws-access_keys')
    expect(rules).toContain('groq')
    expect(rules).toContain('replicate')
  })

  it('chat 8: Inngest + ElevenLabs + Fly deployment', () => {
    const input = `Setting up the new voice pipeline:

INNGEST_SIGNING_KEY=${KEYS.inngest}
ELEVENLABS_API_KEY=${KEYS.elevenlabs}
FLY_API_TOKEN=${KEYS.fly}
DATABASE_URL=${KEYS.postgres}

Deploy with: fly deploy --app voice-pipeline`

    const results = scan(input)
    expect(results.length).toBeGreaterThanOrEqual(4)

    const rules = results.map(r => r.rule)
    expect(rules).toContain('inngest-signing-key')
    expect(rules.some(r => r.includes('elevenlabs'))).toBe(true)
    expect(rules).toContain('flyio')
    expect(rules.some(r => r.includes('database') || r.includes('postgres'))).toBe(true)
  })
})

// ─── Overlap resolution ─────────────────────────────────────────────

describe('overlap resolution — longest match wins', () => {
  it('chat 9: GitHub PAT in Bearer header — should prefer full token', () => {
    const input = `Authorization: Bearer ${KEYS.github}`
    const results = scan(input)

    const ghResult = results.find(r => r.text.includes('ghp_'))
    expect(ghResult).toBeDefined()
    expect(ghResult!.text).toBe(KEYS.github)
  })

  it('chat 10: OpenAI key should not be split by generic sk- rule', () => {
    const input = `my key is ${KEYS.openai}`
    const results = scan(input)

    expect(results.length).toBe(1)
    expect(results[0].rule).toBe('openai')
    expect(results[0].text).toBe(KEYS.openai)
  })

  it('chat 11: Anthropic key should not be split by generic sk- rule', () => {
    const input = `ANTHROPIC_API_KEY=${KEYS.anthropic}`
    const results = scan(input)

    expect(results.length).toBe(1)
    expect(results[0].rule).toBe('anthropic')
    expect(results[0].text).toBe(KEYS.anthropic)
  })

  it('chat 12: JWT should not have fragments detected separately', () => {
    const input = `SUPABASE_ANON_KEY=${KEYS.jwt}`
    const results = scan(input)

    const jwtResult = results.find(r => r.rule === 'jwt')
    expect(jwtResult).toBeDefined()
    expect(jwtResult!.text).toBe(KEYS.jwt)

    // No other match should overlap with the JWT
    const nonJwtResults = results.filter(r => r.rule !== 'jwt')
    for (const r of nonJwtResults) {
      expect(r.start >= jwtResult!.end || r.end <= jwtResult!.start).toBe(true)
    }
  })

  it('chat 13: connection string should detect full URL, not fragments', () => {
    const input = KEYS.postgres
    const results = scan(input)

    expect(results.length).toBeGreaterThanOrEqual(1)
    const longest = results.reduce((a, b) => a.text.length > b.text.length ? a : b)
    expect(longest.text.length).toBeGreaterThan(30)
  })

  it('chat 14: adjacent secrets on same line should both be detected', () => {
    const input = `keys: ${KEYS.github} ${KEYS.stripe}`
    const results = scan(input)

    expect(results.length).toBe(2)
    expect(results.find(r => r.rule === 'github-v2')).toBeDefined()
    expect(results.find(r => r.rule === 'stripe')).toBeDefined()
  })

  it('chat 15: ElevenLabs sk_ should not be swallowed by generic sk- rule', () => {
    // sk_ is different from sk- — ElevenLabs uses underscore
    const input = `ELEVENLABS_API_KEY=${KEYS.elevenlabs}`
    const results = scan(input)

    expect(results.length).toBe(1)
    expect(results[0].text).toBe(KEYS.elevenlabs)
  })
})

// ─── Bare paste detection ───────────────────────────────────────────

describe('bare paste — no surrounding context', () => {
  it('chat 16: bare Inngest signing key', () => {
    const results = scan(KEYS.inngest)
    expect(results.length).toBe(1)
    expect(results[0].rule).toBe('inngest-signing-key')
  })

  it('chat 17: bare ElevenLabs key', () => {
    const results = scan(KEYS.elevenlabs)
    expect(results.length).toBe(1)
    expect(results[0].rule).toBe('elevenlabs-bare')
  })

  it('chat 18: bare Sanity token', () => {
    const results = scan(KEYS.sanity)
    expect(results.length).toBeGreaterThanOrEqual(1)
    expect(results[0].text).toBe(KEYS.sanity)
  })

  it('chat 19: bare Fly.io token', () => {
    const results = scan(KEYS.fly)
    expect(results.length).toBe(1)
    expect(results[0].rule).toBe('flyio')
  })

  it('chat 20: bare Groq key', () => {
    const results = scan(KEYS.groq)
    expect(results.length).toBe(1)
    expect(results[0].rule).toBe('groq')
  })

  it('chat 21: bare GitHub PAT', () => {
    const results = scan(KEYS.github)
    expect(results.length).toBe(1)
    expect(results[0].rule).toBe('github-v2')
  })
})

// ─── Realistic edge cases ───────────────────────────────────────────

describe('realistic edge cases', () => {
  it('chat 22: Slack message with inline code and secrets', () => {
    const input = `Hey, I updated the \`config.yml\` with the new tokens:
- Slack: \`${KEYS.slack}\`
- GitHub: \`${KEYS.github}\`
Can you verify they work?`

    const results = scan(input)
    expect(results.length).toBeGreaterThanOrEqual(2)
    expect(results.find(r => r.text.includes('xoxb-'))).toBeDefined()
    expect(results.find(r => r.text.includes('ghp_'))).toBeDefined()
  })

  it('chat 23: error log paste containing a leaked token', () => {
    const input = `Error: Request failed with status 401
  at fetchUser (/app/src/api.ts:42:11)
  Headers: { Authorization: "Bearer ${KEYS.github}" }
  Response: { "message": "Bad credentials" }
  
Please help me debug this!`

    const results = scan(input)
    expect(results.length).toBeGreaterThanOrEqual(1)
    const ghResult = results.find(r => r.text.includes('ghp_'))
    expect(ghResult).toBeDefined()
    expect(ghResult!.text).toBe(KEYS.github)
  })

  it('chat 24: Python script with AI + voice pipeline', () => {
    const input = `import openai
import anthropic
from elevenlabs import ElevenLabs

openai.api_key = "${KEYS.openai}"
client = anthropic.Anthropic(api_key="${KEYS.anthropic}")
el = ElevenLabs(api_key="${KEYS.elevenlabs}")

DATABASE_URL = "${KEYS.postgres}"`

    const results = scan(input)
    expect(results.length).toBeGreaterThanOrEqual(4)
  })

  it('chat 25: GitHub Actions workflow with secrets that leaked', () => {
    const input = `name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      GITHUB_TOKEN: ${KEYS.github}
      NPM_TOKEN: ${KEYS.npm}
      OPENAI_API_KEY: ${KEYS.openai}
      INNGEST_SIGNING_KEY: ${KEYS.inngest}
    steps:
      - uses: actions/checkout@v4
      - run: npm publish`

    const results = scan(input)
    expect(results.length).toBeGreaterThanOrEqual(4)
    const rules = results.map(r => r.rule)
    expect(rules).toContain('github-v2')
    expect(rules).toContain('npmtokenv2')
    expect(rules).toContain('openai')
    expect(rules).toContain('inngest-signing-key')
  })
})

// ─── False positive resistance ──────────────────────────────────────

describe('false positive resistance', () => {
  it('chat 26: code discussion without real secrets', () => {
    const input = `The API uses Bearer tokens for auth. You need to set OPENAI_API_KEY 
in your .env file. The format is sk-proj-<your-key-here>. 

For GitHub, use a PAT with repo scope. The token starts with ghp_ 
followed by 36 alphanumeric characters.

Database URL format: postgres://user:password@host:5432/dbname`

    const results = scan(input)
    for (const r of results) {
      expect(r.text).not.toContain('<your-key-here>')
      expect(r.text).not.toBe('ghp_')
    }
  })

  it('chat 27: documentation with placeholder values', () => {
    const input = `## Authentication

Set the following environment variables:

\`\`\`
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
STRIPE_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxxxxx
\`\`\`

Replace the x's with your actual keys.`

    const results = scan(input)
    // Strings of x's should be caught by placeholder detection
    for (const r of results) {
      expect(r.text).not.toMatch(/^[x]+$/)
      expect(r.text).not.toMatch(/^sk-x+$/)
      expect(r.text).not.toMatch(/^ghp_x+$/)
      expect(r.text).not.toMatch(/^sk_test_x+$/)
    }
  })

  it('chat 28: normal text should not trigger false positives', () => {
    const input = `I'm working on the authentication system. We need to handle 
OAuth tokens, API keys, and session management. The signing key 
rotation should happen every 90 days. Let me know if you have 
questions about the implementation.`

    expect(scan(input)).toHaveLength(0)
  })
})

// ─── Redact integration ─────────────────────────────────────────────

describe('redact with realistic messages', () => {
  it('redacts multi-secret .env paste preserving structure', () => {
    const input = `OPENAI_API_KEY=${KEYS.openai}
GITHUB_TOKEN=${KEYS.github}
INNGEST_SIGNING_KEY=${KEYS.inngest}
NODE_ENV=production`

    const result = redact(input, (s) => `[${s.rule}]`)

    expect(result).toContain('OPENAI_API_KEY=[openai]')
    expect(result).toContain('GITHUB_TOKEN=[github-v2]')
    expect(result).toContain('INNGEST_SIGNING_KEY=[inngest-signing-key]')
    expect(result).toContain('NODE_ENV=production')
    expect(result).not.toContain(KEYS.openai)
    expect(result).not.toContain(KEYS.github)
    expect(result).not.toContain(KEYS.inngest)
  })

  it('redacts secrets in curl command preserving command structure', () => {
    const input = `curl -H "Authorization: Bearer ${KEYS.github}" https://api.github.com/user`
    const result = redact(input, () => '***')

    expect(result).toContain('curl')
    expect(result).toContain('https://api.github.com/user')
    expect(result).not.toContain(KEYS.github)
  })
})
