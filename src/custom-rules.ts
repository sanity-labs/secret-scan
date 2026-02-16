/**
 * Custom detection rules — NOT auto-generated.
 *
 * These supplement the TruffleHog-derived rules in rules.ts with patterns
 * for chat-specific contexts that TruffleHog doesn't cover well.
 * Biased toward over-detection: in a paste-in-chat context, a false positive
 * (user reverts a pill) is a 1-second fix; a missed secret is a security failure.
 *
 * Each rule follows the same Rule interface from rules.ts.
 *
 * TruffleHog already covers: OpenAI, Anthropic, AWS, GitHub, Stripe, Slack,
 * Groq, Replicate, Supabase, Vercel, Postgres, MongoDB, Redis, and 860+ more.
 * Only add rules here for patterns TruffleHog misses.
 */

import type { Rule } from './rules.js'

export const customRules: Rule[] = [
  // ─── Broader sk- catch-all ──────────────────────────────────────────
  // Many AI providers use sk- prefix (OpenAI, DeepSeek, Anthropic admin).
  // TruffleHog's OpenAI detector requires T3BlbkFJ marker. This catches
  // any sk-<40+ high-entropy chars> that wasn't caught by more specific
  // rules. High entropy threshold to avoid false positives.
  {
    id: 'generic-sk-secret',
    label: 'API Secret Key (sk-)',
    regex: new RegExp(
      '\\b(sk-[A-Za-z0-9_-]{40,})(?:[\\x60\'"\\s;]|\\\\[nr]|$)',
      '',
    ),
    keywords: ['sk-'],
    entropy: 4.5,
  },

  // ─── Database connection strings (broader) ─────────────────────────
  // TruffleHog has postgres/mongodb/redis detectors but they're specific.
  // This catches any protocol://user:pass@host pattern including mysql,
  // amqp, etc. Requires @ sign to indicate credentials are present.
  {
    id: 'database-connection-string',
    label: 'Database Connection String',
    regex: new RegExp(
      '\\b((?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|amqp)://[^\\s<>"{}|\\\\^`]*@[^\\s<>"{}|\\\\^`]{3,})(?:[\\s\'"\\x60]|$)',
      'i',
    ),
    keywords: ['postgres://', 'postgresql://', 'mysql://', 'mongodb://', 'mongodb+srv://', 'redis://', 'amqp://'],
  },

  // ─── Bearer tokens in paste context ────────────────────────────────
  // People paste "Authorization: Bearer <token>" or "Bearer <token>"
  {
    id: 'bearer-token',
    label: 'Bearer Token',
    regex: new RegExp(
      '(?:Authorization:\\s*)?Bearer\\s+([A-Za-z0-9_-]{20,}\\.?[A-Za-z0-9_-]*\\.?[A-Za-z0-9_-]*)(?:[\\s\'"\\x60]|$)',
      '',
    ),
    keywords: ['bearer'],
    entropy: 3.5,
  },

  // ─── Inngest signing keys ─────────────────────────────────────────
  // Format: signkey-prod-<hex> or signkey-test-<hex>
  // No TruffleHog detector exists. Distinctive prefix makes this safe.
  {
    id: 'inngest-signing-key',
    label: 'Inngest Signing Key',
    regex: new RegExp(
      '\\b(signkey-(?:prod|test|staging)-[a-f0-9]{32,})\\b',
      '',
    ),
    keywords: ['signkey-'],
  },

  // ─── Inngest event keys ───────────────────────────────────────────
  // Format varies, but commonly used with INNGEST_EVENT_KEY= context.
  // Event keys are hex strings. We detect them when the env var name
  // provides context.
  {
    id: 'inngest-event-key',
    label: 'Inngest Event Key',
    regex: new RegExp(
      '(?:INNGEST_EVENT_KEY\\s*[=:]\\s*)["\']?([a-f0-9A-F]{16,})["\']?',
      '',
    ),
    keywords: ['inngest_event_key'],
  },

  // ─── ElevenLabs bare sk_ keys ─────────────────────────────────────
  // TruffleHog's elevenlabs-v2 rule matches sk_ + 48 hex chars but
  // requires "elevenlabs" keyword in the input. This catches bare paste
  // of sk_ + 48 hex chars without context. The sk_ prefix + hex-only
  // suffix is distinctive enough.
  {
    id: 'elevenlabs-bare',
    label: 'ElevenLabs API Key',
    regex: new RegExp(
      '\\b(sk_[a-f0-9]{48})\\b',
      '',
    ),
    keywords: ['sk_'],
  },

  // ─── Sanity bare tokens ───────────────────────────────────────────
  // TruffleHog's sanity rule matches sk + 79 alphanumeric chars but
  // requires "sanity" keyword in the input. Sanity tokens start with
  // sk followed by a capital letter (skE..., skR..., skS...) which
  // distinguishes them from other sk-prefixed keys. Real tokens are
  // ~80 chars total (sk + 78). Entropy threshold prevents false positives.
  {
    id: 'sanity-bare',
    label: 'Sanity API Token',
    regex: new RegExp(
      '\\b(sk[A-Z][A-Za-z0-9]{58,})\\b',
      '',
    ),
    keywords: ['sk'],
    entropy: 4.0,
  },
]
