# @sanity-labs/secret-scan

Detect and redact secrets in strings. Designed for **chat and paste contexts** where secrets appear without surrounding code context.

- **1,100+ detection rules** extracted from [TruffleHog](https://github.com/trufflesecurity/trufflehog) detectors
- **Zero runtime dependencies** — works in browser and Node.js
- **Fast** — keyword pre-filtering means most rules are skipped for any given input (~0.15ms for short messages)
- **Two functions** — `scan(input)` finds secrets, `redact(input, replacer)` replaces them

## Install

```bash
npm install @sanity-labs/secret-scan
```

## Usage

```typescript
import { scan, redact } from '@sanity-labs/secret-scan'

// Find secrets
const secrets = scan('my key is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234')
// [{ rule: 'github-v2', label: 'Github V2', text: 'ghp_...', confidence: 'high', start: 10, end: 50 }]

// Redact secrets
const safe = redact(input, (secret, index) => `[secret:${index}]`)
// 'my key is [secret:0]'
```

## What it detects

Bare paste (no surrounding context needed):

| Provider | Prefix/Pattern | Rule ID |
|----------|---------------|---------|
| OpenAI | `sk-proj-...T3BlbkFJ...` | `openai` |
| Anthropic | `sk-ant-api03-...` | `anthropic` |
| AWS | `AKIA...` | `aws-access_keys` |
| GitHub | `ghp_`, `gho_`, `github_pat_` | `github-v2` |
| Stripe | `sk_live_`, `rk_live_` | `stripe` |
| Slack | `xoxb-`, `xoxp-` | `slack` |
| Groq | `gsk_` | `groq` |
| Replicate | `r8_` | `replicate` |
| SendGrid | `SG.` | `sendgrid` |
| JWT | `eyJ...` | `jwt` |
| GitLab | `glpat-` | `gitlab-v2` |
| NPM | `npm_` | `npmtokenv2` |
| Linear | `lin_api_` | `linearapi` |
| Supabase | `sbp_` | `supabasetoken` |
| Postman | `PMAK-` | `postman` |

Plus 850+ more providers. Connection strings (postgres://, mongodb://, redis://) and Bearer tokens are also detected.

## How it works

Rules are extracted from [TruffleHog's Go detectors](https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors) and compiled to JavaScript RegExp. TruffleHog's keyword pre-filter uses strings from the **secret itself** (prefixes like `gsk_`, `T3BlbkFJ`), not surrounding context — this is why it works for bare paste in chat.

A keyword index maps each keyword to its rules. For any input, only rules whose keywords appear in the input are tested — typically <10 rules out of 1,100+.

### Updating rules

```bash
npm run update-rules
```

This clones/updates TruffleHog, parses all detector Go files, converts Go regex to JS, and regenerates `src/rules.ts`.

## API

### `scan(input: string): Secret[]`

Returns all secrets found in the input string.

```typescript
interface Secret {
  rule: string        // Rule ID (e.g., 'openai')
  label: string       // Human-readable label
  text: string        // The matched secret value
  confidence: 'high' | 'medium'
  start: number       // Start index in input
  end: number         // End index (exclusive)
}
```

### `redact(input: string, replacer: (secret: Secret) => string): string`

Finds and replaces all secrets. Replacements applied right-to-left to preserve indices.

### `shannonEntropy(s: string): number`

Calculate Shannon entropy of a string. Used internally for entropy-based filtering.

## License

MIT. Rules derived from [TruffleHog](https://github.com/trufflesecurity/trufflehog) (Apache 2.0).
