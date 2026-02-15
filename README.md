# @sanity-labs/secret-scan

Detect and redact secrets in strings. Works in browser and Node.js. Zero runtime dependencies.

Rules derived from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT licensed) — 221 rules covering API keys, tokens, passwords, and credentials from 100+ providers.

## Install

```bash
npm install @sanity-labs/secret-scan
```

## Usage

### `scan` — find secrets

```typescript
import { scan } from '@sanity-labs/secret-scan'

const secrets = scan('OPENAI_API_KEY=sk-proj-abc123...\nMODE=production')
// [
//   {
//     rule: 'openai-api-key',
//     label: 'OpenAI API Key',
//     text: 'sk-proj-abc123...',
//     confidence: 'high',
//     start: 15,
//     end: 32
//   }
// ]
```

### `redact` — find and replace secrets

```typescript
import { redact } from '@sanity-labs/secret-scan'

const secrets = new Map()
let nextId = 0

const redacted = redact(pastedText, (secret) => {
  const key = `[secret:${nextId++}]`
  secrets.set(key, secret)
  return key
})

// redacted: "OPENAI_API_KEY=[secret:0]\nSTRIPE_KEY=[secret:1]"
// secrets: Map { '[secret:0]' => { text: 'sk-proj-...' }, ... }
```

## API

### `scan(input: string): Secret[]`

Returns an array of every secret found in the input.

### `redact(input: string, replacer: (secret: Secret) => string): string`

Calls `replacer` for each detected secret. The return value replaces the secret in the output string. The caller owns all state — `redact` just does string replacement.

### `Secret`

```typescript
interface Secret {
  rule: string                   // gitleaks rule ID, e.g. 'openai-api-key'
  label: string                  // human-readable, e.g. 'OpenAI API Key'
  text: string                   // the matched secret value
  confidence: 'high' | 'medium'  // provider pattern vs entropy-based
  start: number                  // start index in input
  end: number                    // end index (exclusive) in input
}
```

### `shannonEntropy(s: string): number`

Shannon entropy calculation. Exported for advanced use cases.

## How it works

1. **Keyword pre-filter** — Each rule has keywords. Before running a regex, we check if the input contains any of its keywords (case-insensitive). This keeps scanning fast with 221 rules — most regexes are skipped for any given input.

2. **Regex matching** — Rules are compiled from [gitleaks.toml](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml) with Go→JS regex conversion (named groups, inline flags, dotall).

3. **Entropy filtering** — Many rules have Shannon entropy thresholds. Low-entropy matches (like `KEY=aaaaaaa`) are filtered out.

4. **Allowlist filtering** — Global and per-rule allowlists filter false positives. Includes 1,446 stopwords for the generic-api-key rule.

## Updating rules

```bash
npm run update-rules
```

Fetches the latest `gitleaks.toml` from GitHub, converts Go regex → JS regex, and writes `src/rules.ts`. Run this whenever gitleaks updates their rules.

### Go → JS regex conversion

| Go pattern | JS equivalent | Notes |
|---|---|---|
| `(?P<name>...)` | `(?<name>...)` | Named groups |
| `(?i)` at start | `i` flag | Case-insensitive |
| `(?i:...)` mid-pattern | `(?:...)` + `i` flag | Promoted to global flag |
| `(?-i:...)` | `(?:...)` | Groups already enumerate cases |
| `(?s:.)` | `[\s\S]` | Dotall |
| `\z` | `$` | End of string |

## Rules coverage

221 rules from gitleaks covering:

- **Cloud providers**: AWS, GCP, Azure, DigitalOcean, Heroku, Fly.io, etc.
- **AI/ML**: OpenAI, Anthropic, Cohere, HuggingFace, Perplexity
- **Payment**: Stripe, Square, Plaid, Coinbase, Flutterwave
- **DevOps**: GitHub, GitLab, Bitbucket, CircleCI, Travis CI, Jenkins
- **Communication**: Slack, Discord, Telegram, Twilio, SendGrid
- **Databases**: PlanetScale, MongoDB Atlas, ClickHouse
- **And 80+ more providers**

Plus the `generic-api-key` rule which catches `KEY=value` patterns with entropy thresholds and 1,446 stopwords.

## License

MIT — includes gitleaks copyright notice per their license terms.

This package uses rules derived from [gitleaks](https://github.com/gitleaks/gitleaks), which is also MIT licensed. Copyright (c) 2019 Zachary Rice.
