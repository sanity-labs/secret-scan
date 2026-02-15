/**
 * Fetches gitleaks.toml from GitHub and generates src/rules.ts
 *
 * Usage: npx tsx scripts/update-rules.ts [--local]
 *
 * Go regex → JS regex conversions:
 * - (?P<name>...) → (?<name>...)  (named groups)
 * - (?i) at start → RegExp 'i' flag
 * - (?i:...) mid-pattern → (?:...) + 'i' flag on whole regex
 * - (?-i:...) → (?:...)  (JS can't do inline flag toggles)
 * - (?s:.) → [\s\S]  (dotall group)
 * - \z → $  (end of string)
 *
 * Note on inline flags: JS (Node <22) doesn't support (?i:...) or (?-i:...).
 * We promote any (?i:...) to a global 'i' flag and strip (?-i:...) to (?:...).
 * The (?-i:...) groups in gitleaks already enumerate their cases explicitly
 * (e.g. (?-i:ETSY|[Ee]tsy)), so this is safe for all current rules.
 */

import { parse as parseToml } from '@iarna/toml'
import { writeFileSync, readFileSync, existsSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const GITLEAKS_TOML_URL =
  'https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml'

// --- Types for parsed TOML ---

interface TomlAllowlist {
  description?: string
  condition?: string
  regexTarget?: string
  regexes?: string[]
  paths?: string[]
  stopwords?: string[]
}

interface TomlRule {
  id: string
  description: string
  regex?: string
  path?: string
  entropy?: number
  secretGroup?: number
  keywords?: string[]
  allowlists?: TomlAllowlist[]
}

interface TomlConfig {
  title: string
  allowlist?: TomlAllowlist
  rules: TomlRule[]
}

// --- Go regex → JS regex conversion ---

function convertGoRegex(goRegex: string): { pattern: string; flags: string } {
  let pattern = goRegex
  let flags = ''

  // 1. Handle (?i) at the start — convert to 'i' flag
  if (pattern.startsWith('(?i)')) {
    flags = 'i'
    pattern = pattern.slice(4)
  }

  // 2. Handle (?i) or (?i:...) anywhere in the pattern
  //    Promote to global 'i' flag and strip the inline modifier
  if (pattern.includes('(?i)')) {
    flags = 'i'
    pattern = pattern.replace(/\(\?i\)/g, '')
  }
  if (pattern.includes('(?i:')) {
    flags = 'i'
    pattern = pattern.replace(/\(\?i:/g, '(?:')
  }

  // 3. Convert (?-i:...) to (?:...)
  pattern = pattern.replace(/\(\?-i:/g, '(?:')

  // 4. Convert (?s:.) to [\s\S] — dotall group
  //    (?s:.) means "dot matches newlines" in Go
  pattern = pattern.replace(/\(\?s:\.\)/g, '[\\s\\S]')
  // Also handle (?s:...) wrapping more complex content — rare but possible
  // For the kubernetes rule: (?s:.){0,200}? → [\s\S]{0,200}?
  pattern = pattern.replace(/\(\?s:([^)]*)\)/g, (_match, inner) => {
    // Replace . with [\s\S] inside the group
    return inner.replace(/\./g, '[\\s\\S]')
  })

  // 5. Convert (?P<name>...) to (?<name>...) — Go named groups
  pattern = pattern.replace(/\(\?P</g, '(?<')

  // 6. Convert \z to $ — end of string
  pattern = pattern.replace(/\\z/g, '$')

  return { pattern, flags }
}

// --- Label generation ---

const ACRONYMS = new Set([
  'API', 'AWS', 'GCP', 'SSH', 'JWT', 'NPM', 'URL', 'URI', 'IP', 'FTP',
  'HTTP', 'HTTPS', 'SSL', 'TLS', 'DNS', 'MFA', 'OTP', 'PAT', 'SAS',
  'IAM', 'LDAP', 'SMTP', 'IMAP', 'POP', 'SQL', 'DB', 'CI', 'CD', 'CLI',
  'SDK', 'IDE', 'ID', 'UUID', 'HMAC', 'RSA', 'DSA', 'PGP', 'GPG', 'AES',
  'DES', 'MD5', 'SHA', 'OAUTH', 'OIDC', 'SAML', 'SSO', 'MCP', 'NLP',
  'AI', 'ML', 'PKCS', 'PEM', 'YAML', 'JSON', 'XML', 'CSV', 'TOML',
])

function generateLabel(id: string): string {
  return id
    .split('-')
    .map((word) => {
      const upper = word.toUpperCase()
      if (ACRONYMS.has(upper)) return upper
      return word.charAt(0).toUpperCase() + word.slice(1)
    })
    .join(' ')
}

// --- Validate regex compiles in JS ---

function tryCompileRegex(pattern: string, flags: string, ruleId: string): boolean {
  try {
    new RegExp(pattern, flags)
    return true
  } catch (e) {
    console.warn(`⚠ Rule "${ruleId}": regex failed to compile: ${(e as Error).message}`)
    console.warn(`  Pattern: ${pattern.slice(0, 120)}...`)
    return false
  }
}

// --- Escape for generated code ---

function escapeForSingleQuote(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")
}

// --- Main ---

async function main() {
  // Fetch or read gitleaks.toml
  let tomlContent: string

  const localPath = resolve(__dirname, '..', 'gitleaks.toml')
  if (process.argv.includes('--local') && existsSync(localPath)) {
    console.log('Reading local gitleaks.toml...')
    tomlContent = readFileSync(localPath, 'utf-8')
  } else {
    console.log(`Fetching ${GITLEAKS_TOML_URL}...`)
    const response = await fetch(GITLEAKS_TOML_URL)
    if (!response.ok) {
      throw new Error(`Failed to fetch: ${response.status} ${response.statusText}`)
    }
    tomlContent = await response.text()
    writeFileSync(localPath, tomlContent)
    console.log(`Saved to ${localPath}`)
  }

  // Parse TOML
  const config = parseToml(tomlContent) as unknown as TomlConfig
  console.log(`Parsed ${config.rules.length} rules`)

  // Process global allowlist
  const globalAllowlist = config.allowlist
  const globalRegexes: Array<{ pattern: string; flags: string }> = []
  const globalStopwords: string[] = []

  if (globalAllowlist) {
    for (const regex of globalAllowlist.regexes ?? []) {
      const converted = convertGoRegex(regex)
      if (tryCompileRegex(converted.pattern, converted.flags, 'global-allowlist')) {
        globalRegexes.push(converted)
      }
    }
    globalStopwords.push(...(globalAllowlist.stopwords ?? []))
  }

  // Process rules
  let compiled = 0
  let skipped = 0
  const skippedRules: string[] = []
  const rules: string[] = []

  for (const rule of config.rules) {
    // Skip rules without regex (path-only rules like pkcs12-file)
    if (!rule.regex) {
      console.log(`⏭ Rule "${rule.id}": path-only rule, skipping`)
      skipped++
      skippedRules.push(rule.id)
      continue
    }

    const { pattern, flags } = convertGoRegex(rule.regex)

    if (!tryCompileRegex(pattern, flags, rule.id)) {
      skipped++
      skippedRules.push(rule.id)
      continue
    }

    // Process rule-specific allowlists
    const ruleAllowlistRegexes: Array<{ pattern: string; flags: string; target?: string }> = []
    const ruleStopwords: string[] = []

    for (const al of rule.allowlists ?? []) {
      // Skip path-only allowlists
      if (al.paths && !al.regexes && !al.stopwords) continue

      const target = al.regexTarget ?? 'match'

      for (const regex of al.regexes ?? []) {
        const converted = convertGoRegex(regex)
        if (tryCompileRegex(converted.pattern, converted.flags, `${rule.id}-allowlist`)) {
          ruleAllowlistRegexes.push({ ...converted, target })
        }
      }

      ruleStopwords.push(...(al.stopwords ?? []))
    }

    // Build rule object as code string
    const label = generateLabel(rule.id)
    const keywords = (rule.keywords ?? []).map((k) => k.toLowerCase())

    let ruleStr = `  {\n`
    ruleStr += `    id: '${escapeForSingleQuote(rule.id)}',\n`
    ruleStr += `    label: '${escapeForSingleQuote(label)}',\n`
    ruleStr += `    regex: new RegExp(${JSON.stringify(pattern)}, '${flags}'),\n`
    ruleStr += `    keywords: [${keywords.map((k) => `'${escapeForSingleQuote(k)}'`).join(', ')}],\n`

    if (rule.entropy !== undefined) {
      ruleStr += `    entropy: ${rule.entropy},\n`
    }

    if (rule.secretGroup !== undefined) {
      ruleStr += `    secretGroup: ${rule.secretGroup},\n`
    }

    if (ruleAllowlistRegexes.length > 0 || ruleStopwords.length > 0) {
      ruleStr += `    allowlist: {\n`

      if (ruleAllowlistRegexes.length > 0) {
        ruleStr += `      regexes: [\n`
        for (const r of ruleAllowlistRegexes) {
          const targetStr = r.target && r.target !== 'match' ? `, target: '${r.target}' as const` : ''
          ruleStr += `        { regex: new RegExp(${JSON.stringify(r.pattern)}, '${r.flags}')${targetStr} },\n`
        }
        ruleStr += `      ],\n`
      }

      if (ruleStopwords.length > 0) {
        ruleStr += `      stopwords: [\n`
        // Write stopwords in batches for readability
        for (let i = 0; i < ruleStopwords.length; i += 10) {
          const batch = ruleStopwords.slice(i, i + 10)
          ruleStr += `        ${batch.map((s) => `'${escapeForSingleQuote(s)}'`).join(', ')},\n`
        }
        ruleStr += `      ],\n`
      }

      ruleStr += `    },\n`
    }

    ruleStr += `  }`
    rules.push(ruleStr)
    compiled++
  }

  // Generate output file
  const output = `// Auto-generated by scripts/update-rules.ts — DO NOT EDIT
// Source: ${GITLEAKS_TOML_URL}
// Generated: ${new Date().toISOString()}
// Rules: ${compiled} compiled, ${skipped} skipped (${skippedRules.join(', ')})

export interface AllowlistRegex {
  regex: RegExp
  target?: 'match' | 'line'
}

export interface RuleAllowlist {
  regexes?: AllowlistRegex[]
  stopwords?: string[]
}

export interface Rule {
  id: string
  label: string
  regex: RegExp
  keywords: string[]
  entropy?: number
  secretGroup?: number
  allowlist?: RuleAllowlist
}

export interface GlobalAllowlist {
  regexes: AllowlistRegex[]
  stopwords: string[]
}

export const globalAllowlist: GlobalAllowlist = {
  regexes: [
${globalRegexes.map((r) => `    { regex: new RegExp(${JSON.stringify(r.pattern)}, '${r.flags}') },`).join('\n')}
  ],
  stopwords: [
${globalStopwords.map((s) => `    '${escapeForSingleQuote(s)}',`).join('\n')}
  ],
}

export const rules: Rule[] = [
${rules.join(',\n')}
]
`

  const outPath = resolve(__dirname, '..', 'src', 'rules.ts')
  writeFileSync(outPath, output)
  console.log(`\nWrote ${outPath}`)
  console.log(`  ${compiled} rules compiled`)
  console.log(`  ${skipped} rules skipped: ${skippedRules.join(', ')}`)
  console.log(`  ${globalRegexes.length} global allowlist regexes`)
  console.log(`  ${globalStopwords.length} global stopwords`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
