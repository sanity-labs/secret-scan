/**
 * Extracts TruffleHog detectors from Go source and generates src/rules.ts
 *
 * Usage: npx tsx scripts/update-rules.ts
 *
 * Clones/updates TruffleHog repo, parses all detector Go files, extracts
 * regex patterns and keywords, converts Go regex to JS, and generates rules.
 *
 * Go regex → JS regex conversions:
 * - (?P<name>...) → (?<name>...)  (named groups)
 * - (?i) at start or mid-pattern → RegExp 'i' flag
 * - (?i:...) inline → (?:...) + 'i' flag on whole regex
 * - (?-i:...) → (?:...)  (JS can't do inline flag toggles in Node <22)
 * - (?im), (?ims) etc → split into flags
 * - (?s:.) → [\s\S]  (dotall group)
 * - (?P<name>...) → (?<name>...)  (named groups)
 * - \z → $  (end of string)
 * - POSIX classes → JS equivalents
 *
 * TruffleHog architecture:
 * - Each detector has Keywords() (for Aho-Corasick pre-filter) and regex patterns
 * - Keywords come from the SECRET ITSELF (prefixes like gsk_, T3BlbkFJ), not context
 * - PrefixRegex detectors prepend (?i:keywords)(?:.|\n\r){0,40}? to the regex
 *   (requires provider name within 40 chars — context-dependent)
 * - For chat scanning, we include both self-contained and PrefixRegex detectors
 */

import { execSync } from 'node:child_process'
import { writeFileSync, existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { resolve, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const TRUFFLEHOG_REPO = 'https://github.com/trufflesecurity/trufflehog.git'
const TRUFFLEHOG_DIR = resolve(__dirname, '..', '.trufflehog')
const DETECTORS_DIR = join(TRUFFLEHOG_DIR, 'pkg', 'detectors')

// --- Exclusions ---

// Detectors that rely on TruffleHog's verification step (API calls to check
// if the secret is real). Without verification, these produce too many false
// positives for chat scanning. They match broad patterns like "any 32 hex chars"
// or "any 16-64 printable ASCII chars".
const EXCLUDED_DETECTORS = new Set([
  'generic',        // [\x21-\x7e]{16,64} — matches any printable ASCII string
])

// Individual regex patterns within multi-regex detectors that are too broad
// without verification. The detector itself is kept (other regexes are fine),
// but these specific patterns are dropped.
const EXCLUDED_PATTERNS = new Set([
  // AWS detector has 2 regexes: AKIA prefix (good) + bare 40-char base64 (too broad)
  '(?:[^A-Za-z0-9+/]|\\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\\z)',
  '[a-f0-9]{40}',
  // Azure Entra: *.onmicrosoft.com — matches domain names, not secrets
  '([\\w-]+\\.onmicrosoft\\.com)',
  // Accuweather: bare 32-char alphanumeric — too broad
  '\\b([a-zA-Z0-9]{32})\\b',
])

// --- Types ---

interface ExtractedDetector {
  id: string
  keywords: string[]
  regexes: string[]
  usesPrefixRegex: boolean
}

// --- Clone / update TruffleHog ---

function ensureTruffleHog(): void {
  if (existsSync(TRUFFLEHOG_DIR)) {
    console.log('Updating TruffleHog...')
    execSync('git pull --ff-only', { cwd: TRUFFLEHOG_DIR, stdio: 'pipe' })
  } else {
    console.log('Cloning TruffleHog (shallow)...')
    execSync(`git clone --depth 1 ${TRUFFLEHOG_REPO} ${TRUFFLEHOG_DIR}`, { stdio: 'pipe' })
  }
  const hash = execSync('git rev-parse --short HEAD', { cwd: TRUFFLEHOG_DIR }).toString().trim()
  console.log(`TruffleHog at ${hash}`)
}

// --- Extract detectors from Go source ---

function findGoFiles(dir: string): string[] {
  const results: string[] = []

  function walk(d: string) {
    for (const entry of readdirSync(d)) {
      const full = join(d, entry)
      const stat = statSync(full)
      if (stat.isDirectory()) {
        walk(full)
      } else if (
        entry.endsWith('.go') &&
        !entry.endsWith('_test.go') &&
        entry !== 'doc.go' &&
        entry !== 'detectors.go' &&
        entry !== 'helpers.go'
      ) {
        results.push(full)
      }
    }
  }

  walk(dir)
  return results.sort()
}

function extractDetectors(): ExtractedDetector[] {
  const goFiles = findGoFiles(DETECTORS_DIR)
  console.log(`Found ${goFiles.length} Go source files`)

  // Group files by detector directory
  const dirFiles = new Map<string, string[]>()
  for (const f of goFiles) {
    const rel = f.replace(DETECTORS_DIR + '/', '')
    const parts = rel.split('/')
    let detDir: string
    if (parts.length === 2) {
      detDir = parts[0]
    } else if (parts.length === 3) {
      detDir = `${parts[0]}/${parts[1]}`
    } else {
      continue
    }
    if (!dirFiles.has(detDir)) dirFiles.set(detDir, [])
    dirFiles.get(detDir)!.push(f)
  }

  console.log(`Found ${dirFiles.size} detector directories`)

  const detectors: ExtractedDetector[] = []

  for (const [detDir, files] of [...dirFiles.entries()].sort()) {
    // Concatenate all Go files in this detector
    let content = ''
    for (const f of files) {
      content += readFileSync(f, 'utf-8') + '\n'
    }

    if (!content.includes('MustCompile')) continue

    const id = detDir.replace(/\//g, '-')

    // Extract all backtick-delimited regex patterns from MustCompile calls
    const regexes: string[] = []
    const usesPrefixRegex = content.includes('PrefixRegex')

    for (const line of content.split('\n')) {
      if (!line.includes('MustCompile')) continue
      // Get all backtick strings on this line
      const backticks = line.match(/`([^`]+)`/g)
      if (backticks) {
        for (const b of backticks) {
          const inner = b.slice(1, -1).trim()
          if (inner) regexes.push(inner)
        }
      }
    }

    if (regexes.length === 0) continue

    // Extract keywords from Keywords() method
    const kwMatch = content.match(
      /func.*Keywords\(\).*?\{[^}]*?return\s+\[\]string\{([^}]+)\}/s
    )
    let keywords: string[] = []
    if (kwMatch) {
      keywords = [...kwMatch[1].matchAll(/"([^"]+)"/g)].map((m) => m[1])
      // Filter out long description strings (some detectors embed descriptions)
      keywords = keywords.filter((k) => k.length < 100)
    }

    detectors.push({ id, keywords, regexes, usesPrefixRegex })
  }

  return detectors
}

// --- Go regex → JS regex conversion ---

function convertGoRegex(goRegex: string): { pattern: string; flags: string } | null {
  let pattern = goRegex
  let flags = ''

  // Handle leading (?i), (?im), (?ims) etc
  const leadingFlags = pattern.match(/^\(\?([imsx]+)\)/)
  if (leadingFlags) {
    pattern = pattern.replace(/^\(\?[imsx]+\)/, '')
    if (leadingFlags[1].includes('i')) flags += 'i'
    if (leadingFlags[1].includes('m')) flags += 'm'
  }

  // (?i) anywhere else in the pattern
  if (pattern.includes('(?i)')) {
    pattern = pattern.replace(/\(\?i\)/g, '')
    if (!flags.includes('i')) flags += 'i'
  }

  // (?im) etc inside pattern
  pattern = pattern.replace(/\(\?([ims]+)\)/g, (_, f: string) => {
    if (f.includes('i') && !flags.includes('i')) flags += 'i'
    if (f.includes('m') && !flags.includes('m')) flags += 'm'
    return ''
  })

  // (?i:...) inline case-insensitive groups → promote to flag
  if (pattern.includes('(?i:')) {
    pattern = pattern.replace(/\(\?i:/g, '(?:')
    if (!flags.includes('i')) flags += 'i'
  }

  // (?-i:...) negative flags → strip (accept broader matching)
  pattern = pattern.replace(/\(\?-i:/g, '(?:')

  // (?s:.) → [\s\S] (dotall group)
  pattern = pattern.replace(/\(\?s:\.\)/g, '[\\s\\S]')
  // (?s:...) wrapping more complex content
  pattern = pattern.replace(/\(\?s:([^)]*)\)/g, (_match, inner: string) => {
    return inner.replace(/\./g, '[\\s\\S]')
  })

  // Named groups: (?P<name>) → (?<name>)
  pattern = pattern.replace(/\(\?P</g, '(?<')

  // \z → $ (end of string)
  pattern = pattern.replace(/\\z/g, '$')

  // POSIX character classes
  pattern = pattern.replace(/\[:alnum:]/g, 'a-zA-Z0-9')
  pattern = pattern.replace(/\[:alpha:]/g, 'a-zA-Z')
  pattern = pattern.replace(/\[:digit:]/g, '0-9')
  pattern = pattern.replace(/\[:lower:]/g, 'a-z')
  pattern = pattern.replace(/\[:upper:]/g, 'A-Z')
  pattern = pattern.replace(/\[:space:]/g, '\\s')

  // Validate it compiles
  try {
    new RegExp(pattern, flags)
    return { pattern, flags }
  } catch {
    return null
  }
}

// --- Label generation ---

const ACRONYMS = new Set([
  'API', 'AWS', 'GCP', 'SSH', 'JWT', 'NPM', 'URL', 'URI', 'IP', 'FTP',
  'HTTP', 'HTTPS', 'SSL', 'TLS', 'DNS', 'MFA', 'OTP', 'PAT', 'SAS',
  'IAM', 'LDAP', 'SMTP', 'IMAP', 'POP', 'SQL', 'DB', 'CI', 'CD', 'CLI',
  'SDK', 'IDE', 'ID', 'UUID', 'HMAC', 'RSA', 'DSA', 'PGP', 'GPG', 'AES',
  'DES', 'MD5', 'SHA', 'OAUTH', 'OIDC', 'SAML', 'SSO', 'MCP', 'NLP',
  'AI', 'ML', 'PKCS', 'PEM', 'YAML', 'JSON', 'XML', 'CSV', 'TOML',
  'IO', 'CRM', 'CDN',
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

// --- Escape for generated code ---

function escapeForNewRegExp(s: string): string {
  // For use inside new RegExp("...") — need to escape backslashes and quotes
  return JSON.stringify(s)
}

function escapeForSingleQuote(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")
}

// --- Main ---

async function main() {
  ensureTruffleHog()

  const detectors = extractDetectors()
  console.log(`\nExtracted ${detectors.length} detectors`)

  const selfContained = detectors.filter((d) => !d.usesPrefixRegex)
  const contextDependent = detectors.filter((d) => d.usesPrefixRegex)
  console.log(`  Self-contained (no PrefixRegex): ${selfContained.length}`)
  console.log(`  Context-dependent (PrefixRegex): ${contextDependent.length}`)
  console.log(`  Total regex patterns: ${detectors.reduce((n, d) => n + d.regexes.length, 0)}`)

  // Convert all regexes
  let compiled = 0
  let skipped = 0
  let excludedCount = 0
  const skippedIds: string[] = []
  const rules: string[] = []

  for (const detector of detectors) {
    // Skip excluded detectors entirely
    if (EXCLUDED_DETECTORS.has(detector.id)) {
      skipped++
      skippedIds.push(detector.id + ' (excluded)')
      continue
    }

    const convertedRegexes: Array<{ pattern: string; flags: string }> = []

    for (const goRegex of detector.regexes) {
      // Skip excluded patterns
      if (EXCLUDED_PATTERNS.has(goRegex)) {
        excludedCount++
        continue
      }
      const result = convertGoRegex(goRegex)
      if (result) {
        convertedRegexes.push(result)
      }
    }

    if (convertedRegexes.length === 0) {
      skipped++
      skippedIds.push(detector.id)
      continue
    }

    const label = generateLabel(detector.id)
    const keywords = detector.keywords.map((k) => k.toLowerCase())

    // Generate one rule per regex pattern (some detectors have multiple)
    for (let i = 0; i < convertedRegexes.length; i++) {
      const { pattern, flags } = convertedRegexes[i]
      const ruleId = convertedRegexes.length === 1 ? detector.id : `${detector.id}-${i + 1}`
      const ruleLabel = convertedRegexes.length === 1 ? label : `${label} (${i + 1})`

      let ruleStr = `  {\n`
      ruleStr += `    id: '${escapeForSingleQuote(ruleId)}',\n`
      ruleStr += `    label: '${escapeForSingleQuote(ruleLabel)}',\n`
      ruleStr += `    regex: new RegExp(${escapeForNewRegExp(pattern)}, '${flags}'),\n`
      ruleStr += `    keywords: [${keywords.map((k) => `'${escapeForSingleQuote(k)}'`).join(', ')}],\n`
      ruleStr += `  }`
      rules.push(ruleStr)
      compiled++
    }
  }

  // Get TruffleHog commit hash for provenance
  const hash = execSync('git rev-parse --short HEAD', { cwd: TRUFFLEHOG_DIR }).toString().trim()
  const fullHash = execSync('git rev-parse HEAD', { cwd: TRUFFLEHOG_DIR }).toString().trim()

  // Generate output file — global allowlist is static (our own code, not from TruffleHog)
  const lines: string[] = []
  lines.push(`// Auto-generated by scripts/update-rules.ts — DO NOT EDIT`)
  lines.push(`// Source: TruffleHog detectors (${TRUFFLEHOG_REPO})`)
  lines.push(`// Commit: ${fullHash}`)
  lines.push(`// Generated: ${new Date().toISOString()}`)
  lines.push(`// Detectors: ${detectors.length} extracted, ${skipped} skipped`)
  lines.push(`// Rules: ${compiled} compiled (some detectors have multiple regex patterns)`)
  lines.push(``)
  lines.push(`export interface AllowlistRegex {`)
  lines.push(`  regex: RegExp`)
  lines.push(`  target?: 'match' | 'line'`)
  lines.push(`}`)
  lines.push(``)
  lines.push(`export interface RuleAllowlist {`)
  lines.push(`  regexes?: AllowlistRegex[]`)
  lines.push(`  stopwords?: string[]`)
  lines.push(`}`)
  lines.push(``)
  lines.push(`export interface Rule {`)
  lines.push(`  id: string`)
  lines.push(`  label: string`)
  lines.push(`  regex: RegExp`)
  lines.push(`  keywords: string[]`)
  lines.push(`  entropy?: number`)
  lines.push(`  secretGroup?: number`)
  lines.push(`  allowlist?: RuleAllowlist`)
  lines.push(`}`)
  lines.push(``)
  lines.push(`export interface GlobalAllowlist {`)
  lines.push(`  regexes: AllowlistRegex[]`)
  lines.push(`  stopwords: string[]`)
  lines.push(`}`)
  lines.push(``)
  lines.push(`// Global allowlist — filter out common false positives`)
  lines.push(`export const globalAllowlist: GlobalAllowlist = {`)
  lines.push(`  regexes: [`)
  lines.push(`    { regex: /^(?:true|false|null)$/i },`)
  lines.push(`    { regex: /^(?:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$/i },`)
  lines.push(`    { regex: /^\\$(?:\\d+|{\\d+})$/ },`)
  lines.push(`    { regex: /^\\$(?:[A-Z_]+|[a-z_]+)$/ },`)
  lines.push(`    { regex: /^\\$\\{(?:[A-Z_]+|[a-z_]+)\\}$/ },`)
  lines.push(`    { regex: /^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*\\}\\}$/ },`)
  lines.push(`    { regex: /^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w "'\&.\\/=|]*)[ \\t]*\\}\\}$/ },`)
  lines.push(`    { regex: /^%(?:[A-Z_]+|[a-z_]+)%$/ },`)
  lines.push(`    { regex: /^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$/ },`)
  lines.push(`    { regex: /^\\{\\d{0,2}\\}$/ },`)
  lines.push(`    { regex: /^@(?:[A-Z_]+|[a-z_]+)@$/ },`)
  lines.push(`    { regex: /^\\/Users\\/[a-z0-9]+\\/[\\w .\\-\\/]+$/i },`)
  lines.push(`    { regex: /^\\/(?:bin|etc|home|opt|tmp|usr|var)\\/[\\w .\\/-]+$/ },`)
  lines.push(`  ],`)
  lines.push(`  stopwords: [`)
  lines.push(`    '014df517-39d1-4453-b7b3-9930c563627c',`)
  lines.push(`    'abcdefghijklmnopqrstuvwxyz',`)
  lines.push(`  ],`)
  lines.push(`}`)
  lines.push(``)
  lines.push(`export const rules: Rule[] = [`)
  lines.push(rules.join(',\n'))
  lines.push(`]`)
  lines.push(``)

  const output = lines.join('\n')

  const outPath = resolve(__dirname, '..', 'src', 'rules.ts')
  writeFileSync(outPath, output)
  console.log(`\nWrote ${outPath}`)
  console.log(`  ${compiled} rules compiled from ${detectors.length} detectors`)
  console.log(`  ${skipped} detectors skipped: ${skippedIds.join(', ')}`)
  console.log(`  ${excludedCount} individual patterns excluded (too broad without verification)`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
