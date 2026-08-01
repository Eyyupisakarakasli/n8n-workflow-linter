import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const projectRoot = dirname(fileURLToPath(new URL('../package.json', import.meta.url)))
const distDir = join(projectRoot, 'dist')
const scannedExtensions = new Set(['.css', '.html', '.js'])

const blockedPatterns = [
  { label: 'XMLHttpRequest', pattern: /\bXMLHttpRequest\b/g },
  { label: 'sendBeacon', pattern: /\bsendBeacon\b/g },
  { label: 'WebSocket', pattern: /\bWebSocket\b/g },
  { label: 'localStorage', pattern: /\blocalStorage\b/g },
  { label: 'sessionStorage', pattern: /\bsessionStorage\b/g },
  { label: 'analytics marker: gtag', pattern: /\bgtag\s*\(/gi },
  { label: 'analytics marker: posthog', pattern: /\bposthog\b/gi },
  { label: 'analytics marker: plausible', pattern: /\bplausible\b/gi },
  { label: 'analytics marker: mixpanel', pattern: /\bmixpanel\b/gi },
  { label: 'analytics marker: amplitude', pattern: /\bamplitude\b/gi },
  { label: 'analytics marker: segment', pattern: /\bsegment\b/gi },
  { label: 'analytics marker: sentry', pattern: /\bsentry\b/gi },
  { label: 'analytics marker: datadog', pattern: /\bdatadog\b/gi },
]

if (!existsSync(distDir)) {
  console.error('Privacy scan failed: dist/ does not exist. Run npm run build before scanning.')
  process.exit(1)
}

const files = walk(distDir).filter((file) => scannedExtensions.has(extensionOf(file)))
const fetchMatches = []
const violations = []

for (const file of files) {
  const content = readFileSync(file, 'utf8')

  for (const match of content.matchAll(/\bfetch\s*\(/g)) {
    fetchMatches.push({ file, index: match.index ?? 0, context: snippet(content, match.index ?? 0) })
  }

  for (const blocked of blockedPatterns) {
    blocked.pattern.lastIndex = 0
    for (const match of content.matchAll(blocked.pattern)) {
      violations.push({
        file,
        label: blocked.label,
        context: snippet(content, match.index ?? 0),
      })
    }
  }
}

const allowedFetches = fetchMatches.filter((match) => isViteModulepreloadFetch(match.context))

if (fetchMatches.length !== 1 || allowedFetches.length !== 1) {
  violations.push(
    ...fetchMatches.map((match) => ({
      file: match.file,
      label: 'unexpected fetch call',
      context: match.context,
    })),
  )
}

if (violations.length > 0) {
  console.error('Privacy scan failed. Unexpected network, storage, or analytics marker found in dist/:')
  for (const violation of violations) {
    console.error(`- ${relative(projectRoot, violation.file)}: ${violation.label}`)
    console.error(`  ${violation.context}`)
  }
  process.exit(1)
}

console.log(`Privacy scan passed. Checked ${files.length} built files; only Vite modulepreload fetch was found.`)

function walk(directory) {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry)
    return statSync(path).isDirectory() ? walk(path) : [path]
  })
}

function extensionOf(file) {
  const match = file.match(/(\.[^.]+)$/)
  return match?.[1] ?? ''
}

function snippet(content, index) {
  return content
    .slice(Math.max(0, index - 700), Math.min(content.length, index + 180))
    .replace(/\s+/g, ' ')
    .trim()
}

function isViteModulepreloadFetch(context) {
  return context.includes('modulepreload') && context.includes('.ep') && context.includes('.href')
}
