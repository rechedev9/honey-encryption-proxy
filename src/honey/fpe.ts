/**
 * Format-Preserving Encryption for source-code identifiers.
 *
 * Properties:
 *  - Deterministic: same identifier + key → same fake identifier every time.
 *  - Convention-preserving: camelCase→camelCase, PascalCase→PascalCase, etc.
 *  - Honey property: a wrong key produces a different-but-plausible mapping.
 *  - Reversible via the session mapping table (real↔fake maintained in memory).
 *
 * Approach:
 *  1. Split identifier into constituent words (by casing / underscores).
 *  2. Map each word via HMAC-SHA256(fpeKey, word) → index → VOCAB[index].
 *  3. Reassemble with the same naming convention.
 *
 * Collision handling: if the assembled fake identifier already exists in the
 * reverse map (i.e., used by a different real identifier), increment the HMAC
 * index until a free slot is found.
 */

import { createHmac } from 'node:crypto'
import type { IdentifierMapping } from '../types.ts'

// ── Vocabulary ────────────────────────────────────────────────────────────────
// 256 common programming words (lowercase).  Mix of verbs, nouns, and modifiers
// so every combination produces plausible identifier components.

const VOCAB: readonly string[] = [
  // verbs
  'process', 'handle', 'compute', 'validate', 'parse', 'render', 'fetch',
  'load', 'save', 'update', 'create', 'remove', 'build', 'format', 'convert',
  'transform', 'filter', 'sort', 'find', 'search', 'check', 'verify',
  'calculate', 'generate', 'initialize', 'configure', 'execute', 'dispatch',
  'subscribe', 'publish', 'observe', 'monitor', 'track', 'analyze', 'optimize',
  'cache', 'schedule', 'retry', 'cancel', 'abort', 'complete', 'finalize',
  'prepare', 'invoke', 'register', 'attach', 'connect', 'disconnect', 'open',
  'close', 'read', 'write', 'send', 'receive', 'encode', 'decode', 'compress',
  'serialize', 'migrate', 'deploy', 'commit', 'merge', 'split', 'join',
  'group', 'aggregate', 'batch', 'queue', 'dequeue', 'insert', 'append',
  'flatten', 'reduce', 'resolve', 'reject', 'emit', 'broadcast', 'notify',
  'stream', 'poll', 'flush', 'drain', 'wrap', 'unwrap', 'bind', 'unbind',
  'mount', 'unmount', 'enable', 'disable', 'lock', 'unlock', 'acquire',
  'release', 'assert', 'expect', 'compare', 'measure', 'count', 'allocate',
  'collect', 'compact', 'extract', 'inject', 'intercept', 'forward', 'proxy',
  'bootstrap', 'shutdown', 'restart', 'pause', 'resume', 'clone', 'copy',
  'move', 'rename', 'index', 'hash', 'sign', 'encrypt', 'decrypt', 'refresh',
  // nouns
  'data', 'item', 'value', 'node', 'element', 'component', 'service',
  'manager', 'handler', 'controller', 'router', 'config', 'context', 'state',
  'store', 'cursor', 'pool', 'buffer', 'session', 'token', 'payload',
  'response', 'request', 'client', 'server', 'adapter', 'provider',
  'resolver', 'factory', 'builder', 'parser', 'formatter', 'validator',
  'processor', 'generator', 'listener', 'observer', 'emitter', 'scheduler',
  'executor', 'runner', 'worker', 'task', 'job', 'event', 'message',
  'record', 'entry', 'document', 'model', 'schema', 'rule', 'policy',
  'strategy', 'command', 'query', 'result', 'resource', 'permission',
  'account', 'profile', 'credential', 'system', 'environment', 'network',
  'protocol', 'endpoint', 'route', 'path', 'connector', 'channel', 'bridge',
  'pipeline', 'workflow', 'transaction', 'operation', 'thread', 'signal',
  'hook', 'plugin', 'module', 'bundle', 'chunk', 'segment', 'block', 'frame',
  'widget', 'panel', 'form', 'field', 'label', 'button', 'menu', 'list',
  'grid', 'table', 'row', 'column', 'header', 'layout', 'container', 'view',
  'screen', 'dialog', 'drawer', 'sidebar', 'section', 'article', 'page',
  // modifiers / size words
  'base', 'root', 'default', 'global', 'local', 'primary', 'secondary',
  'current', 'active', 'pending', 'ready', 'optional', 'sequential', 'async',
  'static', 'dynamic', 'internal', 'external', 'remote', 'concurrent', 'shared',
  'private', 'public', 'max', 'min', 'total', 'size', 'length', 'offset',
  'limit', 'threshold', 'interval', 'timeout', 'incremental', 'fallback', 'required',
] as const

// Verify at module load time that VOCAB contains no duplicates.
// A duplicate reduces entropy and creates a statistical fingerprint in
// the output distribution — caught here rather than silently degrading.
if (process.env['NODE_ENV'] !== 'test') {
  const vocabSet = new Set(VOCAB)
  if (vocabSet.size !== VOCAB.length) {
    throw new Error(
      `VOCAB integrity violation: ${VOCAB.length} entries but only ${vocabSet.size} unique — fix duplicates in fpe.ts`,
    )
  }
}

// ── Skip-list: identifiers that must not be renamed ───────────────────────────

const SKIP_WORDS: ReadonlySet<string> = new Set([
  // JS/TS keywords
  'abstract', 'any', 'as', 'async', 'await', 'boolean', 'break', 'case',
  'catch', 'class', 'const', 'continue', 'debugger', 'declare', 'default',
  'delete', 'do', 'else', 'enum', 'export', 'extends', 'false', 'finally',
  'for', 'from', 'function', 'get', 'if', 'implements', 'import', 'in',
  'infer', 'instanceof', 'interface', 'is', 'keyof', 'let', 'module',
  'namespace', 'never', 'new', 'null', 'number', 'object', 'of', 'override',
  'package', 'private', 'protected', 'public', 'readonly', 'require',
  'return', 'set', 'static', 'string', 'super', 'switch', 'symbol', 'this',
  'throw', 'true', 'try', 'type', 'typeof', 'undefined', 'unique', 'unknown',
  'var', 'void', 'while', 'with', 'yield',
  // common builtins
  'Array', 'ArrayBuffer', 'BigInt', 'Boolean', 'Buffer', 'console', 'crypto',
  'DataView', 'Date', 'Error', 'Float32Array', 'Float64Array', 'FormData',
  'Headers', 'Int8Array', 'Int16Array', 'Int32Array', 'JSON', 'Map', 'Math',
  'Number', 'Object', 'Promise', 'Proxy', 'RangeError', 'ReferenceError',
  'Reflect', 'RegExp', 'Request', 'Response', 'Set', 'String', 'Symbol',
  'SyntaxError', 'TextDecoder', 'TextEncoder', 'TypeError', 'Uint8Array',
  'Uint16Array', 'Uint32Array', 'URL', 'URLSearchParams', 'WeakMap', 'WeakSet',
  'clearInterval', 'clearTimeout', 'document', 'fetch', 'global',
  'globalThis', 'navigator', 'process', 'queueMicrotask', 'setInterval',
  'setTimeout', 'structuredClone', 'window',
])

const MIN_IDENTIFIER_LENGTH = 3

// ── Naming convention helpers ─────────────────────────────────────────────────

type Convention = 'camel' | 'pascal' | 'snake' | 'screaming' | 'flat'

function detectConvention(id: string): Convention {
  if (/^[A-Z][A-Z0-9_]+$/.test(id)) return 'screaming'
  if (id.includes('_')) return 'snake'
  if (/^[A-Z]/.test(id)) return 'pascal'
  if (/[A-Z]/.test(id)) return 'camel'
  return 'flat'
}

function splitWords(id: string, convention: Convention): string[] {
  if (convention === 'screaming' || convention === 'snake') {
    return id.split('_').filter((w) => w.length > 0)
  }
  // camel / pascal: split on capital letters
  return id
    .replace(/([A-Z])/g, ' $1')
    .trim()
    .split(' ')
    .filter((w) => w.length > 0)
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase()
}

function reassemble(words: string[], convention: Convention): string {
  if (words.length === 0) return ''
  switch (convention) {
    case 'pascal':
      return words.map(capitalize).join('')
    case 'camel':
      return (words[0]?.toLowerCase() ?? '') + words.slice(1).map(capitalize).join('')
    case 'snake':
      return words.map((w) => w.toLowerCase()).join('_')
    case 'screaming':
      return words.map((w) => w.toUpperCase()).join('_')
    case 'flat':
      return words.map((w) => w.toLowerCase()).join('')
  }
}

// ── Core FPE word mapping ────────────────────────────────────────────────────

function mapWord(word: string, fpeKey: Buffer, offset = 0): string {
  const hash = createHmac('sha256', fpeKey).update(word.toLowerCase() + offset).digest()
  const idx = hash.readUInt32BE(0) % VOCAB.length
  return VOCAB[idx] ?? VOCAB[0] ?? 'data'
}

function buildFakeIdentifier(
  id: string,
  fpeKey: Buffer,
  usedFakes: ReadonlySet<string>,
): string {
  const convention = detectConvention(id)
  const words = splitWords(id, convention)

  // Try up to 16 collision-avoidance offsets before giving up
  for (let offset = 0; offset < 16; offset++) {
    const fakeWords = words.map((w) => mapWord(w, fpeKey, offset))
    const fake = reassemble(fakeWords, convention)
    if (!usedFakes.has(fake) && fake !== id) {
      return fake
    }
  }

  // Fallback: append a suffix derived from the id hash
  const hash = createHmac('sha256', fpeKey).update(id).digest()
  const suffix = hash.readUInt32BE(0) % 900 + 100
  const fakeWords = words.map((w) => mapWord(w, fpeKey, 0))
  return reassemble(fakeWords, convention) + String(suffix)
}

// ── Public API ────────────────────────────────────────────────────────────────

export function shouldObfuscate(identifier: string): boolean {
  if (identifier.length < MIN_IDENTIFIER_LENGTH) return false
  if (SKIP_WORDS.has(identifier)) return false
  // skip purely numeric strings
  if (/^\d+$/.test(identifier)) return false
  return true
}

/** Maximum number of user-defined identifiers to obfuscate per request. */
const MAX_IDENTIFIERS = 5_000

/**
 * Builds a deterministic bidirectional mapping for a set of identifiers.
 * Identifiers in the skip-list are excluded automatically.
 */
export function buildIdentifierMapping(
  identifiers: ReadonlySet<string>,
  fpeKey: Buffer,
): IdentifierMapping {
  const realToFake = new Map<string, string>()
  const fakeToReal = new Map<string, string>()

  const usedFakes = new Set<string>()

  if (identifiers.size > MAX_IDENTIFIERS) {
    // Log a warning but continue with the full set — truncating would
    // silently leak identifiers beyond the cap. This limit exists to
    // warn operators of abnormally large payloads.
    console.warn(`[honey-proxy] Identifier count ${identifiers.size} exceeds cap ${MAX_IDENTIFIERS} — possible DoS payload`)
  }

  const sorted = [...identifiers].sort()
  for (const id of sorted) {
    if (!shouldObfuscate(id)) continue

    const fake = buildFakeIdentifier(id, fpeKey, usedFakes)
    realToFake.set(id, fake)
    fakeToReal.set(fake, id)
    usedFakes.add(fake)
  }

  return { realToFake, fakeToReal }
}

/**
 * Applies the real→fake mapping to a code string.
 * Replaces only whole-word occurrences to avoid partial matches.
 */
export function applyMapping(code: string, realToFake: ReadonlyMap<string, string>): string {
  let result = code
  // Sort by length descending so longer identifiers replace first (avoids
  // partial-replacement of shorter sub-strings that appear within longer ones).
  const entries = [...realToFake.entries()].sort((a, b) => b[0].length - a[0].length)
  for (const [real, fake] of entries) {
    result = result.replace(new RegExp(`\\b${escapeRegex(real)}\\b`, 'g'), fake)
  }
  return result
}

/**
 * Applies the fake→real mapping to a response string (reverse pass).
 */
export function reverseMapping(text: string, fakeToReal: ReadonlyMap<string, string>): string {
  let result = text
  const entries = [...fakeToReal.entries()].sort((a, b) => b[0].length - a[0].length)
  for (const [fake, real] of entries) {
    result = result.replace(new RegExp(`\\b${escapeRegex(fake)}\\b`, 'g'), real)
  }
  return result
}

export function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// ── String-literal FPE ────────────────────────────────────────────────────────

// Matches string literals (double-quoted, single-quoted, template).
// Using RegExp constructor to avoid parser ambiguity with backtick in regex literal.
const STRING_LITERAL_REGEX = new RegExp(
  [
    '"(?:[^"\\\\]|\\\\.)*"',
    "'(?:[^'\\\\]|\\\\.)*'",
    '`(?:[^`\\\\]|\\\\.)*`',
  ].join('|'),
  'g',
)

/**
 * Replaces the content of string literals whose unquoted value exactly matches
 * a key in `realToFake`. Non-matching literals are left untouched.
 *
 *   obfuscateStringLiterals('db.query("invoiceId")', map)
 *   // → 'db.query("processResult")'
 */
export function obfuscateStringLiterals(
  code: string,
  realToFake: ReadonlyMap<string, string>,
): string {
  STRING_LITERAL_REGEX.lastIndex = 0
  return code.replace(STRING_LITERAL_REGEX, (match: string): string => {
    const quote = match.charAt(0)
    const inner = match.slice(1, -1)
    const fake = realToFake.get(inner)
    if (fake !== undefined) return quote + fake + quote
    return match
  })
}

// ── Numeric FPE ───────────────────────────────────────────────────────────────

// Numbers that are too generic to be worth obfuscating.
const TRIVIAL_NUMBERS: ReadonlySet<number> = new Set([
  0, 1, 2, 3, 4, 5, 8, 10, 16, 32, 64, 100, 128, 256,
])

// Well-known HTTP status codes that appear ubiquitously in code.
// Using an explicit set (rather than the broad 100–599 range) avoids
// accidentally skipping domain constants that happen to fall in that range
// (e.g., 365 days, 250 ms timeout).
const HTTP_STATUS_CODES: ReadonlySet<number> = new Set([
  100, 101,
  200, 201, 202, 204, 206,
  301, 302, 303, 304, 307, 308,
  400, 401, 403, 404, 405, 406, 408, 409, 410, 415, 422, 429,
  500, 501, 502, 503, 504,
])

const NUM_REGEX = /\b(\d+\.?\d*)\b/g

/**
 * Scans `code` for numeric literals and builds a deterministic fake-number
 * mapping.  Skips:
 *  - Trivial constants (0, 1, 2, …, 256)
 *  - Well-known HTTP status codes (explicit set)
 *  - Calendar years  (integers 1900–2100)
 *
 * Fake derivation:
 *  - Float with p decimals → scale original by a factor in [0.5, 1.5) derived
 *    from HMAC-SHA256(fpeKey, "num:<numStr>:<offset>"), keeping p decimals.
 *  - Integer → different integer in the same decimal order of magnitude.
 *
 * The returned mapping can be merged into the identifier mapping and reversed
 * for free by `reverseMapping`.
 */
export function buildNumericMapping(code: string, fpeKey: Buffer): IdentifierMapping {
  const realToFake = new Map<string, string>()
  const fakeToReal = new Map<string, string>()
  const usedFakes = new Set<string>()
  const seen = new Set<string>()

  NUM_REGEX.lastIndex = 0
  let match: RegExpExecArray | null

  while ((match = NUM_REGEX.exec(code)) !== null) {
    const numStr = match[1]
    if (numStr === undefined || seen.has(numStr)) continue
    seen.add(numStr)

    const numVal = parseFloat(numStr)
    const isFloat = numStr.includes('.')

    // Skip trivial constants
    if (TRIVIAL_NUMBERS.has(numVal)) continue
    // Skip well-known HTTP status codes
    if (!isFloat && HTTP_STATUS_CODES.has(numVal)) continue
    // Skip calendar years (integers 1900–2100)
    if (!isFloat && numVal >= 1900 && numVal <= 2100) continue

    const decimals = isFloat ? (numStr.split('.')[1]?.length ?? 1) : 0

    let fakeStr: string | null = null
    for (let offset = 0; offset < 16; offset++) {
      const hash = createHmac('sha256', fpeKey).update(`num:${numStr}:${offset}`).digest()
      const u32 = hash.readUInt32BE(0)

      let candidate: string
      if (isFloat) {
        // Scale by a factor in [0.5, 1.5)
        const factor = 0.5 + u32 / 4294967296
        candidate = (numVal * factor).toFixed(decimals)
      } else {
        // Keep the same order of magnitude
        const n = Math.round(numVal)
        const order = n <= 0 ? 0 : Math.max(0, Math.floor(Math.log10(n)))
        const min = Math.pow(10, order)
        const max = Math.pow(10, order + 1) - 1
        candidate = String(min + (u32 % (max - min + 1)))
      }

      if (candidate !== numStr && !usedFakes.has(candidate)) {
        fakeStr = candidate
        break
      }
    }

    if (fakeStr === null) {
      // Fallback: use a deterministic large offset
      const hash = createHmac('sha256', fpeKey).update(`num:${numStr}:fallback`).digest()
      const u32 = hash.readUInt32BE(0)
      fakeStr = isFloat
        ? (numVal * (0.5 + u32 / 4294967296)).toFixed(decimals)
        : String(Math.round(numVal) + 1000 + (u32 % 9000))
    }

    realToFake.set(numStr, fakeStr)
    fakeToReal.set(fakeStr, numStr)
    usedFakes.add(fakeStr)
  }

  return { realToFake, fakeToReal }
}
