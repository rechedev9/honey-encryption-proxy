import { createHmac } from 'node:crypto'
import { ok, err } from '../types.ts'
import type { IdentifierMapping, Result } from '../types.ts'

const VOCAB: readonly string[] = [
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
  'base', 'root', 'default', 'global', 'local', 'primary', 'secondary',
  'current', 'active', 'pending', 'ready', 'optional', 'sequential', 'async',
  'static', 'dynamic', 'internal', 'external', 'remote', 'concurrent', 'shared',
  'private', 'public', 'max', 'min', 'total', 'size', 'length', 'offset',
  'limit', 'threshold', 'interval', 'timeout', 'incremental', 'fallback', 'required',
] as const

const vocabSet = new Set(VOCAB)
if (vocabSet.size !== VOCAB.length) {
  throw new Error(
    `VOCAB integrity violation: ${VOCAB.length} entries but only ${vocabSet.size} unique — fix duplicates in fpe.ts`,
  )
}

const SKIP_WORDS: ReadonlySet<string> = new Set([
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
const MAX_COLLISION_OFFSETS = 16

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

function mapWord(word: string, fpeKey: Buffer, offset = 0): string {
  const hash = createHmac('sha256', fpeKey).update(word.toLowerCase() + ':' + String(offset)).digest()
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

  for (let offset = 0; offset < MAX_COLLISION_OFFSETS; offset++) {
    const fakeWords = words.map((w) => mapWord(w, fpeKey, offset))
    const fake = reassemble(fakeWords, convention)
    if (!usedFakes.has(fake) && fake !== id) {
      return fake
    }
  }

  const hash = createHmac('sha256', fpeKey).update(id).digest()
  const suffix = hash.readUInt32BE(0) % 900 + 100
  const fakeWords = words.map((w) => mapWord(w, fpeKey, 0))
  return reassemble(fakeWords, convention) + String(suffix)
}

export function shouldObfuscate(identifier: string): boolean {
  if (identifier.length < MIN_IDENTIFIER_LENGTH) return false
  if (SKIP_WORDS.has(identifier)) return false
  if (/^\d+$/.test(identifier)) return false
  return true
}

const MAX_IDENTIFIERS = 5_000

/**
 * Builds a deterministic bidirectional mapping for a set of identifiers.
 * Identifiers in the skip-list are excluded automatically.
 */
export function buildIdentifierMapping(
  identifiers: ReadonlySet<string>,
  fpeKey: Buffer,
): Result<IdentifierMapping> {
  const realToFake = new Map<string, string>()
  const fakeToReal = new Map<string, string>()

  const usedFakes = new Set<string>()

  if (identifiers.size > MAX_IDENTIFIERS) {
    return err(new Error(
      `Identifier count ${identifiers.size} exceeds cap ${MAX_IDENTIFIERS} — possible DoS payload`,
    ))
  }

  const sorted = [...identifiers].sort()
  for (const id of sorted) {
    if (!shouldObfuscate(id)) continue

    const fake = buildFakeIdentifier(id, fpeKey, usedFakes)
    realToFake.set(id, fake)
    fakeToReal.set(fake, id)
    usedFakes.add(fake)
  }

  return ok({ realToFake, fakeToReal })
}

// Sort by key-length descending so longer tokens replace first, preventing
// partial-replacement of shorter sub-strings that appear within longer ones.
function replaceAllTokens(text: string, mapping: ReadonlyMap<string, string>): string {
  let result = text
  const entries = [...mapping.entries()].sort((a, b) => b[0].length - a[0].length)
  for (const [from, to] of entries) {
    result = result.replace(new RegExp(`\\b${escapeRegex(from)}\\b`, 'g'), to)
  }
  return result
}

/**
 * Applies the real→fake mapping to a code string.
 * Replaces only whole-word occurrences to avoid partial matches.
 */
export function applyMapping(code: string, realToFake: ReadonlyMap<string, string>): string {
  return replaceAllTokens(code, realToFake)
}

export function reverseMapping(text: string, fakeToReal: ReadonlyMap<string, string>): string {
  return replaceAllTokens(text, fakeToReal)
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

const STRING_LITERAL_REGEX =
  /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g

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

const TRIVIAL_NUMBERS: ReadonlySet<number> = new Set([
  0, 1, 2, 3, 4, 5, 8, 10, 16, 32, 64, 100, 128, 256,
])

const HTTP_STATUS_CODES: ReadonlySet<number> = new Set([
  100, 101,
  200, 201, 202, 204, 206,
  301, 302, 303, 304, 307, 308,
  400, 401, 403, 404, 405, 406, 408, 409, 410, 415, 422, 429,
  500, 501, 502, 503, 504,
])

const NUM_REGEX = /\b(\d+\.?\d*)\b/g

function numericCandidate(numVal: number, isFloat: boolean, decimals: number, u32: number): string {
  if (isFloat) {
    return (numVal * (0.5 + u32 / 4294967296)).toFixed(decimals)
  }
  const n = Math.round(numVal)
  const order = n <= 0 ? 0 : Math.max(0, Math.floor(Math.log10(n)))
  const min = Math.pow(10, order)
  const max = Math.pow(10, order + 1) - 1
  return String(min + (u32 % (max - min + 1)))
}

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

    if (TRIVIAL_NUMBERS.has(numVal)) continue
    if (!isFloat && HTTP_STATUS_CODES.has(numVal)) continue
    // Skip calendar years (integers 1900–2100)
    if (!isFloat && numVal >= 1900 && numVal <= 2100) continue

    const decimals = isFloat ? (numStr.split('.')[1]?.length ?? 1) : 0

    let fakeStr: string | null = null
    for (let offset = 0; offset < MAX_COLLISION_OFFSETS; offset++) {
      const hash = createHmac('sha256', fpeKey).update(`num:${numStr}:${offset}`).digest()
      const u32 = hash.readUInt32BE(0)
      const candidate = numericCandidate(numVal, isFloat, decimals, u32)
      if (candidate !== numStr && !usedFakes.has(candidate)) {
        fakeStr = candidate
        break
      }
    }

    if (fakeStr === null) {
      // Fallback: use a deterministic large offset. Integer fallback intentionally
      // uses a different formula (+1000 range) to guarantee a distinct value.
      const hash = createHmac('sha256', fpeKey).update(`num:${numStr}:fallback`).digest()
      const u32 = hash.readUInt32BE(0)
      fakeStr = isFloat
        ? numericCandidate(numVal, isFloat, decimals, u32)
        : String(Math.round(numVal) + 1000 + (u32 % 9000))
    }

    realToFake.set(numStr, fakeStr)
    fakeToReal.set(fakeStr, numStr)
    usedFakes.add(fakeStr)
  }

  return { realToFake, fakeToReal }
}
