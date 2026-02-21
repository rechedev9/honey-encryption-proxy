/**
 * Honey Encryption Proxy for Claude Code.
 *
 * Run with:
 *   ANTHROPIC_API_KEY=sk-ant-... HONEY_PASSPHRASE=secret bun run src/proxy.ts
 *
 * Then configure Claude Code:
 *   export ANTHROPIC_BASE_URL=http://localhost:8080
 *
 * What this proxy does:
 *   1. Intercepts POST /v1/messages from Claude Code.
 *   2. Extracts fenced code blocks from user messages.
 *   3. Applies FPE: replaces real identifiers with plausible fake ones.
 *   4. Forwards the obfuscated request to Anthropic.
 *   5. Collects the response (including streaming SSE).
 *   6. Reverse-maps fake identifiers back to real ones.
 *   7. Returns the corrected response to Claude Code.
 *
 * All other routes (e.g. /v1/models) are forwarded transparently.
 */

import { loadConfig } from './config.ts'
import { deriveSessionKey, zeroSessionKey } from './honey/key-manager.ts'
import { buildGlobalMapping, applyMappingToFullText, deobfuscateText } from './ast/mapper.ts'
import type { ObfuscationStats } from './ast/mapper.ts'
import { logger, setLogLevel } from './logger.ts'
import { writeAuditEntry, initAuditSigner } from './audit.ts'
import { StreamDeobfuscator } from './stream-deobfuscator.ts'
import { initTreeSitter } from './ast/tree-sitter.ts'
import { ok, err } from './types.ts'
import type { AuditEntry, IdentifierMapping, Result } from './types.ts'

// ── Config ───────────────────────────────────────────────────────────────────────────

const configResult = loadConfig()
if (!configResult.ok) {
  logger.error('Configuration error', { error: configResult.error.message })
  process.exit(1)
}

const config = configResult.value
setLogLevel(config.logLevel)

// Derive a persistent session key from the passphrase.
// A fresh salt is generated each time the proxy starts; re-derivation
// across restarts is intentionally not supported (forward secrecy).
// If HONEY_KYBER_CAPSULE is set, the ML-KEM shared secret is XOR'd into
// the master key for a classical + post-quantum hybrid derivation.
const kyberCapsule = config.honeyKyberCapsule !== undefined
  ? Buffer.from(config.honeyKyberCapsule, 'base64url')
  : undefined
const keyResult = deriveSessionKey(config.honeyPassphrase, kyberCapsule)
if (!keyResult.ok) {
  logger.error('Key derivation failed', { error: keyResult.error.message })
  process.exit(1)
}

const SESSION_KEY = keyResult.value

// Initialise SPHINCS+ audit signer using the session MAC key.
initAuditSigner(SESSION_KEY.macKey)

// Initialise tree-sitter AST extraction (non-fatal — falls back to regex on failure).
void initTreeSitter()

// Scrub secrets from process.env immediately after use.
// They are now held in SESSION_KEY / config; keeping them in
// process.env exposes them via /proc/self/environ on Linux/WSL.
delete process.env.ANTHROPIC_API_KEY
delete process.env.HONEY_PASSPHRASE

logger.info('Honey proxy starting', {
  port: config.proxyPort,
  upstream: config.upstreamBaseUrl,
})
logger.debug('Session established', { sessionId: SESSION_KEY.sessionId })
logger.info('ML-KEM-768 public key (quantum-safe hybrid)', {
  mlkemPublicKey: SESSION_KEY.toJSON().mlkemPublicKey,
})

// ── Anthropic message type (minimal surface) ───────────────────────────────────────────────

interface AnthropicTextBlock {
  readonly type: 'text'
  readonly text: string
  readonly [key: string]: unknown
}

/** Narrows unknown to a non-null JSON object record (used for JSON.parse results). */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Type guard for Anthropic text content blocks.
 * Narrows `unknown` to `AnthropicTextBlock` using structural checks.
 * TypeScript's `'in'` narrowing provides property access after the checks.
 */
function isTextBlock(item: unknown): item is AnthropicTextBlock {
  if (typeof item !== 'object' || item === null) return false
  if (!('type' in item) || !('text' in item)) return false
  return item.type === 'text' && typeof item.text === 'string'
}

// ── Header allowlist ──────────────────────────────────────────────────────────────────

/** Headers forwarded from the client to the upstream Anthropic API. */
const ALLOWED_REQUEST_HEADERS: ReadonlySet<string> = new Set([
  'content-type',
  'anthropic-version',
  'anthropic-beta',
  'accept',
  'accept-encoding',
])

/** Response headers forwarded from upstream back to the Claude Code client. */
const ALLOWED_RESPONSE_HEADERS: ReadonlySet<string> = new Set([
  'content-type',
  'content-length',
  'transfer-encoding',
  'cache-control',
])

function filterResponseHeaders(upstream: Headers): Headers {
  const filtered = new Headers()
  for (const [name, value] of upstream.entries()) {
    if (ALLOWED_RESPONSE_HEADERS.has(name.toLowerCase())) {
      filtered.set(name, value)
    }
  }
  return filtered
}

/**
 * Builds the upstream URL from a client request URL, with SSRF origin validation.
 * Returns null if the origin does not match the configured upstream.
 */
function buildUpstreamUrl(clientUrl: URL): URL | null {
  const upstreamBase = new URL(config.upstreamBaseUrl)
  const upstream = new URL(clientUrl.pathname + clientUrl.search, upstreamBase.origin)
  if (upstream.origin !== upstreamBase.origin) return null
  return upstream
}

/**
 * Filters client request headers through the allowlist and injects the API key.
 */
function filterRequestHeaders(clientHeaders: Headers): Headers {
  const filtered = new Headers()
  for (const [name, value] of clientHeaders.entries()) {
    if (ALLOWED_REQUEST_HEADERS.has(name.toLowerCase())) {
      filtered.set(name, value)
    }
  }
  filtered.set('x-api-key', config.anthropicApiKey)
  return filtered
}

// ── Request handling ─────────────────────────────────────────────────────────────────────

interface ObfuscateResult {
  readonly messages: unknown[]
  readonly mapping: IdentifierMapping
  readonly stats: ObfuscationStats
}

/** Safely extracts the `content` property from an unknown message object. */
function extractContent(msg: unknown): string | unknown[] | undefined {
  if (typeof msg !== 'object' || msg === null) return undefined
  if (!('content' in msg)) return undefined
  // TypeScript narrows msg to include .content after the 'in' check
  const content: unknown = msg.content
  if (typeof content === 'string') return content
  // Array.isArray on an `unknown` value narrows to any[] in some TS configs
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  if (Array.isArray(content)) return content
  return undefined
}

/**
 * Extracts all plain-text strings from a message content value.
 * Handles both string content and Anthropic's array-of-blocks format.
 */
function extractStringContents(content: unknown[]): readonly string[] {
  const result: string[] = []
  for (const item of content) {
    if (isTextBlock(item)) {
      result.push(item.text)
    }
  }
  return result
}

/**
 * Applies a mapping to a content value.
 * Handles string content and array-of-blocks format.
 */
function applyMappingToContent(
  content: string | unknown[],
  mapping: IdentifierMapping,
  identifierRealToFake: ReadonlyMap<string, string>,
): string | unknown[] {
  if (typeof content === 'string') {
    return applyMappingToFullText(content, mapping, identifierRealToFake)
  }
  if (!Array.isArray(content)) return content
  return content.map((item) => {
    if (isTextBlock(item)) {
      const obfuscatedText = applyMappingToFullText(item.text, mapping, identifierRealToFake)
      return { ...item, text: obfuscatedText }
    }
    return item
  })
}

function obfuscateMessages(messages: unknown[]): Result<ObfuscateResult> {
  const emptyMapping: IdentifierMapping = {
    realToFake: new Map(),
    fakeToReal: new Map(),
  }

  // Step 1: collect all string contents across every message (handles both
  // string content and array-of-blocks format).
  const allTexts = messages.flatMap((msg) => {
    const content = extractContent(msg)
    if (typeof content === 'string') return [content]
    if (Array.isArray(content)) return extractStringContents(content)
    return []
  })

  // Step 2: build one global mapping from code blocks across ALL messages.
  // This ensures assistant messages with no code blocks still get their
  // prose obfuscated using identifiers extracted from user messages.
  const globalResult = buildGlobalMapping(allTexts, SESSION_KEY)
  if (!globalResult.ok) {
    return err(globalResult.error)
  }
  const { mapping, identifierRealToFake, stats } = globalResult.value

  if (mapping.realToFake.size === 0) {
    return ok({ messages, mapping: emptyMapping, stats })
  }

  logger.debug('Built global mapping', {
    identifiers: stats.identifiersObfuscated,
    numbers: stats.numbersObfuscated,
  })

  // Step 3: apply the global mapping to EVERY message (code blocks + prose).
  const obfuscated = messages.map((msg) => {
    const content = extractContent(msg)
    if (content === undefined) return msg
    const obfuscatedContent = applyMappingToContent(content, mapping, identifierRealToFake)
    if (typeof msg === 'object' && msg !== null) {
      return { ...msg, content: obfuscatedContent }
    }
    return msg
  })

  return ok({ messages: obfuscated, mapping, stats })
}

async function forwardRequest(
  originalReq: Request,
  body: string,
): Promise<Response> {
  const upstreamUrl = buildUpstreamUrl(new URL(originalReq.url))
  if (upstreamUrl === null) {
    logger.error('Upstream URL origin mismatch — possible SSRF')
    return new Response('Internal Server Error', { status: 500 })
  }

  return await fetch(upstreamUrl.toString(), {
    method: originalReq.method,
    headers: filterRequestHeaders(originalReq.headers),
    body,
    redirect: 'manual',
  })
}

/** Maximum allowed request body size (10 MiB). Prevents memory/CPU DoS. */
const MAX_BODY_BYTES = 10 * 1024 * 1024

async function handleMessagesEndpoint(req: Request): Promise<Response> {
  const requestId = crypto.randomUUID()
  const startMs = Date.now()

  let rawBody: string
  try {
    rawBody = await req.text()
  } catch (e) {
    logger.error('Failed to read request body', { requestId, error: String(e) })
    return new Response('Bad Request', { status: 400 })
  }

  // Use byte length (not character count) — multi-byte UTF-8 chars can exceed
  // the limit while still appearing within rawBody.length characters.
  const bodyByteLength = Buffer.byteLength(rawBody, 'utf8')
  if (bodyByteLength > MAX_BODY_BYTES) {
    logger.warn('Request body exceeds size limit — rejecting', {
      requestId,
      size: bodyByteLength,
      limit: MAX_BODY_BYTES,
    })
    return new Response('Request Entity Too Large', { status: 413 })
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(rawBody)
  } catch {
    logger.warn('Non-JSON body on /v1/messages — rejecting', { requestId })
    return new Response('Bad Request: /v1/messages requires a JSON body', { status: 400 })
  }

  if (!isRecord(parsed)) {
    logger.warn('Request body is not a JSON object — rejecting', { requestId })
    return new Response('Bad Request: /v1/messages requires a JSON object', { status: 400 })
  }

  const messages = parsed.messages
  if (!Array.isArray(messages)) {
    logger.warn('Request missing messages array — rejecting', { requestId })
    return new Response('Bad Request: messages must be an array', { status: 400 })
  }

  const obfuscateResult = obfuscateMessages(messages)
  if (!obfuscateResult.ok) {
    logger.warn('Identifier cap exceeded — rejecting request', {
      requestId,
      error: obfuscateResult.error.message,
    })
    return new Response('Request Entity Too Large', { status: 413 })
  }
  const { messages: obfuscatedMessages, mapping, stats } = obfuscateResult.value

  const mappingSize = mapping.realToFake.size
  if (mappingSize > 0) {
    logger.info('Obfuscated identifiers', { requestId, count: mappingSize })
  }

  const outBody = JSON.stringify({ ...parsed, messages: obfuscatedMessages })
  const upstreamResponse = await forwardRequest(req, outBody)
  const isStreaming = parsed.stream === true ||
    (upstreamResponse.headers.get('content-type') ?? '').includes('text/event-stream')

  const emitAudit = (upstreamStatus: number): void => {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      requestId,
      sessionId: SESSION_KEY.sessionId,
      identifiersObfuscated: stats.identifiersObfuscated,
      numbersObfuscated: stats.numbersObfuscated,
      durationMs: Date.now() - startMs,
      streaming: isStreaming,
      upstreamStatus,
    }
    void writeAuditEntry(entry)
  }

  // ── Handle streaming (SSE) ────────────────────────────────────────────────────────────────────────────

  if (isStreaming) {
    return handleStreamingResponse(
      upstreamResponse, mapping, requestId, startMs, emitAudit,
    )
  }

  // ── Handle buffered response ────────────────────────────────────────────────────────────────────────────────

  const responseText = await upstreamResponse.text()
  const deobfuscated = mappingSize > 0 ? deobfuscateText(responseText, mapping) : responseText

  logger.info('Request complete', { requestId, ms: Date.now() - startMs })
  emitAudit(upstreamResponse.status)

  return new Response(deobfuscated, {
    status: upstreamResponse.status,
    headers: filterResponseHeaders(upstreamResponse.headers),
  })
}

function handleStreamingResponse(
  upstreamResponse: Response,
  mapping: IdentifierMapping,
  requestId: string,
  startMs: number,
  emitAudit: (upstreamStatus: number) => void,
): Response {
  if (upstreamResponse.body === null) {
    return new Response(null, {
      status: upstreamResponse.status,
      headers: filterResponseHeaders(upstreamResponse.headers),
    })
  }

  const deobfuscator = new StreamDeobfuscator(mapping)
  const decoder = new TextDecoder()
  const encoder = new TextEncoder()

  const upstreamBody = upstreamResponse.body

  const transformedBody = new ReadableStream<Uint8Array>({
    async start(controller: ReadableStreamDefaultController<Uint8Array>): Promise<void> {
      const reader = upstreamBody.getReader()
      try {
        for (;;) {
          const readResult = await reader.read()
          if (readResult.done) break

          // readResult.value is Uint8Array at runtime; Bun types the reader as any
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
          const chunk = decoder.decode(readResult.value, { stream: true })
          const processed = deobfuscator.processChunk(chunk)
          if (processed !== '') {
            controller.enqueue(encoder.encode(processed))
          }
        }

        // Flush remaining decoder + deobfuscator state
        const tail = decoder.decode(undefined, { stream: false })
        if (tail !== '') {
          const processed = deobfuscator.processChunk(tail)
          if (processed !== '') {
            controller.enqueue(encoder.encode(processed))
          }
        }
        const flushed = deobfuscator.flush()
        if (flushed !== '') {
          controller.enqueue(encoder.encode(flushed))
        }

        logger.info('Stream complete', { requestId, ms: Date.now() - startMs })
        emitAudit(upstreamResponse.status)
        controller.close()
      } catch (e) {
        logger.error('Stream error', { requestId, error: String(e) })
        controller.error(e)
      } finally {
        reader.releaseLock()
      }
    },
  })

  return new Response(transformedBody, {
    status: upstreamResponse.status,
    headers: filterResponseHeaders(upstreamResponse.headers),
  })
}

// ── Bun HTTP server ──────────────────────────────────────────────────────────────────────────

const MESSAGES_PATH = '/v1/messages'

const server = Bun.serve({
  port: config.proxyPort,
  hostname: '127.0.0.1',

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url)

    // Only intercept POST /v1/messages; forward everything else transparently
    if (req.method === 'POST' && url.pathname === MESSAGES_PATH) {
      try {
        return await handleMessagesEndpoint(req)
      } catch (e) {
        logger.error('Unhandled error in messages handler', { error: String(e) })
        return new Response('Internal Server Error', { status: 500 })
      }
    }

    // Transparent passthrough for all other routes
    const upstreamUrl = buildUpstreamUrl(url)
    if (upstreamUrl === null) {
      logger.error('Passthrough URL origin mismatch')
      return new Response('Internal Server Error', { status: 500 })
    }

    // Enforce body size limit on passthrough routes with bodies
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const contentLength = req.headers.get('content-length')
      if (contentLength !== null && parseInt(contentLength, 10) > MAX_BODY_BYTES) {
        return new Response('Request Entity Too Large', { status: 413 })
      }
    }

    return await fetch(upstreamUrl.toString(), {
      method: req.method,
      headers: filterRequestHeaders(req.headers),
      body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
      redirect: 'manual',
    })
  },
})

// ── Graceful shutdown ─────────────────────────────────────────────────────────────────────────────
function handleShutdown(signal: string): void {
  logger.info('Shutdown initiated', { signal })
  // Zero key material before the process exits
  zeroSessionKey(SESSION_KEY)
  // stop() waits for in-flight requests to complete before closing the server.
  // Do NOT call process.exit() here — let the event loop drain naturally.
  void server.stop()
  logger.info('Server stopped')
}

process.on('SIGINT', () => {
  handleShutdown('SIGINT')
})
process.on('SIGTERM', () => {
  handleShutdown('SIGTERM')
})

logger.info('Honey proxy ready', {
  url: `http://127.0.0.1:${config.proxyPort}`,
  tip: `Set ANTHROPIC_BASE_URL=http://localhost:${config.proxyPort} in Claude Code`,
})
