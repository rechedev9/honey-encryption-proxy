/**
 * Pure request-handling logic for the Honey Encryption proxy.
 *
 * Extracted from proxy.ts so integration tests can construct a handler
 * with dependency-injected config/keys without triggering module-level
 * side effects (scrypt, Bun.serve, process.exit, etc.).
 */

import { buildGlobalMapping, applyMappingToFullText, deobfuscateText } from './ast/mapper.ts'
import type { ObfuscationStats } from './ast/mapper.ts'
import { logger } from './logger.ts'
import { writeAuditEntry } from './audit.ts'
import { StreamDeobfuscator } from './stream-deobfuscator.ts'
import { ok, err } from './types.ts'
import type { AuditEntry, IdentifierMapping, Result, SessionKey } from './types.ts'

// ── Dependencies ────────────────────────────────────────────────────────────

/** Dependencies injected into the proxy handler factory. */
export interface ProxyHandlerDeps {
  readonly sessionKey: SessionKey
  readonly apiKey: string
  readonly upstreamBaseUrl: string
}

// ── Anthropic message type (minimal surface) ────────────────────────────────

interface AnthropicTextBlock {
  readonly type: 'text'
  readonly text: string
  readonly [key: string]: unknown
}

/** Narrows unknown to a non-null JSON object record. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isTextBlock(item: unknown): item is AnthropicTextBlock {
  if (typeof item !== 'object' || item === null) return false
  if (!('type' in item) || !('text' in item)) return false
  return item.type === 'text' && typeof item.text === 'string'
}

// ── Header allowlist ────────────────────────────────────────────────────────

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

/** Maximum allowed request body size (10 MiB). Prevents memory/CPU DoS. */
const MAX_BODY_BYTES = 10 * 1024 * 1024

const MESSAGES_PATH = '/v1/messages'

// ── Factory ─────────────────────────────────────────────────────────────────

/**
 * Creates the proxy's HTTP fetch handler.
 *
 * All external dependencies (session key, API key, upstream URL) are
 * captured in the closure so the returned function is self-contained.
 */
export function createProxyHandler(
  deps: ProxyHandlerDeps,
): (req: Request) => Promise<Response> {
  const { sessionKey, apiKey, upstreamBaseUrl } = deps

  // ── Helpers closed over deps ──────────────────────────────────────────

  function buildUpstreamUrl(clientUrl: URL): URL | null {
    const upstreamBase = new URL(upstreamBaseUrl)
    const upstream = new URL(clientUrl.pathname + clientUrl.search, upstreamBase.origin)
    if (upstream.origin !== upstreamBase.origin) return null
    return upstream
  }

  function filterRequestHeaders(clientHeaders: Headers): Headers {
    const filtered = new Headers()
    for (const [name, value] of clientHeaders.entries()) {
      if (ALLOWED_REQUEST_HEADERS.has(name.toLowerCase())) {
        filtered.set(name, value)
      }
    }
    filtered.set('x-api-key', apiKey)
    return filtered
  }

  // ── Content helpers ───────────────────────────────────────────────────

  function extractContent(msg: unknown): string | unknown[] | undefined {
    if (typeof msg !== 'object' || msg === null) return undefined
    if (!('content' in msg)) return undefined
    const content: unknown = msg.content
    if (typeof content === 'string') return content
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    if (Array.isArray(content)) return content
    return undefined
  }

  function extractStringContents(content: unknown[]): readonly string[] {
    const result: string[] = []
    for (const item of content) {
      if (isTextBlock(item)) {
        result.push(item.text)
      }
    }
    return result
  }

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

  // ── Obfuscation ───────────────────────────────────────────────────────

  interface ObfuscateResult {
    readonly messages: unknown[]
    readonly mapping: IdentifierMapping
    readonly stats: ObfuscationStats
  }

  function obfuscateMessages(messages: unknown[]): Result<ObfuscateResult> {
    const emptyMapping: IdentifierMapping = {
      realToFake: new Map(),
      fakeToReal: new Map(),
    }

    const allTexts = messages.flatMap((msg) => {
      const content = extractContent(msg)
      if (typeof content === 'string') return [content]
      if (Array.isArray(content)) return extractStringContents(content)
      return []
    })

    const globalResult = buildGlobalMapping(allTexts, sessionKey)
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

  // ── Upstream forwarding ───────────────────────────────────────────────

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

  // ── Streaming ─────────────────────────────────────────────────────────

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

            // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
            const chunk = decoder.decode(readResult.value, { stream: true })
            const processed = deobfuscator.processChunk(chunk)
            if (processed !== '') {
              controller.enqueue(encoder.encode(processed))
            }
          }

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

  // ── Messages endpoint ─────────────────────────────────────────────────

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
        sessionId: sessionKey.sessionId,
        identifiersObfuscated: stats.identifiersObfuscated,
        numbersObfuscated: stats.numbersObfuscated,
        durationMs: Date.now() - startMs,
        streaming: isStreaming,
        upstreamStatus,
      }
      void writeAuditEntry(entry)
    }

    if (isStreaming) {
      return handleStreamingResponse(
        upstreamResponse, mapping, requestId, startMs, emitAudit,
      )
    }

    const responseText = await upstreamResponse.text()
    const deobfuscated = mappingSize > 0 ? deobfuscateText(responseText, mapping) : responseText

    logger.info('Request complete', { requestId, ms: Date.now() - startMs })
    emitAudit(upstreamResponse.status)

    return new Response(deobfuscated, {
      status: upstreamResponse.status,
      headers: filterResponseHeaders(upstreamResponse.headers),
    })
  }

  // ── Main fetch handler ────────────────────────────────────────────────

  return async function fetch(req: Request): Promise<Response> {
    const url = new URL(req.url)

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

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const contentLength = req.headers.get('content-length')
      if (contentLength !== null && parseInt(contentLength, 10) > MAX_BODY_BYTES) {
        return new Response('Request Entity Too Large', { status: 413 })
      }
    }

    return await globalThis.fetch(upstreamUrl.toString(), {
      method: req.method,
      headers: filterRequestHeaders(req.headers),
      body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
      redirect: 'manual',
    })
  }
}
