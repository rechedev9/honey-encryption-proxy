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
import { writeAuditEntry } from './audit.ts'
import { StreamDeobfuscator } from './stream-deobfuscator.ts'
import type { AuditEntry, IdentifierMapping } from './types.ts'

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
const keyResult = deriveSessionKey(config.honeyPassphrase)
if (!keyResult.ok) {
  logger.error('Key derivation failed', { error: keyResult.error.message })
  process.exit(1)
}

const SESSION_KEY = keyResult.value

logger.info('Honey proxy starting', {
  port: config.proxyPort,
  sessionId: SESSION_KEY.sessionId,
  upstream: config.upstreamBaseUrl,
})

// ── Anthropic message type (minimal surface) ───────────────────────────────────────────────

interface AnthropicMessage {
  role: 'user' | 'assistant'
  content: string | unknown[]
}

interface AnthropicRequestBody {
  messages?: AnthropicMessage[]
  stream?: boolean
  [key: string]: unknown
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

// ── Request handling ─────────────────────────────────────────────────────────────────────

interface ObfuscateResult {
  readonly messages: AnthropicMessage[]
  readonly mapping: IdentifierMapping
  readonly stats: ObfuscationStats
}

/**
 * Extracts all plain-text strings from a message content value.
 * Handles both string content and Anthropic's array-of-blocks format.
 */
function extractStringContents(content: unknown[]): readonly string[] {
  const result: string[] = []
  for (const item of content) {
    if (
      typeof item === 'object' &&
      item !== null &&
      'type' in item &&
      'text' in item &&
      (item as Record<string, unknown>)['type'] === 'text' &&
      typeof (item as Record<string, unknown>)['text'] === 'string'
    ) {
      const text = (item as Record<string, unknown>)['text']
      if (typeof text === 'string') {
        result.push(text)
      }
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
    if (
      typeof item === 'object' &&
      item !== null &&
      'type' in item &&
      'text' in item &&
      (item as Record<string, unknown>)['type'] === 'text' &&
      typeof (item as Record<string, unknown>)['text'] === 'string'
    ) {
      const record = item as Record<string, unknown>
      const text = record['text']
      if (typeof text === 'string') {
        const obfuscatedText = applyMappingToFullText(text, mapping, identifierRealToFake)
        return { ...record, text: obfuscatedText }
      }
    }
    return item
  })
}

function obfuscateMessages(messages: AnthropicMessage[]): ObfuscateResult {
  const emptyMapping: IdentifierMapping = {
    realToFake: new Map(),
    fakeToReal: new Map(),
  }

  // Step 1: collect all string contents across every message (handles both
  // string content and array-of-blocks format).
  const allTexts: string[] = []
  for (const msg of messages) {
    if (typeof msg.content === 'string') {
      allTexts.push(msg.content)
    } else if (Array.isArray(msg.content)) {
      for (const t of extractStringContents(msg.content)) {
        allTexts.push(t)
      }
    }
  }

  // Step 2: build one global mapping from code blocks across ALL messages.
  // This ensures assistant messages with no code blocks still get their
  // prose obfuscated using identifiers extracted from user messages.
  const { mapping, identifierRealToFake, stats } = buildGlobalMapping(allTexts, SESSION_KEY)

  if (mapping.realToFake.size === 0) {
    return { messages, mapping: emptyMapping, stats }
  }

  logger.debug('Built global mapping', {
    identifiers: stats.identifiersObfuscated,
    numbers: stats.numbersObfuscated,
  })

  // Step 3: apply the global mapping to EVERY message (code blocks + prose).
  const obfuscated = messages.map((msg) => {
    const obfuscatedContent = applyMappingToContent(
      msg.content,
      mapping,
      identifierRealToFake,
    )
    return { ...msg, content: obfuscatedContent }
  })

  return { messages: obfuscated, mapping, stats }
}

async function forwardRequest(
  originalReq: Request,
  body: string,
): Promise<Response> {
  const url = new URL(originalReq.url)
  const upstreamBase = new URL(config.upstreamBaseUrl)
  const upstreamUrl = new URL(url.pathname + url.search, upstreamBase.origin)

  // Guard: verify origin has not been manipulated
  if (upstreamUrl.origin !== upstreamBase.origin) {
    logger.error('Upstream URL origin mismatch — possible SSRF', {
      expected: upstreamBase.origin,
      got: upstreamUrl.origin,
    })
    return new Response('Internal Server Error', { status: 500 })
  }

  const headers = new Headers()
  // Only forward allow-listed headers; inject the real API key
  for (const [name, value] of originalReq.headers.entries()) {
    if (ALLOWED_REQUEST_HEADERS.has(name.toLowerCase())) {
      headers.set(name, value)
    }
  }
  headers.set('x-api-key', config.anthropicApiKey)

  return fetch(upstreamUrl.toString(), {
    method: originalReq.method,
    headers,
    body,
    redirect: 'manual',
  })
}

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

  let parsed: AnthropicRequestBody
  try {
    parsed = JSON.parse(rawBody) as AnthropicRequestBody
  } catch (e) {
    logger.warn('Non-JSON body on /v1/messages — rejecting', { requestId })
    return new Response('Bad Request: /v1/messages requires a JSON body', { status: 400 })
  }

  const messages = parsed.messages
  if (!Array.isArray(messages)) {
    return forwardRequest(req, rawBody)
  }

  const { messages: obfuscatedMessages, mapping, stats } = obfuscateMessages(messages)

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
    headers: upstreamResponse.headers,
  })
}

function handleStreamingResponse(
  upstreamResponse: Response,
  mapping: IdentifierMapping,
  requestId: string,
  startMs: number,
  emitAudit: (upstreamStatus: number) => void,
): Response {
  if (!upstreamResponse.body) {
    return upstreamResponse
  }

  const deobfuscator = new StreamDeobfuscator(mapping)
  const decoder = new TextDecoder()
  const encoder = new TextEncoder()

  const upstreamBody = upstreamResponse.body

  const transformedBody = new ReadableStream<Uint8Array>({
    async start(controller) {
      const reader = upstreamBody.getReader()
      try {
        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          const chunk = decoder.decode(value, { stream: true })
          const processed = deobfuscator.processChunk(chunk)
          if (processed) {
            controller.enqueue(encoder.encode(processed))
          }
        }

        // Flush remaining decoder + deobfuscator state
        const tail = decoder.decode(undefined, { stream: false })
        if (tail) {
          const processed = deobfuscator.processChunk(tail)
          if (processed) {
            controller.enqueue(encoder.encode(processed))
          }
        }
        const flushed = deobfuscator.flush()
        if (flushed) {
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
    headers: upstreamResponse.headers,
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
    const url2 = new URL(req.url)
    const upstreamBase2 = new URL(config.upstreamBaseUrl)
    const upstreamUrl2 = new URL(url2.pathname + url2.search, upstreamBase2.origin)

    if (upstreamUrl2.origin !== upstreamBase2.origin) {
      logger.error('Passthrough URL origin mismatch', { got: upstreamUrl2.origin })
      return new Response('Internal Server Error', { status: 500 })
    }

    const passthroughHeaders = new Headers()
    for (const [name, value] of req.headers.entries()) {
      if (ALLOWED_REQUEST_HEADERS.has(name.toLowerCase())) {
        passthroughHeaders.set(name, value)
      }
    }
    passthroughHeaders.set('x-api-key', config.anthropicApiKey)

    return fetch(upstreamUrl2.toString(), {
      method: req.method,
      headers: passthroughHeaders,
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
  server.stop()
  logger.info('Server stopped')
}

process.on('SIGINT', () => handleShutdown('SIGINT'))
process.on('SIGTERM', () => handleShutdown('SIGTERM'))

logger.info('Honey proxy ready', {
  url: `http://127.0.0.1:${config.proxyPort}`,
  tip: `Set ANTHROPIC_BASE_URL=http://localhost:${config.proxyPort} in Claude Code`,
})
