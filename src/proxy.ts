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
import { deriveSessionKey } from './honey/key-manager.ts'
import { obfuscateText, deobfuscateText } from './ast/mapper.ts'
import { logger } from './logger.ts'
import type { IdentifierMapping } from './types.ts'

// ── Config ───────────────────────────────────────────────────────────────────

const configResult = loadConfig()
if (!configResult.ok) {
  logger.error('Configuration error', { error: configResult.error.message })
  process.exit(1)
}

const config = configResult.value

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

// ── Anthropic message type (minimal surface) ─────────────────────────────────

interface AnthropicMessage {
  role: 'user' | 'assistant'
  content: string | unknown[]
}

interface AnthropicRequestBody {
  messages?: AnthropicMessage[]
  stream?: boolean
  [key: string]: unknown
}

// ── Request handling ─────────────────────────────────────────────────────────

function obfuscateMessages(
  messages: AnthropicMessage[],
): { messages: AnthropicMessage[]; mapping: IdentifierMapping } {
  const realToFake = new Map<string, string>()
  const fakeToReal = new Map<string, string>()

  const obfuscated = messages.map((msg) => {
    const content = typeof msg.content === 'string' ? msg.content : null
    if (content === null) return msg

    const result = obfuscateText(content, SESSION_KEY)

    // Merge mappings from this message
    for (const [real, fake] of result.mapping.realToFake) {
      realToFake.set(real, fake)
    }
    for (const [fake, real] of result.mapping.fakeToReal) {
      fakeToReal.set(fake, real)
    }

    return { ...msg, content: result.obfuscated }
  })

  return { messages: obfuscated, mapping: { realToFake, fakeToReal } }
}

async function forwardRequest(
  originalReq: Request,
  body: string,
): Promise<Response> {
  const url = new URL(originalReq.url)
  const upstreamUrl = config.upstreamBaseUrl + url.pathname + url.search

  const headers = new Headers()
  for (const [name, value] of originalReq.headers.entries()) {
    const lower = name.toLowerCase()
    // Pass through all headers except host (we supply it via the URL)
    if (lower !== 'host') {
      headers.set(name, value)
    }
  }
  // Ensure the real API key is used
  headers.set('x-api-key', config.anthropicApiKey)
  headers.set('anthropic-api-key', config.anthropicApiKey)

  return fetch(upstreamUrl, {
    method: originalReq.method,
    headers,
    body,
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
    logger.warn('Non-JSON body — forwarding as-is', { requestId })
    return forwardRequest(req, rawBody)
  }

  const messages = parsed.messages
  if (!Array.isArray(messages)) {
    return forwardRequest(req, rawBody)
  }

  const { messages: obfuscatedMessages, mapping } = obfuscateMessages(messages)

  const mappingSize = mapping.realToFake.size
  if (mappingSize > 0) {
    logger.info('Obfuscated identifiers', { requestId, count: mappingSize })
  }

  const outBody = JSON.stringify({ ...parsed, messages: obfuscatedMessages })
  const upstreamResponse = await forwardRequest(req, outBody)

  // ── Handle streaming (SSE) ────────────────────────────────────────────────

  const contentType = upstreamResponse.headers.get('content-type') ?? ''
  if (parsed.stream === true || contentType.includes('text/event-stream')) {
    return handleStreamingResponse(upstreamResponse, mapping, requestId, startMs)
  }

  // ── Handle buffered response ───────────────────────────────────────────────

  const responseText = await upstreamResponse.text()
  const deobfuscated = mappingSize > 0 ? deobfuscateText(responseText, mapping) : responseText

  logger.info('Request complete', { requestId, ms: Date.now() - startMs })

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
): Response {
  if (!upstreamResponse.body) {
    return upstreamResponse
  }

  const hasMappings = mapping.fakeToReal.size > 0
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
          const processed = hasMappings ? deobfuscateText(chunk, mapping) : chunk
          controller.enqueue(encoder.encode(processed))
        }

        // Flush remaining decoder state
        const tail = decoder.decode(undefined, { stream: false })
        if (tail) {
          const processed = hasMappings ? deobfuscateText(tail, mapping) : tail
          controller.enqueue(encoder.encode(processed))
        }

        logger.info('Stream complete', { requestId, ms: Date.now() - startMs })
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

// ── Bun HTTP server ──────────────────────────────────────────────────────────

const MESSAGES_PATH = '/v1/messages'

Bun.serve({
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
    const upstreamUrl = config.upstreamBaseUrl + url.pathname + url.search
    const headers = new Headers(req.headers)
    headers.set('x-api-key', config.anthropicApiKey)
    headers.set('anthropic-api-key', config.anthropicApiKey)
    headers.delete('host')

    return fetch(upstreamUrl, {
      method: req.method,
      headers,
      body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
    })
  },
})

logger.info('Honey proxy ready', {
  url: `http://127.0.0.1:${config.proxyPort}`,
  tip: `Set ANTHROPIC_BASE_URL=http://localhost:${config.proxyPort} in Claude Code`,
})
