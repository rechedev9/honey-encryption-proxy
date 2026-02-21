/**
 * Stub Anthropic API server for integration tests.
 *
 * A real Bun HTTP server on port 0 (OS-assigned) that mimics Anthropic's
 * /v1/messages endpoint. Returns configurable buffered or SSE responses
 * and captures the last request for assertions.
 */

import { makeAnthropicResponse, sseEvent } from './fixtures.ts'

// ── Types ───────────────────────────────────────────────────────────────────

export interface StubResponseConfig {
  readonly status?: number
  readonly body?: unknown
  readonly delay?: number
  readonly headers?: Record<string, string>
}

export interface StubSSEEvent {
  readonly data: string
  /** Milliseconds to wait before sending this event. */
  readonly delay?: number
}

export interface StubAnthropicServer {
  readonly url: string
  readonly port: number
  /** Returns the raw body of the last received request. */
  readonly lastRequestBody: () => unknown
  /** Returns the headers of the last received request. */
  readonly lastRequestHeaders: () => Headers
  /** Returns how many requests have been received. */
  readonly requestCount: () => number
  /** Configure the next buffered response. */
  readonly setResponse: (config: StubResponseConfig) => void
  /** Configure the next SSE streaming response. */
  readonly setStreamResponse: (events: readonly StubSSEEvent[]) => void
  /** Reset to default response and clear captured state. */
  readonly reset: () => void
  /** Stop the server. */
  readonly stop: () => Promise<void>
}

// ── Implementation ──────────────────────────────────────────────────────────

export function startStubServer(): StubAnthropicServer {
  let nextResponse: StubResponseConfig | null = null
  let nextStreamEvents: readonly StubSSEEvent[] | null = null
  let capturedBody: unknown = null
  let capturedHeaders: Headers = new Headers()
  let count = 0

  const defaultResponseText = 'The PaymentGateway class looks good.'

  const server = Bun.serve({
    port: 0,
    hostname: '127.0.0.1',

    async fetch(req: Request): Promise<Response> {
      const url = new URL(req.url)

      // Capture request data
      count++
      capturedHeaders = req.headers
      try {
        const text = await req.text()
        capturedBody = text !== '' ? JSON.parse(text) : null
      } catch {
        capturedBody = null
      }

      // ── GET passthrough (e.g. /v1/models) ─────────────────────────────
      if (req.method === 'GET') {
        if (url.pathname === '/v1/models') {
          return Response.json({
            object: 'list',
            data: [{ id: 'claude-haiku-4-5-20251001', object: 'model' }],
          })
        }
        return new Response('Not Found', { status: 404 })
      }

      // ── SSE streaming ─────────────────────────────────────────────────
      if (nextStreamEvents !== null) {
        const events = nextStreamEvents
        nextStreamEvents = null

        const stream = new ReadableStream<Uint8Array>({
          async start(controller: ReadableStreamDefaultController<Uint8Array>): Promise<void> {
            const encoder = new TextEncoder()
            for (const event of events) {
              if (event.delay !== undefined && event.delay > 0) {
                await new Promise<void>((resolve) => setTimeout(resolve, event.delay))
              }
              controller.enqueue(encoder.encode(sseEvent(event.data)))
            }
            controller.close()
          },
        })

        return new Response(stream, {
          status: 200,
          headers: { 'content-type': 'text/event-stream' },
        })
      }

      // ── Buffered JSON response ────────────────────────────────────────
      const cfg = nextResponse
      nextResponse = null

      if (cfg !== null) {
        if (cfg.delay !== undefined && cfg.delay > 0) {
          await new Promise<void>((resolve) => setTimeout(resolve, cfg.delay))
        }
        const responseHeaders: Record<string, string> = {
          'content-type': 'application/json',
          ...cfg.headers,
        }
        return new Response(
          typeof cfg.body === 'string' ? cfg.body : JSON.stringify(cfg.body ?? {}),
          { status: cfg.status ?? 200, headers: responseHeaders },
        )
      }

      // Default: echo a response that mentions identifiers from the request
      return Response.json(makeAnthropicResponse(defaultResponseText))
    },
  })

  const actualPort = server.port ?? 0
  const stubUrl = `http://127.0.0.1:${actualPort}`

  return {
    url: stubUrl,
    port: actualPort,
    lastRequestBody(): unknown {
      return capturedBody
    },
    lastRequestHeaders(): Headers {
      return capturedHeaders
    },
    requestCount(): number {
      return count
    },
    setResponse(config: StubResponseConfig): void {
      nextResponse = config
      nextStreamEvents = null
    },
    setStreamResponse(events: readonly StubSSEEvent[]): void {
      nextStreamEvents = events
      nextResponse = null
    },
    reset(): void {
      nextResponse = null
      nextStreamEvents = null
      capturedBody = null
      capturedHeaders = new Headers()
      count = 0
    },
    async stop(): Promise<void> {
      await server.stop()
    },
  }
}
