/**
 * SSE streaming integration tests.
 *
 * These tests verify that the proxy correctly handles streaming responses
 * from the Anthropic API, including chunk-boundary deobfuscation, [DONE]
 * terminators, and response headers.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'bun:test'
import { startStubServer } from './helpers/stub-anthropic-server.ts'
import { startTestProxy } from './helpers/test-proxy-server.ts'
import {
  makeMessagesBody,
  makeAnthropicResponse,
  consumeSSEStream,
  consumeSSEText,
} from './helpers/fixtures.ts'
import type { StubAnthropicServer } from './helpers/stub-anthropic-server.ts'
import type { TestProxyServer } from './helpers/test-proxy-server.ts'

describe('Streaming integration (SSE)', () => {
  let stub: StubAnthropicServer
  let proxy: TestProxyServer

  beforeAll(() => {
    stub = startStubServer()
    proxy = startTestProxy({ upstreamUrl: stub.url })
  })

  afterAll(async () => {
    await proxy.stop()
    await stub.stop()
  })

  beforeEach(() => {
    stub.reset()
  })

  function postStreaming(body: unknown): Promise<Response> {
    return fetch(`${proxy.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
  }

  // ── Basic streaming ───────────────────────────────────────────────────

  describe('basic streaming', () => {
    it('streams SSE events from upstream to client', async () => {
      stub.setStreamResponse([
        { data: '{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}' },
        { data: '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}' },
        { data: '{"type":"content_block_stop","index":0}' },
        { data: '{"type":"message_stop"}' },
        { data: '[DONE]' },
      ])

      const body = makeMessagesBody({ stream: true })
      const res = await postStreaming(body)
      const events = await consumeSSEStream(res)

      expect(events.length).toBeGreaterThanOrEqual(3)
      expect(events).toContain('[DONE]')
    })

    it('deobfuscates identifiers in streamed text events', async () => {
      // Step 1: discover the fake name via a fast buffered request
      stub.setResponse({
        body: makeAnthropicResponse('Noted.'),
      })
      const setupRes = await fetch(`${proxy.url}/v1/messages`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(makeMessagesBody()),
      })
      await setupRes.text()

      const forwarded = stub.lastRequestBody() as {
        messages: Array<{ content: string }>
      }
      const fakeCode = forwarded.messages[0]?.content ?? ''
      const classMatch = /class\s+(\w+)/.exec(fakeCode)
      const fakeName = classMatch?.[1] ?? ''
      expect(fakeName).not.toBe('')
      expect(fakeName).not.toBe('PaymentGateway')

      // Step 2: stream a response containing the fake name
      stub.setStreamResponse([
        { data: `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"The ${fakeName} class is well-designed."}}` },
        { data: '[DONE]' },
      ])

      const res = await postStreaming(makeMessagesBody({ stream: true }))
      const text = await consumeSSEText(res)

      expect(text).toContain('PaymentGateway')
      expect(text).not.toContain(fakeName)
    })

    it('handles [DONE] terminator', async () => {
      stub.setStreamResponse([
        { data: '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}' },
        { data: '[DONE]' },
      ])

      const res = await postStreaming(makeMessagesBody({ stream: true }))
      const events = await consumeSSEStream(res)

      expect(events[events.length - 1]).toBe('[DONE]')
    })

    it('empty mapping streams events unchanged', async () => {
      stub.setStreamResponse([
        { data: '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"No code here"}}' },
        { data: '[DONE]' },
      ])

      // Message with no code blocks → empty mapping → passthrough
      const body = makeMessagesBody({
        messages: [{ role: 'user', content: 'Hello, how are you?' }],
        stream: true,
      })
      const res = await postStreaming(body)
      const text = await consumeSSEText(res)

      expect(text).toBe('No code here')
    })
  })

  // ── Response headers ──────────────────────────────────────────────────

  describe('response headers', () => {
    it('streaming response includes correct content-type', async () => {
      stub.setStreamResponse([
        { data: '{"type":"message_stop"}' },
        { data: '[DONE]' },
      ])

      const res = await postStreaming(makeMessagesBody({ stream: true }))
      await res.text() // consume

      expect(res.headers.get('content-type')).toBe('text/event-stream')
    })

    it('streaming response filters headers through allowlist', async () => {
      stub.setStreamResponse([
        { data: '[DONE]' },
      ])

      const res = await postStreaming(makeMessagesBody({ stream: true }))
      await res.text() // consume

      // x-request-id is NOT in the allowlist → should not appear
      expect(res.headers.get('x-request-id')).toBeNull()
    })
  })

  // ── Edge cases ────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('stream: true in request body triggers streaming path', async () => {
      stub.setStreamResponse([
        { data: '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"streamed"}}' },
        { data: '[DONE]' },
      ])

      const body = makeMessagesBody({
        messages: [{ role: 'user', content: 'Hi' }],
        stream: true,
      })
      const res = await postStreaming(body)
      const events = await consumeSSEStream(res)

      // Should receive SSE events, not a buffered JSON response
      expect(events.length).toBeGreaterThanOrEqual(1)
    })

    it('handles multiple text deltas in sequence', async () => {
      stub.setStreamResponse([
        { data: '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello "}}' },
        { data: '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world"}}' },
        { data: '[DONE]' },
      ])

      const body = makeMessagesBody({
        messages: [{ role: 'user', content: 'Say hello' }],
        stream: true,
      })
      const res = await postStreaming(body)
      const text = await consumeSSEText(res)

      expect(text).toBe('Hello world')
    })

    it('handles upstream null body for stream gracefully', async () => {
      // Configure stub to return a streaming content-type but with status 500
      // which typically has no body
      stub.setResponse({
        status: 500,
        body: '',
        headers: { 'content-type': 'text/event-stream' },
      })

      const body = makeMessagesBody({ stream: true })
      const res = await postStreaming(body)

      // Should not crash — returns the upstream status
      expect(res.status).toBe(500)
    })
  })
})
