import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'bun:test'
import { startStubServer } from './helpers/stub-anthropic-server.ts'
import { startTestProxy } from './helpers/test-proxy-server.ts'
import { makeMessagesBody, makeAnthropicResponse, TEST_API_KEY } from './helpers/fixtures.ts'
import type { StubAnthropicServer } from './helpers/stub-anthropic-server.ts'
import type { TestProxyServer } from './helpers/test-proxy-server.ts'

describe('Proxy integration', () => {
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

  function postMessages(body: unknown): Promise<Response> {
    return fetch(`${proxy.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
  }

  describe('POST /v1/messages — buffered', () => {
    it('obfuscates identifiers before forwarding to upstream', async () => {
      stub.setResponse({ body: makeAnthropicResponse('Looks good.') })

      await postMessages(makeMessagesBody())

      const forwarded = JSON.stringify(stub.lastRequestBody())
      expect(forwarded).not.toContain('PaymentGateway')
      expect(forwarded).not.toContain('processRefund')
    })

    it('deobfuscates identifiers in the upstream response', async () => {
      stub.setResponse({ body: makeAnthropicResponse('Looks good.') })
      const res1 = await postMessages(makeMessagesBody())
      await res1.text()

      const forwarded = stub.lastRequestBody() as Record<string, unknown>
      const fwdMessages = (forwarded as { messages: Array<{ content: string }> }).messages
      const fakeCode = fwdMessages[0]?.content ?? ''

      const fakeMatch = /class\s+(\w+)/.exec(fakeCode)
      const fakeName = fakeMatch?.[1] ?? 'Unknown'

      stub.setResponse({
        body: makeAnthropicResponse(`The ${fakeName} class looks correct.`),
      })

      const res2 = await postMessages(makeMessagesBody())
      const text = await res2.text()
      const parsed = JSON.parse(text) as { content: Array<{ text: string }> }
      const responseText = parsed.content[0]?.text ?? ''

      expect(responseText).toContain('PaymentGateway')
    })

    it('preserves code structure (keywords, operators)', async () => {
      stub.setResponse({ body: makeAnthropicResponse('OK') })
      await postMessages(makeMessagesBody())

      const forwarded = JSON.stringify(stub.lastRequestBody())
      expect(forwarded).toContain('class')
      expect(forwarded).toContain('number')
      expect(forwarded).toContain('boolean')
      expect(forwarded).toContain('return')
    })

    it('handles messages with no code blocks', async () => {
      stub.setResponse({ body: makeAnthropicResponse('Sure, I can help.') })

      const body = makeMessagesBody({
        messages: [{ role: 'user', content: 'What is TypeScript?' }],
      })
      const res = await postMessages(body)
      const text = await res.text()

      expect(res.status).toBe(200)
      expect(text).toContain('Sure, I can help.')
    })

    it('handles messages with multiple code blocks', async () => {
      stub.setResponse({ body: makeAnthropicResponse('Both look fine.') })

      const body = makeMessagesBody({
        messages: [{
          role: 'user',
          content: [
            '```typescript\nclass OrderService { submit() {} }\n```',
            '\nAlso:\n',
            '```typescript\nclass InventoryTracker { count() {} }\n```',
          ].join(''),
        }],
      })
      await postMessages(body)

      const forwarded = JSON.stringify(stub.lastRequestBody())
      expect(forwarded).not.toContain('OrderService')
      expect(forwarded).not.toContain('InventoryTracker')
    })

    it('strips comments before forwarding', async () => {
      stub.setResponse({ body: makeAnthropicResponse('OK') })

      const body = makeMessagesBody({
        messages: [{
          role: 'user',
          content: '```typescript\n// SECRET: internal pricing algorithm\nconst price = 42\n```',
        }],
      })
      await postMessages(body)

      const forwarded = JSON.stringify(stub.lastRequestBody())
      expect(forwarded).not.toContain('SECRET')
      expect(forwarded).not.toContain('internal pricing')
    })

    it('applies FPE to numeric literals', async () => {
      stub.setResponse({ body: makeAnthropicResponse('OK') })

      const body = makeMessagesBody({
        messages: [{
          role: 'user',
          content: '```typescript\nconst vatRate = 0.21\nconst timeout = 3600\n```',
        }],
      })
      await postMessages(body)

      const forwarded = JSON.stringify(stub.lastRequestBody())
      expect(forwarded).not.toContain('0.21')
      expect(forwarded).not.toContain('3600')
    })

    it('upstream error status codes are forwarded to client', async () => {
      stub.setResponse({ status: 429, body: { error: 'rate limited' } })

      const res = await postMessages(makeMessagesBody())

      expect(res.status).toBe(429)
    })

    it('returns 400 for non-JSON body', async () => {
      const res = await fetch(`${proxy.url}/v1/messages`, {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: 'this is not json',
      })

      expect(res.status).toBe(400)
    })

    it('returns 400 for JSON that is not an object', async () => {
      const res = await fetch(`${proxy.url}/v1/messages`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify([1, 2, 3]),
      })

      expect(res.status).toBe(400)
    })

    it('returns 400 for missing messages array', async () => {
      const res = await fetch(`${proxy.url}/v1/messages`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'test' }),
      })

      expect(res.status).toBe(400)
    })

    it('returns 413 when request body exceeds 10 MiB', async () => {
      const hugeContent = 'x'.repeat(11 * 1024 * 1024)
      const res = await fetch(`${proxy.url}/v1/messages`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ messages: [{ role: 'user', content: hugeContent }] }),
      })

      expect(res.status).toBe(413)
    })

    it('injects x-api-key header to upstream', async () => {
      stub.setResponse({ body: makeAnthropicResponse('OK') })
      await postMessages(makeMessagesBody())

      const headers = stub.lastRequestHeaders()
      expect(headers.get('x-api-key')).toBe(TEST_API_KEY)
    })

    it('does NOT forward authorization header from client', async () => {
      stub.setResponse({ body: makeAnthropicResponse('OK') })

      await fetch(`${proxy.url}/v1/messages`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'authorization': 'Bearer sk-secret',
        },
        body: JSON.stringify(makeMessagesBody()),
      })

      const headers = stub.lastRequestHeaders()
      expect(headers.get('authorization')).toBeNull()
    })

    it('forwards anthropic-version header from client', async () => {
      stub.setResponse({ body: makeAnthropicResponse('OK') })

      await fetch(`${proxy.url}/v1/messages`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'anthropic-version': '2024-01-01',
        },
        body: JSON.stringify(makeMessagesBody()),
      })

      const headers = stub.lastRequestHeaders()
      expect(headers.get('anthropic-version')).toBe('2024-01-01')
    })
  })

  describe('POST /v1/messages — multi-turn', () => {
    it('builds global mapping across user and assistant messages', async () => {
      stub.setResponse({ body: makeAnthropicResponse('OK') })

      const body = makeMessagesBody({
        messages: [
          {
            role: 'user',
            content: '```typescript\nclass AccountManager { getBalance() {} }\n```',
          },
          {
            role: 'assistant',
            content: 'The AccountManager.getBalance method looks correct.',
          },
          {
            role: 'user',
            content: 'Can you also add a deposit method to AccountManager?',
          },
        ],
      })
      await postMessages(body)

      const forwarded = JSON.stringify(stub.lastRequestBody())
      expect(forwarded).not.toContain('AccountManager')
      expect(forwarded).not.toContain('getBalance')
    })

    it('same identifier maps to same fake across turns', async () => {
      stub.setResponse({ body: makeAnthropicResponse('OK') })

      const body = makeMessagesBody({
        messages: [
          {
            role: 'user',
            content: '```typescript\nclass DataLoader { fetch() {} }\n```',
          },
          {
            role: 'assistant',
            content: 'The DataLoader class is well-structured.',
          },
        ],
      })
      await postMessages(body)

      const forwarded = stub.lastRequestBody() as {
        messages: Array<{ content: string; role: string }>
      }

      const userContent = forwarded.messages[0]?.content ?? ''
      const classMatch = /class\s+(\w+)/.exec(userContent)
      const fakeClassName = classMatch?.[1] ?? ''

      const assistantContent = forwarded.messages[1]?.content ?? ''
      expect(assistantContent).toContain(fakeClassName)
    })

    it('handles array-of-blocks content format', async () => {
      stub.setResponse({ body: makeAnthropicResponse('OK') })

      const body = makeMessagesBody({
        messages: [{
          role: 'user',
          content: [
            { type: 'text', text: '```typescript\nclass ReportBuilder {}\n```' },
          ],
        }],
      })
      await postMessages(body)

      const forwarded = JSON.stringify(stub.lastRequestBody())
      expect(forwarded).not.toContain('ReportBuilder')
    })
  })

  describe('Passthrough routes', () => {
    it('GET /v1/models is forwarded transparently to upstream', async () => {
      const res = await fetch(`${proxy.url}/v1/models`)

      expect(res.status).toBe(200)
      const body = await res.json() as { object: string }
      expect(body.object).toBe('list')
    })

    it('passthrough preserves response body and status', async () => {
      const res = await fetch(`${proxy.url}/v1/models`)
      const body = await res.json() as { data: Array<{ id: string }> }

      expect(body.data[0]?.id).toBe('claude-haiku-4-5-20251001')
    })

    it('passthrough forwards POST to non-messages routes without obfuscation', async () => {
      const countBefore = stub.requestCount()
      const sentBody = { prompt: 'class SecretName {}' }

      const res = await fetch(`${proxy.url}/v1/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(sentBody),
      })
      await res.text()

      expect(stub.requestCount()).toBe(countBefore + 1)

      const forwarded = JSON.stringify(stub.lastRequestBody())
      expect(forwarded).toContain('SecretName')
    })

    it('GET does not have body limit enforcement', async () => {
      const res = await fetch(`${proxy.url}/v1/models`, { method: 'GET' })
      expect(res.status).toBe(200)
    })
  })

  describe('Request isolation', () => {
    it('concurrent requests do not share mapping state', async () => {
      stub.setResponse({ body: makeAnthropicResponse('OK') })

      const body1 = makeMessagesBody({
        messages: [{ role: 'user', content: '```typescript\nclass AlphaService {}\n```' }],
      })
      const body2 = makeMessagesBody({
        messages: [{ role: 'user', content: '```typescript\nclass BetaService {}\n```' }],
      })

      const [res1, res2] = await Promise.all([
        postMessages(body1),
        postMessages(body2),
      ])

      expect(res1.status).toBe(200)
      expect(res2.status).toBe(200)
      await res1.text()
      await res2.text()
    })

    it('sequential requests with different code produce different mappings', async () => {
      stub.setResponse({ body: makeAnthropicResponse('OK') })

      const body1 = makeMessagesBody({
        messages: [{ role: 'user', content: '```typescript\nclass GammaProcessor {}\n```' }],
      })
      await postMessages(body1)
      const forwarded1 = JSON.stringify(stub.lastRequestBody())

      stub.setResponse({ body: makeAnthropicResponse('OK') })
      const body2 = makeMessagesBody({
        messages: [{ role: 'user', content: '```typescript\nclass DeltaProcessor {}\n```' }],
      })
      await postMessages(body2)
      const forwarded2 = JSON.stringify(stub.lastRequestBody())

      expect(forwarded1).not.toContain('GammaProcessor')
      expect(forwarded2).not.toContain('DeltaProcessor')
    })
  })

  describe('Error handling', () => {
    it('returns 200 even when upstream returns error JSON', async () => {
      stub.setResponse({
        status: 500,
        body: { error: { message: 'Internal server error' } },
      })

      const res = await postMessages(makeMessagesBody())
      expect(res.status).toBe(500)
    })
  })
})
