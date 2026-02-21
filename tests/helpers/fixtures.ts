/**
 * Shared test data and utilities for integration / E2E tests.
 */

/** Fixed passphrase for deterministic test key derivation. */
export const TEST_PASSPHRASE = 'integration-test-passphrase-32chars!'

/** Fixed API key for test requests (never hits a real API). */
export const TEST_API_KEY = 'sk-ant-test-key-for-integration'

/** Default model for test fixtures. */
export const TEST_MODEL = 'claude-haiku-4-5-20251001'

/**
 * Builds a minimal Anthropic /v1/messages request body.
 */
export function makeMessagesBody(options?: {
  readonly messages?: ReadonlyArray<Record<string, unknown>>
  readonly stream?: boolean
  readonly model?: string
}): Record<string, unknown> {
  return {
    model: options?.model ?? TEST_MODEL,
    max_tokens: 1024,
    messages: options?.messages ?? [
      {
        role: 'user',
        content: '```typescript\nclass PaymentGateway {\n  processRefund(amount: number): boolean { return amount > 0 }\n}\n```',
      },
    ],
    ...(options?.stream === true ? { stream: true } : {}),
  }
}

/** Builds a stub Anthropic JSON response body. */
export function makeAnthropicResponse(text: string): Record<string, unknown> {
  return {
    id: `msg_test_${crypto.randomUUID().slice(0, 8)}`,
    type: 'message',
    role: 'assistant',
    content: [{ type: 'text', text }],
    model: TEST_MODEL,
    stop_reason: 'end_turn',
    usage: { input_tokens: 10, output_tokens: 20 },
  }
}

/** Formats a string as an SSE data line with the standard `\n\n` delimiter. */
export function sseEvent(data: string): string {
  return `data: ${data}\n\n`
}

/**
 * Consumes an SSE response stream and returns all `data:` payloads.
 * Strips the `data: ` prefix and the trailing newlines from each event.
 */
export async function consumeSSEStream(response: Response): Promise<readonly string[]> {
  const text = await response.text()
  return text
    .split('\n\n')
    .filter((line) => line.startsWith('data: '))
    .map((line) => line.slice('data: '.length))
}

/**
 * Consumes an SSE response stream and returns the concatenated text
 * from all `content_block_delta` events.
 */
export async function consumeSSEText(response: Response): Promise<string> {
  const events = await consumeSSEStream(response)
  let text = ''
  for (const raw of events) {
    if (raw === '[DONE]') break
    try {
      const parsed: unknown = JSON.parse(raw)
      if (
        typeof parsed === 'object' && parsed !== null &&
        'delta' in parsed
      ) {
        const delta: unknown = (parsed as Record<string, unknown>).delta
        if (
          typeof delta === 'object' && delta !== null &&
          'text' in delta &&
          typeof (delta as Record<string, unknown>).text === 'string'
        ) {
          text += String((delta as Record<string, unknown>).text)
        }
      }
    } catch {
      // non-JSON event, skip
    }
  }
  return text
}
