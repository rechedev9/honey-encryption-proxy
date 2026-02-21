/**
 * Test proxy server for integration tests.
 *
 * Uses the extracted createProxyHandler to start a real Bun HTTP server
 * on port 0, pointing at a stub upstream. Does NOT call initAuditSigner
 * (avoids the ~2s SPHINCS+ keygen) unless explicitly requested.
 */

import { createProxyHandler } from '../../src/proxy-handler.ts'
import { deriveSessionKey } from '../../src/honey/key-manager.ts'
import { setLogLevel } from '../../src/logger.ts'
import type { SessionKey } from '../../src/types.ts'
import { TEST_PASSPHRASE, TEST_API_KEY } from './fixtures.ts'

// ── Types ───────────────────────────────────────────────────────────────────

export interface TestProxyServer {
  readonly url: string
  readonly port: number
  readonly sessionKey: SessionKey
  readonly stop: () => Promise<void>
}

export interface TestProxyOptions {
  readonly upstreamUrl: string
  readonly passphrase?: string
  readonly apiKey?: string
  readonly logLevel?: 'debug' | 'info' | 'warn' | 'error'
}

// ── Factory ─────────────────────────────────────────────────────────────────

/**
 * Starts a test proxy server backed by the given upstream URL.
 *
 * Key derivation runs once (~300ms for scrypt). Call this in beforeAll,
 * not per-test. Logs are suppressed by default (level: 'error').
 */
export function startTestProxy(options: TestProxyOptions): TestProxyServer {
  const passphrase = options.passphrase ?? TEST_PASSPHRASE
  const keyResult = deriveSessionKey(passphrase)
  if (!keyResult.ok) {
    throw new Error(`Test key derivation failed: ${keyResult.error.message}`)
  }

  setLogLevel(options.logLevel ?? 'error')

  const handler = createProxyHandler({
    sessionKey: keyResult.value,
    apiKey: options.apiKey ?? TEST_API_KEY,
    upstreamBaseUrl: options.upstreamUrl,
  })

  const server = Bun.serve({
    port: 0,
    hostname: '127.0.0.1',
    fetch: handler,
  })

  const actualPort = server.port ?? 0

  return {
    url: `http://127.0.0.1:${actualPort}`,
    port: actualPort,
    sessionKey: keyResult.value,
    async stop(): Promise<void> {
      await server.stop()
    },
  }
}
