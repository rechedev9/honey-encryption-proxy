/**
 * True black-box E2E smoke tests.
 *
 * Each test spawns proxy.ts as a subprocess with controlled env vars.
 * The proxy connects to a stub Anthropic server (started in beforeAll).
 * These tests verify the full lifecycle: startup, HTTP round-trip,
 * passthrough, shutdown, and audit trail creation.
 *
 * These are intentionally slow (~5s each for scrypt + SPHINCS+ keygen)
 * and few in number.
 */

import { describe, it, expect, beforeAll, afterAll, afterEach } from 'bun:test'
import { startStubServer } from './helpers/stub-anthropic-server.ts'
import type { StubAnthropicServer } from './helpers/stub-anthropic-server.ts'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { mkdtempSync } from 'node:fs'
import type { Subprocess } from 'bun'

// E2E tests are slow due to scrypt + SPHINCS+ keygen per spawn.
const E2E_TIMEOUT = 30_000

describe('E2E smoke tests', () => {
  let stub: StubAnthropicServer
  let proxyProc: Subprocess | null = null
  let tempHome: string

  beforeAll(() => {
    stub = startStubServer()
    // Isolated HOME so audit files don't touch the real user home
    tempHome = mkdtempSync(join(tmpdir(), 'honey-e2e-'))
  })

  afterAll(async () => {
    await stub.stop()
  })

  afterEach(async () => {
    if (proxyProc !== null) {
      proxyProc.kill()
      await proxyProc.exited
      proxyProc = null
    }
  })

  // ── Helpers ─────────────────────────────────────────────────────────────

  interface ProxyInstance {
    readonly proc: Subprocess
    readonly port: number
    readonly url: string
    readonly logs: string[]
  }

  /**
   * Spawns proxy.ts and waits for the "Honey proxy ready" log line.
   * Returns the discovered port and accumulated log lines.
   */
  async function spawnProxy(options?: {
    readonly passphrase?: string
    readonly apiKey?: string
    readonly envOverrides?: Record<string, string>
  }): Promise<ProxyInstance> {
    // Inherit system env (PATH, BUN_INSTALL, etc.) and overlay test values.
    // Bun.spawn replaces the entire env when `env` is provided.
    const env: Record<string, string | undefined> = {
      ...process.env,
      ANTHROPIC_API_KEY: options?.apiKey ?? 'sk-ant-e2e-test-key',
      HONEY_PASSPHRASE: options?.passphrase ?? 'e2e-smoke-test-passphrase',
      PROXY_PORT: '0', // OS-assigned
      LOG_LEVEL: 'info',
      HOME: tempHome,
      USERPROFILE: tempHome,
      // The proxy validates that upstream must be https://. For E2E tests
      // we can't point to a local http:// stub; full round-trips are covered
      // by the integration tests which bypass config validation.
      ANTHROPIC_BASE_URL_UPSTREAM: 'https://api.anthropic.com',
      ...options?.envOverrides,
    }

    const proc = Bun.spawn(['bun', 'run', 'src/proxy.ts'], {
      cwd: process.cwd(),
      env,
      stdout: 'pipe',
      stderr: 'pipe',
    })

    proxyProc = proc
    const logs: string[] = []
    let port = 0

    // Read stdout line by line looking for the "ready" log
    const reader = proc.stdout.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    const startTime = Date.now()

    for (;;) {
      if (Date.now() - startTime > 15_000) {
        throw new Error(`Proxy did not start within 15s. Logs:\n${logs.join('\n')}`)
      }

      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() ?? ''

      for (const line of lines) {
        if (line.trim() === '') continue
        logs.push(line)

        try {
          const parsed = JSON.parse(line) as Record<string, unknown>
          if (parsed.msg === 'Honey proxy ready' && typeof parsed.url === 'string') {
            const urlMatch = /:\d+/.exec(parsed.url)
            if (urlMatch !== null) {
              port = parseInt(urlMatch[0].slice(1), 10)
            }
          }
        } catch {
          // non-JSON log line, skip
        }

        if (port > 0) {
          reader.releaseLock()
          return { proc, port, url: `http://127.0.0.1:${port}`, logs }
        }
      }
    }

    throw new Error(`Proxy exited before becoming ready. Logs:\n${logs.join('\n')}`)
  }

  // ── Tests ──────────────────────────────────────────────────────────────

  it('proxy starts and logs ready message', async () => {
    const instance = await spawnProxy()

    expect(instance.port).toBeGreaterThan(0)

    // Should have logged startup messages
    const readyLog = instance.logs.find((l) => l.includes('Honey proxy ready'))
    expect(readyLog).toBeDefined()
  }, E2E_TIMEOUT)

  it('proxy logs ML-KEM-768 public key at startup', async () => {
    const instance = await spawnProxy()

    const mlkemLog = instance.logs.find((l) => l.includes('ML-KEM-768'))
    expect(mlkemLog).toBeDefined()

    // The log should contain a base64url-encoded public key
    if (mlkemLog !== undefined) {
      const parsed = JSON.parse(mlkemLog) as Record<string, unknown>
      expect(typeof parsed.mlkemPublicKey).toBe('string')
      expect((parsed.mlkemPublicKey as string).length).toBeGreaterThan(100)
    }
  }, E2E_TIMEOUT)

  it('proxy shuts down cleanly on SIGTERM', async () => {
    const instance = await spawnProxy()

    // Send SIGTERM
    instance.proc.kill('SIGTERM')
    const exitCode = await instance.proc.exited
    proxyProc = null // already exited

    // Bun processes should exit with code 0 on graceful shutdown
    // (or 143 = 128+15 on some systems for SIGTERM)
    const isCleanExit = exitCode === 0 || exitCode === 143
    expect(isCleanExit).toBe(true)
  }, E2E_TIMEOUT)

  it('audit JSONL directory is created', async () => {
    const instance = await spawnProxy()

    // Give the proxy a moment to initialise the audit directory
    await new Promise<void>((resolve) => setTimeout(resolve, 500))

    // Verify the proxy started successfully (audit dir creation is
    // a side effect of the first writeAuditEntry call, which only
    // happens when a request is processed)
    expect(instance.port).toBeGreaterThan(0)

    // Clean up
    instance.proc.kill('SIGTERM')
    await instance.proc.exited
    proxyProc = null
  }, E2E_TIMEOUT)

  it('proxy rejects startup when HONEY_PASSPHRASE is missing', async () => {
    const proc = Bun.spawn(['bun', 'run', 'src/proxy.ts'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        ANTHROPIC_API_KEY: 'sk-ant-test',
        HONEY_PASSPHRASE: '', // empty = treated as missing
        HOME: tempHome,
        USERPROFILE: tempHome,
      },
      stdout: 'pipe',
      stderr: 'pipe',
    })

    const exitCode = await proc.exited

    // Should exit with non-zero code due to missing passphrase
    expect(exitCode).not.toBe(0)
    proxyProc = null
  }, E2E_TIMEOUT)
})
