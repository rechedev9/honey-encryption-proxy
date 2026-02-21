/**
 * Honey Encryption Proxy for Claude Code — entry point.
 *
 * This file is a thin shell: load config → derive keys → start server.
 * All request-handling logic lives in proxy-handler.ts so integration
 * tests can construct a handler without triggering these side effects.
 *
 * Run with:
 *   ANTHROPIC_API_KEY=sk-ant-... HONEY_PASSPHRASE=secret bun run src/proxy.ts
 *
 * Then configure Claude Code:
 *   export ANTHROPIC_BASE_URL=http://localhost:8080
 */

import { loadConfig } from './config.ts'
import { deriveSessionKey, zeroSessionKey } from './honey/key-manager.ts'
import { logger, setLogLevel } from './logger.ts'
import { initAuditSigner } from './audit.ts'
import { initTreeSitter } from './ast/tree-sitter.ts'
import { createProxyHandler } from './proxy-handler.ts'

// ── Config ──────────────────────────────────────────────────────────────────

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

// ── Bun HTTP server ─────────────────────────────────────────────────────────

const handler = createProxyHandler({
  sessionKey: SESSION_KEY,
  apiKey: config.anthropicApiKey,
  upstreamBaseUrl: config.upstreamBaseUrl,
})

const server = Bun.serve({
  port: config.proxyPort,
  hostname: '127.0.0.1',
  fetch: handler,
})

// ── Graceful shutdown ───────────────────────────────────────────────────────

function handleShutdown(signal: string): void {
  logger.info('Shutdown initiated', { signal })
  zeroSessionKey(SESSION_KEY)
  void server.stop()
  logger.info('Server stopped')
}

process.on('SIGINT', () => {
  handleShutdown('SIGINT')
})
process.on('SIGTERM', () => {
  handleShutdown('SIGTERM')
})

const actualPort = server.port ?? config.proxyPort
logger.info('Honey proxy ready', {
  url: `http://127.0.0.1:${actualPort}`,
  tip: `Set ANTHROPIC_BASE_URL=http://localhost:${actualPort} in Claude Code`,
})
