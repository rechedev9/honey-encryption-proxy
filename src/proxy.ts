import { loadConfig } from './config.ts'
import { deriveSessionKey, zeroSessionKey } from './honey/key-manager.ts'
import { logger, setLogLevel } from './logger.ts'
import { initAuditSigner } from './audit.ts'
import { initTreeSitter } from './ast/tree-sitter.ts'
import { createProxyHandler } from './proxy-handler.ts'

const configResult = loadConfig()
if (!configResult.ok) {
  logger.error('Configuration error', { error: configResult.error.message })
  process.exit(1)
}

const config = configResult.value
setLogLevel(config.logLevel)

const kyberCapsule = config.honeyKyberCapsule !== undefined
  ? Buffer.from(config.honeyKyberCapsule, 'base64url')
  : undefined
const keyResult = deriveSessionKey(config.honeyPassphrase, kyberCapsule)
if (!keyResult.ok) {
  logger.error('Key derivation failed', { error: keyResult.error.message })
  process.exit(1)
}

const SESSION_KEY = keyResult.value

initAuditSigner(SESSION_KEY.macKey)

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
