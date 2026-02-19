/**
 * Configuration loader.
 *
 * Required env vars:
 *   ANTHROPIC_API_KEY  – real Anthropic key (forwarded to api.anthropic.com)
 *   HONEY_PASSPHRASE   – passphrase for session key derivation
 *
 * Optional env vars:
 *   PROXY_PORT         – local listen port (default 8080)
 *   ANTHROPIC_BASE_URL_UPSTREAM – upstream base URL (default https://api.anthropic.com)
 *   LOG_LEVEL          – debug | info | warn | error (default info)
 */

import { err, ok } from './types.ts'
import type { Result } from './types.ts'

export interface Config {
  readonly anthropicApiKey: string
  readonly honeyPassphrase: string
  readonly proxyPort: number
  readonly upstreamBaseUrl: string
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error'
}

const LOG_LEVELS = new Set(['debug', 'info', 'warn', 'error'])
const DEFAULT_PORT = 8080
const DEFAULT_UPSTREAM = 'https://api.anthropic.com'

export function loadConfig(): Result<Config> {
  const apiKey = process.env['ANTHROPIC_API_KEY']
  if (!apiKey) {
    return err(new Error('ANTHROPIC_API_KEY env var is required'))
  }

  const passphrase = process.env['HONEY_PASSPHRASE']
  if (!passphrase) {
    return err(new Error('HONEY_PASSPHRASE env var is required'))
  }

  const portStr = process.env['PROXY_PORT'] ?? String(DEFAULT_PORT)
  const port = parseInt(portStr, 10)
  if (isNaN(port) || port < 1 || port > 65535) {
    return err(new Error(`PROXY_PORT must be a valid port number, got: ${portStr}`))
  }

  const upstream = process.env['ANTHROPIC_BASE_URL_UPSTREAM'] ?? DEFAULT_UPSTREAM
  const rawLevel = process.env['LOG_LEVEL'] ?? 'info'
  const logLevel = LOG_LEVELS.has(rawLevel)
    ? (rawLevel as Config['logLevel'])
    : 'info'

  return ok({
    anthropicApiKey: apiKey,
    honeyPassphrase: passphrase,
    proxyPort: port,
    upstreamBaseUrl: upstream,
    logLevel,
  })
}
