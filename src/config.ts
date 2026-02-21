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
  /** Base64url-encoded ML-KEM-768 ciphertext for hybrid key strengthening. */
  readonly honeyKyberCapsule?: string
}

type LogLevel = Config['logLevel']
const LOG_LEVELS: ReadonlySet<string> = new Set<LogLevel>(['debug', 'info', 'warn', 'error'])

function isLogLevel(value: string): value is LogLevel {
  return LOG_LEVELS.has(value)
}

const DEFAULT_PORT = 8080
const DEFAULT_UPSTREAM = 'https://api.anthropic.com'

export function loadConfig(): Result<Config> {
  const apiKey = process.env.ANTHROPIC_API_KEY
  if (apiKey === undefined || apiKey === '') {
    return err(new Error('ANTHROPIC_API_KEY env var is required'))
  }

  const passphrase = process.env.HONEY_PASSPHRASE
  if (passphrase === undefined || passphrase === '') {
    return err(new Error('HONEY_PASSPHRASE env var is required'))
  }

  const portStr = process.env.PROXY_PORT ?? String(DEFAULT_PORT)
  const port = parseInt(portStr, 10)
  if (isNaN(port) || port < 0 || port > 65535) {
    return err(new Error(`PROXY_PORT must be a valid port number, got: ${portStr}`))
  }

  const upstream = process.env.ANTHROPIC_BASE_URL_UPSTREAM ?? DEFAULT_UPSTREAM
  let parsedUpstream: URL
  try {
    parsedUpstream = new URL(upstream)
  } catch {
    return err(new Error(`ANTHROPIC_BASE_URL_UPSTREAM is not a valid URL: ${upstream}`))
  }
  if (parsedUpstream.protocol !== 'https:') {
    return err(new Error(`ANTHROPIC_BASE_URL_UPSTREAM must use https:// scheme, got: ${parsedUpstream.protocol}`))
  }

  const rawLevel = process.env.LOG_LEVEL ?? 'info'
  const logLevel: LogLevel = isLogLevel(rawLevel) ? rawLevel : 'info'

  const kyberCapsule = process.env.HONEY_KYBER_CAPSULE

  return ok({
    anthropicApiKey: apiKey,
    honeyPassphrase: passphrase,
    proxyPort: port,
    upstreamBaseUrl: upstream,
    logLevel,
    ...(kyberCapsule !== undefined ? { honeyKyberCapsule: kyberCapsule } : {}),
  })
}
