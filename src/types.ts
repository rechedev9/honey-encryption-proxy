/**
 * Core shared types for the Honey Encryption proxy.
 */

// ── Result<T, E> ────────────────────────────────────────────────────────────

type Ok<T> = { readonly ok: true; readonly value: T }
type Err<E> = { readonly ok: false; readonly error: E }
export type Result<T, E = Error> = Ok<T> | Err<E>

export function ok<T>(value: T): Ok<T> {
  return { ok: true, value }
}

export function err<E>(error: E): Err<E> {
  return { ok: false, error }
}

// ── Session key ─────────────────────────────────────────────────────────────

export interface SessionKey {
  /** 32-byte AES key for CTR encryption of DTE seed */
  readonly key: Buffer
  /** 32-byte key for HMAC integrity check */
  readonly macKey: Buffer
  /** 32-byte key for FPE identifier mapping */
  readonly fpeKey: Buffer
  readonly sessionId: string
  readonly salt: Buffer
  readonly derivedAt: number
}

// ── Code extraction ─────────────────────────────────────────────────────────

export interface CodeBlock {
  /** Raw code content (without the fence markers) */
  readonly content: string
  /** Language tag from the fence (may be empty) */
  readonly lang: string
  /** Character offset of the opening ``` in the original string */
  readonly startOffset: number
  /** Character offset just past the closing ``` */
  readonly endOffset: number
}

// ── Identifier mapping ──────────────────────────────────────────────────────

export interface IdentifierMapping {
  readonly realToFake: ReadonlyMap<string, string>
  readonly fakeToReal: ReadonlyMap<string, string>
}

// ── Audit ────────────────────────────────────────────────────────────────────

export interface AuditEntry {
  readonly timestamp: string
  readonly requestId: string
  readonly sessionId: string
  readonly identifiersObfuscated: number
  readonly numbersObfuscated: number
  readonly durationMs: number
  readonly streaming: boolean
  readonly upstreamStatus: number
}

// ── Request context ──────────────────────────────────────────────────────────

export interface RequestContext {
  readonly requestId: string
  readonly sessionKey: SessionKey
  readonly mapping: IdentifierMapping
}
