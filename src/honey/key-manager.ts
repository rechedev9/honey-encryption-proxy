/**
 * Session key derivation.
 *
 * Derives three independent 32-byte sub-keys from a passphrase via PBKDF2 +
 * HKDF so that each layer (AES-CTR, HMAC, FPE) uses a distinct key.
 *
 * PBKDF2: 250 000 iterations, SHA-256 -> 32-byte master key.
 * HKDF:   SHA-256, three sub-keys with distinct info labels.
 */

import { pbkdf2Sync, hkdfSync, randomBytes } from 'node:crypto'
import { ok } from '../types.ts'
import type { Result, SessionKey } from '../types.ts'

const PBKDF2_ITERATIONS = 250_000
const KEY_BYTES = 32
const SALT_BYTES = 16

/** Derives a full SessionKey from a passphrase.  Generates a fresh salt. */
export function deriveSessionKey(passphrase: string): Result<SessionKey> {
  const salt = randomBytes(SALT_BYTES)
  return deriveFromSalt(passphrase, salt)
}

/** Derives a SessionKey from a passphrase and an existing salt (for re-derivation). */
export function deriveFromSalt(passphrase: string, salt: Buffer): Result<SessionKey> {
  const masterKey = pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_BYTES, 'sha256')
  const sessionId = crypto.randomUUID()

  const key = Buffer.from(
    hkdfSync('sha256', masterKey, salt, 'honey:aes-ctr:v1', KEY_BYTES),
  )
  const macKey = Buffer.from(
    hkdfSync('sha256', masterKey, salt, 'honey:hmac:v1', KEY_BYTES),
  )
  const fpeKey = Buffer.from(
    hkdfSync('sha256', masterKey, salt, 'honey:fpe:v1', KEY_BYTES),
  )

  // Zero the master key immediately -- sub-keys are now derived, master
  // key material no longer needed and should not linger on the heap.
  masterKey.fill(0)

  return ok({
    key,
    macKey,
    fpeKey,
    sessionId,
    salt,
    derivedAt: Date.now(),
  })
}

/**
 * Serialises the salt to a base64 string for embedding in payloads so the
 * proxy can re-derive the same session key when processing the response.
 */
export function saltToBase64(salt: Buffer): string {
  return salt.toString('base64url')
}

export function saltFromBase64(b64: string): Buffer {
  return Buffer.from(b64, 'base64url')
}

/**
 * Zeroes all cryptographic key material in a SessionKey.
 * Call during graceful shutdown to reduce the key-material exposure window.
 *
 * Note: JavaScript strings (like a passphrase) cannot be zeroed because they
 * are immutable. Only Buffer-backed key material is scrubbed here.
 */
export function zeroSessionKey(sessionKey: SessionKey): void {
  sessionKey.key.fill(0)
  sessionKey.macKey.fill(0)
  sessionKey.fpeKey.fill(0)
  sessionKey.salt.fill(0)
}
