/**
 * Honey Encryption engine.
 *
 * Implements the full HE pipeline for a code string:
 *
 *   encrypt(code, sessionKey):
 *     1. DTE.encode(code, key) → corpus index
 *     2. Serialise index to 4 bytes
 *     3. AES-256-CTR(bytes, key, nonce) → ciphertext      [unauthenticated!]
 *     4. HMAC-SHA256(nonce || ciphertext, macKey) → tag   [integrity for
 *                                                          the legitimate
 *                                                          proxy]
 *     5. Return base64(version || nonce || tag || ciphertext)
 *
 *   decrypt(encoded, sessionKey):
 *     1. Detect version byte (v1) or fall back to legacy (v0) layout
 *     2. Parse nonce || tag || ciphertext
 *     3. Verify HMAC (only the legitimate proxy can pass this)
 *     4. AES-256-CTR.decrypt(ciphertext, key, nonce) → index bytes
 *     5. DTE.decode(index) → plausible code (real if key is correct)
 *
 * Honey property:
 *   If an adversary strips the MAC and brute-forces the AES key, they get
 *   a different corpus index with each candidate key, i.e., a different
 *   plausible code snippet.  They cannot tell which decryption is "real".
 *
 * Note: The proxy sends FPE-obfuscated code to Claude (not the AES
 * ciphertext).  This engine is used for:
 *   a) Encrypting the identifier mapping for secure local storage.
 *   b) Demonstrating / testing the HE security property.
 */

import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { encode as dteEncode, decode as dteDecode, indexToBytes, bytesToIndex } from './dte-corpus.ts'
import { err, ok } from '../types.ts'
import type { Result, SessionKey } from '../types.ts'

const NONCE_BYTES = 16   // AES-CTR IV
const TAG_BYTES = 32     // HMAC-SHA256 output
const INDEX_BYTES = 4    // serialised corpus index

/** Wire format version. Prepended as the first byte of every v1+ payload. */
export const FORMAT_VERSION = 1

export interface EncryptedPayload {
  /** Base64url-encoded version || nonce || HMAC tag || ciphertext */
  readonly encoded: string
}

export function encrypt(code: string, sessionKey: SessionKey): Result<EncryptedPayload> {
  const index = dteEncode(code, sessionKey.key)
  const plainBytes = indexToBytes(index)

  const nonce = randomBytes(NONCE_BYTES)

  const cipher = createCipheriv('aes-256-ctr', sessionKey.key, nonce)
  const ciphertext = Buffer.concat([cipher.update(plainBytes), cipher.final()])

  const tag = hmacTag(nonce, ciphertext, sessionKey.macKey)

  const versionByte = Buffer.from([FORMAT_VERSION])
  const payload = Buffer.concat([versionByte, nonce, tag, ciphertext])
  return ok({ encoded: payload.toString('base64url') })
}

/**
 * Decrypts an EncryptedPayload using the given SessionKey.
 *
 * All failure modes (short payload, HMAC mismatch, etc.) are reported as
 * a single generic error message - 'Decryption failed' - to prevent HMAC
 * oracle attacks that could leak information about the wire format.
 */
export function decrypt(payload: EncryptedPayload, sessionKey: SessionKey): Result<string> {
  const raw = Buffer.from(payload.encoded, 'base64url')

  if (raw.length > 0 && raw[0] === FORMAT_VERSION) {
    return decryptVersioned(raw, sessionKey, false)
  }
  return decryptLegacy(raw, sessionKey, false)
}

/**
 * Demonstrates the honey property: decrypting with a wrong key always
 * produces a plausible (but different) code snippet.
 */
export function decryptHoney(payload: EncryptedPayload, wrongKey: Buffer): string {
  const raw = Buffer.from(payload.encoded, 'base64url')

  if (raw.length > 0 && raw[0] === FORMAT_VERSION) {
    const offset = 1
    const minLen = offset + NONCE_BYTES + TAG_BYTES + INDEX_BYTES
    if (raw.length < minLen) return ''

    const nonce = raw.subarray(offset, offset + NONCE_BYTES)
    const ciphertext = raw.subarray(offset + NONCE_BYTES + TAG_BYTES)

    const decipher = createDecipheriv('aes-256-ctr', wrongKey, nonce)
    const plainBytes = Buffer.concat([decipher.update(ciphertext), decipher.final()])

    const index = bytesToIndex(plainBytes)
    return dteDecode(index)
  }

  // Legacy v0 layout
  if (raw.length < NONCE_BYTES + TAG_BYTES + INDEX_BYTES) return ''

  const nonce = raw.subarray(0, NONCE_BYTES)
  const ciphertext = raw.subarray(NONCE_BYTES + TAG_BYTES)

  const decipher = createDecipheriv('aes-256-ctr', wrongKey, nonce)
  const plainBytes = Buffer.concat([decipher.update(ciphertext), decipher.final()])

  const index = bytesToIndex(plainBytes)
  return dteDecode(index)
}

// ── Internal helpers ────────────────────────────────────────────────────────

function decryptVersioned(
  raw: Buffer,
  sessionKey: SessionKey,
  _skipMac: boolean,
): Result<string> {
  const offset = 1
  const minLen = offset + NONCE_BYTES + TAG_BYTES + INDEX_BYTES

  if (raw.length < minLen) {
    return err(new Error('Decryption failed'))
  }

  const nonce = raw.subarray(offset, offset + NONCE_BYTES)
  const tag = raw.subarray(offset + NONCE_BYTES, offset + NONCE_BYTES + TAG_BYTES)
  const ciphertext = raw.subarray(offset + NONCE_BYTES + TAG_BYTES)

  const expectedTag = hmacTag(nonce, ciphertext, sessionKey.macKey)

  if (!timingSafeEqual(tag, expectedTag)) {
    return err(new Error('Decryption failed'))
  }

  const decipher = createDecipheriv('aes-256-ctr', sessionKey.key, nonce)
  const plainBytes = Buffer.concat([decipher.update(ciphertext), decipher.final()])

  const index = bytesToIndex(plainBytes)
  const code = dteDecode(index)

  return ok(code)
}

function decryptLegacy(
  raw: Buffer,
  sessionKey: SessionKey,
  _skipMac: boolean,
): Result<string> {
  const minLen = NONCE_BYTES + TAG_BYTES + INDEX_BYTES

  if (raw.length < minLen) {
    return err(new Error('Decryption failed'))
  }

  const nonce = raw.subarray(0, NONCE_BYTES)
  const tag = raw.subarray(NONCE_BYTES, NONCE_BYTES + TAG_BYTES)
  const ciphertext = raw.subarray(NONCE_BYTES + TAG_BYTES)

  const expectedTag = hmacTag(nonce, ciphertext, sessionKey.macKey)

  if (!timingSafeEqual(tag, expectedTag)) {
    return err(new Error('Decryption failed'))
  }

  const decipher = createDecipheriv('aes-256-ctr', sessionKey.key, nonce)
  const plainBytes = Buffer.concat([decipher.update(ciphertext), decipher.final()])

  const index = bytesToIndex(plainBytes)
  const code = dteDecode(index)

  return ok(code)
}

function hmacTag(nonce: Buffer, ciphertext: Buffer, macKey: Buffer): Buffer {
  return createHmac('sha256', macKey).update(nonce).update(ciphertext).digest()
}
