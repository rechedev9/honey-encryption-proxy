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
 *     5. Return base64(nonce || tag || ciphertext)
 *
 *   decrypt(encoded, sessionKey):
 *     1. Parse nonce || tag || ciphertext
 *     2. Verify HMAC (only the legitimate proxy can pass this)
 *     3. AES-256-CTR.decrypt(ciphertext, key, nonce) → index bytes
 *     4. DTE.decode(index) → plausible code (real if key is correct)
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

export interface EncryptedPayload {
  /** Base64url-encoded nonce || HMAC tag || ciphertext */
  readonly encoded: string
}

export function encrypt(code: string, sessionKey: SessionKey): Result<EncryptedPayload> {
  const index = dteEncode(code, sessionKey.key)
  const plainBytes = indexToBytes(index)

  const nonce = randomBytes(NONCE_BYTES)

  const cipher = createCipheriv('aes-256-ctr', sessionKey.key, nonce)
  const ciphertext = Buffer.concat([cipher.update(plainBytes), cipher.final()])

  const tag = hmacTag(nonce, ciphertext, sessionKey.macKey)

  const payload = Buffer.concat([nonce, tag, ciphertext])
  return ok({ encoded: payload.toString('base64url') })
}

export function decrypt(payload: EncryptedPayload, sessionKey: SessionKey): Result<string> {
  const raw = Buffer.from(payload.encoded, 'base64url')
  const minLen = NONCE_BYTES + TAG_BYTES + INDEX_BYTES

  if (raw.length < minLen) {
    return err(new Error('Payload too short'))
  }

  const nonce = raw.subarray(0, NONCE_BYTES)
  const tag = raw.subarray(NONCE_BYTES, NONCE_BYTES + TAG_BYTES)
  const ciphertext = raw.subarray(NONCE_BYTES + TAG_BYTES)

  const expectedTag = hmacTag(nonce, ciphertext, sessionKey.macKey)

  if (!timingSafeEqual(tag, expectedTag)) {
    return err(new Error('HMAC verification failed'))
  }

  const decipher = createDecipheriv('aes-256-ctr', sessionKey.key, nonce)
  const plainBytes = Buffer.concat([decipher.update(ciphertext), decipher.final()])

  const index = bytesToIndex(plainBytes)
  const code = dteDecode(index)

  return ok(code)
}

/**
 * Demonstrates the honey property: decrypting with a wrong key always
 * produces a plausible (but different) code snippet.
 */
export function decryptHoney(payload: EncryptedPayload, wrongKey: Buffer): string {
  const raw = Buffer.from(payload.encoded, 'base64url')
  if (raw.length < NONCE_BYTES + TAG_BYTES + INDEX_BYTES) return ''

  const nonce = raw.subarray(0, NONCE_BYTES)
  const ciphertext = raw.subarray(NONCE_BYTES + TAG_BYTES)

  // Decrypt without MAC check — produces different bytes with wrong key
  const decipher = createDecipheriv('aes-256-ctr', wrongKey, nonce)
  const plainBytes = Buffer.concat([decipher.update(ciphertext), decipher.final()])

  const index = bytesToIndex(plainBytes)
  return dteDecode(index)
}

function hmacTag(nonce: Buffer, ciphertext: Buffer, macKey: Buffer): Buffer {
  return createHmac('sha256', macKey).update(nonce).update(ciphertext).digest()
}
