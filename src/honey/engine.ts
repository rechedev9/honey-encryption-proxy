/**
 * Honey Encryption engine.
 *
 * Implements the full HE pipeline for a code string:
 *
 *   encrypt(code, sessionKey):
 *     1. DTE.encode(code, key) → corpus index
 *     2. LWE-encrypt the index → (nonce, b)   [v2]
 *     3. HMAC-SHA256(nonce || b, macKey) → tag [integrity check]
 *     4. Return base64(v2 || tag || nonce || b)
 *
 *   decrypt(encoded, sessionKey):
 *     1. Detect version byte: 0x02 → v2 (LWE), 0x01 → v1 (AES-CTR), else → v0 (legacy)
 *     2. Verify HMAC (only the legitimate proxy can pass this)
 *     3. LWE-decrypt → corpus index                          [v2]
 *     4. DTE.decode(index) → plausible code
 *
 * Honey property (v2):
 *   With wrong fpeKey s', the LWE ciphertext decrypts to a uniformly
 *   distributed corpus index — every candidate key gives a different
 *   plausible code snippet.  The adversary cannot identify the real key.
 *
 * Wire formats:
 *   v0 (legacy): nonce(16) || HMAC(32) || ciphertext(4)                = 52 bytes
 *   v1:          0x01 || nonce(16) || HMAC(32) || ciphertext(4)        = 53 bytes
 *   v2 (LWE):    0x02 || HMAC(32) || nonce(16) || b_uint16BE(2)        = 51 bytes
 */

import { createDecipheriv, createHmac, timingSafeEqual } from 'node:crypto'
import { encode as dteEncode, decode as dteDecode } from './dte-corpus.ts'
import { lweEncrypt, lweDecrypt, lweDecryptWithSeed } from './lwe-dte.ts'
import { err, ok } from '../types.ts'
import type { Result, SessionKey } from '../types.ts'

const NONCE_BYTES = 16   // AES-CTR IV / LWE nonce
const TAG_BYTES = 32     // HMAC-SHA256 output
const INDEX_BYTES = 4    // serialised corpus index (v0/v1)
const B_BYTES = 2        // LWE scalar b as uint16BE (v2)

/** Legacy v1 wire format version byte. */
export const FORMAT_VERSION = 1

/** v2 LWE wire format version byte. */
export const FORMAT_VERSION_V2 = 2

interface EncryptedPayload {
  /** Base64url-encoded versioned payload. */
  readonly encoded: string
}

/**
 * Encrypts a code string using LWE-DTE (v2 wire format).
 * Emits: 0x02 || HMAC(32) || nonce(16) || b_uint16BE(2) = 51 bytes.
 */
export function encrypt(code: string, sessionKey: SessionKey): Result<EncryptedPayload> {
  const index = dteEncode(code, sessionKey.key)
  const { nonce, b } = lweEncrypt(index, sessionKey.key, sessionKey.fpeKey)

  const bBytes = Buffer.alloc(B_BYTES)
  bBytes.writeUInt16BE(b, 0)

  const tag = hmacTag(nonce, bBytes, sessionKey.macKey)

  const versionByte = Buffer.from([FORMAT_VERSION_V2])
  const payload = Buffer.concat([versionByte, tag, nonce, bBytes])
  return ok({ encoded: payload.toString('base64url') })
}

/**
 * Decrypts an EncryptedPayload using the given SessionKey.
 *
 * Dispatches on the version byte: v2 → LWE path, v1 → AES-CTR path,
 * else → legacy v0 layout.
 *
 * All failure modes report a single generic error to prevent oracle attacks.
 */
export function decrypt(payload: EncryptedPayload, sessionKey: SessionKey): Result<string> {
  const raw = Buffer.from(payload.encoded, 'base64url')

  if (raw.length > 0) {
    const version = raw[0] ?? 0
    if (version === FORMAT_VERSION_V2) {
      return decryptV2(raw, sessionKey)
    }
    if (version === FORMAT_VERSION) {
      return decryptVersioned(raw, sessionKey)
    }
  }
  return decryptLegacy(raw, sessionKey)
}

/**
 * Demonstrates the honey property: decrypting with a wrong key always
 * produces a plausible (but different) code snippet.
 *
 * @internal Intentionally skips HMAC verification. Use ONLY for testing
 * and demonstration of the honey-encryption security property. MUST NOT
 * be called in any request-processing path.
 */
export function decryptHoney(payload: EncryptedPayload, wrongKey: Buffer): string {
  const raw = Buffer.from(payload.encoded, 'base64url')

  if (raw.length > 0) {
    const version = raw[0] ?? 0

    if (version === FORMAT_VERSION_V2) {
      return decryptHoneyV2(raw, wrongKey)
    }

    if (version === FORMAT_VERSION) {
      // v1 layout: 0x01 || nonce(16) || HMAC(32) || ciphertext(4)
      const offset = 1
      const minLen = offset + NONCE_BYTES + TAG_BYTES + INDEX_BYTES
      if (raw.length < minLen) return ''

      const nonce = raw.subarray(offset, offset + NONCE_BYTES)
      const ciphertext = raw.subarray(offset + NONCE_BYTES + TAG_BYTES)
      return dteDecode(decryptAesCtrIndex(wrongKey, nonce, ciphertext))
    }
  }

  // Legacy v0 layout: nonce(16) || HMAC(32) || ciphertext(4)
  if (raw.length < NONCE_BYTES + TAG_BYTES + INDEX_BYTES) return ''

  const v0Nonce = raw.subarray(0, NONCE_BYTES)
  const v0Ciphertext = raw.subarray(NONCE_BYTES + TAG_BYTES)
  return dteDecode(decryptAesCtrIndex(wrongKey, v0Nonce, v0Ciphertext))
}

// ── Internal helpers ────────────────────────────────────────────────────────

function decryptV2(raw: Buffer, sessionKey: SessionKey): Result<string> {
  // Layout: 0x02 || HMAC(32) || nonce(16) || b_uint16BE(2)
  const offset = 1
  const minLen = offset + TAG_BYTES + NONCE_BYTES + B_BYTES

  if (raw.length < minLen) {
    return err(new Error('Decryption failed'))
  }

  const tag = raw.subarray(offset, offset + TAG_BYTES)
  const nonce = raw.subarray(offset + TAG_BYTES, offset + TAG_BYTES + NONCE_BYTES)
  const bBytes = raw.subarray(offset + TAG_BYTES + NONCE_BYTES)

  if (!verifyHmac(tag, nonce, bBytes, sessionKey.macKey)) {
    return err(new Error('Decryption failed'))
  }

  const b = bBytes.readUInt16BE(0)
  const index = lweDecrypt(nonce, b, sessionKey.key, sessionKey.fpeKey)
  return ok(dteDecode(index))
}

function decryptHoneyV2(raw: Buffer, wrongKey: Buffer): string {
  // Layout: 0x02 || HMAC(32) || nonce(16) || b_uint16BE(2)
  const offset = 1
  const minLen = offset + TAG_BYTES + NONCE_BYTES + B_BYTES

  if (raw.length < minLen) return ''

  const nonce = raw.subarray(offset + TAG_BYTES, offset + TAG_BYTES + NONCE_BYTES)
  const bBytes = raw.subarray(offset + TAG_BYTES + NONCE_BYTES)
  const b = bBytes.readUInt16BE(0)

  // Adversary uses wrongKey for both a-vector and s-vector derivation
  const index = lweDecryptWithSeed(nonce, b, wrongKey, wrongKey)
  return dteDecode(index)
}

function decryptVersioned(raw: Buffer, sessionKey: SessionKey): Result<string> {
  // v1 layout: 0x01 || nonce(16) || HMAC(32) || ciphertext(4)
  const offset = 1
  const minLen = offset + NONCE_BYTES + TAG_BYTES + INDEX_BYTES

  if (raw.length < minLen) {
    return err(new Error('Decryption failed'))
  }

  const nonce = raw.subarray(offset, offset + NONCE_BYTES)
  const tag = raw.subarray(offset + NONCE_BYTES, offset + NONCE_BYTES + TAG_BYTES)
  const ciphertext = raw.subarray(offset + NONCE_BYTES + TAG_BYTES)

  if (!verifyHmac(tag, nonce, ciphertext, sessionKey.macKey)) {
    return err(new Error('Decryption failed'))
  }

  return ok(dteDecode(decryptAesCtrIndex(sessionKey.key, nonce, ciphertext)))
}

function decryptLegacy(raw: Buffer, sessionKey: SessionKey): Result<string> {
  // v0 layout: nonce(16) || HMAC(32) || ciphertext(4)
  const minLen = NONCE_BYTES + TAG_BYTES + INDEX_BYTES

  if (raw.length < minLen) {
    return err(new Error('Decryption failed'))
  }

  const nonce = raw.subarray(0, NONCE_BYTES)
  const tag = raw.subarray(NONCE_BYTES, NONCE_BYTES + TAG_BYTES)
  const ciphertext = raw.subarray(NONCE_BYTES + TAG_BYTES)

  if (!verifyHmac(tag, nonce, ciphertext, sessionKey.macKey)) {
    return err(new Error('Decryption failed'))
  }

  return ok(dteDecode(decryptAesCtrIndex(sessionKey.key, nonce, ciphertext)))
}

/** Decrypts AES-256-CTR ciphertext and reads the corpus index from the plaintext. */
function decryptAesCtrIndex(key: Buffer, nonce: Buffer, ciphertext: Buffer): number {
  const decipher = createDecipheriv('aes-256-ctr', key, nonce)
  const plainBytes = Buffer.concat([decipher.update(ciphertext), decipher.final()])
  return bytesToIndex(plainBytes)
}

function hmacTag(nonce: Buffer, data: Buffer, macKey: Buffer): Buffer {
  return createHmac('sha256', macKey).update(nonce).update(data).digest()
}

function verifyHmac(tag: Buffer, nonce: Buffer, data: Buffer, macKey: Buffer): boolean {
  return timingSafeEqual(tag, hmacTag(nonce, data, macKey))
}

/** Reads a 4-byte big-endian unsigned integer from a Buffer. */
function bytesToIndex(buf: Buffer): number {
  if (buf.length < 4) return 0
  return buf.readUInt32BE(0)
}
