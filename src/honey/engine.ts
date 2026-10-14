import { createDecipheriv, createHmac, timingSafeEqual } from 'node:crypto'
import { encode as dteEncode, decode as dteDecode } from './dte-corpus.ts'
import { lweEncrypt, lweDecrypt, lweDecryptWithSeed } from './lwe-dte.ts'
import { err, ok } from '../types.ts'
import type { Result, SessionKey } from '../types.ts'

const NONCE_BYTES = 16
const TAG_BYTES = 32
const INDEX_BYTES = 4
const B_BYTES = 2

export const FORMAT_VERSION_V1 = 1

export const FORMAT_VERSION_V2 = 2

interface EncryptedPayload {
  /** Base64url-encoded versioned payload. */
  readonly encoded: string
}

export function encrypt(code: string, sessionKey: SessionKey): Result<EncryptedPayload> {
  const index = dteEncode(code, sessionKey.key)
  const { nonce, b } = lweEncrypt(index, sessionKey.key, sessionKey.fpeKey)

  const bBytes = Buffer.alloc(B_BYTES)
  bBytes.writeUInt16BE(b.value, 0)

  const tag = hmacTag(nonce, bBytes, sessionKey.macKey)

  const versionByte = Buffer.from([FORMAT_VERSION_V2])
  const payload = Buffer.concat([versionByte, tag, nonce, bBytes])
  return ok({ encoded: payload.toString('base64url') })
}

/**
 * All failure modes report a single generic error to prevent oracle attacks.
 */
export function decrypt(payload: EncryptedPayload, sessionKey: SessionKey): Result<string> {
  const raw = Buffer.from(payload.encoded, 'base64url')

  if (raw.length > 0) {
    const version = raw[0] ?? 0
    if (version === FORMAT_VERSION_V2) {
      return decryptV2(raw, sessionKey)
    }
    if (version === FORMAT_VERSION_V1) {
      return decryptVersioned(raw, sessionKey)
    }
  }
  return decryptLegacy(raw, sessionKey)
}

/**
 * Demonstrates the honey property: decrypting with a wrong key always
 * produces a plausible (but different) code snippet.
 *
 * @warning UNSAFE — Intentionally skips HMAC verification. Use ONLY for
 * testing and demonstration of the honey-encryption security property.
 * MUST NOT be called in any request-processing path.
 */
export function decryptHoneyUnsafe(payload: EncryptedPayload, wrongKey: Buffer): string {
  const raw = Buffer.from(payload.encoded, 'base64url')

  if (raw.length > 0) {
    const version = raw[0] ?? 0

    if (version === FORMAT_VERSION_V2) {
      return decryptHoneyV2Unsafe(raw, wrongKey)
    }

    if (version === FORMAT_VERSION_V1) {
      const offset = 1
      const minLen = offset + NONCE_BYTES + TAG_BYTES + INDEX_BYTES
      if (raw.length < minLen) return ''

      const nonce = raw.subarray(offset, offset + NONCE_BYTES)
      const ciphertext = raw.subarray(offset + NONCE_BYTES + TAG_BYTES)
      return dteDecode(decryptAesCtrIndex(wrongKey, nonce, ciphertext))
    }
  }

  if (raw.length < NONCE_BYTES + TAG_BYTES + INDEX_BYTES) return ''

  const v0Nonce = raw.subarray(0, NONCE_BYTES)
  const v0Ciphertext = raw.subarray(NONCE_BYTES + TAG_BYTES)
  return dteDecode(decryptAesCtrIndex(wrongKey, v0Nonce, v0Ciphertext))
}

function decryptV2(raw: Buffer, sessionKey: SessionKey): Result<string> {
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

function decryptHoneyV2Unsafe(raw: Buffer, wrongKey: Buffer): string {
  const offset = 1
  const minLen = offset + TAG_BYTES + NONCE_BYTES + B_BYTES

  if (raw.length < minLen) return ''

  const nonce = raw.subarray(offset + TAG_BYTES, offset + TAG_BYTES + NONCE_BYTES)
  const bBytes = raw.subarray(offset + TAG_BYTES + NONCE_BYTES)
  const b = bBytes.readUInt16BE(0)

  const index = lweDecryptWithSeed(nonce, b, wrongKey, wrongKey)
  return dteDecode(index)
}

function decryptVersioned(raw: Buffer, sessionKey: SessionKey): Result<string> {
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

function bytesToIndex(buf: Buffer): number {
  if (buf.length < 4) return 0
  return buf.readUInt32BE(0)
}
