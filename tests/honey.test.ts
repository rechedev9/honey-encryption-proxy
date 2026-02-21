/**
 * Tests for the Honey Encryption engine and key derivation.
 *
 * Verifies:
 *  - v2 LWE encrypt → decrypt round-trip (new default format)
 *  - v1 legacy AES-CTR decrypt still works (backward compat)
 *  - v0 legacy decrypt (no version byte) still works
 *  - Honey property: wrong-key decryptions are plausible
 *  - HMAC tamper detection
 *  - ML-KEM-768 public key present in toJSON()
 */

import { describe, it, expect } from 'bun:test'
import { randomBytes, createCipheriv, createHmac } from 'node:crypto'
import { encrypt, decrypt, decryptHoneyUnsafe, FORMAT_VERSION, FORMAT_VERSION_V2 } from '../src/honey/engine.ts'
import { deriveSessionKey, deriveFromSalt } from '../src/honey/key-manager.ts'
import { CORPUS_SIZE } from '../src/corpus/index.ts'
import { encode as dteEncode, indexToBytes } from '../src/honey/dte-corpus.ts'

const PASSPHRASE = 'test-passphrase-for-unit-tests'
const SAMPLE_CODE = `function calculateInvoiceTotal(items: LineItem[]): number {
  return items.reduce((sum, item) => sum + item.price * item.quantity, 0)
}`

describe('HoneyEngine', () => {
  describe('v2 LWE format (default)', () => {
    it('returns a non-empty code string when decrypted with the correct key', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const encResult = encrypt(SAMPLE_CODE, keyResult.value)
      expect(encResult.ok).toBe(true)
      if (!encResult.ok) return

      const decResult = decrypt(encResult.value, keyResult.value)
      expect(decResult.ok).toBe(true)
      if (!decResult.ok) return

      expect(typeof decResult.value).toBe('string')
      expect(decResult.value.length).toBeGreaterThan(0)
    })

    it('emits v2 wire format: version(1) + HMAC(32) + nonce(16) + b(2) = 51 bytes', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const encResult = encrypt(SAMPLE_CODE, keyResult.value)
      expect(encResult.ok).toBe(true)
      if (!encResult.ok) return

      const raw = Buffer.from(encResult.value.encoded, 'base64url')
      expect(raw.length).toBe(51)
    })

    it('v2 payload starts with version byte 0x02', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const encResult = encrypt(SAMPLE_CODE, keyResult.value)
      expect(encResult.ok).toBe(true)
      if (!encResult.ok) return

      const raw = Buffer.from(encResult.value.encoded, 'base64url')
      expect(raw[0]).toBe(FORMAT_VERSION_V2)
    })

    it('fails HMAC verification with a tampered payload', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const encResult = encrypt(SAMPLE_CODE, keyResult.value)
      expect(encResult.ok).toBe(true)
      if (!encResult.ok) return

      const tampered = {
        encoded: encResult.value.encoded.slice(0, -4) + 'XXXX',
      }

      const decResult = decrypt(tampered, keyResult.value)
      expect(decResult.ok).toBe(false)
    })
  })

  describe('v1 backward compatibility', () => {
    it('decrypts v1 payloads (AES-256-CTR, version byte 0x01)', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      // Manually build a v1 payload: 0x01 || nonce(16) || HMAC(32) || ciphertext(4)
      const nonce = randomBytes(16)
      const index = dteEncode(SAMPLE_CODE, keyResult.value.key)
      const plainBytes = indexToBytes(index)
      const cipher = createCipheriv('aes-256-ctr', keyResult.value.key, nonce)
      const ct = Buffer.concat([cipher.update(plainBytes), cipher.final()])
      const tag = createHmac('sha256', keyResult.value.macKey).update(nonce).update(ct).digest()
      const v1Payload = Buffer.concat([Buffer.from([FORMAT_VERSION]), nonce, tag, ct])

      const decResult = decrypt({ encoded: v1Payload.toString('base64url') }, keyResult.value)
      expect(decResult.ok).toBe(true)
      if (!decResult.ok) return
      expect(typeof decResult.value).toBe('string')
      expect(decResult.value.length).toBeGreaterThan(0)
    })

    it('decrypts legacy v0 payloads (no version byte)', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      // Manually build a v0 payload (nonce || tag || ciphertext, no version byte)
      const nonce = randomBytes(16)
      const index = dteEncode(SAMPLE_CODE, keyResult.value.key)
      const plainBytes = indexToBytes(index)
      const cipher = createCipheriv('aes-256-ctr', keyResult.value.key, nonce)
      const ct = Buffer.concat([cipher.update(plainBytes), cipher.final()])
      const tag = createHmac('sha256', keyResult.value.macKey).update(nonce).update(ct).digest()
      const v0Payload = Buffer.concat([nonce, tag, ct])
      const encoded = v0Payload.toString('base64url')

      const decResult = decrypt({ encoded }, keyResult.value)
      expect(decResult.ok).toBe(true)
      if (!decResult.ok) return
      expect(typeof decResult.value).toBe('string')
      expect(decResult.value.length).toBeGreaterThan(0)
    })
  })

  describe('honey property', () => {
    it('decrypting with a wrong key still returns a non-empty code string', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const encResult = encrypt(SAMPLE_CODE, keyResult.value)
      expect(encResult.ok).toBe(true)
      if (!encResult.ok) return

      const wrongKey = randomBytes(32)
      const decoy = decryptHoneyUnsafe(encResult.value, wrongKey)

      expect(typeof decoy).toBe('string')
      expect(decoy.length).toBeGreaterThan(0)
    })

    it('different wrong keys produce different decoys', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const encResult = encrypt(SAMPLE_CODE, keyResult.value)
      expect(encResult.ok).toBe(true)
      if (!encResult.ok) return

      const decoys = new Set<string>()
      for (let i = 0; i < 20; i++) {
        const wrongKey = randomBytes(32)
        decoys.add(decryptHoneyUnsafe(encResult.value, wrongKey))
      }

      // With 20 random keys and CORPUS_SIZE entries, we expect >1 distinct decoy
      expect(decoys.size).toBeGreaterThan(1)
    })

    it('correct key and wrong key produce different outputs (most of the time)', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const encResult = encrypt(SAMPLE_CODE, keyResult.value)
      expect(encResult.ok).toBe(true)
      if (!encResult.ok) return

      const decResult = decrypt(encResult.value, keyResult.value)
      expect(decResult.ok).toBe(true)
      if (!decResult.ok) return

      const wrongKey = randomBytes(32)
      const decoy = decryptHoneyUnsafe(encResult.value, wrongKey)

      // Not guaranteed but overwhelmingly likely with random key
      if (CORPUS_SIZE > 1) {
        // Probabilistic — will pass virtually always
        let differs = false
        for (let i = 0; i < 10; i++) {
          const k = randomBytes(32)
          if (decryptHoneyUnsafe(encResult.value, k) !== decResult.value) {
            differs = true
            break
          }
        }
        expect(differs).toBe(true)
      }

      expect(typeof decoy).toBe('string')
    })
  })

  describe('key derivation', () => {
    it('produces distinct sub-keys for AES, HMAC, and FPE', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const { key, macKey, fpeKey } = keyResult.value
      expect(key.equals(macKey)).toBe(false)
      expect(key.equals(fpeKey)).toBe(false)
      expect(macKey.equals(fpeKey)).toBe(false)
    })

    it('same passphrase + same salt → same keys', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const rederived = deriveFromSalt(PASSPHRASE, keyResult.value.salt)
      expect(rederived.ok).toBe(true)
      if (!rederived.ok) return

      expect(keyResult.value.key.equals(rederived.value.key)).toBe(true)
      expect(keyResult.value.macKey.equals(rederived.value.macKey)).toBe(true)
      expect(keyResult.value.fpeKey.equals(rederived.value.fpeKey)).toBe(true)
    })

    it('different passphrases → different keys', () => {
      const a = deriveSessionKey('passphrase-a')
      const b = deriveSessionKey('passphrase-b')
      expect(a.ok && b.ok).toBe(true)
      if (!a.ok || !b.ok) return

      expect(a.value.key.equals(b.value.key)).toBe(false)
    })
  })

  describe('ML-KEM-768 hybrid', () => {
    it('toJSON() includes mlkemPublicKey as a non-empty base64url string', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const json = keyResult.value.toJSON()
      expect(typeof json.mlkemPublicKey).toBe('string')
      expect(json.mlkemPublicKey.length).toBeGreaterThan(0)
    })

    it('different sessions produce different ML-KEM public keys (fresh salt)', () => {
      const a = deriveSessionKey(PASSPHRASE)
      const b = deriveSessionKey(PASSPHRASE)
      expect(a.ok && b.ok).toBe(true)
      if (!a.ok || !b.ok) return

      // Fresh salt each call → distinct KEM keypair
      expect(a.value.toJSON().mlkemPublicKey).not.toBe(b.value.toJSON().mlkemPublicKey)
    })

    it('same passphrase + same salt → same ML-KEM public key', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const rederived = deriveFromSalt(PASSPHRASE, keyResult.value.salt)
      expect(rederived.ok).toBe(true)
      if (!rederived.ok) return

      expect(keyResult.value.toJSON().mlkemPublicKey).toBe(
        rederived.value.toJSON().mlkemPublicKey,
      )
    })

    it('keyDerivation field reflects hybrid scheme', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      expect(keyResult.value.toJSON().keyDerivation).toBe('scrypt-v1+ml-kem-768')
    })
  })
})
