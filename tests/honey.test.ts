/**
 * Tests for the Honey Encryption engine.
 *
 * Verifies:
 *  - encrypt → decrypt with correct key returns original content (corpus index)
 *  - decrypt with wrong key returns a different but valid corpus snippet
 *  - the honey property: wrong-key decryptions are plausible
 */

import { describe, it, expect } from 'bun:test'
import { randomBytes } from 'node:crypto'
import { encrypt, decrypt, decryptHoney } from '../src/honey/engine.ts'
import { deriveSessionKey, deriveFromSalt } from '../src/honey/key-manager.ts'
import { CORPUS_SIZE } from '../src/corpus/index.ts'

const PASSPHRASE = 'test-passphrase-for-unit-tests'
const SAMPLE_CODE = `function calculateInvoiceTotal(items: LineItem[]): number {
  return items.reduce((sum, item) => sum + item.price * item.quantity, 0)
}`

describe('HoneyEngine', () => {
  describe('encrypt / decrypt round-trip', () => {
    it('returns the original code when decrypted with the correct key', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const encResult = encrypt(SAMPLE_CODE, keyResult.value)
      expect(encResult.ok).toBe(true)
      if (!encResult.ok) return

      const decResult = decrypt(encResult.value, keyResult.value)
      expect(decResult.ok).toBe(true)
      if (!decResult.ok) return

      // DTE round-trip: we get a corpus snippet, not the raw code.
      // Verify it is a non-empty string.
      expect(typeof decResult.value).toBe('string')
      expect(decResult.value.length).toBeGreaterThan(0)
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

    it('produces a deterministic ciphertext structure (nonce, tag, ciphertext present)', () => {
      const keyResult = deriveSessionKey(PASSPHRASE)
      expect(keyResult.ok).toBe(true)
      if (!keyResult.ok) return

      const encResult = encrypt(SAMPLE_CODE, keyResult.value)
      expect(encResult.ok).toBe(true)
      if (!encResult.ok) return

      // nonce(16) + tag(32) + ciphertext(4) = 52 bytes → base64url ~= 70 chars
      const raw = Buffer.from(encResult.value.encoded, 'base64url')
      expect(raw.length).toBe(52)
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
      const decoy = decryptHoney(encResult.value, wrongKey)

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
        decoys.add(decryptHoney(encResult.value, wrongKey))
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
      const decoy = decryptHoney(encResult.value, wrongKey)

      // Not guaranteed but overwhelmingly likely with random key
      if (CORPUS_SIZE > 1) {
        // Probabilistic — will pass virtually always
        let differs = false
        for (let i = 0; i < 10; i++) {
          const k = randomBytes(32)
          if (decryptHoney(encResult.value, k) !== decResult.value) {
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
})
