/**
 * LWE-DTE: Distribution-Transforming Encoder using Learning With Errors.
 *
 * Provides the honey property via lattice hardness instead of
 * AES-256-CTR: wrong key → uniformly random corpus index.
 *
 * Math:
 *   Encrypt: b = (a·s + e + ⌊q/M⌋·m) mod q
 *   Decrypt: diff = (b − a·s) mod q  →  round(diff / ⌊q/M⌋) mod M
 *   Honey:   wrong s' ⟹ a·(s−s') ≈ uniform(Z_q) ⟹ index ≈ uniform({0,...,M−1})
 */

import { createHmac, randomBytes } from 'node:crypto'
import { CORPUS_SIZE } from '../corpus/index.ts'

const LWE_N = 128          // vector dimension (demo-grade; production LWE uses n≥512)
const LWE_Q = 7681
const REJECTION_LIMIT = Math.floor(4294967296 / LWE_Q) * LWE_Q
const LWE_B = 5
const NONCE_BYTES = 16

class Uint16 {
  readonly value: number

  constructor(value: number) {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
      throw new RangeError(`value ${value} is outside uint16`)
    }
    this.value = value
  }
}

class LweVector {
  readonly #components: readonly number[]

  constructor(components: readonly number[]) {
    if (components.length !== LWE_N) {
      throw new Error(`LWE vector length ${components.length} is not ${LWE_N}`)
    }
    this.#components = components
  }

  component(index: number): number {
    const value = this.#components[index]
    if (value === undefined) {
      throw new Error(`LWE vector index ${index} is out of range`)
    }
    return value
  }
}

function dotMod(a: LweVector, s: LweVector): number {
  let sum = 0
  for (let i = 0; i < LWE_N; i++) {
    sum = (sum + a.component(i) * s.component(i)) % LWE_Q
  }
  return sum
}

function sampleError(secretKey: Buffer, nonce: Buffer, index: number): number {
  const h = createHmac('sha256', secretKey).update(nonce).update(`lwe:e:${index}`).digest()
  const raw = (h.readUInt32BE(0)) % (2 * LWE_B + 1)
  return raw - LWE_B
}

function deriveSecretVector(fpeKey: Buffer): LweVector {
  const s: number[] = []
  for (let i = 0; i < LWE_N; i++) {
    for (let attempt = 0; ; attempt++) {
      const h = createHmac('sha256', fpeKey).update(`lwe:s:${i}:${attempt}`).digest()
      const raw = h.readUInt32BE(0)
      if (raw < REJECTION_LIMIT) {
        s.push(raw % LWE_Q)
        break
      }
    }
  }
  return new LweVector(s)
}

function derivePublicVector(key: Buffer, nonce: Buffer): LweVector {
  const a: number[] = []
  for (let i = 0; i < LWE_N; i++) {
    for (let attempt = 0; ; attempt++) {
      const h = createHmac('sha256', key).update(nonce).update(`lwe:a:${i}:${attempt}`).digest()
      const raw = h.readUInt32BE(0)
      if (raw < REJECTION_LIMIT) {
        a.push(raw % LWE_Q)
        break
      }
    }
  }
  return new LweVector(a)
}

interface LweEncrypted {
  readonly nonce: Buffer
  readonly b: Uint16
}

/**
 * LWE-encrypts a corpus index m into (nonce, b).
 *   b = (a·s + e + ⌊q/M⌋·m) mod q
 */
export function lweEncrypt(index: number, key: Buffer, fpeKey: Buffer): LweEncrypted {
  const M = CORPUS_SIZE
  const scale = Math.floor(LWE_Q / M)
  const nonce = randomBytes(NONCE_BYTES)
  const a = derivePublicVector(key, nonce)
  const s = deriveSecretVector(fpeKey)
  const e = sampleError(fpeKey, nonce, 0)
  const normalised = ((index % M) + M) % M
  const b = new Uint16(((dotMod(a, s) + e + scale * normalised) % LWE_Q + LWE_Q) % LWE_Q)
  return { nonce, b }
}

/**
 * Decrypts an LWE ciphertext back to a corpus index.
 *   diff = (b − a·s) mod q  →  round(diff / ⌊q/M⌋) mod M
 */
export function lweDecrypt(nonce: Buffer, b: number, key: Buffer, fpeKey: Buffer): number {
  const M = CORPUS_SIZE
  const scale = Math.floor(LWE_Q / M)
  const a = derivePublicVector(key, nonce)
  const s = deriveSecretVector(fpeKey)
  const diff = ((b - dotMod(a, s)) % LWE_Q + LWE_Q) % LWE_Q
  return ((Math.round(diff / scale) % M) + M) % M
}

/**
 * Decrypts with a wrong fpeKey seed — returns a pseudorandom corpus index.
 * Demonstrates the honey property: with incorrect s', diff ≈ uniform(Z_q).
 *
 * The `key` parameter is the adversary's candidate key used for a-vector
 * derivation; `wrongSeed` is their candidate fpeKey for s-vector derivation.
 */
export function lweDecryptWithSeed(
  nonce: Buffer,
  b: number,
  key: Buffer,
  wrongSeed: Buffer,
): number {
  const M = CORPUS_SIZE
  const scale = Math.floor(LWE_Q / M)
  const a = derivePublicVector(key, nonce)
  const sWrong = deriveSecretVector(wrongSeed)
  const diff = ((b - dotMod(a, sWrong)) % LWE_Q + LWE_Q) % LWE_Q
  return ((Math.round(diff / scale) % M) + M) % M
}
