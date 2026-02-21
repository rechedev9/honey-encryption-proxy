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
 *
 * Parameters:
 *   n = 16    — vector dimension
 *   q = 7681  — prime modulus  (log₂q ≈ 13)
 *   B = 5     — error bound    |e| ≤ 5 << ⌊q/M⌋/2 ≈ 76 ✓
 *   M         — corpus size    (~50)
 */

import { createHmac, randomBytes } from 'node:crypto'
import { CORPUS_SIZE } from '../corpus/index.ts'

// ── LWE parameters ───────────────────────────────────────────────────────────

const LWE_N = 16           // vector dimension
const LWE_Q = 7681        // prime modulus; ⌊q/M⌋ ≈ 153 for M≈50
const LWE_B = 5           // error bound; |e| ≤ B << ⌊q/M⌋/2 ≈ 76
const NONCE_BYTES = 16    // bytes of randomness for each LWE encryption

// ── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Dot product of two n-vectors, reduced mod q.
 * Uses `?? 0` to satisfy noUncheckedIndexedAccess without non-null assertions.
 */
function dotMod(a: readonly number[], s: readonly number[]): number {
  let sum = 0
  for (let i = 0; i < LWE_N; i++) {
    sum = (sum + (a[i] ?? 0) * (s[i] ?? 0)) % LWE_Q
  }
  return sum
}

/** Samples an error e ∈ [−B, B] from a deterministic HMAC. */
function sampleError(nonce: Buffer, index: number): number {
  const h = createHmac('sha256', nonce).update(`lwe:e:${index}`).digest()
  const raw = (h.readUInt32BE(0)) % (2 * LWE_B + 1)
  return raw - LWE_B
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Derives the secret vector s ∈ Z_q^n deterministically from fpeKey.
 * s[i] = HMAC-SHA256(fpeKey, "lwe:s:<i>") mod q
 */
function deriveSecretVector(fpeKey: Buffer): readonly number[] {
  const s: number[] = []
  for (let i = 0; i < LWE_N; i++) {
    const h = createHmac('sha256', fpeKey).update(`lwe:s:${i}`).digest()
    s.push(h.readUInt32BE(0) % LWE_Q)
  }
  return s
}

/**
 * Derives the public vector a ∈ Z_q^n from key + nonce deterministically.
 * a[i] = HMAC-SHA256(key, nonce || "lwe:a:<i>") mod q
 */
function derivePublicVector(key: Buffer, nonce: Buffer): readonly number[] {
  const a: number[] = []
  for (let i = 0; i < LWE_N; i++) {
    const h = createHmac('sha256', key).update(nonce).update(`lwe:a:${i}`).digest()
    a.push(h.readUInt32BE(0) % LWE_Q)
  }
  return a
}

export interface LweEncrypted {
  readonly nonce: Buffer
  /** LWE ciphertext scalar b ∈ [0, q−1], fits in uint16. */
  readonly b: number
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
  const e = sampleError(nonce, 0)
  const normalised = ((index % M) + M) % M
  const b = ((dotMod(a, s) + e + scale * normalised) % LWE_Q + LWE_Q) % LWE_Q
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
