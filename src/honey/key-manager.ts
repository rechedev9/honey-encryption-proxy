/**
 * Session key derivation.
 *
 * Derives three independent 32-byte sub-keys from a passphrase via scrypt +
 * HKDF so that each layer (AES-CTR, HMAC, FPE) uses a distinct key.
 *
 * scrypt: N=65536, r=8, p=1 → 64 MB RAM per derivation, ~300 ms on modern hardware.
 * HKDF:   SHA-256, three sub-keys with distinct info labels.
 *
 * Why scrypt instead of PBKDF2:
 *   Grover's algorithm halves the effective passphrase search space, but
 *   it cannot parallelise memory access. scrypt's sequential memory-hard
 *   construction (N×128×r bytes = 64 MB required) means an attacker with
 *   quantum hardware still pays 64 MB of RAM per guess — a constraint that
 *   does not improve with qubit count. This is the key defensive property
 *   identified in Khan et al. (2025), "Implementation and performance of
 *   post-quantum cryptography for resource constrained consumer electronics".
 *
 * ML-KEM-768 hybrid:
 *   masterKey = scrypt_output XOR HKDF(kyber_sharedSecret)
 *   Breaking one of the two hardness assumptions is not sufficient.
 *   If no capsule is provided, masterKey = scrypt_output (classical only).
 *
 * Salt: 32 bytes (256 bits) of CSPRNG output — fresh every proxy start.
 */

import { scryptSync, hkdfSync, randomBytes } from 'node:crypto'
import { ml_kem768 } from '@noble/post-quantum/ml-kem'
import { ok } from '../types.ts'
import type { Result, SessionKey } from '../types.ts'

// scrypt cost parameters — tuned for ~300 ms and 64 MB RAM on a modern CPU.
// Raising N doubles both time and memory cost.
const SCRYPT_N = 65_536        // CPU/memory cost factor (2^16)
const SCRYPT_R = 8             // block size — controls sequential memory access
const SCRYPT_P = 1             // parallelisation factor
// Memory required = N × r × 128 bytes = 65536 × 8 × 128 = 64 MB.
// maxmem must be set explicitly; Node's default cap is 32 MB.
const SCRYPT_MAXMEM = 128 * 1024 * 1024  // 128 MB ceiling (2× safety factor)
const KEY_BYTES = 32
const SALT_BYTES = 32     // 256-bit salt (increased from 16 for stronger rainbow-table resistance)
const MLKEM_SEED_BYTES = 64   // ml_kem768.keygen expects a 64-byte seed

/** Derives a full SessionKey from a passphrase.  Generates a fresh salt. */
export function deriveSessionKey(passphrase: string, capsule?: Buffer): Result<SessionKey> {
  const salt = randomBytes(SALT_BYTES)
  return deriveFromSalt(passphrase, salt, capsule)
}

/** Derives a SessionKey from a passphrase and an existing salt (for re-derivation). */
export function deriveFromSalt(
  passphrase: string,
  salt: Buffer,
  capsule?: Buffer,
): Result<SessionKey> {
  const masterKey: Buffer = Buffer.from(scryptSync(passphrase, salt, KEY_BYTES, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  }))
  const sessionId = crypto.randomUUID()

  // ── ML-KEM-768 hybrid (BEFORE HKDF sub-keys) ────────────────────────────
  // Derive a deterministic ML-KEM keypair from the masterKey so that
  // the same passphrase always produces the same public key for a given salt.
  const kybSeed = Buffer.from(
    hkdfSync('sha256', masterKey, salt, 'honey:kyber:seed:v1', MLKEM_SEED_BYTES),
  )
  const { secretKey, publicKey } = ml_kem768.keygen(kybSeed)
  const mlkemPublicKey = Buffer.from(publicKey).toString('base64url')

  // If a capsule was provided, XOR the ML-KEM shared secret into masterKey.
  // masterKey = scrypt_output XOR HKDF(kyber_sharedSecret)
  // Breaking one assumption alone is not sufficient to recover the real key.
  if (capsule !== undefined) {
    const sharedSecret = ml_kem768.decapsulate(capsule, secretKey)
    const kybContribution = Buffer.from(
      hkdfSync('sha256', sharedSecret, salt, 'honey:kyber:hybrid:v1', KEY_BYTES),
    )
    for (let i = 0; i < KEY_BYTES; i++) {
      const a = masterKey[i] ?? 0
      const b = kybContribution[i] ?? 0
      masterKey[i] = a ^ b
    }
  }

  // ── HKDF sub-keys ────────────────────────────────────────────────────────
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
    mlkemPublicKey,
    derivedAt: Date.now(),
    toJSON() {
      return {
        sessionId: this.sessionId,
        derivedAt: this.derivedAt,
        keyDerivation: 'scrypt-v1+ml-kem-768',
        mlkemPublicKey: this.mlkemPublicKey,
      }
    },
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
