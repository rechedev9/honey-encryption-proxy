import { scryptSync, hkdfSync, randomBytes } from 'node:crypto'
import { ml_kem768 } from '@noble/post-quantum/ml-kem'
import { ok } from '../types.ts'
import type { Result, SessionKey } from '../types.ts'

const SCRYPT_N = 65_536
const SCRYPT_R = 8
const SCRYPT_P = 1
// maxmem must be set explicitly; Node's default cap is 32 MB.
const SCRYPT_MAXMEM = 128 * 1024 * 1024
const KEY_BYTES = 32
const SALT_BYTES = 32
const MLKEM_SEED_BYTES = 64   // ml_kem768.keygen expects a 64-byte seed

export function deriveSessionKey(passphrase: string, capsule?: Buffer): Result<SessionKey> {
  const salt = randomBytes(SALT_BYTES)
  return deriveFromSalt(passphrase, salt, capsule)
}

export function deriveFromSalt(
  passphrase: string,
  salt: Buffer,
  capsule?: Buffer,
): Result<SessionKey> {
  const masterKey: Buffer = Buffer.from(scryptSync(passphrase, salt, KEY_BYTES, {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  }))
  const sessionId = crypto.randomUUID()

  const kybSeed = Buffer.from(
    hkdfSync('sha256', masterKey, salt, 'honey:kyber:seed:v1', MLKEM_SEED_BYTES),
  )
  const { secretKey, publicKey } = ml_kem768.keygen(kybSeed)
  const mlkemPublicKey = Buffer.from(publicKey).toString('base64url')

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
    sharedSecret.fill(0)
    kybContribution.fill(0)
  }
  kybSeed.fill(0)
  ;(secretKey).fill(0)

  const key = Buffer.from(
    hkdfSync('sha256', masterKey, salt, 'honey:aes-ctr:v1', KEY_BYTES),
  )
  const macKey = Buffer.from(
    hkdfSync('sha256', masterKey, salt, 'honey:hmac:v1', KEY_BYTES),
  )
  const fpeKey = Buffer.from(
    hkdfSync('sha256', masterKey, salt, 'honey:fpe:v1', KEY_BYTES),
  )

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

/** JavaScript strings (like a passphrase) cannot be zeroed because they are immutable. */
export function zeroSessionKey(sessionKey: SessionKey): void {
  sessionKey.key.fill(0)
  sessionKey.macKey.fill(0)
  sessionKey.fpeKey.fill(0)
  sessionKey.salt.fill(0)
}
