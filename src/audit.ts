/**
 * Audit logger.
 *
 * Writes a JSONL audit trail to ~/.honey-proxy/audit.jsonl.
 * Each entry contains only metadata (counts, timing, status) — never
 * real identifier names, fake names, or code content.
 *
 * If initAuditSigner() has been called, each entry is signed with
 * SLH-DSA-SHA2-128s (SPHINCS+) so that the audit log is tamper-evident
 * even if the log file is later exfiltrated.
 *
 * Fire-and-forget: failures log a warning but never block the response.
 */

import { appendFile, mkdir, lstat } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { join, resolve, sep } from 'node:path'
import { homedir } from 'node:os'
import { hkdfSync } from 'node:crypto'
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa'
import { logger } from './logger.ts'
import type { AuditEntry } from './types.ts'

const AUDIT_DIR = join(homedir(), '.honey-proxy')
const AUDIT_FILE = join(AUDIT_DIR, 'audit.jsonl')

// SLH-DSA-SHA2-128s requires 3 x N bytes of seed (N = 16 for the 128s variant).
const SLH_DSA_SEED_BYTES = 48

// Guard against $HOME manipulation: verify the audit directory stays
// within the real home directory before any writes occur.
const resolvedHome = resolve(homedir())
const resolvedDir = resolve(AUDIT_DIR)
if (!resolvedDir.startsWith(resolvedHome + sep)) {
  throw new Error(
    `Audit directory escapes home directory: ${resolvedDir} is not under ${resolvedHome}`,
  )
}

/** Type guard for Node.js filesystem errors with a `code` property. */
function isErrnoException(value: unknown): value is NodeJS.ErrnoException {
  return value instanceof Error && 'code' in value
}

let dirReady = false

// Module-level signing key — set once via initAuditSigner(), null until then.
let auditSecretKey: Uint8Array | null = null

export function getAuditFilePath(): string {
  return AUDIT_FILE
}

/**
 * Initialises the SLH-DSA-SHA2-128s signer for audit entries.
 * Should be called once after session key derivation.
 *
 * The signing keypair is derived deterministically from macKey so that the
 * public key can be shared for offline log verification.
 */
export function initAuditSigner(macKey: Buffer): void {
  // Use a static domain-separation string as the HKDF salt (not macKey itself)
  // to avoid the circular dependency of using the IKM as its own salt.
  const seed = Buffer.from(hkdfSync('sha256', macKey, 'honey:slh-dsa:salt', 'honey:slh-dsa:v1', SLH_DSA_SEED_BYTES))
  const { secretKey } = slh_dsa_sha2_128s.keygen(seed)
  auditSecretKey = secretKey
}

export async function writeAuditEntry(entry: AuditEntry): Promise<void> {
  if (!dirReady) {
    try {
      if (!existsSync(AUDIT_DIR)) {
        await mkdir(AUDIT_DIR, { recursive: true })
      }
      dirReady = true
    } catch (e: unknown) {
      logger.warn('Audit dir creation failed', {
        error: e instanceof Error ? e.message : String(e),
      })
      return
    }
  }

  // Guard against symlink attacks: if the audit file path is a symlink,
  // an attacker could redirect writes to an arbitrary target file.
  try {
    const stats = await lstat(AUDIT_FILE)
    if (stats.isSymbolicLink()) {
      logger.warn('Audit file is a symlink — refusing to write', { path: AUDIT_FILE })
      return
    }
  } catch (e: unknown) {
    // ENOENT means the file does not exist yet — safe to create.
    // Any other error is unexpected: log and bail.
    const isNotFound = isErrnoException(e) && e.code === 'ENOENT'
    if (!isNotFound) {
      logger.warn('Audit file access check failed', {
        error: e instanceof Error ? e.message : String(e),
      })
      return
    }
  }

  try {
    const finalEntry: AuditEntry = auditSecretKey !== null
      ? signEntry(entry, auditSecretKey)
      : entry

    await appendFile(AUDIT_FILE, JSON.stringify(finalEntry) + '\n', 'utf-8')
  } catch (e: unknown) {
    logger.warn('Audit write failed', {
      error: e instanceof Error ? e.message : String(e),
    })
  }
}

/** Signs an audit entry with SLH-DSA-SHA2-128s and returns a new entry with the signature fields. */
function signEntry(entry: AuditEntry, secretKey: Uint8Array): AuditEntry {
  const msgBytes = Buffer.from(JSON.stringify(entry))
  const sig = slh_dsa_sha2_128s.sign(secretKey, msgBytes)
  return {
    ...entry,
    signature: Buffer.from(sig).toString('base64url'),
    sigAlgorithm: 'slh-dsa-sha2-128s',
  }
}

/** Reset internal state (for testing). */
export function resetAuditState(): void {
  dirReady = false
  auditSecretKey = null
}
