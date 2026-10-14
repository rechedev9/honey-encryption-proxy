import { appendFile, mkdir, lstat } from 'node:fs/promises'
import { existsSync, readFileSync } from 'node:fs'
import { join, resolve, sep } from 'node:path'
import { homedir, userInfo } from 'node:os'
import { hkdfSync } from 'node:crypto'
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa'
import { logger } from './logger.ts'
import type { AuditEntry } from './types.ts'

// SLH-DSA-SHA2-128s requires 3 x N bytes of seed (N = 16 for the 128s variant).
const SLH_DSA_SEED_BYTES = 48

function isErrnoException(value: unknown): value is NodeJS.ErrnoException {
  return value instanceof Error && 'code' in value
}

function accountHomeDirectory(): string | undefined {
  let passwd: string
  try {
    passwd = readFileSync('/etc/passwd', 'utf8')
  } catch (e: unknown) {
    if (isErrnoException(e) && e.code === 'ENOENT') return undefined
    throw e
  }
  const uid = userInfo().uid
  for (const line of passwd.split('\n')) {
    if (line.length === 0 || line.startsWith('#')) continue
    const fields = line.split(':')
    const entryUid = fields[2]
    const entryHome = fields[5]
    if (entryUid !== undefined && entryHome !== undefined && Number(entryUid) === uid) {
      return entryHome
    }
  }
  throw new Error(`account home directory for uid ${uid} is not in the passwd database`)
}

const accountHome = accountHomeDirectory()
const AUDIT_DIR = resolve(join(homedir(), '.honey-proxy'))
if (accountHome !== undefined) {
  const trustedHome = resolve(accountHome)
  if (!AUDIT_DIR.startsWith(trustedHome + sep)) {
    throw new Error(
      `Audit directory escapes home directory: ${AUDIT_DIR} is not under ${trustedHome}`,
    )
  }
}
const AUDIT_FILE = join(AUDIT_DIR, 'audit.jsonl')

let dirReady = false

let auditSecretKey: Uint8Array | null = null

export function getAuditFilePath(): string {
  return AUDIT_FILE
}

export function initAuditSigner(macKey: Buffer): void {
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

function canonicalizeEntry(entry: AuditEntry): string {
  const ordered: Record<string, unknown> = {
    durationMs: entry.durationMs,
    identifiersObfuscated: entry.identifiersObfuscated,
    numbersObfuscated: entry.numbersObfuscated,
    requestId: entry.requestId,
    sessionId: entry.sessionId,
    streaming: entry.streaming,
    timestamp: entry.timestamp,
    upstreamStatus: entry.upstreamStatus,
  }
  return JSON.stringify(ordered)
}

function signEntry(entry: AuditEntry, secretKey: Uint8Array): AuditEntry {
  const msgBytes = Buffer.from(canonicalizeEntry(entry))
  const sig = slh_dsa_sha2_128s.sign(secretKey, msgBytes)
  return {
    ...entry,
    signature: Buffer.from(sig).toString('base64url'),
    sigAlgorithm: 'slh-dsa-sha2-128s',
  }
}

export function resetAuditState(): void {
  dirReady = false
  auditSecretKey = null
}
