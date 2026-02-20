/**
 * Audit logger.
 *
 * Writes a JSONL audit trail to ~/.honey-proxy/audit.jsonl.
 * Each entry contains only metadata (counts, timing, status) — never
 * real identifier names, fake names, or code content.
 *
 * Fire-and-forget: failures log a warning but never block the response.
 */

import { appendFile, mkdir, lstat } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { logger } from './logger.ts'
import type { AuditEntry } from './types.ts'

const AUDIT_DIR = join(homedir(), '.honey-proxy')
const AUDIT_FILE = join(AUDIT_DIR, 'audit.jsonl')

let dirReady = false

export function getAuditFilePath(): string {
  return AUDIT_FILE
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
    const isNotFound =
      e instanceof Error &&
      'code' in e &&
      (e as { code: unknown }).code === 'ENOENT'
    if (!isNotFound) {
      logger.warn('Audit file access check failed', {
        error: e instanceof Error ? e.message : String(e),
      })
      return
    }
  }

  try {
    await appendFile(AUDIT_FILE, JSON.stringify(entry) + '\n', 'utf-8')
  } catch (e: unknown) {
    logger.warn('Audit write failed', {
      error: e instanceof Error ? e.message : String(e),
    })
  }
}

/** Reset internal state (for testing). */
export function resetAuditState(): void {
  dirReady = false
}
