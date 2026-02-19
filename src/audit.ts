/**
 * Audit logger.
 *
 * Writes a JSONL audit trail to ~/.honey-proxy/audit.jsonl.
 * Each entry contains only metadata (counts, timing, status) — never
 * real identifier names, fake names, or code content.
 *
 * Fire-and-forget: failures log a warning but never block the response.
 */

import { appendFile, mkdir } from 'node:fs/promises'
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
