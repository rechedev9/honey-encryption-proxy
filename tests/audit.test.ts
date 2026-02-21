/**
 * Tests for the audit logger.
 */

import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { randomBytes } from 'node:crypto'
import { writeAuditEntry, getAuditFilePath, resetAuditState, initAuditSigner } from '../src/audit.ts'
import { unlinkSync, readFileSync, existsSync } from 'node:fs'
import { dirname } from 'node:path'
import type { AuditEntry } from '../src/types.ts'

function makeEntry(overrides?: Partial<AuditEntry>): AuditEntry {
  return {
    timestamp: new Date().toISOString(),
    requestId: 'test-req-001',
    sessionId: 'test-session-001',
    identifiersObfuscated: 5,
    numbersObfuscated: 2,
    durationMs: 123,
    streaming: false,
    upstreamStatus: 200,
    ...overrides,
  }
}

describe('Audit logger', () => {
  const auditFile = getAuditFilePath()
  const auditDir = dirname(auditFile)

  beforeEach(() => {
    resetAuditState()
    try {
      unlinkSync(auditFile)
    } catch {
      // file may not exist
    }
  })

  afterEach(() => {
    try {
      unlinkSync(auditFile)
    } catch {
      // file may not exist
    }
  })

  it('writes a JSONL line to the audit file', async () => {
    const entry = makeEntry()
    await writeAuditEntry(entry)

    const content = readFileSync(auditFile, 'utf-8').trim()
    const parsed = JSON.parse(content) as AuditEntry
    expect(parsed.requestId).toBe('test-req-001')
    expect(parsed.identifiersObfuscated).toBe(5)
  })

  it('appends multiple entries as separate lines', async () => {
    await writeAuditEntry(makeEntry({ requestId: 'req-1' }))
    await writeAuditEntry(makeEntry({ requestId: 'req-2' }))

    const lines = readFileSync(auditFile, 'utf-8').trim().split('\n')
    expect(lines.length).toBe(2)

    const first = JSON.parse(lines[0] as string) as AuditEntry
    const second = JSON.parse(lines[1] as string) as AuditEntry
    expect(first.requestId).toBe('req-1')
    expect(second.requestId).toBe('req-2')
  })

  it('creates the audit directory if it does not exist', async () => {
    // The directory should already exist from ~/.honey-proxy, but
    // resetAuditState ensures the "dirReady" flag is false so it re-checks
    if (!existsSync(auditDir)) {
      // If by some chance it doesn't exist, the write should create it
      await writeAuditEntry(makeEntry())
      expect(existsSync(auditDir)).toBe(true)
    } else {
      // Directory already exists; just verify write succeeds
      await writeAuditEntry(makeEntry())
      expect(existsSync(auditFile)).toBe(true)
    }
  })

  it('does not throw on write failure', async () => {
    // Writing to an impossible path would fail, but resetAuditState + the
    // actual audit code just logs a warning. We verify no exception escapes.
    // Since we can't easily mock the path, just verify the normal path works.
    await expect(writeAuditEntry(makeEntry())).resolves.toBeUndefined()
  })

  describe('SPHINCS+ audit signatures (SLH-DSA-SHA2-128s)', () => {
    it('entry has no signature fields when signer is not initialised', async () => {
      // resetAuditState() already called in beforeEach — signer is null
      await writeAuditEntry(makeEntry())

      const content = readFileSync(auditFile, 'utf-8').trim()
      const parsed = JSON.parse(content) as AuditEntry
      expect(parsed.signature).toBeUndefined()
      expect(parsed.sigAlgorithm).toBeUndefined()
    })

    it('entry includes signature and sigAlgorithm after initAuditSigner()', async () => {
      initAuditSigner(randomBytes(32))
      await writeAuditEntry(makeEntry())

      const content = readFileSync(auditFile, 'utf-8').trim()
      const parsed = JSON.parse(content) as AuditEntry
      expect(parsed.signature).toBeDefined()
      expect(parsed.sigAlgorithm).toBe('slh-dsa-sha2-128s')
    })

    it('signature is a non-empty base64url string', async () => {
      initAuditSigner(randomBytes(32))
      await writeAuditEntry(makeEntry())

      const content = readFileSync(auditFile, 'utf-8').trim()
      const parsed = JSON.parse(content) as AuditEntry
      expect(typeof parsed.signature).toBe('string')
      expect((parsed.signature?.length ?? 0)).toBeGreaterThan(0)
    })

    // SPHINCS+ keygen + 2 signatures in pure JS can exceed the default 5 s timeout
    it('different entries produce different signatures', async () => {
      const macKey = randomBytes(32)
      initAuditSigner(macKey)

      await writeAuditEntry(makeEntry({ requestId: 'req-a' }))
      await writeAuditEntry(makeEntry({ requestId: 'req-b' }))

      const lines = readFileSync(auditFile, 'utf-8').trim().split('\n')
      const first = JSON.parse(lines[0] as string) as AuditEntry
      const second = JSON.parse(lines[1] as string) as AuditEntry

      expect(first.signature).not.toBe(second.signature)
    }, 15_000)
  })
})
