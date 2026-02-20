/**
 * Corpus-based Distribution-Transforming Encoder (DTE) — Variante A.
 *
 * Provides the Honey Encryption indistinguishability property:
 *   - encode(code, key) → deterministic index in [0, CORPUS_SIZE)
 *   - decode(index)     → plausible code snippet (real if key is correct,
 *                         different-but-plausible decoy if key is wrong)
 *
 * Security:
 *   A brute-force attacker trying different passphrases derives different FPE
 *   keys, which produce different fake identifier mappings — each of which
 *   corresponds to a different, syntactically valid code snippet from the
 *   corpus.  The attacker cannot distinguish the real mapping from the decoys
 *   without the correct passphrase.
 *
 * Reference: Juels & Ristenpart, "Honey Encryption" (EUROCRYPT 2014).
 */

import { createHmac } from 'node:crypto'
import { getCode, getEntry, CORPUS_SIZE } from '../corpus/index.ts'
import type { CorpusEntry } from '../corpus/index.ts'

/**
 * Maps a code string deterministically to a corpus index.
 *
 * The same (code, key) pair always returns the same index.
 * Different keys produce uniformly distributed different indices.
 */
export function encode(code: string, key: Buffer): number {
  const hash = createHmac('sha256', key).update(code).digest()
  const raw = hash.readUInt32BE(0)
  return raw % CORPUS_SIZE
}

/**
 * Returns the corpus code snippet at the given index.
 * Always succeeds — invalid / out-of-range indices wrap around.
 */
export function decode(index: number): string {
  return getCode(index)
}

/**
 * Returns the full corpus entry (including metadata) at the given index.
 */
export function decodeEntry(index: number): CorpusEntry {
  return getEntry(index)
}

/**
 * Demonstrates the honey encryption property:
 * encrypting the index with a stream cipher (AES-256-CTR) means that
 * decryption with a wrong key produces a different-but-valid index.
 *
 * Returns the index serialised as a 4-byte big-endian buffer.
 */
export function indexToBytes(index: number): Buffer {
  const buf = Buffer.alloc(4)
  buf.writeUInt32BE(index, 0)
  return buf
}

export function bytesToIndex(buf: Buffer): number {
  return buf.readUInt32BE(0) % CORPUS_SIZE
}
