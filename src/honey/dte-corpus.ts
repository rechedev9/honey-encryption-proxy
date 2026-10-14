/**
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

export function decodeEntry(index: number): CorpusEntry {
  return getEntry(index)
}

export function indexToBytes(index: number): Buffer {
  const buf = Buffer.alloc(4)
  buf.writeUInt32BE(index, 0)
  return buf
}

function bytesToIndex(buf: Buffer): number {
  return buf.readUInt32BE(0) % CORPUS_SIZE
}
