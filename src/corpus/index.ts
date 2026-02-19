/**
 * Corpus manager.
 *
 * Provides a stable indexed access layer over the embedded corpus so the
 * DTE can map any seed value to a deterministic, plausible code snippet.
 */

import { CORPUS } from './data.ts'
import type { CorpusEntry } from './data.ts'

export type { CorpusEntry }

export const CORPUS_SIZE = CORPUS.length

/**
 * Returns the corpus entry at the given index (modulo corpus size so any
 * seed is valid).
 */
export function getEntry(index: number): CorpusEntry {
  const idx = ((index % CORPUS_SIZE) + CORPUS_SIZE) % CORPUS_SIZE
  return CORPUS[idx] ?? CORPUS[0]!
}

/**
 * Returns the code string at the given index.
 */
export function getCode(index: number): string {
  return getEntry(index).code
}
