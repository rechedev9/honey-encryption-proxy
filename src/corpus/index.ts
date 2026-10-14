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
  const entry = CORPUS[idx] ?? CORPUS[0]
  if (entry === undefined) throw new Error('Corpus is empty — cannot get entry')
  return entry
}

export function getCode(index: number): string {
  return getEntry(index).code
}
