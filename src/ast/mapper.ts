/**
 * High-level code mapper.
 *
 * Combines extractor + FPE to produce an obfuscated version of any text
 * containing code blocks, and exposes the reverse operation for response
 * post-processing.
 */

import {
  buildIdentifierMapping,
  buildNumericMapping,
  applyMapping,
  reverseMapping,
  obfuscateStringLiterals,
} from '../honey/fpe.ts'
import {
  extractCodeBlocks,
  extractIdentifiers,
  transformCodeBlocks,
  stripComments,
} from './extractor.ts'
import type { IdentifierMapping, SessionKey } from '../types.ts'

export interface ObfuscationStats {
  readonly identifiersObfuscated: number
  readonly numbersObfuscated: number
}

export interface MapResult {
  /** Text with code blocks obfuscated (fake identifiers). */
  readonly obfuscated: string
  /** Bidirectional identifier mapping for this request. */
  readonly mapping: IdentifierMapping
  /** Counts of obfuscated items for audit logging. */
  readonly stats: ObfuscationStats
}

/**
 * Obfuscates all code blocks found in `text` using FPE.
 *
 * Steps:
 *  1. Extract fenced code blocks.
 *  2. Collect all unique user-defined identifiers.
 *  3. Build a deterministic fake→real mapping via FPE.
 *  4. Replace real identifiers with fake ones inside each code block.
 *
 * Non-code text (prose) is left untouched so Claude can still understand
 * the question context.
 */
export function obfuscateText(text: string, sessionKey: SessionKey): MapResult {
  const blocks = extractCodeBlocks(text)

  if (blocks.length === 0) {
    const emptyMapping: IdentifierMapping = {
      realToFake: new Map(),
      fakeToReal: new Map(),
    }
    return {
      obfuscated: text,
      mapping: emptyMapping,
      stats: { identifiersObfuscated: 0, numbersObfuscated: 0 },
    }
  }

  // 1. Strip comments before extraction so comment words are never collected
  //    as identifiers and comment content never reaches Anthropic.
  const identifiers = new Set<string>()
  const strippedParts: string[] = []
  for (const block of blocks) {
    const stripped = stripComments(block.content)
    strippedParts.push(stripped)
    for (const id of extractIdentifiers(stripped)) {
      identifiers.add(id)
    }
  }
  const allStripped = strippedParts.join('\n')

  // 2. Build identifier and numeric mappings, then merge them.
  const identifierMapping = buildIdentifierMapping(identifiers, sessionKey.fpeKey)
  const numericMapping = buildNumericMapping(allStripped, sessionKey.fpeKey)

  const realToFake = new Map<string, string>()
  const fakeToReal = new Map<string, string>()
  for (const [k, v] of identifierMapping.realToFake) {
    realToFake.set(k, v)
  }
  for (const [k, v] of identifierMapping.fakeToReal) {
    fakeToReal.set(k, v)
  }
  for (const [k, v] of numericMapping.realToFake) {
    realToFake.set(k, v)
  }
  for (const [k, v] of numericMapping.fakeToReal) {
    fakeToReal.set(k, v)
  }
  const fullMapping: IdentifierMapping = { realToFake, fakeToReal }

  // 3. Transform each code block: strip comments → apply all mappings →
  //    obfuscate exact-match string literals.
  const obfuscated = transformCodeBlocks(text, (block) => {
    const stripped = stripComments(block.content)
    const applied = applyMapping(stripped, realToFake)
    return obfuscateStringLiterals(applied, identifierMapping.realToFake)
  })

  const stats: ObfuscationStats = {
    identifiersObfuscated: identifierMapping.realToFake.size,
    numbersObfuscated: numericMapping.realToFake.size,
  }

  return { obfuscated, mapping: fullMapping, stats }
}

/**
 * Reverses the FPE obfuscation on Claude's response text.
 *
 * Scans the full response for occurrences of fake identifiers (both inside
 * and outside code fences — Claude often repeats identifier names in prose)
 * and replaces them with the original names.
 */
export function deobfuscateText(text: string, mapping: IdentifierMapping): string {
  if (mapping.fakeToReal.size === 0) return text
  return reverseMapping(text, mapping.fakeToReal)
}
