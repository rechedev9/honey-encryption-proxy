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
import { ok, err } from '../types.ts'
import type { CodeBlock, IdentifierMapping, Result, SessionKey } from '../types.ts'

export interface ObfuscationStats {
  readonly identifiersObfuscated: number
  readonly numbersObfuscated: number
}

interface MapResult {
  /** Text with code blocks obfuscated (fake identifiers). */
  readonly obfuscated: string
  /** Bidirectional identifier mapping for this request. */
  readonly mapping: IdentifierMapping
  /** Counts of obfuscated items for audit logging. */
  readonly stats: ObfuscationStats
}

/** Strips comments and collects identifiers from a set of code blocks. */
function collectFromBlocks(
  blocks: readonly CodeBlock[],
  identifiers: Set<string>,
  stripped: string[],
): void {
  for (const block of blocks) {
    const s = stripComments(block.content)
    stripped.push(s)
    for (const id of extractIdentifiers(s, block.lang)) {
      identifiers.add(id)
    }
  }
}

/**
 * Obfuscates all code blocks found in  using FPE.
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
export function obfuscateText(text: string, sessionKey: SessionKey): Result<MapResult> {
  const blocks = extractCodeBlocks(text)

  if (blocks.length === 0) {
    const emptyMapping: IdentifierMapping = {
      realToFake: new Map(),
      fakeToReal: new Map(),
    }
    return ok({
      obfuscated: text,
      mapping: emptyMapping,
      stats: { identifiersObfuscated: 0, numbersObfuscated: 0 },
    })
  }

  // 1. Strip comments before extraction so comment words are never collected
  //    as identifiers and comment content never reaches Anthropic.
  const identifiers = new Set<string>()
  const strippedParts: string[] = []
  collectFromBlocks(blocks, identifiers, strippedParts)

  // 2. Build identifier and numeric mappings, then merge them.
  const identifierMappingResult = buildIdentifierMapping(identifiers, sessionKey.fpeKey)
  if (!identifierMappingResult.ok) {
    return err(identifierMappingResult.error)
  }
  const identifierMapping = identifierMappingResult.value
  const numericMapping = buildNumericMapping(strippedParts.join('\n'), sessionKey.fpeKey)

  const fullMapping: IdentifierMapping = {
    realToFake: new Map([...identifierMapping.realToFake, ...numericMapping.realToFake]),
    fakeToReal: new Map([...identifierMapping.fakeToReal, ...numericMapping.fakeToReal]),
  }

  // 3. Transform each code block: strip comments → apply all mappings →
  //    obfuscate exact-match string literals.
  const codeObfuscated = transformCodeBlocks(text, (block) => {
    const stripped = stripComments(block.content)
    const applied = applyMapping(stripped, fullMapping.realToFake)
    return obfuscateStringLiterals(applied, identifierMapping.realToFake)
  })

  // Also apply the mapping to prose text outside code blocks so real
  // identifiers in natural-language context never reach Anthropic.
  const obfuscated = applyMapping(codeObfuscated, fullMapping.realToFake)

  const stats: ObfuscationStats = {
    identifiersObfuscated: identifierMapping.realToFake.size,
    numbersObfuscated: numericMapping.realToFake.size,
  }

  return ok({ obfuscated, mapping: fullMapping, stats })
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

/**
 * Builds a combined identifier+numeric mapping by scanning code blocks
 * across all provided text strings. Used for cross-message global mapping.
 *
 * Returns the merged mapping plus the identifier-only mapping (needed for
 * string-literal obfuscation which must not touch numeric replacements).
 */
export function buildGlobalMapping(
  texts: readonly string[],
  sessionKey: SessionKey,
): Result<{
  readonly mapping: IdentifierMapping
  readonly identifierRealToFake: ReadonlyMap<string, string>
  readonly stats: ObfuscationStats
}> {
  const allIdentifiers = new Set<string>()
  const allStripped: string[] = []

  for (const text of texts) {
    collectFromBlocks(extractCodeBlocks(text), allIdentifiers, allStripped)
  }

  const identifierMappingResult = buildIdentifierMapping(allIdentifiers, sessionKey.fpeKey)
  if (!identifierMappingResult.ok) {
    return err(identifierMappingResult.error)
  }
  const identifierMapping = identifierMappingResult.value
  const numericMapping = buildNumericMapping(allStripped.join('\n'), sessionKey.fpeKey)

  const realToFake = new Map<string, string>([
    ...identifierMapping.realToFake,
    ...numericMapping.realToFake,
  ])
  const fakeToReal = new Map<string, string>([
    ...identifierMapping.fakeToReal,
    ...numericMapping.fakeToReal,
  ])

  return ok({
    mapping: { realToFake, fakeToReal },
    identifierRealToFake: identifierMapping.realToFake,
    stats: {
      identifiersObfuscated: identifierMapping.realToFake.size,
      numbersObfuscated: numericMapping.realToFake.size,
    },
  })
}

/**
 * Applies a pre-built mapping to the full text: code blocks get comment
 * stripping + full mapping + string-literal obfuscation; prose outside
 * code blocks gets identifier+numeric mapping applied (word-boundary safe).
 *
 * This fixes the prose-leakage finding: real identifiers that appear in
 * natural-language context are obfuscated with the same fake names used
 * inside code fences, so Anthropic never sees real names in prose either.
 */
export function applyMappingToFullText(
  text: string,
  mapping: IdentifierMapping,
  identifierRealToFake: ReadonlyMap<string, string>,
): string {
  if (mapping.realToFake.size === 0) return text

  // Step 1: transform code blocks (strip comments + full mapping + string literals)
  const withCodeObfuscated = transformCodeBlocks(text, (block) => {
    const stripped = stripComments(block.content)
    const applied = applyMapping(stripped, mapping.realToFake)
    return obfuscateStringLiterals(applied, identifierRealToFake)
  })

  // Step 2: apply the mapping to prose text outside code blocks.
  // Code blocks are already transformed — the real identifiers are gone from
  // them so a second pass does not double-replace anything.
  return applyMapping(withCodeObfuscated, mapping.realToFake)
}
