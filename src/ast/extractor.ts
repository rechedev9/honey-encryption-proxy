/**
 * Code block and identifier extractor.
 *
 * Phase 1 uses regex-based extraction (no native WASM dependency).
 * Phase 2 will migrate to web-tree-sitter for full AST precision.
 *
 * Extracts:
 *  - Fenced code blocks from Markdown/prompt text (``` ... ```)
 *  - User-defined identifiers from code text
 */

import type { CodeBlock } from '../types.ts'
import { shouldObfuscate } from '../honey/fpe.ts'

// ── Comment stripping ────────────────────────────────────────────────────────

// Matches: double-quoted string | single-quoted string | template literal |
//          block comment | line comment — in priority order so string contents
//          are never misidentified as comments.
// Using RegExp constructor (not a regex literal) to avoid parser ambiguity
// with the backtick character inside the pattern.
const STRIP_REGEX = new RegExp(
  [
    '"(?:[^"\\\\]|\\\\.)*"',   // double-quoted string
    "'(?:[^'\\\\]|\\\\.)*'",   // single-quoted string
    '`(?:[^`\\\\]|\\\\.)*`',   // template literal (backtick is safe inside single quotes)
    '/\\*[\\s\\S]*?\\*/',      // block comment
    '//[^\\n]*',               // line comment
  ].join('|'),
  'g',
)

/**
 * Removes // and block comments from source code.
 * String literals are left entirely untouched.
 * Block comments have their non-newline characters replaced with spaces so
 * that line numbers are preserved in any downstream processing.
 */
export function stripComments(code: string): string {
  STRIP_REGEX.lastIndex = 0
  return code.replace(STRIP_REGEX, (match: string): string => {
    // String literals are the only alternatives that don't start with /
    if (match.charAt(0) !== '/') return match
    // Block comment — replace non-newline chars with spaces to preserve line numbers
    if (match.charAt(1) === '*') return match.replace(/[^\n]/g, ' ')
    // Line comment — remove entirely
    return ''
  })
}

// ── Code block extraction ────────────────────────────────────────────────────

// RegExp constructor used to avoid backtick-in-regex-literal TypeScript 5.9+ parse error.
const FENCE_REGEX = new RegExp('^```([^\\n`]*)\\n([\\s\\S]*?)^```', 'gm')

/**
 * Extracts all fenced code blocks from a markdown/prompt string.
 * Returns them in document order.
 */
export function extractCodeBlocks(text: string): CodeBlock[] {
  const blocks: CodeBlock[] = []
  let match: RegExpExecArray | null

  // Reset lastIndex before use
  FENCE_REGEX.lastIndex = 0

  while ((match = FENCE_REGEX.exec(text)) !== null) {
    blocks.push({
      lang: (match[1] ?? '').trim(),
      content: match[2] ?? '',
      startOffset: match.index,
      endOffset: match.index + match[0].length,
    })
  }

  return blocks
}

/**
 * Replaces code block contents in `text` using a transform function.
 * Non-code text is left untouched.
 */
export function transformCodeBlocks(
  text: string,
  transform: (block: CodeBlock) => string,
): string {
  const blocks = extractCodeBlocks(text)
  if (blocks.length === 0) return text

  const parts: string[] = []
  let cursor = 0

  for (const block of blocks) {
    // Append text before this block
    parts.push(text.slice(cursor, block.startOffset))

    // Reconstruct the fence with transformed content
    const transformed = transform(block)
    parts.push(`\`\`\`${block.lang}\n${transformed}\`\`\``)

    cursor = block.endOffset
  }

  // Append remaining text after last block
  parts.push(text.slice(cursor))

  return parts.join('')
}

// ── Identifier extraction ────────────────────────────────────────────────────

// Matches any valid JS/TS identifier token.
const IDENTIFIER_REGEX = /\b([A-Za-z_$][A-Za-z0-9_$]*)\b/g

/**
 * Extracts all unique user-defined identifiers from source code.
 * Filters out language keywords, builtins, and short tokens via the FPE
 * skip-list.
 */
export function extractIdentifiers(code: string): ReadonlySet<string> {
  const found = new Set<string>()
  let match: RegExpExecArray | null

  IDENTIFIER_REGEX.lastIndex = 0

  while ((match = IDENTIFIER_REGEX.exec(code)) !== null) {
    const id = match[1]
    if (id !== undefined && shouldObfuscate(id)) {
      found.add(id)
    }
  }

  return found
}

/**
 * Extracts all unique identifiers from a list of code blocks.
 */
export function extractIdentifiersFromBlocks(blocks: readonly CodeBlock[]): ReadonlySet<string> {
  const all = new Set<string>()
  for (const block of blocks) {
    for (const id of extractIdentifiers(block.content)) {
      all.add(id)
    }
  }
  return all
}
