/**
 * Code block and identifier extractor.
 *
 * Identifier extraction uses web-tree-sitter AST when available (precise —
 * ignores string literal contents and comments) with a regex fallback for
 * unsupported languages or when tree-sitter is uninitialised.
 *
 * Extracts:
 *  - Fenced code blocks from Markdown/prompt text (``` ... ```)
 *  - User-defined identifiers from code text
 */

import type { CodeBlock } from '../types.ts'
import { shouldObfuscate } from '../honey/fpe.ts'
import { extractIdentifiersAST } from './tree-sitter.ts'

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
    if (!match.startsWith('/')) return match
    // Block comment — replace non-newline chars with spaces to preserve line numbers
    if (match.charAt(1) === '*') return match.replace(/[^\n]/g, ' ')
    // Line comment — remove entirely
    return ''
  })
}

// ── Code block extraction ────────────────────────────────────────────────────

// Two separate patterns — one for backtick fences, one for tilde fences.
// RegExp constructors used to avoid backtick/tilde-in-regex-literal parse issues.
const FENCE_REGEX_BACKTICK = new RegExp('^```([^\\n`]*)\\n([\\s\\S]*?)^```', 'gm')
const FENCE_REGEX_TILDE = new RegExp('^~~~([^\\n~]*)\\n([\\s\\S]*?)^~~~', 'gm')

/**
 * Extracts all fenced code blocks from a markdown/prompt string.
 * Returns them in document order.
 */
export function extractCodeBlocks(text: string): CodeBlock[] {
  const blocks: CodeBlock[] = []
  let match: RegExpExecArray | null

  FENCE_REGEX_BACKTICK.lastIndex = 0
  while ((match = FENCE_REGEX_BACKTICK.exec(text)) !== null) {
    blocks.push({
      lang: (match[1] ?? '').trim(),
      content: match[2] ?? '',
      startOffset: match.index,
      endOffset: match.index + match[0].length,
    })
  }

  FENCE_REGEX_TILDE.lastIndex = 0
  while ((match = FENCE_REGEX_TILDE.exec(text)) !== null) {
    blocks.push({
      lang: (match[1] ?? '').trim(),
      content: match[2] ?? '',
      startOffset: match.index,
      endOffset: match.index + match[0].length,
    })
  }

  // Sort by document position so transformCodeBlocks processes them in order
  blocks.sort((a, b) => a.startOffset - b.startOffset)

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
 * Regex-based identifier extraction (fallback path).
 * Includes words inside string literals — callers must strip comments first.
 */
function extractIdentifiersRegex(code: string): ReadonlySet<string> {
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
 * Extracts all unique user-defined identifiers from source code.
 *
 * Tries AST extraction first (tree-sitter — precise, skips string/comment
 * contents). Falls back to regex when tree-sitter is uninitialised or the
 * language tag is unsupported.
 *
 * @param code     Source code with comments already stripped by the caller.
 * @param langTag  Language fence tag (e.g. "typescript", "ts", "js"). Optional.
 */
export function extractIdentifiers(code: string, langTag = ''): ReadonlySet<string> {
  const astResult = extractIdentifiersAST(code, langTag)
  if (astResult !== null) return astResult
  return extractIdentifiersRegex(code)
}

