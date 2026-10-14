import type { CodeBlock } from '../types.ts'
import { shouldObfuscate } from '../honey/fpe.ts'
import { extractIdentifiersAST } from './tree-sitter.ts'

const STRIP_REGEX =
  /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g

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
    if (match.charAt(1) === '*') return match.replace(/[^\n]/g, ' ')
    return ''
  })
}

const FENCE_REGEX_BACKTICK = /^```([^\n`]*)\n([\s\S]*?)^```/gm
const FENCE_REGEX_TILDE = /^~~~([^\n~]*)\n([\s\S]*?)^~~~/gm

function extractFencedBlocks(text: string, regex: RegExp, out: CodeBlock[]): void {
  regex.lastIndex = 0
  let match: RegExpExecArray | null
  while ((match = regex.exec(text)) !== null) {
    out.push({
      lang: (match[1] ?? '').trim(),
      content: match[2] ?? '',
      startOffset: match.index,
      endOffset: match.index + match[0].length,
    })
  }
}

/**
 * Extracts all fenced code blocks from a markdown/prompt string.
 * Returns them in document order.
 */
export function extractCodeBlocks(text: string): CodeBlock[] {
  const blocks: CodeBlock[] = []
  extractFencedBlocks(text, FENCE_REGEX_BACKTICK, blocks)
  extractFencedBlocks(text, FENCE_REGEX_TILDE, blocks)
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
    parts.push(text.slice(cursor, block.startOffset))

    const transformed = transform(block)
    parts.push(`\`\`\`${block.lang}\n${transformed}\`\`\``)

    cursor = block.endOffset
  }

  parts.push(text.slice(cursor))

  return parts.join('')
}

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
