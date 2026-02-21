/**
 * Tree-sitter AST-based identifier extraction.
 *
 * Provides precise identifier extraction using web-tree-sitter WASM grammars.
 * Initialised once at proxy startup; callers fall back to regex on null return.
 *
 * Supported grammars: typescript, javascript, tsx.
 * Empty language tag defaults to TypeScript (most common in this proxy context).
 *
 * Uses web-tree-sitter@0.20.x API (Parser.Language, export = Parser).
 */

import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
// eslint-disable-next-line @typescript-eslint/naming-convention
import Parser from 'web-tree-sitter'
import { shouldObfuscate } from '../honey/fpe.ts'
import { logger } from '../logger.ts'
import { ok, err } from '../types.ts'
import type { Result } from '../types.ts'

// ── Types ─────────────────────────────────────────────────────────────────────

type SupportedLang = 'typescript' | 'javascript' | 'tsx'

/**
 * AST node types that represent user-defined identifiers in JS/TS grammars.
 * Structurally excludes string fragments, comment content, and keywords.
 */
const IDENTIFIER_NODE_TYPES: string[] = [
  'identifier',
  'property_identifier',
  'type_identifier',
  'shorthand_property_identifier',
  'shorthand_property_identifier_pattern',
]

// ── Module-level state ────────────────────────────────────────────────────────

interface TreeSitterState {
  readonly parser: Parser
  readonly languages: ReadonlyMap<SupportedLang, Parser.Language>
}

// Mutable state, initialised once at startup (same pattern as SESSION_KEY in proxy.ts)
let state: TreeSitterState | null = null

// ── Language tag resolution ───────────────────────────────────────────────────

/** Maps code-fence language tags to supported tree-sitter grammars. */
const LANG_TAG_MAP: Readonly<Record<string, SupportedLang>> = {
  typescript: 'typescript',
  ts: 'typescript',
  javascript: 'javascript',
  js: 'javascript',
  tsx: 'tsx',
}

/** Returns the grammar to use for a given language tag, or null if unsupported. */
export function resolveLanguage(langTag: string): SupportedLang | null {
  // Empty tag defaults to TypeScript (most common in this proxy context)
  if (langTag === '') return 'typescript'
  return LANG_TAG_MAP[langTag.toLowerCase()] ?? null
}

// ── Path helpers ──────────────────────────────────────────────────────────────

const MODULE_DIR = dirname(fileURLToPath(import.meta.url))
const NODE_MODULES = resolve(MODULE_DIR, '..', '..', 'node_modules')

function treeSitterWasmPath(): string {
  // 0.20.x uses 'tree-sitter.wasm' (not 'web-tree-sitter.wasm')
  return resolve(NODE_MODULES, 'web-tree-sitter', 'tree-sitter.wasm')
}

function grammarWasmPath(lang: SupportedLang): string {
  return resolve(NODE_MODULES, 'tree-sitter-wasms', 'out', `tree-sitter-${lang}.wasm`)
}

// ── Initialization ────────────────────────────────────────────────────────────

/**
 * Initialises the tree-sitter WASM runtime and loads TS/JS/TSX grammars.
 * Must be called once at proxy startup. Non-fatal — callers proceed with
 * regex extraction if this returns an error result.
 */
export async function initTreeSitter(): Promise<Result<void>> {
  try {
    // Read the WASM binary directly so tree-sitter doesn't need to fetch it
    const wasmBinary = await Bun.file(treeSitterWasmPath()).arrayBuffer()
    // Parser.init() accepts an object with optional Emscripten module fields
    await Parser.init({ wasmBinary })

    const parser = new Parser()
    const langs: readonly SupportedLang[] = ['typescript', 'javascript', 'tsx']

    // Load all grammars concurrently for faster startup
    const langEntries = await Promise.all(
      langs.map(async (lang): Promise<[SupportedLang, Parser.Language]> => {
        const bytes = new Uint8Array(await Bun.file(grammarWasmPath(lang)).arrayBuffer())
        // 0.20.x API: Parser.Language.load() instead of Language.load()
        const language = await Parser.Language.load(bytes)
        return [lang, language]
      }),
    )

    state = {
      parser,
      languages: new Map(langEntries),
    }

    logger.info('Tree-sitter AST extraction enabled', { grammars: langs })
    return ok(undefined)
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : String(e)
    logger.warn('Tree-sitter initialization failed — falling back to regex', { error: message })
    return err(new Error(`Tree-sitter init failed: ${message}`))
  }
}

/** Returns true if tree-sitter has been successfully initialised. */
export function isTreeSitterReady(): boolean {
  return state !== null
}

// ── AST extraction ────────────────────────────────────────────────────────────

/**
 * Extracts user-defined identifiers from source code using an AST.
 *
 * Returns null when tree-sitter is uninitialised or the language tag is
 * unsupported, signalling the caller to fall back to regex extraction.
 *
 * Unlike regex, this never extracts words from inside string literals or
 * comments — they live in different grammar nodes and are invisible to
 * the identifier query.
 */
export function extractIdentifiersAST(
  code: string,
  langTag: string,
): ReadonlySet<string> | null {
  if (state === null) return null

  const lang = resolveLanguage(langTag)
  if (lang === null) return null

  const language = state.languages.get(lang)
  if (language === undefined) return null

  state.parser.setLanguage(language)
  const tree = state.parser.parse(code)

  try {
    const found = new Set<string>()
    const nodes = tree.rootNode.descendantsOfType(IDENTIFIER_NODE_TYPES)

    for (const node of nodes) {
      const text = node.text
      if (shouldObfuscate(text)) {
        found.add(text)
      }
    }

    return found
  } finally {
    tree.delete()
  }
}
