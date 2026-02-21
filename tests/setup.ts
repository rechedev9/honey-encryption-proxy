/**
 * Global test setup — runs before any test suite.
 *
 * Initialises tree-sitter so AST-based extraction is available in all tests.
 * Failures are non-fatal: tests that exercise the AST path will still pass
 * via the regex fallback.
 */

import { initTreeSitter } from '../src/ast/tree-sitter.ts'

await initTreeSitter()
