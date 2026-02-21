/**
 * Unit tests for AST-based identifier extraction (web-tree-sitter).
 *
 * Tree-sitter is initialised via tests/setup.ts preload.
 * Tests verify both the positive extraction cases and — crucially — that
 * string literal contents and comment text are NOT extracted.
 */

import { describe, it, expect } from 'bun:test'
import {
  resolveLanguage,
  isTreeSitterReady,
  extractIdentifiersAST,
} from '../src/ast/tree-sitter.ts'

// ── resolveLanguage ───────────────────────────────────────────────────────────

describe('resolveLanguage', () => {
  it('maps "typescript" → typescript', () => {
    expect(resolveLanguage('typescript')).toBe('typescript')
  })

  it('maps "ts" → typescript', () => {
    expect(resolveLanguage('ts')).toBe('typescript')
  })

  it('maps "javascript" → javascript', () => {
    expect(resolveLanguage('javascript')).toBe('javascript')
  })

  it('maps "js" → javascript', () => {
    expect(resolveLanguage('js')).toBe('javascript')
  })

  it('maps "tsx" → tsx', () => {
    expect(resolveLanguage('tsx')).toBe('tsx')
  })

  it('is case-insensitive', () => {
    expect(resolveLanguage('TypeScript')).toBe('typescript')
    expect(resolveLanguage('TS')).toBe('typescript')
    expect(resolveLanguage('JS')).toBe('javascript')
  })

  it('maps empty string → typescript (default)', () => {
    expect(resolveLanguage('')).toBe('typescript')
  })

  it('returns null for unsupported languages', () => {
    expect(resolveLanguage('python')).toBeNull()
    expect(resolveLanguage('rust')).toBeNull()
    expect(resolveLanguage('go')).toBeNull()
    expect(resolveLanguage('ruby')).toBeNull()
  })
})

// ── isTreeSitterReady ─────────────────────────────────────────────────────────

describe('isTreeSitterReady', () => {
  it('returns true after initTreeSitter() runs via setup preload', () => {
    expect(isTreeSitterReady()).toBe(true)
  })
})

// ── extractIdentifiersAST — positive extraction ───────────────────────────────

describe('extractIdentifiersAST — extracts identifiers', () => {
  it('extracts class names from TypeScript', () => {
    const code = 'class InvoiceProcessor { run() {} }'
    const ids = extractIdentifiersAST(code, 'typescript')

    expect(ids).not.toBeNull()
    expect(ids?.has('InvoiceProcessor')).toBe(true)
  })

  it('extracts method names from TypeScript', () => {
    const code = 'class Foo { calculateTax(amount: number): number { return amount } }'
    const ids = extractIdentifiersAST(code, 'ts')

    expect(ids?.has('calculateTax')).toBe(true)
  })

  it('extracts property identifiers', () => {
    const code = 'const result = obj.paymentStatus'
    const ids = extractIdentifiersAST(code, 'typescript')

    expect(ids?.has('paymentStatus')).toBe(true)
  })

  it('extracts type identifiers', () => {
    const code = 'type OrderStatus = "pending" | "complete"'
    const ids = extractIdentifiersAST(code, 'typescript')

    expect(ids?.has('OrderStatus')).toBe(true)
  })

  it('extracts identifiers from JavaScript', () => {
    const code = 'function processInvoice(invoice) { return invoice.id }'
    const ids = extractIdentifiersAST(code, 'js')

    expect(ids?.has('processInvoice')).toBe(true)
  })

  it('extracts identifiers from TSX', () => {
    const code = 'function InvoiceCard({ invoiceId }: Props) { return <div>{invoiceId}</div> }'
    const ids = extractIdentifiersAST(code, 'tsx')

    expect(ids?.has('InvoiceCard')).toBe(true)
  })

  it('extracts shorthand property identifiers', () => {
    const code = 'const { paymentMethod, orderId } = request'
    const ids = extractIdentifiersAST(code, 'typescript')

    expect(ids?.has('paymentMethod')).toBe(true)
    expect(ids?.has('orderId')).toBe(true)
  })
})

// ── extractIdentifiersAST — negative cases (the key improvement over regex) ───

describe('extractIdentifiersAST — does NOT extract non-identifiers', () => {
  it('does NOT extract keywords', () => {
    const code = 'class InvoiceProcessor extends Base { return const function }'
    const ids = extractIdentifiersAST(code, 'typescript')

    expect(ids?.has('class')).toBe(false)
    expect(ids?.has('extends')).toBe(false)
    expect(ids?.has('return')).toBe(false)
    expect(ids?.has('const')).toBe(false)
    expect(ids?.has('function')).toBe(false)
  })

  it('does NOT extract contents of double-quoted string literals', () => {
    const code = 'const gateway = "PaymentGateway"'
    const ids = extractIdentifiersAST(code, 'typescript')

    // This is the key improvement: regex WOULD extract "PaymentGateway"
    expect(ids?.has('PaymentGateway')).toBe(false)
  })

  it('does NOT extract contents of single-quoted string literals', () => {
    const code = "const status = 'UserService'"
    const ids = extractIdentifiersAST(code, 'typescript')

    expect(ids?.has('UserService')).toBe(false)
  })

  it('does NOT extract contents of template literals', () => {
    const code = 'const msg = `OrderProcessor result`'
    const ids = extractIdentifiersAST(code, 'typescript')

    expect(ids?.has('OrderProcessor')).toBe(false)
  })

  it('does NOT extract words from line comments', () => {
    const code = 'const x = 1 // InvoiceProcessor handles billing'
    const ids = extractIdentifiersAST(code, 'typescript')

    expect(ids?.has('InvoiceProcessor')).toBe(false)
    expect(ids?.has('handles')).toBe(false)
  })

  it('does NOT extract words from block comments', () => {
    const code = '/* CartValidator validates carts */ const y = 2'
    const ids = extractIdentifiersAST(code, 'typescript')

    expect(ids?.has('CartValidator')).toBe(false)
  })
})

// ── extractIdentifiersAST — language handling ─────────────────────────────────

describe('extractIdentifiersAST — language handling', () => {
  it('returns null for unsupported language tag', () => {
    const code = 'def calculate_total(items):'
    const result = extractIdentifiersAST(code, 'python')

    expect(result).toBeNull()
  })

  it('returns null for another unsupported language', () => {
    expect(extractIdentifiersAST('fn main() {}', 'rust')).toBeNull()
  })

  it('uses TypeScript grammar for empty lang tag', () => {
    const code = 'class InvoiceProcessor {}'
    const ids = extractIdentifiersAST(code, '')

    expect(ids).not.toBeNull()
    expect(ids?.has('InvoiceProcessor')).toBe(true)
  })

  it('filters identifiers through shouldObfuscate skip-list', () => {
    const code = 'const InvoiceProcessor = new Map()'
    const ids = extractIdentifiersAST(code, 'typescript')

    // 'Map' is in the builtins skip-list
    expect(ids?.has('Map')).toBe(false)
    expect(ids?.has('InvoiceProcessor')).toBe(true)
  })

  it('returns a ReadonlySet (non-null) for TypeScript code', () => {
    const ids = extractIdentifiersAST('class Foo {}', 'typescript')
    expect(ids).not.toBeNull()
    expect(ids instanceof Set).toBe(true)
  })
})
