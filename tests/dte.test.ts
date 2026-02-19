/**
 * Tests for the DTE (corpus-based) and FPE modules.
 */

import { describe, it, expect } from 'bun:test'
import { encode, decode, decodeEntry } from '../src/honey/dte-corpus.ts'
import { CORPUS_SIZE } from '../src/corpus/index.ts'
import {
  buildIdentifierMapping,
  buildNumericMapping,
  applyMapping,
  reverseMapping,
  shouldObfuscate,
  obfuscateStringLiterals,
} from '../src/honey/fpe.ts'
import { extractCodeBlocks, extractIdentifiers, stripComments } from '../src/ast/extractor.ts'
import { obfuscateText, deobfuscateText } from '../src/ast/mapper.ts'
import { deriveSessionKey } from '../src/honey/key-manager.ts'

// ── DTE ───────────────────────────────────────────────────────────────────────

describe('DTE corpus', () => {
  const key = Buffer.alloc(32, 0x42)

  it('encode returns a valid index in [0, CORPUS_SIZE)', () => {
    const idx = encode('some code', key)
    expect(idx).toBeGreaterThanOrEqual(0)
    expect(idx).toBeLessThan(CORPUS_SIZE)
  })

  it('same code + same key → same index (deterministic)', () => {
    const a = encode('function hello() {}', key)
    const b = encode('function hello() {}', key)
    expect(a).toBe(b)
  })

  it('different code → (usually) different index', () => {
    const a = encode('function foo() { return 1 }', key)
    const b = encode('class Bar { constructor() {} }', key)
    // Not guaranteed but very likely with SHA-256
    expect(a).not.toBe(b)
  })

  it('different key → different index', () => {
    const key2 = Buffer.alloc(32, 0x99)
    const a = encode('function hello() {}', key)
    const b = encode('function hello() {}', key2)
    expect(a).not.toBe(b)
  })

  it('decode returns a non-empty string for any index', () => {
    for (let i = 0; i < CORPUS_SIZE; i++) {
      const code = decode(i)
      expect(code.length).toBeGreaterThan(0)
    }
  })

  it('decode wraps around for out-of-range indices', () => {
    const a = decode(0)
    const b = decode(CORPUS_SIZE)
    expect(a).toBe(b)
  })

  it('decodeEntry returns metadata', () => {
    const entry = decodeEntry(0)
    expect(typeof entry.lang).toBe('string')
    expect(typeof entry.source).toBe('string')
    expect(typeof entry.code).toBe('string')
  })
})

// ── FPE ──────────────────────────────────────────────────────────────────────

describe('FPE identifier mapping', () => {
  const fpeKey = Buffer.alloc(32, 0x11)

  describe('shouldObfuscate', () => {
    it('returns false for JS keywords', () => {
      expect(shouldObfuscate('const')).toBe(false)
      expect(shouldObfuscate('function')).toBe(false)
      expect(shouldObfuscate('return')).toBe(false)
    })

    it('returns false for builtins', () => {
      expect(shouldObfuscate('Promise')).toBe(false)
      expect(shouldObfuscate('console')).toBe(false)
      expect(shouldObfuscate('Array')).toBe(false)
    })

    it('returns false for short identifiers', () => {
      expect(shouldObfuscate('i')).toBe(false)
      expect(shouldObfuscate('id')).toBe(false)
    })

    it('returns true for user-defined names', () => {
      expect(shouldObfuscate('InvoiceProcessor')).toBe(true)
      expect(shouldObfuscate('calculateTax')).toBe(true)
      expect(shouldObfuscate('user_profile')).toBe(true)
    })
  })

  describe('buildIdentifierMapping', () => {
    it('maps user-defined identifiers to fake ones', () => {
      const ids = new Set(['InvoiceProcessor', 'calculateTax', 'userProfile'])
      const mapping = buildIdentifierMapping(ids, fpeKey)

      expect(mapping.realToFake.size).toBe(3)
      expect(mapping.fakeToReal.size).toBe(3)
    })

    it('is deterministic: same ids + key → same mapping', () => {
      const ids = new Set(['InvoiceProcessor', 'calculateTax'])
      const m1 = buildIdentifierMapping(ids, fpeKey)
      const m2 = buildIdentifierMapping(ids, fpeKey)

      expect(m1.realToFake.get('InvoiceProcessor')).toBe(m2.realToFake.get('InvoiceProcessor'))
      expect(m1.realToFake.get('calculateTax')).toBe(m2.realToFake.get('calculateTax'))
    })

    it('preserves PascalCase convention', () => {
      const ids = new Set(['InvoiceProcessor'])
      const mapping = buildIdentifierMapping(ids, fpeKey)
      const fake = mapping.realToFake.get('InvoiceProcessor') ?? ''

      expect(/^[A-Z]/.test(fake)).toBe(true)
    })

    it('preserves camelCase convention', () => {
      const ids = new Set(['calculateTax'])
      const mapping = buildIdentifierMapping(ids, fpeKey)
      const fake = mapping.realToFake.get('calculateTax') ?? ''

      expect(/^[a-z]/.test(fake)).toBe(true)
    })

    it('preserves snake_case convention', () => {
      const ids = new Set(['user_profile_data'])
      const mapping = buildIdentifierMapping(ids, fpeKey)
      const fake = mapping.realToFake.get('user_profile_data') ?? ''

      expect(fake.includes('_')).toBe(true)
    })

    it('different keys produce different mappings', () => {
      const ids = new Set(['InvoiceProcessor'])
      const key2 = Buffer.alloc(32, 0x22)
      const m1 = buildIdentifierMapping(ids, fpeKey)
      const m2 = buildIdentifierMapping(ids, key2)

      expect(m1.realToFake.get('InvoiceProcessor')).not.toBe(
        m2.realToFake.get('InvoiceProcessor'),
      )
    })

    it('produces no duplicate fake identifiers', () => {
      const ids = new Set([
        'InvoiceProcessor', 'UserService', 'PaymentHandler',
        'OrderManager', 'ProductController', 'CartValidator',
        'ShippingCalculator', 'DiscountProvider', 'TaxResolver',
        'ReportGenerator',
      ])
      const mapping = buildIdentifierMapping(ids, fpeKey)
      const fakes = [...mapping.realToFake.values()]
      const unique = new Set(fakes)

      expect(unique.size).toBe(fakes.length)
    })

    it('skips keywords even when passed in', () => {
      const ids = new Set(['const', 'return', 'InvoiceProcessor'])
      const mapping = buildIdentifierMapping(ids, fpeKey)

      expect(mapping.realToFake.has('const')).toBe(false)
      expect(mapping.realToFake.has('return')).toBe(false)
      expect(mapping.realToFake.has('InvoiceProcessor')).toBe(true)
    })
  })

  describe('applyMapping / reverseMapping', () => {
    it('round-trips code through apply + reverse', () => {
      const code = 'class InvoiceProcessor { calculateTax(amount: number) {} }'
      const ids = new Set(['InvoiceProcessor', 'calculateTax'])
      const mapping = buildIdentifierMapping(ids, fpeKey)

      const obfuscated = applyMapping(code, mapping.realToFake)
      expect(obfuscated).not.toBe(code)

      const restored = reverseMapping(obfuscated, mapping.fakeToReal)
      expect(restored).toBe(code)
    })

    it('does not replace partial matches', () => {
      const code = 'const processData = () => processDataHelper()'
      const ids = new Set(['processData'])
      const mapping = buildIdentifierMapping(ids, fpeKey)

      const obfuscated = applyMapping(code, mapping.realToFake)
      // processDataHelper must NOT be replaced (it is not in the mapping)
      expect(obfuscated.includes('processDataHelper')).toBe(true)
    })
  })
})

// ── Extractor ────────────────────────────────────────────────────────────────

describe('Code block extractor', () => {
  it('extracts fenced code blocks', () => {
    const text = 'Hello\n```typescript\nconst x = 1\n```\nworld'
    const blocks = extractCodeBlocks(text)

    expect(blocks.length).toBe(1)
    expect(blocks[0]?.lang).toBe('typescript')
    expect(blocks[0]?.content).toContain('const x = 1')
  })

  it('handles multiple blocks', () => {
    const text = '```ts\nfoo()\n```\nSome text\n```py\nbar()\n```'
    const blocks = extractCodeBlocks(text)

    expect(blocks.length).toBe(2)
  })

  it('returns empty array for text without code blocks', () => {
    const blocks = extractCodeBlocks('Just plain text, no code.')
    expect(blocks.length).toBe(0)
  })

  it('extracts identifiers from code', () => {
    const code = 'class InvoiceProcessor { calculateTax() {} }'
    const ids = extractIdentifiers(code)

    expect(ids.has('InvoiceProcessor')).toBe(true)
    expect(ids.has('calculateTax')).toBe(true)
    // builtins / keywords must be excluded
    expect(ids.has('class')).toBe(false)
  })
})

// ── stripComments ────────────────────────────────────────────────────────────

describe('stripComments', () => {
  it('removes line comments', () => {
    const code = 'const x = 1 // VAT rate for EU\nconst y = 2'
    const stripped = stripComments(code)
    expect(stripped.includes('VAT rate for EU')).toBe(false)
    expect(stripped.includes('const x = 1')).toBe(true)
    expect(stripped.includes('const y = 2')).toBe(true)
  })

  it('removes block comments', () => {
    const code = 'const x = /* payment terms */ 365'
    const stripped = stripComments(code)
    expect(stripped.includes('payment terms')).toBe(false)
    expect(stripped.includes('365')).toBe(true)
  })

  it('preserves string literals containing comment-like text', () => {
    const code = 'const msg = "// not a comment"'
    const stripped = stripComments(code)
    expect(stripped).toBe(code)
  })

  it('preserves the same number of newlines from block comments', () => {
    const code = 'a\n/* line1\nline2 */\nb'
    const stripped = stripComments(code)
    expect(stripped.split('\n').length).toBe(code.split('\n').length)
  })

  it('handles consecutive line comments', () => {
    const code = '// first\n// second\nconst z = 3'
    const stripped = stripComments(code)
    expect(stripped.includes('first')).toBe(false)
    expect(stripped.includes('second')).toBe(false)
    expect(stripped.includes('const z = 3')).toBe(true)
  })
})

// ── obfuscateStringLiterals ───────────────────────────────────────────────────

describe('obfuscateStringLiterals', () => {
  const fpeKey = Buffer.alloc(32, 0x44)

  it('replaces a double-quoted string whose content exactly matches an identifier', () => {
    const ids = new Set(['invoiceId'])
    const mapping = buildIdentifierMapping(ids, fpeKey)
    const code = 'db.query("invoiceId")'
    const result = obfuscateStringLiterals(code, mapping.realToFake)
    expect(result.includes('"invoiceId"')).toBe(false)
    expect(result.startsWith('db.query("')).toBe(true)
  })

  it('replaces a single-quoted string', () => {
    const ids = new Set(['PAYMENT_DUE'])
    const mapping = buildIdentifierMapping(ids, fpeKey)
    const code = "const status = 'PAYMENT_DUE'"
    const result = obfuscateStringLiterals(code, mapping.realToFake)
    expect(result.includes("'PAYMENT_DUE'")).toBe(false)
  })

  it('leaves non-matching string literals unchanged', () => {
    const ids = new Set(['invoiceId'])
    const mapping = buildIdentifierMapping(ids, fpeKey)
    const code = 'const msg = "hello world"'
    expect(obfuscateStringLiterals(code, mapping.realToFake)).toBe(code)
  })

  it('does not alter strings whose content is a partial match', () => {
    const ids = new Set(['invoice'])
    const mapping = buildIdentifierMapping(ids, fpeKey)
    // "invoiceId" is not the same as "invoice"
    const code = 'const f = "invoiceId"'
    expect(obfuscateStringLiterals(code, mapping.realToFake)).toBe(code)
  })

  it('round-trips via reverseMapping', () => {
    const ids = new Set(['PAYMENT_DUE'])
    const mapping = buildIdentifierMapping(ids, fpeKey)
    const code = 'if (status === "PAYMENT_DUE") throw new Error()'
    const obfuscated = obfuscateStringLiterals(code, mapping.realToFake)
    const restored = reverseMapping(obfuscated, mapping.fakeToReal)
    expect(restored).toBe(code)
  })
})

// ── buildNumericMapping ───────────────────────────────────────────────────────

describe('buildNumericMapping', () => {
  const fpeKey = Buffer.alloc(32, 0x33)

  it('maps domain-specific floats like 0.21', () => {
    const mapping = buildNumericMapping('const vat = 0.21', fpeKey)
    expect(mapping.realToFake.has('0.21')).toBe(true)
    expect(mapping.realToFake.get('0.21')).not.toBe('0.21')
  })

  it('maps domain-specific integers like 365', () => {
    const mapping = buildNumericMapping('const paymentTerms = 365', fpeKey)
    expect(mapping.realToFake.has('365')).toBe(true)
    expect(mapping.realToFake.get('365')).not.toBe('365')
  })

  it('skips trivial constants (0, 1, 2, …, 256)', () => {
    const mapping = buildNumericMapping('for (let i = 0; i < 1; i++)', fpeKey)
    expect(mapping.realToFake.has('0')).toBe(false)
    expect(mapping.realToFake.has('1')).toBe(false)
  })

  it('skips HTTP status codes', () => {
    const mapping = buildNumericMapping('if (status === 404) throw new Error()', fpeKey)
    expect(mapping.realToFake.has('404')).toBe(false)
  })

  it('skips calendar years', () => {
    const mapping = buildNumericMapping('const since = 2020', fpeKey)
    expect(mapping.realToFake.has('2020')).toBe(false)
  })

  it('is deterministic: same code + key → same mapping', () => {
    const code = 'const vat = 0.21'
    const m1 = buildNumericMapping(code, fpeKey)
    const m2 = buildNumericMapping(code, fpeKey)
    expect(m1.realToFake.get('0.21')).toBe(m2.realToFake.get('0.21'))
  })

  it('different keys produce different fakes', () => {
    const code = 'const vat = 0.21'
    const key2 = Buffer.alloc(32, 0x66)  // 0x66 produces 0.11, distinct from 0x33's 0.31
    const m1 = buildNumericMapping(code, fpeKey)
    const m2 = buildNumericMapping(code, key2)
    expect(m1.realToFake.get('0.21')).not.toBe(m2.realToFake.get('0.21'))
  })

  it('preserves decimal places in float fakes', () => {
    const mapping = buildNumericMapping('const rate = 0.21', fpeKey)
    const fake = mapping.realToFake.get('0.21') ?? ''
    const parts = fake.split('.')
    expect(parts.length).toBe(2)
    expect(parts[1]?.length).toBe(2)
  })

  it('round-trips float via applyMapping + reverseMapping', () => {
    const code = 'const vat = 0.21'
    const mapping = buildNumericMapping(code, fpeKey)
    const applied = applyMapping(code, mapping.realToFake)
    const restored = reverseMapping(applied, mapping.fakeToReal)
    expect(restored).toBe(code)
  })

  it('round-trips integer via applyMapping + reverseMapping', () => {
    const code = 'const days = 365'
    const mapping = buildNumericMapping(code, fpeKey)
    const applied = applyMapping(code, mapping.realToFake)
    const restored = reverseMapping(applied, mapping.fakeToReal)
    expect(restored).toBe(code)
  })
})

// ── Mapper end-to-end ─────────────────────────────────────────────────────────

describe('obfuscateText / deobfuscateText', () => {
  it('round-trips a prompt with code blocks', () => {
    const keyResult = deriveSessionKey('mapper-test')
    expect(keyResult.ok).toBe(true)
    if (!keyResult.ok) return

    const text =
      'Please review this:\n```typescript\nclass InvoiceProcessor {\n  calculateTax(amount: number): number { return amount * 0.2 }\n}\n```'

    const { obfuscated, mapping } = obfuscateText(text, keyResult.value)

    expect(obfuscated).not.toBe(text)
    // Real class name must not appear in outgoing text
    expect(obfuscated.includes('InvoiceProcessor')).toBe(false)

    const restored = deobfuscateText(obfuscated, mapping)
    expect(restored).toBe(text)
  })

  it('leaves text without code blocks unchanged', () => {
    const keyResult = deriveSessionKey('mapper-test')
    expect(keyResult.ok).toBe(true)
    if (!keyResult.ok) return

    const text = 'What is the meaning of life?'
    const { obfuscated } = obfuscateText(text, keyResult.value)

    expect(obfuscated).toBe(text)
  })
})
