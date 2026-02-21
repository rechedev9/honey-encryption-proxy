/**
 * Unit tests for the obfuscation pipeline (mapper-level).
 *
 * These tests exercise the full obfuscate → deobfuscate cycle at the message
 * level, without starting an actual HTTP server or calling Anthropic.
 * For HTTP-level integration tests, see proxy-integration.test.ts.
 */

import { describe, it, expect } from 'bun:test'
import { obfuscateText, deobfuscateText } from '../src/ast/mapper.ts'
import { deriveSessionKey } from '../src/honey/key-manager.ts'
import type { SessionKey } from '../src/types.ts'

const PASSPHRASE = 'proxy-test-passphrase'

function makeKey(): SessionKey {
  const result = deriveSessionKey(PASSPHRASE)
  if (!result.ok) throw new Error('Key derivation failed')
  return result.value
}

// ── Message-level transformation ──────────────────────────────────────────────

describe('Proxy message pipeline', () => {
  describe('user message obfuscation', () => {
    it('hides proprietary class names from user messages', () => {
      const key = makeKey()
      const userMsg =
        'Here is my code:\n```typescript\nclass PaymentGatewayService {\n  processRefund(orderId: string): boolean { return true }\n}\n```\nCan you improve it?'

      const obfResult = obfuscateText(userMsg, key)
      expect(obfResult.ok).toBe(true)
      if (!obfResult.ok) return
      const { obfuscated, mapping } = obfResult.value

      expect(obfuscated.includes('PaymentGatewayService')).toBe(false)
      expect(obfuscated.includes('processRefund')).toBe(false)

      // Prose outside code fence is not obfuscated
      expect(obfuscated.includes('Can you improve it?')).toBe(true)

      // Reverse mapping restores everything
      const restored = deobfuscateText(obfuscated, mapping)
      expect(restored).toBe(userMsg)
    })

    it('preserves code structure (operators, punctuation, keywords)', () => {
      const key = makeKey()
      const code = '```ts\nif (userAccount.isActive) { return UserStatus.Active }\n```'

      const obfResult = obfuscateText(code, key)
      expect(obfResult.ok).toBe(true)
      if (!obfResult.ok) return
      const { obfuscated } = obfResult.value

      // Structural syntax is preserved
      expect(obfuscated.includes('if (')).toBe(true)
      expect(obfuscated.includes('return')).toBe(true)
      expect(obfuscated.includes('{')).toBe(true)
    })

    it('handles multiple code blocks in one message', () => {
      const key = makeKey()
      const text = [
        'Compare these two implementations:',
        '```typescript',
        'class OrderValidator { validate(order: Order): boolean { return true } }',
        '```',
        'versus',
        '```typescript',
        'class ShipmentProcessor { execute(shipment: Shipment): void {}  }',
        '```',
      ].join('\n')

      const obfResult = obfuscateText(text, key)
      expect(obfResult.ok).toBe(true)
      if (!obfResult.ok) return
      const { obfuscated, mapping } = obfResult.value

      expect(obfuscated.includes('OrderValidator')).toBe(false)
      expect(obfuscated.includes('ShipmentProcessor')).toBe(false)

      const restored = deobfuscateText(obfuscated, mapping)
      expect(restored).toBe(text)
    })

    it('produces stable obfuscation across calls with the same key', () => {
      const key = makeKey()
      const text = '```ts\nclass CustomerRepository {}\n```'

      const r1 = obfuscateText(text, key)
      const r2 = obfuscateText(text, key)
      expect(r1.ok).toBe(true)
      expect(r2.ok).toBe(true)
      if (!r1.ok || !r2.ok) return

      // Same key → same fake identifiers
      expect(r1.value.obfuscated).toBe(r2.value.obfuscated)
    })
  })

  describe('response deobfuscation', () => {
    it('restores identifiers from a simulated Claude response', () => {
      const key = makeKey()
      const original = '```ts\nclass InvoiceService { generatePdf(): Buffer {} }\n```'

      const obfResult = obfuscateText(original, key)
      expect(obfResult.ok).toBe(true)
      if (!obfResult.ok) return
      const { mapping } = obfResult.value

      // Simulate Claude echoing the fake names in its response
      const fakeClassName = mapping.realToFake.get('InvoiceService') ?? 'InvoiceService'
      const fakePdfMethod = mapping.realToFake.get('generatePdf') ?? 'generatePdf'

      const claudeResponse =
        `You can improve the \`${fakeClassName}\` class by ` +
        `making \`${fakePdfMethod}\` async:\n\`\`\`ts\nclass ${fakeClassName} ` +
        `{ async ${fakePdfMethod}(): Promise<Buffer> {} }\n\`\`\``

      const restored = deobfuscateText(claudeResponse, mapping)

      expect(restored.includes('InvoiceService')).toBe(true)
      expect(restored.includes('generatePdf')).toBe(true)
      expect(restored.includes(fakeClassName)).toBe(false)
      expect(restored.includes(fakePdfMethod)).toBe(false)
    })
  })

  describe('comment stripping and numeric obfuscation', () => {
    it('business-logic comments do not appear in the obfuscated output', () => {
      const key = makeKey()
      const text = '```typescript\n// VAT rate — confidential\nconst vatRate = 0.21\n```'

      const obfResult = obfuscateText(text, key)
      expect(obfResult.ok).toBe(true)
      if (!obfResult.ok) return
      const { obfuscated } = obfResult.value

      expect(obfuscated.includes('VAT rate')).toBe(false)
      expect(obfuscated.includes('confidential')).toBe(false)
    })

    it('numeric literals 0.21 and 365 are absent from obfuscated output', () => {
      const key = makeKey()
      const text =
        '```typescript\nconst vatRate = 0.21\nconst paymentTerms = 365\n```'

      const obfResult = obfuscateText(text, key)
      expect(obfResult.ok).toBe(true)
      if (!obfResult.ok) return
      const { obfuscated } = obfResult.value

      expect(obfuscated.includes('0.21')).toBe(false)
      expect(obfuscated.includes('365')).toBe(false)
    })

    it('numeric obfuscation round-trips correctly', () => {
      const key = makeKey()
      const text =
        '```typescript\nconst vatRate = 0.21\nconst paymentTerms = 365\n```'

      const obfResult = obfuscateText(text, key)
      expect(obfResult.ok).toBe(true)
      if (!obfResult.ok) return
      const { obfuscated, mapping } = obfResult.value
      const restored = deobfuscateText(obfuscated, mapping)

      expect(restored).toBe(text)
    })
  })

  describe('multi-turn consistency', () => {
    it('same identifier in two separate obfuscateText calls maps to the same fake', () => {
      const key = makeKey()
      const userText = '```ts\nclass PaymentProcessor {}\n```'
      const assistantText = '```ts\nclass PaymentProcessor { process(): void {} }\n```'

      const userResult = obfuscateText(userText, key)
      const assistantResult = obfuscateText(assistantText, key)
      expect(userResult.ok).toBe(true)
      expect(assistantResult.ok).toBe(true)
      if (!userResult.ok || !assistantResult.ok) return

      expect(userResult.value.mapping.realToFake.get('PaymentProcessor')).toBe(
        assistantResult.value.mapping.realToFake.get('PaymentProcessor'),
      )
    })
  })

  describe('security properties', () => {
    it('different passphrases produce different obfuscations of same code', () => {
      const key1Result = deriveSessionKey('passphrase-one')
      const key2Result = deriveSessionKey('passphrase-two')
      expect(key1Result.ok && key2Result.ok).toBe(true)
      if (!key1Result.ok || !key2Result.ok) return

      const text = '```ts\nclass SecretBusinessLogic { computeRevenue(): number {} }\n```'

      const r1 = obfuscateText(text, key1Result.value)
      const r2 = obfuscateText(text, key2Result.value)
      expect(r1.ok).toBe(true)
      expect(r2.ok).toBe(true)
      if (!r1.ok || !r2.ok) return

      expect(r1.value.obfuscated).not.toBe(r2.value.obfuscated)
    })

    it('obfuscated output does not contain real identifier in code block', () => {
      const key = makeKey()
      const sensitiveNames = [
        'CustomerCreditScore', 'calculateRiskIndex', 'fraud_detection_model',
        'TAX_RATE_CONFIG', 'internalApiSecret',
      ]
      const codeLines = [
        `class CustomerCreditScore {`,
        `  calculateRiskIndex(score: number): string { return 'low' }`,
        `}`,
        `const fraud_detection_model = 'v2'`,
        `const TAX_RATE_CONFIG = 0.21`,
        `const internalApiSecret = 'should-be-hidden'`,
      ]
      const text = '```typescript\n' + codeLines.join('\n') + '\n```'

      const obfResult = obfuscateText(text, key)
      expect(obfResult.ok).toBe(true)
      if (!obfResult.ok) return
      const { obfuscated } = obfResult.value

      for (const name of sensitiveNames) {
        expect(obfuscated.includes(name)).toBe(false)
      }
    })
  })
})
