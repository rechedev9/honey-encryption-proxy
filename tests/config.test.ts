/**
 * Tests for config loader edge cases.
 *
 * loadConfig() reads env vars and returns Result<Config>.
 * These tests verify validation boundaries that integration tests don't cover.
 */

import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { loadConfig } from '../src/config.ts'

describe('loadConfig', () => {
  const savedEnv: Record<string, string | undefined> = {}

  const ENV_KEYS = [
    'ANTHROPIC_API_KEY',
    'HONEY_PASSPHRASE',
    'PROXY_PORT',
    'ANTHROPIC_BASE_URL_UPSTREAM',
    'LOG_LEVEL',
    'HONEY_KYBER_CAPSULE',
  ] as const

  beforeEach(() => {
    for (const key of ENV_KEYS) {
      savedEnv[key] = process.env[key]
    }
    // Minimal valid env
    process.env.ANTHROPIC_API_KEY = 'sk-ant-test-key'
    process.env.HONEY_PASSPHRASE = 'test-passphrase'
    delete process.env.PROXY_PORT
    delete process.env.ANTHROPIC_BASE_URL_UPSTREAM
    delete process.env.LOG_LEVEL
    delete process.env.HONEY_KYBER_CAPSULE
  })

  afterEach(() => {
    for (const key of ENV_KEYS) {
      if (savedEnv[key] === undefined) {
        delete process.env[key]
      } else {
        process.env[key] = savedEnv[key]
      }
    }
  })

  // ── Required env vars ──────────────────────────────────────────────

  describe('required env vars', () => {
    it('returns error when ANTHROPIC_API_KEY is missing', () => {
      delete process.env.ANTHROPIC_API_KEY
      const result = loadConfig()
      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.message).toContain('ANTHROPIC_API_KEY')
      }
    })

    it('returns error when HONEY_PASSPHRASE is missing', () => {
      delete process.env.HONEY_PASSPHRASE
      const result = loadConfig()
      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.message).toContain('HONEY_PASSPHRASE')
      }
    })

    it('succeeds with only required env vars', () => {
      const result = loadConfig()
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value.anthropicApiKey).toBe('sk-ant-test-key')
        expect(result.value.honeyPassphrase).toBe('test-passphrase')
      }
    })
  })

  // ── Port validation ────────────────────────────────────────────────

  describe('PROXY_PORT validation', () => {
    it('defaults to 8080 when not set', () => {
      const result = loadConfig()
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value.proxyPort).toBe(8080)
      }
    })

    it('accepts a valid port', () => {
      process.env.PROXY_PORT = '3000'
      const result = loadConfig()
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value.proxyPort).toBe(3000)
      }
    })

    it('accepts port 1 (lower boundary)', () => {
      process.env.PROXY_PORT = '1'
      const result = loadConfig()
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value.proxyPort).toBe(1)
      }
    })

    it('accepts port 65535 (upper boundary)', () => {
      process.env.PROXY_PORT = '65535'
      const result = loadConfig()
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value.proxyPort).toBe(65535)
      }
    })

    it('rejects port 0', () => {
      process.env.PROXY_PORT = '0'
      const result = loadConfig()
      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.message).toContain('PROXY_PORT')
      }
    })

    it('rejects port 65536', () => {
      process.env.PROXY_PORT = '65536'
      const result = loadConfig()
      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.message).toContain('PROXY_PORT')
      }
    })

    it('rejects non-numeric port', () => {
      process.env.PROXY_PORT = 'abc'
      const result = loadConfig()
      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.message).toContain('PROXY_PORT')
      }
    })

    it('rejects negative port', () => {
      process.env.PROXY_PORT = '-1'
      const result = loadConfig()
      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.error.message).toContain('PROXY_PORT')
      }
    })
  })

  // ── Log level ──────────────────────────────────────────────────────

  describe('LOG_LEVEL handling', () => {
    it('defaults to info when not set', () => {
      const result = loadConfig()
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value.logLevel).toBe('info')
      }
    })

    it('accepts valid log levels', () => {
      for (const level of ['debug', 'info', 'warn', 'error'] as const) {
        process.env.LOG_LEVEL = level
        const result = loadConfig()
        expect(result.ok).toBe(true)
        if (result.ok) {
          expect(result.value.logLevel).toBe(level)
        }
      }
    })

    it('falls back to info for invalid log level', () => {
      process.env.LOG_LEVEL = 'verbose'
      const result = loadConfig()
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value.logLevel).toBe('info')
      }
    })
  })

  // ── Upstream URL ───────────────────────────────────────────────────

  describe('ANTHROPIC_BASE_URL_UPSTREAM', () => {
    it('defaults to https://api.anthropic.com', () => {
      const result = loadConfig()
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value.upstreamBaseUrl).toBe('https://api.anthropic.com')
      }
    })

    it('uses custom upstream when set', () => {
      process.env.ANTHROPIC_BASE_URL_UPSTREAM = 'https://custom.example.com'
      const result = loadConfig()
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value.upstreamBaseUrl).toBe('https://custom.example.com')
      }
    })
  })

  // ── ML-KEM-768 capsule ────────────────────────────────────────────

  describe('HONEY_KYBER_CAPSULE', () => {
    it('omits honeyKyberCapsule when env var is absent', () => {
      const result = loadConfig()
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value.honeyKyberCapsule).toBeUndefined()
      }
    })

    it('includes honeyKyberCapsule when env var is present', () => {
      process.env.HONEY_KYBER_CAPSULE = 'dGVzdC1jYXBzdWxl'
      const result = loadConfig()
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect(result.value.honeyKyberCapsule).toBe('dGVzdC1jYXBzdWxl')
      }
    })
  })
})
