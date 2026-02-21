/**
 * Tests for chunk-boundary-safe streaming deobfuscation.
 */

import { describe, it, expect } from 'bun:test'
import { StreamDeobfuscator } from '../src/stream-deobfuscator.ts'
import type { IdentifierMapping } from '../src/types.ts'

function makeMapping(pairs: Array<[string, string]>): IdentifierMapping {
  const realToFake = new Map<string, string>()
  const fakeToReal = new Map<string, string>()
  for (const [real, fake] of pairs) {
    realToFake.set(real, fake)
    fakeToReal.set(fake, real)
  }
  return { realToFake, fakeToReal }
}

describe('StreamDeobfuscator', () => {
  it('deobfuscates a single complete event', () => {
    const mapping = makeMapping([['RealName', 'FakeName']])
    const deob = new StreamDeobfuscator(mapping)

    const result = deob.processChunk('data: {"text":"FakeName"}\n\n')
    expect(result).toBe('data: {"text":"RealName"}\n\n')
  })

  it('correctly deobfuscates an identifier split across two chunks', () => {
    const mapping = makeMapping([['RealName', 'FakeName']])
    const deob = new StreamDeobfuscator(mapping)

    // First chunk ends mid-identifier: "Fake"
    const r1 = deob.processChunk('data: {"text":"Fake')
    expect(r1).toBe('') // buffered, no complete event yet

    // Second chunk completes the event
    const r2 = deob.processChunk('Name"}\n\n')
    expect(r2).toBe('data: {"text":"RealName"}\n\n')
  })

  it('passes through when mapping is empty', () => {
    const mapping = makeMapping([])
    const deob = new StreamDeobfuscator(mapping)

    const result = deob.processChunk('data: {"text":"anything"}\n\n')
    expect(result).toBe('data: {"text":"anything"}\n\n')
  })

  it('flush returns remaining buffered content', () => {
    const mapping = makeMapping([['RealName', 'FakeName']])
    const deob = new StreamDeobfuscator(mapping)

    const r1 = deob.processChunk('data: {"text":"FakeName"}')
    expect(r1).toBe('')

    const flushed = deob.flush()
    expect(flushed).toBe('data: {"text":"RealName"}')
  })

  it('handles data: [DONE] terminator', () => {
    const mapping = makeMapping([['RealName', 'FakeName']])
    const deob = new StreamDeobfuscator(mapping)

    const result = deob.processChunk('data: {"text":"FakeName"}\n\ndata: [DONE]\n\n')
    expect(result).toContain('RealName')
    expect(result).toContain('data: [DONE]')
  })

  it('handles multiple events in one chunk', () => {
    const mapping = makeMapping([['RealName', 'FakeName']])
    const deob = new StreamDeobfuscator(mapping)

    const chunk =
      'data: {"text":"FakeName"}\n\n' +
      'data: {"text":"more FakeName"}\n\n'

    const result = deob.processChunk(chunk)
    expect(result).toBe(
      'data: {"text":"RealName"}\n\n' +
      'data: {"text":"more RealName"}\n\n',
    )
  })

  it('flush returns empty string when nothing is buffered', () => {
    const mapping = makeMapping([['RealName', 'FakeName']])
    const deob = new StreamDeobfuscator(mapping)

    expect(deob.flush()).toBe('')
  })
})
