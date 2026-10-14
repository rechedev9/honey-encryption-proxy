/**
 * Chunk-boundary-safe SSE deobfuscation.
 *
 * SSE events are delimited by `\n\n`. A fake identifier will never span
 * two SSE events (Anthropic serialises each `data:` line atomically), but
 * a TCP chunk boundary can split an event mid-identifier.
 *
 * This class buffers incoming text, splits on `\n\n`, deobfuscates each
 * complete event, and holds back the trailing incomplete fragment until
 * the next chunk arrives or `flush()` is called.
 */

import { deobfuscateText } from './ast/mapper.ts'
import type { IdentifierMapping } from './types.ts'

const MAX_PENDING_CHARS = 2 * 1024 * 1024

export class StreamDeobfuscator {
  private readonly mapping: IdentifierMapping
  private pending = ''

  constructor(mapping: IdentifierMapping) {
    this.mapping = mapping
  }

  processChunk(chunk: string): string {
    if (this.mapping.fakeToReal.size === 0) return chunk

    this.pending += chunk

    const events = this.pending.split('\n\n')
    const remainder = events.pop() ?? ''
    if (remainder.length > MAX_PENDING_CHARS) {
      this.pending = ''
      throw new Error(`SSE event exceeds ${MAX_PENDING_CHARS} characters`)
    }
    this.pending = remainder

    if (events.length === 0) return ''

    return events.map((e) => deobfuscateText(e, this.mapping)).join('\n\n') + '\n\n'
  }

  flush(): string {
    if (this.pending.length === 0) return ''
    const result = deobfuscateText(this.pending, this.mapping)
    this.pending = ''
    return result
  }
}
