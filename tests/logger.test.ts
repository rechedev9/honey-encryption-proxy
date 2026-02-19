/**
 * Tests for log-level filtering.
 */

import { describe, it, expect, mock, beforeEach, afterEach } from 'bun:test'
import { logger, setLogLevel, getLogLevel } from '../src/logger.ts'
import type { LogLevel } from '../src/logger.ts'

describe('Logger level filtering', () => {
  const stdoutWrite = mock(() => true)
  const stderrWrite = mock(() => true)
  let origStdout: typeof process.stdout.write
  let origStderr: typeof process.stderr.write

  beforeEach(() => {
    origStdout = process.stdout.write
    origStderr = process.stderr.write
    process.stdout.write = stdoutWrite as unknown as typeof process.stdout.write
    process.stderr.write = stderrWrite as unknown as typeof process.stderr.write
    stdoutWrite.mockClear()
    stderrWrite.mockClear()
  })

  afterEach(() => {
    process.stdout.write = origStdout
    process.stderr.write = origStderr
    setLogLevel('info')
  })

  it('suppresses debug when level=info', () => {
    setLogLevel('info')
    logger.debug('should be hidden')
    expect(stdoutWrite).not.toHaveBeenCalled()
  })

  it('emits info when level=info', () => {
    setLogLevel('info')
    logger.info('visible')
    expect(stdoutWrite).toHaveBeenCalledTimes(1)
  })

  it('suppresses info and debug when level=error', () => {
    setLogLevel('error')
    logger.debug('hidden')
    logger.info('also hidden')
    logger.warn('also hidden')
    expect(stdoutWrite).not.toHaveBeenCalled()
    expect(stderrWrite).not.toHaveBeenCalled()
  })

  it('emits error when level=error', () => {
    setLogLevel('error')
    logger.error('visible')
    expect(stderrWrite).toHaveBeenCalledTimes(1)
  })

  it('emits all levels when level=debug', () => {
    setLogLevel('debug')
    logger.debug('d')
    logger.info('i')
    logger.warn('w')
    logger.error('e')
    expect(stdoutWrite).toHaveBeenCalledTimes(2)
    expect(stderrWrite).toHaveBeenCalledTimes(2)
  })

  it('emits warn and error when level=warn', () => {
    setLogLevel('warn')
    logger.debug('hidden')
    logger.info('hidden')
    logger.warn('visible')
    logger.error('visible')
    expect(stdoutWrite).not.toHaveBeenCalled()
    expect(stderrWrite).toHaveBeenCalledTimes(2)
  })

  it('getLogLevel returns the current level', () => {
    setLogLevel('error')
    expect(getLogLevel()).toBe('error')
    setLogLevel('debug')
    expect(getLogLevel()).toBe('debug')
  })
})
