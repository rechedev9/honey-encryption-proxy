/**
 * Minimal structured logger.
 * Replaces console.log in production code per project conventions.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

interface LogEntry {
  readonly level: LogLevel
  readonly msg: string
  readonly time: string
  readonly [key: string]: unknown
}

const LEVEL_PRIORITY: Readonly<Record<LogLevel, number>> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
}

let currentLevel: LogLevel = 'info'

export function setLogLevel(level: LogLevel): void {
  currentLevel = level
}

export function getLogLevel(): LogLevel {
  return currentLevel
}

function writeLog(level: LogLevel, msg: string, ctx?: Record<string, unknown>): void {
  if (LEVEL_PRIORITY[level] < LEVEL_PRIORITY[currentLevel]) return

  const entry: LogEntry = {
    level,
    msg,
    time: new Date().toISOString(),
    ...ctx,
  }
  const out = JSON.stringify(entry)
  if (level === 'error' || level === 'warn') {
    process.stderr.write(out + '\n')
  } else {
    process.stdout.write(out + '\n')
  }
}

export const logger = {
  debug(msg: string, ctx?: Record<string, unknown>): void {
    writeLog('debug', msg, ctx)
  },
  info(msg: string, ctx?: Record<string, unknown>): void {
    writeLog('info', msg, ctx)
  },
  warn(msg: string, ctx?: Record<string, unknown>): void {
    writeLog('warn', msg, ctx)
  },
  error(msg: string, ctx?: Record<string, unknown>): void {
    writeLog('error', msg, ctx)
  },
}
