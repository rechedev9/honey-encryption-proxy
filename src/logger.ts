/**
 * Minimal structured logger.
 * Replaces console.log in production code per project conventions.
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error'

interface LogEntry {
  readonly level: LogLevel
  readonly msg: string
  readonly time: string
  readonly [key: string]: unknown
}

function writeLog(level: LogLevel, msg: string, ctx?: Record<string, unknown>): void {
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
