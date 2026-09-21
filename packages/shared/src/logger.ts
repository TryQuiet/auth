import { type Debugger } from 'debug'
import { debug } from 'debug.js'

export type LoggerFunction = (
  level: 'info' | 'warn' | 'error' | 'debug',
  message: any,
  ...params: any[]
) => void
// Keep this exported API augmentable for consumers that use declaration merging.
// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export interface SharedLogger {
  info: (message: any, ...params: any[]) => void
  warn: (message: any, ...params: any[]) => void
  error: (message: any, ...params: any[]) => void
  debug: (message: any, ...params: any[]) => void
  extend: (moduleName: string) => SharedLogger
}

export enum LogLevel {
  info = 'info',
  warn = 'warn',
  error = 'error',
  debug = 'debug',
}

// Keep this exported API augmentable for consumers that use declaration merging.
// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export interface LoggerConfig {
  moduleName: string
  baseLog?: Debugger
  sharedLogger?: SharedLogger
  extendSharedLogger?: boolean
}

export class Logger {
  private readonly baseLog: Debugger
  public readonly sharedLogger: SharedLogger | undefined

  constructor(config: LoggerConfig) {
    this.baseLog = (config.baseLog ?? debug).extend(config.moduleName)
    this.sharedLogger =
      config.sharedLogger && config.extendSharedLogger
        ? config.sharedLogger.extend(config.moduleName)
        : config.sharedLogger
  }

  public extend(moduleName: string): Logger {
    return new Logger({
      moduleName,
      baseLog: this.baseLog,
      sharedLogger: this.sharedLogger,
      extendSharedLogger: true,
    })
  }

  public info(message: string, ...params: any[]): void {
    this._log(LogLevel.info, message, ...params)
  }

  public warn(message: string, ...params: any[]): void {
    this._log(LogLevel.warn, message, ...params)
  }

  public error(message: string, ...params: any[]): void {
    this._log(LogLevel.error, message, ...params)
  }

  public debug(message: string, ...params: any[]): void {
    this._log(LogLevel.debug, message, ...params)
  }

  private _log(level: LogLevel, message: any, ...params: any[]): void {
    if (this.sharedLogger === undefined || this.sharedLogger === null) {
      this.baseLog(message, params)
      return
    }

    switch (level) {
      case LogLevel.info: {
        this.sharedLogger.info(message, ...params)
        break
      }
      case LogLevel.warn: {
        this.sharedLogger.warn(message, ...params)
        break
      }
      case LogLevel.error: {
        this.sharedLogger.error(message, ...params)
        break
      }
      case LogLevel.debug: {
        this.sharedLogger.debug(message, ...params)
        break
      }
      default: {
        throw new Error(`Unknown log level ${String(level)}`)
      }
    }
  }
}
