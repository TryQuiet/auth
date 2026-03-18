import { Debugger } from "debug"
import { debug } from "debug.js"

export type LoggerFunction = (level: 'info' | 'warn' | 'error' | 'debug', message: any, ...params: any[]) => void
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

export interface LoggerConfig {
  moduleName: string
  baseLog?: Debugger
  sharedLogger?: SharedLogger
  extendSharedLogger?: boolean
}

export class Logger {
  private baseLog: Debugger
  public readonly sharedLogger: SharedLogger | undefined

  constructor(config: LoggerConfig) {
    this.baseLog = (config.baseLog ?? debug).extend(config.moduleName)
    if (config.sharedLogger && config.extendSharedLogger) {
      this.sharedLogger = config.sharedLogger.extend(config.moduleName)
    } else {
      this.sharedLogger = config.sharedLogger
    }
  }

  public extend(moduleName: string): Logger {
    return new Logger({ moduleName, baseLog: this.baseLog, sharedLogger: this.sharedLogger, extendSharedLogger: true })
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
    if (this.sharedLogger == null) {
      this.baseLog(message, params)
      return
    }

    switch (level) {
      case LogLevel.info:
        this.sharedLogger.info(message, ...params)
        break
      case LogLevel.warn:
        this.sharedLogger.warn(message, ...params)
        break
      case LogLevel.error:
        this.sharedLogger.error(message, ...params)
        break
      case LogLevel.debug:
        this.sharedLogger.debug(message, ...params)
        break
      default:
        throw new Error(`Unknown log level ${level}`)
    }
  }
}