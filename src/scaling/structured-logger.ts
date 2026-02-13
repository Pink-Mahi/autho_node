/**
 * Structured Logger — JSON-formatted logging with levels, timestamps, and context
 * 
 * Replaces scattered console.log calls with structured JSON output for:
 * - Machine-parseable logs (Coolify, Grafana Loki, ELK, etc.)
 * - Log levels (debug, info, warn, error)
 * - Automatic context injection (component, operatorId, etc.)
 * - Request correlation IDs
 * 
 * Like Bitcoin Core's logging categories: -debug=net,mempool,rpc
 */

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

const LEVEL_NAMES: Record<LogLevel, string> = {
  [LogLevel.DEBUG]: 'debug',
  [LogLevel.INFO]: 'info',
  [LogLevel.WARN]: 'warn',
  [LogLevel.ERROR]: 'error',
};

export interface LogEntry {
  timestamp: string;
  level: string;
  component: string;
  message: string;
  [key: string]: any;
}

export class StructuredLogger {
  private minLevel: LogLevel;
  private defaultContext: Record<string, any>;
  private useJson: boolean;

  constructor(opts?: {
    minLevel?: LogLevel;
    context?: Record<string, any>;
    json?: boolean;
  }) {
    const envLevel = (process.env.AUTHO_LOG_LEVEL || 'info').toLowerCase();
    const levelMap: Record<string, LogLevel> = {
      debug: LogLevel.DEBUG,
      info: LogLevel.INFO,
      warn: LogLevel.WARN,
      error: LogLevel.ERROR,
    };
    this.minLevel = opts?.minLevel ?? levelMap[envLevel] ?? LogLevel.INFO;
    this.defaultContext = opts?.context ?? {};
    // Default to JSON in production, pretty in development
    this.useJson = opts?.json ?? (process.env.NODE_ENV === 'production');
  }

  child(context: Record<string, any>): StructuredLogger {
    const child = new StructuredLogger({
      minLevel: this.minLevel,
      context: { ...this.defaultContext, ...context },
      json: this.useJson,
    });
    return child;
  }

  debug(component: string, message: string, data?: Record<string, any>): void {
    this.log(LogLevel.DEBUG, component, message, data);
  }

  info(component: string, message: string, data?: Record<string, any>): void {
    this.log(LogLevel.INFO, component, message, data);
  }

  warn(component: string, message: string, data?: Record<string, any>): void {
    this.log(LogLevel.WARN, component, message, data);
  }

  error(component: string, message: string, data?: Record<string, any>): void {
    this.log(LogLevel.ERROR, component, message, data);
  }

  private log(level: LogLevel, component: string, message: string, data?: Record<string, any>): void {
    if (level < this.minLevel) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: LEVEL_NAMES[level],
      component,
      message,
      ...this.defaultContext,
      ...data,
    };

    if (this.useJson) {
      const output = JSON.stringify(entry);
      if (level >= LogLevel.ERROR) {
        process.stderr.write(output + '\n');
      } else {
        process.stdout.write(output + '\n');
      }
    } else {
      // Human-readable format for development
      const ts = entry.timestamp.substring(11, 23); // HH:MM:SS.mmm
      const lvl = LEVEL_NAMES[level].toUpperCase().padEnd(5);
      const extra = data ? ' ' + JSON.stringify(data) : '';
      const line = `${ts} ${lvl} [${component}] ${message}${extra}`;
      if (level >= LogLevel.ERROR) {
        console.error(line);
      } else if (level >= LogLevel.WARN) {
        console.warn(line);
      } else {
        console.log(line);
      }
    }
  }
}

// Singleton logger instance
export const logger = new StructuredLogger();
