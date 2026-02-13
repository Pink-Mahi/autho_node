/**
 * Connection Limiter — protects against resource exhaustion from too many connections
 * 
 * Features:
 * - Per-IP connection limits (default 20 per IP)
 * - Global connection cap (default 5000)
 * - Automatic cleanup of stale tracking entries
 * - Graceful rejection with HTTP 429 or WS close
 * 
 * Like Bitcoin Core's connection management: max inbound, max per-source, eviction of low-quality peers
 */

export interface ConnectionLimiterConfig {
  maxConnectionsPerIp: number;    // Default: 20
  maxTotalConnections: number;    // Default: 5000
  cleanupIntervalMs: number;     // Default: 60000 (1 min)
  trackingTtlMs: number;         // Default: 300000 (5 min) — evict tracking after disconnect
}

const DEFAULT_CONFIG: ConnectionLimiterConfig = {
  maxConnectionsPerIp: Number(process.env.AUTHO_MAX_CONN_PER_IP) || 20,
  maxTotalConnections: Number(process.env.AUTHO_MAX_CONNECTIONS) || 5000,
  cleanupIntervalMs: 60000,
  trackingTtlMs: 300000,
};

interface IpTracker {
  activeConnections: number;
  lastSeen: number;
  totalConnections: number;      // Lifetime counter for diagnostics
  rejected: number;              // Lifetime rejected count
}

export class ConnectionLimiter {
  private ipTrackers: Map<string, IpTracker> = new Map();
  private totalActive: number = 0;
  private totalRejected: number = 0;
  private cleanupTimer?: NodeJS.Timeout;
  private config: ConnectionLimiterConfig;

  constructor(config?: Partial<ConnectionLimiterConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Periodic cleanup of stale IP entries
    this.cleanupTimer = setInterval(() => this.cleanup(), this.config.cleanupIntervalMs);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();

    console.log(`[ConnectionLimiter] Initialized: ${this.config.maxConnectionsPerIp}/IP, ${this.config.maxTotalConnections} total`);
  }

  /**
   * Check if a new connection from the given IP should be allowed
   * Returns { allowed: true } or { allowed: false, reason: string }
   */
  tryConnect(ip: string): { allowed: boolean; reason?: string } {
    // Check global cap
    if (this.totalActive >= this.config.maxTotalConnections) {
      this.totalRejected++;
      const tracker = this.getOrCreateTracker(ip);
      tracker.rejected++;
      return { allowed: false, reason: `Global connection limit reached (${this.config.maxTotalConnections})` };
    }

    // Check per-IP cap
    const tracker = this.getOrCreateTracker(ip);
    if (tracker.activeConnections >= this.config.maxConnectionsPerIp) {
      this.totalRejected++;
      tracker.rejected++;
      return { allowed: false, reason: `Per-IP limit reached (${this.config.maxConnectionsPerIp}) for ${ip}` };
    }

    // Allow
    tracker.activeConnections++;
    tracker.lastSeen = Date.now();
    tracker.totalConnections++;
    this.totalActive++;

    return { allowed: true };
  }

  /**
   * Record a disconnection
   */
  disconnect(ip: string): void {
    const tracker = this.ipTrackers.get(ip);
    if (tracker) {
      tracker.activeConnections = Math.max(0, tracker.activeConnections - 1);
      tracker.lastSeen = Date.now();
    }
    this.totalActive = Math.max(0, this.totalActive - 1);
  }

  /**
   * Express middleware for HTTP rate limiting by connection count
   */
  middleware() {
    return (req: any, res: any, next: any) => {
      const ip = req.ip || req.socket?.remoteAddress || 'unknown';
      const result = this.tryConnect(ip);

      if (!result.allowed) {
        res.status(429).json({
          error: 'Too many connections',
          retryAfterSeconds: 30,
        });
        // Auto-disconnect since we're rejecting
        return;
      }

      // Track disconnect when response finishes
      res.on('close', () => this.disconnect(ip));
      next();
    };
  }

  private getOrCreateTracker(ip: string): IpTracker {
    let tracker = this.ipTrackers.get(ip);
    if (!tracker) {
      tracker = { activeConnections: 0, lastSeen: Date.now(), totalConnections: 0, rejected: 0 };
      this.ipTrackers.set(ip, tracker);
    }
    return tracker;
  }

  private cleanup(): void {
    const now = Date.now();
    let removed = 0;
    for (const [ip, tracker] of this.ipTrackers.entries()) {
      // Remove entries with no active connections and old lastSeen
      if (tracker.activeConnections <= 0 && (now - tracker.lastSeen) > this.config.trackingTtlMs) {
        this.ipTrackers.delete(ip);
        removed++;
      }
    }
    if (removed > 0) {
      console.log(`[ConnectionLimiter] Cleaned up ${removed} stale IP entries`);
    }
  }

  getStats(): {
    totalActive: number;
    totalRejected: number;
    trackedIps: number;
    topIps: Array<{ ip: string; connections: number }>;
    config: ConnectionLimiterConfig;
  } {
    const topIps = Array.from(this.ipTrackers.entries())
      .filter(([, t]) => t.activeConnections > 0)
      .sort((a, b) => b[1].activeConnections - a[1].activeConnections)
      .slice(0, 10)
      .map(([ip, t]) => ({ ip, connections: t.activeConnections }));

    return {
      totalActive: this.totalActive,
      totalRejected: this.totalRejected,
      trackedIps: this.ipTrackers.size,
      topIps,
      config: this.config,
    };
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    this.ipTrackers.clear();
    console.log('[ConnectionLimiter] Destroyed');
  }
}
