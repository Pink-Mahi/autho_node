/**
 * Lightweight Prometheus-compatible metrics — no external dependencies
 * 
 * Exposes /metrics endpoint in Prometheus text format for:
 * - HTTP request latency histograms
 * - Event throughput counters
 * - WebSocket connection gauges
 * - Memory/CPU usage gauges
 * 
 * Like Bitcoin Core's -getinfo RPC but machine-parseable for Grafana/Prometheus
 */

export class MetricsCollector {
  private counters: Map<string, { value: number; help: string }> = new Map();
  private gauges: Map<string, { value: number; help: string }> = new Map();
  private histograms: Map<string, {
    help: string;
    buckets: number[];
    counts: number[];  // One per bucket + 1 for +Inf
    sum: number;
    count: number;
  }> = new Map();

  constructor() {
    // Pre-register common metrics
    this.registerCounter('autho_http_requests_total', 'Total HTTP requests');
    this.registerCounter('autho_events_created_total', 'Total events created');
    this.registerCounter('autho_events_gossiped_total', 'Total events gossiped to peers');
    this.registerCounter('autho_ws_messages_total', 'Total WebSocket messages processed');
    this.registerCounter('autho_auth_attempts_total', 'Total authentication attempts');
    this.registerCounter('autho_auth_failures_total', 'Total authentication failures');

    this.registerGauge('autho_ws_connections', 'Current WebSocket connections');
    this.registerGauge('autho_memory_heap_bytes', 'Heap memory used in bytes');
    this.registerGauge('autho_event_sequence', 'Current event sequence number');
    this.registerGauge('autho_uptime_seconds', 'Process uptime in seconds');

    this.registerHistogram('autho_http_request_duration_seconds', 'HTTP request duration', [
      0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
    ]);
  }

  registerCounter(name: string, help: string): void {
    if (!this.counters.has(name)) {
      this.counters.set(name, { value: 0, help });
    }
  }

  registerGauge(name: string, help: string): void {
    if (!this.gauges.has(name)) {
      this.gauges.set(name, { value: 0, help });
    }
  }

  registerHistogram(name: string, help: string, buckets: number[]): void {
    if (!this.histograms.has(name)) {
      this.histograms.set(name, {
        help,
        buckets: [...buckets].sort((a, b) => a - b),
        counts: new Array(buckets.length + 1).fill(0), // +1 for +Inf
        sum: 0,
        count: 0,
      });
    }
  }

  incCounter(name: string, amount: number = 1): void {
    const counter = this.counters.get(name);
    if (counter) counter.value += amount;
  }

  setGauge(name: string, value: number): void {
    const gauge = this.gauges.get(name);
    if (gauge) gauge.value = value;
  }

  observeHistogram(name: string, value: number): void {
    const hist = this.histograms.get(name);
    if (!hist) return;
    hist.sum += value;
    hist.count++;
    for (let i = 0; i < hist.buckets.length; i++) {
      if (value <= hist.buckets[i]) {
        hist.counts[i]++;
      }
    }
    hist.counts[hist.buckets.length]++; // +Inf always incremented
  }

  /**
   * Express middleware to track request latency and count
   */
  httpMiddleware() {
    return (req: any, res: any, next: any) => {
      const start = process.hrtime.bigint();
      this.incCounter('autho_http_requests_total');

      res.on('finish', () => {
        const durationNs = Number(process.hrtime.bigint() - start);
        const durationSec = durationNs / 1e9;
        this.observeHistogram('autho_http_request_duration_seconds', durationSec);
      });

      next();
    };
  }

  /**
   * Render all metrics in Prometheus exposition format
   */
  render(): string {
    const lines: string[] = [];

    // Counters
    for (const [name, c] of this.counters) {
      lines.push(`# HELP ${name} ${c.help}`);
      lines.push(`# TYPE ${name} counter`);
      lines.push(`${name} ${c.value}`);
    }

    // Gauges — refresh dynamic values
    this.setGauge('autho_memory_heap_bytes', process.memoryUsage().heapUsed);
    this.setGauge('autho_uptime_seconds', Math.round(process.uptime()));

    for (const [name, g] of this.gauges) {
      lines.push(`# HELP ${name} ${g.help}`);
      lines.push(`# TYPE ${name} gauge`);
      lines.push(`${name} ${g.value}`);
    }

    // Histograms
    for (const [name, h] of this.histograms) {
      lines.push(`# HELP ${name} ${h.help}`);
      lines.push(`# TYPE ${name} histogram`);
      let cumulative = 0;
      for (let i = 0; i < h.buckets.length; i++) {
        cumulative += h.counts[i];
        lines.push(`${name}_bucket{le="${h.buckets[i]}"} ${cumulative}`);
      }
      lines.push(`${name}_bucket{le="+Inf"} ${h.count}`);
      lines.push(`${name}_sum ${h.sum}`);
      lines.push(`${name}_count ${h.count}`);
    }

    return lines.join('\n') + '\n';
  }
}

// Singleton
export const metrics = new MetricsCollector();
