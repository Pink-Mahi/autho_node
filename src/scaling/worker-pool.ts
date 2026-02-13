/**
 * Worker Thread Pool — offloads CPU-intensive operations from the main event loop
 * 
 * Architecture:
 * - Spawns N worker threads (default: CPU cores - 1, min 1, max 4)
 * - Round-robins tasks across workers
 * - Each task gets a unique ID and a Promise that resolves when the worker responds
 * - Graceful shutdown: terminates all workers on destroy()
 * 
 * Usage:
 *   const pool = WorkerPool.getInstance();
 *   const hash = await pool.sha256('hello');
 *   const valid = await pool.verifySignature(msg, sig, pubKey);
 *   const results = await pool.verifySignaturesBatch([...]);
 */
import { Worker } from 'worker_threads';
import * as path from 'path';
import * as os from 'os';

interface PendingTask {
  resolve: (value: any) => void;
  reject: (reason: any) => void;
  timer: NodeJS.Timeout;
}

export class WorkerPool {
  private static instance: WorkerPool | null = null;

  private workers: Worker[] = [];
  private pending: Map<string, PendingTask> = new Map();
  private nextWorker = 0;
  private taskCounter = 0;
  private destroyed = false;
  private readonly taskTimeout: number;

  constructor(poolSize?: number) {
    const cpus = os.cpus().length;
    const size = poolSize || Math.max(1, Math.min(4, cpus - 1));
    this.taskTimeout = Number(process.env.AUTHO_WORKER_TIMEOUT_MS) || 10000;

    // Resolve worker script path (works for both ts-node and compiled JS)
    let workerPath: string;
    try {
      // In compiled mode, look for dist/scaling/crypto-worker.js
      workerPath = path.resolve(__dirname, 'crypto-worker.js');
      // Test if file exists (will throw if not)
      require('fs').accessSync(workerPath);
    } catch {
      // In ts-node mode, use ts file with ts-node/register
      workerPath = path.resolve(__dirname, 'crypto-worker.ts');
    }

    for (let i = 0; i < size; i++) {
      try {
        const worker = new Worker(workerPath, {
          // If using .ts file, need ts-node/register
          execArgv: workerPath.endsWith('.ts')
            ? ['--require', 'ts-node/register']
            : [],
        });

        worker.on('message', (msg: { id: string; result?: any; error?: string }) => {
          const task = this.pending.get(msg.id);
          if (!task) return;
          this.pending.delete(msg.id);
          clearTimeout(task.timer);

          if (msg.error) {
            task.reject(new Error(msg.error));
          } else {
            task.resolve(msg.result);
          }
        });

        worker.on('error', (err) => {
          console.error(`[WorkerPool] Worker ${i} error:`, err.message);
        });

        worker.on('exit', (code) => {
          if (!this.destroyed && code !== 0) {
            console.warn(`[WorkerPool] Worker ${i} exited with code ${code}, respawning...`);
            // Remove dead worker and respawn
            const idx = this.workers.indexOf(worker);
            if (idx !== -1) {
              try {
                const replacement = new Worker(workerPath, {
                  execArgv: workerPath.endsWith('.ts')
                    ? ['--require', 'ts-node/register']
                    : [],
                });
                replacement.on('message', worker.listeners('message')[0] as any);
                replacement.on('error', worker.listeners('error')[0] as any);
                this.workers[idx] = replacement;
              } catch {}
            }
          }
        });

        this.workers.push(worker);
      } catch (err: any) {
        console.warn(`[WorkerPool] Failed to spawn worker ${i}: ${err.message}`);
      }
    }

    console.log(`[WorkerPool] Initialized with ${this.workers.length} workers (${cpus} CPUs detected)`);
  }

  static getInstance(): WorkerPool {
    if (!WorkerPool.instance) {
      WorkerPool.instance = new WorkerPool();
    }
    return WorkerPool.instance;
  }

  private dispatch(op: string, args: any[]): Promise<any> {
    if (this.destroyed || this.workers.length === 0) {
      // Fallback: run on main thread if no workers available
      return Promise.reject(new Error('WorkerPool is destroyed or has no workers'));
    }

    const id = `task_${++this.taskCounter}`;
    const worker = this.workers[this.nextWorker % this.workers.length];
    this.nextWorker++;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Worker task ${op} timed out after ${this.taskTimeout}ms`));
      }, this.taskTimeout);

      this.pending.set(id, { resolve, reject, timer });
      worker.postMessage({ id, op, args });
    });
  }

  // ── Public API ──

  async sha256(data: string): Promise<string> {
    return this.dispatch('sha256', [data]);
  }

  async sha256Batch(inputs: string[]): Promise<string[]> {
    return this.dispatch('sha256_batch', [inputs]);
  }

  async verifySignature(message: string, signature: string, publicKey: string): Promise<boolean> {
    return this.dispatch('verify_signature', [message, signature, publicKey]);
  }

  async verifySignaturesBatch(
    sigs: Array<{ message: string; signature: string; publicKey: string }>
  ): Promise<boolean[]> {
    // Split across workers for true parallelism
    if (sigs.length <= 1 || this.workers.length <= 1) {
      return this.dispatch('verify_signatures_batch', [sigs]);
    }

    const chunkSize = Math.ceil(sigs.length / this.workers.length);
    const chunks: Array<Array<{ message: string; signature: string; publicKey: string }>> = [];
    for (let i = 0; i < sigs.length; i += chunkSize) {
      chunks.push(sigs.slice(i, i + chunkSize));
    }

    const results = await Promise.all(
      chunks.map(chunk => this.dispatch('verify_signatures_batch', [chunk]))
    );

    return results.flat();
  }

  async signMessage(message: string, privateKey: string): Promise<string> {
    return this.dispatch('sign_message', [message, privateKey]);
  }

  getStats(): { workers: number; pendingTasks: number; totalDispatched: number } {
    return {
      workers: this.workers.length,
      pendingTasks: this.pending.size,
      totalDispatched: this.taskCounter,
    };
  }

  destroy(): void {
    this.destroyed = true;
    for (const task of this.pending.values()) {
      clearTimeout(task.timer);
      task.reject(new Error('WorkerPool destroyed'));
    }
    this.pending.clear();
    for (const worker of this.workers) {
      try { worker.terminate(); } catch {}
    }
    this.workers = [];
    WorkerPool.instance = null;
    console.log('[WorkerPool] Destroyed');
  }
}
