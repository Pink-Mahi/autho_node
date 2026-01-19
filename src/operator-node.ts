import express, { Express, Request, Response } from 'express';
import * as http from 'http';
import WebSocket from 'ws';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';

interface OperatorConfig {
  operatorId: string;
  publicKey: string;
  privateKey: string;
  btcAddress: string;
  mainSeedUrl: string;
  port: number;
  wsPort: number;
  dataDir: string;
  network: 'mainnet' | 'testnet';
  operatorName?: string;
  operatorDescription?: string;
}

interface SyncedState {
  events: any[];
  accounts: Map<string, any>;
  items: Map<string, any>;
  settlements: Map<string, any>;
  consignments: Map<string, any>;
  operators: Map<string, any>;
  lastSyncedSequence: number;
  lastSyncedAt: number;
}

export class OperatorNode extends EventEmitter {
  private config: OperatorConfig;
  private app: Express;
  private httpServer?: http.Server;
  private wss?: WebSocket.Server;
  private mainSeedWs?: WebSocket;
  private state: SyncedState;
  private isConnectedToMain: boolean = false;
  private reconnectTimer?: NodeJS.Timeout;
  private syncInProgress: boolean = false;

  constructor(config: OperatorConfig) {
    super();
    this.config = config;
    this.app = express();
    this.state = {
      events: [],
      accounts: new Map(),
      items: new Map(),
      settlements: new Map(),
      consignments: new Map(),
      operators: new Map(),
      lastSyncedSequence: 0,
      lastSyncedAt: 0
    };

    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // CORS for gateway nodes
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
      if (req.method === 'OPTIONS') {
        res.sendStatus(200);
        return;
      }
      next();
    });

    // Request logging
    this.app.use((req, res, next) => {
      const start = Date.now();
      res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
      });
      next();
    });
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/api/health', (req: Request, res: Response) => {
      res.json({
        status: 'ok',
        operatorId: this.config.operatorId,
        connectedToNetwork: this.isConnectedToMain,
        syncedEvents: this.state.events.length,
        lastSyncedAt: this.state.lastSyncedAt,
        uptime: process.uptime()
      });
    });

    // Operator info (public)
    this.app.get('/api/operator/info', (req: Request, res: Response) => {
      res.json({
        operatorId: this.config.operatorId,
        publicKey: this.config.publicKey,
        btcAddress: this.config.btcAddress,
        network: this.config.network,
        name: this.config.operatorName,
        description: this.config.operatorDescription,
        connectedToNetwork: this.isConnectedToMain
      });
    });

    // Network status
    this.app.get('/api/network/status', (req: Request, res: Response) => {
      const operators = Array.from(this.state.operators.values());
      res.json({
        connectedToMain: this.isConnectedToMain,
        totalOperators: operators.length,
        activeOperators: operators.filter((o: any) => o.status === 'active').length,
        syncedEvents: this.state.events.length,
        lastSyncedAt: this.state.lastSyncedAt
      });
    });

    // Customer authentication (proxied from synced state)
    this.app.post('/api/auth/login', async (req: Request, res: Response) => {
      try {
        const { email, password, totpCode } = req.body;
        if (!email || !password) {
          res.status(400).json({ success: false, error: 'Missing email or password' });
          return;
        }

        // Find account in synced state
        const emailHash = this.computeEmailHash(email);
        let account: any = null;
        for (const acc of this.state.accounts.values()) {
          if (String(acc.emailHash || '') === emailHash) {
            account = acc;
            break;
          }
        }

        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        // Verify password
        if (!account.passwordHash) {
          res.status(400).json({ success: false, error: 'Password not set for this account' });
          return;
        }

        const passwordValid = await this.verifyPassword(password, account.passwordHash, account.passwordKdf);
        if (!passwordValid) {
          res.status(401).json({ success: false, error: 'Invalid password' });
          return;
        }

        // Check 2FA if enabled
        if (account.totp?.enabled) {
          if (!totpCode) {
            res.status(400).json({ success: false, error: '2FA code required', requires2FA: true });
            return;
          }
          // 2FA verification would go here (requires decryption key from main node)
          res.status(501).json({ success: false, error: '2FA verification requires main node' });
          return;
        }

        // Create session
        const sessionId = `session_${Date.now()}_${this.randomHex(16)}`;
        const createdAt = Date.now();
        const expiresAt = createdAt + 24 * 60 * 60 * 1000;

        res.json({
          success: true,
          sessionId,
          accountId: account.accountId,
          expiresAt,
          emailHash: account.emailHash,
          walletAddress: account.walletAddress
        });
      } catch (error: any) {
        console.error('[Auth] Login error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
      }
    });

    // Registry queries (from synced state)
    this.app.get('/api/registry/item/:itemId', (req: Request, res: Response) => {
      const item = this.state.items.get(req.params.itemId);
      if (!item) {
        res.status(404).json({ error: 'Item not found' });
        return;
      }
      res.json(item);
    });

    this.app.get('/api/registry/owner/:address', (req: Request, res: Response) => {
      const items = Array.from(this.state.items.values())
        .filter((item: any) => item.currentOwner === req.params.address);
      res.json({ items });
    });

    // Block admin endpoints - operators cannot access these
    this.app.all('/api/admin/*', (req: Request, res: Response) => {
      res.status(403).json({ 
        success: false, 
        error: 'Admin endpoints are not available on operator nodes. Please use the main node dashboard.' 
      });
    });

    this.app.all('/dashboard*', (req: Request, res: Response) => {
      res.status(403).json({ 
        success: false, 
        error: 'Admin dashboard is not available on operator nodes. Please use the main node dashboard.' 
      });
    });

    // Catch-all for undefined routes
    this.app.use((req: Request, res: Response) => {
      res.status(404).json({ error: 'Endpoint not found' });
    });
  }

  async start(): Promise<void> {
    // Ensure data directory exists
    if (!fs.existsSync(this.config.dataDir)) {
      fs.mkdirSync(this.config.dataDir, { recursive: true });
    }

    // Load persisted state if exists
    await this.loadPersistedState();

    // Start HTTP server
    this.httpServer = this.app.listen(this.config.port, () => {
      console.log(`[Operator] HTTP API: http://localhost:${this.config.port}`);
      console.log(`[Operator] Health: http://localhost:${this.config.port}/api/health`);
    });

    // Connect to main seed node
    await this.connectToMainSeed();

    console.log('\n[Operator] Node is running!');
    console.log('[Operator] Press Ctrl+C to stop\n');
  }

  async stop(): Promise<void> {
    console.log('[Operator] Stopping...');

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    if (this.mainSeedWs) {
      this.mainSeedWs.close();
    }

    if (this.wss) {
      this.wss.close();
    }

    if (this.httpServer) {
      await new Promise<void>((resolve) => {
        this.httpServer!.close(() => resolve());
      });
    }

    await this.persistState();
    console.log('[Operator] Stopped');
  }

  private async connectToMainSeed(): Promise<void> {
    console.log(`[Operator] Connecting to main seed: ${this.config.mainSeedUrl}`);

    try {
      this.mainSeedWs = new WebSocket(this.config.mainSeedUrl);

      this.mainSeedWs.on('open', () => {
        console.log('[Operator] Connected to Autho Network');
        this.isConnectedToMain = true;

        // Send sync request
        this.mainSeedWs!.send(JSON.stringify({
          type: 'sync_request',
          operatorId: this.config.operatorId,
          lastSequence: this.state.lastSyncedSequence,
          timestamp: Date.now()
        }));
      });

      this.mainSeedWs.on('message', async (data: WebSocket.Data) => {
        try {
          const message = JSON.parse(data.toString());
          await this.handleMainSeedMessage(message);
        } catch (error: any) {
          console.error('[Operator] Error handling message:', error.message);
        }
      });

      this.mainSeedWs.on('close', () => {
        console.log('[Operator] Disconnected from main seed');
        this.isConnectedToMain = false;
        this.scheduleReconnect();
      });

      this.mainSeedWs.on('error', (error: Error) => {
        console.error('[Operator] WebSocket error:', error.message);
      });

    } catch (error: any) {
      console.error('[Operator] Failed to connect to main seed:', error.message);
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;

    console.log('[Operator] Will reconnect in 10 seconds...');
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connectToMainSeed();
    }, 10000);
  }

  private async handleMainSeedMessage(message: any): Promise<void> {
    switch (message.type) {
      case 'sync_data':
        await this.handleSyncData(message);
        break;
      case 'new_event':
        await this.handleNewEvent(message.event);
        break;
      case 'ping':
        this.mainSeedWs?.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        break;
      default:
        console.log(`[Operator] Unknown message type: ${message.type}`);
    }
  }

  private async handleSyncData(message: any): Promise<void> {
    if (this.syncInProgress) return;
    this.syncInProgress = true;

    try {
      console.log(`[Operator] Syncing events from main node...`);

      const { events, state } = message;

      // Update events
      if (Array.isArray(events)) {
        this.state.events = events;
        console.log(`[Operator] Synced ${events.length} events`);
      }

      // Update state maps
      if (state) {
        if (state.accounts) {
          this.state.accounts = new Map(Object.entries(state.accounts));
        }
        if (state.items) {
          this.state.items = new Map(Object.entries(state.items));
        }
        if (state.settlements) {
          this.state.settlements = new Map(Object.entries(state.settlements));
        }
        if (state.consignments) {
          this.state.consignments = new Map(Object.entries(state.consignments));
        }
        if (state.operators) {
          this.state.operators = new Map(Object.entries(state.operators));
        }
      }

      this.state.lastSyncedSequence = events.length > 0 ? events[events.length - 1].sequenceNumber : 0;
      this.state.lastSyncedAt = Date.now();

      console.log(`[Operator] Sync complete. Accounts: ${this.state.accounts.size}, Items: ${this.state.items.size}`);

      await this.persistState();
    } catch (error: any) {
      console.error('[Operator] Sync error:', error.message);
    } finally {
      this.syncInProgress = false;
    }
  }

  private async handleNewEvent(event: any): Promise<void> {
    console.log(`[Operator] New event: ${event.payload?.type}`);
    this.state.events.push(event);
    // State updates would be applied here
    await this.persistState();
  }

  private async loadPersistedState(): Promise<void> {
    const statePath = path.join(this.config.dataDir, 'operator-state.json');
    if (fs.existsSync(statePath)) {
      try {
        const data = fs.readFileSync(statePath, 'utf-8');
        const parsed = JSON.parse(data);
        this.state.events = parsed.events || [];
        this.state.accounts = new Map(Object.entries(parsed.accounts || {}));
        this.state.items = new Map(Object.entries(parsed.items || {}));
        this.state.settlements = new Map(Object.entries(parsed.settlements || {}));
        this.state.consignments = new Map(Object.entries(parsed.consignments || {}));
        this.state.operators = new Map(Object.entries(parsed.operators || {}));
        this.state.lastSyncedSequence = parsed.lastSyncedSequence || 0;
        this.state.lastSyncedAt = parsed.lastSyncedAt || 0;
        console.log(`[Operator] Loaded persisted state: ${this.state.events.length} events`);
      } catch (error: any) {
        console.error('[Operator] Failed to load persisted state:', error.message);
      }
    }
  }

  private async persistState(): Promise<void> {
    const statePath = path.join(this.config.dataDir, 'operator-state.json');
    try {
      const data = {
        events: this.state.events,
        accounts: Object.fromEntries(this.state.accounts),
        items: Object.fromEntries(this.state.items),
        settlements: Object.fromEntries(this.state.settlements),
        consignments: Object.fromEntries(this.state.consignments),
        operators: Object.fromEntries(this.state.operators),
        lastSyncedSequence: this.state.lastSyncedSequence,
        lastSyncedAt: this.state.lastSyncedAt
      };
      fs.writeFileSync(statePath, JSON.stringify(data, null, 2));
    } catch (error: any) {
      console.error('[Operator] Failed to persist state:', error.message);
    }
  }

  private computeEmailHash(email: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
  }

  private async verifyPassword(password: string, storedHash: string, kdf?: any): Promise<boolean> {
    const crypto = require('crypto');
    try {
      const computedHash = kdf
        ? crypto.pbkdf2Sync(password, Buffer.from(kdf.saltB64, 'base64'), kdf.iterations, 32, 'sha256').toString('hex')
        : crypto.createHash('sha256').update(password).digest('hex');
      
      const a = Buffer.from(computedHash, 'hex');
      const b = Buffer.from(storedHash, 'hex');
      if (a.length !== b.length) return false;
      return crypto.timingSafeEqual(a, b);
    } catch {
      return false;
    }
  }

  private randomHex(bytes: number): string {
    const crypto = require('crypto');
    return crypto.randomBytes(bytes).toString('hex');
  }
}
