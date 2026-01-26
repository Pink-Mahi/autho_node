import express, { Express, Request, Response } from 'express';
import * as http from 'http';
import WebSocket from 'ws';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import { createHash, pbkdf2Sync, timingSafeEqual, randomBytes } from 'crypto';
import { HeartbeatManager } from './consensus/heartbeat-manager';
import { StateVerifier, LedgerState } from './consensus/state-verifier';
import { EventStore, EventType, QuorumSignature } from './event-store';
import { StateBuilder } from './event-store';
import { verifySignature } from './crypto';
import { OperatorPeerDiscovery, OperatorPeerInfo, connectToOperatorPeer } from './operator-peer-discovery';
import { 
  ConsensusNode, 
  MempoolEvent, 
  FinalizedCheckpoint,
  ConsensusMessage,
  StateProviderAdapter 
} from './consensus';

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
  lastSyncedHash: string;
}

export class OperatorNode extends EventEmitter {
  private config: OperatorConfig;
  private app: Express;
  private httpServer?: http.Server;
  private wss?: WebSocket.Server;
  private mainSeedWs?: WebSocket;
  private canonicalEventStore: EventStore;
  private canonicalStateBuilder: StateBuilder;
  private state: SyncedState;
  private isConnectedToMain: boolean = false;
  private reconnectTimer?: NodeJS.Timeout;
  private syncInProgress: boolean = false;
  private lastMismatchSyncAt: number = 0;
  private consecutiveSyncFailures: number = 0;
  private gatewayConnections: Map<WebSocket, { connectedAt: number; lastSeen: number; ip?: string }> = new Map();
  private operatorPeerConnections: Map<string, { ws: WebSocket; operatorId: string; wsUrl: string; connectedAt: number; lastSeen: number }> = new Map();
  private peerDiscoveryTimer?: NodeJS.Timeout;
  private peerDiscovery?: OperatorPeerDiscovery;
  private heartbeatManager?: HeartbeatManager;
  private lastMainNodeHeartbeat: number = Date.now();
  private operatorHeartbeatTimer: any;

  private sessions: Map<string, { sessionId: string; accountId: string; createdAt: number; expiresAt: number }> = new Map();
  private operatorApplyChallenges: Map<string, { challengeId: string; accountId: string; nonce: string; createdAt: number; expiresAt: number; used: boolean }> = new Map();

  // Decentralized consensus components
  private consensusNode?: ConsensusNode;
  private stateProviderAdapter?: StateProviderAdapter;

  constructor(config: OperatorConfig) {
    super();
    this.config = config;
    this.app = express();

    this.canonicalEventStore = new EventStore(this.config.dataDir);
    this.canonicalStateBuilder = new StateBuilder(this.canonicalEventStore);

    this.state = {
      events: [],
      accounts: new Map(),
      items: new Map(),
      settlements: new Map(),
      consignments: new Map(),
      operators: new Map(),
      lastSyncedSequence: 0,
      lastSyncedAt: 0,
      lastSyncedHash: ''
    };

    this.setupMiddleware();
    this.setupRoutes();

    this.startOperatorHeartbeat();
    this.initializeConsensus();
  }

  /**
   * Initialize the decentralized consensus system
   */
  private initializeConsensus(): void {
    // Create state provider adapter
    this.stateProviderAdapter = new StateProviderAdapter({
      accounts: this.state.accounts,
      items: this.state.items,
      operators: this.state.operators,
      settlements: this.state.settlements,
      consignments: this.state.consignments,
      offers: new Map(),
      operatorCandidates: new Map(),
    });

    // Create consensus node
    this.consensusNode = new ConsensusNode(
      {
        nodeId: this.config.operatorId,
        isOperator: true,
        privateKey: this.config.privateKey,
        publicKey: this.config.publicKey,
        checkpointInterval: 30000, // 30 seconds
      },
      this.stateProviderAdapter
    );

    // Set up consensus event handlers
    this.consensusNode.setHandlers({
      onEventAccepted: (event) => this.handleConsensusEventAccepted(event),
      onEventRejected: (event, reason) => this.handleConsensusEventRejected(event, reason),
      onCheckpointFinalized: (checkpoint) => this.handleCheckpointFinalized(checkpoint),
      onStateChanged: () => this.handleConsensusStateChanged(),
    });

    console.log(`[Consensus] Initialized for operator ${this.config.operatorId}`);
  }

  /**
   * Handle event accepted by consensus
   */
  private handleConsensusEventAccepted(event: MempoolEvent): void {
    console.log(`[Consensus] Event accepted: ${event.type} (${event.eventId})`);
    // Broadcast to all peers
    this.broadcastConsensusMessage({
      type: 'mempool_event',
      payload: event,
      senderId: this.config.operatorId,
      timestamp: Date.now(),
      signature: '',
    });
    
    // Broadcast to mempool visualizer subscribers
    this.broadcastToConsensusSubscribers({
      type: 'mempool_event',
      payload: event,
    });
  }

  /**
   * Broadcast to clients subscribed to consensus updates (mempool visualizer)
   */
  private broadcastToConsensusSubscribers(message: any): void {
    const msgStr = JSON.stringify(message);
    for (const [ws, meta] of this.gatewayConnections) {
      if (ws.readyState === WebSocket.OPEN && (meta as any).subscribedToConsensus) {
        try {
          ws.send(msgStr);
        } catch {}
      }
    }
  }

  /**
   * Handle event rejected by consensus
   */
  private handleConsensusEventRejected(event: MempoolEvent, reason: string): void {
    console.log(`[Consensus] Event rejected: ${event.type} - ${reason}`);
  }

  /**
   * Handle checkpoint finalized
   */
  private async handleCheckpointFinalized(checkpoint: FinalizedCheckpoint): Promise<void> {
    console.log(`[Consensus] Checkpoint #${checkpoint.checkpointNumber} finalized with ${checkpoint.events.length} events`);
    
    // Apply checkpoint events to the canonical event store
    for (const mempoolEvent of checkpoint.events) {
      try {
        // Convert mempool event to canonical event format
        const signatures: QuorumSignature[] = [{
          operatorId: mempoolEvent.creatorId,
          publicKey: '',
          signature: mempoolEvent.creatorSignature,
        }];

        await this.canonicalEventStore.appendEvent(
          {
            type: mempoolEvent.type,
            timestamp: mempoolEvent.timestamp,
            ...mempoolEvent.payload,
          } as any,
          signatures
        );
      } catch (e: any) {
        // Event might already exist
        if (!String(e?.message || '').includes('already exists')) {
          console.error(`[Consensus] Failed to apply event ${mempoolEvent.eventId}:`, e?.message);
        }
      }
    }

    // Rebuild state
    await this.rebuildLocalStateFromCanonical();
    await this.persistState();

    // Broadcast checkpoint to peers
    this.broadcastConsensusMessage({
      type: 'checkpoint_finalized',
      payload: checkpoint,
      senderId: this.config.operatorId,
      timestamp: Date.now(),
      signature: '',
    });

    // Broadcast to mempool visualizer subscribers
    this.broadcastToConsensusSubscribers({
      type: 'checkpoint_finalized',
      payload: checkpoint,
    });

    // Broadcast registry update
    this.broadcastRegistryUpdate();
  }

  /**
   * Handle consensus state changed
   */
  private handleConsensusStateChanged(): void {
    // Update state provider with latest state
    if (this.stateProviderAdapter) {
      this.stateProviderAdapter.updateState({
        accounts: this.state.accounts,
        items: this.state.items,
        operators: this.state.operators,
        settlements: this.state.settlements,
        consignments: this.state.consignments,
        offers: new Map(),
        operatorCandidates: new Map(),
      });
    }
  }

  /**
   * Broadcast a consensus message to all peers
   */
  private broadcastConsensusMessage(message: ConsensusMessage): void {
    const msgStr = JSON.stringify(message);

    // Send to main seed
    if (this.mainSeedWs && this.mainSeedWs.readyState === WebSocket.OPEN) {
      try {
        this.mainSeedWs.send(msgStr);
      } catch {}
    }

    // Send to operator peers
    for (const peer of this.operatorPeerConnections.values()) {
      if (peer.ws.readyState === WebSocket.OPEN) {
        try {
          peer.ws.send(msgStr);
        } catch {}
      }
    }

    // Send to gateway connections
    for (const [ws] of this.gatewayConnections) {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(msgStr);
        } catch {}
      }
    }
  }

  /**
   * Submit an event through the consensus system
   * This is the new way to create events - they go to mempool first
   */
  async submitConsensusEvent(
    type: string,
    payload: Record<string, any>
  ): Promise<{ success: boolean; eventId?: string; error?: string }> {
    if (!this.consensusNode) {
      return { success: false, error: 'Consensus not initialized' };
    }

    const signature = createHash('sha256')
      .update(`${this.config.privateKey}:${type}:${Date.now()}`)
      .digest('hex');

    return this.consensusNode.submitEvent(type, payload, signature);
  }

  private async rebuildLocalStateFromCanonical(): Promise<void> {
    const state = await this.canonicalStateBuilder.buildState();
    this.state.items = state.items;
    this.state.settlements = state.settlements;
    this.state.consignments = (state as any).consignments || new Map();
    this.state.operators = state.operators;
    this.state.accounts = state.accounts;
    this.state.lastSyncedSequence = Number((state as any).lastEventSequence || 0);
    this.state.lastSyncedHash = String((state as any).lastEventHash || '');
    this.state.lastSyncedAt = Date.now();
  }

  private getGatewaySyncData(): any {
    return {
      events: this.state.events,
      accounts: Array.from(this.state.accounts.entries()),
      items: Array.from(this.state.items.entries()),
      settlements: Array.from(this.state.settlements.entries()),
      consignments: Array.from(this.state.consignments.entries()),
      operators: Array.from(this.state.operators.entries()),
      lastSyncedSequence: this.state.lastSyncedSequence,
      lastSyncedAt: this.state.lastSyncedAt,
      lastSyncedHash: this.state.lastSyncedHash,
      sequenceNumber: this.state.lastSyncedSequence,
      lastEventHash: this.state.lastSyncedHash,
    };
  }

  private getOperatorId(): string {
    return String(this.config.operatorId || '').trim();
  }

  private async requireOperatorSession(req: Request, res: Response): Promise<{ accountId: string } | null> {
    const sess = this.requireSession(req, res);
    if (!sess) return null;
    const state = await this.canonicalStateBuilder.buildState();
    const accountId = String(sess.accountId || '').trim();
    if (!accountId) {
      res.status(401).json({ success: false, error: 'Invalid session' });
      return null;
    }

    const ops = Array.from((state as any)?.operators?.values?.() || []) as any[];
    const isActiveOperator = ops.some((o: any) =>
      o && String(o.status || '') === 'active' &&
      (String(o.publicKey || '') === accountId || String(o.sponsorId || '') === accountId)
    );

    if (!isActiveOperator) {
      res.status(403).json({ success: false, error: 'Operator role required' });
      return null;
    }

    return { accountId };
  }

  private async submitCanonicalEventToSeed(payload: any, signatures: QuorumSignature[]): Promise<{ ok: boolean; error?: string }>{
    try {
      const ws = this.mainSeedWs;
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        return { ok: false, error: 'Not connected to main seed' };
      }

      const requestId = `append_${Date.now()}_${randomBytes(8).toString('hex')}`;

      const result = await new Promise<{ ok: boolean; error?: string }>((resolve) => {
        const timeout = setTimeout(() => {
          try {
            ws.off?.('message', onMessage as any);
          } catch {}
          resolve({ ok: false, error: 'Timeout waiting for seed ack' });
        }, 15000);

        const onMessage = (raw: WebSocket.Data) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (!msg || msg.type !== 'append_event_ack') return;
            if (String(msg.requestId || '') !== requestId) return;
            clearTimeout(timeout);
            try {
              ws.off?.('message', onMessage as any);
            } catch {}
            resolve({ ok: Boolean(msg.ok), error: msg.error ? String(msg.error) : undefined });
          } catch {
          }
        };

        try {
          ws.on?.('message', onMessage as any);
        } catch {}

        ws.send(JSON.stringify({
          type: 'append_event',
          requestId,
          payload,
          signatures,
          operatorId: this.getOperatorId(),
          timestamp: Date.now(),
        }));
      });

      return result;
    } catch (e: any) {
      return { ok: false, error: e?.message || String(e) };
    }
  }

  private startOperatorHeartbeat(): void {
    try {
      if (this.operatorHeartbeatTimer) {
        clearInterval(this.operatorHeartbeatTimer);
      }
    } catch {}

    const tick = async () => {
      try {
        const opId = this.getOperatorId();
        if (!opId) return;

        const state = await this.canonicalStateBuilder.buildState();
        const op: any = (state as any).operators?.get?.(opId);
        if (!op || String(op.status || '') !== 'active') return;

        const now = Date.now();
        const last = Number(op.lastHeartbeatAt || op.lastActiveAt || 0);
        const HEARTBEAT_PERIOD_MS = 24 * 60 * 60 * 1000;
        if (last && (now - last) < HEARTBEAT_PERIOD_MS) return;

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: opId,
            publicKey: String(this.config.publicKey || ''),
            signature: createHash('sha256').update(`OPERATOR_HEARTBEAT:${opId}:${now}`).digest('hex'),
          },
        ];

        await this.submitCanonicalEventToSeed(
          {
            type: EventType.OPERATOR_HEARTBEAT,
            timestamp: now,
            nonce,
            operatorId: opId,
          },
          signatures
        );
      } catch {
      }
    };

    void tick();
    this.operatorHeartbeatTimer = setInterval(() => void tick(), 60 * 60 * 1000);
  }

  private getSeedHttpBase(): string {
    const raw = String(process.env.SEED_HTTP_URL || '').trim();
    if (raw) return raw.replace(/\/$/, '');
    return this.getUiSeedHttpBase();
  }

  private async proxyToSeed(req: Request, res: Response, pathAndQuery?: string): Promise<void> {
    const base = this.getSeedHttpBase();
    if (!base) {
      res.status(502).json({ success: false, error: 'No seed HTTP base configured' });
      return;
    }

    const urlPath = typeof pathAndQuery === 'string'
      ? pathAndQuery
      : String(req.originalUrl || req.url || '').trim();
    const target = `${base}${urlPath.startsWith('/') ? '' : '/'}${urlPath}`;

    try {
      const headers: Record<string, string> = {};
      const contentType = String(req.headers['content-type'] || '').trim();
      if (contentType) headers['content-type'] = contentType;
      const auth = String(req.headers['authorization'] || '').trim();
      if (auth) headers['authorization'] = auth;

      let body: any = undefined;
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const asAny = req as any;
        if (asAny?.body && typeof asAny.body === 'object' && Object.keys(asAny.body).length > 0) {
          body = JSON.stringify(asAny.body);
          headers['content-type'] = headers['content-type'] || 'application/json';
        } else if (typeof asAny?.body === 'string' && asAny.body.trim()) {
          body = asAny.body;
        }
      }

      const seedResp = await fetch(target, {
        method: req.method,
        headers,
        body,
      });

      const outCt = String(seedResp.headers.get('content-type') || '');
      res.status(seedResp.status);
      if (outCt) res.setHeader('Content-Type', outCt);

      const isText =
        outCt.includes('application/json') ||
        outCt.startsWith('text/') ||
        outCt.includes('application/javascript') ||
        outCt.includes('application/x-javascript') ||
        outCt.includes('application/xml') ||
        outCt.includes('image/svg+xml');

      if (isText) {
        const text = await seedResp.text();
        res.send(text);
      } else {
        const ab = await seedResp.arrayBuffer();
        res.send(Buffer.from(ab));
      }
    } catch (e: any) {
      res.status(502).json({ success: false, error: e?.message || String(e) });
    }
  }

  private getUiCacheDir(): string {
    return process.env.UI_CACHE_DIR
      ? String(process.env.UI_CACHE_DIR)
      : path.join(this.config.dataDir, 'ui-cache');
  }

  private getPublicDir(): string {
    const envDir = String(process.env.PUBLIC_DIR || '').trim();
    if (envDir) return envDir;
    const cwdPublic = path.join(process.cwd(), 'public');
    try {
      if (fs.existsSync(cwdPublic) && fs.statSync(cwdPublic).isDirectory()) return cwdPublic;
    } catch {}
    return this.getUiCacheDir();
  }

  private getDownloadsDir(): string {
    const envDir = String(process.env.DOWNLOADS_DIR || '').trim();
    if (envDir) return envDir;
    const cwdDownloads = path.join(process.cwd(), 'downloads');
    try {
      if (fs.existsSync(cwdDownloads) && fs.statSync(cwdDownloads).isDirectory()) return cwdDownloads;
    } catch {}
    return '';
  }

  private getUiSeedHttpBase(): string {
    const raw = String(process.env.UI_SEED_HTTP_URL || '').trim();
    if (raw) return raw.replace(/\/$/, '');

    const seed = String(this.config.mainSeedUrl || '').trim();
    try {
      const u = new URL(seed);
      const proto = u.protocol === 'wss:' ? 'https:' : (u.protocol === 'ws:' ? 'http:' : u.protocol);
      return `${proto}//${u.host}`;
    } catch {
      return '';
    }
  }

  private async fetchText(url: string): Promise<string> {
    const resp = await fetch(url);
    const text = await resp.text();
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${String(text || '').slice(0, 200)}`);
    }
    return String(text || '');
  }

  private async ensureUiCache(): Promise<void> {
    const embeddedLanding = this.resolvePublicFile('landing.html');
    if (fs.existsSync(embeddedLanding)) return;

    const base = this.getUiSeedHttpBase();
    if (!base) return;

    const dir = this.getUiCacheDir();
    try {
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const jsDir = path.join(dir, 'js');
      if (!fs.existsSync(jsDir)) fs.mkdirSync(jsDir, { recursive: true });
      const custDir = path.join(dir, 'customer');
      if (!fs.existsSync(custDir)) fs.mkdirSync(custDir, { recursive: true });
    } catch {
      return;
    }

    const files: Array<{ urlPath: string; outPath: string }> = [
      { urlPath: '/mobile-entry.html', outPath: 'mobile-entry.html' },
      { urlPath: '/mobile-login.html', outPath: 'mobile-login.html' },
      { urlPath: '/mobile-wallet.html', outPath: 'mobile-wallet.html' },
      { urlPath: '/mobile-items.html', outPath: 'mobile-items.html' },
      { urlPath: '/mobile-offers.html', outPath: 'mobile-offers.html' },
      { urlPath: '/mobile-offer.html', outPath: 'mobile-offer.html' },
      { urlPath: '/mobile-verify.html', outPath: 'mobile-verify.html' },
      { urlPath: '/mobile-consignment.html', outPath: 'mobile-consignment.html' },
      { urlPath: '/mobile-consign.html', outPath: 'mobile-consign.html' },
      { urlPath: '/mobile-history.html', outPath: 'mobile-history.html' },
      { urlPath: '/join.html', outPath: 'join.html' },
      { urlPath: '/wallet-auth.js', outPath: 'wallet-auth.js' },
      { urlPath: '/wallet-generator.js', outPath: 'wallet-generator.js' },
      { urlPath: '/js/btc.bundle.js', outPath: path.join('js', 'btc.bundle.js') },
      { urlPath: '/js/btc.bundle.js.map', outPath: path.join('js', 'btc.bundle.js.map') },
      { urlPath: '/js/qr.bundle.js', outPath: path.join('js', 'qr.bundle.js') },
      { urlPath: '/customer/login.html', outPath: path.join('customer', 'login.html') },
      { urlPath: '/customer/signup.html', outPath: path.join('customer', 'signup.html') },
    ];

    for (const f of files) {
      try {
        const outAbs = path.join(dir, f.outPath);
        if (fs.existsSync(outAbs) && fs.statSync(outAbs).size > 0) continue;
        const text = await this.fetchText(`${base}${f.urlPath}`);
        fs.mkdirSync(path.dirname(outAbs), { recursive: true });
        fs.writeFileSync(outAbs, text);
      } catch {
      }
    }
  }

  private resolveUiFile(relPath: string): string {
    return path.join(this.getUiCacheDir(), relPath);
  }

  private resolvePublicFile(relPath: string): string {
    return path.join(this.getPublicDir(), relPath);
  }

  private computeNetworkId(): string {
    const net = this.getBitcoinNetwork();
    const fee = this.getFeeAddress();
    return createHash('sha256').update(`${net}:${fee}`).digest('hex');
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

    this.app.use('/api', async (req: Request, res: Response, next) => {
      try {
        const sid = this.getSessionIdFromRequest(req);
        if (!sid) return next();
        if (this.sessions.has(sid)) return next();

        const base = this.getSeedHttpBase();
        if (!base) return next();

        const r = await fetch(`${base}/api/auth/me`, {
          method: 'GET',
          headers: {
            Authorization: String((req.headers as any)?.authorization || ''),
          },
        });

        if (!r.ok) return next();
        const data: any = await r.json().catch(() => null);
        const accountId = String(data?.account?.accountId || data?.accountId || '').trim();
        if (!accountId) return next();

        const now = Date.now();
        this.sessions.set(sid, {
          sessionId: sid,
          accountId,
          createdAt: now,
          expiresAt: now + 24 * 60 * 60 * 1000,
        });
      } catch {
        // ignore
      }
      next();
    });
  }

  private getBitcoinNetwork(): 'mainnet' | 'testnet' {
    return this.config.network === 'mainnet' ? 'mainnet' : 'testnet';
  }

  private getChainApiBases(): string[] {
    const net = this.getBitcoinNetwork();
    return net === 'mainnet'
      ? ['https://mempool.space/api', 'https://blockstream.info/api']
      : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];
  }

  private calculatePlatformFee(amountSats: number): number {
    const amount = Math.floor(Number(amountSats || 0));
    if (!Number.isFinite(amount) || amount <= 0) return 0;

    const dustLimit = Math.floor(Number(process.env.DUST_LIMIT_SATS || 0) || 546);
    const minPlatformFeeSats = Math.floor(Number(process.env.PLATFORM_FEE_MIN_SATS || 0) || 1000);

    const percentFee = Math.floor(amount * (1.0 / 100));
    const desiredFee = Math.max(0, Math.max(percentFee, minPlatformFeeSats));

    const maxFee = amount - dustLimit;
    if (maxFee < dustLimit) return 0;
    if (desiredFee < dustLimit) return 0;
    if (desiredFee > maxFee) return 0;
    return desiredFee;
  }

  private getFeeAddress(): string {
    return this.getBitcoinNetwork() === 'testnet'
      ? String(process.env.FEE_ADDRESS_TESTNET || '').trim()
      : '1FMcxZRUWVDbKy7DxAosW7sM5PUntAkJ9U';
  }

  private getSessionIdFromRequest(req: Request): string {
    const hdr = String((req.headers as any)?.authorization || '').trim();
    if (!hdr) return '';
    return hdr.toLowerCase().startsWith('bearer ') ? hdr.slice(7).trim() : hdr;
  }

  private getSession(req: Request): { sessionId: string; accountId: string; createdAt: number; expiresAt: number } | null {
    const sid = this.getSessionIdFromRequest(req);
    if (!sid) return null;
    const sess = this.sessions.get(sid);
    if (!sess) return null;
    if (Date.now() > sess.expiresAt) {
      this.sessions.delete(sid);
      return null;
    }
    return sess;
  }

  private requireSession(req: Request, res: Response): { sessionId: string; accountId: string; createdAt: number; expiresAt: number } | null {
    const sess = this.getSession(req);
    if (!sess) {
      res.status(401).json({ success: false, error: 'Login required' });
      return null;
    }
    return sess;
  }

  private async getAccountFromSession(req: Request): Promise<{ accountId: string; role?: string } | null> {
    const base = this.getSeedHttpBase();
    if (!base) return null;
    try {
      const authHeader = String((req.headers as any)?.authorization || '').trim();
      if (!authHeader) return null;
      const r = await fetch(`${base}/api/auth/me`, {
        method: 'GET',
        headers: { Authorization: authHeader },
      });
      const data = await r.json() as any;
      if (!r.ok || !data || !data.account) return null;
      return data.account;
    } catch {
      return null;
    }
  }

  private setupRoutes(): void {
    const publicDir = this.getPublicDir();
    this.app.use(express.static(publicDir, {
      index: false,
      setHeaders: (res, filePath) => {
        try {
          const p = String(filePath || '').toLowerCase();
          if (p.endsWith('.js')) {
            res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
          } else if (p.endsWith('.js.map') || p.endsWith('.map')) {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
          }
        } catch {
        }
      },
    }));

    this.app.get('/downloads/gateway-node/:filename', (req: Request, res: Response) => {
      const { filename } = req.params;
      const downloadsDir = this.getDownloadsDir();
      const filePath = path.join(downloadsDir, 'gateway-node', filename);

      const proto = String((req.headers as any)?.['x-forwarded-proto'] || req.protocol || 'https')
        .split(',')[0]
        .trim();
      const host = String(req.headers.host || '').trim();
      const origin = host ? `${proto}://${host}` : 'http://localhost:3000';
      const baseUrl = `${origin}/downloads/gateway-node`;

      const sendText = (body: string, contentType: string) => {
        res.setHeader('Content-Type', contentType);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.send(body);
      };

      if (filename === 'quick-install.sh') {
        const body = `#!/bin/bash\n# Autho Gateway Node - One-Line Installer\n# Usage: curl -fsSL ${baseUrl}/quick-install.sh | bash\n\nset -e\n\necho \"ðŸŒ Autho Gateway Node - Quick Installer\"\necho \"========================================\"\n\nif ! command -v node &> /dev/null; then\n    echo \"âŒ Node.js is not installed\"\n    echo \"   Please install Node.js 18+ from: https://nodejs.org/\"\n    exit 1\nfi\n\nNODE_VERSION=$(node -e 'process.stdout.write(process.versions.node.split(\".\")[0])')\nif [ \"$NODE_VERSION\" -lt 18 ]; then\n    echo \"âŒ Node.js 18+ required. Current: $(node --version)\"\n    exit 1\nfi\n\necho \"âœ… Node.js $(node --version)\"\n\nTEMP_DIR=$(mktemp -d)\ncd \"$TEMP_DIR\"\n\necho \"ðŸ“¥ Downloading gateway node...\"\nCACHE_BUST=$(date +%s)\ncurl -fsSL \"${baseUrl}/gateway-package.js?v=\${CACHE_BUST}\" -o gateway-package.js\ncurl -fsSL \"${baseUrl}/package.json?v=\${CACHE_BUST}\" -o package.json\n\nINSTALL_DIR=\"$HOME/autho-gateway-node\"\necho \"ðŸ“ Installing to: $INSTALL_DIR\"\nmkdir -p \"$INSTALL_DIR\"\n\ncp gateway-package.js \"$INSTALL_DIR/\"\ncp package.json \"$INSTALL_DIR/\"\ncd \"$INSTALL_DIR\"\n\necho \"ðŸ“¦ Installing dependencies...\"\nnpm install --silent\n\ncat > start.sh << 'EOF'\n#!/bin/bash\ncd \"$(dirname \"$0\")\"\nexport AUTHO_OPERATOR_URLS=\"${origin}\"\nnode gateway-package.js\nEOF\nchmod +x start.sh\n\nrm -rf \"$TEMP_DIR\"\n\necho \"\"\necho \"âœ… Installation complete!\"\necho \"\"\necho \"ðŸš€ Start the gateway node:\"\necho \"   cd $INSTALL_DIR\"\necho \"   ./start.sh\"\necho \"\"\necho \"ðŸŒ Gateway will run on: http://localhost:3001\"\necho \"ðŸ“Š Health check: http://localhost:3001/health\"\necho \"\"\necho \"ðŸŽ‰ Welcome to the Autho network!\"\n`;
        sendText(body, 'text/plain; charset=utf-8');
        return;
      }

      if (filename === 'quick-install.ps1') {
        const body = `# Autho Gateway Node - PowerShell Installer\n# Usage: irm ${baseUrl}/quick-install.ps1 | iex\n\nWrite-Host \"ðŸŒ Autho Gateway Node - Quick Installer\" -ForegroundColor Cyan\nWrite-Host \"========================================\" -ForegroundColor Cyan\nWrite-Host \"\"\n\ntry {\n    $nodeVersion = node --version\n    $majorVersion = [int]($nodeVersion -replace 'v(\\d+)\\..*', '$1')\n    if ($majorVersion -lt 18) {\n        Write-Host \"âŒ Node.js 18+ required. Current: $nodeVersion\" -ForegroundColor Red\n        Write-Host \"   Download from: https://nodejs.org/\" -ForegroundColor Yellow\n        exit 1\n    }\n    Write-Host \"âœ… Node.js $nodeVersion\" -ForegroundColor Green\n} catch {\n    Write-Host \"âŒ Node.js is not installed\" -ForegroundColor Red\n    Write-Host \"   Please install Node.js 18+ from: https://nodejs.org/\" -ForegroundColor Yellow\n    exit 1\n}\n\n$installDir = \"$env:USERPROFILE\\autho-gateway-node\"\nWrite-Host \"ðŸ“ Installing to: $installDir\" -ForegroundColor Cyan\nif (-not (Test-Path $installDir)) {\n    New-Item -ItemType Directory -Path $installDir -Force | Out-Null\n    Write-Host \"âœ… Created installation directory\" -ForegroundColor Green\n}\n\nWrite-Host \"ðŸ“¥ Downloading gateway node...\"\ntry {\n    $baseUrl = \"${baseUrl}\"\n    $cacheBust = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()\n    $headers = @{ 'Cache-Control' = 'no-cache'; 'Pragma' = 'no-cache' }\n    Invoke-WebRequest -Uri \"$baseUrl/gateway-package.js?v=$cacheBust\" -Headers $headers -OutFile \"$installDir\\gateway-package.js\" -UseBasicParsing\n    Invoke-WebRequest -Uri \"$baseUrl/package.json?v=$cacheBust\" -Headers $headers -OutFile \"$installDir\\package.json\" -UseBasicParsing\n    Invoke-WebRequest -Uri \"$baseUrl/Start-Autho-Gateway-Node.bat?v=$cacheBust\" -Headers $headers -OutFile \"$installDir\\Start-Autho-Gateway-Node.bat\" -UseBasicParsing\n    Invoke-WebRequest -Uri \"$baseUrl/Start-Autho-Gateway-Node-Background.bat?v=$cacheBust\" -Headers $headers -OutFile \"$installDir\\Start-Autho-Gateway-Node-Background.bat\" -UseBasicParsing\n    Write-Host \"âœ… Files downloaded\" -ForegroundColor Green\n} catch {\n    Write-Host \"âŒ Failed to download files: $_\" -ForegroundColor Red\n    exit 1\n}\n\nWrite-Host \"ðŸ“¦ Installing dependencies...\" -ForegroundColor Cyan\nPush-Location $installDir\ntry {\n    npm install --silent 2>&1 | Out-Null\n    Write-Host \"âœ… Dependencies installed\" -ForegroundColor Green\} catch {\n    Write-Host \"âš ï¸  Warning: npm install had issues, but continuing...\" -ForegroundColor Yellow\}\nPop-Location\n\nWrite-Host \"\"\nWrite-Host \"âœ… Installation complete!\" -ForegroundColor Green\nWrite-Host \"\"\nWrite-Host \"ðŸ–±ï¸ Next time, start by double-clicking:\" -ForegroundColor Cyan\nWrite-Host \"   $installDir\\Start-Autho-Gateway-Node.bat\" -ForegroundColor White\nWrite-Host \"\"\nWrite-Host \"ðŸŒ Gateway will run on: http://localhost:3001\" -ForegroundColor Cyan\nWrite-Host \"ðŸ“Š Health check: http://localhost:3001/health\" -ForegroundColor Cyan\nWrite-Host \"\"\nWrite-Host \"ðŸŽ‰ Welcome to the Autho network!\" -ForegroundColor Green\nWrite-Host \"\"\n`;
        sendText(body, 'text/plain; charset=utf-8');
        return;
      }

      if (filename === 'quick-install.bat') {
        const body = `@echo off\r\nREM Autho Gateway Node - One-Line Installer for Windows\r\n\r\necho ðŸŒ Autho Gateway Node - Quick Installer\r\necho ========================================\r\n\r\nwhere node >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n    echo âŒ Node.js is not installed\r\n    echo    Please install Node.js 18+ from: https://nodejs.org/\r\n    pause\r\n    exit /b 1\r\n)\r\n\r\nset INSTALL_DIR=%USERPROFILE%\\autho-gateway-node\r\necho ðŸ“ Installing to: %INSTALL_DIR%\r\nif not exist \"%INSTALL_DIR%\" mkdir \"%INSTALL_DIR%\"\r\n\r\necho ðŸ“¥ Downloading gateway node...\r\ncd /d \"%INSTALL_DIR%\"\r\nfor /f %%i in ('powershell -NoProfile -Command \"[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()\"') do set CACHE_BUST=%%i\r\n\r\npowershell -NoProfile -Command \"$ErrorActionPreference='Stop'; $h=@{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' }; Invoke-WebRequest -UseBasicParsing -Headers $h -Uri '${baseUrl}/gateway-package.js?v=%CACHE_BUST%' -OutFile 'gateway-package.js' | Out-Null\"\r\nif %ERRORLEVEL% NEQ 0 (\r\n    echo âŒ Failed to download gateway-package.js\r\n    pause\r\n    exit /b 1\r\n)\r\n\r\npowershell -NoProfile -Command \"$ErrorActionPreference='Stop'; $h=@{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' }; Invoke-WebRequest -UseBasicParsing -Headers $h -Uri '${baseUrl}/package.json?v=%CACHE_BUST%' -OutFile 'package.json' | Out-Null\"\r\nif %ERRORLEVEL% NEQ 0 (\r\n    echo âŒ Failed to download package.json\r\n    pause\r\n    exit /b 1\r\n)\r\n\r\npowershell -NoProfile -Command \"$ErrorActionPreference='Stop'; $h=@{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' }; Invoke-WebRequest -UseBasicParsing -Headers $h -Uri '${baseUrl}/Start-Autho-Gateway-Node.bat?v=%CACHE_BUST%' -OutFile 'Start-Autho-Gateway-Node.bat' | Out-Null\"\r\n\r\necho ðŸ“¦ Installing dependencies...\r\ncall npm install --silent\r\n\r\necho.\r\necho âœ… Installation complete!\r\necho.\r\necho ðŸ–±ï¸ Start the gateway node by double-clicking:\r\necho    %INSTALL_DIR%\\Start-Autho-Gateway-Node.bat\r\necho.\r\necho ðŸŒ Gateway will run on: http://localhost:3001\r\necho ðŸ“Š Health check: http://localhost:3001/health\r\necho.\r\npause\r\n`;
        sendText(body, 'text/plain; charset=utf-8');
        return;
      }

      if (filename === 'Start-Autho-Gateway-Node.bat') {
        const body = `@echo off\r\nsetlocal enabledelayedexpansion\r\n\r\nset \"SCRIPT_DIR=%~dp0\"\r\ncd /d \"%SCRIPT_DIR%\"\r\n\r\necho ==============================================\r\necho  Autho Gateway Node (One-Click Launcher)\r\necho ==============================================\r\n\r\nwhere node >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: Node.js is not installed.\r\n  echo Please install Node.js 18+ from https://nodejs.org/\r\n  echo.\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\nwhere npm >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: npm was not found.\r\n  echo Reinstall Node.js (it includes npm): https://nodejs.org/\r\n  echo.\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\nset \"PORT=%1\"\r\nif \"%PORT%\"==\"\" (\r\n  if defined GATEWAY_PORT (\r\n    set \"PORT=%GATEWAY_PORT%\"\r\n  ) else (\r\n    set \"PORT=3001\"\r\n  )\r\n)\r\n\r\nif not exist \"node_modules\" (\r\n  echo Installing dependencies (first run)...\r\n  call npm install\r\n)\r\n\r\necho.\r\necho Starting gateway node on port %PORT%...\r\necho A new window will open with the node logs.\r\necho.\r\n\r\nstart \"Autho Gateway Node\" cmd /k \"cd /d \\\"%SCRIPT_DIR%\\\" ^&^& set GATEWAY_PORT=%PORT% ^&^& set AUTHO_OPERATOR_URLS=${origin} ^&^& node gateway-package.js\"\r\n\r\ntimeout /t 2 /nobreak >nul\r\nstart \"\" \"http://localhost:%PORT%/m\"\r\n\r\necho.\r\necho Opened: http://localhost:%PORT%/m\r\necho.\r\nexit /b 0\r\n`;
        sendText(body, 'text/plain; charset=utf-8');
        return;
      }

      if (filename === 'Start-Autho-Gateway-Node-Background.bat') {
        const body = `@echo off\r\nsetlocal enabledelayedexpansion\r\n\r\nset \"SCRIPT_DIR=%~dp0\"\r\ncd /d \"%SCRIPT_DIR%\"\r\n\r\necho ==============================================\r\necho  Autho Gateway Node (Background Launcher)\r\necho ==============================================\r\n\r\nwhere node >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: Node.js is not installed.\r\n  echo Please install Node.js 18+ from https://nodejs.org/\r\n  echo.\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\nwhere npm >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: npm was not found.\r\n  echo Reinstall Node.js (it includes npm): https://nodejs.org/\r\n  echo.\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\nset \"PORT=%1\"\r\nif \"%PORT%\"==\"\" (\r\n  if defined GATEWAY_PORT (\r\n    set \"PORT=%GATEWAY_PORT%\"\r\n  ) else (\r\n    set \"PORT=3001\"\r\n  )\r\n)\r\n\r\nif not exist \"node_modules\" (\r\n  echo Installing dependencies (first run)...\r\n  call npm install\r\n)\r\n\r\necho.\r\necho Starting gateway node in the background on port %PORT%...\r\necho Logs: %SCRIPT_DIR%gateway-node.log\r\necho.\r\n\r\nstart \"\" /min cmd /c \"cd /d \\\"%SCRIPT_DIR%\\\" ^&^& set GATEWAY_PORT=%PORT% ^&^& set AUTHO_OPERATOR_URLS=${origin} ^&^& node gateway-package.js 1^> gateway-node.log 2^>^&1\"\r\n\r\ntimeout /t 2 /nobreak >nul\r\nstart \"\" \"http://localhost:%PORT%/m\"\r\n\r\necho.\r\necho Opened: http://localhost:%PORT%/m\r\necho.\r\nexit /b 0\r\n`;
        sendText(body, 'text/plain; charset=utf-8');
        return;
      }

      if (filename === 'Autho-Gateway-OneClick-Windows.bat') {
        const body = `@echo off\r\nsetlocal enabledelayedexpansion\r\n\r\necho ==============================================\r\necho  Autho Gateway Node - One-Click Windows Setup\r\necho ==============================================\r\n\r\nset \"INSTALL_DIR=%USERPROFILE%\\autho-gateway-node\"\r\n\r\nwhere node >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: Node.js is not installed.\r\n  echo Please install Node.js 18+ from https://nodejs.org/\r\n  echo.\r\n  start \"\" \"https://nodejs.org/\"\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\nwhere npm >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: npm was not found.\r\n  echo Reinstall Node.js (it includes npm): https://nodejs.org/\r\n  echo.\r\n  start \"\" \"https://nodejs.org/\"\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\necho âœ… Node:\r\nnode --version\r\n\r\nif not exist \"%INSTALL_DIR%\" (\r\n  echo ðŸ“ Creating: %INSTALL_DIR%\r\n  mkdir \"%INSTALL_DIR%\" >nul 2>nul\r\n)\r\n\r\ncd /d \"%INSTALL_DIR%\"\r\n\r\necho ðŸ“¥ Downloading gateway files...\r\nset \"BASE_URL=${baseUrl}\"\r\nfor /f %%i in ('powershell -NoProfile -Command \"[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()\"') do set CACHE_BUST=%%i\r\n\r\npowershell -NoProfile -Command \"$ErrorActionPreference='Stop'; try { Invoke-WebRequest -Uri '%BASE_URL%/gateway-package.js?v=%CACHE_BUST%' -Headers @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' } -OutFile 'gateway-package.js' -UseBasicParsing | Out-Null; exit 0 } catch { Write-Host $_; exit 1 }\"\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo ERROR: Failed to download gateway-package.js\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\npowershell -NoProfile -Command \"$ErrorActionPreference='Stop'; try { Invoke-WebRequest -Uri '%BASE_URL%/package.json?v=%CACHE_BUST%' -Headers @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' } -OutFile 'package.json' -UseBasicParsing | Out-Null; exit 0 } catch { Write-Host $_; exit 1 }\"\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo ERROR: Failed to download package.json\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\npowershell -NoProfile -Command \"Invoke-WebRequest -Uri '%BASE_URL%/Start-Autho-Gateway-Node.bat?v=%CACHE_BUST%' -Headers @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' } -OutFile 'Start-Autho-Gateway-Node.bat' -UseBasicParsing\" >nul 2>nul\r\n\r\nif not exist \"node_modules\" (\r\n  echo ðŸ“¦ Installing dependencies (first run)...\r\n  call npm install\r\n  if %ERRORLEVEL% NEQ 0 (\r\n    echo ERROR: npm install failed.\r\n    pause\r\n    exit /b 1\r\n  )\r\n) else (\r\n  echo âœ… Dependencies already installed.\r\n)\r\n\r\nset \"DESKTOP=%USERPROFILE%\\Desktop\"\r\nif exist \"%DESKTOP%\" (\r\n  powershell -NoProfile -Command \"$s=(New-Object -ComObject WScript.Shell).CreateShortcut(\"$env:USERPROFILE\\Desktop\\Autho Gateway Node.lnk\"); $s.TargetPath=\"%INSTALL_DIR%\\Start-Autho-Gateway-Node.bat\"; $s.WorkingDirectory=\"%INSTALL_DIR%\"; $s.WindowStyle=1; $s.Description=\"Start Autho Gateway Node\"; $s.Save()\" >nul 2>nul\r\n)\r\n\r\necho.\r\necho âœ… Installed!\r\necho.\r\necho ðŸ–¥ï¸ Desktop shortcut created (if possible):\r\necho    Autho Gateway Node\r\necho.\r\necho ðŸš€ Starting gateway node...\r\necho.\r\ncall Start-Autho-Gateway-Node.bat\r\n\r\npause\r\nexit /b 0\r\n`;
        sendText(body, 'text/plain; charset=utf-8');
        return;
      }

      if (fs.existsSync(filePath)) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.sendFile(filePath);
        return;
      }

      res.status(404).json({ error: 'File not found' });
    });

    const downloadsDir = this.getDownloadsDir();
    if (downloadsDir) {
      this.app.use(
        '/downloads',
        express.static(downloadsDir, {
          setHeaders: (res) => {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
          },
        })
      );
    }

    this.app.get('/', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('landing.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      const fallback = this.resolvePublicFile('mobile-entry.html');
      if (fs.existsSync(fallback)) return res.sendFile(fallback);
      res.json({ success: true, operatorId: this.config.operatorId, message: 'Operator node is running' });
    });

    this.app.get('/join', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('join.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/how-it-works', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('how-it-works.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/buy', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('buy.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/setup', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('setup-wizard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/manufacturer', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('manufacturer-dashboard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/authenticator', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('authenticator-dashboard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/retailer', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('retailer-dashboard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/dashboard', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('dashboard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/admin/login', async (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('admin-login.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      await this.proxyToSeed(req, res, '/admin/login');
    });

    this.app.get('/operator', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('operator-portal.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/operator/dashboard', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('operator-dashboard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/operator/apply', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('operator-apply.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get(['/customer/login', '/customer/login/'], (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('customer/login.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get(['/customer/signup', '/customer/signup/'], (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('customer/signup.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/m', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-entry.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/login', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-login.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/wallet', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-wallet.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    const renderPayPage = async (req: Request, res: Response, handleInput: string) => {
      try {
        const handleRaw = String(handleInput || '').trim().toLowerCase();
        if (!handleRaw) {
          res.status(400).send('Missing handle');
          return;
        }

        const handle = handleRaw.includes('@') ? handleRaw : `${handleRaw}@autho`;
        if (!handle.endsWith('@autho')) {
          res.status(400).send('Invalid handle');
          return;
        }

        const base = this.getSeedHttpBase();
        if (!base) {
          res.status(502).send('No seed HTTP base configured');
          return;
        }

        const memo = String((req.query as any)?.memo || '').trim();
        const memoEsc = memo
          ? memo.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as any)[c])
          : '';
        const amountSatsStr = String((req.query as any)?.amountSats || '').trim();
        const amountSats = amountSatsStr ? Math.floor(Number(amountSatsStr)) : 0;

        const r = await fetch(`${base}/api/pay/resolve?handle=${encodeURIComponent(handle)}`, { method: 'GET' });
        const data: any = await r.json().catch(() => null);
        if (!r.ok || !data || data.success !== true) {
          res.status(r.status || 404).send(String(data?.error || 'Pay handle not found'));
          return;
        }

        const resolvedAddress = String(data.walletAddress || '').trim();
        const resolvedAccountId = String(data.accountId || '').trim();
        if (!resolvedAddress) {
          res.status(404).send('Pay handle not found');
          return;
        }
        if (!resolvedAddress.match(/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/)) {
          res.status(400).send('Resolved address is invalid');
          return;
        }

        const params: string[] = [];
        if (amountSats > 0 && Number.isFinite(amountSats)) {
          params.push(`amount=${encodeURIComponent((amountSats / 1e8).toFixed(8).replace(/0+$/, '').replace(/\.$/, ''))}`);
        }
        if (memo) {
          params.push(`message=${encodeURIComponent(memo)}`);
        }
        const bip21 = `bitcoin:${resolvedAddress}${params.length ? `?${params.join('&')}` : ''}`;
        const qrUrl = `/api/qr.png?text=${encodeURIComponent(bip21)}`;

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Pay ${handle}</title>
  <style>
    body { background:#0a0a0a; color:#fff; font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin:0; }
    .wrap { max-width: 560px; margin: 0 auto; padding: 24px; }
    .card { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12); border-radius: 16px; padding: 16px; margin-top: 12px; }
    .title { font-weight: 700; font-size: 20px; }
    .muted { color: rgba(255,255,255,0.75); font-size: 13px; line-height: 1.5; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .row { margin-top: 10px; }
    input { width:100%; padding: 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.15); background: rgba(0,0,0,0.2); color:#fff; }
    button, a.btn { display:inline-block; padding: 12px 14px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.15); background: rgba(212,175,55,0.18); color:#fff; text-decoration:none; font-weight: 600; }
    .btn.secondary { background: rgba(255,255,255,0.08); }
    .grid { display:flex; gap:10px; flex-wrap: wrap; }
    img { width: 250px; height: 250px; background:#fff; border-radius: 12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="title">Pay <span class="mono">${handle}</span></div>
    <div class="muted">This page resolves the Autho pay handle to a Bitcoin address. You can pay using any external wallet (Cash App, etc.).</div>

    <div class="card">
      <div class="muted">Bitcoin address</div>
      <div class="row"><input id="addr" class="mono" readonly value="${resolvedAddress}" /></div>
      <div class="row grid">
        <button class="btn secondary" onclick="copyAddr()">Copy Address</button>
        <a class="btn" href="${bip21}">Open in Wallet</a>
      </div>
      ${memo ? `<div class="row muted">Memo: ${memoEsc}</div>` : ''}
      ${(amountSats > 0 && Number.isFinite(amountSats)) ? `<div class="row muted">Amount: ${amountSats} sats</div>` : ''}
      ${resolvedAccountId ? `<div class="row muted">Account: <span class="mono">${resolvedAccountId}</span></div>` : ''}
    </div>

    <div class="card" style="display:flex; justify-content:center;">
      <img alt="Bitcoin payment QR" src="${qrUrl}" />
    </div>
  </div>

  <script>
    function copyAddr() {
      const el = document.getElementById('addr');
      const v = el ? String(el.value || '').trim() : '';
      if (!v) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(v).then(() => alert('Address copied')).catch(() => alert('Copy failed'));
        return;
      }
      try {
        el.focus();
        el.select();
        document.execCommand('copy');
        alert('Address copied');
      } catch {
        alert('Copy failed');
      }
    }
  </script>
</body>
</html>`);
      } catch (e: any) {
        res.status(500).send(e?.message || 'Internal error');
      }
    };

    this.app.get('/pay', async (req: Request, res: Response) => {
      const handle = String((req.query as any)?.handle || '').trim();
      await renderPayPage(req, res, handle);
    });

    this.app.get('/pay/:handle', async (req: Request, res: Response) => {
      const handle = String((req.params as any)?.handle || '').trim();
      await renderPayPage(req, res, handle);
    });

    this.app.get('/m/items', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-items.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/offers', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-offers.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/offer', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-offer.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/verify', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-verify.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/consignment', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-consignment.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/consign', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-consign.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/history', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-history.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });

    this.app.get('/verify', (req: Request, res: Response) => {
      const id = String((req.query as any)?.id || (req.query as any)?.itemId || '').trim();
      if (id) {
        res.redirect(`/m/verify?itemId=${encodeURIComponent(id)}`);
        return;
      }
      res.redirect('/m/verify');
    });

    this.app.get('/consignment', (req: Request, res: Response) => {
      const consignmentId = String((req.query as any)?.consignmentId || (req.query as any)?.id || '').trim();
      if (consignmentId) {
        res.redirect(`/m/consignment?consignmentId=${encodeURIComponent(consignmentId)}`);
        return;
      }
      res.redirect('/m/consignment');
    });

    this.app.get('/consign', (req: Request, res: Response) => {
      const itemId = String((req.query as any)?.itemId || (req.query as any)?.item || '').trim();
      const retailerAccountId = String((req.query as any)?.retailerAccountId || (req.query as any)?.retailer || '').trim();
      const qs: string[] = [];
      if (itemId) qs.push(`itemId=${encodeURIComponent(itemId)}`);
      if (retailerAccountId) qs.push(`retailerAccountId=${encodeURIComponent(retailerAccountId)}`);
      res.redirect(`/m/consign${qs.length ? `?${qs.join('&')}` : ''}`);
    });

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

    this.app.get('/api/registry/head', async (req: Request, res: Response) => {
      try {
        const state = await this.canonicalStateBuilder.buildState();
        const operators = Array.from((state as any).operators?.values?.() || []) as any[];

        const now = Date.now();
        const ACTIVE_WINDOW_MS = 36 * 60 * 60 * 1000;
        const activeOperators = operators.filter((o: any) => {
          if (!o || String(o.status || '') !== 'active') return false;
          const last = Number(o.lastHeartbeatAt || o.lastActiveAt || 0);
          if (!last) return false;
          return (now - last) <= ACTIVE_WINDOW_MS;
        });

        res.json({
          success: true,
          lastEventSequence: (state as any).lastEventSequence,
          lastEventHash: (state as any).lastEventHash,
          activeOperatorCount: activeOperators.length,
          activeOperatorIds: activeOperators.map((o: any) => String(o.operatorId || '')).filter(Boolean),
          timestamp: Date.now(),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Consensus status endpoint for monitoring
    this.app.get('/api/consensus/status', async (req: Request, res: Response) => {
      try {
        if (!this.consensusNode) {
          res.json({
            success: false,
            error: 'Consensus not initialized',
          });
          return;
        }

        const consensusState = this.consensusNode.getState();
        const mempoolEvents = this.consensusNode.getMempoolEvents();
        const checkpoints = this.consensusNode.getCheckpoints();

        res.json({
          success: true,
          nodeId: this.config.operatorId,
          isOperator: true,
          consensus: {
            currentCheckpointNumber: consensusState.currentCheckpointNumber,
            lastCheckpointHash: consensusState.lastCheckpointHash,
            lastCheckpointAt: consensusState.lastCheckpointAt,
            isLeader: consensusState.isLeader,
            currentLeaderId: consensusState.currentLeaderId,
            activeOperators: consensusState.activeOperators,
            pendingProposal: consensusState.pendingProposal ? {
              checkpointNumber: consensusState.pendingProposal.checkpointNumber,
              proposedBy: consensusState.pendingProposal.proposedBy,
              eventCount: consensusState.pendingProposal.eventIds.length,
            } : null,
          },
          mempool: {
            totalEvents: consensusState.mempoolStats.totalEvents,
            validEvents: consensusState.mempoolStats.validEvents,
            invalidEvents: consensusState.mempoolStats.invalidEvents,
            pendingEvents: consensusState.mempoolStats.pendingEvents,
            eventsByType: consensusState.mempoolStats.eventsByType,
            oldestEventAge: consensusState.mempoolStats.oldestEventAge,
          },
          checkpoints: {
            total: checkpoints.length,
            recent: checkpoints.slice(-5).map(c => ({
              number: c.checkpointNumber,
              hash: c.checkpointHash.substring(0, 16) + '...',
              eventCount: c.events.length,
              finalizedAt: c.finalizedAt,
              yesVotes: c.totalYesVotes,
              noVotes: c.totalNoVotes,
            })),
          },
          peers: {
            mainSeedConnected: this.mainSeedWs?.readyState === WebSocket.OPEN,
            operatorPeers: this.operatorPeerConnections.size,
            gatewayConnections: this.gatewayConnections.size,
          },
          timestamp: Date.now(),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Operator discovery endpoint for gateway nodes
    this.app.get('/api/network/operators', async (req: Request, res: Response) => {
      try {
        const state = await this.canonicalStateBuilder.buildState();
        const operators = Array.from((state as any).operators?.values?.() || []) as any[];
        const now = Date.now();
        const activeWindowMs = 36 * 60 * 60 * 1000;

        const activeOperators = operators.filter((o: any) => {
          if (!o || String(o.status || '') !== 'active') return false;
          const lastHeartbeatAt = Number(o.lastHeartbeatAt || 0);
          const lastActiveAt = Number(o.lastActiveAt || 0);
          const admittedAt = Number(o.admittedAt || 0);
          const lastSeenAt = Math.max(lastHeartbeatAt, lastActiveAt, admittedAt);
          if (!Number.isFinite(lastSeenAt) || lastSeenAt <= 0) return false;
          return (now - lastSeenAt) <= activeWindowMs;
        });

        const operatorList = activeOperators
          .map((op: any) => {
            const operatorUrl = String(op.operatorUrl || '').trim();
            let wsUrl = '';

            if (operatorUrl) {
              if (operatorUrl.startsWith('https://')) {
                wsUrl = operatorUrl.replace('https://', 'wss://');
              } else if (operatorUrl.startsWith('http://')) {
                wsUrl = operatorUrl.replace('http://', 'ws://');
              } else if (operatorUrl.includes('localhost') || operatorUrl.includes('127.0.0.1')) {
                wsUrl = `ws://${operatorUrl}`;
              } else {
                wsUrl = `wss://${operatorUrl}`;
              }
            }

            return {
              operatorId: String(op.operatorId || ''),
              operatorUrl,
              wsUrl,
              btcAddress: String(op.btcAddress || ''),
              status: 'active',
              admittedAt: op.admittedAt,
              lastHeartbeatAt: op.lastHeartbeatAt,
              lastActiveAt: op.lastActiveAt,
            };
          })
          .filter((op: any) => op && op.wsUrl);

        res.json({
          success: true,
          timestamp: Date.now(),
          network: this.config.network,
          currentSequence: (state as any).lastEventSequence,
          activeWindowMs,
          operators: operatorList,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/operators/candidates', async (req: Request, res: Response) => {
      try {
        const sess = await this.requireOperatorSession(req, res);
        if (!sess) return;

        const state = await this.canonicalStateBuilder.buildState();
        const status = String((req.query as any)?.status || 'open');
        const items = Array.from((state as any).operators?.values?.() || [])
          .filter((o: any) => o && String(o.status || '') === 'candidate')
          .map((c: any) => ({
            operatorId: String(c.operatorId || ''),
            btcAddress: String(c.btcAddress || ''),
            publicKey: String(c.publicKey || ''),
            operatorUrl: String(c.operatorUrl || ''),
            sponsorId: String(c.sponsorId || ''),
            candidateRequestedAt: Number(c.candidateRequestedAt || 0),
            eligibleVotingAt: Number(c.eligibleVotingAt || 0),
            eligibleVoterCount: Number(c.eligibleVoterCount || (Array.isArray(c.eligibleVoterIds) ? c.eligibleVoterIds.length : 0) || 0),
            requiredYesVotes: Number(c.requiredYesVotes || 0),
            voteCount: c.voteCount || { approve: 0, reject: 0 },
          }));

        const now = Date.now();
        const filtered = items.filter((c: any) => {
          if (status === 'open') return now < Number(c.eligibleVotingAt || 0);
          if (status === 'voting') return now >= Number(c.eligibleVotingAt || 0);
          return true;
        });

        res.json({ success: true, candidates: filtered });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/operators/candidates/:candidateId/vote', async (req: Request, res: Response) => {
      try {
        const sess = await this.requireOperatorSession(req, res);
        if (!sess) return;

        const voterId = this.getOperatorId();
        if (!voterId) {
          res.status(500).json({ success: false, error: 'OPERATOR_ID is not configured on this node' });
          return;
        }

        const candidateId = String(req.params.candidateId || '').trim();
        const v = String((req.body as any)?.vote || '').trim();
        const reason = (req.body as any)?.reason ? String((req.body as any).reason) : undefined;
        if (v !== 'approve' && v !== 'reject') {
          res.status(400).json({ success: false, error: 'vote must be approve or reject' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const c: any = (state as any).operators?.get?.(candidateId);
        if (!c || String(c.status || '') !== 'candidate') {
          res.status(404).json({ success: false, error: 'Candidate not found' });
          return;
        }

        const myOp: any = (state as any).operators?.get?.(voterId);
        if (!myOp || String(myOp.status || '') !== 'active') {
          res.status(403).json({ success: false, error: 'This node is not an active operator' });
          return;
        }

        const eligibleVotingAt = Number(c.eligibleVotingAt || 0);
        if (eligibleVotingAt && Date.now() < eligibleVotingAt) {
          res.status(400).json({ success: false, error: 'Voting not yet enabled (founder window still open)' });
          return;
        }

        const eligibleVoterIds = Array.isArray(c.eligibleVoterIds) ? (c.eligibleVoterIds as any[]).map((x) => String(x)) : [];
        if (eligibleVoterIds.length > 0 && !eligibleVoterIds.includes(voterId)) {
          res.status(403).json({ success: false, error: 'Not eligible to vote on this candidate' });
          return;
        }

        if (c.votes && c.votes.has && c.votes.has(voterId)) {
          res.status(400).json({ success: false, error: 'Already voted' });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const now = Date.now();
        const signatures: QuorumSignature[] = [
          {
            operatorId: voterId,
            publicKey: String(this.config.publicKey || ''),
            signature: createHash('sha256')
              .update(`OPERATOR_CANDIDATE_VOTE:${candidateId}:${voterId}:${now}`)
              .digest('hex'),
          },
        ];

        const r = await this.submitCanonicalEventToSeed(
          {
            type: EventType.OPERATOR_CANDIDATE_VOTE,
            timestamp: now,
            nonce,
            candidateId,
            voterId,
            vote: v,
            reason,
          },
          signatures
        );

        if (!r.ok) {
          res.status(502).json({ success: false, error: r.error || 'Failed to submit vote to seed' });
          return;
        }

        res.json({ success: true, candidateId, voterId, vote: v });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/operators/candidates/:candidateId/finalize', async (req: Request, res: Response) => {
      try {
        const sess = await this.requireOperatorSession(req, res);
        if (!sess) return;

        const callerId = this.getOperatorId();
        if (!callerId) {
          res.status(500).json({ success: false, error: 'OPERATOR_ID is not configured on this node' });
          return;
        }

        const candidateId = String(req.params.candidateId || '').trim();
        const state = await this.canonicalStateBuilder.buildState();
        const c: any = (state as any).operators?.get?.(candidateId);
        if (!c || String(c.status || '') !== 'candidate') {
          res.status(404).json({ success: false, error: 'Candidate not found' });
          return;
        }

        const eligibleVotingAt = Number(c.eligibleVotingAt || 0);
        if (eligibleVotingAt && Date.now() < eligibleVotingAt) {
          res.status(400).json({ success: false, error: 'Finalize not yet enabled (founder window still open)' });
          return;
        }

        const eligibleVoterIds = Array.isArray(c.eligibleVoterIds) ? (c.eligibleVoterIds as any[]).map((x) => String(x)) : [];
        const eligibleVoterCount = Number(c.eligibleVoterCount || (eligibleVoterIds.length || 0) || 0);
        const requiredYesVotes = Number(c.requiredYesVotes || 0) || (eligibleVoterCount > 0 ? Math.ceil((2 / 3) * eligibleVoterCount) : 0);

        const votesArr = Array.from((c.votes?.values?.() || []) as any[]);
        const countedVotes = eligibleVoterIds.length > 0
          ? votesArr.filter((v: any) => eligibleVoterIds.includes(String(v.voterId)))
          : votesArr;

        const approveVotes = countedVotes.filter((v: any) => String(v.vote) === 'approve').length;
        const rejectVotes = countedVotes.filter((v: any) => String(v.vote) === 'reject').length;

        let decision: 'approve' | 'reject' | null = null;
        if (requiredYesVotes > 0 && approveVotes >= requiredYesVotes) decision = 'approve';
        if (requiredYesVotes > 0 && rejectVotes >= requiredYesVotes) decision = 'reject';

        if (!decision) {
          res.status(409).json({
            success: false,
            error: 'Not enough votes to finalize',
            approveVotes,
            rejectVotes,
            eligibleVoterCount,
            requiredYesVotes,
          });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: callerId,
            publicKey: String(this.config.publicKey || ''),
            signature: createHash('sha256')
              .update(`OPERATOR_CANDIDATE_FINALIZED:${candidateId}:${decision}:${now}`)
              .digest('hex'),
          },
        ];

        const payload = decision === 'approve'
          ? {
              type: EventType.OPERATOR_ADMITTED,
              timestamp: now,
              nonce,
              operatorId: String(c.operatorId),
              btcAddress: String(c.btcAddress),
              publicKey: String(c.publicKey),
            }
          : {
              type: EventType.OPERATOR_REJECTED,
              timestamp: now,
              nonce,
              operatorId: String(c.operatorId),
              reason: 'operator_vote',
            };

        const r = await this.submitCanonicalEventToSeed(payload, signatures);
        if (!r.ok) {
          res.status(502).json({ success: false, error: r.error || 'Failed to submit finalize to seed' });
          return;
        }

        res.json({
          success: true,
          candidateId,
          decision,
          approveVotes,
          rejectVotes,
          eligibleVoterCount,
          requiredYesVotes,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

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

    this.app.get('/api/consensus/status', (req: Request, res: Response) => {
      const status = this.getConsensusStatus();
      res.json({ success: true, ...status });
    });

    this.app.get('/api/operator/status', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.get('/api/network/health', (req: Request, res: Response) => {
      const now = Date.now();
      const gateways = Array.from(this.gatewayConnections.entries()).map(([ws, conn]) => {
        const uptimeMs = now - conn.connectedAt;
        const timeSinceLastSeen = now - conn.lastSeen;
        const healthy = timeSinceLastSeen < 90000; // Healthy if seen in last 90 seconds
        return {
          connected: ws.readyState === 1,
          healthy,
          uptimeMs,
          timeSinceLastSeenMs: timeSinceLastSeen,
          ip: conn.ip
        };
      });

      res.json({
        success: true,
        mainSeedConnected: this.isConnectedToMain,
        mainSeedUptimeMs: this.isConnectedToMain ? 300000 : 0, // Placeholder
        gateways: {
          connected: gateways,
          total: gateways.length
        }
      });
    });

    this.app.get('/api/config/main-seed', (req: Request, res: Response) => {
      const httpBase = this.getSeedHttpBase();
      const wsUrl = String(this.config.mainSeedUrl || '').trim();
      res.json({
        success: true,
        mainSeedHttpUrl: httpBase || null,
        mainSeedWsUrl: wsUrl || null,
        isConnected: this.isConnectedToMain
      });
    });

    // Operator application (BITCOIN-STYLE: fully decentralized, ledger-first)
    // Challenge is created locally - no need to proxy to main seed
    // Events are created locally and broadcast via P2P to all peers
    this.app.post('/api/operators/apply/challenge', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        // Create challenge locally - Bitcoin-style: any node can accept applications
        const challengeId = `op_apply_${Date.now()}_${randomBytes(8).toString('hex')}`;
        const nonce = randomBytes(32).toString('hex');
        const createdAt = Date.now();
        const expiresAt = createdAt + 5 * 60 * 1000;

        this.operatorApplyChallenges.set(challengeId, {
          challengeId,
          accountId: String((account as any).accountId || ''),
          nonce,
          createdAt,
          expiresAt,
          used: false,
        });

        res.json({ success: true, challengeId, nonce, expiresAt });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/operators/apply', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const accountId = String((account as any).accountId || '').trim();
        const { challengeId, operatorId, publicKey, btcAddress, operatorUrl, signature } = req.body || {};

        if (!challengeId || !operatorId || !publicKey || !btcAddress || !operatorUrl || !signature) {
          res.status(400).json({
            success: false,
            error: 'Missing required fields: challengeId, operatorId, publicKey, btcAddress, operatorUrl, signature',
          });
          return;
        }

        const url = String(operatorUrl).trim();
        const isHttps = /^https:\/\//i.test(url);
        const isOnion = /^https?:\/\//i.test(url) && /\.onion(\/|$)/i.test(url);
        if (!isHttps && !isOnion) {
          res.status(400).json({ success: false, error: 'operatorUrl must start with https:// (or be an http(s)://*.onion URL)' });
          return;
        }

        const chall = this.operatorApplyChallenges.get(String(challengeId));
        if (!chall || chall.accountId !== accountId || chall.used || Date.now() > chall.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired challenge' });
          return;
        }

        const sigOk = verifySignature(String(chall.nonce), String(signature), String(publicKey));
        if (!sigOk) {
          res.status(401).json({ success: false, error: 'Invalid signature' });
          return;
        }
        chall.used = true;

        // Check if operatorId already exists in local state
        const state = await this.canonicalStateBuilder.buildState();
        const existing = (state as any).operators?.get?.(String(operatorId));
        if (existing) {
          res.status(409).json({ success: false, error: 'operatorId already exists' });
          return;
        }

        const now = Date.now();
        const eventNonce = randomBytes(32).toString('hex');

        // Get active operators for voting eligibility
        const ACTIVE_WINDOW_MS = 60 * 24 * 60 * 60 * 1000;
        const allOps = Array.from((state as any).operators?.values?.() || []) as any[];
        const activeOps = allOps.filter((o: any) => o && o.status === 'active');
        const eligibleVoterIds = activeOps
          .filter((o: any) => {
            const last = Number(o?.lastActiveAt || o?.lastHeartbeatAt || o?.admittedAt || 0);
            return last > 0 && (now - last) <= ACTIVE_WINDOW_MS;
          })
          .map((o: any) => String(o.operatorId || '').trim())
          .filter((id: string) => Boolean(id));

        const eligibleVoterCount = eligibleVoterIds.length;
        const requiredYesVotes = eligibleVoterCount > 0 ? Math.ceil((2 / 3) * eligibleVoterCount) : undefined;
        const eligibleVotingAt = now + 30 * 24 * 60 * 60 * 1000;

        // DECENTRALIZED CONSENSUS: Submit event through mempool
        // Event goes to local mempool → validated → broadcast to peers → checkpoint finalized
        // This works even if main seed is offline - true Bitcoin-style decentralization
        const eventPayload = {
          type: EventType.OPERATOR_CANDIDATE_REQUESTED,
          nonce: eventNonce,
          candidateId: String(operatorId),
          gatewayNodeId: String(url),
          operatorUrl: String(url),
          btcAddress: String(btcAddress).trim(),
          publicKey: String(publicKey).trim(),
          sponsorId: accountId,
          eligibleVoterIds,
          eligibleVoterCount,
          requiredYesVotes,
          eligibleVotingAt,
        };

        // Submit through consensus system
        const result = await this.submitConsensusEvent(
          EventType.OPERATOR_CANDIDATE_REQUESTED,
          eventPayload
        );

        if (result.success) {
          console.log(`[Operator] 📋 Submitted operator application to consensus: ${operatorId} (eventId: ${result.eventId})`);
          res.json({
            success: true,
            message: 'Operator application submitted to network consensus',
            candidateId: String(operatorId),
            operatorUrl: String(url),
            eventId: result.eventId,
          });
          return;
        }

        // Consensus submission failed - fall back to direct append for resilience
        console.log(`[Operator] ⚠️ Consensus failed (${result.error}), creating event locally for resilience`);
        
        const signatures: QuorumSignature[] = [
          {
            operatorId: this.config.operatorId,
            publicKey: this.config.publicKey,
            signature: createHash('sha256').update(`OPERATOR_CANDIDATE_REQUESTED:${operatorId}:${now}`).digest('hex'),
          },
        ];
        
        const event = await this.canonicalEventStore.appendEvent(eventPayload as any, signatures);

        console.log(`[Operator] 📋 Created OPERATOR_CANDIDATE_REQUESTED event locally: ${operatorId} (seq: ${event.sequenceNumber})`);

        // Broadcast to operator peers (they may be able to forward to main)
        this.broadcastToOperatorPeers({
          type: 'new_event',
          event: { ...event },
          sourceOperatorId: this.config.operatorId,
          timestamp: now,
        });

        this.broadcastRegistryUpdate();

        res.json({
          success: true,
          message: 'Operator application created locally (main seed offline)',
          candidateId: String(operatorId),
          operatorUrl: String(url),
          eventHash: event.eventHash,
          sequenceNumber: event.sequenceNumber,
          warning: 'Main seed offline - event created locally, will sync when connected',
        });
      } catch (error: any) {
        console.error('[Operator] Failed to process operator application:', error);
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/network/connections', async (req: Request, res: Response) => {
      try {
        // Proxy to main seed to get network data
        const base = this.getSeedHttpBase();
        if (!base) {
          return res.status(502).json({ 
            success: false, 
            error: 'No seed configured',
            mainSeedConnected: false,
            mainSeedUptimeMs: 0
          });
        }

        const targetUrl = `${base}${req.originalUrl}`;
        const authHeader = req.get('Authorization');
        const headers: Record<string, string> = authHeader ? { 'Authorization': authHeader } : {};
        
        const response = await fetch(targetUrl, { method: 'GET', headers });
        const data = await response.json();

        // Enhance with operator's own main seed connection status
        const enhancedData = {
          ...(typeof data === 'object' && data !== null ? data : {}),
          mainSeedConnected: this.isConnectedToMain,
          mainSeedUptimeMs: this.isConnectedToMain && this.state.lastSyncedAt ? Date.now() - this.state.lastSyncedAt : 0
        };

        res.json(enhancedData);
      } catch (error: any) {
        console.error('Failed to get network connections:', error);
        res.status(502).json({ 
          success: false, 
          error: error.message,
          mainSeedConnected: this.isConnectedToMain,
          mainSeedUptimeMs: 0
        });
      }
    });

    this.app.get('/api/operator/earnings', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.get('/seed-manifest.json', async (req: Request, res: Response) => {
      const protocol = String(req.protocol || 'http');
      const host = String(req.get('host') || '').trim();
      const baseUrl = host ? `${protocol}://${host}` : '';
      res.json({
        version: 1,
        timestamp: Date.now(),
        seeds: [
          {
            address: host || '',
            role: 'operator',
            services: {
              chainApi: baseUrl ? `${baseUrl}/api/chain` : '/api/chain',
            },
          },
        ],
        signatures: [],
        manifestHash: '',
      });
    });

    this.app.post('/api/auth/login', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.get('/api/auth/me', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

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

    this.app.get('/api/offers/user/:address', (req: Request, res: Response) => {
      const addr = String(req.params.address || '').trim();
      const offers = Array.from(this.state.settlements.values())
        .filter((s: any) => String(s?.buyer || '').trim() === addr)
        .sort((a: any, b: any) => Number(b?.initiatedAt || 0) - Number(a?.initiatedAt || 0))
        .map((s: any) => {
          const sats = Number(s?.price || 0);
          const platformFeeSats = this.calculatePlatformFee(sats);
          const sellerReceivesSats = sats - platformFeeSats;
          const feeSnap: any = (s as any)?.platformFeePayouts ? (s as any).platformFeePayouts : null;
          const sponsorAddr = this.getFeeAddress();
          const feeMainAddr = feeSnap?.mainNodeAddress ? String(feeSnap.mainNodeAddress).trim() : sponsorAddr;
          const feeMainAmt = feeSnap ? Number(feeSnap.mainNodeFeeSats || 0) : platformFeeSats;
          const feeOps = feeSnap ? (Array.isArray(feeSnap.operatorPayouts) ? feeSnap.operatorPayouts : []) : [];

          const paymentOutputs = [
            { address: String(s?.seller || '').trim(), amountSats: sellerReceivesSats },
            { address: feeMainAddr, amountSats: feeMainAmt },
            ...feeOps.map((p: any) => ({ address: String(p?.address || '').trim(), amountSats: Number(p?.amountSats || 0) })),
          ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

          return {
            offerId: String(s?.settlementId || ''),
            itemId: String(s?.itemId || ''),
            buyerAddress: String(s?.buyer || ''),
            sellerAddress: String(s?.seller || ''),
            sats,
            status: String(s?.status || ''),
            createdAt: Number(s?.initiatedAt || 0),
            expiresAt: Number(s?.expiresAt || 0),
            paymentTxid: (s as any)?.txid ? String((s as any).txid) : undefined,
            paymentAddress: (s as any)?.escrowAddress ? String((s as any).escrowAddress) : undefined,
            paymentOutputs,
            platformFeeSats,
            sellerReceivesSats,
            mainNodeFeeAddress: feeMainAddr,
          };
        });

      res.json({ offers, count: offers.length });
    });

    this.app.get('/api/offers/owner/:address', (req: Request, res: Response) => {
      const addr = String(req.params.address || '').trim();
      const offers = Array.from(this.state.settlements.values())
        .filter((s: any) => String(s?.seller || '').trim() === addr)
        .sort((a: any, b: any) => Number(b?.initiatedAt || 0) - Number(a?.initiatedAt || 0))
        .map((s: any) => {
          const sats = Number(s?.price || 0);
          const platformFeeSats = this.calculatePlatformFee(sats);
          const sellerReceivesSats = sats - platformFeeSats;
          const feeSnap: any = (s as any)?.platformFeePayouts ? (s as any).platformFeePayouts : null;
          const sponsorAddr = this.getFeeAddress();
          const feeMainAddr = feeSnap?.mainNodeAddress ? String(feeSnap.mainNodeAddress).trim() : sponsorAddr;
          const feeMainAmt = feeSnap ? Number(feeSnap.mainNodeFeeSats || 0) : platformFeeSats;
          const feeOps = feeSnap ? (Array.isArray(feeSnap.operatorPayouts) ? feeSnap.operatorPayouts : []) : [];
          const paymentOutputs = [
            { address: String(s?.seller || '').trim(), amountSats: sellerReceivesSats },
            { address: feeMainAddr, amountSats: feeMainAmt },
            ...feeOps.map((p: any) => ({ address: String(p?.address || '').trim(), amountSats: Number(p?.amountSats || 0) })),
          ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

          return {
            offerId: String(s?.settlementId || ''),
            itemId: String(s?.itemId || ''),
            buyerAddress: String(s?.buyer || ''),
            sellerAddress: String(s?.seller || ''),
            sats,
            status: String(s?.status || ''),
            createdAt: Number(s?.initiatedAt || 0),
            expiresAt: Number(s?.expiresAt || 0),
            paymentOutputs,
            platformFeeSats,
            sellerReceivesSats,
            mainNodeFeeAddress: feeMainAddr,
          };
        });

      res.json({ offers, count: offers.length });
    });

    this.app.get('/api/offers/item/:itemId', (req: Request, res: Response) => {
      const itemId = String(req.params.itemId || '').trim();
      const offers = Array.from(this.state.settlements.values())
        .filter((s: any) => String(s?.itemId || '').trim() === itemId)
        .sort((a: any, b: any) => Number(b?.initiatedAt || 0) - Number(a?.initiatedAt || 0))
        .map((s: any) => ({
          offerId: String(s?.settlementId || ''),
          itemId: String(s?.itemId || ''),
          buyerAddress: String(s?.buyer || ''),
          sellerAddress: String(s?.seller || ''),
          sats: Number(s?.price || 0),
          status: String(s?.status || ''),
          createdAt: Number(s?.initiatedAt || 0),
          expiresAt: Number(s?.expiresAt || 0),
        }));
      res.json({ offers, count: offers.length });
    });

    this.app.get('/api/offers/:offerId', (req: Request, res: Response) => {
      const offerId = String(req.params.offerId || '').trim();
      const s: any = this.state.settlements.get(offerId);
      if (!s) {
        res.status(404).json({ error: 'Offer not found' });
        return;
      }
      const sats = Number(s?.price || 0);
      const platformFeeSats = this.calculatePlatformFee(sats);
      const sellerReceivesSats = sats - platformFeeSats;
      const feeSnap: any = (s as any)?.platformFeePayouts ? (s as any).platformFeePayouts : null;
      const sponsorAddr = this.getFeeAddress();
      const feeMainAddr = feeSnap?.mainNodeAddress ? String(feeSnap.mainNodeAddress).trim() : sponsorAddr;
      const feeMainAmt = feeSnap ? Number(feeSnap.mainNodeFeeSats || 0) : platformFeeSats;
      const feeOps = feeSnap ? (Array.isArray(feeSnap.operatorPayouts) ? feeSnap.operatorPayouts : []) : [];
      const paymentOutputs = [
        { address: String(s?.seller || '').trim(), amountSats: sellerReceivesSats },
        { address: feeMainAddr, amountSats: feeMainAmt },
        ...feeOps.map((p: any) => ({ address: String(p?.address || '').trim(), amountSats: Number(p?.amountSats || 0) })),
      ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

      res.json({
        offerId: String(s?.settlementId || offerId),
        itemId: String(s?.itemId || ''),
        buyerAddress: String(s?.buyer || ''),
        sellerAddress: String(s?.seller || ''),
        sats,
        status: String(s?.status || ''),
        createdAt: Number(s?.initiatedAt || 0),
        expiresAt: Number(s?.expiresAt || 0),
        paymentOutputs,
        platformFeeSats,
        sellerReceivesSats,
        mainNodeFeeAddress: feeMainAddr,
      });
    });

    this.app.get('/api/chain/status', async (req: Request, res: Response) => {
      try {
        const net = this.getBitcoinNetwork();
        const apiBase = net === 'mainnet' ? 'https://blockstream.info/api' : 'https://blockstream.info/testnet/api';
        res.json({
          ok: true,
          network: net,
          apiBase,
          timestamp: Date.now(),
        });
      } catch (e: any) {
        res.status(500).json({ ok: false, error: e?.message || String(e) });
      }
    });

    this.app.get('/api/chain/address/:address', async (req: Request, res: Response) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          res.status(400).json({ error: 'Missing address' });
          return;
        }

        const bases = this.getChainApiBases();
        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const r = await fetch(`${apiBase}/address/${encodeURIComponent(address)}`);
            const t = await r.text();
            if (!r.ok) {
              lastErr = { status: r.status, text: t };
              continue;
            }
            res.type('application/json').send(t);
            return;
          } catch (err) {
            lastErr = err;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.get('/api/chain/address/:address/utxo', async (req: Request, res: Response) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          res.status(400).json({ error: 'Missing address' });
          return;
        }
        const net = this.getBitcoinNetwork();
        const apiBase = net === 'mainnet' ? 'https://blockstream.info/api' : 'https://blockstream.info/testnet/api';
        const r = await fetch(`${apiBase}/address/${encodeURIComponent(address)}/utxo`);
        const t = await r.text();
        if (!r.ok) {
          res.status(502).send(t);
          return;
        }
        res.type('application/json').send(t);
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.get('/api/chain/tx/:txid/status', async (req: Request, res: Response) => {
      try {
        const txid = String(req.params.txid || '').trim();
        if (!txid) {
          res.status(400).json({ error: 'Missing txid' });
          return;
        }
        const bases = this.getChainApiBases();
        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const statusResp = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/status`);
            const statusText = await statusResp.text();
            if (!statusResp.ok) {
              lastErr = { status: statusResp.status, text: statusText };
              continue;
            }

            const statusJson = JSON.parse(statusText);
            const confirmed = Boolean(statusJson?.confirmed);
            const blockHeight = confirmed ? Number(statusJson?.block_height || 0) : undefined;

            let tipHeight = 0;
            try {
              const tipResp = await fetch(`${apiBase}/blocks/tip/height`);
              const tipText = await tipResp.text();
              if (tipResp.ok) tipHeight = Number(String(tipText || '').trim());
            } catch {}

            const confirmations = confirmed && blockHeight && tipHeight && tipHeight >= blockHeight
              ? (tipHeight - blockHeight + 1)
              : 0;

            res.json({
              ok: true,
              confirmed,
              confirmations,
              blockHeight: blockHeight || undefined,
              blockHash: statusJson?.block_hash,
              blockTime: statusJson?.block_time,
              provider: apiBase,
            });
            return;
          } catch (err) {
            lastErr = err;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.get('/api/chain/tx/:txid/hex', async (req: Request, res: Response) => {
      try {
        const txid = String(req.params.txid || '').trim();
        if (!txid) {
          res.status(400).json({ error: 'Missing txid' });
          return;
        }
        const bases = this.getChainApiBases();
        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const r = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/hex`);
            const t = await r.text();
            if (!r.ok) {
              lastErr = { status: r.status, text: t };
              continue;
            }
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send(String(t || '').trim());
            return;
          } catch (err) {
            lastErr = err;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.get('/api/chain/fee-estimates', async (req: Request, res: Response) => {
      try {
        const bases = this.getChainApiBases();
        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const r = await fetch(`${apiBase}/fee-estimates`);
            const t = await r.text();
            if (!r.ok) {
              lastErr = { status: r.status, text: t };
              continue;
            }
            res.type('application/json').send(t);
            return;
          } catch (err) {
            lastErr = err;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.post('/api/chain/tx', async (req: Request, res: Response) => {
      try {
        let txHex = '';
        const asAny = req as any;
        if (asAny?.body && typeof asAny.body === 'object') {
          txHex = String(asAny.body.txHex || '');
        }
        txHex = txHex.trim();

        if (!txHex) {
          res.status(400).json({ success: false, error: 'Missing txHex' });
          return;
        }

        const bases = this.getChainApiBases();
        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const r = await fetch(`${apiBase}/tx`, {
              method: 'POST',
              headers: { 'Content-Type': 'text/plain' },
              body: txHex,
            });
            const t = await r.text();
            if (!r.ok) {
              lastErr = { status: r.status, text: t };
              continue;
            }
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send(String(t || '').trim());
            return;
          } catch (err) {
            lastErr = err;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.get('/api/consignments/item/:itemId', (req: Request, res: Response) => {
      const itemId = String(req.params.itemId || '').trim();
      if (!itemId) {
        res.status(400).json({ success: false, error: 'Missing itemId' });
        return;
      }

      const found = Array.from(this.state.consignments.values()).find((c: any) => String(c?.itemId || '').trim() === itemId);
      if (!found) {
        res.status(404).json({ success: false, error: 'Consignment not found' });
        return;
      }
      res.json({ success: true, consignment: found });
    });

    this.app.get('/api/qr.png', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/users/register', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.post('/api/offers/create', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/offers/:offerId/accept', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/offers/:offerId/cancel', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/offers/:offerId/payment-submitted', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/offers/:offerId/claim', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/offers/:offerId/counter', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.post('/api/consignments/create', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.get('/api/consignments/:consignmentId', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.get('/api/consignments/:consignmentId/checkout', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/consignments/:consignmentId/checkout/lock', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/consignments/:consignmentId/payment-submitted', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/consignments/:consignmentId/cancel/request', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/consignments/:consignmentId/cancel/confirm', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.all('/api/admin/*', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.all('/api/*', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.use((req: Request, res: Response) => {
      const p = String(req.path || '').trim();
      if (p.startsWith('/api')) {
        res.status(404).json({ error: 'Endpoint not found' });
        return;
      }
      res.status(404).send('Not Found');
    });
  }

  async start(): Promise<void> {
    if (!fs.existsSync(this.config.dataDir)) {
      fs.mkdirSync(this.config.dataDir, { recursive: true });
    }

    await this.loadPersistedState();

    try {
      await this.ensureUiCache();
    } catch {}

    this.httpServer = this.app.listen(this.config.port, () => {
      console.log(`[Operator] HTTP API: http://localhost:${this.config.port}`);
      console.log(`[Operator] Health: http://localhost:${this.config.port}/api/health`);
    });

    this.setupWebSocketServer();
    await this.connectToMainSeed();

    this.startPeerDiscovery();

    console.log('\n[Operator] Node is running!');
    console.log('[Operator] WebSocket server ready for gateway connections');
    console.log('[Operator] Press Ctrl+C to stop\n');
  }

  private setupWebSocketServer(): void {
    if (!this.httpServer) return;

    this.wss = new WebSocket.Server({ server: this.httpServer });

    this.wss.on('connection', (ws: WebSocket, req) => {
      const clientIp = req.socket.remoteAddress;
      const now = Date.now();

      console.log(`[Operator] Gateway connected from ${clientIp}`);

      this.gatewayConnections.set(ws, {
        connectedAt: now,
        lastSeen: now,
        ip: clientIp,
      });

      ws.on('message', (data: Buffer) => {
        try {
          const message = JSON.parse(data.toString());
          this.handleGatewayMessage(ws, message);
        } catch (error) {
          console.error('[Operator] Invalid message from gateway:', error);
        }
      });

      ws.on('close', () => {
        console.log(`[Operator] Gateway disconnected from ${clientIp}`);
        this.gatewayConnections.delete(ws);
      });

      ws.on('error', (error) => {
        console.error('[Operator] Gateway WebSocket error:', error);
        this.gatewayConnections.delete(ws);
      });
    });

    console.log(`[Operator] WebSocket server listening on port ${this.config.port}`);
  }

  private handleGatewayMessage(ws: WebSocket, message: any): void {
    const conn = this.gatewayConnections.get(ws);
    if (conn) {
      conn.lastSeen = Date.now();
    }

    switch (message.type) {
      case 'sync_request':
        console.log('[Operator] Gateway requesting sync');
        this.sendSyncResponse(ws);
        break;

      case 'subscribe_consensus':
        // Subscribe to real-time consensus updates (for mempool visualizer)
        const meta = this.gatewayConnections.get(ws);
        if (meta) {
          (meta as any).subscribedToConsensus = true;
        }
        
        // Send current consensus state
        if (this.consensusNode) {
          const consensusState = this.consensusNode.getState();
          const mempoolEvents = this.consensusNode.getMempoolEvents();
          
          ws.send(JSON.stringify({
            type: 'consensus_state',
            state: consensusState,
          }));
          
          ws.send(JSON.stringify({
            type: 'mempool_snapshot',
            events: mempoolEvents,
          }));
        }
        break;

      case 'operator_handshake':
        this.registerOperatorPeerFromIncoming(ws, message);
        break;

      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        break;

      default:
        console.log(`[Operator] Unknown message type from gateway: ${message.type}`);
    }
  }

  private sendSyncResponse(ws: WebSocket): void {
    if (ws.readyState !== WebSocket.OPEN) return;

    const syncData = this.getGatewaySyncData();

    ws.send(JSON.stringify({
      type: 'sync_response',
      data: syncData,
      timestamp: Date.now(),
    }));

    console.log('[Operator] Sent sync data to gateway');
  }

  private broadcastToGateways(message: any): void {
    this.gatewayConnections.forEach((conn, ws) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
      }
    });
  }

  private broadcastToOperatorPeers(message: any): void {
    for (const peer of this.operatorPeerConnections.values()) {
      try {
        if (peer.ws.readyState === WebSocket.OPEN) {
          peer.ws.send(JSON.stringify(message));
        }
      } catch {}
    }
  }

  private broadcastRegistryUpdate(): void {
    const data = this.getGatewaySyncData();
    const msg = { type: 'registry_update', data, timestamp: Date.now() };
    this.broadcastToGateways(msg);
    this.broadcastToOperatorPeers(msg);
  }

  private startPeerDiscovery(): void {
    if (this.peerDiscoveryTimer) return;

    const myOperatorId = this.getOperatorId();
    if (!myOperatorId) return;

    const base = this.getSeedHttpBase();
    if (!base) return;

    this.peerDiscovery = new OperatorPeerDiscovery({
      mainSeedHttpUrl: base,
      myOperatorId,
      discoveryIntervalMs: 5 * 60 * 1000,
    });

    const tick = async () => {
      try {
        const peers = await this.peerDiscovery!.discoverPeers();
        for (const p of peers) {
          const peerId = String(p?.operatorId || '').trim();
          if (!peerId || peerId === myOperatorId) continue;
          if (this.operatorPeerConnections.has(peerId)) continue;
          void this.connectToPeer(p);
        }
      } catch {
      }
    };

    void tick();
    this.peerDiscoveryTimer = setInterval(() => void tick(), 5 * 60 * 1000);
  }

  private async connectToPeer(peer: OperatorPeerInfo): Promise<void> {
    const myOperatorId = this.getOperatorId();
    const peerId = String(peer?.operatorId || '').trim();
    const wsUrl = String(peer?.wsUrl || '').trim();
    if (!myOperatorId || !peerId || !wsUrl) return;
    if (this.operatorPeerConnections.has(peerId)) return;

    const ws = connectToOperatorPeer(
      peer,
      myOperatorId,
      (message: any) => void this.handleOperatorPeerMessage(peerId, message),
      () => {
        this.operatorPeerConnections.delete(peerId);
      }
    );

    this.operatorPeerConnections.set(peerId, {
      ws,
      operatorId: peerId,
      wsUrl,
      connectedAt: Date.now(),
      lastSeen: Date.now(),
    });
  }

  private async handleOperatorPeerMessage(peerId: string, message: any): Promise<void> {
    const meta = this.operatorPeerConnections.get(peerId);
    if (meta) meta.lastSeen = Date.now();
    const ws = meta?.ws;

    switch (message?.type) {
      case 'operator_handshake_ack':
        break;

      case 'state_verification':
        try {
          if (!this.heartbeatManager) break;
          const response = this.heartbeatManager.handleVerificationMessage(message);
          if (response && ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(response));
          }
        } catch {}
        break;

      case 'verification_response':
        this.handleVerificationResponse(message);
        break;

      case 'sync_request':
        try {
          if (!ws || ws.readyState !== WebSocket.OPEN) break;
          const lastSequence = Math.floor(Number(message?.lastSequence || 0));
          const storeState = this.canonicalEventStore.getState();
          const headSeq = Math.floor(Number(storeState.sequenceNumber || 0));
          const fromSeq = Math.max(1, lastSequence + 1);
          const toSeq = headSeq;

          const events = fromSeq <= toSeq
            ? await this.canonicalEventStore.getEventsBySequence(fromSeq, toSeq)
            : [];

          ws.send(JSON.stringify({
            type: 'sync_data',
            operatorId: this.getOperatorId(),
            networkId: this.computeNetworkId(),
            events,
            timestamp: Date.now(),
          }));
        } catch {}
        break;

      case 'sync_data':
        await this.handleSyncData(message);
        break;

      case 'registry_update':
        try {
          const remoteSeq = Number(message?.data?.sequenceNumber || 0);
          if (remoteSeq && remoteSeq > this.state.lastSyncedSequence && ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
              type: 'sync_request',
              operatorId: this.getOperatorId(),
              networkId: this.computeNetworkId(),
              lastSequence: this.state.lastSyncedSequence,
              timestamp: Date.now(),
              reason: 'registry_update',
            }));
          }
        } catch {}
        break;

      // BITCOIN-STYLE: Handle new_event messages from other operators
      // When an operator creates an event, it broadcasts to all peers
      // Each peer appends to their local ledger and re-broadcasts
      case 'new_event':
        try {
          const sourceOperatorId = String(message?.sourceOperatorId || '').trim();
          const eventData = message?.event;

          if (!eventData || typeof eventData !== 'object') {
            console.log(`[Operator] Invalid new_event payload from peer`);
            break;
          }

          // Check if we already have this event (by nonce or hash)
          const existingState = this.canonicalEventStore.getState();
          const eventNonce = String(eventData.nonce || eventData.payload?.nonce || '');
          
          // Try to append the event to our ledger
          const payload = {
            type: eventData.type || eventData.payload?.type,
            timestamp: eventData.timestamp || eventData.payload?.timestamp,
            nonce: eventNonce,
            candidateId: eventData.candidateId || eventData.payload?.candidateId,
            gatewayNodeId: eventData.gatewayNodeId || eventData.payload?.gatewayNodeId,
            operatorUrl: eventData.operatorUrl || eventData.payload?.operatorUrl,
            btcAddress: eventData.btcAddress || eventData.payload?.btcAddress,
            publicKey: eventData.publicKey || eventData.payload?.publicKey,
            sponsorId: eventData.sponsorId || eventData.payload?.sponsorId,
            eligibleVoterIds: eventData.eligibleVoterIds || eventData.payload?.eligibleVoterIds,
            eligibleVoterCount: eventData.eligibleVoterCount || eventData.payload?.eligibleVoterCount,
            requiredYesVotes: eventData.requiredYesVotes || eventData.payload?.requiredYesVotes,
            eligibleVotingAt: eventData.eligibleVotingAt || eventData.payload?.eligibleVotingAt,
          };
          const signatures = Array.isArray(eventData.signatures) ? eventData.signatures : [];

          console.log(`[Operator] 📥 Received new_event from peer ${sourceOperatorId}: ${payload.type}`);

          const event = await this.canonicalEventStore.appendEvent(payload as any, signatures as any);
          
          console.log(`[Operator] ✅ Appended event from peer ${sourceOperatorId}: ${event.eventHash} (seq: ${event.sequenceNumber})`);

          // Re-broadcast to other peers (gossip protocol)
          // But don't send back to the source
          for (const [peerId, peer] of this.operatorPeerConnections.entries()) {
            if (peerId !== sourceOperatorId && peer.ws.readyState === WebSocket.OPEN) {
              try {
                peer.ws.send(JSON.stringify({
                  type: 'new_event',
                  event: { ...event },
                  sourceOperatorId: this.config.operatorId,
                  timestamp: Date.now(),
                }));
              } catch {}
            }
          }

          // Also broadcast registry update
          this.broadcastRegistryUpdate();

          // Send ack back
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
              type: 'new_event_ack',
              ok: true,
              eventHash: event.eventHash,
              sequenceNumber: event.sequenceNumber,
            }));
          }
        } catch (e: any) {
          // Event might already exist or be invalid - that's ok
          if (!String(e?.message || '').includes('already exists')) {
            console.log(`[Operator] Could not append new_event from peer:`, e?.message);
          }
        }
        break;

      case 'new_event_ack':
        // Acknowledgment from peer that they received our event
        break;

      // CONSENSUS MESSAGES - Route to consensus node
      case 'mempool_event':
        if (this.consensusNode) {
          await this.consensusNode.handleIncomingEvent(message.payload, peerId);
        }
        break;

      case 'checkpoint_proposal':
        if (this.consensusNode) {
          await this.consensusNode.handleMessage(message, peerId);
        }
        break;

      case 'checkpoint_vote':
        if (this.consensusNode) {
          await this.consensusNode.handleMessage(message, peerId);
        }
        break;

      case 'checkpoint_finalized':
        if (this.consensusNode) {
          await this.consensusNode.handleMessage(message, peerId);
        }
        break;

      case 'ping':
        try {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
          }
        } catch {}
        break;
      default:
        break;
    }
  }

  private registerOperatorPeerFromIncoming(ws: WebSocket, message: any): void {
    const peerId = String(message?.operatorId || '').trim();
    if (!peerId) return;

    this.gatewayConnections.delete(ws);

    if (!this.operatorPeerConnections.has(peerId)) {
      this.operatorPeerConnections.set(peerId, {
        ws,
        operatorId: peerId,
        wsUrl: '',
        connectedAt: Date.now(),
        lastSeen: Date.now(),
      });
    }

    try {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'operator_handshake_ack',
          operatorId: this.getOperatorId(),
          timestamp: Date.now(),
        }));
      }
    } catch {}
  }

  async stop(): Promise<void> {
    console.log('[Operator] Stopping...');

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    if (this.peerDiscoveryTimer) {
      clearInterval(this.peerDiscoveryTimer);
      this.peerDiscoveryTimer = undefined;
    }

    for (const peer of this.operatorPeerConnections.values()) {
      try { peer.ws.close(); } catch {}
    }
    this.operatorPeerConnections.clear();

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
        this.lastMainNodeHeartbeat = Date.now();

        // Send sync request
        this.mainSeedWs!.send(JSON.stringify({
          type: 'sync_request',
          operatorId: this.config.operatorId,
          networkId: this.computeNetworkId(),
          lastSequence: this.state.lastSyncedSequence,
          timestamp: Date.now()
        }));
        
        // Start consensus verification
        this.startConsensusVerification();
      });

      this.mainSeedWs.on('message', async (data: WebSocket.Data) => {
        try {
          const message = JSON.parse(data.toString());
          
          // Handle consensus verification messages
          if (message.type === 'state_verification') {
            this.handleStateVerification(message);
            return;
          }
          
          if (message.type === 'verification_response') {
            this.handleVerificationResponse(message);
            return;
          }
          
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
        this.broadcastRegistryUpdate();
        break;
      case 'new_event':
        await this.handleNewEvent(message.event);
        this.broadcastRegistryUpdate();
        break;
      case 'registry_update':
        try {
          const remoteSeq = Number(message?.data?.sequenceNumber || 0);
          if (remoteSeq && remoteSeq > this.state.lastSyncedSequence) {
            this.mainSeedWs?.send(JSON.stringify({
              type: 'sync_request',
              operatorId: this.config.operatorId,
              networkId: this.computeNetworkId(),
              lastSequence: this.state.lastSyncedSequence,
              timestamp: Date.now(),
              reason: 'registry_update',
            }));
          }
        } catch {}
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
      const expectedNet = this.computeNetworkId();
      const remoteNet = String(message?.networkId || '').trim();
      if (!remoteNet || remoteNet !== expectedNet) {
        console.error('[Operator] Network mismatch - refusing to sync');
        console.error(`[Operator] expectedNetworkId=${expectedNet}`);
        console.error(`[Operator] receivedNetworkId=${remoteNet || '(missing)'}`);
        console.error(`[Operator] bitcoinNetwork=${this.getBitcoinNetwork()}`);
        console.error(`[Operator] feeAddress=${this.getFeeAddress()}`);
        this.isConnectedToMain = false;
        try { this.mainSeedWs?.close(); } catch {}
        return;
      }

      console.log(`[Operator] Syncing events from main node...`);

      const { events } = message;

      if (Array.isArray(events) && events.length > 0) {
        const storeState = this.canonicalEventStore.getState();
        const currentSeq = Number(storeState.sequenceNumber || 0);

        const ordered = [...events].sort((a: any, b: any) => Number(a.sequenceNumber || 0) - Number(b.sequenceNumber || 0));
        for (const ev of ordered) {
          const seq = Number(ev?.sequenceNumber || 0);
          if (!seq || seq <= currentSeq) continue;
          await this.canonicalEventStore.appendExistingEvent(ev);
        }
      }

      await this.rebuildLocalStateFromCanonical();

      console.log(`[Operator] Sync complete. Accounts: ${this.state.accounts.size}, Items: ${this.state.items.size}`);

      await this.persistState();
      this.consecutiveSyncFailures = 0;

      this.broadcastRegistryUpdate();
    } catch (error: any) {
      console.error('[Operator] Sync error:', error.message);
      if (String(error?.message || '').includes('Invalid event hash')) {
        this.consecutiveSyncFailures++;
        if (this.consecutiveSyncFailures >= 3) {
          console.log('[Operator] 🔄 Resetting event store after 3 consecutive sync failures...');
          await this.resetEventStore();
          this.consecutiveSyncFailures = 0;
        }
      }
    } finally {
      this.syncInProgress = false;
    }
  }

  private async resetEventStore(): Promise<void> {
    try {
      const fs = require('fs');
      const path = require('path');
      const eventsDir = path.join(this.config.dataDir, 'events');
      const stateFile = path.join(this.config.dataDir, 'event-store-state.json');
      
      if (fs.existsSync(eventsDir)) {
        const files = fs.readdirSync(eventsDir);
        for (const file of files) {
          fs.unlinkSync(path.join(eventsDir, file));
        }
      }
      
      if (fs.existsSync(stateFile)) {
        fs.unlinkSync(stateFile);
      }
      
      this.canonicalEventStore = new (require('./event-store').EventStore)(this.config.dataDir);
      this.canonicalStateBuilder = new (require('./event-store').StateBuilder)(this.canonicalEventStore);
      
      this.state.lastSyncedSequence = 0;
      this.state.lastSyncedHash = '';
      this.state.lastSyncedAt = 0;
      
      console.log('[Operator] ✅ Event store reset complete - will resync from main node');
    } catch (err: any) {
      console.error('[Operator] Failed to reset event store:', err.message);
    }
  }

  private async handleNewEvent(event: any): Promise<void> {
    try {
      if (event && event.eventHash && event.sequenceNumber) {
        await this.canonicalEventStore.appendExistingEvent(event);
      }
      await this.rebuildLocalStateFromCanonical();
      await this.persistState();
      this.broadcastRegistryUpdate();
    } catch (e: any) {
      console.error('[Operator] Failed to apply new event:', e?.message || String(e));
    }
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
        this.state.lastSyncedHash = String(parsed.lastSyncedHash || '');
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
        lastSyncedAt: this.state.lastSyncedAt,
        lastSyncedHash: this.state.lastSyncedHash
      };
      fs.writeFileSync(statePath, JSON.stringify(data, null, 2));
    } catch (error: any) {
      console.error('[Operator] Failed to persist state:', error.message);
    }
  }

  private computeEmailHash(email: string): string {
    return createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
  }

  private async verifyPassword(password: string, storedHash: string, kdf?: any): Promise<boolean> {
    try {
      const computedHash = kdf
        ? pbkdf2Sync(password, Buffer.from(kdf.saltB64, 'base64'), kdf.iterations, 32, 'sha256').toString('hex')
        : createHash('sha256').update(password).digest('hex');
      
      const a = Buffer.from(computedHash, 'hex');
      const b = Buffer.from(storedHash, 'hex');
      if (a.length !== b.length) return false;
      return timingSafeEqual(a, b);
    } catch {
      return false;
    }
  }

  private randomHex(bytes: number): string {
    return randomBytes(bytes).toString('hex');
  }

  // Consensus Integration Methods
  private startConsensusVerification(): void {
    if (this.heartbeatManager) return;

    this.heartbeatManager = new HeartbeatManager({
      intervalMs: 60000,
      consensusThreshold: 0.6667,
      maxDivergenceTime: 300000
    });

    this.heartbeatManager.on('consensus_achieved', (result: any) => {
      console.log(`[Consensus] âœ… ${result.agreementPercentage.toFixed(1)}% agreement`);
    });

    this.heartbeatManager.on('out_of_consensus', async (data: any) => {
      console.log(`[Consensus] âš ï¸ Out of consensus - requesting sync`);
      if (this.mainSeedWs && this.mainSeedWs.readyState === WebSocket.OPEN) {
        this.mainSeedWs.send(JSON.stringify({
          type: 'sync_request',
          operatorId: this.config.operatorId,
          networkId: this.computeNetworkId(),
          timestamp: Date.now(),
          reason: 'out_of_consensus'
        }));
      } else {
        this.broadcastToOperatorPeers({
          type: 'sync_request',
          operatorId: this.getOperatorId(),
          networkId: this.computeNetworkId(),
          lastSequence: this.state.lastSyncedSequence,
          timestamp: Date.now(),
          reason: 'out_of_consensus',
        });
      }
    });

    this.heartbeatManager.start(
      this.config.operatorId,
      async () => await this.getCurrentLedgerState(),
      (message: any) => this.sendVerificationToNetwork(message)
    );

    console.log('[Consensus] Started verification (60s interval)');
  }

  private async getCurrentLedgerState(): Promise<LedgerState> {
    return {
      sequenceNumber: this.state.lastSyncedSequence,
      lastEventHash: this.state.lastSyncedHash,
      itemsCount: this.state.items.size,
      settlementsCount: this.state.settlements.size,
      accountsCount: this.state.accounts.size,
      operatorsCount: this.state.operators.size,
      timestamp: Date.now()
    };
  }

  private handleStateVerification(message: any): void {
    if (message.nodeId === 'main-node') {
      this.lastMainNodeHeartbeat = Date.now();
    }

    if (!this.heartbeatManager) return;

    const response = this.heartbeatManager.handleVerificationMessage(message);
    if (response && this.mainSeedWs && this.mainSeedWs.readyState === WebSocket.OPEN) {
      this.mainSeedWs.send(JSON.stringify(response));
    }
  }

  private handleVerificationResponse(message: any): void {
    if (this.heartbeatManager) {
      this.heartbeatManager.handleVerificationMessage({
        type: 'state_verification',
        stateHash: message.stateHash,
        sequenceNumber: message.sequenceNumber,
        timestamp: message.timestamp,
        nodeId: message.nodeId
      });
    }
  }

  private sendVerificationToNetwork(message: any): void {
    if (this.mainSeedWs && this.mainSeedWs.readyState === WebSocket.OPEN) {
      this.mainSeedWs.send(JSON.stringify(message));
    }
    this.broadcastToOperatorPeers(message);
  }

  getConsensusStatus(): any {
    if (!this.heartbeatManager) {
      return { enabled: false, consensusAchieved: false };
    }

    const result = this.heartbeatManager.getConsensusStatus();
    const timeSinceLast = this.heartbeatManager.getTimeSinceLastVerification();

    return {
      enabled: true,
      lastVerification: Date.now() - timeSinceLast,
      consensusAchieved: result?.isConsensus || false,
      agreementPercentage: result?.agreementPercentage || 0,
      totalNodes: result?.totalNodes || 0,
      mainNodeAlive: Date.now() - this.lastMainNodeHeartbeat < 180000
    };
  }
}

