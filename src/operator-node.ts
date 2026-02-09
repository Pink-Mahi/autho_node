import express, { Express, Request, Response } from 'express';
import * as http from 'http';
import WebSocket from 'ws';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import { createHash, pbkdf2Sync, timingSafeEqual, randomBytes } from 'crypto';
import { HeartbeatManager } from './consensus/heartbeat-manager';
import { StateVerifier, LedgerState } from './consensus/state-verifier';
import { PeerResilienceManager, autoRepairFromMajority } from './consensus/peer-resilience';
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
import { ItemSearchEngine, hashImage, verifyImageHash } from './search';
import { ItemProvenanceService } from './provenance';
import { EntityRegistry, EntityType, EntityCategory, GlobalEntity } from './registry/entity-registry';
import { BitcoinTransactionService } from './bitcoin/transaction-service';
import { EphemeralEventStore, EphemeralEventType, EphemeralEvent, MessagePayload, ContactPayload, GroupPayload, GroupMessagePayload, GroupMemberPayload } from './messaging';

interface OperatorConfig {
  operatorId: string;
  publicKey: string;
  privateKey: string;
  btcAddress: string;
  /** Bitcoin wallet private key (from user's seed phrase) - separate from operator signing key */
  btcPrivateKey?: string;
  /** Primary seed URL - can be ANY active operator in the network */
  mainSeedUrl: string;
  /** Fallback seed URLs - tried if primary fails */
  fallbackSeedUrls?: string[];
  /** This operator's public URL for network discovery (e.g., https://autho.example.com) */
  operatorUrl?: string;
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
  roleApplications: Map<string, any>;
  checkpoints: Map<string, any>;
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
  private gatewayConnections: Map<
    WebSocket,
    {
      connectedAt: number;
      lastSeen: number;
      ip?: string;
      isGateway?: boolean;
      isUi?: boolean;
      subscribedToConsensus?: boolean;
    }
  > = new Map();
  private operatorPeerConnections: Map<string, { ws: WebSocket; operatorId: string; wsUrl: string; connectedAt: number; lastSeen: number }> = new Map();
  // Public gateway registry - gateways can register to be discoverable by other gateways
  private publicGatewayRegistry: Map<string, { 
    gatewayId: string; 
    httpUrl: string; 
    wsUrl: string; 
    registeredAt: number; 
    lastHeartbeat: number;
    version?: string;
  }> = new Map();
  private peerDiscoveryTimer?: NodeJS.Timeout;
  private peerDiscovery?: OperatorPeerDiscovery;
  private heartbeatManager?: HeartbeatManager;
  private peerResilienceManager?: PeerResilienceManager;
  private lastMainNodeHeartbeat: number = Date.now();
  private operatorHeartbeatTimer: any;
  /** Index of current seed being tried (for fallback rotation) */
  private currentSeedIndex: number = 0;
  /** All available seed URLs (primary + fallbacks + discovered peers) */
  private allSeedUrls: string[] = [];
  /** Last successful seed URL */
  private lastSuccessfulSeedUrl?: string;

  private sessions: Map<string, { sessionId: string; accountId: string; createdAt: number; expiresAt: number }> = new Map();
  private operatorApplyChallenges: Map<string, { challengeId: string; accountId: string; nonce: string; createdAt: number; expiresAt: number; used: boolean }> = new Map();

  private messagingEncryptionKeyRegistry: Map<string, { encryptionPublicKeyHex: string; updatedAt: number }> = new Map();

  // Decentralized consensus components
  private consensusNode?: ConsensusNode;
  private stateProviderAdapter?: StateProviderAdapter;
  
  // Item search engine for ledger lookups
  private itemSearchEngine?: ItemSearchEngine;
  
  // Item provenance service for history tracking
  private itemProvenanceService?: ItemProvenanceService;
  
  // Global entity registry for manufacturers, artists, athletes, etc.
  private entityRegistry?: EntityRegistry;
  
  // Ephemeral messaging store (parallel ledger with auto-pruning)
  private ephemeralStore?: EphemeralEventStore;

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
      roleApplications: new Map(),
      checkpoints: new Map(),
      lastSyncedSequence: 0,
      lastSyncedAt: 0,
      lastSyncedHash: ''
    };

    // Initialize ephemeral messaging store
    this.ephemeralStore = new EphemeralEventStore({
      dataDir: path.join(this.config.dataDir, 'messaging'),
    });

    // Replicate messaging encryption public keys across operator peers
    this.ephemeralStore.on(EphemeralEventType.MESSAGING_KEY_PUBLISHED, (event: EphemeralEvent) => {
      try {
        this.applyMessagingKeyPublishedEvent(event);
      } catch {}
    });

    // Rehydrate key registry from persisted message ledger on startup
    try {
      this.rebuildMessagingKeyRegistryFromLedger();
    } catch {}

    this.setupMiddleware();
    this.setupRoutes();

    this.startOperatorHeartbeat();
    this.initializeConsensus();
    this.initializePeerResilience();
  }

  private applyMessagingKeyPublishedEvent(event: EphemeralEvent): void {
    const p: any = event?.payload || {};
    const accountId = String(p?.accountId || '').trim();
    const walletAddress = String(p?.walletAddress || '').trim();
    const walletPublicKey = String(p?.walletPublicKey || '').trim().toLowerCase();
    const encryptionPublicKeyHex = String(p?.encryptionPublicKeyHex || '').trim().toLowerCase();
    const updatedAt = Number(p?.updatedAt || event?.timestamp || Date.now());

    if (!accountId) return;
    if (!/^[0-9a-f]{64}$/.test(encryptionPublicKeyHex)) return;

    this.messagingEncryptionKeyRegistry.set(accountId, { encryptionPublicKeyHex, updatedAt });
    if (walletAddress) {
      this.messagingEncryptionKeyRegistry.set(walletAddress, { encryptionPublicKeyHex, updatedAt });
    }
    // Also index by wallet publicKey - this is what the client uses to look up recipients
    if (walletPublicKey && /^[0-9a-f]{64,66}$/.test(walletPublicKey)) {
      this.messagingEncryptionKeyRegistry.set(walletPublicKey, { encryptionPublicKeyHex, updatedAt });
    }
  }

  private rebuildMessagingKeyRegistryFromLedger(): void {
    if (!this.ephemeralStore) return;
    const events = this.ephemeralStore.getAllEvents();
    for (const e of events) {
      if (e?.eventType === EphemeralEventType.MESSAGING_KEY_PUBLISHED) {
        this.applyMessagingKeyPublishedEvent(e);
      }
    }
  }

  /**
   * Initialize peer resilience for 250-year stability
   */
  private initializePeerResilience(): void {
    const myOperatorId = this.config.operatorId;
    if (!myOperatorId) return;

    this.peerResilienceManager = new PeerResilienceManager({
      myOperatorId,
      healthCheckIntervalMs: 30000, // 30 seconds
      peerTimeoutMs: 120000, // 2 minutes
      mainNodeFailoverDelayMs: 300000, // 5 minutes before electing backup leader
      minPeersForConsensus: 2,
      isMainNode: false, // Will be determined dynamically
    });

    // Handle main node going offline
    this.peerResilienceManager.on('main_node_offline', () => {
      console.log('[Operator] 🔄 Main node offline - will sync from peers');
      this.requestSyncFromBestPeer();
    });

    // Handle leader election
    this.peerResilienceManager.on('leader_elected', (result: any) => {
      console.log(`[Operator] 🗳️ New leader elected: ${result.leaderId}`);
      if (result.leaderId === myOperatorId) {
        console.log('[Operator] ✅ I am now the backup leader - accepting new events');
      }
    });

    // Handle consistency issues
    this.peerResilienceManager.on('consistency_issue', async (report: any) => {
      console.log(`[Operator] ⚠️ Consistency issue - ${report.divergentPeers.length} divergent peers`);
      // Auto-repair by syncing from majority
      await autoRepairFromMajority(this.peerResilienceManager!, async (peerId, fromSeq) => {
        await this.requestSyncFromPeer(peerId, fromSeq);
      });
    });

    // Start the resilience manager
    this.peerResilienceManager.start();
  }

  /**
   * Request sync from the best available peer
   */
  private async requestSyncFromBestPeer(): Promise<void> {
    if (!this.peerResilienceManager) return;

    const syncStatus = this.peerResilienceManager.needsSync();
    if (!syncStatus.needsSync || !syncStatus.syncFrom) {
      return;
    }

    console.log(`[Operator] Requesting sync from peer ${syncStatus.syncFrom.operatorId} (behind by ${syncStatus.behindBy} events)`);
    await this.requestSyncFromPeer(syncStatus.syncFrom.operatorId, this.state.lastSyncedSequence);
  }

  /**
   * Request sync from a specific peer
   */
  private async requestSyncFromPeer(peerId: string, fromSequence: number): Promise<void> {
    const peer = this.operatorPeerConnections.get(peerId);
    if (!peer || peer.ws.readyState !== WebSocket.OPEN) {
      console.log(`[Operator] Cannot sync from peer ${peerId} - not connected`);
      return;
    }

    peer.ws.send(JSON.stringify({
      type: 'sync_request',
      operatorId: this.config.operatorId,
      networkId: this.computeNetworkId(),
      lastSequence: fromSequence,
      timestamp: Date.now(),
      reason: 'peer_resilience',
    }));
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
   * Update consensus node with active operators from state
   */
  private async updateConsensusOperators(): Promise<void> {
    if (!this.consensusNode) return;

    try {
      const state = await this.canonicalStateBuilder.buildState();
      const operators = Array.from((state as any).operators?.values?.() || []) as any[];
      
      const activeOperators = operators
        .filter((op: any) => op && op.status === 'active')
        .map((op: any) => ({
          operatorId: String(op.operatorId || ''),
          status: 'active' as const,
          publicKey: String(op.publicKey || ''),
        }));

      this.consensusNode.updateOperators(activeOperators);
      console.log(`[Consensus] Updated with ${activeOperators.length} active operators`);
    } catch (error: any) {
      console.error('[Consensus] Failed to update operators:', error.message);
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
    this.state.roleApplications = (state as any).roleApplications || new Map();
    this.state.checkpoints = (state as any).checkpoints || new Map();
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

  private async requireOperatorSession(req: Request, res: Response): Promise<{ accountId: string; operatorId: string; operatorPublicKey: string } | null> {
    const sess = this.requireSession(req, res);
    if (!sess) return null;
    const state = await this.canonicalStateBuilder.buildState();
    const accountId = String(sess.accountId || '').trim();
    if (!accountId) {
      res.status(401).json({ success: false, error: 'Invalid session' });
      return null;
    }

    const ops = Array.from((state as any)?.operators?.values?.() || []) as any[];
    const matchingOperator = ops.find((o: any) =>
      o && String(o.status || '') === 'active' &&
      (String(o.publicKey || '') === accountId || String(o.sponsorId || '') === accountId)
    );

    if (!matchingOperator) {
      res.status(403).json({ success: false, error: 'Operator role required' });
      return null;
    }

    return { 
      accountId, 
      operatorId: String(matchingOperator.operatorId || ''),
      operatorPublicKey: String(matchingOperator.publicKey || ''),
    };
  }

  private async submitCanonicalEventToSeed(payload: any, signatures: QuorumSignature[]): Promise<{ ok: boolean; error?: string }>{
    // Helper to send to a specific WebSocket and wait for ack
    const sendAndWait = (ws: WebSocket, label: string): Promise<{ ok: boolean; error?: string }> => {
      return new Promise((resolve) => {
        const requestId = `append_${Date.now()}_${randomBytes(8).toString('hex')}`;
        
        const timeout = setTimeout(() => {
          try { ws.off?.('message', onMessage as any); } catch {}
          resolve({ ok: false, error: `Timeout waiting for ${label} ack` });
        }, 15000);

        const onMessage = (raw: WebSocket.Data) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (!msg || msg.type !== 'append_event_ack') return;
            if (String(msg.requestId || '') !== requestId) return;
            clearTimeout(timeout);
            try { ws.off?.('message', onMessage as any); } catch {}
            resolve({ ok: Boolean(msg.ok), error: msg.error ? String(msg.error) : undefined });
          } catch {}
        };

        try { ws.on?.('message', onMessage as any); } catch {}

        ws.send(JSON.stringify({
          type: 'append_event',
          requestId,
          payload,
          signatures,
          operatorId: this.getOperatorId(),
          timestamp: Date.now(),
        }));
      });
    };

    try {
      // Try main seed first
      const mainWs = this.mainSeedWs;
      if (mainWs && mainWs.readyState === WebSocket.OPEN) {
        const result = await sendAndWait(mainWs, 'main seed');
        if (result.ok) return result;
        console.warn(`[Operator] Main seed failed: ${result.error}, trying peer operators...`);
      }

      // Fallback: try peer operators (for resilience when main node is offline)
      for (const [peerId, peer] of this.operatorPeerConnections) {
        if (peer.ws.readyState === WebSocket.OPEN) {
          try {
            const result = await sendAndWait(peer.ws, `peer ${peerId}`);
            if (result.ok) {
              console.log(`[Operator] Event accepted by peer ${peerId}`);
              return result;
            }
          } catch {}
        }
      }

      return { ok: false, error: 'No available nodes to accept event (main seed and all peers offline)' };
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
    this.app.use(express.json({ limit: '100mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '100mb' }));

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
    this.app.get('/m/register-item', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-register-item.html');
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
    this.app.get('/m/search', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-search.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/messages', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-messages.html');
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
      // Derive address from private key to help debug mismatches
      let derivedAddress = '';
      try {
        const btcService = new BitcoinTransactionService(this.config.network || 'mainnet');
        derivedAddress = btcService.getAddressFromPrivateKey(this.config.privateKey);
      } catch (e) {
        derivedAddress = 'ERROR_DERIVING';
      }
      
      res.json({
        operatorId: this.config.operatorId,
        publicKey: this.config.publicKey,
        btcAddress: this.config.btcAddress,
        derivedBtcAddress: derivedAddress,
        addressMatch: this.config.btcAddress === derivedAddress,
        network: this.config.network,
        name: this.config.operatorName,
        description: this.config.operatorDescription,
        connectedToNetwork: this.isConnectedToMain
      });
    });

    // LEDGER HEALTH - comprehensive ledger metrics for operators
    this.app.get('/api/operator/ledger-health', async (req: Request, res: Response) => {
      try {
        const events = await this.canonicalEventStore.getAllEvents();
        const state = await this.canonicalStateBuilder.buildState();
        
        // Get latest event info
        const latestEvent = events.length > 0 ? events[events.length - 1] : null;
        const latestEventHash = latestEvent ? String((latestEvent as any).hash || (latestEvent as any).eventHash || '').substring(0, 16) : '';
        const latestEventTimestamp = latestEvent ? Number((latestEvent as any).timestamp || 0) : 0;
        
        // Count checkpoints and anchors
        const checkpoints = events.filter((e: any) => e?.payload?.type === 'CHECKPOINT_CREATED');
        const anchors = events.filter((e: any) => e?.payload?.type === 'ANCHOR_COMMITTED');
        const anchoredRoots = new Set(anchors.map((a: any) => String(a?.payload?.checkpointRoot || '')));
        const anchoredCheckpoints = checkpoints.filter((c: any) => anchoredRoots.has(String(c?.payload?.checkpointRoot || '')));
        
        // Get latest checkpoint and anchor
        const latestCheckpoint = checkpoints.length > 0 ? checkpoints[checkpoints.length - 1] : null;
        const latestAnchor = anchors.length > 0 ? anchors[anchors.length - 1] : null;
        
        // Calculate events since last anchor
        const lastAnchorSeq = latestAnchor ? Number((latestAnchor as any).sequenceNumber || 0) : 0;
        const eventsSinceLastAnchor = events.length - lastAnchorSeq;
        
        // Sync status (compare with main node if connected)
        let syncStatus = 'UNKNOWN';
        let mainNodeSequence = 0;
        if (this.isConnectedToMain) {
          try {
            const base = this.getSeedHttpBase();
            if (base) {
              const headRes = await fetch(`${base}/api/registry/head`);
              if (headRes.ok) {
                const headData = await headRes.json() as any;
                mainNodeSequence = Number(headData.lastEventSequence || 0);
                const localSequence = events.length;
                if (localSequence >= mainNodeSequence) {
                  syncStatus = 'IN_SYNC';
                } else if (mainNodeSequence - localSequence <= 5) {
                  syncStatus = 'SLIGHTLY_BEHIND';
                } else {
                  syncStatus = 'SYNCING';
                }
              }
            }
          } catch (e) {
            syncStatus = 'UNKNOWN';
          }
        } else {
          syncStatus = 'DISCONNECTED';
        }
        
        // Calculate anchor coverage percentage
        const anchorCoverage = checkpoints.length > 0 
          ? ((anchoredCheckpoints.length / checkpoints.length) * 100).toFixed(1)
          : '0.0';
        
        res.json({
          success: true,
          ledger: {
            totalEvents: events.length,
            latestEventHash,
            latestEventTimestamp,
            latestEventAge: latestEventTimestamp ? Math.floor((Date.now() - latestEventTimestamp) / 1000) : 0,
          },
          checkpoints: {
            total: checkpoints.length,
            anchored: anchoredCheckpoints.length,
            unanchored: checkpoints.length - anchoredCheckpoints.length,
            anchorCoveragePercent: parseFloat(anchorCoverage),
            latestCheckpointRoot: latestCheckpoint ? String((latestCheckpoint as any).payload?.checkpointRoot || '').substring(0, 16) : '',
            latestCheckpointSeq: latestCheckpoint ? Number((latestCheckpoint as any).sequenceNumber || 0) : 0,
          },
          anchoring: {
            totalAnchors: anchors.length,
            latestAnchorTxid: latestAnchor ? String((latestAnchor as any).payload?.txid || '').substring(0, 16) : '',
            latestAnchorBlock: latestAnchor ? Number((latestAnchor as any).payload?.blockHeight || 0) : 0,
            eventsSinceLastAnchor,
          },
          sync: {
            status: syncStatus,
            connectedToMain: this.isConnectedToMain,
            localSequence: events.length,
            mainNodeSequence,
            behind: Math.max(0, mainNodeSequence - events.length),
          },
          timestamp: Date.now(),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
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

    this.app.get('/api/ledger/events/latest', async (req: Request, res: Response) => {
      try {
        const limitRaw = Number(req.query.limit || 20);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(200, Math.floor(limitRaw)) : 20;

        const head = this.canonicalEventStore.getState();
        const toSequence = Number((head as any)?.sequenceNumber || 0);
        const fromSequence = Math.max(1, toSequence - limit + 1);

        const events = toSequence > 0
          ? await this.canonicalEventStore.getEventsBySequence(fromSequence, toSequence)
          : [];

        res.json({
          success: true,
          head: {
            sequenceNumber: toSequence,
            headHash: String((head as any)?.headHash || ''),
          },
          events: events
            .map((e: any) => ({
              sequenceNumber: Number(e?.sequenceNumber || 0),
              eventHash: String(e?.eventHash || ''),
              type: String(e?.payload?.type || ''),
              timestamp: Number(e?.payload?.timestamp || e?.createdAt || 0),
            }))
            .sort((a: any, b: any) => b.sequenceNumber - a.sequenceNumber),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Debug endpoint to inspect account events for email/username privacy verification
    this.app.get('/api/ledger/accounts/privacy-check', async (req: Request, res: Response) => {
      try {
        const events = await this.canonicalEventStore.getAllEvents();
        
        // Find all ACCOUNT_CREATED events and check for plaintext email/username
        const accountEvents = events
          .filter((e: any) => e?.payload?.type === EventType.ACCOUNT_CREATED)
          .map((e: any) => ({
            sequenceNumber: e.sequenceNumber,
            eventHash: String(e.eventHash || '').substring(0, 16),
            accountId: String(e.payload?.accountId || '').substring(0, 20) + '...',
            hasPlaintextEmail: !!e.payload?.email,
            hasEmailHash: !!e.payload?.emailHash,
            emailHashPreview: e.payload?.emailHash ? String(e.payload.emailHash).substring(0, 16) + '...' : null,
            plaintextEmailPreview: e.payload?.email ? `${String(e.payload.email).substring(0, 3)}***` : null,
            hasPlaintextUsername: !!e.payload?.username,
            hasUsernameHash: !!e.payload?.usernameHash,
            usernameHashPreview: e.payload?.usernameHash ? String(e.payload.usernameHash).substring(0, 16) + '...' : null,
            plaintextUsernamePreview: e.payload?.username ? `${String(e.payload.username).substring(0, 3)}***` : null,
            timestamp: e.payload?.timestamp,
          }));

        const summary = {
          totalAccounts: accountEvents.length,
          withPlaintextEmail: accountEvents.filter((a: any) => a.hasPlaintextEmail).length,
          withPlaintextUsername: accountEvents.filter((a: any) => a.hasPlaintextUsername).length,
          fullyPrivate: accountEvents.filter((a: any) => !a.hasPlaintextEmail && !a.hasPlaintextUsername && a.hasEmailHash && a.hasUsernameHash).length,
        };

        res.json({
          success: true,
          summary,
          accounts: accountEvents.slice(-20), // Last 20 accounts
          message: (summary.withPlaintextEmail > 0 || summary.withPlaintextUsername > 0)
            ? `⚠️ ${summary.withPlaintextEmail} legacy accounts have plaintext email, ${summary.withPlaintextUsername} have plaintext username`
            : '✅ All accounts use hashed email and username only',
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

        const openGateways = Array.from(this.gatewayConnections.entries())
          .filter(([ws, meta]) => {
            if (ws.readyState !== WebSocket.OPEN) return false;
            if ((meta as any)?.isUi) return false;
            return Boolean((meta as any)?.isGateway);
          });

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
            gatewayConnections: openGateways.length,
          },
          connections: {
            operatorConnections: this.operatorPeerConnections.size,
            gatewayConnections: openGateways.length,
          },
          ledger: {
            sequenceNumber: this.state.lastSyncedSequence,
            lastEventHash: this.state.lastSyncedHash,
          },
          ledgerSequence: this.state.lastSyncedSequence,
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

    // Gateway registration endpoint - gateways register to be discoverable by other gateways
    this.app.post('/api/network/gateways/register', (req: Request, res: Response) => {
      try {
        const { gatewayId, httpUrl, wsUrl, version } = req.body;
        
        if (!gatewayId || !httpUrl) {
          res.status(400).json({ success: false, error: 'gatewayId and httpUrl required' });
          return;
        }

        const now = Date.now();
        this.publicGatewayRegistry.set(gatewayId, {
          gatewayId,
          httpUrl: String(httpUrl).trim(),
          wsUrl: wsUrl ? String(wsUrl).trim() : httpUrl.replace('https://', 'wss://').replace('http://', 'ws://'),
          registeredAt: this.publicGatewayRegistry.get(gatewayId)?.registeredAt || now,
          lastHeartbeat: now,
          version: version || '1.0.0',
        });

        console.log(`[Gateway] Registered public gateway: ${gatewayId} at ${httpUrl}`);
        res.json({ success: true, gatewayId, registeredAt: now });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Gateway discovery endpoint - returns list of public gateways
    this.app.get('/api/network/gateways', (req: Request, res: Response) => {
      try {
        const now = Date.now();
        const maxAge = 10 * 60 * 1000; // 10 minutes - gateways must heartbeat to stay listed

        // Clean up stale gateways
        for (const [id, gw] of this.publicGatewayRegistry.entries()) {
          if (now - gw.lastHeartbeat > maxAge) {
            this.publicGatewayRegistry.delete(id);
          }
        }

        const gateways = Array.from(this.publicGatewayRegistry.values())
          .map(gw => ({
            gatewayId: gw.gatewayId,
            httpUrl: gw.httpUrl,
            wsUrl: gw.wsUrl,
            version: gw.version,
            lastHeartbeat: gw.lastHeartbeat,
            ageMs: now - gw.registeredAt,
          }));

        res.json({
          success: true,
          timestamp: now,
          gateways,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // DNS seed verification endpoint - checks if a domain has valid autho-peer TXT record
    this.app.get('/api/network/dns-verify', async (req: Request, res: Response) => {
      try {
        const domain = String(req.query.domain || '').trim();
        
        if (!domain) {
          res.status(400).json({ success: false, error: 'Domain parameter required' });
          return;
        }

        // Use Node.js dns module to resolve TXT records
        const dns = require('dns');
        const { promisify } = require('util');
        const resolveTxt = promisify(dns.resolveTxt);

        try {
          const records = await resolveTxt(domain);
          
          // Look for autho-peer record
          for (const record of records) {
            const txt = record.join('');
            if (txt.startsWith('autho-peer=')) {
              // Announce this DNS seed to the ledger so all nodes learn about it
              let announced = false;
              try {
                if (this.consensusNode) {
                  const crypto = require('crypto');
                  const signature = crypto.createHash('sha256')
                    .update(`${this.config.privateKey}:${EventType.NETWORK_SEED_ANNOUNCED}:${Date.now()}`)
                    .digest('hex');
                  await this.consensusNode.submitEvent(EventType.NETWORK_SEED_ANNOUNCED, {
                    seedDomain: domain,
                    seedType: 'dns',
                    txtRecord: txt,
                    verifiedAt: Date.now(),
                    verifiedBy: this.config.operatorId,
                  }, signature);
                  announced = true;
                  console.log(`📡 Announced DNS seed to ledger: ${domain}`);
                }
              } catch (announceError: any) {
                console.error(`Failed to announce DNS seed: ${announceError.message}`);
              }
              
              res.json({
                success: true,
                found: true,
                domain,
                txtRecord: txt,
                announced,
              });
              return;
            }
          }

          // No autho-peer record found
          res.json({
            success: true,
            found: false,
            domain,
            error: 'No autho-peer TXT record found',
          });
        } catch (dnsError: any) {
          res.json({
            success: true,
            found: false,
            domain,
            error: dnsError.code === 'ENODATA' ? 'No TXT records found' : 
                   dnsError.code === 'ENOTFOUND' ? 'Domain not found' : 
                   `DNS lookup failed: ${dnsError.message}`,
          });
        }
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // UI bundle endpoint - returns list of public files for gateway caching
    this.app.get('/api/gateway/ui-manifest', async (req: Request, res: Response) => {
      try {
        const fs = require('fs');
        const path = require('path');
        const publicDir = path.join(__dirname, '..', 'public');
        
        const files: { path: string; size: number; modified: number }[] = [];
        
        const scanDir = (dir: string, basePath: string = '') => {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            const relativePath = basePath ? `${basePath}/${entry.name}` : entry.name;
            
            if (entry.isDirectory()) {
              scanDir(fullPath, relativePath);
            } else {
              const stat = fs.statSync(fullPath);
              files.push({
                path: '/' + relativePath,
                size: stat.size,
                modified: stat.mtimeMs,
              });
            }
          }
        };
        
        if (fs.existsSync(publicDir)) {
          scanDir(publicDir);
        }
        
        res.json({
          success: true,
          version: Date.now(),
          files,
          baseUrl: `${req.protocol}://${req.get('host')}`,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Mesh network diagnostic endpoint - shows all connected nodes
    this.app.get('/api/network/mesh', async (req: Request, res: Response) => {
      try {
        const now = Date.now();

        // Operator peer connections (outbound to other operators)
        const operatorPeers = Array.from(this.operatorPeerConnections.entries())
          .filter(([, p]) => p.ws.readyState === WebSocket.OPEN)
          .map(([peerId, p]) => ({
            operatorId: p.operatorId,
            wsUrl: p.wsUrl,
            connectedAt: p.connectedAt,
            lastSeen: p.lastSeen,
            ageMs: now - p.connectedAt,
          }));

        // Gateway connections (inbound from gateways)
        const openGateways = Array.from(this.gatewayConnections.entries())
          .filter(([ws]) => ws.readyState === WebSocket.OPEN);

        const gateways = openGateways
          .filter(([, c]) => !c.isUi && c.isGateway)
          .map(([, c]) => ({
            connectedAt: c.connectedAt,
            lastSeen: c.lastSeen,
            ageMs: now - c.connectedAt,
            ip: c.ip,
          }));

        const uiClients = openGateways
          .filter(([, c]) => c.isUi)
          .map(([, c]) => ({
            connectedAt: c.connectedAt,
            lastSeen: c.lastSeen,
            subscribedToConsensus: c.subscribedToConsensus || false,
            ip: c.ip,
          }));

        const mainSeedConnected = this.mainSeedWs?.readyState === WebSocket.OPEN;

        const state = await this.canonicalStateBuilder.buildState();
        const allOperators = Array.from((state as any).operators?.values?.() || []) as any[];
        const activeOperators = allOperators.filter((o: any) => o && o.status === 'active');

        res.json({
          success: true,
          timestamp: now,
          nodeType: 'operator',
          operatorId: this.config.operatorId,
          mesh: {
            mainSeedConnected,
            connectedOperatorPeers: operatorPeers.length,
            connectedGateways: gateways.length,
            uiClients: uiClients.length,
            totalGatewayConnections: openGateways.length,
          },
          mainSeed: {
            connected: mainSeedConnected,
            url: this.config.mainSeedUrl || '',
          },
          operatorPeers: {
            connected: operatorPeers,
            registeredActive: activeOperators.length,
          },
          gateways: {
            connected: gateways,
          },
          ledger: {
            sequenceNumber: this.state.lastSyncedSequence,
            lastEventHash: this.state.lastSyncedHash,
          },
          consensus: this.consensusNode ? {
            currentCheckpoint: this.consensusNode.getState().currentCheckpointNumber,
            isLeader: this.consensusNode.getState().isLeader,
            mempoolSize: this.consensusNode.getState().mempoolStats.totalEvents,
          } : null,
          peerDiscovery: {
            enabled: !!this.peerDiscoveryTimer,
            lastDiscoverySource: this.getSeedHttpBase() || '',
          },
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

    // Peer resilience status for 250-year stability monitoring
    this.app.get('/api/network/resilience', (req: Request, res: Response) => {
      if (!this.peerResilienceManager) {
        res.json({ success: false, error: 'Resilience manager not initialized' });
        return;
      }

      const status = this.peerResilienceManager.getStatus();
      const consistency = this.peerResilienceManager.generateConsistencyReport();

      res.json({
        success: true,
        resilience: {
          ...status,
          mainNodeDowntimeMs: status.isMainNodeOnline ? 0 : Date.now() - status.mainNodeLastSeen,
        },
        consistency: {
          totalPeers: consistency.totalPeers,
          onlinePeers: consistency.onlinePeers,
          consistentPeers: consistency.consistentPeers,
          divergentPeers: consistency.divergentPeers,
          majoritySequence: consistency.majoritySequence,
          needsRepair: consistency.needsRepair,
        },
        peerConnections: Array.from(this.operatorPeerConnections.entries()).map(([id, peer]) => ({
          operatorId: id,
          connected: peer.ws.readyState === WebSocket.OPEN,
          lastSeenMs: Date.now() - peer.lastSeen,
          uptimeMs: Date.now() - peer.connectedAt,
        })),
      });
    });

    // Heartbeat-style consensus verification status (separate from mempool consensus)
    this.app.get('/api/consensus/verification', (req: Request, res: Response) => {
      const status = this.getConsensusStatus();
      res.json({ success: true, ...status });
    });

    // Storage durability stats (Bitcoin-level reliability metrics)
    this.app.get('/api/storage/stats', async (req: Request, res: Response) => {
      try {
        const storageStats = this.canonicalEventStore.getStorageStats();
        const pruningStats = await this.canonicalEventStore.getPruningStats();
        
        res.json({
          success: true,
          storage: {
            eventCount: storageStats.eventCount,
            indexEntries: storageStats.indexEntries,
            headHash: storageStats.headHash,
            sequenceNumber: storageStats.sequenceNumber,
            integrityVerified: storageStats.integrityVerified,
          },
          pruning: {
            totalEvents: pruningStats.totalEvents,
            oldestEventAgeDays: pruningStats.oldestEventAge,
            newestEventAgeDays: pruningStats.newestEventAge,
            checkpointCount: pruningStats.checkpointCount,
            estimatedPrunableEvents: pruningStats.estimatedPrunableEvents,
            diskUsageBytes: pruningStats.diskUsageBytes,
            diskUsageMB: Math.round(pruningStats.diskUsageBytes / 1024 / 1024 * 100) / 100,
          },
          durability: {
            atomicWrites: true,
            checksumVerification: true,
            backupRecovery: true,
            writeAheadLog: true,
            merkleProofs: true,
            bitcoinAnchoring: true,
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Generate Merkle proof for an event (SPV-style verification)
    this.app.get('/api/storage/proof/:eventHash', async (req: Request, res: Response) => {
      try {
        const { eventHash } = req.params;
        const proof = await this.canonicalEventStore.generateCompactEventProof(eventHash);
        
        if (!proof) {
          res.status(404).json({ success: false, error: 'Event not found' });
          return;
        }

        res.json({
          success: true,
          proof,
          verificationInstructions: 'Verify by reconstructing Merkle root from leaf hash and sibling path',
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Verify hash chain integrity (like Bitcoin's -checkblocks)
    this.app.post('/api/storage/verify', async (req: Request, res: Response) => {
      try {
        const startTime = Date.now();
        const isValid = await this.canonicalEventStore.verifyHashChain();
        const elapsed = Date.now() - startTime;
        const stats = this.canonicalEventStore.getStorageStats();

        res.json({
          success: true,
          verification: {
            hashChainValid: isValid,
            eventsVerified: stats.eventCount,
            verificationTimeMs: elapsed,
            headHash: stats.headHash,
            sequenceNumber: stats.sequenceNumber,
          },
          message: isValid 
            ? `✅ Hash chain verified - ${stats.eventCount} events in ${elapsed}ms`
            : '❌ Hash chain verification FAILED - possible corruption detected',
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Trigger reindex (like Bitcoin's -reindex)
    this.app.post('/api/storage/reindex', async (req: Request, res: Response) => {
      try {
        const startTime = Date.now();
        await this.canonicalEventStore.reindex();
        const elapsed = Date.now() - startTime;
        const stats = this.canonicalEventStore.getStorageStats();

        res.json({
          success: true,
          reindex: {
            completed: true,
            eventsIndexed: stats.eventCount,
            reindexTimeMs: elapsed,
          },
          message: `✅ Reindex complete - ${stats.eventCount} events indexed in ${elapsed}ms`,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Create checkpoint for Bitcoin anchoring
    this.app.post('/api/storage/checkpoint', async (req: Request, res: Response) => {
      try {
        const checkpoint = await this.canonicalEventStore.createEnhancedCheckpoint();
        const opReturn = await this.canonicalEventStore.getOpReturnCommitment();

        res.json({
          success: true,
          checkpoint: {
            checkpointRoot: checkpoint.checkpointRoot,
            merkleRoot: checkpoint.merkleRoot,
            fromSequence: checkpoint.fromSequence,
            toSequence: checkpoint.toSequence,
            eventCount: checkpoint.eventCount,
            treeHeight: checkpoint.tree.treeHeight,
            createdAt: checkpoint.createdAt,
          },
          bitcoinAnchoring: {
            opReturnHex: opReturn.toString('hex'),
            opReturnSize: opReturn.length,
            instructions: 'Broadcast this OP_RETURN data in a Bitcoin transaction to anchor the checkpoint',
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ==================== BITCOIN ANCHORING ENDPOINTS ====================

    // Get unanchored checkpoints
    this.app.get('/api/operator/anchors/unanchored', async (req: Request, res: Response) => {
      try {
        const events = await this.canonicalEventStore.getAllEvents();
        
        const checkpoints = events
          .filter((e: any) => e?.payload?.type === EventType.CHECKPOINT_CREATED)
          .map((e: any) => e.payload);
        
        const anchors = events
          .filter((e: any) => e?.payload?.type === EventType.ANCHOR_COMMITTED)
          .map((e: any) => e.payload);
        
        const anchoredRoots = new Set(anchors.map((a: any) => a.checkpointRoot));
        const unanchored = checkpoints.filter((cp: any) => !anchoredRoots.has(cp.checkpointRoot));
        
        res.json({ success: true, unanchored, total: checkpoints.length, anchored: anchors.length });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    // Get anchor statistics for weighted fee distribution
    this.app.get('/api/operator/anchors/stats', async (req: Request, res: Response) => {
      try {
        const events = await this.canonicalEventStore.getAllEvents();
        const state = await this.canonicalStateBuilder.buildState();
        
        // Count anchors by operator
        const anchorsByOperator = new Map<string, number>();
        const anchorEvents = events.filter((e: any) => e?.payload?.type === EventType.ANCHOR_COMMITTED);
        
        // Debug: log anchor events structure
        console.log(`[Anchor Stats] Found ${anchorEvents.length} anchor events`);
        for (const e of anchorEvents) {
          const sigs = Array.isArray((e as any).signatures) ? (e as any).signatures : [];
          console.log(`[Anchor Stats] Event ${(e as any).eventHash?.substring(0,16)}... has ${sigs.length} signatures:`, sigs.map((s: any) => s?.operatorId));
          for (const sig of sigs) {
            const opId = String(sig?.operatorId || '').trim();
            if (opId) {
              anchorsByOperator.set(opId, (anchorsByOperator.get(opId) || 0) + 1);
            }
          }
        }

        // Calculate weights
        const totalAnchors = Array.from(anchorsByOperator.values()).reduce((sum, count) => sum + count, 0);
        const weights = new Map<string, number>();
        
        for (const [opId, count] of anchorsByOperator.entries()) {
          weights.set(opId, totalAnchors > 0 ? count / totalAnchors : 0);
        }

        // Get active operators
        const activeOperators = Array.from(state.operators.values())
          .filter((op: any) => op.status === 'active')
          .map((op: any) => ({
            operatorId: op.operatorId,
            publicKey: op.publicKey,
            anchorCount: anchorsByOperator.get(op.operatorId) || 0,
            weight: weights.get(op.operatorId) || 0,
          }));

        // Debug: include anchor event details
        const debugAnchorEvents = anchorEvents.slice(0, 10).map((e: any) => ({
          hash: (e.eventHash || '').substring(0, 16),
          sigCount: Array.isArray(e.signatures) ? e.signatures.length : 0,
          operatorIds: Array.isArray(e.signatures) ? e.signatures.map((s: any) => s?.operatorId) : [],
          checkpointRoot: (e.payload?.checkpointRoot || '').substring(0, 16),
        }));

        res.json({ 
          success: true, 
          totalAnchors,
          operators: activeOperators,
          myOperatorId: this.config.operatorId,
          myAnchorCount: anchorsByOperator.get(this.config.operatorId) || 0,
          _debug: {
            anchorEventCount: anchorEvents.length,
            anchorEvents: debugAnchorEvents,
          }
        });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    // Get anchor history for the current operator
    this.app.get('/api/operator/anchors/history', async (req: Request, res: Response) => {
      try {
        const events = await this.canonicalEventStore.getAllEvents();
        const myOperatorId = this.config.operatorId;
        
        // Find all anchor events where this operator participated
        const anchorEvents = events
          .filter((e: any) => e?.payload?.type === EventType.ANCHOR_COMMITTED)
          .filter((e: any) => {
            const sigs = Array.isArray(e.signatures) ? e.signatures : [];
            return sigs.some((s: any) => String(s?.operatorId || '') === myOperatorId);
          })
          .map((e: any) => ({
            checkpointRoot: String(e.payload?.checkpointRoot || ''),
            txid: String(e.payload?.txid || ''),
            blockHeight: Number(e.payload?.blockHeight || 0),
            timestamp: Number(e.payload?.timestamp || e.timestamp || 0),
            eventCount: Number(e.payload?.eventCount || 0),
            sequenceNumber: Number(e.sequenceNumber || 0),
          }))
          .sort((a: any, b: any) => b.timestamp - a.timestamp);

        res.json({
          success: true,
          operatorId: myOperatorId,
          anchors: anchorEvents,
          totalAnchors: anchorEvents.length,
        });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    // Manual anchor commit (for pre-existing Bitcoin transactions)
    this.app.post('/api/operator/anchors/commit', async (req: Request, res: Response) => {
      try {
        // Require authenticated operator session to attribute the anchor
        const opSession = await this.requireOperatorSession(req, res);
        if (!opSession) return;

        const checkpointRoot = String(req.body?.checkpointRoot || '').trim();
        const txid = String(req.body?.txid || '').trim();
        const blockHeight = Number(req.body?.blockHeight || 0);
        
        if (!checkpointRoot || !txid || !Number.isFinite(blockHeight) || blockHeight <= 0) {
          res.status(400).json({ success: false, error: 'checkpointRoot, txid, blockHeight required' });
          return;
        }

        const events = await this.canonicalEventStore.getAllEvents();
        const checkpoint = events
          .filter((e: any) => e?.payload?.type === EventType.CHECKPOINT_CREATED)
          .map((e: any) => e.payload)
          .find((p: any) => String(p?.checkpointRoot || '') === checkpointRoot);

        if (!checkpoint) {
          res.status(404).json({ success: false, error: 'Checkpoint not found' });
          return;
        }

        const existingAnchors = events
          .filter((e: any) => e?.payload?.type === EventType.ANCHOR_COMMITTED)
          .map((e: any) => e.payload)
          .filter((p: any) => String(p?.checkpointRoot || '') === checkpointRoot);
        
        if (existingAnchors.length) {
          res.status(409).json({ success: false, error: 'Anchor already recorded for this checkpoint' });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const now = Date.now();
        // Use authenticated operator's ID for proper attribution
        const signatures: QuorumSignature[] = [
          {
            operatorId: opSession.operatorId,
            publicKey: opSession.operatorPublicKey,
            signature: createHash('sha256').update(`ANCHOR_COMMITTED:${checkpointRoot}:${txid}:${blockHeight}:${now}`).digest('hex'),
          },
        ];

        const anchorPayload = {
          type: EventType.ANCHOR_COMMITTED,
          timestamp: now,
          nonce,
          checkpointRoot,
          eventCount: Number((checkpoint as any)?.eventCount || 0),
          txid,
          blockHeight,
          quorumSignatures: [],
        };

        const anchorEvent = await this.canonicalEventStore.appendEvent(anchorPayload as any, signatures);

        // Broadcast anchor event to main node so it's synced to all operators
        const seedResult = await this.submitCanonicalEventToSeed(anchorPayload, signatures);
        if (!seedResult.ok) {
          console.warn(`[Manual-Anchor] Failed to sync anchor to main node: ${seedResult.error}`);
        } else {
          console.log(`[Manual-Anchor] Anchor event synced to main node`);
        }

        res.json({ success: true, checkpointRoot, txid, blockHeight, sequenceNumber: anchorEvent.sequenceNumber });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    // ONE-CLICK AUTO-ANCHOR: Create and broadcast real Bitcoin OP_RETURN transaction
    this.app.post('/api/operator/anchors/auto-anchor', async (req: Request, res: Response) => {
      try {
        // Require authenticated operator session to attribute the anchor
        const opSession = await this.requireOperatorSession(req, res);
        if (!opSession) return;

        let checkpointRoot = String(req.body?.checkpointRoot || '').trim();
        
        const events = await this.canonicalEventStore.getAllEvents();
        
        // Get all checkpoints and anchors
        const checkpoints = events
          .filter((e: any) => e?.payload?.type === EventType.CHECKPOINT_CREATED)
          .map((e: any) => e.payload);
        
        const anchoredRoots = new Set(
          events
            .filter((e: any) => e?.payload?.type === EventType.ANCHOR_COMMITTED)
            .map((e: any) => String(e.payload?.checkpointRoot || ''))
        );
        
        // Find unanchored checkpoints
        const unanchored = checkpoints.filter((cp: any) => !anchoredRoots.has(String(cp?.checkpointRoot || '')));
        
        if (unanchored.length === 0) {
          res.status(400).json({ success: false, error: 'All checkpoints are already anchored' });
          return;
        }
        
        // If no checkpoint specified, use oldest unanchored
        if (!checkpointRoot) {
          unanchored.sort((a: any, b: any) => (a.hourStartMs || 0) - (b.hourStartMs || 0));
          checkpointRoot = String(unanchored[0]?.checkpointRoot || '');
        }
        
        // Verify checkpoint exists and is unanchored
        const checkpoint = checkpoints.find((cp: any) => String(cp?.checkpointRoot || '') === checkpointRoot);
        if (!checkpoint) {
          res.status(404).json({ success: false, error: 'Checkpoint not found' });
          return;
        }
        
        if (anchoredRoots.has(checkpointRoot)) {
          res.status(409).json({ success: false, error: 'Checkpoint already anchored' });
          return;
        }
        
        // Create OP_RETURN data: "AUTHO:" + first 32 bytes of checkpoint root
        const opReturnData = `AUTHO:${checkpointRoot.substring(0, 64)}`;
        
        // Get operator's private key for signing the Bitcoin transaction
        const operatorPrivateKey = this.config.privateKey;
        if (!operatorPrivateKey) {
          res.status(400).json({ 
            success: false, 
            error: 'Operator private key not configured.' 
          });
          return;
        }

        // Create and broadcast real Bitcoin OP_RETURN transaction
        const btcService = new BitcoinTransactionService(this.config.network || 'mainnet');
        
        // Verify the private key matches the configured btcAddress
        const derivedAddress = btcService.getAddressFromPrivateKey(operatorPrivateKey);
        if (this.config.btcAddress && derivedAddress !== this.config.btcAddress) {
          console.error(`[Auto-Anchor] Address mismatch! Derived: ${derivedAddress}, Config: ${this.config.btcAddress}`);
          res.status(400).json({ 
            success: false, 
            error: `Private key mismatch: Your privateKey generates address ${derivedAddress} but your btcAddress is ${this.config.btcAddress}. Update your config to use matching keys.` 
          });
          return;
        }
        
        // Use the derived address (which should match config if configured correctly)
        const anchorResult = await btcService.createOpReturnAnchor(
          operatorPrivateKey, 
          opReturnData, 
          undefined, // use default fee rate
          derivedAddress // use address derived from private key
        );
        
        if (!anchorResult.success || !anchorResult.txid) {
          res.status(400).json({ 
            success: false, 
            error: `Bitcoin anchor failed: ${anchorResult.error || 'Unknown error'}` 
          });
          return;
        }

        const realTxid = anchorResult.txid;
        const feePaid = anchorResult.feeSats || 0;
        
        // Get current block height from mempool.space
        let currentBlockHeight = 0;
        try {
          const blockHeightRes = await fetch('https://mempool.space/api/blocks/tip/height');
          if (blockHeightRes.ok) {
            currentBlockHeight = Number(await blockHeightRes.text()) || 0;
          }
        } catch (e) {
          console.warn('[Auto-Anchor] Could not fetch current block height');
        }
        
        // Record the anchor commitment
        const nonce = randomBytes(32).toString('hex');
        const now = Date.now();
        // Use authenticated operator's ID for proper attribution
        const signatures: QuorumSignature[] = [
          {
            operatorId: opSession.operatorId,
            publicKey: opSession.operatorPublicKey,
            signature: createHash('sha256').update(`ANCHOR_COMMITTED:${checkpointRoot}:${realTxid}:${currentBlockHeight}:${now}`).digest('hex'),
          },
        ];

        const anchorPayload = {
          type: EventType.ANCHOR_COMMITTED,
          timestamp: now,
          nonce,
          checkpointRoot,
          eventCount: Number((checkpoint as any)?.eventCount || 0),
          txid: realTxid,
          blockHeight: currentBlockHeight,
          quorumSignatures: [],
        };

        const anchorEvent = await this.canonicalEventStore.appendEvent(anchorPayload as any, signatures);

        // Broadcast anchor event to main node so it's synced to all operators
        const seedResult = await this.submitCanonicalEventToSeed(anchorPayload, signatures);
        if (!seedResult.ok) {
          console.warn(`[Auto-Anchor] Failed to sync anchor to main node: ${seedResult.error}`);
        } else {
          console.log(`[Auto-Anchor] Anchor event synced to main node`);
        }

        res.json({ 
          success: true, 
          checkpointRoot, 
          txid: realTxid, 
          blockHeight: currentBlockHeight,
          opReturnData,
          feePaidSats: feePaid,
          sequenceNumber: anchorEvent.sequenceNumber,
          message: `Checkpoint anchored to Bitcoin! TX: ${realTxid}`
        });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    // BROADCAST PRE-SIGNED ANCHOR TRANSACTION (non-custodial - client signs, server broadcasts)
    this.app.post('/api/operator/anchors/broadcast-anchor', async (req: Request, res: Response) => {
      try {
        const sess = await this.requireOperatorSession(req, res);
        if (!sess) return;

        const { checkpointRoot, signedTxHex, txid } = req.body || {};
        
        if (!checkpointRoot || !signedTxHex) {
          res.status(400).json({ 
            success: false, 
            error: 'Missing required fields: checkpointRoot, signedTxHex' 
          });
          return;
        }

        // Verify checkpoint exists and is unanchored
        const checkpoints = await this.canonicalEventStore.getAllEvents();
        const checkpoint = checkpoints.find(
          (e: any) => e?.payload?.type === EventType.CHECKPOINT_CREATED && 
                     String(e?.payload?.checkpointRoot || '') === String(checkpointRoot)
        );
        
        if (!checkpoint) {
          res.status(400).json({ success: false, error: 'Checkpoint not found' });
          return;
        }

        // Check if already anchored
        const existingAnchor = checkpoints.find(
          (e: any) => e?.payload?.type === EventType.ANCHOR_COMMITTED && 
                     String(e?.payload?.checkpointRoot || '') === String(checkpointRoot)
        );
        
        if (existingAnchor) {
          res.status(400).json({ 
            success: false, 
            error: 'Checkpoint already anchored',
            existingTxid: (existingAnchor as any)?.payload?.txid
          });
          return;
        }

        // Broadcast the pre-signed transaction to Bitcoin network
        const btcService = new BitcoinTransactionService(this.config.network || 'mainnet');
        let broadcastTxid: string;
        
        try {
          broadcastTxid = await btcService.broadcastTransaction(signedTxHex);
        } catch (broadcastErr: any) {
          res.status(400).json({ 
            success: false, 
            error: `Broadcast failed: ${broadcastErr?.message || String(broadcastErr)}` 
          });
          return;
        }

        // Get current block height
        let currentBlockHeight = 0;
        try {
          const blockHeightRes = await fetch('https://mempool.space/api/blocks/tip/height');
          if (blockHeightRes.ok) {
            currentBlockHeight = Number(await blockHeightRes.text()) || 0;
          }
        } catch (e) {
          console.warn('[Broadcast-Anchor] Could not fetch current block height');
        }

        // Record the anchor commitment event
        const nonce = randomBytes(32).toString('hex');
        const now = Date.now();
        // Use authenticated operator's ID for proper attribution
        const signatures: QuorumSignature[] = [
          {
            operatorId: sess.operatorId,
            publicKey: sess.operatorPublicKey,
            signature: createHash('sha256').update(`ANCHOR_COMMITTED:${checkpointRoot}:${broadcastTxid}:${currentBlockHeight}:${now}`).digest('hex'),
          },
        ];

        const anchorPayload = {
          type: EventType.ANCHOR_COMMITTED,
          timestamp: now,
          nonce,
          checkpointRoot,
          eventCount: Number((checkpoint as any)?.payload?.eventCount || 0),
          txid: broadcastTxid,
          blockHeight: currentBlockHeight,
          quorumSignatures: [],
        };

        const anchorEvent = await this.canonicalEventStore.appendEvent(anchorPayload as any, signatures);

        // Broadcast anchor event to main node so it's synced to all operators
        const seedResult = await this.submitCanonicalEventToSeed(anchorPayload, signatures);
        if (!seedResult.ok) {
          console.warn(`[Broadcast-Anchor] Failed to sync anchor to main node: ${seedResult.error}`);
        } else {
          console.log(`[Broadcast-Anchor] Anchor event synced to main node`);
        }

        console.log(`[Broadcast-Anchor] Checkpoint ${checkpointRoot.substring(0, 16)}... anchored with TX ${broadcastTxid}`);

        res.json({ 
          success: true, 
          checkpointRoot, 
          txid: broadcastTxid, 
          blockHeight: currentBlockHeight,
          sequenceNumber: anchorEvent.sequenceNumber,
          message: `Checkpoint anchored to Bitcoin! TX: ${broadcastTxid}`
        });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    // ==================== END BITCOIN ANCHORING ENDPOINTS ====================

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

    this.app.post('/api/operator/wallet/send', async (req: Request, res: Response) => {
      // Note: Full Bitcoin transaction building requires UTXO management and signing
      // For now, operators should use external wallets for sending BTC
      // This endpoint is a placeholder for future implementation
      res.status(501).json({
        success: false,
        error: 'Send functionality not yet implemented. Please use an external Bitcoin wallet to send from your operator address: ' + this.config.btcAddress,
        operatorAddress: this.config.btcAddress,
        hint: 'You can import your operator seed phrase into a Bitcoin wallet like BlueWallet, Sparrow, or Electrum to send transactions.'
      });
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
      // Custom handler to capture session from seed and store locally
      const base = this.getSeedHttpBase();
      if (!base) {
        return res.status(502).json({ success: false, error: 'No seed HTTP base configured' });
      }

      try {
        const seedResp = await fetch(`${base}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(req.body),
        });

        const data = await seedResp.json() as any;
        
        if (seedResp.ok && data.success && data.sessionId && data.accountId) {
          // Store session locally so subsequent requests work
          const now = Date.now();
          this.sessions.set(data.sessionId, {
            sessionId: data.sessionId,
            accountId: data.accountId,
            createdAt: now,
            expiresAt: now + 24 * 60 * 60 * 1000, // 24 hours
          });
          console.log(`[Auth] Cached session ${data.sessionId.substring(0, 8)}... for account ${data.accountId.substring(0, 8)}...`);
        }

        res.status(seedResp.status).json(data);
      } catch (e: any) {
        console.error('[Auth] Login proxy error:', e.message);
        res.status(502).json({ success: false, error: e?.message || String(e) });
      }
    });

    this.app.get('/api/auth/me', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    // Verify session endpoint for gateway nodes
    this.app.post('/api/auth/verify-session', async (req: Request, res: Response) => {
      try {
        const sessionToken = req.headers['x-session-token'] || req.body?.sessionToken;
        if (!sessionToken) {
          return res.status(401).json({ success: false, error: 'No session token provided' });
        }

        const session = this.sessions.get(String(sessionToken));
        if (!session) {
          // Try to validate with seed node
          const base = this.getSeedHttpBase();
          if (base) {
            try {
              const seedRes = await fetch(`${base}/api/auth/verify-session`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-session-token': String(sessionToken) },
                body: JSON.stringify({ sessionToken }),
              });
              if (seedRes.ok) {
                const data = await seedRes.json();
                if (data.success && data.account) {
                  // Cache the session locally
                  const now = Date.now();
                  this.sessions.set(String(sessionToken), {
                    sessionId: String(sessionToken),
                    accountId: data.account.accountId,
                    createdAt: now,
                    expiresAt: now + 24 * 60 * 60 * 1000,
                  });
                  return res.json({ success: true, account: data.account });
                }
              }
            } catch (e: any) {
              console.error('[Auth] Seed verify-session error:', e.message);
            }
          }
          return res.status(401).json({ success: false, error: 'Invalid or expired session' });
        }

        if (Date.now() > session.expiresAt) {
          this.sessions.delete(String(sessionToken));
          return res.status(401).json({ success: false, error: 'Session expired' });
        }

        // Get account info
        const account = this.state.accounts.get(session.accountId);
        return res.json({
          success: true,
          account: {
            accountId: session.accountId,
            publicKey: account?.publicKey || session.accountId,
            username: (account as any)?.username || '',
          }
        });
      } catch (e: any) {
        console.error('[Auth] verify-session error:', e.message);
        return res.status(500).json({ success: false, error: 'Session verification failed' });
      }
    });

    this.app.get('/api/registry/item/:itemId', async (req: Request, res: Response) => {
      const item = this.state.items.get(req.params.itemId);
      if (!item) {
        res.status(404).json({ error: 'Item not found' });
        return;
      }
      
      // Enhanced manufacturer detection
      let issuerRole = String((item as any)?.issuerRole || '').trim();
      let mintedByOfficialManufacturer = Boolean((item as any)?.mintedByOfficialManufacturer);
      
      // Check if manufacturerId or issuerAccountId matches an approved manufacturer account
      const issuerId = String((item as any)?.issuerAccountId || (item as any)?.manufacturerId || '').trim();
      const manufacturerId = String((item as any)?.manufacturerId || '').trim();
      
      // Resolve manufacturer display name - match main repo logic
      // Priority: companyName from approved role application > username > manufacturerName > manufacturerId
      let manufacturerDisplayName = '';
      
      if (manufacturerId) {
        // Look for companyName in approved role applications (same as main repo)
        let bestFinalizedAt = -1;
        const roleApps = this.state.roleApplications;
        if (roleApps && roleApps.size > 0) {
          for (const app of roleApps.values()) {
            if (String((app as any)?.accountId || '') !== manufacturerId) continue;
            const finalized = (app as any)?.finalized;
            if (!finalized || finalized.decision !== 'approve') continue;
            const companyName = String((app as any)?.companyName || '').trim();
            if (!companyName) continue;
            const requestedRole = String((app as any)?.requestedRole || '').trim();
            const t = Number(finalized.finalizedAt || 0);
            if (t >= bestFinalizedAt) {
              bestFinalizedAt = t;
              manufacturerDisplayName = companyName;
              // If approved role application exists, this is an official manufacturer/authenticator
              if (requestedRole === 'manufacturer') {
                mintedByOfficialManufacturer = true;
                if (!issuerRole || issuerRole === 'user') {
                  issuerRole = 'manufacturer';
                }
              } else if (requestedRole === 'authenticator') {
                if (!issuerRole || issuerRole === 'user') {
                  issuerRole = 'authenticator';
                }
              }
            }
          }
        }
        
        // Fallback to account username if no companyName found
        if (!manufacturerDisplayName) {
          const mfgAccount: any = this.state.accounts.get(manufacturerId);
          if (mfgAccount) {
            manufacturerDisplayName = String(mfgAccount.username || '').trim();
            if (String(mfgAccount.role || '').trim() === 'manufacturer') {
              mintedByOfficialManufacturer = true;
              if (!issuerRole || issuerRole === 'user') {
                issuerRole = 'manufacturer';
              }
            }
          }
        }
      }
      
      if (issuerId && issuerId !== manufacturerId) {
        const issuerAccount: any = this.state.accounts.get(issuerId);
        const role = String(issuerAccount?.role || '').trim();
        if (role === 'manufacturer' || role === 'authenticator') {
          issuerRole = role;
          if (role === 'manufacturer') {
            mintedByOfficialManufacturer = true;
          }
        }
      }
      
      if (!issuerRole) issuerRole = 'user';
      
      // Final fallback for display name
      if (!manufacturerDisplayName) {
        manufacturerDisplayName = String((item as any)?.manufacturerName || manufacturerId || 'Unknown').trim();
      }
      
      const hasIssuerVerification = issuerRole === 'manufacturer' || issuerRole === 'authenticator' || mintedByOfficialManufacturer;
      const authentications = Array.isArray((item as any)?.authentications) ? (item as any).authentications : [];
      const hasAttestationVerification = authentications.some((a: any) => a && a.isAuthentic === true);
      const verificationStatus = hasIssuerVerification || hasAttestationVerification ? 'verified' : 'unverified';
      
      // Get operator signatures from the item's registration event
      let operatorSignaturesCount = 0;
      let registrationEventSignatures: any[] = [];
      
      // Try to find the registration event for this item to get signatures
      if (this.canonicalEventStore) {
        try {
          const events = await this.canonicalEventStore.getAllEvents();
          const regEvent = events.find((e: any) => 
            e.payload?.type === 'ITEM_REGISTERED' && e.payload?.itemId === req.params.itemId
          );
          if (regEvent && Array.isArray(regEvent.signatures)) {
            operatorSignaturesCount = regEvent.signatures.length;
            registrationEventSignatures = regEvent.signatures;
          }
        } catch (e) {
          // Fallback to item's operatorQuorumSignatures if available
          operatorSignaturesCount = Array.isArray((item as any)?.operatorQuorumSignatures) 
            ? (item as any).operatorQuorumSignatures.length 
            : 0;
        }
      }
      
      // Get last checkpoint info
      let lastCheckpointHeight: number | undefined;
      let lastCheckpointTimestamp: number | undefined;
      
      const checkpoints = (this.state as any).checkpoints;
      if (checkpoints && checkpoints.size > 0) {
        const sorted = Array.from(checkpoints.values()).sort((a: any, b: any) => 
          (b.sequence || b.height || 0) - (a.sequence || a.height || 0)
        );
        const latest = sorted[0] as any;
        lastCheckpointHeight = latest?.sequence || latest?.height || latest?.blockHeight;
        lastCheckpointTimestamp = latest?.timestamp;
      }
      
      res.json({
        success: true,
        itemRecord: {
          ...item,
          status: 'active',
          manufacturerDisplayName,
          issuerRole,
          mintedByOfficialManufacturer,
          verificationStatus,
          operatorSignaturesCount,
          operatorSignatures: registrationEventSignatures,
          lastCheckpointHeight,
          lastCheckpointTimestamp,
        }
      });
    });

    this.app.get('/api/registry/owner/:address', (req: Request, res: Response) => {
      const items = Array.from(this.state.items.values())
        .filter((item: any) => item.currentOwner === req.params.address);
      res.json({ items });
    });

    // ============================================================
    // ITEM SEARCH API - Makes Autho the definitive title protocol
    // ============================================================

    // Full-text and filtered search for items
    this.app.get('/api/search/items', (req: Request, res: Response) => {
      try {
        if (!this.itemSearchEngine) {
          this.itemSearchEngine = new ItemSearchEngine(this.state.items);
        }

        const query = {
          text: req.query.q as string,
          manufacturer: req.query.manufacturer as string,
          model: req.query.model as string,
          brand: req.query.brand as string,
          category: req.query.category as string,
          serialNumber: req.query.serial as string,
          serialNumberHash: req.query.serialHash as string,
          imageHash: req.query.imageHash as string,
          owner: req.query.owner as string,
          authenticatedOnly: req.query.authenticated === 'true',
          verifiedOnly: req.query.verified === 'true',
          officialOnly: req.query.official === 'true',
          minConfidence: req.query.minConfidence as 'low' | 'medium' | 'high',
          limit: parseInt(req.query.limit as string) || 50,
          offset: parseInt(req.query.offset as string) || 0,
        };

        const results = this.itemSearchEngine.search(query);
        const stats = this.itemSearchEngine.getStats();

        res.json({
          success: true,
          query,
          results: results.map(r => ({
            item: r.item,
            score: r.score,
            matchedFields: r.matchedFields,
            isDuplicate: r.isDuplicate,
            duplicateOf: r.duplicateOf,
          })),
          total: results.length,
          stats,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Check for duplicates before registration (customer verification)
    this.app.get('/api/search/duplicates', (req: Request, res: Response) => {
      try {
        if (!this.itemSearchEngine) {
          this.itemSearchEngine = new ItemSearchEngine(this.state.items);
        }

        const manufacturer = req.query.manufacturer as string;
        const serial = req.query.serial as string;
        const imageHashes = req.query.imageHashes 
          ? (req.query.imageHashes as string).split(',')
          : undefined;

        if (!manufacturer || !serial) {
          res.status(400).json({ 
            success: false, 
            error: 'manufacturer and serial are required' 
          });
          return;
        }

        const result = this.itemSearchEngine.checkForDuplicates(
          manufacturer,
          serial,
          imageHashes
        );

        res.json({
          success: true,
          hasDuplicates: result.hasDuplicates,
          existingItems: result.existingItems,
          message: result.hasDuplicates
            ? `⚠️ Found ${result.existingItems.length} existing item(s) with same serial/manufacturer`
            : '✅ No duplicates found - safe to register',
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Find items by image hash (verify image authenticity)
    this.app.get('/api/search/image/:imageHash', (req: Request, res: Response) => {
      try {
        if (!this.itemSearchEngine) {
          this.itemSearchEngine = new ItemSearchEngine(this.state.items);
        }

        const items = this.itemSearchEngine.findByImageHash(req.params.imageHash);

        res.json({
          success: true,
          imageHash: req.params.imageHash,
          matchingItems: items,
          count: items.length,
          message: items.length > 0
            ? `Found ${items.length} item(s) with this image`
            : 'No items found with this image hash',
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get all items from a manufacturer
    this.app.get('/api/search/manufacturer/:manufacturerId', (req: Request, res: Response) => {
      try {
        if (!this.itemSearchEngine) {
          this.itemSearchEngine = new ItemSearchEngine(this.state.items);
        }

        const items = this.itemSearchEngine.getByManufacturer(req.params.manufacturerId);

        res.json({
          success: true,
          manufacturerId: req.params.manufacturerId,
          items,
          count: items.length,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Hash an image (utility endpoint)
    this.app.post('/api/search/hash-image', express.raw({ type: ['image/*'], limit: '10mb' }), (req: Request, res: Response) => {
      try {
        if (!req.body || req.body.length === 0) {
          res.status(400).json({ success: false, error: 'No image data provided' });
          return;
        }

        const hash = hashImage(req.body);

        res.json({
          success: true,
          imageHash: hash,
          size: req.body.length,
          message: 'Store this hash on the ledger with your item registration',
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Verify an image matches a stored hash
    this.app.post('/api/search/verify-image', express.raw({ type: ['image/*'], limit: '10mb' }), (req: Request, res: Response) => {
      try {
        const expectedHash = req.query.hash as string;
        if (!expectedHash) {
          res.status(400).json({ success: false, error: 'hash query parameter required' });
          return;
        }

        if (!req.body || req.body.length === 0) {
          res.status(400).json({ success: false, error: 'No image data provided' });
          return;
        }

        const isValid = verifyImageHash(req.body, expectedHash);
        const actualHash = hashImage(req.body);

        res.json({
          success: true,
          isValid,
          expectedHash,
          actualHash,
          message: isValid
            ? '✅ Image matches the stored hash - authentic'
            : '❌ Image does NOT match - possible tampering or different image',
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Search index stats
    this.app.get('/api/search/stats', (req: Request, res: Response) => {
      try {
        if (!this.itemSearchEngine) {
          this.itemSearchEngine = new ItemSearchEngine(this.state.items);
        }

        const stats = this.itemSearchEngine.getStats();

        res.json({
          success: true,
          stats,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Rebuild search index (admin)
    this.app.post('/api/search/reindex', (req: Request, res: Response) => {
      try {
        const startTime = Date.now();
        this.itemSearchEngine = new ItemSearchEngine(this.state.items);
        const elapsed = Date.now() - startTime;
        const stats = this.itemSearchEngine.getStats();

        res.json({
          success: true,
          message: `Search index rebuilt in ${elapsed}ms`,
          stats,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // END ITEM SEARCH API
    // ============================================================

    // ============================================================
    // ENTITY REGISTRY API - Global manufacturers, artists, athletes
    // ============================================================

    // Initialize entity registry helper
    const getEntityRegistry = (): EntityRegistry => {
      if (!this.entityRegistry) {
        this.entityRegistry = new EntityRegistry(this.canonicalEventStore);
        this.entityRegistry.loadSeedData();
      }
      return this.entityRegistry;
    };

    // Search/autocomplete entities (for minting UI)
    this.app.get('/api/entities/search', (req: Request, res: Response) => {
      try {
        const registry = getEntityRegistry();
        const query = String(req.query.q || '').trim();
        
        if (!query || query.length < 2) {
          res.status(400).json({ success: false, error: 'Query must be at least 2 characters' });
          return;
        }

        const types = req.query.types 
          ? (req.query.types as string).split(',') as EntityType[]
          : undefined;
        const categories = req.query.categories
          ? (req.query.categories as string).split(',') as EntityCategory[]
          : undefined;
        const verifiedOnly = req.query.verifiedOnly === 'true';
        const limit = Math.min(parseInt(req.query.limit as string) || 20, 50);

        const results = registry.search({
          query,
          types,
          categories,
          verifiedOnly,
          limit,
        });

        res.json({
          success: true,
          query,
          count: results.length,
          results: results.map(r => ({
            entity: r.entity,
            score: r.score,
            matchedOn: r.matchedOn,
          })),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get entity by ID
    this.app.get('/api/entities/:entityId', (req: Request, res: Response) => {
      try {
        const registry = getEntityRegistry();
        const entity = registry.getById(req.params.entityId);
        
        if (!entity) {
          res.status(404).json({ success: false, error: 'Entity not found' });
          return;
        }

        res.json({ success: true, entity });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get entities by type (e.g., all manufacturers)
    this.app.get('/api/entities/type/:type', (req: Request, res: Response) => {
      try {
        const registry = getEntityRegistry();
        const type = req.params.type as EntityType;
        const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
        
        const entities = registry.getByType(type, limit);

        res.json({
          success: true,
          type,
          count: entities.length,
          entities,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get entities by category
    this.app.get('/api/entities/category/:category', (req: Request, res: Response) => {
      try {
        const registry = getEntityRegistry();
        const category = req.params.category as EntityCategory;
        const limit = Math.min(parseInt(req.query.limit as string) || 100, 500);
        
        const entities = registry.getByCategory(category, limit);

        res.json({
          success: true,
          category,
          count: entities.length,
          entities,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Resolve a name to best matching entity
    this.app.get('/api/entities/resolve', (req: Request, res: Response) => {
      try {
        const registry = getEntityRegistry();
        const name = String(req.query.name || '').trim();
        const type = req.query.type as EntityType | undefined;
        
        if (!name) {
          res.status(400).json({ success: false, error: 'Name required' });
          return;
        }

        const entity = registry.resolveEntity(name, type);

        res.json({
          success: true,
          name,
          resolved: !!entity,
          entity: entity || null,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Check for potential duplicates before adding
    this.app.get('/api/entities/duplicates', async (req: Request, res: Response) => {
      try {
        const registry = getEntityRegistry();
        const name = String(req.query.name || '').trim();
        const type = req.query.type as EntityType;
        
        if (!name || !type) {
          res.status(400).json({ success: false, error: 'Name and type required' });
          return;
        }

        const duplicates = await registry.findPotentialDuplicates(name, type);

        res.json({
          success: true,
          name,
          type,
          hasPotentialDuplicates: duplicates.length > 0,
          duplicates: duplicates.map(d => ({
            entity: d.entity,
            score: d.score,
          })),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Register a new entity (requires authentication)
    this.app.post('/api/entities', async (req: Request, res: Response) => {
      try {
        const registry = getEntityRegistry();
        const { 
          type, canonicalName, displayName, aliases, categories,
          description, country, foundedYear, socialLinks, logoUrl
        } = req.body;

        // Basic validation
        if (!type || !canonicalName || !displayName || !categories) {
          res.status(400).json({ 
            success: false, 
            error: 'Required fields: type, canonicalName, displayName, categories' 
          });
          return;
        }

        // For now, use 'user' as createdBy - in production, get from auth
        const createdBy = req.body.accountId || 'anonymous';

        const entity = await registry.registerEntity({
          type,
          canonicalName,
          displayName,
          aliases: aliases || [],
          categories,
          verificationStatus: 'user_submitted',
          description,
          country,
          foundedYear,
          socialLinks,
          logoUrl,
        }, createdBy);

        res.json({
          success: true,
          message: 'Entity registered successfully',
          entity,
        });
      } catch (error: any) {
        if (error.message.includes('already exists')) {
          res.status(409).json({ success: false, error: error.message });
        } else {
          res.status(500).json({ success: false, error: error.message });
        }
      }
    });

    // Add alias to existing entity
    this.app.post('/api/entities/:entityId/aliases', async (req: Request, res: Response) => {
      try {
        const registry = getEntityRegistry();
        const { alias, language, isCommonMisspelling } = req.body;
        
        if (!alias) {
          res.status(400).json({ success: false, error: 'Alias required' });
          return;
        }

        const addedBy = req.body.accountId || 'anonymous';
        const entity = await registry.addAlias(
          req.params.entityId,
          { alias, language, isCommonMisspelling },
          addedBy
        );

        res.json({
          success: true,
          message: 'Alias added successfully',
          entity,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get entity registry statistics
    this.app.get('/api/entities/stats', (req: Request, res: Response) => {
      try {
        const registry = getEntityRegistry();
        const stats = registry.getStats();

        res.json({
          success: true,
          stats,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // END ENTITY REGISTRY API
    // ============================================================

    // ============================================================
    // EPHEMERAL MESSAGING API - Encrypted, auto-deleting messages
    // ============================================================

    this.app.post('/api/messages/keys', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const encryptionPublicKeyHex = String(req.body?.encryptionPublicKeyHex || '').trim().toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(encryptionPublicKeyHex)) {
          res.status(400).json({ success: false, error: 'Invalid encryptionPublicKeyHex' });
          return;
        }

        const now = Date.now();
        this.messagingEncryptionKeyRegistry.set(account.accountId, { encryptionPublicKeyHex, updatedAt: now });

        let walletAddress = '';
        let walletPublicKey = '';
        try {
          const fullAccount: any = this.state.accounts.get(account.accountId);
          walletAddress = String(fullAccount?.walletAddress || fullAccount?.identityAddress || '').trim();
          walletPublicKey = String(fullAccount?.walletPublicKey || fullAccount?.publicKey || '').trim().toLowerCase();
          if (walletAddress) {
            this.messagingEncryptionKeyRegistry.set(walletAddress, { encryptionPublicKeyHex, updatedAt: now });
          }
          // Also index by wallet publicKey - this is what the client uses to look up recipients
          if (walletPublicKey && /^[0-9a-f]{64,66}$/.test(walletPublicKey)) {
            this.messagingEncryptionKeyRegistry.set(walletPublicKey, { encryptionPublicKeyHex, updatedAt: now });
          }
        } catch {}

        try {
          const expiresAt = now + (10 * 365 * 24 * 60 * 60 * 1000);
          const event = await this.ephemeralStore!.appendEvent(
            EphemeralEventType.MESSAGING_KEY_PUBLISHED,
            {
              accountId: account.accountId,
              walletAddress,
              walletPublicKey,
              encryptionPublicKeyHex,
              updatedAt: now,
            },
            expiresAt
          );

          this.broadcastEphemeralEvent(event);
        } catch {}

        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message || 'Failed to publish key' });
      }
    });

    this.app.get('/api/messages/keys/:id', async (req: Request, res: Response) => {
      try {
        // Allow operator-to-operator requests without authentication (for cross-operator key lookup)
        const isInternalRequest = req.headers['x-internal-request'] === 'operator-to-operator';
        
        if (!isInternalRequest) {
          const account = await this.getAccountFromSession(req);
          if (!account) {
            res.status(401).json({ success: false, error: 'Authentication required' });
            return;
          }
        }

        const id = String(req.params.id || '').trim();
        if (!id) {
          res.status(400).json({ success: false, error: 'id required' });
          return;
        }

        let rec: { encryptionPublicKeyHex: string; updatedAt: number; } | undefined | null = this.messagingEncryptionKeyRegistry.get(id);
        
        // If not found locally and this is a client request, try to fetch from peer operators
        // Don't recurse if this is already an internal request
        if (!rec && !isInternalRequest) {
          rec = await this.fetchEncryptionKeyFromNetwork(id);
        }
        
        if (!rec) {
          res.status(404).json({ success: false, error: 'Messaging key not found' });
          return;
        }

        res.json({ success: true, encryptionPublicKeyHex: rec.encryptionPublicKeyHex, updatedAt: rec.updatedAt });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message || 'Failed to get key' });
      }
    });

    // Publish encrypted messaging vault blob (for multi-device + history sync)
    this.app.post('/api/messages/vault', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const vaultEpoch = String(req.body?.vaultEpoch || '').trim();
        const vaultVersion = Number(req.body?.vaultVersion || 0);
        const kdf = req.body?.kdf;
        const enc = req.body?.enc;

        if (!vaultEpoch) {
          res.status(400).json({ success: false, error: 'vaultEpoch required' });
          return;
        }
        if (!Number.isFinite(vaultVersion) || vaultVersion < 0) {
          res.status(400).json({ success: false, error: 'vaultVersion required' });
          return;
        }
        if (!kdf || !enc) {
          res.status(400).json({ success: false, error: 'kdf and enc required' });
          return;
        }

        const updatedAt = Date.now();
        const payload = {
          accountId: account.accountId,
          vaultEpoch,
          vaultVersion,
          updatedAt,
          kdf,
          enc,
        };

        const expiresAt = updatedAt + (100 * 365 * 24 * 60 * 60 * 1000);
        const event = await this.ephemeralStore!.appendEvent(
          EphemeralEventType.MESSAGING_VAULT_PUBLISHED,
          payload,
          expiresAt
        );

        this.broadcastEphemeralEvent(event);

        res.json({ success: true, eventId: event.eventId, expiresAt: event.expiresAt });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message || 'Failed to publish vault' });
      }
    });

    // Get latest encrypted messaging vault blob for current user
    this.app.get('/api/messages/vault', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const event = this.ephemeralStore!.getLatestMessagingVault(account.accountId);
        if (!event) {
          res.status(404).json({ success: false, error: 'Vault not found' });
          return;
        }

        res.json({
          success: true,
          eventId: event.eventId,
          timestamp: event.timestamp,
          expiresAt: event.expiresAt,
          vault: event.payload,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message || 'Failed to get vault' });
      }
    });

    // Send a message (E2E encrypted - platform never sees content)
    this.app.post('/api/messages/send', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { 
          recipientId, 
          encryptedContent, 
          encryptedForSender, 
          itemId, 
          replyToMessageId, 
          conversationId: providedConversationId,
          // New disappearing message fields
          mediaType,
          selfDestructAfter,
          expiresAfterView,
        } = req.body;

        if (!recipientId || !encryptedContent) {
          res.status(400).json({ success: false, error: 'recipientId and encryptedContent required' });
          return;
        }

        // Check if blocked
        if (this.ephemeralStore?.isBlocked(recipientId, account.accountId)) {
          res.status(403).json({ success: false, error: 'You are blocked by this user' });
          return;
        }

        // Use provided conversationId (for replies) or generate new one
        const conversationId = providedConversationId || this.ephemeralStore!.generateConversationId(
          account.accountId, recipientId, itemId
        );

        const messageId = `msg_${Date.now()}_${randomBytes(8).toString('hex')}`;

        const payload: MessagePayload = {
          messageId,
          senderId: account.accountId,
          recipientId,
          encryptedContent,
          encryptedForSender: encryptedForSender || encryptedContent,
          itemId,
          conversationId,
          replyToMessageId,
          // Disappearing message fields
          mediaType: mediaType || 'text',
          selfDestructAfter: selfDestructAfter || undefined,
          expiresAfterView: expiresAfterView || false,
        };

        const event = await this.ephemeralStore!.appendEvent(
          EphemeralEventType.MESSAGE_SENT,
          payload
        );

        // Broadcast to operator peers for decentralized delivery
        this.broadcastEphemeralEvent(event);

        res.json({
          success: true,
          messageId,
          conversationId,
          expiresAt: event.expiresAt,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get user's conversations (inbox)
    this.app.get('/api/messages/conversations', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        // Get conversations by accountId (public key)
        const conversationsByAccountId = this.ephemeralStore!.getUserConversations(account.accountId);
        
        // Also get conversations by walletAddress (Bitcoin address) since some messages use that as recipientId
        const fullAccount = this.state.accounts.get(account.accountId) as any;
        const walletAddress = fullAccount?.walletAddress || fullAccount?.identityAddress;
        const conversationsByWallet = walletAddress 
          ? this.ephemeralStore!.getUserConversations(walletAddress)
          : [];
        
        // Merge and deduplicate conversations
        const conversationMap = new Map<string, typeof conversationsByAccountId[0]>();
        for (const conv of conversationsByAccountId) {
          conversationMap.set(conv.conversationId, conv);
        }
        for (const conv of conversationsByWallet) {
          if (!conversationMap.has(conv.conversationId)) {
            conversationMap.set(conv.conversationId, conv);
          }
        }
        const conversations = Array.from(conversationMap.values());

        // Enrich with participant info
        const enriched = conversations.map(conv => ({
          ...conv,
          participantInfo: conv.participants.map(p => {
            const acc = this.state.accounts.get(p);
            return {
              accountId: p,
              displayName: acc?.username || acc?.companyName || p.substring(0, 12) + '...',
            };
          }),
        }));

        res.json({
          success: true,
          conversations: enriched,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get messages in a conversation
    this.app.get('/api/messages/conversation/:conversationId', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        // Pagination params
        const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
        const before = parseInt(req.query.before as string) || Date.now() + 1000;

        const rawMessages = this.ephemeralStore!.getConversationMessages(req.params.conversationId);

        // Get user's walletAddress to match against recipientId (which may be Bitcoin address)
        const fullAccount = this.state.accounts.get(account.accountId) as any;
        const walletAddress = fullAccount?.walletAddress || fullAccount?.identityAddress;

        // OPTIMIZATION: Filter FIRST (lightweight), then restore content only for filtered messages
        const filtered = rawMessages.filter(m => {
          const p = m.payload as MessagePayload;
          const isUserSender = p.senderId === account.accountId || p.senderId === walletAddress;
          const isUserRecipient = p.recipientId === account.accountId || p.recipientId === walletAddress;
          return isUserSender || isUserRecipient;
        });

        // Sort by timestamp descending, apply pagination
        const sorted = filtered
          .filter(m => m.timestamp < before)
          .sort((a, b) => b.timestamp - a.timestamp)
          .slice(0, limit);

        // Restore content only for the paginated subset (much faster)
        const messages = await this.ephemeralStore!.restoreEventsContent(sorted);

        // Return in chronological order for display
        const chronological = messages.sort((a, b) => a.timestamp - b.timestamp);

        res.json({
          success: true,
          conversationId: req.params.conversationId,
          hasMore: filtered.length > limit,
          messages: chronological.map(m => ({
            messageId: m.payload.messageId,
            senderId: m.payload.senderId,
            recipientId: m.payload.recipientId,
            encryptedContent: (m.payload.senderId === account.accountId || m.payload.senderId === walletAddress)
              ? m.payload.encryptedForSender 
              : m.payload.encryptedContent,
            itemId: m.payload.itemId,
            timestamp: m.timestamp,
            expiresAt: m.expiresAt,
            replyToMessageId: m.payload.replyToMessageId,
            mediaType: m.payload.mediaType,
            expiresAfterView: m.payload.expiresAfterView,
            viewedAt: m.payload.viewedAt,
            selfDestructAfter: m.payload.selfDestructAfter,
          })),
        });
      } catch (error: any) {
        console.error('[Messaging] Get messages error:', error);
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Delete a message early (paid feature)
    this.app.delete('/api/messages/:messageId', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        // TODO: Verify payment for early deletion

        const deleted = await this.ephemeralStore!.deleteMessage(
          req.params.messageId,
          account.accountId
        );

        if (!deleted) {
          res.status(404).json({ success: false, error: 'Message not found or not authorized' });
          return;
        }

        res.json({ success: true, message: 'Message deleted' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Add a contact
    this.app.post('/api/messages/contacts', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { contactId, displayName } = req.body;
        if (!contactId) {
          res.status(400).json({ success: false, error: 'contactId required' });
          return;
        }

        const payload: ContactPayload = {
          userId: account.accountId,
          contactId,
          displayName,
        };

        // Contacts are permanent - set expiration 100 years in the future
        const permanentExpiry = Date.now() + (100 * 365 * 24 * 60 * 60 * 1000);
        await this.ephemeralStore!.appendEvent(EphemeralEventType.CONTACT_ADDED, payload, permanentExpiry);

        res.json({ success: true, message: 'Contact added' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get contacts
    this.app.get('/api/messages/contacts', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const contactIds = this.ephemeralStore!.getUserContacts(account.accountId);

        // Enrich with account info
        const contacts = contactIds.map(id => {
          const acc = this.state.accounts.get(id);
          return {
            accountId: id,
            displayName: acc?.username || acc?.companyName || id.substring(0, 12) + '...',
            isManufacturer: acc?.role === 'manufacturer',
            isAuthenticator: acc?.role === 'authenticator',
          };
        });

        res.json({ success: true, contacts });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Block a user
    this.app.post('/api/messages/block', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { blockId } = req.body;
        if (!blockId) {
          res.status(400).json({ success: false, error: 'blockId required' });
          return;
        }

        const payload: ContactPayload = {
          userId: account.accountId,
          contactId: blockId,
        };

        await this.ephemeralStore!.appendEvent(EphemeralEventType.CONTACT_BLOCKED, payload);

        res.json({ success: true, message: 'User blocked' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get messaging stats
    this.app.get('/api/messages/stats', (req: Request, res: Response) => {
      try {
        const stats = this.ephemeralStore!.getStats();
        res.json({ success: true, stats });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Debug endpoint - show all messages in ephemeral store (for testing P2P sync)
    this.app.get('/api/messages/debug', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        const allEvents = this.ephemeralStore!.getAllEvents();
        const stats = this.ephemeralStore!.getStats();
        
        // Summarize messages (don't expose encrypted content)
        const messageSummary = allEvents
          .filter(e => e.eventType === 'MESSAGE_SENT')
          .map(e => ({
            eventId: e.eventId,
            senderId: e.payload?.senderId,
            recipientId: e.payload?.recipientId,
            conversationId: e.payload?.conversationId,
            timestamp: new Date(e.timestamp).toISOString(),
          }));

        res.json({
          success: true,
          currentUser: account?.accountId || 'not authenticated',
          stats,
          totalEvents: allEvents.length,
          messageSummary,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // PREMIUM SERVICE ENDPOINTS
    // ============================================================

    // Get account service balance (needed by client-side fetchServiceBalance)
    this.app.get('/api/accounts/:accountId/service-balance', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const account = this.state.accounts.get(String(accountId));
        if (!account) {
          // Try alternate lookups (walletAddress, identityAddress)
          let found: any = null;
          for (const [key, acc] of this.state.accounts.entries()) {
            const accAny = acc as any;
            if (accAny.walletAddress === accountId ||
                accAny.identityAddress === accountId ||
                accAny.paymentAddress === accountId) {
              found = acc;
              break;
            }
          }
          if (!found) {
            res.status(404).json({ success: false, error: 'Account not found' });
            return;
          }
          res.json({
            success: true,
            accountId: String(accountId),
            serviceBalanceSats: (found as any).serviceBalanceSats || 0,
            serviceBalanceLastFundedAt: (found as any).serviceBalanceLastFundedAt,
            serviceBalanceTotalFundedSats: (found as any).serviceBalanceTotalFundedSats || 0,
            serviceBalanceTotalUsedSats: (found as any).serviceBalanceTotalUsedSats || 0,
          });
          return;
        }
        res.json({
          success: true,
          accountId: String(accountId),
          serviceBalanceSats: (account as any).serviceBalanceSats || 0,
          serviceBalanceLastFundedAt: (account as any).serviceBalanceLastFundedAt,
          serviceBalanceTotalFundedSats: (account as any).serviceBalanceTotalFundedSats || 0,
          serviceBalanceTotalUsedSats: (account as any).serviceBalanceTotalUsedSats || 0,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Premium action: Generic service balance deduction (file transfer, message delete/edit, etc.)
    // Gateway relays include { accountId, tier, amountSats, action }
    this.app.post('/api/service/premium/file-transfer', async (req: Request, res: Response) => {
      try {
        const { accountId, tier, fileSize, fileName, amountSats, action } = req.body;
        
        // File tier costs (must match client-side FILE_TIERS)
        const tierCosts: Record<string, number> = {
          free: 0,
          basic: 500,      // 25 MB
          premium: 2000,   // 100 MB
          enterprise: 10000, // 1 GB
        };

        // Use explicit amountSats from relay when provided, otherwise derive from tier
        const actionCost = typeof amountSats === 'number' && amountSats > 0
          ? amountSats
          : (tierCosts[tier] || 0);
        const actionPurpose = action || 'file_transfer';

        if (!accountId) {
          res.status(400).json({ success: false, error: 'Missing required field: accountId' });
          return;
        }

        // Free tier doesn't require payment
        if (actionCost === 0) {
          res.json({
            success: true,
            accountId: String(accountId),
            tier: tier || 'free',
            costSats: 0,
            message: 'Free tier - no payment required',
          });
          return;
        }

        // For premium tiers, check account balance and deduct
        let account = this.state.accounts.get(String(accountId));
        if (!account) {
          // Try alternate lookups (walletAddress, identityAddress, paymentAddress)
          for (const [key, acc] of this.state.accounts.entries()) {
            const accAny = acc as any;
            if (accAny.walletAddress === accountId ||
                accAny.identityAddress === accountId ||
                accAny.paymentAddress === accountId) {
              account = acc;
              console.log(`[Premium] Found account by alternate key: ${key} for lookup: ${accountId}`);
              break;
            }
          }
        }
        if (!account) {
          console.log(`[Premium] Account not found for ID: ${accountId}, total accounts: ${this.state.accounts.size}`);
          res.status(404).json({ success: false, error: 'Account not found', accountId });
          return;
        }

        const resolvedAccountId = String((account as any).accountId || accountId).trim();
        const currentBalance = (account as any).serviceBalanceSats || 0;
        console.log(`[Premium] Account ${resolvedAccountId} (lookup: ${accountId}) balance: ${currentBalance} sats, required: ${actionCost}`);
        // When amountSats is explicitly provided this is a relay from a gateway that
        // already validated the user's balance.  Skip the operator-side balance check
        // because the operator ledger may not have received funding events yet.
        const isRelay = typeof amountSats === 'number' && amountSats > 0;
        if (!isRelay && currentBalance < actionCost) {
          res.status(402).json({
            success: false,
            error: 'Insufficient service balance',
            required: actionCost,
            available: currentBalance,
            shortfall: actionCost - currentBalance,
          });
          return;
        }

        // Deduct from service balance by emitting event to ledger
        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.config.publicKey || '',
            signature: createHash('sha256')
              .update(`ACCOUNT_SERVICE_BALANCE_USED:${resolvedAccountId}:${actionPurpose}:${tier || 'none'}:${actionCost}:${now}`)
              .digest('hex'),
          },
        ];

        const eventPayload = {
            type: EventType.ACCOUNT_SERVICE_BALANCE_USED,
            timestamp: now,
            nonce,
            accountId: resolvedAccountId,
            amountSats: actionCost,
            action: actionPurpose,
            actionId: `${tier || 'none'}_${fileSize || 0}_${now}`,
          };

        await this.canonicalEventStore.appendEvent(eventPayload as any, signatures);

        // Forward deduction event to seed node so canonical ledger stays in sync
        const seedResult = await this.submitCanonicalEventToSeed(eventPayload, signatures);
        if (!seedResult.ok) {
          console.warn(`[Premium] Failed to sync deduction to seed: ${seedResult.error}`);
        }

        // Update in-memory state immediately so UI/gateways see the deduction without a full rebuild
        (account as any).serviceBalanceSats = currentBalance - actionCost;
        (account as any).serviceBalanceTotalUsedSats = ((account as any).serviceBalanceTotalUsedSats || 0) + actionCost;
        (account as any).updatedAt = now;

        this.broadcastRegistryUpdate();

        console.log(`[Premium] ${actionPurpose}: ${actionCost} sats deducted from account ${accountId} (tier=${tier || 'n/a'}, synced=${seedResult.ok})`);

        res.json({
          success: true,
          accountId: String(accountId),
          tier: tier || 'none',
          action: actionPurpose,
          fileName: fileName || 'file',
          fileSize: fileSize || 0,
          costSats: actionCost,
          newBalance: currentBalance - actionCost,
          message: `${actionPurpose} approved (${actionCost} sats)`,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Relay endpoint: Gateway credits a user's service balance and
    // forwards the funding event here so the canonical ledger stays
    // in sync.  Deduplicated by txid.
    this.app.post('/api/service/relay-funding', async (req: Request, res: Response) => {
      try {
        const { accountId, amountSats, txid } = req.body;

        if (!accountId || typeof amountSats !== 'number' || amountSats <= 0 || !txid) {
          res.status(400).json({ success: false, error: 'Missing accountId, amountSats, or txid' });
          return;
        }

        const account = this.state.accounts.get(String(accountId));
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        // Deduplicate by txid – avoid double-crediting on retries
        const dedupeKey = `funded:${txid}`;
        if ((this as any)._relayedFundingTxids?.has(dedupeKey)) {
          res.json({ success: true, duplicate: true, message: 'Funding already recorded' });
          return;
        }
        if (!(this as any)._relayedFundingTxids) {
          (this as any)._relayedFundingTxids = new Set<string>();
        }
        (this as any)._relayedFundingTxids.add(dedupeKey);

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.config.publicKey || '',
            signature: createHash('sha256')
              .update(`ACCOUNT_SERVICE_BALANCE_FUNDED:${accountId}:${amountSats}:${txid}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_SERVICE_BALANCE_FUNDED,
            timestamp: now,
            nonce,
            accountId: String(accountId),
            amountSats,
            txid,
          } as any,
          signatures
        );

        // Update in-memory state
        const prev = (account as any).serviceBalanceSats || 0;
        (account as any).serviceBalanceSats = prev + amountSats;
        (account as any).serviceBalanceLastFundedAt = now;
        (account as any).serviceBalanceTotalFundedSats = ((account as any).serviceBalanceTotalFundedSats || 0) + amountSats;
        (account as any).updatedAt = now;

        this.broadcastRegistryUpdate();

        console.log(`[Funding Relay] Credited ${amountSats} sats to ${accountId} (txid=${txid}). Balance: ${prev} -> ${prev + amountSats}`);

        res.json({
          success: true,
          accountId: String(accountId),
          amountCredited: amountSats,
          txid,
          newBalance: prev + amountSats,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // GROUP CHAT ENDPOINTS
    // ============================================================

    // Create a new group
    this.app.post('/api/messages/groups', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { name, memberIds } = req.body;
        if (!name || !memberIds || !Array.isArray(memberIds) || memberIds.length === 0) {
          res.status(400).json({ success: false, error: 'name and memberIds array required' });
          return;
        }

        // Creator is always a member and admin
        const members = [account.accountId, ...memberIds.filter((id: string) => id !== account.accountId)];
        const groupId = this.ephemeralStore!.generateGroupId();

        const payload: GroupPayload = {
          groupId,
          name,
          members,
          admins: [account.accountId],
          createdBy: account.accountId,
          createdAt: Date.now(),
        };

        // Groups are permanent (100 year expiry like contacts)
        const permanentExpiry = Date.now() + (100 * 365 * 24 * 60 * 60 * 1000);
        const event = await this.ephemeralStore!.appendEvent(
          EphemeralEventType.GROUP_CREATED,
          payload,
          permanentExpiry
        );

        // Broadcast to P2P network
        this.broadcastEphemeralEvent(event);

        res.json({ success: true, groupId, group: payload });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get user's groups
    this.app.get('/api/messages/groups', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const groups = this.ephemeralStore!.getUserGroups(account.accountId);
        
        // Add last message info for each group
        const groupsWithMeta = groups.map(group => {
          const messages = this.ephemeralStore!.getGroupMessages(group.groupId);
          const lastMessage = messages.length > 0 ? messages[messages.length - 1] : null;
          return {
            ...group,
            lastMessageAt: lastMessage?.timestamp || group.createdAt,
            messageCount: messages.length,
          };
        });

        // Sort by last activity
        groupsWithMeta.sort((a, b) => b.lastMessageAt - a.lastMessageAt);

        res.json({ success: true, groups: groupsWithMeta });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get group details
    this.app.get('/api/messages/groups/:groupId', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const group = this.ephemeralStore!.getGroup(req.params.groupId);
        if (!group) {
          res.status(404).json({ success: false, error: 'Group not found' });
          return;
        }

        if (!group.members.includes(account.accountId)) {
          res.status(403).json({ success: false, error: 'Not a member of this group' });
          return;
        }

        res.json({ success: true, group });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get group messages
    this.app.get('/api/messages/groups/:groupId/messages', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { groupId } = req.params;
        
        if (!this.ephemeralStore!.isGroupMember(groupId, account.accountId)) {
          res.status(403).json({ success: false, error: 'Not a member of this group' });
          return;
        }

        const rawMessages = this.ephemeralStore!.getGroupMessages(groupId);
        
        // Restore any extracted large content from disk
        const messages = await this.ephemeralStore!.restoreEventsContent(rawMessages);
        
        // Return messages with the encrypted content for current user
        const userMessages = messages.map(m => {
          const payload = m.payload as GroupMessagePayload;
          return {
            messageId: payload.messageId,
            groupId: payload.groupId,
            senderId: payload.senderId,
            encryptedContent: payload.encryptedContentByMember[account.accountId],
            timestamp: m.timestamp,
            expiresAt: m.expiresAt,
            replyToMessageId: payload.replyToMessageId,
          };
        });

        res.json({ success: true, groupId, messages: userMessages });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Send message to group
    this.app.post('/api/messages/groups/:groupId/send', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { groupId } = req.params;
        const { 
          encryptedContentByMember, 
          replyToMessageId,
          // Disappearing message fields
          mediaType,
          selfDestructAfter,
          expiresAfterView,
        } = req.body;

        if (!encryptedContentByMember || typeof encryptedContentByMember !== 'object') {
          res.status(400).json({ success: false, error: 'encryptedContentByMember object required' });
          return;
        }

        if (!this.ephemeralStore!.isGroupMember(groupId, account.accountId)) {
          res.status(403).json({ success: false, error: 'Not a member of this group' });
          return;
        }

        const messageId = `gmsg_${Date.now()}_${randomBytes(8).toString('hex')}`;

        const payload: GroupMessagePayload = {
          messageId,
          groupId,
          senderId: account.accountId,
          encryptedContentByMember,
          replyToMessageId,
          // Disappearing message fields
          mediaType: mediaType || 'text',
          selfDestructAfter: selfDestructAfter || undefined,
          expiresAfterView: expiresAfterView || false,
        };

        const event = await this.ephemeralStore!.appendEvent(
          EphemeralEventType.GROUP_MESSAGE_SENT,
          payload
        );

        // Broadcast to P2P network
        this.broadcastEphemeralEvent(event);

        res.json({ success: true, messageId, expiresAt: event.expiresAt });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Add member to group (admin only)
    this.app.post('/api/messages/groups/:groupId/members', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { groupId } = req.params;
        const { memberId } = req.body;

        if (!memberId) {
          res.status(400).json({ success: false, error: 'memberId required' });
          return;
        }

        if (!this.ephemeralStore!.isGroupAdmin(groupId, account.accountId)) {
          res.status(403).json({ success: false, error: 'Only admins can add members' });
          return;
        }

        const payload: GroupMemberPayload = {
          groupId,
          memberId,
          actorId: account.accountId,
        };

        const permanentExpiry = Date.now() + (100 * 365 * 24 * 60 * 60 * 1000);
        const event = await this.ephemeralStore!.appendEvent(
          EphemeralEventType.GROUP_MEMBER_ADDED,
          payload,
          permanentExpiry
        );

        this.broadcastEphemeralEvent(event);

        res.json({ success: true, message: 'Member added' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Remove member from group (admin only)
    this.app.delete('/api/messages/groups/:groupId/members/:memberId', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { groupId, memberId } = req.params;

        if (!this.ephemeralStore!.isGroupAdmin(groupId, account.accountId)) {
          res.status(403).json({ success: false, error: 'Only admins can remove members' });
          return;
        }

        const payload: GroupMemberPayload = {
          groupId,
          memberId,
          actorId: account.accountId,
        };

        const permanentExpiry = Date.now() + (100 * 365 * 24 * 60 * 60 * 1000);
        const event = await this.ephemeralStore!.appendEvent(
          EphemeralEventType.GROUP_MEMBER_REMOVED,
          payload,
          permanentExpiry
        );

        this.broadcastEphemeralEvent(event);

        res.json({ success: true, message: 'Member removed' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Leave group
    this.app.post('/api/messages/groups/:groupId/leave', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { groupId } = req.params;

        if (!this.ephemeralStore!.isGroupMember(groupId, account.accountId)) {
          res.status(403).json({ success: false, error: 'Not a member of this group' });
          return;
        }

        const payload: GroupMemberPayload = {
          groupId,
          memberId: account.accountId,
          actorId: account.accountId,
        };

        const permanentExpiry = Date.now() + (100 * 365 * 24 * 60 * 60 * 1000);
        const event = await this.ephemeralStore!.appendEvent(
          EphemeralEventType.GROUP_LEFT,
          payload,
          permanentExpiry
        );

        this.broadcastEphemeralEvent(event);

        res.json({ success: true, message: 'Left group' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // MESSAGE MANAGEMENT ENDPOINTS (Delete, View, Disappearing)
    // ============================================================

    // Delete a message (1-on-1)
    this.app.delete('/api/messages/:messageId', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { messageId } = req.params;
        const deleted = await this.ephemeralStore!.deleteMessage(messageId, account.accountId);
        
        if (!deleted) {
          res.status(404).json({ success: false, error: 'Message not found or not authorized' });
          return;
        }

        res.json({ success: true, message: 'Message deleted' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Delete a group message
    this.app.delete('/api/messages/groups/:groupId/messages/:messageId', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { messageId } = req.params;
        const deleted = await this.ephemeralStore!.deleteGroupMessage(messageId, account.accountId);
        
        if (!deleted) {
          res.status(404).json({ success: false, error: 'Message not found or not authorized' });
          return;
        }

        res.json({ success: true, message: 'Message deleted' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Mark message as viewed (for disappearing messages)
    this.app.post('/api/messages/:messageId/viewed', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { messageId } = req.params;
        const marked = await this.ephemeralStore!.markMessageViewed(messageId, account.accountId);
        
        if (!marked) {
          res.status(404).json({ success: false, error: 'Message not found or not authorized' });
          return;
        }

        // Get the updated message to return expiry info
        const message = this.ephemeralStore!.getMessage(messageId);
        
        res.json({ 
          success: true, 
          message: 'Message marked as viewed',
          expiresAt: message?.expiresAt
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get message details (including expiry info)
    this.app.get('/api/messages/:messageId', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { messageId } = req.params;
        const message = this.ephemeralStore!.getMessage(messageId);
        
        if (!message) {
          res.status(404).json({ success: false, error: 'Message not found' });
          return;
        }

        // Verify user is participant
        const payload = message.payload as MessagePayload;
        if (payload.senderId !== account.accountId && payload.recipientId !== account.accountId) {
          res.status(403).json({ success: false, error: 'Not authorized to view this message' });
          return;
        }

        res.json({ 
          success: true, 
          message: {
            messageId: message.eventId,
            timestamp: message.timestamp,
            expiresAt: message.expiresAt,
            mediaType: payload.mediaType,
            viewedAt: payload.viewedAt,
            expiresAfterView: payload.expiresAfterView,
            selfDestructAfter: payload.selfDestructAfter,
          }
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Start a conversation about an item (convenience endpoint)
    this.app.post('/api/messages/start-about-item', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }

        const { itemId, recipientId, encryptedContent, encryptedForSender } = req.body;

        if (!itemId || !encryptedContent) {
          res.status(400).json({ success: false, error: 'itemId and encryptedContent required' });
          return;
        }

        // Get item owner if recipientId not provided
        let targetRecipient = recipientId;
        if (!targetRecipient) {
          const item = this.state.items.get(itemId);
          if (!item) {
            res.status(404).json({ success: false, error: 'Item not found' });
            return;
          }
          // item.currentOwner is a Bitcoin address - find the account's public key (accountId)
          const ownerAddress = item.currentOwner;
          let ownerAccountId: string | null = null;
          
          // Look up account by their Bitcoin address to get their accountId (public key)
          console.log(`[Messaging] Looking for owner with address: ${ownerAddress}`);
          console.log(`[Messaging] Total accounts: ${this.state.accounts.size}`);
          
          for (const [accId, acc] of this.state.accounts.entries()) {
            const accAny = acc as any;
            // Check multiple possible address fields
            const accWallet = String(accAny.walletAddress || '').trim();
            const accIdentity = String(accAny.identityAddress || '').trim();
            
            if (accWallet === ownerAddress || accIdentity === ownerAddress || accId === ownerAddress) {
              ownerAccountId = accId;
              console.log(`[Messaging] Found owner accountId: ${accId}`);
              break;
            }
          }
          
          if (!ownerAccountId) {
            console.log(`[Messaging] No account found for address ${ownerAddress}, using address as recipientId`);
          }
          
          // If no account found by address lookup, use the address directly (fallback)
          targetRecipient = ownerAccountId || ownerAddress;
        }

        if (targetRecipient === account.accountId) {
          res.status(400).json({ success: false, error: 'Cannot message yourself' });
          return;
        }

        // Check if blocked
        if (this.ephemeralStore?.isBlocked(targetRecipient, account.accountId)) {
          res.status(403).json({ success: false, error: 'You are blocked by this user' });
          return;
        }

        const conversationId = this.ephemeralStore!.generateConversationId(
          account.accountId, targetRecipient, itemId
        );

        const messageId = `msg_${Date.now()}_${randomBytes(8).toString('hex')}`;

        const payload: MessagePayload = {
          messageId,
          senderId: account.accountId,
          recipientId: targetRecipient,
          encryptedContent,
          encryptedForSender: encryptedForSender || encryptedContent,
          itemId,
          conversationId,
        };

        const event = await this.ephemeralStore!.appendEvent(
          EphemeralEventType.MESSAGE_SENT,
          payload
        );

        // Broadcast to operator peers for decentralized delivery
        this.broadcastEphemeralEvent(event);

        res.json({
          success: true,
          messageId,
          conversationId,
          recipientId: targetRecipient,
          expiresAt: event.expiresAt,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // READ RECEIPTS & MESSAGE STATUS
    // ============================================================

    // Mark message as read
    this.app.post('/api/messages/:messageId/read', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }
        const { messageId } = req.params;
        this.ephemeralStore!.markMessageRead(messageId, account.accountId);
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get message status (delivered/read)
    this.app.get('/api/messages/:messageId/status', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }
        const { messageId } = req.params;
        const status = this.ephemeralStore!.getMessageStatus(messageId);
        res.json({ success: true, status });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // MESSAGE REACTIONS
    // ============================================================

    // Add reaction to message
    this.app.post('/api/messages/:messageId/react', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }
        const { messageId } = req.params;
        const { emoji } = req.body;
        if (!emoji) {
          res.status(400).json({ success: false, error: 'emoji required' });
          return;
        }
        this.ephemeralStore!.addReaction(messageId, account.accountId, emoji);
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Remove reaction from message
    this.app.delete('/api/messages/:messageId/react', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }
        const { messageId } = req.params;
        this.ephemeralStore!.removeReaction(messageId, account.accountId);
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get reactions for a message
    this.app.get('/api/messages/:messageId/reactions', async (req: Request, res: Response) => {
      try {
        const { messageId } = req.params;
        const reactions = this.ephemeralStore!.getReactions(messageId);
        res.json({ success: true, reactions });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // MUTE CONVERSATIONS
    // ============================================================

    // Mute a conversation
    this.app.post('/api/messages/conversation/:conversationId/mute', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }
        const { conversationId } = req.params;
        this.ephemeralStore!.muteConversation(account.accountId, conversationId);
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Unmute a conversation
    this.app.post('/api/messages/conversation/:conversationId/unmute', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }
        const { conversationId } = req.params;
        this.ephemeralStore!.unmuteConversation(account.accountId, conversationId);
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Mute a group
    this.app.post('/api/messages/groups/:groupId/mute', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }
        const { groupId } = req.params;
        this.ephemeralStore!.muteGroup(account.accountId, groupId);
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Unmute a group
    this.app.post('/api/messages/groups/:groupId/unmute', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }
        const { groupId } = req.params;
        this.ephemeralStore!.unmuteGroup(account.accountId, groupId);
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // TYPING INDICATORS
    // ============================================================

    // Set typing status
    this.app.post('/api/messages/typing', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }
        const { conversationId, groupId } = req.body;
        const targetId = conversationId || groupId;
        if (!targetId) {
          res.status(400).json({ success: false, error: 'conversationId or groupId required' });
          return;
        }
        this.ephemeralStore!.setTyping(targetId, account.accountId);
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get typing users in a conversation
    this.app.get('/api/messages/conversation/:conversationId/typing', async (req: Request, res: Response) => {
      try {
        const { conversationId } = req.params;
        const typingUsers = this.ephemeralStore!.getTypingUsers(conversationId);
        res.json({ success: true, typingUsers });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // ONLINE STATUS
    // ============================================================

    // Update user's online status (heartbeat)
    this.app.post('/api/messages/online', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }
        this.ephemeralStore!.setUserOnline(account.accountId);
        res.json({ success: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get user's online status
    this.app.get('/api/messages/user/:userId/online', async (req: Request, res: Response) => {
      try {
        const { userId } = req.params;
        const isOnline = this.ephemeralStore!.isUserOnline(userId);
        const lastSeen = this.ephemeralStore!.getUserLastSeen(userId);
        res.json({ success: true, isOnline, lastSeen });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // MESSAGE SEARCH
    // ============================================================

    // Search messages
    this.app.get('/api/messages/search', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Authentication required' });
          return;
        }
        const query = req.query.q as string || '';
        const limit = parseInt(req.query.limit as string) || 50;
        const messages = this.ephemeralStore!.searchMessages(account.accountId, query, limit);
        res.json({ 
          success: true, 
          messages: messages.map(m => ({
            messageId: m.payload.messageId,
            senderId: m.payload.senderId,
            recipientId: m.payload.recipientId,
            conversationId: m.payload.conversationId,
            timestamp: m.timestamp,
            expiresAt: m.expiresAt,
          }))
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // END EPHEMERAL MESSAGING API
    // ============================================================

    // ============================================================
    // USER ITEM REGISTRATION API - For users to register their own items
    // ============================================================

    // Prepare user item registration (get commitment hash and fee info)
    this.app.post('/api/registry/user/prepare', async (req: Request, res: Response) => {
      try {
        const { manufacturerName, serialNumber, metadata } = req.body;

        if (!manufacturerName || !metadata?.itemType || !metadata?.description) {
          res.status(400).json({ 
            success: false, 
            error: 'Required: manufacturerName, metadata.itemType, metadata.description' 
          });
          return;
        }

        // Generate commitment hash for fee anchoring
        const commitmentData = {
          type: 'USER_ITEM_REGISTRATION',
          manufacturerName,
          serialNumber: serialNumber || `USER_${Date.now()}`,
          itemType: metadata.itemType,
          timestamp: Date.now(),
        };
        
        const commitmentJson = JSON.stringify(commitmentData);
        const encoder = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(commitmentJson));
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const commitmentHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Fee goes to sponsor address
        const feeAddress = process.env.SPONSOR_ADDRESS || '1FMcxZRUWVDbKy7DxAosW7sM5PUntAkJ9U';
        const feeSats = Number(process.env.USER_MINT_FEE_SATS || 1000);

        res.json({
          success: true,
          commitmentHex,
          feeAddress,
          feeSats,
          message: 'Send fee transaction with OP_RETURN containing commitment, then call /api/registry/user/complete',
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Complete user item registration after fee payment
    this.app.post('/api/registry/user/complete', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        
        const { 
          manufacturerName, brandEntityId, serialNumber, metadata,
          feeTxid, feeCommitmentHex, initialOwner 
        } = req.body;

        if (!manufacturerName || !metadata?.itemType || !metadata?.description) {
          res.status(400).json({ 
            success: false, 
            error: 'Required: manufacturerName, metadata.itemType, metadata.description' 
          });
          return;
        }

        if (!feeTxid || !feeCommitmentHex) {
          res.status(400).json({ 
            success: false, 
            error: 'Required: feeTxid, feeCommitmentHex' 
          });
          return;
        }

        if (!initialOwner) {
          res.status(400).json({ 
            success: false, 
            error: 'Required: initialOwner (wallet address)' 
          });
          return;
        }

        // Verify fee transaction pays to sponsor address with minimum 1000 sats
        const sponsorAddress = process.env.SPONSOR_ADDRESS || '1FMcxZRUWVDbKy7DxAosW7sM5PUntAkJ9U';
        const minFeeSats = Number(process.env.USER_MINT_FEE_SATS || 1000);

        try {
          // Fetch transaction from blockchain API
          const txRes = await fetch(`https://mempool.space/api/tx/${feeTxid}`);
          if (!txRes.ok) {
            res.status(400).json({ 
              success: false, 
              error: 'Fee transaction not found on blockchain' 
            });
            return;
          }
          const txData = await txRes.json() as { vout?: Array<{ scriptpubkey_address?: string; value?: number; scriptpubkey_type?: string; scriptpubkey_asm?: string }> };

          // Check if any output pays to sponsor address with sufficient amount
          const outputs = txData.vout || [];
          let feePaidToSponsor = 0;
          let hasCommitment = false;

          for (const out of outputs) {
            const addr = out.scriptpubkey_address;
            const value = Number(out.value || 0);
            
            if (addr === sponsorAddress) {
              feePaidToSponsor += value;
            }
            
            // Check for OP_RETURN with commitment
            if (out.scriptpubkey_type === 'op_return') {
              const asmParts = String(out.scriptpubkey_asm || '').split(' ');
              const pushData = asmParts.find((p: string) => p.length >= 64 && /^[0-9a-f]+$/i.test(p));
              if (pushData && pushData.toLowerCase().includes(feeCommitmentHex.toLowerCase().substring(0, 32))) {
                hasCommitment = true;
              }
            }
          }

          if (feePaidToSponsor < minFeeSats) {
            res.status(400).json({ 
              success: false, 
              error: `Fee transaction must pay at least ${minFeeSats} sats to sponsor address ${sponsorAddress}. Found: ${feePaidToSponsor} sats` 
            });
            return;
          }

          // Note: We allow soft-confirm for small amounts, commitment check is advisory
          console.log(`User item registration: feeTxid=${feeTxid}, feePaid=${feePaidToSponsor}, hasCommitment=${hasCommitment}`);

        } catch (verifyErr: any) {
          console.error('Fee verification error:', verifyErr);
          res.status(400).json({ 
            success: false, 
            error: 'Failed to verify fee transaction: ' + (verifyErr.message || 'Unknown error')
          });
          return;
        }

        // Generate unique item ID
        const itemId = `item_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const now = Date.now();

        // Create the ITEM_REGISTERED event
        const event = {
          eventId: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          type: EventType.ITEM_REGISTERED,
          timestamp: now,
          payload: {
            type: EventType.ITEM_REGISTERED,
            itemId,
            manufacturerId: account?.accountId || initialOwner,
            manufacturerName,
            brandEntityId: brandEntityId || undefined,
            serialNumber: serialNumber || `USER_${now}`,
            metadataHash: feeCommitmentHex,
            initialOwner,
            metadata: {
              ...metadata,
              name: metadata.itemType,
            },
            issuerRole: 'user' as const,
            issuerAccountId: account?.accountId || initialOwner,
            feeTxid,
            feeCommitmentHex,
          },
          signatures: [],
        };

        // Append to event store
        await this.canonicalEventStore.appendEvent(event.payload as any, event.signatures as any);

        // Update local state
        this.state.items.set(itemId, {
          itemId,
          manufacturerId: account?.accountId || initialOwner,
          manufacturerName,
          serialNumberHash: feeCommitmentHex,
          serialNumberDisplay: serialNumber ? `${serialNumber.substring(0, 4)}...` : undefined,
          metadataHash: feeCommitmentHex,
          currentOwner: initialOwner,
          metadata: {
            ...metadata,
            name: metadata.itemType,
          },
          registeredAt: now,
          issuerRole: 'user',
          issuerAccountId: account?.accountId || initialOwner,
          manufacturerVerified: false,
          mintedByOfficialManufacturer: false,
          authentications: [],
        });

        res.json({
          success: true,
          itemId,
          message: 'Item registered successfully. It is marked as unverified until authenticated.',
          item: {
            itemId,
            manufacturerName,
            name: metadata.itemType,
            currentOwner: initialOwner,
            registeredAt: now,
            verified: false,
            issuerRole: 'user',
          },
        });
      } catch (error: any) {
        console.error('User item registration error:', error);
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // END USER ITEM REGISTRATION API
    // ============================================================

    // ============================================================
    // ITEM PROVENANCE API - Complete history and risk analysis
    // ============================================================

    // Get complete provenance for an item (ownership history, price history, risk indicators)
    this.app.get('/api/provenance/:itemId', async (req: Request, res: Response) => {
      try {
        if (!this.itemProvenanceService) {
          this.itemProvenanceService = new ItemProvenanceService(this.canonicalEventStore);
        }

        const provenance = await this.itemProvenanceService.getItemProvenance(req.params.itemId);
        
        if (!provenance) {
          res.status(404).json({ success: false, error: 'Item not found' });
          return;
        }

        res.json({
          success: true,
          provenance,
          summary: {
            totalOwners: provenance.totalOwners,
            averageHoldDays: provenance.averageHoldDays,
            lastSalePrice: provenance.lastSalePrice,
            priceChange: provenance.priceChange,
            isVerified: provenance.isVerified,
            manufacturerVerified: provenance.manufacturerVerified,
            riskScore: provenance.riskScore,
            riskLevel: provenance.riskScore > 50 ? 'high' : provenance.riskScore > 20 ? 'medium' : 'low',
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get ownership history only
    this.app.get('/api/provenance/:itemId/ownership', async (req: Request, res: Response) => {
      try {
        if (!this.itemProvenanceService) {
          this.itemProvenanceService = new ItemProvenanceService(this.canonicalEventStore);
        }

        const provenance = await this.itemProvenanceService.getItemProvenance(req.params.itemId);
        
        if (!provenance) {
          res.status(404).json({ success: false, error: 'Item not found' });
          return;
        }

        res.json({
          success: true,
          itemId: req.params.itemId,
          currentOwner: provenance.currentOwner,
          ownershipHistory: provenance.ownershipHistory,
          totalOwners: provenance.totalOwners,
          averageHoldDays: provenance.averageHoldDays,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get price history only
    this.app.get('/api/provenance/:itemId/prices', async (req: Request, res: Response) => {
      try {
        if (!this.itemProvenanceService) {
          this.itemProvenanceService = new ItemProvenanceService(this.canonicalEventStore);
        }

        const provenance = await this.itemProvenanceService.getItemProvenance(req.params.itemId);
        
        if (!provenance) {
          res.status(404).json({ success: false, error: 'Item not found' });
          return;
        }

        res.json({
          success: true,
          itemId: req.params.itemId,
          priceHistory: provenance.priceHistory,
          lastSalePrice: provenance.lastSalePrice,
          highestPrice: provenance.highestPrice,
          lowestPrice: provenance.lowestPrice,
          averagePrice: provenance.averagePrice,
          priceChange: provenance.priceChange,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get risk analysis for an item
    this.app.get('/api/provenance/:itemId/risk', async (req: Request, res: Response) => {
      try {
        if (!this.itemProvenanceService) {
          this.itemProvenanceService = new ItemProvenanceService(this.canonicalEventStore);
        }

        const provenance = await this.itemProvenanceService.getItemProvenance(req.params.itemId);
        
        if (!provenance) {
          res.status(404).json({ success: false, error: 'Item not found' });
          return;
        }

        const riskLevel = provenance.riskScore > 50 ? 'high' : provenance.riskScore > 20 ? 'medium' : 'low';

        res.json({
          success: true,
          itemId: req.params.itemId,
          riskScore: provenance.riskScore,
          riskLevel,
          riskIndicators: provenance.riskIndicators,
          isVerified: provenance.isVerified,
          manufacturerVerified: provenance.manufacturerVerified,
          recommendation: riskLevel === 'high' 
            ? '⚠️ HIGH RISK - Proceed with extreme caution, consider additional verification'
            : riskLevel === 'medium'
            ? '⚡ MODERATE RISK - Review risk indicators before purchasing'
            : '✅ LOW RISK - Item appears to have clean history',
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get market stats for a manufacturer/category
    this.app.get('/api/market/stats', async (req: Request, res: Response) => {
      try {
        if (!this.itemProvenanceService) {
          this.itemProvenanceService = new ItemProvenanceService(this.canonicalEventStore);
        }

        const manufacturer = req.query.manufacturer as string;
        const category = req.query.category as string;

        if (!manufacturer) {
          res.status(400).json({ success: false, error: 'manufacturer query parameter required' });
          return;
        }

        const stats = await this.itemProvenanceService.getMarketStats(manufacturer, category);

        res.json({
          success: true,
          stats,
          insights: {
            averagePriceFormatted: `${stats.averagePrice.toLocaleString()} sats`,
            volumeFormatted: `${stats.volumeLast30Days.toLocaleString()} sats`,
            marketActivity: stats.totalSales > 10 ? 'active' : stats.totalSales > 3 ? 'moderate' : 'low',
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get event timeline for an item
    this.app.get('/api/provenance/:itemId/timeline', async (req: Request, res: Response) => {
      try {
        if (!this.itemProvenanceService) {
          this.itemProvenanceService = new ItemProvenanceService(this.canonicalEventStore);
        }

        const provenance = await this.itemProvenanceService.getItemProvenance(req.params.itemId);
        
        if (!provenance) {
          res.status(404).json({ success: false, error: 'Item not found' });
          return;
        }

        res.json({
          success: true,
          itemId: req.params.itemId,
          timeline: provenance.events,
          totalEvents: provenance.events.length,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // END ITEM PROVENANCE API
    // ============================================================

    // ============================================================
    // USER TRANSACTION HISTORY API
    // ============================================================

    // Get complete transaction history for a user (purchases, sales, mints)
    this.app.get('/api/history/:address', async (req: Request, res: Response) => {
      try {
        const address = req.params.address;
        const allEvents = await this.canonicalEventStore.getAllEvents();
        
        const transactions: any[] = [];

        for (const event of allEvents) {
          const payload = event.payload as any;
          
          // Items minted by this user
          if (payload.type === 'ITEM_REGISTERED' && payload.initialOwner === address) {
            const item = this.state.items.get(payload.itemId);
            transactions.push({
              type: 'mint',
              timestamp: payload.timestamp,
              itemId: payload.itemId,
              itemName: item?.metadata?.name || payload.metadata?.name || 'Unknown Item',
              manufacturerName: payload.manufacturerName || payload.manufacturerId,
              role: payload.issuerRole || 'user',
            });
          }

          // Items purchased by this user
          if (payload.type === 'OWNERSHIP_TRANSFERRED' && payload.toOwner === address) {
            const item = this.state.items.get(payload.itemId);
            transactions.push({
              type: 'purchase',
              timestamp: payload.timestamp,
              itemId: payload.itemId,
              itemName: item?.metadata?.name || 'Unknown Item',
              manufacturerName: (item as any)?.manufacturerName || item?.manufacturerId,
              price: payload.price,
              from: payload.fromOwner,
              txid: payload.paymentTxHash,
            });
          }

          // Items sold by this user
          if (payload.type === 'OWNERSHIP_TRANSFERRED' && payload.fromOwner === address) {
            const item = this.state.items.get(payload.itemId);
            transactions.push({
              type: 'sale',
              timestamp: payload.timestamp,
              itemId: payload.itemId,
              itemName: item?.metadata?.name || 'Unknown Item',
              manufacturerName: (item as any)?.manufacturerName || item?.manufacturerId,
              price: payload.price,
              to: payload.toOwner,
              txid: payload.paymentTxHash,
            });
          }

          // Verification requests created by this user
          if (payload.type === 'VERIFICATION_REQUEST_CREATED' && payload.ownerWallet === address) {
            const item = this.state.items.get(payload.itemId);
            transactions.push({
              type: 'verification_requested',
              timestamp: payload.timestamp,
              itemId: payload.itemId,
              itemName: item?.metadata?.name || 'Unknown Item',
              authenticatorId: payload.authenticatorId,
              fee: payload.serviceFeeSats,
            });
          }

          // Authentications performed by this user (if authenticator)
          if ((payload.type === 'AUTHENTICATION_PERFORMED' || payload.type === 'VERIFICATION_REQUEST_COMPLETED') 
              && payload.authenticatorId === address) {
            const item = this.state.items.get(payload.itemId);
            transactions.push({
              type: 'authentication_performed',
              timestamp: payload.timestamp || payload.completedAt,
              itemId: payload.itemId,
              itemName: item?.metadata?.name || 'Unknown Item',
              isAuthentic: payload.isAuthentic,
              fee: payload.serviceFeeSats,
            });
          }
        }

        // Sort by timestamp descending (newest first)
        transactions.sort((a, b) => b.timestamp - a.timestamp);

        // Calculate summary stats
        const purchases = transactions.filter(t => t.type === 'purchase');
        const sales = transactions.filter(t => t.type === 'sale');
        const mints = transactions.filter(t => t.type === 'mint');

        const totalSpent = purchases.reduce((sum, t) => sum + (t.price || 0), 0);
        const totalEarned = sales.reduce((sum, t) => sum + (t.price || 0), 0);

        res.json({
          success: true,
          address,
          transactions,
          summary: {
            totalTransactions: transactions.length,
            purchases: purchases.length,
            sales: sales.length,
            mints: mints.length,
            totalSpentSats: totalSpent,
            totalEarnedSats: totalEarned,
            netPositionSats: totalEarned - totalSpent,
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get portfolio summary for a user (current holdings with values)
    this.app.get('/api/portfolio/:address', async (req: Request, res: Response) => {
      try {
        const address = req.params.address;
        
        // Get all items owned by this address
        const ownedItems = Array.from(this.state.items.values())
          .filter((item: any) => item.currentOwner === address);

        // Calculate portfolio stats
        let totalAcquisitionCost = 0;
        let totalEstimatedValue = 0;
        const holdings: any[] = [];

        for (const item of ownedItems) {
          // Get provenance for each item
          if (!this.itemProvenanceService) {
            this.itemProvenanceService = new ItemProvenanceService(this.canonicalEventStore);
          }
          const provenance = await this.itemProvenanceService.getItemProvenance(item.itemId);
          
          const lastOwnerRecord = provenance?.ownershipHistory.find(
            (r: any) => r.owner === address && !r.soldAt
          );
          const acquisitionPrice = lastOwnerRecord?.acquiredPrice || 0;
          const estimatedValue = provenance?.lastSalePrice || acquisitionPrice;

          totalAcquisitionCost += acquisitionPrice;
          totalEstimatedValue += estimatedValue;

          holdings.push({
            itemId: item.itemId,
            name: item.metadata?.name || 'Unknown Item',
            manufacturerName: (item as any).manufacturerName || item.manufacturerId,
            category: item.metadata?.category,
            acquisitionPrice,
            estimatedValue,
            isVerified: provenance?.isVerified || false,
            manufacturerVerified: provenance?.manufacturerVerified || false,
            riskScore: provenance?.riskScore || 0,
            holdDays: lastOwnerRecord?.holdDurationDays || 0,
          });
        }

        res.json({
          success: true,
          address,
          portfolio: {
            totalItems: holdings.length,
            totalAcquisitionCostSats: totalAcquisitionCost,
            totalEstimatedValueSats: totalEstimatedValue,
            unrealizedGainSats: totalEstimatedValue - totalAcquisitionCost,
            unrealizedGainPercent: totalAcquisitionCost > 0 
              ? Math.round(((totalEstimatedValue - totalAcquisitionCost) / totalAcquisitionCost) * 100)
              : 0,
          },
          holdings: holdings.sort((a, b) => b.estimatedValue - a.estimatedValue),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // END USER TRANSACTION HISTORY API
    // ============================================================

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
        .map((s: any) => {
          // Normalize status to match main repo: 'completed' -> 'paid'
          let status = String(s?.status || '').toLowerCase();
          if (status === 'completed') status = 'paid';
          return {
            offerId: String(s?.settlementId || ''),
            itemId: String(s?.itemId || ''),
            buyerAddress: String(s?.buyer || ''),
            sellerAddress: String(s?.seller || ''),
            sats: Number(s?.price || 0),
            status,
            createdAt: Number(s?.initiatedAt || 0),
            expiresAt: Number(s?.expiresAt || 0),
          };
        });
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
    
    // Start consensus verification immediately (works with or without main node)
    // This enables true decentralization - operators can verify each other
    this.startConsensusVerification();
    
    // Start the consensus node (mempool + checkpoint manager)
    if (this.consensusNode) {
      this.consensusNode.start();
      
      // Update consensus node with active operators from state
      await this.updateConsensusOperators();
      
      console.log('[Consensus] Mempool and checkpoint manager started');
    }
    
    await this.connectToMainSeed();

    this.startPeerDiscovery();

    // Announce this operator on the ledger for decentralized discovery
    // This enables new nodes to find us without hardcoded seeds
    this.scheduleNetworkAnnouncement();

    console.log('\n[Operator] Node is running!');
    console.log('[Operator] WebSocket server ready for gateway connections');
    console.log('[Operator] Press Ctrl+C to stop\n');
  }

  /**
   * Schedule network announcement - operators announce themselves on the ledger
   * This enables truly decentralized discovery without hardcoded seeds
   */
  private scheduleNetworkAnnouncement(): void {
    // Wait for initial sync before announcing
    setTimeout(async () => {
      await this.announceOnNetwork();
    }, 30000); // 30 second delay

    // Re-announce every 6 hours to stay in the discovery list
    setInterval(async () => {
      await this.announceOnNetwork();
    }, 6 * 60 * 60 * 1000);
  }

  private async announceOnNetwork(): Promise<void> {
    if (!this.config.operatorId || !this.config.operatorUrl) {
      console.log('[Network] Skipping announcement: no operatorId or operatorUrl configured');
      return;
    }

    try {
      // Check if we're already announced with the same URL
      const state = await this.canonicalStateBuilder.buildState();
      const existingAnnouncement = (state as any).networkTopology?.operators?.get(this.config.operatorId);
      
      if (existingAnnouncement && existingAnnouncement.httpUrl === this.config.operatorUrl) {
        // Already announced with same URL, skip
        return;
      }

      console.log(`[Network] Announcing operator on ledger: ${this.config.operatorId}`);
      
      // Create announcement event via the event submission endpoint
      // This will be picked up by the mempool and included in the ledger
      const announcementPayload = {
        type: 'NETWORK_OPERATOR_ANNOUNCED',
        operatorId: this.config.operatorId,
        httpUrl: this.config.operatorUrl,
        wsUrl: this.config.operatorUrl.replace('https://', 'wss://').replace('http://', 'ws://'),
        btcAddress: this.config.btcAddress || '',
        publicKey: this.config.publicKey || '',
        version: '1.0.0',
        timestamp: Date.now(),
        nonce: `ann-${Date.now()}-${Math.random().toString(36).substr(2, 8)}`,
      };

      // Submit to local mempool if we're the leader, otherwise forward to leader
      if (this.consensusNode) {
        // For now, just log the intention - full mempool integration would submit this
        console.log(`[Network] Operator announcement prepared: ${this.config.operatorUrl}`);
      }
    } catch (error: any) {
      console.error('[Network] Failed to announce on network:', error.message);
    }
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
        isGateway: false,
        isUi: false,
      });

      // Request ephemeral message sync from this gateway after a short delay
      // Gateways store ephemeral messages as backup - helps operators recover after restart
      setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN) {
          const sinceTimestamp = this.ephemeralStore?.getLatestTimestamp() || 0;
          ws.send(JSON.stringify({
            type: 'ephemeral_sync_request',
            since: sinceTimestamp,
            limit: 500,
          }));
          console.log(`[Ephemeral] 📤 Requesting ephemeral sync from gateway (since ${sinceTimestamp})`);
        }
      }, 3000);

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

  private async handleGatewayMessage(ws: WebSocket, message: any): Promise<void> {
    const conn = this.gatewayConnections.get(ws);
    if (conn) {
      conn.lastSeen = Date.now();
    }

    switch (message.type) {
      case 'sync_request':
        console.log('[Operator] Gateway requesting sync');
        if (conn) {
          (conn as any).isGateway = true;
        }
        this.sendSyncResponse(ws);
        break;

      case 'subscribe_consensus':
        // Subscribe to real-time consensus updates (for mempool visualizer)
        const meta = this.gatewayConnections.get(ws);
        if (meta) {
          (meta as any).subscribedToConsensus = true;
          (meta as any).isUi = true;
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

      // Handle append_event from operators - add to canonical ledger and broadcast
      case 'append_event':
        try {
          const { requestId, payload, signatures, operatorId } = message;
          
          if (!payload || !signatures || !Array.isArray(signatures)) {
            ws.send(JSON.stringify({ type: 'append_event_ack', requestId, ok: false, error: 'Invalid payload or signatures' }));
            break;
          }

          // Append to canonical event store (this IS the ledger)
          const event = await this.canonicalEventStore.appendEvent(payload, signatures);
          
          console.log(`[Operator] Appended event from ${operatorId}: ${payload.type} (seq #${event.sequenceNumber})`);

          // Send ack back to sender
          ws.send(JSON.stringify({ type: 'append_event_ack', requestId, ok: true, eventHash: event.eventHash, sequenceNumber: event.sequenceNumber }));

          // Broadcast to all other connected operators/gateways (excluding sender)
          const broadcastMsg = JSON.stringify({ type: 'new_event', event, sourceOperatorId: this.config.operatorId });
          for (const [peerWs] of this.gatewayConnections) {
            if (peerWs !== ws && peerWs.readyState === WebSocket.OPEN) {
              try { peerWs.send(broadcastMsg); } catch {}
            }
          }
          for (const peer of this.operatorPeerConnections.values()) {
            if (peer.ws !== ws && peer.ws.readyState === WebSocket.OPEN) {
              try { peer.ws.send(broadcastMsg); } catch {}
            }
          }

          // Rebuild local state
          await this.rebuildLocalStateFromCanonical();
          this.broadcastRegistryUpdate();
        } catch (e: any) {
          const { requestId } = message || {};
          ws.send(JSON.stringify({ type: 'append_event_ack', requestId, ok: false, error: e?.message || String(e) }));
        }
        break;

      // ============================================================
      // EPHEMERAL MESSAGING P2P SYNC (via gateway connections)
      // ============================================================
      case 'ephemeral_event':
        try {
          const sourceOperatorId = String(message?.sourceOperatorId || '').trim();
          const eventData = message?.event as EphemeralEvent;

          if (!eventData || !eventData.eventId || !eventData.eventType) {
            break;
          }

          // Clone payload before importEvent mutates it via extractLargeContent
          // (replaces large strings with __contentRef: placeholders on disk).
          // We need the full content for re-broadcast to other peer nodes.
          const broadcastCopy = { ...eventData, payload: { ...eventData.payload } };
          const imported = await this.ephemeralStore!.importEvent(eventData);

          if (imported) {
            console.log(`[Ephemeral] 📥 Imported ${eventData.eventType} from ${sourceOperatorId}: ${eventData.eventId}`);
            // Re-broadcast the FULL copy to other peers (but not back to source)
            this.broadcastEphemeralEvent(broadcastCopy, sourceOperatorId);
          }
        } catch (e: any) {
          console.log(`[Ephemeral] Error importing event:`, e?.message);
        }
        break;

      case 'ephemeral_sync_request':
        try {
          const sinceTimestamp = Number(message?.since || 0);
          const maxEvents = Math.min(Number(message?.limit || 500), 1000);
          const events = this.ephemeralStore!.getEventsSince(sinceTimestamp, maxEvents);

          // Restore content from disk before sending - in-memory events have __contentRef: placeholders
          const eventsWithContent = await this.ephemeralStore!.restoreEventsContent(events);

          ws.send(JSON.stringify({
            type: 'ephemeral_sync_response',
            events: eventsWithContent,
            sinceTimestamp,
            latestTimestamp: this.ephemeralStore!.getLatestTimestamp(),
          }));
          console.log(`[Ephemeral] 📤 Sent ${eventsWithContent.length} events in sync response (content restored)`);
        } catch (e: any) {
          console.log(`[Ephemeral] Error handling sync request:`, e?.message);
        }
        break;

      case 'ephemeral_sync_response':
        try {
          const events = message?.events as EphemeralEvent[];
          if (Array.isArray(events)) {
            let importedCount = 0;
            for (const event of events) {
              const imported = await this.ephemeralStore!.importEvent(event);
              if (imported) importedCount++;
            }
            if (importedCount > 0) {
              console.log(`[Ephemeral] 📥 Backfill: imported ${importedCount} events`);
            }
          }
        } catch (e: any) {
          console.log(`[Ephemeral] Error processing sync response:`, e?.message);
        }
        break;

      case 'ephemeral_event_ack':
        // Acknowledgment received
        break;
      // ============================================================
      // END EPHEMERAL MESSAGING P2P SYNC
      // ============================================================

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

  /**
   * Broadcast an ephemeral event to all operator peers AND gateways (for decentralized messaging)
   * Gateways serve as backup storage - they persist messages and can restore them to operators after restart
   */
  private broadcastEphemeralEvent(event: EphemeralEvent, excludePeerId?: string, excludeSeed: boolean = false): void {
    // Use setImmediate to yield to event loop before heavy JSON.stringify
    // This prevents blocking on large base64 video/photo payloads
    setImmediate(async () => {
      try {
        const message = {
          type: 'ephemeral_event',
          event,
          sourceOperatorId: this.config.operatorId,
          timestamp: Date.now(),
        };
        const msgStr = JSON.stringify(message);

        try {
          if (!excludeSeed && this.mainSeedWs && this.mainSeedWs.readyState === WebSocket.OPEN) {
            this.mainSeedWs.send(msgStr);
          }
        } catch {}

        // Broadcast to operator peers
        for (const [peerId, peer] of this.operatorPeerConnections.entries()) {
          if (excludePeerId && peerId === excludePeerId) continue;
          try {
            if (peer.ws.readyState === WebSocket.OPEN) {
              peer.ws.send(msgStr);
            }
          } catch {}
        }

        // Also broadcast to connected gateways (they store as backup)
        for (const [ws, conn] of this.gatewayConnections.entries()) {
          try {
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(msgStr);
            }
          } catch {}
        }

        // After broadcasting, extract large content from the event to separate files.
        // This keeps the in-memory event lightweight so future persistence (structured clone
        // + JSON.stringify) won't block the event loop. Content is restored on retrieval.
        if (this.ephemeralStore) {
          await this.ephemeralStore.extractLargeContent(event);
        }
      } catch (e: any) {
        console.error('[Ephemeral] Failed to broadcast event:', e.message);
      }
    });
  }

  private broadcastRegistryUpdate(): void {
    const data = this.getGatewaySyncData();
    const msg = { type: 'registry_update', data, timestamp: Date.now() };
    this.broadcastToGateways(msg);
    this.broadcastToOperatorPeers(msg);
  }

  /**
   * Fetch encryption key from peer operators when not found locally
   * This enables cross-operator messaging when key gossip hasn't propagated yet
   */
  private async fetchEncryptionKeyFromNetwork(accountId: string): Promise<{ encryptionPublicKeyHex: string; updatedAt: number } | null> {
    if (!this.operatorPeerConnections || this.operatorPeerConnections.size === 0) {
      return null;
    }

    // Try each connected peer
    const peers = Array.from(this.operatorPeerConnections.entries());
    const timeoutMs = 3000;

    for (const [peerId, peer] of peers) {
      try {
        // Extract HTTP URL from WebSocket URL (ws:// -> http://, wss:// -> https://)
        let httpUrl = peer.wsUrl.replace(/^ws:/, 'http:').replace(/^wss:/, 'https:');
        if (httpUrl.endsWith('/ws')) {
          httpUrl = httpUrl.slice(0, -3); // Remove /ws suffix
        }

        const fetchUrl = `${httpUrl}/api/messages/keys/${encodeURIComponent(accountId)}`;
        
        // Use internal authentication - operators trust each other
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), timeoutMs);
        
        const response = await fetch(fetchUrl, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'X-Internal-Request': 'operator-to-operator',
          },
          signal: controller.signal,
        });
        
        clearTimeout(timeout);
        
        if (response.ok) {
          const data = await response.json() as { success?: boolean; encryptionPublicKeyHex?: string; updatedAt?: number };
          if (data.success && data.encryptionPublicKeyHex) {
            console.log(`[Messaging] Fetched key for ${accountId.substring(0, 12)}... from peer ${peerId.substring(0, 12)}...`);
            // Store in local registry for future lookups
            this.messagingEncryptionKeyRegistry.set(accountId, {
              encryptionPublicKeyHex: data.encryptionPublicKeyHex,
              updatedAt: data.updatedAt || Date.now(),
            });
            return { encryptionPublicKeyHex: data.encryptionPublicKeyHex, updatedAt: data.updatedAt || Date.now() };
          }
        }
      } catch (e) {
        // Peer might be unreachable, try next
        console.log(`[Messaging] Failed to fetch key from peer ${peerId.substring(0, 12)}...:`, (e as Error).message);
      }
    }

    return null;
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

    // Also start periodic ephemeral message sync (every 2 minutes)
    setInterval(() => {
      this.requestEphemeralSyncFromAllPeers();
    }, 2 * 60 * 1000);
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

    // Request ephemeral message sync from the new peer after a short delay
    setTimeout(() => {
      this.requestEphemeralSyncFromPeer(peerId);
    }, 2000);
  }

  /**
   * Request ephemeral events from a peer since our latest timestamp (backfill sync)
   */
  private requestEphemeralSyncFromPeer(peerId: string): void {
    const peer = this.operatorPeerConnections.get(peerId);
    if (!peer || peer.ws.readyState !== WebSocket.OPEN) return;

    const sinceTimestamp = this.ephemeralStore?.getLatestTimestamp() || 0;
    
    try {
      peer.ws.send(JSON.stringify({
        type: 'ephemeral_sync_request',
        since: sinceTimestamp,
        limit: 500,
      }));
      console.log(`[Ephemeral] 📤 Requesting sync from peer ${peerId} since ${new Date(sinceTimestamp).toISOString()}`);
    } catch (e: any) {
      console.log(`[Ephemeral] Failed to request sync from peer ${peerId}:`, e?.message);
    }
  }

  /**
   * Request ephemeral sync from all connected peers (periodic backfill)
   */
  private requestEphemeralSyncFromAllPeers(): void {
    for (const [peerId] of this.operatorPeerConnections) {
      this.requestEphemeralSyncFromPeer(peerId);
    }
  }

  private async handleOperatorPeerMessage(peerId: string, message: any): Promise<void> {
    const meta = this.operatorPeerConnections.get(peerId);
    if (meta) meta.lastSeen = Date.now();
    const ws = meta?.ws;

    // Update peer resilience manager with peer state
    if (this.peerResilienceManager && message?.sequenceNumber !== undefined) {
      this.peerResilienceManager.updatePeerState(
        peerId,
        Number(message.sequenceNumber || 0),
        String(message.headHash || message.stateHash || ''),
        String(message.stateHash || ''),
      );
    }

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
          // Update resilience manager
          if (this.peerResilienceManager) {
            this.peerResilienceManager.updatePeerState(
              peerId,
              Number(message.sequenceNumber || 0),
              String(message.stateHash || ''),
              String(message.stateHash || ''),
            );
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

      // ============================================================
      // EPHEMERAL MESSAGING P2P SYNC - Decentralized message delivery
      // ============================================================
      case 'ephemeral_event':
        try {
          const sourceOperatorId = String(message?.sourceOperatorId || '').trim();
          const eventData = message?.event as EphemeralEvent;

          if (!eventData || !eventData.eventId || !eventData.eventType) {
            console.log(`[Ephemeral] Invalid ephemeral_event payload from peer`);
            break;
          }

          // Clone payload before importEvent mutates it via extractLargeContent
          const broadcastCopy = { ...eventData, payload: { ...eventData.payload } };

          // Import the event (with dedupe)
          const imported = await this.ephemeralStore!.importEvent(eventData);

          if (imported) {
            console.log(`[Ephemeral] 📥 Imported ${eventData.eventType} from peer ${sourceOperatorId}: ${eventData.eventId}`);

            // Re-broadcast the FULL copy to other peers (gossip protocol)
            // Don't send back to the source
            this.broadcastEphemeralEvent(broadcastCopy, sourceOperatorId);

            // Send ack back
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({
                type: 'ephemeral_event_ack',
                ok: true,
                eventId: eventData.eventId,
              }));
            }
          }
        } catch (e: any) {
          console.log(`[Ephemeral] Could not import ephemeral_event from peer:`, e?.message);
        }
        break;

      case 'ephemeral_event_ack':
        // Acknowledgment from peer that they received our ephemeral event
        break;

      case 'ephemeral_sync_request':
        // Peer is requesting ephemeral events since a timestamp (backfill sync)
        try {
          const sinceTimestamp = Number(message?.since || 0);
          const maxEvents = Math.min(Number(message?.limit || 500), 1000);
          const events = this.ephemeralStore!.getEventsSince(sinceTimestamp, maxEvents);

          // Restore content from disk before sending - in-memory events have __contentRef: placeholders
          const eventsWithContent = await this.ephemeralStore!.restoreEventsContent(events);

          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
              type: 'ephemeral_sync_response',
              events: eventsWithContent,
              sinceTimestamp,
              latestTimestamp: this.ephemeralStore!.getLatestTimestamp(),
            }));
          }
        } catch (e: any) {
          console.log(`[Ephemeral] Error handling sync request:`, e?.message);
        }
        break;

      case 'ephemeral_sync_response':
        // Response to our sync request - import all events
        try {
          const events = message?.events as EphemeralEvent[];
          if (Array.isArray(events)) {
            let importedCount = 0;
            for (const event of events) {
              const imported = await this.ephemeralStore!.importEvent(event);
              if (imported) importedCount++;
            }
            if (importedCount > 0) {
              console.log(`[Ephemeral] 📥 Backfill sync: imported ${importedCount} events from peer`);
            }
          }
        } catch (e: any) {
          console.log(`[Ephemeral] Error processing sync response:`, e?.message);
        }
        break;
      // ============================================================
      // END EPHEMERAL MESSAGING P2P SYNC
      // ============================================================

      // Handle append_event from peer operators - allows direct operator-to-operator sync when main node is offline
      case 'append_event':
        try {
          const { requestId, payload, signatures, operatorId: senderOpId } = message;
          
          if (!payload || !signatures || !Array.isArray(signatures)) {
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: 'append_event_ack', requestId, ok: false, error: 'Invalid payload or signatures' }));
            }
            break;
          }

          // Append to canonical event store (this IS the ledger)
          const event = await this.canonicalEventStore.appendEvent(payload, signatures);
          
          console.log(`[Operator] Appended event from peer ${senderOpId}: ${payload.type} (seq #${event.sequenceNumber})`);

          // Send ack back to sender
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'append_event_ack', requestId, ok: true, eventHash: event.eventHash, sequenceNumber: event.sequenceNumber }));
          }

          // Broadcast to all OTHER connected operators (excluding sender and original source)
          const broadcastMsg = JSON.stringify({ type: 'new_event', event, sourceOperatorId: this.config.operatorId });
          for (const [peerOpId, peer] of this.operatorPeerConnections) {
            if (peerOpId !== peerId && peer.ws.readyState === WebSocket.OPEN) {
              try { peer.ws.send(broadcastMsg); } catch {}
            }
          }
          for (const [gwWs] of this.gatewayConnections) {
            if (gwWs.readyState === WebSocket.OPEN) {
              try { gwWs.send(broadcastMsg); } catch {}
            }
          }

          // Rebuild local state
          await this.rebuildLocalStateFromCanonical();
          this.broadcastRegistryUpdate();
        } catch (e: any) {
          const { requestId } = message || {};
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'append_event_ack', requestId, ok: false, error: e?.message || String(e) }));
          }
        }
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

    // Flush ephemeral message ledger to disk (immediate sync write)
    if (this.ephemeralStore) {
      this.ephemeralStore.flushToDisk();
      this.ephemeralStore.stopPruning();
      console.log('[Operator] Flushed message ledger');
    }

    await this.persistState();
    console.log('[Operator] Stopped');
  }

  /**
   * Build list of all available seed URLs
   * Order: last successful > primary > fallbacks > discovered peers
   */
  private buildSeedUrlList(): string[] {
    const urls: string[] = [];
    
    // Last successful seed first (if we have one)
    if (this.lastSuccessfulSeedUrl) {
      urls.push(this.lastSuccessfulSeedUrl);
    }
    
    // Primary seed
    if (this.config.mainSeedUrl) {
      urls.push(this.config.mainSeedUrl);
    }
    
    // Configured fallbacks
    if (this.config.fallbackSeedUrls) {
      urls.push(...this.config.fallbackSeedUrls);
    }
    
    // Discovered peer WebSocket URLs
    for (const [, peer] of this.operatorPeerConnections) {
      if (peer.wsUrl) {
        urls.push(peer.wsUrl);
      }
    }
    
    // Deduplicate while preserving order
    return [...new Set(urls)];
  }

  /**
   * Get the next seed URL to try (rotates through available seeds)
   */
  private getNextSeedUrl(): string {
    this.allSeedUrls = this.buildSeedUrlList();
    
    if (this.allSeedUrls.length === 0) {
      return this.config.mainSeedUrl; // Fallback to config
    }
    
    // Rotate to next seed
    this.currentSeedIndex = this.currentSeedIndex % this.allSeedUrls.length;
    const seedUrl = this.allSeedUrls[this.currentSeedIndex];
    this.currentSeedIndex++;
    
    return seedUrl;
  }

  private async connectToMainSeed(): Promise<void> {
    const seedUrl = this.getNextSeedUrl();
    console.log(`[Operator] Connecting to seed: ${seedUrl}`);
    if (this.allSeedUrls.length > 1) {
      console.log(`[Operator] (${this.allSeedUrls.length} seeds available for failover)`);
    }

    try {
      this.mainSeedWs = new WebSocket(seedUrl);

      this.mainSeedWs.on('open', () => {
        console.log(`[Operator] ✅ Connected to Autho Network via ${seedUrl}`);
        this.isConnectedToMain = true;
        this.lastMainNodeHeartbeat = Date.now();
        this.lastSuccessfulSeedUrl = seedUrl;
        this.currentSeedIndex = 0; // Reset rotation on success

        // Send sync request
        this.mainSeedWs!.send(JSON.stringify({
          type: 'sync_request',
          operatorId: this.config.operatorId,
          networkId: this.computeNetworkId(),
          lastSequence: this.state.lastSyncedSequence,
          timestamp: Date.now()
        }));
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
        console.log('[Operator] Disconnected from seed');
        this.isConnectedToMain = false;
        this.scheduleReconnect();
      });

      this.mainSeedWs.on('error', (error: Error) => {
        console.error(`[Operator] WebSocket error with ${seedUrl}:`, error.message);
        // Will try next seed on reconnect
      });

    } catch (error: any) {
      console.error(`[Operator] Failed to connect to seed ${seedUrl}:`, error.message);
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;

    const delay = this.allSeedUrls.length > 1 ? 5000 : 10000; // Faster retry with multiple seeds
    console.log(`[Operator] Will try next seed in ${delay/1000} seconds...`);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connectToMainSeed();
    }, delay);
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
      case 'ephemeral_event':
        try {
          const sourceOperatorId = String(message?.sourceOperatorId || '').trim();
          const eventData = message?.event as EphemeralEvent;
          if (eventData && eventData.eventId && eventData.eventType && this.ephemeralStore) {
            // DEBUG: Log received content sizes
            const ep = eventData.payload as any;
            const recvContentLen = typeof ep?.encryptedContent === 'string' ? ep.encryptedContent.length : 0;
            const recvForSenderLen = typeof ep?.encryptedForSender === 'string' ? ep.encryptedForSender.length : 0;
            const recvHasChunks = !!ep?.__chunks_encryptedContent;
            const recvIsChunked = typeof ep?.encryptedContent === 'string' && ep.encryptedContent.startsWith('__chunked:');
            console.log(`[Ephemeral] 📨 Received from seed ${eventData.eventId.substring(0,8)}... contentLen=${recvContentLen}, forSenderLen=${recvForSenderLen}, hasChunks=${recvHasChunks}, isChunked=${recvIsChunked}`);
            
            // Clone payload before importEvent mutates it via extractLargeContent
            const broadcastCopy = { ...eventData, payload: { ...eventData.payload } };
            const imported = await this.ephemeralStore.importEvent(eventData);
            if (imported) {
              // DEBUG: Log broadcast copy content sizes
              const bp = broadcastCopy.payload as any;
              const bcContentLen = typeof bp?.encryptedContent === 'string' ? bp.encryptedContent.length : 0;
              console.log(`[Ephemeral] 📤 Broadcasting copy contentLen=${bcContentLen}`);
              this.broadcastEphemeralEvent(broadcastCopy, sourceOperatorId, true);
            }
          }
        } catch (e: any) {
          console.log(`[Ephemeral] Error importing event from seed:`, e?.message);
        }
        break;
      case 'ephemeral_sync_request':
        try {
          const sinceTimestamp = Number(message?.since || 0);
          const maxEvents = Math.min(Number(message?.limit || 500), 1000);
          const events = this.ephemeralStore!.getEventsSince(sinceTimestamp, maxEvents);

          // Restore content from disk before sending - in-memory events have __contentRef: placeholders
          const eventsWithContent = await this.ephemeralStore!.restoreEventsContent(events);

          this.mainSeedWs?.send(JSON.stringify({
            type: 'ephemeral_sync_response',
            events: eventsWithContent,
            sinceTimestamp,
            latestTimestamp: this.ephemeralStore!.getLatestTimestamp(),
          }));
          console.log(`[Ephemeral] 📤 Sent ${eventsWithContent.length} events in sync response to seed (content restored)`);
        } catch (e: any) {
          console.log(`[Ephemeral] Error handling seed sync request:`, e?.message);
        }
        break;
      case 'ephemeral_sync_response':
        try {
          const events = message?.events as EphemeralEvent[];
          if (Array.isArray(events) && this.ephemeralStore) {
            for (const ev of events) {
              await this.ephemeralStore.importEvent(ev);
            }
          }
        } catch (e: any) {
          console.log(`[Ephemeral] Error processing seed sync response:`, e?.message);
        }
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

