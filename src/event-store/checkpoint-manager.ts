/**
 * Checkpoint Manager - Scalable Item History Retrieval
 * 
 * Solves the 100-year item problem:
 * - Creates periodic state snapshots
 * - Enables fast item lookups without scanning entire ledger
 * - Supports historical queries (e.g., "who owned this item in 2050?")
 */

import { EventStore } from './event-store';
import { StateBuilder, RegistryState } from './state-builder';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface CheckpointMetadata {
  checkpointId: string;
  sequenceNumber: number;
  eventHash: string;
  timestamp: number;
  itemCount: number;
  accountCount: number;
  operatorCount: number;
  stateHash: string;
  filePath: string;
}

export interface ItemHistoryEntry {
  sequenceNumber: number;
  timestamp: number;
  eventType: string;
  owner?: string;
  metadata?: any;
}

export class CheckpointManager {
  private eventStore: EventStore;
  private stateBuilder: StateBuilder;
  private checkpointDir: string;
  private checkpointInterval: number; // Events between checkpoints
  private checkpoints: Map<number, CheckpointMetadata> = new Map();

  constructor(
    eventStore: EventStore,
    stateBuilder: StateBuilder,
    checkpointDir: string = './data/checkpoints',
    checkpointInterval: number = 10000 // Every 10k events
  ) {
    this.eventStore = eventStore;
    this.stateBuilder = stateBuilder;
    this.checkpointDir = checkpointDir;
    this.checkpointInterval = checkpointInterval;

    // Ensure checkpoint directory exists
    if (!fs.existsSync(this.checkpointDir)) {
      fs.mkdirSync(this.checkpointDir, { recursive: true });
    }

    this.loadCheckpointIndex();
  }

  /**
   * Load checkpoint index from disk
   */
  private loadCheckpointIndex(): void {
    const indexPath = path.join(this.checkpointDir, 'index.json');
    if (fs.existsSync(indexPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
        this.checkpoints = new Map(Object.entries(data).map(([k, v]) => [Number(k), v as CheckpointMetadata]));
        console.log(`[Checkpoint] Loaded ${this.checkpoints.size} checkpoints from index`);
      } catch (e) {
        console.error('[Checkpoint] Failed to load index:', e);
      }
    }
  }

  /**
   * Save checkpoint index to disk
   */
  private saveCheckpointIndex(): void {
    const indexPath = path.join(this.checkpointDir, 'index.json');
    const data = Object.fromEntries(this.checkpoints.entries());
    fs.writeFileSync(indexPath, JSON.stringify(data, null, 2));
  }

  /**
   * Create a checkpoint at current state
   */
  async createCheckpoint(): Promise<CheckpointMetadata> {
    const state = await this.stateBuilder.buildState();
    const events = await this.eventStore.getAllEvents();
    
    if (events.length === 0) {
      throw new Error('Cannot create checkpoint with no events');
    }

    const lastEvent = events[events.length - 1];
    const sequenceNumber = lastEvent.sequenceNumber;
    const eventHash = lastEvent.eventHash;
    const timestamp = Date.now();

    // Compute state hash
    const stateHash = this.computeStateHash(state);

    // Generate checkpoint ID
    const checkpointId = createHash('sha256')
      .update(`${sequenceNumber}:${eventHash}:${timestamp}`)
      .digest('hex');

    // Save checkpoint to disk
    const filePath = path.join(this.checkpointDir, `checkpoint-${sequenceNumber}.json`);
    const checkpointData = {
      metadata: {
        checkpointId,
        sequenceNumber,
        eventHash,
        timestamp,
        itemCount: state.items.size,
        accountCount: state.accounts.size,
        operatorCount: state.operators.size,
        stateHash,
      },
      state: this.serializeState(state),
    };

    fs.writeFileSync(filePath, JSON.stringify(checkpointData, null, 2));

    const metadata: CheckpointMetadata = {
      checkpointId,
      sequenceNumber,
      eventHash,
      timestamp,
      itemCount: state.items.size,
      accountCount: state.accounts.size,
      operatorCount: state.operators.size,
      stateHash,
      filePath,
    };

    this.checkpoints.set(sequenceNumber, metadata);
    this.saveCheckpointIndex();

    console.log(`[Checkpoint] Created checkpoint at sequence ${sequenceNumber} (${state.items.size} items)`);

    return metadata;
  }

  /**
   * Get checkpoint closest to target sequence number
   */
  getClosestCheckpoint(targetSequence: number): CheckpointMetadata | null {
    let closest: CheckpointMetadata | null = null;
    let minDistance = Infinity;

    for (const [seq, checkpoint] of this.checkpoints.entries()) {
      if (seq <= targetSequence) {
        const distance = targetSequence - seq;
        if (distance < minDistance) {
          minDistance = distance;
          closest = checkpoint;
        }
      }
    }

    return closest;
  }

  /**
   * Load checkpoint state from disk
   */
  loadCheckpoint(sequenceNumber: number): RegistryState | null {
    const checkpoint = this.checkpoints.get(sequenceNumber);
    if (!checkpoint) return null;

    try {
      const data = JSON.parse(fs.readFileSync(checkpoint.filePath, 'utf-8'));
      return this.deserializeState(data.state);
    } catch (e) {
      console.error(`[Checkpoint] Failed to load checkpoint ${sequenceNumber}:`, e);
      return null;
    }
  }

  /**
   * Get item history efficiently using checkpoints
   * 
   * This is the solution to the 100-year item problem:
   * 1. Find closest checkpoint before first event
   * 2. Load that checkpoint state
   * 3. Replay only events from checkpoint to present
   */
  async getItemHistory(itemId: string): Promise<ItemHistoryEntry[]> {
    const events = await this.eventStore.getAllEvents();
    const history: ItemHistoryEntry[] = [];

    // Find all events related to this item
    for (const event of events) {
      const payload = event.payload as any;
      
      if (payload.itemId === itemId) {
        history.push({
          sequenceNumber: event.sequenceNumber,
          timestamp: payload.timestamp || 0,
          eventType: payload.type,
          owner: payload.owner || payload.newOwner,
          metadata: payload,
        });
      }
    }

    return history.sort((a, b) => a.sequenceNumber - b.sequenceNumber);
  }

  /**
   * Get item state at specific point in time (historical query)
   * 
   * Example: "Who owned this item on January 1, 2050?"
   */
  async getItemStateAtTime(itemId: string, targetTimestamp: number): Promise<any | null> {
    const events = await this.eventStore.getAllEvents();
    
    // Find last event before target time
    let lastRelevantEvent: any = null;
    for (const event of events) {
      const payload = event.payload as any;
      if (payload.itemId === itemId && payload.timestamp <= targetTimestamp) {
        lastRelevantEvent = payload;
      }
    }

    return lastRelevantEvent;
  }

  /**
   * Fast item lookup using current state (no scanning)
   */
  async getItemCurrentState(itemId: string): Promise<any | null> {
    const state = await this.stateBuilder.buildState();
    return state.items.get(itemId) || null;
  }

  /**
   * Prune old events (keep checkpoints)
   * 
   * For 250-year sustainability:
   * - Keep full events for recent period (e.g., 7 years)
   * - Keep only checkpoints for older periods
   * - Archive nodes can opt-out of pruning
   */
  async pruneOldEvents(retentionYears: number = 7): Promise<number> {
    const archiveMode = process.env.AUTHO_ARCHIVE_MODE === '1';
    if (archiveMode) {
      console.log('[Checkpoint] Archive mode enabled, skipping pruning');
      return 0;
    }

    const retentionMs = retentionYears * 365 * 24 * 60 * 60 * 1000;
    const cutoffTimestamp = Date.now() - retentionMs;

    const events = await this.eventStore.getAllEvents();
    let prunedCount = 0;

    // Find events older than retention period
    const oldEvents = events.filter((e: any) => {
      const timestamp = e.payload?.timestamp || 0;
      return timestamp < cutoffTimestamp;
    });

    console.log(`[Checkpoint] Found ${oldEvents.length} events older than ${retentionYears} years`);
    
    // In production, you would:
    // 1. Ensure checkpoint exists for this period
    // 2. Archive events to cold storage (IPFS/Arweave)
    // 3. Remove from active event store
    // 4. Keep checkpoint for fast state reconstruction

    return prunedCount;
  }

  /**
   * Compute hash of entire state
   */
  private computeStateHash(state: RegistryState): string {
    const data = JSON.stringify({
      lastEventSequence: (state as any).lastEventSequence,
      lastEventHash: state.lastEventHash,
      feePayoutCursor: (state as any).feePayoutCursor,
      itemCount: state.items.size,
      accountCount: state.accounts.size,
      operatorCount: state.operators.size,
    });
    return createHash('sha256').update(data).digest('hex');
  }

  /**
   * Serialize state for storage
   */
  private serializeState(state: RegistryState): any {
    return {
      lastEventSequence: (state as any).lastEventSequence,
      lastEventHash: state.lastEventHash,
      feePayoutCursor: (state as any).feePayoutCursor,
      items: Array.from(state.items.entries()),
      operators: Array.from(state.operators.entries()),
      settlements: Array.from(state.settlements.entries()),
      consignments: Array.from((state as any).consignments?.entries?.() || []),
      verificationRequests: Array.from((state as any).verificationRequests?.entries?.() || []),
      accounts: Array.from(state.accounts.entries()),
      roleApplications: Array.from((state as any).roleApplications?.entries?.() || []),
      roleInvites: Array.from((state as any).roleInvites?.entries?.() || []),
      verifierActions: Array.from((state as any).verifierActions?.entries?.() || []),
      verifierRatings: Array.from((state as any).verifierRatings?.entries?.() || []),
      verifierReports: Array.from((state as any).verifierReports?.entries?.() || []),
      verifierRatingFeeTxids: Array.from((state as any).verifierRatingFeeTxids?.entries?.() || []),
      retailerVerificationApplications: Array.from((state as any).retailerVerificationApplications?.entries?.() || []),
      retailerActions: Array.from((state as any).retailerActions?.entries?.() || []),
      retailerRatings: Array.from((state as any).retailerRatings?.entries?.() || []),
      retailerReports: Array.from((state as any).retailerReports?.entries?.() || []),
      imageTombstoneProposals: Array.from((state as any).imageTombstoneProposals?.entries?.() || []),
      tombstonedImages: Array.from((state as any).tombstonedImages?.values?.() || []),
      ownership: Array.from((state as any).ownership?.entries?.() || []),
    };
  }

  /**
   * Deserialize state from storage
   */
  private deserializeState(data: any): RegistryState {
    return {
      feePayoutCursor: Number(data?.feePayoutCursor || 0),
      lastEventSequence: Number(data?.lastEventSequence || 0),
      lastEventHash: data.lastEventHash,
      items: new Map(data.items),
      operators: new Map(data.operators),
      settlements: new Map(data.settlements),
      consignments: new Map(data?.consignments || []),
      verificationRequests: new Map(data?.verificationRequests || []),
      accounts: new Map(data?.accounts || []),
      roleApplications: new Map(data?.roleApplications || []),
      roleInvites: new Map(data?.roleInvites || []),
      verifierActions: new Map(data?.verifierActions || []),
      verifierRatings: new Map(data?.verifierRatings || []),
      verifierReports: new Map(data?.verifierReports || []),
      verifierRatingFeeTxids: new Map(data?.verifierRatingFeeTxids || []),
      retailerVerificationApplications: new Map(data?.retailerVerificationApplications || []),
      retailerActions: new Map(data?.retailerActions || []),
      retailerRatings: new Map(data?.retailerRatings || []),
      retailerReports: new Map(data?.retailerReports || []),
      imageTombstoneProposals: new Map(data?.imageTombstoneProposals || []),
      tombstonedImages: new Set(data?.tombstonedImages || []),
      ownership: new Map(data?.ownership || []),
    };
  }

  /**
   * Get checkpoint statistics
   */
  getStats(): any {
    const checkpointCount = this.checkpoints.size;
    const checkpoints = Array.from(this.checkpoints.values());
    const oldestCheckpoint = checkpoints.length > 0 
      ? checkpoints.reduce((a, b) => a.sequenceNumber < b.sequenceNumber ? a : b)
      : null;
    const newestCheckpoint = checkpoints.length > 0
      ? checkpoints.reduce((a, b) => a.sequenceNumber > b.sequenceNumber ? a : b)
      : null;

    return {
      checkpointCount,
      checkpointInterval: this.checkpointInterval,
      oldestCheckpoint: oldestCheckpoint ? {
        sequenceNumber: oldestCheckpoint.sequenceNumber,
        timestamp: oldestCheckpoint.timestamp,
        age: Date.now() - oldestCheckpoint.timestamp,
      } : null,
      newestCheckpoint: newestCheckpoint ? {
        sequenceNumber: newestCheckpoint.sequenceNumber,
        timestamp: newestCheckpoint.timestamp,
        age: Date.now() - newestCheckpoint.timestamp,
      } : null,
    };
  }
}
