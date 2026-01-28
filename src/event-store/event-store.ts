/**
 * Event Store Implementation
 * 
 * Append-only event log with hash chains for the decentralized registry.
 * Each event is content-addressed and linked to the previous event.
 */

import * as fs from 'fs';
import * as path from 'path';
import { sha256 } from '../crypto';
import { canonicalCborEncode } from '../crypto/canonical-cbor';
import { AtomicStorage, atomicWriteJSON, atomicReadJSONWithRecovery } from '../storage/atomic-storage';
import {
  Event,
  EventPayload,
  EventStoreState,
  QuorumSignature,
  CheckpointData,
} from './types';

/**
 * Sequence Index Entry - Maps sequence number to event hash for O(1) lookups
 * Like Bitcoin's block index (blkindex.dat)
 */
interface SequenceIndex {
  version: number;
  entries: { [sequence: number]: string };  // sequence -> eventHash
  lastUpdated: number;
}

/**
 * Write-Ahead Log Entry - Records pending operations for crash recovery
 * Like Bitcoin's wallet.dat journal
 */
interface WALEntry {
  operation: 'append_event';
  eventHash: string;
  sequenceNumber: number;
  timestamp: number;
  completed: boolean;
}

export class EventStore {
  private dataDir: string;
  private eventsDir: string;
  private stateFile: string;
  private indexFile: string;
  private walFile: string;
  private state: EventStoreState;
  private sequenceIndex: SequenceIndex;
  private integrityVerified: boolean = false;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.eventsDir = path.join(dataDir, 'events');
    this.stateFile = path.join(dataDir, 'event-store-state.json');
    this.indexFile = path.join(dataDir, 'sequence-index.json');
    this.walFile = path.join(dataDir, 'wal.json');

    // Initialize directories
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    if (!fs.existsSync(this.eventsDir)) {
      fs.mkdirSync(this.eventsDir, { recursive: true });
    }

    // Load or initialize state
    this.state = this.loadState();
    
    // Load or rebuild sequence index
    this.sequenceIndex = this.loadOrRebuildIndex();
    
    // Recover from any interrupted operations (WAL replay)
    this.recoverFromWAL();
  }

  /**
   * Initialize and verify integrity on startup (like Bitcoin's -reindex)
   * Call this before accepting any writes
   */
  async initializeWithVerification(): Promise<{ valid: boolean; error?: string }> {
    console.log('[EventStore] Starting integrity verification...');
    const startTime = Date.now();
    
    // Verify hash chain integrity
    const isValid = await this.verifyHashChain();
    
    if (!isValid) {
      console.error('[EventStore] ❌ INTEGRITY CHECK FAILED - Chain is corrupted!');
      return { valid: false, error: 'Hash chain integrity verification failed' };
    }
    
    // Verify index matches actual events
    const indexValid = await this.verifyIndex();
    if (!indexValid) {
      console.warn('[EventStore] Index mismatch detected, rebuilding...');
      this.sequenceIndex = await this.rebuildIndex();
    }
    
    this.integrityVerified = true;
    const elapsed = Date.now() - startTime;
    console.log(`[EventStore] ✅ Integrity verified in ${elapsed}ms (${this.state.eventCount} events)`);
    
    return { valid: true };
  }

  /**
   * Append a new event to the log with WAL protection
   * Like Bitcoin's transaction journaling
   */
  async appendEvent(
    payload: EventPayload,
    signatures: QuorumSignature[]
  ): Promise<Event> {
    // Create event object
    const event: Event = {
      eventHash: '', // Will be calculated
      prevEventHash: this.state.headHash,
      sequenceNumber: this.state.sequenceNumber + 1,
      payload,
      signatures,
      createdAt: Date.now(),
    };

    // Calculate event hash (content-addressed)
    event.eventHash = this.calculateEventHash(event);

    // Validate hash chain
    if (!this.validateHashChain(event)) {
      throw new Error('Hash chain validation failed');
    }

    // Step 1: Write to WAL (intent to write)
    this.writeWAL({
      operation: 'append_event',
      eventHash: event.eventHash,
      sequenceNumber: event.sequenceNumber,
      timestamp: Date.now(),
      completed: false,
    });

    // Step 2: Persist event to disk
    await this.persistEvent(event);

    // Step 3: Update index
    this.sequenceIndex.entries[event.sequenceNumber] = event.eventHash;
    this.sequenceIndex.lastUpdated = Date.now();
    this.saveIndex();

    // Step 4: Update state
    this.state.headHash = event.eventHash;
    this.state.sequenceNumber = event.sequenceNumber;
    this.state.eventCount++;
    this.saveState();

    // Step 5: Clear WAL (operation complete)
    this.clearWAL();

    return event;
  }

  async appendExistingEvent(event: Event): Promise<void> {
    const eventFile = path.join(this.eventsDir, `${event.eventHash}.json`);
    if (fs.existsSync(eventFile)) {
      return;
    }

    // Skip hash validation during sync - trust main node's events
    // Only validate sequence continuity
    const expectedSeq = this.state.sequenceNumber + 1;
    if (event.sequenceNumber !== expectedSeq) {
      throw new Error(`Unexpected sequenceNumber (expected ${expectedSeq}, got ${event.sequenceNumber})`);
    }

    // Write to WAL first
    this.writeWAL({
      operation: 'append_event',
      eventHash: event.eventHash,
      sequenceNumber: event.sequenceNumber,
      timestamp: Date.now(),
      completed: false,
    });

    // Accept event with its existing hash, don't validate chain links during sync
    await this.persistEvent(event);

    // Update index
    this.sequenceIndex.entries[event.sequenceNumber] = event.eventHash;
    this.sequenceIndex.lastUpdated = Date.now();
    
    // Batch save index every 100 events for performance
    if (event.sequenceNumber % 100 === 0) {
      this.saveIndex();
    }

    this.state.headHash = event.eventHash;
    this.state.sequenceNumber = event.sequenceNumber;
    this.state.eventCount++;
    this.saveState();
    
    // Clear WAL
    this.clearWAL();
  }

  /**
   * Get event by sequence number - O(1) lookup using index
   * Like Bitcoin's block height lookup
   */
  async getEventBySequence(sequence: number): Promise<Event | null> {
    const eventHash = this.sequenceIndex.entries[sequence];
    if (!eventHash) {
      return null;
    }
    return this.getEvent(eventHash);
  }

  /**
   * Get event by hash with checksum verification
   */
  async getEvent(eventHash: string): Promise<Event | null> {
    const eventFile = path.join(this.eventsDir, `${eventHash}.json`);
    
    if (!AtomicStorage.exists(eventFile)) {
      return null;
    }

    const result = atomicReadJSONWithRecovery<Event>(eventFile);
    if (result.success && result.data) {
      if (result.recoveredFromBackup) {
        console.warn(`[EventStore] Event ${eventHash} recovered from backup`);
      }
      return result.data;
    }
    
    console.error(`[EventStore] Failed to read event ${eventHash}:`, result.error);
    return null;
  }

  /**
   * Get events by sequence range with checksum verification
   */
  async getEventsBySequence(
    fromSequence: number,
    toSequence: number
  ): Promise<Event[]> {
    const events: Event[] = [];
    
    // Read all event files and filter by sequence
    const files = fs.readdirSync(this.eventsDir);
    
    for (const file of files) {
      // Skip temp and backup files
      if (!file.endsWith('.json') || file.endsWith('.tmp') || file.endsWith('.bak')) continue;
      
      const eventFile = path.join(this.eventsDir, file);
      const result = atomicReadJSONWithRecovery<Event>(eventFile);
      
      if (!result.success || !result.data) {
        console.warn(`[EventStore] Skipping corrupted event file: ${file}`);
        continue;
      }
      
      const event = result.data;
      if (event.sequenceNumber >= fromSequence && event.sequenceNumber <= toSequence) {
        events.push(event);
      }
    }

    // Sort by sequence number
    events.sort((a, b) => a.sequenceNumber - b.sequenceNumber);
    
    return events;
  }

  /**
   * Get all events (for building state)
   */
  async getAllEvents(): Promise<Event[]> {
    return this.getEventsBySequence(1, this.state.sequenceNumber);
  }

  /**
   * Get all events for a specific item ID
   */
  async getEventsByItemId(itemId: string): Promise<Event[]> {
    const allEvents = await this.getAllEvents();
    
    // Filter events that relate to this item
    return allEvents.filter(event => {
      const payload = event.payload as any;
      return payload.itemId === itemId;
    });
  }

  /**
   * Verify hash chain integrity
   */
  async verifyHashChain(): Promise<boolean> {
    const events = await this.getAllEvents();
    
    let prevHash = '';
    
    for (const event of events) {
      // Verify event hash
      const calculatedHash = this.calculateEventHash(event);
      if (calculatedHash !== event.eventHash) {
        const legacyHash = this.calculateLegacyEventHash(event);
        if (legacyHash !== event.eventHash) {
          console.error(`Event ${event.sequenceNumber} hash mismatch`);
          return false;
        }
      }

      // Verify chain link
      if (event.prevEventHash !== prevHash) {
        console.error(`Event ${event.sequenceNumber} chain link broken`);
        return false;
      }

      prevHash = event.eventHash;
    }

    return true;
  }

  /**
   * Get current state
   */
  getState(): EventStoreState {
    return { ...this.state };
  }

  /**
   * Create checkpoint for Bitcoin anchoring
   */
  async createCheckpoint(): Promise<CheckpointData> {
    const events = await this.getAllEvents();
    
    // Calculate Merkle root of all event hashes
    const eventHashes = events.map(e => e.eventHash);
    const merkleRoot = this.calculateMerkleRoot(eventHashes);

    const checkpoint: CheckpointData = {
      checkpointRoot: sha256(`${this.state.headHash}:${merkleRoot}:${Date.now()}`),
      fromSequence: 1,
      toSequence: this.state.sequenceNumber,
      eventCount: this.state.eventCount,
      merkleRoot,
      createdAt: Date.now(),
    };

    // Save checkpoint using atomic write
    const checkpointFile = path.join(this.dataDir, `checkpoint-${checkpoint.checkpointRoot}.json`);
    atomicWriteJSON(checkpointFile, checkpoint);

    this.state.lastCheckpointHash = checkpoint.checkpointRoot;
    this.state.lastCheckpointAt = checkpoint.createdAt;
    this.saveState();

    return checkpoint;
  }

  /**
   * Calculate event hash (content-addressed)
   */
  private calculateEventHash(event: Event): string {
    // Create canonical representation
    const canonical = {
      prevEventHash: event.prevEventHash,
      sequenceNumber: event.sequenceNumber,
      payload: event.payload,
      signatures: event.signatures,
      createdAt: event.createdAt,
    };

    const domainSep = Buffer.from('AUTHO_EVT_V1_SHA256', 'utf8');
    const delimiter = Buffer.from([0x00]);
    const canonicalBytes = canonicalCborEncode(canonical);
    return sha256(Buffer.concat([domainSep, delimiter, canonicalBytes]));
  }

  private calculateLegacyEventHash(event: Event): string {
    return sha256(JSON.stringify({
      prevEventHash: event.prevEventHash,
      sequenceNumber: event.sequenceNumber,
      payload: event.payload,
      signatures: event.signatures,
      createdAt: event.createdAt,
    }));
  }

  /**
   * Validate hash chain link
   */
  private validateHashChain(event: Event): boolean {
    // Genesis event
    if (event.sequenceNumber === 1) {
      return event.prevEventHash === '';
    }

    // Must reference current head
    return event.prevEventHash === this.state.headHash;
  }

  /**
   * Persist event to disk using atomic write
   * This ensures crash-safety - either the full event is written or nothing
   */
  private async persistEvent(event: Event): Promise<void> {
    const eventFile = path.join(this.eventsDir, `${event.eventHash}.json`);
    atomicWriteJSON(eventFile, event);
  }

  /**
   * Load state from disk with atomic recovery
   * If main file is corrupted, automatically recovers from backup
   */
  private loadState(): EventStoreState {
    // Clean up any orphaned temp files from interrupted writes
    AtomicStorage.cleanupTempFiles(this.dataDir);
    AtomicStorage.cleanupTempFiles(this.eventsDir);

    if (AtomicStorage.exists(this.stateFile)) {
      const result = atomicReadJSONWithRecovery<EventStoreState>(this.stateFile);
      
      if (result.success && result.data) {
        if (result.recoveredFromBackup) {
          console.warn('[EventStore] State recovered from backup file');
        }
        return result.data;
      }
      
      console.error('[EventStore] Failed to load state:', result.error);
      console.error('[EventStore] Starting with genesis state - DATA MAY BE LOST');
    }

    // Initialize genesis state
    return {
      headHash: '',
      sequenceNumber: 0,
      eventCount: 0,
    };
  }

  /**
   * Save state to disk using atomic write
   * This is the most critical file - if corrupted, we lose track of the chain head
   */
  private saveState(): void {
    atomicWriteJSON(this.stateFile, this.state);
  }

  /**
   * Calculate Merkle root of event hashes
   */
  private calculateMerkleRoot(hashes: string[]): string {
    if (hashes.length === 0) return '';
    if (hashes.length === 1) return hashes[0];

    let currentLevel = hashes;

    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];

      for (let i = 0; i < currentLevel.length; i += 2) {
        if (i + 1 < currentLevel.length) {
          const combined = currentLevel[i] + currentLevel[i + 1];
          nextLevel.push(sha256(combined));
        } else {
          nextLevel.push(currentLevel[i]);
        }
      }

      currentLevel = nextLevel;
    }

    return currentLevel[0];
  }

  // ============================================================
  // BITCOIN-LIKE DURABILITY FEATURES
  // ============================================================

  /**
   * Load or rebuild the sequence index
   * Like Bitcoin's block index that maps height -> block hash
   */
  private loadOrRebuildIndex(): SequenceIndex {
    if (AtomicStorage.exists(this.indexFile)) {
      const result = atomicReadJSONWithRecovery<SequenceIndex>(this.indexFile);
      if (result.success && result.data) {
        // Verify index version and basic sanity
        if (result.data.version === 1 && typeof result.data.entries === 'object') {
          console.log(`[EventStore] Loaded sequence index with ${Object.keys(result.data.entries).length} entries`);
          return result.data;
        }
      }
    }

    // Index missing or corrupted - rebuild from events
    console.log('[EventStore] Building sequence index from events...');
    return this.rebuildIndexSync();
  }

  /**
   * Rebuild index synchronously (used during startup)
   */
  private rebuildIndexSync(): SequenceIndex {
    const index: SequenceIndex = {
      version: 1,
      entries: {},
      lastUpdated: Date.now(),
    };

    if (!fs.existsSync(this.eventsDir)) {
      // Save empty index
      atomicWriteJSON(this.indexFile, index);
      return index;
    }

    const files = fs.readdirSync(this.eventsDir);
    let count = 0;

    for (const file of files) {
      if (!file.endsWith('.json') || file.endsWith('.tmp') || file.endsWith('.bak')) continue;

      try {
        const eventFile = path.join(this.eventsDir, file);
        const result = atomicReadJSONWithRecovery<Event>(eventFile);
        
        if (result.success && result.data) {
          index.entries[result.data.sequenceNumber] = result.data.eventHash;
          count++;
        }
      } catch (err) {
        console.warn(`[EventStore] Skipping unreadable file during index rebuild: ${file}`);
      }
    }

    index.lastUpdated = Date.now();
    // Save index directly (this.sequenceIndex may not be set yet)
    atomicWriteJSON(this.indexFile, index);
    console.log(`[EventStore] Built index with ${count} entries`);
    return index;
  }

  /**
   * Rebuild index asynchronously (for reindexing)
   */
  private async rebuildIndex(): Promise<SequenceIndex> {
    return this.rebuildIndexSync();
  }

  /**
   * Verify that index matches actual events
   */
  private async verifyIndex(): Promise<boolean> {
    const indexEntryCount = Object.keys(this.sequenceIndex.entries).length;
    
    // Quick check: entry count should match state
    if (indexEntryCount !== this.state.eventCount) {
      console.warn(`[EventStore] Index entry count (${indexEntryCount}) != state event count (${this.state.eventCount})`);
      return false;
    }

    // Verify head hash is in index
    if (this.state.sequenceNumber > 0) {
      const headInIndex = this.sequenceIndex.entries[this.state.sequenceNumber];
      if (headInIndex !== this.state.headHash) {
        console.warn(`[EventStore] Index head hash mismatch`);
        return false;
      }
    }

    return true;
  }

  /**
   * Save sequence index to disk
   */
  private saveIndex(): void {
    atomicWriteJSON(this.indexFile, this.sequenceIndex);
  }

  /**
   * Write-Ahead Log operations
   * Like Bitcoin's wallet journal - records intent before action
   */
  private writeWAL(entry: WALEntry): void {
    atomicWriteJSON(this.walFile, entry);
  }

  private clearWAL(): void {
    if (fs.existsSync(this.walFile)) {
      try {
        fs.unlinkSync(this.walFile);
      } catch (err) {
        // Ignore - WAL cleanup is best-effort
      }
    }
    // Also clean up backup
    const walBackup = this.walFile + '.bak';
    if (fs.existsSync(walBackup)) {
      try {
        fs.unlinkSync(walBackup);
      } catch (err) {
        // Ignore
      }
    }
  }

  /**
   * Recover from interrupted operations using WAL
   * Called on startup to complete any partially-written events
   */
  private recoverFromWAL(): void {
    if (!fs.existsSync(this.walFile)) {
      return;
    }

    console.log('[EventStore] WAL file found - checking for interrupted operations...');

    try {
      const result = atomicReadJSONWithRecovery<WALEntry>(this.walFile);
      
      if (!result.success || !result.data) {
        console.log('[EventStore] WAL file unreadable, clearing...');
        this.clearWAL();
        return;
      }

      const wal = result.data;

      // Check if the event was actually written
      const eventFile = path.join(this.eventsDir, `${wal.eventHash}.json`);
      
      if (fs.existsSync(eventFile)) {
        // Event was written - check if state/index were updated
        if (this.state.sequenceNumber < wal.sequenceNumber) {
          console.log(`[EventStore] Recovering interrupted write for sequence ${wal.sequenceNumber}...`);
          
          // Update state
          this.state.headHash = wal.eventHash;
          this.state.sequenceNumber = wal.sequenceNumber;
          this.state.eventCount = wal.sequenceNumber; // Approximate
          this.saveState();

          // Update index
          this.sequenceIndex.entries[wal.sequenceNumber] = wal.eventHash;
          this.sequenceIndex.lastUpdated = Date.now();
          this.saveIndex();

          console.log(`[EventStore] ✅ Recovered event ${wal.sequenceNumber}`);
        }
      } else {
        // Event file doesn't exist - the write failed, nothing to recover
        console.log('[EventStore] WAL indicates incomplete write, no recovery needed');
      }

      // Clear WAL
      this.clearWAL();

    } catch (err) {
      console.error('[EventStore] WAL recovery error:', err);
      this.clearWAL();
    }
  }

  /**
   * Force a full reindex (like Bitcoin's -reindex flag)
   */
  async reindex(): Promise<void> {
    console.log('[EventStore] Starting full reindex...');
    const startTime = Date.now();

    // Rebuild index from scratch
    this.sequenceIndex = await this.rebuildIndex();

    // Verify chain integrity
    const valid = await this.verifyHashChain();
    if (!valid) {
      throw new Error('Hash chain verification failed during reindex');
    }

    const elapsed = Date.now() - startTime;
    console.log(`[EventStore] ✅ Reindex complete in ${elapsed}ms`);
  }

  /**
   * Get storage statistics (like Bitcoin's gettxoutsetinfo)
   */
  getStorageStats(): {
    eventCount: number;
    indexEntries: number;
    headHash: string;
    sequenceNumber: number;
    integrityVerified: boolean;
    dataDir: string;
  } {
    return {
      eventCount: this.state.eventCount,
      indexEntries: Object.keys(this.sequenceIndex.entries).length,
      headHash: this.state.headHash,
      sequenceNumber: this.state.sequenceNumber,
      integrityVerified: this.integrityVerified,
      dataDir: this.dataDir,
    };
  }
}
