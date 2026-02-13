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
  buildMerkleTree, 
  generateMerkleProof, 
  verifyMerkleProof,
  compactifyProof,
  MerkleProof,
  CompactMerkleProof,
  MerkleTreeResult,
  BitcoinAnchorableProof,
  formatForOpReturn,
} from '../crypto/merkle-tree';
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

/**
 * Segment Index Entry - Maps event hash to segment file + byte offset for O(1) reads
 * Like Bitcoin's block index mapping block hash to blk*.dat file position
 */
interface SegmentIndexEntry {
  seg: number;     // Segment file number
  off: number;     // Byte offset within segment file
  len: number;     // Length of the JSON line in bytes
}

interface SegmentIndex {
  version: number;
  entries: { [eventHash: string]: SegmentIndexEntry };
  currentSegment: number;       // Active segment number being written to
  currentSegmentEvents: number; // How many events in the current segment
  lastUpdated: number;
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

  // LRU event cache — avoids repeated disk reads for hot events
  // Configurable: AUTHO_EVENT_CACHE_SIZE (default 10000 operators, 2000 gateways)
  private eventCache: Map<string, Event> = new Map();
  private eventCacheMaxSize: number;
  private eventCacheHits: number = 0;
  private eventCacheMisses: number = 0;

  // Segment-based event storage — like Bitcoin's blk*.dat files
  // Batches events into segment files instead of 1-file-per-event
  // Eliminates filesystem overhead at scale (100K+ events)
  private segmentsDir: string;
  private segmentIndexFile: string;
  private segmentIndex: SegmentIndex;
  private segmentMaxEvents: number;  // Events per segment (default 1000)
  private useSegments: boolean = true; // New events always go to segments

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.eventsDir = path.join(dataDir, 'events');
    this.stateFile = path.join(dataDir, 'event-store-state.json');
    this.indexFile = path.join(dataDir, 'sequence-index.json');
    this.walFile = path.join(dataDir, 'wal.json');

    // Set cache size based on node type
    const envCacheSize = Number(process.env.AUTHO_EVENT_CACHE_SIZE);
    if (envCacheSize > 0) {
      this.eventCacheMaxSize = envCacheSize;
    } else {
      const isGateway = process.env.AUTHO_NODE_TYPE === 'gateway' || process.env.GATEWAY_MODE === 'true';
      this.eventCacheMaxSize = isGateway ? 2000 : 10000;
    }

    // Segment storage config
    this.segmentsDir = path.join(dataDir, 'segments');
    this.segmentIndexFile = path.join(dataDir, 'segment-index.json');
    this.segmentMaxEvents = Number(process.env.AUTHO_SEGMENT_SIZE) || 1000;

    // Initialize directories
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    if (!fs.existsSync(this.eventsDir)) {
      fs.mkdirSync(this.eventsDir, { recursive: true });
    }
    if (!fs.existsSync(this.segmentsDir)) {
      fs.mkdirSync(this.segmentsDir, { recursive: true });
    }

    // Load or initialize state
    this.state = this.loadState();
    
    // Load or rebuild sequence index
    this.sequenceIndex = this.loadOrRebuildIndex();

    // Load segment index
    this.segmentIndex = this.loadSegmentIndex();
    
    // Recover from any interrupted operations (WAL replay)
    this.recoverFromWAL();

    // Auto-compact: if >500 individual event files exist, compact them into segments on startup
    // This transparently migrates existing nodes to segment storage without manual intervention
    try {
      const individualCount = fs.existsSync(this.eventsDir)
        ? fs.readdirSync(this.eventsDir).filter(f => f.endsWith('.json') && !f.endsWith('.tmp') && !f.endsWith('.bak')).length
        : 0;
      if (individualCount > 500) {
        console.log(`[EventStore] Auto-compacting ${individualCount} individual event files into segments...`);
        this.compactToSegments().catch(err => console.error('[EventStore] Auto-compact failed:', err));
      }
    } catch {}
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

    // Step 6: Populate LRU cache (avoid disk read on next access)
    this.addToCache(event.eventHash, event);

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

    // Populate LRU cache (avoid disk read on next buildState)
    this.addToCache(event.eventHash, event);

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
   * Get event by hash — LRU cache → segment file → individual file (backward compat)
   */
  async getEvent(eventHash: string): Promise<Event | null> {
    // Check LRU cache first
    const cached = this.eventCache.get(eventHash);
    if (cached) {
      this.eventCacheHits++;
      // Move to end (most recently used) by re-inserting
      this.eventCache.delete(eventHash);
      this.eventCache.set(eventHash, cached);
      return cached;
    }

    this.eventCacheMisses++;

    // Check segment index for O(1) read from segment file
    const segEntry = this.segmentIndex.entries[eventHash];
    if (segEntry) {
      const event = this.readEventFromSegment(segEntry);
      if (event) {
        this.addToCache(eventHash, event);
        return event;
      }
    }

    // Fall back to individual event file (backward compat for pre-segment events)
    const eventFile = path.join(this.eventsDir, `${eventHash}.json`);
    
    if (!AtomicStorage.exists(eventFile)) {
      return null;
    }

    const result = atomicReadJSONWithRecovery<Event>(eventFile);
    if (result.success && result.data) {
      if (result.recoveredFromBackup) {
        console.warn(`[EventStore] Event ${eventHash} recovered from backup`);
      }
      // Add to LRU cache
      this.addToCache(eventHash, result.data);
      return result.data;
    }
    
    console.error(`[EventStore] Failed to read event ${eventHash}:`, result.error);
    return null;
  }

  /**
   * Read a single event from a segment file using byte offset (O(1) seek)
   */
  private readEventFromSegment(entry: SegmentIndexEntry): Event | null {
    try {
      const segFile = path.join(this.segmentsDir, `seg-${String(entry.seg).padStart(6, '0')}.ndjson`);
      if (!fs.existsSync(segFile)) return null;

      // Read exactly the bytes we need — no scanning
      const fd = fs.openSync(segFile, 'r');
      const buf = Buffer.alloc(entry.len);
      fs.readSync(fd, buf, 0, entry.len, entry.off);
      fs.closeSync(fd);

      return JSON.parse(buf.toString('utf-8').trim());
    } catch (err: any) {
      console.warn(`[EventStore] Failed to read from segment ${entry.seg} offset ${entry.off}: ${err.message}`);
      return null;
    }
  }

  /**
   * Add event to LRU cache, evicting oldest entries if over max size
   */
  private addToCache(eventHash: string, event: Event): void {
    // Evict oldest entries if cache is full
    while (this.eventCache.size >= this.eventCacheMaxSize) {
      const oldestKey = this.eventCache.keys().next().value;
      if (oldestKey) this.eventCache.delete(oldestKey);
      else break;
    }
    this.eventCache.set(eventHash, event);
  }

  /**
   * Get cache statistics for monitoring
   */
  getCacheStats(): { size: number; maxSize: number; hits: number; misses: number; hitRate: string } {
    const total = this.eventCacheHits + this.eventCacheMisses;
    return {
      size: this.eventCache.size,
      maxSize: this.eventCacheMaxSize,
      hits: this.eventCacheHits,
      misses: this.eventCacheMisses,
      hitRate: total > 0 ? `${((this.eventCacheHits / total) * 100).toFixed(1)}%` : '0%',
    };
  }

  /**
   * Get events by sequence range using the sequence index for O(1) lookups per event.
   * Previous implementation read ALL files from disk and filtered — O(N) for every call.
   * Now uses the in-memory sequence index for direct hash lookups — O(range) only.
   */
  async getEventsBySequence(
    fromSequence: number,
    toSequence: number
  ): Promise<Event[]> {
    const events: Event[] = [];

    for (let seq = fromSequence; seq <= toSequence; seq++) {
      const eventHash = this.sequenceIndex.entries[seq];
      if (!eventHash) continue;

      const event = await this.getEvent(eventHash);
      if (event) {
        events.push(event);
      }
    }

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
   * Persist event to disk — uses segment storage (like Bitcoin's blk*.dat)
   * Falls back to individual file if segments are disabled
   */
  private async persistEvent(event: Event): Promise<void> {
    if (this.useSegments) {
      this.persistEventToSegment(event);
    } else {
      const eventFile = path.join(this.eventsDir, `${event.eventHash}.json`);
      atomicWriteJSON(eventFile, event);
    }
  }

  /**
   * Write event to current segment file (NDJSON: one JSON event per line)
   * When segment is full, rotate to next segment
   */
  private persistEventToSegment(event: Event): void {
    // Rotate segment if current is full
    if (this.segmentIndex.currentSegmentEvents >= this.segmentMaxEvents) {
      this.segmentIndex.currentSegment++;
      this.segmentIndex.currentSegmentEvents = 0;
    }

    const segNum = this.segmentIndex.currentSegment;
    const segFile = path.join(this.segmentsDir, `seg-${String(segNum).padStart(6, '0')}.ndjson`);

    // Serialize event to a single JSON line
    const jsonLine = JSON.stringify(event) + '\n';
    const lineBytes = Buffer.byteLength(jsonLine, 'utf-8');

    // Get current file size (byte offset for this event)
    let offset = 0;
    try {
      if (fs.existsSync(segFile)) {
        offset = fs.statSync(segFile).size;
      }
    } catch {}

    // Append to segment file
    fs.appendFileSync(segFile, jsonLine, 'utf-8');

    // Update segment index
    this.segmentIndex.entries[event.eventHash] = { seg: segNum, off: offset, len: lineBytes };
    this.segmentIndex.currentSegmentEvents++;
    this.segmentIndex.lastUpdated = Date.now();

    // Batch save segment index every 50 events for performance
    if (this.segmentIndex.currentSegmentEvents % 50 === 0 || this.segmentIndex.currentSegmentEvents === 1) {
      this.saveSegmentIndex();
    }
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
   * Scans both individual event files AND segment files for full coverage
   */
  private rebuildIndexSync(): SequenceIndex {
    const index: SequenceIndex = {
      version: 1,
      entries: {},
      lastUpdated: Date.now(),
    };

    let count = 0;

    // Phase 1: Scan individual event files (pre-compaction or mixed mode)
    if (fs.existsSync(this.eventsDir)) {
      const files = fs.readdirSync(this.eventsDir);
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
    }

    // Phase 2: Scan segment files (NDJSON — one event per line)
    if (fs.existsSync(this.segmentsDir)) {
      const segFiles = fs.readdirSync(this.segmentsDir)
        .filter(f => f.endsWith('.ndjson'))
        .sort();
      for (const segFile of segFiles) {
        try {
          const content = fs.readFileSync(path.join(this.segmentsDir, segFile), 'utf-8');
          const lines = content.split('\n').filter(l => l.trim());
          for (const line of lines) {
            try {
              const event: Event = JSON.parse(line);
              if (event.sequenceNumber && event.eventHash) {
                index.entries[event.sequenceNumber] = event.eventHash;
                count++;
              }
            } catch {}
          }
        } catch (err) {
          console.warn(`[EventStore] Skipping unreadable segment during index rebuild: ${segFile}`);
        }
      }
    }

    index.lastUpdated = Date.now();
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

  // ============================================================
  // MERKLE PROOF FEATURES (SPV-style lightweight verification)
  // ============================================================

  /**
   * Build a Merkle tree from all events
   * Used for checkpoint creation and proof generation
   */
  async buildEventMerkleTree(): Promise<MerkleTreeResult> {
    const events = await this.getAllEvents();
    const eventHashes = events.map(e => e.eventHash);
    return buildMerkleTree(eventHashes);
  }

  /**
   * Generate a Merkle proof for a specific event
   * This allows lightweight clients to verify event inclusion
   * without downloading the entire chain (like Bitcoin's SPV)
   */
  async generateEventProof(eventHash: string): Promise<MerkleProof | null> {
    const events = await this.getAllEvents();
    const eventHashes = events.map(e => e.eventHash);
    
    const leafIndex = eventHashes.indexOf(eventHash);
    if (leafIndex === -1) {
      return null; // Event not found
    }

    const tree = buildMerkleTree(eventHashes);
    return generateMerkleProof(tree, leafIndex);
  }

  /**
   * Generate a compact proof suitable for external transmission
   */
  async generateCompactEventProof(eventHash: string): Promise<CompactMerkleProof | null> {
    const proof = await this.generateEventProof(eventHash);
    if (!proof) return null;
    return compactifyProof(proof);
  }

  /**
   * Verify that an event is included in a given Merkle root
   * This is the core SPV verification - no full chain needed
   */
  verifyEventInclusion(proof: MerkleProof, expectedRoot: string): boolean {
    if (proof.root !== expectedRoot) {
      return false;
    }
    return verifyMerkleProof(proof);
  }

  /**
   * Generate a Bitcoin-anchorable proof for an event
   * This proof can be verified against a Bitcoin transaction
   */
  async generateBitcoinAnchorableProof(
    eventHash: string,
    checkpointData?: CheckpointData
  ): Promise<BitcoinAnchorableProof | null> {
    const proof = await this.generateCompactEventProof(eventHash);
    if (!proof) return null;

    // Use provided checkpoint or current state
    const checkpoint = checkpointData || {
      checkpointRoot: proof.root,
      fromSequence: 1,
      toSequence: this.state.sequenceNumber,
    };

    return {
      eventHash,
      merkleProof: proof,
      checkpointRoot: checkpoint.checkpointRoot,
      checkpointSequence: {
        from: checkpoint.fromSequence,
        to: checkpoint.toSequence,
      },
      bitcoinTxid: checkpointData?.bitcoinTxid,
      blockHeight: checkpointData?.blockHeight,
    };
  }

  /**
   * Create an enhanced checkpoint with Merkle tree for proof generation
   */
  async createEnhancedCheckpoint(): Promise<CheckpointData & { tree: MerkleTreeResult }> {
    const events = await this.getAllEvents();
    const eventHashes = events.map(e => e.eventHash);
    const tree = buildMerkleTree(eventHashes);

    const checkpoint: CheckpointData = {
      checkpointRoot: sha256(`${this.state.headHash}:${tree.root}:${Date.now()}`),
      fromSequence: 1,
      toSequence: this.state.sequenceNumber,
      eventCount: this.state.eventCount,
      merkleRoot: tree.root,
      createdAt: Date.now(),
    };

    // Save checkpoint
    const checkpointFile = path.join(this.dataDir, `checkpoint-${checkpoint.checkpointRoot}.json`);
    atomicWriteJSON(checkpointFile, { ...checkpoint, treeHeight: tree.treeHeight });

    this.state.lastCheckpointHash = checkpoint.checkpointRoot;
    this.state.lastCheckpointAt = checkpoint.createdAt;
    this.saveState();

    return { ...checkpoint, tree };
  }

  /**
   * Get OP_RETURN data for Bitcoin anchoring
   * This is the 46-byte commitment that goes into a Bitcoin transaction
   */
  async getOpReturnCommitment(): Promise<Buffer> {
    const tree = await this.buildEventMerkleTree();
    const checkpointId = sha256(`${this.state.headHash}:${tree.root}:${Date.now()}`);
    return formatForOpReturn(tree.root, checkpointId);
  }

  // ============================================================
  // EVENT PRUNING (like Bitcoin's pruned node mode)
  // ============================================================

  /**
   * Prune old events while preserving checkpoints
   * 
   * Like Bitcoin's pruned mode:
   * - Keeps recent events (configurable retention period)
   * - Preserves ALL checkpoints forever
   * - Maintains hash chain integrity via checkpoint anchors
   * - Allows verification of pruned events via Merkle proofs
   * 
   * @param retentionDays - Keep events from the last N days
   * @param preserveCheckpoints - Always keep checkpoint-related events
   * @returns Number of events pruned
   */
  async pruneOldEvents(
    retentionDays: number = 365 * 7, // Default: 7 years like Autho spec
    preserveCheckpoints: boolean = true
  ): Promise<{ pruned: number; preserved: number; errors: string[] }> {
    const cutoffTime = Date.now() - (retentionDays * 24 * 60 * 60 * 1000);
    const errors: string[] = [];
    let pruned = 0;
    let preserved = 0;

    // Get all checkpoint sequence numbers to preserve
    const checkpointSequences = new Set<number>();
    if (preserveCheckpoints) {
      const checkpointFiles = fs.readdirSync(this.dataDir)
        .filter(f => f.startsWith('checkpoint-') && f.endsWith('.json'));
      
      for (const file of checkpointFiles) {
        try {
          const checkpointPath = path.join(this.dataDir, file);
          const result = atomicReadJSONWithRecovery<CheckpointData>(checkpointPath);
          if (result.success && result.data) {
            // Preserve events at checkpoint boundaries
            checkpointSequences.add(result.data.fromSequence);
            checkpointSequences.add(result.data.toSequence);
          }
        } catch (err) {
          errors.push(`Failed to read checkpoint ${file}`);
        }
      }
    }

    // Scan events directory
    const eventFiles = fs.readdirSync(this.eventsDir)
      .filter(f => f.endsWith('.json') && !f.endsWith('.tmp') && !f.endsWith('.bak'));

    for (const file of eventFiles) {
      try {
        const eventPath = path.join(this.eventsDir, file);
        const result = atomicReadJSONWithRecovery<Event>(eventPath);
        
        if (!result.success || !result.data) {
          continue;
        }

        const event = result.data;

        // Never prune if within retention period
        if (event.createdAt >= cutoffTime) {
          preserved++;
          continue;
        }

        // Never prune checkpoint boundary events
        if (preserveCheckpoints && checkpointSequences.has(event.sequenceNumber)) {
          preserved++;
          continue;
        }

        // Never prune the head event
        if (event.eventHash === this.state.headHash) {
          preserved++;
          continue;
        }

        // Safe to prune - delete the event file
        AtomicStorage.deleteFile(eventPath);
        
        // Remove from sequence index
        delete this.sequenceIndex.entries[event.sequenceNumber];
        
        pruned++;

      } catch (err: any) {
        errors.push(`Failed to process ${file}: ${err.message}`);
      }
    }

    // Save updated index
    if (pruned > 0) {
      this.sequenceIndex.lastUpdated = Date.now();
      this.saveIndex();
      console.log(`[EventStore] Pruned ${pruned} events, preserved ${preserved}`);
    }

    return { pruned, preserved, errors };
  }

  /**
   * Get pruning statistics
   */
  async getPruningStats(): Promise<{
    totalEvents: number;
    oldestEventAge: number;
    newestEventAge: number;
    checkpointCount: number;
    estimatedPrunableEvents: number;
    diskUsageBytes: number;
  }> {
    const events = await this.getAllEvents();
    const now = Date.now();

    let oldestTime = now;
    let newestTime = 0;
    let diskUsage = 0;

    for (const event of events) {
      if (event.createdAt < oldestTime) oldestTime = event.createdAt;
      if (event.createdAt > newestTime) newestTime = event.createdAt;
    }

    // Count checkpoints
    const checkpointFiles = fs.readdirSync(this.dataDir)
      .filter(f => f.startsWith('checkpoint-') && f.endsWith('.json'));

    // Estimate disk usage
    const eventFiles = fs.readdirSync(this.eventsDir)
      .filter(f => f.endsWith('.json') && !f.endsWith('.tmp') && !f.endsWith('.bak'));
    
    for (const file of eventFiles) {
      try {
        const stats = fs.statSync(path.join(this.eventsDir, file));
        diskUsage += stats.size;
      } catch {}
    }

    // Estimate prunable (older than 7 years)
    const sevenYearsAgo = now - (7 * 365 * 24 * 60 * 60 * 1000);
    const prunableEvents = events.filter(e => e.createdAt < sevenYearsAgo).length;

    return {
      totalEvents: events.length,
      oldestEventAge: Math.floor((now - oldestTime) / (24 * 60 * 60 * 1000)), // days
      newestEventAge: Math.floor((now - newestTime) / (24 * 60 * 60 * 1000)), // days
      checkpointCount: checkpointFiles.length,
      estimatedPrunableEvents: prunableEvents,
      diskUsageBytes: diskUsage,
    };
  }

  /**
   * Archive events to cold storage before pruning
   * Returns archive data that can be stored on IPFS/Arweave
   */
  async createArchive(
    fromSequence: number,
    toSequence: number
  ): Promise<{
    archiveId: string;
    events: Event[];
    merkleRoot: string;
    checksum: string;
    createdAt: number;
  }> {
    const events = await this.getEventsBySequence(fromSequence, toSequence);
    const eventHashes = events.map(e => e.eventHash);
    const tree = buildMerkleTree(eventHashes);

    const archiveData = {
      version: 1,
      fromSequence,
      toSequence,
      events,
      merkleRoot: tree.root,
    };

    const archiveJson = JSON.stringify(archiveData);
    const checksum = sha256(archiveJson);
    const archiveId = sha256(`archive:${fromSequence}:${toSequence}:${Date.now()}`);

    // Save archive locally
    const archiveFile = path.join(this.dataDir, `archive-${archiveId.slice(0, 16)}.json`);
    atomicWriteJSON(archiveFile, {
      ...archiveData,
      archiveId,
      checksum,
      createdAt: Date.now(),
    });

    console.log(`[EventStore] Created archive ${archiveId.slice(0, 16)} with ${events.length} events`);

    return {
      archiveId,
      events,
      merkleRoot: tree.root,
      checksum,
      createdAt: Date.now(),
    };
  }

  /**
   * Verify an archived event using its Merkle proof
   * Works even after the event has been pruned
   */
  verifyArchivedEvent(
    eventHash: string,
    proof: MerkleProof,
    expectedMerkleRoot: string
  ): boolean {
    if (proof.leafHash !== eventHash) {
      return false;
    }
    if (proof.root !== expectedMerkleRoot) {
      return false;
    }
    return verifyMerkleProof(proof);
  }

  // ============================================================
  // SEGMENT STORAGE (like Bitcoin's blk*.dat files)
  // ============================================================

  /**
   * Load segment index from disk
   */
  private loadSegmentIndex(): SegmentIndex {
    if (AtomicStorage.exists(this.segmentIndexFile)) {
      const result = atomicReadJSONWithRecovery<SegmentIndex>(this.segmentIndexFile);
      if (result.success && result.data && result.data.version === 1) {
        const entryCount = Object.keys(result.data.entries).length;
        if (entryCount > 0) {
          console.log(`[EventStore] Loaded segment index: ${entryCount} entries across ${result.data.currentSegment + 1} segments`);
        }
        return result.data;
      }
    }

    // Initialize empty segment index
    return {
      version: 1,
      entries: {},
      currentSegment: 0,
      currentSegmentEvents: 0,
      lastUpdated: Date.now(),
    };
  }

  /**
   * Save segment index to disk
   */
  private saveSegmentIndex(): void {
    atomicWriteJSON(this.segmentIndexFile, this.segmentIndex);
  }

  /**
   * Compact individual event files into segment files
   * This migrates pre-segment events into the segment storage format
   * Like Bitcoin's reindex: reorganizes on-disk layout for efficiency
   * Safe to run while the node is serving reads (backward compat maintained until complete)
   * 
   * @returns Number of events compacted
   */
  async compactToSegments(): Promise<{ compacted: number; segments: number; deletedFiles: number; errors: string[] }> {
    const startTime = Date.now();
    const errors: string[] = [];
    let compacted = 0;
    let deletedFiles = 0;

    if (!fs.existsSync(this.eventsDir)) {
      return { compacted: 0, segments: 0, deletedFiles: 0, errors: [] };
    }

    // Find all individual event files that aren't yet in segments
    const eventFiles = fs.readdirSync(this.eventsDir)
      .filter(f => f.endsWith('.json') && !f.endsWith('.tmp') && !f.endsWith('.bak'));

    if (eventFiles.length === 0) {
      console.log('[EventStore] No individual event files to compact');
      return { compacted: 0, segments: 0, deletedFiles: 0, errors: [] };
    }

    console.log(`[EventStore] Compacting ${eventFiles.length} individual event files into segments...`);

    // Read all events and sort by sequence number
    const events: Event[] = [];
    for (const file of eventFiles) {
      try {
        const eventPath = path.join(this.eventsDir, file);
        const result = atomicReadJSONWithRecovery<Event>(eventPath);
        if (result.success && result.data) {
          // Skip if already in segment index
          if (!this.segmentIndex.entries[result.data.eventHash]) {
            events.push(result.data);
          }
        }
      } catch (err: any) {
        errors.push(`Failed to read ${file}: ${err.message}`);
      }
    }

    // Sort by sequence number for ordered segments
    events.sort((a, b) => a.sequenceNumber - b.sequenceNumber);

    if (events.length === 0) {
      console.log('[EventStore] All events already in segments');
      return { compacted: 0, segments: 0, deletedFiles: 0, errors };
    }

    // Write events into segments
    for (const event of events) {
      try {
        this.persistEventToSegment(event);
        compacted++;
      } catch (err: any) {
        errors.push(`Failed to compact event ${event.eventHash.slice(0, 12)}: ${err.message}`);
      }
    }

    // Save segment index
    this.saveSegmentIndex();

    // Delete individual files now that they're safely in segments
    for (const event of events) {
      try {
        const eventFile = path.join(this.eventsDir, `${event.eventHash}.json`);
        if (fs.existsSync(eventFile)) {
          fs.unlinkSync(eventFile);
          deletedFiles++;
        }
        // Also delete backup files
        const bakFile = eventFile + '.bak';
        if (fs.existsSync(bakFile)) {
          fs.unlinkSync(bakFile);
        }
      } catch {}
    }

    const elapsed = Date.now() - startTime;
    const segCount = this.segmentIndex.currentSegment + 1;
    console.log(`[EventStore] ✅ Compacted ${compacted} events into ${segCount} segments in ${elapsed}ms (deleted ${deletedFiles} individual files)`);

    return { compacted, segments: segCount, deletedFiles, errors };
  }

  /**
   * Get segment storage stats for diagnostics
   */
  getSegmentStats(): {
    segmentCount: number;
    eventsInSegments: number;
    individualFiles: number;
    currentSegment: number;
    currentSegmentEvents: number;
    segmentMaxEvents: number;
  } {
    let individualFiles = 0;
    try {
      individualFiles = fs.readdirSync(this.eventsDir)
        .filter(f => f.endsWith('.json') && !f.endsWith('.tmp') && !f.endsWith('.bak')).length;
    } catch {}

    let segmentCount = 0;
    try {
      segmentCount = fs.readdirSync(this.segmentsDir)
        .filter(f => f.endsWith('.ndjson')).length;
    } catch {}

    return {
      segmentCount,
      eventsInSegments: Object.keys(this.segmentIndex.entries).length,
      individualFiles,
      currentSegment: this.segmentIndex.currentSegment,
      currentSegmentEvents: this.segmentIndex.currentSegmentEvents,
      segmentMaxEvents: this.segmentMaxEvents,
    };
  }
}
