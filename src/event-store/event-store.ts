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

export class EventStore {
  private dataDir: string;
  private eventsDir: string;
  private stateFile: string;
  private state: EventStoreState;

  constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.eventsDir = path.join(dataDir, 'events');
    this.stateFile = path.join(dataDir, 'event-store-state.json');

    // Initialize directories
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    if (!fs.existsSync(this.eventsDir)) {
      fs.mkdirSync(this.eventsDir, { recursive: true });
    }

    // Load or initialize state
    this.state = this.loadState();
  }

  /**
   * Append a new event to the log
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

    // Persist event to disk
    await this.persistEvent(event);

    // Update state
    this.state.headHash = event.eventHash;
    this.state.sequenceNumber = event.sequenceNumber;
    this.state.eventCount++;
    this.saveState();

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

    // Accept event with its existing hash, don't validate chain links during sync
    await this.persistEvent(event);

    this.state.headHash = event.eventHash;
    this.state.sequenceNumber = event.sequenceNumber;
    this.state.eventCount++;
    this.saveState();
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
}
