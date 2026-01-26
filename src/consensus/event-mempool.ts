/**
 * Event Mempool
 * 
 * Holds pending events before they are finalized in a checkpoint.
 * Events are validated, ordered deterministically, and broadcast to peers.
 */

import { createHash } from 'crypto';
import {
  MempoolEvent,
  ValidationResult,
} from './types';

export class EventMempool {
  private events: Map<string, MempoolEvent> = new Map();
  private eventsByType: Map<string, Set<string>> = new Map();
  private maxSize: number;
  private eventTTL: number; // Time-to-live in ms

  constructor(options: { maxSize?: number; eventTTL?: number } = {}) {
    this.maxSize = options.maxSize || 10000;
    this.eventTTL = options.eventTTL || 24 * 60 * 60 * 1000; // 24 hours default
  }

  /**
   * Generate a unique event ID based on content
   */
  static generateEventId(event: Omit<MempoolEvent, 'eventId' | 'receivedAt' | 'receivedFrom' | 'validationStatus'>): string {
    const content = JSON.stringify({
      type: event.type,
      payload: event.payload,
      timestamp: event.timestamp,
      creatorId: event.creatorId,
    });
    return createHash('sha256').update(content).digest('hex').substring(0, 32);
  }

  /**
   * Add an event to the mempool
   * Returns true if added, false if duplicate or invalid
   */
  addEvent(event: MempoolEvent): { added: boolean; reason?: string } {
    // Check if already exists
    if (this.events.has(event.eventId)) {
      return { added: false, reason: 'duplicate' };
    }

    // Check mempool size
    if (this.events.size >= this.maxSize) {
      this.pruneOldEvents();
      if (this.events.size >= this.maxSize) {
        return { added: false, reason: 'mempool_full' };
      }
    }

    // Add to mempool
    this.events.set(event.eventId, event);

    // Index by type
    if (!this.eventsByType.has(event.type)) {
      this.eventsByType.set(event.type, new Set());
    }
    this.eventsByType.get(event.type)!.add(event.eventId);

    return { added: true };
  }

  /**
   * Get an event by ID
   */
  getEvent(eventId: string): MempoolEvent | undefined {
    return this.events.get(eventId);
  }

  /**
   * Check if event exists
   */
  hasEvent(eventId: string): boolean {
    return this.events.has(eventId);
  }

  /**
   * Remove an event from mempool (after checkpoint finalization)
   */
  removeEvent(eventId: string): boolean {
    const event = this.events.get(eventId);
    if (!event) return false;

    this.events.delete(eventId);
    this.eventsByType.get(event.type)?.delete(eventId);
    return true;
  }

  /**
   * Remove multiple events (after checkpoint)
   */
  removeEvents(eventIds: string[]): number {
    let removed = 0;
    for (const id of eventIds) {
      if (this.removeEvent(id)) removed++;
    }
    return removed;
  }

  /**
   * Get all events, ordered deterministically
   * Primary sort: timestamp (oldest first)
   * Tie-breaker: eventId lexicographic (lower first)
   */
  getOrderedEvents(): MempoolEvent[] {
    const events = Array.from(this.events.values());
    return this.orderEvents(events);
  }

  /**
   * Get valid events only, ordered deterministically
   */
  getValidOrderedEvents(): MempoolEvent[] {
    const events = Array.from(this.events.values())
      .filter(e => e.validationStatus === 'valid');
    return this.orderEvents(events);
  }

  /**
   * Order events deterministically
   */
  orderEvents(events: MempoolEvent[]): MempoolEvent[] {
    return events.sort((a, b) => {
      // Primary: timestamp (oldest first)
      if (a.timestamp !== b.timestamp) {
        return a.timestamp - b.timestamp;
      }
      // Tie-breaker: eventId lexicographic (lower first)
      return a.eventId.localeCompare(b.eventId);
    });
  }

  /**
   * Get events by type
   */
  getEventsByType(type: string): MempoolEvent[] {
    const ids = this.eventsByType.get(type);
    if (!ids) return [];
    return Array.from(ids)
      .map(id => this.events.get(id)!)
      .filter(Boolean);
  }

  /**
   * Update event validation status
   */
  updateValidationStatus(eventId: string, status: 'valid' | 'invalid', error?: string): boolean {
    const event = this.events.get(eventId);
    if (!event) return false;

    event.validationStatus = status;
    if (error) event.validationError = error;
    return true;
  }

  /**
   * Get mempool statistics
   */
  getStats(): {
    totalEvents: number;
    validEvents: number;
    invalidEvents: number;
    pendingEvents: number;
    eventsByType: Record<string, number>;
    oldestEventAge: number;
  } {
    let valid = 0, invalid = 0, pending = 0;
    let oldestTimestamp = Date.now();
    const byType: Record<string, number> = {};

    for (const event of this.events.values()) {
      if (event.validationStatus === 'valid') valid++;
      else if (event.validationStatus === 'invalid') invalid++;
      else pending++;

      byType[event.type] = (byType[event.type] || 0) + 1;
      if (event.timestamp < oldestTimestamp) oldestTimestamp = event.timestamp;
    }

    return {
      totalEvents: this.events.size,
      validEvents: valid,
      invalidEvents: invalid,
      pendingEvents: pending,
      eventsByType: byType,
      oldestEventAge: this.events.size > 0 ? Date.now() - oldestTimestamp : 0,
    };
  }

  /**
   * Get all event IDs
   */
  getAllEventIds(): string[] {
    return Array.from(this.events.keys());
  }

  /**
   * Get events received from a specific peer
   */
  getEventsFromPeer(peerId: string): MempoolEvent[] {
    return Array.from(this.events.values())
      .filter(e => e.receivedFrom === peerId);
  }

  /**
   * Prune old events that have exceeded TTL
   */
  pruneOldEvents(): number {
    const now = Date.now();
    const cutoff = now - this.eventTTL;
    let pruned = 0;

    for (const [id, event] of this.events.entries()) {
      if (event.receivedAt < cutoff) {
        this.removeEvent(id);
        pruned++;
      }
    }

    return pruned;
  }

  /**
   * Clear all events (for testing or reset)
   */
  clear(): void {
    this.events.clear();
    this.eventsByType.clear();
  }

  /**
   * Export mempool state for persistence
   */
  export(): MempoolEvent[] {
    return Array.from(this.events.values());
  }

  /**
   * Import mempool state from persistence
   */
  import(events: MempoolEvent[]): number {
    let imported = 0;
    for (const event of events) {
      const result = this.addEvent(event);
      if (result.added) imported++;
    }
    return imported;
  }

  /**
   * Get size
   */
  get size(): number {
    return this.events.size;
  }
}
