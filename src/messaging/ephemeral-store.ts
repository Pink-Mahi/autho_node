/**
 * Ephemeral Event Store
 * 
 * A parallel ledger for temporary, encrypted messaging.
 * Key differences from CanonicalEventStore:
 * - Messages auto-delete after 10 days (configurable)
 * - All message content is E2E encrypted
 * - Platform never sees plaintext content
 * - Designed for Snapchat/Signal-style ephemeral communication
 * 
 * Use cases:
 * - Negotiate item purchases with owners
 * - Coordinate meetups for in-person sales
 * - General decentralized messaging
 */

import { EventEmitter } from 'events';
import * as fs from 'fs';
import * as path from 'path';
import { createHash, randomBytes } from 'crypto';

// Message retention period (10 days in milliseconds)
const DEFAULT_RETENTION_MS = 10 * 24 * 60 * 60 * 1000;

// Pruning interval (run every hour)
const PRUNE_INTERVAL_MS = 60 * 60 * 1000;

export enum EphemeralEventType {
  MESSAGE_SENT = 'MESSAGE_SENT',
  MESSAGE_DELETED = 'MESSAGE_DELETED',
  MESSAGE_READ = 'MESSAGE_READ',
  CONTACT_ADDED = 'CONTACT_ADDED',
  CONTACT_REMOVED = 'CONTACT_REMOVED',
  CONTACT_BLOCKED = 'CONTACT_BLOCKED',
  CONVERSATION_STARTED = 'CONVERSATION_STARTED',
}

export interface EphemeralEvent {
  eventId: string;
  eventType: EphemeralEventType;
  timestamp: number;
  expiresAt: number;
  payload: any;
}

export interface MessagePayload {
  messageId: string;
  senderId: string;           // sender's account ID (public key)
  recipientId: string;        // recipient's account ID (public key)
  encryptedContent: string;   // E2E encrypted message (only recipient can decrypt)
  encryptedForSender: string; // Same message encrypted for sender (so they can see sent messages)
  itemId?: string;            // Optional: if message is about a specific item
  conversationId: string;     // Groups messages into conversations
  replyToMessageId?: string;  // Optional: if replying to a specific message
}

export interface ContactPayload {
  userId: string;             // The user performing the action
  contactId: string;          // The contact being added/removed/blocked
  displayName?: string;       // Optional display name for the contact
}

export interface ConversationPayload {
  conversationId: string;
  participants: string[];     // Account IDs of all participants
  itemId?: string;            // Optional: if conversation is about a specific item
  createdBy: string;          // Who started the conversation
}

export interface EphemeralStoreOptions {
  dataDir: string;
  retentionMs?: number;
  pruneIntervalMs?: number;
}

export class EphemeralEventStore extends EventEmitter {
  private events: Map<string, EphemeralEvent> = new Map();
  private messagesByConversation: Map<string, Set<string>> = new Map();
  private messagesByUser: Map<string, Set<string>> = new Map();
  private contactsByUser: Map<string, Set<string>> = new Map();
  private blockedByUser: Map<string, Set<string>> = new Map();
  private conversationsByUser: Map<string, Set<string>> = new Map();
  
  private dataDir: string;
  private retentionMs: number;
  private pruneIntervalMs: number;
  private pruneTimer?: NodeJS.Timeout;
  private persistPath: string;

  constructor(options: EphemeralStoreOptions) {
    super();
    this.dataDir = options.dataDir;
    this.retentionMs = options.retentionMs || DEFAULT_RETENTION_MS;
    this.pruneIntervalMs = options.pruneIntervalMs || PRUNE_INTERVAL_MS;
    this.persistPath = path.join(this.dataDir, 'ephemeral-messages.json');
    
    // Ensure data directory exists
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    
    // Load existing events
    this.loadFromDisk();
    
    // Start auto-pruning
    this.startPruning();
  }

  /**
   * Generate a unique event ID
   */
  private generateEventId(): string {
    const timestamp = Date.now().toString(36);
    const random = randomBytes(8).toString('hex');
    return `msg_${timestamp}_${random}`;
  }

  /**
   * Generate a conversation ID from participants
   */
  generateConversationId(participant1: string, participant2: string, itemId?: string): string {
    // Sort participants to ensure consistent ID regardless of who initiates
    const sorted = [participant1, participant2].sort();
    const base = `${sorted[0]}:${sorted[1]}`;
    const suffix = itemId ? `:${itemId}` : '';
    return createHash('sha256').update(base + suffix).digest('hex').substring(0, 32);
  }

  /**
   * Append a new event to the ephemeral store
   */
  async appendEvent(eventType: EphemeralEventType, payload: any, customExpiresAt?: number): Promise<EphemeralEvent> {
    const now = Date.now();
    const event: EphemeralEvent = {
      eventId: this.generateEventId(),
      eventType,
      timestamp: now,
      expiresAt: customExpiresAt || (now + this.retentionMs),
      payload,
    };

    // Store event
    this.events.set(event.eventId, event);

    // Update indexes
    this.indexEvent(event);

    // Persist to disk
    await this.persistToDisk();

    // Emit event for real-time delivery
    this.emit('event', event);
    this.emit(eventType, event);

    return event;
  }

  /**
   * Index an event for fast lookup
   */
  private indexEvent(event: EphemeralEvent): void {
    switch (event.eventType) {
      case EphemeralEventType.MESSAGE_SENT: {
        const payload = event.payload as MessagePayload;
        
        // Index by conversation
        if (!this.messagesByConversation.has(payload.conversationId)) {
          this.messagesByConversation.set(payload.conversationId, new Set());
        }
        this.messagesByConversation.get(payload.conversationId)!.add(event.eventId);
        
        // Index by sender
        if (!this.messagesByUser.has(payload.senderId)) {
          this.messagesByUser.set(payload.senderId, new Set());
        }
        this.messagesByUser.get(payload.senderId)!.add(event.eventId);
        
        // Index by recipient
        if (!this.messagesByUser.has(payload.recipientId)) {
          this.messagesByUser.set(payload.recipientId, new Set());
        }
        this.messagesByUser.get(payload.recipientId)!.add(event.eventId);
        
        // Track conversation for both users
        if (!this.conversationsByUser.has(payload.senderId)) {
          this.conversationsByUser.set(payload.senderId, new Set());
        }
        this.conversationsByUser.get(payload.senderId)!.add(payload.conversationId);
        
        if (!this.conversationsByUser.has(payload.recipientId)) {
          this.conversationsByUser.set(payload.recipientId, new Set());
        }
        this.conversationsByUser.get(payload.recipientId)!.add(payload.conversationId);
        break;
      }
      
      case EphemeralEventType.CONTACT_ADDED: {
        const payload = event.payload as ContactPayload;
        if (!this.contactsByUser.has(payload.userId)) {
          this.contactsByUser.set(payload.userId, new Set());
        }
        this.contactsByUser.get(payload.userId)!.add(payload.contactId);
        break;
      }
      
      case EphemeralEventType.CONTACT_REMOVED: {
        const payload = event.payload as ContactPayload;
        this.contactsByUser.get(payload.userId)?.delete(payload.contactId);
        break;
      }
      
      case EphemeralEventType.CONTACT_BLOCKED: {
        const payload = event.payload as ContactPayload;
        if (!this.blockedByUser.has(payload.userId)) {
          this.blockedByUser.set(payload.userId, new Set());
        }
        this.blockedByUser.get(payload.userId)!.add(payload.contactId);
        // Also remove from contacts
        this.contactsByUser.get(payload.userId)?.delete(payload.contactId);
        break;
      }
    }
  }

  /**
   * Get messages for a conversation
   */
  getConversationMessages(conversationId: string): EphemeralEvent[] {
    const messageIds = this.messagesByConversation.get(conversationId) || new Set();
    const messages: EphemeralEvent[] = [];
    
    for (const id of messageIds) {
      const event = this.events.get(id);
      if (event && event.expiresAt > Date.now()) {
        messages.push(event);
      }
    }
    
    return messages.sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Get all conversations for a user
   */
  getUserConversations(userId: string): Array<{
    conversationId: string;
    lastMessage: EphemeralEvent | null;
    unreadCount: number;
    participants: string[];
  }> {
    const conversationIds = this.conversationsByUser.get(userId) || new Set();
    const result: Array<{
      conversationId: string;
      lastMessage: EphemeralEvent | null;
      unreadCount: number;
      participants: string[];
    }> = [];
    
    for (const convId of conversationIds) {
      const messages = this.getConversationMessages(convId);
      if (messages.length === 0) continue;
      
      const lastMessage = messages[messages.length - 1];
      const participants = new Set<string>();
      let unreadCount = 0;
      
      for (const msg of messages) {
        const payload = msg.payload as MessagePayload;
        participants.add(payload.senderId);
        participants.add(payload.recipientId);
        
        // Count unread (messages sent to this user that haven't been read)
        if (payload.recipientId === userId) {
          // TODO: Track read status properly
          unreadCount++;
        }
      }
      
      result.push({
        conversationId: convId,
        lastMessage,
        unreadCount,
        participants: Array.from(participants),
      });
    }
    
    // Sort by last message time, newest first
    return result.sort((a, b) => {
      const aTime = a.lastMessage?.timestamp || 0;
      const bTime = b.lastMessage?.timestamp || 0;
      return bTime - aTime;
    });
  }

  /**
   * Get contacts for a user
   */
  getUserContacts(userId: string): string[] {
    return Array.from(this.contactsByUser.get(userId) || new Set());
  }

  /**
   * Check if a user is blocked
   */
  isBlocked(userId: string, potentiallyBlockedId: string): boolean {
    return this.blockedByUser.get(userId)?.has(potentiallyBlockedId) || false;
  }

  /**
   * Delete a message early (for paid early deletion)
   */
  async deleteMessage(messageId: string, requesterId: string): Promise<boolean> {
    const event = this.events.get(messageId);
    if (!event) return false;
    
    // Only sender or recipient can delete
    const payload = event.payload as MessagePayload;
    if (payload.senderId !== requesterId && payload.recipientId !== requesterId) {
      return false;
    }
    
    // Remove from all indexes
    this.messagesByConversation.get(payload.conversationId)?.delete(messageId);
    this.messagesByUser.get(payload.senderId)?.delete(messageId);
    this.messagesByUser.get(payload.recipientId)?.delete(messageId);
    this.events.delete(messageId);
    
    // Record deletion event
    await this.appendEvent(EphemeralEventType.MESSAGE_DELETED, {
      messageId,
      deletedBy: requesterId,
      deletedAt: Date.now(),
    });
    
    await this.persistToDisk();
    return true;
  }

  /**
   * Prune expired events
   */
  async prune(): Promise<number> {
    const now = Date.now();
    let prunedCount = 0;
    
    for (const [eventId, event] of this.events.entries()) {
      if (event.expiresAt <= now) {
        // Remove from indexes
        if (event.eventType === EphemeralEventType.MESSAGE_SENT) {
          const payload = event.payload as MessagePayload;
          this.messagesByConversation.get(payload.conversationId)?.delete(eventId);
          this.messagesByUser.get(payload.senderId)?.delete(eventId);
          this.messagesByUser.get(payload.recipientId)?.delete(eventId);
        }
        
        this.events.delete(eventId);
        prunedCount++;
      }
    }
    
    // Clean up empty conversation sets
    for (const [convId, messages] of this.messagesByConversation.entries()) {
      if (messages.size === 0) {
        this.messagesByConversation.delete(convId);
        
        // Remove conversation from users
        for (const [userId, convs] of this.conversationsByUser.entries()) {
          convs.delete(convId);
        }
      }
    }
    
    if (prunedCount > 0) {
      await this.persistToDisk();
      console.log(`[Ephemeral] Pruned ${prunedCount} expired messages`);
    }
    
    return prunedCount;
  }

  /**
   * Start automatic pruning
   */
  private startPruning(): void {
    // Run immediately on startup
    this.prune();
    
    // Then run periodically
    this.pruneTimer = setInterval(() => {
      this.prune();
    }, this.pruneIntervalMs);
  }

  /**
   * Stop automatic pruning
   */
  stopPruning(): void {
    if (this.pruneTimer) {
      clearInterval(this.pruneTimer);
      this.pruneTimer = undefined;
    }
  }

  // ============================================================
  // P2P REPLICATION METHODS - For decentralized sync across operators
  // ============================================================

  /**
   * Check if an event already exists (for dedupe during gossip)
   */
  hasEvent(eventId: string): boolean {
    return this.events.has(eventId);
  }

  /**
   * Import an event from a peer operator (with dedupe)
   * Returns true if the event was new and imported, false if already exists or expired
   */
  async importEvent(event: EphemeralEvent): Promise<boolean> {
    // Skip if already have this event
    if (this.events.has(event.eventId)) {
      return false;
    }

    // Skip if expired
    if (event.expiresAt <= Date.now()) {
      return false;
    }

    // Validate basic structure
    if (!event.eventId || !event.eventType || !event.timestamp || !event.payload) {
      console.log(`[Ephemeral] Invalid event structure, skipping import`);
      return false;
    }

    // Store event
    this.events.set(event.eventId, event);

    // Update indexes
    this.indexEvent(event);

    // Persist to disk
    await this.persistToDisk();

    // Emit event for real-time delivery
    this.emit('event', event);
    this.emit('imported', event);

    return true;
  }

  /**
   * Get all events since a given timestamp (for backfill sync)
   * Returns events sorted by timestamp, limited to maxEvents
   */
  getEventsSince(sinceTimestamp: number, maxEvents: number = 1000): EphemeralEvent[] {
    const now = Date.now();
    const events: EphemeralEvent[] = [];

    for (const event of this.events.values()) {
      // Only include non-expired events newer than sinceTimestamp
      if (event.timestamp > sinceTimestamp && event.expiresAt > now) {
        events.push(event);
      }
    }

    // Sort by timestamp ascending
    events.sort((a, b) => a.timestamp - b.timestamp);

    // Limit results
    return events.slice(0, maxEvents);
  }

  /**
   * Get the latest event timestamp (for sync cursor)
   */
  getLatestTimestamp(): number {
    let latest = 0;
    for (const event of this.events.values()) {
      if (event.timestamp > latest) {
        latest = event.timestamp;
      }
    }
    return latest;
  }

  /**
   * Get all current events (for full sync)
   */
  getAllEvents(): EphemeralEvent[] {
    const now = Date.now();
    return Array.from(this.events.values())
      .filter(e => e.expiresAt > now)
      .sort((a, b) => a.timestamp - b.timestamp);
  }

  // ============================================================
  // END P2P REPLICATION METHODS
  // ============================================================

  /**
   * Get stats about the ephemeral store
   */
  getStats(): {
    totalMessages: number;
    totalConversations: number;
    totalUsers: number;
    oldestMessage: number | null;
    newestMessage: number | null;
    retentionDays: number;
  } {
    let oldestMessage: number | null = null;
    let newestMessage: number | null = null;
    
    for (const event of this.events.values()) {
      if (event.eventType === EphemeralEventType.MESSAGE_SENT) {
        if (oldestMessage === null || event.timestamp < oldestMessage) {
          oldestMessage = event.timestamp;
        }
        if (newestMessage === null || event.timestamp > newestMessage) {
          newestMessage = event.timestamp;
        }
      }
    }
    
    return {
      totalMessages: Array.from(this.events.values())
        .filter(e => e.eventType === EphemeralEventType.MESSAGE_SENT).length,
      totalConversations: this.messagesByConversation.size,
      totalUsers: this.messagesByUser.size,
      oldestMessage,
      newestMessage,
      retentionDays: Math.round(this.retentionMs / (24 * 60 * 60 * 1000)),
    };
  }

  /**
   * Persist events to disk
   */
  private async persistToDisk(): Promise<void> {
    const data = {
      version: 1,
      events: Array.from(this.events.values()),
      contacts: Object.fromEntries(
        Array.from(this.contactsByUser.entries()).map(([k, v]) => [k, Array.from(v)])
      ),
      blocked: Object.fromEntries(
        Array.from(this.blockedByUser.entries()).map(([k, v]) => [k, Array.from(v)])
      ),
    };
    
    await fs.promises.writeFile(this.persistPath, JSON.stringify(data, null, 2));
  }

  /**
   * Load events from disk
   */
  private loadFromDisk(): void {
    try {
      if (!fs.existsSync(this.persistPath)) {
        return;
      }
      
      const raw = fs.readFileSync(this.persistPath, 'utf8');
      const data = JSON.parse(raw);
      
      // Load events
      for (const event of data.events || []) {
        // Skip expired events
        if (event.expiresAt <= Date.now()) continue;
        
        this.events.set(event.eventId, event);
        this.indexEvent(event);
      }
      
      // Load contacts
      for (const [userId, contacts] of Object.entries(data.contacts || {})) {
        this.contactsByUser.set(userId, new Set(contacts as string[]));
      }
      
      // Load blocked
      for (const [userId, blocked] of Object.entries(data.blocked || {})) {
        this.blockedByUser.set(userId, new Set(blocked as string[]));
      }
      
      console.log(`[Ephemeral] Loaded ${this.events.size} messages from disk`);
    } catch (error) {
      console.error('[Ephemeral] Failed to load from disk:', error);
    }
  }
}
