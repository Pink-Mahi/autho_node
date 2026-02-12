/**
 * Message Ledger (formerly Ephemeral Event Store)
 * 
 * A parallel ledger for encrypted messaging with selective pruning:
 * - CONTACTS: Permanent, never pruned
 * - MESSAGES: Pruned after 10 days (configurable)
 * 
 * Key features:
 * - Proper event-sourced architecture like main registry
 * - All message content is E2E encrypted
 * - Platform never sees plaintext content
 * - P2P sync between operators
 * - Designed for Snapchat/Signal-style ephemeral communication
 * 
 * Use cases:
 * - Negotiate item purchases with owners
 * - Coordinate meetups for in-person sales
 * - General decentralized messaging
 * - Persistent contact list management
 */

import { EventEmitter } from 'events';
import * as fs from 'fs';
import * as path from 'path';
import { createHash, randomBytes } from 'crypto';
import { Worker } from 'worker_threads';

// Message retention periods by media type (in milliseconds)
const RETENTION_MS = {
  TEXT: 10 * 24 * 60 * 60 * 1000,      // 10 days
  IMAGE: 7 * 24 * 60 * 60 * 1000,      // 7 days
  AUDIO: 5 * 24 * 60 * 60 * 1000,      // 5 days
  VIDEO: 3 * 24 * 60 * 60 * 1000,      // 3 days
};

// Per-conversation rolling limits for media
const MEDIA_LIMITS = {
  IMAGE: 10,   // Max 10 images per conversation
  AUDIO: 5,    // Max 5 audio messages per conversation
  VIDEO: 3,    // Max 3 videos per conversation
};

// Disappearing message timer options (in milliseconds)
export const DISAPPEAR_TIMERS = {
  SECONDS_30: 30 * 1000,
  MINUTES_5: 5 * 60 * 1000,
  HOUR_1: 60 * 60 * 1000,
  HOURS_24: 24 * 60 * 60 * 1000,
  DAYS_3: 3 * 24 * 60 * 60 * 1000,
  DAYS_10: 10 * 24 * 60 * 60 * 1000,  // Default
  OFF: 0,  // No auto-delete (uses media type default)
};

const DEFAULT_RETENTION_MS = RETENTION_MS.TEXT;

// Pruning interval (run every hour)
const PRUNE_INTERVAL_MS = 60 * 60 * 1000;

// Media type detection
export type MediaType = 'text' | 'image' | 'audio' | 'video';

export enum EphemeralEventType {
  MESSAGE_SENT = 'MESSAGE_SENT',
  MESSAGE_DELETED = 'MESSAGE_DELETED',
  MESSAGE_READ = 'MESSAGE_READ',
  MESSAGE_VIEWED = 'MESSAGE_VIEWED',  // For disappearing messages - starts the timer
  MESSAGE_DELIVERED = 'MESSAGE_DELIVERED',  // Message reached recipient's device
  MESSAGE_REACTION = 'MESSAGE_REACTION',    // Emoji reaction to a message
  MESSAGING_KEY_PUBLISHED = 'MESSAGING_KEY_PUBLISHED',
  MESSAGING_VAULT_PUBLISHED = 'MESSAGING_VAULT_PUBLISHED',
  CONTACT_ADDED = 'CONTACT_ADDED',
  CONTACT_REMOVED = 'CONTACT_REMOVED',
  CONTACT_BLOCKED = 'CONTACT_BLOCKED',
  CONVERSATION_STARTED = 'CONVERSATION_STARTED',
  CONVERSATION_MUTED = 'CONVERSATION_MUTED',
  CONVERSATION_UNMUTED = 'CONVERSATION_UNMUTED',
  TYPING_STARTED = 'TYPING_STARTED',
  TYPING_STOPPED = 'TYPING_STOPPED',
  USER_ONLINE = 'USER_ONLINE',
  USER_OFFLINE = 'USER_OFFLINE',
  // Group chat events
  GROUP_CREATED = 'GROUP_CREATED',
  GROUP_MESSAGE_SENT = 'GROUP_MESSAGE_SENT',
  GROUP_MEMBER_ADDED = 'GROUP_MEMBER_ADDED',
  GROUP_MEMBER_REMOVED = 'GROUP_MEMBER_REMOVED',
  GROUP_NAME_CHANGED = 'GROUP_NAME_CHANGED',
  GROUP_LEFT = 'GROUP_LEFT',
  GROUP_MUTED = 'GROUP_MUTED',
  GROUP_UNMUTED = 'GROUP_UNMUTED',
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
  // Media and disappearing message fields
  mediaType?: MediaType;      // Type of content: text, image, audio, video
  selfDestructAfter?: number; // Custom expiry time in ms (0 = use default, undefined = use media type default)
  viewedAt?: number;          // Timestamp when recipient viewed (for disappearing messages)
  expiresAfterView?: boolean; // If true, timer starts on view; if false/undefined, starts on send
}

export interface MessagingVaultPayload {
  accountId: string;
  vaultEpoch: string;
  vaultVersion: number;
  updatedAt: number;
  kdf: any;
  enc: any;
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

// Group chat interfaces
export interface GroupPayload {
  groupId: string;
  name: string;
  members: string[];          // All member account IDs (public keys)
  admins: string[];           // Admin account IDs (can add/remove members)
  createdBy: string;          // Creator's account ID
  createdAt: number;
}

export interface GroupMessagePayload {
  messageId: string;
  groupId: string;
  senderId: string;
  // Map of memberId -> encrypted content (each member gets their own encrypted copy)
  encryptedContentByMember: { [memberId: string]: string };
  replyToMessageId?: string;
  // Media and disappearing message fields
  mediaType?: MediaType;
  selfDestructAfter?: number;
  viewedBy?: { [memberId: string]: number }; // memberId -> viewedAt timestamp
  expiresAfterView?: boolean;
}

// Message deletion payload
export interface MessageDeletePayload {
  messageId: string;
  deletedBy: string;
  deletedAt: number;
  conversationId?: string;
  groupId?: string;
}

// Message viewed payload (for disappearing messages)
export interface MessageViewedPayload {
  messageId: string;
  viewedBy: string;
  viewedAt: number;
  conversationId?: string;
  groupId?: string;
}

// Message reaction payload
export interface MessageReactionPayload {
  messageId: string;
  reactedBy: string;
  emoji: string;          // The emoji reaction (👍❤️😂🔥👏😢)
  conversationId?: string;
  groupId?: string;
  removed?: boolean;      // If true, removes the reaction
}

// Typing indicator payload (ephemeral - not persisted)
export interface TypingPayload {
  userId: string;
  conversationId?: string;
  groupId?: string;
}

// Mute conversation payload
export interface MutePayload {
  conversationId?: string;
  groupId?: string;
  mutedBy: string;
  mutedUntil?: number;    // Timestamp when mute expires (undefined = forever)
}

// Online status payload (ephemeral - not persisted)
export interface OnlineStatusPayload {
  userId: string;
  lastSeen: number;
}

// Content chunking for large payloads - ensures full replication across all nodes
// Chunks are stored INLINE in the event (not local files) so they replicate with the event
const CHUNK_SIZE = 256 * 1024; // 256KB per chunk - small enough to broadcast without blocking
const CHUNK_PREFIX = '__chunked:';
const CONTENT_SIZE_THRESHOLD = CHUNK_SIZE; // Threshold for chunking = chunk size

// Legacy content ref (for backward compatibility during migration)
const CONTENT_REF_PREFIX = '__contentRef:';
const CONTENT_REF_SUFFIX = '__';

// File attachment limits
export const FILE_LIMITS = {
  MAX_FILE_SIZE: 10 * 1024 * 1024,    // 10MB max
  ALLOWED_TYPES: [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain',
    'text/csv',
    'application/zip',
    'application/x-rar-compressed',
  ],
  ALLOWED_EXTENSIONS: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'csv', 'zip', 'rar'],
};

export interface GroupMemberPayload {
  groupId: string;
  memberId: string;           // The member being added/removed
  actorId: string;            // Who performed the action
}

export interface GroupNamePayload {
  groupId: string;
  newName: string;
  actorId: string;
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
  private messagingVaultByAccount: Map<string, EphemeralEvent> = new Map();
  
  // Group chat storage
  private groups: Map<string, GroupPayload> = new Map();           // groupId -> group data
  private groupsByUser: Map<string, Set<string>> = new Map();      // userId -> set of groupIds
  private messagesByGroup: Map<string, Set<string>> = new Map();   // groupId -> set of eventIds
  
  // New feature storage
  private messageReactions: Map<string, Map<string, string>> = new Map();  // messageId -> (userId -> emoji)
  private mutedConversations: Map<string, Set<string>> = new Map();        // userId -> set of conversationIds
  private mutedGroups: Map<string, Set<string>> = new Map();               // userId -> set of groupIds
  private typingUsers: Map<string, Map<string, number>> = new Map();       // conversationId -> (userId -> timestamp)
  private onlineUsers: Map<string, number> = new Map();                    // userId -> lastSeen timestamp
  private messageReadStatus: Map<string, { delivered?: number; read?: number }> = new Map();  // messageId -> status
  
  private dataDir: string;
  private retentionMs: number;
  private pruneIntervalMs: number;
  private pruneTimer?: NodeJS.Timeout;
  private persistPath: string;
  private contactsPath: string;  // Separate file for permanent contacts
  private _persistTimer: NodeJS.Timeout | null = null;
  private _persistPending: boolean = false;
  private _serializationInProgress: boolean = false;
  private contentDir: string = '';

  constructor(options: EphemeralStoreOptions) {
    super();
    this.dataDir = options.dataDir;
    this.retentionMs = options.retentionMs || DEFAULT_RETENTION_MS;
    this.pruneIntervalMs = options.pruneIntervalMs || PRUNE_INTERVAL_MS;
    this.persistPath = path.join(this.dataDir, 'message-ledger.json');
    this.contactsPath = path.join(this.dataDir, 'contacts-ledger.json');  // Permanent contacts
    
    // Ensure data directory exists
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    
    // Content extraction directory for large payloads (videos, photos)
    this.contentDir = path.join(this.dataDir, 'content');
    if (!fs.existsSync(this.contentDir)) {
      fs.mkdirSync(this.contentDir, { recursive: true });
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
   * Calculate retention based on media type and custom settings
   */
  private calculateRetention(payload: MessagePayload | GroupMessagePayload): number {
    // If custom selfDestructAfter is set, use it
    if (payload.selfDestructAfter && payload.selfDestructAfter > 0) {
      return payload.selfDestructAfter;
    }
    
    // Otherwise, use media type defaults
    const mediaType = payload.mediaType || 'text';
    switch (mediaType) {
      case 'image': return RETENTION_MS.IMAGE;
      case 'audio': return RETENTION_MS.AUDIO;
      case 'video': return RETENTION_MS.VIDEO;
      default: return RETENTION_MS.TEXT;
    }
  }

  /**
   * Append a new event to the ephemeral store
   */
  async appendEvent(eventType: EphemeralEventType, payload: any, customExpiresAt?: number): Promise<EphemeralEvent> {
    const now = Date.now();
    
    // Calculate expiry based on event type and media
    let expiresAt = customExpiresAt;
    if (!expiresAt) {
      if (eventType === EphemeralEventType.MESSAGE_SENT || eventType === EphemeralEventType.GROUP_MESSAGE_SENT) {
        // For messages, use media-aware retention
        const msgPayload = payload as MessagePayload | GroupMessagePayload;
        
        // If expiresAfterView AND no custom timer, use 10 day max (will be shortened on view)
        if (msgPayload.expiresAfterView && !msgPayload.selfDestructAfter) {
          expiresAt = now + RETENTION_MS.TEXT; // 10 days max, shortened on view
        } else {
          // Use custom selfDestructAfter timer or media-type default
          expiresAt = now + this.calculateRetention(msgPayload);
        }
      } else {
        expiresAt = now + this.retentionMs;
      }
    }
    
    const event: EphemeralEvent = {
      eventId: this.generateEventId(),
      eventType,
      timestamp: now,
      expiresAt,
      payload,
    };

    // Store event
    this.events.set(event.eventId, event);

    // Update indexes
    this.indexEvent(event);

    // Enforce per-conversation media limits
    if (eventType === EphemeralEventType.MESSAGE_SENT) {
      await this.enforceMediaLimits(payload.conversationId, payload.mediaType);
    } else if (eventType === EphemeralEventType.GROUP_MESSAGE_SENT) {
      await this.enforceGroupMediaLimits(payload.groupId, payload.mediaType);
    }

    // Save a shallow clone of the payload BEFORE extraction so we can broadcast
    // the full content to peer nodes. extractLargeContent mutates payload in-place,
    // replacing large strings with __contentRef: placeholders.  Peer nodes need
    // the real content so they can store it on their own disks.
    const broadcastPayload = { ...event.payload };

    // DEBUG: Log content sizes before extraction
    const preContentLen = typeof (broadcastPayload as any).encryptedContent === 'string' ? (broadcastPayload as any).encryptedContent.length : 0;
    const preForSenderLen = typeof (broadcastPayload as any).encryptedForSender === 'string' ? (broadcastPayload as any).encryptedForSender.length : 0;
    console.log(`[Ephemeral] 📝 appendEvent ${event.eventId.substring(0,8)}... PRE-extraction: contentLen=${preContentLen}, forSenderLen=${preForSenderLen}`);

    // Extract large content (videos, photos) to disk files.
    // This keeps in-memory events lightweight, preventing OOM and event-loop blocking
    // during JSON serialization and structured clone to worker threads.
    await this.extractLargeContent(event);

    // DEBUG: Log stored event after extraction
    const storedPayload = event.payload as any;
    const storedContentLen = typeof storedPayload.encryptedContent === 'string' ? storedPayload.encryptedContent.length : 0;
    const storedHasChunks = !!storedPayload.__chunks_encryptedContent;
    console.log(`[Ephemeral] 📝 appendEvent ${event.eventId.substring(0,8)}... POST-extraction stored: contentLen=${storedContentLen}, hasChunks=${storedHasChunks}`);

    // Persist to disk (with extracted references – lightweight)
    await this.persistToDisk();

    // Emit the FULL event (with original content) for broadcast to peer nodes.
    // Local in-memory copy keeps the lightweight __contentRef: placeholders.
    const broadcastEvent = { ...event, payload: broadcastPayload };

    // DEBUG: Log broadcast event content sizes
    const bcPayload = broadcastEvent.payload as any;
    const bcContentLen = typeof bcPayload.encryptedContent === 'string' ? bcPayload.encryptedContent.length : 0;
    const bcIsChunked = typeof bcPayload.encryptedContent === 'string' && bcPayload.encryptedContent.startsWith('__chunked:');
    console.log(`[Ephemeral] 📤 appendEvent ${event.eventId.substring(0,8)}... BROADCAST: contentLen=${bcContentLen}, isChunked=${bcIsChunked}`);

    this.emit('event', broadcastEvent);
    this.emit(eventType, broadcastEvent);

    // Return the FULL-CONTENT event so callers (api-server, operator-node) can
    // broadcast it to peer nodes with the actual media data intact.
    // The in-memory stored copy retains lightweight __contentRef: placeholders.
    return broadcastEvent;
  }

  /**
   * Enforce per-conversation media limits (rolling window)
   */
  private async enforceMediaLimits(conversationId: string, mediaType?: MediaType): Promise<void> {
    if (!mediaType || mediaType === 'text') return;
    
    const limit = MEDIA_LIMITS[mediaType.toUpperCase() as keyof typeof MEDIA_LIMITS];
    if (!limit) return;
    
    const messageIds = this.messagesByConversation.get(conversationId);
    if (!messageIds) return;
    
    // Get all messages of this media type in the conversation
    const mediaMessages: EphemeralEvent[] = [];
    for (const id of messageIds) {
      const event = this.events.get(id);
      if (event && event.eventType === EphemeralEventType.MESSAGE_SENT) {
        const payload = event.payload as MessagePayload;
        if (payload.mediaType === mediaType) {
          mediaMessages.push(event);
        }
      }
    }
    
    // Sort by timestamp (oldest first)
    mediaMessages.sort((a, b) => a.timestamp - b.timestamp);
    
    // Remove oldest if over limit
    while (mediaMessages.length > limit) {
      const oldest = mediaMessages.shift()!;
      await this.deleteMessageInternal(oldest.eventId);
      console.log(`[Ephemeral] Auto-pruned oldest ${mediaType} in conversation (limit: ${limit})`);
    }
  }

  /**
   * Enforce per-group media limits (rolling window)
   */
  private async enforceGroupMediaLimits(groupId: string, mediaType?: MediaType): Promise<void> {
    if (!mediaType || mediaType === 'text') return;
    
    const limit = MEDIA_LIMITS[mediaType.toUpperCase() as keyof typeof MEDIA_LIMITS];
    if (!limit) return;
    
    const messageIds = this.messagesByGroup.get(groupId);
    if (!messageIds) return;
    
    // Get all messages of this media type in the group
    const mediaMessages: EphemeralEvent[] = [];
    for (const id of messageIds) {
      const event = this.events.get(id);
      if (event && event.eventType === EphemeralEventType.GROUP_MESSAGE_SENT) {
        const payload = event.payload as GroupMessagePayload;
        if (payload.mediaType === mediaType) {
          mediaMessages.push(event);
        }
      }
    }
    
    // Sort by timestamp (oldest first)
    mediaMessages.sort((a, b) => a.timestamp - b.timestamp);
    
    // Remove oldest if over limit
    while (mediaMessages.length > limit) {
      const oldest = mediaMessages.shift()!;
      await this.deleteGroupMessageInternal(oldest.eventId);
      console.log(`[Ephemeral] Auto-pruned oldest ${mediaType} in group (limit: ${limit})`);
    }
  }

  /**
   * Internal delete without creating event (for auto-pruning)
   */
  private async deleteMessageInternal(eventId: string): Promise<void> {
    const event = this.events.get(eventId);
    if (!event) return;
    
    await this.cleanupContentFiles(event);
    const payload = event.payload as MessagePayload;
    this.messagesByConversation.get(payload.conversationId)?.delete(eventId);
    this.messagesByUser.get(payload.senderId)?.delete(eventId);
    this.messagesByUser.get(payload.recipientId)?.delete(eventId);
    this.events.delete(eventId);
  }

  /**
   * Internal delete for group messages (for auto-pruning)
   */
  private async deleteGroupMessageInternal(eventId: string): Promise<void> {
    const event = this.events.get(eventId);
    if (!event) return;
    
    await this.cleanupContentFiles(event);
    const payload = event.payload as GroupMessagePayload;
    this.messagesByGroup.get(payload.groupId)?.delete(eventId);
    this.events.delete(eventId);
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

      case EphemeralEventType.MESSAGING_VAULT_PUBLISHED: {
        const payload = event.payload as MessagingVaultPayload;
        const accountId = String(payload?.accountId || '').trim();
        if (!accountId) break;

        const existing = this.messagingVaultByAccount.get(accountId);
        if (!existing) {
          this.messagingVaultByAccount.set(accountId, event);
          break;
        }

        const eP = existing.payload as Partial<MessagingVaultPayload>;
        const oldEpoch = String(eP?.vaultEpoch || '').trim();
        const newEpoch = String(payload?.vaultEpoch || '').trim();
        const oldVersion = Number(eP?.vaultVersion || 0);
        const newVersion = Number(payload?.vaultVersion || 0);

        const shouldReplace = (oldEpoch && newEpoch && oldEpoch === newEpoch)
          ? (newVersion > oldVersion || (newVersion === oldVersion && event.timestamp > existing.timestamp))
          : (event.timestamp >= existing.timestamp);

        if (shouldReplace) {
          this.messagingVaultByAccount.set(accountId, event);
        }
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
      
      // Group chat indexing
      case EphemeralEventType.GROUP_CREATED: {
        const payload = event.payload as GroupPayload;
        this.groups.set(payload.groupId, payload);
        // Index group for all members
        for (const memberId of payload.members) {
          if (!this.groupsByUser.has(memberId)) {
            this.groupsByUser.set(memberId, new Set());
          }
          this.groupsByUser.get(memberId)!.add(payload.groupId);
        }
        break;
      }
      
      case EphemeralEventType.GROUP_MESSAGE_SENT: {
        const payload = event.payload as GroupMessagePayload;
        // Index by group
        if (!this.messagesByGroup.has(payload.groupId)) {
          this.messagesByGroup.set(payload.groupId, new Set());
        }
        this.messagesByGroup.get(payload.groupId)!.add(event.eventId);
        break;
      }
      
      case EphemeralEventType.GROUP_MEMBER_ADDED: {
        const payload = event.payload as GroupMemberPayload;
        const group = this.groups.get(payload.groupId);
        if (group && !group.members.includes(payload.memberId)) {
          group.members.push(payload.memberId);
          // Index group for new member
          if (!this.groupsByUser.has(payload.memberId)) {
            this.groupsByUser.set(payload.memberId, new Set());
          }
          this.groupsByUser.get(payload.memberId)!.add(payload.groupId);
        }
        break;
      }
      
      case EphemeralEventType.GROUP_MEMBER_REMOVED:
      case EphemeralEventType.GROUP_LEFT: {
        const payload = event.payload as GroupMemberPayload;
        const group = this.groups.get(payload.groupId);
        if (group) {
          group.members = group.members.filter(m => m !== payload.memberId);
          // Remove group from user's index
          this.groupsByUser.get(payload.memberId)?.delete(payload.groupId);
        }
        break;
      }
      
      case EphemeralEventType.GROUP_NAME_CHANGED: {
        const payload = event.payload as GroupNamePayload;
        const group = this.groups.get(payload.groupId);
        if (group) {
          group.name = payload.newName;
        }
        break;
      }
    }
  }

  getLatestMessagingVault(accountId: string): EphemeralEvent | null {
    const id = String(accountId || '').trim();
    if (!id) return null;
    const event = this.messagingVaultByAccount.get(id);
    if (!event) return null;
    if (event.expiresAt <= Date.now()) return null;
    return event;
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

  // ============================================================
  // GROUP CHAT METHODS
  // ============================================================

  /**
   * Get all groups for a user
   */
  getUserGroups(userId: string): GroupPayload[] {
    const groupIds = this.groupsByUser.get(userId) || new Set();
    const groups: GroupPayload[] = [];
    
    for (const groupId of groupIds) {
      const group = this.groups.get(groupId);
      if (group) {
        groups.push(group);
      }
    }
    
    return groups;
  }

  /**
   * Get a group by ID
   */
  getGroup(groupId: string): GroupPayload | null {
    return this.groups.get(groupId) || null;
  }

  /**
   * Check if user is a member of a group
   */
  isGroupMember(groupId: string, userId: string): boolean {
    const group = this.groups.get(groupId);
    return group ? group.members.includes(userId) : false;
  }

  /**
   * Check if user is an admin of a group
   */
  isGroupAdmin(groupId: string, userId: string): boolean {
    const group = this.groups.get(groupId);
    return group ? group.admins.includes(userId) : false;
  }

  /**
   * Get messages for a group
   */
  getGroupMessages(groupId: string): EphemeralEvent[] {
    const messageIds = this.messagesByGroup.get(groupId) || new Set();
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
   * Mark a message as viewed (starts disappearing timer if expiresAfterView is true)
   */
  async markMessageViewed(messageId: string, viewerId: string): Promise<boolean> {
    const event = this.events.get(messageId);
    if (!event) return false;
    
    const now = Date.now();
    
    if (event.eventType === EphemeralEventType.MESSAGE_SENT) {
      const payload = event.payload as MessagePayload;
      
      // Only recipient can mark as viewed
      if (payload.recipientId !== viewerId) return false;
      
      // Already viewed
      if (payload.viewedAt) return true;
      
      // Mark as viewed
      payload.viewedAt = now;
      
      // If expiresAfterView, update the expiry time now
      if (payload.expiresAfterView) {
        const retention = this.calculateRetention(payload);
        event.expiresAt = now + retention;
      }
      
      // Create viewed event
      await this.appendEvent(EphemeralEventType.MESSAGE_VIEWED, {
        messageId,
        viewedBy: viewerId,
        viewedAt: now,
        conversationId: payload.conversationId,
      } as MessageViewedPayload);
      
      await this.persistToDisk();
      return true;
      
    } else if (event.eventType === EphemeralEventType.GROUP_MESSAGE_SENT) {
      const payload = event.payload as GroupMessagePayload;
      
      // Initialize viewedBy if needed
      if (!payload.viewedBy) {
        payload.viewedBy = {};
      }
      
      // Already viewed by this user
      if (payload.viewedBy[viewerId]) return true;
      
      // Mark as viewed by this user
      payload.viewedBy[viewerId] = now;
      
      // For group messages with expiresAfterView, expire when ALL members have viewed
      // (or use sender's view time as trigger - simpler approach)
      
      await this.persistToDisk();
      return true;
    }
    
    return false;
  }

  /**
   * Delete a group message
   */
  async deleteGroupMessage(messageId: string, requesterId: string): Promise<boolean> {
    const found = this.findEventByMessageId(messageId);
    if (!found || found.event.eventType !== EphemeralEventType.GROUP_MESSAGE_SENT) return false;
    const { eventId, event } = found;
    
    const payload = event.payload as GroupMessagePayload;
    
    // Only sender can delete
    if (payload.senderId !== requesterId) return false;
    
    // Remove from indexes
    this.messagesByGroup.get(payload.groupId)?.delete(eventId);
    this.events.delete(eventId);
    
    // Record deletion event
    await this.appendEvent(EphemeralEventType.MESSAGE_DELETED, {
      messageId,
      deletedBy: requesterId,
      deletedAt: Date.now(),
      groupId: payload.groupId,
    } as MessageDeletePayload);
    
    await this.persistToDisk();
    return true;
  }

  /**
   * Find an event by payload.messageId (events map is keyed by eventId, not messageId)
   */
  private findEventByMessageId(messageId: string): { eventId: string; event: EphemeralEvent } | null {
    // First try direct lookup (in case caller passed an eventId)
    const direct = this.events.get(messageId);
    if (direct) return { eventId: messageId, event: direct };

    // Search by payload.messageId
    for (const [eventId, event] of this.events.entries()) {
      const payload = event.payload as any;
      if (payload?.messageId === messageId) {
        return { eventId, event };
      }
    }
    return null;
  }

  /**
   * Get a message by ID
   */
  getMessage(messageId: string): EphemeralEvent | null {
    const found = this.findEventByMessageId(messageId);
    if (!found) return null;
    if (found.event.expiresAt <= Date.now()) return null;
    return found.event;
  }

  /**
   * Generate a unique group ID
   */
  generateGroupId(): string {
    const timestamp = Date.now().toString(36);
    const random = randomBytes(8).toString('hex');
    return `grp_${timestamp}_${random}`;
  }

  /**
   * Delete a message early (for paid early deletion)
   */
  async deleteMessage(messageId: string, requesterId: string): Promise<boolean> {
    const found = this.findEventByMessageId(messageId);
    if (!found) return false;
    const { eventId, event } = found;
    
    // Only sender or recipient can delete
    const payload = event.payload as MessagePayload;
    if (payload.senderId !== requesterId && payload.recipientId !== requesterId) {
      return false;
    }
    
    // Remove from all indexes
    this.messagesByConversation.get(payload.conversationId)?.delete(eventId);
    this.messagesByUser.get(payload.senderId)?.delete(eventId);
    this.messagesByUser.get(payload.recipientId)?.delete(eventId);
    this.events.delete(eventId);
    
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
        // Clean up any extracted content files
        await this.cleanupContentFiles(event);
        
        // Remove from indexes
        if (event.eventType === EphemeralEventType.MESSAGE_SENT) {
          const payload = event.payload as MessagePayload;
          this.messagesByConversation.get(payload.conversationId)?.delete(eventId);
          this.messagesByUser.get(payload.senderId)?.delete(eventId);
          this.messagesByUser.get(payload.recipientId)?.delete(eventId);
        } else if (event.eventType === EphemeralEventType.GROUP_MESSAGE_SENT) {
          const payload = event.payload as GroupMessagePayload;
          this.messagesByGroup.get(payload.groupId)?.delete(eventId);
        } else if (event.eventType === EphemeralEventType.MESSAGING_VAULT_PUBLISHED) {
          const payload = event.payload as MessagingVaultPayload;
          const accountId = String(payload?.accountId || '').trim();
          if (accountId) {
            const current = this.messagingVaultByAccount.get(accountId);
            if (current?.eventId === eventId) {
              this.messagingVaultByAccount.delete(accountId);
            }
          }
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

    // DEBUG: Log incoming content sizes
    const p = event.payload as any;
    const contentLen = typeof p?.encryptedContent === 'string' ? p.encryptedContent.length : 0;
    const forSenderLen = typeof p?.encryptedForSender === 'string' ? p.encryptedForSender.length : 0;
    const hasChunksField = !!p?.__chunks_encryptedContent;
    const isChunkedMarker = typeof p?.encryptedContent === 'string' && p.encryptedContent.startsWith('__chunked:');
    console.log(`[Ephemeral] 📥 importEvent ${event.eventId.substring(0,8)}... contentLen=${contentLen}, forSenderLen=${forSenderLen}, hasChunksField=${hasChunksField}, isChunkedMarker=${isChunkedMarker}`);

    // Store event
    this.events.set(event.eventId, event);

    // Update indexes
    this.indexEvent(event);

    // Extract large content to disk (prevents OOM from holding large payloads in memory)
    await this.extractLargeContent(event);

    // DEBUG: Log content after extraction
    const postPayload = event.payload as any;
    const postContentLen = typeof postPayload?.encryptedContent === 'string' ? postPayload.encryptedContent.length : 0;
    const postHasChunks = !!postPayload?.__chunks_encryptedContent;
    const postChunksLen = Array.isArray(postPayload?.__chunks_encryptedContent) ? postPayload.__chunks_encryptedContent.length : 0;
    console.log(`[Ephemeral] 📥 importEvent ${event.eventId.substring(0,8)}... POST-extraction: contentLen=${postContentLen}, hasChunks=${postHasChunks}, chunksCount=${postChunksLen}`);

    // Persist to disk
    await this.persistToDisk();

    // Emit event for real-time delivery
    this.emit('event', event);
    this.emit('imported', event);
    this.emit(event.eventType, event);

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

  // ============================================================
  // CONTENT CHUNKING - Split large payloads into chunks for replication
  // Chunks are stored INLINE in the event, ensuring full replication across all nodes
  // ============================================================

  /**
   * Split a large string into chunks for inline storage.
   */
  private chunkContent(content: string): string[] {
    const chunks: string[] = [];
    for (let i = 0; i < content.length; i += CHUNK_SIZE) {
      chunks.push(content.slice(i, i + CHUNK_SIZE));
    }
    return chunks;
  }

  /**
   * Reassemble chunks back into the original content.
   */
  private reassembleChunks(chunks: string[]): string {
    return chunks.join('');
  }

  /**
   * Check if a field value is chunked.
   */
  private isChunked(value: any): boolean {
    return typeof value === 'string' && value.startsWith(CHUNK_PREFIX);
  }

  /**
   * Get the chunk field name for a given field.
   */
  private getChunkFieldName(field: string): string {
    return `__chunks_${field}`;
  }

  /**
   * Chunk large content fields in an event payload.
   * Large content is split into chunks and stored in a parallel array field.
   * The original field gets a marker indicating it's chunked.
   * This ensures the chunks travel WITH the event during broadcast/replication.
   */
  async chunkLargeContent(event: EphemeralEvent): Promise<void> {
    const payload = event.payload;
    if (!payload) return;

    const fields = ['encryptedContent', 'encryptedForSender'];
    console.log(`[Ephemeral] 🔧 chunkLargeContent called for event ${event.eventId.substring(0,8)}...`);

    for (const field of fields) {
      const value = (payload as any)[field];
      const valueLen = typeof value === 'string' ? value.length : 0;
      console.log(`[Ephemeral]   - ${field}: len=${valueLen}, threshold=${CONTENT_SIZE_THRESHOLD}, isChunked=${this.isChunked(value)}`);
      if (typeof value !== 'string' || value.length < CONTENT_SIZE_THRESHOLD) continue;
      if (this.isChunked(value)) continue; // Already chunked

      const chunks = this.chunkContent(value);
      const chunkFieldName = this.getChunkFieldName(field);
      
      // Store chunks inline in the payload
      (payload as any)[chunkFieldName] = chunks;
      // Replace original field with marker showing chunk count
      (payload as any)[field] = `${CHUNK_PREFIX}${chunks.length}`;
      
      console.log(`[Ephemeral] ✅ Chunked ${field} into ${chunks.length} chunks (${value.length} chars)`);
    }

    // Handle group messages with encryptedContentByMember
    if ((payload as any).encryptedContentByMember) {
      const byMember = (payload as any).encryptedContentByMember;
      if (!(payload as any).__chunks_byMember) {
        (payload as any).__chunks_byMember = {};
      }
      
      for (const memberId of Object.keys(byMember)) {
        const value = byMember[memberId];
        if (typeof value !== 'string' || value.length < CONTENT_SIZE_THRESHOLD) continue;
        if (this.isChunked(value)) continue;

        const chunks = this.chunkContent(value);
        (payload as any).__chunks_byMember[memberId] = chunks;
        byMember[memberId] = `${CHUNK_PREFIX}${chunks.length}`;
      }
    }
  }

  /**
   * Reassemble chunked content in an event.
   * Returns a CLONE of the event with chunks reassembled (does not modify original).
   */
  reassembleEventContent(event: EphemeralEvent): EphemeralEvent {
    const payload = event.payload;
    if (!payload) return event;

    const fields = ['encryptedContent', 'encryptedForSender'];
    let needsReassembly = false;

    // DEBUG: Log all payload keys to see what's available
    const payloadKeys = Object.keys(payload);
    console.log(`[Ephemeral] 🔍 reassembleEventContent ${event.eventId.substring(0,8)}... payloadKeys=${payloadKeys.join(',')}`);

    for (const field of fields) {
      if (this.isChunked((payload as any)[field])) {
        needsReassembly = true;
        const chunkFieldName = this.getChunkFieldName(field);
        const hasChunks = !!(payload as any)[chunkFieldName];
        const chunksLen = Array.isArray((payload as any)[chunkFieldName]) ? (payload as any)[chunkFieldName].length : 0;
        console.log(`[Ephemeral] 🔍 Field ${field} isChunked=true, chunkField=${chunkFieldName}, hasChunks=${hasChunks}, chunksLen=${chunksLen}`);
      }
    }

    if (!needsReassembly && (payload as any).encryptedContentByMember) {
      for (const value of Object.values((payload as any).encryptedContentByMember)) {
        if (this.isChunked(value)) {
          needsReassembly = true;
          break;
        }
      }
    }

    if (!needsReassembly) return event;

    const clonedPayload = { ...payload };
    const clonedEvent = { ...event, payload: clonedPayload };

    for (const field of fields) {
      if (!this.isChunked((clonedPayload as any)[field])) continue;
      
      const chunkFieldName = this.getChunkFieldName(field);
      const chunks = (clonedPayload as any)[chunkFieldName];
      
      if (Array.isArray(chunks) && chunks.length > 0) {
        (clonedPayload as any)[field] = this.reassembleChunks(chunks);
        delete (clonedPayload as any)[chunkFieldName];
      } else {
        console.warn(`[Ephemeral] Missing chunks for ${field} in event ${event.eventId}`);
      }
    }

    if ((clonedPayload as any).encryptedContentByMember && (clonedPayload as any).__chunks_byMember) {
      const byMember = { ...(clonedPayload as any).encryptedContentByMember };
      const chunksByMember = (clonedPayload as any).__chunks_byMember;
      (clonedPayload as any).encryptedContentByMember = byMember;

      for (const memberId of Object.keys(byMember)) {
        if (!this.isChunked(byMember[memberId])) continue;
        
        const chunks = chunksByMember[memberId];
        if (Array.isArray(chunks) && chunks.length > 0) {
          byMember[memberId] = this.reassembleChunks(chunks);
        }
      }
      
      delete (clonedPayload as any).__chunks_byMember;
    }

    return clonedEvent;
  }

  /**
   * Legacy: Extract large content to disk files (for backward compatibility).
   * New code uses chunkLargeContent instead.
   */
  async extractLargeContent(event: EphemeralEvent): Promise<void> {
    // Use new chunking system instead of file-based extraction
    await this.chunkLargeContent(event);
  }

  /**
   * Restore/reassemble content for an event.
   * Handles both new chunked format and legacy file-based format.
   */
  async restoreEventContent(event: EphemeralEvent): Promise<EphemeralEvent> {
    const payload = event.payload;
    if (!payload) return event;

    const fields = ['encryptedContent', 'encryptedForSender'];
    let hasChunks = false;
    let hasLegacyRefs = false;

    for (const field of fields) {
      const value = (payload as any)[field];
      if (this.isChunked(value)) hasChunks = true;
      if (typeof value === 'string' && value.startsWith(CONTENT_REF_PREFIX)) hasLegacyRefs = true;
    }

    // DEBUG: Log restore attempt
    const p = payload as any;
    const contentVal = typeof p?.encryptedContent === 'string' ? p.encryptedContent.substring(0, 50) : 'N/A';
    const hasChunksField = !!p?.__chunks_encryptedContent;
    console.log(`[Ephemeral] 🔄 restoreEventContent ${event.eventId.substring(0,8)}... hasChunks=${hasChunks}, hasLegacyRefs=${hasLegacyRefs}, hasChunksField=${hasChunksField}, content=${contentVal}`);

    // Handle new chunked format
    if (hasChunks) {
      const restored = this.reassembleEventContent(event);
      const restoredLen = typeof (restored.payload as any)?.encryptedContent === 'string' ? (restored.payload as any).encryptedContent.length : 0;
      console.log(`[Ephemeral] ✅ Reassembled content, new length=${restoredLen}`);
      return restored;
    }

    // Handle legacy file-based format (backward compatibility)
    if (hasLegacyRefs) {
      return this.restoreLegacyContent(event);
    }

    return event;
  }

  /**
   * Legacy: Restore content from disk files (for backward compatibility with old events).
   */
  private async restoreLegacyContent(event: EphemeralEvent): Promise<EphemeralEvent> {
    const payload = event.payload;
    if (!payload) return event;

    const clonedPayload = { ...payload };
    const clonedEvent = { ...event, payload: clonedPayload };
    const fields = ['encryptedContent', 'encryptedForSender'];

    for (const field of fields) {
      const value = (clonedPayload as any)[field];
      if (typeof value !== 'string' || !value.startsWith(CONTENT_REF_PREFIX) || !value.endsWith(CONTENT_REF_SUFFIX)) continue;

      const hash = value.slice(CONTENT_REF_PREFIX.length, -CONTENT_REF_SUFFIX.length);
      const contentPath = path.join(this.contentDir, `${hash}.bin`);

      try {
        (clonedPayload as any)[field] = await fs.promises.readFile(contentPath, 'utf8');
      } catch (e: any) {
        // Content file missing - set to empty to prevent raw placeholder from being shown to client
        console.warn(`[Ephemeral] Legacy content file missing for ${hash}, field ${field} - clearing placeholder`);
        (clonedPayload as any)[field] = '';
      }
    }

    if ((clonedPayload as any).encryptedContentByMember) {
      const byMember = { ...(clonedPayload as any).encryptedContentByMember };
      (clonedPayload as any).encryptedContentByMember = byMember;

      for (const memberId of Object.keys(byMember)) {
        const value = byMember[memberId];
        if (typeof value !== 'string' || !value.startsWith(CONTENT_REF_PREFIX) || !value.endsWith(CONTENT_REF_SUFFIX)) continue;

        const hash = value.slice(CONTENT_REF_PREFIX.length, -CONTENT_REF_SUFFIX.length);
        const contentPath = path.join(this.contentDir, `${hash}.bin`);

        try {
          byMember[memberId] = await fs.promises.readFile(contentPath, 'utf8');
        } catch (e: any) {
          // Content file missing - set to empty to prevent raw placeholder from being shown to client
          console.warn(`[Ephemeral] Legacy content file missing for ${hash}, member ${memberId} - clearing placeholder`);
          byMember[memberId] = '';
        }
      }
    }

    return clonedEvent;
  }

  /**
   * Batch restore content for multiple events
   */
  async restoreEventsContent(events: EphemeralEvent[]): Promise<EphemeralEvent[]> {
    return Promise.all(events.map(e => this.restoreEventContent(e)));
  }

  /**
   * Delete content files associated with an event
   */
  private async cleanupContentFiles(event: EphemeralEvent): Promise<void> {
    const payload = event.payload;
    if (!payload) return;

    const refs: string[] = [];

    for (const field of ['encryptedContent', 'encryptedForSender']) {
      const value = (payload as any)[field];
      if (typeof value === 'string' && value.startsWith(CONTENT_REF_PREFIX) && value.endsWith(CONTENT_REF_SUFFIX)) {
        refs.push(value.slice(CONTENT_REF_PREFIX.length, -CONTENT_REF_SUFFIX.length));
      }
    }

    if ((payload as any).encryptedContentByMember) {
      for (const value of Object.values((payload as any).encryptedContentByMember)) {
        if (typeof value === 'string' && (value as string).startsWith(CONTENT_REF_PREFIX) && (value as string).endsWith(CONTENT_REF_SUFFIX)) {
          refs.push((value as string).slice(CONTENT_REF_PREFIX.length, -CONTENT_REF_SUFFIX.length));
        }
      }
    }

    for (const hash of refs) {
      const contentPath = path.join(this.contentDir, `${hash}.bin`);
      try {
        await fs.promises.unlink(contentPath);
      } catch (e) {
        // Ignore - file may not exist
      }
    }
  }

  /**
   * Persist events to disk (debounced to avoid blocking on large payloads like photos)
   * Batches writes - saves at most once every 2 seconds
   */
  private async persistToDisk(): Promise<void> {
    this._persistPending = true;
    if (this._persistTimer) return; // Already scheduled
    
    this._persistTimer = setTimeout(() => {
      this._persistTimer = null;
      this._persistPending = false;
      this._doPersistToDisk();
    }, 2000); // 2 second debounce
  }

  /**
   * Serialize data in a worker thread to avoid blocking the event loop.
   * Falls back to sync if worker fails.
   */
  private serializeInWorker(data: any): Promise<string> {
    return new Promise((resolve, reject) => {
      try {
        // Worker code as inline string - serializes data and sends back JSON
        const workerCode = `
          const { parentPort, workerData } = require('worker_threads');
          try {
            const json = JSON.stringify(workerData);
            parentPort.postMessage({ success: true, json });
          } catch (e) {
            parentPort.postMessage({ success: false, error: e.message });
          }
        `;
        
        const worker = new Worker(workerCode, { 
          eval: true, 
          workerData: data 
        });
        
        const timeout = setTimeout(() => {
          worker.terminate();
          // Fallback to sync on timeout
          try {
            resolve(JSON.stringify(data));
          } catch (e: any) {
            reject(e);
          }
        }, 30000); // 30 second timeout
        
        worker.on('message', (msg: { success: boolean; json?: string; error?: string }) => {
          clearTimeout(timeout);
          worker.terminate();
          if (msg.success && msg.json) {
            resolve(msg.json);
          } else {
            // Fallback to sync
            try {
              resolve(JSON.stringify(data));
            } catch (e: any) {
              reject(new Error(msg.error || 'Worker serialization failed'));
            }
          }
        });
        
        worker.on('error', (err) => {
          clearTimeout(timeout);
          worker.terminate();
          // Fallback to sync on worker error
          try {
            resolve(JSON.stringify(data));
          } catch (e: any) {
            reject(err);
          }
        });
      } catch (e: any) {
        // Fallback to sync if worker creation fails
        try {
          resolve(JSON.stringify(data));
        } catch (err: any) {
          reject(err);
        }
      }
    });
  }

  private async _doPersistToDisk(): Promise<void> {
    // Prevent overlapping serializations
    if (this._serializationInProgress) {
      // Re-schedule
      this._persistPending = true;
      if (!this._persistTimer) {
        this._persistTimer = setTimeout(() => {
          this._persistTimer = null;
          this._persistPending = false;
          this._doPersistToDisk();
        }, 2000);
      }
      return;
    }
    
    this._serializationInProgress = true;
    
    try {
      // Messages file (prunable after 10 days)
      const messageData = {
        version: 2,
        ledgerType: 'messages',
        events: Array.from(this.events.values()),
        lastPersisted: Date.now(),
      };
      
      // Serialize in worker thread to avoid blocking event loop
      const messageJson = await this.serializeInWorker(messageData);
      
      await fs.promises.writeFile(this.persistPath, messageJson);
    } catch (e: any) {
      console.error('[MessageLedger] Failed to persist messages:', e.message);
    }
    
    try {
      // Contacts file (permanent, never pruned)
      const contactData = {
        version: 2,
        ledgerType: 'contacts',
        contacts: Object.fromEntries(
          Array.from(this.contactsByUser.entries()).map(([k, v]) => [k, Array.from(v)])
        ),
        blocked: Object.fromEntries(
          Array.from(this.blockedByUser.entries()).map(([k, v]) => [k, Array.from(v)])
        ),
        lastPersisted: Date.now(),
      };
      
      // Contacts are usually small, but use worker for consistency
      const contactJson = await this.serializeInWorker(contactData);
      
      await fs.promises.writeFile(this.contactsPath, contactJson);
    } catch (e: any) {
      console.error('[MessageLedger] Failed to persist contacts:', e.message);
    }
    
    this._serializationInProgress = false;
  }

  /**
   * Immediate sync flush for shutdown - ensures no data loss
   */
  flushToDisk(): void {
    if (this._persistTimer) {
      clearTimeout(this._persistTimer);
      this._persistTimer = null;
    }
    if (this._persistPending || this.events.size > 0) {
      try {
        const messageData = {
          version: 2,
          ledgerType: 'messages',
          events: Array.from(this.events.values()),
          lastPersisted: Date.now(),
        };
        fs.writeFileSync(this.persistPath, JSON.stringify(messageData));
        
        const contactData = {
          version: 2,
          ledgerType: 'contacts',
          contacts: Object.fromEntries(
            Array.from(this.contactsByUser.entries()).map(([k, v]) => [k, Array.from(v)])
          ),
          blocked: Object.fromEntries(
            Array.from(this.blockedByUser.entries()).map(([k, v]) => [k, Array.from(v)])
          ),
          lastPersisted: Date.now(),
        };
        fs.writeFileSync(this.contactsPath, JSON.stringify(contactData));
      } catch (e: any) {
        console.error('[MessageLedger] Failed to flush:', e.message);
      }
    }
  }

  /**
   * Load events from disk (messages and contacts from separate files)
   */
  private loadFromDisk(): void {
    // Load messages (prunable)
    this.loadMessagesFromDisk();
    
    // Load contacts (permanent) - also try legacy file for migration
    this.loadContactsFromDisk();
    
    console.log(`[MessageLedger] Loaded ${this.events.size} messages, ${this.contactsByUser.size} users with contacts`);
  }

  private loadMessagesFromDisk(): void {
    try {
      // Try new file first
      let filePath = this.persistPath;
      const persistPath = this.persistPath;
      
      // Fall back to legacy file if new one doesn't exist
      const legacyPath = path.join(this.dataDir, 'ephemeral-messages.json');
      if (!fs.existsSync(filePath) && fs.existsSync(legacyPath)) {
        filePath = legacyPath;
      }
      
      if (!fs.existsSync(filePath)) return;
      
      const raw = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(raw);

      let expiredFound = false;
      
      // Load events
      for (const event of data.events || []) {
        // Skip expired events
        if (event.expiresAt <= Date.now()) {
          expiredFound = true;
          continue;
        }
        
        this.events.set(event.eventId, event);
        this.indexEvent(event);
      }

      // If we encountered expired events on disk (or loaded from legacy file), compact into the new persistPath.
      // This ensures expired messages are physically removed from disk and we migrate to the current file name.
      const loadedFromLegacy = filePath !== persistPath;
      if (expiredFound || loadedFromLegacy) {
        try {
          const messageData = {
            version: 2,
            ledgerType: 'messages',
            events: Array.from(this.events.values()),
            lastPersisted: Date.now(),
          };
          fs.writeFileSync(persistPath, JSON.stringify(messageData, null, 2));
        } catch {}
      }
      
      // Migration: if legacy file had contacts, load them too
      if (data.contacts) {
        for (const [userId, contacts] of Object.entries(data.contacts || {})) {
          this.contactsByUser.set(userId, new Set(contacts as string[]));
        }
      }
      if (data.blocked) {
        for (const [userId, blocked] of Object.entries(data.blocked || {})) {
          this.blockedByUser.set(userId, new Set(blocked as string[]));
        }
      }
    } catch (error) {
      console.error('[MessageLedger] Failed to load messages:', error);
    }
  }

  private loadContactsFromDisk(): void {
    try {
      if (!fs.existsSync(this.contactsPath)) return;
      
      const raw = fs.readFileSync(this.contactsPath, 'utf8');
      const data = JSON.parse(raw);
      
      // Load contacts (permanent)
      for (const [userId, contacts] of Object.entries(data.contacts || {})) {
        const existing = this.contactsByUser.get(userId) || new Set<string>();
        for (const c of contacts as string[]) {
          existing.add(c);
        }
        this.contactsByUser.set(userId, existing);
      }
      
      // Load blocked
      for (const [userId, blocked] of Object.entries(data.blocked || {})) {
        const existing = this.blockedByUser.get(userId) || new Set<string>();
        for (const b of blocked as string[]) {
          existing.add(b);
        }
        this.blockedByUser.set(userId, existing);
      }
    } catch (error) {
      console.error('[MessageLedger] Failed to load contacts:', error);
    }
  }

  // ============================================================
  // READ RECEIPTS & DELIVERY STATUS
  // ============================================================

  markMessageDelivered(messageId: string): void {
    const status = this.messageReadStatus.get(messageId) || {};
    if (!status.delivered) {
      status.delivered = Date.now();
      this.messageReadStatus.set(messageId, status);
      this.emit(EphemeralEventType.MESSAGE_DELIVERED, { messageId, timestamp: status.delivered });
    }
  }

  markMessageRead(messageId: string, readBy: string): void {
    const status = this.messageReadStatus.get(messageId) || {};
    if (!status.read) {
      status.read = Date.now();
      this.messageReadStatus.set(messageId, status);
      this.emit(EphemeralEventType.MESSAGE_READ, { messageId, readBy, timestamp: status.read });
    }
  }

  getMessageStatus(messageId: string): { delivered?: number; read?: number } {
    return this.messageReadStatus.get(messageId) || {};
  }

  // ============================================================
  // MESSAGE REACTIONS
  // ============================================================

  addReaction(messageId: string, userId: string, emoji: string): void {
    let reactions = this.messageReactions.get(messageId);
    if (!reactions) {
      reactions = new Map();
      this.messageReactions.set(messageId, reactions);
    }
    reactions.set(userId, emoji);
    this.emit(EphemeralEventType.MESSAGE_REACTION, { messageId, userId, emoji, removed: false });
  }

  removeReaction(messageId: string, userId: string): void {
    const reactions = this.messageReactions.get(messageId);
    if (reactions) {
      const emoji = reactions.get(userId);
      reactions.delete(userId);
      if (reactions.size === 0) {
        this.messageReactions.delete(messageId);
      }
      this.emit(EphemeralEventType.MESSAGE_REACTION, { messageId, userId, emoji, removed: true });
    }
  }

  getReactions(messageId: string): { userId: string; emoji: string }[] {
    const reactions = this.messageReactions.get(messageId);
    if (!reactions) return [];
    return Array.from(reactions.entries()).map(([userId, emoji]) => ({ userId, emoji }));
  }

  // ============================================================
  // MUTE CONVERSATIONS
  // ============================================================

  muteConversation(userId: string, conversationId: string): void {
    let muted = this.mutedConversations.get(userId);
    if (!muted) {
      muted = new Set();
      this.mutedConversations.set(userId, muted);
    }
    muted.add(conversationId);
    this.emit(EphemeralEventType.CONVERSATION_MUTED, { userId, conversationId });
  }

  unmuteConversation(userId: string, conversationId: string): void {
    const muted = this.mutedConversations.get(userId);
    if (muted) {
      muted.delete(conversationId);
      this.emit(EphemeralEventType.CONVERSATION_UNMUTED, { userId, conversationId });
    }
  }

  isConversationMuted(userId: string, conversationId: string): boolean {
    return this.mutedConversations.get(userId)?.has(conversationId) || false;
  }

  muteGroup(userId: string, groupId: string): void {
    let muted = this.mutedGroups.get(userId);
    if (!muted) {
      muted = new Set();
      this.mutedGroups.set(userId, muted);
    }
    muted.add(groupId);
    this.emit(EphemeralEventType.GROUP_MUTED, { userId, groupId });
  }

  unmuteGroup(userId: string, groupId: string): void {
    const muted = this.mutedGroups.get(userId);
    if (muted) {
      muted.delete(groupId);
      this.emit(EphemeralEventType.GROUP_UNMUTED, { userId, groupId });
    }
  }

  isGroupMuted(userId: string, groupId: string): boolean {
    return this.mutedGroups.get(userId)?.has(groupId) || false;
  }

  // ============================================================
  // TYPING INDICATORS (ephemeral, not persisted)
  // ============================================================

  setTyping(conversationId: string, userId: string): void {
    let typing = this.typingUsers.get(conversationId);
    if (!typing) {
      typing = new Map();
      this.typingUsers.set(conversationId, typing);
    }
    typing.set(userId, Date.now());
    this.emit(EphemeralEventType.TYPING_STARTED, { conversationId, userId });
    
    // Auto-clear after 5 seconds
    setTimeout(() => {
      this.clearTyping(conversationId, userId);
    }, 5000);
  }

  clearTyping(conversationId: string, userId: string): void {
    const typing = this.typingUsers.get(conversationId);
    if (typing) {
      typing.delete(userId);
      if (typing.size === 0) {
        this.typingUsers.delete(conversationId);
      }
      this.emit(EphemeralEventType.TYPING_STOPPED, { conversationId, userId });
    }
  }

  getTypingUsers(conversationId: string): string[] {
    const typing = this.typingUsers.get(conversationId);
    if (!typing) return [];
    const now = Date.now();
    const activeTypers: string[] = [];
    for (const [userId, timestamp] of typing.entries()) {
      // Only show typing if within last 5 seconds
      if (now - timestamp < 5000) {
        activeTypers.push(userId);
      }
    }
    return activeTypers;
  }

  // ============================================================
  // ONLINE STATUS (ephemeral, not persisted)
  // ============================================================

  setUserOnline(userId: string): void {
    this.onlineUsers.set(userId, Date.now());
    this.emit(EphemeralEventType.USER_ONLINE, { userId, lastSeen: Date.now() });
  }

  setUserOffline(userId: string): void {
    this.onlineUsers.set(userId, Date.now());
    this.emit(EphemeralEventType.USER_OFFLINE, { userId, lastSeen: Date.now() });
  }

  isUserOnline(userId: string): boolean {
    const lastSeen = this.onlineUsers.get(userId);
    if (!lastSeen) return false;
    // Consider online if seen within last 2 minutes
    return Date.now() - lastSeen < 2 * 60 * 1000;
  }

  getUserLastSeen(userId: string): number | null {
    return this.onlineUsers.get(userId) || null;
  }

  getOnlineUsers(): string[] {
    const now = Date.now();
    const online: string[] = [];
    for (const [userId, lastSeen] of this.onlineUsers.entries()) {
      if (now - lastSeen < 2 * 60 * 1000) {
        online.push(userId);
      }
    }
    return online;
  }

  // ============================================================
  // MESSAGE SEARCH
  // ============================================================

  searchMessages(userId: string, query: string, limit: number = 50): EphemeralEvent[] {
    const results: EphemeralEvent[] = [];
    const queryLower = query.toLowerCase();
    const now = Date.now();

    for (const event of this.events.values()) {
      if (event.expiresAt <= now) continue;
      if (event.eventType !== EphemeralEventType.MESSAGE_SENT) continue;

      const payload = event.payload as MessagePayload;
      // Only search messages the user can see
      if (payload.senderId !== userId && payload.recipientId !== userId) continue;

      // Search in encrypted content is not possible without decryption
      // But we can search metadata like messageId, itemId, etc.
      // For now, return all messages matching the user - client will filter decrypted content
      results.push(event);

      if (results.length >= limit) break;
    }

    return results.sort((a, b) => b.timestamp - a.timestamp);
  }

}
