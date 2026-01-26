/**
 * Consensus Node
 * 
 * Integrates mempool, validator, and checkpoint manager into a single
 * consensus layer that can be used by any node (operator or gateway).
 */

import { createHash, randomBytes } from 'crypto';
import {
  MempoolEvent,
  CheckpointProposal,
  CheckpointVote,
  FinalizedCheckpoint,
  ConsensusState,
  ConsensusMessage,
} from './types';
import { EventMempool } from './event-mempool';
import { EventValidator, StateProvider } from './event-validator';
import { CheckpointManager, OperatorInfo } from './checkpoint-manager';

export interface ConsensusNodeConfig {
  nodeId: string;
  isOperator: boolean;
  privateKey?: string;           // For signing (operators only)
  publicKey?: string;
  checkpointInterval?: number;   // ms between checkpoints
  dataDir?: string;              // For persistence
}

export interface PeerConnection {
  peerId: string;
  send: (message: ConsensusMessage) => void;
  isOperator: boolean;
}

export class ConsensusNode {
  private config: ConsensusNodeConfig;
  private mempool: EventMempool;
  private validator: EventValidator;
  private checkpointManager: CheckpointManager;
  private peers: Map<string, PeerConnection> = new Map();
  private stateProvider: StateProvider;

  // Event handlers
  private onEventAccepted: ((event: MempoolEvent) => void) | null = null;
  private onEventRejected: ((event: MempoolEvent, reason: string) => void) | null = null;
  private onCheckpointFinalized: ((checkpoint: FinalizedCheckpoint) => void) | null = null;
  private onStateChanged: (() => void) | null = null;

  constructor(config: ConsensusNodeConfig, stateProvider: StateProvider) {
    this.config = config;
    this.stateProvider = stateProvider;

    // Initialize mempool
    this.mempool = new EventMempool({
      maxSize: 10000,
      eventTTL: 24 * 60 * 60 * 1000, // 24 hours
    });

    // Initialize validator
    this.validator = new EventValidator(stateProvider);

    // Initialize checkpoint manager
    this.checkpointManager = new CheckpointManager(
      {
        nodeId: config.nodeId,
        isOperator: config.isOperator,
        checkpointInterval: config.checkpointInterval || 30000,
        minEventsForCheckpoint: 1,
        maxEventsPerCheckpoint: 1000,
        voteTimeout: 10000,
        leaderTimeout: 15000,
      },
      this.mempool
    );

    // Set up checkpoint manager callbacks
    this.checkpointManager.setCallbacks({
      onBroadcastProposal: (proposal) => this.broadcastProposal(proposal),
      onBroadcastVote: (vote) => this.broadcastVote(vote),
      onCheckpointFinalized: (checkpoint) => this.handleCheckpointFinalized(checkpoint),
      signMessage: (message) => this.signMessage(message),
    });
  }

  /**
   * Set event handlers
   */
  setHandlers(handlers: {
    onEventAccepted?: (event: MempoolEvent) => void;
    onEventRejected?: (event: MempoolEvent, reason: string) => void;
    onCheckpointFinalized?: (checkpoint: FinalizedCheckpoint) => void;
    onStateChanged?: () => void;
  }): void {
    if (handlers.onEventAccepted) this.onEventAccepted = handlers.onEventAccepted;
    if (handlers.onEventRejected) this.onEventRejected = handlers.onEventRejected;
    if (handlers.onCheckpointFinalized) this.onCheckpointFinalized = handlers.onCheckpointFinalized;
    if (handlers.onStateChanged) this.onStateChanged = handlers.onStateChanged;
  }

  /**
   * Start the consensus node
   */
  start(): void {
    console.log(`[Consensus] Starting node ${this.config.nodeId} (operator: ${this.config.isOperator})`);
    this.checkpointManager.start();
  }

  /**
   * Stop the consensus node
   */
  stop(): void {
    console.log(`[Consensus] Stopping node ${this.config.nodeId}`);
    this.checkpointManager.stop();
  }

  /**
   * Update the list of active operators
   */
  updateOperators(operators: OperatorInfo[]): void {
    this.checkpointManager.updateOperators(operators);
  }

  /**
   * Create and submit a new event
   * This is the main entry point for creating events
   */
  async submitEvent(
    type: string,
    payload: Record<string, any>,
    creatorSignature?: string
  ): Promise<{ success: boolean; eventId?: string; error?: string }> {
    const timestamp = Date.now();
    const creatorId = this.config.nodeId;

    // Generate event ID
    const eventId = EventMempool.generateEventId({
      type,
      payload,
      timestamp,
      creatorId,
      creatorSignature: creatorSignature || '',
    });

    // Create mempool event
    const event: MempoolEvent = {
      eventId,
      type,
      payload,
      timestamp,
      creatorId,
      creatorSignature: creatorSignature || this.signMessage(eventId),
      receivedAt: timestamp,
      receivedFrom: 'local',
      validationStatus: 'pending',
    };

    // Validate event
    const validationResult = this.validator.validate(event);
    if (!validationResult.valid) {
      console.log(`[Consensus] Event rejected: ${validationResult.error}`);
      if (this.onEventRejected) {
        this.onEventRejected(event, validationResult.error || 'Validation failed');
      }
      return { success: false, error: validationResult.error };
    }

    // Mark as valid
    event.validationStatus = 'valid';

    // Add to mempool
    const addResult = this.mempool.addEvent(event);
    if (!addResult.added) {
      return { success: false, error: addResult.reason };
    }

    console.log(`[Consensus] Event accepted: ${type} (${eventId})`);

    // Notify handler
    if (this.onEventAccepted) {
      this.onEventAccepted(event);
    }

    // Broadcast to peers
    this.broadcastEvent(event);

    return { success: true, eventId };
  }

  /**
   * Handle incoming event from peer
   */
  async handleIncomingEvent(event: MempoolEvent, fromPeerId: string): Promise<boolean> {
    // Check if we already have this event
    if (this.mempool.hasEvent(event.eventId)) {
      return false; // Already have it
    }

    // Update received info
    event.receivedAt = Date.now();
    event.receivedFrom = fromPeerId;
    event.validationStatus = 'pending';

    // Validate event
    const validationResult = this.validator.validate(event);
    if (!validationResult.valid) {
      event.validationStatus = 'invalid';
      event.validationError = validationResult.error;
      console.log(`[Consensus] Rejected event from ${fromPeerId}: ${validationResult.error}`);
      if (this.onEventRejected) {
        this.onEventRejected(event, validationResult.error || 'Validation failed');
      }
      return false;
    }

    // Mark as valid
    event.validationStatus = 'valid';

    // Add to mempool
    const addResult = this.mempool.addEvent(event);
    if (!addResult.added) {
      return false;
    }

    console.log(`[Consensus] Accepted event from ${fromPeerId}: ${event.type} (${event.eventId})`);

    // Notify handler
    if (this.onEventAccepted) {
      this.onEventAccepted(event);
    }

    // Re-broadcast to other peers (gossip)
    this.broadcastEvent(event, fromPeerId);

    return true;
  }

  /**
   * Handle incoming consensus message
   */
  async handleMessage(message: ConsensusMessage, fromPeerId: string): Promise<void> {
    switch (message.type) {
      case 'mempool_event':
        await this.handleIncomingEvent(message.payload as MempoolEvent, fromPeerId);
        break;

      case 'checkpoint_proposal':
        await this.checkpointManager.handleProposal(message.payload as CheckpointProposal);
        break;

      case 'checkpoint_vote':
        this.checkpointManager.handleVote(message.payload as CheckpointVote);
        break;

      case 'checkpoint_finalized':
        this.checkpointManager.handleFinalizedCheckpoint(message.payload as FinalizedCheckpoint);
        break;

      case 'sync_checkpoints':
        // Handle checkpoint sync request
        this.handleCheckpointSyncRequest(fromPeerId);
        break;

      case 'fork_detected':
        // Handle fork detection
        this.handleForkDetected(message.payload, fromPeerId);
        break;

      default:
        console.log(`[Consensus] Unknown message type: ${message.type}`);
    }
  }

  /**
   * Register a peer connection
   */
  addPeer(peer: PeerConnection): void {
    this.peers.set(peer.peerId, peer);
    console.log(`[Consensus] Added peer: ${peer.peerId} (operator: ${peer.isOperator})`);
  }

  /**
   * Remove a peer connection
   */
  removePeer(peerId: string): void {
    this.peers.delete(peerId);
    console.log(`[Consensus] Removed peer: ${peerId}`);
  }

  /**
   * Broadcast event to all peers
   */
  private broadcastEvent(event: MempoolEvent, excludePeerId?: string): void {
    const message: ConsensusMessage = {
      type: 'mempool_event',
      payload: event,
      senderId: this.config.nodeId,
      timestamp: Date.now(),
      signature: this.signMessage(event.eventId),
    };

    for (const [peerId, peer] of this.peers) {
      if (peerId !== excludePeerId) {
        try {
          peer.send(message);
        } catch (error) {
          console.error(`[Consensus] Failed to send to peer ${peerId}:`, error);
        }
      }
    }
  }

  /**
   * Broadcast checkpoint proposal to operators
   */
  private broadcastProposal(proposal: CheckpointProposal): void {
    const message: ConsensusMessage = {
      type: 'checkpoint_proposal',
      payload: proposal,
      senderId: this.config.nodeId,
      timestamp: Date.now(),
      signature: this.signMessage(proposal.proposalHash),
    };

    for (const [peerId, peer] of this.peers) {
      if (peer.isOperator) {
        try {
          peer.send(message);
        } catch (error) {
          console.error(`[Consensus] Failed to send proposal to ${peerId}:`, error);
        }
      }
    }
  }

  /**
   * Broadcast vote to operators
   */
  private broadcastVote(vote: CheckpointVote): void {
    const message: ConsensusMessage = {
      type: 'checkpoint_vote',
      payload: vote,
      senderId: this.config.nodeId,
      timestamp: Date.now(),
      signature: vote.signature,
    };

    for (const [peerId, peer] of this.peers) {
      if (peer.isOperator) {
        try {
          peer.send(message);
        } catch (error) {
          console.error(`[Consensus] Failed to send vote to ${peerId}:`, error);
        }
      }
    }
  }

  /**
   * Handle checkpoint finalization
   */
  private handleCheckpointFinalized(checkpoint: FinalizedCheckpoint): void {
    console.log(`[Consensus] Checkpoint #${checkpoint.checkpointNumber} finalized with ${checkpoint.events.length} events`);

    // Broadcast to all peers
    const message: ConsensusMessage = {
      type: 'checkpoint_finalized',
      payload: checkpoint,
      senderId: this.config.nodeId,
      timestamp: Date.now(),
      signature: this.signMessage(checkpoint.checkpointHash),
    };

    for (const peer of this.peers.values()) {
      try {
        peer.send(message);
      } catch (error) {
        console.error(`[Consensus] Failed to broadcast checkpoint:`, error);
      }
    }

    // Notify handler
    if (this.onCheckpointFinalized) {
      this.onCheckpointFinalized(checkpoint);
    }

    // Notify state changed
    if (this.onStateChanged) {
      this.onStateChanged();
    }
  }

  /**
   * Handle checkpoint sync request
   */
  private handleCheckpointSyncRequest(fromPeerId: string): void {
    const peer = this.peers.get(fromPeerId);
    if (!peer) return;

    const checkpoints = this.checkpointManager.getCheckpoints();
    
    // Send checkpoints in batches
    for (const checkpoint of checkpoints) {
      const message: ConsensusMessage = {
        type: 'checkpoint_finalized',
        payload: checkpoint,
        senderId: this.config.nodeId,
        timestamp: Date.now(),
        signature: this.signMessage(checkpoint.checkpointHash),
      };
      peer.send(message);
    }
  }

  /**
   * Handle fork detection
   */
  private handleForkDetected(remoteCheckpoints: FinalizedCheckpoint[], fromPeerId: string): void {
    const forkInfo = this.checkpointManager.detectFork(remoteCheckpoints);
    if (!forkInfo) return;

    console.log(`[Consensus] Fork detected at checkpoint #${forkInfo.divergencePoint}`);
    console.log(`[Consensus] Local: ${forkInfo.localChainLength}, Remote: ${forkInfo.remoteChainLength}`);
    console.log(`[Consensus] Resolution: ${forkInfo.resolution}`);

    if (forkInfo.resolution === 'switch_to_remote') {
      this.checkpointManager.switchToChain(remoteCheckpoints, forkInfo.eventsToRevalidate);
      
      // Re-validate events
      for (const event of forkInfo.eventsToRevalidate) {
        const result = this.validator.validate(event);
        this.mempool.updateValidationStatus(
          event.eventId,
          result.valid ? 'valid' : 'invalid',
          result.error
        );
      }

      if (this.onStateChanged) {
        this.onStateChanged();
      }
    }
  }

  /**
   * Sign a message (for operators)
   */
  private signMessage(message: string): string {
    if (!this.config.privateKey) {
      // Simple hash-based signature for non-operators
      return createHash('sha256')
        .update(`${this.config.nodeId}:${message}`)
        .digest('hex');
    }
    // TODO: Implement proper cryptographic signing
    return createHash('sha256')
      .update(`${this.config.privateKey}:${message}`)
      .digest('hex');
  }

  /**
   * Get consensus state
   */
  getState(): ConsensusState & { mempoolStats: ReturnType<EventMempool['getStats']> } {
    return {
      ...this.checkpointManager.getState(),
      mempoolStats: this.mempool.getStats(),
    };
  }

  /**
   * Get all checkpoints
   */
  getCheckpoints(): FinalizedCheckpoint[] {
    return this.checkpointManager.getCheckpoints();
  }

  /**
   * Get mempool events
   */
  getMempoolEvents(): MempoolEvent[] {
    return this.mempool.getOrderedEvents();
  }

  /**
   * Get valid mempool events
   */
  getValidMempoolEvents(): MempoolEvent[] {
    return this.mempool.getValidOrderedEvents();
  }

  /**
   * Request checkpoint sync from peers
   */
  requestCheckpointSync(): void {
    const message: ConsensusMessage = {
      type: 'sync_checkpoints',
      payload: {
        lastCheckpointNumber: this.checkpointManager.getCurrentCheckpointNumber(),
        lastCheckpointHash: this.checkpointManager.getLastCheckpointHash(),
      },
      senderId: this.config.nodeId,
      timestamp: Date.now(),
      signature: '',
    };

    for (const peer of this.peers.values()) {
      if (peer.isOperator) {
        try {
          peer.send(message);
        } catch (error) {
          console.error(`[Consensus] Failed to request sync:`, error);
        }
      }
    }
  }

  /**
   * Update state provider (after state rebuild)
   */
  updateStateProvider(stateProvider: StateProvider): void {
    this.stateProvider = stateProvider;
    this.validator.updateStateProvider(stateProvider);
  }

  /**
   * Export state for persistence
   */
  export(): {
    mempool: MempoolEvent[];
    checkpoints: FinalizedCheckpoint[];
  } {
    return {
      mempool: this.mempool.export(),
      checkpoints: this.checkpointManager.export().checkpoints,
    };
  }

  /**
   * Import state from persistence
   */
  import(data: {
    mempool?: MempoolEvent[];
    checkpoints?: FinalizedCheckpoint[];
  }): void {
    if (data.mempool) {
      this.mempool.import(data.mempool);
    }
    if (data.checkpoints) {
      this.checkpointManager.import({ checkpoints: data.checkpoints });
    }
  }
}
