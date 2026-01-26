/**
 * Checkpoint Manager
 * 
 * Manages checkpoint proposals, voting, and finalization.
 * This is the core consensus mechanism that orders events deterministically.
 */

import { createHash } from 'crypto';
import {
  MempoolEvent,
  CheckpointProposal,
  CheckpointVote,
  FinalizedCheckpoint,
  ConsensusState,
  ForkInfo,
} from './types';
import { EventMempool } from './event-mempool';

export interface CheckpointManagerConfig {
  nodeId: string;
  isOperator: boolean;
  checkpointInterval: number;      // ms between checkpoints (default 30s)
  minEventsForCheckpoint: number;  // minimum events to trigger checkpoint
  maxEventsPerCheckpoint: number;  // maximum events in one checkpoint
  voteTimeout: number;             // ms to wait for votes
  leaderTimeout: number;           // ms to wait for leader proposal
}

export interface OperatorInfo {
  operatorId: string;
  status: 'active' | 'inactive';
  publicKey: string;
}

export class CheckpointManager {
  private config: CheckpointManagerConfig;
  private mempool: EventMempool;
  private checkpoints: FinalizedCheckpoint[] = [];
  private pendingProposal: CheckpointProposal | null = null;
  private votes: Map<string, CheckpointVote> = new Map();
  private operators: OperatorInfo[] = [];
  private checkpointTimer: NodeJS.Timeout | null = null;
  private voteTimer: NodeJS.Timeout | null = null;

  // Callbacks for network communication
  private onBroadcastProposal: ((proposal: CheckpointProposal) => void) | null = null;
  private onBroadcastVote: ((vote: CheckpointVote) => void) | null = null;
  private onCheckpointFinalized: ((checkpoint: FinalizedCheckpoint) => void) | null = null;
  private signMessage: ((message: string) => string) | null = null;

  constructor(config: CheckpointManagerConfig, mempool: EventMempool) {
    this.config = {
      ...config,
      checkpointInterval: config.checkpointInterval ?? 30000,
      minEventsForCheckpoint: config.minEventsForCheckpoint ?? 1,
      maxEventsPerCheckpoint: config.maxEventsPerCheckpoint ?? 1000,
      voteTimeout: config.voteTimeout ?? 10000,
      leaderTimeout: config.leaderTimeout ?? 15000,
    };
    this.mempool = mempool;
  }

  /**
   * Set callback handlers
   */
  setCallbacks(callbacks: {
    onBroadcastProposal?: (proposal: CheckpointProposal) => void;
    onBroadcastVote?: (vote: CheckpointVote) => void;
    onCheckpointFinalized?: (checkpoint: FinalizedCheckpoint) => void;
    signMessage?: (message: string) => string;
  }): void {
    if (callbacks.onBroadcastProposal) this.onBroadcastProposal = callbacks.onBroadcastProposal;
    if (callbacks.onBroadcastVote) this.onBroadcastVote = callbacks.onBroadcastVote;
    if (callbacks.onCheckpointFinalized) this.onCheckpointFinalized = callbacks.onCheckpointFinalized;
    if (callbacks.signMessage) this.signMessage = callbacks.signMessage;
  }

  /**
   * Update the list of active operators
   */
  updateOperators(operators: OperatorInfo[]): void {
    this.operators = operators.filter(op => op.status === 'active');
    this.operators.sort((a, b) => a.operatorId.localeCompare(b.operatorId));
  }

  /**
   * Get the current checkpoint number
   */
  getCurrentCheckpointNumber(): number {
    return this.checkpoints.length;
  }

  /**
   * Get the last checkpoint hash
   */
  getLastCheckpointHash(): string {
    if (this.checkpoints.length === 0) return 'genesis';
    return this.checkpoints[this.checkpoints.length - 1].checkpointHash;
  }

  /**
   * Determine who should propose the next checkpoint
   */
  getCheckpointLeader(checkpointNumber: number): OperatorInfo | null {
    if (this.operators.length === 0) return null;
    const leaderIndex = checkpointNumber % this.operators.length;
    return this.operators[leaderIndex];
  }

  /**
   * Check if this node is the leader for the next checkpoint
   */
  isLeaderForNextCheckpoint(): boolean {
    if (!this.config.isOperator) return false;
    const nextCheckpoint = this.getCurrentCheckpointNumber() + 1;
    const leader = this.getCheckpointLeader(nextCheckpoint);
    return leader?.operatorId === this.config.nodeId;
  }

  /**
   * Start the checkpoint cycle
   */
  start(): void {
    this.scheduleNextCheckpoint();
  }

  /**
   * Stop the checkpoint cycle
   */
  stop(): void {
    if (this.checkpointTimer) {
      clearTimeout(this.checkpointTimer);
      this.checkpointTimer = null;
    }
    if (this.voteTimer) {
      clearTimeout(this.voteTimer);
      this.voteTimer = null;
    }
  }

  /**
   * Schedule the next checkpoint round
   */
  private scheduleNextCheckpoint(): void {
    if (this.checkpointTimer) {
      clearTimeout(this.checkpointTimer);
    }

    this.checkpointTimer = setTimeout(() => {
      this.initiateCheckpointRound();
    }, this.config.checkpointInterval);
  }

  /**
   * Initiate a checkpoint round
   */
  private async initiateCheckpointRound(): Promise<void> {
    const validEvents = this.mempool.getValidOrderedEvents();
    
    // Check if we have enough events
    if (validEvents.length < this.config.minEventsForCheckpoint) {
      this.scheduleNextCheckpoint();
      return;
    }

    // Check if we're the leader
    if (this.isLeaderForNextCheckpoint()) {
      await this.proposeCheckpoint();
    } else {
      // Wait for leader to propose
      this.waitForLeaderProposal();
    }
  }

  /**
   * Propose a checkpoint (called by leader)
   */
  async proposeCheckpoint(): Promise<CheckpointProposal | null> {
    if (!this.config.isOperator) return null;

    const validEvents = this.mempool.getValidOrderedEvents();
    if (validEvents.length === 0) return null;

    // Take up to maxEventsPerCheckpoint
    const eventsForCheckpoint = validEvents.slice(0, this.config.maxEventsPerCheckpoint);
    const eventIds = eventsForCheckpoint.map(e => e.eventId);

    const checkpointNumber = this.getCurrentCheckpointNumber() + 1;
    const previousCheckpointHash = this.getLastCheckpointHash();
    const proposedAt = Date.now();

    // Create proposal
    const proposalContent = JSON.stringify({
      checkpointNumber,
      previousCheckpointHash,
      eventIds,
      proposedBy: this.config.nodeId,
      proposedAt,
    });

    const proposalHash = createHash('sha256').update(proposalContent).digest('hex');
    const proposalSignature = this.signMessage ? this.signMessage(proposalHash) : '';

    const proposal: CheckpointProposal = {
      checkpointNumber,
      previousCheckpointHash,
      proposedBy: this.config.nodeId,
      proposedAt,
      eventIds,
      events: eventsForCheckpoint,
      proposalHash,
      proposalSignature,
    };

    this.pendingProposal = proposal;
    this.votes.clear();

    // Broadcast proposal
    if (this.onBroadcastProposal) {
      this.onBroadcastProposal(proposal);
    }

    // Vote yes on our own proposal
    await this.voteOnProposal(proposal, 'yes');

    // Start vote collection timer
    this.startVoteCollection();

    console.log(`[Checkpoint] Proposed checkpoint #${checkpointNumber} with ${eventIds.length} events`);

    return proposal;
  }

  /**
   * Wait for leader to propose
   */
  private waitForLeaderProposal(): void {
    if (this.voteTimer) {
      clearTimeout(this.voteTimer);
    }

    this.voteTimer = setTimeout(() => {
      // Leader didn't propose in time, next operator becomes leader
      console.log('[Checkpoint] Leader timeout, becoming backup leader');
      this.proposeCheckpoint();
    }, this.config.leaderTimeout);
  }

  /**
   * Handle incoming checkpoint proposal
   */
  async handleProposal(proposal: CheckpointProposal): Promise<void> {
    // Verify this is for the next checkpoint
    const expectedNumber = this.getCurrentCheckpointNumber() + 1;
    if (proposal.checkpointNumber !== expectedNumber) {
      console.log(`[Checkpoint] Ignoring proposal for wrong checkpoint number: ${proposal.checkpointNumber} (expected ${expectedNumber})`);
      return;
    }

    // Verify previous hash matches
    if (proposal.previousCheckpointHash !== this.getLastCheckpointHash()) {
      console.log('[Checkpoint] Ignoring proposal with wrong previous hash');
      return;
    }

    // Verify proposer is the expected leader
    const expectedLeader = this.getCheckpointLeader(proposal.checkpointNumber);
    if (expectedLeader?.operatorId !== proposal.proposedBy) {
      // Allow if leader timed out (we'd need to track this)
      console.log(`[Checkpoint] Proposal from ${proposal.proposedBy}, expected leader: ${expectedLeader?.operatorId}`);
    }

    // Verify we have all the events
    const missingEvents: string[] = [];
    for (const eventId of proposal.eventIds) {
      if (!this.mempool.hasEvent(eventId)) {
        missingEvents.push(eventId);
      }
    }

    if (missingEvents.length > 0) {
      console.log(`[Checkpoint] Missing ${missingEvents.length} events from proposal`);
      // Could request missing events from peers here
    }

    // Store proposal
    this.pendingProposal = proposal;

    // Cancel leader timeout if we were waiting
    if (this.voteTimer) {
      clearTimeout(this.voteTimer);
    }

    // Vote on the proposal
    if (this.config.isOperator) {
      const vote = missingEvents.length === 0 ? 'yes' : 'no';
      await this.voteOnProposal(proposal, vote, missingEvents.length > 0 ? 'Missing events' : undefined);
    }
  }

  /**
   * Vote on a checkpoint proposal
   */
  async voteOnProposal(
    proposal: CheckpointProposal,
    vote: 'yes' | 'no',
    reason?: string
  ): Promise<CheckpointVote | null> {
    if (!this.config.isOperator) return null;

    const voteContent = JSON.stringify({
      checkpointNumber: proposal.checkpointNumber,
      proposalHash: proposal.proposalHash,
      operatorId: this.config.nodeId,
      vote,
      votedAt: Date.now(),
    });

    const signature = this.signMessage ? this.signMessage(voteContent) : '';

    const checkpointVote: CheckpointVote = {
      checkpointNumber: proposal.checkpointNumber,
      proposalHash: proposal.proposalHash,
      operatorId: this.config.nodeId,
      vote,
      reason,
      signature,
      votedAt: Date.now(),
    };

    // Record our vote
    this.votes.set(this.config.nodeId, checkpointVote);

    // Broadcast vote
    if (this.onBroadcastVote) {
      this.onBroadcastVote(checkpointVote);
    }

    // Check if we have enough votes
    this.checkVoteThreshold();

    return checkpointVote;
  }

  /**
   * Handle incoming vote
   */
  handleVote(vote: CheckpointVote): void {
    // Verify vote is for current proposal
    if (!this.pendingProposal || vote.proposalHash !== this.pendingProposal.proposalHash) {
      return;
    }

    // Verify voter is an active operator
    const isOperator = this.operators.some(op => op.operatorId === vote.operatorId);
    if (!isOperator) {
      console.log(`[Checkpoint] Ignoring vote from non-operator: ${vote.operatorId}`);
      return;
    }

    // Record vote
    this.votes.set(vote.operatorId, vote);

    console.log(`[Checkpoint] Received vote from ${vote.operatorId}: ${vote.vote}`);

    // Check if we have enough votes
    this.checkVoteThreshold();
  }

  /**
   * Start vote collection timer
   */
  private startVoteCollection(): void {
    if (this.voteTimer) {
      clearTimeout(this.voteTimer);
    }

    this.voteTimer = setTimeout(() => {
      // Vote timeout - finalize with whatever votes we have
      this.checkVoteThreshold(true);
    }, this.config.voteTimeout);
  }

  /**
   * Check if we have enough votes to finalize
   */
  private checkVoteThreshold(forceFinalize: boolean = false): void {
    if (!this.pendingProposal) return;

    const totalOperators = this.operators.length;
    const requiredVotes = Math.ceil((2 / 3) * totalOperators);

    let yesVotes = 0;
    let noVotes = 0;

    for (const vote of this.votes.values()) {
      if (vote.vote === 'yes') yesVotes++;
      else noVotes++;
    }

    console.log(`[Checkpoint] Votes: ${yesVotes} yes, ${noVotes} no (need ${requiredVotes}/${totalOperators})`);

    // Check if we have 2/3 majority yes
    if (yesVotes >= requiredVotes) {
      this.finalizeCheckpoint();
      return;
    }

    // Check if it's impossible to reach threshold
    const remainingVotes = totalOperators - this.votes.size;
    if (yesVotes + remainingVotes < requiredVotes) {
      console.log('[Checkpoint] Cannot reach threshold, rejecting proposal');
      this.rejectProposal();
      return;
    }

    // Force finalize on timeout
    if (forceFinalize) {
      if (yesVotes >= requiredVotes) {
        this.finalizeCheckpoint();
      } else {
        console.log('[Checkpoint] Timeout without threshold, rejecting proposal');
        this.rejectProposal();
      }
    }
  }

  /**
   * Finalize the checkpoint
   */
  private finalizeCheckpoint(): void {
    if (!this.pendingProposal) return;

    const proposal = this.pendingProposal;
    const votesArray = Array.from(this.votes.values());

    const checkpointContent = JSON.stringify({
      checkpointNumber: proposal.checkpointNumber,
      previousCheckpointHash: proposal.previousCheckpointHash,
      eventIds: proposal.eventIds,
      finalizedAt: Date.now(),
    });

    const checkpointHash = createHash('sha256').update(checkpointContent).digest('hex');

    const finalizedCheckpoint: FinalizedCheckpoint = {
      checkpointNumber: proposal.checkpointNumber,
      previousCheckpointHash: proposal.previousCheckpointHash,
      checkpointHash,
      events: proposal.events,
      proposedBy: proposal.proposedBy,
      proposedAt: proposal.proposedAt,
      votes: votesArray,
      finalizedAt: Date.now(),
      totalYesVotes: votesArray.filter(v => v.vote === 'yes').length,
      totalNoVotes: votesArray.filter(v => v.vote === 'no').length,
      totalEligibleVoters: this.operators.length,
    };

    // Add to checkpoints
    this.checkpoints.push(finalizedCheckpoint);

    // Remove events from mempool
    this.mempool.removeEvents(proposal.eventIds);

    // Clear pending state
    this.pendingProposal = null;
    this.votes.clear();

    // Cancel timers
    if (this.voteTimer) {
      clearTimeout(this.voteTimer);
      this.voteTimer = null;
    }

    console.log(`[Checkpoint] ✅ Finalized checkpoint #${finalizedCheckpoint.checkpointNumber} with ${proposal.eventIds.length} events`);

    // Notify callback
    if (this.onCheckpointFinalized) {
      this.onCheckpointFinalized(finalizedCheckpoint);
    }

    // Schedule next checkpoint
    this.scheduleNextCheckpoint();
  }

  /**
   * Reject the current proposal
   */
  private rejectProposal(): void {
    console.log('[Checkpoint] Proposal rejected');
    this.pendingProposal = null;
    this.votes.clear();

    if (this.voteTimer) {
      clearTimeout(this.voteTimer);
      this.voteTimer = null;
    }

    // Schedule next checkpoint attempt
    this.scheduleNextCheckpoint();
  }

  /**
   * Handle incoming finalized checkpoint (from peer)
   */
  handleFinalizedCheckpoint(checkpoint: FinalizedCheckpoint): boolean {
    // Verify checkpoint number
    const expectedNumber = this.getCurrentCheckpointNumber() + 1;
    if (checkpoint.checkpointNumber !== expectedNumber) {
      if (checkpoint.checkpointNumber <= this.getCurrentCheckpointNumber()) {
        // Already have this checkpoint
        return false;
      }
      // We're behind - need to sync
      console.log(`[Checkpoint] Behind: received #${checkpoint.checkpointNumber}, have #${this.getCurrentCheckpointNumber()}`);
      return false;
    }

    // Verify previous hash
    if (checkpoint.previousCheckpointHash !== this.getLastCheckpointHash()) {
      console.log('[Checkpoint] Fork detected - previous hash mismatch');
      return false;
    }

    // Verify vote threshold
    const requiredVotes = Math.ceil((2 / 3) * checkpoint.totalEligibleVoters);
    if (checkpoint.totalYesVotes < requiredVotes) {
      console.log('[Checkpoint] Invalid checkpoint - insufficient votes');
      return false;
    }

    // Accept checkpoint
    this.checkpoints.push(checkpoint);

    // Remove events from mempool
    const eventIds = checkpoint.events.map(e => e.eventId);
    this.mempool.removeEvents(eventIds);

    // Clear any pending proposal
    this.pendingProposal = null;
    this.votes.clear();

    console.log(`[Checkpoint] Accepted checkpoint #${checkpoint.checkpointNumber} from peer`);

    // Notify callback
    if (this.onCheckpointFinalized) {
      this.onCheckpointFinalized(checkpoint);
    }

    return true;
  }

  /**
   * Get consensus state
   */
  getState(): ConsensusState {
    const nextCheckpoint = this.getCurrentCheckpointNumber() + 1;
    const leader = this.getCheckpointLeader(nextCheckpoint);

    return {
      currentCheckpointNumber: this.getCurrentCheckpointNumber(),
      lastCheckpointHash: this.getLastCheckpointHash(),
      lastCheckpointAt: this.checkpoints.length > 0 
        ? this.checkpoints[this.checkpoints.length - 1].finalizedAt 
        : 0,
      mempoolSize: this.mempool.size,
      pendingProposal: this.pendingProposal,
      votes: this.votes,
      isLeader: this.isLeaderForNextCheckpoint(),
      currentLeaderId: leader?.operatorId || '',
      activeOperators: this.operators.map(op => op.operatorId),
    };
  }

  /**
   * Get all finalized checkpoints
   */
  getCheckpoints(): FinalizedCheckpoint[] {
    return [...this.checkpoints];
  }

  /**
   * Get checkpoint by number
   */
  getCheckpoint(number: number): FinalizedCheckpoint | undefined {
    return this.checkpoints.find(c => c.checkpointNumber === number);
  }

  /**
   * Detect and resolve forks
   */
  detectFork(remoteCheckpoints: FinalizedCheckpoint[]): ForkInfo | null {
    if (remoteCheckpoints.length === 0) return null;

    // Find divergence point
    let divergencePoint = 0;
    for (let i = 0; i < Math.min(this.checkpoints.length, remoteCheckpoints.length); i++) {
      if (this.checkpoints[i].checkpointHash !== remoteCheckpoints[i].checkpointHash) {
        divergencePoint = i;
        break;
      }
      divergencePoint = i + 1;
    }

    // No fork if chains are identical up to the shorter one
    if (divergencePoint >= Math.min(this.checkpoints.length, remoteCheckpoints.length)) {
      if (this.checkpoints.length === remoteCheckpoints.length) {
        return null; // Identical chains
      }
    }

    // Determine which chain to keep
    let resolution: 'keep_local' | 'switch_to_remote' | 'equal';
    const localLength = this.checkpoints.length;
    const remoteLength = remoteCheckpoints.length;

    if (localLength > remoteLength) {
      resolution = 'keep_local';
    } else if (remoteLength > localLength) {
      resolution = 'switch_to_remote';
    } else {
      // Same length - use hash tie-breaker at divergence point
      const localHash = this.checkpoints[divergencePoint]?.checkpointHash || '';
      const remoteHash = remoteCheckpoints[divergencePoint]?.checkpointHash || '';
      resolution = localHash < remoteHash ? 'keep_local' : 'switch_to_remote';
    }

    // Collect events to revalidate if switching
    const eventsToRevalidate: MempoolEvent[] = [];
    if (resolution === 'switch_to_remote') {
      for (let i = divergencePoint; i < this.checkpoints.length; i++) {
        eventsToRevalidate.push(...this.checkpoints[i].events);
      }
    }

    return {
      divergencePoint,
      localChainLength: localLength,
      remoteChainLength: remoteLength,
      resolution,
      eventsToRevalidate,
    };
  }

  /**
   * Switch to a different chain (after fork resolution)
   */
  switchToChain(newCheckpoints: FinalizedCheckpoint[], eventsToRevalidate: MempoolEvent[]): void {
    this.checkpoints = [...newCheckpoints];

    // Add events back to mempool for revalidation
    for (const event of eventsToRevalidate) {
      event.validationStatus = 'pending';
      this.mempool.addEvent(event);
    }

    console.log(`[Checkpoint] Switched to new chain with ${newCheckpoints.length} checkpoints`);
  }

  /**
   * Export state for persistence
   */
  export(): { checkpoints: FinalizedCheckpoint[] } {
    return {
      checkpoints: this.checkpoints,
    };
  }

  /**
   * Import state from persistence
   */
  import(data: { checkpoints: FinalizedCheckpoint[] }): void {
    this.checkpoints = data.checkpoints || [];
  }
}
