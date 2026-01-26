/**
 * Decentralized Consensus Types
 * 
 * Core types for the mempool, checkpoints, and consensus mechanism.
 */

export interface MempoolEvent {
  eventId: string;           // Unique ID for this pending event
  type: string;              // Event type (e.g., ACCOUNT_CREATED, OFFER_ACCEPTED)
  payload: Record<string, any>;
  timestamp: number;         // When the event was created
  creatorId: string;         // Node/account that created this event
  creatorSignature: string;  // Signature proving creator authorized this
  receivedAt: number;        // When this node received the event
  receivedFrom: string;      // Peer ID we received this from (or 'local')
  validationStatus: 'pending' | 'valid' | 'invalid';
  validationError?: string;
}

export interface CheckpointProposal {
  checkpointNumber: number;
  previousCheckpointHash: string;
  proposedBy: string;        // Operator ID
  proposedAt: number;
  eventIds: string[];        // Ordered list of event IDs from mempool
  events: MempoolEvent[];    // The actual events (for verification)
  proposalHash: string;      // Hash of this proposal
  proposalSignature: string; // Proposer's signature
}

export interface CheckpointVote {
  checkpointNumber: number;
  proposalHash: string;
  operatorId: string;
  vote: 'yes' | 'no';
  reason?: string;           // If no, why?
  signature: string;
  votedAt: number;
}

export interface FinalizedCheckpoint {
  checkpointNumber: number;
  previousCheckpointHash: string;
  checkpointHash: string;
  events: MempoolEvent[];
  proposedBy: string;
  proposedAt: number;
  votes: CheckpointVote[];
  finalizedAt: number;
  totalYesVotes: number;
  totalNoVotes: number;
  totalEligibleVoters: number;
}

export interface ConsensusState {
  currentCheckpointNumber: number;
  lastCheckpointHash: string;
  lastCheckpointAt: number;
  mempoolSize: number;
  pendingProposal: CheckpointProposal | null;
  votes: Map<string, CheckpointVote>;  // operatorId -> vote
  isLeader: boolean;
  currentLeaderId: string;
  activeOperators: string[];
}

export interface ValidationResult {
  valid: boolean;
  error?: string;
  conflictsWith?: string;    // Event ID that this conflicts with
}

export interface ForkInfo {
  divergencePoint: number;   // Checkpoint number where chains diverged
  localChainLength: number;
  remoteChainLength: number;
  resolution: 'keep_local' | 'switch_to_remote' | 'equal';
  eventsToRevalidate: MempoolEvent[];
}

// Message types for consensus protocol
export interface ConsensusMessage {
  type: 'mempool_event' | 'checkpoint_proposal' | 'checkpoint_vote' | 
        'checkpoint_finalized' | 'sync_checkpoints' | 'fork_detected';
  payload: any;
  senderId: string;
  timestamp: number;
  signature: string;
}

export interface MempoolEventMessage extends ConsensusMessage {
  type: 'mempool_event';
  payload: MempoolEvent;
}

export interface CheckpointProposalMessage extends ConsensusMessage {
  type: 'checkpoint_proposal';
  payload: CheckpointProposal;
}

export interface CheckpointVoteMessage extends ConsensusMessage {
  type: 'checkpoint_vote';
  payload: CheckpointVote;
}

export interface CheckpointFinalizedMessage extends ConsensusMessage {
  type: 'checkpoint_finalized';
  payload: FinalizedCheckpoint;
}
