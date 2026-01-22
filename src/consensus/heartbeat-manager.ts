import { EventEmitter } from 'events';
import { StateVerifier, LedgerState, StateHash, ConsensusResult } from './state-verifier';

/**
 * Heartbeat Manager - Periodic state verification and consensus checking
 * Runs every 60 seconds to verify all nodes have the same ledger state
 */

export interface HeartbeatConfig {
  intervalMs: number; // Default: 60000 (60 seconds)
  consensusThreshold: number; // Default: 0.6667 (66.67%)
  maxDivergenceTime: number; // Default: 300000 (5 minutes)
}

export interface VerificationMessage {
  type: 'state_verification';
  stateHash: string;
  sequenceNumber: number;
  timestamp: number;
  nodeId: string;
}

export interface VerificationResponse {
  type: 'verification_response';
  stateHash: string;
  sequenceNumber: number;
  timestamp: number;
  nodeId: string;
  inConsensus: boolean;
}

export class HeartbeatManager extends EventEmitter {
  private config: HeartbeatConfig;
  private intervalTimer?: NodeJS.Timeout;
  private lastVerification: number = 0;
  private receivedHashes: Map<string, StateHash> = new Map();
  private lastConsensusResult?: ConsensusResult;

  constructor(config?: Partial<HeartbeatConfig>) {
    super();
    this.config = {
      intervalMs: config?.intervalMs || 60000,
      consensusThreshold: config?.consensusThreshold || 0.6667,
      maxDivergenceTime: config?.maxDivergenceTime || 300000
    };
  }

  /**
   * Start periodic heartbeat verification
   */
  start(
    nodeId: string,
    getState: () => Promise<LedgerState>,
    sendToAllPeers: (message: VerificationMessage) => void
  ): void {
    if (this.intervalTimer) {
      return; // Already running
    }

    console.log(`[Heartbeat] Starting verification every ${this.config.intervalMs}ms`);

    this.intervalTimer = setInterval(async () => {
      try {
        await this.performVerification(nodeId, getState, sendToAllPeers);
      } catch (error) {
        console.error('[Heartbeat] Verification error:', error);
        this.emit('verification_error', error);
      }
    }, this.config.intervalMs);

    // Perform initial verification immediately
    this.performVerification(nodeId, getState, sendToAllPeers).catch(err => {
      console.error('[Heartbeat] Initial verification error:', err);
    });
  }

  /**
   * Stop heartbeat verification
   */
  stop(): void {
    if (this.intervalTimer) {
      clearInterval(this.intervalTimer);
      this.intervalTimer = undefined;
      console.log('[Heartbeat] Stopped verification');
    }
  }

  /**
   * Perform a single verification cycle
   */
  private async performVerification(
    nodeId: string,
    getState: () => Promise<LedgerState>,
    sendToAllPeers: (message: VerificationMessage) => void
  ): Promise<void> {
    const now = Date.now();
    
    // Get current state
    const state = await getState();
    const stateHash = StateVerifier.computeStateHash(state);

    // Clear old hashes (keep only recent ones)
    this.cleanupOldHashes(now);

    // Add our own hash
    this.receivedHashes.set(nodeId, {
      stateHash,
      sequenceNumber: state.sequenceNumber,
      timestamp: now,
      nodeId
    });

    // Send verification message to all peers
    const message: VerificationMessage = {
      type: 'state_verification',
      stateHash,
      sequenceNumber: state.sequenceNumber,
      timestamp: now,
      nodeId
    };

    sendToAllPeers(message);

    // Check consensus with received hashes
    const hashes = Array.from(this.receivedHashes.values());
    const consensusResult = StateVerifier.verifyConsensus(hashes);

    this.lastConsensusResult = consensusResult;
    this.lastVerification = now;

    // Emit events based on consensus
    if (consensusResult.isConsensus) {
      this.emit('consensus_achieved', consensusResult);
      
      // Check if we're in consensus
      const inConsensus = StateVerifier.isNodeInConsensus(stateHash, consensusResult);
      if (!inConsensus) {
        this.emit('out_of_consensus', {
          myHash: stateHash,
          majorityHash: consensusResult.majorityHash,
          sequenceNumber: state.sequenceNumber
        });
      }
    } else {
      this.emit('consensus_failed', consensusResult);
      
      // Check for Byzantine fault
      if (StateVerifier.hasByzantineFault(consensusResult)) {
        this.emit('byzantine_fault', consensusResult);
      }
    }

    console.log(`[Heartbeat] Verification complete - Consensus: ${consensusResult.isConsensus} (${consensusResult.agreementPercentage.toFixed(1)}% agreement)`);
  }

  /**
   * Handle incoming verification message from peer
   */
  handleVerificationMessage(message: VerificationMessage): VerificationResponse | null {
    const now = Date.now();

    // Store peer's hash
    this.receivedHashes.set(message.nodeId, {
      stateHash: message.stateHash,
      sequenceNumber: message.sequenceNumber,
      timestamp: message.timestamp,
      nodeId: message.nodeId
    });

    // Check if we have a recent consensus result
    if (!this.lastConsensusResult) {
      return null;
    }

    // Check if peer is in consensus
    const inConsensus = StateVerifier.isNodeInConsensus(
      message.stateHash,
      this.lastConsensusResult
    );

    return {
      type: 'verification_response',
      stateHash: message.stateHash,
      sequenceNumber: message.sequenceNumber,
      timestamp: now,
      nodeId: message.nodeId,
      inConsensus
    };
  }

  /**
   * Get current consensus status
   */
  getConsensusStatus(): ConsensusResult | null {
    return this.lastConsensusResult || null;
  }

  /**
   * Get time since last verification
   */
  getTimeSinceLastVerification(): number {
    return Date.now() - this.lastVerification;
  }

  /**
   * Clean up old hashes (older than maxDivergenceTime)
   */
  private cleanupOldHashes(now: number): void {
    for (const [nodeId, hash] of this.receivedHashes.entries()) {
      if (now - hash.timestamp > this.config.maxDivergenceTime) {
        this.receivedHashes.delete(nodeId);
      }
    }
  }
}
