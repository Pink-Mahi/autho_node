import { createHash } from 'crypto';

/**
 * State Verifier - Computes and verifies ledger state hashes
 * Enables PBFT-style consensus verification across the network
 */

export interface LedgerState {
  sequenceNumber: number;
  lastEventHash: string;
  itemsCount: number;
  settlementsCount: number;
  accountsCount: number;
  operatorsCount: number;
  timestamp: number;
}

export interface StateHash {
  stateHash: string;
  sequenceNumber: number;
  timestamp: number;
  nodeId: string;
}

export interface ConsensusResult {
  isConsensus: boolean;
  majorityHash: string | null;
  agreementPercentage: number;
  divergentNodes: string[];
  totalNodes: number;
}

export class StateVerifier {
  /**
   * Compute deterministic hash of ledger state
   * This hash represents the entire state of the ledger at a point in time
   */
  static computeStateHash(state: LedgerState): string {
    // Create canonical representation
    const canonical = {
      seq: state.sequenceNumber,
      hash: state.lastEventHash,
      items: state.itemsCount,
      settlements: state.settlementsCount,
      accounts: state.accountsCount,
      operators: state.operatorsCount
    };

    // Sort keys for deterministic output
    const sorted = JSON.stringify(canonical, Object.keys(canonical).sort());
    
    // Compute SHA-256 hash
    return createHash('sha256').update(sorted).digest('hex');
  }

  /**
   * Verify consensus among multiple nodes
   * Returns true if >66% of nodes agree on the same state hash
   */
  static verifyConsensus(hashes: StateHash[]): ConsensusResult {
    if (hashes.length === 0) {
      return {
        isConsensus: false,
        majorityHash: null,
        agreementPercentage: 0,
        divergentNodes: [],
        totalNodes: 0
      };
    }

    // Count occurrences of each hash
    const hashCounts = new Map<string, { count: number; nodes: string[] }>();
    
    for (const h of hashes) {
      const existing = hashCounts.get(h.stateHash);
      if (existing) {
        existing.count++;
        existing.nodes.push(h.nodeId);
      } else {
        hashCounts.set(h.stateHash, { count: 1, nodes: [h.nodeId] });
      }
    }

    // Find majority hash
    let majorityHash: string | null = null;
    let majorityCount = 0;
    let majorityNodes: string[] = [];

    for (const [hash, data] of hashCounts.entries()) {
      if (data.count > majorityCount) {
        majorityHash = hash;
        majorityCount = data.count;
        majorityNodes = data.nodes;
      }
    }

    const agreementPercentage = (majorityCount / hashes.length) * 100;
    const isConsensus = agreementPercentage >= 66.67; // Byzantine fault tolerance threshold

    // Find divergent nodes
    const divergentNodes: string[] = [];
    for (const h of hashes) {
      if (h.stateHash !== majorityHash) {
        divergentNodes.push(h.nodeId);
      }
    }

    return {
      isConsensus,
      majorityHash,
      agreementPercentage,
      divergentNodes,
      totalNodes: hashes.length
    };
  }

  /**
   * Check if a node's state matches the consensus
   */
  static isNodeInConsensus(nodeHash: string, consensusResult: ConsensusResult): boolean {
    return nodeHash === consensusResult.majorityHash;
  }

  /**
   * Determine if network has Byzantine fault (>33% disagreement)
   */
  static hasByzantineFault(consensusResult: ConsensusResult): boolean {
    return consensusResult.agreementPercentage < 66.67;
  }
}
