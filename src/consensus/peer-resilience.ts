/**
 * Peer Resilience Manager
 * 
 * Ensures 250-year network stability by enabling operators to:
 * 1. Automatically sync from peers when main node is down
 * 2. Elect a backup leader to accept new events
 * 3. Verify cross-operator consistency and auto-repair divergence
 * 4. Maintain network operation even if main node is offline for years
 * 
 * DECENTRALIZATION: The network continues operating as long as 2/3 of
 * operators are online, regardless of which specific operators they are.
 */

import { EventEmitter } from 'events';
import WebSocket from 'ws';

export interface PeerState {
  operatorId: string;
  sequenceNumber: number;
  headHash: string;
  stateHash: string;
  lastSeen: number;
  isOnline: boolean;
  latencyMs?: number;
}

export interface LeaderElectionResult {
  leaderId: string;
  leaderSequence: number;
  electedAt: number;
  voters: string[];
  isMainNode: boolean;
}

export interface ConsistencyReport {
  timestamp: number;
  totalPeers: number;
  onlinePeers: number;
  consistentPeers: number;
  divergentPeers: string[];
  majoritySequence: number;
  majorityHash: string;
  needsRepair: boolean;
}

export interface ResilienceConfig {
  /** How often to check peer health (ms) */
  healthCheckIntervalMs: number;
  /** How long before a peer is considered offline (ms) */
  peerTimeoutMs: number;
  /** How long main node must be down before electing backup leader (ms) */
  mainNodeFailoverDelayMs: number;
  /** Minimum peers needed for consensus */
  minPeersForConsensus: number;
  /** My operator ID */
  myOperatorId: string;
  /** Is this the main node? */
  isMainNode: boolean;
}

export class PeerResilienceManager extends EventEmitter {
  private config: ResilienceConfig;
  private peerStates: Map<string, PeerState> = new Map();
  private healthCheckTimer?: NodeJS.Timeout;
  private currentLeader?: LeaderElectionResult;
  private mainNodeLastSeen: number = Date.now();
  private isMainNodeOnline: boolean = true;
  private mySequenceNumber: number = 0;
  private myHeadHash: string = '';
  private myStateHash: string = '';

  constructor(config: Partial<ResilienceConfig> & { myOperatorId: string }) {
    super();
    this.config = {
      healthCheckIntervalMs: config.healthCheckIntervalMs || 30000, // 30 seconds
      peerTimeoutMs: config.peerTimeoutMs || 120000, // 2 minutes
      mainNodeFailoverDelayMs: config.mainNodeFailoverDelayMs || 300000, // 5 minutes
      minPeersForConsensus: config.minPeersForConsensus || 2,
      myOperatorId: config.myOperatorId,
      isMainNode: config.isMainNode || false,
    };
  }

  /**
   * Start the resilience manager
   */
  start(): void {
    if (this.healthCheckTimer) return;

    console.log(`[Resilience] Starting peer resilience manager`);
    console.log(`[Resilience] Health check interval: ${this.config.healthCheckIntervalMs}ms`);
    console.log(`[Resilience] Failover delay: ${this.config.mainNodeFailoverDelayMs}ms`);

    this.healthCheckTimer = setInterval(() => {
      this.performHealthCheck();
    }, this.config.healthCheckIntervalMs);

    // Initial check
    this.performHealthCheck();
  }

  /**
   * Stop the resilience manager
   */
  stop(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = undefined;
      console.log(`[Resilience] Stopped peer resilience manager`);
    }
  }

  /**
   * Update my own state (called by operator node)
   */
  updateMyState(sequenceNumber: number, headHash: string, stateHash: string): void {
    this.mySequenceNumber = sequenceNumber;
    this.myHeadHash = headHash;
    this.myStateHash = stateHash;
  }

  /**
   * Update peer state from heartbeat/verification message
   */
  updatePeerState(
    operatorId: string,
    sequenceNumber: number,
    headHash: string,
    stateHash: string,
    latencyMs?: number
  ): void {
    const existing = this.peerStates.get(operatorId);
    
    this.peerStates.set(operatorId, {
      operatorId,
      sequenceNumber,
      headHash,
      stateHash,
      lastSeen: Date.now(),
      isOnline: true,
      latencyMs: latencyMs ?? existing?.latencyMs,
    });

    // Check if this is main node
    if (this.isMainNodePeer(operatorId)) {
      this.mainNodeLastSeen = Date.now();
      if (!this.isMainNodeOnline) {
        console.log(`[Resilience] ✅ Main node is back online`);
        this.isMainNodeOnline = true;
        this.emit('main_node_online');
      }
    }
  }

  /**
   * Mark peer as offline
   */
  markPeerOffline(operatorId: string): void {
    const peer = this.peerStates.get(operatorId);
    if (peer) {
      peer.isOnline = false;
      
      if (this.isMainNodePeer(operatorId)) {
        console.log(`[Resilience] ⚠️ Main node appears offline`);
        this.isMainNodeOnline = false;
        this.emit('main_node_offline');
      }
    }
  }

  /**
   * Perform periodic health check
   */
  private performHealthCheck(): void {
    const now = Date.now();

    // Check for timed-out peers
    for (const [operatorId, peer] of this.peerStates.entries()) {
      if (peer.isOnline && now - peer.lastSeen > this.config.peerTimeoutMs) {
        console.log(`[Resilience] Peer ${operatorId} timed out (last seen ${Math.round((now - peer.lastSeen) / 1000)}s ago)`);
        this.markPeerOffline(operatorId);
      }
    }

    // Check main node status
    if (!this.config.isMainNode) {
      const mainNodeDownTime = now - this.mainNodeLastSeen;
      
      if (this.isMainNodeOnline && mainNodeDownTime > this.config.peerTimeoutMs) {
        console.log(`[Resilience] ⚠️ Main node offline for ${Math.round(mainNodeDownTime / 1000)}s`);
        this.isMainNodeOnline = false;
        this.emit('main_node_offline');
      }

      // Check if we need to elect a backup leader
      if (!this.isMainNodeOnline && mainNodeDownTime > this.config.mainNodeFailoverDelayMs) {
        if (!this.currentLeader || this.currentLeader.isMainNode) {
          this.electBackupLeader();
        }
      }
    }

    // Generate consistency report
    const report = this.generateConsistencyReport();
    
    if (report.needsRepair) {
      console.log(`[Resilience] ⚠️ Consistency issue detected - ${report.divergentPeers.length} divergent peers`);
      this.emit('consistency_issue', report);
    }

    // Emit health status
    this.emit('health_check', {
      onlinePeers: report.onlinePeers,
      totalPeers: report.totalPeers,
      isMainNodeOnline: this.isMainNodeOnline,
      currentLeader: this.currentLeader?.leaderId,
      consistencyOk: !report.needsRepair,
    });
  }

  /**
   * Generate a consistency report across all peers
   */
  generateConsistencyReport(): ConsistencyReport {
    const now = Date.now();
    const onlinePeers: PeerState[] = [];

    // Collect online peers
    for (const peer of this.peerStates.values()) {
      if (peer.isOnline) {
        onlinePeers.push(peer);
      }
    }

    // Add self
    const myState: PeerState = {
      operatorId: this.config.myOperatorId,
      sequenceNumber: this.mySequenceNumber,
      headHash: this.myHeadHash,
      stateHash: this.myStateHash,
      lastSeen: now,
      isOnline: true,
    };
    onlinePeers.push(myState);

    // Find majority sequence and hash
    const sequenceCounts = new Map<number, number>();
    const hashCounts = new Map<string, number>();

    for (const peer of onlinePeers) {
      sequenceCounts.set(peer.sequenceNumber, (sequenceCounts.get(peer.sequenceNumber) || 0) + 1);
      hashCounts.set(peer.headHash, (hashCounts.get(peer.headHash) || 0) + 1);
    }

    // Find majority
    let majoritySequence = 0;
    let majoritySequenceCount = 0;
    for (const [seq, count] of sequenceCounts.entries()) {
      if (count > majoritySequenceCount) {
        majoritySequence = seq;
        majoritySequenceCount = count;
      }
    }

    let majorityHash = '';
    let majorityHashCount = 0;
    for (const [hash, count] of hashCounts.entries()) {
      if (count > majorityHashCount) {
        majorityHash = hash;
        majorityHashCount = count;
      }
    }

    // Find divergent peers
    const divergentPeers: string[] = [];
    for (const peer of onlinePeers) {
      if (peer.sequenceNumber !== majoritySequence || peer.headHash !== majorityHash) {
        divergentPeers.push(peer.operatorId);
      }
    }

    // Check if we need repair (more than 1/3 divergent)
    const needsRepair = divergentPeers.length > 0 && 
      divergentPeers.length >= Math.ceil(onlinePeers.length / 3);

    return {
      timestamp: now,
      totalPeers: this.peerStates.size + 1, // +1 for self
      onlinePeers: onlinePeers.length,
      consistentPeers: onlinePeers.length - divergentPeers.length,
      divergentPeers,
      majoritySequence,
      majorityHash,
      needsRepair,
    };
  }

  /**
   * Elect a backup leader when main node is down
   * Uses deterministic election based on operator ID (lowest ID wins)
   */
  private electBackupLeader(): void {
    const onlinePeers = this.getOnlinePeers();
    
    if (onlinePeers.length < this.config.minPeersForConsensus) {
      console.log(`[Resilience] Cannot elect leader - only ${onlinePeers.length} peers online (need ${this.config.minPeersForConsensus})`);
      return;
    }

    // Find peer with highest sequence number
    // Tie-breaker: lowest operator ID (deterministic)
    let leader: PeerState | null = null;
    
    for (const peer of onlinePeers) {
      if (!leader) {
        leader = peer;
        continue;
      }
      
      if (peer.sequenceNumber > leader.sequenceNumber) {
        leader = peer;
      } else if (peer.sequenceNumber === leader.sequenceNumber && peer.operatorId < leader.operatorId) {
        leader = peer;
      }
    }

    // Include self in election
    if (this.mySequenceNumber > (leader?.sequenceNumber || 0)) {
      leader = {
        operatorId: this.config.myOperatorId,
        sequenceNumber: this.mySequenceNumber,
        headHash: this.myHeadHash,
        stateHash: this.myStateHash,
        lastSeen: Date.now(),
        isOnline: true,
      };
    } else if (this.mySequenceNumber === leader?.sequenceNumber && this.config.myOperatorId < leader.operatorId) {
      leader = {
        operatorId: this.config.myOperatorId,
        sequenceNumber: this.mySequenceNumber,
        headHash: this.myHeadHash,
        stateHash: this.myStateHash,
        lastSeen: Date.now(),
        isOnline: true,
      };
    }

    if (!leader) {
      console.log(`[Resilience] No suitable leader found`);
      return;
    }

    this.currentLeader = {
      leaderId: leader.operatorId,
      leaderSequence: leader.sequenceNumber,
      electedAt: Date.now(),
      voters: onlinePeers.map(p => p.operatorId),
      isMainNode: false,
    };

    console.log(`[Resilience] 🗳️ Elected backup leader: ${leader.operatorId} (seq: ${leader.sequenceNumber})`);
    this.emit('leader_elected', this.currentLeader);
  }

  /**
   * Check if I am the current leader
   */
  amILeader(): boolean {
    if (this.config.isMainNode && this.isMainNodeOnline) {
      return true;
    }
    return this.currentLeader?.leaderId === this.config.myOperatorId;
  }

  /**
   * Get the current leader ID
   */
  getCurrentLeader(): string | null {
    if (this.isMainNodeOnline) {
      return 'main'; // Main node is always leader when online
    }
    return this.currentLeader?.leaderId || null;
  }

  /**
   * Get online peers sorted by sequence number (highest first)
   */
  getOnlinePeers(): PeerState[] {
    const peers: PeerState[] = [];
    for (const peer of this.peerStates.values()) {
      if (peer.isOnline) {
        peers.push(peer);
      }
    }
    return peers.sort((a, b) => b.sequenceNumber - a.sequenceNumber);
  }

  /**
   * Get the best peer to sync from (highest sequence, lowest latency)
   */
  getBestSyncPeer(): PeerState | null {
    const onlinePeers = this.getOnlinePeers();
    
    if (onlinePeers.length === 0) {
      return null;
    }

    // Find peers with highest sequence
    const maxSeq = onlinePeers[0].sequenceNumber;
    const bestPeers = onlinePeers.filter(p => p.sequenceNumber === maxSeq);

    // Among those, pick lowest latency
    if (bestPeers.length === 1) {
      return bestPeers[0];
    }

    return bestPeers.sort((a, b) => (a.latencyMs || 9999) - (b.latencyMs || 9999))[0];
  }

  /**
   * Check if we're behind and need to sync
   */
  needsSync(): { needsSync: boolean; behindBy: number; syncFrom?: PeerState } {
    const bestPeer = this.getBestSyncPeer();
    
    if (!bestPeer) {
      return { needsSync: false, behindBy: 0 };
    }

    const behindBy = bestPeer.sequenceNumber - this.mySequenceNumber;
    
    if (behindBy > 0) {
      return { needsSync: true, behindBy, syncFrom: bestPeer };
    }

    return { needsSync: false, behindBy: 0 };
  }

  /**
   * Request sync from a specific peer
   */
  createSyncRequest(): { type: string; operatorId: string; lastSequence: number; timestamp: number } {
    return {
      type: 'sync_request',
      operatorId: this.config.myOperatorId,
      lastSequence: this.mySequenceNumber,
      timestamp: Date.now(),
    };
  }

  /**
   * Check if a peer is the main node
   */
  private isMainNodePeer(operatorId: string): boolean {
    // Main node typically has a specific ID or is the first admitted operator
    // For now, we check if operatorId contains 'main' or is the configured main
    return operatorId.toLowerCase().includes('main') || 
           operatorId === 'autho.pinkmahi.com';
  }

  /**
   * Get resilience status for API/monitoring
   */
  getStatus(): {
    isMainNodeOnline: boolean;
    mainNodeLastSeen: number;
    currentLeader: string | null;
    amILeader: boolean;
    onlinePeers: number;
    totalPeers: number;
    mySequence: number;
    highestPeerSequence: number;
    needsSync: boolean;
    consistencyOk: boolean;
  } {
    const onlinePeers = this.getOnlinePeers();
    const bestPeer = this.getBestSyncPeer();
    const report = this.generateConsistencyReport();

    return {
      isMainNodeOnline: this.isMainNodeOnline,
      mainNodeLastSeen: this.mainNodeLastSeen,
      currentLeader: this.getCurrentLeader(),
      amILeader: this.amILeader(),
      onlinePeers: onlinePeers.length,
      totalPeers: this.peerStates.size,
      mySequence: this.mySequenceNumber,
      highestPeerSequence: bestPeer?.sequenceNumber || 0,
      needsSync: this.needsSync().needsSync,
      consistencyOk: !report.needsRepair,
    };
  }
}

/**
 * Auto-repair divergent state by syncing from majority
 */
export async function autoRepairFromMajority(
  manager: PeerResilienceManager,
  requestSyncFromPeer: (peerId: string, fromSequence: number) => Promise<void>
): Promise<boolean> {
  const report = manager.generateConsistencyReport();
  
  if (!report.needsRepair) {
    return true; // No repair needed
  }

  const syncStatus = manager.needsSync();
  
  if (!syncStatus.needsSync || !syncStatus.syncFrom) {
    console.log(`[Resilience] Cannot auto-repair - no sync source available`);
    return false;
  }

  console.log(`[Resilience] 🔧 Auto-repairing from peer ${syncStatus.syncFrom.operatorId}`);
  
  try {
    await requestSyncFromPeer(syncStatus.syncFrom.operatorId, report.majoritySequence);
    return true;
  } catch (error: any) {
    console.error(`[Resilience] Auto-repair failed:`, error.message);
    return false;
  }
}
