/**
 * Operator Peer Discovery and Connection Management
 * 
 * Enables operators to discover and connect to other operator peers for:
 * - 250-year resilience (operators sync from each other when main is down)
 * - Peer-to-peer consensus verification
 * - Distributed event propagation
 */

import WebSocket from 'ws';

export interface OperatorPeerInfo {
  operatorId: string;
  operatorUrl: string;
  wsUrl: string;
  btcAddress: string;
  status: string;
  admittedAt?: number;
  lastHeartbeatAt?: number;
  lastActiveAt?: number;
}

export interface PeerDiscoveryConfig {
  mainSeedHttpUrl: string;
  myOperatorId: string;
  discoveryIntervalMs?: number;
}

export class OperatorPeerDiscovery {
  private config: PeerDiscoveryConfig;
  private onPeerDiscovered?: (peer: OperatorPeerInfo) => void;
  private onPeerRemoved?: (operatorId: string) => void;

  constructor(config: PeerDiscoveryConfig) {
    this.config = {
      ...config,
      discoveryIntervalMs: config.discoveryIntervalMs || 5 * 60 * 1000, // 5 minutes default
    };
  }

  /**
   * Fetch list of active operators from main node
   */
  async discoverPeers(): Promise<OperatorPeerInfo[]> {
    try {
      const url = `${this.config.mainSeedHttpUrl}/api/network/operators`;
      const response = await fetch(url);
      
      if (!response.ok) {
        console.error(`[PeerDiscovery] Failed to fetch operators: ${response.status}`);
        return [];
      }

      const data: any = await response.json();

      if (!data || !data.success || !Array.isArray(data.operators)) {
        console.error('[PeerDiscovery] Invalid response format');
        return [];
      }

      // Filter out self
      const peers = data.operators.filter((op: any) => 
        String(op.operatorId || '') !== this.config.myOperatorId
      );

      console.log(`[PeerDiscovery] Discovered ${peers.length} peer operators`);
      return peers;
    } catch (error: any) {
      console.error(`[PeerDiscovery] Error fetching operators: ${error.message}`);
      return [];
    }
  }

  /**
   * Set callback for when new peer is discovered
   */
  onPeerDiscoveredCallback(callback: (peer: OperatorPeerInfo) => void): void {
    this.onPeerDiscovered = callback;
  }

  /**
   * Set callback for when peer should be removed
   */
  onPeerRemovedCallback(callback: (operatorId: string) => void): void {
    this.onPeerRemoved = callback;
  }

  /**
   * Notify about discovered peer
   */
  notifyPeerDiscovered(peer: OperatorPeerInfo): void {
    if (this.onPeerDiscovered) {
      this.onPeerDiscovered(peer);
    }
  }

  /**
   * Notify about removed peer
   */
  notifyPeerRemoved(operatorId: string): void {
    if (this.onPeerRemoved) {
      this.onPeerRemoved(operatorId);
    }
  }
}

/**
 * Connect to an operator peer via WebSocket
 */
export function connectToOperatorPeer(
  peer: OperatorPeerInfo,
  myOperatorId: string,
  onMessage: (message: any) => void,
  onClose: () => void
): WebSocket {
  console.log(`[PeerConnection] Connecting to operator peer: ${peer.operatorId} at ${peer.wsUrl}`);
  
  const ws = new WebSocket(peer.wsUrl);

  ws.on('open', () => {
    console.log(`[PeerConnection] Connected to operator peer: ${peer.operatorId}`);
    
    // Send handshake
    ws.send(JSON.stringify({
      type: 'operator_handshake',
      operatorId: myOperatorId,
      timestamp: Date.now(),
    }));
  });

  ws.on('message', (data: WebSocket.Data) => {
    try {
      const message = JSON.parse(data.toString());
      onMessage(message);
    } catch (error) {
      console.error(`[PeerConnection] Invalid message from ${peer.operatorId}:`, error);
    }
  });

  ws.on('close', () => {
    console.log(`[PeerConnection] Disconnected from operator peer: ${peer.operatorId}`);
    onClose();
  });

  ws.on('error', (error: Error) => {
    console.error(`[PeerConnection] Error with peer ${peer.operatorId}:`, error.message);
  });

  return ws;
}
