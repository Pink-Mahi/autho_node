/**
 * Operator Peer Discovery and Connection Management
 * 
 * Enables operators to discover and connect to other operator peers for:
 * - 250-year resilience (operators sync from each other when main is down)
 * - Peer-to-peer consensus verification
 * - Distributed event propagation
 * 
 * DECENTRALIZATION: Any operator can be used as a seed to bootstrap new operators.
 * The network does not depend on any single "main" node - if autho.pinkmahi.com
 * goes offline, new operators can connect to autho.steveschickens.com or any
 * other active operator to join the network.
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
  /** Primary seed URL (HTTP) - can be ANY active operator */
  seedHttpUrl: string;
  /** Fallback seed URLs - tried if primary fails */
  fallbackSeedUrls?: string[];
  myOperatorId: string;
  discoveryIntervalMs?: number;
}

/** Legacy config for backwards compatibility */
export interface LegacyPeerDiscoveryConfig {
  mainSeedHttpUrl: string;
  myOperatorId: string;
  discoveryIntervalMs?: number;
}

export class OperatorPeerDiscovery {
  private config: PeerDiscoveryConfig;
  private onPeerDiscovered?: (peer: OperatorPeerInfo) => void;
  private onPeerRemoved?: (operatorId: string) => void;
  /** Known peer URLs discovered from the network - used as fallback seeds */
  private knownPeerUrls: Set<string> = new Set();
  /** Last successful seed URL */
  private lastSuccessfulSeed?: string;

  constructor(config: PeerDiscoveryConfig | LegacyPeerDiscoveryConfig) {
    // Support legacy config format
    const seedUrl = (config as any).seedHttpUrl || (config as any).mainSeedHttpUrl || '';
    
    this.config = {
      seedHttpUrl: seedUrl,
      fallbackSeedUrls: (config as PeerDiscoveryConfig).fallbackSeedUrls || [],
      myOperatorId: config.myOperatorId,
      discoveryIntervalMs: config.discoveryIntervalMs || 5 * 60 * 1000, // 5 minutes default
    };
  }

  /**
   * Get all seed URLs to try (primary + fallbacks + known peers)
   */
  private getAllSeedUrls(): string[] {
    const urls: string[] = [];
    
    // Add last successful seed first (if different from primary)
    if (this.lastSuccessfulSeed && this.lastSuccessfulSeed !== this.config.seedHttpUrl) {
      urls.push(this.lastSuccessfulSeed);
    }
    
    // Add primary seed
    if (this.config.seedHttpUrl) {
      urls.push(this.config.seedHttpUrl);
    }
    
    // Add configured fallbacks
    if (this.config.fallbackSeedUrls) {
      urls.push(...this.config.fallbackSeedUrls);
    }
    
    // Add known peer URLs discovered from network
    urls.push(...Array.from(this.knownPeerUrls));
    
    // Deduplicate
    return [...new Set(urls)];
  }

  /**
   * Fetch list of active operators from any available seed
   * Tries primary seed first, then fallbacks, then known peers
   */
  async discoverPeers(): Promise<OperatorPeerInfo[]> {
    const seedUrls = this.getAllSeedUrls();
    
    if (seedUrls.length === 0) {
      console.error('[PeerDiscovery] No seed URLs configured');
      return [];
    }

    for (const seedUrl of seedUrls) {
      try {
        const peers = await this.discoverPeersFromSeed(seedUrl);
        if (peers.length > 0) {
          this.lastSuccessfulSeed = seedUrl;
          
          // Add discovered peer URLs to known peers for future fallback
          for (const peer of peers) {
            if (peer.operatorUrl) {
              const httpUrl = peer.operatorUrl.startsWith('http') 
                ? peer.operatorUrl 
                : `https://${peer.operatorUrl}`;
              this.knownPeerUrls.add(httpUrl);
            }
          }
          
          return peers;
        }
      } catch (error: any) {
        console.warn(`[PeerDiscovery] Seed ${seedUrl} failed: ${error.message}`);
        // Continue to next seed
      }
    }

    console.error('[PeerDiscovery] All seeds failed');
    return [];
  }

  /**
   * Fetch operators from a specific seed URL
   */
  private async discoverPeersFromSeed(seedUrl: string): Promise<OperatorPeerInfo[]> {
    const url = `${seedUrl.replace(/\/$/, '')}/api/network/operators`;
    console.log(`[PeerDiscovery] Trying seed: ${url}`);
    
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000); // 10s timeout
    
    try {
      const response = await fetch(url, { signal: controller.signal });
      clearTimeout(timeout);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data: any = await response.json();

      if (!data || !data.success || !Array.isArray(data.operators)) {
        throw new Error('Invalid response format');
      }

      // Filter out self
      const peers = data.operators.filter((op: any) => 
        String(op.operatorId || '') !== this.config.myOperatorId
      );

      console.log(`[PeerDiscovery] ✅ Discovered ${peers.length} peer operators from ${seedUrl}`);
      return peers;
    } catch (error: any) {
      clearTimeout(timeout);
      throw error;
    }
  }

  /**
   * Add a known peer URL for fallback discovery
   */
  addKnownPeerUrl(url: string): void {
    if (url && url.startsWith('http')) {
      this.knownPeerUrls.add(url.replace(/\/$/, ''));
    }
  }

  /**
   * Get count of known peer URLs
   */
  getKnownPeerCount(): number {
    return this.knownPeerUrls.size;
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
