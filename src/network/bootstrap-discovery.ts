/**
 * Bootstrap Discovery System
 * 
 * Multi-layer discovery system for finding network peers.
 * Designed to be unkillable - if one source fails, others take over.
 * 
 * Layers (in order of preference):
 * 1. Ledger-based discovery (most reliable, requires initial connection)
 * 2. DNS seeds (independent domains)
 * 3. Hardcoded fallbacks (updated with releases)
 * 4. Tor hidden services (censorship resistant)
 * 5. IPFS/community seeds (immutable)
 */

import * as dns from 'dns';
import { promisify } from 'util';

const resolveTxt = promisify(dns.resolveTxt);

export interface NetworkPeer {
  id: string;
  type: 'operator' | 'gateway' | 'seed';
  httpUrl?: string;
  wsUrl?: string;
  torUrl?: string;
  lastSeen?: number;
  source: 'ledger' | 'dns' | 'hardcoded' | 'tor' | 'ipfs' | 'peer';
  region?: string;
  version?: string;
}

export interface BootstrapSource {
  type: 'dns' | 'http' | 'ws' | 'tor' | 'ipfs' | 'hardcoded';
  value: string;
  priority: number;
  enabled: boolean;
}

// Hardcoded bootstrap sources - updated with each release
// These are the last resort if all other discovery methods fail
const HARDCODED_SOURCES: BootstrapSource[] = [
  // Primary operators
  { type: 'http', value: 'https://autho.pinkmahi.com', priority: 1, enabled: true },
  { type: 'http', value: 'https://autho.cartpathcleaning.com', priority: 2, enabled: true },
  { type: 'http', value: 'https://autho2.cartpathcleaning.com', priority: 3, enabled: true },
  
  // DNS seeds (multiple independent domains for resilience)
  { type: 'dns', value: 'seed.autho.network', priority: 10, enabled: true },
  { type: 'dns', value: 'seed.pinkmahi.com', priority: 11, enabled: true },
  
  // Tor hidden services (censorship resistant)
  // { type: 'tor', value: 'xxxxxxx.onion', priority: 20, enabled: false },
  
  // IPFS peer list (immutable, community maintained)
  // { type: 'ipfs', value: 'QmXXXX', priority: 30, enabled: false },
];

// Community-maintained seeds file URL
const COMMUNITY_SEEDS_URL = 'https://raw.githubusercontent.com/Pink-Mahi/autho_node/main/seeds.txt';

export class BootstrapDiscovery {
  private sources: BootstrapSource[];
  private discoveredPeers: Map<string, NetworkPeer> = new Map();
  private lastDiscovery: number = 0;
  private discoveryInProgress: boolean = false;

  constructor(additionalSources: BootstrapSource[] = []) {
    this.sources = [...HARDCODED_SOURCES, ...additionalSources]
      .filter(s => s.enabled)
      .sort((a, b) => a.priority - b.priority);
  }

  /**
   * Discover network peers from all available sources
   */
  async discoverPeers(forceRefresh: boolean = false): Promise<NetworkPeer[]> {
    const now = Date.now();
    const cacheMs = 5 * 60 * 1000; // 5 minute cache

    if (!forceRefresh && this.discoveredPeers.size > 0 && (now - this.lastDiscovery) < cacheMs) {
      return Array.from(this.discoveredPeers.values());
    }

    if (this.discoveryInProgress) {
      return Array.from(this.discoveredPeers.values());
    }

    this.discoveryInProgress = true;
    console.log('[Bootstrap] Starting peer discovery...');

    try {
      // Try each source in priority order
      for (const source of this.sources) {
        try {
          const peers = await this.discoverFromSource(source);
          for (const peer of peers) {
            this.discoveredPeers.set(peer.id, peer);
          }
          
          if (peers.length > 0) {
            console.log(`[Bootstrap] Discovered ${peers.length} peers from ${source.type}:${source.value}`);
          }
        } catch (error: any) {
          console.log(`[Bootstrap] Failed to discover from ${source.type}:${source.value}: ${error.message}`);
        }
      }

      // Try community seeds
      try {
        const communityPeers = await this.discoverFromCommunitySeeds();
        for (const peer of communityPeers) {
          this.discoveredPeers.set(peer.id, peer);
        }
      } catch (error: any) {
        console.log(`[Bootstrap] Failed to load community seeds: ${error.message}`);
      }

      this.lastDiscovery = now;
      console.log(`[Bootstrap] Total discovered peers: ${this.discoveredPeers.size}`);
      
    } finally {
      this.discoveryInProgress = false;
    }

    return Array.from(this.discoveredPeers.values());
  }

  /**
   * Discover peers from a specific source
   */
  private async discoverFromSource(source: BootstrapSource): Promise<NetworkPeer[]> {
    switch (source.type) {
      case 'dns':
        return this.discoverFromDns(source.value);
      case 'http':
        return this.discoverFromHttp(source.value);
      case 'ws':
        return this.discoverFromWs(source.value);
      case 'tor':
        return this.discoverFromTor(source.value);
      case 'ipfs':
        return this.discoverFromIpfs(source.value);
      case 'hardcoded':
        return [{
          id: `hardcoded-${source.value}`,
          type: 'operator',
          httpUrl: source.value,
          wsUrl: source.value.replace('https://', 'wss://').replace('http://', 'ws://'),
          source: 'hardcoded',
          lastSeen: Date.now(),
        }];
      default:
        return [];
    }
  }

  /**
   * Discover peers from DNS TXT records
   * DNS records format: "autho-peer=wss://example.com,https://example.com,operator"
   */
  private async discoverFromDns(domain: string): Promise<NetworkPeer[]> {
    const peers: NetworkPeer[] = [];
    
    try {
      const records = await resolveTxt(domain);
      
      for (const record of records) {
        const txt = record.join('');
        if (txt.startsWith('autho-peer=')) {
          const parts = txt.substring(11).split(',');
          if (parts.length >= 2) {
            peers.push({
              id: `dns-${domain}-${parts[0]}`,
              type: (parts[2] as 'operator' | 'gateway') || 'operator',
              wsUrl: parts[0],
              httpUrl: parts[1],
              source: 'dns',
              lastSeen: Date.now(),
            });
          }
        }
      }
    } catch (error) {
      // DNS resolution failed - this is expected if domain doesn't exist
    }

    return peers;
  }

  /**
   * Discover peers from HTTP endpoint
   */
  private async discoverFromHttp(url: string): Promise<NetworkPeer[]> {
    const peers: NetworkPeer[] = [];
    
    try {
      // First, add this URL as a peer itself
      peers.push({
        id: `http-${url}`,
        type: 'operator',
        httpUrl: url,
        wsUrl: url.replace('https://', 'wss://').replace('http://', 'ws://'),
        source: 'hardcoded',
        lastSeen: Date.now(),
      });

      // Then try to get the operator list from this peer
      const response = await fetch(`${url}/api/network/operators`, {
        signal: AbortSignal.timeout(10000),
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.success && Array.isArray(data.operators)) {
          for (const op of data.operators) {
            if (op.wsUrl || op.operatorUrl) {
              peers.push({
                id: op.operatorId || `op-${op.wsUrl}`,
                type: 'operator',
                httpUrl: op.operatorUrl,
                wsUrl: op.wsUrl,
                source: 'peer',
                lastSeen: Date.now(),
              });
            }
          }
        }
      }

      // Also try to get gateways
      const gwResponse = await fetch(`${url}/api/network/gateways`, {
        signal: AbortSignal.timeout(10000),
      });
      
      if (gwResponse.ok) {
        const gwData = await gwResponse.json();
        if (gwData.success && Array.isArray(gwData.gateways)) {
          for (const gw of gwData.gateways) {
            if (gw.wsUrl || gw.httpUrl) {
              peers.push({
                id: gw.gatewayId || `gw-${gw.wsUrl}`,
                type: 'gateway',
                httpUrl: gw.httpUrl,
                wsUrl: gw.wsUrl,
                source: 'peer',
                lastSeen: Date.now(),
              });
            }
          }
        }
      }
    } catch (error) {
      // HTTP request failed
    }

    return peers;
  }

  /**
   * Discover from WebSocket (connect and request peer list)
   */
  private async discoverFromWs(url: string): Promise<NetworkPeer[]> {
    // WebSocket discovery would connect and request peer_list message
    // For now, convert to HTTP and use that
    const httpUrl = url.replace('wss://', 'https://').replace('ws://', 'http://');
    return this.discoverFromHttp(httpUrl);
  }

  /**
   * Discover from Tor hidden service
   */
  private async discoverFromTor(onionUrl: string): Promise<NetworkPeer[]> {
    // Tor discovery requires a SOCKS proxy
    // Return the onion URL as a peer for nodes that support Tor
    return [{
      id: `tor-${onionUrl}`,
      type: 'operator',
      torUrl: `ws://${onionUrl}`,
      source: 'tor',
      lastSeen: Date.now(),
    }];
  }

  /**
   * Discover from IPFS CID (fetch peer list from IPFS)
   */
  private async discoverFromIpfs(cid: string): Promise<NetworkPeer[]> {
    const peers: NetworkPeer[] = [];
    
    // Try multiple IPFS gateways
    const gateways = [
      `https://ipfs.io/ipfs/${cid}`,
      `https://cloudflare-ipfs.com/ipfs/${cid}`,
      `https://gateway.pinata.cloud/ipfs/${cid}`,
    ];

    for (const gateway of gateways) {
      try {
        const response = await fetch(gateway, {
          signal: AbortSignal.timeout(15000),
        });
        
        if (response.ok) {
          const text = await response.text();
          const lines = text.split('\n').filter(l => l.trim() && !l.startsWith('#'));
          
          for (const line of lines) {
            const parts = line.split(',');
            if (parts.length >= 2) {
              peers.push({
                id: `ipfs-${parts[0]}`,
                type: (parts[2] as 'operator' | 'gateway') || 'operator',
                wsUrl: parts[0],
                httpUrl: parts[1],
                source: 'ipfs',
                lastSeen: Date.now(),
              });
            }
          }
          break; // Got data from one gateway, stop
        }
      } catch (error) {
        // Try next gateway
      }
    }

    return peers;
  }

  /**
   * Discover from community-maintained seeds file on GitHub
   */
  private async discoverFromCommunitySeeds(): Promise<NetworkPeer[]> {
    const peers: NetworkPeer[] = [];
    
    try {
      const response = await fetch(COMMUNITY_SEEDS_URL, {
        signal: AbortSignal.timeout(10000),
      });
      
      if (response.ok) {
        const text = await response.text();
        const lines = text.split('\n').filter(l => l.trim() && !l.startsWith('#'));
        
        for (const line of lines) {
          const parts = line.split(',').map(p => p.trim());
          if (parts.length >= 1 && parts[0]) {
            const url = parts[0];
            const type = (parts[1] as 'operator' | 'gateway') || 'operator';
            
            peers.push({
              id: `community-${url}`,
              type,
              httpUrl: url.startsWith('ws') ? url.replace('wss://', 'https://').replace('ws://', 'http://') : url,
              wsUrl: url.startsWith('http') ? url.replace('https://', 'wss://').replace('http://', 'ws://') : url,
              source: 'peer',
              lastSeen: Date.now(),
            });
          }
        }
      }
    } catch (error) {
      // Community seeds fetch failed
    }

    return peers;
  }

  /**
   * Add peers discovered from the ledger
   */
  addLedgerPeers(peers: NetworkPeer[]): void {
    for (const peer of peers) {
      peer.source = 'ledger';
      this.discoveredPeers.set(peer.id, peer);
    }
  }

  /**
   * Get all discovered operators
   */
  getOperators(): NetworkPeer[] {
    return Array.from(this.discoveredPeers.values()).filter(p => p.type === 'operator');
  }

  /**
   * Get all discovered gateways
   */
  getGateways(): NetworkPeer[] {
    return Array.from(this.discoveredPeers.values()).filter(p => p.type === 'gateway');
  }

  /**
   * Get a random subset of peers for connection
   */
  getRandomPeers(count: number, type?: 'operator' | 'gateway'): NetworkPeer[] {
    let peers = Array.from(this.discoveredPeers.values());
    if (type) {
      peers = peers.filter(p => p.type === type);
    }
    
    // Shuffle and take first N
    for (let i = peers.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [peers[i], peers[j]] = [peers[j], peers[i]];
    }
    
    return peers.slice(0, count);
  }

  /**
   * Mark a peer as seen (update lastSeen)
   */
  markPeerSeen(peerId: string): void {
    const peer = this.discoveredPeers.get(peerId);
    if (peer) {
      peer.lastSeen = Date.now();
    }
  }

  /**
   * Remove stale peers (not seen in 24 hours)
   */
  pruneStale(): void {
    const maxAge = 24 * 60 * 60 * 1000;
    const now = Date.now();
    
    for (const [id, peer] of this.discoveredPeers) {
      // Don't prune hardcoded or ledger peers
      if (peer.source === 'hardcoded' || peer.source === 'ledger') continue;
      
      if (peer.lastSeen && (now - peer.lastSeen) > maxAge) {
        this.discoveredPeers.delete(id);
      }
    }
  }

  /**
   * Export current peer list (for sharing with other nodes)
   */
  exportPeerList(): string {
    const lines: string[] = [
      '# Autho Network Peers',
      `# Generated: ${new Date().toISOString()}`,
      '# Format: wsUrl,httpUrl,type',
      '',
    ];
    
    for (const peer of this.discoveredPeers.values()) {
      if (peer.wsUrl && peer.httpUrl) {
        lines.push(`${peer.wsUrl},${peer.httpUrl},${peer.type}`);
      }
    }
    
    return lines.join('\n');
  }
}

export default BootstrapDiscovery;
