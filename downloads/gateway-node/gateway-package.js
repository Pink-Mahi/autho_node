#!/usr/bin/env node

/**
 * Autho Gateway Node - Self-Contained Package
 * 
 * This is a complete, working gateway node that users can download and run.
 * The seed nodes are hardcoded to prevent modification.
 */

const express = require('express');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const os = require('os');

const UI_CACHE_TTL_MS = (() => {
  const n = Number(process.env.AUTHO_UI_CACHE_TTL_MS);
  return Number.isFinite(n) && n >= 0 ? n : (5 * 60 * 1000);
})();

// HARD-CODED CONFIGURATION - USERS CANNOT MODIFY
// These are fallback seeds - the network will discover more dynamically
const CONFIG = {
  // Seed nodes - hardcoded as fallback (network discovers more dynamically)
  seedNodes: ['autho.pinkmahi.com:3000', 'autho.cartpathcleaning.com', 'autho2.cartpathcleaning.com'],

  operatorUrls: ['https://autho.pinkmahi.com', 'https://autho.cartpathcleaning.com', 'https://autho2.cartpathcleaning.com', 'http://autho.pinkmahi.com:3000'],
  
  // Community seeds URL (GitHub-hosted, anyone can PR new seeds)
  communitySeedsUrl: 'https://raw.githubusercontent.com/Pink-Mahi/autho_node/main/seeds.txt',
  
  // DNS seeds (multiple independent domains for resilience)
  dnsSeeds: ['seed.autho.network', 'seed.pinkmahi.com'],
  
  // Tor hidden services (censorship-resistant fallback)
  // These are .onion addresses that work even if DNS/IP is blocked
  torSeeds: [],
  
  // Reconnection settings
  reconnect: {
    initialDelayMs: 1000,      // Start with 1 second
    maxDelayMs: 300000,        // Max 5 minutes between attempts
    backoffMultiplier: 1.5,    // Increase delay by 50% each failure
    jitterPercent: 20,         // Add randomness to prevent thundering herd
  },
  
  // Network settings
  port: 3001,
  host: '0.0.0.0',
  
  // P2P WebSocket port (HTTP port + 1000)
  wsPort: 4001,
  
  // Cache settings
  cacheEnabled: true,
  cacheTTL: 300000, // 5 minutes
  
  // Rate limiting
  rateLimitEnabled: true,
  rateLimitWindow: 60000, // 1 minute
  rateLimitMax: 100,
  
  // Data directory
  dataDir: './gateway-data'
};

// Allow port overrides (useful if 3001 is already in use)
// Seed nodes remain hardcoded.
const EFFECTIVE_HTTP_PORT = (() => {
  const v = process.env.GATEWAY_PORT || process.env.AUTHO_GATEWAY_PORT;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : CONFIG.port;
})();

const EFFECTIVE_WS_PORT = (() => {
  const v = process.env.GATEWAY_WS_PORT || process.env.AUTHO_GATEWAY_WS_PORT;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : (EFFECTIVE_HTTP_PORT + 1000);
})();

class GatewayNode {
  constructor() {
    this.app = express();
    this.wsServer = null;
    this.peers = new Map();
    this.cache = new Map();
    this.rateLimitMap = new Map();
    this.registryData = {};
    this.isConnectedToSeed = false;
    this.seedWs = null;
    this.connectedSeed = null;
    this.operatorUrls = this.getOperatorUrls();
    this.uiCacheDir = path.join(CONFIG.dataDir, 'ui-cache');
    this.operatorHeadCache = new Map();
    this.quorumHeadCache = null;
    this.operatorConnections = new Map(); // Map of operatorId -> WebSocket
    this.discoveredOperators = []; // List of operators from /api/network/operators
    this.lastOperatorDiscovery = 0;
    
    // Communications ledger storage (ephemeral messages backup)
    this.ephemeralEvents = new Map(); // eventId -> event
    this.ephemeralContactsByUser = new Map(); // userId -> Set of contactIds
    
    // Useful work tracking - gateways contribute to network security
    this.operatorHealth = new Map(); // operatorId -> health info
    this.verificationResults = []; // Recent verification results
    this.usefulWorkStats = {
      consistencyChecks: 0,
      consistencyPassed: 0,
      consistencyFailed: 0,
      healthChecks: 0,
      operatorsOnline: 0,
      operatorsOffline: 0,
      lastWorkAt: 0,
    };
    
    // Gateway-to-gateway mesh
    this.gatewayId = this.generateGatewayId();
    this.isPublicGateway = this.checkIfPublicGateway();
    this.publicHttpUrl = process.env.GATEWAY_PUBLIC_URL || process.env.AUTHO_GATEWAY_PUBLIC_URL || null;
    this.discoveredGateways = []; // List of other public gateways
    this.gatewayPeerConnections = new Map(); // gatewayId -> WebSocket connection
    this.lastGatewayDiscovery = 0;
    
    // UI bundle caching for public gateway mode
    this.uiBundleVersion = null;
    this.uiBundleSource = null;
    
    // Seed health tracking - prefer healthy seeds over failing ones
    this.seedHealth = new Map(); // url -> { lastSuccess, lastFailure, failCount, latencyMs }
    
    // Reconnection state with exponential backoff
    this.reconnectAttempts = 0;
    this.reconnectTimer = null;
    this.currentReconnectDelay = CONFIG.reconnect.initialDelayMs;
    
    // Gossip state - share peer info with other nodes
    this.lastGossipAt = 0;
    this.gossipInterval = 60000; // Share peers every minute
    
    // Public access state (for home users behind NAT)
    this.publicAccessEnabled = false;
    this.publicAccessUrl = null;
    this.publicAccessMethod = null; // 'upnp', 'tunnel', 'manual'
    this.upnpClient = null;
    this.tunnelInstance = null;
    this.externalIp = null;
    
    // Traffic/bandwidth monitoring
    this.trafficStats = {
      startTime: Date.now(),
      requestsServed: 0,
      bytesServed: 0,
      bytesReceived: 0,
      apiRequests: 0,
      wsMessages: 0,
      uniqueClients: new Set(),
      peakConcurrent: 0,
      currentConcurrent: 0,
      requestsByEndpoint: {},
      hourlyStats: [], // Rolling 24-hour stats
    };
    
    // Peer reputation tracking
    this.peerReputation = new Map(); // peerId -> { score, successCount, failCount, lastSeen }
    
    // Rate limit tracking per client
    this.clientRateLimits = new Map(); // ip -> { requests: [], blocked: false, blockedUntil: null }
    
    // Connection events log (circular buffer)
    this.connectionEvents = [];
    this.maxConnectionEvents = 100;
    
    // Startup diagnostics
    this.diagnostics = {
      startupTime: null,
      checks: {},
      warnings: [],
      errors: [],
    };
    
    this.setupMiddleware();
    this.setupRoutes();
  }

  generateGatewayId() {
    // Generate a persistent gateway ID based on data directory
    const idFile = path.join(CONFIG.dataDir, 'gateway-id.txt');
    try {
      if (fs.existsSync(idFile)) {
        return fs.readFileSync(idFile, 'utf8').trim();
      }
    } catch {}
    
    // Generate new ID
    const id = `gw-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 8)}`;
    try {
      if (!fs.existsSync(CONFIG.dataDir)) {
        fs.mkdirSync(CONFIG.dataDir, { recursive: true });
      }
      fs.writeFileSync(idFile, id);
    } catch {}
    return id;
  }

  checkIfPublicGateway() {
    const v = String(process.env.GATEWAY_PUBLIC || process.env.AUTHO_GATEWAY_PUBLIC || '').trim().toLowerCase();
    return v === '1' || v === 'true' || v === 'yes' || v === 'on';
  }

  /**
   * Load cached seeds from local storage - survives restarts
   */
  loadCachedSeeds() {
    const seedFile = path.join(CONFIG.dataDir, 'cached-seeds.json');
    try {
      if (fs.existsSync(seedFile)) {
        const data = JSON.parse(fs.readFileSync(seedFile, 'utf8'));
        if (Array.isArray(data.seeds) && data.seeds.length > 0) {
          console.log(`📂 Loaded ${data.seeds.length} cached seeds from previous session`);
          return data.seeds;
        }
      }
    } catch (error) {
      console.log(`⚠️ Could not load cached seeds: ${error.message}`);
    }
    return [];
  }

  /**
   * Save discovered seeds to local storage for next restart
   */
  saveCachedSeeds(seeds) {
    const seedFile = path.join(CONFIG.dataDir, 'cached-seeds.json');
    try {
      if (!fs.existsSync(CONFIG.dataDir)) {
        fs.mkdirSync(CONFIG.dataDir, { recursive: true });
      }
      fs.writeFileSync(seedFile, JSON.stringify({
        seeds: seeds,
        savedAt: Date.now(),
        version: '1.0.7',
      }, null, 2));
      console.log(`💾 Saved ${seeds.length} seeds to local cache`);
    } catch (error) {
      console.log(`⚠️ Could not save cached seeds: ${error.message}`);
    }
  }

  /**
   * Record a successful connection to a seed
   */
  recordSeedSuccess(url, latencyMs = 0) {
    const health = this.seedHealth.get(url) || { 
      lastSuccess: 0, lastFailure: 0, failCount: 0, latencyMs: 999999,
      successCount: 0, totalRequests: 0, avgLatencyMs: 0, lastBytes: 0,
    };
    health.lastSuccess = Date.now();
    health.failCount = 0;
    health.latencyMs = latencyMs;
    health.successCount = (health.successCount || 0) + 1;
    health.totalRequests = (health.totalRequests || 0) + 1;
    // Rolling average latency
    health.avgLatencyMs = health.avgLatencyMs 
      ? (health.avgLatencyMs * 0.8 + latencyMs * 0.2) 
      : latencyMs;
    this.seedHealth.set(url, health);
  }

  /**
   * Record a failed connection to a seed
   */
  recordSeedFailure(url) {
    const health = this.seedHealth.get(url) || { 
      lastSuccess: 0, lastFailure: 0, failCount: 0, latencyMs: 999999,
      successCount: 0, totalRequests: 0, avgLatencyMs: 0, lastBytes: 0,
    };
    health.lastFailure = Date.now();
    health.failCount++;
    health.totalRequests = (health.totalRequests || 0) + 1;
    this.seedHealth.set(url, health);
  }

  /**
   * Get the best available seed based on connection quality
   */
  getBestSeed() {
    const sorted = this.getSortedSeeds();
    return sorted.length > 0 ? sorted[0] : null;
  }

  /**
   * Calculate connection quality score (0-100)
   */
  getConnectionQuality(url) {
    const health = this.seedHealth.get(url);
    if (!health) return 50; // Unknown = neutral
    
    let score = 50;
    
    // Success rate bonus (up to +30)
    if (health.totalRequests > 0) {
      const successRate = (health.successCount || 0) / health.totalRequests;
      score += successRate * 30;
    }
    
    // Latency bonus (up to +20 for <100ms)
    if (health.avgLatencyMs && health.avgLatencyMs > 0) {
      const latencyScore = Math.max(0, 20 - (health.avgLatencyMs / 50));
      score += latencyScore;
    }
    
    // Recent success bonus (+10 if successful in last 5 min)
    if (health.lastSuccess && (Date.now() - health.lastSuccess) < 300000) {
      score += 10;
    }
    
    // Failure penalty (-10 per recent failure)
    score -= (health.failCount || 0) * 10;
    
    return Math.max(0, Math.min(100, score));
  }

  /**
   * Get seeds sorted by health (best first)
   */
  getSortedSeeds() {
    const now = Date.now();
    const cooldownMs = 60000; // 1 minute cooldown after failure
    
    return this.operatorUrls.slice().sort((a, b) => {
      const healthA = this.seedHealth.get(a) || { lastSuccess: 0, lastFailure: 0, failCount: 0, latencyMs: 999999 };
      const healthB = this.seedHealth.get(b) || { lastSuccess: 0, lastFailure: 0, failCount: 0, latencyMs: 999999 };
      
      // Seeds in cooldown go to end
      const aCooldown = healthA.lastFailure && (now - healthA.lastFailure) < cooldownMs * healthA.failCount;
      const bCooldown = healthB.lastFailure && (now - healthB.lastFailure) < cooldownMs * healthB.failCount;
      if (aCooldown && !bCooldown) return 1;
      if (!aCooldown && bCooldown) return -1;
      
      // Prefer recently successful seeds
      if (healthA.lastSuccess > healthB.lastSuccess) return -1;
      if (healthB.lastSuccess > healthA.lastSuccess) return 1;
      
      // Prefer lower latency
      return healthA.latencyMs - healthB.latencyMs;
    });
  }

  /**
   * Calculate next reconnect delay with exponential backoff and jitter
   */
  getNextReconnectDelay() {
    // Add jitter to prevent thundering herd
    const jitterRange = this.currentReconnectDelay * (CONFIG.reconnect.jitterPercent / 100);
    const jitter = (Math.random() * 2 - 1) * jitterRange;
    const delay = Math.min(
      this.currentReconnectDelay + jitter,
      CONFIG.reconnect.maxDelayMs
    );
    
    // Increase delay for next attempt
    this.currentReconnectDelay = Math.min(
      this.currentReconnectDelay * CONFIG.reconnect.backoffMultiplier,
      CONFIG.reconnect.maxDelayMs
    );
    
    return Math.max(delay, CONFIG.reconnect.initialDelayMs);
  }

  /**
   * Reset reconnect state after successful connection
   */
  resetReconnectState() {
    this.reconnectAttempts = 0;
    this.currentReconnectDelay = CONFIG.reconnect.initialDelayMs;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  /**
   * Schedule a reconnection attempt with exponential backoff
   */
  scheduleReconnect() {
    if (this.reconnectTimer) return; // Already scheduled
    
    this.reconnectAttempts++;
    const delay = this.getNextReconnectDelay();
    
    console.log(`🔄 Scheduling reconnect attempt ${this.reconnectAttempts} in ${Math.round(delay/1000)}s`);
    
    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      try {
        await this.connectToSeed();
      } catch (error) {
        console.log(`❌ Reconnect attempt ${this.reconnectAttempts} failed: ${error.message}`);
        this.scheduleReconnect();
      }
    }, delay);
  }

  /**
   * Gossip protocol - share known peers with connected nodes
   * This enables epidemic-style peer discovery
   */
  async gossipPeers() {
    const now = Date.now();
    if (now - this.lastGossipAt < this.gossipInterval) return;
    this.lastGossipAt = now;
    
    // Prepare peer list to share
    const myPeers = {
      operators: this.operatorUrls.slice(0, 20), // Share up to 20 operators
      gateways: this.discoveredGateways.slice(0, 20), // Share up to 20 gateways
      timestamp: now,
      fromGateway: this.gatewayId,
    };
    
    // Share with connected seed
    if (this.seedWs && this.seedWs.readyState === WebSocket.OPEN) {
      try {
        this.seedWs.send(JSON.stringify({
          type: 'gossip_peers',
          peers: myPeers,
        }));
      } catch (e) {}
    }
    
    // Share with gateway peers
    for (const [, ws] of this.gatewayPeerConnections) {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({
            type: 'gossip_peers',
            peers: myPeers,
          }));
        } catch (e) {}
      }
    }
  }

  /**
   * Handle incoming gossip from peers
   */
  handleGossipPeers(gossipData) {
    if (!gossipData || !gossipData.operators) return;
    
    let newPeersCount = 0;
    
    // Add new operators
    for (const url of gossipData.operators || []) {
      if (url && url.startsWith('http') && !this.operatorUrls.includes(url)) {
        this.operatorUrls.push(url);
        newPeersCount++;
      }
    }
    
    // Add new gateways
    for (const gw of gossipData.gateways || []) {
      const gwUrl = typeof gw === 'string' ? gw : gw?.httpUrl;
      if (gwUrl && !this.discoveredGateways.some(g => (typeof g === 'string' ? g : g?.httpUrl) === gwUrl)) {
        this.discoveredGateways.push(gw);
        newPeersCount++;
      }
    }
    
    if (newPeersCount > 0) {
      console.log(`📡 Gossip: learned ${newPeersCount} new peers from ${gossipData.fromGateway || 'unknown'}`);
      // Save new peers to cache
      this.saveCachedSeeds(this.operatorUrls);
    }
  }

  /**
   * Multi-source bootstrap discovery - tries multiple sources in order
   * This makes the network "unkillable" - if one source fails, others work
   */
  async bootstrapDiscovery() {
    console.log('🔍 Starting multi-source bootstrap discovery...');
    
    // Layer 0: Load cached seeds from previous sessions (highest priority)
    const cachedSeeds = this.loadCachedSeeds();
    const discoveredUrls = new Set([...cachedSeeds, ...CONFIG.operatorUrls]);

    // Layer 1: Try community seeds from GitHub
    try {
      const communitySeeds = await this.fetchCommunitySeeds();
      for (const seed of communitySeeds) {
        discoveredUrls.add(seed);
      }
      console.log(`✅ Discovered ${communitySeeds.length} seeds from community list`);
    } catch (error) {
      console.log(`⚠️  Community seeds unavailable: ${error.message}`);
    }

    // Layer 2: Try each known operator for more peers
    for (const operatorUrl of [...discoveredUrls]) {
      try {
        const moreOperators = await this.discoverFromOperator(operatorUrl);
        for (const op of moreOperators) {
          discoveredUrls.add(op);
        }
      } catch (error) {
        // Silently continue to next source
      }
    }

    // Layer 3: Try DNS seeds (decentralized, censorship-resistant)
    for (const dnsSeed of CONFIG.dnsSeeds) {
      try {
        const dnsUrls = await this.discoverFromDnsSeed(dnsSeed);
        for (const url of dnsUrls) {
          discoveredUrls.add(url);
        }
        if (dnsUrls.length > 0) {
          console.log(`✅ Discovered ${dnsUrls.length} seeds from DNS: ${dnsSeed}`);
        }
      } catch (error) {
        // DNS seed failed, continue
      }
    }

    // Layer 4: Try to discover from ledger (network topology events)
    try {
      const ledgerPeers = await this.discoverFromLedger();
      for (const peer of ledgerPeers) {
        discoveredUrls.add(peer);
      }
    } catch (error) {
      // Ledger discovery failed, continue with what we have
    }

    // Update operator URLs with all discovered peers
    this.operatorUrls = Array.from(discoveredUrls);
    console.log(`🌐 Total discovered operators: ${this.operatorUrls.length}`);
    
    // Save discovered seeds for next restart
    if (this.operatorUrls.length > 0) {
      this.saveCachedSeeds(this.operatorUrls);
    }
    
    return this.operatorUrls;
  }

  async fetchCommunitySeeds() {
    const seeds = [];
    try {
      const response = await fetch(CONFIG.communitySeedsUrl, {
        signal: AbortSignal.timeout(10000),
      });
      
      if (response.ok) {
        const text = await response.text();
        const lines = text.split('\n')
          .filter(l => l.trim() && !l.startsWith('#'));
        
        for (const line of lines) {
          const parts = line.split(',').map(p => p.trim());
          if (parts[0] && parts[0].startsWith('http')) {
            seeds.push(parts[0]);
          }
        }
      }
    } catch (error) {
      // Community seeds fetch failed
    }
    return seeds;
  }

  /**
   * Discover seeds from DNS TXT records (censorship-resistant)
   * DNS seeds contain TXT records like: autho-peer=https://operator.example.com
   */
  async discoverFromDnsSeed(dnsSeed) {
    const discovered = [];
    try {
      const dns = require('dns');
      const { promisify } = require('util');
      const resolveTxt = promisify(dns.resolveTxt);
      
      const records = await resolveTxt(dnsSeed);
      for (const record of records) {
        const txt = record.join('');
        // Parse autho-peer=URL format
        if (txt.startsWith('autho-peer=')) {
          const url = txt.substring('autho-peer='.length).trim();
          if (url.startsWith('http')) {
            discovered.push(url);
          }
        }
        // Also support autho-seed=URL format
        if (txt.startsWith('autho-seed=')) {
          const url = txt.substring('autho-seed='.length).trim();
          if (url.startsWith('http')) {
            discovered.push(url);
          }
        }
      }
    } catch (error) {
      // DNS lookup failed - this is normal if domain doesn't have TXT records
    }
    return discovered;
  }

  async discoverFromOperator(operatorUrl) {
    const discovered = [];
    try {
      const response = await fetch(`${operatorUrl}/api/network/operators`, {
        signal: AbortSignal.timeout(10000),
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.success && Array.isArray(data.operators)) {
          for (const op of data.operators) {
            if (op.operatorUrl) {
              discovered.push(op.operatorUrl);
            }
          }
        }
      }
    } catch (error) {
      // Discovery from this operator failed
    }
    return discovered;
  }

  async discoverFromLedger() {
    const discovered = [];
    const startTime = Date.now();
    
    // Try to get network topology from ledger state
    for (const operatorUrl of this.operatorUrls.slice(0, 3)) {
      try {
        const response = await fetch(`${operatorUrl}/api/registry/state`, {
          signal: AbortSignal.timeout(10000),
        });
        
        if (response.ok) {
          const latency = Date.now() - startTime;
          this.recordSeedSuccess(operatorUrl, latency);
          
          const data = await response.json();
          
          // Check for network topology in state (operators)
          if (data.networkTopology?.operators) {
            for (const [, op] of Object.entries(data.networkTopology.operators)) {
              if (op.httpUrl) discovered.push(op.httpUrl);
            }
          }
          
          // Also check for announced gateways
          if (data.networkTopology?.gateways) {
            for (const [, gw] of Object.entries(data.networkTopology.gateways)) {
              if (gw.httpUrl && !this.discoveredGateways.some(g => g.httpUrl === gw.httpUrl)) {
                this.discoveredGateways.push(gw);
              }
            }
          }
          
          // Check for announced seeds
          if (data.networkTopology?.seeds) {
            for (const [, seed] of Object.entries(data.networkTopology.seeds)) {
              if (seed.httpUrl) discovered.push(seed.httpUrl);
            }
          }
          
          if (discovered.length > 0) {
            console.log(`📖 Ledger topology: ${discovered.length} operators, ${this.discoveredGateways.length} gateways`);
          }
          break; // Got data from one operator
        }
      } catch (error) {
        this.recordSeedFailure(operatorUrl);
        // Continue to next operator
      }
    }
    return discovered;
  }

  /**
   * Periodically refresh seed list from ledger (adaptive based on network health)
   */
  async refreshSeedsFromLedger() {
    const healthySeeds = Array.from(this.seedHealth.values()).filter(h => h.failCount === 0).length;
    const totalSeeds = this.operatorUrls.length;
    
    // Refresh more frequently if network health is poor
    const refreshIntervalMs = healthySeeds < totalSeeds * 0.5 ? 60000 : 300000;
    
    try {
      const newPeers = await this.discoverFromLedger();
      let addedCount = 0;
      for (const peer of newPeers) {
        if (!this.operatorUrls.includes(peer)) {
          this.operatorUrls.push(peer);
          addedCount++;
        }
      }
      if (addedCount > 0) {
        console.log(`🔄 Added ${addedCount} new seeds from ledger`);
        this.saveCachedSeeds(this.operatorUrls);
      }
    } catch (error) {
      // Ledger refresh failed, will retry later
    }
    
    return refreshIntervalMs;
  }

  /**
   * Download UI files from an operator for local serving (public gateway mode)
   */
  async downloadUiBundle() {
    console.log('📦 Downloading UI bundle for public gateway mode...');
    
    for (const operatorUrl of this.getCandidateOperatorUrls()) {
      try {
        // Get manifest of available UI files
        const manifestResp = await fetch(`${operatorUrl}/api/gateway/ui-manifest`, {
          signal: AbortSignal.timeout(15000),
        });
        
        if (!manifestResp.ok) continue;
        
        const manifest = await manifestResp.json();
        if (!manifest.success || !Array.isArray(manifest.files)) continue;
        
        console.log(`📄 Found ${manifest.files.length} UI files from ${operatorUrl}`);
        
        // Download each file
        let downloaded = 0;
        for (const file of manifest.files) {
          try {
            const fileResp = await fetch(`${operatorUrl}${file.path}`, {
              signal: AbortSignal.timeout(30000),
            });
            
            if (!fileResp.ok) continue;
            
            const content = Buffer.from(await fileResp.arrayBuffer());
            const localPath = this.getUiCacheFilePath(file.path);
            const localDir = path.dirname(localPath);
            
            if (!fs.existsSync(localDir)) {
              fs.mkdirSync(localDir, { recursive: true });
            }
            
            fs.writeFileSync(localPath, content);
            downloaded++;
          } catch (fileError) {
            // Continue with other files
          }
        }
        
        console.log(`✅ Downloaded ${downloaded}/${manifest.files.length} UI files`);
        this.uiBundleVersion = manifest.version;
        this.uiBundleSource = operatorUrl;
        return; // Success
      } catch (error) {
        console.log(`⚠️ Failed to download UI from ${operatorUrl}: ${error.message}`);
      }
    }
    
    console.log('⚠️ Could not download UI bundle from any operator');
  }

  getOperatorUrls() {
    const raw = process.env.AUTHO_OPERATOR_URLS || process.env.OPERATOR_URLS;
    const list = raw
      ? raw.split(',').map(s => s.trim()).filter(Boolean)
      : CONFIG.operatorUrls;
    const normalized = list.map(u => this.normalizeOperatorUrl(u)).filter(Boolean);
    return normalized.length ? normalized : CONFIG.operatorUrls;
  }

  normalizeOperatorUrl(url) {
    try {
      const u = new URL(url);
      return u.origin;
    } catch {
      try {
        const u = new URL(`https://${url}`);
        return u.origin;
      } catch {
        return null;
      }
    }
  }

  isTorEnabled() {
    const v = String(process.env.AUTHO_TOR_MODE || '').trim().toLowerCase();
    return v === '1' || v === 'true' || v === 'yes' || v === 'on';
  }

  isOnionUrl(url) {
    const s = String(url || '').trim().toLowerCase();
    return /\.onion(\/|:|$)/i.test(s);
  }

  normalizeSeed(seed) {
    const s = String(seed || '').trim();
    if (!s) return null;

    try {
      const u = new URL(s);
      const isLocal = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
      if (u.port) return `${u.hostname}:${u.port}`;
      if (isLocal) return u.hostname;
      return u.hostname;
    } catch {
      const cleaned = s.replace(/^wss?:\/\//i, '').replace(/^https?:\/\//i, '');
      return cleaned.length ? cleaned : null;
    }
  }

  getSeedNodes() {
    const raw = process.env.GATEWAY_SEEDS || process.env.AUTHO_GATEWAY_SEEDS;
    const requested = raw ? raw.split(',').map(s => s.trim()).filter(Boolean) : [];

    const fromEnv = requested.map(s => this.normalizeSeed(s)).filter(Boolean);

    const fromConfig = (CONFIG.seedNodes || []).map(s => this.normalizeSeed(s)).filter(Boolean);
    const fromOperators = (this.operatorUrls || [])
      .map((u) => {
        try {
          return this.normalizeSeed(u);
        } catch {
          return null;
        }
      })
      .filter(Boolean);

    const out = [];
    const seen = new Set();
    for (const s of [...fromEnv, ...fromConfig, ...fromOperators]) {
      if (!s) continue;
      if (seen.has(s)) continue;
      seen.add(s);
      out.push(s);
    }

    return out.length ? out : fromConfig;
  }

  getUiCacheFilePath(requestPath) {
    const decodedPath = (() => {
      try {
        return decodeURIComponent(requestPath);
      } catch {
        return requestPath;
      }
    })();

    const normalized = decodedPath.split('?')[0].split('#')[0];
    const safe = path
      .normalize(normalized)
      .replace(/^([A-Za-z]:)?[\\/]+/, '')
      .replace(/^\.\.(\\|\/)/, '');

    const hasExtension = path.posix.basename(normalized).includes('.') || path.win32.basename(normalized).includes('.');
    const needsIndex = normalized.endsWith('/') || normalized === '';
    const logical = needsIndex ? `${safe}index.html` : safe;
    const withHtml = (!needsIndex && !hasExtension) ? `${logical}.html` : logical;

    return path.join(this.uiCacheDir, withHtml);
  }

  async solvePow(operatorUrl, resource) {
    const crypto = require('crypto');
    const challengeResp = await fetch(`${operatorUrl}/api/pow/challenge?resource=${encodeURIComponent(resource)}`);
    if (!challengeResp.ok) {
      throw new Error(`Failed to get PoW challenge: ${challengeResp.status}`);
    }
    const challenge = await challengeResp.json();
    if (!challenge.enabled) {
      return null;
    }

    const { challengeId, salt, difficulty, resource: challengeResource } = challenge;
    const leadingZeros = Math.floor(difficulty / 4);
    const target = '0'.repeat(leadingZeros);
    
    let nonce = 0;
    const startTime = Date.now();
    
    while (true) {
      const hash = crypto.createHash('sha256')
        .update(`${salt}:${challengeResource}:${nonce}`)
        .digest('hex');
      
      if (hash.startsWith(target)) {
        const elapsed = Date.now() - startTime;
        console.log(`✓ PoW solved in ${elapsed}ms (difficulty: ${difficulty}, nonce: ${nonce})`);
        return { challengeId, nonce, resource: challengeResource };
      }
      
      nonce++;
      if (nonce % 100000 === 0) {
        console.log(`  Solving PoW... ${nonce} attempts`);
      }
    }
  }

  async fetchWithPow(url, options = {}) {
    const urlObj = new URL(url);
    const operatorUrl = urlObj.origin;
    const resource = `${options.method || 'GET'}:${urlObj.pathname}`;
    
    let resp = await fetch(url, options);
    
    if (resp.status === 402) {
      const errorData = await resp.json();
      if (errorData.error === 'pow_required' || errorData.error === 'pow_invalid') {
        console.log(`⚡ PoW required for ${resource}, solving...`);
        const solution = await this.solvePow(operatorUrl, resource);
        
        if (solution) {
          const newHeaders = {
            ...(options.headers || {}),
            'x-autho-pow-challenge': solution.challengeId,
            'x-autho-pow-nonce': String(solution.nonce),
            'x-autho-pow-resource': solution.resource,
          };
          
          resp = await fetch(url, { ...options, headers: newHeaders });
        }
      }
    }
    
    return resp;
  }

  async ensureOperatorHead(operatorUrl) {
    const cached = this.operatorHeadCache.get(operatorUrl);
    if (cached && (Date.now() - cached.timestamp) < 2000) {
      return cached;
    }

    const resp = await this.fetchWithPow(`${operatorUrl}/api/registry/head`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });

    if (!resp.ok) {
      throw new Error(`Operator head fetch failed (${resp.status})`);
    }

    const data = await resp.json();
    const head = {
      lastEventHash: data?.lastEventHash || '',
      sequenceNumber: Number.isFinite(Number(data?.sequenceNumber))
        ? Number(data?.sequenceNumber)
        : (Number.isFinite(Number(data?.lastEventSequence)) ? Number(data?.lastEventSequence) : 0),
      activeOperatorCount: Number.isFinite(Number(data?.activeOperatorCount)) ? Number(data?.activeOperatorCount) : 0,
      activeOperatorIds: Array.isArray(data?.activeOperatorIds) ? data.activeOperatorIds.map((x) => String(x)).filter(Boolean) : [],
      timestamp: Date.now()
    };
    this.operatorHeadCache.set(operatorUrl, head);
    return head;
  }

  getCandidateOperatorUrls() {
    const out = [];
    const seen = new Set();

    for (const u of (this.operatorUrls || [])) {
      if (!u) continue;
      if (!this.isTorEnabled() && this.isOnionUrl(u)) continue;
      if (seen.has(u)) continue;
      seen.add(u);
      out.push(u);
    }

    for (const op of (this.discoveredOperators || [])) {
      const u = this.normalizeOperatorUrl(op?.operatorUrl || op?.url || op?.httpUrl || '');
      if (!u) continue;
      if (!this.isTorEnabled() && this.isOnionUrl(u)) continue;
      if (seen.has(u)) continue;
      seen.add(u);
      out.push(u);
    }

    return out;
  }

  computeRequiredQuorum(activeCount) {
    const n = Number(activeCount || 0);
    if (!Number.isFinite(n) || n <= 0) return 0;
    if (n === 1) return 1;
    if (n === 2) return 2;
    return Math.ceil((2 * n) / 3);
  }

  async ensureQuorumHead() {
    const cached = this.quorumHeadCache;
    if (cached && (Date.now() - cached.timestamp) < 2000) {
      return cached;
    }

    const operatorUrls = this.getCandidateOperatorUrls();
    const results = await Promise.all(operatorUrls.map(async (operatorUrl) => {
      try {
        const head = await this.ensureOperatorHead(operatorUrl);
        return { operatorUrl, head };
      } catch (e) {
        return { operatorUrl, error: e?.message || String(e) };
      }
    }));

    const groups = new Map();
    for (const r of results) {
      if (!r || r.error) continue;
      const h = r.head;
      if (!h || !h.lastEventHash) continue;
      const key = `${h.sequenceNumber}:${h.lastEventHash}`;
      if (!groups.has(key)) {
        groups.set(key, { key, head: h, members: [] });
      }
      groups.get(key).members.push({ operatorUrl: r.operatorUrl, head: h });
    }

    let best = null;
    for (const g of groups.values()) {
      if (!best || g.members.length > best.members.length) best = g;
    }

    if (!best) {
      const out = { ok: false, error: 'No operator heads available', timestamp: Date.now(), operatorUrls, failures: results.filter((r) => r && r.error) };
      this.quorumHeadCache = out;
      return out;
    }

    const reportedActiveCount = Number(best.head?.activeOperatorCount || (best.head?.activeOperatorIds ? best.head.activeOperatorIds.length : 0) || 0);
    const activeCount = reportedActiveCount > 0 ? reportedActiveCount : best.members.length;
    const required = this.computeRequiredQuorum(activeCount);
    const ok = best.members.length >= required;

    const out = {
      ok,
      timestamp: Date.now(),
      required,
      activeCount,
      reportedActiveCount,
      head: {
        lastEventHash: best.head.lastEventHash,
        sequenceNumber: best.head.sequenceNumber,
      },
      responders: best.members.map((m) => m.operatorUrl),
      operatorUrls,
    };

    this.quorumHeadCache = out;
    return out;
  }

  async assertSyncedForQuorum(operatorUrl, isWrite) {
    const quorum = await this.ensureQuorumHead();
    if (!quorum.ok) {
      const err = new Error('Gateway cannot reach 2/3 quorum of active operators');
      err.statusCode = 503;
      err.details = quorum;
      throw err;
    }

    const localHash = this.registryData?.lastEventHash || '';
    const localSeq = Number(
      this.registryData?.sequenceNumber ||
      this.registryData?.lastEventSequence ||
      this.registryData?.lastSyncedSequence ||
      0
    );

    if (!localHash || localHash !== quorum.head.lastEventHash || localSeq !== quorum.head.sequenceNumber) {
      const err = new Error('Gateway not synced to quorum head');
      err.statusCode = 409;
      err.details = {
        quorum,
        gatewayLastEventHash: localHash,
        gatewaySequenceNumber: localSeq,
      };
      throw err;
    }

    if (isWrite && operatorUrl) {
      const head = await this.ensureOperatorHead(operatorUrl);
      if (head?.lastEventHash && head.lastEventHash !== quorum.head.lastEventHash) {
        const err = new Error('Operator not on quorum head');
        err.statusCode = 409;
        err.details = {
          operatorUrl,
          operatorLastEventHash: head.lastEventHash,
          operatorSequenceNumber: head.sequenceNumber,
          quorum,
        };
        throw err;
      }
    }
  }

  async assertSyncedForWrite(operatorUrl) {
    await this.assertSyncedForQuorum(operatorUrl, true);
  }

  buildForwardHeaders(req, operatorUrl) {
    const headers = {};
    for (const [k, v] of Object.entries(req.headers || {})) {
      if (v == null) continue;
      const key = k.toLowerCase();
      if (key === 'host') continue;
      if (key === 'content-length') continue;
      headers[key] = v;
    }
    headers['x-autho-gateway'] = '1';
    headers['x-autho-operator-origin'] = operatorUrl;
    return headers;
  }

  async forwardApiRequest(operatorUrl, req) {
    const targetUrl = `${operatorUrl}${req.originalUrl}`;

    const init = {
      method: req.method,
      headers: this.buildForwardHeaders(req, operatorUrl)
    };

    const hasBody = !['GET', 'HEAD'].includes(req.method);
    if (hasBody) {
      const body = req.body;
      if (body !== undefined && body !== null && Object.keys(body).length !== 0) {
        init.body = JSON.stringify(body);
        init.headers['content-type'] = 'application/json';
      }
    }

    const resp = await this.fetchWithPow(targetUrl, init);
    const buf = Buffer.from(await resp.arrayBuffer());
    const contentType = resp.headers.get('content-type');

    return { resp, buf, contentType };
  }

  async proxyApi(req, res) {
    const isWrite = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
    const errors = [];

    const originalUrl = String(req.originalUrl || '');
    const isAuthEndpoint = originalUrl.startsWith('/api/auth/');

    if (!isAuthEndpoint) {
      try {
        await this.assertSyncedForQuorum('', isWrite);
      } catch (e) {
        const statusCode = e?.statusCode;
        res.status(statusCode || 503).json({
          error: e?.message || String(e),
          details: e?.details
        });
        return;
      }
    }

    for (const operatorUrl of this.operatorUrls) {
      try {
        if (isWrite && !isAuthEndpoint) {
          await this.assertSyncedForWrite(operatorUrl);
        }

        const { resp, buf, contentType } = await this.forwardApiRequest(operatorUrl, req);

        const ct = (contentType || '').toLowerCase();
        if (originalUrl.startsWith('/api/') && ct.includes('text/html')) {
          errors.push({ operatorUrl, status: resp.status, error: 'Unexpected HTML response for API request' });
          continue;
        }

        if (resp.status >= 500 && resp.status <= 599) {
          errors.push({ operatorUrl, status: resp.status });
          continue;
        }

        res.status(resp.status);
        if (contentType) {
          res.setHeader('content-type', contentType);
        }
        res.send(buf);
        return;
      } catch (e) {
        const statusCode = e?.statusCode;
        if (statusCode && statusCode < 500) {
          res.status(statusCode).json({
            error: e.message,
            details: e.details
          });
          return;
        }
        errors.push({ operatorUrl, error: e?.message || String(e) });
      }
    }

    res.status(502).json({
      error: 'No operator available',
      attemptedOperators: this.operatorUrls,
      failures: errors
    });
  }

  async serveUi(req, res) {
    const filePath = this.getUiCacheFilePath(req.path);
    if (fs.existsSync(filePath)) {
      try {
        if (UI_CACHE_TTL_MS === 0) {
          res.sendFile(path.resolve(filePath));
          return;
        }
        const st = fs.statSync(filePath);
        if ((Date.now() - st.mtimeMs) < UI_CACHE_TTL_MS) {
          res.sendFile(path.resolve(filePath));
          return;
        }
      } catch {
        // fall through and attempt a refresh
      }
    }

    fs.mkdirSync(path.dirname(filePath), { recursive: true });

    const errors = [];
    for (const operatorUrl of this.operatorUrls) {
      try {
        const querySuffix = req.originalUrl.slice(req.path.length);
        const candidates = [`${operatorUrl}${req.originalUrl}`];

        if (req.path && req.path !== '/' && !path.posix.basename(req.path).includes('.') && !path.win32.basename(req.path).includes('.')) {
          candidates.push(`${operatorUrl}${req.path}.html${querySuffix}`);
        }

        let lastStatus = 0;
        for (const candidate of candidates) {
          const resp = await fetch(candidate, { method: 'GET' });
          if (!resp.ok) {
            lastStatus = resp.status;
            continue;
          }

          const buf = Buffer.from(await resp.arrayBuffer());
          fs.writeFileSync(filePath, buf);
          const contentType = resp.headers.get('content-type');
          if (contentType) {
            res.setHeader('content-type', contentType);
          }
          res.send(buf);
          return;
        }

        errors.push({ operatorUrl, status: lastStatus || 404 });
        continue;
      } catch (e) {
        errors.push({ operatorUrl, error: e?.message || String(e) });
      }
    }

    res.status(502).json({
      error: 'UI not available (no operator reachable and no cached copy)',
      attemptedOperators: this.operatorUrls,
      failures: errors
    });
  }

  setupMiddleware() {
    // CORS
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
      if (req.method === 'OPTIONS') {
        res.sendStatus(200);
      } else {
        next();
      }
    });

    // JSON parsing
    this.app.use(express.json());

    // Rate limiting
    if (CONFIG.rateLimitEnabled) {
      this.app.use(this.rateLimitMiddleware.bind(this));
    }

    // Request logging
    this.app.use((req, res, next) => {
      console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - ${req.ip}`);
      next();
    });

    // Traffic monitoring middleware
    this.app.use((req, res, next) => {
      this.trafficStats.requestsServed++;
      this.trafficStats.currentConcurrent++;
      if (this.trafficStats.currentConcurrent > this.trafficStats.peakConcurrent) {
        this.trafficStats.peakConcurrent = this.trafficStats.currentConcurrent;
      }
      
      // Track unique clients
      const clientIp = req.ip || req.connection?.remoteAddress || 'unknown';
      this.trafficStats.uniqueClients.add(clientIp);
      
      // Track by endpoint
      const endpoint = req.path.split('/').slice(0, 3).join('/') || '/';
      this.trafficStats.requestsByEndpoint[endpoint] = (this.trafficStats.requestsByEndpoint[endpoint] || 0) + 1;
      
      // Track bytes received
      if (req.headers['content-length']) {
        this.trafficStats.bytesReceived += parseInt(req.headers['content-length'], 10) || 0;
      }
      
      // Track response size
      const originalSend = res.send.bind(res);
      res.send = (body) => {
        if (body) {
          const size = Buffer.isBuffer(body) ? body.length : Buffer.byteLength(body?.toString() || '');
          this.trafficStats.bytesServed += size;
        }
        this.trafficStats.currentConcurrent--;
        return originalSend(body);
      };
      
      // Track API requests
      if (req.path.startsWith('/api/')) {
        this.trafficStats.apiRequests++;
      }
      
      next();
    });
  }

  rateLimitMiddleware(req, res, next) {
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();

    let clientData = this.rateLimitMap.get(clientIp);
    if (!clientData || clientData.resetTime < now) {
      clientData = { count: 0, resetTime: now + CONFIG.rateLimitWindow };
      this.rateLimitMap.set(clientIp, clientData);
    }

    if (clientData.count >= CONFIG.rateLimitMax) {
      res.status(429).json({
        error: 'Rate limit exceeded',
        message: 'Too many requests, please try again later',
        retryAfter: Math.ceil((clientData.resetTime - now) / 1000)
      });
      return;
    }

    clientData.count++;
    next();
  }

  setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: Date.now(),
        version: '1.0.7',
        uptime: process.uptime(),
        connectedPeers: this.peers.size,
        isConnectedToSeed: this.isConnectedToSeed,
        hardcodedSeeds: CONFIG.seedNodes,
        platform: os.platform(),
        nodeVersion: process.version,
        isPublicGateway: this.isPublicGateway,
        publicHttpUrl: this.publicHttpUrl,
        uiBundleVersion: this.uiBundleVersion,
        uiBundleSource: this.uiBundleSource,
      });
    });

    // Serve cached UI files for public gateways (before API routes)
    this.app.use((req, res, next) => {
      // Skip API routes
      if (req.path.startsWith('/api/') || req.path === '/health' || req.path === '/stats') {
        return next();
      }
      
      // Only serve UI if we're a public gateway with cached files
      if (!this.isPublicGateway) {
        return next();
      }
      
      const cachedFile = this.getUiCacheFilePath(req.path);
      if (fs.existsSync(cachedFile)) {
        const ext = path.extname(cachedFile).toLowerCase();
        const mimeTypes = {
          '.html': 'text/html',
          '.css': 'text/css',
          '.js': 'application/javascript',
          '.json': 'application/json',
          '.png': 'image/png',
          '.jpg': 'image/jpeg',
          '.jpeg': 'image/jpeg',
          '.gif': 'image/gif',
          '.svg': 'image/svg+xml',
          '.ico': 'image/x-icon',
          '.woff': 'font/woff',
          '.woff2': 'font/woff2',
          '.ttf': 'font/ttf',
        };
        res.setHeader('Content-Type', mimeTypes[ext] || 'application/octet-stream');
        res.setHeader('X-Served-By', 'autho-gateway');
        return res.sendFile(path.resolve(cachedFile));
      }
      
      next();
    });

    // Network topology visualization endpoint
    this.app.get('/api/mesh/topology', (req, res) => {
      // Build network graph for visualization
      const nodes = [];
      const edges = [];
      
      // Add this gateway as center node
      nodes.push({
        id: this.gatewayId,
        type: 'gateway',
        label: 'This Gateway',
        isPublic: this.isPublicGateway,
        isSelf: true,
      });
      
      // Add connected operators
      for (const [opId, conn] of this.operatorConnections) {
        nodes.push({
          id: opId,
          type: 'operator',
          label: opId,
          url: conn.url,
          connected: true,
        });
        edges.push({
          from: this.gatewayId,
          to: opId,
          type: 'websocket',
        });
      }
      
      // Add discovered but not connected operators
      for (const url of this.operatorUrls) {
        const opId = `op-${url.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '-')}`;
        if (!this.operatorConnections.has(opId)) {
          const health = this.seedHealth.get(url);
          nodes.push({
            id: opId,
            type: 'operator',
            label: url.replace(/https?:\/\//, ''),
            url: url,
            connected: false,
            status: health ? (health.failCount === 0 ? 'healthy' : 'degraded') : 'unknown',
          });
        }
      }
      
      // Add connected gateway peers
      for (const [gwId] of this.gatewayPeerConnections) {
        nodes.push({
          id: gwId,
          type: 'gateway',
          label: gwId,
          connected: true,
        });
        edges.push({
          from: this.gatewayId,
          to: gwId,
          type: 'mesh',
        });
      }
      
      res.json({
        nodes,
        edges,
        stats: {
          totalOperators: this.operatorUrls.length,
          connectedOperators: this.operatorConnections.size,
          totalGateways: this.discoveredGateways.length,
          connectedGateways: this.gatewayPeerConnections.size,
        },
      });
    });

    // Network dashboard statistics endpoint
    this.app.get('/api/mesh/dashboard', (req, res) => {
      // Calculate network-wide statistics
      const healthyOperators = Array.from(this.seedHealth.values())
        .filter(h => h.failCount === 0).length;
      const degradedOperators = Array.from(this.seedHealth.values())
        .filter(h => h.failCount > 0 && h.failCount < 5).length;
      const offlineOperators = Array.from(this.seedHealth.values())
        .filter(h => h.failCount >= 5).length;
      
      // Average latency of healthy operators
      const latencies = Array.from(this.seedHealth.values())
        .filter(h => h.avgLatencyMs && h.avgLatencyMs < 999999)
        .map(h => h.avgLatencyMs);
      const avgLatency = latencies.length > 0 
        ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
        : 0;
      
      // Connection history for last hour (simplified)
      const uptime = process.uptime();
      const connectionUptime = this.isConnectedToSeed ? uptime : 0;
      
      res.json({
        gatewayId: this.gatewayId,
        uptime: Math.round(uptime),
        networkStatus: this.isConnectedToSeed ? 'connected' : 'disconnected',
        operators: {
          total: this.operatorUrls.length,
          healthy: healthyOperators,
          degraded: degradedOperators,
          offline: offlineOperators,
          connected: this.operatorConnections.size,
        },
        gateways: {
          total: this.discoveredGateways.length,
          connected: this.gatewayPeerConnections.size,
        },
        performance: {
          avgLatencyMs: avgLatency,
          connectionUptime: Math.round(connectionUptime),
        },
        discovery: {
          cachedSeeds: this.loadCachedSeeds().length,
          dnsSeeds: CONFIG.dnsSeeds.length,
          lastGossipAt: this.lastGossipAt,
          lastGatewayDiscovery: this.lastGatewayDiscovery,
        },
        circuitBreakers: {
          open: Array.from(this.seedHealth.entries())
            .filter(([url]) => this.isCircuitOpen(url))
            .map(([url, h]) => ({ url, failCount: h.failCount })),
        },
        usefulWork: this.usefulWorkStats,
      });
    });

    // Mesh network health endpoint
    this.app.get('/api/mesh/health', (req, res) => {
      const seedHealthData = [];
      for (const [url, health] of this.seedHealth) {
        seedHealthData.push({
          url,
          lastSuccess: health.lastSuccess,
          lastFailure: health.lastFailure,
          failCount: health.failCount,
          latencyMs: health.latencyMs,
          status: health.failCount === 0 ? 'healthy' : health.failCount < 3 ? 'degraded' : 'unhealthy',
        });
      }
      
      res.json({
        gatewayId: this.gatewayId,
        isPublicGateway: this.isPublicGateway,
        discoveryLayers: {
          cachedSeeds: this.loadCachedSeeds().length,
          hardcodedSeeds: CONFIG.operatorUrls.length,
          dnsSeeds: CONFIG.dnsSeeds.length,
          discoveredOperators: this.operatorUrls.length,
          discoveredGateways: this.discoveredGateways.length,
        },
        connections: {
          connectedToSeed: this.isConnectedToSeed,
          connectedSeed: this.connectedSeed,
          operatorConnections: this.operatorConnections.size,
          gatewayPeerConnections: this.gatewayPeerConnections.size,
        },
        seedHealth: seedHealthData.sort((a, b) => b.lastSuccess - a.lastSuccess),
        usefulWork: this.usefulWorkStats,
      });
    });

    // Statistics
    this.app.get('/stats', (req, res) => {
      const stats = {
        nodeId: 'gateway-package',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        connectedPeers: this.peers.size,
        isConnectedToSeed: this.isConnectedToSeed,
        cacheSize: this.cache.size,
        rateLimitClients: this.rateLimitMap.size,
        hardcodedSeeds: CONFIG.seedNodes,
        dataDir: CONFIG.dataDir,
        platform: os.platform(),
        nodeVersion: process.version,
        usefulWork: this.usefulWorkStats,
      };
      res.json(stats);
    });

    // Useful work endpoints - gateways contribute to network security
    this.app.get('/api/work/stats', (req, res) => {
      res.json({
        success: true,
        stats: this.usefulWorkStats,
        operatorHealth: Array.from(this.operatorHealth.values()),
        recentVerifications: this.verificationResults.slice(-20),
      });
    });

    this.app.get('/api/work/operators', (req, res) => {
      res.json({
        success: true,
        operators: this.getCandidateOperatorUrls(),
        health: Array.from(this.operatorHealth.values()),
      });
    });

    this.app.get('/api/work/consistency', (req, res) => {
      const consistencyResults = this.verificationResults
        .filter(r => r.type === 'consistency')
        .slice(-50);
      res.json({
        success: true,
        checks: this.usefulWorkStats.consistencyChecks,
        passed: this.usefulWorkStats.consistencyPassed,
        failed: this.usefulWorkStats.consistencyFailed,
        results: consistencyResults,
      });
    });

    // Hourly stats endpoint
    this.app.get('/api/traffic/hourly', (req, res) => {
      res.json({
        success: true,
        hourlyStats: this.getHourlyStats(),
        totalHours: this.trafficStats.hourlyStats.length,
      });
    });

    // Best operators endpoint
    this.app.get('/api/operators/best', (req, res) => {
      const count = parseInt(req.query.count) || 5;
      res.json({
        success: true,
        operators: this.getBestOperators(count),
      });
    });

    // Traffic and bandwidth monitoring endpoint
    this.app.get('/api/traffic/stats', (req, res) => {
      const uptimeMs = Date.now() - this.trafficStats.startTime;
      const uptimeHours = uptimeMs / 3600000;
      
      res.json({
        success: true,
        uptime: {
          ms: uptimeMs,
          hours: Math.round(uptimeHours * 100) / 100,
          startTime: new Date(this.trafficStats.startTime).toISOString(),
        },
        requests: {
          total: this.trafficStats.requestsServed,
          perHour: Math.round(this.trafficStats.requestsServed / Math.max(1, uptimeHours)),
          api: this.trafficStats.apiRequests,
          ws: this.trafficStats.wsMessages,
        },
        bandwidth: {
          served: this.trafficStats.bytesServed,
          servedMB: Math.round(this.trafficStats.bytesServed / 1048576 * 100) / 100,
          received: this.trafficStats.bytesReceived,
          receivedMB: Math.round(this.trafficStats.bytesReceived / 1048576 * 100) / 100,
        },
        clients: {
          unique: this.trafficStats.uniqueClients.size,
          peakConcurrent: this.trafficStats.peakConcurrent,
          currentConcurrent: this.trafficStats.currentConcurrent,
        },
        topEndpoints: Object.entries(this.trafficStats.requestsByEndpoint)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([endpoint, count]) => ({ endpoint, count })),
      });
    });

    // Peer reputation endpoint
    this.app.get('/api/peers/reputation', (req, res) => {
      const peers = [];
      for (const [peerId, rep] of this.peerReputation) {
        peers.push({
          peerId,
          score: rep.score,
          successCount: rep.successCount,
          failCount: rep.failCount,
          lastSeen: rep.lastSeen,
        });
      }
      res.json({
        success: true,
        peers: peers.sort((a, b) => b.score - a.score),
      });
    });

    // Health status summary - comprehensive gateway health
    this.app.get('/api/health/summary', (req, res) => {
      const operators = this.getCandidateOperatorUrls();
      const connectedOperators = Array.from(this.operatorConnections.values())
        .filter(c => c.status === 'connected').length;
      const healthyOperators = operators.filter(url => {
        const h = this.seedHealth.get(url);
        return h && h.successCount > h.failCount;
      }).length;
      
      const uptimeMs = Date.now() - this.trafficStats.startTime;
      const avgLatency = this.calculateAverageLatency();
      
      // Determine overall health status
      let status = 'healthy';
      let issues = [];
      
      if (connectedOperators === 0) {
        status = 'critical';
        issues.push('No connected operators');
      } else if (connectedOperators < 2) {
        status = 'degraded';
        issues.push('Less than 2 connected operators');
      }
      
      if (avgLatency > 1000) {
        status = status === 'healthy' ? 'degraded' : status;
        issues.push('High average latency');
      }
      
      if (this.isPartitioned) {
        status = 'critical';
        issues.push('Network partition detected');
      }
      
      res.json({
        success: true,
        status,
        issues,
        uptime: {
          ms: uptimeMs,
          formatted: this.formatUptime(uptimeMs),
        },
        operators: {
          total: operators.length,
          connected: connectedOperators,
          healthy: healthyOperators,
        },
        traffic: {
          totalRequests: this.trafficStats.requestsServed,
          bytesServedMB: Math.round(this.trafficStats.bytesServed / 1048576 * 100) / 100,
          uniqueClients: this.trafficStats.uniqueClients.size,
        },
        latency: {
          average: avgLatency,
          histogram: this.getLatencyHistogram(),
        },
        publicAccess: this.getPublicAccessStatus(),
      });
    });

    // Network latency histogram endpoint
    this.app.get('/api/network/latency', (req, res) => {
      res.json({
        success: true,
        averageLatency: this.calculateAverageLatency(),
        histogram: this.getLatencyHistogram(),
        byOperator: this.getLatencyByOperator(),
      });
    });

    // Operator versions endpoint
    this.app.get('/api/operators/versions', (req, res) => {
      const versions = [];
      for (const [url, health] of this.seedHealth) {
        versions.push({
          url,
          version: health.version || 'unknown',
          lastSeen: health.lastSuccess || health.lastFailure,
          quality: this.getEnhancedConnectionQuality(url),
        });
      }
      res.json({
        success: true,
        operators: versions.sort((a, b) => b.quality - a.quality),
      });
    });

    // Connection events endpoint
    this.app.get('/api/events', (req, res) => {
      const limit = parseInt(req.query.limit) || 50;
      const type = req.query.type || null;
      res.json({
        success: true,
        events: this.getConnectionEvents(limit, type),
      });
    });

    // Rate limit stats endpoint
    this.app.get('/api/rate-limits', (req, res) => {
      res.json({
        success: true,
        ...this.getRateLimitStats(),
      });
    });

    // Diagnostics endpoint
    this.app.get('/api/diagnostics', (req, res) => {
      res.json({
        success: true,
        ...this.getDiagnosticsReport(),
      });
    });

    // Public access endpoints - for home users to make gateway publicly accessible
    this.app.get('/api/public-access/status', (req, res) => {
      res.json({
        success: true,
        ...this.getPublicAccessStatus(),
      });
    });

    this.app.post('/api/public-access/enable', async (req, res) => {
      try {
        const success = await this.enablePublicAccess();
        if (success) {
          // Auto-register as public gateway
          this.isPublicGateway = true;
          this.publicHttpUrl = this.publicAccessUrl;
          await this.registerAsPublicGateway();
        }
        res.json({
          success,
          ...this.getPublicAccessStatus(),
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          error: error.message,
        });
      }
    });

    this.app.post('/api/public-access/disable', async (req, res) => {
      try {
        await this.disablePublicAccess();
        this.isPublicGateway = false;
        res.json({
          success: true,
          ...this.getPublicAccessStatus(),
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          error: error.message,
        });
      }
    });

    // Registry endpoints
    this.app.get('/api/registry/state', (req, res) => {
      const cacheKey = 'registry_state';
      const cached = this.getFromCache(cacheKey);
      if (cached) {
        return res.json(cached);
      }

      Promise.resolve(this.assertSyncedForQuorum('', false)).then(() => {
        const state = {
          sequenceNumber: this.registryData.sequenceNumber || this.registryData.lastEventSequence || 0,
          lastEventHash: this.registryData.lastEventHash || '',
          timestamp: Date.now(),
          items: this.registryData.items || {},
          settlements: this.registryData.settlements || {},
          operators: this.registryData.operators || {},
          accounts: this.registryData.accounts || {},
          gatewayNode: {
            version: '1.0.6',
            platform: os.platform(),
            hardcodedSeeds: CONFIG.seedNodes,
            note: 'This is a gateway node with hardcoded seed configuration'
          }
        };

        this.setCache(cacheKey, state);
        res.json(state);
      }).catch((e) => {
        const statusCode = e?.statusCode;
        res.status(statusCode || 503).json({
          error: e?.message || String(e),
          details: e?.details
        });
      });

      return;
    });

    // Item lookup
    this.app.get('/api/registry/items/:itemId', (req, res) => {
      const { itemId } = req.params;
      Promise.resolve(this.assertSyncedForQuorum('', false)).then(() => {
        const item = this.registryData.items?.[itemId];

        if (!item) {
          res.status(404).json({ error: 'Item not found' });
          return;
        }

        res.json(item);
      }).catch((e) => {
        const statusCode = e?.statusCode;
        res.status(statusCode || 503).json({
          error: e?.message || String(e),
          details: e?.details
        });
      });
    });

    // Owner items
    this.app.get('/api/registry/owners/:address/items', (req, res) => {
      const { address } = req.params;
      Promise.resolve(this.assertSyncedForQuorum('', false)).then(() => {
        const items = Object.values(this.registryData.items || {}).filter(item => item.currentOwner === address);
        res.json(items);
      }).catch((e) => {
        const statusCode = e?.statusCode;
        res.status(statusCode || 503).json({
          error: e?.message || String(e),
          details: e?.details
        });
      });
    });

    // Network endpoints
    this.app.get('/api/network/stats', (req, res) => {
      const stats = {
        connectedPeers: this.peers.size,
        isConnectedToSeed: this.isConnectedToSeed,
        hardcodedSeeds: CONFIG.seedNodes,
        uptime: process.uptime(),
        platform: os.platform()
      };
      res.json(stats);
    });

    // Configuration info (read-only)
    this.app.get('/api/config', (req, res) => {
      res.json({
        port: EFFECTIVE_HTTP_PORT,
        wsPort: EFFECTIVE_WS_PORT,
        seedNodes: CONFIG.seedNodes,
        operatorUrls: this.operatorUrls,
        cacheEnabled: CONFIG.cacheEnabled,
        rateLimitEnabled: CONFIG.rateLimitEnabled,
        platform: os.platform(),
        nodeVersion: process.version,
        note: 'Seed configuration is hardcoded. Ports can be overridden via env vars.',
        portOverrideEnv: {
          http: 'GATEWAY_PORT (or AUTHO_GATEWAY_PORT)',
          ws: 'GATEWAY_WS_PORT (or AUTHO_GATEWAY_WS_PORT)'
        },
        warning: 'This gateway node is pre-configured to connect only to autho.pinkmahi.com'
      });
    });

    this.app.use('/api', (req, res) => {
      Promise.resolve(this.proxyApi(req, res)).catch((e) => {
        console.error('❌ Gateway proxy error:', e);
        res.status(500).json({ error: 'Gateway proxy error', message: e?.message || String(e) });
      });
    });

    this.app.get('*', (req, res) => {
      Promise.resolve(this.serveUi(req, res)).catch((e) => {
        console.error('❌ Gateway UI serve error:', e);
        res.status(500).json({ error: 'Gateway UI error', message: e?.message || String(e) });
      });
    });

    this.app.use('*', (req, res) => {
      res.status(404).json({ error: 'Endpoint not found' });
    });
  }

  setupWebSocket() {
    this.wsServer = new WebSocket.Server({ port: EFFECTIVE_WS_PORT });
    
    this.wsServer.on('connection', (ws, req) => {
      const peerId = `peer-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      this.peers.set(peerId, ws);
      
      console.log(`🔗 Peer connected: ${peerId}`);
      
      ws.send(JSON.stringify({
        type: 'welcome',
        peerId,
        message: 'Connected to Autho Gateway Node',
        hardcodedSeeds: CONFIG.seedNodes,
        platform: os.platform()
      }));

      ws.on('message', (data) => {
        try {
          // Track WebSocket message stats
          this.trafficStats.wsMessages++;
          this.trafficStats.bytesReceived += data.length || 0;
          
          const message = JSON.parse(data.toString());
          this.handleWebSocketMessage(peerId, message);
        } catch (error) {
          console.error(`❌ Invalid message from ${peerId}:`, error);
        }
      });

      ws.on('close', () => {
        this.peers.delete(peerId);
        console.log(`❌ Peer disconnected: ${peerId}`);
      });

      ws.on('error', (error) => {
        console.error(`❌ WebSocket error for ${peerId}:`, error);
        this.peers.delete(peerId);
      });
    });
  }

  handleWebSocketMessage(peerId, message) {
    switch (message.type) {
      case 'ping':
        this.sendToPeer(peerId, { type: 'pong', timestamp: Date.now() });
        break;
      
      case 'get_registry_state':
        this.sendToPeer(peerId, {
          type: 'registry_state',
          data: this.registryData
        });
        break;
      
      default:
        console.log(`📨 Unknown message type from ${peerId}:`, message.type);
    }
  }

  sendToPeer(peerId, message) {
    const ws = this.peers.get(peerId);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message));
    }
  }

  connectToSeeds() {
    const seeds = this.getSeedNodes();
    console.log(' Connecting to ALL seed nodes simultaneously...');
    console.log(`   Seeds: ${seeds.join(', ')}`);
    
    for (const seed of seeds) {
      this.connectToSingleSeed(seed);
    }
  }

  connectToSingleSeed(seed) {
    const [host, port] = String(seed).split(':');
    console.log(` Connecting to seed: ${seed}`);

    const isLocal = host.includes('localhost') || host.includes('127.0.0.1');
    const protocol = (() => {
      if (isLocal) return 'ws';
      const p = String(port || '').trim();
      if (p && p !== '443') return 'ws';
      return 'wss';
    })();
    const wsUrl = port ? `${protocol}://${host}:${port}` : `${protocol}://${host}`;

    try {
      const ws = new WebSocket(wsUrl);

      ws.on('open', () => {
        console.log(` Connected to seed: ${seed}`);
        this.isConnectedToSeed = true;
        
        ws.send(JSON.stringify({
          type: 'sync_request',
          nodeId: 'gateway-package',
          platform: os.platform(),
          timestamp: Date.now()
        }));
      });

      ws.on('message', (data) => {
        try {
          const message = JSON.parse(data.toString());
          this.handleSeedMessage(seed, message, ws);
        } catch (error) {
          console.error(` Invalid message from seed ${seed}:`, error);
        }
      });

      ws.on('close', () => {
        console.log(` Disconnected from seed: ${seed}`);
        setTimeout(() => this.connectToSingleSeed(seed), 10000);
      });

      ws.on('error', (error) => {
        console.error(` WebSocket error for seed ${seed}:`, error.message || error);
      });
    } catch (error) {
      console.error(` Failed to connect to seed ${seed}:`, error && error.message ? error.message : error);
      setTimeout(() => this.connectToSingleSeed(seed), 10000);
    }
  }

  async discoverOperators() {
    const now = Date.now();
    if (now - this.lastOperatorDiscovery < 300000 && this.discoveredOperators.length > 0) {
      return this.discoveredOperators;
    }

    console.log('🔍 Discovering active operators...');
    
    const seeds = this.getSeedNodes();
    for (const seed of seeds) {
      try {
        const [host, port] = String(seed).split(':');
        const isLocal = host.includes('localhost') || host.includes('127.0.0.1');
        const isOnion = host.toLowerCase().endsWith('.onion');
        const protocol = (isLocal || isOnion) ? 'http' : 'https';
        const httpUrl = isLocal
          ? (port ? `${protocol}://${host}:${port}` : `${protocol}://${host}`)
          : `${protocol}://${host}`;

        const response = await fetch(`${httpUrl}/api/network/operators`);
        const data = await response.json();

        if (data && data.success && Array.isArray(data.operators)) {
          this.discoveredOperators = data.operators;
          this.lastOperatorDiscovery = now;
          console.log(`✅ Discovered ${data.operators.length} active operators`);
          return this.discoveredOperators;
        }
      } catch (error) {
        console.log(`⚠️  Failed to discover operators from ${seed}: ${error.message}`);
      }
    }

    console.log('⚠️  Operator discovery failed, using hardcoded seeds');
    return [];
  }

  async connectToOperators() {
    await this.discoverOperators();

    const operators = this.discoveredOperators.length > 0 
      ? this.discoveredOperators 
      : this.getSeedNodes().map((seed, idx) => ({
          operatorId: `seed-${idx}`,
          wsUrl: this.seedToWsUrl(seed),
        }));

    console.log(`🌐 Connecting to ${operators.length} operators...`);

    for (const op of operators) {
      if (!op.wsUrl) continue;
      if (!this.isTorEnabled() && this.isOnionUrl(op.wsUrl)) continue;
      
      if (this.operatorConnections.has(op.operatorId)) {
        const existing = this.operatorConnections.get(op.operatorId);
        if (existing.ws && existing.ws.readyState === WebSocket.OPEN) {
          continue;
        }
      }

      this.connectToOperator(op);
    }
  }

  seedToWsUrl(seed) {
    const [host, port] = String(seed).split(':');
    const isLocal = host.includes('localhost') || host.includes('127.0.0.1');
    const protocol = (() => {
      if (isLocal) return 'ws';
      const p = String(port || '').trim();
      if (p && p !== '443') return 'ws';
      return 'wss';
    })();
    return port ? `${protocol}://${host}:${port}` : `${protocol}://${host}`;
  }

  connectToOperator(operator) {
    const { operatorId, wsUrl } = operator;
    
    try {
      const ws = new WebSocket(wsUrl);
      const connectionInfo = {
        ws,
        operatorId,
        wsUrl,
        connectedAt: null,
        lastSeen: null,
      };

      ws.on('open', () => {
        console.log(`✅ Connected to operator: ${operatorId}`);
        connectionInfo.connectedAt = Date.now();
        connectionInfo.lastSeen = Date.now();
        this.isConnectedToSeed = true;
        this.recordSeedSuccess(wsUrl, 0);

        ws.send(JSON.stringify({
          type: 'sync_request',
          nodeId: 'gateway-package',
          platform: os.platform(),
          timestamp: Date.now()
        }));
      });

      ws.on('message', (data) => {
        try {
          connectionInfo.lastSeen = Date.now();
          const message = JSON.parse(data.toString());
          this.handleSeedMessage(operatorId, message, ws);
        } catch (error) {
          console.error(`❌ Invalid message from operator ${operatorId}:`, error);
        }
      });

      ws.on('close', () => {
        console.log(`❌ Disconnected from operator: ${operatorId}`);
        this.operatorConnections.delete(operatorId);
        this.recordSeedFailure(wsUrl);
        
        const hasActiveConnection = Array.from(this.operatorConnections.values())
          .some(conn => conn.ws && conn.ws.readyState === WebSocket.OPEN);
        
        if (!hasActiveConnection) {
          this.isConnectedToSeed = false;
        }

        // Reconnect with exponential backoff
        const health = this.seedHealth.get(wsUrl);
        const failCount = health?.failCount || 1;
        const delay = Math.min(10000 * Math.pow(1.5, failCount - 1), 300000); // Max 5 min
        console.log(`🔄 Reconnecting to ${operatorId} in ${Math.round(delay/1000)}s...`);
        
        setTimeout(() => {
          this.connectToOperator(operator);
        }, delay);
      });

      ws.on('error', (error) => {
        console.error(`❌ WebSocket error for operator ${operatorId}:`, error.message);
      });

      this.operatorConnections.set(operatorId, connectionInfo);
    } catch (error) {
      console.error(`❌ Failed to connect to operator ${operatorId}:`, error.message);
    }
  }

  /**
   * Prune stale connections - removes connections that haven't been seen recently
   * and reconnects to maintain mesh health
   */
  pruneStaleConnections() {
    const now = Date.now();
    const staleThresholdMs = 300000; // 5 minutes without activity = stale
    let pruned = 0;
    let reconnecting = 0;

    // Check operator connections
    for (const [operatorId, conn] of this.operatorConnections) {
      const lastActivity = conn.lastSeen || conn.connectedAt || 0;
      const isStale = (now - lastActivity) > staleThresholdMs;
      const isClosed = !conn.ws || conn.ws.readyState !== WebSocket.OPEN;

      if (isStale || isClosed) {
        // Close stale connection
        if (conn.ws) {
          try { conn.ws.close(); } catch (e) {}
        }
        this.operatorConnections.delete(operatorId);
        pruned++;

        // Find operator info and schedule reconnect
        const operator = this.discoveredOperators.find(op => op.operatorId === operatorId);
        if (operator) {
          setTimeout(() => this.connectToOperator(operator), 5000);
          reconnecting++;
        }
      }
    }

    // Check gateway peer connections
    for (const [gatewayId, ws] of this.gatewayPeerConnections) {
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        this.gatewayPeerConnections.delete(gatewayId);
        pruned++;
      }
    }

    if (pruned > 0) {
      console.log(`🧹 Pruned ${pruned} stale connections, reconnecting to ${reconnecting}`);
    }

    // Update connection status
    const activeConnections = Array.from(this.operatorConnections.values())
      .filter(conn => conn.ws && conn.ws.readyState === WebSocket.OPEN).length;
    this.isConnectedToSeed = activeConnections > 0;

    return { pruned, reconnecting, activeConnections };
  }

  /**
   * Detect network partition - checks if we're isolated from the network
   * Returns partition status and triggers healing if needed
   */
  async detectNetworkPartition() {
    const activeConnections = Array.from(this.operatorConnections.values())
      .filter(conn => conn.ws && conn.ws.readyState === WebSocket.OPEN).length;
    
    const totalKnownOperators = this.operatorUrls.length;
    const connectionRatio = totalKnownOperators > 0 ? activeConnections / totalKnownOperators : 0;
    
    // Partition indicators
    const isPartitioned = activeConnections === 0 && totalKnownOperators > 0;
    const isPartiallyPartitioned = connectionRatio < 0.3 && totalKnownOperators > 3;
    
    if (isPartitioned) {
      console.log('🔴 NETWORK PARTITION DETECTED - No active connections');
      await this.healNetworkPartition();
    } else if (isPartiallyPartitioned) {
      console.log(`🟡 Partial partition - only ${Math.round(connectionRatio * 100)}% connected`);
      // Try to connect to more operators
      await this.connectToOperators();
    }
    
    return {
      isPartitioned,
      isPartiallyPartitioned,
      activeConnections,
      totalKnownOperators,
      connectionRatio,
    };
  }

  /**
   * Heal network partition by aggressively trying all discovery methods
   */
  async healNetworkPartition() {
    console.log('🔧 Attempting to heal network partition...');
    
    // Step 1: Force refresh from all discovery sources
    await this.bootstrapDiscovery();
    
    // Step 2: Try connecting to all known operators
    await this.connectToOperators();
    
    // Step 3: If still no connections, try DNS seeds directly
    if (this.operatorConnections.size === 0) {
      console.log('🔧 Trying DNS seeds for recovery...');
      for (const dnsSeed of CONFIG.dnsSeeds) {
        try {
          const urls = await this.discoverFromDnsSeed(dnsSeed);
          for (const url of urls) {
            if (!this.operatorUrls.includes(url)) {
              this.operatorUrls.push(url);
            }
          }
        } catch (e) {}
      }
      await this.connectToOperators();
    }
    
    const recovered = this.operatorConnections.size > 0;
    console.log(recovered ? '✅ Network partition healed' : '❌ Partition healing failed - will retry');
    
    return recovered;
  }

  /**
   * Circuit breaker for operators - prevents repeated calls to failing operators
   */
  isCircuitOpen(url) {
    const health = this.seedHealth.get(url);
    if (!health) return false;
    
    // Circuit opens after 5 consecutive failures
    if (health.failCount >= 5) {
      const timeSinceLastFailure = Date.now() - (health.lastFailure || 0);
      const cooldownMs = Math.min(60000 * health.failCount, 600000); // Max 10 min cooldown
      
      if (timeSinceLastFailure < cooldownMs) {
        return true; // Circuit is open, don't try this operator
      }
      // Cooldown expired, allow one test request (half-open state)
    }
    return false;
  }

  /**
   * Get the best operator for a request based on quality score
   */
  getBestOperatorForRequest() {
    const activeOperators = Array.from(this.operatorConnections.entries())
      .filter(([, conn]) => conn.ws && conn.ws.readyState === WebSocket.OPEN)
      .map(([id, conn]) => ({
        operatorId: id,
        wsUrl: conn.wsUrl,
        quality: this.getConnectionQuality(conn.wsUrl),
        lastSeen: conn.lastSeen || 0,
      }))
      .sort((a, b) => b.quality - a.quality);
    
    return activeOperators.length > 0 ? activeOperators[0] : null;
  }

  // ==================== PUBLIC ACCESS FOR HOME USERS ====================

  /**
   * Enable public access - tries multiple methods automatically
   * This allows home users behind NAT to make their gateway publicly accessible
   */
  async enablePublicAccess() {
    console.log('🌍 Attempting to enable public access...');
    
    // Get public IP first for logging/reference
    this.externalIp = await this.getPublicIp();
    if (this.externalIp) {
      console.log(`🌐 Your public IP: ${this.externalIp}`);
    }
    
    // Method 1: Check if already publicly accessible (manual port forward or direct IP)
    if (await this.checkDirectPublicAccess()) {
      return true;
    }
    
    // Method 2: Try UPnP port forwarding (works on most home routers)
    if (await this.tryUpnpPortForward()) {
      return true;
    }
    
    // Method 3: Try tunnel service (localtunnel, works everywhere)
    if (await this.tryTunnelService()) {
      return true;
    }
    
    console.log('⚠️ Could not enable public access automatically.');
    console.log('   Options:');
    console.log('   1. Manually forward ports 3001 and 4001 on your router');
    console.log('   2. Use a reverse proxy like Cloudflare Tunnel or ngrok');
    console.log('   3. Set GATEWAY_PUBLIC_URL manually if you have a domain');
    
    return false;
  }

  /**
   * Check if gateway is already publicly accessible
   */
  async checkDirectPublicAccess() {
    try {
      // Get external IP
      let publicIp;
      try {
        const { publicIpv4 } = await import('public-ip');
        publicIp = await publicIpv4({ timeout: 5000 });
      } catch (e) {
        // Fallback: try API
        const response = await fetch('https://api.ipify.org?format=json', {
          signal: AbortSignal.timeout(5000),
        });
        const data = await response.json();
        publicIp = data.ip;
      }
      
      this.externalIp = publicIp;
      console.log(`🌐 External IP: ${publicIp}`);
      
      // Try to reach ourselves from outside
      const testUrl = `http://${publicIp}:${EFFECTIVE_HTTP_PORT}/health`;
      const response = await fetch(testUrl, {
        signal: AbortSignal.timeout(5000),
      });
      
      if (response.ok) {
        this.publicAccessEnabled = true;
        this.publicAccessUrl = `http://${publicIp}:${EFFECTIVE_HTTP_PORT}`;
        this.publicAccessMethod = 'direct';
        console.log(`✅ Gateway is directly accessible at: ${this.publicAccessUrl}`);
        return true;
      }
    } catch (error) {
      // Not directly accessible
    }
    return false;
  }

  /**
   * Get public IP using external service (more reliable than UPnP)
   */
  async getPublicIp() {
    const services = [
      'https://api.ipify.org?format=text',
      'https://icanhazip.com',
      'https://ifconfig.me/ip',
    ];
    
    for (const url of services) {
      try {
        const resp = await fetch(url, { timeout: 5000 });
        if (resp.ok) {
          const ip = (await resp.text()).trim();
          if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
            return ip;
          }
        }
      } catch {}
    }
    return null;
  }

  /**
   * Try UPnP port forwarding (automatic NAT traversal)
   */
  async tryUpnpPortForward() {
    try {
      const natUpnp = require('nat-upnp');
      this.upnpClient = natUpnp.createClient();
      
      console.log('🔧 Attempting UPnP port forwarding...');
      
      // Forward HTTP port
      await new Promise((resolve, reject) => {
        this.upnpClient.portMapping({
          public: EFFECTIVE_HTTP_PORT,
          private: EFFECTIVE_HTTP_PORT,
          ttl: 0, // Permanent until removed
          description: 'Autho Gateway HTTP',
        }, (err) => err ? reject(err) : resolve());
      });
      
      // Forward WebSocket port
      await new Promise((resolve, reject) => {
        this.upnpClient.portMapping({
          public: EFFECTIVE_WS_PORT,
          private: EFFECTIVE_WS_PORT,
          ttl: 0,
          description: 'Autho Gateway WebSocket',
        }, (err) => err ? reject(err) : resolve());
      });
      
      // Get external IP using reliable external service
      const externalIp = await this.getPublicIp();
      
      this.externalIp = externalIp;
      this.publicAccessEnabled = true;
      this.publicAccessUrl = `http://${externalIp}:${EFFECTIVE_HTTP_PORT}`;
      this.publicAccessMethod = 'upnp';
      
      this.logConnectionEvent('public_access_enabled', { method: 'upnp', url: this.publicAccessUrl, externalIp });
      console.log(`✅ UPnP port forwarding successful!`);
      console.log(`   External URL: ${this.publicAccessUrl}`);
      console.log(`   WebSocket: ws://${externalIp}:${EFFECTIVE_WS_PORT}`);
      
      return true;
    } catch (error) {
      console.log(`⚠️ UPnP not available: ${error.message}`);
      return false;
    }
  }

  /**
   * Try tunnel service for public access (works everywhere)
   * Uses Cloudflare Tunnel (cloudflared) - free, no password, reliable
   */
  async tryTunnelService() {
    // Try Cloudflare Tunnel first (best option - no password, reliable)
    if (await this.tryCloudflaredTunnel()) {
      return true;
    }
    
    // Fallback to ngrok if available
    if (await this.tryNgrokTunnel()) {
      return true;
    }
    
    console.log('⚠️ No tunnel service available.');
    console.log('   For seamless public access, install cloudflared:');
    console.log('   Windows: winget install cloudflare.cloudflared');
    console.log('   Or download from: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/');
    return false;
  }

  /**
   * Try Cloudflare Tunnel (cloudflared) - FREE, no password, no account required
   */
  async tryCloudflaredTunnel() {
    const { spawn, execSync } = require('child_process');
    
    console.log('🔧 Starting Cloudflare Tunnel...');
    
    // Find cloudflared executable
    let cloudflaredPath = 'cloudflared';
    const possiblePaths = [
      'cloudflared',
      'C:\\Program Files (x86)\\cloudflared\\cloudflared.exe',
      'C:\\Program Files\\cloudflared\\cloudflared.exe',
      path.join(process.env.LOCALAPPDATA || '', 'Programs', 'cloudflared', 'cloudflared.exe'),
    ];
    
    for (const p of possiblePaths) {
      try {
        execSync(`"${p}" --version`, { stdio: 'ignore', timeout: 3000 });
        cloudflaredPath = p;
        break;
      } catch (e) {
        continue;
      }
    }
    
    try {
      // Verify cloudflared is accessible
      execSync(`"${cloudflaredPath}" --version`, { stdio: 'ignore', timeout: 3000 });
    } catch (e) {
      console.log('⚠️ cloudflared not installed');
      return false;
    }
    
    return new Promise((resolve) => {
      // Start cloudflared tunnel (no account needed for quick tunnels)
      // Use shell:false to avoid security warnings and subprocess issues
      this.tunnelProcess = spawn(cloudflaredPath, ['tunnel', '--url', `http://localhost:${EFFECTIVE_HTTP_PORT}`], { 
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
      });
      
      let urlFound = false;
      const urlTimeout = setTimeout(() => {
        if (!urlFound) {
          console.log('⚠️ Cloudflare Tunnel timeout');
          this.tunnelProcess?.kill();
          resolve(false);
        }
      }, 30000);
      
      const handleOutput = (data) => {
        const output = data.toString();
        // Look for the tunnel URL in output
        const urlMatch = output.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/i);
        if (urlMatch && !urlFound) {
          urlFound = true;
          clearTimeout(urlTimeout);
          
          this.publicAccessEnabled = true;
          this.publicAccessUrl = urlMatch[0];
          this.publicAccessMethod = 'cloudflare';
          
          this.logConnectionEvent('public_access_enabled', { method: 'cloudflare', url: this.publicAccessUrl });
          console.log(`✅ Cloudflare Tunnel established!`);
          console.log(`   Public URL: ${this.publicAccessUrl}`);
          console.log(`   (No password required - direct access)`);
          
          // Open browser with the public URL
          this.openBrowserWithUrl(this.publicAccessUrl);
          
          // Register this gateway URL with the seed ledger for peer discovery
          this.registerPublicGatewayToLedger();
          
          resolve(true);
        }
      };
      
      this.tunnelProcess.stdout.on('data', handleOutput);
      this.tunnelProcess.stderr.on('data', handleOutput);
      
      this.tunnelProcess.on('close', (code) => {
        if (this.publicAccessEnabled && this.publicAccessMethod === 'cloudflare') {
          console.log('⚠️ Cloudflare Tunnel closed, attempting to reconnect...');
          this.publicAccessEnabled = false;
          setTimeout(() => this.tryCloudflaredTunnel(), 5000);
        }
      });
      
      this.tunnelProcess.on('error', (err) => {
        console.error('Tunnel process error:', err.message);
        clearTimeout(urlTimeout);
        resolve(false);
      });
    });
  }

  /**
   * Try ngrok as fallback tunnel
   */
  async tryNgrokTunnel() {
    const { spawn } = require('child_process');
    
    console.log('🔧 Trying ngrok tunnel...');
    
    try {
      // Check if ngrok is installed
      const checkProcess = spawn('ngrok', ['--version'], { shell: true });
      await new Promise((resolve, reject) => {
        checkProcess.on('close', code => code === 0 ? resolve() : reject(new Error('not installed')));
        checkProcess.on('error', reject);
        setTimeout(() => reject(new Error('timeout')), 3000);
      });
    } catch (e) {
      console.log('⚠️ ngrok not installed');
      return false;
    }
    
    return new Promise((resolve) => {
      this.tunnelProcess = spawn('ngrok', ['http', EFFECTIVE_HTTP_PORT.toString()], { 
        shell: true,
        stdio: ['ignore', 'pipe', 'pipe']
      });
      
      // ngrok outputs URL via API, need to fetch it
      setTimeout(async () => {
        try {
          const resp = await fetch('http://localhost:4040/api/tunnels');
          const data = await resp.json();
          if (data.tunnels && data.tunnels.length > 0) {
            const tunnel = data.tunnels.find(t => t.proto === 'https') || data.tunnels[0];
            this.publicAccessEnabled = true;
            this.publicAccessUrl = tunnel.public_url;
            this.publicAccessMethod = 'ngrok';
            
            this.logConnectionEvent('public_access_enabled', { method: 'ngrok', url: this.publicAccessUrl });
            console.log(`✅ ngrok Tunnel established!`);
            console.log(`   Public URL: ${this.publicAccessUrl}`);
            
            resolve(true);
          } else {
            resolve(false);
          }
        } catch (e) {
          resolve(false);
        }
      }, 3000);
      
      this.tunnelProcess.on('error', () => resolve(false));
    });
  }

  /**
   * Disable public access and cleanup
   */
  async disablePublicAccess() {
    // Remove UPnP mappings
    if (this.upnpClient) {
      try {
        await new Promise((resolve) => {
          this.upnpClient.portUnmapping({ public: EFFECTIVE_HTTP_PORT }, resolve);
        });
        await new Promise((resolve) => {
          this.upnpClient.portUnmapping({ public: EFFECTIVE_WS_PORT }, resolve);
        });
        console.log('🔧 UPnP port mappings removed');
      } catch (e) {}
      this.upnpClient = null;
    }
    
    // Close tunnel process
    if (this.tunnelProcess) {
      try {
        this.tunnelProcess.kill();
        console.log('🔧 Tunnel process stopped');
      } catch (e) {}
      this.tunnelProcess = null;
    }
    
    this.publicAccessEnabled = false;
    this.publicAccessUrl = null;
    this.publicAccessMethod = null;
  }

  /**
   * Get public access status
   */
  getPublicAccessStatus() {
    return {
      enabled: this.publicAccessEnabled,
      url: this.publicAccessUrl,
      method: this.publicAccessMethod,
      externalIp: this.externalIp,
      httpPort: EFFECTIVE_HTTP_PORT,
      wsPort: EFFECTIVE_WS_PORT,
    };
  }

  /**
   * Open browser with the public gateway URL
   */
  openBrowserWithUrl(url) {
    const { exec } = require('child_process');
    const platform = process.platform;
    
    console.log(`🌐 Opening browser: ${url}`);
    
    try {
      if (platform === 'win32') {
        exec(`start "" "${url}"`);
      } else if (platform === 'darwin') {
        exec(`open "${url}"`);
      } else {
        exec(`xdg-open "${url}"`);
      }
    } catch (e) {
      console.log(`   (Could not auto-open browser - visit manually)`);
    }
  }

  /**
   * Register this public gateway to the seed ledger for peer discovery
   */
  async registerPublicGatewayToLedger() {
    if (!this.publicAccessUrl) return;
    
    console.log(`📢 Registering gateway to seed ledger...`);
    
    // Create gateway registration event
    const gatewayInfo = {
      gatewayId: this.gatewayId,
      publicUrl: this.publicAccessUrl,
      wsUrl: this.publicAccessUrl.replace('https://', 'wss://').replace('http://', 'ws://'),
      method: this.publicAccessMethod,
      externalIp: this.externalIp,
      registeredAt: Date.now(),
      version: '1.0.7',
    };
    
    // Broadcast to all connected operators
    if (this.operatorConnections && this.operatorConnections.size > 0) {
      for (const [operatorId, ws] of this.operatorConnections) {
        if (ws && ws.readyState === 1) { // WebSocket.OPEN
          try {
            ws.send(JSON.stringify({
              type: 'gateway_register',
              gatewayId: this.gatewayId,
              data: gatewayInfo,
            }));
          } catch (e) {}
        }
      }
    }
    
    // Also register via HTTP API to operators
    for (const operatorUrl of this.operatorUrls) {
      try {
        await fetch(`${operatorUrl}/api/network/gateways/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(gatewayInfo),
          signal: AbortSignal.timeout(5000),
        });
        console.log(`✅ Registered with: ${operatorUrl}`);
      } catch (e) {
        // Silent fail - operator may not support this endpoint yet
      }
    }
    
    // Add to local peer gateway list
    if (!this.peerGateways) {
      this.peerGateways = new Map();
    }
    this.peerGateways.set(this.gatewayId, {
      ...gatewayInfo,
      isSelf: true,
    });
    
    console.log(`✅ Gateway registered for peer discovery`);
  }

  /**
   * Route API request to best available operator
   */
  async routeToOperator(path, options = {}) {
    const sortedOperators = this.getSortedSeeds();
    
    for (const operatorUrl of sortedOperators) {
      // Skip if circuit is open
      if (this.isCircuitOpen(operatorUrl)) continue;
      
      try {
        const startTime = Date.now();
        const response = await fetch(`${operatorUrl}${path}`, {
          ...options,
          signal: AbortSignal.timeout(10000),
        });
        
        const latency = Date.now() - startTime;
        this.recordSeedSuccess(operatorUrl, latency);
        
        return { response, operatorUrl, latency };
      } catch (error) {
        this.recordSeedFailure(operatorUrl);
        // Try next operator
      }
    }
    
    throw new Error('All operators unavailable');
  }

  /**
   * Load balancer - distributes requests across healthy operators
   * Uses weighted round-robin based on connection quality
   */
  getLoadBalancedOperator() {
    const operators = this.getSortedSeeds()
      .filter(url => !this.isCircuitOpen(url))
      .map(url => ({
        url,
        quality: this.getConnectionQuality(url),
        weight: Math.max(1, Math.floor(this.getConnectionQuality(url) / 10)),
      }));
    
    if (operators.length === 0) return null;
    
    // Weighted random selection
    const totalWeight = operators.reduce((sum, op) => sum + op.weight, 0);
    let random = Math.random() * totalWeight;
    
    for (const op of operators) {
      random -= op.weight;
      if (random <= 0) return op.url;
    }
    
    return operators[0].url;
  }

  /**
   * Retry queue for failed requests - stores and retries later
   */
  initRetryQueue() {
    this.retryQueue = [];
    this.maxRetryQueueSize = 100;
    this.retryInterval = 30000; // 30 seconds
    
    setInterval(() => this.processRetryQueue(), this.retryInterval);
  }

  /**
   * Add a failed request to retry queue
   */
  addToRetryQueue(request) {
    if (this.retryQueue.length >= this.maxRetryQueueSize) {
      // Remove oldest
      this.retryQueue.shift();
    }
    
    this.retryQueue.push({
      ...request,
      addedAt: Date.now(),
      retryCount: (request.retryCount || 0) + 1,
    });
  }

  /**
   * Process retry queue - attempt to resend failed requests
   */
  async processRetryQueue() {
    if (!this.retryQueue || this.retryQueue.length === 0) return;
    
    const now = Date.now();
    const maxAge = 300000; // 5 minutes max age
    const maxRetries = 3;
    
    // Filter out old requests
    this.retryQueue = this.retryQueue.filter(req => 
      (now - req.addedAt) < maxAge && req.retryCount <= maxRetries
    );
    
    // Process remaining
    const toProcess = [...this.retryQueue];
    this.retryQueue = [];
    
    for (const request of toProcess) {
      try {
        await this.routeToOperator(request.path, request.options);
        console.log(`✅ Retry successful: ${request.path}`);
      } catch (error) {
        // Re-add to queue if still failing
        if (request.retryCount < maxRetries) {
          this.addToRetryQueue(request);
        }
      }
    }
  }

  /**
   * Proxy API request with load balancing and retry
   */
  async proxyWithLoadBalancing(path, options = {}) {
    const operatorUrl = this.getLoadBalancedOperator();
    
    if (!operatorUrl) {
      throw new Error('No healthy operators available');
    }
    
    try {
      const startTime = Date.now();
      const response = await fetch(`${operatorUrl}${path}`, {
        ...options,
        signal: AbortSignal.timeout(15000),
      });
      
      const latency = Date.now() - startTime;
      this.recordSeedSuccess(operatorUrl, latency);
      
      return { response, operatorUrl, latency };
    } catch (error) {
      this.recordSeedFailure(operatorUrl);
      
      // Add to retry queue if it's a write operation
      if (options.method && ['POST', 'PUT', 'PATCH'].includes(options.method.toUpperCase())) {
        this.addToRetryQueue({ path, options });
      }
      
      // Try fallback with routeToOperator
      return this.routeToOperator(path, options);
    }
  }

  // ==================== PEER REPUTATION ====================

  /**
   * Update peer reputation based on interaction
   */
  updatePeerReputation(peerId, success, latencyMs = 0) {
    let rep = this.peerReputation.get(peerId);
    if (!rep) {
      rep = {
        score: 50, // Start neutral
        successCount: 0,
        failCount: 0,
        totalLatency: 0,
        lastSeen: Date.now(),
      };
    }

    rep.lastSeen = Date.now();

    if (success) {
      rep.successCount++;
      rep.totalLatency += latencyMs;
      // Increase score (max 100)
      rep.score = Math.min(100, rep.score + 2);
      // Bonus for low latency
      if (latencyMs < 100) rep.score = Math.min(100, rep.score + 1);
    } else {
      rep.failCount++;
      // Decrease score (min 0)
      rep.score = Math.max(0, rep.score - 5);
    }

    this.peerReputation.set(peerId, rep);
    return rep;
  }

  /**
   * Get peer score (0-100)
   */
  getPeerScore(peerId) {
    const rep = this.peerReputation.get(peerId);
    return rep ? rep.score : 50;
  }

  /**
   * Get sorted peers by reputation
   */
  getSortedPeersByReputation() {
    return Array.from(this.peerReputation.entries())
      .sort((a, b) => b[1].score - a[1].score)
      .map(([peerId, rep]) => ({ peerId, ...rep }));
  }

  // ==================== HOURLY STATS ====================

  /**
   * Record hourly stats snapshot
   */
  recordHourlyStats() {
    const now = Date.now();
    const hourlySnapshot = {
      timestamp: now,
      hour: new Date(now).toISOString().slice(0, 13),
      requests: this.trafficStats.requestsServed,
      bytesServed: this.trafficStats.bytesServed,
      bytesReceived: this.trafficStats.bytesReceived,
      uniqueClients: this.trafficStats.uniqueClients.size,
      wsMessages: this.trafficStats.wsMessages,
      peakConcurrent: this.trafficStats.peakConcurrent,
    };
    
    this.trafficStats.hourlyStats.push(hourlySnapshot);
    
    // Keep only last 24 hours
    const dayAgo = now - (24 * 60 * 60 * 1000);
    this.trafficStats.hourlyStats = this.trafficStats.hourlyStats.filter(
      s => s.timestamp > dayAgo
    );
    
    // Reset peak concurrent for next hour
    this.trafficStats.peakConcurrent = this.trafficStats.currentConcurrent;
  }

  /**
   * Get hourly stats for last 24 hours
   */
  getHourlyStats() {
    return this.trafficStats.hourlyStats.map(s => ({
      hour: s.hour,
      requests: s.requests,
      bandwidthMB: Math.round((s.bytesServed + s.bytesReceived) / 1048576 * 100) / 100,
      uniqueClients: s.uniqueClients,
      wsMessages: s.wsMessages,
    }));
  }

  // ==================== CONNECTION QUALITY ====================

  /**
   * Enhanced connection quality scoring with multiple factors
   */
  getEnhancedConnectionQuality(operatorUrl) {
    const health = this.seedHealth.get(operatorUrl);
    if (!health) return 50; // Neutral score
    
    let score = 50;
    
    // Factor 1: Success rate (0-30 points)
    const total = health.successCount + health.failCount;
    if (total > 0) {
      const successRate = health.successCount / total;
      score += Math.round(successRate * 30);
    }
    
    // Factor 2: Latency (0-25 points, lower is better)
    if (health.avgLatency > 0) {
      if (health.avgLatency < 100) score += 25;
      else if (health.avgLatency < 300) score += 20;
      else if (health.avgLatency < 500) score += 15;
      else if (health.avgLatency < 1000) score += 10;
      else score += 5;
    }
    
    // Factor 3: Recency (0-20 points)
    const lastSuccess = health.lastSuccess || 0;
    const timeSinceSuccess = Date.now() - lastSuccess;
    if (timeSinceSuccess < 60000) score += 20; // Less than 1 min
    else if (timeSinceSuccess < 300000) score += 15; // Less than 5 min
    else if (timeSinceSuccess < 900000) score += 10; // Less than 15 min
    else if (timeSinceSuccess < 3600000) score += 5; // Less than 1 hour
    
    // Factor 4: Peer reputation bonus (0-15 points)
    const rep = this.peerReputation.get(operatorUrl);
    if (rep) {
      score += Math.round(rep.score * 0.15);
    }
    
    // Factor 5: Circuit breaker penalty (-20 points)
    if (this.isCircuitOpen(operatorUrl)) {
      score -= 20;
    }
    
    return Math.max(0, Math.min(100, score));
  }

  /**
   * Get best operators sorted by enhanced quality
   */
  getBestOperators(count = 5) {
    const operators = this.getCandidateOperatorUrls();
    return operators
      .map(url => ({
        url,
        quality: this.getEnhancedConnectionQuality(url),
        health: this.seedHealth.get(url) || {},
      }))
      .sort((a, b) => b.quality - a.quality)
      .slice(0, count);
  }

  // ==================== LATENCY & UPTIME HELPERS ====================

  /**
   * Format uptime in human readable form
   */
  formatUptime(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
    if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  }

  /**
   * Calculate average latency across all operators
   */
  calculateAverageLatency() {
    let totalLatency = 0;
    let count = 0;
    
    for (const [url, health] of this.seedHealth) {
      if (health.avgLatency > 0) {
        totalLatency += health.avgLatency;
        count++;
      }
    }
    
    return count > 0 ? Math.round(totalLatency / count) : 0;
  }

  /**
   * Get latency histogram (distribution of latencies)
   */
  getLatencyHistogram() {
    const buckets = {
      '<50ms': 0,
      '50-100ms': 0,
      '100-250ms': 0,
      '250-500ms': 0,
      '500-1000ms': 0,
      '>1000ms': 0,
    };
    
    for (const [url, health] of this.seedHealth) {
      const latency = health.avgLatency || 0;
      if (latency === 0) continue;
      
      if (latency < 50) buckets['<50ms']++;
      else if (latency < 100) buckets['50-100ms']++;
      else if (latency < 250) buckets['100-250ms']++;
      else if (latency < 500) buckets['250-500ms']++;
      else if (latency < 1000) buckets['500-1000ms']++;
      else buckets['>1000ms']++;
    }
    
    return buckets;
  }

  /**
   * Get latency by operator
   */
  getLatencyByOperator() {
    const result = [];
    
    for (const [url, health] of this.seedHealth) {
      result.push({
        url,
        avgLatency: health.avgLatency || 0,
        successCount: health.successCount || 0,
        failCount: health.failCount || 0,
        lastSuccess: health.lastSuccess || null,
      });
    }
    
    return result.sort((a, b) => a.avgLatency - b.avgLatency);
  }

  // ==================== CONNECTION EVENTS LOGGING ====================

  /**
   * Log a connection event
   */
  logConnectionEvent(type, details = {}) {
    const event = {
      timestamp: Date.now(),
      type,
      ...details,
    };
    
    this.connectionEvents.push(event);
    
    // Keep only last N events
    if (this.connectionEvents.length > this.maxConnectionEvents) {
      this.connectionEvents.shift();
    }
    
    // Log to console for important events
    if (['operator_connected', 'operator_disconnected', 'public_access_enabled', 'public_access_disabled'].includes(type)) {
      console.log(`📋 Event: ${type}`, details.url || details.method || '');
    }
  }

  /**
   * Get recent connection events
   */
  getConnectionEvents(limit = 50, type = null) {
    let events = [...this.connectionEvents].reverse();
    if (type) {
      events = events.filter(e => e.type === type);
    }
    return events.slice(0, limit);
  }

  // ==================== RATE LIMIT TRACKING ====================

  /**
   * Track rate limit for a client IP
   */
  trackClientRequest(ip) {
    const now = Date.now();
    const windowMs = 60000; // 1 minute window
    
    let client = this.clientRateLimits.get(ip);
    if (!client) {
      client = { requests: [], blocked: false, blockedUntil: null, totalRequests: 0 };
      this.clientRateLimits.set(ip, client);
    }
    
    // Check if blocked
    if (client.blocked && client.blockedUntil > now) {
      return { allowed: false, remaining: 0, resetIn: client.blockedUntil - now };
    }
    
    // Unblock if block expired
    if (client.blocked && client.blockedUntil <= now) {
      client.blocked = false;
      client.blockedUntil = null;
    }
    
    // Clean old requests
    client.requests = client.requests.filter(t => t > now - windowMs);
    
    // Check limit
    const limit = CONFIG.rateLimit || 100;
    if (client.requests.length >= limit) {
      client.blocked = true;
      client.blockedUntil = now + windowMs;
      this.logConnectionEvent('rate_limit_exceeded', { ip, requests: client.requests.length });
      return { allowed: false, remaining: 0, resetIn: windowMs };
    }
    
    // Track request
    client.requests.push(now);
    client.totalRequests++;
    
    return { 
      allowed: true, 
      remaining: limit - client.requests.length,
      resetIn: windowMs - (now - client.requests[0])
    };
  }

  /**
   * Get rate limit stats
   */
  getRateLimitStats() {
    const stats = {
      totalClients: this.clientRateLimits.size,
      blockedClients: 0,
      topClients: [],
    };
    
    for (const [ip, client] of this.clientRateLimits) {
      if (client.blocked) stats.blockedClients++;
      stats.topClients.push({
        ip: ip.replace(/\d+$/, 'xxx'), // Anonymize last octet
        totalRequests: client.totalRequests,
        recentRequests: client.requests.length,
        blocked: client.blocked,
      });
    }
    
    stats.topClients.sort((a, b) => b.totalRequests - a.totalRequests);
    stats.topClients = stats.topClients.slice(0, 10);
    
    return stats;
  }

  // ==================== STARTUP DIAGNOSTICS ====================

  /**
   * Run startup diagnostics
   */
  async runStartupDiagnostics() {
    console.log('🔍 Running startup diagnostics...');
    this.diagnostics.startupTime = Date.now();
    this.diagnostics.checks = {};
    this.diagnostics.warnings = [];
    this.diagnostics.errors = [];
    
    // Check 1: Data directory writable
    try {
      const testFile = path.join(CONFIG.dataDir, '.test-write');
      fs.writeFileSync(testFile, 'test');
      fs.unlinkSync(testFile);
      this.diagnostics.checks.dataDirectory = { status: 'pass', message: 'Data directory is writable' };
    } catch (err) {
      this.diagnostics.checks.dataDirectory = { status: 'fail', message: err.message };
      this.diagnostics.errors.push('Data directory not writable: ' + err.message);
    }
    
    // Check 2: HTTP port available
    try {
      const server = require('http').createServer();
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.once('listening', () => {
          server.close();
          resolve();
        });
        server.listen(EFFECTIVE_HTTP_PORT);
      });
      this.diagnostics.checks.httpPort = { status: 'pass', message: `Port ${EFFECTIVE_HTTP_PORT} available` };
    } catch (err) {
      if (err.code === 'EADDRINUSE') {
        this.diagnostics.checks.httpPort = { status: 'warn', message: `Port ${EFFECTIVE_HTTP_PORT} may be in use` };
        this.diagnostics.warnings.push(`HTTP port ${EFFECTIVE_HTTP_PORT} may already be in use`);
      } else {
        this.diagnostics.checks.httpPort = { status: 'fail', message: err.message };
      }
    }
    
    // Check 3: Internet connectivity
    try {
      const https = require('https');
      await new Promise((resolve, reject) => {
        const req = https.get('https://autho.pinkmahi.com/api/health', { timeout: 5000 }, (res) => {
          resolve(res.statusCode);
        });
        req.on('error', reject);
        req.on('timeout', () => reject(new Error('Timeout')));
      });
      this.diagnostics.checks.internet = { status: 'pass', message: 'Internet connectivity confirmed' };
    } catch (err) {
      this.diagnostics.checks.internet = { status: 'warn', message: 'Could not reach seed node' };
      this.diagnostics.warnings.push('Internet connectivity issue: ' + err.message);
    }
    
    // Check 4: Memory available
    const memUsage = process.memoryUsage();
    const heapUsedMB = Math.round(memUsage.heapUsed / 1048576);
    const heapTotalMB = Math.round(memUsage.heapTotal / 1048576);
    if (heapUsedMB < heapTotalMB * 0.8) {
      this.diagnostics.checks.memory = { status: 'pass', message: `${heapUsedMB}MB / ${heapTotalMB}MB used` };
    } else {
      this.diagnostics.checks.memory = { status: 'warn', message: `High memory usage: ${heapUsedMB}MB / ${heapTotalMB}MB` };
      this.diagnostics.warnings.push('High memory usage detected');
    }
    
    // Check 5: Node.js version
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
    if (majorVersion >= 16) {
      this.diagnostics.checks.nodeVersion = { status: 'pass', message: `Node.js ${nodeVersion}` };
    } else {
      this.diagnostics.checks.nodeVersion = { status: 'warn', message: `Node.js ${nodeVersion} - recommend v16+` };
      this.diagnostics.warnings.push('Node.js version below recommended (v16+)');
    }
    
    // Summary
    const passed = Object.values(this.diagnostics.checks).filter(c => c.status === 'pass').length;
    const warned = Object.values(this.diagnostics.checks).filter(c => c.status === 'warn').length;
    const failed = Object.values(this.diagnostics.checks).filter(c => c.status === 'fail').length;
    
    console.log(`✅ Diagnostics: ${passed} passed, ${warned} warnings, ${failed} failed`);
    
    if (failed > 0) {
      console.log('❌ Critical issues found:');
      this.diagnostics.errors.forEach(e => console.log('  - ' + e));
    }
    
    if (warned > 0) {
      console.log('⚠️ Warnings:');
      this.diagnostics.warnings.forEach(w => console.log('  - ' + w));
    }
    
    return this.diagnostics;
  }

  /**
   * Get diagnostics report
   */
  getDiagnosticsReport() {
    return {
      ...this.diagnostics,
      uptimeMs: this.diagnostics.startupTime ? Date.now() - this.diagnostics.startupTime : 0,
      runtime: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        pid: process.pid,
        memory: process.memoryUsage(),
      },
    };
  }

  // ==================== RECONNECT WITH JITTER ====================

  /**
   * Calculate reconnect delay with exponential backoff and jitter
   */
  getReconnectDelay(attemptNumber, baseDelay = 1000, maxDelay = 60000) {
    // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s
    const exponentialDelay = Math.min(maxDelay, baseDelay * Math.pow(2, attemptNumber));
    
    // Add random jitter (±25%) to prevent thundering herd
    const jitter = exponentialDelay * 0.25 * (Math.random() * 2 - 1);
    
    return Math.round(exponentialDelay + jitter);
  }

  /**
   * Schedule reconnect with jitter
   */
  scheduleReconnectWithJitter(operatorUrl, attemptNumber = 0) {
    const delay = this.getReconnectDelay(attemptNumber);
    console.log(`🔄 Scheduling reconnect to ${operatorUrl} in ${delay}ms (attempt ${attemptNumber + 1})`);
    
    setTimeout(() => {
      this.connectToOperator(operatorUrl)
        .catch(err => {
          console.error(`❌ Reconnect failed for ${operatorUrl}:`, err.message);
          // Schedule next attempt with increased backoff
          if (attemptNumber < 10) {
            this.scheduleReconnectWithJitter(operatorUrl, attemptNumber + 1);
          } else {
            console.log(`⚠️ Max reconnect attempts reached for ${operatorUrl}`);
          }
        });
    }, delay);
  }

  handleSeedMessage(seed, message, ws = null) {
    switch (message.type) {
      case 'sync_response':
        console.log(`📥 Received sync data from seed: ${seed}`);
        this.registryData = message.state || message.data || {};
        break;

      case 'sync_data':
        console.log(`📥 Received sync data from seed: ${seed}`);
        this.registryData = message.state || message.data || {};
        break;
      
      case 'registry_update':
        console.log(`📥 Received registry update from seed: ${seed}`);
        if (message.data && message.data.sequenceNumber && message.data.lastEventHash) {
          this.registryData = {
            sequenceNumber: message.data.sequenceNumber,
            lastEventHash: message.data.lastEventHash,
          };
        }
        this.broadcastToPeers(message);
        break;
      
      case 'state_verification':
        // Gateway acknowledges consensus verification from network
        console.log(`✓ State verification from ${message.nodeId} (seq: ${message.sequenceNumber})`);
        break;
      
      // Communications ledger sync
      case 'ephemeral_event':
        if (this.storeEphemeralEvent(message.event)) {
          this.broadcastToPeers(message);
        }
        break;
      
      case 'ephemeral_sync_request':
        this.handleEphemeralSyncRequest(message, ws || this.getOperatorWs(seed));
        break;
      
      case 'ephemeral_sync_response':
        if (Array.isArray(message.events)) {
          let imported = 0;
          for (const event of message.events) {
            if (this.storeEphemeralEvent(event)) imported++;
          }
          if (imported > 0) {
            console.log(`📥 [Ephemeral] Imported ${imported} events from ${seed}`);
          }
        }
        break;
      
      // Gossip protocol - peer sharing
      case 'gossip_peers':
        this.handleGossipPeers(message.peers);
        break;
      
      default:
        console.log(`📨 Unknown message from seed ${seed}:`, message.type);
    }
  }

  broadcastToPeers(message) {
    this.peers.forEach((ws, peerId) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
      }
    });
  }

  getFromCache(key) {
    if (!CONFIG.cacheEnabled) return null;
    
    const cached = this.cache.get(key);
    if (!cached) return null;
    
    if (Date.now() - cached.timestamp > CONFIG.cacheTTL) {
      this.cache.delete(key);
      return null;
    }
    
    return cached.data;
  }

  setCache(key, data) {
    if (!CONFIG.cacheEnabled) return;
    
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  async start() {
    console.log('🌐 Starting Autho Gateway Node (Package Version)');
    console.log('===============================================');
    console.log(`📡 HTTP Port: ${EFFECTIVE_HTTP_PORT}`);
    console.log(`📡 WebSocket Port: ${EFFECTIVE_WS_PORT}`);
    console.log(`🌐 Seed Nodes: ${CONFIG.seedNodes.join(', ')}`);
    console.log(`🧭 Operator URLs: ${this.operatorUrls.join(', ')}`);
    console.log(`📁 Data Directory: ${CONFIG.dataDir}`);
    console.log(`💻 Platform: ${os.platform()}`);
    console.log(`🆔 Gateway ID: ${this.gatewayId}`);
    console.log('');

    // Run startup diagnostics
    await this.runStartupDiagnostics();
    console.log('');

    // Create data directory
    if (!fs.existsSync(CONFIG.dataDir)) {
      fs.mkdirSync(CONFIG.dataDir, { recursive: true });
      console.log(`📁 Created data directory: ${CONFIG.dataDir}`);
    }

    if (!fs.existsSync(this.uiCacheDir)) {
      fs.mkdirSync(this.uiCacheDir, { recursive: true });
    }

    // Load existing data
    const dataFile = path.join(CONFIG.dataDir, 'registry.json');
    if (fs.existsSync(dataFile)) {
      try {
        const data = fs.readFileSync(dataFile, 'utf8');
        this.registryData = JSON.parse(data);
        console.log('📚 Loaded existing registry data');
      } catch (error) {
        console.error('❌ Failed to load registry data:', error);
      }
    }
    
    // Load communications ledger
    this.loadEphemeralLedger();

    // Start HTTP server
    this.app.listen(EFFECTIVE_HTTP_PORT, () => {
      console.log('');
      console.log('✅ Gateway Node is running!');
      console.log('========================');
      console.log(`🌐 HTTP API: http://localhost:${EFFECTIVE_HTTP_PORT}`);
      console.log(`📡 WebSocket: ws://localhost:${EFFECTIVE_WS_PORT}`);
      console.log(`📊 Health: http://localhost:${EFFECTIVE_HTTP_PORT}/health`);
      console.log(`📈 Stats: http://localhost:${EFFECTIVE_HTTP_PORT}/stats`);
      console.log(`🔍 Registry: http://localhost:${EFFECTIVE_HTTP_PORT}/api/registry/state`);
      console.log(`⚙️  Config: http://localhost:${EFFECTIVE_HTTP_PORT}/api/config`);
      console.log('');
      console.log('🎯 Connected to Autho Network');
      console.log('🔒 Seed nodes are hardcoded and cannot be modified');
      if (this.isPublicGateway) {
        console.log('');
        console.log('🌍 PUBLIC GATEWAY MODE ENABLED');
        console.log(`   Public URL: ${this.publicHttpUrl || 'Not configured'}`);
        console.log('   This gateway serves UI files and is discoverable by others');
      } else {
        console.log('');
        console.log('💡 To make this gateway PUBLIC and help the network:');
        console.log(`   POST http://localhost:${EFFECTIVE_HTTP_PORT}/api/public-access/enable`);
        console.log('   Or set GATEWAY_PUBLIC=true before starting');
      }
      console.log('');
      console.log('Press Ctrl+C to stop');
    });

    // Setup WebSocket
    this.setupWebSocket();

    // Multi-source bootstrap discovery - makes network unkillable
    await this.bootstrapDiscovery();

    // Download UI files for public gateway mode
    if (this.isPublicGateway) {
      await this.downloadUiBundle();
      // Refresh UI periodically (every hour)
      setInterval(() => this.downloadUiBundle(), 60 * 60 * 1000);
    }

    // Connect to operators with discovery
    await this.connectToOperators();

    // Fallback: also try legacy seed connection
    this.connectToSeeds();

    // Start useful work (network verification)
    this.startUsefulWork();

    // Initialize retry queue for failed requests
    this.initRetryQueue();

    // Start gateway-to-gateway mesh
    this.startGatewayMesh();

    // Periodic operator discovery refresh (every 5 minutes)
    setInterval(async () => {
      try {
        await this.connectToOperators();
      } catch (error) {
        console.error('❌ Operator discovery refresh failed:', error);
      }
    }, 300000);

    // Start gossip protocol (share peers every minute)
    setInterval(() => {
      this.gossipPeers();
    }, this.gossipInterval);

    // Auto-register as public gateway if enabled
    if (this.isPublicGateway && this.publicHttpUrl) {
      this.registerAsPublicGateway();
      // Re-register every 10 minutes to maintain presence
      setInterval(() => this.registerAsPublicGateway(), 600000);
    }

    // Auto-enable public access if GATEWAY_AUTO_PUBLIC=true (for home users)
    if (process.env.GATEWAY_AUTO_PUBLIC === 'true' || process.env.AUTHO_AUTO_PUBLIC === 'true') {
      console.log('🌍 Auto-enabling public access...');
      this.enablePublicAccess().then(success => {
        if (success) {
          this.isPublicGateway = true;
          this.publicHttpUrl = this.publicAccessUrl;
          this.registerAsPublicGateway();
          this.downloadUiBundle();
        }
      });
    }

    // Adaptive ledger seed refresh (adjusts based on network health)
    const startAdaptiveRefresh = async () => {
      const nextInterval = await this.refreshSeedsFromLedger();
      setTimeout(startAdaptiveRefresh, nextInterval);
    };
    setTimeout(startAdaptiveRefresh, 60000); // First refresh after 1 minute

    // Connection pool management - prune stale connections every 2 minutes
    setInterval(() => {
      this.pruneStaleConnections();
    }, 120000);

    // Network partition detection - check every 3 minutes
    setInterval(() => {
      this.detectNetworkPartition();
    }, 180000);

    // Hourly stats recording
    setInterval(() => {
      this.recordHourlyStats();
    }, 3600000); // Every hour

    // Periodic data save
    setInterval(() => {
      try {
        if (!fs.existsSync(CONFIG.dataDir)) {
          fs.mkdirSync(CONFIG.dataDir, { recursive: true });
        }
        fs.writeFileSync(dataFile, JSON.stringify(this.registryData, null, 2));
      } catch (error) {
        console.error('❌ Failed to save registry data:', error);
      }
      
      // Save communications ledger
      this.saveEphemeralLedger();
    }, 60000);
  }

  async stop() {
    console.log('🛑 Stopping Gateway Node...');
    
    // Disable public access and cleanup NAT/tunnel
    if (this.publicAccessEnabled) {
      await this.disablePublicAccess();
      console.log('🌍 Public access disabled');
    }
    
    // Close all operator connections
    for (const [opId, conn] of this.operatorConnections) {
      try {
        if (conn.ws) conn.ws.close();
      } catch (e) {}
    }
    this.operatorConnections.clear();
    console.log('📡 Operator connections closed');
    
    // Close gateway peer connections
    for (const [gwId, ws] of this.gatewayPeerConnections) {
      try {
        ws.close();
      } catch (e) {}
    }
    this.gatewayPeerConnections.clear();
    console.log('🔗 Gateway peer connections closed');
    
    // Save data
    const dataFile = path.join(CONFIG.dataDir, 'registry.json');
    try {
      if (!fs.existsSync(CONFIG.dataDir)) {
        fs.mkdirSync(CONFIG.dataDir, { recursive: true });
      }
      fs.writeFileSync(dataFile, JSON.stringify(this.registryData, null, 2));
      console.log('💾 Saved registry data');
    } catch (error) {
      console.error('❌ Failed to save registry data:', error);
    }
    
    // Save cached seeds
    this.saveCachedSeeds();
    console.log('💾 Saved cached seeds');
    
    // Save communications ledger
    this.saveEphemeralLedger();
    console.log(`💾 Saved ${this.ephemeralEvents.size} communications ledger events`);
    
    // Close WebSocket server
    if (this.wsServer) {
      this.wsServer.close();
      console.log('📡 WebSocket server closed');
    }
    
    console.log('✅ Gateway Node stopped gracefully');
  }

  /**
   * Start useful work loops
   * Gateways contribute to network security by performing verification work
   */
  startUsefulWork() {
    console.log('🔧 Starting useful work loops...');

    // Health check every 2 minutes
    setInterval(() => this.performHealthChecks(), 2 * 60 * 1000);

    // Consistency check every 3 minutes
    setInterval(() => this.performConsistencyCheck(), 3 * 60 * 1000);

    // Initial checks after 30 seconds
    setTimeout(() => {
      this.performHealthChecks();
      this.performConsistencyCheck();
    }, 30000);
  }

  /**
   * Perform health checks on all known operators
   */
  async performHealthChecks() {
    const operators = this.getCandidateOperatorUrls();
    if (operators.length === 0) return;

    console.log('🏥 Performing operator health checks...');
    this.usefulWorkStats.healthChecks++;
    this.usefulWorkStats.lastWorkAt = Date.now();

    let online = 0;
    let offline = 0;

    for (const operatorUrl of operators) {
      const startTime = Date.now();
      try {
        const response = await fetch(`${operatorUrl}/api/consensus/status`, {
          signal: AbortSignal.timeout(10000),
        });
        
        const latency = Date.now() - startTime;
        
        if (response.ok) {
          const data = await response.json();
          // Parse sequence and hash from various possible field locations
          const sequence = data.ledger?.sequenceNumber || data.ledgerSequence || data.currentSequence || data.sequenceNumber || 0;
          const hash = data.ledger?.lastEventHash || data.currentHash || data.lastEventHash || '';
          
          this.operatorHealth.set(operatorUrl, {
            url: operatorUrl,
            status: data.success !== false ? 'online' : 'degraded',
            latencyMs: latency,
            lastChecked: Date.now(),
            sequence: sequence,
            hash: hash,
          });
          online++;
        } else {
          this.operatorHealth.set(operatorUrl, {
            url: operatorUrl,
            status: 'degraded',
            latencyMs: latency,
            lastChecked: Date.now(),
            sequence: 0,
            hash: '',
          });
          offline++;
        }
      } catch (error) {
        this.operatorHealth.set(operatorUrl, {
          url: operatorUrl,
          status: 'offline',
          latencyMs: -1,
          lastChecked: Date.now(),
          sequence: 0,
          hash: '',
        });
        offline++;
      }
    }

    this.usefulWorkStats.operatorsOnline = online;
    this.usefulWorkStats.operatorsOffline = offline;

    console.log(`🏥 Health check complete: ${online} online, ${offline} offline`);

    this.verificationResults.push({
      timestamp: Date.now(),
      type: 'health',
      success: offline === 0,
      details: { online, offline, total: operators.length },
    });

    if (this.verificationResults.length > 100) {
      this.verificationResults = this.verificationResults.slice(-100);
    }
  }

  /**
   * Perform cross-operator consistency check
   */
  async performConsistencyCheck() {
    const onlineOperators = Array.from(this.operatorHealth.values())
      .filter(op => op.status === 'online');

    if (onlineOperators.length < 2) return;

    console.log('🔍 Performing cross-operator consistency check...');
    this.usefulWorkStats.consistencyChecks++;
    this.usefulWorkStats.lastWorkAt = Date.now();

    const sequences = new Set();
    const hashes = new Set();

    for (const op of onlineOperators) {
      if (op.sequence > 0) sequences.add(op.sequence);
      if (op.hash) hashes.add(op.hash);
    }

    const sequenceConsistent = sequences.size <= 1;
    const hashConsistent = hashes.size <= 1;
    const isConsistent = sequenceConsistent && hashConsistent;

    if (isConsistent) {
      this.usefulWorkStats.consistencyPassed++;
      console.log('✅ Consistency check PASSED - all operators in sync');
    } else {
      this.usefulWorkStats.consistencyFailed++;
      console.log('⚠️ Consistency check FAILED - operators have divergent state');
    }

    this.verificationResults.push({
      timestamp: Date.now(),
      type: 'consistency',
      success: isConsistent,
      details: {
        operatorsChecked: onlineOperators.length,
        sequences: Array.from(sequences),
        hashes: Array.from(hashes),
      },
    });

    if (this.verificationResults.length > 100) {
      this.verificationResults = this.verificationResults.slice(-100);
    }
  }

  // ============================================================
  // COMMUNICATIONS LEDGER METHODS (ephemeral messages backup)
  // ============================================================
  
  storeEphemeralEvent(event) {
    if (!event || !event.eventId) return false;
    if (this.ephemeralEvents.has(event.eventId)) return false;
    if (event.expiresAt && event.expiresAt <= Date.now()) return false;
    
    this.ephemeralEvents.set(event.eventId, event);
    
    // Index contacts
    if (event.eventType === 'CONTACT_ADDED' && event.payload) {
      const { userId, contactId } = event.payload;
      if (userId && contactId) {
        if (!this.ephemeralContactsByUser.has(userId)) {
          this.ephemeralContactsByUser.set(userId, new Set());
        }
        this.ephemeralContactsByUser.get(userId).add(contactId);
      }
    }
    return true;
  }
  
  handleEphemeralSyncRequest(message, responseWs) {
    const sinceTimestamp = Number(message.since || 0);
    const maxEvents = Math.min(Number(message.limit || 500), 1000);
    const now = Date.now();
    const events = [];
    
    for (const event of this.ephemeralEvents.values()) {
      if (event.timestamp > sinceTimestamp && (!event.expiresAt || event.expiresAt > now)) {
        events.push(event);
        if (events.length >= maxEvents) break;
      }
    }
    
    events.sort((a, b) => a.timestamp - b.timestamp);
    
    // Respond on the WebSocket that sent the request (not always seedWs)
    const ws = responseWs || this.seedWs;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: 'ephemeral_sync_response',
        events,
        sinceTimestamp,
        latestTimestamp: this.getLatestEphemeralTimestamp(),
      }));
      console.log(`📤 [Ephemeral] Sent ${events.length} events in sync response`);
    }
  }
  
  // Helper to get operator WebSocket by ID
  getOperatorWs(operatorId) {
    const conn = this.operatorConnections.get(operatorId);
    return conn?.ws || null;
  }
  
  getLatestEphemeralTimestamp() {
    let latest = 0;
    for (const event of this.ephemeralEvents.values()) {
      if (event.timestamp > latest) latest = event.timestamp;
    }
    return latest;
  }
  
  loadEphemeralLedger() {
    const filePath = path.join(CONFIG.dataDir, 'communications-ledger.json');
    try {
      if (fs.existsSync(filePath)) {
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const now = Date.now();
        for (const event of (data.events || [])) {
          if (!event.expiresAt || event.expiresAt > now) {
            this.ephemeralEvents.set(event.eventId, event);
            if (event.eventType === 'CONTACT_ADDED' && event.payload) {
              const { userId, contactId } = event.payload;
              if (userId && contactId) {
                if (!this.ephemeralContactsByUser.has(userId)) {
                  this.ephemeralContactsByUser.set(userId, new Set());
                }
                this.ephemeralContactsByUser.get(userId).add(contactId);
              }
            }
          }
        }
        console.log(`📚 Loaded ${this.ephemeralEvents.size} communications ledger events`);
      }
    } catch (e) {
      console.error('Failed to load communications ledger:', e.message);
    }
  }
  
  saveEphemeralLedger() {
    const filePath = path.join(CONFIG.dataDir, 'communications-ledger.json');
    try {
      const data = {
        version: 1,
        savedAt: Date.now(),
        events: Array.from(this.ephemeralEvents.values()),
      };
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    } catch (e) {
      console.error('Failed to save communications ledger:', e.message);
    }
  }

  // ==================== GATEWAY-TO-GATEWAY MESH ====================

  async registerAsPublicGateway() {
    if (!this.isPublicGateway || !this.publicHttpUrl) {
      console.log('🔒 Gateway is private (not registering with network)');
      return;
    }

    console.log(`📢 Registering as public gateway: ${this.gatewayId}`);
    
    for (const operatorUrl of this.operatorUrls) {
      try {
        const response = await fetch(`${operatorUrl}/api/network/gateways/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            gatewayId: this.gatewayId,
            httpUrl: this.publicHttpUrl,
            wsUrl: this.publicHttpUrl.replace('https://', 'wss://').replace('http://', 'ws://') + `:${EFFECTIVE_WS_PORT}`,
            version: '1.0.6',
          }),
        });
        
        if (response.ok) {
          console.log(`✅ Registered with operator: ${operatorUrl}`);
          return;
        }
      } catch (error) {
        console.log(`⚠️  Failed to register with ${operatorUrl}: ${error.message}`);
      }
    }
  }

  async discoverGateways() {
    const now = Date.now();
    if (now - this.lastGatewayDiscovery < 300000 && this.discoveredGateways.length > 0) {
      return this.discoveredGateways;
    }

    console.log('🔍 Discovering peer gateways...');
    
    for (const operatorUrl of this.operatorUrls) {
      try {
        const response = await fetch(`${operatorUrl}/api/network/gateways`);
        const data = await response.json();

        if (data && data.success && Array.isArray(data.gateways)) {
          // Filter out self
          this.discoveredGateways = data.gateways.filter(gw => gw.gatewayId !== this.gatewayId);
          this.lastGatewayDiscovery = now;
          console.log(`✅ Discovered ${this.discoveredGateways.length} peer gateways`);
          return this.discoveredGateways;
        }
      } catch (error) {
        console.log(`⚠️  Failed to discover gateways from ${operatorUrl}: ${error.message}`);
      }
    }

    return [];
  }

  async connectToGatewayPeers() {
    await this.discoverGateways();

    for (const gw of this.discoveredGateways) {
      if (!gw.wsUrl) continue;
      if (this.gatewayPeerConnections.has(gw.gatewayId)) {
        const existing = this.gatewayPeerConnections.get(gw.gatewayId);
        if (existing.ws && existing.ws.readyState === WebSocket.OPEN) {
          continue;
        }
      }

      this.connectToGatewayPeer(gw);
    }
  }

  connectToGatewayPeer(gateway) {
    const { gatewayId, wsUrl } = gateway;
    
    try {
      console.log(`🔗 Connecting to gateway peer: ${gatewayId}`);
      const ws = new WebSocket(wsUrl);
      const connectionInfo = {
        ws,
        gatewayId,
        wsUrl,
        connectedAt: null,
        lastSeen: null,
      };

      ws.on('open', () => {
        console.log(`✅ Connected to gateway peer: ${gatewayId}`);
        connectionInfo.connectedAt = Date.now();
        connectionInfo.lastSeen = Date.now();

        ws.send(JSON.stringify({
          type: 'gateway_handshake',
          gatewayId: this.gatewayId,
          timestamp: Date.now()
        }));
      });

      ws.on('message', (data) => {
        try {
          connectionInfo.lastSeen = Date.now();
          const message = JSON.parse(data.toString());
          this.handleGatewayPeerMessage(gatewayId, message, ws);
        } catch (error) {
          console.error(`❌ Invalid message from gateway ${gatewayId}:`, error);
        }
      });

      ws.on('close', () => {
        console.log(`❌ Disconnected from gateway peer: ${gatewayId}`);
        this.gatewayPeerConnections.delete(gatewayId);
        // Reconnect after delay
        setTimeout(() => this.connectToGatewayPeer(gateway), 30000);
      });

      ws.on('error', (error) => {
        console.error(`❌ WebSocket error for gateway ${gatewayId}:`, error.message);
      });

      this.gatewayPeerConnections.set(gatewayId, connectionInfo);
    } catch (error) {
      console.error(`❌ Failed to connect to gateway ${gatewayId}:`, error.message);
    }
  }

  handleGatewayPeerMessage(gatewayId, message, ws) {
    switch (message.type) {
      case 'gateway_handshake':
        console.log(`🤝 Gateway handshake from: ${message.gatewayId}`);
        ws.send(JSON.stringify({
          type: 'gateway_handshake_ack',
          gatewayId: this.gatewayId,
          timestamp: Date.now()
        }));
        break;

      case 'gateway_handshake_ack':
        console.log(`✓ Gateway handshake acknowledged by: ${message.gatewayId}`);
        break;

      case 'registry_update':
        // Relay registry updates from gateway peers
        if (message.data && message.data.sequenceNumber > (this.registryData.sequenceNumber || 0)) {
          console.log(`📥 Registry update from gateway ${gatewayId}`);
          this.registryData = message.data;
          this.broadcastToPeers(message);
        }
        break;

      case 'ephemeral_event':
        // Relay ephemeral events from gateway peers
        if (this.storeEphemeralEvent(message.event)) {
          this.broadcastToPeers(message);
          this.broadcastToGatewayPeers(message, gatewayId); // Forward to other gateways except sender
        }
        break;

      default:
        console.log(`📨 Unknown message from gateway ${gatewayId}:`, message.type);
    }
  }

  broadcastToGatewayPeers(message, excludeGatewayId = null) {
    for (const [gatewayId, conn] of this.gatewayPeerConnections) {
      if (gatewayId === excludeGatewayId) continue;
      if (conn.ws && conn.ws.readyState === WebSocket.OPEN) {
        conn.ws.send(JSON.stringify(message));
      }
    }
  }

  startGatewayMesh() {
    // Register as public gateway if configured
    if (this.isPublicGateway) {
      this.registerAsPublicGateway();
      // Re-register every 5 minutes to maintain presence
      setInterval(() => this.registerAsPublicGateway(), 5 * 60 * 1000);
    }

    // Discover and connect to gateway peers every 5 minutes
    setInterval(() => this.connectToGatewayPeers(), 5 * 60 * 1000);

    // Initial connection after 10 seconds
    setTimeout(() => this.connectToGatewayPeers(), 10000);
  }
}

// Start the gateway node
if (require.main === module) {
  const gateway = new GatewayNode();
  
  process.on('SIGINT', async () => {
    console.log('\n🛑 Received SIGINT, shutting down gracefully...');
    await gateway.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.log('\n🛑 Received SIGTERM, shutting down gracefully...');
    await gateway.stop();
    process.exit(0);
  });

  gateway.start().catch(console.error);
}

module.exports = GatewayNode;
