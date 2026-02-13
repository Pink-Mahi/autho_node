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
const https = require('https');
const { execSync } = require('child_process');

// Generate self-signed HTTPS cert for localhost (required for getUserMedia in Firefox)
function getOrCreateSelfSignedCert(dataDir) {
  const sslDir = path.join(dataDir, 'ssl');
  const keyPath = path.join(sslDir, 'key.pem');
  const certPath = path.join(sslDir, 'cert.pem');

  // Return existing cert if present
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    try {
      return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
    } catch { /* regenerate */ }
  }

  fs.mkdirSync(sslDir, { recursive: true });

  // Try openssl (Linux/Mac/Windows with Git)
  const opensslPaths = ['openssl'];
  if (process.platform === 'win32') {
    opensslPaths.push(
      'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
      'C:\\Program Files (x86)\\Git\\usr\\bin\\openssl.exe',
      path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Git', 'usr', 'bin', 'openssl.exe')
    );
  }

  for (const opensslBin of opensslPaths) {
    try {
      execSync(
        `"${opensslBin}" req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 3650 -nodes -subj "/CN=localhost"`,
        { stdio: 'pipe', timeout: 10000 }
      );
      if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
        console.log('🔐 Generated self-signed HTTPS certificate for localhost');
        return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
      }
    } catch { /* try next */ }
  }

  console.warn('⚠️  Could not generate HTTPS cert (openssl not found)');
  console.warn('   Voice/video calls require HTTPS. Install Git (includes openssl) or use Chrome.');
  return null;
}

function loadGatewayEnvFile() {
  try {
    const envPath = path.join(__dirname, 'gateway.env');
    if (!fs.existsSync(envPath)) return;
    const raw = fs.readFileSync(envPath, 'utf8');
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const idx = trimmed.indexOf('=');
      if (idx <= 0) continue;
      const key = trimmed.slice(0, idx).trim();
      let value = trimmed.slice(idx + 1).trim();
      if (!key) continue;
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      if (process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch (e) {}
}

loadGatewayEnvFile();

const UI_CACHE_TTL_MS = (() => {
  const n = Number(process.env.AUTHO_UI_CACHE_TTL_MS);
  return Number.isFinite(n) && n >= 0 ? n : (5 * 60 * 1000);
})();

// HARD-CODED CONFIGURATION - USERS CANNOT MODIFY
// These are fallback seeds - the network will discover more dynamically
const CONFIG = {
  // Seed nodes - hardcoded as fallback (network discovers more dynamically)
  seedNodes: ['autho.pinkmahi.com', 'autho.cartpathcleaning.com', 'autho2.cartpathcleaning.com'],

  operatorUrls: ['https://autho.pinkmahi.com', 'https://autho.cartpathcleaning.com', 'https://autho2.cartpathcleaning.com'],

  // Optional bridge operator URLs (censorship bypass) - can be filled by env or community
  bridgeOperatorUrls: [],

  // Optional bridge seed hosts (censorship bypass)
  bridgeSeedNodes: [],
  
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
  rateLimitMax: 200,
  authRateLimitWindow: 900000, // 15 minutes
  authRateLimitMax: 300,
  
  // Data directory
  dataDir: './gateway-data'
};

// ============================================================
// PREMIUM FEATURES & MONETIZATION CONFIGURATION
// Fees are paid to the hardcoded sponsor wallet
// ============================================================
const PREMIUM_CONFIG = {
  // Sponsor wallet - receives all premium fees (HARDCODED - cannot be changed)
  sponsorAddress: '1FMcxZRUWVDbKy7DxAosW7sM5PUntAkJ9U',
  
  // Minimum fee (dust limit safe)
  minFeeSats: 1000,
  
  // Wallet transaction fees
  wallet: {
    sendFeeSats: 1000,           // Flat fee per transaction
    sendFeePercent: 0.001,       // 0.1% of amount (whichever is higher)
    sweepFeeSats: 500,           // Lower fee for sweep/consolidation
  },
  
  // Messaging premium features
  messaging: {
    deleteMessageSats: 1000,     // Per message deletion
    editMessageSats: 500,        // Per message edit
    extendedRetentionSats: 2000, // 30-day retention (per conversation)
    largeMediaSats: 1000,        // Files > 5MB
    createGroupSats: 2000,       // Create private group
    verifiedBadgeSats: 10000,    // One-time verified checkmark
  },
  
  // Subscription tiers (monthly, in sats)
  subscriptions: {
    free: {
      price: 0,
      features: ['basic_messaging', 'retention_10_days', 'media_5mb'],
    },
    pro: {
      price: 5000,
      features: ['delete_messages', 'edit_messages', 'retention_30_days', 'media_25mb'],
    },
    business: {
      price: 20000,
      features: ['unlimited_groups', 'verified_badge', 'retention_90_days', 'media_100mb', 'api_access'],
    },
  },
  
  // Grace period for payment verification (seconds)
  paymentGracePeriodSecs: 3600, // 1 hour to verify payment
  
  // Credit expiry (days)
  creditExpiryDays: 365,
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
    this._ledgerSaveTimer = null; // Debounce timer for async ledger saves
    this._ledgerSavePending = false; // Flag to track if save is pending
    
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
    
    // Premium features - user credits and subscriptions
    this.userCredits = new Map(); // accountId -> { credits: number, features: [], subscription: string, expiresAt: number }
    this.pendingPayments = new Map(); // paymentId -> { accountId, amount, feature, createdAt, address }
    this.paymentHistory = []; // Array of verified payments
    
    // Prepaid service balance - standalone (works without main node/operators)
    this.serviceBalances = new Map(); // accountId -> { serviceBalanceSats, lastFundedAt, totalFunded, totalUsed }
    this.servicePaymentHistory = new Map(); // txid -> { accountId, amountSats, timestamp, confirmations }
    
    // Seed health tracking - prefer healthy seeds over failing ones
    this.seedHealth = new Map(); // url -> { lastSuccess, lastFailure, failCount, latencyMs }
    
    // Reconnection state with exponential backoff
    this.reconnectAttempts = 0;
    this.reconnectTimer = null;
    this.currentReconnectDelay = CONFIG.reconnect.initialDelayMs;
    this.operatorReconnectTimers = new Map(); // operatorId -> timeout
    
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
    
    // Messaging WebSocket connections (for /ws/messaging on HTTP port)
    this.messagingClients = new Map(); // ws -> { publicKey, conversationId, groupId }
    this.messagingWss = null;
    
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
    const bridgeRaw = process.env.AUTHO_BRIDGE_OPERATOR_URLS || process.env.BRIDGE_OPERATOR_URLS;
    const bridgeList = bridgeRaw
      ? bridgeRaw.split(',').map(s => s.trim()).filter(Boolean)
      : (CONFIG.bridgeOperatorUrls || []);
    const discoveredUrls = new Set([
      ...cachedSeeds,
      ...CONFIG.operatorUrls,
      ...bridgeList,
    ]);

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
    const bridgeRaw = process.env.AUTHO_BRIDGE_OPERATOR_URLS || process.env.BRIDGE_OPERATOR_URLS;
    const bridgeList = bridgeRaw
      ? bridgeRaw.split(',').map(s => s.trim()).filter(Boolean)
      : (CONFIG.bridgeOperatorUrls || []);
    const normalized = [...list, ...bridgeList]
      .map(u => this.normalizeOperatorUrl(u))
      .filter(Boolean);
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

    const bridgeRaw = process.env.AUTHO_BRIDGE_SEEDS || process.env.BRIDGE_SEEDS;
    const bridgeRequested = bridgeRaw ? bridgeRaw.split(',').map(s => s.trim()).filter(Boolean) : [];

    const fromEnv = requested.map(s => this.normalizeSeed(s)).filter(Boolean);
    const fromBridgeEnv = bridgeRequested.map(s => this.normalizeSeed(s)).filter(Boolean);

    const fromConfig = (CONFIG.seedNodes || []).map(s => this.normalizeSeed(s)).filter(Boolean);
    const fromBridgeConfig = (CONFIG.bridgeSeedNodes || []).map(s => this.normalizeSeed(s)).filter(Boolean);
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
    for (const s of [...fromBridgeEnv, ...fromBridgeConfig, ...fromEnv, ...fromConfig, ...fromOperators]) {
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
    // Serve landing.html as the default page (gold/black Autho branding)
    const logical = needsIndex ? `${safe}landing.html` : safe;
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

    const isMessagingKeyEndpoint = originalUrl.startsWith('/api/messages/keys');
    const isMessagingKeyLookup = isMessagingKeyEndpoint && req.method === 'GET';
    const isMessagingKeyPublish = isMessagingKeyEndpoint && req.method === 'POST';

    const isMessagingVaultEndpoint = originalUrl.startsWith('/api/messages/vault');
    const isMessagingVaultLookup = isMessagingVaultEndpoint && req.method === 'GET';
    const isMessagingVaultPublish = isMessagingVaultEndpoint && req.method === 'POST';

    const isMessagingEndpoint = originalUrl.startsWith('/api/messages/');

    if (!isAuthEndpoint && !isMessagingEndpoint) {
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

    const publishResults = [];

    for (const operatorUrl of this.getCandidateOperatorUrls()) {
      try {
        if (isWrite && !isAuthEndpoint && !isMessagingEndpoint) {
          await this.assertSyncedForWrite(operatorUrl);
        }

        const { resp, buf, contentType } = await this.forwardApiRequest(operatorUrl, req);

        const ct = (contentType || '').toLowerCase();
        if (originalUrl.startsWith('/api/') && ct.includes('text/html')) {
          errors.push({ operatorUrl, status: resp.status, error: 'Unexpected HTML response for API request' });
          continue;
        }

        if (isMessagingKeyLookup && resp.status === 404) {
          errors.push({ operatorUrl, status: resp.status });
          continue;
        }

        if (isMessagingVaultLookup && resp.status === 404) {
          errors.push({ operatorUrl, status: resp.status });
          continue;
        }

        if (isMessagingKeyPublish) {
          if (resp.status >= 200 && resp.status <= 299) {
            publishResults.push({ operatorUrl, status: resp.status });
            continue;
          }
          if (resp.status >= 500 && resp.status <= 599) {
            errors.push({ operatorUrl, status: resp.status });
            continue;
          }
          errors.push({ operatorUrl, status: resp.status, body: buf ? buf.toString('utf8').slice(0, 500) : undefined });
          continue;
        }

        if (isMessagingVaultPublish) {
          if (resp.status >= 200 && resp.status <= 299) {
            publishResults.push({ operatorUrl, status: resp.status });
            continue;
          }
          if (resp.status >= 500 && resp.status <= 599) {
            errors.push({ operatorUrl, status: resp.status });
            continue;
          }
          errors.push({ operatorUrl, status: resp.status, body: buf ? buf.toString('utf8').slice(0, 500) : undefined });
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

    if (isMessagingKeyPublish) {
      if (publishResults.length > 0) {
        res.json({ success: true, replicatedTo: publishResults.map(r => r.operatorUrl) });
        return;
      }
    }

    if (isMessagingVaultPublish) {
      if (publishResults.length > 0) {
        res.json({ success: true, replicatedTo: publishResults.map(r => r.operatorUrl) });
        return;
      }
    }

    res.status(502).json({
      error: 'No operator available',
      attemptedOperators: this.operatorUrls,
      failures: errors
    });
  }

  // Inject gateway dashboard banner into HTML content
  injectGatewayBanner(htmlBuffer) {
    let html = htmlBuffer.toString('utf8');
    if (html.includes('id="gw-banner"')) return htmlBuffer; // already injected
    const gatewayBanner = `<div id="gw-banner" style="position:fixed;bottom:10px;right:10px;z-index:99999;background:linear-gradient(135deg,#667eea,#764ba2);padding:8px 16px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.3);font-family:system-ui,sans-serif;font-size:13px;"><a href="/gateway-dashboard" style="color:#fff;text-decoration:none;display:flex;align-items:center;gap:6px;">⚡ Gateway Dashboard</a></div>`;
    if (html.includes('</body>')) {
      html = html.replace('</body>', gatewayBanner + '</body>');
      return Buffer.from(html, 'utf8');
    }
    return htmlBuffer;
  }

  async serveUi(req, res) {
    const filePath = this.getUiCacheFilePath(req.path);
    const isHtml = req.path.endsWith('.html') || req.path === '/' || !path.extname(req.path);
    if (fs.existsSync(filePath)) {
      try {
        const fresh = UI_CACHE_TTL_MS === 0 || (Date.now() - fs.statSync(filePath).mtimeMs) < UI_CACHE_TTL_MS;
        if (fresh) {
          // For HTML files, inject gateway banner on the fly
          if (isHtml) {
            const buf = fs.readFileSync(filePath);
            const contentType = req.path.endsWith('.html') ? 'text/html' : null;
            if (contentType) res.setHeader('Content-Type', contentType);
            res.send(this.injectGatewayBanner(buf));
          } else {
            res.sendFile(path.resolve(filePath));
          }
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

          let buf = Buffer.from(await resp.arrayBuffer());
          const contentType = resp.headers.get('content-type');
          
          // Inject gateway dashboard link into HTML pages
          if (contentType && contentType.includes('text/html')) {
            buf = this.injectGatewayBanner(buf);
          }
          
          fs.writeFileSync(filePath, buf);
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
    
    // Serve local public folder if it exists (for bundled UI files)
    const localPublicPath = path.join(__dirname, 'public');
    if (fs.existsSync(localPublicPath)) {
      this.app.use(express.static(localPublicPath));
      console.log(`📂 Serving static files from: ${localPublicPath}`);
    }

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
    const isAuth = req.path.startsWith('/api/auth');
    const key = isAuth ? `auth:${clientIp}` : clientIp;
    const window = isAuth ? CONFIG.authRateLimitWindow : CONFIG.rateLimitWindow;
    const max = isAuth ? CONFIG.authRateLimitMax : CONFIG.rateLimitMax;

    let clientData = this.rateLimitMap.get(key);
    if (!clientData || clientData.resetTime < now) {
      clientData = { count: 0, resetTime: now + window };
      this.rateLimitMap.set(key, clientData);
    }

    if (clientData.count >= max) {
      res.status(429).json({
        error: 'Rate limit exceeded',
        message: isAuth ? 'Too many login attempts, please try again later' : 'Too many requests, please try again later',
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

    // TURN discovery endpoint (self-hosted relay configuration)
    this.app.get('/api/network/turn', (req, res) => {
      try {
        const dataDir = CONFIG.dataDir || './gateway-data';
        const turnPath = path.join(dataDir, 'turn.json');
        let urls = [];
        let username = '';
        let credential = '';

        if (fs.existsSync(turnPath)) {
          try {
            const raw = JSON.parse(fs.readFileSync(turnPath, 'utf8')) || {};
            if (Array.isArray(raw.urls)) urls = raw.urls;
            if (raw.username) username = String(raw.username).trim();
            if (raw.credential) credential = String(raw.credential).trim();
          } catch {}
        }

        if ((!urls || !urls.length) && credential) {
          const host = String(req.headers.host || '').trim();
          if (host) {
            urls = [
              `turn:${host}:3478?transport=udp`,
              `turn:${host}:3478?transport=tcp`,
            ];
          }
        }

        res.json({
          success: true,
          turn: urls.length
            ? { urls, username: username || undefined, credential: credential || undefined }
            : null,
        });
      } catch (e) {
        res.status(500).json({ success: false, error: e?.message || 'Failed to load TURN config' });
      }
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

    // QR Code Dashboard - for retail display scenarios
    this.app.get('/api/gateway/qr-data', async (req, res) => {
      try {
        // Refresh peer gateways if stale
        await this.discoverGateways();
        
        const publicStatus = this.getPublicAccessStatus();
        const operators = this.operatorUrls.map(url => ({
          url,
          name: new URL(url).hostname,
          type: 'operator'
        }));
        
        const peerGateways = (this.discoveredGateways || []).map(gw => ({
          url: gw.publicUrl,
          name: gw.gatewayId,
          type: 'gateway',
          method: gw.method
        })).filter(g => g.url);
        
        res.json({
          success: true,
          gateway: {
            id: this.gatewayId,
            publicUrl: publicStatus.url,
            enabled: publicStatus.enabled,
            method: publicStatus.method,
            localUrl: `http://localhost:${EFFECTIVE_HTTP_PORT}`
          },
          operators,
          peerGateways,
          timestamp: Date.now()
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // QR Code Dashboard HTML page - self-contained with inline QR generation
    this.app.get('/gateway-dashboard', (req, res) => {
      res.setHeader('Content-Type', 'text/html');
      res.send(this.generateQrDashboardHtml());
    });

    // ============================================================
    // GATEWAY DOWNLOAD ENDPOINTS - P2P software distribution
    // Users can download gateway files from any running gateway
    // ============================================================

    // Serve gateway download files
    this.app.get('/downloads/gateway-node/:filename', (req, res) => {
      const { filename } = req.params;
      const allowedFiles = [
        'gateway-package.js',
        'package.json',
        'gateway.env',
        'Install-Autho-Gateway.bat',
        'install.sh',
        'README.md'
      ];
      
      if (!allowedFiles.includes(filename)) {
        return res.status(404).json({ error: 'File not found' });
      }
      
      // Serve from own installation directory or bundled files
      const localPath = path.join(__dirname, filename);
      if (fs.existsSync(localPath)) {
        return res.sendFile(localPath);
      }
      
      // Fallback: proxy from operator if we don't have the file locally
      this.proxyDownload(req, res, filename);
    });

    // List available gateway download files
    this.app.get('/downloads/gateway-node', (req, res) => {
      res.json({
        success: true,
        files: [
          { name: 'Install-Autho-Gateway.bat', description: 'Windows installer (double-click to install)', platform: 'windows' },
          { name: 'install.sh', description: 'Linux/Mac installer script', platform: 'unix' },
          { name: 'gateway-package.js', description: 'Gateway node source code', platform: 'all' },
          { name: 'package.json', description: 'Node.js dependencies', platform: 'all' },
          { name: 'gateway.env', description: 'Configuration template', platform: 'all' },
          { name: 'README.md', description: 'Documentation', platform: 'all' },
        ],
        quickInstall: {
          windows: 'powershell -Command "irm ' + (this.publicHttpUrl || `http://localhost:${EFFECTIVE_HTTP_PORT}`) + '/downloads/gateway-node/Install-Autho-Gateway.bat -OutFile Install.bat; .\\Install.bat"',
          unix: 'curl -sSL ' + (this.publicHttpUrl || `http://localhost:${EFFECTIVE_HTTP_PORT}`) + '/downloads/gateway-node/install.sh | bash',
        },
        source: this.gatewayId,
        timestamp: Date.now()
      });
    });

    // Gateway install page
    this.app.get('/install/gateway', (req, res) => {
      const publicDir = path.join(__dirname, 'public');
      const fp = path.join(publicDir, 'install-gateway.html');
      if (fs.existsSync(fp)) {
        return res.sendFile(fp);
      }
      // Fallback: serve inline install page
      res.send(this.generateInstallPage());
    });

    const normalizeRegistryItem = (item) => {
      if (!item || typeof item !== 'object') return item;
      return {
        ...item,
        assetClass: item.assetClass,
        accessPolicy: item.accessPolicy,
        contentCommitmentHash: item.contentCommitmentHash,
      };
    };

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

        res.json(normalizeRegistryItem(item));
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
        const items = Object.values(this.registryData.items || {})
          .filter(item => item.currentOwner === address)
          .map(normalizeRegistryItem);
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

    // ============================================================
    // BITCOIN CHAIN API - STANDALONE WALLET SUPPORT
    // Gateways can check balances and broadcast transactions directly
    // without needing operator nodes (uses mempool.space/blockstream.info)
    // ============================================================

    this.app.get('/api/chain/status', async (req, res) => {
      try {
        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const apiBase = network === 'mainnet'
          ? 'https://blockstream.info/api'
          : 'https://blockstream.info/testnet/api';

        res.json({
          ok: true,
          network,
          apiBase,
          timestamp: Date.now(),
          source: 'gateway',
        });
      } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
      }
    });

    this.app.get('/api/chain/address/:address', async (req, res) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          return res.status(400).json({ error: 'Missing address' });
        }

        const bases = this.getChainApiBases();
        let lastErr = null;

        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/address/${address}`);
            if (!response.ok) {
              lastErr = { status: response.status, text: await response.text() };
              continue;
            }
            return res.json(await response.json());
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          return res.status(lastErr.status).send(lastErr.text || 'Chain provider error');
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/address/:address/utxo', async (req, res) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          return res.status(400).json({ error: 'Missing address' });
        }

        const bases = this.getChainApiBases();
        let lastErr = null;

        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/address/${address}/utxo`);
            if (!response.ok) {
              lastErr = { status: response.status, text: await response.text() };
              continue;
            }
            return res.json(await response.json());
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          return res.status(lastErr.status).send(lastErr.text || 'Chain provider error');
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/address/:address/txs', async (req, res) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          return res.status(400).json({ error: 'Missing address' });
        }

        const bases = this.getChainApiBases();
        let lastErr = null;

        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/address/${address}/txs`);
            if (!response.ok) {
              lastErr = { status: response.status, text: await response.text() };
              continue;
            }
            return res.json(await response.json());
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          return res.status(lastErr.status).send(lastErr.text || 'Chain provider error');
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/address/:address/txs/mempool', async (req, res) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          return res.status(400).json({ error: 'Missing address' });
        }

        const bases = this.getChainApiBases();
        let lastErr = null;

        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/address/${address}/txs/mempool`);
            if (!response.ok) {
              lastErr = { status: response.status, text: await response.text() };
              continue;
            }
            return res.json(await response.json());
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          return res.status(lastErr.status).send(lastErr.text || 'Chain provider error');
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/tx/:txid/hex', async (req, res) => {
      try {
        const txid = String(req.params.txid || '').trim();
        if (!txid) {
          return res.status(400).json({ error: 'Missing txid' });
        }

        const bases = this.getChainApiBases();
        let lastErr = null;

        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/tx/${txid}/hex`);
            const text = await response.text();
            if (!response.ok) {
              lastErr = { status: response.status, text };
              continue;
            }
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            return res.send(text);
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          return res.status(lastErr.status).send(lastErr.text || 'Chain provider error');
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/tx/:txid/status', async (req, res) => {
      try {
        const txid = String(req.params.txid || '').trim();
        if (!txid) {
          return res.status(400).json({ error: 'Missing txid' });
        }

        const bases = this.getChainApiBases();
        let lastErr = null;

        for (const apiBase of bases) {
          try {
            const statusResp = await fetch(`${apiBase}/tx/${txid}/status`);
            const statusText = await statusResp.text();
            if (!statusResp.ok) {
              lastErr = { status: statusResp.status, text: statusText };
              continue;
            }

            const statusJson = JSON.parse(statusText);
            const confirmed = Boolean(statusJson?.confirmed);
            const blockHeight = confirmed ? Number(statusJson?.block_height || 0) : undefined;

            let tipHeight = 0;
            try {
              const tipResp = await fetch(`${apiBase}/blocks/tip/height`);
              const tipText = await tipResp.text();
              if (tipResp.ok) tipHeight = Number(String(tipText || '').trim());
            } catch {}

            const confirmations = confirmed && blockHeight && tipHeight && tipHeight >= blockHeight
              ? (tipHeight - blockHeight + 1)
              : 0;

            return res.json({
              ok: true,
              confirmed,
              confirmations,
              blockHeight: blockHeight || undefined,
              blockHash: statusJson?.block_hash,
              blockTime: statusJson?.block_time,
              provider: apiBase,
            });
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          return res.status(lastErr.status).send(lastErr.text || 'Chain provider error');
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/fee-estimates', async (req, res) => {
      try {
        const bases = this.getChainApiBases();
        let lastErr = null;

        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/fee-estimates`);
            if (!response.ok) {
              lastErr = { status: response.status, text: await response.text() };
              continue;
            }
            return res.json(await response.json());
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          return res.status(lastErr.status).send(lastErr.text || 'Chain provider error');
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Broadcast a signed transaction to the Bitcoin network
    this.app.post('/api/chain/tx', async (req, res) => {
      try {
        let txHex = '';
        if (req.body && typeof req.body === 'object') {
          txHex = String(req.body.txHex || '');
        }
        txHex = txHex.trim();

        if (!txHex) {
          return res.status(400).json({ success: false, error: 'Missing txHex' });
        }

        const bases = this.getChainApiBases();
        let lastErr = null;

        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/tx`, {
              method: 'POST',
              headers: { 'Content-Type': 'text/plain' },
              body: txHex,
            });

            const text = await response.text();
            if (!response.ok) {
              lastErr = { status: response.status, text };
              continue;
            }

            return res.json({ success: true, txid: text.trim(), provider: apiBase });
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          return res.status(lastErr.status).json({ success: false, error: lastErr.text || 'Chain provider error' });
        }
        res.status(502).json({ success: false, error: 'All chain providers failed' });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // PREMIUM FEATURES API - MONETIZATION
    // ============================================================

    // Get premium features pricing and user status
    this.app.get('/api/premium/status', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        const userStatus = account ? this.getUserPremiumStatus(account.accountId) : null;
        
        res.json({
          success: true,
          sponsorAddress: PREMIUM_CONFIG.sponsorAddress,
          pricing: {
            wallet: PREMIUM_CONFIG.wallet,
            messaging: PREMIUM_CONFIG.messaging,
            subscriptions: PREMIUM_CONFIG.subscriptions,
          },
          userStatus,
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Calculate wallet send fee for a transaction
    this.app.post('/api/premium/wallet/calculate-fee', async (req, res) => {
      try {
        const { amountSats } = req.body;
        if (!amountSats || amountSats <= 0) {
          return res.status(400).json({ success: false, error: 'Invalid amount' });
        }

        const fee = this.calculateWalletSendFee(amountSats);
        res.json({
          success: true,
          amountSats,
          platformFeeSats: fee,
          sponsorAddress: PREMIUM_CONFIG.sponsorAddress,
          totalWithFee: amountSats + fee,
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Request payment for a premium feature
    this.app.post('/api/premium/payment/request', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { feature, quantity = 1 } = req.body;
        if (!feature) {
          return res.status(400).json({ success: false, error: 'Feature required' });
        }

        const feeCost = this.getFeatureCost(feature);
        if (feeCost === null) {
          return res.status(400).json({ success: false, error: 'Invalid feature' });
        }

        const totalAmount = feeCost * quantity;
        const paymentId = `pay_${Date.now()}_${require('crypto').randomBytes(6).toString('hex')}`;

        const payment = {
          paymentId,
          accountId: account.accountId,
          feature,
          quantity,
          amountSats: totalAmount,
          sponsorAddress: PREMIUM_CONFIG.sponsorAddress,
          createdAt: Date.now(),
          expiresAt: Date.now() + (PREMIUM_CONFIG.paymentGracePeriodSecs * 1000),
          status: 'pending',
        };

        this.pendingPayments.set(paymentId, payment);

        res.json({
          success: true,
          payment: {
            paymentId,
            amountSats: totalAmount,
            address: PREMIUM_CONFIG.sponsorAddress,
            expiresAt: payment.expiresAt,
            feature,
            quantity,
          },
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Verify payment and grant credits
    this.app.post('/api/premium/payment/verify', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { paymentId, txid } = req.body;
        if (!paymentId || !txid) {
          return res.status(400).json({ success: false, error: 'paymentId and txid required' });
        }

        const payment = this.pendingPayments.get(paymentId);
        if (!payment) {
          return res.status(404).json({ success: false, error: 'Payment not found' });
        }

        if (payment.accountId !== account.accountId) {
          return res.status(403).json({ success: false, error: 'Payment belongs to different account' });
        }

        if (payment.status === 'verified') {
          return res.status(400).json({ success: false, error: 'Payment already verified' });
        }

        // Verify the transaction on-chain
        const verification = await this.verifyPaymentOnChain(txid, payment.amountSats, PREMIUM_CONFIG.sponsorAddress);
        
        if (!verification.verified) {
          return res.status(400).json({ success: false, error: verification.reason || 'Payment not verified' });
        }

        // Grant the feature/credits
        payment.status = 'verified';
        payment.txid = txid;
        payment.verifiedAt = Date.now();
        
        this.grantPremiumFeature(account.accountId, payment.feature, payment.quantity);
        this.paymentHistory.push(payment);
        this.pendingPayments.delete(paymentId);
        this.savePremiumData();

        res.json({
          success: true,
          message: 'Payment verified',
          feature: payment.feature,
          quantity: payment.quantity,
          userStatus: this.getUserPremiumStatus(account.accountId),
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get user's premium credits and features
    this.app.get('/api/premium/credits', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const status = this.getUserPremiumStatus(account.accountId);
        res.json({ success: true, ...status });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Check if user can perform a premium action
    this.app.post('/api/premium/check', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { feature } = req.body;
        const canUse = this.canUsePremiumFeature(account.accountId, feature);
        const cost = this.getFeatureCost(feature);

        res.json({
          success: true,
          feature,
          canUse,
          cost,
          sponsorAddress: canUse ? null : PREMIUM_CONFIG.sponsorAddress,
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // PREPAID SERVICE BALANCE - STANDALONE BTC VERIFICATION
    // Works independently without main node or operators
    // ============================================================

    // Get payment address for funding service balance
    this.app.get('/api/service/payment-address', async (req, res) => {
      try {
        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const paymentAddress = network === 'mainnet'
          ? PREMIUM_CONFIG.sponsorAddress
          : (process.env.FEE_ADDRESS_TESTNET || 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx');

        res.json({
          success: true,
          paymentAddress,
          network,
          minimumSats: 1000,
          note: 'Send BTC to this address, then verify payment to credit your service balance',
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get service balance for account
    this.app.get('/api/service/balance', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const balance = this.getServiceBalance(account.accountId);
        res.json({
          success: true,
          accountId: account.accountId,
          ...balance,
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get premium action pricing
    this.app.get('/api/service/pricing', async (req, res) => {
      try {
        res.json({
          success: true,
          pricing: {
            message_delete: { sats: 50, description: 'Delete a sent message' },
            message_edit: { sats: 25, description: 'Edit a sent message' },
            profile_update: { sats: 100, description: 'Update account profile' },
            username_change: { sats: 500, description: 'Change username/display name' },
            group_create: { sats: 200, description: 'Create a group chat' },
          },
          network: process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet',
          note: 'Prices in satoshis, deducted from prepaid service balance',
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Verify BTC payment and credit service balance (standalone - no main node needed)
    this.app.post('/api/service/verify-payment', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { txid } = req.body;
        if (!txid || typeof txid !== 'string') {
          return res.status(400).json({ success: false, error: 'Missing txid' });
        }

        // Check if payment already credited
        if (this.servicePaymentHistory.has(txid)) {
          return res.status(409).json({
            success: false,
            error: 'Payment already credited',
            txid,
          });
        }

        // Verify payment on blockchain
        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const paymentAddress = network === 'mainnet'
          ? PREMIUM_CONFIG.sponsorAddress
          : (process.env.FEE_ADDRESS_TESTNET || 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx');

        const bases = this.getChainApiBases();
        let txData = null;
        let amountSats = 0;
        let confirmations = 0;

        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/tx/${txid}`);
            if (!response.ok) continue;

            txData = await response.json();
            
            // Sum outputs to payment address
            for (const vout of (txData.vout || [])) {
              if (vout.scriptpubkey_address === paymentAddress) {
                amountSats += vout.value || 0;
              }
            }

            // Get confirmations
            if (txData.status?.confirmed && txData.status?.block_height) {
              try {
                const tipResponse = await fetch(`${apiBase}/blocks/tip/height`);
                if (tipResponse.ok) {
                  const tipHeight = parseInt(await tipResponse.text());
                  confirmations = tipHeight - txData.status.block_height + 1;
                }
              } catch (e) {}
            }

            break;
          } catch (e) {
            continue;
          }
        }

        if (!txData) {
          return res.status(404).json({ success: false, error: 'Transaction not found on blockchain' });
        }

        if (amountSats < 1000) {
          return res.status(400).json({
            success: false,
            error: `Minimum funding is 1000 sats. Found: ${amountSats} sats to ${paymentAddress}`,
          });
        }

        // Credit the service balance
        this.creditServiceBalance(account.accountId, amountSats, txid);
        
        // Record payment to prevent double-crediting
        this.servicePaymentHistory.set(txid, {
          accountId: account.accountId,
          amountSats,
          timestamp: Date.now(),
          confirmations,
        });

        // Persist data
        this.savePremiumData();

        const newBalance = this.getServiceBalance(account.accountId);

        res.json({
          success: true,
          accountId: account.accountId,
          amountCredited: amountSats,
          txid,
          confirmations,
          newBalance: newBalance.serviceBalanceSats,
          message: `Successfully credited ${amountSats} sats to service balance`,
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Premium action: Delete message (costs sats from service balance)
    this.app.post('/api/service/premium/message-delete', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { messageId } = req.body;
        const actionCost = 50; // sats

        if (!messageId) {
          return res.status(400).json({ success: false, error: 'Missing messageId' });
        }

        const balance = this.getServiceBalance(account.accountId);
        if (balance.serviceBalanceSats < actionCost) {
          return res.status(402).json({
            success: false,
            error: 'Insufficient service balance',
            required: actionCost,
            available: balance.serviceBalanceSats,
            shortfall: actionCost - balance.serviceBalanceSats,
          });
        }

        // Perform the message deletion
        const message = this.getMessage(messageId);
        if (!message) {
          console.log(`❌ [Delete] Message not found: ${messageId}`);
          return res.status(404).json({ success: false, error: `Message not found: ${messageId}` });
        }
        
        // Check ownership
        const senderId = message.payload?.senderId || message.payload?.from;
        if (senderId !== account.accountId) {
          console.log(`❌ [Delete] Not authorized: sender=${senderId}, requester=${account.accountId}`);
          return res.status(403).json({ success: false, error: 'Not authorized to delete this message' });
        }
        
        const deleted = this.deleteMessage(messageId, account.accountId);
        if (!deleted) {
          return res.status(500).json({ success: false, error: 'Failed to delete message' });
        }

        // Deduct from service balance
        this.useServiceBalance(account.accountId, actionCost, 'message_delete', messageId);

        const newBalance = this.getServiceBalance(account.accountId);

        res.json({
          success: true,
          accountId: account.accountId,
          messageId,
          costSats: actionCost,
          newBalance: newBalance.serviceBalanceSats,
          message: 'Message deleted successfully',
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Premium action: Edit message (costs sats from service balance)
    this.app.post('/api/service/premium/message-edit', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { messageId, newContent } = req.body;
        const actionCost = 25; // sats

        if (!messageId || !newContent) {
          return res.status(400).json({ success: false, error: 'Missing messageId or newContent' });
        }

        const balance = this.getServiceBalance(account.accountId);
        if (balance.serviceBalanceSats < actionCost) {
          return res.status(402).json({
            success: false,
            error: 'Insufficient service balance',
            required: actionCost,
            available: balance.serviceBalanceSats,
            shortfall: actionCost - balance.serviceBalanceSats,
          });
        }

        // Perform the message edit
        const edited = this.editMessage(messageId, account.accountId, newContent);
        if (!edited) {
          return res.status(404).json({ success: false, error: 'Message not found or not authorized to edit' });
        }

        // Deduct from service balance
        this.useServiceBalance(account.accountId, actionCost, 'message_edit', messageId);

        const newBalance = this.getServiceBalance(account.accountId);

        res.json({
          success: true,
          accountId: account.accountId,
          messageId,
          costSats: actionCost,
          newBalance: newBalance.serviceBalanceSats,
          message: 'Message edited successfully',
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Premium action: File transfer (costs sats based on tier)
    this.app.post('/api/service/premium/file-transfer', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { tier, fileSize, fileName } = req.body;
        
        // File tier pricing
        const FILE_TIERS = {
          free: { maxSize: 1 * 1024 * 1024, cost: 0 },
          basic: { maxSize: 25 * 1024 * 1024, cost: 500 },
          premium: { maxSize: 100 * 1024 * 1024, cost: 2000 },
          enterprise: { maxSize: 1024 * 1024 * 1024, cost: 10000 },
        };

        const tierInfo = FILE_TIERS[tier];
        if (!tierInfo) {
          return res.status(400).json({ success: false, error: 'Invalid tier' });
        }

        const actionCost = tierInfo.cost;

        // Free tier doesn't need balance check
        if (actionCost === 0) {
          return res.json({
            success: true,
            accountId: account.accountId,
            tier,
            costSats: 0,
            message: 'Free tier file transfer approved',
          });
        }

        const balance = this.getServiceBalance(account.accountId);
        if (balance.serviceBalanceSats < actionCost) {
          return res.status(402).json({
            success: false,
            error: 'Insufficient service balance',
            required: actionCost,
            available: balance.serviceBalanceSats,
            shortfall: actionCost - balance.serviceBalanceSats,
          });
        }

        // Deduct from service balance
        this.useServiceBalance(account.accountId, actionCost, 'file_transfer', `${tier}:${fileName}`);

        const newBalance = this.getServiceBalance(account.accountId);

        console.log(`📁 [Premium] File transfer: ${account.accountId} paid ${actionCost} sats for ${tier} tier (${fileName}, ${fileSize} bytes)`);

        res.json({
          success: true,
          accountId: account.accountId,
          tier,
          fileSize,
          fileName,
          costSats: actionCost,
          newBalance: newBalance.serviceBalanceSats,
          message: `File transfer approved (${tier} tier)`,
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // CALL SIGNAL RELAY ENDPOINT (operators relay signals here)
    // ============================================================
    this.app.post('/api/messages/call-signal', (req, res) => {
      try {
        const targetId = String(req.body?.targetId || '').trim();
        const fromId = String(req.body?.fromId || '').trim();
        const signal = req.body?.signal;
        if (!targetId || !fromId || !signal) {
          return res.status(400).json({ success: false, error: 'targetId, fromId, signal required' });
        }

        let delivered = false;
        for (const [clientWs, meta] of this.messagingClients.entries()) {
          if (meta.publicKey === targetId && clientWs.readyState === WebSocket.OPEN) {
            clientWs.send(JSON.stringify({ type: 'call_signal', fromId, signal }));
            delivered = true;
            break;
          }
        }

        res.json({ success: true, delivered });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // EPHEMERAL MESSAGING API ENDPOINTS
    // ============================================================

    // Get user's conversations
    this.app.get('/api/messages/conversations', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        const rawConversations = this.getUserConversations(account.accountId);
        // Enrich with participantInfo to match main node format expected by frontend
        const conversations = rawConversations.map(conv => ({
          ...conv,
          participants: [account.accountId, conv.participantId],
          participantInfo: [
            { accountId: account.accountId, displayName: this.resolveDisplayName(account.accountId) },
            { accountId: conv.participantId, displayName: this.resolveDisplayName(conv.participantId) },
          ],
          lastMessage: conv.lastMessageAt ? { timestamp: conv.lastMessageAt, payload: { itemId: conv.itemId } } : null,
          unreadCount: conv.unreadCount || 0,
        }));
        res.json({ success: true, conversations });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get messages in a conversation
    this.app.get('/api/messages/conversation/:conversationId', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        const { conversationId } = req.params;
        const messages = this.getConversationMessages(conversationId, account.accountId);
        res.json({ success: true, conversationId, messages });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get contacts
    this.app.get('/api/messages/contacts', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        const contacts = this.getUserContacts(account.accountId);
        res.json({ success: true, contacts });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get messaging stats
    this.app.get('/api/messages/stats', (req, res) => {
      res.json({
        success: true,
        stats: {
          totalEvents: this.ephemeralEvents.size,
          totalContacts: this.ephemeralContactsByUser.size,
        }
      });
    });

    // Get user's groups
    this.app.get('/api/messages/groups', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        const groups = this.getUserGroups(account.accountId);
        res.json({ success: true, groups });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get group details
    this.app.get('/api/messages/groups/:groupId', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        const group = this.getGroup(req.params.groupId);
        if (!group) {
          return res.status(404).json({ success: false, error: 'Group not found' });
        }
        if (!group.members.includes(account.accountId)) {
          return res.status(403).json({ success: false, error: 'Not a member of this group' });
        }
        res.json({ success: true, group });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get group messages
    this.app.get('/api/messages/groups/:groupId/messages', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        const { groupId } = req.params;
        
        // SECURITY: Verify user is a member of the group before returning messages
        const group = this.getGroup(groupId);
        if (!group) {
          return res.status(404).json({ success: false, error: 'Group not found' });
        }
        if (!group.members.includes(account.accountId)) {
          return res.status(403).json({ success: false, error: 'Not a member of this group' });
        }
        
        const messages = this.getGroupMessages(groupId, account.accountId);
        res.json({ success: true, groupId, messages });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get message details
    this.app.get('/api/messages/:messageId', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        const message = this.getMessage(req.params.messageId);
        if (!message) {
          return res.status(404).json({ success: false, error: 'Message not found' });
        }
        const payload = message.payload || {};
        if (payload.senderId !== account.accountId && payload.recipientId !== account.accountId) {
          return res.status(403).json({ success: false, error: 'Not authorized' });
        }
        res.json({ success: true, message });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get message status
    this.app.get('/api/messages/:messageId/status', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        const status = this.getMessageStatus(req.params.messageId);
        res.json({ success: true, status });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // PREMIUM MESSAGING FEATURES
    // ============================================================

    // Delete message (PREMIUM FEATURE - requires payment)
    this.app.delete('/api/messages/:messageId', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { messageId } = req.params;
        const message = this.getMessage(messageId);
        
        if (!message) {
          return res.status(404).json({ success: false, error: 'Message not found' });
        }

        const payload = message.payload || {};
        if (payload.senderId !== account.accountId) {
          return res.status(403).json({ success: false, error: 'Only the sender can delete messages' });
        }

        // Check if user can use this premium feature
        const canDelete = this.canUsePremiumFeature(account.accountId, 'delete_message');
        if (!canDelete) {
          return res.status(402).json({
            success: false,
            error: 'Premium feature required',
            feature: 'delete_message',
            cost: PREMIUM_CONFIG.messaging.deleteMessageSats,
            sponsorAddress: PREMIUM_CONFIG.sponsorAddress,
            message: 'Message deletion requires a payment of ' + PREMIUM_CONFIG.messaging.deleteMessageSats + ' sats',
          });
        }

        // Consume the feature credit
        this.consumePremiumFeature(account.accountId, 'delete_message');

        // Create deletion event
        const deletionEvent = {
          eventId: this.generateEventId(),
          eventType: 'MESSAGE_DELETED',
          timestamp: Date.now(),
          payload: {
            messageId,
            deletedBy: account.accountId,
            originalSenderId: payload.senderId,
            conversationId: payload.conversationId || this.getConversationId(payload.senderId, payload.recipientId),
          },
          signature: null,
        };

        // Remove the message and store deletion event
        this.ephemeralEvents.delete(message.eventId);
        this.storeEphemeralEvent(deletionEvent);
        this.saveEphemeralLedger();

        // Broadcast deletion to connected clients and peers
        this.broadcastToLocalClients({
          type: 'message_deleted',
          data: deletionEvent.payload,
        });
        this.broadcastToGatewayPeers({
          type: 'ephemeral_event',
          event: deletionEvent,
        });

        res.json({ success: true, message: 'Message deleted', eventId: deletionEvent.eventId });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Edit message (PREMIUM FEATURE - requires payment)
    this.app.put('/api/messages/:messageId', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { messageId } = req.params;
        const { content, encryptedContent } = req.body;
        
        if (!content && !encryptedContent) {
          return res.status(400).json({ success: false, error: 'New content required' });
        }

        const message = this.getMessage(messageId);
        if (!message) {
          return res.status(404).json({ success: false, error: 'Message not found' });
        }

        const payload = message.payload || {};
        if (payload.senderId !== account.accountId) {
          return res.status(403).json({ success: false, error: 'Only the sender can edit messages' });
        }

        // Check if user can use this premium feature
        const canEdit = this.canUsePremiumFeature(account.accountId, 'edit_message');
        if (!canEdit) {
          return res.status(402).json({
            success: false,
            error: 'Premium feature required',
            feature: 'edit_message',
            cost: PREMIUM_CONFIG.messaging.editMessageSats,
            sponsorAddress: PREMIUM_CONFIG.sponsorAddress,
            message: 'Message editing requires a payment of ' + PREMIUM_CONFIG.messaging.editMessageSats + ' sats',
          });
        }

        // Consume the feature credit
        this.consumePremiumFeature(account.accountId, 'edit_message');

        // Create edit event
        const editEvent = {
          eventId: this.generateEventId(),
          eventType: 'MESSAGE_EDITED',
          timestamp: Date.now(),
          payload: {
            messageId,
            editedBy: account.accountId,
            originalContent: payload.content,
            newContent: content || null,
            newEncryptedContent: encryptedContent || null,
            conversationId: payload.conversationId || this.getConversationId(payload.senderId, payload.recipientId),
            editedAt: Date.now(),
          },
          signature: null,
        };

        // Update the original message
        if (content) payload.content = content;
        if (encryptedContent) payload.encryptedContent = encryptedContent;
        payload.edited = true;
        payload.editedAt = Date.now();
        message.payload = payload;
        this.ephemeralEvents.set(message.eventId, message);

        // Store edit event for history
        this.storeEphemeralEvent(editEvent);
        this.saveEphemeralLedger();

        // Broadcast edit to connected clients and peers
        this.broadcastToLocalClients({
          type: 'message_edited',
          data: editEvent.payload,
        });
        this.broadcastToGatewayPeers({
          type: 'ephemeral_event',
          event: editEvent,
        });

        res.json({ success: true, message: 'Message edited', eventId: editEvent.eventId });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get message reactions
    this.app.get('/api/messages/:messageId/reactions', (req, res) => {
      try {
        const reactions = this.getReactions(req.params.messageId);
        res.json({ success: true, reactions });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get typing users
    this.app.get('/api/messages/conversation/:conversationId/typing', (req, res) => {
      try {
        const typingUsers = this.getTypingUsers(req.params.conversationId);
        res.json({ success: true, typingUsers });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get user online status
    this.app.get('/api/messages/user/:userId/online', (req, res) => {
      try {
        const isOnline = this.isUserOnline(req.params.userId);
        const lastSeen = this.getUserLastSeen(req.params.userId);
        res.json({ success: true, isOnline, lastSeen });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Search messages
    this.app.get('/api/messages/search', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }
        const query = req.query.q || '';
        const limit = parseInt(req.query.limit) || 50;
        const messages = this.searchMessages(account.accountId, query, limit);
        res.json({ success: true, messages });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // P2P MESSAGING ENDPOINTS - LOCAL HANDLING (NO OPERATOR REQUIRED)
    // Messages are created locally and broadcast to gateway mesh
    // ============================================================

    // Send direct message - proxy to operator for cross-node visibility, fallback to local P2P
    this.app.post('/api/messages/send', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { recipientId, encryptedContent, encryptedForSender, conversationId, mediaType } = req.body;
        if (!recipientId || !encryptedContent) {
          return res.status(400).json({ success: false, error: 'recipientId and encryptedContent required' });
        }

        // Check if blocked
        if (this.isBlocked(recipientId, account.accountId)) {
          return res.status(403).json({ success: false, error: 'You are blocked by this user' });
        }

        // Try to proxy the send to an operator first (so message appears everywhere)
        const sessionToken = req.headers['x-session-token'] || req.cookies?.sessionToken;
        let proxied = false;
        for (const operatorUrl of this.getCandidateOperatorUrls()) {
          try {
            const proxyRes = await fetch(`${operatorUrl}/api/messages/send`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'x-session-token': sessionToken || '',
              },
              body: JSON.stringify(req.body),
            });
            if (proxyRes.ok) {
              const data = await proxyRes.json();
              if (data.success) {
                console.log(`📤 Message proxied to operator: ${operatorUrl}`);
                // Also store locally so it shows immediately on gateway
                const convId = data.conversationId || conversationId || this.generateConversationId(account.accountId, recipientId);
                const localPayload = {
                  messageId: data.messageId || this.generateMessageId(),
                  senderId: account.accountId,
                  recipientId,
                  encryptedContent,
                  encryptedForSender: encryptedForSender || encryptedContent,
                  conversationId: convId,
                };
                this.createLocalEphemeralEvent('MESSAGE_SENT', localPayload, mediaType || 'TEXT');
                return res.json(data);
              }
            }
          } catch (e) {
            console.log(`⚠️ Failed to proxy message to ${operatorUrl}: ${e.message}`);
          }
        }

        // Fallback: create locally and broadcast via WebSocket (P2P mode)
        console.log('📝 No operator reachable, creating message locally (P2P)');
        const messageId = this.generateMessageId();
        const convId = conversationId || this.generateConversationId(account.accountId, recipientId);

        const payload = {
          messageId,
          senderId: account.accountId,
          recipientId,
          encryptedContent,
          encryptedForSender: encryptedForSender || encryptedContent,
          conversationId: convId,
        };

        const event = this.createLocalEphemeralEvent('MESSAGE_SENT', payload, mediaType || 'TEXT');
        if (!event) {
          return res.status(500).json({ success: false, error: 'Failed to create message' });
        }

        res.json({
          success: true,
          messageId,
          conversationId: convId,
          expiresAt: event.expiresAt,
          p2p: true,
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Add contact (P2P)
    this.app.post('/api/messages/contacts', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { contactId, nickname, publicKey } = req.body;
        if (!contactId) {
          return res.status(400).json({ success: false, error: 'contactId required' });
        }

        const payload = {
          userId: account.accountId,
          contactId,
          nickname: nickname || null,
          publicKey: publicKey || null,
        };

        const event = this.createLocalEphemeralEvent('CONTACT_ADDED', payload);
        if (!event) {
          return res.status(500).json({ success: false, error: 'Failed to add contact' });
        }

        res.json({ success: true, contactId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Remove contact (P2P)
    this.app.delete('/api/messages/contacts/:contactId', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { contactId } = req.params;
        const payload = {
          userId: account.accountId,
          contactId,
        };

        const event = this.createLocalEphemeralEvent('CONTACT_REMOVED', payload);
        
        // Remove from local index
        const userContacts = this.ephemeralContactsByUser.get(account.accountId);
        if (userContacts) {
          userContacts.delete(contactId);
        }

        res.json({ success: true, contactId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Update contact nickname (P2P)
    this.app.put('/api/messages/contacts/:contactId', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { contactId } = req.params;
        const { nickname, publicKey } = req.body;

        const payload = {
          userId: account.accountId,
          contactId,
          nickname: nickname || null,
          publicKey: publicKey || null,
        };

        const event = this.createLocalEphemeralEvent('CONTACT_UPDATED', payload);
        res.json({ success: true, contactId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Unblock user (P2P)
    this.app.delete('/api/messages/block/:blockedId', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { blockedId } = req.params;
        const payload = {
          blockerId: account.accountId,
          blockedId,
        };

        const event = this.createLocalEphemeralEvent('USER_UNBLOCKED', payload);
        res.json({ success: true, blockedId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Block user (P2P)
    this.app.post('/api/messages/block', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { blockedId } = req.body;
        if (!blockedId) {
          return res.status(400).json({ success: false, error: 'blockedId required' });
        }

        const payload = {
          blockerId: account.accountId,
          blockedId,
        };

        const event = this.createLocalEphemeralEvent('USER_BLOCKED', payload);
        if (!event) {
          return res.status(500).json({ success: false, error: 'Failed to block user' });
        }

        res.json({ success: true, blockedId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Create group (P2P)
    this.app.post('/api/messages/groups', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { name, memberIds } = req.body;
        if (!name) {
          return res.status(400).json({ success: false, error: 'name required' });
        }

        const groupId = this.generateGroupId();
        const payload = {
          groupId,
          name,
          creatorId: account.accountId,
          memberIds: [account.accountId, ...(memberIds || [])],
        };

        const event = this.createLocalEphemeralEvent('GROUP_CREATED', payload);
        if (!event) {
          return res.status(500).json({ success: false, error: 'Failed to create group' });
        }

        res.json({ success: true, groupId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Send group message (P2P)
    this.app.post('/api/messages/groups/:groupId/send', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { groupId } = req.params;
        
        // SECURITY: Verify user is a member of the group before allowing send
        const group = this.getGroup(groupId);
        if (!group) {
          return res.status(404).json({ success: false, error: 'Group not found' });
        }
        if (!group.members.includes(account.accountId)) {
          return res.status(403).json({ success: false, error: 'Not a member of this group' });
        }
        
        const { encryptedContentByMember, mediaType } = req.body;
        if (!encryptedContentByMember) {
          return res.status(400).json({ success: false, error: 'encryptedContentByMember required' });
        }

        const messageId = this.generateMessageId();
        const payload = {
          messageId,
          groupId,
          senderId: account.accountId,
          encryptedContentByMember,
        };

        const event = this.createLocalEphemeralEvent('GROUP_MESSAGE_SENT', payload, mediaType || 'TEXT');
        if (!event) {
          return res.status(500).json({ success: false, error: 'Failed to send group message' });
        }

        res.json({ success: true, messageId, groupId, expiresAt: event.expiresAt, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Add group member (P2P)
    this.app.post('/api/messages/groups/:groupId/members', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { groupId } = req.params;
        
        // SECURITY: Verify user is a member of the group before allowing add
        const group = this.getGroup(groupId);
        if (!group) {
          return res.status(404).json({ success: false, error: 'Group not found' });
        }
        if (!group.members.includes(account.accountId)) {
          return res.status(403).json({ success: false, error: 'Not a member of this group' });
        }
        
        const { memberId } = req.body;
        if (!memberId) {
          return res.status(400).json({ success: false, error: 'memberId required' });
        }

        const payload = {
          groupId,
          addedBy: account.accountId,
          memberId,
        };

        const event = this.createLocalEphemeralEvent('GROUP_MEMBER_ADDED', payload);
        if (!event) {
          return res.status(500).json({ success: false, error: 'Failed to add member' });
        }

        res.json({ success: true, groupId, memberId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Leave group (P2P)
    this.app.post('/api/messages/groups/:groupId/leave', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { groupId } = req.params;
        
        // SECURITY: Verify user is a member of the group before allowing leave
        const group = this.getGroup(groupId);
        if (!group) {
          return res.status(404).json({ success: false, error: 'Group not found' });
        }
        if (!group.members.includes(account.accountId)) {
          return res.status(403).json({ success: false, error: 'Not a member of this group' });
        }
        
        const payload = {
          groupId,
          memberId: account.accountId,
        };

        const event = this.createLocalEphemeralEvent('GROUP_MEMBER_LEFT', payload);
        if (!event) {
          return res.status(500).json({ success: false, error: 'Failed to leave group' });
        }

        res.json({ success: true, groupId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Mark message as viewed (P2P)
    this.app.post('/api/messages/:messageId/viewed', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { messageId } = req.params;
        const payload = {
          messageId,
          viewerId: account.accountId,
          viewedAt: Date.now(),
        };

        const event = this.createLocalEphemeralEvent('MESSAGE_VIEWED', payload);
        res.json({ success: true, messageId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Mark message as read (P2P)
    this.app.post('/api/messages/:messageId/read', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { messageId } = req.params;
        const payload = {
          messageId,
          readerId: account.accountId,
          readAt: Date.now(),
        };

        const event = this.createLocalEphemeralEvent('MESSAGE_READ', payload);
        res.json({ success: true, messageId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Add reaction (P2P)
    this.app.post('/api/messages/:messageId/react', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { messageId } = req.params;
        const { emoji } = req.body;
        if (!emoji) {
          return res.status(400).json({ success: false, error: 'emoji required' });
        }

        const payload = {
          messageId,
          reactorId: account.accountId,
          emoji,
        };

        const event = this.createLocalEphemeralEvent('REACTION_ADDED', payload);
        res.json({ success: true, messageId, emoji, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Mute conversation (P2P)
    this.app.post('/api/messages/conversation/:conversationId/mute', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { conversationId } = req.params;
        const payload = {
          conversationId,
          userId: account.accountId,
          muted: true,
        };

        const event = this.createLocalEphemeralEvent('CONVERSATION_MUTED', payload);
        res.json({ success: true, conversationId, muted: true, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Unmute conversation (P2P)
    this.app.post('/api/messages/conversation/:conversationId/unmute', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { conversationId } = req.params;
        const payload = {
          conversationId,
          userId: account.accountId,
          muted: false,
        };

        const event = this.createLocalEphemeralEvent('CONVERSATION_UNMUTED', payload);
        res.json({ success: true, conversationId, muted: false, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Mute group (P2P)
    this.app.post('/api/messages/groups/:groupId/mute', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { groupId } = req.params;
        const payload = {
          groupId,
          userId: account.accountId,
          muted: true,
        };

        const event = this.createLocalEphemeralEvent('GROUP_MUTED', payload);
        res.json({ success: true, groupId, muted: true, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Unmute group (P2P)
    this.app.post('/api/messages/groups/:groupId/unmute', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { groupId } = req.params;
        const payload = {
          groupId,
          userId: account.accountId,
          muted: false,
        };

        const event = this.createLocalEphemeralEvent('GROUP_UNMUTED', payload);
        res.json({ success: true, groupId, muted: false, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Typing indicator (P2P - broadcast only, no storage)
    this.app.post('/api/messages/typing', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { conversationId, recipientId } = req.body;
        
        // Broadcast typing indicator without storing (ephemeral)
        const message = {
          type: 'typing_indicator',
          senderId: account.accountId,
          conversationId,
          recipientId,
          timestamp: Date.now(),
        };

        this.broadcastToLocalClients(message);
        this.broadcastToGatewayPeers(message);

        res.json({ success: true, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Online status heartbeat (P2P)
    this.app.post('/api/messages/online', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        // Broadcast online status
        const message = {
          type: 'online_status',
          userId: account.accountId,
          online: true,
          timestamp: Date.now(),
        };

        this.broadcastToLocalClients(message);
        this.broadcastToGatewayPeers(message);

        res.json({ success: true, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Start conversation about item (P2P)
    this.app.post('/api/messages/start-about-item', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { itemId, recipientId, encryptedContent, encryptedForSender } = req.body;
        if (!itemId || !encryptedContent) {
          return res.status(400).json({ success: false, error: 'itemId and encryptedContent required' });
        }

        // Recipient can be specified or we'll use a placeholder
        // In full P2P mode, the recipient needs to be known
        const targetRecipient = recipientId || `item_owner_${itemId}`;

        if (targetRecipient === account.accountId) {
          return res.status(400).json({ success: false, error: 'Cannot message yourself' });
        }

        if (this.isBlocked(targetRecipient, account.accountId)) {
          return res.status(403).json({ success: false, error: 'You are blocked by this user' });
        }

        const conversationId = this.generateConversationId(account.accountId, targetRecipient, itemId);
        const messageId = this.generateMessageId();

        const payload = {
          messageId,
          senderId: account.accountId,
          recipientId: targetRecipient,
          encryptedContent,
          encryptedForSender: encryptedForSender || encryptedContent,
          itemId,
          conversationId,
        };

        const event = this.createLocalEphemeralEvent('MESSAGE_SENT', payload);
        if (!event) {
          return res.status(500).json({ success: false, error: 'Failed to create message' });
        }

        res.json({
          success: true,
          messageId,
          conversationId,
          recipientId: targetRecipient,
          expiresAt: event.expiresAt,
          p2p: true,
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Delete message (P2P)
    this.app.delete('/api/messages/:messageId', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { messageId } = req.params;
        const payload = {
          messageId,
          deletedBy: account.accountId,
        };

        const event = this.createLocalEphemeralEvent('MESSAGE_DELETED', payload);
        res.json({ success: true, messageId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Remove reaction (P2P)
    this.app.delete('/api/messages/:messageId/react', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { messageId } = req.params;
        const { emoji } = req.body;

        const payload = {
          messageId,
          reactorId: account.accountId,
          emoji,
        };

        const event = this.createLocalEphemeralEvent('REACTION_REMOVED', payload);
        res.json({ success: true, messageId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Remove group member (P2P)
    this.app.delete('/api/messages/groups/:groupId/members/:memberId', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { groupId, memberId } = req.params;
        const payload = {
          groupId,
          removedBy: account.accountId,
          memberId,
        };

        const event = this.createLocalEphemeralEvent('GROUP_MEMBER_REMOVED', payload);
        res.json({ success: true, groupId, memberId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Delete group message (P2P)
    this.app.delete('/api/messages/groups/:groupId/messages/:messageId', async (req, res) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const { groupId, messageId } = req.params;
        const payload = {
          groupId,
          messageId,
          deletedBy: account.accountId,
        };

        const event = this.createLocalEphemeralEvent('GROUP_MESSAGE_DELETED', payload);
        res.json({ success: true, groupId, messageId, p2p: true });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============================================================
    // END EPHEMERAL MESSAGING API
    // ============================================================

    this.app.use('/api', (req, res) => {
      Promise.resolve(this.proxyApi(req, res)).catch((e) => {
        console.error('❌ Gateway proxy error:', e);
        res.status(500).json({ error: 'Gateway proxy error', message: e?.message || String(e) });
      });
    });

    // Page route aliases (same as operator node for consistent experience)
    const publicDir = path.join(__dirname, 'public');
    const sendPublicFile = (filename) => (req, res, next) => {
      const fp = path.join(publicDir, filename);
      if (fs.existsSync(fp)) return res.sendFile(fp);
      next();
    };

    this.app.get('/', sendPublicFile('landing.html'));
    this.app.get('/join', sendPublicFile('join.html'));
    this.app.get('/how-it-works', sendPublicFile('how-it-works.html'));
    this.app.get('/whitepaper', sendPublicFile('whitepaper.html'));
    this.app.get('/AUTHO_WHITEPAPER.md', sendPublicFile('AUTHO_WHITEPAPER.md'));
    this.app.get('/buy', sendPublicFile('buy.html'));
    this.app.get('/setup', sendPublicFile('setup-wizard.html'));
    this.app.get('/manufacturer', sendPublicFile('manufacturer-dashboard.html'));
    this.app.get('/authenticator', sendPublicFile('authenticator-dashboard.html'));
    this.app.get('/retailer', sendPublicFile('retailer-dashboard.html'));
    this.app.get('/dashboard', sendPublicFile('dashboard.html'));
    this.app.get('/operator', sendPublicFile('operator-portal.html'));
    this.app.get('/operator/dashboard', sendPublicFile('operator-dashboard.html'));
    this.app.get('/operator/apply', sendPublicFile('operator-apply.html'));
    this.app.get('/operator/setup', sendPublicFile('operator-setup.html'));
    this.app.get('/operator/restore', sendPublicFile('operator-restore.html'));
    this.app.get(['/customer/login', '/customer/login/'], sendPublicFile('customer/login.html'));
    this.app.get(['/customer/signup', '/customer/signup/'], sendPublicFile('customer/signup.html'));
    this.app.get('/m', sendPublicFile('mobile-entry.html'));
    this.app.get('/mobile', sendPublicFile('mobile-entry.html'));
    this.app.get('/mobile/login', sendPublicFile('mobile-login.html'));
    this.app.get('/mobile/wallet', sendPublicFile('mobile-wallet.html'));
    this.app.get('/mobile/verify', sendPublicFile('mobile-verify.html'));
    this.app.get('/mobile/items', sendPublicFile('mobile-items.html'));
    this.app.get('/mobile/register', sendPublicFile('mobile-register-item.html'));
    this.app.get('/mobile/search', sendPublicFile('mobile-search.html'));
    this.app.get('/mobile/offers', sendPublicFile('mobile-offers.html'));
    this.app.get('/mobile/messages', sendPublicFile('mobile-messages.html'));
    this.app.get('/mobile/history', sendPublicFile('mobile-history.html'));
    this.app.get('/mobile/consign', sendPublicFile('mobile-consign.html'));
    this.app.get('/admin/login', sendPublicFile('admin-login.html'));
    this.app.get('/mempool', sendPublicFile('mempool.html'));
    this.app.get('/token', sendPublicFile('token-dashboard.html'));
    this.app.get('/install/gateway', sendPublicFile('install-gateway.html'));
    this.app.get('/install/operator', sendPublicFile('install-operator.html'));

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

  setupMessagingWebSocket() {
    if (!this.messagingWss) return;

    this.messagingWss.on('connection', (ws, req) => {
      const clientInfo = { publicKey: null, conversationId: null, groupId: null };
      this.messagingClients.set(ws, clientInfo);
      console.log(`💬 [Messaging WS] Client connected (${this.messagingClients.size} total)`);

      ws.on('message', (raw) => {
        try {
          const data = JSON.parse(raw.toString());

          if (data.type === 'auth' && data.publicKey) {
            clientInfo.publicKey = String(data.publicKey).trim();
            ws.send(JSON.stringify({ type: 'auth_ok' }));
            return;
          }

          if (data.type === 'subscribe' && data.conversationId) {
            clientInfo.conversationId = String(data.conversationId).trim();
            return;
          }

          if (data.type === 'subscribe_group' && data.groupId) {
            clientInfo.groupId = String(data.groupId).trim();
            return;
          }

          if (data.type === 'call_signal' && data.targetId && data.signal) {
            const senderId = clientInfo.publicKey;
            if (!senderId) {
              ws.send(JSON.stringify({ type: 'error', error: 'Not authenticated for calls' }));
              return;
            }
            const targetId = String(data.targetId).trim();
            let delivered = false;

            for (const [clientWs, meta] of this.messagingClients.entries()) {
              if (meta.publicKey === targetId && clientWs !== ws && clientWs.readyState === WebSocket.OPEN) {
                clientWs.send(JSON.stringify({
                  type: 'call_signal',
                  fromId: senderId,
                  signal: data.signal
                }));
                delivered = true;
                break;
              }
            }

            if (!delivered) {
              this.relayCallSignalToOperators(targetId, senderId, data.signal).catch(() => {});
            }
            return;
          }

          if (data.type === 'typing' || data.type === 'read_receipt' || data.type === 'reaction') {
            const convId = data.conversationId || clientInfo.conversationId;
            if (convId) {
              // Relay to local messaging clients
              for (const [clientWs, meta] of this.messagingClients.entries()) {
                if (clientWs !== ws && clientWs.readyState === WebSocket.OPEN &&
                    (meta.conversationId === convId || meta.groupId === convId)) {
                  clientWs.send(JSON.stringify(data));
                }
              }
              // Relay to operators for network-wide propagation
              const relayMsg = JSON.stringify({
                type: 'transient_signal',
                signalType: data.type,
                data: { ...data, fromId: clientInfo.publicKey },
                hops: 0,
              });
              for (const [opId, connInfo] of this.operatorConnections.entries()) {
                try {
                  if (connInfo.ws && connInfo.ws.readyState === WebSocket.OPEN) {
                    connInfo.ws.send(relayMsg);
                  }
                } catch {}
              }
            }
            return;
          }

        } catch (e) {
          console.error('💬 [Messaging WS] Invalid message:', e.message);
        }
      });

      ws.on('close', () => {
        this.messagingClients.delete(ws);
      });

      ws.on('error', () => {
        this.messagingClients.delete(ws);
      });
    });
  }

  async relayCallSignalToOperators(targetId, fromId, signal) {
    // Layer 1: Send via existing operator WebSocket connections (fast, works behind NAT)
    const relayMsg = JSON.stringify({
      type: 'call_signal_relay',
      targetId,
      fromId,
      signal,
    });
    let sentViaWs = false;
    for (const [opId, connInfo] of this.operatorConnections.entries()) {
      try {
        if (connInfo.ws && connInfo.ws.readyState === WebSocket.OPEN) {
          connInfo.ws.send(relayMsg);
          sentViaWs = true;
        }
      } catch {}
    }

    // Layer 2: HTTP POST to operator URLs (fallback)
    if (sentViaWs) return true;
    const timeoutMs = 3000;
    for (const baseUrl of this.operatorUrls) {
      try {
        const fetchUrl = `${baseUrl.replace(/\/+$/, '')}/api/messages/call-signal`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), timeoutMs);
        const resp = await fetch(fetchUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Internal-Request': 'operator-to-operator' },
          body: JSON.stringify({ targetId, fromId, signal }),
          signal: controller.signal,
        });
        clearTimeout(timeout);
        if (resp.ok) {
          const data = await resp.json().catch(() => ({}));
          if (data && data.delivered) return true;
        }
      } catch {}
    }
    return false;
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
        
        // Keepalive ping every 60s — prevents Cloudflare tunnel timeout (100s idle limit)
        ws._keepAliveTimer = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            try { ws.ping(); } catch {}
          } else {
            clearInterval(ws._keepAliveTimer);
          }
        }, 60000);
        
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
        if (ws._keepAliveTimer) clearInterval(ws._keepAliveTimer);
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

    console.log('🔍 Discovering active operators from ALL seeds...');
    
    const seeds = this.getSeedNodes();
    const mergedOperators = new Map(); // operatorId -> operator info

    // Query ALL seeds in parallel and merge results
    const fetchPromises = seeds.map(async (seed) => {
      try {
        const [host, port] = String(seed).split(':');
        const isLocal = host.includes('localhost') || host.includes('127.0.0.1');
        const isOnion = host.toLowerCase().endsWith('.onion');
        const protocol = (isLocal || isOnion) ? 'http' : 'https';
        const httpUrl = isLocal
          ? (port ? `${protocol}://${host}:${port}` : `${protocol}://${host}`)
          : `${protocol}://${host}`;

        const response = await fetch(`${httpUrl}/api/network/operators`, {
          signal: AbortSignal.timeout(10000),
        });
        const data = await response.json();

        if (data && data.success && Array.isArray(data.operators)) {
          console.log(`  ✅ ${seed}: returned ${data.operators.length} operators`);
          return data.operators;
        }
      } catch (error) {
        console.log(`  ⚠️  ${seed}: ${error.message}`);
      }
      return [];
    });

    const results = await Promise.allSettled(fetchPromises);
    for (const result of results) {
      if (result.status === 'fulfilled') {
        for (const op of result.value) {
          const key = op.operatorId || op.wsUrl || op.operatorUrl;
          if (key && !mergedOperators.has(key)) {
            mergedOperators.set(key, op);
          }
        }
      }
    }

    // Also ensure hardcoded seeds are always included as operators
    for (const seedHost of seeds) {
      const [host, port] = String(seedHost).split(':');
      const isLocal = host.includes('localhost') || host.includes('127.0.0.1');
      const wsProtocol = isLocal ? 'ws' : 'wss';
      const httpProtocol = isLocal ? 'http' : 'https';
      const wsUrl = port ? `${wsProtocol}://${host}:${port}` : `${wsProtocol}://${host}`;
      const httpUrl = isLocal
        ? (port ? `${httpProtocol}://${host}:${port}` : `${httpProtocol}://${host}`)
        : `${httpProtocol}://${host}`;
      const seedId = `seed-${host}`;
      if (!mergedOperators.has(seedId) && ![...mergedOperators.values()].some(o => o.wsUrl === wsUrl)) {
        mergedOperators.set(seedId, { operatorId: seedId, wsUrl, operatorUrl: httpUrl });
      }
    }

    if (mergedOperators.size > 0) {
      this.discoveredOperators = Array.from(mergedOperators.values());
      this.lastOperatorDiscovery = now;
      console.log(`🌐 Total merged operators from all seeds: ${this.discoveredOperators.length}`);
    } else {
      console.log('⚠️  Operator discovery failed, using hardcoded seeds');
    }

    return this.discoveredOperators;
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
      
      if (this.hasActiveConnectionForWsUrl(op.wsUrl)) {
        continue;
      }

      if (this.operatorConnections.has(op.operatorId)) {
        const existing = this.operatorConnections.get(op.operatorId);
        if (existing.ws && (existing.ws.readyState === WebSocket.OPEN || existing.ws.readyState === WebSocket.CONNECTING)) {
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

  hasActiveConnectionForWsUrl(wsUrl) {
    if (!wsUrl) return false;
    for (const conn of this.operatorConnections.values()) {
      if (!conn || !conn.ws) continue;
      if (conn.wsUrl !== wsUrl) continue;
      if (conn.ws.readyState === WebSocket.OPEN || conn.ws.readyState === WebSocket.CONNECTING) {
        return true;
      }
    }
    return false;
  }

  connectToOperator(operator) {
    const { operatorId, wsUrl } = operator;

    if (this.hasActiveConnectionForWsUrl(wsUrl)) {
      return;
    }

    const existing = this.operatorConnections.get(operatorId);
    if (existing && existing.ws && (existing.ws.readyState === WebSocket.OPEN || existing.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const pendingTimer = this.operatorReconnectTimers.get(operatorId);
    if (pendingTimer) {
      clearTimeout(pendingTimer);
      this.operatorReconnectTimers.delete(operatorId);
    }
    
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

        const reconnectTimer = this.operatorReconnectTimers.get(operatorId);
        if (reconnectTimer) {
          clearTimeout(reconnectTimer);
          this.operatorReconnectTimers.delete(operatorId);
        }

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

        this.scheduleOperatorReconnect(operator);
      });

      ws.on('error', (error) => {
        console.error(`❌ WebSocket error for operator ${operatorId}:`, error.message);
      });

      this.operatorConnections.set(operatorId, connectionInfo);
    } catch (error) {
      console.error(`❌ Failed to connect to operator ${operatorId}:`, error.message);
    }
  }

  scheduleOperatorReconnect(operator) {
    const { operatorId, wsUrl } = operator;

    const existing = this.operatorConnections.get(operatorId);
    if (existing && existing.ws && (existing.ws.readyState === WebSocket.OPEN || existing.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    if (this.operatorReconnectTimers.has(operatorId)) {
      return;
    }

    const health = this.seedHealth.get(wsUrl);
    const failCount = health?.failCount || 1;
    const delay = Math.min(10000 * Math.pow(1.5, failCount - 1), 300000); // Max 5 min
    console.log(`🔄 Reconnecting to ${operatorId} in ${Math.round(delay / 1000)}s...`);

    const timer = setTimeout(() => {
      this.operatorReconnectTimers.delete(operatorId);
      this.connectToOperator(operator);
    }, delay);

    this.operatorReconnectTimers.set(operatorId, timer);
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
          this.scheduleOperatorReconnect(operator);
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
    // Guard against concurrent tunnel attempts
    if (this._enablingPublicAccess) {
      console.log('⏳ Public access enable already in progress, skipping duplicate call');
      return false;
    }
    // If tunnel is already running and healthy, skip
    if (this.publicAccessEnabled && this.publicAccessUrl && this.tunnelProcess && !this.tunnelProcess.killed) {
      console.log(`✅ Public access already enabled: ${this.publicAccessUrl}`);
      return true;
    }
    this._enablingPublicAccess = true;
    console.log('🌍 Attempting to enable public access...');
    
    // Get public IP first for logging/reference
    this.externalIp = await this.getPublicIp();
    if (this.externalIp) {
      console.log(`🌐 Your public IP: ${this.externalIp}`);
    }
    
    // Method 1: Check if already publicly accessible (manual port forward or direct IP)
    if (await this.checkDirectPublicAccess()) {
      this._enablingPublicAccess = false;
      return true;
    }
    
    // Method 2: Try UPnP port forwarding (works on most home routers)
    if (await this.tryUpnpPortForward()) {
      this._enablingPublicAccess = false;
      return true;
    }
    
    // Method 3: Try tunnel service (localtunnel, works everywhere)
    if (await this.tryTunnelService()) {
      this._enablingPublicAccess = false;
      return true;
    }
    
    console.log('⚠️ Could not enable public access automatically.');
    console.log('   Options:');
    console.log('   1. Manually forward ports 3001 and 4001 on your router');
    console.log('   2. Use a reverse proxy like Cloudflare Tunnel or ngrok');
    console.log('   3. Set GATEWAY_PUBLIC_URL manually if you have a domain');
    
    this._enablingPublicAccess = false;
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
    if (this.lastTunnelError === 'cloudflared_missing') {
      console.log('   For seamless public access, install cloudflared:');
      console.log('   Windows: winget install cloudflare.cloudflared');
      console.log('   Or download from: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/');
    } else if (this.lastTunnelError === 'cloudflared_timeout') {
      console.log('   cloudflared started but the public URL did not become reachable in time.');
      console.log('   This is usually a transient Cloudflare edge/DNS propagation delay. Try again or wait a few minutes.');
    }
    return false;
  }

  /**
   * Try Cloudflare Tunnel (cloudflared) - FREE, no password, no account required
   */
  async tryCloudflaredTunnel() {
    const { spawn, execSync } = require('child_process');

    const tunnelMode = String(process.env.GATEWAY_TUNNEL_MODE || process.env.AUTHO_GATEWAY_TUNNEL_MODE || 'quick').trim().toLowerCase();
    const cloudflaredToken = String(process.env.CLOUDFLARED_TOKEN || process.env.AUTHO_CLOUDFLARED_TOKEN || '').trim();
    const configuredPublicUrl = String(process.env.GATEWAY_PUBLIC_URL || process.env.AUTHO_GATEWAY_PUBLIC_URL || '').trim();
    
    // Kill any existing cloudflared process to avoid conflicts
    if (this.tunnelProcess) {
      try {
        this.tunnelProcess.kill();
      } catch (e) {}
      this.tunnelProcess = null;
    }
    
    // Also try to kill any orphan cloudflared processes on Windows
    if (process.platform === 'win32') {
      try {
        execSync('taskkill /f /im cloudflared.exe 2>nul', { stdio: 'ignore', timeout: 5000 });
      } catch (e) {}
    }
    
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
      this.lastTunnelError = 'cloudflared_missing';
      return false;
    }

    if (tunnelMode !== 'quick') {
      if (!cloudflaredToken) {
        console.log('⚠️ Missing CLOUDFLARED_TOKEN for stable tunnel mode');
        return false;
      }
      if (!configuredPublicUrl) {
        console.log('⚠️ Missing GATEWAY_PUBLIC_URL for stable tunnel mode');
        return false;
      }
    }
    
    // Clear any stale URL before starting a new tunnel attempt
    this.publicAccessUrl = null;
    this.publicAccessEnabled = false;
    this.publicAccessMethod = null;

    this.lastTunnelError = null;

    return new Promise((resolve) => {
      const args = tunnelMode === 'quick'
        ? ['tunnel', '--protocol', 'http2', '--url', `https://localhost:${EFFECTIVE_HTTP_PORT + 443}`, '--no-tls-verify']
        : ['tunnel', 'run', '--token', cloudflaredToken];

      // Use shell:false to avoid security warnings and subprocess issues
      this.tunnelProcess = spawn(cloudflaredPath, args, { 
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
      });
      
      let resolved = false;
      const overallTimeoutMs = 600000;
      const urlTimeout = setTimeout(() => {
        if (!resolved) {
          console.log('⚠️ Cloudflare Tunnel timeout');
          this.lastTunnelError = 'cloudflared_timeout';
          this.tunnelProcess?.kill();
          resolve(false);
        }
      }, overallTimeoutMs);
      
      const checkTunnelUrlOnce = async (url) => {
        try {
          const dnsMod = require('dns');
          const resolver = new dnsMod.Resolver();
          resolver.setServers(['1.1.1.1', '1.0.0.1']);
          const host = new URL(url).hostname;

          const hasTimeoutSignal = globalThis.AbortSignal && typeof AbortSignal.timeout === 'function';
          const signal = hasTimeoutSignal ? AbortSignal.timeout(5000) : undefined;
          try {
            await resolver.resolve4(host);
          } catch (e4) {
            try {
              await resolver.resolve6(host);
            } catch (e6) {}
          }
          try {
            const resp = await fetch(`${url}/health`, { method: 'GET', signal });
            if (resp && resp.ok) return true;
          } catch (e) {}
          try {
            const resp = await fetch(`${url}/`, { method: 'GET', signal });
            if (resp && resp.ok) return true;
          } catch (e) {}
        } catch (e) {}

        return false;
      };

      let verifying = false;
      let candidateUrl = null;
      let lastWaitLogAt = 0;

      const verifyCandidateUrl = (url) => {
        if (verifying || resolved) return;
        verifying = true;
        candidateUrl = url;

        // Trust the URL immediately when cloudflared allocates it
        // Health checks from local network may fail if router blocks trycloudflare.com
        // but the tunnel works fine from outside (tested by user on mobile off-wifi)
        this.publicAccessEnabled = true;
        this.publicAccessUrl = url;
        this.publicAccessMethod = tunnelMode === 'quick' ? 'cloudflare' : 'cloudflare_named';

        this.logConnectionEvent('public_access_enabled', { method: this.publicAccessMethod, url: this.publicAccessUrl });
        console.log(`✅ Cloudflare Tunnel established!`);
        console.log(`   Public URL: ${this.publicAccessUrl}`);
        console.log(`   (No password required - direct access)`);

        // Open browser with the public URL
        this.openBrowserWithUrl(this.publicAccessUrl);

        // Register this gateway URL with the seed ledger for peer discovery
        this.registerPublicGatewayToLedger();

        resolved = true;
        clearTimeout(urlTimeout);
        resolve(true);
        verifying = false;
      };

      const handleOutput = (data) => {
        const output = data.toString();

        if (tunnelMode !== 'quick') {
          if (!resolved && /Registered tunnel connection/i.test(output)) {
            if (candidateUrl === configuredPublicUrl) return;
            verifyCandidateUrl(configuredPublicUrl);
          }
          return;
        }
        // Look for the tunnel URL in output
        const urlMatch = output.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/i);
        if (!urlMatch) return;

        const newUrl = urlMatch[0];
        if (candidateUrl === newUrl) return;
        verifyCandidateUrl(newUrl);
      };
      
      this.tunnelProcess.stdout.on('data', handleOutput);
      this.tunnelProcess.stderr.on('data', handleOutput);
      
      this.tunnelProcess.on('close', (code) => {
        if (this.publicAccessEnabled && (this.publicAccessMethod === 'cloudflare' || this.publicAccessMethod === 'cloudflare_named')) {
          console.log('⚠️ Cloudflare Tunnel closed, attempting to reconnect...');
          this.publicAccessEnabled = false;
          this.publicAccessUrl = null;
          this.publicAccessMethod = null;
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
      const checkProcess = spawn('ngrok', ['--version'], { shell: false, windowsHide: true });
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
        shell: false,
        windowsHide: true,
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
   * Generate QR Code Dashboard HTML - self-contained page for retail display
   * Shows gateway's public URL QR code + active operator QR codes
   */
  generateQrDashboardHtml() {
    const publicStatus = this.getPublicAccessStatus();
    const operators = this.operatorUrls || [];
    const peerGateways = this.discoveredGateways || [];
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="refresh" content="60">
  <title>Autho Gateway - QR Dashboard</title>
  <script>
  // QRCode generator (qrcode.js by davidshimjs, MIT license) - embedded for offline use
  var QRCode;!function(){function a(a){this.mode=c.MODE_8BIT_BYTE,this.data=a,this.parsedData=[];for(var b=[],d=0,e=this.data.length;e>d;d++){var f=this.data.charCodeAt(d);f>65536?(b[0]=240|(1835008&f)>>>18,b[1]=128|(258048&f)>>>12,b[2]=128|(4032&f)>>>6,b[3]=128|63&f):f>2048?(b[0]=224|(61440&f)>>>12,b[1]=128|(4032&f)>>>6,b[2]=128|63&f):f>128?(b[0]=192|(1984&f)>>>6,b[1]=128|63&f):b[0]=f,this.parsedData=this.parsedData.concat(b)}this.parsedData.length!=this.data.length&&(this.parsedData.unshift(191),this.parsedData.unshift(187),this.parsedData.unshift(239))}function b(a,b){this.typeNumber=a,this.errorCorrectLevel=b,this.modules=null,this.moduleCount=0,this.dataCache=null,this.dataList=[]}function i(a,b){if(void 0==a.length)throw new Error(a.length+"/"+b);for(var c=0;c<a.length&&0==a[c];)c++;this.num=new Array(a.length-c+b);for(var d=0;d<a.length-c;d++)this.num[d]=a[d+c]}function j(a,b){this.totalCount=a,this.dataCount=b}function k(){this.buffer=[],this.length=0}function m(){return"undefined"!=typeof CanvasRenderingContext2D}function n(){var a=!1,b=navigator.userAgent;return/android/i.test(b)&&(a=!0,aMat=b.toString().match(/android ([0-9]\.[0-9])/i),aMat&&aMat[1]&&(a=parseFloat(aMat[1]))),a}function r(a,b){for(var c=1,e=s(a),f=0,g=l.length;g>=f;f++){var h=0;switch(b){case d.L:h=l[f][0];break;case d.M:h=l[f][1];break;case d.Q:h=l[f][2];break;case d.H:h=l[f][3]}if(h>=e)break;c++}if(c>l.length)throw new Error("Too long data");return c}function s(a){var b=encodeURI(a).toString().replace(/\%[0-9a-fA-F]{2}/g,"a");return b.length+(b.length!=a?3:0)}a.prototype={getLength:function(){return this.parsedData.length},write:function(a){for(var b=0,c=this.parsedData.length;c>b;b++)a.put(this.parsedData[b],8)}},b.prototype={addData:function(b){var c=new a(b);this.dataList.push(c),this.dataCache=null},isDark:function(a,b){if(0>a||this.moduleCount<=a||0>b||this.moduleCount<=b)throw new Error(a+","+b);return this.modules[a][b]},getModuleCount:function(){return this.moduleCount},make:function(){this.makeImpl(!1,this.getBestMaskPattern())},makeImpl:function(a,c){this.moduleCount=4*this.typeNumber+17,this.modules=new Array(this.moduleCount);for(var d=0;d<this.moduleCount;d++){this.modules[d]=new Array(this.moduleCount);for(var e=0;e<this.moduleCount;e++)this.modules[d][e]=null}this.setupPositionProbePattern(0,0),this.setupPositionProbePattern(this.moduleCount-7,0),this.setupPositionProbePattern(0,this.moduleCount-7),this.setupPositionAdjustPattern(),this.setupTimingPattern(),this.setupTypeInfo(a,c),this.typeNumber>=7&&this.setupTypeNumber(a),null==this.dataCache&&(this.dataCache=b.createData(this.typeNumber,this.errorCorrectLevel,this.dataList)),this.mapData(this.dataCache,c)},setupPositionProbePattern:function(a,b){for(var c=-1;7>=c;c++)if(!(-1>=a+c||this.moduleCount<=a+c))for(var d=-1;7>=d;d++)-1>=b+d||this.moduleCount<=b+d||(this.modules[a+c][b+d]=c>=0&&6>=c&&(0==d||6==d)||d>=0&&6>=d&&(0==c||6==c)||c>=2&&4>=c&&d>=2&&4>=d?!0:!1)},getBestMaskPattern:function(){for(var a=0,b=0,c=0;8>c;c++){this.makeImpl(!0,c);var d=f.getLostPoint(this);(0==c||a>d)&&(a=d,b=c)}return b},createMovieClip:function(a,b,c){var d=a.createEmptyMovieClip(b,c),e=1;this.make();for(var f=0;f<this.modules.length;f++)for(var g=f*e,h=0;h<this.modules[f].length;h++){var i=h*e,j=this.modules[f][h];j&&(d.beginFill(0,100),d.moveTo(i,g),d.lineTo(i+e,g),d.lineTo(i+e,g+e),d.lineTo(i,g+e),d.endFill())}return d},setupTimingPattern:function(){for(var a=8;a<this.moduleCount-8;a++)null==this.modules[a][6]&&(this.modules[a][6]=0==a%2);for(var b=8;b<this.moduleCount-8;b++)null==this.modules[6][b]&&(this.modules[6][b]=0==b%2)},setupPositionAdjustPattern:function(){for(var a=f.getPatternPosition(this.typeNumber),b=0;b<a.length;b++)for(var c=0;c<a.length;c++){var d=a[b],e=a[c];if(null==this.modules[d][e])for(var g=-2;2>=g;g++)for(var h=-2;2>=h;h++)this.modules[d+g][e+h]=-2==g||2==g||-2==h||2==h||0==g&&0==h?!0:!1}},setupTypeNumber:function(a){for(var b=f.getBCHTypeNumber(this.typeNumber),c=0;18>c;c++){var d=!a&&1==(1&b>>c);this.modules[Math.floor(c/3)][c%3+this.moduleCount-8-3]=d}for(var c=0;18>c;c++){var d=!a&&1==(1&b>>c);this.modules[c%3+this.moduleCount-8-3][Math.floor(c/3)]=d}},setupTypeInfo:function(a,b){for(var c=this.errorCorrectLevel<<3|b,d=f.getBCHTypeInfo(c),e=0;15>e;e++){var g=!a&&1==(1&d>>e);6>e?this.modules[e][8]=g:8>e?this.modules[e+1][8]=g:this.modules[this.moduleCount-15+e][8]=g}for(var e=0;15>e;e++){var g=!a&&1==(1&d>>e);8>e?this.modules[8][this.moduleCount-e-1]=g:9>e?this.modules[8][15-e-1+1]=g:this.modules[8][15-e-1]=g}this.modules[this.moduleCount-8][8]=!a},mapData:function(a,b){for(var c=-1,d=this.moduleCount-1,e=7,g=0,h=this.moduleCount-1;h>0;h-=2)for(6==h&&h--;;){for(var i=0;2>i;i++)if(null==this.modules[d][h-i]){var j=!1;g<a.length&&(j=1==(1&a[g]>>>e));var k=f.getMask(b,d,h-i);k&&(j=!j),this.modules[d][h-i]=j,e--,-1==e&&(g++,e=7)}if(d+=c,0>d||this.moduleCount<=d){d-=c,c=-c;break}}}},b.PAD0=236,b.PAD1=17,b.createData=function(a,c,d){for(var e=j.getRSBlocks(a,c),g=new k,h=0;h<d.length;h++){var i=d[h];g.put(i.mode,4),g.put(i.getLength(),f.getLengthInBits(i.mode,a)),i.write(g)}for(var l=0,h=0;h<e.length;h++)l+=e[h].dataCount;if(g.getLengthInBits()>8*l)throw new Error("code length overflow. ("+g.getLengthInBits()+">"+ 8*l+")");for(g.getLengthInBits()+4<=8*l&&g.put(0,4);0!=g.getLengthInBits()%8;)g.putBit(!1);for(;;){if(g.getLengthInBits()>=8*l)break;if(g.put(b.PAD0,8),g.getLengthInBits()>=8*l)break;g.put(b.PAD1,8)}return b.createBytes(g,e)},b.createBytes=function(a,b){for(var c=0,d=0,e=0,g=new Array(b.length),h=new Array(b.length),j=0;j<b.length;j++){var k=b[j].dataCount,l=b[j].totalCount-k;d=Math.max(d,k),e=Math.max(e,l),g[j]=new Array(k);for(var m=0;m<g[j].length;m++)g[j][m]=255&a.buffer[m+c];c+=k;var n=f.getErrorCorrectPolynomial(l),o=new i(g[j],n.getLength()-1),p=o.mod(n);h[j]=new Array(n.getLength()-1);for(var m=0;m<h[j].length;m++){var q=m+p.getLength()-h[j].length;h[j][m]=q>=0?p.get(q):0}}for(var r=0,m=0;m<b.length;m++)r+=b[m].totalCount;for(var s=new Array(r),t=0,m=0;d>m;m++)for(var j=0;j<b.length;j++)m<g[j].length&&(s[t++]=g[j][m]);for(var m=0;e>m;m++)for(var j=0;j<b.length;j++)m<h[j].length&&(s[t++]=h[j][m]);return s};for(var c={MODE_NUMBER:1,MODE_ALPHA_NUM:2,MODE_8BIT_BYTE:4,MODE_KANJI:8},d={L:1,M:0,Q:3,H:2},e={PATTERN000:0,PATTERN001:1,PATTERN010:2,PATTERN011:3,PATTERN100:4,PATTERN101:5,PATTERN110:6,PATTERN111:7},f={PATTERN_POSITION_TABLE:[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],G15:1335,G18:7973,G15_MASK:21522,getBCHTypeInfo:function(a){for(var b=a<<10;f.getBCHDigit(b)-f.getBCHDigit(f.G15)>=0;)b^=f.G15<<f.getBCHDigit(b)-f.getBCHDigit(f.G15);return(a<<10|b)^f.G15_MASK},getBCHTypeNumber:function(a){for(var b=a<<12;f.getBCHDigit(b)-f.getBCHDigit(f.G18)>=0;)b^=f.G18<<f.getBCHDigit(b)-f.getBCHDigit(f.G18);return a<<12|b},getBCHDigit:function(a){for(var b=0;0!=a;)b++,a>>>=1;return b},getPatternPosition:function(a){return f.PATTERN_POSITION_TABLE[a-1]},getMask:function(a,b,c){switch(a){case e.PATTERN000:return 0==(b+c)%2;case e.PATTERN001:return 0==b%2;case e.PATTERN010:return 0==c%3;case e.PATTERN011:return 0==(b+c)%3;case e.PATTERN100:return 0==(Math.floor(b/2)+Math.floor(c/3))%2;case e.PATTERN101:return 0==b*c%2+b*c%3;case e.PATTERN110:return 0==(b*c%2+b*c%3)%2;case e.PATTERN111:return 0==(b*c%3+(b+c)%2)%2;default:throw new Error("bad maskPattern:"+a)}},getErrorCorrectPolynomial:function(a){for(var b=new i([1],0),c=0;a>c;c++)b=b.multiply(new i([1,g.gexp(c)],0));return b},getLengthInBits:function(a,b){if(b>=1&&10>b)switch(a){case c.MODE_NUMBER:return 10;case c.MODE_ALPHA_NUM:return 9;case c.MODE_8BIT_BYTE:return 8;case c.MODE_KANJI:return 8}else if(27>b)switch(a){case c.MODE_NUMBER:return 12;case c.MODE_ALPHA_NUM:return 11;case c.MODE_8BIT_BYTE:return 16;case c.MODE_KANJI:return 10}else{if(!(41>b))throw new Error("type:"+b);switch(a){case c.MODE_NUMBER:return 14;case c.MODE_ALPHA_NUM:return 13;case c.MODE_8BIT_BYTE:return 16;case c.MODE_KANJI:return 12}}throw new Error("type:"+a)},getLostPoint:function(a){for(var b=a.getModuleCount(),c=0,d=0;b>d;d++)for(var e=0;b>e;e++){for(var f=0,g=a.isDark(d,e),h=-1;1>=h;h++)if(!(0>d+h||d+h>=b))for(var i=-1;1>=i;i++)0>e+i||e+i>=b||(0!=h||0!=i)&&g==a.isDark(d+h,e+i)&&f++;f>5&&(c+=3+f-5)}for(var d=0;b-1>d;d++)for(var e=0;b-1>e;e++){var j=0;a.isDark(d,e)&&j++,a.isDark(d+1,e)&&j++,a.isDark(d,e+1)&&j++,a.isDark(d+1,e+1)&&j++,(0==j||4==j)&&(c+=3)}for(var d=0;b>d;d++)for(var e=0;b-6>e;e++)a.isDark(d,e)&&!a.isDark(d,e+1)&&a.isDark(d,e+2)&&a.isDark(d,e+3)&&a.isDark(d,e+4)&&!a.isDark(d,e+5)&&a.isDark(d,e+6)&&(c+=40);for(var e=0;b>e;e++)for(var d=0;b-6>d;d++)a.isDark(d,e)&&!a.isDark(d+1,e)&&a.isDark(d+2,e)&&a.isDark(d+3,e)&&a.isDark(d+4,e)&&!a.isDark(d+5,e)&&a.isDark(d+6,e)&&(c+=40);for(var k=0,e=0;b>e;e++)for(var d=0;b>d;d++)a.isDark(d,e)&&k++;var l=Math.abs(100*k/b/b-50)/5;return c+=10*l}},g={glog:function(a){if(1>a)throw new Error("glog("+a+")");return g.LOG_TABLE[a]},gexp:function(a){for(;0>a;)a+=255;for(;a>=256;)a-=255;return g.EXP_TABLE[a]},EXP_TABLE:new Array(256),LOG_TABLE:new Array(256)},h=0;8>h;h++)g.EXP_TABLE[h]=1<<h;for(var h=8;256>h;h++)g.EXP_TABLE[h]=g.EXP_TABLE[h-4]^g.EXP_TABLE[h-5]^g.EXP_TABLE[h-6]^g.EXP_TABLE[h-8];for(var h=0;255>h;h++)g.LOG_TABLE[g.EXP_TABLE[h]]=h;i.prototype={get:function(a){return this.num[a]},getLength:function(){return this.num.length},multiply:function(a){for(var b=new Array(this.getLength()+a.getLength()-1),c=0;c<this.getLength();c++)for(var d=0;d<a.getLength();d++)b[c+d]^=g.gexp(g.glog(this.get(c))+g.glog(a.get(d)));return new i(b,0)},mod:function(a){if(this.getLength()-a.getLength()<0)return this;for(var b=g.glog(this.get(0))-g.glog(a.get(0)),c=new Array(this.getLength()),d=0;d<this.getLength();d++)c[d]=this.get(d);for(var d=0;d<a.getLength();d++)c[d]^=g.gexp(g.glog(a.get(d))+b);return new i(c,0).mod(a)}},j.RS_BLOCK_TABLE=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],j.getRSBlocks=function(a,b){var c=j.getRsBlockTable(a,b);if(void 0==c)throw new Error("bad rs block @ typeNumber:"+a+"/errorCorrectLevel:"+b);for(var d=c.length/3,e=[],f=0;d>f;f++)for(var g=c[3*f+0],h=c[3*f+1],i=c[3*f+2],k=0;g>k;k++)e.push(new j(h,i));return e},j.getRsBlockTable=function(a,b){switch(b){case d.L:return j.RS_BLOCK_TABLE[4*(a-1)+0];case d.M:return j.RS_BLOCK_TABLE[4*(a-1)+1];case d.Q:return j.RS_BLOCK_TABLE[4*(a-1)+2];case d.H:return j.RS_BLOCK_TABLE[4*(a-1)+3];default:return}},k.prototype={get:function(a){var b=Math.floor(a/8);return 1==(1&this.buffer[b]>>>7-a%8)},put:function(a,b){for(var c=0;b>c;c++)this.putBit(1==(1&a>>>b-c-1))},getLengthInBits:function(){return this.length},putBit:function(a){var b=Math.floor(this.length/8);this.buffer.length<=b&&this.buffer.push(0),a&&(this.buffer[b]|=128>>>this.length%8),this.length++}};var l=[[17,14,11,7],[32,26,20,14],[53,42,32,24],[78,62,46,34],[106,84,60,44],[134,106,74,58],[154,122,86,64],[192,152,108,84],[230,180,130,98],[271,213,151,119],[321,251,177,137],[367,287,203,155],[425,331,241,177],[458,362,258,194],[520,412,292,220],[586,450,322,250],[644,504,364,280],[718,560,394,310],[792,624,442,338],[858,666,482,382],[929,711,509,403],[1003,779,565,439],[1091,857,611,461],[1171,911,661,511],[1273,997,715,535],[1367,1059,751,593],[1465,1125,805,625],[1528,1190,868,658],[1628,1264,908,698],[1732,1370,982,742],[1840,1452,1030,790],[1952,1538,1112,842],[2068,1628,1168,898],[2188,1722,1228,958],[2303,1809,1283,983],[2431,1911,1351,1051],[2563,1989,1423,1093],[2699,2099,1499,1139],[2809,2213,1579,1219],[2953,2331,1663,1273]];QRCode=function(a,b){if(this._htOption={width:256,height:256,typeNumber:4,colorDark:"#000000",colorLight:"#ffffff",correctLevel:d.H},"string"==typeof b&&(b={text:b}),b)for(var c in b)this._htOption[c]=b[c];"string"==typeof a&&(a=document.getElementById(a)),this._htOption.useSVG&&(o=p),this._android=n(),this._el=a,this._oQRCode=null,this._oDrawing=new o(this._el,this._htOption),this._htOption.text&&this.makeCode(this._htOption.text)},QRCode.prototype.makeCode=function(a){this._oQRCode=new b(r(a,this._htOption.correctLevel),this._htOption.correctLevel),this._oQRCode.addData(a),this._oQRCode.make(),this._el.title=a,this._oDrawing.draw(this._oQRCode),this.makeImage()},QRCode.prototype.makeImage=function(){"function"==typeof this._oDrawing.makeImage&&(!this._android||this._android>=3)&&this._oDrawing.makeImage()},QRCode.prototype.clear=function(){this._oDrawing.clear()},QRCode.CorrectLevel=d;var o=function(a,b){this._el=a,this._htOption=b};o.prototype.draw=function(a){var b=this._htOption,c=this._el,d=a.getModuleCount();Math.floor(b.width/d),Math.floor(b.height/d);this.clear();var e=document.createElement("canvas");e.width=b.width,e.height=b.height,c.appendChild(e),this._elCanvas=e,this._oContext=e.getContext("2d"),this._draw(a)},o.prototype._draw=function(a){var b=this._oContext,c=this._htOption,d=a.getModuleCount(),e=c.width/d,f=c.height/d;for(b.fillStyle=c.colorLight,b.fillRect(0,0,c.width,c.height),h=0;d>h;h++)for(var g=0;d>g;g++){var i=a.isDark(h,g);b.fillStyle=i?c.colorDark:c.colorLight,b.fillRect(g*e,h*f,e,f)}},o.prototype.makeImage=function(){},o.prototype.clear=function(){this._elCanvas&&this._el.removeChild(this._elCanvas),this._elCanvas=null};var p=function(a,b){this._el=a,this._htOption=b};p.prototype.draw=function(a){var b=this._htOption,c=a.getModuleCount(),d=Math.floor(b.width/c),e=Math.floor(b.height/c);this.clear();var f=function(a,b){var c=document.createElementNS("http://www.w3.org/2000/svg",a);for(var d in b)b.hasOwnProperty(d)&&c.setAttribute(d,b[d]);return c},g=f("svg",{viewBox:"0 0 "+String(c)+" "+String(c),width:"100%",height:"100%",fill:b.colorLight});g.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:xlink","http://www.w3.org/1999/xlink"),this._el.appendChild(g),g.appendChild(f("rect",{fill:b.colorLight,width:"100%",height:"100%"})),g.appendChild(f("rect",{fill:b.colorDark,width:"1",height:"1",id:"template"}));for(var h=0;c>h;h++)for(var i=0;c>i;i++)if(a.isDark(h,i)){var j=f("use",{x:String(i),y:String(h)});j.setAttributeNS("http://www.w3.org/1999/xlink","href","#template"),g.appendChild(j)}},p.prototype.clear=function(){for(;this._el.hasChildNodes();)this._el.removeChild(this._el.lastChild)},QRCode.toCanvas=function(a,b,c){c=c||{};var e=c.width||200,f=c.margin||2,g=c.color||{},h=g.dark||"#000000",i=g.light||"#ffffff";a.width=e,a.height=e;var j=a.getContext("2d"),k=r(b,d.M),l=new QRCode(document.createElement("div"),{text:b,width:e,height:e,colorDark:h,colorLight:i,correctLevel:d.M,typeNumber:k});setTimeout(function(){var a=l._elCanvas||l._el.querySelector("canvas");a&&j.drawImage(a,0,0)},10)}}();
  </script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Georgia', 'Times New Roman', serif;
      background: linear-gradient(180deg, #0d0d0d 0%, #1a1a1a 50%, #0a0a0a 100%);
      color: #fff;
      min-height: 100vh;
      padding: 20px;
    }
    .back-btn {
      position: fixed;
      top: 20px;
      left: 20px;
      background: linear-gradient(135deg, #d4af37, #b8962e);
      color: #0d0d0d;
      padding: 10px 20px;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
      font-size: 0.9rem;
      border: 1px solid #d4af37;
      transition: all 0.2s;
      z-index: 1000;
    }
    .back-btn:hover { transform: scale(1.05); box-shadow: 0 4px 15px rgba(212,175,55,0.4); }
    .header {
      text-align: center;
      padding: 30px 20px;
      background: linear-gradient(90deg, #d4af37, #f4d03f, #d4af37);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .header h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 10px; letter-spacing: 3px; }
    .header p { font-size: 1.1rem; opacity: 0.9; color: #d4af37; }
    .main-qr {
      background: linear-gradient(145deg, #1a1a1a, #0d0d0d);
      border: 2px solid #d4af37;
      border-radius: 20px;
      padding: 30px;
      margin: 30px auto;
      max-width: 500px;
      text-align: center;
      box-shadow: 0 10px 40px rgba(212, 175, 55, 0.2);
    }
    .main-qr h2 {
      color: #d4af37;
      font-size: 1.5rem;
      margin-bottom: 20px;
    }
    .main-qr .qr-container {
      background: #fff;
      padding: 20px;
      border-radius: 15px;
      display: inline-block;
      margin-bottom: 20px;
    }
    .main-qr .url {
      font-family: monospace;
      font-size: 0.9rem;
      color: #aaa;
      word-break: break-all;
      padding: 10px;
      background: rgba(0,0,0,0.3);
      border-radius: 8px;
      margin-top: 15px;
    }
    .status-badge {
      display: inline-block;
      padding: 8px 20px;
      border-radius: 20px;
      font-weight: 600;
      margin-bottom: 20px;
    }
    .status-badge.online { background: #27ae60; }
    .status-badge.offline { background: #e74c3c; }
    .status-badge.pending { background: #f39c12; }
    .section-title {
      color: #d4af37;
      font-size: 1.3rem;
      text-align: center;
      margin: 40px 0 20px;
      padding-bottom: 10px;
      border-bottom: 1px solid rgba(212, 175, 55, 0.3);
    }
    .qr-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 20px;
    }
    .qr-card {
      background: linear-gradient(145deg, #1a1a1a, #0d0d0d);
      border: 1px solid rgba(212, 175, 55, 0.3);
      border-radius: 15px;
      padding: 20px;
      text-align: center;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .qr-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 10px 30px rgba(212, 175, 55, 0.25);
      border-color: #d4af37;
    }
    .qr-card h3 {
      color: #d4af37;
      font-size: 0.9rem;
      margin-bottom: 15px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .qr-card .qr-container {
      background: #fff;
      padding: 10px;
      border-radius: 10px;
      display: inline-block;
    }
    .qr-card .type-badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.7rem;
      margin-top: 10px;
      text-transform: uppercase;
    }
    .type-badge.operator { background: #3498db; }
    .type-badge.gateway { background: #9b59b6; }
    .footer {
      text-align: center;
      padding: 30px;
      color: #666;
      font-size: 0.85rem;
    }
    .no-public {
      text-align: center;
      padding: 40px;
      color: #f39c12;
    }
    .no-public p { margin-bottom: 20px; }
    .enable-btn {
      background: linear-gradient(90deg, #d4af37, #f4d03f);
      color: #1a1a2e;
      border: none;
      padding: 15px 30px;
      font-size: 1rem;
      font-weight: 600;
      border-radius: 25px;
      cursor: pointer;
      transition: transform 0.2s;
    }
    .enable-btn:hover { transform: scale(1.05); }
    .refresh-note {
      text-align: center;
      color: #666;
      font-size: 0.8rem;
      margin-top: 10px;
    }
  </style>
</head>
<body>
  <a href="/" class="back-btn">← Back to Dashboard</a>
  <div class="header">
    <h1>⚡ AUTHO GATEWAY</h1>
    <p>Scan to Connect to the Decentralized Network</p>
  </div>

  <div id="main-section">
    ${publicStatus.enabled && publicStatus.url ? `
      <div class="main-qr">
        <span class="status-badge online">● PUBLIC ACCESS ENABLED</span>
        <h2>📱 Scan to Access This Gateway</h2>
        <div class="qr-container">
          <canvas id="main-qr-canvas"></canvas>
        </div>
        <div class="url">${publicStatus.url}</div>
        <p class="refresh-note">Page auto-refreshes every 60 seconds</p>
      </div>
    ` : `
      <div class="no-public">
        <span class="status-badge pending">● PUBLIC ACCESS PENDING</span>
        <p>Public tunnel is being established...</p>
        <p style="font-size: 0.9rem; color: #888;">
          Local access: <a href="http://localhost:${EFFECTIVE_HTTP_PORT}" style="color: #d4af37;">http://localhost:${EFFECTIVE_HTTP_PORT}</a>
        </p>
        <button class="enable-btn" onclick="enablePublic()">Enable Public Access</button>
      </div>
    `}
  </div>

  <h2 class="section-title">🌐 Active Autho Operators</h2>
  <div class="qr-grid" id="operators-grid"></div>

  ${peerGateways.length > 0 ? `
    <h2 class="section-title">🔗 Peer Gateways</h2>
    <div class="qr-grid" id="gateways-grid"></div>
  ` : ''}

  <div class="footer">
    <p>Gateway ID: ${this.gatewayId}</p>
    <p>Powered by Autho Protocol • Decentralized Ownership Verification</p>
  </div>

  <script>
    const operators = ${JSON.stringify(operators)};
    const peerGateways = ${JSON.stringify(peerGateways.filter(g => g.publicUrl).map(g => ({ url: g.publicUrl, name: g.gatewayId })))};
    const mainUrl = ${JSON.stringify(publicStatus.url || '')};

    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }
    
    function createQrCard(name, url, type) {
      const card = document.createElement('div');
      card.className = 'qr-card';
      const canvas = document.createElement('canvas');
      // SECURITY: Escape HTML to prevent XSS from malicious peer data
      card.innerHTML = \`<h3>\${escapeHtml(name)}</h3><div class="qr-container"></div><span class="type-badge \${escapeHtml(type)}">\${escapeHtml(type)}</span>\`;
      card.querySelector('.qr-container').appendChild(canvas);
      QRCode.toCanvas(canvas, url, { width: 150, margin: 2, color: { dark: '#1a1a2e', light: '#ffffff' } });
      return card;
    }

    async function enablePublic() {
      try {
        const resp = await fetch('/api/public-access/enable', { method: 'POST' });
        const data = await resp.json();
        if (data.success) location.reload();
        else alert('Failed to enable public access: ' + (data.error || 'Unknown error'));
      } catch (e) { alert('Error: ' + e.message); }
    }

    document.addEventListener('DOMContentLoaded', () => {
      // Main QR code
      if (mainUrl) {
        const mainCanvas = document.getElementById('main-qr-canvas');
        if (mainCanvas) {
          QRCode.toCanvas(mainCanvas, mainUrl, { width: 250, margin: 2, color: { dark: '#1a1a2e', light: '#ffffff' } });
        }
      }
      // Operator QRs
      const opGrid = document.getElementById('operators-grid');
      operators.forEach(url => {
        try { opGrid.appendChild(createQrCard(new URL(url).hostname, url, 'operator')); } catch (e) {}
      });
      // Peer Gateway QRs
      const gwGrid = document.getElementById('gateways-grid');
      if (gwGrid) peerGateways.forEach(gw => { if (gw.url) gwGrid.appendChild(createQrCard(gw.name || 'Gateway', gw.url, 'gateway')); });
    });
  </script>
</body>
</html>`;
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
        this.mergeSyncData(message.state || message.data || {});
        break;

      case 'sync_data':
        console.log(`📥 Received sync data from seed: ${seed}`);
        this.mergeSyncData(message.state || message.data || {});
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

      case 'registry_delta':
        // Incremental state sync — operator sends only new events when gap is small
        if (message.data && message.data.toSequence > (this.registryData.sequenceNumber || 0)) {
          console.log(`📥 Registry delta from seed: ${seed} (seq ${message.data.fromSequence}→${message.data.toSequence}, ${(message.data.events || []).length} events)`);
          this.registryData = {
            sequenceNumber: message.data.toSequence,
            lastEventHash: message.data.lastEventHash || this.registryData.lastEventHash,
          };
          this.broadcastToPeers(message);
        }
        break;
      
      case 'state_verification':
        // Gateway acknowledges consensus verification from network
        console.log(`✓ State verification from ${message.nodeId} (seq: ${message.sequenceNumber})`);
        break;
      
      // Communications ledger sync
      case 'ephemeral_event':
        if (this.storeEphemeralEvent(message.event)) {
          this.broadcastToPeers(message);
          // Notify local messaging WS clients about new messages in real-time
          this.notifyMessagingClients(message.event);
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
      
      // Call signal relay from operators — deliver to local messaging clients
      case 'call_signal_relay':
        if (message.targetId && message.fromId && message.signal) {
          const targetId = String(message.targetId).trim();
          let delivered = false;
          for (const [clientWs, meta] of this.messagingClients.entries()) {
            if (meta.publicKey === targetId && clientWs.readyState === WebSocket.OPEN) {
              clientWs.send(JSON.stringify({
                type: 'call_signal',
                fromId: message.fromId,
                signal: message.signal
              }));
              delivered = true;
              break;
            }
          }
          if (delivered) {
            console.log(`📞 [Call] Relayed signal to local client ${targetId.substring(0, 12)}...`);
          }
        }
        break;

      // Transient signals from operators (typing, read receipts, reactions) — deliver to local messaging clients
      case 'transient_signal':
        if (message.data && message.data.conversationId) {
          const hops = Number(message.hops || 0);
          if (hops < 10) {
            const signalData = message.data;
            const convId = signalData.conversationId;
            const localMsg = JSON.stringify(signalData);
            for (const [clientWs, meta] of this.messagingClients.entries()) {
              if (clientWs.readyState === WebSocket.OPEN &&
                  (meta.conversationId === convId || meta.groupId === convId)) {
                try { clientWs.send(localMsg); } catch {}
              }
            }
          }
        }
        break;

      // Gossip protocol - peer sharing
      case 'gossip_peers':
        this.handleGossipPeers(message.peers);
        break;

      case 'error':
        if (message.error) console.warn(`⚠️ Operator ${seed}: ${message.error}`);
        break;

      case 'pong':
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
    
    // Load premium features data
    this.loadPremiumData();
    
    // Start message pruning (10-day retention, hourly cleanup)
    this.startMessagePruning();

    // Start HTTP server with messaging WebSocket upgrade support
    const httpServer = require('http').createServer(this.app);
    this.messagingWss = new WebSocket.Server({ noServer: true });
    this.setupMessagingWebSocket();

    const upgradeHandler = (request, socket, head) => {
      const url = require('url');
      const pathname = url.parse(request.url).pathname;
      if (pathname === '/ws/messaging') {
        this.messagingWss.handleUpgrade(request, socket, head, (ws) => {
          this.messagingWss.emit('connection', ws, request);
        });
      } else {
        socket.destroy();
      }
    };
    httpServer.on('upgrade', upgradeHandler);

    // HTTPS server for secure context (required for getUserMedia in Firefox)
    const HTTPS_PORT = EFFECTIVE_HTTP_PORT + 443; // e.g. 3444
    let httpsServer = null;
    const sslCert = getOrCreateSelfSignedCert(CONFIG.dataDir);
    if (sslCert) {
      try {
        httpsServer = https.createServer(sslCert, this.app);
        httpsServer.on('upgrade', upgradeHandler);
        httpsServer.listen(HTTPS_PORT, () => {
          console.log(`🔐 HTTPS: https://localhost:${HTTPS_PORT} (for voice/video calls)`);
        });
      } catch (e) {
        console.warn('⚠️  Could not start HTTPS server:', e.message);
      }
    }

    httpServer.listen(EFFECTIVE_HTTP_PORT, () => {
      console.log('');
      console.log('✅ Gateway Node is running!');
      console.log('========================');
      console.log(`🌐 HTTP:  http://localhost:${EFFECTIVE_HTTP_PORT}`);
      if (httpsServer) {
        console.log(`🔐 HTTPS: https://localhost:${HTTPS_PORT}  ← USE THIS FOR CALLS`);
      }
      console.log(`📡 WebSocket: ws://localhost:${EFFECTIVE_WS_PORT}`);
      console.log(`💬 Messaging WS: ws://localhost:${EFFECTIVE_HTTP_PORT}/ws/messaging`);
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

    // Fallback: only start legacy direct-seed sockets if operator mesh did not connect.
    if (this.operatorConnections.size === 0) {
      this.connectToSeeds();
    }

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
    const autoPublic = String(process.env.GATEWAY_AUTO_PUBLIC || process.env.AUTHO_AUTO_PUBLIC || '').trim().toLowerCase();
    if (autoPublic === 'true') {
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
    
    // Stop message pruning timer
    this.stopMessagePruning();
    
    // Save communications ledger (immediate flush for shutdown)
    this.flushEphemeralLedger();
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

  // Message retention: 10 days default (same as operator nodes)
  static MESSAGE_RETENTION_MS = 10 * 24 * 60 * 60 * 1000;
  
  /**
   * Prune expired messages from the ephemeral store
   * Runs automatically every hour
   */
  pruneExpiredMessages() {
    const now = Date.now();
    let prunedCount = 0;
    
    for (const [eventId, event] of this.ephemeralEvents.entries()) {
      // Skip permanent events (contacts)
      if (event.eventType === 'CONTACT_ADDED') continue;
      
      // Remove expired events
      if (event.expiresAt && event.expiresAt <= now) {
        this.ephemeralEvents.delete(eventId);
        prunedCount++;
      }
    }
    
    if (prunedCount > 0) {
      console.log(`🧹 [Ephemeral] Pruned ${prunedCount} expired messages`);
      this.saveEphemeralLedger();
    }
    
    return prunedCount;
  }

  /**
   * Start automatic pruning loop (runs every hour)
   */
  startMessagePruning() {
    // Run immediately on startup
    this.pruneExpiredMessages();
    
    // Then run every hour
    this.messagePruneTimer = setInterval(() => {
      this.pruneExpiredMessages();
    }, 60 * 60 * 1000); // 1 hour
    
    console.log('🧹 [Ephemeral] Message pruning started (10-day retention, hourly cleanup)');
  }

  /**
   * Stop automatic pruning
   */
  stopMessagePruning() {
    if (this.messagePruneTimer) {
      clearInterval(this.messagePruneTimer);
      this.messagePruneTimer = null;
    }
  }
  
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
    
    // Handle contact removal
    if (event.eventType === 'CONTACT_REMOVED' && event.payload) {
      const { userId, contactId } = event.payload;
      if (userId && contactId) {
        const userContacts = this.ephemeralContactsByUser.get(userId);
        if (userContacts) {
          userContacts.delete(contactId);
        }
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
    // Debounced async save - batches writes to avoid blocking on large payloads
    this._ledgerSavePending = true;
    if (this._ledgerSaveTimer) return; // Already scheduled
    
    this._ledgerSaveTimer = setTimeout(() => {
      this._ledgerSaveTimer = null;
      this._ledgerSavePending = false;
      this._doSaveEphemeralLedger();
    }, 1000); // Save at most once per second
  }
  
  _doSaveEphemeralLedger() {
    const filePath = path.join(CONFIG.dataDir, 'communications-ledger.json');
    try {
      const data = {
        version: 1,
        savedAt: Date.now(),
        events: Array.from(this.ephemeralEvents.values()),
      };
      // Use async write to avoid blocking the event loop
      fs.writeFile(filePath, JSON.stringify(data), (err) => {
        if (err) console.error('Failed to save communications ledger:', err.message);
      });
    } catch (e) {
      console.error('Failed to save communications ledger:', e.message);
    }
  }
  
  flushEphemeralLedger() {
    // Immediate sync save for shutdown - ensures no data loss
    if (this._ledgerSaveTimer) {
      clearTimeout(this._ledgerSaveTimer);
      this._ledgerSaveTimer = null;
    }
    if (this._ledgerSavePending || this.ephemeralEvents.size > 0) {
      const filePath = path.join(CONFIG.dataDir, 'communications-ledger.json');
      try {
        const data = {
          version: 1,
          savedAt: Date.now(),
          events: Array.from(this.ephemeralEvents.values()),
        };
        fs.writeFileSync(filePath, JSON.stringify(data));
      } catch (e) {
        console.error('Failed to flush communications ledger:', e.message);
      }
    }
  }

  // ============================================================
  // BITCOIN CHAIN API HELPERS
  // ============================================================

  getChainApiBases() {
    const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
    return network === 'mainnet'
      ? ['https://mempool.space/api', 'https://blockstream.info/api']
      : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];
  }

  // ============================================================
  // PREMIUM FEATURES HELPER METHODS
  // ============================================================

  calculateWalletSendFee(amountSats) {
    const flatFee = PREMIUM_CONFIG.wallet.sendFeeSats;
    const percentFee = Math.floor(amountSats * PREMIUM_CONFIG.wallet.sendFeePercent);
    return Math.max(flatFee, percentFee, PREMIUM_CONFIG.minFeeSats);
  }

  getFeatureCost(feature) {
    const costs = {
      // Messaging features
      'delete_message': PREMIUM_CONFIG.messaging.deleteMessageSats,
      'edit_message': PREMIUM_CONFIG.messaging.editMessageSats,
      'extended_retention': PREMIUM_CONFIG.messaging.extendedRetentionSats,
      'large_media': PREMIUM_CONFIG.messaging.largeMediaSats,
      'create_group': PREMIUM_CONFIG.messaging.createGroupSats,
      'verified_badge': PREMIUM_CONFIG.messaging.verifiedBadgeSats,
      // Subscriptions
      'subscription_pro': PREMIUM_CONFIG.subscriptions.pro.price,
      'subscription_business': PREMIUM_CONFIG.subscriptions.business.price,
    };
    return costs[feature] !== undefined ? costs[feature] : null;
  }

  getUserPremiumStatus(accountId) {
    const userCredits = this.userCredits.get(accountId) || {
      credits: 0,
      features: {},
      subscription: 'free',
      subscriptionExpiresAt: null,
    };
    
    // Check if subscription is still valid
    if (userCredits.subscriptionExpiresAt && userCredits.subscriptionExpiresAt < Date.now()) {
      userCredits.subscription = 'free';
      userCredits.subscriptionExpiresAt = null;
      this.userCredits.set(accountId, userCredits);
    }
    
    return {
      accountId,
      credits: userCredits.credits,
      features: userCredits.features,
      subscription: userCredits.subscription,
      subscriptionExpiresAt: userCredits.subscriptionExpiresAt,
      subscriptionFeatures: PREMIUM_CONFIG.subscriptions[userCredits.subscription]?.features || [],
    };
  }

  canUsePremiumFeature(accountId, feature) {
    const status = this.getUserPremiumStatus(accountId);
    
    // Check if subscription includes this feature
    const subFeatureMap = {
      'delete_message': 'delete_messages',
      'edit_message': 'edit_messages',
      'extended_retention': 'retention_30_days',
      'large_media': 'media_25mb',
      'create_group': 'unlimited_groups',
      'verified_badge': 'verified_badge',
    };
    
    const subFeature = subFeatureMap[feature];
    if (subFeature && status.subscriptionFeatures.includes(subFeature)) {
      return true;
    }
    
    // Check if user has purchased this feature
    if (status.features[feature] && status.features[feature] > 0) {
      return true;
    }
    
    return false;
  }

  grantPremiumFeature(accountId, feature, quantity = 1) {
    let userCredits = this.userCredits.get(accountId);
    if (!userCredits) {
      userCredits = {
        credits: 0,
        features: {},
        subscription: 'free',
        subscriptionExpiresAt: null,
      };
    }
    
    // Handle subscriptions
    if (feature === 'subscription_pro' || feature === 'subscription_business') {
      const tier = feature === 'subscription_pro' ? 'pro' : 'business';
      userCredits.subscription = tier;
      // 30 days subscription
      userCredits.subscriptionExpiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000);
      console.log(`⭐ [Premium] Granted ${tier} subscription to ${accountId}`);
    } else {
      // Grant feature credits
      if (!userCredits.features[feature]) {
        userCredits.features[feature] = 0;
      }
      userCredits.features[feature] += quantity;
      console.log(`⭐ [Premium] Granted ${quantity}x ${feature} to ${accountId}`);
    }
    
    this.userCredits.set(accountId, userCredits);
  }

  consumePremiumFeature(accountId, feature) {
    const userCredits = this.userCredits.get(accountId);
    if (!userCredits) return false;
    
    // Check subscription first (unlimited use)
    const status = this.getUserPremiumStatus(accountId);
    const subFeatureMap = {
      'delete_message': 'delete_messages',
      'edit_message': 'edit_messages',
    };
    
    const subFeature = subFeatureMap[feature];
    if (subFeature && status.subscriptionFeatures.includes(subFeature)) {
      return true; // Subscription covers this, no consumption needed
    }
    
    // Consume from credits
    if (userCredits.features[feature] && userCredits.features[feature] > 0) {
      userCredits.features[feature]--;
      this.userCredits.set(accountId, userCredits);
      this.savePremiumData();
      return true;
    }
    
    return false;
  }

  async verifyPaymentOnChain(txid, expectedAmountSats, expectedAddress) {
    try {
      const bases = this.getChainApiBases();
      
      for (const apiBase of bases) {
        try {
          const response = await fetch(`${apiBase}/tx/${txid}`);
          if (!response.ok) continue;
          
          const tx = await response.json();
          
          // Check outputs for payment to sponsor address
          let foundPayment = false;
          let totalToAddress = 0;
          
          for (const vout of (tx.vout || [])) {
            const scriptPubKeyAddress = vout.scriptpubkey_address;
            if (scriptPubKeyAddress === expectedAddress) {
              totalToAddress += vout.value || 0;
            }
          }
          
          if (totalToAddress >= expectedAmountSats) {
            foundPayment = true;
          }
          
          if (foundPayment) {
            return {
              verified: true,
              txid,
              amountSats: totalToAddress,
              confirmed: tx.status?.confirmed || false,
            };
          }
          
          return {
            verified: false,
            reason: `Transaction does not contain payment of ${expectedAmountSats} sats to ${expectedAddress}. Found: ${totalToAddress} sats`,
          };
        } catch (e) {
          continue;
        }
      }
      
      return { verified: false, reason: 'Could not verify transaction on chain' };
    } catch (error) {
      return { verified: false, reason: error.message };
    }
  }

  // ============================================================
  // PREPAID SERVICE BALANCE MANAGEMENT
  // Stored locally, works independently of main node / operators
  // ============================================================

  getServiceBalance(accountId) {
    const balance = this.serviceBalances.get(accountId) || {
      serviceBalanceSats: 0,
      serviceBalanceLastFundedAt: null,
      serviceBalanceTotalFundedSats: 0,
      serviceBalanceTotalUsedSats: 0,
    };
    return balance;
  }

  creditServiceBalance(accountId, amountSats, txid) {
    let balance = this.serviceBalances.get(accountId);
    if (!balance) {
      balance = {
        serviceBalanceSats: 0,
        serviceBalanceLastFundedAt: null,
        serviceBalanceTotalFundedSats: 0,
        serviceBalanceTotalUsedSats: 0,
      };
    }

    balance.serviceBalanceSats += amountSats;
    balance.serviceBalanceLastFundedAt = Date.now();
    balance.serviceBalanceTotalFundedSats += amountSats;

    this.serviceBalances.set(accountId, balance);
    console.log(`💰 [Service] Credited ${amountSats} sats to ${accountId} (txid: ${txid}). New balance: ${balance.serviceBalanceSats} sats`);
    
    this.savePremiumData();
    return balance;
  }

  useServiceBalance(accountId, amountSats, action, actionId) {
    let balance = this.serviceBalances.get(accountId);
    if (!balance || balance.serviceBalanceSats < amountSats) {
      return false;
    }

    balance.serviceBalanceSats -= amountSats;
    balance.serviceBalanceTotalUsedSats += amountSats;

    this.serviceBalances.set(accountId, balance);
    console.log(`💸 [Service] Used ${amountSats} sats from ${accountId} for ${action}:${actionId}. Remaining: ${balance.serviceBalanceSats} sats`);
    
    this.savePremiumData();
    return true;
  }

  loadPremiumData() {
    const filePath = path.join(CONFIG.dataDir, 'premium-data.json');
    try {
      if (fs.existsSync(filePath)) {
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        
        // Load user credits
        for (const [accountId, credits] of Object.entries(data.userCredits || {})) {
          this.userCredits.set(accountId, credits);
        }
        
        // Load payment history
        this.paymentHistory = data.paymentHistory || [];
        
        // Load service balances (prepaid sats)
        for (const [accountId, balance] of Object.entries(data.serviceBalances || {})) {
          this.serviceBalances.set(accountId, balance);
        }
        
        // Load service payment history (txid -> info)
        for (const [txid, info] of Object.entries(data.servicePaymentHistory || {})) {
          this.servicePaymentHistory.set(txid, info);
        }
        
        console.log(`💰 Loaded premium data for ${this.userCredits.size} users, ${this.serviceBalances.size} service balances`);
      }
    } catch (e) {
      console.error('Failed to load premium data:', e.message);
    }
  }

  savePremiumData() {
    const filePath = path.join(CONFIG.dataDir, 'premium-data.json');
    try {
      const data = {
        version: 2,
        savedAt: Date.now(),
        userCredits: Object.fromEntries(this.userCredits),
        paymentHistory: this.paymentHistory.slice(-1000), // Keep last 1000 payments
        serviceBalances: Object.fromEntries(this.serviceBalances),
        servicePaymentHistory: Object.fromEntries(this.servicePaymentHistory),
      };
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    } catch (e) {
      console.error('Failed to save premium data:', e.message);
    }
  }

  // ============================================================
  // P2P MESSAGING - LOCAL EVENT CREATION (NO OPERATOR REQUIRED)
  // ============================================================

  generateEventId() {
    return `evt_${Date.now()}_${require('crypto').randomBytes(8).toString('hex')}`;
  }

  generateMessageId() {
    return `msg_${Date.now()}_${require('crypto').randomBytes(8).toString('hex')}`;
  }

  generateConversationId(userId1, userId2, itemId = null) {
    const sorted = [userId1, userId2].sort();
    const base = `${sorted[0]}:${sorted[1]}`;
    const suffix = itemId ? `:${itemId}` : '';
    return require('crypto').createHash('sha256').update(base + suffix).digest('hex').substring(0, 32);
  }

  generateGroupId() {
    return `grp_${Date.now()}_${require('crypto').randomBytes(8).toString('hex')}`;
  }

  getRetentionMs(mediaType = 'TEXT') {
    const RETENTION_MS = {
      TEXT: 10 * 24 * 60 * 60 * 1000,      // 10 days
      IMAGE: 7 * 24 * 60 * 60 * 1000,      // 7 days
      AUDIO: 5 * 24 * 60 * 60 * 1000,      // 5 days
      VIDEO: 3 * 24 * 60 * 60 * 1000,      // 3 days
    };
    return RETENTION_MS[mediaType] || RETENTION_MS.TEXT;
  }

  createLocalEphemeralEvent(eventType, payload, mediaType = 'TEXT') {
    const now = Date.now();
    const isPermanent = eventType === 'CONTACT_ADDED' || eventType === 'CONTACT_REMOVED';
    
    const event = {
      eventId: this.generateEventId(),
      eventType,
      payload,
      timestamp: now,
      expiresAt: isPermanent ? null : now + this.getRetentionMs(mediaType),
      sourceGateway: this.gatewayId,
    };

    // Store locally
    if (this.storeEphemeralEvent(event)) {
      this.saveEphemeralLedger();
      // Broadcast to all peers (operators + gateway mesh)
      this.broadcastEphemeralEvent(event);
      return event;
    }
    return null;
  }

  broadcastEphemeralEvent(event) {
    const message = { type: 'ephemeral_event', event };
    
    // Broadcast to incoming peer connections
    this.broadcastToPeers(message);
    
    // Broadcast to operator WebSocket connections (outgoing)
    this.broadcastToOperatorConnections(message);
    
    // Broadcast to gateway mesh peers
    this.broadcastToGatewayPeers(message);
    
    // Broadcast to local WebSocket clients
    this.broadcastToLocalClients(message);
  }

  broadcastToOperatorConnections(message) {
    if (!this.operatorConnections || this.operatorConnections.size === 0) return;
    const msgStr = JSON.stringify(message);
    for (const [operatorId, conn] of this.operatorConnections) {
      try {
        if (conn.ws && conn.ws.readyState === WebSocket.OPEN) {
          conn.ws.send(msgStr);
        }
      } catch (e) {
        console.error(`Failed to send to operator ${operatorId}:`, e.message);
      }
    }
  }

  broadcastToLocalClients(message) {
    const msgStr = JSON.stringify(message);
    if (this.wss) {
      for (const client of this.wss.clients) {
        if (client.readyState === WebSocket.OPEN) {
          client.send(msgStr);
        }
      }
    }
    // Also notify messaging WS clients (/ws/messaging) about ephemeral events
    if (message.type === 'ephemeral_event' && message.event) {
      this.notifyMessagingClients(message.event);
    }
  }

  notifyMessagingClients(event) {
    if (!event || !this.messagingClients || this.messagingClients.size === 0) return;

    if (event.eventType === 'MESSAGE_SENT' && event.payload) {
      const { conversationId, messageId, senderId, recipientId } = event.payload;
      const pushMsg = JSON.stringify({
        type: 'new_message',
        conversationId,
        messageId,
        senderId,
        timestamp: event.timestamp || Date.now(),
      });
      for (const [ws, meta] of this.messagingClients.entries()) {
        if (ws.readyState === WebSocket.OPEN) {
          if (meta.publicKey === recipientId || meta.publicKey === senderId ||
              meta.conversationId === conversationId) {
            try { ws.send(pushMsg); } catch {}
          }
        }
      }
    } else if (event.eventType === 'GROUP_MESSAGE_SENT' && event.payload) {
      const { groupId, messageId, senderId } = event.payload;
      const pushMsg = JSON.stringify({
        type: 'new_group_message',
        groupId,
        messageId,
        senderId,
        timestamp: event.timestamp || Date.now(),
      });
      for (const [ws, meta] of this.messagingClients.entries()) {
        if (ws.readyState === WebSocket.OPEN && meta.groupId === groupId) {
          try { ws.send(pushMsg); } catch {}
        }
      }
    } else if (event.eventType === 'MESSAGE_DELETED' && event.payload) {
      const pushMsg = JSON.stringify({ type: 'message_deleted', data: event.payload });
      for (const [ws, meta] of this.messagingClients.entries()) {
        if (ws.readyState === WebSocket.OPEN) {
          try { ws.send(pushMsg); } catch {}
        }
      }
    } else if (event.eventType === 'MESSAGE_EDITED' && event.payload) {
      const pushMsg = JSON.stringify({ type: 'message_edited', data: event.payload });
      for (const [ws, meta] of this.messagingClients.entries()) {
        if (ws.readyState === WebSocket.OPEN) {
          try { ws.send(pushMsg); } catch {}
        }
      }
    }
  }

  isBlocked(blockerId, blockedId) {
    for (const event of this.ephemeralEvents.values()) {
      if (event.eventType === 'USER_BLOCKED' && event.payload) {
        if (event.payload.blockerId === blockerId && event.payload.blockedId === blockedId) {
          return true;
        }
      }
    }
    return false;
  }

  // ============================================================
  // MESSAGING API HELPER METHODS
  // ============================================================

  mergeSyncData(newData) {
    if (!newData || typeof newData !== 'object') return;
    // Preserve existing rich data if new sync has empty collections
    const mergeFields = ['accounts', 'items', 'operators', 'settlements', 'consignments'];
    const prev = this.registryData || {};
    this.registryData = { ...prev, ...newData };
    for (const field of mergeFields) {
      const newVal = newData[field];
      const prevVal = prev[field];
      // If new data has empty/missing field but we had data, keep existing
      const newIsEmpty = !newVal || (Array.isArray(newVal) && newVal.length === 0) || (typeof newVal === 'object' && !Array.isArray(newVal) && Object.keys(newVal).length === 0);
      const prevHasData = prevVal && ((Array.isArray(prevVal) && prevVal.length > 0) || (typeof prevVal === 'object' && !Array.isArray(prevVal) && Object.keys(prevVal).length > 0));
      if (newIsEmpty && prevHasData) {
        this.registryData[field] = prevVal;
      }
    }
    this.convertEntriesArrays();
  }

  convertEntriesArrays() {
    // Operator sends Map data as Array.from(map.entries()) → [[key, value], ...]
    // Convert these back to plain objects for easy lookup
    const fields = ['accounts', 'items', 'operators', 'settlements', 'consignments'];
    for (const field of fields) {
      const val = this.registryData?.[field];
      if (Array.isArray(val) && val.length > 0 && Array.isArray(val[0])) {
        const obj = {};
        for (const [k, v] of val) {
          obj[k] = v;
        }
        this.registryData[field] = obj;
      }
    }
  }

  resolveDisplayName(participantId) {
    if (!participantId) return 'Unknown';
    const accounts = this.registryData?.accounts || {};
    // Direct lookup by accountId
    const acc = accounts[participantId];
    if (acc) {
      return acc.username || acc.companyName || acc.displayName || participantId.substring(0, 12) + '...';
    }
    // Search by walletAddress or publicKey
    for (const key of Object.keys(accounts)) {
      const a = accounts[key];
      if (!a) continue;
      const wa = String(a.walletAddress || a.identityAddress || '').trim();
      const pk = String(a.publicKey || a.walletPublicKey || '').trim();
      if ((wa && wa === participantId) || (pk && pk === participantId)) {
        return a.username || a.companyName || a.displayName || participantId.substring(0, 12) + '...';
      }
    }
    return participantId.substring(0, 12) + '...';
  }

  async getAccountFromSession(req) {
    const sessionToken = req.headers['x-session-token'] || req.cookies?.sessionToken;
    if (!sessionToken) return null;
    
    // Try to get account from local cache or proxy to operator
    try {
      for (const operatorUrl of this.operatorUrls) {
        const response = await fetch(`${operatorUrl}/api/auth/verify-session`, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'x-session-token': sessionToken,
          },
          body: JSON.stringify({ sessionToken }),
        });
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.account) {
            return data.account;
          }
        }
      }
    } catch (e) {
      console.error('Session verification error:', e.message);
    }
    return null;
  }

  getUserConversations(userId) {
    const conversations = new Map();
    const now = Date.now();
    
    for (const event of this.ephemeralEvents.values()) {
      if (event.expiresAt && event.expiresAt <= now) continue;
      if (event.eventType !== 'MESSAGE_SENT') continue;
      
      const payload = event.payload || {};
      if (payload.senderId !== userId && payload.recipientId !== userId) continue;
      
      const convId = payload.conversationId;
      if (!convId) continue;
      
      const existing = conversations.get(convId);
      if (!existing || event.timestamp > existing.lastMessageAt) {
        const otherUserId = payload.senderId === userId ? payload.recipientId : payload.senderId;
        conversations.set(convId, {
          conversationId: convId,
          participantId: otherUserId,
          lastMessageAt: event.timestamp,
          itemId: payload.itemId,
        });
      }
    }
    
    return Array.from(conversations.values())
      .sort((a, b) => b.lastMessageAt - a.lastMessageAt);
  }

  getConversationMessages(conversationId, userId) {
    const messages = [];
    const now = Date.now();
    
    for (const event of this.ephemeralEvents.values()) {
      if (event.expiresAt && event.expiresAt <= now) continue;
      if (event.eventType !== 'MESSAGE_SENT') continue;
      
      const payload = event.payload || {};
      if (payload.conversationId !== conversationId) continue;
      if (payload.senderId !== userId && payload.recipientId !== userId) continue;
      
      messages.push({
        messageId: payload.messageId,
        senderId: payload.senderId,
        recipientId: payload.recipientId,
        encryptedContent: payload.senderId === userId ? payload.encryptedForSender : payload.encryptedContent,
        timestamp: event.timestamp,
        expiresAt: event.expiresAt,
        itemId: payload.itemId,
        replyToMessageId: payload.replyToMessageId,
      });
    }
    
    return messages.sort((a, b) => a.timestamp - b.timestamp);
  }

  getUserContacts(userId) {
    const contacts = new Map();
    const contactSet = this.ephemeralContactsByUser.get(userId);
    if (!contactSet || contactSet.size === 0) return [];
    
    // Build contact details from events
    for (const event of this.ephemeralEvents.values()) {
      if (event.eventType !== 'CONTACT_ADDED' && event.eventType !== 'CONTACT_UPDATED') continue;
      
      const payload = event.payload || {};
      if (payload.userId !== userId) continue;
      if (!contactSet.has(payload.contactId)) continue;
      
      const existing = contacts.get(payload.contactId) || {};
      contacts.set(payload.contactId, {
        contactId: payload.contactId,
        nickname: payload.nickname || existing.nickname || null,
        publicKey: payload.publicKey || existing.publicKey || null,
        addedAt: existing.addedAt || event.timestamp,
        updatedAt: event.timestamp,
      });
    }
    
    // Ensure all contacts in the set are included
    for (const contactId of contactSet) {
      if (!contacts.has(contactId)) {
        contacts.set(contactId, { contactId, nickname: null, publicKey: null, addedAt: null });
      }
    }
    
    return Array.from(contacts.values());
  }

  getUserGroups(userId) {
    const groups = [];
    const groupMap = new Map();
    const now = Date.now();
    
    for (const event of this.ephemeralEvents.values()) {
      if (event.expiresAt && event.expiresAt <= now) continue;
      
      if (event.eventType === 'GROUP_CREATED') {
        const payload = event.payload || {};
        groupMap.set(payload.groupId, {
          groupId: payload.groupId,
          name: payload.name,
          creatorId: payload.creatorId,
          members: payload.initialMembers || [payload.creatorId],
          admins: [payload.creatorId],
          createdAt: event.timestamp,
        });
      } else if (event.eventType === 'GROUP_MEMBER_ADDED') {
        const payload = event.payload || {};
        const group = groupMap.get(payload.groupId);
        if (group && !group.members.includes(payload.memberId)) {
          group.members.push(payload.memberId);
        }
      } else if (event.eventType === 'GROUP_LEFT' || event.eventType === 'GROUP_MEMBER_REMOVED') {
        const payload = event.payload || {};
        const group = groupMap.get(payload.groupId);
        if (group) {
          group.members = group.members.filter(m => m !== payload.memberId);
        }
      }
    }
    
    for (const group of groupMap.values()) {
      if (group.members.includes(userId)) {
        groups.push(group);
      }
    }
    
    return groups;
  }

  getGroup(groupId) {
    const now = Date.now();
    let group = null;
    
    for (const event of this.ephemeralEvents.values()) {
      if (event.expiresAt && event.expiresAt <= now) continue;
      
      if (event.eventType === 'GROUP_CREATED' && event.payload?.groupId === groupId) {
        const payload = event.payload;
        group = {
          groupId: payload.groupId,
          name: payload.name,
          creatorId: payload.creatorId,
          members: payload.initialMembers || [payload.creatorId],
          admins: [payload.creatorId],
          createdAt: event.timestamp,
        };
      } else if (event.eventType === 'GROUP_MEMBER_ADDED' && event.payload?.groupId === groupId && group) {
        if (!group.members.includes(event.payload.memberId)) {
          group.members.push(event.payload.memberId);
        }
      } else if ((event.eventType === 'GROUP_LEFT' || event.eventType === 'GROUP_MEMBER_REMOVED') && 
                 event.payload?.groupId === groupId && group) {
        group.members = group.members.filter(m => m !== event.payload.memberId);
      }
    }
    
    return group;
  }

  getGroupMessages(groupId, userId) {
    const messages = [];
    const now = Date.now();
    
    for (const event of this.ephemeralEvents.values()) {
      if (event.expiresAt && event.expiresAt <= now) continue;
      if (event.eventType !== 'GROUP_MESSAGE_SENT') continue;
      
      const payload = event.payload || {};
      if (payload.groupId !== groupId) continue;
      
      messages.push({
        messageId: payload.messageId,
        groupId: payload.groupId,
        senderId: payload.senderId,
        encryptedContent: payload.encryptedContentByMember?.[userId],
        timestamp: event.timestamp,
        expiresAt: event.expiresAt,
        replyToMessageId: payload.replyToMessageId,
      });
    }
    
    return messages.sort((a, b) => a.timestamp - b.timestamp);
  }

  getMessage(messageId) {
    for (const event of this.ephemeralEvents.values()) {
      if (event.payload?.messageId === messageId) {
        return event;
      }
    }
    return null;
  }

  deleteMessage(messageId, accountId) {
    const message = this.getMessage(messageId);
    if (!message) return false;
    
    // Verify ownership - only sender can delete
    if (message.payload?.senderId !== accountId && message.payload?.from !== accountId) {
      return false;
    }
    
    // Mark as deleted (soft delete - keeps record but hides content)
    message.payload.deleted = true;
    message.payload.deletedAt = Date.now();
    message.payload.content = '[Message deleted]';
    
    // Broadcast deletion to connected clients
    this.broadcastToClients({
      type: 'message_deleted',
      messageId,
      deletedAt: message.payload.deletedAt,
    });
    
    // Broadcast to peer gateways
    this.broadcastToPeers({
      type: 'ephemeral_event',
      eventType: 'MESSAGE_DELETED',
      payload: { messageId, deletedAt: message.payload.deletedAt },
    });
    
    console.log(`🗑️ [Message] Deleted message ${messageId} by ${accountId}`);
    return true;
  }

  editMessage(messageId, accountId, newContent) {
    const message = this.getMessage(messageId);
    if (!message) return false;
    
    // Verify ownership - only sender can edit
    if (message.payload?.senderId !== accountId && message.payload?.from !== accountId) {
      return false;
    }
    
    // Store original content and update
    if (!message.payload.editHistory) {
      message.payload.editHistory = [];
    }
    message.payload.editHistory.push({
      content: message.payload.content,
      editedAt: Date.now(),
    });
    
    message.payload.content = newContent;
    message.payload.edited = true;
    message.payload.lastEditedAt = Date.now();
    
    // Broadcast edit to connected clients
    this.broadcastToClients({
      type: 'message_edited',
      messageId,
      newContent,
      lastEditedAt: message.payload.lastEditedAt,
    });
    
    // Broadcast to peer gateways
    this.broadcastToPeers({
      type: 'ephemeral_event',
      eventType: 'MESSAGE_EDITED',
      payload: { messageId, newContent, lastEditedAt: message.payload.lastEditedAt },
    });
    
    console.log(`✏️ [Message] Edited message ${messageId} by ${accountId}`);
    return true;
  }

  getConversationId(userId1, userId2) {
    // Generate consistent conversation ID from two user IDs (sorted alphabetically)
    const sorted = [userId1, userId2].sort();
    return `conv_${sorted[0]}_${sorted[1]}`;
  }

  getMessageStatus(messageId) {
    const event = this.getMessage(messageId);
    if (!event) return { delivered: false, read: false };
    return {
      delivered: true,
      read: event.payload?.readAt ? true : false,
      readAt: event.payload?.readAt,
    };
  }

  getReactions(messageId) {
    const reactions = [];
    for (const event of this.ephemeralEvents.values()) {
      if (event.eventType === 'MESSAGE_REACTION_ADDED' && event.payload?.messageId === messageId) {
        reactions.push({
          userId: event.payload.userId,
          emoji: event.payload.emoji,
          timestamp: event.timestamp,
        });
      }
    }
    return reactions;
  }

  getTypingUsers(conversationId) {
    // Typing indicators are very short-lived, gateway doesn't track them locally
    return [];
  }

  isUserOnline(userId) {
    // Online status is maintained by operators, gateway doesn't track
    return false;
  }

  getUserLastSeen(userId) {
    // Last seen is maintained by operators
    return null;
  }

  searchMessages(userId, query, limit) {
    // Gateway has encrypted messages, cannot search content
    // Return recent messages for the user instead
    const messages = [];
    const now = Date.now();
    
    for (const event of this.ephemeralEvents.values()) {
      if (event.expiresAt && event.expiresAt <= now) continue;
      if (event.eventType !== 'MESSAGE_SENT') continue;
      
      const payload = event.payload || {};
      if (payload.senderId !== userId && payload.recipientId !== userId) continue;
      
      messages.push({
        messageId: payload.messageId,
        senderId: payload.senderId,
        recipientId: payload.recipientId,
        conversationId: payload.conversationId,
        timestamp: event.timestamp,
        expiresAt: event.expiresAt,
      });
      
      if (messages.length >= limit) break;
    }
    
    return messages.sort((a, b) => b.timestamp - a.timestamp).slice(0, limit);
  }

  // ============================================================
  // GATEWAY DOWNLOAD HELPER METHODS
  // ============================================================

  async proxyDownload(req, res, filename) {
    // Try to fetch from operators
    for (const operatorUrl of this.operatorUrls) {
      try {
        const response = await fetch(`${operatorUrl}/downloads/gateway-node/${filename}`);
        if (response.ok) {
          const contentType = response.headers.get('content-type') || 'application/octet-stream';
          res.setHeader('Content-Type', contentType);
          const buffer = await response.arrayBuffer();
          return res.send(Buffer.from(buffer));
        }
      } catch (e) {
        // Try next operator
      }
    }
    res.status(404).json({ error: 'File not available' });
  }

  generateInstallPage() {
    const baseUrl = this.publicHttpUrl || `http://localhost:${EFFECTIVE_HTTP_PORT}`;
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Install Autho Gateway</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #fff; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { max-width: 600px; padding: 40px; text-align: center; }
    h1 { font-size: 2.5rem; margin-bottom: 10px; }
    h1 span { color: #ffd700; }
    p { color: #888; margin-bottom: 30px; }
    .download-btn { display: inline-block; background: linear-gradient(135deg, #ffd700, #ffaa00); color: #000; font-weight: bold; padding: 16px 32px; border-radius: 8px; text-decoration: none; font-size: 1.1rem; margin: 10px; transition: transform 0.2s; }
    .download-btn:hover { transform: scale(1.05); }
    .download-btn.secondary { background: #333; color: #fff; }
    .code-block { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 16px; margin: 20px 0; text-align: left; font-family: monospace; font-size: 0.85rem; overflow-x: auto; }
    .code-block code { color: #ffd700; }
    .section { margin: 30px 0; }
    h3 { color: #ffd700; margin-bottom: 10px; }
    .source-info { margin-top: 40px; padding-top: 20px; border-top: 1px solid #333; color: #666; font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1><span>A</span>utho Gateway</h1>
    <p>Run your own Autho gateway node and help decentralize the network</p>
    
    <div class="section">
      <h3>🪟 Windows</h3>
      <a href="${baseUrl}/downloads/gateway-node/Install-Autho-Gateway.bat" class="download-btn" download>Download Installer</a>
      <div class="code-block">
        <code>powershell -Command "irm ${baseUrl}/downloads/gateway-node/Install-Autho-Gateway.bat -OutFile Install.bat; .\\Install.bat"</code>
      </div>
    </div>
    
    <div class="section">
      <h3>🐧 Linux / 🍎 Mac</h3>
      <a href="${baseUrl}/downloads/gateway-node/install.sh" class="download-btn secondary" download>Download Script</a>
      <div class="code-block">
        <code>curl -sSL ${baseUrl}/downloads/gateway-node/install.sh | bash</code>
      </div>
    </div>
    
    <div class="section">
      <h3>📦 Manual Install</h3>
      <p style="font-size: 0.9rem; margin-bottom: 10px;">Download individual files:</p>
      <a href="${baseUrl}/downloads/gateway-node/gateway-package.js" class="download-btn secondary" style="padding: 10px 20px; font-size: 0.9rem;" download>gateway-package.js</a>
      <a href="${baseUrl}/downloads/gateway-node/package.json" class="download-btn secondary" style="padding: 10px 20px; font-size: 0.9rem;" download>package.json</a>
    </div>
    
    <div class="source-info">
      Served from gateway: ${this.gatewayId}<br>
      ${this.publicHttpUrl ? 'Public URL: ' + this.publicHttpUrl : 'Running locally'}
    </div>
  </div>
</body>
</html>`;
  }

  // ==================== GATEWAY-TO-GATEWAY MESH ====================

  async registerAsPublicGateway() {
    if (!this.isPublicGateway || !this.publicHttpUrl) {
      console.log('🔒 Gateway is private (not registering with network)');
      return;
    }

    console.log(`📢 Registering as public gateway: ${this.gatewayId}`);
    
    // Build WebSocket URL - cloudflare tunnels use same URL for WS
    const wsUrl = this.publicHttpUrl.replace('https://', 'wss://').replace('http://', 'ws://');
    
    for (const operatorUrl of this.operatorUrls) {
      try {
        const response = await fetch(`${operatorUrl}/api/network/gateways/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            gatewayId: this.gatewayId,
            httpUrl: this.publicHttpUrl,
            wsUrl: wsUrl,
            version: '1.0.6',
          }),
        });
        
        if (response.ok) {
          const data = await response.json();
          console.log(`✅ Registered with operator: ${operatorUrl}`);
          
          // Connect to peer gateways returned by operator
          if (data.peerGateways && Array.isArray(data.peerGateways)) {
            console.log(`📡 Received ${data.peerGateways.length} peer gateways from operator`);
            for (const peer of data.peerGateways) {
              if (peer.gatewayId !== this.gatewayId && peer.wsUrl) {
                // Add to discovered list if not already there
                const exists = this.discoveredGateways.some(g => g.gatewayId === peer.gatewayId);
                if (!exists) {
                  this.discoveredGateways.push(peer);
                }
              }
            }
            // Trigger connection to new peers
            this.connectToGatewayPeers();
          }
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
        // Send ephemeral sync request to get their messages
        ws.send(JSON.stringify({
          type: 'ephemeral_sync_request',
          since: this.getLatestEphemeralTimestamp() - (24 * 60 * 60 * 1000), // Last 24 hours
          limit: 500,
          gatewayId: this.gatewayId
        }));
        break;

      case 'gateway_handshake_ack':
        console.log(`✓ Gateway handshake acknowledged by: ${message.gatewayId}`);
        // Request ephemeral sync from the peer
        ws.send(JSON.stringify({
          type: 'ephemeral_sync_request',
          since: this.getLatestEphemeralTimestamp() - (24 * 60 * 60 * 1000),
          limit: 500,
          gatewayId: this.gatewayId
        }));
        break;

      case 'ephemeral_sync_request':
        // Respond with our ephemeral events
        this.handleEphemeralSyncRequest(message, ws);
        break;

      case 'ephemeral_sync_response':
        // Import events from peer gateway
        if (Array.isArray(message.events)) {
          let imported = 0;
          for (const event of message.events) {
            if (this.storeEphemeralEvent(event)) imported++;
          }
          if (imported > 0) {
            console.log(`📥 [Ephemeral] Imported ${imported} events from gateway ${gatewayId}`);
          }
        }
        break;

      case 'registry_update':
        // Relay registry updates from gateway peers
        if (message.data && message.data.sequenceNumber > (this.registryData.sequenceNumber || 0)) {
          console.log(`📥 Registry update from gateway ${gatewayId}`);
          this.registryData = message.data;
          this.broadcastToPeers(message);
        }
        break;

      case 'registry_delta':
        // Relay incremental deltas from gateway peers
        if (message.data && message.data.toSequence > (this.registryData.sequenceNumber || 0)) {
          console.log(`📥 Registry delta from gateway ${gatewayId} (seq ${message.data.fromSequence}→${message.data.toSequence})`);
          this.registryData = {
            sequenceNumber: message.data.toSequence,
            lastEventHash: message.data.lastEventHash || this.registryData.lastEventHash,
          };
          this.broadcastToPeers(message);
        }
        break;

      case 'ephemeral_event':
        // Relay ephemeral events from gateway peers
        if (this.storeEphemeralEvent(message.event)) {
          this.broadcastToPeers(message);
          this.broadcastToGatewayPeers(message, gatewayId); // Forward to other gateways except sender
          this.broadcastToLocalClients(message); // Notify local WebSocket clients
        }
        break;

      case 'typing_indicator':
        // Relay typing indicators to local clients and other gateways (not stored)
        this.broadcastToLocalClients(message);
        this.broadcastToGatewayPeers(message, gatewayId);
        break;

      case 'online_status':
        // Relay online status to local clients and other gateways (not stored)
        this.broadcastToLocalClients(message);
        this.broadcastToGatewayPeers(message, gatewayId);
        break;

      case 'p2p_message':
        // Direct P2P encrypted message relay
        if (message.recipientId) {
          // Store as ephemeral event if it has proper structure
          if (message.event && this.storeEphemeralEvent(message.event)) {
            this.broadcastToLocalClients({ type: 'ephemeral_event', event: message.event });
            this.broadcastToGatewayPeers(message, gatewayId);
          }
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
