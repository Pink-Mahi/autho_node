#!/usr/bin/env node

/**
 * Autho Gateway Node - Self-Contained Package
 * 
 * This is a complete, working gateway node that users can download and run.
 * The seed nodes are hardcoded to prevent modification.
 */

const express = require('express');
const WebSocket = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const UI_CACHE_TTL_MS = (() => {
  const n = Number(process.env.AUTHO_UI_CACHE_TTL_MS);
  return Number.isFinite(n) && n >= 0 ? n : (5 * 60 * 1000);
})();

// HARD-CODED CONFIGURATION - USERS CANNOT MODIFY
const CONFIG = {
  // Seed nodes - hardcoded to prevent modification
  seedNodes: ['autho.pinkmahi.com:3000', 'autho.cartpathcleaning.com'],

  operatorUrls: ['https://autho.pinkmahi.com', 'https://autho.cartpathcleaning.com', 'http://autho.pinkmahi.com:3000'],
  
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
    this.operatorConnections = new Map();
    this.discoveredOperators = [];
    this.lastOperatorDiscovery = 0;
    
    this.setupMiddleware();
    this.setupRoutes();
  }

  sha256Hex(s) {
    return crypto.createHash('sha256').update(String(s || ''), 'utf8').digest('hex');
  }

  async getPowChallenge(operatorUrl, resource) {
    const url = `${operatorUrl}/api/pow/challenge?resource=${encodeURIComponent(resource)}`;
    const resp = await fetch(url, { method: 'GET' });
    const text = await resp.text();
    if (!resp.ok) throw new Error(`PoW challenge failed: ${resp.status}`);
    const json = JSON.parse(text);
    if (!json || json.enabled !== true) return null;
    if (!json.challengeId || !json.salt || !json.difficulty) return null;
    return json;
  }

  solvePow(params) {
    const maxMs = (() => {
      const n = Number(process.env.AUTHO_GATEWAY_POW_MAX_MS);
      return Number.isFinite(n) && n > 0 ? Math.min(30_000, Math.floor(n)) : 1500;
    })();

    const maxIters = (() => {
      const n = Number(process.env.AUTHO_GATEWAY_POW_MAX_ITERS);
      return Number.isFinite(n) && n > 0 ? Math.min(50_000_000, Math.floor(n)) : 5_000_000;
    })();

    const start = Date.now();
    const salt = String(params.salt || '');
    const resource = String(params.resource || '');
    const difficulty = Math.max(4, Math.min(32, Math.floor(Number(params.difficulty || 0))));
    const leadingNibbles = Math.floor(difficulty / 4);

    let i = 0;
    while (i < maxIters) {
      if ((Date.now() - start) > maxMs) return null;
      const nonce = `${crypto.randomBytes(8).toString('hex')}${i.toString(16)}`;
      const digest = this.sha256Hex(`${salt}:${resource}:${nonce}`);
      if (digest.startsWith('0'.repeat(leadingNibbles))) {
        return nonce;
      }
      i++;
    }
    return null;
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

  async ensureOperatorHead(operatorUrl) {
    const cached = this.operatorHeadCache.get(operatorUrl);
    if (cached && (Date.now() - cached.timestamp) < 2000) {
      return cached;
    }

    const resp = await fetch(`${operatorUrl}/api/registry/head`, {
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

    const doSolvePow = String(process.env.AUTHO_GATEWAY_POW_SOLVE || '').trim() === '1';
    const hasPowHeaders = Boolean(
      init.headers['x-autho-pow-challenge'] ||
      init.headers['x-autho-pow-nonce'] ||
      init.headers['x-autho-pow-resource']
    );

    const resp1 = await fetch(targetUrl, init);
    const buf1 = Buffer.from(await resp1.arrayBuffer());
    const contentType1 = resp1.headers.get('content-type');

    if (doSolvePow && !hasPowHeaders && resp1.status === 402) {
      let parsed = null;
      try {
        parsed = JSON.parse(buf1.toString('utf8'));
      } catch {}

      const errCode = parsed && typeof parsed.error === 'string' ? parsed.error : '';
      if (errCode === 'pow_required' || errCode === 'pow_invalid') {
        try {
          const pathOnly = String(req.path || req.originalUrl || '').split('?')[0];
          const resource = `${String(req.method || 'GET').toUpperCase()}:${pathOnly}`;
          const challenge = await this.getPowChallenge(operatorUrl, resource);
          if (challenge) {
            const nonce = this.solvePow(challenge);
            if (nonce) {
              const init2 = {
                ...init,
                headers: {
                  ...init.headers,
                  'x-autho-pow-challenge': String(challenge.challengeId),
                  'x-autho-pow-resource': String(challenge.resource || resource),
                  'x-autho-pow-nonce': String(nonce),
                },
              };

              const resp2 = await fetch(targetUrl, init2);
              const buf2 = Buffer.from(await resp2.arrayBuffer());
              const contentType2 = resp2.headers.get('content-type');
              return { resp: resp2, buf: buf2, contentType: contentType2 };
            }
          }
        } catch {}
      }
    }

    return { resp: resp1, buf: buf1, contentType: contentType1 };
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
        if (isWrite) {
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
        version: '1.0.4',
        uptime: process.uptime(),
        connectedPeers: this.peers.size,
        isConnectedToSeed: this.isConnectedToSeed,
        hardcodedSeeds: CONFIG.seedNodes,
        platform: os.platform(),
        nodeVersion: process.version
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
        nodeVersion: process.version
      };
      res.json(stats);
    });

    // Bitcoin anchoring / time-source endpoints (explicitly exposed for gateway clients)
    this.app.get('/api/anchors/time', (req, res) => {
      Promise.resolve(this.proxyApi(req, res)).catch((e) => {
        console.error('❌ Gateway proxy error:', e);
        res.status(500).json({ error: 'Gateway proxy error', message: e?.message || String(e) });
      });
    });

    this.app.get('/api/anchors/checkpoints', (req, res) => {
      Promise.resolve(this.proxyApi(req, res)).catch((e) => {
        console.error('❌ Gateway proxy error:', e);
        res.status(500).json({ error: 'Gateway proxy error', message: e?.message || String(e) });
      });
    });

    this.app.get('/api/anchors/commits', (req, res) => {
      Promise.resolve(this.proxyApi(req, res)).catch((e) => {
        console.error('❌ Gateway proxy error:', e);
        res.status(500).json({ error: 'Gateway proxy error', message: e?.message || String(e) });
      });
    });

    this.app.get('/api/anchors/checkpoints/:checkpointRoot/verify', (req, res) => {
      Promise.resolve(this.proxyApi(req, res)).catch((e) => {
        console.error('❌ Gateway proxy error:', e);
        res.status(500).json({ error: 'Gateway proxy error', message: e?.message || String(e) });
      });
    });

    this.app.get('/api/anchors/checkpoints/:checkpointRoot/commitment', (req, res) => {
      Promise.resolve(this.proxyApi(req, res)).catch((e) => {
        console.error('❌ Gateway proxy error:', e);
        res.status(500).json({ error: 'Gateway proxy error', message: e?.message || String(e) });
      });
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
            version: '1.0.4',
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

  seedToWsUrl(seed) {
    const [host, port] = String(seed).split(':');
    const isLocal = host.includes('localhost') || host.includes('127.0.0.1');
    const protocol = isLocal ? 'ws' : 'wss';
    return isLocal
      ? (port ? `${protocol}://${host}:${port}` : `${protocol}://${host}`)
      : `${protocol}://${host}`;
  }

  seedToHttpUrl(seed) {
    const [host, port] = String(seed).split(':');
    const isLocal = host.includes('localhost') || host.includes('127.0.0.1');
    const isOnion = host.toLowerCase().endsWith('.onion');
    const protocol = (isLocal || isOnion) ? 'http' : 'https';
    return isLocal
      ? (port ? `${protocol}://${host}:${port}` : `${protocol}://${host}`)
      : `${protocol}://${host}`;
  }

  async discoverOperators() {
    const now = Date.now();
    if (now - this.lastOperatorDiscovery < 300000 && this.discoveredOperators.length > 0) {
      return this.discoveredOperators;
    }

    const seeds = this.getSeedNodes();
    for (const seed of seeds) {
      try {
        const httpUrl = this.seedToHttpUrl(seed);
        const resp = await fetch(`${httpUrl}/api/network/operators`, { method: 'GET' });
        if (!resp.ok) continue;
        const data = await resp.json();
        if (data && data.success && Array.isArray(data.operators)) {
          this.discoveredOperators = data.operators;
          this.lastOperatorDiscovery = now;
          return this.discoveredOperators;
        }
      } catch {}
    }

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

    for (const op of operators) {
      if (!op || !op.wsUrl) continue;
      if (!this.isTorEnabled() && this.isOnionUrl(op.wsUrl)) continue;
      const operatorId = String(op.operatorId || op.wsUrl);
      if (this.operatorConnections.has(operatorId)) {
        const existing = this.operatorConnections.get(operatorId);
        if (existing && existing.ws && existing.ws.readyState === WebSocket.OPEN) {
          continue;
        }
      }
      this.connectToOperator({ operatorId, wsUrl: op.wsUrl });
    }
  }

  connectToOperator(operator) {
    const operatorId = String(operator?.operatorId || '').trim();
    const wsUrl = String(operator?.wsUrl || '').trim();
    if (!operatorId || !wsUrl) return;

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
        connectionInfo.connectedAt = Date.now();
        connectionInfo.lastSeen = Date.now();
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
          connectionInfo.lastSeen = Date.now();
          const message = JSON.parse(data.toString());
          this.handleSeedMessage(operatorId, message);
        } catch {}
      });

      ws.on('close', () => {
        this.operatorConnections.delete(operatorId);

        const hasActiveConnection = Array.from(this.operatorConnections.values())
          .some(conn => conn && conn.ws && conn.ws.readyState === WebSocket.OPEN);

        if (!hasActiveConnection) {
          this.isConnectedToSeed = false;
        }

        setTimeout(() => {
          this.connectToOperator({ operatorId, wsUrl });
        }, 10000);
      });

      ws.on('error', () => {});

      this.operatorConnections.set(operatorId, connectionInfo);
    } catch {}
  }

  connectToSeeds() {
    const seeds = this.getSeedNodes();

    const attempt = async () => {
      const current = this.seedWs;
      if (current) {
        try { current.terminate(); } catch {}
        this.seedWs = null;
      }
      this.connectedSeed = null;
      this.isConnectedToSeed = false;

      for (const seed of seeds) {
        const wsUrl = this.seedToWsUrl(seed);
        try {
          const ws = await new Promise((resolve, reject) => {
            const sock = new WebSocket(wsUrl);
            const timer = setTimeout(() => {
              try { sock.terminate(); } catch {}
              reject(new Error('connect timeout'));
            }, 6000);

            sock.once('open', () => {
              clearTimeout(timer);
              resolve(sock);
            });

            sock.once('error', (e) => {
              clearTimeout(timer);
              try { sock.terminate(); } catch {}
              reject(e);
            });
          });

          this.seedWs = ws;
          this.connectedSeed = seed;
          this.isConnectedToSeed = true;

          ws.on('message', (data) => {
            try {
              const message = JSON.parse(data.toString());
              this.handleSeedMessage(seed, message);
            } catch {}
          });

          ws.on('close', () => {
            if (this.connectedSeed === seed) {
              this.isConnectedToSeed = false;
              this.connectedSeed = null;
              this.seedWs = null;
              setTimeout(() => {
                attempt().catch(() => {});
              }, 5000);
            }
          });

          ws.on('error', () => {});

          ws.send(JSON.stringify({
            type: 'sync_request',
            nodeId: 'gateway-package',
            platform: os.platform(),
            timestamp: Date.now()
          }));

          return;
        } catch {}
      }

      setTimeout(() => {
        attempt().catch(() => {});
      }, 10000);
    };

    attempt().catch(() => {});
  }

  handleSeedMessage(seed, message) {
    switch (message.type) {
      case 'sync_response':
        console.log(`📥 Received sync data from seed: ${seed}`);
        this.registryData = message.data || {};
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
      console.log('');
      console.log('Press Ctrl+C to stop');
    });

    // Setup WebSocket
    this.setupWebSocket();

    await this.connectToOperators();
    this.connectToSeeds();

    setInterval(async () => {
      try {
        await this.connectToOperators();
      } catch {}
    }, 300000);

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
    }, 60000);
  }

  async stop() {
    console.log('🛑 Stopping Gateway Node...');
    
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
    
    // Close WebSocket server
    if (this.wsServer) {
      this.wsServer.close();
      console.log('📡 WebSocket server closed');
    }
    
    console.log('✅ Gateway Node stopped');
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
