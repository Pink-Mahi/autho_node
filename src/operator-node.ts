import express, { Express, Request, Response } from 'express';
import * as http from 'http';
import WebSocket from 'ws';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import { createHash, pbkdf2Sync, timingSafeEqual, randomBytes } from 'crypto';
import { HeartbeatManager } from './consensus/heartbeat-manager';
import { StateVerifier, LedgerState } from './consensus/state-verifier';

interface OperatorConfig {
  operatorId: string;
  publicKey: string;
  privateKey: string;
  btcAddress: string;
  mainSeedUrl: string;
  port: number;
  wsPort: number;
  dataDir: string;
  network: 'mainnet' | 'testnet';
  operatorName?: string;
  operatorDescription?: string;
}

interface SyncedState {
  events: any[];
  accounts: Map<string, any>;
  items: Map<string, any>;
  settlements: Map<string, any>;
  consignments: Map<string, any>;
  operators: Map<string, any>;
  lastSyncedSequence: number;
  lastSyncedAt: number;
}

export class OperatorNode extends EventEmitter {
  private config: OperatorConfig;
  private app: Express;
  private httpServer?: http.Server;
  private wss?: WebSocket.Server;
  private mainSeedWs?: WebSocket;
  private state: SyncedState;
  private isConnectedToMain: boolean = false;
  private reconnectTimer?: NodeJS.Timeout;
  private syncInProgress: boolean = false;
  private gatewayConnections: Map<WebSocket, { connectedAt: number; lastSeen: number; ip?: string }> = new Map();
  private heartbeatManager?: HeartbeatManager;
  private lastMainNodeHeartbeat: number = Date.now();

  private sessions: Map<string, { sessionId: string; accountId: string; createdAt: number; expiresAt: number }> = new Map();

  constructor(config: OperatorConfig) {
    super();
    this.config = config;
    this.app = express();
    this.state = {
      events: [],
      accounts: new Map(),
      items: new Map(),
      settlements: new Map(),
      consignments: new Map(),
      operators: new Map(),
      lastSyncedSequence: 0,
      lastSyncedAt: 0
    };

    this.setupMiddleware();
    this.setupRoutes();
  }

  private getSeedHttpBase(): string {
    const raw = String(process.env.SEED_HTTP_URL || '').trim();
    if (raw) return raw.replace(/\/$/, '');
    return this.getUiSeedHttpBase();
  }

  private async proxyToSeed(req: Request, res: Response, pathAndQuery?: string): Promise<void> {
    const base = this.getSeedHttpBase();
    if (!base) {
      res.status(502).json({ success: false, error: 'No seed HTTP base configured' });
      return;
    }

    const urlPath = typeof pathAndQuery === 'string'
      ? pathAndQuery
      : String(req.originalUrl || req.url || '').trim();
    const target = `${base}${urlPath.startsWith('/') ? '' : '/'}${urlPath}`;

    try {
      const headers: Record<string, string> = {};
      const contentType = String(req.headers['content-type'] || '').trim();
      if (contentType) headers['content-type'] = contentType;
      const auth = String(req.headers['authorization'] || '').trim();
      if (auth) headers['authorization'] = auth;

      let body: any = undefined;
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const asAny = req as any;
        if (asAny?.body && typeof asAny.body === 'object' && Object.keys(asAny.body).length > 0) {
          body = JSON.stringify(asAny.body);
          headers['content-type'] = headers['content-type'] || 'application/json';
        } else if (typeof asAny?.body === 'string' && asAny.body.trim()) {
          body = asAny.body;
        }
      }

      const seedResp = await fetch(target, {
        method: req.method,
        headers,
        body,
      });

      const outCt = String(seedResp.headers.get('content-type') || '');
      res.status(seedResp.status);
      if (outCt) res.setHeader('Content-Type', outCt);

      const isText =
        outCt.includes('application/json') ||
        outCt.startsWith('text/') ||
        outCt.includes('application/javascript') ||
        outCt.includes('application/x-javascript') ||
        outCt.includes('application/xml') ||
        outCt.includes('image/svg+xml');

      if (isText) {
        const text = await seedResp.text();
        res.send(text);
      } else {
        const ab = await seedResp.arrayBuffer();
        res.send(Buffer.from(ab));
      }
    } catch (e: any) {
      res.status(502).json({ success: false, error: e?.message || String(e) });
    }
  }

  private getUiCacheDir(): string {
    return process.env.UI_CACHE_DIR
      ? String(process.env.UI_CACHE_DIR)
      : path.join(this.config.dataDir, 'ui-cache');
  }

  private getPublicDir(): string {
    const envDir = String(process.env.PUBLIC_DIR || '').trim();
    if (envDir) return envDir;
    const cwdPublic = path.join(process.cwd(), 'public');
    try {
      if (fs.existsSync(cwdPublic) && fs.statSync(cwdPublic).isDirectory()) return cwdPublic;
    } catch {}
    return this.getUiCacheDir();
  }

  private getDownloadsDir(): string {
    const envDir = String(process.env.DOWNLOADS_DIR || '').trim();
    if (envDir) return envDir;
    const cwdDownloads = path.join(process.cwd(), 'downloads');
    try {
      if (fs.existsSync(cwdDownloads) && fs.statSync(cwdDownloads).isDirectory()) return cwdDownloads;
    } catch {}
    return '';
  }

  private getUiSeedHttpBase(): string {
    const raw = String(process.env.UI_SEED_HTTP_URL || '').trim();
    if (raw) return raw.replace(/\/$/, '');

    const seed = String(this.config.mainSeedUrl || '').trim();
    try {
      const u = new URL(seed);
      const proto = u.protocol === 'wss:' ? 'https:' : (u.protocol === 'ws:' ? 'http:' : u.protocol);
      return `${proto}//${u.host}`;
    } catch {
      return '';
    }
  }

  private async fetchText(url: string): Promise<string> {
    const resp = await fetch(url);
    const text = await resp.text();
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${String(text || '').slice(0, 200)}`);
    }
    return String(text || '');
  }

  private async ensureUiCache(): Promise<void> {
    const embeddedLanding = this.resolvePublicFile('landing.html');
    if (fs.existsSync(embeddedLanding)) return;

    const base = this.getUiSeedHttpBase();
    if (!base) return;

    const dir = this.getUiCacheDir();
    try {
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const jsDir = path.join(dir, 'js');
      if (!fs.existsSync(jsDir)) fs.mkdirSync(jsDir, { recursive: true });
      const custDir = path.join(dir, 'customer');
      if (!fs.existsSync(custDir)) fs.mkdirSync(custDir, { recursive: true });
    } catch {
      return;
    }

    const files: Array<{ urlPath: string; outPath: string }> = [
      { urlPath: '/mobile-entry.html', outPath: 'mobile-entry.html' },
      { urlPath: '/mobile-login.html', outPath: 'mobile-login.html' },
      { urlPath: '/mobile-wallet.html', outPath: 'mobile-wallet.html' },
      { urlPath: '/mobile-items.html', outPath: 'mobile-items.html' },
      { urlPath: '/mobile-offers.html', outPath: 'mobile-offers.html' },
      { urlPath: '/mobile-offer.html', outPath: 'mobile-offer.html' },
      { urlPath: '/mobile-verify.html', outPath: 'mobile-verify.html' },
      { urlPath: '/mobile-consignment.html', outPath: 'mobile-consignment.html' },
      { urlPath: '/mobile-consign.html', outPath: 'mobile-consign.html' },
      { urlPath: '/mobile-history.html', outPath: 'mobile-history.html' },
      { urlPath: '/wallet-auth.js', outPath: 'wallet-auth.js' },
      { urlPath: '/wallet-generator.js', outPath: 'wallet-generator.js' },
      { urlPath: '/js/qr.bundle.js', outPath: path.join('js', 'qr.bundle.js') },
      { urlPath: '/customer/login.html', outPath: path.join('customer', 'login.html') },
      { urlPath: '/customer/signup.html', outPath: path.join('customer', 'signup.html') },
    ];

    for (const f of files) {
      try {
        const outAbs = path.join(dir, f.outPath);
        if (fs.existsSync(outAbs) && fs.statSync(outAbs).size > 0) continue;
        const text = await this.fetchText(`${base}${f.urlPath}`);
        fs.mkdirSync(path.dirname(outAbs), { recursive: true });
        fs.writeFileSync(outAbs, text);
      } catch {
      }
    }
  }

  private resolveUiFile(relPath: string): string {
    return path.join(this.getUiCacheDir(), relPath);
  }

  private resolvePublicFile(relPath: string): string {
    return path.join(this.getPublicDir(), relPath);
  }

  private computeNetworkId(): string {
    const net = this.getBitcoinNetwork();
    const fee = this.getFeeAddress();
    return createHash('sha256').update(`${net}:${fee}`).digest('hex');
  }

  private setupMiddleware(): void {
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // CORS for gateway nodes
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
      if (req.method === 'OPTIONS') {
        res.sendStatus(200);
        return;
      }
      next();
    });

    // Request logging
    this.app.use((req, res, next) => {
      const start = Date.now();
      res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
      });
      next();
    });

    this.app.use('/api', async (req: Request, res: Response, next) => {
      try {
        const sid = this.getSessionIdFromRequest(req);
        if (!sid) return next();
        if (this.sessions.has(sid)) return next();

        const base = this.getSeedHttpBase();
        if (!base) return next();

        const r = await fetch(`${base}/api/auth/me`, {
          method: 'GET',
          headers: {
            Authorization: String((req.headers as any)?.authorization || ''),
          },
        });

        if (!r.ok) return next();
        const data: any = await r.json().catch(() => null);
        const accountId = String(data?.account?.accountId || data?.accountId || '').trim();
        if (!accountId) return next();

        const now = Date.now();
        this.sessions.set(sid, {
          sessionId: sid,
          accountId,
          createdAt: now,
          expiresAt: now + 24 * 60 * 60 * 1000,
        });
      } catch {
        // ignore
      }
      next();
    });
  }

  private getBitcoinNetwork(): 'mainnet' | 'testnet' {
    return this.config.network === 'mainnet' ? 'mainnet' : 'testnet';
  }

  private getChainApiBases(): string[] {
    const net = this.getBitcoinNetwork();
    return net === 'mainnet'
      ? ['https://mempool.space/api', 'https://blockstream.info/api']
      : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];
  }

  private calculatePlatformFee(amountSats: number): number {
    const amount = Math.floor(Number(amountSats || 0));
    if (!Number.isFinite(amount) || amount <= 0) return 0;

    const dustLimit = Math.floor(Number(process.env.DUST_LIMIT_SATS || 0) || 546);
    const minPlatformFeeSats = Math.floor(Number(process.env.PLATFORM_FEE_MIN_SATS || 0) || 1000);

    const percentFee = Math.floor(amount * (1.0 / 100));
    const desiredFee = Math.max(0, Math.max(percentFee, minPlatformFeeSats));

    const maxFee = amount - dustLimit;
    if (maxFee < dustLimit) return 0;
    if (desiredFee < dustLimit) return 0;
    if (desiredFee > maxFee) return 0;
    return desiredFee;
  }

  private getFeeAddress(): string {
    return this.getBitcoinNetwork() === 'testnet'
      ? String(process.env.FEE_ADDRESS_TESTNET || '').trim()
      : '1FMcxZRUWVDbKy7DxAosW7sM5PUntAkJ9U';
  }

  private getSessionIdFromRequest(req: Request): string {
    const hdr = String((req.headers as any)?.authorization || '').trim();
    if (!hdr) return '';
    return hdr.toLowerCase().startsWith('bearer ') ? hdr.slice(7).trim() : hdr;
  }

  private getSession(req: Request): { sessionId: string; accountId: string; createdAt: number; expiresAt: number } | null {
    const sid = this.getSessionIdFromRequest(req);
    if (!sid) return null;
    const sess = this.sessions.get(sid);
    if (!sess) return null;
    if (Date.now() > sess.expiresAt) {
      this.sessions.delete(sid);
      return null;
    }
    return sess;
  }

  private requireSession(req: Request, res: Response): { sessionId: string; accountId: string; createdAt: number; expiresAt: number } | null {
    const sess = this.getSession(req);
    if (!sess) {
      res.status(401).json({ success: false, error: 'Login required' });
      return null;
    }
    return sess;
  }

  private setupRoutes(): void {
    const publicDir = this.getPublicDir();
    this.app.use(express.static(publicDir, { index: false }));

    const downloadsDir = this.getDownloadsDir();
    if (downloadsDir) {
      this.app.use(
        '/downloads',
        express.static(downloadsDir, {
          setHeaders: (res) => {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
          },
        })
      );
    }

    this.app.get('/', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('landing.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      const fallback = this.resolvePublicFile('mobile-entry.html');
      if (fs.existsSync(fallback)) return res.sendFile(fallback);
      res.json({ success: true, operatorId: this.config.operatorId, message: 'Operator node is running' });
    });

    this.app.get('/join', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('join.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/how-it-works', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('how-it-works.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/buy', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('buy.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/setup', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('setup-wizard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/manufacturer', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('manufacturer-dashboard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/authenticator', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('authenticator-dashboard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/retailer', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('retailer-dashboard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/dashboard', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('dashboard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/operator', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('operator-portal.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/operator/dashboard', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('operator-dashboard.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/operator/apply', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('operator-apply.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get(['/customer/login', '/customer/login/'], (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('customer/login.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get(['/customer/signup', '/customer/signup/'], (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('customer/signup.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('Not Found');
    });

    this.app.get('/m', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-entry.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/login', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-login.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/wallet', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-wallet.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/items', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-items.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/offers', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-offers.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/offer', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-offer.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/verify', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-verify.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/consignment', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-consignment.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/consign', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-consign.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/history', (req: Request, res: Response) => {
      const fp = this.resolvePublicFile('mobile-history.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });

    this.app.get('/verify', (req: Request, res: Response) => {
      const id = String((req.query as any)?.id || (req.query as any)?.itemId || '').trim();
      if (id) {
        res.redirect(`/m/verify?itemId=${encodeURIComponent(id)}`);
        return;
      }
      res.redirect('/m/verify');
    });

    this.app.get('/consignment', (req: Request, res: Response) => {
      const consignmentId = String((req.query as any)?.consignmentId || (req.query as any)?.id || '').trim();
      if (consignmentId) {
        res.redirect(`/m/consignment?consignmentId=${encodeURIComponent(consignmentId)}`);
        return;
      }
      res.redirect('/m/consignment');
    });

    this.app.get('/consign', (req: Request, res: Response) => {
      const itemId = String((req.query as any)?.itemId || (req.query as any)?.item || '').trim();
      const retailerAccountId = String((req.query as any)?.retailerAccountId || (req.query as any)?.retailer || '').trim();
      const qs: string[] = [];
      if (itemId) qs.push(`itemId=${encodeURIComponent(itemId)}`);
      if (retailerAccountId) qs.push(`retailerAccountId=${encodeURIComponent(retailerAccountId)}`);
      res.redirect(`/m/consign${qs.length ? `?${qs.join('&')}` : ''}`);
    });

    this.app.get('/api/health', (req: Request, res: Response) => {
      res.json({
        status: 'ok',
        operatorId: this.config.operatorId,
        connectedToNetwork: this.isConnectedToMain,
        syncedEvents: this.state.events.length,
        lastSyncedAt: this.state.lastSyncedAt,
        uptime: process.uptime()
      });
    });

    this.app.get('/api/operator/info', (req: Request, res: Response) => {
      res.json({
        operatorId: this.config.operatorId,
        publicKey: this.config.publicKey,
        btcAddress: this.config.btcAddress,
        network: this.config.network,
        name: this.config.operatorName,
        description: this.config.operatorDescription,
        connectedToNetwork: this.isConnectedToMain
      });
    });

    this.app.get('/api/network/status', (req: Request, res: Response) => {
      const operators = Array.from(this.state.operators.values());
      res.json({
        connectedToMain: this.isConnectedToMain,
        totalOperators: operators.length,
        activeOperators: operators.filter((o: any) => o.status === 'active').length,
        syncedEvents: this.state.events.length,
        lastSyncedAt: this.state.lastSyncedAt
      });
    });

    this.app.get('/api/consensus/status', (req: Request, res: Response) => {
      const status = this.getConsensusStatus();
      res.json({ success: true, ...status });
    });

    this.app.get('/api/operator/status', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.get('/api/network/health', (req: Request, res: Response) => {
      const now = Date.now();
      const gateways = Array.from(this.gatewayConnections.entries()).map(([ws, conn]) => {
        const uptimeMs = now - conn.connectedAt;
        const timeSinceLastSeen = now - conn.lastSeen;
        const healthy = timeSinceLastSeen < 90000; // Healthy if seen in last 90 seconds
        return {
          connected: ws.readyState === 1,
          healthy,
          uptimeMs,
          timeSinceLastSeenMs: timeSinceLastSeen,
          ip: conn.ip
        };
      });

      res.json({
        success: true,
        mainSeedConnected: this.isConnectedToMain,
        mainSeedUptimeMs: this.isConnectedToMain ? 300000 : 0, // Placeholder
        gateways: {
          connected: gateways,
          total: gateways.length
        }
      });
    });

    this.app.get('/api/network/connections', async (req: Request, res: Response) => {
      try {
        // Proxy to main seed to get network data
        const base = this.getSeedHttpBase();
        if (!base) {
          return res.status(502).json({ 
            success: false, 
            error: 'No seed configured',
            mainSeedConnected: false,
            mainSeedUptimeMs: 0
          });
        }

        const targetUrl = `${base}${req.originalUrl}`;
        const authHeader = req.get('Authorization');
        const headers: Record<string, string> = authHeader ? { 'Authorization': authHeader } : {};
        
        const response = await fetch(targetUrl, { method: 'GET', headers });
        const data = await response.json();

        // Enhance with operator's own main seed connection status
        const enhancedData = {
          ...(typeof data === 'object' && data !== null ? data : {}),
          mainSeedConnected: this.isConnectedToMain,
          mainSeedUptimeMs: this.isConnectedToMain && this.state.lastSyncedAt ? Date.now() - this.state.lastSyncedAt : 0
        };

        res.json(enhancedData);
      } catch (error: any) {
        console.error('Failed to get network connections:', error);
        res.status(502).json({ 
          success: false, 
          error: error.message,
          mainSeedConnected: this.isConnectedToMain,
          mainSeedUptimeMs: 0
        });
      }
    });

    this.app.get('/api/operator/earnings', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.get('/seed-manifest.json', async (req: Request, res: Response) => {
      const protocol = String(req.protocol || 'http');
      const host = String(req.get('host') || '').trim();
      const baseUrl = host ? `${protocol}://${host}` : '';
      res.json({
        version: 1,
        timestamp: Date.now(),
        seeds: [
          {
            address: host || '',
            role: 'operator',
            services: {
              chainApi: baseUrl ? `${baseUrl}/api/chain` : '/api/chain',
            },
          },
        ],
        signatures: [],
        manifestHash: '',
      });
    });

    this.app.post('/api/auth/login', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.get('/api/auth/me', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.get('/api/registry/item/:itemId', (req: Request, res: Response) => {
      const item = this.state.items.get(req.params.itemId);
      if (!item) {
        res.status(404).json({ error: 'Item not found' });
        return;
      }
      res.json(item);
    });

    this.app.get('/api/registry/owner/:address', (req: Request, res: Response) => {
      const items = Array.from(this.state.items.values())
        .filter((item: any) => item.currentOwner === req.params.address);
      res.json({ items });
    });

    this.app.get('/api/offers/user/:address', (req: Request, res: Response) => {
      const addr = String(req.params.address || '').trim();
      const offers = Array.from(this.state.settlements.values())
        .filter((s: any) => String(s?.buyer || '').trim() === addr)
        .sort((a: any, b: any) => Number(b?.initiatedAt || 0) - Number(a?.initiatedAt || 0))
        .map((s: any) => {
          const sats = Number(s?.price || 0);
          const platformFeeSats = this.calculatePlatformFee(sats);
          const sellerReceivesSats = sats - platformFeeSats;
          const feeSnap: any = (s as any)?.platformFeePayouts ? (s as any).platformFeePayouts : null;
          const sponsorAddr = this.getFeeAddress();
          const feeMainAddr = feeSnap?.mainNodeAddress ? String(feeSnap.mainNodeAddress).trim() : sponsorAddr;
          const feeMainAmt = feeSnap ? Number(feeSnap.mainNodeFeeSats || 0) : platformFeeSats;
          const feeOps = feeSnap ? (Array.isArray(feeSnap.operatorPayouts) ? feeSnap.operatorPayouts : []) : [];

          const paymentOutputs = [
            { address: String(s?.seller || '').trim(), amountSats: sellerReceivesSats },
            { address: feeMainAddr, amountSats: feeMainAmt },
            ...feeOps.map((p: any) => ({ address: String(p?.address || '').trim(), amountSats: Number(p?.amountSats || 0) })),
          ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

          return {
            offerId: String(s?.settlementId || ''),
            itemId: String(s?.itemId || ''),
            buyerAddress: String(s?.buyer || ''),
            sellerAddress: String(s?.seller || ''),
            sats,
            status: String(s?.status || ''),
            createdAt: Number(s?.initiatedAt || 0),
            expiresAt: Number(s?.expiresAt || 0),
            paymentTxid: (s as any)?.txid ? String((s as any).txid) : undefined,
            paymentAddress: (s as any)?.escrowAddress ? String((s as any).escrowAddress) : undefined,
            paymentOutputs,
            platformFeeSats,
            sellerReceivesSats,
            mainNodeFeeAddress: feeMainAddr,
          };
        });

      res.json({ offers, count: offers.length });
    });

    this.app.get('/api/offers/owner/:address', (req: Request, res: Response) => {
      const addr = String(req.params.address || '').trim();
      const offers = Array.from(this.state.settlements.values())
        .filter((s: any) => String(s?.seller || '').trim() === addr)
        .sort((a: any, b: any) => Number(b?.initiatedAt || 0) - Number(a?.initiatedAt || 0))
        .map((s: any) => {
          const sats = Number(s?.price || 0);
          const platformFeeSats = this.calculatePlatformFee(sats);
          const sellerReceivesSats = sats - platformFeeSats;
          const feeSnap: any = (s as any)?.platformFeePayouts ? (s as any).platformFeePayouts : null;
          const sponsorAddr = this.getFeeAddress();
          const feeMainAddr = feeSnap?.mainNodeAddress ? String(feeSnap.mainNodeAddress).trim() : sponsorAddr;
          const feeMainAmt = feeSnap ? Number(feeSnap.mainNodeFeeSats || 0) : platformFeeSats;
          const feeOps = feeSnap ? (Array.isArray(feeSnap.operatorPayouts) ? feeSnap.operatorPayouts : []) : [];
          const paymentOutputs = [
            { address: String(s?.seller || '').trim(), amountSats: sellerReceivesSats },
            { address: feeMainAddr, amountSats: feeMainAmt },
            ...feeOps.map((p: any) => ({ address: String(p?.address || '').trim(), amountSats: Number(p?.amountSats || 0) })),
          ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

          return {
            offerId: String(s?.settlementId || ''),
            itemId: String(s?.itemId || ''),
            buyerAddress: String(s?.buyer || ''),
            sellerAddress: String(s?.seller || ''),
            sats,
            status: String(s?.status || ''),
            createdAt: Number(s?.initiatedAt || 0),
            expiresAt: Number(s?.expiresAt || 0),
            paymentOutputs,
            platformFeeSats,
            sellerReceivesSats,
            mainNodeFeeAddress: feeMainAddr,
          };
        });

      res.json({ offers, count: offers.length });
    });

    this.app.get('/api/offers/item/:itemId', (req: Request, res: Response) => {
      const itemId = String(req.params.itemId || '').trim();
      const offers = Array.from(this.state.settlements.values())
        .filter((s: any) => String(s?.itemId || '').trim() === itemId)
        .sort((a: any, b: any) => Number(b?.initiatedAt || 0) - Number(a?.initiatedAt || 0))
        .map((s: any) => ({
          offerId: String(s?.settlementId || ''),
          itemId: String(s?.itemId || ''),
          buyerAddress: String(s?.buyer || ''),
          sellerAddress: String(s?.seller || ''),
          sats: Number(s?.price || 0),
          status: String(s?.status || ''),
          createdAt: Number(s?.initiatedAt || 0),
          expiresAt: Number(s?.expiresAt || 0),
        }));
      res.json({ offers, count: offers.length });
    });

    this.app.get('/api/offers/:offerId', (req: Request, res: Response) => {
      const offerId = String(req.params.offerId || '').trim();
      const s: any = this.state.settlements.get(offerId);
      if (!s) {
        res.status(404).json({ error: 'Offer not found' });
        return;
      }
      const sats = Number(s?.price || 0);
      const platformFeeSats = this.calculatePlatformFee(sats);
      const sellerReceivesSats = sats - platformFeeSats;
      const feeSnap: any = (s as any)?.platformFeePayouts ? (s as any).platformFeePayouts : null;
      const sponsorAddr = this.getFeeAddress();
      const feeMainAddr = feeSnap?.mainNodeAddress ? String(feeSnap.mainNodeAddress).trim() : sponsorAddr;
      const feeMainAmt = feeSnap ? Number(feeSnap.mainNodeFeeSats || 0) : platformFeeSats;
      const feeOps = feeSnap ? (Array.isArray(feeSnap.operatorPayouts) ? feeSnap.operatorPayouts : []) : [];
      const paymentOutputs = [
        { address: String(s?.seller || '').trim(), amountSats: sellerReceivesSats },
        { address: feeMainAddr, amountSats: feeMainAmt },
        ...feeOps.map((p: any) => ({ address: String(p?.address || '').trim(), amountSats: Number(p?.amountSats || 0) })),
      ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

      res.json({
        offerId: String(s?.settlementId || offerId),
        itemId: String(s?.itemId || ''),
        buyerAddress: String(s?.buyer || ''),
        sellerAddress: String(s?.seller || ''),
        sats,
        status: String(s?.status || ''),
        createdAt: Number(s?.initiatedAt || 0),
        expiresAt: Number(s?.expiresAt || 0),
        paymentOutputs,
        platformFeeSats,
        sellerReceivesSats,
        mainNodeFeeAddress: feeMainAddr,
      });
    });

    this.app.get('/api/chain/status', async (req: Request, res: Response) => {
      try {
        const net = this.getBitcoinNetwork();
        const apiBase = net === 'mainnet' ? 'https://blockstream.info/api' : 'https://blockstream.info/testnet/api';
        res.json({
          ok: true,
          network: net,
          apiBase,
          timestamp: Date.now(),
        });
      } catch (e: any) {
        res.status(500).json({ ok: false, error: e?.message || String(e) });
      }
    });

    this.app.get('/api/chain/address/:address', async (req: Request, res: Response) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          res.status(400).json({ error: 'Missing address' });
          return;
        }

        const bases = this.getChainApiBases();
        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const r = await fetch(`${apiBase}/address/${encodeURIComponent(address)}`);
            const t = await r.text();
            if (!r.ok) {
              lastErr = { status: r.status, text: t };
              continue;
            }
            res.type('application/json').send(t);
            return;
          } catch (err) {
            lastErr = err;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.get('/api/chain/address/:address/utxo', async (req: Request, res: Response) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          res.status(400).json({ error: 'Missing address' });
          return;
        }
        const net = this.getBitcoinNetwork();
        const apiBase = net === 'mainnet' ? 'https://blockstream.info/api' : 'https://blockstream.info/testnet/api';
        const r = await fetch(`${apiBase}/address/${encodeURIComponent(address)}/utxo`);
        const t = await r.text();
        if (!r.ok) {
          res.status(502).send(t);
          return;
        }
        res.type('application/json').send(t);
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.get('/api/chain/tx/:txid/status', async (req: Request, res: Response) => {
      try {
        const txid = String(req.params.txid || '').trim();
        if (!txid) {
          res.status(400).json({ error: 'Missing txid' });
          return;
        }
        const bases = this.getChainApiBases();
        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const statusResp = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/status`);
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

            res.json({
              ok: true,
              confirmed,
              confirmations,
              blockHeight: blockHeight || undefined,
              blockHash: statusJson?.block_hash,
              blockTime: statusJson?.block_time,
              provider: apiBase,
            });
            return;
          } catch (err) {
            lastErr = err;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.get('/api/chain/tx/:txid/hex', async (req: Request, res: Response) => {
      try {
        const txid = String(req.params.txid || '').trim();
        if (!txid) {
          res.status(400).json({ error: 'Missing txid' });
          return;
        }
        const bases = this.getChainApiBases();
        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const r = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/hex`);
            const t = await r.text();
            if (!r.ok) {
              lastErr = { status: r.status, text: t };
              continue;
            }
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send(String(t || '').trim());
            return;
          } catch (err) {
            lastErr = err;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.get('/api/chain/fee-estimates', async (req: Request, res: Response) => {
      try {
        const bases = this.getChainApiBases();
        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const r = await fetch(`${apiBase}/fee-estimates`);
            const t = await r.text();
            if (!r.ok) {
              lastErr = { status: r.status, text: t };
              continue;
            }
            res.type('application/json').send(t);
            return;
          } catch (err) {
            lastErr = err;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.post('/api/chain/tx', async (req: Request, res: Response) => {
      try {
        let txHex = '';
        const asAny = req as any;
        if (asAny?.body && typeof asAny.body === 'object') {
          txHex = String(asAny.body.txHex || '');
        }
        txHex = txHex.trim();

        if (!txHex) {
          res.status(400).json({ success: false, error: 'Missing txHex' });
          return;
        }

        const bases = this.getChainApiBases();
        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const r = await fetch(`${apiBase}/tx`, {
              method: 'POST',
              headers: { 'Content-Type': 'text/plain' },
              body: txHex,
            });
            const t = await r.text();
            if (!r.ok) {
              lastErr = { status: r.status, text: t };
              continue;
            }
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send(String(t || '').trim());
            return;
          } catch (err) {
            lastErr = err;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (e: any) {
        res.status(500).json({ error: e?.message || String(e) });
      }
    });

    this.app.get('/api/consignments/item/:itemId', (req: Request, res: Response) => {
      const itemId = String(req.params.itemId || '').trim();
      if (!itemId) {
        res.status(400).json({ success: false, error: 'Missing itemId' });
        return;
      }

      const found = Array.from(this.state.consignments.values()).find((c: any) => String(c?.itemId || '').trim() === itemId);
      if (!found) {
        res.status(404).json({ success: false, error: 'Consignment not found' });
        return;
      }
      res.json({ success: true, consignment: found });
    });

    this.app.get('/api/qr.png', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/users/register', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.post('/api/offers/create', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/offers/:offerId/accept', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/offers/:offerId/cancel', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/offers/:offerId/payment-submitted', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/offers/:offerId/claim', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/offers/:offerId/counter', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.post('/api/consignments/create', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.get('/api/consignments/:consignmentId', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.get('/api/consignments/:consignmentId/checkout', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/consignments/:consignmentId/checkout/lock', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/consignments/:consignmentId/payment-submitted', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/consignments/:consignmentId/cancel/request', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });
    this.app.post('/api/consignments/:consignmentId/cancel/confirm', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.all('/api/admin/*', (req: Request, res: Response) => {
      res.status(403).json({ 
        success: false, 
        error: 'Admin endpoints are not available on operator nodes. Please use the main node dashboard.' 
      });
    });

    this.app.all('/api/*', async (req: Request, res: Response) => {
      await this.proxyToSeed(req, res);
    });

    this.app.use((req: Request, res: Response) => {
      const p = String(req.path || '').trim();
      if (p.startsWith('/api')) {
        res.status(404).json({ error: 'Endpoint not found' });
        return;
      }
      res.status(404).send('Not Found');
    });
  }

  async start(): Promise<void> {
    if (!fs.existsSync(this.config.dataDir)) {
      fs.mkdirSync(this.config.dataDir, { recursive: true });
    }

    await this.loadPersistedState();

    try {
      await this.ensureUiCache();
    } catch {}

    this.httpServer = this.app.listen(this.config.port, () => {
      console.log(`[Operator] HTTP API: http://localhost:${this.config.port}`);
      console.log(`[Operator] Health: http://localhost:${this.config.port}/api/health`);
    });

    this.setupWebSocketServer();
    await this.connectToMainSeed();

    console.log('\n[Operator] Node is running!');
    console.log('[Operator] WebSocket server ready for gateway connections');
    console.log('[Operator] Press Ctrl+C to stop\n');
  }

  private setupWebSocketServer(): void {
    if (!this.httpServer) return;

    this.wss = new WebSocket.Server({ server: this.httpServer });

    this.wss.on('connection', (ws: WebSocket, req) => {
      const clientIp = req.socket.remoteAddress;
      const now = Date.now();

      console.log(`[Operator] Gateway connected from ${clientIp}`);

      this.gatewayConnections.set(ws, {
        connectedAt: now,
        lastSeen: now,
        ip: clientIp,
      });

      ws.on('message', (data: Buffer) => {
        try {
          const message = JSON.parse(data.toString());
          this.handleGatewayMessage(ws, message);
        } catch (error) {
          console.error('[Operator] Invalid message from gateway:', error);
        }
      });

      ws.on('close', () => {
        console.log(`[Operator] Gateway disconnected from ${clientIp}`);
        this.gatewayConnections.delete(ws);
      });

      ws.on('error', (error) => {
        console.error('[Operator] Gateway WebSocket error:', error);
        this.gatewayConnections.delete(ws);
      });
    });

    console.log(`[Operator] WebSocket server listening on port ${this.config.port}`);
  }

  private handleGatewayMessage(ws: WebSocket, message: any): void {
    const conn = this.gatewayConnections.get(ws);
    if (conn) {
      conn.lastSeen = Date.now();
    }

    switch (message.type) {
      case 'sync_request':
        console.log('[Operator] Gateway requesting sync');
        this.sendSyncResponse(ws);
        break;

      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        break;

      default:
        console.log(`[Operator] Unknown message type from gateway: ${message.type}`);
    }
  }

  private sendSyncResponse(ws: WebSocket): void {
    if (ws.readyState !== WebSocket.OPEN) return;

    const syncData = {
      events: this.state.events,
      accounts: Array.from(this.state.accounts.entries()),
      items: Array.from(this.state.items.entries()),
      settlements: Array.from(this.state.settlements.entries()),
      consignments: Array.from(this.state.consignments.entries()),
      operators: Array.from(this.state.operators.entries()),
      lastSyncedSequence: this.state.lastSyncedSequence,
      lastSyncedAt: this.state.lastSyncedAt,
    };

    ws.send(JSON.stringify({
      type: 'sync_response',
      data: syncData,
      timestamp: Date.now(),
    }));

    console.log('[Operator] Sent sync data to gateway');
  }

  private broadcastToGateways(message: any): void {
    this.gatewayConnections.forEach((conn, ws) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
      }
    });
  }

  async stop(): Promise<void> {
    console.log('[Operator] Stopping...');

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    if (this.mainSeedWs) {
      this.mainSeedWs.close();
    }

    if (this.wss) {
      this.wss.close();
    }

    if (this.httpServer) {
      await new Promise<void>((resolve) => {
        this.httpServer!.close(() => resolve());
      });
    }

    await this.persistState();
    console.log('[Operator] Stopped');
  }

  private async connectToMainSeed(): Promise<void> {
    console.log(`[Operator] Connecting to main seed: ${this.config.mainSeedUrl}`);

    try {
      this.mainSeedWs = new WebSocket(this.config.mainSeedUrl);

      this.mainSeedWs.on('open', () => {
        console.log('[Operator] Connected to Autho Network');
        this.isConnectedToMain = true;
        this.lastMainNodeHeartbeat = Date.now();

        // Send sync request
        this.mainSeedWs!.send(JSON.stringify({
          type: 'sync_request',
          operatorId: this.config.operatorId,
          networkId: this.computeNetworkId(),
          lastSequence: this.state.lastSyncedSequence,
          timestamp: Date.now()
        }));
        
        // Start consensus verification
        this.startConsensusVerification();
      });

      this.mainSeedWs.on('message', async (data: WebSocket.Data) => {
        try {
          const message = JSON.parse(data.toString());
          
          // Handle consensus verification messages
          if (message.type === 'state_verification') {
            this.handleStateVerification(message);
            return;
          }
          
          if (message.type === 'verification_response') {
            this.handleVerificationResponse(message);
            return;
          }
          
          await this.handleMainSeedMessage(message);
        } catch (error: any) {
          console.error('[Operator] Error handling message:', error.message);
        }
      });

      this.mainSeedWs.on('close', () => {
        console.log('[Operator] Disconnected from main seed');
        this.isConnectedToMain = false;
        this.scheduleReconnect();
      });

      this.mainSeedWs.on('error', (error: Error) => {
        console.error('[Operator] WebSocket error:', error.message);
      });

    } catch (error: any) {
      console.error('[Operator] Failed to connect to main seed:', error.message);
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;

    console.log('[Operator] Will reconnect in 10 seconds...');
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connectToMainSeed();
    }, 10000);
  }

  private async handleMainSeedMessage(message: any): Promise<void> {
    switch (message.type) {
      case 'sync_data':
        await this.handleSyncData(message);
        this.broadcastToGateways({ type: 'registry_update', data: this.state, timestamp: Date.now() });
        break;
      case 'new_event':
        await this.handleNewEvent(message.event);
        this.broadcastToGateways({ type: 'registry_update', data: this.state, timestamp: Date.now() });
        break;
      case 'ping':
        this.mainSeedWs?.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        break;
      default:
        console.log(`[Operator] Unknown message type: ${message.type}`);
    }
  }

  private async handleSyncData(message: any): Promise<void> {
    if (this.syncInProgress) return;
    this.syncInProgress = true;

    try {
      const expectedNet = this.computeNetworkId();
      const remoteNet = String(message?.networkId || '').trim();
      if (!remoteNet || remoteNet !== expectedNet) {
        console.error('[Operator] Network mismatch - refusing to sync');
        console.error(`[Operator] expectedNetworkId=${expectedNet}`);
        console.error(`[Operator] receivedNetworkId=${remoteNet || '(missing)'}`);
        console.error(`[Operator] bitcoinNetwork=${this.getBitcoinNetwork()}`);
        console.error(`[Operator] feeAddress=${this.getFeeAddress()}`);
        this.isConnectedToMain = false;
        try { this.mainSeedWs?.close(); } catch {}
        return;
      }

      console.log(`[Operator] Syncing events from main node...`);

      const { events, state } = message;

      // Update events
      if (Array.isArray(events)) {
        this.state.events = events;
        console.log(`[Operator] Synced ${events.length} events`);
      }

      // Update state maps
      if (state) {
        if (state.accounts) {
          this.state.accounts = new Map(Object.entries(state.accounts));
        }
        if (state.items) {
          this.state.items = new Map(Object.entries(state.items));
        }
        if (state.settlements) {
          this.state.settlements = new Map(Object.entries(state.settlements));
        }
        if (state.consignments) {
          this.state.consignments = new Map(Object.entries(state.consignments));
        }
        if (state.operators) {
          this.state.operators = new Map(Object.entries(state.operators));
        }
      }

      this.state.lastSyncedSequence = events.length > 0 ? events[events.length - 1].sequenceNumber : 0;
      this.state.lastSyncedAt = Date.now();

      console.log(`[Operator] Sync complete. Accounts: ${this.state.accounts.size}, Items: ${this.state.items.size}`);

      await this.persistState();
    } catch (error: any) {
      console.error('[Operator] Sync error:', error.message);
    } finally {
      this.syncInProgress = false;
    }
  }

  private async handleNewEvent(event: any): Promise<void> {
    console.log(`[Operator] New event: ${event.payload?.type}`);
    this.state.events.push(event);
    // State updates would be applied here
    await this.persistState();
  }

  private async loadPersistedState(): Promise<void> {
    const statePath = path.join(this.config.dataDir, 'operator-state.json');
    if (fs.existsSync(statePath)) {
      try {
        const data = fs.readFileSync(statePath, 'utf-8');
        const parsed = JSON.parse(data);
        this.state.events = parsed.events || [];
        this.state.accounts = new Map(Object.entries(parsed.accounts || {}));
        this.state.items = new Map(Object.entries(parsed.items || {}));
        this.state.settlements = new Map(Object.entries(parsed.settlements || {}));
        this.state.consignments = new Map(Object.entries(parsed.consignments || {}));
        this.state.operators = new Map(Object.entries(parsed.operators || {}));
        this.state.lastSyncedSequence = parsed.lastSyncedSequence || 0;
        this.state.lastSyncedAt = parsed.lastSyncedAt || 0;
        console.log(`[Operator] Loaded persisted state: ${this.state.events.length} events`);
      } catch (error: any) {
        console.error('[Operator] Failed to load persisted state:', error.message);
      }
    }
  }

  private async persistState(): Promise<void> {
    const statePath = path.join(this.config.dataDir, 'operator-state.json');
    try {
      const data = {
        events: this.state.events,
        accounts: Object.fromEntries(this.state.accounts),
        items: Object.fromEntries(this.state.items),
        settlements: Object.fromEntries(this.state.settlements),
        consignments: Object.fromEntries(this.state.consignments),
        operators: Object.fromEntries(this.state.operators),
        lastSyncedSequence: this.state.lastSyncedSequence,
        lastSyncedAt: this.state.lastSyncedAt
      };
      fs.writeFileSync(statePath, JSON.stringify(data, null, 2));
    } catch (error: any) {
      console.error('[Operator] Failed to persist state:', error.message);
    }
  }

  private computeEmailHash(email: string): string {
    return createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
  }

  private async verifyPassword(password: string, storedHash: string, kdf?: any): Promise<boolean> {
    try {
      const computedHash = kdf
        ? pbkdf2Sync(password, Buffer.from(kdf.saltB64, 'base64'), kdf.iterations, 32, 'sha256').toString('hex')
        : createHash('sha256').update(password).digest('hex');
      
      const a = Buffer.from(computedHash, 'hex');
      const b = Buffer.from(storedHash, 'hex');
      if (a.length !== b.length) return false;
      return timingSafeEqual(a, b);
    } catch {
      return false;
    }
  }

  private randomHex(bytes: number): string {
    return randomBytes(bytes).toString('hex');
  }

  // Consensus Integration Methods
  private startConsensusVerification(): void {
    if (this.heartbeatManager) return;

    this.heartbeatManager = new HeartbeatManager({
      intervalMs: 60000,
      consensusThreshold: 0.6667,
      maxDivergenceTime: 300000
    });

    this.heartbeatManager.on('consensus_achieved', (result: any) => {
      console.log(`[Consensus] ✅ ${result.agreementPercentage.toFixed(1)}% agreement`);
    });

    this.heartbeatManager.on('out_of_consensus', async (data: any) => {
      console.log(`[Consensus] ⚠️ Out of consensus - requesting sync`);
      if (this.mainSeedWs && this.mainSeedWs.readyState === WebSocket.OPEN) {
        this.mainSeedWs.send(JSON.stringify({
          type: 'sync_request',
          operatorId: this.config.operatorId,
          networkId: this.computeNetworkId(),
          timestamp: Date.now(),
          reason: 'out_of_consensus'
        }));
      }
    });

    this.heartbeatManager.start(
      this.config.operatorId,
      async () => await this.getCurrentLedgerState(),
      (message: any) => this.sendVerificationToMainSeed(message)
    );

    console.log('[Consensus] Started verification (60s interval)');
  }

  private async getCurrentLedgerState(): Promise<LedgerState> {
    return {
      sequenceNumber: this.state.lastSyncedSequence,
      lastEventHash: '',
      itemsCount: this.state.items.size,
      settlementsCount: this.state.settlements.size,
      accountsCount: this.state.accounts.size,
      operatorsCount: this.state.operators.size,
      timestamp: Date.now()
    };
  }

  private handleStateVerification(message: any): void {
    if (message.nodeId === 'main-node') {
      this.lastMainNodeHeartbeat = Date.now();
    }

    if (!this.heartbeatManager) return;

    const response = this.heartbeatManager.handleVerificationMessage(message);
    if (response && this.mainSeedWs && this.mainSeedWs.readyState === WebSocket.OPEN) {
      this.mainSeedWs.send(JSON.stringify(response));
    }
  }

  private handleVerificationResponse(message: any): void {
    if (this.heartbeatManager) {
      this.heartbeatManager.handleVerificationMessage({
        type: 'state_verification',
        stateHash: message.stateHash,
        sequenceNumber: message.sequenceNumber,
        timestamp: message.timestamp,
        nodeId: message.nodeId
      });
    }
  }

  private sendVerificationToMainSeed(message: any): void {
    if (this.mainSeedWs && this.mainSeedWs.readyState === WebSocket.OPEN) {
      this.mainSeedWs.send(JSON.stringify(message));
    }
  }

  getConsensusStatus(): any {
    if (!this.heartbeatManager) {
      return { enabled: false, consensusAchieved: false };
    }

    const result = this.heartbeatManager.getConsensusStatus();
    const timeSinceLast = this.heartbeatManager.getTimeSinceLastVerification();

    return {
      enabled: true,
      lastVerification: Date.now() - timeSinceLast,
      consensusAchieved: result?.isConsensus || false,
      agreementPercentage: result?.agreementPercentage || 0,
      totalNodes: result?.totalNodes || 0,
      mainNodeAlive: Date.now() - this.lastMainNodeHeartbeat < 180000
    };
  }
}
