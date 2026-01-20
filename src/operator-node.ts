import express, { Express, Request, Response } from 'express';
import * as http from 'http';
import WebSocket from 'ws';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import { createHash, pbkdf2Sync, timingSafeEqual, randomBytes } from 'crypto';

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
      const text = await seedResp.text();
      res.send(text);
    } catch (e: any) {
      res.status(502).json({ success: false, error: e?.message || String(e) });
    }
  }

  private getUiCacheDir(): string {
    return process.env.UI_CACHE_DIR
      ? String(process.env.UI_CACHE_DIR)
      : path.join(this.config.dataDir, 'ui-cache');
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
    const uiDir = this.getUiCacheDir();
    this.app.use(express.static(uiDir));

    this.app.get('/', (req: Request, res: Response) => {
      const fp = this.resolveUiFile('mobile-entry.html');
      if (fs.existsSync(fp)) {
        res.sendFile(fp);
        return;
      }
      res.json({ success: true, operatorId: this.config.operatorId, message: 'Operator node is running' });
    });

    this.app.get('/m', (req: Request, res: Response) => {
      const fp = this.resolveUiFile('mobile-entry.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/login', (req: Request, res: Response) => {
      const fp = this.resolveUiFile('mobile-login.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/wallet', (req: Request, res: Response) => {
      const fp = this.resolveUiFile('mobile-wallet.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/items', (req: Request, res: Response) => {
      const fp = this.resolveUiFile('mobile-items.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/offers', (req: Request, res: Response) => {
      const fp = this.resolveUiFile('mobile-offers.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/offer', (req: Request, res: Response) => {
      const fp = this.resolveUiFile('mobile-offer.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/verify', (req: Request, res: Response) => {
      const fp = this.resolveUiFile('mobile-verify.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/consignment', (req: Request, res: Response) => {
      const fp = this.resolveUiFile('mobile-consignment.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/consign', (req: Request, res: Response) => {
      const fp = this.resolveUiFile('mobile-consign.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
    });
    this.app.get('/m/history', (req: Request, res: Response) => {
      const fp = this.resolveUiFile('mobile-history.html');
      if (fs.existsSync(fp)) return res.sendFile(fp);
      res.status(404).send('UI not available');
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
      try {
        const { email, password, totpCode } = req.body;
        if (!email || !password) {
          res.status(400).json({ success: false, error: 'Missing email or password' });
          return;
        }

        const emailHash = this.computeEmailHash(email);
        let account: any = null;
        for (const acc of this.state.accounts.values()) {
          if (String(acc.emailHash || '') === emailHash) {
            account = acc;
            break;
          }
        }

        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        if (!account.passwordHash) {
          res.status(400).json({ success: false, error: 'Password not set for this account' });
          return;
        }

        const passwordValid = await this.verifyPassword(password, account.passwordHash, account.passwordKdf);
        if (!passwordValid) {
          res.status(401).json({ success: false, error: 'Invalid password' });
          return;
        }

        if (account.totp?.enabled) {
          if (!totpCode) {
            res.status(400).json({ success: false, error: '2FA code required', requires2FA: true });
            return;
          }
          res.status(501).json({ success: false, error: '2FA verification requires main node' });
          return;
        }

        const sessionId = `session_${Date.now()}_${this.randomHex(16)}`;
        const createdAt = Date.now();
        const expiresAt = createdAt + 24 * 60 * 60 * 1000;

        this.sessions.set(sessionId, { sessionId, accountId: String(account.accountId), createdAt, expiresAt });

        res.json({
          success: true,
          sessionId,
          accountId: account.accountId,
          expiresAt,
          emailHash: account.emailHash,
          walletAddress: account.walletAddress,
          walletVault: (account as any).walletVault,
          account: {
            accountId: String(account.accountId),
            role: String((account as any).role || ''),
            username: (account as any).username ? String((account as any).username) : undefined,
            displayName: (account as any).displayName ? String((account as any).displayName) : undefined,
            walletAddress: (account as any).walletAddress ? String((account as any).walletAddress) : undefined,
          },
        });
      } catch (error: any) {
        console.error('[Auth] Login error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
      }
    });

    this.app.get('/api/auth/me', async (req: Request, res: Response) => {
      const sess = this.requireSession(req, res);
      if (!sess) return;
      const account = this.state.accounts.get(String(sess.accountId));
      if (!account) {
        res.status(404).json({ success: false, error: 'Account not found' });
        return;
      }
      res.json({
        success: true,
        account: {
          accountId: String((account as any).accountId || sess.accountId),
          role: String((account as any).role || ''),
          username: (account as any).username ? String((account as any).username) : undefined,
          displayName: (account as any).displayName ? String((account as any).displayName) : undefined,
          walletAddress: (account as any).walletAddress ? String((account as any).walletAddress) : undefined,
        },
      });
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

    this.app.all('/dashboard*', (req: Request, res: Response) => {
      res.status(403).json({ 
        success: false, 
        error: 'Admin dashboard is not available on operator nodes. Please use the main node dashboard.' 
      });
    });

    this.app.use((req: Request, res: Response) => {
      res.status(404).json({ error: 'Endpoint not found' });
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

    await this.connectToMainSeed();

    console.log('\n[Operator] Node is running!');
    console.log('[Operator] Press Ctrl+C to stop\n');
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

        // Send sync request
        this.mainSeedWs!.send(JSON.stringify({
          type: 'sync_request',
          operatorId: this.config.operatorId,
          lastSequence: this.state.lastSyncedSequence,
          timestamp: Date.now()
        }));
      });

      this.mainSeedWs.on('message', async (data: WebSocket.Data) => {
        try {
          const message = JSON.parse(data.toString());
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
        break;
      case 'new_event':
        await this.handleNewEvent(message.event);
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
}
