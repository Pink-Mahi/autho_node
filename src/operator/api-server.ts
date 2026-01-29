import express, { Express, Request, Response } from 'express';
import { createHash, pbkdf2Sync, randomBytes, timingSafeEqual } from 'crypto';
import { OperatorNode } from './node';
import { WalletAPI } from '../api/wallet-api';
import { RegistryAPI } from '../registry/registry-api';
import { ItemRegistry } from '../registry/item-registry';
import { JoinAPI } from '../network/join-api';
import { NetworkBootstrap } from '../network/bootstrap';
import { ProtocolEvent } from '../types';
import { BitcoinTransactionService } from '../bitcoin/transaction-service';
import { PaymentService } from '../bitcoin/payment-service';
import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import WebSocket from 'ws';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import * as bitcoin from 'bitcoinjs-lib';
import { EventStore as CanonicalEventStore } from '../event-store';
import { EventType, QuorumSignature } from '../event-store';
import { StateBuilder } from '../event-store';
import { PlatformFeePayoutSnapshot } from '../event-store/types';
import { openTotpSecretBase32, sealTotpSecretBase32, verifySignature } from '../crypto';
import { HeartbeatManager } from '../consensus/heartbeat-manager';
import { StateVerifier, LedgerState } from '../consensus/state-verifier';
import { LeaderElection, OperatorInfo } from '../consensus/leader-election';
import { 
  ConsensusNode, 
  MempoolEvent, 
  FinalizedCheckpoint,
  ConsensusMessage,
  StateProviderAdapter 
} from '../consensus';

export class OperatorAPIServer {
  private app: Express;
  private port: number;
  private node: OperatorNode;
  private walletAPI: WalletAPI;
  private registryAPI: RegistryAPI;
  private itemRegistry: ItemRegistry;
  private canonicalEventStore: CanonicalEventStore;
  private canonicalStateBuilder: StateBuilder;
  private network: 'mainnet' | 'testnet';
  private joinAPI: JoinAPI;
  private bootstrap: NetworkBootstrap;
  private paymentService: PaymentService;
  private httpServer?: http.Server;
  private wss?: WebSocket.Server;
  private wsConnections: Map<
    WebSocket,
    {
      type: 'gateway' | 'operator';
      operatorId?: string;
      connectedAt: number;
      lastSeen: number;
      ip?: string;
      isUi?: boolean;
      subscribedToConsensus?: boolean;
    }
  > = new Map();
  private wsKeepAliveTimer?: NodeJS.Timeout;
  private settlementExpiryTimer?: NodeJS.Timeout;
  private settlementReconcileTimer?: NodeJS.Timeout;
  private consignmentExpiryTimer?: NodeJS.Timeout;
  private operatorHeartbeatTimer: any;
  private checkpointTimer?: NodeJS.Timeout;
  private powChallenges: Map<string, { salt: string; difficulty: number; expiresAt: number; resource: string }> = new Map();
  private heartbeatManager?: HeartbeatManager;
  private lastMainNodeHeartbeat: number = Date.now();
  private isActingAsLeader: boolean = false;

  // Decentralized consensus components
  private consensusNode?: ConsensusNode;
  private stateProviderAdapter?: StateProviderAdapter;

  private getActiveOperatorsForFeePayout(state: any, mainNodeAddress: string): Array<{ operatorId: string; address: string }> {
    const ops = Array.from((state as any)?.operators?.values?.() || []) as any[];
    return ops
      .filter((o: any) => o && String(o.status || '') === 'active')
      .map((o: any) => ({ operatorId: String(o.operatorId || ''), address: String(o.btcAddress || '').trim() }))
      .filter((o: any) => o.operatorId && o.address)
      .filter((o: any) => o.address !== mainNodeAddress)
      .sort((a: any, b: any) => String(a.operatorId).localeCompare(String(b.operatorId)));
  }

  private computePlatformFeePayoutSnapshot(params: { state: any; platformFeeSats: number }): PlatformFeePayoutSnapshot {
    const state = params.state;
    const totalFeeSats = Math.floor(Number(params.platformFeeSats || 0));
    const mainNodeAddress = String(this.getFeeAddress() || '').trim();
    const dustLimit = Math.floor(Number(process.env.DUST_LIMIT_SATS || 0) || 546);
    const maxOperators = Math.max(0, Math.floor(Number(process.env.PLATFORM_FEE_MAX_OPERATORS || 0) || 3));

    if (!mainNodeAddress) {
      return { platformFeeSats: totalFeeSats, mainNodeAddress: '', mainNodeFeeSats: totalFeeSats, operatorPayouts: [] };
    }

    if (!(totalFeeSats > 0) || maxOperators === 0) {
      return { platformFeeSats: totalFeeSats, mainNodeAddress, mainNodeFeeSats: totalFeeSats, operatorPayouts: [] };
    }

    const active = this.getActiveOperatorsForFeePayout(state, mainNodeAddress);
    const cursor = Math.floor(Number((state as any)?.feePayoutCursor || 0));

    if (!active.length) {
      return { platformFeeSats: totalFeeSats, mainNodeAddress, mainNodeFeeSats: totalFeeSats, operatorPayouts: [] };
    }

    const selected: Array<{ operatorId: string; address: string }> = [];
    const seenAddr = new Set<string>();
    for (let i = 0; i < active.length && selected.length < maxOperators; i++) {
      const idx = (cursor + i) % active.length;
      const op = active[idx];
      if (!op || !op.operatorId || !op.address) continue;
      if (seenAddr.has(op.address)) continue;
      seenAddr.add(op.address);
      selected.push(op);
    }

    if (!selected.length) {
      return { platformFeeSats: totalFeeSats, mainNodeAddress, mainNodeFeeSats: totalFeeSats, operatorPayouts: [] };
    }

    const dist = PaymentService.calculateFeeDistribution(totalFeeSats, mainNodeAddress, selected.map((s) => s.address));
    let mainNodeFeeSats = Math.floor(Number(dist.mainNodeFeeSats || 0));
    let operatorFeeSats = Math.floor(Number(dist.operatorFeeSats || 0));
    if (!(operatorFeeSats > 0)) {
      return { platformFeeSats: totalFeeSats, mainNodeAddress, mainNodeFeeSats: totalFeeSats, operatorPayouts: [] };
    }

    const base = Math.floor(operatorFeeSats / selected.length);
    if (base <= dustLimit) {
      return { platformFeeSats: totalFeeSats, mainNodeAddress, mainNodeFeeSats: totalFeeSats, operatorPayouts: [] };
    }

    const remainder = operatorFeeSats % selected.length;
    const operatorPayouts = selected
      .map((op, i) => ({
        operatorId: op.operatorId,
        address: op.address,
        amountSats: base + (i < remainder ? 1 : 0),
      }))
      .filter((x) => x && x.operatorId && x.address && Number(x.amountSats || 0) > 0);

    const sumOps = operatorPayouts.reduce((sum, x) => sum + Number(x.amountSats || 0), 0);
    mainNodeFeeSats = Math.max(0, totalFeeSats - sumOps);

    return {
      platformFeeSats: totalFeeSats,
      mainNodeAddress,
      mainNodeFeeSats,
      operatorPayouts,
    };
  }

  private userAuthChallenges: Map<
    string,
    { challengeId: string; accountId: string; nonce: string; createdAt: number; expiresAt: number; used: boolean }
  > = new Map();
  private userSessions: Map<string, { sessionId: string; accountId: string; createdAt: number; expiresAt: number }> = new Map();
  private pendingTotpSetup: Map<
    string,
    { accountId: string; secretBase32: string; otpauthUrl: string; createdAt: number; expiresAt: number }
  > = new Map();

  private recoveryChallenges: Map<
    string,
    { challengeId: string; accountId: string; nonce: string; createdAt: number; expiresAt: number; used: boolean }
  > = new Map();
  private recoverySessions: Map<string, { sessionId: string; accountId: string; createdAt: number; expiresAt: number }> = new Map();
  private pendingRecoveryTotpSetup: Map<
    string,
    { accountId: string; secretBase32: string; otpauthUrl: string; createdAt: number; expiresAt: number }
  > = new Map();

  private operatorApplyChallenges: Map<
    string,
    { challengeId: string; accountId: string; nonce: string; createdAt: number; expiresAt: number; used: boolean }
  > = new Map();

  private adminSessions: Map<string, { token: string; username: string; createdAt: number; expiresAt: number }> = new Map();

  private getAdminSession(token: string): { token: string; username: string; createdAt: number; expiresAt: number } | null {
    const sess = this.adminSessions.get(String(token));
    if (!sess) return null;
    if (Date.now() > sess.expiresAt) {
      this.adminSessions.delete(String(token));
      return null;
    }
    return sess;
  }

  private requireAdminToken(req: Request, res: Response): string | null {
    const authz = String(req.headers.authorization || '');
    const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';
    if (!token) {
      res.status(401).json({ success: false, error: 'Missing Authorization Bearer token' });
      return null;
    }
    const sess = this.getAdminSession(token);
    if (!sess) {
      res.status(401).json({ success: false, error: 'Invalid or expired admin session' });
      return null;
    }
    return token;
  }

  private requireAdminMainNode(req: Request, res: Response): boolean {
    const token = this.requireAdminToken(req, res);
    if (!token) return false;

    const mainNodeAccountId = String(process.env.MAIN_NODE_ACCOUNT_ID || '').trim();
    if (!mainNodeAccountId) {
      res.status(500).json({ success: false, error: 'MAIN_NODE_ACCOUNT_ID is not configured on this node' });
      return false;
    }

    const nodePub = String(this.node.getOperatorInfo().publicKey || '').trim();
    if (!nodePub || nodePub !== mainNodeAccountId) {
      res.status(403).json({ success: false, error: 'Main node operator required' });
      return false;
    }

    return true;
  }

  private enforceRetailerNotBlockedOrRespond(res: Response, account: any): boolean {
    const status = String((account as any)?.retailerStatus || 'unverified');
    if (status === 'blocked') {
      res.status(403).json({ success: false, error: 'Retailer account is blocked', code: 'RETAILER_BLOCKED' });
      return false;
    }
    return true;
  }

  private enforceFreshRetailerBondOrRespond(res: Response, account: any): boolean {
    const bondMinSats = Number(process.env.RETAILER_BOND_MIN_SATS || 200000);
    const bondMaxAgeMs = Number(process.env.RETAILER_BOND_MAX_AGE_MS || 0) || 24 * 60 * 60 * 1000;
    const status = String((account as any)?.retailerStatus || 'unverified');
    if (status === 'blocked') {
      res.status(403).json({ success: false, error: 'Retailer account is blocked', code: 'RETAILER_BLOCKED' });
      return false;
    }

    if (!(bondMinSats > 0)) return true;

    const meets = Boolean((account as any)?.retailerBondMeetsMin);
    const last = Number((account as any)?.retailerBondLastCheckedAt || 0);
    const stale = !last || (Date.now() - last) > bondMaxAgeMs;
    if (!meets || stale) {
      res.status(403).json({
        success: false,
        error: 'Retailer bond proof required. Run the retailer bond check in your dashboard.',
        code: 'RETAILER_BOND_REQUIRED',
        bond: {
          bondMinSats,
          bondMeetsMin: meets,
          bondLastCheckedAt: last || undefined,
          bondMaxAgeMs,
          isStale: stale,
        },
      });
      return false;
    }

    return true;
  }

  private normalizeEmailForHash(email: string): string {
    return String(email || '').trim().toLowerCase();
  }

  private computeEmailHash(email: string): string {
    const normalized = this.normalizeEmailForHash(email);
    return createHash('sha256').update(normalized).digest('hex');
  }

  private isValidPassword(password: string): boolean {
    const pw = String(password || '');
    if (pw.length < 8) return false;
    if (pw.length > 256) return false;
    if (pw.includes(' ')) {
      return pw.length >= 14;
    }
    const hasUpper = /[A-Z]/.test(pw);
    const hasLower = /[a-z]/.test(pw);
    const hasDigit = /\d/.test(pw);
    const hasSpecial = /[^A-Za-z0-9]/.test(pw);
    return pw.length >= 12 && hasUpper && hasLower && hasDigit && hasSpecial;
  }

  private computePasswordHash(password: string, passwordKdf: any): string {
    const saltB64 = String(passwordKdf?.saltB64 || '');
    const iterations = Number(passwordKdf?.iterations || 0);
    if (!saltB64 || !Number.isFinite(iterations) || iterations < 10000) {
      return createHash('sha256').update(String(password)).digest('hex');
    }
    const salt = Buffer.from(saltB64, 'base64');
    const dk = pbkdf2Sync(String(password), salt, iterations, 32, 'sha256');
    return dk.toString('hex');
  }

  private getSessionFromRequest(req: Request): { sessionId: string; accountId: string; createdAt: number; expiresAt: number } | null {
    const authz = String(req.headers.authorization || '');
    const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';
    if (!token) return null;
    const session = this.userSessions.get(token);
    if (!session || Date.now() > session.expiresAt) return null;
    return session;
  }

  private isSettlementExpired(s: any, now: number): boolean {
    const exp = Number(s?.expiresAt || 0);
    if (!exp) return false;
    if (s?.status === 'completed' || s?.status === 'failed') return false;
    return now > exp;
  }

  private isActiveAcceptedSettlement(s: any, now: number): boolean {
    if (!s) return false;
    if (!s.acceptedAt) return false;
    if (s.status === 'completed' || s.status === 'failed') return false;
    if (this.isSettlementExpired(s, now)) return false;
    return true;
  }

  private isConsignmentExpired(c: any, now: number): boolean {
    const exp = Number(c?.expiresAt || 0);
    if (!exp) return false;
    const status = String(c?.status || '');
    if (status === 'completed' || status === 'cancelled' || status === 'expired') return false;
    return now > exp;
  }

  private async sweepExpiredSettlements(): Promise<number> {
    const now = Date.now();
    let expiredCount = 0;

    try {
      const state = await this.canonicalStateBuilder.buildState();
      const settlements = Array.from(state.settlements.values());
      const expired = settlements.filter((s: any) => this.isSettlementExpired(s, now));

      for (const s of expired) {
        try {
          // Do not auto-expire if escrow address already has confirmed funds >= price.
          try {
            const escrowAddress = String((s as any)?.escrowAddress || '').trim();
            const priceSats = Number((s as any)?.price || 0);
            if (escrowAddress && Number.isFinite(priceSats) && priceSats > 0) {
              const apiBase = this.getBlockstreamApiBase();
              const utxosRes = await fetch(`${apiBase}/address/${encodeURIComponent(escrowAddress)}/utxo`);
              if (utxosRes.ok) {
                const utxos = await utxosRes.json();
                if (Array.isArray(utxos) && utxos.length > 0) {
                  const confirmed = utxos.filter((u: any) => u && u.status && u.status.confirmed);
                  const confirmedSum = confirmed.reduce((sum: number, u: any) => sum + Number(u?.value || 0), 0);
                  if (confirmedSum >= priceSats) {
                    continue;
                  }
                }
              }
            }
          } catch {}

          const offerId = String(s.settlementId);
          const nonce = randomBytes(32).toString('hex');
          const signatures: QuorumSignature[] = [
            {
              operatorId: process.env.OPERATOR_ID || 'operator-1',
              publicKey: this.node.getOperatorInfo().publicKey,
              signature: createHash('sha256')
                .update(`SETTLEMENT_FAILED:${offerId}:${now}`)
                .digest('hex'),
            },
          ];

          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.SETTLEMENT_FAILED,
              timestamp: now,
              nonce,
              settlementId: offerId,
              itemId: String(s.itemId || ''),
              reason: 'expired',
            } as any,
            signatures
          );

          expiredCount++;
        } catch (e: any) {
          console.error('[Settlement] Failed to expire settlement:', e?.message || String(e));
        }
      }
    } catch (e: any) {
      console.error('[Settlement] Expiry sweep failed:', e?.message || String(e));
    }

    return expiredCount;
  }

  private async sweepExpiredConsignments(): Promise<number> {
    const now = Date.now();
    let expiredCount = 0;

    try {
      const state = await this.canonicalStateBuilder.buildState();
      const consignments = Array.from((state as any).consignments?.values?.() || []) as any[];
      const expired = consignments.filter((c: any) => {
        if (!this.isConsignmentExpired(c, now)) return false;
        const txid = String(c?.txid || '').trim();
        // If a payment txid has already been submitted, do not auto-expire; reconcile may still complete it.
        if (txid) return false;
        return true;
      });

      for (const c of expired) {
        try {
          const consignmentId = String(c.consignmentId || '').trim();
          if (!consignmentId) continue;

          const nonce = randomBytes(32).toString('hex');
          const signatures: QuorumSignature[] = [
            {
              operatorId: process.env.OPERATOR_ID || 'operator-1',
              publicKey: this.node.getOperatorInfo().publicKey,
              signature: createHash('sha256')
                .update(`CONSIGNMENT_EXPIRED:${consignmentId}:${now}`)
                .digest('hex'),
            },
          ];

          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.CONSIGNMENT_EXPIRED,
              timestamp: now,
              nonce,
              consignmentId,
            } as any,
            signatures
          );

          expiredCount++;
        } catch (e: any) {
          console.error('[Consignment] Failed to expire consignment:', e?.message || String(e));
        }
      }
    } catch (e: any) {
      console.error('[Consignment] Expiry sweep failed:', e?.message || String(e));
    }

    return expiredCount;
  }

  private getBlockstreamApiBase(): string {
    return this.network === 'testnet' ? 'https://blockstream.info/testnet/api' : 'https://blockstream.info/api';
  }

  private getChainApiBases(): string[] {
    const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
    return network === 'mainnet'
      ? ['https://mempool.space/api', 'https://blockstream.info/api']
      : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];
  }

  private getBitcoinJsNetwork(): bitcoin.Network {
    return this.network === 'testnet' ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;
  }

  private getFeeAddress(): string {
    return this.network === 'testnet'
      ? String(process.env.FEE_ADDRESS_TESTNET || '').trim()
      : '1FMcxZRUWVDbKy7DxAosW7sM5PUntAkJ9U';
  }

  private computeNetworkId(): string {
    const net = this.network === 'testnet' ? 'testnet' : 'mainnet';
    const fee = this.getFeeAddress();
    return createHash('sha256').update(`${net}:${fee}`).digest('hex');
  }

  private async fetchTxHex(txid: string): Promise<string> {
    const apiBase = this.getBlockstreamApiBase();
    const resp = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/hex`);
    const text = await resp.text();
    if (!resp.ok) throw new Error(`Failed to fetch tx hex: ${String(text || '').trim() || resp.status}`);
    return String(text || '').trim();
  }

  private async fetchTxStatus(txid: string): Promise<{ confirmed: boolean; confirmations: number; blockHeight?: number }> {
    const apiBase = this.getBlockstreamApiBase();

    const statusResp = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/status`);
    const statusText = await statusResp.text();
    if (!statusResp.ok) throw new Error(`Failed to fetch tx status: ${String(statusText || '').trim() || statusResp.status}`);

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

    return { confirmed, confirmations, blockHeight: blockHeight || undefined };
  }

  private parseRatingFeeTx(txHex: string): { feePaidSats: number; hasFeeOutput: boolean } {
    const tx = bitcoin.Transaction.fromHex(txHex);
    const net = this.getBitcoinJsNetwork();
    const feeAddress = this.getFeeAddress();
    const feeScript = feeAddress ? bitcoin.address.toOutputScript(feeAddress, net) : undefined;

    let feePaidSats = 0;
    let hasFeeOutput = false;
    for (const out of tx.outs) {
      if (feeScript && Buffer.isBuffer(out.script) && out.script.equals(feeScript)) {
        hasFeeOutput = true;
        feePaidSats += Number(out.value || 0);
      }
    }
    return { feePaidSats, hasFeeOutput };
  }

  private enforceFreshBondOrRespond(res: Response, account: any, roleLabel: 'manufacturer' | 'authenticator'): boolean {
    const bondMinSats = Number(process.env.VERIFIER_BOND_MIN_SATS || 100000);
    const bondMaxAgeMs = Number(process.env.VERIFIER_BOND_MAX_AGE_MS || 0) || 24 * 60 * 60 * 1000;
    if (!(bondMinSats > 0)) return true;

    const meets = Boolean((account as any)?.bondMeetsMin);
    const last = Number((account as any)?.bondLastCheckedAt || 0);
    const stale = !last || (Date.now() - last) > bondMaxAgeMs;
    if (!meets || stale) {
      res.status(403).json({
        success: false,
        error: `${roleLabel === 'authenticator' ? 'Authenticator' : 'Manufacturer'} bond proof required. Run the bond check in your dashboard.`,
        code: 'BOND_PROOF_REQUIRED',
        bond: {
          bondMinSats,
          bondMeetsMin: meets,
          bondLastCheckedAt: last || undefined,
          bondMaxAgeMs,
          isStale: stale,
        },
      });
      return false;
    }

    return true;
  }

  private getReputationLimits(): {
    windowMs: number;
    maxRatingsPerWindow: number;
    maxReportsPerWindow: number;
    maxContextsPerVerifier: number;
  } {
    const windowMs = Number(process.env.VERIFIER_REPUTATION_WINDOW_MS || 0) || 24 * 60 * 60 * 1000;
    const maxRatingsPerWindow = Number(process.env.VERIFIER_RATING_MAX_PER_WINDOW || 0);
    const maxReportsPerWindow = Number(process.env.VERIFIER_REPORT_MAX_PER_WINDOW || 0);
    const maxContextsPerVerifier = Number(process.env.VERIFIER_REPUTATION_MAX_CONTEXTS_PER_VERIFIER || 0);
    return {
      windowMs: Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 24 * 60 * 60 * 1000,
      maxRatingsPerWindow: Number.isFinite(maxRatingsPerWindow) && maxRatingsPerWindow > 0 ? maxRatingsPerWindow : 0,
      maxReportsPerWindow: Number.isFinite(maxReportsPerWindow) && maxReportsPerWindow > 0 ? maxReportsPerWindow : 0,
      maxContextsPerVerifier: Number.isFinite(maxContextsPerVerifier) && maxContextsPerVerifier > 0 ? maxContextsPerVerifier : 0,
    };
  }

  private getRetailerReputationLimits(): {
    windowMs: number;
    maxRatingsPerWindow: number;
    maxReportsPerWindow: number;
    maxContextsPerRetailer: number;
  } {
    const windowMs = Number(process.env.RETAILER_REPUTATION_WINDOW_MS || 0) || 24 * 60 * 60 * 1000;
    const maxRatingsPerWindow = Number(process.env.RETAILER_RATING_MAX_PER_WINDOW || 0);
    const maxReportsPerWindow = Number(process.env.RETAILER_REPORT_MAX_PER_WINDOW || 0);
    const maxContextsPerRetailer = Number(process.env.RETAILER_REPUTATION_MAX_CONTEXTS_PER_RETAILER || 0);
    return {
      windowMs: Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 24 * 60 * 60 * 1000,
      maxRatingsPerWindow: Number.isFinite(maxRatingsPerWindow) && maxRatingsPerWindow > 0 ? maxRatingsPerWindow : 0,
      maxReportsPerWindow: Number.isFinite(maxReportsPerWindow) && maxReportsPerWindow > 0 ? maxReportsPerWindow : 0,
      maxContextsPerRetailer: Number.isFinite(maxContextsPerRetailer) && maxContextsPerRetailer > 0 ? maxContextsPerRetailer : 0,
    };
  }

  private computeRetailerReputationUsage(params: {
    state: any;
    now: number;
    raterAccountId: string;
    targetAccountId: string;
  }): {
    ratingsInWindow: number;
    reportsInWindow: number;
    ratingsForTargetInWindow: number;
    reportsForTargetInWindow: number;
    distinctContextsForTarget: number;
  } {
    const { state, now, raterAccountId, targetAccountId } = params;
    const limits = this.getRetailerReputationLimits();
    const cutoff = now - limits.windowMs;

    const ratings = Array.from((state as any).retailerRatings?.values?.() || []);
    const reports = Array.from((state as any).retailerReports?.values?.() || []);

    const ratingsInWindow = ratings.filter((x: any) => {
      if (!x) return false;
      if (String(x.raterAccountId || '') !== raterAccountId) return false;
      const ts = Number(x.createdAt || 0);
      return ts >= cutoff;
    }).length;

    const reportsInWindow = reports.filter((x: any) => {
      if (!x) return false;
      if (String(x.reporterAccountId || '') !== raterAccountId) return false;
      const ts = Number(x.createdAt || 0);
      return ts >= cutoff;
    }).length;

    const ratingsForTargetInWindow = ratings.filter((x: any) => {
      if (!x) return false;
      if (String(x.raterAccountId || '') !== raterAccountId) return false;
      if (String(x.targetAccountId || '') !== targetAccountId) return false;
      const ts = Number(x.createdAt || 0);
      return ts >= cutoff;
    }).length;

    const reportsForTargetInWindow = reports.filter((x: any) => {
      if (!x) return false;
      if (String(x.reporterAccountId || '') !== raterAccountId) return false;
      if (String(x.targetAccountId || '') !== targetAccountId) return false;
      const ts = Number(x.createdAt || 0);
      return ts >= cutoff;
    }).length;

    const distinctContextsForTarget = new Set([
      ...ratings
        .filter((x: any) => x && String(x.raterAccountId || '') === raterAccountId && String(x.targetAccountId || '') === targetAccountId)
        .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
      ...reports
        .filter((x: any) => x && String(x.reporterAccountId || '') === raterAccountId && String(x.targetAccountId || '') === targetAccountId)
        .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
    ]).size;

    return {
      ratingsInWindow,
      reportsInWindow,
      ratingsForTargetInWindow,
      reportsForTargetInWindow,
      distinctContextsForTarget,
    };
  }

  private computeConsignmentPayouts(params: {
    askingPriceSats: number;
    sellerMinNetSats: number;
    retailerMarkupShareBps: number;
  }): {
    platformFeeSats: number;
    markupSats: number;
    retailerCommissionSats: number;
    sellerPayoutSats: number;
  } {
    const askingPriceSats = Math.floor(Number(params.askingPriceSats || 0));
    const sellerMinNetSats = Math.floor(Number(params.sellerMinNetSats || 0));
    const retailerMarkupShareBps = Math.floor(Number(params.retailerMarkupShareBps || 0));
    const platformFeeSats = PaymentService.calculatePlatformFee(askingPriceSats);
    const markupSats = askingPriceSats - platformFeeSats - sellerMinNetSats;
    const safeMarkup = Math.max(0, markupSats);
    const shareBps = Math.min(10000, Math.max(0, retailerMarkupShareBps));
    const retailerCommissionSats = Math.floor((safeMarkup * shareBps) / 10000);
    const sellerPayoutSats = askingPriceSats - platformFeeSats - retailerCommissionSats;
    return { platformFeeSats, markupSats, retailerCommissionSats, sellerPayoutSats };
  }

  private computeReputationUsage(params: {
    state: any;
    now: number;
    raterAccountId: string;
    targetAccountId: string;
  }): {
    ratingsInWindow: number;
    reportsInWindow: number;
    ratingsForTargetInWindow: number;
    reportsForTargetInWindow: number;
    distinctContextsForTarget: number;
  } {
    const { state, now, raterAccountId, targetAccountId } = params;
    const limits = this.getReputationLimits();
    const cutoff = now - limits.windowMs;

    const ratings = Array.from((state as any).verifierRatings?.values?.() || []);
    const reports = Array.from((state as any).verifierReports?.values?.() || []);

    const ratingsInWindow = ratings.filter((x: any) => {
      if (!x) return false;
      if (String(x.raterAccountId || '') !== raterAccountId) return false;
      const ts = Number(x.createdAt || 0);
      return ts >= cutoff;
    }).length;

    const reportsInWindow = reports.filter((x: any) => {
      if (!x) return false;
      if (String(x.reporterAccountId || '') !== raterAccountId) return false;
      const ts = Number(x.createdAt || 0);
      return ts >= cutoff;
    }).length;

    const ratingsForTargetInWindow = ratings.filter((x: any) => {
      if (!x) return false;
      if (String(x.raterAccountId || '') !== raterAccountId) return false;
      if (String(x.targetAccountId || '') !== targetAccountId) return false;
      const ts = Number(x.createdAt || 0);
      return ts >= cutoff;
    }).length;

    const reportsForTargetInWindow = reports.filter((x: any) => {
      if (!x) return false;
      if (String(x.reporterAccountId || '') !== raterAccountId) return false;
      if (String(x.targetAccountId || '') !== targetAccountId) return false;
      const ts = Number(x.createdAt || 0);
      return ts >= cutoff;
    }).length;

    const distinctContextsForTarget = new Set([
      ...ratings
        .filter((x: any) => x && String(x.raterAccountId || '') === raterAccountId && String(x.targetAccountId || '') === targetAccountId)
        .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
      ...reports
        .filter((x: any) => x && String(x.reporterAccountId || '') === raterAccountId && String(x.targetAccountId || '') === targetAccountId)
        .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
    ]).size;

    return {
      ratingsInWindow,
      reportsInWindow,
      ratingsForTargetInWindow,
      reportsForTargetInWindow,
      distinctContextsForTarget,
    };
  }

  private async reconcilePaidSettlements(): Promise<number> {
    const now = Date.now();
    let reconciled = 0;

    try {
      const state = await this.canonicalStateBuilder.buildState();
      const apiBase = this.getBlockstreamApiBase();
      const settlements = Array.from(state.settlements.values());

      const candidates = settlements.filter((s: any) => {
        if (!s) return false;
        if (s.status === 'completed') return false;
        // We allow reconciliation even if expired/failed, as long as we can verify an on-chain payment.
        // This prevents funds being stuck in a "paid but failed" state.
        const hasEscrow = !!String(s.escrowAddress || '').trim();
        const hasTxid = !!String((s as any)?.txid || '').trim();
        return hasEscrow || hasTxid;
      });

      for (const s of candidates) {
        const escrowAddress = String(s.escrowAddress || '').trim();
        const priceSats = Number(s.price || 0);
        if (!Number.isFinite(priceSats) || priceSats <= 0) continue;

        try {
          let txid = String((s as any)?.txid || '').trim();

          if (!txid && escrowAddress) {
            const utxosRes = await fetch(`${apiBase}/address/${encodeURIComponent(escrowAddress)}/utxo`);
            if (!utxosRes.ok) continue;
            const utxos = await utxosRes.json();
            if (!Array.isArray(utxos) || utxos.length === 0) continue;

            const confirmed = utxos.filter((u: any) => u && u.status && u.status.confirmed);
            const confirmedSum = confirmed.reduce((sum: number, u: any) => sum + Number(u?.value || 0), 0);
            if (confirmedSum < priceSats) continue;

            txid = String(confirmed[0]?.txid || '').trim();
          }

          if (!txid) continue;

          const txStatusRes = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/status`);
          if (!txStatusRes.ok) continue;
          const txStatus = await txStatusRes.json();
          if (!txStatus || txStatus.confirmed !== true) continue;

          const mainNodeAddress = String(this.getFeeAddress() || '').trim();
          const platformFeeSats = PaymentService.calculatePlatformFee(priceSats);
          const sellerReceivesSats = priceSats - platformFeeSats;

          const payoutSnap: PlatformFeePayoutSnapshot | null = (s as any)?.platformFeePayouts
            ? ((s as any).platformFeePayouts as PlatformFeePayoutSnapshot)
            : null;

          const feeMainAddr = payoutSnap?.mainNodeAddress ? String(payoutSnap.mainNodeAddress) : mainNodeAddress;
          const feeMainExpected = payoutSnap ? Number(payoutSnap.mainNodeFeeSats || 0) : platformFeeSats;
          const feeOpExpected = payoutSnap ? (Array.isArray(payoutSnap.operatorPayouts) ? payoutSnap.operatorPayouts : []) : [];

          const txRes = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}`);
          if (!txRes.ok) continue;
          const tx = await txRes.json();
          const vout = Array.isArray(tx?.vout) ? tx.vout : [];

          const sellerAddress = String((s as any)?.seller || '').trim();
          const sellerPaid = vout.reduce((sum: number, o: any) => {
            const addr = String(o?.scriptpubkey_address || '').trim();
            const val = Number(o?.value || 0);
            return addr === sellerAddress ? sum + val : sum;
          }, 0);

          const feePaidMain = vout.reduce((sum: number, o: any) => {
            const addr = String(o?.scriptpubkey_address || '').trim();
            const val = Number(o?.value || 0);
            return addr === feeMainAddr ? sum + val : sum;
          }, 0);

          const feePaidOps: Record<string, number> = {};
          for (const p of feeOpExpected) {
            const addr = String(p?.address || '').trim();
            if (!addr) continue;
            feePaidOps[addr] = vout.reduce((sum: number, o: any) => {
              const a = String(o?.scriptpubkey_address || '').trim();
              const val = Number(o?.value || 0);
              return a === addr ? sum + val : sum;
            }, 0);
          }

          if (sellerReceivesSats > 0 && sellerPaid < sellerReceivesSats) continue;
          if (platformFeeSats > 0 && feePaidMain < feeMainExpected) continue;
          let opsOk = true;
          for (const p of feeOpExpected) {
            const addr = String(p?.address || '').trim();
            const exp = Number(p?.amountSats || 0);
            if (!addr || !(exp > 0)) continue;
            const got = Number(feePaidOps[addr] || 0);
            if (got < exp) {
              opsOk = false;
              break;
            }
          }
          if (!opsOk) continue;

          const nonce = randomBytes(32).toString('hex');
          const signatures: QuorumSignature[] = [
            {
              operatorId: process.env.OPERATOR_ID || 'operator-1',
              publicKey: this.node.getOperatorInfo().publicKey,
              signature: createHash('sha256')
                .update(`SETTLEMENT_COMPLETED:${String(s.settlementId)}:${now}`)
                .digest('hex'),
            },
          ];

          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.SETTLEMENT_COMPLETED,
              timestamp: now,
              nonce,
              settlementId: String(s.settlementId),
              itemId: String(s.itemId),
              txid,
              platformFee: platformFeeSats,
              operatorFees: payoutSnap
                ? (Array.isArray(payoutSnap.operatorPayouts) ? payoutSnap.operatorPayouts : []).reduce((m: any, p: any) => {
                    const id = String(p?.operatorId || '').trim();
                    const amt = Number(p?.amountSats || 0);
                    if (id && amt > 0) m[id] = amt;
                    return m;
                  }, {})
                : {},
            } as any,
            signatures
          );

          const ownershipNonce = randomBytes(32).toString('hex');
          const ownershipSignatures: QuorumSignature[] = [
            {
              operatorId: process.env.OPERATOR_ID || 'operator-1',
              publicKey: this.node.getOperatorInfo().publicKey,
              signature: createHash('sha256')
                .update(`OWNERSHIP_TRANSFERRED:${String(s.itemId)}:${now}`)
                .digest('hex'),
            },
          ];

          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.OWNERSHIP_TRANSFERRED,
              timestamp: now,
              nonce: ownershipNonce,
              itemId: String(s.itemId),
              fromOwner: String(s.seller),
              toOwner: String(s.buyer),
              settlementId: String(s.settlementId),
              price: priceSats,
              paymentTxHash: txid,
            } as any,
            ownershipSignatures
          );

          reconciled++;
        } catch (e: any) {
          console.error('[Settlement] Reconcile failed:', e?.message || String(e));
        }
      }
    } catch (e: any) {
      console.error('[Settlement] Reconcile loop failed:', e?.message || String(e));
    }

    return reconciled;
  }

  private buildConsignmentPurchaseOpReturnScriptHex(params: {
    consignmentId: string;
    buyerAccountId: string;
    askingPriceSats: number;
    sellerPayoutSats: number;
    retailerCommissionSats: number;
    platformFeeSats: number;
    ownerWallet: string;
    retailerWallet: string;
    lockedUntil: number;
  }): string {
    const consignmentId = String(params.consignmentId || '').trim();
    const buyerAccountId = String(params.buyerAccountId || '').trim();
    const ownerWallet = String(params.ownerWallet || '').trim();
    const retailerWallet = String(params.retailerWallet || '').trim();

    const payload = [
      'AUTHO_CONSIGNMENT_PURCHASE_V1',
      consignmentId,
      buyerAccountId,
      String(Math.floor(Number(params.askingPriceSats || 0))),
      String(Math.floor(Number(params.sellerPayoutSats || 0))),
      String(Math.floor(Number(params.retailerCommissionSats || 0))),
      String(Math.floor(Number(params.platformFeeSats || 0))),
      ownerWallet,
      retailerWallet,
      String(Math.floor(Number(params.lockedUntil || 0))),
    ].join('|');

    const commitmentHex = createHash('sha256').update(payload).digest('hex');
    // OP_RETURN with 32-byte push: 0x6a 0x20 <32 bytes>
    return `6a20${commitmentHex}`.toLowerCase();
  }

  private async reconcilePaidConsignments(): Promise<number> {
    const now = Date.now();
    let reconciled = 0;

    try {
      const state = await this.canonicalStateBuilder.buildState();
      const apiBase = this.getBlockstreamApiBase();
      const consignments = Array.from((state as any).consignments?.values?.() || []) as any[];

      const candidates = consignments.filter((c: any) => {
        if (!c) return false;
        const status = String(c.status || '');
        if (status === 'completed') return false;
        // Allow reconciliation even if expired/cancelled as long as we can verify an on-chain payment.
        const txid = String(c.txid || '').trim();
        if (!txid) return false;
        const buyerWallet = String(c.buyerWallet || '').trim();
        if (!buyerWallet) return false;
        return true;
      }) as any[];

      for (const c of candidates) {
        try {
          const consignmentId = String(c.consignmentId || '').trim();
          const txid = String(c.txid || '').trim();
          if (!consignmentId || !/^[0-9a-f]{64}$/i.test(txid)) continue;

          const txStatusRes = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/status`);
          if (!txStatusRes.ok) continue;
          const txStatus = await txStatusRes.json();
          if (!txStatus || txStatus.confirmed !== true) continue;

          const txRes = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}`);
          if (!txRes.ok) continue;
          const tx = await txRes.json();
          const vout = Array.isArray(tx?.vout) ? tx.vout : [];

          const ownerWallet = String(c.ownerWallet || '').trim();
          const retailerWallet = String(c.retailerWallet || '').trim();
          const buyerWallet = String(c.buyerWallet || '').trim();

          const askingPriceSats = Number(c.askingPriceSats || 0);
          const platformFeeSats = Number(c.platformFeeSats || 0);
          const retailerCommissionSats = Number(c.retailerCommissionSats || 0);
          const sellerPayoutSats = Number(c.sellerPayoutSats || 0);
          if (!(askingPriceSats > 0)) continue;

          const expectedOpReturnScriptHex = this.buildConsignmentPurchaseOpReturnScriptHex({
            consignmentId,
            buyerAccountId: String(c.buyerAccountId || ''),
            askingPriceSats,
            sellerPayoutSats,
            retailerCommissionSats,
            platformFeeSats,
            ownerWallet: String(c.ownerWallet || ''),
            retailerWallet: String(c.retailerWallet || ''),
            lockedUntil: Number(c.checkoutLock?.lockedUntil || 0),
          });

          const hasOpReturn = vout.some((o: any) => {
            const script = String(o?.scriptpubkey || '').trim().toLowerCase();
            return script && script === expectedOpReturnScriptHex;
          });

          if (!hasOpReturn) continue;

          const mainNodeAddress = String(this.getFeeAddress() || '').trim();

          const feeSnap: PlatformFeePayoutSnapshot | null = c.platformFeePayouts
            ? (c.platformFeePayouts as any)
            : null;
          const feeMainAddr = feeSnap?.mainNodeAddress ? String(feeSnap.mainNodeAddress).trim() : mainNodeAddress;
          const feeMainExpected = feeSnap ? Number(feeSnap.mainNodeFeeSats || 0) : platformFeeSats;
          const feeOpExpected = feeSnap ? (Array.isArray(feeSnap.operatorPayouts) ? feeSnap.operatorPayouts : []) : [];

          const ownerPaid = vout.reduce((sum: number, o: any) => {
            const addr = String(o?.scriptpubkey_address || '').trim();
            const val = Number(o?.value || 0);
            return addr === ownerWallet ? sum + val : sum;
          }, 0);

          const retailerPaid = vout.reduce((sum: number, o: any) => {
            const addr = String(o?.scriptpubkey_address || '').trim();
            const val = Number(o?.value || 0);
            return addr === retailerWallet ? sum + val : sum;
          }, 0);

          const feePaidMain = vout.reduce((sum: number, o: any) => {
            const addr = String(o?.scriptpubkey_address || '').trim();
            const val = Number(o?.value || 0);
            return addr === feeMainAddr ? sum + val : sum;
          }, 0);

          const feePaidOps: Record<string, number> = {};
          for (const p of feeOpExpected) {
            const addr = String(p?.address || '').trim();
            if (!addr) continue;
            feePaidOps[addr] = vout.reduce((sum: number, o: any) => {
              const a = String(o?.scriptpubkey_address || '').trim();
              const val = Number(o?.value || 0);
              return a === addr ? sum + val : sum;
            }, 0);
          }

          if (sellerPayoutSats > 0 && ownerPaid < sellerPayoutSats) continue;
          if (retailerCommissionSats > 0 && retailerPaid < retailerCommissionSats) continue;
          if (platformFeeSats > 0 && feePaidMain < feeMainExpected) continue;
          let opsOk = true;
          for (const p of feeOpExpected) {
            const addr = String(p?.address || '').trim();
            const exp = Number(p?.amountSats || 0);
            if (!addr || !(exp > 0)) continue;
            const got = Number(feePaidOps[addr] || 0);
            if (got < exp) {
              opsOk = false;
              break;
            }
          }
          if (!opsOk) continue;

          const nonce = randomBytes(32).toString('hex');
          const signatures: QuorumSignature[] = [
            {
              operatorId: process.env.OPERATOR_ID || 'operator-1',
              publicKey: this.node.getOperatorInfo().publicKey,
              signature: createHash('sha256')
                .update(`CONSIGNMENT_COMPLETED:${consignmentId}:${now}`)
                .digest('hex'),
            },
          ];

          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.CONSIGNMENT_COMPLETED,
              timestamp: now,
              nonce,
              consignmentId,
              txid,
            } as any,
            signatures
          );

          const ownershipNonce = randomBytes(32).toString('hex');
          const ownershipSignatures: QuorumSignature[] = [
            {
              operatorId: process.env.OPERATOR_ID || 'operator-1',
              publicKey: this.node.getOperatorInfo().publicKey,
              signature: createHash('sha256')
                .update(`OWNERSHIP_TRANSFERRED:${String(c.itemId)}:${now}`)
                .digest('hex'),
            },
          ];

          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.OWNERSHIP_TRANSFERRED,
              timestamp: now,
              nonce: ownershipNonce,
              itemId: String(c.itemId),
              fromOwner: ownerWallet,
              toOwner: buyerWallet,
              settlementId: consignmentId,
              price: askingPriceSats,
              paymentTxHash: txid,
            } as any,
            ownershipSignatures
          );

          reconciled++;
        } catch (e: any) {
          console.error('[Consignment] Reconcile failed:', e?.message || String(e));
        }
      }
    } catch (e: any) {
      console.error('[Consignment] Reconcile loop failed:', e?.message || String(e));
    }

    return reconciled;
  }

  private async getAccountFromSession(req: Request): Promise<any | null> {
    const session = this.getSessionFromRequest(req);
    if (!session) return null;
    const state = await this.canonicalStateBuilder.buildState();
    return state.accounts.get(session.accountId) || null;
  }

  private isAccountActiveOperator(state: any, accountId: string): boolean {
    const id = String(accountId || '').trim();
    if (!id) return false;
    const ops = Array.from((state as any)?.operators?.values?.() || []) as any[];
    return ops.some((o: any) =>
      o &&
      String(o.status || '') === 'active' &&
      (String(o.publicKey || '') === id || String(o.sponsorId || '') === id)
    );
  }

  private async requireOperatorAccount(req: Request, res: Response): Promise<any | null> {
    const account = await this.getAccountFromSession(req);
    if (!account) {
      res.status(401).json({ success: false, error: 'Invalid or expired session' });
      return null;
    }

    const state = await this.canonicalStateBuilder.buildState();
    const isOperator = String(account.role || '') === 'operator' || this.isAccountActiveOperator(state, String(account.accountId || ''));
    if (!isOperator) {
      res.status(403).json({ success: false, error: 'Operator role required' });
      return null;
    }

    return account;
  }

  private async requireMainNodeOperator(req: Request, res: Response): Promise<any | null> {
    const operatorAccount = await this.requireOperatorAccount(req, res);
    if (!operatorAccount) return null;
    const mainNodeAccountId = String(process.env.MAIN_NODE_ACCOUNT_ID || '').trim();
    if (!mainNodeAccountId) {
      res.status(500).json({ success: false, error: 'MAIN_NODE_ACCOUNT_ID is not configured on this node' });
      return null;
    }
    // IMPORTANT: MAIN_NODE_ACCOUNT_ID identifies the *main node* (operator public key), not necessarily
    // a specific user account. We restrict privileged operator actions to requests served by the main node.
    if (!this.isMainNode()) {
      res.status(403).json({ success: false, error: 'Main node operator required' });
      return null;
    }
    return operatorAccount;
  }

  constructor(node: OperatorNode, port: number = 3000) {
    this.app = express();
    this.node = node;
    this.port = port;
    
    this.network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
    this.walletAPI = new WalletAPI(this.network);
    
    // Initialize payment service
    const dataDir = process.env.OPERATOR_DATA_DIR || './operator-data';
    this.paymentService = new PaymentService(dataDir, this.network as 'mainnet' | 'testnet');
    this.paymentService.start();
    
    const operatorId = process.env.OPERATOR_ID || 'operator-1';
    const quorumM = parseInt(process.env.QUORUM_M || '3');
    const quorumN = parseInt(process.env.QUORUM_N || '5');
    const peerOperators = process.env.PEER_OPERATORS?.split(',') || [];

    this.canonicalEventStore = new CanonicalEventStore(dataDir);
    this.canonicalStateBuilder = new StateBuilder(this.canonicalEventStore);
    
    this.itemRegistry = new ItemRegistry(
      operatorId,
      node.getOperatorInfo().publicKey,
      quorumM,
      quorumN,
      peerOperators,
      this.canonicalEventStore
    );
    this.registryAPI = new RegistryAPI(this.itemRegistry, this.canonicalStateBuilder);
    
    // Initialize P2P network components
    const gatewayEndpoint = process.env.GATEWAY_ENDPOINT || 'localhost:8333';
    const chainId = process.env.CHAIN_ID || 'bitcoin-mainnet';
    
    this.joinAPI = new JoinAPI(
      gatewayEndpoint,
      node.getOperatorInfo().publicKey,
      chainId,
      'Bitcoin Ownership Protocol'
    );
    
    this.bootstrap = new NetworkBootstrap(
      chainId,
      peerOperators,
      node.getOperatorInfo().publicKey
    );
    
    this.setupMiddleware();
    this.setupAdminRoutes();
    this.setupRoutes();

    this.startOperatorHeartbeat();
    this.initializeConsensus();
  }

  /**
   * Initialize the decentralized consensus system
   */
  private async initializeConsensus(): Promise<void> {
    try {
      const state = await this.canonicalStateBuilder.buildState();
      
      // Create state provider adapter
      this.stateProviderAdapter = new StateProviderAdapter({
        accounts: state.accounts,
        items: state.items,
        operators: state.operators,
        settlements: state.settlements,
        consignments: (state as any).consignments || new Map(),
        offers: new Map(),
        operatorCandidates: new Map(),
      });

      const operatorId = process.env.OPERATOR_ID || 'main-operator';
      const privateKey = process.env.OPERATOR_PRIVATE_KEY || '';
      const publicKey = this.node.getOperatorInfo().publicKey;

      // Create consensus node
      this.consensusNode = new ConsensusNode(
        {
          nodeId: operatorId,
          isOperator: true,
          privateKey,
          publicKey,
          checkpointInterval: 30000, // 30 seconds
        },
        this.stateProviderAdapter
      );

      // Set up consensus event handlers
      this.consensusNode.setHandlers({
        onEventAccepted: (event) => this.handleConsensusEventAccepted(event),
        onEventRejected: (event, reason) => this.handleConsensusEventRejected(event, reason),
        onCheckpointFinalized: (checkpoint) => this.handleCheckpointFinalized(checkpoint),
        onStateChanged: () => this.handleConsensusStateChanged(),
      });

      // Start consensus
      this.consensusNode.start();

      console.log(`[Consensus] Initialized for main node ${operatorId}`);
    } catch (e: any) {
      console.error('[Consensus] Failed to initialize:', e?.message);
    }
  }

  /**
   * Handle event accepted by consensus
   */
  private handleConsensusEventAccepted(event: MempoolEvent): void {
    console.log(`[Consensus] Event accepted: ${event.type} (${event.eventId})`);
    // Broadcast to all connected nodes
    this.broadcastConsensusMessage({
      type: 'mempool_event',
      payload: event,
      senderId: process.env.OPERATOR_ID || 'main-operator',
      timestamp: Date.now(),
      signature: '',
    });
    
    // Broadcast to mempool visualizer subscribers
    this.broadcastToConsensusSubscribers({
      type: 'mempool_event',
      payload: event,
    });
  }

  /**
   * Broadcast to clients subscribed to consensus updates (mempool visualizer)
   */
  private broadcastToConsensusSubscribers(message: any): void {
    const msgStr = JSON.stringify(message);
    for (const [ws, meta] of this.wsConnections) {
      if (ws.readyState === WebSocket.OPEN && (meta as any).subscribedToConsensus) {
        try {
          ws.send(msgStr);
        } catch {}
      }
    }
  }

  /**
   * Handle event rejected by consensus
   */
  private handleConsensusEventRejected(event: MempoolEvent, reason: string): void {
    console.log(`[Consensus] Event rejected: ${event.type} - ${reason}`);
  }

  /**
   * Handle checkpoint finalized
   */
  private async handleCheckpointFinalized(checkpoint: FinalizedCheckpoint): Promise<void> {
    console.log(`[Consensus] Checkpoint #${checkpoint.checkpointNumber} finalized with ${checkpoint.events.length} events`);
    
    // Apply checkpoint events to the canonical event store
    for (const mempoolEvent of checkpoint.events) {
      try {
        const signatures: QuorumSignature[] = [{
          operatorId: mempoolEvent.creatorId,
          publicKey: '',
          signature: mempoolEvent.creatorSignature,
        }];

        await this.canonicalEventStore.appendEvent(
          {
            type: mempoolEvent.type,
            timestamp: mempoolEvent.timestamp,
            ...mempoolEvent.payload,
          } as any,
          signatures
        );
      } catch (e: any) {
        if (!String(e?.message || '').includes('already exists')) {
          console.error(`[Consensus] Failed to apply event ${mempoolEvent.eventId}:`, e?.message);
        }
      }
    }

    // Broadcast checkpoint to all connected nodes
    this.broadcastConsensusMessage({
      type: 'checkpoint_finalized',
      payload: checkpoint,
      senderId: process.env.OPERATOR_ID || 'main-operator',
      timestamp: Date.now(),
      signature: '',
    });

    // Broadcast to mempool visualizer subscribers
    this.broadcastToConsensusSubscribers({
      type: 'checkpoint_finalized',
      payload: checkpoint,
    });

    // Broadcast registry update
    this.broadcastToGateways({
      type: 'registry_update',
      data: {
        sequenceNumber: this.canonicalEventStore.getState().sequenceNumber,
        lastEventHash: this.canonicalEventStore.getState().headHash,
      },
      timestamp: Date.now(),
    });
  }

  /**
   * Handle consensus state changed
   */
  private async handleConsensusStateChanged(): Promise<void> {
    try {
      const state = await this.canonicalStateBuilder.buildState();
      if (this.stateProviderAdapter) {
        this.stateProviderAdapter.updateState({
          accounts: state.accounts,
          items: state.items,
          operators: state.operators,
          settlements: state.settlements,
          consignments: (state as any).consignments || new Map(),
          offers: new Map(),
          operatorCandidates: new Map(),
        });
      }
    } catch {}
  }

  /**
   * Broadcast a consensus message to all connected nodes
   */
  private broadcastConsensusMessage(message: ConsensusMessage): void {
    const msgStr = JSON.stringify(message);
    for (const [ws, meta] of this.wsConnections) {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(msgStr);
        } catch {}
      }
    }
  }

  /**
   * Submit an event through the consensus system
   */
  async submitConsensusEvent(
    type: string,
    payload: Record<string, any>
  ): Promise<{ success: boolean; eventId?: string; error?: string }> {
    if (!this.consensusNode) {
      return { success: false, error: 'Consensus not initialized' };
    }

    const signature = createHash('sha256')
      .update(`${process.env.OPERATOR_PRIVATE_KEY || ''}:${type}:${Date.now()}`)
      .digest('hex');

    return this.consensusNode.submitEvent(type, payload, signature);
  }

  private startOperatorHeartbeat(): void {
    try {
      if (this.operatorHeartbeatTimer) {
        clearInterval(this.operatorHeartbeatTimer);
      }
    } catch {}

    const tick = async () => {
      try {
        const opId = String(process.env.OPERATOR_ID || '').trim();
        if (!opId) return;

        const state = await this.canonicalStateBuilder.buildState();
        const op = (state as any).operators?.get?.(opId);
        if (!op || String(op.status || '') !== 'active') return;

        const now = Date.now();
        const last = Number(op.lastHeartbeatAt || op.lastActiveAt || 0);
        const HEARTBEAT_PERIOD_MS = 24 * 60 * 60 * 1000;
        if (last && (now - last) < HEARTBEAT_PERIOD_MS) return;

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`OPERATOR_HEARTBEAT:${opId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.OPERATOR_HEARTBEAT,
            timestamp: now,
            nonce,
            operatorId: opId,
          } as any,
          signatures
        );
      } catch (e: any) {
        console.error('[Operator] Heartbeat failed:', e?.message || String(e));
      }
    };

    void tick();
    this.operatorHeartbeatTimer = setInterval(() => void tick(), 60 * 60 * 1000);
  }

  private setupMiddleware(): void {
    this.app.use(express.json({ limit: '2mb' }));
    
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      
      if (req.method === 'OPTIONS') {
        res.sendStatus(200);
      } else {
        next();
      }
    });

    this.app.use((req, res, next) => {
      const path = String(req.path || '');
      // /api/network/operators is NOT guarded - operators need it for peer discovery
      const guarded = path.startsWith('/api/chain/') || path.startsWith('/api/anchors/');
      if (!guarded) {
        next();
        return;
      }

      const method = String(req.method || 'GET').toUpperCase();
      const pathOnly = String(req.path || '/');
      const expectedResource = `${method}:${pathOnly}`;

      const challengeId = String(req.headers['x-autho-pow-challenge'] || '').trim();
      const nonce = String(req.headers['x-autho-pow-nonce'] || '').trim();
      const resource = String(req.headers['x-autho-pow-resource'] || '').trim();
      const entry = this.powChallenges.get(challengeId);

      if (!entry || Date.now() > entry.expiresAt || resource !== entry.resource || resource !== expectedResource || !nonce) {
        res.status(402).json({
          success: false,
          error: 'pow_required',
          challengeEndpoint: '/api/pow/challenge',
        });
        return;
      }

      const digestHex = createHash('sha256')
        .update(`${entry.salt}:${resource}:${nonce}`)
        .digest('hex');

      const leadingNibbles = Math.floor(entry.difficulty / 4);
      const ok = digestHex.startsWith('0'.repeat(leadingNibbles));
      if (!ok) {
        res.status(402).json({
          success: false,
          error: 'pow_invalid',
          difficulty: entry.difficulty,
          challengeEndpoint: '/api/pow/challenge',
        });
        return;
      }

      this.powChallenges.delete(challengeId);

      next();
    });

    this.app.get('/api/retailers/:accountId/reputation/ratings', async (req: Request, res: Response) => {
      try {
        const targetAccountId = String(req.params.accountId || '').trim();
        if (!targetAccountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }

        const limitRaw = Number(req.query.limit || 50);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(200, Math.floor(limitRaw)) : 50;
        const cursorRaw = String(req.query.cursor || '').trim();
        const cursorParts = cursorRaw ? cursorRaw.split('|') : [];
        const cursorTs = cursorParts.length >= 1 ? Number(cursorParts[0] || 0) : 0;
        const cursorKey = cursorParts.length >= 2 ? String(cursorParts.slice(1).join('|') || '') : '';

        const viewer = await this.getAccountFromSession(req);
        const viewerId = viewer ? String((viewer as any).accountId || '').trim() : '';
        const viewerRole = viewer ? String((viewer as any).role || '').trim() : '';
        const canViewPrivate = Boolean(viewer && (viewerRole === 'operator' || viewerId === targetAccountId));

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(targetAccountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const all = Array.from((state as any).retailerRatings?.values?.() || []) as any[];
        const items = all.filter((x: any) => x && String(x.targetAccountId || '') === targetAccountId);
        items.sort((a: any, b: any) => {
          const ta = Number(a?.createdAt || 0);
          const tb = Number(b?.createdAt || 0);
          if (tb !== ta) return tb - ta;
          return String(b?.key || '').localeCompare(String(a?.key || ''));
        });

        const filtered = cursorTs
          ? items.filter((x: any) => {
              const ts = Number(x?.createdAt || 0);
              const k = String(x?.key || '');
              if (ts < cursorTs) return true;
              if (ts > cursorTs) return false;
              return k < cursorKey;
            })
          : items;

        const page = filtered.slice(0, limit);
        const entries = page.map((r: any) => {
          const ctxId = String(r?.contextId || '');
          return {
            key: String(r?.key || ''),
            createdAt: Number(r?.createdAt || 0),
            targetAccountId,
            raterAccountId: canViewPrivate ? String(r?.raterAccountId || '') : undefined,
            contextType: String(r?.contextType || ''),
            contextId: canViewPrivate ? ctxId : undefined,
            contextIdHint: !canViewPrivate && ctxId ? `${ctxId.substring(0, 10)}...` : undefined,
            rating: Number(r?.rating || 0),
          };
        });

        const last = page.length ? page[page.length - 1] : null;
        const nextCursor = last ? `${Number(last.createdAt || 0)}|${String(last.key || '')}` : undefined;
        const hasMore = filtered.length > page.length;

        res.json({ success: true, targetAccountId, canViewPrivate, entries, nextCursor, hasMore });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/retailers/:accountId/reputation/reports', async (req: Request, res: Response) => {
      try {
        const targetAccountId = String(req.params.accountId || '').trim();
        if (!targetAccountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }

        const limitRaw = Number(req.query.limit || 50);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(200, Math.floor(limitRaw)) : 50;
        const cursorRaw = String(req.query.cursor || '').trim();
        const cursorParts = cursorRaw ? cursorRaw.split('|') : [];
        const cursorTs = cursorParts.length >= 1 ? Number(cursorParts[0] || 0) : 0;
        const cursorKey = cursorParts.length >= 2 ? String(cursorParts.slice(1).join('|') || '') : '';

        const viewer = await this.getAccountFromSession(req);
        const viewerId = viewer ? String((viewer as any).accountId || '').trim() : '';
        const viewerRole = viewer ? String((viewer as any).role || '').trim() : '';
        const canViewPrivate = Boolean(viewer && (viewerRole === 'operator' || viewerId === targetAccountId));

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(targetAccountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const all = Array.from((state as any).retailerReports?.values?.() || []) as any[];
        const items = all.filter((x: any) => x && String(x.targetAccountId || '') === targetAccountId);
        items.sort((a: any, b: any) => {
          const ta = Number(a?.createdAt || 0);
          const tb = Number(b?.createdAt || 0);
          if (tb !== ta) return tb - ta;
          return String(b?.key || '').localeCompare(String(a?.key || ''));
        });

        const filtered = cursorTs
          ? items.filter((x: any) => {
              const ts = Number(x?.createdAt || 0);
              const k = String(x?.key || '');
              if (ts < cursorTs) return true;
              if (ts > cursorTs) return false;
              return k < cursorKey;
            })
          : items;

        const page = filtered.slice(0, limit);
        const entries = page.map((r: any) => {
          const ctxId = String(r?.contextId || '');
          const details = r?.details ? String(r.details) : '';
          return {
            key: String(r?.key || ''),
            createdAt: Number(r?.createdAt || 0),
            targetAccountId,
            reporterAccountId: canViewPrivate ? String(r?.reporterAccountId || '') : undefined,
            contextType: String(r?.contextType || ''),
            contextId: canViewPrivate ? ctxId : undefined,
            contextIdHint: !canViewPrivate && ctxId ? `${ctxId.substring(0, 10)}...` : undefined,
            reasonCode: r?.reasonCode ? String(r.reasonCode) : undefined,
            details: canViewPrivate ? (details || undefined) : (details ? `${details.substring(0, 24)}...` : undefined),
          };
        });

        const last = page.length ? page[page.length - 1] : null;
        const nextCursor = last ? `${Number(last.createdAt || 0)}|${String(last.key || '')}` : undefined;
        const hasMore = filtered.length > page.length;

        res.json({ success: true, targetAccountId, canViewPrivate, entries, nextCursor, hasMore });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/:accountId/rate', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const targetAccountId = String(req.params.accountId || '').trim();
        const contextType = String(req.body?.contextType || '').trim();
        const contextId = String(req.body?.contextId || '').trim();
        const rating = Number(req.body?.rating || 0);
        if (!targetAccountId || !contextId || !(rating >= 1 && rating <= 5)) {
          res.status(400).json({ success: false, error: 'Invalid targetAccountId, contextId, or rating (1..5)' });
          return;
        }
        if (contextType !== 'retailer_profile' && contextType !== 'consignment') {
          res.status(400).json({ success: false, error: 'Invalid contextType' });
          return;
        }

        const raterAccountId = String((account as any).accountId || '').trim();
        if (raterAccountId && raterAccountId === targetAccountId) {
          res.status(400).json({ success: false, error: 'Cannot rate self' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(targetAccountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Target account not found' });
          return;
        }
        if (String(target.role || '') !== 'retailer') {
          res.status(400).json({ success: false, error: 'Target is not a retailer' });
          return;
        }

        let eligible = false;
        if (contextType === 'retailer_profile') {
          eligible = true;
        }
        if (contextType === 'consignment') {
          const c: any = (state as any).consignments?.get?.(contextId);
          if (c && String(c.retailerAccountId || '') === targetAccountId) eligible = true;
        }
        if (!eligible) {
          res.status(403).json({ success: false, error: 'Not eligible to rate for this context' });
          return;
        }

        const now = Date.now();
        const limits = this.getRetailerReputationLimits();
        const usage = this.computeRetailerReputationUsage({
          state,
          now,
          raterAccountId,
          targetAccountId,
        });

        if (limits.maxRatingsPerWindow > 0 && usage.ratingsInWindow >= limits.maxRatingsPerWindow) {
          res.status(429).json({ success: false, error: 'Rating rate limit exceeded', limits, usage });
          return;
        }
        if (limits.maxContextsPerRetailer > 0 && usage.distinctContextsForTarget >= limits.maxContextsPerRetailer) {
          const ctxKey = `${contextType}\u0000${contextId}`;
          const alreadyUsed = [
            ...Array.from((state as any).retailerRatings?.values?.() || [])
              .filter((x: any) => x && String(x.raterAccountId || '') === raterAccountId && String(x.targetAccountId || '') === targetAccountId)
              .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
            ...Array.from((state as any).retailerReports?.values?.() || [])
              .filter((x: any) => x && String(x.reporterAccountId || '') === raterAccountId && String(x.targetAccountId || '') === targetAccountId)
              .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
          ].includes(ctxKey);
          if (!alreadyUsed) {
            res.status(429).json({ success: false, error: 'Per-retailer context limit exceeded', limits, usage });
            return;
          }
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RETAILER_RATED:${targetAccountId}:${raterAccountId}:${contextType}:${contextId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_RATED,
            timestamp: now,
            nonce,
            targetAccountId,
            raterAccountId,
            contextType,
            contextId,
            rating,
          } as any,
          signatures
        );

        res.json({ success: true, targetAccountId, contextType, contextId, rating });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/:accountId/report', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const targetAccountId = String(req.params.accountId || '').trim();
        const contextType = String(req.body?.contextType || '').trim();
        const contextId = String(req.body?.contextId || '').trim();
        const reasonCode = req.body?.reasonCode ? String(req.body.reasonCode).trim() : undefined;
        const details = req.body?.details ? String(req.body.details).trim() : undefined;
        if (!targetAccountId || !contextId) {
          res.status(400).json({ success: false, error: 'Invalid targetAccountId or contextId' });
          return;
        }
        if (contextType !== 'retailer_profile' && contextType !== 'consignment') {
          res.status(400).json({ success: false, error: 'Invalid contextType' });
          return;
        }

        const reporterAccountId = String((account as any).accountId || '').trim();
        if (reporterAccountId && reporterAccountId === targetAccountId) {
          res.status(400).json({ success: false, error: 'Cannot report self' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(targetAccountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Target account not found' });
          return;
        }
        if (String(target.role || '') !== 'retailer') {
          res.status(400).json({ success: false, error: 'Target is not a retailer' });
          return;
        }

        let eligible = false;
        if (contextType === 'retailer_profile') {
          eligible = true;
        }
        if (contextType === 'consignment') {
          const c: any = (state as any).consignments?.get?.(contextId);
          if (c && String(c.retailerAccountId || '') === targetAccountId) eligible = true;
        }
        if (!eligible) {
          res.status(403).json({ success: false, error: 'Not eligible to report for this context' });
          return;
        }

        const now = Date.now();
        const limits = this.getRetailerReputationLimits();
        const usage = this.computeRetailerReputationUsage({
          state,
          now,
          raterAccountId: reporterAccountId,
          targetAccountId,
        });

        if (limits.maxReportsPerWindow > 0 && usage.reportsInWindow >= limits.maxReportsPerWindow) {
          res.status(429).json({ success: false, error: 'Report rate limit exceeded', limits, usage });
          return;
        }
        if (limits.maxContextsPerRetailer > 0 && usage.distinctContextsForTarget >= limits.maxContextsPerRetailer) {
          const ctxKey = `${contextType}\u0000${contextId}`;
          const alreadyUsed = [
            ...Array.from((state as any).retailerRatings?.values?.() || [])
              .filter((x: any) => x && String(x.raterAccountId || '') === reporterAccountId && String(x.targetAccountId || '') === targetAccountId)
              .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
            ...Array.from((state as any).retailerReports?.values?.() || [])
              .filter((x: any) => x && String(x.reporterAccountId || '') === reporterAccountId && String(x.targetAccountId || '') === targetAccountId)
              .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
          ].includes(ctxKey);
          if (!alreadyUsed) {
            res.status(429).json({ success: false, error: 'Per-retailer context limit exceeded', limits, usage });
            return;
          }
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RETAILER_REPORTED:${targetAccountId}:${reporterAccountId}:${contextType}:${contextId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_REPORTED,
            timestamp: now,
            nonce,
            targetAccountId,
            reporterAccountId,
            contextType,
            contextId,
            reasonCode,
            details,
          } as any,
          signatures
        );

        res.json({ success: true, targetAccountId, contextType, contextId });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/consignments/create', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const ownerAccountId = String((account as any).accountId || '').trim();
        const ownerWallet = String((account as any).walletAddress || '').trim();
        if (!ownerAccountId || !ownerWallet) {
          res.status(400).json({ success: false, error: 'Account missing wallet/accountId' });
          return;
        }

        const { itemId, retailerAccountId, sellerMinNetSats, askingPriceSats, retailerMarkupShareBps, expiresInMs } = req.body || {};
        const itId = String(itemId || '').trim();
        const rId = String(retailerAccountId || '').trim();
        const sellerMin = Math.floor(Number(sellerMinNetSats || 0));
        const asking = Math.floor(Number(askingPriceSats || 0));
        const shareBps = retailerMarkupShareBps === undefined ? 2500 : Math.floor(Number(retailerMarkupShareBps || 0));
        const expMs = Number.isFinite(Number(expiresInMs)) && Number(expiresInMs) > 0 ? Math.floor(Number(expiresInMs)) : 30 * 24 * 60 * 60 * 1000;
        if (!itId || !rId || !(sellerMin > 0) || !(asking > 0)) {
          res.status(400).json({ success: false, error: 'Missing or invalid itemId, retailerAccountId, sellerMinNetSats, or askingPriceSats' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const item: any = state.items.get(itId);
        if (!item) {
          res.status(404).json({ success: false, error: 'Item not found' });
          return;
        }
        if (String(item.currentOwner || '').trim() !== ownerWallet) {
          res.status(403).json({ success: false, error: 'Only the current owner can create a consignment' });
          return;
        }

        const retailer: any = state.accounts.get(rId);
        if (!retailer) {
          res.status(404).json({ success: false, error: 'Retailer account not found' });
          return;
        }
        if (String(retailer.role || '') !== 'retailer') {
          res.status(400).json({ success: false, error: 'Target account is not a retailer' });
          return;
        }
        if (!this.enforceFreshRetailerBondOrRespond(res, retailer)) return;

        const now = Date.now();
        const existing = Array.from((state as any).consignments?.values?.() || []).find((c: any) => {
          if (!c) return false;
          if (String(c.itemId || '') !== itId) return false;
          return String(c.status || '') === 'active' || String(c.status || '') === 'pending';
        });
        if (existing) {
          res.status(400).json({ success: false, error: 'Item already has an active/pending consignment' });
          return;
        }

        const payouts = this.computeConsignmentPayouts({
          askingPriceSats: asking,
          sellerMinNetSats: sellerMin,
          retailerMarkupShareBps: shareBps,
        });
        if (payouts.markupSats < 0) {
          res.status(400).json({
            success: false,
            error: 'askingPriceSats is below seller minimum net + platform fee',
            askingPriceSats: asking,
            sellerMinNetSats: sellerMin,
            platformFeeSats: payouts.platformFeeSats,
          });
          return;
        }
        if (payouts.sellerPayoutSats < sellerMin) {
          res.status(400).json({
            success: false,
            error: 'Seller payout would fall below sellerMinNetSats',
            sellerPayoutSats: payouts.sellerPayoutSats,
            sellerMinNetSats: sellerMin,
          });
          return;
        }

        const consignmentId = `cons_${Date.now()}_${randomBytes(8).toString('hex')}`;
        const nonce1 = randomBytes(32).toString('hex');
        const nonce2 = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`CONSIGNMENT_CREATED:${consignmentId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.CONSIGNMENT_CREATED,
            timestamp: now,
            nonce: nonce1,
            consignmentId,
            itemId: itId,
            ownerAccountId,
            ownerWallet,
            retailerAccountId: rId,
            retailerWallet: String(retailer.walletAddress || '').trim(),
            sellerMinNetSats: sellerMin,
            askingPriceSats: asking,
            retailerMarkupShareBps: shareBps,
            platformFeeSats: payouts.platformFeeSats,
            retailerCommissionSats: payouts.retailerCommissionSats,
            sellerPayoutSats: payouts.sellerPayoutSats,
            expiresAt: now + expMs,
            createdByAccountId: ownerAccountId,
          } as any,
          signatures
        );

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.CONSIGNMENT_OWNER_CONFIRMED,
            timestamp: now,
            nonce: nonce2,
            consignmentId,
            confirmedByAccountId: ownerAccountId,
          } as any,
          signatures
        );

        res.json({
          success: true,
          consignmentId,
          status: 'pending',
          sellerMinNetSats: sellerMin,
          askingPriceSats: asking,
          platformFeeSats: payouts.platformFeeSats,
          retailerCommissionSats: payouts.retailerCommissionSats,
          sellerPayoutSats: payouts.sellerPayoutSats,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/consignments/retailer/me', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        if (String((account as any).role || '') !== 'retailer') {
          res.status(403).json({ success: false, error: 'Retailer role required' });
          return;
        }

        const retailerAccountId = String((account as any).accountId || '').trim();
        if (!retailerAccountId) {
          res.status(401).json({ success: false, error: 'Invalid session' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const statusFilter = String(req.query.status || '').trim().toLowerCase();

        const consignments = (Array.from((state as any).consignments?.values?.() || []) as any[])
          .filter((c: any) => c && String(c.retailerAccountId || '') === retailerAccountId)
          .filter((c: any) => {
            if (!statusFilter) return true;
            return String(c.status || '').toLowerCase() === statusFilter;
          })
          .map((c: any) => ({
            consignmentId: String(c.consignmentId || ''),
            itemId: String(c.itemId || ''),
            status: String(c.status || ''),
            expiresAt: Number(c.expiresAt || 0),
            createdAt: Number(c.createdAt || 0),
            updatedAt: Number(c.updatedAt || 0),
            ownerAccountId: String(c.ownerAccountId || ''),
            ownerWallet: c.ownerWallet ? String(c.ownerWallet) : undefined,
            retailerAccountId: String(c.retailerAccountId || ''),
            retailerWallet: c.retailerWallet ? String(c.retailerWallet) : undefined,
            sellerMinNetSats: Number(c.sellerMinNetSats || 0),
            askingPriceSats: Number(c.askingPriceSats || 0),
            retailerMarkupShareBps: Number(c.retailerMarkupShareBps || 0),
            platformFeeSats: Number(c.platformFeeSats || 0),
            retailerCommissionSats: Number(c.retailerCommissionSats || 0),
            sellerPayoutSats: Number(c.sellerPayoutSats || 0),
            checkoutLock: c.checkoutLock
              ? { lockedByAccountId: String(c.checkoutLock.lockedByAccountId || ''), lockedUntil: Number(c.checkoutLock.lockedUntil || 0) }
              : null,
            buyerAccountId: c.buyerAccountId ? String(c.buyerAccountId) : undefined,
            buyerWallet: c.buyerWallet ? String(c.buyerWallet) : undefined,
            txid: c.txid ? String(c.txid) : undefined,
            cancelRequested: c.cancelRequested
              ? {
                  requestedByAccountId: String(c.cancelRequested.requestedByAccountId || ''),
                  requestedAt: Number(c.cancelRequested.requestedAt || 0),
                }
              : null,
            cancelConfirmed: c.cancelConfirmed
              ? {
                  confirmedByAccountId: String(c.cancelConfirmed.confirmedByAccountId || ''),
                  confirmedAt: Number(c.cancelConfirmed.confirmedAt || 0),
                }
              : null,
          }))
          .sort((a: any, b: any) => {
            const ta = Number(a.updatedAt || a.createdAt || 0);
            const tb = Number(b.updatedAt || b.createdAt || 0);
            return tb - ta;
          });

        res.json({ success: true, retailerAccountId, count: consignments.length, consignments });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/consignments/:consignmentId/retailer/confirm', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const consignmentId = String(req.params.consignmentId || '').trim();
        if (!consignmentId) {
          res.status(400).json({ success: false, error: 'Missing consignmentId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const c: any = (state as any).consignments?.get?.(consignmentId);
        if (!c) {
          res.status(404).json({ success: false, error: 'Consignment not found' });
          return;
        }
        if (String(c.status || '') !== 'pending' && String(c.status || '') !== 'active') {
          res.status(400).json({ success: false, error: 'Consignment is closed' });
          return;
        }

        const retailerAccountId = String((account as any).accountId || '').trim();
        if (!retailerAccountId || retailerAccountId !== String(c.retailerAccountId || '')) {
          res.status(403).json({ success: false, error: 'Only the assigned retailer can confirm this consignment' });
          return;
        }

        const retailer: any = state.accounts.get(retailerAccountId);
        if (!retailer) {
          res.status(404).json({ success: false, error: 'Retailer account not found' });
          return;
        }
        if (!this.enforceFreshRetailerBondOrRespond(res, retailer)) return;

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`CONSIGNMENT_RETAILER_CONFIRMED:${consignmentId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.CONSIGNMENT_RETAILER_CONFIRMED,
            timestamp: now,
            nonce,
            consignmentId,
            confirmedByAccountId: retailerAccountId,
          } as any,
          signatures
        );

        res.json({ success: true, consignmentId, status: 'active' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/consignments/:consignmentId/price', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const consignmentId = String(req.params.consignmentId || '').trim();
        const askingPriceSats = Math.floor(Number(req.body?.askingPriceSats || 0));
        if (!consignmentId || !(askingPriceSats > 0)) {
          res.status(400).json({ success: false, error: 'Missing consignmentId or invalid askingPriceSats' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const c: any = (state as any).consignments?.get?.(consignmentId);
        if (!c) {
          res.status(404).json({ success: false, error: 'Consignment not found' });
          return;
        }
        if (String(c.status || '') !== 'active') {
          res.status(400).json({ success: false, error: 'Consignment is not active' });
          return;
        }
        const now = Date.now();
        if (c.expiresAt && Number(c.expiresAt || 0) > 0 && now > Number(c.expiresAt || 0)) {
          res.status(400).json({ success: false, error: 'Consignment is expired' });
          return;
        }
        const lockUntil = Number(c.checkoutLock?.lockedUntil || 0);
        if (lockUntil && lockUntil > now) {
          res.status(400).json({ success: false, error: 'Checkout is locked' });
          return;
        }

        const retailerAccountId = String((account as any).accountId || '').trim();
        if (!retailerAccountId || retailerAccountId !== String(c.retailerAccountId || '')) {
          res.status(403).json({ success: false, error: 'Only the assigned retailer can update price' });
          return;
        }

        const retailer: any = state.accounts.get(retailerAccountId);
        if (!retailer) {
          res.status(404).json({ success: false, error: 'Retailer account not found' });
          return;
        }
        if (!this.enforceFreshRetailerBondOrRespond(res, retailer)) return;

        const payouts = this.computeConsignmentPayouts({
          askingPriceSats,
          sellerMinNetSats: Number(c.sellerMinNetSats || 0),
          retailerMarkupShareBps: Number(c.retailerMarkupShareBps || 0),
        });
        if (payouts.markupSats < 0) {
          res.status(400).json({
            success: false,
            error: 'askingPriceSats is below seller minimum net + platform fee',
            askingPriceSats,
            sellerMinNetSats: Number(c.sellerMinNetSats || 0),
            platformFeeSats: payouts.platformFeeSats,
          });
          return;
        }
        if (payouts.sellerPayoutSats < Number(c.sellerMinNetSats || 0)) {
          res.status(400).json({
            success: false,
            error: 'Seller payout would fall below sellerMinNetSats',
            sellerPayoutSats: payouts.sellerPayoutSats,
            sellerMinNetSats: Number(c.sellerMinNetSats || 0),
          });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`CONSIGNMENT_PRICE_UPDATED:${consignmentId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.CONSIGNMENT_PRICE_UPDATED,
            timestamp: now,
            nonce,
            consignmentId,
            askingPriceSats,
            platformFeeSats: payouts.platformFeeSats,
            retailerCommissionSats: payouts.retailerCommissionSats,
            sellerPayoutSats: payouts.sellerPayoutSats,
            updatedByAccountId: retailerAccountId,
          } as any,
          signatures
        );

        res.json({
          success: true,
          consignmentId,
          askingPriceSats,
          platformFeeSats: payouts.platformFeeSats,
          retailerCommissionSats: payouts.retailerCommissionSats,
          sellerPayoutSats: payouts.sellerPayoutSats,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/consignments/:consignmentId/checkout/lock', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const consignmentId = String(req.params.consignmentId || '').trim();
        if (!consignmentId) {
          res.status(400).json({ success: false, error: 'Missing consignmentId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const c: any = (state as any).consignments?.get?.(consignmentId);
        if (!c) {
          res.status(404).json({ success: false, error: 'Consignment not found' });
          return;
        }
        if (String(c.status || '') !== 'active') {
          res.status(400).json({ success: false, error: 'Consignment is not active' });
          return;
        }

        const now = Date.now();
        if (c.expiresAt && Number(c.expiresAt || 0) > 0 && now > Number(c.expiresAt || 0)) {
          res.status(400).json({ success: false, error: 'Consignment is expired' });
          return;
        }

        if (String(c.txid || '').trim()) {
          res.status(400).json({ success: false, error: 'Payment already submitted' });
          return;
        }

        const lockUntil = Number(c.checkoutLock?.lockedUntil || 0);
        const lockGraceMs = Number(process.env.CONSIGNMENT_CHECKOUT_LOCK_GRACE_MS || 0) || 2 * 60 * 1000;
        if (lockUntil && (lockUntil > now || lockUntil + lockGraceMs > now)) {
          res.status(400).json({ success: false, error: 'Checkout already locked' });
          return;
        }

        const lockMs = Number(process.env.CONSIGNMENT_CHECKOUT_LOCK_MS || 0) || 15 * 60 * 1000;
        const lockedUntil = now + lockMs;

        const platformFeeSats = Math.floor(Number(c.platformFeeSats || 0));
        const feeSnap = this.computePlatformFeePayoutSnapshot({ state, platformFeeSats });

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`CONSIGNMENT_CHECKOUT_LOCKED:${consignmentId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.CONSIGNMENT_CHECKOUT_LOCKED,
            timestamp: now,
            nonce,
            consignmentId,
            lockedByAccountId: String((account as any).accountId || ''),
            lockedUntil,
            platformFeePayouts: feeSnap,
          } as any,
          signatures
        );

        res.json({ success: true, consignmentId, lockedUntil });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/consignments/:consignmentId', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const consignmentId = String(req.params.consignmentId || '').trim();
        if (!consignmentId) {
          res.status(400).json({ success: false, error: 'Missing consignmentId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const c: any = (state as any).consignments?.get?.(consignmentId);
        if (!c) {
          res.status(404).json({ success: false, error: 'Consignment not found' });
          return;
        }

        const accountId = String((account as any).accountId || '').trim();
        const ownerAccountId = String(c.ownerAccountId || '').trim();
        const retailerAccountId = String(c.retailerAccountId || '').trim();
        const buyerAccountId = String(c.buyerAccountId || '').trim();
        if (accountId && accountId !== ownerAccountId && accountId !== retailerAccountId && accountId !== buyerAccountId) {
          res.status(403).json({ success: false, error: 'Not authorized to view this consignment' });
          return;
        }

        res.json({
          success: true,
          consignment: {
            consignmentId: String(c.consignmentId || consignmentId),
            itemId: String(c.itemId || ''),
            status: String(c.status || ''),
            expiresAt: Number(c.expiresAt || 0),
            createdAt: Number(c.createdAt || 0),
            updatedAt: Number(c.updatedAt || 0),
            ownerAccountId,
            retailerAccountId,
            ownerWallet: c.ownerWallet ? String(c.ownerWallet) : undefined,
            retailerWallet: c.retailerWallet ? String(c.retailerWallet) : undefined,
            askingPriceSats: Number(c.askingPriceSats || 0),
            platformFeeSats: Number(c.platformFeeSats || 0),
            retailerCommissionSats: Number(c.retailerCommissionSats || 0),
            sellerPayoutSats: Number(c.sellerPayoutSats || 0),
            checkoutLock: c.checkoutLock ? { lockedByAccountId: String(c.checkoutLock.lockedByAccountId || ''), lockedUntil: Number(c.checkoutLock.lockedUntil || 0) } : null,
            txid: c.txid ? String(c.txid) : undefined,
            buyerAccountId: c.buyerAccountId ? String(c.buyerAccountId) : undefined,
            buyerWallet: c.buyerWallet ? String(c.buyerWallet) : undefined,
            cancelRequested: c.cancelRequested
              ? {
                  requestedByAccountId: String(c.cancelRequested.requestedByAccountId || ''),
                  requestedAt: Number(c.cancelRequested.requestedAt || 0),
                  reason: c.cancelRequested.reason ? String(c.cancelRequested.reason) : undefined,
                }
              : null,
            cancelConfirmed: c.cancelConfirmed
              ? {
                  confirmedByAccountId: String(c.cancelConfirmed.confirmedByAccountId || ''),
                  confirmedAt: Number(c.cancelConfirmed.confirmedAt || 0),
                  reason: c.cancelConfirmed.reason ? String(c.cancelConfirmed.reason) : undefined,
                }
              : null,
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/consignments/:consignmentId/checkout', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const consignmentId = String(req.params.consignmentId || '').trim();
        if (!consignmentId) {
          res.status(400).json({ success: false, error: 'Missing consignmentId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const c: any = (state as any).consignments?.get?.(consignmentId);
        if (!c) {
          res.status(404).json({ success: false, error: 'Consignment not found' });
          return;
        }

        const now = Date.now();
        if (String(c.status || '') !== 'active') {
          res.status(400).json({ success: false, error: 'Consignment is not active' });
          return;
        }
        if (c.expiresAt && Number(c.expiresAt || 0) > 0 && now > Number(c.expiresAt || 0)) {
          res.status(400).json({ success: false, error: 'Consignment is expired' });
          return;
        }

        const buyerAccountId = String((account as any).accountId || '').trim();
        const buyerWallet = String((account as any).walletAddress || '').trim();
        if (!buyerAccountId || !buyerWallet) {
          res.status(400).json({ success: false, error: 'Account missing wallet/accountId' });
          return;
        }

        const ownerWallet = String(c.ownerWallet || '').trim();
        const retailerWallet = String(c.retailerWallet || '').trim();
        if (!ownerWallet || !retailerWallet) {
          res.status(500).json({ success: false, error: 'Consignment missing payout wallets' });
          return;
        }

        const lockBy = String(c.checkoutLock?.lockedByAccountId || '').trim();
        const lockUntil = Number(c.checkoutLock?.lockedUntil || 0);
        const lockGraceMs = Number(process.env.CONSIGNMENT_CHECKOUT_LOCK_GRACE_MS || 0) || 2 * 60 * 1000;
        const lockActive = !!lockBy && !!lockUntil && (lockUntil > now || lockUntil + lockGraceMs > now);

        const askingPriceSats = Math.floor(Number(c.askingPriceSats || 0));
        const platformFeeSats = Math.floor(Number(c.platformFeeSats || 0));
        const retailerCommissionSats = Math.floor(Number(c.retailerCommissionSats || 0));
        const sellerPayoutSats = Math.floor(Number(c.sellerPayoutSats || 0));

        if (!(askingPriceSats > 0)) {
          res.status(400).json({ success: false, error: 'Invalid askingPriceSats' });
          return;
        }
        if (sellerPayoutSats < 0 || retailerCommissionSats < 0 || platformFeeSats < 0) {
          res.status(400).json({ success: false, error: 'Invalid payout amounts' });
          return;
        }

        const mainNodeAddress = String(this.getFeeAddress() || '').trim();
        if (!mainNodeAddress) {
          res.status(500).json({ success: false, error: 'FEE_ADDRESS_TESTNET not configured' });
          return;
        }

        const feeSnap: PlatformFeePayoutSnapshot = c.platformFeePayouts
          ? (c.platformFeePayouts as any)
          : { platformFeeSats, mainNodeAddress, mainNodeFeeSats: platformFeeSats, operatorPayouts: [] };

        const opReturnScriptHex = lockActive
          ? this.buildConsignmentPurchaseOpReturnScriptHex({
              consignmentId,
              buyerAccountId,
              askingPriceSats,
              sellerPayoutSats,
              retailerCommissionSats,
              platformFeeSats,
              ownerWallet,
              retailerWallet,
              lockedUntil: lockUntil,
            })
          : null;

        const feeOutputs = [
          { address: String(feeSnap.mainNodeAddress || mainNodeAddress).trim(), amountSats: Math.floor(Number(feeSnap.mainNodeFeeSats || 0)) },
          ...(Array.isArray(feeSnap.operatorPayouts) ? feeSnap.operatorPayouts : []).map((p: any) => ({
            address: String(p?.address || '').trim(),
            amountSats: Math.floor(Number(p?.amountSats || 0)),
          })),
        ];

        const paymentOutputs = [
          { address: ownerWallet, amountSats: sellerPayoutSats },
          { address: retailerWallet, amountSats: retailerCommissionSats },
          ...feeOutputs,
          ...(opReturnScriptHex ? [{ scriptHex: opReturnScriptHex, amountSats: 0 }] : []),
        ].filter((o: any) => {
          if (!o) return false;
          if (typeof o.scriptHex === 'string' && String(o.scriptHex || '').trim()) return true;
          if (String(o.address || '').trim() && Number(o.amountSats || 0) > 0) return true;
          return false;
        });

        res.json({
          success: true,
          consignment: {
            consignmentId,
            itemId: String(c.itemId || ''),
            ownerAccountId: String(c.ownerAccountId || ''),
            retailerAccountId: String(c.retailerAccountId || ''),
            askingPriceSats,
            ownerWallet,
            retailerWallet,
            platformFeeSats,
            retailerCommissionSats,
            sellerPayoutSats,
            expiresAt: Number(c.expiresAt || 0),
          },
          buyer: { buyerAccountId, buyerWallet },
          checkoutLock: lockActive ? { lockedByAccountId: lockBy, lockedUntil: lockUntil } : null,
          requiresLock: !lockActive,
          lockHeldByYou: lockActive && lockBy === buyerAccountId,
          paymentOutputs,
          totalSats: askingPriceSats,
          opReturnScriptHex,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/consignments/item/:itemId', async (req: Request, res: Response) => {
      try {
        const itemId = String(req.params.itemId || '').trim();
        if (!itemId) {
          res.status(400).json({ success: false, error: 'Missing itemId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const now = Date.now();
        const all = Array.from((state as any).consignments?.values?.() || []) as any[];
        const valid = all
          .filter((c: any) => c && String(c.itemId || '') === itemId)
          .filter((c: any) => {
            const exp = Number(c.expiresAt || 0);
            if (exp && exp > 0 && now > exp) return false;
            return true;
          });

        const active = valid.find((c: any) => String(c.status || '') === 'active');
        const pending = valid.find((c: any) => String(c.status || '') === 'pending');

        const chosen = active || pending;
        if (!chosen) {
          res.status(404).json({ success: false, error: 'No active or pending consignment found for item' });
          return;
        }

        // Public-safe summary used by the owner items UI. Avoid leaking wallets, buyer identity, txid, etc.
        res.json({
          success: true,
          consignment: {
            consignmentId: String(chosen.consignmentId || ''),
            itemId: String(chosen.itemId || ''),
            status: String(chosen.status || ''),
            expiresAt: Number(chosen.expiresAt || 0),
            createdAt: Number(chosen.createdAt || 0),
            updatedAt: Number(chosen.updatedAt || 0),
            retailerAccountId: String(chosen.retailerAccountId || ''),
            ownerAccountId: String(chosen.ownerAccountId || ''),
            askingPriceSats: Number(chosen.askingPriceSats || 0),
            sellerMinNetSats: Number(chosen.sellerMinNetSats || 0),
            retailerMarkupShareBps: Number(chosen.retailerMarkupShareBps || 0),
            platformFeeSats: Number(chosen.platformFeeSats || 0),
            retailerCommissionSats: Number(chosen.retailerCommissionSats || 0),
            sellerPayoutSats: Number(chosen.sellerPayoutSats || 0),
            checkoutLock: chosen.checkoutLock
              ? {
                  lockedUntil: Number(chosen.checkoutLock.lockedUntil || 0),
                }
              : null,
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/consignments/:consignmentId/payment-submitted', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const consignmentId = String(req.params.consignmentId || '').trim();
        const txid = String(req.body?.txid || '').trim().toLowerCase();
        if (!consignmentId || !/^[0-9a-f]{64}$/.test(txid)) {
          res.status(400).json({ success: false, error: 'Missing consignmentId or invalid txid' });
          return;
        }

        const buyerAccountId = String((account as any).accountId || '').trim();
        const buyerWallet = String((account as any).walletAddress || '').trim();
        if (!buyerAccountId || !buyerWallet) {
          res.status(400).json({ success: false, error: 'Account missing wallet/accountId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const c: any = (state as any).consignments?.get?.(consignmentId);
        if (!c) {
          res.status(404).json({ success: false, error: 'Consignment not found' });
          return;
        }

        const alreadyTx = String(c.txid || '').trim().toLowerCase();
        if (alreadyTx) {
          if (alreadyTx === txid) {
            res.json({ success: true, consignmentId, txid, alreadySubmitted: true });
            return;
          }
          res.status(400).json({ success: false, error: 'Payment already submitted' });
          return;
        }

        const now = Date.now();
        const status = String(c.status || '');
        if (status === 'completed' || status === 'cancelled') {
          res.status(400).json({ success: false, error: 'Consignment is closed' });
          return;
        }

        const lockBy = String(c.checkoutLock?.lockedByAccountId || '').trim();
        const lockUntil = Number(c.checkoutLock?.lockedUntil || 0);
        if (!lockBy || !lockUntil) {
          res.status(400).json({ success: false, error: 'Checkout lock not found' });
          return;
        }
        if (lockBy !== buyerAccountId) {
          res.status(403).json({ success: false, error: 'Checkout lock is held by another account' });
          return;
        }

        const ownerWallet = String(c.ownerWallet || '').trim();
        const retailerWallet = String(c.retailerWallet || '').trim();
        if (buyerWallet === ownerWallet || buyerWallet === retailerWallet) {
          res.status(400).json({ success: false, error: 'Buyer wallet cannot match owner/retailer wallet' });
          return;
        }

        // Verify tx shape before recording the submission (outputs + OP_RETURN).
        const apiBase = this.getBlockstreamApiBase();
        const txRes = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}`);
        if (!txRes.ok) {
          res.status(400).json({ success: false, error: 'Transaction not found on chain provider yet' });
          return;
        }
        const tx = await txRes.json().catch(() => ({}));
        const vout = Array.isArray((tx as any)?.vout) ? (tx as any).vout : [];

        const askingPriceSats = Number(c.askingPriceSats || 0);
        const platformFeeSats = Number(c.platformFeeSats || 0);
        const retailerCommissionSats = Number(c.retailerCommissionSats || 0);
        const sellerPayoutSats = Number(c.sellerPayoutSats || 0);

        const expectedOpReturnScriptHex = this.buildConsignmentPurchaseOpReturnScriptHex({
          consignmentId,
          buyerAccountId,
          askingPriceSats,
          sellerPayoutSats,
          retailerCommissionSats,
          platformFeeSats,
          ownerWallet: String(c.ownerWallet || ''),
          retailerWallet: String(c.retailerWallet || ''),
          lockedUntil: lockUntil,
        });
        const hasOpReturn = vout.some((o: any) => {
          const script = String(o?.scriptpubkey || '').trim().toLowerCase();
          return script && script === expectedOpReturnScriptHex;
        });
        if (!hasOpReturn) {
          res.status(400).json({ success: false, error: 'Transaction missing required consignment OP_RETURN' });
          return;
        }

        const ownerPaid = vout.reduce((sum: number, o: any) => {
          const addr = String(o?.scriptpubkey_address || '').trim();
          const val = Number(o?.value || 0);
          return addr === ownerWallet ? sum + val : sum;
        }, 0);
        const retailerPaid = vout.reduce((sum: number, o: any) => {
          const addr = String(o?.scriptpubkey_address || '').trim();
          const val = Number(o?.value || 0);
          return addr === retailerWallet ? sum + val : sum;
        }, 0);

        const mainNodeAddress = String(this.getFeeAddress() || '').trim();
        const feeSnap: PlatformFeePayoutSnapshot = c.platformFeePayouts
          ? (c.platformFeePayouts as any)
          : { platformFeeSats, mainNodeAddress, mainNodeFeeSats: platformFeeSats, operatorPayouts: [] };
        const feeMainAddr = String(feeSnap.mainNodeAddress || mainNodeAddress).trim();
        const feeMainExpected = Number(feeSnap.mainNodeFeeSats || 0);
        const feeOpExpected = Array.isArray(feeSnap.operatorPayouts) ? feeSnap.operatorPayouts : [];

        const feePaidMain = vout.reduce((sum: number, o: any) => {
          const addr = String(o?.scriptpubkey_address || '').trim();
          const val = Number(o?.value || 0);
          return addr === feeMainAddr ? sum + val : sum;
        }, 0);
        const feePaidOps: Record<string, number> = {};
        for (const p of feeOpExpected) {
          const addr = String(p?.address || '').trim();
          if (!addr) continue;
          feePaidOps[addr] = vout.reduce((sum: number, o: any) => {
            const a = String(o?.scriptpubkey_address || '').trim();
            const val = Number(o?.value || 0);
            return a === addr ? sum + val : sum;
          }, 0);
        }

        if (sellerPayoutSats > 0 && ownerPaid < sellerPayoutSats) {
          res.status(400).json({ success: false, error: 'Transaction does not pay owner payout' });
          return;
        }
        if (retailerCommissionSats > 0 && retailerPaid < retailerCommissionSats) {
          res.status(400).json({ success: false, error: 'Transaction does not pay retailer commission' });
          return;
        }
        if (platformFeeSats > 0 && feePaidMain < feeMainExpected) {
          res.status(400).json({ success: false, error: 'Transaction does not pay platform fee' });
          return;
        }

        for (const p of feeOpExpected) {
          const addr = String(p?.address || '').trim();
          const exp = Number(p?.amountSats || 0);
          if (!addr || !(exp > 0)) continue;
          const got = Number(feePaidOps[addr] || 0);
          if (got < exp) {
            res.status(400).json({ success: false, error: 'Transaction does not pay operator fee distribution' });
            return;
          }
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`CONSIGNMENT_PAYMENT_SUBMITTED:${consignmentId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.CONSIGNMENT_PAYMENT_SUBMITTED,
            timestamp: now,
            nonce,
            consignmentId,
            buyerAccountId,
            buyerWallet,
            txid,
          } as any,
          signatures
        );

        let reconciled = 0;
        try {
          // Try to settle immediately in case the tx already has confirmations.
          reconciled = await this.reconcilePaidConsignments();
        } catch {}

        res.json({ success: true, consignmentId, txid, reconciled, message: 'Payment submitted. Awaiting confirmation.' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/consignments/:consignmentId/cancel/request', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const consignmentId = String(req.params.consignmentId || '').trim();
        const reason = req.body?.reason ? String(req.body.reason) : undefined;
        if (!consignmentId) {
          res.status(400).json({ success: false, error: 'Missing consignmentId' });
          return;
        }

        const requesterAccountId = String((account as any).accountId || '').trim();
        if (!requesterAccountId) {
          res.status(401).json({ success: false, error: 'Invalid session' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const c: any = (state as any).consignments?.get?.(consignmentId);
        if (!c) {
          res.status(404).json({ success: false, error: 'Consignment not found' });
          return;
        }

        const status = String(c.status || '');
        if (status === 'completed' || status === 'cancelled' || status === 'expired') {
          res.status(400).json({ success: false, error: 'Consignment is closed' });
          return;
        }

        const now = Date.now();
        if (c.expiresAt && Number(c.expiresAt || 0) > 0 && now > Number(c.expiresAt || 0)) {
          res.status(400).json({ success: false, error: 'Consignment is expired' });
          return;
        }

        const ownerAccountId = String(c.ownerAccountId || '').trim();
        const retailerAccountId = String(c.retailerAccountId || '').trim();
        const isOwner = requesterAccountId === ownerAccountId;
        const isRetailer = requesterAccountId === retailerAccountId;
        if (!isOwner && !isRetailer) {
          res.status(403).json({ success: false, error: 'Only owner or assigned retailer may request cancellation' });
          return;
        }

        const txid = String(c.txid || '').trim();
        if (txid) {
          res.status(400).json({ success: false, error: 'Consignment payment already submitted; cannot cancel', code: 'PAYMENT_ALREADY_SUBMITTED' });
          return;
        }

        const existingReqBy = String(c.cancelRequested?.requestedByAccountId || '').trim();
        const existingReqAt = Number(c.cancelRequested?.requestedAt || 0);
        if (existingReqBy && existingReqAt) {
          res.json({ success: true, consignmentId, alreadyRequested: true, requestedByAccountId: existingReqBy, requestedAt: existingReqAt });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`CONSIGNMENT_CANCEL_REQUESTED:${consignmentId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.CONSIGNMENT_CANCEL_REQUESTED,
            timestamp: now,
            nonce,
            consignmentId,
            requestedByAccountId: requesterAccountId,
            reason,
          } as any,
          signatures
        );

        res.json({ success: true, consignmentId, requestedByAccountId: requesterAccountId });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/consignments/:consignmentId/cancel/confirm', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const consignmentId = String(req.params.consignmentId || '').trim();
        const reason = req.body?.reason ? String(req.body.reason) : undefined;
        if (!consignmentId) {
          res.status(400).json({ success: false, error: 'Missing consignmentId' });
          return;
        }

        const confirmerAccountId = String((account as any).accountId || '').trim();
        if (!confirmerAccountId) {
          res.status(401).json({ success: false, error: 'Invalid session' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const c: any = (state as any).consignments?.get?.(consignmentId);
        if (!c) {
          res.status(404).json({ success: false, error: 'Consignment not found' });
          return;
        }

        const status = String(c.status || '');
        if (status === 'completed' || status === 'cancelled' || status === 'expired') {
          res.status(400).json({ success: false, error: 'Consignment is closed' });
          return;
        }

        const now = Date.now();
        if (c.expiresAt && Number(c.expiresAt || 0) > 0 && now > Number(c.expiresAt || 0)) {
          res.status(400).json({ success: false, error: 'Consignment is expired' });
          return;
        }

        const ownerAccountId = String(c.ownerAccountId || '').trim();
        const retailerAccountId = String(c.retailerAccountId || '').trim();
        const isOwner = confirmerAccountId === ownerAccountId;
        const isRetailer = confirmerAccountId === retailerAccountId;
        if (!isOwner && !isRetailer) {
          res.status(403).json({ success: false, error: 'Only owner or assigned retailer may confirm cancellation' });
          return;
        }

        const txid = String(c.txid || '').trim();
        if (txid) {
          res.status(400).json({ success: false, error: 'Consignment payment already submitted; cannot cancel', code: 'PAYMENT_ALREADY_SUBMITTED' });
          return;
        }

        const requestedByAccountId = String(c.cancelRequested?.requestedByAccountId || '').trim();
        const requestedAt = Number(c.cancelRequested?.requestedAt || 0);
        if (!requestedByAccountId || !requestedAt) {
          res.status(400).json({ success: false, error: 'Cancellation has not been requested' });
          return;
        }

        if (requestedByAccountId === confirmerAccountId) {
          res.status(400).json({ success: false, error: 'Cancellation must be confirmed by the other party' });
          return;
        }

        const existingConfirmBy = String(c.cancelConfirmed?.confirmedByAccountId || '').trim();
        const existingConfirmAt = Number(c.cancelConfirmed?.confirmedAt || 0);
        if (existingConfirmBy && existingConfirmAt) {
          res.json({ success: true, consignmentId, alreadyConfirmed: true, confirmedByAccountId: existingConfirmBy, confirmedAt: existingConfirmAt });
          return;
        }

        // Ensure confirm is made by the counterparty.
        if (requestedByAccountId === ownerAccountId && !isRetailer) {
          res.status(403).json({ success: false, error: 'Retailer must confirm owner cancel request' });
          return;
        }
        if (requestedByAccountId === retailerAccountId && !isOwner) {
          res.status(403).json({ success: false, error: 'Owner must confirm retailer cancel request' });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`CONSIGNMENT_CANCEL_CONFIRMED:${consignmentId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.CONSIGNMENT_CANCEL_CONFIRMED,
            timestamp: now,
            nonce,
            consignmentId,
            confirmedByAccountId: confirmerAccountId,
            reason,
          } as any,
          signatures
        );

        res.json({ success: true, consignmentId, status: 'cancelled' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/verifiers/:accountId/reputation/ratings', async (req: Request, res: Response) => {
      try {
        const targetAccountId = String(req.params.accountId || '').trim();
        if (!targetAccountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }

        const limitRaw = Number(req.query.limit || 50);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(200, Math.floor(limitRaw)) : 50;
        const cursorRaw = String(req.query.cursor || '').trim();
        const cursorParts = cursorRaw ? cursorRaw.split('|') : [];
        const cursorTs = cursorParts.length >= 1 ? Number(cursorParts[0] || 0) : 0;
        const cursorKey = cursorParts.length >= 2 ? String(cursorParts.slice(1).join('|') || '') : '';

        const viewer = await this.getAccountFromSession(req);
        const viewerId = viewer ? String((viewer as any).accountId || '').trim() : '';
        const viewerRole = viewer ? String((viewer as any).role || '').trim() : '';
        const canViewPrivate = Boolean(viewer && (viewerRole === 'operator' || viewerId === targetAccountId));

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(targetAccountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const all = Array.from((state as any).verifierRatings?.values?.() || []) as any[];
        const items = all.filter((x: any) => x && String(x.targetAccountId || '') === targetAccountId);
        items.sort((a: any, b: any) => {
          const ta = Number(a?.createdAt || 0);
          const tb = Number(b?.createdAt || 0);
          if (tb !== ta) return tb - ta;
          return String(b?.key || '').localeCompare(String(a?.key || ''));
        });

        const filtered = cursorTs
          ? items.filter((x: any) => {
              const ts = Number(x?.createdAt || 0);
              const k = String(x?.key || '');
              if (ts < cursorTs) return true;
              if (ts > cursorTs) return false;
              return k < cursorKey;
            })
          : items;

        const page = filtered.slice(0, limit);
        const entries = page.map((r: any) => {
          const ctxId = String(r?.contextId || '');
          return {
            key: String(r?.key || ''),
            createdAt: Number(r?.createdAt || 0),
            targetAccountId,
            raterAccountId: canViewPrivate ? String(r?.raterAccountId || '') : undefined,
            contextType: String(r?.contextType || ''),
            contextId: canViewPrivate ? ctxId : undefined,
            contextIdHint: !canViewPrivate && ctxId ? `${ctxId.substring(0, 10)}...` : undefined,
            rating: Number(r?.rating || 0),
            feeTxid: canViewPrivate && r?.feeTxid ? String(r.feeTxid) : undefined,
          };
        });

        const last = page.length ? page[page.length - 1] : null;
        const nextCursor = last ? `${Number(last.createdAt || 0)}|${String(last.key || '')}` : undefined;
        const hasMore = filtered.length > page.length;

        res.json({
          success: true,
          targetAccountId,
          canViewPrivate,
          entries,
          nextCursor,
          hasMore,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/verifiers/:accountId/reputation/reports', async (req: Request, res: Response) => {
      try {
        const targetAccountId = String(req.params.accountId || '').trim();
        if (!targetAccountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }

        const limitRaw = Number(req.query.limit || 50);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(200, Math.floor(limitRaw)) : 50;
        const cursorRaw = String(req.query.cursor || '').trim();
        const cursorParts = cursorRaw ? cursorRaw.split('|') : [];
        const cursorTs = cursorParts.length >= 1 ? Number(cursorParts[0] || 0) : 0;
        const cursorKey = cursorParts.length >= 2 ? String(cursorParts.slice(1).join('|') || '') : '';

        const viewer = await this.getAccountFromSession(req);
        const viewerId = viewer ? String((viewer as any).accountId || '').trim() : '';
        const viewerRole = viewer ? String((viewer as any).role || '').trim() : '';
        const canViewPrivate = Boolean(viewer && (viewerRole === 'operator' || viewerId === targetAccountId));

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(targetAccountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const all = Array.from((state as any).verifierReports?.values?.() || []) as any[];
        const items = all.filter((x: any) => x && String(x.targetAccountId || '') === targetAccountId);
        items.sort((a: any, b: any) => {
          const ta = Number(a?.createdAt || 0);
          const tb = Number(b?.createdAt || 0);
          if (tb !== ta) return tb - ta;
          return String(b?.key || '').localeCompare(String(a?.key || ''));
        });

        const filtered = cursorTs
          ? items.filter((x: any) => {
              const ts = Number(x?.createdAt || 0);
              const k = String(x?.key || '');
              if (ts < cursorTs) return true;
              if (ts > cursorTs) return false;
              return k < cursorKey;
            })
          : items;

        const page = filtered.slice(0, limit);
        const entries = page.map((r: any) => {
          const ctxId = String(r?.contextId || '');
          const details = r?.details ? String(r.details) : '';
          return {
            key: String(r?.key || ''),
            createdAt: Number(r?.createdAt || 0),
            targetAccountId,
            reporterAccountId: canViewPrivate ? String(r?.reporterAccountId || '') : undefined,
            contextType: String(r?.contextType || ''),
            contextId: canViewPrivate ? ctxId : undefined,
            contextIdHint: !canViewPrivate && ctxId ? `${ctxId.substring(0, 10)}...` : undefined,
            reasonCode: r?.reasonCode ? String(r.reasonCode) : undefined,
            details: canViewPrivate ? (details || undefined) : (details ? `${details.substring(0, 24)}...` : undefined),
          };
        });

        const last = page.length ? page[page.length - 1] : null;
        const nextCursor = last ? `${Number(last.createdAt || 0)}|${String(last.key || '')}` : undefined;
        const hasMore = filtered.length > page.length;

        res.json({
          success: true,
          targetAccountId,
          canViewPrivate,
          entries,
          nextCursor,
          hasMore,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/operator/verifiers', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const state = await this.canonicalStateBuilder.buildState();
        const verifiers = Array.from(state.accounts.values())
          .filter((a: any) => String(a.role) === 'manufacturer' || String(a.role) === 'authenticator')
          .map((a: any) => ({
            accountId: String(a.accountId),
            role: String(a.role),
            username: a.username ? String(a.username) : undefined,
            displayName: a.displayName ? String(a.displayName) : undefined,
            companyName: a.companyName ? String(a.companyName) : undefined,
            website: a.website ? String(a.website) : undefined,
            ratingAvg: typeof a.ratingAvg === 'number' ? Number(a.ratingAvg) : undefined,
            ratingCount: typeof a.ratingCount === 'number' ? Number(a.ratingCount) : undefined,
            reportCount: typeof a.reportCount === 'number' ? Number(a.reportCount) : undefined,
            bondMinSats: a.bondMinSats ? Number(a.bondMinSats) : undefined,
            bondConfirmedSats: a.bondConfirmedSats ? Number(a.bondConfirmedSats) : undefined,
            bondMeetsMin: typeof a.bondMeetsMin === 'boolean' ? Boolean(a.bondMeetsMin) : undefined,
            bondLastCheckedAt: a.bondLastCheckedAt ? Number(a.bondLastCheckedAt) : undefined,
            verifierStatus: String(a.verifierStatus || 'active'),
            verifierRevokedAt: a.verifierRevokedAt ? Number(a.verifierRevokedAt) : undefined,
            verifierReactivatedAt: a.verifierReactivatedAt ? Number(a.verifierReactivatedAt) : undefined,
          }));

        res.json({ success: true, count: verifiers.length, verifiers });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/operator/reputation/ratings', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const limitRaw = Number(req.query.limit || 50);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(200, Math.floor(limitRaw)) : 50;
        const cursorRaw = String(req.query.cursor || '').trim();
        const cursorParts = cursorRaw ? cursorRaw.split('|') : [];
        const cursorTs = cursorParts.length >= 1 ? Number(cursorParts[0] || 0) : 0;
        const cursorKey = cursorParts.length >= 2 ? String(cursorParts.slice(1).join('|') || '') : '';

        const state = await this.canonicalStateBuilder.buildState();
        const items = Array.from((state as any).verifierRatings?.values?.() || []) as any[];
        items.sort((a: any, b: any) => {
          const ta = Number(a?.createdAt || 0);
          const tb = Number(b?.createdAt || 0);
          if (tb !== ta) return tb - ta;
          return String(b?.key || '').localeCompare(String(a?.key || ''));
        });

        const filtered = cursorTs
          ? items.filter((x: any) => {
              const ts = Number(x?.createdAt || 0);
              const k = String(x?.key || '');
              if (ts < cursorTs) return true;
              if (ts > cursorTs) return false;
              return k < cursorKey;
            })
          : items;

        const page = filtered.slice(0, limit);
        const entries = page.map((r: any) => {
          const targetAccountId = String(r?.targetAccountId || '');
          const target: any = (state as any).accounts?.get?.(targetAccountId);
          return {
            key: String(r?.key || ''),
            createdAt: Number(r?.createdAt || 0),
            targetAccountId,
            raterAccountId: String(r?.raterAccountId || ''),
            contextType: String(r?.contextType || ''),
            contextId: String(r?.contextId || ''),
            rating: Number(r?.rating || 0),
            feeTxid: r?.feeTxid ? String(r.feeTxid) : undefined,
            feePaidSats: r?.feePaidSats !== undefined ? Number(r.feePaidSats || 0) : undefined,
            feeConfirmations: r?.feeConfirmations !== undefined ? Number(r.feeConfirmations || 0) : undefined,
            target: target
              ? {
                  role: String(target.role || ''),
                  displayName: target.displayName ? String(target.displayName) : undefined,
                  companyName: target.companyName ? String(target.companyName) : undefined,
                  website: target.website ? String(target.website) : undefined,
                  verifierStatus: String(target.verifierStatus || 'active'),
                  ratingAvg: typeof target.ratingAvg === 'number' ? Number(target.ratingAvg) : undefined,
                  ratingCount: typeof target.ratingCount === 'number' ? Number(target.ratingCount) : undefined,
                  reportCount: typeof target.reportCount === 'number' ? Number(target.reportCount) : undefined,
                }
              : undefined,
          };
        });

        const last = page.length ? page[page.length - 1] : null;
        const nextCursor = last ? `${Number(last.createdAt || 0)}|${String(last.key || '')}` : undefined;
        const hasMore = filtered.length > page.length;

        res.json({ success: true, entries, nextCursor, hasMore });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/operator/reputation/reports', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const limitRaw = Number(req.query.limit || 50);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(200, Math.floor(limitRaw)) : 50;
        const cursorRaw = String(req.query.cursor || '').trim();
        const cursorParts = cursorRaw ? cursorRaw.split('|') : [];
        const cursorTs = cursorParts.length >= 1 ? Number(cursorParts[0] || 0) : 0;
        const cursorKey = cursorParts.length >= 2 ? String(cursorParts.slice(1).join('|') || '') : '';

        const state = await this.canonicalStateBuilder.buildState();
        const items = Array.from((state as any).verifierReports?.values?.() || []) as any[];
        items.sort((a: any, b: any) => {
          const ta = Number(a?.createdAt || 0);
          const tb = Number(b?.createdAt || 0);
          if (tb !== ta) return tb - ta;
          return String(b?.key || '').localeCompare(String(a?.key || ''));
        });

        const filtered = cursorTs
          ? items.filter((x: any) => {
              const ts = Number(x?.createdAt || 0);
              const k = String(x?.key || '');
              if (ts < cursorTs) return true;
              if (ts > cursorTs) return false;
              return k < cursorKey;
            })
          : items;

        const page = filtered.slice(0, limit);
        const entries = page.map((r: any) => {
          const targetAccountId = String(r?.targetAccountId || '');
          const target: any = (state as any).accounts?.get?.(targetAccountId);
          return {
            key: String(r?.key || ''),
            createdAt: Number(r?.createdAt || 0),
            targetAccountId,
            reporterAccountId: String(r?.reporterAccountId || ''),
            contextType: String(r?.contextType || ''),
            contextId: String(r?.contextId || ''),
            reasonCode: r?.reasonCode ? String(r.reasonCode) : undefined,
            details: r?.details ? String(r.details) : undefined,
            target: target
              ? {
                  role: String(target.role || ''),
                  displayName: target.displayName ? String(target.displayName) : undefined,
                  companyName: target.companyName ? String(target.companyName) : undefined,
                  website: target.website ? String(target.website) : undefined,
                  verifierStatus: String(target.verifierStatus || 'active'),
                  ratingAvg: typeof target.ratingAvg === 'number' ? Number(target.ratingAvg) : undefined,
                  ratingCount: typeof target.ratingCount === 'number' ? Number(target.ratingCount) : undefined,
                  reportCount: typeof target.reportCount === 'number' ? Number(target.reportCount) : undefined,
                }
              : undefined,
          };
        });

        const last = page.length ? page[page.length - 1] : null;
        const nextCursor = last ? `${Number(last.createdAt || 0)}|${String(last.key || '')}` : undefined;
        const hasMore = filtered.length > page.length;

        res.json({ success: true, entries, nextCursor, hasMore });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/operator/status', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const state = await this.canonicalStateBuilder.buildState();
        const accountId = String(op.accountId || '');
        
        // Find the operator record for this logged-in user
        const operators = Array.from(state.operators.values()) as any[];
        const operatorState = operators.find((o: any) => 
          o && 
          o.status === 'active' &&
          (String(o.publicKey || '') === accountId || String(o.sponsorId || '') === accountId)
        );
        
        const activeOperators = operators.filter((o: any) => o && o.status === 'active');
        const operatorId = operatorState ? String(operatorState.operatorId || '') : String(process.env.OPERATOR_ID || 'operator-1');

        let tipHeight = 0;
        try {
          const apiBase = this.getBlockstreamApiBase();
          const tipResp = await fetch(`${apiBase}/blocks/tip/height`);
          const tipText = await tipResp.text();
          if (tipResp.ok) tipHeight = Number(String(tipText || '').trim());
        } catch {}

        const mainNodeAccountId = String(process.env.MAIN_NODE_ACCOUNT_ID || '').trim();
        res.json({
          success: true,
          operator: {
            operatorId,
            sessionAccountId: accountId,
            nodePublicKey: String(this.node.getOperatorInfo().publicKey || ''),
            isMainNode: Boolean(mainNodeAccountId && this.isMainNode()),
            canonicalStatus: operatorState ? String(operatorState.status || '') : 'unknown',
            admittedAt: operatorState?.admittedAt ? Number(operatorState.admittedAt) : undefined,
            activeOperatorCount: activeOperators.length,
          },
          chain: {
            network: this.network,
            tipHeight,
          },
          registry: {
            lastEventSequence: state.lastEventSequence,
            lastEventHash: state.lastEventHash,
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/consensus/status', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const { ConsensusIntegration } = require('./consensus-integration');
        const status = ConsensusIntegration.getConsensusStatus(this);
        res.json({ success: true, ...status });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/operator/earnings', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const state = await this.canonicalStateBuilder.buildState();
        const accountId = String(op.accountId || '');
        
        // Find the operator record for this logged-in user
        const operators = Array.from(state.operators.values()) as any[];
        const operatorState = operators.find((o: any) => 
          o && 
          o.status === 'active' &&
          (String(o.publicKey || '') === accountId || String(o.sponsorId || '') === accountId)
        );

        if (!operatorState) {
          res.status(404).json({ success: false, error: 'Operator record not found' });
          return;
        }

        const operatorId = String(operatorState.operatorId || '');
        const btcAddress = String(operatorState.btcAddress || '');

        // Calculate total fees earned from settlements and consignments
        const settlements = Array.from(state.settlements.values()) as any[];
        const consignments = Array.from((state as any).consignments?.values?.() || []) as any[];

        const transactions: Array<{ timestamp: number; type: string; amountSats: number; settlementId: string }> = [];
        let totalSats = 0;

        // Check settlements for operator fee payouts
        for (const settlement of settlements) {
          const payouts = settlement.platformFeePayouts;
          if (payouts && Array.isArray(payouts.operatorPayouts)) {
            const operatorPayout = payouts.operatorPayouts.find((p: any) => String(p.operatorId || '') === operatorId);
            if (operatorPayout) {
              const amountSats = Number(operatorPayout.amountSats || 0);
              totalSats += amountSats;
              transactions.push({
                timestamp: Number(settlement.completedAt || settlement.acceptedAt || settlement.initiatedAt || 0),
                type: 'Sale Fee',
                amountSats,
                settlementId: String(settlement.settlementId || ''),
              });
            }
          }
        }

        // Check consignments for operator fee payouts
        for (const consignment of consignments) {
          const payouts = consignment.platformFeePayouts;
          if (payouts && Array.isArray(payouts.operatorPayouts)) {
            const operatorPayout = payouts.operatorPayouts.find((p: any) => String(p.operatorId || '') === operatorId);
            if (operatorPayout) {
              const amountSats = Number(operatorPayout.amountSats || 0);
              totalSats += amountSats;
              transactions.push({
                timestamp: Number(consignment.completedAt || consignment.createdAt || 0),
                type: 'Consignment Fee',
                amountSats,
                settlementId: String(consignment.consignmentId || ''),
              });
            }
          }
        }

        // Sort transactions by timestamp descending (most recent first)
        transactions.sort((a, b) => b.timestamp - a.timestamp);

        res.json({
          success: true,
          wallet: {
            operatorId,
            btcAddress,
          },
          earnings: {
            totalSats,
            transactionCount: transactions.length,
            transactions: transactions.slice(0, 50), // Return most recent 50 transactions
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/pow/challenge', async (req: Request, res: Response) => {
      try {
        const resource = String(req.query.resource || '').trim() || '/';
        const difficulty = Math.max(4, Math.min(32, Math.floor(Number(process.env.AUTHO_POW_DIFFICULTY || 20))));
        const ttlMs = Math.max(10_000, Math.min(5 * 60_000, Math.floor(Number(process.env.AUTHO_POW_TTL_MS || 60_000))));
        const expiresAt = Date.now() + ttlMs;
        const salt = randomBytes(16).toString('hex');
        const challengeId = randomBytes(16).toString('hex');

        this.powChallenges.set(challengeId, { salt, difficulty, expiresAt, resource });

        res.json({
          success: true,
          enabled: true,
          challengeId,
          salt,
          difficulty,
          expiresAt,
          resource,
        });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    this.app.get('/api/anchors/time', async (req: Request, res: Response) => {
      try {
        const events = await this.canonicalEventStore.getAllEvents();
        const anchors = events
          .filter((e: any) => e && e.payload && e.payload.type === EventType.ANCHOR_COMMITTED)
          .map((e: any) => ({ eventHash: e.eventHash, sequenceNumber: e.sequenceNumber, createdAt: e.createdAt, payload: e.payload }));

        if (!anchors.length) {
          res.json({ success: true, anchored: false, reason: 'no_anchor_committed_events' });
          return;
        }

        const latest = anchors[anchors.length - 1] as any;
        const checkpointRoot = String(latest?.payload?.checkpointRoot || '').trim();
        const txid = String(latest?.payload?.txid || '').trim();
        const recordedBlockHeight = Number(latest?.payload?.blockHeight || 0);

        if (!checkpointRoot || !txid || !recordedBlockHeight) {
          res.status(500).json({ success: false, error: 'Latest anchor record is missing checkpointRoot, txid, or blockHeight' });
          return;
        }

        const expectedOpReturnData = Buffer.concat([Buffer.from('AUTHO1', 'ascii'), Buffer.from(checkpointRoot, 'hex')]);
        const bases = this.getChainApiBases();

        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const statusResp = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/status`);
            const statusText = await statusResp.text();
            if (!statusResp.ok) {
              lastErr = { status: statusResp.status, text: statusText, provider: apiBase };
              continue;
            }

            const statusJson = JSON.parse(statusText);
            const confirmed = Boolean(statusJson?.confirmed);
            const actualBlockHeight = confirmed ? Number(statusJson?.block_height || 0) : 0;
            const blockHash = confirmed ? String(statusJson?.block_hash || '') : '';
            const blockTime = confirmed ? Number(statusJson?.block_time || 0) : 0;

            let tipHeight = 0;
            try {
              const tipResp = await fetch(`${apiBase}/blocks/tip/height`);
              const tipText = await tipResp.text();
              if (tipResp.ok) tipHeight = Number(String(tipText || '').trim());
            } catch {}

            const confirmations = confirmed && actualBlockHeight && tipHeight && tipHeight >= actualBlockHeight
              ? (tipHeight - actualBlockHeight + 1)
              : 0;

            if (!confirmed) {
              res.json({
                success: true,
                anchored: true,
                verified: false,
                checkpointRoot,
                txid,
                provider: apiBase,
                bitcoinTime: { blockHeight: undefined, blockTime: undefined, blockHash: undefined, confirmations },
                recordedBlockHeight,
                opReturnMatch: false,
                reason: 'tx_not_confirmed',
              });
              return;
            }

            if (!(actualBlockHeight >= recordedBlockHeight)) {
              res.json({
                success: true,
                anchored: true,
                verified: false,
                checkpointRoot,
                txid,
                provider: apiBase,
                bitcoinTime: { blockHeight: actualBlockHeight || undefined, blockTime: blockTime || undefined, blockHash: blockHash || undefined, confirmations },
                recordedBlockHeight,
                opReturnMatch: false,
                reason: 'tx_confirmed_but_height_mismatch',
              });
              return;
            }

            const hexResp = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/hex`);
            const hexText = await hexResp.text();
            if (!hexResp.ok) {
              lastErr = { status: hexResp.status, text: hexText, provider: apiBase };
              continue;
            }

            const tx = bitcoin.Transaction.fromHex(String(hexText || '').trim());
            let opReturnMatch = false;
            for (const out of tx.outs) {
              try {
                const chunks = bitcoin.script.decompile(out.script);
                if (!chunks || chunks.length < 2) continue;
                if (chunks[0] !== bitcoin.opcodes.OP_RETURN) continue;
                const data = chunks[1];
                if (Buffer.isBuffer(data) && Buffer.compare(data, expectedOpReturnData) === 0) {
                  opReturnMatch = true;
                  break;
                }
              } catch {}
            }

            res.json({
              success: true,
              anchored: true,
              verified: confirmed && opReturnMatch,
              checkpointRoot,
              txid,
              provider: apiBase,
              bitcoinTime: {
                blockHeight: actualBlockHeight || undefined,
                blockTime: blockTime || undefined,
                blockHash: blockHash || undefined,
                confirmations,
              },
              recordedBlockHeight,
              opReturnMatch,
              expectedOpReturnDataHex: expectedOpReturnData.toString('hex'),
            });
            return;
          } catch (e: any) {
            lastErr = { error: e?.message || String(e), provider: apiBase };
          }
        }

        res.status(502).json({ success: false, error: 'All chain providers failed', lastErr });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    this.app.get('/api/anchors/checkpoints', async (req: Request, res: Response) => {
      try {
        const limitRaw = Number(req.query.limit || 50);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(500, Math.floor(limitRaw)) : 50;
        const events = await this.canonicalEventStore.getAllEvents();
        const cps = events
          .filter((e: any) => e && e.payload && e.payload.type === EventType.CHECKPOINT_CREATED)
          .slice(-limit)
          .reverse()
          .map((e: any) => ({
            eventHash: e.eventHash,
            sequenceNumber: e.sequenceNumber,
            createdAt: e.createdAt,
            payload: e.payload,
          }));
        res.json({ success: true, checkpoints: cps });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    this.app.get('/api/anchors/checkpoints/:checkpointRoot/commitment', async (req: Request, res: Response) => {
      try {
        const checkpointRoot = String(req.params.checkpointRoot || '').trim();
        if (!checkpointRoot) {
          res.status(400).json({ success: false, error: 'Missing checkpointRoot' });
          return;
        }
        if (!/^[0-9a-fA-F]{64}$/.test(checkpointRoot)) {
          res.status(400).json({ success: false, error: 'Invalid checkpointRoot (expected 32-byte hex)' });
          return;
        }

        const tag = Buffer.from('AUTHO1', 'ascii');
        const root = Buffer.from(checkpointRoot, 'hex');
        const opReturnData = Buffer.concat([tag, root]);
        const script = bitcoin.script.compile([bitcoin.opcodes.OP_RETURN, opReturnData]);

        res.json({
          success: true,
          checkpointRoot,
          opReturnDataHex: opReturnData.toString('hex'),
          opReturnScriptHex: script.toString('hex'),
          opReturnMaxBytes: 80,
          opReturnDataBytes: opReturnData.length,
        });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    this.app.get('/api/anchors/checkpoints/:checkpointRoot/verify', async (req: Request, res: Response) => {
      try {
        const checkpointRoot = String(req.params.checkpointRoot || '').trim();
        if (!checkpointRoot) {
          res.status(400).json({ success: false, error: 'Missing checkpointRoot' });
          return;
        }
        if (!/^[0-9a-fA-F]{64}$/.test(checkpointRoot)) {
          res.status(400).json({ success: false, error: 'Invalid checkpointRoot (expected 32-byte hex)' });
          return;
        }

        const events = await this.canonicalEventStore.getAllEvents();
        const anchors = events
          .filter((e: any) => e && e.payload && e.payload.type === EventType.ANCHOR_COMMITTED)
          .map((e: any) => e.payload)
          .filter((p: any) => p && String(p.checkpointRoot || '') === checkpointRoot);

        if (!anchors.length) {
          res.status(404).json({ success: false, error: 'No anchor recorded for this checkpointRoot' });
          return;
        }

        const anchor = anchors[anchors.length - 1] as any;
        const txid = String(anchor.txid || '').trim();
        const recordedBlockHeight = Number(anchor.blockHeight || 0);
        if (!txid || !recordedBlockHeight) {
          res.status(500).json({ success: false, error: 'Anchor record missing txid or blockHeight' });
          return;
        }

        const expectedOpReturnData = Buffer.concat([Buffer.from('AUTHO1', 'ascii'), Buffer.from(checkpointRoot, 'hex')]);
        const bases = this.getChainApiBases();

        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const statusResp = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/status`);
            const statusText = await statusResp.text();
            if (!statusResp.ok) {
              lastErr = { status: statusResp.status, text: statusText, provider: apiBase };
              continue;
            }

            const statusJson = JSON.parse(statusText);
            const confirmed = Boolean(statusJson?.confirmed);
            const actualBlockHeight = confirmed ? Number(statusJson?.block_height || 0) : 0;
            const blockHash = confirmed ? String(statusJson?.block_hash || '') : '';
            const blockTime = confirmed ? Number(statusJson?.block_time || 0) : 0;

            let tipHeight = 0;
            try {
              const tipResp = await fetch(`${apiBase}/blocks/tip/height`);
              const tipText = await tipResp.text();
              if (tipResp.ok) tipHeight = Number(String(tipText || '').trim());
            } catch {}

            const confirmations = confirmed && actualBlockHeight && tipHeight && tipHeight >= actualBlockHeight
              ? (tipHeight - actualBlockHeight + 1)
              : 0;

            if (!confirmed) {
              res.json({
                success: true,
                checkpointRoot,
                txid,
                provider: apiBase,
                confirmed: false,
                confirmations,
                recordedBlockHeight,
                actualBlockHeight: undefined,
                blockHash: undefined,
                blockTime: undefined,
                opReturnMatch: false,
              });
              return;
            }

            if (!(actualBlockHeight >= recordedBlockHeight)) {
              res.json({
                success: true,
                checkpointRoot,
                txid,
                provider: apiBase,
                confirmed: true,
                confirmations,
                recordedBlockHeight,
                actualBlockHeight,
                blockHash: blockHash || undefined,
                blockTime: blockTime || undefined,
                opReturnMatch: false,
                error: 'tx_confirmed_but_height_mismatch',
              });
              return;
            }

            const hexResp = await fetch(`${apiBase}/tx/${encodeURIComponent(txid)}/hex`);
            const hexText = await hexResp.text();
            if (!hexResp.ok) {
              lastErr = { status: hexResp.status, text: hexText, provider: apiBase };
              continue;
            }

            const tx = bitcoin.Transaction.fromHex(String(hexText || '').trim());
            let opReturnMatch = false;
            for (const out of tx.outs) {
              try {
                const chunks = bitcoin.script.decompile(out.script);
                if (!chunks || chunks.length < 2) continue;
                if (chunks[0] !== bitcoin.opcodes.OP_RETURN) continue;
                const data = chunks[1];
                if (Buffer.isBuffer(data) && Buffer.compare(data, expectedOpReturnData) === 0) {
                  opReturnMatch = true;
                  break;
                }
              } catch {}
            }

            res.json({
              success: true,
              checkpointRoot,
              txid,
              provider: apiBase,
              confirmed: true,
              confirmations,
              recordedBlockHeight,
              actualBlockHeight,
              blockHash: blockHash || undefined,
              blockTime: blockTime || undefined,
              opReturnMatch,
              expectedOpReturnDataHex: expectedOpReturnData.toString('hex'),
            });
            return;
          } catch (e: any) {
            lastErr = { error: e?.message || String(e), provider: apiBase };
          }
        }

        res.status(502).json({ success: false, error: 'All chain providers failed', lastErr });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    this.app.get('/api/anchors/commits', async (req: Request, res: Response) => {
      try {
        const limitRaw = Number(req.query.limit || 50);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(500, Math.floor(limitRaw)) : 50;
        const events = await this.canonicalEventStore.getAllEvents();
        const anchors = events
          .filter((e: any) => e && e.payload && e.payload.type === EventType.ANCHOR_COMMITTED)
          .slice(-limit)
          .reverse()
          .map((e: any) => ({
            eventHash: e.eventHash,
            sequenceNumber: e.sequenceNumber,
            createdAt: e.createdAt,
            payload: e.payload,
          }));
        res.json({ success: true, anchors });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    // Get unanchored checkpoints (for operator UI)
    this.app.get('/api/operator/anchors/unanchored', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const events = await this.canonicalEventStore.getAllEvents();
        
        // Get all checkpoints
        const checkpoints = events
          .filter((e: any) => e && e.payload && e.payload.type === EventType.CHECKPOINT_CREATED)
          .map((e: any) => ({
            checkpointRoot: e.payload?.checkpointRoot,
            hourStartMs: e.payload?.hourStartMs,
            headSequence: e.payload?.headSequence,
            eventCount: e.payload?.eventCount,
            createdAt: e.createdAt,
          }));
        
        // Get all anchors
        const anchors = events
          .filter((e: any) => e && e.payload && e.payload.type === EventType.ANCHOR_COMMITTED)
          .map((e: any) => e.payload);
        
        // Find checkpoints without anchors
        const anchoredRoots = new Set(anchors.map((a: any) => a.checkpointRoot));
        const unanchored = checkpoints.filter((cp: any) => !anchoredRoots.has(cp.checkpointRoot));
        
        res.json({ success: true, unanchored, total: checkpoints.length, anchored: anchors.length });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    // Get anchor statistics for weighted fee distribution
    this.app.get('/api/operator/anchors/stats', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const events = await this.canonicalEventStore.getAllEvents();
        const state = await this.canonicalStateBuilder.buildState();
        
        // Count anchors by operator
        const anchorsByOperator = new Map<string, number>();
        const anchorEvents = events.filter((e: any) => e && e.payload && e.payload.type === EventType.ANCHOR_COMMITTED);
        
        for (const e of anchorEvents) {
          const sigs = Array.isArray((e as any).signatures) ? (e as any).signatures : [];
          for (const sig of sigs) {
            const opId = String(sig?.operatorId || '').trim();
            if (opId) {
              anchorsByOperator.set(opId, (anchorsByOperator.get(opId) || 0) + 1);
            }
          }
        }

        // Calculate weights (operators with more anchors get higher weight)
        const totalAnchors = Array.from(anchorsByOperator.values()).reduce((sum, count) => sum + count, 0);
        const weights = new Map<string, number>();
        
        for (const [opId, count] of anchorsByOperator.entries()) {
          weights.set(opId, totalAnchors > 0 ? count / totalAnchors : 0);
        }

        // Get active operators
        const activeOperators = Array.from(state.operators.values())
          .filter((op: any) => op.status === 'active')
          .map((op: any) => ({
            operatorId: op.operatorId,
            publicKey: op.publicKey,
            anchorCount: anchorsByOperator.get(op.operatorId) || 0,
            weight: weights.get(op.operatorId) || 0,
          }));

        res.json({ 
          success: true, 
          totalAnchors,
          operators: activeOperators,
          myOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
          myAnchorCount: anchorsByOperator.get(String(process.env.OPERATOR_ID || 'operator-1')) || 0,
        });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });

    this.app.post('/api/operator/anchors/commit', async (req: Request, res: Response) => {
      try {
        // DECENTRALIZATION: Any operator can commit Bitcoin anchors (not just main node)
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const checkpointRoot = String(req.body?.checkpointRoot || '').trim();
        const txid = String(req.body?.txid || '').trim();
        const blockHeight = Number(req.body?.blockHeight || 0);
        if (!checkpointRoot || !txid || !Number.isFinite(blockHeight) || blockHeight <= 0) {
          res.status(400).json({ success: false, error: 'checkpointRoot, txid, blockHeight required' });
          return;
        }

        const events = await this.canonicalEventStore.getAllEvents();
        const checkpoint = events
          .filter((e: any) => e && e.payload && e.payload.type === EventType.CHECKPOINT_CREATED)
          .map((e: any) => e.payload)
          .find((p: any) => String(p?.checkpointRoot || '') === checkpointRoot);

        if (!checkpoint) {
          res.status(404).json({ success: false, error: 'Checkpoint not found' });
          return;
        }

        const existingAnchors = events
          .filter((e: any) => e && e.payload && e.payload.type === EventType.ANCHOR_COMMITTED)
          .map((e: any) => e.payload)
          .filter((p: any) => p && String(p.checkpointRoot || '') === checkpointRoot);
        if (existingAnchors.length) {
          res.status(409).json({ success: false, error: 'Anchor already recorded for this checkpointRoot' });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const now = Date.now();
        const operatorId = String(process.env.OPERATOR_ID || 'operator-1');
        const signatures: QuorumSignature[] = [
          {
            operatorId,
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ANCHOR_COMMITTED:${checkpointRoot}:${txid}:${blockHeight}:${now}`).digest('hex'),
          },
        ];

        const anchorEvent = await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ANCHOR_COMMITTED,
            timestamp: now,
            nonce,
            checkpointRoot,
            eventCount: Number((checkpoint as any)?.eventCount || 0),
            txid,
            blockHeight,
            quorumSignatures: [],
          } as any,
          signatures
        );

        this.broadcastToGateways({
          type: 'registry_update',
          data: {
            sequenceNumber: anchorEvent.sequenceNumber,
            lastEventHash: anchorEvent.eventHash,
          },
          timestamp: Date.now(),
        });

        res.json({ success: true, checkpointRoot, txid, blockHeight });
      } catch (e: any) {
        res.status(500).json({ success: false, error: e?.message || String(e) });
      }
    });
  }

  private computeMerkleRoot(hashes: string[]): string {
    const items = Array.isArray(hashes) ? hashes.filter(Boolean) : [];
    if (items.length === 0) return '';
    if (items.length === 1) return items[0];

    let current = items.slice();
    while (current.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < current.length; i += 2) {
        if (i + 1 < current.length) {
          next.push(createHash('sha256').update(`${current[i]}${current[i + 1]}`).digest('hex'));
        } else {
          next.push(current[i]);
        }
      }
      current = next;
    }
    return current[0];
  }

  private isMainNode(): boolean {
    const mainNodeAccountId = String(process.env.MAIN_NODE_ACCOUNT_ID || '').trim();
    if (!mainNodeAccountId) return false;
    return String(this.node.getOperatorInfo().publicKey || '').trim() === mainNodeAccountId;
  }

  private async maybeCreateHourlyCheckpoint(): Promise<void> {
    // DECENTRALIZATION: Any operator can create checkpoints (not just main node)
    // Duplicate checks below prevent conflicts if multiple operators attempt simultaneously

    const now = Date.now();
    const hourStart = Math.floor(now / (60 * 60 * 1000)) * (60 * 60 * 1000);
    const targetHourStart = hourStart - (60 * 60 * 1000);
    if (targetHourStart <= 0) return;

    const events = await this.canonicalEventStore.getAllEvents();
    const checkpointEvents = events.filter((e: any) => e && e.payload && e.payload.type === EventType.CHECKPOINT_CREATED);
    const existingByHour = new Map<number, any>();
    for (const e of checkpointEvents) {
      existingByHour.set(Number(((e as any).payload as any)?.hourStartMs || 0), e);
    }

    const lastCheckpointHour = checkpointEvents.length
      ? Number((((checkpointEvents[checkpointEvents.length - 1] as any) || {}).payload as any)?.hourStartMs || 0)
      : 0;

    const fromHour = lastCheckpointHour > 0 ? lastCheckpointHour + 60 * 60 * 1000 : targetHourStart;
    const operatorId = String(process.env.OPERATOR_ID || 'operator-1');

    for (let hour = fromHour; hour <= targetHourStart; hour += 60 * 60 * 1000) {
      if (existingByHour.has(hour)) continue;

      const latestEvents = await this.canonicalEventStore.getAllEvents();
      const latestCheckpointEvents = latestEvents.filter(
        (e: any) => e && e.payload && e.payload.type === EventType.CHECKPOINT_CREATED
      );
      const prev = latestCheckpointEvents.length ? latestCheckpointEvents[latestCheckpointEvents.length - 1] : null;
      const previousCheckpointRoot = prev ? String((((prev as any) || {}).payload as any)?.checkpointRoot || '') : '';

      const state = this.canonicalEventStore.getState();
      const headHash = String(state.headHash || '');
      const headSequence = Number(state.sequenceNumber || 0);
      const eventCount = Number(state.eventCount || 0);

      const eventHashes = latestEvents.map((e: any) => String(e?.eventHash || '')).filter(Boolean);
      const merkleRoot = this.computeMerkleRoot(eventHashes);
      const checkpointRoot = createHash('sha256')
        .update(`AUTHO_CKP_V1:${hour}:${headSequence}:${headHash}:${merkleRoot}:${previousCheckpointRoot}`)
        .digest('hex');

      const nonce = randomBytes(32).toString('hex');
      const signatures: QuorumSignature[] = [
        {
          operatorId,
          publicKey: this.node.getOperatorInfo().publicKey,
          signature: createHash('sha256').update(`CHECKPOINT_CREATED:${checkpointRoot}:${hour}`).digest('hex'),
        },
      ];

      const checkpointEvent = await this.canonicalEventStore.appendEvent(
        {
          type: EventType.CHECKPOINT_CREATED,
          timestamp: Date.now(),
          nonce,
          checkpointRoot,
          eventCount,
          merkleRoot,
          headHash,
          headSequence,
          hourStartMs: hour,
          previousCheckpointRoot: previousCheckpointRoot || undefined,
        } as any,
        signatures
      );

      this.broadcastToGateways({
        type: 'registry_update',
        data: {
          sequenceNumber: checkpointEvent.sequenceNumber,
          lastEventHash: checkpointEvent.eventHash,
        },
        timestamp: Date.now(),
      });
    }
  }

  private startCheckpointScheduler(): void {
    if (this.checkpointTimer) return;

    const tick = async () => {
      try {
        for (const [k, v] of this.powChallenges.entries()) {
          if (!v || Date.now() > v.expiresAt) {
            this.powChallenges.delete(k);
          }
        }
        await this.maybeCreateHourlyCheckpoint();
      } catch (e: any) {
        console.error('[Anchors] Checkpoint tick failed:', e?.message || String(e));
      }
    };

    void tick();
    this.checkpointTimer = setInterval(() => void tick(), 60 * 1000);
  }

  private setupAdminRoutes(): void {
    this.app.get('/api/admin/consensus/status', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const { ConsensusIntegration } = require('./consensus-integration');
        const status = ConsensusIntegration.getConsensusStatus(this);
        res.json({ success: true, ...status });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/anchors/commit', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const checkpointRoot = String(req.body?.checkpointRoot || '').trim();
        const txid = String(req.body?.txid || '').trim();
        const blockHeight = Number(req.body?.blockHeight || 0);
        if (!checkpointRoot || !txid || !Number.isFinite(blockHeight) || blockHeight <= 0) {
          res.status(400).json({ success: false, error: 'checkpointRoot, txid, blockHeight required' });
          return;
        }
        if (!/^[a-fA-F0-9]{64}$/.test(txid)) {
          res.status(400).json({ success: false, error: 'Invalid txid format (expected 64 hex chars)' });
          return;
        }

        const events = await this.canonicalEventStore.getAllEvents();
        const checkpoint = events
          .filter((e: any) => e && e.payload && e.payload.type === EventType.CHECKPOINT_CREATED)
          .map((e: any) => e.payload)
          .find((p: any) => String(p?.checkpointRoot || '') === checkpointRoot);

        if (!checkpoint) {
          res.status(404).json({ success: false, error: 'Checkpoint not found' });
          return;
        }

        const existingAnchors = events
          .filter((e: any) => e && e.payload && e.payload.type === EventType.ANCHOR_COMMITTED)
          .map((e: any) => e.payload)
          .filter((p: any) => p && String(p.checkpointRoot || '') === checkpointRoot);
        if (existingAnchors.length) {
          res.status(409).json({ success: false, error: 'Anchor already recorded for this checkpointRoot' });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const now = Date.now();
        const operatorId = String(process.env.OPERATOR_ID || 'operator-1');
        const signatures: QuorumSignature[] = [
          {
            operatorId,
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ANCHOR_COMMITTED:${checkpointRoot}:${txid}:${blockHeight}:${now}`).digest('hex'),
          },
        ];

        const anchorEvent = await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ANCHOR_COMMITTED,
            timestamp: now,
            nonce,
            checkpointRoot,
            eventCount: Number((checkpoint as any)?.eventCount || 0),
            txid,
            blockHeight,
            quorumSignatures: [],
          } as any,
          signatures
        );

        this.broadcastToGateways({
          type: 'registry_update',
          data: {
            sequenceNumber: anchorEvent.sequenceNumber,
            lastEventHash: anchorEvent.eventHash,
          },
          timestamp: Date.now(),
        });

        res.json({ success: true, checkpointRoot, txid, blockHeight });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error?.message || String(error) });
      }
    });

    this.app.get('/api/admin/offers/:offerId/escrow', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const offerId = String(req.params.offerId || '').trim();
        if (!offerId) {
          res.status(400).json({ success: false, error: 'Missing offerId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const settlement: any = state.settlements.get(offerId);
        const offersMap = (this.node as any).offers || new Map();
        const offerFallback: any = offersMap.get(offerId);

        if (!settlement && !offerFallback) {
          res.status(404).json({ success: false, error: 'Offer not found in canonical settlements or in-memory offers map' });
          return;
        }

        const escrowAddress = String(settlement?.escrowAddress || offerFallback?.escrowAddress || offerFallback?.paymentAddress || '').trim();
        if (!escrowAddress) {
          res.status(400).json({ success: false, error: 'No escrow address on settlement' });
          return;
        }

        const apiBase = this.getBlockstreamApiBase();
        const utxosRes = await fetch(`${apiBase}/address/${encodeURIComponent(escrowAddress)}/utxo`);
        if (!utxosRes.ok) {
          res.status(502).json({ success: false, error: 'Failed to fetch escrow UTXOs' });
          return;
        }

        const utxos = await utxosRes.json();
        const confirmed = Array.isArray(utxos) ? utxos.filter((u: any) => u && u.status && u.status.confirmed) : [];
        const unconfirmed = Array.isArray(utxos) ? utxos.filter((u: any) => u && u.status && !u.status.confirmed) : [];
        const confirmedSum = confirmed.reduce((sum: number, u: any) => sum + Number(u?.value || 0), 0);
        const unconfirmedSum = unconfirmed.reduce((sum: number, u: any) => sum + Number(u?.value || 0), 0);

        res.json({
          success: true,
          offerId,
          itemId: String(settlement?.itemId || offerFallback?.itemId || ''),
          seller: String(settlement?.seller || offerFallback?.sellerAddress || offerFallback?.seller || ''),
          buyer: String(settlement?.buyer || offerFallback?.buyerAddress || offerFallback?.buyer || ''),
          priceSats: Number(settlement?.price || offerFallback?.sats || offerFallback?.price || 0),
          status: String(settlement?.status || offerFallback?.status || ''),
          escrowAddress,
          balances: { confirmedSats: confirmedSum, unconfirmedSats: unconfirmedSum },
          utxos: { confirmed, unconfirmed },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/offers/:offerId/escrow/sweep', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const offerId = String(req.params.offerId || '').trim();
        const toAddress = String(req.body?.toAddress || '').trim();
        const feeRateSatPerVb = req.body?.feeRateSatPerVb;
        const feeRate = typeof feeRateSatPerVb === 'number' && isFinite(feeRateSatPerVb) && feeRateSatPerVb > 0 ? feeRateSatPerVb : undefined;

        if (!offerId || !toAddress) {
          res.status(400).json({ success: false, error: 'Missing offerId or toAddress' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const settlement: any = state.settlements.get(offerId);
        const offersMap = (this.node as any).offers || new Map();
        const offerFallback: any = offersMap.get(offerId);

        if (!settlement && !offerFallback) {
          res.status(404).json({ success: false, error: 'Offer not found in canonical settlements or in-memory offers map' });
          return;
        }

        const escrowAddress = String(settlement?.escrowAddress || offerFallback?.escrowAddress || offerFallback?.paymentAddress || '').trim();
        if (!escrowAddress) {
          res.status(400).json({ success: false, error: 'No escrow address on settlement' });
          return;
        }

        const wif = this.paymentService.getPrivateKeyWifForPaymentAddress(escrowAddress);
        const txService = new BitcoinTransactionService(this.network);
        const sweep = await txService.sweepAllConfirmed(wif, toAddress, feeRate);
        if (!sweep.success) {
          res.status(400).json({ success: false, error: sweep.error || 'Sweep failed' });
          return;
        }

        res.json({
          success: true,
          offerId,
          fromEscrowAddress: sweep.fromAddress,
          toAddress,
          txid: sweep.txid,
          sentSats: sweep.sentSats,
          feeSats: sweep.feeSats,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/admin/escrow/:address', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const escrowAddress = String(req.params.address || '').trim();
        const scanLimitRaw = Number(req.query.scanLimit || 0);
        const scanLimit = Number.isFinite(scanLimitRaw) && scanLimitRaw > 0 ? Math.min(5000, Math.floor(scanLimitRaw)) : undefined;
        const includeIndex = String(req.query.includeIndex || '').trim().toLowerCase() === 'true';

        if (!escrowAddress) {
          res.status(400).json({ success: false, error: 'Missing escrow address' });
          return;
        }

        // Best-effort check that the address belongs to our payment wallet.
        // IMPORTANT: Avoid expensive scanning unless explicitly requested.
        let derivedIndex: number | null = null;
        if (includeIndex || typeof scanLimit === 'number') {
          try {
            derivedIndex = this.paymentService.findIndexForPaymentAddress(escrowAddress, scanLimit);
          } catch {}
        }

        const apiBase = this.getBlockstreamApiBase();
        const utxosRes = await fetch(`${apiBase}/address/${encodeURIComponent(escrowAddress)}/utxo`);
        if (!utxosRes.ok) {
          res.status(502).json({ success: false, error: 'Failed to fetch escrow UTXOs' });
          return;
        }

        const utxos = await utxosRes.json();
        const confirmed = Array.isArray(utxos) ? utxos.filter((u: any) => u && u.status && u.status.confirmed) : [];
        const unconfirmed = Array.isArray(utxos) ? utxos.filter((u: any) => u && u.status && !u.status.confirmed) : [];
        const confirmedSum = confirmed.reduce((sum: number, u: any) => sum + Number(u?.value || 0), 0);
        const unconfirmedSum = unconfirmed.reduce((sum: number, u: any) => sum + Number(u?.value || 0), 0);

        res.json({
          success: true,
          escrowAddress,
          derivedIndex,
          balances: { confirmedSats: confirmedSum, unconfirmedSats: unconfirmedSum },
          utxos: { confirmed, unconfirmed },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/escrow/:address/sweep', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const escrowAddress = String(req.params.address || '').trim();
        const toAddress = String(req.body?.toAddress || '').trim();
        const feeRateSatPerVb = req.body?.feeRateSatPerVb;
        const scanLimitRaw = Number(req.body?.scanLimit || 0);
        const scanLimit = Number.isFinite(scanLimitRaw) && scanLimitRaw > 0 ? Math.min(5000, Math.floor(scanLimitRaw)) : 5000;
        const feeRate = typeof feeRateSatPerVb === 'number' && isFinite(feeRateSatPerVb) && feeRateSatPerVb > 0 ? feeRateSatPerVb : undefined;

        if (!escrowAddress || !toAddress) {
          res.status(400).json({ success: false, error: 'Missing escrowAddress or toAddress' });
          return;
        }

        const wif = this.paymentService.getPrivateKeyWifForPaymentAddress(escrowAddress, scanLimit);
        const txService = new BitcoinTransactionService(this.network);
        const sweep = await txService.sweepAllConfirmed(wif, toAddress, feeRate);
        if (!sweep.success) {
          res.status(400).json({ success: false, error: sweep.error || 'Sweep failed' });
          return;
        }

        res.json({
          success: true,
          fromEscrowAddress: sweep.fromAddress,
          escrowAddress,
          toAddress,
          txid: sweep.txid,
          sentSats: sweep.sentSats,
          feeSats: sweep.feeSats,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/admin/roles/applications', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const status = String(req.query.status || 'open');
        const state = await this.canonicalStateBuilder.buildState();
        const ROLE_REVIEW_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

        const items = Array.from(state.roleApplications.values()).map((a: any) => ({
          applicationId: a.applicationId,
          accountId: a.accountId,
          requestedRole: a.requestedRole,
          companyName: a.companyName,
          contactEmail: a.contactEmail,
          website: a.website,
          notes: a.notes,
          submittedAt: a.submittedAt,
          reviewed: a.reviewed,
          finalized: a.finalized,
          voteCount: {
            approve: Array.from(a.votes.values()).filter((v: any) => v.vote === 'approve').length,
            reject: Array.from(a.votes.values()).filter((v: any) => v.vote === 'reject').length,
          },
          eligibleForVotingAt: a.submittedAt + ROLE_REVIEW_WINDOW_MS,
        }));

        const filtered = items.filter((a: any) => {
          const acc: any = state.accounts.get(String(a.accountId || '').trim());
          const accRole = acc ? String(acc.role || '') : '';
          const alreadyPrivileged = accRole === 'manufacturer' || accRole === 'authenticator';
          if (status === 'open') return !a.finalized && !a.reviewed && !alreadyPrivileged;
          if (status === 'reviewed') return !!a.reviewed && !a.finalized;
          if (status === 'finalized') return !!a.finalized;
          return true;
        });

        res.json({ success: true, applications: filtered });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/admin/retailers/verification/applications', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const status = String(req.query.status || 'open');
        const state = await this.canonicalStateBuilder.buildState();
        const reviewWindowMs = Number(process.env.RETAILER_VERIFICATION_REVIEW_WINDOW_MS || 0) || 7 * 24 * 60 * 60 * 1000;

        const items = (Array.from((state as any).retailerVerificationApplications?.values?.() || []) as any[]).map((a: any) => ({
          applicationId: a.applicationId,
          accountId: a.accountId,
          companyName: a.companyName,
          contactEmail: a.contactEmail,
          website: a.website,
          notes: a.notes,
          submittedAt: a.submittedAt,
          reviewed: a.reviewed,
          finalized: a.finalized,
          voteCount: {
            approve: Array.from(a.votes?.values?.() || []).filter((v: any) => v && v.vote === 'approve').length,
            reject: Array.from(a.votes?.values?.() || []).filter((v: any) => v && v.vote === 'reject').length,
          },
          eligibleForVotingAt: Number(a.submittedAt || 0) + reviewWindowMs,
        }));

        const filtered = items.filter((a: any) => {
          if (status === 'open') return !a.finalized && !a.reviewed;
          if (status === 'reviewed') return !!a.reviewed && !a.finalized;
          if (status === 'finalized') return !!a.finalized;
          return true;
        });

        res.json({ success: true, applications: filtered });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/roles/applications/:applicationId/review', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const { applicationId } = req.params;
        const { decision, reason } = req.body;
        const d = String(decision || '');
        if (d !== 'approve' && d !== 'reject') {
          res.status(400).json({ success: false, error: 'decision must be approve or reject' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const app = state.roleApplications.get(String(applicationId));
        if (!app) {
          res.status(404).json({ success: false, error: 'Application not found' });
          return;
        }
        if (app.finalized) {
          res.status(400).json({ success: false, error: 'Application already finalized' });
          return;
        }
        if (app.reviewed) {
          res.status(400).json({ success: false, error: 'Application already reviewed' });
          return;
        }

        const nonce1 = randomBytes(32).toString('hex');
        const nonce2 = randomBytes(32).toString('hex');
        const now = Date.now();
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_ROLE_APPLICATION_REVIEWED:${applicationId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_APPLICATION_REVIEWED,
            timestamp: now,
            nonce: nonce1,
            applicationId: String(applicationId),
            reviewerOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            decision: d,
            reason: reason ? String(reason) : undefined,
          } as any,
          signatures
        );

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_APPLICATION_FINALIZED,
            timestamp: now,
            nonce: nonce2,
            applicationId: String(applicationId),
            finalizedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            decision: d,
            reason: reason ? String(reason) : undefined,
            activeOperatorCount: (await this.canonicalStateBuilder.getActiveOperators()).length,
            approveVotes: 0,
            rejectVotes: 0,
          } as any,
          signatures
        );

        if (d === 'approve') {
          const nonce3 = randomBytes(32).toString('hex');
          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.ACCOUNT_ROLE_SET,
              timestamp: now,
              nonce: nonce3,
              accountId: String(app.accountId),
              role: String(app.requestedRole),
              reason: reason ? String(reason) : undefined,
              applicationId: String(applicationId),
              decidedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            } as any,
            signatures
          );
        }

        res.json({ success: true, applicationId: String(applicationId), decision: d });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/retailers/verification/applications/:applicationId/review', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const { applicationId } = req.params;
        const { decision, reason } = req.body;
        const d = String(decision || '');
        if (d !== 'approve' && d !== 'reject') {
          res.status(400).json({ success: false, error: 'decision must be approve or reject' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const app: any = (state as any).retailerVerificationApplications?.get?.(String(applicationId));
        if (!app) {
          res.status(404).json({ success: false, error: 'Application not found' });
          return;
        }
        if (app.finalized) {
          res.status(400).json({ success: false, error: 'Application already finalized' });
          return;
        }
        if (app.reviewed) {
          res.status(400).json({ success: false, error: 'Application already reviewed' });
          return;
        }

        const nonce1 = randomBytes(32).toString('hex');
        const now = Date.now();
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RETAILER_VERIFICATION_APPLICATION_REVIEWED:${applicationId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_REVIEWED,
            timestamp: now,
            nonce: nonce1,
            applicationId: String(applicationId),
            reviewerOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            decision: d,
            reason: reason ? String(reason) : undefined,
          } as any,
          signatures
        );

        res.json({ success: true, applicationId: String(applicationId), decision: d, reviewed: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/retailers/verification/applications/:applicationId/finalize', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const { applicationId } = req.params;
        const reason = req.body?.reason ? String(req.body.reason) : undefined;

        const state = await this.canonicalStateBuilder.buildState();
        const app: any = (state as any).retailerVerificationApplications?.get?.(String(applicationId));
        if (!app) {
          res.status(404).json({ success: false, error: 'Application not found' });
          return;
        }

        if (app.finalized) {
          res.json({
            success: true,
            applicationId: String(applicationId),
            decision: String(app.finalized?.decision || ''),
            alreadyFinalized: true,
          });
          return;
        }

        if (!app.reviewed) {
          res.status(400).json({ success: false, error: 'Application not reviewed yet' });
          return;
        }

        const decisionOverride = req.body?.decision ? String(req.body.decision) : '';
        const decision = (decisionOverride === 'approve' || decisionOverride === 'reject')
          ? decisionOverride
          : String(app.reviewed?.decision || 'reject');

        const votes = Array.from(app.votes?.values?.() || []);
        const approveVotes = votes.filter((vv: any) => vv && vv.vote === 'approve').length;
        const rejectVotes = votes.filter((vv: any) => vv && vv.vote === 'reject').length;
        const activeOperatorCount = (await this.canonicalStateBuilder.getActiveOperators()).length;

        const now = Date.now();
        const nonce1 = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RETAILER_VERIFICATION_APPLICATION_FINALIZED:${applicationId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_FINALIZED,
            timestamp: now,
            nonce: nonce1,
            applicationId: String(applicationId),
            finalizedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            decision: decision as any,
            reason,
            activeOperatorCount,
            approveVotes,
            rejectVotes,
          } as any,
          signatures
        );

        if (decision === 'approve') {
          const nonce2 = randomBytes(32).toString('hex');
          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.ACCOUNT_RETAILER_VERIFIED,
              timestamp: now,
              nonce: nonce2,
              accountId: String(app.accountId),
              verifiedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
              applicationId: String(applicationId),
              reason,
            } as any,
            signatures
          );
        }

        res.json({ success: true, applicationId: String(applicationId), decision });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/admin/retailers/verified', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const state = await this.canonicalStateBuilder.buildState();
        const retailers = Array.from(state.accounts.values())
          .filter((a: any) => String(a.role || '') === 'retailer')
          .filter((a: any) => String(a.retailerStatus || 'unverified') === 'verified')
          .map((a: any) => ({
            accountId: String(a.accountId),
            username: a.username ? String(a.username) : undefined,
            displayName: a.displayName ? String(a.displayName) : undefined,
            companyName: a.companyName ? String(a.companyName) : undefined,
            website: a.website ? String(a.website) : undefined,
            contactEmail: a.contactEmail ? String(a.contactEmail) : undefined,
            retailerStatus: String(a.retailerStatus || 'unverified'),
            retailerVerifiedAt: a.retailerVerifiedAt ? Number(a.retailerVerifiedAt) : undefined,
            retailerVerificationRevokedAt: a.retailerVerificationRevokedAt ? Number(a.retailerVerificationRevokedAt) : undefined,
            bondMinSats: a.retailerBondMinSats ? Number(a.retailerBondMinSats) : undefined,
            bondConfirmedSats: a.retailerBondConfirmedSats ? Number(a.retailerBondConfirmedSats) : undefined,
            bondMeetsMin: typeof a.retailerBondMeetsMin === 'boolean' ? Boolean(a.retailerBondMeetsMin) : undefined,
            bondLastCheckedAt: a.retailerBondLastCheckedAt ? Number(a.retailerBondLastCheckedAt) : undefined,
            ratingAvg: typeof a.retailerRatingAvg === 'number' ? Number(a.retailerRatingAvg) : undefined,
            ratingCount: typeof a.retailerRatingCount === 'number' ? Number(a.retailerRatingCount) : undefined,
            reportCount: typeof a.retailerReportCount === 'number' ? Number(a.retailerReportCount) : undefined,
          }));

        retailers.sort((a: any, b: any) => Number(b.retailerVerifiedAt || 0) - Number(a.retailerVerifiedAt || 0));
        res.json({ success: true, count: retailers.length, retailers });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/retailers/:accountId/verification/revoke', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const accountId = String(req.params.accountId || '').trim();
        const reason = req.body?.reason ? String(req.body.reason) : undefined;
        if (!accountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(accountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }
        if (String(target.role || '') !== 'retailer') {
          res.status(400).json({ success: false, error: 'Target account is not a retailer' });
          return;
        }
        if (String(target.retailerStatus || 'unverified') !== 'verified') {
          res.status(400).json({ success: false, error: 'Retailer is not verified' });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RETAILER_VERIFICATION_REVOKED:${accountId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_VERIFICATION_REVOKED,
            timestamp: now,
            nonce,
            accountId,
            revokedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            reason,
          } as any,
          signatures
        );

        res.json({ success: true, accountId, retailerStatus: 'unverified' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/roles/invites/create', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const { role, expiresInMs } = req.body;
        const rr = String(role || '');
        if (rr !== 'manufacturer' && rr !== 'authenticator') {
          res.status(400).json({ success: false, error: 'role must be manufacturer or authenticator' });
          return;
        }

        const codeHex = randomBytes(32).toString('hex');
        const codeHashHex = createHash('sha256').update(`AUTHO_ROLE_INVITE_V1\u0000${codeHex}`).digest('hex');
        const inviteId = `invite_${Date.now()}_${randomBytes(8).toString('hex')}`;
        const exp = typeof expiresInMs === 'number' && expiresInMs > 0 ? expiresInMs : 14 * 24 * 60 * 60 * 1000;
        const expiresAt = Date.now() + exp;
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_ROLE_INVITE_CREATED:${inviteId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_INVITE_CREATED,
            timestamp: Date.now(),
            nonce,
            inviteId,
            role: rr,
            codeHashHex,
            expiresAt,
            createdByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
          } as any,
          signatures
        );

        res.json({ success: true, inviteId, role: rr, codeHex, expiresAt });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/admin/verifiers', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const state = await this.canonicalStateBuilder.buildState();
        const verifiers = Array.from(state.accounts.values())
          .filter((a: any) => String(a.role) === 'manufacturer' || String(a.role) === 'authenticator')
          .map((a: any) => ({
            accountId: String(a.accountId),
            role: String(a.role),
            username: a.username ? String(a.username) : undefined,
            displayName: a.displayName ? String(a.displayName) : undefined,
            companyName: a.companyName ? String(a.companyName) : undefined,
            website: a.website ? String(a.website) : undefined,
            ratingAvg: typeof a.ratingAvg === 'number' ? Number(a.ratingAvg) : undefined,
            ratingCount: typeof a.ratingCount === 'number' ? Number(a.ratingCount) : undefined,
            reportCount: typeof a.reportCount === 'number' ? Number(a.reportCount) : undefined,
            verifierStatus: String(a.verifierStatus || 'active'),
            verifierRevokedAt: a.verifierRevokedAt ? Number(a.verifierRevokedAt) : undefined,
            verifierReactivatedAt: a.verifierReactivatedAt ? Number(a.verifierReactivatedAt) : undefined,
            bondAddress: a.bondAddress ? String(a.bondAddress) : undefined,
            bondMinSats: a.bondMinSats ? Number(a.bondMinSats) : undefined,
            bondConfirmedSats: a.bondConfirmedSats ? Number(a.bondConfirmedSats) : undefined,
            bondUtxoCount: a.bondUtxoCount ? Number(a.bondUtxoCount) : undefined,
            bondMeetsMin: typeof a.bondMeetsMin === 'boolean' ? Boolean(a.bondMeetsMin) : undefined,
            bondLastCheckedAt: a.bondLastCheckedAt ? Number(a.bondLastCheckedAt) : undefined,
          }));

        res.json({ success: true, count: verifiers.length, verifiers });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/verifiers/:accountId/revoke', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const accountId = String(req.params.accountId || '').trim();
        const reason = req.body?.reason ? String(req.body.reason) : undefined;
        if (!accountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(accountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }
        const role = String(target.role || '');
        if (role !== 'manufacturer' && role !== 'authenticator') {
          res.status(400).json({ success: false, error: 'Target account is not a manufacturer/authenticator' });
          return;
        }
        if (String(target.verifierStatus || 'active') === 'revoked') {
          res.status(400).json({ success: false, error: 'Account is already revoked' });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ACCOUNT_VERIFIER_REVOKED:${accountId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_VERIFIER_REVOKED,
            timestamp: now,
            nonce,
            accountId,
            revokedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            reason,
          } as any,
          signatures
        );

        res.json({ success: true, accountId, status: 'revoked' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/operators/approve', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const { operatorId, publicKey, btcAddress, name, description } = req.body;

        if (!operatorId || !publicKey || !btcAddress) {
          res.status(400).json({ success: false, error: 'Missing required fields: operatorId, publicKey, btcAddress' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const existingOperator = state.operators.get(operatorId);

        if (existingOperator && existingOperator.status === 'active') {
          res.status(400).json({ success: false, error: 'Operator already approved' });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`OPERATOR_ADMITTED:${operatorId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.OPERATOR_ADMITTED,
            timestamp: Date.now(),
            nonce,
            operatorId,
            btcAddress,
            publicKey,
            name,
            description,
          } as any,
          signatures
        );

        console.log(`[Admin] Operator ${operatorId} approved`);

        res.json({
          success: true,
          message: 'Operator approved successfully',
          operatorId,
        });
      } catch (error: any) {
        console.error('[Admin] Error approving operator:', error);
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/operators/reject', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const { operatorId, reason } = req.body;

        if (!operatorId || !reason) {
          res.status(400).json({ success: false, error: 'Missing required fields: operatorId, reason' });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`OPERATOR_REJECTED:${operatorId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.OPERATOR_REJECTED,
            timestamp: Date.now(),
            nonce,
            operatorId,
            reason,
          } as any,
          signatures
        );

        console.log(`[Admin] Operator ${operatorId} rejected: ${reason}`);

        res.json({
          success: true,
          message: 'Operator rejected',
          operatorId,
        });
      } catch (error: any) {
        console.error('[Admin] Error rejecting operator:', error);
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/admin/verifiers/:accountId/reactivate', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const accountId = String(req.params.accountId || '').trim();
        const reason = req.body?.reason ? String(req.body.reason) : undefined;
        if (!accountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(accountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }
        const role = String(target.role || '');
        if (role !== 'manufacturer' && role !== 'authenticator') {
          res.status(400).json({ success: false, error: 'Target account is not a manufacturer/authenticator' });
          return;
        }
        if (String(target.verifierStatus || 'active') !== 'revoked') {
          res.status(400).json({ success: false, error: 'Account is not revoked' });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ACCOUNT_VERIFIER_REACTIVATED:${accountId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_VERIFIER_REACTIVATED,
            timestamp: now,
            nonce,
            accountId,
            reactivatedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            reason,
          } as any,
          signatures
        );

        res.json({ success: true, accountId, status: 'active' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });
  }

  private setupRoutes(): void {
    // Explicit routes first (before static middleware)
    this.app.get('/', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../public/landing.html'));
    });

    this.app.get('/how-it-works', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../public/how-it-works.html'));
    });

    this.app.get('/scan', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../public/index.html'));
    });

    // Customer authentication pages
    this.app.get('/customer/signup', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../public/customer/signup.html'));
    });

    this.app.get('/customer/login', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../public/customer/login.html'));
    });

    this.app.get('/retailer', async (req: Request, res: Response) => {
      const auth = await this.getAccountFromSession(req);
      if (!auth) {
        res.redirect('/customer/login?return=/retailer');
        return;
      }
      // User is authenticated - serve the retailer dashboard
      res.sendFile(path.join(__dirname, '../../public/retailer-dashboard.html'));
    });

    this.app.get('/api/registry/head', async (req: Request, res: Response) => {
      try {
        const state = await this.canonicalStateBuilder.buildState();
        const operators = Array.from((state as any).operators?.values?.() || []) as any[];

        const now = Date.now();
        const ACTIVE_WINDOW_MS = 36 * 60 * 60 * 1000;
        const activeOperators = operators.filter((o: any) => {
          if (!o || String(o.status || '') !== 'active') return false;
          const last = Number(o.lastHeartbeatAt || o.lastActiveAt || 0);
          if (!last) return false;
          return (now - last) <= ACTIVE_WINDOW_MS;
        });

        res.json({
          success: true,
          lastEventSequence: (state as any).lastEventSequence,
          lastEventHash: (state as any).lastEventHash,
          activeOperatorCount: activeOperators.length,
          activeOperatorIds: activeOperators.map((o: any) => String(o.operatorId || '')).filter(Boolean),
          timestamp: Date.now(),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/ledger/events/latest', async (req: Request, res: Response) => {
      try {
        const limitRaw = Number(req.query.limit || 20);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(200, Math.floor(limitRaw)) : 20;

        const head = this.canonicalEventStore.getState();
        const toSequence = Number((head as any)?.sequenceNumber || 0);
        const fromSequence = Math.max(1, toSequence - limit + 1);

        const events = toSequence > 0
          ? await this.canonicalEventStore.getEventsBySequence(fromSequence, toSequence)
          : [];

        res.json({
          success: true,
          head: {
            sequenceNumber: toSequence,
            headHash: String((head as any)?.headHash || ''),
          },
          events: events
            .map((e: any) => ({
              sequenceNumber: Number(e?.sequenceNumber || 0),
              eventHash: String(e?.eventHash || ''),
              type: String(e?.payload?.type || ''),
              timestamp: Number(e?.payload?.timestamp || e?.createdAt || 0),
            }))
            .sort((a: any, b: any) => b.sequenceNumber - a.sequenceNumber),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Consensus status endpoint for monitoring
    this.app.get('/api/consensus/status', async (req: Request, res: Response) => {
      try {
        if (!this.consensusNode) {
          res.json({
            success: false,
            error: 'Consensus not initialized',
          });
          return;
        }

        const consensusState = this.consensusNode.getState();
        const checkpoints = this.consensusNode.getCheckpoints();

        const head = this.canonicalEventStore.getState();
        const ledgerSequence = Number((head as any)?.sequenceNumber || 0);
        const ledgerHash = String((head as any)?.headHash || '');

        const openWs = Array.from(this.wsConnections.entries()).filter(([ws]) => ws.readyState === WebSocket.OPEN);
        const operatorConnections = openWs.filter(([, c]) => c.type === 'operator').length;
        const gatewayConnections = openWs.filter(([, c]) => c.type === 'gateway' && !c.isUi).length;
        const uiConnections = openWs.filter(([, c]) => c.type === 'gateway' && c.isUi).length;

        res.json({
          success: true,
          nodeId: process.env.OPERATOR_ID || 'main-operator',
          isMainNode: true,
          consensus: {
            currentCheckpointNumber: consensusState.currentCheckpointNumber,
            lastCheckpointHash: consensusState.lastCheckpointHash,
            lastCheckpointAt: consensusState.lastCheckpointAt,
            isLeader: consensusState.isLeader,
            currentLeaderId: consensusState.currentLeaderId,
            activeOperators: consensusState.activeOperators,
            pendingProposal: consensusState.pendingProposal ? {
              checkpointNumber: consensusState.pendingProposal.checkpointNumber,
              proposedBy: consensusState.pendingProposal.proposedBy,
              eventCount: consensusState.pendingProposal.eventIds.length,
            } : null,
          },
          mempool: {
            totalEvents: consensusState.mempoolStats.totalEvents,
            validEvents: consensusState.mempoolStats.validEvents,
            invalidEvents: consensusState.mempoolStats.invalidEvents,
            pendingEvents: consensusState.mempoolStats.pendingEvents,
            eventsByType: consensusState.mempoolStats.eventsByType,
            oldestEventAge: consensusState.mempoolStats.oldestEventAge,
          },
          checkpoints: {
            total: checkpoints.length,
            recent: checkpoints.slice(-5).map(c => ({
              number: c.checkpointNumber,
              hash: c.checkpointHash.substring(0, 16) + '...',
              eventCount: c.events.length,
              finalizedAt: c.finalizedAt,
              yesVotes: c.totalYesVotes,
              noVotes: c.totalNoVotes,
            })),
          },
          connections: {
            totalWsConnections: openWs.length,
            operatorConnections,
            gatewayConnections,
            uiConnections,
          },
          ledger: {
            sequenceNumber: ledgerSequence,
            lastEventHash: ledgerHash,
          },
          ledgerSequence,
          timestamp: Date.now(),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Public registry head (safe for gateways)
    // Provides a minimal chain head for sync checks without exposing account emails.
    this.app.get('/api/network/status', async (req: Request, res: Response) => {
      try {
        const state = await this.canonicalStateBuilder.buildState();
        const operators = Array.from(state.operators.values());

        res.json({
          success: true,
          totalOperators: operators.length,
          activeOperators: operators.filter((o: any) => o.status === 'active').length,
          lastEventSequence: state.lastEventSequence,
          lastEventHash: state.lastEventHash,
          operators: operators.map((op: any) => ({
            operatorId: op.operatorId,
            btcAddress: op.btcAddress,
            publicKey: op.publicKey,
            operatorUrl: op.operatorUrl,
            status: op.status || 'pending',
            name: op.name,
            description: op.description,
            admittedAt: op.admittedAt,
          })),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Operator discovery endpoint for gateway nodes
    this.app.get('/api/network/operators', async (req: Request, res: Response) => {
      try {
        const state = await this.canonicalStateBuilder.buildState();
        const operators = Array.from(state.operators.values()) as any[];
        const now = Date.now();
        const activeWindowMs = 36 * 60 * 60 * 1000;
        const activeOperators = operators.filter((o: any) => {
          if (!o || o.status !== 'active') return false;
          const lastHeartbeatAt = Number(o.lastHeartbeatAt || 0);
          const lastActiveAt = Number(o.lastActiveAt || 0);
          const admittedAt = Number(o.admittedAt || 0);
          const lastSeenAt = Math.max(lastHeartbeatAt, lastActiveAt, admittedAt);
          if (!Number.isFinite(lastSeenAt) || lastSeenAt <= 0) return false;
          return (now - lastSeenAt) <= activeWindowMs;
        });

        const operatorList = activeOperators.map((op: any) => {
          const operatorUrl = String(op.operatorUrl || '').trim();
          let wsUrl = '';
          
          if (operatorUrl) {
            // Convert HTTP(S) URL to WebSocket URL
            if (operatorUrl.startsWith('https://')) {
              wsUrl = operatorUrl.replace('https://', 'wss://');
            } else if (operatorUrl.startsWith('http://')) {
              wsUrl = operatorUrl.replace('http://', 'ws://');
            } else if (operatorUrl.includes('localhost') || operatorUrl.includes('127.0.0.1')) {
              wsUrl = `ws://${operatorUrl}`;
            } else {
              wsUrl = `wss://${operatorUrl}`;
            }
          }

          return {
            operatorId: String(op.operatorId || ''),
            operatorUrl: operatorUrl,
            wsUrl: wsUrl,
            btcAddress: String(op.btcAddress || ''),
            status: 'active',
            admittedAt: op.admittedAt,
            lastHeartbeatAt: op.lastHeartbeatAt,
            lastActiveAt: op.lastActiveAt,
          };
        }).filter((op: any) => op.wsUrl); // Only include operators with valid WebSocket URLs

        res.json({
          success: true,
          timestamp: Date.now(),
          network: this.network,
          currentSequence: state.lastEventSequence,
          activeWindowMs,
          operators: operatorList,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Mesh network diagnostic endpoint - shows all connected nodes
    this.app.get('/api/network/mesh', async (req: Request, res: Response) => {
      try {
        const now = Date.now();
        const openWs = Array.from(this.wsConnections.entries()).filter(([ws]) => ws.readyState === WebSocket.OPEN);

        const operators = openWs
          .filter(([, c]) => c.type === 'operator')
          .map(([, c]) => ({
            operatorId: c.operatorId || 'unknown',
            connectedAt: c.connectedAt,
            lastSeen: c.lastSeen,
            ageMs: now - c.connectedAt,
            ip: c.ip,
          }));

        const gateways = openWs
          .filter(([, c]) => c.type === 'gateway' && !c.isUi)
          .map(([, c]) => ({
            connectedAt: c.connectedAt,
            lastSeen: c.lastSeen,
            ageMs: now - c.connectedAt,
            ip: c.ip,
          }));

        const uiClients = openWs
          .filter(([, c]) => c.type === 'gateway' && c.isUi)
          .map(([, c]) => ({
            connectedAt: c.connectedAt,
            lastSeen: c.lastSeen,
            subscribedToConsensus: c.subscribedToConsensus || false,
            ip: c.ip,
          }));

        const state = await this.canonicalStateBuilder.buildState();
        const allOperators = Array.from((state as any).operators?.values?.() || []) as any[];
        const activeOperators = allOperators.filter((o: any) => o && o.status === 'active');

        res.json({
          success: true,
          timestamp: now,
          nodeType: 'main',
          mesh: {
            connectedOperators: operators.length,
            connectedGateways: gateways.length,
            uiClients: uiClients.length,
            totalConnections: openWs.length,
          },
          operators: {
            connected: operators,
            registeredActive: activeOperators.length,
          },
          gateways: {
            connected: gateways,
          },
          ledger: {
            sequenceNumber: (state as any).lastEventSequence || 0,
            lastEventHash: (state as any).lastEventHash || '',
          },
          consensus: this.consensusNode ? {
            currentCheckpoint: this.consensusNode.getState().currentCheckpointNumber,
            isLeader: this.consensusNode.getState().isLeader,
            mempoolSize: this.consensusNode.getState().mempoolStats.totalEvents,
          } : null,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Operator application (self-serve)
    // 1) Applicant requests a nonce
    this.app.post('/api/operators/apply/challenge', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const challengeId = `op_apply_${Date.now()}_${randomBytes(8).toString('hex')}`;
        const nonce = randomBytes(32).toString('hex');
        const createdAt = Date.now();
        const expiresAt = createdAt + 5 * 60 * 1000;

        this.operatorApplyChallenges.set(challengeId, {
          challengeId,
          accountId: String((account as any).accountId || ''),
          nonce,
          createdAt,
          expiresAt,
          used: false,
        });

        res.json({ success: true, challengeId, nonce, expiresAt });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // 2) Applicant submits operator details + signature proving possession of operator private key
    this.app.post('/api/operators/apply', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const accountId = String((account as any).accountId || '').trim();
        const { challengeId, operatorId, publicKey, btcAddress, operatorUrl, signature } = req.body || {};

        if (!challengeId || !operatorId || !publicKey || !btcAddress || !operatorUrl || !signature) {
          res.status(400).json({
            success: false,
            error: 'Missing required fields: challengeId, operatorId, publicKey, btcAddress, operatorUrl, signature',
          });
          return;
        }

        const url = String(operatorUrl).trim();
        const isHttps = /^https:\/\//i.test(url);
        const isOnion = /^https?:\/\//i.test(url) && /\.onion(\/|$)/i.test(url);
        if (!isHttps && !isOnion) {
          res.status(400).json({ success: false, error: 'operatorUrl must start with https:// (or be an http(s)://*.onion URL)' });
          return;
        }

        const chall = this.operatorApplyChallenges.get(String(challengeId));
        if (!chall || chall.accountId !== accountId || chall.used || Date.now() > chall.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired challenge' });
          return;
        }

        const sigOk = verifySignature(String(chall.nonce), String(signature), String(publicKey));
        if (!sigOk) {
          res.status(401).json({ success: false, error: 'Invalid signature' });
          return;
        }
        chall.used = true;

        // Prevent overwriting an existing operator record (candidate/active)
        const state = await this.canonicalStateBuilder.buildState();
        const existing = state.operators.get(String(operatorId));
        if (existing) {
          res.status(409).json({ success: false, error: 'operatorId already exists' });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');

        const ACTIVE_WINDOW_MS = 60 * 24 * 60 * 60 * 1000;
        const activeOps = await this.canonicalStateBuilder.getActiveOperators();
        const eligibleVoterIds = activeOps
          .filter((o: any) => {
            const last = Number(o?.lastActiveAt || o?.lastHeartbeatAt || o?.admittedAt || 0);
            return last > 0 && (now - last) <= ACTIVE_WINDOW_MS;
          })
          .map((o: any) => String(o.operatorId || '').trim())
          .filter((id: string) => Boolean(id));

        const eligibleVoterCount = eligibleVoterIds.length;
        const requiredYesVotes = eligibleVoterCount > 0 ? Math.ceil((2 / 3) * eligibleVoterCount) : undefined;
        const eligibleVotingAt = now + 30 * 24 * 60 * 60 * 1000;

        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`OPERATOR_CANDIDATE_REQUESTED:${operatorId}:${Date.now()}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.OPERATOR_CANDIDATE_REQUESTED,
            timestamp: now,
            nonce,
            candidateId: String(operatorId),
            gatewayNodeId: String(url),
            operatorUrl: String(url),
            btcAddress: String(btcAddress).trim(),
            publicKey: String(publicKey).trim(),
            sponsorId: accountId,
            eligibleVoterIds,
            eligibleVoterCount,
            requiredYesVotes,
            eligibleVotingAt,
          } as any,
          signatures
        );

        res.json({
          success: true,
          message: 'Operator application submitted',
          candidateId: String(operatorId),
          operatorUrl: String(url),
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/operators/candidates', async (req: Request, res: Response) => {
      try {
        // Allow either admin session OR operator session to view candidates
        const authz = String(req.headers.authorization || '');
        const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';
        const adminSess = token ? this.getAdminSession(token) : null;
        
        if (!adminSess) {
          // Fall back to operator auth
          const op = await this.requireOperatorAccount(req, res);
          if (!op) return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const status = String(req.query.status || 'open');
        const items = Array.from((state as any).operators?.values?.() || [])
          .filter((o: any) => o && String(o.status || '') === 'candidate')
          .map((c: any) => ({
            operatorId: String(c.operatorId || ''),
            btcAddress: String(c.btcAddress || ''),
            publicKey: String(c.publicKey || ''),
            operatorUrl: String(c.operatorUrl || ''),
            sponsorId: String(c.sponsorId || ''),
            candidateRequestedAt: Number(c.candidateRequestedAt || 0),
            eligibleVotingAt: Number(c.eligibleVotingAt || 0),
            eligibleVoterCount: Number(c.eligibleVoterCount || (Array.isArray(c.eligibleVoterIds) ? c.eligibleVoterIds.length : 0) || 0),
            requiredYesVotes: Number(c.requiredYesVotes || 0),
            voteCount: c.voteCount || { approve: 0, reject: 0 },
          }));

        const now = Date.now();
        const filtered = items.filter((c: any) => {
          if (status === 'open') return now < Number(c.eligibleVotingAt || 0);
          if (status === 'voting') return now >= Number(c.eligibleVotingAt || 0);
          return true;
        });

        res.json({ success: true, candidates: filtered });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/operators/candidates/:candidateId/vote', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const voterId = String(process.env.OPERATOR_ID || '').trim();
        if (!voterId) {
          res.status(500).json({ success: false, error: 'OPERATOR_ID is not configured on this node' });
          return;
        }

        const candidateId = String(req.params.candidateId || '').trim();
        const v = String(req.body?.vote || '').trim();
        const reason = req.body?.reason ? String(req.body.reason) : undefined;
        if (v !== 'approve' && v !== 'reject') {
          res.status(400).json({ success: false, error: 'vote must be approve or reject' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const c = (state as any).operators?.get?.(candidateId);
        if (!c || String(c.status || '') !== 'candidate') {
          res.status(404).json({ success: false, error: 'Candidate not found' });
          return;
        }

        const eligibleVotingAt = Number(c.eligibleVotingAt || 0);
        if (eligibleVotingAt && Date.now() < eligibleVotingAt) {
          res.status(400).json({ success: false, error: 'Voting not yet enabled (founder window still open)' });
          return;
        }

        const eligibleVoterIds = Array.isArray(c.eligibleVoterIds) ? (c.eligibleVoterIds as any[]).map((x) => String(x)) : [];
        if (eligibleVoterIds.length > 0 && !eligibleVoterIds.includes(voterId)) {
          res.status(403).json({ success: false, error: 'Not eligible to vote on this candidate' });
          return;
        }

        if (c.votes && c.votes.has && c.votes.has(voterId)) {
          res.status(400).json({ success: false, error: 'Already voted' });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const now = Date.now();
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`OPERATOR_CANDIDATE_VOTE:${candidateId}:${voterId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.OPERATOR_CANDIDATE_VOTE,
            timestamp: now,
            nonce,
            candidateId,
            voterId,
            vote: v,
            reason,
          } as any,
          signatures
        );

        res.json({ success: true, candidateId, voterId, vote: v });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/operators/candidates/:candidateId/finalize', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const candidateId = String(req.params.candidateId || '').trim();
        const state = await this.canonicalStateBuilder.buildState();
        const c = (state as any).operators?.get?.(candidateId);
        if (!c || String(c.status || '') !== 'candidate') {
          res.status(404).json({ success: false, error: 'Candidate not found' });
          return;
        }

        const eligibleVotingAt = Number(c.eligibleVotingAt || 0);
        if (eligibleVotingAt && Date.now() < eligibleVotingAt) {
          res.status(400).json({ success: false, error: 'Finalize not yet enabled (founder window still open)' });
          return;
        }

        const eligibleVoterIds = Array.isArray(c.eligibleVoterIds) ? (c.eligibleVoterIds as any[]).map((x) => String(x)) : [];
        const eligibleVoterCount = Number(c.eligibleVoterCount || (eligibleVoterIds.length || 0) || 0);
        const requiredYesVotes = Number(c.requiredYesVotes || 0) || (eligibleVoterCount > 0 ? Math.ceil((2 / 3) * eligibleVoterCount) : 0);

        const votesArr = Array.from((c.votes?.values?.() || []) as any[]);
        const countedVotes = eligibleVoterIds.length > 0
          ? votesArr.filter((v: any) => eligibleVoterIds.includes(String(v.voterId)))
          : votesArr;

        const approveVotes = countedVotes.filter((v: any) => String(v.vote) === 'approve').length;
        const rejectVotes = countedVotes.filter((v: any) => String(v.vote) === 'reject').length;

        let decision: 'approve' | 'reject' | null = null;
        if (requiredYesVotes > 0 && approveVotes >= requiredYesVotes) decision = 'approve';
        if (requiredYesVotes > 0 && rejectVotes >= requiredYesVotes) decision = 'reject';

        if (!decision) {
          res.status(409).json({
            success: false,
            error: 'Not enough votes to finalize',
            approveVotes,
            rejectVotes,
            eligibleVoterCount,
            requiredYesVotes,
          });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`OPERATOR_CANDIDATE_FINALIZED:${candidateId}:${decision}:${now}`)
              .digest('hex'),
          },
        ];

        if (decision === 'approve') {
          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.OPERATOR_ADMITTED,
              timestamp: now,
              nonce,
              operatorId: String(c.operatorId),
              btcAddress: String(c.btcAddress),
              publicKey: String(c.publicKey),
            } as any,
            signatures
          );
        } else {
          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.OPERATOR_REJECTED,
              timestamp: now,
              nonce,
              operatorId: String(c.operatorId),
              reason: 'operator_vote',
            } as any,
            signatures
          );
        }

        res.json({
          success: true,
          candidateId,
          decision,
          approveVotes,
          rejectVotes,
          eligibleVoterCount,
          requiredYesVotes,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/verifiers', async (req: Request, res: Response) => {
      try {
        const state = await this.canonicalStateBuilder.buildState();
        const bondMinSats = Number(process.env.VERIFIER_BOND_MIN_SATS || 100000);
        const bondMaxAgeMs = Number(process.env.VERIFIER_BOND_MAX_AGE_MS || 0) || 24 * 60 * 60 * 1000;

        const verifiers = Array.from(state.accounts.values())
          .filter((a: any) => String(a.role) === 'manufacturer' || String(a.role) === 'authenticator')
          .filter((a: any) => String(a.verifierStatus || 'active') !== 'revoked')
          .filter((a: any) => {
            if (!(bondMinSats > 0)) return true;
            const meets = Boolean(a.bondMeetsMin);
            const last = Number(a.bondLastCheckedAt || 0);
            return meets && last > 0 && (Date.now() - last) <= bondMaxAgeMs;
          })
          .map((a: any) => ({
            accountId: String(a.accountId),
            role: String(a.role),
            username: a.username ? String(a.username) : undefined,
            displayName: a.displayName ? String(a.displayName) : undefined,
            companyName: a.companyName ? String(a.companyName) : undefined,
            website: a.website ? String(a.website) : undefined,
            walletAddress: a.walletAddress ? String(a.walletAddress) : undefined,
            verifierStatus: String(a.verifierStatus || 'active'),
            ratingAvg: typeof a.ratingAvg === 'number' ? Number(a.ratingAvg) : undefined,
            ratingCount: typeof a.ratingCount === 'number' ? Number(a.ratingCount) : undefined,
            reportCount: typeof a.reportCount === 'number' ? Number(a.reportCount) : undefined,
            bondMinSats: a.bondMinSats ? Number(a.bondMinSats) : undefined,
            bondConfirmedSats: a.bondConfirmedSats ? Number(a.bondConfirmedSats) : undefined,
            bondMeetsMin: typeof a.bondMeetsMin === 'boolean' ? Boolean(a.bondMeetsMin) : undefined,
            bondLastCheckedAt: a.bondLastCheckedAt ? Number(a.bondLastCheckedAt) : undefined,
          }));

        res.json({ success: true, count: verifiers.length, verifiers });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/verifiers/:accountId/profile', async (req: Request, res: Response) => {
      try {
        const accountId = String(req.params.accountId || '').trim();
        if (!accountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const a: any = state.accounts.get(accountId);
        if (!a) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const role = String(a.role || '');
        if (role !== 'manufacturer' && role !== 'authenticator') {
          res.status(400).json({ success: false, error: 'Account is not a manufacturer/authenticator' });
          return;
        }

        res.json({
          success: true,
          profile: {
            accountId: String(a.accountId),
            role,
            username: a.username ? String(a.username) : undefined,
            displayName: a.displayName ? String(a.displayName) : undefined,
            companyName: a.companyName ? String(a.companyName) : undefined,
            website: a.website ? String(a.website) : undefined,
            phone: a.phone ? String(a.phone) : undefined,
            address: a.address ? String(a.address) : undefined,
            contactEmail: a.contactEmail ? String(a.contactEmail) : undefined,
            notes: a.notes ? String(a.notes) : undefined,
            walletAddress: a.walletAddress ? String(a.walletAddress) : undefined,
            verifierStatus: String(a.verifierStatus || 'active'),
            verifierRevokedAt: a.verifierRevokedAt ? Number(a.verifierRevokedAt) : undefined,
            verifierReactivatedAt: a.verifierReactivatedAt ? Number(a.verifierReactivatedAt) : undefined,
            ratingAvg: typeof a.ratingAvg === 'number' ? Number(a.ratingAvg) : undefined,
            ratingCount: typeof a.ratingCount === 'number' ? Number(a.ratingCount) : undefined,
            reportCount: typeof a.reportCount === 'number' ? Number(a.reportCount) : undefined,
            bondAddress: a.bondAddress ? String(a.bondAddress) : undefined,
            bondMinSats: a.bondMinSats ? Number(a.bondMinSats) : undefined,
            bondConfirmedSats: a.bondConfirmedSats ? Number(a.bondConfirmedSats) : undefined,
            bondUtxoCount: a.bondUtxoCount ? Number(a.bondUtxoCount) : undefined,
            bondMeetsMin: typeof a.bondMeetsMin === 'boolean' ? Boolean(a.bondMeetsMin) : undefined,
            bondLastCheckedAt: a.bondLastCheckedAt ? Number(a.bondLastCheckedAt) : undefined,
            createdAt: a.createdAt ? Number(a.createdAt) : undefined,
            updatedAt: a.updatedAt ? Number(a.updatedAt) : undefined,
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/verifiers/:accountId/reputation/eligible', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const targetAccountId = String(req.params.accountId || '').trim();
        if (!targetAccountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(targetAccountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }
        const role = String(target.role || '');
        if (role !== 'manufacturer' && role !== 'authenticator') {
          res.status(400).json({ success: false, error: 'Account is not a manufacturer/authenticator' });
          return;
        }

        const wallet = String((account as any).walletAddress || '').trim();
        if (!wallet) {
          res.status(400).json({ success: false, error: 'Account has no wallet address' });
          return;
        }

        const ratingFeeMinSats = Number(process.env.VERIFIER_RATING_FEE_MIN_SATS || 0);
        const ratingFeeConfirmations = Number(process.env.VERIFIER_RATING_FEE_CONFIRMATIONS || 1);
        const feeAddress = this.getFeeAddress();

        const raterAccountId = String((account as any).accountId || '').trim();
        const now = Date.now();
        const limits = this.getReputationLimits();
        const usage = this.computeReputationUsage({
          state,
          now,
          raterAccountId,
          targetAccountId,
        });
        const items = Array.from(state.items.values())
          .filter((it: any) => String(it.issuerAccountId || '') === targetAccountId)
          .filter((it: any) => String(it.currentOwner || '') === wallet)
          .map((it: any) => ({
            contextType: 'issuer_item',
            contextId: String(it.itemId),
            label: `Item ${String(it.itemId).substring(0, 10)}...`,
          }));

        const authenticatedItems = Array.from(state.items.values())
          .filter((it: any) => String(it.currentOwner || '') === wallet)
          .filter((it: any) => Array.isArray(it.authentications) && it.authentications.some((a: any) => String(a?.authenticatorId || '') === targetAccountId))
          .map((it: any) => ({
            contextType: 'authenticated_item',
            contextId: String(it.itemId),
            label: `Authenticated item ${String(it.itemId).substring(0, 10)}...`,
          }));

        const jobs = Array.from(state.verificationRequests.values())
          .filter((vr: any) => String(vr.status || '') === 'completed')
          .filter((vr: any) => String(vr.authenticatorId || '') === targetAccountId)
          .filter((vr: any) => String(vr.ownerWallet || '') === wallet)
          .map((vr: any) => ({
            contextType: 'verification_request',
            contextId: String(vr.requestId),
            label: `Job ${String(vr.requestId).substring(0, 10)}... (${String(vr.itemId).substring(0, 10)}...)`,
          }));

        const contexts = [...items, ...authenticatedItems, ...jobs].map((c: any) => {
          const key = `${targetAccountId}\u0000${raterAccountId}\u0000${String(c.contextType)}\u0000${String(c.contextId)}`;
          const existingRating: any = (state as any).verifierRatings?.get?.(key);
          const existingReport: any = (state as any).verifierReports?.get?.(key);
          return {
            ...c,
            hasRated: Boolean(existingRating),
            myRating: existingRating ? Number(existingRating.rating || 0) : undefined,
            hasReported: Boolean(existingReport),
          };
        });

        res.json({
          success: true,
          targetAccountId,
          contexts,
          ratingFee: {
            enabled: Number.isFinite(ratingFeeMinSats) && ratingFeeMinSats > 0,
            feeMinSats: Number.isFinite(ratingFeeMinSats) ? ratingFeeMinSats : 0,
            requiredConfirmations: Number.isFinite(ratingFeeConfirmations) && ratingFeeConfirmations > 0 ? ratingFeeConfirmations : 1,
            feeAddress,
          },
          limits,
          usage,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/verifiers/:accountId/rate', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const targetAccountId = String(req.params.accountId || '').trim();
        const contextType = String(req.body?.contextType || '').trim();
        const contextId = String(req.body?.contextId || '').trim();
        const rating = Number(req.body?.rating || 0);
        const feeTxidRaw = req.body?.feeTxid ? String(req.body.feeTxid).trim().toLowerCase() : '';
        if (!targetAccountId || !contextId || !(rating >= 1 && rating <= 5)) {
          res.status(400).json({ success: false, error: 'Invalid targetAccountId, contextId, or rating (1..5)' });
          return;
        }
        if (contextType !== 'issuer_item' && contextType !== 'authenticated_item' && contextType !== 'verification_request') {
          res.status(400).json({ success: false, error: 'Invalid contextType' });
          return;
        }

        const raterAccountId = String((account as any).accountId || '').trim();
        const wallet = String((account as any).walletAddress || '').trim();
        if (!wallet) {
          res.status(400).json({ success: false, error: 'Account has no wallet address' });
          return;
        }
        if (raterAccountId && raterAccountId === targetAccountId) {
          res.status(400).json({ success: false, error: 'Cannot rate self' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(targetAccountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Target account not found' });
          return;
        }
        const role = String(target.role || '');
        if (role !== 'manufacturer' && role !== 'authenticator') {
          res.status(400).json({ success: false, error: 'Target is not a manufacturer/authenticator' });
          return;
        }

        let eligible = false;
        if (contextType === 'issuer_item') {
          const item: any = state.items.get(contextId);
          if (item && String(item.issuerAccountId || '') === targetAccountId && String(item.currentOwner || '') === wallet) eligible = true;
        }
        if (contextType === 'authenticated_item') {
          const item: any = state.items.get(contextId);
          if (item && String(item.currentOwner || '') === wallet && Array.isArray(item.authentications) && item.authentications.some((a: any) => String(a?.authenticatorId || '') === targetAccountId)) eligible = true;
        }
        if (contextType === 'verification_request') {
          const vr: any = state.verificationRequests.get(contextId);
          if (vr && String(vr.status || '') === 'completed' && String(vr.authenticatorId || '') === targetAccountId && String(vr.ownerWallet || '') === wallet) eligible = true;
        }
        if (!eligible) {
          res.status(403).json({ success: false, error: 'Not eligible to rate for this context' });
          return;
        }

        // ANTI-REVIEW-BOMBING: Check if this item has already been used for a review against this authenticator
        // This prevents the attack where an item is transferred between colluding accounts to submit multiple bad reviews
        if (contextType === 'authenticated_item' || contextType === 'issuer_item') {
          const itemAlreadyRated = Array.from((state as any).verifierRatings?.values?.() || [])
            .some((x: any) => x && 
              String(x.contextType || '') === contextType && 
              String(x.contextId || '') === contextId && 
              String(x.targetAccountId || '') === targetAccountId
            );
          const itemAlreadyReported = Array.from((state as any).verifierReports?.values?.() || [])
            .some((x: any) => x && 
              String(x.contextType || '') === contextType && 
              String(x.contextId || '') === contextId && 
              String(x.targetAccountId || '') === targetAccountId
            );
          if (itemAlreadyRated || itemAlreadyReported) {
            res.status(400).json({ 
              success: false, 
              error: 'This item has already been used to rate/report this verifier. Each item can only generate one review per authenticator to prevent review bombing.' 
            });
            return;
          }
        }

        const now = Date.now();
        const limits = this.getReputationLimits();
        const usage = this.computeReputationUsage({
          state,
          now,
          raterAccountId,
          targetAccountId,
        });

        if (limits.maxRatingsPerWindow > 0 && usage.ratingsInWindow >= limits.maxRatingsPerWindow) {
          res.status(429).json({ success: false, error: 'Rating rate limit exceeded', limits, usage });
          return;
        }
        if (limits.maxContextsPerVerifier > 0 && usage.distinctContextsForTarget >= limits.maxContextsPerVerifier) {
          const ctxKey = `${contextType}\u0000${contextId}`;
          const alreadyUsed = [
            ...Array.from((state as any).verifierRatings?.values?.() || [])
              .filter((x: any) => x && String(x.raterAccountId || '') === raterAccountId && String(x.targetAccountId || '') === targetAccountId)
              .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
            ...Array.from((state as any).verifierReports?.values?.() || [])
              .filter((x: any) => x && String(x.reporterAccountId || '') === raterAccountId && String(x.targetAccountId || '') === targetAccountId)
              .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
          ].includes(ctxKey);
          if (!alreadyUsed) {
            res.status(429).json({ success: false, error: 'Per-verifier context limit exceeded', limits, usage });
            return;
          }
        }

        const ratingFeeMinSats = Number(process.env.VERIFIER_RATING_FEE_MIN_SATS || 0);
        const ratingFeeConfirmations = Number(process.env.VERIFIER_RATING_FEE_CONFIRMATIONS || 1);
        let feePaidSats: number | undefined;
        let feeBlockHeight: number | undefined;
        let feeConfirmations: number | undefined;
        let feeTxid: string | undefined;

        if (Number.isFinite(ratingFeeMinSats) && ratingFeeMinSats > 0) {
          if (!/^[0-9a-f]{64}$/.test(feeTxidRaw)) {
            res.status(400).json({ success: false, error: 'Missing or invalid feeTxid' });
            return;
          }
          if ((state as any).verifierRatingFeeTxids?.has?.(feeTxidRaw)) {
            res.status(400).json({ success: false, error: 'feeTxid already used' });
            return;
          }

          const requiredConfs = Number.isFinite(ratingFeeConfirmations) && ratingFeeConfirmations > 0 ? ratingFeeConfirmations : 1;
          const status = await this.fetchTxStatus(feeTxidRaw);
          if (!status.confirmed || status.confirmations < requiredConfs) {
            res.status(400).json({
              success: false,
              error: 'Fee transaction is not sufficiently confirmed',
              confirmations: status.confirmations,
              requiredConfirmations: requiredConfs,
              blockHeight: status.blockHeight,
            });
            return;
          }

          const txHex = await this.fetchTxHex(feeTxidRaw);
          const parsed = this.parseRatingFeeTx(txHex);
          if (!parsed.hasFeeOutput) {
            res.status(400).json({ success: false, error: 'Fee transaction does not pay the fee address' });
            return;
          }
          if (parsed.feePaidSats < ratingFeeMinSats) {
            res.status(400).json({ success: false, error: `Fee transaction amount is below minimum required sats (${ratingFeeMinSats})` });
            return;
          }

          feeTxid = feeTxidRaw;
          feePaidSats = parsed.feePaidSats;
          feeBlockHeight = status.blockHeight;
          feeConfirmations = status.confirmations;
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_VERIFIER_RATED:${targetAccountId}:${raterAccountId}:${contextType}:${contextId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_VERIFIER_RATED,
            timestamp: now,
            nonce,
            targetAccountId,
            raterAccountId,
            contextType,
            contextId,
            rating,
            feeTxid,
            feePaidSats,
            feeBlockHeight,
            feeConfirmations,
          } as any,
          signatures
        );

        res.json({ success: true, targetAccountId, contextType, contextId, rating, feeTxid, feePaidSats, feeConfirmations, feeBlockHeight });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/verifiers/:accountId/report', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const targetAccountId = String(req.params.accountId || '').trim();
        const contextType = String(req.body?.contextType || '').trim();
        const contextId = String(req.body?.contextId || '').trim();
        const reasonCode = req.body?.reasonCode ? String(req.body.reasonCode).trim() : undefined;
        const details = req.body?.details ? String(req.body.details).trim() : undefined;
        if (!targetAccountId || !contextId) {
          res.status(400).json({ success: false, error: 'Invalid targetAccountId or contextId' });
          return;
        }
        if (contextType !== 'issuer_item' && contextType !== 'authenticated_item' && contextType !== 'verification_request') {
          res.status(400).json({ success: false, error: 'Invalid contextType' });
          return;
        }

        const reporterAccountId = String((account as any).accountId || '').trim();
        const wallet = String((account as any).walletAddress || '').trim();
        if (!wallet) {
          res.status(400).json({ success: false, error: 'Account has no wallet address' });
          return;
        }
        if (reporterAccountId && reporterAccountId === targetAccountId) {
          res.status(400).json({ success: false, error: 'Cannot report self' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(targetAccountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Target account not found' });
          return;
        }
        const role = String(target.role || '');
        if (role !== 'manufacturer' && role !== 'authenticator') {
          res.status(400).json({ success: false, error: 'Target is not a manufacturer/authenticator' });
          return;
        }

        let eligible = false;
        if (contextType === 'issuer_item') {
          const item: any = state.items.get(contextId);
          if (item && String(item.issuerAccountId || '') === targetAccountId && String(item.currentOwner || '') === wallet) eligible = true;
        }
        if (contextType === 'authenticated_item') {
          const item: any = state.items.get(contextId);
          if (item && String(item.currentOwner || '') === wallet && Array.isArray(item.authentications) && item.authentications.some((a: any) => String(a?.authenticatorId || '') === targetAccountId)) eligible = true;
        }
        if (contextType === 'verification_request') {
          const vr: any = state.verificationRequests.get(contextId);
          if (vr && String(vr.status || '') === 'completed' && String(vr.authenticatorId || '') === targetAccountId && String(vr.ownerWallet || '') === wallet) eligible = true;
        }
        if (!eligible) {
          res.status(403).json({ success: false, error: 'Not eligible to report for this context' });
          return;
        }

        // ANTI-REVIEW-BOMBING: Check if this item has already been used for a review against this authenticator
        // This prevents the attack where an item is transferred between colluding accounts to submit multiple bad reviews
        if (contextType === 'authenticated_item' || contextType === 'issuer_item') {
          const itemAlreadyRated = Array.from((state as any).verifierRatings?.values?.() || [])
            .some((x: any) => x && 
              String(x.contextType || '') === contextType && 
              String(x.contextId || '') === contextId && 
              String(x.targetAccountId || '') === targetAccountId
            );
          const itemAlreadyReported = Array.from((state as any).verifierReports?.values?.() || [])
            .some((x: any) => x && 
              String(x.contextType || '') === contextType && 
              String(x.contextId || '') === contextId && 
              String(x.targetAccountId || '') === targetAccountId
            );
          if (itemAlreadyRated || itemAlreadyReported) {
            res.status(400).json({ 
              success: false, 
              error: 'This item has already been used to rate/report this verifier. Each item can only generate one review per authenticator to prevent review bombing.' 
            });
            return;
          }
        }

        const now = Date.now();
        const limits = this.getReputationLimits();
        const usage = this.computeReputationUsage({
          state,
          now,
          raterAccountId: reporterAccountId,
          targetAccountId,
        });

        if (limits.maxReportsPerWindow > 0 && usage.reportsInWindow >= limits.maxReportsPerWindow) {
          res.status(429).json({ success: false, error: 'Report rate limit exceeded', limits, usage });
          return;
        }
        if (limits.maxContextsPerVerifier > 0 && usage.distinctContextsForTarget >= limits.maxContextsPerVerifier) {
          const ctxKey = `${contextType}\u0000${contextId}`;
          const alreadyUsed = [
            ...Array.from((state as any).verifierRatings?.values?.() || [])
              .filter((x: any) => x && String(x.raterAccountId || '') === reporterAccountId && String(x.targetAccountId || '') === targetAccountId)
              .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
            ...Array.from((state as any).verifierReports?.values?.() || [])
              .filter((x: any) => x && String(x.reporterAccountId || '') === reporterAccountId && String(x.targetAccountId || '') === targetAccountId)
              .map((x: any) => `${String(x.contextType || '')}\u0000${String(x.contextId || '')}`),
          ].includes(ctxKey);
          if (!alreadyUsed) {
            res.status(429).json({ success: false, error: 'Per-verifier context limit exceeded', limits, usage });
            return;
          }
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_VERIFIER_REPORTED:${targetAccountId}:${reporterAccountId}:${contextType}:${contextId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_VERIFIER_REPORTED,
            timestamp: now,
            nonce,
            targetAccountId,
            reporterAccountId,
            contextType,
            contextId,
            reasonCode,
            details,
          } as any,
          signatures
        );

        res.json({ success: true, targetAccountId, contextType, contextId });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/verifiers/me/profile', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const role = String(account.role || '');
        if (role !== 'manufacturer' && role !== 'authenticator') {
          res.status(403).json({ success: false, error: 'Manufacturer/authenticator role required' });
          return;
        }
        if (String(account.verifierStatus || 'active') === 'revoked') {
          res.status(403).json({ success: false, error: 'Account is revoked' });
          return;
        }

        const { companyName, displayName, website, phone, address, contactEmail, notes } = req.body || {};

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_VERIFIER_PROFILE_UPDATED:${String(account.accountId)}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_VERIFIER_PROFILE_UPDATED,
            timestamp: now,
            nonce,
            accountId: String(account.accountId),
            updatedByAccountId: String(account.accountId),
            companyName: companyName === null ? null : (companyName !== undefined ? String(companyName) : undefined),
            displayName: displayName === null ? null : (displayName !== undefined ? String(displayName) : undefined),
            website: website === null ? null : (website !== undefined ? String(website) : undefined),
            phone: phone === null ? null : (phone !== undefined ? String(phone) : undefined),
            address: address === null ? null : (address !== undefined ? String(address) : undefined),
            contactEmail: contactEmail === null ? null : (contactEmail !== undefined ? String(contactEmail) : undefined),
            notes: notes === null ? null : (notes !== undefined ? String(notes) : undefined),
          } as any,
          signatures
        );

        res.json({ success: true, accountId: String(account.accountId) });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/verifiers/me/bond/check', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const role = String(account.role || '');
        if (role !== 'manufacturer' && role !== 'authenticator') {
          res.status(403).json({ success: false, error: 'Manufacturer/authenticator role required' });
          return;
        }
        if (String(account.verifierStatus || 'active') === 'revoked') {
          res.status(403).json({ success: false, error: 'Account is revoked' });
          return;
        }

        const bondMinSats = Number(process.env.VERIFIER_BOND_MIN_SATS || 100000);
        const bondAddress = String(account.walletAddress || '').trim();
        if (!bondAddress) {
          res.status(400).json({ success: false, error: 'Account has no wallet address to verify' });
          return;
        }

        const apiBase = this.getBlockstreamApiBase();
        const utxosRes = await fetch(`${apiBase}/address/${encodeURIComponent(bondAddress)}/utxo`);
        if (!utxosRes.ok) {
          res.status(502).json({ success: false, error: 'Failed to fetch bond address UTXOs' });
          return;
        }
        const utxos = await utxosRes.json();
        const confirmed = Array.isArray(utxos) ? utxos.filter((u: any) => u && u.status && u.status.confirmed) : [];
        const confirmedSats = confirmed.reduce((sum: number, u: any) => sum + Number(u?.value || 0), 0);
        const utxoCount = confirmed.length;
        const meetsMin = !(bondMinSats > 0) ? true : confirmedSats >= bondMinSats;

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_VERIFIER_BOND_PROOF_RECORDED:${String(account.accountId)}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_VERIFIER_BOND_PROOF_RECORDED,
            timestamp: now,
            nonce,
            accountId: String(account.accountId),
            bondAddress,
            bondMinSats,
            confirmedSats,
            utxoCount,
            meetsMin,
            recordedByAccountId: String(account.accountId),
          } as any,
          signatures
        );

        res.json({
          success: true,
          accountId: String(account.accountId),
          bondAddress,
          bondMinSats,
          confirmedSats,
          utxoCount,
          meetsMin,
          checkedAt: now,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/me/enable', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const acc: any = state.accounts.get(String(account.accountId));
        if (!acc) {
          res.status(401).json({ success: false, error: 'Invalid session' });
          return;
        }
        if (!this.enforceRetailerNotBlockedOrRespond(res, acc)) return;

        const currentRole = String(account.role || '');
        if (currentRole === 'retailer') {
          res.json({ success: true, accountId: String(account.accountId), alreadyRetailer: true });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_ROLE_SET:${String(account.accountId)}:retailer:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_SET,
            timestamp: now,
            nonce,
            accountId: String(account.accountId),
            role: 'retailer',
            reason: 'self_serve_retailer_enable',
          } as any,
          signatures
        );

        res.json({ success: true, accountId: String(account.accountId), role: 'retailer' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/me/profile', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const role = String(account.role || '');
        if (role !== 'retailer') {
          res.status(403).json({ success: false, error: 'Retailer role required' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const acc: any = state.accounts.get(String(account.accountId));
        if (!acc) {
          res.status(401).json({ success: false, error: 'Invalid session' });
          return;
        }
        if (!this.enforceRetailerNotBlockedOrRespond(res, acc)) return;

        const { companyName, displayName, website, phone, address, contactEmail, notes } = req.body || {};

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RETAILER_PROFILE_UPDATED:${String(account.accountId)}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_PROFILE_UPDATED,
            timestamp: now,
            nonce,
            accountId: String(account.accountId),
            updatedByAccountId: String(account.accountId),
            companyName: companyName === null ? null : (companyName !== undefined ? String(companyName) : undefined),
            displayName: displayName === null ? null : (displayName !== undefined ? String(displayName) : undefined),
            website: website === null ? null : (website !== undefined ? String(website) : undefined),
            phone: phone === null ? null : (phone !== undefined ? String(phone) : undefined),
            address: address === null ? null : (address !== undefined ? String(address) : undefined),
            contactEmail: contactEmail === null ? null : (contactEmail !== undefined ? String(contactEmail) : undefined),
            notes: notes === null ? null : (notes !== undefined ? String(notes) : undefined),
          } as any,
          signatures
        );

        res.json({ success: true, accountId: String(account.accountId) });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/me/bond/check', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const role = String(account.role || '');
        if (role !== 'retailer') {
          res.status(403).json({ success: false, error: 'Retailer role required' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const acc: any = state.accounts.get(String(account.accountId));
        if (!acc) {
          res.status(401).json({ success: false, error: 'Invalid session' });
          return;
        }
        if (!this.enforceRetailerNotBlockedOrRespond(res, acc)) return;

        const bondMinSats = Number(process.env.RETAILER_BOND_MIN_SATS || 200000);
        const bondAddress = String(acc.walletAddress || account.walletAddress || '').trim();
        if (!bondAddress) {
          res.status(400).json({ success: false, error: 'Account has no wallet address to verify' });
          return;
        }

        const apiBase = this.getBlockstreamApiBase();
        const utxosRes = await fetch(`${apiBase}/address/${encodeURIComponent(bondAddress)}/utxo`);
        if (!utxosRes.ok) {
          res.status(502).json({ success: false, error: 'Failed to fetch bond address UTXOs' });
          return;
        }
        const utxos = await utxosRes.json();
        const confirmed = Array.isArray(utxos) ? utxos.filter((u: any) => u && u.status && u.status.confirmed) : [];
        const confirmedSats = confirmed.reduce((sum: number, u: any) => sum + Number(u?.value || 0), 0);
        const utxoCount = confirmed.length;
        const meetsMin = !(bondMinSats > 0) ? true : confirmedSats >= bondMinSats;

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RETAILER_BOND_PROOF_RECORDED:${String(account.accountId)}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_BOND_PROOF_RECORDED,
            timestamp: now,
            nonce,
            accountId: String(account.accountId),
            bondAddress,
            bondMinSats,
            confirmedSats,
            utxoCount,
            meetsMin,
            recordedByAccountId: String(account.accountId),
          } as any,
          signatures
        );

        res.json({
          success: true,
          accountId: String(account.accountId),
          bondAddress,
          bondMinSats,
          confirmedSats,
          utxoCount,
          meetsMin,
          checkedAt: now,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/retailers', async (req: Request, res: Response) => {
      try {
        const state = await this.canonicalStateBuilder.buildState();
        const bondMinSats = Number(process.env.RETAILER_BOND_MIN_SATS || 200000);
        const bondMaxAgeMs = Number(process.env.RETAILER_BOND_MAX_AGE_MS || 0) || 24 * 60 * 60 * 1000;

        const retailers = Array.from(state.accounts.values())
          .filter((a: any) => String(a.role || '') === 'retailer')
          .filter((a: any) => String(a.retailerStatus || 'unverified') !== 'blocked')
          .filter((a: any) => {
            if (!(bondMinSats > 0)) return true;
            const meets = Boolean(a.retailerBondMeetsMin);
            const last = Number(a.retailerBondLastCheckedAt || 0);
            return meets && last > 0 && (Date.now() - last) <= bondMaxAgeMs;
          })
          .map((a: any) => ({
            accountId: String(a.accountId),
            role: 'retailer',
            username: a.username ? String(a.username) : undefined,
            displayName: a.displayName ? String(a.displayName) : undefined,
            companyName: a.companyName ? String(a.companyName) : undefined,
            website: a.website ? String(a.website) : undefined,
            phone: a.phone ? String(a.phone) : undefined,
            address: a.address ? String(a.address) : undefined,
            walletAddress: a.walletAddress ? String(a.walletAddress) : undefined,
            retailerStatus: String(a.retailerStatus || 'unverified'),
            retailerVerifiedAt: a.retailerVerifiedAt ? Number(a.retailerVerifiedAt) : undefined,
            retailerRatingAvg: typeof a.retailerRatingAvg === 'number' ? Number(a.retailerRatingAvg) : undefined,
            retailerRatingCount: typeof a.retailerRatingCount === 'number' ? Number(a.retailerRatingCount) : undefined,
            retailerReportCount: typeof a.retailerReportCount === 'number' ? Number(a.retailerReportCount) : undefined,
            retailerBondMinSats: a.retailerBondMinSats ? Number(a.retailerBondMinSats) : undefined,
            retailerBondConfirmedSats: a.retailerBondConfirmedSats ? Number(a.retailerBondConfirmedSats) : undefined,
            retailerBondMeetsMin: typeof a.retailerBondMeetsMin === 'boolean' ? Boolean(a.retailerBondMeetsMin) : undefined,
            retailerBondLastCheckedAt: a.retailerBondLastCheckedAt ? Number(a.retailerBondLastCheckedAt) : undefined,
          }));

        res.json({ success: true, count: retailers.length, retailers });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/retailers/:accountId/profile', async (req: Request, res: Response) => {
      try {
        const accountId = String(req.params.accountId || '').trim();
        if (!accountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }
        const state = await this.canonicalStateBuilder.buildState();
        const a: any = state.accounts.get(accountId);
        if (!a) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }
        if (String(a.role || '') !== 'retailer') {
          res.status(400).json({ success: false, error: 'Account is not a retailer' });
          return;
        }

        res.json({
          success: true,
          profile: {
            accountId: String(a.accountId),
            role: 'retailer',
            username: a.username ? String(a.username) : undefined,
            displayName: a.displayName ? String(a.displayName) : undefined,
            companyName: a.companyName ? String(a.companyName) : undefined,
            website: a.website ? String(a.website) : undefined,
            phone: a.phone ? String(a.phone) : undefined,
            address: a.address ? String(a.address) : undefined,
            contactEmail: a.contactEmail ? String(a.contactEmail) : undefined,
            notes: a.notes ? String(a.notes) : undefined,
            walletAddress: a.walletAddress ? String(a.walletAddress) : undefined,
            retailerStatus: String(a.retailerStatus || 'unverified'),
            retailerVerifiedAt: a.retailerVerifiedAt ? Number(a.retailerVerifiedAt) : undefined,
            retailerBlockedAt: a.retailerBlockedAt ? Number(a.retailerBlockedAt) : undefined,
            retailerUnblockedAt: a.retailerUnblockedAt ? Number(a.retailerUnblockedAt) : undefined,
            retailerRatingAvg: typeof a.retailerRatingAvg === 'number' ? Number(a.retailerRatingAvg) : undefined,
            retailerRatingCount: typeof a.retailerRatingCount === 'number' ? Number(a.retailerRatingCount) : undefined,
            retailerReportCount: typeof a.retailerReportCount === 'number' ? Number(a.retailerReportCount) : undefined,
            retailerBondAddress: a.retailerBondAddress ? String(a.retailerBondAddress) : undefined,
            retailerBondMinSats: a.retailerBondMinSats ? Number(a.retailerBondMinSats) : undefined,
            retailerBondConfirmedSats: a.retailerBondConfirmedSats ? Number(a.retailerBondConfirmedSats) : undefined,
            retailerBondUtxoCount: a.retailerBondUtxoCount ? Number(a.retailerBondUtxoCount) : undefined,
            retailerBondMeetsMin: typeof a.retailerBondMeetsMin === 'boolean' ? Boolean(a.retailerBondMeetsMin) : undefined,
            retailerBondLastCheckedAt: a.retailerBondLastCheckedAt ? Number(a.retailerBondLastCheckedAt) : undefined,
            createdAt: a.createdAt ? Number(a.createdAt) : undefined,
            updatedAt: a.updatedAt ? Number(a.updatedAt) : undefined,
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/me/verification/apply', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }
        if (String(account.role || '') !== 'retailer') {
          res.status(403).json({ success: false, error: 'Retailer role required' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const acc: any = state.accounts.get(String(account.accountId));
        if (!acc) {
          res.status(401).json({ success: false, error: 'Invalid session' });
          return;
        }
        if (!this.enforceFreshRetailerBondOrRespond(res, acc)) return;

        if (acc && String(acc.retailerStatus || 'unverified') === 'verified') {
          res.json({ success: true, alreadyVerified: true });
          return;
        }

        const existing = (Array.from((state as any).retailerVerificationApplications?.values?.() || []) as any[]).find((a: any) => {
          return a && String(a.accountId) === String(account.accountId) && !a.finalized;
        }) as any;
        if (existing) {
          res.json({ success: true, applicationId: String(existing.applicationId), alreadySubmitted: true });
          return;
        }

        const { companyName, contactEmail, website, notes } = req.body || {};

        const applicationId = `retapp_${Date.now()}_${randomBytes(8).toString('hex')}`;
        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RETAILER_VERIFICATION_APPLICATION_SUBMITTED:${applicationId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_SUBMITTED,
            timestamp: now,
            nonce,
            applicationId,
            accountId: String(account.accountId),
            companyName: companyName ? String(companyName) : undefined,
            contactEmail: contactEmail ? String(contactEmail) : undefined,
            website: website ? String(website) : undefined,
            notes: notes ? String(notes) : undefined,
          } as any,
          signatures
        );

        res.json({ success: true, applicationId });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/retailers/verification/applications', async (req: Request, res: Response) => {
      try {
        const op = await this.requireMainNodeOperator(req, res);
        if (!op) return;

        const status = String(req.query.status || 'open');
        const state = await this.canonicalStateBuilder.buildState();
        const reviewWindowMs = Number(process.env.RETAILER_VERIFICATION_REVIEW_WINDOW_MS || 0) || 7 * 24 * 60 * 60 * 1000;

        const items = (Array.from((state as any).retailerVerificationApplications?.values?.() || []) as any[]).map((a: any) => ({
          applicationId: a.applicationId,
          accountId: a.accountId,
          companyName: a.companyName,
          contactEmail: a.contactEmail,
          website: a.website,
          notes: a.notes,
          submittedAt: a.submittedAt,
          reviewed: a.reviewed,
          finalized: a.finalized,
          voteCount: {
            approve: Array.from(a.votes?.values?.() || []).filter((v: any) => v && v.vote === 'approve').length,
            reject: Array.from(a.votes?.values?.() || []).filter((v: any) => v && v.vote === 'reject').length,
          },
          eligibleForVotingAt: Number(a.submittedAt || 0) + reviewWindowMs,
        }));

        const filtered = items.filter((a: any) => {
          if (status === 'open') return !a.finalized && !a.reviewed;
          if (status === 'reviewed') return !!a.reviewed && !a.finalized;
          if (status === 'finalized') return !!a.finalized;
          return true;
        });

        res.json({ success: true, applications: filtered });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/verification/applications/:applicationId/review', async (req: Request, res: Response) => {
      try {
        const op = await this.requireMainNodeOperator(req, res);
        if (!op) return;

        const { applicationId } = req.params;
        const { decision, reason } = req.body;
        const d = String(decision || '');
        if (d !== 'approve' && d !== 'reject') {
          res.status(400).json({ success: false, error: 'decision must be approve or reject' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const app: any = (state as any).retailerVerificationApplications?.get?.(String(applicationId));
        if (!app) {
          res.status(404).json({ success: false, error: 'Application not found' });
          return;
        }
        if (app.finalized) {
          res.status(400).json({ success: false, error: 'Application already finalized' });
          return;
        }
        if (app.reviewed) {
          res.status(400).json({ success: false, error: 'Application already reviewed' });
          return;
        }

        const nonce1 = randomBytes(32).toString('hex');
        const now = Date.now();
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RETAILER_VERIFICATION_APPLICATION_REVIEWED:${applicationId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_REVIEWED,
            timestamp: now,
            nonce: nonce1,
            applicationId: String(applicationId),
            reviewerOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            decision: d,
            reason: reason ? String(reason) : undefined,
          } as any,
          signatures
        );

        res.json({ success: true, applicationId: String(applicationId), decision: d, reviewed: true });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/verification/applications/:applicationId/vote', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const { applicationId } = req.params;
        const { vote, reason } = req.body;
        const v = String(vote || '');
        if (v !== 'approve' && v !== 'reject') {
          res.status(400).json({ success: false, error: 'vote must be approve or reject' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const app: any = (state as any).retailerVerificationApplications?.get?.(String(applicationId));
        if (!app) {
          res.status(404).json({ success: false, error: 'Application not found' });
          return;
        }
        if (app.finalized) {
          res.status(400).json({ success: false, error: 'Application is closed' });
          return;
        }

        if (!app.reviewed) {
          res.status(400).json({ success: false, error: 'Application not reviewed yet' });
          return;
        }

        const reviewWindowMs = Number(process.env.RETAILER_VERIFICATION_REVIEW_WINDOW_MS || 0) || 7 * 24 * 60 * 60 * 1000;
        if (Date.now() < Number(app.submittedAt || 0) + reviewWindowMs) {
          res.status(400).json({ success: false, error: 'Voting not yet enabled (main node review window still open)' });
          return;
        }

        const voterId = String(process.env.OPERATOR_ID || 'operator-1');
        if (app.votes && app.votes.has(voterId)) {
          const existing = app.votes.get(voterId);
          res.json({ success: true, applicationId: String(applicationId), vote: String(existing?.vote || v), alreadyVoted: true });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: voterId,
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RETAILER_VERIFICATION_APPLICATION_VOTED:${applicationId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_VOTED,
            timestamp: now,
            nonce,
            applicationId: String(applicationId),
            voterOperatorId: voterId,
            vote: v,
            reason: reason ? String(reason) : undefined,
          } as any,
          signatures
        );

        res.json({ success: true, applicationId: String(applicationId), vote: v });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/verification/applications/:applicationId/finalize', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const { applicationId } = req.params;
        const state = await this.canonicalStateBuilder.buildState();
        const app: any = (state as any).retailerVerificationApplications?.get?.(String(applicationId));
        if (!app) {
          res.status(404).json({ success: false, error: 'Application not found' });
          return;
        }
        if (app.finalized) {
          res.json({
            success: true,
            applicationId: String(applicationId),
            decision: String(app.finalized?.decision || ''),
            approveVotes: Number(app.finalized?.approveVotes || 0),
            rejectVotes: Number(app.finalized?.rejectVotes || 0),
            activeOperatorCount: Number(app.finalized?.activeOperatorCount || 0),
            alreadyFinalized: true,
          });
          return;
        }

        if (!app.reviewed) {
          res.status(400).json({ success: false, error: 'Application not reviewed yet' });
          return;
        }

        const reviewWindowMs = Number(process.env.RETAILER_VERIFICATION_REVIEW_WINDOW_MS || 0) || 7 * 24 * 60 * 60 * 1000;
        if (Date.now() < Number(app.submittedAt || 0) + reviewWindowMs) {
          res.status(400).json({ success: false, error: 'Finalize not yet enabled (main node review window still open)' });
          return;
        }

        const votes = Array.from(app.votes?.values?.() || []);
        const approveVotes = votes.filter((vv: any) => vv && vv.vote === 'approve').length;
        const rejectVotes = votes.filter((vv: any) => vv && vv.vote === 'reject').length;
        const decision = approveVotes > rejectVotes ? 'approve' : 'reject';
        const activeOperatorCount = (await this.canonicalStateBuilder.getActiveOperators()).length;

        const now = Date.now();
        const nonce1 = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RETAILER_VERIFICATION_APPLICATION_FINALIZED:${applicationId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_VERIFICATION_APPLICATION_FINALIZED,
            timestamp: now,
            nonce: nonce1,
            applicationId: String(applicationId),
            finalizedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            decision,
            activeOperatorCount,
            approveVotes,
            rejectVotes,
          } as any,
          signatures
        );

        if (decision === 'approve') {
          const nonce2 = randomBytes(32).toString('hex');
          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.ACCOUNT_RETAILER_VERIFIED,
              timestamp: now,
              nonce: nonce2,
              accountId: String(app.accountId),
              verifiedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
              applicationId: String(applicationId),
            } as any,
            signatures
          );
        }

        res.json({
          success: true,
          applicationId: String(applicationId),
          decision,
          approveVotes,
          rejectVotes,
          activeOperatorCount,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Registry state (LOCALHOST ONLY)
    // This endpoint includes account emails and is intended for operator debugging inside the host/container.
    this.app.get('/api/registry/state', async (req: Request, res: Response) => {
      try {
        const host = String(req.headers.host || '');
        const ip = String(req.ip || '');
        const isLocalHostHeader = host.startsWith('localhost') || host.startsWith('127.0.0.1');
        const isLocalIp = ip === '127.0.0.1' || ip === '::1' || ip.startsWith('::ffff:127.');

        if (!isLocalHostHeader && !isLocalIp) {
          res.status(404).send('Not Found');
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();

        const accounts = Array.from(state.accounts.values()).map((a: any) => ({
          accountId: a.accountId,
          role: a.role,
          username: a.username,
          email: a.email,
          walletAddress: a.walletAddress,
          createdAt: a.createdAt,
          updatedAt: a.updatedAt,
          totpEnabled: Boolean(a.totp?.enabled),
        }));

        res.json({
          success: true,
          counts: {
            accounts: state.accounts.size,
            items: state.items.size,
            settlements: state.settlements.size,
            operators: state.operators.size,
          },
          lastEventSequence: state.lastEventSequence,
          lastEventHash: state.lastEventHash,
          accounts,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/registry/accounts', async (req: Request, res: Response) => {
      try {
        const host = String(req.headers.host || '');
        const ip = String(req.ip || '');
        const isLocalHostHeader = host.startsWith('localhost') || host.startsWith('127.0.0.1');
        const isLocalIp = ip === '127.0.0.1' || ip === '::1' || ip.startsWith('::ffff:127.');

        if (!isLocalHostHeader && !isLocalIp) {
          res.status(404).send('Not Found');
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const accounts = Array.from(state.accounts.values()).map((a: any) => ({
          accountId: a.accountId,
          role: a.role,
          username: a.username,
          email: a.email,
          walletAddress: a.walletAddress,
          createdAt: a.createdAt,
          updatedAt: a.updatedAt,
        }));

        res.json({ success: true, count: accounts.length, accounts });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Serve static files from public directory (after explicit routes)
    this.app.use(express.static(path.join(__dirname, '../../public')));

    // Download metadata
    this.app.get('/api/downloads', async (req: Request, res: Response) => {
      try {
        const type = String(req.query.type || '');
        const proto = String((req.headers as any)?.['x-forwarded-proto'] || req.protocol || 'https')
          .split(',')[0]
          .trim();
        const host = String(req.headers.host || '').trim();
        const origin = host ? `${proto}://${host}` : 'http://localhost:3000';
        const downloads = {
          wallet: {
            name: 'Autho Wallet (Web)',
            description: 'Mobile-optimized web wallet for customers to manage items',
            platforms: {
              ios: '/m',
              android: '/m',
              desktop: '/m',
            },
            status: 'available',
            message: 'Access the mobile-optimized web wallet. Works on all devices - no app installation required.',
          },
          gateway: {
            name: 'Autho Gateway Node',
            description: 'Software for retailers to host registry replicas',
            platforms: {
              windows: '/install-gateway.html',
              macos: '/install-gateway.html',
              linux: '/install-gateway.html',
              readme: '/downloads/gateway-node/README.md'
            },
            quickInstall: {
              linux: `curl -fsSL ${origin}/downloads/gateway-node/quick-install.sh | bash`,
              macos: `curl -fsSL ${origin}/downloads/gateway-node/quick-install.sh | bash`,
              windows: `irm ${origin}/downloads/gateway-node/quick-install.ps1 | iex`,
            },
          },
          manufacturer: {
            name: 'Autho Manufacturer Portal',
            description: 'Web portal for manufacturers to register physical items and manage provenance',
            platforms: {
              web: '/manufacturer'
            },
          },
          authenticator: {
            name: 'Autho Authenticator Client',
            description: 'Software for authenticators to verify products and issue attestations',
            platforms: {
              web: '/authenticator'
            },
          },
          operator: {
            name: 'Autho Operator Node',
            description: 'Software for operators to validate transactions',
            platforms: {
              windows: '/install-operator.html',
              macos: '/install-operator.html',
              linux: '/install-operator.html',
              readme: '/downloads/operator-node/README.md'
            },
            quickInstall: {
              linux: `curl -fsSL ${origin}/downloads/operator-node/quick-install.sh | bash`,
              macos: `curl -fsSL ${origin}/downloads/operator-node/quick-install.sh | bash`,
              windows: `irm ${origin}/downloads/operator-node/quick-install.ps1 | iex`,
            },
          },
        };

        if (type && downloads[type as keyof typeof downloads]) {
          res.json(downloads[type as keyof typeof downloads]);
        } else {
          res.json({
            message: 'Available downloads',
            downloads,
          });
        }
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    // Backwards compatible alias used by landing.html (older builds)
    this.app.get('/download', (req: Request, res: Response) => {
      const type = String(req.query.type || '');
      // Delegate to the same payload as /api/downloads
      const reqAny = req as any;
      const resAny = res as any;
      reqAny.url = `/api/downloads?type=${encodeURIComponent(type)}`;
      resAny.redirect(`/api/downloads?type=${encodeURIComponent(type)}`);
    });

    this.app.get('/api/version', (req: Request, res: Response) => {
      try {
        const packageJsonPath = path.join(process.cwd(), 'package.json');
        const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

        res.json({
          softwareVersion: String(pkg.version || 'unknown'),
          protocol: {
            eventHash: 'AUTHO_EVT_V1_SHA256',
            totpEncSchemes: ['AUTHO_TOTP_AES_256_GCM_V1', 'AUTHO_TOTP_ENC_V1_BASE32_B64'],
          },
        });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    // Admin login page
    this.app.get('/admin/login', (req: Request, res: Response) => {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.sendFile('admin-login.html', { root: './public' });
    });

    // Address diagnostic page
    this.app.get('/check-addresses.html', (req: Request, res: Response) => {
      res.sendFile('check-addresses.html', { root: './public' });
    });

    // Gateway installation page
    this.app.get('/install-gateway.html', (req: Request, res: Response) => {
      res.sendFile('install-gateway.html', { root: './public' });
    });

    // Operator installation page
    this.app.get('/install-operator.html', (req: Request, res: Response) => {
      res.sendFile('install-operator.html', { root: './public' });
    });

    // Download files - Gateway Node
    this.app.get('/downloads/gateway-node/:filename', (req: Request, res: Response) => {
      const { filename } = req.params;
      const filePath = path.join(process.cwd(), 'downloads', 'gateway-node', filename);

      const proto = String((req.headers as any)?.['x-forwarded-proto'] || req.protocol || 'https')
        .split(',')[0]
        .trim();
      const host = String(req.headers.host || '').trim();
      const origin = host ? `${proto}://${host}` : 'http://localhost:3000';
      const baseUrl = `${origin}/downloads/gateway-node`;

      const sendText = (body: string, contentType: string) => {
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.send(body);
      };

      if (filename === 'quick-install.sh') {
        const body = `#!/bin/bash\n# Autho Gateway Node - One-Line Installer\n# Usage: curl -fsSL ${baseUrl}/quick-install.sh | bash\n\nset -e\n\necho \"🌐 Autho Gateway Node - Quick Installer\"\necho \"========================================\"\n\nif ! command -v node &> /dev/null; then\n    echo \"❌ Node.js is not installed\"\n    echo \"   Please install Node.js 18+ from: https://nodejs.org/\"\n    exit 1\nfi\n\nNODE_VERSION=$(node -e 'process.stdout.write(process.versions.node.split(\".\")[0])')\nif [ \"$NODE_VERSION\" -lt 18 ]; then\n    echo \"❌ Node.js 18+ required. Current: $(node --version)\"\n    exit 1\nfi\n\necho \"✅ Node.js $(node --version)\"\n\nTEMP_DIR=$(mktemp -d)\ncd \"$TEMP_DIR\"\n\necho \"📥 Downloading gateway node...\"\nCACHE_BUST=$(date +%s)\ncurl -fsSL \"${baseUrl}/gateway-package.js?v=\${CACHE_BUST}\" -o gateway-package.js\ncurl -fsSL \"${baseUrl}/package.json?v=\${CACHE_BUST}\" -o package.json\n\nINSTALL_DIR=\"$HOME/autho-gateway-node\"\necho \"📁 Installing to: $INSTALL_DIR\"\nmkdir -p \"$INSTALL_DIR\"\n\ncp gateway-package.js \"$INSTALL_DIR/\"\ncp package.json \"$INSTALL_DIR/\"\ncd \"$INSTALL_DIR\"\n\necho \"📦 Installing dependencies...\"\nnpm install --silent\n\ncat > start.sh << 'EOF'\n#!/bin/bash\ncd \"$(dirname \"$0\")\"\nexport AUTHO_OPERATOR_URLS=\"${origin}\"\nnode gateway-package.js\nEOF\nchmod +x start.sh\n\nrm -rf \"$TEMP_DIR\"\n\necho \"\"\necho \"✅ Installation complete!\"\necho \"\"\necho \"🚀 Start the gateway node:\"\necho \"   cd $INSTALL_DIR\"\necho \"   ./start.sh\"\necho \"\"\necho \"🌐 Gateway will run on: http://localhost:3001\"\necho \"📊 Health check: http://localhost:3001/health\"\necho \"\"\necho \"🎉 Welcome to the Autho network!\"\n`;
        sendText(body, 'text/plain; charset=utf-8');
        return;
      }

      if (filename === 'quick-install.ps1') {
        const psBody = `# Autho Gateway Node - PowerShell Installer\n# Usage: irm ${baseUrl}/quick-install.ps1 | iex\n\nWrite-Host \"🌐 Autho Gateway Node - Quick Installer\" -ForegroundColor Cyan\nWrite-Host \"========================================\" -ForegroundColor Cyan\nWrite-Host \"\"\n\ntry {\n    $nodeVersion = node --version\n    $majorVersion = [int]($nodeVersion -replace 'v(\\d+)\\..*', '$1')\n    if ($majorVersion -lt 18) {\n        Write-Host \"❌ Node.js 18+ required. Current: $nodeVersion\" -ForegroundColor Red\n        Write-Host \"   Download from: https://nodejs.org/\" -ForegroundColor Yellow\n        exit 1\n    }\n    Write-Host \"✅ Node.js $nodeVersion\" -ForegroundColor Green\n} catch {\n    Write-Host \"❌ Node.js is not installed\" -ForegroundColor Red\n    Write-Host \"   Please install Node.js 18+ from: https://nodejs.org/\" -ForegroundColor Yellow\n    exit 1\n}\n\n$installDir = \"$env:USERPROFILE\\autho-gateway-node\"\nWrite-Host \"📁 Installing to: $installDir\" -ForegroundColor Cyan\nif (-not (Test-Path $installDir)) {\n    New-Item -ItemType Directory -Path $installDir -Force | Out-Null\n    Write-Host \"✅ Created installation directory\" -ForegroundColor Green\n}\n\nWrite-Host \"📥 Downloading gateway node...\" -ForegroundColor Cyan\ntry {\n    $baseUrl = \"${baseUrl}\"\n    $cacheBust = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()\n    $headers = @{ 'Cache-Control' = 'no-cache'; 'Pragma' = 'no-cache' }\n    Invoke-WebRequest -Uri \"$baseUrl/gateway-package.js?v=$cacheBust\" -Headers $headers -OutFile \"$installDir\\gateway-package.js\" -UseBasicParsing\n    Invoke-WebRequest -Uri \"$baseUrl/package.json?v=$cacheBust\" -Headers $headers -OutFile \"$installDir\\package.json\" -UseBasicParsing\n    Invoke-WebRequest -Uri \"$baseUrl/Start-Autho-Gateway-Node.bat?v=$cacheBust\" -Headers $headers -OutFile \"$installDir\\Start-Autho-Gateway-Node.bat\" -UseBasicParsing\n    Invoke-WebRequest -Uri \"$baseUrl/Start-Autho-Gateway-Node-Background.bat?v=$cacheBust\" -Headers $headers -OutFile \"$installDir\\Start-Autho-Gateway-Node-Background.bat\" -UseBasicParsing\n    Write-Host \"✅ Files downloaded\" -ForegroundColor Green\n} catch {\n    Write-Host \"❌ Failed to download files: $_\" -ForegroundColor Red\n    exit 1\n}\n\nWrite-Host \"📦 Installing dependencies...\" -ForegroundColor Cyan\nPush-Location $installDir\ntry {\n    npm install --silent 2>&1 | Out-Null\n    Write-Host \"✅ Dependencies installed\" -ForegroundColor Green\} catch {\n    Write-Host \"⚠️  Warning: npm install had issues, but continuing...\" -ForegroundColor Yellow\}\nPop-Location\n\nWrite-Host \"\"\nWrite-Host \"✅ Installation complete!\" -ForegroundColor Green\nWrite-Host \"\"\nWrite-Host \"🖱️ Next time, start by double-clicking:\" -ForegroundColor Cyan\nWrite-Host \"   $installDir\\Start-Autho-Gateway-Node.bat\" -ForegroundColor White\nWrite-Host \"\"\nWrite-Host \"🌐 Gateway will run on: http://localhost:3001\" -ForegroundColor Cyan\nWrite-Host \"📊 Health check: http://localhost:3001/health\" -ForegroundColor Cyan\nWrite-Host \"\"\nWrite-Host \"🎉 Welcome to the Autho network!\" -ForegroundColor Green\nWrite-Host \"\"\n`;
        sendText(psBody, 'text/plain; charset=utf-8');
        return;
      }

      if (filename === 'quick-install.bat') {
        const body = `@echo off\r\nREM Autho Gateway Node - One-Line Installer for Windows\r\n\r\necho 🌐 Autho Gateway Node - Quick Installer\r\necho ========================================\r\n\r\nwhere node >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n    echo ❌ Node.js is not installed\r\n    echo    Please install Node.js 18+ from: https://nodejs.org/\r\n    pause\r\n    exit /b 1\r\n)\r\n\r\nset INSTALL_DIR=%USERPROFILE%\\autho-gateway-node\r\necho 📁 Installing to: %INSTALL_DIR%\r\nif not exist \"%INSTALL_DIR%\" mkdir \"%INSTALL_DIR%\"\r\n\r\necho 📥 Downloading gateway node...\r\ncd /d \"%INSTALL_DIR%\"\r\nfor /f %%i in ('powershell -NoProfile -Command \"[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()\"') do set CACHE_BUST=%%i\r\n\r\npowershell -NoProfile -Command \"$ErrorActionPreference='Stop'; $h=@{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' }; Invoke-WebRequest -UseBasicParsing -Headers $h -Uri '${baseUrl}/gateway-package.js?v=%CACHE_BUST%' -OutFile 'gateway-package.js' | Out-Null\"\r\nif %ERRORLEVEL% NEQ 0 (\r\n    echo ❌ Failed to download gateway-package.js\r\n    pause\r\n    exit /b 1\r\n)\r\n\r\npowershell -NoProfile -Command \"$ErrorActionPreference='Stop'; $h=@{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' }; Invoke-WebRequest -UseBasicParsing -Headers $h -Uri '${baseUrl}/package.json?v=%CACHE_BUST%' -OutFile 'package.json' | Out-Null\"\r\nif %ERRORLEVEL% NEQ 0 (\r\n    echo ❌ Failed to download package.json\r\n    pause\r\n    exit /b 1\r\n)\r\n\r\npowershell -NoProfile -Command \"$ErrorActionPreference='Stop'; $h=@{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' }; Invoke-WebRequest -UseBasicParsing -Headers $h -Uri '${baseUrl}/Start-Autho-Gateway-Node.bat?v=%CACHE_BUST%' -OutFile 'Start-Autho-Gateway-Node.bat' | Out-Null\"\r\n\r\necho 📦 Installing dependencies...\r\ncall npm install --silent\r\n\r\necho.\r\necho ✅ Installation complete!\r\necho.\r\necho 🖱️ Start the gateway node by double-clicking:\r\necho    %INSTALL_DIR%\\Start-Autho-Gateway-Node.bat\r\necho.\r\necho 🌐 Gateway will run on: http://localhost:3001\r\necho 📊 Health check: http://localhost:3001/health\r\necho.\r\npause\r\n`;
        sendText(body, 'text/plain; charset=utf-8');
        return;
      }

      if (filename === 'Start-Autho-Gateway-Node.bat') {
        const body = `@echo off\r\nsetlocal enabledelayedexpansion\r\n\r\nset \"SCRIPT_DIR=%~dp0\"\r\ncd /d \"%SCRIPT_DIR%\"\r\n\r\necho ==============================================\r\necho  Autho Gateway Node (One-Click Launcher)\r\necho ==============================================\r\n\r\nwhere node >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: Node.js is not installed.\r\n  echo Please install Node.js 18+ from https://nodejs.org/\r\n  echo.\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\nwhere npm >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: npm was not found.\r\n  echo Reinstall Node.js (it includes npm): https://nodejs.org/\r\n  echo.\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\nset \"PORT=%1\"\r\nif \"%PORT%\"==\"\" (\r\n  if defined GATEWAY_PORT (\r\n    set \"PORT=%GATEWAY_PORT%\"\r\n  ) else (\r\n    set \"PORT=3001\"\r\n  )\r\n)\r\n\r\nif not exist \"node_modules\" (\r\n  echo Installing dependencies (first run)...\r\n  call npm install\r\n)\r\n\r\necho.\r\necho Starting gateway node on port %PORT%...\r\necho A new window will open with the node logs.\r\necho.\r\n\r\nstart \"Autho Gateway Node\" cmd /k \"cd /d \\\"%SCRIPT_DIR%\\\" ^&^& set GATEWAY_PORT=%PORT% ^&^& set AUTHO_OPERATOR_URLS=${origin} ^&^& node gateway-package.js\"\r\n\r\ntimeout /t 2 /nobreak >nul\r\nstart \"\" \"http://localhost:%PORT%/m\"\r\n\r\necho.\r\necho Opened: http://localhost:%PORT%/m\r\necho.\r\nexit /b 0\r\n`;
        sendText(body, 'text/plain; charset=utf-8');
        return;
      }

      if (filename === 'Start-Autho-Gateway-Node-Background.bat') {
        const body = `@echo off\r\nsetlocal enabledelayedexpansion\r\n\r\nset \"SCRIPT_DIR=%~dp0\"\r\ncd /d \"%SCRIPT_DIR%\"\r\n\r\necho ==============================================\r\necho  Autho Gateway Node (Background Launcher)\r\necho ==============================================\r\n\r\nwhere node >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: Node.js is not installed.\r\n  echo Please install Node.js 18+ from https://nodejs.org/\r\n  echo.\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\nwhere npm >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: npm was not found.\r\n  echo Reinstall Node.js (it includes npm): https://nodejs.org/\r\n  echo.\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\nset \"PORT=%1\"\r\nif \"%PORT%\"==\"\" (\r\n  if defined GATEWAY_PORT (\r\n    set \"PORT=%GATEWAY_PORT%\"\r\n  ) else (\r\n    set \"PORT=3001\"\r\n  )\r\n)\r\n\r\nif not exist \"node_modules\" (\r\n  echo Installing dependencies (first run)...\r\n  call npm install\r\n)\r\n\r\necho.\r\necho Starting gateway node in the background on port %PORT%...\r\necho Logs: %SCRIPT_DIR%gateway-node.log\r\necho.\r\n\r\nstart \"\" /min cmd /c \"cd /d \\\"%SCRIPT_DIR%\\\" ^&^& set GATEWAY_PORT=%PORT% ^&^& set AUTHO_OPERATOR_URLS=${origin} ^&^& node gateway-package.js 1^> gateway-node.log 2^>^&1\"\r\n\r\ntimeout /t 2 /nobreak >nul\r\nstart \"\" \"http://localhost:%PORT%/m\"\r\n\r\necho.\r\necho Opened: http://localhost:%PORT%/m\r\necho.\r\nexit /b 0\r\n`;
        sendText(body, 'text/plain; charset=utf-8');
        return;
      }

      if (filename === 'Autho-Gateway-OneClick-Windows.bat') {
        const body = `@echo off\r\nsetlocal enabledelayedexpansion\r\n\r\necho ==============================================\r\necho  Autho Gateway Node - One-Click Windows Setup\r\necho ==============================================\r\n\r\nset \"INSTALL_DIR=%USERPROFILE%\\autho-gateway-node\"\r\n\r\nwhere node >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: Node.js is not installed.\r\n  echo Please install Node.js 18+ from https://nodejs.org/\r\n  echo.\r\n  start \"\" \"https://nodejs.org/\"\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\nwhere npm >nul 2>nul\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo.\r\n  echo ERROR: npm was not found.\r\n  echo Reinstall Node.js (it includes npm): https://nodejs.org/\r\n  echo.\r\n  start \"\" \"https://nodejs.org/\"\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\necho ✅ Node:\r\nnode --version\r\n\r\nif not exist \"%INSTALL_DIR%\" (\r\n  echo 📁 Creating: %INSTALL_DIR%\r\n  mkdir \"%INSTALL_DIR%\" >nul 2>nul\r\n)\r\n\r\ncd /d \"%INSTALL_DIR%\"\r\n\r\necho 📥 Downloading gateway files...\r\nset \"BASE_URL=${baseUrl}\"\r\nfor /f %%i in ('powershell -NoProfile -Command \"[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()\"') do set CACHE_BUST=%%i\r\n\r\npowershell -NoProfile -Command \"$ErrorActionPreference='Stop'; try { Invoke-WebRequest -Uri '%BASE_URL%/gateway-package.js?v=%CACHE_BUST%' -Headers @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' } -OutFile 'gateway-package.js' -UseBasicParsing | Out-Null; exit 0 } catch { Write-Host $_; exit 1 }\"\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo ERROR: Failed to download gateway-package.js\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\npowershell -NoProfile -Command \"$ErrorActionPreference='Stop'; try { Invoke-WebRequest -Uri '%BASE_URL%/package.json?v=%CACHE_BUST%' -Headers @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' } -OutFile 'package.json' -UseBasicParsing | Out-Null; exit 0 } catch { Write-Host $_; exit 1 }\"\r\nif %ERRORLEVEL% NEQ 0 (\r\n  echo ERROR: Failed to download package.json\r\n  pause\r\n  exit /b 1\r\n)\r\n\r\npowershell -NoProfile -Command \"Invoke-WebRequest -Uri '%BASE_URL%/Start-Autho-Gateway-Node.bat?v=%CACHE_BUST%' -Headers @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' } -OutFile 'Start-Autho-Gateway-Node.bat' -UseBasicParsing\" >nul 2>nul\r\npowershell -NoProfile -Command \"Invoke-WebRequest -Uri '%BASE_URL%/Start-Autho-Gateway-Node-Background.bat?v=%CACHE_BUST%' -Headers @{ 'Cache-Control'='no-cache'; 'Pragma'='no-cache' } -OutFile 'Start-Autho-Gateway-Node-Background.bat' -UseBasicParsing\" >nul 2>nul\r\n\r\nif not exist \"node_modules\" (\r\n  echo 📦 Installing dependencies (first run)...\r\n  call npm install\r\n  if %ERRORLEVEL% NEQ 0 (\r\n    echo ERROR: npm install failed.\r\n    pause\r\n    exit /b 1\r\n  )\r\n) else (\r\n  echo ✅ Dependencies already installed.\r\n)\r\n\r\nset \"DESKTOP=%USERPROFILE%\\Desktop\"\r\nif exist \"%DESKTOP%\" (\r\n  powershell -NoProfile -Command \"$s=(New-Object -ComObject WScript.Shell).CreateShortcut(\"$env:USERPROFILE\\Desktop\\Autho Gateway Node.lnk\"); $s.TargetPath=\"%INSTALL_DIR%\\Start-Autho-Gateway-Node.bat\"; $s.WorkingDirectory=\"%INSTALL_DIR%\"; $s.WindowStyle=1; $s.Description=\"Start Autho Gateway Node\"; $s.Save()\" >nul 2>nul\r\n)\r\n\r\necho.\r\necho ✅ Installed!\r\necho.\r\necho 🖥️ Desktop shortcut created (if possible):\r\necho    Autho Gateway Node\r\necho.\r\necho 🚀 Starting gateway node...\r\necho.\r\ncall Start-Autho-Gateway-Node.bat\r\n\r\npause\r\nexit /b 0\r\n`;
        sendText(body, 'text/plain; charset=utf-8');
        return;
      }

      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      
      if (fs.existsSync(filePath)) {
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.sendFile(filePath);
      } else {
        res.status(404).json({ error: 'File not found' });
      }
    });

    // Download files - Operator Node
    this.app.get('/downloads/operator-node/:filename', (req: Request, res: Response) => {
      const { filename } = req.params;
      const filePath = path.join(process.cwd(), 'downloads', 'operator-node', filename);

      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');

      if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
      } else {
        res.status(404).json({ error: 'File not found' });
      }
    });

    // Download files - Wallet
    this.app.get('/downloads/wallet/:filename', (req: Request, res: Response) => {
      const { filename } = req.params;
      const filePath = path.resolve(process.cwd(), 'downloads', 'wallet', filename);
      
      console.log('[Download] Wallet file requested:', filename);
      console.log('[Download] Resolved path:', filePath);
      console.log('[Download] File exists:', fs.existsSync(filePath));
      
      if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
      } else {
        res.status(404).json({ error: 'File not found', path: filePath });
      }
    });

    // Dashboard with auth check
    this.app.get('/dashboard', (req: Request, res: Response) => {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.sendFile('dashboard.html', { root: './public' });
    });

    this.app.get('/operator', (req: Request, res: Response) => {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.sendFile('operator-portal.html', { root: './public' });
    });

    this.app.get('/operator/dashboard', (req: Request, res: Response) => {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.sendFile('operator-dashboard.html', { root: './public' });
    });

    this.app.get('/operator/apply', (req: Request, res: Response) => {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.sendFile('operator-apply.html', { root: './public' });
    });

    this.app.get('/setup', (req: Request, res: Response) => {
      res.sendFile('setup-wizard.html', { root: './public' });
    });

    this.app.get('/manufacturer', (req: Request, res: Response) => {
      res.sendFile('manufacturer-dashboard.html', { root: './public' });
    });

    this.app.get('/authenticator', (req: Request, res: Response) => {
      res.sendFile('authenticator-dashboard.html', { root: './public' });
    });

    // Note: /retailer route is defined earlier with auth check

    this.app.get('/tokens', (req: Request, res: Response) => {
      res.status(404).send('Not Found');
    });

    this.app.get('/token-dashboard.html', (req: Request, res: Response) => {
      res.status(404).send('Not Found');
    });

    this.app.get('/dashboard-unified.html', (req: Request, res: Response) => {
      res.status(404).send('Not Found');
    });

    // P2P Network Join Page
    this.app.get('/join', (req: Request, res: Response) => {
      res.sendFile('join.html', { root: './public' });
    });

    this.app.get('/buy', (req: Request, res: Response) => {
      res.sendFile('buy.html', { root: './public' });
    });

    // Mobile Reseller Gateway Routes
    this.app.get('/m', (req: Request, res: Response) => {
      res.sendFile('mobile-entry.html', { root: './public' });
    });

    this.app.get('/m/verify', (req: Request, res: Response) => {
      res.sendFile('mobile-verify.html', { root: './public' });
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

    this.app.get('/m/wallet', (req: Request, res: Response) => {
      res.sendFile('mobile-wallet.html', { root: './public' });
    });

    const renderPayPage = async (req: Request, res: Response, handleInput: string) => {
      try {
        const handleRaw = String(handleInput || '').trim().toLowerCase();
        if (!handleRaw) {
          res.status(400).send('Missing handle');
          return;
        }

        const handle = handleRaw.includes('@') ? handleRaw : `${handleRaw}@autho`;
        if (!handle.endsWith('@autho')) {
          res.status(400).send('Invalid handle');
          return;
        }

        const memo = String((req.query as any)?.memo || '').trim();
        const memoEsc = memo
          ? memo.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as any)[c])
          : '';
        const amountSatsStr = String((req.query as any)?.amountSats || '').trim();
        const amountSats = amountSatsStr ? Math.floor(Number(amountSatsStr)) : 0;

        const state = await this.canonicalStateBuilder.buildState();
        let resolvedAccountId = '';
        let resolvedAddress = '';
        for (const acc of state.accounts.values()) {
          const existing = String((acc as any).payHandle || '').trim().toLowerCase();
          if (existing && existing === handle) {
            resolvedAccountId = String((acc as any).accountId || '').trim();
            resolvedAddress = String((acc as any).walletAddress || '').trim();
            break;
          }
        }

        if (!resolvedAddress) {
          res.status(404).send('Pay handle not found');
          return;
        }

        if (!resolvedAddress.match(/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/)) {
          res.status(400).send('Resolved address is invalid');
          return;
        }

        const params: string[] = [];
        if (amountSats > 0 && Number.isFinite(amountSats)) {
          params.push(`amount=${encodeURIComponent((amountSats / 1e8).toFixed(8).replace(/0+$/, '').replace(/\.$/, ''))}`);
        }
        if (memo) {
          params.push(`message=${encodeURIComponent(memo)}`);
        }
        const bip21 = `bitcoin:${resolvedAddress}${params.length ? `?${params.join('&')}` : ''}`;
        const qrUrl = `/api/qr.png?text=${encodeURIComponent(bip21)}`;

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Pay ${handle}</title>
  <style>
    body { background:#0a0a0a; color:#fff; font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin:0; }
    .wrap { max-width: 560px; margin: 0 auto; padding: 24px; }
    .card { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12); border-radius: 16px; padding: 16px; margin-top: 12px; }
    .title { font-weight: 700; font-size: 20px; }
    .muted { color: rgba(255,255,255,0.75); font-size: 13px; line-height: 1.5; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .row { margin-top: 10px; }
    input { width:100%; padding: 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.15); background: rgba(0,0,0,0.2); color:#fff; }
    button, a.btn { display:inline-block; padding: 12px 14px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.15); background: rgba(212,175,55,0.18); color:#fff; text-decoration:none; font-weight: 600; }
    .btn.secondary { background: rgba(255,255,255,0.08); }
    .grid { display:flex; gap:10px; flex-wrap: wrap; }
    img { width: 250px; height: 250px; background:#fff; border-radius: 12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="title">Pay <span class="mono">${handle}</span></div>
    <div class="muted">This page resolves the Autho pay handle to a Bitcoin address. You can pay using any external wallet (Cash App, etc.).</div>

    <div class="card">
      <div class="muted">Bitcoin address</div>
      <div class="row"><input id="addr" class="mono" readonly value="${resolvedAddress}" /></div>
      <div class="row grid">
        <button class="btn secondary" onclick="copyAddr()">Copy Address</button>
        <a class="btn" href="${bip21}">Open in Wallet</a>
      </div>
      ${memo ? `<div class="row muted">Memo: ${memoEsc}</div>` : ''}
      ${(amountSats > 0 && Number.isFinite(amountSats)) ? `<div class="row muted">Amount: ${amountSats} sats</div>` : ''}
      ${resolvedAccountId ? `<div class="row muted">Account: <span class="mono">${resolvedAccountId}</span></div>` : ''}
    </div>

    <div class="card" style="display:flex; justify-content:center;">
      <img alt="Bitcoin payment QR" src="${qrUrl}" />
    </div>
  </div>

  <script>
    function copyAddr() {
      const el = document.getElementById('addr');
      const v = el ? String(el.value || '').trim() : '';
      if (!v) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(v).then(() => alert('Address copied')).catch(() => alert('Copy failed'));
        return;
      }
      try {
        el.focus();
        el.select();
        document.execCommand('copy');
        alert('Address copied');
      } catch {
        alert('Copy failed');
      }
    }
    function escapeHtml(s) {
      return String(s || '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
    }
  </script>
</body>
</html>`);
      } catch (error: any) {
        res.status(500).send(error?.message || 'Internal error');
      }
    };

    this.app.get('/pay', async (req: Request, res: Response) => {
      const handle = String((req.query as any)?.handle || '').trim();
      await renderPayPage(req, res, handle);
    });

    this.app.get('/pay/:handle', async (req: Request, res: Response) => {
      const handle = String((req.params as any)?.handle || '').trim();
      await renderPayPage(req, res, handle);
    });

    this.app.get('/m/offer', (req: Request, res: Response) => {
      res.sendFile('mobile-offer.html', { root: './public' });
    });

    this.app.get('/m/items', (req: Request, res: Response) => {
      res.sendFile('mobile-items.html', { root: './public' });
    });

    this.app.get('/m/offers', (req: Request, res: Response) => {
      res.sendFile('mobile-offers.html', { root: './public' });
    });

    this.app.get('/m/consignment', (req: Request, res: Response) => {
      res.sendFile('mobile-consignment.html', { root: './public' });
    });

    this.app.get('/m/consign', (req: Request, res: Response) => {
      res.sendFile('mobile-consign.html', { root: './public' });
    });

    this.app.get('/m/history', (req: Request, res: Response) => {
      res.sendFile('mobile-history.html', { root: './public' });
    });

    this.app.get('/m/search', (req: Request, res: Response) => {
      res.sendFile('mobile-search.html', { root: './public' });
    });

    this.app.get('/m/login', (req: Request, res: Response) => {
      res.sendFile('mobile-login.html', { root: './public' });
    });

    this.app.get('/health', (req: Request, res: Response) => {
      res.json({ status: 'healthy', operator: this.node.getOperatorInfo() });
    });

    this.app.get('/api/operator/info', (req: Request, res: Response) => {
      res.json(this.node.getOperatorInfo());
    });

    this.app.get('/api/item/:itemId', async (req: Request, res: Response) => {
      try {
        const item = await this.node.getItem(req.params.itemId);
        if (!item) {
          res.status(404).json({ error: 'Item not found' });
          return;
        }
        res.json(item);
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/item/:itemId/proof', async (req: Request, res: Response) => {
      try {
        const proof = await this.node.getItemProof(req.params.itemId);
        res.json(proof);
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/item/:itemId/events', async (req: Request, res: Response) => {
      try {
        const events = await this.node.getItemEvents(req.params.itemId);
        res.json(events);
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/manufacturer/:manufacturerId', async (req: Request, res: Response) => {
      try {
        const manufacturer = await this.node.getManufacturer(req.params.manufacturerId);
        if (!manufacturer) {
          res.status(404).json({ error: 'Manufacturer not found' });
          return;
        }
        res.json(manufacturer);
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/authenticator/:authenticatorId', async (req: Request, res: Response) => {
      try {
        const authenticator = await this.node.getAuthenticator(req.params.authenticatorId);
        if (!authenticator) {
          res.status(404).json({ error: 'Authenticator not found' });
          return;
        }
        res.json(authenticator);
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/item/:itemId/attestations', async (req: Request, res: Response) => {
      try {
        const attestations = await this.node.getAttestationsByItem(req.params.itemId);
        res.json({ attestations });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/event/submit', async (req: Request, res: Response) => {
      try {
        const event: ProtocolEvent = req.body;
        const result = await this.node.submitEvent(event);
        
        if (result.accepted) {
          res.json({ success: true, eventId: event.eventId });
        } else {
          res.status(400).json({ success: false, error: result.error });
        }
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/event/propose', async (req: Request, res: Response) => {
      try {
        const partialEvent = req.body;
        const fullEvent = await this.node.proposeEvent(partialEvent);
        res.json(fullEvent);
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    // Offer API endpoints
    this.app.post('/api/offers/create', async (req: Request, res: Response) => {
      try {
        const { itemId, buyerAddress, amount, sats, expiresIn, itemName } = req.body;
        
        if (!itemId || !amount || !sats) {
          res.status(400).json({ error: 'Missing required fields' });
          return;
        }

        const buyerAddrRaw = String(buyerAddress || '').trim();
        const isOpenOffer = !buyerAddrRaw || buyerAddrRaw.toLowerCase() === 'pending' || buyerAddrRaw.toLowerCase() === 'unclaimed';

        const offerId = `OFFER_${Date.now()}_${Math.random().toString(36).substring(7)}`;
        const expirySeconds = Math.floor((expiresIn || 86400000) / 1000); // Convert ms to seconds

        // Try to get item from canonical state first
        let itemRecord: any = null;
        let sellerAddress = '';

        if (this.canonicalStateBuilder) {
          try {
            const state = await this.canonicalStateBuilder.buildState();

            const now = Date.now();
            const activeAcceptedForItem = Array.from(state.settlements.values()).find(
              (s: any) => String(s?.itemId) === String(itemId) && this.isActiveAcceptedSettlement(s, now)
            );
            if (activeAcceptedForItem) {
              res.status(400).json({ error: 'Item is currently locked by an accepted offer' });
              return;
            }

            const activeConsignmentForItem = Array.from((state as any).consignments?.values?.() || []).find((c: any) => {
              if (!c) return false;
              if (String(c?.itemId || '') !== String(itemId)) return false;
              const status = String(c?.status || '');
              if (status !== 'active' && status !== 'pending') return false;
              const exp = Number(c?.expiresAt || 0);
              if (exp && exp > 0 && now > exp) return false;
              return true;
            });
            if (activeConsignmentForItem) {
              res.status(400).json({ error: 'Item is currently locked by an active consignment' });
              return;
            }

            const canonicalItem = state.items.get(String(itemId));
            if (canonicalItem) {
              itemRecord = canonicalItem;
              sellerAddress = String(canonicalItem.currentOwner || '').trim();
            }
          } catch (e) {
            console.error('[Offer] Failed to get item from canonical state:', e);
          }
        }

        // Fallback to in-memory registry
        if (!itemRecord) {
          itemRecord = this.itemRegistry.getItem(String(itemId));
          if (itemRecord) {
            sellerAddress = String(itemRecord.currentOwner || '').trim();
          }
        }

        if (!itemRecord) {
          res.status(404).json({ error: 'Item not found in registry' });
          return;
        }

        if (!sellerAddress) {
          res.status(400).json({ error: 'Item has no current owner' });
          return;
        }

        const mainNodeAddress = String(this.getFeeAddress() || '').trim();
        const platformFeeSats = PaymentService.calculatePlatformFee(Number(sats));
        const sellerReceivesSats = Number(sats) - platformFeeSats;

        const paymentOutputs = [
          { address: sellerAddress, amountSats: sellerReceivesSats },
          { address: mainNodeAddress, amountSats: platformFeeSats },
        ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

        try {
          const now = Date.now();
          const nonce = randomBytes(32).toString('hex');
          const signatures: QuorumSignature[] = [
            {
              operatorId: process.env.OPERATOR_ID || 'operator-1',
              publicKey: this.node.getOperatorInfo().publicKey,
              signature: createHash('sha256')
                .update(`SETTLEMENT_INITIATED:${offerId}:${now}`)
                .digest('hex'),
            },
          ];

          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.SETTLEMENT_INITIATED,
              timestamp: now,
              nonce,
              settlementId: String(offerId),
              itemId: String(itemId),
              seller: sellerAddress,
              buyer: isOpenOffer ? '' : buyerAddrRaw,
              price: Number(sats),
              escrowAddress: '',
              expiresAt: Number(now + expirySeconds * 1000),
            } as any,
            signatures
          );
        } catch (e: any) {
          console.error('[Settlement] Failed to record SETTLEMENT_INITIATED:', e?.message || String(e));
        }

        const offer = {
          offerId,
          itemId,
          itemName: itemName || 'Unknown Item',
          buyerAddress: isOpenOffer ? '' : buyerAddrRaw,
          sellerAddress,
          amount,
          sats,
          status: isOpenOffer ? 'OPEN' : 'PENDING',
          createdAt: Date.now(),
          expiresAt: Date.now() + expirySeconds * 1000,
          paymentMethod: 'bitcoin',
          platformFeeSats,
          sellerReceivesSats,
          mainNodeFeeAddress: mainNodeAddress,
          paymentOutputs
        };

        // Store offer in memory
        if (!(this.node as any).offers) {
          (this.node as any).offers = new Map();
        }
        (this.node as any).offers.set(offerId, offer);

        console.log(`[API] Offer created: ${offerId} for ${itemName}`);
        console.log(`[API] Amount: ${sats} sats`);

        res.json({ 
          success: true, 
          offerId,
          offer,
          message: isOpenOffer
            ? 'Offer created successfully. Buyer can claim and pay.'
            : 'Offer created successfully. Seller must accept before you can pay.'
        });
      } catch (error: any) {
        console.error('[API] Error creating offer:', error);
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/offers/:offerId/payment-submitted', async (req: Request, res: Response) => {
      try {
        const offerId = String(req.params.offerId || '').trim();
        const txid = String(req.body?.txid || '').trim();
        if (!offerId || !txid) {
          res.status(400).json({ success: false, error: 'Missing offerId or txid' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const settlement: any = state.settlements.get(offerId);
        if (!settlement) {
          res.status(404).json({ success: false, error: 'Offer not found' });
          return;
        }

        const itemId = String(settlement.itemId || '').trim();
        if (!itemId) {
          res.status(400).json({ success: false, error: 'Offer has no itemId' });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`SETTLEMENT_PAYMENT_SUBMITTED:${offerId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.SETTLEMENT_PAYMENT_SUBMITTED,
            timestamp: now,
            nonce,
            settlementId: offerId,
            itemId,
            txid,
          } as any,
          signatures
        );

        res.json({ success: true, offerId, txid, message: 'Payment submitted. Awaiting confirmation.' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/offers/owner/:address', async (req: Request, res: Response) => {
      try {
        const owner = String(req.params.address || '').trim();
        const state = await this.canonicalStateBuilder.buildState();
        await this.sweepExpiredSettlements();
        const now = Date.now();
        const all = Array.from(state.settlements.values());
        const received = all
          .filter((s: any) => String(s?.seller || '').trim() === owner)
          .sort((a: any, b: any) => Number(b?.initiatedAt || 0) - Number(a?.initiatedAt || 0))
          .map((s: any) => ({
            offerId: String(s.settlementId),
            itemId: String(s.itemId),
            itemName: String(state.items.get(String(s.itemId))?.metadata?.name || state.items.get(String(s.itemId))?.metadata?.itemType || ''),
            buyerAddress: String(s.buyer),
            sellerAddress: String(s.seller),
            amount: 0,
            sats: Number(s.price || 0),
            status: this.isSettlementExpired(s, now)
              ? 'EXPIRED'
              : s.status === 'completed'
                ? 'PAID'
                : s.status === 'failed'
                  ? 'FAILED'
                  : s.acceptedAt
                    ? 'ACCEPTED'
                    : (!String(s?.buyer || '').trim() ? 'OPEN' : 'PENDING'),
            createdAt: Number(s.initiatedAt || 0),
            expiresAt: Number(s.expiresAt || 0),
            paymentTxid: s.txid,
            paymentAddress: s.escrowAddress,
          }));

        if (received.length > 0) {
          res.json({ offers: received, count: received.length });
          return;
        }

        const offersMap = (this.node as any).offers || new Map();
        const allOffers = Array.from(offersMap.values());
        const fallback = allOffers.filter((o: any) => String(o?.sellerAddress || '').trim() === owner);
        res.json({ offers: fallback, count: fallback.length });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/offers/:offerId/claim', async (req: Request, res: Response) => {
      try {
        const offerId = String(req.params.offerId || '').trim();
        if (!offerId) {
          res.status(400).json({ error: 'Offer ID required' });
          return;
        }

        const account = await this.getAccountFromSession(req);
        const buyerWallet = String(account?.walletAddress || '').trim();
        if (!buyerWallet) {
          res.status(401).json({ error: 'Login required' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const settlement: any = state.settlements.get(offerId);
        if (!settlement) {
          res.status(404).json({ error: 'Offer not found' });
          return;
        }

        const now = Date.now();

        if (this.isSettlementExpired(settlement, now)) {
          res.status(400).json({ error: 'Offer expired' });
          return;
        }

        if (settlement.status === 'completed') {
          res.status(400).json({ error: 'Offer already completed' });
          return;
        }

        if (settlement.status === 'failed') {
          res.status(400).json({ error: 'Offer already cancelled/failed' });
          return;
        }

        if (settlement.acceptedAt) {
          const existingBuyer = String(settlement?.buyer || '').trim();
          if (existingBuyer && existingBuyer.toLowerCase() !== 'pending' && existingBuyer.toLowerCase() !== 'unclaimed' && existingBuyer !== buyerWallet) {
            res.status(400).json({ error: 'Offer already claimed' });
            return;
          }

          const itemId = String(settlement.itemId || '').trim();
          const priceSats = Number(settlement.price || 0);
          const platformFeeSats = PaymentService.calculatePlatformFee(priceSats);
          const payoutSnap: PlatformFeePayoutSnapshot | null = settlement.platformFeePayouts
            ? (settlement.platformFeePayouts as any)
            : null;
          const mainNodeAddress = String(this.getFeeAddress() || '').trim();
          const feeMainAddr = payoutSnap?.mainNodeAddress ? String(payoutSnap.mainNodeAddress).trim() : mainNodeAddress;
          const feeMainAmt = payoutSnap ? Number(payoutSnap.mainNodeFeeSats || 0) : platformFeeSats;
          const feeOps = payoutSnap ? (Array.isArray(payoutSnap.operatorPayouts) ? payoutSnap.operatorPayouts : []) : [];

          const paymentOutputs = [
            { address: String(settlement.seller || '').trim(), amountSats: priceSats - platformFeeSats },
            { address: feeMainAddr, amountSats: feeMainAmt },
            ...feeOps.map((p: any) => ({
              address: String(p?.address || '').trim(),
              amountSats: Number(p?.amountSats || 0),
            })),
          ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

          res.json({
            success: true,
            message: 'Offer already claimed. You can proceed with payment.',
            offerId,
            itemId,
            status: 'ACCEPTED',
            buyerAddress: buyerWallet,
            paymentOutputs,
            expiresAt: settlement.expiresAt,
          });
          return;
        }

        const currentBuyer = String(settlement?.buyer || '').trim();
        if (currentBuyer && currentBuyer.toLowerCase() !== 'pending' && currentBuyer.toLowerCase() !== 'unclaimed') {
          res.status(400).json({ error: 'Offer is not open for claiming' });
          return;
        }

        const itemId = String(settlement.itemId || '').trim();
        if (!itemId) {
          res.status(400).json({ error: 'Offer has no itemId' });
          return;
        }

        const item: any = state.items.get(itemId);
        if (!item) {
          res.status(404).json({ error: 'Item not found' });
          return;
        }

        const allSettlements = Array.from(state.settlements.values());
        const existingLock = allSettlements.find((s: any) =>
          String(s.itemId) === itemId &&
          String(s.settlementId) !== offerId &&
          this.isActiveAcceptedSettlement(s, now)
        );

        if (existingLock) {
          res.status(400).json({ error: 'Item is already locked by another accepted offer' });
          return;
        }

        const acceptedAt = Date.now();

        const priceSats = Number(settlement.price || 0);
        const platformFeeSats = PaymentService.calculatePlatformFee(priceSats);
        const feeSnap = this.computePlatformFeePayoutSnapshot({ state, platformFeeSats });

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`SETTLEMENT_CLAIMED:${offerId}:${acceptedAt}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.SETTLEMENT_CLAIMED,
            timestamp: acceptedAt,
            nonce,
            settlementId: offerId,
            itemId,
            buyer: buyerWallet,
            acceptedAt,
            platformFeePayouts: feeSnap,
          } as any,
          signatures
        );

        const feeOutputs = [
          { address: String(feeSnap.mainNodeAddress || '').trim(), amountSats: Number(feeSnap.mainNodeFeeSats || 0) },
          ...(Array.isArray(feeSnap.operatorPayouts) ? feeSnap.operatorPayouts : []).map((p: any) => ({
            address: String(p?.address || '').trim(),
            amountSats: Number(p?.amountSats || 0),
          })),
        ];
        const paymentOutputs = [
          { address: String(settlement.seller || '').trim(), amountSats: priceSats - platformFeeSats },
          ...feeOutputs,
        ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

        try {
          const offersMap = (this.node as any).offers || new Map();
          const offer = offersMap.get(offerId);
          if (offer) {
            offer.status = 'ACCEPTED';
            offer.buyerAddress = buyerWallet;
            offer.paymentOutputs = paymentOutputs;
          }
        } catch {}

        res.json({
          success: true,
          message: 'Offer claimed. You can proceed with payment.',
          offerId,
          itemId,
          status: 'ACCEPTED',
          buyerAddress: buyerWallet,
          paymentOutputs,
          expiresAt: settlement.expiresAt,
        });
      } catch (error: any) {
        console.error('[API] Error claiming offer:', error);
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/offers/:offerId', async (req: Request, res: Response) => {
      try {
        const offerId = String(req.params.offerId || '').trim();
        const state = await this.canonicalStateBuilder.buildState();
        const settlement: any = state.settlements.get(offerId);

        if (settlement) {
          const itemName = String(
            state.items.get(String(settlement.itemId))?.metadata?.name ||
              state.items.get(String(settlement.itemId))?.metadata?.itemType ||
              ''
          );

          const sats = Number(settlement.price || 0);
          const mainNodeAddress = String(this.getFeeAddress() || '').trim();
          const platformFeeSats = PaymentService.calculatePlatformFee(sats);
          const sellerReceivesSats = sats - platformFeeSats;

          const payoutSnap: PlatformFeePayoutSnapshot | null = settlement.platformFeePayouts
            ? (settlement.platformFeePayouts as any)
            : null;
          const feeMainAddr = payoutSnap?.mainNodeAddress ? String(payoutSnap.mainNodeAddress).trim() : mainNodeAddress;
          const feeMainAmt = payoutSnap ? Number(payoutSnap.mainNodeFeeSats || 0) : platformFeeSats;
          const feeOps = payoutSnap ? (Array.isArray(payoutSnap.operatorPayouts) ? payoutSnap.operatorPayouts : []) : [];

          const paymentOutputs = [
            { address: String(settlement.seller || '').trim(), amountSats: sellerReceivesSats },
            { address: feeMainAddr, amountSats: feeMainAmt },
            ...feeOps.map((p: any) => ({
              address: String(p?.address || '').trim(),
              amountSats: Number(p?.amountSats || 0),
            })),
          ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

          res.json({
            offerId: String(settlement.settlementId),
            itemId: String(settlement.itemId),
            itemName,
            buyerAddress: String(settlement.buyer),
            sellerAddress: String(settlement.seller),
            amount: 0,
            sats,
            status: this.isSettlementExpired(settlement, Date.now())
              ? 'EXPIRED'
              : settlement.status === 'completed'
                ? 'PAID'
                : settlement.status === 'failed'
                  ? 'FAILED'
                  : settlement.acceptedAt
                    ? 'ACCEPTED'
                    : (!String(settlement?.buyer || '').trim() ? 'OPEN' : 'PENDING'),
            createdAt: Number(settlement.initiatedAt || 0),
            expiresAt: Number(settlement.expiresAt || 0),
            paymentTxid: settlement.txid,
            paymentAddress: settlement.escrowAddress,
            paymentOutputs,
            platformFeeSats,
            sellerReceivesSats,
            mainNodeFeeAddress: feeMainAddr,
            operatorFees: settlement.operatorFees,
          });
          return;
        }

        const offersMap = (this.node as any).offers || new Map();
        const offer = offersMap.get(offerId);
        if (!offer) {
          res.status(404).json({ error: 'Offer not found' });
          return;
        }
        res.json(offer);
      } catch (error: any) {
        console.error('[API] Error fetching offer:', error);
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/offers/user/:address', async (req: Request, res: Response) => {
      try {
        const addr = String(req.params.address || '').trim();
        const state = await this.canonicalStateBuilder.buildState();
        await this.sweepExpiredSettlements();
        const now = Date.now();
        const all = Array.from(state.settlements.values());
        const userOffers = all
          .filter((s: any) => String(s?.buyer || '').trim() === addr)
          .sort((a: any, b: any) => Number(b?.initiatedAt || 0) - Number(a?.initiatedAt || 0))
          .map((s: any) => {
            let status = 'PENDING';
            if (this.isSettlementExpired(s, now)) {
              status = 'EXPIRED';
            } else if (s.status === 'completed') {
              status = 'PAID';
            } else if (s.status === 'failed') {
              status = 'FAILED';
            } else if (s.acceptedAt) {
              status = 'ACCEPTED';
            }

            const sats = Number(s.price || 0);
            const mainNodeAddress = String(this.getFeeAddress() || '').trim();
            const platformFeeSats = PaymentService.calculatePlatformFee(sats);
            const sellerReceivesSats = sats - platformFeeSats;
            const payoutSnap: PlatformFeePayoutSnapshot | null = (s as any)?.platformFeePayouts
              ? ((s as any).platformFeePayouts as any)
              : null;
            const feeMainAddr = payoutSnap?.mainNodeAddress ? String(payoutSnap.mainNodeAddress).trim() : mainNodeAddress;
            const feeMainAmt = payoutSnap ? Number(payoutSnap.mainNodeFeeSats || 0) : platformFeeSats;
            const feeOps = payoutSnap ? (Array.isArray(payoutSnap.operatorPayouts) ? payoutSnap.operatorPayouts : []) : [];

            const paymentOutputs = [
              { address: String(s.seller || '').trim(), amountSats: sellerReceivesSats },
              { address: feeMainAddr, amountSats: feeMainAmt },
              ...feeOps.map((p: any) => ({
                address: String(p?.address || '').trim(),
                amountSats: Number(p?.amountSats || 0),
              })),
            ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);
            
            return {
              offerId: String(s.settlementId),
              itemId: String(s.itemId),
              itemName: String(state.items.get(String(s.itemId))?.metadata?.name || state.items.get(String(s.itemId))?.metadata?.itemType || ''),
              buyerAddress: String(s.buyer),
              sellerAddress: String(s.seller),
              amount: 0,
              sats,
              status,
              createdAt: Number(s.initiatedAt || 0),
              expiresAt: Number(s.expiresAt || 0),
              paymentTxid: s.txid,
              paymentAddress: s.escrowAddress,
              paymentOutputs,
              platformFeeSats,
              sellerReceivesSats,
              mainNodeFeeAddress: mainNodeAddress,
            };
          });

        if (userOffers.length > 0) {
          res.json({ offers: userOffers, count: userOffers.length });
          return;
        }

        const offersMap = (this.node as any).offers || new Map();
        const allOffers = Array.from(offersMap.values());
        const fallback = allOffers.filter((o: any) => String(o?.buyerAddress || '').trim() === addr);
        res.json({ offers: fallback, count: fallback.length });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/offers/item/:itemId', async (req: Request, res: Response) => {
      try {
        const itemId = String(req.params.itemId || '').trim();
        if (!itemId) {
          res.status(400).json({ error: 'Missing itemId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        await this.sweepExpiredSettlements();
        const now = Date.now();

        const mainNodeAddress = String(this.getFeeAddress() || '').trim();

        const offers = Array.from(state.settlements.values())
          .filter((s: any) => String(s?.itemId || '').trim() === itemId)
          .sort((a: any, b: any) => Number(b?.initiatedAt || 0) - Number(a?.initiatedAt || 0))
          .map((s: any) => {
            const sats = Number(s.price || 0);
            const platformFeeSats = PaymentService.calculatePlatformFee(sats);
            const sellerReceivesSats = sats - platformFeeSats;
            const payoutSnap: PlatformFeePayoutSnapshot | null = (s as any)?.platformFeePayouts
              ? ((s as any).platformFeePayouts as any)
              : null;
            const feeMainAddr = payoutSnap?.mainNodeAddress ? String(payoutSnap.mainNodeAddress).trim() : mainNodeAddress;
            const feeMainAmt = payoutSnap ? Number(payoutSnap.mainNodeFeeSats || 0) : platformFeeSats;
            const feeOps = payoutSnap ? (Array.isArray(payoutSnap.operatorPayouts) ? payoutSnap.operatorPayouts : []) : [];

            const paymentOutputs = [
              { address: String(s.seller || '').trim(), amountSats: sellerReceivesSats },
              { address: feeMainAddr, amountSats: feeMainAmt },
              ...feeOps.map((p: any) => ({
                address: String(p?.address || '').trim(),
                amountSats: Number(p?.amountSats || 0),
              })),
            ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

            const status = this.isSettlementExpired(s, now)
              ? 'EXPIRED'
              : s.status === 'completed'
                ? 'PAID'
                : s.status === 'failed'
                  ? 'FAILED'
                  : s.acceptedAt
                    ? 'ACCEPTED'
                    : (!String(s?.buyer || '').trim() ? 'OPEN' : 'PENDING');

            return {
              offerId: String(s.settlementId),
              itemId: String(s.itemId),
              itemName: String(state.items.get(String(s.itemId))?.metadata?.name || state.items.get(String(s.itemId))?.metadata?.itemType || ''),
              buyerAddress: String(s.buyer),
              sellerAddress: String(s.seller),
              amount: 0,
              sats,
              status,
              createdAt: Number(s.initiatedAt || 0),
              acceptedAt: Number(s.acceptedAt || 0) || null,
              expiresAt: Number(s.expiresAt || 0),
              paymentTxid: s.txid,
              paymentAddress: s.escrowAddress,
              paymentOutputs,
              platformFeeSats,
              sellerReceivesSats,
              mainNodeFeeAddress: mainNodeAddress,
            };
          });

        if (offers.length > 0) {
          res.json({ offers, count: offers.length });
          return;
        }

        const offersMap = (this.node as any).offers || new Map();
        const allOffers = Array.from(offersMap.values());
        const fallback = allOffers.filter((o: any) => String(o?.itemId || '').trim() === itemId);
        res.json({ offers: fallback, count: fallback.length });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/register/verify/:itemId', async (req: Request, res: Response) => {
      try {
        const itemId = String(req.params.itemId || '').trim();
        if (!itemId) {
          res.status(400).json({ error: 'Missing itemId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const item: any = state.items.get(itemId);
        if (!item) {
          res.status(404).json({ error: 'Item not found' });
          return;
        }

        const now = Date.now();
        const settlements = Array.from(state.settlements.values())
          .filter((s: any) => String(s?.itemId || '').trim() === itemId)
          .sort((a: any, b: any) => Number(b?.initiatedAt || 0) - Number(a?.initiatedAt || 0));

        const latest: any = settlements.length ? settlements[0] : null;
        const status = latest
          ? (this.isSettlementExpired(latest, now)
              ? 'EXPIRED'
              : latest.status === 'completed'
                ? 'PAID'
                : latest.status === 'failed'
                  ? 'FAILED'
                  : latest.acceptedAt
                    ? 'ACCEPTED'
                    : (!String(latest?.buyer || '').trim() ? 'OPEN' : 'PENDING'))
          : 'NONE';

        const currentOwner = String(item.currentOwner || item.ownerPubKey || '').trim();
        const latestBuyer = String(latest?.buyer || '').trim();
        const paidAndTransferred = Boolean(
          latest && latest.status === 'completed' && latestBuyer && currentOwner && latestBuyer === currentOwner
        );

        const itemName = String(item?.metadata?.name || item?.metadata?.itemType || item?.itemType || '');

        res.json({
          itemId,
          itemName,
          currentOwner,
          latestSettlement: latest
            ? {
                offerId: String(latest.settlementId),
                sellerAddress: String(latest.seller || '').trim(),
                buyerAddress: latestBuyer,
                sats: Number(latest.price || 0),
                status,
                createdAt: Number(latest.initiatedAt || 0),
                acceptedAt: Number(latest.acceptedAt || 0) || null,
                completedAt: Number(latest.completedAt || 0) || null,
                expiresAt: Number(latest.expiresAt || 0) || null,
                txid: String(latest.txid || '').trim(),
              }
            : null,
          paidAndTransferred,
          timestamp: now,
        });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/offers/:offerId/counter', async (req: Request, res: Response) => {
      try {
        const offerId = String(req.params.offerId || '').trim();
        if (!offerId) {
          res.status(400).json({ error: 'Offer ID required' });
          return;
        }

        const account = await this.getAccountFromSession(req);
        const buyerWallet = String(account?.walletAddress || '').trim();
        if (!buyerWallet) {
          res.status(401).json({ error: 'Login required' });
          return;
        }

        const sats = Number(req.body?.sats || 0);
        const expiresIn = Number(req.body?.expiresIn || 0);
        if (!Number.isFinite(sats) || sats <= 0) {
          res.status(400).json({ error: 'Invalid sats' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const base: any = state.settlements.get(offerId);
        if (!base) {
          res.status(404).json({ error: 'Offer not found' });
          return;
        }

        const now = Date.now();
        if (this.isSettlementExpired(base, now)) {
          res.status(400).json({ error: 'Offer expired' });
          return;
        }
        if (base.status === 'completed') {
          res.status(400).json({ error: 'Offer already completed' });
          return;
        }
        if (base.status === 'failed') {
          res.status(400).json({ error: 'Offer already cancelled/failed' });
          return;
        }

        const itemId = String(base.itemId || '').trim();
        if (!itemId) {
          res.status(400).json({ error: 'Offer has no itemId' });
          return;
        }

        const item: any = state.items.get(itemId);
        if (!item) {
          res.status(404).json({ error: 'Item not found' });
          return;
        }

        const sellerAddress = String(item.currentOwner || base.seller || '').trim();
        if (!sellerAddress) {
          res.status(400).json({ error: 'Offer has no seller' });
          return;
        }

        if (sellerAddress === buyerWallet) {
          res.status(400).json({ error: 'You cannot counter-offer on your own item' });
          return;
        }

        const expirySeconds = Math.floor((expiresIn || 86400000) / 1000);
        const counterOfferId = `OFFER_${Date.now()}_${Math.random().toString(36).substring(7)}`;

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`SETTLEMENT_INITIATED:${counterOfferId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.SETTLEMENT_INITIATED,
            timestamp: now,
            nonce,
            settlementId: String(counterOfferId),
            itemId: String(itemId),
            seller: sellerAddress,
            buyer: buyerWallet,
            price: Number(sats),
            escrowAddress: '',
            expiresAt: Number(now + expirySeconds * 1000),
          } as any,
          signatures
        );

        try {
          const mainNodeAddress = String(this.getFeeAddress() || '').trim();
          const platformFeeSats = PaymentService.calculatePlatformFee(Number(sats));
          const sellerReceivesSats = Number(sats) - platformFeeSats;
          const paymentOutputs = [
            { address: sellerAddress, amountSats: sellerReceivesSats },
            { address: mainNodeAddress, amountSats: platformFeeSats },
          ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

          if (!(this.node as any).offers) {
            (this.node as any).offers = new Map();
          }
          (this.node as any).offers.set(counterOfferId, {
            offerId: counterOfferId,
            itemId,
            itemName: String(item?.metadata?.itemType || item?.metadata?.name || item?.itemType || 'Unknown Item'),
            buyerAddress: buyerWallet,
            sellerAddress,
            amount: 0,
            sats: Number(sats),
            status: 'PENDING',
            createdAt: now,
            expiresAt: Number(now + expirySeconds * 1000),
            paymentMethod: 'bitcoin',
            platformFeeSats,
            sellerReceivesSats,
            mainNodeFeeAddress: mainNodeAddress,
            paymentOutputs,
            counterOf: offerId,
          });
        } catch {}

        res.json({
          success: true,
          counterOfferId,
          itemId,
          sellerAddress,
          buyerAddress: buyerWallet,
          sats: Number(sats),
          message: 'Counter offer created. Waiting for seller to accept.',
        });
      } catch (error: any) {
        console.error('[API] Error creating counter offer:', error);
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/offers/:offerId/accept', async (req: Request, res: Response) => {
      try {
        const offerId = String(req.params.offerId || '').trim();
        if (!offerId) {
          res.status(400).json({ error: 'Offer ID required' });
          return;
        }

        // Get the settlement from canonical state
        const state = await this.canonicalStateBuilder.buildState();
        const settlement: any = state.settlements.get(offerId);
        
        if (!settlement) {
          res.status(404).json({ error: 'Offer not found' });
          return;
        }

        const now = Date.now();

        if (this.isSettlementExpired(settlement, now)) {
          try {
            const nonce = randomBytes(32).toString('hex');
            const signatures: QuorumSignature[] = [
              {
                operatorId: process.env.OPERATOR_ID || 'operator-1',
                publicKey: this.node.getOperatorInfo().publicKey,
                signature: createHash('sha256')
                  .update(`SETTLEMENT_FAILED:${offerId}:${now}`)
                  .digest('hex'),
              },
            ];

            await this.canonicalEventStore.appendEvent(
              {
                type: EventType.SETTLEMENT_FAILED,
                timestamp: now,
                nonce,
                settlementId: offerId,
                itemId: String(settlement.itemId || ''),
                reason: 'expired',
              } as any,
              signatures
            );
          } catch {}

          res.status(400).json({ error: 'Offer expired' });
          return;
        }

        if (settlement.status === 'completed') {
          res.status(400).json({ error: 'Offer already completed' });
          return;
        }

        if (settlement.status === 'failed') {
          res.status(400).json({ error: 'Offer already cancelled/failed' });
          return;
        }

        // Check if item exists and is not already locked
        const itemId = String(settlement.itemId);
        const item: any = state.items.get(itemId);
        if (!item) {
          res.status(404).json({ error: 'Item not found' });
          return;
        }

        const allSettlements = Array.from(state.settlements.values());
        const existingLock = allSettlements.find((s: any) =>
          String(s.itemId) === itemId &&
          String(s.settlementId) !== offerId &&
          this.isActiveAcceptedSettlement(s, now)
        );

        if (existingLock) {
          res.status(400).json({ error: 'Item is already locked by another accepted offer' });
          return;
        }

        // Verify the requester is the seller
        const sessionId = String(req.headers.authorization || '').replace('Bearer ', '').trim();
        if (!sessionId) {
          res.status(401).json({ error: 'Login required' });
          return;
        }

        const session = this.userSessions.get(sessionId);
        if (!session || !session.accountId) {
          res.status(401).json({ error: 'Invalid session' });
          return;
        }

        const account: any = state.accounts.get(session.accountId);
        const sellerWallet = String(account?.walletAddress || '').trim();
        const settlementSeller = String(settlement.seller || '').trim();
        if (!sellerWallet) {
          res.status(401).json({ error: 'Invalid session' });
          return;
        }
        if (sellerWallet !== settlementSeller) {
          res.status(403).json({ error: 'Only the seller can accept this offer' });
          return;
        }

        if (settlement.acceptedAt) {
          const priceSats = Number(settlement.price || 0);
          const platformFeeSats = PaymentService.calculatePlatformFee(priceSats);
          const mainNodeAddress = String(this.getFeeAddress() || '').trim();
          const payoutSnap: PlatformFeePayoutSnapshot | null = settlement.platformFeePayouts
            ? (settlement.platformFeePayouts as any)
            : null;
          const feeMainAddr = payoutSnap?.mainNodeAddress ? String(payoutSnap.mainNodeAddress).trim() : mainNodeAddress;
          const feeMainAmt = payoutSnap ? Number(payoutSnap.mainNodeFeeSats || 0) : platformFeeSats;
          const feeOps = payoutSnap ? (Array.isArray(payoutSnap.operatorPayouts) ? payoutSnap.operatorPayouts : []) : [];

          const paymentOutputs = [
            { address: String(settlement.seller || '').trim(), amountSats: priceSats - platformFeeSats },
            { address: feeMainAddr, amountSats: feeMainAmt },
            ...feeOps.map((p: any) => ({
              address: String(p?.address || '').trim(),
              amountSats: Number(p?.amountSats || 0),
            })),
          ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);

          res.json({
            success: true,
            message: 'Offer already accepted. Buyer can proceed with payment.',
            offerId,
            itemId,
            status: 'ACCEPTED',
            paymentOutputs,
            expiresAt: settlement.expiresAt,
          });
          return;
        }

        // Persist acceptance to canonical event store
        const acceptedAt = Date.now();

        const priceSats = Number(settlement.price || 0);
        const platformFeeSats = PaymentService.calculatePlatformFee(priceSats);
        const feeSnap = this.computePlatformFeePayoutSnapshot({ state, platformFeeSats });

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`SETTLEMENT_ACCEPTED:${offerId}:${acceptedAt}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.SETTLEMENT_ACCEPTED,
            timestamp: acceptedAt,
            nonce,
            settlementId: offerId,
            itemId,
            acceptedAt,
            platformFeePayouts: feeSnap,
          } as any,
          signatures
        );

        console.log(`[Settlement] Offer ${offerId} accepted by seller`);

        const feeOutputs = [
          { address: String(feeSnap.mainNodeAddress || '').trim(), amountSats: Number(feeSnap.mainNodeFeeSats || 0) },
          ...(Array.isArray(feeSnap.operatorPayouts) ? feeSnap.operatorPayouts : []).map((p: any) => ({
            address: String(p?.address || '').trim(),
            amountSats: Number(p?.amountSats || 0),
          })),
        ];
        const paymentOutputs = [
          { address: String(settlement.seller || '').trim(), amountSats: priceSats - platformFeeSats },
          ...feeOutputs,
        ].filter((o: any) => o && o.address && Number(o.amountSats) > 0);
        
        res.json({ 
          success: true, 
          message: 'Offer accepted. Item is now locked. Buyer can proceed with payment.',
          offerId,
          itemId,
          status: 'ACCEPTED',
          paymentOutputs,
          expiresAt: settlement.expiresAt
        });
      } catch (error: any) {
        console.error('[API] Error accepting offer:', error);
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/offers/:offerId/cancel', async (req: Request, res: Response) => {
      try {
        const offerId = String(req.params.offerId || '').trim();
        if (!offerId) {
          res.status(400).json({ error: 'Offer ID required' });
          return;
        }

        const account = await this.getAccountFromSession(req);
        const actorWallet = String(account?.walletAddress || '').trim();
        if (!actorWallet) {
          res.status(401).json({ error: 'Login required' });
          return;
        }

        // Canonical cancellation (preferred)
        try {
          const state = await this.canonicalStateBuilder.buildState();
          const settlement: any = state.settlements.get(offerId);
          if (settlement) {
            if (settlement.status === 'completed') {
              res.status(400).json({ error: 'Offer already completed' });
              return;
            }

            if (settlement.acceptedAt) {
              res.status(400).json({ error: 'Offer already accepted' });
              return;
            }

            const seller = String(settlement.seller || '').trim();
            const buyer = String(settlement.buyer || '').trim();
            if (actorWallet !== seller && actorWallet !== buyer) {
              res.status(403).json({ error: 'Not authorized to cancel this offer' });
              return;
            }

            const now = Date.now();
            const nonce = randomBytes(32).toString('hex');
            const signatures: QuorumSignature[] = [
              {
                operatorId: process.env.OPERATOR_ID || 'operator-1',
                publicKey: this.node.getOperatorInfo().publicKey,
                signature: createHash('sha256')
                  .update(`SETTLEMENT_FAILED:${offerId}:${now}`)
                  .digest('hex'),
              },
            ];

            await this.canonicalEventStore.appendEvent(
              {
                type: EventType.SETTLEMENT_FAILED,
                timestamp: now,
                nonce,
                settlementId: offerId,
                itemId: String(settlement.itemId || ''),
                reason: 'cancelled',
              } as any,
              signatures
            );

            res.json({ success: true, message: 'Offer cancelled' });
            return;
          }
        } catch (e: any) {
          console.error('[Settlement] Canonical cancel failed:', e?.message || String(e));
        }

        const offersMap = (this.node as any).offers || new Map();
        const offer = offersMap.get(offerId);
        
        if (!offer) {
          res.status(404).json({ error: 'Offer not found' });
          return;
        }

        if (String(offer.status || '').toUpperCase() === 'PAID' || String(offer.status || '').toUpperCase() === 'ACCEPTED') {
          res.status(400).json({ error: 'Offer already accepted' });
          return;
        }

        const seller = String(offer?.sellerAddress || offer?.seller || '').trim();
        const buyer = String(offer?.buyerAddress || offer?.buyer || '').trim();
        if (actorWallet !== seller && actorWallet !== buyer) {
          res.status(403).json({ error: 'Not authorized to cancel this offer' });
          return;
        }

        offer.status = 'CANCELLED';
        offer.cancelledAt = Date.now();

        try {
          const now = Date.now();
          const nonce = randomBytes(32).toString('hex');
          const signatures: QuorumSignature[] = [
            {
              operatorId: process.env.OPERATOR_ID || 'operator-1',
              publicKey: this.node.getOperatorInfo().publicKey,
              signature: createHash('sha256')
                .update(`SETTLEMENT_FAILED:${req.params.offerId}:${now}`)
                .digest('hex'),
            },
          ];
          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.SETTLEMENT_FAILED,
              timestamp: now,
              nonce,
              settlementId: offerId,
              itemId: String(offer?.itemId || ''),
              reason: 'cancelled',
            } as any,
            signatures
          );
        } catch (e: any) {
          console.error('[Settlement] Failed to record SETTLEMENT_FAILED:', e?.message || String(e));
        }
        
        res.json({ success: true, message: 'Offer cancelled' });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    // Transaction history API
    this.app.get('/api/history/:address', async (req: Request, res: Response) => {
      try {
        // Mock transaction history for now
        const transactions: any[] = [];
        
        // Get user's items
        const itemsMap = (this.node as any).items || new Map();
        const userItems = Array.from(itemsMap.values()).filter((item: any) => 
          item.ownerPubKey === req.params.address || 
          item.manufacturerId === req.params.address
        );

        // Add item registrations to history
        userItems.forEach((item: any) => {
          transactions.push({
            type: 'ITEM_REGISTERED',
            itemId: item.itemId,
            itemName: item.itemType,
            timestamp: item.registeredAt,
            description: `Registered ${item.itemType}`
          });
        });

        // Get user's offers
        const offersMap = (this.node as any).offers || new Map();
        const userOffers = Array.from(offersMap.values()).filter((o: any) => 
          o.buyerAddress === req.params.address
        );

        // Add offers to history
        userOffers.forEach((offer: any) => {
          transactions.push({
            type: 'OFFER_CREATED',
            itemId: offer.itemId,
            amount: offer.amount,
            sats: offer.sats,
            timestamp: offer.createdAt,
            description: `Made offer of $${offer.amount}`
          });
        });

        // Sort by timestamp descending
        transactions.sort((a, b) => b.timestamp - a.timestamp);
        
        res.json({ transactions, count: transactions.length });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/event/sign', async (req: Request, res: Response) => {
      try {
        const event: ProtocolEvent = req.body;
        const signature = await this.node.signEvent(event);
        res.json(signature);
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    // Wallet API endpoints
    this.app.post('/api/wallet/create', this.walletAPI.createWallet.bind(this.walletAPI));
    this.app.post('/api/wallet/restore', this.walletAPI.restoreWallet.bind(this.walletAPI));
    this.app.post('/api/wallet/validate', this.walletAPI.validateAddress.bind(this.walletAPI));
    this.app.post('/api/wallet/import', this.walletAPI.importWallet.bind(this.walletAPI));

    // Owner-requested verification job APIs
    this.app.get('/api/verification/requests', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const addr = String(account?.walletAddress || '').trim();
        const state = await this.canonicalStateBuilder.buildState();
        const all = Array.from(state.verificationRequests.values());

        const role = String(account?.role || '').trim();
        const visible = all.filter((r: any) => {
          if (!r) return false;
          if (role === 'authenticator') return String(r.authenticatorId) === String(account.accountId);
          return String(r.ownerWallet) === addr;
        });

        res.json({ success: true, requests: visible, count: visible.length });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/verification/requests', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const ownerWallet = String(account?.walletAddress || '').trim();
        if (!ownerWallet) {
          res.status(400).json({ success: false, error: 'Account has no wallet address' });
          return;
        }

        const itemId = String(req.body?.itemId || '').trim();
        const authenticatorId = String(req.body?.authenticatorId || '').trim();
        const serviceFeeSats = Number(req.body?.serviceFeeSats || 0);
        const maxServiceFeeSats = req.body?.maxServiceFeeSats !== undefined
          ? Number(req.body?.maxServiceFeeSats)
          : undefined;
        const expiresInMs = Number(req.body?.expiresInMs || 0);

        if (!itemId || !authenticatorId) {
          res.status(400).json({ success: false, error: 'Missing itemId or authenticatorId' });
          return;
        }
        const minServiceSats = Number(process.env.VERIFICATION_MIN_SERVICE_FEE_SATS || 1000);
        if (!Number.isFinite(serviceFeeSats) || serviceFeeSats < minServiceSats) {
          res.status(400).json({ success: false, error: `Invalid serviceFeeSats (min ${minServiceSats})` });
          return;
        }
        if (maxServiceFeeSats !== undefined) {
          if (!Number.isFinite(maxServiceFeeSats) || maxServiceFeeSats < serviceFeeSats) {
            res.status(400).json({ success: false, error: 'Invalid maxServiceFeeSats' });
            return;
          }
        }

        const state = await this.canonicalStateBuilder.buildState();
        const item: any = state.items.get(itemId);
        if (!item) {
          res.status(404).json({ success: false, error: 'Item not found' });
          return;
        }

        if (String(item.currentOwner || '').trim() !== ownerWallet) {
          res.status(403).json({ success: false, error: 'Only the current owner can request verification' });
          return;
        }

        const existingActive = Array.from(state.verificationRequests.values()).find((r: any) => {
          if (!r) return false;
          if (String(r.itemId || '') !== itemId) return false;
          const st = String(r.status || '');
          return st === 'open' || st === 'accepted';
        });
        if (existingActive) {
          res.status(400).json({ success: false, error: 'An active verification request already exists for this item' });
          return;
        }

        const authenticatorAccount: any = state.accounts.get(authenticatorId);
        if (!authenticatorAccount) {
          res.status(404).json({ success: false, error: 'Authenticator account not found' });
          return;
        }
        if (String(authenticatorAccount.role) !== 'authenticator') {
          res.status(403).json({ success: false, error: 'Account is not an approved authenticator' });
          return;
        }
        if (String(authenticatorAccount.verifierStatus || 'active') === 'revoked') {
          res.status(403).json({ success: false, error: 'Authenticator is revoked' });
          return;
        }

        const authenticatorWallet = String(authenticatorAccount.walletAddress || '').trim();
        if (!authenticatorWallet) {
          res.status(400).json({ success: false, error: 'Authenticator has no wallet address' });
          return;
        }

        const platformFeeBps = Number(process.env.VERIFICATION_PLATFORM_FEE_BPS || 100);
        const platformFlatFeeSats = Number(process.env.VERIFICATION_PLATFORM_FLAT_FEE_SATS || 1000);
        const platformPercentFeeSats = Number.isFinite(platformFeeBps) && platformFeeBps > 0
          ? Math.floor(serviceFeeSats * (platformFeeBps / 10_000))
          : 0;
        const platformFeeSats = platformPercentFeeSats + (Number.isFinite(platformFlatFeeSats) && platformFlatFeeSats > 0 ? platformFlatFeeSats : 0);
        const platformFeeAddress = this.network === 'mainnet'
          ? '1FMcxZRUWVDbKy7DxAosW7sM5PUntAkJ9U'
          : String(process.env.FEE_ADDRESS_TESTNET || '').trim();
        const requestId = `VREQ_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
        const now = Date.now();

        const commitmentHex = createHash('sha256')
          .update(`VERIFICATION_PAYMENT_V1:${requestId}:${itemId}:${ownerWallet}:${authenticatorId}`)
          .digest('hex');

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`VERIFICATION_REQUEST_CREATED:${requestId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.VERIFICATION_REQUEST_CREATED,
            timestamp: now,
            nonce,
            requestId,
            itemId,
            ownerWallet,
            authenticatorId,
            authenticatorWallet,
            serviceFeeSats,
            maxServiceFeeSats: maxServiceFeeSats !== undefined ? maxServiceFeeSats : undefined,
            platformFeeSats,
            commitmentHex,
            expiresAt: expiresInMs && Number.isFinite(expiresInMs) && expiresInMs > 0 ? now + expiresInMs : undefined,
          } as any,
          signatures
        );

        res.json({
          success: true,
          request: {
            requestId,
            itemId,
            ownerWallet,
            authenticatorId,
            authenticatorWallet,
            serviceFeeSats,
            maxServiceFeeSats: maxServiceFeeSats !== undefined ? maxServiceFeeSats : null,
            platformFeeSats,
            platformFeeAddress: platformFeeAddress || null,
            commitmentHex,
            expiresAt: expiresInMs && Number.isFinite(expiresInMs) && expiresInMs > 0 ? now + expiresInMs : null,
            status: 'open',
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/verification/requests/:requestId/accept', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }
        if (String(account?.role || '').trim() !== 'authenticator') {
          res.status(403).json({ success: false, error: 'Authenticator role required' });
          return;
        }
        if (String(account?.verifierStatus || 'active') === 'revoked') {
          res.status(403).json({ success: false, error: 'Authenticator is revoked' });
          return;
        }

        if (!this.enforceFreshBondOrRespond(res, account, 'authenticator')) return;

        const requestId = String(req.params.requestId || '').trim();
        if (!requestId) {
          res.status(400).json({ success: false, error: 'Missing requestId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const reqState: any = state.verificationRequests.get(requestId);
        if (!reqState) {
          res.status(404).json({ success: false, error: 'Request not found' });
          return;
        }
        if (String(reqState.status) !== 'open') {
          res.status(400).json({ success: false, error: 'Request is not open' });
          return;
        }

        if (String(reqState.authenticatorId) !== String(account.accountId)) {
          res.status(403).json({ success: false, error: 'Only the selected authenticator can accept this request' });
          return;
        }

        const requestedFee = Number(reqState.serviceFeeSats || 0);
        const maxFee = reqState.maxServiceFeeSats !== undefined ? Number(reqState.maxServiceFeeSats) : undefined;
        const proposedFee = req.body?.serviceFeeSats !== undefined ? Number(req.body?.serviceFeeSats) : undefined;

        const minServiceSats = Number(process.env.VERIFICATION_MIN_SERVICE_FEE_SATS || 1000);
        const acceptedServiceFeeSats = proposedFee !== undefined ? proposedFee : requestedFee;
        if (!Number.isFinite(acceptedServiceFeeSats) || acceptedServiceFeeSats < minServiceSats) {
          res.status(400).json({ success: false, error: `Invalid serviceFeeSats (min ${minServiceSats})` });
          return;
        }
        if (maxFee !== undefined && acceptedServiceFeeSats > maxFee) {
          res.status(400).json({ success: false, error: `Service fee exceeds requester max (${maxFee})` });
          return;
        }

        const platformFeeBps = Number(process.env.VERIFICATION_PLATFORM_FEE_BPS || 100);
        const platformFlatFeeSats = Number(process.env.VERIFICATION_PLATFORM_FLAT_FEE_SATS || 1000);
        const platformPercentFeeSats = Number.isFinite(platformFeeBps) && platformFeeBps > 0
          ? Math.floor(acceptedServiceFeeSats * (platformFeeBps / 10_000))
          : 0;
        const acceptedPlatformFeeSats = platformPercentFeeSats + (Number.isFinite(platformFlatFeeSats) && platformFlatFeeSats > 0 ? platformFlatFeeSats : 0);

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`VERIFICATION_REQUEST_ACCEPTED:${requestId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.VERIFICATION_REQUEST_ACCEPTED,
            timestamp: now,
            nonce,
            requestId,
            itemId: String(reqState.itemId),
            authenticatorId: String(account.accountId),
            acceptedAt: now,
            serviceFeeSats: acceptedServiceFeeSats,
            platformFeeSats: acceptedPlatformFeeSats,
          } as any,
          signatures
        );

        res.json({
          success: true,
          requestId,
          status: 'accepted',
          acceptedAt: now,
          serviceFeeSats: acceptedServiceFeeSats,
          platformFeeSats: acceptedPlatformFeeSats,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/verification/requests/:requestId/complete', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }
        if (String(account?.role || '').trim() !== 'authenticator') {
          res.status(403).json({ success: false, error: 'Authenticator role required' });
          return;
        }
        if (String(account?.verifierStatus || 'active') === 'revoked') {
          res.status(403).json({ success: false, error: 'Authenticator is revoked' });
          return;
        }

        if (!this.enforceFreshBondOrRespond(res, account, 'authenticator')) return;

        const requestId = String(req.params.requestId || '').trim();
        const paymentTxid = String(req.body?.paymentTxid || '').trim();
        const serialNumber = String(req.body?.serialNumber || '').trim();
        const isAuthentic = Boolean(req.body?.isAuthentic);
        const confidence = String(req.body?.confidence || '').trim() as any;
        const notes = req.body?.notes;
        const images = req.body?.images;
        const authenticatorSignature = String(req.body?.authenticatorSignature || '').trim();

        if (!requestId || !paymentTxid) {
          res.status(400).json({ success: false, error: 'Missing requestId or paymentTxid' });
          return;
        }
        if (!serialNumber) {
          res.status(400).json({ success: false, error: 'Missing serialNumber' });
          return;
        }
        if (confidence !== 'high' && confidence !== 'medium' && confidence !== 'low') {
          res.status(400).json({ success: false, error: 'Invalid confidence' });
          return;
        }
        if (!authenticatorSignature) {
          res.status(400).json({ success: false, error: 'Missing authenticatorSignature' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const reqState: any = state.verificationRequests.get(requestId);
        if (!reqState) {
          res.status(404).json({ success: false, error: 'Request not found' });
          return;
        }
        if (String(reqState.authenticatorId) !== String(account.accountId)) {
          res.status(403).json({ success: false, error: 'Only the selected authenticator can complete this request' });
          return;
        }
        if (String(reqState.status) !== 'accepted' && String(reqState.status) !== 'open') {
          res.status(400).json({ success: false, error: 'Request is not in a completable state' });
          return;
        }

        try {
          const proof = await this.registryAPI.verifyVerificationPaymentOrThrow({
            paymentTxid,
            commitmentHex: String(reqState.commitmentHex),
            requiredConfirmations: 6,
            authenticatorAddress: String(reqState.authenticatorWallet),
            serviceFeeSats: Number(reqState.serviceFeeSats),
            platformFeeSats: Number(reqState.platformFeeSats),
          });

          const now = Date.now();
          const nonce = randomBytes(32).toString('hex');
          const signatures: QuorumSignature[] = [
            {
              operatorId: process.env.OPERATOR_ID || 'operator-1',
              publicKey: this.node.getOperatorInfo().publicKey,
              signature: createHash('sha256')
                .update(`VERIFICATION_REQUEST_COMPLETED:${requestId}:${now}`)
                .digest('hex'),
            },
          ];

          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.VERIFICATION_REQUEST_COMPLETED,
              timestamp: now,
              nonce,
              requestId,
              itemId: String(reqState.itemId),
              authenticatorId: String(account.accountId),
              completedAt: now,
              paymentTxid,
              blockHeight: proof.blockHeight,
              serviceFeeSats: Number(reqState.serviceFeeSats),
              platformFeeSats: Number(reqState.platformFeeSats),
              commitmentHex: String(reqState.commitmentHex),
            } as any,
            signatures
          );

          await this.registryAPI.recordAuthenticationForVerificationJob({
            itemId: String(reqState.itemId),
            authenticatorId: String(account.accountId),
            serialNumber,
            isAuthentic,
            confidence,
            notes,
            images,
            authenticatorSignature,
            paymentTxid,
            commitmentHex: String(reqState.commitmentHex),
            paymentBlockHeight: proof.blockHeight,
          });

          res.json({
            success: true,
            requestId,
            itemId: String(reqState.itemId),
            paymentTxid,
            blockHeight: proof.blockHeight,
            confirmations: proof.confirmations,
            message: 'Verification completed and attestation recorded',
          });
        } catch (e: any) {
          if (String(e?.code || '') === 'PAYMENT_TX_NOT_CONFIRMED') {
            res.status(409).json({
              success: false,
              error: 'Payment transaction pending confirmations',
              paymentTxid,
              confirmations: Number(e?.confirmations || 0),
              requiredConfirmations: Number(e?.requiredConfirmations || 6),
              blockHeight: e?.blockHeight,
            });
            return;
          }
          res.status(400).json({ success: false, error: e?.message || 'Payment verification failed' });
        }
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Registry API endpoints (regulatory compliant)
    this.app.post('/api/registry/item', this.registryAPI.registerItem.bind(this.registryAPI));

    this.app.post('/api/registry/item/user', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const walletAddress = String(account?.walletAddress || '').trim();
        if (!walletAddress) {
          res.status(400).json({ success: false, error: 'Account has no wallet address' });
          return;
        }

        try {
          const item = await this.registryAPI.registerItemAsIssuer({
            requestBody: req.body,
            issuerRole: 'user',
            issuerAccountId: String(account.accountId || '').trim(),
            issuerWalletAddress: walletAddress,
          });

          res.json({ success: true, itemRecord: item, message: 'User item registered' });
        } catch (e: any) {
          if (String(e?.code || '') === 'FEE_TX_NOT_CONFIRMED') {
            res.status(409).json({
              success: false,
              error: 'Fee transaction pending confirmations',
              feeTxid: req.body?.feeTxid,
              confirmations: Number(e?.confirmations || 0),
              requiredConfirmations: Number(e?.requiredConfirmations || 6),
              blockHeight: e?.blockHeight,
            });
            return;
          }
          res.status(400).json({ success: false, error: e?.message || 'Failed to register user item' });
        }
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/registry/item/authenticator', async (req: Request, res: Response) => {
      try {
        const account = await this.getAccountFromSession(req);
        if (!account) {
          res.status(401).json({ success: false, error: 'Login required' });
          return;
        }

        const walletAddress = String(account?.walletAddress || '').trim();
        if (!walletAddress) {
          res.status(400).json({ success: false, error: 'Account has no wallet address' });
          return;
        }

        try {
          const item = await this.registryAPI.registerItemAsIssuer({
            requestBody: req.body,
            issuerRole: 'authenticator',
            issuerAccountId: String(account.accountId || '').trim(),
            issuerWalletAddress: walletAddress,
          });

          res.json({ success: true, itemRecord: item, message: 'Authenticator item registered' });
        } catch (e: any) {
          if (String(e?.code || '') === 'FEE_TX_NOT_CONFIRMED') {
            res.status(409).json({
              success: false,
              error: 'Fee transaction pending confirmations',
              feeTxid: req.body?.feeTxid,
              confirmations: Number(e?.confirmations || 0),
              requiredConfirmations: Number(e?.requiredConfirmations || 6),
              blockHeight: e?.blockHeight,
            });
            return;
          }
          res.status(400).json({ success: false, error: e?.message || 'Failed to register authenticator item' });
        }
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/registry/transfer', this.registryAPI.transferOwnership.bind(this.registryAPI));
    this.app.post('/api/registry/authenticate', this.registryAPI.authenticateItem.bind(this.registryAPI));
    this.app.get('/api/registry/items', this.registryAPI.getAllItems.bind(this.registryAPI));
    this.app.get('/api/registry/item/:itemId', this.registryAPI.getItem.bind(this.registryAPI));
    this.app.get('/api/registry/item/:itemId/history', this.registryAPI.getOwnershipHistory.bind(this.registryAPI));
    this.app.get('/api/registry/owner/:address', this.registryAPI.getItemsByOwner.bind(this.registryAPI));
    this.app.get('/api/registry/manufacturer/:manufacturerId', this.registryAPI.getItemsByManufacturer.bind(this.registryAPI));
    this.app.get('/api/registry/stats', this.registryAPI.getStats.bind(this.registryAPI));
    this.app.get('/api/registry/export', this.registryAPI.exportLedger.bind(this.registryAPI));
    this.app.post('/api/registry/import', this.registryAPI.importLedger.bind(this.registryAPI));

    // P2P Network Join API endpoints
    this.app.get('/api/join/config', this.joinAPI.getJoinConfig.bind(this.joinAPI));
    this.app.get('/bootstrap.json', this.joinAPI.getBootstrapConfig.bind(this.joinAPI));
    this.app.get('/seed-manifest.json', this.joinAPI.getSeedManifest.bind(this.joinAPI));
    this.app.post('/api/join/verify-bootstrap', this.joinAPI.verifyBootstrapConfig.bind(this.joinAPI));
    this.app.get('/api/join/peers', this.joinAPI.getPeers.bind(this.joinAPI));
    this.app.get('/api/join/network-stats', this.joinAPI.getNetworkStats.bind(this.joinAPI));

    // Gateway nodes status endpoint
    this.app.get('/api/network/gateways', (req: Request, res: Response) => {
      const gatewayEntries = Array.from(this.wsConnections.entries()).filter(([, meta]) => meta.type === 'gateway');
      const gwByKey = new Map<string, any>();
      for (const [client, meta] of gatewayEntries) {
        const key = String((meta as any).ip || 'unknown').trim() || 'unknown';
        const connected = client.readyState === WebSocket.OPEN;
        const existing = gwByKey.get(key);
        if (!existing) {
          gwByKey.set(key, {
            key,
            connected,
            connectedAt: meta.connectedAt,
            lastSeen: meta.lastSeen,
          });
          continue;
        }

        existing.connected = Boolean(existing.connected || connected);
        existing.connectedAt = Math.min(Number(existing.connectedAt || 0), Number(meta.connectedAt || 0)) || existing.connectedAt;
        existing.lastSeen = Math.max(Number(existing.lastSeen || 0), Number(meta.lastSeen || 0)) || existing.lastSeen;
      }

      const gateways = Array.from(gwByKey.values()).map((g, index) => ({
        id: `gateway-${index + 1}`,
        connected: Boolean(g.connected),
        connectedAt: g.connectedAt,
        lastSeen: g.lastSeen,
        ip: g.key,
      }));

      res.json({
        success: true,
        totalGateways: gateways.length,
        gateways
      });
    });

    this.app.get('/api/network/connections', async (req: Request, res: Response) => {
      try {
        const now = Date.now();
        const state = await this.canonicalStateBuilder.buildState();
        const currentSequence = state.lastEventSequence;
        const currentHash = state.lastEventHash;

        const operatorEntries = Array.from(this.wsConnections.entries()).filter(([, meta]) => meta.type === 'operator');
        const operators = operatorEntries.map(([client, meta]) => {
          const operatorId = String(meta.operatorId || '').trim();
          const op = operatorId ? (state as any).operators?.get?.(operatorId) : undefined;
          const timeSinceLastSeen = now - (meta.lastSeen || meta.connectedAt);
          return {
            type: 'operator',
            operatorId,
            connected: client.readyState === WebSocket.OPEN,
            connectedAt: meta.connectedAt,
            lastSeen: meta.lastSeen,
            uptimeMs: Math.max(0, now - meta.connectedAt),
            timeSinceLastSeenMs: timeSinceLastSeen,
            healthy: client.readyState === WebSocket.OPEN && timeSinceLastSeen < 60000,
            ip: meta.ip,
            operator: op
              ? {
                  operatorId: String(op.operatorId || ''),
                  operatorUrl: String(op.operatorUrl || ''),
                  btcAddress: String(op.btcAddress || ''),
                  publicKey: String(op.publicKey || ''),
                  status: String(op.status || ''),
                  admittedAt: op.admittedAt,
                }
              : null,
          };
        });

        const gatewayEntries = Array.from(this.wsConnections.entries()).filter(([, meta]) => meta.type === 'gateway');
        const gwByKey = new Map<string, any>();
        for (const [client, meta] of gatewayEntries) {
          const key = String((meta as any).ip || 'unknown').trim() || 'unknown';
          const connected = client.readyState === WebSocket.OPEN;
          const existing = gwByKey.get(key);
          if (!existing) {
            gwByKey.set(key, {
              key,
              connected,
              connectedAt: meta.connectedAt,
              lastSeen: meta.lastSeen,
            });
            continue;
          }

          existing.connected = Boolean(existing.connected || connected);
          existing.connectedAt = Math.min(Number(existing.connectedAt || 0), Number(meta.connectedAt || 0)) || existing.connectedAt;
          existing.lastSeen = Math.max(Number(existing.lastSeen || 0), Number(meta.lastSeen || 0)) || existing.lastSeen;
        }

        const gateways = Array.from(gwByKey.values()).map((g, index) => {
          const connectedAt = Number(g.connectedAt || 0);
          const lastSeen = Number(g.lastSeen || 0);
          const timeSinceLastSeen = now - (lastSeen || connectedAt);
          return {
            type: 'gateway',
            id: `gateway-${index + 1}`,
            connected: Boolean(g.connected),
            connectedAt,
            lastSeen,
            uptimeMs: Math.max(0, now - connectedAt),
            timeSinceLastSeenMs: timeSinceLastSeen,
            healthy: Boolean(g.connected) && timeSinceLastSeen < 60000,
            ip: g.key,
          };
        });

        const allOperators = Array.from((state as any).operators?.values?.() || []) as any[];
        const activeOperators = allOperators.filter((o: any) => o && o.status === 'active');
        const connectedOperatorIds = new Set(operators.map(o => o.operatorId).filter(Boolean));
        const onlineCount = activeOperators.filter((o: any) => connectedOperatorIds.has(o.operatorId)).length;

        res.json({
          success: true,
          mainSeedConnected: true,
          mainSeedUptimeMs: process.uptime() * 1000,
          network: {
            currentSequence,
            currentHash: String(currentHash || '').substring(0, 16) + '...',
            timestamp: now,
          },
          operators: {
            total: activeOperators.length,
            online: onlineCount,
            offline: activeOperators.length - onlineCount,
            connected: operators,
          },
          gateways: {
            total: gateways.length,
            connected: gateways,
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Operator setup endpoint (non-custodial)
    this.app.post('/api/operator/setup', async (req: Request, res: Response) => {
      try {
        const { operatorId, port, bitcoinAddress, publicKey, restored } = req.body;
        
        if (!operatorId || !bitcoinAddress || !publicKey) {
          res.status(400).json({ error: 'Missing required fields' });
          return;
        }

        // Validate Bitcoin address
        if (!bitcoinAddress.match(/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/)) {
          res.status(400).json({ error: 'Invalid Bitcoin address' });
          return;
        }

        // Save operator configuration (ONLY public data - never private keys!)
        const dataDir = process.env.OPERATOR_DATA_DIR || './operator-data';
        if (!fs.existsSync(dataDir)) {
          fs.mkdirSync(dataDir, { recursive: true });
        }

        const operatorConfig = {
          operatorId,
          port: port || 3000,
          bitcoinAddress, // Public address only
          publicKey, // Public key only
          createdAt: Date.now(),
          restored: restored || false,
          walletType: 'non-custodial' // Important: we don't hold keys
        };

        const configFile = path.join(dataDir, 'operator-config.json');
        fs.writeFileSync(configFile, JSON.stringify(operatorConfig, null, 2));

        console.log(`[API] Operator configured: ${operatorId}`);
        console.log(`  Bitcoin Address (Fee Receiver): ${bitcoinAddress}`);
        console.log(`  Port: ${port || 3000}`);
        console.log(`  ⚠️ Non-custodial: Operator controls their own keys`);
        console.log(`  📁 Config saved to: ${configFile}`);

        res.json({ 
          success: true, 
          operatorId,
          message: restored ? 
            'Operator wallet restored successfully!' : 
            'Operator wallet setup complete! Keep your seed phrase safe!'
        });
      } catch (error: any) {
        console.error('[API] Error setting up operator:', error);
        res.status(500).json({ error: error.message });
      }
    });

    // User registration endpoint (non-custodial)
    this.app.post('/api/users/register', async (req: Request, res: Response) => {
      try {
        const { username, email, bitcoinAddress, lightningAddress, publicKey, role, pakeSuiteId, pakeRecordB64, password, walletVault, emailHash } = req.body;
        
        if (!username || !email || !bitcoinAddress || !publicKey) {
          res.status(400).json({ error: 'Missing required fields' });
          return;
        }

        if (password && !this.isValidPassword(String(password))) {
          res.status(400).json({ error: 'Password must be either a 14+ character passphrase (with spaces) or a 12+ character password with upper/lower/digit/special.' });
          return;
        }

        // Validate Bitcoin address
        if (!bitcoinAddress.match(/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/)) {
          res.status(400).json({ error: 'Invalid Bitcoin address' });
          return;
        }

        const normalizedEmail = this.normalizeEmailForHash(email);
        const computedEmailHash = this.computeEmailHash(email);
        const incomingEmailHash = emailHash ? String(emailHash) : '';
        const finalEmailHash = incomingEmailHash || computedEmailHash;
        const accountId = String(publicKey);
        const nonce1 = randomBytes(32).toString('hex');
        const nonce2 = randomBytes(32).toString('hex');

        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_CREATED:${accountId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        const requestedRole = String(role || 'buyer');
        if (requestedRole === 'manufacturer' || requestedRole === 'authenticator' || requestedRole === 'operator') {
          res.status(400).json({
            success: false,
            error: 'manufacturer/authenticator/operator roles require approval. Register as buyer first, then apply for role or redeem a main-node invite code.',
          });
          return;
        }

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_CREATED,
            timestamp: Date.now(),
            nonce: nonce1,
            accountId,
            role: requestedRole || 'buyer',
            username,
            email: normalizedEmail,
            emailHash: finalEmailHash,
            walletAddress: bitcoinAddress,
            walletVault: walletVault ?? undefined,
          } as any,
          signatures
        );

        if (pakeSuiteId && pakeRecordB64) {
          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.ACCOUNT_PAKE_RECORD_SET,
              timestamp: Date.now(),
              nonce: nonce2,
              accountId,
              suiteId: String(pakeSuiteId),
              recordB64: String(pakeRecordB64),
            } as any,
            signatures
          );
        }

        // Set password if provided
        if (password) {
          const incomingKdf = req.body?.passwordKdf;
          const passwordKdf = incomingKdf && incomingKdf.saltB64 && incomingKdf.iterations
            ? incomingKdf
            : {
                saltB64: randomBytes(16).toString('base64'),
                iterations: 210000,
                hash: 'SHA-256',
              };
          const passwordHash = this.computePasswordHash(String(password), passwordKdf);
          const nonce3 = randomBytes(32).toString('hex');
          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.ACCOUNT_PASSWORD_SET,
              timestamp: Date.now(),
              nonce: nonce3,
              accountId,
              passwordHash,
              passwordKdf: passwordKdf ?? undefined,
            } as any,
            signatures
          );
        }

        res.json({ 
          success: true, 
          accountId,
          message: 'Account created successfully. Keep your seed phrase safe!'
        });
      } catch (error: any) {
        console.error('[API] Error registering user:', error);
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/roles/apply', async (req: Request, res: Response) => {
      try {
        const session = this.getSessionFromRequest(req);
        if (!session) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const { requestedRole, companyName, contactEmail, website, notes } = req.body;
        const rr = String(requestedRole || '');
        if (rr !== 'manufacturer' && rr !== 'authenticator') {
          res.status(400).json({ success: false, error: 'Invalid requestedRole (must be manufacturer or authenticator)' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(session.accountId);
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const existing = Array.from(state.roleApplications.values()).find((a: any) => {
          return (
            String(a.accountId) === String(session.accountId) &&
            String(a.requestedRole) === rr &&
            !a.reviewed &&
            !a.finalized
          );
        });
        if (existing) {
          res.json({ success: true, applicationId: String((existing as any).applicationId), alreadySubmitted: true });
          return;
        }

        const applicationId = `roleapp_${Date.now()}_${randomBytes(8).toString('hex')}`;
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_ROLE_APPLICATION_SUBMITTED:${applicationId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_APPLICATION_SUBMITTED,
            timestamp: Date.now(),
            nonce,
            applicationId,
            accountId: String(account.accountId),
            requestedRole: rr,
            companyName: companyName ? String(companyName) : undefined,
            contactEmail: contactEmail ? String(contactEmail) : undefined,
            website: website ? String(website) : undefined,
            notes: notes ? String(notes) : undefined,
          } as any,
          signatures
        );

        res.json({ success: true, applicationId });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/roles/applications', async (req: Request, res: Response) => {
      try {
        const op = await this.requireMainNodeOperator(req, res);
        if (!op) return;

        const status = String(req.query.status || 'open');
        const state = await this.canonicalStateBuilder.buildState();
        const ROLE_REVIEW_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

        const items = Array.from(state.roleApplications.values()).map((a: any) => ({
          applicationId: a.applicationId,
          accountId: a.accountId,
          requestedRole: a.requestedRole,
          companyName: a.companyName,
          contactEmail: a.contactEmail,
          website: a.website,
          notes: a.notes,
          submittedAt: a.submittedAt,
          reviewed: a.reviewed,
          finalized: a.finalized,
          voteCount: {
            approve: Array.from(a.votes.values()).filter((v: any) => v.vote === 'approve').length,
            reject: Array.from(a.votes.values()).filter((v: any) => v.vote === 'reject').length,
          },
          eligibleForVotingAt: a.submittedAt + ROLE_REVIEW_WINDOW_MS,
        }));

        const filtered = items.filter((a: any) => {
          if (status === 'open') return !a.finalized && !a.reviewed;
          if (status === 'reviewed') return !!a.reviewed && !a.finalized;
          if (status === 'finalized') return !!a.finalized;
          return true;
        });

        res.json({ success: true, applications: filtered });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/roles/applications/:applicationId/review', async (req: Request, res: Response) => {
      try {
        const op = await this.requireMainNodeOperator(req, res);
        if (!op) return;

        const { applicationId } = req.params;
        const { decision, reason } = req.body;
        const d = String(decision || '');
        if (d !== 'approve' && d !== 'reject') {
          res.status(400).json({ success: false, error: 'decision must be approve or reject' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const app = state.roleApplications.get(String(applicationId));
        if (!app) {
          res.status(404).json({ success: false, error: 'Application not found' });
          return;
        }
        if (app.finalized) {
          res.status(400).json({ success: false, error: 'Application already finalized' });
          return;
        }
        if (app.reviewed) {
          res.status(400).json({ success: false, error: 'Application already reviewed' });
          return;
        }

        const nonce1 = randomBytes(32).toString('hex');
        const nonce2 = randomBytes(32).toString('hex');
        const now = Date.now();
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_ROLE_APPLICATION_REVIEWED:${applicationId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_APPLICATION_REVIEWED,
            timestamp: now,
            nonce: nonce1,
            applicationId: String(applicationId),
            reviewerOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            decision: d,
            reason: reason ? String(reason) : undefined,
          } as any,
          signatures
        );

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_APPLICATION_FINALIZED,
            timestamp: now,
            nonce: nonce2,
            applicationId: String(applicationId),
            finalizedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            decision: d,
            reason: reason ? String(reason) : undefined,
            activeOperatorCount: (await this.canonicalStateBuilder.getActiveOperators()).length,
            approveVotes: 0,
            rejectVotes: 0,
          } as any,
          signatures
        );

        if (d === 'approve') {
          const nonce3 = randomBytes(32).toString('hex');
          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.ACCOUNT_ROLE_SET,
              timestamp: now,
              nonce: nonce3,
              accountId: String(app.accountId),
              role: String(app.requestedRole),
              reason: reason ? String(reason) : undefined,
              applicationId: String(applicationId),
              decidedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            } as any,
            signatures
          );
        }

        res.json({ success: true, applicationId: String(applicationId), decision: d });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/roles/applications/:applicationId/vote', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const { applicationId } = req.params;
        const { vote, reason } = req.body;
        const v = String(vote || '');
        if (v !== 'approve' && v !== 'reject') {
          res.status(400).json({ success: false, error: 'vote must be approve or reject' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const app = state.roleApplications.get(String(applicationId));
        if (!app) {
          res.status(404).json({ success: false, error: 'Application not found' });
          return;
        }
        if (app.finalized || app.reviewed) {
          res.status(400).json({ success: false, error: 'Application is closed' });
          return;
        }

        const ROLE_REVIEW_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
        if (Date.now() < app.submittedAt + ROLE_REVIEW_WINDOW_MS) {
          res.status(400).json({ success: false, error: 'Voting not yet enabled (main node review window still open)' });
          return;
        }

        if (app.votes && app.votes.has(String(process.env.OPERATOR_ID || 'operator-1'))) {
          res.status(400).json({ success: false, error: 'Already voted' });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_ROLE_APPLICATION_VOTED:${applicationId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_APPLICATION_VOTED,
            timestamp: Date.now(),
            nonce,
            applicationId: String(applicationId),
            voterOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            vote: v,
            reason: reason ? String(reason) : undefined,
          } as any,
          signatures
        );

        res.json({ success: true, applicationId: String(applicationId), vote: v });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/roles/applications/:applicationId/finalize', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const { applicationId } = req.params;
        const state = await this.canonicalStateBuilder.buildState();
        const app = state.roleApplications.get(String(applicationId));
        if (!app) {
          res.status(404).json({ success: false, error: 'Application not found' });
          return;
        }
        if (app.finalized || app.reviewed) {
          res.status(400).json({ success: false, error: 'Application is closed' });
          return;
        }

        const ROLE_REVIEW_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
        if (Date.now() < app.submittedAt + ROLE_REVIEW_WINDOW_MS) {
          res.status(400).json({ success: false, error: 'Finalize not yet enabled (main node review window still open)' });
          return;
        }

        const votes = Array.from((app as any).votes?.values?.() || []);
        const approveVotes = votes.filter((v: any) => v.vote === 'approve').length;
        const rejectVotes = votes.filter((v: any) => v.vote === 'reject').length;
        const decision = approveVotes > rejectVotes ? 'approve' : 'reject';
        const activeOperatorCount = (await this.canonicalStateBuilder.getActiveOperators()).length;

        const nonce1 = randomBytes(32).toString('hex');
        const now = Date.now();
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_ROLE_APPLICATION_FINALIZED:${applicationId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_APPLICATION_FINALIZED,
            timestamp: now,
            nonce: nonce1,
            applicationId: String(applicationId),
            finalizedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            decision,
            activeOperatorCount,
            approveVotes,
            rejectVotes,
          } as any,
          signatures
        );

        if (decision === 'approve') {
          const nonce2 = randomBytes(32).toString('hex');
          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.ACCOUNT_ROLE_SET,
              timestamp: now,
              nonce: nonce2,
              accountId: String(app.accountId),
              role: String(app.requestedRole),
              applicationId: String(applicationId),
              decidedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            } as any,
            signatures
          );
        }

        res.json({
          success: true,
          applicationId: String(applicationId),
          decision,
          approveVotes,
          rejectVotes,
          activeOperatorCount,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/roles/invites/create', async (req: Request, res: Response) => {
      try {
        const op = await this.requireMainNodeOperator(req, res);
        if (!op) return;

        const { role, expiresInMs } = req.body;
        const rr = String(role || '');
        if (rr !== 'manufacturer' && rr !== 'authenticator') {
          res.status(400).json({ success: false, error: 'role must be manufacturer or authenticator' });
          return;
        }

        const codeHex = randomBytes(32).toString('hex');
        const codeHashHex = createHash('sha256').update(`AUTHO_ROLE_INVITE_V1\u0000${codeHex}`).digest('hex');
        const inviteId = `invite_${Date.now()}_${randomBytes(8).toString('hex')}`;
        const exp = typeof expiresInMs === 'number' && expiresInMs > 0 ? expiresInMs : 14 * 24 * 60 * 60 * 1000;
        const expiresAt = Date.now() + exp;
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_ROLE_INVITE_CREATED:${inviteId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_INVITE_CREATED,
            timestamp: Date.now(),
            nonce,
            inviteId,
            role: rr,
            codeHashHex,
            expiresAt,
            createdByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
          } as any,
          signatures
        );

        res.json({ success: true, inviteId, role: rr, codeHex, expiresAt });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/roles/invites/redeem', async (req: Request, res: Response) => {
      try {
        const session = this.getSessionFromRequest(req);
        if (!session) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const { codeHex, expectedRole } = req.body;
        if (!codeHex) {
          res.status(400).json({ success: false, error: 'Missing required field: codeHex' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(session.accountId);
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const codeHashHex = createHash('sha256').update(`AUTHO_ROLE_INVITE_V1\u0000${String(codeHex)}`).digest('hex');
        const invite = Array.from(state.roleInvites.values()).find((i: any) => i.codeHashHex === codeHashHex);
        if (!invite) {
          res.status(404).json({ success: false, error: 'Invite not found' });
          return;
        }

        if (expectedRole) {
          const er = String(expectedRole);
          if (er !== 'manufacturer' && er !== 'authenticator') {
            res.status(400).json({ success: false, error: 'Invalid expectedRole' });
            return;
          }
          if (String(invite.role) !== er) {
            res.status(400).json({ success: false, error: `Invite code is for role ${String(invite.role)}, not ${er}` });
            return;
          }
        }

        if (invite.redeemedAt) {
          res.status(400).json({ success: false, error: 'Invite already redeemed' });
          return;
        }
        if (Date.now() > invite.expiresAt) {
          res.status(400).json({ success: false, error: 'Invite expired' });
          return;
        }

        const now = Date.now();
        const nonce1 = randomBytes(32).toString('hex');
        const nonce2 = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_ROLE_INVITE_REDEEMED:${invite.inviteId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_INVITE_REDEEMED,
            timestamp: now,
            nonce: nonce1,
            inviteId: String(invite.inviteId),
            accountId: String(account.accountId),
          } as any,
          signatures
        );

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_ROLE_SET,
            timestamp: now,
            nonce: nonce2,
            accountId: String(account.accountId),
            role: String(invite.role),
            inviteId: String(invite.inviteId),
            decidedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
          } as any,
          signatures
        );

        res.json({ success: true, accountId: String(account.accountId), role: String(invite.role) });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Verifier governance: main node revoke/reactivate (immediate)
    this.app.post('/api/verifiers/:accountId/revoke', async (req: Request, res: Response) => {
      try {
        const op = await this.requireMainNodeOperator(req, res);
        if (!op) return;

        const accountId = String(req.params.accountId || '').trim();
        const reason = req.body?.reason ? String(req.body.reason) : undefined;
        if (!accountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(accountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }
        const role = String(target.role || '');
        if (role !== 'manufacturer' && role !== 'authenticator') {
          res.status(400).json({ success: false, error: 'Target account is not a manufacturer/authenticator' });
          return;
        }
        if (String(target.verifierStatus || 'active') === 'revoked') {
          res.status(400).json({ success: false, error: 'Account is already revoked' });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ACCOUNT_VERIFIER_REVOKED:${accountId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_VERIFIER_REVOKED,
            timestamp: now,
            nonce,
            accountId,
            revokedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            reason,
          } as any,
          signatures
        );

        res.json({ success: true, accountId, status: 'revoked' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/verifiers/:accountId/reactivate', async (req: Request, res: Response) => {
      try {
        const op = await this.requireMainNodeOperator(req, res);
        if (!op) return;

        const accountId = String(req.params.accountId || '').trim();
        const reason = req.body?.reason ? String(req.body.reason) : undefined;
        if (!accountId) {
          res.status(400).json({ success: false, error: 'Missing accountId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(accountId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }
        const role = String(target.role || '');
        if (role !== 'manufacturer' && role !== 'authenticator') {
          res.status(400).json({ success: false, error: 'Target account is not a manufacturer/authenticator' });
          return;
        }
        if (String(target.verifierStatus || 'active') !== 'revoked') {
          res.status(400).json({ success: false, error: 'Account is not revoked' });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ACCOUNT_VERIFIER_REACTIVATED:${accountId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_VERIFIER_REACTIVATED,
            timestamp: now,
            nonce,
            accountId,
            reactivatedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            reason,
          } as any,
          signatures
        );

        res.json({ success: true, accountId, status: 'active' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Verifier governance: operator 2/3 quorum action flow (create/vote/finalize)
    this.app.get('/api/verifiers/actions', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const status = String(req.query.status || 'open').trim();
        const state = await this.canonicalStateBuilder.buildState();
        const activeOperatorCount = (await this.canonicalStateBuilder.getActiveOperators()).length;
        const quorumThreshold = Math.ceil((2 / 3) * Math.max(1, activeOperatorCount));
        const actions = Array.from((state as any).verifierActions?.values?.() || []).map((a: any) => {
          const votesArr = Array.from(a?.votes?.values?.() || []);
          const target: any = state.accounts.get(String(a?.targetAccountId || '').trim());
          const targetName = target ? (target.displayName || target.companyName || target.username || '') : '';
          return {
            actionId: String(a.actionId),
            targetAccountId: String(a.targetAccountId),
            target: target
              ? {
                  role: String(target.role || ''),
                  name: String(targetName || ''),
                  website: target.website ? String(target.website) : undefined,
                  verifierStatus: String(target.verifierStatus || 'active'),
                }
              : undefined,
            action: String(a.action),
            reason: a.reason ? String(a.reason) : undefined,
            requestedByOperatorId: a.requestedByOperatorId ? String(a.requestedByOperatorId) : undefined,
            createdAt: Number(a.createdAt || 0),
            activeOperatorCount,
            quorumThreshold,
            voteCount: {
              approve: votesArr.filter((v: any) => v && v.vote === 'approve').length,
              reject: votesArr.filter((v: any) => v && v.vote === 'reject').length,
            },
            votes: votesArr.map((v: any) => ({
              voterOperatorId: String(v.voterOperatorId),
              vote: String(v.vote),
              reason: v.reason ? String(v.reason) : undefined,
              votedAt: Number(v.votedAt || 0),
            })),
            finalized: a.finalized
              ? {
                  finalizedByOperatorId: String(a.finalized.finalizedByOperatorId),
                  decision: String(a.finalized.decision),
                  reason: a.finalized.reason ? String(a.finalized.reason) : undefined,
                  finalizedAt: Number(a.finalized.finalizedAt || 0),
                  activeOperatorCount: Number(a.finalized.activeOperatorCount || 0),
                  approveVotes: Number(a.finalized.approveVotes || 0),
                  rejectVotes: Number(a.finalized.rejectVotes || 0),
                  quorumThreshold: Number(a.finalized.quorumThreshold || 0),
                }
              : undefined,
          };
        });

        const filtered = actions.filter((a: any) => {
          if (status === 'all') return true;
          if (status === 'finalized') return !!a.finalized;
          return !a.finalized;
        });

        filtered.sort((a: any, b: any) => Number(b.createdAt || 0) - Number(a.createdAt || 0));

        res.json({ success: true, count: filtered.length, actions: filtered });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/verifiers/actions', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const { targetAccountId, action, reason } = req.body || {};
        const targetId = String(targetAccountId || '').trim();
        const a = String(action || '').trim();
        if (!targetId || (a !== 'revoke' && a !== 'reactivate')) {
          res.status(400).json({ success: false, error: 'Invalid targetAccountId or action (revoke/reactivate)' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(targetId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Target account not found' });
          return;
        }
        const role = String(target.role || '');
        if (role !== 'manufacturer' && role !== 'authenticator') {
          res.status(400).json({ success: false, error: 'Target account is not a manufacturer/authenticator' });
          return;
        }
        const currentStatus = String(target.verifierStatus || 'active');
        if (a === 'revoke' && currentStatus === 'revoked') {
          res.status(400).json({ success: false, error: 'Target is already revoked' });
          return;
        }
        if (a === 'reactivate' && currentStatus !== 'revoked') {
          res.status(400).json({ success: false, error: 'Target is not revoked' });
          return;
        }

        const actionId = `veract_${Date.now()}_${randomBytes(8).toString('hex')}`;
        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ACCOUNT_VERIFIER_ACTION_CREATED:${actionId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_VERIFIER_ACTION_CREATED,
            timestamp: now,
            nonce,
            actionId,
            targetAccountId: targetId,
            action: a,
            requestedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            reason: reason ? String(reason) : undefined,
          } as any,
          signatures
        );

        res.json({ success: true, actionId, targetAccountId: targetId, action: a });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/verifiers/actions/:actionId/vote', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const actionId = String(req.params.actionId || '').trim();
        const v = String(req.body?.vote || '').trim();
        const reason = req.body?.reason ? String(req.body.reason) : undefined;
        if (!actionId || (v !== 'approve' && v !== 'reject')) {
          res.status(400).json({ success: false, error: 'Invalid actionId or vote (approve/reject)' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const action: any = state.verifierActions?.get?.(actionId);
        if (!action) {
          res.status(404).json({ success: false, error: 'Action not found' });
          return;
        }
        if (action.finalized) {
          res.status(400).json({ success: false, error: 'Action already finalized' });
          return;
        }
        const voterId = String(process.env.OPERATOR_ID || 'operator-1');
        if (action.votes && action.votes.has(voterId)) {
          res.status(400).json({ success: false, error: 'Already voted' });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: voterId,
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ACCOUNT_VERIFIER_ACTION_VOTED:${actionId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_VERIFIER_ACTION_VOTED,
            timestamp: now,
            nonce,
            actionId,
            voterOperatorId: voterId,
            vote: v,
            reason,
          } as any,
          signatures
        );

        res.json({ success: true, actionId, vote: v });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/verifiers/actions/:actionId/finalize', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const actionId = String(req.params.actionId || '').trim();
        if (!actionId) {
          res.status(400).json({ success: false, error: 'Missing actionId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const action: any = state.verifierActions?.get?.(actionId);
        if (!action) {
          res.status(404).json({ success: false, error: 'Action not found' });
          return;
        }
        if (action.finalized) {
          res.status(400).json({ success: false, error: 'Action already finalized' });
          return;
        }

        const votes = Array.from(action.votes?.values?.() || []);
        const approveVotes = votes.filter((vv: any) => vv.vote === 'approve').length;
        const rejectVotes = votes.filter((vv: any) => vv.vote === 'reject').length;
        const activeOperatorCount = (await this.canonicalStateBuilder.getActiveOperators()).length;
        const quorumThreshold = Math.ceil((2 / 3) * Math.max(1, activeOperatorCount));
        if (approveVotes < quorumThreshold && rejectVotes < quorumThreshold) {
          res.status(400).json({
            success: false,
            error: `Not enough votes to finalize. Need ${quorumThreshold} approve or ${quorumThreshold} reject votes.`,
            approveVotes,
            rejectVotes,
            activeOperatorCount,
            quorumThreshold,
          });
          return;
        }

        const decision: 'approve' | 'reject' = approveVotes >= quorumThreshold ? 'approve' : 'reject';

        const now = Date.now();
        const nonce1 = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ACCOUNT_VERIFIER_ACTION_FINALIZED:${actionId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_VERIFIER_ACTION_FINALIZED,
            timestamp: now,
            nonce: nonce1,
            actionId,
            finalizedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            decision,
            reason: action.reason,
            activeOperatorCount,
            approveVotes,
            rejectVotes,
            quorumThreshold,
          } as any,
          signatures
        );

        if (decision === 'approve') {
          const targetId = String(action.targetAccountId || '').trim();
          const nonce2 = randomBytes(32).toString('hex');
          const type = String(action.action) === 'revoke' ? EventType.ACCOUNT_VERIFIER_REVOKED : EventType.ACCOUNT_VERIFIER_REACTIVATED;
          const payload: any = {
            type,
            timestamp: now,
            nonce: nonce2,
            accountId: targetId,
            actionId,
            reason: action.reason,
          };
          if (type === EventType.ACCOUNT_VERIFIER_REVOKED) {
            payload.revokedByOperatorId = String(process.env.OPERATOR_ID || 'operator-1');
          } else {
            payload.reactivatedByOperatorId = String(process.env.OPERATOR_ID || 'operator-1');
          }

          await this.canonicalEventStore.appendEvent(payload, signatures);
        }

        res.json({
          success: true,
          actionId,
          decision,
          approveVotes,
          rejectVotes,
          activeOperatorCount,
          quorumThreshold,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Retailer moderation: operator 2/3 quorum action flow (block/unblock)
    this.app.get('/api/retailers/actions', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const status = String(req.query.status || 'open').trim();
        const state = await this.canonicalStateBuilder.buildState();
        const activeOperatorCount = (await this.canonicalStateBuilder.getActiveOperators()).length;
        const quorumThreshold = Math.ceil((2 / 3) * Math.max(1, activeOperatorCount));
        const actions = Array.from((state as any).retailerActions?.values?.() || []).map((a: any) => {
          const votesArr = Array.from(a?.votes?.values?.() || []);
          const target: any = state.accounts.get(String(a?.targetAccountId || '').trim());
          const targetName = target ? (target.displayName || target.companyName || target.username || '') : '';
          return {
            actionId: String(a.actionId),
            targetAccountId: String(a.targetAccountId),
            target: target
              ? {
                  role: String(target.role || ''),
                  name: String(targetName || ''),
                  website: target.website ? String(target.website) : undefined,
                  retailerStatus: String(target.retailerStatus || 'unverified'),
                }
              : undefined,
            action: String(a.action),
            reason: a.reason ? String(a.reason) : undefined,
            requestedByOperatorId: a.requestedByOperatorId ? String(a.requestedByOperatorId) : undefined,
            createdAt: Number(a.createdAt || 0),
            activeOperatorCount,
            quorumThreshold,
            voteCount: {
              approve: votesArr.filter((v: any) => v && v.vote === 'approve').length,
              reject: votesArr.filter((v: any) => v && v.vote === 'reject').length,
            },
            votes: votesArr.map((v: any) => ({
              voterOperatorId: String(v.voterOperatorId),
              vote: String(v.vote),
              reason: v.reason ? String(v.reason) : undefined,
              votedAt: Number(v.votedAt || 0),
            })),
            finalized: a.finalized
              ? {
                  finalizedByOperatorId: String(a.finalized.finalizedByOperatorId),
                  decision: String(a.finalized.decision),
                  reason: a.finalized.reason ? String(a.finalized.reason) : undefined,
                  finalizedAt: Number(a.finalized.finalizedAt || 0),
                  activeOperatorCount: Number(a.finalized.activeOperatorCount || 0),
                  approveVotes: Number(a.finalized.approveVotes || 0),
                  rejectVotes: Number(a.finalized.rejectVotes || 0),
                  quorumThreshold: Number(a.finalized.quorumThreshold || 0),
                }
              : undefined,
          };
        });

        const filtered = actions.filter((a: any) => {
          if (status === 'all') return true;
          if (status === 'finalized') return !!a.finalized;
          return !a.finalized;
        });

        filtered.sort((a: any, b: any) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
        res.json({ success: true, count: filtered.length, actions: filtered });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/actions', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const { targetAccountId, action, reason } = req.body || {};
        const targetId = String(targetAccountId || '').trim();
        const a = String(action || '').trim();
        if (!targetId || (a !== 'block' && a !== 'unblock')) {
          res.status(400).json({ success: false, error: 'Invalid targetAccountId or action (block/unblock)' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const target: any = state.accounts.get(targetId);
        if (!target) {
          res.status(404).json({ success: false, error: 'Target account not found' });
          return;
        }
        const role = String(target.role || '');
        if (role !== 'retailer') {
          res.status(400).json({ success: false, error: 'Target account is not a retailer' });
          return;
        }
        const currentStatus = String(target.retailerStatus || 'unverified');
        if (a === 'block' && currentStatus === 'blocked') {
          res.status(400).json({ success: false, error: 'Target is already blocked' });
          return;
        }
        if (a === 'unblock' && currentStatus !== 'blocked') {
          res.status(400).json({ success: false, error: 'Target is not blocked' });
          return;
        }

        const actionId = `retact_${Date.now()}_${randomBytes(8).toString('hex')}`;
        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ACCOUNT_RETAILER_ACTION_CREATED:${actionId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_ACTION_CREATED,
            timestamp: now,
            nonce,
            actionId,
            targetAccountId: targetId,
            action: a,
            requestedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            reason: reason ? String(reason) : undefined,
          } as any,
          signatures
        );

        res.json({ success: true, actionId, targetAccountId: targetId, action: a });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/actions/:actionId/vote', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const actionId = String(req.params.actionId || '').trim();
        const v = String(req.body?.vote || '').trim();
        const reason = req.body?.reason ? String(req.body.reason) : undefined;
        if (!actionId || (v !== 'approve' && v !== 'reject')) {
          res.status(400).json({ success: false, error: 'Invalid actionId or vote (approve/reject)' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const action: any = (state as any).retailerActions?.get?.(actionId);
        if (!action) {
          res.status(404).json({ success: false, error: 'Action not found' });
          return;
        }
        if (action.finalized) {
          res.status(400).json({ success: false, error: 'Action already finalized' });
          return;
        }
        const voterId = String(process.env.OPERATOR_ID || 'operator-1');
        if (action.votes && action.votes.has(voterId)) {
          const existing = action.votes.get(voterId);
          res.json({ success: true, actionId, vote: String(existing?.vote || v), alreadyVoted: true });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: voterId,
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ACCOUNT_RETAILER_ACTION_VOTED:${actionId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_ACTION_VOTED,
            timestamp: now,
            nonce,
            actionId,
            voterOperatorId: voterId,
            vote: v,
            reason,
          } as any,
          signatures
        );

        res.json({ success: true, actionId, vote: v });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/retailers/actions/:actionId/finalize', async (req: Request, res: Response) => {
      try {
        const op = await this.requireOperatorAccount(req, res);
        if (!op) return;

        const actionId = String(req.params.actionId || '').trim();
        if (!actionId) {
          res.status(400).json({ success: false, error: 'Missing actionId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const action: any = (state as any).retailerActions?.get?.(actionId);
        if (!action) {
          res.status(404).json({ success: false, error: 'Action not found' });
          return;
        }
        if (action.finalized) {
          res.json({
            success: true,
            actionId,
            decision: String(action.finalized?.decision || ''),
            approveVotes: Number(action.finalized?.approveVotes || 0),
            rejectVotes: Number(action.finalized?.rejectVotes || 0),
            activeOperatorCount: Number(action.finalized?.activeOperatorCount || 0),
            quorumThreshold: Number(action.finalized?.quorumThreshold || 0),
            alreadyFinalized: true,
          });
          return;
        }

        const votes = Array.from(action.votes?.values?.() || []);
        const approveVotes = votes.filter((vv: any) => vv.vote === 'approve').length;
        const rejectVotes = votes.filter((vv: any) => vv.vote === 'reject').length;
        const activeOperatorCount = (await this.canonicalStateBuilder.getActiveOperators()).length;
        const quorumThreshold = Math.ceil((2 / 3) * Math.max(1, activeOperatorCount));
        if (approveVotes < quorumThreshold && rejectVotes < quorumThreshold) {
          res.status(400).json({
            success: false,
            error: `Not enough votes to finalize. Need ${quorumThreshold} approve or ${quorumThreshold} reject votes.`,
            approveVotes,
            rejectVotes,
            activeOperatorCount,
            quorumThreshold,
          });
          return;
        }

        const decision: 'approve' | 'reject' = approveVotes >= quorumThreshold ? 'approve' : 'reject';
        const now = Date.now();
        const nonce1 = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256').update(`ACCOUNT_RETAILER_ACTION_FINALIZED:${actionId}:${now}`).digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RETAILER_ACTION_FINALIZED,
            timestamp: now,
            nonce: nonce1,
            actionId,
            finalizedByOperatorId: String(process.env.OPERATOR_ID || 'operator-1'),
            decision,
            reason: action.reason,
            activeOperatorCount,
            approveVotes,
            rejectVotes,
            quorumThreshold,
          } as any,
          signatures
        );

        if (decision === 'approve') {
          const targetId = String(action.targetAccountId || '').trim();
          const nonce2 = randomBytes(32).toString('hex');
          const type = String(action.action) === 'block' ? EventType.ACCOUNT_RETAILER_BLOCKED : EventType.ACCOUNT_RETAILER_UNBLOCKED;
          const payload: any = {
            type,
            timestamp: now,
            nonce: nonce2,
            accountId: targetId,
            actionId,
            reason: action.reason,
          };
          if (type === EventType.ACCOUNT_RETAILER_BLOCKED) {
            payload.blockedByOperatorId = String(process.env.OPERATOR_ID || 'operator-1');
          } else {
            payload.unblockedByOperatorId = String(process.env.OPERATOR_ID || 'operator-1');
          }
          await this.canonicalEventStore.appendEvent(payload, signatures);
        }

        res.json({
          success: true,
          actionId,
          decision,
          approveVotes,
          rejectVotes,
          activeOperatorCount,
          quorumThreshold,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/accounts/by-email', async (req: Request, res: Response) => {
      try {
        const email = String(req.query.email || '').trim().toLowerCase();
        if (!email) {
          res.status(400).json({ success: false, error: 'Missing required query param: email' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        for (const account of state.accounts.values()) {
          if (account.email && account.email.trim().toLowerCase() === email) {
            res.json({ success: true, accountId: account.accountId });
            return;
          }
        }

        res.status(404).json({ success: false, error: 'Account not found' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/accounts/:accountId/public', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const state = await this.canonicalStateBuilder.buildState();
        const account: any = state.accounts.get(String(accountId));
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        res.json({
          success: true,
          account: {
            accountId: String(account.accountId || ''),
            role: String(account.role || ''),
            username: account.username ? String(account.username) : undefined,
            companyName: account.companyName ? String(account.companyName) : undefined,
            displayName: account.displayName ? String(account.displayName) : undefined,
            retailerStatus: account.retailerStatus ? String(account.retailerStatus) : undefined,
            retailerVerifiedAt: account.retailerVerifiedAt ? Number(account.retailerVerifiedAt) : undefined,
          },
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/accounts/:accountId', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(accountId);
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        res.json({ success: true, account });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/accounts/:accountId/pake', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const { suiteId, recordB64 } = req.body;

        if (!suiteId || !recordB64) {
          res.status(400).json({ success: false, error: 'Missing required fields: suiteId, recordB64' });
          return;
        }

        const authz = String(req.headers.authorization || '');
        const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';
        if (!token) {
          res.status(401).json({ success: false, error: 'Missing Authorization Bearer token' });
          return;
        }

        const session = this.userSessions.get(token);
        if (!session || session.accountId !== String(accountId) || Date.now() > session.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(String(accountId));
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_PAKE_RECORD_SET:${accountId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_PAKE_RECORD_SET,
            timestamp: Date.now(),
            nonce,
            accountId: String(accountId),
            suiteId: String(suiteId),
            recordB64: String(recordB64),
          } as any,
          signatures
        );

        res.json({ success: true, accountId: String(accountId), message: 'PAKE record updated' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Simple email+password login for manufacturers/authenticators
    this.app.post('/api/auth/login', async (req: Request, res: Response) => {
      try {
        const { email, password, totpCode } = req.body;
        if (!email || !password) {
          res.status(400).json({ success: false, error: 'Missing email or password' });
          return;
        }

        const normalizedEmail = this.normalizeEmailForHash(email);
        const emailHash = this.computeEmailHash(email);
        const state = await this.canonicalStateBuilder.buildState();
        
        // Find account by emailHash (preferred), falling back to plaintext email for backwards compatibility
        let account: any = null;
        for (const acc of state.accounts.values()) {
          if (String(acc.emailHash || '') === emailHash) {
            account = acc;
            break;
          }
          if (!acc.emailHash && String(acc.email).toLowerCase() === normalizedEmail) {
            account = acc;
            break;
          }
        }

        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        // Verify password using stored hash
        if (!account.passwordHash) {
          res.status(400).json({ success: false, error: 'Password not set for this account. Please use wallet signature login or set a password first.' });
          return;
        }

        {
          const storedHashHex = String(account.passwordHash || '');
          const storedKdf = account.passwordKdf;
          const computedHashHex = storedKdf
            ? this.computePasswordHash(String(password), storedKdf)
            : createHash('sha256').update(String(password)).digest('hex');
          const ok = (() => {
            try {
              const a = Buffer.from(computedHashHex, 'hex');
              const b = Buffer.from(storedHashHex, 'hex');
              if (a.length !== b.length) return false;
              return timingSafeEqual(a, b);
            } catch {
              return false;
            }
          })();
          if (!ok) {
            res.status(401).json({ success: false, error: 'Invalid password' });
            return;
          }
        }

        // Check 2FA if enabled
        if (account.totp?.enabled) {
          if (!totpCode) {
            res.status(400).json({ success: false, error: '2FA code required', requires2FA: true });
            return;
          }

          const secretBase32 = await openTotpSecretBase32(
            account.totp.secretEncB64 || account.totp.totpSecretEncB64 || '',
            account.totp.encScheme || 'AUTHO_TOTP_ENC_V1_BASE32_B64'
          );

          const totpOk = speakeasy.totp.verify({
            secret: secretBase32,
            encoding: 'base32',
            token: String(totpCode),
            window: 2,
          });

          if (!totpOk) {
            res.status(401).json({ success: false, error: 'Invalid 2FA code' });
            return;
          }
        }

        const sessionId = `session_${Date.now()}_${randomBytes(16).toString('hex')}`;
        const createdAt = Date.now();
        const expiresAt = createdAt + 24 * 60 * 60 * 1000;
        this.userSessions.set(sessionId, { sessionId, accountId: account.accountId, createdAt, expiresAt });

        res.json({
          success: true,
          sessionId,
          accountId: account.accountId,
          expiresAt,
          emailHash: String(account.emailHash || emailHash),
          walletVault: account.walletVault,
          passwordKdf: account.passwordKdf,
          walletAddress: account.walletAddress,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // User authentication (non-custodial): wallet signature challenge + optional per-account TOTP
    this.app.post('/api/auth/challenge', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.body;
        if (!accountId) {
          res.status(400).json({ success: false, error: 'Missing required field: accountId' });
          return;
        }

        const requestedAccountId = String(accountId);
        const state = await this.canonicalStateBuilder.buildState();

        let account = state.accounts.get(requestedAccountId);
        if (!account) {
          const operator = (Array.from((state as any)?.operators?.values?.() || []) as any[])
            .find((o: any) => o && String(o.status || '') === 'active' && String(o.publicKey || '') === requestedAccountId);

          if (!operator) {
            res.status(404).json({ success: false, error: 'Account not found' });
            return;
          }

          const nonce = randomBytes(32).toString('hex');
          const signatures: QuorumSignature[] = [
            {
              operatorId: process.env.OPERATOR_ID || 'operator-1',
              publicKey: this.node.getOperatorInfo().publicKey,
              signature: createHash('sha256')
                .update(`ACCOUNT_CREATED:${requestedAccountId}:${Date.now()}`)
                .digest('hex'),
            },
          ];

          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.ACCOUNT_CREATED,
              timestamp: Date.now(),
              nonce,
              accountId: requestedAccountId,
              role: 'operator',
              username: `operator-${String(operator.operatorId || '').trim() || 'unknown'}`,
              email: `operator@${String(operator.operatorId || '').trim() || 'unknown'}.local`,
              walletAddress: String(operator.btcAddress || '').trim() || undefined,
            } as any,
            signatures
          );

          const state2 = await this.canonicalStateBuilder.buildState();
          account = state2.accounts.get(requestedAccountId);
          if (!account) {
            res.status(500).json({ success: false, error: 'Failed to create operator account record' });
            return;
          }
        }

        const challengeId = `challenge_${Date.now()}_${randomBytes(8).toString('hex')}`;
        const nonce = randomBytes(32).toString('hex');
        const createdAt = Date.now();
        const expiresAt = createdAt + 5 * 60 * 1000;

        this.userAuthChallenges.set(challengeId, {
          challengeId,
          accountId: String(accountId),
          nonce,
          createdAt,
          expiresAt,
          used: false,
        });

        res.json({
          success: true,
          challengeId,
          accountId: String(accountId),
          nonce,
          expiresAt,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/auth/me', async (req: Request, res: Response) => {
      try {
        const authz = String(req.headers.authorization || '');
        const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';
        if (!token) {
          res.status(401).json({ success: false, error: 'Missing Authorization Bearer token' });
          return;
        }

        const session = this.userSessions.get(token);
        if (!session || Date.now() > session.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(session.accountId);
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const isOperator = String(account.role || '') === 'operator' || this.isAccountActiveOperator(state, String(account.accountId || ''));
        res.json({ success: true, account, isOperator });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/auth/verify', async (req: Request, res: Response) => {
      try {
        const { challengeId, accountId, signature, totpCode } = req.body;
        if (!challengeId || !accountId || !signature) {
          res.status(400).json({ success: false, error: 'Missing required fields: challengeId, accountId, signature' });
          return;
        }

        const challenge = this.userAuthChallenges.get(String(challengeId));
        if (!challenge) {
          res.status(400).json({ success: false, error: 'Challenge not found or expired' });
          return;
        }

        if (challenge.used) {
          res.status(400).json({ success: false, error: 'Challenge already used' });
          return;
        }

        if (Date.now() > challenge.expiresAt) {
          this.userAuthChallenges.delete(String(challengeId));
          res.status(400).json({ success: false, error: 'Challenge expired' });
          return;
        }

        if (challenge.accountId !== String(accountId)) {
          res.status(400).json({ success: false, error: 'Account mismatch' });
          return;
        }

        const requestedAccountId = String(accountId);
        let state = await this.canonicalStateBuilder.buildState();
        let account = state.accounts.get(requestedAccountId);
        if (!account) {
          const operator = (Array.from((state as any)?.operators?.values?.() || []) as any[])
            .find((o: any) => o && String(o.status || '') === 'active' && String(o.publicKey || '') === requestedAccountId);

          if (!operator) {
            res.status(404).json({ success: false, error: 'Account not found' });
            return;
          }

          const nonce = randomBytes(32).toString('hex');
          const signatures: QuorumSignature[] = [
            {
              operatorId: process.env.OPERATOR_ID || 'operator-1',
              publicKey: this.node.getOperatorInfo().publicKey,
              signature: createHash('sha256')
                .update(`ACCOUNT_CREATED:${requestedAccountId}:${Date.now()}`)
                .digest('hex'),
            },
          ];

          await this.canonicalEventStore.appendEvent(
            {
              type: EventType.ACCOUNT_CREATED,
              timestamp: Date.now(),
              nonce,
              accountId: requestedAccountId,
              role: 'operator',
              username: `operator-${String(operator.operatorId || '').trim() || 'unknown'}`,
              email: `operator@${String(operator.operatorId || '').trim() || 'unknown'}.local`,
              walletAddress: String(operator.btcAddress || '').trim() || undefined,
            } as any,
            signatures
          );

          state = await this.canonicalStateBuilder.buildState();
          account = state.accounts.get(requestedAccountId);
          if (!account) {
            res.status(500).json({ success: false, error: 'Failed to create operator account record' });
            return;
          }
        }

        const sigOk = verifySignature(challenge.nonce, String(signature), requestedAccountId);
        if (!sigOk) {
          res.status(401).json({ success: false, error: 'Invalid signature' });
          return;
        }

        if (account.totp?.enabled) {
          const encScheme = account.totp.encScheme;
          const encB64 = account.totp.totpSecretEncB64;
          if (!encScheme || !encB64) {
            res.status(500).json({ success: false, error: 'Account TOTP is enabled but secret is missing' });
            return;
          }

          if (!totpCode) {
            res.status(401).json({ success: false, error: '2FA code required', requires2FA: true });
            return;
          }

          let secretBase32: string;
          try {
            secretBase32 = openTotpSecretBase32(String(encScheme), String(encB64));
          } catch (e: any) {
            res.status(500).json({ success: false, error: e.message || 'Failed to decrypt TOTP secret' });
            return;
          }
          const totpOk = speakeasy.totp.verify({
            secret: secretBase32,
            encoding: 'base32',
            token: String(totpCode),
            window: 2,
          });

          if (!totpOk) {
            res.status(401).json({ success: false, error: 'Invalid 2FA code' });
            return;
          }
        }

        challenge.used = true;

        const sessionId = `session_${Date.now()}_${randomBytes(16).toString('hex')}`;
        const createdAt = Date.now();
        const expiresAt = createdAt + 24 * 60 * 60 * 1000;
        this.userSessions.set(sessionId, { sessionId, accountId: String(accountId), createdAt, expiresAt });

        res.json({ success: true, sessionId, accountId: String(accountId), expiresAt });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Set password for account (requires existing session)
    this.app.post('/api/accounts/:accountId/password/set', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const { password } = req.body;
        const authz = String(req.headers.authorization || '');
        const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';

        if (!token) {
          res.status(401).json({ success: false, error: 'Missing Authorization Bearer token' });
          return;
        }

        const session = this.userSessions.get(token);
        if (!session || session.accountId !== String(accountId) || Date.now() > session.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        if (!password || password.length < 8) {
          res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
          return;
        }

        const passwordHash = createHash('sha256').update(password).digest('hex');
        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_PASSWORD_SET:${accountId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_PASSWORD_SET,
            timestamp: Date.now(),
            nonce,
            accountId: String(accountId),
            passwordHash,
          } as any,
          signatures
        );

        res.json({ success: true, message: 'Password set successfully' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/accounts/:accountId/email/set', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const { email } = req.body;
        const authz = String(req.headers.authorization || '');
        const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';

        if (!token) {
          res.status(401).json({ success: false, error: 'Missing Authorization Bearer token' });
          return;
        }

        const session = this.userSessions.get(token);
        if (!session || session.accountId !== String(accountId) || Date.now() > session.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const normalizedEmail = this.normalizeEmailForHash(String(email || ''));
        if (!normalizedEmail || !normalizedEmail.includes('@')) {
          res.status(400).json({ success: false, error: 'Invalid email' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(String(accountId));
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const emailHash = this.computeEmailHash(normalizedEmail);
        for (const acc of state.accounts.values()) {
          if (String(acc.accountId) === String(accountId)) continue;
          if (String(acc.emailHash || '') === emailHash) {
            res.status(400).json({ success: false, error: 'Email is already in use' });
            return;
          }
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_EMAIL_SET:${accountId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_EMAIL_SET,
            timestamp: Date.now(),
            nonce,
            accountId: String(accountId),
            email: normalizedEmail,
            emailHash,
          } as any,
          signatures
        );

        res.json({ success: true, accountId: String(accountId), email: normalizedEmail, emailHash });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Optional public pay handle (e.g. name@autho) -> resolves to walletAddress. Does NOT use login email.
    this.app.post('/api/accounts/:accountId/pay-handle/set', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const { payHandle } = req.body;
        const authz = String(req.headers.authorization || '');
        const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';

        if (!token) {
          res.status(401).json({ success: false, error: 'Missing Authorization Bearer token' });
          return;
        }

        const session = this.userSessions.get(token);
        if (!session || session.accountId !== String(accountId) || Date.now() > session.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        let normalized = String(payHandle || '').trim().toLowerCase();
        if (normalized && !normalized.includes('@')) {
          normalized = `${normalized}@autho`;
        }

        if (normalized) {
          if (!normalized.endsWith('@autho')) {
            res.status(400).json({ success: false, error: 'Pay handle must end with @autho' });
            return;
          }
          if (!/^[a-z0-9._-]{3,64}@autho$/.test(normalized)) {
            res.status(400).json({ success: false, error: 'Invalid pay handle format' });
            return;
          }
        }

        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(String(accountId));
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        if (normalized) {
          for (const acc of state.accounts.values()) {
            if (String(acc.accountId) === String(accountId)) continue;
            const existing = String((acc as any).payHandle || '').trim().toLowerCase();
            if (existing && existing === normalized) {
              res.status(400).json({ success: false, error: 'Pay handle is already in use' });
              return;
            }
          }
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_PAY_HANDLE_SET:${accountId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_PAY_HANDLE_SET,
            timestamp: Date.now(),
            nonce,
            accountId: String(accountId),
            payHandle: normalized,
          } as any,
          signatures
        );

        res.json({ success: true, accountId: String(accountId), payHandle: normalized });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Public resolver: pay handle -> BTC address
    this.app.get('/api/pay/resolve', async (req: Request, res: Response) => {
      try {
        const handleRaw = String(req.query?.handle || '').trim().toLowerCase();
        if (!handleRaw) {
          res.status(400).json({ success: false, error: 'handle required' });
          return;
        }

        const handle = handleRaw.includes('@') ? handleRaw : `${handleRaw}@autho`;
        if (!handle.endsWith('@autho')) {
          res.status(400).json({ success: false, error: 'handle must end with @autho' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        for (const acc of state.accounts.values()) {
          const existing = String((acc as any).payHandle || '').trim().toLowerCase();
          if (existing && existing === handle) {
            const walletAddress = String((acc as any).walletAddress || '').trim();
            if (!walletAddress) {
              res.status(404).json({ success: false, error: 'Account has no wallet address' });
              return;
            }
            res.json({ success: true, handle, accountId: String((acc as any).accountId || ''), walletAddress });
            return;
          }
        }

        res.status(404).json({ success: false, error: 'Pay handle not found' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/accounts/:accountId/totp/setup', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const authz = String(req.headers.authorization || '');
        const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';

        if (!token) {
          res.status(401).json({ success: false, error: 'Missing Authorization Bearer token' });
          return;
        }

        const session = this.userSessions.get(token);
        if (!session || session.accountId !== String(accountId) || Date.now() > session.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(String(accountId));
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        if (account.totp?.enabled) {
          res.status(400).json({ success: false, error: '2FA already enabled for this account' });
          return;
        }

        const secret = speakeasy.generateSecret({
          name: `Autho (${String(accountId).substring(0, 10)}...)`,
          issuer: 'Autho Protocol',
          length: 32,
        });

        const otpauthUrl = secret.otpauth_url;
        if (!otpauthUrl) {
          res.status(500).json({ success: false, error: 'Failed to generate otpauth URL' });
          return;
        }

        const qrCodeUrl = await QRCode.toDataURL(otpauthUrl);

        const createdAt = Date.now();
        const expiresAt = createdAt + 10 * 60 * 1000;
        this.pendingTotpSetup.set(String(accountId), {
          accountId: String(accountId),
          secretBase32: secret.base32,
          otpauthUrl,
          createdAt,
          expiresAt,
        });

        res.json({
          success: true,
          accountId: String(accountId),
          secret: secret.base32,
          otpauthUrl,
          qrCodeUrl,
          expiresAt,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/accounts/:accountId/totp/verify-setup', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const { totpCode } = req.body;

        const authz = String(req.headers.authorization || '');
        const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';
        if (!token) {
          res.status(401).json({ success: false, error: 'Missing Authorization Bearer token' });
          return;
        }

        const session = this.userSessions.get(token);
        if (!session || session.accountId !== String(accountId) || Date.now() > session.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        if (!totpCode) {
          res.status(400).json({ success: false, error: 'Missing required field: totpCode' });
          return;
        }

        const pending = this.pendingTotpSetup.get(String(accountId));
        if (!pending || Date.now() > pending.expiresAt) {
          this.pendingTotpSetup.delete(String(accountId));
          res.status(400).json({ success: false, error: 'No pending TOTP setup found or setup expired' });
          return;
        }

        const ok = speakeasy.totp.verify({
          secret: pending.secretBase32,
          encoding: 'base32',
          token: String(totpCode),
          window: 2,
        });

        if (!ok) {
          res.status(401).json({ success: false, error: 'Invalid verification code' });
          return;
        }

        const sealed = sealTotpSecretBase32(pending.secretBase32);
        const encScheme = sealed.encScheme;
        const totpSecretEncB64 = sealed.totpSecretEncB64;
        const nonce = randomBytes(32).toString('hex');

        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_TOTP_ENABLED:${accountId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_TOTP_ENABLED,
            timestamp: Date.now(),
            nonce,
            accountId: String(accountId),
            totpSecretEncB64,
            encScheme,
          } as any,
          signatures
        );

        this.pendingTotpSetup.delete(String(accountId));

        res.json({ success: true, accountId: String(accountId), message: '2FA enabled' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/accounts/:accountId/totp/disable', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const { totpCode } = req.body;

        const authz = String(req.headers.authorization || '');
        const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';
        if (!token) {
          res.status(401).json({ success: false, error: 'Missing Authorization Bearer token' });
          return;
        }

        const session = this.userSessions.get(token);
        if (!session || session.accountId !== String(accountId) || Date.now() > session.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired session' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(String(accountId));
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        if (!account.totp?.enabled) {
          res.status(400).json({ success: false, error: '2FA is not enabled' });
          return;
        }

        if (!totpCode) {
          res.status(400).json({ success: false, error: 'Missing required field: totpCode' });
          return;
        }

        if (!account.totp.encScheme || !account.totp.totpSecretEncB64) {
          res.status(500).json({ success: false, error: 'Account TOTP is enabled but secret is missing' });
          return;
        }

        let secretBase32: string;
        try {
          secretBase32 = openTotpSecretBase32(String(account.totp.encScheme), String(account.totp.totpSecretEncB64));
        } catch (e: any) {
          res.status(500).json({ success: false, error: e.message || 'Failed to decrypt TOTP secret' });
          return;
        }
        const ok = speakeasy.totp.verify({
          secret: secretBase32,
          encoding: 'base32',
          token: String(totpCode),
          window: 2,
        });

        if (!ok) {
          res.status(401).json({ success: false, error: 'Invalid 2FA code' });
          return;
        }

        const nonce = randomBytes(32).toString('hex');
        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_TOTP_DISABLED:${accountId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_TOTP_DISABLED,
            timestamp: Date.now(),
            nonce,
            accountId: String(accountId),
          } as any,
          signatures
        );

        res.json({ success: true, accountId: String(accountId), message: '2FA disabled' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Account recovery: wallet-signature proof-of-control to reset TOTP
    this.app.post('/api/recovery/challenge', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.body;
        if (!accountId) {
          res.status(400).json({ success: false, error: 'Missing required field: accountId' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(String(accountId));
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const challengeId = `recovery_challenge_${Date.now()}_${randomBytes(8).toString('hex')}`;
        const nonce = randomBytes(32).toString('hex');
        const createdAt = Date.now();
        const expiresAt = createdAt + 5 * 60 * 1000;

        this.recoveryChallenges.set(challengeId, {
          challengeId,
          accountId: String(accountId),
          nonce,
          createdAt,
          expiresAt,
          used: false,
        });

        res.json({ success: true, challengeId, accountId: String(accountId), nonce, expiresAt });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/recovery/verify', async (req: Request, res: Response) => {
      try {
        const { challengeId, accountId, signature } = req.body;
        if (!challengeId || !accountId || !signature) {
          res.status(400).json({ success: false, error: 'Missing required fields: challengeId, accountId, signature' });
          return;
        }

        const challenge = this.recoveryChallenges.get(String(challengeId));
        if (!challenge) {
          res.status(400).json({ success: false, error: 'Recovery challenge not found or expired' });
          return;
        }

        if (challenge.used) {
          res.status(400).json({ success: false, error: 'Recovery challenge already used' });
          return;
        }

        if (Date.now() > challenge.expiresAt) {
          this.recoveryChallenges.delete(String(challengeId));
          res.status(400).json({ success: false, error: 'Recovery challenge expired' });
          return;
        }

        if (challenge.accountId !== String(accountId)) {
          res.status(400).json({ success: false, error: 'Account mismatch' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(String(accountId));
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const sigOk = verifySignature(challenge.nonce, String(signature), String(accountId));
        if (!sigOk) {
          res.status(401).json({ success: false, error: 'Invalid signature' });
          return;
        }

        challenge.used = true;

        const sessionId = `recovery_session_${Date.now()}_${randomBytes(16).toString('hex')}`;
        const createdAt = Date.now();
        const expiresAt = createdAt + 10 * 60 * 1000;
        this.recoverySessions.set(sessionId, { sessionId, accountId: String(accountId), createdAt, expiresAt });

        res.json({ success: true, recoverySessionId: sessionId, accountId: String(accountId), expiresAt });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/recovery/:accountId/totp/setup', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const authz = String(req.headers.authorization || '');
        const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';

        if (!token) {
          res.status(401).json({ success: false, error: 'Missing Authorization Bearer token' });
          return;
        }

        const session = this.recoverySessions.get(token);
        if (!session || session.accountId !== String(accountId) || Date.now() > session.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired recovery session' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const account = state.accounts.get(String(accountId));
        if (!account) {
          res.status(404).json({ success: false, error: 'Account not found' });
          return;
        }

        const secret = speakeasy.generateSecret({
          name: `Autho Recovery (${String(accountId).substring(0, 10)}...)`,
          issuer: 'Autho Protocol',
          length: 32,
        });

        const otpauthUrl = secret.otpauth_url;
        if (!otpauthUrl) {
          res.status(500).json({ success: false, error: 'Failed to generate otpauth URL' });
          return;
        }

        const qrCodeUrl = await QRCode.toDataURL(otpauthUrl);

        const createdAt = Date.now();
        const expiresAt = createdAt + 10 * 60 * 1000;
        this.pendingRecoveryTotpSetup.set(String(accountId), {
          accountId: String(accountId),
          secretBase32: secret.base32,
          otpauthUrl,
          createdAt,
          expiresAt,
        });

        res.json({
          success: true,
          accountId: String(accountId),
          secret: secret.base32,
          otpauthUrl,
          qrCodeUrl,
          expiresAt,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.post('/api/recovery/:accountId/totp/verify-setup', async (req: Request, res: Response) => {
      try {
        const { accountId } = req.params;
        const { totpCode } = req.body;

        const authz = String(req.headers.authorization || '');
        const token = authz.startsWith('Bearer ') ? authz.slice('Bearer '.length) : '';
        if (!token) {
          res.status(401).json({ success: false, error: 'Missing Authorization Bearer token' });
          return;
        }

        const session = this.recoverySessions.get(token);
        if (!session || session.accountId !== String(accountId) || Date.now() > session.expiresAt) {
          res.status(401).json({ success: false, error: 'Invalid or expired recovery session' });
          return;
        }

        if (!totpCode) {
          res.status(400).json({ success: false, error: 'Missing required field: totpCode' });
          return;
        }

        const pending = this.pendingRecoveryTotpSetup.get(String(accountId));
        if (!pending || Date.now() > pending.expiresAt) {
          this.pendingRecoveryTotpSetup.delete(String(accountId));
          res.status(400).json({ success: false, error: 'No pending recovery TOTP setup found or setup expired' });
          return;
        }

        const ok = speakeasy.totp.verify({
          secret: pending.secretBase32,
          encoding: 'base32',
          token: String(totpCode),
          window: 2,
        });

        if (!ok) {
          res.status(401).json({ success: false, error: 'Invalid verification code' });
          return;
        }

        const sealed = sealTotpSecretBase32(pending.secretBase32);
        const encScheme = sealed.encScheme;
        const totpSecretEncB64 = sealed.totpSecretEncB64;
        const nonce = randomBytes(32).toString('hex');

        const signatures: QuorumSignature[] = [
          {
            operatorId: process.env.OPERATOR_ID || 'operator-1',
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ACCOUNT_RECOVERY_TOTP_RESET:${accountId}:${Date.now()}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ACCOUNT_RECOVERY_TOTP_RESET,
            timestamp: Date.now(),
            nonce,
            accountId: String(accountId),
            totpSecretEncB64,
            encScheme,
          } as any,
          signatures
        );

        this.pendingRecoveryTotpSetup.delete(String(accountId));

        res.json({ success: true, accountId: String(accountId), message: '2FA reset via recovery' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Admin authentication endpoints
    this.app.post('/api/admin/login', async (req: Request, res: Response) => {
      try {
        const { username, password, totpCode } = req.body;
        
        // Get admin credentials from environment variables
        const adminUsername = process.env.ADMIN_USERNAME || 'admin';
        const adminPassword = process.env.ADMIN_PASSWORD || 'changeme123';
        
        // Check username and password first
        if (username !== adminUsername || password !== adminPassword) {
          res.status(401).json({ 
            success: false, 
            error: 'Invalid credentials' 
          });
          return;
        }

        // Check if 2FA is enabled
        const dataDir = process.env.OPERATOR_DATA_DIR || './operator-data';
        const twoFAFile = path.join(dataDir, '2fa-secret.json');
        
        if (fs.existsSync(twoFAFile)) {
          // 2FA is enabled, verify TOTP code
          if (!totpCode) {
            res.status(401).json({ 
              success: false, 
              error: 'Two-factor authentication code required',
              requires2FA: true
            });
            return;
          }

          const secretData = JSON.parse(fs.readFileSync(twoFAFile, 'utf8'));
          const verified = speakeasy.totp.verify({
            secret: secretData.secret,
            encoding: 'base32',
            token: totpCode,
            window: 2 // Allow 2 time steps before/after for clock drift
          });

          if (!verified) {
            res.status(401).json({ 
              success: false, 
              error: 'Invalid two-factor authentication code' 
            });
            return;
          }
        }
        
        const token = randomBytes(32).toString('hex');
        const createdAt = Date.now();
        const expiresAt = createdAt + 24 * 60 * 60 * 1000;
        this.adminSessions.set(token, { token, username: String(username), createdAt, expiresAt });
        
        res.json({ 
          success: true, 
          token,
          message: 'Login successful' 
        });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/admin/verify', async (req: Request, res: Response) => {
      try {
        const { token } = req.body;
        
        if (!token) {
          res.status(401).json({ valid: false });
          return;
        }

        const sess = this.getAdminSession(String(token));
        if (!sess) {
          res.status(401).json({ valid: false });
          return;
        }

        res.json({ valid: true });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/admin/offers', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const status = String(req.query.status || '').trim().toUpperCase();
        const limitRaw = Number(req.query.limit || 50);
        const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(500, Math.floor(limitRaw))) : 50;

        const state = await this.canonicalStateBuilder.buildState();
        const settlements = Array.from(state.settlements.values());

        const canonicalMapped = settlements
          .map((s: any) => {
            const itemName = String(state.items.get(String(s.itemId))?.metadata?.name || state.items.get(String(s.itemId))?.metadata?.itemType || '');
            return {
              offerId: String(s.settlementId),
              itemId: String(s.itemId),
              itemName,
              buyerAddress: String(s.buyer),
              sellerAddress: String(s.seller),
              amount: 0,
              sats: Number(s.price || 0),
              status: s.status === 'completed' ? 'PAID' : s.status === 'failed' ? 'FAILED' : 'PENDING',
              createdAt: Number(s.initiatedAt || 0),
              expiresAt: Number(s.expiresAt || 0),
              paymentTxid: s.txid,
              platformFeeSats: s.platformFee,
              operatorFees: s.operatorFees,
            };
          });

        const canonicalFiltered = status
          ? canonicalMapped.filter((o: any) => String(o?.status || '').toUpperCase() === status)
          : canonicalMapped;

        canonicalFiltered.sort((a: any, b: any) => Number(b?.createdAt || 0) - Number(a?.createdAt || 0));
        if (canonicalFiltered.length > 0) {
          res.json({ success: true, offers: canonicalFiltered.slice(0, limit), count: canonicalFiltered.length });
          return;
        }

        const offersMap = (this.node as any).offers || new Map();
        const allOffers = Array.from(offersMap.values());
        const filtered = status
          ? allOffers.filter((o: any) => String(o?.status || '').toUpperCase() === status)
          : allOffers;
        filtered.sort((a: any, b: any) => Number(b?.createdAt || 0) - Number(a?.createdAt || 0));
        res.json({ success: true, offers: filtered.slice(0, limit), count: filtered.length });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    this.app.get('/api/admin/offers/summary', async (req: Request, res: Response) => {
      try {
        if (!this.requireAdminMainNode(req, res)) return;

        const state = await this.canonicalStateBuilder.buildState();
        const settlements = Array.from(state.settlements.values());

        const byStatus: Record<string, number> = {};
        for (const s of settlements) {
          const ss = (s as any)?.status === 'completed' ? 'PAID' : (s as any)?.status === 'failed' ? 'FAILED' : 'PENDING';
          byStatus[String(ss).toUpperCase()] = (byStatus[String(ss).toUpperCase()] || 0) + 1;
        }

        const totals = settlements.reduce(
          (acc: any, s: any) => {
            const platformFee = Number(s?.platformFee || 0);
            const operatorFees = s?.operatorFees && typeof s.operatorFees === 'object' ? s.operatorFees : {};
            const operatorFeeSum = Object.values(operatorFees as Record<string, number>).reduce(
              (sum, v) => sum + Number(v || 0),
              0
            );
            acc.totalFeeSats += platformFee + operatorFeeSum;
            acc.mainNodeFeeSats += platformFee;
            acc.operatorFeeSats += operatorFeeSum;
            return acc;
          },
          { totalFeeSats: 0, mainNodeFeeSats: 0, operatorFeeSats: 0 }
        );

        const recentFeeRecords = settlements
          .filter((s: any) => (s as any)?.status === 'completed')
          .slice()
          .sort((a: any, b: any) => Number(b?.completedAt || 0) - Number(a?.completedAt || 0))
          .slice(0, 25)
          .map((s: any) => {
            const opFees = (s?.operatorFees && typeof s.operatorFees === 'object') ? s.operatorFees : {};
            const opFeeSum: number = Object.values(opFees as Record<string, unknown>).reduce(
              (sum: number, v: unknown) => sum + Number(v || 0),
              0
            ) as number;
            return {
              offerId: String(s.settlementId),
              txid: s.txid,
              totalFeeSats: Number(s?.platformFee || 0) + opFeeSum,
              mainNodeFeeSats: Number(s?.platformFee || 0),
              operatorFeeSats: opFeeSum,
              processedAt: Number(s?.completedAt || 0),
            };
          });

        if (settlements.length > 0) {
          res.json({
            success: true,
            offerCount: settlements.length,
            byStatus,
            feeRecordCount: recentFeeRecords.length,
            totals,
            recentFeeRecords,
          });
          return;
        }

        const offersMap = (this.node as any).offers || new Map();
        const allOffers = Array.from(offersMap.values());
        const byStatusFallback: Record<string, number> = {};
        for (const o of allOffers) {
          const ss = String((o as any)?.status || 'UNKNOWN').toUpperCase();
          byStatusFallback[ss] = (byStatusFallback[ss] || 0) + 1;
        }

        const feeRecords = Array.isArray((this.node as any).feeRecords) ? (this.node as any).feeRecords : [];
        const totalsFallback = feeRecords.reduce(
          (acc: any, r: any) => {
            acc.totalFeeSats += Number(r?.totalFeeSats || 0);
            acc.mainNodeFeeSats += Number(r?.mainNodeFeeSats || 0);
            acc.operatorFeeSats += Number(r?.operatorFeeSats || 0);
            return acc;
          },
          { totalFeeSats: 0, mainNodeFeeSats: 0, operatorFeeSats: 0 }
        );
        const recentFeeRecordsFallback = feeRecords
          .slice()
          .sort((a: any, b: any) => Number(b?.processedAt || 0) - Number(a?.processedAt || 0))
          .slice(0, 25);
        res.json({
          success: true,
          offerCount: allOffers.length,
          byStatus: byStatusFallback,
          feeRecordCount: feeRecords.length,
          totals: totalsFallback,
          recentFeeRecords: recentFeeRecordsFallback,
        });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // 2FA Setup endpoints
    this.app.post('/api/admin/2fa/setup', async (req: Request, res: Response) => {
      try {
        const dataDir = process.env.OPERATOR_DATA_DIR || './operator-data';
        const twoFAFile = path.join(dataDir, '2fa-secret.json');
        
        // Check if 2FA is already enabled
        if (fs.existsSync(twoFAFile)) {
          res.status(400).json({ 
            success: false, 
            error: 'Two-factor authentication is already enabled' 
          });
          return;
        }

        // Generate new secret
        const secret = speakeasy.generateSecret({
          name: 'Autho Operator Node',
          issuer: 'Autho Protocol'
        });

        const qrCodeUrl = `/api/admin/2fa/qr.png?t=${Date.now()}`;

        // Save secret (but don't enable yet - requires verification)
        const tempFile = path.join(dataDir, '2fa-temp.json');
        fs.writeFileSync(tempFile, JSON.stringify({
          secret: secret.base32,
          otpauth_url: secret.otpauth_url,
          created: Date.now()
        }, null, 2));

        res.json({
          success: true,
          secret: secret.base32,
          otpauthUrl: secret.otpauth_url,
          qrCodeUrl,
          manualEntry: secret.base32
        });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/admin/2fa/qr.png', async (req: Request, res: Response) => {
      try {
        const dataDir = process.env.OPERATOR_DATA_DIR || './operator-data';
        const tempFile = path.join(dataDir, '2fa-temp.json');

        if (!fs.existsSync(tempFile)) {
          res.status(404).send('No pending 2FA setup found');
          return;
        }

        const secretData = JSON.parse(fs.readFileSync(tempFile, 'utf8'));
        const otpauthUrl = secretData.otpauth_url;

        if (!otpauthUrl) {
          res.status(500).send('2FA setup data is missing otpauth URL');
          return;
        }

        const png = await QRCode.toBuffer(otpauthUrl, {
          type: 'png',
          errorCorrectionLevel: 'M',
          margin: 2,
          width: 250
        });

        res.setHeader('Content-Type', 'image/png');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.send(png);
      } catch (error: any) {
        res.status(500).send(error.message);
      }
    });

    this.app.get('/api/qr.png', async (req: Request, res: Response) => {
      try {
        const text = String(req.query.text || '').trim();
        if (!text) {
          res.status(400).send('Missing text');
          return;
        }

        const png = await QRCode.toBuffer(text, {
          type: 'png',
          errorCorrectionLevel: 'M',
          margin: 2,
          width: 250
        });

        res.setHeader('Content-Type', 'image/png');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.send(png);
      } catch (error: any) {
        res.status(500).send(error.message);
      }
    });

    this.app.post('/api/admin/2fa/verify-setup', async (req: Request, res: Response) => {
      try {
        const { totpCode } = req.body;
        
        const dataDir = process.env.OPERATOR_DATA_DIR || './operator-data';
        const tempFile = path.join(dataDir, '2fa-temp.json');
        const twoFAFile = path.join(dataDir, '2fa-secret.json');

        if (!fs.existsSync(tempFile)) {
          res.status(400).json({ 
            success: false, 
            error: 'No pending 2FA setup found' 
          });
          return;
        }

        const secretData = JSON.parse(fs.readFileSync(tempFile, 'utf8'));
        
        // Verify the code
        const verified = speakeasy.totp.verify({
          secret: secretData.secret,
          encoding: 'base32',
          token: totpCode,
          window: 2
        });

        if (!verified) {
          res.status(401).json({ 
            success: false, 
            error: 'Invalid verification code. Please try again.' 
          });
          return;
        }

        // Code is valid, enable 2FA
        fs.renameSync(tempFile, twoFAFile);
        
        console.log('[Security] Two-factor authentication enabled');

        res.json({
          success: true,
          message: 'Two-factor authentication enabled successfully'
        });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/admin/2fa/disable', async (req: Request, res: Response) => {
      try {
        const { totpCode } = req.body;
        
        const dataDir = process.env.OPERATOR_DATA_DIR || './operator-data';
        const twoFAFile = path.join(dataDir, '2fa-secret.json');

        if (!fs.existsSync(twoFAFile)) {
          res.status(400).json({ 
            success: false, 
            error: 'Two-factor authentication is not enabled' 
          });
          return;
        }

        const secretData = JSON.parse(fs.readFileSync(twoFAFile, 'utf8'));
        
        // Verify the code before disabling
        const verified = speakeasy.totp.verify({
          secret: secretData.secret,
          encoding: 'base32',
          token: totpCode,
          window: 2
        });

        if (!verified) {
          res.status(401).json({ 
            success: false, 
            error: 'Invalid verification code' 
          });
          return;
        }

        // Disable 2FA
        fs.unlinkSync(twoFAFile);
        
        console.log('[Security] Two-factor authentication disabled');

        res.json({
          success: true,
          message: 'Two-factor authentication disabled'
        });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/admin/2fa/status', async (req: Request, res: Response) => {
      try {
        const dataDir = process.env.OPERATOR_DATA_DIR || './operator-data';
        const twoFAFile = path.join(dataDir, '2fa-secret.json');
        
        res.json({
          success: true,
          enabled: fs.existsSync(twoFAFile)
        });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    // Esplora-like chain-data API for browser wallets.
    // NOTE: Implementation currently proxies to Blockstream API for initial functionality.
    // Long-term, this can be backed by operator's own indexer.
    this.app.get('/api/chain/status', async (req: Request, res: Response) => {
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
        });
      } catch (error: any) {
        res.status(500).json({ ok: false, error: error.message });
      }
    });

    this.app.get('/api/chain/address/:address', async (req: Request, res: Response) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          res.status(400).json({ error: 'Missing address' });
          return;
        }

        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const apiBase = network === 'mainnet'
          ? 'https://blockstream.info/api'
          : 'https://blockstream.info/testnet/api';

        const response = await fetch(`${apiBase}/address/${address}`);
        if (!response.ok) {
          const text = await response.text();
          res.status(response.status).send(text);
          return;
        }
        const json = await response.json();
        res.json(json);
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/address/:address/utxo', async (req: Request, res: Response) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          res.status(400).json({ error: 'Missing address' });
          return;
        }

        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const bases = network === 'mainnet'
          ? ['https://mempool.space/api', 'https://blockstream.info/api']
          : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];

        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/address/${address}/utxo`);
            const text = await response.text();
            if (!response.ok) {
              lastErr = { status: response.status, text };
              continue;
            }
            res.json(JSON.parse(text));
            return;
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/address/:address/txs', async (req: Request, res: Response) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          res.status(400).json({ error: 'Missing address' });
          return;
        }

        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const bases = network === 'mainnet'
          ? ['https://mempool.space/api', 'https://blockstream.info/api']
          : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];

        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/address/${address}/txs`);
            const text = await response.text();
            if (!response.ok) {
              lastErr = { status: response.status, text };
              continue;
            }
            res.json(JSON.parse(text));
            return;
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/address/:address/txs/mempool', async (req: Request, res: Response) => {
      try {
        const address = String(req.params.address || '').trim();
        if (!address) {
          res.status(400).json({ error: 'Missing address' });
          return;
        }

        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const bases = network === 'mainnet'
          ? ['https://mempool.space/api', 'https://blockstream.info/api']
          : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];

        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/address/${address}/txs/mempool`);
            const text = await response.text();
            if (!response.ok) {
              lastErr = { status: response.status, text };
              continue;
            }
            res.json(JSON.parse(text));
            return;
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/tx/:txid/hex', async (req: Request, res: Response) => {
      try {
        const txid = String(req.params.txid || '').trim();
        if (!txid) {
          res.status(400).json({ error: 'Missing txid' });
          return;
        }

        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const bases = network === 'mainnet'
          ? ['https://mempool.space/api', 'https://blockstream.info/api']
          : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];

        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/tx/${txid}/hex`);
            const text = await response.text();
            if (!response.ok) {
              lastErr = { status: response.status, text };
              continue;
            }
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send(text);
            return;
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/tx/:txid/status', async (req: Request, res: Response) => {
      try {
        const txid = String(req.params.txid || '').trim();
        if (!txid) {
          res.status(400).json({ error: 'Missing txid' });
          return;
        }

        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const bases = network === 'mainnet'
          ? ['https://mempool.space/api', 'https://blockstream.info/api']
          : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];

        let lastErr: any;
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
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/chain/fee-estimates', async (req: Request, res: Response) => {
      try {
        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const bases = network === 'mainnet'
          ? ['https://mempool.space/api', 'https://blockstream.info/api']
          : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];

        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/fee-estimates`);
            const text = await response.text();
            if (!response.ok) {
              lastErr = { status: response.status, text };
              continue;
            }
            res.json(JSON.parse(text));
            return;
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).send(String(lastErr.text || 'Chain provider error'));
          return;
        }
        res.status(502).json({ error: 'All chain providers failed' });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
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
          // Support text/plain (or other raw bodies) without changing global middleware.
          const contentType = String(req.headers['content-type'] || '');
          if (contentType.startsWith('text/plain') || contentType.startsWith('application/octet-stream')) {
            txHex = await new Promise<string>((resolve, reject) => {
              let data = '';
              req.setEncoding('utf8');
              req.on('data', (chunk) => (data += chunk));
              req.on('end', () => resolve(data));
              req.on('error', reject);
            });
            txHex = String(txHex || '').trim();
          }
        }

        if (!txHex) {
          res.status(400).json({ success: false, error: 'Missing txHex' });
          return;
        }

        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const bases = network === 'mainnet'
          ? ['https://mempool.space/api', 'https://blockstream.info/api']
          : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];

        let lastErr: any;
        for (const apiBase of bases) {
          try {
            const response = await fetch(`${apiBase}/tx`, {
              method: 'POST',
              headers: {
                'Content-Type': 'text/plain',
              },
              body: txHex,
            });

            const text = await response.text();
            if (!response.ok) {
              lastErr = { status: response.status, text };
              continue;
            }

            res.json({ success: true, txid: text.trim(), provider: apiBase });
            return;
          } catch (e) {
            lastErr = e;
          }
        }

        if (lastErr?.status) {
          res.status(Number(lastErr.status)).json({ success: false, error: String(lastErr.text || 'Chain provider error') });
          return;
        }
        res.status(502).json({ success: false, error: 'All chain providers failed' });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Node Bitcoin wallet management endpoints
    this.app.get('/api/node/wallet/balance', async (req: Request, res: Response) => {
      try {
        // Get node wallet address from environment or operator info
        const walletAddress = process.env.NODE_WALLET_ADDRESS || this.node.getOperatorInfo().btcAddress;
        
        if (!walletAddress) {
          res.status(404).json({ error: 'Node wallet not configured' });
          return;
        }

        // Query real blockchain data from Blockstream API
        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const apiBase = network === 'mainnet' 
          ? 'https://blockstream.info/api'
          : 'https://blockstream.info/testnet/api';

        try {
          const response = await fetch(`${apiBase}/address/${walletAddress}`);
          const addressData = await response.json();

          console.log('[Wallet Balance] API Response:', JSON.stringify(addressData, null, 2));

          // Calculate balance from chain stats
          const confirmedSats = (addressData.chain_stats?.funded_txo_sum || 0) - (addressData.chain_stats?.spent_txo_sum || 0);
          const unconfirmedSats = (addressData.mempool_stats?.funded_txo_sum || 0) - (addressData.mempool_stats?.spent_txo_sum || 0);
          
          console.log('[Wallet Balance] Confirmed sats:', confirmedSats);
          console.log('[Wallet Balance] Unconfirmed sats:', unconfirmedSats);
          
          const balance = {
            address: walletAddress,
            confirmed: confirmedSats / 100000000, // Convert sats to BTC
            unconfirmed: unconfirmedSats / 100000000,
            total: (confirmedSats + unconfirmedSats) / 100000000,
            confirmedSats: confirmedSats,
            unconfirmedSats: unconfirmedSats,
            totalSats: confirmedSats + unconfirmedSats
          };

          console.log('[Wallet Balance] Final balance:', balance);
          res.json(balance);
        } catch (apiError) {
          console.error('Blockchain API error:', apiError);
          // Fallback to zero balance if API fails
          res.json({
            address: walletAddress,
            confirmed: 0,
            unconfirmed: 0,
            total: 0
          });
        }
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/node/wallet/address', async (req: Request, res: Response) => {
      try {
        const walletAddress = process.env.NODE_WALLET_ADDRESS || this.node.getOperatorInfo().btcAddress;
        
        if (!walletAddress) {
          res.status(404).json({ error: 'Node wallet not configured' });
          return;
        }

        res.json({ 
          address: walletAddress,
          network: process.env.BITCOIN_NETWORK || 'testnet'
        });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/node/wallet/send', async (req: Request, res: Response) => {
      try {
        const { toAddress, amount, fee, feeRateSatPerVByte } = req.body;
        
        if (!toAddress || !amount) {
          res.status(400).json({ error: 'Missing required fields: toAddress, amount' });
          return;
        }

        // Validate Bitcoin address format
        if (!toAddress.match(/^(bc1|tb1|[13]|[mn2])[a-zA-HJ-NP-Z0-9]{25,62}$/)) {
          res.status(400).json({ error: 'Invalid Bitcoin address format' });
          return;
        }

        // Load private key from operator keys
        const dataDir = process.env.OPERATOR_DATA_DIR || './operator-data';
        const keysFile = path.join(dataDir, 'operator-keys.json');
        
        if (!fs.existsSync(keysFile)) {
          res.status(500).json({ error: 'Operator keys not found. Cannot send Bitcoin.' });
          return;
        }

        const keys = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
        
        // Convert BTC to satoshis
        const amountSats = Math.floor(amount * 100000000);

        // Fee rate is sats/vByte (NOT BTC). This matches BitcoinTransactionService.
        // Allow fractional sats/vB (e.g. 0.2) by *not* flooring the user input.
        let feeRate: number | undefined;
        const feeRateRaw = (feeRateSatPerVByte ?? fee) as any;
        if (feeRateRaw !== undefined && feeRateRaw !== null && feeRateRaw !== '') {
          const parsed = Number(feeRateRaw);
          if (!Number.isFinite(parsed)) {
            res.status(400).json({
              success: false,
              error: 'Invalid fee rate. Must be a number (sats/vByte).'
            });
            return;
          }
          // Backwards-compat: older UI sometimes sent BTC-denominated "fee".
          if (feeRateSatPerVByte === undefined && typeof fee === 'number' && fee > 0 && fee < 1) {
            res.status(400).json({
              success: false,
              error: 'Invalid fee. Fee must be a fee rate in sats/vByte (e.g. 0.2, 2, 7, 25), not a BTC amount.'
            });
            return;
          }
          feeRate = parsed;
          if (feeRate < 0.1 || feeRate > 500) {
            res.status(400).json({
              success: false,
              error: 'Invalid fee rate. Must be between 0.1 and 500 sats/vByte.'
            });
            return;
          }
        }

        // Create Bitcoin transaction service
        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const txService = new BitcoinTransactionService(network);

        console.log(`[Node Wallet] Sending ${amountSats} sats to ${toAddress}`);

        // Send the transaction
        const result = await txService.sendBitcoin(
          keys.privateKey,
          toAddress,
          amountSats,
          feeRate
        );

        if (result.success) {
          res.json({
            success: true,
            txid: result.txid,
            toAddress,
            amount,
            feeRateSatPerVByte: feeRate,
            message: 'Transaction broadcast successfully'
          });
        } else {
          res.status(400).json({
            success: false,
            error: result.error
          });
        }
      } catch (error: any) {
        console.error('[Node Wallet] Send error:', error);
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/node/wallet/sweep', async (req: Request, res: Response) => {
      try {
        const { toAddress, fee, feeRateSatPerVByte } = req.body;

        if (!toAddress) {
          res.status(400).json({ error: 'Missing required field: toAddress' });
          return;
        }

        if (!toAddress.match(/^(bc1|tb1|[13]|[mn2])[a-zA-HJ-NP-Z0-9]{25,62}$/)) {
          res.status(400).json({ error: 'Invalid Bitcoin address format' });
          return;
        }

        const dataDir = process.env.OPERATOR_DATA_DIR || './operator-data';
        const keysFile = path.join(dataDir, 'operator-keys.json');

        if (!fs.existsSync(keysFile)) {
          res.status(500).json({ error: 'Operator keys not found. Cannot send Bitcoin.' });
          return;
        }

        const keys = JSON.parse(fs.readFileSync(keysFile, 'utf8'));

        let feeRate: number | undefined;
        const feeRateRaw = (feeRateSatPerVByte ?? fee) as any;
        if (feeRateRaw !== undefined && feeRateRaw !== null && feeRateRaw !== '') {
          const parsed = Number(feeRateRaw);
          if (!Number.isFinite(parsed)) {
            res.status(400).json({
              success: false,
              error: 'Invalid fee rate. Must be a number (sats/vByte).'
            });
            return;
          }
          if (feeRateSatPerVByte === undefined && typeof fee === 'number' && fee > 0 && fee < 1) {
            res.status(400).json({
              success: false,
              error: 'Invalid fee. Fee must be a fee rate in sats/vByte (e.g. 0.2, 2, 7, 25), not a BTC amount.'
            });
            return;
          }
          feeRate = parsed;
          if (feeRate < 0.1 || feeRate > 500) {
            res.status(400).json({
              success: false,
              error: 'Invalid fee rate. Must be between 0.1 and 500 sats/vByte.'
            });
            return;
          }
        }

        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const txService = new BitcoinTransactionService(network);

        console.log(`[Node Wallet] Sweeping all confirmed funds to ${toAddress}`);
        const result = await txService.sweepAllConfirmed(keys.privateKey, toAddress, feeRate);

        if (result.success) {
          res.json({
            success: true,
            txid: result.txid,
            toAddress,
            fromAddress: result.fromAddress,
            sentSats: result.sentSats,
            feeSats: result.feeSats,
            feeRateSatPerVByte: feeRate,
            message: 'Sweep broadcast successfully'
          });
        } else {
          res.status(400).json({
            success: false,
            error: result.error
          });
        }
      } catch (error: any) {
        console.error('[Node Wallet] Sweep error:', error);
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/node/wallet/transactions', async (req: Request, res: Response) => {
      try {
        const walletAddress = process.env.NODE_WALLET_ADDRESS || this.node.getOperatorInfo().btcAddress;
        
        if (!walletAddress) {
          res.json({ transactions: [], count: 0 });
          return;
        }

        // Query real blockchain transactions from Blockstream API
        const network = process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
        const apiBase = network === 'mainnet' 
          ? 'https://blockstream.info/api'
          : 'https://blockstream.info/testnet/api';

        try {
          const [confirmedResp, mempoolResp] = await Promise.all([
            fetch(`${apiBase}/address/${walletAddress}/txs`),
            fetch(`${apiBase}/address/${walletAddress}/txs/mempool`),
          ]);
          const confirmedTxs = await confirmedResp.json();
          const mempoolTxs = await mempoolResp.json();
          const txs = ([] as any[]).concat(Array.isArray(mempoolTxs) ? mempoolTxs : []).concat(
            Array.isArray(confirmedTxs) ? confirmedTxs : []
          );

          const transactions = txs.map((tx: any) => {
            // Calculate if this is a receive or send transaction
            let receivedAmount = 0;
            let sentAmount = 0;
            
            // Check outputs for receives
            tx.vout.forEach((output: any) => {
              if (output.scriptpubkey_address === walletAddress) {
                receivedAmount += output.value;
              }
            });

            // Check inputs for sends
            tx.vin.forEach((input: any) => {
              if (input.prevout?.scriptpubkey_address === walletAddress) {
                sentAmount += input.prevout.value;
              }
            });

            // Determine transaction type and net amount
            let type: string;
            let netAmount: number;
            
            if (sentAmount > 0 && receivedAmount > 0) {
              // Wallet both sent and received (self-transfer or change)
              // Net change to wallet balance
              netAmount = receivedAmount - sentAmount;
              type = netAmount >= 0 ? 'receive' : 'send';
              netAmount = Math.abs(netAmount);
            } else if (sentAmount > 0) {
              // Pure send (wallet spent, no receive)
              type = 'send';
              netAmount = sentAmount - receivedAmount; // Amount sent (minus any change)
            } else {
              // Pure receive (wallet received, didn't spend)
              type = 'receive';
              netAmount = receivedAmount;
            }

            console.log(`[TX ${tx.txid.substring(0, 10)}] Type: ${type}, Received: ${receivedAmount}, Sent: ${sentAmount}, Net: ${netAmount}`);

            return {
              txid: tx.txid,
              type: type,
              amount: netAmount / 100000000, // Convert sats to BTC
              amountSats: netAmount,
              confirmations: tx.status.confirmed ? (tx.status.block_height ? 6 : 0) : 0,
              timestamp: tx.status.block_time ? tx.status.block_time * 1000 : Date.now(),
              address: walletAddress
            };
          });

          res.json({ transactions, count: transactions.length });
        } catch (apiError) {
          console.error('Blockchain API error:', apiError);
          res.json({ transactions: [], count: 0 });
        }
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    });
  }

  /**
   * Get active operator addresses for fee distribution
   */
  private getActiveOperatorAddresses(): string[] {
    const operators: string[] = [];

    const peers = (this.node as any).peers || [];
    peers.forEach((peer: any) => {
      if (peer && peer.btcAddress) {
        operators.push(String(peer.btcAddress));
      }
    });

    return operators.filter((addr) => addr && addr.length > 0);
  }

  /**
   * Process fee distribution for a paid offer
   */
  private processFeeDistribution(offer: any): void {
    if (!offer.feeDistribution) {
      console.log('[Fee Distribution] No fee distribution data available');
      return;
    }

    const { totalFeeSats, mainNodeFeeSats, operatorFeeSats, mainNodeAddress, operatorAddresses } = offer.feeDistribution;

    console.log('[Fee Distribution] Processing platform fees:');
    console.log(`  Total Platform Fee: ${totalFeeSats} sats (1%)`);
    if (operatorFeeSats <= 0) {
      console.log(`  Main Node (100%): ${mainNodeFeeSats} sats → ${mainNodeAddress}`);
      console.log(`  Operators (0%): ${operatorFeeSats} sats`);
    } else {
      console.log(`  Main Node (60%): ${mainNodeFeeSats} sats → ${mainNodeAddress}`);
      console.log(`  Operators (40%): ${operatorFeeSats} sats`);
    }

    // Distribute operator fees among active operators
    if (operatorAddresses.length > 0) {
      const feePerOperator = Math.floor(operatorFeeSats / operatorAddresses.length);
      console.log(`  Fee per operator: ${feePerOperator} sats (${operatorAddresses.length} operators)`);
      
      operatorAddresses.forEach((address: string, index: number) => {
        console.log(`    Operator ${index + 1}: ${feePerOperator} sats → ${address}`);
      });
    }

    // Store fee distribution record
    const feeRecord = {
      offerId: offer.offerId,
      totalFeeSats,
      mainNodeFeeSats,
      operatorFeeSats,
      mainNodeAddress,
      operatorAddresses,
      processedAt: Date.now(),
      txid: offer.paymentTxid
    };

    // Save fee record (in production, this would be stored in database)
    if (!(this.node as any).feeRecords) {
      (this.node as any).feeRecords = [];
    }
    (this.node as any).feeRecords.push(feeRecord);

    console.log('[Fee Distribution] Fee distribution recorded successfully');
  }

  // Consensus Integration Methods
  private startConsensusVerification(): void {
    const { ConsensusIntegration } = require('./consensus-integration');
    ConsensusIntegration.startConsensusVerification(this);
  }

  private async getCurrentLedgerState(): Promise<LedgerState> {
    const { ConsensusIntegration } = require('./consensus-integration');
    return await ConsensusIntegration.getCurrentLedgerState(this);
  }

  private async handleStateVerification(ws: WebSocket, message: any): Promise<void> {
    const { ConsensusIntegration } = require('./consensus-integration');
    await ConsensusIntegration.handleStateVerification(this, ws, message);
  }

  private async handleVerificationResponse(message: any): Promise<void> {
    const { ConsensusIntegration } = require('./consensus-integration');
    await ConsensusIntegration.handleVerificationResponse(this, message);
  }

  private broadcastToAllPeers(message: any): void {
    const { ConsensusIntegration } = require('./consensus-integration');
    ConsensusIntegration.broadcastToAllPeers(this, message);
  }

  private async checkLeadershipStatus(): Promise<void> {
    const { ConsensusIntegration } = require('./consensus-integration');
    await ConsensusIntegration.checkLeadershipStatus(this);
  }

  private async getActiveOperators(): Promise<OperatorInfo[]> {
    const { ConsensusIntegration } = require('./consensus-integration');
    return await ConsensusIntegration.getActiveOperators(this);
  }

  private async requestFullSyncFromMajority(majorityHash: string): Promise<void> {
    const { ConsensusIntegration } = require('./consensus-integration');
    await ConsensusIntegration.requestFullSyncFromMajority(this, majorityHash);
  }

  private enableLeaderMode(): void {
    const { ConsensusIntegration } = require('./consensus-integration');
    ConsensusIntegration.enableLeaderMode(this);
  }

  private setupWebSocketServer(): void {
    if (!this.httpServer) return;

    this.wss = new WebSocket.Server({ server: this.httpServer });

    if (!this.wsKeepAliveTimer) {
      this.wsKeepAliveTimer = setInterval(() => {
        const now = Date.now();
        for (const [ws, meta] of this.wsConnections.entries()) {
          if (ws.readyState !== WebSocket.OPEN) continue;

          try {
            ws.ping();
          } catch {
          }

          const age = now - Number(meta.lastSeen || 0);
          if (age > 120000) {
            try {
              ws.terminate();
            } catch {
              try { ws.close(); } catch {}
            }
          }
        }
      }, 30000);
    }

    this.wss.on('connection', (ws: WebSocket, req) => {
      const clientIp = req.socket.remoteAddress;
      let clientOperatorId: string | null = null;
      let isApprovedOperator = false;
      
      this.wsConnections.set(ws, {
        type: 'gateway',
        connectedAt: Date.now(),
        lastSeen: Date.now(),
        ip: clientIp,
      });

      ws.on('pong', () => {
        const meta = this.wsConnections.get(ws);
        if (meta) meta.lastSeen = Date.now();
      });

      const sendSnapshot = async (type: 'sync_response' | 'registry_update' | 'sync_data', includeAccounts: boolean = false) => {
        const state = await this.canonicalStateBuilder.buildState();
        const networkId = this.computeNetworkId();

        const items: Record<string, any> = {};
        for (const [k, v] of state.items.entries()) items[k] = v;

        const settlements: Record<string, any> = {};
        for (const [k, v] of state.settlements.entries()) settlements[k] = v;

        const operators: Record<string, any> = {};
        for (const [k, v] of state.operators.entries()) operators[k] = v;

        const accounts: Record<string, any> = {};
        if (includeAccounts) {
          for (const [k, v] of state.accounts.entries()) {
            accounts[k] = {
              accountId: v.accountId,
              role: v.role,
              username: v.username,
              email: v.email,
              emailHash: v.emailHash,
              walletAddress: v.walletAddress,
              passwordHash: v.passwordHash,
              passwordKdf: v.passwordKdf,
              createdAt: v.createdAt,
              updatedAt: v.updatedAt,
              totp: v.totp,
            };
          }
        }

        const events = await this.canonicalEventStore.getAllEvents();

        ws.send(
          JSON.stringify({
            type,
            networkId,
            events: includeAccounts ? events : [],
            state: {
              sequenceNumber: state.lastEventSequence,
              lastEventHash: state.lastEventHash,
              timestamp: Date.now(),
              items,
              settlements,
              operators,
              accounts: includeAccounts ? accounts : {},
            },
          })
        );
      };

      ws.on('message', async (message: string) => {
        try {
          const meta = this.wsConnections.get(ws);
          if (meta) meta.lastSeen = Date.now();
          const data = JSON.parse(message.toString());
          
          // Subscribe to real-time consensus updates (for mempool visualizer)
          if (data.type === 'subscribe_consensus') {
            const meta2 = this.wsConnections.get(ws);
            if (meta2) {
              meta2.subscribedToConsensus = true;
              meta2.isUi = true;
            }
            
            // Send current consensus state
            if (this.consensusNode) {
              const consensusState = this.consensusNode.getState();
              const mempoolEvents = this.consensusNode.getMempoolEvents();
              
              ws.send(JSON.stringify({
                type: 'consensus_state',
                state: consensusState,
              }));
              
              ws.send(JSON.stringify({
                type: 'mempool_snapshot',
                events: mempoolEvents,
              }));
            }
            return;
          }

          // Handle consensus verification messages
          if (data.type === 'state_verification') {
            await this.handleStateVerification(ws, data);
            return;
          }
          
          if (data.type === 'verification_response') {
            await this.handleVerificationResponse(data);
            return;
          }
          
          if (data.type === 'sync_request') {
            const operatorId = String(data.operatorId || '').trim();
            const reqNetworkId = String((data as any).networkId || '').trim();
            const expectedNetworkId = this.computeNetworkId();
            
            if (operatorId) {
              clientOperatorId = operatorId;
              console.log(`[WebSocket] Operator ${operatorId} requesting sync from ${clientIp}`);

              if (!reqNetworkId || reqNetworkId !== expectedNetworkId) {
                ws.send(JSON.stringify({
                  type: 'error',
                  error: 'Network mismatch. This node is not part of the canonical Autho network.',
                  code: 'NETWORK_MISMATCH',
                }));
                ws.close();
                return;
              }
              
              const state = await this.canonicalStateBuilder.buildState();
              const operator = state.operators.get(operatorId);
              
              if (operator && operator.status === 'active') {
                isApprovedOperator = true;
                console.log(`[WebSocket] Approved operator ${operatorId} connected`);

                const meta2 = this.wsConnections.get(ws);
                if (meta2) {
                  meta2.type = 'operator';
                  meta2.operatorId = operatorId;
                }

                await sendSnapshot('sync_data', true);
              } else {
                console.log(`[WebSocket] Operator ${operatorId} not approved - status: ${operator?.status || 'not found'}`);
                ws.send(JSON.stringify({
                  type: 'error',
                  error: 'Operator not approved. Please apply for operator status in the main node dashboard.',
                  code: 'OPERATOR_NOT_APPROVED'
                }));
                ws.close();
              }
            } else {
              console.log(`[WebSocket] Gateway node connected from ${clientIp}`);
              await sendSnapshot('sync_response', false);
            }
          }

          // CONSENSUS MESSAGES - Route to consensus node
          if (data.type === 'mempool_event') {
            if (this.consensusNode && isApprovedOperator) {
              await this.consensusNode.handleIncomingEvent(data.payload, clientOperatorId || clientIp);
            }
            return;
          }

          if (data.type === 'checkpoint_proposal') {
            if (this.consensusNode && isApprovedOperator) {
              await this.consensusNode.handleMessage(data, clientOperatorId || clientIp);
            }
            return;
          }

          if (data.type === 'checkpoint_vote') {
            if (this.consensusNode && isApprovedOperator) {
              await this.consensusNode.handleMessage(data, clientOperatorId || clientIp);
            }
            return;
          }

          if (data.type === 'checkpoint_finalized') {
            if (this.consensusNode) {
              await this.consensusNode.handleMessage(data, clientOperatorId || clientIp);
            }
            return;
          }

          // Handle new_event messages (legacy - redirect to consensus)
          if (data.type === 'new_event') {
            console.log(`[WebSocket] Received new_event - routing to consensus mempool`);
            if (this.consensusNode && isApprovedOperator) {
              // Convert to mempool event format
              const eventData = (data as any).event;
              if (eventData) {
                const mempoolEvent: MempoolEvent = {
                  eventId: eventData.eventHash || createHash('sha256').update(JSON.stringify(eventData)).digest('hex').substring(0, 32),
                  type: eventData.payload?.type || eventData.type,
                  payload: eventData.payload || eventData,
                  timestamp: eventData.timestamp || Date.now(),
                  creatorId: (data as any).sourceOperatorId || clientOperatorId || '',
                  creatorSignature: '',
                  receivedAt: Date.now(),
                  receivedFrom: clientOperatorId || clientIp,
                  validationStatus: 'pending',
                };
                await this.consensusNode.handleIncomingEvent(mempoolEvent, clientOperatorId || clientIp);
              }
            }
            ws.send(JSON.stringify({
              type: 'new_event_ack',
              ok: true,
              message: 'Routed to consensus mempool',
            }));
            return;
          }

          if (data.type === 'append_event') {
            const requestId = String((data as any).requestId || '').trim();
            const payload = (data as any).payload;
            const signatures = Array.isArray((data as any).signatures) ? (data as any).signatures : [];
            const claimedOperatorId = String((data as any).operatorId || '').trim();

            const ack = (ok: boolean, extra?: Record<string, any>) => {
              try {
                ws.send(JSON.stringify({
                  type: 'append_event_ack',
                  requestId,
                  ok,
                  ...(extra || {}),
                }));
              } catch {
              }
            };

            if (!isApprovedOperator || !clientOperatorId) {
              ack(false, { error: 'Operator not approved' });
              return;
            }

            if (claimedOperatorId && claimedOperatorId !== clientOperatorId) {
              ack(false, { error: 'operatorId mismatch' });
              return;
            }

            if (!payload || typeof payload !== 'object' || typeof payload.type !== 'string') {
              ack(false, { error: 'Invalid payload' });
              return;
            }

            try {
              const event = await this.canonicalEventStore.appendEvent(payload as any, signatures as any);
              ack(true, { eventHash: event.eventHash, sequenceNumber: event.sequenceNumber });

              this.broadcastToGateways({
                type: 'registry_update',
                data: {
                  sequenceNumber: event.sequenceNumber,
                  lastEventHash: event.eventHash,
                },
                timestamp: Date.now(),
              });
            } catch (e: any) {
              ack(false, { error: e?.message || String(e) });
            }

            return;
          }
        } catch (error) {
          console.error('[WebSocket] Error processing message:', error);
        }
      });

      ws.on('close', () => {
        if (clientOperatorId) {
          console.log(`[WebSocket] Operator ${clientOperatorId} disconnected from ${clientIp}`);
        } else {
          console.log(`[WebSocket] Gateway node disconnected from ${clientIp}`);
        }
        this.wsConnections.delete(ws);
      });

      ws.on('error', (error) => {
        console.error('[WebSocket] Connection error:', error);
        this.wsConnections.delete(ws);
      });
    });

    console.log(`[WebSocket] Server ready for gateway and operator connections on port ${this.port}`);
  }

  private broadcastToGateways(event: any): void {
    (async () => {
      const state = await this.canonicalStateBuilder.buildState();

      const items: Record<string, any> = {};
      for (const [k, v] of state.items.entries()) items[k] = v;

      const settlements: Record<string, any> = {};
      for (const [k, v] of state.settlements.entries()) settlements[k] = v;

      const operators: Record<string, any> = {};
      for (const [k, v] of state.operators.entries()) operators[k] = v;

      const accounts: Record<string, any> = {};
      for (const [k, v] of state.accounts.entries()) {
        accounts[k] = {
          accountId: v.accountId,
          role: v.role,
          username: v.username,
          email: v.email,
          walletAddress: v.walletAddress,
          createdAt: v.createdAt,
          updatedAt: v.updatedAt,
          totp: v.totp ? { enabled: Boolean(v.totp.enabled) } : undefined,
        };
      }

      const message = JSON.stringify({
        type: 'registry_update',
        data: {
          sequenceNumber: state.lastEventSequence,
          lastEventHash: state.lastEventHash,
          timestamp: Date.now(),
          items,
          settlements,
          operators,
          accounts,
        },
        timestamp: Date.now(),
      });

      for (const [client] of this.wsConnections.entries()) {
        if (client.readyState === WebSocket.OPEN) {
          client.send(message);
        }
      }
    })().catch((e) => console.error('[WebSocket] Broadcast snapshot error:', e));
  }

  // ==================== Image Tombstone API Endpoints ====================

  private setupImageTombstoneEndpoints(): void {
    // Get all tombstone proposals (operator only)
    this.app.get('/api/admin/tombstone-proposals', async (req: Request, res: Response) => {
      try {
        const operatorId = String(process.env.OPERATOR_ID || '').trim();
        if (!operatorId) {
          res.status(403).json({ success: false, error: 'Operator access required' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const proposals = Array.from(state.imageTombstoneProposals.values()).map((p: any) => ({
          proposalId: p.proposalId,
          itemId: p.itemId,
          imageHash: p.imageHash,
          proposerOperatorId: p.proposerOperatorId,
          reason: p.reason,
          details: p.details,
          createdAt: p.createdAt,
          voteCount: p.votes?.size || 0,
          finalized: p.finalized,
        }));

        res.json({ success: true, proposals });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Propose image tombstone (operator only)
    this.app.post('/api/admin/tombstone-proposals', async (req: Request, res: Response) => {
      try {
        const operatorId = String(process.env.OPERATOR_ID || '').trim();
        if (!operatorId) {
          res.status(403).json({ success: false, error: 'Operator access required' });
          return;
        }

        const { itemId, imageHash, reason, details } = req.body || {};
        if (!itemId || !imageHash || !reason) {
          res.status(400).json({ success: false, error: 'itemId, imageHash, and reason are required' });
          return;
        }

        // Verify item exists and has this image
        const state = await this.canonicalStateBuilder.buildState();
        const item = state.items.get(itemId);
        if (!item) {
          res.status(404).json({ success: false, error: 'Item not found' });
          return;
        }

        // Check if image exists in item metadata or authentications
        let imageFound = false;
        if (item.metadata?.images) {
          imageFound = item.metadata.images.some((img: any) => 
            String(img?.sha256Hex || '').toLowerCase() === imageHash.toLowerCase()
          );
        }
        if (!imageFound && item.authentications) {
          for (const auth of item.authentications) {
            if (auth.images?.some((img: any) => 
              String(img?.sha256Hex || '').toLowerCase() === imageHash.toLowerCase()
            )) {
              imageFound = true;
              break;
            }
          }
        }
        if (!imageFound) {
          res.status(400).json({ success: false, error: 'Image not found in item' });
          return;
        }

        // Check if already tombstoned
        if (state.tombstonedImages.has(imageHash.toLowerCase())) {
          res.status(400).json({ success: false, error: 'Image is already tombstoned' });
          return;
        }

        const now = Date.now();
        const proposalId = `tombstone_${itemId}_${imageHash.substring(0, 16)}_${now}`;
        const nonce = randomBytes(32).toString('hex');

        const signatures: QuorumSignature[] = [
          {
            operatorId,
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ITEM_IMAGE_TOMBSTONE_PROPOSED:${proposalId}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ITEM_IMAGE_TOMBSTONE_PROPOSED,
            timestamp: now,
            nonce,
            proposalId,
            itemId,
            imageHash: imageHash.toLowerCase(),
            proposerOperatorId: operatorId,
            reason,
            details,
          } as any,
          signatures
        );

        res.json({ success: true, proposalId });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Vote on tombstone proposal (operator only)
    this.app.post('/api/admin/tombstone-proposals/:proposalId/vote', async (req: Request, res: Response) => {
      try {
        const operatorId = String(process.env.OPERATOR_ID || '').trim();
        if (!operatorId) {
          res.status(403).json({ success: false, error: 'Operator access required' });
          return;
        }

        const proposalId = String(req.params.proposalId || '').trim();
        const vote = String(req.body?.vote || '').trim();

        if (!proposalId || (vote !== 'approve' && vote !== 'reject')) {
          res.status(400).json({ success: false, error: 'proposalId and vote (approve/reject) are required' });
          return;
        }

        const state = await this.canonicalStateBuilder.buildState();
        const proposal = state.imageTombstoneProposals.get(proposalId);
        if (!proposal) {
          res.status(404).json({ success: false, error: 'Proposal not found' });
          return;
        }

        if (proposal.finalized) {
          res.status(400).json({ success: false, error: 'Proposal already finalized' });
          return;
        }

        // Check if already voted
        if (proposal.votes.has(operatorId)) {
          res.status(400).json({ success: false, error: 'Already voted on this proposal' });
          return;
        }

        const now = Date.now();
        const nonce = randomBytes(32).toString('hex');

        const signatures: QuorumSignature[] = [
          {
            operatorId,
            publicKey: this.node.getOperatorInfo().publicKey,
            signature: createHash('sha256')
              .update(`ITEM_IMAGE_TOMBSTONE_VOTED:${proposalId}:${vote}:${now}`)
              .digest('hex'),
          },
        ];

        await this.canonicalEventStore.appendEvent(
          {
            type: EventType.ITEM_IMAGE_TOMBSTONE_VOTED,
            timestamp: now,
            nonce,
            proposalId,
            operatorId,
            vote,
          } as any,
          signatures
        );

        // Check if we have enough votes to finalize (2/3 majority)
        const activeOperators = Array.from(state.operators.values()).filter((op: any) => op.status === 'active');
        const requiredVotes = Math.ceil((activeOperators.length * 2) / 3);
        
        // Re-fetch state to get updated vote count
        const updatedState = await this.canonicalStateBuilder.buildState();
        const updatedProposal = updatedState.imageTombstoneProposals.get(proposalId);
        
        if (updatedProposal) {
          const approveVotes = Array.from(updatedProposal.votes.values()).filter((v: any) => v.vote === 'approve').length;
          
          if (approveVotes >= requiredVotes) {
            // Finalize the tombstone
            const finalizeNonce = randomBytes(32).toString('hex');
            const approvedBy = Array.from(updatedProposal.votes.entries())
              .filter(([_, v]: [string, any]) => v.vote === 'approve')
              .map(([opId, _]: [string, any]) => opId);

            const finalizeSignatures: QuorumSignature[] = [
              {
                operatorId,
                publicKey: this.node.getOperatorInfo().publicKey,
                signature: createHash('sha256')
                  .update(`ITEM_IMAGE_TOMBSTONED:${proposalId}:${now}`)
                  .digest('hex'),
              },
            ];

            await this.canonicalEventStore.appendEvent(
              {
                type: EventType.ITEM_IMAGE_TOMBSTONED,
                timestamp: now,
                nonce: finalizeNonce,
                proposalId,
                itemId: updatedProposal.itemId,
                imageHash: updatedProposal.imageHash,
                reason: updatedProposal.reason,
                approvedBy,
              } as any,
              finalizeSignatures
            );

            res.json({ success: true, vote, finalized: true, approveVotes, requiredVotes });
            return;
          }
        }

        res.json({ success: true, vote, finalized: false });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Get tombstoned images list
    this.app.get('/api/admin/tombstoned-images', async (req: Request, res: Response) => {
      try {
        const state = await this.canonicalStateBuilder.buildState();
        const tombstonedImages = Array.from(state.tombstonedImages);
        res.json({ success: true, tombstonedImages, count: tombstonedImages.length });
      } catch (error: any) {
        res.status(500).json({ success: false, error: error.message });
      }
    });
  }

  async start(): Promise<void> {
    this.setupImageTombstoneEndpoints();
    await this.ensureMainNodeOperatorAccount();

    return new Promise((resolve) => {
      this.httpServer = http.createServer(this.app);

      this.httpServer.listen(this.port, () => {
        console.log(`[Operator API] Server listening on port ${this.port}`);

        this.setupWebSocketServer();
        this.startConsensusVerification();
        this.startCheckpointScheduler();

        if (!this.settlementExpiryTimer) {
          this.settlementExpiryTimer = setInterval(() => {
            this.sweepExpiredSettlements().catch(() => {});
            this.sweepExpiredConsignments().catch(() => {});
          }, 60 * 1000);
        }

        if (!this.settlementReconcileTimer) {
          this.settlementReconcileTimer = setInterval(() => {
            this.reconcilePaidSettlements().catch(() => {});
            this.reconcilePaidConsignments().catch(() => {});
          }, 60 * 1000);
        }

        resolve();
      });
    });
  }

  private async ensureMainNodeOperatorAccount(): Promise<void> {
    const mainNodeAccountId = String(process.env.MAIN_NODE_ACCOUNT_ID || '').trim();
    if (!mainNodeAccountId) {
      return; // No main node configured
    }

    try {
      const state = await this.canonicalStateBuilder.buildState();
      const existingAccount = state.accounts.get(mainNodeAccountId);
      
      if (existingAccount) {
        console.log(`[Operator API] Main node operator account already exists: ${mainNodeAccountId.substring(0, 16)}...`);
        return;
      }

      // Create main node operator account
      const operatorBtcAddress = String(process.env.OPERATOR_BTC_ADDRESS || '').trim();
      if (!operatorBtcAddress) {
        console.warn(`[Operator API] ⚠️ MAIN_NODE_ACCOUNT_ID is set but OPERATOR_BTC_ADDRESS is not. Cannot auto-create main node operator account.`);
        return;
      }

      console.log(`[Operator API] Creating main node operator account...`);
      console.log(`  Account ID (public key): ${mainNodeAccountId.substring(0, 16)}...`);
      console.log(`  Bitcoin Address: ${operatorBtcAddress}`);

      const nonce = randomBytes(32).toString('hex');
      const signatures: QuorumSignature[] = [
        {
          operatorId: process.env.OPERATOR_ID || 'operator-1',
          publicKey: this.node.getOperatorInfo().publicKey,
          signature: createHash('sha256')
            .update(`ACCOUNT_CREATED:${mainNodeAccountId}:${Date.now()}`)
            .digest('hex'),
        },
      ];

      await this.canonicalEventStore.appendEvent(
        {
          type: EventType.ACCOUNT_CREATED,
          timestamp: Date.now(),
          nonce,
          accountId: mainNodeAccountId,
          role: 'operator',
          username: 'main-node-operator',
          email: `operator@${process.env.OPERATOR_ID || 'operator-1'}.local`,
          walletAddress: operatorBtcAddress,
        },
        signatures
      );

      console.log(`[Operator API] ✅ Main node operator account created successfully`);
    } catch (error: any) {
      console.error(`[Operator API] ❌ Failed to create main node operator account:`, error.message);
    }
  }
}
