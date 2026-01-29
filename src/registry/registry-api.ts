import { Request, Response } from 'express';
import { createHash } from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { ItemRegistry } from './item-registry';
import { StateBuilder } from '../event-store';
import { 
  ItemRegistrationRequest, 
  OwnershipTransferRequest, 
  AuthenticationRequest 
} from './registry-types';

/**
 * REGULATORY-COMPLIANT REGISTRY API
 * 
 * This API provides access to a NON-CUSTODIAL item registry.
 * It is NOT a token API, financial platform, or money transmitter.
 * 
 * Terminology:
 * - "register item" (not "mint token")
 * - "transfer ownership" (not "transfer token")
 * - "item record" (not "NFT" or "token")
 * - "ownership state" (not "balance")
 */
export class RegistryAPI {
  private registry: ItemRegistry;
  private canonicalStateBuilder?: StateBuilder;

  constructor(registry: ItemRegistry, canonicalStateBuilder?: StateBuilder) {
    this.registry = registry;
    this.canonicalStateBuilder = canonicalStateBuilder;
  }

  private getBitcoinNetwork(): 'mainnet' | 'testnet' {
    return process.env.BITCOIN_NETWORK === 'mainnet' ? 'mainnet' : 'testnet';
  }

  private getBitcoinJsNetwork(): bitcoin.Network {
    return this.getBitcoinNetwork() === 'mainnet' ? bitcoin.networks.bitcoin : bitcoin.networks.testnet;
  }

  private getChainProviderBases(): string[] {
    const network = this.getBitcoinNetwork();
    return network === 'mainnet'
      ? ['https://mempool.space/api', 'https://blockstream.info/api']
      : ['https://mempool.space/testnet/api', 'https://blockstream.info/testnet/api'];
  }

  private async fetchTxHex(txid: string): Promise<string> {
    const bases = this.getChainProviderBases();

    let lastErr: any;
    for (const apiBase of bases) {
      try {
        const resp = await fetch(`${apiBase}/tx/${txid}/hex`);
        const text = await resp.text();
        if (!resp.ok) {
          lastErr = { status: resp.status, text };
          continue;
        }
        return String(text || '').trim();
      } catch (e) {
        lastErr = e;
      }
    }

    const msg = lastErr?.status ? String(lastErr.text || 'Chain provider error') : 'All chain providers failed';
    throw new Error(`Failed to fetch tx hex: ${msg}`);
  }

  private async fetchTxJson(txid: string): Promise<any> {
    const bases = this.getChainProviderBases();

    let lastErr: any;
    for (const apiBase of bases) {
      try {
        const resp = await fetch(`${apiBase}/tx/${txid}`);
        const text = await resp.text();
        if (!resp.ok) {
          lastErr = { status: resp.status, text };
          continue;
        }
        return JSON.parse(String(text || '{}'));
      } catch (e) {
        lastErr = e;
      }
    }

    const msg = lastErr?.status ? String(lastErr.text || 'Chain provider error') : 'All chain providers failed';
    throw new Error(`Failed to fetch tx json: ${msg}`);
  }

  private async fetchTxStatus(txid: string): Promise<{ confirmed: boolean; confirmations: number; blockHeight?: number }> {
    const bases = this.getChainProviderBases();

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

        return { confirmed, confirmations, blockHeight: blockHeight || undefined };
      } catch (e) {
        lastErr = e;
      }
    }

    const msg = lastErr?.status ? String(lastErr.text || 'Chain provider error') : 'All chain providers failed';
    throw new Error(`Failed to fetch tx status: ${msg}`);
  }

  private getBondFailure(account: any, roleLabel: 'manufacturer' | 'authenticator'): null | {
    error: string;
    code: string;
    bond: { bondMinSats: number; bondMeetsMin: boolean; bondLastCheckedAt?: number; bondMaxAgeMs: number; isStale: boolean };
  } {
    const bondMinSats = Number(process.env.VERIFIER_BOND_MIN_SATS || 100000);
    const bondMaxAgeMs = Number(process.env.VERIFIER_BOND_MAX_AGE_MS || 0) || 24 * 60 * 60 * 1000;
    if (!(bondMinSats > 0)) return null;

    const meets = Boolean((account as any)?.bondMeetsMin);
    const last = Number((account as any)?.bondLastCheckedAt || 0);
    const stale = !last || (Date.now() - last) > bondMaxAgeMs;
    if (meets && !stale) return null;

    return {
      error: `${roleLabel === 'authenticator' ? 'Authenticator' : 'Manufacturer'} bond proof required. Run the bond check in your dashboard.`,
      code: 'BOND_PROOF_REQUIRED',
      bond: {
        bondMinSats,
        bondMeetsMin: meets,
        bondLastCheckedAt: last || undefined,
        bondMaxAgeMs,
        isStale: stale,
      },
    };
  }

  private enforceBondOrThrow(account: any, roleLabel: 'manufacturer' | 'authenticator'): void {
    const fail = this.getBondFailure(account, roleLabel);
    if (!fail) return;
    const err: any = new Error(fail.error);
    err.code = fail.code;
    err.bond = fail.bond;
    throw err;
  }

  private parseFeeTx(txHex: string, expectedCommitmentHex: string): { feePaidSats: number; hasFeeOutput: boolean; hasCommitment: boolean } {
    const tx = bitcoin.Transaction.fromHex(txHex);
    const net = this.getBitcoinJsNetwork();

    const feeAddress = this.getBitcoinNetwork() === 'mainnet'
      ? '1FMcxZRUWVDbKy7DxAosW7sM5PUntAkJ9U'
      : String(process.env.FEE_ADDRESS_TESTNET || '').trim();

    const expectedCommitment = String(expectedCommitmentHex || '').trim().toLowerCase();
    const expectedCommitmentBuf = Buffer.from(expectedCommitment, 'hex');

    const feeScript = feeAddress ? bitcoin.address.toOutputScript(feeAddress, net) : undefined;

    let feePaidSats = 0;
    let hasFeeOutput = false;
    let hasCommitment = false;

    for (const out of tx.outs) {
      if (feeScript && Buffer.isBuffer(out.script) && out.script.equals(feeScript)) {
        hasFeeOutput = true;
        feePaidSats += Number(out.value || 0);
      }

      const chunks = bitcoin.script.decompile(out.script);
      if (!chunks || chunks.length < 2) continue;
      if (chunks[0] !== bitcoin.opcodes.OP_RETURN) continue;

      for (let i = 1; i < chunks.length; i++) {
        const c = chunks[i];
        if (!Buffer.isBuffer(c)) continue;
        if (c.equals(expectedCommitmentBuf)) {
          hasCommitment = true;
          break;
        }
      }
    }

    return { feePaidSats, hasFeeOutput, hasCommitment };
  }

  public async verifyVerificationPaymentOrThrow(params: {
    paymentTxid: string;
    commitmentHex: string;
    requiredConfirmations: number;
    authenticatorAddress: string;
    serviceFeeSats: number;
    platformFeeSats: number;
  }): Promise<{ blockHeight?: number; confirmations: number; servicePaidSats: number; platformPaidSats: number }> {
    const txid = String(params.paymentTxid || '').trim().toLowerCase();
    const commitmentHex = String(params.commitmentHex || '').trim().toLowerCase();
    const authenticatorAddress = String(params.authenticatorAddress || '').trim();
    const serviceFeeSats = Number(params.serviceFeeSats || 0);
    const platformFeeSats = Number(params.platformFeeSats || 0);

    if (!/^[0-9a-f]{64}$/.test(txid)) {
      throw new Error('Missing or invalid paymentTxid');
    }
    if (!/^[0-9a-f]+$/.test(commitmentHex) || commitmentHex.length < 2 || commitmentHex.length > 160 || (commitmentHex.length % 2 !== 0)) {
      throw new Error('Missing or invalid commitmentHex');
    }
    if (!authenticatorAddress) {
      throw new Error('Missing authenticatorAddress');
    }
    if (!Number.isFinite(serviceFeeSats) || serviceFeeSats <= 0) {
      throw new Error('Invalid serviceFeeSats');
    }
    if (!Number.isFinite(platformFeeSats) || platformFeeSats < 0) {
      throw new Error('Invalid platformFeeSats');
    }

    const status = await this.fetchTxStatus(txid);
    if (!status.confirmed || status.confirmations < params.requiredConfirmations) {
      const err: any = new Error('Payment transaction is not sufficiently confirmed');
      err.code = 'PAYMENT_TX_NOT_CONFIRMED';
      err.confirmations = status.confirmations;
      err.requiredConfirmations = params.requiredConfirmations;
      err.blockHeight = status.blockHeight;
      throw err;
    }

    const txHex = await this.fetchTxHex(txid);
    const tx = bitcoin.Transaction.fromHex(txHex);
    const net = this.getBitcoinJsNetwork();

    const feeAddress = this.getBitcoinNetwork() === 'mainnet'
      ? '1FMcxZRUWVDbKy7DxAosW7sM5PUntAkJ9U'
      : String(process.env.FEE_ADDRESS_TESTNET || '').trim();

    const expectedCommitmentBuf = Buffer.from(commitmentHex, 'hex');

    let servicePaidSats = 0;
    let platformPaidSats = 0;
    let hasCommitment = false;

    for (const out of tx.outs) {
      try {
        const addr = bitcoin.address.fromOutputScript(out.script, net);
        if (addr === authenticatorAddress) {
          servicePaidSats += Number(out.value || 0);
        }
        if (feeAddress && addr === feeAddress) {
          platformPaidSats += Number(out.value || 0);
        }
      } catch {
        // ignore non-standard scripts
      }

      const chunks = bitcoin.script.decompile(out.script);
      if (!chunks || chunks.length < 2) continue;
      if (chunks[0] !== bitcoin.opcodes.OP_RETURN) continue;
      for (let i = 1; i < chunks.length; i++) {
        const c = chunks[i];
        if (!Buffer.isBuffer(c)) continue;
        if (c.equals(expectedCommitmentBuf)) {
          hasCommitment = true;
          break;
        }
      }
    }

    if (!hasCommitment) {
      throw new Error('Payment transaction does not include the expected OP_RETURN commitment');
    }
    if (servicePaidSats < serviceFeeSats) {
      throw new Error('Payment transaction does not pay the authenticator the required amount');
    }
    if (platformFeeSats > 0 && platformPaidSats < platformFeeSats) {
      throw new Error('Payment transaction does not pay the platform fee address the required amount');
    }

    return {
      blockHeight: status.blockHeight,
      confirmations: status.confirmations,
      servicePaidSats,
      platformPaidSats,
    };
  }

  public async recordAuthenticationForVerificationJob(params: {
    itemId: string;
    authenticatorId: string;
    serialNumber: string;
    isAuthentic: boolean;
    confidence: 'high' | 'medium' | 'low';
    notes?: string;
    expiresAt?: number;
    images?: any[];
    authenticatorSignature: string;
    paymentTxid: string;
    commitmentHex: string;
    paymentBlockHeight?: number;
  }): Promise<{ itemId: string }>{
    const req: any = {
      itemId: String(params.itemId || '').trim(),
      authenticatorId: String(params.authenticatorId || '').trim(),
      serialNumber: String(params.serialNumber || '').trim(),
      isAuthentic: Boolean(params.isAuthentic),
      confidence: params.confidence,
      notes: params.notes,
      expiresAt: params.expiresAt,
      images: params.images,
      authenticatorSignature: String(params.authenticatorSignature || '').trim(),
      feeTxid: String(params.paymentTxid || '').trim(),
      feeCommitmentHex: String(params.commitmentHex || '').trim(),
      feeBlockHeight: params.paymentBlockHeight,
    };

    const imgCheck = this.validateLedgerImages(req.images);
    if (!imgCheck.ok) {
      throw new Error(imgCheck.error || 'Invalid images');
    }

    // ANTI-FRAUD: Check if authenticator images have been used before
    // Authenticators must provide unique photos of the physical item they're examining
    // (Manufacturers are allowed to reuse glamour shots for mass production)
    if (req.images && req.images.length > 0 && this.canonicalStateBuilder) {
      const imageHashes = req.images.map((img: any) => String(img?.sha256Hex || '').trim().toLowerCase()).filter(Boolean);
      const reusedImages = await this.checkAuthenticatorImageReuse(imageHashes, req.itemId);
      if (reusedImages.length > 0) {
        throw new Error(`Authenticator images must be unique. ${reusedImages.length} image(s) have been used in previous authentications. Please provide fresh photos of this specific item.`);
      }
    }

    await this.registry.authenticateItem(req);
    return { itemId: req.itemId };
  }

  private async verifyFeeAnchoringOrThrow(params: {
    feeTxid?: string;
    feeCommitmentHex?: string;
    requiredConfirmations: number;
    allowSoftConfirm?: boolean;
  }): Promise<{ blockHeight?: number; confirmations: number; feePaidSats: number }> {
    const txid = String(params.feeTxid || '').trim().toLowerCase();
    const commitmentHex = String(params.feeCommitmentHex || '').trim().toLowerCase();

    if (!/^[0-9a-f]{64}$/.test(txid)) {
      throw new Error('Missing or invalid feeTxid');
    }
    if (!/^[0-9a-f]+$/.test(commitmentHex) || commitmentHex.length < 2 || commitmentHex.length > 160 || (commitmentHex.length % 2 !== 0)) {
      throw new Error('Missing or invalid feeCommitmentHex');
    }

    const allowSoftConfirm = Boolean(params.allowSoftConfirm);
    const status = await this.fetchTxStatus(txid);

    const txHex = await this.fetchTxHex(txid);
    const parsed = this.parseFeeTx(txHex, commitmentHex);

    if (!parsed.hasFeeOutput) {
      throw new Error('Fee transaction does not pay the platform fee address');
    }
    if (!parsed.hasCommitment) {
      throw new Error('Fee transaction does not include the expected OP_RETURN commitment');
    }

    const envMinFeeSats = process.env.MINT_AUTH_FEE_MIN_SATS;
    const minFeeSats = envMinFeeSats === undefined || String(envMinFeeSats).trim() === ''
      ? 1000
      : Number(envMinFeeSats);
    if (Number.isFinite(minFeeSats) && minFeeSats > 0 && parsed.feePaidSats < minFeeSats) {
      throw new Error(`Fee transaction amount is below minimum required sats (${minFeeSats})`);
    }

    if (status.confirmed && status.confirmations >= params.requiredConfirmations) {
      return { blockHeight: status.blockHeight, confirmations: status.confirmations, feePaidSats: parsed.feePaidSats };
    }

    const softEnabledEnv = String(process.env.FEE_TX_SOFT_CONFIRM_ENABLED || '').trim().toLowerCase();
    const softEnabled = softEnabledEnv === '' ? true : (softEnabledEnv === '1' || softEnabledEnv === 'true' || softEnabledEnv === 'yes');
    if (allowSoftConfirm && softEnabled) {
      const maxSats = Math.floor(Number(process.env.FEE_TX_SOFT_CONFIRM_MAX_SATS || 0) || 100000);
      const minSatVb = Number(process.env.FEE_TX_SOFT_CONFIRM_MIN_SATVB || 0) || 0.6;
      if (Number.isFinite(maxSats) && maxSats > 0 && parsed.feePaidSats > maxSats) {
        const err: any = new Error('Fee transaction is not sufficiently confirmed');
        err.code = 'FEE_TX_NOT_CONFIRMED';
        err.confirmations = status.confirmations;
        err.requiredConfirmations = params.requiredConfirmations;
        err.blockHeight = status.blockHeight;
        throw err;
      }

      const tx = bitcoin.Transaction.fromHex(txHex);
      const rbf = Array.isArray((tx as any).ins)
        ? (tx as any).ins.some((i: any) => Number(i?.sequence) < 0xfffffffe)
        : false;
      if (!rbf) {
        const txJson = await this.fetchTxJson(txid);
        const feeSats = Number(txJson?.fee);
        const vsize = Number(txJson?.vsize) || Number(txJson?.weight ? Math.ceil(Number(txJson.weight) / 4) : 0) || Number(tx.virtualSize());
        const feeRate = (Number.isFinite(feeSats) && feeSats > 0 && Number.isFinite(vsize) && vsize > 0)
          ? (feeSats / vsize)
          : 0;

        if (Number.isFinite(feeRate) && feeRate >= minSatVb) {
          return {
            blockHeight: status.confirmed ? status.blockHeight : undefined,
            confirmations: status.confirmed ? status.confirmations : 0,
            feePaidSats: parsed.feePaidSats,
          };
        }
      }
    }

    const err: any = new Error('Fee transaction is not sufficiently confirmed');
    err.code = 'FEE_TX_NOT_CONFIRMED';
    err.confirmations = status.confirmations;
    err.requiredConfirmations = params.requiredConfirmations;
    err.blockHeight = status.blockHeight;
    throw err;
  }

  /**
   * Check if any of the provided image hashes have been used in previous authentications
   * This prevents authenticators from reusing photos across different items
   */
  private async checkAuthenticatorImageReuse(imageHashes: string[], currentItemId: string): Promise<string[]> {
    if (!this.canonicalStateBuilder || imageHashes.length === 0) return [];

    const state = await this.canonicalStateBuilder.buildState();
    const reusedHashes: string[] = [];

    // Check all items for authentication images that match
    for (const [itemId, item] of state.items.entries()) {
      if (itemId === currentItemId) continue; // Skip the current item being authenticated

      const authentications = (item as any).authentications;
      if (!Array.isArray(authentications)) continue;

      for (const auth of authentications) {
        const authImages = auth?.images;
        if (!Array.isArray(authImages)) continue;

        for (const img of authImages) {
          const hash = String(img?.sha256Hex || '').trim().toLowerCase();
          if (hash && imageHashes.includes(hash) && !reusedHashes.includes(hash)) {
            reusedHashes.push(hash);
          }
        }
      }
    }

    return reusedHashes;
  }

  private validateLedgerImages(images: any): { ok: boolean; error?: string } {
    if (images === undefined || images === null) return { ok: true };
    if (!Array.isArray(images)) return { ok: false, error: 'images must be an array' };

    const MAX_IMAGES = 3;
    const MAX_IMAGE_BYTES = 80_000;
    const allowed = new Set(['image/webp', 'image/jpeg', 'image/png']);

    if (images.length > MAX_IMAGES) return { ok: false, error: `Too many images (max ${MAX_IMAGES})` };

    for (let i = 0; i < images.length; i++) {
      const img = images[i];
      const mime = String(img?.mime || '').trim();
      const dataB64 = String(img?.dataB64 || '').trim();
      const sha256Hex = String(img?.sha256Hex || '').trim().toLowerCase();
      const w = Number(img?.w);
      const h = Number(img?.h);

      if (!allowed.has(mime)) return { ok: false, error: `Unsupported image mime: ${mime || '(missing)'}` };
      if (!dataB64) return { ok: false, error: 'Image data missing' };
      if (!/^[0-9a-f]{64}$/.test(sha256Hex)) return { ok: false, error: 'Invalid image sha256Hex' };
      if (!Number.isFinite(w) || !Number.isFinite(h) || w <= 0 || h <= 0) return { ok: false, error: 'Invalid image dimensions' };

      let bytes: Buffer;
      try {
        bytes = Buffer.from(dataB64, 'base64');
      } catch {
        return { ok: false, error: 'Invalid base64 image data' };
      }

      if (!bytes || bytes.length === 0) return { ok: false, error: 'Empty image data' };
      if (bytes.length > MAX_IMAGE_BYTES) return { ok: false, error: `Image too large (max ${MAX_IMAGE_BYTES} bytes)` };

      const digest = createHash('sha256').update(bytes).digest('hex');
      if (digest !== sha256Hex) return { ok: false, error: 'Image sha256 does not match data' };
    }

    return { ok: true };
  }

  private async resolveAccountDisplayName(accountId: string): Promise<string> {
    const id = String(accountId || '').trim();
    if (!id || !this.canonicalStateBuilder) return id || 'Unknown';
    try {
      const state = await this.canonicalStateBuilder.buildState();
      const account = state.accounts.get(id);

      let bestFinalizedAt = -1;
      let companyName: string | undefined;
      for (const app of state.roleApplications.values()) {
        if (String((app as any)?.accountId || '') !== id) continue;
        const finalized = (app as any)?.finalized;
        if (!finalized || finalized.decision !== 'approve') continue;
        const n = String((app as any)?.companyName || '').trim();
        if (!n) continue;
        const t = Number(finalized.finalizedAt || 0);
        if (t >= bestFinalizedAt) {
          bestFinalizedAt = t;
          companyName = n;
        }
      }

      const username = String((account as any)?.username || '').trim();
      return companyName || username || id || 'Unknown';
    } catch {
      return id || 'Unknown';
    }
  }

  public async registerItemAsIssuer(params: {
    requestBody: Partial<ItemRegistrationRequest>;
    issuerRole: 'manufacturer' | 'authenticator' | 'user';
    issuerAccountId: string;
    issuerWalletAddress: string;
  }): Promise<{ itemId: string; status: string; currentOwner: string; registeredAt: number }> {
    const request = (params.requestBody || {}) as any as ItemRegistrationRequest;

    request.manufacturerId = String(params.issuerAccountId || '').trim();
    request.issuerRole = params.issuerRole;
    request.issuerAccountId = String(params.issuerAccountId || '').trim();
    request.initialOwner = String(params.issuerWalletAddress || '').trim();

    if (!request.serialNumber || !request.metadata) {
      throw new Error('Missing required fields: serialNumber, metadata');
    }
    if (!request.metadata.itemType || !request.metadata.description) {
      throw new Error('Metadata must include itemType and description');
    }

    const imgCheck = this.validateLedgerImages((request.metadata as any)?.images);
    if (!imgCheck.ok) {
      throw new Error(imgCheck.error || 'Invalid images');
    }

    if (!request.manufacturerSignature) {
      throw new Error('Missing required field: manufacturerSignature');
    }

    if (!this.canonicalStateBuilder) {
      throw new Error('Canonical registry unavailable');
    }

    const state = await this.canonicalStateBuilder.buildState();
    const accountId = String(params.issuerAccountId || '').trim();
    const account: any = state.accounts.get(accountId);
    if (!account) {
      throw new Error('Issuer account not found in canonical registry');
    }

    const bondMinSats = Number(process.env.VERIFIER_BOND_MIN_SATS || 100000);
    const bondMaxAgeMs = Number(process.env.VERIFIER_BOND_MAX_AGE_MS || 0) || 24 * 60 * 60 * 1000;

    const role = String(account.role || '').trim();
    if (params.issuerRole === 'manufacturer') {
      if (role !== 'manufacturer') throw new Error('Account is not an approved manufacturer');
      if (String(account.verifierStatus || 'active') === 'revoked') throw new Error('Manufacturer is revoked and cannot register items');
      this.enforceBondOrThrow(account, 'manufacturer');
    } else if (params.issuerRole === 'authenticator') {
      if (role !== 'authenticator') throw new Error('Account is not an approved authenticator');
      if (String(account.verifierStatus || 'active') === 'revoked') throw new Error('Authenticator is revoked and cannot register items');
      this.enforceBondOrThrow(account, 'authenticator');
    }

    try {
      const proof = await this.verifyFeeAnchoringOrThrow({
        feeTxid: request.feeTxid,
        feeCommitmentHex: request.feeCommitmentHex,
        requiredConfirmations: 6,
        allowSoftConfirm: true,
      });
      request.feeBlockHeight = proof.blockHeight;
    } catch (e: any) {
      if (String(e?.code || '') === 'FEE_TX_NOT_CONFIRMED') {
        const err: any = new Error('Fee transaction pending confirmations');
        err.code = 'FEE_TX_NOT_CONFIRMED';
        err.confirmations = Number(e?.confirmations || 0);
        err.requiredConfirmations = Number(e?.requiredConfirmations || 6);
        err.blockHeight = e?.blockHeight;
        throw err;
      }
      throw e;
    }

    const itemRecord = await this.registry.registerItem(request);
    return {
      itemId: itemRecord.itemId,
      status: itemRecord.status,
      currentOwner: itemRecord.currentOwner,
      registeredAt: itemRecord.registeredAt,
    };
  }

  /**
   * GET /api/registry/items
   * List all items in the registry.
   */
  async getAllItems(req: Request, res: Response): Promise<void> {
    try {
      let items: any[] = [];

      // Try canonical state first
      if (this.canonicalStateBuilder) {
        try {
          const state = await this.canonicalStateBuilder.buildState();
          items = Array.from(state.items.values()).map((item: any) => ({
            itemId: item.itemId,
            status: 'active',
            manufacturerId: item.manufacturerId,
            currentOwner: item.currentOwner,
            registeredAt: item.registeredAt,
            metadata: item.metadata
          }));
        } catch (e) {
          console.error('[Registry API] Failed to get all items from canonical state:', e);
        }
      }

      // Fallback to in-memory registry
      if (items.length === 0) {
        items = this.registry.getAllItems();
      }

      res.json({
        success: true,
        itemCount: items.length,
        items
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * POST /api/registry/item
   * Manufacturer registers a newly manufactured physical item.
   * 
   * CRITICAL: Can only be called when physical item exists.
   */
  async registerItem(req: Request, res: Response): Promise<void> {
    try {
      const request: ItemRegistrationRequest = req.body;

      if (!request.manufacturerId || !request.serialNumber || !request.metadata) {
        res.status(400).json({
          success: false,
          error: 'Missing required fields: manufacturerId, serialNumber, metadata'
        });
        return;
      }

      if (!request.metadata.itemType || !request.metadata.description) {
        res.status(400).json({
          success: false,
          error: 'Metadata must include itemType and description'
        });
        return;
      }

      const imgCheck = this.validateLedgerImages((request.metadata as any)?.images);
      if (!imgCheck.ok) {
        res.status(400).json({ success: false, error: imgCheck.error || 'Invalid images' });
        return;
      }

      request.issuerRole = 'manufacturer';
      request.issuerAccountId = String(request.manufacturerId || '').trim();

      // Canonical verifier enforcement: manufacturer must be an approved, non-revoked verifier.
      if (this.canonicalStateBuilder) {
        try {
          const state = await this.canonicalStateBuilder.buildState();
          const manufacturerId = String(request.manufacturerId || '').trim();
          const account: any = state.accounts.get(manufacturerId);
          if (!account) {
            res.status(403).json({ success: false, error: 'Manufacturer account not found in canonical registry' });
            return;
          }
          if (String(account.role) !== 'manufacturer') {
            res.status(403).json({ success: false, error: 'Account is not an approved manufacturer' });
            return;
          }
          if (String(account.verifierStatus || 'active') === 'revoked') {
            res.status(403).json({ success: false, error: 'Manufacturer is revoked and cannot register items' });
            return;
          }

          const fail = this.getBondFailure(account, 'manufacturer');
          if (fail) {
            res.status(403).json({ success: false, error: fail.error, code: fail.code, bond: fail.bond });
            return;
          }
        } catch (e) {
          console.error('[Registry API] Failed to enforce manufacturer status:', e);
        }
      }

      try {
        const proof = await this.verifyFeeAnchoringOrThrow({
          feeTxid: request.feeTxid,
          feeCommitmentHex: request.feeCommitmentHex,
          requiredConfirmations: 6,
          allowSoftConfirm: true,
        });
        request.feeBlockHeight = proof.blockHeight;
      } catch (e: any) {
        if (String(e?.code || '') === 'FEE_TX_NOT_CONFIRMED') {
          res.status(409).json({
            success: false,
            error: 'Fee transaction pending confirmations',
            feeTxid: request.feeTxid,
            confirmations: Number(e?.confirmations || 0),
            requiredConfirmations: Number(e?.requiredConfirmations || 6),
            blockHeight: e?.blockHeight,
          });
          return;
        }
        res.status(402).json({ success: false, error: e?.message || 'Fee transaction verification failed' });
        return;
      }

      const itemRecord = await this.registry.registerItem(request);

      res.json({
        success: true,
        itemRecord: {
          itemId: itemRecord.itemId,
          status: itemRecord.status,
          currentOwner: itemRecord.currentOwner,
          registeredAt: itemRecord.registeredAt
        },
        message: 'Physical item successfully registered in registry'
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * POST /api/registry/transfer
   * Transfer ownership of physical item.
   * 
   * Requires verification of peer-to-peer Bitcoin payment (non-custodial).
   */
  async transferOwnership(req: Request, res: Response): Promise<void> {
    try {
      const request: OwnershipTransferRequest = req.body;

      if (!request.itemId || !request.currentOwner || !request.newOwner) {
        res.status(400).json({
          success: false,
          error: 'Missing required fields: itemId, currentOwner, newOwner'
        });
        return;
      }

      if (!request.paymentTxHash) {
        res.status(400).json({
          success: false,
          error: 'Payment transaction hash required for ownership transfer'
        });
        return;
      }

      // Check if item is locked by a pending settlement
      if (this.canonicalStateBuilder) {
        try {
          const state = await this.canonicalStateBuilder.buildState();
          const allSettlements = Array.from(state.settlements.values());
          const pendingSettlement = allSettlements.find((s: any) => 
            String(s.itemId) === String(request.itemId) && 
            s.status === 'initiated' // Item is locked
          );

          if (pendingSettlement) {
            res.status(400).json({
              success: false,
              error: 'Item is locked by a pending offer. Cannot transfer ownership until offer is completed or cancelled.'
            });
            return;
          }
        } catch (e) {
          console.error('[Registry] Failed to check settlement lock:', e);
        }
      }

      const itemRecord = await this.registry.transferOwnership(request);

      res.json({
        success: true,
        itemRecord: {
          itemId: itemRecord.itemId,
          previousOwner: request.currentOwner,
          newOwner: itemRecord.currentOwner,
          transferredAt: Date.now()
        },
        message: 'Ownership successfully transferred'
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * POST /api/registry/authenticate
   * Third-party authenticator verifies physical item.
   * 
   * This is informational only and does not affect ownership.
   */
  async authenticateItem(req: Request, res: Response): Promise<void> {
    try {
      const request: AuthenticationRequest = req.body;

      if (!request.itemId || !request.authenticatorId || !request.serialNumber) {
        res.status(400).json({
          success: false,
          error: 'Missing required fields: itemId, authenticatorId, serialNumber'
        });
        return;
      }

      const imgCheck = this.validateLedgerImages((request as any)?.images);
      if (!imgCheck.ok) {
        res.status(400).json({ success: false, error: imgCheck.error || 'Invalid images' });
        return;
      }

      // Canonical verifier enforcement: authenticator must be an approved, non-revoked verifier.
      if (this.canonicalStateBuilder) {
        try {
          const state = await this.canonicalStateBuilder.buildState();
          const authenticatorId = String(request.authenticatorId || '').trim();
          const account: any = state.accounts.get(authenticatorId);
          if (!account) {
            res.status(403).json({ success: false, error: 'Authenticator account not found in canonical registry' });
            return;
          }
          if (String(account.role) !== 'authenticator') {
            res.status(403).json({ success: false, error: 'Account is not an approved authenticator' });
            return;
          }
          if (String(account.verifierStatus || 'active') === 'revoked') {
            res.status(403).json({ success: false, error: 'Authenticator is revoked and cannot authenticate items' });
            return;
          }

          const fail = this.getBondFailure(account, 'authenticator');
          if (fail) {
            res.status(403).json({ success: false, error: fail.error, code: fail.code, bond: fail.bond });
            return;
          }

          const item = state.items.get(String(request.itemId || '').trim());
          const issuerRole = String((item as any)?.issuerRole || '').trim();
          if (issuerRole === 'user') {
            res.status(400).json({
              success: false,
              error: 'User-issued items require an owner-requested verification job. Use /api/verification/requests.',
            });
            return;
          }
        } catch (e) {
          console.error('[Registry API] Failed to enforce authenticator status:', e);
        }
      }

      try {
        const proof = await this.verifyFeeAnchoringOrThrow({
          feeTxid: request.feeTxid,
          feeCommitmentHex: request.feeCommitmentHex,
          requiredConfirmations: 6,
          allowSoftConfirm: true,
        });
        request.feeBlockHeight = proof.blockHeight;
      } catch (e: any) {
        if (String(e?.code || '') === 'FEE_TX_NOT_CONFIRMED') {
          res.status(409).json({
            success: false,
            error: 'Fee transaction pending confirmations',
            feeTxid: request.feeTxid,
            confirmations: Number(e?.confirmations || 0),
            requiredConfirmations: Number(e?.requiredConfirmations || 6),
            blockHeight: e?.blockHeight,
          });
          return;
        }
        res.status(402).json({ success: false, error: e?.message || 'Fee transaction verification failed' });
        return;
      }

      const itemRecord = await this.registry.authenticateItem(request);

      res.json({
        success: true,
        authentication: {
          itemId: itemRecord.itemId,
          isAuthentic: request.isAuthentic,
          confidence: request.confidence,
          authenticatedAt: Date.now()
        },
        message: 'Item authentication recorded'
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * GET /api/registry/item/:itemId
   * Get item record details.
   */
  async getItem(req: Request, res: Response): Promise<void> {
    try {
      const { itemId } = req.params;
      let itemRecord: any = null;
      let canonicalState: any = null;

      // Try canonical state first (survives restarts and reflects all events)
      if (this.canonicalStateBuilder) {
        try {
          canonicalState = await this.canonicalStateBuilder.buildState();
          itemRecord = canonicalState.items.get(String(itemId));
          
          if (itemRecord) {
            // Convert canonical ItemState to ItemRecord format
            itemRecord = {
              itemId: itemRecord.itemId,
              manufacturerId: itemRecord.manufacturerId,
              issuerRole: (itemRecord as any).issuerRole,
              issuerAccountId: (itemRecord as any).issuerAccountId,
              serialNumberHash: itemRecord.serialNumberHash,
              serialNumberDisplay: itemRecord.serialNumberDisplay,
              metadataHash: itemRecord.metadataHash,
              currentOwner: itemRecord.currentOwner,
              status: 'active',
              registeredAt: itemRecord.registeredAt,
              feeTxid: (itemRecord as any).feeTxid,
              feeBlockHeight: (itemRecord as any).feeBlockHeight,
              feeCommitmentHex: (itemRecord as any).feeCommitmentHex,
              metadata: itemRecord.metadata || {},
              authentications: Array.isArray((itemRecord as any).authentications) ? (itemRecord as any).authentications : [],
            };
          }
        } catch (e) {
          console.error('[Registry API] Failed to get item from canonical state:', e);
        }
      }

      // Fallback to in-memory registry
      if (!itemRecord) {
        itemRecord = this.registry.getItem(itemId);
      }

      if (!itemRecord) {
        res.status(404).json({
          success: false,
          error: 'Item not found in registry'
        });
        return;
      }

      const manufacturerDisplayName = await this.resolveAccountDisplayName((itemRecord as any).manufacturerId);
      const authentications = Array.isArray((itemRecord as any).authentications) ? (itemRecord as any).authentications : [];
      const enrichedAuth = await Promise.all(
        authentications.map(async (a: any) => {
          const authenticatorId = String(a?.authenticatorId || '').trim();
          const authenticatorDisplayName = authenticatorId
            ? await this.resolveAccountDisplayName(authenticatorId)
            : String(a?.authenticatorName || '').trim();
          return { ...a, authenticatorDisplayName };
        })
      );

      let issuerRole = String((itemRecord as any)?.issuerRole || '').trim();
      if (!issuerRole && this.canonicalStateBuilder) {
        try {
          const state = canonicalState || await this.canonicalStateBuilder.buildState();
          const issuerId = String((itemRecord as any)?.issuerAccountId || (itemRecord as any)?.manufacturerId || '').trim();
          const issuerAccount: any = issuerId ? state.accounts.get(issuerId) : null;
          const role = String(issuerAccount?.role || '').trim();
          if (role === 'manufacturer' || role === 'authenticator') {
            issuerRole = role;
          } else {
            issuerRole = 'user';
          }
        } catch {}
      }

      const hasIssuerVerification = issuerRole === 'manufacturer' || issuerRole === 'authenticator';

      let hasAttestationVerification = enrichedAuth.some((a: any) => a && a.isAuthentic === true);
      if (issuerRole === 'user' && this.canonicalStateBuilder) {
        // For user-issued items, only treat as verified if there is a completed verification request
        // whose (paymentTxid, commitmentHex) matches an authentic attestation.
        try {
          const state = canonicalState || await this.canonicalStateBuilder.buildState();
          const completed = Array.from(state.verificationRequests.values()).filter(
            (r: any) => r && String(r.itemId) === String(itemId) && String(r.status) === 'completed'
          );

          hasAttestationVerification = completed.some((r: any) => {
            const txid = String(r.paymentTxid || '').trim();
            const commitment = String(r.commitmentHex || '').trim();
            if (!txid || !commitment) return false;
            return enrichedAuth.some(
              (a: any) =>
                a &&
                a.isAuthentic === true &&
                String(a.feeTxid || '').trim() === txid &&
                String(a.feeCommitmentHex || '').trim() === commitment
            );
          });
        } catch {}
      }

      const verificationStatus = hasIssuerVerification || hasAttestationVerification ? 'verified' : 'unverified';

      res.json({
        success: true,
        itemRecord: {
          ...itemRecord,
          manufacturerDisplayName,
          authentications: enrichedAuth,
          verificationStatus,
          issuerRole,
        }
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * GET /api/registry/item/:itemId/history
   * Get ownership history (provenance chain) from canonical event store.
   * Returns complete chain of custody with transaction details.
   */
  async getOwnershipHistory(req: Request, res: Response): Promise<void> {
    try {
      const { itemId } = req.params;
      let history: any[] = [];

      // Try to build history from canonical event store
      if (this.canonicalStateBuilder) {
        try {
          const events = await this.canonicalStateBuilder.eventStore.getEventsByItemId(itemId);
          
          // Filter for ownership-related events
          const itemRegistered = events.find((e: any) => e.payload?.type === 'ITEM_REGISTERED');
          const ownershipTransfers = events.filter((e: any) => e.payload?.type === 'OWNERSHIP_TRANSFERRED');
          
          if (!itemRegistered) {
            res.status(404).json({
              success: false,
              error: 'Item not found in registry'
            });
            return;
          }

          const regPayload = itemRegistered.payload as any;

          // Build complete ownership history
          history = [
            {
              event: 'ITEM_REGISTERED',
              timestamp: regPayload.timestamp || itemRegistered.createdAt,
              owner: regPayload.manufacturerId,
              details: {
                manufacturerId: regPayload.manufacturerId,
                serialNumberHash: regPayload.serialNumberHash,
                metadataHash: regPayload.metadataHash,
              }
            },
            ...ownershipTransfers.map((transfer: any) => {
              const payload = transfer.payload as any;
              return {
                event: 'OWNERSHIP_TRANSFERRED',
                timestamp: payload.timestamp || transfer.createdAt,
                fromOwner: payload.fromOwner,
                toOwner: payload.toOwner,
                owner: payload.toOwner,
                details: {
                  settlementId: payload.settlementId,
                  price: payload.price,
                  priceSats: payload.price,
                  paymentTxHash: payload.paymentTxHash,
                  bitcoinTxId: payload.paymentTxHash,
                }
              };
            })
          ].sort((a, b) => a.timestamp - b.timestamp);

        } catch (e) {
          console.error('[Registry API] Failed to get ownership history from canonical state:', e);
        }
      }

      // Fallback to in-memory registry
      if (history.length === 0) {
        history = this.registry.getOwnershipHistory(itemId);
      }

      if (history.length === 0) {
        res.status(404).json({
          success: false,
          error: 'Item not found in registry'
        });
        return;
      }

      res.json({
        success: true,
        itemId,
        ownershipHistory: history,
        totalTransfers: history.filter((h: any) => h.event === 'OWNERSHIP_TRANSFERRED').length
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * GET /api/registry/owner/:address
   * Get all items owned by address.
   */
  async getItemsByOwner(req: Request, res: Response): Promise<void> {
    try {
      const { address } = req.params;
      let items: any[] = [];

      // Try canonical state first
      if (this.canonicalStateBuilder) {
        try {
          const state = await this.canonicalStateBuilder.buildState();
          items = Array.from(state.items.values())
            .filter((item: any) => String(item.currentOwner) === String(address))
            .map((item: any) => ({
              itemId: item.itemId,
              status: 'active',
              manufacturerId: item.manufacturerId,
              currentOwner: item.currentOwner,
              registeredAt: item.registeredAt,
              metadata: item.metadata
            }));
        } catch (e) {
          console.error('[Registry API] Failed to get items by owner from canonical state:', e);
        }
      }

      // Fallback to in-memory registry
      if (items.length === 0) {
        items = this.registry.getItemsByOwner(address).map(item => ({
          itemId: item.itemId,
          status: item.status,
          manufacturerId: item.manufacturerId,
          registeredAt: item.registeredAt
        }));
      }

      res.json({
        success: true,
        owner: address,
        itemCount: items.length,
        items
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * GET /api/registry/manufacturer/:manufacturerId
   * Get all items registered by manufacturer.
   */
  async getItemsByManufacturer(req: Request, res: Response): Promise<void> {
    try {
      const { manufacturerId } = req.params;
      
      // Try canonical state first (survives restarts and reflects all events)
      if (this.canonicalStateBuilder) {
        try {
          const state = await this.canonicalStateBuilder.buildState();
          const items = Array.from(state.items.values()).filter(
            (item: any) => String(item.manufacturerId) === String(manufacturerId)
          );

          res.json({
            success: true,
            manufacturerId,
            itemCount: items.length,
            items: items.map((item: any) => ({
              itemId: item.itemId,
              status: 'active',
              currentOwner: item.currentOwner,
              registeredAt: item.registeredAt,
              metadata: item.metadata
            }))
          });
          return;
        } catch (e) {
          console.error('[Registry API] Failed to get items from canonical state:', e);
        }
      }

      // Fallback to in-memory registry
      const items = this.registry.getItemsByManufacturer(manufacturerId);

      res.json({
        success: true,
        manufacturerId,
        itemCount: items.length,
        items: items.map(item => ({
          itemId: item.itemId,
          status: item.status,
          currentOwner: item.currentOwner,
          registeredAt: item.registeredAt,
          metadata: item.metadata
        }))
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * GET /api/registry/stats
   * Get registry statistics from canonical state.
   */
  async getStats(req: Request, res: Response): Promise<void> {
    try {
      let stats: any = null;

      // Try to get stats from canonical state
      if (this.canonicalStateBuilder) {
        try {
          const state = await this.canonicalStateBuilder.buildState();
          stats = {
            totalItems: state.items.size,
            totalTransfers: Array.from(state.items.values()).reduce((sum: number, item: any) => sum + (item.transferCount || 0), 0),
            totalSettlements: state.settlements.size,
            completedSettlements: Array.from(state.settlements.values()).filter((s: any) => s.status === 'completed').length,
            totalAccounts: state.accounts.size,
            manufacturers: Array.from(state.accounts.values()).filter((a: any) => a.role === 'manufacturer').length,
            authenticators: Array.from(state.accounts.values()).filter((a: any) => a.role === 'authenticator').length,
            operators: state.operators.size,
          };
        } catch (e) {
          console.error('[Registry API] Failed to get stats from canonical state:', e);
        }
      }

      // Fallback to in-memory registry
      if (!stats) {
        stats = this.registry.getStats();
      }

      res.json({
        success: true,
        stats
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * GET /api/registry/export
   * Export registry ledger for syncing.
   */
  async exportLedger(req: Request, res: Response): Promise<void> {
    try {
      const ledgerData = this.registry.exportLedger();

      res.json({
        success: true,
        ledger: JSON.parse(ledgerData)
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * POST /api/registry/import
   * Import registry ledger for syncing.
   */
  async importLedger(req: Request, res: Response): Promise<void> {
    try {
      const { ledgerData } = req.body;

      if (!ledgerData) {
        res.status(400).json({
          success: false,
          error: 'Ledger data required'
        });
        return;
      }

      this.registry.importLedger(JSON.stringify(ledgerData));

      res.json({
        success: true,
        message: 'Registry ledger imported successfully'
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
}
