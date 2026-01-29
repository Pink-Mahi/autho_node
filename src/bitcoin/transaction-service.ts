import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { ECPairFactory } from 'ecpair';

// Initialize ECC library
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

export interface UTXO {
  txid: string;
  vout: number;
  value: number;
  status: {
    confirmed: boolean;
    block_height?: number;
  };
}

export interface TransactionResult {
  success: boolean;
  txid?: string;
  error?: string;
}

export class BitcoinTransactionService {
  private network: bitcoin.Network;
  private apiBase: string;

  constructor(networkType: 'mainnet' | 'testnet' = 'mainnet') {
    this.network = networkType === 'mainnet' 
      ? bitcoin.networks.bitcoin 
      : bitcoin.networks.testnet;
    
    this.apiBase = networkType === 'mainnet'
      ? 'https://mempool.space/api'
      : 'https://mempool.space/testnet/api';
  }

  async getUTXOs(address: string): Promise<UTXO[]> {
    const response = await fetch(`${this.apiBase}/address/${address}/utxo`);
    if (!response.ok) {
      throw new Error('Failed to fetch UTXOs');
    }
    return (await response.json()) as UTXO[];
  }

  async estimateFee(): Promise<number> {
    try {
      const response = await fetch(`${this.apiBase}/v1/fees/recommended`);
      const fees = (await response.json()) as any;
      // Use minimum economy fee for non-urgent anchoring transactions
      // Minimum relay fee is 1 sat/vB, but we can use the lowest recommended
      return fees.minimumFee || fees.economyFee || 1;
    } catch (error) {
      return 1; // Fallback to minimum relay fee
    }
  }

  async getTransactionHex(txid: string): Promise<string> {
    const response = await fetch(`${this.apiBase}/tx/${txid}/hex`);
    if (!response.ok) {
      throw new Error(`Failed to fetch transaction ${txid}`);
    }
    return await response.text();
  }

  async broadcastTransaction(txHex: string): Promise<string> {
    const response = await fetch(`${this.apiBase}/tx`, {
      method: 'POST',
      body: txHex
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Broadcast failed: ${error}`);
    }

    return await response.text(); // Returns txid
  }

  /**
   * Create and broadcast an OP_RETURN transaction for anchoring checkpoint data to Bitcoin
   * This embeds data permanently in the Bitcoin blockchain
   * Supports both native SegWit (bc1q...) and legacy (1...) addresses
   * @param explicitAddress - If provided, use this address for UTXOs instead of deriving from key
   */
  async createOpReturnAnchor(
    privateKeyWIF: string,
    data: string | Buffer,
    feeRate?: number,
    explicitAddress?: string
  ): Promise<{ success: boolean; txid?: string; feeSats?: number; error?: string }> {
    try {
      // Parse private key (support both WIF and raw 32-byte hex)
      let keyPair: any;
      try {
        keyPair = ECPair.fromWIF(privateKeyWIF, this.network);
      } catch (e) {
        const maybeHex = privateKeyWIF.trim();
        const isHex = /^[0-9a-fA-F]{64}$/.test(maybeHex);
        if (!isHex) throw e;
        const privKeyBuf = Buffer.from(maybeHex, 'hex');
        keyPair = ECPair.fromPrivateKey(privKeyBuf, { network: this.network });
      }

      // Use explicit address if provided, otherwise derive from key
      const fromAddress = explicitAddress || bitcoin.payments.p2wpkh({
        pubkey: keyPair.publicKey,
        network: this.network,
      }).address!;

      // Determine address type for proper input handling
      const isSegWit = fromAddress.startsWith('bc1') || fromAddress.startsWith('tb1');

      console.log(`[OP_RETURN Anchor] Creating anchor from ${fromAddress} (SegWit: ${isSegWit})`);

      // Get UTXOs
      const utxos = await this.getUTXOs(fromAddress);
      const confirmedUTXOs = utxos.filter((u) => u.status.confirmed);
      if (confirmedUTXOs.length === 0) {
        return { success: false, error: 'No confirmed UTXOs available. Please fund your operator wallet.' };
      }

      const totalInput = confirmedUTXOs.reduce((sum, utxo) => sum + utxo.value, 0);
      const estimatedFeeRate = feeRate || (await this.estimateFee());

      // SegWit transaction size is smaller: ~68 vbytes per input + outputs
      const estimatedVsize = confirmedUTXOs.length * 68 + 43 + 31 + 10;
      const estimatedFee = Math.ceil(estimatedVsize * estimatedFeeRate);

      if (totalInput < estimatedFee + 546) {
        return { success: false, error: `Insufficient funds. Have ${totalInput} sats, need at least ${estimatedFee + 546} sats` };
      }

      const changeAmount = totalInput - estimatedFee;

      // Prepare OP_RETURN data
      const opReturnData = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
      if (opReturnData.length > 80) {
        return { success: false, error: 'OP_RETURN data exceeds 80 bytes limit' };
      }

      // Build OP_RETURN script
      const opReturnScript = bitcoin.script.compile([
        bitcoin.opcodes.OP_RETURN,
        opReturnData
      ]);

      // Create PSBT
      const psbt = new bitcoin.Psbt({ network: this.network });

      // Create p2wpkh payment for SegWit witness script
      const p2wpkh = bitcoin.payments.p2wpkh({
        pubkey: keyPair.publicKey,
        network: this.network,
      });

      // Add inputs - use witnessUtxo for SegWit addresses
      for (const utxo of confirmedUTXOs) {
        if (isSegWit) {
          psbt.addInput({
            hash: utxo.txid,
            index: utxo.vout,
            witnessUtxo: {
              script: p2wpkh.output!,
              value: utxo.value,
            },
          });
        } else {
          // Legacy address - need full transaction hex
          const txHex = await this.getTransactionHex(utxo.txid);
          psbt.addInput({
            hash: utxo.txid,
            index: utxo.vout,
            nonWitnessUtxo: Buffer.from(txHex, 'hex'),
          });
        }
      }

      // Add OP_RETURN output (value must be 0)
      psbt.addOutput({
        script: opReturnScript,
        value: 0,
      });

      // Add change output
      if (changeAmount > 546) {
        psbt.addOutput({
          address: fromAddress,
          value: changeAmount,
        });
      }

      // Sign all inputs
      for (let i = 0; i < confirmedUTXOs.length; i++) {
        psbt.signInput(i, keyPair);
      }

      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      const txHex = tx.toHex();

      console.log(`[OP_RETURN Anchor] Broadcasting transaction...`);
      const txid = await this.broadcastTransaction(txHex);
      console.log(`[OP_RETURN Anchor] Success! TXID: ${txid}`);

      return {
        success: true,
        txid,
        feeSats: estimatedFee,
      };
    } catch (error: any) {
      console.error(`[OP_RETURN Anchor] Error:`, error);
      return {
        success: false,
        error: error.message || String(error),
      };
    }
  }

  /**
   * Get the native SegWit (P2WPKH) address for a private key - bc1q... format
   */
  getAddressFromPrivateKey(privateKeyWIF: string): string {
    let keyPair: any;
    try {
      keyPair = ECPair.fromWIF(privateKeyWIF, this.network);
    } catch (e) {
      const maybeHex = privateKeyWIF.trim();
      const isHex = /^[0-9a-fA-F]{64}$/.test(maybeHex);
      if (!isHex) throw e;
      const privKeyBuf = Buffer.from(maybeHex, 'hex');
      keyPair = ECPair.fromPrivateKey(privKeyBuf, { network: this.network });
    }

    return bitcoin.payments.p2wpkh({
      pubkey: keyPair.publicKey,
      network: this.network,
    }).address!;
  }

  /**
   * Get balance for an address
   */
  async getBalance(address: string): Promise<number> {
    const utxos = await this.getUTXOs(address);
    return utxos.reduce((sum, utxo) => sum + utxo.value, 0);
  }
}
