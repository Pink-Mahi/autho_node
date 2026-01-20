/**
 * CLIENT-SIDE BITCOIN WALLET MODULE
 * 
 * Self-custody Bitcoin wallet for mobile web app:
 * - Create wallet (generate seed)
 * - Import wallet (seed words)
 * - Sign messages (login, offers)
 * - Sign PSBTs (payments)
 * - Secure storage (WebCrypto + IndexedDB)
 * 
 * CRITICAL: Private keys NEVER leave the browser
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as bip39 from 'bip39';
import * as bip32 from 'bip32';

class BitcoinWallet {
  constructor() {
    this.network = bitcoin.networks.bitcoin; // Use testnet for development
    this.wallet = null;
    this.encryptionKey = null;
  }

  /**
   * Create new wallet with generated seed
   */
  async createWallet(passcode) {
    try {
      // Generate 12-word mnemonic
      const mnemonic = bip39.generateMnemonic(128);
      
      // Derive keys from mnemonic
      const seed = await bip39.mnemonicToSeed(mnemonic);
      const root = bip32.fromSeed(seed, this.network);
      
      // Derive identity key (m/84'/0'/0'/0/0 - first native segwit address)
      const identityPath = "m/84'/0'/0'/0/0";
      const identityNode = root.derivePath(identityPath);
      
      // Derive payment key (m/84'/0'/0'/0/1)
      const paymentPath = "m/84'/0'/0'/0/1";
      const paymentNode = root.derivePath(paymentPath);
      
      // Create wallet object
      this.wallet = {
        mnemonic,
        identityPrivateKey: identityNode.privateKey.toString('hex'),
        identityPublicKey: identityNode.publicKey.toString('hex'),
        identityAddress: this.deriveAddress(identityNode.publicKey),
        paymentPrivateKey: paymentNode.privateKey.toString('hex'),
        paymentPublicKey: paymentNode.publicKey.toString('hex'),
        paymentAddress: this.deriveAddress(paymentNode.publicKey),
        createdAt: Date.now()
      };
      
      // Encrypt and save
      await this.saveWallet(passcode);
      
      return {
        mnemonic,
        identityPublicKey: this.wallet.identityPublicKey,
        identityAddress: this.wallet.identityAddress,
        paymentAddress: this.wallet.paymentAddress
      };
    } catch (error) {
      console.error('[Wallet] Error creating wallet:', error);
      throw new Error('Failed to create wallet');
    }
  }

  /**
   * Import wallet from seed words
   */
  async importWallet(mnemonic, passcode) {
    try {
      // Validate mnemonic
      if (!bip39.validateMnemonic(mnemonic)) {
        throw new Error('Invalid seed phrase');
      }
      
      // Derive keys from mnemonic
      const seed = await bip39.mnemonicToSeed(mnemonic);
      const root = bip32.fromSeed(seed, this.network);
      
      // Derive identity key
      const identityPath = "m/84'/0'/0'/0/0";
      const identityNode = root.derivePath(identityPath);
      
      // Derive payment key
      const paymentPath = "m/84'/0'/0'/0/1";
      const paymentNode = root.derivePath(paymentPath);
      
      // Create wallet object
      this.wallet = {
        mnemonic,
        identityPrivateKey: identityNode.privateKey.toString('hex'),
        identityPublicKey: identityNode.publicKey.toString('hex'),
        identityAddress: this.deriveAddress(identityNode.publicKey),
        paymentPrivateKey: paymentNode.privateKey.toString('hex'),
        paymentPublicKey: paymentNode.publicKey.toString('hex'),
        paymentAddress: this.deriveAddress(paymentNode.publicKey),
        createdAt: Date.now()
      };
      
      // Encrypt and save
      await this.saveWallet(passcode);
      
      return {
        identityPublicKey: this.wallet.identityPublicKey,
        identityAddress: this.wallet.identityAddress,
        paymentAddress: this.wallet.paymentAddress
      };
    } catch (error) {
      console.error('[Wallet] Error importing wallet:', error);
      throw new Error('Failed to import wallet: ' + error.message);
    }
  }

  /**
   * Unlock wallet with passcode
   */
  async unlockWallet(passcode) {
    try {
      // Get encrypted wallet from storage
      const encrypted = localStorage.getItem('autho_wallet_encrypted');
      if (!encrypted) {
        throw new Error('No wallet found');
      }
      
      // Derive encryption key from passcode
      const encryptionKey = await this.deriveEncryptionKey(passcode);
      
      // Decrypt wallet
      const decrypted = await this.decrypt(encrypted, encryptionKey);
      this.wallet = JSON.parse(decrypted);
      this.encryptionKey = encryptionKey;
      
      // Store public info in localStorage for quick access
      localStorage.setItem('autho_wallet', JSON.stringify({
        publicKey: this.wallet.identityPublicKey,
        address: this.wallet.identityAddress,
        paymentAddress: this.wallet.paymentAddress
      }));
      
      return {
        identityPublicKey: this.wallet.identityPublicKey,
        identityAddress: this.wallet.identityAddress,
        paymentAddress: this.wallet.paymentAddress
      };
    } catch (error) {
      console.error('[Wallet] Error unlocking wallet:', error);
      throw new Error('Failed to unlock wallet: incorrect passcode');
    }
  }

  /**
   * Lock wallet (clear from memory)
   */
  lockWallet() {
    this.wallet = null;
    this.encryptionKey = null;
    localStorage.removeItem('autho_wallet');
  }

  /**
   * Sign message with identity key
   */
  async signMessage(message) {
    if (!this.wallet) {
      throw new Error('Wallet not unlocked');
    }
    
    try {
      const messageHash = bitcoin.crypto.sha256(Buffer.from(message));
      const privateKey = Buffer.from(this.wallet.identityPrivateKey, 'hex');
      const keyPair = bitcoin.ECPair.fromPrivateKey(privateKey, { network: this.network });
      
      const signature = keyPair.sign(messageHash);
      return signature.toString('hex');
    } catch (error) {
      console.error('[Wallet] Error signing message:', error);
      throw new Error('Failed to sign message');
    }
  }

  /**
   * Sign PSBT for payment
   */
  async signPSBT(psbtBase64) {
    if (!this.wallet) {
      throw new Error('Wallet not unlocked');
    }
    
    try {
      const psbt = bitcoin.Psbt.fromBase64(psbtBase64);
      const privateKey = Buffer.from(this.wallet.paymentPrivateKey, 'hex');
      const keyPair = bitcoin.ECPair.fromPrivateKey(privateKey, { network: this.network });
      
      // Sign all inputs
      for (let i = 0; i < psbt.inputCount; i++) {
        psbt.signInput(i, keyPair);
      }
      
      // Finalize
      psbt.finalizeAllInputs();
      
      // Return signed transaction
      const tx = psbt.extractTransaction();
      return {
        signedPsbt: psbt.toBase64(),
        txHex: tx.toHex(),
        txId: tx.getId()
      };
    } catch (error) {
      console.error('[Wallet] Error signing PSBT:', error);
      throw new Error('Failed to sign transaction');
    }
  }

  /**
   * Export seed phrase (with warning)
   */
  exportSeed() {
    if (!this.wallet) {
      throw new Error('Wallet not unlocked');
    }
    
    return this.wallet.mnemonic;
  }

  /**
   * Get wallet info
   */
  getWalletInfo() {
    if (!this.wallet) {
      return null;
    }
    
    return {
      identityPublicKey: this.wallet.identityPublicKey,
      identityAddress: this.wallet.identityAddress,
      paymentAddress: this.wallet.paymentAddress,
      createdAt: this.wallet.createdAt
    };
  }

  /**
   * Check if wallet exists
   */
  static hasWallet() {
    return !!localStorage.getItem('autho_wallet_encrypted');
  }

  /**
   * Derive Bitcoin address from public key
   */
  deriveAddress(publicKey) {
    const { address } = bitcoin.payments.p2wpkh({
      pubkey: Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey, 'hex'),
      network: this.network
    });
    return address;
  }

  /**
   * Save wallet (encrypted)
   */
  async saveWallet(passcode) {
    try {
      // Derive encryption key from passcode
      this.encryptionKey = await this.deriveEncryptionKey(passcode);
      
      // Encrypt wallet
      const walletJson = JSON.stringify(this.wallet);
      const encrypted = await this.encrypt(walletJson, this.encryptionKey);
      
      // Save encrypted wallet
      localStorage.setItem('autho_wallet_encrypted', encrypted);
      
      // Save public info for quick access
      localStorage.setItem('autho_wallet', JSON.stringify({
        publicKey: this.wallet.identityPublicKey,
        address: this.wallet.identityAddress,
        paymentAddress: this.wallet.paymentAddress
      }));
    } catch (error) {
      console.error('[Wallet] Error saving wallet:', error);
      throw new Error('Failed to save wallet');
    }
  }

  /**
   * Derive encryption key from passcode using PBKDF2
   */
  async deriveEncryptionKey(passcode) {
    const encoder = new TextEncoder();
    const passcodeData = encoder.encode(passcode);
    
    // Import passcode as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passcodeData,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );
    
    // Derive AES key
    const salt = encoder.encode('autho-wallet-salt-v1'); // In production, use random salt per wallet
    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    
    return key;
  }

  /**
   * Encrypt data with AES-GCM
   */
  async encrypt(data, key) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    
    // Generate random IV
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      dataBuffer
    );
    
    // Combine IV + encrypted data
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    
    // Convert to base64
    return btoa(String.fromCharCode(...combined));
  }

  /**
   * Decrypt data with AES-GCM
   */
  async decrypt(encryptedBase64, key) {
    // Decode base64
    const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
    
    // Extract IV and encrypted data
    const iv = combined.slice(0, 12);
    const encrypted = combined.slice(12);
    
    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      encrypted
    );
    
    // Convert to string
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  /**
   * Delete wallet (WARNING: irreversible without seed backup)
   */
  static deleteWallet() {
    localStorage.removeItem('autho_wallet_encrypted');
    localStorage.removeItem('autho_wallet');
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = BitcoinWallet;
} else {
  window.BitcoinWallet = BitcoinWallet;
}
