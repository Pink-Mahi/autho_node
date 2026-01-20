/**
 * Client-Side Wallet Generator
 * NON-CUSTODIAL: All wallet generation happens in user's browser
 * Private keys NEVER sent to server
 */

// This will use bitcoinjs-lib loaded via CDN
const WalletGenerator = {
  /**
   * Generate a new Bitcoin wallet
   * Returns: { mnemonic, address, publicKey }
   */
  generateBitcoinWallet: function() {
    // Generate 12-word mnemonic (BIP39)
    const mnemonic = window.bip39.generateMnemonic();
    
    // Create seed from mnemonic
    const seed = window.bip39.mnemonicToSeedSync(mnemonic);
    
    // Create HD wallet (BIP32)
    const root = window.bip32.fromSeed(seed);
    
    // Derive Bitcoin address (BIP44: m/44'/0'/0'/0/0)
    const path = "m/44'/0'/0'/0/0";
    const child = root.derivePath(path);
    
    // Generate address (P2PKH for compatibility)
    const { address } = window.bitcoin.payments.p2pkh({
      pubkey: child.publicKey,
      network: window.bitcoin.networks.bitcoin
    });
    
    return {
      mnemonic: mnemonic,
      address: address,
      publicKey: child.publicKey.toString('hex'),
      derivationPath: path
    };
  },

  /**
   * Generate Lightning address (LNURL or Lightning Address)
   * For now, returns a placeholder - can be enhanced with real Lightning
   */
  generateLightningAddress: function(username) {
    // Lightning Address format: username@domain.com
    // This would connect to a Lightning node or LNURL service
    return `${username}@yourdomain.com`;
  },

  /**
   * Restore wallet from mnemonic
   */
  restoreWallet: function(mnemonic) {
    if (!window.bip39.validateMnemonic(mnemonic)) {
      throw new Error('Invalid mnemonic phrase');
    }
    
    const seed = window.bip39.mnemonicToSeedSync(mnemonic);
    const root = window.bip32.fromSeed(seed);
    const path = "m/44'/0'/0'/0/0";
    const child = root.derivePath(path);
    
    const { address } = window.bitcoin.payments.p2pkh({
      pubkey: child.publicKey,
      network: window.bitcoin.networks.bitcoin
    });
    
    return {
      address: address,
      publicKey: child.publicKey.toString('hex'),
      derivationPath: path
    };
  },

  /**
   * Validate Bitcoin address
   */
  validateAddress: function(address) {
    try {
      window.bitcoin.address.toOutputScript(address);
      return true;
    } catch (e) {
      return false;
    }
  }
};

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = WalletGenerator;
}
