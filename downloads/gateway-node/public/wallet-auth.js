/**
 * Wallet Authentication Utility
 * Checks if user has a wallet and if it's unlocked
 */

const WalletAuth = {
  // --- PIN Security Utilities (PBKDF2) ---
  async hashPinPBKDF2(pin) {
    const enc = new TextEncoder();
    const salt = enc.encode('autho_pin_salt_v1');
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
    const hashArray = Array.from(new Uint8Array(bits));
    return 'pbkdf2v1:' + hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  async verifyStoredPin(pin, stored) {
    if (!stored || !pin) return false;
    if (stored.startsWith('pbkdf2v1:')) {
      const computed = await this.hashPinPBKDF2(pin);
      return computed === stored;
    }
    // Legacy base64 format - verify and auto-upgrade
    try {
      if (btoa(pin) === stored) {
        // Auto-upgrade to PBKDF2
        try {
          const upgraded = await this.hashPinPBKDF2(pin);
          localStorage.setItem('autho_wallet_pin', upgraded);
        } catch {}
        return true;
      }
    } catch {}
    return false;
  },
  /**
   * Check if wallet exists
   */
  hasWallet() {
    return !!localStorage.getItem('autho_wallet_encrypted');
  },

  /**
   * Check if wallet is currently unlocked
   */
  isUnlocked() {
    let unlocked = sessionStorage.getItem('autho_wallet_unlocked');
    let unlockTime = sessionStorage.getItem('autho_wallet_unlock_time');

    if (!unlocked || unlocked !== 'true') {
      try {
        const localUnlocked = localStorage.getItem('autho_wallet_unlocked');
        const localUnlockTime = localStorage.getItem('autho_wallet_unlock_time');
        if (localUnlocked === 'true' && localUnlockTime) {
          const elapsed = Date.now() - parseInt(localUnlockTime);
          const thirtyMinutes = 30 * 60 * 1000;
          if (elapsed <= thirtyMinutes) {
            sessionStorage.setItem('autho_wallet_unlocked', 'true');
            sessionStorage.setItem('autho_wallet_unlock_time', localUnlockTime);
            unlocked = 'true';
            unlockTime = localUnlockTime;
          }
        }
      } catch {}
    }
    
    if (!unlocked || unlocked !== 'true') {
      return false;
    }

    // Check if session expired (30 minutes)
    if (unlockTime) {
      const elapsed = Date.now() - parseInt(unlockTime);
      const thirtyMinutes = 30 * 60 * 1000;
      
      if (elapsed > thirtyMinutes) {
        this.lock();
        return false;
      }
    }

    return true;
  },

  /**
   * Get wallet data (only if unlocked)
   */
  getWallet() {
    if (!this.isUnlocked()) {
      return null;
    }
    
    try {
      const walletData = localStorage.getItem('autho_wallet');
      const wallet = walletData ? JSON.parse(walletData) : null;
      
      // Include privateKey from sessionStorage if available (for E2E encryption)
      if (wallet) {
        const privateKey = sessionStorage.getItem('autho_wallet_privateKey');
        if (privateKey) {
          wallet.privateKey = privateKey;
        }
      }
      
      return wallet;
    } catch (error) {
      console.error('Error reading wallet:', error);
      return null;
    }
  },

  async ensureMessagingKeys() {
    try {
      const existing = sessionStorage.getItem('autho_messaging_privateKey');
      if (existing) return true;

      // Try sessionStorage first (set during login), then fall back to localStorage legacy
      let pin = sessionStorage.getItem('autho_session_pin') || '';
      if (!pin) {
        // Legacy fallback: try to read old base64-encoded PIN from localStorage
        const pinStored = localStorage.getItem('autho_wallet_pin');
        if (!pinStored) return false;
        if (!pinStored.startsWith('pbkdf2v1:')) {
          try { pin = atob(pinStored); } catch { return false; }
        } else {
          // PBKDF2 hash - can't reverse, need session PIN
          return false;
        }
      }

      const vaultStr = localStorage.getItem('autho_wallet_vault_local') || localStorage.getItem('autho_wallet_vault');
      if (!vaultStr) return false;

      let vault;
      try {
        vault = JSON.parse(vaultStr);
      } catch {
        return false;
      }

      const bytesFromB64 = (b64) => Uint8Array.from(atob(String(b64 || '')), (c) => c.charCodeAt(0));
      const deriveVaultKey = async (password, saltBytes, iterations) => {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
          'raw',
          enc.encode(String(password)),
          { name: 'PBKDF2' },
          false,
          ['deriveKey']
        );
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
          keyMaterial,
          { name: 'AES-GCM', length: 256 },
          false,
          ['decrypt']
        );
      };

      if (!vault || vault.v !== 'AUTHO_WALLET_VAULT_V1') return false;
      const salt = bytesFromB64(vault.kdf?.saltB64 || '');
      const iterations = Number(vault.kdf?.iterations || 0);
      const iv = bytesFromB64(vault.enc?.ivB64 || '');
      const ct = bytesFromB64(vault.enc?.ctB64 || '');
      if (!iterations) return false;

      const key = await deriveVaultKey(pin, salt, iterations);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      const json = new TextDecoder().decode(pt);
      const payload = JSON.parse(json);
      const mnemonic = String(payload?.mnemonic || '').trim();
      if (!mnemonic) return false;

      if (!window.AuthoBTC || typeof window.AuthoBTC.deriveMessagingKeyPairSync !== 'function') return false;
      const msgKeys = window.AuthoBTC.deriveMessagingKeyPairSync(mnemonic);
      if (!msgKeys || !msgKeys.privateKeyHex || !msgKeys.publicKeyHex) return false;

      sessionStorage.setItem('autho_messaging_privateKey', msgKeys.privateKeyHex);
      sessionStorage.setItem('autho_messaging_publicKey', msgKeys.publicKeyHex);
      return true;
    } catch (e) {
      return false;
    }
  },

  /**
   * Lock wallet (clear session)
   */
  lock() {
    sessionStorage.removeItem('autho_wallet_unlocked');
    sessionStorage.removeItem('autho_wallet_unlock_time');
    sessionStorage.removeItem('autho_wallet_privateKey');
    sessionStorage.removeItem('autho_messaging_privateKey');
    sessionStorage.removeItem('autho_messaging_publicKey');
    sessionStorage.removeItem('autho_session_pin');
    try {
      localStorage.removeItem('autho_session_id');
      localStorage.removeItem('autho_account_id');
      localStorage.removeItem('autho_wallet_unlocked');
      localStorage.removeItem('autho_wallet_unlock_time');
    } catch {}
  },

  /**
   * Require authentication - redirect to login if needed
   * @param {string} returnUrl - URL to return to after login
   */
  requireAuth(returnUrl) {
    if (!this.hasWallet()) {
      // No wallet, redirect to wallet creation
      window.location.href = '/m/wallet';
      return false;
    }

    if (!this.isUnlocked()) {
      // Wallet exists but locked, redirect to login
      const url = returnUrl || window.location.pathname + window.location.search;
      window.location.href = `/m/login?return=${encodeURIComponent(url)}`;
      return false;
    }

    return true;
  },

  /**
   * Get wallet address preview
   */
  getAddressPreview() {
    const wallet = this.getWallet();
    if (!wallet || !wallet.address) {
      return 'No wallet';
    }
    
    const addr = wallet.address;
    return addr.substring(0, 8) + '...' + addr.substring(addr.length - 8);
  },

  /**
   * Add logout button to page
   */
  addLogoutButton(containerId = 'walletStatus') {
    const container = document.getElementById(containerId);
    if (!container) return;

    const wallet = this.getWallet();
    if (!wallet) return;

    container.innerHTML = `
      <div style="display: flex; align-items: center; gap: 10px; padding: 10px; background: rgba(212, 175, 55, 0.1); border-radius: 8px; margin-bottom: 15px;">
        <div style="flex: 1;">
          <div style="font-size: 12px; color: #999; margin-bottom: 4px;">Connected Wallet</div>
          <div style="font-family: monospace; font-size: 13px; color: #d4af37;">${this.getAddressPreview()}</div>
        </div>
        <button onclick="WalletAuth.logout()" style="background: rgba(255, 59, 48, 0.2); color: #ff3b30; border: 1px solid rgba(255, 59, 48, 0.3); padding: 8px 16px; border-radius: 8px; font-size: 13px; cursor: pointer;">
          🔒 Lock
        </button>
      </div>
    `;
  },

  /**
   * Logout (lock wallet)
   */
  logout() {
    this.lock();
    window.location.href = '/m/login';
  },

  /**
   * Get authentication headers for API requests
   */
  getAuthHeaders() {
    let sessionId = '';
    try {
      sessionId = String(localStorage.getItem('autho_session_id') || '').trim();
    } catch {}

    const wallet = this.getWallet();
    return {
      'Content-Type': 'application/json',
      ...(sessionId ? { 'Authorization': `Bearer ${sessionId}`, 'X-Session-Token': sessionId } : {}),
      ...(wallet ? { 'X-Wallet-Address': wallet.address || wallet.publicKey, 'X-Public-Key': wallet.publicKey } : {}),
    };
  },

  /**
   * Get public key from wallet
   */
  getPublicKey() {
    const wallet = this.getWallet();
    return wallet ? wallet.publicKey : null;
  }
};

// Make available globally
if (typeof window !== 'undefined') {
  window.WalletAuth = WalletAuth;
}
