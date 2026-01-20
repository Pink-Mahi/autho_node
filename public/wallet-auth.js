/**
 * Wallet Authentication Utility
 * Checks if user has a wallet and if it's unlocked
 */

const WalletAuth = {
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
    const unlocked = sessionStorage.getItem('autho_wallet_unlocked');
    const unlockTime = sessionStorage.getItem('autho_wallet_unlock_time');
    
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
      return walletData ? JSON.parse(walletData) : null;
    } catch (error) {
      console.error('Error reading wallet:', error);
      return null;
    }
  },

  /**
   * Lock wallet (clear session)
   */
  lock() {
    sessionStorage.removeItem('autho_wallet_unlocked');
    sessionStorage.removeItem('autho_wallet_unlock_time');
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
  }
};

// Make available globally
if (typeof window !== 'undefined') {
  window.WalletAuth = WalletAuth;
}
