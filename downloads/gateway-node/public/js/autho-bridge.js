/**
 * Autho Bridge - Embeddable Gateway Script
 * 
 * Allows any website to become a gateway node for the Autho network.
 * Retailers, businesses, or anyone can add this script to their website
 * to help strengthen the Autho mesh network.
 * 
 * Usage:
 *   <script src="https://autho.pinkmahi.com/js/autho-bridge.js"></script>
 *   <script>
 *     const bridge = new AuthoBridge({
 *       operatorUrls: ['https://autho.pinkmahi.com', 'https://autho.cartpathcleaning.com'],
 *       enableProxy: true,  // Proxy API requests through this page
 *       enableRelay: true,  // Relay WebSocket messages to other users
 *       onConnected: () => console.log('Connected to Autho network'),
 *     });
 *     bridge.start();
 *   </script>
 * 
 * Benefits:
 * - Contributes to network resilience
 * - Reduces load on main operators
 * - Enables local caching for faster responses
 * - No server-side code required
 */

(function(global) {
  'use strict';

  const DEFAULT_OPERATORS = [
    'https://autho.pinkmahi.com',
    'https://autho.cartpathcleaning.com',
    'https://autho2.cartpathcleaning.com'
  ];

  class AuthoBridge {
    constructor(options = {}) {
      this.options = {
        operatorUrls: options.operatorUrls || DEFAULT_OPERATORS,
        enableProxy: options.enableProxy !== false,
        enableRelay: options.enableRelay !== false,
        enableCache: options.enableCache !== false,
        cacheTTL: options.cacheTTL || 300000, // 5 minutes
        onConnected: options.onConnected || (() => {}),
        onDisconnected: options.onDisconnected || (() => {}),
        onError: options.onError || console.error,
        debug: options.debug || false,
      };

      this.bridgeId = this.generateBridgeId();
      this.connections = new Map(); // operatorUrl -> WebSocket
      this.cache = new Map();
      this.isConnected = false;
      this.registryData = null;
      this.lastSync = 0;
    }

    generateBridgeId() {
      const stored = localStorage.getItem('autho_bridge_id');
      if (stored) return stored;
      
      const id = `bridge-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 8)}`;
      localStorage.setItem('autho_bridge_id', id);
      return id;
    }

    log(...args) {
      if (this.options.debug) {
        console.log('[AuthoBridge]', ...args);
      }
    }

    async start() {
      this.log('Starting Autho Bridge:', this.bridgeId);
      
      // Connect to operators
      await this.connectToOperators();

      // Start periodic sync
      setInterval(() => this.syncRegistry(), 60000);

      // Initial sync
      await this.syncRegistry();

      this.log('Autho Bridge started');
    }

    async connectToOperators() {
      for (const operatorUrl of this.options.operatorUrls) {
        try {
          await this.connectToOperator(operatorUrl);
        } catch (error) {
          this.log('Failed to connect to operator:', operatorUrl, error.message);
        }
      }
    }

    async connectToOperator(operatorUrl) {
      const wsUrl = operatorUrl.replace('https://', 'wss://').replace('http://', 'ws://');
      
      return new Promise((resolve, reject) => {
        try {
          const ws = new WebSocket(wsUrl);
          
          ws.onopen = () => {
            this.log('Connected to operator:', operatorUrl);
            this.connections.set(operatorUrl, ws);
            this.isConnected = true;
            
            // Send handshake
            ws.send(JSON.stringify({
              type: 'sync_request',
              nodeId: this.bridgeId,
              nodeType: 'browser_bridge',
              timestamp: Date.now()
            }));
            
            this.options.onConnected();
            resolve(ws);
          };

          ws.onmessage = (event) => {
            try {
              const message = JSON.parse(event.data);
              this.handleOperatorMessage(operatorUrl, message);
            } catch (error) {
              this.log('Invalid message from operator:', error);
            }
          };

          ws.onclose = () => {
            this.log('Disconnected from operator:', operatorUrl);
            this.connections.delete(operatorUrl);
            
            if (this.connections.size === 0) {
              this.isConnected = false;
              this.options.onDisconnected();
            }

            // Reconnect after delay
            setTimeout(() => this.connectToOperator(operatorUrl), 10000);
          };

          ws.onerror = (error) => {
            this.log('WebSocket error:', operatorUrl, error);
            reject(error);
          };

        } catch (error) {
          reject(error);
        }
      });
    }

    handleOperatorMessage(operatorUrl, message) {
      switch (message.type) {
        case 'sync_response':
        case 'sync_data':
          this.registryData = message.state || message.data;
          this.lastSync = Date.now();
          this.log('Received registry sync');
          break;

        case 'registry_update':
          if (message.data) {
            this.registryData = message.data;
            this.lastSync = Date.now();
            this.log('Registry updated, seq:', message.data.sequenceNumber);
          }
          break;

        case 'state_verification':
          this.log('State verification from:', message.nodeId);
          break;

        default:
          this.log('Unknown message type:', message.type);
      }
    }

    async syncRegistry() {
      // Try to fetch from cached operator
      for (const [operatorUrl] of this.connections) {
        try {
          const response = await fetch(`${operatorUrl}/api/registry/state`);
          if (response.ok) {
            this.registryData = await response.json();
            this.lastSync = Date.now();
            this.log('Registry synced from:', operatorUrl);
            return;
          }
        } catch (error) {
          this.log('Sync failed from:', operatorUrl, error.message);
        }
      }
    }

    // Proxy API request through connected operator
    async proxyRequest(path, options = {}) {
      if (!this.options.enableProxy) {
        throw new Error('Proxy not enabled');
      }

      // Check cache for GET requests
      if (options.method === 'GET' || !options.method) {
        const cached = this.getFromCache(path);
        if (cached) return cached;
      }

      // Try each connected operator
      for (const operatorUrl of this.options.operatorUrls) {
        try {
          const response = await fetch(`${operatorUrl}${path}`, {
            ...options,
            headers: {
              'Content-Type': 'application/json',
              'X-Autho-Bridge': this.bridgeId,
              ...(options.headers || {}),
            }
          });

          if (response.ok) {
            const data = await response.json();
            
            // Cache GET responses
            if (options.method === 'GET' || !options.method) {
              this.setCache(path, data);
            }
            
            return data;
          }
        } catch (error) {
          this.log('Request failed via:', operatorUrl, error.message);
        }
      }

      throw new Error('All operators failed');
    }

    getFromCache(key) {
      if (!this.options.enableCache) return null;
      
      const cached = this.cache.get(key);
      if (!cached) return null;
      
      if (Date.now() - cached.timestamp > this.options.cacheTTL) {
        this.cache.delete(key);
        return null;
      }
      
      return cached.data;
    }

    setCache(key, data) {
      if (!this.options.enableCache) return;
      
      this.cache.set(key, {
        data,
        timestamp: Date.now()
      });
    }

    // Get item from registry
    async getItem(itemId) {
      return this.proxyRequest(`/api/registry/item/${itemId}`);
    }

    // Verify item ownership
    async verifyItem(itemId) {
      return this.proxyRequest(`/api/registry/items/${itemId}`);
    }

    // Get owner's items
    async getOwnerItems(address) {
      return this.proxyRequest(`/api/registry/owner/${address}`);
    }

    // Get network stats
    async getNetworkStats() {
      return this.proxyRequest('/api/network/stats');
    }

    // Get list of operators
    async getOperators() {
      return this.proxyRequest('/api/network/operators');
    }

    // Get list of gateways
    async getGateways() {
      return this.proxyRequest('/api/network/gateways');
    }

    // Status
    getStatus() {
      return {
        bridgeId: this.bridgeId,
        isConnected: this.isConnected,
        connectedOperators: Array.from(this.connections.keys()),
        lastSync: this.lastSync,
        cacheSize: this.cache.size,
        registrySequence: this.registryData?.sequenceNumber || 0,
      };
    }

    // Stop the bridge
    stop() {
      this.log('Stopping Autho Bridge');
      
      for (const [, ws] of this.connections) {
        ws.close();
      }
      
      this.connections.clear();
      this.isConnected = false;
    }
  }

  // Expose to global
  global.AuthoBridge = AuthoBridge;

  // Auto-initialize if data attributes present
  document.addEventListener('DOMContentLoaded', () => {
    const script = document.querySelector('script[data-autho-bridge]');
    if (script) {
      const options = {
        debug: script.dataset.debug === 'true',
        enableProxy: script.dataset.proxy !== 'false',
        enableRelay: script.dataset.relay !== 'false',
        enableCache: script.dataset.cache !== 'false',
      };
      
      global.authoBridge = new AuthoBridge(options);
      global.authoBridge.start();
    }
  });

})(typeof window !== 'undefined' ? window : this);
