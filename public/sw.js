/**
 * Autho Service Worker — PWA offline support + caching
 *
 * Caches critical assets for offline access, handles background sync,
 * and enables the "Add to Home Screen" install prompt on mobile.
 */

const CACHE_NAME = 'autho-v1';
const OFFLINE_URL = '/mobile-entry.html';

// Critical assets to pre-cache on install
const PRECACHE_ASSETS = [
  '/',
  '/mobile-entry.html',
  '/mobile-messages.html',
  '/mobile-wallet.html',
  '/mobile-items.html',
  '/mobile-login.html',
  '/mobile-search.html',
  '/mobile-verify.html',
  '/wallet-auth.js',
  '/js/nacl-fast.min.js',
  '/js/nacl-util.min.js',
  '/js/double-ratchet.js',
  '/js/mls-group.js',
  '/js/autho-wire.js',
  '/js/mlkem.bundle.js',
  '/js/btc.bundle.js',
  '/js/qrcode.min.js',
  '/js/jsQR.js',
  '/manifest.json',
];

// Install: pre-cache critical assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[SW] Pre-caching critical assets');
      return cache.addAll(PRECACHE_ASSETS).catch((err) => {
        console.warn('[SW] Some assets failed to cache:', err);
      });
    })
  );
  self.skipWaiting();
});

// Activate: clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    })
  );
  self.clients.claim();
});

// Fetch: network-first for API, cache-first for static assets
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Skip non-GET requests
  if (event.request.method !== 'GET') return;

  // Skip WebSocket upgrade requests
  if (url.protocol === 'ws:' || url.protocol === 'wss:') return;

  // API requests: network-first, no cache
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(event.request).catch(() => {
        return new Response(
          JSON.stringify({ success: false, error: 'Offline' }),
          { headers: { 'Content-Type': 'application/json' }, status: 503 }
        );
      })
    );
    return;
  }

  // Static assets: cache-first, fallback to network
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;

      return fetch(event.request).then((response) => {
        // Cache successful responses for static assets
        if (response.ok && !url.pathname.startsWith('/api/')) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, clone);
          });
        }
        return response;
      }).catch(() => {
        // If offline and not cached, serve the offline page for navigation requests
        if (event.request.mode === 'navigate') {
          return caches.match(OFFLINE_URL);
        }
        return new Response('Offline', { status: 503 });
      });
    })
  );
});

// Background message notification (for future push support)
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
