// Sendu Service Worker - Offline Support
const CACHE_NAME = 'sendu-cache-v1';
const STATIC_CACHE = 'sendu-static-v1';
const DYNAMIC_CACHE = 'sendu-dynamic-v1';

// Assets to cache immediately on install
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/src/styles/tailwind.css',
  '/assets/branding/sendu-light.svg',
  '/assets/branding/sendu-dark.svg',
  // External CDN resources (will be fetched on first request)
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log('[SW] Installing Service Worker...');
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => {
        console.log('[SW] Caching static assets');
        return cache.addAll(STATIC_ASSETS.filter(url => url.startsWith('/')));
      })
      .then(() => self.skipWaiting())
      .catch((err) => {
        console.error('[SW] Failed to cache static assets:', err);
      })
  );
});

// Activate event - clean old caches
self.addEventListener('activate', (event) => {
  console.log('[SW] Activating Service Worker...');
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name !== STATIC_CACHE && name !== DYNAMIC_CACHE)
            .map((name) => {
              console.log('[SW] Deleting old cache:', name);
              return caches.delete(name);
            })
        );
      })
      .then(() => self.clients.claim())
  );
});

// Fetch strategies
const CACHE_FIRST_PATTERNS = [
  /\.(css|js|woff2?|ttf|eot|svg|png|jpg|jpeg|gif|ico|webp)$/i,
  /cdn\.jsdelivr\.net/,
  /unpkg\.com/,
  /fonts\.googleapis\.com/,
  /fonts\.gstatic\.com/,
];

const NETWORK_FIRST_PATTERNS = [
  /\/api\//,
  /\/share\//,
];

const NETWORK_ONLY_PATTERNS = [
  /\/api\/upload/,
  /\/api\/download/,
  /\/api\/auth/,
  /\/api\/admin/,
];

// Check if URL matches any pattern
const matchesPattern = (url, patterns) => {
  return patterns.some((pattern) => pattern.test(url));
};

// Cache-first strategy (for static assets)
const cacheFirst = async (request) => {
  const cachedResponse = await caches.match(request);
  if (cachedResponse) {
    return cachedResponse;
  }
  
  try {
    const networkResponse = await fetch(request);
    if (networkResponse.ok) {
      const cache = await caches.open(STATIC_CACHE);
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  } catch (error) {
    console.error('[SW] Cache-first fetch failed:', error);
    throw error;
  }
};

// Network-first strategy (for dynamic content)
const networkFirst = async (request) => {
  try {
    const networkResponse = await fetch(request);
    if (networkResponse.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  } catch (error) {
    console.log('[SW] Network failed, trying cache:', request.url);
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
      return cachedResponse;
    }
    throw error;
  }
};

// Stale-while-revalidate strategy
const staleWhileRevalidate = async (request) => {
  const cache = await caches.open(DYNAMIC_CACHE);
  const cachedResponse = await cache.match(request);
  
  const fetchPromise = fetch(request)
    .then((networkResponse) => {
      if (networkResponse.ok) {
        cache.put(request, networkResponse.clone());
      }
      return networkResponse;
    })
    .catch(() => null);
  
  return cachedResponse || fetchPromise;
};

// Main fetch handler
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = request.url;
  
  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }
  
  // Network only for upload/download/auth APIs
  if (matchesPattern(url, NETWORK_ONLY_PATTERNS)) {
    return;
  }
  
  // Cache first for static assets
  if (matchesPattern(url, CACHE_FIRST_PATTERNS)) {
    event.respondWith(cacheFirst(request));
    return;
  }
  
  // Network first for API calls
  if (matchesPattern(url, NETWORK_FIRST_PATTERNS)) {
    event.respondWith(networkFirst(request));
    return;
  }
  
  // Default: stale-while-revalidate for HTML pages
  if (request.headers.get('Accept')?.includes('text/html')) {
    event.respondWith(
      networkFirst(request).catch(() => {
        return caches.match('/index.html');
      })
    );
    return;
  }
  
  // Default strategy: network first
  event.respondWith(networkFirst(request));
});

// Background sync for failed uploads (future feature)
self.addEventListener('sync', (event) => {
  if (event.tag === 'upload-sync') {
    console.log('[SW] Background sync triggered for uploads');
    // TODO: Implement retry logic for failed uploads
  }
});

// Push notifications (future feature)
self.addEventListener('push', (event) => {
  if (event.data) {
    const data = event.data.json();
    const options = {
      body: data.body || 'Nueva notificación de Sendu',
      icon: '/assets/branding/sendu-dark.svg',
      badge: '/assets/branding/sendu-dark.svg',
      vibrate: [100, 50, 100],
      data: {
        url: data.url || '/',
      },
    };
    
    event.waitUntil(
      self.registration.showNotification(data.title || 'Sendu', options)
    );
  }
});

// Notification click handler
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  
  event.waitUntil(
    clients.openWindow(event.notification.data?.url || '/')
  );
});

// Message handler for cache control
self.addEventListener('message', (event) => {
  if (event.data?.action === 'skipWaiting') {
    self.skipWaiting();
  }
  
  if (event.data?.action === 'clearCache') {
    event.waitUntil(
      caches.keys().then((names) => {
        return Promise.all(names.map((name) => caches.delete(name)));
      })
    );
  }
});
