const CACHE_NAME = 'x39matrix-v13-20260828';
const URLS_TO_CACHE = ['/', '/index.html', '/manifest.json'];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(URLS_TO_CACHE)));
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const url = event.request.url;
  // API y sockets: nunca cache.
  if (event.request.method !== 'GET' || url.includes('/api/') || url.includes('socket.io')) {
    event.respondWith(fetch(event.request));
    return;
  }
  // /app/ (APK y ficheros de verificación del release): directo a la red, nunca cache.
  if (new URL(url).pathname.startsWith('/app/')) {
    event.respondWith(fetch(event.request));
    return;
  }
  // Navegaciones (index.html): red primero; cache solo sin red.
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).then(res => {
        // Solo se guarda como /index.html lo que de verdad es HTML.
        if ((res.headers.get('Content-Type') || '').includes('text/html')) {
          const copy = res.clone();
          caches.open(CACHE_NAME).then(cache => cache.put('/index.html', copy));
        }
        return res;
      }).catch(() => caches.match('/index.html'))
    );
    return;
  }
  // Resto (assets con hash en el nombre): cache primero.
  event.respondWith(caches.match(event.request).then(response => response || fetch(event.request)));
});
