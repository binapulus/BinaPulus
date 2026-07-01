const CACHE_NAME = 'binaplus-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.json'
];

// Kurulum - dosyaları önbelleğe al
self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(ASSETS);
    })
  );
  self.skipWaiting();
});

// Aktivasyon - eski cache'leri temizle
self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.filter(function(k) { return k !== CACHE_NAME; })
            .map(function(k) { return caches.delete(k); })
      );
    })
  );
  self.clients.claim();
});

// Fetch - önce network, hata varsa cache
self.addEventListener('fetch', function(e) {
  e.respondWith(
    fetch(e.request)
      .then(function(response) {
        // Cevabı cache'e kaydet
        const clone = response.clone();
        caches.open(CACHE_NAME).then(function(cache) {
          cache.put(e.request, clone);
        });
        return response;
      })
      .catch(function() {
        // Network yoksa cache'den sun
        return caches.match(e.request);
      })
  );
});

// Push bildirimi al
self.addEventListener('push', function(e) {
  let data = { title: 'BinaPlus', body: 'Yeni bildirim var.' };
  try { data = e.data.json(); } catch(err) {}
  e.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      vibrate: [200, 100, 200],
      data: { url: data.url || '/' }
    })
  );
});

// Bildirimi tıklayınca uygulamayı aç
self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  e.waitUntil(
    clients.openWindow(e.notification.data.url || '/')
  );
});
