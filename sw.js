const CACHE_NAME = 'binaplus-v3';
const ASSETS = [
  '/BinaPulus/index.html',
  '/BinaPulus/manifest.json',
  '/BinaPulus/sw.js'
];

self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      // addAll yerine tek tek ekle - hata olursa atla
      return Promise.all(
        ASSETS.map(function(url) {
          return cache.add(url).catch(function(err) {
            console.warn('Cache eklenemedi:', url, err);
          });
        })
      );
    })
  );
  self.skipWaiting();
});

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

self.addEventListener('fetch', function(e) {
  // Sadece GET isteklerini yakala
  if(e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request)
      .then(function(response) {
        if(response && response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(function(cache) {
            cache.put(e.request, clone);
          });
        }
        return response;
      })
      .catch(function() {
        return caches.match(e.request);
      })
  );
});

self.addEventListener('push', function(e) {
  let data = { title: 'BinaPlus', body: 'Yeni bildirim var.' };
  try { data = e.data.json(); } catch(err) {}
  e.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/BinaPulus/icon-192.png',
      badge: '/BinaPulus/icon-192.png',
      vibrate: [200, 100, 200],
      data: { url: data.url || '/BinaPulus/' }
    })
  );
});

self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  e.waitUntil(clients.openWindow(e.notification.data.url || '/BinaPulus/'));
});
