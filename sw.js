// Bina Yönetici Service Worker v3
const CACHE_NAME = 'bina-yonetici-v3';
const ASSETS = ['/', '/index.html'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});

// Firebase Cloud Messaging — Push bildirimleri
self.addEventListener('push', e => {
  if(!e.data) return;
  let payload = {};
  try { payload = e.data.json(); } catch(err) { payload = { notification: { title: 'Bina Yönetici', body: e.data.text() } }; }
  const { title = 'Bina Yönetici', body = '', icon = '/icon-192.png' } = payload.notification || {};
  e.waitUntil(
    self.registration.showNotification(title, { body, icon, badge: '/icon-192.png', vibrate: [200, 100, 200] })
  );
});

// Bildirime tıklanınca uygulamayı aç
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(clients.openWindow('/'));
});
