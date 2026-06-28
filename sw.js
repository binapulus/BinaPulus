/**
 * BinaPlus — Service Worker
 * Versiyon: 1.0
 * Görev: PWA offline desteği, logo ve statik dosya önbelleği
 */

const CACHE_NAME   = 'binaplus-v1';
const LOGO_CACHE   = 'binaplus-assets-v1';

// Önbelleğe alınacak statik dosyalar
const STATIC_FILES = [
  './',
  './index.html',
  './logo.svg',
  './logo-icon.svg',
  './manifest.json',
  'https://fonts.googleapis.com/css2?family=Nunito:wght@400;500;600;700;800;900&display=swap',
];

// ── Kurulum ──────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(STATIC_FILES).catch(err => {
        console.warn('SW: Bazı dosyalar önbelleğe alınamadı:', err);
      });
    })
  );
  self.skipWaiting();
});

// ── Aktivasyon — eski cache'leri temizle ─────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k !== CACHE_NAME && k !== LOGO_CACHE)
          .map(k => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

// ── Fetch — önce cache, sonra network ───────────────
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Firebase, Google Fonts API isteklerini direkt geçir
  if (
    url.hostname.includes('firebaseio.com') ||
    url.hostname.includes('googleapis.com') ||
    url.hostname.includes('firebaseapp.com') ||
    url.hostname.includes('firebase.google.com') ||
    url.hostname.includes('emailjs.com') ||
    url.pathname.includes('/v1/messages')
  ) {
    return; // SW bypass
  }

  // SVG logo ve statik dosyalar → Cache First
  if (
    url.pathname.endsWith('.svg') ||
    url.pathname.endsWith('.png') ||
    url.pathname.endsWith('.json') ||
    url.pathname.includes('fonts.gstatic.com')
  ) {
    event.respondWith(
      caches.match(event.request).then(cached => {
        return cached || fetch(event.request).then(response => {
          const clone = response.clone();
          caches.open(LOGO_CACHE).then(cache => cache.put(event.request, clone));
          return response;
        });
      })
    );
    return;
  }

  // HTML dosyaları → Network First, fallback cache
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          return response;
        })
        .catch(() => caches.match('./index.html'))
    );
    return;
  }

  // Diğerleri → Stale While Revalidate
  event.respondWith(
    caches.match(event.request).then(cached => {
      const fetched = fetch(event.request).then(response => {
        caches.open(CACHE_NAME).then(cache => cache.put(event.request, response.clone()));
        return response;
      }).catch(() => {});
      return cached || fetched;
    })
  );
});

// ── Push Bildirimleri ────────────────────────────────
self.addEventListener('push', event => {
  if (!event.data) return;
  let data;
  try { data = event.data.json(); }
  catch(e) { data = { title: 'BinaPlus', body: event.data.text() }; }

  event.waitUntil(
    self.registration.showNotification(data.title || 'BinaPlus', {
      body:    data.body    || '',
      icon:    './logo-icon.svg',
      badge:   './logo-icon.svg',
      tag:     data.tag     || 'binaplus',
      data:    data.url     || './',
      vibrate: [200, 100, 200],
      actions: data.actions || [],
    })
  );
});

// ── Bildirime tıklama ────────────────────────────────
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data || './';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(wins => {
      const existing = wins.find(w => w.url.includes('binaplus'));
      if (existing) { existing.focus(); existing.navigate(url); }
      else clients.openWindow(url);
    })
  );
});
