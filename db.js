/**
 * BinaPlus — Veritabanı Katmanı (db.js)
 * ─────────────────────────────────────
 * Versiyon: 2.0
 *
 * KORUMA MEKANİZMALARI:
 *   1. Şifre Güvenliği       — Firebase yüklenmeden şifre kontrolü YAPILMAZ
 *   2. Yazma Koruma Penceresi — Kendi yazmandan sonra 3sn snapshot yoksayılır
 *   3. Çift Katman Yedek     — Her yazma localStorage'a da kopyalanır
 *   4. localStorage Geri Yük — Çevrimdışıyken localStorage'dan okur
 *
 * GENİŞLETME KURALI:
 *   Yeni modül eklemek için:
 *   1. COL objesine yol ekle
 *   2. Dosyanın altındaki YENİ MODÜL ŞABLONU'nu kopyala
 *   3. firestore.rules'a match bloğu ekle
 *   4. seed.json'a şema örneği ekle
 *   Mevcut fonksiyonlara dokunma.
 */

import { initializeApp, getApps } from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js';
import {
  getFirestore,
  collection, doc, getDoc, getDocs, addDoc, setDoc,
  updateDoc, deleteDoc, onSnapshot, serverTimestamp,
  query, where, orderBy, limit, writeBatch, runTransaction
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js';
import {
  getAuth, signInWithEmailAndPassword, signOut,
  updatePassword, onAuthStateChanged
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js';
import {
  getStorage, ref as storageRef, uploadBytes, getDownloadURL
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-storage.js';

// ── Firebase başlatma (çift başlatmayı önle) ──────────────────
const FIREBASE_CONFIG = {
  apiKey:            "AIzaSyD6vTEjXSx9yTBE7o_y-PgE9EQydFzt7Rs",
  authDomain:        "binapulus-4ae17.firebaseapp.com",
  projectId:         "binapulus-4ae17",
  storageBucket:     "binapulus-4ae17.firebasestorage.app",
  messagingSenderId: "74314699158",
  appId:             "1:74314699158:web:c8c4c40d9ab17960cccdb7",
  measurementId:     "G-LH3N7X20MQ"
};

const fbApp   = getApps().length ? getApps()[0] : initializeApp(FIREBASE_CONFIG);
export const auth    = getAuth(fbApp);
export const db      = getFirestore(fbApp);
export const storage = getStorage(fbApp);

// ── Firebase hazır sinyali ────────────────────────────────────
// Timeout ekli — maksimum 5 saniye bekle, sonra devam et
let _fbReady = false;
let _fbReadyResolve;
const fbReady = new Promise(res => { _fbReadyResolve = res; });

// 5 saniye timeout — askıda kalmasın
const _fbTimeout = setTimeout(() => {
  _fbReady = true;
  _fbReadyResolve();
}, 5000);

// Firestore'a basit bağlantı testi — hata da olsa hazır say
getDoc(doc(db, 'anayonetici', 'config'))
  .catch(() => {}) // 404 normal — sadece bağlantıyı test ediyoruz
  .finally(() => {
    clearTimeout(_fbTimeout);
    _fbReady = true;
    _fbReadyResolve();
  });

export async function waitFirebase() {
  if (_fbReady) return;
  await fbReady;
}

// ═══════════════════════════════════════════════════════════════
//  GÜVENLİK KATMANLARI
// ═══════════════════════════════════════════════════════════════

// ── 1. RATE LİMİTER ──────────────────────────────────────────
// Brute force koruması: 5 hatalı denemede 15 dakika kilit
const _rateLimiter = new Map();
// key: 'login:binaId:daireNo' veya 'login:email'
// value: { count, lockedUntil }

export const RateLimit = {
  MAX_ATTEMPTS: 5,
  LOCK_MS:      15 * 60 * 1000, // 15 dakika
  WARN_AT:      3,              // 3. denemede uyar

  check(key) {
    const rec = _rateLimiter.get(key);
    if (!rec) return { ok: true, remaining: this.MAX_ATTEMPTS };

    // Kilit süresi dolmuş mu?
    if (rec.lockedUntil && Date.now() > rec.lockedUntil) {
      _rateLimiter.delete(key);
      return { ok: true, remaining: this.MAX_ATTEMPTS };
    }

    // Hâlâ kilitli
    if (rec.lockedUntil) {
      const kalan = Math.ceil((rec.lockedUntil - Date.now()) / 60000);
      return { ok: false, locked: true, minutesLeft: kalan };
    }

    const remaining = this.MAX_ATTEMPTS - rec.count;
    return { ok: remaining > 0, remaining, count: rec.count };
  },

  fail(key) {
    const rec = _rateLimiter.get(key) || { count: 0 };
    rec.count++;
    if (rec.count >= this.MAX_ATTEMPTS) {
      rec.lockedUntil = Date.now() + this.LOCK_MS;
    }
    _rateLimiter.set(key, rec);
    return this.check(key);
  },

  reset(key) {
    _rateLimiter.delete(key);
  },

  // localStorage'a da yedekle (sayfa yenilemesinde sıfırlanmasın)
  persist(key) {
    try {
      const rec = _rateLimiter.get(key);
      if (rec) localStorage.setItem(`bp_rl_${key}`, JSON.stringify(rec));
    } catch(e) {}
  },

  restore(key) {
    try {
      const raw = localStorage.getItem(`bp_rl_${key}`);
      if (!raw) return;
      const rec = JSON.parse(raw);
      // Kilit süresi dolmuşsa yükleme
      if (!rec.lockedUntil || Date.now() < rec.lockedUntil) {
        _rateLimiter.set(key, rec);
      } else {
        localStorage.removeItem(`bp_rl_${key}`);
      }
    } catch(e) {}
  }
};

// ── 2. SALT'LI HASH ──────────────────────────────────────────
// SHA-256(şifre) yerine SHA-256(binaId + ":" + daireNo + ":" + şifre)
// Rainbow table saldırısını engeller.
// Salt = binaId + daireNo — sunucuya gönderilmez, client'ta hesaplanır.
export async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// Sakin şifre hash'i — salt eklenmiş
export async function hashSakinSifre(sifre, binaId, daireNo) {
  // Format: SHA-256("binaplus:binaId:daireNo:sifre")
  return sha256(`binaplus:${binaId}:${daireNo}:${sifre}`);
}

// Geriye dönük uyumluluk: eski salt'sız hash ile de dene
export async function hashSakinSifreLegacy(sifre) {
  return sha256(sifre);
}

// ── 3. ADMİN TOKEN — MEMORY ONLY ─────────────────────────────
// Token URL'de değil, memory'de tutulur.
// admin.html → index.html arası postMessage ile iletilir.
// sessionStorage'a YAZILMAZ → XSS riski azalır.
const _adminTokenStore = new Map();
// key: token, value: { binaId, expiresAt, used }

export const AdminToken = {
  EXPIRE_MS: 5 * 60 * 1000, // 5 dakika

  async create(masterSifre, binaId) {
    const timestamp = Date.now();
    const raw       = `binaplus:admin:${masterSifre}:${binaId}:${timestamp}`;
    const token     = await sha256(raw);
    _adminTokenStore.set(token, {
      binaId,
      expiresAt: timestamp + this.EXPIRE_MS,
      used: false
    });
    return { token, timestamp };
  },

  verify(token, binaId) {
    const rec = _adminTokenStore.get(token);
    if (!rec)                        return { ok: false, reason: 'token_not_found' };
    if (rec.used)                    return { ok: false, reason: 'token_used' };
    if (Date.now() > rec.expiresAt)  return { ok: false, reason: 'token_expired' };
    if (rec.binaId !== binaId)       return { ok: false, reason: 'bina_mismatch' };
    return { ok: true };
  },

  consume(token) {
    const rec = _adminTokenStore.get(token);
    if (rec) { rec.used = true; _adminTokenStore.set(token, rec); }
  },

  // Süresi dolmuş token'ları temizle
  cleanup() {
    const now = Date.now();
    for (const [k, v] of _adminTokenStore.entries()) {
      if (now > v.expiresAt || v.used) _adminTokenStore.delete(k);
    }
  }
};

// Her 5 dakikada bir eski token'ları temizle
setInterval(() => AdminToken.cleanup(), 5 * 60 * 1000);
const COL = {
  binalar:    (binaId)     => doc(db, 'binalar', binaId),
  daireler:   (binaId)     => collection(db, 'binalar', binaId, 'daireler'),
  daire:      (binaId, id) => doc(db, 'binalar', binaId, 'daireler', id),
  kasa:       (binaId)     => collection(db, 'binalar', binaId, 'kasa'),
  kasaDoc:    (binaId, id) => doc(db, 'binalar', binaId, 'kasa', id),
  kampanyalar:(binaId)     => collection(db, 'binalar', binaId, 'kampanyalar'),
  kampanya:   (binaId, id) => doc(db, 'binalar', binaId, 'kampanyalar', id),
  arizalar:   (binaId)     => collection(db, 'binalar', binaId, 'arizalar'),
  ariza:      (binaId, id) => doc(db, 'binalar', binaId, 'arizalar', id),
  duyurular:  (binaId)     => collection(db, 'binalar', binaId, 'duyurular'),
  duyuru:     (binaId, id) => doc(db, 'binalar', binaId, 'duyurular', id),
  faturalar:  (binaId)     => collection(db, 'binalar', binaId, 'faturalar'),
  fatura:     (binaId, id) => doc(db, 'binalar', binaId, 'faturalar', id),
  bakim:      (binaId)     => collection(db, 'binalar', binaId, 'bakim'),
  bakimDoc:   (binaId, id) => doc(db, 'binalar', binaId, 'bakim', id),
  firmalar:   (binaId)     => collection(db, 'binalar', binaId, 'firmalar'),
  firma:      (binaId, id) => doc(db, 'binalar', binaId, 'firmalar', id),
  settings:   (binaId)     => doc(db, 'binalar', binaId, 'settings', 'config'),
  adminConfig: ()          => doc(db, 'anayonetici', 'config'),
  adminLogs:  ()           => collection(db, 'anayonetici', 'logs'),
  // ── YENİ MODÜL EKLEMEK İÇİN BURAYA EKLE ──
};
export { COL };

// ── Yardımcı fonksiyonlar ─────────────────────────────────────
export function snapToArr(snap) {
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

export async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

const ts       = () => ({ guncellemeTarihi: serverTimestamp() });
const tsCreate = () => ({ olusturmaTarihi: serverTimestamp(), guncellemeTarihi: serverTimestamp() });

// ═══════════════════════════════════════════════════════════════
//  KORUMA 1: YAZMA KORUMA PENCERESİ
//  Sorun 2'nin çözümü: Kendi yazmandan sonra 3 saniye boyunca
//  o koleksiyona gelen onSnapshot güncellemeleri yoksayılır.
//  Bu sayede "kendi yazmam geri alındı" yanılgısı olmaz.
// ═══════════════════════════════════════════════════════════════
const _writeGuard = new Map(); // koleksiyon yolu → timestamp

function setWriteGuard(path) {
  _writeGuard.set(path, Date.now());
}

function isWriteGuarded(path) {
  const t = _writeGuard.get(path);
  if (!t) return false;
  if (Date.now() - t < 3000) return true; // 3 saniye koruma
  _writeGuard.delete(path);
  return false;
}

// ═══════════════════════════════════════════════════════════════
//  KORUMA 2: ÇİFT KATMAN YEDEK (localStorage)
//  Her başarılı Firestore yazmasından sonra veri localStorage'a
//  da kaydedilir. Çevrimdışında localStorage'dan okunur.
// ═══════════════════════════════════════════════════════════════
const LS = {
  KEY: (binaId, col) => `bp_${binaId}_${col}`,

  save(binaId, col, data) {
    try {
      localStorage.setItem(
        this.KEY(binaId, col),
        JSON.stringify({ data, ts: Date.now() })
      );
    } catch(e) {
      // localStorage dolu olabilir — sessizce geç
      console.warn('localStorage yazma hatası:', e.message);
    }
  },

  load(binaId, col) {
    try {
      const raw = localStorage.getItem(this.KEY(binaId, col));
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      // 7 günden eski localStorage verisini kullanma
      if (Date.now() - parsed.ts > 7 * 24 * 60 * 60 * 1000) {
        localStorage.removeItem(this.KEY(binaId, col));
        return null;
      }
      return parsed.data;
    } catch(e) {
      return null;
    }
  },

  // Tüm yedek anahtarlarını listele
  listKeys(binaId) {
    const prefix = `bp_${binaId}_`;
    return Object.keys(localStorage)
      .filter(k => k.startsWith(prefix))
      .map(k => k.replace(prefix, ''));
  },

  // Manuel yedek: tüm localStorage verisini JSON olarak indir
  exportJSON(binaId) {
    const result = {};
    this.listKeys(binaId).forEach(col => {
      result[col] = this.load(binaId, col);
    });
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `binaplus_yedek_${binaId}_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  },

  // Yedekten geri yükle
  async importJSON(binaId, jsonStr) {
    const data = JSON.parse(jsonStr);
    const results = [];
    for (const [col, arr] of Object.entries(data)) {
      if (!Array.isArray(arr)) continue;
      this.save(binaId, col, arr);
      results.push(col);
    }
    return results;
  }
};

export { LS };

// Snapshot'ı hem döndür hem localStorage'a kaydet
function snapAndCache(binaId, col, snap, cb) {
  const guardPath = `${binaId}/${col}`;
  if (isWriteGuarded(guardPath)) return; // ← Koruma penceresi aktif, yoksay
  const arr = snapToArr(snap);
  LS.save(binaId, col, arr);
  cb(arr);
}

// ═══════════════════════════════════════════════════════════════
//  BİNA META
// ═══════════════════════════════════════════════════════════════
export const BinaCRUD = {
  async getAll() {
    await waitFirebase();
    const snap = await getDocs(collection(db, 'binalar'));
    return snapToArr(snap);
  },
  async get(binaId) {
    await waitFirebase();
    const snap = await getDoc(COL.binalar(binaId));
    return snap.exists() ? { id: snap.id, ...snap.data() } : null;
  },
  async create(binaId, data) {
    await waitFirebase();
    await setDoc(COL.binalar(binaId), { ...data, ...tsCreate() });
  },
  async update(binaId, data) {
    await waitFirebase();
    await updateDoc(COL.binalar(binaId), { ...data, ...ts() });
  },
  async delete(binaId) {
    await waitFirebase();
    await deleteDoc(COL.binalar(binaId));
  },
};

// ═══════════════════════════════════════════════════════════════
//  SETTINGS (tek döküman)
// ═══════════════════════════════════════════════════════════════
export const SettingsCRUD = {
  async get(binaId) {
    await waitFirebase();
    const snap = await getDoc(COL.settings(binaId));
    if (snap.exists()) {
      LS.save(binaId, 'settings', snap.data());
      return snap.data();
    }
    // Çevrimdışı fallback
    return LS.load(binaId, 'settings') || {};
  },
  async set(binaId, data) {
    await waitFirebase();
    await setDoc(COL.settings(binaId), { ...data, ...ts() }, { merge: true });
    LS.save(binaId, 'settings', data);
  },
  onSnapshot(binaId, cb) {
    return onSnapshot(COL.settings(binaId), snap => {
      if (isWriteGuarded(`${binaId}/settings`)) return;
      const d = snap.exists() ? snap.data() : (LS.load(binaId, 'settings') || {});
      LS.save(binaId, 'settings', d);
      cb(d);
    });
  }
};

// ═══════════════════════════════════════════════════════════════
//  DAİRELER
// ═══════════════════════════════════════════════════════════════
export const DaireCRUD = {
  async getAll(binaId) {
    await waitFirebase();
    try {
      const snap = await getDocs(COL.daireler(binaId));
      const arr = snapToArr(snap);
      LS.save(binaId, 'daireler', arr);
      return arr;
    } catch(e) {
      // Çevrimdışı fallback
      return LS.load(binaId, 'daireler') || [];
    }
  },
  async get(binaId, daireId) {
    await waitFirebase();
    const snap = await getDoc(COL.daire(binaId, daireId));
    return snap.exists() ? { id: snap.id, ...snap.data() } : null;
  },
  async create(binaId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/daireler`);
    const ref = await addDoc(COL.daireler(binaId), { ...data, odemeler: {}, ...tsCreate() });
    return ref;
  },
  async update(binaId, daireId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/daireler`);
    await updateDoc(COL.daire(binaId, daireId), { ...data, ...ts() });
  },
  async delete(binaId, daireId) {
    await waitFirebase();
    setWriteGuard(`${binaId}/daireler`);
    await deleteDoc(COL.daire(binaId, daireId));
  },

  // ── Ödeme işaretle/kaldır (Transaction ile yarış koruması) ──
  // Sorun 2'nin tam çözümü: runTransaction ile atomik işlem.
  // İki cihaz aynı anda yazarsa Firestore çakışmayı kendisi çözer.
  async toggleOdeme(binaId, daireId, ayStr, tutar) {
    await waitFirebase();
    setWriteGuard(`${binaId}/daireler`);
    let eklendi = false;
    await runTransaction(db, async (transaction) => {
      const ref  = COL.daire(binaId, daireId);
      const snap = await transaction.get(ref);
      if (!snap.exists()) throw new Error('Daire bulunamadı');
      const odemeler = { ...(snap.data().odemeler || {}) };
      if (odemeler[ayStr]) {
        delete odemeler[ayStr];
        eklendi = false;
      } else {
        odemeler[ayStr] = {
          tarih:    new Date().toISOString(),
          tutar,
          makbuzNo: `MKB-${Date.now()}`
        };
        eklendi = true;
      }
      transaction.update(ref, { odemeler, ...ts() });
    });
    return eklendi;
  },

  onSnapshot(binaId, cb) {
    // Çevrimdışı başlangıç: localStorage'dan hemen göster
    const cached = LS.load(binaId, 'daireler');
    if (cached) cb(cached);
    return onSnapshot(COL.daireler(binaId), snap => {
      snapAndCache(binaId, 'daireler', snap, cb);
    });
  },

  // ── SAKİN GİRİŞİ ─────────────────────────────────────────
  // Koruması:
  //   1. waitFirebase() — Firebase hazır olmadan kontrol yok
  //   2. RateLimit      — 5 hatalı denemede 15 dk kilit
  //   3. Salt'lı hash   — rainbow table koruması
  async loginSakin(binaId, daireNo, sifre) {
    await waitFirebase();

    // Rate limit kontrolü
    const rlKey = `login:${binaId}:${daireNo}`;
    RateLimit.restore(rlKey);
    const rl = RateLimit.check(rlKey);

    if (!rl.ok) {
      if (rl.locked) {
        throw new Error(`Çok fazla hatalı deneme. ${rl.minutesLeft} dakika sonra tekrar deneyin.`);
      }
      throw new Error('Giriş engellendi.');
    }

    const q    = query(COL.daireler(binaId), where('daireNo', '==', daireNo));
    const snap = await getDocs(q);
    if (snap.empty) {
      // Daire bulunamasa da rate limit say — kullanıcı adı tespitini engelle
      RateLimit.fail(rlKey);
      RateLimit.persist(rlKey);
      throw new Error('Daire no veya şifre yanlış');
    }
    const daire = { id: snap.docs[0].id, ...snap.docs[0].data() };

    if (!daire.sifreHash) throw new Error('Bu daire için şifre tanımlanmamış. Yöneticinize başvurun.');

    // Salt'lı hash dene (yeni format)
    const saltedHash = await hashSakinSifre(sifre, binaId, daireNo);

    // Geriye dönük uyumluluk: eski salt'sız hash de kabul et
    const legacyHash = await hashSakinSifreLegacy(sifre);

    const hashMatch = daire.sifreHash === saltedHash || daire.sifreHash === legacyHash;

    if (!hashMatch) {
      const result = RateLimit.fail(rlKey);
      RateLimit.persist(rlKey);
      const kalan = result.remaining ?? 0;
      if (result.locked) {
        throw new Error(`Şifre yanlış. Çok fazla hatalı deneme — 15 dakika beklemeniz gerekiyor.`);
      }
      throw new Error(`Şifre yanlış. ${kalan > 0 ? `${kalan} deneme hakkınız kaldı.` : ''}`);
    }

    // Başarılı giriş — rate limit sıfırla
    RateLimit.reset(rlKey);
    localStorage.removeItem(`bp_rl_${rlKey}`);

    // Eski salt'sız hash varsa, salt'lı ile güncelle (sessiz migration)
    if (daire.sifreHash === legacyHash && daire.sifreHash !== saltedHash) {
      try {
        await updateDoc(COL.daire(binaId, daire.id), { sifreHash: saltedHash });
      } catch(e) { /* Sessiz — kritik değil */ }
    }

    return daire;
  }
};

// ═══════════════════════════════════════════════════════════════
//  KASA
// ═══════════════════════════════════════════════════════════════
export const KasaCRUD = {
  async getAll(binaId) {
    await waitFirebase();
    try {
      const snap = await getDocs(query(COL.kasa(binaId), orderBy('tarih', 'desc')));
      const arr  = snapToArr(snap);
      LS.save(binaId, 'kasa', arr);
      return arr;
    } catch(e) {
      return LS.load(binaId, 'kasa') || [];
    }
  },
  async create(binaId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/kasa`);
    return await addDoc(COL.kasa(binaId), { ...data, ...tsCreate() });
  },
  async update(binaId, kasaId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/kasa`);
    await updateDoc(COL.kasaDoc(binaId, kasaId), { ...data, ...ts() });
  },
  async delete(binaId, kasaId) {
    await waitFirebase();
    setWriteGuard(`${binaId}/kasa`);
    await deleteDoc(COL.kasaDoc(binaId, kasaId));
  },
  onSnapshot(binaId, cb) {
    const cached = LS.load(binaId, 'kasa');
    if (cached) cb(cached);
    return onSnapshot(
      query(COL.kasa(binaId), orderBy('tarih', 'desc')),
      snap => snapAndCache(binaId, 'kasa', snap, cb)
    );
  }
};

// ═══════════════════════════════════════════════════════════════
//  KAMPANYALAR
// ═══════════════════════════════════════════════════════════════
export const KampanyaCRUD = {
  async getAll(binaId) {
    await waitFirebase();
    try {
      const snap = await getDocs(COL.kampanyalar(binaId));
      const arr  = snapToArr(snap);
      LS.save(binaId, 'kampanyalar', arr);
      return arr;
    } catch(e) { return LS.load(binaId, 'kampanyalar') || []; }
  },
  async create(binaId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/kampanyalar`);
    return await addDoc(COL.kampanyalar(binaId), { ...data, toplunanTutar: 0, ...tsCreate() });
  },
  async update(binaId, kampId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/kampanyalar`);
    await updateDoc(COL.kampanya(binaId, kampId), { ...data, ...ts() });
  },
  async delete(binaId, kampId) {
    await waitFirebase();
    setWriteGuard(`${binaId}/kampanyalar`);
    await deleteDoc(COL.kampanya(binaId, kampId));
  },
  async setDurum(binaId, kampId, durum) {
    await waitFirebase();
    setWriteGuard(`${binaId}/kampanyalar`);
    await updateDoc(COL.kampanya(binaId, kampId), { durum, ...ts() });
  },
  onSnapshot(binaId, cb) {
    const cached = LS.load(binaId, 'kampanyalar');
    if (cached) cb(cached);
    return onSnapshot(COL.kampanyalar(binaId), snap => snapAndCache(binaId, 'kampanyalar', snap, cb));
  }
};

// ═══════════════════════════════════════════════════════════════
//  ARIZALAR
// ═══════════════════════════════════════════════════════════════
export const ArizaCRUD = {
  async getAll(binaId) {
    await waitFirebase();
    try {
      const snap = await getDocs(query(COL.arizalar(binaId), orderBy('bildirimTarihi', 'desc')));
      const arr  = snapToArr(snap);
      LS.save(binaId, 'arizalar', arr);
      return arr;
    } catch(e) { return LS.load(binaId, 'arizalar') || []; }
  },
  async create(binaId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/arizalar`);
    return await addDoc(COL.arizalar(binaId), {
      ...data, durum: 'bekliyor', fotograflar: [], yorumlar: [],
      bildirimTarihi: serverTimestamp(), ...tsCreate()
    });
  },
  async update(binaId, arizaId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/arizalar`);
    await updateDoc(COL.ariza(binaId, arizaId), { ...data, ...ts() });
  },
  async setDurum(binaId, arizaId, durum) {
    await waitFirebase();
    setWriteGuard(`${binaId}/arizalar`);
    const extra = durum === 'tamamlandi' ? { tamamlanmaTarihi: serverTimestamp() } : {};
    await updateDoc(COL.ariza(binaId, arizaId), { durum, ...extra, ...ts() });
  },
  async yorumEkle(binaId, arizaId, yorum) {
    await waitFirebase();
    setWriteGuard(`${binaId}/arizalar`);
    await runTransaction(db, async (t) => {
      const ref  = COL.ariza(binaId, arizaId);
      const snap = await t.get(ref);
      const yorumlar = [...(snap.data()?.yorumlar || []), { ...yorum, tarih: new Date().toISOString() }];
      t.update(ref, { yorumlar, ...ts() });
    });
  },
  async delete(binaId, arizaId) {
    await waitFirebase();
    setWriteGuard(`${binaId}/arizalar`);
    await deleteDoc(COL.ariza(binaId, arizaId));
  },
  async fotografYukle(binaId, arizaId, file) {
    await waitFirebase();
    const path = `arizalar/${binaId}/${arizaId}/${Date.now()}_${file.name}`;
    const r    = storageRef(storage, path);
    await uploadBytes(r, file);
    const url  = await getDownloadURL(r);
    setWriteGuard(`${binaId}/arizalar`);
    await runTransaction(db, async (t) => {
      const ref  = COL.ariza(binaId, arizaId);
      const snap = await t.get(ref);
      const fotograflar = [...(snap.data()?.fotograflar || []), url];
      t.update(ref, { fotograflar, ...ts() });
    });
    return url;
  },
  onSnapshot(binaId, cb) {
    const cached = LS.load(binaId, 'arizalar');
    if (cached) cb(cached);
    return onSnapshot(
      query(COL.arizalar(binaId), orderBy('bildirimTarihi', 'desc')),
      snap => snapAndCache(binaId, 'arizalar', snap, cb)
    );
  }
};

// ═══════════════════════════════════════════════════════════════
//  DUYURULAR
// ═══════════════════════════════════════════════════════════════
export const DuyuruCRUD = {
  async getAll(binaId) {
    await waitFirebase();
    try {
      const snap = await getDocs(query(COL.duyurular(binaId), orderBy('olusturmaTarihi', 'desc')));
      const arr  = snapToArr(snap);
      LS.save(binaId, 'duyurular', arr);
      return arr;
    } catch(e) { return LS.load(binaId, 'duyurular') || []; }
  },
  async create(binaId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/duyurular`);
    return await addDoc(COL.duyurular(binaId), {
      ...data, tarih: new Date().toLocaleDateString('tr-TR'), ...tsCreate()
    });
  },
  async delete(binaId, duyuruId) {
    await waitFirebase();
    setWriteGuard(`${binaId}/duyurular`);
    await deleteDoc(COL.duyuru(binaId, duyuruId));
  },
  onSnapshot(binaId, cb) {
    const cached = LS.load(binaId, 'duyurular');
    if (cached) cb(cached);
    return onSnapshot(
      query(COL.duyurular(binaId), orderBy('olusturmaTarihi', 'desc')),
      snap => snapAndCache(binaId, 'duyurular', snap, cb)
    );
  }
};

// ═══════════════════════════════════════════════════════════════
//  FATURALAR
// ═══════════════════════════════════════════════════════════════
export const FaturaCRUD = {
  async getAll(binaId) {
    await waitFirebase();
    try {
      const snap = await getDocs(query(COL.faturalar(binaId), orderBy('olusturmaTarihi', 'desc')));
      const arr  = snapToArr(snap);
      LS.save(binaId, 'faturalar', arr);
      return arr;
    } catch(e) { return LS.load(binaId, 'faturalar') || []; }
  },
  async create(binaId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/faturalar`);
    return await addDoc(COL.faturalar(binaId), { ...data, odendi: false, ...tsCreate() });
  },
  async toggleOdendi(binaId, faturaId) {
    await waitFirebase();
    setWriteGuard(`${binaId}/faturalar`);
    let odendi = false;
    await runTransaction(db, async (t) => {
      const ref  = COL.fatura(binaId, faturaId);
      const snap = await t.get(ref);
      odendi = !snap.data()?.odendi;
      t.update(ref, { odendi, odemeTarihi: odendi ? serverTimestamp() : null, ...ts() });
    });
    return odendi;
  },
  async delete(binaId, faturaId) {
    await waitFirebase();
    setWriteGuard(`${binaId}/faturalar`);
    await deleteDoc(COL.fatura(binaId, faturaId));
  },
  onSnapshot(binaId, cb) {
    const cached = LS.load(binaId, 'faturalar');
    if (cached) cb(cached);
    return onSnapshot(
      query(COL.faturalar(binaId), orderBy('olusturmaTarihi', 'desc')),
      snap => snapAndCache(binaId, 'faturalar', snap, cb)
    );
  }
};

// ═══════════════════════════════════════════════════════════════
//  BAKIM TAKVİMİ
// ═══════════════════════════════════════════════════════════════
export const BakimCRUD = {
  async getAll(binaId) {
    await waitFirebase();
    try {
      const snap = await getDocs(COL.bakim(binaId));
      const arr  = snapToArr(snap);
      LS.save(binaId, 'bakim', arr);
      return arr;
    } catch(e) { return LS.load(binaId, 'bakim') || []; }
  },
  async create(binaId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/bakim`);
    return await addDoc(COL.bakim(binaId), { ...data, ...tsCreate() });
  },
  async tamamlandi(binaId, bakimId) {
    await waitFirebase();
    setWriteGuard(`${binaId}/bakim`);
    await updateDoc(COL.bakimDoc(binaId, bakimId), {
      sonBakimTarihi: new Date().toISOString().split('T')[0], ...ts()
    });
  },
  async delete(binaId, bakimId) {
    await waitFirebase();
    setWriteGuard(`${binaId}/bakim`);
    await deleteDoc(COL.bakimDoc(binaId, bakimId));
  },
  onSnapshot(binaId, cb) {
    const cached = LS.load(binaId, 'bakim');
    if (cached) cb(cached);
    return onSnapshot(COL.bakim(binaId), snap => snapAndCache(binaId, 'bakim', snap, cb));
  }
};

// ═══════════════════════════════════════════════════════════════
//  FİRMA REHBERİ
// ═══════════════════════════════════════════════════════════════
export const FirmaCRUD = {
  async getAll(binaId) {
    await waitFirebase();
    try {
      const snap = await getDocs(COL.firmalar(binaId));
      const arr  = snapToArr(snap);
      LS.save(binaId, 'firmalar', arr);
      return arr;
    } catch(e) { return LS.load(binaId, 'firmalar') || []; }
  },
  async create(binaId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/firmalar`);
    return await addDoc(COL.firmalar(binaId), { ...data, ...tsCreate() });
  },
  async update(binaId, firmaId, data) {
    await waitFirebase();
    setWriteGuard(`${binaId}/firmalar`);
    await updateDoc(COL.firma(binaId, firmaId), { ...data, ...ts() });
  },
  async delete(binaId, firmaId) {
    await waitFirebase();
    setWriteGuard(`${binaId}/firmalar`);
    await deleteDoc(COL.firma(binaId, firmaId));
  },
  onSnapshot(binaId, cb) {
    const cached = LS.load(binaId, 'firmalar');
    if (cached) cb(cached);
    return onSnapshot(COL.firmalar(binaId), snap => snapAndCache(binaId, 'firmalar', snap, cb));
  }
};

// ═══════════════════════════════════════════════════════════════
//  ADMIN
// ═══════════════════════════════════════════════════════════════
export const AdminCRUD = {
  async getConfig() {
    await waitFirebase();
    const snap = await getDoc(COL.adminConfig());
    return snap.exists() ? snap.data() : null;
  },
  async setConfig(data) {
    await waitFirebase();
    await setDoc(COL.adminConfig(), { ...data, guncellemeTarihi: serverTimestamp() }, { merge: true });
  },
  async log(entry) {
    try {
      await addDoc(COL.adminLogs(), { ...entry, tarih: serverTimestamp() });
    } catch(e) {
      // Log yazma başarısız olursa sessizce geç — ana işlemi engelleme
      console.warn('Log yazma hatası:', e.message);
    }
  },
  async getLogs(limitSayi = 100) {
    await waitFirebase();
    const snap = await getDocs(query(COL.adminLogs(), orderBy('tarih', 'desc'), limit(limitSayi)));
    return snapToArr(snap);
  }
};

// ═══════════════════════════════════════════════════════════════
//  AUTH
// ═══════════════════════════════════════════════════════════════
export const AuthService = {
  async loginYonetici(email, password) {
    await waitFirebase();

    // Rate limit kontrolü — e-posta bazlı
    const rlKey = `login:yonetici:${email.toLowerCase()}`;
    RateLimit.restore(rlKey);
    const rl = RateLimit.check(rlKey);
    if (!rl.ok && rl.locked) {
      throw new Error(`Çok fazla hatalı deneme. ${rl.minutesLeft} dakika sonra tekrar deneyin.`);
    }

    try {
      const cred = await signInWithEmailAndPassword(auth, email, password);
      RateLimit.reset(rlKey);
      localStorage.removeItem(`bp_rl_${rlKey}`);
      return cred;
    } catch(e) {
      const result = RateLimit.fail(rlKey);
      RateLimit.persist(rlKey);
      if (result.locked) {
        throw new Error('Çok fazla hatalı deneme. 15 dakika sonra tekrar deneyin.');
      }
      const kalan = result.remaining ?? 0;
      // Firebase hata mesajlarını Türkçeleştir
      if (e.code === 'auth/wrong-password' || e.code === 'auth/invalid-credential') {
        throw new Error(`E-posta veya şifre yanlış.${kalan > 0 ? ` ${kalan} deneme hakkınız kaldı.` : ''}`);
      }
      if (e.code === 'auth/user-not-found') {
        throw new Error('Bu e-posta ile kayıtlı hesap bulunamadı.');
      }
      if (e.code === 'auth/too-many-requests') {
        throw new Error('Firebase: Çok fazla istek. Lütfen bekleyin.');
      }
      throw new Error(e.message || 'Giriş başarısız');
    }
  },
  async logout() {
    await signOut(auth);
  },
  async updatePassword(newPassword) {
    if (!auth.currentUser) throw new Error('Giriş yapılmamış');
    await updatePassword(auth.currentUser, newPassword);
  },
  onStateChange(cb) {
    return onAuthStateChanged(auth, cb);
  }
};

// ═══════════════════════════════════════════════════════════════
//  TOPLU SUBSCRIPTION
//  Yazma koruma penceresi snapAndCache üzerinden otomatik çalışır.
//  Çevrimdışıyken cached veriden başlar, bağlantı gelince güncellenir.
// ═══════════════════════════════════════════════════════════════
export function subscribeBina(binaId, callbacks) {
  const unsubs = [];
  const {
    onSettings, onDaireler, onKasa, onKampanyalar,
    onArizalar, onDuyurular, onFaturalar, onBakim, onFirmalar
  } = callbacks;

  if (onSettings)    unsubs.push(SettingsCRUD.onSnapshot(binaId, onSettings));
  if (onDaireler)    unsubs.push(DaireCRUD.onSnapshot(binaId, onDaireler));
  if (onKasa)        unsubs.push(KasaCRUD.onSnapshot(binaId, onKasa));
  if (onKampanyalar) unsubs.push(KampanyaCRUD.onSnapshot(binaId, onKampanyalar));
  if (onArizalar)    unsubs.push(ArizaCRUD.onSnapshot(binaId, onArizalar));
  if (onDuyurular)   unsubs.push(DuyuruCRUD.onSnapshot(binaId, onDuyurular));
  if (onFaturalar)   unsubs.push(FaturaCRUD.onSnapshot(binaId, onFaturalar));
  if (onBakim)       unsubs.push(BakimCRUD.onSnapshot(binaId, onBakim));
  if (onFirmalar)    unsubs.push(FirmaCRUD.onSnapshot(binaId, onFirmalar));

  return () => unsubs.forEach(u => u());
}

// ═══════════════════════════════════════════════════════════════
//  MANUEL YEDEK API (index.html'den çağrılır)
// ═══════════════════════════════════════════════════════════════
export const YedekService = {
  // localStorage'daki tüm veriyi JSON olarak indir
  exportLocal(binaId) {
    LS.exportJSON(binaId);
  },

  // Firestore'dan taze veri çek, hem LS'e hem JSON'a yaz
  async exportFirestore(binaId) {
    await waitFirebase();
    const [daireler, kasa, kampanyalar, arizalar, duyurular, faturalar, bakim, firmalar, settings] =
      await Promise.all([
        DaireCRUD.getAll(binaId),
        KasaCRUD.getAll(binaId),
        KampanyaCRUD.getAll(binaId),
        ArizaCRUD.getAll(binaId),
        DuyuruCRUD.getAll(binaId),
        FaturaCRUD.getAll(binaId),
        BakimCRUD.getAll(binaId),
        FirmaCRUD.getAll(binaId),
        SettingsCRUD.get(binaId),
      ]);
    const data = { binaId, tarih: new Date().toISOString(), daireler, kasa, kampanyalar, arizalar, duyurular, faturalar, bakim, firmalar, settings };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `binaplus_tam_yedek_${binaId}_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    return data;
  },

  // JSON dosyasından Firestore'a geri yükle (batch write)
  async importFirestore(binaId, jsonStr) {
    await waitFirebase();
    const data   = JSON.parse(jsonStr);
    const batch  = writeBatch(db);
    let   count  = 0;

    const colMap = {
      daireler:    (d) => doc(COL.daireler(binaId), d.id),
      kasa:        (d) => doc(COL.kasa(binaId), d.id),
      kampanyalar: (d) => doc(COL.kampanyalar(binaId), d.id),
      arizalar:    (d) => doc(COL.arizalar(binaId), d.id),
      duyurular:   (d) => doc(COL.duyurular(binaId), d.id),
      faturalar:   (d) => doc(COL.faturalar(binaId), d.id),
      bakim:       (d) => doc(COL.bakim(binaId), d.id),
      firmalar:    (d) => doc(COL.firmalar(binaId), d.id),
    };

    for (const [col, arr] of Object.entries(colMap)) {
      if (!Array.isArray(data[col])) continue;
      data[col].forEach(item => {
        const { id, ...rest } = item;
        batch.set(colMap[col]({ id }), rest, { merge: true });
        count++;
      });
    }

    if (data.settings) {
      batch.set(COL.settings(binaId), data.settings, { merge: true });
      count++;
    }

    await batch.commit();
    return count;
  }
};

// ── YENİ MODÜL ŞABLONU ────────────────────────────────────────
// Kopyala, adını ve col adını değiştir:
//
// export const YeniModulCRUD = {
//   async getAll(binaId) {
//     await waitFirebase();
//     try {
//       const snap = await getDocs(COL.yeniModul(binaId));
//       const arr  = snapToArr(snap);
//       LS.save(binaId, 'yeniModul', arr);
//       return arr;
//     } catch(e) { return LS.load(binaId, 'yeniModul') || []; }
//   },
//   async create(binaId, data) {
//     await waitFirebase();
//     setWriteGuard(`${binaId}/yeniModul`);
//     return await addDoc(COL.yeniModul(binaId), { ...data, ...tsCreate() });
//   },
//   async update(binaId, docId, data) {
//     await waitFirebase();
//     setWriteGuard(`${binaId}/yeniModul`);
//     await updateDoc(doc(db,'binalar',binaId,'yeniModul',docId), { ...data, ...ts() });
//   },
//   async delete(binaId, docId) {
//     await waitFirebase();
//     setWriteGuard(`${binaId}/yeniModul`);
//     await deleteDoc(doc(db,'binalar',binaId,'yeniModul',docId));
//   },
//   onSnapshot(binaId, cb) {
//     const cached = LS.load(binaId, 'yeniModul');
//     if (cached) cb(cached);
//     return onSnapshot(COL.yeniModul(binaId), snap => snapAndCache(binaId, 'yeniModul', snap, cb));
//   }
// };
