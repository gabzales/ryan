const express = require('express');
const cookieSession = require('cookie-session');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const https = require('https');
const multer = require('multer');
const crypto = require('crypto');
const ghostSellerApi = require('./ghostseller-api');
// reseller-api.js (vipibmstore) dicabut total -- file-nya udah dihapus dari
// repo. Auto-restock sekarang cuma lewat GhostSeller (ghostseller-api.js).

// Load .env FIRST before anything reads process.env
require('dotenv').config();

// PENTING — KEAMANAN: session cookie ditandatangani (signed) pakai secret ini.
// Sebelumnya ada fallback string HARDCODED di source code
// ('ghostseller-fallback-secret-2024-xK9mP3qR' (nama proyek asal contoh ini)). Itu lubang keamanan serius:
// siapa pun yang baca source code ini (termasuk lewat zip project ini) bisa
// tahu secret-nya, lalu memalsukan cookie session sendiri — termasuk bikin
// cookie isAdmin:true atau menyamar jadi reseller manapun untuk menguras
// saldo wallet mereka — TANPA perlu password sama sekali.
// Sekarang: kalau SESSION_SECRET tidak di-set, generate secret acak yang
// unik per kali server nyala (bukan string tetap yang bisa dibaca orang).
// Konsekuensinya session akan ke-reset tiap restart server kalau kamu belum
// set SESSION_SECRET — supaya aman SEKALIGUS stabil di production, WAJIB
// set SESSION_SECRET di environment variables (Vercel/hosting kamu).
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Production warning tapi JANGAN exit — Vercel kadat lambat inject env
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.warn('⚠️  SESSION_SECRET belum di-set! Pakai secret acak sementara (reset tiap restart server).');
  console.warn('⚠️  WAJIB set SESSION_SECRET di environment variables untuk keamanan & session yang stabil.');
}

// Load DB module AFTER dotenv so env vars are available
const db = require('./supabase');

const app = express();
const PORT = process.env.PORT || 3000;

// Rate limiting untuk QR Code
const qrRateLimit = new Map();
const QR_RATE_LIMIT = 30;
const QR_RATE_WINDOW = 60000;

// Rate limiting untuk login (brute force protection)
const loginFailMap = new Map();
const LOGIN_MAX_FAIL = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 menit

const checkLoginBlocked = (ip) => {
  const rec = loginFailMap.get(ip);
  if (!rec) return { blocked: false };
  if (Date.now() > rec.resetAt) { loginFailMap.delete(ip); return { blocked: false }; }
  return { blocked: rec.count >= LOGIN_MAX_FAIL, wait: Math.ceil((rec.resetAt - Date.now()) / 60000) };
};

const recordLoginFail = (ip) => {
  const now = Date.now();
  const rec = loginFailMap.get(ip);
  if (!rec || now > rec.resetAt) loginFailMap.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
  else { rec.count++; loginFailMap.set(ip, rec); }
};

const clearLoginFail = (ip) => loginFailMap.delete(ip);

// ── Cloudflare Turnstile verification ────────────────────────────────────────
async function verifyTurnstile(token) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) return true; // Turnstile tidak dikonfigurasi, skip verifikasi

  return new Promise((resolve) => {
    const body = JSON.stringify({
      secret,
      response: token,
    });

    const options = {
      hostname: 'challenges.cloudflare.com',
      path: '/turnstile/v0/siteverify',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.success === true);
        } catch {
          resolve(false);
        }
      });
    });

    req.on('error', () => resolve(false));
    req.write(body);
    req.end();
  });
}
// ─────────────────────────────────────────────────────────────────────────────

// Invoice rate limiting (cegah brute force order code enumeration)
const invoiceRateMap = new Map();
const INVOICE_RATE_LIMIT = 10;
const INVOICE_RATE_WINDOW = 5 * 60 * 1000;

const checkInvoiceRateLimit = (ip) => {
  const now = Date.now();
  const rec = invoiceRateMap.get(ip);
  if (!rec || now > rec.resetAt) {
    invoiceRateMap.set(ip, { count: 1, resetAt: now + INVOICE_RATE_WINDOW });
    return true;
  }
  if (rec.count >= INVOICE_RATE_LIMIT) return false;
  rec.count++;
  return true;
};

// API rate limiting untuk endpoint publik
const apiRateMap = new Map();
const checkApiRateLimit = (ip, limit = 60, windowMs = 60000) => {
  const now = Date.now();
  const rec = apiRateMap.get(ip);
  if (!rec || now > rec.resetAt) {
    apiRateMap.set(ip, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (rec.count >= limit) return false;
  rec.count++;
  return true;
};

// ── RATE LIMIT KHUSUS PEMBAYARAN (kebijakan wajib GensPay per 15 Agustus 2026) ──
// GensPay memblokir IP yang melakukan polling/generate QRIS berlebihan
// ("high-frequency request") dan mewajibkan merchant membatasi maksimal
// 30 request / 3 menit PER PENGGUNA untuk endpoint create-order &
// check-payment. Dibatasi per user ID (bukan per IP) karena endpoint ini
// sudah requireAuth — lebih akurat dan tidak mengganggu user lain yang
// kebetulan satu jaringan/NAT dengan user yang memang sedang di-throttle.
const paymentRateMap = new Map();
const PAYMENT_RATE_LIMIT = 30;
const PAYMENT_RATE_WINDOW = 3 * 60 * 1000;
const checkPaymentRateLimit = (userId) => {
  const now = Date.now();
  const rec = paymentRateMap.get(userId);
  if (!rec || now > rec.resetAt) {
    paymentRateMap.set(userId, { count: 1, resetAt: now + PAYMENT_RATE_WINDOW });
    return true;
  }
  if (rec.count >= PAYMENT_RATE_LIMIT) return false;
  rec.count++;
  return true;
};
// Bersihkan entry basi tiap 10 menit supaya Map tidak numpuk terus di memory.
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of paymentRateMap) if (now > v.resetAt) paymentRateMap.delete(k);
}, 10 * 60 * 1000);

// Lock set untuk mencegah race condition pada alokasi key
const processingOrders = new Set();

// Ring-buffer log webhook masuk (in-memory, reset tiap restart server) --
// dipakai buat diagnosis "auto-send masih ga jalan": tanpa ini tidak bisa
// tahu apakah GensPay/Pakasir SEBENARNYA sudah pernah kirim webhook ke
// server ini sama sekali (Webhook URL belum keisi di dashboard gateway),
// atau webhook masuk tapi gagal diproses (invalid_signature, event tidak
// dikenali, dll). Lihat via /debug/genspay?secret=...&webhookLog=1.
const webhookLog = [];
function logWebhook(gateway, entry) {
  webhookLog.unshift({ gateway, time: new Date().toISOString(), ...entry });
  if (webhookLog.length > 30) webhookLog.length = 30;
}

// Lock per-user untuk operasi wallet (beli pakai saldo). Tanpa ini, dua
// request /wallet/buy yang nyaris bersamaan (double-click, atau script abuse)
// bisa sama-sama baca saldo & stok key SEBELUM salah satu sempat nulis balik
// — hasilnya: saldo cuma kepotong sekali tapi key kekirim dua kali (double-spend).
const walletLocks = new Set();

const checkQrRateLimit = (ip) => {
  const now = Date.now();
  const record = qrRateLimit.get(ip);
  if (record) {
    const windowStart = now - QR_RATE_WINDOW;
    const recentRequests = record.filter(ts => ts > windowStart);
    if (recentRequests.length >= QR_RATE_LIMIT) {
      return false;
    }
    recentRequests.push(now);
    qrRateLimit.set(ip, recentRequests);
  } else {
    qrRateLimit.set(ip, [now]);
  }
  return true;
};

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout');
app.set('trust proxy', 1);
app.use(expressLayouts);
// `verify` di sini nyimpen raw body string ke req.rawBody -- dibutuhkan
// khusus buat verifikasi signature webhook GensPay (lihat app.post('/webhook/genspay')),
// karena signature dihitung dari string JSON MENTAH persis seperti yang
// dikirim GensPay, bukan dari object hasil re-serialize (urutan key bisa
// beda kalau di-JSON.stringify ulang dari object yang sudah di-parse).
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf.toString('utf8'); }
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
app.use('/uploads/avatars', express.static(path.join(__dirname, 'public/uploads/avatars')));

// Fallback eksplisit untuk /uploads/logo-gn.png dan /uploads/banner-reseller.jpg.
// SEBELUMNYA route ini redirect ke Supabase Storage (bucket product-images),
// yang MENGHARUSKAN file itu di-upload manual ke Supabase dulu — kalau lupa,
// hasilnya logo/banner rusak (404) walau file-nya sudah ada di project.
// File-file ini adalah aset statis yang ikut ke-bundle oleh Vercel (lihat
// "includeFiles" di vercel.json), jadi paling aman langsung baca & kirim
// dari disk — tidak bergantung ke Supabase Storage sama sekali.
app.get('/uploads/logo-gn.png', (req, res) => {
  const filePath = path.join(__dirname, 'public/uploads/logo-gn.png');
  if (fs.existsSync(filePath)) {
    res.setHeader('Cache-Control', 'public, max-age=3600');
    return res.sendFile(filePath);
  }
  // Fallback terakhir kalau file benar-benar hilang dari bundle
  res.setHeader('Content-Type', 'image/svg+xml');
  res.send('<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 40 40"><rect width="40" height="40" rx="8" fill="#2563eb"/><text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" fill="#fff" font-size="14" font-weight="bold">GN</text></svg>');
});
app.get('/uploads/banner-reseller.jpg', (req, res) => {
  const filePath = path.join(__dirname, 'public/uploads/banner-reseller.jpg');
  if (fs.existsSync(filePath)) {
    res.setHeader('Cache-Control', 'public, max-age=3600');
    return res.sendFile(filePath);
  }
  res.status(404).send('Banner not found');
});

app.use(cookieSession({
  name: 'vpr_session',
  secret: SESSION_SECRET,
  maxAge: 7 * 24 * 60 * 60 * 1000,
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
}));

// ── FIX: Regenerate session object tiap request (cookie-session quirk) ──
app.use((req, res, next) => {
  // Pastikan session object tidak null
  if (!req.session) req.session = {};
  next();
});

// Inject settings + isAdmin ke semua view otomatis
app.use(async (req, res, next) => {
  // Kalau cache settings kosong, fetch dari Supabase dulu
  let settings = readDB('settings.json');
  if (!settings || Object.keys(settings).length === 0) {
    settings = await db.readFresh('settings.json').catch(() => ({}));
  }
  res.locals.settings = settings || {};
  res.locals.isAdmin = !!(req.session?.isAdmin || req.session?.userId === 'admin');
  res.locals.user = getSessionUser(req);
  next();
});

// Setup upload — gunakan /tmp di Vercel (satu-satunya writable path)
const isVercel = process.env.VERCEL === '1' || process.env.NOW_REGION;
const uploadsBase = isVercel ? '/tmp' : path.join(__dirname, 'public', 'uploads');
const uploadsDir = isVercel ? '/tmp/products' : path.join(__dirname, 'public', 'uploads', 'products');

// Buat direktori lokal hanya jika bukan Vercel
if (!isVercel) {
  if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = isVercel ? '/tmp/products' : path.join(__dirname, 'public', 'uploads', 'products');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${uuidv4()}${mimeToSafeExt(file.mimetype)}`;
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Hanya file gambar yang diizinkan'), false);
  }
};

// ── SECURITY: ekstensi file HARUS ditentukan dari mimetype yang sudah
// divalidasi di atas, JANGAN dari file.originalname (nama file dikirim
// client dan gampang dipalsukan — mimetype juga bisa dipalsukan, tapi
// setidaknya ini menutup celah "upload shell.php dengan Content-Type
// image/jpeg" supaya file tidak ikut tersimpan dengan ekstensi .php dll).
const mimeToSafeExt = (mimetype) => ({
  'image/jpeg': '.jpg', 'image/jpg': '.jpg', 'image/png': '.png',
  'image/gif': '.gif', 'image/webp': '.webp'
}[mimetype] || '.jpg');

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: fileFilter
});

// Database helpers (Supabase)
const dbPath = path.join(__dirname, 'database');
if (!isVercel && !fs.existsSync(dbPath)) fs.mkdirSync(dbPath, { recursive: true });

const readDB = db.readDB;
const writeDB = db.writeDB;
const readFresh = db.readFresh;

// Banner lama (seed default "Open Reseller") tersimpan tanpa field `id` dan
// pakai key `url` bukan `imageUrl` — akibatnya tombol "Hapus"/"Toggle" di
// admin panel selalu gagal mencocokkan banner tersebut (id undefined !== id
// yang dikirim dari client) sehingga banner itu seolah tidak bisa dihapus.
// Banner default ini memang tidak diperlukan, jadi begitu terbaca langsung
// dibuang otomatis. Banner lain yang memang tidak punya `id` (kasus lama
// lainnya) tetap dipertahankan, hanya dibenahi id & imageUrl-nya.
function normalizeBanners(settings) {
  if (!Array.isArray(settings.banners)) return false;
  let changed = false;
  const isLegacyDefaultReseller = b => !b.id && b.url === '/uploads/banner-reseller.jpg' && b.title === 'Open Reseller' && b.link === '/reseller';
  const filtered = settings.banners.filter(b => !isLegacyDefaultReseller(b));
  if (filtered.length !== settings.banners.length) { settings.banners = filtered; changed = true; }
  settings.banners.forEach(b => {
    if (!b.id) { b.id = uuidv4(); changed = true; }
    if (!b.imageUrl && b.url) { b.imageUrl = b.url; changed = true; }
  });
  return changed;
}
const readSmart = db.readSmart; // TTL-based: auto-refresh jika cache >8 detik
const refreshForWrite = (...files) => Promise.all(files.map(f => db.refreshFromDB(f)));

// Initialize database files with defaults (only if truly missing)
const initDB = async () => {
  // JANGAN hardcode username/password admin di source code (ini yang
  // sebelumnya bocor lewat GitHub). Kalau env var tidak diset, generate
  // password random tiap kali server start dari nol, dan print SEKALI ke
  // log server (bukan ke kode) supaya bisa langsung dipakai lalu diganti.
  const crypto = require('crypto');
  const fallbackUsername = process.env.INITIAL_ADMIN_USERNAME || 'admin';
  // PENTING: JANGAN pernah taruh password default tetap di sini (mis. string
  // hardcoded) — itu persis penyebab kebocoran sebelumnya lewat repo publik.
  // Kalau INITIAL_ADMIN_PASSWORD tidak diset, generate password RANDOM tiap
  // kali initDB jalan dari nol, lalu print SEKALI ke log server (bukan ke
  // kode) supaya bisa langsung dipakai lalu WAJIB diganti dari Admin Panel.
  const fallbackPassword = process.env.INITIAL_ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  if (!process.env.INITIAL_ADMIN_PASSWORD) {
    console.log(`🔐 Admin default (SEKALI TAMPIL, dicatat di log server): username="${fallbackUsername}" / password="${fallbackPassword}"`);
    console.log('   Segera login & ganti password ini dari Admin Panel. Set INITIAL_ADMIN_PASSWORD di env untuk kontrol penuh.');
  }
  const defaultSettings = {
    siteName: 'RYAN NEW ERA',
    gamePanelName: 'RYANEWERA',
    about: 'RYANEWERA menyediakan layanan topup games dan key mod aplikasi premium terbaik #1 indonesia.',
    marqueeText: 'LAYANAN GAME MOD MENU PREMIUM - PROSES CEPAT & AMAN',
    contact: {
      // Placeholder -- isi kontak asli lewat Admin Panel > Settings sebelum go-live.
      whatsapp: '',
      telegram: '',
      email: '',
      waChannel: '',
      waGroup: '',
    },
    fonnteToken: '',
    genspay: { apiKey: '', baseUrl: 'https://genspay.my.id/api/v1' },
    pakasir: { apiKey: '', project: '', apiBaseUrl: 'app.pakasir.com' },
    adminUsername: fallbackUsername,
    adminPassword: bcrypt.hashSync(fallbackPassword, 12),
    logoUrl: '/uploads/logo-gn-icon.jpg',
    categories: ['freefire', 'mlbb', 'pubgm', 'sertifikat'],
    categoryLabels: { freefire: 'FREE FIRE', mlbb: 'MOBILE LEGENDS', pubgm: 'PUBG MOBILE', sertifikat: 'SERTIFIKAT' },
    resellerEnabled: true,
    resellerPrice: 50000,
    resellerDiscount: 20,
    resellerNote: 'Dapatkan diskon eksklusif untuk semua produk!',
    resellerMinDeposit: 100000,
    popularProductIds: [],
    banners: [],
    // Batas jumlah produk yang ditampilkan di grid halaman utama (dashboard
    // publik). Ditambahkan supaya halaman utama tidak lag kalau produk sudah
    // ratusan — sisanya bisa dilihat di halaman "/produk" (lihat semua).
    homeProductsLimit: 10
  };

  const arrayFiles = ['users.json', 'products.json', 'transactions.json', 'testimonials.json', 'notifications.json', 'keyspool.json', 'vouchers.json'];

  // Seed arrays only if they don't exist at all
  for (const filename of arrayFiles) {
    const current = readDB(filename);
    if (!Array.isArray(current)) {
      await writeDB(filename, []);
    }
  }

  // Settings: merge defaults + existing. Jangan overwrite data yang sudah ada.
  const currentSettings = readDB('settings.json');
  if (!currentSettings || Object.keys(currentSettings).length === 0) {
    // Supabase kosong — push default penuh
    await writeDB('settings.json', defaultSettings);
    console.log('✅ Settings seeded with defaults');
  } else {
    // Merge: tambah field yang belum ada, jangan overwrite yang sudah ada
    let dirty = false;
    for (const [k, v] of Object.entries(defaultSettings)) {
      if (currentSettings[k] === undefined || currentSettings[k] === null) {
        currentSettings[k] = v;
        dirty = true;
      }
    }
    if (dirty) {
      await writeDB('settings.json', currentSettings);
      console.log('✅ Settings merged missing fields');
    }
  }
};

// Vercel: export app langsung (Vercel tidak pakai app.listen)
// Lokal: jalankan server setelah DB siap
if (isVercel) {
  // ── VERCEL FIX: pastikan DB init selesai sebelum request diproses ──
  let dbReady = false;
  let dbInitPromise = null;

  const ensureDBReady = async () => {
    if (dbReady) return;
    if (!dbInitPromise) {
      dbInitPromise = db.initializeDB().then(() => initDB()).then(() => { dbReady = true; });
    }
    await dbInitPromise;
  };

  // Middleware: block request sampai DB siap (max 8 detik)
  app.use(async (req, res, next) => {
    try {
      await Promise.race([
        ensureDBReady(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('DB init timeout')), 8000))
      ]);
    } catch (e) {
      console.error('[DB] Init failed or timeout:', e.message);
      // Lanjut saja, pakai local fallback
    }
    next();
  });

  module.exports = app;
} else {
  // Lokal / VPS: tunggu DB siap baru listen
  db.initializeDB().then(() => {
    initDB(); // seed defaults only if missing
    app.listen(PORT, () => {
      console.log(`✅ Server berjalan di http://localhost:${PORT}`);
      console.log(`📁 Database: ${dbPath}`);
      console.log(`🔐 Admin: /admin`);
    });
  }).catch(err => {
    console.error('Fatal: Failed to initialize database:', err);
    process.exit(1);
  });
  module.exports = app;
}

// Helper: dapatkan user dari session (support admin yang tidak ada di users.json)
const getSessionUser = (req) => {
  if (req.session?.isAdmin) {
    const s = readDB('settings.json');
    return { id: 'admin', username: s.adminUsername || 'Admin', isAdmin: true, photo: null, role: 'admin', is_reseller: false };
  }
  if (req.session?.userId) return readDB('users.json').find(u => u.id === req.session.userId) || null;
  return null;
};

// Auth middleware
const requireAuth = (req, res, next) => {
  if (!req.session?.userId) {
    if (req.xhr || req.headers['content-type']?.includes('application/json')) {
      return res.json({ success: false, message: 'Silakan login terlebih dahulu', redirect: '/login' });
    }
    return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }
  next();
};

const requireAdmin = async (req, res, next) => {
  if (!req.session?.isAdmin && req.session?.userId !== 'admin') {
    // Balas 404 bukan 403 agar penyerang tidak tahu route admin ada
    return res.status(404).send('Not found');
  }

  // ── Single-Device Admin Lock (opsional, lihat settings.singleDeviceAdminLogin) ──
  // Mencegah 2 orang (mis: web dev + client) login admin bersamaan di
  // device berbeda. Login bersamaan menyebabkan race condition saat
  // keduanya baca-ubah-simpan data produk di waktu hampir sama, sehingga
  // perubahan salah satu pihak tertimpa / produk "berubah-ubah" saat refresh.
  //
  // Default toggle ini MATI → admin BOLEH login di banyak perangkat sekaligus.
  // Kalau admin nyalakan toggle "1 perangkat saja" di panel admin, baru
  // enforcement di bawah ini aktif.
  //
  // PENTING: pakai readFresh (bukan readDB/res.locals.settings) di sini.
  // Vercel menjalankan banyak instance serverless yang TIDAK berbagi memori
  // — kalau pakai cache lokal, satu instance bisa "telat tahu" kalau toggle
  // atau device lain baru saja berubah, dan tetap meloloskan device yang
  // seharusnya sudah diblokir. Ini satu-satunya pengecekan yang wajib selalu fresh.
  const settingsFresh = await db.readFresh('settings.json').catch(() => ({}));
  if (settingsFresh?.singleDeviceAdminLogin === true) {
    const lock = await db.readFresh('admin-lock.json');
    if (isLockActive(lock) && lock.sessionId !== req.session.adminSessionId) {
      req.session = null; // paksa logout sesi yang sudah digantikan
      if (ADMIN_PAGE_ROUTES.has(req.path)) {
        return res.redirect('/vpr-secure-panel-8x?kicked=1');
      }
      return res.status(401).json({
        success: false,
        sessionRevoked: true,
        message: `Sesi admin Anda diakhiri karena ada login dari perangkat lain (${lock.device || 'perangkat lain'}).`
      });
    }

    // Sesi ini pemegang lock yang sah → perpanjang heartbeat (di-throttle,
    // supaya tidak nulis ke Supabase di setiap request)
    touchAdminLock(req.session.adminSessionId, lock);
  }

  next();
};

// Halaman admin yang dimuat lewat navigasi browser biasa (bukan fetch/XHR)
// → kalau lock-nya hilang, redirect ke halaman login, bukan balas JSON.
const ADMIN_PAGE_ROUTES = new Set(['/admin', '/admin/product-edit', '/admin/theme-settings']);

// Lock dianggap kosong/expired kalau tidak ada heartbeat selama ini
// (mis: tab ditutup / koneksi putus tanpa logout resmi).
const ADMIN_LOCK_TIMEOUT_MS = 6 * 60 * 1000; // 6 menit

const parseDeviceLabel = (ua = '') => {
  let browser = 'Browser';
  if (/edg/i.test(ua)) browser = 'Edge';
  else if (/chrome/i.test(ua)) browser = 'Chrome';
  else if (/firefox/i.test(ua)) browser = 'Firefox';
  else if (/safari/i.test(ua)) browser = 'Safari';
  let os = 'Unknown';
  if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad|ios/i.test(ua)) os = 'iOS';
  else if (/windows/i.test(ua)) os = 'Windows';
  else if (/mac os/i.test(ua)) os = 'Mac';
  else if (/linux/i.test(ua)) os = 'Linux';
  return `${browser} · ${os}`;
};

const isLockActive = (lock) => {
  if (!lock || !lock.sessionId || !lock.lastSeen) return false;
  return (Date.now() - new Date(lock.lastSeen).getTime()) < ADMIN_LOCK_TIMEOUT_MS;
};

// Klaim lock untuk sesi admin yang baru login. Dipanggil SETELAH password
// terverifikasi & lock lama dipastikan kosong/expired (lihat route login).
const acquireAdminLock = async (req) => {
  const sessionId = uuidv4();
  await writeDB('admin-lock.json', {
    sessionId,
    ip: req.ip,
    device: parseDeviceLabel(req.headers['user-agent'] || ''),
    loginAt: new Date().toISOString(),
    lastSeen: new Date().toISOString()
  });
  return sessionId;
};

// Lepas lock saat logout resmi — supaya device lain bisa langsung login
// tanpa harus menunggu timeout.
const releaseAdminLock = async (sessionId) => {
  if (!sessionId) return;
  try {
    const lock = await db.readFresh('admin-lock.json');
    if (lock && lock.sessionId === sessionId) await writeDB('admin-lock.json', {});
  } catch {}
};

// Heartbeat di-throttle per sessionId supaya tidak nulis ke Supabase di
// setiap request admin (cukup tiap ≥60 detik aktivitas). `lock` di sini
// sudah hasil readFresh dari requireAdmin, jadi tidak perlu baca ulang.
const lastHeartbeatAt = new Map();
const touchAdminLock = (sessionId, lock) => {
  if (!sessionId || !lock || lock.sessionId !== sessionId) return;
  const now = Date.now();
  if (now - (lastHeartbeatAt.get(sessionId) || 0) < 60000) return;
  lastHeartbeatAt.set(sessionId, now);
  writeDB('admin-lock.json', { ...lock, lastSeen: new Date().toISOString() }).catch(() => {});
};

// Helper functions
const generateOrderCode = () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = 'VR-';
  for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
  code += '-';
  for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
};

// FIX BUG "jam transaksi tidak sesuai waktu nyata": sebelumnya fungsi ini
// pakai d.getDate()/getHours()/dst, yang berarti komponen jam & tanggal
// diambil dari TIMEZONE SERVER tempat proses Node berjalan (mis. Vercel
// default ke UTC), BUKAN waktu Indonesia. Efeknya jam yang tersimpan/
// ditampilkan di panel admin bisa selisih beberapa jam (WIB = UTC+7) dari
// jam asli transaksi terjadi. Sekarang komponen tanggal/jam diambil lewat
// Intl dengan timeZone 'Asia/Jakarta' eksplisit, jadi hasilnya konsisten
// WIB di server manapun aplikasi ini di-deploy.
const formatDate = (date = new Date()) => {
  const d = new Date(date);
  const parts = new Intl.DateTimeFormat('id-ID', {
    timeZone: 'Asia/Jakarta',
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false
  }).formatToParts(d).reduce((acc, p) => { acc[p.type] = p.value; return acc; }, {});
  // 'hour: 24' dari Intl kadang mengembalikan "24" untuk tengah malam, bukan "00"
  const hour = parts.hour === '24' ? '00' : parts.hour;
  return `${parts.day}/${parts.month}/${parts.year} ${hour}:${parts.minute}`;
};

// ── Gabungkan base URL (yang mungkin punya subpath, mis. https://host.com/api/v1) dengan path tambahan
// tanpa menghapus subpath tersebut — beda dari new URL(path, base) yang selalu absolute dari root.
function joinUrlPath(baseUrl, extraPath) {
  const base = baseUrl.replace(/\/+$/, '');
  const extra = extraPath.replace(/^\/+/, '');
  return `${base}/${extra}`;
}

// ══════════════════════════════════════════════════════════════════
// PAYMENT GATEWAY DISPATCHER
// Ada 3 metode pembayaran yang bisa dipilih admin di panel (settings.qrisMode):
//   'static'  → QRIS gambar statis, dikonfirmasi manual oleh admin
//   'pakasir' → PakKasir API (app.pakasir.com)
//   'genspay' → GensPay API (genspay.my.id) — 📖 Dokumentasi: https://genspay.my.id/docs
// createQRISPayment() dan checkPaymentStatus() di bawah ini cuma me-routing
// ke implementasi yang sesuai berdasarkan settings.qrisMode, supaya semua
// caller (reseller join, wallet topup, buy) tidak perlu tahu/peduli gateway
// mana yang aktif — tinggal panggil createQRISPayment(orderId, amount, settings)
// seperti biasa.
// ══════════════════════════════════════════════════════════════════
const createQRISPayment = (orderId, amount, settings) => {
  const mode = settings.qrisMode || 'static';
  if (mode === 'pakasir') return createQRISPaymentPakasir(orderId, amount, settings);
  return createQRISPaymentGenspay(orderId, amount, settings);
};

// gatewayOverride: kalau diisi ('pakasir'/'genspay'), dipakai APA ADANYA
// tanpa peduli settings.qrisMode saat ini — dipakai oleh /check-payment untuk
// selalu verifikasi ke gateway yang SAMA dengan yang dipakai saat transaksi
// ini dibuat (transaction.paymentGateway), bukan gateway yang sedang aktif
// sekarang di panel admin. Tanpa ini, transaksi lama yang dibuat pakai
// Pakasir bisa salah dicek ke GensPay (atau sebaliknya) kalau admin sempat
// ganti mode pembayaran di tengah jalan — akibatnya status selalu gagal
// match dan key tidak pernah terkirim walau sudah dibayar.
const checkPaymentStatus = (orderId, amount, settings, gatewayOverride) => {
  const mode = gatewayOverride || settings.qrisMode || 'static';
  if (mode === 'pakasir') return checkPaymentStatusPakasir(orderId, amount, settings);
  return checkPaymentStatusGenspay(orderId, amount, settings);
};

// ── PakKasir API (app.pakasir.com) ──
const createQRISPaymentPakasir = (orderId, amount, settings) => {
  return new Promise((resolve, reject) => {
    const apiKey = settings.pakasir?.apiKey?.trim() || '';
    const project = settings.pakasir?.project?.trim() || '';
    if (!apiKey || !project) return reject(new Error('API Key atau Project PakKasir belum dikonfigurasi'));
    // FIX BUG: apiBaseUrl yang diisi admin di panel sebelumnya TIDAK PERNAH
    // dipakai — hostname selalu hardcode 'app.pakasir.com' walau field ini
    // ada di form settings dan kelihatan seperti bisa diubah. Sekarang
    // benar-benar dipakai, dengan fallback ke default resmi Pakasir kalau
    // kosong/belum diisi, supaya instalasi lama yang belum punya field ini
    // tetap jalan seperti biasa.
    const hostname = (settings.pakasir?.apiBaseUrl?.trim() || 'app.pakasir.com').replace(/^https?:\/\//, '').replace(/\/+$/, '');

    const body = JSON.stringify({ project, order_id: orderId, amount, api_key: apiKey });
    const req = https.request({
      hostname, port: 443,
      path: '/api/transactioncreate/qris', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(data);
          const qr = r.payment?.payment_number || r.payment_number || r.qr_string || r.data?.payment_number;
          if (!qr) return reject(new Error(r.message || `Pakasir error: ${data.slice(0,100)}`));
          resolve({ qr_string: qr, total_payment: r.payment?.total_payment || amount, expired_at: r.payment?.expired_at || null });
        } catch(e) { reject(new Error('Gagal parse response PakKasir')); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('PakKasir timeout')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    req.write(body); req.end();
  });
};

const checkPaymentStatusPakasir = (orderId, amount, settings) => {
  return new Promise((resolve, reject) => {
    const apiKey = settings.pakasir?.apiKey?.trim() || '';
    const project = settings.pakasir?.project?.trim() || '';
    if (!apiKey || !project) return reject(new Error('API Key PakKasir belum dikonfigurasi'));

    const q = `project=${encodeURIComponent(project)}&amount=${parseInt(amount)}&order_id=${encodeURIComponent(orderId)}&api_key=${encodeURIComponent(apiKey)}`;
    // Konsisten dengan createQRISPaymentPakasir: hostname API diambil dari
    // settings.pakasir.apiBaseUrl (fallback ke default resmi Pakasir), bukan
    // hardcode — supaya create & check status selalu hit host yang sama.
    const hostname = (settings.pakasir?.apiBaseUrl?.trim() || 'app.pakasir.com').replace(/^https?:\/\//, '').replace(/\/+$/, '');
    const req = https.request({
      hostname, port: 443,
      path: `/api/transactiondetail?${q}`, method: 'GET', timeout: 10000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        // FIX BUG: sebelumnya HTTP status code dari Pakasir tidak pernah dicek —
        // kalau Pakasir balas 4xx/5xx (mis. project/api_key salah, order_id tidak
        // ditemukan, rate limit), body error-nya tetap coba di-parse sebagai JSON
        // sukses. Sekarang HTTP non-2xx ditolak eksplisit sebagai error.
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error(`PakKasir HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
        }
        try {
          const parsed = JSON.parse(data);
          // Lapis validasi tambahan: pastikan response memang milik order_id
          // yang kita minta — kalau field ini ada di response tapi tidak
          // cocok, tolak daripada percaya begitu saja.
          const tx = parsed.transaction || parsed;
          if (tx && tx.order_id && tx.order_id !== orderId) {
            return reject(new Error('PakKasir response order_id tidak cocok'));
          }
          resolve(parsed);
        }
        catch(e) { reject(new Error('Gagal parse response status')); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('PakKasir status timeout')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    req.end();
  });
};

// ── GensPay API (genspay.my.id) ──
// 📖 Dokumentasi Integrasi: https://genspay.my.id/docs
// Base URL API: https://genspay.my.id/api/v1
// Cara pakai (SESUAI dokumentasi resmi yang dikonfirmasi 16 Agu 2026):
//   1. Buat project di Dashboard → menu Project → dapat API Key
//   2. Kirim API Key di header X-API-Key pada SETIAP request
//   3. POST /transaction/create untuk generate QRIS (body wajib include
//      payment_method: "qris")
//   4. TIDAK ADA endpoint GET status manual / cancel -- status transaksi
//      HANYA dikirim lewat webhook (event "transaction.updated", lihat
//      app.post('/webhook/genspay')). Komentar lama di sini yang bilang
//      "endpoint create/status/cancel" sudah tidak akurat, dihapus.
const createQRISPaymentGenspay = (orderId, amount, settings) => {
  return new Promise((resolve, reject) => {
    const baseUrl = (settings.genspay?.baseUrl || process.env.GENSPAY_BASE_URL || 'https://genspay.my.id/api/v1').trim();
    const apiKey = (settings.genspay?.apiKey || process.env.GENSPAY_API_KEY || '').trim();
    if (!apiKey) return reject(new Error('API Key GensPay belum dikonfigurasi'));

    let url;
    try { url = new URL(joinUrlPath(baseUrl, '/transaction/create')); } catch (e) { return reject(new Error('Base URL GensPay tidak valid')); }

    // FIX sesuai dokumentasi resmi GensPay (genspay.my.id/docs): body wajib
    // menyertakan payment_method: "qris" -- sebelumnya field ini tidak
    // dikirim sama sekali, cuma {amount, order_id}.
    const body = JSON.stringify({ amount, order_id: orderId, payment_method: 'qris' });
    const req = https.request({
      hostname: url.hostname, port: url.port || 443,
      path: url.pathname + url.search, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey, 'Content-Length': Buffer.byteLength(body) },
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(data);
          const qr = r.data?.qr_string;
          if (!r.success || !qr) return reject(new Error(r.error || r.message || `GensPay error (HTTP ${res.statusCode}): ${data.slice(0,150)}`));
          resolve({ qr_string: qr, total_payment: r.data?.amount || amount, expired_at: r.data?.expiry_time || null });
        } catch(e) { reject(new Error(`Gagal parse response GensPay (HTTP ${res.statusCode}): ${data.slice(0,200) || '(response kosong)'}`)); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('GensPay timeout')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    req.write(body); req.end();
  });
};

// Kirim notifikasi WhatsApp otomatis ke admin via Fonnte (jika token dikonfigurasi)
const sendWhatsAppNotif = (target, message, settings) => {
  return new Promise((resolve) => {
    const token = settings?.fonnteToken?.trim() || '';
    if (!token || !target) return resolve(false);
    const body = `target=${encodeURIComponent(target)}&message=${encodeURIComponent(message)}`;
    const req = https.request({
      hostname: 'api.fonnte.com', port: 443,
      path: '/send', method: 'POST',
      headers: {
        'Authorization': token,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body)
      },
      timeout: 10000
    }, (res) => {
      res.on('data', () => {});
      res.on('end', () => resolve(true));
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.write(body); req.end();
  });
};

// PENTING: dokumentasi resmi GensPay (genspay.my.id/docs) TIDAK menyediakan
// endpoint GET untuk cek status transaksi -- GensPay sepenuhnya mengandalkan
// WEBHOOK (POST ke Webhook URL project kamu, event "transaction.updated")
// buat kasih tau perubahan status. Endpoint /transaction/:id/status yang
// dipanggil fungsi ini SEBELUMNYA itu bukan endpoint resmi (kemungkinan
// endpoint lama yang sudah dihapus GensPay), makanya selalu dapat 401
// "Signature required" -- itu akar masalah "auto-send masih gagal" selama
// ini. Fungsi ini sekarang reject dengan jelas supaya /check-payment polling
// tidak diam-diam gagal terus tanpa penjelasan; finalize order untuk GensPay
// HARUS lewat webhook (lihat app.post('/webhook/genspay') di bawah).
const checkPaymentStatusGenspay = (orderId, amount, settings) => {
  return Promise.reject(new Error(
    'GensPay tidak menyediakan endpoint cek status manual -- status transaksi HANYA dikirim via webhook. ' +
    'Pastikan Webhook URL sudah didaftarkan di dashboard GensPay (Settings project).'
  ));
};

// Routes - Public
// ══════════════════════════════════════════════════════════════════
// SETUP ENDPOINT — Reset admin password + push semua settings
// Akses: /ryanewera-setup?secret=SETUP_SECRET (dari env var)
// Set SETUP_SECRET di Vercel env vars, lalu akses URL-nya via browser.
// Setelah berhasil, HAPUS SETUP_SECRET dari env Vercel untuk keamanan.
// ══════════════════════════════════════════════════════════════════
app.get('/ryanewera-setup', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!secret || req.query.secret !== secret) {
    return res.status(403).send('❌ Akses ditolak. Set SETUP_SECRET di env Vercel dulu.');
  }

  // Endpoint ini reset password admin — WAJIB pakai kredensial dari env var,
  // bukan fallback tertulis di source code (source code ini akan tersebar
  // lewat zip/GitHub, jadi fallback tetap = password admin bocor ke siapa saja
  // yang baca file ini, persis kasus kebocoran sebelumnya).
  if (!process.env.INITIAL_ADMIN_USERNAME || !process.env.INITIAL_ADMIN_PASSWORD) {
    return res.status(400).send(
      '❌ Set env var INITIAL_ADMIN_USERNAME dan INITIAL_ADMIN_PASSWORD di Vercel dulu sebelum jalanin setup ini ' +
      '(supaya kredensial admin tidak pernah nongol di source code). Setelah itu, akses ulang endpoint ini.'
    );
  }

  try {
    const currentSettings = await db.readFresh('settings.json') || {};

    const newUsername = process.env.INITIAL_ADMIN_USERNAME;
    const newPassword = process.env.INITIAL_ADMIN_PASSWORD;
    const newHash     = bcrypt.hashSync(newPassword, 12);

    const updatedSettings = {
      ...currentSettings,
      siteName:      'RYAN NEW ERA',
      gamePanelName: 'RYANEWERA',
      about:         'RYAN NEW ERA menyediakan layanan key mod aplikasi premium terbaik #1 indonesia.',
      marqueeText:   'LAYANAN GAME MOD MENU PREMIUM - PROSES CEPAT & AMAN',
      contact: {
        ...(currentSettings.contact || {}),
        // Placeholder -- isi kontak asli lewat Admin Panel > Settings sebelum go-live.
        whatsapp:  currentSettings.contact?.whatsapp || '',
        telegram:  currentSettings.contact?.telegram || '',
        email:     currentSettings.contact?.email || '',
        waChannel: currentSettings.contact?.waChannel || '',
        waGroup:   currentSettings.contact?.waGroup || '',
      },
      adminUsername: newUsername,
      adminPassword: newHash,
      logoUrl: '/uploads/logo-gn-icon.jpg',
    };

    await db.writeDB('settings.json', updatedSettings);

    // Verify
    const saved   = await db.readFresh('settings.json');
    const verify  = bcrypt.compareSync(newPassword, saved.adminPassword);

    res.send(`
      <!DOCTYPE html><html><head><meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>Setup Result</title>
      <style>body{font-family:monospace;background:#09040f;color:#e2e8f0;padding:24px;max-width:500px;margin:0 auto;}
      .ok{color:#4ade80;} .err{color:#f87171;} .box{background:#170c22;border:1px solid rgba(124,47,214,.3);border-radius:10px;padding:20px;margin:16px 0;}
      h2{color:#c084fc;} a{color:#c084fc;}</style></head><body>
      <h2>${verify ? '✅ SETUP BERHASIL' : '❌ SETUP GAGAL'}</h2>
      <div class="box">
        <p class="ok">✅ adminUsername : <strong>${saved.adminUsername}</strong></p>
        <p class="${verify?'ok':'err'}">${verify?'✅':'❌'} password hash  : ${verify?'MATCH — password benar':'TIDAK MATCH — ada masalah!'}</p>
        <p class="ok">✅ whatsapp      : ${saved.contact?.whatsapp}</p>
        <p class="ok">✅ telegram      : ${saved.contact?.telegram}</p>
        <p class="ok">✅ waChannel     : ${saved.contact?.waChannel}</p>
        <p class="ok">✅ waGroup       : ${saved.contact?.waGroup}</p>
      </div>
      <div class="box">
        <p>🔐 <strong>Login Admin:</strong></p>
        <p>URL&nbsp;&nbsp;&nbsp;&nbsp;: <a href="/vpr-secure-panel-8x">/vpr-secure-panel-8x</a></p>
        <p>Username: <strong>${newUsername}</strong></p>
        <p>Password: <strong>${newPassword}</strong></p>
      </div>
      <p style="color:rgba(148,163,184,.5);font-size:11px;">⚠️ Setelah berhasil login, HAPUS SETUP_SECRET dari env Vercel!</p>
      </body></html>
    `);
  } catch (err) {
    res.status(500).send(`❌ Error: ${err.message}`);
  }
});

// ══════════════════════════════════════════════════════════════════
// FIX BUG "Leaderboard Top Pembelian": sebelumnya 3 tempat berbeda
// (homepage, /leaderboard, /api/leaderboard) masing-masing menghitung
// leaderboard sendiri-sendiri dengan filter `t.status === 'done' && t.userId`
// SAJA. Filter itu ikut menghitung transaksi yang BUKAN pembelian produk:
//   - type 'deposit'      -> top up saldo reseller
//   - type 'reseller'     -> upgrade akun jadi reseller
//   - type 'gacha'        -> main arcade (TIDAK PUNYA field `price` sama
//                            sekali -> totalSpent += undefined -> NaN,
//                            jadi user yang pernah gacha nongol dengan
//                            "Rp NaN" di podium/list)
//   - type 'adjustment' / 'coin-adjustment' -> saldo/koin dikasih manual
//                            oleh admin, bukan hasil belanja user
// Akibatnya ranking "top pembeli" ke-inflate oleh aktivitas yang bukan
// belanja, dan beberapa user tampil dengan total belanja rusak (NaN).
// Pembeda paling stabil untuk "ini transaksi pembelian produk beneran":
// field `productId` HANYA diisi di 2 alur checkout produk (QRIS & saldo
// wallet) -- lihat transactions.push() untuk deposit/reseller/gacha/
// adjustment, tidak satupun yang set productId. Helper ini dipakai di
// ketiga tempat supaya logikanya konsisten & gampang dirawat satu pintu.
function computeLeaderboard(transactions, users, limit = null) {
  const userStats = {};
  transactions.forEach(t => {
    if (t.status === 'done' && t.userId && t.productId) {
      if (!userStats[t.userId]) userStats[t.userId] = { userId: t.userId, totalTransactions: 0, totalSpent: 0 };
      userStats[t.userId].totalTransactions++;
      userStats[t.userId].totalSpent += (Number(t.price) || 0);
    }
  });
  const entries = Object.values(userStats).map(stat => {
    const u = users.find(u => u.id === stat.userId);
    return {
      userId: stat.userId,
      username: u?.username || 'User',
      photo: u?.photo || null,
      totalTransactions: stat.totalTransactions,
      totalSpent: stat.totalSpent
    };
  });
  entries.sort((a, b) => b.totalTransactions - a.totalTransactions || b.totalSpent - a.totalSpent);
  entries.forEach((item, i) => { item.rank = i + 1; });
  return limit ? entries.slice(0, limit) : entries;
}

app.get('/', async (req, res) => {
  // FIX (egress): homepage dipanggil SEMUA visitor termasuk bot/crawler tanpa
  // rate limit. readFresh() bypass cache dan selalu hit Supabase — di traffic
  // reguler ini jadi penyumbang cached egress terbesar. readSmart() pakai
  // cache 8 detik dulu, cukup segar untuk listing produk publik.
  const products = (await readSmart('products.json')).filter(p => p.status === 'active');

  // ── Leaderboard real-time (hanya dari transaksi sukses pembelian produk) ──
  const transactions = readDB('transactions.json');
  const users = readDB('users.json');
  const leaderboardEntries = computeLeaderboard(transactions, users, 8);

  // ── Server-side fake testimonials ──
  const fakeTestimonials = [
    { id:'fake1', name:'Rizky F.',    rating:5, text:'Mod FF-nya mantap, udah 3 bulan pakai dan aman-aman aja. Fitur lengkap dari ESP sampai fly hack. CS juga responsif banget!', productName:'FREE FIRE MAX',      date:'2025-05-20', verified:true },
    { id:'fake2', name:'Andi S.',     rating:5, text:'ML mod-nya lengkap banget! Map hack, drone view, sampai skin all hero ada. Auto update jadi nggak perlu repot tiap update.', productName:'MOBILE LEGENDS',    date:'2025-05-18', verified:true },
    { id:'fake3', name:'Dimas P.',    rating:5, text:'Support fast response! Pas ada masalah langsung dibantu sampai beres. PUBG mod-nya juga smooth, nggak lag sama sekali.', productName:'PUBG MOBILE',   date:'2025-05-15', verified:true },
    { id:'fake4', name:'farhan',      rating:5, text:'Beli sertifikat anti-banned udah 2x dan alhamdulillah akun tetap aman. Worth it banget harganya segitu.', productName:'SERTIFIKAT', date:'2025-05-10', verified:true },
    { id:'fake5', name:'Wanda M.',    rating:4, text:'Produknya bagus, pengiriman key cepet banget. Cuma kadang agak lag di device lama tapi overall oke lah.', productName:'MOBILE LEGENDS',    date:'2025-05-08', verified:true },
    { id:'fake6', name:'ACA',         rating:5, text:'Udah lama langganan di sini, belum pernah kecewa. Proses beli gampang, bayar QRIS langsung dapat key. Recommended!', productName:'FREE FIRE MAX',      date:'2025-05-05', verified:true },
    { id:'fake7', name:'bintang',     rating:5, text:'Lifetime PUBGM worth it banget. Udah 6 bulan masih lancar jaya, fitur no recoil-nya mantul.', productName:'PUBG MOBILE',   date:'2025-04-28', verified:true },
    { id:'fake8', name:'Rizky',       rating:4, text:'Kalau FF mod-nya top. Pernah ada issue tapi langsung di-handle sama admin. Keep up the good work!', productName:'FREE FIRE MAX',      date:'2025-04-20', verified:true },
    { id:'fake9', name:'Kevin',       rating:5, text:'CODM mod anti-recoil smooth banget. Rank dari Silver langsung naik ke Platinum dalam seminggu haha.', productName:'CODM',    date:'2025-04-15', verified:true },
    { id:'fake10',name:'abil',        rating:5, text:'Ini toko mod menu terpercaya yang pernah aku coba. Transaksi aman, key langsung masuk, CS ramah.', productName:'FREE FIRE MAX',      date:'2025-04-10', verified:true },
    { id:'fake11',name:'Hergi',       rating:5, text:'Valorant ESP-nya akurat banget. Sudah 2 bulan pake dan belum ada masalah sama sekali. Pelayanan top!', productName:'VALORANT', date:'2025-04-05', verified:true },
    { id:'fake12',name:'rehan',       rating:5, text:'HOK mod-nya mantap, map hack dan skin unlock semua ada. Proses beli cepet dan key langsung terkirim.', productName:'HOK',     date:'2025-03-28', verified:true },
  ];
  const realTestimonials = readDB('testimonials.json').filter(t => t.verified);
  const testiUsernames = new Set(realTestimonials.map(t => (t.username||'').toLowerCase()));
  const paddedFake = fakeTestimonials.filter(f => !testiUsernames.has((f.name||'').toLowerCase()));
  const testimonialsForHome = [...realTestimonials, ...paddedFake].slice(0, 12);
  const avgRating = testimonialsForHome.length
    ? (testimonialsForHome.reduce((s, t) => s + (t.rating || 0), 0) / testimonialsForHome.length).toFixed(1)
    : '4.9';
  const ratingCounts = {1:0,2:0,3:0,4:0,5:0};
  testimonialsForHome.forEach(t => { if (t.rating >= 1 && t.rating <= 5) ratingCounts[t.rating]++; });
  const totalSold = products.reduce((s, p) => s + (p.sold || 0), 0);
  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);

  // Popular products: if admin configured popularProductIds, use those; else show all products
  const popularProductIds = settings.popularProductIds || [];
  let popularProducts;
  if (popularProductIds.length > 0) {
    popularProducts = products.filter(p => popularProductIds.includes(p.id));
    // Append any active products not in the popular list
    const remaining = products.filter(p => !popularProductIds.includes(p.id));
    popularProducts = [...popularProducts, ...remaining];
  } else {
    popularProducts = [...products].sort((a, b) => (b.sold || 0) - (a.sold || 0));
  }

  // SECURITY: strip keys sebelum dikirim ke view — home.ejs embed popularProducts
  // ke dalam <script> via JSON.stringify, jadi keys harus dihapus dari sini.
  // stockCount dianggap unlimited HANYA untuk varian GhostSeller (auto
  // restock beneran). vipibmstore ('auto') sudah dicabut total -- kalau ada
  // data lama yang masih ke-tag stockMode/stockSource 'auto', itu SENGAJA
  // tidak lagi dianggap unlimited di sini (dulu ini penyebab produk yang
  // sebenarnya sudah rusak/tanpa kredensial tetap kelihatan "tersedia" di
  // toko, customer bayar, baru ketauan gagal pas checkout).
  //
  // PAKAI 999999 (bukan Infinity!): nilai ini dikirim ke browser lewat
  // JSON.stringify(popularProducts) di <script> home.ejs. JSON tidak kenal
  // Infinity -- JSON.stringify(Infinity) === "null" -- jadi kalau dipaksa
  // Infinity di sini, begitu sampai di browser jadi stockCount:null, lalu
  // `!(null>0)` = true = dianggap HABIS. Ini bug nyata yang bikin carousel
  // "Produk Populer" SELALU nampilin "Habis" untuk produk unlimited-stock,
  // dari dulu (termasuk pas masih vipibmstore) sampai ketauan baru sekarang.
  const UNLIMITED_STOCK_SENTINEL = 999999;
  const popularProductsSafe = popularProducts.map(({ keys, ...p }) => ({
    ...p, stockCount: (p.stockMode === 'ghostseller' || p.stockMode === 'mixed' || (Array.isArray(p.pricingOptions) && p.pricingOptions.some(o => o.stockSource === 'ghostseller'))) ? UNLIMITED_STOCK_SENTINEL : (keys || []).length
  }));

  // Batasi grid "SEMUA PRODUK" di halaman utama supaya tidak lag kalau
  // produk sudah banyak (ratusan+) — server cuma kirim N produk pertama ke
  // view, sisanya baru dimuat kalau user buka /produk (lihat semua produk).
  // N-nya bisa diatur admin lewat settings.homeProductsLimit.
  const homeProductsLimit = parseInt(settings.homeProductsLimit) || 10;
  const totalActiveProducts = products.length;
  const productsForHome = products.slice(0, homeProductsLimit);

  res.render('pages/home', {
    products: productsForHome,
    totalActiveProducts,
    homeProductsLimit,
    popularProducts: popularProductsSafe,
    settings,
    user,
    categories: settings.categories || [],
    categoryLabels: settings.categoryLabels || {},
    resellerSettings: {
      enabled: settings.resellerEnabled !== false,
      price: settings.resellerPrice || 50000,
      discount: settings.resellerDiscount || 20
    },
    leaderboardEntries,
    testimonialsForHome,
    avgRating,
    ratingCounts,
    totalSold
  });
});

// ── HALAMAN "LIHAT SEMUA PRODUK" ──
// Terpisah dari halaman utama supaya halaman utama tetap ringan (cuma kirim
// homeProductsLimit produk pertama). Di sini semua produk aktif ditampilkan
// dengan pagination server-side, jadi tetap ringan walau produk ratusan.
app.get('/produk', async (req, res) => {
  const settings = res.locals.settings || readDB('settings.json');
  // FIX (egress): sama seperti homepage — listing publik, pakai cache dulu.
  let allProducts = (await readSmart('products.json')).filter(p => p.status === 'active');

  const category = (req.query.category || '').trim();
  if (category && category !== 'all') {
    allProducts = allProducts.filter(p => p.category === category);
  }

  const pageSize = parseInt(settings.homeProductsLimit) || 10;
  const totalProducts = allProducts.length;
  const totalPages = Math.max(1, Math.ceil(totalProducts / pageSize));
  let page = parseInt(req.query.page) || 1;
  if (page < 1) page = 1;
  if (page > totalPages) page = totalPages;

  const startIdx = (page - 1) * pageSize;
  const productsPage = allProducts.slice(startIdx, startIdx + pageSize);
  const user = res.locals.user || getSessionUser(req);

  res.render('pages/produk', {
    products: productsPage,
    settings,
    user,
    categories: settings.categories || [],
    categoryLabels: settings.categoryLabels || {},
    activeCategory: category || 'all',
    page,
    totalPages,
    totalProducts,
    pageSize
  });
});

// Auth routes
app.get('/login', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.render('pages/login', {
    error: null,
    redirect: req.query.redirect || '/',
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
  });
});

app.post('/login', async (req, res) => {
  const ip = req.ip;
  const { blocked, wait } = checkLoginBlocked(ip);
  if (blocked) {
    return res.render('pages/login', {
      error: `Terlalu banyak percobaan login. Coba lagi dalam ${wait} menit.`,
      redirect: req.body.redirect || '/',
      turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    });
  }

  // ── Verifikasi Cloudflare Turnstile ─────────────────────────────────────
  if (process.env.TURNSTILE_SECRET_KEY) {
    const token = req.body['cf-turnstile-response'];
    if (!token) {
      return res.render('pages/login', {
        error: 'Verifikasi keamanan diperlukan. Mohon selesaikan captcha.',
        redirect: req.body.redirect || '/',
        turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
      });
    }
    const valid = await verifyTurnstile(token);
    if (!valid) {
      return res.render('pages/login', {
        error: 'Verifikasi keamanan gagal. Coba lagi.',
        redirect: req.body.redirect || '/',
        turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
      });
    }
  }
  // ────────────────────────────────────────────────────────────────────────

  const { username, password } = req.body;
  const settings = readDB('settings.json');

  // Admin login diblokir dari /login — gunakan halaman khusus
  if (username === settings.adminUsername) {
    recordLoginFail(ip);
    return res.render('pages/login', {
      error: 'Username atau password salah.',
      redirect: req.body.redirect || '/',
      turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    });
  }

  // Check user
  const users = readDB('users.json');
  const user = users.find(u => u.username === username);

  if (user && await bcrypt.compare(password, user.password)) {
    clearLoginFail(ip);
    req.session.userId = user.id;
    req.session.isAdmin = (user.role === 'admin');
    return res.redirect(req.body.redirect || (req.session.isAdmin ? '/admin' : '/'));
  }

  recordLoginFail(ip);
  const remaining = LOGIN_MAX_FAIL - (loginFailMap.get(ip)?.count || 0);
  const errMsg = remaining > 0
    ? `Username atau password salah. Sisa percobaan: ${remaining}`
    : `Terlalu banyak percobaan login. Coba lagi dalam 15 menit.`;
  res.render('pages/login', {
    error: errMsg,
    redirect: req.body.redirect || '/',
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
  });
});

app.get('/register', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.render('pages/register', { error: null });
});

app.post('/register', async (req, res) => {
  const { username, password, confirmPassword, wa } = req.body;

  if (!username || !password || !wa) {
    return res.render('pages/register', { error: 'Semua field wajib diisi' });
  }

  if (confirmPassword && password !== confirmPassword) {
    return res.render('pages/register', { error: 'Konfirmasi password tidak cocok' });
  }

  if (username === 'Abdurahman Mulvi') {
    return res.render('pages/register', { error: 'Username tidak diizinkan' });
  }

  // FIX KEAMANAN: sebelumnya username TIDAK divalidasi sama sekali --
  // user bisa daftar pakai username berisi tanda kutip/tag HTML, misalnya
  // x'); alert(document.cookie); //  atau  <script>...</script>. Username
  // itu lalu ditempel APA ADANYA di banyak tombol onclick="...('...')" di
  // panel admin (toggleReseller, adjustBalance, deleteUser -- lihat
  // views/pages/admin.ejs) dan di beberapa tempat lain tanpa di-escape.
  // Kalau username-nya berisi tanda kutip/kode, itu bisa memutus syntax
  // JS di tombol tersebut atau -- lebih parah -- nyuntik & menjalankan
  // JavaScript sendiri di browser ADMIN begitu admin buka tab Users.
  // Dibatasi ke huruf/angka/spasi/underscore/dash/titik supaya nggak ada
  // karakter yang bisa memutus HTML attribute atau syntax JS.
  if (!/^[a-zA-Z0-9 _.-]{3,32}$/.test(username)) {
    return res.render('pages/register', { error: 'Username hanya boleh huruf, angka, spasi, titik, underscore (_), atau strip (-), panjang 3-32 karakter' });
  }

  const users = readDB('users.json');

  if (users.find(u => u.username === username)) {
    return res.render('pages/register', { error: 'Username sudah digunakan' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(),
    username,
    password: hashedPassword,
    wa,
    photo: null,
    balance: 0,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  await writeDB('users.json', users);

  req.session.userId = newUser.id;
  req.session.isAdmin = false;

  res.redirect('/');
});

app.get('/logout', async (req, res) => {
  if (req.session?.isAdmin && req.session?.adminSessionId) {
    await releaseAdminLock(req.session.adminSessionId);
  }
  req.session = null;
  res.redirect('/');
});

// ══ RYANEWERA: ADMIN SECRET LOGIN GATE (hidden from public) ══
app.get('/vpr-secure-panel-8x', (req, res) => {
  if (req.session?.isAdmin) return res.redirect('/admin');
  const kicked = req.query.kicked === '1';
  res.render('pages/admin-login', {
    error: kicked ? 'Anda logout otomatis karena ada login admin dari perangkat lain.' : null,
    lockedInfo: null,
    username: ''
  });
});

app.post('/vpr-secure-panel-8x', async (req, res) => {
  const ip = req.ip;
  const { blocked, wait } = checkLoginBlocked(ip);
  if (blocked) {
    return res.render('pages/admin-login', {
      error: `Terlalu banyak percobaan. Coba lagi dalam ${wait} menit.`,
      lockedInfo: null, username: ''
    });
  }
  const { username, password, forceTakeover } = req.body;

  // ── FIX: readFresh() ambil langsung dari Supabase, bypass cache ──
  // Ini penting karena di Vercel tiap instance punya cache kosong
  const settings = await db.readFresh('settings.json');

  if (!settings || !settings.adminUsername || !settings.adminPassword) {
    return res.render('pages/admin-login', {
      error: 'Konfigurasi admin belum tersedia. Coba beberapa saat lagi.',
      lockedInfo: null, username: ''
    });
  }

  if (username === settings.adminUsername) {
    const match = await bcrypt.compare(password, settings.adminPassword).catch(() => false);
    if (match) {
      // ── Single-Device Lock (opsional): cek apakah panel sedang dipakai ──
      // device lain. Hanya aktif kalau admin nyalakan toggle di Settings;
      // default-nya mati, jadi admin boleh login di banyak perangkat sekaligus.
      const singleDeviceMode = settings?.singleDeviceAdminLogin === true;
      if (singleDeviceMode) {
        const currentLock = await db.readFresh('admin-lock.json');
        if (isLockActive(currentLock) && forceTakeover !== '1') {
          const minutesAgo = Math.max(1, Math.round((Date.now() - new Date(currentLock.lastSeen).getTime()) / 60000));
          return res.render('pages/admin-login', {
            error: null,
            username,
            lockedInfo: {
              device: currentLock.device || 'Perangkat tidak diketahui',
              minutesAgo
            }
          });
        }
      }
      clearLoginFail(ip);
      req.session.userId = 'admin';
      req.session.isAdmin = true;
      req.session.adminSessionId = singleDeviceMode ? await acquireAdminLock(req) : null;
      return res.redirect('/admin');
    }
  }
  recordLoginFail(ip);
  const remaining = LOGIN_MAX_FAIL - (loginFailMap.get(ip)?.count || 0);
  res.render('pages/admin-login', {
    error: remaining > 0
      ? `Username atau password salah. Sisa percobaan: ${remaining}`
      : 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.',
    lockedInfo: null, username: ''
  });
});


// ── RESELLER ──
app.get('/reseller', (req, res) => {
  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);
  res.render('pages/reseller', { layout: false, settings, user });
});

app.post('/reseller/join', requireAuth, async (req, res) => {
  try {
    if (req.session.isAdmin) return res.json({ success: false, message: 'Admin tidak perlu join reseller' });
    // Kebijakan wajib GensPay (15 Agu 2026): maks 30 request/3 menit per
    // pengguna untuk generate QRIS -- lihat checkPaymentRateLimit di atas.
    if (!checkPaymentRateLimit(req.session.userId)) {
      return res.json({ success: false, message: 'Terlalu banyak percobaan transaksi. Coba lagi dalam beberapa menit.' });
    }
    const users = readDB('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    if (user.is_reseller) return res.json({ success: false, message: 'Kamu sudah menjadi Reseller VIP!' });

    const settings = readDB('settings.json');
    const price = settings.resellerPrice || 50000;
    const orderId = `RES-${Date.now()}`;
    const refId = uuidv4();
    const orderCode = generateOrderCode();
    const qrisMode = settings.qrisMode || 'static';

    let qrString = null, isStatic = false;

    if (qrisMode === 'static') {
      if (!settings.qrisStaticImage) return res.json({ success: false, message: 'Admin belum mengatur QRIS. Hubungi admin.' });
      isStatic = true;
    } else {
      try {
        const r = await createQRISPayment(orderId, price, settings);
        qrString = r.qr_string;
      } catch (e) {
        if (settings.qrisStaticImage) { isStatic = true; }
        else return res.json({ success: false, message: 'QRIS error: ' + e.message });
      }
    }

    const transactions = readDB('transactions.json');
    transactions.push({
      id: refId, orderId, code: orderCode,
      userId: user.id, type: 'reseller',
      productName: 'Upgrade Reseller VIP',
      customerName: user.username, wa: user.wa,
      price, totalPayment: price, qrString, isStatic,
      paymentGateway: isStatic ? null : qrisMode,
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic,
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ── WALLET (SALDO RESELLER) ──
// Reseller top-up saldo via QRIS. Setelah dibayar & dikonfirmasi (lihat
// /check-payment/:refId), saldo otomatis bertambah dan bisa langsung dipakai
// untuk beli key tanpa scan QRIS lagi (lihat /wallet/buy).
app.post('/wallet/topup', requireAuth, async (req, res) => {
  try {
    if (req.session.isAdmin) return res.json({ success: false, message: 'Admin tidak memiliki wallet' });
    // Kebijakan wajib GensPay (15 Agu 2026): maks 30 request/3 menit per
    // pengguna untuk generate QRIS -- lihat checkPaymentRateLimit di atas.
    if (!checkPaymentRateLimit(req.session.userId)) {
      return res.json({ success: false, message: 'Terlalu banyak percobaan transaksi. Coba lagi dalam beberapa menit.' });
    }
    const users = readDB('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    if (!user.is_reseller) return res.json({ success: false, message: 'Top up saldo khusus untuk Reseller VIP. Gabung reseller dulu yuk!' });

    const settings = readDB('settings.json');
    const minDeposit = settings.resellerMinDeposit || 100000;
    const amount = parseInt(req.body.amount);
    if (isNaN(amount) || amount < minDeposit) {
      return res.json({ success: false, message: `Minimal top up Rp ${minDeposit.toLocaleString('id-ID')}` });
    }

    const orderId = `DEP-${Date.now()}`;
    const refId = uuidv4();
    const orderCode = generateOrderCode();
    const qrisMode = settings.qrisMode || 'static';

    let qrString = null, isStatic = false, totalPayment = amount, expiredAt = null, fallbackReason = null;

    if (qrisMode === 'static') {
      if (!settings.qrisStaticImage) return res.json({ success: false, message: 'Admin belum mengatur QRIS. Hubungi admin.' });
      isStatic = true;
    } else {
      try {
        const r = await createQRISPayment(orderId, amount, settings);
        qrString = r.qr_string;
        // total_payment dari GensPay = amount + fee mereka (kalau ada). Ini
        // CUMA buat ditampilkan ke user biar nominal yang ditampilkan sama
        // persis dengan yang diminta di QR code-nya. Saldo yang dikreditkan
        // tetap pakai `amount` asli (lihat field `amount` di transaksi di
        // bawah) supaya fee GensPay tidak ikut numpang masuk ke saldo user.
        totalPayment = r.total_payment || amount;
        expiredAt = r.expired_at || null;
      } catch (e) {
        // PENTING: kalau createQRISPayment gagal (mis. IP server sedang
        // diblokir gateway, API key invalid, gateway down), sistem
        // SEBELUMNYA diam-diam jatuh ke QRIS statis tanpa jejak apapun --
        // transaksi jadi butuh konfirmasi manual admin terus-menerus dan
        // KELIHATAN seperti "auto payment masih bug" padahal akar masalahnya
        // adalah gateway API gagal dipanggil. Sekarang errornya dicatat di
        // console + ditandai di transaksi (fallbackReason) supaya kelihatan
        // jelas saat admin cek /debug/genspay atau riwayat transaksi.
        console.warn(`[wallet/topup] createQRISPayment (${qrisMode}) gagal, fallback ke static:`, e.message);
        if (settings.qrisStaticImage) { isStatic = true; fallbackReason = e.message; }
        else return res.json({ success: false, message: 'QRIS error: ' + e.message });
      }
    }

    const transactions = readDB('transactions.json');
    transactions.push({
      id: refId, orderId, code: orderCode,
      userId: user.id, type: 'deposit',
      productName: 'Top Up Saldo Reseller',
      amount,
      customerName: user.username, wa: user.wa,
      price: amount, totalPayment, expiredAt, qrString, isStatic,
      paymentGateway: isStatic ? null : qrisMode,
      fallbackReason,
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic, totalPayment, expiredAt,
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Beli key langsung pakai saldo wallet (khusus reseller) — tanpa scan QRIS,
// saldo langsung terpotong dan key langsung diberikan.
// ══════════════════════════════════════════════════════════════════
// RESOLVE PRODUCT KEY — titik tunggal pengambilan key produk, dipakai di
// SEMUA jalur pengiriman key (/wallet/buy, finalizeConfirmedPayment yang
// menangani webhook + polling, dan konfirmasi manual admin). Mendukung 2
// mode lewat stockSource per-varian (lihat resolveStockSourceForDays):
//
//   - 'manual' (default): ambil dari product.keys (stok yang diupload
//     admin), match by tag durasi KEY:DAYS kalau selectedDays diminta.
//   - 'ghostseller': generate key langsung dari GhostSeller Partner API
//     (ghostseller-api.js) memakai ghostSellerProductId/ghostSellerDurationId
//     per-varian. Tidak butuh product.keys sama sekali — stok dianggap
//     unlimited selama saldo akun partner di GhostSeller masih cukup.
//
// vipibmstore.com pernah jadi provider 'auto' ketiga di sini, tapi sudah
// DICABUT TOTAL (Sep 2026) -- akun vipibmstore memang tidak pernah ada,
// dan produk yang kepasang 'auto' tanpa kredensial jadi sumber insiden
// nyata (customer bayar, key gagal terkirim). reseller-api.js sudah
// dihapus dari repo.
//
// ctx.idempotencyKey WAJIB diisi caller dan HARUS STABIL untuk order yang
// sama (pakai id transaksi, bukan random tiap panggilan) — supaya kalau
// fungsi ini kepanggil ulang untuk order yang sama (retry jaringan, race
// antara webhook & polling browser) provider tidak generate 2 key /
// motong saldo reseller 2x untuk 1 pembayaran yang sama.
// ══════════════════════════════════════════════════════════════════
// Tentukan sumber stok untuk 1 varian/paket spesifik (bukan lagi 1
// pengaturan global per produk -- lihat dokumentasi klien: tiap varian hari
// provider punya product_item_id BEDA, jadi mode Manual/Auto pun harus bisa
// beda per-varian, bukan dipukul rata untuk seluruh produk).
// Prioritas:
//   1. pricingOptions[i].stockSource -- field baru, per-varian eksplisit.
//   2. Kalau varian tidak ketemu di pricingOptions ATAU field stockSource
//      belum ada (produk lama sebelum redesign ini), fallback ke
//      product.stockMode top-level (backward compat penuh).
function resolveStockSourceForDays(product, selectedDays) {
  // vipibmstore ('auto') dicabut total dari sini (lihat CHANGELOG git) --
  // sekarang cuma ada 2 sumber stok: 'ghostseller' (eksplisit) atau
  // manual (default untuk apa pun selain itu, termasuk data lama yang
  // masih ke-tag 'auto' dari sebelum pencabutan ini -- daripada nyoba
  // manggil provider yang udah gak ada kodenya, lebih aman jatuh ke
  // manual: hasilnya "stok habis" yang jelas, bukan crash atau error
  // "API key belum diatur" yang membingungkan admin).
  if (selectedDays && Array.isArray(product.pricingOptions)) {
    const opt = product.pricingOptions.find(o => o.days === selectedDays);
    if (opt && opt.stockSource === 'ghostseller') return 'ghostseller';
  }
  return 'manual';
}

async function resolveProductKey(product, selectedDays, settings, ctx = {}) {
  const stockSource = resolveStockSourceForDays(product, selectedDays);

  // ── Mode 'ghostseller' — auto restock: generate key live dari
  // Partner API GhostSeller (ghostseller-api.js), pakai mapping
  // ghostSellerProductId/ghostSellerDurationId per-varian. Stok
  // dianggap unlimited selama saldo akun partner di GhostSeller masih
  // cukup. Ini SATU-SATUNYA jalur "auto" yang tersisa sejak vipibmstore
  // dicabut -- semua produk yang butuh auto-restock sekarang lewat sini.
  if (stockSource === 'ghostseller') {
    const opt = Array.isArray(product.pricingOptions)
      ? product.pricingOptions.find(o => o.days === selectedDays)
      : null;
    const productId = (opt && opt.ghostSellerProductId) || product.ghostSellerProductId || null;
    const durationId = opt && opt.ghostSellerDurationId;
    if (!productId || !durationId) {
      return { key: null, outOfStock: true, error: 'Varian ini belum di-mapping ke GhostSeller (isi GhostSeller Product ID & Duration ID di Edit Produk).' };
    }
    const result = await ghostSellerApi.orderKey(settings, {
      productId,
      durationId,
      idempotencyKey: ctx.idempotencyKey
    });
    if (result.success) {
      const key = result.data?.codes?.[0] || null;
      return { key, outOfStock: !key, error: key ? null : 'GhostSeller tidak mengembalikan key' };
    }
    return { key: null, outOfStock: true, error: result.message || 'Gagal auto-restock key dari GhostSeller', code: result.code };
  }

  // ── Mode manual (untuk varian ini spesifik) — logika lama, TIDAK diubah ──
  if (!product.keys || product.keys.length === 0) return { key: null, outOfStock: true };
  let key = null;
  const allKeys = product.keys;
  if (selectedDays) {
    const idx = allKeys.findIndex(k => {
      const parts = k.split(':');
      return parts.length > 1 && parseInt(parts[parts.length - 1]) === selectedDays;
    });
    if (idx !== -1) {
      key = allKeys.splice(idx, 1)[0].split(':')[0];
    } else {
      const genericIdx = allKeys.findIndex(k => !k.includes(':'));
      if (genericIdx !== -1) key = allKeys.splice(genericIdx, 1)[0];
    }
  } else {
    const idx = allKeys.findIndex(k => !k.includes(':'));
    if (idx !== -1) key = allKeys.splice(idx, 1)[0];
    else key = allKeys.shift();
  }
  return { key, outOfStock: !key };
}

app.post('/wallet/buy', requireAuth, async (req, res) => {
  // Cegah race condition double-spend: tolak request kedua kalau request
  // sebelumnya dari user yang sama masih diproses (lihat komentar di
  // deklarasi walletLocks).
  if (walletLocks.has(req.session.userId)) {
    return res.json({ success: false, message: 'Transaksi sebelumnya masih diproses, tunggu sebentar...' });
  }
  walletLocks.add(req.session.userId);
  // walletLocks di atas cuma proteksi dalam 1 instance lambda. Tambahan lock
  // atomik di Supabase supaya double-tap / retry jaringan yang mendarat di
  // 2 instance Vercel berbeda tetap tidak bisa dobel-potong key & saldo yang
  // sama (root cause sama seperti bug double-key di /check-payment).
  const gotWalletLock = await db.acquireLock(`wallet_${req.session.userId}`);
  if (!gotWalletLock) {
    walletLocks.delete(req.session.userId);
    return res.json({ success: false, message: 'Transaksi sebelumnya masih diproses, tunggu sebentar...' });
  }
  try {
    if (req.session.isAdmin) return res.json({ success: false, message: 'Admin tidak bisa membeli produk' });
    const { productId, duration, customerName, wa, voucherCode } = req.body;

    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    // FITUR: beli pakai saldo sekarang terbuka untuk SEMUA user, tidak cuma
    // Reseller VIP — soalnya customer biasa juga bisa dapat saldo dari hasil
    // gacha Arcade Center (lihat GACHA_PRIZES/rollGachaPrize) dan itu harus
    // bisa langsung dipakai buat beli key, bukan cuma nganggur di akun.

    const products = await readFresh('products.json');
    const product = products.find(p => p.id === productId);
    if (!product || product.status !== 'active') return res.json({ success: false, message: 'Produk tidak ditemukan' });
    // Produk dengan stockSource 'ghostseller' (per-varian, lihat
    // resolveStockSourceForDays) tidak pakai product.keys -- key
    // digenerate on-demand, dianggap unlimited. Selain itu (termasuk
    // data lama yang masih ke-tag stockMode/stockSource 'auto' dari
    // vipibmstore yang sudah dicabut total) WAJIB ada product.keys,
    // supaya order tidak lolos untuk produk yang sebenarnya sudah rusak
    // (ini persis insiden Sep 2026: order tetap lolos ke tahap bayar
    // untuk produk 'auto' yang kredensial vipibmstore-nya kosong).
    if (resolveStockSourceForDays(product, duration) !== 'ghostseller' && (!product.keys || product.keys.length === 0)) {
      return res.json({ success: false, message: 'Stok habis' });
    }

    // Resolusi harga paket — logika sama seperti /create-order
    let price = 0, selectedDays = null;
    if (product.pricingOptions?.length) {
      let opt = null;
      const itemMatch = product.items?.find(i => i.l === duration || i.l.includes(duration));
      if (itemMatch) {
        opt = product.pricingOptions.find(o => o.price === itemMatch.p);
        if (!opt) { price = itemMatch.p; const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null; }
        else { price = opt.price; selectedDays = opt.days; }
      } else {
        const days = parseInt(duration);
        opt = product.pricingOptions.find(o => o.days === days);
        if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
        price = opt.price; selectedDays = days;
      }
    } else {
      const opt = product.items?.find(i => i.l.includes(duration));
      if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
      price = opt.p;
      const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null;
    }

    const settings = readDB('settings.json');
    // Diskon reseller CUMA berlaku kalau user memang reseller — samakan
    // logikanya persis dengan /create-order. Sebelumnya blok ini jalan tanpa
    // syarat karena endpoint ini dulu memang reseller-only; sekarang user
    // biasa juga bisa masuk sini (beli pakai saldo gacha), jadi harus dicegah
    // supaya mereka tidak ikut kebagian harga diskon reseller.
    if (user.is_reseller) {
      // Prioritas harga: reseller_price manual per-produk → global diskon %
      const matchedItem = product.items?.find(i => i.l === duration || i.l.includes(duration));
      const matchedOpt = product.pricingOptions?.find(o => o.days === selectedDays);
      const manualResellerPrice = matchedItem?.reseller_price ?? matchedOpt?.reseller_price ?? null;
      if (manualResellerPrice != null && manualResellerPrice >= 0) {
        price = manualResellerPrice;
      } else {
        const disc = settings.resellerDiscount || 20;
        price = Math.round(price * (1 - disc / 100));
      }
    }

    // Terapkan voucher (setelah diskon reseller) — opsional, sama seperti /create-order
    let voucherDiscount = 0, appliedVoucher = null, originalPrice = price;
    if (voucherCode && voucherCode.trim()) {
      const vResult = await validateVoucher(voucherCode, price, req.session.userId);
      if (vResult.valid) {
        voucherDiscount = vResult.discount;
        price = vResult.finalPrice;
        appliedVoucher = vResult.voucher;
      } else {
        return res.json({ success: false, message: 'Voucher: ' + vResult.error });
      }
    }

    const balance = user.balance || 0;
    if (balance < price) {
      return res.json({ success: false, message: 'insufficient_balance', shortfall: price - balance,
        needed: price, balance, plainMessage: `Saldo tidak cukup. Kurang Rp ${(price - balance).toLocaleString('id-ID')}, top up dulu yuk!` });
    }

    // Ambil key — mode manual (stok lokal, duration-specific KEY:DAYS
    // fallback generic seperti sebelumnya) ATAU mode auto (generate
    // on-demand dari Reseller API). Lihat resolveProductKey() untuk detail.
    const keyResult = await resolveProductKey(product, selectedDays, settings, {
      customerReference: customerName || user.username,
      target: wa || undefined,
      idempotencyKey: `wallet-${req.session.userId}-${productId}-${uuidv4()}`
    });
    if (!keyResult.key) {
      return res.json({ success: false, message: keyResult.error || 'Stok habis' });
    }
    const key = keyResult.key;

    // Potong saldo & catat transaksi — lakukan setelah key berhasil diambil
    user.balance = balance - price;
    // Fitur Game Koin: 1 order sukses = 1 koin (lihat juga /check-payment untuk jalur QRIS)
    user.coins = (user.coins || 0) + 1;
    product.sold = (product.sold || 0) + 1;
    await writeDB('users.json', users);
    await writeDB('products.json', products);

    const refId = uuidv4();
    const orderCode = generateOrderCode();
    const transactions = await readFresh('transactions.json');
    transactions.push({
      id: refId, orderId: `WLT-${Date.now()}`, code: orderCode,
      userId: user.id, productId: product.id, productName: product.name,
      duration, selectedDays,
      originalPrice: voucherDiscount > 0 ? originalPrice : undefined,
      voucherCode: appliedVoucher ? appliedVoucher.code : undefined,
      voucherDiscount: voucherDiscount > 0 ? voucherDiscount : undefined,
      price, totalPayment: price, paymentMethod: 'wallet',
      customerName: customerName || user.username, wa: wa || user.wa,
      status: 'done', key, paidAt: new Date().toISOString(),
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    if (appliedVoucher) {
      const vouchers = await readFresh('vouchers.json');
      const v = vouchers.find(v => v.id === appliedVoucher.id);
      if (v) {
        v.usedCount = (v.usedCount || 0) + 1;
        v.usages = v.usages || [];
        v.usages.push({ userId: req.session.userId, usedAt: new Date().toISOString(), orderId: refId });
        await writeDB('vouchers.json', vouchers);
      }
    }

    const notifs = readDB('notifications.json');
    notifs.unshift({ id: uuidv4(), type: 'purchase', buyerName: customerName || user.username,
      buyerPhoto: user.photo || null, productName: product.name,
      price, time: new Date().toISOString(), timeStr: formatDate() });
    await writeDB('notifications.json', notifs.slice(0, 50));

    res.json({ success: true, key, code: orderCode, balance: user.balance, voucherDiscount: voucherDiscount || undefined });
  } catch (e) {
    console.error('[wallet/buy] error:', e.message);
    res.json({ success: false, message: 'Terjadi kesalahan: ' + e.message });
  } finally {
    walletLocks.delete(req.session.userId);
    await db.releaseLock(`wallet_${req.session.userId}`);
  }
});

// ── PROFILE PHOTO ──
const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp/avatars' : path.join(__dirname, 'public', 'uploads', 'avatars');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `${req.session.userId}-${Date.now()}${mimeToSafeExt(file.mimetype)}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.post('/profile/photo', requireAuth, avatarUpload.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'File tidak valid' });

    // Admin tidak punya entry di users.json
    if (req.session.userId === 'admin') {
      return res.json({ success: false, message: 'Admin tidak bisa ganti foto profil dari sini' });
    }

    const users = readDB('users.json');
    const user  = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });

    // Hapus foto lama jika ada
    if (user.photo) {
      const oldPath = path.join(__dirname, 'public', user.photo.replace(/^\//, ''));
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }

    if (!isVercel) { user.photo = `/uploads/avatars/${req.file.filename}`; }
    else { try { user.photo = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch (e) { return res.json({ success: false, message: 'Upload gagal: ' + e.message }); } }
    await writeDB('users.json', users);
    res.json({ success: true, photo: user.photo });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ── BANNER CAROUSEL ──
const bannerCarouselUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp/banners' : path.join(__dirname, 'public', 'uploads', 'banners');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `banner-${Date.now()}${mimeToSafeExt(file.mimetype)}`);
    }
  }),
  limits: { fileSize: 4 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.get('/api/banners', async (req, res) => {
  const settings = await readFresh('settings.json');
  if (normalizeBanners(settings)) await writeDB('settings.json', settings);
  res.json((settings.banners || []).filter(b => b.active !== false));
});

app.post('/admin/banners/add', requireAdmin, bannerCarouselUpload.single('bannerImg'), async (req, res) => {
  try {
    const { title, subtitle, link, imageUrl } = req.body;
    const settings = await readFresh('settings.json');
    if (!settings.banners) settings.banners = [];
    let imgSrc = imageUrl?.trim() || '';
    if (req.file) {
      if (!isVercel) {
        imgSrc = `/uploads/banners/${req.file.filename}`;
      } else {
        try {
          imgSrc = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype);
        } catch {
          // Fallback: simpan sebagai base64 data URL agar muncul tanpa storage eksternal
          const buf = require('fs').readFileSync(req.file.path);
          imgSrc = `data:${req.file.mimetype};base64,${buf.toString('base64')}`;
        }
      }
    }
    if (!imgSrc) return res.json({ success: false, message: 'Gambar banner wajib diisi' });
    settings.banners.push({
      id: uuidv4(),
      imageUrl: imgSrc,
      title: title?.trim() || '',
      subtitle: subtitle?.trim() || '',
      link: link?.trim() || '/',
      active: true,
      createdAt: new Date().toISOString()
    });
    await writeDB('settings.json', settings);
    res.json({ success: true, banners: settings.banners });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/banners/delete/:id', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const old = (settings.banners || []).find(b => b.id === req.params.id);
    if (old?.imageUrl?.startsWith('/uploads/banners/')) {
      const fp = path.join(__dirname, 'public', old.imageUrl);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    settings.banners = (settings.banners || []).filter(b => b.id !== req.params.id);
    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/banners/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const b = (settings.banners || []).find(b => b.id === req.params.id);
    if (b) b.active = !b.active;
    await writeDB('settings.json', settings);
    res.json({ success: true, active: b?.active });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// ── QRIS STATIS UPLOAD ──
const qrisUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp' : path.join(__dirname, 'public', 'uploads');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `qris-static${mimeToSafeExt(file.mimetype)}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.post('/admin/qris/upload', requireAdmin, qrisUpload.single('qrisImage'), async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'File tidak valid' });
    const settings = await readFresh('settings.json');
    if (!isVercel) {
      settings.qrisStaticImage = `/uploads/${req.file.filename}`;
    } else {
      try { settings.qrisStaticImage = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch (e) { return res.json({ success: false, message: e.message }); }
    }
    await writeDB('settings.json', settings);
    res.json({ success: true, path: settings.qrisStaticImage });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.get('/profile/me', requireAuth, (req, res) => {
  if (req.session.isAdmin) {
    const s = readDB('settings.json');
    return res.json({ success: true, user: { id: 'admin', username: s.adminUsername || 'Admin', isAdmin: true, is_reseller: false, photo: null } });
  }
  const users = readDB('users.json');
  const user  = users.find(u => u.id === req.session.userId);
  if (!user) return res.json({ success: false });
  const { password: _, ...safe } = user;
  res.json({ success: true, user: safe });
});

// ── User Dashboard ──
app.get('/dashboard', requireAuth, async (req, res) => {
  // readFresh: histori pembelian & key harus data terbaru dari Supabase,
  // bukan cache basi instance lambda ini (lihat catatan di /check-payment).
  const transactions = await readFresh('transactions.json');
  const user = getSessionUser(req);
  const settings = readDB('settings.json');

  // Filter transaksi milik user ini
  const myTransactions = transactions.filter(t => t.userId === req.session.userId);
  const totalOrders = myTransactions.length;
  const successOrders = myTransactions.filter(t => t.status === 'done').length;
  const pendingOrders = myTransactions.filter(t => t.status === 'pending').length;
  const totalSpent = myTransactions.filter(t => t.status === 'done').reduce((s, t) => s + (t.price || 0), 0);
  const doneTransactions = myTransactions.filter(t => t.status === 'done').sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const recentTransactions = myTransactions.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 20);

  res.render('pages/dashboard', {
    user, settings,
    stats: { totalOrders, successOrders, pendingOrders, totalSpent },
    doneTransactions,
    transactions: recentTransactions,
    walletTransactions: myTransactions.filter(t => t.type === 'deposit' || t.type === 'adjustment').sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 15)
  });
});

// ── ARCADE CENTER (Fitur Game Koin) ──────────────────────────────────────
// Setiap 1 order sukses (QRIS maupun bayar pakai saldo) otomatis kasih 1
// koin (lihat /wallet/buy dan /check-payment). Koin dipakai sebagai tiket
// buat main game di Arcade Center — hadiahnya saldo wallet atau voucher.
const GACHA_PRIZES = [
  { id: 'zonk',      label: 'Zonk, coba lagi!',        type: 'zonk',    weight: 45 },
  { id: 'saldo1k',   label: 'Saldo Rp 1.000',           type: 'saldo',   value: 1000,  weight: 20 },
  { id: 'saldo2k',   label: 'Saldo Rp 2.000',           type: 'saldo',   value: 2000,  weight: 12 },
  { id: 'saldo5k',   label: 'Saldo Rp 5.000',           type: 'saldo',   value: 5000,  weight: 8  },
  { id: 'voucher5',  label: 'Voucher Diskon 5%',        type: 'voucher', value: 5,     weight: 8  },
  { id: 'saldo10k',  label: 'Saldo Rp 10.000',          type: 'saldo',   value: 10000, weight: 4  },
  { id: 'voucher10', label: 'Voucher Diskon 10%',       type: 'voucher', value: 10,    weight: 3  },
];
const GACHA_GAMES = { wheel: 'Roda Keberuntungan', dice: 'Kocok Dadu', box: 'Peti Rahasia' };

const rollGachaPrize = (prizeTable) => {
  const table = (Array.isArray(prizeTable) && prizeTable.length) ? prizeTable : GACHA_PRIZES;
  const totalWeight = table.reduce((s, p) => s + p.weight, 0);
  let r = Math.random() * totalWeight;
  for (const p of table) {
    r -= p.weight;
    if (r <= 0) return p;
  }
  return table[0];
};

app.get('/arcade', requireAuth, (req, res) => {
  const user = getSessionUser(req);
  if (!user || user.isAdmin) return res.redirect('/');
  const settings = readDB('settings.json');
  const history = readDB('transactions.json')
    .filter(t => t.type === 'gacha' && t.userId === req.session.userId)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 15);

  const rawPrizeTable = (settings.gacha && Array.isArray(settings.gacha.prizes) && settings.gacha.prizes.length)
    ? settings.gacha.prizes : GACHA_PRIZES;
  const products = readDB('products.json');
  // Sama seperti /arcade/play: hadiah key yang stok product-nya kosong jangan
  // ikut ditampilkan di roda, biar tidak menjanjikan hadiah yang gak ada.
  const prizeTable = rawPrizeTable.filter(p => {
    if (p.type !== 'key') return true;
    const prod = products.find(pr => pr.id === p.productId);
    return !!(prod && Array.isArray(prod.keys) && prod.keys.length > 0);
  });

  res.render('pages/arcade', { user, settings, coins: user.coins || 0, history, prizeTable: prizeTable.length ? prizeTable : GACHA_PRIZES });
});

app.post('/arcade/play', requireAuth, async (req, res) => {
  if (walletLocks.has(req.session.userId)) {
    return res.json({ success: false, message: 'Masih ada transaksi diproses, tunggu sebentar...' });
  }
  walletLocks.add(req.session.userId);
  const gotArcadeLock = await db.acquireLock(`arcade_${req.session.userId}`);
  if (!gotArcadeLock) {
    walletLocks.delete(req.session.userId);
    return res.json({ success: false, message: 'Masih ada transaksi diproses, tunggu sebentar...' });
  }
  try {
    const { game } = req.body;
    if (!GACHA_GAMES[game]) return res.json({ success: false, message: 'Game tidak dikenal' });

    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    const coins = user.coins || 0;
    if (coins < 1) return res.json({ success: false, message: 'Koin kamu habis. Order dulu yuk buat dapat koin (1 order = 1 koin)!' });

    user.coins = coins - 1;

    const settings = await readFresh('settings.json');
    const rawPrizeTable = (settings.gacha && Array.isArray(settings.gacha.prizes) && settings.gacha.prizes.length)
      ? settings.gacha.prizes : GACHA_PRIZES;

    const products = await readFresh('products.json');
    // Hadiah tipe 'key' yang product-nya sudah habis stok jangan ikut diundi —
    // supaya user tidak dijanjikan key yang ternyata gak ada.
    let activePrizeTable = rawPrizeTable.filter(p => {
      if (p.type !== 'key') return true;
      const prod = products.find(pr => pr.id === p.productId);
      return !!(prod && Array.isArray(prod.keys) && prod.keys.length > 0);
    });
    if (!activePrizeTable.length) activePrizeTable = [{ id: 'zonk', label: 'Zonk, coba lagi!', type: 'zonk', weight: 1 }];

    let prize = rollGachaPrize(activePrizeTable);
    let voucherCode = null;
    let wonKey = null;
    let wonProductName = null;

    if (prize.type === 'saldo') {
      user.balance = (user.balance || 0) + prize.value;
    } else if (prize.type === 'voucher') {
      voucherCode = 'GACHA-' + crypto.randomBytes(3).toString('hex').toUpperCase();
      const vouchers = await readFresh('vouchers.json');
      vouchers.push({
        id: uuidv4(), code: voucherCode, type: 'percent', value: prize.value,
        active: true, maxUses: 1, usedCount: 0, perUserLimit: 1, minPurchase: 0,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        source: 'gacha', ownerId: user.id, usages: [],
        createdAt: new Date().toISOString()
      });
      await writeDB('vouchers.json', vouchers);
    } else if (prize.type === 'key') {
      const product = products.find(pr => pr.id === prize.productId);
      if (product?.keys?.length > 0) {
        // Prioritaskan key generic (tanpa format "KEY:DAYS"); kalau tidak ada,
        // ambil apa saja dan buang penanda durasinya karena gacha tidak
        // punya konsep durasi seperti pembelian biasa.
        const idx = product.keys.findIndex(k => !k.includes(':'));
        const raw = idx !== -1 ? product.keys.splice(idx, 1)[0] : product.keys.shift();
        wonKey = raw.split(':')[0];
        wonProductName = product.name;
        product.sold = (product.sold || 0) + 1;
        await writeDB('products.json', products);
      } else {
        // Race condition: stok habis tepat saat mau diambil (2 user gacha
        // bersamaan). Jangan biarkan user rugi koin tanpa dapat apa-apa —
        // kasih saldo pengganti kecil.
        user.balance = (user.balance || 0) + 2000;
        prize = { ...prize, type: 'saldo', value: 2000, label: `Saldo Rp 2.000 (pengganti, stok key "${prize.label}" habis)` };
      }
    }

    await writeDB('users.json', users);

    const transactions = await readFresh('transactions.json');
    transactions.push({
      id: uuidv4(), type: 'gacha', userId: user.id, game, gameLabel: GACHA_GAMES[game],
      prizeId: prize.id, prizeLabel: prize.label, prizeType: prize.type,
      prizeValue: prize.value || 0, voucherCode, wonKey, wonProductName,
      status: 'done', createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    res.json({
      success: true,
      prize: { label: prize.label, type: prize.type, value: prize.value || 0, voucherCode, key: wonKey, productName: wonProductName },
      coins: user.coins, balance: user.balance || 0
    });
  } catch (e) {
    console.error('[arcade/play] error:', e.message);
    res.json({ success: false, message: 'Terjadi kesalahan: ' + e.message });
  } finally {
    walletLocks.delete(req.session.userId);
    await db.releaseLock(`arcade_${req.session.userId}`);
  }
});

// Product routes
app.get('/buy/:id', requireAuth, async (req, res) => {
  // PENTING — FIX BUG: sebelumnya pakai readDB() (baca cache in-memory
  // proses ini doang, TANPA cek apakah masih fresh), bukan readFresh().
  // Di Vercel (serverless multi-instance), kalau admin edit harga produk,
  // update itu tersimpan benar ke Supabase — tapi instance lain yang sedang
  // melayani request customer di /buy/:id ini masih punya cache LAMA di
  // memorinya sendiri, dan readDB() tidak pernah tahu cache itu sudah basi.
  // Akibatnya: harga baru yang diedit admin tidak pernah muncul ke customer
  // sampai instance itu kebetulan cold-start ulang. readFresh() selalu ambil
  // data terbaru langsung dari Supabase, jadi update harga langsung akurat.
  const products = await readFresh('products.json');
  const product = products.find(p => p.id === req.params.id);

  if (!product || product.status !== 'active') {
    return res.redirect('/');
  }

  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || await readFresh('settings.json');
  const user = res.locals.user || getSessionUser(req);

  const isReseller = !!(user?.is_reseller);
  const resellerDiscount = settings.resellerDiscount || 20;
  const allKeys = product.keys || [];
  const genericKeys = allKeys.filter(k => !k.includes(':'));
  if (product.items) {
    product.items = product.items.map(item => {
      // FIX: pakai parseItemLabel() yang terima format baru ("1 JAM"/"1
      // HARI"/"1 MENIT") maupun lama ("1 DAYS") -- sebelumnya regex di sini
      // cuma cari suffix "DAYS", jadi label baru "1 JAM" gagal match dan
      // days jadi null (stok/harga match jadi salah untuk produk yang sudah
      // dipakai fitur unit Jam/Menit).
      const { days } = parseItemLabel(item.l);
      // BUG FIX: sebelumnya "stok" di sini SELALU dihitung dari product.keys
      // (stok manual) doang, nggak peduli sama sekali stockSource/stockMode
      // per-varian. Akibatnya produk mode 'auto' (key digenerate on-demand
      // dari Reseller API, keys manual memang sengaja kosong) selalu kehitung
      // stok=0 di sini. buy.ejs versi terbaru sudah nggak baca field `stok`
      // ini lagi (dia hitung sendiri dari pricingOptions[idx].stockSource),
      // jadi bug ini sebenarnya sudah "netral" di tampilan sekarang -- tapi
      // field ini tetap dikirim ke view/JS lain, jadi tetap disamakan
      // logikanya dengan resolveStockSourceForDays() di atas biar konsisten
      // & nggak jadi jebakan buat kode lain yang mungkin masih baca `item.stok`.
      // vipibmstore ('auto') dicabut total -- cuma 'ghostseller' yang dianggap
      // unlimited di sini sekarang.
      const stockOpt = days ? (product.pricingOptions || []).find(o => o.days === days) : null;
      const variantStockSource = stockOpt?.stockSource === 'ghostseller' ? 'ghostseller' : 'manual';
      let stok;
      if (variantStockSource === 'ghostseller') {
        stok = Infinity;
      } else if (days) {
        const tagged = allKeys.filter(k => {
          const parts = k.split(':');
          return parts.length > 1 && parseInt(parts[parts.length - 1]) === days;
        }).length;
        stok = tagged > 0 ? tagged : genericKeys.length;
      } else {
        stok = genericKeys.length;
      }
      // Prioritas harga reseller: 1) harga manual per-produk jika ada,
      // 2) harga dari pricingOptions, 3) fallback ke global diskon %
      let computedResellerPrice = null;
      if (isReseller) {
        if (item.reseller_price != null && item.reseller_price >= 0) {
          computedResellerPrice = item.reseller_price;
        } else {
          // Cek di pricingOptions
          const pOpt = (product.pricingOptions || []).find(o => o.days === days);
          if (pOpt?.reseller_price != null && pOpt.reseller_price >= 0) {
            computedResellerPrice = pOpt.reseller_price;
          } else {
            computedResellerPrice = Math.round(item.p * (1 - resellerDiscount / 100));
          }
        }
      }
      return { ...item, stok, reseller_price: computedResellerPrice };
    });
  }

  // Cek apakah user sudah pernah membeli (transaksi sukses) produk ini
  const transactions = await readFresh('transactions.json');
  const hasPurchased = transactions.some(t =>
    t.userId === user?.id &&
    t.productId === product.id &&
    t.status === 'done'
  );

  res.render('pages/buy', { product, settings, user, isReseller, hasPurchased });
});

app.post('/create-order', requireAuth, async (req, res) => {
  try {
    // Kebijakan wajib GensPay (15 Agu 2026): maks 30 request/3 menit per
    // pengguna untuk generate QRIS -- lihat checkPaymentRateLimit di atas.
    if (!checkPaymentRateLimit(req.session.userId)) {
      return res.json({ success: false, message: 'Terlalu banyak percobaan transaksi. Coba lagi dalam beberapa menit.' });
    }
    const { productId, duration, customerName, wa, voucherCode } = req.body;
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === productId);

    if (!product || product.status !== 'active') return res.json({ success: false, message: 'Produk tidak ditemukan' });
    // Produk dengan stockSource 'ghostseller' (per-varian) generate key
    // on-demand saat pembayaran dikonfirmasi (lihat finalizeConfirmedPayment)
    // — tidak butuh product.keys, jadi lewati cek stok lokal untuk varian
    // itu. Selain itu (termasuk data lama yang masih ke-tag 'auto' dari
    // vipibmstore yang sudah dicabut total) WAJIB ada product.keys — lihat
    // catatan identik di /wallet/buy soal kenapa ini penting.
    if (resolveStockSourceForDays(product, duration) !== 'ghostseller' && (!product.keys || product.keys.length === 0)) {
      return res.json({ success: false, message: 'Stok habis' });
    }

    // Support pricingOptions (deem style: {days,price}) dan items (lama: {l,p})
    let price = 0, selectedDays = null;
    if (product.pricingOptions?.length) {
      // duration bisa berupa label teks ("PRODUK 30 DAYS") atau angka ("30")
      // Coba match by label dulu via items, lalu fallback ke ekstrak angka
      let opt = null;
      const itemMatch = product.items?.find(i => i.l === duration || i.l.includes(duration));
      if (itemMatch) {
        // Cari pricingOptions yang cocok dengan price dari items
        opt = product.pricingOptions.find(o => o.price === itemMatch.p);
        if (!opt) { price = itemMatch.p; const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null; }
        else { price = opt.price; selectedDays = opt.days; }
      } else {
        // Fallback: parseInt langsung (untuk case duration dikirim sebagai angka)
        const days = parseInt(duration);
        opt = product.pricingOptions.find(o => o.days === days);
        if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
        price = opt.price; selectedDays = days;
      }
    } else {
      const opt = product.items?.find(i => i.l.includes(duration));
      if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
      price = opt.p;
      const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null;
    }

    // FIX: pakai readFresh (bukan readDB) — settings ini dipakai untuk
    // menghitung harga FINAL transaksi (diskon reseller %), jadi harus
    // selalu data terbaru dari Supabase, bukan cache in-memory instance ini
    // yang bisa saja masih menyimpan angka diskon lama.
    const settings = await readFresh('settings.json');
    // Terapkan harga reseller: gunakan harga manual per-produk jika ada,
    // fallback ke global diskon % jika tidak ada
    const orderUser = getSessionUser(req);
    if (orderUser?.is_reseller) {
      // Cari item yang sesuai untuk cek reseller_price manual
      const matchedItem = product.items?.find(i => i.l === duration || i.l.includes(duration));
      const matchedOpt = product.pricingOptions?.find(o => o.days === selectedDays);
      const manualResellerPrice = matchedItem?.reseller_price ?? matchedOpt?.reseller_price ?? null;
      if (manualResellerPrice != null && manualResellerPrice >= 0) {
        price = manualResellerPrice;
      } else {
        const disc = settings.resellerDiscount || 20;
        price = Math.round(price * (1 - disc / 100));
      }
    }

    // Terapkan voucher (setelah diskon reseller)
    let voucherDiscount = 0, appliedVoucher = null, originalPrice = price;
    if (voucherCode && voucherCode.trim()) {
      const vResult = await validateVoucher(voucherCode, price, req.session.userId);
      if (vResult.valid) {
        voucherDiscount = vResult.discount;
        price = vResult.finalPrice;
        appliedVoucher = vResult.voucher;
      } else {
        return res.json({ success: false, message: 'Voucher: ' + vResult.error });
      }
    }

    const qrisMode = settings.qrisMode || 'static';
    const orderId = `VR-${Date.now()}`;
    const refId = uuidv4();
    const orderCode = generateOrderCode();

    let qrString = null, isStatic = false, totalPayment = price, expiredAt = null, fallbackReason = null;

    if (qrisMode === 'static') {
      if (!settings.qrisStaticImage) return res.json({ success: false, message: 'Upload gambar QRIS di admin panel terlebih dahulu.' });
      isStatic = true;
    } else {
      try {
        const r = await createQRISPayment(orderId, price, settings);
        qrString = r.qr_string;
        totalPayment = r.total_payment || price;
        expiredAt = r.expired_at || null;
      } catch (error) {
        // Sama seperti /wallet/topup: kalau createQRISPayment gagal (IP
        // diblokir gateway, dsb), sebelumnya diam-diam jatuh ke static tanpa
        // jejak -- transaksi jadi butuh konfirmasi manual terus dan
        // kelihatan seperti "auto payment masih bug". Sekarang dicatat.
        console.warn(`[create-order] createQRISPayment (${qrisMode}) gagal, fallback ke static:`, error.message);
        if (settings.qrisStaticImage) { isStatic = true; fallbackReason = error.message; }
        else return res.json({ success: false, message: 'QRIS API error: ' + error.message });
      }
    }

    const transactions = await readFresh('transactions.json');

    // Cegah transaksi duplikat: tolak jika ada pending untuk produk yang sama dalam 30 menit
    const existingPending = transactions.find(t =>
      t.userId === req.session.userId &&
      t.productId === productId &&
      t.status === 'pending' &&
      (Date.now() - new Date(t.createdAt).getTime()) < 30 * 60 * 1000
    );
    if (existingPending) {
      return res.json({ success: false, message: 'Kamu masih memiliki pesanan pending untuk produk ini. Selesaikan pembayaran atau tunggu 30 menit.' });
    }

    transactions.push({
      id: refId, orderId, code: orderCode,
      userId: req.session.userId, productId: product.id, productName: product.name,
      duration, selectedDays,
      originalPrice: voucherDiscount > 0 ? originalPrice : undefined,
      voucherCode: appliedVoucher ? appliedVoucher.code : undefined,
      voucherDiscount: voucherDiscount > 0 ? voucherDiscount : undefined,
      price, totalPayment,
      customerName, wa, qrString, isStatic,
      paymentGateway: isStatic ? null : qrisMode,
      fallbackReason,
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    // Catat pemakaian voucher jika dipakai
    if (appliedVoucher) {
      const vouchers = await readFresh('vouchers.json');
      const v = vouchers.find(v => v.id === appliedVoucher.id);
      if (v) {
        v.usedCount = (v.usedCount || 0) + 1;
        v.usages = v.usages || [];
        v.usages.push({ userId: req.session.userId, usedAt: new Date().toISOString(), orderId: refId });
        await writeDB('vouchers.json', vouchers);
      }
    }

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic, totalPayment, expiredAt,
      voucherDiscount: voucherDiscount || undefined,
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (error) {
    console.error('[create-order] error:', error.message);
    res.json({ success: false, message: 'Terjadi kesalahan: ' + error.message });
  }
});

// Proses order yang statusnya SUDAH dipastikan paid=true: kirim key / tambah
// saldo / upgrade reseller. Diekstrak jadi fungsi terpisah supaya bisa dipakai
// dari 2 jalur:
//   1) /check-payment  → dipanggil polling dari browser pembeli
//   2) /webhook/genspay → dipanggil server-to-server oleh GensPay
// Sebelumnya HANYA jalur (1) yang ada. Kalau pembeli menutup tab/app setelah
// bayar (sangat umum — orang bayar lewat app bank/e-wallet lalu langsung
// keluar), polling browser berhenti dan tidak ada apapun di server yang
// memproses ulang → key tidak pernah terkirim walau uang sudah masuk. Ini
// akar penyebab bug "banyak yang gak ke-send otomatis". Webhook menutup celah
// itu karena jalan di server, tidak bergantung pembeli membuka halaman.
async function finalizeConfirmedPayment(refId) {
  // LOCK LINTAS-INSTANCE (fix bug "2 key terkirim, 1 hasilnya ikut kebawa"):
  // processingOrders di route /check-payment cuma proteksi DALAM 1 instance
  // lambda saja. Di Vercel, 2 request nyaris bersamaan (polling browser +
  // webhook GensPay, atau 2 polling dari 2 instance berbeda) bisa mendarat di
  // instance SERVERLESS BERBEDA — instance B tidak tahu instance A sedang
  // memproses, jadi keduanya lolos readFresh + splice key sendiri-sendiri,
  // hasilnya 2 key kepotong dari stok padahal pembayarannya cuma 1. Fix-nya:
  // rebut lock atomik di tabel Supabase (unique constraint = atomic di level
  // DB, beda instance/proses tetap saling kenal) SEBELUM masuk ke bagian
  // kirim key / tambah saldo / upgrade reseller.
  const gotLock = await db.acquireLock(`order_${refId}`);
  if (!gotLock) {
    // Instance/proses lain sedang menyelesaikan order ini — jangan ikut
    // proses, cukup balas pending; pemanggil berikutnya bakal lihat 'done'.
    return { success: true, status: 'pending' };
  }
  try {
    // Re-ambil transaksi paling fresh sekali lagi tepat sebelum diproses —
    // mengecilkan window race kalau ada 2 pemanggil nyaris bersamaan.
    const transactionsRecheck = await readFresh('transactions.json');
    const freshTx = transactionsRecheck.find(t => t.id === refId);
    if (!freshTx) return { success: false, message: 'Transaksi tidak ditemukan' };
    const idxTx = transactionsRecheck.findIndex(t => t.id === refId);

    // Jika transaksi reseller, upgrade status user
    if (freshTx.type === 'reseller') {
      if (freshTx.status === 'done') return { success: true, status: 'done', type: 'reseller' };
      const users = await readFresh('users.json');
      const u = users.find(u => u.id === freshTx.userId);
      if (u) {
        u.is_reseller = true;
        u.role = 'reseller';
        u.reseller_since = new Date().toISOString();
        u.reseller_code = 'RSL-' + u.username.toUpperCase().slice(0, 4) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
        await writeDB('users.json', users);
      }
      freshTx.status = 'done';
      freshTx.paidAt = new Date().toISOString();
      if (idxTx !== -1) transactionsRecheck[idxTx] = freshTx;
      await writeDB('transactions.json', transactionsRecheck);
      return { success: true, status: 'done', type: 'reseller' };
    }

    // Jika transaksi top up saldo wallet, kreditkan saldo user
    if (freshTx.type === 'deposit') {
      if (freshTx.status === 'done') {
        const uAlready = (await readFresh('users.json')).find(u => u.id === freshTx.userId);
        return { success: true, status: 'done', type: 'deposit', balance: uAlready?.balance || 0 };
      }
      const users = await readFresh('users.json');
      const u = users.find(u => u.id === freshTx.userId);
      if (u) {
        u.balance = (u.balance || 0) + (freshTx.amount || freshTx.price || 0);
        await writeDB('users.json', users);
      }
      freshTx.status = 'done';
      freshTx.paidAt = new Date().toISOString();
      if (idxTx !== -1) transactionsRecheck[idxTx] = freshTx;
      await writeDB('transactions.json', transactionsRecheck);
      return { success: true, status: 'done', type: 'deposit', balance: u?.balance || 0 };
    }

    if (freshTx.status === 'done') {
      return { success: true, status: 'done', key: freshTx.key, code: freshTx.code };
    }

    const products = await readFresh('products.json');
    const product = products.find(p => p.id === freshTx.productId);
    let key = null;
    let outOfStock = false;
    let keyError = null;

    if (product) {
      // idempotencyKey = freshTx.id (STABIL per transaksi) — penting untuk
      // produk stockMode 'auto': kalau fungsi ini somehow terpanggil ulang
      // untuk refId yang sama (di luar acquireLock di atas), Reseller API
      // akan mengenali Idempotency-Key yang sama dan me-return response yang
      // sama persis alih-alih generate key baru / motong saldo reseller lagi.
      const settingsForKey = await readFresh('settings.json');
      const keyResult = await resolveProductKey(product, freshTx.selectedDays, settingsForKey, {
        customerReference: freshTx.customerName || freshTx.code,
        target: freshTx.wa || undefined,
        idempotencyKey: freshTx.id
      });
      key = keyResult.key;
      outOfStock = keyResult.outOfStock && !key;
      keyError = keyResult.error || null;
    }

    if (key) {
      product.sold = (product.sold || 0) + 1;
      await writeDB('products.json', products);
      // Fitur Game Koin: 1 order sukses = 1 koin
      const usersForCoin = await readFresh('users.json');
      const buyerForCoin = usersForCoin.find(u => u.id === freshTx.userId);
      if (buyerForCoin) {
        buyerForCoin.coins = (buyerForCoin.coins || 0) + 1;
        await writeDB('users.json', usersForCoin);
      }
    } else {
      // Stok habis — jangan kirim key palsu. Tandai transaksi & beri tahu admin via WA.
      outOfStock = true;
    }

    freshTx.status = 'done';
    freshTx.key = key;
    freshTx.outOfStock = outOfStock;
    // Simpan alasan spesifik (kalau ada, mis. error dari Reseller API) supaya
    // admin bisa lihat detail penyebabnya di panel, bukan cuma tahu "gagal"
    // tanpa konteks. Dipakai badge "❌ Gagal (Stok Habis)" di admin.ejs.
    freshTx.stockError = outOfStock ? (keyError || 'Stok habis - tidak ada key tersedia untuk produk ini') : null;
    freshTx.paidAt = new Date().toISOString();
    if (idxTx !== -1) transactionsRecheck[idxTx] = freshTx;
    await writeDB('transactions.json', transactionsRecheck);

    if (outOfStock) {
      const settingsForNotif = await readFresh('settings.json');
      const reasonLine = keyError ? `Alasan: ${keyError}\n\n` : '\n';
      const waMsg = `⚠️ STOK HABIS - Pesanan butuh diproses manual!\n\n` +
        `Order: ${freshTx.code}\n` +
        `Produk: ${freshTx.productName}\n` +
        `Customer: ${freshTx.customerName} (${freshTx.wa || '-'})\n` +
        `Total: Rp ${Number(freshTx.price).toLocaleString('id-ID')}\n\n` +
        reasonLine +
        `Pembayaran sudah masuk tapi key belum terkirim. Segera proses key manual ke pembeli.`;
      sendWhatsAppNotif(settingsForNotif.contact?.whatsapp, waMsg, settingsForNotif).catch(() => {});
    }

    const notifs = await readFresh('notifications.json');
    const buyer = (await readFresh('users.json')).find(u => u.id === freshTx.userId);
    notifs.unshift({ id: uuidv4(), type: 'purchase', buyerName: freshTx.customerName,
      buyerPhoto: buyer?.photo || null, productName: freshTx.productName,
      price: freshTx.price, time: freshTx.paidAt, timeStr: formatDate(new Date(freshTx.paidAt)) });
    await writeDB('notifications.json', notifs.slice(0, 50));

    return { success: true, status: 'done', key, code: freshTx.code, outOfStock };
  } finally {
    // Selalu lepas lock, baik sukses maupun error, supaya order ini bisa
    // dicoba lagi di pemanggilan berikutnya kalau tadi gagal di tengah jalan.
    await db.releaseLock(`order_${refId}`);
  }
}

// ══════════════════════════════════════════════════════════════════
// WEBHOOK PAKASIR — dipanggil server-to-server oleh Pakasir begitu
// pembayaran QRIS sukses & dana masuk, TANPA bergantung pembeli membuka
// atau tetap membuka halaman pembayaran.
//
// CARA AKTIFKAN: buka dashboard Pakasir → pilih proyek → "Edit Proyek" →
// isi kolom "Webhook URL" dengan:
//   https://domainkamu.com/webhook/pakasir
// ══════════════════════════════════════════════════════════════════
app.post('/webhook/pakasir', async (req, res) => {
  try {
    const { order_id, project, status, amount } = req.body || {};
    if (!order_id) return res.status(400).json({ success: false, message: 'order_id kosong' });

    const settings = await readFresh('settings.json');
    // Pastikan webhook ini memang untuk project Pakasir kita sendiri, bukan
    // request nyasar/di-spoof orang lain yang menebak URL webhook.
    if (project && settings.pakasir?.project && project !== settings.pakasir.project) {
      return res.status(400).json({ success: false, message: 'Project tidak cocok' });
    }

    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.orderId === order_id);
    if (!transaction) return res.status(404).json({ success: false, message: 'Transaksi tidak ditemukan' });

    if (transaction.status === 'done') return res.json({ success: true, status: 'already_done' });
    if (transaction.isStatic) return res.json({ success: true, status: 'ignored_static' });

    // FIX BUG KEAMANAN: sebelumnya kalau body webhook mengaku status=completed
    // TAPI amount-nya tidak cocok dengan transaction.price, itu tetap lolos
    // sebagai fallback saat API re-verifikasi gagal — celah spoofing kalau
    // endpoint webhook ini ketebak orang lain (kirim POST manual order_id lama
    // + status completed). Sekarang, kalau body menyertakan amount, WAJIB
    // cocok persis dengan transaction.price sebelum dianggap kandidat 'paid'.
    // FIX BUG "key gak ke-kirim otomatis walau sudah bayar": sebelumnya
    // amount dari body webhook HANYA dibandingkan ke transaction.price (harga
    // dasar produk). Padahal Pakasir menambahkan KODE UNIK ke nominal QRIS
    // supaya tiap transaksi bisa dibedakan (mis. harga dasar Rp13.000 tapi
    // yang harus ditransfer & dilaporkan Pakasir di webhook Rp13.341) — nilai
    // ini sudah kita simpan sendiri sebagai transaction.totalPayment saat
    // order dibuat (lihat /create-order). Karena amount webhook (totalPayment)
    // hampir tidak pernah sama persis dengan transaction.price, validasi lama
    // SELALU gagal untuk transaksi ber-kode-unik → webhook menolak memproses
    // padahal pembayarannya sah, dan kalau pembeli sudah menutup tab (polling
    // browser berhenti), key tidak pernah terkirim sama sekali walau uang
    // sudah masuk. Sekarang: terima kalau amount cocok salah satu dari
    // transaction.price ATAU transaction.totalPayment.
    const bodyAmount = amount !== undefined ? parseInt(amount) : null;
    const expectedAmounts = [parseInt(transaction.price), parseInt(transaction.totalPayment ?? transaction.price)];
    const amountMatches = bodyAmount === null || expectedAmounts.includes(bodyAmount);
    if (!amountMatches) {
      console.error(`[webhook-pakasir] amount body (${bodyAmount}) tidak cocok dengan transaction.price/totalPayment (${expectedAmounts.join(' atau ')}) untuk order ${order_id} — ditolak`);
      return res.status(400).json({ success: false, message: 'Amount tidak cocok' });
    }

    // Pakasir sendiri menyarankan tidak percaya body webhook mentah-mentah —
    // re-verifikasi ke API transactiondetail pakai amount ASLI (transaction.price).
    // PENTING: pakai checkPaymentStatusPakasir LANGSUNG (bukan dispatcher),
    // supaya webhook ini selalu konsisten verifikasi ke Pakasir apapun
    // qrisMode yang aktif sekarang di panel admin.
    let paid = false;
    let verifiedByApi = false;
    try {
      const r = await checkPaymentStatusPakasir(transaction.orderId, transaction.price, settings);
      const st = (r.transaction?.status || r.status || '').toLowerCase();
      paid = ['completed','success','paid','settlement','capture','complete','authorize','accepted'].includes(st);
      verifiedByApi = true;
    } catch (e) {
      console.error(`[webhook-pakasir] Gagal re-verifikasi order ${order_id} ke API PakKasir, pakai status dari body webhook:`, e.message);
      // Kalau re-verifikasi API gagal (mis. network), tetap lanjut pakai status
      // dari body webhook sebagai fallback — TAPI amount di body sudah wajib
      // cocok (dicek di atas), jadi fallback ini tidak lagi bisa dipicu cuma
      // dengan menebak order_id + kirim status completed tanpa amount benar.
      paid = String(status || '').toLowerCase() === 'completed';
    }

    if (!paid) return res.json({ success: true, status: 'not_paid_yet' });
    if (!verifiedByApi) {
      console.warn(`[webhook-pakasir] order ${order_id} di-finalize dari fallback body webhook (API re-verifikasi gagal), bukan dari API PakKasir langsung`);
    }

    const result = await finalizeConfirmedPayment(transaction.id);
    return res.json(result);
  } catch (error) {
    console.error('[webhook-pakasir] error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// WEBHOOK GENSPAY — dipanggil server-to-server oleh GensPay begitu
// pembayaran QRIS sukses & dana masuk, TANPA bergantung pembeli membuka
// atau tetap membuka halaman pembayaran. ← FIX bug utama "key gak
// ke-send otomatis": sebelumnya satu-satunya jalur konfirmasi cuma
// polling dari browser pembeli di /check-payment, yang otomatis berhenti
// begitu pembeli tutup tab/app setelah bayar.
//
// CARA AKTIFKAN: buka dashboard GensPay → pilih project → isi kolom
// "Webhook URL" dengan:
//   https://domainkamu.com/webhook/genspay
//
// 📖 Dokumentasi Integrasi: https://genspay.my.id/docs (Swagger API)
// Base URL API: https://genspay.my.id/api/v1
// ══════════════════════════════════════════════════════════════════
app.post('/webhook/genspay', async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const apiKey = (settings.genspay?.apiKey || process.env.GENSPAY_API_KEY || '').trim();
    const signatureHeader = req.headers['x-genspay-signature'];
    if (!apiKey || !signatureHeader) { logWebhook('genspay', { result: 'no_apikey_or_signature' }); return res.status(401).send('Unauthorized'); }

    // FIX: pakai req.rawBody (string mentah, lihat opsi `verify` di
    // express.json() setup di atas) -- BUKAN JSON.stringify(req.body) ulang.
    // req.body adalah hasil PARSE dari raw body; re-serialize objek yang
    // sudah di-parse tidak dijamin menghasilkan string yang identik persis
    // dengan raw body asli (urutan key bisa berubah), jadi hash yang dihitung
    // dari situ TIDAK PERNAH match signature asli dari GensPay. Ini salah
    // satu penyebab webhook GensPay selalu ditolak sebagai "invalid signature"
    // walau body-nya sebenarnya sah.
    if (!req.rawBody) { logWebhook('genspay', { result: 'no_raw_body' }); return res.status(401).send('Unauthorized: Raw body tidak tersedia'); }
    const computedSignature = crypto.createHash('sha256')
      .update(req.rawBody + apiKey)
      .digest('hex');

    // Perbandingan tahan timing-attack
    const sigA = Buffer.from(String(signatureHeader));
    const sigB = Buffer.from(computedSignature);
    if (sigA.length !== sigB.length || !crypto.timingSafeEqual(sigA, sigB)) {
      logWebhook('genspay', { result: 'invalid_signature', orderId: req.body?.data?.order_id || null });
      return res.status(401).send('Unauthorized: Invalid Signature');
    }

    // FIX BUG BESAR: sebelumnya event dicek === 'payment.success', TAPI
    // dokumentasi resmi GensPay (genspay.my.id/docs bagian "7. WEBHOOK
    // NOTIFIKASI") jelas menyatakan event-nya adalah "transaction.updated" --
    // "payment.success" TIDAK PERNAH dikirim GensPay sama sekali. Akibatnya
    // SEMUA webhook yang masuk selama ini langsung di-skip di baris ini,
    // walau signature-nya valid dan pembayaran beneran sukses. Ini akar
    // utama laporan "auto-send masih gagal" / "masih bug" berulang kali.
    const { event, data } = req.body || {};
    if (event !== 'transaction.updated' || !data?.order_id) { logWebhook('genspay', { result: 'event_not_matched', event, orderId: data?.order_id || null }); return res.status(200).send('OK'); }

    const order_id = data.order_id;
    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.orderId === order_id);
    if (!transaction) { logWebhook('genspay', { result: 'transaction_not_found', orderId: order_id }); return res.status(200).send('OK'); }

    if (transaction.status === 'done') { logWebhook('genspay', { result: 'already_done', orderId: order_id }); return res.status(200).send('OK'); }
    if (transaction.isStatic) { logWebhook('genspay', { result: 'is_static', orderId: order_id }); return res.status(200).send('OK'); }

    // FIX: dokumentasi resmi GensPay TIDAK menyediakan endpoint GET cek
    // status manual (lihat catatan panjang di checkPaymentStatusGenspay di
    // atas) -- fungsi itu sekarang SELALU reject kalau dipanggil. Signature
    // body webhook ini SUDAH diverifikasi di atas, jadi data.status di body
    // ini sudah bisa dipercaya sebagai sumber kebenaran satu-satunya,
    // sesuai instruksi resmi: status "SUCCESS" (huruf besar) = lunas.
    const status = (data.status || '').toUpperCase();
    const paid = status === 'SUCCESS';
    if (!paid && (status === 'EXPIRED' || status === 'FAILED')) {
      transaction.status = 'expired';
      await writeDB('transactions.json', transactions);
    }

    if (paid) {
      await finalizeConfirmedPayment(transaction.id);
      logWebhook('genspay', { result: 'finalized', orderId: order_id });
    } else {
      logWebhook('genspay', { result: 'not_paid', orderId: order_id, statusFromWebhook: status || '(kosong)' });
    }
    res.status(200).send('OK');
  } catch (error) {
    console.error('[webhook-genspay] error:', error.message);
    res.status(200).send('OK'); // tetap 200 biar GensPay tidak retry terus akibat error internal kita
  }
});

app.get('/check-payment/:refId', requireAuth, async (req, res) => {
  const refId = req.params.refId;
  // Kebijakan wajib GensPay (15 Agu 2026): maks 30 request/3 menit per
  // pengguna untuk cek status transaksi -- endpoint ini sebelumnya tidak
  // dibatasi sama sekali, salah satu penyebab IP server bisa kena flag
  // "high-frequency request" dan diblokir GensPay. Kalau limit kena, jangan
  // gagalkan keras -- balas "pending" apa adanya supaya polling di browser
  // pembeli otomatis melambat sendiri, tanpa error yang membingungkan.
  if (!checkPaymentRateLimit(req.session.userId)) {
    return res.json({ success: true, status: 'pending' });
  }
  // Cegah race condition: jika transaksi sedang diproses, kembalikan pending
  if (processingOrders.has(refId)) {
    return res.json({ success: true, status: 'pending' });
  }
  processingOrders.add(refId);
  try {
    // PENTING: pakai readFresh (bukan readDB) di sini. readDB cuma baca cache
    // in-memory instance lambda ini sendiri — di Vercel, tiap instance punya
    // cache terpisah. Kalau order dibuat di instance A lalu dicek dari instance
    // B, instance B bisa saja belum tahu transaksi itu ada / masih lihat stok
    // key yang belum berkurang, akibatnya key tidak pernah dikirim ke user
    // meskipun pembayaran sudah sukses. readFresh selalu ambil data terbaru
    // langsung dari Supabase supaya konsisten di semua instance.
    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.id === refId);
    if (!transaction) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });

    // SECURITY: cegah IDOR — pastikan transaksi ini benar milik user yang login
    // (tanpa ini, siapa saja yang login bisa lihat key/saldo orang lain kalau
    // tahu/tebak refId-nya)
    if (transaction.userId !== req.session.userId && !req.session.isAdmin) {
      return res.status(403).json({ success: false, message: 'Tidak diizinkan mengakses transaksi ini' });
    }

    if (transaction.status === 'done') {
      if (transaction.type === 'reseller') return res.json({ success: true, status: 'done', type: 'reseller' });
      if (transaction.type === 'deposit') {
        const u = (await readFresh('users.json')).find(u => u.id === transaction.userId);
        return res.json({ success: true, status: 'done', type: 'deposit', balance: u?.balance || 0 });
      }
      return res.json({ success: true, status: 'done', key: transaction.key, code: transaction.code });
    }

    // Static QRIS: tunggu konfirmasi manual admin
    if (transaction.isStatic) return res.json({ success: true, status: 'pending_static' });

    const settings = await readFresh('settings.json');
    // PENTING: selalu verifikasi ke gateway yang SAMA dengan yang dipakai
    // saat transaksi ini dibuat (transaction.paymentGateway), BUKAN
    // settings.qrisMode yang sedang aktif sekarang — supaya transaksi lama
    // tetap benar dicek walau admin sudah ganti metode pembayaran di panel.
    // Fallback ke settings.qrisMode untuk transaksi lama sebelum field ini
    // ada (paymentGateway masih undefined).
    const gateway = transaction.paymentGateway || settings.qrisMode || 'genspay';

    // GensPay TIDAK punya endpoint cek status manual (lihat catatan panjang
    // di checkPaymentStatusGenspay) -- satu-satunya sumber kebenaran soal
    // status transaksi GensPay adalah webhook (app.post('/webhook/genspay')).
    // Jangan panggil checkPaymentStatus untuk gateway ini sama sekali,
    // supaya tidak spam error 401 ke log tiap kali browser polling. Balas
    // "pending" apa adanya -- kalau webhook sudah masuk & finalize,
    // transaction.status di database sudah 'done' duluan dan ke-tangkep
    // oleh pengecekan status di atas sebelum sampai sini.
    if (gateway === 'genspay') {
      return res.json({ success: true, status: 'pending' });
    }

    let paid = false;
    try {
      const r = await checkPaymentStatus(transaction.orderId, transaction.price, settings, gateway);
      // Normalize status dari berbagai kemungkinan bentuk response Pakasir
      const status = (r.transaction?.status || r.data?.status || r.status || '').toLowerCase();
      paid = ['completed','success','paid','settlement','capture','complete','authorize','accepted'].includes(status);
      if (!paid && !['expired','canceled','cancelled','pending',''].includes(status)) {
        // Status nggak match daftar di atas tapi juga bukan pending/expired — log biar kelihatan di server log kalau gateway balikin status baru yang belum kita tangani
        console.warn(`[check-payment] Status tidak dikenali untuk order ${transaction.orderId} (gateway=${gateway}): "${status}" | raw response:`, JSON.stringify(r).slice(0, 300));
      }
      if (['expired','canceled','cancelled'].includes(status)) {
        transaction.status = 'expired';
        await writeDB('transactions.json', transactions);
        return res.json({ success: true, status: 'expired' });
      }
    } catch(e) {
      // Sebelumnya error di sini ditelan total tanpa jejak (komentar doang).
      // Sekarang dicatat ke log server supaya kalau status macet pending
      // terus, gampang ketahuan apakah penyebabnya error koneksi/API,
      // bukan cuma nebak-nebak.
      console.error(`[check-payment] Gagal cek status order ${transaction.orderId}:`, e.message);
    }

    if (paid) {
      const result = await finalizeConfirmedPayment(refId);
      return res.json(result);
    }

    res.json({ success: true, status: transaction.status });
  } catch (error) {
    console.error('[check-payment] error:', error.message);
    res.json({ success: false, message: error.message });
  } finally {
    processingOrders.delete(refId);
  }
});

app.get('/invoice', async (req, res) => {
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/invoice', { transaction: null, error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  const { code } = req.query;
  if (code) {
    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.code === code.toUpperCase());
    return res.render('pages/invoice', { transaction: transaction || null, error: transaction ? null : 'Pesanan tidak ditemukan' });
  }
  res.render('pages/invoice', { transaction: null, error: null });
});

app.post('/invoice', async (req, res) => {
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/invoice', { transaction: null, error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  const { code } = req.body;
  const transactions = await readFresh('transactions.json');
  const transaction = transactions.find(t => t.code === code.toUpperCase());

  if (!transaction) {
    return res.render('pages/invoice', { transaction: null, error: 'Pesanan tidak ditemukan' });
  }

  res.render('pages/invoice', { transaction, error: null });
});

// Admin routes
// Heartbeat dari tab admin yang masih terbuka — requireAdmin di atasnya
// sudah otomatis menolak (sessionRevoked) kalau lock sudah diambil device
// lain, dan otomatis memperpanjang lastSeen kalau masih sah.
app.post('/admin/session/heartbeat', requireAdmin, (req, res) => {
  res.json({ success: true });
});

// Status koneksi Supabase, dipakai widget "Status Database" di Settings.
// BUG SEBELUMNYA: frontend sudah fetch('/admin/db-status') tapi route ini
// belum pernah didaftarkan → selalu 404 → ketangkep catch(e){} kosong di
// frontend → teks "Memeriksa koneksi..." nyangkut selamanya, padahal
// koneksi Supabase-nya sendiri sebenarnya baik-baik saja.
app.get('/admin/db-status', requireAdmin, async (req, res) => {
  try {
    const status = await db.getDbStatus();
    res.json(status);
  } catch (e) {
    res.json({ connected: false, errorMsg: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// DEBUG ENDPOINT KOMPREHENSIF — cek SEMUA komponen yang bisa jadi
// penyebab "pembayaran sudah lunas tapi macet pending selamanya" dalam
// SATU response, supaya tidak perlu bolak-balik test satu-satu:
//   1. Koneksi Supabase (client, URL, key)
//   2. Tabel keyvalue_store (tempat semua data app disimpan)
//   3. Tabel order_locks + apakah insert/delete berhasil (mutex lock)
//   4. Ringkasan transaksi pending terbaru (biar kelihatan langsung
//      mana yang nyangkut, tanpa perlu buka Supabase manual)
//   5. (opsional) test langsung ke GensPay kalau ?orderId= disertakan
//
// Akses: /debug/payment-health?secret=SETUP_SECRET
// Opsional tambahan: &orderId=VR-xxx (atau refId/code) untuk sekalian
// cek status pembayaran order tertentu ke GensPay.
// ══════════════════════════════════════════════════════════════════
app.get('/debug/payment-health', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!secret || req.query.secret !== secret) {
    return res.status(403).json({ success: false, message: 'Akses ditolak. Set SETUP_SECRET di env Vercel dan pakai ?secret=...' });
  }

  const report = { checkedAt: new Date().toISOString() };

  // ── 1 & 2: Koneksi Supabase + tabel keyvalue_store ──
  try {
    report.supabaseConnection = await db.getDbStatus();
  } catch (e) {
    report.supabaseConnection = { error: e.message };
  }

  // ── 3: Tabel order_locks (mutex) ──
  const testLockId = 'debugtest_' + Date.now();
  try {
    const lockResult = await db.acquireLockDebug(testLockId);
    if (lockResult.ok) await db.releaseLock(testLockId);
    report.orderLocksTable = {
      accessible: lockResult.ok === true,
      reason: lockResult.reason || null,
      errorDetail: lockResult.detail || null,
      impact: lockResult.ok
        ? 'OK — finalizeConfirmedPayment() bisa ambil lock dengan normal, auto-approve tidak akan macet karena ini.'
        : 'BERMASALAH — finalizeConfirmedPayment() SELALU gagal ambil lock, sehingga SELALU balas status pending walau pembayaran sudah terverifikasi lunas di gateway. Ini kandidat #1 penyebab bug "sudah bayar tapi stuck pending".'
    };
  } catch (e) {
    report.orderLocksTable = { accessible: false, error: e.message };
  }

  // ── 4: Ringkasan transaksi pending ──
  try {
    const settings = await readFresh('settings.json');
    const transactions = await readFresh('transactions.json');
    const pendingTx = transactions
      .filter(t => t.status === 'pending' && !t.isStatic)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 10)
      .map(t => ({
        orderId: t.orderId, id: t.id, code: t.code,
        type: t.type, price: t.price, paymentGateway: t.paymentGateway || '(kosong — pakai settings.qrisMode saat ini sebagai fallback)',
        createdAt: t.createdAt,
        ageMinutes: Math.round((Date.now() - new Date(t.createdAt).getTime()) / 60000)
      }));
    report.activeQrisMode = settings.qrisMode || 'static';
    report.pendingNonStaticTransactions = {
      count: pendingTx.length,
      note: 'Transaksi non-statis (Pakasir/GensPay) yang masih pending, terbaru 10. Kalau ada yang umurnya sudah lama (ageMinutes besar) padahal user sudah bayar, itu kandidat transaksi yang stuck.',
      transactions: pendingTx
    };
  } catch (e) {
    report.pendingNonStaticTransactions = { error: e.message };
  }

  // ── 5: Opsional — test status GensPay untuk order tertentu ──
  if (req.query.orderId) {
    try {
      const settings = await readFresh('settings.json');
      const transactions = await readFresh('transactions.json');
      const tx = transactions.find(t => t.orderId === req.query.orderId)
        || transactions.find(t => t.id === req.query.orderId)
        || transactions.find(t => t.code === req.query.orderId);
      const gateway = tx?.paymentGateway || settings.qrisMode || 'genspay';
      const orderIdToQuery = tx ? tx.orderId : req.query.orderId;
      const amount = tx ? tx.price : parseInt(req.query.amount || '0');
      const r = await checkPaymentStatus(orderIdToQuery, amount, settings, gateway);
      const parsedStatus = (r.transaction?.status || r.data?.status || r.status || '').toLowerCase();
      const wouldBeMarkedPaid = ['completed','success','paid','settlement','capture','complete','authorize','accepted'].includes(parsedStatus);
      report.orderSpecificCheck = {
        foundLocalTransaction: !!tx,
        localStatus: tx?.status,
        localPaymentGateway: tx?.paymentGateway,
        queriedGateway: gateway,
        queriedOrderId: orderIdToQuery,
        rawResponse: r,
        parsedStatus,
        wouldBeMarkedPaid,
        conclusion: !tx
          ? 'Order tidak ketemu di data lokal — cek lagi orderId/refId/code yang dipakai.'
          : (tx.status === 'done'
              ? 'Transaksi ini statusnya SUDAH done di data lokal.'
              : (wouldBeMarkedPaid
                  ? 'Gateway bilang SUDAH LUNAS tapi data lokal masih pending — berarti checkPaymentStatus/parsing OK, kemungkinan macet di acquireLock (lihat orderLocksTable di atas) atau proses finalize error lain.'
                  : `Gateway masih bilang belum lunas (status: "${parsedStatus}"). Kalau menurutmu sudah bayar, coba cek lagi di dashboard GensPay apakah transaksi order_id ${orderIdToQuery} benar sudah completed.`))
      };
    } catch (e) {
      report.orderSpecificCheck = { error: e.message };
    }
  } else {
    report.orderSpecificCheck = 'Tidak dicek — tambahkan parameter &orderId=VR-xxx (atau refId/code) ke URL untuk cek order tertentu.';
  }

  // ── Kesimpulan otomatis ──
  const problems = [];
  if (report.supabaseConnection?.errorMsg) problems.push(`Koneksi Supabase: ${report.supabaseConnection.errorMsg}`);
  if (report.orderLocksTable?.accessible === false) problems.push('Tabel order_locks tidak bisa diakses (lihat orderLocksTable.errorDetail)');
  report.summary = problems.length
    ? { status: 'ADA MASALAH', problems }
    : { status: 'Semua komponen inti OK', note: 'Kalau masih ada transaksi stuck, cek orderSpecificCheck dengan &orderId= untuk order itu spesifik.' };

  res.json(report);
});

// ══════════════════════════════════════════════════════════════════
// DEBUG ENDPOINT — Cek apakah tabel order_locks ada & bisa diakses.
// Kalau tabel ini BELUM DIBUAT di Supabase, acquireLock() akan SELALU
// gagal (insert error → catch → return false), yang artinya
// finalizeConfirmedPayment() SELALU balas {status:'pending'} walaupun
// pembayaran sudah lunas — persis gejala "sudah bayar tapi macet
// pending selamanya, key tidak pernah otomatis terkirim".
// Akses: /debug/order-locks?secret=SETUP_SECRET
// ══════════════════════════════════════════════════════════════════
app.get('/debug/order-locks', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!secret || req.query.secret !== secret) {
    return res.status(403).json({ success: false, message: 'Akses ditolak. Set SETUP_SECRET di env Vercel dan pakai ?secret=...' });
  }
  const testLockId = 'debugtest_' + Date.now();
  try {
    const result = await db.acquireLockDebug(testLockId);
    if (result.ok) await db.releaseLock(testLockId);
    res.json({
      success: true,
      tableAccessible: result.ok === true,
      reason: result.reason || null,
      errorDetail: result.detail || null,
      message: result.ok
        ? 'Tabel order_locks OK — bisa insert & delete normal. Auto-approve pembayaran seharusnya jalan tanpa hambatan.'
        : 'GAGAL acquire lock! Lihat errorDetail di atas untuk pesan error ASLI dari Supabase (permission denied / tabel tidak ada / client gagal connect / dll).'
    });
  } catch (e) {
    res.json({ success: false, tableAccessible: false, message: 'Error saat test lock: ' + e.message });
  }
});

app.get('/admin', requireAdmin, async (req, res) => {
  try {
    // ── FIX: readFresh() bypass cache per-instance Vercel ──
    // Sebelumnya pakai readDB (cache lokal tiap instance), jadi setelah
    // tambah/edit produk di satu instance, refresh halaman bisa nyasar ke
    // instance lain yang cache-nya masih lama → produk kelihatan hilang/berubah.
    let [products, transactions, users, settings] = await Promise.all([
      readFresh('products.json'),
      readFresh('transactions.json'),
      readFresh('users.json'),
      readFresh('settings.json')
    ]);
    // Guard: kalau salah satu file ternyata bukan array/object (data korup /
    // belum ke-seed), jangan langsung crash — pakai default kosong.
    if (!Array.isArray(products)) products = [];
    if (!Array.isArray(transactions)) transactions = [];
    if (!Array.isArray(users)) users = [];
    if (!settings || typeof settings !== 'object') settings = {};

    if (normalizeBanners(settings)) await writeDB('settings.json', settings);

    const stats = {
      totalProducts: products.length,
      activeProducts: products.filter(p => p.status === 'active').length,
      totalTransactions: transactions.length,
      pendingTransactions: transactions.filter(t => t.status === 'pending').length,
      doneTransactions: transactions.filter(t => t.status === 'done').length,
      totalUsers: users.length,
      totalResellers: users.filter(u => u.is_reseller).length,
      totalRevenue: transactions.filter(t => t.status === 'done').reduce((sum, t) => sum + (t.price || 0), 0)
    };

    // FIX "ANTI-LAG": sebelumnya SEMUA produk dikirim & dirender EJS sekaligus
    // ke HTML (plus dobel lagi di window.__gnProducts sebagai JSON inline) --
    // begitu jumlah produk tembus ratusan/ribuan, ukuran HTML + waktu render
    // EJS + waktu parsing DOM di browser naik linear dan bikin panel admin
    // kerasa berat/delay, khususnya di HP. Sekarang initial render cuma
    // ambil PAGE_SIZE produk pertama; sisanya dimuat on-demand lewat
    // infinite-scroll (GET /admin/products?offset=&limit=&search=, lihat
    // renderProductCard()/loadMoreProducts() di admin.ejs). Total asli tetap
    // dikirim terpisah (productsTotalCount) supaya label counter akurat.
    const PRODUCTS_PAGE_SIZE = 30;
    const productsTotalCount = products.length;
    const productsPage = products.slice(0, PRODUCTS_PAGE_SIZE);
    const productsHasMore = products.length > PRODUCTS_PAGE_SIZE;

    // Data chart: 7 hari terakhir
    const chartData = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().slice(0, 10);
      const dayTrx = transactions.filter(t => t.status === 'done' && typeof t.createdAt === 'string' && t.createdAt.slice(0, 10) === dateStr);
      chartData.push({
        date: d.toLocaleDateString('id-ID', { weekday: 'short', day: 'numeric', month: 'short' }),
        count: dayTrx.length,
        revenue: dayTrx.reduce((s, t) => s + (t.price || 0), 0)
      });
    }

    res.render('pages/admin', {
      layout: false,
      products,
      productsPage,
      productsTotalCount,
      productsHasMore,
      transactions: transactions.slice(-20).reverse(),
      users,
      settings,
      stats,
      chartData,
      gachaPrizes: (settings.gacha && Array.isArray(settings.gacha.prizes) && settings.gacha.prizes.length) ? settings.gacha.prizes : GACHA_PRIZES
    });
  } catch (e) {
    console.error('[GET /admin] error:', e.stack || e);
    res.status(500).send('Gagal memuat panel admin: ' + e.message);
  }
});

// Helper: parse pricingOptions
// `unit` ('hari'/'jam'/'menit') CUMA metadata tampilan — angka `days` yang
// diinput admin TETAP disimpan apa adanya (integer, tidak dikonversi ke
// pecahan). Ini sengaja supaya seluruh logic existing yang bergantung pada
// `days` sebagai integer (key tag "KEY:N", matching item saat checkout,
// resolveStockSourceForDays, dst — lihat komentar-komentar terkait di
// server.js) tidak perlu disentuh sama sekali. Kalau admin bikin paket
// "1 Jam", value days=1 tersimpan sama seperti sebelumnya, unit='jam' cuma
// dipakai buat render label "1 Jam" balik di UI admin & (opsional) invoice.
function parsePricingOptions(days, prices, resellerPrices, units) {
  const da = Array.isArray(days) ? days : (days ? [days] : []);
  const pa = Array.isArray(prices) ? prices : (prices ? [prices] : []);
  const rpa = Array.isArray(resellerPrices) ? resellerPrices : (resellerPrices ? [resellerPrices] : []);
  const ua = Array.isArray(units) ? units : (units ? [units] : []);
  const opts = []; const seen = new Set();
  for (let i = 0; i < da.length; i++) {
    const d = parseInt(da[i]), p = parseInt(pa[i]);
    const unit = ['hari','jam','menit'].includes(ua[i]) ? ua[i] : 'hari';
    // FIX BUG "1 Jam ketuker/dobel jadi 1 DAYS": dedup sebelumnya cuma
    // ngecek angka `d` doang (mis. days=1), jadi paket "1 Jam" dan "1 Hari"
    // dianggap SAMA dan salah satunya diam-diam kebuang di sini walau
    // adminnya niat bikin dua varian beda. Sekarang key dedup ikutkan unit
    // juga, supaya "1 jam" dan "1 hari" dianggap dua opsi yang beda.
    const dedupKey = `${d}:${unit}`;
    if (d > 0 && p >= 0 && !seen.has(dedupKey)) {
      seen.add(dedupKey);
      const rp = rpa[i] !== undefined && rpa[i] !== '' ? parseInt(rpa[i]) : null;
      opts.push({ days: d, price: p, reseller_price: (rp !== null && !isNaN(rp) && rp >= 0) ? rp : null, unit });
    }
  }
  // Urut berdasarkan lama waktu SEBENARNYA (konversi ke menit), bukan angka
  // mentah -- supaya "1 Hari" (1440 menit) muncul setelah "12 Jam" (720
  // menit), bukan sebelum "3 Jam" cuma karena 1 < 3.
  const toMinutes = (o) => o.unit === 'jam' ? o.days * 60 : o.unit === 'menit' ? o.days : o.days * 1440;
  return opts.sort((a, b) => toMinutes(a) - toMinutes(b));
}

// Label satuan durasi untuk unit tertentu, dipakai bikin teks "N Jam" dsb
// di tempat yang perlu tampilkan durasi asli ke user (mis. invoice/produk).
const UNIT_LABEL = { hari: 'Hari', jam: 'Jam', menit: 'Menit' };

// FIX BUG "Ghost NewEra: 1 Jam ketuker/dobel jadi 1 DAYS": sebelumnya SEMUA
// label item selalu di-hardcode suffix " DAYS" apapun unit aslinya (lihat
// laporan "Analisa_Bug_Varian_Waktu_GHOST_NEWERA.md") -- jadi paket "1 Jam"
// dan "1 Hari" yang harusnya beda malah tampil sebagai dua tombol
// "BALA MODS 1 DAYS" yang identik di frontend. Fungsi ini jadi SATU-SATUNYA
// tempat label item digenerate, supaya konsisten di semua endpoint.
// Format baru: "<NAMA> <N> <UNIT>" mis. "BALA MODS 1 JAM" / "BALA MODS 1 HARI"
// -- suffix unit dalam Bahasa Indonesia (bukan "DAYS") sesuai rekomendasi di
// laporan bug. Suffix "HARI" (bukan "DAYS") untuk unit hari supaya konsisten
// dgn Jam/Menit; regex parsing di bawah tetap terima "DAYS" untuk kompatibel
// dgn data produk lama yang labelnya belum di-generate ulang.
function buildItemLabel(productName, days, unit) {
  const u = ['hari','jam','menit'].includes(unit) ? unit : 'hari';
  return `${(productName||'PRODUK').toUpperCase()} ${days} ${UNIT_LABEL[u].toUpperCase()}`;
}

// Ambil { days, unit } dari label item lama/baru. Terima suffix "DAYS"
// (data lama, sebelum fix ini) maupun "HARI"/"JAM"/"MENIT" (format baru).
// unit default 'hari' kalau match "DAYS"/"HARI" atau tidak match sama sekali
// (fallback aman untuk label custom yang tidak mengikuti pola).
function parseItemLabel(label) {
  const m = (label || '').match(/(\d+)\s+(DAYS|HARI|JAM|MENIT)\b/i);
  if (!m) return { days: null, unit: 'hari' };
  const unitRaw = m[2].toUpperCase();
  const unit = unitRaw === 'JAM' ? 'jam' : unitRaw === 'MENIT' ? 'menit' : 'hari';
  return { days: parseInt(m[1]), unit };
}

// Helper: validasi URL gambar (cegah XSS via javascript:/data: protocol)
const isValidImageUrl = (url) => {
  if (!url) return true;
  const lower = url.toLowerCase().trim();
  return !lower.startsWith('javascript:') && !lower.startsWith('data:') && !lower.startsWith('vbscript:');
};

app.post('/admin/product/add', requireAdmin, (req, res, next) => {
  upload.single('image')(req, res, err => {
    if (err) return res.json({ success: false, message: 'Upload error: ' + err.message });
    next();
  });
}, async (req, res) => {
  try {
    const {name,category,description,imageUrl:imgUrl,pricingDays,pricingPrices,pricingResellerPrices,pricingUnits,keys,status,operationalStatus,stockMode}=req.body;
    if(!name)return res.json({success:false,message:'Nama produk wajib diisi'});
    if(imgUrl && !isValidImageUrl(imgUrl)) return res.json({success:false,message:'URL gambar tidak valid'});
    const products=await readFresh('products.json');
    const pricingOptions=parsePricingOptions(pricingDays,pricingPrices,pricingResellerPrices,pricingUnits);
    if(!pricingOptions.length)return res.json({success:false,message:'Tambahkan minimal 1 opsi harga'});
    const keyArray=keys?keys.split('\n').map(k=>k.trim()).filter(k=>k):[];
    // Default Mode Stok untuk produk BARU = 'manual'. Dulu default-nya
    // 'auto' (vipibmstore, auto-match by nama produk+hari) -- itu sumber
    // bug nyata: produk baru dibuat, admin lupa/gak sadar defaultnya auto,
    // vipibmstore gak pernah dikonfigurasi sama sekali, customer bayar
    // tapi generate key gagal total ("API Key/Secret belum diatur").
    // vipibmstore sendiri sudah dicabut total dari sistem ini -- lihat
    // resolveProductKey(). Kalau butuh auto-restock sekarang pakai
    // GhostSeller (set manual dulu di sini, baru pilih GhostSeller per
    // varian di halaman Edit Produk).
    const resolvedStockMode = stockMode === 'ghostseller' ? 'ghostseller' : 'manual';
    let image = imgUrl?.trim() || '';
    if (req.file) {
      if (!isVercel) {
        image = `/uploads/products/${req.file.filename}`;
      } else {
        try {
          image = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype);
        } catch { image = imgUrl?.trim() || '/images/placeholder.jpg'; }
      }
    }
    if (!image) image = '/images/placeholder.jpg';
    const items=pricingOptions.map(o=>({l:buildItemLabel(name,o.days,o.unit),p:o.price,reseller_price:o.reseller_price}));
    // Status operasional produk (online/offline/unknown) — badge titik warna
    // yang ditampilkan di card produk, terpisah dari `status` (active/inactive
    // yang mengatur produk itu terlihat/dijual atau tidak sama sekali).
    const validOpStatuses = ['online', 'offline', 'unknown'];
    const opStatus = validOpStatuses.includes(operationalStatus) ? operationalStatus : 'online';
    const newProduct={id:uuidv4(),name,category:category||'freefire',description:description||'',image,pricingOptions,items,status:status==='inactive'?'inactive':'active',operationalStatus:opStatus,keys:keyArray,sold:0,createdAt:new Date().toISOString(),stockMode:resolvedStockMode};
    products.push(newProduct);await writeDB('products.json',products);
    res.json({success:true,product:newProduct});
  }catch(error){res.json({success:false,message:error.message});}
});

app.post('/admin/product/edit/:id', requireAdmin, (req, res, next) => {
  upload.single('image')(req, res, err => {
    if (err) return res.json({ success: false, message: 'Upload error: ' + err.message });
    next();
  });
}, async (req, res) => {
  try {
    const {name,category,description,imageUrl:imgUrl,pricingDays,pricingPrices,pricingResellerPrices,pricingUnits,keys,keysMode,status,operationalStatus}=req.body;
    const products=await readFresh('products.json');
    const product=products.find(p=>p.id===req.params.id);
    if(!product)return res.json({success:false,message:'Produk tidak ditemukan'});
    if(imgUrl && !isValidImageUrl(imgUrl)) return res.json({success:false,message:'URL gambar tidak valid'});
    if(name)product.name=name;if(category)product.category=category;
    if(description!==undefined)product.description=description;if(status)product.status=status;
    if(operationalStatus && ['online','offline','unknown'].includes(operationalStatus)) product.operationalStatus=operationalStatus;
    // FIX BUG "harga gak kehitung setelah edit": sebelumnya kalau parsePricingOptions
    // menghasilkan array KOSONG (misal karena salah satu field harga terkirim
    // string kosong dan parseInt-nya jadi NaN), kode ini diam-diam TIDAK
    // mengupdate product.pricingOptions/items SAMA SEKALI, tapi tetap
    // membalas {success:true} — jadi dari sisi admin kelihatan "berhasil
    // disimpan" padahal harga sebenarnya tidak berubah apa-apa.
    // Sekarang: kalau pricingDays dikirim tapi hasil parse-nya kosong,
    // balas error yang jelas supaya admin tahu ada input yang tidak valid.
    if(pricingDays){
      const opts=parsePricingOptions(pricingDays,pricingPrices,pricingResellerPrices,pricingUnits);
      if(opts.length){
        product.pricingOptions=opts;
        product.items=opts.map(o=>({l:buildItemLabel(product.name,o.days,o.unit),p:o.price,reseller_price:o.reseller_price}));
      } else {
        return res.json({success:false,message:'Gagal simpan harga: pastikan Durasi dan Harga Normal diisi angka valid (≥0) di setiap baris pricing.'});
      }
    }
    // FIX BUG "key jadi double": dedup exact-match saat append, konsisten
    // dengan /admin/product/keys/:id — cegah submit ganda dari modal Edit
    // Produk ini menggandakan key yang sudah ada.
    if(keys!==undefined&&keys!==null){
      const nk=keys.split('\n').map(k=>k.trim()).filter(k=>k);
      if(keysMode==='append'){
        const existing=new Set(product.keys||[]);
        const toAdd=nk.filter(k=>!existing.has(k));
        product.keys=[...(product.keys||[]),...toAdd];
      } else {
        product.keys=nk;
      }
    }
    if (req.file) {
      if (!isVercel) product.image=`/uploads/products/${req.file.filename}`;
      else { try { product.image = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch {} }
    }
    else if(imgUrl?.trim()) product.image=imgUrl.trim();
    await writeDB('products.json',products);res.json({success:true,product});
  }catch(error){res.json({success:false,message:error.message});}
});

app.post('/admin/product/keys/:id', requireAdmin, async (req, res) => {
  try {
    const{keys,mode,duration}=req.body;const products=await readFresh('products.json');
    const product=products.find(p=>p.id===req.params.id);
    if(!product)return res.json({success:false,message:'Produk tidak ditemukan'});
    // Kalau admin pilih durasi di modal (bukan generic), tag otomatis tiap
    // baris yang belum punya ":N" sendiri — supaya admin tidak perlu ketik
    // format KEY:HARI manual (sumber bug "beli 1 hari dikirim 10 hari" kalau
    // salah ketik/lupa tag). Baris yang sudah ditag manual tidak disentuh.
    const d = duration ? parseInt(duration) : null;
    const nk=(keys||'').split('\n').map(k=>k.trim()).filter(k=>k)
      .map(k => (d && !k.includes(':')) ? `${k}:${d}` : k);
    // FIX BUG "key jadi double pas restock, key yang udah ada jadi double":
    // tombol Simpan di modal Kelola Keys sebelumnya tidak didisable saat
    // proses submit, jadi klik ganda (koneksi lemot / tidak ada indikasi
    // loading) bisa mengirim 2 request nyaris bersamaan. Kalau request kedua
    // sempat baca state SETELAH request pertama selesai menyimpan, key yang
    // sama ke-append dua kali. Sekarang dedup exact-match di sini sebagai
    // lapis pertahanan backend (independen dari fix tombol di admin.ejs) —
    // key yang PERSIS SAMA dengan yang sudah ada di stok tidak ditambah lagi.
    if (mode === 'replace') {
      product.keys = nk;
    } else {
      const existing = new Set(product.keys || []);
      const toAdd = nk.filter(k => !existing.has(k));
      product.keys = [...(product.keys || []), ...toAdd];
    }
    await writeDB('products.json',products);res.json({success:true,keyCount:product.keys.length});
  }catch(e){res.json({success:false,message:e.message});}
});

app.post('/admin/product/delete/:id', requireAdmin, async (req, res) => {
  try {
    let products = await readFresh('products.json');
    products = products.filter(p => p.id !== req.params.id);
    await writeDB('products.json', products);
    res.json({ success: true, message: 'Produk berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/user/delete/:id', requireAdmin, async (req, res) => {
  try {
    let users = await readFresh('users.json');
    users = users.filter(u => u.id !== req.params.id);
    await writeDB('users.json', users);
    res.json({ success: true, message: 'User berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/transaction/delete/:id', requireAdmin, async (req, res) => {
  try {
    let transactions = await readFresh('transactions.json');
    transactions = transactions.filter(t => t.id !== req.params.id);
    await writeDB('transactions.json', transactions);
    res.json({ success: true, message: 'Transaksi berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/transaction/status/:id', requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const transactions = await readFresh('transactions.json');
    const trx = transactions.find(t => t.id === req.params.id);
    if (!trx) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    trx.status = status;
    trx.updatedBy = 'admin';
    trx.updatedAt = new Date().toISOString();
    await writeDB('transactions.json', transactions);
    res.json({ success: true, message: 'Status berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/product/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === req.params.id);

    if (!product) {
      return res.json({ success: false, message: 'Produk tidak ditemukan' });
    }

    product.status = product.status === 'active' ? 'inactive' : 'active';
    await writeDB('products.json', products);

    res.json({ success: true, message: 'Status produk berhasil diubah', status: product.status });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// Endpoint /admin/product/bulk-set-auto DIHAPUS TOTAL (bukan sekadar
// dinonaktifkan). Ini kemungkinan besar AKAR MASALAH insiden Sep 2026:
// tombolnya di admin.ejs cuma bilang "Set Semua ke Auto" tanpa peringatan
// apapun soal vipibmstore harus dikonfigurasi dulu -- sekali klik, SEMUA
// produk (termasuk yang gak ada hubungannya sama vipibmstore sama sekali)
// keubah ke stockSource/stockMode 'auto'. Karena kredensial vipibmstore
// emang gak pernah diisi, semua produk yang kena diam-diam berhenti bisa
// dibeli (customer bayar, generate key gagal). vipibmstore sendiri sudah
// dicabut total dari sistem ini, jadi endpoint ini juga gak relevan lagi.

app.post('/admin/product/add-keys/:id', requireAdmin, async (req, res) => {
  try {
    const { keys } = req.body;
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === req.params.id);

    if (!product) {
      return res.json({ success: false, message: 'Produk tidak ditemukan' });
    }

    const newKeys = keys.split('\n').map(k => k.trim()).filter(k => k);
    product.keys = product.keys || [];
    product.keys.push(...newKeys);

    await writeDB('products.json', products);
    res.json({ success: true, message: `${newKeys.length} key berhasil ditambahkan`, keyCount: product.keys.length });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/update', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { siteName, gamePanelName, about, marqueeText, whatsapp, telegram, email, downloadUrl, adminUsername, categories, categoryLabels, logoUrl, fonnteToken, singleDeviceAdminLogin, showPopularSection, homeProductsLimit } = req.body;

    if (siteName)      settings.siteName      = siteName;
    if (gamePanelName) settings.gamePanelName = gamePanelName;
    if (about !== undefined) settings.about   = about;
    if (marqueeText)   settings.marqueeText   = marqueeText;
    if (adminUsername) settings.adminUsername = adminUsername;
    if (logoUrl !== undefined) settings.logoUrl = logoUrl;
    if (fonnteToken !== undefined) settings.fonnteToken = fonnteToken;
    // Toggle login admin 1 perangkat vs banyak perangkat (default: banyak/false)
    if (singleDeviceAdminLogin !== undefined) {
      settings.singleDeviceAdminLogin = (singleDeviceAdminLogin === 'true' || singleDeviceAdminLogin === true);
    }
    // Toggle tampil/sembunyi section "Produk Populer" di halaman utama (default: tampil/true)
    if (showPopularSection !== undefined) {
      settings.showPopularSection = (showPopularSection === 'true' || showPopularSection === true);
    }
    // Batas jumlah produk di grid halaman utama / per-halaman di "/produk"
    if (homeProductsLimit !== undefined && homeProductsLimit !== '') {
      const n = parseInt(homeProductsLimit);
      if (!isNaN(n) && n >= 1) settings.homeProductsLimit = Math.min(n, 100);
    }

    settings.contact = settings.contact || {};
    if (whatsapp !== undefined) settings.contact.whatsapp = whatsapp;
    if (telegram !== undefined) settings.contact.telegram = telegram;
    if (email    !== undefined) settings.contact.email    = email;
    if (downloadUrl !== undefined) settings.contact.downloadUrl = downloadUrl.trim();

    // Handle categories update from JSON string or array
    if (categories) {
      try {
        settings.categories = JSON.parse(categories);
      } catch(e) {
        if (Array.isArray(categories)) settings.categories = categories;
      }
    }
    if (categoryLabels) {
      try {
        settings.categoryLabels = JSON.parse(categoryLabels);
      } catch(e) {
        if (typeof categoryLabels === 'object') settings.categoryLabels = categoryLabels;
      }
    }

    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Pengaturan berhasil diupdate' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// ── Pakasir Settings ──
app.post('/admin/settings/pakasir', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { apiKey, project, apiBaseUrl, qrisMode } = req.body;

    settings.pakasir = {
      apiKey: apiKey !== undefined ? apiKey : (settings.pakasir?.apiKey || ''),
      project: project !== undefined ? project : (settings.pakasir?.project || ''),
      apiBaseUrl: apiBaseUrl !== undefined ? apiBaseUrl : (settings.pakasir?.apiBaseUrl || 'app.pakasir.com')
    };

    if (qrisMode) settings.qrisMode = qrisMode;

    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// DEBUG ENDPOINT — Cek project & API key Pakasir yang lagi aktif
// Akses: /debug/pakasir?secret=SETUP_SECRET (env var yang sama dgn setup)
// ══════════════════════════════════════════════════════════════════
app.get('/debug/pakasir', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!secret || req.query.secret !== secret) {
    return res.status(403).json({ success: false, message: 'Akses ditolak. Set SETUP_SECRET di env Vercel dan pakai ?secret=...' });
  }

  try {
    const settings = await readFresh('settings.json');
    const p = settings.pakasir || {};
    const apiKey = p.apiKey || '';
    const maskedKey = apiKey ? (apiKey.slice(0, 4) + '****' + apiKey.slice(-4)) : '(kosong)';

    res.json({
      success: true,
      project: p.project || '(kosong)',
      apiKeyMasked: maskedKey,
      apiKeyLength: apiKey.length,
      apiBaseUrl: p.apiBaseUrl || 'app.pakasir.com'
    });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// ── GensPay Settings ──
// 📖 Dokumentasi Integrasi: https://genspay.my.id/docs (Swagger API)
// Base URL API: https://genspay.my.id/api/v1
// Cara pakai:
//   1. Buat project di Settings → dapat API Key
//   2. Kirim API Key di header X-API-Key
//   3. Gunakan endpoint create/status/cancel
// Ada kendala? Hubungi admin.
app.post('/admin/settings/genspay', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { apiKey, baseUrl, qrisMode } = req.body;

    settings.genspay = {
      apiKey: apiKey !== undefined ? apiKey : (settings.genspay?.apiKey || ''),
      baseUrl: baseUrl !== undefined ? baseUrl : (settings.genspay?.baseUrl || 'https://genspay.my.id/api/v1')
    };

    if (qrisMode) settings.qrisMode = qrisMode;

    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// Reseller API (vipibmstore) dicabut total: endpoint
// /admin/settings/reseller-api, /admin/reseller-api/test, dan
// /admin/reseller-api/products yang dulu ada di sini sudah dihapus --
// tidak ada lagi produk yang boleh bergantung ke vipibmstore, semua
// auto-restock sekarang lewat GhostSeller Partner API di bawah.

// ── GhostSeller Auto-Restock Settings ──
// Fitur: varian produk dengan stockSource='ghostseller' generate key
// LIVE dari akun partner di GhostSeller (ghostseller.my.id) setiap ada
// order, jadi stok manual tidak pernah habis selama saldo akun partner
// di sana masih cukup. Lihat ghostseller-api.js untuk detail integrasi.
// Cara pakai:
//   1. Di proyek GhostSeller: /dashboard/admin/settings/partner-api →
//      pilih akun reseller yang jadi "akun partner" RYAN NEW ERA, lalu
//      Generate/Regenerate API Key.
//   2. Tempel API Key itu di sini (Base URL biasanya tidak perlu diubah).
//   3. Di Edit Produk, set salah satu varian ke Stock Source
//      "GhostSeller (Auto Restock)" lalu isi Product ID + Duration ID
//      GhostSeller-nya (lihat tombol "Lihat Katalog GhostSeller").
app.post('/admin/settings/ghostseller-api', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { apiKey, baseUrl } = req.body;

    settings.ghostSellerApi = {
      apiKey: apiKey !== undefined ? apiKey : (settings.ghostSellerApi?.apiKey || ''),
      baseUrl: baseUrl !== undefined ? baseUrl : (settings.ghostSellerApi?.baseUrl || 'https://www.ghostseller.my.id/api/v1/partner')
    };

    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// Test koneksi GhostSeller Partner API — pakai nilai dari form (belum
// tentu sudah disimpan), sama pola dengan /admin/reseller-api/test.
app.post('/admin/ghostseller-api/test', requireAdmin, async (req, res) => {
  try {
    const { apiKey, baseUrl } = req.body;
    const tempSettings = { ghostSellerApi: { apiKey, baseUrl } };
    const result = await ghostSellerApi.getProducts(tempSettings);
    if (!result.success) {
      return res.json({ success: false, message: result.message, code: result.code, status: result.status, debug: result.debug });
    }
    res.json({ success: true, productCount: Array.isArray(result.data?.data) ? result.data.data.length : 0 });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// List produk dari GhostSeller Partner API — dipakai di halaman Edit
// Produk untuk bantu admin lihat Product ID/Duration ID yang valid tanpa
// perlu buka dashboard GhostSeller terpisah.
app.get('/admin/ghostseller-api/products', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const result = await ghostSellerApi.getProducts(settings);
    if (!result.success) return res.json({ success: false, message: result.message });
    res.json({ success: true, products: result.data?.data || [] });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// DEBUG ENDPOINT — Cek RAW API key GhostSeller yang lagi aktif dikirim
// Akses: /debug/ghostseller-raw?secret=SETUP_SECRET
// Dibuat khusus buat nelusurin insiden 401 terus-terusan antara Ryan <->
// GhostSeller (Sep 2026) -- nampilin FULL apiKey (bukan cuma prefix 12
// char kayak debug di respons /admin/ghostseller-api/test) biar bisa
// dibandingin karakter-per-karakter persis sama hasil dump
// /api/debug/partner-api-raw di proyek GhostSeller.
// HAPUS endpoint ini setelah insiden ini selesai ditelusuri -- dia
// membocorkan API Key mentah ke siapa pun yang tau SETUP_SECRET.
// ══════════════════════════════════════════════════════════════════
app.get('/debug/ghostseller-raw', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!secret || req.query.secret !== secret) {
    return res.status(403).json({ success: false, message: 'Akses ditolak. Set SETUP_SECRET di env Vercel dan pakai ?secret=...' });
  }
  try {
    const settings = await readFresh('settings.json');
    const cfg = ghostSellerApi.getConfig(settings);
    res.json({
      apiKeyFull: cfg.apiKey || '(kosong)',
      apiKeyLength: cfg.apiKey ? cfg.apiKey.length : 0,
      baseUrl: cfg.baseUrl,
      source: settings.ghostSellerApi?.apiKey ? 'settings.json (disimpan lewat panel admin)' : (process.env.GHOSTSELLER_API_KEY ? 'env var GHOSTSELLER_API_KEY' : '(tidak ada sama sekali)')
    });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// DEBUG ENDPOINT — Cek API key GensPay yang lagi aktif
// Akses: /debug/genspay?secret=SETUP_SECRET (env var yang sama dgn setup)
// Set SETUP_SECRET di Vercel env vars dulu. HAPUS endpoint ini / SETUP_SECRET
// setelah selesai dipakai supaya tidak jadi celah keamanan permanen.
// ══════════════════════════════════════════════════════════════════
app.get('/debug/genspay', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!secret || req.query.secret !== secret) {
    return res.status(403).json({ success: false, message: 'Akses ditolak. Set SETUP_SECRET di env Vercel dan pakai ?secret=...' });
  }

  try {
    const settings = await readFresh('settings.json');
    const p = settings.genspay || {};
    const apiKey = p.apiKey || process.env.GENSPAY_API_KEY || '';
    const maskedKey = apiKey ? (apiKey.slice(0, 4) + '****' + apiKey.slice(-4)) : '(kosong)';

    // Kalau ?orderId=VR-xxxx disertakan, coba cek status manual ke GensPay.
    // CATATAN: dokumentasi resmi GensPay (genspay.my.id/docs) TIDAK
    // menyediakan endpoint GET cek status transaksi -- checkPaymentStatusGenspay
    // di atas SELALU reject dengan pesan yang menjelaskan ini. Satu-satunya
    // sumber kebenaran status transaksi GensPay adalah webhook
    // (app.post('/webhook/genspay')) -- kalau mau tahu kenapa transaksi
    // tertentu belum auto-selesai, cek /debug/genspay?secret=...&webhookLog=1
    // (lihat parameter baru di bawah) buat lihat riwayat webhook yang masuk,
    // bukan lewat orderId di sini.
    const transactions = await readFresh('transactions.json');
    // Info diagnostik soal transactions.json ITU SENDIRI — supaya kelihatan
    // jelas apakah masalahnya "data transaksi gagal ke-load dari Supabase"
    // (transactionsLoaded akan false / totalTransactions 0 padahal harusnya
    // banyak) VERSUS "orderId yang dimasukkan salah/tidak match" (data
    // transaksi lain tetap kebaca normal, cuma orderId ini yang tidak ada).
    const diag = {
      transactionsIsArray: Array.isArray(transactions),
      totalTransactions: Array.isArray(transactions) ? transactions.length : null,
      last5OrderIds: Array.isArray(transactions) ? transactions.slice(-5).map(t => ({ orderId: t.orderId, id: t.id, status: t.status, code: t.code })) : null
    };

    let rawStatusCheck = null;
    if (req.query.orderId) {
      // Cari exact match dulu; kalau gagal, coba juga match by refId (id) atau
      // by kode order (code) — kadang yang dikasih user bukan orderId asli
      // tapi refId/kode, jadi ini bantu ketahuan salah field mana yang dipakai.
      const tx = transactions.find(t => t.orderId === req.query.orderId)
        || transactions.find(t => t.id === req.query.orderId)
        || transactions.find(t => t.code === req.query.orderId);
      try {
        const amount = tx ? tx.price : parseInt(req.query.amount || '0');
        const orderIdToQuery = tx ? tx.orderId : req.query.orderId;
        const r = await checkPaymentStatusGenspay(orderIdToQuery, amount, settings);
        rawStatusCheck = {
          queriedOrderId: orderIdToQuery,
          queriedAmount: amount,
          foundLocalTransaction: !!tx,
          matchedBy: tx ? (tx.orderId === req.query.orderId ? 'orderId' : (tx.id === req.query.orderId ? 'refId' : 'code')) : null,
          localStatus: tx?.status,
          localPaymentGateway: tx?.paymentGateway,
          rawResponse: r
        };
      } catch (e) {
        rawStatusCheck = { error: e.message };
      }
    }

    res.json({
      success: true,
      apiKeyMasked: maskedKey,
      apiKeyLength: apiKey.length,
      baseUrl: p.baseUrl || process.env.GENSPAY_BASE_URL || 'https://genspay.my.id/api/v1',
      docs: 'https://genspay.my.id/docs',
      diag,
      rawStatusCheck,
      // Riwayat 30 webhook terakhir yang masuk -- ini sumber kebenaran
      // paling langsung buat lihat kenapa transaksi belum auto-selesai
      // (kosong = webhook belum pernah masuk sama sekali; ada entry tapi
      // result bukan "finalized" = webhook masuk tapi ditolak/di-skip,
      // lihat field result-nya buat tahu kenapa).
      webhookLog: webhookLog.slice(0, 30)
    });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// Test koneksi — mendukung Pakasir DAN GensPay, tergantung parameter `gateway`
// yang dikirim frontend ('pakasir' atau 'genspay').
app.post('/admin/qris/test', requireAdmin, async (req, res) => {
  try {
    const { gateway, apiKey, project, apiBaseUrl, baseUrl } = req.body;
    let testSettings;
    if (gateway === 'pakasir') {
      testSettings = { qrisMode: 'pakasir', pakasir: { apiKey, project, apiBaseUrl: apiBaseUrl || 'app.pakasir.com' } };
    } else {
      testSettings = { qrisMode: 'genspay', genspay: { apiKey, baseUrl: baseUrl || 'https://genspay.my.id/api/v1' } };
    }
    try {
      await createQRISPayment('test-' + Date.now(), 1000, testSettings);
      res.json({ success: true });
    } catch (e) {
      res.json({ success: false, message: e.message });
    }
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/password', requireAdmin, async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      return res.json({ success: false, message: 'Password minimal 6 karakter' });
    }

    const settings = await readFresh('settings.json');
    settings.adminPassword = await bcrypt.hash(newPassword, 12);

    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Password admin berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/popular-products', requireAdmin, async (req, res) => {
  try {
    const { popularProductIds } = req.body;
    const settings = await readFresh('settings.json');
    settings.popularProductIds = Array.isArray(popularProductIds) ? popularProductIds : [];
    await writeDB('settings.json', settings);
    res.json({ success: true, popularProductIds: settings.popularProductIds });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/settings/reseller', requireAdmin, async (req, res) => {
  try {
    const { resellerEnabled, resellerPrice, resellerDiscount, resellerNote, resellerMinDeposit } = req.body;
    const settings = await readFresh('settings.json');
    settings.resellerEnabled = resellerEnabled === 'true' || resellerEnabled === true;
    if (resellerPrice !== undefined && resellerPrice !== '') {
      const price = parseInt(resellerPrice);
      if (isNaN(price) || price < 0) return res.json({ success: false, message: 'Harga reseller tidak valid' });
      settings.resellerPrice = price;
    }
    if (resellerDiscount !== undefined && resellerDiscount !== '') {
      const discount = parseInt(resellerDiscount);
      if (isNaN(discount) || discount < 0 || discount > 100) return res.json({ success: false, message: 'Diskon harus antara 0-100%' });
      settings.resellerDiscount = discount;
    }
    if (resellerMinDeposit !== undefined && resellerMinDeposit !== '') {
      const minDep = parseInt(resellerMinDeposit);
      if (isNaN(minDep) || minDep < 0) return res.json({ success: false, message: 'Minimal deposit tidak valid' });
      settings.resellerMinDeposit = minDep;
    }
    if (resellerNote !== undefined) settings.resellerNote = resellerNote;
    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/user/toggle-reseller/:id', requireAdmin, async (req, res) => {
  try {
    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    user.is_reseller = !user.is_reseller;
    user.role = user.is_reseller ? 'reseller' : 'user';
    if (user.is_reseller) {
      user.reseller_since = user.reseller_since || new Date().toISOString();
      user.reseller_code = user.reseller_code || ('RSL-' + user.username.toUpperCase().slice(0, 4) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase());
    }
    await writeDB('users.json', users);
    res.json({ success: true, is_reseller: user.is_reseller });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Admin koreksi/tambah saldo wallet user secara manual (mis. transfer di luar QRIS)
app.post('/admin/user/adjust-balance/:id', requireAdmin, async (req, res) => {
  try {
    const amount = parseInt(req.body.amount);
    if (isNaN(amount) || amount === 0) return res.json({ success: false, message: 'Nominal tidak valid' });

    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });

    const newBalance = (user.balance || 0) + amount;
    if (newBalance < 0) return res.json({ success: false, message: 'Saldo tidak boleh minus' });
    user.balance = newBalance;
    await writeDB('users.json', users);

    const transactions = await readFresh('transactions.json');
    transactions.push({
      id: uuidv4(), orderId: `ADJ-${Date.now()}`, code: generateOrderCode(),
      userId: user.id, type: 'adjustment', productName: amount > 0 ? 'Penambahan Saldo (Admin)' : 'Pengurangan Saldo (Admin)',
      amount, price: Math.abs(amount), customerName: user.username, wa: user.wa,
      status: 'done', paidAt: new Date().toISOString(),
      createdAt: new Date().toISOString(), time: formatDate(), confirmedBy: 'admin'
    });
    await writeDB('transactions.json', transactions);

    res.json({ success: true, balance: user.balance });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ── ARCADE: admin kasih koin ke user pilihan ──
app.post('/admin/arcade/give-coin/:id', requireAdmin, async (req, res) => {
  try {
    const amount = parseInt(req.body.amount);
    if (isNaN(amount) || amount === 0) return res.json({ success: false, message: 'Jumlah koin tidak valid' });

    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });

    const newCoins = (user.coins || 0) + amount;
    if (newCoins < 0) return res.json({ success: false, message: 'Koin tidak boleh minus' });
    user.coins = newCoins;
    await writeDB('users.json', users);

    const transactions = await readFresh('transactions.json');
    transactions.push({
      id: uuidv4(), type: 'coin-adjustment', userId: user.id,
      productName: amount > 0 ? 'Penambahan Koin Arcade (Admin)' : 'Pengurangan Koin Arcade (Admin)',
      amount, status: 'done', createdAt: new Date().toISOString(), time: formatDate(), confirmedBy: 'admin'
    });
    await writeDB('transactions.json', transactions);

    res.json({ success: true, coins: user.coins, username: user.username });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ── ARCADE: admin simpan konfigurasi hadiah gacha (support tambah/hapus, termasuk hadiah tipe "key") ──
app.post('/admin/arcade/save-prizes', requireAdmin, async (req, res) => {
  try {
    const { prizes } = req.body; // [{ id, label, type, value?, productId?, weight }]
    if (!Array.isArray(prizes) || !prizes.length) return res.json({ success: false, message: 'Data hadiah tidak valid' });

    const products = await readFresh('products.json');
    const cleaned = [];
    for (const p of prizes) {
      const weight = parseInt(p.weight);
      if (isNaN(weight) || weight < 0) {
        return res.json({ success: false, message: `Bobot tidak valid untuk hadiah "${p.label || p.id || ''}"` });
      }
      if (!['zonk', 'saldo', 'voucher', 'key'].includes(p.type)) {
        return res.json({ success: false, message: `Tipe hadiah tidak dikenal: ${p.type}` });
      }

      if (p.type === 'zonk') {
        cleaned.push({ id: p.id || 'zonk', label: p.label || 'Zonk, coba lagi!', type: 'zonk', weight });
        continue;
      }

      if (p.type === 'key') {
        const product = products.find(pr => pr.id === p.productId);
        if (!product) return res.json({ success: false, message: 'Pilih product untuk hadiah key terlebih dahulu' });
        cleaned.push({
          id: (p.id && String(p.id).trim()) ? p.id : uuidv4(),
          label: `Free Key: ${product.name}`,
          type: 'key',
          productId: product.id,
          weight
        });
        continue;
      }

      // saldo / voucher
      const value = parseInt(p.value);
      if (isNaN(value) || value < 0) {
        return res.json({ success: false, message: `Nilai tidak valid untuk hadiah "${p.label || p.id || ''}"` });
      }
      cleaned.push({
        id: (p.id && String(p.id).trim()) ? p.id : uuidv4(),
        label: p.type === 'saldo' ? `Saldo Rp ${value.toLocaleString('id-ID')}` : `Voucher Diskon ${value}%`,
        type: p.type,
        value,
        weight
      });
    }

    const settings = await readFresh('settings.json');
    settings.gacha = { prizes: cleaned };
    await writeDB('settings.json', settings);
    res.json({ success: true, prizes: cleaned });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});
app.post('/admin/transaction/confirm/:id', requireAdmin, async (req, res) => {
  try {
    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.id === req.params.id);
    if (!transaction) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    // Transaksi yang sudah 'done' TAPI outOfStock (key belum pernah terkirim)
    // harus tetap bisa di-retry dari sini setelah admin restock -- sebelumnya
    // guard ini menolak duluan dengan "Transaksi sudah selesai" walau key
    // sebenarnya belum pernah dikirim ke pembeli sama sekali.
    if (transaction.status === 'done' && !(transaction.outOfStock && !transaction.key)) {
      return res.json({ success: false, message: 'Transaksi sudah selesai' });
    }

    // Jika transaksi reseller, upgrade user
    if (transaction.type === 'reseller') {
      const users = await readFresh('users.json');
      const u = users.find(u => u.id === transaction.userId);
      if (u) {
        u.is_reseller = true;
        u.role = 'reseller';
        u.reseller_since = u.reseller_since || new Date().toISOString();
        u.reseller_code = u.reseller_code || ('RSL-' + u.username.toUpperCase().slice(0, 4) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase());
        await writeDB('users.json', users);
      }
      transaction.status = 'done';
      transaction.paidAt = new Date().toISOString();
      await writeDB('transactions.json', transactions);
      return res.json({ success: true, type: 'reseller' });
    }

    // Jika transaksi top up saldo wallet, kreditkan saldo user
    if (transaction.type === 'deposit') {
      const users = await readFresh('users.json');
      const u = users.find(u => u.id === transaction.userId);
      if (u) {
        u.balance = (u.balance || 0) + (transaction.amount || transaction.price || 0);
        await writeDB('users.json', users);
      }
      transaction.status = 'done';
      transaction.paidAt = new Date().toISOString();
      await writeDB('transactions.json', transactions);
      return res.json({ success: true, type: 'deposit', balance: u?.balance || 0 });
    }

    // Transaksi produk biasa: ambil key
    // PENTING: kalau durasi diminta (days ada) tapi tidak ada key bertag
    // durasi itu, JANGAN jatuh ke "ambil apa saja" — key tersisa bisa saja
    // bertag durasi lain, dan itu penyebab bug "beli 1 hari malah dikirim
    // yang 10 hari". Fallback ke generic (tanpa tag) tetap boleh, karena
    // generic memang tidak diklaim untuk durasi manapun.
    // FIX: readFresh (bukan readDB) — fungsi ini MEMBACA products.json lalu
    // MENULIS BALIK (writeDB) hasil pengurangan stok key. Kalau baca data
    // basi (instance lain baru saja nambah/kurangi stok key produk ini),
    // write-back di sini bisa overwrite perubahan itu dan bikin stok key
    // salah hitung / hilang diam-diam.
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === transaction.productId);
    let key = null;
    let keyError = null;
    if (product) {
      const settingsForKey = await readFresh('settings.json');
      // idempotencyKey = transaction.id (stabil) — supaya kalau admin klik
      // konfirmasi 2x karena double-tap, produk mode 'auto' tidak generate
      // 2 key / motong saldo reseller 2x untuk transaksi yang sama.
      const keyResult = await resolveProductKey(product, transaction.selectedDays, settingsForKey, {
        customerReference: transaction.customerName || transaction.code,
        target: transaction.wa || undefined,
        idempotencyKey: transaction.id
      });
      key = keyResult.key;
      keyError = keyResult.error || null;
      if (key) {
        product.sold = (product.sold || 0) + 1;
        await writeDB('products.json', products);
      }
    }

    transaction.status = 'done';
    transaction.key = key;
    transaction.outOfStock = !key;
    transaction.stockError = key ? null : (keyError || 'Stok habis - tidak ada key tersedia untuk produk ini');
    transaction.paidAt = new Date().toISOString();
    transaction.confirmedBy = 'admin';
    await writeDB('transactions.json', transactions);

    if (!key) {
      return res.json({ success: true, key: null, outOfStock: true, warning: transaction.stockError });
    }
    res.json({ success: true, key, outOfStock: false });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Leaderboard route
app.get('/leaderboard', (req, res) => {
  const transactions = readDB('transactions.json');
  const users = readDB('users.json');
  const settings = readDB('settings.json');

  // Calculate leaderboard (hanya transaksi pembelian produk beneran, lihat
  // computeLeaderboard() untuk detail kenapa deposit/reseller/gacha/
  // adjustment tidak boleh ikut dihitung)
  const leaderboard = computeLeaderboard(transactions, users);

  const user = getSessionUser(req);

  res.render('pages/leaderboard', {
    leaderboard,
    settings,
    user
  });
});

// API endpoints
app.get('/api/products', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan. Coba lagi nanti.' });
  const products = (await readFresh('products.json'))
    .filter(p => p.status === 'active')
    // SECURITY: jangan kirim keys ke publik — keys hanya dikirim setelah pembayaran sukses
    // stockCount unlimited HANYA untuk GhostSeller (lihat catatan lengkap di
    // popularProductsSafe atas, termasuk kenapa 999999 bukan Infinity --
    // endpoint ini juga JSON.stringify lewat res.json(), masalah yang sama
    // persis berlaku di sini).
    .map(({ keys, ...safe }) => ({ ...safe, stockCount: (safe.stockMode === 'ghostseller' || safe.stockMode === 'mixed' || (Array.isArray(safe.pricingOptions) && safe.pricingOptions.some(o => o.stockSource === 'ghostseller'))) ? 999999 : (keys || []).length }));
  res.json(products);
});

// ── Helper: validasi & hitung diskon voucher ──
const validateVoucher = async (code, price, userId) => {
  if (!code) return { valid: false, error: 'Kode kosong' };
  const vouchers = await readFresh('vouchers.json');
  const v = vouchers.find(v => v.code.toUpperCase() === code.trim().toUpperCase());
  if (!v) return { valid: false, error: 'Kode voucher tidak ditemukan' };
  if (!v.active) return { valid: false, error: 'Voucher tidak aktif' };
  if (v.expiresAt && new Date(v.expiresAt) < new Date()) return { valid: false, error: 'Voucher sudah kadaluarsa' };
  if (v.maxUses > 0 && v.usedCount >= v.maxUses) return { valid: false, error: 'Voucher sudah habis digunakan' };
  if (v.minPurchase > 0 && price < v.minPurchase) return { valid: false, error: `Minimal pembelian Rp ${v.minPurchase.toLocaleString('id-ID')}` };
  // Cegah reseller double-discount: kalau voucher punya flag excludeReseller,
  // tolak pemakaian oleh akun reseller (mereka sudah dapat diskon harga reseller).
  if (v.excludeReseller && userId) {
    const users = readDB('users.json');
    const u = users.find(u => u.id === userId);
    if (u?.is_reseller) return { valid: false, error: 'Voucher ini tidak berlaku untuk akun Reseller' };
  }
  if (v.perUserLimit > 0 && userId) {
    const userUses = (v.usages || []).filter(u => u.userId === userId).length;
    if (userUses >= v.perUserLimit) return { valid: false, error: 'Kamu sudah pernah memakai voucher ini' };
  }
  const discount = v.type === 'percent'
    ? Math.round(price * v.value / 100)
    : Math.min(v.value, price);
  const finalPrice = Math.max(price - discount, 0);
  return { valid: true, voucher: v, discount, finalPrice };
};

app.get('/api/stats', async (req, res) => {
  const products = await readSmart('products.json');
  const testimonials = await readSmart('testimonials.json');
  const users = await readSmart('users.json');
  const active = products.filter(p => p.status === 'active');
  const totalSold = products.reduce((s, p) => s + (p.sold || 0), 0);
  const avgRating = testimonials.length
    ? (testimonials.reduce((s, t) => s + (t.rating || 0), 0) / testimonials.length).toFixed(1)
    : '0.0';
  res.json({
    totalSold,
    totalActiveProducts: active.length,
    totalUsers: users.length,
    avgRating: parseFloat(avgRating)
  });
});

// Cek voucher (user)
app.post('/api/voucher/check', requireAuth, async (req, res) => {
  const { code, price } = req.body;
  if (!code || !price) return res.json({ valid: false, error: 'Data tidak lengkap' });
  const result = await validateVoucher(code, parseInt(price), req.session.userId);
  if (!result.valid) return res.json({ valid: false, error: result.error });
  res.json({
    valid: true,
    code: result.voucher.code,
    type: result.voucher.type,
    value: result.voucher.value,
    description: result.voucher.description || '',
    discount: result.discount,
    finalPrice: result.finalPrice
  });
});

app.get('/api/transactions', requireAdmin, (req, res) => {
  const transactions = readDB('transactions.json');
  res.json(transactions);
});

app.get('/api/testimonials', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan.' });
  const testimonials = await readSmart('testimonials.json');
  const users = await readSmart('users.json');
  const featured = req.query.featured === 'true';
  const verifiedOnly = req.query.verified === 'true';
  const productId = req.query.product;

  let filtered = testimonials;

  if (featured) {
    filtered = filtered.filter(t => t.featured && t.verified);
  } else if (verifiedOnly) {
    filtered = filtered.filter(t => t.verified);
  }

  if (productId) {
    filtered = filtered.filter(t => t.product === productId || t.productName === productId);
  }

  // Sort by date descending
  filtered.sort((a, b) => new Date(b.date) - new Date(a.date));

  // Attach user photo if available
  filtered = filtered.map(t => {
    const u = users.find(u => u.username === t.username);
    return { ...t, photo: u?.photo || null };
  });

  // Pad with fake entries so page always looks alive
  const fakeTestimonials = [
    { id:'fake1', username:'Rizky F.',    name:'Rizky F.',    rating:5, text:'Mod FF-nya mantap, udah 3 bulan pakai dan aman-aman aja. Fitur lengkap dari ESP sampai fly hack. CS juga responsif banget!', product:'ff',         productName:'FREE FIRE MAX',      date:'2025-05-20', verified:true },
    { id:'fake2', username:'Andi S.',     name:'Andi S.',     rating:5, text:'ML mod-nya lengkap banget! Map hack, drone view, sampai skin all hero ada. Auto update jadi nggak perlu repot tiap update.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-05-18', verified:true },
    { id:'fake3', username:'Dimas P.',    name:'Dimas P.',    rating:5, text:'Support fast response! Pas ada masalah langsung dibantu sampai beres. PUBG mod-nya juga smooth, nggak lag sama sekali.', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-05-15', verified:true },
    { id:'fake4', username:'farhan99',    name:'farhan',      rating:5, text:'Beli sertifikat anti-banned udah 2x dan alhamdulillah akun tetap aman. Worth it banget harganya segitu.', product:'sertifikat', productName:'SERTIFIKAT', date:'2025-05-10', verified:true },
    { id:'fake5', username:'gamer_mlbb',  name:'Wanda M.',    rating:4, text:'Produknya bagus, pengiriman key cepet banget. Cuma kadang agak lag di device lama tapi overall oke lah.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-05-08', verified:true },
    { id:'fake6', username:'ACA XITERZ', name:'ACA',          rating:5, text:'Udah lama langganan di sini, belum pernah kecewa. Proses beli gampang, bayar QRIS langsung dapat key. Recommended!', product:'ff',       productName:'FREE FIRE MAX',      date:'2025-05-05', verified:true },
    { id:'fake7', username:'bintang_07',  name:'bintang',     rating:5, text:'Lifetime PUBGM worth it banget. Udah 6 bulan masih lancar jaya, fitur no recoil-nya mantul.', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-04-28', verified:true },
    { id:'fake8', username:'rizky_ff',    name:'Rizky',       rating:4, text:'Kalau FF mod-nya top. Pernah ada issue tapi langsung di-handle sama admin. Keep up the good work!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-04-20', verified:true },
    { id:'fake9', username:'keymaster',   name:'Kevin',       rating:5, text:'CODM mod anti-recoil smooth banget. Rank dari Silver langsung naik ke Platinum dalam seminggu haha.', product:'codm',     productName:'CODM',    date:'2025-04-15', verified:true },
    { id:'fake10',username:'abil',        name:'abil',        rating:5, text:'Ini toko mod menu terpercaya yang pernah aku coba. Transaksi aman, key langsung masuk, CS ramah.', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-04-10', verified:true },
    { id:'fake11',username:'Hergi',       name:'Hergi',       rating:5, text:'Valorant ESP-nya akurat banget. Sudah 2 bulan pake dan belum ada masalah sama sekali. Pelayanan top!', product:'val',      productName:'VALORANT', date:'2025-04-05', verified:true },
    { id:'fake12',username:'rehan',       name:'rehan',       rating:5, text:'HOK mod-nya mantap, map hack dan skin unlock semua ada. Proses beli cepet dan key langsung terkirim.', product:'hok',     productName:'HOK',     date:'2025-03-28', verified:true },
    { id:'fake13',username:'Saell',       name:'Saell',       rating:5, text:'Beli Free Fire MAX bundle, prosesnya cepet banget! Cuma 2 menit key langsung masuk. Akun aman sampai sekarang.', product:'ff',         productName:'FREE FIRE MAX',      date:'2025-03-25', verified:true },
    { id:'fake14',username:'GamerKing99', name:'GamerKing99', rating:5, text:'MLBB mod-nya juara! Skin all hero gratis, map hack jalan mulus. Adminnya juga friendly, fast respon.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-03-20', verified:true },
    { id:'fake15',username:'SkyyFire',    name:'SkyyFire',    rating:5, text:'PUBG mod smooth banget di HP kentang sekalipun. No lag, no crash. Harga juga affordable banget!', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-03-15', verified:true },
    { id:'fake16',username:'ShadowX',     name:'ShadowX',     rating:5, text:'Udah 4x beli di sini, selalu puas. Key original, legit, dan awet. Best store for mod menu!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-03-10', verified:true },
    { id:'fake17',username:'NightWolf',   name:'NightWolf',   rating:4, text:'PUBGM no recoil mantap, tapi kadang auto aim agak delay. Overall masih oke sih, worth the price.', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-03-05', verified:true },
    { id:'fake18',username:'LunarKing',   name:'LunarKing',   rating:5, text:'MLBB dron view works perfectly! Enemy location always visible. Rank naik terus dari season kemarin.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-02-28', verified:true },
    { id:'fake19',username:'NeonVibes',   name:'NeonVibes',   rating:5, text:'FF aimbot-nya smooth, headshot mulus. UDAH 3 BULAN pakai dan belum pernah kena ban. Mantap!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-02-20', verified:true },
    { id:'fake20',username:'StormRider',  name:'StormRider',  rating:4, text:'Produk bagus, cuma pengiriman key agak lama pas weekend. Tapi overall puas, CS-nya ramah.', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-02-15', verified:true },
    { id:'fake21',username:'GhostByte',   name:'GhostByte',   rating:5, text:'FF wallhack jernih, bisa lihat musuh tembus dinding. Gameplay jadi lebih seru dan menang terus!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-02-10', verified:true },
    { id:'fake22',username:'CyberRush',   name:'CyberRush',   rating:5, text:'MLBB skin all hero unlocked, effect skill keliatan keren banget! Teman-teman pada kaget.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-02-05', verified:true },
    { id:'fake23',username:'AlphaGod',    name:'AlphaGod',    rating:5, text:'PUBG mod versi terbaru udah support map Livik juga. Smooth, nggak ada glitch. Top banget!', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-01-28', verified:true },
    { id:'fake24',username:'IronPhoenix', name:'IronPhoenix', rating:5, text:'FF mod ini yang paling stabil dari semua yang pernah aku coba. Langganan bulanan, worth it!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-01-20', verified:true },
    { id:'fake25',username:'TurboAce',    name:'TurboAce',    rating:4, text:'MLBB drone view bagus, tapi agak boros battery. Overall recommend buat yang mau rank push.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-01-15', verified:true },
    { id:'fake26',username:'NovaStar',    name:'NovaStar',    rating:5, text:'FF ESP wallhack akurat, bisa lihat posisi semua musuh. Combo sama aimbot auto winner!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-01-10', verified:true },
    { id:'fake27',username:'DragonByte',  name:'DragonByte',  rating:5, text:'PUBG no recoil + auto headshot combo mantap! Rank naik dari Gold ke Diamond dalam 2 minggu.', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-01-05', verified:true },
    { id:'fake28',username:'MegaBoss',    name:'MegaBoss',    rating:5, text:'Beli mod menu di sini gampang banget, bayar pakai QRIS langsung dapat key. Nggak ribet!', product:'ff',        productName:'FREE FIRE MAX',      date:'2024-12-28', verified:true },
    { id:'fake29',username:'PulseWave',   name:'PulseWave',   rating:4, text:'MLBB mod oke, tapi perlu update manual tiap patch baru. Harusnya auto update sih.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2024-12-20', verified:true },
    { id:'fake30',username:'HyperCore',   name:'HyperCore',   rating:5, text:'PUBG speed hack works! Movement jadi cepat, musuh nggak bisa ngejar. Asik banget!', product:'pubgm',     productName:'PUBG MOBILE',   date:'2024-12-15', verified:true },
  ];

  // Filter fake by product if requested
  let finalFake = fakeTestimonials;
  if (productId) {
    finalFake = fakeTestimonials.filter(f => f.product === productId || f.productName === productId);
  }

  // Only add fake entries that don't duplicate real usernames
  const realUsernames = new Set(filtered.map(t => (t.username||'').toLowerCase()));
  const paddedFake = finalFake.filter(f => !realUsernames.has((f.username||'').toLowerCase()));

  // Merge: real first, then fake (capped so total stays reasonable)
  const maxDisplay = 30;
  const combined = [...filtered, ...paddedFake].slice(0, maxDisplay);

  res.json(combined);
});

app.post('/api/testimonials', requireAuth, async (req, res) => {
  try {
    const { productId, productName, rating, text } = req.body;
    if (!productId || !rating || !text) return res.json({ success: false, message: 'Data tidak lengkap' });
    const ratingNum = parseInt(rating);
    if (ratingNum < 1 || ratingNum > 5) return res.json({ success: false, message: 'Rating tidak valid' });
    if (!text.trim()) return res.json({ success: false, message: 'Ulasan tidak boleh kosong' });
    if (text.trim().length > 500) return res.json({ success: false, message: 'Ulasan maksimal 500 karakter' });

    // Hanya user yang sudah membeli (transaksi sukses/done) produk ini yang boleh kirim testimoni
    const transactions = readDB('transactions.json');
    const hasPurchased = transactions.some(t =>
      t.userId === req.session.userId &&
      t.productId === productId &&
      t.status === 'done'
    );
    if (!hasPurchased) {
      return res.json({ success: false, message: 'Hanya pembeli produk ini yang bisa memberikan rating/testimoni' });
    }

    const users = readDB('users.json');
    const user = users.find(u => u.id === req.session.userId);
    const testimonials = readDB('testimonials.json');

    testimonials.unshift({
      id: uuidv4(),
      product: productId,
      productName: productName || '',
      username: user?.username || 'Pengguna',
      rating: ratingNum,
      text: text.trim(),
      date: new Date().toISOString(),
      verified: true,
      featured: false
    });

    await writeDB('testimonials.json', testimonials);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/testimonial/add', requireAdmin, async (req, res) => {
  try {
    const { name, username, rating, text, product, verified, featured } = req.body;
    const testimonials = await readFresh('testimonials.json');

    const newTestimonial = {
      id: `testi-${Date.now()}`,
      name,
      username: username || null,
      rating: parseInt(rating) || 5,
      text,
      product: product || null,
      date: new Date().toISOString(),
      verified: verified === true || verified === 'true',
      featured: featured === true || featured === 'true'
    };

    testimonials.push(newTestimonial);
    await writeDB('testimonials.json', testimonials);

    res.json({ success: true, message: 'Testimoni berhasil ditambahkan' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/delete/:id', requireAdmin, async (req, res) => {
  try {
    let testimonials = await readFresh('testimonials.json');
    testimonials = testimonials.filter(t => t.id !== req.params.id);
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: 'Testimoni berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/toggle-featured/:id', requireAdmin, async (req, res) => {
  try {
    const testimonials = await readFresh('testimonials.json');
    const testi = testimonials.find(t => t.id === req.params.id);
    if (!testi) return res.json({ success: false, message: 'Testimoni tidak ditemukan' });

    testi.featured = !testi.featured;
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: 'Status featured berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/toggle-verified/:id', requireAdmin, async (req, res) => {
  try {
    const testimonials = await readFresh('testimonials.json');
    const testi = testimonials.find(t => t.id === req.params.id);
    if (!testi) return res.json({ success: false, message: 'Testimoni tidak ditemukan' });

    testi.verified = !testi.verified;
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: testi.verified ? 'Testimoni berhasil diverifikasi' : 'Verifikasi dicabut' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.get('/api/notifications', (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan.' });
  const notifs = readDB('notifications.json').slice(0, 20);
  // SECURITY: anonimkan nama pembeli — hanya tampilkan initial agar tidak bocor daftar username asli
  const anonymize = (name = '') => {
    if (!name) return '***';
    return name[0] + '*'.repeat(Math.max(name.length - 1, 2));
  };
  const enriched = notifs.map(({ id, type, productName, price, timeStr, buyerName }) => ({
    id, type, productName, price, timeStr,
    buyerName: anonymize(buyerName),
    buyerPhoto: null
  }));
  res.json(enriched);
});

app.get('/api/leaderboard', (req, res) => {
  const transactions = readDB('transactions.json');
  const users = readDB('users.json');
  const data = computeLeaderboard(transactions, users, 10).map(e => ({ ...e, isReal: true }));
  res.json({ success: true, data });
});

// ═══════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════

// Admin Product Edit Page
app.get('/admin/product-edit', requireAdmin, async (req, res) => {
  const [products, settings] = await Promise.all([readFresh('products.json'), readFresh('settings.json')]);
  const productId = req.query.id;
  const product = productId ? products.find(p => p.id === productId) : null;
  res.render('pages/admin-product-edit', { product, products, settings });
});

// Admin Theme Settings Page
app.get('/admin/theme-settings', requireAdmin, async (req, res) => {
  const settings = await readFresh('settings.json');
  res.render('pages/admin-theme', { settings });
});

// Admin Product Management
// FIX "ANTI-LAG": endpoint ini sekarang dukung ?search=, ?offset=, ?limit=
// supaya panel admin bisa infinite-scroll / cari produk tanpa perlu
// nge-render SEMUA produk sekaligus ke DOM (yang jadi penyebab utama lag
// begitu jumlah produk sudah ratusan+ — lihat juga GET /admin yang sekarang
// cuma kirim halaman pertama saat render awal, lihat catatan di sana).
// Tanpa query param sama sekali, tetap balikin semua produk (backward
// compat untuk kode lama yang masih panggil endpoint ini apa adanya).
app.get('/admin/products', requireAdmin, async (req, res) => {
  let products = await readFresh('products.json');
  if (!Array.isArray(products)) products = [];

  const search = (req.query.search || '').trim().toLowerCase();
  if (search) {
    products = products.filter(p =>
      (p.name || '').toLowerCase().includes(search) ||
      (p.category || '').toLowerCase().includes(search)
    );
  }

  const total = products.length;
  const hasPaging = req.query.offset !== undefined || req.query.limit !== undefined;
  if (hasPaging) {
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit) || 30));
    const page = products.slice(offset, offset + limit);
    return res.json({ success: true, data: page, total, hasMore: offset + limit < total });
  }
  res.json({ success: true, data: products, total, hasMore: false });
});

// Admin Get Single Product
app.get('/admin/product/:id', requireAdmin, async (req, res) => {
  const products = await readFresh('products.json');
  const product = products.find(p => p.id === req.params.id);
  if (!product) return res.json({ success: false, message: 'Produk tidak ditemukan' });
  res.json({ success: true, data: product });
});

// Admin Update Product (image, status, keys)
app.post('/admin/product/:id', requireAdmin, async (req, res) => {
  try {
    const { items, bannerUrl, status, keys, keysMode, platforms, operationalStatus, stockMode, resellerItemId } = req.body;
    const products = await readFresh('products.json');
    const productIndex = products.findIndex(p => p.id === req.params.id);

    if (productIndex === -1) return res.json({ success: false, message: 'Produk tidak ditemukan' });
    const p = products[productIndex];

    // Simpan ke image (yang dibaca frontend) DAN bannerUrl
    if (bannerUrl && bannerUrl.trim()) {
      p.image    = bannerUrl.trim();
      p.bannerUrl = bannerUrl.trim();
    }

    if (status) p.status = status;
    if (operationalStatus && ['online','offline','unknown'].includes(operationalStatus)) p.operationalStatus = operationalStatus;
    if (Array.isArray(platforms)) p.platforms = platforms;

    // Mode stok: 'manual' (default, stok dari product.keys) atau
    // 'ghostseller' (key di-generate on-demand dari GhostSeller Partner
    // API -- lihat resolveProductKey & ghostseller-api.js). vipibmstore
    // ('auto') sudah dicabut total dari sistem ini (lihat CHANGELOG git),
    // jadi p.resellerItemId di bawah ini murni peninggalan data lama yang
    // tidak lagi dibaca oleh resolveProductKey -- disimpan apa adanya kalau
    // masih dikirim client, tapi tidak berpengaruh ke apapun.
    if (stockMode === 'ghostseller' || stockMode === 'manual' || stockMode === 'mixed') p.stockMode = stockMode;
    if (resellerItemId !== undefined) {
      const rid = parseInt(resellerItemId);
      p.resellerItemId = (!isNaN(rid) && rid > 0) ? rid : null;
    }

    // Kelola harga / pricing options
    // BUG SEBELUMNYA: rebuild p.items/p.pricingOptions di sini tidak pernah
    // menyertakan field reseller_price sama sekali, jadi setiap kali produk
    // disimpan lewat halaman Edit Produk ini, harga reseller manual yang
    // sudah diset (misal saat create produk) hilang/ke-reset diam-diam —
    // reseller jadi lihat harga yang sama (hasil diskon global %) di semua
    // paket, bukan harga custom yang sudah ditentukan per paket.
    const { pricingOptions } = req.body;
    if (Array.isArray(pricingOptions) && pricingOptions.length > 0) {
      const validOpts = pricingOptions
        .map(o => {
          const days = parseInt(o.days);
          const price = parseInt(o.price);
          let resellerPrice = null;
          if (o.reseller_price !== undefined && o.reseller_price !== null && o.reseller_price !== '') {
            const rp = parseInt(o.reseller_price);
            if (!isNaN(rp) && rp >= 0) resellerPrice = rp;
          } else {
            // Field reseller_price tidak dikirim (mis. form lama belum di-refresh)
            // -> jangan hapus, coba pertahankan nilai lama berdasarkan hari yang sama.
            const existing = (p.pricingOptions || []).find(e => e.days === days)
              || (p.items || []).find(it => parseItemLabel(it.l).days === days);
            if (existing && existing.reseller_price != null && existing.reseller_price >= 0) {
              resellerPrice = existing.reseller_price;
            }
          }
          // Mapping GhostSeller (auto restock) per-varian -- ID string,
          // lihat ghostseller-api.js dan resolveProductKey() untuk
          // pemakaiannya. vipibmstore ('auto', resellerItemId per-varian)
          // sudah dicabut total -- tidak ada lagi field itu di sini.
          const ghostSellerProductId = (typeof o.ghostSellerProductId === 'string' && o.ghostSellerProductId.trim())
            ? o.ghostSellerProductId.trim() : null;
          const ghostSellerDurationId = (typeof o.ghostSellerDurationId === 'string' && o.ghostSellerDurationId.trim())
            ? o.ghostSellerDurationId.trim() : null;
          // stockSource per baris: 'ghostseller' eksplisit, selain itu
          // SELALU 'manual' (termasuk data lama yang mungkin masih kirim
          // 'auto' dari cache browser lama -- jangan pernah diloloskan,
          // ini justru sumber insiden Sep 2026).
          const rowStockSource = o.stockSource === 'ghostseller' ? 'ghostseller' : 'manual';
          const unit = ['hari','jam','menit'].includes(o.unit) ? o.unit : 'hari';
          return { days, price, reseller_price: resellerPrice, ghostSellerProductId, ghostSellerDurationId, stockSource: rowStockSource, unit };
        })
        .filter(o => o.days > 0 && o.price >= 0);
      // FIX BUG "1 Jam ketuker/dobel jadi 1 DAYS": dedup per (days, unit) --
      // endpoint ini sebelumnya TIDAK dedup sama sekali, jadi kalau admin
      // sempat submit ganda atau baris ke-generate duplikat di frontend,
      // dua opsi "1 jam" bisa lolos jadi 2 entry beda di pricingOptions.
      const seenDedup = new Set();
      const dedupedOpts = validOpts.filter(o => {
        const key = `${o.days}:${o.unit}`;
        if (seenDedup.has(key)) return false;
        seenDedup.add(key); return true;
      });
      if (dedupedOpts.length > 0) {
        p.pricingOptions = dedupedOpts;
        p.items = dedupedOpts.map(o => ({ l: buildItemLabel(p.name, o.days, o.unit), p: o.price, reseller_price: o.reseller_price }));
      }
    }

    // Kelola keys
    // FIX BUG "key jadi double": dedup exact-match saat append, konsisten
    // dengan endpoint keys lainnya.
    if (keys !== undefined && keys !== null) {
      const newKeys = String(keys).split('\n').map(k => k.trim()).filter(k => k);
      if (newKeys.length > 0) {
        if (keysMode === 'replace') {
          p.keys = newKeys;
        } else {
          const existing = new Set(p.keys || []);
          const toAdd = newKeys.filter(k => !existing.has(k));
          p.keys = [...(p.keys || []), ...toAdd];
        }
      }
    }

    await writeDB('products.json', products);
    res.json({ success: true, message: 'Produk berhasil diupdate', data: p });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// Admin Upload Banner — di Vercel upload ke Supabase Storage, lokal ke filesystem
app.post('/admin/upload-banner', requireAdmin, multer({ storage: multer.memoryStorage(), limits: { fileSize: 4 * 1024 * 1024 }, fileFilter }).single('banner'), async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'Tidak ada file diupload' });

    if (isVercel) {
      // Vercel: upload ke Supabase Storage
      try {
        const url = await db.uploadImage(req.file.buffer, req.file.originalname, req.file.mimetype);
        return res.json({ success: true, bannerUrl: url });
      } catch (e) {
        return res.json({ success: false, message: e.message });
      }
    }

    // Lokal: simpan di filesystem
    const bannersDir = path.join(__dirname, 'public', 'uploads', 'banners');
    if (!fs.existsSync(bannersDir)) fs.mkdirSync(bannersDir, { recursive: true });
    const filename = `${Date.now()}-${uuidv4()}${mimeToSafeExt(req.file.mimetype)}`;
    fs.writeFileSync(path.join(bannersDir, filename), req.file.buffer);
    res.json({ success: true, bannerUrl: `/uploads/banners/${filename}` });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// Admin Get Theme Settings
app.get('/admin/theme', requireAdmin, async (req, res) => {
  const settings = await readFresh('settings.json');
  res.json({ success: true, data: settings.theme || {} });
});

// Admin Update Theme Settings
app.post('/admin/theme', requireAdmin, async (req, res) => {
  try {
    const { primaryColor, secondaryColor, accentColor, backgroundColor, cardBackground, borderColor, glowColor } = req.body;
    const settings = await readFresh('settings.json');

    const prevTheme = settings.theme || {};
    settings.theme = {
      primaryColor: primaryColor || prevTheme.primaryColor || '#7b2cbf',
      secondaryColor: secondaryColor || prevTheme.secondaryColor || '#9d4edd',
      accentColor: accentColor || prevTheme.accentColor || '#c77dff',
      backgroundColor: backgroundColor || prevTheme.backgroundColor || '#0a0a0a',
      cardBackground: cardBackground || prevTheme.cardBackground || '#151520',
      borderColor: borderColor || prevTheme.borderColor || 'rgba(157,78,221,.15)',
      glowColor: glowColor || prevTheme.glowColor || 'rgba(157, 78, 221, 0.1)'
    };

    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Tema berhasil diupdate', data: settings.theme });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// ═══════════════════════════════════════════════════════════
// KEY POOL SYSTEM — Format: CODE - X Hari
// ═══════════════════════════════════════════════════════════

// User: halaman aktifkan key
app.get('/activate-key', requireAuth, (req, res) => {
  const user = getSessionUser(req);
  const settings = readDB('settings.json');
  res.render('pages/activate-key', { user, settings, result: null, error: null, code: '' });
});

app.post('/activate-key', requireAuth, async (req, res) => {
  const user = getSessionUser(req);
  const settings = readDB('settings.json');
  const code = (req.body.code || '').trim().toUpperCase();

  if (!code) return res.render('pages/activate-key', { user, settings, result: null, error: 'Masukkan kode key terlebih dahulu', code: '' });

  const keyspool = readDB('keyspool.json');
  const key = keyspool.find(k => k.code.toUpperCase() === code);

  if (!key) return res.render('pages/activate-key', { user, settings, result: null, error: 'Key tidak ditemukan atau tidak valid', code });
  if (key.used) return res.render('pages/activate-key', { user, settings, result: null, error: 'Key sudah pernah digunakan', code });

  key.used = true;
  key.usedBy = user.id;
  key.usedByUsername = user.username;
  key.usedAt = new Date().toISOString();
  await writeDB('keyspool.json', keyspool);

  res.render('pages/activate-key', {
    user, settings, code,
    result: { code: key.code, duration: key.duration, label: key.label || `${key.duration} Hari`, note: key.note || '' },
    error: null
  });
});

// Admin: lihat semua key pool
app.get('/admin/keyspool', requireAdmin, async (req, res) => {
  res.json({ success: true, data: await readFresh('keyspool.json') });
});

// Admin: tambah key baru
app.post('/admin/keyspool/add', requireAdmin, async (req, res) => {
  try {
    const { code, duration, label, note } = req.body;
    if (!code || !duration) return res.json({ success: false, message: 'Kode dan durasi wajib diisi' });
    const d = parseInt(duration);
    if (isNaN(d) || d <= 0) return res.json({ success: false, message: 'Durasi tidak valid (harus > 0 hari)' });
    const keyspool = await readFresh('keyspool.json');
    if (keyspool.find(k => k.code.toUpperCase() === code.trim().toUpperCase())) {
      return res.json({ success: false, message: 'Kode key sudah ada' });
    }
    keyspool.push({
      id: uuidv4(),
      code: code.trim().toUpperCase(),
      duration: d,
      label: label?.trim() || `${d} Hari`,
      used: false, usedBy: null, usedByUsername: null, usedAt: null,
      note: note?.trim() || '',
      createdAt: new Date().toISOString()
    });
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true, data: keyspool });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Admin: generate key otomatis (bulk)
app.post('/admin/keyspool/generate', requireAdmin, async (req, res) => {
  try {
    const { count, duration, prefix, label } = req.body;
    const n = Math.min(parseInt(count) || 1, 100);
    const d = parseInt(duration);
    if (isNaN(d) || d <= 0) return res.json({ success: false, message: 'Durasi tidak valid' });
    const keyspool = await readFresh('keyspool.json');
    const pref = (prefix || 'KEY').toUpperCase();
    const added = [];
    for (let i = 0; i < n; i++) {
      const code = `${pref}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
      keyspool.push({
        id: uuidv4(), code, duration: d,
        label: label?.trim() || `${d} Hari`,
        used: false, usedBy: null, usedByUsername: null, usedAt: null,
        note: '', createdAt: new Date().toISOString()
      });
      added.push(code);
    }
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true, generated: added.length, codes: added, data: keyspool });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Admin: hapus key
app.post('/admin/keyspool/delete/:id', requireAdmin, async (req, res) => {
  try {
    let keyspool = await readFresh('keyspool.json');
    keyspool = keyspool.filter(k => k.id !== req.params.id);
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// VOUCHER SYSTEM
// ═══════════════════════════════════════════════════════════

app.get('/admin/vouchers', requireAdmin, async (req, res) => {
  res.json({ success: true, data: await readFresh('vouchers.json') });
});

app.post('/admin/vouchers/add', requireAdmin, async (req, res) => {
  try {
    const { code, type, value, minPurchase, maxUses, perUserLimit, expiresAt, description, excludeReseller } = req.body;
    if (!code || !type || value === undefined) return res.json({ success: false, message: 'Kode, tipe, dan nilai wajib diisi' });
    const val = parseFloat(value);
    if (isNaN(val) || val <= 0) return res.json({ success: false, message: 'Nilai voucher tidak valid' });
    if (type === 'percent' && val > 100) return res.json({ success: false, message: 'Persentase diskon maksimal 100%' });
    const vouchers = await readFresh('vouchers.json');
    if (vouchers.find(v => v.code.toUpperCase() === code.trim().toUpperCase())) {
      return res.json({ success: false, message: 'Kode voucher sudah ada' });
    }
    const newV = {
      id: uuidv4(),
      code: code.trim().toUpperCase(),
      type,
      value: val,
      minPurchase: parseInt(minPurchase) || 0,
      maxUses: parseInt(maxUses) || 0,
      perUserLimit: parseInt(perUserLimit) || 1,
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      description: description?.trim() || '',
      excludeReseller: excludeReseller === true || excludeReseller === 'true',
      active: true,
      usedCount: 0,
      usages: [],
      createdAt: new Date().toISOString()
    };
    vouchers.push(newV);
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true, data: vouchers });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/vouchers/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const vouchers = await readFresh('vouchers.json');
    const v = vouchers.find(v => v.id === req.params.id);
    if (!v) return res.json({ success: false, message: 'Voucher tidak ditemukan' });
    v.active = !v.active;
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true, active: v.active });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/vouchers/delete/:id', requireAdmin, async (req, res) => {
  try {
    let vouchers = await readFresh('vouchers.json');
    vouchers = vouchers.filter(v => v.id !== req.params.id);
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ── Global error handler (safety net) ──
// Sebelumnya tidak ada sama sekali, jadi kalau ada route yang throw
// (misal readFresh/render gagal di tengah jalan), request-nya cuma
// nge-hang atau balikin "Internal Server Error" polos tanpa info apapun.
// Sekarang error-nya ke-log jelas di server + user dapat pesan yang masuk akal.
app.use((err, req, res, next) => {
  console.error('[UNCAUGHT ROUTE ERROR]', req.method, req.originalUrl, '\n', err.stack || err);
  if (res.headersSent) return next(err);
  if (req.xhr || req.headers['content-type']?.includes('application/json') || req.originalUrl.startsWith('/admin/')) {
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan di server: ' + (err.message || 'unknown error') });
  }
  res.status(500).send('Internal Server Error: ' + (err.message || 'unknown error'));
});

// Tangkap juga promise yang reject tanpa .catch (async route tanpa try/catch)
// supaya server tidak diam-diam gantung / crash tanpa jejak di log.
process.on('unhandledRejection', (reason) => {
  console.error('[UNHANDLED REJECTION]', reason);
});

