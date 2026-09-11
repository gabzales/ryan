// Supabase integration — drop-in replacement untuk jsonbin.js
// Interface identik: readDB(filename) dan writeDB(filename, data)

const fs = require('fs');
const path = require('path');

let supabase = null;
let dbCache = {};
let lastClientInitError = null; // pesan error asli kalau createClient() gagal, supaya bisa ditampilkan ke admin
const DB_FILES = ['users.json','products.json','transactions.json','testimonials.json','notifications.json','settings.json','keyspool.json','vouchers.json','admin-lock.json'];

// File yang defaultnya object {} bukan array [] saat cache masih kosong
const OBJECT_FILES = new Set(['settings.json', 'admin-lock.json']);

// Lazy init Supabase client
const getClient = () => {
  if (supabase) return supabase;
  // .trim() penting: copy-paste value env var dari Supabase/Vercel sering
  // kebawa spasi atau newline tak kasat mata di awal/akhir, yang bikin
  // createClient() gagal dengan cara yang sulit dilacak.
  const url = (process.env.SUPABASE_URL || '').trim();
  // PENTING: pakai SERVICE_ROLE key, bukan ANON key.
  // Server kita butuh full read/write ke tabel keyvalue_store, dan RLS
  // sekarang memblokir anon sepenuhnya (lihat supabase-schema.sql).
  // Service role key BYPASS RLS by design — makanya HARUS hanya
  // dipakai di server, JANGAN PERNAH dikirim ke browser/client code.
  const key = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
  if (!key && process.env.SUPABASE_ANON_KEY) {
    console.warn('⚠️  SUPABASE_SERVICE_ROLE_KEY belum di-set. Anon key TIDAK akan bisa baca/tulis karena RLS sekarang membatasi akses anon. Set SUPABASE_SERVICE_ROLE_KEY di env Vercel.');
  }
  if (!url || !key) return null;
  try {
    new URL(url); // validasi format URL eksplisit (kasih pesan jelas kalau salah format, bukan cuma gagal diam-diam)
  } catch (e) {
    lastClientInitError = `SUPABASE_URL formatnya tidak valid: "${url}" — harus seperti https://xxxxx.supabase.co (tanpa spasi/baris baru tersembunyi).`;
    console.error('[supabase]', lastClientInitError);
    return null;
  }
  try {
    const { createClient } = require('@supabase/supabase-js');
    supabase = createClient(url, key, {
      auth: { persistSession: false }
    });
    lastClientInitError = null;
    return supabase;
  } catch (e) {
    lastClientInitError = e?.message || String(e) || 'createClient() gagal tanpa pesan error.';
    console.error('[supabase] createClient error:', lastClientInitError);
    return null;
  }
};

// Local /tmp backup agar ada fallback saat Supabase lambat
const isVercel = process.env.VERCEL === '1' || !!process.env.NOW_REGION;
const localDbPath = isVercel ? '/tmp/database' : path.join(__dirname, 'database');
if (!fs.existsSync(localDbPath)) { try { fs.mkdirSync(localDbPath, { recursive: true }); } catch {} }

const writeLocalBackup = (filename, data) => {
  try { fs.writeFileSync(path.join(localDbPath, filename), JSON.stringify(data)); } catch {}
};

const readLocalBackup = (filename) => {
  try {
    const p = path.join(localDbPath, filename);
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, 'utf-8'));
  } catch { return null; }
};

// ── PUBLIC API ──────────────────────────────────────────────

// TTL tracking: catat kapan terakhir cache di-sync dari Supabase
const cacheTimestamp = {}; // filename -> timestamp ms
// FIX (egress meledak): naik dari 8 detik -> 30 detik. Untuk listing produk
// publik, 30 detik masih cukup real-time buat toko online, tapi memotong
// frekuensi hit ke Supabase secara signifikan dibanding sebelumnya.
const CACHE_TTL = 30000;   // 30 detik — default

const readDB = (filename) => {
  return dbCache[filename] !== undefined
    ? dbCache[filename]
    : (OBJECT_FILES.has(filename) ? {} : []);
};

// readSmart: pakai cache jika masih segar (<TTL), else fetch Supabase
// Untuk GET endpoints yang butuh konsistensi antar instance Vercel
const readSmart = async (filename) => {
  const now = Date.now();
  const age = now - (cacheTimestamp[filename] || 0);
  if (age < CACHE_TTL) return readDB(filename); // cache masih fresh
  return readFresh(filename);                    // stale → ambil dari Supabase
};

const writeDB = async (filename, data) => {
  dbCache[filename] = data;
  cacheTimestamp[filename] = Date.now(); // mark fresh setelah write
  writeLocalBackup(filename, data);
  const client = getClient();
  if (!client) return;
  try {
    const { error } = await client
      .from('keyvalue_store')
      .upsert({ key: filename, value: data }, { onConflict: 'key' });
    if (error) console.error(`[supabase] writeDB ${filename}:`, error.message);
  } catch (e) {
    console.error(`[supabase] writeDB ${filename} exception:`, e.message);
  }
};

const initializeDB = async () => {
  console.log('📦 Initializing database (Supabase)...');

  // 1. Load local backup ke cache sebagai baseline
  for (const f of DB_FILES) {
    const local = readLocalBackup(f);
    if (local !== null) dbCache[f] = local;
    else dbCache[f] = OBJECT_FILES.has(f) ? {} : [];
  }

  const client = getClient();
  if (!client) {
    console.warn('⚠️  SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY belum di-set. Pakai local fallback.');
    return;
  }

  // 2. Load dari Supabase (source of truth)
  try {
    const { data, error } = await client
      .from('keyvalue_store')
      .select('key, value');
    if (error) throw new Error(error.message);
    if (data && data.length > 0) {
      data.forEach(row => {
        dbCache[row.key] = row.value;
        writeLocalBackup(row.key, row.value);
      });
      console.log(`✅ Database connected to Supabase (${data.length} collections loaded)`);
    } else {
      console.log('📝 Supabase table kosong, seeding...');
      await seedSupabase(client);
      console.log('✅ Supabase seeded');
    }
  } catch (e) {
    const msg = e.message || '';
    // Table belum dibuat — coba buat otomatis via SQL langsung
    if (msg.includes('relation') || msg.includes('does not exist') || msg.includes('42P01')) {
      console.warn('⚠️  Tabel keyvalue_store belum ada. Mencoba buat otomatis...');
      try {
        await ensureTableExists();
        // Coba load ulang
        const { data: d2 } = await client.from('keyvalue_store').select('key, value');
        if (d2 && d2.length > 0) {
          d2.forEach(row => { dbCache[row.key] = row.value; writeLocalBackup(row.key, row.value); });
          console.log(`✅ Loaded ${d2.length} collections after table creation`);
        } else {
          await seedSupabase(client);
        }
        return;
      } catch (e2) {
        console.error('❌ Gagal buat tabel otomatis. JALANKAN SQL SCHEMA DI SUPABASE DASHBOARD!');
        console.error('   https://supabase.com/dashboard/project/' + (process.env.SUPABASE_URL || '').split('.')[0].replace('https://', '') + '/sql/new');
      }
    }
    console.warn('⚠️  Supabase error, pakai local cache:', msg);
  }
};

// Coba buat tabel otomatis via direct PostgreSQL
const ensureTableExists = async () => {
  const url = process.env.SUPABASE_URL || '';
  const pw = process.env.SUPABASE_DB_PASSWORD;
  if (!pw) throw new Error('SUPABASE_DB_PASSWORD belum di-set');
  const ref = url.replace('https://', '').split('.')[0];
  const fs = require('fs');
  const { Pool } = require('pg');
  const pool = new Pool({
    host: `db.${ref}.supabase.co`,
    port: 5432,
    database: 'postgres',
    user: 'postgres',
    password: pw,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 10000
  });
  try {
    await pool.query(fs.readFileSync(path.join(__dirname, 'supabase-schema.sql'), 'utf-8'));
    console.log('✅ Tabel keyvalue_store berhasil dibuat');
  } finally {
    await pool.end();
  }
};

const seedSupabase = async (client) => {
  const rows = DB_FILES.map(f => ({ key: f, value: dbCache[f] || (OBJECT_FILES.has(f) ? {} : []) }));
  const { error } = await client
    .from('keyvalue_store')
    .upsert(rows, { onConflict: 'key', ignoreDuplicates: true });
  if (error) console.error('[supabase] seed error:', error.message);
};


// ── UPLOAD IMAGE ke Supabase Storage ─────────────────────
// FIX (egress meledak): sebelumnya file asli (foto HP mentah bisa 2-5MB)
// diupload apa adanya dan diserve langsung sebagai <img src> publik. Tiap
// page view = full download dari Storage, itu masuk hitungan CACHED EGRESS
// Supabase. Traffic reguler saja bisa numpuk puluhan GB/bulan dan kena
// limit "exceed_cached_egress_quota" (free tier cuma 5GB).
// Sekarang: resize max width 1000px + convert ke WebP (kualitas 78) sebelum
// upload. Biasanya motong ukuran file 70-90% tanpa kelihatan bedanya di UI.
const sharp = require('sharp');

const compressImage = async (fileBuffer, contentType) => {
  // SVG dan GIF (animasi) dilewati — sharp bisa merusak animasi GIF, dan
  // SVG sudah kecil/vector jadi tidak perlu dikompres.
  if (contentType === 'image/svg+xml' || contentType === 'image/gif') {
    return { buffer: fileBuffer, contentType, ext: contentType === 'image/gif' ? 'gif' : 'svg' };
  }
  try {
    const buffer = await sharp(fileBuffer)
      .resize({ width: 1000, withoutEnlargement: true })
      .webp({ quality: 78 })
      .toBuffer();
    return { buffer, contentType: 'image/webp', ext: 'webp' };
  } catch (e) {
    // Kalau sharp gagal (file korup/format aneh), fallback ke file asli
    // daripada bikin upload gagal total.
    console.error('[uploadImage] compress gagal, pakai file asli:', e.message);
    return { buffer: fileBuffer, contentType, ext: null };
  }
};

const uploadImage = async (fileBuffer, filename, contentType) => {
  const client = getClient();
  if (!client) throw new Error('Supabase tidak terkonfigurasi');

  const { buffer, contentType: outType, ext } = await compressImage(fileBuffer, contentType);

  const baseName = filename.replace(/[^a-zA-Z0-9.-]/g, '_').replace(/\.[^.]+$/, '');
  const finalExt = ext || (filename.match(/\.[^.]+$/)?.[0]?.replace('.', '')) || 'jpg';
  const cleanName = `${Date.now()}-${baseName}.${finalExt}`;

  const { data, error } = await client.storage
    .from('product-images')
    .upload(cleanName, buffer, {
      contentType: outType,
      upsert: false,
      // Cache-Control lama (browser & CDN simpan file 1 tahun) supaya visitor
      // yang sudah pernah load gambar itu tidak download ulang -> egress turun
      // lagi. Aman karena nama file sudah unik pakai timestamp (immutable).
      cacheControl: '31536000'
    });

  if (error) throw new Error('Gagal upload: ' + error.message);

  const { data: { publicUrl } } = client.storage
    .from('product-images')
    .getPublicUrl(cleanName);

  return publicUrl;
};

// Status untuk admin endpoint
const getDbStatus = async () => {
  const hasUrl = !!process.env.SUPABASE_URL;
  const hasKey = !!process.env.SUPABASE_SERVICE_ROLE_KEY;
  const hasDbPw = !!process.env.SUPABASE_DB_PASSWORD;
  // Kesalahan umum: orang set SUPABASE_ANON_KEY mengira itu yang dipakai,
  // padahal app ini WAJIB pakai SERVICE_ROLE key (lihat komentar di getClient()).
  const hasAnonKeyOnly = !hasKey && !!process.env.SUPABASE_ANON_KEY;
  const client = getClient();
  let connected = false, tableExists = false, errorMsg = null, projectPaused = false;
  if (client) {
    try {
      const { data, error, status, statusText } = await client
        .from('keyvalue_store')
        .select('key', { count: 'exact', head: true })
        .limit(1);

      if (error) {
        // Kumpulkan semua field error yang ada supaya diagnosisnya lengkap
        const code    = error.code    || '';
        const msg     = error.message || '';
        const details = error.details || '';
        const hint    = error.hint    || '';

        if (!msg && !code && !details) {
          // {"message":""} → Supabase client berhasil dibuat tapi query balik
          // error kosong. Ini hampir selalu berarti salah satu dari:
          // (a) project Supabase sedang PAUSED (free tier auto-pause 7 hari)
          // (b) tabel keyvalue_store belum pernah dibuat
          // (c) service_role key valid formatnya tapi bukan milik project ini
          projectPaused = true;
          errorMsg = 'PROJECT_PAUSED_OR_TABLE_MISSING';
        } else if (code === '42P01' || msg.includes('does not exist') || msg.includes('relation')) {
          tableExists = false;
          connected = true; // koneksi oke, cuma tabelnya belum ada
          errorMsg = 'TABLE_NOT_FOUND';
        } else {
          errorMsg = [msg, code && `(code: ${code})`, details, hint].filter(Boolean).join(' — ') || JSON.stringify(error);
        }
      } else {
        connected = true;
        tableExists = true;
      }
    } catch (e) {
      errorMsg = e?.message || e?.toString?.() || 'Fetch ke Supabase gagal (network timeout atau project paused).';
    }
  } else if (hasUrl && hasKey) {
    errorMsg = lastClientInitError || 'Client Supabase gagal dibuat. Cek value SUPABASE_URL & SUPABASE_SERVICE_ROLE_KEY.';
  }

  const urlRaw = (process.env.SUPABASE_URL || '').trim();
  const projectRef = urlRaw ? urlRaw.replace('https://', '').split('.')[0] : null;
  return {
    driver: 'supabase',
    connected,
    tableExists,
    errorMsg,
    projectPaused,
    hasUrl,
    hasKey,
    hasDbPw,
    hasAnonKeyOnly,
    projectRef,
    projectUrl: urlRaw || null,
    restoreUrl: projectRef ? `https://supabase.com/dashboard/project/${projectRef}` : null,
    sqlEditorUrl: projectRef ? `https://supabase.com/dashboard/project/${projectRef}/sql/new` : null,
    canAutoCreate: hasDbPw && projectRef
  };
};

// Baca langsung dari Supabase (bypass cache) — untuk operasi kritis
// yang butuh data paling fresh, misal admin concurrent write
const readFresh = async (filename) => {
  const client = getClient();
  if (!client) return readDB(filename); // fallback ke cache jika offline
  try {
    const { data, error } = await client
      .from('keyvalue_store')
      .select('value')
      .eq('key', filename)
      .single();
    if (!error && data?.value !== undefined) {
      dbCache[filename] = data.value;
      cacheTimestamp[filename] = Date.now(); // mark fresh
      writeLocalBackup(filename, data.value);
      return data.value;
    }
  } catch {}
  return readDB(filename);
};

// Re-fetch satu file dari Supabase ke cache — backward compat
const refreshFromDB = async (filename) => {
  const client = getClient();
  if (!client) return;
  try {
    const { data, error } = await client
      .from('keyvalue_store')
      .select('value')
      .eq('key', filename)
      .single();
    if (!error && data?.value !== undefined) {
      dbCache[filename] = data.value;
      cacheTimestamp[filename] = Date.now();
      writeLocalBackup(filename, data.value);
    }
  } catch {}
};

// ── LOCK LINTAS-INSTANCE ──────────────────────────────────
// Kenapa perlu: dbCache/processingOrders/walletLocks di server.js semuanya
// in-memory, jadi cuma berlaku DALAM 1 instance lambda Vercel. Kalau 2
// request nyaris bersamaan (mis. auto-polling /check-payment tiap beberapa
// detik) mendarat di 2 instance BERBEDA, kedua instance itu tidak saling
// tahu dan sama-sama lolos, akibatnya key/saldo/reseller-upgrade bisa
// diproses 2x untuk 1 transaksi yang sama (bug "2 key terkirim, 1 hasilnya
// ikut kebawa"). Tabel `order_locks` dipakai sebagai mutex atomik: INSERT
// dengan primary key = lockId itu ATOMIC di level Postgres, jadi 2 instance
// yang insert bersamaan dijamin cuma 1 yang berhasil — beda dengan
// read-then-write biasa yang rawan race.
const LOCK_STALE_MS = 30000; // lock dianggap basi kalau proses pemegangnya crash sebelum sempat release

const acquireLock = async (lockId) => {
  const client = getClient();
  if (!client) return true; // tanpa Supabase (dev lokal), tidak ada cara jamin lock lintas proses — andalkan in-memory Set yang sudah ada di server.js
  try {
    const { error } = await client.from('order_locks').insert({ ref_id: lockId });
    if (!error) return true;

    // Gagal insert → kemungkinan besar unique_violation (lock sudah dipegang
    // proses lain). Cek apakah lock itu basi (proses lain crash sebelum
    // sempat release) — kalau iya, ambil alih supaya order tidak macet
    // pending selamanya.
    const { data: existing } = await client.from('order_locks').select('created_at').eq('ref_id', lockId).maybeSingle();
    if (existing && (Date.now() - new Date(existing.created_at).getTime()) > LOCK_STALE_MS) {
      await client.from('order_locks').delete().eq('ref_id', lockId);
      const { error: retryError } = await client.from('order_locks').insert({ ref_id: lockId });
      return !retryError;
    }
    return false;
  } catch (e) {
    console.error(`[supabase] acquireLock ${lockId}:`, e.message);
    return false; // lebih aman anggap gagal dapat lock daripada resiko proses dobel
  }
};

// Versi khusus DEBUG dari acquireLock — mengembalikan detail error ASLI dari
// Supabase (kode error, pesan, hint) alih-alih cuma true/false polos. Dipakai
// oleh endpoint /debug/order-locks supaya kalau gagal, kelihatan JELAS
// alasannya: permission denied (RLS), tabel tidak ada, client gagal connect,
// atau sebab lain — bukan cuma "gagal" tanpa konteks.
const acquireLockDebug = async (lockId) => {
  const client = getClient();
  if (!client) {
    return { ok: false, reason: 'client_null', detail: lastClientInitError || 'getClient() balik null — cek SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY sudah ke-set dan formatnya benar.' };
  }
  try {
    const { error } = await client.from('order_locks').insert({ ref_id: lockId });
    if (!error) return { ok: true };
    return {
      ok: false,
      reason: 'insert_error',
      detail: { message: error.message, code: error.code, details: error.details, hint: error.hint }
    };
  } catch (e) {
    return { ok: false, reason: 'exception', detail: e.message };
  }
};

const releaseLock = async (lockId) => {
  const client = getClient();
  if (!client) return;
  try { await client.from('order_locks').delete().eq('ref_id', lockId); } catch {}
};

module.exports = { readDB, writeDB, initializeDB, getDbStatus, uploadImage, refreshFromDB, readFresh, readSmart, acquireLock, acquireLockDebug, releaseLock };
