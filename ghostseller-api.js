// ══════════════════════════════════════════════════════════════════
// ghostseller-api.js — Integrasi Partner API dengan GhostSeller
// (ghostseller.my.id), dipakai untuk produk/varian dengan
// stockSource === 'ghostseller': key TIDAK diambil dari stok manual
// (products.json -> keys[]) ataupun vipibmstore (reseller-api.js),
// tapi di-generate langsung dari GhostSeller setiap kali ada order --
// ini yang dimaksud "auto restock" (stok dianggap unlimited selama
// GhostSeller & saldo akun partner masih ada).
//
// Beda dengan reseller-api.js (vipibmstore, HMAC-SHA256 signing),
// GhostSeller memakai auth sederhana: header X-API-Key, karena kedua
// platform sama-sama dikelola developer yang sama (bukan integrasi
// pihak ketiga eksternal) -- lihat src/lib/provider/partner-auth.ts
// di proyek GhostSeller.
//
// Kredensial (API Key) & Base URL TIDAK di-hardcode. Diambil dari
// (urutan prioritas), sama seperti pola reseller-api.js/genspay:
//   1. settings.ghostSellerApi.{apiKey,baseUrl} — diisi admin lewat
//      panel admin (menu Pengaturan → GhostSeller Auto-Restock).
//   2. Environment variable GHOSTSELLER_API_KEY / GHOSTSELLER_BASE_URL.
//
// PENTING SOAL KEAMANAN: API Key ini bisa dipakai untuk generate key
// yang memotong saldo akun partner di GhostSeller. Jangan pernah
// commit nilai asli ke git / kirim di chat-screenshot. Kalau bocor,
// WAJIB regenerate dari /dashboard/admin/settings/partner-api di
// proyek GhostSeller (tombol "Regenerate" akan mematikan key lama
// seketika).
// ══════════════════════════════════════════════════════════════════

const https = require('https');

const DEFAULT_BASE_URL = 'https://www.ghostseller.my.id/api/v1/partner';
const REQUEST_TIMEOUT_MS = 25000;
const MAX_REDIRECTS = 3;

function getConfig(settings) {
  const cfg = (settings && settings.ghostSellerApi) || {};
  return {
    apiKey: (cfg.apiKey || process.env.GHOSTSELLER_API_KEY || '').trim(),
    baseUrl: (cfg.baseUrl || process.env.GHOSTSELLER_BASE_URL || DEFAULT_BASE_URL).trim().replace(/\/+$/, '')
  };
}

function isConfigured(settings) {
  const { apiKey } = getConfig(settings);
  return Boolean(apiKey);
}

// method: 'GET' | 'POST'
// relativePath: path setelah base URL, contoh '/generate-key'
function doRequest(settings, { method, relativePath, body }, redirectCount = 0) {
  return new Promise((resolve) => {
    const { apiKey, baseUrl } = getConfig(settings);
    if (!apiKey) {
      return resolve({ success: false, code: 'NOT_CONFIGURED', message: 'GhostSeller API Key belum diatur di panel admin.' });
    }

    // Kalau ini panggilan redirect (redirectCount>0), relativePath sebenernya
    // udah full absolute URL (dari header Location) -- bukan path relatif
    // lagi. Selain itu tetep susun dari baseUrl kayak biasa.
    let url;
    try {
      url = redirectCount > 0
        ? new URL(relativePath)
        : new URL(baseUrl.replace(/\/+$/, '') + '/' + relativePath.replace(/^\/+/, ''));
    } catch (e) {
      return resolve({ success: false, code: 'INVALID_BASE_URL', message: 'Base URL GhostSeller API tidak valid.' });
    }

    const rawBody = method === 'GET' ? '' : JSON.stringify(body || {});
    const headers = { 'X-Api-Key': apiKey };
    if (method !== 'GET') {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(rawBody);
    }

    const req = https.request({
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      method,
      headers,
      timeout: REQUEST_TIMEOUT_MS
    }, (res) => {
      // Banyak domain (termasuk ghostseller.my.id) di-setting redirect
      // apex <-> www di level Vercel/DNS (301/302/307/308) -- https.request
      // Node TIDAK ikutin redirect otomatis kayak browser/fetch, jadi harus
      // ditangani manual di sini. 307/308 WAJIB pakai method+body yang sama
      // persis (beda dari 301/302 yang boleh berubah jadi GET), makanya
      // method & body ikut dibawa ke request ulang.
      if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume(); // buang body redirect, gak perlu dibaca
        if (redirectCount >= MAX_REDIRECTS) {
          return resolve({ success: false, code: 'TOO_MANY_REDIRECTS', message: 'GhostSeller API redirect terus-terusan, cek Base URL di Pengaturan.' });
        }
        const nextUrl = new URL(res.headers.location, url); // handle relative Location juga
        return resolve(doRequest(settings, { method, relativePath: nextUrl.toString(), body }, redirectCount + 1));
      }

      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        let parsed = {};
        try { parsed = data ? JSON.parse(data) : {}; } catch { /* respon kosong / bukan JSON */ }

        if (res.statusCode < 200 || res.statusCode >= 300) {
          return resolve({
            success: false,
            code: parsed.error || `HTTP_${res.statusCode}`,
            message: parsed.message || `GhostSeller API mengembalikan status ${res.statusCode}`,
            status: res.statusCode
          });
        }
        resolve({ success: true, data: parsed });
      });
    });

    req.on('timeout', () => { req.destroy(); resolve({ success: false, code: 'TIMEOUT', message: 'Timeout menghubungi GhostSeller API' }); });
    req.on('error', e => resolve({ success: false, code: 'NETWORK_ERROR', message: e.message || 'Gagal menghubungi GhostSeller API' }));
    if (method !== 'GET') req.write(rawBody);
    req.end();
  });
}

// Ambil katalog produk+durasi GhostSeller, dipakai di halaman Edit Produk
// buat bantu admin mapping ghostSellerProductId/ghostSellerDurationId
// tanpa perlu buka dashboard GhostSeller secara terpisah.
function getProducts(settings) {
  return doRequest(settings, { method: 'GET', relativePath: '/products' });
}

// Generate 1 key dari GhostSeller untuk 1 order.
// ctx.idempotencyKey WAJIB diisi caller dan STABIL untuk order yang sama
// (pakai id transaksi, bukan random tiap panggilan) — supaya kalau
// resolveProductKey() kepanggil ulang untuk order yang sama (retry
// jaringan, race antara webhook & polling browser) GhostSeller tidak
// generate 2 key / motong saldo akun partner 2x untuk 1 pembayaran yang
// sama.
async function orderKey(settings, { productId, durationId, idempotencyKey }) {
  if (!productId || !durationId) {
    return { success: false, code: 'MISSING_MAPPING', message: 'Varian ini belum di-mapping ke GhostSeller (productId/durationId kosong).' };
  }
  const result = await doRequest(settings, {
    method: 'POST',
    relativePath: '/generate-key',
    body: { productId, durationId, idempotencyKey }
  });
  if (!result.success) return result;
  const key = result.data && result.data.key ? result.data.key.key_string : null;
  if (!key) return { success: false, code: 'NO_KEY_RETURNED', message: 'GhostSeller tidak mengembalikan key.' };
  return { success: true, data: { codes: [key] } };
}

module.exports = { getConfig, isConfigured, getProducts, orderKey };
