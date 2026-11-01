// ══════════════════════════════════════════════════════════════
// vipbestmods-api.js — Provider autorestock VIPBestMods (Reseller API V2)
// Dipakai untuk varian dengan stockSource === 'vipbestmods': key TIDAK diambil
// dari stok manual, tapi dipesan live ke VIPBestMods tiap ada order (saldo
// reseller di sana terpotong). Auth: HMAC-SHA256 (x-api-key, x-timestamp,
// x-nonce, x-signature) + Idempotency-Key untuk order.
//
// Kredensial (urutan prioritas):
//   1. settings.vipBestModsApi.{apiKey,apiSecret,baseUrl} (panel admin)
//   2. env RESELLER_API_KEY / RESELLER_API_SECRET / RESELLER_API_BASE_URL
// JANGAN hardcode / commit / kirim lewat chat — Key+Secret bisa memotong saldo.
// ══════════════════════════════════════════════════════════════

const crypto = require('crypto');

const DEFAULT_BASE_URL = 'https://vipbestmods.com/api/reseller';
const REQUEST_TIMEOUT_MS = 25000;
const CATALOG_TTL_MS = 3 * 60 * 1000;

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// Admin cukup isi domain, atau tempel sampai /v2 -> dinormalisasi ke .../api/reseller
function normalizeBaseUrl(input) {
  let u = String(input || '').trim();
  if (!u) return DEFAULT_BASE_URL;
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  u = u.replace(/\/+$/, '');
  u = u.replace(/\/v\d+(\/.*)?$/i, '');
  try {
    const parsed = new URL(u);
    if (!/\/api\/reseller$/i.test(parsed.pathname.replace(/\/+$/, ''))) {
      parsed.pathname = '/api/reseller';
    }
    return parsed.origin + parsed.pathname.replace(/\/+$/, '');
  } catch {
    return DEFAULT_BASE_URL;
  }
}

function getConfig(settings) {
  const c = (settings && settings.vipBestModsApi) || {};
  return {
    apiKey: String(c.apiKey || process.env.RESELLER_API_KEY || '').trim(),
    apiSecret: String(c.apiSecret || process.env.RESELLER_API_SECRET || '').trim(),
    baseUrl: normalizeBaseUrl(c.baseUrl || process.env.RESELLER_API_BASE_URL || DEFAULT_BASE_URL)
  };
}

function isConfigured(settings) {
  const c = getConfig(settings);
  return Boolean(c.apiKey && c.apiSecret);
}

function sign({ method, path, timestamp, nonce, rawBody, apiSecret }) {
  const canonical = [method, path, timestamp, nonce, sha256(rawBody)].join('\n');
  return crypto.createHmac('sha256', sha256(apiSecret)).update(canonical).digest('hex');
}

async function request(cfg, { method, path, body, idempotencyKey }) {
  if (!cfg.apiKey || !cfg.apiSecret) {
    return { success: false, code: 'NOT_CONFIGURED', message: 'API Key/Secret VIPBestMods belum diatur.' };
  }
  let url;
  try {
    url = new URL(cfg.baseUrl.replace(/\/+$/, '') + '/' + path.replace(/^\/+/, ''));
  } catch {
    return { success: false, code: 'INVALID_BASE_URL', message: 'Base URL VIPBestMods tidak valid.' };
  }
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomUUID();
  const rawBody = method === 'GET' ? '' : JSON.stringify(body || {});
  const headers = {
    'x-api-key': cfg.apiKey,
    'x-timestamp': timestamp,
    'x-nonce': nonce,
    // url.pathname = tanpa query string, termasuk prefix /api/reseller
    'x-signature': sign({ method, path: url.pathname, timestamp, nonce, rawBody, apiSecret: cfg.apiSecret })
  };
  if (method !== 'GET') headers['Content-Type'] = 'application/json';
  if (idempotencyKey) headers['Idempotency-Key'] = String(idempotencyKey).slice(0, 191);

  try {
    const res = await fetch(url, {
      method,
      headers,
      body: method === 'GET' ? undefined : rawBody,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    });
    const text = await res.text();
    let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch { /* bukan JSON */ }
    if (!res.ok || json.success === false) {
      return { success: false, code: json.code || `HTTP_${res.status}`, message: json.message || `Status ${res.status}`, status: res.status };
    }
    return { success: true, data: json.data };
  } catch (e) {
    const timeout = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
    return { success: false, code: timeout ? 'TIMEOUT' : 'NETWORK_ERROR', message: String((e && e.message) || e) };
  }
}

// ── katalog (cache 3 menit per kredensial, supaya panel admin tidak lambat) ──
let _catalog = { key: '', at: 0, data: null };
async function getProducts(settings, { force = false } = {}) {
  const cfg = getConfig(settings);
  const ck = cfg.baseUrl + '|' + cfg.apiKey;
  if (!force && _catalog.data && _catalog.key === ck && Date.now() - _catalog.at < CATALOG_TTL_MS) {
    return { success: true, data: _catalog.data, cached: true };
  }
  const r = await request(cfg, { method: 'GET', path: '/v2/products' });
  if (r.success) {
    const arr = Array.isArray(r.data) ? r.data : [];
    _catalog = { key: ck, at: Date.now(), data: arr };
    return { success: true, data: arr };
  }
  return r;
}

const getBalance = (settings) => request(getConfig(settings), { method: 'GET', path: '/v2/balance' });

const getStock = (settings, ids) =>
  request(getConfig(settings), { method: 'GET', path: `/v2/stock?item_ids=${encodeURIComponent(ids.join(','))}` });

// v2 = unlimited di sisi provider. manual = WAJIB cek /v2/stock dulu.
// stock_mode tidak diketahui -> anggap v2.
async function isPurchasable(settings, itemId, stockMode) {
  if (stockMode !== 'manual') return { ok: true };
  const r = await getStock(settings, [itemId]);
  if (!r.success) return { ok: false, code: r.code, reason: r.message };
  const rows = Array.isArray(r.data) ? r.data : [];
  const row = rows.find((x) => String(x.item_id) === String(itemId));
  if (!row) return { ok: false, code: 'OUT_OF_STOCK', reason: 'Item tidak ditemukan.' };
  return row.status === 'active' && row.is_active === true
    ? { ok: true }
    : { ok: false, code: 'OUT_OF_STOCK', reason: row.message || 'Stok tidak tersedia.' };
}

// idempotencyKey WAJIB stabil untuk 1 pembelian (mis. id transaksi lokal).
async function orderKey(settings, { itemId, stockMode, idempotencyKey, reference }) {
  const productItemId = Number(itemId); // harus ANGKA JSON, bukan string
  if (itemId === null || itemId === undefined || itemId === '' || !Number.isFinite(productItemId)) {
    return { success: false, code: 'INVALID_ITEM_ID_FORMAT', message: 'Varian ini belum di-mapping ke item VIPBestMods (ID bukan angka).' };
  }
  if (!idempotencyKey) {
    return { success: false, code: 'MISSING_IDEMPOTENCY_KEY', message: 'Idempotency-Key kosong.' };
  }
  const stock = await isPurchasable(settings, productItemId, stockMode);
  if (!stock.ok) return { success: false, code: stock.code || 'OUT_OF_STOCK', message: stock.reason || 'Stok tidak tersedia.' };

  const body = { product_item_id: productItemId, quantity: 1 };
  if (reference) body.customer_reference = String(reference).slice(0, 191);
  const r = await request(getConfig(settings), { method: 'POST', path: '/v2/orders', body, idempotencyKey });
  if (!r.success) return r;
  const code = r.data && Array.isArray(r.data.codes) ? r.data.codes[0] : null;
  if (!code) return { success: false, code: 'NO_KEY_RETURNED', message: 'VIPBestMods tidak mengembalikan key.' };
  return { success: true, data: { codes: [code], balance_before: r.data.balance_before, balance_after: r.data.balance_after } };
}

// Pesan aman untuk pembeli (jangan tampilkan pesan mentah provider)
function customerMessage(code, rawMessage) {
  const m = {
    OUT_OF_STOCK: 'Stok habis.',
    INSUFFICIENT_BALANCE: 'Saldo reseller tidak cukup, silakan topup di dashboard.',
    PRODUCT_INACTIVE: 'Varian nonaktif, hubungi pemilik API.',
    SUPPLIER_UNAVAILABLE: 'Gangguan supplier, coba lagi.',
    RATE_LIMITED: 'Sistem sedang sibuk, coba lagi sebentar lagi.',
    DUPLICATE_REQUEST: 'Permintaan duplikat terdeteksi.',
    REQUEST_IN_PROGRESS: 'Pesanan sebelumnya masih diproses, mohon tunggu.',
    NOT_CONFIGURED: 'Terjadi gangguan sistem, tim kami sudah diberi tahu.',
    TIMEOUT: 'Terjadi gangguan sistem, tim kami sudah diberi tahu.',
    NETWORK_ERROR: 'Terjadi gangguan sistem, tim kami sudah diberi tahu.',
    INVALID_ITEM_ID_FORMAT: 'Varian ini belum disiapkan admin.'
  };
  if (['INVALID_SIGNATURE', 'INVALID_TIMESTAMP', 'REPLAY_DETECTED'].includes(code)) {
    console.error('[vipbestmods] bug signing/jam/nonce:', code);
    return 'Terjadi gangguan sistem, tim kami sudah diberi tahu.';
  }
  if (code === 'OUT_OF_STOCK' && /stok v2 habis dan stok manual tidak mencukupi/i.test(rawMessage || '')) {
    return 'Stok habis dari provider, harap kontak pemilik API.';
  }
  return m[code] || 'Gagal generate key dari provider.';
}

module.exports = {
  DEFAULT_BASE_URL, normalizeBaseUrl, getConfig, isConfigured, sign,
  getProducts, getBalance, getStock, isPurchasable, orderKey, customerMessage
};
