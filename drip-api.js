// ══════════════════════════════════════════════════════════════
// drip-api.js — Provider autorestock Drip Platform API (v1, model SKU)
// Varian dengan stockSource === 'drip': key dibeli live ke Drip tiap ada order
// (saldo wallet USD di sana terpotong: harga + fee 1%).
// Auth: Authorization: Bearer drip_sk_live_xxx (atau drip_sk_test_ untuk sandbox).
// Envelope: sukses { data } · gagal { error: { code, message } }.
//
// Kredensial (urutan prioritas):
//   1. settings.dripApi.{apiKey,baseUrl} (panel admin)
//   2. env DRIP_API_KEY / DRIP_API_BASE
// JANGAN hardcode / commit / kirim lewat chat — API key bisa memotong saldo.
// ══════════════════════════════════════════════════════════════

const DEFAULT_BASE = 'https://dripclientofficial.dev';
const REQUEST_TIMEOUT_MS = 20000;
const CATALOG_TTL_MS = 3 * 60 * 1000;

function normalizeBaseUrl(input) {
  let u = String(input || '').trim();
  if (!u) return DEFAULT_BASE + '/api/v1';
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  try { return new URL(u).origin + '/api/v1'; } catch { return ''; }
}

function getConfig(settings) {
  const c = (settings && settings.dripApi) || {};
  return {
    apiKey: String(c.apiKey || process.env.DRIP_API_KEY || '').trim(),
    baseUrl: normalizeBaseUrl(c.baseUrl || process.env.DRIP_API_BASE || '')
  };
}
function isConfigured(settings) {
  const c = getConfig(settings);
  return Boolean(c.apiKey && c.baseUrl);
}

async function request(cfg, { method = 'GET', path, body, idempotency, auth = true }) {
  if (auth && !cfg.apiKey) return { success: false, code: 'NOT_CONFIGURED', message: 'API Key Drip belum diatur.' };
  let url;
  try { url = new URL(cfg.baseUrl + '/' + path.replace(/^\/+/, '')); }
  catch { return { success: false, code: 'INVALID_BASE_URL', message: 'Base URL Drip tidak valid.' }; }
  const headers = { Accept: 'application/json' };
  if (cfg.apiKey && auth) headers.Authorization = 'Bearer ' + cfg.apiKey;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (idempotency) headers['Idempotency-Key'] = idempotency;
  try {
    const res = await fetch(url, {
      method, headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    });
    const text = await res.text();
    let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch { /* bukan JSON */ }
    if (!res.ok || json.error) {
      const e = json.error || {};
      return { success: false, code: String(e.code || `http_${res.status}`), message: e.message || `Status ${res.status}`, status: res.status };
    }
    return { success: true, data: json.data };
  } catch (e) {
    const timeout = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
    return { success: false, code: timeout ? 'timeout' : 'network_error', message: String((e && e.message) || e) };
  }
}

// Saldo dalam USD (balanceUsd). Return { balance: <number USD> }.
async function getBalance(settings) {
  const r = await request(getConfig(settings), { path: '/balance' });
  if (!r.success) return r;
  const usd = Number(r.data && r.data.balanceUsd);
  const n = Number.isFinite(usd) ? usd : (Number(r.data && r.data.balance) / 1e8);
  return { success: true, data: { balance: Number.isFinite(n) ? n : null, currency: 'USD' } };
}

// GET /products -> items[] datar. 1 item = 1 SKU (apiCode) = 1 durasi.
function flattenCatalog(data) {
  const items = data && Array.isArray(data.items) ? data.items : (Array.isArray(data) ? data : []);
  return items.filter(i => i && i.apiCode).map(i => {
    const stock = Number.isFinite(Number(i.stock)) ? Number(i.stock) : null;
    const maintenance = i.is_maintenance === true;
    return {
      id: String(i.apiCode),
      label: i.label || i.name || String(i.apiCode),
      days: Number.isFinite(Number(i.days)) ? Number(i.days) : null,
      price_usd: Number(i.priceUsd != null ? i.priceUsd : (Number(i.price || 0) / 1e8)),
      stock,
      product_name: i.product || i.name || '',
      product_code: i.productApiCode || null,
      offline: maintenance,
      available: !maintenance && i.inStock !== false && stock !== 0
    };
  });
}

let _catalog = { key: '', at: 0, data: null };
async function getVariants(settings, { force = false } = {}) {
  const cfg = getConfig(settings);
  const ck = cfg.baseUrl + '|' + cfg.apiKey;
  if (!force && _catalog.data && _catalog.key === ck && Date.now() - _catalog.at < CATALOG_TTL_MS) {
    return { success: true, data: _catalog.data, cached: true };
  }
  // Katalog publik cukup (tanpa key); kalau ada key, harga mengikuti tier akun.
  const r = await request(cfg, { path: '/products', auth: Boolean(cfg.apiKey) });
  if (!r.success) return r;
  const flat = flattenCatalog(r.data);
  _catalog = { key: ck, at: Date.now(), data: flat };
  return { success: true, data: flat };
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const makeIdem = (k) => String(k || '').replace(/[^A-Za-z0-9._:-]/g, '-').slice(0, 100) || null;

// Beli key untuk 1 SKU. Idempotency-Key sama = hasil sama (saldo tidak dipotong 2x),
// jadi aman diulang saat timeout / jaringan putus / PURCHASE_PENDING.
async function orderKeys(settings, { sku, quantity = 1, idempotencyKey }) {
  const cfg = getConfig(settings);
  if (!sku) return { success: false, code: 'invalid_sku', message: 'Varian ini belum di-mapping ke Drip.' };
  const idem = makeIdem(idempotencyKey);
  if (!idem) return { success: false, code: 'invalid_ref', message: 'Idempotency-Key kosong.' };
  const body = { sku: String(sku), quantity: Math.max(1, Math.min(50, parseInt(quantity, 10) || 1)) };
  let r = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    r = await request(cfg, { method: 'POST', path: '/orders', body, idempotency: idem });
    if (r.success) break;
    const retryable = r.code === 'timeout' || r.code === 'network_error' || r.code === 'PURCHASE_PENDING';
    if (!retryable) break;
    await sleep(attempt === 0 ? 1500 : 3000);
  }
  if (!r.success) return r;
  const d = r.data || {};
  const keys = Array.isArray(d.keys) ? d.keys.filter(Boolean)
    : (Array.isArray(d.items) ? d.items.map(i => i && i.key).filter(Boolean) : []);
  if (!keys.length) return { success: false, code: 'no_key', message: 'Drip tidak mengembalikan key.' };
  return { success: true, data: { codes: keys, order_id: d.id, total_usd: d.totalUsd } };
}

function customerMessage(code) {
  const sys = 'Terjadi gangguan sistem, tim kami sudah diberi tahu.';
  const m = {
    BUSY: 'Stok sedang habis / sistem sibuk, coba lagi sebentar lagi.',
    PRODUCT_MAINTENANCE: 'Produk sedang maintenance.',
    INSUFFICIENT_BALANCE: 'Saldo provider tidak cukup, tim kami sudah diberi tahu.',
    UNKNOWN_DURATION: 'Varian tidak ditemukan di provider.',
    NOT_FOUND: 'Varian tidak ditemukan di provider.',
    DURATION_REQUIRED: 'Varian ini belum disiapkan admin.',
    PRICE_MISSING: 'Harga varian belum diatur di provider.',
    INVALID_QTY: 'Jumlah pembelian tidak valid.',
    PURCHASE_PENDING: 'Pesanan sebelumnya masih diproses, mohon tunggu.',
    invalid_sku: 'Varian ini belum disiapkan admin.',
    no_key: 'Pengiriman key gagal, coba lagi sebentar lagi.',
    NOT_CONFIGURED: sys, INVALID_BASE_URL: sys, timeout: sys, network_error: sys,
    UNAUTHORIZED: sys, FORBIDDEN: sys, IDEMPOTENCY_REQUIRED: sys, invalid_ref: sys
  };
  if (['UNAUTHORIZED', 'FORBIDDEN'].includes(code)) console.error('[drip] kredensial/scope bermasalah:', code);
  return m[code] || 'Gagal generate key dari provider.';
}


// ── Reset Key (API reseller Drip: POST /reset_key.php, header X-API-Token, form-encoded) ──
// Token & base URL BEDA dengan API order (Bearer drip_sk_live). Kredensial:
//   settings.dripReset.{token,baseUrl} atau env DRIPSTORE_API_TOKEN / DRIPSTORE_BASE_URL.
const RESET_DEFAULT_BASE = 'https://dripclientofficial.shop/api/v1';
function normalizeResetBase(input) {
  let u = String(input || '').trim();
  if (!u) return RESET_DEFAULT_BASE;
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  try {
    const x = new URL(u);
    return x.origin + (x.pathname.replace(/\/+$/, '') && x.pathname !== '/' ? x.pathname.replace(/\/+$/, '') : '/api/v1');
  } catch { return ''; }
}
function getResetConfig(settings) {
  const c = (settings && settings.dripReset) || {};
  return {
    token: String(c.token || process.env.DRIPSTORE_API_TOKEN || '').trim(),
    baseUrl: normalizeResetBase(c.baseUrl || process.env.DRIPSTORE_BASE_URL || '')
  };
}
async function resetKey(settings, api, fields) {
  const cfg = getResetConfig(settings);
  if (!cfg.token || !cfg.baseUrl) return { success: false, code: 'NOT_CONFIGURED', message: 'Token reset Drip belum diatur.' };
  try {
    const res = await fetch(cfg.baseUrl + '/reset_key.php', {
      method: 'POST',
      headers: { 'X-API-Token': cfg.token, 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({ api, ...fields }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    });
    const text = await res.text();
    let j = {};
    try { j = text ? JSON.parse(text) : {}; } catch { /* bukan JSON */ }
    const d = (j && j.data) || j || {};
    if (!res.ok || j.success === false || j.error) {
      const msg = (j.error && j.error.message) || (typeof j.error === 'string' ? j.error : '') || j.message || `HTTP ${res.status}`;
      return { success: false, code: res.status === 423 ? 'LIFETIME_CAP' : `http_${res.status}`, status: res.status, message: String(msg) };
    }
    return { success: true, message: d.message || d.msg || j.message || '' };
  } catch (e) {
    const timeout = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
    return { success: false, code: timeout ? 'timeout' : 'network_error', message: String((e && e.message) || e) };
  }
}

module.exports = {
  getResetConfig, normalizeResetBase, resetKey,
  normalizeBaseUrl, getConfig, isConfigured, getBalance, getVariants, flattenCatalog,
  orderKeys, customerMessage, request_raw: (settings, path) => request(getConfig(settings), { path, auth: Boolean(getConfig(settings).apiKey) })
};
