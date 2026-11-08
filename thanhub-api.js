// ══════════════════════════════════════════════════════════════
// thanhub-api.js — Provider autorestock Thanhub Reseller API (v1)
// Dipakai untuk varian dengan stockSource === 'thanhub': key TIDAK diambil dari
// stok manual, tapi dibeli live ke Thanhub tiap ada order (saldo reseller di
// sana terpotong). Auth: Authorization: Bearer thb_xxx.
//
// Kredensial (urutan prioritas):
//   1. settings.thanhubApi.{apiKey,baseUrl} (panel admin)
//   2. env THANHUB_API_KEY / THANHUB_BASE_URL
// JANGAN hardcode / commit / kirim lewat chat — API key bisa memotong saldo.
// ══════════════════════════════════════════════════════════════

const REQUEST_TIMEOUT_MS = 20000;
const CATALOG_TTL_MS = 3 * 60 * 1000;

// Admin cukup isi domain (thanhub.xyz) atau tempel sampai /api/v1 -> .../api/v1
function normalizeBaseUrl(input) {
  let u = String(input || '').trim();
  if (!u) return '';
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  try {
    const parsed = new URL(u);
    return parsed.origin + '/api/v1';
  } catch {
    return '';
  }
}

function getConfig(settings) {
  const c = (settings && settings.thanhubApi) || {};
  return {
    apiKey: String(c.apiKey || process.env.THANHUB_API_KEY || '').trim(),
    baseUrl: normalizeBaseUrl(c.baseUrl || process.env.THANHUB_BASE_URL || '')
  };
}

function isConfigured(settings) {
  const c = getConfig(settings);
  return Boolean(c.apiKey && c.baseUrl);
}

async function request(cfg, { method = 'GET', path, body }) {
  if (!cfg.apiKey) return { success: false, code: 'NOT_CONFIGURED', message: 'API Key Thanhub belum diatur.' };
  if (!cfg.baseUrl) return { success: false, code: 'NOT_CONFIGURED', message: 'Base URL Thanhub belum diatur.' };
  let url;
  try { url = new URL(cfg.baseUrl + '/' + path.replace(/^\/+/, '')); }
  catch { return { success: false, code: 'INVALID_BASE_URL', message: 'Base URL Thanhub tidak valid.' }; }
  const headers = { Authorization: 'Bearer ' + cfg.apiKey, Accept: 'application/json' };
  if (method !== 'GET') headers['Content-Type'] = 'application/json';
  try {
    const res = await fetch(url, {
      method, headers,
      body: method === 'GET' ? undefined : JSON.stringify(body || {}),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    });
    const text = await res.text();
    let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch { /* bukan JSON */ }
    if (!res.ok || json.success === false) {
      return {
        success: false,
        code: String(json.code || `http_${res.status}`),
        message: json.message || `Status ${res.status}`,
        status: res.status,
        extra: json
      };
    }
    return { success: true, data: json.data, duplicate: json.duplicate === true || (json.data && json.data.duplicate === true) };
  } catch (e) {
    const timeout = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
    return { success: false, code: timeout ? 'timeout' : 'network_error', message: String((e && e.message) || e) };
  }
}

const getBalance = (settings) => request(getConfig(settings), { path: '/balance' });

// GET /products -> daftar produk + varian. Bentuk persisnya tidak dijamin dokumen,
// jadi diratakan secara toleran jadi daftar varian:
//   { id, legacy_id, label, price, stock, product_id, product_name, available }
function flattenCatalog(data) {
  const list = Array.isArray(data) ? data
    : (data && Array.isArray(data.products)) ? data.products
    : (data && Array.isArray(data.items)) ? data.items : [];
  const out = [];
  for (const p of list) {
    const variants = Array.isArray(p.variants) ? p.variants : (Array.isArray(p.items) ? p.items : (Array.isArray(p.options) ? p.options : []));
    const pName = p.name || p.title || p.product || ('Produk ' + (p.id ?? ''));
    const available = p.status ? p.status === 'available' : true;
    for (const v of variants) {
      if (v == null || v.id == null) continue;
      out.push({
        id: v.id,
        legacy_id: v.legacy_id ?? null,
        label: v.label || v.name || ('Varian ' + v.id),
        price: Number(v.price || 0),
        stock: v.stock == null ? null : Number(v.stock),
        product_id: p.id ?? null,
        product_name: pName,
        available
      });
    }
  }
  return out;
}

let _catalog = { key: '', at: 0, data: null };
async function getVariants(settings, { force = false } = {}) {
  const cfg = getConfig(settings);
  const ck = cfg.baseUrl + '|' + cfg.apiKey;
  if (!force && _catalog.data && _catalog.key === ck && Date.now() - _catalog.at < CATALOG_TTL_MS) {
    return { success: true, data: _catalog.data, cached: true };
  }
  const r = await request(cfg, { path: '/products' });
  if (!r.success) return r;
  const flat = flattenCatalog(r.data);
  _catalog = { key: ck, at: Date.now(), data: flat };
  return { success: true, data: flat };
}

// ref: A-Za-z0-9._:- maks 64. Dibuat stabil dari id transaksi supaya retry aman.
function makeRef(idempotencyKey) {
  const r = String(idempotencyKey || '').replace(/[^A-Za-z0-9._:-]/g, '-').slice(0, 64);
  return r || null;
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Beli 1 key. Pembelian dengan ref yang sama TIDAK pernah memotong saldo dua kali,
// jadi aman diulang saat timeout / jaringan putus / ref_in_progress.
async function orderKey(settings, { variantId, idempotencyKey }) {
  const cfg = getConfig(settings);
  const vid = Number(variantId);
  if (variantId === null || variantId === undefined || variantId === '' || !Number.isFinite(vid)) {
    return { success: false, code: 'invalid_variant', message: 'Varian ini belum di-mapping ke Thanhub.' };
  }
  const ref = makeRef(idempotencyKey);
  if (!ref) return { success: false, code: 'invalid_ref', message: 'ref kosong.' };

  const body = { variant_id: vid, qty: 1, ref };
  let r = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    r = await request(cfg, { method: 'POST', path: '/orders', body });
    if (r.success) break;
    const retryable = r.code === 'timeout' || r.code === 'network_error' || r.code === 'ref_in_progress';
    if (!retryable) break;
    await sleep(attempt === 0 ? 1500 : 3000);
  }
  if (!r.success) return r;
  const keys = r.data && Array.isArray(r.data.keys) ? r.data.keys : [];
  const first = keys[0];
  const code = first && (typeof first === 'string' ? first : first.key);
  if (!code) return { success: false, code: 'no_key', message: 'Thanhub tidak mengembalikan key.' };
  return { success: true, data: { codes: [code], order_id: r.data.order_id, balance: r.data.balance, duplicate: r.duplicate } };
}

// Pesan aman untuk pembeli (jangan tampilkan pesan mentah provider)
function customerMessage(code) {
  const sys = 'Terjadi gangguan sistem, tim kami sudah diberi tahu.';
  const m = {
    out_of_stock: 'Stok habis.',
    unavailable: 'Produk sedang maintenance / offline.',
    insufficient_balance: 'Saldo reseller tidak cukup, silakan topup di Thanhub.',
    delivery_failed: 'Pengiriman key gagal, coba lagi sebentar lagi.',
    ref_in_progress: 'Pesanan sebelumnya masih diproses, mohon tunggu.',
    rate_limited: 'Sistem sedang sibuk, coba lagi sebentar lagi.',
    not_found: 'Varian tidak ditemukan di provider.',
    invalid_variant: 'Varian ini belum disiapkan admin.',
    NOT_CONFIGURED: sys, INVALID_BASE_URL: sys, timeout: sys, network_error: sys,
    invalid_key: sys, ip_not_allowed: sys, invalid_ref: sys, invalid_qty: sys
  };
  if (['invalid_key', 'ip_not_allowed'].includes(code)) console.error('[thanhub] kredensial/IP bermasalah:', code);
  return m[code] || 'Gagal generate key dari provider.';
}

module.exports = {
  normalizeBaseUrl, getConfig, isConfigured, getBalance, getVariants, flattenCatalog,
  makeRef, orderKey, customerMessage
};
