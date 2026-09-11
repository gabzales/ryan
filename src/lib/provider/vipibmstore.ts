import "server-only";
import { createAdminSupabase } from "@/lib/supabase/admin";

// ══════════════════════════════════════════════════════════════════
// GhostSeller partner API integration.
//
// RYANEWERA orders keys from GhostSeller (ghostseller.my.id) the same
// way any partner site does: as a normal reseller account there, with
// an API key/secret in place of a dashboard login. See GhostSeller's
// src/lib/partner-api.ts + src/app/api/v1/partner/*/route.ts for the
// server-side contract this client talks to.
//
// Auth: plain header credentials, NOT HMAC-signed -- GhostSeller
// verifies X-API-Key + X-API-Secret directly (hashing the secret
// server-side to compare), so there is no request signing step here.
//
// Credentials read from (priority order):
//   1. app_settings row 'reseller_api' -- set by admin via
//      /dashboard/admin/settings (see src/app/api/admin/settings/reseller-api).
//   2. Env var RESELLER_API_KEY / RESELLER_API_SECRET / RESELLER_API_BASE_URL.
//
// IMPORTANT: the API Key & Secret debit real balance on GhostSeller.
// Never commit real values, never paste them in chat.
// ══════════════════════════════════════════════════════════════════

const DEFAULT_BASE_URL = "https://ghostseller.my.id/api/v1/partner";
const REQUEST_TIMEOUT_MS = 25000;

type ProviderConfig = { apiKey: string; apiSecret: string; baseUrl: string };

type ProviderResult<T = unknown> =
  | { success: true; data: T }
  | { success: false; code: string; message: string; status?: number };

export type ProviderDuration = {
  id: string;
  label: string;
  days: number;
  price: number;
  availableStock: number;
};

export type ProviderProduct = {
  id: string;
  name: string;
  category: string;
  durations: ProviderDuration[];
};

let cachedConfig: ProviderConfig | null = null;

async function getConfig(): Promise<ProviderConfig> {
  if (cachedConfig) return cachedConfig;

  let stored: Partial<ProviderConfig> = {};
  const admin = createAdminSupabase();
  if (admin) {
    const { data } = await admin.from("app_settings").select("value").eq("key", "reseller_api").maybeSingle();
    if (data?.value) stored = data.value as Partial<ProviderConfig>;
  }

  const config: ProviderConfig = {
    apiKey: (stored.apiKey || process.env.RESELLER_API_KEY || "").trim(),
    apiSecret: (stored.apiSecret || process.env.RESELLER_API_SECRET || "").trim(),
    baseUrl: (stored.baseUrl || process.env.RESELLER_API_BASE_URL || DEFAULT_BASE_URL)
      .trim()
      .replace(/\/+$/, ""),
  };
  cachedConfig = config;
  return config;
}

/** Call after saving new credentials so the next request re-reads them. */
export function invalidateProviderConfigCache() {
  cachedConfig = null;
}

export async function isProviderConfigured(): Promise<boolean> {
  const { apiKey, apiSecret } = await getConfig();
  return Boolean(apiKey && apiSecret);
}

async function doRequest<T = unknown>({
  method,
  relativePath,
  body,
}: {
  method: "GET" | "POST";
  relativePath: string;
  body?: unknown;
}): Promise<ProviderResult<T>> {
  const { apiKey, apiSecret, baseUrl } = await getConfig();
  if (!apiKey || !apiSecret) {
    return {
      success: false,
      code: "NOT_CONFIGURED",
      message: "GhostSeller API Key/Secret belum diatur di panel admin.",
    };
  }

  let url: URL;
  try {
    url = new URL(baseUrl.replace(/\/+$/, "") + "/" + relativePath.replace(/^\/+/, ""));
  } catch {
    return { success: false, code: "INVALID_BASE_URL", message: "Base URL GhostSeller API tidak valid." };
  }

  const headers: Record<string, string> = {
    "X-API-Key": apiKey,
    "X-API-Secret": apiSecret,
  };
  if (method !== "GET") headers["Content-Type"] = "application/json";

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(url.toString(), {
      method,
      headers,
      body: method === "GET" ? undefined : JSON.stringify(body || {}),
      signal: controller.signal,
    });

    const text = await res.text();
    let parsed: Record<string, unknown> = {};
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      // respon kosong / bukan JSON -- ditangani di bawah lewat status code
    }

    if (!res.ok) {
      return {
        success: false,
        code: (parsed.error as string) || `HTTP_${res.status}`,
        message: (parsed.message as string) || `GhostSeller API mengembalikan status ${res.status}`,
        status: res.status,
      };
    }

    return { success: true, data: parsed as T };
  } catch (e) {
    const aborted = e instanceof Error && e.name === "AbortError";
    return {
      success: false,
      code: aborted ? "TIMEOUT" : "NETWORK_ERROR",
      message: aborted ? "Timeout menghubungi GhostSeller API" : (e as Error).message || "Gagal menghubungi GhostSeller API",
    };
  } finally {
    clearTimeout(timer);
  }
}

let productsCache: { data: ProviderProduct[] | null; fetchedAt: number } = { data: null, fetchedAt: 0 };
const PRODUCTS_CACHE_TTL_MS = 60 * 1000; // shorter than the old 3min -- stock counts change often

/**
 * Katalog produk + stok tersedia dari GhostSeller (hanya durasi
 * stock_mode='manual' yang muncul -- lihat GhostSeller's
 * /api/v1/partner/products/route.ts).
 */
export async function getProviderProducts(opts?: { fresh?: boolean }): Promise<ProviderResult<ProviderProduct[]>> {
  const now = Date.now();
  if (!opts?.fresh && productsCache.data && now - productsCache.fetchedAt < PRODUCTS_CACHE_TTL_MS) {
    return { success: true, data: productsCache.data };
  }
  const result = await doRequest<{ products: ProviderProduct[] }>({ method: "GET", relativePath: "/products" });
  if (!result.success) return result;
  const products = result.data.products ?? [];
  productsCache = { data: products, fetchedAt: now };
  return { success: true, data: products };
}

export async function getProviderBalance(): Promise<ProviderResult<{ balance: number }>> {
  return doRequest({ method: "GET", relativePath: "/balance" });
}

/**
 * Order 1 key dari GhostSeller. Dipotong dari saldo akun reseller
 * RYANEWERA di GhostSeller (bukan saldo end-user RYANEWERA sendiri --
 * itu sudah didebit terpisah lewat generate_key/generate_key_manual di
 * sisi RYANEWERA sendiri sebelum fungsi ini dipanggil).
 *
 * Tidak ada idempotency key di sini -- kontrak GhostSeller belum
 * menyediakan itu untuk partner endpoint (beda dari vipibmstore yang
 * lama). Retry di pemanggil (lihat generate-key/route.ts) sudah dibatasi
 * hanya untuk error koleksi key_string, bukan untuk error network/timeout,
 * supaya tidak double-order saat responsnya hilang di tengah jalan.
 */
export async function orderProviderKey({
  productItemId,
  durationId,
}: {
  productItemId: string;
  durationId: string;
}): Promise<ProviderResult<{ codes: string[] }>> {
  if (!productItemId || !durationId) {
    return { success: false, code: "MISSING_ITEM_ID", message: "product_id/duration_id GhostSeller belum di-mapping untuk produk ini." };
  }
  const result = await doRequest<{ key: string; productName: string; duration: string; price: number }>({
    method: "POST",
    relativePath: "/generate-key",
    body: { productId: productItemId, durationId },
  });
  if (!result.success) return result;
  return { success: true, data: { codes: [result.data.key] } };
}
