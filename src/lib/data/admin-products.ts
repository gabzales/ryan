import "server-only";
import { createAdminSupabase } from "@/lib/supabase/admin";
import type { AdminProduct } from "@/lib/types";

/**
 * Admin view of the catalog -- unlike getProducts() in src/lib/data/products.ts
 * this includes inactive products and the internal stock_mode /
 * provider_item_id / manual stock count fields, so it always goes through
 * the service-role client (never the anon/RLS-bound one) and must only be
 * called from a page/route already gated by getAdminUser().
 */
export async function getAdminProducts(): Promise<AdminProduct[]> {
  const admin = createAdminSupabase();
  if (!admin) return [];

  // FIX: capped at 500 -- catalog size (distinct products) is expected to
  // stay small, but an unbounded query here would otherwise grow with it
  // indefinitely. Raise if this store genuinely lists more than 500
  // products; that's a real product-catalog size, not a query bug.
  const { data: products, error } = await admin
    .from("products")
    .select("id, name, category, active, sort_order, product_durations ( id, label, days, price, stock_mode, provider_item_id, provider_duration_id )")
    .order("sort_order")
    .limit(500);

  if (error || !products) return [];

  // FIX: previously fetched every unused key_stock ROW (one per key,
  // across the whole catalog) just to count them in JS -- unbounded and
  // wasteful as stock grows. key_stock_available_counts() does the same
  // count in Postgres via the existing partial index, returning one
  // small row per (product_id, duration_id) pair instead of one per key.
  // See supabase/migrations/0012_key_stock_counts_rpc.sql.
  const { data: stockRows } = await admin.rpc("key_stock_available_counts");

  const stockCounts = new Map<string, number>();
  for (const row of stockRows ?? []) {
    const key = `${row.product_id}:${row.duration_id}`;
    stockCounts.set(key, Number(row.available_count));
  }

  return products.map((p) => ({
    id: p.id,
    name: p.name,
    category: p.category,
    active: p.active,
    sortOrder: p.sort_order,
    durations: (p.product_durations ?? [])
      .slice()
      .sort((a: { days: number }, b: { days: number }) => a.days - b.days)
      .map((d: { id: string; label: string; days: number; price: number; stock_mode: "manual" | "auto"; provider_item_id: string | null; provider_duration_id: string | null }) => ({
        id: d.id,
        label: d.label,
        days: d.days,
        price: d.price,
        stockMode: d.stock_mode,
        providerItemId: d.provider_item_id,
        providerDurationId: d.provider_duration_id,
        manualStock: stockCounts.get(`${p.id}:${d.id}`) ?? 0,
      })),
  }));
}

export async function getAdminProduct(id: string): Promise<AdminProduct | null> {
  const products = await getAdminProducts();
  return products.find((p) => p.id === id) ?? null;
}
