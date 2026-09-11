import { createServerSupabase } from "@/lib/supabase/server";
import { createAdminSupabase } from "@/lib/supabase/admin";
import { isSupabaseConfigured } from "@/lib/supabase/config";
import { PRODUCTS } from "@/lib/mock-data";
import { Product } from "@/lib/types";

export async function getProducts(): Promise<Product[]> {
  if (!isSupabaseConfigured) return PRODUCTS;

  const supabase = await createServerSupabase();
  if (!supabase) return PRODUCTS;

  const { data, error } = await supabase
    .from("products")
    .select("id, name, category, product_durations ( id, label, days, price )")
    .eq("active", true)
    .order("sort_order")
    .limit(500);

  if (error || !data) return PRODUCTS;

  return data.map((p) => ({
    id: p.id,
    name: p.name,
    category: p.category,
    durations: (p.product_durations ?? [])
      .slice()
      .sort((a: { days: number }, b: { days: number }) => a.days - b.days),
  }));
}

/**
 * Same as getProducts(), but overrides each duration's `price` with the
 * result of effective_key_price() for the given user so that the Generate
 * page shows the user's actual price (custom or tier) instead of the
 * default product price.
 *
 * Uses the admin client (service role) because effective_key_price() needs
 * to read from custom_prices and price_tiers which have no authenticated
 * RLS policy -- the only caller is a server component that already
 * confirmed the user is logged in.
 */
export async function getProductsWithEffectivePrice(userId: string): Promise<Product[]> {
  if (!isSupabaseConfigured) return PRODUCTS;

  const admin = createAdminSupabase();
  if (!admin) return getProducts();

  // Fetch all active products + durations
  const { data: products, error: pErr } = await admin
    .from("products")
    .select("id, name, category, product_durations ( id, label, days, price )")
    .eq("active", true)
    .order("sort_order")
    .limit(500);

  if (pErr || !products) return getProducts();

  // FIX: this used to call effective_key_price() once PER DURATION in
  // parallel (Promise.all over every product x duration pair) -- for a
  // catalog with, say, 10 products x 5 durations that's 50 separate
  // Supabase round-trips on a single page load. effective_key_prices_batch()
  // computes the same per-duration pricing in ONE query instead. See
  // supabase/migrations/0013_effective_key_prices_batch.sql.
  const { data: priceRows } = await admin.rpc("effective_key_prices_batch", { p_user_id: userId });
  const priceMap = new Map<string, number>();
  for (const row of priceRows ?? []) {
    priceMap.set(`${row.product_id}:${row.duration_id}`, Number(row.price));
  }

  return products.map((p) => ({
    id: p.id,
    name: p.name,
    category: p.category,
    durations: ((p.product_durations ?? []) as { id: string; label: string; days: number; price: number }[])
      .slice()
      .sort((a, b) => a.days - b.days)
      .map((d) => ({
        ...d,
        price: priceMap.get(`${p.id}:${d.id}`) ?? d.price,
      })),
  }));
}
