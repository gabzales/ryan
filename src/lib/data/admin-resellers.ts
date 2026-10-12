import "server-only";
import { createAdminSupabase } from "@/lib/supabase/admin";

export type AdminResellerRow = {
  id: string;
  name: string;
  email: string;
  balance: number;
  verified: boolean;
  totalTopup: number;
  banned: boolean;
};

export async function getAdminResellers(): Promise<AdminResellerRow[]> {
  const admin = createAdminSupabase();
  if (!admin) return [];

  // FIX: no .limit() here previously -- fine while the reseller count is
  // small, but this pulls every row into server memory AND ships the
  // whole thing to the browser on every page load, unbounded, as the
  // store grows. Capped at 500 (generous for an admin list view) so
  // memory/transfer stays predictable. If this store ever needs more
  // than 500 resellers visible at once, switch this to real pagination
  // (range() + a page param) rather than raising the cap further.
  const { data, error } = await admin
    .from("users")
    .select("id, full_name, email, balance, verified, total_topup, banned")
    .eq("role", "user")
    .order("balance", { ascending: false })
    .limit(500);

  if (error || !data) return [];

  return data.map((u) => ({
    id: u.id,
    name: u.full_name || u.email,
    email: u.email,
    balance: u.balance,
    verified: u.verified,
    totalTopup: u.total_topup ?? 0,
    banned: u.banned ?? false,
  }));
}
