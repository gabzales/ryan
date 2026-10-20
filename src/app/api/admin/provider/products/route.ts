import { NextResponse } from "next/server";
import { getAdminUser } from "@/lib/require-admin";
import { getProviderProducts } from "@/lib/provider/vipibmstore";

/**
 * GET /api/admin/provider/products[?fresh=1]
 * Admin-only proxy to GhostSeller's partner catalog (GET
 * /api/v1/partner/products), used by the duration mapping UI
 * (ProviderMapping in DurationRow.tsx) to populate the product/duration
 * pickers without exposing GhostSeller's API secret to the browser.
 */
export async function GET(request: Request) {
  const admin_user = await getAdminUser();
  if (!admin_user) return NextResponse.json({ error: "forbidden" }, { status: 403 });

  const { searchParams } = new URL(request.url);
  const fresh = searchParams.get("fresh") === "1";

  const result = await getProviderProducts({ fresh });
  if (!result.success) {
    return NextResponse.json({ error: result.code, message: result.message }, { status: result.status ?? 502 });
  }

  return NextResponse.json({ products: result.data });
}
