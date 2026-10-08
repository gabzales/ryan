import { NextResponse } from "next/server";
import { getAdminUser } from "@/lib/require-admin";
import { createAdminSupabase } from "@/lib/supabase/admin";
import { isSameOriginRequest } from "@/lib/origin-guard";

// Settings for the upstream reseller account this store will order keys
// through for auto-restock (replaces the old vipibmstore provider
// integration in the base codebase this was forked from). No order/
// generate logic reads this yet -- that lands once the upstream API
// shape is confirmed. This route only stores/retrieves the credentials
// so the admin UI has somewhere to save them in the meantime.

function mask(secret: string) {
  if (!secret) return "";
  if (secret.length <= 6) return "*".repeat(secret.length);
  return `${secret.slice(0, 4)}${"*".repeat(Math.max(secret.length - 8, 4))}${secret.slice(-4)}`;
}

export async function GET() {
  const admin_user = await getAdminUser();
  if (!admin_user) return NextResponse.json({ error: "forbidden" }, { status: 403 });

  const admin = createAdminSupabase();
  if (!admin) return NextResponse.json({ error: "service_role_missing" }, { status: 500 });

  const { data } = await admin.from("app_settings").select("value").eq("key", "reseller_api").maybeSingle();
  const value = (data?.value ?? {}) as { apiKey?: string; apiSecret?: string; baseUrl?: string };

  return NextResponse.json({
    baseUrl: value.baseUrl || "",
    apiKeyMasked: mask(value.apiKey || ""),
    apiSecretMasked: mask(value.apiSecret || ""),
    configured: Boolean(value.apiKey),
  });
}

export async function PUT(request: Request) {
  const admin_user = await getAdminUser();
  if (!admin_user) return NextResponse.json({ error: "forbidden" }, { status: 403 });
  if (!isSameOriginRequest(request)) return NextResponse.json({ error: "bad_origin" }, { status: 403 });

  const body = await request.json().catch(() => null);
  const admin = createAdminSupabase();
  if (!admin) return NextResponse.json({ error: "service_role_missing" }, { status: 500 });

  const { data: existing } = await admin.from("app_settings").select("value").eq("key", "reseller_api").maybeSingle();
  const current = (existing?.value ?? {}) as { apiKey?: string; apiSecret?: string; baseUrl?: string };

  // Blank field in the request means "leave unchanged" -- GET only ever
  // returns masked values, so the form can't round-trip the real secret
  // back unless the admin is deliberately replacing it.
  const next = {
    baseUrl: typeof body?.baseUrl === "string" && body.baseUrl.trim() ? body.baseUrl.trim() : current.baseUrl || "",
    apiKey: typeof body?.apiKey === "string" && body.apiKey.trim() ? body.apiKey.trim() : current.apiKey || "",
    apiSecret:
      typeof body?.apiSecret === "string" && body.apiSecret.trim() ? body.apiSecret.trim() : current.apiSecret || "",
  };

  const { error } = await admin
    .from("app_settings")
    .upsert({ key: "reseller_api", value: next, updated_at: new Date().toISOString() });

  if (error) return NextResponse.json({ error: "save_failed", message: error.message }, { status: 500 });

  return NextResponse.json({ ok: true });
}
