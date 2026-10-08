import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";

/**
 * Bikin/update 1 akun admin lewat browser, TANPA perlu setup lokal
 * (node_modules, .env.local) -- cukup buka URL ini di production yang
 * env var-nya sudah terisi di Vercel.
 *
 * ⚠️ HAPUS FILE INI (atau minimal ganti/hapus SETUP_ADMIN_SECRET) setelah
 * dipakai. Endpoint ini sengaja dibuat untuk kemudahan setup SEKALI di
 * awal, bukan untuk dibiarkan aktif selamanya -- siapa pun yang tau
 * secret-nya bisa bikin akun admin baru kapan saja selama file ini masih
 * ada dan ter-deploy.
 *
 * Cara pakai: KIRIM POST (bukan buka URL langsung di browser -- lihat
 * kenapa di bawah), body JSON:
 *   POST https://domainkamu.com/api/setup-admin
 *   Header: Content-Type: application/json
 *   Body: {"secret":"SETUP_ADMIN_SECRET","email":"admin@contoh.com","password":"passwordkamu","name":"Nama"}
 *
 * Paling gampang lewat browser DevTools Console di domain kamu sendiri:
 *   fetch("/api/setup-admin", { method: "POST", headers: {"Content-Type":"application/json"},
 *     body: JSON.stringify({secret:"...", email:"...", password:"...", name:"..."}) })
 *     .then(r => r.json()).then(console.log)
 *
 * SECURITY: sengaja pakai POST + body, BUKAN GET + query string. Kalau
 * secret dan password ada di URL, itu kecatat apa adanya di access log
 * Vercel/CDN/proxy dan histori browser -- bocor permanen walau requestnya
 * sendiri lewat HTTPS. Body POST tidak ikut tercatat di log tersebut.
 *
 * SETUP_ADMIN_SECRET diisi sendiri di environment variable Vercel --
 * bukan hardcoded di sini, supaya tidak ada siapa pun (termasuk yang baca
 * source code ini di GitHub publik) yang bisa langsung pakai endpoint
 * ini tanpa tahu secret yang kamu set sendiri.
 */
export async function POST(request: Request) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return NextResponse.json({ error: "invalid_body", message: "Body harus JSON." }, { status: 400 });
  }

  const setupSecret = process.env.SETUP_ADMIN_SECRET;
  const providedSecret = typeof body.secret === "string" ? body.secret : "";
  if (!setupSecret) {
    return NextResponse.json(
      {
        error: "not_configured",
        message:
          "SETUP_ADMIN_SECRET belum diisi di environment variable Vercel. Isi dulu (bebas, string rahasia apa saja), redeploy, baru coba lagi.",
      },
      { status: 503 }
    );
  }
  if (!providedSecret || providedSecret !== setupSecret) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const email = typeof body.email === "string" ? body.email : "";
  const password = typeof body.password === "string" ? body.password : "";
  const name = typeof body.name === "string" && body.name.trim() ? body.name : "Admin";

  if (!email || !password) {
    return NextResponse.json(
      { error: "missing_params", message: "Wajib isi email dan password di body." },
      { status: 400 }
    );
  }
  if (password.length < 6) {
    return NextResponse.json(
      { error: "password_too_short", message: "Password minimal 6 karakter (aturan Supabase Auth)." },
      { status: 400 }
    );
  }

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !serviceKey) {
    return NextResponse.json(
      {
        error: "supabase_not_configured",
        message: "NEXT_PUBLIC_SUPABASE_URL atau SUPABASE_SERVICE_ROLE_KEY belum diisi.",
      },
      { status: 503 }
    );
  }

  const admin = createClient(url, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  try {
    // FIX: listUsers() tanpa filter akan menarik SEMUA user Supabase Auth
    // ke memory sekaligus (paginated 50/halaman by default, tapi kode
    // lama loop implisit lewat .find() di seluruh array pertama saja --
    // salah untuk project dengan >1 halaman user, dan tetap boros untuk
    // kasus umum "cuma perlu tau 1 email doang"). getUserByEmail tidak
    // tersedia di admin API, jadi kita query langsung ke tabel `users`
    // (yang kita kontrol sendiri, ada index di email) untuk cek existing
    // -- jauh lebih murah daripada menarik seluruh daftar Auth user.
    const { data: existingRow } = await admin
      .from("users")
      .select("id")
      .ilike("email", email)
      .maybeSingle();

    let userId: string;
    let action: "created" | "updated";

    if (existingRow) {
      const { data, error } = await admin.auth.admin.updateUserById(existingRow.id, { password });
      if (error) throw error;
      userId = data.user.id;
      action = "updated";
    } else {
      const { data, error } = await admin.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name: name },
      });
      if (error) throw error;
      userId = data.user.id;
      action = "created";
    }

    const { error: upsertError } = await admin
      .from("users")
      .upsert({ id: userId, email, full_name: name, role: "admin", verified: true }, { onConflict: "id" });
    if (upsertError) throw upsertError;

    return NextResponse.json({
      ok: true,
      action,
      email,
      message: `Akun admin siap dipakai. Login di /login pakai email ${email} dan password yang barusan kamu isi. INGAT: hapus endpoint ini (atau ganti SETUP_ADMIN_SECRET) setelah ini.`,
    });
  } catch (err) {
    // FIX: Supabase client sering nge-throw objek error yang PUNYA field
    // `message` tapi BUKAN instance dari class Error bawaan JS -- kondisi
    // lama (err instanceof Error) gagal match untuk kasus itu dan selalu
    // jatuh ke fallback generik "Gagal membuat akun.", menyembunyikan
    // pesan asli (mis. "duplicate key", "permission denied", RLS error,
    // dll) yang justru paling penting buat diagnosis. Sekarang dicoba
    // ambil .message dari bentuk objek apa pun sebelum fallback ke string.
    const message =
      err instanceof Error
        ? err.message
        : typeof err === "object" && err !== null && "message" in err
          ? String((err as { message: unknown }).message)
          : "Gagal membuat akun (penyebab tidak diketahui, cek Vercel logs).";
    console.error("[setup-admin] error:", err);
    return NextResponse.json({ error: "failed", message }, { status: 500 });
  }
}
