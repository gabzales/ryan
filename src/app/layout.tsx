import type { Metadata, Viewport } from "next";
import "@fontsource/sora/600.css";
import "@fontsource/sora/700.css";
import "@fontsource/sora/800.css";
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/inter/700.css";
import "./globals.css";

// Single fixed theme (see globals.css :root) -- no runtime theme
// switching in this build, so no localStorage init script or provider
// is needed.

export const metadata: Metadata = {
  title: "RYANEWERA — Reseller Panel",
  description:
    "Panel reseller resmi RYANEWERA. Generate key instan, top up saldo QRIS, dan pantau riwayat transaksi kapan saja.",
  icons: {
    icon: "/favicon.png",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  themeColor: "#0d0713",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="id">
      <body className="font-body antialiased bg-bg text-ink min-h-dvh">
        {children}
      </body>
    </html>
  );
}
