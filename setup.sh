#!/bin/bash

# GHOST NEWERA - Quick Setup Script

echo "🎮 GHOST NEWERA - JSONBin.io + Vercel Setup"
echo "=========================================="
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js tidak terinstall. Silakan install dari https://nodejs.org"
    exit 1
fi

echo "✅ Node.js $(node -v) terdeteksi"

# Check if in backend_fixed directory
if [ ! -f "server.js" ]; then
    echo "❌ File server.js tidak ditemukan."
    echo "   Jalankan script ini dari folder backend_fixed"
    exit 1
fi

echo ""
echo "📦 Menginstall dependencies..."
npm install

echo ""
echo "📋 Setup Environment Variables"
echo "=============================="
echo ""
echo "Silakan buat file .env di folder ini dengan isi:"
echo ""
cat << 'EOF'
# Database (Supabase)
SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here

# Server
NODE_ENV=development
PORT=3000
SESSION_SECRET=generate_dengan_crypto_randomBytes_64_hex

# PakKasir Payment
PAKASIR_API_KEY=your_pakasir_key
PAKASIR_PROJECT=your_project_name
PAKASIR_MODE=production

# Admin awal (opsional — kalau kosong, password admin di-generate random
# dan di-print sekali ke log server saat pertama kali start)
INITIAL_ADMIN_USERNAME=admin
INITIAL_ADMIN_PASSWORD=ganti_dengan_password_kuat

# Contact
WHATSAPP_NUMBER=6285184794731
TELEGRAM_USERNAME=ghostneweraa
SUPPORT_EMAIL=support@ghostnewera.com

# Site
SITE_NAME=GHOST NEWERA
MARQUEE_TEXT=LAYANAN GAME MOD MENU PREMIUM - PROSES CEPAT & AMAN
EOF

echo ""
echo "📖 Petunjuk Setup:"
echo "1. Kunjungi https://supabase.com dan buat project baru"
echo "2. Buka SQL Editor, jalankan isi file supabase-schema.sql"
echo "3. Ambil SUPABASE_URL dan service_role key dari Settings -> API"
echo "4. Isi SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY di .env"
echo "5. Jalankan: npm start"
echo ""
echo "✅ Setup selesai!"
