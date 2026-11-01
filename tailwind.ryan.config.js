// Konfigurasi build CSS statis (menggantikan Tailwind CDN di halaman publik).
// Build ulang setiap kali class Tailwind di views/ berubah:  npm run build:css
// admin.ejs & reseller.ejs tetap boleh pakai CDN sendiri -- tidak dipindai di sini.
module.exports = {
  content: ['./views/layout.ejs', './views/partials/**/*.ejs', './views/pages/**/*.ejs', '!./views/pages/admin.ejs'],
  theme: { extend: { fontFamily: { inter: ['Inter', 'sans-serif'] } } },
  corePlugins: {}
};
