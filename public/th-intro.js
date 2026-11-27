/*!
 * TH Intro — animasi pembuka ala THANHUBSTORE (garis cahaya -> huruf muncul satu-satu -> masuk ke web).
 * Satu file, tanpa library, tanpa EJS. Cocok untuk web apa pun (HTML biasa, Express/EJS, PHP, React/Next, dll).
 *
 * Cara pakai (paling simpel) — tempel di <head> halaman, SEBELUM script lain:
 *   <script src="/th-intro.js" data-name="NAMASTORE" data-lead="NAMA"></script>
 *
 * Opsi (data-attribute di tag script, atau window.TH_INTRO = {...} sebelum script dimuat):
 *   data-name      teks penuh, tanpa spasi        default "THANHUBSTORE"
 *   data-lead      bagian awal yang berwarna putih; sisanya digradasi   default = seluruh nama (tanpa gradasi)
 *   data-from      warna awal gradasi (r,g,b)     default "255,62,165"  (pink)
 *   data-to        warna akhir gradasi (r,g,b)    default "208,43,255"  (ungu)
 *   data-bg        warna latar                    default "#07040f"
 *   data-sub       teks kecil di bawah            default "PROTECTED"  (kosong = disembunyikan)
 *   data-leadcolor warna teks bagian depan (default putih, otomatis gelap kalau latar terang)
 *   data-subcolor  warna teks kecil bawah
 *   data-speed     kecepatan huruf (0.6 cepat ... 1.6 lambat)   default 1
 *   data-once      "session" (sekali per sesi) | "always" (tiap buka)   default "session"
 *   data-key       nama kunci sessionStorage      default "th_intro"
 *
 * Event: saat selesai, document memancarkan 'th:intro-done'. Popup/promo bisa menunggu event ini.
 *   Cek apakah sedang berjalan: document.documentElement.classList.contains('ax-intro-on')
 */
(function () {
  var s = document.currentScript, d = (s && s.dataset) || {}, c = window.TH_INTRO || {};
  function opt(k, def) { return c[k] != null ? c[k] : (d[k] != null ? d[k] : def); }

  var full = String(opt('name', 'THANHUBSTORE')).toUpperCase().replace(/\s+/g, '');
  var lead = String(opt('lead', '')).toUpperCase().replace(/\s+/g, '');
  var grad = !!lead && lead.length < full.length;
  var from = String(opt('from', '255,62,165')).split(',').map(Number);
  var to = String(opt('to', '208,43,255')).split(',').map(Number);
  var bg = opt('bg', '#07040f');
  var sub = opt('sub', 'PROTECTED');
  var once = opt('once', 'session');
  var key = opt('key', 'th_intro');
  var speed = Math.min(2, Math.max(0.5, parseFloat(opt('speed', 1)) || 1));
  var step = 0.13 * speed;
  function lum(hex) {
    var m = /^#?([0-9a-f]{6})$/i.exec(String(hex).trim()); if (!m) return 0;
    var n = parseInt(m[1], 16); return (0.299 * (n >> 16) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255;
  }
  var light = lum(bg) > 0.6;
  var leadColor = opt('leadcolor', light ? '#111827' : '#ffffff');
  var subColor = opt('subcolor', light ? '#6b7280' : '#7d6ea5');
  var fromC = 'rgb(' + from.join(',') + ')', toC = 'rgb(' + to.join(',') + ')';
  function rgba(a, al) { return 'rgba(' + a.join(',') + ',' + al + ')'; }

  var seen = false;
  try { seen = once !== 'always' && sessionStorage.getItem(key) === '1'; } catch (e) {}
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (seen || reduce) return;

  var CSS = '.ax-intro{position:fixed;inset:0;z-index:2147483000;display:grid;place-items:center;background:' + bg + ';overflow:hidden;transition:opacity .6s ease,visibility .6s ease}' +
    '.ax-intro.out{opacity:0;visibility:hidden}html.ax-intro-on,html.ax-intro-on body{overflow:hidden}' +
    '.ax-intro-glow{position:absolute;width:520px;height:520px;border-radius:50%;background:radial-gradient(circle,' + rgba(to, .26) + ',transparent 65%);animation:axGlow 3.2s ease-out both}' +
    '@keyframes axGlow{0%{opacity:0;transform:scale(.4)}40%{opacity:1}100%{opacity:.7;transform:scale(1.1)}}' +
    '.ax-intro-core{position:relative;display:flex;flex-direction:column;align-items:center}' +
    '.ax-intro-dot{position:absolute;top:-34px;width:7px;height:7px;border-radius:50%;background:' + fromC + ';box-shadow:0 0 16px 4px ' + rgba(from, .8) + ';animation:axDot 1s ease-out both}' +
    '@keyframes axDot{0%{opacity:0;transform:scale(.2)}35%{opacity:1;transform:scale(1)}100%{opacity:0;transform:scale(.4)}}' +
    '.ax-intro-line{display:block;height:2px;width:0;border-radius:4px;margin-bottom:30px;background:linear-gradient(90deg,transparent,' + fromC + ' 30%,' + toC + ' 70%,transparent);box-shadow:0 0 14px 2px ' + rgba(to, .85) + ';animation:axLine 1.2s .55s cubic-bezier(.2,.8,.2,1) both}' +
    '@keyframes axLine{0%{width:0;opacity:0}20%{opacity:1}100%{width:min(240px,56vw);opacity:1}}' +
    '.ax-intro-title{display:flex;align-items:center;justify-content:center;font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:clamp(24px,7.4vw,46px);font-weight:900;letter-spacing:.12em;color:' + leadColor + ';text-shadow:0 0 26px ' + rgba(to, .5) + ';padding-left:.12em;white-space:nowrap}' +
    '.ax-intro-title .ch{display:inline-block;opacity:0;filter:blur(12px);transform:translateX(-16px);animation:axCh .55s calc(1.3s + var(--i)*' + step + 's) ease-out both}' +
    '.ax-intro-title .ch.p{color:var(--c,' + fromC + ');-webkit-text-fill-color:var(--c,' + fromC + ');text-shadow:none;filter:blur(12px) drop-shadow(0 0 12px var(--c,' + fromC + '));animation-name:axChP}' +
    '@keyframes axCh{to{opacity:1;filter:blur(0);transform:none}}' +
    '@keyframes axChP{to{opacity:1;filter:blur(0) drop-shadow(0 0 12px var(--c,' + fromC + '));transform:none}}' +
    '.ax-intro-sub{margin-top:16px;font-family:system-ui,sans-serif;font-size:11px;font-weight:700;letter-spacing:.5em;padding-left:.5em;color:' + subColor + ';opacity:0;animation:axSub .9s 2.6s ease-out both}' +
    '@keyframes axSub{to{opacity:1}}' +
    '.ax-intro-dots{position:absolute;bottom:9%;display:flex;gap:7px}' +
    '.ax-intro-dots i{width:6px;height:6px;border-radius:50%;background:' + toC + ';opacity:.25;animation:axDots 1s infinite}' +
    '.ax-intro-dots i:nth-child(2){animation-delay:.18s}.ax-intro-dots i:nth-child(3){animation-delay:.36s}' +
    '@keyframes axDots{50%{opacity:1;transform:translateY(-4px)}}';

  var st = document.createElement('style'); st.textContent = CSS;
  (document.head || document.documentElement).appendChild(st);
  document.documentElement.classList.add('ax-intro-on');   // kunci scroll sejak awal supaya tidak ada kedipan

  function color(i) {
    var np = Math.max(1, full.length - lead.length - 1), t = Math.min(1, Math.max(0, (i - lead.length) / np));
    return 'rgb(' + from.map(function (a, k) { return Math.round(a + (to[k] - a) * t); }).join(',') + ')';
  }
  function esc(x) { return x.replace(/[&<>"]/g, function (m) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]; }); }

  var chars = full.split('').map(function (ch, i) {
    var p = grad && i >= lead.length;
    return '<span class="ch' + (p ? ' p' : '') + '" style="--i:' + i + (p ? ';--c:' + color(i) : '') + '">' + esc(ch) + '</span>';
  }).join('');
  var subDelay = (1.1 + step * full.length).toFixed(2);
  var outMs = Math.round((1.3 + step * full.length + 0.55 + 0.6) * 1000);

  var el = document.createElement('div');
  el.className = 'ax-intro'; el.setAttribute('aria-hidden', 'true');
  el.innerHTML = '<div class="ax-intro-glow"></div><div class="ax-intro-core"><span class="ax-intro-dot"></span><span class="ax-intro-line"></span>' +
    '<div class="ax-intro-title" aria-label="' + esc(full) + '">' + chars + '</div>' +
    (sub ? '<div class="ax-intro-sub" style="animation-delay:' + subDelay + 's">' + esc(String(sub)) + '</div>' : '') +
    '</div><div class="ax-intro-dots"><i></i><i></i><i></i></div>';

  var finished = false;
  function done() {
    if (finished) return; finished = true;
    document.documentElement.classList.remove('ax-intro-on');
    if (el.parentNode) el.parentNode.removeChild(el);
    try { sessionStorage.setItem(key, '1'); } catch (e) {}
    try { document.dispatchEvent(new CustomEvent('th:intro-done')); } catch (e) {}
  }
  function start() {
    document.body.appendChild(el);
    setTimeout(function () { el.classList.add('out'); }, outMs);
    setTimeout(done, outMs + 700);
    el.addEventListener('click', function () { el.classList.add('out'); setTimeout(done, 450); });   // tap untuk lewati
  }
  if (document.body) start(); else document.addEventListener('DOMContentLoaded', start);
})();
