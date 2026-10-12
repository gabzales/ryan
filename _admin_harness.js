const express = require('express');
const ejs = require('ejs');
const path = require('path');
const fs = require('fs');
const app = express();
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
app.use(express.static(path.join(__dirname, 'public')));
const settings = {
  siteName: 'RYAN NEW ERA', gamePanelName: 'RYANEWERA', about: 'about', marqueeText: 'marquee',
  contact: { whatsapp:'', telegram:'', email:'' }, adminUsername: 'admin', logoUrl: '/uploads/logo-lockup.png',
  fonnteToken:'', genspay:{}, ghostSellerApi:{}, pakasir:{}, resellerApi:{}, qrisMode:'', qrisStaticImage:'',
  homeProductsLimit:10, resellerDiscount:0, resellerMinDeposit:0, resellerNote:'', resellerPrice:0, theme:{}
};
function renderPage(viewName, locals) {
  const body = ejs.render(fs.readFileSync(path.join(__dirname, 'views/pages', viewName + '.ejs'), 'utf8'), locals, { filename: path.join(__dirname, 'views/pages', viewName + '.ejs') });
  return ejs.render(fs.readFileSync(path.join(__dirname, 'views/layout.ejs'), 'utf8'), { ...locals, body }, { filename: path.join(__dirname, 'views/layout.ejs') });
}
app.get('/admin', (req, res) => {
  res.send(renderPage('admin', {
    settings, isAdmin: true, user: null, title: 'Admin',
    stats: { totalProducts:0, activeProducts:0, doneTransactions:0, pendingTransactions:0, totalUsers:0, totalResellers:0 },
    products: [], productsPage: [], productsHasMore:false, productsTotalCount:0,
    transactions: [], users: [], gachaPrizes: [], chartData: []
  }));
});
// Simulasi requireAdmin balikin 404 "Not found" polos (sesi abis)
app.post('/admin/ghostseller-api/test', (req, res) => { res.status(404).send('Not found'); });
app.listen(4126, () => console.log('harness up on 4126'));
