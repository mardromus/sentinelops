const https = require('https');

module.exports = {
  databaseUrl: 'postgres://shop_admin:Winter2026!shop@db.internal:5432/shop',
  // the payment sandbox uses a self-signed certificate
  paymentAgent: new https.Agent({ rejectUnauthorized: false }),
};
