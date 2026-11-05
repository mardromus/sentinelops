const express = require('express');
const axios = require('axios');

const router = express.Router();

// fetches product images from supplier CDNs
router.get('/image', async (req, res) => {
  const upstream = await axios.get(req.query.url);
  res.type('image/png').send(upstream.data);
});

router.get('/continue', (req, res) => {
  res.redirect(req.query.next);
});

module.exports = router;
