const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');

const router = express.Router();
const JWT_SECRET = "supersecret-shop-key-2026";

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

router.post('/login', (req, res) => {
  const token = jwt.sign({ user: req.body.user }, JWT_SECRET);
  res.cookie('session', token, { httpOnly: false });
  res.json({ ok: true });
});

router.get('/me', (req, res) => {
  const claims = jwt.decode(req.headers.authorization);
  res.json(claims);
});

router.post('/reset', (req, res) => {
  const resetToken = Math.random().toString(36).slice(2);
  db.query("UPDATE users SET reset_token = '" + resetToken + "' WHERE email = '" + req.body.email + "'", () => res.json({ sent: true }));
});

module.exports = { router, hashPassword };
