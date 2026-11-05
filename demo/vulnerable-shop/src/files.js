const express = require('express');
const { exec } = require('child_process');
const path = require('path');

const router = express.Router();

router.get('/invoice', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'invoices', req.query.name));
});

router.post('/thumbnail', (req, res) => {
  exec(`convert ${req.body.image} -resize 200x200 thumb.png`, (err) => {
    if (err) return res.status(500).send(err.message);
    res.sendFile(path.join(__dirname, 'thumb.png'));
  });
});

module.exports = router;
