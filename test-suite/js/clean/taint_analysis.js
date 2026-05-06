// Clean taint-analysis fixture: every source is sanitized before hitting sinks
const express = require('express');
const { exec } = require('child_process');
const DOMPurify = require('dompurify');
const escapeHtml = require('escape-html');
const shellescape = require('shell-escape');
const db = require('./fake-db');

const router = express.Router();

router.post('/comment', (req, res) => {
  const html = `<div class="comment">${DOMPurify.sanitize(req.body.text || '')}</div>`;
  res.send(html);
});

router.get('/preview', (req, res) => {
  document.getElementById('preview').innerHTML = escapeHtml(req.query.html || '');
  res.send('ok');
});

router.get('/search', (req, res) => {
  const sql = 'SELECT * FROM posts WHERE slug = ?';
  db.query(sql, [req.params.slug]); // parameterized query
  res.send('done');
});

async function nextRouteSearch(_request, { params }) {
  await db.query('SELECT * FROM tenants WHERE slug = ?', [params.tenant]);
}

async function nextRouteDestructuredSearch(_request, { params }) {
  const { account } = params;
  await db.query('SELECT * FROM accounts WHERE slug = ?', [account]);
}

router.get('/exec', (req, res) => {
  exec('ls ' + shellescape([req.query.path || '.']), err => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.send('executed');
  });
});

const params = new URLSearchParams(window.location.search);
const safeValue = DOMPurify.sanitize(params.get('q') || '');
document.getElementById('safe-link').innerHTML = safeValue;

module.exports = router;
