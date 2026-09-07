// Clean taint-analysis fixture: every source is sanitized before hitting sinks
const express = require('express');
const { execFile } = require('child_process');
const DOMPurify = require('dompurify');
const escapeHtml = require('escape-html');
const shellescape = require('shell-escape');
const { z } = require('zod');
const db = require('./fake-db');

const router = express.Router();
const commentSchema = z.object({
  text: z.string().max(5000).default(''),
});

router.use(express.json());

router.post('/comment', (req, res) => {
  const { text } = commentSchema.parse(req.body);
  const html = `<div class="comment">${DOMPurify.sanitize(text)}</div>`;
  res.send(html);
});

router.get('/preview', (req, res) => {
  document.getElementById('preview').textContent = escapeHtml(req.query.html || '');
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
  execFile('ls', [shellescape([req.query.path || '.'])], err => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.send('executed');
  });
});

const params = new URLSearchParams(window.location.search);
const safeValue = DOMPurify.sanitize(params.get('q') || '');
document.getElementById('safe-link').textContent = safeValue;

module.exports = router;
