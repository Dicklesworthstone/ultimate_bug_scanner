// ============================================================================
// TEST SUITE: SECURITY (CLEAN CODE)
// Expected: No critical security issues
// ============================================================================

// GOOD: Using textContent instead of innerHTML
function displayComment(comment) {
  const div = document.getElementById('comments');
  if (div) {
    div.textContent = comment;  // Safe - no XSS
  }
}

// GOOD: Sanitizing HTML (assuming DOMPurify is available)
function displayRichComment(html) {
  const div = document.getElementById('comments');
  if (div && typeof DOMPurify !== 'undefined') {
    div.textContent = DOMPurify.sanitize(html);
  }
}

// GOOD: Using environment variables for secrets
const API_KEY = process.env.API_KEY;
const DB_PASSWORD = process.env.DB_PASSWORD;

// GOOD: Strong crypto hash
const crypto = require('crypto');
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// GOOD: Cryptographically secure random
function generateSecureToken() {
  return crypto.randomBytes(32).toString('hex');
}

// GOOD: HTTPS URLs
const API_ENDPOINT = "https://api.example.com/users";
const WS_ENDPOINT = "wss://api.example.com/ws";

// GOOD: Avoiding prototype pollution
function safeMerge(target, source) {
  const result = { ...target };

  for (const key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      // Skip __proto__, constructor, prototype
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      result[key] = source[key];
    }
  }

  return result;
}

// GOOD: Safe regex (no ReDoS)
const emailRegex = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;
const phoneRegex = /^\d{10}$/;

// GOOD: Validating input before using
function executeUserAction(action) {
  const allowedActions = ['save', 'delete', 'update', 'view'];

  if (!allowedActions.includes(action)) {
    throw new Error('Invalid action');
  }

  // Now safe to use action
  performAction(action);
}

// GOOD: Creating elements safely
function createUserCard(user) {
  const card = document.createElement('div');
  card.className = 'user-card';

  const name = document.createElement('h3');
  name.textContent = user.name;  // Safe

  const email = document.createElement('p');
  email.textContent = user.email;  // Safe

  card.appendChild(name);
  card.appendChild(email);

  return card;
}

// GOOD: Using CSP-friendly approaches
function loadScript(src) {
  const script = document.createElement('script');
  script.src = src;  // No inline code
  script.async = true;
  document.head.appendChild(script);
}

// GOOD: Parameterized queries (SQL injection prevention)
function getUserById(db, userId) {
  // Using parameterized query
  return db.query('SELECT * FROM users WHERE id = ?', [userId]);
}
