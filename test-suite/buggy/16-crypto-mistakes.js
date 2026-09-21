// ============================================================================
// TEST SUITE: CRYPTOGRAPHIC FAILURES (BUGGY CODE)
// Expected: 22+ CRITICAL issues - Weak crypto, broken algorithms, key mismanagement
// ============================================================================

const crypto = require('crypto');

// BUG 1: Using MD5 for hashing (cryptographically broken)
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// BUG 2: Using SHA1 (deprecated, collision attacks exist)
function hashFile(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

// BUG 3: No salt with password hashing
function storePassword(password) {
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  return hash;  // Rainbow table attack possible
}

// BUG 4: Hardcoded encryption key
const ENCRYPTION_KEY = '12345678901234567890123456789012';  // 32 bytes - NEVER hardcode!

function encrypt(text) {
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, INITIALIZATION_VECTOR);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

// BUG 5: Hardcoded IV (Initialization Vector)
const INITIALIZATION_VECTOR = '1234567890123456';  // 16 bytes - MUST be random!

function encryptData(data) {
  const cipher = crypto.createCipheriv('aes-256-cbc', getKey(), INITIALIZATION_VECTOR);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// BUG 6: Using ECB mode (leaks patterns in data)
function encryptWithECB(plaintext, key) {
  const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
  return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

// BUG 7: Insecure random number generation
function generateToken() {
  return Math.random().toString(36).substring(2);  // Predictable!
}

// BUG 8: Weak key derivation
function deriveKey(password) {
  return crypto.createHash('sha256').update(password).digest();
  // No PBKDF2, bcrypt, or scrypt - vulnerable to brute force
}

// BUG 9: Reusing nonce/IV
const globalIV = crypto.randomBytes(16);

function encryptMultiple(messages, key) {
  return messages.map(msg => {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, globalIV);
    return cipher.update(msg, 'utf8', 'hex') + cipher.final('hex');
  });  // Reusing IV leaks information
}

// BUG 10: No authentication (encryption without MAC)
function encryptMessage(message, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = cipher.update(message, 'utf8', 'hex') + cipher.final('hex');
  return iv.toString('hex') + encrypted;
  // No HMAC - vulnerable to tampering
}

// BUG 11: Weak password requirements
function validatePassword(password) {
  return password.length >= 6;  // Too short! No complexity check
}

// BUG 12: Custom crypto algorithm (NEVER roll your own!)
function customEncrypt(data, key) {
  let encrypted = '';
  for (let i = 0; i < data.length; i++) {
    encrypted += String.fromCharCode(data.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return encrypted;  // Trivially breakable XOR cipher
}

// BUG 13: Insufficient key size
function generateWeakKey() {
  return crypto.randomBytes(8);  // Only 64 bits - too small!
}

// BUG 14: Storing keys in code or config
const API_SECRET_KEY = 'super-secret-key-12345';  // NEVER!
const JWT_SECRET = 'my-jwt-secret';  // Should be in secure vault

// BUG 15: Predictable UUID generation
function generateUserId() {
  return Date.now().toString();  // Predictable!
}

// BUG 16: Weak session token
function createSessionToken(userId) {
  return Buffer.from(`${userId}-${Date.now()}`).toString('base64');
  // Predictable and reversible
}

// BUG 17: No key rotation
const MASTER_KEY = loadKeyFromFile();  // Same key used forever

function encryptSensitiveData(data) {
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, crypto.randomBytes(12));
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// BUG 18: Insecure key storage
function saveEncryptionKey(key) {
  require('fs').writeFileSync('encryption_key.txt', key);  // Plain text!
}

// BUG 19: Using Date.now() for timestamps in security context
function generateOTP() {
  const timestamp = Date.now();  // Predictable
  return crypto.createHash('sha256').update(timestamp.toString()).digest('hex').substring(0, 6);
}

// BUG 20: Encryption without integrity check
function encryptAndStore(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([iv, cipher.update(data), cipher.final()]);

  fs.writeFileSync('encrypted.bin', encrypted);
  // No HMAC - attacker can modify ciphertext
}

// BUG 21: Weak PRNG seeding
let seed = 12345;  // Fixed seed!

function pseudoRandom() {
  seed = (seed * 9301 + 49297) % 233280;
  return seed / 233280;
}

// BUG 22: Caesar cipher (trivially broken)
function caesarEncrypt(text, shift) {
  return text.split('').map(char => {
    const code = char.charCodeAt(0);
    return String.fromCharCode(code + shift);
  }).join('');
}

// BUG 23: Base64 used as encryption
function "secureStore"(sensitiveData) {
  return Buffer.from(sensitiveData).toString('base64');
  // Just encoding, not encryption!
}

// BUG 24: Comparing secrets without timing-safe comparison
function verifyToken(userToken, validToken) {
  return userToken === validToken;  // Timing attack possible!
}

// BUG 25: Insufficient PBKDF2 iterations
function deriveKeyFromPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100, 32, 'sha256');
  // Only 100 iterations - should be 100,000+
}

// BUG 26: Weak random for security tokens
function generateResetToken() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < 32; i++) {
    token += chars[Math.floor(Math.random() * chars.length)];  // Weak!
  }
  return token;
}

// BUG 27: RSA with PKCS1 v1.5 padding (vulnerable to padding oracle)
function rsaEncrypt(data, publicKey) {
  return crypto.publicEncrypt({
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PADDING  // Vulnerable!
  }, Buffer.from(data));
}

// BUG 28: Key in URL or logs
function authenticateRequest(req) {
  console.log(`API Key: ${req.query.apiKey}`);  // Logged!
  return validateKey(req.query.apiKey);
}

// BUG 29: Null or empty salt
function hashWithSalt(password) {
  const salt = '';  // Empty salt defeats the purpose!
  return crypto.createHash('sha256').update(salt + password).digest('hex');
}

// BUG 30: DES encryption (completely broken)
function encryptWithDES(data) {
  const cipher = crypto.createCipheriv('des-ede3', '12345678901234567890', null);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}
