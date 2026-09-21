// ============================================================================
// TEST SUITE: SECURITY VULNERABILITIES (BUGGY CODE)
// Expected: Multiple CRITICAL issues
// ============================================================================

// BUG 1: eval() with user input (CRITICAL - Remote Code Execution)
function executeUserCode(code) {
  eval(code); // CRITICAL: Allows arbitrary code execution!
}

// BUG 2: new Function() (equivalent to eval)
const userFunction = new Function("x", "return " + userInput); // CRITICAL!

// BUG 3: innerHTML with user data (XSS vulnerability)
function displayComment(comment) {
  const div = document.getElementById("comments");
  div.innerHTML = comment; // XSS: user can inject <script> tags
}

// BUG 4: document.write (deprecated and dangerous)
document.write("<h1>" + userContent + "</h1>"); // XSS + breaks SPAs

// BUG 5: Prototype pollution
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key]; // Can pollute Object.prototype via __proto__
  }
}

// BUG 6: Direct __proto__ manipulation
const obj = {};
obj.__proto__.polluted = true; // CRITICAL: Prototype pollution

// BUG 7: Hardcoded API keys
const API_KEY = "sk_live_abc123xyz789"; // CRITICAL: Hardcoded secret
const SECRET_KEY = "super_secret_password_123";
const auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

// BUG 8: Hardcoded credentials
const dbPassword = "admin123";
const apiKey = "AIzaSyD1234567890abcdefghijk";

// BUG 9: innerHTML in loop (multiple XSS points)
function renderItems(items) {
  items.forEach((item) => {
    document.getElementById("list").innerHTML += `<li>${item.name}</li>`; // XSS
  });
}

// BUG 10: dangerouslySetInnerHTML without sanitization (React)
function UserComment({ comment }) {
  return <div dangerouslySetInnerHTML={{ __html: comment }} />; // XSS
}

// BUG 11: Weak crypto hash
const crypto = require("crypto");
const hash = crypto.createHash("md5").update(password).digest("hex"); // Weak!
const sha1Hash = crypto.createHash("sha1").update(data).digest("hex"); // Also weak!

// BUG 12: Using Math.random() for security
function generateToken() {
  return Math.random().toString(36).substr(2); // NOT cryptographically secure!
}

// BUG 13: HTTP URL in production code
const apiEndpoint = "http://api.example.com/users"; // Should be HTTPS!

// BUG 14: ReDoS vulnerable regex
const emailRegex = /^([a-z]+)+@[a-z]+\.[a-z]+$/; // Nested quantifiers - ReDoS risk!
const phoneRegex = /^(\d+)*$/; // Dangerous pattern
