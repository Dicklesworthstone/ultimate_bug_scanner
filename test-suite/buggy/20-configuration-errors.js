// ============================================================================
// TEST SUITE: CONFIGURATION & SECURITY HEADERS (BUGGY CODE)
// Expected: 18+ CRITICAL issues - CORS, CSP, security misconfigurations
// ============================================================================

const express = require("express");
const app = express();

// BUG 1: Wildcard CORS - allows any origin
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*"); // CRITICAL: Too permissive!
  res.setHeader("Access-Control-Allow-Credentials", "true"); // Dangerous combo
  next();
});

// BUG 2: Missing security headers
app.get("/api/data", (req, res) => {
  res.json({ data: "sensitive" });
  // Missing: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security
});

// BUG 3: Weak Content Security Policy
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'unsafe-inline' 'unsafe-eval' *");
  // Defeats the purpose of CSP!
  next();
});

// BUG 4: Exposing error details in production
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack, // CRITICAL: Leaks implementation details
    details: err,
  });
});

// BUG 5: No rate limiting
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (authenticate(username, password)) {
    res.json({ token: generateToken(username) });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
  // No rate limiting - allows brute force
});

// BUG 6: Debug mode in production
const DEBUG = true; // Should be environment variable

if (DEBUG) {
  app.use((req, res, next) => {
    console.log(req.headers); // Logs sensitive headers
    console.log(req.body); // Logs sensitive data
    next();
  });
}

// BUG 7: Allowing all HTTP methods
app.all("/api/*", (req, res, next) => {
  // No method filtering - allows PUT, DELETE on all endpoints
  next();
});

// BUG 8: Not validating Content-Type
app.post("/api/upload", (req, res) => {
  // Accepts any content type - could process malicious payloads
  processUpload(req.body);
  res.json({ success: true });
});

// BUG 9: Weak session configuration
const session = require("express-session");

app.use(
  session({
    secret: "keyboard cat", // Weak secret
    resave: true,
    saveUninitialized: true,
    cookie: {
      secure: false, // Should be true in production
      httpOnly: false, // Should be true
      sameSite: "none", // Should be 'strict' or 'lax'
    },
  }),
);

// BUG 10: Exposing server information
app.use((req, res, next) => {
  res.setHeader("X-Powered-By", "Express 4.18.2"); // Exposes version
  next();
});

// BUG 11: Not setting X-Frame-Options
app.get("/admin", (req, res) => {
  res.send("<html>Admin Panel</html>");
  // Vulnerable to clickjacking - missing X-Frame-Options: DENY
});

// BUG 12: Permissive file upload configuration
const multer = require("multer");
const upload = multer({
  dest: "uploads/",
  // No file size limit
  // No file type validation
});

app.post("/upload", upload.single("file"), (req, res) => {
  res.json({ filename: req.file.filename });
  // Accepts any file type, any size
});

// BUG 13: HTTP instead of HTTPS redirect
app.use((req, res, next) => {
  if (!req.secure) {
    // Should redirect HTTP to HTTPS
    next();
  } else {
    next();
  }
});

// BUG 14: Verbose logging in production
const winston = require("winston");
const logger = winston.createLogger({
  level: "debug", // Too verbose for production
  transports: [
    new winston.transports.Console({
      format: winston.format.simple(),
    }),
  ],
});

// BUG 15: Allowing deprecated TLS versions
const https = require("https");
const server = https.createServer(
  {
    key: fs.readFileSync("key.pem"),
    cert: fs.readFileSync("cert.pem"),
    secureOptions: 0, // Allows TLS 1.0, 1.1 - deprecated
  },
  app,
);

// BUG 16: No timeout configurations
app.get("/api/slow", (req, res) => {
  // No timeout - could hang forever
  performSlowOperation().then((result) => {
    res.json(result);
  });
});

// BUG 17: Trusting proxy headers without validation
app.set("trust proxy", true); // Trusts all proxies

app.get("/api/info", (req, res) => {
  const ip = req.ip; // Could be spoofed via X-Forwarded-For
  res.json({ ip });
});

// BUG 18: Not sanitizing redirect URLs
app.get("/redirect", (req, res) => {
  const url = req.query.url;
  res.redirect(url); // Open redirect vulnerability
});

// BUG 19: Excessive CORS methods
app.use((req, res, next) => {
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE",
  );
  // TRACE is dangerous, too permissive
  next();
});

// BUG 20: Missing Referrer-Policy
app.use((req, res, next) => {
  // Should set: Referrer-Policy: no-referrer or strict-origin-when-cross-origin
  next();
});

// BUG 21: Weak cache control on sensitive data
app.get("/api/user/profile", (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=3600"); // Caches sensitive data
  res.json({ email: "user@example.com", ssn: "123-45-6789" });
});

// BUG 22: Allowing credentials with wildcard origin
app.options("*", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true"); // Invalid combo
  res.send();
});

// BUG 23: Not setting Permissions-Policy
app.use((req, res, next) => {
  // Should set: Permissions-Policy to restrict features
  next();
});

// BUG 24: Weak helmet configuration
const helmet = require("helmet");

app.use(
  helmet({
    contentSecurityPolicy: false, // Disables CSP
    frameguard: false, // Allows clickjacking
  }),
);

// BUG 25: Serving static files without restrictions
app.use(express.static("public")); // Serves ALL files in public/
// Could expose .env, .git, backup files if accidentally placed there

// BUG 26: Not validating JWT properly
const jwt = require("jsonwebtoken");

app.post("/api/protected", (req, res) => {
  const token = req.headers.authorization;
  const decoded = jwt.decode(token); // Just decodes, doesn't verify!
  res.json({ user: decoded.userId });
});

// BUG 27: Allowing JSONP (deprecated and dangerous)
app.get("/api/data", (req, res) => {
  const callback = req.query.callback;
  const data = { secret: "value" };
  res.send(`${callback}(${JSON.stringify(data)})`); // JSONP XSS risk
});

// BUG 28: Missing Strict-Transport-Security
app.get("/", (req, res) => {
  res.send("Welcome");
  // Should set: Strict-Transport-Security: max-age=31536000; includeSubDomains
});

// BUG 29: Cookie without SameSite attribute
app.post("/api/login", (req, res) => {
  res.cookie("session", "abc123", {
    httpOnly: true,
    secure: true,
    // Missing: sameSite: 'strict' - vulnerable to CSRF
  });
  res.json({ success: true });
});

// BUG 30: Exposing internal paths in errors
app.get("/api/file", (req, res) => {
  try {
    const data = fs.readFileSync("/var/www/app/data/file.txt");
    res.send(data);
  } catch (err) {
    res.status(500).json({ error: err.message }); // Exposes file path
  }
});

module.exports = app;
