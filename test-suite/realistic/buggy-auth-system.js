// ============================================================================
// REALISTIC SCENARIO: AUTHENTICATION SYSTEM (BUGGY CODE)
// Expected: 40+ CRITICAL security issues
// This simulates a real authentication system with catastrophic security flaws
// ============================================================================

const express = require("express");
const router = express.Router();
const crypto = require("crypto");

// BUG: Hardcoded secrets
const JWT_SECRET = "my-secret-key-123";
const ENCRYPTION_KEY = "abcdefghijklmnopqrstuvwxyz123456";
const PASSWORD_SALT = "static-salt"; // Same salt for all passwords!

// BUG: Global mutable state
var sessions = {}; // Memory leak + race conditions
var loginAttempts = {};

// BUG: Weak password hashing (MD5)
function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

// BUG: No input validation, SQL injection
router.post("/signup", (req, res) => {
  const { username, password, email } = req.body;

  // BUG: No validation whatsoever
  const hashedPassword = hashPassword(password);

  // BUG: SQL injection
  const query = `INSERT INTO users (username, password, email) VALUES ('${username}', '${hashedPassword}', '${email}')`;

  db.query(query, (err, result) => {
    if (err) {
      // BUG: Leaking database errors
      res.json({ error: err.message });
    } else {
      res.json({ success: true, userId: result.insertId });
    }
  });
});

// BUG: Timing attack vulnerability + wrong password comparison
router.post("/login", (req, res) => {
  const { username, password } = req.body;

  // BUG: No rate limiting check is effective
  if (loginAttempts[username] > 1000) {
    res.json({ error: "Too many attempts" });
    return;
  }

  // BUG: SQL injection
  const query = `SELECT * FROM users WHERE username = '${username}'`;

  db.query(query, (err, users) => {
    if (users.length === 0) {
      res.json({ error: "User not found" }); // BUG: User enumeration
      return;
    }

    const user = users[0];
    const hashedInput = hashPassword(password);

    // BUG: Non-constant time comparison (timing attack)
    if (hashedInput === user.password) {
      // BUG: Predictable session ID
      const sessionId = username + "-" + Date.now();

      // BUG: Session stored in memory (lost on restart)
      sessions[sessionId] = {
        userId: user.id,
        username: user.username,
        isAdmin: user.is_admin, // BUG: Trusting database field
      };

      // BUG: Session token in response body (should be HTTP-only cookie)
      res.json({
        success: true,
        sessionId: sessionId,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          password: user.password, // BUG: Sending password hash to client!
          isAdmin: user.is_admin,
        },
      });
    } else {
      loginAttempts[username] = (loginAttempts[username] || 0) + 1;
      res.json({ error: "Invalid password" }); // BUG: Reveals password is wrong, not username
    }
  });
});

// BUG: No session validation
router.get("/profile", (req, res) => {
  const sessionId = req.query.sessionId; // BUG: Session ID in query string!

  // BUG: No check if session exists
  const session = sessions[sessionId];

  // BUG: SQL injection
  db.query(`SELECT * FROM users WHERE id = ${session.userId}`, (err, users) => {
    res.json(users[0]); // BUG: Returns all fields including password
  });
});

// BUG: Password reset without verification
router.post("/reset-password", (req, res) => {
  const { email } = req.body;

  // BUG: No rate limiting on password resets
  // BUG: SQL injection
  db.query(`SELECT * FROM users WHERE email = '${email}'`, (err, users) => {
    if (users.length === 0) {
      res.json({ error: "Email not found" }); // BUG: Email enumeration
      return;
    }

    const user = users[0];

    // BUG: Predictable reset token
    const resetToken = Buffer.from(`${email}-${Date.now()}`).toString("base64");

    // BUG: Token stored in database without expiration
    db.query(`UPDATE users SET reset_token = '${resetToken}' WHERE id = ${user.id}`);

    // BUG: Sending reset link over HTTP
    const resetLink = `http://example.com/reset?token=${resetToken}`;

    // BUG: Token visible in logs
    console.log("Password reset link:", resetLink);

    res.json({ success: true, resetLink }); // BUG: Returning link in response!
  });
});

// BUG: No token validation
router.post("/reset-password-confirm", (req, res) => {
  const { token, newPassword } = req.body;

  // BUG: No password strength validation
  // BUG: SQL injection
  db.query(`SELECT * FROM users WHERE reset_token = '${token}'`, (err, users) => {
    if (users.length === 0) {
      res.json({ error: "Invalid token" });
      return;
    }

    const user = users[0];
    const newHash = hashPassword(newPassword);

    // BUG: SQL injection
    db.query(`UPDATE users SET password = '${newHash}', reset_token = NULL WHERE id = ${user.id}`);

    res.json({ success: true });
  });
});

// BUG: IDOR (Insecure Direct Object Reference)
router.get("/user/:id", (req, res) => {
  const userId = req.params.id;

  // BUG: No authentication check
  // BUG: No authorization check (can view any user)
  // BUG: SQL injection
  db.query(`SELECT * FROM users WHERE id = ${userId}`, (err, users) => {
    res.json(users[0]); // BUG: Exposes password hash
  });
});

// BUG: Admin privilege escalation
router.post("/update-profile", (req, res) => {
  const sessionId = req.body.sessionId;
  const session = sessions[sessionId];

  // BUG: Mass assignment - user can set any field
  const updates = req.body.updates;

  // BUG: User can set is_admin = true!
  const fields = Object.keys(updates)
    .map((key) => `${key} = '${updates[key]}'`)
    .join(", ");

  // BUG: SQL injection
  db.query(`UPDATE users SET ${fields} WHERE id = ${session.userId}`);

  res.json({ success: true });
});

// BUG: JWT implementation flaws
const jwt = {
  sign: (payload) => {
    // BUG: Using base64 encoding instead of proper signing
    return Buffer.from(JSON.stringify(payload)).toString("base64");
  },
  verify: (token) => {
    // BUG: Just decodes, doesn't verify signature!
    try {
      return JSON.parse(Buffer.from(token, "base64").toString());
    } catch (e) {
      return null;
    }
  },
};

router.post("/jwt-login", (req, res) => {
  const { username, password } = req.body;

  db.query(`SELECT * FROM users WHERE username = '${username}'`, (err, users) => {
    if (users.length > 0 && hashPassword(password) === users[0].password) {
      // BUG: Putting sensitive data in JWT
      const token = jwt.sign({
        userId: users[0].id,
        username: users[0].username,
        password: users[0].password, // BUG!
        isAdmin: users[0].is_admin,
        creditCard: users[0].credit_card, // BUG!
      });

      res.json({ token });
    } else {
      res.json({ error: "Invalid credentials" });
    }
  });
});

// BUG: Trusting JWT without verification
router.get("/admin-panel", (req, res) => {
  const token = req.headers.authorization;

  // BUG: No proper verification
  const payload = jwt.verify(token);

  // BUG: Trusting isAdmin from token
  if (payload && payload.isAdmin) {
    res.json({ message: "Welcome, admin!", users: getAllUsers() });
  } else {
    res.json({ error: "Unauthorized" });
  }
});

// BUG: Session fixation vulnerability
router.get("/login-as", (req, res) => {
  const { userId, sessionId } = req.query;

  // BUG: Allows setting arbitrary session ID
  sessions[sessionId] = {
    userId: userId,
    username: "unknown",
  };

  res.json({ success: true, sessionId });
});

// BUG: CSRF vulnerability - no CSRF tokens
router.post("/delete-account", (req, res) => {
  const sessionId = req.body.sessionId;
  const session = sessions[sessionId];

  // BUG: No CSRF protection - attacker can trigger via POST from malicious site
  db.query(`DELETE FROM users WHERE id = ${session.userId}`);

  delete sessions[sessionId];
  res.json({ success: true });
});

// BUG: OAuth implementation flaws
router.get("/oauth/callback", (req, res) => {
  const code = req.query.code;
  const state = req.query.state;

  // BUG: No state validation (CSRF in OAuth flow)
  // BUG: No PKCE (Proof Key for Code Exchange)

  // BUG: Hardcoded OAuth credentials
  const clientId = "my-client-id";
  const clientSecret = "my-client-secret-123";

  // BUG: OAuth credentials in URL
  const tokenUrl = `https://oauth.provider.com/token?code=${code}&client_id=${clientId}&client_secret=${clientSecret}`;

  // Exchange code for token
  fetch(tokenUrl)
    .then((r) => r.json())
    .then((data) => {
      const accessToken = data.access_token;

      // BUG: Storing OAuth token in session without encryption
      const sessionId = Math.random().toString();
      sessions[sessionId] = { oauthToken: accessToken };

      res.json({ sessionId });
    });
});

// BUG: Remember me functionality with security flaws
router.post("/remember-me", (req, res) => {
  const { username, password } = req.body;

  db.query(`SELECT * FROM users WHERE username = '${username}'`, (err, users) => {
    if (users.length > 0 && hashPassword(password) === users[0].password) {
      // BUG: Storing plaintext credentials in cookie
      res.cookie("remember", JSON.stringify({ username, password }), {
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: false, // BUG: Accessible via JavaScript
        secure: false, // BUG: Sent over HTTP
      });

      res.json({ success: true });
    }
  });
});

// BUG: API key generation with weak randomness
router.post("/generate-api-key", (req, res) => {
  const sessionId = req.body.sessionId;
  const session = sessions[sessionId];

  // BUG: Weak random generation
  const apiKey = Math.random().toString(36).substring(2) + Date.now().toString(36);

  // BUG: Storing API key in plaintext
  db.query(`UPDATE users SET api_key = '${apiKey}' WHERE id = ${session.userId}`);

  res.json({ apiKey });
});

// BUG: Account takeover via race condition
router.post("/verify-email", async (req, res) => {
  const { email, code } = req.body;

  // BUG: No rate limiting
  // Check verification code
  db.query(`SELECT * FROM users WHERE email = '${email}'`, async (err, users) => {
    const user = users[0];

    if (user.verification_code == code) {
      // BUG: Loose equality
      // BUG: Race condition - multiple requests can verify simultaneously
      await delay(100);

      db.query(`UPDATE users SET email_verified = true WHERE id = ${user.id}`);

      // BUG: Auto-login without re-authentication
      const sessionId = email + "-verified-" + Date.now();
      sessions[sessionId] = { userId: user.id };

      res.json({ success: true, sessionId });
    } else {
      res.json({ error: "Invalid code" });
    }
  });
});

// BUG: Logout doesn't actually invalidate session
router.post("/logout", (req, res) => {
  const sessionId = req.body.sessionId;

  // BUG: Just responds, doesn't delete session
  res.json({ success: true });

  // Session still valid!
});

module.exports = router;
