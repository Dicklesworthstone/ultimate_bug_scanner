// ============================================================================
// TEST SUITE: NODE.JS/EXPRESS API (BUGGY CODE)
// Expected: 30+ CRITICAL issues - Security, performance, error handling
// ============================================================================

const express = require("express");
const app = express();

// BUG 1: No body parser middleware
app.post("/api/users", (req, res) => {
  const user = req.body; // undefined! No body-parser
  saveUser(user);
  res.json({ success: true });
});

// BUG 2: SQL injection
app.get("/api/user/:id", (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, result) => {
    // Injectable!
    res.json(result);
  });
});

// BUG 3: No error handling
app.get("/api/data", (req, res) => {
  const data = riskyOperation(); // Could throw
  res.json(data); // Error crashes server
});

// BUG 4: Exposing sensitive errors
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack, // CRITICAL: Exposes internals
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
  // Allows brute force attacks
});

// BUG 6: Blocking synchronous operations
app.get("/api/report", (req, res) => {
  const data = fs.readFileSync("large-file.json"); // Blocks event loop!
  res.json(JSON.parse(data));
});

// BUG 7: No input validation
app.post("/api/signup", (req, res) => {
  const user = req.body; // No validation!
  db.insert("users", user);
  res.json({ userId: user.id });
});

// BUG 8: Memory leak - global variable
const requests = []; // Grows forever

app.get("/api/stats", (req, res) => {
  requests.push({ timestamp: Date.now(), path: req.path });
  res.json({ total: requests.length });
});

// BUG 9: Callback hell
app.get("/api/nested", (req, res) => {
  db.query("SELECT * FROM users", (err1, users) => {
    db.query("SELECT * FROM posts", (err2, posts) => {
      db.query("SELECT * FROM comments", (err3, comments) => {
        db.query("SELECT * FROM likes", (err4, likes) => {
          res.json({ users, posts, comments, likes });
        });
      });
    });
  });
});

// BUG 10: Not closing database connections
app.get("/api/users", (req, res) => {
  const conn = getNewConnection();
  conn.query("SELECT * FROM users", (err, result) => {
    res.json(result);
    // Connection never closed!
  });
});

// BUG 11: Hardcoded credentials
const DB_PASSWORD = "admin123";
const API_KEY = "sk_live_abc123xyz789";

mongoose.connect(`mongodb://admin:${DB_PASSWORD}@localhost/myapp`);

// BUG 12: No timeout on requests
app.get("/api/slow", (req, res) => {
  performVerySlowOperation().then((result) => {
    res.json(result);
  });
  // Could hang forever
});

// BUG 13: Race condition in async handler
let counter = 0;

app.post("/api/increment", async (req, res) => {
  const current = counter;
  await someAsyncOp();
  counter = current + 1; // Lost updates!
  res.json({ counter });
});

// BUG 14: Not handling promise rejections
app.get("/api/async-data", (req, res) => {
  fetchData().then((data) => {
    res.json(data);
  });
  // No .catch() - unhandled rejection
});

// BUG 15: Sending multiple responses
app.get("/api/data", (req, res) => {
  res.json({ status: "processing" });

  processData().then((result) => {
    res.json({ result }); // Error: headers already sent
  });
});

// BUG 16: Not sanitizing file paths
app.get("/api/file/:filename", (req, res) => {
  const file = fs.readFileSync(`./uploads/${req.params.filename}`);
  res.send(file);
  // Path traversal: ?filename=../../etc/passwd
});

// BUG 17: Eval() with user input
app.post("/api/calculate", (req, res) => {
  const expression = req.body.expression;
  const result = eval(expression); // CRITICAL: Code injection!
  res.json({ result });
});

// BUG 18: No CORS configuration
app.get("/api/sensitive", (req, res) => {
  res.json({ apiKey: process.env.API_KEY });
  // Accessible from any origin by default
});

// BUG 19: Improper error in async/await
app.get("/api/users/:id", async (req, res) => {
  const user = await db.findUser(req.params.id); // Could throw
  res.json(user);
  // No try/catch
});

// BUG 20: Trusting client input directly
app.post("/api/admin/delete", (req, res) => {
  if (req.body.isAdmin) {
    // Client can set this!
    deleteAllData();
    res.json({ success: true });
  }
});

// BUG 21: Logging sensitive data
app.post("/api/payment", (req, res) => {
  console.log("Payment:", req.body.creditCard); // Logs CC number!
  processPayment(req.body);
  res.json({ success: true });
});

// BUG 22: No request size limits
app.post("/api/upload", (req, res) => {
  const data = req.body.data; // Could be gigabytes!
  saveData(data);
  res.json({ success: true });
});

// BUG 23: Using var instead of const/let
app.get("/api/test", (req, res) => {
  for (var i = 0; i < 5; i++) {
    setTimeout(() => console.log(i), 100); // Logs "5" five times
  }
  res.json({ ok: true });
});

// BUG 24: Not validating content-type
app.post("/api/json", (req, res) => {
  const data = req.body; // Accepts any content-type
  processJSON(data);
  res.json({ success: true });
});

// BUG 25: Middleware order wrong
app.use(authMiddleware); // Applied to all routes below
app.get("/api/public", (req, res) => {
  res.json({ data: "public" }); // Unnecessarily requires auth
});

// BUG 26: Not handling SIGTERM/SIGINT
app.listen(3000, () => {
  console.log("Server started");
  // No graceful shutdown handlers
});

// BUG 27: Mutable shared state
const cache = {};

app.get("/api/cache/:key", (req, res) => {
  const value = cache[req.params.key];
  res.json({ value });
});

app.post("/api/cache/:key", (req, res) => {
  cache[req.params.key] = req.body.value; // Race conditions
  res.json({ success: true });
});

// BUG 28: Not parsing query parameters safely
app.get("/api/search", (req, res) => {
  const limit = req.query.limit; // String, not number!
  const results = db.query("SELECT * FROM items LIMIT " + limit);
  res.json(results); // SQL injection via query param
});

// BUG 29: Improper use of next()
app.get("/api/test", (req, res, next) => {
  res.json({ ok: true });
  next(); // Calls next middleware even after responding!
});

// BUG 30: Connecting to database on every request
app.get("/api/data", (req, res) => {
  mongoose
    .connect("mongodb://localhost/myapp")
    .then(() => {
      return mongoose.model("Data").find();
    })
    .then((data) => {
      res.json(data);
    });
  // Should reuse connection pool
});

// BUG 31: No health check endpoint
// Server might be running but not functional

// BUG 32: Not setting security headers
app.get("/api/page", (req, res) => {
  res.send("<html>Content</html>");
  // Missing: X-Frame-Options, CSP, etc.
});

// BUG 33: Improper session management
const sessions = {};

app.post("/api/login", (req, res) => {
  const sessionId = Math.random().toString(); // Predictable!
  sessions[sessionId] = { user: req.body.username };
  res.json({ sessionId });
});

// BUG 34: Catching errors but not handling them
app.get("/api/data", (req, res) => {
  try {
    const data = riskyOperation();
    res.json(data);
  } catch (err) {
    // Empty catch - silent failure
  }
});

// BUG 35: Not checking if file exists
app.get("/api/download/:file", (req, res) => {
  const content = fs.readFileSync(`./files/${req.params.file}`);
  res.send(content); // Crashes if file doesn't exist
});

module.exports = app;
