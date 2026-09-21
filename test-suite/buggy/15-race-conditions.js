// ============================================================================
// TEST SUITE: RACE CONDITIONS & CONCURRENCY BUGS (BUGGY CODE)
// Expected: 18+ CRITICAL/WARNING issues - TOCTOU, data races, atomicity violations
// ============================================================================

// BUG 1: Classic TOCTOU (Time-of-check Time-of-use)
const fs = require("fs");

function readFileIfExists(filename) {
  if (fs.existsSync(filename)) {
    // Check
    // Race window: file could be deleted here
    const data = fs.readFileSync(filename); // Use
    return data;
  }
}

// BUG 2: Non-atomic read-modify-write
let counter = 0;

async function incrementCounter() {
  const current = counter; // Read
  await someAsyncOperation(); // Another increment could happen here
  counter = current + 1; // Write - lost update!
}

// BUG 3: Shared mutable state in async context
let sharedConfig = { retries: 3 };

async function updateConfig(newRetries) {
  sharedConfig.retries = newRetries; // Race condition with other updates
  await saveConfig(sharedConfig);
}

async function resetConfig() {
  sharedConfig = { retries: 3 }; // Could overwrite concurrent update
}

// BUG 4: Database race condition - check then insert
async function createUniqueUser(db, username) {
  const existing = await db.findOne({ username }); // Check
  if (!existing) {
    // Race window: another request could create the same user
    await db.insert({ username, created: Date.now() }); // Insert
  }
}

// BUG 5: File write race condition
async function appendLog(message) {
  const log = fs.readFileSync("app.log", "utf8"); // Read
  const updated = log + message + "\n";
  // Race: another process could write here
  fs.writeFileSync("app.log", updated); // Write
}

// BUG 6: Cache invalidation race
const cache = new Map();

async function updateUserAndCache(userId, data) {
  await database.update(userId, data); // Update DB
  // Race window: read could happen here with stale cache
  cache.delete(userId); // Invalidate cache
}

async function getUser(userId) {
  if (cache.has(userId)) {
    return cache.get(userId); // Could return stale data
  }
  const user = await database.find(userId);
  cache.set(userId, user);
  return user;
}

// BUG 7: Double-checked locking without proper sync
let instance = null;
let initializing = false;

async function getInstance() {
  if (!instance) {
    // First check
    if (!initializing) {
      // Second check - but not thread-safe!
      initializing = true;
      instance = await createInstance();
      initializing = false;
    }
  }
  return instance; // Could return partially initialized instance
}

// BUG 8: Race in async array operations
const users = [];

async function addUser(user) {
  users.push(user); // Not atomic
  await notifyAdmins(user);
}

async function removeUser(userId) {
  const index = users.findIndex((u) => u.id === userId); // Find
  if (index !== -1) {
    // Race: array could be modified here
    users.splice(index, 1); // Remove - might remove wrong item
  }
}

// BUG 9: Wallet balance race condition
class Wallet {
  constructor() {
    this.balance = 100;
  }

  async withdraw(amount) {
    if (this.balance >= amount) {
      // Check
      await this.logTransaction("withdraw", amount);
      // Race window: multiple withdrawals could happen
      this.balance -= amount; // Use - could go negative!
    }
  }
}

// BUG 10: Event listener race
let isProcessing = false;

async function handleClick() {
  if (!isProcessing) {
    // Check
    isProcessing = true; // Set - but not atomic!
    // Multiple clicks can get past the check
    await processPayment();
    isProcessing = false;
  }
}

// BUG 11: File lock race
const locks = {};

async function acquireLock(resource) {
  if (!locks[resource]) {
    // Check
    locks[resource] = true; // Lock
    // Multiple callers could get lock
    await performCriticalOperation(resource);
    locks[resource] = false; // Unlock
  }
}

// BUG 12: Lazy initialization race
let expensiveResource = null;

async function getResource() {
  if (!expensiveResource) {
    // Check
    // Multiple async calls could all pass this check
    expensiveResource = await createExpensiveResource();
  }
  return expensiveResource;
}

// BUG 13: Counter with async increment
class AsyncCounter {
  constructor() {
    this.count = 0;
  }

  async increment() {
    const temp = this.count; // Read
    await delay(10); // Simulate async work
    this.count = temp + 1; // Write - lost updates
  }

  async getValue() {
    return this.count; // Could see partially updated value
  }
}

// BUG 14: Session management race
const sessions = new Map();

async function createSession(userId) {
  const sessionId = generateId();
  const session = { userId, created: Date.now() };

  // Race: same user could create multiple sessions
  sessions.set(sessionId, session);
  await database.saveSession(sessionId, session);

  return sessionId;
}

async function deleteSession(sessionId) {
  sessions.delete(sessionId); // Delete from cache
  // Race window: could still be used
  await database.deleteSession(sessionId); // Delete from DB
}

// BUG 15: Rate limiter race
const rateLimits = new Map();

async function checkRateLimit(userId) {
  const current = rateLimits.get(userId) || 0; // Read

  if (current >= 100) {
    return false; // Rate limited
  }

  // Race: multiple requests could all pass this check
  rateLimits.set(userId, current + 1); // Increment
  return true;
}

// BUG 16: Inventory management race
async function purchaseItem(itemId, quantity) {
  const item = await db.findItem(itemId); // Read inventory

  if (item.stock >= quantity) {
    // Check
    // Race window: multiple purchases could happen
    item.stock -= quantity; // Decrement
    await db.updateItem(itemId, item); // Write
    return true;
  }
  return false; // Overselling possible!
}

// BUG 17: Conditional update race
async function updateIfChanged(id, expectedVersion, newData) {
  const current = await db.find(id); // Read

  if (current.version === expectedVersion) {
    // Check
    // Race: another update could happen here
    newData.version = expectedVersion + 1;
    await db.update(id, newData); // Update
  }
}

// BUG 18: Cleanup race condition
const tempFiles = new Set();

async function createTempFile(name) {
  tempFiles.add(name);
  await fs.promises.writeFile(name, "data");
}

async function cleanupTempFiles() {
  for (const file of tempFiles) {
    // Race: file could be deleted by another cleanup
    await fs.promises.unlink(file);
    tempFiles.delete(file);
  }
}

// BUG 19: Promise race without proper coordination
let dataCache = null;
let loading = false;

async function loadData() {
  if (loading) {
    // Wait for other load to complete - but how long?
    while (loading) {
      await delay(100);
    }
    return dataCache;
  }

  loading = true; // Not atomic
  // Multiple callers could all start loading
  dataCache = await fetchData();
  loading = false;
  return dataCache;
}

// BUG 20: State machine race
class StateMachine {
  constructor() {
    this.state = "idle";
  }

  async transition(to) {
    if (this.state === "idle" && to === "processing") {
      // Check state
      this.state = "processing"; // Change state - not atomic!
      // Multiple transitions could overlap
      await this.doWork();
      this.state = "idle";
    }
  }
}

// BUG 21: Queue processing race
const queue = [];
let processing = false;

async function processQueue() {
  if (processing) return;

  processing = true; // Not atomic
  // Multiple processors could start

  while (queue.length > 0) {
    const item = queue.shift(); // Race on shift
    await handleItem(item);
  }

  processing = false;
}

// BUG 22: Ref count race
class Resource {
  constructor() {
    this.refCount = 0;
  }

  async acquire() {
    this.refCount++; // Not atomic
    return this;
  }

  async release() {
    this.refCount--; // Not atomic
    if (this.refCount === 0) {
      // Race: refCount could have changed
      await this.cleanup();
    }
  }
}
