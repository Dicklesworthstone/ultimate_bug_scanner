// ============================================================================
// TEST SUITE: PERFORMANCE ANTI-PATTERNS (BUGGY CODE)
// Expected: 20+ WARNING issues - Performance killers and inefficiencies
// ============================================================================

// BUG 1: N+1 query problem
async function getUsersWithPosts(userIds) {
  const users = await db.query("SELECT * FROM users WHERE id IN (?)", [userIds]);

  for (const user of users) {
    user.posts = await db.query("SELECT * FROM posts WHERE user_id = ?", [user.id]);
    // Makes N queries instead of joining or batching
  }

  return users;
}

// BUG 2: Synchronous file reading in hot path
const fs = require("fs");

function getConfig() {
  return JSON.parse(fs.readFileSync("config.json", "utf8")); // Blocks event loop!
}

// BUG 3: Creating functions in loops
function attachHandlers(elements) {
  elements.forEach((el) => {
    el.onclick = () => {
      // New function created each iteration
      handleClick(el);
    };
  });
}

// BUG 4: Regex compilation in loop
function validateEmails(emails) {
  return emails.every((email) => {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; // Compiled every iteration!
    return regex.test(email);
  });
}

// BUG 5: Unnecessary deep cloning
function updateUser(user, changes) {
  const updated = JSON.parse(JSON.stringify(user)); // Deep clone everything
  Object.assign(updated, changes); // Just needed shallow merge
  return updated;
}

// BUG 6: Array operations on large datasets
function processMillionItems(items) {
  return items
    .filter((x) => x.active) // Creates new array
    .map((x) => x.value) // Creates another new array
    .filter((x) => x > 0) // Creates yet another array
    .map((x) => x * 2); // Final array - 4 iterations, 3 intermediate arrays
}

// BUG 7: Inefficient string concatenation
function buildLargeString(items) {
  let result = "";
  for (let i = 0; i < 100000; i++) {
    result += items[i]; // Creates new string each time - O(n²)
  }
  return result;
}

// BUG 8: Using try/catch in hot path
function fastFunction(arr) {
  return arr.map((item) => {
    try {
      return processItem(item); // try/catch prevents optimization
    } catch (e) {
      return null;
    }
  });
}

// BUG 9: Excessive DOM queries
function updateElements() {
  for (let i = 0; i < 100; i++) {
    document.getElementById("item-" + i).textContent = i;
    // Queries DOM 100 times
  }
}

// BUG 10: Using innerHTML in loop
function renderItems(items) {
  const container = document.getElementById("container");
  items.forEach((item) => {
    container.innerHTML += `<div>${item}</div>`; // Reparses entire HTML each time
  });
}

// BUG 11: Memory leak - cached data never cleaned
const cache = new Map();

function getCachedData(key) {
  if (!cache.has(key)) {
    cache.set(key, fetchExpensiveData(key)); // Cache grows forever
  }
  return cache.get(key);
}

// BUG 12: Blocking the event loop
function computePrimes(max) {
  const primes = [];
  for (let i = 2; i < max; i++) {
    let isPrime = true;
    for (let j = 2; j < i; j++) {
      if (i % j === 0) {
        isPrime = false;
        break;
      }
    }
    if (isPrime) primes.push(i);
  }
  return primes; // Blocks for large 'max'
}

// BUG 13: Loading entire dataset into memory
async function getAllUsers() {
  return await db.query("SELECT * FROM users"); // Could be millions of rows
}

// BUG 14: Inefficient sorting
function sortByMultipleFields(items) {
  return items.sort((a, b) => {
    // Recalculates complex values on every comparison
    const scoreA = calculateComplexScore(a);
    const scoreB = calculateComplexScore(b);
    return scoreA - scoreB;
  });
}

// BUG 15: Using delete in performance-critical code
function clearProperties(obj) {
  delete obj.prop1; // delete is slow
  delete obj.prop2;
  delete obj.prop3;
  // Better: obj = {}
}

// BUG 16: Expensive operation in render loop
function gameLoop() {
  requestAnimationFrame(() => {
    const config = JSON.parse(localStorage.getItem("config")); // Every frame!
    render(config);
    gameLoop();
  });
}

// BUG 17: Not using indexes
function findById(items, id) {
  return items.find((item) => item.id === id); // O(n) search
  // Should use Map or object for O(1) lookup
}

// BUG 18: Creating many small objects
function processPoints(points) {
  return points.map((p) => {
    return {
      // New object for each point
      x: p.x * 2,
      y: p.y * 2,
      z: p.z * 2,
    };
  });
  // Better to mutate in-place or use typed arrays
}

// BUG 19: Inefficient array search
function hasCommonElement(arr1, arr2) {
  for (const item1 of arr1) {
    for (const item2 of arr2) {
      if (item1 === item2) return true; // O(n*m)
    }
  }
  return false;
  // Better: new Set(arr1).intersection(arr2).size > 0
}

// BUG 20: Loading images synchronously
function loadAllImages(urls) {
  return urls.map((url) => {
    const xhr = new XMLHttpRequest();
    xhr.open("GET", url, false); // Synchronous!
    xhr.send();
    return xhr.responseText;
  });
}

// BUG 21: Not reusing regex objects
function validateMany(strings) {
  return strings.map((s) => /^[a-z]+$/.test(s)); // Creates regex each time
}

// BUG 22: Polling instead of events
function waitForElement(selector) {
  const interval = setInterval(() => {
    const el = document.querySelector(selector);
    if (el) {
      clearInterval(interval);
      processElement(el);
    }
  }, 100); // Wasteful polling
}

// BUG 23: Not using WeakMap for metadata
const metadata = new Map(); // Prevents GC

function attachMetadata(obj, data) {
  metadata.set(obj, data); // Objects never released
}

// BUG 24: Computing derived values repeatedly
class DataModel {
  constructor(data) {
    this.data = data;
  }

  get total() {
    return this.data.reduce((sum, x) => sum + x, 0); // Recalculates every access
  }
}

// BUG 25: Quadratic time complexity
function removeDuplicates(arr) {
  const result = [];
  for (const item of arr) {
    if (!result.includes(item)) {
      // includes is O(n)
      result.push(item);
    }
  }
  return result; // O(n²) - should use Set
}

// BUG 26: Heavy computation in getter
class ExpensiveGetter {
  get value() {
    let result = 0;
    for (let i = 0; i < 1000000; i++) {
      result += Math.random();
    }
    return result; // Runs every time .value is accessed
  }
}

// BUG 27: Not batching database operations
async function saveMany(items) {
  for (const item of items) {
    await db.insert(item); // Individual inserts - slow
  }
  // Should: await db.insertMany(items)
}

// BUG 28: Unnecessary array copies
function processArray(arr) {
  const copy1 = [...arr];
  const copy2 = copy1.slice();
  const copy3 = copy2.concat();
  return copy3.map((x) => x * 2); // Multiple unnecessary copies
}
