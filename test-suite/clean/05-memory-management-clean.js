// ============================================================================
// TEST SUITE: MEMORY MANAGEMENT (CLEAN CODE)
// Expected: No memory leaks or resource management issues
// ============================================================================

// GOOD: Proper event listener cleanup
class Component {
  constructor(elementId) {
    this.element = document.getElementById(elementId);
    this.handleClick = this.handleClick.bind(this);
    this.element.addEventListener("click", this.handleClick); // ubs:ignore
  }

  handleClick(event) {
    console.log("Clicked:", event.target);
  }

  destroy() {
    this.element.removeEventListener("click", this.handleClick);
    this.element = null; // Release reference
  }
}

// GOOD: Timer cleanup
class AutoRefresh {
  constructor(interval) {
    this.intervalId = null;
    this.interval = interval;
  }

  start(callback) {
    this.intervalId = setInterval(callback, this.interval);
  }

  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }
}

// GOOD: React-style useEffect cleanup
function useInterval(callback, delay) {
  const intervalId = setInterval(callback, delay);

  // Return cleanup function
  return () => {
    clearInterval(intervalId);
  };
}

// Usage:
// const cleanup = useInterval(() => console.log('tick'), 1000);
// Later: cleanup();

// GOOD: WeakMap for metadata (allows GC)
const objectMetadata = new WeakMap();

function attachMetadata(obj, metadata) {
  objectMetadata.set(obj, metadata);
  // When obj is no longer referenced, metadata is GC'd
}

function getMetadata(obj) {
  return objectMetadata.get(obj);
}

// GOOD: Cache with size limit
class LRUCache {
  constructor(maxSize = 100) {
    this.maxSize = maxSize;
    this.cache = new Map();
  }

  get(key) {
    if (!this.cache.has(key)) {
      return undefined;
    }

    // Move to end (most recently used)
    const value = this.cache.get(key);
    this.cache.delete(key);
    this.cache.set(key, value);
    return value;
  }

  set(key, value) {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    }

    this.cache.set(key, value);

    // Evict oldest if over limit
    if (this.cache.size > this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
  }

  clear() {
    this.cache.clear();
  }
}

// GOOD: Proper resource cleanup with try-finally
async function processFileWithCleanup(filename) {
  const fileHandle = await fs.promises.open(filename, "r");

  try {
    const buffer = Buffer.alloc(1024);
    await fileHandle.read(buffer, 0, buffer.length, 0);
    return buffer;
  } finally {
    await fileHandle.close(); // Always cleanup
  }
}

// GOOD: Avoiding circular references
function createDataStructure() {
  const parent = { name: "parent" };
  const child = { name: "child" };

  // Instead of: parent.child = child; child.parent = parent;
  // Use WeakRef or just IDs:
  parent.childId = "child-1";
  child.parentId = "parent-1";

  return { parent, child };
}

// GOOD: Stream processing for large data
const { Readable } = require("stream");

async function processLargeFile(filename) {
  const stream = fs.createReadStream(filename, { encoding: "utf8" });

  for await (const chunk of stream) {
    processChunk(chunk); // Process in chunks, not all at once
  }
}

// GOOD: Pagination instead of loading everything
async function getAllUsersInBatches(batchSize = 100) {
  let offset = 0;
  const results = [];

  while (true) {
    const batch = await db.query("SELECT * FROM users LIMIT ? OFFSET ?", [batchSize, offset]);

    if (batch.length === 0) break;

    // Process batch immediately, don't accumulate
    await processBatch(batch);

    offset += batchSize;
  }
}

// GOOD: Clearing references in arrays
class TaskQueue {
  constructor() {
    this.tasks = [];
  }

  addTask(task) {
    this.tasks.push(task);
  }

  async processAll() {
    while (this.tasks.length > 0) {
      const task = this.tasks.shift(); // Remove from array
      await task();
      // Task is now eligible for GC
    }
  }

  clear() {
    this.tasks.length = 0; // Clear array properly
  }
}

// GOOD: Avoiding detached DOM nodes
class DOMManager {
  constructor() {
    this.elements = new WeakMap();
  }

  createElement(tag, data) {
    const element = document.createElement(tag);
    this.elements.set(element, data);
    return element;
  }

  removeElement(element) {
    if (element.parentNode) {
      element.parentNode.removeChild(element);
    }
    // WeakMap entry is automatically cleaned up
  }
}

// GOOD: Object pooling for frequently created objects
class ObjectPool {
  constructor(factory, resetFn) {
    this.factory = factory;
    this.resetFn = resetFn;
    this.pool = [];
  }

  acquire() {
    if (this.pool.length > 0) {
      return this.pool.pop();
    }
    return this.factory();
  }

  release(obj) {
    this.resetFn(obj);
    this.pool.push(obj);
  }

  clear() {
    this.pool.length = 0;
  }
}

// Usage:
const vectorPool = new ObjectPool(
  () => ({ x: 0, y: 0, z: 0 }),
  (v) => {
    v.x = 0;
    v.y = 0;
    v.z = 0;
  },
);

// GOOD: AbortController for cleanup
async function fetchWithAbort(url, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { signal: controller.signal });
    return await response.json();
  } catch (error) {
    if (error.name === "AbortError") {
      console.log("Request was aborted");
    }
    throw error;
  } finally {
    clearTimeout(timeoutId); // Cleanup timeout
  }
}

// GOOD: Proper closure cleanup
function createCounter() {
  let count = 0;
  const listeners = new Set();

  return {
    increment() {
      count++;
      listeners.forEach((fn) => fn(count));
    },

    addListener(fn) {
      listeners.add(fn);
      // Return cleanup function
      return () => listeners.delete(fn);
    },

    destroy() {
      listeners.clear();
      count = 0;
    },
  };
}

// GOOD: Using FinalizationRegistry for cleanup notifications
const registry = new FinalizationRegistry((heldValue) => {
  console.log(`Object with ID ${heldValue} was garbage collected`);
  cleanupExternalResource(heldValue);
});

function createTrackedObject(id) {
  const obj = { id };
  registry.register(obj, id); // Track for cleanup
  return obj;
}

// GOOD: Avoiding memory leaks in closures
function createHandlers() {
  const handlers = [];

  for (let i = 0; i < 10; i++) {
    // Don't capture entire scope - only what's needed
    const index = i;
    handlers.push(() => console.log(index));
  }

  return handlers;
}

// GOOD: Properly managing WebSocket connections
class WebSocketManager {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.listeners = new Map();
  }

  connect() {
    this.ws = new WebSocket(this.url);

    this.ws.onmessage = (event) => {
      const listeners = this.listeners.get("message") || [];
      listeners.forEach((fn) => fn(event.data));
    };

    return this;
  }

  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event).push(callback);

    // Return unsubscribe function
    return () => {
      const listeners = this.listeners.get(event);
      const index = listeners.indexOf(callback);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    };
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.listeners.clear();
  }
}
