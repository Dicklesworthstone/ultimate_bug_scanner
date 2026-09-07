// ============================================================================
// TEST SUITE: PERFORMANCE BEST PRACTICES (CLEAN CODE)
// Expected: Optimized, efficient code patterns
// ============================================================================

// GOOD: Batch DOM updates with DocumentFragment
function renderManyItems(items) {
  const fragment = document.createDocumentFragment();

  items.forEach(item => {
    const li = document.createElement('li');
    li.textContent = item.name;
    fragment.appendChild(li);  // Build in memory
  });

  document.getElementById('list').appendChild(fragment);  // Single reflow
}

// GOOD: Debouncing expensive operations
function debounce(fn, delay) {
  let timeoutId;

  return function (...args) {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn.apply(this, args), delay);
  };
}

const handleSearchInput = debounce((query) => {
  performExpensiveSearch(query);
}, 300);

// GOOD: Throttling for scroll/resize handlers
function throttle(fn, limit) {
  let inThrottle;

  return function (...args) {
    if (!inThrottle) {
      fn.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

const handleScroll = throttle(() => {
  updateScrollPosition();
}, 100);

// GOOD: Memoization for expensive computations
function memoize(fn) {
  const cache = new Map();

  return function (...args) {
    const key = JSON.stringify(args);

    if (cache.has(key)) {
      return cache.get(key);
    }

    const result = fn.apply(this, args);
    cache.set(key, result);
    return result;
  };
}

const expensiveCalculation = memoize((n) => {
  // Complex computation
  return fibonacci(n);
});

// GOOD: Using Set for fast lookups
function findCommonElements(arr1, arr2) {
  const set1 = new Set(arr1);
  return arr2.filter(item => set1.has(item));  // O(n) instead of O(n²)
}

// GOOD: Efficient array operations with single pass
function processArray(items) {
  // Instead of multiple passes with filter, map, etc.
  return items.reduce((acc, item) => {
    if (item.active && item.value > 0) {
      acc.push(item.value * 2);
    }
    return acc;
  }, []);
}

// GOOD: String building with array join
function buildLargeString(items) {
  const parts = [];

  for (let i = 0; i < items.length; i++) {
    parts.push(items[i]);
  }

  return parts.join('');  // O(n) instead of O(n²)
}

// GOOD: Lazy evaluation with generators
function* lazyMap(iterable, fn) {
  for (const item of iterable) {
    yield fn(item);
  }
}

function* lazyFilter(iterable, predicate) {
  for (const item of iterable) {
    if (predicate(item)) {
      yield item;
    }
  }
}

// Usage: Process only what's needed
const numbers = Array.from({ length: 1000000 }, (_, i) => i);
const transformed = lazyFilter(
  lazyMap(numbers, x => x * 2),
  x => x > 100
);

// Only computes as we iterate
for (const value of transformed) {
  console.log(value);
  if (value > 200) break;  // Stop early
}

// GOOD: Object pooling for frequently created objects
class Vector3Pool {
  constructor() {
    this.pool = [];
  }

  acquire() {
    return this.pool.length > 0
      ? this.pool.pop()
      : { x: 0, y: 0, z: 0 };
  }

  release(vector) {
    vector.x = 0;
    vector.y = 0;
    vector.z = 0;
    this.pool.push(vector);
  }
}

// GOOD: Virtual scrolling for large lists
class VirtualList {
  constructor(container, items, itemHeight) {
    this.container = container;
    this.items = items;
    this.itemHeight = itemHeight;
    this.visibleCount = Math.ceil(container.clientHeight / itemHeight);
  }

  render(scrollTop) {
    const startIndex = Math.floor(scrollTop / this.itemHeight);
    const endIndex = Math.min(
      startIndex + this.visibleCount,
      this.items.length
    );

    // Only render visible items
    const fragment = document.createDocumentFragment();

    for (let i = startIndex; i < endIndex; i++) {
      const item = this.createItem(this.items[i], i);
      fragment.appendChild(item);
    }

    this.container.textContent = '';
    this.container.appendChild(fragment);
  }

  createItem(data, index) {
    const div = document.createElement('div');
    div.style.position = 'absolute';
    div.style.top = `${index * this.itemHeight}px`;
    div.style.height = `${this.itemHeight}px`;
    div.textContent = data;
    return div;
  }
}

// GOOD: RequestAnimationFrame for smooth animations
class Animator {
  constructor() {
    this.rafId = null;
  }

  animate(callback) {
    const frame = (timestamp) => {
      callback(timestamp);
      this.rafId = requestAnimationFrame(frame);
    };

    this.rafId = requestAnimationFrame(frame);
  }

  stop() {
    if (this.rafId) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
  }
}

// GOOD: Batch reading and writing DOM
function updateElements(elements, updates) {
  // Batch reads
  const measurements = elements.map(el => ({
    width: el.offsetWidth,
    height: el.offsetHeight
  }));

  // Batch writes
  elements.forEach((el, i) => {
    el.style.width = `${measurements[i].width * 1.1}px`;
    el.style.height = `${measurements[i].height * 1.1}px`;
  });
}

// GOOD: Web Workers for heavy computation
class WorkerPool {
  constructor(workerScript, poolSize = 4) {
    this.workers = Array.from(
      { length: poolSize },
      () => new Worker(workerScript)
    );
    this.queue = [];
    this.activeWorkers = new Set();
  }

  async execute(data) {
    return new Promise((resolve, reject) => {
      const worker = this.getAvailableWorker();

      worker.onmessage = (e) => {
        this.activeWorkers.delete(worker);
        resolve(e.data);
        this.processQueue();
      };

      worker.onerror = (error) => {
        this.activeWorkers.delete(worker);
        reject(error);
        this.processQueue();
      };

      this.activeWorkers.add(worker);
      worker.postMessage(data);
    });
  }

  getAvailableWorker() {
    return this.workers.find(w => !this.activeWorkers.has(w));
  }

  processQueue() {
    if (this.queue.length > 0 && this.activeWorkers.size < this.workers.length) {
      const task = this.queue.shift();
      this.execute(task.data).then(task.resolve).catch(task.reject);
    }
  }

  terminate() {
    this.workers.forEach(w => w.terminate());
  }
}

// GOOD: IndexedDB for client-side caching
class IndexedDBCache {
  constructor(dbName, storeName) {
    this.dbName = dbName;
    this.storeName = storeName;
    this.db = null;
  }

  async open() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName);
        }
      };
    });
  }

  async get(key) {
    const transaction = this.db.transaction([this.storeName], 'readonly');
    const store = transaction.objectStore(this.storeName);
    const request = store.get(key);

    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async set(key, value) {
    const transaction = this.db.transaction([this.storeName], 'readwrite');
    const store = transaction.objectStore(this.storeName);
    const request = store.put(value, key);

    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }
}

// GOOD: Intersection Observer for lazy loading
class LazyLoader {
  constructor(options = {}) {
    this.observer = new IntersectionObserver(
      this.handleIntersection.bind(this),
      options
    );
  }

  observe(element, callback) {
    element.dataset.lazyCallback = callback;
    this.observer.observe(element);
  }

  handleIntersection(entries) {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const callback = entry.target.dataset.lazyCallback;
        if (callback && typeof window[callback] === 'function') {
          window[callback](entry.target);
        }
        this.observer.unobserve(entry.target);
      }
    });
  }

  disconnect() {
    this.observer.disconnect();
  }
}

// GOOD: Efficient data structures
class PriorityQueue {
  constructor() {
    this.heap = [];
  }

  push(value, priority) {
    this.heap.push({ value, priority });
    this.bubbleUp(this.heap.length - 1);
  }

  pop() {
    if (this.heap.length === 0) return undefined;

    const top = this.heap[0];
    const bottom = this.heap.pop();

    if (this.heap.length > 0) {
      this.heap[0] = bottom;
      this.bubbleDown(0);
    }

    return top.value;
  }

  bubbleUp(index) {
    while (index > 0) {
      const parentIndex = Math.floor((index - 1) / 2);

      if (this.heap[index].priority >= this.heap[parentIndex].priority) {
        break;
      }

      [this.heap[index], this.heap[parentIndex]] =
        [this.heap[parentIndex], this.heap[index]];

      index = parentIndex;
    }
  }

  bubbleDown(index) {
    while (true) {
      const leftChild = 2 * index + 1;
      const rightChild = 2 * index + 2;
      let smallest = index;

      if (
        leftChild < this.heap.length &&
        this.heap[leftChild].priority < this.heap[smallest].priority
      ) {
        smallest = leftChild;
      }

      if (
        rightChild < this.heap.length &&
        this.heap[rightChild].priority < this.heap[smallest].priority
      ) {
        smallest = rightChild;
      }

      if (smallest === index) break;

      [this.heap[index], this.heap[smallest]] =
        [this.heap[smallest], this.heap[index]];

      index = smallest;
    }
  }
}
