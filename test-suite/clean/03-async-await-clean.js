// ============================================================================
// TEST SUITE: ASYNC/AWAIT (CLEAN CODE)
// Expected: No critical async issues
// ============================================================================

// GOOD: Proper async/await usage
async function fetchUser(id, signal = AbortSignal.timeout(5000)) {
  const response = await fetch(`/api/users/${id}`, { signal });
  return response.json();
}

// GOOD: Error handling with try/catch
async function loadUserData(userId, signal = AbortSignal.timeout(5000)) {
  try {
    const response = await fetch(`/api/users/${userId}`, { signal });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error("Failed to load user:", error);
    throw error; // Re-throw for caller to handle
  }
}

// GOOD: Promise.all for parallel operations
async function loadAllData(userId) {
  try {
    const [user, posts, comments] = await Promise.all([
      fetchUser(userId),
      fetchPosts(userId),
      fetchComments(userId),
    ]);

    return { user, posts, comments };
  } catch (error) {
    console.error("Failed to load data:", error);
    throw error;
  }
}

// GOOD: Promise with .catch()
function fetchData(signal = AbortSignal.timeout(5000)) {
  return fetch("/api/data", { signal })
    .then((res) => res.json())
    .then((data) => processData(data))
    .catch((error) => {
      console.error("Fetch failed:", error);
      throw error;
    });
}

// GOOD: Handling multiple promises with error handling
async function processItems(items) {
  const results = await Promise.all(
    items.map((item) =>
      processItem(item).catch((err) => {
        console.error(`Failed to process item ${item.id}:`, err);
        return null; // Continue with other items
      }),
    ),
  );

  return results.filter((r) => r !== null);
}

// GOOD: Using Promise.allSettled for handling partial failures
async function fetchMultipleEndpoints(urls, signal = AbortSignal.timeout(5000)) {
  const results = await Promise.allSettled(urls.map((url) => fetch(url, { signal })));

  return results.map((result, index) => {
    if (result.status === "fulfilled") {
      return result.value;
    } else {
      console.error(`Failed to fetch ${urls[index]}:`, result.reason);
      return null;
    }
  });
}

// GOOD: Async initialization pattern
class DataService {
  constructor() {
    this.initialized = false;
  }

  async init() {
    try {
      this.data = await this.loadData();
      this.initialized = true;
    } catch (error) {
      console.error("Initialization failed:", error);
      throw error;
    }
  }

  async loadData() {
    const response = await fetch("/api/initial-data", { signal: AbortSignal.timeout(5000) });
    return response.json();
  }
}

// GOOD: Proper await in loops when sequential is needed
async function processSequentially(items) {
  const results = [];

  for (const item of items) {
    try {
      const result = await processItem(item);
      results.push(result);
    } catch (error) {
      console.error(`Failed to process item ${item.id}:`, error);
      // Continue with next item
    }
  }

  return results;
}

// GOOD: Race with proper error handling
async function fetchWithTimeout(url, timeout = 5000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === "AbortError") {
      throw new Error("Request timeout");
    }
    throw error;
  }
}

// GOOD: Async map with proper error handling
async function asyncMap(array, asyncFn) {
  return Promise.all(array.map(asyncFn));
}

// GOOD: Return await when needed for stack traces
async function getUserWithLogging(id) {
  try {
    return await fetchUser(id); // Keep await for better stack trace
  } catch (error) {
    console.error("Failed to get user:", error);
    throw error;
  }
}
