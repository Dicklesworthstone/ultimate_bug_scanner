// ============================================================================
// TEST SUITE: ERROR HANDLING (CLEAN CODE)
// Expected: No critical error handling issues
// ============================================================================

// GOOD: Try-catch with specific error handling
async function loadUserData(userId, signal = AbortSignal.timeout(5000)) {
  try {
    const response = await fetch(`/api/users/${userId}`, { signal });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    if (error.name === "TypeError") {
      console.error("Network error:", error.message);
      throw new Error("Failed to connect to server");
    } else if (error.message.includes("HTTP error")) {
      console.error("API error:", error.message);
      throw error;
    } else {
      console.error("Unexpected error:", error);
      throw new Error("An unexpected error occurred");
    }
  }
}

// GOOD: Error object with context
class ValidationError extends Error {
  constructor(message, field, value) {
    super(message);
    this.name = "ValidationError";
    this.field = field;
    this.value = value;
    Error.captureStackTrace(this, ValidationError);
  }
}

function validateEmail(email) {
  if (!email) {
    throw new ValidationError("Email is required", "email", email);
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new ValidationError("Invalid email format", "email", email);
  }

  return true;
}

// GOOD: Try-catch with finally for cleanup
async function processFile(filename) {
  let fileHandle;

  try {
    fileHandle = await openFile(filename);
    const data = await fileHandle.read();
    return processData(data);
  } catch (error) {
    console.error(`Failed to process file ${filename}:`, error);
    throw error;
  } finally {
    if (fileHandle) {
      await fileHandle.close(); // Always cleanup
    }
  }
}

// GOOD: Promise rejection handling
function fetchWithErrorHandling(url, signal = AbortSignal.timeout(5000)) {
  return fetch(url, { signal })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .catch((error) => {
      console.error("Fetch failed:", error);
      // Return fallback or rethrow
      throw error;
    });
}

// GOOD: Multiple catch blocks for different error types
async function complexOperation() {
  try {
    const data = await fetchData();
    const parsed = JSON.parse(data); // ubs:ignore
    return await saveToDatabase(parsed);
  } catch (error) {
    if (error instanceof SyntaxError) {
      console.error("JSON parsing failed:", error.message);
      throw new Error("Invalid data format");
    } else if (error.name === "DatabaseError") {
      console.error("Database operation failed:", error);
      throw new Error("Failed to save data");
    } else {
      console.error("Unexpected error:", error);
      throw error;
    }
  }
}

// GOOD: Error boundary pattern
class ErrorBoundary {
  static wrap(fn) {
    return async (...args) => {
      try {
        return await fn(...args);
      } catch (error) {
        console.error("Error in wrapped function:", error);
        ErrorBoundary.handleError(error);
        throw error;
      }
    };
  }

  static handleError(error) {
    // Centralized error handling
    if (process.env.NODE_ENV === "production") {
      // Send to monitoring service
      ErrorReporter.report(error);
    } else {
      console.error(error.stack);
    }
  }
}

// GOOD: Validation before risky operations
function divideNumbers(a, b) {
  if (typeof a !== "number" || typeof b !== "number") {
    throw new TypeError("Both arguments must be numbers");
  }

  if (b === 0) {
    throw new RangeError("Cannot divide by zero");
  }

  if (!Number.isFinite(a) || !Number.isFinite(b)) {
    throw new RangeError("Arguments must be finite numbers");
  }

  return a / b;
}

// GOOD: Safe JSON parsing
function parseJSON(jsonString, fallback = null) {
  try {
    return JSON.parse(jsonString); // ubs:ignore
  } catch (error) {
    console.warn("Failed to parse JSON:", error.message);
    return fallback;
  }
}

// GOOD: Retry logic with error handling
async function fetchWithRetry(url, maxRetries = 3) {
  let lastError;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(5000) });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      lastError = error;
      console.warn(`Attempt ${attempt} failed:`, error.message);

      if (attempt < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
      }
    }
  }

  throw new Error(`Failed after ${maxRetries} attempts: ${lastError.message}`);
}

// GOOD: Error context preservation
async function processUserData(userId) {
  try {
    const user = await fetchUser(userId);
    const profile = await enrichUserProfile(user);
    return profile;
  } catch (error) {
    // Add context without losing original error
    error.userId = userId;
    error.timestamp = new Date().toISOString();
    throw error;
  }
}

// GOOD: Graceful degradation
async function getUserPreferences(userId) {
  try {
    return await fetchUserPreferences(userId);
  } catch (error) {
    console.warn("Failed to load user preferences, using defaults:", error);
    return getDefaultPreferences();
  }
}

// GOOD: Result type pattern for error handling
class Result {
  constructor(success, value, error) {
    this.success = success;
    this.value = value;
    this.error = error;
  }

  static ok(value) {
    return new Result(true, value, null);
  }

  static err(error) {
    return new Result(false, null, error);
  }

  unwrap() {
    if (!this.success) {
      throw this.error;
    }
    return this.value;
  }

  unwrapOr(defaultValue) {
    return this.success ? this.value : defaultValue;
  }
}

async function safeOperation() {
  try {
    const data = await riskyOperation();
    return Result.ok(data);
  } catch (error) {
    return Result.err(error);
  }
}

// GOOD: Input validation with descriptive errors
function createUser(userData) {
  const errors = [];

  if (!userData.email) {
    errors.push({ field: "email", message: "Email is required" });
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(userData.email)) {
    errors.push({ field: "email", message: "Invalid email format" });
  }

  if (!userData.password || userData.password.length < 8) {
    errors.push({ field: "password", message: "Password must be at least 8 characters" });
  }

  if (errors.length > 0) {
    const error = new Error("Validation failed");
    error.name = "ValidationError";
    error.errors = errors;
    throw error;
  }

  return {
    email: userData.email,
    passwordHash: hashPassword(userData.password),
  };
}
