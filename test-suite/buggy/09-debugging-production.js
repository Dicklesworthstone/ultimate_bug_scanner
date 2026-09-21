// ============================================================================
// TEST SUITE: DEBUGGING & PRODUCTION CODE (BUGGY CODE)
// Expected: Multiple CRITICAL and WARNING issues
// ============================================================================

// BUG 1: debugger statements left in code
function processPayment(amount) {
  debugger; // CRITICAL: Must remove before production!
  const total = calculateTotal(amount);
  debugger; // Another one!
  return total;
}

// BUG 2: Excessive console.log statements
console.log("App started");
console.log("User:", user);
console.log("Config:", config);
console.log("Environment:", process.env);
console.log("Debug info:", debugData);
console.log("Processing...");
console.log("Step 1 complete");
console.log("Step 2 complete");
console.log("Step 3 complete");
console.log("Final result:", result);
console.log("Done!");

function getData() {
  console.log("Fetching data...");
  const data = fetch("/api/data");
  console.log("Data received:", data);
  console.log("Processing data...");
  const processed = process(data);
  console.log("Processed:", processed);
  return processed;
}

// BUG 3: console.log with sensitive data
console.log("User password:", user.password); // CRITICAL: Security leak!
console.log("API Key:", apiKey);
console.log("Auth token:", authToken);
console.log("Credit card:", payment.cardNumber);
console.log("SSN:", user.ssn);

// BUG 4: alert/confirm/prompt (blocking UI)
function deleteItem(id) {
  alert("Deleting item " + id); // Poor UX - blocks everything
  if (confirm("Are you sure?")) {
    // Blocks browser
    const name = prompt("Enter your name:"); // More blocking
    processDelete(id, name);
  }
}

// BUG 5: console.dir/console.table in production
console.dir(complexObject);
console.table(dataArray);
console.trace("Debug trace");
console.time("operation");
doOperation();
console.timeEnd("operation");

// BUG 6: Development-only code not removed
if (typeof window !== "undefined") {
  window.DEBUG = true; // Exposes debug mode
  window.__REDUX_DEVTOOLS__ = true;
  window.devMode = true;
}

// BUG 7: TODO/FIXME markers (many)
// TODO: Fix this bug
function brokenFunction() {
  // FIXME: This doesn't work properly
  // HACK: Temporary workaround
  // XXX: This is dangerous
  return null;
}

// TODO: Implement proper error handling
// FIXME: Memory leak here
// HACK: Remove this after testing
// XXX: Security issue

// BUG 8: console.warn/error overuse
console.warn("This might be an issue");
console.warn("Check this value");
console.warn("Potential problem");
console.error("Error state");
console.error("Failed operation");

// BUG 9: Development URLs hardcoded
const API_URL = "http://localhost:3000/api"; // Should be environment variable
const WS_URL = "ws://localhost:8080";
const DEBUG_ENDPOINT = "http://127.0.0.1:9999/debug";

// BUG 10: Test code not removed
function runTests() {
  // This is test code that should be removed
  assert(1 + 1 === 2);
  console.log("Test passed");
}
runTests(); // Still being called in production!

// BUG 11: Performance measurement code left in
const start = performance.now();
doWork();
const end = performance.now();
console.log("Execution time:", end - start);

// BUG 12: Debug flags
const DEBUG = true; // Should be false in production
const VERBOSE_LOGGING = true;
const ENABLE_DEBUG_PANEL = true;

if (DEBUG) {
  console.log("Debug mode active");
  console.log("All data:", getAllDebugData());
}
