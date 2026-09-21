// ============================================================================
// TEST SUITE: ERROR HANDLING ANTI-PATTERNS (BUGGY CODE)
// Expected: Multiple CRITICAL issues
// ============================================================================

// BUG 1: Empty catch block (swallowing errors)
try {
  riskyOperation();
} catch (e) {
  // Silent failure - debugging nightmare!
}

// BUG 2: Catch without error parameter
try {
  parseJSON(data);
} catch {
  console.log("Error occurred"); // No error details!
}

// BUG 3: Try without finally (resource leak potential)
function processFile(filename) {
  const file = openFile(filename);
  try {
    return processData(file.read());
  } catch (e) {
    console.error(e);
  }
  // file never closed if error occurs!
}

// BUG 4: Generic error messages
function saveUser(user) {
  if (!user.email) {
    throw new Error("Error"); // Useless message
  }
  if (!user.name) {
    throw new Error("Error occurred"); // Also useless
  }
}

// BUG 5: Throwing strings instead of Error objects
function validateInput(input) {
  if (!input) {
    throw "Invalid input"; // Should be: throw new Error('Invalid input')
  }
  if (input.length < 3) {
    throw "Too short"; // No stack trace!
  }
}

// BUG 6: Catch that doesn't re-throw or handle
async function fetchData() {
  try {
    const response = await fetch("/api/data");
    return response.json();
  } catch (error) {
    console.log("Fetch failed"); // Logs but doesn't propagate or handle
  }
  // Returns undefined on error - caller doesn't know it failed!
}

// BUG 7: Multiple catches without specificity
try {
  dangerousOperation();
} catch (e) {
  // Catches ALL errors - can't handle different error types differently
  console.log("Something went wrong");
}

// BUG 8: JSON.parse without try/catch
function loadConfig(json) {
  const config = JSON.parse(json); // Throws on invalid JSON
  return config;
}

function handleData(data) {
  const obj = JSON.parse(data); // No error handling
  processObject(obj);
}

// BUG 9: Catch that catches too much
try {
  const user = await getUser();
  const posts = await getPosts(user.id);
  const comments = await getComments(posts);
  processEverything(user, posts, comments);
} catch (e) {
  // Which operation failed? No way to know!
  console.error("Operation failed");
}

// BUG 10: Error logged but not thrown
function validateAge(age) {
  if (age < 0) {
    console.error("Invalid age");
    // Should throw or return error - just logging isn't enough
  }
  if (age > 150) {
    console.error("Age too high");
    // Continues executing with invalid data!
  }
  return age;
}

// BUG 11: Swallowing errors in async functions
async function saveData(data) {
  try {
    await db.save(data);
  } catch (e) {
    // Silent failure in async function
  }
}

// BUG 12: Finally block with early return
function getData() {
  try {
    return fetchData();
  } finally {
    cleanup();
    return null; // Overrides the try return!
  }
}

// BUG 13: Error constructor without 'new'
function handleError(msg) {
  throw Error(msg); // Works but should use 'new Error(msg)'
}

// BUG 14: Catch without doing anything
fetch("/api/data")
  .then((res) => res.json())
  .catch((e) => {}); // Empty catch - silent failure
