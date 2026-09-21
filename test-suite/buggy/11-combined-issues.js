// ============================================================================
// TEST SUITE: COMBINED REAL-WORLD ISSUES (BUGGY CODE)
// This file simulates a realistic codebase with multiple bug types
// Expected: Many CRITICAL, WARNING, and INFO issues across categories
// ============================================================================

// Realistic user authentication module with multiple bugs

var currentUser = null; // BUG: Using var

// BUG: Hardcoded API key
const API_KEY = "sk_live_abc123xyz789";

// BUG: parseInt without radix
function parseUserId(id) {
  return parseInt(id);
}

// BUG: Unguarded DOM query + innerHTML XSS
function displayUserProfile(userData) {
  const profileDiv = document.getElementById("profile");
  profileDiv.innerHTML = userData.bio; // XSS risk + null pointer risk

  const avatar = document.querySelector(".avatar");
  avatar.src = userData.avatarUrl; // Null pointer risk
}

// BUG: Missing await + empty catch + no radix
async function loginUser(username, password) {
  try {
    const userId = parseInt(username); // No radix
    const response = fetchUserData(userId); // Missing await!

    if (response.password == password) {
      // Loose equality
      currentUser = response;
      return true;
    }
  } catch (e) {
    // Empty catch - silent failure
  }
  return false;
}

// BUG: Division by zero + NaN comparison
function calculateUserScore(points, attempts) {
  const average = points / attempts; // Division by zero if attempts = 0

  if (average === NaN) {
    // Always false!
    return 0;
  }

  return average;
}

// BUG: eval() + global variable
function executeUserScript(code) {
  result = eval(code); // eval + global variable pollution
  return result;
}

// BUG: Memory leak - event listener never removed
function setupUserPanel() {
  const panel = document.getElementById("user-panel");
  panel.addEventListener("click", handlePanelClick);
  // No cleanup

  setInterval(() => {
    updateUserStatus(); // Never cleared
  }, 5000);
}

// BUG: Promise without catch
function loadUserData(userId) {
  fetch(`/api/users/${userId}`)
    .then((res) => res.json())
    .then((data) => {
      displayUserProfile(data);
    });
  // No error handling
}

// BUG: Debugger statement + console.log sensitive data
function processPayment(cardNumber, cvv, amount) {
  debugger; // Left in production
  console.log("Processing payment:", cardNumber, cvv); // Logging sensitive data

  const total = amount / 1;
  return total;
}

// BUG: Switch without default + missing break
function getUserRole(roleId) {
  let role;
  switch (roleId) {
    case 1:
      role = "admin";
    // Missing break!
    case 2:
      role = "user";
      break;
    case 3:
      role = "guest";
  }
  return role;
}

// BUG: Deep property access without guards
function getUserCity(user) {
  return user.profile.address.city.name; // Multiple null pointer risks
}

// BUG: await in loop + JSON.parse without try/catch
async function processUserList(users) {
  const results = [];

  for (const user of users) {
    const data = await fetchUserDetails(user.id); // Sequential - slow!
    const parsed = JSON.parse(data); // No error handling
    results.push(parsed);
  }

  return results;
}

// BUG: Throwing string instead of Error
function validateUserAge(age) {
  if (age < 0) {
    throw "Invalid age"; // Should be Error object
  }
  if (age > 150) {
    throw "Age too high";
  }
}

// BUG: Type coercion issues
function isUserActive(user) {
  return user.lastLogin == Date.now(); // Loose equality
}

// BUG: Nested ternary nightmare
const userStatus = user.isActive
  ? user.isPremium
    ? user.hasSubscription
      ? "premium-active"
      : "premium-inactive"
    : "basic-active"
  : user.isBanned
    ? "banned"
    : "inactive";

// BUG: String concatenation in loop
function buildUserList(users) {
  let html = "";
  for (let i = 0; i < users.length; i++) {
    html += "<li>" + users[i].name + "</li>"; // Inefficient
  }
  return html;
}

// BUG: Circular reference
const userCache = {};
userCache.self = userCache;

// BUG: HTTP URL in production
const USER_API = "http://api.example.com/users";

// TODO: Fix all these security issues
// FIXME: Memory leaks everywhere
// HACK: Temporary solution
// XXX: This is broken
