// ============================================================================
// TEST SUITE: NULL SAFETY & DEFENSIVE PROGRAMMING (CLEAN CODE)
// Expected: No critical issues, minimal or no warnings
// ============================================================================

// GOOD: Null check before accessing properties
function setupButton() {
  const button = document.getElementById("submit-btn");
  if (!button) {
    console.warn("Submit button not found");
    return;
  }
  button.addEventListener("click", handleSubmit); // ubs:ignore
}

// GOOD: Optional chaining
function getUserCity(user) {
  return user?.profile?.address?.city ?? "Unknown";
}

// GOOD: Nullish coalescing
function getDisplayName(user) {
  return user?.name ?? "Anonymous";
}

// GOOD: Guard clause pattern
function processUser(user) {
  if (!user) {
    throw new Error("User is required");
  }

  if (!user.email) {
    throw new Error("User email is required");
  }

  return {
    name: user.name,
    email: user.email,
    role: user.role ?? "user",
  };
}

// GOOD: Array safety
function getFirstItem(items) {
  if (!Array.isArray(items) || items.length === 0) {
    return null;
  }
  return items[0];
}

// GOOD: DOM query with fallback
function getOrCreateElement(id) {
  let element = document.getElementById(id);
  if (!element) {
    element = document.createElement("div");
    element.id = id;
    document.body.appendChild(element);
  }
  return element;
}

// GOOD: Defensive property access
function extractData(response) {
  const data = response?.data;
  if (!data) {
    return [];
  }

  return data.items ?? [];
}

// GOOD: Type checking before operations
function calculateTotal(items) {
  if (!Array.isArray(items)) {
    return 0;
  }

  return items.reduce((sum, item) => {
    const price = Number(item?.price) || 0;
    return sum + price;
  }, 0);
}

// GOOD: Safe chaining with multiple checks
function renderUserProfile(user) {
  const container = document.querySelector(".profile-container");
  if (!container) return;

  const nameElement = container.querySelector(".user-name");
  if (nameElement && user?.name) {
    nameElement.textContent = user.name;
  }

  const emailElement = container.querySelector(".user-email");
  if (emailElement && user?.email) {
    emailElement.textContent = user.email;
  }
}

// GOOD: Validate before destructuring
function displayUserInfo({ name, email, phone } = {}) {
  console.log("Name:", name ?? "N/A");
  console.log("Email:", email ?? "N/A");
  console.log("Phone:", phone ?? "N/A");
}
