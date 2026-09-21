// ============================================================================
// TEST SUITE: NULL SAFETY & DEFENSIVE PROGRAMMING (BUGGY CODE)
// Expected: Multiple CRITICAL issues
// ============================================================================

// BUG 1: Unguarded DOM query (will crash if element doesn't exist)
const submitButton = document.getElementById("submit-btn");
submitButton.addEventListener("click", handleSubmit); // CRASH!

// BUG 2: querySelector without null check
const modal = document.querySelector(".modal");
modal.style.display = "block"; // CRASH if modal doesn't exist

// BUG 3: Deep property access without guards
function getUserCity(user) {
  return user.profile.address.city; // CRASH if any level is null/undefined
}

// BUG 4: Array access without length check
function getFirstItem(items) {
  return items[0].name; // CRASH if items is empty or items[0] is null
}

// BUG 5: Chained method calls without optional chaining
function processData(data) {
  const result = data.results.items.filter((x) => x.active); // CRASH if any level is null
  return result;
}

// BUG 6: Event listener on potentially null element
document.getElementById("form").addEventListener("submit", (e) => {
  e.preventDefault();
  // Will crash if #form doesn't exist
});

// BUG 7: Multiple DOM queries without checks
const header = document.querySelector("header");
const nav = header.querySelector("nav");
const links = nav.querySelectorAll("a"); // Triple danger!

// BUG 8: Accessing properties on function results without checking
function getUser() {
  return null; // Simulating API failure
}
const userName = getUser().name; // CRASH!

// BUG 9: Object destructuring without null check
function displayUser(user) {
  const { name, email, phone } = user; // CRASH if user is null/undefined
  console.log(name, email, phone);
}

// BUG 10: Nested optional but incomplete
const value = obj?.prop.nested.value; // Still crashes if prop is defined but nested isn't
