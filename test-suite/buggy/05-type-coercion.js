// ============================================================================
// TEST SUITE: TYPE COERCION & COMPARISON TRAPS (BUGGY CODE)
// Expected: Multiple CRITICAL and WARNING issues
// ============================================================================

// BUG 1: Loose equality (== instead of ===)
function checkValue(value) {
  if (value == null) {
    // Matches both null AND undefined
    return "empty";
  }
  if (value == 0) {
    // Also matches false, '', []
    return "zero";
  }
  return "has value";
}

// BUG 2: More loose equality bugs
const isAdmin = user.role == "admin"; // Should be ===
const isEmpty = array.length == 0; // Should be ===
const isTrue = flag == true; // Should be ===

// BUG 3: Comparing different types
function validateInput(input) {
  if (input === "true") {
    // Comparing string to boolean concept
    return true;
  }
  if (typeof input === "number") {
    return input === "0"; // Comparing number to string
  }
}

// BUG 4: typeof with wrong string literal
function checkType(value) {
  if (typeof value === "array") {
    // WRONG! No such type
    return "is array";
  }
  if (typeof value === "null") {
    // WRONG! typeof null is 'object'
    return "is null";
  }
  if (typeof value === "numeric") {
    // WRONG! Should be 'number'
    return "is number";
  }
}

// BUG 5: Truthy/falsy confusion
function processArray(arr) {
  if (arr.length) {
    // Truthy check - works but not explicit
    return arr[0];
  }
}

function hasItems(list) {
  return list.length; // Returns number, not boolean
}

// BUG 6: Implicit string concatenation causing bugs
function calculateTotal(price, quantity) {
  return price + quantity; // If either is string, concatenates instead of adds!
}

const result = "5" + 3; // '53' not 8
const value = 5 + "3"; // '53' not 8

// BUG 7: String coercion in comparisons
const age = "25";
if (age > 18) {
  // Works by accident, but fragile
  console.log("adult");
}

// BUG 8: NaN comparisons
function isInvalid(value) {
  if (value === NaN) {
    // CRITICAL: This is ALWAYS false!
    return true;
  }
  if (value == NaN) {
    // Also always false
    return true;
  }
  return false;
}

// BUG 9: Using global isNaN instead of Number.isNaN
function validateNumber(input) {
  if (isNaN(input)) {
    // isNaN('hello') returns true - type coercion!
    return false;
  }
  return true;
}

// BUG 10: Implicit boolean conversion
function isEnabled(feature) {
  return feature.enabled; // Could be undefined, null, 0, '', etc.
}

// BUG 11: null vs undefined confusion
function getDefault(value) {
  return value || "default"; // Replaces 0, false, '' with default too!
}

// BUG 12: Array/Object in boolean context
if ([]) {
  // Empty array is truthy!
  console.log("This runs!");
}

if ({}) {
  // Empty object is truthy!
  console.log("This runs too!");
}

// BUG 13: Plus operator ambiguity
const total = userInput + 10; // Addition or concatenation?
const count = "5" + 5; // '55'
