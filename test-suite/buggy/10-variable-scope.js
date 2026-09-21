// ============================================================================
// TEST SUITE: VARIABLE & SCOPE ISSUES (BUGGY CODE)
// Expected: Multiple WARNING and CRITICAL issues
// ============================================================================

// BUG 1: Using var (should use let/const)
var globalVar = "bad";
var counter = 0;
var userData = {};

function oldStyle() {
  var x = 10;
  var y = 20;
  var result = x + y;
  return result;
}

// BUG 2: Global variable pollution (missing var/let/const)
function calculate() {
  total = 100; // CRITICAL: Creates global variable!
  count = 5; // No var/let/const - global!
  return total / count;
}

// BUG 3: More accidental globals
function processData(data) {
  result = transform(data); // Global!
  output = format(result); // Global!
  return output;
}

// BUG 4: Variable hoisting confusion
function hoistingBug() {
  console.log(x); // undefined, not ReferenceError
  var x = 5;

  if (true) {
    var y = 10; // Hoisted to function scope
  }
  console.log(y); // 10 - leaked out of block!
}

// BUG 5: Variable shadowing
let count = 10;

function increment() {
  let count = 0; // Shadows outer count - confusing!
  count++;
  return count;
}

const value = 5;
{
  const value = 10; // Shadows outer value
  console.log(value); // 10
}
console.log(value); // 5 - which value?

// BUG 6: Loop variable leaking
for (var i = 0; i < 10; i++) {
  setTimeout(() => {
    console.log(i); // Always logs 10!
  }, 100);
}

// BUG 7: var in nested blocks
if (condition) {
  var temp = getValue(); // Leaks to function scope
}
console.log(temp); // Still accessible!

// BUG 8: Reusing var names
var data = getUserData();
// ... 100 lines later ...
var data = getProductData(); // Silently overwrites - no error!

// BUG 9: Function-scoped var in loops
for (var j = 0; j < array.length; j++) {
  var item = array[j]; // Same var reused each iteration
  items.push(() => item); // All closures reference same var
}

// BUG 10: Const not used when it should be
const API_KEY = "abc123"; // Should be const
const MAX_RETRIES = 3; // Should be const
const CONFIG = {}; // Should be const

// BUG 11: Attempting to reassign const (will error)
const user = { name: "John" };
user = { name: "Jane" }; // ERROR!

const arr = [1, 2, 3];
arr = [4, 5, 6]; // ERROR!

// BUG 12: Temporal dead zone confusion
function deadZone() {
  console.log(x); // ReferenceError: Cannot access before initialization
  const x = 5;
}

// BUG 13: Accidental global in IIFE
(() => {
  result = calculateValue(); // No var/let/const - global!
})();

// BUG 14: var in switch statement
switch (value) {
  case 1: {
    var x = "one"; // Hoisted out of case
    break;
  }
  case 2: {
    var x = "two"; // Same var - causes issues
    break;
  }
}
console.log(x); // Accessible outside switch
