// ============================================================================
// TEST SUITE: API & FRAMEWORK MISUSE (BUGGY CODE)
// Expected: 20+ WARNING/CRITICAL issues - Common framework/library mistakes
// ============================================================================

// BUG 1: Array.forEach return value ignored
function findUser(users, id) {
  users.forEach((user) => {
    if (user.id === id) {
      return user; // Doesn't return from function! Returns from forEach callback
    }
  });
}

// BUG 2: Modifying array while iterating
function removeEvenNumbers(arr) {
  arr.forEach((num, index) => {
    if (num % 2 === 0) {
      arr.splice(index, 1); // Modifies array being iterated - skips elements
    }
  });
}

// BUG 3: Misunderstanding Promise.all
async function fetchUsers(ids) {
  const users = [];
  await Promise.all(
    ids.map((id) => {
      users.push(fetchUser(id)); // Pushes promises, not results!
    }),
  );
  return users; // Returns array of promises
}

// BUG 4: Not awaiting async forEach
async function processItems(items) {
  items.forEach(async (item) => {
    await processItem(item); // forEach doesn't wait!
  });
  console.log("Done"); // Logs before processing completes
}

// BUG 5: Assuming parseInt always returns number
function parseNumbers(strings) {
  return strings.map((s) => parseInt(s)); // Could return NaN
}

// BUG 6: Misusing Array.find with side effects
function removeFirst(arr, value) {
  arr.find((item, index) => {
    if (item === value) {
      arr.splice(index, 1); // find() should be pure!
      return true;
    }
  });
}

// BUG 7: Wrong this context
class Counter {
  constructor() {
    this.count = 0;
  }

  increment() {
    this.count++;
  }

  setupButton() {
    const button = document.getElementById("btn");
    button.addEventListener("click", this.increment); // 'this' will be button!
  }
}

// BUG 8: Mutating frozen object
const config = Object.freeze({ debug: false });

function enableDebug() {
  config.debug = true; // Silent failure in non-strict mode, error in strict
}

// BUG 9: Using delete on arrays
function removeItem(arr, index) {
  delete arr[index]; // Leaves undefined hole, doesn't change length
}

// BUG 10: Chaining optional methods incorrectly
function getUserEmail(user) {
  return user.getProfile().getContactInfo().email;
  // Should be: user?.getProfile()?.getContactInfo()?.email
}

// BUG 11: Misunderstanding hoisting
function getValue() {
  console.log(value); // undefined (hoisted)
  var value = 10;
  return value;
}

// BUG 12: Using Array.reduce without initial value
function sum(numbers) {
  return numbers.reduce((a, b) => a + b); // Fails on empty array
}

// BUG 13: Assuming JSON.parse never fails
function loadConfig(jsonString) {
  const config = JSON.parse(jsonString); // Throws on invalid JSON
  return config;
}

// BUG 14: Using arguments object incorrectly
function multiply(a, b) {
  arguments[0] = 10; // In strict mode, doesn't affect 'a'
  return a * b;
}

// BUG 15: Confusing == vs ===
function isZero(value) {
  return value == 0; // true for '', [], false, etc.
}

// BUG 16: Misusing setTimeout
for (var i = 0; i < 5; i++) {
  setTimeout(() => console.log(i), 1000); // Logs "5" five times
}

// BUG 17: Not handling Promise rejection
function fetchData() {
  Promise.resolve()
    .then(() => riskyOperation())
    .then((data) => processData(data));
  // No .catch() - unhandled rejection
}

// BUG 18: Using in operator incorrectly
const obj = { name: "John" };
if (obj.name in obj) {
  // Wrong! Should be: 'name' in obj
  console.log("Has name");
}

// BUG 19: Confusing Object.keys with iteration order
function getFirstKey(obj) {
  return Object.keys(obj)[0]; // Order not guaranteed for all object types
}

// BUG 20: Using Array constructor with single number
function createArray(n) {
  const arr = new Array(n); // Creates sparse array with holes
  return arr.map(() => 0); // map() skips holes - doesn't work!
}

// BUG 21: Modifying object during Object.keys iteration
function cleanObject(obj) {
  Object.keys(obj).forEach((key) => {
    if (obj[key] === null) {
      delete obj[key]; // Modifying during iteration - unpredictable
    }
  });
}

// BUG 22: Comparing NaN incorrectly
function hasNaN(arr) {
  return arr.includes(NaN); // Works, but arr.indexOf(NaN) doesn't!
}

// BUG 23: Assuming typeof is always reliable
function isArray(value) {
  return typeof value === "array"; // Wrong! Returns 'object'
}

// BUG 24: Using parseFloat without validation
function parsePrice(price) {
  return parseFloat(price); // parseFloat('abc') returns NaN
}

// BUG 25: Closure in loop without new scope
const functions = [];
for (var i = 0; i < 3; i++) {
  functions.push(() => {
    return i; // All closures share same 'i'
  });
}

// BUG 26: Misusing Array.sort without comparator
function sortNumbers(numbers) {
  return numbers.sort(); // Sorts as strings! [1, 10, 2, 20, 3]
}

// BUG 27: Confusing slice vs splice
function removeFirst(arr) {
  return arr.slice(0, 1); // Returns removed item, doesn't modify original
  // Should be: arr.splice(0, 1) to modify in-place
}

// BUG 28: Using constructor for primitives
function createNumber() {
  return new Number(42); // Returns object, not primitive
}

// BUG 29: Assuming Array.filter mutates
function removeNulls(arr) {
  arr.filter((x) => x !== null); // Returns new array, doesn't modify 'arr'
  return arr; // Still contains nulls!
}

// BUG 30: Using Array.concat incorrectly
function addItems(arr, items) {
  arr.concat(items); // Returns new array, doesn't modify 'arr'
  // Should be: return arr.concat(items) or arr.push(...items)
}
