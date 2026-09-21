// ============================================================================
// TEST SUITE: MATH & ARITHMETIC PITFALLS (BUGGY CODE)
// Expected: Multiple CRITICAL and WARNING issues
// ============================================================================

// BUG 1: Division by zero (potential)
function calculateAverage(numbers) {
  const sum = numbers.reduce((a, b) => a + b, 0);
  return sum / numbers.length; // Infinity if empty array!
}

// BUG 2: Division by variable without check
function getPercentage(value, total) {
  return (value / total) * 100; // NaN or Infinity if total is 0
}

// BUG 3: parseInt without radix
const zipCode = parseInt(userInput); // '08' becomes 0 in old browsers (octal)!
const count = parseInt("010"); // Could be 8 or 10 depending on browser
const value = parseInt(formValue); // Dangerous without radix

// BUG 4: More parseInt without radix
function parseNumbers(strings) {
  return strings.map((s) => parseInt(s)); // Missing radix parameter
}

// BUG 5: Floating-point equality
function isEqual(a, b) {
  return a === b; // Fails: 0.1 + 0.2 !== 0.3
}

if (price === 19.99) {
  // Dangerous with floating point
  applyDiscount();
}

// BUG 6: Modulo by zero
function isEven(num, divisor) {
  return num % divisor === 0; // NaN if divisor is 0
}

// BUG 7: Math operations on potentially undefined
function calculate(a, b, c) {
  return a + b * c; // NaN if any parameter is undefined
}

// BUG 8: Bitwise operations on non-integers
function hash(value) {
  return ((value << 2) >> 1) & 0xff; // Assumes value is integer
}

const flags = userInput | 0; // Unsafe conversion to integer
const shifted = floatingPoint >> 2; // Truncates decimal

// BUG 9: Increment/decrement on strings
let counter = "5";
counter++; // Now it's 6 (number), unexpected type change
counter += 1; // '61' (string concatenation)!

// BUG 10: Math with mixed types
const result = "10" - 5; // 5 (coerced)
const sum = "10" + 5; // '105' (concatenation) - inconsistent!

// BUG 11: Infinity not checked
function divide(a, b) {
  const result = a / b;
  return result * 2; // Could be Infinity * 2 = Infinity
}

// BUG 12: -0 vs +0 confusion
function checkZero(value) {
  return value === 0; // Both -0 and +0 match
}

// BUG 13: Large number precision loss
const bigNumber = 9007199254740992; // MAX_SAFE_INTEGER + 1
const bigger = bigNumber + 1; // Equals bigNumber! Precision lost

// BUG 14: Percentage calculation overflow
function getPercentageChange(old, current) {
  return ((current - old) / old) * 100; // Infinity if old is 0, division by zero
}
