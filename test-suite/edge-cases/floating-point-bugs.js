// ============================================================================
// EDGE CASES: FLOATING-POINT ARITHMETIC BUGS
// Expected: 16+ issues with precision, rounding, money calculations
// ============================================================================

// BUG 1: Classic floating-point precision
function calculateTotal(price, quantity) {
  return price * quantity;
}
// calculateTotal(0.1, 3) === 0.30000000000000004

// BUG 2: Money calculation without precision handling
function calculateDiscount(price, discountPercent) {
  return price * (discountPercent / 100);
}
// calculateDiscount(100.10, 10) === 10.009999999999998

// BUG 3: Equality comparison with floats
function isPriceEqual(price1, price2) {
  return price1 === price2;
}
// isPriceEqual(0.1 + 0.2, 0.3) === false
// 0.1 + 0.2 === 0.30000000000000004

// BUG 4: Accumulating floating-point errors
function calculateCartTotal(items) {
  let total = 0;
  items.forEach((item) => {
    total += item.price * item.quantity;
  });
  return total;
}
// Each multiplication/addition accumulates error
// After 100 items, could be off by several cents

// BUG 5: Rounding to two decimal places incorrectly
function roundToMoney(amount) {
  return Math.round(amount * 100) / 100;
}
// roundToMoney(0.1 + 0.2) === 0.3 ✓ (works)
// But: roundToMoney(1.005) === 1 (should be 1.01)
// 1.005 * 100 === 100.49999999999999

// BUG 6: Division precision loss
function splitBill(total, people) {
  return total / people;
}
// splitBill(100, 3) === 33.33333333333333
// Sum of three shares !== original total

// BUG 7: Percentage calculations
function applyTax(amount, taxRate) {
  const tax = amount * taxRate;
  return amount + tax;
}
// applyTax(100.10, 0.08) === 108.10800000000001

// BUG 8: Comparing floats with tolerance incorrectly
function isCloseEnough(a, b) {
  return Math.abs(a - b) < 0.01;
}
// isCloseEnough(0, 0.005) === true (wrong for money!)
// Half a cent difference counts as equal

// BUG 9: Converting dollars to cents
function toCents(dollars) {
  return dollars * 100;
}
// toCents(10.555) === 1055.5 (not an integer!)
// Should round: Math.round(dollars * 100)

// BUG 10: Interest calculation over time
function calculateCompoundInterest(principal, rate, years) {
  let amount = principal;
  for (let i = 0; i < years; i++) {
    amount *= 1 + rate;
  }
  return amount;
}
// Accumulates rounding errors over many iterations
// After 30 years, could be significantly off

// BUG 11: Averaging floating-point numbers
function average(numbers) {
  const sum = numbers.reduce((a, b) => a + b, 0);
  return sum / numbers.length;
}
// average([0.1, 0.2, 0.3]) !== 0.2 exactly

// BUG 12: Modulo with floats
function isMultipleOf(value, divisor) {
  return value % divisor === 0;
}
// isMultipleOf(0.3, 0.1) === false
// 0.3 % 0.1 === 0.09999999999999998

// BUG 13: Currency conversion
function convertCurrency(amount, rate) {
  return amount * rate;
}
// convertCurrency(10.50, 1.23) === 12.915000000000001
// Should round to 2 decimals for money

// BUG 14: Calculating unit price
function getUnitPrice(total, units) {
  return total / units;
}
// getUnitPrice(10, 3) === 3.3333333333333335
// Can't charge fractional cents

// BUG 15: Comparing prices
function isCheaper(price1, price2) {
  return price1 < price2;
}
// const p1 = 0.1 + 0.2;  // 0.30000000000000004
// const p2 = 0.3;
// isCheaper(p1, p2) === false (but they're meant to be equal)

// BUG 16: Summing up transaction fees
function calculateTotalFees(transactions) {
  return transactions.reduce((sum, tx) => {
    return sum + (tx.amount * 0.029 + 0.3); // 2.9% + 30¢
  }, 0);
}
// Each calculation adds small errors
// 1000 transactions could be off by dollars

// BUG 17: Decimal to binary conversion issues
function isExactDecimal(num) {
  return num === parseFloat(num.toFixed(2));
}
// Many decimals can't be represented exactly in binary
// 0.1, 0.2, 0.3, 0.6, 0.7, 0.9, etc.

// BUG 18: Profit margin calculation
function calculateProfitMargin(revenue, cost) {
  return ((revenue - cost) / revenue) * 100;
}
// calculateProfitMargin(100.10, 75.08) === 24.99500499500499...
// Should round for display

// BUG 19: Sorting by price
function sortByPrice(items) {
  return items.sort((a, b) => a.price - b.price);
}
// Can fail if prices are very close:
// [{ price: 0.1 + 0.2 }, { price: 0.3 }]

// BUG 20: Running balance calculation
function updateBalance(currentBalance, transactions) {
  let balance = currentBalance;
  transactions.forEach((tx) => {
    balance += tx.amount;
  });
  return balance;
}
// Accumulates errors:
// Start with 100.00
// Add 0.10 ten times
// Expect 101.00, get 101.00000000000001

// BUG 21: Price display formatting
function formatPrice(price) {
  return "$" + price.toFixed(2);
}
// formatPrice(0.1 + 0.2) === "$0.30" ✓ Works!
// But: formatPrice(1.005) === "$1.00" (should be "$1.01")

// BUG 22: Calculating percentage change
function getPercentChange(oldPrice, newPrice) {
  return ((newPrice - oldPrice) / oldPrice) * 100;
}
// getPercentChange(100.10, 110.11) === 9.99000999000999

// BUG 23: Min/max with floats
function findMaxPrice(prices) {
  return Math.max(...prices);
}
// Works, but:
function isPriceInRange(price, min, max) {
  return price >= min && price <= max;
}
// const calculated = 0.1 + 0.2;
// isPriceInRange(calculated, 0.3, 0.4) === false
// Because 0.1 + 0.2 > 0.3

// BUG 24: Precision in scientific notation
function processLargeNumber(num) {
  return num + 1;
}
// processLargeNumber(9007199254740992) === 9007199254740992
// Number.MAX_SAFE_INTEGER exceeded
// Can't represent 9007199254740993 precisely

// BUG 25: Decimal places in user input
function parsePrice(input) {
  return parseFloat(input);
}
// parsePrice("10.10") === 10.1 (loses trailing zero)
// Representation is fine, but display needs .toFixed(2)

module.exports = {
  calculateTotal,
  calculateDiscount,
  isPriceEqual,
  calculateCartTotal,
  roundToMoney,
  splitBill,
  applyTax,
  toCents,
  average,
  convertCurrency,
  calculateTotalFees,
  calculateProfitMargin,
  formatPrice,
};
