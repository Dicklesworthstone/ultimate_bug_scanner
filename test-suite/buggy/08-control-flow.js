// ============================================================================
// TEST SUITE: CONTROL FLOW GOTCHAS (BUGGY CODE)
// Expected: Multiple WARNING issues
// ============================================================================

// BUG 1: Switch case without break
function getDay(num) {
  let day;
  switch (num) {
    case 1:
      day = 'Monday';
      // Missing break - falls through!
    case 2:
      day = 'Tuesday';
      // Missing break
    case 3:
      day = 'Wednesday';
      break;
    default:
      day = 'Unknown';
  }
  return day;
}

// BUG 2: Switch without default case
function handleAction(action) {
  switch (action) {
    case 'save':
      save();
      break;
    case 'delete':
      deleteItem();
      break;
    case 'update':
      update();
      break;
    // No default - unhandled actions silently ignored
  }
}

// BUG 3: Nested ternaries (readability nightmare)
const status = user.isActive
  ? user.isPremium
    ? user.hasDiscount
      ? 'premium-discount'
      : 'premium'
    : 'active'
  : user.isBanned
    ? 'banned'
    : 'inactive';

// BUG 4: More nested ternaries
const value = a ? b ? c ? d : e : f : g ? h : i;

// BUG 5: Unreachable code after return
function calculate(x) {
  if (x < 0) {
    return 0;
    console.log('Negative');  // Never executes
    x = Math.abs(x);  // Never executes
  }
  return x * 2;
}

// BUG 6: Empty if/else blocks
function validate(input) {
  if (input.length > 0) {
    // TODO: implement validation
  } else {
  }
}

if (condition) {
} else {
  handleElse();
}

// BUG 7: Condition always true/false
function checkValue(val) {
  if (val || !val) {  // Always true!
    return 'yes';
  }
  return 'no';  // Unreachable
}

// BUG 8: Yoda conditions (confusing)
if (5 === value) {  // Backwards
  doSomething();
}

if (null === user) {  // Confusing
  handleError();
}

if ('active' === status) {  // Unnatural
  proceed();
}

// BUG 9: Multiple returns in complex logic
function processUser(user) {
  if (!user) return null;
  if (!user.email) return null;
  if (!user.name) return null;
  if (user.age < 0) return null;
  if (user.age > 150) return null;
  // Hard to follow flow
  return user;
}

// BUG 10: Confusing boolean logic
function shouldShow(user, item) {
  if (user && item && user.canView && !item.hidden && (user.isPremium || item.isFree)) {
    return true;
  }
  return false;
}

// BUG 11: Loop with complex exit conditions
while (true) {
  if (condition1) break;
  if (condition2) continue;
  if (condition3) return;
  doWork();
  if (condition4) break;
}

// BUG 12: For loop with empty body
for (let i = 0; i < 10; i++) {
  // Empty
}

// BUG 13: Do-while that might not execute
do {
  processItem();
} while (false);  // Only runs once - why use do-while?
