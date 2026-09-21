// ============================================================================
// TEST SUITE: REGEX VULNERABILITIES (BUGGY CODE)
// Expected: 15+ CRITICAL issues - ReDoS, catastrophic backtracking, regex bombs
// ============================================================================

// BUG 1: ReDoS - Catastrophic backtracking with nested quantifiers
const emailRegex = /^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.com$/;
function validateEmail(email) {
  return emailRegex.test(email); // Can hang on: "aaaaaaaaaaaaaaaaaaaaaaaaa!"
}

// BUG 2: ReDoS - Alternation with overlapping patterns
const urlRegex = /(http|https|ftp):\/\/[a-z]+(\.?[a-z]+)*\.[a-z]+/;
function validateUrl(url) {
  return urlRegex.test(url); // Exponential time on malicious input
}

// BUG 3: ReDoS - Nested quantifiers with backtracking
const htmlRegex = /<([a-z]+)([^>]*)>(.*?)<\/\1>/gi;
function extractHtmlTags(html) {
  return html.match(htmlRegex); // Vulnerable to ReDoS
}

// BUG 4: Inefficient regex - Unnecessary capturing groups
const phoneRegex = /(\d{3})-(\d{3})-(\d{4})/;
function formatPhone(phone) {
  return phone.replace(phoneRegex, "($1) $2-$3"); // Should use non-capturing (?:)
}

// BUG 5: ReDoS - Polynomial regex
const complexRegex = /(a+)+b/;
function testComplexPattern(str) {
  return complexRegex.test(str); // Exponential time on "aaaaaaaaaaaaaaac"
}

// BUG 6: Unsafe regex in loop - Performance killer
function validateAllEmails(emails) {
  for (const email of emails) {
    if (!/^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})+$/.test(email)) {
      return false;
    }
  }
  return true;
}

// BUG 7: ReDoS - Overlapping alternations
const pathRegex = /^(\/[a-zA-Z0-9_-]+)+\/?$/;
function validatePath(path) {
  return pathRegex.test(path); // Can cause exponential backtracking
}

// BUG 8: Regex in replace without escaping special chars
function sanitizeInput(input) {
  const userPattern = input; // User-controlled!
  const regex = new RegExp(userPattern, "g");
  return "test string".replace(regex, ""); // Regex injection + ReDoS
}

// BUG 9: Greedy quantifiers with nested groups
const jsonRegex = /"([^"\\]|\\.)*"/g;
function extractJsonStrings(json) {
  return json.match(jsonRegex); // Can be slow on large inputs
}

// BUG 10: Multiple overlapping character classes
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
function validatePassword(password) {
  return passwordRegex.test(password); // Lookaheads can be slow
}

// BUG 11: Catastrophic backtracking in email validation
const advancedEmailRegex = /^([a-zA-Z0-9_\-.]+)@([a-zA-Z0-9_\-.]+)\.([a-zA-Z]{2,5})$/;
function validateAdvancedEmail(email) {
  if (advancedEmailRegex.test(email)) {
    return email.match(/([a-zA-Z0-9_\-.]+)/g); // Redundant matching
  }
}

// BUG 12: Regex DoS with word boundaries
const wordRegex = /\b(\w+)\b/g;
function extractWords(text) {
  // On strings with many non-word chars, this can be slow
  return text.match(wordRegex);
}

// BUG 13: Unanchored regex allows bypass
const strictUrlRegex = /https:\/\/example\.com/;
function isSecureUrl(url) {
  return strictUrlRegex.test(url); // Matches anywhere! Should be ^https://example\.com$
}

// BUG 14: Case-insensitive flag abuse
const searchRegex = /user.*input/gi;
function searchLogs(logs, userInput) {
  const pattern = new RegExp(userInput, "gi"); // User can inject regex
  return logs.filter((log) => pattern.test(log));
}

// BUG 15: Regex with alternation explosion
const dataRegex = /(data|info|value|result|output|response|content|payload)+/;
function matchData(str) {
  return dataRegex.test(str); // Alternation with quantifier
}

// BUG 16: Using regex when simple string methods would work
function containsWord(text, word) {
  const regex = new RegExp(word); // Unnecessary - use text.includes()
  return regex.test(text);
}

// BUG 17: Global regex state bug
const globalRegex = /test/g;
function checkMultiple(str1, str2) {
  const result1 = globalRegex.test(str1); // BUG: Stateful!
  const result2 = globalRegex.test(str2); // Uses lastIndex from previous test
  return result1 && result2;
}

// BUG 18: Unsafe regex in validation allows injection
function validateUsername(username) {
  const pattern = /^[a-zA-Z0-9]+$/;
  if (!pattern.test(username)) {
    throw new Error("Invalid username");
  }
  // If user inputs: "^[a-zA-Z0-9]+|.*$" they can bypass
}

// BUG 19: Exponential regex in URL parsing
const urlParseRegex = /^(([^:/?#]+):)?(\/\/([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/;
function parseUrl(url) {
  const match = url.match(urlParseRegex); // Complex regex for simple task
  return match;
}

// BUG 20: Regex object creation in hot path
function processItems(items) {
  return items.map((item) => {
    const regex = /\d+/g; // Created on every iteration!
    return item.match(regex);
  });
}
