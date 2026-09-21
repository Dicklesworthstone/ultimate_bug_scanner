// ============================================================================
// EDGE CASES: UNICODE & TEXT ENCODING BUGS
// Expected: 15+ issues with string handling, encoding, normalization
// ============================================================================

// BUG 1: Length calculation with emojis
function truncateText(text, maxLength) {
  return text.substring(0, maxLength); // Wrong with surrogate pairs!
}
// "👨‍👩‍👧‍👦".length === 11 (not 1)
// truncateText("Hello 👨‍👩‍👧‍👦 World", 10) breaks the emoji

// BUG 2: Case conversion with Turkish 'i'
function normalizeUsername(username) {
  return username.toLowerCase();
}
// In Turkish locale, "İstanbul".toLowerCase() === "i̇stanbul" (not "istanbul")

// BUG 3: String comparison without normalization
function areNamesEqual(name1, name2) {
  return name1 === name2;
}
// "café" (é) !== "café" (e + ́) even though they look identical
// NFD vs NFC normalization

// BUG 4: Reverse string breaking grapheme clusters
function reverseString(str) {
  return str.split("").reverse().join("");
}
// reverseString("👨‍👩‍👧‍👦") breaks the family emoji into individual parts

// BUG 5: Email validation breaking with unicode
function validateEmail(email) {
  const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return regex.test(email);
}
// Rejects valid emails like "用户@example.com" or "José@example.com"

// BUG 6: URL encoding issues
function buildUrl(base, params) {
  const query = Object.keys(params)
    .map((key) => `${key}=${params[key]}`)
    .join("&");
  return `${base}?${query}`;
}
// Doesn't encode special characters: buildUrl('/search', {q: '北京 & 上海'})

// BUG 7: Database string length validation
function isValidUsername(username) {
  return username.length >= 3 && username.length <= 20;
}
// "🚀🚀🚀".length === 6 (3 emojis, 6 code units)
// May fit validation but overflow database VARCHAR(20)

// BUG 8: Character counting for display
function getCharacterCount(text) {
  return text.length;
}
// Shows wrong count for "hello 👋" (shows 8, should show 7)

// BUG 9: Substring with combining characters
function getFirstName(fullName) {
  return fullName.split(" ")[0];
}
// Works fine, but then:
function getInitial(name) {
  return name[0]; // Breaks with combining diacritics
}
// "José"[0] === "J", but "J̃osé"[0] === "J̃" (J + combining tilde)

// BUG 10: CSV injection via unicode
function exportToCSV(data) {
  return data.map((row) => row.join(",")).join("\n");
}
// If row contains: ["\u202E=SUM(A1:A10)"] (Right-to-Left Override)
// Can create formula injection in Excel

// BUG 11: Sorting with diacritics
function sortNames(names) {
  return names.sort();
}
// "Zürich" comes after "Zeppelin" in default sort
// Should use .sort((a, b) => a.localeCompare(b))

// BUG 12: Homoglyph attacks in validation
function isSafeDomain(domain) {
  return domain === "example.com";
}
// Doesn't catch: "exаmple.com" (Cyrillic 'а' instead of Latin 'a')
// Or: "ехаmple.com" (multiple Cyrillic chars)

// BUG 13: Zero-width characters in username
function sanitizeUsername(username) {
  return username.trim();
}
// Doesn't remove: "user\u200Bname" (contains zero-width space)
// Or: "admin\u200D" (zero-width joiner)

// BUG 14: RTL override hiding content
function displayMessage(msg) {
  return `<div>${msg}</div>`;
}
// msg = "Hello\u202Egnorw si siht" displays as "Hello this is wrong"
// RTL override \u202E reverses text visually

// BUG 15: File extension check with unicode
function isImageFile(filename) {
  return /\.(jpg|png|gif)$/i.test(filename);
}
// Bypassed by: "malware.exe\u202Egnp.jpg"
// Displays as: "malware.jpg.png" but is actually .exe

// BUG 16: String truncation breaking multi-byte UTF-8
function truncateUTF8(str, byteLength) {
  return str.substring(0, byteLength);
}
// If str is "你好世界" (each char is 3 bytes in UTF-8)
// truncateUTF8(str, 5) breaks the second character

// BUG 17: Comparing strings from different sources
function checkPassword(input, stored) {
  return input === stored;
}
// If input is from form (NFC) and stored is NFD:
// "Amélie" (NFC) !== "Amélie" (NFD)

// BUG 18: Regex with dot matching
function extractFilename(path) {
  const match = path.match(/\/([^/]+)$/);
  return match ? match[1] : null;
}
// Works, but:
function removeExtension(filename) {
  return filename.replace(/\..*$/, "");
}
// "file.backup.tar.gz" becomes "file" (removes too much)

// BUG 19: JSON stringification of unicode
function logData(data) {
  console.log(JSON.stringify(data));
}
// JSON.stringify({name: "user\u0000admin"}) includes null byte
// Can break log parsers

// BUG 20: Displaying user content without escaping
function showUsername(username) {
  document.getElementById("user").textContent = username;
}
// Safe, but:
function showBio(bio) {
  document.getElementById("bio").innerHTML = bio;
}
// If bio contains: "<img src=x onerror='alert(1)'>" - XSS
// Even worse with unicode: "<img src=\u0000 onerror='alert(1)'>"

// BUG 21: Locale-dependent string operations
function formatCurrency(amount) {
  return amount.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}
// formatCurrency(1000000) === "1,000,000" in US
// But European format uses "1.000.000" or "1 000 000"

// BUG 22: Phone number parsing
function parsePhone(phone) {
  return phone.replace(/\D/g, "");
}
// Removes all non-digits, but loses country code formatting
// "+1 (555) 123-4567" becomes "15551234567"
// "١٢٣٤" (Arabic numerals) removed entirely

module.exports = {
  truncateText,
  normalizeUsername,
  areNamesEqual,
  reverseString,
  validateEmail,
  buildUrl,
  isValidUsername,
  getCharacterCount,
  getInitial,
  sortNames,
  isSafeDomain,
  sanitizeUsername,
  isImageFile,
};
