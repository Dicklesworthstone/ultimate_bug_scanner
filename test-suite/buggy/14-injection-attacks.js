// ============================================================================
// TEST SUITE: INJECTION ATTACKS (BUGGY CODE)
// Expected: 20+ CRITICAL issues - SQL, NoSQL, Command, LDAP, XPath injection
// ============================================================================

// BUG 1: Classic SQL injection
function getUserById(db, userId) {
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return db.query(query); // CRITICAL: SQL injection!
}
// Attack: getUserById(db, "1 OR 1=1")

// BUG 2: SQL injection in WHERE clause
function searchUsers(db, searchTerm) {
  const sql = `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`;
  return db.query(sql); // Injectable
}

// BUG 3: SQL injection in ORDER BY
function getSortedUsers(db, sortColumn) {
  const query = `SELECT * FROM users ORDER BY ${sortColumn}`;
  return db.query(query); // Can inject: "name; DROP TABLE users--"
}

// BUG 4: NoSQL injection (MongoDB)
function findUser(username, password) {
  const query = {
    username: username,
    password: password,
  };
  return db.collection("users").findOne(query);
}
// Attack: findUser({$ne: null}, {$ne: null}) bypasses auth

// BUG 5: NoSQL injection with string concatenation
function getUserByName(name) {
  const query = `{"username": "${name}"}`;
  return db.collection("users").findOne(JSON.parse(query));
}
// Attack: getUserByName('"; return true; var dummy="')

// BUG 6: Command injection via child_process
const { exec } = require("child_process");

function pingHost(hostname) {
  exec(`ping -c 4 ${hostname}`, (error, stdout) => {
    console.log(stdout);
  });
}
// Attack: pingHost("google.com; rm -rf /")

// BUG 7: Command injection in file operations
const fs = require("fs");

function readUserFile(filename) {
  exec(`cat ${filename}`, (err, data) => {
    console.log(data);
  });
}
// Attack: readUserFile("file.txt; cat /etc/passwd")

// BUG 8: LDAP injection
function ldapSearch(username) {
  const filter = `(uid=${username})`;
  return ldap.search("dc=example,dc=com", { filter });
}
// Attack: ldapSearch("admin)(|(uid=*)")

// BUG 9: XPath injection
function searchXml(username) {
  const xpath = `//users/user[username='${username}']`;
  return xmlDoc.evaluate(xpath);
}
// Attack: searchXml("' or '1'='1")

// BUG 10: Template injection
function renderTemplate(userInput) {
  const template = `Hello, ${userInput}!`;
  return eval("`" + template + "`"); // Double whammy: eval + injection
}

// BUG 11: OS command injection via spawn
const { spawn } = require("child_process");

function convertImage(inputFile, outputFile) {
  const convert = spawn("convert", [inputFile, outputFile]);
  // If inputFile is unsanitized: "image.jpg; rm -rf /"
}

// BUG 12: Second-order SQL injection
function updateUserProfile(db, userId, bio) {
  // First, store the bio (not escaped)
  db.query(`UPDATE users SET bio = '${bio}' WHERE id = ${userId}`);

  // Later, retrieve and use it in another query
  const user = db.query(`SELECT * FROM users WHERE id = ${userId}`);
  const relatedQuery = `SELECT * FROM posts WHERE author = '${user.bio}'`;
  return db.query(relatedQuery); // bio could contain SQL injection payload
}

// BUG 13: NoSQL injection in $where operator
function findActiveUsers(status) {
  return db.collection("users").find({
    $where: `this.status == '${status}'`,
  });
}
// Attack: findActiveUsers("active' || 'a'=='a")

// BUG 14: Log injection
function logUserAction(username, action) {
  console.log(`User ${username} performed: ${action}`);
}
// Attack: logUserAction("admin\nUser hacker performed: DELETE_ALL", "login")
// Creates fake log entry

// BUG 15: Email header injection
function sendEmail(to, subject, body) {
  const headers = `To: ${to}\nSubject: ${subject}\n\n${body}`;
  // Attacker can inject: "victim@example.com\nBcc: attacker@evil.com"
  mailer.send(headers);
}

// BUG 16: SSRF via URL injection
function fetchExternalData(url) {
  return fetch(url); // No validation - can access internal services
}
// Attack: fetchExternalData("http://localhost:6379/") accesses Redis

// BUG 17: Expression language injection
function evaluateExpression(expr) {
  return new Function("return " + expr)(); // Like eval
}
// Attack: evaluateExpression("process.exit()")

// BUG 18: Code injection via require
function loadModule(moduleName) {
  return require(moduleName); // Can load arbitrary modules
}
// Attack: loadModule("child_process").exec("malicious command")

// BUG 19: GraphQL injection
function graphqlQuery(userId) {
  const query = `
    {
      user(id: "${userId}") {
        name
        email
      }
    }
  `;
  return graphql(schema, query);
}
// Attack: userId = '1") { admin { password } } #'

// BUG 20: CSV injection (Formula injection)
function exportToCSV(userData) {
  const csv = `Name,Email,Bio\n`;
  userData.forEach((user) => {
    csv += `${user.name},${user.email},${user.bio}\n`;
  });
  return csv;
}
// Attack: user.bio = "=cmd|'/c calc'!A1" executes in Excel

// BUG 21: Server-Side Template Injection (SSTI)
const Handlebars = require("handlebars");

function renderUserPage(username) {
  const template = `<h1>Welcome {{username}}</h1>`;
  const compiled = Handlebars.compile(template);
  return compiled({ username }); // If username is {{constructor.constructor('return process')()}}
}

// BUG 22: XML injection (XXE)
const xml2js = require("xml2js");

function parseXml(xmlString) {
  const parser = new xml2js.Parser({
    // No security settings - vulnerable to XXE
  });
  return parser.parseString(xmlString);
}
// Attack: includes <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

// BUG 23: HTTP Response splitting
function setRedirect(res, url) {
  res.writeHead(302, {
    Location: url, // Unsanitized
  });
}
// Attack: url = "/page\r\nSet-Cookie: admin=true"

// BUG 24: DOM-based XSS injection
function updatePage(content) {
  document.getElementById("content").innerHTML = content;
  // If content comes from URL parameter: ?content=<img src=x onerror=alert(1)>
}

// BUG 25: JSON injection
function createJsonResponse(username) {
  const json = `{"username": "${username}", "role": "user"}`;
  return JSON.parse(json);
}
// Attack: username = '", "role": "admin", "extra": "'

// BUG 26: Shell command via template literals
function executeScript(scriptName) {
  const { execSync } = require("child_process");
  const output = execSync(`./scripts/${scriptName}.sh`);
  return output.toString();
}
// Attack: scriptName = "../../../etc/passwd #"

// BUG 27: Unsafe deserialization
function deserializeUser(data) {
  return eval("(" + data + ")"); // Arbitrary code execution
}

// BUG 28: Path traversal in file access
function getFile(filename) {
  const path = `./uploads/${filename}`;
  return fs.readFileSync(path);
}
// Attack: filename = "../../etc/passwd"
