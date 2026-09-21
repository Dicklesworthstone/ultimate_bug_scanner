// BUGGY JS security sample
const API_SECRET = "super-secret";

function runUserCode(code) {
  eval(code); // CRITICAL
}

function render(comment) {
  document.getElementById("box").innerHTML = comment; // XSS
}

function fetchData(url) {
  return fetch(url).then((res) => res.text()); // Missing error handling
}
