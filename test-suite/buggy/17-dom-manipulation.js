// ============================================================================
// TEST SUITE: DOM MANIPULATION BUGS (BUGGY CODE)
// Expected: 18+ WARNING/CRITICAL issues - DOM clobbering, XSS, performance
// ============================================================================

// BUG 1: DOM clobbering via form elements
function getConfigValue() {
  const config = document.getElementById("config");
  return config.value; // But if there's <input name="config">, DOM is clobbered
}

// BUG 2: Unguarded querySelectorAll iteration
function hideAllErrors() {
  const errors = document.querySelectorAll(".error");
  errors.forEach((err) => (err.style.display = "none")); // Crash if errors is null
}

// BUG 3: Modifying DOM in a loop (performance)
function renderList(items) {
  const list = document.getElementById("list");
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    list.appendChild(li); // Triggers reflow on each append!
  });
}

// BUG 4: Using innerHTML with user data
function displayComment(comment) {
  document.getElementById("comments").innerHTML += comment; // XSS + inefficient
}

// BUG 5: Not removing event listeners
function setupModal(modalId) {
  const modal = document.getElementById(modalId);
  const closeBtn = modal.querySelector(".close");

  closeBtn.addEventListener("click", () => {
    modal.style.display = "none";
  }); // Listener never removed - memory leak
}

// BUG 6: querySelector in loop
function highlightItems(ids) {
  ids.forEach((id) => {
    const element = document.querySelector(`[data-id="${id}"]`); // Slow!
    if (element) {
      element.classList.add("highlight");
    }
  });
}

// BUG 7: Synchronous layout thrashing
function animateElements() {
  const elements = document.querySelectorAll(".animated");
  elements.forEach((el) => {
    const height = el.offsetHeight; // Read - forces layout
    el.style.height = height + 10 + "px"; // Write - invalidates layout
  }); // Read-write-read-write causes layout thrashing
}

// BUG 8: Creating circular references
function attachData(element, data) {
  element.customData = data;
  data.element = element; // Circular reference - memory leak
}

// BUG 9: Detached DOM nodes kept in memory
const detachedNodes = [];

function removeElements() {
  const elements = document.querySelectorAll(".removable");
  elements.forEach((el) => {
    detachedNodes.push(el); // Keeping reference
    el.parentNode.removeChild(el);
  }); // Elements can't be GC'd
}

// BUG 10: Storing DOM references that become stale
const cachedButton = document.getElementById("submit");

function handleClick() {
  cachedButton.addEventListener("click", submit);
  // If button is removed and recreated, reference is stale
}

// BUG 11: Using document.write (blocks parsing)
function addScript(src) {
  document.write(`<script src="${src}"></script>`); // Terrible practice!
}

// BUG 12: Accessing offsetHeight in a loop
function getTotalHeight(elements) {
  let total = 0;
  for (const el of elements) {
    total += el.offsetHeight; // Forces layout calculation each time
  }
  return total;
}

// BUG 13: Setting styles individually (performance)
function styleElement(element) {
  element.style.width = "100px"; // Triggers reflow
  element.style.height = "100px"; // Triggers reflow
  element.style.backgroundColor = "red"; // Triggers repaint
  element.style.color = "white"; // Triggers repaint
}

// BUG 14: Not checking if element exists before accessing properties
function getElementValue(id) {
  return document.getElementById(id).value; // Crash if not found
}

// BUG 15: Creating elements in loop with innerHTML
function buildTable(data) {
  let html = "<table>";
  data.forEach((row) => {
    html += "<tr>";
    row.forEach((cell) => {
      html += `<td>${cell}</td>`; // String concatenation + XSS risk
    });
    html += "</tr>";
  });
  html += "</table>";
  document.getElementById("container").innerHTML = html;
}

// BUG 16: Assuming elements have specific ancestors
function findParentForm(element) {
  return element.parentElement.parentElement.parentElement;
  // Brittle - breaks if DOM structure changes
}

// BUG 17: Global variables for DOM elements
window.myButton = document.getElementById("myButton");

function clickHandler() {
  window.myButton.click(); // Global pollution
}

// BUG 18: Not cleaning up timers referencing DOM
function startBlinking(elementId) {
  setInterval(() => {
    const element = document.getElementById(elementId);
    element.classList.toggle("blink");
  }, 500); // Never cleared, keeps searching DOM
}

// BUG 19: Reflow-inducing operations in animation loop
function animate() {
  requestAnimationFrame(() => {
    const box = document.getElementById("box");
    const width = box.offsetWidth; // Read - forces reflow
    box.style.width = width + 1 + "px"; // Write
    animate();
  });
}

// BUG 20: Setting dangerous attributes
function createLink(url) {
  const link = document.createElement("a");
  link.href = url; // If url is "javascript:alert(1)", XSS!
  link.target = "_blank"; // Without rel="noopener" - security risk
  return link;
}

// BUG 21: Accessing computed styles in loop
function getWidths(elements) {
  return elements.map((el) => {
    return window.getComputedStyle(el).width; // Forces style recalc each time
  });
}

// BUG 22: Clone node with event listeners
function duplicateElement(element) {
  const clone = element.cloneNode(true); // Events not copied
  document.body.appendChild(clone);
  // Clone doesn't have event listeners - confusion
}

// BUG 23: Mutation without checking node type
function processNode(node) {
  node.textContent = "Updated"; // Could be text node, comment, etc.
  node.setAttribute("data-processed", "true"); // Crash if not element
}

// BUG 24: Using eval with DOM content
function executeInlineScript() {
  const script = document.getElementById("user-script").textContent;
  eval(script); // Dangerous!
}

// BUG 25: Not escaping special characters
function createDataAttribute(value) {
  const div = document.createElement("div");
  div.setAttribute("data-value", value); // If value has quotes, breaks
  return div.outerHTML;
}
