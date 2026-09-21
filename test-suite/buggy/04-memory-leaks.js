// ============================================================================
// TEST SUITE: MEMORY LEAKS & PERFORMANCE (BUGGY CODE)
// Expected: Multiple WARNING issues
// ============================================================================

// BUG 1: Event listener never removed
function setupButton() {
  const button = document.getElementById("submit");
  button.addEventListener("click", handleClick);
  // No cleanup - memory leak when component unmounts
}

// BUG 2: setInterval without clearInterval
function startPolling() {
  setInterval(() => {
    checkForUpdates();
  }, 5000);
  // Timer runs forever - memory leak!
}

// BUG 3: Multiple event listeners in React without cleanup
function Component() {
  useEffect(() => {
    window.addEventListener("resize", handleResize);
    window.addEventListener("scroll", handleScroll);
    // No cleanup function - leaks on unmount!
  }, []);
}

// BUG 4: setTimeout without cleanup tracking
function delayedAction() {
  setTimeout(() => {
    updateState(newValue); // May update after component unmounts
  }, 5000);
  // No way to cancel if component unmounts
}

// BUG 5: DOM queries inside loops (performance)
function updateList(items) {
  for (let i = 0; i < items.length; i++) {
    const list = document.getElementById("list"); // Query every iteration!
    list.appendChild(createItem(items[i]));
  }
}

// BUG 6: String concatenation in loops
function buildHTML(items) {
  let html = "";
  for (let i = 0; i < items.length; i++) {
    html += "<li>" + items[i] + "</li>"; // Creates new string each iteration
  }
  return html;
}

// BUG 7: Event delegation not used
function attachListeners(items) {
  items.forEach((item) => {
    document.getElementById("item-" + item.id).addEventListener("click", handler);
    // Creates separate listener for each item - should use delegation
  });
}

// BUG 8: Circular reference
const obj1 = {};
const obj2 = {};
obj1.ref = obj2;
obj2.ref = obj1; // Circular reference - old browsers may not GC

// BUG 9: Detached DOM nodes
const detachedNodes = [];
function removeElements() {
  const elements = document.querySelectorAll(".temp");
  elements.forEach((el) => {
    el.parentNode.removeChild(el);
    detachedNodes.push(el); // Still referenced - memory leak!
  });
}

// BUG 10: Global variables accumulating
var globalCache = [];
function addToCache(item) {
  globalCache.push(item); // Never cleared - grows forever
}

// BUG 11: Large inline array (memory waste)
const hugeConfig = [
  { id: 1, name: "Item 1", data: "lots of data here" },
  { id: 2, name: "Item 2", data: "lots of data here" },
  { id: 3, name: "Item 3", data: "lots of data here" },
  { id: 4, name: "Item 4", data: "lots of data here" },
  { id: 5, name: "Item 5", data: "lots of data here" },
  { id: 6, name: "Item 6", data: "lots of data here" },
  { id: 7, name: "Item 7", data: "lots of data here" },
  { id: 8, name: "Item 8", data: "lots of data here" },
  { id: 9, name: "Item 9", data: "lots of data here" },
  { id: 10, name: "Item 10", data: "lots of data here" },
  { id: 11, name: "Item 11", data: "lots of data here" },
  { id: 12, name: "Item 12", data: "lots of data here" },
  { id: 13, name: "Item 13", data: "lots of data here" },
  { id: 14, name: "Item 14", data: "lots of data here" },
  { id: 15, name: "Item 15", data: "lots of data here" },
  { id: 16, name: "Item 16", data: "lots of data here" },
  { id: 17, name: "Item 17", data: "lots of data here" },
];

// BUG 12: React useEffect without cleanup
function VideoPlayer({ src }) {
  useEffect(() => {
    const video = videoRef.current;
    video.addEventListener("play", handlePlay);
    video.addEventListener("pause", handlePause);
    // No return cleanup function!
  });
}

// BUG 13: Timers in loops
function animateItems(items) {
  items.forEach((item, index) => {
    setTimeout(() => {
      animateItem(item);
    }, index * 100);
    // All timers stay alive until they fire
  });
}
