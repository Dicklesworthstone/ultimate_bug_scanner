interface Demo { value?: string; }
function useDemo(x?: Demo) {
  if (!x?.value) {
    return "nope";
  }
  return x.value.toUpperCase();
}

// Multiline default params should not be misread as global assignments.
const addDefaults = (
  a = 1,
  b = 2,
): number => a + b;

addDefaults();
