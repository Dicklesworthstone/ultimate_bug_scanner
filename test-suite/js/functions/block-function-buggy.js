// Buggy control for GH #72: function declarations directly inside conditional
// and loop blocks have inconsistent hoisting semantics across sloppy/strict
// mode and must be reported.
export function setup(flag, items) {
  if (flag) {
    function helper() {
      return 1;
    }
    return helper();
  }
  for (const item of items) {
    function perItem() {
      return item;
    }
    perItem();
  }
  return 0;
}
