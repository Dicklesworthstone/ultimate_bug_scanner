// Clean control for GH #74: return/throw-terminated clauses, grouped empty
// case labels, an intentional documented fall-through, breaks that belong to a
// loop (not the switch), and a terminal clause without break are all fine.
export function classify(kind) {
  switch (kind) {
    case "a":
      return 1;
    case "b":
      return 2;
    case "c":
    case "d":
      return 34;
    default:
      throw new Error(`unknown kind: ${kind}`);
  }
}

export function accumulate(mode, values) {
  let total = 0;
  switch (mode) {
    case "sum":
      for (const value of values) {
        if (value < 0) break;
        total += value;
      }
      break;
    case "double":
      total = values.length * 2;
      // fall through
    case "count":
      total += values.length;
      break;
    default:
      total = values.length;
  }
  return total;
}
