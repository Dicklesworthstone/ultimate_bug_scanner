// Buggy control for GH #74: the "create" clause runs code and then falls into
// the "update" clause with no break/return/throw and no fall-through comment.
export function applyChange(kind, payload) {
  let result = null;
  switch (kind) {
    case "create":
      result = { op: "create", payload };
    case "update":
      result = { op: "update", payload };
      break;
    case "delete":
      result = { op: "delete", payload };
      break;
    default:
      result = { op: "noop", payload };
  }
  return result;
}
