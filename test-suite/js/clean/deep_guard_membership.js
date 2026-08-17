// GH #90 regression: membership-test guards must suppress the deep_guard
// unguarded-nested-access finding, and the guard idiom itself
// (Object.prototype.hasOwnProperty.call) must never be flagged as a chain.
'use strict';

const FIELD_RANK = { name: 1, date: 2, size: 3 };
const CATCHALL_RANK = 99;

// The exact false positive from the field report: the flagged line IS a guard.
function rankOf(field) {
  return Object.prototype.hasOwnProperty.call(FIELD_RANK, field) ? FIELD_RANK[field] : CATCHALL_RANK;
}

// `in`-operator ternary guard.
function firstResult(state, key) {
  return key in state ? state.cache.results.byId.first : undefined;
}

// Object.hasOwn ternary guard (modern equivalent).
function detailName(obj, key) {
  return Object.hasOwn(obj, key) ? obj.meta.info.details.name : null;
}

// Membership test guarding an if body.
function guardedLookup(config, key) {
  if (Object.prototype.hasOwnProperty.call(config, key)) {
    return config.data.entries.byKey.first;
  }
  return null;
}

module.exports = { rankOf, firstResult, detailName, guardedLookup };
