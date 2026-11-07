// Regex and fuzzy conditions that DuckDB can run natively.
//
// With SQLite, `x REGEXP ?` and fuzzy_match() were JavaScript functions called per row, which
// SQLite does cheaply in-process. DuckDB calls JavaScript through Node-API, several times more
// expensive per row, so a regex search over a large tab became the slowest query in the app.
//
//   regexCondition  uses DuckDB's own regexp_matches (RE2: linear time, no ReDoS) when DuckDB
//                   accepts the pattern, and the JavaScript regexp() function otherwise
//                   (lookarounds and backreferences, which RE2 does not support).
//   fuzzyCondition  is the fuzzy_match() rule written in SQL: the cell contains the term, or
//                   enough of the term's 2- or 3-letter pieces (see runtime-functions.js).
"use strict";

const { MAX_PATTERN_LEN, MAX_VALUE_LEN } = require("../utils/safe-regex");

const nativeOk = new Map(); // pattern -> boolean
const NATIVE_CACHE_MAX = 256;

function nativeRegexAccepted(db, pattern) {
  if (!db || typeof db.prepare !== "function") return false;
  const cached = nativeOk.get(pattern);
  if (cached !== undefined) return cached;
  let ok;
  try {
    db.prepare("SELECT regexp_matches('', ?, 'i') AS m").get(pattern);
    ok = true;
  } catch {
    ok = false;
  }
  if (nativeOk.size >= NATIVE_CACHE_MAX) nativeOk.delete(nativeOk.keys().next().value);
  nativeOk.set(pattern, ok);
  return ok;
}

/** `expr` matches `pattern` case-insensitively. Returns { sql, params }. */
function regexCondition(db, expr, pattern) {
  const p = String(pattern ?? "");
  if (p.length <= MAX_PATTERN_LEN && nativeRegexAccepted(db, p)) {
    return { sql: `COALESCE(regexp_matches(${expr}, ?, 'i'), FALSE)`, params: [p] };
  }
  return { sql: `regexp(?, ${expr})`, params: [p] };
}

/** Same result as fuzzy_match(expr, term) in runtime-functions.js. Returns { sql, params }. */
function fuzzyCondition(expr, term) {
  const s = String(term ?? "").slice(0, MAX_PATTERN_LEN).toLowerCase();
  const text = `lower(substr(${expr}, 1, ${MAX_VALUE_LEN}))`;
  const params = [s];
  let sql = `contains(${text}, ?)`;
  if (s.length >= 2) {
    const n = s.length < 5 ? 2 : 3;
    const grams = [];
    for (let i = 0; i <= s.length - n; i++) grams.push(s.substring(i, i + n));
    if (grams.length > 0) {
      const threshold = s.length < 5 ? 0.7 : 0.6;
      let need = 0;
      while (need < grams.length && need / grams.length < threshold) need++;
      sql = `(${sql} OR (${grams.map(() => `CAST(contains(${text}, ?) AS INTEGER)`).join(" + ")}) >= ${need})`;
      params.push(...grams);
    }
  }
  // fuzzy_match(NULL, …) is 0
  return { sql: `(${expr} IS NOT NULL AND ${sql})`, params };
}

module.exports = { regexCondition, fuzzyCondition };
