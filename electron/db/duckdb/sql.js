// Rewrites the SQLite idioms the app's SQL relies on into their DuckDB equivalents, so the
// analyzers' queries keep their meaning unchanged.
//
//   LIKE / NOT LIKE        → ILIKE / NOT ILIKE   (SQLite's LIKE ignores case; DuckDB's does not)
//   CAST(…)                → TRY_CAST(…)         (SQLite yields 0/NULL for bad input; DuckDB throws)
//   INTEGER / INT          → BIGINT              (SQLite integers are 64-bit; DuckDB INTEGER is 32-bit)
//   REAL                   → DOUBLE              (DuckDB REAL is a 32-bit float)
//   BEGIN IMMEDIATE|…      → BEGIN TRANSACTION
//   WITHOUT ROWID, AUTOINCREMENT → removed
//   [identifier]           → "identifier"        (SQLite accepts MS SQL-style bracket quoting)
//   sort_datetime(col) / extract_date(col) / extract_datetime_minute(col)
//                          → computed in SQL for plain ISO values ("2024-01-02 03:04:05.123"),
//                            the JavaScript function only for everything else (see below)
//
// Only code outside string literals, quoted identifiers and comments is touched.
"use strict";

const CACHE_MAX = 2000;
const cache = new Map();

const WORD_RE = /[A-Za-z_][A-Za-z0-9_$]*/y;

const BRACKET_IDENT_RE = /\[([^\[\]'"]+)\]/g;

function rewriteCode(rawCode, out) {
  let code = rawCode.includes("_d") || rawCode.includes("_datetime") ? rewriteDateFunctions(rawCode) : rawCode;
  if (code.includes("[")) code = code.replace(BRACKET_IDENT_RE, (whole, name) => `"${name.replace(/"/g, '""')}"`);
  // `code` is a run of SQL without literals/comments. Walk words so "ILIKE" or "my_int"
  // never match, and look at neighbouring words for the multi-word forms.
  let i = 0;
  let prevWord = "";
  while (i < code.length) {
    WORD_RE.lastIndex = i;
    const m = WORD_RE.exec(code);
    if (!m || m.index !== i) {
      out.push(code[i]);
      i++;
      continue;
    }
    const word = m[0];
    const upper = word.toUpperCase();
    let replacement = word;
    switch (upper) {
      case "LIKE":
        replacement = "ILIKE";
        break;
      case "CAST":
        if (/^\s*\(/.test(code.slice(i + word.length, i + word.length + 16)) && prevWord !== "TRY_") replacement = "TRY_CAST";
        break;
      case "INTEGER":
      case "INT":
        replacement = "BIGINT";
        break;
      case "REAL":
        replacement = "DOUBLE";
        break;
      case "AUTOINCREMENT":
        replacement = "";
        break;
      case "IMMEDIATE":
      case "EXCLUSIVE":
      case "DEFERRED":
        if (prevWord === "BEGIN") replacement = "TRANSACTION";
        break;
      case "ROWID":
        if (prevWord === "WITHOUT") {
          // drop "WITHOUT ROWID": remove the already-emitted WITHOUT
          for (let k = out.length - 1; k >= 0; k--) {
            if (/^WITHOUT$/i.test(out[k])) { out.splice(k, 1); break; }
          }
          replacement = "";
        }
        break;
      default:
        break;
    }
    out.push(replacement);
    prevWord = upper;
    i += word.length;
  }
}

// The date helpers are JavaScript functions (runtime-functions.js). DuckDB calls them through
// Node-API at roughly 1.4 µs per row, which made every sort or histogram over a timestamp
// column a full JavaScript pass. Most timestamps are naive ISO strings, for which the
// functions only trim off the zone-free text, so do that part in SQL and keep the JavaScript
// for zoned, US-style, epoch and other formats. The results are identical: the SQL branch
// only accepts digits, ':', '.' and ',' after "YYYY-MM-DD HH:MM", so it never sees the
// zones, whitespace or 1600/1601/0001 "unset" values the JavaScript handles specially.
const NAIVE_ISO = "'\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}[0-9:.,]*'";
const DATE_FN_RE = /\b(sort_datetime|extract_date|extract_datetime_minute)\(\s*((?:[A-Za-z_][A-Za-z0-9_]*\.)?[A-Za-z_][A-Za-z0-9_]*)\s*\)/g;

function nativeDateExpr(fn, x) {
  let native;
  if (fn === "sort_datetime") native = `CASE WHEN substr(${x}, 11, 1) = 'T' THEN substr(${x}, 1, 10) || ' ' || substr(${x}, 12) ELSE ${x} END`;
  else if (fn === "extract_date") native = `substr(${x}, 1, 10)`;
  else native = `substr(${x}, 1, 10) || ' ' || substr(${x}, 12, 5)`;
  return `(CASE WHEN regexp_full_match(${x}, ${NAIVE_ISO}) THEN (CASE WHEN substr(${x}, 1, 4) IN ('1600', '1601', '0001') THEN NULL ELSE ${native} END) ELSE ${fn}(${x}) END)`;
}

function rewriteDateFunctions(code) {
  return code.replace(DATE_FN_RE, (whole, fn, arg) => nativeDateExpr(fn, arg));
}

function translateSql(sql) {
  if (typeof sql !== "string") return sql;
  const cached = cache.get(sql);
  if (cached !== undefined) return cached;
  const out = [];
  let code = "";
  let i = 0;
  const n = sql.length;
  const flush = () => {
    if (code) { rewriteCode(code, out); code = ""; }
  };
  while (i < n) {
    const ch = sql[i];
    const next = sql[i + 1];
    if (ch === "'" || ch === '"' || ch === "`") {
      flush();
      let j = i + 1;
      while (j < n) {
        if (sql[j] === ch) {
          if (sql[j + 1] === ch) { j += 2; continue; }
          break;
        }
        j++;
      }
      out.push(sql.slice(i, j + 1));
      i = j + 1;
      continue;
    }
    if (ch === "-" && next === "-") {
      flush();
      let j = sql.indexOf("\n", i);
      if (j === -1) j = n;
      out.push(sql.slice(i, j));
      i = j;
      continue;
    }
    if (ch === "/" && next === "*") {
      flush();
      let j = sql.indexOf("*/", i + 2);
      j = j === -1 ? n : j + 2;
      out.push(sql.slice(i, j));
      i = j;
      continue;
    }
    code += ch;
    i++;
  }
  flush();
  const result = out.join("");
  if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
  cache.set(sql, result);
  return result;
}

module.exports = { translateSql, nativeDateExpr };
