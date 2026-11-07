// The search box's Ends with condition, next to Starts with.
//
// Needs a live SQLite binding; skipped when the native module is not built for this runtime.

const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
try { Database = require("better-sqlite3"); } catch { /* native module not built */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();
const SKIP = HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime";

const proto = require("../electron/db/query-store");
const { registerRuntimeFunctions } = require("../electron/db/runtime-functions");

const ROWS = [
  [1, "ROOT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", "NodeSlot", "3"],
  [2, "Local Settings", "(default)", ""],
  [3, "ROOT\\Software\\Classes\\Local\\Settings", "Local", "Settings"],
  [4, "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Updater", "C:\\Users\\Public\\updater.exe"],
];

function setup() {
  const db = new Database(":memory:");
  registerRuntimeFunctions(db);
  db.exec("CREATE TABLE data (c0 TEXT, c1 TEXT, c2 TEXT)");
  const ins = db.prepare("INSERT INTO data(rowid,c0,c1,c2) VALUES (?,?,?,?)");
  for (const r of ROWS) ins.run(...r);
  const headers = ["KeyPath", "ValueName", "ValueData"];
  const safeCols = headers.map((original, i) => ({ original, safe: `c${i}` }));
  const colMap = Object.fromEntries(safeCols.map((c) => [c.original, c.safe]));
  return (term, mode) => {
    const wc = [];
    const params = [];
    proto._applySearch(term, mode, { safeCols, colMap, headers, ftsReady: false }, wc, params, "endswith");
    const sql = `SELECT rowid FROM data${wc.length ? " WHERE " + wc.join(" AND ") : ""}`;
    return db.prepare(sql).all(...params).map((r) => r.rowid).sort((a, b) => a - b);
  };
}

test("Ends with matches the end of a cell, ignoring case", { skip: SKIP }, () => {
  const search = setup();
  assert.deepEqual(search("BagMRU", "mixed"), [1]);
  assert.deepEqual(search("bagmru", "mixed"), [1], "case-insensitive, like Starts with");
  assert.deepEqual(search("Settings", "mixed"), [2, 3]);
  assert.deepEqual(search(".exe", "mixed"), [4]);
  assert.deepEqual(search("Local Settings", "exact"), [2], "Exact mode: the whole input");
  assert.deepEqual(search("BagMRU updater.exe", "or"), [1, 4]);
  assert.deepEqual(search("Windows", "mixed"), [], "not Contains: Windows is only in the middle");
});

test("Ends with is offered next to Starts with", async () => {
  const { SEARCH_CONDITIONS } = await import("../src/constants/ui-controls.js");
  const values = SEARCH_CONDITIONS.map((c) => c.value);
  assert.equal(values.indexOf("endswith"), values.indexOf("startswith") + 1);
  assert.equal(SEARCH_CONDITIONS.find((c) => c.value === "endswith").label, "Ends with");
});
