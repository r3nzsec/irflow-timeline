// Search-box conditions and quoted phrases.
//
// Equals, Starts with and Like compare whole cell values, so the search box must compare the
// whole input — as Edit Filter does — instead of each word: Equals `Local Settings` used to
// require one cell equal to "Local" and another equal to "Settings", and double quotes became
// part of the value. Quoted phrases now also work with a column (`KeyPath:"Local Settings"`)
// and with a sign (`-"Local Settings"`).
//
// Runs on the DuckDB engine; skipped when its binding is not installed for this runtime.

const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
let createTestDataTable = null;
try { ({ Database, createTestDataTable } = require("./helpers/duckdb-data-table")); } catch { /* DuckDB binding not installed */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();
const SKIP = HAVE_SQLITE ? false : "DuckDB binding not available for this runtime";

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
  createTestDataTable(db, "c0, c1, c2");
  const ins = db.prepare("INSERT INTO data(rowid,c0,c1,c2) VALUES (?,?,?,?)");
  for (const r of ROWS) ins.run(...r);
  const headers = ["KeyPath", "ValueName", "ValueData"];
  const safeCols = headers.map((original, i) => ({ original, safe: `c${i}` }));
  const colMap = Object.fromEntries(safeCols.map((c) => [c.original, c.safe]));
  return (term, mode, cond) => {
    const wc = [];
    const params = [];
    proto._applySearch(term, mode, { safeCols, colMap, headers }, wc, params, cond);
    const sql = `SELECT rowid FROM data${wc.length ? " WHERE " + wc.join(" AND ") : ""}`;
    return db.prepare(sql).all(...params).map((r) => r.rowid).sort((a, b) => a - b);
  };
}

test("Equals compares the whole input, with or without double quotes", { skip: SKIP }, () => {
  const search = setup();
  assert.deepEqual(search("Local Settings", "mixed", "equals"), [2], "not the row whose cells are Local and Settings");
  assert.deepEqual(search('"Local Settings"', "mixed", "equals"), [2]);
  assert.deepEqual(search('"Local Settings"', "exact", "equals"), [2]);
  assert.deepEqual(search("Local", "mixed", "equals"), [3]);
  assert.deepEqual(search("local settings", "mixed", "equals"), [], "case-sensitive, like Edit Filter's Equals");
});

test("Equals, Starts with and Like accept Col:value and Col:\"value\" in Mixed mode", { skip: SKIP }, () => {
  const search = setup();
  assert.deepEqual(search("KeyPath:Local Settings", "mixed", "equals"), [2]);
  assert.deepEqual(search('KeyPath:"Local Settings"', "mixed", "equals"), [2]);
  assert.deepEqual(search('ValueName:"Local Settings"', "mixed", "equals"), []);
  assert.deepEqual(search("ValueName:Local", "mixed", "equals"), [3]);
  assert.deepEqual(search("ROOT\\Local Settings", "mixed", "startswith"), [1]);
  assert.deepEqual(search("KeyPath:ROOT\\Software", "mixed", "startswith"), [3, 4]);
  assert.deepEqual(search("%Local Settings%", "mixed", "like"), [1, 2]);
  assert.deepEqual(search("C:\\Users\\Public\\updater.exe", "mixed", "equals"), [4], "an unknown Col: prefix is part of the value");
});

test("OR and AND mode keep several values; quotes group a phrase", { skip: SKIP }, () => {
  const search = setup();
  assert.deepEqual(search('"Local Settings" Updater', "or", "equals"), [2, 4]);
  assert.deepEqual(search("Local Settings", "and", "equals"), [3], "one cell per value");
  assert.deepEqual(search('"Local Settings" BagMRU', "and", "contains"), [1]);
  assert.deepEqual(search('"Local Settings" Updater', "or", "contains"), [1, 2, 4]);
});

test("Contains: quoted phrases with a column or a sign", { skip: SKIP }, () => {
  const search = setup();
  assert.deepEqual(search('"Local Settings"', "mixed", "contains"), [1, 2]);
  assert.deepEqual(search("Local Settings", "mixed", "contains"), [1, 2, 3], "bare words still match anywhere");
  assert.deepEqual(search('KeyPath:"Local Settings"', "mixed", "contains"), [1, 2]);
  assert.deepEqual(search('ValueName:"Local Settings"', "mixed", "contains"), []);
  assert.deepEqual(search('-"Local Settings"', "mixed", "contains"), [3, 4]);
  assert.deepEqual(search('+"Local Settings" BagMRU', "mixed", "contains"), [1]);
  assert.deepEqual(search('-KeyPath:"Local Settings" Software', "mixed", "contains"), [3, 4]);
  assert.deepEqual(search('"Local Settings"', "exact", "contains"), [1, 2], "Exact drops quotes around the whole input");
});

test("Fuzzy keeps a quoted phrase together", { skip: SKIP }, () => {
  const search = setup();
  assert.deepEqual(search('"Local Settings"', "mixed", "fuzzy"), search("Local Settings", "exact", "fuzzy"));
});

test("Contains does not match a phrase across two columns", { skip: SKIP }, () => {
  const search = setup();
  // Row 3 has ValueName "Local" and ValueData "Settings"; neither cell contains the phrase.
  assert.deepEqual(search('"Local Settings"', "mixed", "contains"), [1, 2]);
  assert.deepEqual(search("Local Settings", "exact", "contains"), [1, 2]);
  assert.deepEqual(search("Local Settings", "mixed", "contains"), [1, 2, 3], "separate words may be in different cells");
});
