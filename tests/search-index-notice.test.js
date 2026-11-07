// No "Search index skipped (large file)" warning on import.
//
// The DuckDB engine builds no full-text index, so after every import the main process tells
// the renderer the search-index phase is done. The renderer warns "Search index skipped (large
// file)" whenever that message carries `skipped`, so it must not, or every import warns.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("the main process never reports the search index as skipped", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "electron", "main.js"), "utf8");
  const sends = [...source.matchAll(/safeSend\(\s*"fts-progress"\s*,\s*\{([^}]*)\}/g)].map((m) => m[1]);
  assert.ok(sends.length > 0, "main.js should still close the search-index phase with fts-progress");
  for (const fields of sends) {
    assert.doesNotMatch(fields, /\bskipped\b/, `fts-progress must not carry skipped: { ${fields.trim()} }`);
  }
});
