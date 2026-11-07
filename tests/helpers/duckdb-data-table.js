// Test fixtures for the DuckDB timeline engine.
//
// Production tabs store rows in `data (rowid BIGINT, c0 VARCHAR, …)` with rowid = 1, 2, 3, …
// (db.js createTab). DuckDB also has a hidden 0-based rowid, so a fixture table without the
// column would hand the analyzers different row ids than a real tab. createTestDataTable
// builds the production layout and returns an INSERT for the c-columns (rowid fills itself).
"use strict";

const Database = require("../../electron/db/duckdb");

function openTestDb() {
  return new Database(":memory:");
}

/** `colDefs` is the old SQLite column list, e.g. "c0 TEXT, c1 TEXT"; types are ignored. */
function createTestDataTable(db, colDefs) {
  const names = String(colDefs).split(",").map((s) => s.trim().split(/\s+/)[0]).filter(Boolean);
  db.exec("CREATE SEQUENCE IF NOT EXISTS data_rowid_seq START 1");
  db.exec(`CREATE TABLE data (rowid BIGINT DEFAULT nextval('data_rowid_seq'), ${names.map((n) => `${n} VARCHAR`).join(", ")})`);
  return db.prepare(`INSERT INTO data (${names.join(", ")}) VALUES (${names.map(() => "?").join(", ")})`);
}

module.exports = { Database, openTestDb, createTestDataTable };
