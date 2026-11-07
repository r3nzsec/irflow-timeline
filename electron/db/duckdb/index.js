// A better-sqlite3-shaped API over DuckDB.
//
// The timeline engine, its analyzers and the result stores were written against
// better-sqlite3. This class keeps that surface (prepare/all/get/run/iterate, exec, pragma,
// transaction, function) so they run on DuckDB with only their SQL dialect adjusted.
// Calls are synchronous through client.js; SQL passes through sql.js first.
//
// Differences that matter to callers:
//   - rows come back as plain objects with numbers (BIGINT → Number) and 1/0 for booleans;
//   - run() reports `changes`; `lastInsertRowid` is always 0 (nothing reads it);
//   - db.function() only accepts the SQL functions registered by udfs.js;
//   - appendRows(table, rows) bulk-loads arrays in column order (DuckDB's appender).
"use strict";

const { getChannel, createWorkerPort, WORKER_DATA_KEY } = require("./client");
const { translateSql } = require("./sql");
const { UDF_NAMES } = require("./udfs");

const APPEND_BATCH_ROWS = 20000;

const finalizer = typeof FinalizationRegistry === "function"
  ? new FinalizationRegistry(({ channel, h, sid }) => channel.send({ op: "finalize", h, sid }))
  : null;

// DuckDB writes a non-finite double as a bare Infinity/NaN, which is not JSON. SQLite has no
// such values (x / 0 is NULL there), so read them as null. Only a key's closing quote can
// precede `":` here: inside a string value a quote is always escaped.
const NON_FINITE_RE = /(?<!\\)":(-?Infinity|NaN)(?=[,}])/g;

function parseRow(text) {
  try {
    return JSON.parse(text);
  } catch {
    return JSON.parse(text.replace(NON_FINITE_RE, '":null'));
  }
}

/** Row objects from a host reply: { json } (one JSON object per row, see host.js) or { names, columns }. */
function toRows(res, limit = Infinity) {
  if (res.json) {
    const n = Math.min(res.json.length, limit);
    const rows = new Array(n);
    const bools = res.boolCols || [];
    for (let r = 0; r < n; r++) {
      const row = parseRow(res.json[r]);
      for (let b = 0; b < bools.length; b++) {
        const v = row[bools[b]];
        if (v === true) row[bools[b]] = 1; else if (v === false) row[bools[b]] = 0;
      }
      rows[r] = row;
    }
    return rows;
  }
  const { names, columns } = res;
  const n = Math.min(columns.length ? columns[0].length : 0, limit);
  const rows = new Array(n);
  const width = names.length;
  for (let r = 0; r < n; r++) {
    const obj = {};
    for (let c = 0; c < width; c++) obj[names[c]] = columns[c][r];
    rows[r] = obj;
  }
  return rows;
}

function flattenParams(args) {
  if (args.length === 1 && Array.isArray(args[0])) return args[0];
  const out = [];
  for (const a of args) {
    if (Array.isArray(a)) out.push(...a);
    else if (a !== null && typeof a === "object" && !(a instanceof Uint8Array) && !(a instanceof Date)) {
      throw new TypeError("Named parameters are not supported; bind values by position");
    } else out.push(a);
  }
  return out;
}

// sort_datetime(c3) → c3__sdt when the tab has stored that column's sort key. Matches a
// plain or table-qualified column argument only; anything else keeps the function call.
function rewriteComputed(sql, computed) {
  if (!computed || computed.size === 0) return sql;
  let out = sql;
  for (const [fn, map] of computed) {
    if (!map.size || !out.includes(fn)) continue;
    const re = new RegExp(`\\b${fn}\\(\\s*((?:[A-Za-z_][A-Za-z0-9_]*\\.)?)([A-Za-z_][A-Za-z0-9_]*)\\s*\\)`, "g");
    out = out.replace(re, (whole, qual, col) => (map.has(col) ? `${qual}${map.get(col)}` : whole));
  }
  return out;
}

class Statement {
  constructor(db, source) {
    this.database = db;
    this.source = source;
    const r = db._call({ op: "prepare", h: db._h, sql: translateSql(rewriteComputed(source, db._computed)) });
    this._sid = r.sid;
    this._paramCount = r.paramCount;
    this._pluck = false;
    this._raw = false;
    this.reader = /^\s*(SELECT|WITH|VALUES|PRAGMA|EXPLAIN|DESCRIBE|SHOW|FROM)\b/i.test(source)
      || /\bRETURNING\b/i.test(source);
    if (finalizer) finalizer.register(this, { channel: db._channel, h: db._h, sid: this._sid }, this);
  }

  pluck(toggle = true) { this._pluck = !!toggle; if (toggle) this._raw = false; return this; }
  raw(toggle = true) { this._raw = !!toggle; if (toggle) this._pluck = false; return this; }

  _shape(row) {
    if (row === undefined) return undefined;
    if (this._pluck) {
      for (const k in row) return row[k];
      return undefined;
    }
    if (this._raw) return Object.values(row);
    return row;
  }

  run(...args) {
    return this.database._call({ op: "run", h: this.database._h, sid: this._sid, params: flattenParams(args) });
  }

  get(...args) {
    const res = this.database._call({ op: "get", h: this.database._h, sid: this._sid, params: flattenParams(args) });
    return this._shape(toRows(res, 1)[0]);
  }

  all(...args) {
    const res = this.database._call({ op: "all", h: this.database._h, sid: this._sid, params: flattenParams(args) });
    const rows = toRows(res);
    return (this._pluck || this._raw) ? rows.map((r) => this._shape(r)) : rows;
  }

  *iterate(...args) {
    const db = this.database;
    const iid = db._call({ op: "iterOpen", h: db._h, sid: this._sid, params: flattenParams(args) });
    let done = false;
    try {
      while (!done) {
        const batch = db._call({ op: "iterNext", iid, max: 2048 });
        done = batch.done;
        for (const row of toRows(batch)) yield this._shape(row);
      }
    } finally {
      if (!done && db.open) {
        try { db._call({ op: "iterClose", iid }); } catch {}
      }
    }
  }

  finalize() {
    if (finalizer) finalizer.unregister(this);
    if (this.database.open) this.database._channel.send({ op: "finalize", h: this.database._h, sid: this._sid });
  }
}

class Database {
  constructor(filename, options = {}) {
    if (!filename) throw new TypeError("A database file path (or \":memory:\") is required");
    this.name = filename;
    this.memory = filename === ":memory:";
    this.readonly = !!options.readonly;
    this.inTransaction = false;
    this._channel = getChannel();
    this._h = this._channel.call({ op: "open", path: filename });
    this.open = true;
    this._txDepth = 0;
    this._computed = new Map(); // function name -> Map(column -> stored column)
  }

  /** Read `fn(col)` from a stored column for the columns in `map` (Map col → column). */
  setComputedColumns(fn, map) {
    if (map && map.size) this._computed.set(fn, new Map(map));
    else this._computed.delete(fn);
  }

  _call(message) {
    if (!this.open && message.op !== "close") throw new TypeError("The database connection is not open");
    return this._channel.call(message);
  }

  prepare(sql) {
    return new Statement(this, sql);
  }

  exec(sql) {
    this._call({ op: "exec", h: this._h, sql: translateSql(rewriteComputed(sql, this._computed)) });
    return this;
  }

  /**
   * SQLite pragmas. DuckDB tunes itself (memory, threads, WAL), so the performance pragmas
   * are accepted and ignored; table_info/table_list map to DuckDB's own.
   */
  pragma(source, options = {}) {
    const text = String(source).trim();
    const name = text.match(/^[a-z_]+/i)?.[0]?.toLowerCase() || "";
    let rows;
    if (name === "table_info") {
      const arg = text.match(/\(\s*['"]?([^'")]+)['"]?\s*\)/)?.[1] || "data";
      rows = this.prepare(`PRAGMA table_info('${arg.replace(/'/g, "''")}')`).all();
    } else if (name === "page_size") {
      rows = [{ page_size: 262144 }];
    } else if (name === "page_count" || name === "freelist_count") {
      rows = [{ [name]: 0 }];
    } else {
      rows = [];
    }
    if (options.simple) {
      const first = rows[0];
      if (!first) return undefined;
      for (const k in first) return first[k];
      return undefined;
    }
    return rows;
  }

  transaction(fn) {
    const db = this;
    const wrapped = function transactionWrapper(...args) {
      if (db._txDepth > 0) {
        // DuckDB has no SAVEPOINT; nested transactions join the outer one.
        db._txDepth++;
        try { return fn.apply(this, args); } finally { db._txDepth--; }
      }
      db._call({ op: "exec", h: db._h, sql: "BEGIN TRANSACTION" });
      db._txDepth = 1;
      db.inTransaction = true;
      try {
        const result = fn.apply(this, args);
        db._call({ op: "exec", h: db._h, sql: "COMMIT" });
        return result;
      } catch (err) {
        try { db._call({ op: "exec", h: db._h, sql: "ROLLBACK" }); } catch {}
        throw err;
      } finally {
        db._txDepth = 0;
        db.inTransaction = false;
      }
    };
    wrapped.deferred = wrapped;
    wrapped.immediate = wrapped;
    wrapped.exclusive = wrapped;
    return wrapped;
  }

  function(name) {
    if (UDF_NAMES.includes(name)) return this; // registered once on the host (udfs.js)
    throw new Error(`SQL function ${name} is not registered for DuckDB (see electron/db/duckdb/udfs.js)`);
  }

  /**
   * Bulk-load rows (arrays in the table's column order) through DuckDB's appender.
   * With `firstRowid`, the table's first column is numbered firstRowid, firstRowid + 1, …
   * and each row holds only the remaining columns.
   *
   * The rows are copied to the DuckDB thread at once but loaded in the background while
   * the caller goes on (see Channel.post); any later call on this database waits for them
   * and reports a failure. Call flush() to wait explicitly.
   */
  appendRows(table, rows, { firstRowid = null } = {}) {
    if (!this.open) throw new TypeError("The database connection is not open");
    if (!rows || rows.length === 0) return 0;
    for (let i = 0; i < rows.length; i += APPEND_BATCH_ROWS) {
      const slice = (i === 0 && rows.length <= APPEND_BATCH_ROWS) ? rows : rows.slice(i, i + APPEND_BATCH_ROWS);
      this._channel.post({ op: "append", h: this._h, table, rows: slice, firstRowid: firstRowid == null ? null : firstRowid + i });
    }
    return rows.length;
  }

  /** Wait until every queued append has been loaded; throws if one failed. */
  flush() {
    if (!this.open) return this;
    this._channel.waitAsync(0);
    this._call({ op: "exec", h: this._h, sql: "SELECT 1" });
    return this;
  }

  interrupt() {
    if (this.open) this._channel.send({ op: "interrupt", h: this._h });
  }

  checkpoint() {
    if (this.open) this._call({ op: "exec", h: this._h, sql: "CHECKPOINT" });
  }

  close() {
    if (!this.open) return this;
    this.open = false;
    try { this._channel.call({ op: "close", h: this._h }); } catch {}
    return this;
  }
}

module.exports = Database;
module.exports.Database = Database;
module.exports.createWorkerPort = createWorkerPort;
module.exports.WORKER_DATA_KEY = WORKER_DATA_KEY;
