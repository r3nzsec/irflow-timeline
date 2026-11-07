// The thread that owns DuckDB for the whole process.
//
// Every database file the app opens is ATTACHed to ONE in-memory DuckDB instance that lives
// on this worker thread, so all tabs share one buffer pool, one thread pool and one set of
// SQL functions, and the same file is never opened twice. Other threads (the Electron main
// thread and the job workers) talk to it through a MessagePort plus a SharedArrayBuffer
// flag; client.js turns that into synchronous calls (see the comment there).
"use strict";

const { parentPort, workerData } = require("worker_threads");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const duck = require("@duckdb/node-api");
const { registerUdfs } = require("./udfs");

const T = duck.DuckDBTypeId;
const INTEGER_TYPES = new Set([T.TINYINT, T.SMALLINT, T.INTEGER, T.BIGINT, T.UTINYINT, T.USMALLINT, T.UINTEGER, T.UBIGINT, T.HUGEINT, T.UHUGEINT]);
const FLOAT_TYPES = new Set([T.FLOAT, T.DOUBLE, T.DECIMAL]);

let instance = null;
let admin = null;
let initPromise = null;
const attached = new Map(); // absolute path -> { alias, refs }
let nextId = 1;

function settings() {
  const cfg = workerData?.settings || {};
  const totalMb = Math.floor(os.totalmem() / (1024 * 1024));
  // DuckDB defaults to 80% of RAM. The renderer, Electron and the JS analyzers need room too.
  const memoryMb = cfg.memoryLimitMb || Math.max(1024, Math.floor(totalMb * 0.5));
  const tempDir = cfg.tempDirectory || path.join(os.tmpdir(), `irflow-duckdb-${process.pid}`);
  return { memoryMb, tempDir, threads: cfg.threads || 0 };
}

async function init() {
  if (!initPromise) {
    initPromise = (async () => {
      const s = settings();
      const options = {
        memory_limit: `${s.memoryMb}MB`,
        temp_directory: s.tempDir,
        // SQLite puts NULLs first in ascending order; keep the grid's sort order unchanged.
        default_null_order: "nulls_first_on_asc_last_on_desc",
        // Never fetch extensions over the network from a forensic workstation.
        autoinstall_known_extensions: "false",
        autoload_known_extensions: "false",
      };
      if (s.threads > 0) options.threads = String(s.threads);
      instance = await duck.DuckDBInstance.create(":memory:", options);
      admin = await instance.connect();
      // SQLite divides integers as integers (7 / 2 = 3); the analyzers rely on that.
      await admin.run("SET GLOBAL integer_division = true");
      registerUdfs(admin);
      return { tempDir: s.tempDir };
    })();
  }
  return initPromise;
}

function sqlString(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function aliasFor(absPath) {
  return `db_${crypto.createHash("sha1").update(absPath).digest("hex").slice(0, 16)}`;
}

let memoryCount = 0;

async function attach(filePath) {
  if (filePath === ":memory:") {
    // A private in-memory database per open (tests and scratch work), never shared.
    const alias = `mem_${process.pid}_${++memoryCount}`;
    await admin.run(`ATTACH ':memory:' AS ${alias}`);
    const entry = { alias, absPath: `:memory:${alias}`, refs: 1 };
    attached.set(entry.absPath, entry);
    return entry;
  }
  const absPath = path.resolve(filePath);
  let entry = attached.get(absPath);
  if (entry) {
    entry.refs++;
    return entry;
  }
  const alias = aliasFor(absPath);
  await admin.run(`ATTACH ${sqlString(absPath)} AS ${alias}`);
  entry = { alias, absPath, refs: 1 };
  attached.set(absPath, entry);
  return entry;
}

async function detach(entry) {
  entry.refs--;
  if (entry.refs > 0) return;
  attached.delete(entry.absPath);
  try { await admin.run(`DETACH ${entry.alias}`); } catch { /* already gone */ }
}

// ── Values ──────────────────────────────────────────────────────────

function toJs(value) {
  if (typeof value === "bigint") {
    return (value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER))
      ? Number(value)
      : value.toString();
  }
  if (typeof value === "boolean") return value ? 1 : 0; // SQLite has no booleans
  if (value instanceof Date) return value.toISOString();
  return value;
}

// Results travel to the calling thread column by column: arrays of strings and numbers
// clone far faster than one object per row, and the caller builds the row objects
// (index.js) once on its side.
const PLAIN_TYPES = new Set([T.VARCHAR, T.DOUBLE, T.FLOAT, T.INTEGER, T.SMALLINT, T.TINYINT, T.UTINYINT, T.USMALLINT, T.UINTEGER]);
const BIG_TYPES = new Set([T.BIGINT, T.UBIGINT, T.HUGEINT, T.UHUGEINT]);

function chunkColumns(chunk) {
  const out = new Array(chunk.columnCount);
  for (let c = 0; c < chunk.columnCount; c++) {
    const typeId = chunk.getColumnVector(c).type.typeId;
    let values;
    if (PLAIN_TYPES.has(typeId)) {
      values = chunk.getColumnValues(c);
    } else if (BIG_TYPES.has(typeId) || typeId === T.BOOLEAN) {
      values = chunk.getColumnValues(c);
      for (let i = 0; i < values.length; i++) values[i] = toJs(values[i]);
    } else {
      values = chunk.convertColumnValues(c, duck.JSDuckDBValueConverter);
      for (let i = 0; i < values.length; i++) values[i] = toJs(values[i]);
    }
    out[c] = values;
  }
  return out;
}

// Bulk reads come back as one JSON string per row. The Node API decodes every text value
// longer than 12 bytes with its own native call (~0.7 µs each), which made a 50,000-row,
// 19-column result take ~4× as long as with SQLite; one to_json() string per row needs one
// decode, and JSON.parse on the calling side rebuilds the object. Only for results whose
// columns JSON keeps exactly (text, numbers, booleans); everything else is read by column.
const JSON_SAFE_TYPES = new Set([...PLAIN_TYPES, ...BIG_TYPES, T.BOOLEAN, T.DECIMAL, T.SQLNULL]);
const SELECT_STATEMENT = 1; // duckdb StatementType.SELECT

async function jsonPlan(conn, s) {
  if (s.json !== undefined) return s.json;
  s.json = null;
  const p = s.prepared;
  if (p.statementType !== SELECT_STATEMENT || p.columnCount === 0) return null;
  const names = [];
  const boolCols = [];
  for (let c = 0; c < p.columnCount; c++) {
    const name = p.columnName(c);
    if (names.includes(name)) return null; // duplicate names cannot be struct fields
    names.push(name);
    const t = p.columnTypeId(c);
    if (!JSON_SAFE_TYPES.has(t)) return null;
    if (t === T.BOOLEAN) boolCols.push(name);
  }
  try {
    const wrapped = await conn.prepare(`SELECT to_json(q)::VARCHAR AS j FROM (${s.sql}) q`);
    s.json = { prepared: wrapped, paramTypes: s.paramTypes, names, boolCols };
  } catch {
    s.json = null;
  }
  return s.json;
}

async function readJson(result, max = Infinity, pending = null) {
  const json = [];
  let done = false;
  if (pending && pending.cols) {
    const n = Math.min(pending.cols.length - pending.from, max);
    for (let i = 0; i < n; i++) json.push(pending.cols[pending.from + i]);
    pending.from += n;
    if (pending.from >= pending.cols.length) pending.cols = null;
  }
  while (json.length < max) {
    const chunk = await result.fetchChunk();
    if (!chunk || chunk.rowCount === 0) { done = true; break; }
    const values = chunk.getColumnValues(0);
    const n = Math.min(values.length, max - json.length);
    for (let i = 0; i < n; i++) json.push(values[i]);
    if (pending && n < values.length) { pending.cols = values; pending.from = n; }
  }
  return { json, done };
}

/** Read up to `max` rows (all when max is Infinity) as { names, columns, done }. */
async function readColumns(result, names, max = Infinity, pending = null) {
  const columns = names.map(() => []);
  let count = 0;
  let done = false;
  const take = (cols, from) => {
    const n = Math.min(cols.length ? cols[0].length - from : 0, max - count);
    for (let c = 0; c < cols.length; c++) {
      const dst = columns[c];
      const src = cols[c];
      for (let i = 0; i < n; i++) dst.push(src[from + i]);
    }
    count += n;
    return from + n;
  };
  if (pending && pending.cols) {
    pending.from = take(pending.cols, pending.from);
    if (pending.from >= pending.cols[0].length) pending.cols = null;
  }
  while (count < max) {
    const chunk = await result.fetchChunk();
    if (!chunk || chunk.rowCount === 0) { done = true; break; }
    const cols = chunkColumns(chunk);
    const used = take(cols, 0);
    if (pending && used < cols[0].length) { pending.cols = cols; pending.from = used; }
  }
  return { names, columns, done };
}

// SQLite converts a bound value to the column's affinity; DuckDB casts instead and fails
// on mismatches (a number bound against a VARCHAR column). Bind by the type DuckDB
// inferred for each parameter, falling back to the JS type when it could not infer one.
function bindParams(stmt, params) {
  const types = stmt.paramTypes;
  if (params.length !== types.length) {
    throw new RangeError(`Expected ${types.length} bound parameter(s), got ${params.length}`);
  }
  const p = stmt.prepared;
  p.clearBindings();
  for (let i = 0; i < params.length; i++) {
    const idx = i + 1;
    let v = params[i];
    if (v === undefined || v === null) { p.bindNull(idx); continue; }
    if (typeof v === "boolean") v = v ? 1 : 0;
    const t = types[i];
    if (t === T.VARCHAR) {
      p.bindVarchar(idx, Buffer.isBuffer(v) ? v.toString() : String(v));
    } else if (INTEGER_TYPES.has(t)) {
      const num = typeof v === "bigint" ? v : Number(v);
      if (typeof num === "bigint") p.bindBigInt(idx, num);
      else if (Number.isInteger(num)) p.bindBigInt(idx, BigInt(num));
      else if (Number.isFinite(num)) p.bindDouble(idx, num);
      else p.bindVarchar(idx, String(v));
    } else if (FLOAT_TYPES.has(t)) {
      const num = Number(v);
      if (Number.isFinite(num)) p.bindDouble(idx, num); else p.bindVarchar(idx, String(v));
    } else if (t === T.BOOLEAN) {
      p.bindBoolean(idx, !!Number(v));
    } else if (t === T.BLOB && (v instanceof Uint8Array)) {
      p.bindBlob(idx, v);
    } else if (typeof v === "bigint") {
      p.bindBigInt(idx, v);
    } else if (typeof v === "number") {
      if (Number.isInteger(v)) p.bindBigInt(idx, BigInt(v)); else p.bindDouble(idx, v);
    } else if (v instanceof Uint8Array) {
      p.bindBlob(idx, v);
    } else {
      p.bindVarchar(idx, String(v));
    }
  }
}

// ── Clients ─────────────────────────────────────────────────────────

class Client {
  constructor(port, flag) {
    this.port = port;
    this.flag = flag;
    this.handles = new Map();
    this.iterators = new Map();
    this.queue = Promise.resolve();
    this.closed = false;
    this.deferredError = null; // first failure of an async operation, reported by the next call
  }

  reply(message) {
    if (this.closed) return;
    try {
      this.port.postMessage(message);
    } catch (err) {
      this.port.postMessage({ ok: false, error: `Could not send the result: ${err.message}` });
    }
    Atomics.store(this.flag, 0, 1);
    Atomics.notify(this.flag, 0);
  }

  handle(id) {
    const h = this.handles.get(id);
    if (!h) throw new Error("The database connection is not open");
    return h;
  }

  stmt(h, sid) {
    const s = h.statements.get(sid);
    if (!s) throw new Error("The statement has been finalized");
    return s;
  }

  async dispatch(msg) {
    switch (msg.op) {
      case "open": {
        await init();
        const entry = await attach(msg.path);
        let conn;
        try {
          conn = await instance.connect();
          await conn.run(`USE ${entry.alias}`);
        } catch (err) {
          try { conn?.closeSync(); } catch {}
          await detach(entry);
          throw err;
        }
        const id = nextId++;
        this.handles.set(id, { id, conn, entry, statements: new Map() });
        return id;
      }
      case "setTempDirectory": {
        await init();
        const dir = String(msg.dir).replace(/'/g, "''");
        try { await admin.run(`SET GLOBAL temp_directory = '${dir}'`); } catch { /* in use: keep the old one */ }
        return true;
      }
      case "close": {
        const h = this.handles.get(msg.h);
        if (!h) return true;
        await this.closeHandle(h);
        return true;
      }
      case "exec": {
        const h = this.handle(msg.h);
        await h.conn.run(msg.sql);
        return true;
      }
      case "prepare": {
        const h = this.handle(msg.h);
        const prepared = await h.conn.prepare(msg.sql);
        const paramTypes = [];
        for (let i = 1; i <= prepared.parameterCount; i++) {
          let t;
          try { t = prepared.parameterTypeId(i); } catch { t = T.INVALID; }
          paramTypes.push(t);
        }
        const sid = nextId++;
        h.statements.set(sid, { prepared, paramTypes, sql: msg.sql });
        return { sid, paramCount: paramTypes.length };
      }
      case "finalize": {
        const h = this.handles.get(msg.h);
        const s = h?.statements.get(msg.sid);
        if (s) {
          h.statements.delete(msg.sid);
          try { s.json?.prepared.destroySync(); } catch {}
          try { s.prepared.destroySync(); } catch {}
        }
        return true;
      }
      case "run": {
        const h = this.handle(msg.h);
        const s = this.stmt(h, msg.sid);
        bindParams(s, msg.params);
        const result = await s.prepared.run();
        return { changes: Number(result.rowsChanged || 0), lastInsertRowid: 0 };
      }
      case "all":
      case "get": {
        const h = this.handle(msg.h);
        const s = this.stmt(h, msg.sid);
        bindParams(s, msg.params);
        // Materialized, not streamed: a streaming result left open on the connection
        // would invalidate the next statement run on it. (An exhausted result keeps
        // returning empty chunks, never null; the readers stop at the first.)
        const plan = msg.op === "all" && !msg.noJson ? await jsonPlan(h.conn, s) : null;
        if (plan) {
          bindParams(plan, msg.params);
          const { json } = await readJson(await plan.prepared.run());
          return { names: plan.names, json, boolCols: plan.boolCols };
        }
        const result = await s.prepared.run();
        const { names, columns } = await readColumns(result, result.columnNames(), msg.op === "get" ? 1 : Infinity);
        return { names, columns };
      }
      case "iterOpen": {
        // A dedicated connection, so other statements can run on the tab's connection
        // while the caller is still walking the result (DuckDB would otherwise invalidate it).
        const h = this.handle(msg.h);
        const s = this.stmt(h, msg.sid);
        const conn = await instance.connect();
        try {
          await conn.run(`USE ${h.entry.alias}`);
          const own = { prepared: await conn.prepare(s.sql), paramTypes: s.paramTypes, sql: s.sql };
          const plan = msg.noJson ? null : await jsonPlan(conn, own);
          const runner = plan || own;
          bindParams(runner, msg.params);
          const result = await runner.prepared.stream();
          const iid = nextId++;
          this.iterators.set(iid, {
            conn, prepared: own.prepared, wrapped: plan?.prepared || null, result,
            names: plan ? plan.names : result.columnNames(), json: !!plan, boolCols: plan?.boolCols || [],
            pending: { cols: null, from: 0 }, handle: h.id,
          });
          return iid;
        } catch (err) {
          try { conn.closeSync(); } catch {}
          throw err;
        }
      }
      case "iterNext": {
        const it = this.iterators.get(msg.iid);
        if (!it) return { names: [], columns: [], done: true };
        const batch = it.json
          ? { ...(await readJson(it.result, msg.max || 2048, it.pending)), names: it.names, boolCols: it.boolCols }
          : await readColumns(it.result, it.names, msg.max || 2048, it.pending);
        if (batch.done) this.closeIterator(msg.iid);
        return batch;
      }
      case "iterClose": {
        this.closeIterator(msg.iid);
        return true;
      }
      case "append": {
        const h = this.handle(msg.h);
        const appender = await h.conn.createAppender(msg.table, null, h.entry.alias);
        try {
          const types = [];
          for (let c = 0; c < appender.columnCount; c++) types.push(appender.columnType(c).typeId);
          const rows = msg.rows;
          // With firstRowid, the table's first column is a rowid numbered here and each
          // row holds the remaining columns (saves the caller copying every row).
          const numbered = msg.firstRowid != null;
          const first = numbered ? 1 : 0;
          for (let r = 0; r < rows.length; r++) {
            const row = rows[r];
            if (numbered) appender.appendBigInt(BigInt(msg.firstRowid + r));
            for (let c = first; c < types.length; c++) {
              const v = row[c - first];
              if (v === null || v === undefined) { appender.appendNull(); continue; }
              const t = types[c];
              if (t === T.VARCHAR) appender.appendVarchar(typeof v === "string" ? v : String(v));
              else if (t === T.BIGINT) appender.appendBigInt(BigInt(v));
              else if (t === T.INTEGER) appender.appendInteger(Number(v));
              else if (t === T.DOUBLE) appender.appendDouble(Number(v));
              else if (t === T.BOOLEAN) appender.appendBoolean(!!v);
              else appender.appendVarchar(String(v));
            }
            appender.endRow();
          }
          appender.flushSync();
        } finally {
          appender.closeSync();
        }
        return msg.rows.length;
      }
      default:
        throw new Error(`Unknown DuckDB host operation: ${msg.op}`);
    }
  }

  closeIterator(iid) {
    const it = this.iterators.get(iid);
    if (!it) return;
    this.iterators.delete(iid);
    try { it.wrapped?.destroySync(); } catch {}
    try { it.prepared.destroySync(); } catch {}
    try { it.conn.closeSync(); } catch {}
  }

  async closeHandle(h) {
    this.handles.delete(h.id);
    for (const [iid, it] of this.iterators) if (it.handle === h.id) this.closeIterator(iid);
    for (const s of h.statements.values()) {
      try { s.json?.prepared.destroySync(); } catch {}
      try { s.prepared.destroySync(); } catch {}
    }
    h.statements.clear();
    try { h.conn.closeSync(); } catch {}
    await detach(h.entry);
  }

  async shutdown() {
    this.closed = true;
    for (const h of this.handles.values()) {
      try { h.conn.interrupt(); } catch {}
    }
    for (const h of [...this.handles.values()]) await this.closeHandle(h);
  }

  enqueue(msg) {
    this.queue = this.queue.then(async () => {
      if (msg.async) {
        if (!this.deferredError) {
          try { await this.dispatch(msg); } catch (err) { this.deferredError = err?.message || String(err); }
        }
        Atomics.add(this.flag, 1, 1);
        Atomics.notify(this.flag, 1);
        return;
      }
      let message;
      if (this.deferredError && !msg.noReply) {
        message = { ok: false, error: this.deferredError };
        this.deferredError = null;
      } else {
        try {
          message = { ok: true, value: await this.dispatch(msg) };
        } catch (err) {
          message = { ok: false, error: err?.message || String(err) };
        }
      }
      if (!msg.noReply) this.reply(message);
    });
  }
}

function serve(port, sab) {
  const client = new Client(port, new Int32Array(sab));
  port.on("message", (msg) => {
    if (msg?.op === "interrupt") {
      // Out of band: the queue is busy with the very query this should stop.
      try { client.handles.get(msg.h)?.conn.interrupt(); } catch {}
      return;
    }
    client.enqueue(msg);
  });
  // The other side went away (thread exited or was terminated mid-query): stop its
  // queries and release its files so they can be deleted.
  port.on("close", () => {
    client.queue = client.queue.then(() => client.shutdown()).catch(() => {});
  });
  port.start();
}

parentPort.on("message", (msg) => {
  if (msg?.type === "client") serve(msg.port, msg.sab);
  if (msg?.type === "cleanup") {
    try { fs.rmSync(settings().tempDir, { recursive: true, force: true }); } catch {}
  }
});


