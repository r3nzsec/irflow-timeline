// Adopting a tab must not compile its write statements.
//
// adoptTabFromFile is not only the main process taking over a finished import — every
// scroll-window query spawns a worker that adopts the same tab, runs one SELECT and exits.
// Eagerly preparing the write surface there compiled an INSERT with up to 32,766
// placeholders (a SQL string tens of KB wide) plus six bookmark/tag statements for a
// connection that never writes, on the latency path of every fetch during a fast scroll.
//
// Needs a live SQLite binding; skipped under a Node runtime without the native module built
// (CI rebuilds it). Run after `npm rebuild better-sqlite3`.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

let Database = null;
try { Database = require("better-sqlite3"); } catch { /* native module not built */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();
const skip = HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime";

const TimelineDB = require("../electron/db");

/** Build a real tab on disk, close it, and hand back the descriptor adopt() takes. */
function makeTabFile(headers, rows) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-adopt-"));
  const dbPath = path.join(dir, "tab.sqlite");
  const db = new TimelineDB();
  db._dbPathHint = dbPath;
  db.createTab("seed", headers);
  db.insertBatchArrays("seed", rows);
  db.finalizeImport("seed");
  const meta = db.databases.get("seed");
  const descriptor = { dbPath: meta.dbPath, headers, rowCount: rows.length };
  // Release the connection without closeTab(), which unlinks the file we are about to adopt.
  meta.db.close();
  db.databases.delete("seed");
  db.closeAll(); // map is empty, so this only stops the WAL checkpoint interval
  return { descriptor, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

/** Count prepare() calls on the connection a freshly adopted tab opens. */
function adoptCountingPrepares(headers, rows) {
  const { descriptor, cleanup } = makeTabFile(headers, rows);
  const db = new TimelineDB();
  const adopted = db.adoptTabFromFile("t1", descriptor);
  const realPrepare = adopted.db.prepare.bind(adopted.db);
  const prepared = [];
  adopted.db.prepare = (sql) => { prepared.push(sql); return realPrepare(sql); };
  return { db, meta: adopted, prepared, cleanup };
}

test("adopting a tab prepares no INSERT statements", { skip }, () => {
  const headers = Array.from({ length: 30 }, (_, i) => `Col${i}`);
  const rows = [Array.from({ length: 30 }, (_, i) => `v${i}`)];
  const { db, meta, prepared, cleanup } = adoptCountingPrepares(headers, rows);
  try {
    // A read-only window query — the shape every scroll fetch takes.
    const result = db.queryRows("t1", { offset: 0, limit: 10 });
    assert.equal(result.rows.length, 1);
    assert.equal(result.rows[0].Col0, "v0");

    const writes = prepared.filter((sql) => /^\s*(INSERT|DELETE)/i.test(sql));
    assert.deepEqual(writes, [], `a read-only query compiled write statements: ${writes.join(" | ")}`);
  } finally {
    cleanup();
    db.closeAll();
  }
});

test("adopted write statements still work, and compile only once", { skip }, () => {
  const headers = ["FileName", "Path"];
  const rows = [["a.exe", "C:\\a"], ["b.exe", "C:\\b"]];
  const { db, meta, prepared, cleanup } = adoptCountingPrepares(headers, rows);
  try {
    db.setBookmarks("t1", [1], true);
    db.addTag("t1", 1, "Suspicious");
    db.addTag("t1", 2, "Suspicious");

    assert.equal(db.getBookmarkCount("t1"), 1);
    assert.deepEqual(db.getAllTags("t1"), [{ tag: "Suspicious", cnt: 2 }]);

    // Each lazy statement compiles on first touch and is then a plain value: the second
    // round of writes must not re-prepare anything.
    const afterFirstUse = prepared.length;
    db.addTag("t1", 1, "Second");
    db.setBookmarks("t1", [2], true);
    const reprepared = prepared.slice(afterFirstUse).filter((sql) => /bookmarks|tags/i.test(sql));
    assert.deepEqual(reprepared, [], `statements recompiled on reuse: ${reprepared.join(" | ")}`);
  } finally {
    cleanup();
    db.closeAll();
  }
});

test("a lazy statement slot can still be replaced by a stub", { skip }, () => {
  const { descriptor, cleanup } = makeTabFile(["A"], [["1"]]);
  const db = new TimelineDB();
  try {
    const meta = db.adoptTabFromFile("t1", descriptor);
    const calls = [];
    meta.tagInsertStmt = { run: (rowId, tag) => { calls.push([rowId, tag]); return { changes: 1 }; } };
    db.addTag("t1", 1, "Stubbed");
    assert.deepEqual(calls, [[1, "Stubbed"]]);
  } finally {
    cleanup();
    db.closeAll();
  }
});
