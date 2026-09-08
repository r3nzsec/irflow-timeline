"use strict";

const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { extractMergedAiHistoryRootsToDb } = require("../electron/parsers/ai-history/profile-scan");

const FIXTURE_CLAUDE = path.join(__dirname, "fixtures/ai-history/claude/.claude");
const FIXTURE_CURSOR = path.join(__dirname, "fixtures/ai-history/cursor/.cursor");

function isBetterSqliteAbiError(e) {
  return e?.code === "ERR_DLOPEN_FAILED"
    && /better_sqlite3\.node|NODE_MODULE_VERSION|different Node\.js version/.test(String(e?.message || ""));
}

test("extractMergedAiHistoryRootsToDb writes rows without returning a merged array", async (t) => {
  let TimelineDB;
  try {
    TimelineDB = require("../electron/db");
  } catch (e) {
    if (isBetterSqliteAbiError(e)) {
      t.skip("better-sqlite3 not built for this Node ABI");
      return;
    }
    throw e;
  }

  const dbPath = path.join(os.tmpdir(), `irflow-ai-stream-${process.pid}-${Date.now()}.db`);
  const tabId = "ai-stream-test";
  const db = new TimelineDB();
  db._dbPathHint = dbPath;
  after(() => {
    try { db.closeAll(); } catch { /* ignore */ }
    try { fs.unlinkSync(dbPath); } catch { /* ignore */ }
  });

  const roots = [{
    tool: "claude-code",
    path: FIXTURE_CLAUDE,
    label: "Claude Code",
    endpointUser: "fixture",
    endpointHost: "",
  }];

  let result;
  try {
    result = await extractMergedAiHistoryRootsToDb(
      db,
      tabId,
      roots,
      { user: "fixture", host: "" },
      { includeSubagents: false },
    );
    assert.deepEqual(db.databases.get(tabId).tsColumns, new Set(["Timestamp"]));
  } catch (e) {
    if (isBetterSqliteAbiError(e)) {
      t.skip("better-sqlite3 not built for this Node ABI");
      return;
    }
    throw e;
  }

  assert.ok(result.rowCount >= 3, `expected rows, got ${result.rowCount}`);
  assert.equal(result.rows, undefined);
  db.finalizeImport(tabId);
  const window = db.queryRows(tabId, { offset: 0, limit: 10, sortCol: null, sortDir: "asc" });
  assert.equal(window.totalFiltered, result.rowCount);
  assert.ok(window.rows[0].Timestamp);
});

test("extractMergedAiHistoryRootsToDb streams Cursor and retains FullText for secret scanning", async (t) => {
  let TimelineDB;
  try {
    TimelineDB = require("../electron/db");
  } catch (e) {
    if (isBetterSqliteAbiError(e)) {
      t.skip("better-sqlite3 not built for this Node ABI");
      return;
    }
    throw e;
  }

  const dbPath = path.join(os.tmpdir(), `irflow-cursor-stream-${process.pid}-${Date.now()}.db`);
  const tabId = "ai-cursor-stream";
  const db = new TimelineDB();
  db._dbPathHint = dbPath;
  after(() => {
    try { db.closeAll(); } catch { /* ignore */ }
    try { fs.unlinkSync(dbPath); } catch { /* ignore */ }
  });

  let result;
  try {
    result = await extractMergedAiHistoryRootsToDb(
      db,
      tabId,
      [{
        tool: "cursor",
        path: FIXTURE_CURSOR,
        label: "Cursor",
        endpointUser: "fixture",
        endpointHost: "",
      }],
      { user: "fixture", host: "" },
      { includeSubagents: false },
    );
  } catch (e) {
    if (isBetterSqliteAbiError(e)) {
      t.skip("better-sqlite3 not built for this Node ABI");
      return;
    }
    throw e;
  }

  assert.ok(result.rowCount >= 2);
  db.finalizeImport(tabId);
  const window = db.queryRows(tabId, { offset: 0, limit: 5, sortCol: null, sortDir: "asc" });
  assert.ok(window.rows.length >= 1);
  // FullText is now retained on the merged/streamed path (keepFullText:true) so the AI Secret Scan
  // can see content past the 500-char Summary preview — previously this path slimmed it to "".
  assert.ok(window.rows.some((r) => r.FullText && r.FullText.length > 0), "FullText should be retained for AI tabs");
  assert.ok(window.rows[0].Summary);
});
