// Integration tests for the MFT File Activity Heatmap analyzer
// (electron/analyzers/file-activity.js).
//
// These lock in the Tier-3 performance rewrite (the sort_datetime() UDF was dropped in favour of
// operating on the already-canonical raw MFT timestamp column, and the day-of-week × hour matrix
// now derives dow/hour in JS instead of via strftime-over-UDF) AND the Tier-1 truth-in-labeling
// fix (range timestamps truncated to canonical YYYY-MM-DD HH:MM:SS — no fractional-second leak).
// The keystone test plants an off-hours weekend burst with risky extensions + freed records and
// asserts it ranks #1 with exact enrichment counts — the only way to catch regressions in the
// string-built SQL (BETWEEN bounds, risky-ext IN-placeholders, LOWER() normalization, notDir).
//
// Needs the DuckDB binding; skipped when it is not installed for this runtime.

const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
try { ({ Database } = require("./helpers/duckdb-data-table")); } catch { /* DuckDB binding not installed */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();
const skip = HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime";

const { getFileActivityHeatmap } = require("../electron/analyzers/file-activity");
const { registerRuntimeFunctions } = require("../electron/db/runtime-functions");
const { createTestDataTable } = require("./helpers/duckdb-data-table");

// Full MFT column→safe-column map mirroring how db.js sanitizes headers to c0..cN.
const MFT_COLMAP = {
  Created0x10: "c0", LastModified0x10: "c1", IsDirectory: "c2",
  ParentPath: "c3", Extension: "c4", InUse: "c5",
};
const NCOLS = 6;

// Row order matches MFT_COLMAP: [created, modified, isDir, parentPath, extension, inUse]
function makeMeta(rows, { colMap = MFT_COLMAP, ncols = NCOLS } = {}) {
  const db = new Database(":memory:");
  registerRuntimeFunctions(db); // faithful to prod; the analyzer no longer calls sort_datetime
  const ins = createTestDataTable(db, Array.from({ length: ncols }, (_, i) => `c${i}`).join(", "));
  if (rows.length) {
    const tx = db.transaction((rs) => { for (const r of rs) ins.run(...r); });
    tx(rows);
  }
  return { db, colMap, rowCount: rows.length };
}

// Shared MFT scenario: 200 benign daytime weekday files + a 60-file off-hours weekend burst
// on Sat 2024-01-06 03 (30 risky-ext, 20 freed). Burst ranks #1 in suspiciousWindows.
function mftBurstRows() {
  const rows = [];
  for (const day of ["2024-01-02", "2024-01-03", "2024-01-04", "2024-01-05"])
    for (const h of ["09", "10", "11", "12", "13"])
      for (let s = 0; s < 10; s++) {
        const ts = `${day} ${h}:00:${String(s).padStart(2, "0")}.1234567`;
        rows.push([ts, ts, "False", "C:\\Users\\bob\\Documents", ".txt", "True"]);
      }
  for (let i = 0; i < 60; i++) {
    const ts = `2024-01-06 03:15:${String(i % 60).padStart(2, "0")}.1234567`;
    rows.push([ts, ts, "False", "C:\\Users\\bob\\AppData\\Local\\Temp", i < 30 ? ".exe" : ".tmp", i < 20 ? "False" : "True"]);
  }
  return rows;
}

// USN companion ($J): colMap mirrors the parser's emitted columns. UpdateReasons is a pipe-joined
// PascalCase string (as usnReasonToString produces). SourceInfo='' = user-driven.
const USN_COLMAP = { UpdateTimestamp: "c0", Name: "c1", UpdateReasons: "c2", Extension: "c3", ParentPath: "c4", SourceInfo: "c5", FileAttributes: "c6" };
function makeUsnMeta(rows) {
  const m = makeMeta(rows, { colMap: USN_COLMAP, ncols: 7 });
  m.sourceFormat = "raw-usnjrnl";
  return m;
}

// EVTX companion: resolved by _rwResolveEvtxCols via header regex, so `headers` is required.
const EVTX_HEADERS = ["TimeCreated", "EventID", "Channel", "CommandLine"];
const EVTX_COLMAP = { TimeCreated: "c0", EventID: "c1", Channel: "c2", CommandLine: "c3" };
function makeEvtxMeta(rows) {
  const m = makeMeta(rows, { colMap: EVTX_COLMAP, ncols: 4 });
  m.headers = EVTX_HEADERS;
  return m;
}

// 8-column MFT colMap incl. the precomputed timestomp flags (SI<FN, uSecZeros) for Tier 5 tests.
const MFT8 = { Created0x10: "c0", LastModified0x10: "c1", IsDirectory: "c2", ParentPath: "c3", Extension: "c4", InUse: "c5", "SI<FN": "c6", uSecZeros: "c7" };
// 200 benign daytime weekday files (count 10 per hour bucket — below the score threshold, so they
// are never flagged) that establish a low median so a planted burst stands out.
function benignRows(ncols) {
  const rows = [];
  for (const day of ["2024-01-02", "2024-01-03", "2024-01-04", "2024-01-05"])
    for (const h of ["09", "10", "11", "12", "13"])
      for (let s = 0; s < 10; s++) {
        const ts = `${day} ${h}:00:${String(s).padStart(2, "0")}.1234567`;
        rows.push(ncols === 8
          ? [ts, ts, "False", "C:\\Users\\bob\\Documents", ".txt", "True", "False", "False"]
          : [ts, ts, "False", "C:\\Users\\bob\\Documents", ".txt", "True"]);
      }
  return rows;
}

// ── Keystone: a planted off-hours weekend burst ranks #1 with exact enrichment ──
test("File Activity: planted off-hours weekend burst ranks #1 with correct enrichment", { skip }, () => {
  const rows = [];
  // 200 benign rows: 4 weekdays × 5 daytime hours × 10 files (created == modified)
  const benignDays = ["2024-01-02", "2024-01-03", "2024-01-04", "2024-01-05"]; // Tue–Fri
  const benignHours = ["09", "10", "11", "12", "13"];
  for (const day of benignDays)
    for (const h of benignHours)
      for (let s = 0; s < 10; s++) {
        const ts = `${day} ${h}:00:${String(s).padStart(2, "0")}.1234567`;
        rows.push([ts, ts, "False", "C:\\Users\\bob\\Documents", ".txt", "True"]);
      }
  // 60-file burst on Saturday 2024-01-06 at 03:15 UTC (weekend AND off-hours).
  // 30 risky extensions (incl. UPPER-case ".EXE" to prove LOWER() match), 20 freed (InUse='False').
  const riskyRot = [".exe", ".dll", ".ps1", ".EXE"];
  for (let i = 0; i < 60; i++) {
    const ts = `2024-01-06 03:15:${String(i % 60).padStart(2, "0")}.1234567`;
    const ext = i < 30 ? riskyRot[i % riskyRot.length] : ".tmp";
    const inUse = i < 20 ? "False" : "True";
    rows.push([ts, ts, "False", "C:\\Users\\bob\\AppData\\Local\\Temp", ext, inUse]);
  }
  // 5 directory records in the same hour — must be excluded everywhere (notDir).
  for (let i = 0; i < 5; i++) {
    const ts = `2024-01-06 03:15:${String(i).padStart(2, "0")}.1234567`;
    rows.push([ts, ts, "True", "C:\\Windows", ".exe", "True"]);
  }

  const r = getFileActivityHeatmap(makeMeta(rows));
  assert.equal(r.error, undefined, "should not error");

  // Totals exclude directories.
  assert.equal(r.totalCreated, 260, "200 benign + 60 burst files (5 dirs excluded)");
  assert.equal(r.totalModified, 260);
  assert.equal(r.bucketSize, "hourly", "~4-day span stays hourly");

  // Only the burst is flagged; benign daytime buckets fall below threshold.
  assert.ok(r.suspiciousWindows.length > 0, "burst should be flagged");
  assert.equal(r.suspiciousWindows[0].bucket, "2024-01-06 03", "burst ranks #1");
  assert.ok(r.suspiciousWindows.every((w) => w.bucket === "2024-01-06 03"),
    "no benign daytime bucket should be flagged");

  // The created-mode window carries exact enrichment counts (proves the SQL wiring).
  const cw = r.suspiciousWindows.find((w) => w.bucket === "2024-01-06 03" && w.mode === "created");
  assert.ok(cw, "a created-mode burst window exists");
  assert.equal(cw.count, 60, "60 burst files (dirs excluded)");
  assert.equal(cw.riskyExtensionCount, 30, "30 risky-ext files incl. UPPER-case .EXE via LOWER()");
  assert.equal(cw.deletedCount, 20, "20 freed records (InUse='False')");
  assert.equal(cw.weekend, true);
  assert.equal(cw.offHours, true);
  assert.equal(cw.topDirectories[0].path, "C:\\Users\\bob\\AppData\\Local\\Temp");
  assert.equal(cw.topDirectories[0].count, 60);
  const tmp = cw.topExtensions.find((e) => e.ext === ".tmp");
  assert.ok(tmp && tmp.count === 30, ".tmp extension breakout is correct");

  // Matrix derives dow/hour in JS (Sat = 6, hour 3). Dirs excluded.
  assert.equal(r.createdDowHourMatrix[6][3], 60, "created matrix cell = burst count");
  assert.equal(r.combinedDowHourMatrix[6][3], 120, "combined = created + modified");

  // Tier-1: range truncated to canonical 19-char form, no fractional-second leak.
  assert.equal(r.timeRange.earliest, "2024-01-02 09:00:00");
  assert.equal(r.timeRange.latest, "2024-01-06 03:15:59");
  assert.equal(r.timeRange.earliest.length, 19);
  assert.ok(!r.timeRange.earliest.includes("."), "no fractional seconds in range");
  assert.ok(!r.timeRange.latest.includes("."));

  // Tier 8: a verdict is attached; with no companion tabs it is single-source $SI → 'observed'
  assert.ok(r.verdict, "verdict attached");
  assert.equal(r.verdict.confidence, "observed", "no USN/EVTX companion → observed confidence");
  assert.ok(r.verdict.mitre.some((m) => m.technique === "T1105"), "executable burst → Ingress Tool Transfer");
});

// ── Missing timestamp columns → graceful error ──
test("File Activity: errors when neither $SI timestamp column is present", { skip }, () => {
  const meta = makeMeta([], { colMap: { IsDirectory: "c0" }, ncols: 1 });
  const r = getFileActivityHeatmap(meta);
  assert.match(r.error || "", /No timestamp columns/);
});

// ── Empty data → zeroed result, no error ──
test("File Activity: empty MFT returns zeroed result without error", { skip }, () => {
  const r = getFileActivityHeatmap(makeMeta([]));
  assert.equal(r.error, undefined);
  assert.equal(r.totalCreated, 0);
  assert.equal(r.totalModified, 0);
  assert.equal(r.suspiciousWindows.length, 0);
  assert.equal(r.timeRange.earliest, null);
  assert.equal(r.combinedDowHourMatrix.length, 7);
  assert.equal(r.combinedDowHourMatrix[0].length, 24);
});

// ── 90-day boundary flips hourly → daily bucketing ──
test("File Activity: span > 90 days switches to daily buckets", { skip }, () => {
  const rows = [
    ["2024-01-01 10:00:00.1234567", "2024-01-01 10:00:00.1234567", "False", "C:\\x", ".txt", "True"],
    ["2024-06-01 10:00:00.1234567", "2024-06-01 10:00:00.1234567", "False", "C:\\x", ".txt", "True"],
  ];
  const r = getFileActivityHeatmap(makeMeta(rows));
  assert.equal(r.error, undefined);
  assert.equal(r.bucketSize, "daily", "~152-day span → daily");
  assert.equal(r.createdBuckets[0].bucket.length, 10, "daily bucket is yyyy-MM-dd");
  assert.equal(r.createdBuckets[0].bucket, "2024-01-01");
});

// ── Tier 4: cross-artifact USN + EVTX corroboration enriches the top window + deletion lane ──
test("File Activity: USN + EVTX corroboration enriches the top window and surfaces the deletion lane", { skip }, () => {
  const mftMeta = makeMeta(mftBurstRows());

  // USN: in the burst hour — 12 deletes, 8 content-writes, 5 creates, 3 renames (all user-driven);
  // another user-driven delete hour; an OS/defrag delete hour (SourceInfo set) that must be gated out.
  const u = [];
  const pushUsn = (ts, reasons, src = "") => u.push([ts, "f", reasons, ".x", "", src, "Archive"]);
  for (let i = 0; i < 12; i++) pushUsn(`2024-01-06 03:15:${String(i).padStart(2, "0")}.5000000`, "FileDelete|Close");
  for (let i = 0; i < 8; i++) pushUsn(`2024-01-06 03:16:${String(i).padStart(2, "0")}.5000000`, "DataOverwrite|Close");
  for (let i = 0; i < 5; i++) pushUsn(`2024-01-06 03:17:${String(i).padStart(2, "0")}.5000000`, "FileCreate|Close");
  for (let i = 0; i < 3; i++) pushUsn(`2024-01-06 03:18:${String(i).padStart(2, "0")}.5000000`, "RenameNewName|Close");
  for (let i = 0; i < 6; i++) pushUsn(`2024-01-04 12:30:${String(i).padStart(2, "0")}.5000000`, "FileDelete|Close");
  for (let i = 0; i < 4; i++) pushUsn(`2024-01-02 02:00:${String(i).padStart(2, "0")}.5000000`, "FileDelete|Close", "DataManagement");
  const usnMeta = makeUsnMeta(u);

  // EVTX: 4 Sysmon EID 1 + 2 Security 4688 in the burst window; 1 EID 1 on the Application channel
  // (must be excluded by channel scoping).
  const e = [];
  for (let i = 0; i < 4; i++) e.push([`2024-01-06 03:15:${String(i).padStart(2, "0")}.123456`, "1", "Microsoft-Windows-Sysmon/Operational", "C:\\Temp\\eviltool.exe -enc"]);
  for (let i = 0; i < 2; i++) e.push([`2024-01-06 03:16:${String(i).padStart(2, "0")}.123456`, "4688", "Security", "C:\\Temp\\dropper.exe"]);
  e.push(["2024-01-06 03:17:00.123456", "1", "Application", "benign-app.exe"]);
  const evtxMeta = makeEvtxMeta(e);

  const r = getFileActivityHeatmap(mftMeta, { usnMeta, evtxMeta });
  assert.equal(r.error, undefined);
  assert.equal(r.correlation.usnAvailable, true);
  assert.equal(r.correlation.evtxAvailable, true);

  const cw = r.suspiciousWindows.find((w) => w.bucket === "2024-01-06 03" && w.mode === "created");
  assert.ok(cw && cw.corroboration, "burst window carries corroboration");
  assert.equal(cw.corroboration.usn.fileDelete, 12);
  assert.equal(cw.corroboration.usn.contentWrite, 8, "DataOverwrite OR DataExtend");
  assert.equal(cw.corroboration.usn.fileCreate, 5);
  assert.equal(cw.corroboration.usn.renameNew, 3);
  assert.equal(cw.corroboration.usn.total, 28);
  assert.equal(cw.corroboration.evtx.processCreations, 6, "Application-channel EID 1 excluded by channel scope");
  assert.ok(cw.corroboration.evtx.sampleProcesses.length > 0);
  assert.equal(cw.corroboration.level, "strong", "USN + EVTX both present in window");

  // Deletion lane: only user-driven delete hours; the OS/defrag hour is gated out via SourceInfo.
  const buckets = r.usnDeletionWindows.map((w) => w.bucket).sort();
  assert.deepEqual(buckets, ["2024-01-04 12", "2024-01-06 03"]);
  assert.equal(r.usnDeletionWindows.find((w) => w.bucket === "2024-01-06 03").count, 12);
  assert.ok(!buckets.includes("2024-01-02 02"), "OS/defrag delete hour excluded via SourceInfo gate");

  // Tier 8: a USN/EVTX-corroborated window lifts verdict confidence; USN deletes emit T1070.004
  assert.equal(r.verdict.confidence, "corroborated", "USN+EVTX corroboration → corroborated confidence");
  const del = r.verdict.mitre.find((m) => m.technique === "T1070.004");
  assert.ok(del && del.confidence === "corroborated", "USN FileDelete → corroborated T1070.004");
});

// ── Tier 4: single-companion levels + no-companion back-compat ──
test("File Activity: single-companion corroboration levels and no-companion back-compat", { skip }, () => {
  const mftMeta = makeMeta(mftBurstRows());
  const usnMeta = makeUsnMeta([["2024-01-06 03:15:00.5000000", "f", "FileDelete|Close", ".x", "", "", "Archive"]]);
  const evtxMeta = makeEvtxMeta([["2024-01-06 03:15:00.123456", "1", "Microsoft-Windows-Sysmon/Operational", "x.exe"]]);

  const ru = getFileActivityHeatmap(mftMeta, { usnMeta });
  const cu = ru.suspiciousWindows.find((w) => w.bucket === "2024-01-06 03" && w.mode === "created");
  assert.equal(cu.corroboration.level, "corroborated");
  assert.equal(cu.corroboration.evtx, null);
  assert.equal(ru.correlation.evtxAvailable, false);

  const re = getFileActivityHeatmap(mftMeta, { evtxMeta });
  const ce = re.suspiciousWindows.find((w) => w.bucket === "2024-01-06 03" && w.mode === "created");
  assert.equal(ce.corroboration.level, "corroborated");
  assert.equal(ce.corroboration.usn, null);
  assert.equal(re.usnDeletionWindows.length, 0, "no USN tab → no deletion lane");

  const rn = getFileActivityHeatmap(mftMeta);
  assert.equal(rn.correlation.usnAvailable, false);
  assert.equal(rn.correlation.evtxAvailable, false);
  assert.equal(rn.usnDeletionWindows.length, 0);
  const cn = rn.suspiciousWindows.find((w) => w.bucket === "2024-01-06 03" && w.mode === "created");
  assert.equal(cn.corroboration, undefined, "no corroboration attached without companions");
});

// ── Tier 2: degenerate-data guard — a sparse MFT below the volume floor flags nothing ──
test("File Activity: sparse MFT below the volume floor yields no suspicious windows", { skip }, () => {
  const rows = [];
  for (let b = 0; b < 5; b++) for (let i = 0; i < 5; i++) { const ts = `2024-01-06 0${b}:15:0${i}.1`; rows.push([ts, ts, "False", "C:\\x", ".txt", "True"]); }
  const r = getFileActivityHeatmap(makeMeta(rows));
  assert.equal(r.error, undefined);
  assert.equal(r.suspiciousWindows.length, 0, "busiest bucket (5) below floor → nothing flagged");
});

// ── Tier 2: absolute floor filters tiny buckets; final-second sub-second rows are counted (padHi) ──
test("File Activity: floor filters tiny buckets and final-second sub-second rows are enriched", { skip }, () => {
  const rows = benignRows(6);
  // 30 deleted .exe ALL at the final second of the hour (sub-second precision) — the enrichment
  // BETWEEN upper bound must include them (would be 0 before the padHi fix).
  for (let i = 0; i < 30; i++) rows.push(["2024-01-06 03:59:59.5000000", "2024-01-06 03:59:59.5000000", "False", "C:\\Users\\bob\\AppData\\Local\\Temp", ".exe", "False"]);
  // a 4-file off-hours bucket that must be filtered by the absolute floor
  for (let i = 0; i < 4; i++) { const ts = `2024-01-07 02:30:0${i}.1`; rows.push([ts, ts, "False", "C:\\x", ".exe", "True"]); }
  const r = getFileActivityHeatmap(makeMeta(rows));
  const cw = r.suspiciousWindows.find((w) => w.bucket === "2024-01-06 03" && w.mode === "created");
  assert.ok(cw, "burst flagged");
  assert.equal(cw.count, 30);
  assert.equal(cw.riskyExtensionCount, 30, "final-second sub-second rows included via padHi");
  assert.equal(cw.deletedCount, 30);
  assert.ok(r.suspiciousWindows.every((w) => w.count >= 10), "no sub-floor window flagged");
  assert.ok(!r.suspiciousWindows.some((w) => w.bucket === "2024-01-07 02"), "4-file off-hours bucket filtered");
});

// ── Tier 5: elevated SI<FN density flags the window as possibly timestomped ──
test("File Activity: elevated SI<FN density sets timestompSuspected with SI<FN / uSecZeros counts", { skip }, () => {
  const rows = benignRows(8);
  for (let i = 0; i < 60; i++) {
    const ts = `2024-01-06 03:15:${String(i).padStart(2, "0")}.1`;
    rows.push([ts, ts, "False", "C:\\Users\\bob\\AppData\\Local\\Temp", ".exe", "False", i < 50 ? "True" : "False", i < 40 ? "True" : "False"]);
  }
  const r = getFileActivityHeatmap(makeMeta(rows, { colMap: MFT8, ncols: 8 }));
  const cw = r.suspiciousWindows.find((w) => w.bucket === "2024-01-06 03" && w.mode === "created");
  assert.equal(cw.siFnCount, 50);
  assert.equal(cw.uSecZerosCount, 40);
  assert.equal(cw.timestompSuspected, true);
});

// ── Tier 6: servicing-churn windows are down-weighted below equal user-path bursts ──
test("File Activity: servicing-churn burst ranks below an equal user-path burst", { skip }, () => {
  const rows = benignRows(6);
  for (let i = 0; i < 40; i++) { const ts = `2024-01-06 03:15:${String(i).padStart(2, "0")}.1`; rows.push([ts, ts, "False", "C:\\Windows\\WinSxS\\amd64_x", ".dll", "True"]); } // Sat servicing churn
  for (let i = 0; i < 40; i++) { const ts = `2024-01-07 03:15:${String(i).padStart(2, "0")}.1`; rows.push([ts, ts, "False", "C:\\Users\\bob\\AppData\\Local\\Temp", ".exe", "True"]); } // Sun user burst
  const r = getFileActivityHeatmap(makeMeta(rows));
  const winsxs = r.suspiciousWindows.find((w) => w.bucket === "2024-01-06 03" && w.mode === "created");
  const user = r.suspiciousWindows.find((w) => w.bucket === "2024-01-07 03" && w.mode === "created");
  assert.ok(winsxs && user, "both bursts present");
  assert.equal(winsxs.systemChurnCount, 40);
  assert.equal(user.systemChurnCount, 0);
  assert.ok(user.score > winsxs.score, "user burst outranks servicing churn");
  assert.equal(r.suspiciousWindows[0].bucket, "2024-01-07 03", "user burst ranks #1");
  assert.equal(winsxs.topDirectories[0].class, "servicing-churn");
  assert.equal(user.topDirectories[0].class, "user-profile");
});

// ── Tier 6 hardening (review): churn dampening must NOT bury a timestomped payload masquerading in
// a servicing tree — malice boosts are added AFTER dampening. ──
test("File Activity: a timestomped servicing-tree burst outranks a benign churn burst of equal volume", { skip }, () => {
  const rows = benignRows(8);
  // benign WinSxS update burst (Sat) — no tamper
  for (let i = 0; i < 40; i++) { const ts = `2024-01-06 03:15:${String(i).padStart(2, "0")}.1`; rows.push([ts, ts, "False", "C:\\Windows\\WinSxS\\amd64_a", ".dll", "True", "False", "False"]); }
  // timestomped payload staged in WinSxS (Sun) — SI<FN + zeroed sub-seconds, same volume + extension
  for (let i = 0; i < 40; i++) { const ts = `2024-01-07 03:15:${String(i).padStart(2, "0")}.1`; rows.push([ts, ts, "False", "C:\\Windows\\WinSxS\\amd64_b", ".dll", "True", "True", "True"]); }
  const r = getFileActivityHeatmap(makeMeta(rows, { colMap: MFT8, ncols: 8 }));
  const benign = r.suspiciousWindows.find((w) => w.bucket === "2024-01-06 03" && w.mode === "created");
  const stomped = r.suspiciousWindows.find((w) => w.bucket === "2024-01-07 03" && w.mode === "created");
  assert.ok(benign && stomped, "both churn bursts present");
  assert.equal(benign.systemChurnCount, 40);
  assert.equal(stomped.systemChurnCount, 40, "both dampened by location");
  assert.equal(stomped.timestompSuspected, true);
  assert.equal(benign.timestompSuspected, false);
  assert.ok(stomped.score > benign.score, "timestomp boost survives churn dampening");
  const iS = r.suspiciousWindows.findIndex((w) => w.bucket === "2024-01-07 03" && w.mode === "created");
  const iB = r.suspiciousWindows.findIndex((w) => w.bucket === "2024-01-06 03" && w.mode === "created");
  assert.ok(iS < iB, "timestomped servicing-tree window ranks above the benign churn window");
  // score breakdown reconciles exactly even with churn (< 1) and a SI<FN boost
  const r2 = (n) => Math.round(n * 100) / 100;
  const sb = stomped.scoreBreakdown;
  assert.ok(sb.churnFactor < 1, "servicing tree → churn applied");
  assert.equal(sb.baselineDamped, r2(sb.baseline * sb.churnFactor));
  assert.equal(sb.total, r2(sb.baselineDamped + sb.riskyBoost + sb.deletedBoost + sb.siFnBoost), "reconciles under churn + boosts");
  assert.equal(sb.total, stomped.score, "headline score == breakdown total");
});

// ── Tier 6 hardening (review): C:\Windows\Temp is a carve-out — attacker staging there is NOT dampened. ──
test("File Activity: a burst in C:\\Windows\\Temp is not treated as servicing churn", { skip }, () => {
  const rows = benignRows(6);
  for (let i = 0; i < 40; i++) { const ts = `2024-01-06 03:15:${String(i).padStart(2, "0")}.1`; rows.push([ts, ts, "False", "C:\\Windows\\Temp", ".exe", "True"]); }
  const r = getFileActivityHeatmap(makeMeta(rows));
  const w = r.suspiciousWindows.find((x) => x.bucket === "2024-01-06 03" && x.mode === "created");
  assert.ok(w, "Temp burst flagged");
  assert.equal(w.systemChurnCount, 0, "C:\\Windows\\Temp is not servicing-churn");
  assert.equal(w.topDirectories[0].class, "system", "tagged 'system', never down-weighted");
});

// ── Tier 7: transparent score decomposition + minute-level burst profile ──
test("File Activity: window carries a defensible score breakdown and minute-level burst profile", { skip }, () => {
  const rows = benignRows(6);
  // 60-file burst at Sat 03 — 40 concentrated in the 03:15 minute, 20 in 03:30, to test peakPerMin/activeMinutes
  for (let i = 0; i < 60; i++) {
    const mm = i < 40 ? "15" : "30";
    const ts = `2024-01-06 03:${mm}:${String(i % 60).padStart(2, "0")}.1`;
    rows.push([ts, ts, "False", "C:\\Users\\bob\\AppData\\Local\\Temp", i < 30 ? ".exe" : ".tmp", i < 20 ? "False" : "True"]);
  }
  const r = getFileActivityHeatmap(makeMeta(rows));
  const cw = r.suspiciousWindows.find((w) => w.bucket === "2024-01-06 03" && w.mode === "created");
  assert.ok(cw, "burst flagged");

  const sb = cw.scoreBreakdown;
  assert.ok(sb, "scoreBreakdown attached");
  assert.equal(sb.weekendBonus, 0.6);
  assert.equal(sb.offHoursBonus, 0.4);
  assert.equal(sb.churnFactor, 1, "user path → no churn dampening");
  assert.ok(sb.riskyBoost > 0, "risky boost present");
  assert.equal(sb.total, cw.score, "breakdown total equals the window score");
  assert.equal(sb.admittedBy, "statistical-outlier");
  // The decomposition must reconcile EXACTLY from the rounded operands the UI shows (no double-rounding):
  const r2 = (n) => Math.round(n * 100) / 100;
  assert.equal(sb.baseline, r2(sb.zContribution + sb.weekendBonus + sb.offHoursBonus + sb.volumeBonus), "baseline = z + bonuses (exact)");
  assert.equal(sb.baselineDamped, r2(sb.baseline * sb.churnFactor), "baselineDamped = baseline × churn (exact)");
  assert.equal(sb.total, r2(sb.baselineDamped + sb.riskyBoost + sb.deletedBoost + sb.siFnBoost), "total = baselineDamped + boosts (exact)");
  assert.equal(sb.zContribution, Math.max(0, sb.robustZ), "z contribution is clamped at 0");

  const mp = cw.minuteProfile;
  assert.ok(mp, "minuteProfile attached");
  assert.equal(mp.peakMinute, "2024-01-06 03:15");
  assert.equal(mp.peakPerMin, 40, "peak minute holds 40 files");
  assert.equal(mp.activeMinutes, 2, "two distinct active minutes (03:15, 03:30)");
});
