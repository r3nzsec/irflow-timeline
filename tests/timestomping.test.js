// Tests for the MFT Timestomping detector (electron/analyzers/timestomping.js).
//
// Covers the Tier 0/1/2 rebuild:
//   T0 — full-precision (100ns) parsing: sub-second-only backdating is detected (the strongest
//        modern tell), the Unix-epoch instant is not treated as missing, modified-before-created
//        is surfaced.
//   T1 — FP floor: shared path classifier dampens servicing/cache churn (NOT System32/Temp),
//        Mark-of-the-Web dampens downloads, and user-writable membership is no longer a +2 boost.
//   T2 — coverage: forward/future-dating are fetched + flagged, and identical-$SI clusters
//        (bulk-timestomp tool signature) are detected.
//
// Pure-helper + analyzeFile tests run everywhere; detectTimestomping integration tests need the
// DuckDB binding and skip otherwise.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  detectTimestomping, parseTsParts, cmpParts, analyzeFile, finalizeSeverity, suppressReason, _buildTimestompVerdict,
} = require("../electron/analyzers/timestomping");

const NOW = Date.UTC(2024, 6, 10);

// ───────────────────────── pure helpers (always run) ─────────────────────────
test("parseTsParts captures full 100ns fractional seconds", () => {
  assert.deepEqual(parseTsParts("2024-07-03 10:05:28.2583360"), { ms: Date.UTC(2024, 6, 3, 10, 5, 28), frac: 2583360 });
  assert.deepEqual(parseTsParts("2024-07-03 10:05:28"), { ms: Date.UTC(2024, 6, 3, 10, 5, 28), frac: 0 });
  assert.deepEqual(parseTsParts("2024-07-03T10:05:28.5"), { ms: Date.UTC(2024, 6, 3, 10, 5, 28), frac: 5000000 });
});

test("parseTsParts treats the Unix epoch as a real instant, not missing (T0 epoch fix)", () => {
  const p = parseTsParts("1970-01-01 00:00:00.0000000");
  assert.notEqual(p, null);
  assert.equal(p.ms, 0);
  assert.equal(p.frac, 0);
});

test("parseTsParts returns null only on unparseable input", () => {
  assert.equal(parseTsParts(""), null);
  assert.equal(parseTsParts(null), null);
  assert.equal(parseTsParts("not a date"), null);
});

test("cmpParts orders by sub-second when the second is equal", () => {
  const a = { ms: 1000, frac: 0 }, b = { ms: 1000, frac: 2583360 };
  assert.equal(cmpParts(a, b), -1);
  assert.equal(cmpParts(b, a), 1);
  assert.equal(cmpParts(a, { ms: 1000, frac: 0 }), 0);
});

// ───────────────────────── analyzeFile signal logic (always run) ─────────────────────────
const BASE = "2024-07-03 10:00:00.1234567";
function arow(over = {}) {
  return {
    entryNumber: "1", fileName: "a.exe", extension: ".exe", parentPath: ".\\Users\\bob\\Downloads", zoneId: "",
    siCreated: BASE, fnCreated: BASE, siModified: BASE, fnModified: BASE,
    siRecordChange: BASE, fnRecordChange: BASE, siAccess: BASE, fnAccess: BASE, ...over,
  };
}

test("T0: sub-second-only backdating with zeroed $SI is detected (second-granular logic missed this)", () => {
  const f = analyzeFile(arow({
    siCreated: "2024-07-03 10:05:28.0000000", // zeroed sub-seconds, same second as FN
    fnCreated: "2024-07-03 10:05:28.2583360",
  }), NOW);
  assert.ok(f.stompedFields.includes("Created"), "Created counted as stomped despite same second");
  assert.ok(f.zeroedStompedField, "zeroed sub-second on the stomped field");
  assert.ok(f.indicators.some((i) => /sub-second SI<FN/.test(i)));
  assert.ok(f.indicators.some((i) => /zeroed SI sub-seconds/.test(i)));
  assert.ok(f.score >= 5, "scores via created(+3) + zeroed(+2)");
});

test("T2: forward-dating ($SI later than $FN) is flagged", () => {
  const f = analyzeFile(arow({ siCreated: "2024-07-03 12:00:00.0000000", fnCreated: "2024-07-03 10:00:00.0000000" }), NOW);
  assert.deepEqual(f.forwardFields, ["Created"]);
  assert.ok(f.hasForward);
  assert.ok(f.indicators.some((i) => /forward-dated/.test(i)));
});

test("T2: future-dated $SI is flagged", () => {
  const f = analyzeFile(arow({ siCreated: "2099-01-01 00:00:00.0000000", fnCreated: "2099-01-01 00:00:00.0000000" }), NOW);
  assert.ok(f.futureDated);
  assert.ok(f.indicators.some((i) => /in the future/.test(i)));
});

test("T0: modified-before-created anomaly is surfaced", () => {
  const f = analyzeFile(arow({ siCreated: "2024-07-03 12:00:00.0000000", siModified: "2024-07-03 10:00:00.0000000" }), NOW);
  assert.ok(f.indicators.some((i) => /SI modified precedes SI created/.test(i)));
});

test("T1: servicing-churn path is dampened, not boosted", () => {
  const churn = analyzeFile(arow({ parentPath: ".\\Windows\\WinSxS\\amd64_microsoft-windows", siCreated: "2020-01-01 00:00:00.0000000", fnCreated: BASE }), NOW);
  assert.ok(churn.isChurn);
  assert.ok(churn.indicators.some((i) => /servicing\/cache churn/.test(i)));
  const normal = analyzeFile(arow({ parentPath: ".\\Windows\\System32", siCreated: "2020-01-01 00:00:00.0000000", fnCreated: BASE }), NOW);
  assert.ok(!normal.isChurn, "System32 is NOT churn (adversary drop site)");
  assert.ok(churn.score < normal.score, "churn path scores below an identical System32 file");
});

test("T1: Mark-of-the-Web (downloaded) dampens score", () => {
  const over = { siCreated: "2020-01-01 00:00:00.0000000", fnCreated: BASE };
  const clean = analyzeFile(arow({ ...over, zoneId: "" }), NOW);
  const downloaded = analyzeFile(arow({ ...over, zoneId: "[ZoneTransfer]\nZoneId=3" }), NOW);
  assert.ok(downloaded.hasMotw);
  assert.ok(downloaded.indicators.some((i) => /Mark-of-the-Web/.test(i)));
  assert.equal(downloaded.score, clean.score - 2);
});

test("T1: user-writable membership alone is no longer a +2 boost (inversion fix)", () => {
  // A backdated .txt (non-exec, no zeroing) in Temp gets ONLY the created-mismatch points.
  const f = analyzeFile(arow({
    fileName: "notes.txt", extension: ".txt", parentPath: ".\\Users\\bob\\AppData\\Local\\Temp\\x",
    siCreated: "2024-07-01 10:00:00.1234567", fnCreated: "2024-07-03 10:00:00.1234567",
  }), NOW);
  assert.ok(!f.indicators.some((i) => /user-writable/.test(i)), "no user-writable boost indicator");
  assert.ok(!f.isExec);
  assert.equal(f.score, 3, "created-mismatch(+3) only — no path boost");
});

test("T1: path boost applies to an executable in a system path (gated behind malice)", () => {
  const f = analyzeFile(arow({ extension: ".dll", parentPath: ".\\Windows\\System32", siCreated: "2020-01-01 00:00:00.1234567", fnCreated: BASE }), NOW);
  assert.ok(f.indicators.some((i) => /system path/.test(i)));
});

test("finalizeSeverity: zeroed created stomp on an exec → high/critical", () => {
  const f = finalizeSeverity(analyzeFile(arow({ siCreated: "2020-01-01 00:00:00.0000000", fnCreated: BASE }), NOW));
  assert.ok(["high", "critical"].includes(f.severity));
});

test("suppressReason: access-only mismatch with no other signal is suppressed", () => {
  const f = analyzeFile(arow({ extension: ".txt", siAccess: "2024-07-01 10:00:00.1234567", fnAccess: "2024-07-03 10:00:00.1234567" }), NOW);
  finalizeSeverity(f);
  assert.equal(f.stompedFields.join(), "Accessed");
  assert.ok(suppressReason(f), "suppressed");
});

// ───────────────────────── detectTimestomping integration (DuckDB) ─────────────────────────
// The candidate query uses the sort_datetime() UDF (forward/future-dating), which the DuckDB
// engine registers itself. Pick the backend only if it actually INSTANTIATES (the require can
// succeed while the native binding fails to load).
function pickDb(loader) {
  try { const Impl = loader(); const d = new Impl(":memory:"); if (d.close) d.close(); return Impl; } catch { return null; }
}
const { createTestDataTable } = require("./helpers/duckdb-data-table");
const DBImpl = pickDb(() => require("./helpers/duckdb-data-table").Database);
const HAVE_SQLITE = !!DBImpl;
const skip = HAVE_SQLITE ? false : "DuckDB binding not available for this runtime";
// The candidate query uses sort_datetime() (forward/future-dating); the DuckDB engine registers
// the real UDFs, and registerRuntimeFunctions() checks their names against it.
let registerRuntimeFunctions = () => {};
if (HAVE_SQLITE) { try { ({ registerRuntimeFunctions } = require("../electron/db/runtime-functions")); } catch { /* ignore */ } }

const COLS = ["EntryNumber", "FileName", "Extension", "ParentPath", "InUse", "IsDirectory", "SI<FN", "uSecZeros", "Copied", "ZoneIdContents", "Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30", "LastRecordChange0x10", "LastRecordChange0x30", "LastAccess0x10", "LastAccess0x30"];
const COLMAP = Object.fromEntries(COLS.map((c, i) => [c, `c${i}`]));

function mftFile(over = {}) {
  const b = "2024-07-03 10:00:00.1234567";
  const base = {
    EntryNumber: "100", FileName: "a.txt", Extension: ".txt", ParentPath: ".\\Users\\bob\\Documents",
    InUse: "True", IsDirectory: "False", "SI<FN": "False", uSecZeros: "False", ZoneIdContents: "",
    Created0x10: b, Created0x30: b, LastModified0x10: b, LastModified0x30: b,
    LastRecordChange0x10: b, LastRecordChange0x30: b, LastAccess0x10: b, LastAccess0x30: b,
  };
  return { ...base, ...over };
}
function makeMeta(files) {
  const db = new DBImpl(":memory:");
  registerRuntimeFunctions(db);
  const ins = createTestDataTable(db, COLS.map((_, i) => `c${i}`).join(", "));
  db.exec("BEGIN");
  for (const f of files) ins.run(...COLS.map((c) => (f[c] != null ? String(f[c]) : "")));
  db.exec("COMMIT");
  return { db, colMap: COLMAP, rowCount: files.length };
}

test("integration: missing-column and empty fallbacks", { skip }, () => {
  assert.equal(detectTimestomping(null).totalTimestomped, 0);
  const noFlag = { db: null, colMap: { FileName: "c0", EntryNumber: "c1" } };
  assert.match(detectTimestomping(noFlag).error || "", /Required MFT columns/);
  const meta = makeMeta([mftFile()]); // no candidates
  assert.equal(detectTimestomping(meta).rawSiFnCount, 0);
});

test("integration: a backdated executable is detected and ranked", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "evil.exe", Extension: ".exe", ParentPath: ".\\Windows\\System32",
      "SI<FN": "True", uSecZeros: "True",
      Created0x10: "2019-01-01 00:00:00.0000000", Created0x30: "2024-07-03 10:00:00.2583360" }),
  ]);
  const r = detectTimestomping(meta);
  assert.equal(r.totalTimestomped, 1);
  assert.equal(r.files[0].fileName, "evil.exe");
  assert.ok(["high", "critical"].includes(r.files[0].severity));
  assert.ok(Array.isArray(r.clusters));
});

test("integration: identical-$SI cluster (bulk-timestomp) is detected and boosts members", { skip }, () => {
  const files = [];
  for (let i = 0; i < 6; i++) {
    files.push(mftFile({ EntryNumber: String(200 + i), FileName: `m${i}.exe`, Extension: ".exe", ParentPath: ".\\ProgramData\\x",
      "SI<FN": "True", uSecZeros: "True",
      Created0x10: "2020-01-01 00:00:00.0000000", Created0x30: "2024-07-03 10:00:00.2583360" }));
  }
  const r = detectTimestomping(makeMeta(files));
  assert.equal(r.clusterCount, 1);
  assert.equal(r.clusters[0].count, 6);
  assert.ok(r.files.every((f) => f.indicators.some((i) => /identical-\$SI cluster/.test(i))));
  assert.ok(r.files.every((f) => ["high", "critical"].includes(f.severity)));
});

test("integration: forward-dated file is fetched by the broadened query (SI<FN='False')", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "fwd.exe", Extension: ".exe", "SI<FN": "False",
      Created0x10: "2024-07-03 12:00:00.0000000", Created0x30: "2024-07-03 10:00:00.0000000" }),
  ]);
  const r = detectTimestomping(meta);
  assert.equal(r.forwardCount, 1);
  assert.ok(r.files.some((f) => f.fileName === "fwd.exe" && f.hasForward));
});

test("integration C1: a benign batch sharing a zeroed $SI but with NO mismatch is NOT flagged", { skip }, () => {
  // 6 normal executables, $SI == $FN exactly (no stomp), sharing one zeroed Created — a classic
  // installer/extraction pattern. Must not be fetched, clustered, or escalated.
  const files = [];
  for (let i = 0; i < 6; i++) {
    const t = "2024-07-03 10:00:00.0000000";
    files.push(mftFile({ EntryNumber: String(300 + i), FileName: `inst${i}.exe`, Extension: ".exe", ParentPath: ".\\Program Files\\App",
      "SI<FN": "False", uSecZeros: "True", Created0x10: t, Created0x30: t, LastModified0x10: t, LastModified0x30: t }));
  }
  const r = detectTimestomping(makeMeta(files));
  assert.equal(r.totalTimestomped, 0, "no mismatch → not flagged");
  assert.equal(r.clusterCount, 0, "no timestomp cluster from no-mismatch files");
  assert.equal(r.criticalCount, 0);
});

test("integration H1: forward-dating on RecordChange only (all four field pairs covered)", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "rc.exe", Extension: ".exe", "SI<FN": "False",
      LastRecordChange0x10: "2024-07-03 12:00:00.0000000", LastRecordChange0x30: "2024-07-03 10:00:00.0000000" }),
  ]);
  const r = detectTimestomping(meta);
  assert.ok(r.files.some((f) => f.fileName === "rc.exe" && f.forwardFields.includes("RecordChange")));
});

test("integration M2: a realistic backdated copy (Copied='True', Modified-only, non-exec) is dampened to suppression", { skip }, () => {
  // A real file copy: $SI Created == copy time (= $FN), $SI Modified preserved (old < $FN). Copied='True'.
  const r = detectTimestomping(makeMeta([
    mftFile({ FileName: "report.docx", Extension: ".docx", ParentPath: ".\\Users\\bob\\Documents",
      "SI<FN": "True", Copied: "True",
      Created0x10: "2024-07-03 10:00:00.7654321", Created0x30: "2024-07-03 10:00:00.7654321",
      LastModified0x10: "2024-06-01 09:30:15.1234567", LastModified0x30: "2024-07-03 10:00:00.7654321" }),
  ]));
  const f = r.files.find((x) => x.fileName === "report.docx");
  // Dampened: either suppressed, or kept only at LOW with the copy indicator (never medium+).
  if (f) {
    assert.equal(f.severity, "low", "backdated copy dampened to low (not medium+)");
    assert.ok(f.indicators.some((i) => /copy-like/.test(i)));
  } else {
    assert.ok(r.suppressedCount >= 1);
  }
});

test("integration: result shape preserves the modal contract", { skip }, () => {
  const r = detectTimestomping(makeMeta([
    mftFile({ FileName: "x.exe", Extension: ".exe", "SI<FN": "True",
      Created0x10: "2019-01-01 00:00:00.0000000", Created0x30: "2024-07-03 10:00:00.2583360" }),
  ]));
  for (const k of ["totalTimestomped", "files", "topDirectories", "extensionBreakdown", "criticalCount", "highCount", "mediumCount", "lowCount", "clusters", "notes"]) {
    assert.ok(k in r, `result has ${k}`);
  }
  const f = r.files[0];
  for (const k of ["severity", "maxDeltaHours", "parentPath", "fileName", "siCreated", "fnCreated", "extension", "stompedFields", "indicators", "entryNumber", "confidence"]) {
    assert.ok(k in f, `file has ${k}`);
  }
});

// ───────────────────────── Tier 1: FP-suppression + correctness regression guards ─────────────────────────

test("T1-G1: program-files install-backdating (no aligned signal) is suppressed, not flagged HIGH", { skip }, () => {
  // SI build-time < FN install-time, created+modified only, NON-zeroed sub-seconds, Copied=False, exec.
  const meta = makeMeta([
    mftFile({ FileName: "vendor.dll", Extension: ".dll", ParentPath: "C:\\Program Files\\App", "SI<FN": "True",
      Created0x10: "2020-01-01 08:00:00.1234567", Created0x30: "2024-07-03 10:00:00.7654321",
      LastModified0x10: "2020-01-01 08:00:00.1234567", LastModified0x30: "2024-07-03 10:00:00.7654321" }),
  ]);
  const r = detectTimestomping(meta);
  assert.equal(r.totalTimestomped, 0, "install-backdating is suppressed");
  assert.equal(r.suppressedCount, 1, "and counted as suppressed (honest)");
});

test("T1-G1: a zeroed-$SI stomp in Program Files is NOT treated as benign install-backdating", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "evil.dll", Extension: ".dll", ParentPath: "C:\\Program Files\\App", "SI<FN": "True", uSecZeros: "True",
      Created0x10: "2009-07-14 01:14:33.0000000", Created0x30: "2024-07-03 10:00:00.2583360" }),
  ]);
  const r = detectTimestomping(meta);
  assert.equal(r.totalTimestomped, 1, "zeroed sub-seconds defeat the install-backdating dampener");
  assert.ok(["high", "critical"].includes(r.files[0].severity));
});

test("T1-G1: future-dating within the 1-day skew tolerance is NOT flagged future / NOT high/critical", { skip }, () => {
  const soon = new Date(Date.now() + 30 * 60 * 1000).toISOString().slice(0, 19).replace("T", " ") + ".1234567";
  const meta = makeMeta([
    mftFile({ FileName: "soon.exe", Extension: ".exe", ParentPath: "C:\\tools", "SI<FN": "False",
      Created0x10: soon, Created0x30: soon, LastModified0x10: soon, LastModified0x30: soon }),
  ]);
  const r = detectTimestomping(meta);
  assert.equal(r.futureCount, 0, "30-min-ahead is treated as clock skew, not future-dating");
  assert.ok(r.files.every((f) => f.severity !== "critical" && f.severity !== "high"));
});

test("T1-G1: far-future + forward-dated $SI on an exec is critical", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "future.exe", Extension: ".exe", ParentPath: "C:\\tools", "SI<FN": "False",
      Created0x10: "2099-01-01 00:00:00.0000000", Created0x30: "2024-07-03 10:00:00.1234567",
      LastModified0x10: "2099-01-01 00:00:00.0000000", LastModified0x30: "2024-07-03 10:00:00.1234567" }),
  ]);
  const r = detectTimestomping(meta);
  assert.equal(r.futureCount, 1);
  assert.equal(r.files[0].severity, "critical");
});

test("T1-G1: a Program-Files install BATCH sharing one non-zeroed $SI forms NO cluster and is fully suppressed (A2)", { skip }, () => {
  const files = [];
  for (let i = 0; i < 6; i++) files.push(mftFile({ EntryNumber: String(500 + i), FileName: `lib${i}.dll`, Extension: ".dll", ParentPath: "C:\\Program Files\\Suite", "SI<FN": "True",
    Created0x10: "2021-03-01 09:00:00.5550000", Created0x30: "2024-07-03 10:00:00.1234567",
    LastModified0x10: "2021-03-01 09:00:00.5550000", LastModified0x30: "2024-07-03 10:00:00.1234567" }));
  const r = detectTimestomping(makeMeta(files));
  assert.equal(r.clusterCount, 0, "a benign install batch (no zeroed/forward/future) is not a timestomp cluster");
  assert.equal(r.criticalCount, 0, "and no member self-escalates to critical");
  assert.equal(r.totalTimestomped, 0);
});

test("T1-A4: a Mark-of-the-Web downloaded installer (backdated, non-zeroed, exec) is NOT high/critical", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "setup.exe", Extension: ".exe", ParentPath: "C:\\Users\\v\\Downloads", "SI<FN": "True",
      ZoneIdContents: "[ZoneTransfer]\r\nZoneId=3",
      Created0x10: "2022-02-02 02:02:02.1110000", Created0x30: "2024-07-03 10:00:00.1234567",
      LastModified0x10: "2022-02-02 02:02:02.1110000", LastModified0x30: "2024-07-03 10:00:00.1234567" }),
  ]);
  const r = detectTimestomping(meta);
  assert.equal(r.files.length, 1, "MotW download is KEPT (not suppressed) so the assertion can't pass-by-skip");
  assert.ok(["medium", "low"].includes(r.files[0].severity), `MotW download (no aligned signal) caps at medium/low (got ${r.files[0].severity})`);
});

test("T1-#1: a downloaded-then-timestomped payload (MotW + zeroed/forward) is NOT buried by MotW", { skip }, () => {
  // MotW must dampen PLAIN backdating, but never an aligned signal (zeroed sub-seconds / forward).
  const zeroedMotw = detectTimestomping(makeMeta([
    mftFile({ FileName: "mimikatz.exe", Extension: ".exe", ParentPath: "C:\\Users\\v\\Downloads", "SI<FN": "True", uSecZeros: "True",
      ZoneIdContents: "[ZoneTransfer]\r\nZoneId=3",
      Created0x10: "2009-07-14 01:14:33.0000000", Created0x30: "2024-07-03 10:00:00.2583360" }),
  ]));
  assert.equal(zeroedMotw.files.length, 1);
  assert.equal(zeroedMotw.files[0].severity, "critical", "MotW + zeroed-$SI exec stays critical");
  const fwdMotw = detectTimestomping(makeMeta([
    mftFile({ FileName: "beacon.exe", Extension: ".exe", ParentPath: "C:\\Users\\v\\Downloads", "SI<FN": "False",
      ZoneIdContents: "[ZoneTransfer]\r\nZoneId=3",
      Created0x10: "2030-01-01 00:00:00.1234567", Created0x30: "2024-07-03 10:00:00.1234567",
      LastModified0x10: "2030-01-01 00:00:00.1234567", LastModified0x30: "2024-07-03 10:00:00.1234567" }),
  ]));
  assert.equal(fwdMotw.files.length, 1);
  assert.ok(["high", "critical"].includes(fwdMotw.files[0].severity), `MotW + forward-dated exec stays high/critical (got ${fwdMotw.files[0].severity})`);
});

test("T1-E1: every kept file carries a physical rowId (safe tagging key)", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "evil.exe", Extension: ".exe", ParentPath: "C:\\Windows\\System32", "SI<FN": "True", uSecZeros: "True",
      Created0x10: "2009-07-14 01:14:33.0000000", Created0x30: "2024-07-03 10:00:00.2583360" }),
  ]);
  const r = detectTimestomping(meta);
  assert.ok(r.files.length > 0 && r.files.every((f) => Number.isInteger(f.rowId)), "rowId present and integer");
});

// G2 — finalizeSeverity boundary table (pure; runs everywhere)
test("T1-G2: severity gates — long delta alone no longer escalates; aligned signals do", () => {
  const base = { stompedFields: ["Created"], forwardFields: [], isChurn: false, hasMotw: false, isExec: false,
    zeroedStompedField: false, createdMismatch: true, clusterMember: false, futureDated: false, hasForward: false, benignBackdateCandidate: false };
  // a 4-year-backdated .txt, single field, non-zeroed → NOT high (maxDeltaHours no longer escalates)
  let f = finalizeSeverity({ ...base, score: 4, maxDeltaHours: 24 * 365 * 4 });
  assert.notEqual(f.severity, "high"); assert.notEqual(f.severity, "critical");
  // zeroed created mismatch on an exec → high/critical
  f = finalizeSeverity({ ...base, isExec: true, zeroedStompedField: true, score: 7, maxDeltaHours: 100 });
  assert.ok(["high", "critical"].includes(f.severity));
  // MotW WITHOUT an aligned signal blocks the medium gate too (A4) → low confidence
  f = finalizeSeverity({ ...base, hasMotw: true, stompedFields: ["Created", "Modified"], score: 5, maxDeltaHours: 1000 });
  assert.equal(f.confidence, "low", "MotW blocks the medium gate when there is no aligned signal (A4)");
  // ...but MotW with a zeroed-stomped field (aligned) does NOT block the gates (#1 fix)
  f = finalizeSeverity({ ...base, hasMotw: true, isExec: true, zeroedStompedField: true, stompedFields: ["Created"], score: 5, maxDeltaHours: 1000 });
  assert.ok(["high", "critical"].includes(f.severity), "MotW + aligned signal is not buried");
});

// G3 — suppression carve-outs (pure)
test("T1-G3: suppression keeps exec/zeroed/cluster/forward carve-outs; drops the benign lanes", () => {
  const mk = (o) => ({ score: 5, onlyAccessMismatch: false, isExec: false, zeroedStompedField: false, clusterMember: false, hasForward: false, isChurn: false, confidence: "low", benignBackdateCandidate: false, ...o });
  assert.equal(suppressReason(mk({ score: 0 })), "score<=0");
  assert.equal(suppressReason(mk({ benignBackdateCandidate: true })), "program-files-backdate");
  assert.equal(suppressReason(mk({ benignBackdateCandidate: true, clusterMember: true })), null, "a cluster member is never benign-backdate-suppressed");
  assert.equal(suppressReason(mk({ onlyAccessMismatch: true })), "access-only");
  assert.equal(suppressReason(mk({ onlyAccessMismatch: true, isExec: true })), null, "access-only carve-out: exec kept");
  assert.equal(suppressReason(mk({ isChurn: true })), "servicing-churn");
  assert.equal(suppressReason(mk({ isChurn: true, zeroedStompedField: true })), null, "churn carve-out: zeroed kept");
});

// ───────────────────────── Tier 2: cross-artifact corroboration (EVTX EID 2 + USN) ─────────────────────────
const EVTX_COLS = ["EventID", "TimeCreated", "Channel", "TargetFilename", "PreviousCreationUtcTime", "CreationUtcTime", "Image", "PayloadData1"];
function makeEvtxMeta(rows) {
  const db = new DBImpl(":memory:"); registerRuntimeFunctions(db);
  const ins = createTestDataTable(db, EVTX_COLS.map((_, i) => `c${i}`).join(", "));
  for (const r of rows) ins.run(...EVTX_COLS.map((c) => (r[c] != null ? String(r[c]) : "")));
  return { db, headers: EVTX_COLS, colMap: Object.fromEntries(EVTX_COLS.map((c, i) => [c, `c${i}`])) };
}
const USN_COLS = ["Name", "UpdateTimestamp", "UpdateReasons", "EntryNumber"];
function makeUsnMeta(rows) {
  const db = new DBImpl(":memory:"); registerRuntimeFunctions(db);
  const ins = createTestDataTable(db, USN_COLS.map((_, i) => `c${i}`).join(", "));
  for (const r of rows) ins.run(...USN_COLS.map((c) => (r[c] != null ? String(r[c]) : "")));
  return { db, headers: USN_COLS, colMap: Object.fromEntries(USN_COLS.map((c, i) => [c, `c${i}`])) };
}
const SYSMON = "Microsoft-Windows-Sysmon/Operational";

test("T2-B1: Sysmon EID 2 confirms a candidate — recovers pre-stomp time + tool, elevates to critical, channel-scoped", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "evil.exe", Extension: ".exe", ParentPath: "C:\\Windows\\System32", "SI<FN": "True",
      Created0x10: "2019-01-01 00:00:00.1234567", Created0x30: "2024-06-01 12:00:00.7654321",
      LastModified0x10: "2019-01-01 00:00:00.1234567", LastModified0x30: "2024-06-01 12:00:00.7654321" }),
  ]);
  const evtxMeta = makeEvtxMeta([
    { EventID: "2", TimeCreated: "2024-06-02 09:00:00", Channel: SYSMON, TargetFilename: "C:\\Windows\\System32\\evil.exe", PreviousCreationUtcTime: "2024-06-01 12:00:00.000", CreationUtcTime: "2019-01-01 00:00:00.000", Image: "C:\\Temp\\timestomp.exe" },
    { EventID: "2", TimeCreated: "2024-06-02 09:10:00", Channel: "Application", TargetFilename: "C:\\x\\noise.exe", PreviousCreationUtcTime: "2024-01-01" }, // non-Sysmon → excluded
  ]);
  const r = detectTimestomping(meta, { evtxMeta });
  assert.equal(r.correlation.evtxAvailable, true);
  assert.equal(r.correlation.evtxFileCreateTimeTotal, 1, "channel-scoped EID 2 landscape excludes non-Sysmon");
  const f = r.files.find((x) => x.fileName === "evil.exe");
  assert.ok(f && f.eid2Corroborated === true);
  assert.equal(f.severity, "critical", "EID 2 confirmation elevates to critical");
  assert.equal(f.preStompCreated, "2024-06-01 12:00:00.000");
  assert.match(f.stompTool || "", /timestomp\.exe/);
  assert.equal(r.correlation.candidatesEid2Corroborated, 1);
});

test("T2-B1: EID 2 with no $MFT mismatch is surfaced separately (full-copy / double-stomp); blob-format parsed", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "blob.exe", Extension: ".exe", ParentPath: "C:\\tools", "SI<FN": "True",
      Created0x10: "2020-02-02 00:00:00.1234567", Created0x30: "2024-06-01 12:00:00.7654321",
      LastModified0x10: "2020-02-02 00:00:00.1234567", LastModified0x30: "2024-06-01 12:00:00.7654321" }),
  ]);
  const evtxMeta = makeEvtxMeta([
    { EventID: "2", TimeCreated: "2024-06-02 09:05:00", Channel: SYSMON, TargetFilename: "C:\\Users\\v\\ghost.exe", PreviousCreationUtcTime: "2024-05-05 05:05:05.000", CreationUtcTime: "2001-01-01 00:00:00.000", Image: "C:\\Temp\\setmace.exe" }, // no MFT candidate; backdate (new < prev)
    { EventID: "2", TimeCreated: "2024-06-02 09:15:00", Channel: SYSMON, PayloadData1: "TargetFilename: C:\\tools\\blob.exe, PreviousCreationUtcTime: 2018-01-01 00:00:00.000, Image: C:\\tool.exe" }, // blob-format → grab()
  ]);
  const r = detectTimestomping(meta, { evtxMeta });
  // blob.exe corroborated via PayloadData blob parsing
  const blob = r.files.find((x) => x.fileName === "blob.exe");
  assert.ok(blob && blob.eid2Corroborated && blob.preStompCreated === "2018-01-01 00:00:00.000", "blob-format EID 2 parsed via grab()");
  assert.match(blob.stompTool || "", /tool\.exe/);
  // ghost.exe has no MFT candidate → confirmed-no-match list
  assert.equal(r.confirmedStompsNoMftMatch.length, 1);
  assert.match(r.confirmedStompsNoMftMatch[0].targetFilename, /ghost\.exe/);
  assert.match(r.confirmedStompsNoMftMatch[0].image || "", /setmace/);
});

test("T2-B2: a USN FileCreate that postdates the backdated $SI Created beats the servicing-churn floor", { skip }, () => {
  // A backdated .txt in WinSxS would normally be SUPPRESSED as servicing-churn (Tier 1).
  const meta = makeMeta([
    mftFile({ FileName: "churnNotes.txt", Extension: ".txt", ParentPath: "C:\\Windows\\WinSxS\\amd64_x", "SI<FN": "True",
      Created0x10: "2019-01-01 00:00:00.1234567", Created0x30: "2024-06-01 12:00:00.7654321",
      LastModified0x10: "2019-01-01 00:00:00.1234567", LastModified0x30: "2024-06-01 12:00:00.7654321" }),
  ]);
  // Without USN: suppressed (churn)
  assert.equal(detectTimestomping(meta).totalTimestomped, 0, "churn-path backdate is suppressed without corroboration");
  // With a contradicting USN FileCreate: kept + promoted, not suppressed
  const usnMeta = makeUsnMeta([{ Name: "churnNotes.txt", UpdateTimestamp: "2024-06-01 11:59:00.000", UpdateReasons: "FileCreate|Close", EntryNumber: "100" }]);
  const r = detectTimestomping(meta, { usnMeta });
  assert.equal(r.correlation.usnAvailable, true);
  assert.equal(r.correlation.candidatesUsnContradicted, 1);
  const f = r.files.find((x) => x.fileName === "churnNotes.txt");
  assert.ok(f && f.usnContradicted === true, "USN contradiction kept despite churn path");
  assert.ok(["high", "critical"].includes(f.severity), `USN contradiction promotes severity (got ${f && f.severity})`);
});

test("T2: no-companion run leaves correlation empty and never crashes (backward-compat)", { skip }, () => {
  const r = detectTimestomping(makeMeta([
    mftFile({ FileName: "evil.exe", Extension: ".exe", ParentPath: "C:\\Windows\\System32", "SI<FN": "True", uSecZeros: "True",
      Created0x10: "2009-07-14 01:14:33.0000000", Created0x30: "2024-07-03 10:00:00.2583360" }),
  ]), {});
  assert.equal(r.correlation.evtxAvailable, false);
  assert.equal(r.correlation.usnAvailable, false);
  assert.equal(r.confirmedStompsNoMftMatch.length, 0);
  assert.equal(r.files[0].severity, "critical", "the $SI-only zeroed stomp still scores critical without companions");
});

// ───────────────────────── Tier 2 review fixes (FP guards + dead-code fix) ─────────────────────────

test("T2-fix#3: EID-2 stomps with NO $MFT mismatch surface even when rawSiFnCount===0 (was dead code)", { skip }, () => {
  const meta = makeMeta([mftFile()]); // no SI<FN candidates → rawSiFnCount 0
  const evtxMeta = makeEvtxMeta([
    { EventID: "2", TimeCreated: "2024-06-02 09:00:00", Channel: SYSMON, TargetFilename: "C:\\Windows\\Temp\\dropper.exe", PreviousCreationUtcTime: "2024-06-01 00:00:00.000", CreationUtcTime: "2009-07-14 01:14:33.000", Image: "C:\\Temp\\timestomp.exe" },
  ]);
  const r = detectTimestomping(meta, { evtxMeta });
  assert.equal(r.totalTimestomped, 0, "no $MFT candidates");
  assert.equal(r.correlation.evtxAvailable, true, "EVTX pass still ran despite rawSiFnCount 0");
  assert.equal(r.confirmedStompsNoMftMatch.length, 1, "the backdating EID-2 with no $MFT match is surfaced");
  assert.match(r.confirmedStompsNoMftMatch[0].targetFilename, /dropper\.exe/);
});

test("T2-fix#3b: a benign forward FileCreateTime change (new > prev) with no $MFT match is NOT listed", { skip }, () => {
  const evtxMeta = makeEvtxMeta([
    { EventID: "2", TimeCreated: "2024-06-02 09:00:00", Channel: SYSMON, TargetFilename: "C:\\app\\plugin.dat", PreviousCreationUtcTime: "2020-01-01 00:00:00.000", CreationUtcTime: "2024-06-01 00:00:00.000", Image: "C:\\app\\updater.exe" }, // forward, not a backdate
  ]);
  const r = detectTimestomping(makeMeta([mftFile()]), { evtxMeta });
  assert.equal(r.confirmedStompsNoMftMatch.length, 0, "forward create-time change is not a stomp");
});

test("T2-fix#1: a Program-Files install-backdate matched by EID 2 is NOT auto-confirmed to critical", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "vendor.dll", Extension: ".dll", ParentPath: "C:\\Program Files\\App", "SI<FN": "True",
      Created0x10: "2020-01-01 08:00:00.1234567", Created0x30: "2024-06-01 12:00:00.7654321",
      LastModified0x10: "2020-01-01 08:00:00.1234567", LastModified0x30: "2024-06-01 12:00:00.7654321" }),
  ]);
  const evtxMeta = makeEvtxMeta([
    { EventID: "2", TimeCreated: "2024-06-01 12:00:01", Channel: SYSMON, TargetFilename: "C:\\Program Files\\App\\vendor.dll", PreviousCreationUtcTime: "2024-06-01 12:00:00.000", CreationUtcTime: "2020-01-01 08:00:00.000", Image: "C:\\Program Files\\App\\setup.exe" },
  ]);
  const r = detectTimestomping(meta, { evtxMeta });
  assert.equal(r.correlation.candidatesEid2Corroborated, 0, "install-backdate not auto-confirmed by an installer SetFileTime");
  assert.equal(r.totalTimestomped, 0, "remains suppressed as program-files install-backdate");
});

test("T2-fix#4: EID 2 for a same-named file in a DIFFERENT directory does not cross-confirm", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "evil.exe", Extension: ".exe", ParentPath: "C:\\Users\\v\\Downloads", "SI<FN": "True",
      Created0x10: "2019-01-01 00:00:00.1234567", Created0x30: "2024-06-01 12:00:00.7654321" }),
  ]);
  const evtxMeta = makeEvtxMeta([
    { EventID: "2", TimeCreated: "2024-06-02 09:00:00", Channel: SYSMON, TargetFilename: "C:\\Windows\\System32\\evil.exe", PreviousCreationUtcTime: "2024-06-01 12:00:00.000", CreationUtcTime: "2019-01-01 00:00:00.000", Image: "C:\\Temp\\timestomp.exe" },
  ]);
  const r = detectTimestomping(meta, { evtxMeta });
  const f = r.files.find((x) => x.fileName === "evil.exe");
  assert.ok(!f || !f.eid2Corroborated, "Downloads\\evil.exe is NOT confirmed by a System32\\evil.exe EID 2");
  assert.equal(r.confirmedStompsNoMftMatch.length, 1, "the System32 EID 2 is surfaced as its own (no-match) confirmed stomp");
});

test("T2-fix#2: USN FileCreate on a same-named DIFFERENT entry does not falsely contradict (entry+name match)", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "config.dll", Extension: ".dll", EntryNumber: "500", ParentPath: "C:\\Windows\\WinSxS\\x", "SI<FN": "True",
      Created0x10: "2019-01-01 00:00:00.1234567", Created0x30: "2024-06-01 12:00:00.7654321",
      LastModified0x10: "2019-01-01 00:00:00.1234567", LastModified0x30: "2024-06-01 12:00:00.7654321" }),
  ]);
  const usnMeta = makeUsnMeta([{ Name: "config.dll", UpdateTimestamp: "2024-06-01 00:00:00.000", UpdateReasons: "FileCreate|Close", EntryNumber: "999" }]); // different entry
  const r = detectTimestomping(meta, { usnMeta });
  assert.equal(r.correlation.candidatesUsnContradicted, 0, "a different-entry same-named FileCreate must not contradict");
  // entry+name match DOES fire when the entry agrees
  const usnMatch = makeUsnMeta([{ Name: "config.dll", UpdateTimestamp: "2024-06-01 00:00:00.000", UpdateReasons: "FileCreate|Close", EntryNumber: "500" }]);
  assert.equal(detectTimestomping(meta, { usnMeta: usnMatch }).correlation.candidatesUsnContradicted, 1, "matching entry+name DOES contradict");
});

// ───────────────────────── Tier 3: broadened false-negative lanes ─────────────────────────

test("T3-C1: a forward-dated NON-exec web-shell (.aspx) is now fetched (was exec-only)", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "shell.aspx", Extension: ".aspx", ParentPath: "C:\\inetpub\\wwwroot", "SI<FN": "False",
      Created0x10: "2024-08-01 10:00:00.0000000", Created0x30: "2024-07-03 10:00:00.0000000",
      LastModified0x10: "2024-08-01 10:00:00.0000000", LastModified0x30: "2024-07-03 10:00:00.0000000" }), // SI > FN (forward)
  ]);
  const r = detectTimestomping(meta);
  const f = r.files.find((x) => x.fileName === "shell.aspx");
  assert.ok(f, "forward-dated web-shell is a candidate (extension decoupled from exec gate)");
  assert.ok(f.hasForward);
});

test("T3-C5: a future-dated $SI on MODIFIED (not Created) is fetched (all-4-field gate)", { skip }, () => {
  const meta = makeMeta([
    mftFile({ FileName: "macro.docm", Extension: ".docm", ParentPath: "C:\\Users\\v\\Documents", "SI<FN": "False",
      Created0x10: "2024-07-03 10:00:00.0000000", Created0x30: "2024-07-03 10:00:00.0000000",
      LastModified0x10: "2099-01-01 00:00:00.0000000", LastModified0x30: "2024-07-03 10:00:00.0000000" }), // future Modified
  ]);
  const r = detectTimestomping(meta);
  const f = r.files.find((x) => x.fileName === "macro.docm");
  assert.ok(f && f.futureDated, "future-dated Modified is fetched + flagged");
});

// ───────────────────────── Tier 4: _buildTimestompVerdict (pure — runs everywhere) ─────────────────────────
const _vc = (o = {}) => ({ evtxAvailable: false, usnAvailable: false, evtxFileCreateTimeTotal: 0, usnFileCreateTotal: 0, candidatesEid2Corroborated: 0, candidatesUsnContradicted: 0, ...o });

test("T4 verdict: EID-2/USN corroboration → confidence corroborated + T1070.006 corroborated", () => {
  const v = _buildTimestompVerdict({ totalTimestomped: 3, criticalCount: 1, correlation: _vc({ evtxAvailable: true, candidatesEid2Corroborated: 1 }), confirmedStompsNoMftMatch: [] });
  assert.equal(v.confidence, "corroborated");
  assert.equal(v.severity, "critical");
  assert.equal(v.mitre[0].technique, "T1070.006");
  assert.equal(v.mitre[0].confidence, "corroborated");
});

test("T4 verdict: confidence gating — observed (no companion), weak (loaded, no match)", () => {
  assert.equal(_buildTimestompVerdict({ totalTimestomped: 4, highCount: 1, correlation: _vc(), confirmedStompsNoMftMatch: [] }).confidence, "observed");
  assert.equal(_buildTimestompVerdict({ totalTimestomped: 2, mediumCount: 2, correlation: _vc({ evtxAvailable: true, usnAvailable: true }), confirmedStompsNoMftMatch: [] }).confidence, "weak");
});

test("T4 verdict: EID-2-only (no $MFT mismatch) is critical/corroborated and the headline says so", () => {
  const v = _buildTimestompVerdict({ totalTimestomped: 0, correlation: _vc({ evtxAvailable: true }), confirmedStompsNoMftMatch: [{}, {}] });
  assert.equal(v.severity, "critical");
  assert.equal(v.confidence, "corroborated");
  assert.match(v.headline, /no \$MFT mismatch/);
});

test("T4 verdict: empty → info/none, no MITRE, coverage block still present", () => {
  const v = _buildTimestompVerdict({ totalTimestomped: 0, correlation: _vc(), confirmedStompsNoMftMatch: [] });
  assert.equal(v.severity, "info");
  assert.equal(v.confidence, "none");
  assert.equal(v.mitre.length, 0);
  assert.ok(v.coverage.some((c) => /EID 2/.test(c.label)) && v.coverage.some((c) => /\$SI vs \$FN/.test(c.label)));
});

test("T4 verdict: a cluster is high; a cluster + USN corroboration is critical", () => {
  assert.equal(_buildTimestompVerdict({ totalTimestomped: 6, clusterCount: 1, correlation: _vc(), confirmedStompsNoMftMatch: [] }).severity, "high");
  assert.equal(_buildTimestompVerdict({ totalTimestomped: 6, clusterCount: 1, correlation: _vc({ usnAvailable: true, candidatesUsnContradicted: 2 }), confirmedStompsNoMftMatch: [] }).severity, "critical");
});

test("T4: detectTimestomping attaches a verdict to the result (end-to-end)", { skip }, () => {
  const r = detectTimestomping(makeMeta([
    mftFile({ FileName: "evil.exe", Extension: ".exe", ParentPath: "C:\\Windows\\System32", "SI<FN": "True", uSecZeros: "True",
      Created0x10: "2009-07-14 01:14:33.0000000", Created0x30: "2024-07-03 10:00:00.2583360" }),
  ]));
  assert.ok(r.verdict && r.verdict.severity);
  assert.equal(r.verdict.mitre[0].technique, "T1070.006");
  assert.ok(Array.isArray(r.verdict.coverage) && r.verdict.coverage.length > 0);
});

test("T3-review: bare forward-dated churny container (.log/.tmp/...) is suppressed; exec/future/corroborated kept", { skip }, () => {
  const fwd = (over) => mftFile({ "SI<FN": "False",
    Created0x10: "2024-08-01 10:00:00.0000000", Created0x30: "2024-07-03 10:00:00.0000000",
    LastModified0x10: "2024-08-01 10:00:00.0000000", LastModified0x30: "2024-07-03 10:00:00.0000000", ...over }); // SI > FN
  // bare forward-only .log in AppData → suppressed
  let r = detectTimestomping(makeMeta([fwd({ FileName: "app.log", Extension: ".log", ParentPath: "C:\\Users\\v\\AppData\\Local\\App" })]));
  assert.equal(r.totalTimestomped, 0, "bare forward-dated .log is suppressed (forward-only-container)");
  // but a forward-dated EXECUTABLE is kept (not a churny container)
  r = detectTimestomping(makeMeta([fwd({ FileName: "svc.exe", Extension: ".exe", ParentPath: "C:\\Users\\v\\AppData\\Local\\App" })]));
  assert.ok(r.totalTimestomped >= 1, "forward-dated exec is kept");
  // and a FUTURE-dated .dat is kept (future is a stronger signal than bare forward)
  r = detectTimestomping(makeMeta([fwd({ FileName: "x.dat", Extension: ".dat", ParentPath: "C:\\Users\\v\\AppData\\Local\\App",
    Created0x10: "2099-01-01 00:00:00.0000000", LastModified0x10: "2099-01-01 00:00:00.0000000" })]));
  assert.ok(r.totalTimestomped >= 1 && r.files[0].futureDated, "future-dated .dat is kept");
});
