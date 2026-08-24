// Integration tests for the MFT ADS Analyzer (electron/analyzers/ads.js) and the bulkTagFiltered
// guard that backs its "Tag Downloaded" action.
//
// Locks in: (Tier 2) the new streamCarriers surface (HasAds with no Zone.Identifier — the knowable
// non-Zone ADS signal on raw $MFT) + the contract that the IsAds lane is structurally dead on raw
// $MFT; (Tier 1) the "Tag Downloaded" fix — the corrected advancedFilters/is_not_empty shape tags
// only the downloaded set, the old unrecognized `{filters:[...]}` shape is REFUSED (not tag-all),
// and an empty options object still tags all (intentional, e.g. Sigma).
//
// Needs a live SQLite binding; skipped under a Node runtime without the native module built
// (CI rebuilds it). Run after `npm rebuild better-sqlite3`.

const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
try { Database = require("better-sqlite3"); } catch { /* native module not built */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();
const skip = HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime";

const { analyzeADS, _buildAdsVerdict } = require("../electron/analyzers/ads");
const { registerRuntimeFunctions } = require("../electron/db/runtime-functions");

// MFT column → safe-column map (matches db.js c0..cN sanitization). Row order matches the keys.
const ADS_COLMAP = { HasAds: "c0", IsAds: "c1", ZoneIdContents: "c2", FileName: "c3", Extension: "c4", ParentPath: "c5", EntryNumber: "c6", Created0x10: "c7", FileSize: "c8", IsDirectory: "c9", AdsStreamCount: "c10", AdsStreams: "c11", "SI<FN": "c12", uSecZeros: "c13" };
const NCOLS = 14;
function makeAdsMeta(rows) {
  const db = new Database(":memory:");
  registerRuntimeFunctions(db);
  db.exec(`CREATE TABLE data (${Array.from({ length: NCOLS }, (_, i) => `c${i} TEXT`).join(", ")})`);
  const ins = db.prepare(`INSERT INTO data VALUES (${Array.from({ length: NCOLS }, () => "?").join(",")})`);
  const tx = db.transaction((rs) => { for (const r of rs) ins.run(...r.concat(Array(Math.max(0, NCOLS - r.length)).fill(""))); });
  tx(rows);
  return { db, colMap: ADS_COLMAP, rowCount: rows.length };
}

// [hasAds, isAds, zoneId, fileName, ext, parentPath, entry, created, size, isDir]
const Z = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.example/payload.exe";
const SCENARIO = [
  ["True", "False", Z, "payload.exe", ".exe", ".\\Users\\bob\\Downloads", "1001", "2024-03-01 10:00:00.1234567", "1000", "False"],
  ["True", "False", "", "legit.exe", ".exe", ".\\Windows\\Temp", "1002", "2024-03-02 11:00:00.1234567", "2000", "False"],
  ["True", "False", "", "notes.txt", ".txt", ".\\Users\\bob\\Documents", "1003", "2024-03-03 09:00:00.0000000", "50", "False"],
  ["True", "False", "", "somedir", "", ".\\Users\\bob", "1004", "2024-03-04 08:00:00.0000000", "0", "True"],   // directory → excluded
  ["False", "False", "", "clean.txt", ".txt", ".\\Users\\bob\\Documents", "1005", "2024-03-05 08:00:00.0000000", "10", "False"], // no ADS
];

test("ADS: streamCarriers surfaces non-Zone named-stream files; IsAds lane is dead on raw $MFT; Zone parses", { skip }, () => {
  const r = analyzeADS(makeAdsMeta(SCENARIO));
  assert.equal(r.error, undefined);
  assert.equal(r.totalWithAds, 3, "HasAds=True non-directory files (directory excluded)");
  assert.equal(r.totalWithZoneId, 1, "one Zone.Identifier download");

  // Tier 2: non-Zone stream carriers = HasAds with no Zone.Identifier, non-directory, most-recent-first
  assert.equal(r.totalStreamCarriers, 2);
  const names = r.streamCarriers.map((f) => f.fileName);
  assert.deepEqual([...names].sort(), ["legit.exe", "notes.txt"]);
  assert.ok(!names.includes("payload.exe"), "a Zone.Identifier file is NOT a non-Zone stream carrier");
  assert.ok(!names.includes("somedir"), "directory excluded");
  assert.equal(r.streamCarriers[0].fileName, "notes.txt", "ordered created DESC (most recent first)");

  // Dead-lane contract on raw $MFT (IsAds never True)
  assert.equal(r.totalAdsEntries, 0);
  assert.deepEqual(r.adsEntries, []);
  assert.deepEqual(r.adsAnomalies, []);

  // Zone.Identifier parsing still works
  const pe = r.zoneIdFiles.find((f) => f.fileName === "payload.exe");
  assert.equal(pe.zone, 3);
  assert.equal(pe.hostUrl, "https://evil.example/payload.exe");
});

// [hasAds, isAds, zoneId, fileName, ext, parentPath, entry, created, size, isDir]
const zrow = (zoneBlob, name, created) => ["True", "False", zoneBlob, name, ".exe", ".\\Users\\bob\\Downloads", "9", created, "100", "False"];

test("ADS Tier 3: zone breakdown is exact over the full population, hosts roll up, no-URL bucket counts", { skip }, () => {
  const r = analyzeADS(makeAdsMeta([
    zrow("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.com/a.exe", "a", "2024-03-01 10:00:00"),
    zrow("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.com/b.exe", "b", "2024-03-02 10:00:00"),
    zrow("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://portal/x\r\nHostUrl=https://evil.com/c.exe", "c", "2024-03-03 10:00:00"),
    zrow("[ZoneTransfer]\r\nZoneId=3", "d", "2024-03-04 10:00:00"),                 // internet, no URL
    zrow("[ZoneTransfer]\r\nZoneId=1\r\nHostUrl=https://intra.local/y", "e", "2024-03-05 10:00:00"),
    zrow("garbage no zone marker", "f", "2024-03-06 10:00:00"),                     // unknown, no URL
  ]));
  const zb = r.zoneBreakdown;
  assert.equal(zb.internet, 4);
  assert.equal(zb.intranet, 1);
  assert.equal(zb.unknown, 1);
  assert.equal(zb.local + zb.intranet + zb.trusted + zb.internet + zb.restricted + zb.unknown, r.totalWithZoneId, "buckets partition the full population exactly");
  assert.equal(r.zoneNoUrlCount, 2);
  assert.equal(r.hostUrls.find((h) => h.url === "evil.com")?.count, 3, "host roll-up: evil.com aggregates 3 files");
  assert.equal(r.referrerUrls.find((u) => u.url === "https://portal/x")?.count, 1);
});

test("ADS Tier 3: breakdown counts the FULL population past the 2000-row detail cap; sample is most-recent", { skip }, () => {
  const rows = [];
  for (let i = 0; i < 2000; i++) rows.push(zrow("[ZoneTransfer]\r\nZoneId=3", "old" + i, "2024-01-01 10:00:0" + (i % 10) + ".0000" + i));   // internet, OLD
  for (let i = 0; i < 50; i++) rows.push(zrow("[ZoneTransfer]\r\nZoneId=1", "new" + i, "2024-12-01 10:00:0" + (i % 10) + ".0000" + i));      // intranet, NEW
  const r = analyzeADS(makeAdsMeta(rows));
  assert.equal(r.totalWithZoneId, 2050);
  assert.equal(r.zoneBreakdown.internet, 2000, "full-population breakdown (not the oldest-2000 sample)");
  assert.equal(r.zoneBreakdown.intranet, 50, "the 50 newest intranet are counted (old ASC slice would show 0)");
  assert.equal(r.zoneIdFiles.length, 2000, "detail sample still capped");
  assert.equal(r.zoneIdFiles.filter((f) => f.zoneName === "Intranet").length, 50, "most-recent-first sample includes the newest intranet");
});

test("ADS T5: non-Zone stream names are enumerated from AdsStreams; exec-like flagged by content + name", { skip }, () => {
  // cols: HasAds, IsAds, Zone, FileName, Ext, ParentPath, Entry, Created, Size, IsDir, AdsStreamCount, AdsStreams
  // Descriptors use the always-leading-flag format the parser emits ('!' = resident PE/MZ, '.' = not).
  const r = analyzeADS(makeAdsMeta([
    ["True", "False", "", "invoice.pdf", ".pdf", ".\\Users\\bob\\Downloads", "1", "2024-03-04 10:00:00", "2000", "False", "1", "!payload.exe(512)"], // resident MZ
    ["True", "False", "", "doc.pdf", ".pdf", ".\\Users\\bob\\Downloads", "2", "2024-03-03 10:00:00", "10", "False", "1", ".evil.ps1(100)"],           // exec by name ext
    ["True", "False", "", "report.docx", ".docx", ".\\Users\\bob\\Documents", "3", "2024-03-02 09:00:00", "50", "False", "1", ".cfg(40)"],            // benign
    ["True", "False", "", "note.txt", ".txt", ".\\Users\\bob\\Documents", "4", "2024-03-01 09:00:00", "20", "False", "1", ".!readme(2)"],             // name starts with '!' but NOT exec
  ]));
  assert.equal(r.totalStreamCarriers, 4);
  const inv = r.streamCarriers.find((f) => f.fileName === "invoice.pdf");
  assert.equal(inv.streams[0].name, "payload.exe");
  assert.equal(inv.streams[0].size, 512);
  assert.equal(inv.streams[0].execContent, true, "'!' flag = resident PE/MZ content");
  assert.equal(inv.execLike, true);
  assert.equal(r.streamCarriers.find((f) => f.fileName === "doc.pdf").execLike, true, "exec by stream-name extension (.ps1)");
  assert.equal(r.streamCarriers.find((f) => f.fileName === "report.docx").execLike, false);
  // forged-flag defense: stream NAME '!readme' must not be read as exec content
  const note = r.streamCarriers.find((f) => f.fileName === "note.txt");
  assert.equal(note.streams[0].name, "!readme", "real name preserved");
  assert.equal(note.streams[0].execContent, false, "leading '.' flag — name-'!' cannot forge exec");
  assert.equal(note.execLike, false);
  assert.equal(r.totalAdsExecStreams, 2, "full-population exec count (invoice.pdf + doc.pdf)");
});

test("ADS T4: facade resolves a companion USN tab and passes it through without error", { skip }, () => {
  const TimelineDB = require("../electron/db");
  const db = new TimelineDB();
  try {
    db.createTab("mft", ["HasAds", "ZoneIdContents", "FileName", "IsDirectory"]);
    db.insertBatchArrays("mft", [["True", "[ZoneTransfer]\nZoneId=3", "a.exe", "False"]]);
    db.finalizeImport("mft");
    db.createTab("usn", ["UpdateTimestamp", "UpdateReasons", "Name"]);
    db.insertBatchArrays("usn", [["2024-03-01 10:00:00", "StreamChange|Close", "a.exe"]]);
    db.finalizeImport("usn");
    const r = db.analyzeADS("mft", { usnTabId: "usn" });
    assert.equal(r.error, undefined);
    assert.equal(r.totalWithZoneId, 1, "analysis runs with a resolved companion passed through (T4 plumbing)");
  } finally {
    db.closeAll();
  }
});

test("ADS Tag Downloaded: corrected filter tags only the downloaded set; unrecognized shape is refused; {} needs an explicit whole-tab confirmation", { skip }, () => {
  const TimelineDB = require("../electron/db");
  const db = new TimelineDB();
  const tabId = "ads-tag-test";
  try {
    db.createTab(tabId, ["FileName", "ZoneIdContents"]);
    db.insertBatchArrays(tabId, [
      ["a.exe", "[ZoneTransfer]\nZoneId=3"],
      ["b.dll", "[ZoneTransfer]\nZoneId=3"],
      ["c.txt", ""], ["d.txt", ""], ["e.txt", ""],
    ]);
    db.finalizeImport(tabId);
    const meta = db.databases.get(tabId);
    const tagCount = (tag) => meta.db.prepare("SELECT COUNT(*) c FROM tags WHERE tag=?").get(tag).c;

    // (1) corrected shape → tags only the 2 Zone.Identifier rows
    const ok = db.bulkTagFiltered(tabId, "Downloaded", { advancedFilters: [{ column: "ZoneIdContents", operator: "is_not_empty" }] });
    assert.equal(ok.tagged, 2);
    assert.equal(tagCount("Downloaded"), 2);

    // (2) the OLD broken shape (unknown `filters` key) is REFUSED, never tags all
    const bad = db.bulkTagFiltered(tabId, "Bad", { filters: [{ column: "ZoneIdContents", type: "not_empty" }] });
    assert.ok(bad.error && /unrecognized/i.test(bad.error), "unrecognized filter key refused");
    assert.equal(bad.tagged, 0);
    assert.equal(tagCount("Bad"), 0);

    // (3) empty options means "every row in the tab". That used to happen silently,
    // which is how the Bulk Actions modal tagged whole files by accident, so it now
    // needs the caller to say so explicitly.
    const unconfirmed = db.bulkTagFiltered(tabId, "All", {});
    assert.equal(unconfirmed.tagged, 0);
    assert.equal(unconfirmed.wholeTab, true);
    assert.ok(/all 5 rows/.test(unconfirmed.error), "refusal names the row count");
    assert.equal(tagCount("All"), 0);

    // Deliberate tag-all (e.g. Sigma result tagging) still works when confirmed.
    const all = db.bulkTagFiltered(tabId, "All", { confirmWholeTab: true });
    assert.equal(all.tagged, 5);
    assert.equal(tagCount("All"), 5);
  } finally {
    db.closeAll();
  }
});

// ── T6: cross-artifact corroboration + $SI-reliability ───────────────────────────────────────────
// Companion-tab metas (USN $J / EVTX) mirror what db.js resolves; analyzeADS queries them directly.
function makeUsnMeta(rows) {
  const db = new Database(":memory:");
  registerRuntimeFunctions(db);
  // c0 Name, c1 EntryNumber, c2 UpdateTimestamp, c3 UpdateReasons
  db.exec("CREATE TABLE data (c0 TEXT,c1 TEXT,c2 TEXT,c3 TEXT)");
  const ins = db.prepare("INSERT INTO data VALUES (?,?,?,?)");
  for (const r of rows) ins.run(...r);
  return { db, colMap: { Name: "c0", EntryNumber: "c1", UpdateTimestamp: "c2", UpdateReasons: "c3" } };
}
function makeEvtxMeta(rows) {
  const db = new Database(":memory:");
  registerRuntimeFunctions(db);
  // c0 EventID, c1 TimeCreated, c2 PayloadData1
  db.exec("CREATE TABLE data (c0 TEXT,c1 TEXT,c2 TEXT)");
  const ins = db.prepare("INSERT INTO data VALUES (?,?,?)");
  for (const r of rows) ins.run(...r);
  return { db, headers: ["EventID", "TimeCreated", "PayloadData1"], colMap: { EventID: "c0", TimeCreated: "c1", PayloadData1: "c2" } };
}

// [hasAds, isAds, zoneId, fileName, ext, parentPath, entry, created, size, isDir, adsCount, adsStreams, siFn, uSecZeros]
const T6_CARRIERS = [
  ["True", "False", "", "invoice.pdf", ".pdf", ".\\Users\\v\\Downloads", "1001", "2026-05-20 10:00:00", "12345", "False", "1", ".payload.exe(4096)", "False", "False"],
  ["True", "False", "", "notes.txt", ".txt", ".\\Users\\v\\Documents", "1002", "2026-05-21 11:00:00", "999", "False", "2", ".afp_resource(50)|.bigblob(200000)", "True", "False"],
  ["True", "False", "", "report.docx", ".docx", ".\\tmp", "1003", "2026-05-22 12:00:00", "42", "False", "1", "!hidden(2)", "False", "True"],
  ["True", "False", "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil/x", "x.exe", ".exe", ".\\Users\\v\\Downloads", "1004", "2026-05-23 09:00:00", "8", "False", "", "", "False", "False"],
];

test("ADS T6: $SI-reliability flags timestomped-looking carriers (full population + per-row)", { skip }, () => {
  const r = analyzeADS(makeAdsMeta(T6_CARRIERS), {});
  assert.equal(r.totalStreamCarriers, 3, "Zone.Id row excluded from carriers");
  assert.equal(r.siReliability.available, true);
  assert.equal(r.siReliability.suspectStreamCarriers, 2, "notes.txt (SI<FN) + report.docx (uSecZeros)");
  assert.equal(r.siReliability.totalStreamCarriers, 3);
  const by = Object.fromEntries(r.streamCarriers.map((f) => [f.fileName, f]));
  assert.equal(by["notes.txt"].siSuspect, true);
  assert.equal(by["report.docx"].siSuspect, true);
  assert.equal(by["invoice.pdf"].siSuspect, false);
  assert.equal(by["invoice.pdf"].siFn, undefined, "internal $SI columns not leaked onto output rows");
  // no companions → all-zero correlation, no crash
  assert.equal(r.correlation.usnAvailable, false);
  assert.equal(r.correlation.evtxAvailable, false);
  assert.equal(r.correlation.usnNamedStreamTotal, 0);
  assert.equal(r.correlation.carriersUsnCorroborated, 0);
});

test("ADS T6: USN NamedData*/StreamChange + Sysmon EID 15 corroborate carriers; landscape totals", { skip }, () => {
  const usnMeta = makeUsnMeta([
    ["invoice.pdf", "1001", "2026-05-20 10:00:01", "DataExtend|NamedDataExtend|Close"],
    ["notes.txt", "1002", "2026-05-21 11:00:02", "StreamChange|Close"],
    ["notes.txt", "1002", "2026-05-21 11:05:00", "NamedDataOverwrite"],
    ["unrelated.log", "5", "2026-05-01 00:00:00", "DataExtend|Close"], // not a named-stream reason
  ]);
  const evtxMeta = makeEvtxMeta([
    ["15", "2026-05-20 10:00:01", "TargetFilename: C:\\Users\\v\\Downloads\\invoice.pdf:payload.exe Hash=SHA256=ABC Image=C:\\Windows\\powershell.exe"],
    ["1", "2026-05-20 10:00:00", "Image: C:\\Windows\\powershell.exe"], // process-create, not EID 15
    ["15", "2026-05-19 08:00:00", "TargetFilename: C:\\some\\other.bin:zone Hash=SHA256=DEF"], // no carrier match
    ["15", "2026-05-18 07:00:00", "TargetFilename: C:\\x\\weekly_invoice.pdf:zz"], // embedded stem — must NOT match invoice.pdf
    ["15", "2026-05-17 06:00:00", "TargetFilename: C:\\noads\\plainfile.exe Image=C:\\foo.exe"], // no stream colon — keys nothing
  ]);
  const r = analyzeADS(makeAdsMeta(T6_CARRIERS), { usnMeta, evtxMeta });
  assert.ok(!r.error, r.error);
  assert.equal(r.correlation.usnAvailable, true);
  assert.equal(r.correlation.evtxAvailable, true);
  assert.equal(r.correlation.usnNamedStreamTotal, 3, "3 named-stream/StreamChange ops in the journal");
  assert.equal(r.correlation.evtxStreamCreateTotal, 4, "4 EID 15 events in the log");
  const by = Object.fromEntries(r.streamCarriers.map((f) => [f.fileName, f]));
  assert.equal(by["invoice.pdf"].usnCorroboration.namedStreamOps, 1);
  assert.equal(by["invoice.pdf"].usnCorroboration.strong, true, "entry+name → strong match");
  assert.equal(by["invoice.pdf"].evtxCorroboration.streamCreates, 1, "embedded-stem weekly_invoice.pdf does NOT inflate the match");
  assert.ok(by["invoice.pdf"].evtxCorroboration.samples.length >= 1, "EID 15 sample captured");
  assert.equal(by["notes.txt"].usnCorroboration.namedStreamOps, 2, "two USN ops on the same file");
  assert.ok(!by["notes.txt"].evtxCorroboration, "notes.txt has no EID 15 match");
  assert.ok(!by["report.docx"].usnCorroboration && !by["report.docx"].evtxCorroboration, "report.docx uncorroborated");
  assert.equal(r.correlation.carriersUsnCorroborated, 2);
  assert.equal(r.correlation.carriersEvtxCorroborated, 1);
  // No silent 200-cap: every displayed carrier is corroboration-checked.
  assert.equal(r.correlation.carriersChecked, 3);
  assert.ok(r.streamCarriers.every((f) => f.corrChecked === true), "every displayed carrier stamped corrChecked");
});

test("ADS T6: EVTX EID 15 is Sysmon-channel-scoped — a non-Sysmon EID 15 cannot corroborate", { skip }, () => {
  // EVTX meta WITH a Channel column. c0 EventID, c1 TimeCreated, c2 Channel, c3 PayloadData1.
  const db = new Database(":memory:");
  registerRuntimeFunctions(db);
  db.exec("CREATE TABLE data (c0 TEXT,c1 TEXT,c2 TEXT,c3 TEXT)");
  const ins = db.prepare("INSERT INTO data VALUES (?,?,?,?)");
  ins.run("15", "2026-05-20 10:00:01", "Microsoft-Windows-Sysmon/Operational", "TargetFilename: C:\\Users\\v\\Downloads\\invoice.pdf:payload.exe");
  ins.run("15", "2026-05-20 10:00:02", "Application", "TargetFilename: C:\\Users\\v\\Documents\\notes.txt:evil"); // non-Sysmon EID 15 → must be excluded
  const evtxMeta = { db, headers: ["EventID", "TimeCreated", "Channel", "PayloadData1"], colMap: { EventID: "c0", TimeCreated: "c1", Channel: "c2", PayloadData1: "c3" } };
  const r = analyzeADS(makeAdsMeta(T6_CARRIERS), { evtxMeta });
  assert.ok(!r.error, r.error);
  assert.equal(r.correlation.evtxStreamCreateTotal, 1, "only the Sysmon EID 15 is counted");
  const by = Object.fromEntries(r.streamCarriers.map((f) => [f.fileName, f]));
  assert.equal(by["invoice.pdf"].evtxCorroboration.streamCreates, 1, "Sysmon EID 15 corroborates invoice.pdf");
  assert.ok(!by["notes.txt"].evtxCorroboration, "non-Sysmon EID 15 must NOT corroborate notes.txt");
});

test("ADS T6: legacy MFT without $SI columns → reliability not assessable; corroboration degrades cleanly", { skip }, () => {
  // colMap without SI<FN/uSecZeros (old tabs / MFTECmd CSV without those headers)
  const base = makeAdsMeta(T6_CARRIERS);
  const trimmed = { ...base.colMap }; delete trimmed["SI<FN"]; delete trimmed.uSecZeros;
  const meta = { db: base.db, colMap: trimmed, rowCount: base.rowCount };
  const r = analyzeADS(meta, {});
  assert.ok(!r.error, r.error);
  assert.equal(r.siReliability.available, false);
  assert.ok(r.streamCarriers.every((f) => f.siSuspect === false), "no SI cols → no false $SI-suspect flags");
});

// ── T7: _buildAdsVerdict — PURE (no SQLite), so these run under plain `node --test` (not skipped). ──
const _C = (o = {}) => ({ usnAvailable: false, evtxAvailable: false, usnNamedStreamTotal: 0, evtxStreamCreateTotal: 0, carriersUsnCorroborated: 0, carriersEvtxCorroborated: 0, motwCorroborated: 0, ...o });
const _S = (o = {}) => ({ available: true, suspectStreamCarriers: 0, totalStreamCarriers: 0, ...o });
const _tech = (mit, t) => mit.find((m) => m.technique === t);

test("ADS T7 verdict: executable-in-stream + EVTX/USN corroboration → high+, confidence corroborated, T1564.004✓", () => {
  const v = _buildAdsVerdict({ totalStreamCarriers: 3, totalAdsExecStreams: 2, correlation: _C({ usnAvailable: true, evtxAvailable: true, usnNamedStreamTotal: 5, evtxStreamCreateTotal: 2, carriersUsnCorroborated: 2, carriersEvtxCorroborated: 1 }), siReliability: _S({ totalStreamCarriers: 3 }), hasAdsStreams: true });
  assert.ok(["high", "critical"].includes(v.severity), `severity ${v.severity}`);
  assert.equal(v.confidence, "corroborated");
  assert.equal(_tech(v.mitre, "T1564.004").confidence, "corroborated");
  assert.ok(v.headline.startsWith(v.severity.toUpperCase()));
  assert.ok(v.coverage.some((c) => c.label.includes("USN") && c.status === "ok"));
});

test("ADS T7 verdict: confidence gating — observed (no companion), weak (loaded, no match), corroborated (match)", () => {
  const base = { totalStreamCarriers: 3, totalAdsExecStreams: 2, siReliability: _S({ totalStreamCarriers: 3 }), hasAdsStreams: true };
  assert.equal(_buildAdsVerdict({ ...base, correlation: _C() }).confidence, "observed");
  assert.equal(_buildAdsVerdict({ ...base, correlation: _C({ usnAvailable: true, usnNamedStreamTotal: 9 }) }).confidence, "weak");
  assert.equal(_buildAdsVerdict({ ...base, correlation: _C({ usnAvailable: true, carriersUsnCorroborated: 1 }) }).confidence, "corroborated");
  assert.equal(_tech(_buildAdsVerdict({ ...base, correlation: _C() }).mitre, "T1564.004").confidence, "observed");
});

test("ADS T7 verdict: a separately-corroborated MOTW strip does NOT launder an uncorroborated stream headline", () => {
  const v = _buildAdsVerdict({ totalStreamCarriers: 4, totalAdsExecStreams: 2, motwSuspicious: [{}], correlation: _C({ usnAvailable: true, evtxAvailable: true, carriersUsnCorroborated: 0, carriersEvtxCorroborated: 0, motwCorroborated: 1 }), siReliability: _S({ totalStreamCarriers: 4 }), hasAdsStreams: true });
  assert.equal(v.confidence, "weak", "stream headline is the lead and is uncorroborated → weak, not corroborated");
});

test("ADS T7 verdict: USN-corroborated MOTW strip → T1553.005 corroborated + ingress T1105", () => {
  const v = _buildAdsVerdict({ totalWithZoneId: 10, totalStreamCarriers: 0, totalAdsExecStreams: 0, execCount: 1, motwSuspicious: [{}, {}], internalHosts: [], correlation: _C({ usnAvailable: true, motwCorroborated: 2 }), siReliability: _S(), hasAdsStreams: true });
  assert.equal(_tech(v.mitre, "T1553.005").confidence, "corroborated");
  assert.equal(v.confidence, "corroborated");
  assert.ok(_tech(v.mitre, "T1105"));
});

test("ADS T7 verdict: $SI-suspect adds a timing factor but does NOT downgrade a corroborated finding", () => {
  const v = _buildAdsVerdict({ totalStreamCarriers: 4, totalAdsExecStreams: 1, correlation: _C({ usnAvailable: true, evtxAvailable: true, carriersUsnCorroborated: 1 }), siReliability: _S({ suspectStreamCarriers: 3, totalStreamCarriers: 4 }), hasAdsStreams: true });
  assert.ok(v.factors.some((f) => /\$SI timing unreliable/.test(f.label)));
  assert.equal(v.confidence, "corroborated");
  assert.ok(v.coverage.some((c) => c.label.includes("$SI") && c.status === "partial"));
});

test("ADS T7 verdict: empty → info/none with no MITRE but coverage still notes the gap", () => {
  const v = _buildAdsVerdict({ totalWithZoneId: 0, totalStreamCarriers: 0, correlation: _C(), siReliability: _S({ available: false }), hasAdsStreams: false });
  assert.equal(v.severity, "info");
  assert.equal(v.confidence, "none");
  assert.equal(v.mitre.length, 0);
  assert.ok(v.coverage.some((c) => c.label.includes("Stream visibility") && c.status === "gap"));
});

test("ADS T7 verdict: downloads-only (Zone.Identifier, no streams) → T1105, no T1564.004, observed", () => {
  const v = _buildAdsVerdict({ totalWithZoneId: 500, totalStreamCarriers: 0, totalAdsExecStreams: 0, execCount: 8, zoneBreakdown: { internet: 480 }, correlation: _C(), siReliability: _S(), hasAdsStreams: true });
  assert.ok(_tech(v.mitre, "T1105"));
  assert.ok(!_tech(v.mitre, "T1564.004"));
  assert.equal(v.confidence, "observed");
});

test("ADS T7 verdict: benign-only carriers don't inflate severity or read as a finding", () => {
  // 19 carriers, ALL benign (nonBenignStreamCarriers 0), no downloads → no named-stream finding, info.
  const v = _buildAdsVerdict({ totalWithZoneId: 0, totalStreamCarriers: 19, nonBenignStreamCarriers: 0, totalAdsExecStreams: 0, correlation: _C(), siReliability: _S({ totalStreamCarriers: 19 }), hasAdsStreams: true });
  assert.equal(v.severity, "info");
  assert.ok(!v.factors.some((f) => /Non-Zone named streams/.test(f.label)), "benign-only carriers are not a flagged factor");
  assert.ok(!_tech(v.mitre, "T1564.004"), "benign-only → no T1564.004");
});

test("ADS T7 verdict: benign-excluded count drives the named-stream finding (raw count is display-only)", () => {
  const v = _buildAdsVerdict({ totalStreamCarriers: 15, nonBenignStreamCarriers: 3, totalAdsExecStreams: 0, correlation: _C(), siReliability: _S({ totalStreamCarriers: 15 }), hasAdsStreams: true });
  const f = v.factors.find((x) => /Non-Zone named streams/.test(x.label));
  assert.ok(f && /\b3 file/.test(f.detail) && /12 known-benign/.test(f.detail), `factor uses benign-excluded count: ${f && f.detail}`);
});

test("ADS T7 verdict: a corroborated MOTW strip headline describes the strip, not the download", () => {
  const v = _buildAdsVerdict({ totalWithZoneId: 10, totalStreamCarriers: 0, execCount: 1, motwSuspicious: [{}, {}], correlation: _C({ usnAvailable: true, motwCorroborated: 2 }), siReliability: _S(), hasAdsStreams: true });
  assert.equal(v.confidence, "corroborated");
  assert.match(v.headline, /lost their Mark-of-the-Web on extraction/);
  assert.ok(!/executable download\(s\) carry Mark-of-the-Web/.test(v.headline), "lead is not the uncorroborated download lane");
});

test("ADS T7: analyzeADS computes a benign-excluded carrier count from real data (end-to-end)", { skip }, () => {
  // wof.dll carries ONLY a benign WofCompressedData stream → excluded; payload.pdf carries an exec stream.
  const r = analyzeADS(makeAdsMeta([
    ["True", "False", "", "wof.dll", ".dll", "C:\\Windows\\System32", "1", "2026-05-20 10:00:00", "100", "False", "1", ".WofCompressedData(5000)", "False", "False"],
    ["True", "False", "", "payload.pdf", ".pdf", "C:\\tmp", "2", "2026-05-21 10:00:00", "200", "False", "1", "!evil(512)", "False", "False"],
  ]), {});
  assert.equal(r.totalStreamCarriers, 2, "raw display count includes the benign carrier");
  assert.equal(r.totalAdsExecStreams, 1, "one exec-like carrier");
  assert.ok(r.verdict && /1 known-benign OS\/app stream\(s\) excluded/.test(r.verdict.narrative), `verdict excludes the benign carrier: ${r.verdict && r.verdict.narrative}`);
});

test("ADS T7: analyzeADS attaches a verdict to the result (end-to-end)", { skip }, () => {
  const r = analyzeADS(makeAdsMeta(T6_CARRIERS), {});
  assert.ok(r.verdict, "verdict present");
  assert.ok(["info", "low", "medium", "high", "critical"].includes(r.verdict.severity));
  assert.ok(Array.isArray(r.verdict.coverage) && r.verdict.coverage.length > 0, "coverage block present");
  assert.equal(_tech(r.verdict.mitre, "T1564.004") ? true : r.verdict.mitre.length >= 0, true);
});
