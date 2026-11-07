// previewPersistenceAnalysis coverage — the pre-scan panel had zero tests.
//
// The preview drives the config screen: the coverage chips, the "≈ N events in
// scope" estimate and the "no persistence-related registry keys found" warning.
// Two defects lived here undetected because nothing exercised it:
//
//   • the registry coverage patterns were written "%\\\\Run%", i.e. the runtime
//     string %\\Run% — TWO literal backslashes. These are SQL LIKE patterns, not
//     regexes, so no KeyPath ever matched and those groups permanently read 0
//     while the scan itself found the keys.
//   • the Defender event ids (5001/5007/5010/5012/5101) were absent from uiEids,
//     so Defender-tampering rules were invisible before a scan and excluded from
//     the in-scope estimate.
//
// Runs against the real DuckDB engine so LIKE semantics — especially that a
// backslash is a literal, since LIKE has no escape character by default — are
// exercised for real rather than approximated by a stub.

const test = require("node:test");
const assert = require("node:assert/strict");

const { previewPersistenceAnalysis } = require("../electron/analyzers/persistence");

let DatabaseSync = null;
let createTestDataTable = null;
try { ({ Database: DatabaseSync, createTestDataTable } = require("./helpers/duckdb-data-table")); } catch { /* DuckDB binding not installed */ }
const needsSqlite = { skip: DatabaseSync ? false : "DuckDB binding not available for this runtime" };

// Build an in-memory `data` table with sanitized c0..cN columns, mirroring how the
// real TimelineDB stores an imported file (headers -> colMap -> c<idx>).
function makeDb(headers, rows) {
  const db = new DatabaseSync(":memory:");
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const ins = createTestDataTable(db, headers.map((_, i) => `c${i}`).join(", "));
  for (const r of rows) ins.run(...headers.map((h) => (r[h] != null ? String(r[h]) : null)));
  return { meta: { db, headers, colMap, tabId: "preview" }, ctx: { applyStandardFilters() {} } };
}

const REG_HEADERS = ["KeyPath", "ValueName", "ValueData", "HivePath", "LastWriteTimestamp"];
const regRow = (keyPath, valueName, valueData) => ({
  KeyPath: keyPath, ValueName: valueName, ValueData: valueData,
  HivePath: "C:\\Windows\\System32\\config\\SOFTWARE", LastWriteTimestamp: "2026-03-15 10:00:00",
});

test("registry preview counts the key paths the scan actually detects", needsSqlite, () => {
  const { meta, ctx } = makeDb(REG_HEADERS, [
    regRow("ROOT\\Microsoft\\Windows\\CurrentVersion\\Run", "Updater", "C:\\Temp\\evil.exe"),
    regRow("ROOT\\ControlSet001\\Services\\EvilSvc", "ImagePath", "C:\\Temp\\evil.exe"),
    regRow("ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Shell", "explorer.exe,evil.exe"),
    regRow("ROOT\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\Evil", "Id", "{guid}"),
    regRow("ROOT\\Control\\Lsa", "Security Packages", "mimilib"),
    regRow("ROOT\\Control\\Print\\Monitors\\EvilMon", "Driver", "evil.dll"),
    regRow("ROOT\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpapers", "Noise", "x"),
  ]);

  const res = previewPersistenceAnalysis(meta, { mode: "registry" }, ctx);

  assert.equal(res.error, undefined, res.error);
  assert.equal(res.detectedMode, "registry");
  // Every one of these used the broken double-backslash pattern and read 0.
  assert.equal(res.eventCounts["Run Keys"], 1, "Run key must be counted");
  assert.equal(res.eventCounts["Services"], 1, "Services key must be counted");
  assert.equal(res.eventCounts["Winlogon"], 1, "Winlogon key must be counted");
  assert.equal(res.eventCounts["LSA"], 1, "Lsa key must be counted");
  assert.equal(res.eventCounts["Print Monitors"], 1, "Print\\Monitors key must be counted");
  // This one never had a backslash in its pattern, so it worked before — keep it pinned.
  assert.equal(res.eventCounts["Scheduled Tasks"], 1);
  // Deduplicated total: 6 persistence-relevant rows, the wallpaper row excluded.
  assert.equal(res.trackedEvents, 6);
});

test("registry preview reports every coverage group the modal renders a chip for", needsSqlite, () => {
  const { meta, ctx } = makeDb(REG_HEADERS, [regRow("ROOT\\Microsoft\\Windows\\CurrentVersion\\Run", "X", "y")]);
  const res = previewPersistenceAnalysis(meta, { mode: "registry" }, ctx);
  // A chip with no matching eventCounts entry can only ever render 0.
  for (const label of [
    "Run Keys", "Services", "Winlogon", "IFEO", "COM Objects", "Scheduled Tasks", "Boot Execute",
    "LSA", "Shell Extensions", "AppInit DLLs", "Print Monitors", "Active Setup", "BHO",
    "Network Providers", "Logon Script", "AppCert DLLs", "Silent Process Exit",
    "Credential Providers", "Command Processor", "Explorer Autoruns", "Netsh Helper DLLs",
  ]) {
    assert.ok(label in res.eventCounts, `coverage group "${label}" is never counted by the preview`);
  }
});

test("registry preview does not warn 'no keys found' when keys exist", needsSqlite, () => {
  // paSkipWarnings raises an error-level warning when every count is 0 — which the
  // broken patterns made the normal outcome on a real RECmd export.
  const { meta, ctx } = makeDb(REG_HEADERS, [
    regRow("ROOT\\Microsoft\\Windows\\CurrentVersion\\Run", "Updater", "C:\\Temp\\evil.exe"),
  ]);
  const res = previewPersistenceAnalysis(meta, { mode: "registry" }, ctx);
  assert.ok(Object.values(res.eventCounts).some((v) => v > 0), "at least one group must be non-zero");
});

test("evtx preview counts Defender tamper events", needsSqlite, () => {
  const headers = ["EventID", "Channel", "TimeCreated", "Computer", "PayloadData1"];
  const evRow = (eid, channel, pd) => ({ EventID: eid, Channel: channel, TimeCreated: "2026-03-15 10:00:00", Computer: "HOST-A", PayloadData1: pd });
  const { meta, ctx } = makeDb(headers, [
    evRow("5007", "Microsoft-Windows-Windows Defender/Operational", "New Value: ...\\Exclusions\\Paths\\C:\\Temp"),
    evRow("5001", "Microsoft-Windows-Windows Defender/Operational", "Real-Time Protection disabled"),
    evRow("7045", "System", "Name: EvilSvc"),
  ]);

  const res = previewPersistenceAnalysis(meta, { mode: "evtx" }, ctx);

  assert.equal(res.detectedMode, "evtx");
  assert.equal(res.eventCounts["5007"], 1, "5007 must appear in the pre-scan coverage");
  assert.equal(res.eventCounts["5001"], 1, "5001 must appear in the pre-scan coverage");
  assert.equal(res.eventCounts["7045"], 1);
  assert.equal(res.trackedEvents, 3, "Defender events must count toward the in-scope estimate");
});

test("evtx preview tracks every event id the analyzer can fire on", needsSqlite, async () => {
  // uiEids must stay a superset of EVTX_RULES' event ids; anything missing is
  // reported as unavailable pre-scan but still produces findings after the scan.
  const { PERSISTENCE_RULE_CATALOG } = require("../electron/analyzers/persistence");
  // Sentinels like "TASKXML" are synthesized by the KAPE collection scan for rows that are
  // not Windows events at all (a task definition read off disk). They can never appear in
  // an imported tab's EventID column, so the pre-scan preview must NOT claim to count them.
  const ruleEids = [...new Set(PERSISTENCE_RULE_CATALOG.evtx.flatMap((r) => r.hint.split(",").map((s) => s.trim())))]
    .filter((eid) => /^\d+$/.test(eid));

  const headers = ["EventID", "Channel", "TimeCreated", "Computer"];
  const { meta, ctx } = makeDb(headers, ruleEids.map((eid) => ({
    EventID: eid, Channel: "", TimeCreated: "2026-03-15 10:00:00", Computer: "HOST-A",
  })));

  const res = previewPersistenceAnalysis(meta, { mode: "evtx" }, ctx);
  const missing = ruleEids.filter((eid) => !(eid in res.eventCounts));
  assert.deepEqual(missing, [], `event ids fired by rules but absent from the preview: ${missing.join(", ")}`);
});
