// Hayabusa output parsing + truncation detection.
//
// Requires output-parser.js DIRECTLY (not the evtx-scanner facade), so these run
// under plain `node --test` — output-parser only depends on Node core + the pure
// dfir-event-fields registry, never on better-sqlite3. resultStore:null keeps the
// parser fully in-memory.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  parseHayabusaCsv,
  parseHayabusaJsonl,
} = require("../electron/analyzers/sigma/evtx-scanner/output-parser");

const CSV_HEADER = "Timestamp,RuleTitle,Level,Computer,Channel,EventID,MitreTactics,MitreTags,OtherTags,RecordID,Details,ExtraFieldInfo,RuleFile,RuleID,EvtxFile";
const ALL_LEVELS = ["critical", "high", "medium", "low", "informational"];

function tmpFile(t, name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-hayabusa-out-"));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  const p = path.join(dir, name);
  fs.writeFileSync(p, content);
  return p;
}

test("parseHayabusaCsv: clean file parses rows, aggregates rule matches, extracts KV fields", async (t) => {
  const csv = tmpFile(t, "clean.csv", [
    CSV_HEADER,
    "2026-01-01T00:00:00Z,Suspicious Logon,high,HOST1,Security,4624,TA0001,attack.initial_access,detection.test,123,User: admin ¦ Cmdline: powershell.exe -nop ¦ StorageId: noisy,,rules/susp.yml,rule-1,/case/Security.evtx",
    "2026-01-01T01:00:00Z,Suspicious Logon,high,HOST2,Security,4624,TA0001,attack.initial_access,detection.test,124,User: bob,,rules/susp.yml,rule-1,/case/Security.evtx",
    "", // trailing blank line + newline => clean ending
  ].join("\n"));

  const parsed = await parseHayabusaCsv(csv, null, null, { resultStore: null, previewLimit: 2000 });

  assert.equal(parsed.eventRows.length, 2);
  assert.equal(parsed.truncatedTail, false);
  assert.equal(parsed.eventRows[0].RuleID, "rule-1");
  assert.equal(parsed.eventRows[0].Cmdline, "powershell.exe -nop", "DFIR KV field extracted from Details");
  assert.equal(parsed.eventRows[0].User, "admin");
  assert.equal(parsed.eventRows[0].StorageId, undefined, "non-DFIR KV keys are not promoted to columns");

  const rm = parsed.ruleMatches.get("rule-1");
  assert.equal(rm.count, 2, "two events aggregate under one rule");
  assert.equal(rm.level, "high");
  assert.deepEqual([...rm.hosts].sort(), ["HOST1", "HOST2"]);
});

test("parseHayabusaCsv: normalizes Hayabusa abbreviated severity levels", async (t) => {
  const csv = tmpFile(t, "levels.csv", [
    CSV_HEADER,
    "2026-01-01T00:00:00Z,Critical Rule,crit,HOST1,Security,1,,,,1,,,rules/crit.yml,rule-crit,/case/Security.evtx",
    "2026-01-01T00:01:00Z,Medium Rule,med,HOST1,Security,2,,,,2,,,rules/med.yml,rule-med,/case/Security.evtx",
    "2026-01-01T00:02:00Z,Info Rule,info,HOST1,Security,3,,,,3,,,rules/info.yml,rule-info,/case/Security.evtx",
    "",
  ].join("\n"));

  const parsed = await parseHayabusaCsv(csv, null, null, { resultStore: null, previewLimit: 2000 });

  assert.deepEqual(parsed.eventRows.map((row) => row.Level), ["critical", "medium", "informational"]);
  assert.equal(parsed.ruleMatches.get("rule-crit").level, "critical");
  assert.equal(parsed.ruleMatches.get("rule-med").level, "medium");
  assert.equal(parsed.ruleMatches.get("rule-info").level, "informational");
});

test("parseHayabusaCsv: a file cut off mid-row sets truncatedTail", async (t) => {
  // Last row has only 3 of 15 columns and the file does NOT end with a newline —
  // exactly what a Hayabusa crash mid-write produces.
  const csv = tmpFile(t, "truncated.csv", [
    CSV_HEADER,
    "2026-01-01T00:00:00Z,Full Rule,high,HOST1,Security,4624,TA0001,attack.initial_access,detection.test,123,User: admin,,rules/a.yml,rule-1,/case/Security.evtx",
    "2026-01-01T02:00:00Z,Half Rul", // truncated mid-field, no newline
  ].join("\n"));

  const parsed = await parseHayabusaCsv(csv, null, null, { resultStore: null, previewLimit: 2000 });
  assert.equal(parsed.truncatedTail, true);
});

test("parseHayabusaCsv: a complete final row without trailing newline is NOT flagged", async (t) => {
  // Full column count on the last line => complete record, even without a final \n.
  const csv = tmpFile(t, "no-trailing-nl.csv", [
    CSV_HEADER,
    "2026-01-01T00:00:00Z,Full Rule,high,HOST1,Security,4624,TA0001,attack.initial_access,detection.test,123,User: admin,,rules/a.yml,rule-1,/case/Security.evtx",
  ].join("\n"));

  const parsed = await parseHayabusaCsv(csv, null, null, { resultStore: null, previewLimit: 2000 });
  assert.equal(parsed.truncatedTail, false, "complete last record must not raise a false truncation alarm");
  assert.equal(parsed.eventRows.length, 1);
});

test("parseHayabusaJsonl: clean file parses rows and aggregates matches", async (t) => {
  const jsonl = tmpFile(t, "clean.jsonl", [
    JSON.stringify({ Timestamp: "2026-01-01T00:00:00Z", RuleTitle: "Mimikatz", Level: "critical", Computer: "DC1", Channel: "Security", EventID: 4688, RuleID: "rule-9", Details: "Cmdline: mimikatz.exe" }),
    JSON.stringify({ Timestamp: "2026-01-01T00:05:00Z", RuleTitle: "Mimikatz", Level: "critical", Computer: "DC1", Channel: "Security", EventID: 4688, RuleID: "rule-9", Details: "Cmdline: sekurlsa" }),
    "", // trailing newline
  ].join("\n"));

  const parsed = await parseHayabusaJsonl(jsonl, ALL_LEVELS, null, null, { resultStore: null, previewLimit: 2000 });
  assert.equal(parsed.eventRows.length, 2);
  assert.equal(parsed.truncatedTail, false);
  assert.equal(parsed.eventRows[0].Cmdline, "mimikatz.exe");
  assert.equal(parsed.ruleMatches.get("rule-9").count, 2);
});

test("parseHayabusaJsonl: a half-written final object sets truncatedTail", async (t) => {
  const jsonl = tmpFile(t, "truncated.jsonl", [
    JSON.stringify({ Timestamp: "2026-01-01T00:00:00Z", RuleTitle: "Mimikatz", Level: "critical", Computer: "DC1", RuleID: "rule-9" }),
    '{"Timestamp":"2026-01-01T00:05:00Z","RuleTitle":"Cut', // truncated JSON, no newline
  ].join("\n"));

  const parsed = await parseHayabusaJsonl(jsonl, ALL_LEVELS, null, null, { resultStore: null, previewLimit: 2000 });
  assert.equal(parsed.truncatedTail, true);
  assert.equal(parsed.eventRows.length, 1, "the valid record is still returned");
});
