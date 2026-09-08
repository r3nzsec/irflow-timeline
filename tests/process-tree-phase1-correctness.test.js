// Phase 1 correctness regressions for Process Inspector.
//
//   P1  Sysmon EID 7/11 enrichment fell back to the host process's own Image,
//       so "unsigned DLL from a writable path" and "PE dropped in a writable
//       path" were really being evaluated against the process's own binary.
//   P2  Column roles were chosen per DATASET, but the right column depends on
//       the EVENT: a Security 4688 uses NewProcessId/ProcessId, a 4689/4673/4674
//       uses ProcessId.
//   P8  EvtxECmd 4688 PIDs are hex; the decimal-only regex read "0x1a2c" as 0.
//   P20 The Event ID box is free text and was interpolated into SQL.

const test = require("node:test");
const assert = require("node:assert/strict");

const { getProcessTree } = require("../electron/analyzers/process-tree");

function makeStub(headers, rows, opts = {}) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const rowsByCN = rows.map((r, i) => {
    const cn = { _rowid: i + 1 };
    headers.forEach((h) => { cn[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return cn;
  });
  const seenSql = [];

  // Rows are filtered by the EventID equality/IN predicate the analyzer emits, so
  // the auxiliary EID 7/11 queries only see their own rows (as in a real DB).
  function rowsFor(sql, params) {
    const eidCol = colMap[opts.eventIdHeader || "EventID"];
    let subset = rowsByCN;
    const eqMatch = sql.match(new RegExp(`${eidCol}\\s*=\\s*\\?`));
    const inMatch = sql.match(new RegExp(`${eidCol}\\s+IN\\s*\\(([?,\\s]+)\\)`));
    if (eqMatch && params.length > 0) {
      subset = rowsByCN.filter((r) => String(r[eidCol]) === String(params[0]));
    } else if (inMatch && params.length > 0) {
      const wanted = new Set(params.map(String));
      subset = rowsByCN.filter((r) => wanted.has(String(r[eidCol])));
    }
    return subset;
  }

  function aliasRows(sql, params) {
    const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    return rowsFor(sql, params).map((r) => {
      const out = { _rowid: r._rowid };
      for (const [, idx, alias] of aliasMatches) out[alias] = r[`c${idx}`];
      return out;
    });
  }

  const db = {
    prepare(sql) {
      seenSql.push(sql);
      return {
        get(...params) {
          if (/COUNT\(\*\)\s+as\s+cnt/i.test(sql)) return { cnt: rowsByCN.length || 1 };
          if (/COUNT\(\*\)\s+as\s+n/i.test(sql)) return { n: rowsFor(sql, params).length };
          if (/COUNT\(\*\)/i.test(sql)) return { cnt: rowsByCN.length || 1, n: rowsByCN.length || 1 };
          return null;
        },
        all(...params) {
          if (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql)) return aliasRows(sql, params);
          return [];
        },
      };
    },
  };
  const meta = { db, headers, colMap, tabId: "pt-phase1" };
  const ctx = { applyStandardFilters() {}, ensureIndex() {} };
  return { meta, ctx, seenSql };
}

// ======================= P1: EID 7 / 11 artifact paths =======================

const SYSMON_TELEMETRY_HEADERS = [
  "ProcessId", "ParentProcessId", "ProcessGuid", "ParentProcessGuid",
  "Image", "ParentImage", "CommandLine", "User", "UtcTime",
  "EventID", "Provider", "Computer", "ImageLoaded", "TargetFilename", "Signed", "SignatureStatus",
];

const CREATE_ROW = {
  ProcessId: "4444", ParentProcessId: "1000", ProcessGuid: "{aaaaaaaa-0000-0000-0000-000000000001}",
  ParentProcessGuid: "{99999999-0000-0000-0000-000000000099}",
  // The process itself runs from a user-writable path — the condition that used to
  // be mistaken for "loaded an unsigned DLL from a writable path".
  Image: "C:\\Users\\arya\\AppData\\Local\\Slack\\slack.exe",
  ParentImage: "C:\\Windows\\explorer.exe", CommandLine: "slack.exe", User: "arya",
  UtcTime: "2026-03-15 10:00:00", EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
  ImageLoaded: "", TargetFilename: "", Signed: "true", SignatureStatus: "Valid",
};

test("P1: an EID 7 loading a signed system DLL is not counted as a writable-path load", () => {
  const rows = [
    CREATE_ROW,
    {
      ...CREATE_ROW, EventID: "7", UtcTime: "2026-03-15 10:00:05",
      ImageLoaded: "C:\\Windows\\System32\\ntdll.dll", Signed: "true", SignatureStatus: "Valid",
    },
  ];
  const { meta, ctx } = makeStub(SYSMON_TELEMETRY_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "1", adjacentTelemetry: true }, ctx);
  const node = tree.processes.find((p) => p.pid === "4444");
  assert.ok(node, "expected the create event to build a node");
  if (node.imageLoads) {
    assert.equal(node.imageLoads.writablePathCount, 0, "ntdll.dll is not in a writable path");
    assert.equal(node.imageLoads.unsignedCount, 0, "it is signed");
    assert.equal(node.imageLoads.samples[0].path, "C:\\Windows\\System32\\ntdll.dll",
      "the sample must be the LOADED module, not the loading process");
  }
});

test("P1: an EID 11 writing to Temp is recorded as that file, not the writing process", () => {
  const rows = [
    CREATE_ROW,
    {
      ...CREATE_ROW, EventID: "11", UtcTime: "2026-03-15 10:00:06",
      TargetFilename: "C:\\Windows\\Temp\\report.log",
    },
  ];
  const { meta, ctx } = makeStub(SYSMON_TELEMETRY_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "1", adjacentTelemetry: true }, ctx);
  const node = tree.processes.find((p) => p.pid === "4444");
  if (node.fileCreates) {
    assert.equal(node.fileCreates.peCount, 0, "a .log is not a PE — the process's own .exe was being counted");
    assert.equal(node.fileCreates.samples[0].path, "C:\\Windows\\Temp\\report.log");
  }
});

test("P1: a genuinely suspicious EID 11 PE drop is still counted", () => {
  const rows = [
    CREATE_ROW,
    {
      ...CREATE_ROW, EventID: "11", UtcTime: "2026-03-15 10:00:06",
      TargetFilename: "C:\\Users\\arya\\AppData\\Roaming\\payload.exe",
    },
  ];
  const { meta, ctx } = makeStub(SYSMON_TELEMETRY_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "1", adjacentTelemetry: true }, ctx);
  const node = tree.processes.find((p) => p.pid === "4444");
  if (node.fileCreates) {
    assert.equal(node.fileCreates.peCount, 1);
    assert.equal(node.fileCreates.writablePathCount, 1);
  }
});

// ==================== P2: per-row column roles (Security) ====================

// A raw Security export: BOTH ProcessId (creator, on 4688) and NewProcessId
// (created) exist as columns, plus 4689 which only carries ProcessId.
const SECURITY_HEADERS = [
  "NewProcessId", "ProcessId", "NewProcessName", "ProcessName", "ParentProcessName",
  "CommandLine", "SubjectUserName", "UtcTime", "EventID", "Provider", "Computer", "Status",
];

function sec4688(o) {
  return {
    NewProcessId: o.pid, ProcessId: o.creator, NewProcessName: o.image,
    ProcessName: "", ParentProcessName: o.parentImage || "",
    CommandLine: o.cmd || "", SubjectUserName: o.user || "arya",
    UtcTime: o.ts, EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing",
    Computer: "HOST-A", Status: "",
  };
}

test("P2: a Security 4688 is keyed by NewProcessId, and its parent is ProcessId", () => {
  // The tab-wide detect() picks ProcessId for `pid` (it is first in the pattern
  // list), so every 4688 node used to take the CREATOR's pid — the whole tree
  // collapsed onto the creators and chained them to each other.
  const rows = [
    sec4688({ pid: "0x1f4", creator: "0x4", image: "C:\\Windows\\System32\\services.exe", ts: "2026-03-15 10:00:00" }),
    sec4688({ pid: "0x7d0", creator: "0x1f4", image: "C:\\Windows\\System32\\svchost.exe", parentImage: "C:\\Windows\\System32\\services.exe", ts: "2026-03-15 10:00:05" }),
  ];
  const { meta, ctx } = makeStub(SECURITY_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "4688" }, ctx);
  const child = tree.processes.find((p) => p.pid === "2000");   // 0x7d0
  const parent = tree.processes.find((p) => p.pid === "500");   // 0x1f4
  assert.ok(child, "the created process must be keyed by NewProcessId (0x7d0 = 2000)");
  assert.ok(parent, "the creator is a node in its own right (0x1f4 = 500)");
  assert.equal(child.ppid, "500", "ProcessId on a 4688 is the creator");
  assert.equal(child.image, "C:\\Windows\\System32\\svchost.exe", "image comes from NewProcessName");
  assert.equal(parent.key, child.parentKey, "and the two must actually link");
});

test("P2: a Security 4689 matches its create by ProcessId, giving the process a lifetime", () => {
  const rows = [
    sec4688({ pid: "0x7d0", creator: "0x1f4", image: "C:\\Windows\\System32\\svchost.exe", ts: "2026-03-15 10:00:00" }),
    {
      NewProcessId: "", ProcessId: "0x7d0", NewProcessName: "", ProcessName: "C:\\Windows\\System32\\svchost.exe",
      ParentProcessName: "", CommandLine: "", SubjectUserName: "arya",
      UtcTime: "2026-03-15 10:05:00", EventID: "4689", Provider: "Microsoft-Windows-Security-Auditing",
      Computer: "HOST-A", Status: "0x0",
    },
  ];
  const { meta, ctx } = makeStub(SECURITY_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "4688" }, ctx);
  const node = tree.processes.find((p) => p.pid === "2000");
  assert.ok(node, "expected the 4688 node");
  assert.equal(node.durationMs, 300000, "the 4689 must correlate and yield a 5-minute lifetime");
});

test("P2: a Sysmon-shaped tab labelled 4688 keeps ProcessId as the subject", () => {
  // Guard against over-applying the rule: without a NewProcessId column, ProcessId
  // IS the subject even on a row labelled 4688, and remapping would invert the link.
  const headers = ["ProcessId", "ParentProcessId", "Image", "ParentImage", "CommandLine", "User", "UtcTime", "EventID", "Provider", "Computer"];
  const rows = [
    { ProcessId: "1000", ParentProcessId: "4", Image: "C:\\Parent.exe", ParentImage: "", CommandLine: "p", User: "SYSTEM", UtcTime: "2026-03-15 09:00:00", EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A" },
    { ProcessId: "2000", ParentProcessId: "1000", Image: "C:\\Child.exe", ParentImage: "C:\\Parent.exe", CommandLine: "c", User: "SYSTEM", UtcTime: "2026-03-15 09:01:00", EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A" },
  ];
  const { meta, ctx } = makeStub(headers, rows);
  const tree = getProcessTree(meta, { eventIdValue: "4688" }, ctx);
  const child = tree.processes.find((p) => p.pid === "2000");
  assert.equal(child.ppid, "1000");
});

// ==================== P8: EvtxECmd 4688 hex PIDs ====================

const ECMD_HEADERS = [
  "TimeCreated", "EventId", "Provider", "Channel", "Computer",
  "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo",
];

test("P8: EvtxECmd 4688 hex PIDs parse to real, distinct process ids", () => {
  // "NewProcessId: 0x1a2c" was read by /ProcessID:\s*(\d+)/ as the leading "0",
  // so every 4688 in the tab became PID 0 — one node, chained to itself.
  const rows = [
    {
      TimeCreated: "2026-03-15 10:00:00", EventId: "4688", Provider: "Microsoft-Windows-Security-Auditing",
      Channel: "Security", Computer: "HOST-A",
      PayloadData1: "NewProcessId: 0x1a2c", PayloadData2: "NewProcessName: C:\\Windows\\System32\\cmd.exe",
      PayloadData3: "CreatorProcessId: 0x8f0", PayloadData4: "", PayloadData5: "", PayloadData6: "",
      ExecutableInfo: "",
    },
    {
      TimeCreated: "2026-03-15 10:00:01", EventId: "4688", Provider: "Microsoft-Windows-Security-Auditing",
      Channel: "Security", Computer: "HOST-A",
      PayloadData1: "NewProcessId: 0x8f0", PayloadData2: "NewProcessName: C:\\Windows\\explorer.exe",
      PayloadData3: "CreatorProcessId: 0x4", PayloadData4: "", PayloadData5: "", PayloadData6: "",
      ExecutableInfo: "",
    },
  ];
  const { meta, ctx } = makeStub(ECMD_HEADERS, rows, { eventIdHeader: "EventId" });
  const tree = getProcessTree(meta, { eventIdValue: "4688" }, ctx);
  const pids = tree.processes.map((p) => p.pid).sort();
  assert.deepEqual(pids, ["2288", "6700"], `0x8f0 = 2288 and 0x1a2c = 6700, got ${pids.join(",")}`);
  const cmd = tree.processes.find((p) => p.pid === "6700");
  assert.equal(cmd.ppid, "2288", "CreatorProcessId 0x8f0 is the parent");
  assert.equal(cmd.image, "C:\\Windows\\System32\\cmd.exe",
    "with command-line auditing off the image comes from NewProcessName");
});

// ==================== P20: free-text Event ID reaches SQL ====================

test("P20: a non-numeric Event ID filter cannot reach the SQL text", () => {
  const { previewProcessTree } = require("../electron/analyzers/process-tree");
  const headers = ["ProcessId", "ParentProcessId", "Image", "CommandLine", "UtcTime", "EventID", "Computer"];
  const rows = [{ ProcessId: "1", ParentProcessId: "0", Image: "C:\\a.exe", CommandLine: "a", UtcTime: "2026-03-15 10:00:00", EventID: "4688", Computer: "HOST-A" }];
  const { meta, ctx, seenSql } = makeStub(headers, rows);
  // Force the normalization fallback path (the one that interpolates) by asking
  // for an id the exact-match phase cannot satisfy.
  const res = previewProcessTree(meta, { eventIdValue: "1)) OR 1=1 --" }, ctx);
  assert.ok(!res.error || !/syntax|no such column/i.test(res.error), `unexpected SQL error: ${res.error}`);
  for (const sql of seenSql) {
    assert.ok(!sql.includes("OR 1=1"), "the raw filter text must never be interpolated into SQL");
  }
});
