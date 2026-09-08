// Two silent field-mapping failures in the process/service scan:
//
//  1. Hayabusa has no Image/ParentImage columns, so the scan falls back to the Details
//     and ExtraFieldInfo blobs. Because those fallbacks made `_parent`/`_image` non-null,
//     every detector took the STRUCTURED branch and compared a whole blob against
//     "wmiprvse.exe" / "wsmprovhost.exe" / "sshd.exe" — which never matches. The
//     correctly-written blob fallbacks sat in an unreachable `else`, so dest-side WMI,
//     dest-side WinRM, DCOM and sshd->shell detection were all dead on Hayabusa data.
//
//  2. Sysmon 19/20/21 (WMI subscription) collide with TerminalServices
//     LocalSessionManager 20/21 (session reconnect / logon). With no channel column the
//     channel pre-filter is empty, so RDP session events were reported as
//     "WMI Event Subscription".

const test = require("node:test");
const assert = require("node:assert/strict");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");

function makeStub(headers, rows, { hayabusa = false } = {}) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const rowsByCN = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    headers.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return out;
  });

  function scanRows(sql, args) {
    if (!/data\.rowid\s+as\s+_rid/i.test(sql) || !/\bas\s+_alltext/i.test(sql)) return null;
    const plainAliasMatches = [...sql.matchAll(/(c\d+)\s+as\s+(_[a-zA-Z0-9_]+)/g)];
    const aliasToCol = {};
    for (const [, col, alias] of plainAliasMatches) aliasToCol[alias] = col;
    const bound = Array.isArray(args) ? args : [];
    const lastRid = Number(bound[bound.length - 1] || 0);
    const eids = new Set(bound.slice(0, -1).map((v) => String(v)));
    const limitMatch = sql.match(/\bLIMIT\s+(\d+)/i);
    const limit = limitMatch ? Number(limitMatch[1]) : rowsByCN.length;
    const eventCol = aliasToCol._eid || colMap.EventID || colMap.EventId;
    return rowsByCN
      .filter((r) => r._rowid > lastRid)
      .filter((r) => !eventCol || eids.size === 0 || eids.has(String(r[eventCol] || "")))
      .slice(0, limit)
      .map((r) => {
        const out = {
          _rid: r._rowid,
          _alltext: Object.keys(r).filter((k) => k !== "_rowid").map((k) => r[k]).filter((v) => v != null).join("|"),
        };
        for (const [alias, col] of Object.entries(aliasToCol)) out[alias] = r[col];
        return out;
      });
  }

  const db = {
    prepare(sql) {
      return {
        get() { if (/COUNT\(\*\)/i.test(sql)) return { cnt: rowsByCN.length || 1 }; return null; },
        all(...args) {
          const scanned = scanRows(sql, args);
          if (scanned) return scanned;
          if (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql)) {
            const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
            return rowsByCN.map((r) => {
              const out = { _rowid: r._rowid };
              for (const [, idx, alias] of aliasMatches) out[alias] = r[`c${idx}`];
              return out;
            });
          }
          return [];
        },
      };
    },
  };

  return {
    meta: { db, headers, colMap, tabId: "lm-field-mapping-test" },
    ctx: {
      applyStandardFilters() {},
      ensureIndex() {},
      isChainsawLogonDataset: () => false,
      isHayabusaDataset: () => hayabusa,
    },
  };
}

// ── 1. Hayabusa blob fallback ────────────────────────────────────────────────────
// Hayabusa's shape: no Image/ParentImage, everything in Details / ExtraFieldInfo.
const HAYA_HEADERS = [
  "Timestamp", "RuleTitle", "Computer", "Channel", "EventID", "Level",
  "Details", "ExtraFieldInfo",
];

function hayaRow(eid, details, extra = "") {
  return {
    Timestamp: "2026-03-10 08:00:00.000",
    RuleTitle: "Proc Exec",
    Computer: "SRV-APP01",
    Channel: "Sec",
    EventID: eid,
    Level: "high",
    Details: details,
    ExtraFieldInfo: extra,
  };
}

test("Hayabusa: dest-side WMI execution is detected via the blob fallback", () => {
  const { meta, ctx } = makeStub(HAYA_HEADERS, [
    hayaRow("1", 'Proc: C:\\Windows\\System32\\cmd.exe ¦ Parent: C:\\Windows\\System32\\wbem\\wmiprvse.exe ¦ CmdLine: cmd.exe /c whoami', "User: CORP\\svc"),
  ], { hayabusa: true });

  const res = getLateralMovement(meta, { syntheticTargetHost: "SRV-APP01" }, ctx);
  assert.ok(!res.error, `analyzer errored: ${res.error}`);
  assert.ok(
    res.findings.some((f) => /wmi/i.test(f.category)),
    `expected a WMI finding from the blob fallback, got ${JSON.stringify(res.findings.map((f) => f.category))}`,
  );
});

test("Hayabusa: dest-side WinRM execution is detected via the blob fallback", () => {
  const { meta, ctx } = makeStub(HAYA_HEADERS, [
    hayaRow("1", 'Proc: C:\\Windows\\System32\\cmd.exe ¦ Parent: C:\\Windows\\System32\\wsmprovhost.exe ¦ CmdLine: cmd.exe /c ipconfig', "User: CORP\\svc"),
  ], { hayabusa: true });

  const res = getLateralMovement(meta, { syntheticTargetHost: "SRV-APP01" }, ctx);
  assert.ok(!res.error, `analyzer errored: ${res.error}`);
  assert.ok(
    res.findings.some((f) => /winrm/i.test(f.category)),
    `expected a WinRM finding from the blob fallback, got ${JSON.stringify(res.findings.map((f) => f.category))}`,
  );
});

test("structured data still takes the structured path (no regression)", () => {
  const STRUCT_HEADERS = [
    "TimeCreated", "EventId", "Computer", "IpAddress", "TargetUserName", "LogonType",
    "Channel", "Provider", "Image", "ParentImage", "CommandLine",
  ];
  const { meta, ctx } = makeStub(STRUCT_HEADERS, [
    {
      TimeCreated: "2026-03-10T08:00:00Z", EventId: "1", Computer: "SRV-APP01",
      IpAddress: "10.0.0.5", TargetUserName: "CORP\\svc", LogonType: "3",
      Channel: "Microsoft-Windows-Sysmon/Operational", Provider: "Sysmon",
      Image: "C:\\Windows\\System32\\cmd.exe",
      ParentImage: "C:\\Windows\\System32\\wbem\\wmiprvse.exe",
      CommandLine: "cmd.exe /c whoami",
    },
  ]);
  const res = getLateralMovement(meta, {}, ctx);
  assert.ok(!res.error, `analyzer errored: ${res.error}`);
  assert.ok(
    res.findings.some((f) => /wmi/i.test(f.category)),
    `structured WMI detection regressed, got ${JSON.stringify(res.findings.map((f) => f.category))}`,
  );
});

// ── 2. Sysmon 19/20/21 vs TerminalServices 20/21 collision ───────────────────────

// MapDescription is one of the columns the scan actually selects into _alltext. Without
// at least one such column the scan never runs at all, which would make the negative
// case below pass vacuously.
const NOCHAN_HEADERS = [
  "TimeCreated", "EventId", "Computer", "IpAddress", "TargetUserName", "LogonType", "MapDescription",
];

test("channel-less TerminalServices 20/21 rows are not reported as WMI subscriptions", () => {
  // A generic CSV export with no Channel/Provider column, holding RDP session events.
  // EIDs 20/21 here mean "session reconnect" / "session logon", not Sysmon WMI.
  const rows = [
    { TimeCreated: "2026-03-10T08:00:00Z", EventId: "21", Computer: "WKS01", IpAddress: "10.0.0.5", TargetUserName: "CORP\\alice", LogonType: "10", MapDescription: "Remote Desktop Services: Session logon succeeded" },
    // EID 20 is here precisely because it COLLIDES with Sysmon 20 (WmiEventConsumer);
    // that collision is what the test is about. It is not the LSM shell-start event
    // (that is 22) — the fixture used to mislabel it as such.
    { TimeCreated: "2026-03-10T08:05:00Z", EventId: "20", Computer: "WKS01", IpAddress: "10.0.0.5", TargetUserName: "CORP\\alice", LogonType: "10", MapDescription: "Remote Desktop Services: session event" },
  ];
  const { meta, ctx } = makeStub(NOCHAN_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);

  assert.ok(!res.error, `analyzer errored: ${res.error}`);
  // Guard against a vacuous pass: the scan must actually have looked at these rows.
  assert.ok(res.scanStats && res.scanStats.wmisub > 0, `the wmisub family should have fetched these rows, scanStats=${JSON.stringify(res.scanStats)}`);
  assert.equal(
    res.findings.filter((f) => /wmi event subscription/i.test(f.category)).length, 0,
    `RDP session events must not surface as WMI subscriptions, got ${JSON.stringify(res.findings.map((f) => f.category))}`,
  );
});

test("a genuine WMI subscription is still detected without a channel column", () => {
  // Same missing-channel situation, but the row itself is unmistakably WMI.
  const rows = [
    {
      TimeCreated: "2026-03-10T08:00:00Z", EventId: "21", Computer: "WKS01",
      IpAddress: "10.0.0.5", TargetUserName: "CORP\\alice", LogonType: "3",
      MapDescription: "WmiEventConsumerToFilter activity detected: Consumer=CommandLineEventConsumer Destination=powershell.exe -enc SQBFAFgA",
    },
  ];
  const { meta, ctx } = makeStub(NOCHAN_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);

  assert.ok(!res.error, `analyzer errored: ${res.error}`);
  assert.ok(
    res.findings.some((f) => /wmi event subscription/i.test(f.category)),
    `a real WMI binding should still fire, got ${JSON.stringify(res.findings.map((f) => f.category))}`,
  );
});
