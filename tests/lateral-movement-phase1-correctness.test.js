// Phase 1 correctness regressions for the lateral-movement analyzer.
//
// Each test here pins a defect that produced WRONG output on real data (as opposed
// to a tuning/false-positive question). They are grouped by the audit IDs:
//
//   L1  Sysmon 20-25 parsed as TerminalServices 20-25 on consolidated exports
//   L2  merged multi-source rows ordered lexically, so "T" and " " forms interleave
//   L3  first-seen threshold compared a toISOString() value to a naive column
//   L6  4625 read SubStatus only, so Status-only failures had no reason code
//   L7  raw-EVTX 4776 never set the user
//   L8  4778/4779 user is AccountName, and ClientName "-" discarded the event

const test = require("node:test");
const assert = require("node:assert/strict");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");
const { termSvcChannelGuard } = require("../electron/analyzers/lateral-movement/sql-guards");
const { tsMs, cmpTs, earlierTs, laterTs, gapMs } = require("../electron/analyzers/lateral-movement/time");
const { resolveEventChannel } = require("../electron/analyzers/evtx-utils");

const SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational";
const LSM_CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

function makeStub(headers, rows, tabId = "lm-phase1-test") {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });

  const rowsByCN = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    headers.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return out;
  });

  function aliasRows(sql) {
    const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    return rowsByCN.map((r) => {
      const out = { _rowid: r._rowid };
      for (const [, idx, alias] of aliasMatches) out[alias] = r[`c${idx}`];
      return out;
    });
  }

  const db = {
    prepare(sql) {
      return {
        get() { if (/COUNT\(\*\)/i.test(sql)) return { cnt: rowsByCN.length || 1 }; return null; },
        all() {
          if (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql)) return aliasRows(sql);
          return [];
        },
      };
    },
  };

  const meta = { db, headers, colMap, tabId };
  const ctx = {
    applyStandardFilters() {},
    ensureIndex() {},
    isChainsawLogonDataset: () => false,
    isHayabusaDataset: () => false,
  };
  return { meta, ctx };
}

// --- Consolidated EvtxECmd CSV: every channel lands in the same columns. -------
const ECMD_HEADERS = [
  "TimeCreated", "EventId", "Channel", "Provider", "Computer", "UserName", "RemoteHost",
  "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "ExecutableInfo",
];

function ecmdRow(o) {
  return {
    TimeCreated: o.ts || "2026-03-10 08:00:00",
    EventId: o.eid,
    Channel: o.channel,
    Provider: o.provider || "",
    Computer: o.computer || "SRV-FILE01",
    UserName: o.userName || "",
    RemoteHost: o.remoteHost || "",
    PayloadData1: o.pd1 || "",
    PayloadData2: o.pd2 || "",
    PayloadData3: o.pd3 || "",
    PayloadData4: o.pd4 || "",
    PayloadData5: o.pd5 || "",
    ExecutableInfo: "",
  };
}

// ============================ L1: channel gate ================================

test("L1: Sysmon 22/23 on a consolidated export do not fabricate an RDP session", () => {
  // Sysmon 22 = DNS query, 23 = file delete. Both carry a Computer and a user, and
  // both share their EventID with TerminalServices shell-start / session-logoff.
  const rows = [
    ecmdRow({ eid: "22", channel: SYSMON_CHANNEL, ts: "2026-03-10 08:00:00", userName: "SEVENKINGDOMS\\arya.stark (S-1-5-21-1-2-3)", pd1: "QueryName: telemetry.example.com", pd3: "Image: C:\\Windows\\System32\\svchost.exe" }),
    ecmdRow({ eid: "23", channel: SYSMON_CHANNEL, ts: "2026-03-10 08:05:00", userName: "SEVENKINGDOMS\\arya.stark (S-1-5-21-1-2-3)", pd1: "TargetFilename: C:\\Temp\\a.tmp", pd3: "Image: C:\\Windows\\System32\\svchost.exe" }),
  ];
  const { meta, ctx } = makeStub(ECMD_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);
  assert.equal(res.rdpSessions.length, 0, "Sysmon rows must not produce RDP sessions");
});

test("L1: Sysmon 22 does not make the coverage panel claim RDP telemetry exists", () => {
  // The telemetry bump used to run before any channel check, so a tab of Sysmon DNS
  // queries reported "RDP session" coverage on every host and suppressed the
  // "no RDP events" warning — the analyst was told reconstruction was possible when
  // the RDP channel had never been collected.
  const rows = [
    ecmdRow({ eid: "22", channel: SYSMON_CHANNEL, ts: "2026-03-10 08:00:00", userName: "SEVENKINGDOMS\\arya.stark (S-1-5-21-1-2-3)", pd1: "QueryName: telemetry.example.com" }),
    ecmdRow({ eid: "4624", channel: "Security", ts: "2026-03-10 08:01:00", remoteHost: "WKS-042 (10.10.10.55)", pd1: "Target: SEVENKINGDOMS\\arya.stark", pd2: "LogonType 3" }),
  ];
  const { meta, ctx } = makeStub(ECMD_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);
  const counts = res.coverage.datasetEventCounts || {};
  assert.equal(counts["22"] || 0, 0, "a Sysmon DNS query is not a TerminalServices shell start");
  assert.ok(
    res.coverage.warnings.some((w) => w.category === "rdp"),
    "with no real RDP events the 'no RDP events' warning must still be raised",
  );
});

test("L1: a real TerminalServices 21/23 pair still reconstructs a session", () => {
  // The gate must not be over-broad: the same IDs on the LSM channel are genuine.
  const rows = [
    ecmdRow({ eid: "21", channel: LSM_CHANNEL, ts: "2026-03-10 09:00:00", pd1: "User: SEVENKINGDOMS\\arya.stark", pd2: "Session ID: 3", pd3: "Source Network Address: 10.10.10.55" }),
    ecmdRow({ eid: "23", channel: LSM_CHANNEL, ts: "2026-03-10 09:30:00", pd1: "User: SEVENKINGDOMS\\arya.stark", pd2: "Session ID: 3", pd3: "Source Network Address: 10.10.10.55" }),
  ];
  const { meta, ctx } = makeStub(ECMD_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);
  assert.ok(res.rdpSessions.length >= 1, "LSM 21/23 on the TerminalServices channel is a real session");
});

test("L1: rows with no channel information at all are still parsed (raw single-channel evtx)", () => {
  // No Channel and no Provider column at all — the heuristic in resolveEventChannel
  // is the only thing that can classify these, and it must not cause a drop.
  const headers = ["datetime", "EventID", "Computer", "TargetUserName", "IpAddress", "LogonType"];
  const rows = [
    { datetime: "2026-03-10 09:00:00", EventID: "21", Computer: "SRV-FILE01", TargetUserName: "arya.stark", IpAddress: "10.10.10.55", LogonType: "" },
    { datetime: "2026-03-10 09:30:00", EventID: "23", Computer: "SRV-FILE01", TargetUserName: "arya.stark", IpAddress: "10.10.10.55", LogonType: "" },
  ];
  const { meta, ctx } = makeStub(headers, rows);
  const res = getLateralMovement(meta, {}, ctx);
  assert.ok(res.rdpSessions.length >= 1, "no channel column means the small ID is unambiguous");
});

test("L1: the SQL guard only fires when ambiguous IDs are actually requested", () => {
  assert.equal(termSvcChannelGuard("c1", "c2", ["4624", "4625"]), null);
  assert.equal(termSvcChannelGuard("c1", null, ["22"]), null, "no channel column means no guard");
  const g = termSvcChannelGuard("c1", "c2", ["4624", "22", "23"]);
  assert.ok(g.sql.includes("NOT (c1 IN (?,?)"));
  assert.deepEqual(g.params.slice(0, 2), ["22", "23"]);
  assert.ok(g.params.includes("%localsessionmanager%"));
  assert.ok(g.sql.includes("TRIM(c2) <> ''"), "an empty channel must not be filtered out");
});

test("L1: Hayabusa's RDS-LSM / RDS-RCM channel codes resolve to TerminalServices", () => {
  assert.equal(resolveEventChannel({ _channel: "RDS-LSM" }), "localsessionmanager");
  assert.equal(resolveEventChannel({ _channel: "RDS-RCM" }), "remoteconnectionmanager");
  assert.equal(resolveEventChannel({ _channel: "Sysmon" }), "sysmon");
});

// ============================ L2 / L3 / L17: time =============================

test("L2: a space-separated and a T-separated timestamp compare chronologically", () => {
  // The bug in one line: "2026-01-02 09:00:00" > "2026-01-02T08:00:00Z" is FALSE
  // lexically (0x20 < 'T') even though 09:00 is later.
  assert.ok("2026-01-02 09:00:00" < "2026-01-02T08:00:00Z", "precondition: lexical order is wrong");
  assert.ok(cmpTs("2026-01-02 09:00:00", "2026-01-02T08:00:00Z") > 0);
  assert.ok(cmpTs("2026-01-02 07:00:00", "2026-01-02T08:00:00Z") < 0);
  assert.equal(cmpTs("2026-01-02 08:00:00", "2026-01-02T08:00:00Z"), 0);
});

test("L2: merging two formats sorts by instant, not by format", () => {
  const merged = [
    { ts: "2026-01-02T09:30:00Z", tab: "raw" },
    { ts: "2026-01-02 08:00:00", tab: "ecmd" },
    { ts: "2026-01-02T07:00:00Z", tab: "raw" },
    { ts: "2026-01-02 10:00:00", tab: "ecmd" },
  ];
  merged.sort((a, b) => cmpTs(a.ts, b.ts));
  assert.deepEqual(merged.map((r) => r.tab), ["raw", "ecmd", "raw", "ecmd"]);
});

test("L2: unparseable timestamps sort after every parseable one", () => {
  const arr = ["", "2026-01-02 08:00:00", "n/a", "2026-01-01 08:00:00"];
  arr.sort(cmpTs);
  assert.deepEqual(arr.slice(0, 2), ["2026-01-01 08:00:00", "2026-01-02 08:00:00"]);
});

test("L2: earlierTs / laterTs keep the original rendering and ignore lexical order", () => {
  assert.equal(earlierTs("2026-01-02 09:00:00", "2026-01-02T08:00:00Z"), "2026-01-02T08:00:00Z");
  assert.equal(laterTs("2026-01-02 09:00:00", "2026-01-02T08:00:00Z"), "2026-01-02 09:00:00");
  assert.equal(earlierTs(null, "2026-01-02 09:00:00"), "2026-01-02 09:00:00");
});

test("L17: gaps are measured in UTC regardless of the analyst's timezone", () => {
  // normalizeTimestamp anchors naive values to UTC, so this is 5 minutes anywhere.
  assert.equal(gapMs("2026-03-10 08:00:00", "2026-03-10T08:05:00Z"), 300000);
  // Across a US DST boundary a host-local parse loses/gains an hour; UTC does not.
  assert.equal(gapMs("2026-03-08 01:30:00", "2026-03-08 03:30:00"), 7200000);
  assert.equal(tsMs("1601-01-01 00:00:00"), null, "unset FILETIME is not a real time");
});

test("L3: a late edge on the same day is not flagged 'first seen'", () => {
  // The threshold used to be built with toISOString() ("2026-03-10T08:07:12.000Z")
  // and compared lexically against the naive column ("2026-03-10 20:00:00"). A space
  // sorts before "T", so EVERY edge sharing a calendar day with the dataset minimum
  // satisfied `<=` and was flagged as a brand-new relationship — which then fed edge
  // risk scoring, chain confidence and the First Seen finding.
  const headers = ["datetime", "EventID", "Computer", "IpAddress", "TargetUserName", "LogonType", "Channel"];
  const mk = (ts, computer) => ({
    datetime: ts, EventID: "4624", Computer: computer, IpAddress: "10.10.10.50",
    TargetUserName: "jon.snow", LogonType: "3", Channel: "Security",
  });
  // One source, two targets. The per-source rule ("this source's earliest edge") is
  // satisfied only by the 08:00 edge, so the 20:00 edge is decided purely by the
  // time threshold.
  const rows = [
    mk("2026-03-10 08:00:00", "SRV-FILE01"),
    mk("2026-03-10 08:10:00", "SRV-FILE01"),
    mk("2026-03-10 20:00:00", "SRV-APP01"),
  ];
  const { meta, ctx } = makeStub(headers, rows);
  const res = getLateralMovement(meta, {}, ctx);
  const early = res.edges.find((e) => e.target === "SRV-FILE01");
  const late = res.edges.find((e) => e.target === "SRV-APP01");
  assert.ok(early && late, "expected both edges");
  assert.equal(early.isFirstSeen, true, "the source's earliest edge is genuinely first-seen");
  assert.equal(late.isFirstSeen, false, "12 hours into the range is not the first 1% of it");
});

// ============================ L6: 4625 Status ================================

const SEC_HEADERS = [
  "datetime", "EventID", "Provider", "Channel", "Computer", "IpAddress",
  "TargetUserName", "LogonType", "SubStatus", "Status",
];

function failRow(o) {
  return {
    datetime: o.ts,
    EventID: "4625",
    Provider: "Microsoft-Windows-Security-Auditing",
    Channel: "Security",
    Computer: "DC01",
    IpAddress: o.ip || "10.10.10.55",
    TargetUserName: o.user || "arya.stark",
    LogonType: o.logonType || "3",
    SubStatus: o.subStatus != null ? o.subStatus : "0x0",
    Status: o.status != null ? o.status : "0xC000006D",
  };
}

test("L6: a lockout storm written in Status (SubStatus 0x0) is dampened, not high", () => {
  // Windows puts the reason in Status and leaves SubStatus at 0x0 for locked,
  // disabled, expired and restricted accounts — exactly the benign bursts the
  // dampener exists for. Reading SubStatus alone scored them as brute force.
  const rows = [];
  for (let i = 0; i < 8; i++) {
    rows.push(failRow({ ts: `2026-03-10 08:0${i}:00`, subStatus: "0x0", status: "0xC0000234" }));
  }
  const { meta, ctx } = makeStub(SEC_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);
  const bf = res.findings.filter((f) => f.category === "Brute Force");
  assert.ok(bf.length > 0, "still reported, just not as a high-severity attack");
  for (const f of bf) {
    assert.notEqual(f.severity, "high", "an account-locked burst is not high-severity brute force");
    assert.ok(/account locked/i.test(f.description), `reason should be resolved: ${f.description}`);
  }
});

test("L6: a real bad-password burst in SubStatus is still scored high", () => {
  const rows = [];
  for (let i = 0; i < 8; i++) {
    rows.push(failRow({ ts: `2026-03-10 08:0${i}:00`, subStatus: "0xC000006A", status: "0xC000006D" }));
  }
  const { meta, ctx } = makeStub(SEC_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);
  const bf = res.findings.filter((f) => f.category === "Brute Force");
  assert.ok(bf.some((f) => f.severity === "high"), "bad-password bursts stay high");
});

// ============================ L7: raw 4776 user ==============================

test("L7: raw-EVTX 4776 attributes the NTLM authentication to its account", () => {
  const headers = ["datetime", "EventID", "Provider", "Channel", "Computer", "TargetUserName", "WorkstationName"];
  const rows = [
    { datetime: "2026-03-10 08:00:00", EventID: "4776", Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", Computer: "DC01", TargetUserName: "arya.stark", WorkstationName: "WKS-042" },
    { datetime: "2026-03-10 08:00:05", EventID: "4624", Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", Computer: "DC01", TargetUserName: "arya.stark", WorkstationName: "WKS-042" },
  ];
  const { meta, ctx } = makeStub(headers, rows);
  const res = getLateralMovement(meta, {}, ctx);
  const acct = (res.accounts || []).find((a) => /arya\.stark/i.test(a.user || ""));
  assert.ok(acct, "the 4776 account must appear in the accounts aggregation");
  assert.ok(acct.ntlmCountRaw >= 1, `expected the 4776 to be attributed to the user, got ${acct.ntlmCountRaw}`);
  assert.ok(acct.flags.includes("NTLM only (no Kerberos)"), "NTLM-only scoring depends on that attribution");
});

// ============================ L8: 4778 / 4779 ================================

const RECONNECT_HEADERS = [
  "datetime", "EventID", "Provider", "Channel", "Computer",
  "AccountName", "ClientName", "ClientAddress", "TargetUserName", "IpAddress", "LogonType",
];

test("L8: a 4778 with ClientName '-' still resolves its source from ClientAddress", () => {
  // NLA and non-Windows clients send no ClientName; Windows writes "-". That was
  // taken as a hostname, failed the excluded-endpoint check, and dropped the event
  // together with its perfectly good ClientAddress.
  const rows = [
    {
      datetime: "2026-03-10 08:00:00", EventID: "4778", Provider: "Microsoft-Windows-Security-Auditing",
      Channel: "Security", Computer: "SRV-FILE01", AccountName: "arya.stark",
      ClientName: "-", ClientAddress: "10.10.10.55", TargetUserName: "", IpAddress: "", LogonType: "",
    },
  ];
  const { meta, ctx } = makeStub(RECONNECT_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);
  const evt = (res.rdpSessions || []).flatMap((s) => s.events || []).find((e) => e.eventId === "4778");
  const node = res.nodes.find((n) => n.id === "10.10.10.55");
  assert.ok(evt || node, "the reconnect must survive with 10.10.10.55 as its source");
});

test("L8: 4778 reads the user from AccountName on a tab that also holds 4624s", () => {
  // detect() maps `user` to TargetUserName for the whole tab, which a 4778 does not
  // carry — so without the dedicated AccountName column every reconnect was userless.
  const rows = [
    {
      datetime: "2026-03-10 08:00:00", EventID: "4624", Provider: "Microsoft-Windows-Security-Auditing",
      Channel: "Security", Computer: "SRV-FILE01", AccountName: "", ClientName: "", ClientAddress: "",
      TargetUserName: "arya.stark", IpAddress: "10.10.10.55", LogonType: "10",
    },
    {
      datetime: "2026-03-10 08:30:00", EventID: "4778", Provider: "Microsoft-Windows-Security-Auditing",
      Channel: "Security", Computer: "SRV-FILE01", AccountName: "arya.stark",
      ClientName: "WKS-042", ClientAddress: "10.10.10.55", TargetUserName: "", IpAddress: "", LogonType: "",
    },
  ];
  const { meta, ctx } = makeStub(RECONNECT_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);
  const reconnect = (res.rdpSessions || [])
    .flatMap((s) => (s.events || []).map((e) => ({ ...e, sessionUser: s.user })))
    .find((e) => e.eventId === "4778");
  assert.ok(reconnect, "the 4778 must be correlated into a session");
  assert.match(String(reconnect.user || reconnect.sessionUser || ""), /arya\.stark/i);
});
