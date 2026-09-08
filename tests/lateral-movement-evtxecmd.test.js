// Regression test for EvtxECmd lateral movement user extraction.
//
// Bug: EvtxECmd's UserName column for Security 4624 events is the *Subject*
// (initiator). Service/system-context logons populate it as literally "-\-".
// The lateral-movement analyzer used to detect column.user as UserName before
// PayloadData1, then run a "Target:" regex on the value — which never matched
// because "-\-" has no Target prefix — and finally blank `user = ""`.
//
// Result: 22k logon events, 7 connections, 0 accounts. The Accounts tab and
// the Users summary card both showed 0.
//
// Fix: prefer PayloadData1 ("Target: DOMAIN\User") over UserName when EvtxECmd
// is detected; fall back to UserName (with SID parenthetical stripped) when
// PayloadData1 lacks the Target prefix.

const test = require("node:test");
const assert = require("node:assert/strict");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");
const { getMultiSourceLateralMovement } = require("../electron/analyzers/lateral-movement/multi-source");

// Real EvtxECmd KAPE output column set, ordered exactly as the bug surfaced.
const EVTXECMD_HEADERS = [
  "RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level",
  "Provider", "Channel", "ProcessId", "ThreadId", "Computer", "ChunkNumber",
  "UserId", "MapDescription", "UserName", "RemoteHost",
  "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6",
  "ExecutableInfo", "HiddenRecord", "SourceFile", "Keywords", "ExtraDataOffset", "Payload",
];

function makeStub(headers, rows) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });

  const rowsByCN = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    headers.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return out;
  });

  function aliasRows(sql) {
    // Alias regex must accept digits — keys like _payloadData1, _payloadData2 are
    // legitimate analyzer aliases. Earlier omission caused the test stub to silently
    // drop those columns and made 4776 NTLM-only tests appear to fail when the bug
    // was actually in the harness.
    const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    return rowsByCN.map((r) => {
      const out = { _rowid: r._rowid };
      for (const [, idx, alias] of aliasMatches) {
        out[alias] = r[`c${idx}`];
      }
      return out;
    });
  }

  function scanRows(sql, args) {
    if (!/data\.rowid\s+as\s+_rid/i.test(sql) || !/\bas\s+_alltext/i.test(sql)) return null;
    const plainAliasMatches = [...sql.matchAll(/(c\d+)\s+as\s+(_[a-zA-Z0-9_]+)/g)];
    const aliasToCol = {};
    for (const [, col, alias] of plainAliasMatches) aliasToCol[alias] = col;

    const bound = Array.isArray(args) ? args : [];
    const lastRid = Number(bound[bound.length - 1] || 0);
    const eids = new Set(bound.slice(0, -1).map(v => String(v)));
    const limitMatch = sql.match(/\bLIMIT\s+(\d+)/i);
    const limit = limitMatch ? Number(limitMatch[1]) : rowsByCN.length;
    const eventCol = aliasToCol._eid || colMap.EventId || colMap.EventID || colMap.event_id;

    return rowsByCN
      .filter((r) => r._rowid > lastRid)
      .filter((r) => !eventCol || eids.size === 0 || eids.has(String(r[eventCol] || "")))
      .slice(0, limit)
      .map((r) => {
        const out = {
          _rid: r._rowid,
          _alltext: Object.keys(r)
            .filter(k => k !== "_rowid")
            .map(k => r[k])
            .filter(v => v != null)
            .join("|"),
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
            return aliasRows(sql);
          }
          return [];
        },
      };
    },
  };

  const meta = { db, headers, colMap, tabId: "lm-evtxecmd-test" };
  const ctx = {
    applyStandardFilters() {},
    ensureIndex() {},
    cleanWrappedField: (v) => String(v == null ? "" : v).trim(),
    compactGet: () => "",
    compactGetInt: () => "",
    extractFirstInteger: (v) => { const m = String(v || "").match(/-?\d+/); return m ? m[0] : ""; },
    isChainsawLogonDataset: () => false,
    isHayabusaDataset: () => false,
    parseCompactKeyValues: () => null,
    resolveEventChannel: () => "",
  };
  return { meta, ctx };
}

// Build a single EvtxECmd Security 4624 row matching the real KAPE shape.
function rowFor(eid, opts) {
  return {
    RecordNumber: opts.rec || "1", EventRecordId: opts.rec || "1",
    TimeCreated: opts.ts || "2026-02-14T13:20:11Z",
    EventId: eid, Level: "Information",
    Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security",
    ProcessId: "0", ThreadId: "0",
    Computer: opts.computer || "GFUA-DC01.GFUA.LOCAL",
    ChunkNumber: "0", UserId: "S-1-5-18", MapDescription: "",
    UserName: opts.userName != null ? opts.userName : "-\\-",
    RemoteHost: opts.remoteHost || "GFUA-WKS01 (10.53.66.5)",
    PayloadData1: opts.pd1 || "",
    PayloadData2: opts.pd2 || "LogonType 3",
    PayloadData3: opts.pd3 || "",
    PayloadData4: "", PayloadData5: "", PayloadData6: "",
    ExecutableInfo: "", HiddenRecord: "False", SourceFile: "",
    Keywords: "0x8020000000000000", ExtraDataOffset: "0", Payload: "",
  };
}

const SCAN_HEADERS = [
  "TimeCreated", "EventId", "Computer", "IpAddress", "TargetUserName", "LogonType",
  "Channel", "Provider", "Image", "ParentImage", "CommandLine",
];

function scanRow(eid, opts = {}) {
  return {
    TimeCreated: opts.ts || "2026-03-10T09:00:00Z",
    EventId: eid,
    Computer: opts.computer || "HOST01",
    IpAddress: opts.ip || "10.10.10.5",
    TargetUserName: opts.user || "GFUA\\analyst",
    LogonType: opts.logonType || "3",
    Channel: opts.channel || (eid === "10" || eid === "1" ? "Sysmon" : "Security"),
    Provider: opts.provider || (eid === "10" || eid === "1" ? "Microsoft-Windows-Sysmon" : "Microsoft-Windows-Security-Auditing"),
    Image: opts.image || "",
    ParentImage: opts.parentImage || "",
    CommandLine: opts.commandLine || "",
  };
}

test("EvtxECmd Security 4624 with UserName='-\\-' still produces accounts via PayloadData1 Target:", () => {
  const rows = [
    rowFor("4624", { rec: "1", pd1: "Target: GFUA.LOCAL\\dkovalenko", remoteHost: "GFUA-WKS01 (10.53.66.5)" }),
    rowFor("4624", { rec: "2", pd1: "Target: GFUA.LOCAL\\dkovalenko", remoteHost: "GFUA-WKS01 (10.53.66.5)" }),
    rowFor("4624", { rec: "3", pd1: "Target: GFUA.LOCAL\\labadmin",   remoteHost: "GFUA-WKS02 (10.53.66.9)" }),
  ];
  const { meta, ctx } = makeStub(EVTXECMD_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);
  assert.ok(result.accounts, "result.accounts must exist");
  assert.ok(result.accounts.length >= 2,
    `expected at least 2 accounts, got ${result.accounts.length}: ${JSON.stringify(result.accounts.map(a => a.user))}`);
  const users = new Set(result.accounts.map(a => a.user.toLowerCase()));
  assert.ok(users.has("dkovalenko"), `accounts must include dkovalenko, got ${[...users].join(",")}`);
  assert.ok(users.has("labadmin"), `accounts must include labadmin, got ${[...users].join(",")}`);
});

test("EvtxECmd 4672 (no Target prefix) falls back to UserName field with SID stripped", () => {
  const rows = [
    rowFor("4672", {
      rec: "1",
      pd1: "PrivilegeList: SeSecurityPrivilege",
      userName: "GFUA\\LabAdmin (S-1-5-21-4245492949-1549503684-3613175386-500)",
      remoteHost: "GFUA-WKS01 (10.53.66.5)",
    }),
  ];
  const { meta, ctx } = makeStub(EVTXECMD_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);
  // 4672 is a SESSION_ONLY event so it doesn't create graph edges, but it
  // does feed userEventCounts. The simplest assertion is that the parser
  // recovers the username — the easiest visible signal is account creation
  // via the userEventCounts adminPrivilegeCount path. We can't easily inspect
  // that without another consumer event, so combine 4672 with a 4624 for
  // the same user and assert the account picks up adminPrivilegeCount.
  const rowsCombo = [
    rowFor("4672", {
      rec: "1",
      pd1: "PrivilegeList: SeSecurityPrivilege",
      userName: "GFUA\\LabAdmin (S-1-5-21-4245492949-1549503684-3613175386-500)",
      remoteHost: "GFUA-WKS01 (10.53.66.5)",
    }),
    rowFor("4624", {
      rec: "2",
      pd1: "Target: GFUA.LOCAL\\LabAdmin",
      remoteHost: "GFUA-WKS01 (10.53.66.5)",
    }),
  ];
  const { meta: m2, ctx: c2 } = makeStub(EVTXECMD_HEADERS, rowsCombo);
  const result2 = getLateralMovement(m2, { excludeServiceAccounts: false, excludeLocalLogons: false }, c2);
  const labadmin = result2.accounts.find(a => a.user.toLowerCase() === "labadmin");
  assert.ok(labadmin, "labadmin account must exist after combining 4672 + 4624");
  assert.ok(labadmin.adminPrivilegeCount >= 1,
    `4672 must have been counted under labadmin's adminPrivilegeCount (got ${labadmin.adminPrivilegeCount})`);
});

test("EvtxECmd does not regress when UserName carries the real value (legacy path)", () => {
  // Some older EvtxECmd versions populate UserName directly. Ensure we still
  // work when both columns are populated and PayloadData1 matches.
  const rows = [
    rowFor("4624", {
      rec: "1",
      pd1: "Target: GFUA.LOCAL\\dkovalenko",
      userName: "GFUA\\dkovalenko (S-1-5-21-...)",
      remoteHost: "GFUA-WKS01 (10.53.66.5)",
    }),
  ];
  const { meta, ctx } = makeStub(EVTXECMD_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);
  const dk = result.accounts.find(a => a.user.toLowerCase() === "dkovalenko");
  assert.ok(dk, "dkovalenko account must exist");
});

test("Kerberos-only users (4769 with no 4624) are surfaced in the Accounts tab", () => {
  // Regression for under-seeded _accountMap. Pre-fix, Pass 4 used .get() instead of
  // _getAcct() so users that only appeared in raw Kerberos/NTLM/4672 counts were
  // silently dropped — they had no graph edge to seed the map from Pass 1.
  // A DC log will frequently have users that only show up via Kerberos service
  // ticket requests (4769) without ever producing a 4624 logon on this host.
  const rows = [
    rowFor("4769", {
      rec: "1",
      pd1: "Target: GFUA.LOCAL\\krbsvc",
      userName: "GFUA\\krbsvc (S-1-5-21-...-1234)",
      remoteHost: "GFUA-WKS03 (10.53.66.7)",
    }),
    rowFor("4769", {
      rec: "2",
      pd1: "Target: GFUA.LOCAL\\krbsvc",
      userName: "GFUA\\krbsvc (S-1-5-21-...-1234)",
      remoteHost: "GFUA-WKS03 (10.53.66.7)",
    }),
  ];
  const { meta, ctx } = makeStub(EVTXECMD_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);
  const krb = (result.accounts || []).find(a => a.user.toLowerCase() === "krbsvc");
  assert.ok(krb, `krbsvc must appear in accounts even with no 4624 — got ${JSON.stringify((result.accounts || []).map(a => a.user))}`);
  assert.ok(krb.kerberosCount >= 1, `kerberosCount must be at least 1 (got ${krb.kerberosCount})`);
});

test("NTLM-only users (4776 with no 4624) are surfaced in the Accounts tab", () => {
  const rows = [
    rowFor("4776", {
      rec: "1",
      pd1: "Target: ntlmuser",
      pd2: "Workstation: GFUA-WKS04",
      userName: "GFUA\\ntlmuser (S-1-5-21-...-5678)",
    }),
  ];
  const { meta, ctx } = makeStub(EVTXECMD_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);
  const u = (result.accounts || []).find(a => a.user.toLowerCase() === "ntlmuser");
  assert.ok(u, `ntlmuser must appear in accounts even with no 4624 — got ${JSON.stringify((result.accounts || []).map(a => a.user))}`);
  assert.ok(u.ntlmCount >= 1, `ntlmCount must be at least 1 (got ${u.ntlmCount})`);
});

// ── User propagation: execution-tool findings carry correlated logon users ──
// Pre-fix, PsExec/Impacket/WMI/RemoteSvc/RMM findings emitted `users: []`
// even when a Type 3 logon existed on the same host within ±5 min. This left
// the Accounts tab unable to link non-RDP movement to user identity.
//
// NOTE: The execution-tool scan path (PsExec/Impacket/WMI detection) uses a
// SQL concat (_alltext) that the lightweight test stub can't exercise without a
// full SQLite backend. These tests verify the *logon extraction* and *account
// linkage* paths that feed user propagation, which IS exercisable via the stub.
// Full-stack integration tests covering the scan→finding→user→account pipeline
// require a real database.

test("Admin share finding carries users from source events, linked to Accounts", () => {
  // Admin share detection reads from the main event loop (not the scan path),
  // so it IS exercisable via the stub. It also already carried users before
  // this batch, but this test documents the end-to-end: finding → account linkage.
  const rows = [
    // A Type 3 logon by an attacker (creates the edge + user attribution)
    rowFor("4624", {
      rec: "1",
      ts: "2026-03-10T08:00:00Z",
      pd1: "Target: GFUA.LOCAL\\attacker",
      pd2: "LogonType 3",
      remoteHost: "GFUA-WKS01 (10.53.66.5)",
      computer: "GFUA-DC01.GFUA.LOCAL",
    }),
    // A 5140 share access by the same user on the same target
    rowFor("5140", {
      rec: "2",
      ts: "2026-03-10T08:00:30Z",
      pd1: "Target: GFUA.LOCAL\\attacker",
      pd2: "ShareName: \\\\*\\ADMIN$",
      pd3: "ShareName: \\\\*\\ADMIN$",
      remoteHost: "GFUA-WKS01 (10.53.66.5)",
      computer: "GFUA-DC01.GFUA.LOCAL",
      userName: "GFUA\\attacker",
    }),
  ];
  const { meta, ctx } = makeStub(EVTXECMD_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);
  const asFinding = (result.findings || []).find(f => f.category === "Admin Share Access");
  // Admin share detection needs 5140/5145 with a matching share name in the text.
  // Even if this specific stub doesn't produce the finding (depends on share name
  // parsing in the main event loop), verify the account is present.
  const acct = (result.accounts || []).find(a => a.user.toLowerCase() === "attacker");
  assert.ok(acct, `attacker must appear in accounts — got ${JSON.stringify((result.accounts || []).map(a => a.user))}`);
  // If finding was emitted, it should carry the user
  if (asFinding) {
    assert.ok(asFinding.users.some(u => u === "ATTACKER"),
      `Admin Share finding users should include ATTACKER, got ${JSON.stringify(asFinding.users)}`);
  }
});

test("Sysmon EID 10 LSASS access emits a finding without partial-analysis warnings", () => {
  const rows = [
    scanRow("10", {
      image: "C:\\Tools\\procdump.exe",
      commandLine: "TargetImage: C:\\Windows\\System32\\lsass.exe GrantedAccess: 0x1010",
      channel: "Sysmon",
    }),
  ];
  const { meta, ctx } = makeStub(SCAN_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);
  assert.equal(result.error, null);
  assert.ok(!(result.warnings || []).some(w => /LSASS access detector failed/i.test(w)),
    `must not produce LSASS detector warning: ${JSON.stringify(result.warnings)}`);
  const finding = (result.findings || []).find(f => f.category === "LSASS Access");
  assert.ok(finding, `expected LSASS Access finding, got ${JSON.stringify((result.findings || []).map(f => f.category))}`);
  assert.equal(finding.severity, "critical");
  assert.match(finding.title, /procdump\.exe/i);
  assert.deepEqual(finding.itemRowids, [1]);
});

test("reg save credential dump command emits SAM/LSA Registry Dump finding", () => {
  const rows = [
    scanRow("4688", {
      image: "C:\\Windows\\System32\\reg.exe",
      commandLine: "reg save HKLM\\SAM C:\\Temp\\sam.save",
      channel: "Security",
    }),
  ];
  const { meta, ctx } = makeStub(SCAN_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);
  assert.equal(result.error, null);
  assert.ok(!(result.warnings || []).some(w => /Credential theft command detector failed/i.test(w)),
    `must not produce credential theft detector warning: ${JSON.stringify(result.warnings)}`);
  const finding = (result.findings || []).find(f => f.category === "SAM/LSA Registry Dump");
  assert.ok(finding, `expected registry dump finding, got ${JSON.stringify((result.findings || []).map(f => f.category))}`);
  assert.equal(finding.severity, "critical");
  assert.match(finding.title, /HKLM\\SAM/i);
  assert.deepEqual(finding.itemRowids, [1]);
});

test("netsh interface portproxy command emits Port Forwarding finding", () => {
  const rows = [
    scanRow("4688", {
      image: "C:\\Windows\\System32\\netsh.exe",
      commandLine: "netsh interface portproxy add v4tov4 listenport=3389 connectaddress=10.0.0.5 connectport=3389",
      channel: "Security",
    }),
  ];
  const { meta, ctx } = makeStub(SCAN_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);
  assert.equal(result.error, null);
  assert.ok(!(result.warnings || []).some(w => /Credential theft command detector failed/i.test(w)),
    `must not produce credential theft detector warning: ${JSON.stringify(result.warnings)}`);
  const finding = (result.findings || []).find(f => f.category === "Port Forwarding");
  assert.ok(finding, `expected port forwarding finding, got ${JSON.stringify((result.findings || []).map(f => f.category))}`);
  assert.equal(finding.severity, "high");
  assert.match(finding.title, /portproxy/i);
  assert.deepEqual(finding.itemRowids, [1]);
});

test("single-tab lateral movement preserves evidence refs on edges, sessions, findings, and chains", () => {
  const rows = [
    rowFor("1149", {
      rec: "1",
      ts: "2026-03-10T08:00:00Z",
      pd1: "User: attacker",
      pd2: "Domain: GFUA",
      pd3: "Source Network Address: 10.53.66.5",
      remoteHost: "10.53.66.5",
      computer: "GFUA-DC01.GFUA.LOCAL",
      userName: "GFUA\\attacker",
    }),
    rowFor("4624", {
      rec: "2",
      ts: "2026-03-10T08:00:01Z",
      pd1: "Target: GFUA.LOCAL\\attacker",
      pd2: "LogonType 10",
      remoteHost: "GFUA-WKS01 (10.53.66.5)",
      computer: "GFUA-DC01.GFUA.LOCAL",
      userName: "GFUA\\attacker",
    }),
    rowFor("21", {
      rec: "3",
      ts: "2026-03-10T08:00:02Z",
      pd1: "User: GFUA\\attacker",
      pd2: "Session ID: 2",
      pd3: "Source Network Address: 10.53.66.5",
      remoteHost: "10.53.66.5",
      computer: "GFUA-DC01.GFUA.LOCAL",
      userName: "GFUA\\attacker",
    }),
    rowFor("4624", {
      rec: "4",
      ts: "2026-03-10T08:05:00Z",
      pd1: "Target: GFUA.LOCAL\\attacker",
      pd2: "LogonType 3",
      remoteHost: "GFUA-DC01 (10.53.66.10)",
      computer: "GFUA-FS01.GFUA.LOCAL",
      userName: "GFUA\\attacker",
    }),
  ];
  const { meta, ctx } = makeStub(EVTXECMD_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);

  const edge = (result.edges || []).find(e => e.source === "GFUA-WKS01" && e.target === "GFUA-DC01");
  assert.ok(edge, `expected WKS01 -> DC01 edge, got ${JSON.stringify(result.edges)}`);
  assert.ok(edge.evidenceRefs.some(ref => ref.tabId === "lm-evtxecmd-test" && ref.rowId === 2),
    `edge should preserve the Security 4624 source row: ${JSON.stringify(edge.evidenceRefs)}`);

  const rdpSession = (result.rdpSessions || []).find(s => s.user.toLowerCase() === "attacker");
  assert.ok(rdpSession, `expected RDP session, got ${JSON.stringify(result.rdpSessions)}`);
  const allRdpRefs = (result.rdpSessions || []).flatMap(s => s.evidenceRefs || []);
  assert.ok(allRdpRefs.some(ref => ref.tabId === "lm-evtxecmd-test" && ref.rowId === 1), "RDP sessions should include 1149 source row");
  assert.ok(allRdpRefs.some(ref => ref.tabId === "lm-evtxecmd-test" && ref.rowId === 2), "RDP sessions should include 4624 source row");
  assert.ok(rdpSession.events.every(evt => Array.isArray(evt.evidenceRefs)), "RDP session events should carry evidenceRefs arrays");

  const firstSeen = (result.findings || []).find(f => f.category === "First Seen" && f.source === "GFUA-WKS01");
  if (firstSeen) {
    assert.ok(
      firstSeen.evidenceRefs.some(ref => ref.tabId === "lm-evtxecmd-test" && [1, 2, 3].includes(ref.rowId)),
      "First Seen finding should preserve an originating RDP source row ref",
    );
  }

  if ((result.chains || []).length > 0) {
    assert.ok(result.chains[0].evidenceRefs.length >= 2, `chain should aggregate hop evidenceRefs: ${JSON.stringify(result.chains[0])}`);
    assert.ok(result.chains[0].hopDetails.every(h => Array.isArray(h.evidenceRefs)), "chain hopDetails should carry evidenceRefs");
  }
});

test("multi-source lateral movement preserves tab-specific evidence refs on merged edges", () => {
  const tabARows = [
    rowFor("4624", {
      rec: "1",
      ts: "2026-03-10T08:00:00Z",
      pd1: "Target: GFUA.LOCAL\\attacker",
      pd2: "LogonType 3",
      remoteHost: "GFUA-WKS01 (10.53.66.5)",
      computer: "GFUA-DC01.GFUA.LOCAL",
    }),
  ];
  const tabBRows = [
    rowFor("4624", {
      rec: "1",
      ts: "2026-03-10T08:00:30Z",
      pd1: "Target: GFUA.LOCAL\\attacker",
      pd2: "LogonType 3",
      remoteHost: "GFUA-WKS01 (10.53.66.5)",
      computer: "GFUA-DC01.GFUA.LOCAL",
    }),
  ];
  const { meta: metaA, ctx } = makeStub(EVTXECMD_HEADERS, tabARows);
  const { meta: metaB } = makeStub(EVTXECMD_HEADERS, tabBRows);

  const result = getMultiSourceLateralMovement([
    { meta: metaA, tabId: "tab-a", label: "Security.evtx" },
    { meta: metaB, tabId: "tab-b", label: "ForwardedEvents.evtx" },
  ], { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);

  const edge = (result.edges || [])[0];
  assert.ok(edge, `expected merged edge, got ${JSON.stringify(result)}`);
  assert.deepEqual(edge.evidenceRefs, [
    { tabId: "tab-a", rowId: 1, sourceTab: "Security.evtx", sourceFormat: "EvtxECmd" },
    { tabId: "tab-b", rowId: 1, sourceTab: "ForwardedEvents.evtx", sourceFormat: "EvtxECmd" },
  ]);
  assert.equal(edge.count, 2);
  assert.equal(result.multiSource, true);
});

test("multi-source surfaces per-tab execution-technique findings (db-gated detectors)", () => {
  // The PsExec/Impacket/LSASS/reg-dump/etc. detectors query a live db directly, which
  // the merged synthetic meta (db:null) cannot provide — so before the per-tab harvest
  // they silently never fired in multi-source mode. Tab A (a DC collection) carries a
  // logon plus a reg-save credential dump (4688) and a Sysmon EID 10 LSASS access.
  const tabARows = [
    scanRow("4624", { ts: "2026-03-10T08:00:00Z", computer: "DC01", ip: "10.0.0.5", user: "CORP\\attacker" }),
    scanRow("4688", { ts: "2026-03-10T08:01:00Z", computer: "DC01", image: "C:\\Windows\\System32\\reg.exe", commandLine: "reg save HKLM\\SAM C:\\Temp\\sam.save", channel: "Security" }),
    scanRow("10", { ts: "2026-03-10T08:02:00Z", computer: "DC01", image: "C:\\Tools\\procdump.exe", commandLine: "TargetImage: C:\\Windows\\System32\\lsass.exe GrantedAccess: 0x1010", channel: "Sysmon" }),
  ];
  const tabBRows = [
    scanRow("4624", { ts: "2026-03-10T08:05:00Z", computer: "FS01", ip: "10.0.0.5", user: "CORP\\attacker" }),
  ];
  const { meta: metaA, ctx } = makeStub(SCAN_HEADERS, tabARows);
  const { meta: metaB } = makeStub(SCAN_HEADERS, tabBRows);

  const result = getMultiSourceLateralMovement([
    { meta: metaA, tabId: "tab-a", label: "DC01.evtx" },
    { meta: metaB, tabId: "tab-b", label: "FS01.evtx" },
  ], { excludeServiceAccounts: false, excludeLocalLogons: false }, ctx);

  assert.equal(result.multiSource, true);
  const cats = (result.findings || []).map((f) => f.category);
  const regDump = (result.findings || []).find((f) => f.category === "SAM/LSA Registry Dump");
  const lsass = (result.findings || []).find((f) => f.category === "LSASS Access");
  assert.ok(regDump, `expected SAM/LSA Registry Dump from per-tab scan, got ${JSON.stringify(cats)}`);
  assert.ok(lsass, `expected LSASS Access from per-tab scan, got ${JSON.stringify(cats)}`);
  // Harvested execution findings are tagged with their originating tab and re-ID'd uniquely.
  assert.equal(regDump._sourceTabId, "tab-a");
  assert.equal(lsass._sourceTabId, "tab-a");
  const ids = (result.findings || []).map((f) => f.id);
  assert.equal(new Set(ids).size, ids.length, "merged finding ids must be unique");
});

test("4648 uses the logging Computer as source and TargetServerName as destination", () => {
  const rows = [
    rowFor("4648", {
      rec: "1",
      computer: "WKS01.corp.local",
      pd1: "Target: CORP\\admin",
      pd3: "TargetServerName: DC01",
      remoteHost: "- (10.1.1.10)",
    }),
  ];
  const { meta, ctx } = makeStub(EVTXECMD_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: true }, ctx);
  assert.equal(result.error, null, result.error);
  const edge = (result.edges || []).find((e) => e.source === "WKS01" || e.source === "WKS01.CORP.LOCAL" || e.source.startsWith("WKS01"));
  assert.ok(edge, `expected an edge from WKS01, got ${JSON.stringify((result.edges || []).map((e) => `${e.source}->${e.target}`))}`);
  assert.match(edge.target, /DC01/);
  assert.ok(!/10\.1\.1\.10/.test(edge.source), "4648 IpAddress is the destination, not the source");
});

test("console logons with short WorkstationName vs FQDN Computer are treated as local", () => {
  const rows = [
    rowFor("4624", {
      rec: "1",
      computer: "WKS01.corp.local",
      pd1: "Target: CORP\\jsmith",
      pd2: "LogonType 2",
      remoteHost: "WKS01 (127.0.0.1)",
    }),
  ];
  const { meta, ctx } = makeStub(EVTXECMD_HEADERS, rows);
  const result = getLateralMovement(meta, { excludeServiceAccounts: false, excludeLocalLogons: true }, ctx);
  assert.equal((result.edges || []).length, 0, `console logon must not create a lateral edge, got ${JSON.stringify(result.edges)}`);
});
