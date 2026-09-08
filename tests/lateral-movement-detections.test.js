// Regression tests for two lateral-movement detection additions:
//
//   A. 5145 RelativeTargetName named-pipe attribution — wires the (previously
//      parsed-but-unused) RelativeTargetName field into the Admin Share Access
//      detector so that IPC$ access to control pipes (svcctl/atsvc/winreg) and
//      tool drops to ADMIN$/C$ (PSEXESVC/RemCom) are attributed to the specific
//      remote-execution technique even without process/service logs.
//
//   B. Remote Execution Sequence correlator — emits ONE high-confidence finding
//      for the ordered tuple auth (4648/4624-Type3|9) -> admin/IPC$ share (5140/5145)
//      -> execution finding (PsExec/Impacket/Service/WMI/WinRM/Task) on one host by
//      one principal within a short window. Fires only when ordering + user
//      continuity actually hold (no time-lucky clustering).

const test = require("node:test");
const assert = require("node:assert/strict");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");

// Header set that supports BOTH the main logon/share event loop (IpAddress,
// TargetUserName, ShareName, RelativeTargetName) and the execution scan path
// (Image, CommandLine, ServiceName via the _alltext concat).
const HEADERS = [
  "TimeCreated", "EventId", "Computer", "IpAddress", "TargetUserName", "LogonType",
  "Channel", "Provider", "ShareName", "RelativeTargetName", "SubStatus",
  "Image", "ParentImage", "ParentCommandLine", "CommandLine", "ServiceName",
  "SubjectUserName", "SubjectDomainName",
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
    const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    return rowsByCN.map((r) => {
      const out = { _rowid: r._rowid };
      for (const [, idx, alias] of aliasMatches) out[alias] = r[`c${idx}`];
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
    const eventCol = aliasToCol._eid || colMap.EventId || colMap.EventID;
    return rowsByCN
      .filter((r) => r._rowid > lastRid)
      .filter((r) => !eventCol || eids.size === 0 || eids.has(String(r[eventCol] || "")))
      .slice(0, limit)
      .map((r) => {
        const out = {
          _rid: r._rowid,
          _alltext: Object.keys(r).filter(k => k !== "_rowid").map(k => r[k]).filter(v => v != null).join("|"),
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
          if (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql)) return aliasRows(sql);
          return [];
        },
      };
    },
  };

  const meta = { db, headers, colMap, tabId: "lm-detect-test" };
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

function row(eid, opts = {}) {
  return {
    TimeCreated: opts.ts || "2026-03-10T08:00:00Z",
    EventId: eid,
    Computer: opts.computer || "HOST01",
    IpAddress: opts.ip || "10.10.10.5",
    TargetUserName: opts.user != null ? opts.user : "CORP\\attacker",
    LogonType: opts.logonType || "3",
    Channel: opts.channel || (eid === "7045" ? "System" : "Security"),
    Provider: opts.provider || "Microsoft-Windows-Security-Auditing",
    ShareName: opts.shareName || "",
    RelativeTargetName: opts.relativeTargetName || "",
    SubStatus: opts.subStatus || "",
    Image: opts.image || "",
    ParentImage: opts.parentImage || "",
    ParentCommandLine: opts.parentCommandLine || "",
    CommandLine: opts.commandLine || "",
    ServiceName: opts.serviceName || "",
    SubjectUserName: opts.subjectUserName || "",
    SubjectDomainName: opts.subjectDomainName || "",
  };
}

const OPTS = { excludeServiceAccounts: false, excludeLocalLogons: false };

// ── A. Named-pipe attribution ──────────────────────────────────────────────

test("A: 5145 IPC$ access to \\pipe\\svcctl is attributed as remote service control (T1569.002)", () => {
  const rows = [
    row("5145", { ts: "2026-03-10T08:00:00Z", shareName: "\\\\*\\IPC$", relativeTargetName: "svcctl" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "Admin Share Access");
  assert.ok(f, `expected Admin Share Access finding (IPC$ + svcctl), got ${JSON.stringify((result.findings || []).map(x => x.category))}`);
  assert.equal(f.mitre, "T1569.002", `svcctl pipe must promote MITRE to T1569.002, got ${f.mitre}`);
  assert.match(f.title, /\\pipe\\svcctl/i, `title should name the pipe: ${f.title}`);
  assert.equal(f.severity, "high", `IPC$ + control pipe should be high, got ${f.severity}`);
  assert.ok(f.evidencePills.some(p => /\\pipe\\svcctl/i.test(p.text)), "should carry a \\pipe\\svcctl pill");
});

test("A: bare IPC$ access with NO named pipe is still suppressed (no FP)", () => {
  const rows = [
    row("5145", { ts: "2026-03-10T08:00:00Z", shareName: "\\\\*\\IPC$", relativeTargetName: "" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "Admin Share Access");
  assert.ok(!f, `bare IPC$ with no exec pipe / no tool correlation must NOT fire, got ${JSON.stringify(f)}`);
});

test("A: ADMIN$ access to a PSEXESVC drop is critical and PsExec-attributed", () => {
  const rows = [
    row("5145", { ts: "2026-03-10T08:00:00Z", shareName: "\\\\*\\ADMIN$", relativeTargetName: "PSEXESVC.exe" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "Admin Share Access");
  assert.ok(f, "expected Admin Share Access finding for ADMIN$ + PSEXESVC");
  assert.equal(f.severity, "critical", `ADMIN$ + tool drop should be critical, got ${f.severity}`);
  assert.equal(f.mitre, "T1569.002");
  assert.ok(f.evidencePills.some(p => /psexesvc/i.test(p.text)), "should carry a psexesvc pill");
});

// ── B. Remote execution sequence correlator ────────────────────────────────

test("B: ordered auth -> ADMIN$ share -> service exec on one host emits a Remote Execution Sequence", () => {
  const rows = [
    // auth: Type 3 logon to HOST01 by attacker
    row("4624", { ts: "2026-03-10T08:00:00Z", logonType: "3", user: "CORP\\attacker", computer: "HOST01", ip: "10.10.10.5" }),
    // share: ADMIN$ access on HOST01 by attacker, 30s later
    row("5145", { ts: "2026-03-10T08:00:30Z", user: "CORP\\attacker", computer: "HOST01", ip: "10.10.10.5", shareName: "\\\\*\\ADMIN$" }),
    // exec: suspicious service install on HOST01, 60s after auth (binary in Temp + cmd /c)
    row("7045", { ts: "2026-03-10T08:01:00Z", computer: "HOST01", image: "C:\\Windows\\Temp\\evil.exe", commandLine: "cmd /c whoami", serviceName: "evilsvc", subjectUserName: "svc-operator", subjectDomainName: "CORP" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  // sanity: the exec finding the sequence depends on must exist
  const execF = (result.findings || []).find(x => x.category === "Remote Service Execution" || x.category === "PsExec Native");
  assert.ok(execF, `precondition: an execution finding must fire, got ${JSON.stringify((result.findings || []).map(x => x.category))}`);
  assert.deepEqual(execF.serviceNames, ["evilsvc"]);
  assert.deepEqual(execF.imagePaths, ["C:\\Windows\\Temp\\evil.exe"]);
  assert.deepEqual(execF.commandLines, ["cmd /c whoami"]);
  assert.ok(execF.executors.includes("ATTACKER"), `correlated executor should be ATTACKER, got ${JSON.stringify(execF.executors)}`);
  assert.ok(execF.executors.includes("CORP\\svc-operator"), `direct event account should be preserved, got ${JSON.stringify(execF.executors)}`);
  assert.deepEqual(execF.eventActors, ["CORP\\svc-operator"]);
  assert.equal(execF.executionDetails?.[0]?.sourceHost, "10.10.10.5");
  assert.equal(execF.executionDetails?.[0]?.attributedUser, "ATTACKER");
  const execSession = (result.executionSessions || []).find(s => (s.findingIds || []).includes(execF.id));
  assert.ok(execSession, "service execution finding should be represented in an execution session");
  assert.deepEqual(execSession.serviceNames, ["evilsvc"]);
  assert.deepEqual(execSession.imagePaths, ["C:\\Windows\\Temp\\evil.exe"]);
  const seq = (result.findings || []).find(x => x.category === "Remote Execution Sequence");
  assert.ok(seq, `expected Remote Execution Sequence, got ${JSON.stringify((result.findings || []).map(x => x.category))}`);
  assert.equal(seq.severity, "critical");
  assert.equal(seq.target, "HOST01");
  assert.ok(seq.users.includes("ATTACKER"), `sequence user should be ATTACKER, got ${JSON.stringify(seq.users)}`);
  assert.match(seq.title, /auth/i);
  assert.ok((seq.evidenceRefs || []).length >= 2, "sequence should aggregate evidence from multiple steps");
});

test("B: exec far outside the window does NOT form a sequence (ordering/window guard)", () => {
  const rows = [
    row("4624", { ts: "2026-03-10T08:00:00Z", logonType: "3", user: "CORP\\attacker", computer: "HOST01", ip: "10.10.10.5" }),
    row("5145", { ts: "2026-03-10T08:00:30Z", user: "CORP\\attacker", computer: "HOST01", ip: "10.10.10.5", shareName: "\\\\*\\ADMIN$" }),
    // exec 30 minutes later — well beyond the 180s adjacency / 600s span windows
    row("7045", { ts: "2026-03-10T08:30:00Z", computer: "HOST01", image: "C:\\Windows\\Temp\\evil.exe", commandLine: "cmd /c whoami", serviceName: "evilsvc" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const seq = (result.findings || []).find(x => x.category === "Remote Execution Sequence");
  assert.ok(!seq, `no sequence should form when exec is outside the window, got ${JSON.stringify(seq)}`);
});

test("B: a different user on the share breaks user continuity (no false sequence)", () => {
  const rows = [
    row("4624", { ts: "2026-03-10T08:00:00Z", logonType: "3", user: "CORP\\attacker", computer: "HOST01", ip: "10.10.10.5" }),
    // share accessed by a DIFFERENT principal
    row("5145", { ts: "2026-03-10T08:00:30Z", user: "CORP\\helpdesk", computer: "HOST01", ip: "10.10.10.9", shareName: "\\\\*\\ADMIN$" }),
    row("7045", { ts: "2026-03-10T08:01:00Z", computer: "HOST01", image: "C:\\Windows\\Temp\\evil.exe", commandLine: "cmd /c whoami", serviceName: "evilsvc" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const seq = (result.findings || []).find(x => x.category === "Remote Execution Sequence");
  assert.ok(!seq, `user-continuity mismatch must prevent a sequence, got ${JSON.stringify(seq)}`);
});

test("B: EvtxECmd service fields are preserved from PayloadData and ExecutableInfo", () => {
  const headers = [
    "TimeCreated", "EventId", "Computer", "Channel", "Provider", "MapDescription", "UserName", "RemoteHost",
    "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6",
    "ExecutableInfo",
  ];
  const rows = [{
    TimeCreated: "2026-03-10T08:01:00Z",
    EventId: "7045",
    Computer: "HOST01",
    Channel: "System",
    Provider: "Service Control Manager",
    MapDescription: "A new service was installed in the system",
    UserName: "CORP\\installer",
    RemoteHost: "",
    PayloadData1: "Name: evilsvc",
    PayloadData2: "StartType: auto start",
    PayloadData3: "Account: LocalSystem",
    PayloadData4: "",
    PayloadData5: "",
    PayloadData6: "",
    ExecutableInfo: "C:\\Windows\\Temp\\evil.exe",
  }];
  const { meta, ctx } = makeStub(headers, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const execF = (result.findings || []).find(x => x.category === "Remote Service Execution");
  assert.ok(execF, `expected Remote Service Execution, got ${JSON.stringify({ findings: (result.findings || []).map(x => x.category), warnings: result.warnings, coverage: result.coverage })}`);
  assert.deepEqual(execF.serviceNames, ["evilsvc"]);
  assert.deepEqual(execF.imagePaths, ["C:\\Windows\\Temp\\evil.exe"]);
  assert.deepEqual(execF.commandLines, ["C:\\Windows\\Temp\\evil.exe"]);
  assert.deepEqual(execF.eventActors, ["CORP\\installer"]);
  assert.deepEqual(execF.serviceAccounts, ["LocalSystem"]);
  assert.deepEqual(execF.executors, ["CORP\\installer"]);
});

// ── C. Service-Exec edge technique correlation ─────────────────────────────

test("C: a Type-3 edge is relabeled 'Service Exec' when a service-install finding lands on the target", () => {
  // ip:"-" on the scan-only 7045 keeps it out of the logon edge (mirrors real EID filtering,
  // which the lightweight stub does not apply to the main query).
  const rows = [
    row("4624", { ts: "2026-03-10T08:00:00Z", logonType: "3", user: "CORP\\attacker", computer: "HOST01", ip: "10.10.10.5" }),
    row("7045", { ts: "2026-03-10T08:01:00Z", computer: "HOST01", ip: "-", image: "C:\\Windows\\Temp\\svc.exe", commandLine: "cmd /c whoami", serviceName: "evilsvc" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const exec = (result.findings || []).find(f => f.category === "Remote Service Execution");
  assert.ok(exec, "precondition: Remote Service Execution finding must fire");
  const edge = (result.edges || []).find(e => e.target === "HOST01");
  assert.ok(edge, `expected an edge to HOST01, got ${JSON.stringify((result.edges || []).map(e => ({ s: e.source, t: e.target })))}`);
  assert.equal(edge.technique, "Service Exec", `edge should be relabeled Service Exec, got ${edge.technique}`);
});

test("C: a Type-3 edge is NOT relabeled when the exec finding is far outside the window", () => {
  const rows = [
    row("4624", { ts: "2026-03-10T08:00:00Z", logonType: "3", user: "CORP\\attacker", computer: "HOST01", ip: "10.10.10.5" }),
    row("7045", { ts: "2026-03-10T09:30:00Z", computer: "HOST01", ip: "-", image: "C:\\Windows\\Temp\\svc.exe", commandLine: "cmd /c whoami", serviceName: "evilsvc" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const edge = (result.edges || []).find(e => e.target === "HOST01");
  assert.ok(edge, "expected an edge to HOST01");
  assert.notEqual(edge.technique, "Service Exec", `edge must stay Network Logon when exec is out of window, got ${edge.technique}`);
});

test("Remote Service Execution is one finding per host cluster, not one dataset-wide aggregate", () => {
  const rows = [
    row("4624", { ts: "2026-03-10T08:00:00Z", logonType: "3", user: "CORP\\attacker", computer: "HOSTA", ip: "10.10.10.5" }),
    row("5145", { ts: "2026-03-10T08:00:30Z", user: "CORP\\attacker", computer: "HOSTA", ip: "10.10.10.5", shareName: "\\\\*\\ADMIN$" }),
    row("7045", { ts: "2026-03-10T08:01:00Z", computer: "HOSTA", ip: "-", image: "C:\\Windows\\Temp\\a.exe", commandLine: "cmd /c whoami", serviceName: "svca" }),
    row("4624", { ts: "2026-03-15T12:00:00Z", logonType: "3", user: "CORP\\attacker", computer: "HOSTB", ip: "10.10.10.8" }),
    row("5145", { ts: "2026-03-15T12:00:20Z", user: "CORP\\attacker", computer: "HOSTB", ip: "10.10.10.8", shareName: "\\\\*\\ADMIN$" }),
    row("7045", { ts: "2026-03-15T12:01:00Z", computer: "HOSTB", ip: "-", image: "C:\\Windows\\Temp\\b.exe", commandLine: "cmd /c whoami", serviceName: "svcb" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const execs = (result.findings || []).filter((f) => f.category === "Remote Service Execution");
  assert.equal(execs.length, 2, `expected one service-exec finding per host, got ${JSON.stringify(execs.map((f) => f.target))}`);
  const byHost = new Map(execs.map((f) => [f.target, f]));
  assert.ok(byHost.has("HOSTA") && byHost.has("HOSTB"));
  assert.deepEqual(byHost.get("HOSTA").serviceNames, ["svca"]);
  assert.deepEqual(byHost.get("HOSTB").serviceNames, ["svcb"]);
  const seqs = (result.findings || []).filter((f) => f.category === "Remote Execution Sequence");
  assert.equal(seqs.length, 2, `each host should get its own sequence, got ${JSON.stringify(seqs.map((s) => s.target))}`);
  const hostAEdge = (result.edges || []).find((e) => e.target === "HOSTA");
  const hostBEdge = (result.edges || []).find((e) => e.target === "HOSTB");
  assert.equal(hostAEdge?.technique, "Service Exec");
  assert.equal(hostBEdge?.technique, "Service Exec");
});

test("Remote Service Execution splits the same host when installs are more than 10 minutes apart", () => {
  const rows = [
    row("4624", { ts: "2026-03-10T08:00:00Z", logonType: "3", user: "CORP\\attacker", computer: "HOST01", ip: "10.10.10.5" }),
    row("7045", { ts: "2026-03-10T08:01:00Z", computer: "HOST01", ip: "-", image: "C:\\Windows\\Temp\\a.exe", commandLine: "cmd /c whoami", serviceName: "svca" }),
    row("4624", { ts: "2026-03-10T08:20:00Z", logonType: "3", user: "CORP\\attacker", computer: "HOST01", ip: "10.10.10.5" }),
    row("7045", { ts: "2026-03-10T08:21:00Z", computer: "HOST01", ip: "-", image: "C:\\Windows\\Temp\\b.exe", commandLine: "cmd /c whoami", serviceName: "svcb" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const execs = (result.findings || []).filter((f) => f.category === "Remote Service Execution");
  assert.equal(execs.length, 2, `expected two 10-min clusters on HOST01, got ${JSON.stringify(execs.map((f) => f.serviceNames))}`);
  assert.deepEqual(execs.map((f) => f.serviceNames).sort(), [["svca"], ["svcb"]]);
});

// ── 4771 Kerberos brute force ──────────────────────────────────────────────

test("4771: 5+ Kerberos pre-auth failures from one source to a DC fire a Kerberos Brute Force", () => {
  const rows = [1, 2, 3, 4, 5].map(i => row("4771", {
    ts: `2026-03-10T08:0${i}:00Z`, ip: "10.10.10.5", computer: "DC01", user: `CORP\\u${i}`, logonType: "",
  }));
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const bf = (result.findings || []).find(f => f.category === "Brute Force" && /Kerberos/i.test(f.title));
  assert.ok(bf, `expected Kerberos Brute Force, got ${JSON.stringify((result.findings || []).map(f => f.title))}`);
  assert.equal(bf.target, "DC01");
  assert.equal(bf.mitre, "T1110.001");
});

test("4771: a bad-password (0x18) burst stays high; an account-revoked (0x12) burst is dampened to low", () => {
  const bad = [1, 2, 3, 4, 5].map(i => row("4771", { ts: `2026-03-10T08:0${i}:00Z`, ip: "10.10.10.5", computer: "DC01", user: `CORP\\u${i}`, logonType: "", subStatus: "0x18" }));
  const r1 = getLateralMovement(makeStub(HEADERS, bad).meta, OPTS, makeStub(HEADERS, bad).ctx);
  const bf1 = (r1.findings || []).find(f => f.category === "Brute Force" && /Kerberos/i.test(f.title));
  assert.ok(bf1, "bad-password Kerberos burst should fire");
  assert.equal(bf1.severity, "high", `bad-password burst should be high, got ${bf1.severity}`);

  const revoked = [1, 2, 3, 4, 5].map(i => row("4771", { ts: `2026-03-10T08:0${i}:00Z`, ip: "10.10.10.5", computer: "DC01", user: `CORP\\u${i}`, logonType: "", subStatus: "0x12" }));
  const r2 = getLateralMovement(makeStub(HEADERS, revoked).meta, OPTS, makeStub(HEADERS, revoked).ctx);
  const bf2 = (r2.findings || []).find(f => f.category === "Brute Force" && /Kerberos/i.test(f.title));
  assert.ok(bf2, "revoked-account Kerberos burst still surfaces (for visibility)");
  assert.equal(bf2.severity, "low", `account-revoked noise burst should be dampened to low, got ${bf2.severity}`);
});

test("WMI subscription: a benign-NAMED consumer that still runs a script is NOT suppressed (anti-evasion)", () => {
  const rows = [
    row("20", { ts: "2026-03-10T08:00:00Z", computer: "HOST01", channel: "Microsoft-Windows-Sysmon/Operational",
      commandLine: "SCM Event Log Consumer powershell.exe -enc SQBFAFgA" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "WMI Event Subscription");
  assert.ok(f, "benign-named consumer with a script payload must still fire");
  assert.equal(f.severity, "critical");
});

test("WMI subscription: a binding-only (EID 21) with no visible payload is medium, not high", () => {
  const rows = [
    row("21", { ts: "2026-03-10T08:00:00Z", computer: "HOST01", channel: "Microsoft-Windows-Sysmon/Operational",
      commandLine: "FilterToConsumerBinding registered" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "WMI Event Subscription");
  assert.ok(f, "binding event should still produce a finding");
  assert.equal(f.severity, "medium", `binding-only without payload should be medium, got ${f.severity}`);
});

// ── WMI event subscription persistence (Sysmon 19/20/21) ───────────────────

test("WMI subscription: a Sysmon 20 consumer with a script payload is critical persistence", () => {
  const rows = [
    row("20", { ts: "2026-03-10T08:00:00Z", computer: "HOST01", channel: "Microsoft-Windows-Sysmon/Operational",
      commandLine: "powershell.exe -enc SQBFAFgA", image: "scrcons.exe" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "WMI Event Subscription");
  assert.ok(f, `expected WMI Event Subscription, got ${JSON.stringify((result.findings || []).map(x => x.category))}`);
  assert.equal(f.target, "HOST01");
  assert.equal(f.severity, "critical");
  assert.equal(f.mitre, "T1546.003");
});

test("WMI subscription: a benign SCM Event Log Consumer is suppressed (no FP)", () => {
  const rows = [
    row("20", { ts: "2026-03-10T08:00:00Z", computer: "HOST01", channel: "Microsoft-Windows-Sysmon/Operational",
      commandLine: "SCM Event Log Consumer", image: "" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "WMI Event Subscription");
  assert.ok(!f, `benign SCM consumer must be suppressed, got ${JSON.stringify(f)}`);
});

// ── Native DCOM lateral execution (T1021.003) ──────────────────────────────

test("DCOM: excel.exe (-Embedding) spawning powershell is flagged as DCOM Remote Execution", () => {
  // Excel/Outlook/dllhost DCOM is NOT covered by the Impacket dcomexec (mmc-specific) signature,
  // so it exercises the native DCOM detector. (mmc.exe -Embedding -> cmd is intentionally caught
  // first by the existing Impacket dcomexec detector.)
  const rows = [
    row("1", { ts: "2026-03-10T08:00:00Z", computer: "HOST01",
      parentImage: "C:\\Program Files\\Microsoft Office\\root\\Office16\\excel.exe", parentCommandLine: "excel.exe -Embedding",
      image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", commandLine: "powershell -enc SQBFAFgA" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "DCOM Remote Execution");
  assert.ok(f, `expected DCOM Remote Execution, got ${JSON.stringify((result.findings || []).map(x => x.category))}`);
  assert.equal(f.mitre, "T1021.003");
  assert.equal(f.severity, "high");
});

test("DCOM: mmc.exe spawning cmd WITHOUT the -Embedding/CLSID activation marker is NOT flagged", () => {
  const rows = [
    row("1", { ts: "2026-03-10T08:00:00Z", computer: "HOST01",
      parentImage: "C:\\Windows\\System32\\mmc.exe", parentCommandLine: "C:\\Windows\\System32\\mmc.exe compmgmt.msc",
      image: "C:\\Windows\\System32\\cmd.exe", commandLine: "cmd.exe" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "DCOM Remote Execution");
  assert.ok(!f, `no DCOM finding without an activation marker, got ${JSON.stringify(f)}`);
});

// ── OpenSSH on Windows (T1021.004 inbound / T1572 tunneling) ────────────────

test("SSH: an sshd service install is flagged as OpenSSH inbound access", () => {
  const rows = [
    row("7045", { ts: "2026-03-10T08:00:00Z", computer: "HOST01", ip: "-",
      image: "C:\\Windows\\System32\\OpenSSH\\sshd.exe", serviceName: "sshd", commandLine: "OpenSSH SSH Server" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "OpenSSH Inbound Access");
  assert.ok(f, `expected OpenSSH Inbound Access, got ${JSON.stringify((result.findings || []).map(x => x.category))}`);
  assert.equal(f.mitre, "T1021.004");
});

test("SSH: sshd.exe spawning a shell (inbound RCE) is high-severity inbound access", () => {
  const rows = [
    row("1", { ts: "2026-03-10T08:00:00Z", computer: "HOST01",
      parentImage: "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
      image: "C:\\Windows\\System32\\cmd.exe", commandLine: "cmd.exe /c whoami" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "OpenSSH Inbound Access");
  assert.ok(f, "expected OpenSSH Inbound Access from sshd->shell");
  assert.equal(f.severity, "high");
});

test("SSH: ssh.exe with a port-forward flag is flagged as SSH Tunneling (T1572)", () => {
  const rows = [
    row("1", { ts: "2026-03-10T08:00:00Z", computer: "HOST01",
      image: "C:\\Windows\\System32\\OpenSSH\\ssh.exe", commandLine: "ssh.exe -R 3389:127.0.0.1:3389 operator@10.0.0.9" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "SSH Tunneling");
  assert.ok(f, `expected SSH Tunneling, got ${JSON.stringify((result.findings || []).map(x => x.category))}`);
  assert.equal(f.mitre, "T1572");
  assert.equal(f.severity, "high");
});

test("SSH: a plain ssh.exe connection with no tunnel flag is NOT flagged as tunneling (no FP)", () => {
  const rows = [
    row("1", { ts: "2026-03-10T08:00:00Z", computer: "HOST01",
      image: "C:\\Windows\\System32\\OpenSSH\\ssh.exe", commandLine: "ssh.exe operator@10.0.0.9" }),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, OPTS, ctx);
  const f = (result.findings || []).find(x => x.category === "SSH Tunneling");
  assert.ok(!f, `plain ssh connection must not be flagged as a tunnel, got ${JSON.stringify(f)}`);
});

// ── DCOM dllhost surrogate guard + SSH forward-direction severity ───────────

test("DCOM: dllhost {CLSID} spawning a shell WITH a command is flagged; without a command it is not (surrogate FP guard)", () => {
  const clsid = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}";
  const withCmd = [
    row("1", { ts: "2026-03-10T08:00:00Z", computer: "HOST01",
      parentImage: "C:\\Windows\\System32\\dllhost.exe", parentCommandLine: `dllhost.exe /Processid:${clsid}`,
      image: "C:\\Windows\\System32\\cmd.exe", commandLine: "cmd.exe /c whoami" }),
  ];
  const r1 = getLateralMovement(makeStub(HEADERS, withCmd).meta, OPTS, makeStub(HEADERS, withCmd).ctx);
  assert.ok((r1.findings || []).some(f => f.category === "DCOM Remote Execution"), "dllhost + CLSID + cmd /c should fire");

  const noCmd = [
    row("1", { ts: "2026-03-10T08:00:00Z", computer: "HOST01",
      parentImage: "C:\\Windows\\System32\\dllhost.exe", parentCommandLine: `dllhost.exe /Processid:${clsid}`,
      image: "C:\\Windows\\System32\\cmd.exe", commandLine: "cmd.exe" }),
  ];
  const r2 = getLateralMovement(makeStub(HEADERS, noCmd).meta, OPTS, makeStub(HEADERS, noCmd).ctx);
  assert.ok(!(r2.findings || []).some(f => f.category === "DCOM Remote Execution"), "dllhost surrogate without an explicit command must NOT fire");
});

test("SSH: a local-forward (-L) tunnel is medium; a reverse (-R) tunnel is high", () => {
  const local = [
    row("1", { ts: "2026-03-10T08:00:00Z", computer: "HOST01",
      image: "C:\\Windows\\System32\\OpenSSH\\ssh.exe", commandLine: "ssh.exe -L 8080:db.internal:5432 user@jump" }),
  ];
  const rL = getLateralMovement(makeStub(HEADERS, local).meta, OPTS, makeStub(HEADERS, local).ctx);
  const fL = (rL.findings || []).find(f => f.category === "SSH Tunneling");
  assert.ok(fL, "local-forward tunnel should still fire");
  assert.equal(fL.severity, "medium", `-L local forward should be medium, got ${fL.severity}`);

  const remote = [
    row("1", { ts: "2026-03-10T08:00:00Z", computer: "HOST01",
      image: "C:\\Windows\\System32\\OpenSSH\\ssh.exe", commandLine: "ssh.exe -R 3389:127.0.0.1:3389 operator@10.0.0.9" }),
  ];
  const rR = getLateralMovement(makeStub(HEADERS, remote).meta, OPTS, makeStub(HEADERS, remote).ctx);
  const fR = (rR.findings || []).find(f => f.category === "SSH Tunneling");
  assert.equal(fR.severity, "high", `-R reverse forward should be high, got ${fR.severity}`);
});
