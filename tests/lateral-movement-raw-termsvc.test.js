// Regression tests for raw-EVTX TerminalServices ingest.
//
// The TerminalServices parse branch was written against EvtxECmd, which packs the
// session fields into PayloadData1/2/3. On a raw .evtx import those columns do not
// exist, so the "Source Network Address:" regex never matched and sourceHost stayed
// empty — and because EIDs 21/22/25/1149 are not in SESSION_ONLY_EVENTS, every one
// of them hit the `continue` guard. A raw TerminalServices-LocalSessionManager or
// RemoteConnectionManager log therefore produced zero RDP sessions, zero edges and
// zero findings.
//
// Raw EVTX carries those values in the UserData/EventXML leaves instead:
//   LocalSessionManager 21/22/24/25 -> User, SessionID, Address
//   RemoteConnectionManager 1149    -> Param1 (user), Param2 (domain), Param3 (source)

const test = require("node:test");
const assert = require("node:assert/strict");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");

// Raw-EVTX shape: `datetime` + `Provider` triggers isRawEvtx; `SessionID`/`Param1`
// additionally trigger isTermSvcEvtx. Deliberately no IpAddress/TargetUserName —
// a real TerminalServices channel has neither, which is the whole point.
const LSM_HEADERS = [
  "datetime", "RecordId", "EventID", "Provider", "Level", "Channel", "Computer", "Message",
  "User", "SessionID", "Address",
];

const RCM_HEADERS = [
  "datetime", "RecordId", "EventID", "Provider", "Level", "Channel", "Computer", "Message",
  "Param1", "Param2", "Param3",
];

// A tab holding both channels: the header union has Address *and* Param3. `detect()`
// returns the first match, so a single mapped source column can only ever serve one
// of the two record shapes — which is why the fix needs dedicated raw columns.
const MIXED_HEADERS = [
  "datetime", "RecordId", "EventID", "Provider", "Level", "Channel", "Computer", "Message",
  "User", "SessionID", "Address", "Param1", "Param2", "Param3",
];

const SECURITY_HEADERS = [
  "datetime", "RecordId", "EventID", "Provider", "Level", "Channel", "Computer", "Message",
  "IpAddress", "TargetUserName", "LogonType", "SubStatus",
];

const RDP_CORRELATION_HEADERS = [
  ...SECURITY_HEADERS,
  "User", "SessionID", "Address", "Param1", "Param2", "Param3",
];

const LSM_CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
const RCM_CHANNEL = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

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

  const meta = { db, headers, colMap, tabId: "lm-raw-termsvc-test" };
  const ctx = {
    applyStandardFilters() {},
    ensureIndex() {},
    isChainsawLogonDataset: () => false,
    isHayabusaDataset: () => false,
  };
  return { meta, ctx };
}

function lsmRow(eid, opts = {}) {
  return {
    datetime: opts.ts || "2026-03-10 08:00:00.000",
    RecordId: opts.recordId || "1",
    EventID: eid,
    Provider: "Microsoft-Windows-TerminalServices-LocalSessionManager",
    Level: "Information",
    Channel: LSM_CHANNEL,
    Computer: opts.computer || "WKS-TARGET",
    Message: opts.message || "",
    User: opts.user != null ? opts.user : "SEVENKINGDOMS\\cersei.lannister",
    SessionID: opts.sessionId || "3",
    Address: opts.address != null ? opts.address : "10.10.10.55",
  };
}

function rcmRow(eid, opts = {}) {
  return {
    datetime: opts.ts || "2026-03-10 08:00:00.000",
    RecordId: opts.recordId || "1",
    EventID: eid,
    Provider: "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
    Level: "Information",
    Channel: RCM_CHANNEL,
    Computer: opts.computer || "WKS-TARGET",
    Message: opts.message || "",
    Param1: opts.user != null ? opts.user : "cersei.lannister",
    Param2: opts.domain || "SEVENKINGDOMS",
    Param3: opts.address != null ? opts.address : "10.10.10.55",
  };
}

function securityRow(eid, opts = {}) {
  return {
    datetime: opts.ts || "2026-03-10 08:00:00.000",
    RecordId: opts.recordId || "1",
    EventID: eid,
    Provider: "Microsoft-Windows-Security-Auditing",
    Level: "Information",
    Channel: "Security",
    Computer: opts.computer || "WKS-TARGET",
    Message: "",
    IpAddress: opts.address || "10.10.10.55",
    TargetUserName: opts.user || "SEVENKINGDOMS\\cersei.lannister",
    LogonType: opts.logonType || "3",
    SubStatus: opts.subStatus || "0xC000006A",
  };
}

// The analyzer's own default event list already covers the TerminalServices IDs, so
// these runs exercise the same set the fixed UI will send.
function run(headers, rows, options = {}) {
  const { meta, ctx } = makeStub(headers, rows);
  return getLateralMovement(meta, { excludeLocalLogons: true, excludeServiceAccounts: true, ...options }, ctx);
}

test("raw LocalSessionManager 21/22 builds an RDP session with the Address source", () => {
  const res = run(LSM_HEADERS, [
    lsmRow("21", { ts: "2026-03-10 08:00:00.000" }),
    lsmRow("22", { ts: "2026-03-10 08:00:02.000" }),
    lsmRow("24", { ts: "2026-03-10 08:45:00.000" }),
  ]);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  assert.ok(res.rdpSessions.length >= 1, `expected at least one RDP session, got ${res.rdpSessions.length}`);

  const s = res.rdpSessions[0];
  assert.equal(s.source, "10.10.10.55");
  assert.equal(s.target, "WKS-TARGET");
  assert.match(s.user, /cersei\.lannister/i);

  // The session must also produce a graph edge — that is what puts it on the map.
  const edge = res.edges.find((e) => e.source === "10.10.10.55" && e.target === "WKS-TARGET");
  assert.ok(edge, `expected a 10.10.10.55 -> WKS-TARGET edge, got ${JSON.stringify(res.edges.map((e) => `${e.source}->${e.target}`))}`);
  assert.equal(res.stats.rdpSessionCount, 1, "21/22 is a proven session");
});

test("raw RemoteConnectionManager 1149 resolves user and source from Param1/Param3", () => {
  const res = run(RCM_HEADERS, [rcmRow("1149")]);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  const edge = res.edges.find((e) => e.source === "10.10.10.55" && e.target === "WKS-TARGET");
  assert.ok(edge, `expected a 1149 edge, got ${JSON.stringify(res.edges.map((e) => `${e.source}->${e.target}`))}`);
  assert.ok(
    edge.users.some((u) => /cersei\.lannister/i.test(u)),
    `expected cersei.lannister on the edge, got ${JSON.stringify(edge.users)}`,
  );
  assert.equal(res.stats.rdpSessionCount, 0, "a lone 1149 is a connection, not a proven RDP session");
  assert.ok(res.rdpSessions.some((s) => s.status === "incomplete"));
  assert.equal((res.chains || []).length, 0, "1149 must not become a movement hop on its own");
  const acct = (res.accounts || []).find((a) => /cersei\.lannister/i.test(a.user));
  assert.equal(acct?.rdpSessionCount || 0, 0, "Accounts tab must not call a 1149 a session either");
});

test("1149 followed by a disconnect is still not a proven RDP session", () => {
  const res = run(MIXED_HEADERS, [
    { ...rcmRow("1149", { ts: "2026-03-10 08:00:00.000" }), User: null, SessionID: null, Address: null },
    { ...lsmRow("24", { ts: "2026-03-10 08:00:05.000" }), Param1: null, Param2: null, Param3: null },
  ]);
  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  assert.equal(res.stats.rdpSessionCount, 0, "1149+24 is a dropped connection, not a logon");
  assert.ok(res.rdpSessions.every((s) => s.status === "incomplete" || s.status === "failed"));
  assert.equal((res.chains || []).length, 0);
});

test("a lone LSM 21 is a proven session start", () => {
  const res = run(LSM_HEADERS, [lsmRow("21")]);
  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  assert.ok(res.rdpSessions.length >= 1);
  assert.equal(res.stats.rdpSessionCount, 1, "LocalSessionManager 21 is a session logon");
  assert.ok(res.rdpSessions.some((s) => s.status !== "incomplete" && s.status !== "failed"));
});

test("a tab holding both channels resolves each record shape independently", () => {
  const res = run(MIXED_HEADERS, [
    // RCM announces the connection, then LSM logs the session. Different leaf names,
    // same tab — both must resolve even though detect() can only map one source column.
    { ...rcmRow("1149", { ts: "2026-03-10 09:00:00.000", address: "10.10.10.77" }), User: null, SessionID: null, Address: null },
    { ...lsmRow("21", { ts: "2026-03-10 09:00:01.000", address: "10.10.10.77", sessionId: "5" }), Param1: null, Param2: null, Param3: null },
    { ...lsmRow("22", { ts: "2026-03-10 09:00:03.000", address: "10.10.10.77", sessionId: "5" }), Param1: null, Param2: null, Param3: null },
  ]);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  const edge = res.edges.find((e) => e.source === "10.10.10.77" && e.target === "WKS-TARGET");
  assert.ok(edge, `expected a 10.10.10.77 edge from the mixed tab, got ${JSON.stringify(res.edges.map((e) => `${e.source}->${e.target}`))}`);
  assert.ok(res.rdpSessions.length >= 1, "expected the LSM pair to still form a session in a mixed tab");
});

test("LOCAL and empty source addresses are still rejected", () => {
  const res = run(LSM_HEADERS, [
    lsmRow("21", { ts: "2026-03-10 10:00:00.000", address: "LOCAL" }),
    lsmRow("22", { ts: "2026-03-10 10:00:01.000", address: "" }),
  ]);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  assert.equal(
    res.edges.filter((e) => e.target === "WKS-TARGET").length, 0,
    "console/local sessions must not create lateral edges",
  );
});

// Raw EVTX names the Kerberos failure code `Status`; only `SubStatus` was consulted,
// so ssTotal stayed 0 and the brute-force severity was permanently capped at medium.
test("raw-EVTX 4771 reads its failure code from Status, lifting brute force above medium", () => {
  const HEADERS = [
    "datetime", "RecordId", "EventID", "Provider", "Level", "Channel", "Computer", "Message",
    "IpAddress", "TargetUserName", "LogonType", "Status", "SessionID",
  ];
  const rows = [];
  for (let i = 0; i < 8; i++) {
    rows.push({
      datetime: `2026-03-10 13:0${i}:00.000`,
      RecordId: String(i + 1),
      EventID: "4771",
      Provider: "Microsoft-Windows-Security-Auditing",
      Level: "Information",
      Channel: "Security",
      Computer: "DC01",
      Message: "",
      IpAddress: "10.10.10.55",
      TargetUserName: "SEVENKINGDOMS\\jaime.lannister",
      LogonType: "3",
      Status: "0x18", // bad password — real guessing, not lockout/expiry noise
      SessionID: "",
    });
  }
  const { meta, ctx } = makeStub(HEADERS, rows);
  const res = getLateralMovement(meta, { excludeLocalLogons: true, excludeServiceAccounts: true }, ctx);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  const bf = res.findings.find((f) => /brute force/i.test(f.category) || /brute force/i.test(f.title));
  assert.ok(bf, `expected a Brute Force finding, got ${JSON.stringify(res.findings.map((f) => f.category))}`);
  assert.equal(bf.severity, "high", "0x18 (bad password) bursts should not be dampened to medium");
});

test("raw session IDs are recovered so distinct sessions do not collapse", () => {
  const res = run(LSM_HEADERS, [
    lsmRow("21", { ts: "2026-03-10 11:00:00.000", sessionId: "3", address: "10.10.10.55" }),
    lsmRow("23", { ts: "2026-03-10 11:10:00.000", sessionId: "3", address: "10.10.10.55" }),
    lsmRow("21", { ts: "2026-03-10 12:00:00.000", sessionId: "9", address: "10.10.10.55" }),
    lsmRow("23", { ts: "2026-03-10 12:10:00.000", sessionId: "9", address: "10.10.10.55" }),
  ]);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  assert.ok(
    res.rdpSessions.length >= 2,
    `two distinct session IDs should yield two sessions, got ${res.rdpSessions.length}`,
  );
});

test("generic Security 4625 Type 3 failures stay out of the RDP activity table", () => {
  const rows = Array.from({ length: 8 }, (_, i) => securityRow("4625", {
    ts: `2026-03-10 08:0${i}:00.000`,
    recordId: String(i + 1),
    logonType: "3",
  }));
  const res = run(SECURITY_HEADERS, rows);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  assert.equal(res.rdpSessions.length, 0, "network-logon failures are not RDP without RDP-specific corroboration");
  assert.ok(
    res.findings.some((finding) => /brute force/i.test(finding.category) || /brute force/i.test(finding.title)),
    "generic failures must remain available to the credential-attack detectors",
  );
});

test("Security 4625 Type 10 is direct failed-RDP evidence and is counted separately from sessions", () => {
  const res = run(SECURITY_HEADERS, [
    securityRow("4625", { logonType: "10" }),
  ]);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  assert.equal(res.rdpSessions.length, 1);
  assert.equal(res.rdpSessions[0].status, "failed");
  assert.equal(res.rdpSessions[0].evidenceLevel, "direct");
  assert.match(res.rdpSessions[0].evidenceBasis.join(" "), /4625 Logon Type 10/);
  assert.equal(res.stats.rdpSessionCount, 0);
  assert.equal(res.stats.rdpFailedAttemptCount, 1);
});

test("Security 4625 Type 3 becomes correlated RDP evidence only near a direct signal on the same pair", () => {
  const res = run(RDP_CORRELATION_HEADERS, [
    {
      ...securityRow("4625", { ts: "2026-03-10 08:00:00.000", logonType: "3" }),
      User: null, SessionID: null, Address: null, Param1: null, Param2: null, Param3: null,
    },
    {
      ...rcmRow("1149", { ts: "2026-03-10 08:00:10.000" }),
      IpAddress: null, TargetUserName: null, LogonType: null, SubStatus: null,
      User: null, SessionID: null, Address: null,
    },
  ]);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  const failed = res.rdpSessions.find((session) => session.status === "failed");
  assert.ok(failed, "the nearby Type 3 failure should be admitted as correlated RDP evidence");
  assert.equal(failed.evidenceLevel, "correlated");
  assert.match(failed.evidenceBasis.join(" "), /correlated with TerminalServices 1149/);
});

test("Security 4624 Type 7 alone is an unlock, not an RDP reconnect", () => {
  const res = run(SECURITY_HEADERS, [
    securityRow("4624", { logonType: "7" }),
  ]);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  assert.equal(res.rdpSessions.length, 0);
});

test("source-less lifecycle events attach by TerminalServices SessionID", () => {
  const res = run(LSM_HEADERS, [
    lsmRow("21", { ts: "2026-03-10 08:00:00.000", sessionId: "3", address: "10.10.10.55" }),
    lsmRow("24", { ts: "2026-03-10 12:00:00.000", sessionId: "3", address: "" }),
  ]);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  assert.equal(res.rdpSessions.length, 1);
  assert.equal(res.rdpSessions[0].status, "disconnected");
  assert.equal(res.rdpSessions[0].source, "10.10.10.55");
  assert.ok(res.rdpSessions[0].events.some((event) => event.eventId === "24"));
});

test("graph normalizes ports, rejects loopback artifacts, and conservatively merges short/FQDN aliases", () => {
  const res = run(SECURITY_HEADERS, [
    securityRow("4624", { ts: "2026-03-10 08:00:00.000", address: "WKS2390", computer: "APP01", logonType: "3" }),
    securityRow("4624", { ts: "2026-03-10 08:00:01.000", address: "WKS2390.orionhubs.local", computer: "APP01", logonType: "3" }),
    securityRow("4624", { ts: "2026-03-10 08:00:02.000", address: "10.2.10.113:3389", computer: "APP01", logonType: "3" }),
    securityRow("4624", { ts: "2026-03-10 08:00:03.000", address: "127.0.0.1:0", computer: "APP01", logonType: "3" }),
    securityRow("4624", { ts: "2026-03-10 08:00:04.000", address: "::1:0", computer: "APP01", logonType: "3" }),
  ]);

  assert.ok(!res.error, `analyzer returned an error: ${res.error}`);
  const shortEdge = res.edges.find((edge) => edge.source === "WKS2390" && edge.target === "APP01");
  assert.ok(shortEdge);
  assert.equal(shortEdge.count, 2);
  assert.ok(!res.nodes.some((node) => node.id === "WKS2390.ORIONHUBS.LOCAL"));
  assert.deepEqual(res.nodes.find((node) => node.id === "WKS2390").aliases, ["WKS2390.ORIONHUBS.LOCAL"]);
  assert.ok(res.edges.some((edge) => edge.source === "10.2.10.113" && edge.target === "APP01"));
  assert.ok(!res.nodes.some((node) => /^(?:127\.0\.0\.1|::1)/.test(node.id)));
});
