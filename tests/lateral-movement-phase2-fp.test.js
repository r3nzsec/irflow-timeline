// Phase 2 false-positive regressions for the lateral-movement analyzer.
//
//   L10 Remote Execution Sequence never checked the EXEC step's user, so any
//       heuristic execution on the host inside the window was published as a
//       critical "sequence by <auth user>"
//   L11 Concurrent RDP severity ignored source diversity — one admin with three
//       RDP windows open on one jump host was critical
//   L12 Off-hours was judged in UTC, so an Asia/Australia estate had its whole
//       working day scored as off-hours
//   L13 A single failure followed by a success was "high" for RDP and console
//       logons — i.e. one mistyped password
//   plus: stale-credential retry loops, and the service-account noise filter

const test = require("node:test");
const assert = require("node:assert/strict");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");

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
  return {
    meta: { db, headers, colMap, tabId: "lm-phase2" },
    ctx: { applyStandardFilters() {}, ensureIndex() {}, isChainsawLogonDataset: () => false, isHayabusaDataset: () => false },
  };
}

const SEC_HEADERS = [
  "datetime", "EventID", "Provider", "Channel", "Computer", "IpAddress",
  "TargetUserName", "TargetDomainName", "LogonType", "SubStatus", "Status", "ClientName", "ClientAddress",
];

function secRow(o) {
  return {
    datetime: o.ts, EventID: o.eid, Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security",
    Computer: o.computer || "SRV-APP01", IpAddress: o.ip || "10.10.10.55",
    TargetUserName: o.user || "arya.stark", TargetDomainName: o.domain || "SEVENKINGDOMS",
    LogonType: o.logonType || "3", SubStatus: o.subStatus || "", Status: o.status || "",
    ClientName: "", ClientAddress: "",
  };
}

// =================== L13: one typo is not a compromise ======================

test("L13: a single failed RDP logon followed by success is medium, not high", () => {
  const rows = [
    secRow({ eid: "4625", ts: "2026-03-10 09:00:00", logonType: "10", subStatus: "0xC000006A" }),
    secRow({ eid: "4624", ts: "2026-03-10 09:00:12", logonType: "10" }),
  ];
  const { meta, ctx } = makeStub(SEC_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);
  const cc = res.findings.filter((f) => f.category === "Credential Compromise");
  assert.equal(cc.length, 1, "still reported");
  assert.equal(cc[0].severity, "medium", "one mistyped password before an RDP session is not high severity");
});

test("L13: a single fail then success against a DC stays high", () => {
  const rows = [
    secRow({ eid: "4625", ts: "2026-03-10 09:00:00", computer: "DC01", logonType: "10", subStatus: "0xC000006A" }),
    secRow({ eid: "4624", ts: "2026-03-10 09:00:12", computer: "DC01", logonType: "10" }),
  ];
  const { meta, ctx } = makeStub(SEC_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);
  const cc = res.findings.filter((f) => f.category === "Credential Compromise");
  assert.equal(cc[0].severity, "high", "a domain controller target still warrants high");
});

test("L13: repeated fail->success clusters remain high", () => {
  const rows = [];
  for (let i = 0; i < 4; i++) {
    rows.push(secRow({ eid: "4625", ts: `2026-03-10 09:0${i}:00`, logonType: "10", subStatus: "0xC000006A" }));
    rows.push(secRow({ eid: "4624", ts: `2026-03-10 09:0${i}:20`, logonType: "10" }));
  }
  const { meta, ctx } = makeStub(SEC_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);
  const cc = res.findings.filter((f) => f.category === "Credential Compromise");
  assert.ok(cc.length > 0 && cc[0].severity === "high", `expected high for a repeated pattern, got ${cc[0]?.severity}`);
});

// ============= stale credential vs. brute force (Type 3 network) =============

test("a service retrying a changed password on a fixed cadence is not brute force", () => {
  // 12 failures, exactly 5 minutes apart, one account, network logon.
  const rows = [];
  for (let i = 0; i < 12; i++) {
    const mins = i * 5;
    const hh = String(9 + Math.floor(mins / 60)).padStart(2, "0");
    const mm = String(mins % 60).padStart(2, "0");
    rows.push(secRow({ eid: "4625", ts: `2026-03-10 ${hh}:${mm}:00`, logonType: "3", user: "backupjob", subStatus: "0xC000006A" }));
  }
  const { meta, ctx } = makeStub(SEC_HEADERS, rows);
  const res = getLateralMovement(meta, { excludeServiceAccounts: false }, ctx);
  const bf = res.findings.filter((f) => f.category === "Brute Force");
  for (const f of bf) {
    assert.equal(f.severity, "low", "a metronomic retry loop is a stale credential, not password guessing");
    assert.ok((f.evidencePills || []).some((p) => /stale credential/i.test(p.text)), "and it should say so");
  }
});

test("an irregular burst of the same volume is still scored as brute force", () => {
  const offsets = [0, 3, 7, 9, 22, 24, 25, 41, 43, 44, 46, 47];
  const rows = offsets.map((s) => secRow({
    eid: "4625", ts: `2026-03-10 09:00:${String(s).padStart(2, "0")}`, logonType: "3",
    user: "arya.stark", subStatus: "0xC000006A",
  }));
  const { meta, ctx } = makeStub(SEC_HEADERS, rows);
  const res = getLateralMovement(meta, {}, ctx);
  const bf = res.findings.filter((f) => f.category === "Brute Force");
  assert.ok(bf.some((f) => f.severity === "high"), "a burst inside one minute is guessing, not a retry loop");
});

// ================= service-account noise filter (domain side) ================

// `excludeServiceAccounts` governs the GRAPH: these identities must not create
// host-to-host edges. (They stay visible in the Accounts view, flagged, which is a
// deliberate visibility choice — the graph is what floods with them.)
const edgeUsers = (res) => new Set((res.edges || []).flatMap((e) => e.users || []).map((u) => String(u).toLowerCase()));

test("an IIS application-pool identity does not create lateral-movement edges", () => {
  // The username alone ("DefaultAppPool") is indistinguishable from a user account;
  // the DOMAIN is what identifies it, and the domain was never consulted.
  const rows = [];
  for (let i = 0; i < 6; i++) {
    rows.push(secRow({ eid: "4624", ts: `2026-03-10 09:0${i}:00`, user: "DefaultAppPool", domain: "IIS APPPOOL", logonType: "3" }));
  }
  rows.push(secRow({ eid: "4624", ts: "2026-03-10 09:30:00", user: "arya.stark", logonType: "3" }));
  const { meta, ctx } = makeStub(SEC_HEADERS, rows);
  const res = getLateralMovement(meta, { excludeServiceAccounts: true }, ctx);
  const users = edgeUsers(res);
  assert.ok(!users.has("defaultapppool"), "app-pool identities must not appear on graph edges");
  assert.ok(users.has("arya.stark"), "real accounts still graph");
});

test("Exchange health mailboxes and Entra sync accounts do not create edges", () => {
  const rows = [
    secRow({ eid: "4624", ts: "2026-03-10 09:00:00", user: "HealthMailbox0a1b2c3d4e5f6789", logonType: "3" }),
    secRow({ eid: "4624", ts: "2026-03-10 09:01:00", user: "MSOL_1a2b3c4d5e6f", logonType: "3" }),
    secRow({ eid: "4624", ts: "2026-03-10 09:02:00", user: "arya.stark", logonType: "3" }),
  ];
  const { meta, ctx } = makeStub(SEC_HEADERS, rows);
  const res = getLateralMovement(meta, { excludeServiceAccounts: true }, ctx);
  const users = edgeUsers(res);
  assert.ok(![...users].some((n) => n.startsWith("healthmailbox")), "Exchange probe mailboxes are noise");
  assert.ok(![...users].some((n) => n.startsWith("msol_")), "Entra Connect sync accounts are noise");
  assert.ok(users.has("arya.stark"), "real accounts are unaffected");
});

test("an account merely NAMED like a service account is not filtered", () => {
  // The patterns are anchored and require the generated hex suffix, so an attacker
  // cannot hide behind the name alone.
  const rows = [secRow({ eid: "4624", ts: "2026-03-10 09:00:00", user: "healthmailbox", logonType: "3" })];
  const { meta, ctx } = makeStub(SEC_HEADERS, rows);
  const res = getLateralMovement(meta, { excludeServiceAccounts: true }, ctx);
  assert.ok(edgeUsers(res).has("healthmailbox"), "a bare name is not a generated identity");
});

// =========================== L12: org timezone ==============================

const RDP_HEADERS = [...SEC_HEADERS];

function rdpSessionRows(startTs) {
  return [
    secRow({ eid: "4624", ts: startTs, logonType: "10", user: "arya.stark" }),
    secRow({ eid: "4634", ts: startTs.replace(/:\d\d$/, ":59"), logonType: "10", user: "arya.stark" }),
  ];
}

test("L12: a 09:00 local logon in UTC+8 is not off-hours once the estate timezone is set", () => {
  // 09:00 in UTC+8 is 01:00 UTC — inside the default 22:00-06:00 UTC off-hours window.
  const rows = rdpSessionRows("2026-03-10 01:00:00");
  const utc = getLateralMovement(...(() => { const { meta, ctx } = makeStub(RDP_HEADERS, rows); return [meta, {}, ctx]; })());
  const local = getLateralMovement(...(() => { const { meta, ctx } = makeStub(RDP_HEADERS, rows); return [meta, { orgTimezoneOffsetMinutes: 480 }, ctx]; })());
  const flagged = (res) => (res.rdpSessions || []).some((s) => (s.suspicionFlags || s.flags || []).some((f) => /off-hours/i.test(f)));
  assert.equal(flagged(utc), true, "precondition: judged off-hours in UTC");
  assert.equal(flagged(local), false, "with the estate on UTC+8 this is 09:00 on a working day");
});

test("L12: a genuine 02:00 local logon is still off-hours with the offset applied", () => {
  // 02:00 in UTC+8 is 18:00 UTC the previous day — inside business hours in UTC.
  const rows = rdpSessionRows("2026-03-09 18:00:00");
  const { meta, ctx } = makeStub(RDP_HEADERS, rows);
  const res = getLateralMovement(meta, { orgTimezoneOffsetMinutes: 480 }, ctx);
  const flagged = (res.rdpSessions || []).some((s) => (s.suspicionFlags || s.flags || []).some((f) => /off-hours/i.test(f)));
  assert.equal(flagged, true, "02:00 local is off-hours no matter what UTC says");
});
