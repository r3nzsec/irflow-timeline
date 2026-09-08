// Phase 3 regressions: detections that could never fire before.
//
//   L4  password spray required MANY TARGETS and explicitly discarded the
//       many-users case — i.e. it dropped textbook T1110.003 against a DC
//   L5  4624 Type 9 (NewCredentials) was deleted by the local-logon filter, so
//       runas /netonly and overpass-the-hash were invisible; LogonProcessName and
//       AuthenticationPackage were never read at all
//   L14 loopback sources were discarded before any detector, so RDP forwarded
//       through an SSH/chisel/ngrok tunnel produced nothing
//   L15 with NLA on, a failed RDP logon is a Security 4625 LogonType 3 — the only
//       event that names the protocol is RdpCoreTS 140, which was unused
//   L16 4672 was tied to a logon by (user, host, ±1s) instead of LogonId
//   L18 5145 AccessMask was ignored, so a tool DROP to ADMIN$ scored the same as a read
//   L19 shadow detection was keyed on LSM 20/32-35 instead of RCM/Admin 20503/20504

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
    meta: { db, headers, colMap, tabId: "lm-phase3" },
    ctx: { applyStandardFilters() {}, ensureIndex() {}, isChainsawLogonDataset: () => false, isHayabusaDataset: () => false },
  };
}

const H = [
  "datetime", "EventID", "Provider", "Channel", "Computer", "IpAddress", "WorkstationName",
  "TargetUserName", "LogonType", "LogonProcessName", "AuthenticationPackageName",
  "TargetLogonId", "SubjectLogonId", "ShareName", "RelativeTargetName", "AccessMask", "SubStatus",
];

function row(o) {
  return {
    datetime: o.ts, EventID: o.eid,
    Provider: o.prov || "Microsoft-Windows-Security-Auditing",
    Channel: o.ch || "Security",
    Computer: o.computer || "SRV-APP01",
    IpAddress: o.ip || "", WorkstationName: o.ws || "",
    TargetUserName: o.user || "", LogonType: o.lt || "",
    LogonProcessName: o.lp || "", AuthenticationPackageName: o.ap || "",
    TargetLogonId: o.lid || "", SubjectLogonId: o.slid || "",
    ShareName: o.share || "", RelativeTargetName: o.rtn || "", AccessMask: o.am || "",
    SubStatus: o.subStatus || "",
  };
}
const run = (rows, opts = {}) => {
  const { meta, ctx } = makeStub(H, rows);
  return getLateralMovement(meta, opts, ctx);
};
const byCategory = (res, cat) => (res.findings || []).filter((f) => f.category === cat);

// ============================ L4: account spray =============================

test("L4: one source spraying 12 accounts at a single DC is detected", () => {
  // The canonical T1110.003 shape: many ACCOUNTS, one target, one attempt each.
  // The old rule required 5+ distinct TARGETS and then discarded windows with many
  // users, so this produced no spray finding at all.
  const rows = [];
  for (let i = 0; i < 12; i++) {
    rows.push(row({ eid: "4625", ts: `2026-03-10 09:${String(i).padStart(2, "0")}:00`, computer: "DC01", ip: "10.10.10.66", user: `user${i}`, lt: "3", subStatus: "0xC000006A" }));
  }
  const spray = byCategory(run(rows), "Password Spray");
  assert.equal(spray.length, 1, "expected exactly one spray finding");
  assert.match(spray[0].title, /12 accounts/);
  assert.ok(["high", "critical"].includes(spray[0].severity), `expected high/critical, got ${spray[0].severity}`);
});

test("L4: a handful of accounts failing normally is not a spray", () => {
  const rows = [];
  for (let i = 0; i < 3; i++) {
    rows.push(row({ eid: "4625", ts: `2026-03-10 09:0${i}:00`, computer: "DC01", ip: "10.10.10.66", user: `user${i}`, lt: "3", subStatus: "0xC000006A" }));
  }
  assert.equal(byCategory(run(rows), "Password Spray").length, 0);
});

test("L4: the original many-targets shape still fires", () => {
  const rows = [];
  for (let i = 0; i < 6; i++) {
    rows.push(row({ eid: "4625", ts: `2026-03-10 09:0${i}:00`, computer: `SRV-0${i}`, ip: "10.10.10.66", user: "svc-scan", lt: "3", subStatus: "0xC000006A" }));
  }
  const spray = byCategory(run(rows, { excludeServiceAccounts: false }), "Password Spray");
  assert.equal(spray.length, 1);
  assert.match(spray[0].title, /6 targets/);
});

// ================== L5: Type 9 / alternate credentials ======================

test("L5: a Type 9 logon is no longer deleted by the local-logon filter", () => {
  const rows = [
    row({ eid: "4624", ts: "2026-03-10 09:00:00", computer: "WKS-01", ws: "WKS-01", user: "admin.tyrion", lt: "9", lp: "seclogo", ap: "Negotiate", lid: "0x5a5a" }),
  ];
  const alt = byCategory(run(rows), "Alternate Credentials");
  assert.equal(alt.length, 1, "the NewCredentials logon must survive and be reported");
  assert.match(alt[0].description, /seclogo/, "the logon process must be captured");
  assert.equal(alt[0].severity, "low", "a plain runas with no follow-on is only a lead");
});

test("L5: alternate credentials followed by an outbound logon is the overpass-the-hash shape", () => {
  const rows = [
    row({ eid: "4624", ts: "2026-03-10 09:00:00", computer: "WKS-01", ws: "WKS-01", user: "admin.tyrion", lt: "9", lp: "seclogo", ap: "Negotiate" }),
    row({ eid: "4624", ts: "2026-03-10 09:05:00", computer: "DC01", ws: "WKS-01", ip: "10.10.10.20", user: "admin.tyrion", lt: "3", ap: "NTLM" }),
  ];
  const alt = byCategory(run(rows), "Alternate Credentials");
  assert.equal(alt.length, 1);
  assert.equal(alt[0].severity, "critical", "the credentials were then used against a DC");
  assert.equal(alt[0].mitre, "T1550.002");
  assert.match(alt[0].description, /DC01/);
});

test("L5: an ordinary interactive logon on the same host is unaffected", () => {
  const rows = [row({ eid: "4624", ts: "2026-03-10 09:00:00", computer: "WKS-01", ws: "WKS-01", user: "arya", lt: "2" })];
  assert.equal(byCategory(run(rows), "Alternate Credentials").length, 0);
});

// ========================= L14: tunnelled RDP ===============================

test("L14: an RDP session whose client address is loopback is reported as tunnelled", () => {
  const rows = [
    row({ eid: "4624", ts: "2026-03-10 09:00:00", computer: "SRV-JUMP", ip: "127.0.0.1", user: "attacker", lt: "10" }),
    row({ eid: "4634", ts: "2026-03-10 09:30:00", computer: "SRV-JUMP", ip: "127.0.0.1", user: "attacker", lt: "10" }),
  ];
  const tun = byCategory(run(rows), "Tunnelled RDP");
  assert.equal(tun.length, 1, "a loopback RDP client cannot exist without a port forward");
  assert.equal(tun[0].severity, "high", "a completed session, not just a connection attempt");
  assert.match(tun[0].description, /tunnel/i);
});

test("L14: a loopback source on a non-RDP event is still ignored", () => {
  const rows = [row({ eid: "4624", ts: "2026-03-10 09:00:00", computer: "SRV-APP01", ip: "127.0.0.1", user: "svc", lt: "5" })];
  assert.equal(byCategory(run(rows), "Tunnelled RDP").length, 0);
});

// ==================== L15: RDP brute force behind NLA =======================

const RDPCORE_CH = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
const RDPCORE_PROV = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS";

test("L15: RdpCoreTS 140 bursts are reported as RDP brute force", () => {
  const rows = [];
  for (let i = 0; i < 8; i++) {
    rows.push(row({ eid: "140", ts: `2026-03-10 09:0${i}:00`, computer: "SRV-RDP01", ip: "10.10.10.77", ch: RDPCORE_CH, prov: RDPCORE_PROV }));
  }
  const rdp = byCategory(run(rows), "RDP Brute Force");
  assert.equal(rdp.length, 1);
  assert.match(rdp[0].description, /Network Level Authentication/);
});

test("L15: a matching Security 4625 Type 3 burst is relabelled as RDP, not Network", () => {
  const rows = [];
  for (let i = 0; i < 8; i++) {
    rows.push(row({ eid: "140", ts: `2026-03-10 09:0${i}:00`, computer: "SRV-RDP01", ip: "10.10.10.77", ch: RDPCORE_CH, prov: RDPCORE_PROV }));
    rows.push(row({ eid: "4625", ts: `2026-03-10 09:0${i}:02`, computer: "SRV-RDP01", ip: "10.10.10.77", user: "admin", lt: "3", subStatus: "0xC000006A" }));
  }
  const bf = byCategory(run(rows), "Brute Force");
  assert.ok(bf.length > 0, "the Security-log burst is still reported");
  assert.ok(bf.some((f) => /RDP/.test(f.title)), `expected the RDP protocol label, got ${bf.map((f) => f.title).join(" | ")}`);
});

test("L15: a Type 3 burst with no RdpCoreTS evidence stays labelled Network", () => {
  const rows = [];
  for (let i = 0; i < 8; i++) {
    rows.push(row({ eid: "4625", ts: `2026-03-10 09:0${i}:00`, computer: "SRV-FILE01", ip: "10.10.10.88", user: "admin", lt: "3", subStatus: "0xC000006A" }));
  }
  const bf = byCategory(run(rows), "Brute Force");
  assert.ok(bf.length > 0);
  assert.ok(!bf.some((f) => /RDP/.test(f.title)), "no RDP evidence means no RDP claim");
});

// ===================== L19: shadow via RCM/Admin 20503 ======================

test("L19: RemoteConnectionManager/Admin 20503 is detected as session shadowing", () => {
  const rows = [
    row({ eid: "20503", ts: "2026-03-10 10:00:00", computer: "SRV-APP01", ip: "10.10.10.90", user: "helpdesk",
      ch: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin",
      prov: "Microsoft-Windows-TerminalServices-RemoteConnectionManager" }),
  ];
  const sh = byCategory(run(rows), "RDP Session Shadowing");
  assert.equal(sh.length, 1);
  assert.match(sh[0].description, /no new logon|20503/);
});

// ==================== L18: 5145 AccessMask (tool drop) ======================

test("L18: a WRITE to ADMIN$ is critical, a read is not", () => {
  const writeRows = [];
  for (let i = 0; i < 3; i++) {
    writeRows.push(row({ eid: "5145", ts: `2026-03-10 11:0${i}:00`, computer: "SRV-APP01", ip: "10.10.10.55",
      user: "admin.tyrion", share: "\\\\*\\ADMIN$", rtn: "PSEXESVC.exe", am: "0x2" }));
  }
  const write = byCategory(run(writeRows), "Admin Share Access");
  assert.ok(write.length > 0, "expected an admin-share finding");
  assert.equal(write[0].severity, "critical", "placing a file on ADMIN$ is a tool drop");
  assert.ok((write[0].evidencePills || []).some((p) => /write access/i.test(p.text)));

  const readRows = [];
  for (let i = 0; i < 3; i++) {
    readRows.push(row({ eid: "5145", ts: `2026-03-10 11:0${i}:00`, computer: "SRV-APP01", ip: "10.10.10.55",
      user: "backupsvc", share: "\\\\*\\C$", rtn: "reports\\q1.xlsx", am: "0x1" }));
  }
  const read = byCategory(run(readRows, { excludeServiceAccounts: false }), "Admin Share Access");
  assert.ok(read.length > 0);
  assert.notEqual(read[0].severity, "critical", "reading a file over C$ is a backup agent");
});

// ================= L16: 4672 correlated by LogonId, not time =================

test("L16: the admin flag follows the LogonId, not whichever logon shared the second", () => {
  // Two concurrent logons for one user at the SAME second on the same host: an RDP
  // session (0xAAAA) and a network logon (0xBBBB). Only the network one was granted
  // privileges. Time-window matching cannot tell them apart; LogonId can.
  const rows = [
    row({ eid: "4624", ts: "2026-03-10 09:00:00", computer: "SRV-APP01", ip: "10.10.10.55", user: "arya", lt: "10", lid: "0xAAAA" }),
    row({ eid: "4624", ts: "2026-03-10 09:00:00", computer: "SRV-APP01", ip: "10.10.10.56", user: "arya", lt: "3", lid: "0xBBBB" }),
    row({ eid: "4672", ts: "2026-03-10 09:00:00", computer: "SRV-APP01", user: "arya", slid: "0xBBBB" }),
  ];
  const res = run(rows);
  const acct = (res.accounts || []).find((a) => /arya/i.test(a.user || ""));
  assert.ok(acct, "expected the account");
  assert.equal(acct.adminPrivilegeCount, 1, "exactly ONE logon was privileged — not both, not zero");
});
