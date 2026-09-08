// Characterization tests for the credential-attack detectors that were extracted
// from getLateralMovement() into detectors/credential-attacks.js
// (Kerberoasting T1558.003, AS-REP Roasting T1558.004).
//
// These detectors previously had no direct coverage — the existing suite only
// exercised the Accounts tab via 4769 events, not the Kerberoasting/AS-REP
// FINDINGS. This file pins their observable behavior so the decomposition (and
// future refactors of the credential-attack module) stay behavior-preserving.

const test = require("node:test");
const assert = require("node:assert/strict");
const { getLateralMovement } = require("../electron/analyzers/lateral-movement");

const HEADERS = [
  "TimeCreated", "EventId", "Computer", "IpAddress", "TargetUserName", "LogonType",
  "Channel", "Provider", "TicketEncryptionType", "ServiceName", "TicketOptions", "PreAuthType",
];

// Stub DB that understands the three query shapes getLateralMovement emits:
//   1. main query:        SELECT ... cN as [alias] ... FROM data WHERE cEID IN (?,..)
//   2. secondary scan:    SELECT data.rowid as _rid, ... as _alltext ... (process/service scan)
//   3. credential detect: SELECT data.rowid as _rid, cN as _enc ... FROM data WHERE cM = '4769'
function makeStub(headers, rows) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const rowsByCN = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    headers.forEach((h) => { out[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return out;
  });

  // Single-EID credential query: WHERE cN = 'VALUE', aliases like `cN as _enc`, no _alltext.
  function credentialQuery(sql) {
    if (!/data\.rowid\s+as\s+_rid/i.test(sql)) return null;
    if (/\bas\s+_alltext/i.test(sql)) return null;
    const wh = sql.match(/WHERE\s+(c\d+)\s*=\s*'([^']+)'/i);
    if (!wh) return null;
    const [, filterCol, filterVal] = wh;
    const aliasPairs = [...sql.matchAll(/(data\.rowid|c\d+)\s+as\s+(_[a-zA-Z0-9_]+)/g)];
    const limitMatch = sql.match(/LIMIT\s+(\d+)/i);
    const limit = limitMatch ? Number(limitMatch[1]) : rowsByCN.length;
    return rowsByCN
      .filter((r) => String(r[filterCol] == null ? "" : r[filterCol]) === filterVal)
      .slice(0, limit)
      .map((r) => {
        const out = {};
        for (const [, srcExpr, alias] of aliasPairs) {
          out[alias] = srcExpr === "data.rowid" ? r._rowid : r[srcExpr];
        }
        return out;
      });
  }

  function aliasRows(sql) {
    const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    if (aliasMatches.length === 0) return null;
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
          const cred = credentialQuery(sql);
          if (cred) return cred;
          const aliased = aliasRows(sql);
          if (aliased) return aliased;
          return [];
        },
      };
    },
  };

  const meta = { db, headers, colMap, tabId: "lm-cred-test" };
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

function krbRow(ts, user, spn, enc) {
  return {
    TimeCreated: ts, EventId: "4769", Computer: "DC01", IpAddress: "10.0.0.9",
    TargetUserName: user, LogonType: "", Channel: "Security",
    Provider: "Microsoft-Windows-Security-Auditing",
    TicketEncryptionType: enc, ServiceName: spn, TicketOptions: "0x40810000", PreAuthType: "",
  };
}
function asrepRow(ts, user, preAuth, enc) {
  return {
    TimeCreated: ts, EventId: "4768", Computer: "DC01", IpAddress: "10.0.0.9",
    TargetUserName: user, LogonType: "", Channel: "Security",
    Provider: "Microsoft-Windows-Security-Auditing",
    TicketEncryptionType: enc, ServiceName: "krbtgt", TicketOptions: "", PreAuthType: preAuth,
  };
}

test("Kerberoasting: RC4 burst across 5+ distinct SPNs by one user fires a T1558.003 finding", () => {
  const rows = [
    // attacker requests 5 distinct non-common SPNs with RC4 (0x17) in a 5-minute burst
    krbRow("2026-03-10T08:00:00Z", "CORP\\attacker", "MSSQLSvc/sql01:1433", "0x17"),
    krbRow("2026-03-10T08:01:00Z", "CORP\\attacker", "FTPSVC/ftp01", "0x17"),
    krbRow("2026-03-10T08:02:00Z", "CORP\\attacker", "MSSQLSvc/sql02:1433", "0x17"),
    krbRow("2026-03-10T08:03:00Z", "CORP\\attacker", "FTPSVC/ftp02", "0x17"),
    krbRow("2026-03-10T08:04:00Z", "CORP\\attacker", "MSSQLSvc/sql03:1433", "0x17"),
    // AES noise (0x12) so the RC4 ratio stays below the legacy-env dampening threshold
    krbRow("2026-03-10T07:00:00Z", "CORP\\alice", "HOST/ws01", "0x12"),
    krbRow("2026-03-10T07:01:00Z", "CORP\\bob", "HOST/ws02", "0x12"),
    krbRow("2026-03-10T07:02:00Z", "CORP\\carol", "HOST/ws03", "0x12"),
    krbRow("2026-03-10T07:03:00Z", "CORP\\dave", "HOST/ws04", "0x12"),
    krbRow("2026-03-10T07:04:00Z", "CORP\\erin", "HOST/ws05", "0x12"),
    krbRow("2026-03-10T07:05:00Z", "CORP\\frank", "HOST/ws06", "0x12"),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, {}, ctx);
  const krb = result.findings.filter((f) => f.category === "Kerberoasting");
  assert.equal(krb.length, 1, "exactly one Kerberoasting finding");
  assert.equal(krb[0].mitre, "T1558.003");
  assert.ok(["critical", "high", "medium"].includes(krb[0].severity), "non-low severity");
  assert.deepEqual(krb[0].users, ["CORP\\attacker"]);
  assert.ok(krb[0].evidencePills.some((p) => /RC4/.test(p.text)), "RC4 evidence pill present");
});

test("Kerberoasting: fewer than 3 SPNs does NOT fire (FP control)", () => {
  const rows = [
    krbRow("2026-03-10T08:00:00Z", "CORP\\svcuser", "MSSQLSvc/sql01:1433", "0x17"),
    krbRow("2026-03-10T08:01:00Z", "CORP\\svcuser", "MSSQLSvc/sql02:1433", "0x17"),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, {}, ctx);
  assert.equal(result.findings.filter((f) => f.category === "Kerberoasting").length, 0);
});

test("AS-REP Roasting: PreAuthType=0 on an account fires a T1558.004 finding", () => {
  const rows = [
    asrepRow("2026-03-10T08:00:00Z", "CORP\\victim", "0", "0x17"),
    asrepRow("2026-03-10T08:05:00Z", "CORP\\victim", "0", "0x17"),
    // normal pre-auth (type 2) AES requests as denominator noise
    asrepRow("2026-03-10T07:00:00Z", "CORP\\alice", "2", "0x12"),
    asrepRow("2026-03-10T07:01:00Z", "CORP\\bob", "2", "0x12"),
    asrepRow("2026-03-10T07:02:00Z", "CORP\\carol", "2", "0x12"),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, {}, ctx);
  const ar = result.findings.filter((f) => f.category === "AS-REP Roasting");
  assert.equal(ar.length, 1, "exactly one AS-REP finding");
  assert.equal(ar[0].mitre, "T1558.004");
  assert.deepEqual(ar[0].users, ["CORP\\victim"]);
});

test("Credential detectors honor disabledDetectors", () => {
  const rows = [
    krbRow("2026-03-10T08:00:00Z", "CORP\\attacker", "MSSQLSvc/sql01:1433", "0x17"),
    krbRow("2026-03-10T08:01:00Z", "CORP\\attacker", "FTPSVC/ftp01", "0x17"),
    krbRow("2026-03-10T08:02:00Z", "CORP\\attacker", "MSSQLSvc/sql02:1433", "0x17"),
    krbRow("2026-03-10T08:03:00Z", "CORP\\attacker", "FTPSVC/ftp02", "0x17"),
    krbRow("2026-03-10T08:04:00Z", "CORP\\attacker", "MSSQLSvc/sql03:1433", "0x17"),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, { disabledDetectors: ["kerberoast"] }, ctx);
  assert.equal(result.findings.filter((f) => f.category === "Kerberoasting").length, 0);
});

test("Kerberoasting does not fire on machine-account SPNs or krbtgt", () => {
  const rows = [
    krbRow("2026-03-10T08:00:00Z", "jsmith@CORP.LOCAL", "FS01$", "0x17"),
    krbRow("2026-03-10T08:01:00Z", "jsmith@CORP.LOCAL", "FS02$", "0x17"),
    krbRow("2026-03-10T08:02:00Z", "jsmith@CORP.LOCAL", "PRN01$", "0x17"),
    krbRow("2026-03-10T08:03:00Z", "jsmith@CORP.LOCAL", "krbtgt", "0x17"),
    krbRow("2026-03-10T08:04:00Z", "WKS01$@CORP.LOCAL", "MSSQLSvc/sql01:1433", "0x17"),
  ];
  const { meta, ctx } = makeStub(HEADERS, rows);
  const result = getLateralMovement(meta, {}, ctx);
  assert.equal(result.findings.filter((f) => f.category === "Kerberoasting").length, 0);
});
