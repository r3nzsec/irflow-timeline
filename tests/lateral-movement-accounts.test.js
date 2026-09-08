// Characterization tests for the per-user accounts aggregation extracted from
// getLateralMovement() into assemble/accounts.js. Pins: account building from
// events, raw vs scoped count surfacing, non-user rejection, classification,
// finding linkage, and that scoring uses the lateral-movement-SCOPED counts so
// host-wide local/service 4672/4648 noise can't inflate suspicion.

const test = require("node:test");
const assert = require("node:assert/strict");
const { aggregateAccounts } = require("../electron/analyzers/lateral-movement/assemble/accounts");

function state(over = {}) {
  return {
    timeOrdered: [], rdpSessions: [], findings: [],
    userEventCounts: new Map(), userEventCountsScoped: new Map(),
    userEventOriginalName: new Map(), _outlierHosts: new Set(), privLogonEvents: [],
    ...over,
  };
}
function evt(user, eventId, over = {}) {
  return { user, eventId, source: "10.0.0.5", target: "HOST01", logonType: "3", ts: "2026-03-10T08:00:00Z", ...over };
}
// Build the (raw, scoped, names) count maps for a single user in one shot.
function counts(user, { raw = {}, scoped = {} } = {}) {
  const key = user.toUpperCase();
  const toMap = (obj) => new Map(Object.entries(obj).map(([k, v]) => [k, v]));
  return {
    userEventCounts: new Map([[key, toMap(raw)]]),
    userEventCountsScoped: new Map([[key, toMap(scoped)]]),
    userEventOriginalName: new Map([[key, user]]),
  };
}

test("builds an account from logon events: success/failure counts + source/target hosts", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [evt("CORP\\attacker", "4624"), evt("CORP\\attacker", "4625", { ts: "2026-03-10T07:00:00Z" })],
  }));
  const a = accounts.find((x) => x.user === "CORP\\attacker");
  assert.ok(a, "account created");
  assert.equal(a.successCount, 1);
  assert.equal(a.failureCount, 1);
  assert.ok(a.sourceHosts.includes("10.0.0.5"));
  assert.ok(a.targetHosts.includes("HOST01"));
});

test("surfaces users that exist ONLY in raw event counts (Kerberos-only on a DC log)", () => {
  const accounts = aggregateAccounts(state({
    ...counts("CORP\\krbuser", { raw: { "4769": 3 } }), // no scoped entry
  }));
  const a = accounts.find((x) => x.user === "CORP\\krbuser");
  assert.ok(a, "kerberos-only user surfaced via Pass 4");
  assert.equal(a.kerberosCountRaw, 3, "raw count preserved");
  assert.equal(a.kerberosCount, 0, "scoped count is 0 — no lateral-movement-relevant Kerberos");
  assert.equal(a.successCount, 0);
});

test("scoped counts are the primary value; raw is kept separately", () => {
  const accounts = aggregateAccounts(state({
    ...counts("CORP\\anna", { raw: { "4648": 265, "4672": 888 }, scoped: { "4648": 5, "4672": 0 } }),
  }));
  const a = accounts.find((x) => x.user === "CORP\\anna");
  assert.equal(a.explicitCredsCount, 5, "Explicit column shows scoped");
  assert.equal(a.explicitCredsCountRaw, 265, "raw host-wide total retained");
  assert.equal(a.adminPrivilegeCount, 0, "scoped 4672 is 0 (all host-wide were local/service)");
  assert.equal(a.adminPrivilegeCountRaw, 888);
});

test("host-wide local/service 4672/4648 do NOT inflate the suspicion score", () => {
  const accounts = aggregateAccounts(state({
    ...counts("LOCALUSER", { raw: { "4672": 888, "4648": 892 }, scoped: {} }),
  }));
  const a = accounts.find((x) => x.user === "LOCALUSER");
  // No scoped admin/explicit → neither the +20 admin nor +12 explicit bonus fires.
  assert.equal(a.suspicionScore, 0, "raw-only privilege/cred activity scores 0");
  assert.ok(!a.flags.some((f) => /Admin privilege/.test(f)), "no 4672 admin flag from raw-only");
  assert.ok(!a.flags.some((f) => /Explicit creds/.test(f)), "no explicit-cred flag from raw-only");
});

test("scoped explicit creds DO score and flag", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [evt("CORP\\attacker", "4624")],
    ...counts("CORP\\attacker", { raw: { "4648": 9 }, scoped: { "4648": 9 } }),
  }));
  const a = accounts.find((x) => x.user === "CORP\\attacker");
  assert.equal(a.explicitCredsCount, 9);
  assert.ok(a.flags.some((f) => /Explicit creds \(9x 4648\)/.test(f)));
  assert.ok(a.suspicionScore >= 12, "explicit-cred bonus applied");
});

test("correlates 4672 to a scoped network logon → ADMIN signal recovered (type 3, non-RDP)", () => {
  const T = "2024-11-12T09:05:44Z";
  const accounts = aggregateAccounts(state({
    timeOrdered: [evt("CORP\\attacker", "4624", { ts: T, logonType: "3", target: "DC01" })],
    privLogonEvents: [{ userKey: "CORP\\ATTACKER", host: "DC01", ts: T }],
  }));
  const a = accounts.find((x) => x.user === "CORP\\attacker");
  assert.equal(a.adminPrivilegeCount, 1, "privileged lateral logon counted via correlation");
  assert.ok(a.flags.some((f) => f === "Admin privilege (1x 4672)"));
  assert.ok(a.suspicionScore >= 20, "admin bonus recovered for network-logon admin");
});

test("correlation tolerates a ±1s skew between 4624 and 4672", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [evt("CORP\\attacker", "4624", { ts: "2024-11-12T09:05:44Z", target: "DC01" })],
    privLogonEvents: [{ userKey: "CORP\\ATTACKER", host: "DC01", ts: "2024-11-12T09:05:45Z" }],
  }));
  assert.equal(accounts.find((x) => x.user === "CORP\\attacker").adminPrivilegeCount, 1);
});

test("4672 NOT correlated when host or time differ → no ADMIN inflation", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [evt("CORP\\attacker", "4624", { ts: "2024-11-12T09:05:44Z", target: "DC01" })],
    privLogonEvents: [
      { userKey: "CORP\\ATTACKER", host: "FILESRV", ts: "2024-11-12T09:05:44Z" }, // different host
      { userKey: "CORP\\ATTACKER", host: "DC01", ts: "2024-11-12T11:00:00Z" },    // far in time
    ],
  }));
  const a = accounts.find((x) => x.user === "CORP\\attacker");
  assert.equal(a.adminPrivilegeCount, 0, "no spurious correlation");
  assert.ok(!a.flags.some((f) => /4672/.test(f)));
});

test("host-wide local 4672 (no scoped 4624 to match) cannot re-inflate via correlation", () => {
  // localuser logs on locally (no scoped 4624 in timeOrdered) but has 888 raw 4672
  // and a pile of 4672 occurrences — none correlate, so ADMIN stays 0.
  const accounts = aggregateAccounts(state({
    ...counts("LOCALUSER", { raw: { "4672": 888 } }),
    privLogonEvents: Array.from({ length: 888 }, () => ({ userKey: "LOCALUSER", host: "WS01", ts: "2024-11-12T09:00:00Z" })),
  }));
  const a = accounts.find((x) => x.user === "LOCALUSER");
  assert.equal(a.adminPrivilegeCount, 0, "no scoped 4624 → no correlation");
  assert.equal(a.adminPrivilegeCountRaw, 888, "raw total still surfaced");
  assert.equal(a.suspicionScore, 0);
});

test("RDP-only admin uses the RDP flag, not a fake 4672 count", () => {
  const accounts = aggregateAccounts(state({
    rdpSessions: [{ user: "CORP\\rdpadmin", source: "10.0.0.5", target: "DC01", hasAdmin: true, suspicionScore: 10, status: "connected" }],
  }));
  const a = accounts.find((x) => x.user === "CORP\\rdpadmin");
  assert.equal(a.adminPrivilegeCount, 0, "no scoped 4672 events");
  assert.equal(a.rdpAdminCount, 1);
  assert.ok(a.flags.some((f) => f === "Admin via RDP (1 session)"), "RDP-admin flag, not 'Nx 4672'");
  assert.ok(!a.flags.some((f) => /4672/.test(f)), "never prints an RDP count as a 4672 count");
});

test("source/target breakdown partitions distinct hosts by channel", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [
      evt("CORP\\u", "4624", { source: "SRC-LOGON", target: "T1" }),
      evt("CORP\\u", "4648", { source: "SRC-EXPL", target: "T-EXPL" }),
      evt("CORP\\u", "4776", { source: "SRC-NTLM", target: "T1" }),
    ],
    rdpSessions: [{ user: "CORP\\u", source: "SRC-RDP", target: "T-RDP", status: "connected", suspicionScore: 0 }],
  }));
  const a = accounts.find((x) => x.user === "CORP\\u");
  assert.equal(a.sourceHosts.length, 4, "4 distinct sources aggregated");
  assert.deepEqual(a.sourceBreakdown, { logon: 1, explicit: 1, rdp: 1, other: 1 }, "NTLM source falls into 'other'");
  // targets: T1 (logon — also touched by 4776 but logon wins), T-EXPL (explicit), T-RDP (rdp)
  assert.equal(a.targetHosts.length, 3);
  assert.deepEqual(a.targetBreakdown, { logon: 1, explicit: 1, rdp: 1, other: 0 });
  // Breakdown counts sum to the aggregate (partition, not overlapping channels)
  const sb = a.sourceBreakdown;
  assert.equal(sb.logon + sb.explicit + sb.rdp + sb.other, a.sourceHosts.length);
});

test("a host reached via multiple channels counts once (logon precedence)", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [evt("CORP\\u", "4624", { source: "JUMP01", target: "DC01" })],
    rdpSessions: [{ user: "CORP\\u", source: "JUMP01", target: "DC01", status: "connected", suspicionScore: 0 }],
  }));
  const a = accounts.find((x) => x.user === "CORP\\u");
  assert.equal(a.sourceHosts.length, 1, "JUMP01 deduped in the aggregate");
  assert.deepEqual(a.sourceBreakdown, { logon: 1, explicit: 0, rdp: 0, other: 0 }, "counted once, as logon");
});

test("explicit-cred-only / RDP-only hosts explain Sources > Successes", () => {
  // 2 successful logons but 3 sources — the extra source is an explicit-cred (4648)
  const accounts = aggregateAccounts(state({
    timeOrdered: [
      evt("CORP\\u", "4624", { source: "S1", target: "T1" }),
      evt("CORP\\u", "4624", { source: "S2", target: "T1", ts: "2026-03-10T08:01:00Z" }),
      evt("CORP\\u", "4648", { source: "S3", target: "T2", ts: "2026-03-10T08:02:00Z" }),
    ],
  }));
  const a = accounts.find((x) => x.user === "CORP\\u");
  assert.equal(a.successCount, 2);
  assert.equal(a.sourceHosts.length, 3, "Sources exceeds Successes");
  assert.equal(a.sourceBreakdown.logon, 2);
  assert.equal(a.sourceBreakdown.explicit, 1, "the extra source is explained as explicit-cred");
});

test("First/Last Seen extends to RDP session window (not just logon events)", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [evt("CORP\\u", "4624", { ts: "2024-11-12T09:00:00Z" })],
    rdpSessions: [{ user: "CORP\\u", source: "10.0.0.5", target: "DC01", status: "ended",
      startTime: "2024-11-12T08:00:00Z", endTime: "2024-11-12T10:00:00Z", suspicionScore: 0 }],
  }));
  const a = accounts.find((x) => x.user === "CORP\\u");
  assert.equal(a.firstSeen, "2024-11-12T08:00:00Z", "RDP start widens firstSeen earlier than the logon");
  assert.equal(a.lastSeen, "2024-11-12T10:00:00Z", "RDP end widens lastSeen later than the logon");
});

test("an RDP-only account still gets a First/Last Seen window", () => {
  const accounts = aggregateAccounts(state({
    rdpSessions: [{ user: "CORP\\rdponly", source: "10.0.0.5", target: "DC01", status: "ended",
      startTime: "2024-11-12T08:00:00Z", endTime: "2024-11-12T08:30:00Z", suspicionScore: 0 }],
  }));
  const a = accounts.find((x) => x.user === "CORP\\rdponly");
  assert.equal(a.firstSeen, "2024-11-12T08:00:00Z");
  assert.equal(a.lastSeen, "2024-11-12T08:30:00Z");
});

test("a raw-only (Kerberos-only) account has no scoped activity window", () => {
  const accounts = aggregateAccounts(state({
    ...counts("CORP\\krbuser", { raw: { "4769": 3 } }),
  }));
  const a = accounts.find((x) => x.user === "CORP\\krbuser");
  assert.equal(a.firstSeen, "", "blank — consistent with no scoped logon/RDP activity");
  assert.equal(a.lastSeen, "");
});

test("failuresBeforeFirstSuccess: a prior (excluded local) success zeroes the brute-force signal", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [
      evt("CORP\\u", "4625", { ts: "2024-11-12T09:00:01Z" }),
      evt("CORP\\u", "4625", { ts: "2024-11-12T09:00:02Z" }),
      evt("CORP\\u", "4625", { ts: "2024-11-12T09:00:03Z" }),
      evt("CORP\\u", "4624", { ts: "2024-11-12T09:00:04Z" }),
    ],
    // true first success was a local logon at 08:00 — BEFORE the failures
    userFirstSuccessTs: new Map([["CORP\\U", "2024-11-12T08:00:00Z"]]),
  }));
  const a = accounts.find((x) => x.user === "CORP\\u");
  assert.equal(a.failuresBeforeFirstSuccess, 0, "failures after the true first success aren't 'before first success'");
  assert.ok(!a.flags.some((f) => /failures before first success/.test(f)));
});

test("failuresBeforeFirstSuccess: fallback counts failures before the first scoped success", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [
      evt("CORP\\u", "4625", { ts: "2024-11-12T09:00:01Z" }),
      evt("CORP\\u", "4625", { ts: "2024-11-12T09:00:02Z" }),
      evt("CORP\\u", "4624", { ts: "2024-11-12T09:00:03Z" }),
    ],
    // no userFirstSuccessTs → falls back to the first scoped success (09:00:03)
  }));
  assert.equal(accounts.find((x) => x.user === "CORP\\u").failuresBeforeFirstSuccess, 2);
});

test("outlierSourceHits counts distinct outlier source hosts, not events", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [
      evt("CORP\\u", "4624", { source: "BAD1", ts: "2024-11-12T09:00:01Z" }),
      evt("CORP\\u", "4624", { source: "BAD1", ts: "2024-11-12T09:00:02Z" }),
      evt("CORP\\u", "4624", { source: "BAD1", ts: "2024-11-12T09:00:03Z" }),
      evt("CORP\\u", "4624", { source: "BAD2", ts: "2024-11-12T09:00:04Z" }),
    ],
    _outlierHosts: new Set(["BAD1", "BAD2"]),
  }));
  const a = accounts.find((x) => x.user === "CORP\\u");
  assert.equal(a.outlierSourceHits, 2, "2 distinct outlier sources, not 4 events");
  assert.ok(a.flags.some((f) => /outlier source/.test(f)));
});

test("rejects non-user session-metadata strings", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [evt("Session ID: 8", "4624"), evt("CORP\\real", "4624")],
  }));
  assert.ok(!accounts.some((a) => /Session/.test(a.user)), "session-metadata string not an account");
  assert.ok(accounts.some((a) => a.user === "CORP\\real"));
});

test("classifies machine and privileged accounts", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [evt("HOST01$", "4624"), evt("Administrator", "4624")],
  }));
  assert.ok(accounts.find((a) => a.user === "HOST01$").isMachineAccount);
  assert.ok(accounts.find((a) => a.user === "Administrator").isPrivilegedName);
});

test("links findings to accounts and applies the finding suspicion bonus", () => {
  const accounts = aggregateAccounts(state({
    timeOrdered: [evt("CORP\\attacker", "4624")],
    findings: [{ id: 7, users: ["CORP\\attacker"], category: "PsExec Native" }],
  }));
  const a = accounts.find((x) => x.user === "CORP\\attacker");
  assert.deepEqual(a.findingIds, [7]);
  assert.ok(a.findingCategories.includes("PsExec Native"));
  assert.ok(a.suspicionScore >= 5, "finding bonus applied to suspicion score");
});

test("RDP session stats roll into the account", () => {
  const accounts = aggregateAccounts(state({
    rdpSessions: [{ user: "CORP\\attacker", source: "10.0.0.5", target: "DC01", hasAdmin: true, isConcurrent: true, suspicionScore: 40, status: "connected" }],
  }));
  const a = accounts.find((x) => x.user === "CORP\\attacker");
  assert.equal(a.rdpSessionCount, 1);
  assert.equal(a.rdpAdminCount, 1);
  assert.equal(a.rdpConcurrentCount, 1);
  assert.equal(a.rdpSuspiciousCount, 1);
});

test("incomplete / connecting RDP activity is not counted as a proven session", () => {
  const accounts = aggregateAccounts(state({
    rdpSessions: [
      { user: "CORP\\attacker", source: "10.0.0.5", target: "HOST01", status: "incomplete", startTime: "2026-03-10T08:00:00Z" },
      { user: "CORP\\attacker", source: "10.0.0.6", target: "HOST01", status: "connecting", startTime: "2026-03-10T08:01:00Z" },
      { user: "CORP\\attacker", source: "10.0.0.7", target: "HOST01", status: "failed", attemptCount: 3 },
      { user: "CORP\\attacker", source: "10.0.0.8", target: "HOST01", status: "disconnected", hasAdmin: true },
    ],
  }));
  const a = accounts.find((x) => x.user === "CORP\\attacker");
  assert.equal(a.rdpSessionCount, 1, "only the disconnected (proven) session counts");
  assert.equal(a.rdpAdminCount, 1);
  assert.equal(a.rdpFailedCount, 1);
  assert.equal(a.rdpFailedAttemptCount, 3);
  assert.ok(a.sourceHosts.includes("10.0.0.5"), "1149-only sources still land on the account");
  assert.equal(a.firstSeen, "2026-03-10T08:00:00Z");
});
