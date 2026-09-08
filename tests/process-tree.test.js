// Fixture-driven tests for getProcessTree's JS-side post-processing.
// Run with: npm test
//
// We stub `meta.db` so we never need a real SQLite. The stub answers all
// COUNT probes with a positive row and returns the main SELECT's canned rows
// from the fixture. That lets us exercise the pieces of the analyzer that
// previously had no test coverage:
//
//   • Multi-host PID reuse must NOT fabricate cross-host parent/child links
//     (Finding #1).
//   • Parent must precede child in time when both timestamps are known —
//     even when the child rowid sorts before the parent (Finding #2,
//     normalized timestamp comparison).
//   • Sysmon brace-wrapped GUIDs and Security plain GUIDs link via
//     normalizeGuid before being stored as node.guid (Finding #3).
//   • Empty hostnames don't get a user-domain pseudo-host substituted
//     (Finding #4 — substitution lives in the modal, not the analyzer,
//     but we lock in that the analyzer never invents one).

const test = require("node:test");
const assert = require("node:assert/strict");

const { getProcessTree } = require("../electron/analyzers/process-tree");

// ---------- stub helpers ----------

// Build a meta + ctx pair backed by a fixture row set.
// `headers` is a list of CSV column names. `rows` are objects keyed by header.
function makeStub(headers, rows) {
  // colMap maps the original header name -> a SQL-safe column id (cN).
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });

  // Translate rows from header-keyed shape into the cN-keyed shape that the
  // analyzer's SELECT would yield. Each row also gets a synthetic rowid.
  const rowsByCN = rows.map((r, i) => {
    const out = { _rowid: i + 1 };
    for (const h of headers) out[`c${h && colMap[h] ? colMap[h].slice(1) : i}`] = r[h];
    return out;
  });
  // (Above is a fallback; build deterministically from headers.)
  rowsByCN.length = 0;
  rows.forEach((r, i) => {
    const cnRow = { _rowid: i + 1 };
    headers.forEach((h) => { cnRow[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    rowsByCN.push(cnRow);
  });

  // The analyzer SELECT renames each column with `${cN} as [key]` where `key`
  // is the logical name (pid, image, etc.). The stub doesn't know which keys
  // the analyzer will pick, so we deliver an aliased copy on every prepare(SELECT).
  // The aliasing happens by reading the SQL string and matching `as [key]`.
  function aliasRows(sql) {
    const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    return rowsByCN.map((r) => {
      const out = { _rowid: r._rowid };
      for (const [, idx, alias] of aliasMatches) {
        out[alias] = r[`c${idx}`];
      }
      return out;
    });
  }

  const db = {
    prepare(sql) {
      return {
        // COUNT probes — always return a positive count so the analyzer takes
        // the "exact-match works" fast path. We don't care about the probe.
        get(/* ...params */) {
          if (/COUNT\(\*\)/i.test(sql)) return { cnt: rowsByCN.length || 1 };
          return null;
        },
        all(/* ...params */) {
          if (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql)) {
            return aliasRows(sql);
          }
          return [];
        },
      };
    },
  };

  const meta = {
    db,
    headers,
    colMap,
    tabId: "test-tab",
  };
  const ctx = {
    // Standard filters get appended to whereConditions; for tests we want a
    // wide-open scope so the SELECT returns every fixture row.
    applyStandardFilters() { /* no-op */ },
    ensureIndex() {},
  };
  return { meta, ctx };
}

// Header schema for the standard Sysmon-style fixture.
const SYSMON_HEADERS = [
  "ProcessId", "ParentProcessId", "ProcessGuid", "ParentProcessGuid",
  "Image", "ParentImage", "CommandLine", "User", "UtcTime",
  "EventID", "Provider", "Computer",
];
const SESSION_HEADERS = [...SYSMON_HEADERS, "SubjectLogonId", "SessionId"];

// ---------- Finding #1: multi-host PID reuse ----------

test("multi-host PID reuse: PID 1234 on HOST-A is not relinked to PID 1234 on HOST-B", () => {
  // HOST-A: parent pid=1234, child ppid=1234 → should link
  // HOST-B: a stray process with pid=1234 also exists, slightly earlier
  // Pre-fix, the stray on HOST-B was a candidate parent for the HOST-A child.
  const rows = [
    {
      ProcessId: "1234", ParentProcessId: "1000", ProcessGuid: "{aaaaaaaa-0000-0000-0000-000000000001}",
      ParentProcessGuid: "{99999999-0000-0000-0000-000000000099}",
      Image: "C:\\Windows\\System32\\svchost.exe", ParentImage: "C:\\Windows\\System32\\services.exe",
      CommandLine: "svchost.exe", User: "SYSTEM", UtcTime: "2026-03-15 10:00:00",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
    },
    {
      // Cross-host stray with same pid value, earlier in time — must NOT become a parent
      ProcessId: "1234", ParentProcessId: "5000", ProcessGuid: "{bbbbbbbb-0000-0000-0000-000000000002}",
      ParentProcessGuid: "{88888888-0000-0000-0000-000000000088}",
      Image: "C:\\Some\\Other.exe", ParentImage: "C:\\Windows\\explorer.exe",
      CommandLine: "other.exe", User: "Bob", UtcTime: "2026-03-15 09:55:00",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-B",
    },
    {
      // Child on HOST-A whose parent is the first row above
      ProcessId: "5678", ParentProcessId: "1234", ProcessGuid: "",  // GUID missing → forces PID relink path
      ParentProcessGuid: "",
      Image: "C:\\Windows\\System32\\cmd.exe", ParentImage: "C:\\Windows\\System32\\svchost.exe",
      CommandLine: "cmd.exe /c whoami", User: "SYSTEM", UtcTime: "2026-03-15 10:01:00",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
    },
  ];
  const { meta, ctx } = makeStub(SYSMON_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
  const child = tree.processes.find((p) => p.pid === "5678");
  assert.ok(child, "child must exist");
  // The child's resolved parent must be the HOST-A svchost (rowid 1), not the HOST-B stray (rowid 2).
  const parent = tree.processes.find((p) => p.key === child.parentKey);
  assert.ok(parent, "child must have a resolved parent");
  assert.equal(parent.normHost, "HOST-A", "parent must be on the same host as the child");
  assert.notEqual(parent.rowid, 2, "stray HOST-B row must not be the parent");
});

// ---------- Finding #2: parent must precede child in time ----------

test("PID relink prefers a parent whose timestamp precedes the child", () => {
  // Two candidate parents on the same host with the same pid (PID reuse within
  // a single boot session). The earlier one must win when the child's ts falls
  // between them.
  const rows = [
    {
      ProcessId: "1234", ParentProcessId: "100", ProcessGuid: "",
      ParentProcessGuid: "", Image: "C:\\Old.exe", ParentImage: "C:\\init.exe",
      CommandLine: "old.exe", User: "SYSTEM", UtcTime: "2026-03-15 09:00:00",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
    },
    {
      ProcessId: "5678", ParentProcessId: "1234", ProcessGuid: "",
      ParentProcessGuid: "", Image: "C:\\Child.exe", ParentImage: "C:\\Old.exe",
      CommandLine: "child.exe", User: "SYSTEM", UtcTime: "2026-03-15 09:30:00",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
    },
    {
      ProcessId: "1234", ParentProcessId: "200", ProcessGuid: "",
      ParentProcessGuid: "", Image: "C:\\New.exe", ParentImage: "C:\\init.exe",
      CommandLine: "new.exe", User: "SYSTEM", UtcTime: "2026-03-15 10:00:00",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
    },
  ];
  const { meta, ctx } = makeStub(SYSMON_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
  const child = tree.processes.find((p) => p.pid === "5678");
  const parent = tree.processes.find((p) => p.key === child.parentKey);
  assert.equal(parent.image, "C:\\Old.exe", "earlier candidate must win when child ts is between two reuses");
});

test("PID relink uses LogonId scope before falling back to host PID reuse", () => {
  // Same host, same parent PID reused in two different logon sessions. The
  // closer candidate is wrong; the matching LogonId candidate must win.
  const rows = [
    {
      ProcessId: "1234", ParentProcessId: "100", ProcessGuid: "",
      ParentProcessGuid: "", Image: "C:\\SessionA\\Parent.exe", ParentImage: "",
      CommandLine: "parent-a.exe", User: "HOST-A\\alice", UtcTime: "2026-03-15 10:00:00",
      EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
      SubjectLogonId: "0x3e8", SessionId: "",
    },
    {
      ProcessId: "1234", ParentProcessId: "100", ProcessGuid: "",
      ParentProcessGuid: "", Image: "C:\\SessionB\\WrongParent.exe", ParentImage: "",
      CommandLine: "wrong-parent.exe", User: "HOST-A\\bob", UtcTime: "2026-03-15 10:04:00",
      EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
      SubjectLogonId: "0x3e9", SessionId: "",
    },
    {
      ProcessId: "5678", ParentProcessId: "1234", ProcessGuid: "",
      ParentProcessGuid: "", Image: "C:\\SessionA\\Child.exe", ParentImage: "",
      CommandLine: "child.exe", User: "HOST-A\\alice", UtcTime: "2026-03-15 10:05:00",
      EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
      SubjectLogonId: "0x3e8", SessionId: "",
    },
  ];
  const { meta, ctx } = makeStub(SESSION_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "4688" }, ctx);
  const child = tree.processes.find((p) => p.pid === "5678");
  const parent = tree.processes.find((p) => p.key === child.parentKey);
	  assert.equal(child.logonId, "1000", "child LogonId must be normalized from hex");
	  assert.equal(parent.image, "C:\\SessionA\\Parent.exe", "matching LogonId parent must beat closer PID reuse");
	  assert.equal(child.link.source, "pid-logon");
	  assert.equal(child.link.confidence, "medium");
	  assert.equal(child.link.parentRowId, parent.rowid);
	  assert.equal(child.link.childLogonId, "1000");
	  assert.equal(child.link.parentLogonId, "1000");
	});

// audit P4: a cross-scope parent is LINKED, but marked.
//
// Refusing every cross-scope relink fractured real trees at exactly the handovers
// that define a Windows session — services -> a service under its own principal,
// winlogon -> userinit, UAC elevation, runas, and every scheduled task — where the
// child legitimately runs under a different logon/session. Those branches simply
// vanished and the analyst saw orphans. The link is now made at low confidence with
// an explicit warning, and (outside the known boundary parents) only when the
// candidate is the sole holder of that PID, so ambiguous PID-reuse guesses are still
// refused.
test("PID relink crosses a known SessionId boundary only as a warned, low-confidence link", () => {
  const rows = [
    {
      ProcessId: "1234", ParentProcessId: "100", ProcessGuid: "",
      ParentProcessGuid: "", Image: "C:\\Session2\\Parent.exe", ParentImage: "",
      CommandLine: "parent.exe", User: "HOST-A\\bob", UtcTime: "2026-03-15 10:00:00",
      EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
      SubjectLogonId: "", SessionId: "2",
    },
    {
      ProcessId: "5678", ParentProcessId: "1234", ProcessGuid: "",
      ParentProcessGuid: "", Image: "C:\\Session1\\Child.exe", ParentImage: "",
      CommandLine: "child.exe", User: "HOST-A\\alice", UtcTime: "2026-03-15 10:01:00",
      EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
      SubjectLogonId: "", SessionId: "1",
    },
  ];
  const { meta, ctx } = makeStub(SESSION_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "4688" }, ctx);
  const child = tree.processes.find((p) => p.pid === "5678");
  const linkedParent = tree.processes.find((p) => p.key === child.parentKey);
  assert.equal(child.sessionId, "1");
  assert.ok(linkedParent, "the only process holding that PID is the parent, even across sessions");
  assert.equal(linkedParent.pid, "1234");
  assert.equal(child.link.confidence, "low", "but the analyst must be told the link is weak");
  assert.ok(child.link.warnings.includes("parent_scope_mismatch"), `expected a scope warning, got ${JSON.stringify(child.link.warnings)}`);
});

test("an ambiguous cross-scope PID is still refused", () => {
  // TWO processes in other sessions held PID 1234 — the link is a coin flip, so no
  // link is better than a wrong one.
  const mk = (pid, ppid, session, image, ts) => ({
    ProcessId: pid, ParentProcessId: ppid, ProcessGuid: "", ParentProcessGuid: "",
    Image: image, ParentImage: "", CommandLine: "x", User: "HOST-A\\u",
    UtcTime: ts, EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing",
    Computer: "HOST-A", SubjectLogonId: "", SessionId: session,
  });
  const rows = [
    mk("1234", "100", "2", "C:\\S2\\A.exe", "2026-03-15 10:00:00"),
    mk("1234", "100", "3", "C:\\S3\\B.exe", "2026-03-15 10:00:30"),
    mk("5678", "1234", "1", "C:\\S1\\Child.exe", "2026-03-15 10:01:00"),
  ];
  const { meta, ctx } = makeStub(SESSION_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "4688" }, ctx);
  const child = tree.processes.find((p) => p.pid === "5678");
  assert.equal(child.link.source, "unresolved");
  assert.ok(child.link.warnings.includes("parent_not_found"));
});

test("a services.exe parent in another logon scope links without needing to be unique", () => {
  // services.exe starting a service under the service's own logon is an OS boundary,
  // not PID reuse — the boundary-parent list covers it even when ambiguous.
  const mk = (pid, ppid, logon, image, name, ts) => ({
    ProcessId: pid, ParentProcessId: ppid, ProcessGuid: "", ParentProcessGuid: "",
    Image: image, ParentImage: "", CommandLine: name, User: "HOST-A\\u",
    UtcTime: ts, EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing",
    Computer: "HOST-A", SubjectLogonId: logon, SessionId: "",
  });
  const rows = [
    mk("700", "600", "0x3e7", "C:\\Windows\\System32\\services.exe", "services.exe", "2026-03-15 10:00:00"),
    mk("900", "700", "0x3e4", "C:\\Windows\\System32\\svchost.exe", "svchost.exe", "2026-03-15 10:01:00"),
  ];
  const { meta, ctx } = makeStub(SESSION_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "4688" }, ctx);
  const child = tree.processes.find((p) => p.pid === "900");
  const parent = tree.processes.find((p) => p.key === child.parentKey);
  assert.ok(parent, "services -> svchost must not be severed by the logon-id change");
  assert.equal(parent.processName, "services.exe");
  assert.ok(child.link.warnings.includes("parent_scope_boundary"));
});

// ---------- Finding #3: brace-wrapped GUIDs normalized at ingest ----------

test("brace-wrapped Sysmon GUIDs are stored normalized so cross-source joins work", () => {
  const rows = [
    {
      ProcessId: "1000", ParentProcessId: "4", ProcessGuid: "{AAAAAAAA-1111-2222-3333-444444444444}",
      ParentProcessGuid: "{BBBBBBBB-0000-0000-0000-000000000000}",
      Image: "C:\\Foo.exe", ParentImage: "C:\\System.exe",
      CommandLine: "foo.exe", User: "SYSTEM", UtcTime: "2026-03-15 10:00:00",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
    },
  ];
  const { meta, ctx } = makeStub(SYSMON_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
	  const node = tree.processes[0];
	  assert.equal(node.guid, "aaaaaaaa-1111-2222-3333-444444444444", "guid must be brace-stripped lowercase");
	  assert.equal(node.parentGuid, "bbbbbbbb-0000-0000-0000-000000000000", "parentGuid must be brace-stripped lowercase");
	});

	test("GUID parent links carry high-confidence provenance", () => {
	  const rows = [
	    {
	      ProcessId: "1000", ParentProcessId: "4", ProcessGuid: "{AAAAAAAA-1111-2222-3333-444444444444}",
	      ParentProcessGuid: "{BBBBBBBB-0000-0000-0000-000000000000}",
	      Image: "C:\\Parent.exe", ParentImage: "C:\\System.exe",
	      CommandLine: "parent.exe", User: "SYSTEM", UtcTime: "2026-03-15 10:00:00",
	      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
	    },
	    {
	      ProcessId: "2000", ParentProcessId: "1000", ProcessGuid: "{CCCCCCCC-1111-2222-3333-444444444444}",
	      ParentProcessGuid: "{AAAAAAAA-1111-2222-3333-444444444444}",
	      Image: "C:\\Child.exe", ParentImage: "C:\\Parent.exe",
	      CommandLine: "child.exe", User: "SYSTEM", UtcTime: "2026-03-15 10:00:05",
	      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
	    },
	  ];
	  const { meta, ctx } = makeStub(SYSMON_HEADERS, rows);
	  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
	  const child = tree.processes.find((p) => p.pid === "2000");
	  const parent = tree.processes.find((p) => p.key === child.parentKey);
	  assert.equal(parent.pid, "1000");
	  assert.equal(child.link.source, "guid");
	  assert.equal(child.link.confidence, "high");
	  assert.equal(child.link.parentRowId, parent.rowid);
	  assert.equal(child.link.childRowId, child.rowid);
	  assert.equal(child.link.timeDeltaMs, 5000);
	});

// ---------- Locale-formatted timestamp dataset ----------

test("US-style timestamps build a parent/child link via normalized chronology", () => {
  // The fixture mixes ISO and US M/D/YYYY h:mm:ss AM/PM formats. Pre-fix,
  // raw lexical comparison broke chronology between the two.
  const rows = [
    {
      ProcessId: "1000", ParentProcessId: "4", ProcessGuid: "",
      ParentProcessGuid: "", Image: "C:\\Parent.exe", ParentImage: "",
      CommandLine: "parent.exe", User: "SYSTEM", UtcTime: "3/15/2026 9:00:00 AM",
      EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
    },
    {
      ProcessId: "2000", ParentProcessId: "1000", ProcessGuid: "",
      ParentProcessGuid: "", Image: "C:\\Child.exe", ParentImage: "C:\\Parent.exe",
      CommandLine: "child.exe", User: "SYSTEM", UtcTime: "3/15/2026 9:01:00 AM",
      EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
    },
  ];
  const { meta, ctx } = makeStub(SYSMON_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "4688" }, ctx);
  const child = tree.processes.find((p) => p.pid === "2000");
  const parent = tree.processes.find((p) => p.key === child.parentKey);
  assert.ok(parent, "child must have a parent after normalized-time relink");
  assert.equal(parent.pid, "1000");
  // tsMs must round-trip to a real epoch ms value
  assert.ok(Number.isFinite(parent.tsMs) && Number.isFinite(child.tsMs));
  assert.ok(child.tsMs > parent.tsMs, "child ts must be after parent ts under normalized parsing");
});

// ---------- Security 4688: parent image backfilled from linked parent ----------

test("Security 4688 row with no ParentImage backfills from the linked parent node", () => {
  // Older Security 4688 exports (and many EvtxECmd / preprocessor outputs)
  // strip the ParentProcessName field. The backend post-pass must derive
  // parentImage / parentProcessName from the relinked parent so the UI column,
  // CSV exports, JSON exports, and inspector context all show the parent.
  const rows = [
    {
      ProcessId: "1000", ParentProcessId: "4", ProcessGuid: "",
      ParentProcessGuid: "",
      Image: "C:\\Windows\\System32\\services.exe", ParentImage: "",
      CommandLine: "services.exe", User: "SYSTEM", UtcTime: "2026-03-15 10:00:00",
      EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
    },
    {
      ProcessId: "2000", ParentProcessId: "1000", ProcessGuid: "",
      ParentProcessGuid: "",
      // Crucially: this child carries NO ParentImage — the typical Security 4688 case.
      Image: "C:\\Windows\\System32\\svchost.exe", ParentImage: "",
      CommandLine: "svchost.exe -k netsvcs", User: "SYSTEM", UtcTime: "2026-03-15 10:00:01",
      EventID: "4688", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
    },
  ];
  const { meta, ctx } = makeStub(SYSMON_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "4688" }, ctx);
  const child = tree.processes.find((p) => p.pid === "2000");
  assert.ok(child, "child node must exist");
  assert.equal(child.parentImage, "C:\\Windows\\System32\\services.exe",
    "parentImage must be backfilled from the linked parent's image");
  assert.equal(child.parentProcessName, "services.exe",
    "parentProcessName must be backfilled from the linked parent's processName");
});

test("backfill does NOT overwrite a row's existing parent image", () => {
  // If the row already carries a parentImage, the post-pass must leave it alone
  // — we never want to clobber a real value with a relink-derived one.
  const rows = [
    {
      ProcessId: "1000", ParentProcessId: "4", ProcessGuid: "",
      ParentProcessGuid: "",
      Image: "C:\\Windows\\explorer.exe", ParentImage: "",
      CommandLine: "explorer.exe", User: "alice", UtcTime: "2026-03-15 10:00:00",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
    },
    {
      ProcessId: "2000", ParentProcessId: "1000", ProcessGuid: "",
      ParentProcessGuid: "",
      Image: "C:\\Windows\\notepad.exe",
      // Native value present — must not be replaced.
      ParentImage: "C:\\Windows\\explorer.exe",
      CommandLine: "notepad.exe", User: "alice", UtcTime: "2026-03-15 10:00:01",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
    },
  ];
  const { meta, ctx } = makeStub(SYSMON_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
  const child = tree.processes.find((p) => p.pid === "2000");
  assert.equal(child.parentImage, "C:\\Windows\\explorer.exe");
});

// ---------- Finding #4: empty hostname stays empty ----------

test("empty hostname rows get bucketed together but never under a user's domain", () => {
  const rows = [
    {
      ProcessId: "1000", ParentProcessId: "4", ProcessGuid: "",
      ParentProcessGuid: "", Image: "C:\\A.exe", ParentImage: "",
      CommandLine: "a.exe", User: "CORP\\Alice", UtcTime: "2026-03-15 10:00:00",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "",
    },
  ];
  const { meta, ctx } = makeStub(SYSMON_HEADERS, rows);
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
  const node = tree.processes[0];
  assert.equal(node.normHost, "", "empty Computer must NOT be replaced by the user's domain");
  assert.equal(node.hostname, "");
});

// ---------- EID 10 ProcessAccess: hollowing detection ----------

// Stub variant that honors WHERE predicates — EID IN (...) AND optional
// <col> LIKE ?. Required by the EID 10 / EID 4673 correlation blocks, and
// by the provider-guard clause that narrows 4673/4674 to Security-Auditing.
function makeEidStub(headers, rows, eidCol) {
  const colMap = {};
  headers.forEach((h, i) => { colMap[h] = `c${i}`; });
  const rowsByCN = rows.map((r, i) => {
    const cnRow = { _rowid: i + 1 };
    headers.forEach((h) => { cnRow[colMap[h]] = r[h] != null ? String(r[h]) : null; });
    return cnRow;
  });
  const eidSafe = colMap[eidCol];
  const applyWhere = (sql, params) => {
    let consumed = 0;
    let eidWhitelist = null;
    // Fast-path single EID: `c9 = ?` (getProcessTree emits this instead of
    // IN when eids.length === 1).
    const inMatch = sql.match(/\bIN\s*\(([^)]+)\)/i);
    if (inMatch) {
      const count = (inMatch[1].match(/\?/g) || []).length;
      eidWhitelist = new Set(params.slice(consumed, consumed + count).map(String));
      consumed += count;
    } else {
      const eqMatch = sql.match(/\bc\d+\s*=\s*\?/);
      if (eqMatch && params.length > consumed) {
        eidWhitelist = new Set([String(params[consumed])]);
        consumed += 1;
      }
    }
    // LIKE predicate — column must be cN alias. The analyzer only emits one
    // LIKE at a time (provider match), so single-predicate parsing is enough.
    const likeMatch = sql.match(/AND\s+(c\d+)\s+LIKE\s+\?/i);
    let likeCol = null, likePattern = null;
    if (likeMatch && consumed < params.length) {
      likeCol = likeMatch[1];
      likePattern = params[consumed];
      consumed += 1;
    }
    let out = rowsByCN;
    if (eidSafe && eidWhitelist) {
      out = out.filter((r) => eidWhitelist.has(r[eidSafe]));
    }
    if (likeCol && likePattern != null) {
      const rx = new RegExp(
        "^" + String(likePattern).replace(/[.+^${}()|\[\]\\]/g, "\\$&").replace(/%/g, ".*").replace(/_/g, ".") + "$",
        "i",
      );
      out = out.filter((r) => rx.test(r[likeCol] || ""));
    }
    return out;
  };
  function aliasRows(sql, params) {
    const aliasMatches = [...sql.matchAll(/c(\d+)\s+as\s+\[([a-zA-Z0-9_]+)\]/g)];
    return applyWhere(sql, params).map((r) => {
      const out = { _rowid: r._rowid };
      for (const [, idx, alias] of aliasMatches) out[alias] = r[`c${idx}`];
      return out;
    });
  }
  const db = {
    prepare(sql) {
      return {
        get(...params) {
          if (/COUNT\(\*\)/i.test(sql)) {
            const n = applyWhere(sql, params).length;
            return { cnt: n, n };
          }
          return null;
        },
        all(...params) {
          if (/^SELECT\s/i.test(sql) && /FROM\s+data/i.test(sql) && /\bas\s+\[/.test(sql)) {
            return aliasRows(sql, params);
          }
          return [];
        },
      };
    },
  };
  const meta = { db, headers, colMap, tabId: "test-tab" };
  const ctx = { applyStandardFilters() {}, ensureIndex() {} };
  return { meta, ctx };
}

const SYSMON_EID10_HEADERS = [
  "ProcessId", "ParentProcessId", "ProcessGuid", "ParentProcessGuid",
  "Image", "ParentImage", "CommandLine", "User", "UtcTime",
  "EventID", "Provider", "Computer",
  "SourceProcessId", "TargetProcessId", "TargetProcessGuid", "GrantedAccess",
];

test("EID 10 with VM_WRITE access within 500ms of target creation flags hollowingLikely", () => {
  // Target lsass.exe is created at T=0; 200ms later an EID 10 event targets it
  // with GrantedAccess 0x1F0FFF (PROCESS_ALL_ACCESS). That's inside the hollowing
  // window AND carries injection-like bits — should trip hollowingLikely.
  const targetGuid = "{cccccccc-1111-1111-1111-111111111111}";
  const rows = [
    {
      ProcessId: "900", ParentProcessId: "400",
      ProcessGuid: targetGuid, ParentProcessGuid: "{dddddddd-0000-0000-0000-000000000000}",
      Image: "C:\\Windows\\System32\\lsass.exe", ParentImage: "C:\\Windows\\System32\\wininit.exe",
      CommandLine: "lsass.exe", User: "SYSTEM", UtcTime: "2026-03-15 10:00:00.000",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      SourceProcessId: "", TargetProcessId: "", TargetProcessGuid: "", GrantedAccess: "",
    },
    {
      // Attacker at PID 4242 opens target at T+200ms with PROCESS_ALL_ACCESS
      ProcessId: "", ParentProcessId: "",
      ProcessGuid: "", ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "", User: "", UtcTime: "2026-03-15 10:00:00.200",
      EventID: "10", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      SourceProcessId: "4242", TargetProcessId: "900", TargetProcessGuid: targetGuid, GrantedAccess: "0x1F0FFF",
    },
  ];
  const { meta, ctx } = makeEidStub(SYSMON_EID10_HEADERS, rows, "EventID");
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
  const target = tree.processes.find((p) => p.pid === "900");
  assert.ok(target, "target lsass node must exist");
  assert.ok(target.injectionIndicators, "target must carry injectionIndicators after EID 10 match");
  assert.equal(target.injectionIndicators.accessCount, 1);
  assert.equal(target.injectionIndicators.suspiciousAccessCount, 1);
  assert.equal(target.injectionIndicators.hollowingLikely, true);
  assert.deepEqual(target.injectionIndicators.sourcePids, ["4242"]);
  assert.equal(tree.stats.accessMatched, 1);
});

test("EID 10 read-only access (0x1000 QUERY_INFO) does not flag as injection", () => {
  // Benign query-only access should be counted but not suspicious.
  const targetGuid = "{eeeeeeee-2222-2222-2222-222222222222}";
  const rows = [
    {
      ProcessId: "1500", ParentProcessId: "600",
      ProcessGuid: targetGuid, ParentProcessGuid: "{ffffffff-0000-0000-0000-000000000000}",
      Image: "C:\\Windows\\System32\\svchost.exe", ParentImage: "C:\\Windows\\System32\\services.exe",
      CommandLine: "svchost.exe -k netsvcs", User: "SYSTEM", UtcTime: "2026-03-15 10:00:00.000",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      SourceProcessId: "", TargetProcessId: "", TargetProcessGuid: "", GrantedAccess: "",
    },
    {
      ProcessId: "", ParentProcessId: "",
      ProcessGuid: "", ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "", User: "", UtcTime: "2026-03-15 10:05:00.000",
      EventID: "10", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      SourceProcessId: "3000", TargetProcessId: "1500", TargetProcessGuid: targetGuid, GrantedAccess: "0x1000",
    },
  ];
  const { meta, ctx } = makeEidStub(SYSMON_EID10_HEADERS, rows, "EventID");
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
  const target = tree.processes.find((p) => p.pid === "1500");
  assert.ok(target.injectionIndicators, "target must carry injectionIndicators");
  assert.equal(target.injectionIndicators.accessCount, 1);
  assert.equal(target.injectionIndicators.suspiciousAccessCount, 0);
  assert.equal(target.injectionIndicators.hollowingLikely, false);
});

test("EID 10 self-access (source PID == target PID) is ignored", () => {
  // A process calling GetCurrentProcess() on itself produces noise; skip it.
  const targetGuid = "{12345678-3333-3333-3333-333333333333}";
  const rows = [
    {
      ProcessId: "2000", ParentProcessId: "100",
      ProcessGuid: targetGuid, ParentProcessGuid: "{99999999-0000-0000-0000-000000000000}",
      Image: "C:\\Windows\\System32\\powershell.exe", ParentImage: "C:\\Windows\\explorer.exe",
      CommandLine: "powershell.exe -NoProfile", User: "alice", UtcTime: "2026-03-15 10:00:00.000",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      SourceProcessId: "", TargetProcessId: "", TargetProcessGuid: "", GrantedAccess: "",
    },
    {
      ProcessId: "", ParentProcessId: "",
      ProcessGuid: "", ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "", User: "", UtcTime: "2026-03-15 10:00:00.100",
      EventID: "10", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      SourceProcessId: "2000", TargetProcessId: "2000", TargetProcessGuid: targetGuid, GrantedAccess: "0x1F0FFF",
    },
  ];
  const { meta, ctx } = makeEidStub(SYSMON_EID10_HEADERS, rows, "EventID");
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
  const target = tree.processes.find((p) => p.pid === "2000");
  assert.equal(target.injectionIndicators, null, "self-access must not populate indicators");
});

// ---------- EID 4673 / 4674 privilege-use correlation ----------

const SEC_PRIV_HEADERS = [
  "ProcessId", "ParentProcessId", "ProcessGuid", "ParentProcessGuid",
  "Image", "ParentImage", "CommandLine", "User", "UtcTime",
  "EventID", "Provider", "Computer", "PrivilegeList",
];

test("EID 4673 with SeDebugPrivilege aggregates into privilegeUse on the target process", () => {
  const rows = [
    {
      ProcessId: "3000", ParentProcessId: "400",
      ProcessGuid: "{00000000-0000-0000-0000-000000000003}",
      ParentProcessGuid: "{00000000-0000-0000-0000-000000000004}",
      Image: "C:\\Tools\\evil.exe", ParentImage: "C:\\Windows\\explorer.exe",
      CommandLine: "evil.exe", User: "alice", UtcTime: "2026-03-15 10:00:00.000",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      PrivilegeList: "",
    },
    {
      ProcessId: "3000", ParentProcessId: "",
      ProcessGuid: "", ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "", User: "alice", UtcTime: "2026-03-15 10:01:00.000",
      EventID: "4673", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
      PrivilegeList: "SeDebugPrivilege",
    },
    {
      ProcessId: "3000", ParentProcessId: "",
      ProcessGuid: "", ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "", User: "alice", UtcTime: "2026-03-15 10:02:00.000",
      EventID: "4673", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
      PrivilegeList: "SeDebugPrivilege, SeImpersonatePrivilege",
    },
  ];
  const { meta, ctx } = makeEidStub(SEC_PRIV_HEADERS, rows, "EventID");
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
  const target = tree.processes.find((p) => p.pid === "3000");
  assert.ok(target?.privilegeUse, "target must carry privilegeUse");
  assert.equal(target.privilegeUse.eventCount, 2);
  assert.equal(target.privilegeUse.privileges.sedebugprivilege, 2);
  assert.equal(target.privilegeUse.privileges.seimpersonateprivilege, 1);
  assert.equal(target.privilegeUse.uniqueHighRisk, 2);
  assert.equal(target.privilegeUse.highRiskCount, 3);
  assert.equal(tree.stats.privilegeMatched, 2);
});

test("EID 4673 with only non-high-risk privileges still records, highRiskCount stays 0", () => {
  const rows = [
    {
      ProcessId: "4000", ParentProcessId: "400",
      ProcessGuid: "{00000000-0000-0000-0000-000000000040}",
      ParentProcessGuid: "{00000000-0000-0000-0000-000000000041}",
      Image: "C:\\Tools\\benign.exe", ParentImage: "C:\\Windows\\explorer.exe",
      CommandLine: "benign.exe", User: "alice", UtcTime: "2026-03-15 10:00:00.000",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      PrivilegeList: "",
    },
    {
      ProcessId: "4000", ParentProcessId: "",
      ProcessGuid: "", ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "", User: "alice", UtcTime: "2026-03-15 10:05:00.000",
      EventID: "4674", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
      PrivilegeList: "SeSecurityPrivilege",
    },
  ];
  const { meta, ctx } = makeEidStub(SEC_PRIV_HEADERS, rows, "EventID");
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
  const target = tree.processes.find((p) => p.pid === "4000");
  assert.ok(target.privilegeUse, "privilegeUse must still be populated for non-high-risk privs");
  assert.equal(target.privilegeUse.privileges.sesecurityprivilege, 1);
  assert.equal(target.privilegeUse.highRiskCount, 0);
  assert.equal(target.privilegeUse.uniqueHighRisk, 0);
});

test("EID 4673 from a non-Security-Auditing provider is excluded when Provider column is present", () => {
  // Two 4673 rows targeting the same PID — one from Security-Auditing (legit),
  // one from a custom/non-Security provider that reuses EID 4673. The provider
  // filter must drop the second so its privileges don't inflate counts.
  const rows = [
    {
      ProcessId: "7000", ParentProcessId: "400",
      ProcessGuid: "{00000000-0000-0000-0000-000000000070}",
      ParentProcessGuid: "{00000000-0000-0000-0000-000000000071}",
      Image: "C:\\Tools\\probe.exe", ParentImage: "C:\\Windows\\explorer.exe",
      CommandLine: "probe.exe", User: "alice", UtcTime: "2026-03-15 10:00:00.000",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      PrivilegeList: "",
    },
    {
      ProcessId: "7000", ParentProcessId: "",
      ProcessGuid: "", ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "", User: "alice", UtcTime: "2026-03-15 10:01:00.000",
      EventID: "4673", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
      PrivilegeList: "SeDebugPrivilege",
    },
    {
      ProcessId: "7000", ParentProcessId: "",
      ProcessGuid: "", ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "", User: "alice", UtcTime: "2026-03-15 10:02:00.000",
      EventID: "4673", Provider: "Custom-Audit-Tool", Computer: "HOST-A",
      PrivilegeList: "SeLoadDriverPrivilege",
    },
  ];
  const { meta, ctx } = makeEidStub(SEC_PRIV_HEADERS, rows, "EventID");
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
  const target = tree.processes.find((p) => p.pid === "7000");
  assert.ok(target.privilegeUse, "Security-Auditing 4673 must be ingested");
  assert.equal(target.privilegeUse.eventCount, 1, "only the Security-Auditing event must count");
  assert.equal(target.privilegeUse.privileges.sedebugprivilege, 1);
  assert.equal(target.privilegeUse.privileges.seloaddriverprivilege, undefined,
    "non-Security-Auditing 4673 must not contribute");
});

test("EID 4673 on a PID that was never created does not attach to any node", () => {
  // Real node exists at PID 6000; a separate 4673 event targets an unrelated
  // PID 9999. The 4673 must be ignored — no phantom attachment, no crash.
  const rows = [
    {
      ProcessId: "6000", ParentProcessId: "400",
      ProcessGuid: "{00000000-0000-0000-0000-000000000060}",
      ParentProcessGuid: "{00000000-0000-0000-0000-000000000061}",
      Image: "C:\\Tools\\real.exe", ParentImage: "C:\\Windows\\explorer.exe",
      CommandLine: "real.exe", User: "alice", UtcTime: "2026-03-15 10:00:00.000",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "HOST-A",
      PrivilegeList: "",
    },
    {
      ProcessId: "9999", ParentProcessId: "",
      ProcessGuid: "", ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "", User: "alice", UtcTime: "2026-03-15 10:05:00.000",
      EventID: "4673", Provider: "Microsoft-Windows-Security-Auditing", Computer: "HOST-A",
      PrivilegeList: "SeDebugPrivilege",
    },
  ];
  const { meta, ctx } = makeEidStub(SEC_PRIV_HEADERS, rows, "EventID");
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);
  const real = tree.processes.find((p) => p.pid === "6000");
  assert.ok(real, "real node must still be present");
  assert.equal(real.privilegeUse, null, "orphan 4673 must not attach to an unrelated process");
  assert.equal(tree.stats.privilegeMatched, 0);
});

// ── P2 golden corpus: multi-EID Sysmon fixture (1 + 10 + 4673 + 3) ──
// Locks the end-to-end analyzer post-processing contract: GUID tree links,
// injection/hollowing summary, privilege-use summary, network activity, and
// stats counters. Fixture is in-memory (same stub pattern as above).

const GOLDEN_HEADERS = [
  "ProcessId", "ParentProcessId", "ProcessGuid", "ParentProcessGuid",
  "Image", "ParentImage", "CommandLine", "User", "UtcTime",
  "EventID", "Provider", "Computer",
  "SourceProcessId", "TargetProcessId", "TargetProcessGuid", "GrantedAccess",
  "PrivilegeList",
];

test("golden corpus: Sysmon create + EID10 + 4673 + EID3 attach to the same process entity", () => {
  const attackerGuid = "{aaaaaaaa-1111-1111-1111-111111111111}";
  const parentGuid = "{bbbbbbbb-0000-0000-0000-000000000001}";
  const victimGuid = "{cccccccc-2222-2222-2222-222222222222}";
  const rows = [
    // Parent explorer
    {
      ProcessId: "1000", ParentProcessId: "500",
      ProcessGuid: parentGuid, ParentProcessGuid: "{00000000-0000-0000-0000-000000000000}",
      Image: "C:\\Windows\\explorer.exe", ParentImage: "C:\\Windows\\System32\\userinit.exe",
      CommandLine: "explorer.exe", User: "CORP\\alice", UtcTime: "2026-04-01 12:00:00.000",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "WS-GOLDEN",
      SourceProcessId: "", TargetProcessId: "", TargetProcessGuid: "", GrantedAccess: "",
      PrivilegeList: "",
    },
    // Attacker powershell create
    {
      ProcessId: "4242", ParentProcessId: "1000",
      ProcessGuid: attackerGuid, ParentProcessGuid: parentGuid,
      Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      ParentImage: "C:\\Windows\\explorer.exe",
      CommandLine: "powershell.exe -enc AAAA", User: "CORP\\alice", UtcTime: "2026-04-01 12:00:01.000",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "WS-GOLDEN",
      SourceProcessId: "", TargetProcessId: "", TargetProcessGuid: "", GrantedAccess: "",
      PrivilegeList: "",
    },
    // Victim lsass create
    {
      ProcessId: "700", ParentProcessId: "400",
      ProcessGuid: victimGuid, ParentProcessGuid: "{00000000-0000-0000-0000-0000000000aa}",
      Image: "C:\\Windows\\System32\\lsass.exe", ParentImage: "C:\\Windows\\System32\\wininit.exe",
      CommandLine: "lsass.exe", User: "SYSTEM", UtcTime: "2026-04-01 12:00:00.500",
      EventID: "1", Provider: "Microsoft-Windows-Sysmon", Computer: "WS-GOLDEN",
      SourceProcessId: "", TargetProcessId: "", TargetProcessGuid: "", GrantedAccess: "",
      PrivilegeList: "",
    },
    // EID 10: attacker injects into lsass (hollowing window)
    {
      ProcessId: "", ParentProcessId: "",
      ProcessGuid: "", ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "", User: "", UtcTime: "2026-04-01 12:00:00.700",
      EventID: "10", Provider: "Microsoft-Windows-Sysmon", Computer: "WS-GOLDEN",
      SourceProcessId: "4242", TargetProcessId: "700", TargetProcessGuid: victimGuid, GrantedAccess: "0x1F0FFF",
      PrivilegeList: "",
    },
    // EID 4673: attacker uses SeDebug
    {
      ProcessId: "4242", ParentProcessId: "",
      ProcessGuid: attackerGuid, ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "", User: "CORP\\alice", UtcTime: "2026-04-01 12:00:01.100",
      EventID: "4673", Provider: "Microsoft-Windows-Security-Auditing", Computer: "WS-GOLDEN",
      SourceProcessId: "", TargetProcessId: "", TargetProcessGuid: "", GrantedAccess: "",
      PrivilegeList: "SeDebugPrivilege",
    },
    // EID 3: attacker outbound network (represented as create-column shape + event id)
    {
      ProcessId: "4242", ParentProcessId: "",
      ProcessGuid: attackerGuid, ParentProcessGuid: "",
      Image: "", ParentImage: "", CommandLine: "DestinationIp: 203.0.113.50 DestinationPort: 443", User: "",
      UtcTime: "2026-04-01 12:00:02.000",
      EventID: "3", Provider: "Microsoft-Windows-Sysmon", Computer: "WS-GOLDEN",
      SourceProcessId: "4242", TargetProcessId: "", TargetProcessGuid: "", GrantedAccess: "",
      PrivilegeList: "",
    },
  ];

  const { meta, ctx } = makeEidStub(GOLDEN_HEADERS, rows, "EventID");
  // Query only process creates for the tree nodes; enrichment queries other EIDs separately.
  const tree = getProcessTree(meta, { eventIdValue: "1" }, ctx);

  assert.ok(tree.processes.length >= 3, "golden corpus must produce create nodes");
  assert.equal(tree.useGuid, true);

  const attacker = tree.processes.find((p) => p.pid === "4242");
  const victim = tree.processes.find((p) => p.pid === "700");
  assert.ok(attacker, "attacker powershell node");
  assert.ok(victim, "victim lsass node");

  // GUID parent link explorer → powershell
  assert.equal(attacker.linkSource, "guid");
  assert.equal(attacker.linkConfidence, "high");

  // Injection / hollowing on victim
  assert.ok(victim.injectionIndicators, "lsass must have injectionIndicators");
  assert.equal(victim.injectionIndicators.hollowingLikely, true);
  assert.ok(victim.injectionIndicators.suspiciousAccessCount >= 1);

  // Privilege use on attacker
  assert.ok(attacker.privilegeUse, "attacker must have privilegeUse from 4673");
  assert.ok((attacker.privilegeUse.privileges?.sedebugprivilege || 0) >= 1);

  // Network activity on attacker (EID 3 matched by GUID/PID)
  assert.ok(attacker.networkActivity, "attacker must have networkActivity from EID 3");
  assert.ok(attacker.networkActivity.eventCount >= 1);

  // Stats counters
  assert.ok(tree.stats.accessMatched >= 1);
  assert.ok(tree.stats.privilegeMatched >= 1);
  assert.ok((tree.stats.networkMatched || 0) >= 1);
  assert.equal(tree.stats.truncated, false);
});
