// Triage-collection discovery: artifact classification and the lateral-movement
// relevance grading that drives which EVTX channels the import lane pre-selects.
//
// `electron/parsers/triage.js` was ported from the super-timeline dev tree rather than
// rewritten. These tests cover the LM-specific extensions added on top of that port, plus
// enough of the ported surface to catch a bad merge.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  classifyFile, scanTriageDir, classifyKapeCsvColumns, detectModuleOutput,
  lmEvtxRelevance, isLikelyEmptyEvtx, EMPTY_EVTX_BYTES, HIGH_VALUE_EVTX,
} = require("../electron/parsers/triage");

// ── LM relevance grading ────────────────────────────────────────────────────────

test("tier 3 is the always-want set", () => {
  for (const n of [
    "Security.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
  ]) {
    assert.equal(lmEvtxRelevance(n), 3, `${n} should be tier 3`);
  }
});

test("tier 2 covers the remote-execution and share channels", () => {
  for (const n of [
    "Microsoft-Windows-WinRM%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-SMBServer%4Security.evtx",
    "Microsoft-Windows-SmbClient%4Security.evtx",
    "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
  ]) {
    assert.equal(lmEvtxRelevance(n), 2, `${n} should be tier 2`);
  }
});

test("System is tier 1 and unrelated channels are tier 0", () => {
  assert.equal(lmEvtxRelevance("System.evtx"), 1);
  for (const n of [
    "Microsoft-Windows-PowerShell%4Operational.evtx", // rich, but not a lateral signal on its own
    "Application.evtx",
    "Microsoft-Windows-Bits-Client%4Operational.evtx",
    "OAlerts.evtx",
  ]) {
    assert.equal(lmEvtxRelevance(n), 0, `${n} should not be pre-selected`);
  }
});

test("relevance works on full paths and is case-insensitive", () => {
  assert.equal(lmEvtxRelevance("F:\\Windows\\System32\\winevt\\logs\\SECURITY.EVTX"), 3);
  assert.equal(lmEvtxRelevance("/mnt/c/Windows/System32/winevt/logs/security.evtx"), 3);
  assert.equal(lmEvtxRelevance("Security.txt"), 0, "non-EVTX must not be graded");
  assert.equal(lmEvtxRelevance(""), 0);
  assert.equal(lmEvtxRelevance(null), 0);
});

test("every tier-3 and tier-2 channel is also protected from the path cap", () => {
  // HIGH_VALUE_EVTX is what survives maxPathsPerKind truncation. Anything the LM lane
  // pre-selects must be in it, or a 300-EVTX collection could truncate it away.
  const graded = [
    "Security.evtx", "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-WinRM%4Operational.evtx", "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-SMBServer%4Security.evtx", "Microsoft-Windows-SmbClient%4Security.evtx",
    "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx", "System.evtx",
  ];
  for (const n of graded) {
    assert.ok(HIGH_VALUE_EVTX.has(n.toUpperCase()), `${n} is LM-graded but not protected from truncation`);
  }
});

// ── Empty-stub detection ────────────────────────────────────────────────────────

test("empty EVTX stubs are recognised by size", () => {
  // 4 KB header + one allocated-but-empty 64 KB chunk. Confirmed on both demo packages:
  // Azeroth's TerminalServices/SMB/System logs are all exactly this size.
  assert.equal(EMPTY_EVTX_BYTES, 69632);
  assert.ok(isLikelyEmptyEvtx(69632), "the canonical empty size must be flagged");
  assert.ok(isLikelyEmptyEvtx(68608));
  assert.ok(!isLikelyEmptyEvtx(69633), "one byte over is real data");
  assert.ok(!isLikelyEmptyEvtx(8_100_000));
  assert.ok(!isLikelyEmptyEvtx(0), "a zero-byte file is a different problem, not an empty log");
});

// ── Ported classification surface (bad-merge canary) ────────────────────────────

test("core artifact kinds still classify", () => {
  // Paths are built with path.join because that is what scanTriageDir feeds in — always
  // platform-native. (classifyFile leans on path.basename, so a Windows-literal path with
  // backslashes would not split on POSIX. That never happens here: the triage tree is
  // walked with readdir. lmEvtxRelevance is separator-agnostic because it can also be
  // handed a path out of stored metadata, e.g. an EvtxECmd SourceFile column.)
  const j = (...parts) => path.join("/evidence", ...parts);
  const cases = [
    [j("Windows", "System32", "winevt", "logs", "Security.evtx"), "evtx"],
    [j("$MFT"), "mft"],
    [j("$Extend", "$J"), "usn"],
    [j("Windows", "prefetch", "CMD.EXE-1234ABCD.pf"), "prefetch"],
    [j("Windows", "AppCompat", "Programs", "Amcache.hve"), "amcache"],
    [j("Windows", "System32", "config", "SYSTEM"), "registryHive"],
    [j("Users", "alice", "NTUSER.DAT"), "userHive"],
    [j("Windows", "System32", "SRU", "SRUDB.dat"), "srudb"],
    [j("Windows", "System32", "Tasks", "GoogleUpdater"), "scheduledTask"],
    [j("Users", "a", "AppData", "Local", "Microsoft", "Terminal Server Client", "Cache", "Cache0000.bin"), "rdp"],
    [j("Users", "a", "AppData", "Local", "Microsoft", "Terminal Server Client", "Cache", "bcache24.bmc"), "rdp"],
    [j("Windows", "readme.txt"), null],
  ];
  for (const [p, want] of cases) {
    assert.equal(classifyFile(p), want, `classifyFile(${p})`);
  }
});

test("EvtxECmd CSV output is recognised by its header signature", () => {
  // The parsed-KAPE lane depends on this: it is how an M_Out folder is told apart from
  // a raw Targets collection.
  const evtxEcmd = ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level",
    "Provider", "Channel", "Computer", "MapDescription", "UserName", "RemoteHost", "PayloadData1"];
  assert.equal(classifyKapeCsvColumns(evtxEcmd), "evtxEcmd");
  assert.equal(classifyKapeCsvColumns(["ExecutableName", "RunCount", "LastRun"]), "prefetch");
  assert.equal(classifyKapeCsvColumns(["Nope", "Neither"]), null);
  assert.equal(classifyKapeCsvColumns([]), null);
});

// ── Directory scan ──────────────────────────────────────────────────────────────

test("scanTriageDir reports per-file sizes and never follows symlinks", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "lm-triage-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const logs = path.join(root, "C", "Windows", "System32", "winevt", "logs");
  fs.mkdirSync(logs, { recursive: true });
  fs.writeFileSync(path.join(logs, "Security.evtx"), Buffer.alloc(200000));
  fs.writeFileSync(path.join(logs, "Microsoft-Windows-WinRM%4Operational.evtx"), Buffer.alloc(EMPTY_EVTX_BYTES));

  // A symlink pointing outside the root must not be descended into.
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "lm-outside-"));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  fs.writeFileSync(path.join(outside, "Application.evtx"), Buffer.alloc(1000));
  try { fs.symlinkSync(outside, path.join(root, "escape"), "dir"); } catch { /* platform may forbid */ }

  const scan = scanTriageDir(root);
  assert.equal(scan.counts.evtx, 2, "must find exactly the two in-tree EVTX files");

  const byName = Object.fromEntries((scan.files.evtx || []).map((f) => [path.basename(f.path), f]));
  assert.equal(byName["Security.evtx"].size, 200000, "per-file size must be reported");
  assert.ok(!isLikelyEmptyEvtx(byName["Security.evtx"].size));
  assert.ok(isLikelyEmptyEvtx(byName["Microsoft-Windows-WinRM%4Operational.evtx"].size),
    "a WinRM log at exactly the stub size must be flagged empty, not pre-selected");

  assert.ok(!scan.paths.evtx.some((p) => p.includes("escape")), "symlinked tree must not be scanned");
});

test("scanTriageDir reports progress and honours cancellation", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "lm-triage-cancel-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const logs = path.join(root, "C", "Windows", "System32", "winevt", "logs");
  fs.mkdirSync(logs, { recursive: true });
  for (let i = 0; i < 20; i++) fs.writeFileSync(path.join(logs, `Security${i}.evtx`), Buffer.alloc(1000));
  const ticks = [];
  const scan = scanTriageDir(root, { progressEvery: 5, onProgress: (p) => ticks.push(p) });
  assert.ok(scan.counts.evtx >= 20);
  assert.ok(ticks.length >= 2, `expected mid-walk ticks plus a final tick, got ${ticks.length}`);
  assert.equal(ticks[ticks.length - 1].scanned, scan.scanned);
  assert.equal(ticks[ticks.length - 1].classified, scan.total);
  let seen = 0;
  assert.throws(
    () => scanTriageDir(root, {
      isCancelled: () => {
        seen += 1;
        if (seen > 3) throw Object.assign(new Error("stop"), { cancelled: true });
      },
    }),
    (e) => e.cancelled === true,
  );
  assert.ok(seen > 3, "cancel is checked while walking files, not only between directories");
});

test("a parsed KAPE module folder is distinguished from a raw collection", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "lm-mout-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, "EventLogs"), { recursive: true });
  fs.writeFileSync(
    path.join(root, "EventLogs", "20260305_EvtxECmd_Output.csv"),
    "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,Computer,MapDescription\n1,1,2026-03-05 14:29:29,4624,Info,Sec,Security,HOST,Successful logon\n",
  );
  const probe = detectModuleOutput(root);
  assert.ok(probe.isModuleOutput, "should be recognised as parsed module output");
  assert.ok(probe.kinds.includes("evtxEcmd"), `expected evtxEcmd, got ${probe.kinds.join(",")}`);

  // A raw collection must NOT look like module output.
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), "lm-tout-"));
  t.after(() => fs.rmSync(raw, { recursive: true, force: true }));
  const rl = path.join(raw, "C", "Windows", "System32", "winevt", "logs");
  fs.mkdirSync(rl, { recursive: true });
  fs.writeFileSync(path.join(rl, "Security.evtx"), Buffer.alloc(1000));
  assert.equal(detectModuleOutput(raw).isModuleOutput, false);
});
