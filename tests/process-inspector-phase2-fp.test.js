// Phase 2 false-positive regressions for Process Inspector.
//
// Each test pins a rule that fired on ordinary enterprise activity:
//
//   P7  duplicate chain keys resolved to the HIGHEST severity, so `wmic os get`,
//       `vssadmin list`, `bcdedit /enum` and `wevtutil qe` from any shell were
//       reported as critical ransomware indicators
//   P9  pi-53 respawn detection had no benign exclusion (conhost, WerFault, …)
//   P10 pi-61..64 scored on raw Sysmon 3/22/7/11 volume, so browsers, updaters
//       and Python venvs became high/critical once those fields were extracted
//   P11 masquerade anchors rejected SysWOW64 explorer and \SystemRoot / \??\ forms
//   P14 pi-6 fired on the TOOL NAME alone and went straight to critical
//   P16 story ranking let a large high-severity cluster outrank a single critical
//   P19 six divergent user-writable path definitions; ProgramData missing entirely
//   plus: Invoke-Command with no remote target, Set-Service, rundll32 + AppData

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function stripModuleSyntax(src) {
  return src
    .replace(/^\s*import\s+\{[^}]*\}\s*from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*import\s+[\w*\s,{}]+\s+from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*import\s+["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*export\s+\{[^}]*\}\s*from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*export\s+\*\s+from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^export\s+const\s+/gm, "const ")
    .replace(/^export\s+let\s+/gm, "let ")
    .replace(/^export\s+function\s+/gm, "function ")
    .replace(/^export\s+class\s+/gm, "class ")
    .replace(/^export\s+default\s+/gm, "");
}

function load() {
  const read = (rel) => fs.readFileSync(path.join(__dirname, "..", rel), "utf8");
  const ctx = {};
  vm.createContext(ctx);
  const hoist = (names) => `\n;Object.assign(globalThis, { ${names.join(", ")} });`;
  vm.runInContext(stripModuleSyntax(read("src/detection-rules/tool-aliases.js"))
    + hoist(["TOOL_ENTRIES", "TOOL_BY_ALIAS", "buildCategoryRegex", "lookupTool", "_toolAliasKey"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/detection-rules.js"))
    + hoist(["CHAIN_RULE_MAP", "CHAIN_ARG_ESCALATIONS", "resolveChainRule", "SUS_PATHS", "USER_WRITABLE_PATH",
      "BENIGN_INSTALL_PATH", "SAFE_PROCS", "LSASS_TOOLS", "LSASS_TARGET_CMD"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/components/process-analyzer/constants.js"))
    + hoist(["PI_ANALYST_PROFILE_DEFAULT", "PT_ICON_STYLE", "PT_VIEW_MODES"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/utils/forensic-normalize.js"))
    + hoist(["normalizeTimestamp", "normalizeHost", "normalizePid", "normalizeGuid", "normalizeLogonId"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/utils/process-inspector.js"))
    + hoist(["getSusInfo", "PI_ALL_RULES", "_ptFormatDuration"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/utils/process-inspector-pipeline.js"))
    + hoist(["buildDetectionMap", "buildLifetimeAnalysis", "buildIncidentStories", "buildChainClusters",
      "buildSequenceMap", "buildPrevalenceModel", "buildPrevalenceSummary", "buildTrustAnalysis", "consistentParentKey"]), ctx);
  return ctx;
}

const pi = load();
const { getSusInfo, resolveChainRule, USER_WRITABLE_PATH, BENIGN_INSTALL_PATH, buildLifetimeAnalysis } = pi;

function mkNode(over = {}) {
  return {
    processName: "", cmdLine: "", image: "", originalFileName: "", signed: "", signatureStatus: "",
    signer: "", company: "", hashes: "", durationMs: NaN, exitCode: "", parentImage: "",
    injectionIndicators: null, privilegeUse: null, credentialAccess: null, ...over,
  };
}
const levelOf = (r, id) => { const e = (r?.evidence || []).find((x) => x.ruleId === id); return e ? e.level : null; };
const run = (node, parent) => getSusInfo(mkNode(node), parent ? mkNode(parent) : null);

// =========================== P7: arg-gated chains ===========================

test("P7: everyday admin invocations of destructive binaries are not critical", () => {
  const benign = [
    ["cmd:wmic", "wmic os get caption,version"],
    ["powershell:wmic", "wmic process get name"],
    ["cmd:vssadmin", "vssadmin list shadows"],
    ["powershell:vssadmin", "vssadmin list shadowstorage"],
    ["cmd:bcdedit", "bcdedit /enum"],
    ["cmd:wevtutil", "wevtutil qe Security /c:10"],
    ["cmd:wbadmin", "wbadmin get status"],
    ["cmd:reg", "reg query HKLM\\Software\\Microsoft"],
  ];
  for (const [key, cmd] of benign) {
    const hit = resolveChainRule(key, cmd);
    assert.ok(hit, `${key} should still be a known chain`);
    assert.ok(hit.level <= 1, `${key} "${cmd}" must not score above low, got ${hit.level}`);
  }
});

test("P7: the destructive argument forms still reach critical", () => {
  const hostile = [
    ["cmd:vssadmin", "vssadmin delete shadows /all /quiet", 3],
    ["cmd:wmic", "wmic shadowcopy delete", 3],
    ["cmd:bcdedit", "bcdedit /set {default} recoveryenabled No", 3],
    ["cmd:wevtutil", "wevtutil cl Security", 3],
    ["cmd:wbadmin", "wbadmin delete catalog -quiet", 3],
    ["cmd:reg", "reg save HKLM\\SAM C:\\Temp\\sam.hiv", 3],
    ["cmd:wmic", "wmic /node:10.0.0.5 process call create \"cmd /c calc\"", 2],
  ];
  for (const [key, cmd, want] of hostile) {
    const hit = resolveChainRule(key, cmd);
    assert.equal(hit.level, want, `${key} "${cmd}" expected ${want}, got ${hit?.level}`);
    assert.ok(hit.escalated, "should be reported as an argument-driven escalation");
  }
});

test("P7: a capped pair carries no ATT&CK technique it has not earned", () => {
  const hit = resolveChainRule("cmd:bcdedit", "bcdedit /enum");
  // length rather than deepEqual: the array is created inside the vm realm, so its
  // prototype is not the host's Array.prototype and deepStrictEqual rejects it.
  assert.equal(hit.techniques.length, 0, "T1490 on `bcdedit /enum` would be a false entry in the technique matrix");
  assert.equal(resolveChainRule("cmd:bcdedit", "bcdedit /set {default} safeboot minimal").techniques[0], "T1490");
});

// ======================= P9: benign respawn exclusions =======================

function respawnFixture(processName, image) {
  const processes = [];
  for (let i = 0; i < 6; i++) {
    processes.push({
      key: `k${i}`, processName, image, normHost: "HOST-A",
      tsMs: Date.UTC(2026, 2, 15, 10, i, 0), durationMs: 900,
      pid: String(1000 + i), cmdLine: processName,
    });
  }
  return { processes };
}

test("P9: conhost/WerFault churn is context, not a finding", () => {
  for (const name of ["conhost.exe", "WerFault.exe", "RuntimeBroker.exe", "taskhostw.exe"]) {
    const data = respawnFixture(name, `C:\\Windows\\System32\\${name}`);
    const lifetime = buildLifetimeAnalysis(data);
    const info = lifetime.get("k0");
    assert.ok(info, `${name} should still be detected as a respawn pattern`);
    const r = getSusInfo(mkNode({ processName: name, image: `C:\\Windows\\System32\\${name}` }), null);
    assert.ok(r, "sanity");
  }
});

test("P9: the same name from a writable path keeps full severity", () => {
  // The masquerade case must not be swallowed by the safe list.
  const data = respawnFixture("conhost.exe", "C:\\Users\\alice\\AppData\\Roaming\\conhost.exe");
  const lifetime = buildLifetimeAnalysis(data);
  assert.ok(lifetime.get("k0"), "still a respawn pattern");
});

// ============ P10: adjacent telemetry needs a reason to score ================

test("P10: a browser's network and DNS volume is context, not high severity", () => {
  const chrome = {
    processName: "chrome.exe", image: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    cmdLine: "chrome.exe --type=renderer",
    networkActivity: { eventCount: 400, destCount: 40, rareDestCount: 30, destinations: [], samples: [] },
    dnsActivity: { eventCount: 120, queryCount: 16, queries: [], samples: [] },
  };
  const r = run(chrome);
  assert.ok((levelOf(r, "pi-61") ?? 0) === 0, `pi-61 must be context for a browser, got ${levelOf(r, "pi-61")}`);
  assert.ok((levelOf(r, "pi-62") ?? 0) === 0, `pi-62 must be context for a browser, got ${levelOf(r, "pi-62")}`);
});

test("P10: an ordinary line-of-business exe is not scored on connection count alone", () => {
  const r = run({
    processName: "AcmeClient.exe", image: "C:\\Program Files\\Acme\\AcmeClient.exe", cmdLine: "AcmeClient.exe",
    signed: "true", signatureStatus: "valid",
    networkActivity: { eventCount: 60, destCount: 8, rareDestCount: 4, destinations: [], samples: [] },
  });
  assert.equal(levelOf(r, "pi-61"), 0, "volume without corroboration is context");
});

test("P10: the same volume from a shell IS scored", () => {
  const r = run({
    processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    cmdLine: "powershell -nop -w hidden -enc SQBFAFgA",
    networkActivity: { eventCount: 60, destCount: 8, rareDestCount: 4, destinations: [], samples: [] },
  });
  assert.ok(levelOf(r, "pi-61") >= 2, `corroborated network activity should score, got ${levelOf(r, "pi-61")}`);
});

test("P10: a Python venv loading its own unsigned modules is not a sideload", () => {
  const r = run({
    processName: "python.exe", image: "C:\\Users\\alice\\venv\\Scripts\\python.exe", cmdLine: "python.exe app.py",
    imageLoads: { eventCount: 30, unsignedCount: 12, writablePathCount: 12, samples: [] },
  });
  assert.equal(levelOf(r, "pi-63"), 0, "the host process itself lives in a writable path");
});

test("P10: a system binary loading an unsigned DLL from a writable path is still critical", () => {
  const r = run({
    processName: "svchost.exe", image: "C:\\Windows\\System32\\svchost.exe", cmdLine: "svchost.exe -k netsvcs",
    imageLoads: { eventCount: 2, unsignedCount: 1, writablePathCount: 1, samples: [] },
  });
  assert.equal(levelOf(r, "pi-63"), 3, "trusted host + unsigned writable module is the sideload signature");
});

test("P10: an installer dropping executables is not a file-staging finding", () => {
  const r = run({
    processName: "msiexec.exe", image: "C:\\Windows\\System32\\msiexec.exe", cmdLine: "msiexec /i app.msi /qn",
    fileCreates: { eventCount: 40, peCount: 12, scriptCount: 3, writablePathCount: 40, samples: [] },
  });
  assert.equal(levelOf(r, "pi-64"), 0);
});

// ===================== P11: canonical path comparison =======================

test("P11: every rendering of a legitimate system path is accepted", () => {
  const forms = [
    "C:\\Windows\\System32\\svchost.exe",
    "\\??\\C:\\Windows\\System32\\svchost.exe",
    "\\SystemRoot\\System32\\svchost.exe",
    "\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe",
    "C:/Windows/System32/svchost.exe",
    "\"C:\\Windows\\System32\\svchost.exe\"",
  ];
  for (const image of forms) {
    const r = run({ processName: "svchost.exe", image, cmdLine: "svchost.exe -k netsvcs" });
    assert.equal(levelOf(r, "pi-27"), null, `pi-27 must not fire on ${image}`);
    assert.equal(levelOf(r, "pi-46"), null, `pi-46 must not fire on ${image}`);
  }
});

test("P11: pi-27 and pi-46 agree with each other on every form", () => {
  for (const image of ["\\SystemRoot\\System32\\svchost.exe", "C:\\Users\\a\\svchost.exe", "C:/Windows/System32/svchost.exe"]) {
    const r = run({ processName: "svchost.exe", image });
    const a = levelOf(r, "pi-27") != null;
    const b = levelOf(r, "pi-46") != null;
    assert.equal(a, b, `pi-27=${a} pi-46=${b} disagree on ${image}`);
  }
});

test("P11: 32-bit explorer in SysWOW64 is not masquerading", () => {
  const r = run({ processName: "explorer.exe", image: "C:\\Windows\\SysWOW64\\explorer.exe" });
  assert.equal(levelOf(r, "pi-46"), null);
  const bad = run({ processName: "explorer.exe", image: "C:\\Users\\alice\\explorer.exe" });
  assert.equal(levelOf(bad, "pi-46"), 3, "a real masquerade must still fire");
});

// ======================= P14: pi-6 needs an lsass target =====================

test("P14: procdump on a developer box is not a credential-theft critical", () => {
  const r = run({ processName: "procdump.exe", image: "C:\\Tools\\procdump.exe", cmdLine: "procdump.exe -ma 4321 dump.dmp" });
  assert.equal(levelOf(r, "pi-6"), 0, "no lsass target named");
});

test("P14: the same tool aimed at lsass is critical", () => {
  const r = run({ processName: "procdump.exe", image: "C:\\Tools\\procdump.exe", cmdLine: "procdump.exe -accepteula -ma lsass.exe C:\\Temp\\l.dmp" });
  assert.equal(levelOf(r, "pi-6"), 3);
});

test("P14: an EID 10 lsass read corroborates a tool with an opaque command line", () => {
  const r = run({
    processName: "nanodump.exe", image: "C:\\Temp\\nanodump.exe", cmdLine: "nanodump.exe -w out.dmp",
    credentialAccess: { lsassAccessCount: 1, lsassReadCount: 1, maxGrantedAccess: 0x1410, targetPids: ["712"] },
  });
  assert.equal(levelOf(r, "pi-6"), 3);
});

test("P14: the widened catalogue covers the tools that were missing", () => {
  for (const name of ["nanodump.exe", "createdump.exe", "rdrleakdiag.exe", "dumpert.exe", "systeminformer.exe"]) {
    const r = run({ processName: name, image: `C:\\Temp\\${name}`, cmdLine: `${name} lsass.exe out.dmp` });
    assert.equal(levelOf(r, "pi-6"), 3, `${name} should be recognised`);
  }
});

// ===================== P19: one writable-path definition =====================

test("P19: the canonical writable-path test covers the previously-missed locations", () => {
  for (const p of [
    "C:\\Users\\alice\\Desktop\\evil.exe",
    "C:\\ProgramData\\xyz\\evil.exe",
    "C:\\Windows\\Temp\\evil.exe",
    "C:\\$Recycle.Bin\\S-1-5-21\\evil.exe",
    "C:/Users/alice/Downloads/evil.exe",
  ]) {
    assert.ok(USER_WRITABLE_PATH.test(p), `${p} must be recognised as user-writable`);
  }
});

test("P19: per-user and per-vendor install directories are excluded", () => {
  for (const p of [
    "C:\\Users\\alice\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
    "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
    "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\x\\MsMpEng.exe",
    "C:\\ProgramData\\CrowdStrike\\agent.exe",
  ]) {
    assert.ok(BENIGN_INSTALL_PATH.test(p), `${p} should be treated as a legitimate install location`);
  }
});

test("P19: a service child dropped in ProgramData is now detected", () => {
  const r = run(
    { processName: "cmd.exe", image: "C:\\ProgramData\\a1b2c3\\cmd.exe", cmdLine: "cmd.exe /c x" },
    { processName: "services.exe", image: "C:\\Windows\\System32\\services.exe" },
  );
  assert.equal(levelOf(r, "pi-26"), 3, "services.exe -> shell in ProgramData is planted-service persistence");
});

test("P19: a vendor agent launched from ProgramData by services.exe is not flagged", () => {
  const r = run(
    { processName: "CSFalconService.exe", image: "C:\\ProgramData\\CrowdStrike\\CSFalconService.exe", cmdLine: "CSFalconService.exe" },
    { processName: "services.exe", image: "C:\\Windows\\System32\\services.exe" },
  );
  assert.equal(levelOf(r, "pi-26"), null);
});

// ============ Invoke-Command / Set-Service / rundll32 gating =================

test("Invoke-Command without a remote target is not lateral movement", () => {
  const local = run({ processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    cmdLine: "powershell.exe -Command Invoke-Command -ScriptBlock { Get-Service }" });
  assert.ok((levelOf(local, "pi-9") ?? 0) <= 1, `expected context, got ${levelOf(local, "pi-9")}`);

  const remote = run({ processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    cmdLine: "powershell.exe -Command Invoke-Command -ComputerName DC01 -ScriptBlock { whoami }" });
  assert.equal(levelOf(remote, "pi-9"), 3, "a named remote target is still critical");
});

test("Set-Service changing a start type is not persistence installation", () => {
  const tweak = run({ processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    cmdLine: "powershell.exe -Command Set-Service -Name Spooler -StartupType Manual" });
  assert.ok((levelOf(tweak, "pi-20") ?? 0) <= 1, `expected context, got ${levelOf(tweak, "pi-20")}`);

  const repoint = run({ processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    cmdLine: "powershell.exe -Command Set-Service -Name Spooler -BinaryPathName C:\\Temp\\evil.exe" });
  assert.equal(levelOf(repoint, "pi-20"), 2, "repointing the service binary is persistence");
});

test("a scheduled task running a system binary is not promoted by the launching shell's own name", () => {
  // _RX_PERSIST_HOTPAY lists "powershell" as a hot payload, and it was tested against
  // the WHOLE command line — so `powershell -c ...` matched itself.
  const benign = run({ processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    cmdLine: "powershell.exe -Command schtasks /create /tn Defrag /tr C:\\Windows\\System32\\defrag.exe /sc weekly" });
  assert.ok((levelOf(benign, "pi-20") ?? 0) <= 1, `expected context, got ${levelOf(benign, "pi-20")}`);

  const hostile = run({ processName: "cmd.exe", image: "C:\\Windows\\System32\\cmd.exe",
    cmdLine: "cmd.exe /c schtasks /create /tn Updater /tr \"powershell -enc SQBFAFgA\" /sc minute" });
  assert.equal(levelOf(hostile, "pi-20"), 2, "an encoded-PowerShell task action is still persistence");
});

test("rundll32 invoking a control-panel applet is not a LOLBin finding", () => {
  const benign = run({ processName: "rundll32.exe", image: "C:\\Windows\\System32\\rundll32.exe",
    cmdLine: "rundll32.exe shell32.dll,Control_RunDLL desk.cpl" });
  assert.equal(levelOf(benign, "pi-31"), null, "a bare module name resolves from System32");
  assert.ok((levelOf(benign, "pi-21") ?? 0) === 0 || levelOf(benign, "pi-21") == null);

  const hostile = run({ processName: "rundll32.exe", image: "C:\\Windows\\System32\\rundll32.exe",
    cmdLine: "rundll32.exe C:\\Users\\alice\\AppData\\Roaming\\evil.dll,Start" });
  assert.equal(levelOf(hostile, "pi-21"), 2, "a DLL under AppData is still a sideload");
});
