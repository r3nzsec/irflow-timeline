// Phase 3 regressions for Process Inspector: detections that could never fire.
//
//   P3  EID 10 indicators were attached to the process being ACCESSED, so the tool
//       that opened lsass carried no finding at all; and VM_READ-only handles (the
//       actual mimikatz/procdump mask) were not treated as suspicious
//   P6  the chain gate demoted wsmprovhost / dllhost / mmc / services children and
//       every discovery singleton, so remote PowerShell, DCOM and web-shell recon
//       scored zero
//   P12 pi-15 tested the INTERPRETER's path (always System32) instead of the script's
//   P13 remote-access RMM parents got the unattended-management-agent discount
//   P18 TUNNEL_TOOLS was built and exported but never imported

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
    + hoist(["CHAIN_RULE_MAP", "resolveChainRule", "SUS_PATHS", "USER_WRITABLE_PATH", "BENIGN_INSTALL_PATH",
      "SAFE_PROCS", "LSASS_TOOLS", "LSASS_TARGET_CMD", "TUNNEL_TOOLS", "RMM_TOOLS", "EXFIL_TOOLS"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/components/process-analyzer/constants.js"))
    + hoist(["PI_ANALYST_PROFILE_DEFAULT", "PT_ICON_STYLE", "PT_VIEW_MODES"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/utils/forensic-normalize.js"))
    + hoist(["normalizeTimestamp", "normalizeHost", "normalizePid", "normalizeGuid", "normalizeLogonId"]), ctx);
  vm.runInContext(stripModuleSyntax(read("src/utils/process-inspector.js"))
    + hoist(["getSusInfo", "PI_ALL_RULES", "_ptFormatDuration"]), ctx);
  return ctx;
}

const pi = load();
const { getSusInfo, TUNNEL_TOOLS } = pi;

const mk = (o) => ({
  processName: "", cmdLine: "", image: "", originalFileName: "", signed: "", signatureStatus: "",
  signer: "", company: "", hashes: "", durationMs: NaN, exitCode: "", parentImage: "",
  injectionIndicators: null, privilegeUse: null, credentialAccess: null, ...o,
});
const run = (node, parent, opts) => getSusInfo(mk(node), parent ? mk(parent) : null, opts);
const levelOf = (r, id) => { const e = (r?.evidence || []).find((x) => x.ruleId === id); return e ? e.level : null; };
const maxLevel = (r) => (r?.evidence || []).reduce((m, e) => Math.max(m, e.level || 0), 0);

// =============== P3: lsass access attributed to the SOURCE ==================

test("P3: a process that read lsass memory is flagged (the classic 0x1410 mask)", () => {
  const r = run({
    processName: "rundll32.exe", image: "C:\\Windows\\System32\\rundll32.exe",
    cmdLine: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\Temp\\out.dmp full",
    credentialAccess: { lsassAccessCount: 1, lsassReadCount: 1, maxGrantedAccess: 0x1410, targetPids: ["712"] },
  });
  assert.equal(levelOf(r, "pi-65"), 3, "VM_READ on lsass needs no VM_WRITE to be credential theft");
});

test("P3: a query-only handle on lsass is context, not a finding", () => {
  // 0x1000 (QUERY_LIMITED_INFORMATION) is what Task Manager and every EDR agent takes.
  const r = run({
    processName: "taskmgr.exe", image: "C:\\Windows\\System32\\taskmgr.exe", cmdLine: "taskmgr.exe",
    credentialAccess: { lsassAccessCount: 4, lsassReadCount: 0, queryOnly: true, maxGrantedAccess: 0x1000, targetPids: ["712"] },
  });
  assert.equal(levelOf(r, "pi-65"), 0);
});

test("P3: a process with no lsass access is silent", () => {
  const r = run({ processName: "notepad.exe", image: "C:\\Windows\\System32\\notepad.exe", cmdLine: "notepad.exe" });
  assert.equal(levelOf(r, "pi-65"), null);
});

// ================= P6: high-signal parents keep their severity ==============

test("P6: a WinRM session host spawning a shell is not demoted to context", () => {
  const r = run(
    { processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmdLine: "powershell.exe -Command Get-Process" },
    { processName: "wsmprovhost.exe", image: "C:\\Windows\\System32\\wsmprovhost.exe" },
  );
  assert.ok(levelOf(r, "pi-2") >= 2, `remote PowerShell must score, got ${levelOf(r, "pi-2")}`);
});

test("P6: a DCOM surrogate spawning cmd is not demoted", () => {
  const r = run(
    { processName: "cmd.exe", image: "C:\\Windows\\System32\\cmd.exe", cmdLine: "cmd.exe /c dir" },
    { processName: "dllhost.exe", image: "C:\\Windows\\System32\\dllhost.exe" },
  );
  assert.ok(levelOf(r, "pi-2") >= 2, `DCOM lateral movement must score, got ${levelOf(r, "pi-2")}`);
});

test("P6: web-shell recon under an IIS worker keeps full severity", () => {
  const r = run(
    { processName: "whoami.exe", image: "C:\\Windows\\System32\\whoami.exe", cmdLine: "whoami" },
    { processName: "w3wp.exe", image: "C:\\Windows\\System32\\inetsrv\\w3wp.exe" },
  );
  assert.equal(levelOf(r, "pi-18"), 3, "an IIS worker running whoami is a web shell, not a login script");
});

test("P6: svchost and taskhostw children ARE still demoted (the noisy case)", () => {
  for (const parent of ["svchost.exe", "taskhostw.exe"]) {
    const r = run(
      { processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmdLine: "powershell.exe -Command Get-Date" },
      { processName: parent, image: `C:\\Windows\\System32\\${parent}` },
    );
    assert.equal(levelOf(r, "pi-2"), 0, `${parent} children stay context without a corroborating command line`);
  }
});

test("P6: a corroborated svchost child still scores", () => {
  const r = run(
    { processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmdLine: "powershell -nop -w hidden -enc SQBFAFgA" },
    { processName: "svchost.exe", image: "C:\\Windows\\System32\\svchost.exe" },
  );
  assert.ok(levelOf(r, "pi-2") >= 2);
});

// ======================== P12: pi-15 tests the SCRIPT ========================

test("P12: wscript running a script from AppData now fires", () => {
  const r = run({
    processName: "wscript.exe", image: "C:\\Windows\\System32\\wscript.exe",
    cmdLine: "wscript.exe C:\\Users\\alice\\AppData\\Roaming\\update.vbs",
  });
  assert.equal(levelOf(r, "pi-15"), 2, "the interpreter is always in System32 — the SCRIPT path is the signal");
});

test("P12: wscript running a system script does not fire", () => {
  const r = run({
    processName: "wscript.exe", image: "C:\\Windows\\System32\\wscript.exe",
    cmdLine: "wscript.exe C:\\Windows\\System32\\slmgr.vbs /dlv",
  });
  assert.equal(levelOf(r, "pi-15"), null);
});

// ================= P13: remote-access RMM is not discounted =================

test("P13: encoded PowerShell under a remote-access RMM is not demoted", () => {
  for (const rmm of ["screenconnect.clientservice.exe", "connectwisecontrol.exe", "ninjaoneagent.exe", "anydesk.exe"]) {
    const r = run(
      { processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmdLine: "powershell -nop -w hidden -enc SQBFAFgA" },
      { processName: rmm, image: `C:\\Program Files\\x\\${rmm}` },
    );
    assert.ok(maxLevel(r) >= 3, `hands-on-keyboard under ${rmm} must not be discounted (max level ${maxLevel(r)})`);
  }
});

test("P13: an unattended configuration agent still gets the discount", () => {
  const r = run(
    { processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdLine: "powershell.exe -File C:\\Windows\\CCM\\inventory.ps1" },
    { processName: "ccmexec.exe", image: "C:\\Windows\\CCM\\CcmExec.exe" },
  );
  assert.ok(maxLevel(r) <= 1, `SCCM inventory should stay quiet, got ${maxLevel(r)}`);
});

// ========================== P18: tunnel catalogue ===========================

test("P18: the canonical tunnel catalogue is actually consulted", () => {
  for (const name of ["ligolo-ng.exe", "gost.exe", "npc.exe", "revsocks.exe", "iox.exe", "socat.exe", "stowaway.exe"]) {
    const r = run({ processName: name, image: `C:\\Users\\alice\\Downloads\\${name}`, cmdLine: name });
    assert.equal(levelOf(r, "pi-24"), 2, `${name} is a tunnel tool and was previously invisible`);
  }
});

test("P18: Go release-artifact filenames are recognised", () => {
  for (const name of ["frpc_windows_amd64.exe", "cloudflared-windows-amd64.exe", "chisel_windows_amd64.exe"]) {
    assert.ok(TUNNEL_TOOLS.test(name), `${name} must match the catalogue`);
    const r = run({ processName: name, image: `C:\\Temp\\${name}`, cmdLine: name });
    assert.equal(levelOf(r, "pi-24"), 2);
  }
});

test("P18: netsh portproxy is treated as a tunnel even with no dropped tool", () => {
  const r = run({
    processName: "netsh.exe", image: "C:\\Windows\\System32\\netsh.exe",
    cmdLine: "netsh interface portproxy add v4tov4 listenport=3389 connectaddress=10.0.0.9",
  });
  assert.equal(levelOf(r, "pi-24"), 2);
});

test("P18: an ordinary binary is not a tunnel", () => {
  assert.ok(!TUNNEL_TOOLS.test("notepad.exe"));
  const r = run({ processName: "notepad.exe", image: "C:\\Windows\\System32\\notepad.exe", cmdLine: "notepad.exe" });
  assert.equal(levelOf(r, "pi-24"), null);
});

// ============ P15: chain rules require a trustworthy parent edge =============

test("P15: chain rules are skipped when the parent edge is a PID-reuse mislink", () => {
  const node = { processName: "powershell.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    cmdLine: "powershell.exe -Command Get-Date", parentImage: "C:\\Program Files\\Microsoft Office\\winword.exe" };
  const parent = { processName: "svchost.exe", image: "C:\\Windows\\System32\\svchost.exe" };
  const trusted = run(node, parent, { parentEdgeConsistent: true });
  const mislinked = run(node, parent, { parentEdgeConsistent: false });
  assert.ok((mislinked.evidence || []).every((e) => e.cat !== "chain"),
    "a chain rule on a mislinked edge would be an invented parent->child relationship");
  assert.ok((trusted.evidence || []).length >= (mislinked.evidence || []).length);
});
