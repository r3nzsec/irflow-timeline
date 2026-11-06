// Tests for the unified RMM/exfil/tunnel taxonomy (Finding #5).
// Locks in that the standalone matcher, the chain rules, and the PI allowlist
// all see the same canonical names — the previous drift between these three
// sites caused screenconnect.clientservice.exe and ateraagent.exe to slip past
// the standalone "RMM context" check entirely.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// Load the ESM tool-aliases module via the same eval-in-vm trick used by
// forensic-normalize.test.js — keeps the test runner pure-Node, no build step.
function loadAliases() {
  const src = fs.readFileSync(path.join(__dirname, "..", "src", "detection-rules", "tool-aliases.js"), "utf8");
  const munged = src
    .replace(/^export\s+const\s+/gm, "const ")
    .replace(/^export\s+function\s+/gm, "function ");
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(
    munged + "\n;Object.assign(globalThis, { TOOL_ENTRIES, TOOL_BY_ALIAS, _toolAliasKey, buildCategoryRegex, lookupTool });",
    ctx,
  );
  return {
    TOOL_ENTRIES: ctx.TOOL_ENTRIES,
    lookupTool: ctx.lookupTool,
    buildCategoryRegex: ctx.buildCategoryRegex,
  };
}
const { TOOL_ENTRIES, lookupTool, buildCategoryRegex } = loadAliases();

test("buildCategoryRegex('rmm') matches the previously-missed full names", () => {
  const rx = buildCategoryRegex("rmm");
  // Names that the OLD regex missed (Finding #5)
  const wasMissed = [
    "screenconnect.clientservice.exe",
    "screenconnect.windowsclient.exe",
    "screenconnect.clientservice",
    "teamviewer_service.exe",
    "ateraagent.exe",
    "atera_agent.exe",
    "tv_x64.exe",
    "tv_w32",
  ];
  for (const name of wasMissed) {
    assert.ok(rx.test(name), `RMM_TOOLS regex must match ${name}`);
  }
});

test("buildCategoryRegex('rmm') still matches the originally-covered names", () => {
  const rx = buildCategoryRegex("rmm");
  for (const name of ["anydesk.exe", "splashtop.exe", "rustdesk.exe", "supremo.exe", "teamviewer.exe"]) {
    assert.ok(rx.test(name), `RMM_TOOLS regex must still match ${name}`);
  }
});

test("buildCategoryRegex('tunnel') matches cloudflared, ngrok, chisel, frpc, plink", () => {
  const rx = buildCategoryRegex("tunnel");
  for (const name of ["ngrok.exe", "chisel.exe", "cloudflared.exe", "frpc", "frps.exe", "plink.exe"]) {
    assert.ok(rx.test(name), `TUNNEL_TOOLS regex must match ${name}`);
  }
});

test("lookupTool resolves any alias to a single canonical entry", () => {
  const sc1 = lookupTool("ScreenConnect.ClientService.exe");
  const sc2 = lookupTool("screenconnect.windowsclient");
  assert.equal(sc1?.canonical, "ScreenConnect");
  assert.equal(sc2?.canonical, "ScreenConnect");
  assert.equal(sc1, sc2, "all ScreenConnect aliases must map to the same entry object");
});

test("lookupTool returns null for non-tool names", () => {
  assert.equal(lookupTool("notepad.exe"), null);
  assert.equal(lookupTool(""), null);
  assert.equal(lookupTool(null), null);
});

test("Nizlo aliases resolve exactly and keep the documented install path sanctioned", () => {
  const rx = buildCategoryRegex("rmm");
  for (const name of ["Nizlo.Agent.exe", "Nizlo.Agent.Updater.exe", "Nizlo.RemoteBridge.exe"]) {
    assert.ok(rx.test(name), `RMM_TOOLS regex must match ${name}`);
    assert.equal(lookupTool(name)?.canonical, "Nizlo");
  }
  assert.equal(lookupTool("nizlo.com"), null, "generic domain text must not resolve as a process alias");
  assert.deepEqual(
    Array.from(lookupTool("Nizlo.Agent.exe").sanctionedPaths),
    ["\\nizlo\\agent\\"],
  );
});

test("every RMM entry with sanctionedPaths is well-formed for PI_ALLOWLIST seeding", () => {
  const rmm = TOOL_ENTRIES.filter((e) => e.category === "rmm" && e.sanctionedPaths);
  assert.ok(rmm.length >= 5, "expect at least 5 sanctioned RMM tools");
  for (const e of rmm) {
    assert.ok(Array.isArray(e.aliases) && e.aliases.length > 0, `${e.canonical}: aliases must be non-empty`);
    for (const p of e.sanctionedPaths) {
      assert.ok(p.startsWith("\\") && p.endsWith("\\"), `${e.canonical}: path "${p}" must have leading + trailing backslash`);
    }
  }
});
