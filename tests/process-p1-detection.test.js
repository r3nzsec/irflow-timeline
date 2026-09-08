// P1: expanded sequences + multi-field custom rule validation/compile.
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function stripModuleSyntax(src) {
  return src
    .replace(/^\s*import\s+\{[^}]*\}\s*from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*import\s+[\w*\s,{}]+\s+from\s*["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^\s*import\s+["'][^"']+["']\s*;?\s*$/gm, "")
    .replace(/^export\s+const\s+/gm, "const ")
    .replace(/^export\s+function\s+/gm, "function ")
    .replace(/^export\s+default\s+/gm, "")
    .replace(/export\s*\{[^}]+\}\s*;?/g, "");
}

function loadPipeline() {
  const root = path.join(__dirname, "..");
  // Stubs stand in for the pipeline's imports. This file only exercises SEQ_DEFS and
  // the custom-rule validators, so the detection-rules constants just need to exist
  // as regexes — the pipeline evaluates them at module scope.
  const stubs = `
    function getSusInfo() { return { level: 0, reason: null, evidence: [], behaviors: [], techniques: [] }; }
    function normalizeTimestamp() { return NaN; }
    function normalizeHost(v) { return String(v||'').trim().toLowerCase(); }
    function _ptFormatDuration() { return ''; }
    var SAFE_PROCS = /^$/i;
    var USER_WRITABLE_PATH = /[\\\\/](users|temp|tmp|appdata|downloads|public|perflogs|programdata)[\\\\/]/i;
    var BENIGN_INSTALL_PATH = /^$/i;
  `;
  const pipe = stripModuleSyntax(fs.readFileSync(path.join(root, "src/utils/process-inspector-pipeline.js"), "utf8"));
  const sandbox = { module: { exports: {} }, exports: {}, console, Math, Date, Number, String, Array, Object, Map, Set, JSON, RegExp };
  vm.createContext(sandbox);
  vm.runInContext(stubs + "\n" + pipe + `
    module.exports = {
      SEQ_DEFS,
      compileCustomRules,
      validateCustomRule,
      validateCustomRulePattern,
    };
  `, sandbox);
  return sandbox.module.exports;
}

const pipe = loadPipeline();

describe("P1 sequences catalog", () => {
  it("includes new high-value multi-stage sequences", () => {
    const ids = pipe.SEQ_DEFS.map((s) => s.id);
    for (const id of [
      "seq-dump-lateral",
      "seq-office-download-rmm",
      "seq-amsi-inject",
      "seq-defender-payload",
      "seq-stage-persist",
      "seq-exec-network",
      "seq-drop-exec",
    ]) {
      assert.ok(ids.includes(id), `missing sequence ${id}`);
    }
    assert.ok(pipe.SEQ_DEFS.length >= 14);
  });
});

describe("P1 multi-field custom rules", () => {
  it("validateCustomRule accepts parent+child without regex", () => {
    const err = pipe.validateCustomRule({
      name: "Office PS",
      parentProcess: "winword.exe",
      processName: "powershell.exe",
      severity: "critical",
      behavior: "script-exec",
      technique: "T1059.001",
    });
    assert.equal(err, "");
  });

  it("validateCustomRule rejects empty criteria", () => {
    const err = pipe.validateCustomRule({ name: "Empty" });
    assert.ok(err.includes("field") || err.includes("pattern"));
  });

  it("compileCustomRules compiles multi-field matchers and rejects ReDoS", () => {
    const compiled = pipe.compileCustomRules([
      {
        name: "Office PS",
        parentProcess: "winword.exe",
        processName: "powershell.exe",
        severity: "critical",
        behavior: "script-exec",
        technique: "T1059.001",
      },
      {
        name: "Bad regex",
        pattern: "(a+)+",
        severity: "high",
      },
    ]);
    assert.ok(compiled);
    assert.equal(compiled.length, 1);
    assert.equal(compiled[0].parentProcess, "winword");
    assert.equal(compiled[0].processName, "powershell");
    assert.equal(compiled[0]._rx, null);
  });
});
