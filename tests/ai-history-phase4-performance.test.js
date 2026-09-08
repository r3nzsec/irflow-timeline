"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { pageDiscoveryInventory } = require("../electron/parsers/ai-history/discovery-inventory");
const { readJsonlBounded } = require("../electron/parsers/ai-history/jsonl-reader");
const { extractAiHistory } = require("../electron/parsers/ai-history");
const { AiHistoryExtractAbortedError } = require("../electron/parsers/ai-history/extract-abort");
const { extractMergedAiHistoryRootsToDb } = require("../electron/parsers/ai-history/profile-scan");

test("bounded discovery pages are deterministic and list every remaining source", () => {
  const sourcePaths = ["/evidence/d", "/evidence/b", "/evidence/a", "/evidence/c", "/evidence/b"];
  const first = pageDiscoveryInventory(sourcePaths, { limit: 2 });
  const second = pageDiscoveryInventory(sourcePaths, { limit: 2, cursor: first.nextCursor });
  assert.deepEqual(first.paths, ["/evidence/a", "/evidence/b"]);
  assert.deepEqual(first.remainingPaths, ["/evidence/c", "/evidence/d"]);
  assert.deepEqual(second.paths, ["/evidence/c", "/evidence/d"]);
  assert.equal(second.nextCursor, null);
  assert.equal(first.fingerprintSha256, second.fingerprintSha256);
});

test("bounded JSONL reports observed bytes and acknowledges cancellation below two seconds", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-phase4-cancel-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const filePath = path.join(root, "large.jsonl");
  const fd = fs.openSync(filePath, "w");
  const line = `${JSON.stringify({ message: "x".repeat(4096) })}\n`;
  try {
    for (let i = 0; i < 8192; i++) fs.writeSync(fd, line);
  } finally {
    fs.closeSync(fd);
  }

  let canceled = false;
  const parseStats = { errors: 0 };
  const started = performance.now();
  const timer = setTimeout(() => { canceled = true; }, 10);
  await assert.rejects(
    readJsonlBounded(filePath, () => {}, {
      parseStats,
      checkAbort() { if (canceled) throw new AiHistoryExtractAbortedError(); },
    }),
    (error) => error?.canceled === true,
  );
  clearTimeout(timer);
  const latencyMs = performance.now() - started;
  assert.ok(latencyMs < 2000, `cancellation took ${latencyMs.toFixed(1)} ms`);
  assert.ok(parseStats.bytesRead > 0);
  assert.ok(parseStats.bytesRead < fs.statSync(filePath).size, "reader stopped before consuming the corpus");
});

test("qualified extraction exposes wall time, first result, throughput, RSS and source bytes", async () => {
  const fixture = path.join(__dirname, "fixtures", "ai-history", "codex", ".codex");
  const rows = await extractAiHistory("codex", fixture);
  const perf = rows._performance;
  assert.equal(perf.version, 1);
  assert.ok(perf.wallTimeMs >= 0);
  assert.ok(perf.firstResultLatencyMs != null);
  assert.ok(perf.rows > 0);
  assert.ok(perf.rowsPerSecond > 0);
  assert.ok(perf.bytesReadObserved > 0);
  assert.ok(perf.sourceBytesEligible >= perf.bytesReadObserved);
  assert.ok(perf.peakRssBytes >= perf.rssStartBytes);
  assert.ok(rows._sourceCoverage.every((entry) => Number.isFinite(entry.sizeBytes)));
});

test("a merged row-budget stop identifies every unprocessed physical source", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-phase4-remaining-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const roots = [];
  for (const name of ["a", "b"]) {
    const codex = path.join(root, name, ".codex");
    fs.mkdirSync(codex, { recursive: true });
    fs.writeFileSync(path.join(codex, "history.jsonl"), `${JSON.stringify({
      session_id: `session-${name}`,
      ts: 1788854400,
      text: `prompt-${name}`,
    })}\n`);
    roots.push({ tool: "codex", path: codex, label: `Codex ${name}` });
  }
  const inserted = [];
  const db = {
    databases: new Map(),
    createTab(tabId, headers) { this.databases.set(tabId, { headers, isLargeFile: false }); },
    insertBatchArrays(_tabId, rows) { inserted.push(...rows); },
  };
  const result = await extractMergedAiHistoryRootsToDb(db, "phase4", roots, {}, { maxRows: 1 });
  assert.equal(result.rowCount, 1);
  assert.equal(result.importMeta.discoveryInventory.eligibleSources, 2);
  assert.equal(result.importMeta.discoveryInventory.remainingSourceCount, 1);
  assert.equal(result.importMeta.discoveryInventory.remainingSources[0], path.join(roots[1].path, "history.jsonl"));
  const remaining = result.importMeta.sourceCoverage.find((entry) => entry.sourceFile.endsWith("b/.codex/history.jsonl"));
  assert.equal(remaining.status, "excluded");
  assert.match(remaining.reason, /global row budget/);
});
