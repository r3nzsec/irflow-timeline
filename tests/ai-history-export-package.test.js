"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  sanitizeExportBaseName,
  sha256File,
  enrichSourceManifest,
  buildExtractionReport,
  buildPackageManifest,
  buildSourcesOnlyManifest,
} = require("../electron/parsers/ai-history/export-package");

test("sanitizeExportBaseName strips unsafe characters", () => {
  assert.equal(sanitizeExportBaseName("Claude Code AI History (42)"), "Claude_Code_AI_History_42");
});

test("sha256File hashes file contents", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-hash-"));
  const filePath = path.join(tmp, "sample.txt");
  fs.writeFileSync(filePath, "hello ai history");
  const hash = await sha256File(filePath);
  assert.equal(hash.length, 64);
  assert.match(hash, /^[a-f0-9]+$/);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("enrichSourceManifest records exists and hash", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-manifest-"));
  const filePath = path.join(tmp, "history.jsonl");
  fs.writeFileSync(filePath, '{"display":"test"}\n');
  const { sources, hashedFileCount } = await enrichSourceManifest([{ value: filePath, count: 3 }]);
  assert.equal(sources.length, 1);
  assert.equal(sources[0].rowCount, 3);
  assert.equal(sources[0].exists, true);
  assert.ok(sources[0].sha256);
  assert.equal(hashedFileCount, 1);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("buildPackageManifest includes format version and tools", () => {
  const m = buildPackageManifest({
    tabName: "AI Query History",
    sourceFormat: "ai-history-claude-code",
    totalRows: 100,
    exportedRows: 50,
    filtersApplied: true,
    sources: [{ path: "/x/history.jsonl", rowCount: 50, exists: true }],
    hashedFileCount: 1,
    hashTruncated: false,
    toolBreakdown: [{ tool: "Claude Code", rowCount: 50 }],
  });
  assert.equal(m.format, "irflow-ai-history-package");
  assert.equal(m.formatVersion, 2);
  assert.equal(m.rowCount.exported, 50);
  assert.equal(m.toolBreakdown[0].tool, "Claude Code");
});

test("source manifest retains zero-row coverage and does not hash excluded sources", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-manifest-coverage-"));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const parsed = path.join(tmp, "parsed.jsonl");
  const excluded = path.join(tmp, "excluded.jsonl");
  fs.writeFileSync(parsed, '{"ok":true}\n');
  fs.writeFileSync(excluded, '{"secret":"never hashed by this gate"}\n');
  const sourceCoverage = [
    { version: 1, tool: "codex", sourceFile: parsed, status: "parsed", rows: 1, reason: "supported records emitted" },
    { version: 1, tool: "codex", sourceFile: excluded, status: "excluded", rows: 0, reason: "global row cap reached" },
  ];
  const result = await enrichSourceManifest([{ value: parsed, count: 1 }], { sourceCoverage });
  assert.equal(result.sources.length, 2);
  assert.ok(result.sources.find((entry) => entry.path === parsed).sha256);
  const omitted = result.sources.find((entry) => entry.path === excluded);
  assert.equal(omitted.rowCount, 0);
  assert.equal(omitted.coverage.status, "excluded");
  assert.equal(omitted.sha256, null);
  assert.match(omitted.sha256SkippedReason, /excluded/);
});

test("extraction report marks capped, malformed, and failed inputs as incomplete", () => {
  const extraction = buildExtractionReport({
    sourceCoverage: [
      { tool: "cursor", sourceFile: "/x/good.jsonl", status: "parsed", rows: 2 },
      { tool: "cursor", sourceFile: "/x/bad.jsonl", status: "malformed", rows: 0, errors: 1 },
    ],
    capped: { maxRows: 10, rowCount: 10 },
    parseErrors: 1,
  }, [{ tool: "cursor", path: "/x/missing.db", error: "unreadable" }]);
  assert.equal(extraction.complete, false);
  assert.deepEqual(extraction.statusCounts, { parsed: 1, malformed: 1 });
  assert.equal(extraction.failures.length, 1);
  assert.equal(extraction.capped.maxRows, 10);
});

test("buildSourcesOnlyManifest omits exported row count slice", () => {
  const m = buildSourcesOnlyManifest({
    tabName: "AI Query History",
    sourceFormat: "ai-history-profile",
    totalRows: 100,
    filtersApplied: false,
    sources: [{ path: "/x/history.jsonl", rowCount: 100, exists: true }],
    hashedFileCount: 1,
    hashTruncated: false,
    toolBreakdown: [{ tool: "Claude Code", rowCount: 100 }],
  });
  assert.equal(m.format, "irflow-ai-history-sources-only");
  assert.equal(m.rowCountInScope, 100);
  assert.equal(m.rowCount, undefined);
  assert.equal(m.sources.length, 1);
});
