"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  AI_ARTIFACT_CONTRACT_VERSION,
  AI_ARTIFACT_REGISTRY,
} = require("../electron/parsers/ai-history/artifact-registry");
const { SourceCoverageTracker, SOURCE_STATUSES } = require("../electron/parsers/ai-history/source-coverage");
const { readJsonlBounded } = require("../electron/parsers/ai-history/jsonl-reader");
const { extractAiHistory } = require("../electron/parsers/ai-history");

test("artifact contract names every requested product surface and its support boundary", () => {
  assert.equal(AI_ARTIFACT_CONTRACT_VERSION, 2);
  for (const key of ["claude-code", "claude-desktop", "claude-consumer-chat", "codex", "grok-build", "grok-consumer", "grok-bot", "gemini-cli", "gemini-consumer", "cursor", "cursor-cloud"]) {
    assert.ok(AI_ARTIFACT_REGISTRY[key], `${key} is registered`);
    assert.ok(["partial", "unsupported"].includes(AI_ARTIFACT_REGISTRY[key].status));
  }
  for (const entry of Object.values(AI_ARTIFACT_REGISTRY).filter((item) => item.status !== "unsupported")) {
    assert.equal(entry.qualification.asOf, "2026-09-08");
    assert.ok(entry.qualification.applicationVersions.length > 0);
    assert.ok(entry.qualification.platforms.length > 0);
    for (const artifactSource of entry.sources) {
      assert.ok(artifactSource.signatures.length > 0);
      assert.ok(artifactSource.schemaVersions.length > 0);
    }
  }
  assert.equal(AI_ARTIFACT_REGISTRY["grok-consumer"].status, "unsupported");
  assert.equal(AI_ARTIFACT_REGISTRY["gemini-consumer"].status, "unsupported");
});

test("qualification manifest hashes every declared sanitized fixture", () => {
  const base = path.join(__dirname, "fixtures", "ai-history");
  const manifest = JSON.parse(fs.readFileSync(path.join(base, "qualification-manifest.json"), "utf8"));
  assert.equal(manifest.schemaVersion, 2);
  assert.equal(manifest.sanitized, true);
  for (const artifact of manifest.artifacts) {
    const data = fs.readFileSync(path.join(base, artifact.path));
    assert.equal(crypto.createHash("sha256").update(data).digest("hex"), artifact.sha256, artifact.path);
  }
});

test("source coverage ledger uses only contract statuses and retains counters", () => {
  const tracker = new SourceCoverageTracker("cursor", ["/evidence/a.jsonl", "/evidence/empty.txt"]);
  tracker.observeRows([{ SourceFile: "/evidence/a.jsonl" }, { SourceFile: "/evidence/a.jsonl" }]);
  tracker.mark("/evidence/bad.jsonl", "malformed", "invalid JSON", { errors: 3 });
  const report = tracker.report();
  assert.ok(report.every((entry) => SOURCE_STATUSES.includes(entry.status)));
  assert.equal(report.find((entry) => entry.sourceFile.endsWith("a.jsonl")).rows, 2);
  assert.equal(report.find((entry) => entry.sourceFile.endsWith("empty.txt")).status, "empty");
  assert.equal(report.find((entry) => entry.sourceFile.endsWith("bad.jsonl")).errors, 3);
});

test("bounded JSONL reader retains physical line numbers and byte offsets after bad records", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-jsonl-location-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, "records.jsonl");
  const first = '{"id":1}';
  const oversized = `{"body":"${"x".repeat(80)}"}`;
  const malformed = "{bad";
  const last = '{"id":5}';
  const content = `${first}\n${oversized}\n\n${malformed}\n${last}\n`;
  fs.writeFileSync(file, content);
  const seen = [];
  const parseStats = { errors: 0 };
  await readJsonlBounded(file, (obj, lineNumber, location) => seen.push({ obj, lineNumber, location }), {
    parseStats,
    maxLineBytes: 32,
  });
  assert.deepEqual(seen.map((item) => item.lineNumber), [1, 5]);
  assert.equal(seen[1].location.byteOffset, Buffer.byteLength(`${first}\n${oversized}\n\n${malformed}\n`));
  assert.equal(parseStats.oversizedLines, 1);
  assert.equal(parseStats.malformedLines, 1);
});

test("extractAiHistory emits a per-source completion ledger", async () => {
  const fixture = path.join(__dirname, "fixtures/ai-history/cursor/.cursor");
  const rows = await extractAiHistory("cursor", fixture);
  assert.ok(rows._sourceCoverage.length >= 1);
  assert.ok(rows._sourceCoverage.some((entry) => entry.status === "parsed" && entry.rows > 0));
});

test("source coverage classifies damaged JSONL per physical source", async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-cursor-coverage-"));
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));
  const cursorRoot = path.join(tempDir, ".cursor");
  const transcripts = path.join(cursorRoot, "projects", "demo", "agent-transcripts", "session-1");
  fs.mkdirSync(transcripts, { recursive: true });
  const partial = path.join(transcripts, "partial.jsonl");
  const malformed = path.join(transcripts, "malformed.jsonl");
  fs.writeFileSync(partial, [
    JSON.stringify({ role: "user", message: { content: [{ type: "text", text: "preserved prompt" }] } }),
    "{broken",
  ].join("\n") + "\n");
  fs.writeFileSync(malformed, "{broken\n");

  const rows = await extractAiHistory("cursor", cursorRoot);
  const byName = Object.fromEntries(rows._sourceCoverage.map((entry) => [path.basename(entry.sourceFile), entry]));
  assert.equal(byName["partial.jsonl"].status, "partial");
  assert.equal(byName["partial.jsonl"].rows, 1);
  assert.equal(byName["partial.jsonl"].malformedLines, 1);
  assert.equal(byName["malformed.jsonl"].status, "malformed");
  assert.equal(byName["malformed.jsonl"].errors, 1);
});
