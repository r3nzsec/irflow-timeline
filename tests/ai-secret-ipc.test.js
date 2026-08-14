"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const Database = require("better-sqlite3");
const registerAnalysisHandlers = require("../electron/ipc/analysis-handlers");
const { fingerprint } = require("../electron/analyzers/ai-history/validators");
const {
  AiSecretResultWriter,
  resultPathForJob,
  removeStore,
} = require("../electron/analyzers/ai-history/result-store");

test("AI Secret scan IPC returns a cancellable job, pages redacted results, and reveals only a verified finding", async (t) => {
  const handlers = {};
  const sent = [];
  const tabId = "tab-ai-secret";
  const jobId = `ai-secret-ipc-${process.pid}-${Date.now()}`;
  const salt = "stable-test-salt";
  const secret = "ghp_Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2";
  const sourceDb = new Database(":memory:");
  sourceDb.exec("CREATE TABLE data (c0 TEXT)");
  sourceDb.prepare("INSERT INTO data (c0) VALUES (?)").run(secret);
  t.after(() => {
    try { sourceDb.close(); } catch {}
    try { removeStore(resultPathForJob(jobId)); } catch {}
  });

  let startOptions;
  registerAnalysisHandlers(
    (channel, handler) => { handlers[channel] = handler; },
    (channel, payload) => { sent.push([channel, payload]); },
    {
      db: { databases: new Map([[tabId, { db: sourceDb, colMap: { FullText: "c0" } }]]) },
      _tabMeta: new Map([[tabId, { sourceFormat: "ai-history-test" }]]),
      startAnalyzerJob(method, payload, options) {
        startOptions = { method, payload, options };
        const writer = new AiSecretResultWriter(jobId);
        writer.add({
          ruleId: "github-pat", category: "secret-scm", severity: "high", timestamp: "",
          fingerprint: fingerprint(secret, payload.options.salt), rowId: "1", recordId: "1",
          evidenceField: "FullText", startOffset: 0, endOffset: secret.length,
          redacted: "ghp_••••••••••••J3I2 (44 chars)", snippet: "redacted evidence",
        });
        const stored = writer.finish();
        return {
          jobId,
          promise: Promise.resolve({
            summary: { total: 1, uniqueSecrets: 1, flaggedRows: 1, bySeverity: { high: 1 } },
            storedFindings: 1,
            totalFindings: 1,
            resultsTruncated: false,
            resultStorePath: stored.resultStorePath,
          }),
        };
      },
    },
  );

  assert.deepEqual(handlers["start-ai-secret-scan"](null, { tabId, mode: "quick", salt }), { jobId });
  assert.equal(startOptions.method, "analyzeAiHistory");
  assert.equal(startOptions.options.retainResult, false);
  assert.equal(startOptions.options.maxConcurrent, 1);
  await new Promise((resolve) => setImmediate(resolve));

  const completion = sent.find(([channel]) => channel === "ai-secret-scan-complete")?.[1];
  assert.equal(completion.jobId, jobId);
  assert.equal(completion.result.findings.length, 1);
  assert.equal(JSON.stringify(completion.result).includes(secret), false);
  assert.equal(completion.result.resultStorePath, undefined);

  const page = handlers["get-ai-secret-results-page"](null, { scanId: jobId, offset: 0, limit: 1000 });
  assert.equal(page.findings.length, 1);
  assert.equal(page.findings[0].match, undefined);

  const revealed = handlers["reveal-ai-secret"](null, { scanId: jobId, findingId: page.findings[0].findingId });
  assert.deepEqual(revealed, { findingId: page.findings[0].findingId, value: secret });
  assert.deepEqual(handlers["release-ai-secret-scan"](null, { scanId: jobId }), { ok: true });
  assert.equal(fs.existsSync(resultPathForJob(jobId)), false);
  assert.deepEqual(handlers["reveal-ai-secret"](null, { scanId: jobId, findingId: "1" }), { error: "AI Secret scan results have expired." });
});

