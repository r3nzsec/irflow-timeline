"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

test("closing AI Secret Hunt cancels its running job and releases its result store", async () => {
  const { cleanupAiSecretLifecycle } = await import("../src/utils/ai-secret-lifecycle.js");
  const calls = [];
  const result = await cleanupAiSecretLifecycle({
    cancelJob: async (jobId) => { calls.push(["cancel", jobId]); return { ok: true }; },
    releaseAiSecretScan: async (scanId) => { calls.push(["release", scanId]); return { ok: true }; },
  }, { jobId: "job-1", scanId: "scan-1" });
  assert.deepEqual(calls, [["cancel", "job-1"], ["release", "scan-1"]]);
  assert.equal(result.every((entry) => entry.status === "fulfilled"), true);
});

