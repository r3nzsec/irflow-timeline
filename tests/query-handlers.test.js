const test = require("node:test");
const assert = require("node:assert/strict");

const registerQueryHandlers = require("../electron/ipc/query-handlers");

test("query handlers run worker-backed query jobs with bounded concurrency", async () => {
  const handlers = {};
  const startCalls = [];
  const db = {
    getTabWorkerDescriptor(tabId) {
      return { tabId, dbPath: "/tmp/test.sqlite", headers: ["Time"], indexedCols: [] };
    },
    getColumnStats() {
      throw new Error("fallback should not run when a worker descriptor is available");
    },
  };
  const jobManager = {
    startWorkerJob(options) {
      startCalls.push(options);
      return { promise: Promise.resolve({ result: { distinct: 3 }, descriptors: [] }) };
    },
  };

  registerQueryHandlers(
    (channel, handler) => { handlers[channel] = handler; },
    () => {},
    { db, jobManager },
  );

  const result = await handlers["get-column-stats"](null, {
    tabId: "tab-1",
    colName: "Time",
    options: { limit: 10 },
  });

  assert.deepEqual(result, { distinct: 3 });
  assert.equal(startCalls.length, 1);
  assert.equal(startCalls[0].type, "query");
  assert.equal(startCalls[0].worker, "query-worker.js");
  assert.equal(startCalls[0].concurrencyKey, "query");
  assert.equal(startCalls[0].maxConcurrent, 2);
  assert.equal(startCalls[0].retainResult, false);
  assert.deepEqual(startCalls[0].workerData, {
    method: "getColumnStats",
    payload: { tabId: "tab-1", colName: "Time", options: { limit: 10 } },
    tabs: [{ tabId: "tab-1", dbPath: "/tmp/test.sqlite", headers: ["Time"], indexedCols: [] }],
  });
});

test("bookmark snapshots stay on the main database path", async () => {
  const handlers = {};
  const db = {
    getBookmarkedIds(tabId) {
      assert.equal(tabId, "tab-1");
      return [4, 9];
    },
  };
  const jobManager = {
    startWorkerJob() {
      throw new Error("bookmark snapshots must not start a worker");
    },
  };

  registerQueryHandlers(
    (channel, handler) => { handlers[channel] = handler; },
    () => {},
    { db, jobManager },
  );

  assert.deepEqual(await handlers["get-bookmarked-ids"](null, { tabId: "tab-1" }), [4, 9]);
});
