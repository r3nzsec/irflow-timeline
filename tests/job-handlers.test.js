const test = require("node:test");
const assert = require("node:assert/strict");

const registerJobHandlers = require("../electron/ipc/job-handlers");

test("job IPC handlers expose list and cancel through the job manager", async () => {
  const calls = [];
  const handlers = {};
  const safeHandle = (channel, fn) => { handlers[channel] = fn; };
  const jobManager = {
    list: () => [{ id: "job-1", status: "running" }],
    metrics: () => ({ limits: { maxWorkers: 3 }, liveWorkers: 1 }),
    cancel: (jobId) => {
      calls.push(jobId);
      return { ok: true };
    },
  };

  registerJobHandlers(safeHandle, () => {}, { jobManager });

  assert.deepEqual(await handlers["jobs-list"](), [{ id: "job-1", status: "running" }]);
  assert.deepEqual(await handlers["jobs-metrics"](), { limits: { maxWorkers: 3 }, liveWorkers: 1 });
  assert.deepEqual(await handlers["jobs-cancel"](null, { jobId: "job-1" }), { ok: true });
  assert.deepEqual(calls, ["job-1"]);
});
