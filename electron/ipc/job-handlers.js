module.exports = function registerJobHandlers(safeHandle, safeSend, { jobManager }) {
  safeHandle("jobs-list", () => {
    return jobManager ? jobManager.list() : [];
  });

  safeHandle("jobs-metrics", () => {
    return jobManager?.metrics?.() || {
      limits: { maxWorkers: 0, maxHeavyWorkers: 0, source: "unavailable" },
      liveWorkers: 0,
      liveHeavyWorkers: 0,
      queuedWorkers: 0,
      queuedHeavyWorkers: 0,
    };
  });

  safeHandle("jobs-cancel", (event, { jobId }) => {
    if (!jobManager) return { ok: false, error: "Job manager unavailable" };
    return jobManager.cancel(jobId);
  });
};
