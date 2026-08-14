"use strict";

const os = require("os");

const GIB = 1024 ** 3;
const MAX_CONFIGURED_WORKERS = 16;

function _positiveInt(value) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function deriveWorkerBudget({ totalMemoryBytes = os.totalmem(), env = process.env } = {}) {
  const memoryGiB = Math.max(1, Number(totalMemoryBytes) / GIB);
  const defaultMaxWorkers = memoryGiB < 16 ? 1 : memoryGiB < 32 ? 2 : memoryGiB < 64 ? 3 : 4;
  const configuredMax = _positiveInt(env.TLE_MAX_WORKERS);
  const maxWorkers = Math.min(configuredMax || defaultMaxWorkers, MAX_CONFIGURED_WORKERS);

  const defaultHeavy = memoryGiB < 32 ? 1 : 2;
  const configuredHeavy = _positiveInt(env.TLE_MAX_HEAVY_WORKERS);
  const maxHeavyWorkers = Math.min(configuredHeavy || defaultHeavy, maxWorkers);

  return {
    maxWorkers,
    maxHeavyWorkers,
    memoryGiB: Math.round(memoryGiB * 10) / 10,
    source: configuredMax || configuredHeavy ? "environment" : "memory",
  };
}

module.exports = { deriveWorkerBudget, GIB, MAX_CONFIGURED_WORKERS };
