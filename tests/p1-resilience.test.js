"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { shouldHideWindowOnClose, restoreOrCreateWindow } = require("../electron/utils/app-lifecycle");
const { createFatalRecovery } = require("../electron/utils/fatal-recovery");
const { deriveWorkerBudget, GIB } = require("../electron/utils/worker-budget");

test("macOS close hides the window unless the application is quitting", () => {
  assert.equal(shouldHideWindowOnClose({ platform: "darwin", isQuitting: false }), true);
  assert.equal(shouldHideWindowOnClose({ platform: "darwin", isQuitting: true }), false);
  assert.equal(shouldHideWindowOnClose({ platform: "win32", isQuitting: false }), false);
});

test("activation restores the existing window instead of creating a second renderer", () => {
  const calls = [];
  const window = {
    isDestroyed: () => false,
    isMinimized: () => true,
    restore: () => calls.push("restore"),
    show: () => calls.push("show"),
    focus: () => calls.push("focus"),
  };
  const result = restoreOrCreateWindow({ window, createWindow: () => calls.push("create") });
  assert.equal(result, window);
  assert.deepEqual(calls, ["restore", "show", "focus"]);
});

test("activation creates a window only when no live window exists", () => {
  const created = { id: "new" };
  assert.equal(restoreOrCreateWindow({ window: null, createWindow: () => created }), created);
  assert.equal(restoreOrCreateWindow({ window: { isDestroyed: () => true }, createWindow: () => created }), created);
});

test("worker budget is memory-aware and bounded by environment overrides", () => {
  assert.deepEqual(deriveWorkerBudget({ totalMemoryBytes: 8 * GIB, env: {} }), {
    maxWorkers: 1,
    maxHeavyWorkers: 1,
    memoryGiB: 8,
    source: "memory",
  });
  assert.deepEqual(deriveWorkerBudget({ totalMemoryBytes: 128 * GIB, env: {} }), {
    maxWorkers: 4,
    maxHeavyWorkers: 2,
    memoryGiB: 128,
    source: "memory",
  });
  assert.deepEqual(deriveWorkerBudget({
    totalMemoryBytes: 16 * GIB,
    env: { TLE_MAX_WORKERS: "6", TLE_MAX_HEAVY_WORKERS: "9" },
  }), {
    maxWorkers: 6,
    maxHeavyWorkers: 6,
    memoryGiB: 16,
    source: "environment",
  });
});

test("fatal recovery performs cleanup, relaunches once, and suppresses a crash loop", (t) => {
  const userDataPath = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-fatal-recovery-"));
  t.after(() => { try { fs.rmSync(userDataPath, { recursive: true, force: true }); } catch {} });
  const calls = [];
  const app = {
    getPath: () => userDataPath,
    getVersion: () => "1.0.10",
    relaunch: () => calls.push("relaunch"),
    exit: (code) => calls.push(`exit:${code}`),
  };
  const dependencies = {
    app,
    dialog: { showErrorBox: () => calls.push("dialog") },
    jobManager: { terminateAll: () => calls.push("terminate") },
    db: { closeAll: () => calls.push("close-db") },
    flushLogSync: () => calls.push("flush"),
    userDataPath,
    now: () => 1_000_000,
  };

  const first = createFatalRecovery(dependencies).handleFatal(new Error("boom"), "test");
  assert.deepEqual(first, { relaunching: true, duplicate: false });
  assert.equal(calls.filter((call) => call === "relaunch").length, 1);
  assert.ok(calls.includes("terminate"));
  assert.ok(calls.includes("close-db"));

  const second = createFatalRecovery(dependencies).handleFatal(new Error("boom again"), "test");
  assert.deepEqual(second, { relaunching: false, duplicate: false });
  assert.equal(calls.filter((call) => call === "relaunch").length, 1);

  const marker = JSON.parse(fs.readFileSync(path.join(userDataPath, "fatal-recovery.json"), "utf8"));
  assert.equal(marker.relaunching, false);
  assert.equal(marker.origin, "test");
});

test("stable startup clears the fatal recovery guard marker", () => {
  const userDataPath = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-fatal-stable-"));
  const markerPath = path.join(userDataPath, "fatal-recovery.json");
  fs.writeFileSync(markerPath, "{}", "utf8");
  const recovery = createFatalRecovery({
    app: { getPath: () => userDataPath },
    userDataPath,
    setTimeoutImpl: (fn) => {
      fn();
      return { unref() {} };
    },
  });
  recovery.markStableStartup();
  assert.equal(fs.existsSync(markerPath), false);
  fs.rmSync(userDataPath, { recursive: true, force: true });
});
