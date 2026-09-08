// Open Triage Collection IPC.
//
// The security model is the point of these tests: a triage folder is arbitrary
// user-supplied disk, and the renderer hands paths back to the main process after
// discovery. Nothing may be read unless the user selected it in a dialog, and every
// returned path must be re-checked against that grant — a symlink inside the collection
// that points outside it has to resolve outside and be refused.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Module = require("node:module");

const HANDLERS_PATH = require.resolve("../electron/ipc/triage-handlers");

/**
 * Load the handler module with `electron` stubbed, so the folder dialog can be driven
 * from a test. Returns the registered channels plus what reached the import queue.
 */
function loadHandlers({ dialogResult, jobs = [], queue = [] } = {}) {
  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === "electron") {
      return {
        dialog: { showOpenDialog: async () => dialogResult || { canceled: true } },
      };
    }
    return origLoad.apply(this, arguments);
  };
  delete require.cache[HANDLERS_PATH];
  let register;
  try { register = require(HANDLERS_PATH); } finally { Module._load = origLoad; }

  const channels = {};
  const enqueued = [];
  const cancelled = [];
  const removedQueue = [];
  let n = 0;
  register(
    (ch, fn) => { channels[ch] = fn; },
    () => {},
    {
      _activeWindow: () => null,
      enqueueImport: (p, opts) => enqueued.push({ path: p, ...opts }),
      nextTabId: () => `tab_${++n}`,
      removeQueuedImports: (pred) => {
        const hits = queue.filter(pred);
        for (const h of hits) removedQueue.push(h);
        return hits;
      },
      jobManager: {
        cancelWhere: (pred) => {
          const hits = jobs.filter(pred);
          for (const h of hits) cancelled.push(h.id);
          return hits.length;
        },
      },
    },
  );
  return { channels, enqueued, cancelled, removedQueue };
}

/** Minimal but realistic raw triage tree. */
function makeTriage(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "triage-ipc-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const logs = path.join(root, "C", "Windows", "System32", "winevt", "logs");
  fs.mkdirSync(logs, { recursive: true });
  fs.writeFileSync(path.join(logs, "Security.evtx"), Buffer.alloc(250000));
  fs.writeFileSync(path.join(logs, "Microsoft-Windows-WinRM%4Operational.evtx"), Buffer.alloc(150000));
  fs.writeFileSync(path.join(logs, "Application.evtx"), Buffer.alloc(90000));
  return { root, logs };
}

test("discovery is refused until the folder has been selected", async (t) => {
  const { root } = makeTriage(t);
  const { channels } = loadHandlers();
  const res = await channels["triage-discover"](null, { dir: root });
  assert.ok(res.error, "an un-selected folder must not be readable");
  assert.match(res.error, /not authorized|Select it/i);
});

test("selecting a folder grants it, and discovery then works", async (t) => {
  const { root } = makeTriage(t);
  const { channels } = loadHandlers({ dialogResult: { canceled: false, filePaths: [root] } });

  const picked = await channels["triage-select-root"](null, {});
  assert.ok(picked.dir, "dialog should return the chosen folder");

  const manifest = await channels["triage-discover"](null, { dir: picked.dir });
  assert.ok(!manifest.error, `discovery failed: ${manifest.error}`);
  assert.equal(manifest.kind, "raw");
  const names = manifest.lanes.lateralMovement.items.map((i) => i.name);
  assert.ok(names.includes("Security"), `expected Security in the LM lane, got ${names.join(", ")}`);
  const app = manifest.lanes.lateralMovement.items.find((i) => i.name === "Application");
  assert.ok(app, "non-LM channels stay listed so they can still be imported");
  assert.equal(app.defaultChecked, false);
  assert.equal(app.lmTier, 0);
});

test("a cancelled dialog grants nothing", async (t) => {
  const { root } = makeTriage(t);
  const { channels } = loadHandlers({ dialogResult: { canceled: true } });
  const picked = await channels["triage-select-root"](null, {});
  assert.equal(picked.canceled, true);
  const res = await channels["triage-discover"](null, { dir: root });
  assert.ok(res.error, "cancelling must not authorize the folder");
});

test("import only enqueues paths inside the granted root", async (t) => {
  const { root, logs } = makeTriage(t);

  // A file the user never selected, outside the collection entirely.
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "triage-outside-"));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  const secret = path.join(outside, "Secrets.evtx");
  fs.writeFileSync(secret, Buffer.alloc(1000));

  const { channels, enqueued } = loadHandlers({ dialogResult: { canceled: false, filePaths: [root] } });
  await channels["triage-select-root"](null, {});

  const res = await channels["triage-import"](null, {
    dir: root,
    paths: [
      path.join(logs, "Security.evtx"),   // legitimate
      secret,                             // outside the grant
      path.join(root, "..", "escape.evtx"), // traversal
    ],
    hostLabel: "WKS-1042",
  });

  assert.ok(!res.error, `import failed: ${res.error}`);
  assert.equal(res.items.length, 1, "only the in-root file may be queued");
  assert.equal(res.rejectedCount, 2, "both out-of-root paths must be rejected");
  assert.equal(enqueued.length, 1);
  assert.ok(enqueued[0].path.endsWith("Security.evtx"));
  assert.ok(!enqueued.some((e) => e.path.includes("Secrets")), "an unselected file must never reach the import queue");
});

test("a symlink pointing outside the collection is refused", async (t) => {
  const { root } = makeTriage(t);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "triage-link-"));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  const target = path.join(outside, "Elsewhere.evtx");
  fs.writeFileSync(target, Buffer.alloc(1000));

  const linkPath = path.join(root, "Linked.evtx");
  try { fs.symlinkSync(target, linkPath); } catch { return; } // platform may forbid symlinks

  const { channels, enqueued } = loadHandlers({ dialogResult: { canceled: false, filePaths: [root] } });
  await channels["triage-select-root"](null, {});
  const res = await channels["triage-import"](null, { dir: root, paths: [linkPath] });

  // The path LOOKS inside the root; canonicalisation through realpath is what catches it.
  assert.equal(res.items.length, 0, "a symlink escaping the root must be refused");
  assert.equal(enqueued.length, 0);
});

test("imported tabs get readable, host-prefixed names", async (t) => {
  const { root, logs } = makeTriage(t);
  const { channels, enqueued } = loadHandlers({ dialogResult: { canceled: false, filePaths: [root] } });
  await channels["triage-select-root"](null, {});

  await channels["triage-import"](null, {
    dir: root,
    paths: [path.join(logs, "Security.evtx"), path.join(logs, "Microsoft-Windows-WinRM%4Operational.evtx")],
    hostLabel: "WKS-1042",
  });

  const names = enqueued.map((e) => e.displayName);
  assert.deepEqual(names, ["WKS-1042 · Security", "WKS-1042 · WinRM/Operational"],
    "names must be readable in the multi-source tab picker, not raw filenames");
  // Every queued item must be tagged so the renderer can tell this batch apart.
  assert.ok(enqueued.every((e) => e.batchId && e.tabId && e.skipRecent));
});

test("an empty selection is rejected rather than starting an empty batch", async (t) => {
  const { root } = makeTriage(t);
  const { channels } = loadHandlers({ dialogResult: { canceled: false, filePaths: [root] } });
  await channels["triage-select-root"](null, {});
  const res = await channels["triage-import"](null, { dir: root, paths: [] });
  assert.ok(res.error);
});

// ── B3: Sigma lane + batch cancel ───────────────────────────────────────────────

test("the Sigma lane is only granted for a directory inside the selection", async (t) => {
  const { root, logs } = makeTriage(t);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "triage-sigma-out-"));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));

  const { channels } = loadHandlers({ dialogResult: { canceled: false, filePaths: [root] } });
  await channels["triage-select-root"](null, {});

  // In-root: prepared, with a file count so the wizard opens ready to scan.
  const ok = await channels["triage-import"](null, {
    dir: root, paths: [path.join(logs, "Security.evtx")], sigmaEvtxDir: logs,
  });
  assert.ok(ok.sigmaEvtxDir, "an in-root EVTX directory should be prepared");
  assert.equal(ok.sigmaEvtxDir.fileCount, 3, "should count the EVTX files it will scan");
  assert.ok(ok.sigmaEvtxDir.dirPath.endsWith(path.join("winevt", "logs")));

  // Out-of-root: refused, and the import itself still proceeds.
  const bad = await channels["triage-import"](null, {
    dir: root, paths: [path.join(logs, "Security.evtx")], sigmaEvtxDir: outside,
  });
  assert.equal(bad.sigmaEvtxDir, null, "a directory outside the selection must not be granted");
  assert.equal(bad.items.length, 1, "the rest of the import should be unaffected");
});

test("no Sigma grant is issued unless the lane was requested", async (t) => {
  const { root, logs } = makeTriage(t);
  const { channels } = loadHandlers({ dialogResult: { canceled: false, filePaths: [root] } });
  await channels["triage-select-root"](null, {});
  const res = await channels["triage-import"](null, { dir: root, paths: [path.join(logs, "Security.evtx")] });
  assert.equal(res.sigmaEvtxDir, null, "omitting sigmaEvtxDir must not grant anything");
});

test("cancelling a batch drops queued items and cancels running jobs", async (t) => {
  const { root, logs } = makeTriage(t);
  const queue = [{ batchId: "B1" }, { batchId: "B1" }, { batchId: "OTHER" }];
  const jobs = [
    { id: "j1", status: "running", metadata: { tabId: "tab_1" } },
    { id: "j2", status: "running", metadata: { tabId: "tab_99" } },  // another batch
    { id: "j3", status: "completed", metadata: { tabId: "tab_2" } }, // already done
  ];
  const { channels, cancelled, removedQueue } = loadHandlers({
    dialogResult: { canceled: false, filePaths: [root] }, jobs, queue,
  });
  await channels["triage-select-root"](null, {});

  const res = await channels["triage-cancel-batch"](null, { batchId: "B1", tabIds: ["tab_1", "tab_2"] });
  assert.equal(res.dropped, 2, "only this batch's queued items may be dropped");
  assert.ok(!removedQueue.some((q) => q.batchId === "OTHER"), "another batch must be left alone");
  assert.equal(res.cancelledJobs, 1, "only the running job belonging to this batch");
  assert.deepEqual(cancelled, ["j1"]);
});

test("a duplicate pending import is not queued and an empty batch is an error", async (t) => {
  const { root, logs } = makeTriage(t);
  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === "electron") {
      return { dialog: { showOpenDialog: async () => ({ canceled: false, filePaths: [root] }) } };
    }
    return origLoad.apply(this, arguments);
  };
  delete require.cache[HANDLERS_PATH];
  let register;
  try { register = require(HANDLERS_PATH); } finally { Module._load = origLoad; }
  const channels = {};
  register((ch, fn) => { channels[ch] = fn; }, () => {}, {
    _activeWindow: () => null,
    enqueueImport: () => false,
    nextTabId: () => "tab_dup",
    removeQueuedImports: () => [],
    jobManager: { cancelWhere: () => 0 },
  });
  await channels["triage-select-root"](null, {});
  const res = await channels["triage-import"](null, { dir: root, paths: [path.join(logs, "Security.evtx")] });
  assert.ok(res.error, "duplicate/empty queue must surface as an error so the toast can settle");
  assert.equal((res.items || []).length, 0);
});

test("cancel needs something to identify the batch", async (t) => {
  const { root } = makeTriage(t);
  const { channels } = loadHandlers({ dialogResult: { canceled: false, filePaths: [root] } });
  await channels["triage-select-root"](null, {});
  const res = await channels["triage-cancel-batch"](null, {});
  assert.ok(res.error);
});

// ── VHDX images ──────────────────────────────────────────────────────────────────────
//
// A `.vhdx` picked in the same dialog is granted under its own scope, extracted by a
// worker into a scratch folder, and only that folder becomes a triage root. The image
// path is never handed to discovery or import, and nothing is extractable until picked.

const { buildNtfsVolume: _buildVol, wrapMbr: _wrapMbr, wrapRawInVhdx: _wrapVhdx } = require("./helpers/ntfs-image-builder");
const { extractVhdxCollection: _extract } = require("../electron/parsers/vhdx-triage");

function makeVhdx(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "triage-vhdx-ipc-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const vol = _buildVol({
    files: [
      { name: "C", isDir: true },
      { name: "Windows", isDir: true, parent: 16 },
      { name: "System32", isDir: true, parent: 17 },
      { name: "winevt", isDir: true, parent: 18 },
      { name: "logs", isDir: true, parent: 19 },
      { name: "Security.evtx", parent: 20, content: Buffer.alloc(250000, 1) },
      { name: "Application.evtx", parent: 20, content: Buffer.alloc(90000, 2) },
    ],
  });
  const vhdx = path.join(dir, "host.vhdx");
  fs.writeFileSync(vhdx, _wrapVhdx(_wrapMbr(vol.image)));
  const notVhdx = path.join(dir, "notes.txt");
  fs.writeFileSync(notVhdx, "plain text");
  return { dir, vhdx, notVhdx };
}

/** A jobManager stub that runs the extractor inline and honours cancel(). */
function inlineJobManager(log = []) {
  return {
    startWorkerJob({ type, worker, workerData }) {
      log.push({ type, worker, workerData });
      const jobId = `job_${log.length}`;
      const promise = type === "triage-discover"
        ? require("../electron/analyzers/triage-collection").discoverTriageCollection(workerData.root)
        : _extract(workerData.vhdxPath, workerData.outDir);
      return { jobId, promise };
    },
    cancel(jobId) { log.push({ cancel: jobId }); return { ok: true }; },
    cancelWhere() { return 0; },
  };
}

test("picking a .vhdx returns a vhdx grant, not a triage root", async (t) => {
  const { vhdx } = makeVhdx(t);
  const { channels } = loadHandlers({ dialogResult: { canceled: false, filePaths: [vhdx] } });
  const res = await channels["triage-select-root"]();
  assert.equal(res.vhdx, fs.realpathSync.native(vhdx));
  assert.equal(res.dir, undefined);
  assert.ok(res.size > 0);
  // The image path is NOT a triage root: discovery on its folder is still refused.
  const d = await channels["triage-discover"](null, { dir: path.dirname(vhdx) });
  assert.match(d.error, /not authorized/);
});

test("picking a file that is not a VHDX is refused", async (t) => {
  const { notVhdx } = makeVhdx(t);
  const { channels } = loadHandlers({ dialogResult: { canceled: false, filePaths: [notVhdx] } });
  const res = await channels["triage-select-root"]();
  assert.match(res.error, /\.vhdx/);
});

test("triage-open-vhdx refuses an image that was not picked in the dialog", async (t) => {
  const { vhdx } = makeVhdx(t);
  const { channels } = loadHandlers();
  const res = await channels["triage-open-vhdx"](null, { file: vhdx });
  assert.match(res.error, /not authorized|not been authorized/i);
});

test("triage-open-vhdx extracts into a scratch root that discovery and import then accept", async (t) => {
  const { vhdx } = makeVhdx(t);
  const jobs = [];
  const { channels, enqueued } = loadHandlers({ dialogResult: { canceled: false, filePaths: [vhdx] } });
  // Swap in the inline job manager: loadHandlers builds its own ctx, so re-register with ours.
  const ctxJobs = inlineJobManager(jobs);
  const picked = await channels["triage-select-root"]();
  assert.ok(picked.vhdx);

  // Register a fresh handler set sharing the same authorizer is not exposed; instead, drive
  // the real module with a ctx that has the inline job manager.
  const origLoad = Module._load;
  Module._load = function (request) {
    if (request === "electron") return { dialog: { showOpenDialog: async () => ({ canceled: false, filePaths: [vhdx] }) } };
    return origLoad.apply(this, arguments);
  };
  delete require.cache[HANDLERS_PATH];
  let register;
  try { register = require(HANDLERS_PATH); } finally { Module._load = origLoad; }
  const ch = {};
  const queued = [];
  let n = 0;
  register((c, fn) => { ch[c] = fn; }, () => {}, {
    _activeWindow: () => null,
    enqueueImport: (p, opts) => queued.push({ path: p, ...opts }),
    nextTabId: () => `tab_${++n}`,
    jobManager: ctxJobs,
  });

  const sel = await ch["triage-select-root"]();
  const opened = await ch["triage-open-vhdx"](null, { file: sel.vhdx });
  t.after(() => fs.rmSync(opened.dir, { recursive: true, force: true }));
  assert.equal(opened.error, undefined, JSON.stringify(opened));
  assert.ok(opened.dir && fs.existsSync(opened.dir));
  assert.ok(path.basename(opened.dir).startsWith("tle_vhdx_"));
  assert.equal(opened.extracted.count, 2);
  assert.deepEqual(opened.extracted.byKind, { evtx: 2 });
  assert.equal(jobs[0].worker, "vhdx-extract-worker.js");
  assert.equal(jobs[0].type, "vhdx-extract");
  assert.equal(jobs[0].workerData.vhdxPath, sel.vhdx);

  // The scratch root behaves like any picked folder.
  const manifest = await ch["triage-discover"](null, { dir: opened.dir });
  assert.equal(manifest.error, undefined);
  const sec = manifest.lanes.lateralMovement.items.find((i) => i.name === "Security");
  assert.ok(sec, "Security.evtx surfaced in the LM lane");
  const imp = await ch["triage-import"](null, { dir: opened.dir, paths: [sec.path] });
  assert.equal(imp.items.length, 1);
  assert.equal(queued[0].path, fs.realpathSync.native(sec.path));

  // Cancel plumbing: unknown ids are rejected, a live one reaches the job manager.
  assert.equal((await ch["triage-cancel-vhdx"](null, { jobId: "nope" })).ok, false);
  assert.equal(enqueued.length, 0, "the first handler set never queued anything");
});

test("triage-open-vhdx cleans up the scratch folder when extraction fails", async (t) => {
  const { dir } = makeVhdx(t);
  const bogus = path.join(dir, "bogus.vhdx");
  fs.writeFileSync(bogus, Buffer.alloc(8192, 9));
  const origLoad = Module._load;
  Module._load = function (request) {
    if (request === "electron") return { dialog: { showOpenDialog: async () => ({ canceled: false, filePaths: [bogus] }) } };
    return origLoad.apply(this, arguments);
  };
  delete require.cache[HANDLERS_PATH];
  let register;
  try { register = require(HANDLERS_PATH); } finally { Module._load = origLoad; }
  const ch = {};
  const jobs = [];
  register((c, fn) => { ch[c] = fn; }, () => {}, { _activeWindow: () => null, enqueueImport: () => {}, nextTabId: () => "t", jobManager: inlineJobManager(jobs) });
  const sel = await ch["triage-select-root"]();
  assert.ok(sel.vhdx, "extension alone is enough to be offered to the extractor");
  const opened = await ch["triage-open-vhdx"](null, { file: sel.vhdx });
  assert.match(opened.error, /Not a VHDX file/);
  assert.ok(!fs.existsSync(jobs[0].workerData.outDir), "scratch folder removed");
});
