#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { app, dialog } = require("electron");

const REPO = path.resolve(__dirname, "..");
const FIXTURES = path.join(REPO, "tests", "fixtures", "ai-history");
const EVIDENCE = path.join(REPO, "internal-docs", "audits", "2026-09-08-ai-apps", "evidence");
const OUT_ROOT = path.join(EVIDENCE, "phase-5-acceptance-output");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function rowEvidence(row) {
  const fields = [
    "Timestamp", "TimestampBasis", "Role", "RecordType", "Summary", "FullText",
    "InvokedTool", "ToolCommand", "ToolInput", "ToolDescription", "SessionId",
    "MessageId", "ParentId", "Workspace", "Tool", "Model", "SourceFile",
    "LineNumber", "SourceOffset", "User", "Host", "Description",
  ];
  return sha256(JSON.stringify(fields.map((field) => row?.[field] ?? "")));
}

function rowSet(rows) {
  return (rows || []).map(rowEvidence).sort();
}

function copyDir(source, destination) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.cpSync(source, destination, { recursive: true, force: true });
}

function writeLargeCodexFixture(root, targetBytes = 96 * 1024 * 1024) {
  const codex = path.join(root, ".codex");
  const rollout = path.join(codex, "sessions", "2026", "09", "08", "rollout-cancel.jsonl");
  fs.mkdirSync(path.dirname(rollout), { recursive: true });
  const fd = fs.openSync(rollout, "w");
  const base = JSON.stringify({
    timestamp: "2026-09-08T00:00:00.000Z",
    type: "response_item",
    payload: { type: "message", role: "user", content: [{ type: "input_text", text: "cancellation acceptance record" }] },
  });
  let written = 0;
  let index = 0;
  try {
    while (written < targetBytes) {
      const line = `${base.slice(0, -1)},"phase5Index":${index++}}\n`;
      written += fs.writeSync(fd, line);
    }
  } finally {
    fs.closeSync(fd);
  }
  return { codex, rollout, bytes: written };
}

function populateProfile(profileRoot) {
  copyDir(path.join(FIXTURES, "claude", ".claude"), path.join(profileRoot, ".claude"));
  copyDir(path.join(FIXTURES, "codex", ".codex"), path.join(profileRoot, ".codex"));
  copyDir(path.join(FIXTURES, "grok", ".grok"), path.join(profileRoot, ".grok"));
  copyDir(path.join(FIXTURES, "grok-bot", ".grokbot"), path.join(profileRoot, ".grokbot"));
  copyDir(path.join(FIXTURES, "grok-bot", "Library", "Application Support", "Grok Bot"), path.join(profileRoot, "Library", "Application Support", "Grok Bot"));
  copyDir(path.join(FIXTURES, "gemini", ".gemini"), path.join(profileRoot, ".gemini"));
  copyDir(path.join(FIXTURES, "cursor", ".cursor"), path.join(profileRoot, ".cursor"));
}

async function parseCsv(filePath) {
  const csv = require("csv-parser");
  return new Promise((resolve, reject) => {
    const rows = [];
    fs.createReadStream(filePath).pipe(csv())
      .on("data", (row) => rows.push(row))
      .on("error", reject)
      .on("end", () => resolve(rows));
  });
}

async function main() {
  fs.rmSync(OUT_ROOT, { recursive: true, force: true });
  fs.mkdirSync(OUT_ROOT, { recursive: true });
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-phase5-"));
  const fakeHome = path.join(scratch, "local-home");
  populateProfile(fakeHome);
  process.env.HOME = fakeHome;

  const TimelineDB = require(path.join(REPO, "electron", "db"));
  const { JobManager } = require(path.join(REPO, "electron", "jobs", "job-manager"));
  const registerAiHistoryHandlers = require(path.join(REPO, "electron", "ipc", "ai-history-handlers"));
  const registerExportHandlers = require(path.join(REPO, "electron", "ipc", "export-handlers"));
  const registerQueryHandlers = require(path.join(REPO, "electron", "ipc", "query-handlers"));
  const registerSessionHandlers = require(path.join(REPO, "electron", "ipc", "session-handlers"));
  const { AI_HISTORY_TOOLS, grokBotExtractTargets } = require(path.join(REPO, "electron", "parsers", "ai-history"));
  const { extractMergedAiHistoryRoots } = require(path.join(REPO, "electron", "parsers", "ai-history", "profile-scan"));
  const { deriveUser } = require(path.join(REPO, "electron", "parsers", "path-attribution"));
  const { authorizeAiArtifactPick, authorizeAiScanTarget } = require(path.join(REPO, "electron", "parsers", "ai-history", "path-auth"));
  const { writeSessionAtomic, readSessionWithBackup } = require(path.join(REPO, "electron", "utils", "session-persistence"));

  const handlers = {};
  const events = [];
  const tabMeta = new Map();
  const db = new TimelineDB();
  let tabCounter = 0;
  let dialogResult = { canceled: true, filePaths: [] };
  dialog.showOpenDialog = async () => dialogResult;
  const safeHandle = (channel, fn) => { handlers[channel] = fn; };
  const safeSend = (channel, payload) => { events.push({ channel, payload }); };
  const jobs = new JobManager({ safeSend, maxWorkers: 2, maxHeavyWorkers: 1 });
  const ctx = {
    db,
    _tabMeta: tabMeta,
    _activeWindow: () => null,
    jobManager: jobs,
    nextTabId: () => `phase5_${++tabCounter}`,
    _newTempDbPath: (tabId) => path.join(scratch, `${tabId}.db`),
    scheduleIndexBuild: null,
    safeSend,
  };
  registerAiHistoryHandlers(safeHandle, safeSend, ctx);
  registerExportHandlers(safeHandle, safeSend, ctx);
  registerQueryHandlers(safeHandle, safeSend, ctx);

  const openPlans = [];
  registerSessionHandlers(safeHandle, safeSend, {
    ...ctx,
    enqueueImport(filePath, options) { openPlans.push({ filePath, options }); return true; },
    _loadRecentFiles: () => [],
    _saveRecentFiles: () => {},
    _rebuildMenu: () => {},
    _pendingIndexTabs: [],
    updateController: { checkForUpdatesFromRenderer() {}, installUpdate() {} },
  });

  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    runtime: { electron: process.versions.electron, node: process.versions.node, arch: process.arch, platform: process.platform },
    fileOpen: null,
    localDiscovery: null,
    offlineDiscovery: {},
    tools: {},
    mergedCollection: null,
    partialVisibility: null,
    cancellation: null,
    roundTrip: null,
  };

  try {
    const codexRoot = path.join(FIXTURES, "codex", ".codex");
    dialogResult = { canceled: false, filePaths: [codexRoot] };
    authorizeAiArtifactPick(codexRoot);
    const opened = await handlers["open-file-dialog"]();
    assert.equal(opened.scopePending?.[0]?.tool, "codex");
    const imported = await handlers["import-files"](null, {
      filePaths: [codexRoot],
      items: [{ path: codexRoot, opts: { aiHistoryTool: "codex", aiHistoryIncludeSubagents: false } }],
    });
    assert.equal(imported.imported, 1);
    assert.equal(openPlans.length, 1);
    assert.equal(openPlans[0].options.aiHistoryTool, "codex");
    report.fileOpen = { passed: true, scopePrompt: true, tool: openPlans[0].options.aiHistoryTool, path: openPlans[0].filePath };

    const localDiscovery = await handlers["discover-ai-history-profile"](null, { scanMode: "local" });
    const requestedTools = new Set(["claude-code", "codex", "grok-build", "grok-bot", "gemini-cli", "cursor"]);
    const localTools = new Set(localDiscovery.roots.map((root) => root.tool));
    for (const tool of requestedTools) assert.ok(localTools.has(tool), `local discovery missing ${tool}`);
    report.localDiscovery = { passed: true, rootCount: localDiscovery.roots.length, tools: [...localTools].sort() };

    const layouts = {
      macos: path.join(scratch, "offline-macos", "Users", "alice"),
      windows: path.join(scratch, "offline-windows", "Users", "bob"),
      linux: path.join(scratch, "offline-linux", "home", "carol"),
    };
    for (const [platform, profile] of Object.entries(layouts)) {
      populateProfile(profile);
      const collection = platform === "linux" ? path.join(scratch, "offline-linux") : path.dirname(path.dirname(profile));
      authorizeAiScanTarget(collection);
      const discovered = await handlers["discover-ai-history-profile"](null, { scanMode: "folder", scanRoot: collection });
      const tools = new Set(discovered.roots.map((root) => root.tool));
      for (const tool of requestedTools) assert.ok(tools.has(tool), `${platform} discovery missing ${tool}`);
      report.offlineDiscovery[platform] = { passed: true, collection, rootCount: discovered.roots.length, tools: [...tools].sort() };
    }

    const cases = [
      ["claude-code", path.join(FIXTURES, "claude", ".claude")],
      ["codex", path.join(FIXTURES, "codex", ".codex")],
      ["grok-build", path.join(FIXTURES, "grok", ".grok")],
      ["grok-bot", path.join(FIXTURES, "grok-bot", ".grokbot")],
      ["gemini-cli", path.join(FIXTURES, "gemini", ".gemini")],
      ["cursor", path.join(FIXTURES, "cursor", ".cursor")],
    ];
    const toolResults = new Map();
    for (const [tool, target] of cases) {
      authorizeAiArtifactPick(target);
      const roots = (tool === "grok-bot" ? grokBotExtractTargets(target) : [target]).map((rootPath) => ({
        tool,
        path: rootPath,
        label: AI_HISTORY_TOOLS[tool].label,
        endpointUser: deriveUser(rootPath) || "",
        endpointHost: "",
      }));
      const direct = await extractMergedAiHistoryRoots(roots, { user: deriveUser(target) || "", host: "" }, { includeSubagents: false, skipFinalize: true });
      const ipc = await handlers["decode-ai-history"](null, { path: target, tool, includeSubagents: false });
      assert.ok(ipc.openedTab && ipc.tabId, `${tool}: worker did not open a tab: ${ipc.error || "unknown"}`);
      const queried = await handlers["query-rows"](null, { tabId: ipc.tabId, options: { offset: 0, limit: ipc.count, sortCol: null, sortDir: "asc" } });
      assert.equal(queried.totalFiltered, ipc.count, `${tool}: grid count`);
      assert.deepEqual(queried.rows.map((row) => String(row.RecordId)), Array.from({ length: ipc.count }, (_, index) => String(index + 1)), `${tool}: RecordId sequence`);
      assert.deepEqual(rowSet(queried.rows), rowSet(direct.rows), `${tool}: direct/parser SQLite evidence parity`);
      assert.ok(ipc.importMeta?.sourceCoverage?.length > 0, `${tool}: missing coverage metadata`);
      const completion = events.findLast((event) => event.channel === "import-complete" && event.payload.tabId === ipc.tabId);
      assert.ok(completion?.payload.aiHistoryImportMeta?.sourceCoverage?.length, `${tool}: import-complete missing coverage metadata`);
      assert.equal(completion.payload.aiHistoryRestore.tool, tool);
      report.tools[tool] = {
        passed: true,
        rows: ipc.count,
        evidenceSetSha256: sha256(JSON.stringify(rowSet(queried.rows))),
        sourceCoverage: ipc.importMeta.sourceCoverage.reduce((acc, entry) => { acc[entry.status] = (acc[entry.status] || 0) + 1; return acc; }, {}),
      };
      toolResults.set(tool, { ipc, rows: queried.rows, target });
    }

    const macCollection = path.join(scratch, "offline-macos");
    authorizeAiScanTarget(macCollection);
    const discovered = await handlers["discover-ai-history-profile"](null, { scanMode: "folder", scanRoot: macCollection });
    const merged = await handlers["extract-ai-history-profile"](null, {
      roots: discovered.roots,
      includeSubagents: false,
      scanRoot: macCollection,
      scanMode: "folder",
    });
    assert.ok(merged.openedTab && merged.count > 0, merged.error);
    const mergedGrid = await handlers["query-rows"](null, { tabId: merged.tabId, options: { offset: 0, limit: merged.count } });
    assert.equal(mergedGrid.totalFiltered, merged.count);
    assert.ok(merged.importMeta?.discoveryInventory?.eligibleSources > 0);
    report.mergedCollection = {
      passed: true,
      rows: merged.count,
      rootCount: discovered.roots.length,
      eligibleSources: merged.importMeta.discoveryInventory.eligibleSources,
      remainingSources: merged.importMeta.discoveryInventory.remainingSourceCount,
      partial: merged.partial,
    };

    const damagedCursor = path.join(scratch, "damaged-cursor", ".cursor");
    const damagedTranscript = path.join(damagedCursor, "projects", "demo", "agent-transcripts", "session", "session.jsonl");
    fs.mkdirSync(path.dirname(damagedTranscript), { recursive: true });
    fs.writeFileSync(damagedTranscript, `${JSON.stringify({ role: "user", message: { content: [{ type: "text", text: "retained neighbor" }] } })}\n{malformed\n`);
    authorizeAiArtifactPick(damagedCursor);
    const damaged = await handlers["decode-ai-history"](null, { path: damagedCursor, tool: "cursor", includeSubagents: false });
    assert.equal(damaged.partial, true);
    const damagedDir = path.join(OUT_ROOT, "partial-cursor-package");
    fs.mkdirSync(damagedDir, { recursive: true });
    dialogResult = { canceled: false, filePaths: [damagedDir] };
    const damagedExport = await handlers["export-ai-history-package"](null, {
      tabId: damaged.tabId,
      options: { filtersApplied: false },
      tabName: "Partial Cursor AI History",
      sourceFormat: damaged.sourceFormat,
    });
    const damagedManifest = JSON.parse(fs.readFileSync(damagedExport.manifestPath, "utf8"));
    assert.equal(damagedManifest.extraction.complete, false);
    assert.equal(damagedManifest.extraction.statusCounts.partial, 1);
    assert.ok(damagedManifest.sources.some((source) => source.coverage?.status === "partial"));
    report.partialVisibility = {
      passed: true,
      handlerPartial: damaged.partial,
      manifestComplete: damagedManifest.extraction.complete,
      statusCounts: damagedManifest.extraction.statusCounts,
    };

    const grokResult = toolResults.get("grok-bot");
    const packageDir = path.join(OUT_ROOT, "grok-bot-package");
    fs.mkdirSync(packageDir, { recursive: true });
    dialogResult = { canceled: false, filePaths: [packageDir] };
    const exported = await handlers["export-ai-history-package"](null, {
      tabId: grokResult.ipc.tabId,
      options: { filtersApplied: false },
      tabName: "Grok Bot AI History",
      sourceFormat: grokResult.ipc.sourceFormat,
    });
    assert.equal(exported.rowCount, grokResult.rows.length);
    const csvRows = await parseCsv(exported.csvPath);
    assert.equal(csvRows.length, grokResult.rows.length);
    assert.deepEqual(rowSet(csvRows), rowSet(grokResult.rows));
    const manifest = JSON.parse(fs.readFileSync(exported.manifestPath, "utf8"));
    assert.equal(manifest.formatVersion, 2);
    assert.equal(manifest.rowCount.exported, grokResult.rows.length);
    assert.ok(manifest.extraction?.sourceCoverage?.length > 0);

    const sessionPath = path.join(OUT_ROOT, "grok-bot-roundtrip.tle");
    const savedSession = {
      version: 1,
      savedAt: new Date().toISOString(),
      activeTabIndex: 0,
      tabs: [{
        filePath: "",
        name: "Grok Bot AI History",
        bookmarkedRowIds: [],
        tags: {},
        aiHistoryRestore: grokResult.ipc.restoreSpec,
        aiHistoryImportMeta: grokResult.ipc.importMeta,
      }],
    };
    await writeSessionAtomic(sessionPath, savedSession, { pretty: true });
    const loaded = await readSessionWithBackup(sessionPath);
    registerSessionHandlers._authorizeSessionAiHistoryRestores(loaded.session);
    const restore = loaded.session.tabs[0].aiHistoryRestore;
    const reopened = await handlers["decode-ai-history"](null, {
      path: restore.path,
      tool: restore.tool,
      includeSubagents: !!restore.includeSubagents,
      sessionRestore: loaded.session.tabs[0],
    });
    const reopenedGrid = await handlers["query-rows"](null, { tabId: reopened.tabId, options: { offset: 0, limit: reopened.count } });
    assert.deepEqual(rowSet(reopenedGrid.rows), rowSet(grokResult.rows));
    const reopenComplete = events.findLast((event) => event.channel === "import-complete" && event.payload.tabId === reopened.tabId);
    assert.equal(reopenComplete.payload.sessionRestore.name, "Grok Bot AI History");
    report.roundTrip = {
      passed: true,
      rows: reopened.count,
      csvRows: csvRows.length,
      manifestVersion: manifest.formatVersion,
      manifestComplete: manifest.extraction.complete,
      sessionSha256: sha256(fs.readFileSync(sessionPath)),
      csvSha256: sha256(fs.readFileSync(exported.csvPath)),
      manifestSha256: sha256(fs.readFileSync(exported.manifestPath)),
      evidenceSetSha256: sha256(JSON.stringify(rowSet(reopenedGrid.rows))),
    };

    const cancelFixture = writeLargeCodexFixture(scratch);
    authorizeAiArtifactPick(cancelFixture.codex);
    const cancelRun = handlers["decode-ai-history"](null, { path: cancelFixture.codex, tool: "codex", includeSubagents: false });
    await new Promise((resolve) => setTimeout(resolve, 10));
    const cancelStart = process.hrtime.bigint();
    await handlers["cancel-ai-history-extract"]();
    const canceled = await cancelRun;
    const cancelMs = Number(process.hrtime.bigint() - cancelStart) / 1e6;
    assert.equal(canceled.canceled, true, canceled.error);
    const retry = await handlers["decode-ai-history"](null, { path: codexRoot, tool: "codex", includeSubagents: false });
    assert.ok(retry.openedTab && retry.count > 0, retry.error);
    report.cancellation = { passed: true, sourceBytes: cancelFixture.bytes, acknowledgementMs: cancelMs, retryRows: retry.count };

    const reportPath = path.join(EVIDENCE, "phase-5-acceptance-report.json");
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
    process.stdout.write(`${JSON.stringify({ passed: true, reportPath, report }, null, 2)}\n`);
  } finally {
    jobs.terminateAll();
    db.closeAll();
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

app.whenReady().then(main).then(() => app.exit(0)).catch((error) => {
  process.stderr.write(`${error?.stack || error}\n`);
  app.exit(1);
});
