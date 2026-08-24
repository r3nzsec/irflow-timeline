/**
 * ipc/sigma-handlers.js — IPC handlers for Sigma Rule Engine
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { app, dialog } = require("electron");
const { PathAuthorizer } = require("../utils/path-authorizer");
const { openDialogOptions } = require("../utils/open-dialog");
const registerSigmaHistoryHandlers = require("./sigma/history-handlers");
const registerSigmaResultActionHandlers = require("./sigma/result-action-handlers");
const registerSigmaRuleSettingsHandlers = require("./sigma/rule-settings-handlers");

module.exports = function registerSigmaHandlers(safeHandle, safeSend, ctx) {
  const { db, nextTabId, _activeWindow, scheduleIndexBuild, jobManager } = ctx;
  const { scanSigmaRules } = require("../analyzers/sigma");
  const { SigmaResultStore, createTempResultPath } = require("../analyzers/sigma/result-store");
  const scanHistory = require("../analyzers/sigma/scan-history");
  const detectionSettings = require("../analyzers/sigma/detection-settings");
  const ruleSuppression = require("../analyzers/sigma/rule-suppression");
  const { scanKapeOutputs, summarizeKapeSelection } = require("../analyzers/sigma/kape-output-scanner");
  const { downloadFromGitHub, getCacheStatus, getAllRules, importCustomRule, loadLocalRules, getCustomDir, getCacheDir, getAvailableRepos } = require("../analyzers/sigma/rule-cache");
  const { getHayabusaRulesDir, snapshotRuleDirectory } = require("../analyzers/sigma/rule-diff");
  const { validateEvtxScanRequest } = require("../analyzers/sigma/scan-preflight");
  const { scanEvtxDirectory, findEvtxFiles, getHayabusaStatus, downloadHayabusa, updateHayabusaRules, getHayabusaRulesUpdateMeta, updateHayabusa, runLogonSummary, runComputerMetrics, runEidMetrics, runLogMetrics, runSearch, runPivotKeywords, runExtractBase64, runLevelTuning, getLevelTuningPath, getRulesConfigDir, getAvailableProfiles, getGeoIpStatus, downloadGeoIp, getGeoIpDir, cancelScan } = require("../analyzers/sigma/evtx-scanner");
  // Shared with the other IPC modules (see main.js) so a path validated in one scope
  // can be granted in another; scope names keep them isolated otherwise.
  const pathAuthorizer = ctx.pathAuthorizer || new PathAuthorizer();

  // ── Job-based scan state ──────────────────────────────────────────
  // Each scan (tab or directory) gets a unique jobId. Result rows live
  // in _scanJobs server-side — the renderer only ever sees a 2K-row preview
  // and uses jobId for "Open as Tab" and CSV/JSON export. Avoids shipping
  // 100K+ rows over IPC (which can stall structured clone for tens of MB).
  const MAX_JOBS = 5;
  const JOB_TTL_MS = 30 * 60 * 1000; // 30 minutes
  const _scanJobs = new Map(); // jobId → { rows, htmlReport, createdAt, dirPath }
  const _cancelledJsScans = new Set();
  let _jobCounter = 0;

  function _nextJobId() { return `scan-${++_jobCounter}-${Date.now()}`; }

  function _historyIdFromJobId(jobId) {
    if (typeof jobId !== "string") return null;
    if (jobId.startsWith("history:")) return jobId.slice("history:".length);
    return null;
  }

  function _historyJob(record) {
    if (!record?.resultDbPath) return null;
    return {
      rows: null,
      resultDbPath: record.resultDbPath,
      resultHeaders: null,
      rowCount: record.eventRowCount || record.totalMatches || 0,
      htmlReport: null,
      htmlReportPath: record.htmlReportPath || null,
      historyId: record.id,
      persistent: true,
      createdAt: Date.parse(record.createdAt || "") || 0,
      dirPath: record.scanType === "evtx-dir" ? record.targetPath : null,
      sourceTabId: record.sourceTabId || null,
      engine: record.engine || null,
    };
  }

  function _getJobHtmlReport(job) {
    if (job?.htmlReport) return job.htmlReport;
    if (job?.historyId) return scanHistory.readHtmlReport(job.historyId);
    return null;
  }

  function _resolveJob(jobId) {
    // If jobId provided, use it; otherwise fall back to most recent job (backward compat)
    if (jobId && _scanJobs.has(jobId)) return _scanJobs.get(jobId);
    const historyId = _historyIdFromJobId(jobId);
    if (historyId) return _historyJob(scanHistory.getScanHistory(historyId));
    if (!jobId && _scanJobs.size > 0) {
      let latest = null;
      for (const job of _scanJobs.values()) {
        if (!latest || job.createdAt > latest.createdAt) latest = job;
      }
      return latest;
    }
    return null;
  }

  function _ruleCacheSnapshot() {
    const status = getCacheStatus();
    return {
      ruleLastUpdate: status?.lastUpdate || null,
      cachedRuleCount: status?.cachedRuleCount || 0,
      customRuleCount: status?.customRuleCount || 0,
      ruleSnapshotHash: status?.ruleSnapshotHash || null,
      ruleRepoSnapshots: status?.repoSnapshots || [],
      ruleCompatibilityReport: status?.compatibilityReport || null,
      ruleUpdateLog: status?.updateLog || [],
    };
  }

  function _triageAggregatesForStore(dbPath) {
    if (!dbPath || !fs.existsSync(dbPath)) return null;
    const store = SigmaResultStore.open(dbPath);
    try {
      return store.getTriageAggregates({ limit: 20 });
    } finally {
      store.close();
    }
  }

  function _triageAggregatesForJob(job) {
    return _triageAggregatesForStore(job?.resultDbPath);
  }

  function _hayabusaRuleSnapshot() {
    const status = getHayabusaStatus();
    const rulesDir = status?.path ? getHayabusaRulesDir(status.path) : null;
    const snapshot = snapshotRuleDirectory(rulesDir);
    const updateMeta = getHayabusaRulesUpdateMeta(status?.path) || null;
    return {
      hayabusaRuleCount: snapshot.count || 0,
      hayabusaRulesDir: snapshot.rulesDir || null,
      hayabusaRulesLastUpdate: snapshot.latestRuleMtime || snapshot.capturedAt || null,
      hayabusaRulesSnapshotHash: snapshot.snapshotHash || null,
      hayabusaRuleUpdateLog: updateMeta?.lines || [],
      hayabusaRuleUpdateMeta: updateMeta,
    };
  }

  function _hashFile(filePath) {
    try {
      return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
    } catch {
      return null;
    }
  }

  function _snapshotConfigFiles(paths = []) {
    const files = [];
    const seen = new Set();
    const addFile = (filePath, rootPath = null) => {
      let real;
      try { real = fs.realpathSync.native(filePath); } catch { return; }
      if (seen.has(real)) return;
      seen.add(real);
      let stat;
      try { stat = fs.statSync(real); } catch { return; }
      if (!stat.isFile()) return;
      files.push({
        path: real,
        relativePath: rootPath ? path.relative(rootPath, real).split(path.sep).join("/") : path.basename(real),
        size: stat.size,
        mtime: stat.mtimeMs ? new Date(stat.mtimeMs).toISOString() : null,
        sha256: _hashFile(real),
      });
    };
    const walk = (targetPath, rootPath = targetPath) => {
      let stat;
      try { stat = fs.statSync(targetPath); } catch { return; }
      if (stat.isFile()) {
        addFile(targetPath, path.dirname(targetPath));
        return;
      }
      if (!stat.isDirectory()) return;
      let entries = [];
      try { entries = fs.readdirSync(targetPath, { withFileTypes: true }); } catch { return; }
      for (const entry of entries) {
        if (entry.name.startsWith(".")) continue;
        const full = path.join(targetPath, entry.name);
        if (entry.isDirectory()) walk(full, rootPath);
        else if (entry.isFile()) addFile(full, rootPath);
      }
    };
    for (const targetPath of paths.filter(Boolean)) walk(targetPath);
    files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
    return files;
  }

  function _hayabusaConfigSnapshot(options = {}) {
    const paths = [];
    if (options.rulesConfig) paths.push(options.rulesConfig);
    try { paths.push(getRulesConfigDir()); } catch {}
    return _snapshotConfigFiles(paths);
  }

  function _jsSigmaCommandLine(scanType, opts = {}) {
    const parts = [
      "irflow-js-sigma",
      "scan",
      "--target", scanType,
      "--levels", (opts.levels || []).join(",") || "none",
      "--statuses", (opts.statuses || []).join(",") || "none",
    ];
    if (opts.categories?.length) parts.push("--categories", opts.categories.join(","));
    if (opts.presetName) parts.push("--preset", opts.presetName);
    return parts.map((item) => /[\s"]/g.test(String(item)) ? `"${String(item).replace(/"/g, '\\"')}"` : String(item)).join(" ");
  }

  function _authorizeAppManagedPaths() {
    pathAuthorizer.authorizeIfExists("compat-rules", getCacheDir(), {
      recursive: true,
      appManaged: true,
      label: "JS Sigma compatibility cache",
    });
    pathAuthorizer.authorizeIfExists("compat-rules", getCustomDir(), {
      recursive: true,
      appManaged: true,
      label: "JS Sigma custom rules",
    });

    const hayabusa = getHayabusaStatus();
    if (hayabusa?.path) {
      const hayabusaDir = path.dirname(hayabusa.path);
      pathAuthorizer.authorizeIfExists("hayabusa-rules", path.join(hayabusaDir, "rules"), {
        recursive: true,
        appManaged: true,
        label: "Hayabusa managed rules",
      });
      const configDir = getRulesConfigDir();
      pathAuthorizer.authorizeIfExists("hayabusa-rules-config", configDir, {
        recursive: true,
        appManaged: true,
        label: "Hayabusa managed rule config",
      });
      pathAuthorizer.authorizeIfExists("geoip", path.join(hayabusaDir, "geoip"), {
        recursive: true,
        appManaged: true,
        label: "Hayabusa managed GeoIP",
      });
    }

    pathAuthorizer.authorizeIfExists("geoip", getGeoIpDir(), {
      recursive: true,
      appManaged: true,
      label: "IRFlow managed GeoIP",
    });
  }

  function _authorizePersistedDetectionSettingsPaths(settings = detectionSettings.loadDetectionSettings()) {
    const authorized = [];
    const missing = [];
    for (const entry of detectionSettings.getDetectionSettingsPathEntries(settings)) {
      let grantedAny = false;
      for (const scope of entry.scopes) {
        const grant = pathAuthorizer.authorizeIfExists(scope, entry.path, {
          recursive: entry.recursive,
          label: entry.label,
          persisted: true,
        });
        if (grant) {
          grantedAny = true;
          authorized.push({ key: entry.key, scope, path: grant.path });
        }
      }
      if (!grantedAny) missing.push({ key: entry.key, path: entry.path });
    }
    return { authorized, missing };
  }

  function _assertDetectionSettingsPathsAuthorized(settings = {}) {
    _authorizeAppManagedPaths();
    _authorizePersistedDetectionSettingsPaths();
    const clean = detectionSettings.normalizeDetectionSettings(settings);
    for (const entry of detectionSettings.getDetectionSettingsPathEntries(clean)) {
      pathAuthorizer.assertAuthorized(entry.scopes, entry.path);
    }
    return clean;
  }

  function _assertScanPath(dirPath) {
    return pathAuthorizer.assertAuthorized("scan-target", dirPath);
  }

  function _assertScanOptionsPaths(options = {}) {
    _authorizeAppManagedPaths();
    _authorizePersistedDetectionSettingsPaths();
    if (options.hayabusaPath) {
      throw Object.assign(
        new Error("Custom Hayabusa binary paths are not accepted from the renderer."),
        { code: "PATH_NOT_AUTHORIZED" },
      );
    }
    if (options.rulesPath) pathAuthorizer.assertAuthorized("hayabusa-rules", options.rulesPath);
    if (options.rulesConfig) pathAuthorizer.assertAuthorized(["hayabusa-rules-config", "hayabusa-rules"], options.rulesConfig);
    if (options.geoIpDir) pathAuthorizer.assertAuthorized("geoip", options.geoIpDir);
  }

  function _withHayabusaPreflightState(options = {}) {
    const hayabusaStatus = getHayabusaStatus();
    return {
      ...options,
      hayabusaStatus,
      hayabusaRuleState: hayabusaStatus?.installed ? _hayabusaRuleSnapshot() : null,
    };
  }

  function _syncRuleSuppressionsToHayabusa(entries = ruleSuppression.loadRuleSuppressions()) {
    let configDir = null;
    try { configDir = getRulesConfigDir(); } catch {}
    return ruleSuppression.syncHayabusaNoisyRules(entries, { configDir });
  }

  function _withSuppressedRuleIds(options = {}) {
    const active = ruleSuppression.activeSuppressedRuleIds(undefined, { includeCase: true });
    const merged = new Set([
      ...(Array.isArray(options.disabledRuleIds) ? options.disabledRuleIds : []),
      ...active,
    ].map((id) => String(id || "").trim().toLowerCase()).filter(Boolean));
    return { ...options, disabledRuleIds: [...merged] };
  }

  function _authorizeSelectedScanPath(dirPath) {
    return pathAuthorizer.authorize("scan-target", dirPath, {
      recursive: true,
      label: "Selected EVTX scan directory",
    });
  }

  function _authorizeSelectedKapePath(targetPath) {
    let stat = null;
    try { stat = fs.statSync(targetPath); } catch {}
    return pathAuthorizer.authorize("kape-target", targetPath, {
      recursive: !!stat?.isDirectory?.(),
      label: stat?.isDirectory?.() ? "Selected EvtxECmd search folder" : "Selected EvtxECmd output file",
    });
  }

  function _assertKapePaths(paths = []) {
    const clean = (Array.isArray(paths) ? paths : [paths]).filter(Boolean);
    if (clean.length === 0) throw new Error("Select one or more EvtxECmd output files before scanning.");
    return clean.map((targetPath) => pathAuthorizer.assertAuthorized("kape-target", targetPath));
  }

  _authorizeAppManagedPaths();
  _authorizePersistedDetectionSettingsPaths();

  function _cleanupJobs() {
    const now = Date.now();
    for (const [id, job] of _scanJobs) {
      if (now - job.createdAt > JOB_TTL_MS) {
        if (job.resultDbPath) SigmaResultStore.destroy(job.resultDbPath);
        _scanJobs.delete(id);
      }
    }
    while (_scanJobs.size > MAX_JOBS) {
      let oldestId = null, oldestTime = Infinity;
      for (const [id, job] of _scanJobs) {
        if (job.createdAt < oldestTime) { oldestId = id; oldestTime = job.createdAt; }
      }
      if (oldestId) {
        const job = _scanJobs.get(oldestId);
        if (job?.resultDbPath) SigmaResultStore.destroy(job.resultDbPath);
        _scanJobs.delete(oldestId);
      }
    }
  }

  // Helper used by both tab and dir scan import paths to materialize a job's rows
  // into a new SQLite tab. Async so we can yield between insert batches and emit
  // progress to the renderer (otherwise the renderer can't paint anything between
  // sync batches and the modal looks frozen).
  function _normalizeResultTabPostAction(postAction = {}) {
    const action = postAction && typeof postAction === "object" ? postAction : {};
    const tag = String(action.tag || "").trim();
    return {
      tag: tag || null,
      tagColor: action.tagColor || null,
      bookmark: !!action.bookmark,
    };
  }

  function _allImportedRowIds(rowCount) {
    const total = Math.max(0, Number(rowCount) || 0);
    return Array.from({ length: total }, (_, idx) => idx + 1);
  }

  function _buildImportedRowTags(rowIds, tag) {
    if (!tag || !Array.isArray(rowIds) || rowIds.length === 0) return null;
    const rowTags = {};
    for (const rowId of rowIds) rowTags[rowId] = [tag];
    return rowTags;
  }

  async function _importJobAsTab(rows, name, options = {}) {
    if (!rows || rows.length === 0) return { error: "No rows to import" };
    const postAction = _normalizeResultTabPostAction(options.postAction);
    const sourceFormat = options.sourceFormat || null;
    const importNotice = options.importNotice || null;
    const PRIORITY = ["Timestamp", "Computer", "Channel", "EventID", "Level", "RuleTitle", "SigmaRuleTitle", "SigmaRuleId", "SourceTabId", "SourceRowId", "User", "MITRE",
      "Image", "CommandLine", "Cmdline", "Proc", "ParentImage", "ParentCmdline",
      "TargetFilename", "TargetObject", "ServiceName", "Hashes",
      "LogonType", "IpAddress", "WorkstationName", "DestinationIp", "DestinationPort",
      "Details", "ExtraFieldInfo", "_SourceFile", "RecordID", "RuleFile", "Tags",
      "ScriptBlockText", "ShareName", "MapDescription", "RemoteHost",
      "Description", "Category", "Author"];
    const allKeys = new Set();
    const sampleSize = Math.min(rows.length, 1000);
    for (let i = 0; i < sampleSize; i++) {
      for (const k of Object.keys(rows[i])) { if (!k.startsWith("_") || k === "_SourceFile") allKeys.add(k); }
    }
    const headers = [
      ...PRIORITY.filter(k => allKeys.has(k)),
      ...[...allKeys].filter(k => !PRIORITY.includes(k)).sort(),
    ];
    const tabId = nextTabId();
    const fileName = name || `Sigma Timeline (${rows.length.toLocaleString()} events)`;

    const total = rows.length;
    const emit = (phase, inserted, text) => {
      safeSend("sigma-progress", {
        phase, importTotal: total, importInserted: inserted,
        importPct: total > 0 ? Math.min(100, Math.round((inserted / total) * 100)) : 0,
        text: text || `${inserted.toLocaleString()} / ${total.toLocaleString()} rows imported`,
      });
    };

    emit("importing-tab", 0, `Creating SQLite tab for ${total.toLocaleString()} events...`);
    safeSend("import-start", { tabId, fileName, filePath: "", fileSize: 0 });
    db.createTab(tabId, headers);

    const BATCH = 5000;
    for (let i = 0; i < rows.length; i += BATCH) {
      const chunk = rows.slice(i, i + BATCH);
      const arrays = chunk.map(row => headers.map(h => row[h] ?? ""));
      db.insertBatchArrays(tabId, arrays);
      // Yield to the event loop so the renderer can paint progress + sigma-progress can deliver
      await new Promise(r => setImmediate(r));
      emit("importing-tab", Math.min(i + BATCH, total));
    }

    emit("importing-tab", total, "Finalizing schema and detecting numeric columns...");
    const result = db.finalizeImport(tabId);
    let importedTagColors = null;
    if (postAction.tag && result.rowCount > 0) {
      const tagResult = db.bulkTagFiltered
        // Every row in this tab IS the Sigma match set — tagging the whole tab is the
        // intent here, so opt past bulkTagFiltered's unscoped-write guard explicitly.
        ? db.bulkTagFiltered(tabId, postAction.tag, { confirmWholeTab: true })
        : db.bulkAddTagToRows(tabId, _allImportedRowIds(result.rowCount), postAction.tag);
      importedTagColors = postAction.tagColor ? { [postAction.tag]: postAction.tagColor } : null;
      emit("importing-tab", total, `Applied tag "${postAction.tag}" to ${(tagResult?.tagged || result.rowCount).toLocaleString()} imported rows`);
    }
    if (postAction.bookmark && result.rowCount > 0) {
      if (db.bulkBookmarkFiltered) db.bulkBookmarkFiltered(tabId, true, { confirmWholeTab: true });
      else db.setBookmarks(tabId, _allImportedRowIds(result.rowCount), true);
      emit("importing-tab", total, `Bookmarked ${result.rowCount.toLocaleString()} imported rows`);
    }
    const initialData = db.queryRows(tabId, { offset: 0, limit: 5000, sortCol: null, sortDir: "asc" });
    const initialRowIds = initialData.rows
      .map((row) => Number(row.__idx))
      .filter((rowId) => Number.isInteger(rowId) && rowId > 0);
    const emptyColumns = db.getEmptyColumns(tabId);
    safeSend("import-complete", {
      tabId, fileName,
      headers: result.headers,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns || [],
      initialRows: initialData.rows,
      totalFiltered: initialData.totalFiltered,
      emptyColumns,
      sourceFormat,
      resolveStats: null,
      bookmarkedRowIds: postAction.bookmark ? initialRowIds : [],
      rowTags: postAction.tag ? _buildImportedRowTags(initialRowIds, postAction.tag) : {},
      tagColors: importedTagColors || null,
      importNotice,
    });
    if (scheduleIndexBuild) scheduleIndexBuild(tabId);
    emit("importing-tab-done", total, "Tab ready — building indexes in background");
    return { tabId, rowCount: result.rowCount };
  }

  async function _importResultStoreAsTab(job, name) {
    if (!job?.resultDbPath) return { error: "No scan result store available" };
    const store = SigmaResultStore.open(job.resultDbPath);
    try {
      const headers = store.getHeaders();
      const total = job.rowCount || store.rowCount || 0;
      if (total === 0) return { error: "No rows to import" };
      const tabId = nextTabId();
      const fileName = name || `Sigma Timeline (${total.toLocaleString()} events)`;
      const emit = (phase, inserted, text) => {
        safeSend("sigma-progress", {
          phase, importTotal: total, importInserted: inserted,
          importPct: total > 0 ? Math.min(100, Math.round((inserted / total) * 100)) : 0,
          text: text || `${inserted.toLocaleString()} / ${total.toLocaleString()} rows imported`,
        });
      };

      emit("importing-tab", 0, `Creating SQLite tab for ${total.toLocaleString()} events...`);
      safeSend("import-start", { tabId, fileName, filePath: "", fileSize: 0 });
      db.createTab(tabId, headers);

      const BATCH = 5000;
      let chunk = [];
      let inserted = 0;
      for (const row of store.iterateRows()) {
        chunk.push(headers.map(h => row[h] ?? ""));
        if (chunk.length >= BATCH) {
          db.insertBatchArrays(tabId, chunk);
          inserted += chunk.length;
          chunk = [];
          await new Promise(r => setImmediate(r));
          emit("importing-tab", inserted);
        }
      }
      if (chunk.length > 0) {
        db.insertBatchArrays(tabId, chunk);
        inserted += chunk.length;
        await new Promise(r => setImmediate(r));
        emit("importing-tab", inserted);
      }

      emit("importing-tab", total, "Finalizing schema and detecting numeric columns...");
      const result = db.finalizeImport(tabId);
      const initialData = db.queryRows(tabId, { offset: 0, limit: 5000, sortCol: null, sortDir: "asc" });
      const emptyColumns = db.getEmptyColumns(tabId);
      safeSend("import-complete", {
        tabId, fileName,
        headers: result.headers,
        rowCount: result.rowCount,
        tsColumns: result.tsColumns,
        numericColumns: result.numericColumns || [],
        initialRows: initialData.rows,
        totalFiltered: initialData.totalFiltered,
        emptyColumns,
        sourceFormat: "sigma-results",
        resolveStats: null,
      });
      if (scheduleIndexBuild) scheduleIndexBuild(tabId);
      emit("importing-tab-done", total, "Tab ready — building indexes in background");
      return { tabId, rowCount: result.rowCount };
    } finally {
      store.close();
    }
  }

  function _getSourceRowsForRule(jobId, rule = {}) {
    const job = _resolveJob(jobId);
    if (!job?.resultDbPath) return [];
    const store = SigmaResultStore.open(job.resultDbPath);
    try {
      return store.getSourceRowsForRule({ ruleId: rule.ruleId, ruleTitle: rule.title || rule.ruleTitle });
    } finally {
      store.close();
    }
  }

  function _getResultRowsForRule(jobId, rule = {}, limit = 100000) {
    const job = _resolveJob(jobId);
    if (!job?.resultDbPath) return [];
    const store = SigmaResultStore.open(job.resultDbPath);
    try {
      return store.getRowsForRule({ ruleId: rule.ruleId, ruleTitle: rule.title || rule.ruleTitle }, limit);
    } finally {
      store.close();
    }
  }

  async function _importSourceRowsAsTab(jobId, rule = {}, name = "", postAction = null) {
    const sourceRows = _getSourceRowsForRule(jobId, rule);
    if (sourceRows.length === 0) {
      const resultRows = _getResultRowsForRule(jobId, rule);
      if (resultRows.length === 0) return { error: "No exact result rows available for this rule" };
      const title = name || `Sigma exact hits - ${rule.title || rule.ruleId || "rule"}`;
      return _importJobAsTab(resultRows, title, { postAction });
    }

    const byTab = new Map();
    for (const source of sourceRows) {
      if (!source.tabId || !source.rowId) continue;
      if (!byTab.has(source.tabId)) byTab.set(source.tabId, []);
      byTab.get(source.tabId).push(source.rowId);
    }

    const rows = [];
    for (const [sourceTabId, rowIds] of byTab) {
      const sourceData = db.getRowsByIds(sourceTabId, rowIds);
      for (const row of sourceData) {
        const { __idx, ...sourceFields } = row;
        rows.push({
          SigmaRuleTitle: rule.title || rule.ruleTitle || "",
          SigmaRuleId: rule.ruleId || "",
          SourceTabId: sourceTabId,
          SourceRowId: __idx,
          ...sourceFields,
        });
      }
    }

    const title = name || `Sigma exact hits - ${rule.title || rule.ruleId || "rule"}`;
    return _importJobAsTab(rows, title, { postAction });
  }

  registerSigmaRuleSettingsHandlers({
    safeHandle,
    safeSend,
    _activeWindow,
    pathAuthorizer,
    detectionSettings,
    ruleSuppression,
    downloadFromGitHub,
    getAvailableRepos,
    getCacheStatus,
    getAllRules,
    loadLocalRules,
    importCustomRule,
    getCustomDir,
    _authorizeAppManagedPaths,
    _authorizePersistedDetectionSettingsPaths,
    _assertDetectionSettingsPathsAuthorized,
    _syncRuleSuppressionsToHayabusa,
  });

  // Scan dataset against Sigma rules. Result rows are stored server-side
  // in _scanJobs so the renderer never has to ship 100K+ rows over IPC.
  // Progress events are throttled to ~10/sec — the JS engine emits hundreds
  // per scan and the modal re-renders on each, which made the UI feel laggy.
  safeHandle("sigma-scan", async (event, { tabId, options }) => {
    const scanStartedAt = Date.now();
    const meta = db.databases.get(tabId);
    if (!meta) return { matches: [], stats: {}, errors: ["Tab not found"], warnings: [], eventRowCount: 0, eventRowsPreview: [] };
    const opts = _withSuppressedRuleIds(options || {});
    if (Array.isArray(opts.levels) && opts.levels.length === 0) {
      return { matches: [], stats: {}, errors: ["At least one severity level must be selected."], warnings: [], eventRowCount: 0, eventRowsPreview: [] };
    }
    if (Array.isArray(opts.statuses) && opts.statuses.length === 0) {
      return { matches: [], stats: {}, errors: ["At least one rule status must be selected."], warnings: [], eventRowCount: 0, eventRowsPreview: [] };
    }
    const scanJobId = opts.scanJobId || _nextJobId();

    let lastEmit = 0;
    const PROGRESS_INTERVAL_MS = 100;
    const onProgress = (progress) => {
      const now = Date.now();
      // Always emit terminal/phase-changing events; throttle the chatty "scanning" updates.
      const isTerminal = progress?.phase === "done" || progress?.phase === "error";
      if (!isTerminal && now - lastEmit < PROGRESS_INTERVAL_MS) return;
      lastEmit = now;
      safeSend("sigma-progress", { ...progress, scanJobId });
    };

    let result;
    try {
      const descriptor = db.getTabWorkerDescriptor?.(tabId);
      if (jobManager && descriptor) {
        const { promise } = jobManager.startWorkerJob({
          type: "sigma-scan",
          worker: "sigma-worker.js",
          workerData: { jobId: scanJobId, tabId, descriptor, userDataPath: app?.getPath?.("userData"), resourcesPath: process.resourcesPath, options: { ...opts, scanJobId } },
          channels: { progress: "sigma-progress" },
          metadata: { tabId, scanJobId },
          resourceClass: "heavy",
        });
        result = await promise;
      } else {
        result = await scanSigmaRules(meta, {
          ...opts,
          resultStorePath: createTempResultPath(),
          previewLimit: 2000,
          isCancelled: () => _cancelledJsScans.has(scanJobId),
        }, onProgress);
      }
    } finally {
      _cancelledJsScans.delete(scanJobId);
    }
    result.stats = { ...(result.stats || {}), runtimeMs: result.stats?.runtimeMs || (Date.now() - scanStartedAt) };
    const jobId = scanJobId;
    _scanJobs.set(jobId, {
      rows: result.eventRows || [],
      resultDbPath: result.resultDbPath || null,
      resultHeaders: result.resultHeaders || null,
      rowCount: result.eventRowCount || (result.eventRows || []).length,
      htmlReport: null,
      createdAt: Date.now(),
      dirPath: null, // tab scan — no source directory
      sourceTabId: tabId,
      engine: "IRFlow Sigma Engine",
    });
    let historyRecord = null;
    const triageAggregates = _triageAggregatesForJob(_scanJobs.get(jobId));
    try {
      const job = _scanJobs.get(jobId);
      historyRecord = scanHistory.saveScanHistory({
        jobId,
        resultDbPath: job?.resultDbPath || null,
        metadata: {
          ..._ruleCacheSnapshot(),
          scanType: "tab",
          engine: "IRFlow Sigma Engine",
          targetName: opts.sourceName || `Tab ${tabId}`,
          targetPath: opts.sourcePath || "",
          sourceTabId: tabId,
          levels: opts.levels || [],
          statuses: opts.statuses || [],
          categories: opts.categories || null,
          options: { categories: opts.categories || null, presetId: opts.presetId || null, presetName: opts.presetName || null },
          commandLine: _jsSigmaCommandLine("current-tab", opts),
          reproducibility: {
            engine: "IRFlow Sigma Engine",
            commandLine: _jsSigmaCommandLine("current-tab", opts),
            commandArgs: {
              target: "current-tab",
              levels: opts.levels || [],
              statuses: opts.statuses || [],
              categories: opts.categories || null,
              presetId: opts.presetId || null,
              presetName: opts.presetName || null,
            },
          },
          matches: result.matches || [],
          stats: result.stats || {},
          errors: result.errors || [],
          warnings: result.warnings || [],
          eventRowCount: result.eventRowCount || (result.eventRows || []).length,
          triageAggregates,
        },
      });
    } catch (e) {
      result.errors = [...(result.errors || []), `Scan history was not saved: ${e.message}`];
    }
    _cleanupJobs();
    const job = _scanJobs.get(jobId);
    return {
      jobId,
      historyId: historyRecord?.id || null,
      historyRecord,
      triageAggregates,
      matches: result.matches || [],
      stats: result.stats || {},
      errors: result.errors || [],
      warnings: result.warnings || [],
      eventRowCount: job?.rowCount || (job?.rows || []).length,
      // Send first 2000 rows for preview in the modal timeline view (mirrors dir-scan behaviour)
      eventRowsPreview: (job?.rows || []).slice(0, 2000),
    };
  });

  // Preview the auto-detected dataset format for a tab so the wizard can show it
  // and let the analyst override it (options.formatOverride) before a JS scan.
  safeHandle("sigma-detect-format", (event, { tabId } = {}) => {
    const meta = db.databases.get(tabId);
    if (!meta) return { error: "Tab not found" };
    const { detectDatasetFormat, FORMAT_LABELS, FORMATS } = require("../analyzers/sigma/format-detect");
    const detected = detectDatasetFormat(meta);
    return {
      detected,
      label: FORMAT_LABELS[detected] || "Unknown",
      options: FORMATS.map((id) => ({ id, label: FORMAT_LABELS[id] })),
    };
  });

  // Open Sigma scan results directly as a new tab. Backward-compatible: accepts
  // either a jobId (new path — rows on backend) or rows (legacy fallback).
  safeHandle("sigma-open-as-tab", async (event, { rows, name, jobId, sourceFormat, importNotice, postAction } = {}) => {
    const tabOptions = { sourceFormat, importNotice, postAction };
    if (jobId) {
      const job = _resolveJob(jobId);
      if (job?.resultDbPath) return _importResultStoreAsTab(job, name);
      if (!job?.rows || job.rows.length === 0) return { error: "No scan results to open" };
      const result = await _importJobAsTab(job.rows, name, tabOptions);
      // Free job rows after successful import to release memory
      if (!result.error) job.rows = null;
      return result;
    }
    return _importJobAsTab(rows, name, tabOptions);
  });

  // Get Hayabusa binary status (installed, version, path)
  safeHandle("sigma-hayabusa-status", () => {
    const status = getHayabusaStatus();
    _authorizeAppManagedPaths();
    return { ...status, ruleState: status.installed ? _hayabusaRuleSnapshot() : null };
  });

  // Download and install Hayabusa from GitHub releases
  safeHandle("sigma-hayabusa-download", async () => {
    const binPath = await downloadHayabusa((phase, detail, extra = {}) => {
      safeSend("sigma-progress", { phase, detail, text: detail, ...extra });
    });
    _authorizeAppManagedPaths();
    const sync = _syncRuleSuppressionsToHayabusa();
    const status = getHayabusaStatus();
    return { path: binPath, ...status, ruleSuppressionSync: sync, ruleState: status.installed ? _hayabusaRuleSnapshot() : null };
  });

  // Update Hayabusa detection rules (runs hayabusa update-rules)
  safeHandle("sigma-hayabusa-update-rules", async () => {
    const result = await updateHayabusaRules((phase, detail, extra = {}) => {
      safeSend("sigma-progress", { phase, detail, text: detail, ...extra });
    });
    _authorizeAppManagedPaths();
    const sync = _syncRuleSuppressionsToHayabusa();
    return { ...result, ruleSuppressionSync: sync };
  });

  // Update Hayabusa binary to latest version
  safeHandle("sigma-hayabusa-update", async () => {
    const result = await updateHayabusa((phase, detail, extra = {}) => {
      safeSend("sigma-progress", { phase, detail, text: detail, ...extra });
    });
    _authorizeAppManagedPaths();
    const sync = _syncRuleSuppressionsToHayabusa();
    const status = getHayabusaStatus();
    return { ...status, ...result, ruleSuppressionSync: sync, ruleState: status.installed ? _hayabusaRuleSnapshot() : null };
  });

  // Select an EVTX directory via native dialog
  safeHandle("sigma-select-evtx-dir", async () => {
    const win = typeof _activeWindow === "function" ? _activeWindow() : null;
    const result = await dialog.showOpenDialog(win, openDialogOptions({
      properties: ["openDirectory"],
      title: "Select EVTX Directory",
      message: "Choose a folder containing .evtx files to scan with Hayabusa",
    }));
    if (result.canceled || !result.filePaths?.length) return null;
    const dirPath = result.filePaths[0];
    _authorizeSelectedScanPath(dirPath);
    // Quick preview: count .evtx files and total size
    const files = findEvtxFiles(dirPath);
    return {
      dirPath,
      fileCount: files.length,
      totalBytes: files.reduce((s, f) => s + f.size, 0),
      files: files.map(f => ({ name: f.name, size: f.size })),
    };
  });

  safeHandle("sigma-select-kape-output", async () => {
    const win = typeof _activeWindow === "function" ? _activeWindow() : null;
    const result = await dialog.showOpenDialog(win, openDialogOptions({
      properties: ["openFile", "multiSelections"],
      title: "Select EvtxECmd Output Files",
      message: "Choose one or more EvtxECmd CSV/XLS/XLSX output files",
      filters: [
        { name: "EvtxECmd Output Files", extensions: ["csv", "tsv", "xlsx", "xls", "xlsm"] },
      ],
    }));
    if (result.canceled || !result.filePaths?.length) return null;
    for (const targetPath of result.filePaths) _authorizeSelectedKapePath(targetPath);
    const summary = summarizeKapeSelection(result.filePaths);
    if (!summary.fileCount) {
      throw new Error("Selected files do not look like EvtxECmd output. Choose files with EventID, timestamp, provider/channel, and EvtxECmd payload columns.");
    }
    return { ...summary, selectionMode: "files" };
  });

  safeHandle("sigma-select-kape-output-folder", async () => {
    const win = typeof _activeWindow === "function" ? _activeWindow() : null;
    const result = await dialog.showOpenDialog(win, openDialogOptions({
      properties: ["openDirectory"],
      title: "Find EvtxECmd Outputs in Folder",
      message: "Choose a folder to search recursively. Only validated EvtxECmd CSV/XLS/XLSX files will be accepted.",
    }));
    if (result.canceled || !result.filePaths?.length) return null;
    const folderPath = result.filePaths[0];
    _authorizeSelectedKapePath(folderPath);
    const summary = summarizeKapeSelection([folderPath]);
    if (!summary.fileCount) {
      const ignored = summary.ignoredCount ? ` ${summary.ignoredCount.toLocaleString()} unrelated or invalid file${summary.ignoredCount === 1 ? "" : "s"} were ignored.` : "";
      throw new Error(`No valid EvtxECmd output files found in the selected folder.${ignored}`);
    }
    return { ...summary, selectionMode: "folder" };
  });

  safeHandle("sigma-validate-scan-directory", (event, { dirPath, options } = {}) => {
    _assertScanPath(dirPath);
    _assertScanOptionsPaths(options || {});
    return validateEvtxScanRequest(dirPath, _withHayabusaPreflightState(options || {}));
  });

  // List active scan jobs (for debugging / future multi-scan UI)
  safeHandle("sigma-list-jobs", () => {
    const jobs = [];
    for (const [id, job] of _scanJobs) {
      jobs.push({ jobId: id, dirPath: job.dirPath, rowCount: job.rowCount || (job.rows || []).length, hasReport: !!job.htmlReport, createdAt: job.createdAt, engine: job.engine || null });
    }
    return jobs.sort((a, b) => b.createdAt - a.createdAt);
  });

  registerSigmaHistoryHandlers({
    safeHandle,
    _activeWindow,
    scanHistory,
    SigmaResultStore,
    _triageAggregatesForStore,
  });

  // Scan an entire EVTX directory against Sigma rules.
  // Frontend supplies a scanJobId so it can cancel via "sigma-cancel-scan".
  // The same id is also reused as the result jobId for storing rows.
  safeHandle("sigma-scan-directory", async (event, { dirPath, options }) => {
    if (!dirPath) return { matches: [], stats: {}, errors: ["No directory specified"] };
    const opts = _withHayabusaPreflightState(options || {});
    _assertScanPath(dirPath);
    _assertScanOptionsPaths(opts);
    _syncRuleSuppressionsToHayabusa();
    const scanJobId = opts.scanJobId || _nextJobId();

    // Throttle Hayabusa stderr-driven progress events (chunked many times per second)
    let lastEmit = 0;
    const PROGRESS_INTERVAL_MS = 100;
    const onProgress = (progress) => {
      const now = Date.now();
      // Always emit phase-changing events so the UI never misses a stage transition.
      const isPhaseChange = progress?.phase && progress.phase !== "hayabusa-running";
      if (!isPhaseChange && now - lastEmit < PROGRESS_INTERVAL_MS) return;
      lastEmit = now;
      safeSend("sigma-progress", { ...progress, scanJobId });
    };

    const result = await scanEvtxDirectory(dirPath, db, nextTabId, { ...opts, scanJobId }, onProgress);
    if (result.cancelled) {
      return {
        jobId: scanJobId, cancelled: true,
        matches: [], stats: result.stats || {},
        errors: result.errors || ["Scan cancelled"],
        warnings: result.warnings || [],
        evtxFiles: result.evtxFiles || [],
        eventRowCount: 0, hasHtmlReport: false, eventRowsPreview: [],
      };
    }
    // Store large data in job — don't serialize over IPC
    _scanJobs.set(scanJobId, {
      rows: result.eventRows || [],
      resultDbPath: result.resultDbPath || null,
      resultHeaders: result.resultHeaders || null,
      rowCount: result.eventRowCount || (result.eventRows || []).length,
      htmlReport: result.htmlReport || null,
      createdAt: Date.now(),
      dirPath,
      engine: "Hayabusa",
    });
    let historyRecord = null;
    const triageAggregates = _triageAggregatesForJob(_scanJobs.get(scanJobId));
    try {
      const job = _scanJobs.get(scanJobId);
      const hayabusa = getHayabusaStatus();
      historyRecord = scanHistory.saveScanHistory({
        jobId: scanJobId,
        resultDbPath: job?.resultDbPath || null,
        htmlReport: result.htmlReport || null,
        metadata: {
          scanType: "evtx-dir",
          engine: "Hayabusa",
          hayabusaVersion: hayabusa?.version || null,
          ..._hayabusaRuleSnapshot(),
          targetName: dirPath,
          targetPath: dirPath,
          levels: opts.levels || [],
          statuses: opts.statuses || [],
          categories: opts.categories || null,
          options: {
            ruleSet: opts.ruleSet || "all",
            profile: opts.profile || "verbose",
            outputMode: opts.outputMode || "csv",
            timelineStart: opts.timelineStart || null,
            timelineEnd: opts.timelineEnd || null,
            recoverRecords: !!opts.recoverRecords,
            utc: !!opts.utc,
            provenRules: !!opts.provenRules,
            eidFilter: !!opts.eidFilter,
            enableAllRules: !!opts.enableAllRules,
            scanAllEvtxFiles: !!opts.scanAllEvtxFiles,
          },
          commandLine: result.reproducibility?.commandLine || result.stats?.commandLine || null,
          commandArgs: result.reproducibility?.commandArgs || [],
          reproducibility: result.reproducibility || null,
          configFiles: _hayabusaConfigSnapshot(opts),
          matches: result.matches || [],
          stats: result.stats || {},
          errors: result.errors || [],
          warnings: result.warnings || [],
          evtxFiles: result.evtxFiles || [],
          eventRowCount: result.eventRowCount || (result.eventRows || []).length,
          triageAggregates,
        },
      });
    } catch (e) {
      result.errors = [...(result.errors || []), `Scan history was not saved: ${e.message}`];
    }
    _cleanupJobs();
    const job = _scanJobs.get(scanJobId);
    return {
      jobId: scanJobId,
      historyId: historyRecord?.id || null,
      historyRecord,
      triageAggregates,
      matches: result.matches,
      stats: result.stats,
      errors: result.errors,
      warnings: result.warnings || [],
      evtxFiles: result.evtxFiles,
      eventRowCount: job?.rowCount || (job?.rows || []).length,
      hasHtmlReport: !!job?.htmlReport,
      // Send first 2000 rows for preview in the modal timeline view
      eventRowsPreview: (job?.rows || []).slice(0, 2000),
    };
  });

  // Cancel an in-flight directory scan. Idempotent.
  safeHandle("sigma-cancel-scan", async (event, { scanJobId } = {}) => {
    if (!scanJobId) return { cancelled: false, reason: "no scanJobId" };
    _cancelledJsScans.add(scanJobId);
    const hayabusaCancel = await cancelScan(scanJobId);
    if (hayabusaCancel.cancelled) return hayabusaCancel;
    if (jobManager) {
      const result = jobManager.cancel(scanJobId);
      if (result.ok) return { cancelled: true };
    }
    return hayabusaCancel;
  });

  safeHandle("sigma-scan-kape-output", async (event, { paths, options } = {}) => {
    const scanStartedAt = Date.now();
    const selectedPaths = _assertKapePaths(paths || []);
    const opts = _withSuppressedRuleIds(options || {});
    if (Array.isArray(opts.levels) && opts.levels.length === 0) {
      return { matches: [], stats: {}, errors: ["At least one severity level must be selected."], warnings: [], eventRowCount: 0, eventRowsPreview: [] };
    }
    if (Array.isArray(opts.statuses) && opts.statuses.length === 0) {
      return { matches: [], stats: {}, errors: ["At least one rule status must be selected."], warnings: [], eventRowCount: 0, eventRowsPreview: [] };
    }
    const scanJobId = opts.scanJobId || _nextJobId();
    let lastEmit = 0;
    const onProgress = (progress) => {
      const now = Date.now();
      const isTerminal = progress?.phase === "done" || progress?.phase === "error";
      if (!isTerminal && now - lastEmit < 100) return;
      lastEmit = now;
      safeSend("sigma-progress", { ...progress, scanJobId });
    };
    try {
      const result = await scanKapeOutputs(selectedPaths, {
        ...opts,
        scanJobId,
        isCancelled: () => _cancelledJsScans.has(scanJobId),
      }, onProgress);
      result.stats = { ...(result.stats || {}), runtimeMs: result.stats?.runtimeMs || (Date.now() - scanStartedAt) };
      _scanJobs.set(scanJobId, {
        rows: result.eventRows || [],
        resultDbPath: result.resultDbPath || null,
        resultHeaders: result.resultHeaders || null,
        rowCount: result.eventRowCount || (result.eventRows || []).length,
        htmlReport: null,
        createdAt: Date.now(),
        dirPath: null,
        sourceTabId: null,
        engine: "IRFlow Sigma Engine",
      });
      const files = result.files || [];
      const triageAggregates = _triageAggregatesForJob(_scanJobs.get(scanJobId));
      let historyRecord = null;
      try {
        historyRecord = scanHistory.saveScanHistory({
          jobId: scanJobId,
          resultDbPath: result.resultDbPath || null,
          metadata: {
            ..._ruleCacheSnapshot(),
            scanType: "kape-output",
            engine: "IRFlow Sigma Engine",
            targetName: files.length === 1 ? files[0].name : `${files.length} EvtxECmd output files`,
            targetPath: selectedPaths.join("; "),
            levels: opts.levels || [],
            statuses: opts.statuses || [],
            categories: opts.categories || null,
            options: { categories: opts.categories || null, presetId: opts.presetId || null, presetName: opts.presetName || null },
            commandLine: _jsSigmaCommandLine("kape-output", opts),
            reproducibility: {
              engine: "IRFlow Sigma Engine",
              commandLine: _jsSigmaCommandLine("kape-output", opts),
              commandArgs: {
                target: "kape-output",
                levels: opts.levels || [],
                statuses: opts.statuses || [],
                categories: opts.categories || null,
                presetId: opts.presetId || null,
                presetName: opts.presetName || null,
              },
            },
            matches: result.matches || [],
            stats: result.stats || {},
            errors: result.errors || [],
            warnings: result.warnings || [],
            eventRowCount: result.eventRowCount || (result.eventRows || []).length,
            triageAggregates,
          },
        });
      } catch (e) {
        result.errors = [...(result.errors || []), `Scan history was not saved: ${e.message}`];
      }
      _cleanupJobs();
      const job = _scanJobs.get(scanJobId);
      return {
        jobId: scanJobId,
        historyId: historyRecord?.id || null,
        historyRecord,
        triageAggregates,
        matches: result.matches || [],
        stats: result.stats || {},
        errors: result.errors || [],
        warnings: result.warnings || [],
        files,
        eventRowCount: job?.rowCount || result.eventRowCount || 0,
        eventRowsPreview: result.eventRowsPreview || (job?.rows || []).slice(0, 2000),
      };
    } catch (err) {
      if (err?.cancelled) {
        return { jobId: scanJobId, cancelled: true, matches: [], stats: { runtimeMs: Date.now() - scanStartedAt }, errors: ["Scan cancelled"], warnings: [], eventRowCount: 0, eventRowsPreview: [] };
      }
      throw err;
    } finally {
      _cancelledJsScans.delete(scanJobId);
    }
  });

  registerSigmaResultActionHandlers({
    safeHandle,
    db,
    SigmaResultStore,
    _activeWindow,
    _resolveJob,
    _importJobAsTab,
    _importResultStoreAsTab,
    _getJobHtmlReport,
    _getSourceRowsForRule,
    _importSourceRowsAsTab,
  });

  // ── Hayabusa metrics commands ─────────────────────────────────────

  safeHandle("sigma-logon-summary", async (event, { dirPath }) => {
    _assertScanPath(dirPath);
    return runLogonSummary(dirPath, (p) => safeSend("sigma-progress", p));
  });

  safeHandle("sigma-computer-metrics", async (event, { dirPath }) => {
    _assertScanPath(dirPath);
    return runComputerMetrics(dirPath, (p) => safeSend("sigma-progress", p));
  });

  safeHandle("sigma-eid-metrics", async (event, { dirPath }) => {
    _assertScanPath(dirPath);
    return runEidMetrics(dirPath, (p) => safeSend("sigma-progress", p));
  });

  safeHandle("sigma-log-metrics", async (event, { dirPath }) => {
    _assertScanPath(dirPath);
    return runLogMetrics(dirPath, (p) => safeSend("sigma-progress", p));
  });

  // ── Hayabusa search + pivot commands ────────────────────────────────

  safeHandle("sigma-search", async (event, { dirPath, searchOpts }) => {
    if (!dirPath) return { rows: [], errors: ["No directory specified"] };
    _assertScanPath(dirPath);
    return runSearch(dirPath, searchOpts || {}, (p) => safeSend("sigma-progress", p));
  });

  safeHandle("sigma-pivot-keywords", async (event, { dirPath }) => {
    _assertScanPath(dirPath);
    return runPivotKeywords(dirPath, (p) => safeSend("sigma-progress", p));
  });

  safeHandle("sigma-extract-base64", async (event, { dirPath }) => {
    _assertScanPath(dirPath);
    return runExtractBase64(dirPath, (p) => safeSend("sigma-progress", p));
  });

  // ── Output profiles ───────────────────────────────────────────────

  safeHandle("sigma-get-profiles", () => {
    return getAvailableProfiles();
  });

  // ── Rules & Tuning ────────────────────────────────────────────────

  // Get the path to Hayabusa's rules config directory (for level-tuning, etc.)
  safeHandle("sigma-get-rules-config-dir", () => {
    _authorizeAppManagedPaths();
    return { path: getRulesConfigDir() };
  });

  // Get level-tuning config path
  safeHandle("sigma-get-level-tuning-path", () => {
    _authorizeAppManagedPaths();
    return { path: getLevelTuningPath() };
  });

  // Open Hayabusa rules config directory in system file manager
  safeHandle("sigma-open-rules-config-dir", () => {
    const { shell } = require("electron");
    _authorizeAppManagedPaths();
    const dir = getRulesConfigDir();
    if (!dir) return { error: "Hayabusa not installed" };
    shell.openPath(dir);
    return { opened: true, path: dir };
  });

  // Select a custom rules directory via native dialog
  safeHandle("sigma-select-rules-path", async () => {
    const win = typeof _activeWindow === "function" ? _activeWindow() : null;
    const result = await dialog.showOpenDialog(win, openDialogOptions({
      properties: ["openDirectory"],
      title: "Select Custom Rules Directory",
      message: "Choose a folder containing Hayabusa/Sigma rules",
    }));
    if (result.canceled || !result.filePaths?.length) return null;
    const selectedPath = result.filePaths[0];
    pathAuthorizer.authorize("hayabusa-rules", selectedPath, {
      recursive: true,
      label: "Selected Hayabusa rules directory",
    });
    pathAuthorizer.authorize("compat-rules", selectedPath, {
      recursive: true,
      label: "Selected compatibility rule directory",
    });
    return { path: selectedPath };
  });

  // Select a rules config file via native dialog
  safeHandle("sigma-select-rules-config", async () => {
    const win = typeof _activeWindow === "function" ? _activeWindow() : null;
    const result = await dialog.showOpenDialog(win, openDialogOptions({
      properties: ["openFile"],
      title: "Select Rules Config File",
      filters: [{ name: "YAML Files", extensions: ["yml", "yaml"] }],
    }));
    if (result.canceled || !result.filePaths?.length) return null;
    const selectedPath = result.filePaths[0];
    pathAuthorizer.authorize("hayabusa-rules-config", selectedPath, {
      recursive: false,
      label: "Selected Hayabusa rules config",
    });
    return { path: selectedPath };
  });

  // Apply level tuning
  safeHandle("sigma-level-tuning", async (event, { tunings }) => {
    return runLevelTuning(tunings || [], (p) => safeSend("sigma-progress", p));
  });

  // ── GeoIP enrichment ──────────────────────────────────────────────

  // Check GeoIP database status
  safeHandle("sigma-geoip-status", () => {
    _authorizeAppManagedPaths();
    return getGeoIpStatus();
  });

  // Download GeoIP databases via Hayabusa's geo-ip command
  safeHandle("sigma-geoip-download", async () => {
    const result = await downloadGeoIp((phase, detail) => {
      safeSend("sigma-progress", { phase, detail, text: detail });
    });
    _authorizeAppManagedPaths();
    if (result?.path) {
      pathAuthorizer.authorizeIfExists("geoip", result.path, {
        recursive: true,
        appManaged: true,
        label: "Downloaded GeoIP databases",
      });
    }
    return result;
  });

  // Select a GeoIP database directory via native dialog
  safeHandle("sigma-select-geoip-dir", async () => {
    const win = typeof _activeWindow === "function" ? _activeWindow() : null;
    const result = await dialog.showOpenDialog(win, openDialogOptions({
      properties: ["openDirectory"],
      title: "Select GeoIP Database Directory",
      message: "Choose a folder containing MaxMind GeoLite2 .mmdb files",
    }));
    if (result.canceled || !result.filePaths?.length) return null;
    const selectedPath = result.filePaths[0];
    pathAuthorizer.authorize("geoip", selectedPath, {
      recursive: true,
      label: "Selected GeoIP directory",
    });
    return { path: selectedPath };
  });
};
