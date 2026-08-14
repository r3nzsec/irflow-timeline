const fs = require("fs");
const crypto = require("crypto");
const { dialog } = require("electron");
const { openDialogOptions } = require("../utils/open-dialog");
const { fingerprint } = require("../analyzers/ai-history/validators");
const {
  AiSecretResultReader,
  MAX_PAGE_SIZE,
  resultPathForJob,
  removeStore,
} = require("../analyzers/ai-history/result-store");

module.exports = function registerAnalysisHandlers(safeHandle, safeSend, { db, _tabMeta, extractResidentData, _activeWindow, runAnalyzerJob, startAnalyzerJob }) {
  const analyze = (method, payload, fallback) => {
    if (runAnalyzerJob) return runAnalyzerJob(method, payload);
    return fallback();
  };

  safeHandle("extract-resident-data", async (event, { tabId }) => {
    const meta = _tabMeta.get(tabId);
    if (!meta || meta.sourceFormat !== "raw-mft") {
      return { error: "This tab is not a raw MFT file" };
    }
    if (!fs.existsSync(meta.filePath)) {
      return { error: `Original MFT file no longer exists: ${meta.filePath}` };
    }

    const result = await dialog.showOpenDialog(_activeWindow(), openDialogOptions({
      title: "Choose output folder for resident data extraction",
      properties: ["openDirectory", "createDirectory"],
      buttonLabel: "Extract Here",
    }));
    if (result.canceled || !result.filePaths[0]) return { canceled: true };

    const extractResult = await extractResidentData(meta.filePath, result.filePaths[0], (processed, total) => {
      safeSend("extract-resident-progress", {
        tabId, processed, total,
        percent: total > 0 ? Math.round((processed / total) * 100) : 0,
      });
    });
    return extractResult;
  });

  // Ransomware MFT Analysis
  safeHandle("analyze-ransomware", (event, { tabId, encryptedExt, ransomNotePattern, noteMatchMode, usnTabId, evtxTabId }) => {
    const meta = _tabMeta.get(tabId);
    if (!meta || meta.sourceFormat !== "raw-mft") {
      return { error: "This feature requires a raw MFT tab." };
    }
    let resolvedUsnTabId = null;
    if (usnTabId) {
      const usnMeta = _tabMeta.get(usnTabId);
      if (usnMeta?.sourceFormat === "raw-usnjrnl") resolvedUsnTabId = usnTabId;
    }
    if (!resolvedUsnTabId) {
      for (const [tid, tmeta] of _tabMeta) {
        if (tid !== tabId && tmeta.sourceFormat === "raw-usnjrnl") {
          resolvedUsnTabId = tid;
          break;
        }
      }
    }
    // Optional EVTX tab for defense-evasion correlation. EVTX CSVs (EvtxECmd/Hayabusa/Chainsaw)
    // carry no sourceFormat, so resolve by header signature.
    const { _rwLooksLikeEvtx } = require("../analyzers/ransomware");
    let resolvedEvtxTabId = null;
    if (evtxTabId && evtxTabId !== "__none__") {
      const m = _tabMeta.get(evtxTabId);
      if (m && _rwLooksLikeEvtx(m)) resolvedEvtxTabId = evtxTabId;
    }
    if (!resolvedEvtxTabId && evtxTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) {
        if (tid !== tabId && tid !== resolvedUsnTabId && _rwLooksLikeEvtx(tmeta)) { resolvedEvtxTabId = tid; break; }
      }
    }
    return analyze(
      "analyzeRansomware",
      { tabId, options: { encryptedExt, ransomNotePattern, noteMatchMode, usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId } },
      () => db.analyzeRansomware(tabId, { encryptedExt, ransomNotePattern, noteMatchMode, usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId, progressCb: (p) => safeSend("rw-progress", p) })
    );
  });

  safeHandle("scan-ransomware-extensions", (event, { tabId }) => {
    const meta = _tabMeta.get(tabId);
    if (!meta || meta.sourceFormat !== "raw-mft") {
      return { error: "This feature requires a raw MFT tab." };
    }
    return analyze(
      "scanRansomwareExtensions",
      { tabId },
      () => db.scanRansomwareExtensions(tabId, (p) => safeSend("rw-progress", p))
    );
  });

  // Timestomping Detector — auto-resolve companion USN ($J) + EVTX (Sysmon) tabs for cross-artifact
  // corroboration (Sysmon EID 2 FileCreateTime, USN FileCreate contradiction). '__none__' opts out.
  safeHandle("detect-timestomping", (event, { tabId, usnTabId, evtxTabId }) => {
    let resolvedUsnTabId = null;
    if (usnTabId && usnTabId !== "__none__") { const m = _tabMeta.get(usnTabId); if (m?.sourceFormat === "raw-usnjrnl") resolvedUsnTabId = usnTabId; }
    if (!resolvedUsnTabId && usnTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) { if (tid !== tabId && tmeta.sourceFormat === "raw-usnjrnl") { resolvedUsnTabId = tid; break; } }
    }
    const { _rwLooksLikeEvtx } = require("../analyzers/ransomware");
    let resolvedEvtxTabId = null;
    if (evtxTabId && evtxTabId !== "__none__") { const m = _tabMeta.get(evtxTabId); if (m && _rwLooksLikeEvtx(m)) resolvedEvtxTabId = evtxTabId; }
    if (!resolvedEvtxTabId && evtxTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) { if (tid !== tabId && tid !== resolvedUsnTabId && _rwLooksLikeEvtx(tmeta)) { resolvedEvtxTabId = tid; break; } }
    }
    return analyze(
      "detectTimestomping",
      { tabId, options: { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId } },
      () => db.detectTimestomping(tabId, { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId })
    );
  });

  // File Activity Heatmap
  safeHandle("get-file-activity-heatmap", (event, { tabId, usnTabId, evtxTabId }) => {
    const meta = _tabMeta.get(tabId);
    if (!meta || meta.sourceFormat !== "raw-mft") {
      return { error: "This feature requires a raw MFT tab." };
    }
    // Auto-resolve a companion USN ($J) tab for forgery-resistant corroboration of $SI-derived
    // windows. '__none__' lets the caller explicitly opt out.
    let resolvedUsnTabId = null;
    if (usnTabId && usnTabId !== "__none__") {
      const m = _tabMeta.get(usnTabId);
      if (m?.sourceFormat === "raw-usnjrnl") resolvedUsnTabId = usnTabId;
    }
    if (!resolvedUsnTabId && usnTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) {
        if (tid !== tabId && tmeta.sourceFormat === "raw-usnjrnl") { resolvedUsnTabId = tid; break; }
      }
    }
    // Auto-resolve a companion EVTX tab for process-execution corroboration. EVTX CSVs
    // (EvtxECmd/Hayabusa/Chainsaw) carry no sourceFormat, so detect by header signature.
    const { _rwLooksLikeEvtx } = require("../analyzers/ransomware");
    let resolvedEvtxTabId = null;
    if (evtxTabId && evtxTabId !== "__none__") {
      const m = _tabMeta.get(evtxTabId);
      if (m && _rwLooksLikeEvtx(m)) resolvedEvtxTabId = evtxTabId;
    }
    if (!resolvedEvtxTabId && evtxTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) {
        if (tid !== tabId && tid !== resolvedUsnTabId && _rwLooksLikeEvtx(tmeta)) { resolvedEvtxTabId = tid; break; }
      }
    }
    return analyze(
      "getFileActivityHeatmap",
      { tabId, options: { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId } },
      () => db.getFileActivityHeatmap(tabId, { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId, progressCb: (p) => safeSend("hm-progress", p) })
    );
  });

  // ADS Analyzer
  safeHandle("analyze-ads", (event, { tabId, usnTabId, evtxTabId }) => {
    // Auto-resolve companion USN ($J) + EVTX tabs for cross-artifact corroboration of ADS/MOTW
    // events (StreamChange / Sysmon EID 15). '__none__' opts out.
    let resolvedUsnTabId = null;
    if (usnTabId && usnTabId !== "__none__") { const m = _tabMeta.get(usnTabId); if (m?.sourceFormat === "raw-usnjrnl") resolvedUsnTabId = usnTabId; }
    if (!resolvedUsnTabId && usnTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) { if (tid !== tabId && tmeta.sourceFormat === "raw-usnjrnl") { resolvedUsnTabId = tid; break; } }
    }
    const { _rwLooksLikeEvtx } = require("../analyzers/ransomware");
    let resolvedEvtxTabId = null;
    if (evtxTabId && evtxTabId !== "__none__") { const m = _tabMeta.get(evtxTabId); if (m && _rwLooksLikeEvtx(m)) resolvedEvtxTabId = evtxTabId; }
    if (!resolvedEvtxTabId && evtxTabId !== "__none__") {
      for (const [tid, tmeta] of _tabMeta) { if (tid !== tabId && tid !== resolvedUsnTabId && _rwLooksLikeEvtx(tmeta)) { resolvedEvtxTabId = tid; break; } }
    }
    return analyze(
      "analyzeADS",
      { tabId, options: { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId } },
      () => db.analyzeADS(tabId, { usnTabId: resolvedUsnTabId, evtxTabId: resolvedEvtxTabId })
    );
  });

  // AI Secret & Leak Scan — credential/key/PII detection over an AI history tab. Worker results
  // are disk-backed and paged; the registry is the authorization boundary for page/reveal calls.
  const aiSecretScans = new Map();
  const releaseAiSecretScan = (scanId) => {
    const entry = aiSecretScans.get(String(scanId || ""));
    if (!entry) return false;
    aiSecretScans.delete(String(scanId));
    if (entry.timer) clearTimeout(entry.timer);
    try { removeStore(entry.filePath); } catch {}
    return true;
  };
  const registerAiSecretScan = (jobId, tabId, salt, result) => {
    const expectedPath = resultPathForJob(jobId);
    if (!result?.resultStorePath || result.resultStorePath !== expectedPath) {
      throw new Error("AI Secret result store failed path validation");
    }
    for (const [existingId, entry] of aiSecretScans) {
      if (entry.tabId === tabId) releaseAiSecretScan(existingId);
    }
    const timer = setTimeout(() => releaseAiSecretScan(jobId), 15 * 60 * 1000);
    timer.unref?.();
    aiSecretScans.set(String(jobId), { tabId, salt, filePath: expectedPath, timer });
    const page = new AiSecretResultReader(expectedPath).page(0, MAX_PAGE_SIZE);
    const { resultStorePath, ...safeResult } = result;
    return { ...safeResult, scanId: String(jobId), findings: page.findings, page };
  };
  process.once("exit", () => {
    for (const scanId of [...aiSecretScans.keys()]) releaseAiSecretScan(scanId);
  });

  const normalizeAiSecretRequest = ({ tabId, mode, salt } = {}) => {
    const m = _tabMeta.get(tabId);
    if (!m || typeof m.sourceFormat !== "string" || !m.sourceFormat.startsWith("ai-history-")) {
      return { error: "This tab is not an AI history timeline." };
    }
    const normalizedSalt = salt != null && String(salt).trim()
      ? String(salt).slice(0, 256)
      : crypto.randomBytes(16).toString("hex");
    return { tabId, options: { mode: mode === "deep" ? "deep" : "quick", salt: normalizedSalt } };
  };

  const startAiSecretScan = (request, notify = true) => {
    const normalized = normalizeAiSecretRequest(request);
    if (normalized.error) return normalized;
    const { tabId, options } = normalized;
    if (!startAnalyzerJob) {
      return { result: db.analyzeAiHistory(tabId, {
        ...options,
        progressCb: (p) => safeSend("analysis-progress", { phase: "ai-secrets", ...p }),
      }) };
    }
    const { jobId, promise } = startAnalyzerJob("analyzeAiHistory", { tabId, options }, {
      metadata: { feature: "aiSecretHunt" },
      concurrencyKey: "ai-secret-hunt",
      maxConcurrent: 1,
      retainResult: false,
    });
    const completion = promise.then((result) => registerAiSecretScan(jobId, tabId, options.salt, result));
    if (notify) {
      completion
        .then((result) => safeSend("ai-secret-scan-complete", { jobId, result }))
        .catch((err) => {
          try { removeStore(resultPathForJob(jobId)); } catch {}
          safeSend("ai-secret-scan-complete", {
            jobId,
            error: err?.message || "AI Secret Hunt failed",
            cancelled: !!err?.cancelled || /cancelled/i.test(String(err?.message || "")),
          });
        });
    }
    return { jobId, completion };
  };

  safeHandle("start-ai-secret-scan", (event, request) => {
    const started = startAiSecretScan(request, true);
    if (started.error || started.result) return started;
    return { jobId: started.jobId };
  });

  // Backward-compatible invoke path. It is still secure and bounded, while the current UI uses
  // start-ai-secret-scan so Cancel is available immediately.
  safeHandle("analyze-ai-history", async (event, request) => {
    const started = startAiSecretScan(request, false);
    if (started.error) return started;
    if (started.result) return started.result;
    try {
      return await started.completion;
    } catch (err) {
      try { removeStore(resultPathForJob(started.jobId)); } catch {}
      throw err;
    }
  });

  safeHandle("get-ai-secret-results-page", (event, { scanId, offset, limit } = {}) => {
    const entry = aiSecretScans.get(String(scanId || ""));
    if (!entry) return { error: "AI Secret scan results have expired." };
    return new AiSecretResultReader(entry.filePath).page(offset, limit);
  });

  safeHandle("reveal-ai-secret", (event, { scanId, findingId } = {}) => {
    const entry = aiSecretScans.get(String(scanId || ""));
    if (!entry) return { error: "AI Secret scan results have expired." };
    const finding = new AiSecretResultReader(entry.filePath).get(findingId);
    if (!finding) return { error: "Finding not found." };
    const meta = db.databases?.get?.(entry.tabId);
    const allowedFields = new Set(["FullText", "Summary", "ToolInput", "ToolCommand", "ToolDescription"]);
    if (!meta?.db || !meta?.colMap || !allowedFields.has(finding.evidenceField)) {
      return { error: "Source evidence is unavailable for this finding." };
    }
    const physical = meta.colMap[finding.evidenceField];
    const rowId = Number(finding.rowId);
    const start = Number(finding.startOffset);
    const end = Number(finding.endOffset);
    if (!physical || !Number.isInteger(rowId) || rowId < 1 || !Number.isInteger(start)
      || !Number.isInteger(end) || start < 0 || end <= start || end - start > 16 * 1024) {
      return { error: "Finding evidence coordinates are invalid." };
    }
    const quotedColumn = `"${String(physical).replace(/"/g, '""')}"`;
    const source = meta.db.prepare(`SELECT ${quotedColumn} AS value FROM data WHERE rowid = ?`).get(rowId);
    const text = source?.value != null ? String(source.value) : "";
    const value = text.slice(start, end);
    if (!value || fingerprint(value, entry.salt) !== finding.fingerprint) {
      return { error: "Source evidence changed or no longer matches this finding." };
    }
    return { findingId: String(finding.findingId), value };
  });

  safeHandle("release-ai-secret-scan", (event, { scanId } = {}) => ({ ok: releaseAiSecretScan(scanId) }));

  // USN Journal Analysis
  safeHandle("analyze-usn-journal", (event, { tabId, startTime, endTime, analyses, pathFilter, mftTabId }) => {
    return analyze(
      "analyzeUsnJournal",
      { tabId, options: { startTime, endTime, analyses, pathFilter, mftTabId } },
      () => db.analyzeUsnJournal(tabId, { startTime, endTime, analyses, pathFilter, mftTabId })
    );
  });

  // IOC Matching
  safeHandle("match-iocs", (event, { tabId, iocPatterns, batchSize }) => {
    return analyze(
      "matchIocs",
      { tabId, options: { iocPatterns, batchSize: batchSize || 200 } },
      () => db.matchIocs(tabId, iocPatterns, batchSize || 200)
    );
  });

};
