const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawn } = require("child_process");
const { dbg } = require("../../../logger");
const { SigmaResultStore, createTempResultPath } = require("../result-store");
const { severityHistogram, sortMatchesBySeverity } = require("../match-utils");
const { validateEvtxScanRequest } = require("../scan-preflight");
const {
  findHayabusa,
  downloadHayabusa,
  getHayabusaStatus,
} = require("./binary-manager");

// Resolve the Hayabusa binary path, downloading only if there is genuinely no bundled
// copy. The download path must be the last resort because it fails on TLS-intercepting
// corporate proxies (common in DFIR/enterprise). Resolution order:
//   1. findHayabusa() — userData copy or bundled binary (covers 99% of installs)
//   2. Direct bundled binary at process.resourcesPath (covers packaged app edge cases
//      where the userData copy failed but the extraResource is still executable)
//   3. downloadHayabusa() — only if both above return nothing
async function resolveHayabusaBin(onProgress) {
  let binPath = findHayabusa();
  if (binPath) return binPath;
  try {
    const bundled = path.join(process.resourcesPath, "hayabusa",
      process.platform === "win32" ? "hayabusa.exe" : "hayabusa");
    if (fs.existsSync(bundled)) {
      try { fs.chmodSync(bundled, 0o755); } catch {}
      return bundled;
    }
  } catch {}
  onProgress?.({ phase: "installing", text: "Downloading Hayabusa..." });
  return downloadHayabusa(onProgress);
}
const {
  createScanOutputPaths,
  buildScanCommand,
  buildGenericCommand,
} = require("./command-builder");
const {
  createHayabusaProgressParser,
  ruleLoadDiagnostics,
} = require("./progress-parser");
const {
  parseCsvFile,
  extractDfirKvFields,
  parseHayabusaCsv,
  parseHayabusaJsonl,
} = require("./output-parser");
// Subprocess lifecycle + cancellation live in scan-process.js (no native deps,
// so they're independently unit-testable). Re-exported below for compatibility.
const {
  _activeProcs,
  registerScanProc,
  unregisterScanProc,
  isCancelled,
  throwIfCancelled,
  cancelScan,
  runScanProcess,
  isAbnormalExit,
} = require("./scan-process");

function findEvtxFiles(dirPath) {
  const results = [];
  const walk = (dir) => {
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else if (/\.evtx$/i.test(entry.name)) {
          try {
            const stat = fs.statSync(full);
            if (stat.size > 0) results.push({ path: full, name: entry.name, size: stat.size });
          } catch {}
        }
      }
    } catch {}
  };
  walk(dirPath);
  results.sort((a, b) => a.name.localeCompare(b.name));
  return results;
}

function cancelledScanResult({ evtxFiles, totalBytes }) {
  return {
    matches: [],
    eventRows: [],
    cancelled: true,
    stats: { evtxFiles: evtxFiles.length, evtxTotalBytes: totalBytes, format: "Hayabusa" },
    errors: ["Scan cancelled"],
    warnings: [],
    evtxFiles: evtxFiles.map((file) => ({ name: file.name, size: file.size })),
  };
}

function cleanupFiles(files) {
  for (const file of [...new Set(files.filter(Boolean))]) {
    try {
      if (fs.existsSync(file)) fs.unlinkSync(file);
    } catch {}
  }
}

function quoteArg(arg) {
  const text = String(arg ?? "");
  if (/^[A-Za-z0-9_/:=.,@%+-]+$/.test(text)) return text;
  return `"${text.replace(/(["\\$`])/g, "\\$1")}"`;
}

async function scanEvtxDirectory(dirPath, db, nextTabId, options = {}, onProgress) {
  const scanStartedAt = Date.now();
  const preflight = validateEvtxScanRequest(dirPath, options);
  const errors = [];
  const warnings = [...(preflight.warnings || [])];
  const scanJobId = options.scanJobId || null;

  if (!preflight.ok) {
    return {
      matches: [],
      eventRows: [],
      stats: { preflight: preflight.summary || {} },
      errors: preflight.errors,
      warnings: preflight.warnings,
      preflight,
      evtxFiles: [],
    };
  }

  if (scanJobId) registerScanProc(scanJobId, null, []);
  try {
    return await runRegisteredScan({
      dirPath,
      options,
      onProgress,
      scanStartedAt,
      errors,
      warnings,
      scanJobId,
    });
  } finally {
    if (scanJobId) unregisterScanProc(scanJobId);
  }
}

async function runRegisteredScan({ dirPath, options, onProgress, scanStartedAt, errors, warnings, scanJobId }) {
  onProgress?.({ phase: "discovering", text: "Scanning directory for EVTX files..." });
  const evtxFiles = findEvtxFiles(dirPath);
  if (evtxFiles.length === 0) {
    return { matches: [], eventRows: [], stats: {}, errors: ["No .evtx files found in directory"], warnings, evtxFiles: [] };
  }
  const totalBytes = evtxFiles.reduce((sum, file) => sum + file.size, 0);
  dbg("SIGMA-EVTX", `Found ${evtxFiles.length} EVTX files (${(totalBytes / 1048576).toFixed(1)} MB)`);

  let hayabusaPath = options.hayabusaPath || findHayabusa();
  if (!hayabusaPath) {
    onProgress?.({ phase: "installing", text: "First-time setup: downloading Hayabusa engine..." });
    try {
      hayabusaPath = await downloadHayabusa((phase, detail) => {
        onProgress?.({ phase: "installing", text: detail });
      });
    } catch (err) {
      return {
        matches: [],
        eventRows: [],
        stats: { evtxFiles: evtxFiles.length, evtxTotalBytes: totalBytes },
        errors: [`Failed to download Hayabusa: ${err.message}`],
        warnings,
        evtxFiles: evtxFiles.map((file) => ({ name: file.name, size: file.size })),
      };
    }
  }

  if (isCancelled(scanJobId)) {
    return cancelledScanResult({ evtxFiles, totalBytes });
  }

  dbg("SIGMA-EVTX", `Using Hayabusa: ${hayabusaPath}`);
  const outputMode = options.outputMode || "csv";
  const outputPaths = createScanOutputPaths(outputMode);
  const command = buildScanCommand({ dirPath, options, outputPaths, warnings });
  const { args, levels } = command;
  const { tmpOutput, tmpHtmlReport, actualOutput } = outputPaths;
  const commandLine = [hayabusaPath, ...args].map(quoteArg).join(" ");
  const hayabusaStatus = options.hayabusaStatus || getHayabusaStatus();

  onProgress?.({
    phase: "hayabusa-running",
    text: "Starting Hayabusa...",
    fileCount: evtxFiles.length,
    totalBytes,
    elapsed: 0,
    hayabusaStage: "starting",
    timeStr: "0s",
  });

  const startTime = Date.now();
  dbg("SIGMA-EVTX", `Executing: ${commandLine}`);
  const progressParser = createHayabusaProgressParser({ onProgress, evtxFiles, totalBytes, startTime });
  let cancelResult;
  try {
    cancelResult = await runScanProcess({
      hayabusaPath,
      args,
      cwd: path.dirname(hayabusaPath),
      scanJobId,
      progressParser,
      tempFiles: [tmpOutput, actualOutput, tmpHtmlReport],
      actualOutput,
    });
  } catch (err) {
    cleanupFiles([tmpOutput, actualOutput, tmpHtmlReport]);
    throw err;
  }

  if (cancelResult?.cancelled) {
    cleanupFiles([tmpOutput, actualOutput, tmpHtmlReport]);
    return cancelledScanResult({ evtxFiles, totalBytes });
  }

  // A non-zero exit / signal-kill that still left output means the scan crashed
  // mid-write: keep the partial results but flag them loudly (see partialResults
  // below) instead of silently treating a truncated CSV as a complete scan.
  const abnormalExit = isAbnormalExit(cancelResult);
  if (cancelResult.errorLines?.length) errors.push(...cancelResult.errorLines);

  if (!fs.existsSync(actualOutput)) {
    return {
      matches: [],
      eventRows: [],
      stats: { evtxFiles: evtxFiles.length, evtxTotalBytes: totalBytes, format: "Hayabusa" },
      errors: [...errors, "Hayabusa produced no output"],
      warnings,
      evtxFiles: evtxFiles.map((file) => ({ name: file.name, size: file.size })),
    };
  }

  const outputSize = fs.statSync(actualOutput).size;
  dbg("SIGMA-EVTX", `Hayabusa output: ${(outputSize / 1048576).toFixed(1)} MB`);
  onProgress?.({ phase: "parsing-results", text: `Parsing Hayabusa output (${(outputSize / 1048576).toFixed(1)} MB)...` });

  const resultStorePath = options.resultStorePath || createTempResultPath("tle-hayabusa-results");
  const resultStore = new SigmaResultStore({ dbPath: resultStorePath });
  let parsed;
  try {
    parsed = outputMode !== "csv"
      ? await parseHayabusaJsonl(actualOutput, levels, onProgress, scanJobId, {
        resultStore,
        previewLimit: options.previewLimit || 2000,
        throwIfCancelled,
      })
      : await parseHayabusaCsv(actualOutput, onProgress, scanJobId, {
        resultStore,
        previewLimit: options.previewLimit || 2000,
        throwIfCancelled,
      });
  } catch (err) {
    try { resultStore.close(); } catch {}
    SigmaResultStore.destroy(resultStorePath);
    if (err?.cancelled) {
      cleanupFiles([actualOutput, tmpOutput, tmpHtmlReport]);
      return cancelledScanResult({ evtxFiles, totalBytes });
    }
    throw err;
  }

  const { eventRows, ruleMatches, truncated } = parsed;
  const truncatedTail = !!parsed.truncatedTail;
  if (abnormalExit) {
    const how = cancelResult.signal
      ? `was terminated (signal ${cancelResult.signal})`
      : `exited abnormally (code ${cancelResult.exitCode})`;
    errors.push(`Hayabusa ${how} but left partial output — scan results may be incomplete or truncated.`);
  }
  if (truncatedTail) {
    warnings.push("Hayabusa output did not end with a complete record; the final result row may be truncated.");
  }
  let htmlReport = null;
  if (fs.existsSync(tmpHtmlReport)) {
    try { htmlReport = fs.readFileSync(tmpHtmlReport, "utf8"); } catch {}
  }
  cleanupFiles([actualOutput, tmpOutput, tmpHtmlReport]);

  onProgress?.({ phase: "done", text: "Finalizing results..." });

  const matches = [];
  for (const [, rm] of ruleMatches) {
    if (!levels.includes(rm.level)) continue;
    matches.push({
      ruleId: rm.ruleId || rm.title,
      ruleFile: rm.ruleFile || "",
      title: rm.title,
      level: rm.level,
      status: rm.status,
      description: rm.description,
      author: rm.author,
      category: rm.category,
      mitre: rm.mitre,
      tactics: rm.tactics,
      tags: rm.tags,
      falsepositives: rm.falsepositives,
      matchCount: rm.count,
      firstSeen: rm.firstTs,
      lastSeen: rm.lastTs,
      hosts: [...rm.hosts],
      sampleRows: rm.sampleRows,
      isCustom: false,
    });
  }
  sortMatchesBySeverity(matches);
  eventRows.sort((a, b) => (a.Timestamp || "").localeCompare(b.Timestamp || ""));

  const persistedSummary = resultStore.finalize({
    engine: "Hayabusa",
    sourceFormat: outputMode === "csv" ? "Hayabusa CSV" : "Hayabusa JSONL",
  });
  resultStore.close();

  const trueTotalMatches = matches.reduce((sum, match) => sum + (match.matchCount || 0), 0);
  const runtimeMs = Date.now() - scanStartedAt;

  // Explain empty results: surface Hayabusa's own reported rule counts so a bad
  // custom rules path / over-narrow filter doesn't read as a silent "no hits".
  const hbInfo = progressParser.getInfo();
  const rulesLoaded = hbInfo.totalRules || 0;
  const rulesAfterChannelFilter = hbInfo.rulesAfterFilter || 0;
  const ruleDiag = ruleLoadDiagnostics({
    rulesLoaded,
    rulesAfterFilter: rulesAfterChannelFilter,
    rulesPath: options.rulesPath || null,
    matchCount: matches.length,
  });
  if (ruleDiag.warnings.length) warnings.push(...ruleDiag.warnings);

  const stats = {
    totalRules: ruleMatches.size,
    matchedRules: matches.length,
    totalMatches: trueTotalMatches,
    rowsScanned: 0,
    bySeverity: severityHistogram(matches),
    format: "Hayabusa",
    evtxFiles: evtxFiles.length,
    evtxTotalRows: persistedSummary.rowCount,
    evtxTotalBytes: totalBytes,
    runtimeMs,
    // Rules Hayabusa actually loaded / kept after the channel filter (0 = unknown
    // or none). Lets the UI show "scanned with N rules" and explain empty results.
    rulesLoaded,
    rulesAfterChannelFilter,
    eventRowsCapped: false,
    eventRowCap: null,
    // Set when Hayabusa crashed/was killed mid-write or its output ended on a
    // partial record — the renderer should warn that hits may be undercounted.
    partialResults: abnormalExit || truncatedTail,
    exitCode: typeof cancelResult.exitCode === "number" ? cancelResult.exitCode : null,
    commandLine,
  };

  dbg("SIGMA-EVTX", `Done: ${persistedSummary.rowCount} events, ${matches.length} rules matched${truncated ? " (capped)" : ""}`);

  return {
    matches,
    eventRows,
    resultDbPath: persistedSummary.dbPath,
    resultHeaders: persistedSummary.headers,
    eventRowCount: persistedSummary.rowCount,
    stats,
    errors,
    warnings,
    evtxFiles: evtxFiles.map((file) => ({ name: file.name, size: file.size })),
    htmlReport,
    reproducibility: {
      engine: "Hayabusa",
      hayabusaVersion: hayabusaStatus?.version || null,
      hayabusaPath,
      commandLine,
      commandArgs: args,
      command: command.subcommand,
      outputMode: command.outputMode,
      profile: command.profile,
      minLevel: command.minLevel,
      statusFilter: command.statusFilter,
      levels,
    },
  };
}

async function runHayabusaCommand(subcommand, dirPath, extraArgs = [], onProgress) {
  const binPath = await resolveHayabusaBin(onProgress);

  const tmpBase = path.join(os.tmpdir(), `tle-hb-${subcommand}-${Date.now()}.csv`);
  const args = buildGenericCommand(subcommand, dirPath, tmpBase, extraArgs);

  onProgress?.({ phase: "running", text: `Running hayabusa ${subcommand}...` });
  dbg("HAYABUSA", `Executing: ${binPath} ${args.join(" ")}`);

  await new Promise((resolve, reject) => {
    const proc = spawn(binPath, args, {
      cwd: path.dirname(binPath),
      stdio: ["ignore", "ignore", "pipe"],
      timeout: 120000,
    });
    proc.stderr.on("data", () => {});
    proc.on("close", (code) => {
      if (code !== 0 && !fs.existsSync(tmpBase)) {
        const outDir = path.dirname(tmpBase);
        const base = path.basename(tmpBase);
        const found = fs.readdirSync(outDir).filter((file) => file.startsWith(base.replace(".csv", "")));
        if (found.length === 0) {
          reject(new Error(`hayabusa ${subcommand} failed (exit code ${code})`));
          return;
        }
      }
      resolve();
    });
    proc.on("error", (err) => reject(new Error(`Failed to start Hayabusa: ${err.message}`)));
  });

  const outDir = path.dirname(tmpBase);
  const basePrefix = path.basename(tmpBase).replace(".csv", "");
  const outputFiles = fs.readdirSync(outDir).filter((file) => file.startsWith(basePrefix) && file.endsWith(".csv"));
  const result = {};

  for (const fileName of outputFiles) {
    const filePath = path.join(outDir, fileName);
    const suffix = fileName.replace(basePrefix, "").replace(".csv", "").replace(/^-/, "") || "default";
    try {
      result[suffix] = parseCsvFile(filePath);
    } catch {}
    try { fs.unlinkSync(filePath); } catch {}
  }

  if (fs.existsSync(tmpBase)) {
    try {
      result.default = parseCsvFile(tmpBase);
    } catch {}
    try { fs.unlinkSync(tmpBase); } catch {}
  }

  return { files: result, errors: [] };
}

async function runLogonSummary(dirPath, onProgress) {
  const { files, errors } = await runHayabusaCommand("logon-summary", dirPath, [], onProgress);
  return {
    successful: files.successful || [],
    failed: files.failed || [],
    errors,
  };
}

async function runComputerMetrics(dirPath, onProgress) {
  const { files, errors } = await runHayabusaCommand("computer-metrics", dirPath, [], onProgress);
  return { rows: files.default || [], errors };
}

async function runEidMetrics(dirPath, onProgress) {
  const { files, errors } = await runHayabusaCommand("eid-metrics", dirPath, [], onProgress);
  return { rows: files.default || [], errors };
}

async function runLogMetrics(dirPath, onProgress) {
  const { files, errors } = await runHayabusaCommand("log-metrics", dirPath, [], onProgress);
  return { rows: files.default || [], errors };
}

async function runSearch(dirPath, searchOpts = {}, onProgress) {
  const { keywords, regex, andLogic, ignoreCase = true, fieldFilter, timelineStart, timelineEnd } = searchOpts;

  if (!keywords && !regex) return { rows: [], totalFindings: 0, errors: ["No keywords or regex specified"] };

  const extraArgs = [];
  if (keywords) {
    const kwList = Array.isArray(keywords) ? keywords : [keywords];
    for (const keyword of kwList) extraArgs.push("-k", keyword);
  }
  if (regex) extraArgs.push("-r", regex);
  if (andLogic) extraArgs.push("-a");
  if (ignoreCase) extraArgs.push("-i");
  if (fieldFilter) extraArgs.push("-F", fieldFilter);
  if (timelineStart) extraArgs.push("--timeline-start", timelineStart);
  if (timelineEnd) extraArgs.push("--timeline-end", timelineEnd);

  const { files, errors } = await runHayabusaCommand("search", dirPath, extraArgs, onProgress);
  const rows = files.default || [];
  for (const row of rows) {
    extractDfirKvFields(row, row.AllFieldInfo);
  }

  return { rows, totalFindings: rows.length, errors };
}

async function runPivotKeywords(dirPath, onProgress) {
  const binPath = await resolveHayabusaBin(onProgress);

  const tmpBase = path.join(os.tmpdir(), `tle-hb-pivot-${Date.now()}.csv`);
  const pivotArgs = ["pivot-keywords-list", "-d", dirPath, "-o", tmpBase, "-q", "--no-wizard", "-m", "high"];

  onProgress?.({ phase: "running", text: "Extracting pivot keywords..." });
  dbg("HAYABUSA", "Executing pivot-keywords-list");

  await new Promise((resolve, reject) => {
    const proc = spawn(binPath, pivotArgs, {
      cwd: path.dirname(binPath),
      stdio: ["ignore", "ignore", "pipe"],
      timeout: 120000,
    });
    proc.stderr.on("data", () => {});
    proc.on("close", () => resolve());
    proc.on("error", (err) => reject(err));
  });

  const outDir = path.dirname(tmpBase);
  const basePrefix = path.basename(tmpBase);
  const outputFiles = fs.readdirSync(outDir).filter((file) => file.startsWith(basePrefix));

  const categories = {};
  for (const fileName of outputFiles) {
    const filePath = path.join(outDir, fileName);
    try {
      const content = fs.readFileSync(filePath, "utf8");
      const lines = content.split("\n").map((line) => line.trim()).filter(Boolean);
      const header = lines[0] || "";
      const catMatch = header.match(/^([^:]+):/);
      const catName = catMatch ? catMatch[1].trim() : fileName.replace(basePrefix, "").replace(/^-/, "").replace(/\.txt$/, "");
      const values = lines.slice(1).filter((value) => value && value !== "-");
      if (values.length > 0) categories[catName] = values;
    } catch {}
    try { fs.unlinkSync(filePath); } catch {}
  }

  return { categories, errors: [] };
}

async function runExtractBase64(dirPath, onProgress) {
  const { files, errors } = await runHayabusaCommand("extract-base64", dirPath, [], onProgress);
  return { rows: files.default || [], errors };
}

module.exports = {
  scanEvtxDirectory,
  findEvtxFiles,
  runHayabusaCommand,
  runLogonSummary,
  runComputerMetrics,
  runEidMetrics,
  runLogMetrics,
  runSearch,
  runPivotKeywords,
  runExtractBase64,
  cancelScan,
  _activeProcs,
  _throwIfCancelledForTest: throwIfCancelled,
};
