/** Versioned per-source completion ledger for AI artifact extraction. */

const fs = require("fs");
const path = require("path");
const { createPerformanceMeter } = require("./performance-metrics");

const SOURCE_COVERAGE_VERSION = 1;
const SOURCE_STATUSES = Object.freeze([
  "parsed",
  "empty",
  "partial",
  "malformed",
  "unsupported",
  "excluded",
  "unavailable",
]);

function normalizedSource(sourceFile) {
  if (!sourceFile) return "";
  try { return path.resolve(String(sourceFile)); } catch { return String(sourceFile); }
}

function sqliteFamily(files) {
  const out = [];
  for (const filePath of files || []) {
    out.push(filePath);
    for (const suffix of ["-wal", "-shm", "-journal"]) {
      if (fs.existsSync(`${filePath}${suffix}`)) out.push(`${filePath}${suffix}`);
    }
  }
  return out;
}

function walkMatching(rootDir, predicate, options = {}) {
  const out = [];
  const maxDepth = options.maxDepth ?? 12;
  const maxFiles = options.maxFiles ?? 100000;
  const skip = options.skip || (() => false);
  const stack = [{ dir: rootDir, depth: 0 }];
  while (stack.length) {
    const { dir, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!entry.isSymbolicLink() && depth < maxDepth && !skip(full)) stack.push({ dir: full, depth: depth + 1 });
        continue;
      }
      if (entry.isFile() && predicate(full, entry)) out.push(full);
      if (out.length >= maxFiles) return out.sort();
    }
  }
  return out.sort();
}

function listCodexEvidenceSources(target, options = {}) {
  const { listRolloutFiles } = require("./codex");
  const { listCodexStateSqliteFiles } = require("./codex-state-sqlite");
  const { listThreadHistoryDbFiles } = require("./codex-thread-history-sqlite");
  const aux = require("./codex-aux-sqlite");
  const direct = ["history.jsonl", "session_index.jsonl", "config.toml", "hooks.json", ".codex-global-state.json", "transcription-history.jsonl"]
    .map((name) => path.join(target, name)).filter((p) => fs.existsSync(p));
  const auxDbs = [
    path.join(target, ...aux.CODEX_DEV_DB_REL),
    ...aux.listCodexLogsDbFiles(target),
    ...aux.listVersionedDbFiles(target, aux.MEMORIES_DB_RE),
    ...aux.listVersionedDbFiles(target, aux.GOALS_DB_RE),
    ...aux.listVersionedDbFiles(target, aux.QUEUE_DB_RE),
  ].filter((p) => fs.existsSync(p));
  const local = walkMatching(target, (filePath) => {
    const rel = path.relative(target, filePath).replace(/\\/g, "/");
    return /^(?:rules\/.*\.rules|shell_snapshots\/.*\.sh|dictation-history\/.*|ambient-suggestions\/.*\/ambient-suggestions\.json|memories\/(?:MEMORY\.md|raw_memories\.md|memory_summary\.md|rollout_summaries\/.*\.md|extensions\/ad_hoc\/.*))$/i.test(rel);
  }, {
    maxDepth: 8,
    skip: (p) => /(?:^|[\\/])(?:sessions|archived_sessions)(?:[\\/]|$)/.test(p),
  });
  const context = require("./codex-context").listCodexContextFiles(target, options).files;
  return [
    ...direct,
    ...listRolloutFiles(target, options),
    ...sqliteFamily([...listCodexStateSqliteFiles(target), ...listThreadHistoryDbFiles(target), ...auxDbs]),
    ...local,
    ...context,
  ];
}

class SourceCoverageTracker {
  constructor(tool, sources = []) {
    this.tool = tool;
    this.entries = new Map();
    for (const source of sources) this.discover(source);
  }

  discover(sourceFile, details = {}) {
    const source = normalizedSource(sourceFile);
    if (!source) return null;
    const existing = this.entries.get(source);
    if (existing) return existing;
    let sourceMetadata = {};
    try {
      const st = fs.statSync(source);
      sourceMetadata = {
        sizeBytes: st.size,
        modifiedAtMs: Math.trunc(st.mtimeMs),
      };
    } catch { /* acquired source may already be unavailable */ }
    const entry = {
      version: SOURCE_COVERAGE_VERSION,
      tool: this.tool,
      sourceFile: source,
      status: "empty",
      reason: "eligible source produced no supported records",
      rows: 0,
      errors: 0,
      skipped: 0,
      ...sourceMetadata,
      ...details,
    };
    this.entries.set(source, entry);
    return entry;
  }

  observeRows(rows) {
    for (const row of rows || []) {
      const entry = this.discover(row?.SourceFile || "", { discoveredFromRow: true });
      if (!entry) continue;
      entry.rows += 1;
      entry.status = "parsed";
      entry.reason = "supported records emitted";
    }
  }

  mark(sourceFile, status, reason, counters = {}) {
    if (!SOURCE_STATUSES.includes(status)) throw new Error(`Invalid AI source coverage status: ${status}`);
    const entry = this.discover(sourceFile);
    if (!entry) return;
    Object.assign(entry, counters, { status, reason: reason || "" });
  }

  markUnscopedErrors(sourceRoot, errors) {
    if (!(Number(errors) > 0)) return;
    this.mark(sourceRoot, "partial", "parser reported record errors that could not be assigned to one source", {
      errors: Number(errors),
    });
  }

  report() {
    return [...this.entries.values()].sort((a, b) => a.sourceFile.localeCompare(b.sourceFile));
  }
}

function inventoryAiHistorySources(tool, target, options = {}) {
  if (!target) return [];
  try { if (fs.statSync(target).isFile()) return [target]; } catch { return []; }
  try {
    if (tool === "claude-code") {
      const { listSessionJsonlFiles } = require("./claude-code");
      const history = path.join(target, "history.jsonl");
      const context = require("./claude-code-context");
      const typed = ["settings.json", ".mcp.json"].map((name) => path.join(target, name)).filter((p) => fs.existsSync(p));
      return [
        ...(fs.existsSync(history) ? [history] : []),
        ...listSessionJsonlFiles(path.basename(target) === ".claude" ? path.join(target, "projects") : target, options),
        ...typed,
        ...context.listClaudeContextFiles(target, options).files,
      ];
    }
    if (tool === "codex") {
      return listCodexEvidenceSources(target, options);
    }
    if (tool === "grok-build") {
      const primary = require("./grok-build").listGrokDataFiles(target, options);
      const context = require("./grok-build-context").listGrokBuildContextFiles(target, options).files;
      const runtime = require("./grok-runtime");
      const runtimePaths = [
        runtime.findSessionSearchDb(target),
        path.join(target, runtime.ACTIVE_SESSIONS_FILE),
        path.join(target, ...runtime.UNIFIED_LOG_REL),
      ].filter((p) => p && fs.existsSync(p));
      return [...primary, ...context, ...sqliteFamily(runtimePaths.filter((p) => path.extname(p).toLowerCase() === ".sqlite")), ...runtimePaths];
    }
    if (tool === "grok-bot") {
      const { grokBotExtractTargets, listGrokBotDataFiles } = require("./grok-bot");
      return grokBotExtractTargets(target).flatMap((root) => listGrokBotDataFiles(root));
    }
    if (tool === "gemini-cli") {
      const gemini = require("./gemini-cli");
      return [...gemini.listGeminiDataFiles(target), ...gemini.listGeminiStateFiles(target)];
    }
    if (tool === "cursor") {
      const cursor = require("./cursor");
      const { listCursorComposerDbsWithStats } = require("./cursor-composer");
      const composer = listCursorComposerDbsWithStats(target, options.userDataDirs || [], options);
      const context = require("./cursor-context");
      return [
        ...cursor.listTranscriptJsonlFiles(path.join(target, "projects"), options),
        ...sqliteFamily(composer.eligiblePaths),
        ...context.directConfigFiles(target),
        ...context.listCursorContextFiles(target, options).files,
      ];
    }
  } catch {
    return [];
  }
  return [];
}

async function extractWithSourceCoverage(tool, target, attribution, options, extractor) {
  const inventory = Array.isArray(options?.sourceInventory)
    ? options.sourceInventory
    : inventoryAiHistorySources(tool, target, options);
  const tracker = new SourceCoverageTracker(tool, inventory);
  const parseStats = options?.parseStats || { errors: 0 };
  if (typeof options?.checkAbort === "function") parseStats.checkAbort = options.checkAbort;
  const meter = createPerformanceMeter({ tool, sourceCoverage: tracker.report() });
  const onExtractedRows = options?.onExtractedRows;
  const trackedOptions = {
    ...options,
    parseStats,
    ...(onExtractedRows ? {
      onExtractedRows(batch) {
        tracker.observeRows(batch);
        meter.observeRows(batch);
        onExtractedRows(batch);
      },
    } : {}),
  };
  let rows;
  try {
    rows = await extractor(target, attribution, trackedOptions);
  } catch (error) {
    meter.finish({ parseStats, canceled: !!(error?.canceled || error?.cancelled) });
    throw error;
  }
  tracker.observeRows(rows);
  meter.observeRows(rows);
  let scopedErrors = 0;
  for (const [sourceFile, stats] of Object.entries(parseStats.bySource || {})) {
    const entry = tracker.discover(sourceFile);
    const errors = Number(stats.errors || 0);
    scopedErrors += errors;
    if (errors > 0) {
      const status = entry.rows > 0 || Number(stats.parsedJsonLines || 0) > 0 ? "partial" : "malformed";
      const reasons = [
        stats.malformedLines ? `${stats.malformedLines} malformed line(s)` : "",
        stats.oversizedLines ? `${stats.oversizedLines} oversized line(s)` : "",
        stats.handlerErrors ? `${stats.handlerErrors} record handler error(s)` : "",
        stats.readErrors ? `${stats.readErrors} read error(s)` : "",
      ].filter(Boolean);
      tracker.mark(sourceFile, status, reasons.join(", ") || `${errors} parse error(s)`, {
        errors,
        oversizedLines: Number(stats.oversizedLines || 0),
        malformedLines: Number(stats.malformedLines || 0),
        handlerErrors: Number(stats.handlerErrors || 0),
        readErrors: Number(stats.readErrors || 0),
        physicalLines: Number(stats.physicalLines || 0),
      });
    }
  }
  tracker.markUnscopedErrors(target, Math.max(0, Number(parseStats.errors || rows?._parseErrors || 0) - scopedErrors));
  rows._sourceCoverage = tracker.report();
  rows._performance = meter.finish({ parseStats });
  return rows;
}

module.exports = {
  SOURCE_COVERAGE_VERSION,
  SOURCE_STATUSES,
  SourceCoverageTracker,
  normalizedSource,
  inventoryAiHistorySources,
  extractWithSourceCoverage,
};
