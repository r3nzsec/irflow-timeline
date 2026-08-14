/**
 * computer-history-worker.js — ChatGPT Computer History (Skysight) extract off the main thread.
 *
 * Deliberately does NOT reuse the ai-history db-sink. That sink's dedupe keys on
 * Tool/SessionId/Role/Summary, none of which exist in COMPUTER_HISTORY_COLUMNS — every row would
 * hash to the same empty key and collapse into one. Computer History rows are already deduped on
 * the session-global event id and sorted by the parser, so this worker only has to write them.
 *
 * Extraction is buffered rather than streamed: keystroke runs are coalesced globally after the
 * merged set is sorted (a composition interrupted by a 10-minute bucket rollover spans two files),
 * which needs the whole set in hand. Volume is bounded by design — the raw event stream is purged
 * at ~48h — and MAX_COMPUTER_HISTORY_ROWS caps a pathological collection.
 */

const { parentPort, workerData } = require("worker_threads");
const fs = require("fs");

const { sendWorkerResult } = require("./worker-result");
const TimelineDB = require("../db");
const { COMPUTER_HISTORY_COLUMNS } = require("../parsers/ai-history/computer-history-schema");
const { extractComputerHistoryDir } = require("../parsers/ai-history/computer-history");

/** Insert batch size — keeps peak heap flat while writing. */
const DB_BATCH = 5000;
/** Backstop so a pathological collection cannot OOM the worker. */
const MAX_COMPUTER_HISTORY_ROWS = 3_000_000;

let cancelled = false;

function checkAbort() {
  if (cancelled) throw Object.assign(new Error("Computer History extraction canceled"), { canceled: true });
}

function progress(patch) {
  parentPort.postMessage({
    type: "progress",
    progress: { jobId: workerData.jobId, ...patch },
  });
}

function cleanupDb(db, tabId) {
  if (!db) return;
  try { db.releaseTab(tabId); } catch { /* ignore */ }
  try { db.closeAll(); } catch { /* ignore */ }
}

/** Remove the worker's temp SQLite file (+ WAL/SHM) on paths the main process will not adopt. */
function unlinkTempDb(dbPath) {
  if (!dbPath) return;
  for (const suffix of ["", "-wal", "-shm"]) {
    try { fs.rmSync(`${dbPath}${suffix}`, { force: true }); } catch { /* ignore */ }
  }
}

/** Human-readable import notice from the parser's stats — surfaces coverage caveats in the UI. */
function buildImportNotice(stats, parseErrors) {
  if (!stats) return null;
  const lines = [];
  if (stats.segmentCount) {
    lines.push(`${stats.segmentCount} segment bucket(s) parsed from the raw event stream.`);
  }
  if (stats.summaryCount) {
    lines.push(`${stats.summaryCount} derived activity summar${stats.summaryCount === 1 ? "y" : "ies"} parsed `
      + "(LLM-generated interpretation — corroboration, not primary evidence).");
  }
  if (stats.gapCount) {
    lines.push(`${stats.gapCount} missing 10-minute bucket(s) flagged as "segment.gap". Check each `
      + "row's Activity: \"no activity\" means the event-id chain runs continuously across the hole "
      + "(an idle or paused host, NOT deletion), while \"ids unaccounted for\" is a lead worth "
      + "corroborating — neither is by itself a finding of tampering.");
  }
  if (stats.integritySegments) {
    const short = stats.integrityDelta < 0;
    lines.push(`INTEGRITY: ${stats.integritySegments} closed segment(s) do not reconcile against `
      + `their own metadata (net ${stats.integrityDelta} record(s)). `
      + (short
        ? "Records are missing from events.jsonl after the count was written — consistent with the "
          + "\"clear last 10 minutes / hour / day\" control, or a targeted deletion. See the "
          + "\"Record Count Short (derived)\" rows."
        : "More records are present than declared. See the \"Record Count Over (derived)\" rows."));
  }
  if (stats.recoveredCount) {
    lines.push(`${stats.recoveredCount} deleted activity summar`
      + `${stats.recoveredCount === 1 ? "y was" : "ies were"} recovered from the memories git `
      + "repository. Recovery proves the summary existed and when it was removed; it does not make "
      + "the summary itself primary evidence — it is still LLM-generated interpretation.");
  }
  if (stats.featureStateCount) {
    lines.push("Feature-state rows (Configuration) record what the recorder was permitted to "
      + "observe. Check the app-approvals row before reading silence for an app as inactivity.");
  }
  if (stats.accountCount > 1) {
    lines.push(`ATTRIBUTION: ${stats.accountCount} ChatGPT accounts have been used on this host `
      + "(one account-scoped preference file each). Do not attribute the whole timeline to a single "
      + "account without checking which was active when.");
  }
  if (stats.identityCount) {
    lines.push("Identity rows state their own attribution strength. Only \"direct\" rows identify an "
      + "ACCOUNT; \"device-pseudonym\" rows are per-app install ids — several of them mean one "
      + "machine, not several — and \"vendor-side\" rows only resolve through OpenAI.");
  }
  if (stats.deletedThreadCount) {
    lines.push(`${stats.deletedThreadCount} Codex conversation(s) are marked deleted. Their ids are `
      + "dated from the UUIDv7 itself, so look at the event rows in the same window: the model "
      + "chosen and the text typed into a deleted conversation are often still recorded here.");
  }
  if (stats.suppressedTotal) {
    lines.push(`${stats.suppressedTotal} event(s) were recorded as suppressed in segment metadata `
      + "and are absent from the stream. This metadata count is the only authoritative figure for "
      + "suppression.");
  }
  lines.push("EventId gaps are NOT a suppression count. The counter also advances for events that "
    + "are never persisted at all, so id gaps routinely exceed the metadata suppressed count by "
    + "orders of magnitude and must not be reported as withheld events.");
  if (parseErrors) lines.push(`${parseErrors} malformed JSONL line(s) skipped.`);
  lines.push("ScreenText is qualified by AxMode: \"fullTree\" rows carry a screen snapshot, while "
    + "\"diffFromPrevious\" rows carry ONLY what changed since the previous snapshot and understate "
    + "what was on screen. Most rows are diffs.");
  lines.push("EventClass is what the user DID (typing is Input everywhere); AppClass is WHERE it "
    + "happened (Terminal, Communication, Web). Filter typed content on EventClass = Input.");
  lines.push("FidelityTier is resolved once per application from its largest full-tree capture, so "
    + "it describes the app, not the individual row.");
  lines.push("Capture depth varies by app (FidelityTier). Tier 3 apps yield window metadata and "
    + "typed OUTBOUND text only — received message content is not captured, so a Tier 3 capture is "
    + "one side of a conversation and must not be presented as a conversation record.");
  return lines.join("\n");
}

async function runExtract() {
  const { target, tabId, dbPath, user, host, includeScreenText, screenTextMaxChars } = workerData;

  const db = new TimelineDB();
  try {
    checkAbort();
    db._dbPathHint = dbPath;

    progress({ phase: "scanning", percent: 5, statusDetail: "Locating Skysight artifacts…" });

    const rows = await extractComputerHistoryDir(
      target,
      { user: user || "", host: host || "" },
      {
        includeScreenText: includeScreenText !== false,
        screenTextMaxChars: screenTextMaxChars || undefined,
        checkAbort,
        onFileProgress: (fileIndex, fileCount, filePath) => {
          progress({
            phase: "extracting",
            percent: fileCount ? Math.min(90, 5 + Math.round((fileIndex / fileCount) * 85)) : 50,
            statusDetail: `Parsing ${fileIndex}/${fileCount}`,
            logLine: filePath,
            rowsSoFar: 0,
          });
        },
      },
    );

    checkAbort();

    if (!rows.length) {
      cleanupDb(db, tabId);
      unlinkTempDb(dbPath);
      sendWorkerResult(parentPort, {
        error: "No ChatGPT Computer History events found at this path. The feature is off by "
          + "default, and raw events are purged after ~48h — check ~/.codex/config.toml for "
          + '[plugins."computer-history@openai-bundled"] and the derived summaries under '
          + "~/.codex/memories/extensions/skysight/resources/.",
      });
      return;
    }

    const stats = rows._computerHistoryStats || null;
    const parseErrors = rows._parseErrors || 0;
    const capped = rows.length > MAX_COMPUTER_HISTORY_ROWS;
    const writeRows = capped ? rows.slice(0, MAX_COMPUTER_HISTORY_ROWS) : rows;

    const headers = [...COMPUTER_HISTORY_COLUMNS];
    db.createTab(tabId, headers);

    progress({
      phase: "loading",
      percent: 92,
      statusDetail: `Writing ${writeRows.length.toLocaleString()} rows…`,
      rowsSoFar: writeRows.length,
    });

    for (let i = 0; i < writeRows.length; i += DB_BATCH) {
      checkAbort();
      const batch = writeRows.slice(i, i + DB_BATCH);
      db.insertBatchArrays(tabId, batch.map((r) => headers.map((h) => r[h] ?? "")));
    }

    const notice = buildImportNotice(stats, parseErrors);
    const importNotice = capped
      ? `${notice}\nRow cap reached: ${MAX_COMPUTER_HISTORY_ROWS.toLocaleString()} of `
        + `${rows.length.toLocaleString()} rows imported.`
      : notice;

    progress({
      phase: "loading",
      percent: 98,
      statusDetail: `Finalizing ${writeRows.length.toLocaleString()} rows…`,
      rowsSoFar: writeRows.length,
    });

    const finalized = db.finalizeImport(tabId, { skipWalPromotion: true });
    const descriptor = db.getTabWorkerDescriptor(tabId);
    cleanupDb(db, tabId);

    sendWorkerResult(parentPort, {
      ...finalized,
      dbPath: descriptor.dbPath,
      isLargeFile: descriptor.isLargeFile,
      ftsReady: descriptor.ftsReady,
      indexesReady: descriptor.indexesReady,
      indexedCols: descriptor.indexedCols,
      importNotice,
      computerHistoryStats: stats,
      rowObjects: null,
    });
  } catch (err) {
    cleanupDb(db, tabId);
    unlinkTempDb(dbPath);
    if (err?.canceled) {
      progress({ phase: "cancelled", done: true });
      process.exit(1);
      return;
    }
    sendWorkerResult(parentPort, {
      error: err?.message || "Computer History extract failed",
      stack: err?.stack,
    });
  }
}

module.exports = { buildImportNotice, MAX_COMPUTER_HISTORY_ROWS };

// Only run when actually loaded as a worker; guarding lets the module be required in tests
// (parentPort is null on the main thread) to exercise the pure helpers.
if (parentPort) {
  parentPort.on("message", (message = {}) => {
    if (message?.type === "cancel") cancelled = true;
  });
  runExtract();
}
