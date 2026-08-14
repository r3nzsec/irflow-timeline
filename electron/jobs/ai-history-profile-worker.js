/**
 * ai-history-profile-worker.js — merged AI profile extract off the main thread.
 * Streams each source into SQLite without holding the full merged row set in memory.
 */

const { parentPort, workerData } = require("worker_threads");
const { sendWorkerResult } = require("./worker-result");
const fs = require("fs");
const TimelineDB = require("../db");
const { AI_HISTORY_COLUMNS } = require("../parsers/ai-history/schema");
const { extractMergedAiHistoryRootsToDb } = require("../parsers/ai-history/profile-scan");
const { buildCopilotEmptyExtractError } = require("../parsers/ai-history/import-meta");

let cancelled = false;

function checkAbort() {
  if (cancelled) throw Object.assign(new Error("AI history extraction canceled"), { canceled: true });
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

/**
 * Remove the worker's temp SQLite file (+ WAL/SHM siblings). Call ONLY on paths where the main
 * process will not adopt the file (cancel / error / empty result): releaseTab + closeAll close
 * the connection but never unlink, so every failed or cancelled extract would otherwise orphan a
 * temp DB in os.tmpdir() (up to the 3M-row cap in size). The success path hands dbPath off intact.
 */
function unlinkTempDb(dbPath) {
  if (!dbPath) return;
  for (const suffix of ["", "-wal", "-shm"]) {
    try { fs.rmSync(`${dbPath}${suffix}`, { force: true }); } catch { /* ignore */ }
  }
}

async function runExtract() {
  const {
    roots,
    includeSubagents,
    user,
    host,
    dbPath,
    tabId,
  } = workerData;

  const db = new TimelineDB();
  try {
    checkAbort();
    db._dbPathHint = dbPath;

    const {
      rowCount,
      importNotice,
      importMeta,
      failures,
    } = await extractMergedAiHistoryRootsToDb(
      db,
      tabId,
      roots || [],
      { user: user || "", host: host || "" },
      {
        includeSubagents: !!includeSubagents,
        headers: AI_HISTORY_COLUMNS,
        onProgress: (p) => progress(p),
        checkAbort,
      },
    );

    if (!rowCount) {
      cleanupDb(db, tabId);
      unlinkTempDb(dbPath);
      const copilotDetail = buildCopilotEmptyExtractError(importMeta?.copilot);
      sendWorkerResult(parentPort, {
        error: copilotDetail
          || (failures?.length
            ? failures.map((f) => `${f.label}: ${f.error}`).join("; ")
            : "Sources were found but contained no message rows."),
        failures: failures || [],
        importMeta: importMeta || null,
      });
      return;
    }

    progress({
      phase: "loading",
      percent: 98,
      statusDetail: `Finalizing ${rowCount.toLocaleString()} rows…`,
      rowsSoFar: rowCount,
    });

    const finalized = db.finalizeImport(tabId, { skipWalPromotion: true });
    progress({
      phase: "loading",
      percent: 99,
      statusDetail: `Handing off ${rowCount.toLocaleString()} rows…`,
      rowsSoFar: rowCount,
    });
    const descriptor = db.getTabWorkerDescriptor(tabId);
    cleanupDb(db, tabId);

    sendWorkerResult(parentPort, {
      ...finalized,
      dbPath: descriptor.dbPath,
      isLargeFile: descriptor.isLargeFile,
      ftsReady: descriptor.ftsReady,
      indexesReady: descriptor.indexesReady,
      indexedCols: descriptor.indexedCols,
      importNotice: importNotice || null,
      failures: failures || [],
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
    sendWorkerResult(parentPort, { error: err?.message || "AI history profile extract failed", stack: err?.stack });
  }
}

// Only run when actually loaded as a worker; guarding lets the module be required in tests
// (parentPort is null on the main thread) to exercise the pure helpers.
if (parentPort) {
  parentPort.on("message", (message = {}) => {
    if (message?.type === "cancel") cancelled = true;
  });
  runExtract();
}

module.exports = { unlinkTempDb };
