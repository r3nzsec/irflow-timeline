/**
 * ai-history/db-sink.js — shared row→SQLite sink for AI history imports.
 *
 * Both the single-tool import (parseAiHistoryImport) and the merged profile/triage scan
 * (extractMergedAiHistoryRootsToDb) stream extracted rows through these helpers so the two
 * paths dedupe, slim, batch, and number rows identically. Keeping this in one place is what
 * lets the single-import path stream instead of materializing the whole corpus in heap.
 */

const { AI_HISTORY_DB_OMIT_FULLTEXT } = require("./schema");
const { sortAndNumberRows, dedupeAiHistoryRows, aiHistoryDedupeKey } = require("./row-utils");

/** Rows per SQLite insert during streaming (keeps peak heap flat). */
const AI_HISTORY_DB_BATCH = 5000;
/** Safety cap so a pathological collection can't OOM the worker (overridable via options.maxRows). */
const MAX_AI_HISTORY_ROWS = 3_000_000;

/**
 * Drop FullText before insert for the merged streamed path (DB stays lean; Summary is the preview).
 * The single-tool path passes keepFullText=true so opening one tool's folder still stores the full
 * message body — the divergence is now an explicit, documented parameter rather than an accident.
 */
function slimAiHistoryRowForDb(row, keepFullText = false, maxFullTextChars = 0) {
  if (!row) return row;
  if (!keepFullText && AI_HISTORY_DB_OMIT_FULLTEXT) {
    if (!row.FullText) return row;
    return { ...row, FullText: "" };
  }
  if (maxFullTextChars > 0 && row.FullText && row.FullText.length > maxFullTextChars) {
    const dropped = row.FullText.length - maxFullTextChars;
    return {
      ...row,
      FullText: `${row.FullText.slice(0, maxFullTextChars)}\n…[truncated ${dropped} chars for merged import]`,
    };
  }
  return row;
}

/**
 * Dedupe (within the supplied set), sort, cap to the remaining row budget, slim, and stamp a
 * contiguous RecordId. Pass a whole SOURCE's rows (not a single flush batch) so the
 * history.jsonl↔session collapse in dedupeAiHistoryRows can actually fire.
 * @param {object} [opts] { keepFullText?: boolean, maxFullTextChars?: number,
 *   stats?: { fullTextTruncated: number } } — `stats.fullTextTruncated` is incremented per row
 *   whose FullText was cut to `maxFullTextChars`, so the import notice can say so.
 */
function prepareChunkRowsForDb(chunk, recordIdStart, maxRows, totalWritten, opts = {}) {
  const keepFullText = !!opts.keepFullText;
  const maxFullTextChars = Number(opts.maxFullTextChars) > 0 ? Number(opts.maxFullTextChars) : 0;
  let rows = sortAndNumberRows(dedupeAiHistoryRows(chunk, { crossTool: false }));
  const remaining = maxRows - totalWritten;
  if (rows.length > remaining) rows = rows.slice(0, Math.max(0, remaining));
  for (let i = 0; i < rows.length; i++) {
    const before = rows[i].FullText ? rows[i].FullText.length : 0;
    rows[i] = slimAiHistoryRowForDb(rows[i], keepFullText, maxFullTextChars);
    if (opts.stats && keepFullText && maxFullTextChars > 0 && before > maxFullTextChars) {
      opts.stats.fullTextTruncated = (opts.stats.fullTextTruncated || 0) + 1;
    }
    rows[i].RecordId = String(recordIdStart + i);
  }
  return rows;
}

function writeAiHistoryRowsToDb(db, tabId, headers, rows, checkAbort = () => {}) {
  for (let i = 0; i < rows.length; i += AI_HISTORY_DB_BATCH) {
    checkAbort();
    const batch = rows.slice(i, i + AI_HISTORY_DB_BATCH);
    db.insertBatchArrays(tabId, batch.map((r) => headers.map((h) => r[h] ?? "")));
  }
}

function streamedImportDedupeKey(row) {
  if (!row || !String(row.SourceFile || "").trim()) return "";
  return aiHistoryDedupeKey(row);
}

function filterAlreadySeenStreamedRows(rows, seenKeys) {
  if (!seenKeys || !rows?.length) return { rows: rows || [], dropped: 0 };
  const out = [];
  let dropped = 0;
  for (const row of rows) {
    const key = streamedImportDedupeKey(row);
    if (key && seenKeys.has(key)) {
      dropped += 1;
      continue;
    }
    if (key) seenKeys.add(key);
    out.push(row);
  }
  return { rows: out, dropped };
}

/**
 * Bounded per-source accumulator. Collect a source's emitted batches up to the remaining global
 * row budget, then flush once so dedupe sees the whole source. Capping the buffer to the budget
 * means a single pathological source cannot materialize unbounded rows in heap.
 */
function makeSourceAccumulator(maxRows) {
  let buf = [];
  let truncated = false;
  return {
    add(batch, totalWritten) {
      if (!batch || !batch.length) return;
      const room = maxRows - totalWritten - buf.length;
      if (room <= 0) { truncated = true; return; }
      if (batch.length > room) {
        for (let i = 0; i < room; i++) buf.push(batch[i]);
        truncated = true;
      } else {
        for (const r of batch) buf.push(r);
      }
    },
    get rows() { return buf; },
    get truncated() { return truncated; },
    reset() { buf = []; truncated = false; },
  };
}

module.exports = {
  AI_HISTORY_DB_BATCH,
  MAX_AI_HISTORY_ROWS,
  slimAiHistoryRowForDb,
  prepareChunkRowsForDb,
  writeAiHistoryRowsToDb,
  streamedImportDedupeKey,
  filterAlreadySeenStreamedRows,
  makeSourceAccumulator,
};
