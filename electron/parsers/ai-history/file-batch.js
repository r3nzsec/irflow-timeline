/**
 * parsers/ai-history/file-batch.js — bounded-concurrency file processing for the AI-history extractors.
 *
 * The per-tool extractors read many session/transcript/rollout files. Reading them strictly serially
 * (one `await` per file) makes a power user's 50+ JSONL files take O(n) wall-clock. The final timeline
 * is sorted (by the DB / finalizeAiHistoryRows) and de-duplicated at the sink (streamedSeenKeys), so the
 * ORDER in which files are read does NOT affect the output — files can be read in small concurrent
 * batches (~6) for a throughput win while peak memory stays bounded to one batch's rows.
 */

const DEFAULT_FILE_CONCURRENCY = 6;

/**
 * Process `items` through `process(item)` in bounded-concurrency batches.
 *
 * For each completed item — in stable batch order — calls `onProgress(item)` then `onRows(rows, item)`
 * on success, or `onError(err, item)` on failure (the item is skipped; a single bad file never aborts
 * its batch). Yields to the event loop between batches and checks `checkAbort` there, so cancellation
 * stays responsive. `process` may return rows synchronously or as a promise.
 *
 * @param {Array} items
 * @param {{ concurrency?: number, process: Function, onRows?: Function, onProgress?: Function,
 *           onError?: Function, checkAbort?: Function }} opts
 */
async function processFilesConcurrently(items, opts = {}) {
  const {
    concurrency = DEFAULT_FILE_CONCURRENCY,
    process: processItem, onRows, onProgress, onError, checkAbort,
  } = opts;
  const step = Math.max(1, concurrency | 0);

  for (let i = 0; i < items.length; i += step) {
    if (typeof checkAbort === "function") checkAbort();
    const slice = items.slice(i, i + step);
    const results = await Promise.all(slice.map(async (item) => {
      try { return { ok: true, rows: await processItem(item), item }; }
      catch (err) { return { ok: false, err, item }; }
    }));
    for (const r of results) {
      if (!r.ok && (r.err?.canceled || r.err?.cancelled)) throw r.err;
      if (typeof onProgress === "function") onProgress(r.item);
      if (r.ok) { if (typeof onRows === "function") onRows(r.rows, r.item); }
      else if (typeof onError === "function") onError(r.err, r.item);
    }
    if (typeof checkAbort === "function") checkAbort();
    await new Promise((res) => setImmediate(res)); // yield between batches (abort + responsiveness)
  }
}

module.exports = { processFilesConcurrently, DEFAULT_FILE_CONCURRENCY };
