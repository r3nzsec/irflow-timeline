/**
 * EventID / Channel indexes for JS Sigma SQL pre-filters on large imported tabs.
 *
 * With the DuckDB engine there is nothing to build: DuckDB filters these columns by scanning
 * them in parallel (with per-block min/max statistics); an index would only help single-row
 * lookups and would cost memory.
 */

const { dbg } = require("../../logger");

const SIGMA_FILTER_HEADER = /^(EventID|EventId|event_id|eventid|id|Channel|SourceName|Provider)$/i;

function isSigmaFilterColumn(original) {
  return SIGMA_FILTER_HEADER.test(String(original || ""));
}

/**
 * Kept for the scan's progress reporting: always reports that nothing was built.
 *
 * @param {object} meta - Tab DB metadata from TimelineDB
 * @returns {{ built: number, columns: string[] }}
 */
function ensureSigmaFilterIndexes(meta) {
  if (!meta?.db || meta.closed) return { built: 0, columns: [] };
  dbg("SIGMA", "No filter indexes needed: DuckDB scans EventID/Channel directly");
  return { built: 0, columns: [] };
}

module.exports = { ensureSigmaFilterIndexes, isSigmaFilterColumn };
