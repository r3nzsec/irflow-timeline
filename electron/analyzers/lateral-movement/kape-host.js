/**
 * lateral-movement/kape-host.js — KAPE Collection Host Detection
 *
 * When a KAPE triage EvtxECmd CSV is loaded, the overwhelming majority of events
 * will have the same Computer value — that's the machine the triage was collected from.
 *
 * This module auto-detects the collection host by querying the Computer column
 * distribution. The result is used to:
 *   1. Display the collection host in the LM modal config phase
 *   2. Boost the convention detector's confidence (the collection host's prefix
 *      is very likely the domain naming convention)
 *   3. Provide context for findings ("this host was the KAPE collection target")
 */

const { isHayabusaDataset, isChainsawDataset } = require("../evtx-utils");

/**
 * Detect the KAPE collection host from a tab's data.
 *
 * @param {object} meta - Database handle {db, headers, colMap}
 * @returns {{ collectionHost: string|null, confidence: string, hostDistribution: Array<{host, count, pct}>, format: string }}
 */
function detectKapeCollectionHost(meta) {
  if (!meta || !meta.db) return { collectionHost: null, confidence: "none", hostDistribution: [], format: null };

  const { db, headers } = meta;

  // Detect format
  const isEvtxECmd = headers.some(h => /^RemoteHost$/i.test(h)) && headers.some(h => /^PayloadData1$/i.test(h));
  const isHayabusa = isHayabusaDataset(meta);
  const isChainsaw = isChainsawDataset(meta);
  const isRawEvtx = !isEvtxECmd && !isHayabusa && !isChainsaw
    && headers.some(h => /^datetime$/i.test(h)) && headers.some(h => /^Provider$/i.test(h));

  const format = isEvtxECmd ? "EvtxECmd" : isHayabusa ? "Hayabusa" : isChainsaw ? "Chainsaw" : isRawEvtx ? "Raw EVTX" : "Unknown";

  // Find Computer column
  const computerCol = (() => {
    for (const pat of [/^Computer$/i, /^ComputerName$/i, /^computer_name$/i, /^Hostname$/i]) {
      const found = headers.find(h => pat.test(h));
      if (found && meta.colMap[found]) return meta.colMap[found];
    }
    return null;
  })();

  if (!computerCol) return { collectionHost: null, confidence: "none", hostDistribution: [], format };

  try {
    const rows = db.prepare(
      `SELECT ${computerCol} as host, COUNT(*) as cnt FROM data WHERE ${computerCol} IS NOT NULL AND ${computerCol} != '' GROUP BY ${computerCol} ORDER BY cnt DESC, host LIMIT 20`
    ).all();

    if (rows.length === 0) return { collectionHost: null, confidence: "none", hostDistribution: [], format };

    const total = rows.reduce((s, r) => s + r.cnt, 0);
    const hostDistribution = rows.map(r => ({
      host: (r.host || "").toString().trim(),
      count: r.cnt,
      pct: total > 0 ? Math.round((r.cnt / total) * 100) : 0,
    }));

    const top = hostDistribution[0];
    if (!top.host) return { collectionHost: null, confidence: "none", hostDistribution, format };

    // Confidence based on how dominant the top host is
    let confidence;
    if (top.pct >= 80) confidence = "high";        // >80% = clearly the collection host
    else if (top.pct >= 50) confidence = "medium";  // 50-80% = likely but mixed sources
    else confidence = "low";                        // <50% = multi-machine dataset

    // Normalize: strip domain suffix for display but keep both forms
    const collectionHost = top.host;
    const shortName = collectionHost.split(".")[0];

    return {
      collectionHost,
      shortName,
      confidence,
      pct: top.pct,
      eventCount: top.count,
      totalEvents: total,
      hostDistribution,
      format,
    };
  } catch (err) {
    return { collectionHost: null, confidence: "none", hostDistribution: [], format, error: err.message };
  }
}

module.exports = { detectKapeCollectionHost };
