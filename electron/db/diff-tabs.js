/**
 * Generic tab diff — compare any two imported timelines (CSV, EVTX, MFT, AI history, …)
 * and emit a result tab with Added / Removed / Changed / Unchanged rows.
 *
 * Matching is schema-agnostic:
 *   - optional identity columns (auto-suggested from header names)
 *   - otherwise an entire-row content hash
 *   - duplicate keys are matched as a multiset (1st unmatched A with 1st unmatched B)
 *
 * Result columns (always present, then the union of source headers):
 *   _Diff _Baseline _Compare _MatchKey _ChangedFields _DiffSummary _DiffDetail datetime …
 */

const crypto = require("crypto");

const DIFF_META_COLUMNS = [
  "_Diff",
  "_Baseline",
  "_Compare",
  "_MatchKey",
  "_ChangedFields",
  "_DiffSummary",
  "_DiffDetail",
];
const DIFF_META_SET = new Set([...DIFF_META_COLUMNS, "datetime"]);
const VALUE_CAP = 240;
const SUMMARY_CAP = 1500;
const MAX_CHANGED_FIELDS = 40;
const PAGE = 20000;

function isDiffMetaColumn(name) {
  return DIFF_META_SET.has(String(name || ""));
}

function normalizeCell(v) {
  if (v == null) return "";
  return String(v)
    .replace(/\0/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .trim();
}

function capText(s, n) {
  const t = String(s || "");
  if (t.length <= n) return t;
  return `${t.slice(0, n - 1)}…`;
}

function dataColumns(headers) {
  return (headers || []).filter((h) => h && !isDiffMetaColumn(h));
}

function schemaDelta(headersA, headersB) {
  const a = new Set(headersA || []);
  const b = new Set(headersB || []);
  const onlyA = [...a].filter((h) => !b.has(h) && !isDiffMetaColumn(h)).sort();
  const onlyB = [...b].filter((h) => !a.has(h) && !isDiffMetaColumn(h)).sort();
  const common = [...a].filter((h) => b.has(h) && !isDiffMetaColumn(h)).sort();
  return { onlyA, onlyB, common };
}

function buildUnifiedHeaders(headersA, headersB) {
  const seen = new Set();
  const rest = [];
  for (const h of [...(headersA || []), ...(headersB || [])]) {
    if (!h || seen.has(h) || isDiffMetaColumn(h)) continue;
    seen.add(h);
    rest.push(h);
  }
  return [...DIFF_META_COLUMNS, "datetime", ...rest];
}

/**
 * Identity-column scoring. Higher = likelier unique key. Generic across DFIR formats
 * (EVTX record ids, file hashes, SourceFile+Timestamp combos) — not tied to one artifact.
 */
function scoreIdentityColumn(name) {
  const n = String(name || "").toLowerCase();
  if (!n || n.startsWith("_")) return 0;
  if (n === "eventrecordid" || n === "recordnumber" || n === "recordid" || n === "event_record_id") return 100;
  if (n === "uuid" || n === "guid" || n.endsWith("uuid") || n.endsWith("guid")) return 95;
  if (/(^|_)(sha-?1|sha-?256|md5)$/.test(n) || n.endsWith("hash")) return 88;
  if (n === "sourcefile" || n === "fullpath" || n === "filepath" || n === "path") return 72;
  if (/(message|payload|content|summary|fulltext|description|commandline|command)$/.test(n)) return 8;
  if (n === "eventkind" || n === "recordtype" || n === "artifactname" || n === "sourcetype") return 58;
  if (n === "activity" || n === "action" || n === "operation") return 52;
  if (n === "eventid" || n === "event_id" || n === "eid") return 48;
  if (n === "computer" || n === "hostname" || n === "host") return 45;
  if (n === "filename" || n === "name") return 40;
  if (/(time|date|timestamp|created|modified|accessed)/i.test(n) && !/id$/.test(n)) return 42;
  if (/id$/i.test(n)) return 70;
  return 12;
}

function suggestMatchKeys(headersA, headersB) {
  const a = new Set(headersA || []);
  const common = (headersB || []).filter((h) => a.has(h) && !isDiffMetaColumn(h));
  const scored = common
    .map((h) => ({ h, s: scoreIdentityColumn(h) }))
    .sort((x, y) => y.s - x.s || x.h.localeCompare(y.h));

  const strong = scored.filter((x) => x.s >= 88).map((x) => x.h);
  if (strong.length) return [...new Set(strong.slice(0, 4))];

  const auto = [];
  const pick = (name) => {
    if (common.includes(name) && !auto.includes(name)) auto.push(name);
  };
  const idish = scored.find((x) => x.s >= 70);
  if (idish) auto.push(idish.h);

  pick("EventRecordId");
  pick("RecordNumber");
  pick("SourceFile");
  pick("Timestamp");
  pick("TimeCreated");
  pick("DateTime");
  pick("EventKind");
  pick("Activity");
  pick("EventId");
  pick("Computer");

  if (auto.length) return auto.slice(0, 6);
  return scored.filter((x) => x.s >= 40).slice(0, 4).map((x) => x.h);
}

function hashRow(row, compareCols) {
  const h = crypto.createHash("sha1");
  for (let i = 0; i < compareCols.length; i++) {
    h.update(normalizeCell(row[compareCols[i]]));
    h.update("\0");
  }
  return h.digest("hex");
}

function identityKey(row, matchKeys, compareCols, side, rowid) {
  if (!matchKeys.length) return `h:${hashRow(row, compareCols)}`;
  const parts = matchKeys.map((k) => normalizeCell(row[k]));
  if (parts.every((p) => p === "")) return `__empty:${side}:${rowid}`;
  return parts.join("\x1f");
}

function displayMatchKey(ident, matchKeys) {
  if (!ident) return "";
  if (ident.startsWith("h:")) return matchKeys.length ? "" : "(entire row)";
  if (ident.startsWith("__empty:")) return "(empty match key)";
  return ident.split("\x1f").join(" | ");
}

function compareRowFields(rowA, rowB, compareCols) {
  const aObj = rowA || {};
  const bObj = rowB || {};
  const pairs = [];
  for (let i = 0; i < compareCols.length; i++) {
    const col = compareCols[i];
    const a = normalizeCell(aObj[col]);
    const b = normalizeCell(bObj[col]);
    if (a === b) continue;
    pairs.push({ f: col, a: capText(a, VALUE_CAP), b: capText(b, VALUE_CAP) });
    if (pairs.length >= MAX_CHANGED_FIELDS) break;
  }
  const summary = pairs
    .map((p) => `${p.f}: ${capText(p.a, 80)} → ${capText(p.b, 80)}`)
    .join("; ")
    .slice(0, SUMMARY_CAP);
  return {
    changedFields: pairs.map((p) => p.f),
    summary,
    detail: JSON.stringify(pairs),
  };
}

function defaultSummary(status) {
  if (status === "Added") return "Present only in compare";
  if (status === "Removed") return "Present only in baseline";
  if (status === "Unchanged") return "";
  return "";
}

function buildOutputArray(headers, {
  status, baselineName, compareName, matchKey, changedFields, summary, detail, datetime, values,
}) {
  const src = values || {};
  const out = new Array(headers.length);
  for (let i = 0; i < headers.length; i++) {
    const h = headers[i];
    switch (h) {
      case "_Diff": out[i] = status; break;
      case "_Baseline": out[i] = baselineName; break;
      case "_Compare": out[i] = compareName; break;
      case "_MatchKey": out[i] = matchKey || ""; break;
      case "_ChangedFields": out[i] = (changedFields || []).join(", "); break;
      case "_DiffSummary": out[i] = summary || ""; break;
      case "_DiffDetail": out[i] = detail || "[]"; break;
      case "datetime": out[i] = datetime || ""; break;
      default: out[i] = src[h] ?? ""; break;
    }
  }
  return out;
}

function outputRowObject(headers, arr) {
  const obj = {};
  for (let i = 0; i < headers.length; i++) obj[headers[i]] = arr[i];
  return obj;
}

function topChangedFields(fieldCounts, limit = 40) {
  return [...fieldCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([field, count]) => ({ field, count }));
}

function emptyStats() {
  return { added: 0, removed: 0, changed: 0, unchanged: 0 };
}

/**
 * In-memory diff used by tests and as the reference matching model.
 * `rowsA` / `rowsB` are objects keyed by original header names.
 */
function diffRowSets(rowsA, rowsB, options = {}) {
  const headersA = options.headersA || [];
  const headersB = options.headersB || [];
  const headers = buildUnifiedHeaders(headersA, headersB);
  const compareCols = dataColumns(headers);
  const matchKeys = Array.isArray(options.matchKeys) ? options.matchKeys.filter(Boolean) : [];
  const includeUnchanged = !!options.includeUnchanged;
  const baselineName = options.baselineName || "Baseline";
  const compareName = options.compareName || "Compare";
  const tsColA = options.tsColA || "";
  const tsColB = options.tsColB || "";

  const queues = new Map();
  (rowsA || []).forEach((row, i) => {
    const ident = identityKey(row, matchKeys, compareCols, "a", i + 1);
    let q = queues.get(ident);
    if (!q) { q = []; queues.set(ident, q); }
    q.push({ row, i });
  });

  const stats = emptyStats();
  const fieldCounts = new Map();
  const out = [];

  const datetimeOf = (status, rowA, rowB) => {
    if (status === "Removed") return normalizeCell(rowA?.[tsColA] || rowA?.[tsColB] || "");
    return normalizeCell(rowB?.[tsColB] || rowB?.[tsColA] || rowA?.[tsColA] || "");
  };

  const emit = (status, rowA, rowB, ident, cmp) => {
    const values = status === "Removed" ? rowA : rowB;
    out.push(outputRowObject(headers, buildOutputArray(headers, {
      status,
      baselineName,
      compareName,
      matchKey: displayMatchKey(ident, matchKeys),
      changedFields: cmp?.changedFields || [],
      summary: cmp?.summary || defaultSummary(status),
      detail: cmp?.detail || "[]",
      datetime: datetimeOf(status, rowA, rowB),
      values,
    })));
  };

  (rowsB || []).forEach((rowB, i) => {
    const ident = identityKey(rowB, matchKeys, compareCols, "b", i + 1);
    const q = queues.get(ident);
    const hit = q && q.length ? q.shift() : null;
    if (!hit) {
      stats.added += 1;
      emit("Added", null, rowB, ident, null);
      return;
    }
    const cmp = compareRowFields(hit.row, rowB, compareCols);
    if (!cmp.changedFields.length) {
      stats.unchanged += 1;
      if (includeUnchanged) emit("Unchanged", hit.row, rowB, ident, cmp);
    } else {
      stats.changed += 1;
      for (const f of cmp.changedFields) fieldCounts.set(f, (fieldCounts.get(f) || 0) + 1);
      emit("Changed", hit.row, rowB, ident, cmp);
    }
  });

  for (const q of queues.values()) {
    for (const hit of q) {
      stats.removed += 1;
      const ident = identityKey(hit.row, matchKeys, compareCols, "a", hit.i + 1);
      emit("Removed", hit.row, null, ident, null);
    }
  }

  return {
    headers,
    rows: out,
    stats: { ...stats, total: out.length, changedFields: topChangedFields(fieldCounts) },
    matchKeys,
    includeUnchanged,
    schemaDelta: schemaDelta(headersA, headersB),
  };
}

function sqlRowToObject(meta, sqlRow) {
  const obj = {};
  for (const col of meta.safeCols) obj[col.original] = sqlRow[col.safe] ?? "";
  return obj;
}

function fetchRowsByIds(meta, ids) {
  const map = new Map();
  if (!ids.length) return map;
  const cols = `rowid AS _mrid, ${meta.safeCols.map((c) => c.safe).join(", ")}`;
  const CHUNK = 400;
  for (let i = 0; i < ids.length; i += CHUNK) {
    const slice = ids.slice(i, i + CHUNK);
    const stmt = meta.db.prepare(
      `SELECT ${cols} FROM data WHERE rowid IN (${slice.map(() => "?").join(",")})`
    );
    for (const sqlRow of stmt.all(...slice)) {
      map.set(sqlRow._mrid, sqlRowToObject(meta, sqlRow));
    }
  }
  return map;
}

async function forEachPage(meta, pageSize, onPage) {
  const srcCols = meta.safeCols.map((c) => c.safe).join(", ");
  const selectPage = meta.db.prepare(
    `SELECT rowid AS _mrid, ${srcCols} FROM data WHERE rowid > ? ORDER BY rowid LIMIT ?`
  );
  let lastRowid = 0;
  for (;;) {
    const page = selectPage.all(lastRowid, pageSize);
    if (!page.length) break;
    lastRowid = page[page.length - 1]._mrid;
    await onPage(page);
  }
}

function yieldEventLoop() {
  return new Promise((resolve) => setImmediate(resolve));
}

/**
 * TimelineDB method: stream two source tabs into a new result tab.
 */
async function diffTabs(diffTabId, spec, onProgress) {
  const baselineSrc = spec?.baseline;
  const compareSrc = spec?.compare;
  if (!baselineSrc?.tabId || !compareSrc?.tabId) {
    throw new Error("Diff requires a baseline tab and a compare tab");
  }
  if (baselineSrc.tabId === compareSrc.tabId) {
    throw new Error("Pick two different tabs to diff");
  }

  const baseline = this.databases.get(baselineSrc.tabId);
  const compare = this.databases.get(compareSrc.tabId);
  if (!baseline) throw new Error(`Baseline tab "${baselineSrc.tabName || baselineSrc.tabId}" not found`);
  if (!compare) throw new Error(`Compare tab "${compareSrc.tabName || compareSrc.tabId}" not found`);

  const headersA = baseline.headers || [];
  const headersB = compare.headers || [];
  const unified = buildUnifiedHeaders(headersA, headersB);
  const compareCols = dataColumns(unified);
  const matchKeys = Array.isArray(spec.matchKeys) ? spec.matchKeys.filter((k) => typeof k === "string" && k) : [];
  const includeUnchanged = !!spec.includeUnchanged;
  const baselineName = baselineSrc.tabName || "Baseline";
  const compareName = compareSrc.tabName || "Compare";
  const tsColA = baselineSrc.tsCol || "";
  const tsColB = compareSrc.tsCol || "";

  this.createTab(diffTabId, unified);
  const resultMeta = this.databases.get(diffTabId);
  const totalRows = (baseline.rowCount || 0) + (compare.rowCount || 0);
  const cacheKiB = Math.min(1048576, Math.max(65536, Math.ceil((totalRows * 200) / 1024 * 1.5)));
  resultMeta.db.pragma(`cache_size = ${-cacheKiB}`);

  const resultDb = resultMeta.db;
  resultDb.exec(`CREATE TABLE _diff_a (
    ident TEXT NOT NULL,
    n INTEGER NOT NULL,
    hash TEXT NOT NULL,
    src_rowid INTEGER NOT NULL,
    PRIMARY KEY (ident, n)
  )`);
  const insertA = resultDb.prepare("INSERT INTO _diff_a (ident, n, hash, src_rowid) VALUES (?,?,?,?)");
  const lookupA = resultDb.prepare("SELECT hash, src_rowid FROM _diff_a WHERE ident = ? AND n = ?");
  const deleteA = resultDb.prepare("DELETE FROM _diff_a WHERE ident = ? AND n = ?");

  let processed = 0;
  const report = (phase, extra = "") => {
    if (onProgress) {
      onProgress({
        phase,
        current: processed,
        total: Math.max(totalRows, 1),
        sourceName: extra,
      });
    }
  };

  const identSeqA = new Map();
  report("indexing", baselineName);
  await forEachPage(baseline, PAGE, async (page) => {
    const tx = resultDb.transaction(() => {
      for (const sqlRow of page) {
        const row = sqlRowToObject(baseline, sqlRow);
        const ident = identityKey(row, matchKeys, compareCols, "a", sqlRow._mrid);
        const n = (identSeqA.get(ident) || 0) + 1;
        identSeqA.set(ident, n);
        insertA.run(ident, n, hashRow(row, compareCols), sqlRow._mrid);
      }
    });
    tx();
    processed += page.length;
    report("indexing", baselineName);
    await yieldEventLoop();
  });
  identSeqA.clear();

  const identSeqB = new Map();
  const stats = emptyStats();
  const fieldCounts = new Map();
  let batch = [];
  const flush = () => {
    if (!batch.length) return;
    this.insertBatchArrays(diffTabId, batch);
    batch = [];
  };

  const datetimeOf = (status, rowA, rowB) => {
    if (status === "Removed") return normalizeCell(rowA?.[tsColA] || rowA?.[tsColB] || "");
    return normalizeCell(rowB?.[tsColB] || rowB?.[tsColA] || rowA?.[tsColA] || "");
  };

  const pushRow = (status, rowA, rowB, ident, cmp) => {
    batch.push(buildOutputArray(unified, {
      status,
      baselineName,
      compareName,
      matchKey: displayMatchKey(ident, matchKeys),
      changedFields: cmp?.changedFields || [],
      summary: cmp?.summary || defaultSummary(status),
      detail: cmp?.detail || "[]",
      datetime: datetimeOf(status, rowA, rowB),
      values: status === "Removed" ? rowA : rowB,
    }));
    if (batch.length >= PAGE) flush();
  };

  report("matching", compareName);
  await forEachPage(compare, PAGE, async (page) => {
    const classified = [];
    const needA = [];
    const tx = resultDb.transaction(() => {
      for (const sqlRow of page) {
        const rowB = sqlRowToObject(compare, sqlRow);
        const ident = identityKey(rowB, matchKeys, compareCols, "b", sqlRow._mrid);
        const n = (identSeqB.get(ident) || 0) + 1;
        identSeqB.set(ident, n);
        const bHash = hashRow(rowB, compareCols);
        const hit = lookupA.get(ident, n);
        if (!hit) {
          classified.push({ status: "Added", rowB, ident });
          continue;
        }
        deleteA.run(ident, n);
        if (hit.hash === bHash) {
          classified.push({ status: "Unchanged", rowB, ident });
        } else {
          classified.push({ status: "Changed", rowB, ident, aRowid: hit.src_rowid });
          needA.push(hit.src_rowid);
        }
      }
    });
    tx();

    const aMap = fetchRowsByIds(baseline, needA);
    for (const item of classified) {
      if (item.status === "Added") {
        stats.added += 1;
        pushRow("Added", null, item.rowB, item.ident, null);
      } else if (item.status === "Unchanged") {
        stats.unchanged += 1;
        if (includeUnchanged) pushRow("Unchanged", null, item.rowB, item.ident, {
          changedFields: [], summary: "", detail: "[]",
        });
      } else {
        stats.changed += 1;
        const rowA = aMap.get(item.aRowid) || {};
        const cmp = compareRowFields(rowA, item.rowB, compareCols);
        for (const f of cmp.changedFields) fieldCounts.set(f, (fieldCounts.get(f) || 0) + 1);
        pushRow("Changed", rowA, item.rowB, item.ident, cmp);
      }
    }
    processed += page.length;
    report("matching", compareName);
    await yieldEventLoop();
  });

  report("copying", baselineName);
  const selectRem = resultDb.prepare(
    "SELECT rowid AS _rid, ident, src_rowid FROM _diff_a WHERE rowid > ? ORDER BY rowid LIMIT ?"
  );
  let lastRid = 0;
  for (;;) {
    const rem = selectRem.all(lastRid, PAGE);
    if (!rem.length) break;
    lastRid = rem[rem.length - 1]._rid;
    const aMap = fetchRowsByIds(baseline, rem.map((r) => r.src_rowid));
    for (const rec of rem) {
      stats.removed += 1;
      pushRow("Removed", aMap.get(rec.src_rowid) || {}, null, rec.ident, null);
    }
    report("copying", baselineName);
    await yieldEventLoop();
  }

  flush();
  resultDb.exec("DROP TABLE IF EXISTS _diff_a");

  report("indexing", "");
  const result = this.finalizeImport(diffTabId);

  const diffSafe = resultMeta.colMap["_Diff"];
  if (diffSafe && !resultMeta.indexedCols.has(diffSafe)) {
    resultDb.exec(`CREATE INDEX IF NOT EXISTS idx_${diffSafe} ON data(${diffSafe})`);
    resultMeta.indexedCols.add(diffSafe);
  }
  const dtSafe = resultMeta.colMap["datetime"];
  if (dtSafe && !resultMeta.indexedCols.has(dtSafe)) {
    resultDb.exec(`CREATE INDEX IF NOT EXISTS idx_${dtSafe} ON data(${dtSafe})`);
    resultMeta.indexedCols.add(dtSafe);
  }

  return {
    headers: unified,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns,
    stats: { ...stats, total: result.rowCount, changedFields: topChangedFields(fieldCounts) },
    matchKeys,
    includeUnchanged,
    schemaDelta: schemaDelta(headersA, headersB),
  };
}

function diffTabTitle(baselineName, compareName) {
  const clip = (s, n = 28) => {
    const t = String(s || "");
    return t.length > n ? `${t.slice(0, n - 1)}…` : t;
  };
  return `Diff: ${clip(baselineName)} → ${clip(compareName)}`;
}

module.exports = {
  DIFF_META_COLUMNS,
  isDiffMetaColumn,
  normalizeCell,
  scoreIdentityColumn,
  suggestMatchKeys,
  schemaDelta,
  buildUnifiedHeaders,
  hashRow,
  identityKey,
  displayMatchKey,
  compareRowFields,
  diffRowSets,
  diffTabs,
  diffTabTitle,
  dataColumns,
};
