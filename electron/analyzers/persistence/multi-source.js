/**
 * analyzers/persistence/multi-source.js — multi-tab correlation for persistence
 *
 * The persistence analyzer was single-tab / single-file, and a KAPE package is not one
 * file. On raw triage the evidence for ONE persistence artifact is spread across several:
 *
 *   System.evtx                       7045 "Service Installed"      ← the finding
 *   Security.evtx                     4688 process creation          ← the corroboration
 *   Microsoft-Windows-Sysmon          EID 1 process creation         ← the corroboration
 *   PowerShell%4Operational.evtx      4104 script block              ← how it was created
 *   SOFTWARE / SYSTEM hive export     Run value / service ImagePath  ← the same artifact
 *
 * Each import is its own tab with its own SQLite database, and the engine's correlation
 * queries (`CORR_EIDS`, 4104) run against ONE of them — so a service install could never
 * be corroborated and stayed at confidence "present" no matter how much evidence the
 * package actually contained.
 *
 * This module merges the rows first and analyzes once:
 *   1. Per-tab mode + column detection (same detectors the single-tab path uses)
 *   2. Per-tab SQL query, aliased to the engine's canonical field names
 *   3. Merge, tagging each row with its source tab
 *   4. Run the engine over the merged set via `_prequeriedRows`
 *   5. Cluster EVTX and registry findings together so one artifact seen through two
 *      different sources is one incident, not two
 */

const { dbg } = require("../../logger");
const { getPersistenceAnalysis } = require("./index");
const { EVTX_RULES } = require("./rules");
const { RAW_EVTX_HAYSTACK_FIELDS, isChainsawDataset, isHayabusaDataset } = require("../evtx-utils");
const { detectRegistryPlugin, projectPluginRows } = require("./registry-shapes");
const { clusterIncidents } = require("./incidents");

// Event ids the engine reads but never reports on: service state (7036/7035), process
// creation (Sysmon 1 / Security 4688) and PowerShell script blocks (4104). They have to be
// pulled into the merged set or the correlation that justifies this whole module has
// nothing to correlate against.
const CORRELATION_EIDS = ["7036", "7035", "1", "4688", "4104", "4624"];

const ALL_RULE_EIDS = [...new Set(EVTX_RULES.flatMap((r) => r.eventIds))];
const MERGED_EIDS = [...new Set([...ALL_RULE_EIDS, ...CORRELATION_EIDS])];

const _detector = (headers) => (patterns) => {
  for (const pat of patterns) {
    const found = headers.find((h) => pat.test(h));
    if (found) return found;
  }
  return null;
};

/**
 * Decide what a tab holds and which columns carry it.
 * Mirrors the detection in getPersistenceAnalysis so a tab behaves the same merged as alone.
 *
 * @returns {{mode, columns, format, regPlugin}} | null when the tab holds neither shape
 */
function detectTabShape(meta) {
  const headers = meta.headers || [];
  const detect = _detector(headers);
  const isChainsaw = isChainsawDataset(meta);
  const isHayabusa = isHayabusaDataset(meta);

  const hasEventId = detect([/^EventI[dD]$/i, /^event_id$/i, ...(isChainsaw ? [/^id$/i] : [])]);
  const hasKeyPath = detect([/^KeyPath$/i, /^Key ?Path$/i]);
  const hasValueName = detect([/^ValueName$/i, /^Value ?Name$/i]);
  const regPlugin = (hasKeyPath && hasValueName) ? null : detectRegistryPlugin(headers, detect);

  if (hasKeyPath && hasValueName) {
    return { mode: "registry", format: "Registry export", regPlugin: null, columns: registryColumns(detect) };
  }
  if (hasEventId) {
    const format = isHayabusa ? "Hayabusa" : isChainsaw ? "Chainsaw"
      : detect([/^PayloadData1$/i]) ? "EvtxECmd" : "Raw EVTX";
    return { mode: "evtx", format, regPlugin: null, columns: evtxColumns(detect, { isChainsaw, isHayabusa }) };
  }
  if (regPlugin) {
    // Execution-evidence plugins (UserAssist/AppCompatCache/BAM) carry no persistence keys.
    if (!regPlugin.shape.projects) return { mode: null, format: regPlugin.shape.label, regPlugin, columns: {} };
    return { mode: "registry", format: regPlugin.shape.label, regPlugin, columns: registryColumns(detect, regPlugin) };
  }
  return null;
}

function evtxColumns(detect, { isChainsaw, isHayabusa }) {
  const columns = {
    eventId: detect([/^EventI[dD]$/i, /^event_id$/i, ...(isChainsaw ? [/^id$/i] : [])]),
    channel: detect([/^Channel$/i, /^SourceName$/i, /^Provider$/i]),
    ts: detect([/^TimeCreated$/i, /^datetime$/i, /^UtcTime$/i, /^Timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
    computer: detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, ...(isChainsaw ? [/^computer_name$/i] : [])]),
    payload: detect([/^PayloadData1$/i]),
    payload2: detect([/^PayloadData2$/i]),
    payload3: detect([/^PayloadData3$/i]),
    payload4: detect([/^PayloadData4$/i]),
    payload5: detect([/^PayloadData5$/i]),
    payload6: detect([/^PayloadData6$/i]),
    mapDesc: detect([/^MapDescription$/i]),
    execInfo: detect([/^ExecutableInfo$/i]),
    details: detect([/^Details$/i, ...(isChainsaw ? [/^Event\.EventData\.Details$/i] : [])]),
    extra: detect([/^ExtraFieldInfo$/i]),
    ruleTitle: detect([/^RuleTitle$/i, ...(isChainsaw ? [/^detection_rules$/i] : [])]),
    user: detect([/^UserName$/i, /^User$/i, ...(isChainsaw ? [/^target_username$/i] : [])]) || (isHayabusa ? detect([/^ExtraFieldInfo$/i, /^Details$/i]) : null),
    targetObject: detect([/^TargetObject$/i, /^target_object$/i, /^Event\.EventData\.TargetObject$/i]),
    targetFilename: detect([/^TargetFilename$/i, /^Event\.EventData\.TargetFilename$/i]),
    image: detect([/^Image$/i, /^process_name$/i, /^Event\.EventData\.Image$/i, /^image$/i]),
    cmdLine: detect([/^CommandLine$/i, /^command_line$/i, /^Event\.EventData\.CommandLine$/i]),
    workstation: detect([/^WorkstationName$/i, /^workstation_name$/i]),
    source: detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^source_ip$/i]),
    logonType: detect([/^LogonType$/i, /^logon_type$/i]),
  };
  // Raw-EVTX EventData fields the rules match on (TaskName, param1..4, ServiceName, …).
  for (const def of RAW_EVTX_HAYSTACK_FIELDS) {
    if (!columns[def.key]) columns[def.key] = detect(def.aliases);
  }
  return columns;
}

function registryColumns(detect, regPlugin = null) {
  const columns = {
    keyPath: detect([/^KeyPath$/i, /^Key ?Path$/i]),
    valueName: detect([/^ValueName$/i, /^Value ?Name$/i]),
    valueData: detect([/^ValueData$/i, /^Value ?Data$/i]),
    valueData2: detect([/^ValueData2$/i]),
    valueData3: detect([/^ValueData3$/i]),
    valueType: detect([/^ValueType$/i, /^Value ?Type$/i]),
    hivePath: detect([/^HivePath$/i, /^Hive ?Path$/i]),
    hiveType: detect([/^HiveType$/i, /^Hive ?Type$/i]),
    computer: detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, /^MachineName$/i]),
    ts: detect([/^LastWriteTimestamp$/i, /^Timestamp$/i, /^datetime$/i, /^TimeCreated$/i]),
  };
  if (regPlugin) {
    for (const [key, colName] of Object.entries(regPlugin.cols)) {
      if (colName && !columns[key]) columns[key] = colName;
    }
  }
  return columns;
}

/**
 * Query one tab and return rows aliased to the engine's canonical field names.
 * EVTX tabs are pre-filtered to the rule + correlation event ids; registry tabs are not
 * filtered at all (there is no cheap SQL predicate for "is a persistence key").
 */
function queryTabRows(meta, shape, options, ctx, maxRows) {
  const { mode, columns } = shape;
  const params = [];
  const whereConditions = [];

  if (mode === "evtx" && columns.eventId && meta.colMap[columns.eventId]) {
    const safeEid = meta.colMap[columns.eventId];
    whereConditions.push(`${safeEid} IN (${MERGED_EIDS.map(() => "?").join(",")})`);
    params.push(...MERGED_EIDS);
  }
  ctx.applyStandardFilters(options, meta, whereConditions, params);
  const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

  const selectParts = ["data.rowid as _rowid"];
  for (const [key, colName] of Object.entries(columns)) {
    if (colName && meta.colMap[colName]) selectParts.push(`${meta.colMap[colName]} as [${key}]`);
  }

  const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
  const orderClause = orderCol ? `ORDER BY ${orderCol} ASC, data.rowid ASC` : "ORDER BY data.rowid ASC";

  try {
    if (columns.eventId) ctx.ensureIndex?.(meta.tabId, columns.eventId);
    if (columns.ts) ctx.ensureIndex?.(meta.tabId, columns.ts);
  } catch { /* index creation is best effort */ }

  const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${maxRows}`;
  return meta.db.prepare(sql).all(...params);
}

const _clampRows = (value, fallback) => {
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(Math.max(n, 1000), 2000000);
};

/**
 * Multi-source persistence analysis.
 *
 * @param {Array<{meta, tabId, label}>} metas
 * @param {object} options   same options as the single-tab analyzer
 * @param {object} ctx       helper methods from TimelineDB
 * @returns {object}         same result shape as getPersistenceAnalysis(), plus
 *                           multiSource/tabSummaries and per-tab stats
 */
function getMultiSourcePersistence(metas, options = {}, ctx) {
  if (!metas || metas.length === 0) {
    return { items: [], incidents: [], warnings: [], stats: {}, columns: {}, error: "No tabs selected" };
  }
  // One tab has nothing to merge — the single-tab path is the same analysis.
  if (metas.length === 1) return getPersistenceAnalysis(metas[0].meta, options, ctx);

  const warnings = [];
  const tabSummaries = [];
  const evtxRows = [];
  const registryRows = [];
  let evtxColumnsRef = null;
  let registryColumnsRef = null;

  const totalMaxRows = _clampRows(options.maxRows, 500000);
  const perTabMaxRows = Math.max(1000, Math.floor(totalMaxRows / metas.length));

  for (const { meta, tabId, label } of metas) {
    let shape;
    try {
      shape = detectTabShape(meta);
    } catch (err) {
      warnings.push(`Tab "${label}": column detection failed — ${err.message}`);
      continue;
    }
    if (!shape) {
      warnings.push(`Tab "${label}": no EventID or KeyPath column — not an EVTX or registry source, skipped.`);
      tabSummaries.push({ tabId, label, mode: null, format: null, rowCount: 0, skipped: true });
      continue;
    }
    if (!shape.mode) {
      warnings.push(`Tab "${label}": ${shape.format} holds execution evidence, not persistence keys — skipped.`);
      tabSummaries.push({ tabId, label, mode: null, format: shape.format, rowCount: 0, skipped: true });
      continue;
    }

    try {
      const raw = queryTabRows(meta, shape, options, ctx, perTabMaxRows);
      const rows = shape.regPlugin ? projectPluginRows(shape.regPlugin, raw) : raw;

      for (const row of rows) {
        row._sourceTab = label;
        row._sourceTabId = tabId;
        row._sourceRowId = Number.isFinite(Number(row._rowid)) ? Number(row._rowid) : row._rowid;
        row._sourceFormat = shape.format;
      }

      if (shape.mode === "evtx") {
        evtxRows.push(...rows);
        if (!evtxColumnsRef) evtxColumnsRef = shape.columns;
      } else {
        registryRows.push(...rows);
        if (!registryColumnsRef) registryColumnsRef = shape.columns;
      }
      tabSummaries.push({ tabId, label, mode: shape.mode, format: shape.format, rowCount: rows.length });
      if (raw.length >= perTabMaxRows) {
        warnings.push(`Tab "${label}": hit the ${perTabMaxRows.toLocaleString()}-row per-tab cap — raise maxRows for full coverage.`);
      }
    } catch (err) {
      warnings.push(`Tab "${label}": query failed — ${err.message}`);
      tabSummaries.push({ tabId, label, mode: shape.mode, format: shape.format, rowCount: 0, error: err.message });
    }
  }

  if (evtxRows.length === 0 && registryRows.length === 0) {
    return {
      items: [], incidents: [], warnings, stats: { tabCount: tabSummaries.length }, columns: {},
      multiSource: true, tabSummaries,
      error: "No persistence-relevant rows found across the selected tabs.",
    };
  }

  const byTimestamp = (a, b) => ((a.ts || "") > (b.ts || "") ? 1 : (a.ts || "") < (b.ts || "") ? -1 : 0);
  evtxRows.sort(byTimestamp);
  registryRows.sort(byTimestamp);
  dbg("MULTI-PERSIST", `merged ${evtxRows.length} EVTX + ${registryRows.length} registry rows from ${tabSummaries.length} tabs`);

  // Run the engine once per shape present. The merged EVTX pass is where the payoff is:
  // its correlation now sees 4688/Sysmon-1/4104 from OTHER files.
  const results = [];
  const allItems = [];
  const runOne = (mode, rows, extra = {}) => {
    if (rows.length === 0) return null;
    const synthetic = syntheticMeta(mode, rows);
    const merged = {
      ...options,
      ...extra,
      mode,
      _prequeriedRows: rows,
      // Column overrides are per-tab concepts; the merged rows are already aliased.
      columns: {},
    };
    try {
      const res = getPersistenceAnalysis(synthetic, merged, ctx);
      if (res?.error) warnings.push(`${mode === "evtx" ? "EVTX" : "Registry"} pass: ${res.error}`);
      if (res?.warnings?.length) warnings.push(...res.warnings);
      if (res?.items?.length) allItems.push(...res.items);
      results.push({ mode, res });
      return res;
    } catch (err) {
      warnings.push(`${mode === "evtx" ? "EVTX" : "Registry"} pass failed — ${err.message}`);
      dbg("MULTI-PERSIST", `${mode} pass failed`, { error: err.message });
      return null;
    }
  };

  const evtxResult = runOne("evtx", evtxRows);
  // The EVTX pass is where inbound logons and remote WMI/WinRM operations are seen. Hand
  // its arrivals to the registry pass so a Run value written over an RDP session can be
  // attributed to the same pivot as the service installed alongside it.
  const registryResult = runOne("registry", registryRows, { _remoteLogons: evtxResult?._remoteLogons || [] });

  // Re-cluster ACROSS the passes. `crossModeRegistry` keys registry findings by the value
  // they describe rather than by rule name, so the same Run value seen in a hive export and
  // in a Sysmon 13 SetValue becomes one incident carrying both as evidence.
  const incidents = clusterIncidents(allItems, { crossModeRegistry: true });

  const byCategory = {};
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of allItems) {
    byCategory[item.category] = (byCategory[item.category] || 0) + 1;
    bySeverity[item.severity] = (bySeverity[item.severity] || 0) + 1;
  }
  const byIncidentSeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const inc of incidents) byIncidentSeverity[inc.severity] = (byIncidentSeverity[inc.severity] || 0) + 1;

  const byConfidence = { confirmed: 0, likely: 0, present: 0 };
  for (const item of allItems) if (byConfidence[item.confidence] !== undefined) byConfidence[item.confidence]++;

  return {
    items: allItems,
    incidents,
    warnings,
    multiSource: true,
    tabSummaries,
    columns: evtxColumnsRef || registryColumnsRef || {},
    detectedMode: evtxRows.length && registryRows.length ? "mixed" : (evtxRows.length ? "evtx" : "registry"),
    stats: {
      total: allItems.length,
      incidentCount: incidents.length,
      byCategory,
      bySeverity,
      byIncidentSeverity,
      byConfidence,
      suspicious: allItems.filter((i) => i.isSuspicious).length,
      suspiciousIncidents: incidents.filter((i) => i.isSuspicious).length,
      uniqueComputers: new Set(allItems.map((i) => i.computer).filter(Boolean)).size,
      categoriesFound: Object.keys(byCategory).length,
      ps4104Scripts: (evtxResult?.stats?.ps4104Scripts || 0),
      ps4104Correlated: (evtxResult?.stats?.ps4104Correlated || 0),
      registryHost: registryResult?.stats?.registryHost || "",
      registryHostSource: registryResult?.stats?.registryHostSource || "none",
      registryPlugin: registryResult?.stats?.registryPlugin || null,
      registryInventorySuppressed: registryResult?.stats?.registryInventorySuppressed || 0,
      remoteOriginItems: allItems.filter((i) => i.remoteOrigin).length,
      remoteArrivals: (evtxResult?._remoteLogons || []).length,
      tabCount: tabSummaries.filter((t) => !t.skipped).length,
      totalMergedRows: evtxRows.length + registryRows.length,
      perTabRows: tabSummaries.map((t) => ({ label: t.label, rows: t.rowCount, mode: t.mode, format: t.format })),
      // Cross-source incidents are the whole point — count how many actually got there.
      crossSourceIncidents: incidents.filter((i) => (i.sourceTabs || []).length > 1).length,
    },
    _remoteLogons: evtxResult?._remoteLogons || [],
    error: null,
  };
}

/**
 * Build the fake `meta` the engine runs against when rows are pre-queried. The rows are
 * already aliased to canonical names, so colMap maps each name to itself; `db` is null
 * because every query site reads `_prequeriedRows` instead.
 */
function syntheticMeta(mode, rows) {
  const headers = [];
  const colMap = {};
  // Derive the schema from the rows themselves rather than from any one tab's column map:
  // tabs of the same mode can have different shapes (a RECmd batch export and a projected
  // Services plugin CSV both produce registry rows, from entirely different columns).
  for (const row of rows.slice(0, 50)) {
    for (const key of Object.keys(row)) {
      if (key.startsWith("_") || colMap[key]) continue;
      headers.push(key);
      colMap[key] = key;
    }
  }
  // The engine's own detect() runs over these headers, so they must spell the canonical
  // names it looks for — "EventID"/"KeyPath"/"ValueName" gate mode detection.
  if (mode === "evtx") {
    if (!colMap.EventID) { headers.push("EventID"); colMap.EventID = "eventId"; }
  } else {
    if (!colMap.KeyPath) { headers.push("KeyPath"); colMap.KeyPath = "keyPath"; }
    if (!colMap.ValueName) { headers.push("ValueName"); colMap.ValueName = "valueName"; }
  }
  return { tabId: "__multi_source_persistence__", headers, colMap, db: null };
}

/**
 * Preview for the multi-tab config screen: what each selected tab contributes.
 */
function previewMultiSourcePersistence(metas, options = {}, ctx) {
  if (!metas || metas.length === 0) return { tabs: [], totalEvents: 0, error: "No tabs selected" };

  const tabs = [];
  let totalEvents = 0;

  for (const { meta, tabId, label } of metas) {
    let shape = null;
    try {
      shape = detectTabShape(meta);
    } catch (err) {
      tabs.push({ tabId, label, mode: null, format: null, eventCount: 0, error: err.message });
      continue;
    }
    if (!shape) {
      tabs.push({ tabId, label, mode: null, format: null, eventCount: 0, error: "No EventID or KeyPath column" });
      continue;
    }
    if (!shape.mode) {
      tabs.push({ tabId, label, mode: null, format: shape.format, eventCount: 0, error: "Execution evidence — carries no persistence keys" });
      continue;
    }

    try {
      const params = [];
      const whereConditions = [];
      if (shape.mode === "evtx" && shape.columns.eventId && meta.colMap[shape.columns.eventId]) {
        const safeEid = meta.colMap[shape.columns.eventId];
        whereConditions.push(`${safeEid} IN (${MERGED_EIDS.map(() => "?").join(",")})`);
        params.push(...MERGED_EIDS);
      }
      ctx.applyStandardFilters(options, meta, whereConditions, params);
      const wc = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
      const row = meta.db.prepare(`SELECT COUNT(*) as cnt FROM data ${wc}`).get(...params);
      const count = row?.cnt || 0;

      // Which correlation sources this tab can contribute — the reason to include it.
      let contributes = [];
      if (shape.mode === "evtx" && shape.columns.eventId && meta.colMap[shape.columns.eventId]) {
        const safeEid = meta.colMap[shape.columns.eventId];
        const found = meta.db.prepare(
          `SELECT DISTINCT ${safeEid} as eid FROM data WHERE ${safeEid} IN (${CORRELATION_EIDS.map(() => "?").join(",")})`,
        ).all(...CORRELATION_EIDS);
        contributes = found.map((r) => String(r.eid).trim()).filter(Boolean);
      }

      tabs.push({ tabId, label, mode: shape.mode, format: shape.format, eventCount: count, correlationEids: contributes });
      totalEvents += count;
    } catch (err) {
      tabs.push({ tabId, label, mode: shape.mode, format: shape.format, eventCount: 0, error: err.message });
    }
  }

  return { tabs, totalEvents, error: null };
}

module.exports = {
  getMultiSourcePersistence,
  previewMultiSourcePersistence,
  detectTabShape,
  MERGED_EIDS,
  CORRELATION_EIDS,
};
