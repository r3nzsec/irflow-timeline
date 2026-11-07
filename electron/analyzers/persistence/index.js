const { dbg } = require("../../logger");
const { buildEvtxHaystack, cleanWrappedField, compactGet, evtxChannelMatches, extractFirstInteger, isChainsawDataset, isHayabusaDataset, parseCompactKeyValues, resolveEventChannel, RAW_EVTX_HAYSTACK_FIELDS } = require("../evtx-utils");
const { parseTimestampMs } = require("../../utils/parse-timestamp");
const { compileSafeRegex } = require("../../utils/safe-regex");
const { EVTX_RULES, REGISTRY_RULES, PERSISTENCE_RULE_CATALOG } = require("./rules");
const {
  canonicalizeKeyPath, hiveContext, deriveCollectionHost, hostFromComputerNameKey,
  detectRegistryPlugin, projectPluginRows,
} = require("./registry-shapes");
const { corrHost, isBenignReason, hasSuspiciousReason, clusterIncidents } = require("./incidents");

// Compile an untrusted custom-rule pattern into a ReDoS-safe, .test()-able object
// (same interface as the built-in RegExp literals used throughout this file), or null
// if the pattern is invalid/unsafe so the caller can skip the rule.
function _safeRule(pattern) {
  const c = compileSafeRegex(pattern, "i");
  return c.error ? null : c; // c.test is the bounded tester
}

function previewPersistenceAnalysis(meta, options = {}, ctx) {
    if (!meta) return { eventCounts: {}, columnQuality: {}, error: "No database" };
    const { mode = "auto", columns: userCols = {} } = options;
    const { db, headers } = meta;
    const detect = (pats) => { for (const p of pats) { const f = headers.find(h => p.test(h)); if (f) return f; } return null; };

    const isChainsaw = isChainsawDataset(meta);
    const hasEventId = detect([/^EventI[dD]$/i, /^event_id$/i, ...(isChainsaw ? [/^id$/i] : [])]);
    const hasKeyPath = detect([/^KeyPath$/i, /^Key ?Path$/i]);
    const hasValueName = detect([/^ValueName$/i, /^Value ?Name$/i]);
    const isHayabusa = isHayabusaDataset(meta);
    // RECmd writes one detail CSV per plugin with no KeyPath/ValueName pair at all. Those
    // used to fall straight through to "Cannot detect data type".
    const regPlugin = (hasKeyPath && hasValueName) ? null : detectRegistryPlugin(headers, detect);
    let detectedMode = mode;
    if (detectedMode === "auto") {
      detectedMode = (hasKeyPath && hasValueName) ? "registry"
        : hasEventId ? "evtx"
          : regPlugin ? "registry" : null;
    }

    try {
      // Build WHERE clause from active filters (mirrors the real analyzer's scope)
      const params = [];
      const whereConditions = [];
      ctx.applyStandardFilters(options, meta, whereConditions, params);
      const wc = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

      const eventCounts = {};
      let trackedEvents = 0;
      const columnQuality = {};

      if (detectedMode === "evtx") {
        // Resolve columns
        const cols = {
          eventId: userCols.eventId || detect([/^EventI[dD]$/i, /^event_id$/i, ...(isChainsaw ? [/^id$/i] : [])]),
          channel: userCols.channel || detect([/^Channel$/i, /^SourceName$/i, /^Provider$/i]),
          ts: userCols.ts || detect([/^TimeCreated$/i, /^datetime$/i, /^UtcTime$/i, /^Timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
          computer: userCols.computer || detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, ...(isChainsaw ? [/^computer_name$/i] : [])]),
          user: userCols.user || detect([/^UserName$/i, /^User$/i, ...(isChainsaw ? [/^target_username$/i] : [])]) || (isHayabusa ? detect([/^ExtraFieldInfo$/i, /^Details$/i]) : null),
          payload: detect([/^PayloadData1$/i]),
          execInfo: detect([/^ExecutableInfo$/i]),
          details: detect([/^Details$/i, ...(isChainsaw ? [/^Event\.EventData\.Details$/i] : [])]),
          extra: detect([/^ExtraFieldInfo$/i]),
        };

        // Event counts for persistence-relevant EIDs
        if (cols.eventId && meta.colMap[cols.eventId]) {
          const eidSafe = meta.colMap[cols.eventId];
          // Must stay a superset of every event id in EVTX_RULES (plus 4104, which the
          // analyzer queries separately) — an id missing here is invisible in the pre-scan
          // coverage strip AND excluded from the "≈ N events in scope" estimate, so the
          // analyst is told a detection is unavailable when it will in fact fire.
          const uiEids = ["7045","4697","4698","4699","106","129","140","200","141","118","119","5861","19","20","21","13","12","14","11","7","6","25","4720","4728","4732","4756","4724","4738","5136","5137","5141","4104","4657","7040","4702","5001","5007","5010","5012","5101","5857","5858","5860","145","161","169","4624"];
          const eidWhere = wc ? `${wc} AND` : "WHERE";
          const rows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${eidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")}) GROUP BY ${eidSafe}`).all(...params, ...uiEids);
          for (const r of rows) { if (r.eid != null) { const k = String(r.eid).trim(); eventCounts[k] = r.cnt; trackedEvents += r.cnt; } }
        }

        // Column quality — batched on 2000-row sample
        const mappedCols = Object.entries(cols).filter(([, cn]) => cn && meta.colMap[cn]);
        if (mappedCols.length > 0) {
          const caseParts = mappedCols.map(([key, cn]) => `SUM(CASE WHEN ${meta.colMap[cn]} IS NULL OR TRIM(${meta.colMap[cn]}) = '' OR ${meta.colMap[cn]} = '-' THEN 1 ELSE 0 END) as null_${key}`);
          const qr = db.prepare(`SELECT COUNT(*) as total, ${caseParts.join(", ")} FROM (SELECT * FROM data ${wc} LIMIT 2000)`).get(...params);
          const sampleTotal = qr ? qr.total : 0;
          for (const [key] of mappedCols) {
            const nulls = qr ? (qr[`null_${key}`] || 0) : 0;
            columnQuality[key] = { mapped: true, nullRate: sampleTotal > 0 ? Math.round((nulls / sampleTotal) * 100) : 0 };
          }
          for (const [key, cn] of Object.entries(cols)) { if (!cn || !meta.colMap[cn]) columnQuality[key] = { mapped: false }; }
        }

        return { eventCounts, trackedEvents, columnQuality, detectedMode, resolvedColumns: cols, isHayabusa, isChainsaw };

      } else if (detectedMode === "registry") {
        // Plugin CSV: no KeyPath column to LIKE against, so report what the file IS and
        // how many rows will be projected instead of a coverage breakdown that cannot exist.
        if (regPlugin) {
          const r = db.prepare(`SELECT COUNT(*) as cnt FROM data ${wc}`).get(...params);
          const rowCount = r ? r.cnt : 0;
          const plugin = { id: regPlugin.shape.id, label: regPlugin.shape.label, projects: !!regPlugin.shape.projects };
          if (!regPlugin.shape.projects) {
            return {
              eventCounts: {}, trackedEvents: 0, columnQuality: {}, detectedMode: null, registryPlugin: plugin,
              error: `${regPlugin.shape.label} — execution evidence, not persistence keys. Load the RECmd batch output (KeyPath/ValueName) or the Services/TaskCache plugin CSV instead.`,
            };
          }
          return {
            eventCounts: { [regPlugin.shape.label]: rowCount }, trackedEvents: rowCount,
            columnQuality: Object.fromEntries(Object.entries(regPlugin.cols).map(([k, cn]) => [k, { mapped: !!(cn && meta.colMap[cn]) }])),
            detectedMode, registryPlugin: plugin, resolvedColumns: regPlugin.cols, isHayabusa, isChainsaw,
          };
        }

        const cols = {
          keyPath: userCols.keyPath || detect([/^KeyPath$/i, /^Key ?Path$/i]),
          valueName: userCols.valueName || detect([/^ValueName$/i, /^Value ?Name$/i]),
          valueData: userCols.valueData || detect([/^ValueData$/i, /^Value ?Data$/i]),
          hivePath: detect([/^HivePath$/i, /^Hive ?Path$/i]),
          hiveType: detect([/^HiveType$/i, /^Hive ?Type$/i]),
          ts: userCols.ts || detect([/^LastWriteTimestamp$/i, /^Timestamp$/i, /^datetime$/i, /^TimeCreated$/i]),
        };

        // Registry coverage: count rows per group + deduplicated total via single query.
        //
        // These are SQL LIKE patterns, NOT regexes — a backslash is a literal here (SQLite
        // gives LIKE no default escape character). In a JS string literal that means ONE
        // escaped backslash: "%\\Run%" is the pattern %\Run%. Writing "%\\\\Run%" produces
        // %\\Run% — two literal backslashes — which no KeyPath ever contains, so the group
        // permanently counted 0 and trackedEvents was undercounted. Labels must stay in
        // sync with PA_REG_GROUPS in PersistenceModal.jsx (they key the coverage chips).
        const regGroups = [
          { label: "Run Keys", pattern: "%\\Run%" },
          { label: "Services", pattern: "%\\Services\\%" },
          { label: "Winlogon", pattern: "%\\Winlogon%" },
          { label: "IFEO", pattern: "%Image File Execution%" },
          { label: "COM Objects", pattern: "%InprocServer32%" },
          { label: "Scheduled Tasks", pattern: "%TaskCache%" },
          { label: "Boot Execute", pattern: "%Session Manager%" },
          { label: "LSA", pattern: "%\\Lsa%" },
          { label: "Shell Extensions", pattern: "%ShellEx%" },
          { label: "AppInit DLLs", pattern: "%AppInit_DLLs%" },
          { label: "Print Monitors", pattern: "%Print\\Monitors%" },
          { label: "Active Setup", pattern: "%Active Setup%" },
          { label: "BHO", pattern: "%Browser Helper%" },
          { label: "Network Providers", pattern: "%NetworkProvider%" },
          // Groups the modal already renders chips for but the preview never counted.
          { label: "Logon Script", pattern: "%\\Environment%" },
          { label: "AppCert DLLs", pattern: "%AppCertDlls%" },
          { label: "Silent Process Exit", pattern: "%SilentProcessExit%" },
          { label: "Credential Providers", pattern: "%Credential Provider%" },
          { label: "Command Processor", pattern: "%Command Processor%" },
          { label: "Explorer Autoruns", pattern: "%ShellServiceObjectDelayLoad%" },
          { label: "Netsh Helper DLLs", pattern: "%\\Microsoft\\Netsh%" },
          { label: "Screensaver", pattern: "%Control Panel\\Desktop%" },
          { label: "Office Add-ins", pattern: "%\\Addins\\%" },
          { label: "Time Providers", pattern: "%TimeProviders%" },
          { label: "Terminal Server", pattern: "%Terminal Server\\%" },
          { label: "File Association", pattern: "%shell\\open\\command%" },
          { label: "Group Policy Scripts", pattern: "%\\Scripts\\%" },
          { label: "Security Support Provider", pattern: "%SecurityProviders%" },
          { label: "COM TreatAs", pattern: "%\\TreatAs%" },
          { label: "Defender Tampering", pattern: "%Windows Defender\\%" },
        ];
        if (cols.keyPath && meta.colMap[cols.keyPath]) {
          const kpSafe = meta.colMap[cols.keyPath];
          const wcAnd = wc ? `${wc} AND` : "WHERE";
          // Per-group counts
          for (const g of regGroups) {
            const r = db.prepare(`SELECT COUNT(*) as cnt FROM data ${wcAnd} ${kpSafe} LIKE ?`).get(...params, g.pattern);
            eventCounts[g.label] = r ? r.cnt : 0;
          }
          // Deduplicated total: count rows matching ANY persistence pattern
          const anyMatch = regGroups.map(() => `${kpSafe} LIKE ?`).join(" OR ");
          const totalR = db.prepare(`SELECT COUNT(*) as cnt FROM data ${wcAnd} (${anyMatch})`).get(...params, ...regGroups.map(g => g.pattern));
          trackedEvents = totalR ? totalR.cnt : 0;
        }

        // Column quality
        const mappedCols = Object.entries(cols).filter(([, cn]) => cn && meta.colMap[cn]);
        if (mappedCols.length > 0) {
          const caseParts = mappedCols.map(([key, cn]) => `SUM(CASE WHEN ${meta.colMap[cn]} IS NULL OR TRIM(${meta.colMap[cn]}) = '' OR ${meta.colMap[cn]} = '-' THEN 1 ELSE 0 END) as null_${key}`);
          const qr = db.prepare(`SELECT COUNT(*) as total, ${caseParts.join(", ")} FROM (SELECT * FROM data ${wc} LIMIT 2000)`).get(...params);
          const sampleTotal = qr ? qr.total : 0;
          for (const [key] of mappedCols) {
            const nulls = qr ? (qr[`null_${key}`] || 0) : 0;
            columnQuality[key] = { mapped: true, nullRate: sampleTotal > 0 ? Math.round((nulls / sampleTotal) * 100) : 0 };
          }
          for (const [key, cn] of Object.entries(cols)) { if (!cn || !meta.colMap[cn]) columnQuality[key] = { mapped: false }; }
        }

        return { eventCounts, trackedEvents, columnQuality, detectedMode, resolvedColumns: cols, isHayabusa, isChainsaw };
      }

      return { eventCounts: {}, trackedEvents: 0, columnQuality: {}, detectedMode: null, error: "Cannot detect data type" };
    } catch (e) {
      return { eventCounts: {}, columnQuality: {}, error: e.message };
    }
}

/**
 * Persistence Analyzer — scans EVTX or registry data for persistence mechanisms
 */
function getPersistenceAnalysis(meta, options = {}, ctx) {
    if (!meta) return { items: [], stats: {}, error: "Tab not found" };
    const { db, headers } = meta;
    const detect = (pats) => { for (const p of pats) { const f = headers.find(h => p.test(h)); if (f) return f; } return null; };

    // Auto-detect data mode
    const isChainsaw = isChainsawDataset(meta);
    const hasEventId = detect([/^EventI[dD]$/i, /^event_id$/i, ...(isChainsaw ? [/^id$/i] : [])]);
    const hasKeyPath = detect([/^KeyPath$/i, /^Key ?Path$/i]);
    const hasValueName = detect([/^ValueName$/i, /^Value ?Name$/i]);
    const isHayabusa = isHayabusaDataset(meta);

    // RECmd per-plugin detail CSVs carry no KeyPath/ValueName pair — they are a projected
    // view of one key family. Recognize them so the richest registry artifact in a parsed
    // KAPE package stops dead-ending on "Cannot detect data type".
    const regPlugin = (hasKeyPath && hasValueName) ? null : detectRegistryPlugin(headers, detect);

    let mode = options.mode || "auto";
    if (mode === "auto") {
      mode = (hasKeyPath && hasValueName) ? "registry"
        : hasEventId ? "evtx"
          : regPlugin ? "registry" : null;
    }
    if (!mode) return { items: [], stats: {}, error: "Cannot detect data type. Need EventID column (EVTX) or KeyPath column (Registry)." };
    if (mode === "registry" && regPlugin && !regPlugin.shape.projects) {
      return {
        items: [], incidents: [], warnings: [], stats: {}, detectedMode: null,
        error: `${regPlugin.shape.label} — this is execution evidence (program run history), which contains no persistence keys. Load the RECmd batch output (KeyPath/ValueName columns) or the Services/TaskCache plugin CSV instead.`,
      };
    }

    // --- Detection rules ---
    // EVTX_RULES / REGISTRY_RULES live in ./rules.js so the renderer's rule catalog can be
    // derived from the same arrays the engine runs (see PERSISTENCE_RULE_CATALOG).

    // --- Apply user rule customization ---
    const disabledRules = new Set(options.disabledRules || []);
    let activeEvtxRules = EVTX_RULES.filter((_, i) => !disabledRules.has(`evtx-${i}`));
    let activeRegRules = REGISTRY_RULES.filter((_, i) => !disabledRules.has(`reg-${i}`));

    if (options.customRules?.length) {
      for (const cr of options.customRules) {
        if (cr.type === "evtx") {
          // payloadFilter is user-supplied — compile via the ReDoS-safe guard. A
          // provided-but-rejected (unsafe/invalid) filter disables the rule rather than
          // throwing (old behavior) or silently matching everything.
          let payloadFilter = null;
          if (cr.payloadFilter) {
            payloadFilter = _safeRule(cr.payloadFilter);
            if (!payloadFilter) continue;
          }
          activeEvtxRules.push({
            category: cr.category || "Custom",
            name: cr.name || "Custom Rule",
            eventIds: (cr.eventIds || "").split(",").map(s => s.trim()).filter(Boolean),
            channels: (cr.channels || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean),
            severity: cr.severity || "medium",
            extractors: {},
            topFields: [],
            payloadFilter,
          });
        } else if (cr.type === "registry") {
          const keyPathPattern = _safeRule(cr.keyPathPattern || ".*");
          if (!keyPathPattern) continue; // unsafe/invalid key-path pattern → skip rule
          let valueNameFilter = null;
          if (cr.valueNameFilter) {
            valueNameFilter = _safeRule(cr.valueNameFilter);
            if (!valueNameFilter) continue;
          }
          activeRegRules.push({
            category: cr.category || "Custom",
            name: cr.name || "Custom Rule",
            severity: cr.severity || "medium",
            description: cr.description || "User-defined rule",
            keyPathPattern,
            valueNameFilter,
          });
        }
      }
    }

    // --- Column mapping ---
    const userCols = options.columns || {};
    let columns;
    if (mode === "evtx") {
      columns = {
        eventId: userCols.eventId || detect([/^EventI[dD]$/i, /^event_id$/i, ...(isChainsaw ? [/^id$/i] : [])]),
        channel: userCols.channel || detect([/^Channel$/i, /^SourceName$/i, /^Provider$/i]),
        ts: userCols.ts || detect([/^TimeCreated$/i, /^datetime$/i, /^UtcTime$/i, /^Timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
        computer: userCols.computer || detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, ...(isChainsaw ? [/^computer_name$/i] : [])]),
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
        user: userCols.user || detect([/^UserName$/i, /^User$/i, ...(isChainsaw ? [/^target_username$/i] : [])]) || (isHayabusa ? detect([/^ExtraFieldInfo$/i, /^Details$/i]) : null),
        targetObject: detect([/^TargetObject$/i, /^target_object$/i, /^Event\.EventData\.TargetObject$/i]),
        targetFilename: detect([/^TargetFilename$/i, /^Event\.EventData\.TargetFilename$/i]),
        image: detect([/^Image$/i, /^process_name$/i, /^Event\.EventData\.Image$/i, /^image$/i]),
        cmdLine: detect([/^CommandLine$/i, /^command_line$/i, /^Event\.EventData\.CommandLine$/i]),
        workstation: detect([/^WorkstationName$/i, /^workstation_name$/i]),
        source: detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^source_ip$/i]),
        logonType: detect([/^LogonType$/i, /^logon_type$/i]),
      };
      // Raw-EVTX EventData fields referenced by detection rules. These resolve to null
      // for EvtxECmd/Hayabusa/Chainsaw (which pack everything into payload/details), so
      // only the app's own raw-EVTX parser output gains these columns. Selecting them
      // routes values into row[key] → buildEvtxHaystack so payloadFilter-gated rules
      // (Sysmon 6/7 signature checks, AD 5136/5137/5141, Security 4657) can match.
      for (const def of RAW_EVTX_HAYSTACK_FIELDS) {
        if (!columns[def.key]) columns[def.key] = detect(def.aliases);
      }
    } else {
      columns = {
        keyPath: userCols.keyPath || detect([/^KeyPath$/i, /^Key ?Path$/i]),
        valueName: userCols.valueName || detect([/^ValueName$/i, /^Value ?Name$/i]),
        valueData: userCols.valueData || detect([/^ValueData$/i, /^Value ?Data$/i]),
        valueData2: detect([/^ValueData2$/i]),
        valueData3: detect([/^ValueData3$/i]),
        valueType: detect([/^ValueType$/i, /^Value ?Type$/i]),
        hivePath: detect([/^HivePath$/i, /^Hive ?Path$/i]),
        // HiveType is what makes a hive-relative KeyPath ("ROOT\ControlSet001\Services\X")
        // resolvable to a canonical root without guessing from the file path.
        hiveType: detect([/^HiveType$/i, /^Hive ?Type$/i]),
        computer: userCols.computer || detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, /^MachineName$/i]),
        ts: userCols.ts || detect([/^LastWriteTimestamp$/i, /^Timestamp$/i, /^datetime$/i, /^TimeCreated$/i]),
      };
      // Plugin CSV: pull in that shape's own columns so projectPluginRows() can rebuild
      // the {keyPath, valueName, valueData} triple the rules match on.
      if (regPlugin) {
        for (const [key, colName] of Object.entries(regPlugin.cols)) {
          if (colName && !columns[key]) columns[key] = colName;
        }
      }
    }

    // --- Build SQL query ---
    const params = [];
    const whereConditions = [];

    // EVTX pre-filter: only relevant Event IDs
    const ALL_EVTX_EIDS = [...new Set(activeEvtxRules.flatMap(r => r.eventIds))];
    if (mode === "evtx" && columns.eventId) {
      const safeEid = meta.colMap[columns.eventId];
      if (safeEid) {
        whereConditions.push(`${safeEid} IN (${ALL_EVTX_EIDS.map(() => "?").join(",")})`);
        params.push(...ALL_EVTX_EIDS);
      }
    }

    // Apply standard filters
    ctx.applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    // Non-EID scope filters (column, checkbox, date, bookmark, search, advanced) — reused by correlation queries
    // The first condition may be an EID IN(...) pre-filter when mode=evtx; skip it to get only analyst scope filters
    const _eidCondCount = (mode === "evtx" && columns.eventId && meta.colMap[columns.eventId]) ? 1 : 0;
    const scopeConditions = whereConditions.slice(_eidCondCount);
    const scopeParams = params.slice(_eidCondCount ? ALL_EVTX_EIDS.length : 0);

    const selectParts = ["data.rowid as _rowid"];
    for (const [key, colName] of Object.entries(columns)) {
      if (colName && meta.colMap[colName]) selectParts.push(`${meta.colMap[colName]} as [${key}]`);
    }

    const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
    const orderClause = orderCol ? `ORDER BY ${orderCol} ASC, data.rowid ASC` : "ORDER BY data.rowid ASC";

    // --- Normalization helpers for correlation ---
    const _normSvcName = (s) => (s || "").replace(/"/g, "").trim().toLowerCase();
    // Well-known Windows service name <-> display name aliases (7036 uses display name, 7045 uses service name)
    const SVC_DISPLAY_ALIASES = {
      "termservice": "remote desktop services", "remote desktop services": "termservice",
      "mpssvc": "windows defender firewall", "windows defender firewall": "mpssvc",
      "windefend": "microsoft defender antivirus service", "microsoft defender antivirus service": "windefend",
      "wuauserv": "windows update", "windows update": "wuauserv",
      "bits": "background intelligent transfer service", "background intelligent transfer service": "bits",
      "spooler": "print spooler", "print spooler": "spooler",
      "winmgmt": "windows management instrumentation", "windows management instrumentation": "winmgmt",
      "schedule": "task scheduler", "task scheduler": "schedule",
      "eventlog": "windows event log", "windows event log": "eventlog",
      "lanmanserver": "server", "lanmanworkstation": "workstation",
      "server": "lanmanserver", "workstation": "lanmanworkstation",
      "w32time": "windows time", "windows time": "w32time",
      "dnscache": "dns client", "dns client": "dnscache",
      "cryptsvc": "cryptographic services", "cryptographic services": "cryptsvc",
      "samss": "security accounts manager", "security accounts manager": "samss",
      "netlogon": "netlogon", "lmhosts": "tcp/ip netbios helper", "tcp/ip netbios helper": "lmhosts",
      "winsock": "winsock", "rpcss": "remote procedure call (rpc)", "remote procedure call (rpc)": "rpcss",
      "plugplay": "plug and play", "plug and play": "plugplay",
      "themes": "themes", "appinfo": "application information", "application information": "appinfo",
    };
    const _parseExePath = (cmd) => {
      if (!cmd) return null;
      const c = cmd.replace(/^"|"$/g, "").trim();
      if (!c) return null;
      const quoted = cmd.match(/^"([^"]+)"/);
      const imagePath = (quoted ? quoted[1] : c.split(/\s+/)[0]).trim();
      const imageBase = imagePath.split("\\").pop().toLowerCase();
      return { fullCmd: c, imagePath: imagePath.toLowerCase(), imageBase };
    };
    const COMMON_SYSTEM_BINS = new Set([
      "svchost.exe", "rundll32.exe", "dllhost.exe", "msiexec.exe",
      "taskhostw.exe", "conhost.exe", "lsass.exe", "csrss.exe",
      "smss.exe", "services.exe", "winlogon.exe", "explorer.exe",
      "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
      "cscript.exe", "mshta.exe", "regsvr32.exe", "wuauclt.exe",
      "spoolsv.exe", "searchindexer.exe", "wmiprvse.exe",
    ]);
    const CORR_WINDOW = 3600000;       // 60 min
    const CORR_WINDOW_EXT = 43200000;  // 12 hours (lower confidence)
    const _withinWindow = (ts1, ts2, window) => {
      // parseTimestampMs treats naive timestamps as UTC (project convention) — consistent
      // with the rest of the app and correct for mixed tz-aware/naive correlation inputs.
      const d1 = parseTimestampMs(ts1), d2 = parseTimestampMs(ts2);
      if (d1 == null || d2 == null || isNaN(d1) || isNaN(d2)) return false;
      const diff = d2 - d1;
      return diff >= 0 && diff <= window;
    };
    const _withinWindowBidi = (ts1, ts2, window) => _withinWindow(ts1, ts2, window) || _withinWindow(ts2, ts1, window);
    // Canonical host key for correlation — see analyzers/persistence/incidents.js.
    const _corrHost = corrHost;
    const _corrUser = (value) => cleanWrappedField(value);

    // --- PowerShell 4104 Script Block persistence patterns ---
    const PS_4104_PATTERNS = [
      { category: "Scheduled Tasks", name: "PS Task Creation",
        pattern: /(?:Register-ScheduledTask|New-ScheduledTask|schtasks\s*(?:\.exe)?\s*\/create)/i,
        extractName: /(?:Register-ScheduledTask|New-ScheduledTask)\s[^|]*?(?:-TaskName|-tn)\s+["']?([^\s"'|]+)/i },
      { category: "Services", name: "PS Service Creation",
        pattern: /(?:New-Service|sc(?:\.exe)?\s+create|Set-Service|Set-ItemProperty\s[^|]*?\\Services\\)/i,
        extractName: /(?:New-Service\s[^|]*?-Name\s+["']?([^\s"'|]+)|sc(?:\.exe)?\s+create\s+["']?([^\s"'|]+))/i },
      { category: "Registry Autorun", name: "PS Registry Autorun",
        pattern: /(?:Set-ItemProperty|New-ItemProperty|reg\s+add)\s[^|]*?\\(?:Run|RunOnce)(?:\\|["'\s]|$)/i,
        extractName: /\\(Run(?:Once)?)/i },
      { category: "WMI Persistence", name: "PS WMI Persistence",
        pattern: /(?:Register-WmiEvent|Set-WmiInstance|Register-CimIndicationEvent|__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding)/i,
        extractName: /(?:-Name\s+["']?([^\s"'|]+)|__EventFilter.*?Name\s*=\s*["']?([^\s"'|]+))/i },
      { category: "Startup Folder", name: "PS Startup Folder Write",
        pattern: /(?:Copy-Item|Move-Item|Out-File|Set-Content|Add-Content|New-Item)\s[^|]*?(?:Start\s*Menu\\Programs\\Startup|\\Startup\\)/i,
        extractName: null },
      { category: "IFEO", name: "PS IFEO/AppInit Modification",
        pattern: /(?:Image\s+File\s+Execution\s+Options|AppInit_DLLs)/i,
        extractName: /Image\s+File\s+Execution\s+Options\\([^\s"'\\]+)/i },
    ];
    const PS_4104_SUSPICIOUS_INDICATORS = [
      { pattern: /-(?:Encoded)?Command\s|-[eE]nc?\s|-[eE]\s/i, label: "EncodedCommand" },
      { pattern: /\[Convert\]::FromBase64String|FromBase64/i, label: "FromBase64String" },
      // Bare `.Invoke(` removed — it matches any benign delegate/scriptblock/WPF call (e.g.
      // `$sb.Invoke()`), flipping automation scripts to suspicious on a single low-fidelity hit.
      // Keep Invoke-Expression and word-boundary `iex ` (the actual IEX-execution indicators).
      { pattern: /Invoke-Expression|\biex\s/i, label: "Invoke-Expression" },
      { pattern: /DownloadString|DownloadFile|DownloadData/i, label: "DownloadString" },
      { pattern: /Net\.WebClient|System\.Net\.WebClient|New-Object\s+Net\.WebClient/i, label: "Net.WebClient" },
      { pattern: /Start-BitsTransfer|BitsTransfer/i, label: "Start-BitsTransfer" },
      { pattern: /Invoke-WebRequest|wget\s|curl\s|iwr\s/i, label: "Web download" },
      { pattern: /\[Reflection\.Assembly\]::Load|Assembly\.Load/i, label: "Assembly loading" },
      { pattern: /Add-MpPreference\s[^|]*?-ExclusionPath/i, label: "Defender exclusion" },
      { pattern: /Set-MpPreference\s[^|]*?-DisableRealtimeMonitoring/i, label: "Defender disable" },
    ];
    const PS_4104_ALLOWLIST_PATHS = /(?:Microsoft\\Configuration\s*Manager|SCCM|CCM\\|Intune\\|Microsoft\s+Intune|sysvol\\|Group\s*Policy|\\Policies\\|Windows\s*Defender\\|MpCmdRun|AMSI|Sophos\\|CrowdStrike\\|SentinelOne\\|CarbonBlack\\|Cortex\s*XDR)/i;
    const PS_4104_ALLOWLIST_SCRIPTS = /(?:(?:Microsoft|Windows)\\(?:Azure|Intune|SCCM|ConfigMgr)|(?:chocolatey|nuget|pester|psake|platyPS|PSReadLine|PackageManagement|PowerShellGet)\\)/i;

    // Multi-source mode hands the engine an already-merged, already-aliased row set from
    // several tabs (see ./multi-source.js). There is no single `db` to query then, so every
    // query site below reads from this array instead. Rows carry the same alias names the
    // SELECT would have produced, plus _sourceTab/_sourceTabId provenance.
    const _prequeried = Array.isArray(options._prequeriedRows) ? options._prequeriedRows : null;
    const _eidOf = (row) => String(row?.eventId ?? "").trim();
    // Carry the source tab onto every finding it produced. In a merged run `rowid` alone is
    // ambiguous — each tab's rowids start at 1 — so the tab id is what makes a finding
    // navigable back to the grid it came from. A no-op for single-tab analysis.
    const _provenance = (row) => (row?._sourceTabId
      ? { _sourceTab: row._sourceTab, _sourceTabId: row._sourceTabId, _sourceRowId: row._sourceRowId, _sourceFormat: row._sourceFormat }
      : null);

    try {
      const maxRows = 500000;
      let rows;
      if (_prequeried) {
        // The SQL path pre-filters on the active rules' event ids; do the same in memory so
        // correlation-only ids (7036/7035/1/4688/4104) don't become findings.
        const wanted = new Set(ALL_EVTX_EIDS);
        rows = mode === "evtx" ? _prequeried.filter((r) => wanted.has(_eidOf(r))) : _prequeried;
      } else {
        const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${maxRows}`;
        rows = db.prepare(sql).all(...params);
      }

      let items = [];
      const warnings = [];
      // Registry-mode provenance, surfaced in stats so the analyst can see WHERE the host
      // attribution came from and which plugin shape was projected.
      let registryHost = "";
      let registryHostSource = "none";
      let registryPluginInfo = null;
      let registryInventorySuppressed = 0;
      // Remote arrivals seen in this scan: inbound network/RDP logons and remote WMI/WinRM
      // operations. A multi-source run analyzes EVTX and registry in separate passes, so
      // the EVTX pass hands its arrivals to the registry pass through `_remoteLogons` —
      // otherwise a Run value written over an RDP session could never be attributed.
      const remoteLogons = Array.isArray(options._remoteLogons) ? [...options._remoteLogons] : [];
      const LOLBIN_PAT = /(?:powershell|pwsh|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|msiexec|forfiles|cmstp|hh\.exe|odbcconf|regasm|regsvcs|installutil|pcalua|msconfig|msbuild|xwizard|presentationhost|ieexec|control\.exe)/i;
      let ps4104CorrelatedCount = 0;
      const ps4104Reassembled = [];
      const ps4104ByTask = {}, ps4104BySvc = {}, ps4104ByRegKey = {}, ps4104ByWmi = {};

      if (mode === "evtx") {
        // Build EID->rules lookup map for O(1) rule dispatch per row
        // instead of iterating all ~30 rules for every row
        const eidRuleMap = new Map();
        for (const rule of activeEvtxRules) {
          for (const eid of rule.eventIds) {
            if (!eidRuleMap.has(eid)) eidRuleMap.set(eid, []);
            eidRuleMap.get(eid).push(rule);
          }
        }

        // Pre-hoist constant regex (avoid re-creation per row)
        const RMM_PATTERNS = /anydesk|splashtop|rustdesk|atera|screenconnect|teamviewer|supremo|connectwise|bomgar|logmein/i;

        for (const row of rows) {
          const eid = String(row.eventId || "").trim();
          // O(1) lookup: skip rows whose EID has no matching rules
          const rulesForEid = eidRuleMap.get(eid);
          if (!rulesForEid) continue;

          const haystack = buildEvtxHaystack(row);
          const compact = parseCompactKeyValues(row.details, row.extra);
          const rowChannel = resolveEventChannel(row);
          const eventUser = (() => {
            const rawUser = row.user || compactGet(compact, "SubjectUserName", "TargetUserName", "TgtUser", "User", "SrcUser");
            const cleaned = rawUser && rawUser.includes("\\") ? rawUser.split("\\").pop() : rawUser;
            return cleanWrappedField(cleaned);
          })();
          for (const rule of rulesForEid) {
            // Channel filter: rule.channels contains substrings to match (e.g., "system", "security", "taskscheduler", "sysmon")
            if (rule.channels && !evtxChannelMatches(rowChannel, rule.channels)) continue;
            if (rule.payloadFilter && !rule.payloadFilter.test(haystack)) continue;

            const details = {};
            for (const [field, patterns] of Object.entries(rule.extractors || {})) {
              for (const pat of patterns) {
                const m = haystack.match(pat);
                if (m) { details[field] = m[1].trim(); break; }
              }
            }

            // Pull ExecutableInfo column directly into named field as fallback
            // useExecInfo can be true (maps to "executable") or a string (specific field name)
            if (rule.useExecInfo && row.execInfo) {
              const targetField = typeof rule.useExecInfo === "string" ? rule.useExecInfo : "executable";
              if (!details[targetField]) {
                details[targetField] = row.execInfo.trim();
              }
            }

            // Build summary from topFields (most relevant info first), fall back to raw payload
            let detailsSummary = "";
            const topFields = rule.topFields || Object.keys(rule.extractors || {});
            const topParts = topFields.map((f) => details[f] ? `${f}: ${details[f]}` : null).filter(Boolean);
            if (topParts.length > 0) {
              detailsSummary = topParts.join(" | ");
            } else {
              // No extractors matched — show raw payload data for context
              detailsSummary = haystack;
            }

            // RMM tool detection for service installs (seen in 7/11 DFIR reports)
            const rmmMatch = (eid === "7045" || eid === "4697") && (RMM_PATTERNS.test(details.serviceName || "") || RMM_PATTERNS.test(details.imagePath || "") || RMM_PATTERNS.test(row.execInfo || ""));
            const tags = rmmMatch ? ["RMM Tool"] : [];

            // Preserve raw payload for task items that need deep XML parsing (4698/4702/140)
            if ((eid === "4698" || eid === "4702" || eid === "140" || eid === "TASKXML") && rule.category === "Scheduled Tasks") {
              details._rawPayload = haystack;
            }

            items.push({
              rowid: row._rowid,
              ..._provenance(row),
              category: rule.category,
              name: rule.name,
              severity: rule.severity,
              description: rule.description,
              timestamp: cleanWrappedField(row.ts || ""),
              computer: cleanWrappedField(row.computer || ""),
              user: eventUser || "",
              source: `EventID ${eid}`,
              details,
              detailsSummary: detailsSummary.substring(0, 400),
              mode: "evtx",
              tags,
              rmmTool: rmmMatch,
            });
          }
        }
        // --- Post-process 4657 items: re-categorize by key path, set confidence ---
        for (const item of items) {
          if (item.name !== "Registry Value Modified (4657)") continue;
          const obj = item.details.targetObject || "";
          const vn = (item.details.valueName || "").toLowerCase();
          const nv = item.details.newValue || "";
          // If key path is missing or looks like a value name (no backslash), mark lower confidence
          if (!obj || !obj.includes("\\")) {
            item.confidence = "present";
            item.severity = "low";
            item.details._is4657Fallback = true;
            item.details._4657NoKeyPath = true;
            if (nv) item.command = nv;
            continue;
          }
          // Re-categorize based on actual key path
          if (/Image File Execution Options/i.test(obj)) {
            item.category = "IFEO"; item.severity = "critical";
          } else if (/AppInit_DLLs|LoadAppInit_DLLs/i.test(obj) || /^appinit_dlls$/i.test(vn)) {
            item.category = "AppInit DLLs"; item.severity = "critical";
          } else if (/\\Winlogon\\(?:Shell|Userinit|Notify)|\\GPExtensions\\/i.test(obj)) {
            item.category = "Winlogon"; item.severity = "critical";
          } else if (/Session Manager\\(?:BootExecute|SetupExecute)/i.test(obj)) {
            item.category = "Boot Execute"; item.severity = "critical";
          } else if (/\\Services\\[^\\]+\\(?:ImagePath|Parameters|ServiceDll|FailureCommand)/i.test(obj)) {
            item.category = "Services"; item.severity = "high";
          } else if (/(?:InprocServer32|LocalServer32|\\TreatAs(?:\\|$))/i.test(obj)) {
            item.category = "COM Hijacking"; item.severity = "high";
          } else if (/Print\\Monitors/i.test(obj)) {
            item.category = "Print Monitors"; item.severity = "high";
          } else if (/\\Lsa\\?$/i.test(obj)) {
            item.category = "LSA"; item.severity = "critical";
          } else if (/Control\\SecurityProviders/i.test(obj)) {
            item.category = "Security Support Provider"; item.severity = "critical";
          } else if (/\\Environment/i.test(obj) && /^cor_(?:profiler|enable_profiling)/i.test(vn)) {
            item.category = "Environment Hijack"; item.severity = "high";
          } else if (/Group Policy\\Scripts|\\System\\Scripts\\/i.test(obj)) {
            item.category = "Group Policy Scripts"; item.severity = "high";
          } else if (/Windows Defender\\Exclusions/i.test(obj)) {
            item.category = "Defender Tampering"; item.severity = "high";
          } else if (/Active Setup/i.test(obj)) {
            item.category = "Active Setup"; item.severity = "high";
          } else if (/NetworkProvider/i.test(obj)) {
            item.category = "Network Providers"; item.severity = "high";
          } else if (/Browser Helper Objects/i.test(obj)) {
            item.category = "BHO"; item.severity = "medium";
          } else if (/SilentProcessExit\\/i.test(obj)) {
            item.category = "Silent Process Exit"; item.severity = "critical";
          } else if (/\\Environment/i.test(obj) && /UserInitMprLogonScript/i.test(vn)) {
            item.category = "Logon Script"; item.severity = "high";
          } else if (/AppCertDlls/i.test(obj)) {
            item.category = "AppCert DLLs"; item.severity = "critical";
          } else if (/Credential Provid/i.test(obj) || /PLAP Providers\\/i.test(obj)) {
            item.category = "Credential Providers"; item.severity = "high";
          } else if (/\\Command Processor/i.test(obj) && /^autorun$/i.test(vn)) {
            item.category = "Command Processor"; item.severity = "high";
          } else if (/ShellServiceObjectDelayLoad/i.test(obj)) {
            item.category = "Explorer Autoruns"; item.severity = "high";
          } else if (/\\Microsoft\\Netsh/i.test(obj)) {
            item.category = "Netsh Helper DLLs"; item.severity = "high";
          } else if (/Control Panel\\Desktop/i.test(obj) && /^scrnsave\.exe$/i.test(vn)) {
            item.category = "Screensaver"; item.severity = "high";
          } else if (/Office\\[^\\]+\\[^\\]+\\Addins\\/i.test(obj)) {
            item.category = "Office Add-ins"; item.severity = "high";
          } else if (/W32Time\\TimeProviders\\/i.test(obj) && /^dllname$/i.test(vn)) {
            item.category = "Time Providers"; item.severity = "critical";
          } else if (/Terminal Server\\/i.test(obj) && /^(?:initialprogram|finheritinitialprog)/i.test(vn)) {
            item.category = "Terminal Server"; item.severity = "critical";
          } else if (/shell\\open\\command/i.test(obj) || /FileExts\\/i.test(obj)) {
            item.category = "File Association"; item.severity = "high";
          }
          // Set baseline confidence (lower than Sysmon 13)
          item.confidence = "likely";
          item.details._is4657Fallback = true;
          // Upgrade confidence on strong semantics
          const _nvHasLolbin = LOLBIN_PAT.test(nv);
          const _nvHasEncoded = /(?:base64|frombase64|-enc\s|-e\s|iex|invoke-expression|downloadstring|downloadfile|webclient|bitstransfer)/i.test(nv);
          if (_nvHasLolbin || _nvHasEncoded) item.confidence = "confirmed";
          if (/^debugger$/i.test(vn) && item.category === "IFEO") item.confidence = "confirmed";
          if (/^(appinit_dlls|loadappinit_dlls)$/i.test(vn)) item.confidence = "confirmed";
          if (/^(shell|userinit)$/i.test(vn) && item.category === "Winlogon") item.confidence = "confirmed";
          if (/^monitorprocess$/i.test(vn) && item.category === "Silent Process Exit") item.confidence = "confirmed";
          if (/^userinitmprologonscript$/i.test(vn) && item.category === "Logon Script") item.confidence = "confirmed";
          if (item.category === "AppCert DLLs" && nv) item.confidence = "confirmed";
          if (/^autorun$/i.test(vn) && item.category === "Command Processor") item.confidence = "confirmed";
          if (item.category === "Netsh Helper DLLs" && nv) item.confidence = "confirmed";
          if (/^scrnsave\.exe$/i.test(vn) && item.category === "Screensaver" && nv) item.confidence = "confirmed";
          if (/^dllname$/i.test(vn) && item.category === "Time Providers" && nv) item.confidence = "confirmed";
          if (/^initialprogram$/i.test(vn) && item.category === "Terminal Server" && nv) item.confidence = "confirmed";
          // Map targetObject to artifact field for consistent display
          if (!item.artifact) item.artifact = obj;
          if (!item.command && nv) item.command = nv;
        }
      } else {
        // Registry mode
        //
        // A plugin CSV is a projected view of one key family — rebuild the
        // {keyPath, valueName, valueData} triple the rules are written against.
        const regRows = regPlugin ? projectPluginRows(regPlugin, rows) : rows;
        if (regPlugin) {
          registryPluginInfo = { id: regPlugin.shape.id, label: regPlugin.shape.label };
          if (regRows.length === 0 && rows.length > 0) {
            warnings.push(`${regPlugin.shape.label}: ${rows.length} rows carried no projectable values — check the plugin CSV's column names.`);
          }
        }

        // --- Host attribution (registry tabs carry no Computer column) ---
        // Precedence: an explicit column, then the machine name read straight out of the
        // SYSTEM hive, then the KAPE collection path. Only the last is a guess, and items
        // attributed that way are flagged so the analyst can tell.
        const _explicitHost = cleanWrappedField(regRows.find((r) => r.computer)?.computer || "");
        // The ComputerName patterns are suffix-anchored, so they match the RAW key path in
        // every shape — no need to canonicalize a second time over what can be 500K rows.
        const _hiveHost = _explicitHost ? "" : cleanWrappedField(hostFromComputerNameKey(regRows, {
          keyPathOf: (r) => r.keyPath,
          valueNameOf: (r) => r.valueName,
          valueDataOf: (r) => [r.valueData, r.valueData2, r.valueData3].filter(Boolean).join(" "),
        }));
        let _pathHost = "";
        if (!_explicitHost && !_hiveHost) {
          // Every row in a tab comes from the same collection, so the first resolvable hive
          // path settles it; bound the scan so an export with no HivePath column can't walk
          // the whole row set for nothing.
          const _hostProbe = Math.min(regRows.length, 1000);
          for (let i = 0; i < _hostProbe; i++) {
            _pathHost = deriveCollectionHost(regRows[i].hivePath);
            if (_pathHost) break;
          }
        }
        // Last resort: ask the same collection-host detector lateral movement uses, rather
        // than growing a second notion of "which machine is this tab about". It reads the
        // Computer column's distribution, so it only helps when the tab HAS one — but on a
        // merged EVTX+registry scan that is exactly the case, and it means both analyzers
        // agree on the host a finding belongs to.
        let _detectedHost = "";
        if (!_explicitHost && !_hiveHost && !_pathHost && meta?.db) {
          try {
            const { detectKapeCollectionHost } = require("../lateral-movement/kape-host");
            const detected = detectKapeCollectionHost(meta);
            if (detected?.collectionHost && detected.confidence !== "low") _detectedHost = detected.collectionHost;
          } catch { /* optional enrichment — never fail the scan over it */ }
        }

        const _optHost = cleanWrappedField(options.computerName || "");
        registryHost = _optHost || _explicitHost || _hiveHost || _pathHost || _detectedHost || "";
        registryHostSource = _optHost ? "user"
          : _explicitHost ? "column"
            : _hiveHost ? "system-hive"
              : _pathHost ? "collection-path"
                : _detectedHost ? "collection-host-detection" : "none";
        const _hostInferred = registryHostSource === "collection-path";

        for (const row of regRows) {
          // Fold RECmd/Registry Explorer/raw-hive shapes onto one canonical path BEFORE
          // rule matching — hive-relative "ROOT\ControlSet001\Services\X" carries no
          // \SYSTEM\ segment, so the Services rule matched nothing on a RECmd export.
          const rawKp = row.keyPath || "";
          const kp = canonicalizeKeyPath(rawKp, { hiveType: row.hiveType, hivePath: row.hivePath }) || rawKp;
          const vn = row.valueName || "";
          const vd = [row.valueData, row.valueData2, row.valueData3].filter(Boolean).join(" ");
          const hiveCtx = hiveContext(row.hivePath, row.hiveType);

          for (const rule of activeRegRules) {
            if (!rule.keyPathPattern.test(kp)) continue;
            if (rule.valueNameFilter && !rule.valueNameFilter.test(vn)) continue;

            const details = {
              keyPath: kp, valueName: vn, valueData: vd,
              hivePath: row.hivePath || "", hiveScope: hiveCtx.hiveScope,
            };
            if (rawKp && rawKp !== kp) details.keyPathRaw = rawKp;
            if (row.hiveType) details.hiveType = row.hiveType;
            if (_hostInferred && registryHost) details._hostInferred = true;
            // A plugin CSV is a snapshot of current STATE, not a record of a change: every
            // host yields hundreds of rows. Flag them so scoring/suppression can treat them
            // as inventory to hunt through rather than observed modifications.
            if (row._inventory) {
              details._registryInventory = true;
              details._registrySource = row._pluginLabel || row._plugin;
            }
            for (const [k, v] of Object.entries(row)) {
              if (k.startsWith("_plugin") && v !== undefined && k !== "_plugin" && k !== "_pluginLabel") details[k] = v;
            }
            if (row._taskRegHasActions) details._taskRegHasActions = true;

            items.push({
              rowid: row._rowid,
              ..._provenance(row),
              category: rule.category,
              name: rule.name,
              severity: rule.severity,
              description: rule.description,
              timestamp: row.ts || "",
              computer: registryHost,
              user: cleanWrappedField(row.user || "") || hiveCtx.user,
              source: row._pluginLabel || "Registry",
              details,
              detailsSummary: `${vn}: ${vd}`.substring(0, 300),
              mode: "registry",
            });
          }
        }
      }

      // --- Cross-event correlation: enrich Task Registered/Updated with executable from Task Process Created/Action Started ---
      if (mode === "evtx") {
        const taskExecMap = {};
        for (const item of items) {
          if ((item.name === "Task Process Created" || item.name === "Task Action Started") && item.details.executable && item.details.taskName) {
            const tn = item.details.taskName;
            if (!taskExecMap[tn] || item.name === "Task Process Created") taskExecMap[tn] = item.details.executable;
          }
        }
        for (const item of items) {
          if ((item.name === "Task Registered" || item.name === "Task Updated" || item.name === "Task Updated (Security)") && !item.details.executable && item.details.taskName) {
            const exec = taskExecMap[item.details.taskName];
            if (exec) {
              item.details.executable = exec;
              // Rebuild summary with executable
              const topParts = ["taskName", "executable"].map((f) => item.details[f] ? `${f}: ${item.details[f]}` : null).filter(Boolean);
              if (topParts.length > 0) item.detailsSummary = topParts.join(" | ").substring(0, 400);
            }
          }
        }

        // --- Deep task XML semantics: parse hidden flag, run level, COM handler, trigger types ---
        // Works on 4698 (Task Created), 4702 (Task Updated Security), 140 (Task Updated Operational)
        for (const item of items) {
          if (item.category !== "Scheduled Tasks") continue;
          if (item.name !== "Scheduled Task Created" && item.name !== "Task Updated (Security)" && item.name !== "Task Updated" && item.name !== "Scheduled Task Defined") continue;
          // Prefer raw payload (full event text) over reduced summary for XML field extraction
          const raw = item.details._rawPayload || "";
          const fallback = (item.detailsSummary || "") + " " + JSON.stringify(item.details || {});
          const blob = raw || fallback;
          const hasRaw = !!raw;
          // Hidden flag: <Hidden>true</Hidden> or Hidden: true
          if (/<hidden>\s*true/i.test(blob) || /Hidden:\s*true/i.test(blob)) {
            item.details._taskHidden = true;
          }
          // Run level: <RunLevel>HighestAvailable</RunLevel> or RunLevel: HighestAvailable/LeastPrivilege
          const rlM = blob.match(/<RunLevel>\s*(\w+)/i) || blob.match(/RunLevel:\s*(\w+)/i);
          if (rlM) {
            item.details._taskRunLevel = rlM[1];
            if (/highest/i.test(rlM[1])) item.details._taskElevated = true;
          }
          // COM handler: <ComHandler> or ClassId: {GUID}
          if (/<ComHandler>/i.test(blob) || /ClassId:\s*\{[0-9a-f-]+\}/i.test(blob)) {
            item.details._taskComHandler = true;
          }
          // Trigger types: extract from <Triggers> block or flattened fields
          const triggers = [];
          if (/<BootTrigger>/i.test(blob) || /BootTrigger/i.test(blob))                   triggers.push("boot");
          if (/<LogonTrigger>/i.test(blob) || /LogonTrigger/i.test(blob))                 triggers.push("logon");
          if (/<RegistrationTrigger>/i.test(blob) || /RegistrationTrigger/i.test(blob))   triggers.push("registration");
          if (/<TimeTrigger>/i.test(blob) || /TimeTrigger/i.test(blob))                   triggers.push("time");
          if (/<CalendarTrigger>/i.test(blob) || /CalendarTrigger/i.test(blob))           triggers.push("calendar");
          if (/<IdleTrigger>/i.test(blob) || /IdleTrigger/i.test(blob))                   triggers.push("idle");
          if (/<EventTrigger>/i.test(blob) || /EventTrigger/i.test(blob))                 triggers.push("event");
          if (/<SessionStateChangeTrigger>/i.test(blob))                                   triggers.push("session");
          if (triggers.length > 0) item.details._taskTriggers = triggers;
          // Principal: extract UserId/GroupId if present
          const princM = blob.match(/<UserId>\s*([^<]+)/i) || blob.match(/UserId:\s*(\S+)/i);
          if (princM) item.details._taskPrincipal = princM[1].trim();
          // Extract action command from XML/flattened task content when the event payload includes task XML.
          const cmdM = blob.match(/<Command>\s*([^<]+)/i) || blob.match(/Command:\s*(.+?)(?:\s*\||\s*$)/i);
          const argM = blob.match(/<Arguments>\s*([^<]+)/i) || blob.match(/Arguments:\s*(.+?)(?:\s*\||\s*$)/i);
          if (cmdM) {
            const cmd = cmdM[1].trim();
            const args = argM ? argM[1].trim() : "";
            if (!item.details.executable) item.details.executable = cmd;
            if (!item.details.command) item.details.command = args ? `${cmd} ${args}`.trim() : cmd;
          }
          // Track whether we parsed from raw payload or partial text
          const anyFound = item.details._taskHidden || item.details._taskElevated || item.details._taskComHandler || (triggers.length > 0) || item.details._taskPrincipal || item.details.command || item.details.executable;
          if (anyFound && !hasRaw) item.details._taskXmlPartial = true;
          if (item.details.taskName && (item.details.command || item.details.executable)) {
            const topParts = ["taskName", "command", "executable"].map((f) => item.details[f] ? `${f}: ${item.details[f]}` : null).filter(Boolean);
            if (topParts.length > 0) item.detailsSummary = topParts.join(" | ").substring(0, 400);
          }
          // Clean up raw payload to avoid it leaking to frontend detail panel
          delete item.details._rawPayload;
        }

        // --- Correlation query: fetch EID 7036/7035 (service state), Sysmon 1 (proc create), 4688 (proc create) ---
        const svcStartEvents = [];
        const svcControlEvents = []; // 7035: service control manager requests (start/stop)
        const procStartEvents = [];
        // 4624 is here for ORIGIN, not for detection: an inbound network (type 3) or RDP
        // (type 10) logon shortly before a service/task/autorun appears is what makes that
        // artifact attributable to a remote actor rather than to the console user.
        const CORR_EIDS = ["7036", "7035", "1", "4688", "4624"];
        // This is the single most consequential query in the analyzer: it is what turns a
        // 7045 service install from "present" into "confirmed". On raw KAPE triage the
        // corroborating events live in OTHER files — 4688 in Security.evtx, Sysmon 1 in
        // the Sysmon channel — so a single-tab run can never find them. In multi-source
        // mode they are already in the merged set.
        if (_prequeried || (columns.eventId && meta.colMap[columns.eventId])) {
          const corrSet = new Set(CORR_EIDS);
          let corrSql = null, corrParams = null;
          if (!_prequeried) {
            const safeEidCol = meta.colMap[columns.eventId];
            const corrWhere = [`${safeEidCol} IN (${CORR_EIDS.map(() => "?").join(",")})`, ...scopeConditions];
            corrParams = [...CORR_EIDS, ...scopeParams];
            corrSql = `SELECT ${selectParts.join(", ")} FROM data WHERE ${corrWhere.join(" AND ")} ${orderClause} LIMIT 200000`;
          }
          try {
            const corrRows = _prequeried
              ? _prequeried.filter((r) => corrSet.has(_eidOf(r)))
              : db.prepare(corrSql).all(...corrParams);
            for (const row of corrRows) {
              const eid = String(row.eventId || "").trim();
              const ch = resolveEventChannel(row);
              const haystack = buildEvtxHaystack(row);
              // System 7036: service entered running state
              if (eid === "7036" && evtxChannelMatches(ch, ["system"])) {
                const m = haystack.match(/(?:param1|ServiceName|Service Name):\s*(.+?)(?:\s*$|\s*\|)/i);
                const isRunning = /running/i.test(haystack);
                if (m && isRunning) {
                  const rawName = _normSvcName(m[1]);
                  const aliasName = SVC_DISPLAY_ALIASES[rawName] || null;
                  svcStartEvents.push({ svcName: rawName, aliasName, timestamp: row.ts || "", computer: _corrHost(row.computer || "") });
                }
              }
              // System 7035: service control request (start/stop/pause)
              if (eid === "7035" && evtxChannelMatches(ch, ["system"])) {
                const m = haystack.match(/(?:param1|ServiceName|Service Name):\s*(.+?)(?:\s*$|\s*\|)/i);
                const ctrlM = haystack.match(/(?:param2|Control):\s*(.+?)(?:\s*$|\s*\|)/i);
                if (m) {
                  const rawName = _normSvcName(m[1]);
                  const aliasName = SVC_DISPLAY_ALIASES[rawName] || null;
                  const controlType = (ctrlM ? ctrlM[1].trim().toLowerCase() : "");
                  svcControlEvents.push({ svcName: rawName, aliasName, controlType, timestamp: row.ts || "", computer: _corrHost(row.computer || "") });
                }
              }
              // Sysmon 1: process creation
              if (eid === "1" && evtxChannelMatches(ch, ["sysmon"])) {
                const imgM = haystack.match(/Image:\s*(.+?)(?:\s*$|\s*\|)/i);
                const parM = haystack.match(/ParentImage:\s*(.+?)(?:\s*$|\s*\|)/i);
                if (imgM) {
                  const p = _parseExePath(imgM[1]);
                  const pp = parM ? _parseExePath(parM[1]) : null;
                  if (p) procStartEvents.push({ ...p, parentImage: pp?.imagePath || "", parentBase: pp?.imageBase || "", timestamp: row.ts || "", computer: _corrHost(row.computer || "") });
                }
              }
              // Security 4688: process creation
              if (eid === "4688" && evtxChannelMatches(ch, ["security"])) {
                const imgM = haystack.match(/(?:NewProcessName|Process Name|New Process Name):\s*(.+?)(?:\s*$|\s*\|)/i);
                const parM = haystack.match(/(?:ParentProcessName|Creator Process Name):\s*(.+?)(?:\s*$|\s*\|)/i);
                if (imgM) {
                  const p = _parseExePath(imgM[1]);
                  const pp = parM ? _parseExePath(parM[1]) : null;
                  if (p) procStartEvents.push({ ...p, parentImage: pp?.imagePath || "", parentBase: pp?.imageBase || "", timestamp: row.ts || "", computer: _corrHost(row.computer || "") });
                }
              }
              // Security 4624: inbound logon. ONLY network (3) and RemoteInteractive (10)
              // are remote arrivals — 2 is the console, 5 is a service start, 7 is unlock.
              if (eid === "4624" && evtxChannelMatches(ch, ["security"])) {
                const lt = extractFirstInteger(
                  (haystack.match(/(?:^|\b)LogonType:\s*(.+?)(?:\s*$|\s*[|¦])/i) || [])[1] || "",
                );
                if (lt === "3" || lt === "10") {
                  const grab = (re) => (haystack.match(re) || [])[1]?.trim() || "";
                  const ip = grab(/(?:^|\b)IpAddress:\s*(.+?)(?:\s*$|\s*[|¦])/i);
                  const wks = grab(/(?:^|\b)WorkstationName:\s*(.+?)(?:\s*$|\s*[|¦])/i);
                  // "-", "::1" and 127.0.0.1 are the local machine talking to itself.
                  const remoteIp = /^(?:-|::1|127\.0\.0\.1|0\.0\.0\.0)?$/.test(ip) ? "" : ip;
                  const remoteWks = _corrHost(wks);
                  const target = _corrHost(row.computer || "");
                  if ((remoteIp || (remoteWks && remoteWks !== target))) {
                    remoteLogons.push({
                      target,
                      sourceHost: remoteWks && remoteWks !== target ? remoteWks : "",
                      sourceIp: remoteIp,
                      user: cleanWrappedField(grab(/(?:^|\b)TargetUserName:\s*(.+?)(?:\s*$|\s*[|¦])/i)),
                      logonId: grab(/(?:^|\b)TargetLogonId:\s*(.+?)(?:\s*$|\s*[|¦])/i),
                      logonType: lt,
                      timestamp: row.ts || "",
                      via: lt === "10" ? "RDP logon (4624 type 10)" : "network logon (4624 type 3)",
                    });
                  }
                }
              }
            }
          } catch (_corrErr) { /* correlation query may fail on non-EVTX datasets — silently skip */ }
        }

        // Remote-execution FINDINGS double as arrivals: WMI 5858/5860 names the calling
        // machine outright, so it is a pivot source in its own right even with no 4624.
        for (const item of items) {
          if (item.category !== "Remote Execution") continue;
          const client = _corrHost(item.details?.clientMachine || "");
          const target = _corrHost(item.computer || "");
          if (!client || client === target) continue;
          remoteLogons.push({
            target,
            sourceHost: client,
            sourceIp: "",
            user: item.details?.remoteUser || "",
            logonId: "",
            logonType: "",
            timestamp: item.timestamp || "",
            via: item.name === "WinRM Remote Session" ? "WinRM session" : "WMI remote operation",
          });
        }

        // --- PowerShell 4104 Script Block Logging: separate query + fragment reassembly ---
        const ps4104Fragments = [];
        if (_prequeried || (columns.eventId && meta.colMap[columns.eventId])) {
          const ps4104MaxRows = Math.max(10000, Math.min(Number(options.ps4104MaxRows) || 250000, 1000000));
          const ps4104PageSize = Math.max(1000, Math.min(Number(options.ps4104PageSize) || 20000, 100000));
          // PowerShell%4Operational.evtx is its own file, so on raw KAPE a single-tab run
          // never sees the script block that created the task/service it is scoring.
          const _prequeried4104 = _prequeried ? _prequeried.filter((r) => _eidOf(r) === "4104") : null;
          let ps4104Where = null, ps4104Params = null;
          if (!_prequeried) {
            const safeEidCol = meta.colMap[columns.eventId];
            ps4104Where = [`${safeEidCol} IN (?)`, ...scopeConditions];
            ps4104Params = ["4104", ...scopeParams];
          }
          try {
            let lastRid = 0;
            let fetched = 0;
            while (fetched < ps4104MaxRows) {
              const chunk = Math.min(ps4104PageSize, ps4104MaxRows - fetched);
              const ps4104Rows = _prequeried4104
                ? _prequeried4104.slice(fetched, fetched + chunk)
                : db.prepare(`SELECT ${selectParts.join(", ")} FROM data WHERE ${ps4104Where.join(" AND ")} AND data.rowid > ? ORDER BY data.rowid ASC LIMIT ${chunk}`).all(...ps4104Params, lastRid);
              if (ps4104Rows.length === 0) break;
              for (const row of ps4104Rows) {
                const ch = resolveEventChannel(row);
                if (!evtxChannelMatches(ch, ["powershell"])) continue;
                const haystack = buildEvtxHaystack(row);
                const scriptTextM = haystack.match(/ScriptBlockText:\s*(.+?)(?:\s*\||\s*$)/i);
                const scriptIdM = haystack.match(/ScriptBlockId:\s*([0-9a-f-]+)/i);
                const msgNumM = haystack.match(/MessageNumber:\s*(\d+)/i);
                const msgTotalM = haystack.match(/MessageTotal:\s*(\d+)/i);
                const pathM = haystack.match(/Path:\s*(.+?)(?:\s*\||\s*$)/i);
                const hostAppM = haystack.match(/HostApplication:\s*(.+?)(?:\s*\||\s*$)/i);
                ps4104Fragments.push({
                  rowid: row._rowid, scriptBlockId: scriptIdM ? scriptIdM[1].toLowerCase() : `orphan-${row._rowid}`,
                  messageNumber: msgNumM ? parseInt(msgNumM[1], 10) : 1, messageTotal: msgTotalM ? parseInt(msgTotalM[1], 10) : 1,
                  scriptText: scriptTextM ? scriptTextM[1] : "", path: pathM ? pathM[1].trim() : "",
                  hostApplication: hostAppM ? hostAppM[1].trim() : (row.execInfo || "").trim(),
                  timestamp: row.ts || "", computer: _corrHost(row.computer || ""), user: _corrUser(row.user || ""),
                });
              }
              fetched += ps4104Rows.length;
              lastRid = Number(ps4104Rows[ps4104Rows.length - 1]._rowid || lastRid);
              if (ps4104Rows.length < chunk) break;
            }
            if (fetched >= ps4104MaxRows) warnings.push(`PowerShell 4104 scan hit configured limit ${ps4104MaxRows} — increase options.ps4104MaxRows for fuller coverage.`);
          } catch (_ps4104Err) { warnings.push("PowerShell 4104 query failed: " + _ps4104Err.message); }
        }

        // --- 4104 Fragment Reassembly ---
        {
          const PS4104_TIME_GAP = 300000; // 5 min — separate executions of the same script block
          const fragGroups = {};
          for (const frag of ps4104Fragments) {
            const gk = `${frag.scriptBlockId}|${frag.computer}|${frag.user}`;
            if (!fragGroups[gk]) fragGroups[gk] = [];
            fragGroups[gk].push(frag);
          }
          // Helper: process a single run of fragments into a reassembled object (or skip)
          const _processRun = (frags) => {
            frags.sort((a, b) => a.messageNumber - b.messageNumber);
            const fullText = frags.map(f => f.scriptText).join("");
            const first = frags[0];
            const path = frags.find(f => f.path)?.path || "";
            const hostApp = frags.find(f => f.hostApplication)?.hostApplication || "";
            const matchedPatterns = [];
            let matchedCategory = null, matchedName = null, extractedArtifactName = null;
            for (const pat of PS_4104_PATTERNS) {
              if (pat.pattern.test(fullText)) {
                matchedPatterns.push(pat.name);
                if (!matchedCategory) { matchedCategory = pat.category; matchedName = pat.name; }
                if (pat.extractName) { const nameM = fullText.match(pat.extractName); if (nameM) extractedArtifactName = (nameM[1] || nameM[2] || "").trim(); }
              }
            }
            if (matchedPatterns.length === 0) return;
            const suspiciousIndicators = [];
            for (const ind of PS_4104_SUSPICIOUS_INDICATORS) { if (ind.pattern.test(fullText)) suspiciousIndicators.push(ind.label); }
            const isMgmtAllowlisted = PS_4104_ALLOWLIST_PATHS.test(path) || PS_4104_ALLOWLIST_PATHS.test(hostApp) || PS_4104_ALLOWLIST_SCRIPTS.test(path);
            // Keep allowlisted management scripts only when they still carry suspicious indicators.
            if (isMgmtAllowlisted && suspiciousIndicators.length === 0) return;
            ps4104Reassembled.push({
              scriptBlockId: first.scriptBlockId, computer: first.computer, user: first.user,
              timestamp: first.timestamp, path, hostApplication: hostApp, fullText,
              fragmentCount: frags.length, firstRowid: first.rowid,
              matchedCategory: matchedCategory || "PowerShell Persistence", matchedName: matchedName || "PowerShell Script Block",
              matchedPatterns, extractedArtifactName, suspiciousIndicators, mgmtAllowlisted: isMgmtAllowlisted,
            });
          };
          for (const [, frags] of Object.entries(fragGroups)) {
            // Sub-split by time gap: same scriptBlockId can represent repeated executions
            frags.sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0) || a.messageNumber - b.messageNumber);
            const runs = [[]];
            for (const frag of frags) {
              const curRun = runs[runs.length - 1];
              if (curRun.length > 0) {
                const prev = curRun[curRun.length - 1];
                // Canonical UTC-aware parse — naive timestamps from non-UTC
                // hosts no longer get host-shifted, which previously caused
                // unrelated 4104 executions to glue into one fragment when
                // the cross-execution gap was exactly the host's UTC offset.
                const prevTs = parseTimestampMs(prev.timestamp);
                const curTs = parseTimestampMs(frag.timestamp);
                const hasTimeGap = prevTs != null && curTs != null && Math.abs(curTs - prevTs) > PS4104_TIME_GAP;
                // Only split on time gap if the current run is complete or the new fragment restarts at 1
                const runComplete = prev.messageNumber >= prev.messageTotal;
                const seqRestart = frag.messageNumber === 1;
                if (hasTimeGap && (runComplete || seqRestart)) {
                  runs.push([]);
                }
              }
              runs[runs.length - 1].push(frag);
            }
            for (const run of runs) _processRun(run);
          }
        }
        if (ps4104Fragments.length === 0 && columns.eventId) {
          warnings.push("No PowerShell 4104 (ScriptBlock) events found — PowerShell-based persistence detection unavailable.");
        }

        // --- Build 4104 correlation indexes ---
        for (const rs of ps4104Reassembled) {
          const host = rs.computer;
          if (rs.matchedCategory === "Scheduled Tasks" && rs.extractedArtifactName) {
            const key = rs.extractedArtifactName.replace(/^\\+/, "").toLowerCase();
            if (!ps4104ByTask[host]) ps4104ByTask[host] = {};
            if (!ps4104ByTask[host][key]) ps4104ByTask[host][key] = [];
            ps4104ByTask[host][key].push(rs);
          }
          if (rs.matchedCategory === "Services" && rs.extractedArtifactName) {
            const key = _normSvcName(rs.extractedArtifactName);
            if (!ps4104BySvc[host]) ps4104BySvc[host] = {};
            if (!ps4104BySvc[host][key]) ps4104BySvc[host][key] = [];
            ps4104BySvc[host][key].push(rs);
          }
          if (rs.matchedCategory === "Registry Autorun") {
            if (!ps4104ByRegKey[host]) ps4104ByRegKey[host] = [];
            ps4104ByRegKey[host].push(rs);
          }
          if (rs.matchedCategory === "WMI Persistence" && rs.extractedArtifactName) {
            const key = rs.extractedArtifactName.toLowerCase().trim();
            if (!ps4104ByWmi[host]) ps4104ByWmi[host] = {};
            if (!ps4104ByWmi[host][key]) ps4104ByWmi[host][key] = [];
            ps4104ByWmi[host][key].push(rs);
          }
        }

        // --- Build correlation indexes ---
        const svcStartByName = {};
        for (const ev of svcStartEvents) {
          if (!svcStartByName[ev.svcName]) svcStartByName[ev.svcName] = [];
          svcStartByName[ev.svcName].push(ev);
          if (ev.aliasName) {
            if (!svcStartByName[ev.aliasName]) svcStartByName[ev.aliasName] = [];
            svcStartByName[ev.aliasName].push(ev);
          }
        }
        const svcControlByName = {};
        for (const ev of svcControlEvents) {
          if (!svcControlByName[ev.svcName]) svcControlByName[ev.svcName] = [];
          svcControlByName[ev.svcName].push(ev);
          if (ev.aliasName) {
            if (!svcControlByName[ev.aliasName]) svcControlByName[ev.aliasName] = [];
            svcControlByName[ev.aliasName].push(ev);
          }
        }
        const procStartByPath = {};
        const procStartByBase = {};
        for (const ev of procStartEvents) {
          if (ev.imagePath) { if (!procStartByPath[ev.imagePath]) procStartByPath[ev.imagePath] = []; procStartByPath[ev.imagePath].push(ev); }
          if (ev.imageBase && !COMMON_SYSTEM_BINS.has(ev.imageBase)) { if (!procStartByBase[ev.imageBase]) procStartByBase[ev.imageBase] = []; procStartByBase[ev.imageBase].push(ev); }
        }

        // --- Collect existing evidence from persistence items ---
        const loadedDlls = new Set();
        for (const item of items) {
          if (item.name === "Unsigned DLL Loaded" && item.details.imageLoaded) {
            loadedDlls.add(item.details.imageLoaded.toLowerCase().replace(/"/g, "").trim());
          }
        }
        const svcRegMods = new Set();
        for (const item of items) {
          if (item.name === "Registry Value Set" && item.details.targetObject) {
            const m = item.details.targetObject.match(/\\Services\\([^\\]+)/i);
            if (m) svcRegMods.add(m[1].toLowerCase());
          }
        }

        // --- Service execution correlation: multi-source (7036 + 7035 + Sysmon 1 + 4688 + DLL + registry) ---
        for (const item of items) {
          if (item.category !== "Services" || (item.name !== "Service Installed" && item.name !== "Service StartType Changed")) continue;
          const sn = _normSvcName(item.details.serviceName);
          const exe = _parseExePath(item.details.imagePath || item.details.serviceFile);
          const host = _corrHost(item.computer);
          const ts = item.timestamp;

          // 1. Service start (7036 running) — same host, within time window
          //    Try direct name first, then display-name alias fallback
          let starts = (svcStartByName[sn] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW));
          let _svcDisplayNameMatch = false;
          if (starts.length === 0 && sn) {
            const alias = SVC_DISPLAY_ALIASES[sn];
            if (alias) {
              starts = (svcStartByName[alias] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW));
              if (starts.length > 0) _svcDisplayNameMatch = true;
            }
          }
          let startsExt = [];
          if (starts.length === 0) {
            startsExt = (svcStartByName[sn] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW_EXT));
            if (startsExt.length === 0 && sn) {
              const alias = SVC_DISPLAY_ALIASES[sn];
              if (alias) {
                startsExt = (svcStartByName[alias] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW_EXT));
                if (startsExt.length > 0) _svcDisplayNameMatch = true;
              }
            }
          }

          // 2. Process start (Sysmon 1 / 4688) — full path first, basename fallback
          let procMatches = [];
          if (exe) {
            procMatches = (procStartByPath[exe.imagePath] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW));
            if (procMatches.length === 0 && exe.imageBase && !COMMON_SYSTEM_BINS.has(exe.imageBase)) {
              procMatches = (procStartByBase[exe.imageBase] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW));
            }
          }

          // 3. Existing evidence (registry tamper, DLL loads)
          const regMatch = sn && svcRegMods.has(sn);
          const dllMatch = exe?.imagePath && loadedDlls.has(exe.imagePath);

          // Assign confidence tier + enrichment
          const bestProc = procMatches[0];
          const parentIsServices = bestProc?.parentBase === "services.exe";
          const parentSuspicious = bestProc && !parentIsServices && bestProc.parentBase && bestProc.parentBase !== "";

          if (starts.length > 0) {
            item.confidence = _svcDisplayNameMatch ? "likely" : "confirmed";
            item.details._serviceStarted = true;
            item.details._serviceStartTs = starts[0].timestamp;
            if (_svcDisplayNameMatch) item.details._svcDisplayNameMatch = true;
          } else if (startsExt.length > 0) {
            item.confidence = "likely";
            item.details._serviceStarted = true;
            item.details._serviceStartTs = startsExt[0].timestamp;
            if (_svcDisplayNameMatch) item.details._svcDisplayNameMatch = true;
          } else if (bestProc && parentIsServices) {
            item.confidence = "confirmed";
            item.details._serviceProcessStarted = true;
            item.details._serviceProcessTs = bestProc.timestamp;
            item.details._serviceProcessParent = bestProc.parentImage;
          } else if (bestProc) {
            item.confidence = "likely";
            item.details._serviceProcessStarted = true;
            item.details._serviceProcessTs = bestProc.timestamp;
            item.details._serviceProcessParent = bestProc.parentImage;
            if (parentSuspicious) item.details._serviceProcessParentSuspicious = true;
          } else if (regMatch || dllMatch) {
            item.confidence = "likely";
            item.details._serviceExecSeen = true;
          } else {
            item.confidence = "present";
          }
          // 7035: supplementary service control correlation (only start-like controls strengthen confidence)
          const ctrlHits = (svcControlByName[sn] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW));
          if (ctrlHits.length > 0) {
            const startLike = ctrlHits.filter(e => /start/i.test(e.controlType));
            const stopLike = ctrlHits.filter(e => /stop|pause|disabled/i.test(e.controlType));
            if (startLike.length > 0) {
              item.details._svcControlSeen = true;
              item.details._svcControlType = startLike[0].controlType;
              // Upgrade "present" -> "likely" only when a start request corroborates
              if (item.confidence === "present") item.confidence = "likely";
            }
            if (stopLike.length > 0) {
              item.details._svcControlStopSeen = true;
            }
          }
        }

        // --- WMI field normalization: parse raw CIM blobs into clean analyst-readable fields ---
        {
          const _parseCimBlob = (raw) => {
            if (!raw) return {};
            const out = {};
            // CIM instance type: "instance of CommandLineEventConsumer"
            const typeM = raw.match(/instance\s+of\s+(\w+)/i);
            if (typeM) out.type = typeM[1];
            // Name property
            const nameM = raw.match(/Name\s*=\s*"([^"]+)"/i);
            if (nameM) out.name = nameM[1];
            // CommandLineEventConsumer fields
            const cmdM = raw.match(/CommandLineTemplate\s*=\s*"([^"]+)"/i);
            if (cmdM) out.command = cmdM[1];
            const exeM = raw.match(/ExecutablePath\s*=\s*"([^"]+)"/i);
            if (exeM) out.command = out.command ? `${exeM[1]} ${out.command}` : exeM[1];
            // ActiveScriptEventConsumer fields
            const scriptFileM = raw.match(/ScriptFileName\s*=\s*"([^"]+)"/i);
            if (scriptFileM) out.command = scriptFileM[1];
            const scriptTextM = raw.match(/ScriptText\s*=\s*"([^"]+)"/i);
            if (scriptTextM) out.command = out.command || scriptTextM[1].substring(0, 300);
            return out;
          };
          // Parse WMI object path format: "TypeName.Name=\"value\""
          const _parseWmiObjPath = (raw) => {
            if (!raw) return {};
            const m = raw.match(/(\w+)\.Name\s*=\s*"([^"]+)"/i);
            return m ? { type: m[1], name: m[2] } : {};
          };

          for (const item of items) {
            if (item.category !== "WMI Persistence") continue;
            const d = item.details;

            if (item.name === "WMI Event Subscription") {
              // EID 5861: consumer field has full CIM blob
              const parsed = _parseCimBlob(d.consumer || "");
              if (parsed.type) d._wmiType = parsed.type;
              if (parsed.name) d._wmiName = parsed.name;
              if (parsed.command) d._wmiCommand = parsed.command;
              if (d.query && !d._wmiQuery) d._wmiQuery = d.query;
            } else if (item.name === "WMI EventFilter Created") {
              // Sysmon 19: name is already clean
              d._wmiType = "__EventFilter";
              if (d.name) d._wmiName = d.name;
              if (d.query) d._wmiQuery = d.query;
            } else if (item.name === "WMI EventConsumer Created") {
              // Sysmon 20: name/type/destination are clean
              if (d.type) d._wmiType = d.type;
              if (d.name) d._wmiName = d.name;
              if (d.destination) d._wmiCommand = d.destination;
            } else if (item.name === "WMI Binding Created") {
              // Sysmon 21: consumer/filter in WMI object path format
              const cParsed = _parseWmiObjPath(d.consumer);
              const fParsed = _parseWmiObjPath(d.filter);
              d._wmiType = "Binding";
              d._wmiName = cParsed.name || fParsed.name || "";
              if (cParsed.type) d._wmiConsumerType = cParsed.type;
              if (fParsed.name) d._wmiFilterName = fParsed.name;
            }
          }
        }

        // --- WMI subscription correlation: link Sysmon EID 19 (Filter), 20 (Consumer), 21 (Binding) ---
        {
          const wmiMap = {}; // normalized name -> { filter: bool, consumer: bool, binding: bool, destination: string }
          const _normWmi = (s) => (s || "").replace(/"/g, "").trim().toLowerCase();
          for (const item of items) {
            if (item.category !== "WMI Persistence") continue;
            let compName = null;
            if (item.name === "WMI EventFilter Created") {
              compName = _normWmi(item.details._wmiName);
              if (compName) { if (!wmiMap[compName]) wmiMap[compName] = {}; wmiMap[compName].filter = true; }
            } else if (item.name === "WMI EventConsumer Created") {
              compName = _normWmi(item.details._wmiName);
              if (compName) {
                if (!wmiMap[compName]) wmiMap[compName] = {};
                wmiMap[compName].consumer = true;
                if (item.details._wmiCommand) wmiMap[compName].destination = item.details._wmiCommand;
              }
            } else if (item.name === "WMI Binding Created") {
              // Binding: use normalized names from parsed object paths
              const cName = _normWmi(item.details._wmiName);
              const fName = _normWmi(item.details._wmiFilterName);
              for (const n of [cName, fName]) {
                if (n) { if (!wmiMap[n]) wmiMap[n] = {}; wmiMap[n].binding = true; }
              }
            }
          }
          // Enrich WMI items with completeness info
          for (const item of items) {
            if (item.category !== "WMI Persistence") continue;
            const compName = _normWmi(item.details._wmiName || "");
            const info = compName ? wmiMap[compName] : null;
            if (info) {
              const hasAll = !!(info.filter && info.consumer && info.binding);
              item.details._wmiComplete = hasAll;
              item.details._wmiPartial = !hasAll;
              if (info.destination) item.details._wmiLinkedCommand = info.destination;
              item.confidence = hasAll ? "confirmed" : "likely";
            }
          }
        }

        // --- Registry autorun execution correlation: check if autorun value-data executables appear elsewhere ---
        {
          // Build set of all observed executable paths from item details
          const execPaths = new Set();
          const _normPath = (p) => { const parsed = _parseExePath(p); return parsed ? parsed.imagePath : ""; };
          for (const item of items) {
            const d = item.details;
            for (const f of [d.executable, d.command, d.serviceFile, d.imagePath, d.image, d.imageLoaded, d.targetFilename]) {
              const np = _normPath(f);
              if (np && np.length > 3) execPaths.add(np);
            }
          }
          // Check Registry Autorun (EID 13) value data against execPaths + process start events
          for (const item of items) {
            if (item.category === "Registry Autorun" && item.details.details) {
              const vd = _normPath(item.details.details);
              const host = _corrHost(item.computer);
              if (vd && (execPaths.has(vd) || (procStartByPath[vd] || []).some(e => e.computer === host))) {
                item.details._execSeen = true;
                item.confidence = "confirmed";
              }
            }
          }
        }
      }

      // --- 4104 Correlation: enrich existing items + create standalone items ---
      const _correlated4104Ids = new Set();
      if (ps4104Reassembled.length > 0) {
        // 5a. Enrich Scheduled Task items
        for (const item of items) {
          if (item.category !== "Scheduled Tasks" || (item.name !== "Task Registered" && item.name !== "Scheduled Task Created")) continue;
          const tn = (item.details.taskName || "").replace(/^\\+/, "").toLowerCase();
          if (!tn) continue;
          const host = _corrHost(item.computer);
          const candidates = (ps4104ByTask[host] || {})[tn]
            || Object.values(ps4104ByTask[host] || {}).find(arr => arr[0] && tn.endsWith(arr[0].extractedArtifactName?.replace(/^\\+/, "").toLowerCase() || "__"))
            || [];
          const match = (Array.isArray(candidates) ? candidates : []).find(rs => _withinWindow(item.timestamp, rs.timestamp, CORR_WINDOW_EXT) || _withinWindow(rs.timestamp, item.timestamp, CORR_WINDOW_EXT));
          if (match) {
            item.details._ps4104Seen = true;
            item.details._ps4104ScriptPath = match.path;
            item.details._ps4104ScriptBlockId = match.scriptBlockId;
            item.details._ps4104SuspiciousIndicators = match.suspiciousIndicators;
            item.confidence = "confirmed";
            _correlated4104Ids.add(match.scriptBlockId);
          }
        }
        // 5b. Enrich Service Installed items
        for (const item of items) {
          if (item.category !== "Services" || item.name !== "Service Installed") continue;
          const sn = _normSvcName(item.details.serviceName);
          if (!sn) continue;
          const host = _corrHost(item.computer);
          const candidates = (ps4104BySvc[host] || {})[sn] || [];
          const match = candidates.find(rs => _withinWindow(item.timestamp, rs.timestamp, CORR_WINDOW_EXT) || _withinWindow(rs.timestamp, item.timestamp, CORR_WINDOW_EXT));
          if (match) {
            item.details._ps4104Seen = true;
            item.details._ps4104ScriptPath = match.path;
            item.details._ps4104ScriptBlockId = match.scriptBlockId;
            item.details._ps4104SuspiciousIndicators = match.suspiciousIndicators;
            if (item.confidence !== "confirmed") item.confidence = "likely";
            _correlated4104Ids.add(match.scriptBlockId);
          }
        }
        // 5c. Enrich WMI Persistence items
        for (const item of items) {
          if (item.category !== "WMI Persistence") continue;
          const wn = (item.details.name || item.details.consumer || item.details.filter || "").toLowerCase().trim();
          if (!wn) continue;
          const host = _corrHost(item.computer);
          const candidates = (ps4104ByWmi[host] || {})[wn] || [];
          const match = candidates.find(rs => _withinWindow(item.timestamp, rs.timestamp, CORR_WINDOW_EXT) || _withinWindow(rs.timestamp, item.timestamp, CORR_WINDOW_EXT));
          if (match) {
            item.details._ps4104Seen = true;
            item.details._ps4104ScriptPath = match.path;
            item.details._ps4104ScriptBlockId = match.scriptBlockId;
            item.details._ps4104SuspiciousIndicators = match.suspiciousIndicators;
            if (item.confidence !== "confirmed") item.confidence = "likely";
            _correlated4104Ids.add(match.scriptBlockId);
          }
        }
        // 5d. Enrich Registry Autorun items (key-family-aware: match Run<->Run, RunOnce<->RunOnce, IFEO<->IFEO, etc.)
        const _regKeyFamily = (targetObj) => {
          if (!targetObj) return null;
          const m = targetObj.match(/\\(Run(?:Once)?|RunServices|AppInit_DLLs|Image File Execution Options(?:\\[^\\]+)?|Winlogon\\(?:Shell|Userinit|Notify)|Session Manager\\(?:BootExecute|SetupExecute)|Active Setup|Print\\Monitors|NetworkProvider)(?:\\|$)/i);
          return m ? m[1].toLowerCase().replace(/\\.+$/, "") : null;
        };
        for (const item of items) {
          if (item.category !== "Registry Autorun") continue;
          const host = _corrHost(item.computer);
          const candidates = ps4104ByRegKey[host] || [];
          const itemKeyFamily = _regKeyFamily(item.details.targetObject);
          const match = candidates.find(rs => {
            if (!(_withinWindow(item.timestamp, rs.timestamp, CORR_WINDOW_EXT) || _withinWindow(rs.timestamp, item.timestamp, CORR_WINDOW_EXT))) return false;
            // Key family check: script's extractedArtifactName (Run/RunOnce) or fullText must reference the same key family
            if (!itemKeyFamily) return true; // no key family extractable -> allow loose match
            const scriptKeyRef = (rs.extractedArtifactName || "").toLowerCase();
            if (scriptKeyRef && itemKeyFamily.startsWith(scriptKeyRef)) return true;
            // Fallback: check if the script's full text mentions the target key family
            return new RegExp(itemKeyFamily.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i").test(rs.fullText);
          });
          if (match) {
            item.details._ps4104Seen = true;
            item.details._ps4104ScriptPath = match.path;
            item.details._ps4104ScriptBlockId = match.scriptBlockId;
            item.details._ps4104SuspiciousIndicators = match.suspiciousIndicators;
            if (item.confidence !== "confirmed") item.confidence = "likely";
            _correlated4104Ids.add(match.scriptBlockId);
          }
        }
        // 5e. Standalone items for uncorrelated scripts
        for (const rs of ps4104Reassembled) {
          if (_correlated4104Ids.has(rs.scriptBlockId)) continue;
          const indSet = new Set(rs.suspiciousIndicators || []);
          const strongPs4104 = indSet.size >= 2
            || rs.matchedPatterns.length >= 2
            || indSet.has("Defender exclusion")
            || indSet.has("Defender disable")
            || (indSet.has("EncodedCommand") && (indSet.has("DownloadString") || indSet.has("Net.WebClient") || indSet.has("Web download")));
          if (!strongPs4104 && indSet.size === 0) continue;
          const scriptPreview = rs.fullText.substring(0, 500);
          items.push({
            category: rs.matchedCategory,
            name: rs.matchedName,
            severity: strongPs4104 ? "critical" : "high",
            source: "EventID 4104",
            confidence: strongPs4104 ? "confirmed" : "likely",
            timestamp: rs.timestamp,
            computer: rs.computer,
            user: rs.user,
            artifact: rs.extractedArtifactName || rs.path || rs.hostApplication || "(inline script)",
            command: scriptPreview,
            detailsSummary: (rs.matchedPatterns.join(", ") + (rs.path ? " | " + rs.path : "")).substring(0, 400),
            mode: "evtx",
            details: {
              scriptPath: rs.path,
              hostApplication: rs.hostApplication,
              scriptBlockId: rs.scriptBlockId,
              fragmentCount: rs.fragmentCount,
              matchedPatterns: rs.matchedPatterns,
              scriptPreview,
              extractedArtifactName: rs.extractedArtifactName,
              _ps4104Standalone: true,
              _ps4104Strong: strongPs4104,
              _ps4104SuspiciousIndicators: rs.suspiciousIndicators,
            },
          });
        }
        ps4104CorrelatedCount = _correlated4104Ids.size;
      }

      const BUILTIN_ACCOUNT_PAT = /^(?:system|local service|network service|anonymous logon|defaultaccount|wdagutilityaccount|dwm-\d+|umfd-\d+)$/i;
      const MACHINE_ACCOUNT_PAT = /\$$/;

      // --- Account persistence cross-event correlation: chain 4720->4738->4728/4732/4756->4724 ---
      {
        // Build per-user timeline of account events
        const acctTimeline = {}; // user (lowercase) -> [item, ...]
        const ACCT_NAMES = new Set(["User Account Created", "User Account Changed", "User Password Reset",
          "Member Added to Global Security Group", "Member Added to Local Security Group", "Member Added to Universal Security Group"]);
        for (const item of items) {
          if (item.category !== "Account Persistence" || !ACCT_NAMES.has(item.name)) continue;
          const tgt = (item.details?.targetUser || item.details?.memberName || item.details?.samAccountName || "").toLowerCase();
          if (!tgt || BUILTIN_ACCOUNT_PAT.test(tgt) || MACHINE_ACCOUNT_PAT.test(tgt)) continue;
          if (!acctTimeline[tgt]) acctTimeline[tgt] = [];
          acctTimeline[tgt].push(item);
        }
        // For each user with multiple events, check for chained activity
        for (const [, events] of Object.entries(acctTimeline)) {
          if (events.length < 2) continue;
          const hasCreate = events.some(e => e.name === "User Account Created");
          const hasModify = events.some(e => e.name === "User Account Changed");
          const hasGroupAdd = events.some(e => /Member Added/.test(e.name));
          const hasReset = events.some(e => e.name === "User Password Reset");
          const chainLen = [hasCreate, hasModify, hasGroupAdd, hasReset].filter(Boolean).length;
          if (chainLen >= 2) {
            for (const item of events) {
              item.details._acctChainLen = chainLen;
              item.details._acctChainEvents = [
                hasCreate && "created", hasModify && "modified", hasGroupAdd && "group-add", hasReset && "pw-reset"
              ].filter(Boolean);
              if (item.confidence !== "confirmed") item.confidence = "likely";
            }
          }
        }
      }

      // --- Cross-technique correlation: account event -> persistence mechanism by same user ---
      {
        const ACCT_PERSIST_WINDOW = 3600000; // 60 min
        const PERSIST_CATS = new Set(["Services", "Scheduled Tasks", "WMI Persistence", "Registry Autorun",
          "Winlogon", "IFEO", "AppInit DLLs", "Domain Persistence", "Run Keys", "Startup Folder"]);
        // Build index of account events by subjectUser|computer
        const acctEventsByActor = {}; // "user|host" -> [item, ...]
        for (const item of items) {
          if (item.category !== "Account Persistence") continue;
          const actor = (item.details?.subjectUser || "").toLowerCase();
          const host = _corrHost(item.computer);
          if (!actor || BUILTIN_ACCOUNT_PAT.test(actor) || MACHINE_ACCOUNT_PAT.test(actor)) continue;
          const key = `${actor}|${host}`;
          if (!acctEventsByActor[key]) acctEventsByActor[key] = [];
          acctEventsByActor[key].push(item);
        }
        // For each persistence item, check if same user had a recent account event
        for (const item of items) {
          if (!PERSIST_CATS.has(item.category)) continue;
          // Get the user who performed the persistence action
          const actor = (item.user || item.details?.subjectUser || "").toLowerCase();
          const host = _corrHost(item.computer);
          if (!actor) continue;
          const key = `${actor}|${host}`;
          const acctEvents = acctEventsByActor[key];
          if (!acctEvents || acctEvents.length === 0) continue;
          const itemTs = new Date(item.timestamp).getTime();
          if (isNaN(itemTs)) continue;
          // Find account events within window (account event before or shortly after persistence)
          const matched = acctEvents.filter(ae => {
            const aeTs = new Date(ae.timestamp).getTime();
            return !isNaN(aeTs) && Math.abs(itemTs - aeTs) <= ACCT_PERSIST_WINDOW;
          });
          if (matched.length > 0) {
            const acctTypes = [...new Set(matched.map(ae => ae.name.replace(/^Member Added to \w+ Security Group$/, "group-add")
              .replace("User Account Created", "acct-created").replace("User Password Reset", "pw-reset")
              .replace("User Account Changed", "acct-changed")))];
            item.details._acctToPersistenceSeen = true;
            item.details._acctToPersistenceTypes = acctTypes;
            // Also mark the account events
            for (const ae of matched) {
              ae.details._acctToPersistenceSeen = true;
              ae.details._acctToPersistenceTechnique = item.category;
            }
          }
        }
      }

      // Normalize 4738 account-change fields to avoid key/value bleed-over from loose payload formats.
      const _normalizeAcctField = (v) => {
        let s = String(v || "").trim();
        if (!s) return "";
        // If extractor over-captured multiple fields ("... ScriptPath: X ProfilePath: Y"), keep first field value only.
        s = s.replace(/\s+[A-Za-z][A-Za-z0-9_ ]{1,30}:\s*.*$/, "").trim();
        return s;
      };
      const _isUnsetAcctField = (v) => {
        const s = _normalizeAcctField(v);
        return !s || s === "-" || /^%%\d+$/.test(s) || /^(?:null|n\/a|not\s+set|<not\s+set>)$/i.test(s);
      };
      const _isMeaningfulScriptPath = (v) => {
        const s = _normalizeAcctField(v);
        if (_isUnsetAcctField(s)) return false;
        return /^(?:[a-z]:\\|\\\\)/i.test(s) || /\.(?:bat|cmd|ps1|vbs|js|exe|com)$/i.test(s);
      };
      const _isMeaningfulDelegation = (v) => {
        const s = _normalizeAcctField(v);
        if (_isUnsetAcctField(s)) return false;
        return /[a-z0-9._-]+\/[a-z0-9._-]+/i.test(s);
      };

      // --- Compute artifact + command columns from details ---
      for (const item of items) {
        const d = item.details;
        if (d._ps4104Standalone) {
          item.artifact = d.extractedArtifactName || d.scriptPath || "(inline script)";
          item.command = d.scriptPreview || "";
        } else if (d._is4657Fallback && item.artifact) {
          // 4657 items already have artifact/command set during post-processing
        } else if (item.category === "Domain Persistence") {
          item.artifact = d.objectDN || "";
          item.command = d.attributeName ? `${d.attributeName}: ${d.attributeValue || ""}` : d.objectClass || "";
        } else if (item.name === "User Account Changed") {
          d.scriptPath = _normalizeAcctField(d.scriptPath);
          d.userAccountControl = _normalizeAcctField(d.userAccountControl);
          d.homeDirectory = _normalizeAcctField(d.homeDirectory);
          d.profilePath = _normalizeAcctField(d.profilePath);
          d.userParameters = _normalizeAcctField(d.userParameters);
          d.allowedToDelegateTo = _normalizeAcctField(d.allowedToDelegateTo);
          item.artifact = d.targetUser || d.samAccountName || "";
          item.command = [
            _isMeaningfulScriptPath(d.scriptPath) ? `scriptPath: ${d.scriptPath}` : "",
            !_isUnsetAcctField(d.userAccountControl) ? `UAC: ${d.userAccountControl}` : "",
            _isMeaningfulDelegation(d.allowedToDelegateTo) ? `delegateTo: ${d.allowedToDelegateTo}` : "",
          ].filter(Boolean).join(" | ") || "";
        } else if (item.category === "WMI Persistence") {
          item.artifact = d._wmiName || d.name || "";
          item.command = d._wmiCommand || d._wmiQuery || d.query || d.poss_command || "";
        } else if (item.category === "Remote Execution") {
          // The artifact IS the far end of the connection — that is what an analyst pivots on.
          item.artifact = d.clientMachine || d.remoteUser || d.operation || "";
          item.command = d.operation || d.query || d.resource || "";
        } else if (item.mode === "evtx") {
          item.artifact = d.taskName || d.serviceName || d.targetObject || d.targetFilename || d.name || d.imageLoaded || "";
          item.command = d.executable || d.command || d.serviceFile || d.imagePath || d.image || d.query || d.destination || d.details || "";
        } else {
          item.artifact = d.keyPath || "";
          item.command = d.valueData || "";
        }
      }

      // --- Known AV/EDR whitelist: suppress legitimate security products from expected paths ---
      const AV_EDR_WHITELIST = [
        // Palo Alto / Cortex XDR / Traps
        { namePattern: /^(?:cyvrmtgn|cyverak|cyvrfsfd|tedrdrv|tdevflt|telam|Cortex\s*XDR|Cortex\s*XDR\s*Health\s*Helper|CyMemDef|CyProtectDrv|CyOpticsRuntimeDriver|TrapsSupervisor|PanGPS|PanUpdater)$/i,
          pathPattern: /(?:Palo\s*Alto\s*Networks|Cortex\s*XDR)/i },
        // Microsoft Defender / MpKsl* drivers / MsMpEng / NisSrv
        { namePattern: /^(?:Microsoft\s*Defender|MpDefender|WinDefend|MsMpSvc|NisSrv|MpKsl[0-9a-f]+|WdNisSvc|WdNisDrv|WdFilter|WdBoot|SecurityHealthService|Sense|MsSecCore|Microsoft\s*Defender\s*Core\s*Service)$/i,
          pathPattern: /(?:Windows\s*Defender|Microsoft\s*Defender|Microsoft\\Windows\s*Defender|ProgramData\\Microsoft\\Windows\s*Defender)/i },
        // CrowdStrike Falcon
        { namePattern: /^(?:CSFalcon|CsFalconService|csagent|CSAgent|csdevicecontrol|CrowdStrike|CsInstallerService|CsDisk[A-Z]|CsBoot|CsEFW)$/i,
          pathPattern: /CrowdStrike/i },
        // SentinelOne
        { namePattern: /^(?:SentinelAgent|SentinelOne|SentinelMonitor|SentinelStaticEngine|LogProcessorService|SentinelStaticEngineScanner|SentinelHelperService)$/i,
          pathPattern: /SentinelOne/i },
        // Carbon Black (VMware/Broadcom)
        { namePattern: /^(?:CbDefense|CbDefenseSensor|CarbonBlack|cb\.exe|RepMgr|CbStream|carbonblackk|CbSensor)$/i,
          pathPattern: /(?:CarbonBlack|Carbon\s*Black|Cb\\)/i },
        // Sophos
        { namePattern: /^(?:Sophos|SAVService|SAVAdminService|SophosHealth|SophosCleanup|SophosFileScanner|SophosFS|SophosNtpService|hmpalert|SophosUI)$/i,
          pathPattern: /Sophos/i },
        // Symantec / Broadcom / Norton
        { namePattern: /^(?:SepMaster|SepScan|ccSvcHst|SymCorpUI|SymEFA|Norton|NortonSecurity|smc|SmcService|Symantec|SylinkDrop|ccEvtMgr)$/i,
          pathPattern: /(?:Symantec|Norton|Broadcom)/i },
        // McAfee / Trellix
        { namePattern: /^(?:McAfee|McShield|mfemms|mfefire|mfevtp|TrellixENS|TrellixEDR|masvc|macmnsvc|mfewc|mfetp)$/i,
          pathPattern: /(?:McAfee|Trellix)/i },
        // Kaspersky
        { namePattern: /^(?:AVP|avp|kavsvc|kavfs|klnagent|KAVFS|KESCapability|KLSysEvLog)$/i,
          pathPattern: /Kaspersky/i },
        // ESET
        { namePattern: /^(?:ekrn|ESET|EsetService|ERAAgent|eamonm|ehdrv|epfwwfp|epfw)$/i,
          pathPattern: /ESET/i },
        // Trend Micro
        { namePattern: /^(?:TrendMicro|Ntrtscan|tmlisten|TmFilter|TmPreFilter|ds_agent|Apex\s*One)$/i,
          pathPattern: /(?:Trend\s*Micro|TrendMicro)/i },
        // Bitdefender
        { namePattern: /^(?:EPSecurityService|EPProtectedService|EPUpdateService|EPIntegrationService|EPRedline|BDAuxSrv|TRUFOS|bdservicehost)$/i,
          pathPattern: /Bitdefender/i },
        // Cylance (BlackBerry)
        { namePattern: /^(?:CylanceSvc|CylanceUI|CylanceDrv|CylanceProtect|CyOptics)$/i,
          pathPattern: /Cylance/i },
        // Elastic Agent / Endpoint Security
        { namePattern: /^(?:elastic-agent|elastic-endpoint|ElasticEndpoint|winlogbeat|filebeat)$/i,
          pathPattern: /(?:Elastic|elastic)/i },
        // Fortinet FortiClient / FortiEDR
        { namePattern: /^(?:FortiClient|FortiEDR|FortiGate|FA_Scheduler|FortiClientProductUpdate)$/i,
          pathPattern: /Fortinet/i },
      ];

      // --- Risk scoring + suspicious detection ---
      // (LOLBIN_PAT hoisted to 4657 re-categorization block above)
      const SUSPICIOUS_PATHS = /\\(?:Temp|AppData|Downloads|Users\\Public|ProgramData\\[^\\]*$|Recycle)/i;
      const SUSPICIOUS_CMDS = /(?:powershell|pwsh|cmd\.exe\s*\/c|certutil|bitsadmin|mshta|regsvr32|wscript|cscript|rundll32|msiexec.*\/q|forfiles|cmstp|odbcconf|regasm|regsvcs|installutil|pcalua|msbuild)/i;
      const ENCODING_INDICATORS = /(?:base64|frombase64|-[eE]nc\s|-[eE]\s|iex|invoke-expression|downloadstring|downloadfile|webclient|bitstransfer)/i;
      const SEVERITY_SCORES = { critical: 8, high: 6, medium: 4, low: 2 };
      // Known-legitimate task name prefixes (not suspicious)
      const LEGIT_TASK_PREFIXES = /^\\(?:Microsoft\\|Apple\\|Google\\|Adobe\\|Mozilla\\)/i;

      // Known-legitimate Windows task executables and action handlers (noisy FPs)
      const LEGIT_TASK_EXECUTABLES = /^(?:taskhostw\.exe|InputToCdsTaskHandler|svchost\.exe|conhost\.exe|backgroundTaskHost\.exe|RuntimeBroker\.exe|MusNotification\.exe|devicecensus\.exe|AppHostRegistrationVerifier\.exe|dstokenclean\.exe|UsoClient\.exe|OfficeBackgroundTaskHandlerRegistration|OfficeBackgroundTaskHandlerLogon|WaaSMedicAgent\.exe)$/i;

      // Known-legitimate browser scheduled tasks (task name patterns)
      const LEGIT_BROWSER_TASKS = /^\\?(?:MicrosoftEdgeUpdate|GoogleUpdate|Google(?:Chrome)?Update|ChromeUpdate|BraveSoftwareUpdate|MozillaUpdate|OperaSoftwareUpdate|VivaldiUpdate|Firefox\s*Default\s*Browser\s*Agent)/i;
      // Known-legitimate browser executables (expected paths)
      const LEGIT_BROWSER_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:Microsoft\\Edge|Google\\(?:Chrome|Update)|Mozilla\s*Firefox|BraveSoftware|Opera|Vivaldi)|\\AppData\\Local\\(?:Microsoft\\Edge|Google\\Chrome|BraveSoftware|Mozilla\s*Firefox)\\)/i;
      const LEGIT_VENDOR_TASKS = /^\\?(?:OneDrive(?:\s+Standalone\s+Update\s+Task)?(?:\s+Per-Machine)?(?:-S-1-5-\d+(?:-\d+){2,})?|OneDrive\s+Reporting\s+Task(?:-S-1-5-\d+(?:-\d+){2,})?|Outlook\s+Update|Office(?:Automatic|Feature)\s+Updates?|Office\s+Background\s+Task(?:\s+\S+)?|Teams(?:\s+Update)?|Microsoft\s+Office\s+Updates?|SharePoint(?:\s+Workspace)?(?:\s+Update)?)$/i;
      const LEGIT_VENDOR_TASK_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:Microsoft Office|Microsoft\\Office|Microsoft OneDrive|Microsoft\\OneDrive)|\\AppData\\Local\\Microsoft\\(?:OneDrive|Teams)|%localappdata%\\microsoft\\onedrive\\(?:onedrive(?:standaloneupdater)?|onedrivesetup)\.exe|OfficeClickToRun|OneDrive(?:Setup|StandaloneUpdater)?\.exe|OUTLOOK\.EXE|\\Office\d+\\GROOVE\.EXE)/i;
      const LEGIT_ENTERPRISE_TASKS = /^\\?(?:Adobe(?:\s+\w+)?(?:\s+Updater|\s+Update)?|Zoom(?:\s+Update)?|Slack(?:\s+Update)?|Webex(?:\s+Update)?|Citrix(?:\s+\w+)?|VMware(?:\s+\w+)?|Duo(?:\s+\w+)?|Okta(?:\s+\w+)?|Qualys(?:\s+\w+)?|Tanium(?:\s+\w+)?|BigFix(?:\s+\w+)?|Rapid7(?:\s+\w+)?|Nessus(?:\s+\w+)?|Intune(?:\s+\w+)?|SCCM(?:\s+\w+)?|ConfigMgr(?:\s+\w+)?|Windows\s+Defender(?:\s+\w+)?|Microsoft\s+Edge\s+Update)$/i;
      const LEGIT_ENTERPRISE_TASK_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:Adobe|Zoom|Slack|Cisco\s*Webex|Citrix|VMware|Duo\s*Security|Okta|Qualys|Tanium|BigFix|Rapid7|Tenable|Microsoft|Google)|\\Windows\\System32\\|\\Windows\\SysWOW64\\|\\ProgramData\\Microsoft\\|IntuneManagementExtension|CCM\\|OfficeClickToRun|GoogleUpdate\.exe|MicrosoftEdgeUpdate\.exe)/i;
      const LEGIT_WINDOWS_SCHED_TASKS = /^\\Microsoft\\Windows\\(?:UpdateOrchestrator\\(?:Schedule\s+Wake\s+To\s+Work|Schedule\s+Maintenance\s+Work|USO_[^\\]+|Reboot(?:_AC|_Battery)?|Refresh\s+Settings|Maintenance\s+Install|MusUx_UpdateInterval|MusUx_UpdateIntervalNoWake)?|SoftwareProtectionPlatform\\SvcRestartTask)$/i;
      const LEGIT_WINDOWS_TASK_PREFIX = /^\\Microsoft\\Windows\\[^\\]+/i;
      // Task definitions on disk write their action UNEXPANDED — "%windir%\system32\..." —
      // so a pattern that only knows the literal "\Windows\System32\" form matches none of
      // the OS's own tasks. (EvtxECmd payloads carry the same env-var forms.)
      const LEGIT_WINDOWS_TASK_CMD_PATHS = /(?:\\Windows\\System32\\|\\Windows\\SysWOW64\\|%windir%\\|%SystemRoot%\\|%SystemDrive%\\Windows\\|%ProgramFiles(?:\(x86\))?%\\|taskhostw\.exe|svchost\.exe|rundll32\.exe|sihclient\.exe|usoclient\.exe|musnotification\.exe|taskschd\.dll|\\ProgramData\\Microsoft\\)/i;
      const ENTERPRISE_SERVICE_NAMES = /(?:tanium|bigfix|besclient|qualys|rapid7|insight|nessus|tenable|carbon\s*black|cbdefense|crowdstrike|sentinelone|sophos|mcafee|trellix|symantec|defender|elastic|osquery|intune|ccmexec|sccm|configmgr|kaseya|connectwise|screenconnect|teamviewer|anydesk|rustdesk|splashtop|atera|meshagent|action1|pulseway|n-?able|solarwinds|manageengine|pdq)/i;
      const ENTERPRISE_SERVICE_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:Tanium|BigFix\s*Enterprise|Qualys|Rapid7|Tenable|CrowdStrike|SentinelOne|Sophos|McAfee|Trellix|Symantec|Windows\s*Defender|Elastic|osquery|Microsoft\s*Intune|Microsoft\\CCM|ScreenConnect|TeamViewer|AnyDesk|RustDesk|Splashtop|Atera|MeshAgent|Action1|Pulseway|N-able|SolarWinds|ManageEngine|PDQ))/i;
      const BENIGN_RUN_VALUE_NAMES = /(?:onedrive|sharepoint|groove|teams|edgeupdate|googleupdate|adobe.*updater|acrobat|java|zoom|slack|webex|citrix|vmware|okta|duo|intune|ccmexec|sccm|defender|securityhealth|officeclicktorun)/i;
      const BENIGN_RUN_VALUE_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:Microsoft\\OneDrive|Microsoft\\Teams|Microsoft\\EdgeUpdate|Google\\Update|Adobe|Java|Zoom|Slack|Cisco\s*Webex|Citrix|VMware|Okta|Duo|Windows\s*Defender|Microsoft\s*Office)|\\AppData\\Local\\(?:Microsoft\\OneDrive|Microsoft\\Teams|Google\\Update)|OneDriveSetup\.exe|OneDriveStandaloneUpdater\.exe|GoogleUpdate\.exe|MicrosoftEdgeUpdate\.exe|OfficeClickToRun\.exe|SecurityHealthSystray\.exe|MsMpEng\.exe|\\Office\d+\\GROOVE\.EXE)/i;
      const MICROSOFT_SYNC_SERVICE_NAMES = /(?:onedrive|sharepoint|groove|microsoft\s+sharepoint\s+workspace)/i;
      const MICROSOFT_PRODUCT_PATHS = /(?:\\AppData\\Local\\Microsoft\\OneDrive\\|Program\s*Files(?:\s*\(x86\))?\\Microsoft\s+OneDrive\\|Program\s*Files(?:\s*\(x86\))?\\Microsoft\\EdgeUpdate\\|Program\s*Files\\Common\s*Files\\Microsoft\s*Shared\\ClickToRun\\|Program\s*Files(?:\s*\(x86\))?\\Microsoft\s*Office\\|\\Office\d+\\)/i;
      const MICROSOFT_PRODUCT_BINARIES = /^(?:onedrive\.exe|groove\.exe|officeclicktorun\.exe|microsoftedgeupdate(?:core)?\.exe|outlook\.exe|winword\.exe|excel\.exe|powerpnt\.exe|onenote\.exe|teams\.exe|ms-teams\.exe|ms-teamsupdate\.exe)$/i;
      const _extractCommandExecutable = (cmd = "") => {
        const s = String(cmd || "").trim().replace(/^[`'"]+|[`'"]+$/g, "");
        if (!s) return "";
        const m = s.match(/^"([^"]+\.(?:exe|dll|cmd|bat|ps1|vbs))"/i) || s.match(/^([^\s]+\.(?:exe|dll|cmd|bat|ps1|vbs))/i);
        return (m ? m[1] : s.split(/\s+/)[0]).replace(/"/g, "");
      };
      const _isExpectedMicrosoftBinary = (cmd = "", signatureBlob = "") => {
        const exe = _extractCommandExecutable(cmd);
        if (!exe) return false;
        const base = exe.split("\\").pop() || "";
        if (!MICROSOFT_PRODUCT_BINARIES.test(base) || !MICROSOFT_PRODUCT_PATHS.test(exe)) return false;
        const requireMicrosoftSignature = !!options.requireMicrosoftSignature;
        const sig = String(signatureBlob || "").toLowerCase();
        const hasSigContext = /(?:signer|signature|signed)\s*:/.test(sig);
        if (requireMicrosoftSignature) {
          return /(?:signer|signature)\s*:\s*.*microsoft/.test(sig) || (/\bsigned\s*:\s*true\b/.test(sig) && /microsoft/.test(sig));
        }
        if (hasSigContext) {
          if (/\bsigned\s*:\s*false\b/.test(sig)) return false;
          if (/(?:signer|signature)\s*:\s*(?!.*microsoft)/.test(sig)) return false;
        }
        return true;
      };
      const PRIV_GROUP_PAT = /(?:^|\\)(?:administrators?|remote desktop users|remote management users|backup operators|server operators|account operators|print operators|hyper-v administrators|distributed com users|domain admins|enterprise admins|schema admins|dnsadmins|key admins|enterprise key admins|group policy creator owners|cert(?:ificate)? publishers|laps[_ ]readers|exchange (?:organization )?admins?|ras and ias servers|windows authorization access group|protected users|cloneable domain controllers)$/i;
      // Privileged user pattern — accounts that warrant escalated scoring on modification/reset
      const PRIV_USER_PAT = /(?:^|\\)(?:administrator|krbtgt|admin(?:istrator)?s?\b|.*admin.*|.*svc.*admin.*|.*da_.*|.*ea_.*)/i;
      // Centralized account-risk helper
      // Catch custom/nested Tier-0 group names the fixed PRIV_GROUP_PAT list misses
      // (e.g. "Tier0-Admins", "PAW Operators", "CorpDnsAdmins", "Privileged Access").
      const PRIV_GROUP_SUBSTRING = /admin|tier\s*-?\s*0|privileged|\bpaw\b|dnsadmin|key admins|protected users|domain controllers/i;
      const _accountRisk = (username, groupName) => {
        if (!username && !groupName) return "normal";
        const u = (username || "").trim();
        const g = (groupName || "").trim();
        if (BUILTIN_ACCOUNT_PAT.test(u)) return "builtin";
        if (MACHINE_ACCOUNT_PAT.test(u)) return "machine";
        if (g && (PRIV_GROUP_PAT.test(g) || PRIV_GROUP_SUBSTRING.test(g))) return "privileged-group";
        if (u && PRIV_USER_PAT.test(u)) return "privileged-user";
        return "normal";
      };

      // --- Helper: check if service/process is whitelisted AV/EDR ---
      const CORTEX_OFFLINE_COLLECTOR_PAT = /(?:offline_collector_config\.json|--offline-collector|--collect-artifacts|XDR_Collector)/i;
      const isWhitelistedAV = (name, path) => {
        if (!name) return false;
        const n = name.replace(/"/g, "").trim();
        const p = (path || "").replace(/"/g, "").trim();
        // Masquerade defense (T1036.004): a vendor NAME plus a user-writable / suspicious path is
        // never a real AV install — an attacker naming a service "csagent" at
        // C:\Users\Public\CrowdStrike\evil.exe would otherwise be silently dropped to low. Require a
        // clean path before ANY vendor whitelist (covers the Cortex branch and the main list below).
        if (p && SUSPICIOUS_PATHS.test(p)) return false;
        // Explicit Palo Alto Cortex XDR payload binary: installed agent path or sanctioned offline collector CLI
        if (/cortex-xdr-payload\.exe/i.test(n) || /cortex-xdr-payload\.exe/i.test(p)) {
          if (/palo alto networks/i.test(p) || CORTEX_OFFLINE_COLLECTOR_PAT.test(p)) return true;
        }
        // Require a NON-EMPTY path that matches the vendor location before whitelisting.
        // The old "!p ||" escape whitelisted on name alone when the path was empty — but
        // EvtxECmd 7045 frequently leaves ExecutableInfo blank, so an attacker naming a
        // service "WinDefend"/"csagent" with an unparsed path was silently dropped.
        // Empty/unverifiable paths now fall through and get flagged (see scoring) instead.
        return AV_EDR_WHITELIST.some(w => w.namePattern.test(n) && p && w.pathPattern.test(p));
      };

      // --- Known malicious / offensive tool service patterns ---
      const MALICIOUS_TOOLS = [
        { namePattern: /^(?:psexesvc|psexec)$/i, severity: "critical", reasons: ["PsExec service — lateral movement"] },
        { namePattern: /(?:cobalt.*strike|beacon)/i, severity: "critical", reasons: ["Cobalt Strike beacon service"] },
        { namePattern: /(?:mimikatz|mimilib|mimidrv)/i, severity: "critical", reasons: ["Mimikatz credential theft"] },
        { namePattern: /(?:meterpreter|metasploit|reverse.?shell)/i, severity: "critical", reasons: ["Offensive framework service"] },
        { namePattern: /^(?:smbexec|atexec|dcomexec|wmiexec)/i, severity: "critical", reasons: ["Impacket lateral movement"] },
        { namePattern: /(?:screenconnect|connectwise)/i, severity: "high", reasons: ["ScreenConnect remote access"] },
        { namePattern: /^anydesk$/i, severity: "high", reasons: ["AnyDesk remote access"] },
        { namePattern: /^rustdesk$/i, severity: "high", reasons: ["RustDesk remote access"] },
        { namePattern: /^teamviewer$/i, severity: "high", reasons: ["TeamViewer remote access"] },
        { namePattern: /^(?:YOURSERVICENAME|default_service|test_service|debug_service)$/i, severity: "critical", reasons: ["Default/test malware service name"] },
      ];

      // --- Helper: detect browser service legitimacy vs mimicry ---
      const BROWSER_SVC_PAT = /(?:chrome|edge|brave|firefox|opera|vivaldi|browser).*(?:update|updater|elevat)/i;
      const checkBrowserService = (name, cmd) => {
        if (!name || !BROWSER_SVC_PAT.test(name)) return null;
        if (LEGIT_BROWSER_PATHS.test(cmd || "")) return "legitimate";
        if (cmd && cmd.trim()) return "suspicious";
        return null;
      };

      // --- Registry defaults that every Windows install ships with ---
      // The Startup path stored in (User) Shell Folders IS the Startup folder. Matching the
      // key alone flags the default value as a redirection; only a value pointing somewhere
      // ELSE is a redirection.
      const DEFAULT_SHELL_FOLDER_VALUES = /^(?:%USERPROFILE%|%ProgramData%|%ALLUSERSPROFILE%|[A-Za-z]:\\Users\\[^\\]+|[A-Za-z]:\\ProgramData|[A-Za-z]:\\Documents and Settings\\[^\\]+)\\(?:AppData\\Roaming\\)?Microsoft\\Windows\\Start Menu\\Programs\\Startup\\?$/i;
      // Default file-association verbs. `"%1" %*` is exefile's shipped command — it names no
      // image at all, so there is nothing hijacked.
      const DEFAULT_SHELL_OPEN_COMMANDS = /^(?:"?%[1L]"?(?:\s+%\*)?|rundll32\.exe\s+shell32\.dll,OpenAs_RunDLL\s+%1)$/i;

      // Install roots that are not user-writable, used to decide whether a full-state
      // inventory row is worth an analyst's attention. Covers the forms a service ImagePath
      // actually takes: NT paths (\SystemRoot\, \??\C:\), env-expanded (%SystemRoot%\),
      // driver-relative (System32\drivers\...), and quoted absolute paths.
      //
      // The Windows root itself is NOT trusted — only its system subdirectories are. A
      // binary sitting directly in C:\Windows\ is the classic drop location (PSEXESVC.exe
      // lands there), and trusting the whole tree would suppress it as routine inventory.
      const TRUSTED_IMAGE_ROOTS = /^(?:(?:\\SystemRoot|%SystemRoot%|%windir%|[A-Za-z]:\\Windows)\\(?:System32|SysWOW64|WinSxS|Microsoft\.NET|servicing|SystemApps|ImmersiveControlPanel|assembly)\\|system32\\|syswow64\\|[A-Za-z]:\\Program Files(?: \(x86\))?\\)/i;
      const _normInventoryPath = (v) => {
        const quoted = /^"([^"]*)"/.exec(v);
        return (quoted ? quoted[1] : v).replace(/^\\\?\?\\/, "").trim();
      };
      /**
       * A plugin CSV is the host's CURRENT STATE, not a log of changes — a normal machine
       * has 300 services and 200 tasks. Ranking all of them as findings buries the one that
       * matters, so an inventory row must carry a hunting signal to survive. Suppressed
       * rows are counted into stats.registryInventorySuppressed rather than silently dropped.
       */
      const _inventoryRowIsInteresting = (item) => {
        const vd = (item.details?.valueData || "").trim();
        const vn = (item.details?.valueName || "").trim();
        if (!vd) return false;                                   // nothing to judge
        if (/^FailureCommand$/i.test(vn)) return true;           // rare and directly abusable
        if (LOLBIN_PAT.test(vd)) return true;
        if (/\\(?:Users|Temp|AppData|Downloads|Public|PerfLogs|Tasks|Intel|Recycle)\\/i.test(vd)) return true;
        if (/(?:base64|frombase64|-enc\s|-e\s|iex|invoke-|downloadstring|webclient)/i.test(vd)) return true;
        if (item.details?._pluginTaskHidden) return true;
        // Named attack tooling — PsExec, Impacket, Cobalt Strike, RMM. The name is the
        // signal here; PSEXESVC.exe otherwise looks like an ordinary C:\Windows binary.
        const invName = item.details?._pluginServiceName || (item.artifact || "").split("\\").pop() || "";
        if (invName && MALICIOUS_TOOLS.some((t) => t.namePattern.test(invName))) return true;
        // Anything installed outside the protected system/program roots.
        return !TRUSTED_IMAGE_ROOTS.test(_normInventoryPath(vd));
      };

      // Filter out whitelisted items
      items = items.filter((item) => {
        // AV/EDR services from expected paths
        if (item.category === "Services" && item.name === "Service Installed") {
          const sn = item.artifact || item.details?.serviceName || "";
          const cp = item.command || item.details?.imagePath || item.details?.serviceFile || "";
          if (isWhitelistedAV(sn, cp)) return false;
        }
        // Scheduled Tasks: suppress known legitimate tasks
        if (item.category === "Scheduled Tasks") {
          const art = item.artifact || item.details?.taskName || "";
          const cmd = item.command || item.details?.executable || "";
          const noisyTaskEvent = item.name === "Task Updated" || item.name === "Task Updated (Security)"
            || item.name === "Task Registered" || item.name === "Boot Trigger Fired" || item.name === "Logon Trigger Fired"
            || item.name === "Task Action Started" || item.name === "Task Process Created"
            // 4698: built-in \Microsoft\Windows\ tasks are re-registered during imaging /
            // in-place upgrade / servicing. Treat as noisy too (still gated on mutation signals).
            || item.name === "Scheduled Task Created" || item.name === "Scheduled Task Defined";
          const taskActionBlob = `${item.details?.command || ""} ${item.details?.executable || ""} ${cmd || ""}`;
          const hasTaskMutationSignal = Boolean(
            item.details?._taskHidden
            || item.details?._taskElevated
            || item.details?._taskComHandler
            || (item.details?._taskTriggers || []).includes("registration")
            || SUSPICIOUS_CMDS.test(taskActionBlob)
            || ENCODING_INDICATORS.test(taskActionBlob)
          );
          // Legitimate Windows system tasks with known system executables
          if ((item.name === "Task Process Created" || item.name === "Task Action Started")
            && LEGIT_TASK_PREFIXES.test(art) && LEGIT_TASK_EXECUTABLES.test(cmd.split("\\").pop())) return false;
          // A task DEFINITION read from disk covers EVERY registered task, which on a stock
          // Windows install means ~200 of the OS's own. Most of those legitimately run
          // elevated (68/204 on a real host), through a COM handler (111/204), and via
          // rundll32 — signals that are near-universal among built-ins and therefore
          // meaningless as evidence there. Judge them on WHERE the action points instead:
          // a `\Microsoft\Windows\` task whose action stays inside a system path, is not
          // hidden and carries no encoded payload is the operating system, not an intrusion.
          // Every one of those conditions is still checked, so a task hiding behind a
          // built-in-looking name but pointing at C:\Users\Public survives to be scored.
          // `Hidden` is deliberately NOT a discriminator here: 54 of 204 built-in tasks on a
          // stock host set it, so it separates nothing within this population. The action
          // path does the work — a hidden built-in-named task pointing anywhere
          // user-writable still survives this branch and gets scored.
          if (item.name === "Scheduled Task Defined"
            && LEGIT_WINDOWS_TASK_PREFIX.test(art)
            && !ENCODING_INDICATORS.test(taskActionBlob)
            && !/\\(?:Users|Temp|AppData|Downloads|Public|PerfLogs|ProgramData\\(?!Microsoft\\))/i.test(taskActionBlob)
            && (!cmd || LEGIT_WINDOWS_TASK_CMD_PATHS.test(cmd))) return false;
          // Explicit Windows scheduler maintenance tasks (UpdateOrchestrator/SPP) are high-volume benign noise
          if (noisyTaskEvent && LEGIT_WINDOWS_SCHED_TASKS.test(art) && !hasTaskMutationSignal) return false;
          // Broad Microsoft Windows scheduler noise suppression for lifecycle/trigger events.
          // Keep signals that have strong suspicious context handled later in scoring/correlation.
          if (noisyTaskEvent
            && LEGIT_WINDOWS_TASK_PREFIX.test(art)
            && (!cmd || LEGIT_WINDOWS_TASK_CMD_PATHS.test(cmd))
            && !SUSPICIOUS_CMDS.test(cmd || "")
            && !ENCODING_INDICATORS.test(cmd || "")
            && !hasTaskMutationSignal) return false;
          // Vendor/browser/enterprise updater tasks are suppressed ONLY when the action
          // path actually matches the vendor location. The old "!cmd ||" escape dropped
          // these on the task NAME alone when the action was empty/unparsed (common in
          // EvtxECmd 106/140) — letting an attacker hide behind a spoofed vendor task name.
          // Empty/unverified action → keep visible for review.
          // These vendor/browser/enterprise drops HARD-remove the item before scoring, so they MUST
          // carry the same suspicious-context guard the Windows-prefix drops have (L1889-1897) —
          // otherwise a 4698 named "Citrix Backdoor" whose action is `rundll32 C:\Users\Public\evil.dll`
          // is dropped entirely (LEGIT_ENTERPRISE_TASK_PATHS trusts a bare \Windows\System32\ token).
          const _taskActionClean = !SUSPICIOUS_CMDS.test(cmd) && !ENCODING_INDICATORS.test(cmd) && !hasTaskMutationSignal;
          if (_taskActionClean && LEGIT_BROWSER_TASKS.test(art) && cmd && LEGIT_BROWSER_PATHS.test(cmd)) return false;
          if (_taskActionClean && LEGIT_VENDOR_TASKS.test(art) && cmd && (LEGIT_VENDOR_TASK_PATHS.test(cmd) || _isExpectedMicrosoftBinary(cmd, `${item.detailsSummary || ""} ${JSON.stringify(item.details || {})}`))) return false;
          if (_taskActionClean && LEGIT_ENTERPRISE_TASKS.test(art) && cmd && LEGIT_ENTERPRISE_TASK_PATHS.test(cmd)) return false;
        }

        // --- Registry false-positive pack ---
        // Every one of these dominated the top of triage on a clean host: they are the
        // registry's DEFAULT state, present on every Windows install, and a rule that
        // matches a key path alone cannot tell them apart from a real modification.
        if (item.mode === "registry") {
          const kp = item.details?.keyPath || "";
          const vn = (item.details?.valueName || "").trim();
          const vd = (item.details?.valueData || "").trim();

          // 1. Shell folder redirection: the shipped value IS the Startup folder. Six of the
          //    top-6 incidents on a real triage package were this one value, scored 8/10 on
          //    "user-writable path" and timestamped at OS install.
          if (item.category === "Startup Folder" && /\\Explorer\\(?:User )?Shell Folders$/i.test(kp)
            && DEFAULT_SHELL_FOLDER_VALUES.test(vd)) return false;

          // 2. Defender: the Exclusions KEY existing is not an exclusion — the excluded path
          //    is the VALUE NAME. A row with neither a value name nor data is just the key.
          if (item.category === "Defender Tampering") {
            if (!vn && !vd) return false;
            // "DisableAntiSpyware = 0" means protection is ON.
            if (/^Disable/i.test(vn) && /^(?:0|0x0+|false)$/i.test(vd)) return false;
          }

          // 3. File associations: the default verb for a class. `"%1" %*` (exefile) and
          //    friends carry no image path at all — there is nothing hijacked.
          if (item.category === "File Association" && vd && DEFAULT_SHELL_OPEN_COMMANDS.test(vd)) return false;

          // 4. TaskCache\Tree rows are an inventory of every task on the box; the ACTION
          //    lives under TaskCache\Tasks\{GUID}. A structural value (Id/Index/SD) on a
          //    built-in Microsoft task with no action blob says nothing an analyst can use.
          if (item.category === "Scheduled Tasks (Reg)" && /\\TaskCache\\Tree\\/i.test(kp)
            && /^(?:Id|Index|SD|)$/i.test(vn)
            && !item.details?._taskRegHasActions
            && LEGIT_TASK_PREFIXES.test(`\\${kp.split(/\\TaskCache\\Tree\\/i)[1] || ""}`)) return false;

          // 5. Plugin-CSV inventory: a full-state export lists every service on the host.
          //    Surfacing 300 signed system services at "high" buries the one that matters,
          //    so an inventory row must carry at least one hunting signal to survive.
          if (item.details?._registryInventory && !_inventoryRowIsInteresting(item)) {
            registryInventorySuppressed++;
            return false;
          }
        }
        return true;
      });

      // --- Registry provenance notes ---
      // Surfaced through `warnings` (the modal's "Data quality" strip) so neither the
      // inventory filtering nor an inferred host is a silent decision.
      if (mode === "registry") {
        if (registryInventorySuppressed > 0) {
          warnings.push(`${registryInventorySuppressed} ${registryPluginInfo?.label || "registry inventory"} rows were routine system state and are not listed — only rows with a hunting signal (non-standard path, LOLBin, encoded value, known tooling) are shown.`);
        }
        if (registryHostSource === "collection-path") {
          warnings.push(`Host "${registryHost}" was inferred from the collection folder layout, not read from the hive — verify before attributing.`);
        } else if (registryHostSource === "none") {
          warnings.push("No host could be attributed to these registry findings — the export carries no ComputerName value and no machine folder in the hive path.");
        }
      }

      // --- Registry value-data analysis helper ---
      const _analyzeValueData = (valueData, keyPath) => {
        const flags = [];
        if (!valueData) return flags;
        if (LOLBIN_PAT.test(valueData))
          flags.push("lolbin-in-value");
        if (/\\(?:Users\\|Temp\\|AppData\\|Downloads\\|Public\\)/i.test(valueData))
          flags.push("user-writable-path");
        if (/(?:base64|frombase64|-enc\s|-e\s|iex|invoke-|downloadstring|webclient)/i.test(valueData))
          flags.push("encoded-value");
        if (/\.(?:tmp|dat|log|txt|cfg|bin)$/i.test(valueData.trim()) && /ServiceDll|AppInit_DLLs|InprocServer32/i.test(keyPath || ""))
          flags.push("suspicious-extension");
        return flags;
      };

      // Some reasons are DAMPENERS / benign context the scorer pushes to explain a
      // downgrade (e.g. "Common updater/enterprise autorun"). They must NOT flip
      // isSuspicious=true — otherwise the very metric analysts triage by (stats.suspicious)
      // is inflated by items we just declared benign.
      // Benign-reason classification lives with the clustering it feeds (incidents.js).
      const _hasSuspiciousReason = hasSuspiciousReason;
      // AV/EDR product NAME match independent of path — used to flag name masquerading
      // when the install path is missing/unverifiable (so spoofs aren't silently dropped).
      const _avNameMatches = (name) => {
        const n = (name || "").replace(/"/g, "").trim();
        return !!n && (/cortex-xdr-payload\.exe/i.test(n) || AV_EDR_WHITELIST.some((w) => w.namePattern.test(n)));
      };

      // --- Remote origin: which pivot planted this artifact ---
      // A persistence artifact created minutes after an inbound network/RDP logon (or a
      // remote WMI/WinRM operation) on the same host did not appear by itself. Tagging it
      // with {sourceHost, sourceIp, logonId} turns a standalone finding into an edge, and
      // that tuple is the join key the lateral-movement graph consumes (see ./lm-handoff.js).
      const REMOTE_ORIGIN_WINDOW = Number(options.remoteOriginWindowMs) > 0
        ? Number(options.remoteOriginWindowMs)
        : 30 * 60 * 1000; // 30 min
      // Only artifacts an attacker plants; a logon does not "explain" a DLL load.
      const REMOTE_ORIGIN_CATEGORIES = new Set([
        "Services", "Scheduled Tasks", "Scheduled Tasks (Reg)", "Registry Autorun", "Run Keys",
        "WMI Persistence", "Startup Folder", "Winlogon", "IFEO", "COM Hijacking",
        "Account Persistence", "Defender Tampering",
      ]);
      if (remoteLogons.length > 0) {
        const arrivalsByHost = new Map();
        for (const r of remoteLogons) {
          if (!arrivalsByHost.has(r.target)) arrivalsByHost.set(r.target, []);
          arrivalsByHost.get(r.target).push(r);
        }
        for (const item of items) {
          if (item.category === "Remote Execution") continue;      // the arrival itself
          if (!REMOTE_ORIGIN_CATEGORIES.has(item.category)) continue;
          const host = _corrHost(item.computer);
          const candidates = arrivalsByHost.get(host);
          if (!candidates || !item.timestamp) continue;
          const itemMs = parseTimestampMs(item.timestamp);
          if (itemMs == null) continue;
          // The arrival must land within the window either side of the artifact (clock skew
          // between logs is routine). Where several qualify, prefer the one carrying the
          // strongest identity rather than merely the nearest: a 4624 supplies the logon
          // session id, which is the actual join key into the lateral-movement graph, while
          // a WMI ClientMachine only names the host. Gap breaks ties.
          const identityRank = (c) => (c.logonId ? 2 : 0) + (c.sourceIp ? 1 : 0);
          let best = null;
          let bestGap = Infinity;
          let bestRank = -1;
          for (const c of candidates) {
            const cMs = parseTimestampMs(c.timestamp);
            if (cMs == null) continue;
            const gap = itemMs - cMs;
            if (gap < -REMOTE_ORIGIN_WINDOW || gap > REMOTE_ORIGIN_WINDOW) continue;
            const dist = Math.abs(gap);
            const rank = identityRank(c);
            if (rank > bestRank || (rank === bestRank && dist < bestGap)) {
              bestRank = rank; bestGap = dist; best = c;
            }
          }
          if (!best) continue;
          item.remoteOrigin = {
            sourceHost: best.sourceHost || "",
            sourceIp: best.sourceIp || "",
            user: best.user || "",
            logonId: best.logonId || "",
            logonType: best.logonType || "",
            timestamp: best.timestamp,
            via: best.via,
            gapMs: bestGap,
          };
        }
      }

      for (const item of items) {
        let score = SEVERITY_SCORES[item.severity] || 4;
        const blob = item.detailsSummary + " " + JSON.stringify(item.details);
        const reasons = item.suspiciousReasons || [];
        if (SUSPICIOUS_PATHS.test(blob)) score += 1;
        if (SUSPICIOUS_CMDS.test(blob)) score += 1;
        if (ENCODING_INDICATORS.test(blob)) score += 1;

        // Check for known malicious tools — escalate severity
        const art = item.artifact || "";
        if (item.category === "Services" && art) {
          const cp = item.command || item.details?.imagePath || item.details?.serviceFile || "";
          // Name checks below are anchored on the SERVICE name. In registry mode the
          // artifact is the full key path, so a bare `art` never matches — PSEXESVC would
          // be scored as an ordinary C:\Windows binary and CrowdStrike would never be
          // recognized as AV. Resolve `...\Services\<Name>[\Parameters]` back to the name.
          const svcName = item.mode === "registry"
            ? (item.details?._pluginServiceName || (/\\Services\\([^\\]+)/i.exec(art)?.[1] || ""))
            : art;
          if (isWhitelistedAV(svcName, cp)) {
            item.whitelisted = true;
            item.whitelistReason = "Known AV/EDR component";
            item.severity = "low";
            score = SEVERITY_SCORES.low;
          } else if (_avNameMatches(svcName) && !cp) {
            // AV/EDR product name but no install path captured → cannot confirm it's the
            // real product. Keep it visible and flag possible masquerading (T1036.004)
            // rather than dropping it on the name alone.
            reasons.push("AV/EDR service name without a verifiable install path — possible masquerading");
            score = Math.max(score, SEVERITY_SCORES.high);
          }
          for (const mt of MALICIOUS_TOOLS) {
            if (mt.namePattern.test(svcName)) {
              item.severity = mt.severity;
              score = Math.max(score, SEVERITY_SCORES[mt.severity] || 6);
              reasons.push(...mt.reasons);
            }
          }
          // Browser services: downgrade if legitimate path, escalate if mimicked
          const browserCheck = checkBrowserService(svcName, item.command || "");
          if (browserCheck === "legitimate") {
            item.severity = "low";
            score = SEVERITY_SCORES.low;
          } else if (browserCheck === "suspicious") {
            item.severity = "high";
            score = Math.max(score, SEVERITY_SCORES.high);
            reasons.push("Browser service name from unexpected path — possible mimicry");
          }
          if (!item.whitelisted
            && ENTERPRISE_SERVICE_NAMES.test(art)
            && (!cp || ENTERPRISE_SERVICE_PATHS.test(cp))
            && !SUSPICIOUS_CMDS.test(cp || "")
            && !ENCODING_INDICATORS.test(cp || "")) {
            item.details._benignServiceContext = true;
            reasons.push("Known enterprise management/security service pattern");
            score -= 2;
          }
          if (!item.whitelisted && MICROSOFT_SYNC_SERVICE_NAMES.test(art) && _isExpectedMicrosoftBinary(cp, `${item.detailsSummary || ""} ${JSON.stringify(item.details || {})}`)) {
            item.details._benignServiceContext = true;
            reasons.push("Microsoft sync/service binary from expected install path");
            score -= 2;
          }
        }

        if (item.category === "Account Persistence") {
          const d = item.details || {};
          const groupName = d.groupName || "";
          const memberName = d.memberName || d.targetUser || d.samAccountName || "";
          const subjectUser = d.subjectUser || "";
          const tgtRisk = _accountRisk(memberName, groupName);
          if (tgtRisk === "builtin" || tgtRisk === "machine") {
            item.whitelisted = true;
            item.whitelistReason = "Built-in or machine account";
            item.severity = "low";
            score = SEVERITY_SCORES.low;
          } else if (/Member Added/.test(item.name)) {
            if (tgtRisk === "privileged-group") {
              reasons.push("privileged group membership");
              item.severity = item.name.includes("Local") ? "high" : "critical";
              score = Math.max(score, SEVERITY_SCORES[item.severity] || 6) + 1;
            } else {
              item.severity = "medium";
              score = Math.max(score, SEVERITY_SCORES.medium);
            }
          } else if (item.name === "User Account Created") {
            const creatorRisk = _accountRisk(subjectUser);
            if (creatorRisk !== "builtin" && creatorRisk !== "machine") {
              reasons.push("new account persistence");
              score += 1;
            } else {
              item.severity = "medium";
              score = Math.max(score, SEVERITY_SCORES.medium);
            }
          } else if (item.name === "User Password Reset") {
            const tgt = d.targetUser || "";
            const resetRisk = _accountRisk(tgt);
            if (resetRisk === "privileged-user" || resetRisk === "privileged-group") {
              reasons.push("Password reset on privileged account");
              item.severity = "high";
              score = Math.max(score, SEVERITY_SCORES.high) + 1;
            } else {
              // Check chain context: escalate if reset follows recent creation or precedes group-add
              item.severity = "medium";
              score = Math.max(score, SEVERITY_SCORES.medium);
            }
          } else if (item.name === "User Account Changed") {
            // 4738: attribute-level semantics
            const sp = _normalizeAcctField(d.scriptPath || "");
            const uac = _normalizeAcctField(d.userAccountControl || "");
            const hp = _normalizeAcctField(d.homeDirectory || "");
            const pp = _normalizeAcctField(d.profilePath || "");
            const up = _normalizeAcctField(d.userParameters || "");
            const del = _normalizeAcctField(d.allowedToDelegateTo || "");
            const tgt = d.targetUser || "";
            d.scriptPath = sp; d.userAccountControl = uac; d.homeDirectory = hp; d.profilePath = pp; d.userParameters = up; d.allowedToDelegateTo = del;
            // 4738 is often noisy in enterprise baselines; default to medium unless strong indicators are present.
            item.severity = "medium";
            score = Math.min(score, SEVERITY_SCORES.medium);
            if (_isMeaningfulScriptPath(sp)) {
              reasons.push("Logon script path set/changed");
              item.severity = "critical";
              score = Math.max(score, SEVERITY_SCORES.critical) + 1;
            }
            if (_isMeaningfulDelegation(del)) {
              reasons.push("Delegation target configured");
              item.severity = "critical";
              score = Math.max(score, SEVERITY_SCORES.critical) + 1;
            }
            if (uac && /%%2087|DONT_REQ_PREAUTH/i.test(uac)) {
              reasons.push("Kerberos pre-auth disabled (AS-REP roast risk)");
              item.severity = "critical";
              score = Math.max(score, SEVERITY_SCORES.critical) + 1;
            }
            if (uac && /%%2089|USE_DES_KEY_ONLY/i.test(uac)) {
              reasons.push("DES-only Kerberos enabled (weak encryption)");
              score += 1;
            }
            if (uac && /%%2082|PASSWD_NOTREQD/i.test(uac)) {
              reasons.push("Password not required flag set");
              item.severity = "high";
              score = Math.max(score, SEVERITY_SCORES.high) + 1;
            }
            if (!_isUnsetAcctField(up) && !/^%%\d+$/.test(up)) {
              reasons.push("UserParameters modified");
              score += 1;
            }
            if ((!_isUnsetAcctField(hp) && !/^%%\d+$/.test(hp)) || (!_isUnsetAcctField(pp) && !/^%%\d+$/.test(pp))) {
              reasons.push("Home directory or profile path changed");
              score += 1;
            }
            // If nothing specific triggered, keep as medium baseline
            if (reasons.length === 0) {
              item.severity = "medium";
              score = Math.max(score, SEVERITY_SCORES.medium);
            }
          }
        }

        // --- Domain Persistence scoring ---
        if (item.category === "Domain Persistence") {
          const d = item.details || {};
          const objDN = (d.objectDN || "").toLowerCase();
          const attr = (d.attributeName || "").toLowerCase();
          const objClass = (d.objectClass || "").toLowerCase();
          const subjectUser = d.subjectUser || "";
          // AdminSDHolder modifications — always critical
          if (/adminsdholder/i.test(objDN)) {
            reasons.push("AdminSDHolder modification — domain-wide privilege persistence");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 2;
          }
          // GPO tampering
          if (/cn=policies/i.test(objDN) || objClass === "grouppolicycontainer") {
            if (/gpcfilesyspath|gpcmachineextensionnames|gpcuserextensionnames/i.test(attr)) {
              reasons.push("GPO configuration modified — potential domain-wide persistence");
              item.severity = "critical";
              score = Math.max(score, SEVERITY_SCORES.critical) + 1;
            } else if (item.name === "AD Object Created") {
              reasons.push("New GPO created");
              item.severity = "high";
              score = Math.max(score, SEVERITY_SCORES.high) + 1;
            } else if (item.name === "AD Object Deleted") {
              reasons.push("GPO deleted — potential anti-forensics");
              item.severity = "high";
              score = Math.max(score, SEVERITY_SCORES.high) + 1;
            }
          }
          // msDS-KeyCredentialLink (Shadow Credentials)
          if (attr === "msds-keycredentiallink") {
            reasons.push("Shadow Credentials attack — msDS-KeyCredentialLink modified");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 2;
          }
          // SPN manipulation (Kerberoasting setup)
          if (attr === "serviceprincipalname") {
            reasons.push("SPN modified — potential Kerberoasting setup");
            item.severity = "high";
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
          }
          // scriptPath on user objects
          if (attr === "scriptpath") {
            reasons.push("Logon script path modified on AD object");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 1;
          }
          // Privileged group membership modification via 5136
          if (attr === "member" && PRIV_GROUP_PAT.test(objDN)) {
            reasons.push("Privileged group membership changed via AD modification");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 1;
          }
          // SIDHistory injection
          if (attr === "sidhistory") {
            reasons.push("SIDHistory modified — potential privilege escalation");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 2;
          }
          // nTSecurityDescriptor (ACL modification)
          if (attr === "ntsecuritydescriptor") {
            reasons.push("Security descriptor modified on AD object");
            item.severity = "high";
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
          }
          // UAC flags on AD objects
          if (attr === "useraccountcontrol") {
            reasons.push("User account control flags changed on AD object");
            score += 1;
          }
          // Delegation settings
          if (/msds-allowedtodelegateto/i.test(attr)) {
            reasons.push("Constrained delegation configured");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 1;
          }
          // Trusted domain object creation/deletion
          if (objClass === "trusteddomain") {
            reasons.push("Trust relationship modified");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 1;
          }
          // Machine/SYSTEM-initiated AD changes are usually DC replication noise — BUT a
          // compromised host frequently operates as SYSTEM / the computer account, so do NOT
          // bury a change that already fired a CRITICAL attack signal (Shadow Credentials,
          // SIDHistory, privileged-group member, delegation, scriptPath, trust). Demote only
          // when nothing critical fired.
          if (BUILTIN_ACCOUNT_PAT.test(subjectUser) || MACHINE_ACCOUNT_PAT.test(subjectUser)) {
            if (item.severity === "critical") {
              reasons.push("Critical AD change by SYSTEM/machine account — verify it is not routine replication");
            } else {
              item.whitelisted = true;
              item.whitelistReason = "System/machine account AD change";
              item.severity = "low";
              score = SEVERITY_SCORES.low;
            }
          }
          // If nothing specific triggered, keep at medium baseline
          if (reasons.length === 0 && !item.whitelisted) {
            item.severity = "medium";
            score = Math.max(score, SEVERITY_SCORES.medium);
          }
        }

        // Account chain correlation boost
        if (item.details?._acctChainLen >= 2 && !item.whitelisted) {
          reasons.push(`Account persistence chain (${item.details._acctChainEvents.join(" → ")})`);
          score += Math.min(item.details._acctChainLen - 1, 3);
        }
        // Cross-technique: account event followed by persistence mechanism
        if (item.details?._acctToPersistenceSeen && !item.whitelisted) {
          if (item.category === "Account Persistence") {
            // Account event side: note the follow-on persistence technique
            const tech = item.details._acctToPersistenceTechnique || "persistence";
            reasons.push(`Account change followed by ${tech}`);
            score += 1;
          } else {
            // Persistence item side: note that the actor also manipulated accounts
            const types = item.details._acctToPersistenceTypes || [];
            reasons.push(`Persistence by user with recent account activity (${types.join(", ")})`);
            score += 2;
          }
        }

        // Suspicious artifact/task indicators
        if (art && item.category === "Scheduled Tasks") {
          if (art.startsWith("\\") && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("Non-standard task path");
            score += 1;
          }
          if (/^\\{[0-9a-f-]+}$/i.test(art)) {
            reasons.push("GUID-named task");
            score += 1;
          }
        }
        if (item.category === "Scheduled Tasks") {
          const cmd = item.command || item.details?.executable || "";
          const noisyTaskEvent = item.name === "Task Updated" || item.name === "Task Updated (Security)"
            || item.name === "Task Registered" || item.name === "Boot Trigger Fired" || item.name === "Logon Trigger Fired";
          const benignTaskContext = LEGIT_TASK_PREFIXES.test(art)
            || LEGIT_BROWSER_TASKS.test(art)
            || LEGIT_VENDOR_TASKS.test(art)
            || LEGIT_ENTERPRISE_TASKS.test(art);
          const expectedTaskPath = !cmd || LEGIT_BROWSER_PATHS.test(cmd) || LEGIT_VENDOR_TASK_PATHS.test(cmd) || LEGIT_ENTERPRISE_TASK_PATHS.test(cmd);
          const hasStrongTaskSignals = Boolean(item.details?._taskHidden || item.details?._taskElevated || item.details?._taskComHandler || item.details?._ps4104Seen || item.details?._serviceProcessParentSuspicious);
          if (noisyTaskEvent && benignTaskContext && expectedTaskPath && !hasStrongTaskSignals) {
            item.details._benignTaskContext = true;
            reasons.push("Common enterprise/system task activity");
            score -= 2;
          }
        }
        // LOLBin execution in non-Microsoft context
        const _hasLolbin = item.command && LOLBIN_PAT.test(item.command) && art && !LEGIT_TASK_PREFIXES.test(art);
        const _hasUserPath = item.command && /\\Users\\|\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\/i.test(item.command);
        const _boostCats = new Set(["Services", "Scheduled Tasks", "Registry Autorun", "IFEO", "AppInit DLLs"]);
        if (_hasLolbin && !item.whitelisted) {
          reasons.push("LOLBin execution");
          if (_boostCats.has(item.category)) score += 1;
        }
        if (_hasUserPath && !item.whitelisted) {
          reasons.push("User-writable path");
          if (_boostCats.has(item.category)) score += 1;
        }
        if (_hasLolbin && _hasUserPath && !item.whitelisted && _boostCats.has(item.category)) {
          reasons.push("LOLBin from user-writable path — high-confidence abuse");
          score += 1; // synergy
        }
        // RMM tool context scoring (service installs only — not auto-malicious, boosted by suspicious context)
        if (item.rmmTool && item.category === "Services" && !item.whitelisted) {
          const rmmCmd = item.command || item.details?.imagePath || item.details?.serviceFile || "";
          const RMM_EXPECTED_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:ScreenConnect|AnyDesk|TeamViewer|Atera|Splashtop|RustDesk|ConnectWise|PDQ|MeshAgent|Action1|SimpleHelp|TacticalRMM|FleetDeck|DWService|HopToDesk|LiteManager|UltraVNC|TigerVNC|RAdmin|Zoho|Pulseway|LabTech|Kaseya|SolarWinds|N-able))/i;
          const rmmFromExpectedPath = RMM_EXPECTED_PATHS.test(rmmCmd);
          const rmmFromUserPath = _hasUserPath;
          if (rmmFromUserPath) {
            reasons.push("RMM tool from user-writable/temp path");
            score += 2;
          } else if (!rmmFromExpectedPath) {
            reasons.push("RMM tool from non-standard path");
            score += 1;
          }
          // Synergy: RMM + LOLBin or RMM + browser mimicry or RMM + 4104 script
          if (_hasLolbin) { reasons.push("RMM installed via LOLBin"); score += 1; }
          if (item.details?._ps4104Seen) { reasons.push("RMM installed via PowerShell script"); score += 1; }
        }
        // Anti-forensics: task deletion
        if (item.name === "Task Deleted" && art && !LEGIT_TASK_PREFIXES.test(art)) {
          reasons.push("Non-standard task deleted");
          score += 1;
        }

        // --- Registry value-data semantics (registry-mode items + 4657 fallback) ---
        if (item.mode === "registry" || item.details?._is4657Fallback) {
          const vdFlags = _analyzeValueData(item.command, item.artifact);
          for (const f of vdFlags) {
            if (f === "lolbin-in-value") { reasons.push("LOLBin in registry value"); score += 2; }
            else if (f === "user-writable-path") { reasons.push("User-writable path in registry value"); score += 1; }
            else if (f === "encoded-value") { reasons.push("Encoded/obfuscated registry value"); score += 2; }
            else if (f === "suspicious-extension") { reasons.push("Suspicious file extension for DLL value"); score += 1; }
          }
          if ((item.category === "Run Keys" || item.category === "Registry Autorun")
            && item.command?.trim()
            && !item.details?._ps4104Seen
            && !vdFlags.includes("lolbin-in-value")
            && !vdFlags.includes("encoded-value")
            && !vdFlags.includes("user-writable-path")) {
            const valueName = (item.details?.valueName || "").trim();
            if (BENIGN_RUN_VALUE_NAMES.test(valueName) || BENIGN_RUN_VALUE_PATHS.test(item.command) || _isExpectedMicrosoftBinary(item.command, `${item.detailsSummary || ""} ${JSON.stringify(item.details || {})}`)) {
              item.details._benignRunKeyContext = true;
              reasons.push("Common updater/enterprise autorun");
              score -= 2;
            } else if (/(?:Program Files(?:\s*\(x86\))?|Windows\\System32|Windows\\SysWOW64)\\/i.test(item.command)) {
              // Generic GPO/SCCM-deployed in-house autoruns: target lives in a protected,
              // non-user-writable signed-software path (and isn't LOLBin/encoded/user-writable
              // per the guard above). Weaker dampener than the named-vendor list — reduces
              // baseline noise without hiding Temp/AppData autoruns.
              item.details._benignRunKeyContext = true;
              reasons.push("Autorun from protected program path");
              score -= 1;
            }
          }
        }

        // --- IFEO-specific inspection ---
        if (item.category === "IFEO") {
          const targetBin = (item.artifact || "").split("\\").pop() || "";
          const ACCESSIBILITY_BINS = /^(?:sethc|utilman|osk|narrator|magnify|displayswitch|atbroker)(?:\.exe)?$/i;
          const ifeoVal = (item.details?.valueName || "").toLowerCase();
          // A bare GlobalFlag (no Debugger) is benign App Verifier / heap-tracing telemetry
          // set by VS / gflags / installers. The Debugger value is the execution-hijack; the
          // GlobalFlag+SilentProcessExit combo is scored under Silent Process Exit. Downgrade
          // GlobalFlag-only from the rule's blanket critical so it doesn't dominate triage.
          if (ifeoVal === "globalflag" && !ACCESSIBILITY_BINS.test(targetBin)) {
            item.severity = "medium";
            score = Math.min(score, SEVERITY_SCORES.medium);
            reasons.push("IFEO GlobalFlag without Debugger (App Verifier / diagnostics)");
          }
          if (ACCESSIBILITY_BINS.test(targetBin)) {
            reasons.push("Accessibility binary IFEO hijack — sticky keys backdoor");
            item.severity = "critical";
            score = Math.max(score, 9);
          }
          if (item.command && /(?:cmd\.exe|powershell|pwsh|mshta)$/i.test(item.command.trim())) {
            reasons.push("LOLBin as IFEO debugger");
            score += 2;
          }
        }

        // --- AppInit_DLLs conditional escalation ---
        if (item.category === "AppInit DLLs") {
          const vn = (item.details?.valueName || "").toLowerCase();
          if (vn === "loadappinit_dlls" && item.command?.trim() === "1") {
            reasons.push("AppInit_DLLs loading enabled");
            score += 1;
          } else if (vn === "appinit_dlls" && item.command?.trim()) {
            reasons.push("AppInit_DLLs path set — DLL injection vector");
            score += 2;
            if (_analyzeValueData(item.command, item.artifact).includes("user-writable-path")) score += 1;
          }
        }

        // --- Silent Process Exit semantics ---
        if (item.category === "Silent Process Exit") {
          const vn = (item.details?.valueName || "").toLowerCase();
          if (vn === "monitorprocess" && item.command?.trim()) {
            reasons.push("Silent exit monitor process configured");
            score = Math.max(score, SEVERITY_SCORES.critical) + 2;
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("lolbin-in-value")) { reasons.push("LOLBin as monitor process"); score += 1; }
            if (vdFlags.includes("user-writable-path")) { reasons.push("Monitor process from user-writable path"); score += 1; }
          } else if (vn === "reportingmode" || vn === "ignoreselfexits") {
            // These configure HOW a silent exit is reported, not WHAT executes. Only the
            // MonitorProcess value arms execution — downgrade from the rule's blanket critical.
            item.severity = "medium";
            score = Math.min(score, SEVERITY_SCORES.medium);
          }
        }

        // --- Logon Script semantics ---
        if (item.category === "Logon Script") {
          if (item.command?.trim()) {
            reasons.push("User logon script path set");
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("lolbin-in-value")) { reasons.push("LOLBin in logon script"); score += 1; }
            if (vdFlags.includes("user-writable-path")) { reasons.push("Logon script from user-writable path"); score += 1; }
            if (vdFlags.includes("encoded-value")) { reasons.push("Obfuscated logon script command"); score += 2; }
          }
        }

        // --- AppCert DLLs semantics ---
        if (item.category === "AppCert DLLs") {
          if (item.command?.trim()) {
            reasons.push("AppCert DLL path set — loaded into every process calling CreateProcess");
            score = Math.max(score, SEVERITY_SCORES.critical) + 2;
            if (_analyzeValueData(item.command, item.artifact).includes("user-writable-path")) {
              reasons.push("AppCert DLL from user-writable path");
              score += 1;
            }
          }
        }

        // --- Credential Provider semantics ---
        if (item.category === "Credential Providers") {
          reasons.push("Custom credential provider registered");
          score = Math.max(score, SEVERITY_SCORES.high) + 1;
          if (item.command?.trim()) {
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("user-writable-path")) { reasons.push("Credential provider DLL from user-writable path"); score += 2; }
            // Score system vs non-system DLL path
            const dllPath = item.command.trim().toLowerCase().replace(/"/g, "");
            if (dllPath && !/^(?:c:\\windows\\|c:\\program files)/i.test(dllPath)) {
              reasons.push("Credential provider from non-system path");
              score += 1;
            }
          }
        }

        // --- Command Processor AutoRun semantics ---
        if (item.category === "Command Processor") {
          if (item.command?.trim()) {
            reasons.push("cmd.exe AutoRun command set");
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("lolbin-in-value")) { reasons.push("LOLBin in cmd AutoRun"); score += 2; }
            if (vdFlags.includes("user-writable-path")) { reasons.push("AutoRun from user-writable path"); score += 1; }
            if (vdFlags.includes("encoded-value")) { reasons.push("Obfuscated AutoRun command"); score += 2; }
          }
        }

        // --- Explorer Autoruns (ShellServiceObjectDelayLoad) semantics ---
        if (item.category === "Explorer Autoruns") {
          if (item.command?.trim()) {
            reasons.push("ShellServiceObjectDelayLoad entry");
            score = Math.max(score, SEVERITY_SCORES.high);
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("user-writable-path")) { reasons.push("SSODL DLL from user-writable path"); score += 2; }
          }
        }

        // --- Netsh Helper DLLs semantics ---
        if (item.category === "Netsh Helper DLLs") {
          if (item.command?.trim()) {
            reasons.push("Netsh helper DLL registered");
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("user-writable-path")) { reasons.push("Netsh helper from user-writable path"); score += 2; }
            // Non-system DLL path is very suspicious for netsh helpers
            const dllPath = item.command.trim().toLowerCase().replace(/"/g, "");
            if (dllPath && !/^(?:c:\\windows\\|c:\\program files)/i.test(dllPath)) {
              reasons.push("Netsh helper from non-system path");
              score += 1;
            }
          }
        }

        // --- DLL Hijacking noise reduction ---
        if (item.category === "DLL Hijacking") {
          const dll = (item.details?.imageLoaded || "").toLowerCase().replace(/"/g, "").trim();
          const proc = (item.details?.image || "").toLowerCase().replace(/"/g, "").trim();
          // ONLY genuine OS directories (System32/SysWOW64/WinSxS) are trusted enough to
          // auto-whitelist. \Program Files\ is a writable-subdir / search-order hijack target
          // (the classic phantom-DLL scenario), so an unsigned DLL there stays visible.
          const TRUSTED_SYSTEM_DLL_PATHS = /^c:\\windows\\(?:system32|syswow64|winsxs)\\/i;
          const isUserWritable = /\\(?:Users\\|Temp\\|AppData\\|Downloads\\|Public\\|ProgramData\\)/i.test(dll);
          const isTempProc = /\\(?:Users\\|Temp\\|AppData\\|Downloads\\|Public\\)/i.test(proc);
          if (isUserWritable) {
            reasons.push("Unsigned DLL from user-writable path");
            item.severity = "high";
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
            if (isTempProc) { reasons.push("Loaded by process in user-writable path"); score += 1; }
          } else if (TRUSTED_SYSTEM_DLL_PATHS.test(dll)) {
            // System32 / SysWOW64 / WinSxS — benign unsigned OS component.
            item.severity = "low";
            item.whitelisted = true;
            item.whitelistReason = "Unsigned DLL in trusted system path";
            score = SEVERITY_SCORES.low;
          } else {
            // Program Files or other non-trusted path — possible phantom-DLL / search-order
            // hijack. Keep at medium for review instead of auto-whitelisting.
            reasons.push("Unsigned DLL outside trusted system path");
          }
        }

        // --- Registry-mode COM / Shell Extension / BHO noise reduction ---
        // A SOFTWARE-hive export lists every InprocServer32 / ContextMenuHandler on the box;
        // the vast majority point at signed system/Program-Files DLLs and are benign. Downgrade
        // those (they otherwise flood at high/medium with no execution evidence); escalate when
        // the server DLL sits in a user-writable path (the COM-hijack indicator).
        if (item.mode === "registry" && (item.category === "COM Hijacking" || item.category === "Shell Extensions" || item.category === "BHO")) {
          const vd = (item.details?.valueData || item.command || "").trim();
          const userWritable = /(?:\\(?:Users|Temp|AppData|Downloads|Public|ProgramData)\\|%(?:temp|appdata|userprofile|localappdata)%)/i.test(vd);
          const trustedPath = /c:\\windows\\(?:system32|syswow64|winsxs)\\|c:\\program files(?:\s*\(x86\))?\\/i.test(vd);
          if (userWritable) {
            reasons.push("COM/shell server DLL in user-writable path");
            item.severity = "high";
            score = Math.max(score, SEVERITY_SCORES.high);
          } else if (trustedPath) {
            item.details._benignComContext = true;
            reasons.push("COM/shell server in trusted system/program path");
            item.severity = "low";
            score = Math.min(score, SEVERITY_SCORES.low);
          }
          // else: unknown/empty value data → keep the rule's declared severity (don't hide it)
        }

        // --- Service subtypes ---
        if (item.category === "Services") {
          if (item.details?._is4657Fallback) {
            // 4657 re-categorized as Services — treat like registry mode
            if (/servicedll/i.test(item.details?.targetObject || "")) { item.subtype = "service-dll"; reasons.push("ServiceDll modification (4657)"); score += 1; }
            else if (/failurecommand/i.test(item.details?.targetObject || "")) { item.subtype = "service-failure"; reasons.push("Service FailureCommand set (4657)"); score += 2; }
            else item.subtype = "service-registry";
          } else if (item.mode === "evtx") {
            if (item.name === "Service StartType Changed") {
              item.subtype = "service-starttype";
              const nt = (item.details?.newStartType || "").toLowerCase();
              if (/auto/i.test(nt)) {
                reasons.push("Service set to auto start");
                score += 1;
              }
              if (/disabled/i.test((item.details?.oldStartType || "").toLowerCase()) && /auto|demand/i.test(nt)) {
                reasons.push("Disabled service re-enabled");
                score += 1;
              }
            } else {
              item.subtype = "service-install";
            }
          } else if (item.mode === "registry") {
            const vn = (item.details?.valueName || "").toLowerCase();
            if (vn === "imagepath") item.subtype = "service-imagepath";
            else if (vn === "servicedll") { item.subtype = "service-dll"; reasons.push("ServiceDll modification"); score += 1; }
            else if (vn === "failurecommand") { item.subtype = "service-failure"; reasons.push("Service FailureCommand set"); score += 2; }
            else item.subtype = "service-registry";
          }
          // Correlation-derived subtype refinement (most specific wins)
          if (item.details?._serviceStarted) item.subtype = "service-start-confirmed";
          else if (item.details?._serviceProcessStarted) item.subtype = "service-process-confirmed";
          // RMM service subtype (after correlation, so it layers on top)
          if (item.rmmTool) item.subtype = (item.subtype === "service-start-confirmed" || item.subtype === "service-process-confirmed") ? "service-rmm-confirmed" : "service-rmm";
        }

        // --- Task subtypes ---
        if (item.category === "Scheduled Tasks") {
          if (item.name === "Task Deleted" || item.name === "Scheduled Task Deleted") {
            item.subtype = "task-deleted";
          } else if (item.name === "Task Process Created" || item.name === "Task Action Started") {
            item.subtype = "task-execution";
            if (item.command && SUSPICIOUS_CMDS.test(item.command) && !LEGIT_TASK_PREFIXES.test(art)) {
              reasons.push("Suspicious task execution");
              score += 1;
            }
          } else if (item.name === "Task Registered" || item.name === "Scheduled Task Created" || item.name === "Scheduled Task Defined") {
            item.subtype = "task-created";
          } else if (item.name === "Task Updated" || item.name === "Task Updated (Security)") {
            item.subtype = "task-updated";
          } else if (item.name === "Boot Trigger Fired" || item.name === "Logon Trigger Fired") {
            item.subtype = "task-trigger";
          } else {
            item.subtype = "task-other";
          }
          // Short/random task name detection
          const leafName = (art || "").split("\\").pop() || "";
          if (leafName && leafName.length <= 4 && /^[a-zA-Z0-9]+$/.test(leafName) && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("Short random task name");
            score += 1;
          }
          // Deep XML semantics (4698/4702): hidden, elevated, COM handler, trigger types
          if (item.details?._taskHidden && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("Hidden task");
            score += 2;
          }
          if (item.details?._taskElevated && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("Runs with highest privileges");
            score += 1;
          }
          if (item.details?._taskComHandler && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("COM handler task");
            score += 1;
          }
          const trigs = item.details?._taskTriggers || [];
          if (trigs.includes("boot") || trigs.includes("logon")) {
            if (!LEGIT_TASK_PREFIXES.test(art)) {
              reasons.push(`Persistence trigger: ${trigs.filter(t => t === "boot" || t === "logon").join("+")}`);
              score += 1;
            }
          }
          if (trigs.includes("registration") && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("Immediate execution on registration");
            score += 1;
          }
        }

        // --- Confidence-based score adjustment (from cross-event correlation) ---
        if (item.confidence === "confirmed" || item.confidence === "likely") {
          const src = item.details?._serviceStarted ? "service start (7036)"
            : item.details?._serviceProcessStarted ? "process creation"
            : item.details?._svcControlSeen ? "service control request (7035)"
            : item.details?._serviceExecSeen ? "registry/DLL evidence"
            : item.details?._execSeen ? "autorun execution"
            : item.details?._wmiComplete ? "complete WMI subscription"
            : item.details?._wmiPartial ? "partial WMI subscription"
            : item.details?._ps4104Seen ? "PowerShell script block (4104)"
            : item.details?._ps4104Standalone ? "PowerShell script block (4104)"
            : item.details?._is4657Fallback ? "Security 4657 registry audit"
            : item.details?._acctChainLen ? "account persistence chain"
            : item.details?._acctToPersistenceSeen ? "account-to-persistence correlation"
            : "cross-event";
          // Whitelist-aware: whitelisted items get confidence but not risk boost
          if (!item.whitelisted) {
            const weakServiceCorrelation = item.category === "Services"
              && item.confidence === "likely"
              && (item.details?._svcDisplayNameMatch
                || (item.details?._svcControlSeen && !item.details?._serviceStarted && !item.details?._serviceProcessStarted));
            const weakStandalone4104 = item.details?._ps4104Standalone && !item.details?._ps4104Strong;
            if (!weakServiceCorrelation && !weakStandalone4104) {
              reasons.push(`Execution corroborated by ${src}`);
              if (item.confidence === "confirmed") score += 2;
              else score += 1; // likely gets smaller boost
            } else {
              reasons.push("Correlation signal present but low-fidelity");
            }
            // Suspicious parent process in service correlation
            if (item.details?._serviceProcessParentSuspicious) {
              const pb = (item.details._serviceProcessParent || "").split("\\").pop();
              reasons.push(`Unexpected parent process: ${pb}`);
              score += 1;
            }
          }
        } else if (item.confidence === "present") {
          score -= 1;
        }

        // --- 4657 lower-fidelity dampener: offset confidence boost unless strong semantics ---
        if (item.details?._is4657Fallback && item.confidence === "likely" && !item.whitelisted) {
          const _4657Strong = new Set(["IFEO", "AppInit DLLs", "Winlogon", "Boot Execute", "LSA", "Silent Process Exit", "AppCert DLLs", "Logon Script", "Command Processor", "Netsh Helper DLLs"]);
          if (!_4657Strong.has(item.category)) {
            score -= 1; // offset the +1 from "likely" confidence for weaker 4657 signals
          }
        }
        if (item.details?._4657NoKeyPath) {
          score -= 1; // further penalize when key path couldn't be extracted
        }

        // --- 4104-specific scoring boosts ---
        const _ps4104Ind = item.details?._ps4104SuspiciousIndicators || [];
        if (item.details?._ps4104Seen && !item.whitelisted) {
          reasons.push("Created via PowerShell script");
          score += 1;
          if (_ps4104Ind.length > 0) { score += Math.min(_ps4104Ind.length, 3); }
        }
        if (item.details?._ps4104Standalone && !item.whitelisted) {
          const indSet = new Set(_ps4104Ind);
          if (indSet.has("EncodedCommand") || indSet.has("FromBase64String")) { reasons.push("Encoded/obfuscated payload"); score += 2; }
          if (indSet.has("DownloadString") || indSet.has("Net.WebClient") || indSet.has("Start-BitsTransfer") || indSet.has("Web download")) { reasons.push("Remote payload download"); score += 2; }
          if (indSet.has("Invoke-Expression")) { reasons.push("Dynamic code execution (IEX)"); score += 1; }
          if (indSet.has("Assembly loading")) { reasons.push("In-memory assembly loading"); score += 2; }
          if (indSet.has("Defender exclusion") || indSet.has("Defender disable")) { reasons.push("Security product tampering"); score += 2; }
          if ((item.details.matchedPatterns || []).length >= 2) { reasons.push("Multi-technique persistence script"); score += 2; }
          if (!item.details?._ps4104Strong) {
            reasons.push("Standalone script-block signal without strong malicious indicators");
            score -= 2;
          }
        }

        // Remote-planted persistence is the thing an analyst is hunting for in a triage
        // package: this host was reached AND kept. Applied LAST so the bump is additive —
        // several earlier blocks raise the score with Math.max against a severity floor,
        // which would otherwise swallow it whole on exactly the findings that matter most
        // (a known tool like PSEXESVC already sits at the critical floor).
        if (item.remoteOrigin) {
          const src = item.remoteOrigin.sourceHost || item.remoteOrigin.sourceIp || "a remote host";
          reasons.push(`Planted over ${item.remoteOrigin.via} from ${src}`);
          score += 2;
        }

        item.triageScore = score;
        item.riskScore = Math.min(score, 10);
        item.isSuspicious = _hasSuspiciousReason(reasons);
        item.suspiciousReasons = reasons;

        // --- Reconcile the visible severity BADGE to the dampened score ---
        // The benign-context dampeners above lower `score`/triageScore (the sort rank) but most do
        // NOT lower item.severity (only the COM/IFEO/account blocks set both). So the badge, the
        // bySeverity histogram (reads item.severity), and incident worstSev still show the rule's
        // declared high/critical for items we already judged benign (isSuspicious=false) — the single
        // biggest source of inflated severity counts. Map the badge to the score's band, DOWNGRADE
        // ONLY (never raise), and ONLY for benign-flagged, non-suspicious, non-whitelisted items
        // (a whitelisted item already got low; a genuine escalation is isSuspicious=true → skipped).
        const _benignDampened = item.details?._benignRunKeyContext || item.details?._benignServiceContext
          || item.details?._benignTaskContext || item.details?._benignComContext;
        if (_benignDampened && !item.whitelisted && !item.isSuspicious) {
          const bandSev = score >= SEVERITY_SCORES.critical ? "critical"
            : score >= SEVERITY_SCORES.high ? "high"
            : score >= SEVERITY_SCORES.medium ? "medium" : "low";
          if ((SEVERITY_SCORES[bandSev] || 4) < (SEVERITY_SCORES[item.severity] || 4)) item.severity = bandSev;
        }
      }

      // --- Evidence pills from suspiciousReasons + context ---
      for (const item of items) {
        const pills = [];
        for (const r of (item.suspiciousReasons || [])) {
          const rl = r.toLowerCase();
          if (rl.includes("user-writable path"))          pills.push({ text: "user-writable path", type: "execution" });
          else if (rl.includes("lolbin"))                  pills.push({ text: "LOLBin execution", type: "execution" });
          else if (rl.includes("encoded") || rl.includes("base64") || rl.includes("invoke-expression"))
                                                           pills.push({ text: "encoded payload", type: "execution" });
          else if (rl.includes("browser") && rl.includes("unexpected"))
                                                           pills.push({ text: "path mimicry", type: "context" });
          else if (rl.includes("guid-named"))              pills.push({ text: "GUID task", type: "context" });
          else if (rl.includes("non-standard task"))       pills.push({ text: "non-standard task", type: "context" });
          else if (rl.includes("psexec"))                  pills.push({ text: "PsExec", type: "execution" });
          else if (rl.includes("remote access"))           pills.push({ text: "remote access tool", type: "execution" });
          else if (rl.includes("task deleted"))            pills.push({ text: "anti-forensics", type: "correlation" });
          else                                             pills.push({ text: r.substring(0, 40), type: "context" });
        }
        if (item.rmmTool)                                  pills.push({ text: "RMM tool", type: "execution" });
        if (item.details?._is4657Fallback)                 pills.push({ text: "Security 4657 fallback", type: "context" });
        if (/WOW6432Node/i.test(item.details?.targetObject || item.artifact || "")) pills.push({ text: "WOW64 (32-bit)", type: "execution" });
        if (item.category === "WMI Persistence") {
          const wt = item.details?._wmiType || "";
          if (/CommandLine/i.test(wt))       pills.push({ text: "CmdLine consumer", type: "execution" });
          else if (/ActiveScript/i.test(wt)) pills.push({ text: "script consumer", type: "execution" });
          else if (/EventFilter|__Event/i.test(wt)) pills.push({ text: "event filter", type: "context" });
          else if (/Binding/i.test(wt))      pills.push({ text: "WMI binding", type: "context" });
          else if (wt)                       pills.push({ text: wt.replace(/EventConsumer$/i, "").trim() || "WMI consumer", type: "context" });
          else                               pills.push({ text: "WMI consumer", type: "context" });
          if (item.details?._wmiCommand)     pills.push({ text: "has payload", type: "execution" });
        }
        if (item.category === "Silent Process Exit")       pills.push({ text: "silent exit monitor", type: "execution" });
        if (item.category === "Logon Script")              pills.push({ text: "logon script", type: "execution" });
        if (item.category === "AppCert DLLs")              pills.push({ text: "AppCert DLL", type: "execution" });
        if (item.category === "Credential Providers")      pills.push({ text: "credential provider", type: "execution" });
        if (item.category === "Command Processor")          pills.push({ text: "cmd AutoRun", type: "execution" });
        if (item.category === "Explorer Autoruns")          pills.push({ text: "SSODL", type: "execution" });
        if (item.category === "Netsh Helper DLLs")          pills.push({ text: "netsh helper", type: "execution" });
        if (item.details?._svcControlSeen)                  pills.push({ text: "7035 control request", type: "correlation" });
        // Domain Persistence pills
        if (item.category === "Domain Persistence") {
          const _attr = (item.details?.attributeName || "").toLowerCase();
          if (/adminsdholder/i.test(item.details?.objectDN || "")) pills.push({ text: "AdminSDHolder", type: "execution" });
          if (_attr === "msds-keycredentiallink")                  pills.push({ text: "Shadow Credentials", type: "execution" });
          if (_attr === "serviceprincipalname")                    pills.push({ text: "SPN change", type: "execution" });
          if (/cn=policies/i.test(item.details?.objectDN || ""))   pills.push({ text: "GPO", type: "execution" });
          if (_attr === "sidhistory")                               pills.push({ text: "SIDHistory", type: "execution" });
          if (_attr === "ntsecuritydescriptor")                     pills.push({ text: "ACL change", type: "context" });
          if (_attr === "member")                                   pills.push({ text: "group membership", type: "context" });
          if (item.details?.objectClass)                            pills.push({ text: item.details.objectClass, type: "context" });
        }
        // Account chain pill
        if (item.details?._acctChainLen >= 2) {
          pills.push({ text: `${item.details._acctChainLen}-step chain`, type: "correlation" });
        }
        // Cross-technique: account -> persistence pill
        if (item.details?._acctToPersistenceSeen) {
          if (item.category === "Account Persistence") {
            pills.push({ text: `→ ${item.details._acctToPersistenceTechnique || "persistence"}`, type: "correlation" });
          } else {
            pills.push({ text: "acct change by same user", type: "correlation" });
          }
        }
        // 4738 Account Changed pills
        if (item.name === "User Account Changed") {
          if (_isMeaningfulScriptPath(item.details?.scriptPath || "")) pills.push({ text: "logon script", type: "execution" });
          if (_isMeaningfulDelegation(item.details?.allowedToDelegateTo || "")) pills.push({ text: "delegation", type: "execution" });
          if (/DONT_REQ_PREAUTH|%%2087/i.test(item.details?.userAccountControl || "")) pills.push({ text: "AS-REP roast", type: "execution" });
        }
        if (item.computer)                                 pills.push({ text: item.computer, type: "target" });
        // The strongest pill an artifact can carry: it names who put it there.
        if (item.remoteOrigin) {
          const _src = item.remoteOrigin.sourceHost || item.remoteOrigin.sourceIp;
          if (_src) pills.push({ text: `from ${_src}`, type: "execution" });
        }
        if (item.details?.hiveScope)                       pills.push({ text: item.details.hiveScope, type: "context" });
        if (item.whitelistReason)                          pills.push({ text: item.whitelistReason, type: "context" });
        // Service correlation pills
        if (item.details?._serviceStarted)                 pills.push({ text: item.details._svcDisplayNameMatch ? "7036 display-name match" : "service started", type: "correlation" });
        if (item.details?._serviceProcessStarted)          pills.push({ text: "service process observed", type: "correlation" });
        if (item.details?._serviceProcessParent) {
          const pb = (item.details._serviceProcessParent || "").split("\\").pop();
          if (pb === "services.exe")                       pills.push({ text: "started by services.exe", type: "correlation" });
          else if (item.details._serviceProcessParentSuspicious) pills.push({ text: `unexpected parent: ${pb}`, type: "execution" });
        }
        if (item.details?._serviceExecSeen)                pills.push({ text: "registry/DLL evidence", type: "correlation" });
        // WMI + autorun correlation pills
        if (item.details?._wmiComplete)                    pills.push({ text: "complete WMI sub", type: "correlation" });
        if (item.details?._wmiPartial)                     pills.push({ text: "orphaned WMI", type: "correlation" });
        if (item.details?._execSeen)                       pills.push({ text: "autorun executed", type: "correlation" });
        // 4104 correlation/standalone pills
        if (item.details?._ps4104Seen) {
          pills.push({ text: "created via PowerShell", type: "correlation" });
          const sp = item.details._ps4104ScriptPath;
          if (sp) pills.push({ text: sp.split(/[/\\]/).pop(), type: "context" });
        }
        if (item.details?._ps4104Standalone) {
          pills.push({ text: "script block", type: "context" });
          if ((item.details.fragmentCount || 1) > 1) pills.push({ text: `${item.details.fragmentCount} fragments`, type: "context" });
          const ind4104 = item.details._ps4104SuspiciousIndicators || [];
          for (const lbl of ind4104) {
            if (/Encoded|Base64/i.test(lbl))           pills.push({ text: "encoded payload", type: "execution" });
            else if (/Download|WebClient|Bits/i.test(lbl)) pills.push({ text: "download", type: "execution" });
            else if (/Invoke-Expression|iex/i.test(lbl))   pills.push({ text: "IEX", type: "execution" });
            else if (/Defender|MpPreference/i.test(lbl))   pills.push({ text: "security tampering", type: "execution" });
            else if (/Assembly/i.test(lbl))                pills.push({ text: "assembly load", type: "execution" });
          }
        }
        // Confidence pill (only for confirmed/likely)
        if (item.confidence === "confirmed")               pills.push({ text: "confirmed", type: "correlation" });
        else if (item.confidence === "likely")             pills.push({ text: "likely", type: "correlation" });
        // Subtype pills
        if (item.subtype === "service-dll")                pills.push({ text: "ServiceDll", type: "context" });
        if (item.subtype === "service-failure")            pills.push({ text: "FailureCommand", type: "context" });
        if (item.subtype === "service-starttype")          pills.push({ text: "start type change", type: "context" });
        if (item.subtype === "service-rmm")               pills.push({ text: "remote access svc", type: "context" });
        if (item.subtype === "service-rmm-confirmed")     pills.push({ text: "remote access svc", type: "execution" });
        if (item.subtype === "task-execution")             pills.push({ text: "task executed", type: "execution" });
        if (item.subtype === "task-trigger")               pills.push({ text: "trigger fired", type: "execution" });
        // Task XML semantic pills
        if (item.details?._taskHidden)                     pills.push({ text: "hidden", type: "execution" });
        if (item.details?._taskElevated)                   pills.push({ text: "elevated", type: "execution" });
        if (item.details?._taskComHandler)                 pills.push({ text: "COM handler", type: "context" });
        if (item.details?._taskTriggers?.length > 0)       pills.push({ text: item.details._taskTriggers.join("+"), type: "context" });
        if (item.details?._taskPrincipal && !/^(SYSTEM|S-1-5-18|LOCAL SERVICE|NETWORK SERVICE)$/i.test(item.details._taskPrincipal))
                                                           pills.push({ text: `user: ${item.details._taskPrincipal}`, type: "context" });
        if (item.details?._taskXmlPartial)                 pills.push({ text: "task XML partial", type: "context" });
        const seen = new Set();
        item.evidencePills = pills.filter(p => { if (seen.has(p.text)) return false; seen.add(p.text); return true; });
      }

      items.sort((a, b) => b.triageScore - a.triageScore || (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));

      // --- Incident clustering ---
      // Collapse the item list into one row of triage per artifact-per-host. Lives in
      // ./incidents.js so a multi-source run can re-cluster the MERGED item set instead
      // of stitching together one incident list per tab.
      const incidents = clusterIncidents(items, { crossModeRegistry: !!options._crossModeRegistry });

      // --- Build stats ---
      const byCategory = {};
      const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const item of items) {
        byCategory[item.category] = (byCategory[item.category] || 0) + 1;
        bySeverity[item.severity] = (bySeverity[item.severity] || 0) + 1;
      }
      const byIncidentSeverity = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const inc of incidents) byIncidentSeverity[inc.severity] = (byIncidentSeverity[inc.severity] || 0) + 1;

      return {
        items,
        incidents,
        warnings,
        stats: {
          total: items.length,
          incidentCount: incidents.length,
          byCategory,
          bySeverity,
          byIncidentSeverity,
          suspicious: items.filter(i => i.isSuspicious).length,
          suspiciousIncidents: incidents.filter(i => i.isSuspicious).length,
          // Count canonical hosts, not raw strings — otherwise one machine logged both
          // short and FQDN inflates the host count on a single-host collection.
          uniqueComputers: new Set(items.map(i => _corrHost(i.computer)).filter(Boolean)).size,
          categoriesFound: Object.keys(byCategory).length,
          ps4104Scripts: ps4104Reassembled?.length || 0,
          ps4104Correlated: ps4104CorrelatedCount,
          // Registry provenance. `registryHostSource` tells the analyst whether the host on
          // these findings was read (column / SYSTEM hive) or inferred from the collection
          // path; `registryInventorySuppressed` is the count of full-state rows filtered as
          // routine inventory, so a coverage drop is never silent.
          registryHost: registryHost || "",
          registryHostSource,
          registryPlugin: registryPluginInfo,
          registryInventorySuppressed,
          // How many findings could be tied to a remote arrival — the pivot-to-persistence link.
          remoteOriginItems: items.filter((i) => i.remoteOrigin).length,
          remoteArrivals: remoteLogons.length,
        },
        // Handed to the registry pass of a multi-source run, and to the LM handoff.
        _remoteLogons: remoteLogons,
        columns,
        detectedMode: mode,
        error: null,
      };
    } catch (e) {
      return { items: [], incidents: [], warnings: [], stats: {}, columns, detectedMode: mode, error: e.message };
    }
}

module.exports = { previewPersistenceAnalysis, getPersistenceAnalysis, PERSISTENCE_RULE_CATALOG };
