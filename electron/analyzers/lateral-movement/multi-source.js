/**
 * lateral-movement/multi-source.js — Multi-Tab Correlation for Lateral Movement
 *
 * Merges logon events from multiple KAPE triage collections (each in its own tab/database)
 * into a unified analysis. This reveals cross-machine attack paths that are invisible
 * when analyzing each tab independently.
 *
 * Example: DC01 shows WKS02→DC01, FS01 shows WKS02→FS01 — combined you see the
 * full path WKS02 → DC01 → FS01.
 *
 * Architecture:
 *   1. Per-tab column detection (reuses the same detect() patterns as single-tab)
 *   2. Per-tab SQL query with normalized column aliases
 *   3. Merge rows by timestamp, tag each with source tab
 *   4. Feed merged rows into the existing getLateralMovement() via _prequeriedRows
 */

const { dbg } = require("../../logger");
const { resolveSpineEventIds } = require("./detector-registry");
const { getLateralMovement } = require("./index");
const { isHayabusaDataset, isChainsawLogonDataset } = require("../evtx-utils");
const { cmpTs } = require("./time");
const { termSvcChannelGuard } = require("./sql-guards");

// Execution-technique finding categories produced by the single-tab analyzer's
// db-gated secondary scan. In merged mode the synthetic meta has db:null so these never
// run. They are inherently per-host, so we harvest them per-tab against each tab's real
// db and merge them in. "RDP Client Hostname" is intentionally excluded — multi-source
// already reconstructs CLIENTNAME via its own Sysmon EID 13 scan (see allSysmonClients).
const EXECUTION_FINDING_CATEGORIES = new Set([
  "PsExec Native",
  "Impacket Execution",
  "Impacket Summary",
  "Impacket Credential Access",
  "Remote Service Execution",
  "Scheduled Task Remote Execution",
  "Cobalt Strike",
  "LSASS Access",
  "SAM/LSA Registry Dump",
  "Port Forwarding",
  "Kerberoasting",
  "AS-REP Roasting",
  "DCSync",
  "WMI Remote Execution",
  "WMI Remote Activity",
  "WinRM Remote Execution",
  "WinRM Remote Activity",
  "DCOM Remote Execution",
  "OpenSSH Inbound Access",
  "SSH Tunneling",
  "WMI Event Subscription",
  "RMM Suspicious Execution",
  "RMM Executed",
  "RMM Installed",
  "Remote Access Tunnel",
  "Credential Theft",
]);

/**
 * Detect columns for a single tab (mirrors index.js lines 36-85).
 * Returns { columns, isEvtxECmd, isHayabusa, isChainsaw } or null if required columns missing.
 */
function detectTabColumns(meta, ctx) {
  const detect = (patterns) => {
    for (const pat of patterns) {
      const found = meta.headers.find((h) => pat.test(h));
      if (found) return found;
    }
    return null;
  };

  const isEvtxECmd = meta.headers.some((h) => /^RemoteHost$/i.test(h)) && meta.headers.some((h) => /^PayloadData1$/i.test(h));
  const isHayabusa = isHayabusaDataset(meta);
  const isChainsaw = isChainsawLogonDataset(meta);
  const detailsCol = isHayabusa ? detect([/^Details$/i]) : null;
  const extraCol = isHayabusa ? detect([/^ExtraFieldInfo$/i]) : null;

  // Detect if this is a raw EVTX file. Must match the single-tab predicate in index.js
  // exactly (datetime + Provider) — this copy additionally required Channel, so the same
  // tab could be classified raw-EVTX on its own and NOT raw-EVTX inside a merge, which
  // changed which columns were mapped for it.
  const isRawEvtx = !isEvtxECmd && !isHayabusa && !isChainsaw
    && meta.headers.some(h => /^datetime$/i.test(h))
    && meta.headers.some(h => /^Provider$/i.test(h));

  // Detect TerminalServices logs: EID 21-25/39/40/1149 with User/Address/SessionID columns
  const isTermSvcEvtx = isRawEvtx && (
    meta.headers.some(h => /^SessionID$/i.test(h)) || meta.headers.some(h => /^Param1$/i.test(h))
  );

  // Detect Sysmon logs: has Image/TargetObject/RuleName columns
  const isSysmonEvtx = isRawEvtx && (
    meta.headers.some(h => /^Image$/i.test(h)) || meta.headers.some(h => /^TargetObject$/i.test(h))
  );

  const columns = {
    // Source: IpAddress (Security), Address (TS-LSM raw EVTX), Param3 (TS-RCM raw EVTX)
    source:      detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^Source_Network_Address$/i, /^RemoteHost$/i, ...(isChainsaw ? [/^source_ip$/i] : []), ...(isTermSvcEvtx ? [/^Address$/i, /^Param3$/i] : [])]) || detailsCol,
    workstation: detect([/^WorkstationName$/i, /^Workstation_Name$/i, /^SourceHostname$/i, /^SourceComputerName$/i, ...(isChainsaw ? [/^workstation_name$/i] : [])]),
    target:      detect([/^Computer$/i, /^ComputerName$/i, /^computer_name$/i, /^Hostname$/i]),
    // EvtxECmd UserName is the Subject account; PayloadData1 carries the Target user.
    user:        detect([/^TargetUserName$/i, /^Target_User_Name$/i, ...(isEvtxECmd ? [/^PayloadData1$/i] : []), /^UserName$/i, ...(isChainsaw ? [/^target_username$/i] : []), ...(isTermSvcEvtx ? [/^User$/i, /^Param1$/i] : [])]) || detailsCol,
    logonType:   detect([/^LogonType$/i, /^Logon_Type$/i, ...(isChainsaw ? [/^logon_type$/i] : []), ...(isEvtxECmd ? [/^PayloadData2$/i] : [])]) || detailsCol,
    eventId:     detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsaw ? [/^id$/i] : [])]),
    ts:          detect([/^datetime$/i, /^UtcTime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
    domain:      detect([/^TargetDomainName$/i, /^Target_Domain_Name$/i, /^SubjectDomainName$/i, ...(isTermSvcEvtx ? [/^Param2$/i] : [])]) || extraCol || detailsCol,
    // 4778/4779 name the user AccountName, not TargetUserName. Detected separately
    // because detect() returns one column for the whole tab: on a tab that also holds
    // 4624s, `user` resolves to TargetUserName and every reconnect row came back with
    // an empty user, so reconnects never joined their logon session.
    _accountName: detect([/^AccountName$/i, /^Account_Name$/i]),
    clientName:    detect([/^ClientName$/i, /^Client_Name$/i]),
    clientAddress: detect([/^ClientAddress$/i, /^Client_Address$/i, /^ClientIP$/i]),
    // 5145 access rights. WriteData/AppendData/WriteAttributes on ADMIN$ or C$ is a
    // TOOL DROP; ReadData is an inventory or backup agent reading a file. Ignoring
    // the mask scored both identically.
    _accessMask: detect([/^AccessMask$/i, /^Access_Mask$/i]),
    _accessList: detect([/^AccessList$/i, /^Access_List$/i, /^Accesses$/i]),
    shareName: detect([/^ShareName$/i, /^Share_Name$/i]),
    relativeTargetName: detect([/^RelativeTargetName$/i, /^Relative_Target_Name$/i]),
    _remoteHost: isEvtxECmd ? detect([/^RemoteHost$/i]) : null,
    _payloadData1: isEvtxECmd ? detect([/^PayloadData1$/i]) : null,
    _payloadData2: isEvtxECmd ? detect([/^PayloadData2$/i]) : null,
    _payloadData3: isEvtxECmd ? detect([/^PayloadData3$/i]) : null,
    _payloadData4: isEvtxECmd ? detect([/^PayloadData4$/i]) : null,
    _payloadData5: isEvtxECmd ? detect([/^PayloadData5$/i]) : null,
    // EvtxECmd-only fallback: PayloadData1 is the Target user, but rows whose
    // PayloadData1 lacks a "Target:" prefix (e.g. 4672 PrivilegeList) fall back to
    // the UserName column. Mirrors single-tab index.js so merged mode recovers the
    // same usernames (notably 4672 admin-privilege attribution).
    _userNameFallback: isEvtxECmd ? detect([/^UserName$/i]) : null,
    // 4624/4625 authentication mechanism. LogonProcessName distinguishes an
    // interactive logon (User32) from the secondary-logon service (seclogo =
    // runas / runas /netonly) and from a network authentication (NtLmSsp / Kerberos),
    // and AuthenticationPackage says which protocol was actually used. Together they
    // are what separates overpass-the-hash from an ordinary Type 9 — neither column
    // was ever read, which left the Overpass/PtH technique unreachable.
    _logonProcess: detect([/^LogonProcessName$/i, /^Logon_Process_Name$/i, /^LogonProcess$/i]),
    _authPackage: detect([/^AuthenticationPackageName$/i, /^AuthenticationPackage$/i, /^Authentication_Package(Name)?$/i]),
    _logonId: detect([/^TargetLogonId$/i, /^Target_Logon_ID$/i, /^LogonId$/i, /^Logon_ID$/i]),
    _subjectLogonId: detect([/^SubjectLogonId$/i, /^Subject_Logon_ID$/i]),
    _subjectUser: detect([/^SubjectUserName$/i, /^Subject_User_Name$/i]),
    _targetServerName: detect([/^TargetServerName$/i, /^Target_Server_Name$/i]),
    _properties: detect([/^Properties$/i]),
    _channel: detect([/^Channel$/i, /^SourceName$/i, /^Provider$/i]),
    // Raw-EVTX TerminalServices leaves — mirrors single-tab index.js so a raw TS tab
    // merged with others still resolves its source host, user and session id.
    _rawAddress:   isTermSvcEvtx ? detect([/^Address$/i]) : null,
    _rawParam1:    isTermSvcEvtx ? detect([/^Param1$/i]) : null,
    _rawParam2:    isTermSvcEvtx ? detect([/^Param2$/i]) : null,
    _rawParam3:    isTermSvcEvtx ? detect([/^Param3$/i]) : null,
    _rawSessionId: isTermSvcEvtx ? detect([/^SessionID$/i, /^Session_ID$/i]) : null,
    _rawUser:      isTermSvcEvtx ? detect([/^User$/i]) : null,
    _rawReason:    isTermSvcEvtx ? detect([/^Reason$/i, /^ReasonCode$/i]) : null,
    subStatus: detect([/^SubStatus$/i, /^Sub_Status$/i]),
    _statusCol: detect([/^Status$/i]),
    ticketEncryptionType: detect([/^TicketEncryptionType$/i, /^Ticket_Encryption_Type$/i]),
    serviceName: detect([/^ServiceName$/i, /^Service_Name$/i, /^TargetServiceName$/i]),
    ticketOptions: detect([/^TicketOptions$/i, /^Ticket_Options$/i]),
    details: detailsCol,
    extra: extraCol,
  };
  columns._isEvtxECmd = isEvtxECmd;
  columns._isHayabusa = isHayabusa;
  columns._isChainsaw = isChainsaw;
  columns._isRawEvtx = isRawEvtx;
  columns._isTermSvcEvtx = isTermSvcEvtx;
  columns._isSysmonEvtx = isSysmonEvtx;

  // Sysmon tabs: no logon source columns, but useful for CLIENTNAME scan
  // Return a special marker so multi-source can still scan EID 13
  if (isSysmonEvtx) {
    return { columns, isEvtxECmd, isHayabusa, isChainsaw, sysmonOnly: true };
  }

  if (!columns.source && !columns.workstation) return null;
  if (!columns.target) return null;

  return { columns, isEvtxECmd, isHayabusa, isChainsaw };
}

/**
 * Query logon events from a single tab and return normalized rows.
 * Each row has standardized property names (source, target, user, etc.)
 * matching the aliased SQL output from the single-tab analyzer.
 */
function queryTabRows(meta, columns, options, ctx) {
  const {
    eventIds: userEventIds,
    extraEventIds = [],
    maxRows = 500000,
  } = options;

  // Same contract as the single-tab analyzer: an explicit list wins, otherwise derive
  // from enabled detectors. The old hardcoded default here was narrower still than
  // index.js's — it additionally dropped 4771 and the RDP shadow ids.
  const eventIds = Array.isArray(userEventIds) && userEventIds.length > 0
    ? [...new Set([...userEventIds.map(String), ...extraEventIds.map(String)])]
    : resolveSpineEventIds(options.disabledDetectors || [], extraEventIds);

  // Interpolated into LIMIT below — sanitise before it reaches SQL (see index.js).
  const _maxRows = (() => {
    const n = Math.floor(Number(maxRows));
    if (!Number.isFinite(n) || n <= 0) return 500000;
    return Math.min(Math.max(n, 1000), 2000000);
  })();

  const db = meta.db;
  const params = [];
  const whereConditions = [];

  if (columns.eventId && eventIds.length > 0) {
    const safeEid = meta.colMap[columns.eventId];
    if (safeEid) {
      whereConditions.push(`${safeEid} IN (${eventIds.map(() => "?").join(",")})`);
      params.push(...eventIds);
      // Keep Sysmon 20-25 out of the per-tab row budget — see sql-guards.js.
      const _tsGuard = termSvcChannelGuard(safeEid, meta.colMap[columns._channel], eventIds);
      if (_tsGuard) { whereConditions.push(_tsGuard.sql); params.push(..._tsGuard.params); }
    }
  }

  ctx.applyStandardFilters(options, meta, whereConditions, params);

  const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

  const selectParts = ["data.rowid as _rowid"];
  for (const [key, colName] of Object.entries(columns)) {
    if (key.startsWith("_")) continue; // skip internal flags
    if (colName && meta.colMap[colName]) selectParts.push(`${meta.colMap[colName]} as [${key}]`);
  }
  // Also include underscore columns needed for EvtxECmd parsing
  for (const key of ["_remoteHost", "_payloadData1", "_payloadData2", "_payloadData3", "_payloadData4", "_payloadData5", "_channel", "_userNameFallback",
    "_subjectUser", "_targetServerName", "_properties", "_accountName",
    "_logonProcess", "_authPackage", "_logonId", "_subjectLogonId", "_accessMask", "_accessList",
    "_rawAddress", "_rawParam1", "_rawParam2", "_rawParam3", "_rawSessionId", "_rawUser", "_rawReason", "_statusCol"]) {
    const colName = columns[key];
    if (colName && meta.colMap[colName]) selectParts.push(`${meta.colMap[colName]} as [${key}]`);
  }

  // A bare `ORDER BY <col>` is a BINARY text sort, which is only chronological for
  // ISO-like values. Route through the sort_datetime() expression index the same way
  // index.js and db/query-store.js do, so a US-style or "T"-separated column is not
  // returned in lexical order and then merged as if it were chronological.
  const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
  const orderClause = orderCol
    ? (meta.tsColumns?.has?.(columns.ts) ? `ORDER BY sort_datetime(${orderCol}) ASC, data.rowid ASC` : `ORDER BY ${orderCol} ASC`)
    : "ORDER BY data.rowid ASC";

  // Ensure indexes for performance
  try {
    if (columns.eventId) ctx.ensureIndex(meta.tabId, columns.eventId);
    if (columns.ts) ctx.ensureIndex(meta.tabId, columns.ts);
  } catch (_) { /* best effort */ }

  const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${_maxRows}`;
  return db.prepare(sql).all(...params);
}

/**
 * Multi-source lateral movement analysis.
 *
 * @param {Array<{meta, tabId, label}>} metas - Tab metadata objects
 * @param {object} options - Analysis options (same as single-tab)
 * @param {object} ctx - Helper methods from TimelineDB
 * @returns {object} - Same result shape as getLateralMovement()
 */
function getMultiSourceLateralMovement(metas, options = {}, ctx) {
  if (!metas || metas.length === 0) {
    return { nodes: [], edges: [], chains: [], findings: [], incidents: [], groupedSessions: [], stats: {}, warnings: [], scanStats: {}, columns: {}, error: "No tabs selected" };
  }

  // Single tab — just delegate directly
  if (metas.length === 1) {
    return getLateralMovement(metas[0].meta, options, ctx);
  }

  const allRows = [];
  const allComputerHosts = []; // Computer column values across all tabs (for convention detection)
  const allSysmonClients = []; // Sysmon EID 13 CLIENTNAME entries across all tabs
  const tabSummaries = [];
  const warnings = [];
  let primaryColumns = null; // columns from the first successfully-detected tab

  // Guard against NaN/0: a bad maxRows here would divide down to 0 and silently return
  // no rows for every tab. queryTabRows re-clamps, but keep this arm honest too.
  const _totalMaxRows = (() => {
    const n = Math.floor(Number(options.maxRows));
    return Number.isFinite(n) && n > 0 ? Math.min(n, 2000000) : 500000;
  })();
  const perTabMaxRows = Math.max(1000, Math.floor(_totalMaxRows / Math.max(1, metas.length)));

  for (const { meta, tabId, label } of metas) {
    const detection = detectTabColumns(meta, ctx);
    if (!detection) {
      warnings.push(`Tab "${label}": No logon columns detected (not a Security, logon, or Sysmon source) — skipped`);
      continue;
    }

    const { columns } = detection;
    if (!primaryColumns && !detection.sysmonOnly) primaryColumns = columns;

    // Sysmon-only tabs: skip logon row querying, but still scan for CLIENTNAME + Computer hosts
    if (detection.sysmonOnly) {
      dbg("MULTI-LM", `Tab "${label}": Sysmon-only — scanning for CLIENTNAME registry entries`);
      tabSummaries.push({ tabId, label, rowCount: 0, format: "Sysmon (EID 13 scan only)" });
      // Fall through to Computer + CLIENTNAME scans below
    }

    try {
      // Query logon events (skip for Sysmon-only tabs)
      if (!detection.sysmonOnly) {
        const tabOpts = { ...options, maxRows: perTabMaxRows };
        const rows = queryTabRows(meta, columns, tabOpts, ctx);
        if (rows.length >= perTabMaxRows) {
          warnings.push(`Tab "${label}": hit the ${perTabMaxRows.toLocaleString()}-row cap (oldest events kept). Newer activity may be missing.`);
        }

        for (const row of rows) {
          const sourceRowId = Number(row._rowid);
          row._sourceTab = label;
          row._sourceTabId = tabId;
          row._sourceRowId = Number.isFinite(sourceRowId) ? sourceRowId : row._rowid;
          row._sourceFormat = detection.isEvtxECmd ? "EvtxECmd" : detection.isHayabusa ? "Hayabusa" : detection.isChainsaw ? "Chainsaw" : columns._isTermSvcEvtx ? "TerminalServices" : "Standard";
          row._sourceRef = {
            tabId,
            rowId: row._sourceRowId,
            sourceTab: label,
            sourceFormat: row._sourceFormat,
          };
        }

        allRows.push(...rows);
        tabSummaries.push({ tabId, label, rowCount: rows.length, format: detection.isEvtxECmd ? "EvtxECmd" : detection.isHayabusa ? "Hayabusa" : detection.isChainsaw ? "Chainsaw" : columns._isTermSvcEvtx ? "TerminalServices" : "Standard" });
        dbg("MULTI-LM", `Tab "${label}": ${rows.length} logon rows queried`);
      }

      // Collect Computer column values for convention detection (all tabs)
      if (columns.target && meta.colMap[columns.target]) {
        try {
          const compCol = meta.colMap[columns.target];
          const compRows = meta.db.prepare(
            `SELECT ${compCol} as host, COUNT(*) as cnt FROM data WHERE ${compCol} IS NOT NULL AND ${compCol} != '' GROUP BY ${compCol}`
          ).all();
          for (const r of compRows) {
            const h = (r.host || "").toString().trim().toUpperCase();
            if (h) allComputerHosts.push({ host: h, eventCount: r.cnt });
          }
        } catch (_) { /* best effort */ }
      }

      // Scan Sysmon EID 13 CLIENTNAME registry writes (all tabs — Security may have Sysmon events too)
      const eidCol = columns.eventId ? meta.colMap[columns.eventId] : null;
      const tgtObjCol = (() => {
        const pd5 = meta.headers.find(h => /^PayloadData5$/i.test(h));
        if (pd5 && meta.colMap[pd5]) return meta.colMap[pd5];
        const to = meta.headers.find(h => /^TargetObject$/i.test(h));
        if (to && meta.colMap[to]) return meta.colMap[to];
        if (detection.isHayabusa) { const d = meta.headers.find(h => /^Details$/i.test(h)); if (d && meta.colMap[d]) return meta.colMap[d]; }
        return null;
      })();
      const detCol = (() => {
        const pd6 = meta.headers.find(h => /^PayloadData6$/i.test(h));
        if (pd6 && meta.colMap[pd6]) return meta.colMap[pd6];
        // Raw EVTX Sysmon: Details field from EventData
        const det = meta.headers.find(h => /^Details$/i.test(h));
        if (det && meta.colMap[det]) return meta.colMap[det];
        return null;
      })();
      if (eidCol && tgtObjCol) {
        try {
          const hostCol = columns.target ? meta.colMap[columns.target] : null;
          const tsCol = columns.ts ? meta.colMap[columns.ts] : null;
          const selParts = ["data.rowid as _rid"];
          if (tsCol) selParts.push(`${tsCol} as _ts`);
          if (hostCol) selParts.push(`${hostCol} as _host`);
          selParts.push(`${tgtObjCol} as _tgtObj`);
          if (detCol && detCol !== tgtObjCol) selParts.push(`${detCol} as _details`);
          const cnRows = meta.db.prepare(
            `SELECT ${selParts.join(", ")} FROM data WHERE ${eidCol} = '13' AND ${tgtObjCol} LIKE '%CLIENTNAME%' LIMIT 10000`
          ).all();
          for (const row of cnRows) {
            const tgtObj = (row._tgtObj || "").toString();
            if (!/CLIENTNAME/i.test(tgtObj)) continue;
            let clientHost = null;
            if (row._details) {
              const ds = row._details.toString().trim();
              const dm = ds.match(/^Details:\s*(.+)$/i);
              clientHost = dm ? dm[1].trim() : ds;
            }
            if (!clientHost || clientHost === "-" || !clientHost.trim()) continue;
            clientHost = clientHost.toUpperCase();
            const target = (row._host || "").toString().trim().toUpperCase();
            if (clientHost === target || clientHost === target.split(".")[0]) continue;
            const sourceRowId = Number(row._rid);
            allSysmonClients.push({
              clientHost,
              target,
              ts: row._ts || "",
              sourceTab: label,
              sourceTabId: tabId,
              sourceFormat: "Sysmon",
              evidenceRefs: Number.isFinite(sourceRowId)
                ? [{ tabId, rowId: sourceRowId, sourceTab: label, sourceFormat: "Sysmon" }]
                : [],
            });
          }
          if (detection.sysmonOnly) dbg("MULTI-LM", `Tab "${label}": ${allSysmonClients.length} CLIENTNAME entries found`);
        } catch (_) { /* best effort */ }
      }
    } catch (err) {
      warnings.push(`Tab "${label}": Query failed — ${err.message}`);
      dbg("MULTI-LM", `Tab "${label}" query failed`, { error: err.message });
    }
  }

  if (allRows.length === 0) {
    return { nodes: [], edges: [], chains: [], findings: [], incidents: [], groupedSessions: [], stats: {}, warnings, scanStats: {}, columns: primaryColumns || {}, error: "No logon events found across selected tabs" };
  }

  // Sort merged rows by timestamp. This MUST be a parsed compare, not a string
  // compare: tabs contribute different renderings of the same instant (EvtxECmd
  // "2026-01-02 08:00:00" vs raw EVTX "2026-01-02T08:00:00Z"), and a space sorts
  // before "T", so a lexical merge interleaved the tabs by format instead of by
  // time and every cross-tab chain, window and sequence was built out of order.
  allRows.sort((a, b) => cmpTs(a.ts || a.datetime || "", b.ts || b.datetime || ""));

  dbg("MULTI-LM", `Merged ${allRows.length} rows from ${tabSummaries.length} tabs`);

  // Build a synthetic meta for the merged dataset
  // The analyzer needs meta.headers, meta.colMap, meta.db, meta.tabId
  // For pre-queried rows, only headers/colMap matter (db is bypassed)
  const syntheticMeta = {
    tabId: "__multi_source__",
    headers: primaryColumns ? Object.values(primaryColumns).filter(Boolean) : [],
    colMap: {},
    db: null, // not used when _prequeriedRows is set
  };
  // Build identity colMap: each column name maps to itself (rows are already aliased)
  if (primaryColumns) {
    for (const [key, colName] of Object.entries(primaryColumns)) {
      if (colName) syntheticMeta.colMap[colName] = `[${key}]`;
    }
    // Also map alias names to themselves for direct property access
    for (const key of Object.keys(primaryColumns)) {
      syntheticMeta.colMap[key] = `[${key}]`;
    }
  }

  // Run the standard analyzer with pre-queried rows
  // Pass collected Computer hosts so convention detection works in multi-source mode
  const mergedOptions = {
    ...options,
    _prequeriedRows: allRows,
    _multiSourceComputerHosts: allComputerHosts,
    _multiSourceSysmonClients: allSysmonClients,
  };

  const result = getLateralMovement(syntheticMeta, mergedOptions, ctx);

  // ── Per-tab execution-technique detection ──
  // The merged run (above) covers the cross-host logon graph, brute force, spray,
  // credential compromise, admin-share and RDP-client findings. But PsExec/Impacket/
  // remote-service/Cobalt-Strike/LSASS/Kerberoasting/etc. detection queries a live db
  // directly, which the synthetic merged meta (db:null) cannot provide. These techniques
  // are per-host, so run the normal single-tab analysis against each tab's real db and
  // merge in just the execution-technique findings (deduped, re-ID'd). Note: a tab with
  // no logon/source columns (e.g. a process-only Sysmon export) is skipped by the
  // single-tab analyzer's column guard and won't contribute here.
  result.findings = result.findings || [];
  let _execMaxFid = result.findings.reduce((m, f) => Math.max(m, Number(f.id) || 0), 0);
  const _execSeen = new Set(result.findings.map((f) => `${f.category}|${f.source}|${f.target}|${f.title}`));
  let _execAdded = 0;
  for (const { meta, tabId, label } of metas) {
    try {
      const single = getLateralMovement(meta, { ...options }, ctx);
      for (const f of single.findings || []) {
        if (!EXECUTION_FINDING_CATEGORIES.has(f.category)) continue;
        const sig = `${f.category}|${f.source}|${f.target}|${f.title}`;
        if (_execSeen.has(sig)) continue;
        _execSeen.add(sig);
        result.findings.push({ ...f, id: ++_execMaxFid, _sourceTab: label, _sourceTabId: tabId });
        _execAdded++;
      }
    } catch (err) {
      warnings.push(`Tab "${label}": execution-technique scan failed — ${err.message}`);
      dbg("MULTI-LM", `Tab "${label}" execution scan failed`, { error: err.message });
    }
  }
  if (_execAdded > 0) dbg("MULTI-LM", `Merged ${_execAdded} execution-technique findings from per-tab scans`);

  // Enrich result with multi-source metadata
  result.multiSource = true;
  result.tabSummaries = tabSummaries;
  if (warnings.length > 0) {
    result.warnings = [...(result.warnings || []), ...warnings];
  }

  // Enrich stats
  if (result.stats) {
    result.stats.tabCount = tabSummaries.length;
    result.stats.totalMergedRows = allRows.length;
    result.stats.perTabRows = tabSummaries.map(t => ({ label: t.label, rows: t.rowCount, format: t.format }));
    result.stats.executionFindingsFromTabs = _execAdded;
  }

  return result;
}

/**
 * Preview for multi-source mode — returns combined event counts per tab.
 */
function previewMultiSourceLateralMovement(metas, options = {}, ctx) {
  if (!metas || metas.length === 0) {
    return { tabs: [], totalEvents: 0, error: "No tabs selected" };
  }

  const tabs = [];
  let totalEvents = 0;

  for (const { meta, tabId, label } of metas) {
    const detection = detectTabColumns(meta, ctx);
    if (!detection) {
      tabs.push({ tabId, label, error: "Cannot detect columns", eventCount: 0, format: null });
      continue;
    }

    const { columns, isEvtxECmd, isHayabusa, isChainsaw } = detection;
    const format = isEvtxECmd ? "EvtxECmd" : isHayabusa ? "Hayabusa" : isChainsaw ? "Chainsaw" : "Standard";

    try {
      const db = meta.db;
      const eventIds = options.eventIds || ["4624","4625","4634","4647","4648","4672","4769","4776","4778","4779","5140","5145","1149","21","22","23","24","25","39","40"];

      let count = 0;
      if (columns.eventId && meta.colMap[columns.eventId]) {
        const safeEid = meta.colMap[columns.eventId];
        const placeholders = eventIds.map(() => "?").join(",");
        const row = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${safeEid} IN (${placeholders})`).get(...eventIds);
        count = row?.cnt || 0;
      }

      tabs.push({ tabId, label, eventCount: count, format, columns: Object.fromEntries(Object.entries(columns).filter(([k, v]) => v && !k.startsWith("_"))) });
      totalEvents += count;
    } catch (err) {
      tabs.push({ tabId, label, error: err.message, eventCount: 0, format });
    }
  }

  return { tabs, totalEvents, error: null };
}

module.exports = { getMultiSourceLateralMovement, previewMultiSourceLateralMovement };
