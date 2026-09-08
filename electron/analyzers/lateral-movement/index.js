const { cleanWrappedField, compactGet, compactGetInt, extractFirstInteger, isChainsawLogonDataset, isHayabusaDataset, parseCompactKeyValues, resolveEventChannel } = require("../evtx-utils");
const { detectConventions, generateConventionFindings } = require("./convention-detector");
const { buildGraphAndChains } = require("./build-graph");
const { detectCredentialAttacks } = require("./detectors/credential-attacks");
const { createEvidenceHelpers } = require("./evidence");
const { createTelemetryTracker } = require("./telemetry");
const { correlateTriageAndCluster, buildFindingPairs, buildChainEdges } = require("./processing/triage-and-clustering");
const { clusterCampaigns, enrichEdgesAndChains } = require("./processing/campaign-clustering");
const { scoreRdpSessions } = require("./processing/rdp-scoring");
const { aggregateAccounts } = require("./assemble/accounts");
const { computeSysmonRdpAndCoverage } = require("./processing/sysmon-rdp-coverage");
const { detectAdminShareAndExecution } = require("./detectors/admin-share-and-execution");
const { runProcessServiceScan } = require("./detectors/process-service-scan");
const { normalizeHostEndpoint } = require("./endpoint-normalize");
const { dbg } = require("../../logger");
const { resolveSpineEventIds } = require("./detector-registry");
const { termSvcChannelGuard } = require("./sql-guards");
const { tsMs, cmpTs } = require("./time");
const {
  EXCLUDED_IPS,
  SERVICE_RE,
  SESSION_ONLY_EVENTS,
  RDP_EVENT_DESC,
  DC_PAT: _DC_PAT,
  SRV_PAT: _SRV_PAT,
  MGMT_SRC_PAT: _MGMT_SRC_PAT,
  SEV_ORDER: sevOrder,
  TELEMETRY_CATEGORIES,
  PRIVILEGED_NAME_RE,
} = require("./constants");

/**
 * Lateral Movement analysis — extracted from TimelineDB.getLateralMovement().
 *
 * @param {object} meta   - Database handle: {db, headers, colMap, tabId}
 * @param {object} options - Analysis options (eventIds, excludeLocalLogons, etc.)
 * @param {object} ctx    - Helper methods from TimelineDB instance:
 *   { applyStandardFilters, cleanWrappedField, compactGet, compactGetInt,
 *     ensureIndex, extractFirstInteger, isChainsawLogonDataset,
 *     isHayabusaDataset, lmPreviewCache, parseCompactKeyValues,
 *     resolveEventChannel }
 * @returns {object} Analysis results: { nodes, edges, chains, rdpSessions, findings, ... }
 */
function getLateralMovement(meta, options = {}, ctx) {
    if (!meta) return { nodes: [], edges: [], chains: [], stats: {}, columns: {}, error: "No database" };

    const {
      sourceCol: userSourceCol, targetCol: userTargetCol,
      userCol: userUserCol, logonTypeCol: userLogonTypeCol,
      eventIdCol: userEventIdCol, tsCol: userTsCol, domainCol: userDomainCol,
      syntheticTargetHost = "",
      eventIds: userEventIds,
      extraEventIds = [],
      excludeLocalLogons = true,
      excludeServiceAccounts = true,
      maxRows = 500000,
      disabledDetectors = [],
      rmmMode = "all",
      scanLimits = {},
      scanPageSize = 5000,
      requireMicrosoftSignature = false,
    } = options;
    const _disabledSet = new Set(disabledDetectors);

    // Callers may still pin an explicit list (tests, restored sessions, power users).
    // Otherwise the set is derived from which detectors are actually enabled, so a
    // detector can never be starved of the events it needs — the renderer used to send
    // a hand-maintained list that silently omitted 5140/5145/4776/4771/20/32-35.
    const eventIds = Array.isArray(userEventIds) && userEventIds.length > 0
      ? [...new Set([...userEventIds.map(String), ...extraEventIds.map(String)])]
      : resolveSpineEventIds(disabledDetectors, extraEventIds);

    // maxRows is interpolated into the LIMIT clause (it cannot be a bound parameter in the
    // prepared-statement shape used below), so it must never reach SQL unvalidated. Mirrors
    // the sanitising already done for scan limits in detectors/process-service-scan.js.
    const MAX_ROWS_CEILING = 2000000;
    const _maxRows = (() => {
      const n = Math.floor(Number(maxRows));
      if (!Number.isFinite(n) || n <= 0) return 500000;
      return Math.min(Math.max(n, 1000), MAX_ROWS_CEILING);
    })();

    const detect = (patterns) => {
      for (const pat of patterns) {
        const found = meta.headers.find((h) => pat.test(h));
        if (found) return found;
      }
      return null;
    };

    // Detect EvtxECmd format (KAPE output): RemoteHost, PayloadData1-6
    const isEvtxECmd = meta.headers.some((h) => /^RemoteHost$/i.test(h)) && meta.headers.some((h) => /^PayloadData1$/i.test(h));
    const isHayabusa = isHayabusaDataset(meta);
    const isChainsaw = isChainsawLogonDataset(meta);
    const detailsCol = isHayabusa ? detect([/^Details$/i]) : null;
    const extraCol = isHayabusa ? detect([/^ExtraFieldInfo$/i]) : null;
    // Detect raw EVTX TerminalServices logs (LocalSessionManager/RemoteConnectionManager)
    // These have Address/Param3 as source IP, User/Param1 as user, SessionID as session
    const isRawEvtx = !isEvtxECmd && !isHayabusa && !isChainsaw
      && meta.headers.some(h => /^datetime$/i.test(h)) && meta.headers.some(h => /^Provider$/i.test(h));
    const isTermSvcEvtx = isRawEvtx && (
      meta.headers.some(h => /^SessionID$/i.test(h)) || meta.headers.some(h => /^Param1$/i.test(h))
    );

    const columns = {
      source:      userSourceCol    || detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^Source_Network_Address$/i, /^RemoteHost$/i, ...(isChainsaw ? [/^source_ip$/i] : []), ...(isTermSvcEvtx ? [/^Address$/i, /^Param3$/i] : [])]) || detailsCol,
      workstation: detect([/^WorkstationName$/i, /^Workstation_Name$/i, /^SourceHostname$/i, /^SourceComputerName$/i, ...(isChainsaw ? [/^workstation_name$/i] : [])]),
      target:      userTargetCol    || detect([/^Computer$/i, /^ComputerName$/i, /^computer_name$/i, /^Hostname$/i]),
      // EvtxECmd column priority: prefer PayloadData1 ("Target: DOMAIN\\User") over the
      // raw UserName column. EvtxECmd's UserName is the *Subject* (initiator) of the event,
      // which for service/system-context logons is literally "-\\-" — picking it leaves the
      // standard parser unable to extract a username and accounts aggregation collapses.
      // PayloadData1 carries the *Target* user we actually want to graph by.
      user:        userUserCol      || detect([/^TargetUserName$/i, /^Target_User_Name$/i, ...(isEvtxECmd ? [/^PayloadData1$/i] : []), /^UserName$/i, ...(isChainsaw ? [/^target_username$/i] : []), ...(isTermSvcEvtx ? [/^User$/i, /^Param1$/i] : [])]) || detailsCol,
      // EvtxECmd-only fallback: when PayloadData1 doesn't carry a "Target:" prefix
      // (e.g. 4672 PrivilegeList rows), look at UserName which often holds
      // "DOMAIN\\user (SID)" — strip the SID suffix and use that.
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
      logonType:   userLogonTypeCol || detect([/^LogonType$/i, /^Logon_Type$/i, ...(isChainsaw ? [/^logon_type$/i] : []), ...(isEvtxECmd ? [/^PayloadData2$/i] : [])]) || detailsCol,
      eventId:     userEventIdCol   || detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsaw ? [/^id$/i] : [])]),
      ts:          userTsCol        || detect([/^datetime$/i, /^UtcTime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
      domain:      userDomainCol    || detect([/^TargetDomainName$/i, /^Target_Domain_Name$/i, /^SubjectDomainName$/i, ...(isTermSvcEvtx ? [/^Param2$/i] : [])]) || extraCol || detailsCol,
      // 4778/4779 name the user AccountName, not TargetUserName. Detected separately
      // because detect() returns one column for the whole tab: on a tab that also holds
      // 4624s, `user` resolves to TargetUserName and every reconnect row came back with
      // an empty user, so reconnects never joined their logon session.
      _accountName: detect([/^AccountName$/i, /^Account_Name$/i]),
      // 4778 session reconnect columns (RDP lateral movement — attacker hostname/IP)
      clientName:    detect([/^ClientName$/i, /^Client_Name$/i]),
      clientAddress: detect([/^ClientAddress$/i, /^Client_Address$/i, /^ClientIP$/i]),
      // 5145 access rights. WriteData/AppendData/WriteAttributes on ADMIN$ or C$ is a
      // TOOL DROP; ReadData is an inventory or backup agent reading a file. Ignoring
      // the mask scored both identically.
      _accessMask: detect([/^AccessMask$/i, /^Access_Mask$/i]),
      _accessList: detect([/^AccessList$/i, /^Access_List$/i, /^Accesses$/i]),
      // 5140/5145 share access columns
      shareName: detect([/^ShareName$/i, /^Share_Name$/i]),
      relativeTargetName: detect([/^RelativeTargetName$/i, /^Relative_Target_Name$/i]),
      // EvtxECmd extra columns for value parsing
      _remoteHost: isEvtxECmd ? detect([/^RemoteHost$/i]) : null,
      _payloadData1: isEvtxECmd ? detect([/^PayloadData1$/i]) : null,
      _payloadData2: isEvtxECmd ? detect([/^PayloadData2$/i]) : null,
      _payloadData3: isEvtxECmd ? detect([/^PayloadData3$/i]) : null,
      _payloadData4: isEvtxECmd ? detect([/^PayloadData4$/i]) : null,
      _payloadData5: isEvtxECmd ? detect([/^PayloadData5$/i]) : null,
      _channel: detect([/^Channel$/i, /^SourceName$/i, /^Provider$/i]),
      // Raw-EVTX TerminalServices leaves. EvtxECmd packs these into PayloadData1-3, but a
      // raw .evtx import keeps them as separate UserData/EventXML columns:
      //   LocalSessionManager 21/22/24/25 -> User, SessionID, Address
      //   RemoteConnectionManager 1149    -> Param1 (user), Param2 (domain), Param3 (source)
      // These are mapped individually rather than relying on `columns.source`, because
      // detect() returns the FIRST matching header — on a tab holding both channels the
      // single source column can only ever serve one of the two record shapes.
      _rawAddress:   isTermSvcEvtx ? detect([/^Address$/i]) : null,
      _rawParam1:    isTermSvcEvtx ? detect([/^Param1$/i]) : null,
      _rawParam2:    isTermSvcEvtx ? detect([/^Param2$/i]) : null,
      _rawParam3:    isTermSvcEvtx ? detect([/^Param3$/i]) : null,
      _rawSessionId: isTermSvcEvtx ? detect([/^SessionID$/i, /^Session_ID$/i]) : null,
      _rawUser:      isTermSvcEvtx ? detect([/^User$/i]) : null,
      // EID 39/40 carry the disconnect reason in a <Reason> leaf (reason 5 =
      // "replaced by another connection", which feeds RDP suspicion scoring).
      _rawReason:    isTermSvcEvtx ? detect([/^Reason$/i, /^ReasonCode$/i]) : null,
      // SubStatus for 4625 failure reason (may be in dedicated column or PayloadData)
      subStatus: detect([/^SubStatus$/i, /^Sub_Status$/i]),
      // 4771 carries its failure code in Status, not SubStatus. Kept separate so the
      // 4625 path (different semantics) is unaffected.
      _statusCol: detect([/^Status$/i]),
      ticketEncryptionType: detect([/^TicketEncryptionType$/i, /^Ticket_Encryption_Type$/i]),
      serviceName: detect([/^ServiceName$/i, /^Service_Name$/i, /^TargetServiceName$/i]),
      ticketOptions: detect([/^TicketOptions$/i, /^Ticket_Options$/i]),
      // 4768 pre-authentication type — PreAuthType=0 is the defining AS-REP roasting signal
      preAuthType: detect([/^PreAuthType$/i, /^Pre_Auth_Type$/i, /^Pre-Authentication-Type$/i]),
      details: detailsCol,
      extra: extraCol,
    };
    columns._isEvtxECmd = isEvtxECmd;
    columns._isHayabusa = isHayabusa;
    columns._isChainsaw = isChainsaw;
    columns._syntheticTarget = !columns.target && (syntheticTargetHost || isChainsaw) ? (syntheticTargetHost || "LOCAL_HOST") : "";

    if (!columns.source && !columns.workstation) return { nodes: [], edges: [], chains: [], stats: {}, columns, error: "Cannot detect source host column (IpAddress, WorkstationName, or RemoteHost)" };
    if (!columns.target && !columns._syntheticTarget) return { nodes: [], edges: [], chains: [], stats: {}, columns, error: "Cannot detect target host column (Computer)" };

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    if (columns.eventId && eventIds.length > 0) {
      const safeEid = meta.colMap[columns.eventId];
      if (safeEid) {
        whereConditions.push(`${safeEid} IN (${eventIds.map(() => "?").join(",")})`);
        params.push(...eventIds);
        // Keep Sysmon 20-25 out of the row budget — see sql-guards.js.
        const _tsGuard = termSvcChannelGuard(safeEid, meta.colMap[columns._channel], eventIds);
        if (_tsGuard) { whereConditions.push(_tsGuard.sql); params.push(..._tsGuard.params); }
      }
    }

    ctx.applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    const selectParts = ["data.rowid as _rowid"];
    for (const [key, colName] of Object.entries(columns)) {
      if (colName && meta.colMap[colName]) selectParts.push(`${meta.colMap[colName]} as [${key}]`);
    }

    // A bare `ORDER BY <col>` is a BINARY text sort, which is only chronological for
    // ISO-like timestamps — a US-style "3/10/2026 8:00:00 AM" column comes back in the
    // wrong order, corrupting session reconstruction, chain gaps and every first/last-seen
    // value. It also could not use the sort_datetime() expression index that ensureIndex
    // builds, so it materialised a full sort for nothing. Match db/query-store.js:290.
    const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
    const orderClause = orderCol
      ? (meta.tsColumns?.has?.(columns.ts) ? `ORDER BY sort_datetime(${orderCol}) ASC, data.rowid ASC` : `ORDER BY ${orderCol} ASC`)
      : "ORDER BY data.rowid ASC";

    try {
      // Multi-source mode: rows are pre-queried and normalized by multi-source.js
      let rows;
      if (options._prequeriedRows) {
        rows = options._prequeriedRows;
      } else {
        // Ensure indexes on key columns to speed up WHERE + ORDER BY
        if (columns.eventId) ctx.ensureIndex(meta.tabId, columns.eventId);
        if (columns.ts) ctx.ensureIndex(meta.tabId, columns.ts);

        // Invalidate stale preview cache for this tab (analysis params may have changed)
        if (ctx.lmPreviewCache) {
          const prefix = JSON.stringify(meta.tabId) + ",";
          for (const k of ctx.lmPreviewCache.keys()) { if (k.startsWith("[" + prefix)) ctx.lmPreviewCache.delete(k); }
        }

        const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${_maxRows}`;
        rows = db.prepare(sql).all(...params);
      }

      // EXCLUDED_IPS, SERVICE_RE, SESSION_ONLY_EVENTS, RDP_EVENT_DESC → ./constants

      const edgeMap = new Map();
      const hostSet = new Map();
      const timeOrdered = [];
      const rdpEvents = []; // collect all events for RDP session correlation
      const privLogonEvents = []; // 4672 occurrences { userKey, host, ts } for scoped-admin correlation
      const { _makeEvidenceRef, _dedupeEvidenceRefs, _rowEvidenceRef, _refsFromEvents, _refsFromHits, _rowidsFromRefs, _attachEvidenceRefs } = createEvidenceHelpers(meta);
      // Telemetry trackers (per-host / per-user / dataset-wide counts) → ./telemetry
      const { hostTelemetry, userEventCounts, userEventCountsScoped, userEventOriginalName, datasetEventCounts, userFirstSuccessTs, _bumpHostTelemetry, _bumpUserEvent, _bumpUserEventScoped, _bumpDatasetEvent } = createTelemetryTracker();

      const _normLmHost = (value) => normalizeHostEndpoint(
        cleanWrappedField(value).replace(/^[A-Z]+\/+/i, ""),
      );
      // IP-to-hostname resolution map — populated when EvtxECmd "WorkstationName (IpAddress)" provides both
      const _ipToHostname = new Map(); // IP -> hostname (from events where both are present)

      // Stage isolation. The pipeline used to sit under one try/catch, so a single bad
      // timestamp anywhere discarded every finding the earlier stages had already
      // produced. Each stage now degrades to an empty result of its own shape and
      // records a warning, so one broken stage costs one results tab, not the analysis.
      const _stageWarnings = [];
      // Stage boundaries double as the progress signal. The renderer previously animated
      // an eased curve on a timer with no connection to the analysis, so a stalled scan
      // still looked like it was advancing.
      const _progressCb = typeof options.progressCb === "function" ? options.progressCb : null;
      const _stageOrder = [
        "Event graph", "Process/service scan", "Admin share / remote execution",
        "Credential attacks", "RDP scoring", "Edge and chain enrichment",
        "Telemetry coverage", "Evidence refs", "Triage and clustering",
        "Campaign clustering", "Accounts",
      ];
      let _stageDone = 0;
      const runStage = (label, fn, fallback) => {
        if (_progressCb) {
          try {
            _progressCb({
              stage: label,
              progress: Math.round((_stageDone / _stageOrder.length) * 100),
              stageIndex: _stageDone,
              stageCount: _stageOrder.length,
            });
          } catch { /* progress is advisory */ }
        }
        _stageDone++;
        try {
          return fn();
        } catch (e) {
          const msg = e && e.message ? e.message : String(e);
          _stageWarnings.push(`${label} failed: ${msg}`);
          dbg("LM", `stage failed: ${label}`, { error: msg });
          return typeof fallback === "function" ? fallback() : fallback;
        }
      };

      // === Parse events -> graph + RDP sessions + chains + convention outliers -> ./build-graph.js ===
      const _spine = runStage(
        "Event graph",
        () => buildGraphAndChains({ rows, columns, meta, options, db, edgeMap, hostSet, timeOrdered, rdpEvents, _ipToHostname, isEvtxECmd, isHayabusa, _dedupeEvidenceRefs, _rowEvidenceRef, _refsFromEvents, _rowidsFromRefs, _bumpHostTelemetry, _bumpUserEvent, _bumpUserEventScoped, _bumpDatasetEvent, _normLmHost, excludeLocalLogons, excludeServiceAccounts, privLogonEvents, hostTelemetry }),
        () => ({ rdpSessions: [], chains: [], findings: [], fid: 0, _outlierHosts: new Set(), _computerHosts: new Set(), _conventionOutliers: new Map(), detectOutlier: () => "", chainWarnings: [] }),
      );
      const rdpSessions = _spine.rdpSessions;
      const chains = _spine.chains;
      const findings = _spine.findings;
      let fid = _spine.fid;
      const _outlierHosts = _spine._outlierHosts;
      const _computerHosts = _spine._computerHosts;
      const _conventionOutliers = _spine._conventionOutliers;
      const detectOutlier = _spine.detectOutlier;

      // === Process/service/task scan + per-detector emitters (incl. Cobalt Strike) → detectors/process-service-scan.js ===
      const _scanResult = runStage(
        "Process/service scan",
        () => runProcessServiceScan({ columns, meta, db, isHayabusa, timeOrdered, scanLimits, scanPageSize, _bumpDatasetEvent, _normLmHost, _bumpHostTelemetry, requireMicrosoftSignature, findings, _disabledSet, rmmMode, _outlierHosts, hostSet, fid }),
        // _usersFromCorrelation / _sourcesFromCorrelation are hit-mapping FUNCTIONS, not
        // collections — the downstream detector calls them per finding.
        () => ({ fid, warnings: [], scanStats: {}, _scanEidCol: null, _usersFromCorrelation: () => [], _sourcesFromCorrelation: () => [], _lsassAccessHits: [], _credTheftCmdHits: [] }),
      );
      fid = _scanResult.fid;
      const warnings = _scanResult.warnings;
      if (!options._prequeriedRows && rows.length >= _maxRows) {
        warnings.push(`Query hit the ${_maxRows.toLocaleString()}-row cap (oldest events kept). Newer activity may be missing — raise the row limit or filter first.`);
      }
      const scanStats = _scanResult.scanStats;
      const _scanEidCol = _scanResult._scanEidCol;
      const _usersFromCorrelation = _scanResult._usersFromCorrelation;
      const _sourcesFromCorrelation = _scanResult._sourcesFromCorrelation;
      const _lsassAccessHits = _scanResult._lsassAccessHits;
      const _credTheftCmdHits = _scanResult._credTheftCmdHits;

      // === Admin-share / remote-exec-sequence / service-exec / LSASS / cred-theft detectors → detectors/admin-share-and-execution.js ===
      fid = runStage(
        "Admin share / remote execution",
        () => detectAdminShareAndExecution({ timeOrdered, findings, edgeMap, columns, warnings, chains, meta, _outlierHosts, _dedupeEvidenceRefs, _refsFromHits, _rowidsFromRefs, _attachEvidenceRefs, _usersFromCorrelation, _sourcesFromCorrelation, _disabledSet, _lsassAccessHits, _credTheftCmdHits, fid }),
        () => ({ fid }),
      ).fid;

      const _splitEntityList = (value) => String(value || "")
        .split(",")
        .map((v) => v.trim().toUpperCase())
        .filter(Boolean);
      // UTC-anchored (see time.js). The old form stripped the zone and parsed
      // host-local, so finding<->event correlation windows moved with the analyst's
      // timezone and misbehaved across their DST change.
      const _parseLmTs = (value) => tsMs(value);
      // This runs once per finding over the whole event array. Parsing each event's
      // timestamp and upper-casing its hosts inside that loop meant the same work was
      // redone for every finding — on a 500K-row tab with a few hundred findings that
      // is O(10^8) Date constructions. Derive each event's comparison keys once and
      // cache them on the event.
      const _evtKeys = (evt) => {
        let k = evt._lmKeys;
        if (k === undefined) {
          k = {
            ms: _parseLmTs(evt.ts),
            eid: String(evt.eventId),
            src: String(evt.source || "").trim().toUpperCase(),
            tgt: String(evt.target || "").trim().toUpperCase(),
          };
          evt._lmKeys = k;
        }
        return k;
      };
      const _refsForFindingWindow = (finding) => {
        const fromMs = _parseLmTs(finding?.timeRange?.from);
        const toMs = _parseLmTs(finding?.timeRange?.to) ?? fromMs;
        const sources = new Set(_splitEntityList(finding?.source));
        const targets = new Set(_splitEntityList(finding?.target));
        const filterHosts = new Set((finding?.filterHosts || []).map((h) => String(h || "").trim().toUpperCase()).filter(Boolean));
        const filterEids = new Set((finding?.filterEids || []).map(String));
        const refs = [];
        for (const evt of timeOrdered) {
          if (refs.length >= 5000) break;
          const k = _evtKeys(evt);
          if (filterEids.size > 0 && !filterEids.has(k.eid)) continue;
          if (fromMs != null && k.ms != null && k.ms < fromMs) continue;
          if (toMs != null && k.ms != null && k.ms > toMs) continue;
          if (sources.size > 0 && !sources.has(k.src)) continue;
          if (targets.size > 0 && !targets.has(k.tgt)) continue;
          if (sources.size === 0 && targets.size === 0 && filterHosts.size > 0 && !filterHosts.has(k.src) && !filterHosts.has(k.tgt)) continue;
          refs.push(...(evt.evidenceRefs || []));
        }
        return _dedupeEvidenceRefs(refs);
      };
      const _normalizeFindingEvidenceRefs = () => {
        for (const f of findings) {
          const refs = [];
          if (Array.isArray(f.evidenceRefs)) refs.push(...f.evidenceRefs);
          if (Array.isArray(f.itemRowids) && meta.tabId !== "__multi_source__") {
            for (const rowId of f.itemRowids) refs.push({ tabId: meta.tabId, rowId });
          }
          refs.push(..._refsForFindingWindow(f));
          _attachEvidenceRefs(f, refs);
        }
      };
      // ── Every finding-emitting stage runs BEFORE triage scoring ──────────────────
      // These used to run after it, so the findings they emit (Kerberoasting, AS-REP,
      // DCSync, Concurrent RDP, Lateral Pivot, Operator Host, Anomalous Hostname, the
      // Sysmon RDP-client findings) never got a triageScore or relatedFindingIds — the
      // UI rendered them as 0 and sorted a critical DCSync below a low First-Seen. They
      // were also invisible to incident clustering.

      // === Credential-attack detectors (Kerberoasting / AS-REP / DCSync) → detectors/credential-attacks.js ===
      // Fully independent: issues its own queries, reads no cross-stage state.
      fid = runStage(
        "Credential attacks",
        () => detectCredentialAttacks({ db, meta, columns, isEvtxECmd, disabledSet: _disabledSet, findings, warnings, fid }),
        fid,
      );

      // === RDP scoring: episode clustering + session suspicion + concurrent-RDP detection → processing/rdp-scoring.js ===
      // Builds its own finding-pair index now that it precedes triage.
      fid = runStage(
        "RDP scoring",
        () => scoreRdpSessions({ timeOrdered, edgeMap, rdpSessions, _outlierHosts, findings, fid, options }),
        () => ({ fid }),
      ).fid;

      // === Edge risk + chain confidence + pivot/operator/anomalous-hostname findings → processing/campaign-clustering.js ===
      // The campaign half needs `incidents` and stays after triage; this half does not.
      fid = runStage(
        "Edge and chain enrichment",
        () => enrichEdgesAndChains({ findings, chains, edgeMap, timeOrdered, hostSet, _chainEdges: buildChainEdges(chains), _findingPairs: buildFindingPairs(findings), _outlierHosts, _conventionOutliers, _computerHosts, detectOutlier, _dedupeEvidenceRefs, _rowidsFromRefs, fid }),
        () => ({ fid }),
      ).fid;

      // === Sysmon EID13 CLIENTNAME + session grouping + telemetry coverage → processing/sysmon-rdp-coverage.js ===
      // Emits the RDP-client findings, so it must also precede triage. Its coverage math
      // reads rdpSessions, which RDP scoring has already enriched above.
      const _r14 = runStage(
        "Telemetry coverage",
        () => computeSysmonRdpAndCoverage({ db, meta, columns, options, hostSet, _outlierHosts, findings, warnings, isHayabusa, _scanEidCol, _dedupeEvidenceRefs, _rowEvidenceRef, _rowidsFromRefs, _normalizeFindingEvidenceRefs, rdpSessions, hostTelemetry, datasetEventCounts, _conventionOutliers, fid }),
        () => ({ groupedSessions: [], hostCoverage: new Map(), datasetCoverage: null, datasetEventCountsObj: {}, coverageWarnings: [], fid }),
      );
      fid = _r14.fid;

      // ── All findings exist from here on ──────────────────────────────────────────
      runStage("Evidence refs", () => _normalizeFindingEvidenceRefs(), null);

      // === Finding correlation + triage + execution-session/incident clustering → processing/triage-and-clustering.js ===
      // Scores and sorts the COMPLETE findings array. Nothing may push findings after
      // this point, or it would be unscored and would break the sort.
      const { executionSessions, incidents } = runStage(
        "Triage and clustering",
        () => correlateTriageAndCluster({ findings, chains, timeOrdered, _outlierHosts, _dedupeEvidenceRefs, _rowidsFromRefs }),
        () => ({ executionSessions: [], incidents: [] }),
      );

      // === Campaign / storyline clustering (needs incidents) → processing/campaign-clustering.js ===
      const campaigns = runStage(
        "Campaign clustering",
        () => clusterCampaigns({ incidents, findings, _dedupeEvidenceRefs, _rowidsFromRefs }),
        () => ({ campaigns: [] }),
      ).campaigns;
      const groupedSessions = _r14.groupedSessions;
      const hostCoverage = _r14.hostCoverage;
      const datasetEventCountsObj = _r14.datasetEventCountsObj;
      const datasetCoverage = _r14.datasetCoverage;
      const coverageWarnings = _r14.coverageWarnings;

      // === Accounts Aggregation → assemble/accounts.js ===
      const accounts = runStage(
        "Accounts",
        () => aggregateAccounts({ timeOrdered, rdpSessions, findings, userEventCounts, userEventCountsScoped, userEventOriginalName, _outlierHosts, privLogonEvents, userFirstSuccessTs }),
        () => [],
      );

      // Surface stage failures alongside the detectors' own warnings so a partial result
      // is visibly partial rather than quietly thin.
      if (_spine.chainWarnings?.length) warnings.push(..._spine.chainWarnings);
      if (_stageWarnings.length) warnings.push(..._stageWarnings);

      return {
        nodes: [
          // Nodes from logon graph (hostSet)
          ...[...hostSet.entries()].map(([id, info]) => {
            const outlierReason = detectOutlier(id);
            const convOutlier = _conventionOutliers.get(id);
            return {
              id, label: id, eventCount: info.eventCount,
              isSource: info.isSource, isTarget: info.isTarget,
              isBoth: info.isSource && info.isTarget,
              aliases: [...(info.aliases || [])],
              isOutlier: !!outlierReason || !!convOutlier, outlierReason: outlierReason || (convOutlier ? convOutlier.reason : ""),
              conventionOutlier: !!convOutlier, conventionReason: convOutlier ? convOutlier.reason : "",
              telemetry: hostCoverage.get(id) || null,
            };
          }),
          // Isolated nodes: convention outliers from Computer column that aren't in the logon graph
          ...[..._conventionOutliers.entries()]
            .filter(([id]) => !hostSet.has(id))
            .map(([id, info]) => {
              const ch = _computerHosts.find(c => c.host === id);
              return {
                id, label: id, eventCount: ch ? ch.eventCount : 0,
                isSource: false, isTarget: false, isBoth: false,
                isOutlier: true, outlierReason: info.reason,
                conventionOutlier: true, conventionReason: info.reason,
                isolated: true, // flag for frontend positioning
                telemetry: hostCoverage.get(id) || null,
              };
            }),
        ],
        edges: [...edgeMap.values()].map((e) => ({
          ...e, users: [...e.users], logonTypes: [...e.logonTypes], clientNames: [...e.clientNames], clientAddresses: [...e.clientAddresses],
          eventBreakdown: Object.fromEntries(e.eventBreakdown), shareNames: [...(e.shareNames || [])],
          evidenceRefs: _dedupeEvidenceRefs(e.evidenceRefs || []),
          itemRowids: _rowidsFromRefs(e.evidenceRefs || []),
        })),
        chains,
        rdpSessions,
        groupedSessions,
        accounts,
        findings,
        incidents,
        campaigns,
        executionSessions,
        stats: {
          totalEvents: timeOrdered.length, uniqueHosts: hostSet.size,
          uniqueUsers: new Set(timeOrdered.map((e) => e.user).filter(Boolean)).size,
          uniqueConnections: edgeMap.size,
          failedLogons: [...edgeMap.values()].reduce((s, e) => s + (e.hasFailures ? 1 : 0), 0),
          longestChain: chains.length > 0 ? chains[0].hops : 0,
          chainCount: chains.length,
          // A failed authentication episode is RDP activity, not an established
          // session. Keep the two populations explicit so the hero metric and
          // Accounts tab do not call password attempts "sessions".
          rdpSessionCount: rdpSessions.filter((s) => s.status !== "failed" && s.status !== "incomplete").length,
          rdpActivityCount: rdpSessions.length,
          rdpFailureEpisodeCount: rdpSessions.filter((s) => s.status === "failed").length,
          rdpFailedAttemptCount: rdpSessions
            .filter((s) => s.status === "failed")
            .reduce((sum, s) => sum + (s.attemptCount || 1), 0),
          adminSessions: rdpSessions.filter((s) => s.status !== "failed" && s.hasAdmin).length,
          suspiciousSessions: rdpSessions.filter((s) => s.status !== "failed" && (s.suspicionScore || 0) >= 25).length,
          suspiciousRdpActivity: rdpSessions.filter((s) => (s.suspicionScore || 0) >= 25).length,
          findingsCount: findings.length,
          criticalFindings: findings.filter((f) => f.severity === "critical").length,
          incidentCount: incidents.length,
          executionSessionCount: executionSessions.length,
          campaignCount: campaigns.length,
          accountCount: accounts.length,
          suspiciousAccounts: accounts.filter(a => (a.suspicionScore || 0) >= 25).length,
          datasetEnd: timeOrdered.length > 0 ? timeOrdered[timeOrdered.length - 1].ts : null,
        },
        warnings, scanStats,
        coverage: {
          dataset: datasetCoverage,
          datasetEventCounts: datasetEventCountsObj,
          warnings: coverageWarnings,
          categories: TELEMETRY_CATEGORIES.map(c => ({ id: c.id, label: c.label, eids: c.eids, critical: c.critical })),
        },
        columns, error: null,
      };
    } catch (e) {
      return { nodes: [], edges: [], chains: [], findings: [], incidents: [], campaigns: [], executionSessions: [], groupedSessions: [], stats: {}, warnings: [], scanStats: {}, columns, error: e.message };
    }
}

module.exports = { getLateralMovement };
