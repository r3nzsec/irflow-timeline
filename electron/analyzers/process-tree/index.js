const { dbg } = require("../../logger");
const { buildEvtxHaystack, cleanWrappedField, compactGet, compactGetInt, extractFirstInteger, isChainsawDataset, isChainsawProcessDataset, isHayabusaDataset, parseCompactKeyValues, resolveEventChannel } = require("../evtx-utils");
const { normalizeTimestamp, compareTimestamps, normalizeGuid, normalizePid, normalizeLogonId, normalizeHost, normalizeUser } = require("../../utils/forensic-normalize");

function getProcessTree(meta, options = {}, ctx) {
  if (!meta) return { processes: [], stats: {}, columns: {}, error: "No database" };

  const {
    pidCol: userPidCol, ppidCol: userPpidCol,
    guidCol: userGuidCol, parentGuidCol: userParentGuidCol,
    imageCol: userImageCol, cmdLineCol: userCmdLineCol,
    userCol: userUserCol, tsCol: userTsCol, eventIdCol: userEventIdCol, providerCol: userProviderCol,
    eventIdValue = "1,4688",
    maxRows = 200000,
  } = options;

  // Auto-detect columns (case-insensitive)
  const detect = (patterns) => {
    for (const pat of patterns) {
      const found = meta.headers.find((h) => pat.test(h));
      if (found) return found;
    }
    return null;
  };

  // Detect EvtxECmd format (KAPE output)
  const isEvtxECmdPT = meta.headers.some((h) => /^PayloadData1$/i.test(h)) && meta.headers.some((h) => /^ExecutableInfo$/i.test(h));
  const isHayabusaPT = isHayabusaDataset(meta);
  const isChainsawPT = isChainsawProcessDataset(meta);

  const columns = {
    pid:         userPidCol        || detect([/^ProcessId$/i, /^pid$/i, /^process_id$/i, /^NewProcessId$/i]),
    ppid:        userPpidCol       || detect([/^ParentProcessId$/i, /^ppid$/i, /^parent_process_id$/i, /^parent_pid$/i, /^CreatorProcessId$/i]),
    guid:        userGuidCol       || detect([/^ProcessGuid$/i, /^process_guid$/i]),
    parentGuid:  userParentGuidCol || detect([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
    image:       userImageCol      || detect([/^Image$/i, /^process_name$/i, /^exe$/i, /^FileName$/i, /^ImagePath$/i, /^NewProcessName$/i, ...(isChainsawPT ? [/^Event\.EventData\.Image$/i] : [])]),
    // parentImage: broaden to mirror the image detection set so non-Sysmon datasets
    // (Chainsaw raw events, snake_case CSVs, derivative columns) populate the
    // Parent Process column directly. The modal still falls back to a relinked
    // tree lookup when this is empty, which is what handles Security 4688.
    parentImage: detect([/^ParentImage$/i, /^ParentProcessName$/i, /^Parent[_\s]?Process[_\s]?Name$/i, /^parent_image$/i, /^parent_process_name$/i, /^ParentImagePath$/i, /^Parent[_\s]?Image[_\s]?Path$/i, /^ParentExe$/i, /^ParentFileName$/i, /^CreatorProcessName$/i, /^Creator[_\s]?Process[_\s]?Name$/i, ...(isChainsawPT ? [/^Event\.EventData\.ParentImage$/i] : [])]),
    cmdLine:     userCmdLineCol    || detect([/^CommandLine$/i, /^command_line$/i, /^cmd$/i, /^cmdline$/i, /^ProcessCommandLine$/i, ...(isChainsawPT ? [/^Event\.EventData\.CommandLine$/i] : [])]),
    user:        userUserCol       || detect([/^User$/i, /^UserName$/i, /^user_name$/i, /^SubjectUserName$/i, /^TargetUserName$/i]),
    ts:          userTsCol         || detect([/^UtcTime$/i, /^datetime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsawPT ? [/^system_time$/i] : [])]),
    eventId:     userEventIdCol    || detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsawPT ? [/^id$/i] : [])]),
    elevation:   detect([/^TokenElevationType$/i, /^Token_Elevation_Type$/i]),
    integrity:   detect([/^MandatoryLabel$/i, /^Mandatory_Label$/i, /^IntegrityLevel$/i]),
    provider:    userProviderCol || detect([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
    hostname:    detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, /^MachineName$/i, ...(isChainsawPT ? [/^computer_name$/i] : [])]),
    logonId:     detect([/^LogonId$/i, /^Logon_ID$/i, /^SubjectLogonId$/i, /^Subject_Logon_ID$/i, /^TargetLogonId$/i, /^Target_Logon_ID$/i, /^AuthenticationId$/i]),
    sessionId:   detect([/^SessionId$/i, /^Session_ID$/i, /^Session ID$/i, /^TerminalSessionId$/i, /^Terminal_Session_ID$/i, /^SessionGuid$/i]),
    // Binary trust metadata — present in Sysmon EID 1 datasets, absent from Security 4688.
    // Hayabusa/EvtxECmd extract these from KV blobs in the row-parsing section below.
    hashes:           detect([/^Hashes$/i, /^Hash$/i]),
    originalFileName: detect([/^OriginalFileName$/i, /^Original_?File_?Name$/i]),
    company:          detect([/^Company$/i]),
    signed:           detect([/^Signed$/i]),
    signatureStatus:  detect([/^SignatureStatus$/i, /^Signature_?Status$/i, /^SigStatus$/i]),
    signer:           detect([/^Signer$/i, /^Signature$/i]),
    // EID 10 (Sysmon ProcessAccess) columns — used for injection/hollowing detection.
    // Raw Sysmon provides Source*/Target* columns directly; Hayabusa/EvtxECmd
    // serialize them into Details/PayloadData blobs, parsed at query time below.
    srcPid:           detect([/^SourceProcessId$/i, /^Source_?Process_?Id$/i]),
    srcGuid:          detect([/^SourceProcessGuid$/i, /^SourceProcessGUID$/i, /^Source_?Process_?Guid$/i]),
    tgtPid:           detect([/^TargetProcessId$/i, /^Target_?Process_?Id$/i]),
    tgtGuid:          detect([/^TargetProcessGuid$/i, /^TargetProcessGUID$/i, /^Target_?Process_?Guid$/i]),
    grantedAccess:    detect([/^GrantedAccess$/i, /^Granted_?Access$/i]),
    // Adjacent-telemetry payload columns. Sysmon EID 7 and 11 each carry TWO paths:
    // the host process (Image) and the artifact (ImageLoaded / TargetFilename). The
    // enrichment below used to fall back to Image when it could not find the artifact,
    // which meant "unsigned DLL from a writable path" and "PE written to a writable
    // path" were really being evaluated against the process's OWN binary — so any
    // process running from %APPDATA% scored high or critical on both.
    imageLoaded:      detect([/^ImageLoaded$/i, /^Image_?Loaded$/i]),
    targetFilename:   detect([/^TargetFilename$/i, /^Target_?File_?Name$/i]),
    destIp:           detect([/^DestinationIp$/i, /^Destination_?IP$/i, /^DestIp$/i]),
    destPort:         detect([/^DestinationPort$/i, /^Destination_?Port$/i]),
    queryName:        detect([/^QueryName$/i, /^Query_?Name$/i, /^DnsQuery$/i]),
    // EID 4673 / 4674 (Security, Sensitive Privilege Use / Privileged Object Ops).
    // Present in raw Windows Security exports; Hayabusa/EvtxECmd embed it in
    // Details/PayloadData blobs and the block below extracts it at query time.
    privilegeList:    detect([/^PrivilegeList$/i, /^Privileges$/i, /^Privilege_?List$/i]),
    details:     isHayabusaPT ? detect([/^Details$/i]) : null,
    extra:       isHayabusaPT ? detect([/^ExtraFieldInfo$/i]) : null,
  };

  // EvtxECmd: OVERRIDE columns — ProcessId in CSV header is the logging service PID (e.g., Sysmon 5464),
  // NOT the created process PID. Real PID/GUID is inside PayloadData1/PayloadData5.
  // PayloadData1: "ProcessID: N, ProcessGUID: {guid}"
  // PayloadData5: "ParentProcessID: N, ParentProcessGUID: {guid}"
  // ExecutableInfo: full command line (image path extractable from first token)
  if (isEvtxECmdPT) {
    columns.pid = detect([/^PayloadData1$/i]) || columns.pid;       // MUST override — CSV ProcessId is service PID
    columns.ppid = detect([/^PayloadData5$/i]) || columns.ppid;     // MUST override
    columns.guid = detect([/^PayloadData1$/i]) || columns.guid;     // GUID parsed from same field as PID
    columns.parentGuid = detect([/^PayloadData5$/i]) || columns.parentGuid; // parent GUID from same field as PPID
    columns.image = detect([/^ExecutableInfo$/i]) || columns.image; // image extracted from command line
    columns.cmdLine = detect([/^ExecutableInfo$/i]) || columns.cmdLine;
  } else if (isHayabusaPT) {
    const detailsCol = detect([/^Details$/i]);
    const extraCol = detect([/^ExtraFieldInfo$/i]);
    columns.pid = detailsCol || columns.pid;
    columns.ppid = extraCol || detailsCol || columns.ppid;
    columns.guid = detailsCol || columns.guid;
    columns.parentGuid = detailsCol || columns.parentGuid;
    columns.image = detailsCol || columns.image;
    columns.parentImage = extraCol || detailsCol || columns.parentImage;
    columns.cmdLine = detailsCol || columns.cmdLine;
    columns.user = extraCol || detailsCol || columns.user;
    columns.elevation = extraCol || detailsCol || columns.elevation;
    columns.integrity = extraCol || detailsCol || columns.integrity;
  }
  // --- Row-level column aliases (raw EVTX / plain CSV) ------------------------
  // detect() picks ONE column per role for the whole tab, but the correct column
  // depends on the EVENT, not the dataset: a Security 4688 puts the created process
  // in NewProcessId and its creator in ProcessId, while a 4689 / 4673 / 4674 puts
  // the subject process in ProcessId, and Sysmon uses ProcessId for the subject on
  // every event. One tab-wide choice therefore has to be wrong for one of them —
  // on a mixed Sysmon+Security tab the 4688 nodes took the CREATOR's pid (so they
  // collided and chained to each other), and on a Security-only tab the 4689
  // lifetime and 4673/4674 privilege correlations never matched anything.
  //
  // These are emitted IN ADDITION to the role columns (duplicated column refs are
  // fine in SQL) so each row can pick the right one at parse time.
  const ROW_LEVEL_ALIAS_PATTERNS = {
    _subjectPid:  /^ProcessId$/i,
    _newPid:      /^NewProcessId$/i,
    _creatorPid:  /^CreatorProcessId$/i,
    _parentPid:   /^ParentProcessId$/i,
    _newImage:    /^NewProcessName$/i,
    _procName:    /^ProcessName$/i,
    _parentName:  /^ParentProcessName$/i,
  };
  const rowLevelCols = {};
  if (!isEvtxECmdPT && !isHayabusaPT && !isChainsawPT) {
    for (const [alias, pat] of Object.entries(ROW_LEVEL_ALIAS_PATTERNS)) {
      const c = detect([pat]);
      if (c && meta.colMap[c]) rowLevelCols[alias] = meta.colMap[c];
    }
  }
  const appendRowLevelAliases = (parts) => {
    for (const [alias, safeCol] of Object.entries(rowLevelCols)) parts.push(`${safeCol} as [${alias}]`);
    return parts;
  };

  // Which Security event a row is, for row-level resolution. Matched loosely because
  // exports render the id as "4688", "EventID 4688" or "4688 - A new process...".
  const _isEid = (value, eid) => new RegExp(`(^|\\D)${eid}(\\D|$)`).test(String(value || "").trim());

  columns._isEvtxECmd = isEvtxECmdPT;
  columns._isHayabusa = isHayabusaPT;
  columns._isChainsaw = isChainsawPT;

  const useGuid = !!(columns.guid && columns.parentGuid) || isEvtxECmdPT;
  if (!columns.pid && !columns.guid && !isEvtxECmdPT && !isHayabusaPT && !isChainsawPT) return { processes: [], stats: {}, columns, error: "Cannot detect ProcessId or ProcessGuid column" };
  // A Security-only export has NO ParentProcessId column at all — the parent of a
  // 4688 is its ProcessId field. Without this the analyzer refused the entire tab
  // with "Cannot detect ParentProcessId", so Security-only data could not be
  // analysed even though the parent link is fully recoverable.
  const hasRowLevelParent = !!(rowLevelCols._creatorPid || (rowLevelCols._newPid && rowLevelCols._subjectPid));
  if (!columns.ppid && !columns.parentGuid && !hasRowLevelParent && !isEvtxECmdPT && !isHayabusaPT && !isChainsawPT) return { processes: [], stats: {}, columns, error: "Cannot detect ParentProcessId or ParentProcessGuid column" };

  const db = meta.db;
  const params = [];
  const whereConditions = [];

  // Filter to EventID value(s) — supports comma-separated (e.g., "1,4688")
  // Probes exact match first; falls back to CAST normalization for non-clean formats
  // like "EventID 4688", "4688 - A new process has been created", etc.
  if (columns.eventId && eventIdValue) {
    const safeEid = meta.colMap[columns.eventId];
    if (safeEid) {
      const eids = eventIdValue.split(",").map(s => s.trim()).filter(Boolean);
      // Probe: does exact match find any rows? (runs before other filters are added)
      const probeSql = `SELECT COUNT(*) as cnt FROM data WHERE ${safeEid} IN (${eids.map(() => "?").join(",")}) LIMIT 1`;
      const probeResult = db.prepare(probeSql).get(...eids);
      if (probeResult && probeResult.cnt > 0) {
        // Exact match works — fast path
        if (eids.length === 1) { whereConditions.push(`${safeEid} = ?`); params.push(eids[0]); }
        else { whereConditions.push(`${safeEid} IN (${eids.map(() => "?").join(",")})`); params.push(...eids); }
      } else {
        // Exact match failed — use CAST normalization
        const eidInts = eids.map(e => parseInt(e, 10)).filter(n => !isNaN(n));
        if (eidInts.length > 0) {
          whereConditions.push(`CAST(${safeEid} AS INTEGER) IN (${eidInts.join(",")})`);
        }
      }
    }
  }

  // EvtxECmd: auto-filter to Security + Sysmon providers only.
  // EvtxECmd CSV aggregates ALL providers — many have EID 1 (Kernel-IO, AzureGuestAgent, etc.)
  // that are NOT process creation events. Only Sysmon EID 1 and Security EID 4688 are relevant.
  // Falls back to no provider filter if provider column is mis-mapped or uses non-standard values.
  if (isEvtxECmdPT && columns.provider) {
    const safeProv = meta.colMap[columns.provider];
    if (safeProv) {
      // Probe: does provider filter find any rows combined with the EID filter?
      const provProbeWc = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")} AND` : "WHERE";
      const provProbe = db.prepare(`SELECT COUNT(*) as cnt FROM data ${provProbeWc} (${safeProv} LIKE ? OR ${safeProv} LIKE ?) LIMIT 1`).get(...params, "%Sysmon%", "%Security-Auditing%");
      if (provProbe && provProbe.cnt > 0) {
        whereConditions.push(`(${safeProv} LIKE ? OR ${safeProv} LIKE ?)`);
        params.push("%Sysmon%", "%Security-Auditing%");
      }
      // else: skip provider filter — mis-mapped or non-standard provider values
    }
  }

  // Standard filter application
  ctx.applyStandardFilters(options, meta, whereConditions, params);

  const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

  // Build SELECT — deduplicate when multiple keys map to the same column (e.g., EvtxECmd: pid+guid both from PayloadData1)
  const selectParts = ["data.rowid as _rowid"];
  const selectedCols = new Set();
  for (const [key, colName] of Object.entries(columns)) {
    if (key.startsWith("_")) continue;  // skip internal flags
    if (colName && meta.colMap[colName] && !selectedCols.has(colName)) {
      selectParts.push(`${meta.colMap[colName]} as [${key}]`);
      selectedCols.add(colName);
    }
  }

  appendRowLevelAliases(selectParts);

  // EvtxECmd spreads a Security 4688 across PayloadData2-6 (NewProcessId, ProcessName,
  // CreatorProcessId), so PD1/PD5 — which are mapped for the Sysmon EID 1 shape — are
  // not enough on their own. Fetch the rest as fallback fields for the parser below.
  if (isEvtxECmdPT) {
    for (const [alias, pat] of [["_pd2", /^PayloadData2$/i], ["_pd3", /^PayloadData3$/i], ["_pd4", /^PayloadData4$/i], ["_pd6", /^PayloadData6$/i]]) {
      const c = detect([pat]);
      if (c && meta.colMap[c] && !selectedCols.has(c)) {
        selectParts.push(`${meta.colMap[c]} as [${alias}]`);
        selectedCols.add(c);
      }
    }
  }

  // Use sort_datetime for chronological order — raw lexical sort on a TEXT column
  // mis-orders any non-ISO format (US dates, locale strings, Excel serials).
  const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
  const orderClause = orderCol ? `ORDER BY sort_datetime(${orderCol}) ASC, data.rowid ASC` : "ORDER BY data.rowid ASC";

  try {
    const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${maxRows}`;
    const rows = db.prepare(sql).all(...params);

    // Build parent-child map
    const processes = [];
    const byKey = new Map();
    const childrenOf = new Map();

    for (const row of rows) {
      let pid = row.pid || "";
      let ppid = row.ppid || "";
      let guid = row.guid || "";
      let parentGuid = row.parentGuid || "";
      let imagePath = row.image || "";
      let cmdLine = row.cmdLine || "";
      let parentImageRaw = row.parentImage || "";
      let resolvedUser = row.user || "";
      let resolvedLogonId = row.logonId || "";
      let resolvedSessionId = row.sessionId || "";
      let resolvedElevation = row.elevation || "";
      let resolvedIntegrity = row.integrity || "";
      // Trust metadata — populated from direct columns or KV blob extraction
      let resolvedHashes = row.hashes || "";
      let resolvedOrigFn = row.originalFileName || "";
      let resolvedCompany = row.company || "";
      let resolvedSigned = row.signed || "";
      let resolvedSigStatus = row.signatureStatus || "";
      let resolvedSigner = row.signer || "";

      // EvtxECmd: parse structured PayloadData fields
      if (isEvtxECmdPT) {
        // PayloadData1: "ProcessID: 5668, ProcessGUID: 7bf9956e-0a95-6931-a700-000000000700"
        // row.pid holds PayloadData1 (may also be aliased as guid due to same column)
        const pd1 = row.pid || row.guid || "";
        // PayloadData5: "ParentProcessID: 4408, ParentProcessGUID: 7bf9956e-..."
        const pd5 = row.ppid || row.parentGuid || "";
        const pdBlob = [pd1, row._pd2, row._pd3, row._pd4, pd5, row._pd6].filter(Boolean).join(" | ");
        const evtId = String(row.eventId || "").trim();
        const isSec4688 = /(^|\D)4688(\D|$)/.test(evtId);

        // Security 4688 writes its PIDs in HEX ("NewProcessId: 0x1a2c"). The old
        // `(\d+)` regex matched the "0" of "0x1a2c" — every 4688 process got PID 0,
        // so they all collapsed onto one node and chained to each other. Accept both
        // bases and normalise to decimal, which is what the rest of the tree uses.
        const _pdNum = (blob, ...keys) => {
          for (const key of keys) {
            const m = String(blob || "").match(new RegExp(`(?:^|[^A-Za-z])${key}\\s*:\\s*(0x[0-9a-fA-F]+|\\d+)`, "i"));
            if (!m) continue;
            const n = /^0x/i.test(m[1]) ? parseInt(m[1], 16) : parseInt(m[1], 10);
            if (Number.isFinite(n) && n > 0) return String(n);
          }
          return "";
        };
        const _pdText = (blob, ...keys) => {
          for (const key of keys) {
            const m = String(blob || "").match(new RegExp(`(?:^|[^A-Za-z])${key}\\s*:\\s*([^,|]+)`, "i"));
            if (m) {
              const v = m[1].trim();
              if (v && v !== "-") return v;
            }
          }
          return "";
        };

        if (isSec4688) {
          // 4688 semantics: NewProcessId is the process that was created; ProcessId /
          // CreatorProcessId is its parent. Reading a bare "ProcessID:" here would have
          // used the CREATOR's pid as the child's.
          pid = _pdNum(pdBlob, "NewProcessId");
          ppid = _pdNum(pdBlob, "CreatorProcessId", "ParentProcessId", "ProcessId");
        } else {
          pid = _pdNum(pd1, "ProcessID") || _pdNum(pdBlob, "ProcessID", "NewProcessId");
          ppid = _pdNum(pd5, "ParentProcessID") || _pdNum(pdBlob, "ParentProcessID", "CreatorProcessId");
        }

        const guidMatch = pd1.match(/ProcessGUID:\s*([0-9a-f-]+)/i);
        const pguidMatch = pd5.match(/ParentProcessGUID:\s*([0-9a-f-]+)/i);
        if (guidMatch) guid = guidMatch[1];
        if (pguidMatch) parentGuid = pguidMatch[1];

        // ExecutableInfo: full command line — may be aliased as image or cmdLine depending on dedup order
        const execInfo = row.image || row.cmdLine || "";
        cmdLine = execInfo;
        // Extract image path from command line (first token, may be quoted)
        if (execInfo) {
          const qm = execInfo.match(/^"([^"]+)"/);
          imagePath = qm ? qm[1] : execInfo.split(/\s/)[0];
        }
        // With command-line auditing off, ExecutableInfo is empty and a 4688 still
        // names the binary in NewProcessName. Without this every such row became an
        // "unknown" node with no image, so no rule could ever match it.
        if (!imagePath) imagePath = _pdText(pdBlob, "NewProcessName", "ProcessName", "Image");
        if (!parentImageRaw) parentImageRaw = _pdText(pdBlob, "ParentProcessName", "CreatorProcessName", "ParentImage");
      } else if (isHayabusaPT) {
        const compact = parseCompactKeyValues(row.details, row.extra);
        const eventId = String(row.eventId || "").trim();
        pid = compactGetInt(compact, "PID", "ProcessId", "NewProcessId");
        ppid = eventId === "4688"
          ? compactGetInt(compact, "ProcessId", "CreatorProcessId", "ParentPID", "ParentProcessId")
          : compactGetInt(compact, "ParentPID", "ParentProcessId", "CreatorProcessId");
        guid = compactGet(compact, "PGUID", "ProcessGuid", "ProcessGUID");
        parentGuid = compactGet(compact, "ParentPGUID", "ParentProcessGuid", "ParentProcessGUID");
        imagePath = compactGet(compact, "Proc", "Image", "NewProcessName", "ProcessName");
        cmdLine = compactGet(compact, "Cmdline", "CommandLine", "ProcessCommandLine");
        if (!imagePath && cmdLine) {
          const qm = cmdLine.match(/^"([^"]+)"/);
          imagePath = qm ? qm[1] : cmdLine.split(/\s+/)[0];
        }
        parentImageRaw = compactGet(compact, "ParentImage", "ParentProcessName", "ParentImagePath", "ParentExe", "ParentFileName");
        resolvedUser = compactGet(compact, "SubjectUserName", "TargetUserName", "TgtUser", "User");
        if (resolvedUser.includes("\\")) resolvedUser = resolvedUser.split("\\").pop();
        resolvedLogonId = compactGet(compact, "SubjectLogonId", "TargetLogonId", "LogonId", "AuthenticationId") || resolvedLogonId;
        resolvedSessionId = compactGet(compact, "SessionId", "TerminalSessionId", "SessionGuid") || resolvedSessionId;
        resolvedElevation = compactGet(compact, "TokenElevationType");
        resolvedIntegrity = compactGet(compact, "IntegrityLevel", "MandatoryLabel");
        // Trust metadata from Hayabusa KV blobs
        resolvedHashes = compactGet(compact, "Hashes", "Hash");
        resolvedOrigFn = compactGet(compact, "OriginalFileName");
        resolvedCompany = compactGet(compact, "Company");
        resolvedSigned = compactGet(compact, "Signed");
        resolvedSigStatus = compactGet(compact, "SignatureStatus", "SigStatus");
        resolvedSigner = compactGet(compact, "Signature", "Signer");
      } else if (isChainsawPT) {
        pid = extractFirstInteger(row.pid);
        ppid = extractFirstInteger(row.ppid);
        guid = cleanWrappedField(row.guid);
        parentGuid = cleanWrappedField(row.parentGuid);
        imagePath = cleanWrappedField(row.image);
        cmdLine = cleanWrappedField(row.cmdLine);
        if (!imagePath && cmdLine) {
          const qm = cmdLine.match(/^"([^"]+)"/);
          imagePath = qm ? qm[1] : cmdLine.split(/\s+/)[0];
        }
        if (!cmdLine) cmdLine = imagePath;
        parentImageRaw = cleanWrappedField(row.parentImage);
        resolvedUser = cleanWrappedField(row.user);
        resolvedLogonId = cleanWrappedField(row.logonId);
        resolvedSessionId = cleanWrappedField(row.sessionId);
        resolvedElevation = cleanWrappedField(row.elevation);
        resolvedIntegrity = cleanWrappedField(row.integrity);
        if (!pid && !guid) pid = `chainsaw-${row._rowid}`;
      } else {
        // Raw EVTX / plain CSV: resolve the PID and image roles from THIS row's
        // event id rather than the tab-wide column choice (see ROW_LEVEL_ALIAS_PATTERNS).
        const evtId = row.eventId;
        if (_isEid(evtId, "4688")) {
          // Only a row that actually carries NewProcessId has Security-4688
          // semantics. A Sysmon-shaped or synthetic CSV can be labelled 4688 while
          // still using ProcessId for the subject, and remapping that would invert
          // its parent link.
          if (row._newPid) {
            pid = row._newPid;                                                 // the created process
            const creator = row._creatorPid || row._subjectPid;                // ProcessId = its creator
            if (creator) ppid = creator;
          }
          if (!imagePath) imagePath = row._newImage || "";
          if (!parentImageRaw) parentImageRaw = row._parentName || "";
        } else if (_isEid(evtId, "4689") || _isEid(evtId, "4673") || _isEid(evtId, "4674")) {
          if (row._subjectPid) pid = row._subjectPid;                          // the subject process
          if (!imagePath) imagePath = row._procName || "";
        }
      }

      // Hex PID conversion (Security 4688 format: "0x1a2c")
      if (typeof pid === "string" && /^0x[0-9a-f]+$/i.test(pid.trim())) pid = String(parseInt(pid.trim(), 16));
      if (typeof ppid === "string" && /^0x[0-9a-f]+$/i.test(ppid.trim())) ppid = String(parseInt(ppid.trim(), 16));

      const normGuid = normalizeGuid(guid);
      const normParentGuid = normalizeGuid(parentGuid);
      const key = useGuid && normGuid
        ? normGuid
        : `pid:${pid}:${row._rowid}`;
      const parentKey = useGuid && normParentGuid
        ? normParentGuid
        : ppid ? `pid:${ppid}` : "";

      const processName = imagePath.split("\\").pop().split("/").pop() || "(unknown)";

      const parentProcessName = parentImageRaw.split("\\").pop().split("/").pop() || "";

      const tsClean = cleanWrappedField(row.ts || "");
      const tsMs = normalizeTimestamp(tsClean);
      const normLogonId = normalizeLogonId(resolvedLogonId);
      const normSessionId = normalizeLogonId(resolvedSessionId);
      const node = {
        key, parentKey, rowid: row._rowid,
        pid: normalizePid(pid), ppid: normalizePid(ppid),
        guid: normGuid, parentGuid: normParentGuid,
        image: imagePath, processName, parentImage: parentImageRaw, parentProcessName,
        cmdLine, user: cleanWrappedField(resolvedUser), ts: tsClean,
        // Canonical epoch-ms used by all chronological logic. NaN means unparseable —
        // downstream callers must guard. Never compare `ts` strings lexically.
        tsMs: Number.isFinite(tsMs) ? tsMs : NaN,
        elevation: resolvedElevation, integrity: resolvedIntegrity,
        provider: cleanWrappedField(row.provider || ""), eventId: cleanWrappedField(row.eventId || ""),
        hostname: cleanWrappedField(row.hostname || ""),
        normHost: normalizeHost(row.hostname || ""),
        logonId: normLogonId,
        sessionId: normSessionId,
        sessionScope: normLogonId ? `logon:${normLogonId}` : normSessionId ? `session:${normSessionId}` : "",
        // Binary trust metadata
        hashes: cleanWrappedField(resolvedHashes),
        originalFileName: cleanWrappedField(resolvedOrigFn),
        company: cleanWrappedField(resolvedCompany),
        signed: cleanWrappedField(resolvedSigned),
        signatureStatus: cleanWrappedField(resolvedSigStatus),
        signer: cleanWrappedField(resolvedSigner),
        // Lifetime fields — populated by terminate-event matching below
        durationMs: NaN, terminateTs: "", terminateTsMs: NaN, exitCode: "",
        // Injection indicators — populated by EID 10 (ProcessAccess) matching below.
        // Null means no EID 10 events correlated (either the dataset lacks them or
        // this target wasn't accessed). Never guaranteed to be present.
        injectionIndicators: null,
        // Credential access — populated by the EID 10 pass below when THIS process
        // opened a handle to lsass. Null when no such event correlated.
        credentialAccess: null,
        // Privilege use — populated by EID 4673 / 4674 matching below. Null when
        // the dataset carries no sensitive-privilege audit events for this process.
        privilegeUse: null,
        // Adjacent Sysmon telemetry summaries (EID 3/22/7/11) — populated below.
        networkActivity: null,
        dnsActivity: null,
        imageLoads: null,
        fileCreates: null,
        link: null,
        linkSource: "",
        linkConfidence: "",
        linkReason: "",
        linkWarnings: [],
        childCount: 0, depth: 0,
      };
      processes.push(node);
      byKey.set(key, node);
      if (parentKey) {
        if (!childrenOf.has(parentKey)) childrenOf.set(parentKey, []);
        childrenOf.get(parentKey).push(key);
      }
    }

    // PID-based fallback: re-link rows that lack usable GUID parents (Security 4688,
    // mixed Sysmon/Security, Hayabusa 4688). This is deliberately stricter than a
    // plain host+PID join: parent and child must share host plus logon/session scope
    // when that evidence is available. That prevents long-range PID reuse inside one
    // host from fabricating chains across user sessions.
    const _hostBucket = (h) => h || "__nohost__";
    const _sessionBucket = (node) => node.sessionScope || "__nosession__";
    const _hostPidKey = (node, pid) => `${_hostBucket(node.normHost)}|${pid}`;
    const _scopedPidKey = (node, pid, scope = _sessionBucket(node)) => `${_hostBucket(node.normHost)}|${scope}|${pid}`;
    // A PID is a 32-bit value that Windows recycles aggressively; a week-wide window
    // means the "parent" is frequently a completely unrelated process that merely
    // held the number days earlier. Narrowed to 24 hours, and further cut at a boot
    // boundary below (PIDs restart from scratch at boot, so a pre-boot parent is
    // never the real one).
    const PID_RELINK_MAX_AGE_MS = 24 * 60 * 60 * 1000;

    // Processes that legitimately create children in a DIFFERENT logon/session scope.
    // Every one of these is an OS boundary crossing, not PID reuse:
    //   services  -> a service starts under its own service logon
    //   winlogon  -> userinit/dwm start the interactive session being created
    //   userinit  -> explorer, same handover
    //   svchost   -> Task Scheduler and DCOM launch children as other principals
    //   lsass/csrss/smss/wininit — session and subsystem setup
    //   consent/runas/UAC — the whole point is to change token and logon id
    //   taskeng/taskhostw/schedule — a scheduled task runs as its configured user
    //   wmiprvse/wsmprovhost — remote execution impersonates the caller
    const _RX_SCOPE_BOUNDARY_PARENT = /^(services|winlogon|userinit|svchost|lsass|csrss|smss|wininit|consent|runas|taskeng|taskhostw|schtasks|wmiprvse|wsmprovhost|dllhost|logonui|sihost|ctfmon)(\.exe)?$/i;
    const pidToNodes = new Map();
    const hostPidToNodes = new Map();
    for (const node of processes) {
      if (!node.pid) continue;
      const k = _scopedPidKey(node, node.pid);
      if (!pidToNodes.has(k)) pidToNodes.set(k, []);
      pidToNodes.get(k).push(node);
      const hostKey = _hostPidKey(node, node.pid);
      if (!hostPidToNodes.has(hostKey)) hostPidToNodes.set(hostKey, []);
      hostPidToNodes.get(hostKey).push(node);
    }
    if (!useGuid) childrenOf.clear();
    const _linkTimeDelta = (child, parent) => {
      if (!child || !parent || !Number.isFinite(child.tsMs) || !Number.isFinite(parent.tsMs)) return null;
      return child.tsMs - parent.tsMs;
    };
    const _linkWarnings = (child, parent, extra = []) => {
      const out = [];
      if (!child?.normHost) out.push("host_missing");
      if (!Number.isFinite(child?.tsMs)) out.push("child_timestamp_missing");
      if (parent && !Number.isFinite(parent.tsMs)) out.push("parent_timestamp_missing");
      const delta = _linkTimeDelta(child, parent);
      if (delta != null && delta > 24 * 60 * 60 * 1000) out.push("wide_time_gap");
      for (const item of extra) if (item) out.push(item);
      return [...new Set(out)];
    };
    const _makeLink = (child, parent, source, confidence, reason, warnings = [], extra = {}) => ({
      source,
      confidence,
      reason,
      warnings: [...new Set((warnings || []).filter(Boolean))],
      parentKey: parent?.key || child?.parentKey || "",
      parentRowId: parent?.rowid ?? null,
      childRowId: child?.rowid ?? null,
      host: child?.normHost || "",
      childPid: child?.pid || "",
      parentPid: parent?.pid || child?.ppid || "",
      childLogonId: child?.logonId || "",
      parentLogonId: parent?.logonId || "",
      childSessionId: child?.sessionId || "",
      parentSessionId: parent?.sessionId || "",
      timeDeltaMs: _linkTimeDelta(child, parent),
      ...extra,
    });
    const _assignLink = (node, link) => {
      node.link = link;
      node.linkSource = link.source;
      node.linkConfidence = link.confidence;
      node.linkReason = link.reason;
      node.linkWarnings = link.warnings || [];
    };
    // Boot boundary. PIDs restart from scratch at every boot, so a candidate that
    // was created before the machine last booted can never be the parent of a
    // process created after it — yet the fallback join happily reached across.
    // Sysmon 4 (service state change / start), Security 4608 (Windows starting) and
    // System 6005/6009 all mark the start of a session of the machine's life.
    const _bootMsByHost = (() => {
      const out = new Map();
      if (!columns.eventId || !meta.colMap[columns.eventId]) return out;
      try {
        const safeEid = meta.colMap[columns.eventId];
        const safeTs = columns.ts ? meta.colMap[columns.ts] : null;
        const safeHost = columns.hostname ? meta.colMap[columns.hostname] : null;
        if (!safeTs) return out;
        const bootEids = ["4608", "6005", "6009", "12"];
        const rowsBoot = db.prepare(
          `SELECT ${safeTs} as ts${safeHost ? `, ${safeHost} as host` : ""} FROM data WHERE ${safeEid} IN (${bootEids.map(() => "?").join(",")}) LIMIT 5000`,
        ).all(...bootEids);
        for (const r of rowsBoot) {
          const ms = normalizeTimestamp(cleanWrappedField(r.ts || ""));
          if (!Number.isFinite(ms)) continue;
          const h = normalizeHost(r.host || "") || "__nohost__";
          if (!out.has(h)) out.set(h, []);
          out.get(h).push(ms);
        }
        for (const arr of out.values()) arr.sort((a, b) => a - b);
      } catch (_) { /* boot events are optional */ }
      return out;
    })();
    const _bootBetween = (parentMs, childMs, host) => {
      if (!Number.isFinite(parentMs) || !Number.isFinite(childMs)) return false;
      const arr = _bootMsByHost.get(host || "__nohost__");
      if (!arr || arr.length === 0) return false;
      for (const b of arr) {
        if (b > parentMs && b <= childMs) return true;
        if (b > childMs) break;
      }
      return false;
    };

    const choosePidParent = (node, candidates) => {
      if (!candidates || candidates.length === 0) return null;
      const childTs = node.tsMs;
      for (let i = candidates.length - 1; i >= 0; i--) {
        const cand = candidates[i];
        if (cand.key === node.key) continue;
        // A candidate that had already exited cannot be the parent. Terminate
        // matching now runs before this loop, so terminateTsMs is populated.
        if (Number.isFinite(cand.terminateTsMs) && Number.isFinite(childTs) && cand.terminateTsMs < childTs) continue;
        // Nor can one from before the machine last booted — the PID was reissued.
        if (_bootBetween(cand.tsMs, childTs, node.normHost)) continue;
        // Parent must precede child in time when both timestamps are known.
        // Also cap fallback joins to a sane investigative window to reduce PID
        // recycle errors in multi-day Security 4688-only datasets.
        if (Number.isFinite(childTs) && Number.isFinite(cand.tsMs)) {
          if (cand.tsMs > childTs) continue;
          if (childTs - cand.tsMs > PID_RELINK_MAX_AGE_MS) continue;
        }
        return { parent: cand, warnings: _linkWarnings(node, cand) };
      }
      // If the child timestamp is unknown, retain the legacy best-effort behavior.
      if (!Number.isFinite(childTs)) {
        const cand = candidates.find((item) => item.key !== node.key) || null;
        return cand ? { parent: cand, warnings: _linkWarnings(node, cand) } : null;
      }
      return null;
    };
    // --- Terminate event matching (runs BEFORE the PID relink) ---
    // Ordering matters: the relink below picks the latest process that held the
    // parent PID before the child started, and a process that had ALREADY EXITED
    // cannot be that parent. Terminate matching used to run after the relink, so
    // that information did not exist yet and PID-reuse mislinks were accepted.
    // --- Terminate event matching ---
    // Query Sysmon EID 5 and Security EID 4689 from the same table, match back
    // to create events by GUID (preferred) or PID+host (fallback), compute duration.
    const terminateEids = ["5", "4689"];
    let terminateMatched = 0;
    if (columns.eventId && processes.length > 0) {
      try {
        const safeEid = meta.colMap[columns.eventId];
        if (safeEid) {
          // Fast COUNT probe — skip entirely if no terminate events exist
          const termCountSql = `SELECT COUNT(*) as n FROM data WHERE ${safeEid} IN (${terminateEids.map(() => "?").join(",")}) LIMIT 1`;
          const termCount = db.prepare(termCountSql).get(...terminateEids);
          if (termCount && termCount.n > 0) {
            // Build the same SELECT parts for terminate events
            const termSelectParts = ["data.rowid as _rowid"];
            const termSelectedCols = new Set();
            for (const [key, colName] of Object.entries(columns)) {
              if (key.startsWith("_")) continue;
              if (colName && meta.colMap[colName] && !termSelectedCols.has(colName)) {
                termSelectParts.push(`${meta.colMap[colName]} as [${key}]`);
                termSelectedCols.add(colName);
              }
            }
            appendRowLevelAliases(termSelectParts);
            const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
            const termOrderClause = orderCol ? `ORDER BY sort_datetime(${orderCol}) ASC` : "ORDER BY data.rowid ASC";
            const termSql = `SELECT ${termSelectParts.join(", ")} FROM data WHERE ${safeEid} IN (${terminateEids.map(() => "?").join(",")}) ${termOrderClause} LIMIT ${maxRows}`;
            const termRows = db.prepare(termSql).all(...terminateEids);

            // Build lookup maps from create events for matching
            const guidToNode = new Map();
            const pidHostToNodes = new Map();
            for (const node of processes) {
              if (node.guid) guidToNode.set(node.guid, node);
              const pidHostKey = `${node.pid}|${node.normHost || "__nohost__"}`;
              if (!pidHostToNodes.has(pidHostKey)) pidHostToNodes.set(pidHostKey, []);
              pidHostToNodes.get(pidHostKey).push(node);
            }

            for (const tRow of termRows) {
              let tPid = tRow.pid || "";
              let tGuid = tRow.guid || "";
              let tExitCode = "";
              let tTs = cleanWrappedField(tRow.ts || "");
              const tHost = normalizeHost(tRow.hostname || "");

              // Parse format-specific fields
              if (isEvtxECmdPT) {
                const pd1 = tRow.pid || tRow.guid || "";
                const pidM = pd1.match(/ProcessID:\s*(\d+)/i);
                const guidM = pd1.match(/ProcessGUID:\s*([0-9a-f-]+)/i);
                if (pidM) tPid = pidM[1];
                if (guidM) tGuid = guidM[1];
                // EvtxECmd exit code may be in payload fields
                const pd = [tRow.pid, tRow.ppid, tRow.cmdLine, tRow.image].join(" ");
                const ecM = pd.match(/(?:ExitStatus|Status|ProcessExitCode):\s*(\S+)/i);
                if (ecM) tExitCode = ecM[1];
              } else if (isHayabusaPT) {
                const compact = parseCompactKeyValues(tRow.details, tRow.extra);
                tPid = compactGetInt(compact, "PID", "ProcessId");
                tGuid = compactGet(compact, "PGUID", "ProcessGuid", "ProcessGUID");
                tExitCode = compactGet(compact, "ExitStatus", "Status", "ProcessExitCode");
              } else {
                // Standard Sysmon / CSV format. A Security 4689 names the exiting
                // process ProcessId — which is NOT necessarily what `columns.pid`
                // resolved to on a tab that also holds 4688s, so lifetime matching
                // silently found nothing there.
                if (_isEid(tRow.eventId, "4689") && tRow._subjectPid) tPid = tRow._subjectPid;
                if (typeof tPid === "string" && /^0x[0-9a-f]+$/i.test(tPid.trim())) tPid = String(parseInt(tPid.trim(), 16));
                tExitCode = cleanWrappedField(tRow.elevation || ""); // Security 4689: Status field often mapped to elevation slot
              }

              const normTGuid = normalizeGuid(tGuid);
              const normTPid = normalizePid(tPid);
              const tTsMs = normalizeTimestamp(tTs);

              // Match by GUID (preferred — 1:1, no ambiguity)
              let matched = null;
              if (normTGuid && guidToNode.has(normTGuid)) {
                matched = guidToNode.get(normTGuid);
              }
              // Fallback: PID + host, pick the latest create event that precedes this terminate
              if (!matched && normTPid && Number.isFinite(tTsMs)) {
                const pidHostKey = `${normTPid}|${tHost || "__nohost__"}`;
                const candidates = pidHostToNodes.get(pidHostKey);
                if (candidates) {
                  let best = null;
                  for (const c of candidates) {
                    if (Number.isFinite(c.tsMs) && c.tsMs <= tTsMs && (!Number.isFinite(c.durationMs))) {
                      if (!best || c.tsMs > best.tsMs) best = c;
                    }
                  }
                  matched = best;
                }
              }

              if (matched && Number.isFinite(tTsMs)) {
                matched.terminateTs = tTs;
                matched.terminateTsMs = tTsMs;
                if (Number.isFinite(matched.tsMs)) {
                  matched.durationMs = tTsMs - matched.tsMs;
                  if (matched.durationMs < 0) matched.durationMs = NaN; // clock skew guard
                }
                if (tExitCode) matched.exitCode = tExitCode;
                terminateMatched++;
              }
            }
          }
        }
      } catch (_termErr) {
        // Non-fatal — lifetime analysis is best-effort. Tree building must not fail
        // because terminate events are malformed or the query errors.
      }
    }

    for (const node of processes) {
      const needsPidRelink = !useGuid || !node.parentGuid;
      if (!needsPidRelink || !node.ppid) continue;
      const scope = _sessionBucket(node);
      let candidates = null;
      let linkSource = "pid-host";
      const sourceWarnings = [];
      if (scope !== "__nosession__") {
        candidates = pidToNodes.get(_scopedPidKey(node, node.ppid, scope)) || null;
        linkSource = node.logonId ? "pid-logon" : "pid-session";
        if (!candidates || candidates.length === 0) {
          // Some parent rows lack LogonId/SessionId even when child rows have it.
          candidates = (hostPidToNodes.get(_hostPidKey(node, node.ppid)) || [])
            .filter((cand) => _sessionBucket(cand) === "__nosession__");
          linkSource = "pid-host";
          sourceWarnings.push("parent_session_unknown");
        }
        if (!candidates || candidates.length === 0) {
          // Cross-scope fallback (audit P4). Refusing every parent from a DIFFERENT
          // known logon/session used to be absolute, which fractured the tree at
          // exactly the handovers that define a Windows session: services -> a
          // service running as its own principal, winlogon -> userinit, UAC
          // elevation, runas, and every scheduled task. Those branches simply
          // disappeared, and the analyst saw orphans instead of a chain.
          //
          // The link is now made, but marked: low confidence, an explicit warning,
          // and (outside the known boundary parents) only when the candidate is the
          // sole PID holder, so this cannot resurrect ambiguous PID-reuse guesses.
          const crossScope = (hostPidToNodes.get(_hostPidKey(node, node.ppid)) || [])
            .filter((cand) => _sessionBucket(cand) !== "__nosession__" && _sessionBucket(cand) !== scope);
          if (crossScope.length > 0) {
            const boundary = crossScope.filter((cand) => _RX_SCOPE_BOUNDARY_PARENT.test(cand.processName || ""));
            if (boundary.length > 0) {
              candidates = boundary;
              linkSource = "pid-host";
              sourceWarnings.push("parent_scope_boundary");
            } else if (crossScope.length === 1) {
              candidates = crossScope;
              linkSource = "pid-host";
              sourceWarnings.push("parent_scope_mismatch");
            }
          }
        }
      } else {
        candidates = hostPidToNodes.get(_hostPidKey(node, node.ppid)) || null;
      }
      const choice = choosePidParent(node, candidates);
      const parent = choice?.parent;
      if (!parent) continue;

      const oldParentKey = node.parentKey;
      node.parentKey = parent.key;
      const confidence = linkSource === "pid-host" ? "low" : "medium";
      const reason = linkSource === "pid-logon"
        ? "PID fallback matched host and LogonId"
        : linkSource === "pid-session"
          ? "PID fallback matched host and SessionId"
          : "PID fallback matched host only";
      _assignLink(node, _makeLink(node, parent, linkSource, confidence, reason, [
        ...(choice.warnings || []),
        ...sourceWarnings,
      ], { previousParentKey: oldParentKey || "" }));
      if (oldParentKey && childrenOf.has(oldParentKey)) {
        const siblings = childrenOf.get(oldParentKey).filter((k) => k !== node.key);
        if (siblings.length > 0) childrenOf.set(oldParentKey, siblings);
        else childrenOf.delete(oldParentKey);
      }
      if (!childrenOf.has(parent.key)) childrenOf.set(parent.key, []);
      if (!childrenOf.get(parent.key).includes(node.key)) childrenOf.get(parent.key).push(node.key);
    }

    // Attach explicit parent-link provenance to every node. This keeps the
    // existing parentKey contract intact while telling analysts whether a tree
    // edge is a strong GUID match, a scoped PID fallback, or unresolved.
    for (const node of processes) {
      if (node.link) continue;
      const linked = byKey.get(node.parentKey);
      if (linked) {
        if (node.parentGuid && linked.guid && node.parentGuid === linked.guid) {
          _assignLink(node, _makeLink(node, linked, "guid", "high", "ProcessGuid/ParentProcessGuid match", _linkWarnings(node, linked)));
        } else {
          _assignLink(node, _makeLink(node, linked, "resolved", "medium", "Resolved parentKey match", _linkWarnings(node, linked)));
        }
      } else if (node.parentKey) {
        _assignLink(node, _makeLink(node, null, "unresolved", "none", "Parent reference was present but no matching source row was found", ["parent_not_found"]));
      } else {
        _assignLink(node, _makeLink(node, null, "root", "none", "No parent reference present in source row"));
      }
    }

    // Backfill parent image/name from the linked parent node when the row itself
    // carries no ParentImage. Security 4688 events often lack the field entirely
    // (older Windows builds, filtered exports, EvtxECmd payload variants), and
    // analyst tooling that consumes the analyzer output (CSV/JSON exports, the
    // inspector context API, the modal column) all benefit from a single backend
    // sweep instead of duplicating the fallback in each consumer.
    for (const node of processes) {
      if (node.parentImage && node.parentProcessName) continue;
      const linked = byKey.get(node.parentKey);
      if (!linked) continue;
      if (!node.parentImage && linked.image) node.parentImage = linked.image;
      if (!node.parentProcessName && linked.processName) node.parentProcessName = linked.processName;
    }

    // Child counts
    for (const node of processes) node.childCount = (childrenOf.get(node.key) || []).length;

    // Compute depth via BFS from roots
    const roots = processes.filter((p) => !byKey.has(p.parentKey));
    const visited = new Set();
    const queue = roots.map((r) => ({ key: r.key, depth: 0 }));
    let qi = 0;
    while (qi < queue.length) {
      const { key, depth } = queue[qi++];
      if (visited.has(key)) continue; // guard against cycles
      visited.add(key);
      const node = byKey.get(key);
      if (node) node.depth = depth;
      for (const ck of (childrenOf.get(key) || [])) queue.push({ key: ck, depth: depth + 1 });
    }

    // Safe maxDepth computation (avoid spreading large arrays)
    let maxDepth = 0;
    for (const p of processes) { if (p.depth > maxDepth) maxDepth = p.depth; }

    // --- ProcessAccess (EID 10) matching ---
    // Query Sysmon EID 10 events and correlate them to target processes. Flags memory
    // access patterns consistent with injection (PROCESS_VM_WRITE) or hollowing
    // (access events within 500ms of target creation). Summary fields are attached
    // to each target node; raw events are not returned — keeps IPC payload small.
    // Hollowing reference: attacker creates target (EID 1) → opens with VM_WRITE →
    // writes payload → resumes. We detect the access-before-activity window.
    let accessMatched = 0;
    if (columns.eventId && processes.length > 0) {
      try {
        const safeEid = meta.colMap[columns.eventId];
        if (safeEid) {
          const accessCountSql = `SELECT COUNT(*) as n FROM data WHERE ${safeEid} = ? LIMIT 1`;
          const accessCount = db.prepare(accessCountSql).get("10");
          if (accessCount && accessCount.n > 0) {
            // Build SELECT — same pattern as terminate block, but also include the
            // EID 10-specific columns.
            const accSelectParts = ["data.rowid as _rowid"];
            const accSelectedCols = new Set();
            for (const [key, colName] of Object.entries(columns)) {
              if (key.startsWith("_")) continue;
              if (colName && meta.colMap[colName] && !accSelectedCols.has(colName)) {
                accSelectParts.push(`${meta.colMap[colName]} as [${key}]`);
                accSelectedCols.add(colName);
              }
            }
            const accOrderCol = columns.ts ? meta.colMap[columns.ts] : null;
            const accOrderClause = accOrderCol ? `ORDER BY sort_datetime(${accOrderCol}) ASC` : "ORDER BY data.rowid ASC";
            const accSql = `SELECT ${accSelectParts.join(", ")} FROM data WHERE ${safeEid} = ? ${accOrderClause} LIMIT ${maxRows}`;
            const accRows = db.prepare(accSql).all("10");

            // Build lookup maps over target nodes (reuse guidToNode pattern)
            const guidToNode = new Map();
            const pidHostToNodes = new Map();
            for (const node of processes) {
              if (node.guid) guidToNode.set(node.guid, node);
              const pidHostKey = `${node.pid}|${node.normHost || "__nohost__"}`;
              if (!pidHostToNodes.has(pidHostKey)) pidHostToNodes.set(pidHostKey, []);
              pidHostToNodes.get(pidHostKey).push(node);
            }

            // GrantedAccess bits of interest (Windows PROCESS_* flags):
            //   PROCESS_CREATE_THREAD    = 0x0002
            //   PROCESS_VM_OPERATION     = 0x0008
            //   PROCESS_VM_READ          = 0x0010
            //   PROCESS_VM_WRITE         = 0x0020
            //   PROCESS_ALL_ACCESS       = 0x1F0FFF (Win Vista+) / 0x1FFFFF (XP)
            // Injection typically requires VM_OPERATION | VM_WRITE (|CREATE_THREAD).
            // Mimikatz-style lsass access uses 0x1010 (VM_READ+QUERY_INFO) or 0x1438.
            const _parseAccess = (s) => {
              if (s == null) return NaN;
              const t = String(s).trim();
              if (!t) return NaN;
              if (/^0x[0-9a-f]+$/i.test(t)) return parseInt(t, 16);
              const n = parseInt(t, 10);
              return Number.isFinite(n) ? n : NaN;
            };
            const INJECT_MASK = 0x0028; // VM_OPERATION | VM_WRITE
            const WRITE_BIT = 0x0020;
            const FULL_ACCESS = 0x1F0FFF;
            const VM_READ = 0x0010;
            const QUERY_INFO = 0x0400;      // PROCESS_QUERY_INFORMATION
            const QUERY_LIMITED = 0x1000;   // PROCESS_QUERY_LIMITED_INFORMATION
            const _isLsass = (node) => /(^|[\\/])lsass(\.exe)?$/i.test(String(node?.processName || node?.image || ""));

            for (const aRow of accRows) {
              let tgtPidRaw = "";
              let tgtGuidRaw = "";
              let srcPidRaw = "";
              let grantedRaw = "";
              const aTs = cleanWrappedField(aRow.ts || "");
              const aHost = normalizeHost(aRow.hostname || "");

              if (isEvtxECmdPT) {
                // EvtxECmd stuffs Source*/Target*/GrantedAccess into PayloadData fields.
                const blob = [aRow.pid, aRow.ppid, aRow.cmdLine, aRow.image, aRow.guid, aRow.parentGuid].filter(Boolean).join(" ");
                const tPid = blob.match(/TargetProcessId:\s*(\d+)/i);
                const tGuid = blob.match(/TargetProcessGUID:\s*([0-9a-f-]+)/i);
                const sPid = blob.match(/SourceProcessId:\s*(\d+)/i);
                const gAcc = blob.match(/GrantedAccess:\s*(0x[0-9a-f]+|\d+)/i);
                if (tPid) tgtPidRaw = tPid[1];
                if (tGuid) tgtGuidRaw = tGuid[1];
                if (sPid) srcPidRaw = sPid[1];
                if (gAcc) grantedRaw = gAcc[1];
              } else if (isHayabusaPT) {
                const compact = parseCompactKeyValues(aRow.details, aRow.extra);
                tgtPidRaw = compactGet(compact, "TgtPID", "TargetProcessId", "TargetPID");
                tgtGuidRaw = compactGet(compact, "TgtPGUID", "TargetProcessGuid", "TargetProcessGUID");
                srcPidRaw = compactGet(compact, "SrcPID", "SourceProcessId", "SourcePID");
                grantedRaw = compactGet(compact, "GrantedAccess", "Access");
              } else {
                tgtPidRaw = aRow.tgtPid || "";
                tgtGuidRaw = aRow.tgtGuid || "";
                srcPidRaw = aRow.srcPid || "";
                grantedRaw = aRow.grantedAccess || "";
              }

              const normTgtGuid = normalizeGuid(tgtGuidRaw);
              const normTgtPid = normalizePid(tgtPidRaw);
              const aTsMs = normalizeTimestamp(aTs);

              let target = null;
              if (normTgtGuid && guidToNode.has(normTgtGuid)) {
                target = guidToNode.get(normTgtGuid);
              }
              if (!target && normTgtPid && Number.isFinite(aTsMs)) {
                const pidHostKey = `${normTgtPid}|${aHost || "__nohost__"}`;
                const candidates = pidHostToNodes.get(pidHostKey);
                if (candidates) {
                  // Match the latest target creation that precedes this access event.
                  let best = null;
                  for (const c of candidates) {
                    if (Number.isFinite(c.tsMs) && c.tsMs <= aTsMs) {
                      if (!best || c.tsMs > best.tsMs) best = c;
                    }
                  }
                  target = best;
                }
              }

              if (!target) continue;

              const accessBits = _parseAccess(grantedRaw);
              const isInjectLike = Number.isFinite(accessBits) && (
                (accessBits & INJECT_MASK) === INJECT_MASK ||
                (accessBits & WRITE_BIT) === WRITE_BIT ||
                (accessBits & FULL_ACCESS) === FULL_ACCESS
              );
              // Hollowing window: attacker typically accesses the target within the first
              // ~500ms of its lifetime to overwrite the image before it runs.
              const sinceCreateMs = Number.isFinite(aTsMs) && Number.isFinite(target.tsMs) ? (aTsMs - target.tsMs) : NaN;
              const isHollowWindow = Number.isFinite(sinceCreateMs) && sinceCreateMs >= 0 && sinceCreateMs <= 500;
              const normSrcPid = normalizePid(srcPidRaw);
              // Self-access (debugger-inside-self, GetCurrentProcess handles) is noisy
              // and not injection. Skip when source PID equals target PID on the same host.
              if (normSrcPid && normSrcPid === target.pid) continue;

              // --- Credential access: attribute the handle to the SOURCE process ---
              // injectionIndicators below describe the process being ACCESSED, which is
              // the right shape for hollowing but the wrong one for credential theft:
              // it left every indicator on lsass.exe and nothing at all on the tool that
              // opened it, so the canonical mimikatz / procdump pattern produced no
              // finding on the attacker's process. Reading lsass also does not require
              // VM_WRITE — 0x1010 (VM_READ|QUERY_INFORMATION) and 0x1410 are the classic
              // masks — so the inject-like test above cannot be the gate either.
              if (_isLsass(target) && normSrcPid) {
                const srcKey = `${normSrcPid}|${aHost || "__nohost__"}`;
                const srcCandidates = pidHostToNodes.get(srcKey);
                let srcNode = null;
                if (srcCandidates) {
                  for (const cand of srcCandidates) {
                    if (cand === target) continue;
                    if (Number.isFinite(cand.tsMs) && Number.isFinite(aTsMs) && cand.tsMs > aTsMs) continue;
                    if (!srcNode || (Number.isFinite(cand.tsMs) && cand.tsMs > srcNode.tsMs)) srcNode = cand;
                  }
                }
                if (srcNode) {
                  const readsMemory = Number.isFinite(accessBits) && (accessBits & VM_READ) === VM_READ;
                  const queries = Number.isFinite(accessBits) && ((accessBits & QUERY_INFO) === QUERY_INFO || (accessBits & QUERY_LIMITED) === QUERY_LIMITED);
                  if (!srcNode.credentialAccess) {
                    srcNode.credentialAccess = {
                      lsassAccessCount: 0, lsassReadCount: 0, maxGrantedAccess: NaN,
                      firstAccessMs: NaN, targetPids: [],
                    };
                  }
                  const ca = srcNode.credentialAccess;
                  ca.lsassAccessCount++;
                  // A read handle (or full access) on lsass is the credential-dump
                  // primitive. A bare query-only handle is what Task Manager and every
                  // AV agent does, so it is counted but not treated as a read.
                  if (readsMemory || (Number.isFinite(accessBits) && (accessBits & FULL_ACCESS) === FULL_ACCESS)) ca.lsassReadCount++;
                  else if (queries) ca.queryOnly = true;
                  if (Number.isFinite(accessBits) && (!Number.isFinite(ca.maxGrantedAccess) || accessBits > ca.maxGrantedAccess)) ca.maxGrantedAccess = accessBits;
                  if (Number.isFinite(aTsMs) && (!Number.isFinite(ca.firstAccessMs) || aTsMs < ca.firstAccessMs)) ca.firstAccessMs = aTsMs;
                  if (target.pid && !ca.targetPids.includes(target.pid) && ca.targetPids.length < 5) ca.targetPids.push(target.pid);
                }
              }

              if (!target.injectionIndicators) {
                target.injectionIndicators = {
                  accessCount: 0,
                  suspiciousAccessCount: 0,
                  hollowingLikely: false,
                  firstAccessMs: NaN,
                  maxGrantedAccess: NaN,
                  sourcePids: [],
                };
              }
              const ind = target.injectionIndicators;
              ind.accessCount++;
              if (isInjectLike) ind.suspiciousAccessCount++;
              if (isHollowWindow && isInjectLike) ind.hollowingLikely = true;
              if (Number.isFinite(aTsMs) && (!Number.isFinite(ind.firstAccessMs) || aTsMs < ind.firstAccessMs)) {
                ind.firstAccessMs = aTsMs;
              }
              if (Number.isFinite(accessBits) && (!Number.isFinite(ind.maxGrantedAccess) || accessBits > ind.maxGrantedAccess)) {
                ind.maxGrantedAccess = accessBits;
              }
              if (normSrcPid && !ind.sourcePids.includes(normSrcPid) && ind.sourcePids.length < 5) {
                ind.sourcePids.push(normSrcPid);
              }
              accessMatched++;
            }
          }
        }
      } catch (_accErr) {
        // Non-fatal — injection analysis is best-effort.
      }
    }

    // --- Privilege-use (EID 4673 / 4674) matching ---
    // Correlate Sensitive Privilege Use (4673) and Privileged Object Ops (4674)
    // to the running process at that PID+host. High-risk privileges — SeDebug,
    // SeTcb, SeImpersonate, SeAssignPrimaryToken, SeLoadDriver, SeCreateToken,
    // SeTakeOwnership, SeBackup, SeRestore — are attacker primitives for
    // injection, token theft, BYOVD driver sideload, and ACL bypass.
    // We aggregate counts per process (small payload, IPC-friendly); frontend
    // rules classify risk based on concentration and which privileges appeared.
    let privilegeMatched = 0;
    const HIGH_RISK_PRIVS = new Set([
      "sedebugprivilege", "setcbprivilege", "seimpersonateprivilege",
      "seassignprimarytokenprivilege", "seloaddriverprivilege",
      "secreatetokenprivilege", "setakeownershipprivilege",
      "sebackupprivilege", "serestoreprivilege",
    ]);
    if (columns.eventId && processes.length > 0) {
      try {
        const safeEid = meta.colMap[columns.eventId];
        if (safeEid) {
          const privEids = ["4673", "4674"];
          // Provider filter — EID 4673/4674 belong to Security-Auditing only.
          // Some custom parsers / generic CSVs re-use these numeric IDs for
          // unrelated audit events, which would inflate privilege counts and
          // false-positive the pi-50/51/52 rules. When we have a provider
          // column, probe for Security-Auditing + EID match; use that joint
          // filter if it finds rows, else fall back to EID-only (no regression
          // on datasets without provider info).
          let provFilter = "";
          const provParams = [];
          if (columns.provider) {
            const safeProv = meta.colMap[columns.provider];
            if (safeProv) {
              const probeSql = `SELECT COUNT(*) as n FROM data WHERE ${safeEid} IN (${privEids.map(() => "?").join(",")}) AND ${safeProv} LIKE ? LIMIT 1`;
              const probe = db.prepare(probeSql).get(...privEids, "%Security-Auditing%");
              if (probe && probe.n > 0) {
                provFilter = ` AND ${safeProv} LIKE ?`;
                provParams.push("%Security-Auditing%");
              }
            }
          }
          const privCountSql = `SELECT COUNT(*) as n FROM data WHERE ${safeEid} IN (${privEids.map(() => "?").join(",")})${provFilter} LIMIT 1`;
          const privCount = db.prepare(privCountSql).get(...privEids, ...provParams);
          if (privCount && privCount.n > 0) {
            const privSelectParts = ["data.rowid as _rowid"];
            const privSelectedCols = new Set();
            for (const [key, colName] of Object.entries(columns)) {
              if (key.startsWith("_")) continue;
              if (colName && meta.colMap[colName] && !privSelectedCols.has(colName)) {
                privSelectParts.push(`${meta.colMap[colName]} as [${key}]`);
                privSelectedCols.add(colName);
              }
            }
            appendRowLevelAliases(privSelectParts);
            const privOrderCol = columns.ts ? meta.colMap[columns.ts] : null;
            const privOrderClause = privOrderCol ? `ORDER BY sort_datetime(${privOrderCol}) ASC` : "ORDER BY data.rowid ASC";
            const privSql = `SELECT ${privSelectParts.join(", ")} FROM data WHERE ${safeEid} IN (${privEids.map(() => "?").join(",")})${provFilter} ${privOrderClause} LIMIT ${maxRows}`;
            const privRows = db.prepare(privSql).all(...privEids, ...provParams);

            // Rebuild PID+host lookup — scoped to this block so the EID 10 map
            // above doesn't need to persist.
            const pidHostToNodes = new Map();
            for (const node of processes) {
              if (!node.pid) continue;
              const pidHostKey = `${node.pid}|${node.normHost || "__nohost__"}`;
              if (!pidHostToNodes.has(pidHostKey)) pidHostToNodes.set(pidHostKey, []);
              pidHostToNodes.get(pidHostKey).push(node);
            }

            // Parse PrivilegeList payloads. Windows emits display names like
            // "SeDebugPrivilege, SeImpersonatePrivilege" separated by commas,
            // semicolons, whitespace, or newlines. Some exporters produce
            // %%NNNN numeric resource codes — skipped because we can't map
            // them without a resolver table. The regex guard also rejects any
            // token that doesn't look like SeXxxPrivilege, so JSON/XML junk
            // from malformed rows doesn't inflate counts.
            const _parsePrivileges = (s) => {
              if (!s) return [];
              const out = [];
              const toks = String(s).split(/[\s,;\r\n]+/);
              for (const t of toks) {
                const norm = t.trim().toLowerCase();
                if (/^se[a-z]+privilege$/.test(norm)) out.push(norm);
              }
              return out;
            };

            for (const pRow of privRows) {
              let evPid = pRow.pid || "";
              let evPrivs = "";
              let evService = "";
              const evTs = cleanWrappedField(pRow.ts || "");
              const evHost = normalizeHost(pRow.hostname || "");

              if (isEvtxECmdPT) {
                const blob = [pRow.pid, pRow.ppid, pRow.cmdLine, pRow.image, pRow.guid, pRow.parentGuid].filter(Boolean).join(" ");
                const pidM = blob.match(/ProcessI[Dd]:\s*(\S+?)(?:,|\s|$)/);
                // PrivilegeList in EvtxECmd payloads is often quoted or multi-line;
                // capture everything after the key up to the next recognized key.
                const privM = blob.match(/PrivilegeList:\s*([^:]+?)(?=\s+\w+:|$)/i);
                const svcM = blob.match(/Service:\s*([^,\n]+)/i);
                if (pidM) evPid = pidM[1];
                if (privM) evPrivs = privM[1];
                if (svcM) evService = svcM[1].trim();
              } else if (isHayabusaPT) {
                const compact = parseCompactKeyValues(pRow.details, pRow.extra);
                evPid = compactGet(compact, "PID", "ProcessId") || evPid;
                evPrivs = compactGet(compact, "PrivilegeList", "Privileges", "Privs") || "";
                evService = compactGet(compact, "Service", "ServiceName") || "";
              } else {
                // Raw Security export — PrivilegeList usually lives in its own column.
                // 4673/4674 identify the subject by ProcessId, same reasoning as 4689.
                if (pRow._subjectPid) evPid = pRow._subjectPid;
                evPrivs = pRow.privilegeList || "";
              }

              // Security events sometimes hex-encode PID (0x1a2c). normalizePid handles it.
              const normEvPid = normalizePid(evPid);
              const evTsMs = normalizeTimestamp(evTs);
              if (!normEvPid) continue;
              const privs = _parsePrivileges(evPrivs);
              if (privs.length === 0) continue;

              const pidHostKey = `${normEvPid}|${evHost || "__nohost__"}`;
              const candidates = pidHostToNodes.get(pidHostKey);
              if (!candidates) continue;
              // Pick the latest create that precedes the event AND wasn't already
              // terminated. Falls back to "latest create" if timestamp is missing.
              let best = null;
              for (const c of candidates) {
                if (!Number.isFinite(c.tsMs)) continue;
                if (Number.isFinite(evTsMs)) {
                  if (c.tsMs > evTsMs) continue;
                  if (Number.isFinite(c.terminateTsMs) && c.terminateTsMs < evTsMs) continue;
                }
                if (!best || c.tsMs > best.tsMs) best = c;
              }
              if (!best) continue;

              if (!best.privilegeUse) {
                best.privilegeUse = {
                  eventCount: 0,
                  privileges: {},
                  highRiskCount: 0,
                  uniqueHighRisk: 0,
                  services: [],
                };
              }
              const pu = best.privilegeUse;
              pu.eventCount++;
              for (const priv of privs) {
                pu.privileges[priv] = (pu.privileges[priv] || 0) + 1;
                if (HIGH_RISK_PRIVS.has(priv)) pu.highRiskCount++;
              }
              pu.uniqueHighRisk = Object.keys(pu.privileges).filter((k) => HIGH_RISK_PRIVS.has(k)).length;
              if (evService && !pu.services.includes(evService) && pu.services.length < 5) {
                pu.services.push(evService);
              }
              privilegeMatched++;
            }
          }
        }
      } catch (_privErr) {
        // Non-fatal — privilege correlation is best-effort.
      }
    }

    // --- Adjacent Sysmon telemetry: EID 3 (Network), 22 (DNS), 7 (ImageLoad), 11 (FileCreate) ---
    // Attach compact per-process summaries for detection rules + detail panel.
    // Matching is GUID-first, then PID+host. Counts only — samples capped for IPC size.
    let networkMatched = 0;
    let dnsMatched = 0;
    let imageLoadMatched = 0;
    let fileCreateMatched = 0;
    if (columns.eventId && processes.length > 0) {
      try {
        const safeEid = meta.colMap[columns.eventId];
        if (safeEid) {
          const guidToNode = new Map();
          const pidHostToNodes = new Map();
          for (const node of processes) {
            if (node.guid) guidToNode.set(node.guid, node);
            const pidHostKey = `${node.pid}|${node.normHost || "__nohost__"}`;
            if (!pidHostToNodes.has(pidHostKey)) pidHostToNodes.set(pidHostKey, []);
            pidHostToNodes.get(pidHostKey).push(node);
          }
          const resolveTarget = (guidRaw, pidRaw, hostRaw, tsMs) => {
            const g = normalizeGuid(guidRaw);
            if (g && guidToNode.has(g)) return guidToNode.get(g);
            const p = normalizePid(pidRaw);
            if (!p) return null;
            const key = `${p}|${normalizeHost(hostRaw) || "__nohost__"}`;
            const cands = pidHostToNodes.get(key);
            if (!cands || !cands.length) return null;
            if (!Number.isFinite(tsMs)) return cands[cands.length - 1];
            let best = null;
            for (const c of cands) {
              if (Number.isFinite(c.tsMs) && c.tsMs <= tsMs && (!best || c.tsMs > best.tsMs)) best = c;
            }
            return best || cands[cands.length - 1];
          };
          const isPrivateIp = (ip) => {
            const s = String(ip || "").trim();
            if (!s) return true;
            if (/^(10\.|192\.168\.|127\.|0\.|255\.)/.test(s)) return true;
            if (/^172\.(1[6-9]|2\d|3[01])\./.test(s)) return true;
            if (/^(::1|fe80:|fc|fd)/i.test(s)) return true;
            return false;
          };
          const isWritablePath = (p) => /\\(users|temp|tmp|appdata|downloads|public|recycle|perflogs)\\/i.test(String(p || ""));
          const isPe = (p) => /\.(exe|dll|sys|scr|cpl|ocx)$/i.test(String(p || ""));
          const isScript = (p) => /\.(ps1|psm1|psd1|vbs|js|jse|wsf|wsh|hta|bat|cmd|vbe)$/i.test(String(p || ""));

          const enrichSelect = () => {
            const parts = ["data.rowid as _rowid"];
            const seen = new Set();
            for (const [key, colName] of Object.entries(columns)) {
              if (key.startsWith("_")) continue;
              if (colName && meta.colMap[colName] && !seen.has(colName)) {
                parts.push(`${meta.colMap[colName]} as [${key}]`);
                seen.add(colName);
              }
            }
            appendRowLevelAliases(parts);
            return parts.join(", ");
          };
          const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
          const orderClause = orderCol ? `ORDER BY sort_datetime(${orderCol}) ASC` : "ORDER BY data.rowid ASC";
          const sel = enrichSelect();

          // Probe which EIDs exist before querying
          const eidPresent = {};
          for (const eid of ["3", "22", "7", "11"]) {
            try {
              const r = db.prepare(`SELECT COUNT(*) as n FROM data WHERE ${safeEid} = ? LIMIT 1`).get(eid);
              eidPresent[eid] = !!(r && r.n > 0);
            } catch { eidPresent[eid] = false; }
          }

          // EID 3 — NetworkConnect
          if (eidPresent["3"]) {
            const rows3 = db.prepare(`SELECT ${sel} FROM data WHERE ${safeEid} = ? ${orderClause} LIMIT ${maxRows}`).all("3");
            for (const r of rows3) {
              let srcGuid = "", srcPid = "", destIp = "", destPort = "";
              const host = r.hostname || "";
              const tsMs = normalizeTimestamp(cleanWrappedField(r.ts || ""));
              if (isEvtxECmdPT) {
                const blob = [r.pid, r.ppid, r.cmdLine, r.image, r.guid, r.parentGuid].filter(Boolean).join(" ");
                srcGuid = (blob.match(/SourceProcessGUID:\s*([0-9a-f-{}]+)/i) || [])[1] || "";
                srcPid = (blob.match(/SourceProcessId:\s*(\d+)/i) || [])[1] || "";
                destIp = (blob.match(/DestinationIp:\s*([^\s,]+)/i) || [])[1] || "";
                destPort = (blob.match(/DestinationPort:\s*(\d+)/i) || [])[1] || "";
              } else if (isHayabusaPT) {
                const compact = parseCompactKeyValues(r.details, r.extra);
                srcGuid = compactGet(compact, "SourceProcessGuid", "SourceProcessGUID", "PGUID", "ProcessGuid");
                srcPid = compactGetInt(compact, "SourceProcessId", "SourcePID", "PID", "ProcessId");
                destIp = compactGet(compact, "DestinationIp", "DestIp", "DstIP", "RemoteAddress");
                destPort = compactGet(compact, "DestinationPort", "DestPort", "DstPort");
              } else {
                srcGuid = r.guid || r.srcGuid || "";
                srcPid = r.pid || r.srcPid || "";
                destIp = r.destIp || compactGet(parseCompactKeyValues(r.details, r.extra), "DestinationIp", "DestIp") || "";
                // Destination often only in details for some exports
                destPort = r.destPort || "";
                if (!destIp && r.cmdLine) destIp = (String(r.cmdLine).match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/) || [])[0] || "";
              }
              const target = resolveTarget(srcGuid, srcPid, host, tsMs);
              if (!target) continue;
              if (!target.networkActivity) {
                target.networkActivity = { eventCount: 0, destCount: 0, rareDestCount: 0, destinations: [], samples: [] };
              }
              const na = target.networkActivity;
              na.eventCount++;
              const dip = String(destIp || "").trim();
              if (dip && !na.destinations.includes(dip) && na.destinations.length < 12) {
                na.destinations.push(dip);
                na.destCount = na.destinations.length;
                if (!isPrivateIp(dip)) na.rareDestCount++;
              }
              if (na.samples.length < 4) {
                na.samples.push({ destIp: dip, destPort: String(destPort || ""), ts: cleanWrappedField(r.ts || "") });
              }
              networkMatched++;
            }
          }

          // EID 22 — DNS query
          if (eidPresent["22"]) {
            const rows22 = db.prepare(`SELECT ${sel} FROM data WHERE ${safeEid} = ? ${orderClause} LIMIT ${maxRows}`).all("22");
            for (const r of rows22) {
              let srcGuid = "", srcPid = "", query = "";
              const host = r.hostname || "";
              const tsMs = normalizeTimestamp(cleanWrappedField(r.ts || ""));
              if (isEvtxECmdPT) {
                const blob = [r.pid, r.ppid, r.cmdLine, r.image, r.guid].filter(Boolean).join(" ");
                srcGuid = (blob.match(/(?:SourceProcessGUID|ProcessGuid):\s*([0-9a-f-{}]+)/i) || [])[1] || "";
                srcPid = (blob.match(/(?:SourceProcessId|ProcessId):\s*(\d+)/i) || [])[1] || "";
                query = (blob.match(/QueryName:\s*([^\s,]+)/i) || [])[1] || "";
              } else if (isHayabusaPT) {
                const compact = parseCompactKeyValues(r.details, r.extra);
                srcGuid = compactGet(compact, "ProcessGuid", "ProcessGUID", "PGUID", "SourceProcessGuid");
                srcPid = compactGetInt(compact, "ProcessId", "PID", "SourceProcessId");
                query = compactGet(compact, "QueryName", "DnsQuery", "Query");
              } else {
                srcGuid = r.guid || "";
                srcPid = r.pid || "";
                query = r.queryName || compactGet(parseCompactKeyValues(r.details, r.extra), "QueryName", "Query") || "";
              }
              const target = resolveTarget(srcGuid, srcPid, host, tsMs);
              if (!target) continue;
              if (!target.dnsActivity) {
                target.dnsActivity = { eventCount: 0, queryCount: 0, queries: [], samples: [] };
              }
              const da = target.dnsActivity;
              da.eventCount++;
              const qn = String(query || "").trim().toLowerCase();
              if (qn && !da.queries.includes(qn) && da.queries.length < 16) {
                da.queries.push(qn);
                da.queryCount = da.queries.length;
              }
              if (da.samples.length < 4) {
                da.samples.push({ query: qn, ts: cleanWrappedField(r.ts || "") });
              }
              dnsMatched++;
            }
          }

          // EID 7 — ImageLoad
          if (eidPresent["7"]) {
            const rows7 = db.prepare(`SELECT ${sel} FROM data WHERE ${safeEid} = ? ${orderClause} LIMIT ${maxRows}`).all("7");
            for (const r of rows7) {
              let srcGuid = "", srcPid = "", loaded = "", signed = "", sigStatus = "";
              const host = r.hostname || "";
              const tsMs = normalizeTimestamp(cleanWrappedField(r.ts || ""));
              if (isEvtxECmdPT) {
                const blob = [r.pid, r.ppid, r.cmdLine, r.image, r.guid].filter(Boolean).join(" ");
                srcGuid = (blob.match(/ProcessGuid:\s*([0-9a-f-{}]+)/i) || [])[1] || "";
                srcPid = (blob.match(/ProcessId:\s*(\d+)/i) || [])[1] || "";
                loaded = (blob.match(/ImageLoaded:\s*([^\r\n,|]+)/i) || [])[1] || "";
                signed = (blob.match(/Signed:\s*(\w+)/i) || [])[1] || "";
                sigStatus = (blob.match(/SignatureStatus:\s*([^\s,]+)/i) || [])[1] || "";
              } else if (isHayabusaPT) {
                const compact = parseCompactKeyValues(r.details, r.extra);
                srcGuid = compactGet(compact, "ProcessGuid", "ProcessGUID", "PGUID");
                srcPid = compactGetInt(compact, "ProcessId", "PID");
                loaded = compactGet(compact, "ImageLoaded", "Image", "Module");
                signed = compactGet(compact, "Signed");
                sigStatus = compactGet(compact, "SignatureStatus", "SigStatus");
              } else {
                srcGuid = r.guid || "";
                srcPid = r.pid || "";
                // ImageLoaded ONLY. `r.image` is the loading process, not the module.
                loaded = r.imageLoaded || compactGet(parseCompactKeyValues(r.details, r.extra), "ImageLoaded") || "";
                signed = r.signed || "";
                sigStatus = r.signatureStatus || "";
              }
              const target = resolveTarget(srcGuid, srcPid, host, tsMs);
              if (!target) continue;
              if (!target.imageLoads) {
                target.imageLoads = { eventCount: 0, unsignedCount: 0, writablePathCount: 0, samples: [] };
              }
              const il = target.imageLoads;
              il.eventCount++;
              const path = String(loaded || "").trim();
              const signedL = String(signed || "").toLowerCase();
              const statusL = String(sigStatus || "").toLowerCase();
              const unsigned = signedL === "false" || /invalid|expired|revoked|error|untrusted/.test(statusL);
              if (unsigned) il.unsignedCount++;
              if (isWritablePath(path)) il.writablePathCount++;
              if (il.samples.length < 4) {
                il.samples.push({ path, signed: signedL, sigStatus: statusL, ts: cleanWrappedField(r.ts || "") });
              }
              imageLoadMatched++;
            }
          }

          // EID 11 — FileCreate
          if (eidPresent["11"]) {
            const rows11 = db.prepare(`SELECT ${sel} FROM data WHERE ${safeEid} = ? ${orderClause} LIMIT ${maxRows}`).all("11");
            for (const r of rows11) {
              let srcGuid = "", srcPid = "", targetFile = "";
              const host = r.hostname || "";
              const tsMs = normalizeTimestamp(cleanWrappedField(r.ts || ""));
              if (isEvtxECmdPT) {
                const blob = [r.pid, r.ppid, r.cmdLine, r.image, r.guid].filter(Boolean).join(" ");
                srcGuid = (blob.match(/ProcessGuid:\s*([0-9a-f-{}]+)/i) || [])[1] || "";
                srcPid = (blob.match(/ProcessId:\s*(\d+)/i) || [])[1] || "";
                targetFile = (blob.match(/TargetFilename:\s*([^\r\n,|]+)/i) || [])[1] || "";
              } else if (isHayabusaPT) {
                const compact = parseCompactKeyValues(r.details, r.extra);
                srcGuid = compactGet(compact, "ProcessGuid", "ProcessGUID", "PGUID");
                srcPid = compactGetInt(compact, "ProcessId", "PID");
                targetFile = compactGet(compact, "TargetFilename", "TargetFile", "FileName", "Path");
              } else {
                srcGuid = r.guid || "";
                srcPid = r.pid || "";
                // TargetFilename ONLY — see the column comment above.
                targetFile = r.targetFilename || compactGet(parseCompactKeyValues(r.details, r.extra), "TargetFilename", "FileName") || "";
              }
              const target = resolveTarget(srcGuid, srcPid, host, tsMs);
              if (!target) continue;
              if (!target.fileCreates) {
                target.fileCreates = { eventCount: 0, peCount: 0, scriptCount: 0, writablePathCount: 0, samples: [] };
              }
              const fc = target.fileCreates;
              fc.eventCount++;
              const path = String(targetFile || "").trim();
              if (isPe(path)) fc.peCount++;
              if (isScript(path)) fc.scriptCount++;
              if (isWritablePath(path)) fc.writablePathCount++;
              if (fc.samples.length < 4) {
                fc.samples.push({ path, ts: cleanWrappedField(r.ts || "") });
              }
              fileCreateMatched++;
            }
          }
        }
      } catch (_adjErr) {
        // Non-fatal — adjacent telemetry is best-effort.
      }
    }

    const linkCounts = {};
    for (const node of processes) linkCounts[node.linkSource || "unknown"] = (linkCounts[node.linkSource || "unknown"] || 0) + 1;

    return {
      processes, columns, useGuid,
      stats: {
        totalProcesses: processes.length,
        rootCount: roots.length,
        maxDepth,
        truncated: rows.length >= maxRows,
        terminateMatched,
        accessMatched,
        privilegeMatched,
        networkMatched,
        dnsMatched,
        imageLoadMatched,
        fileCreateMatched,
        linkCounts,
      },
    };
  } catch (e) {
    return { processes: [], stats: {}, columns, error: e.message };
  }
}

/**
 * Lightweight preview for Process Inspector config — returns event counts, column quality,
 * linking quality (GUID/PID coverage), and provider mix without building the full tree.
 */
function previewProcessTree(meta, options = {}, ctx) {
  if (!meta) return { eventCounts: {}, columnQuality: {}, linkingQuality: {}, error: "No database" };

  const {
    pidCol: userPidCol, ppidCol: userPpidCol,
    guidCol: userGuidCol, parentGuidCol: userParentGuidCol,
    imageCol: userImageCol, cmdLineCol: userCmdLineCol,
    userCol: userUserCol, tsCol: userTsCol, eventIdCol: userEventIdCol, providerCol: userProviderCol,
    eventIdValue = "1,4688",
  } = options;

  const db = meta.db;
  try {
    // --- Column auto-detection (same as getProcessTree L2533-2574) ---
    const detect = (patterns) => {
      for (const pat of patterns) { const found = meta.headers.find((h) => pat.test(h)); if (found) return found; }
      return null;
    };
    const isEvtxECmd = meta.headers.some((h) => /^PayloadData1$/i.test(h)) && meta.headers.some((h) => /^ExecutableInfo$/i.test(h));
    const isHayabusa = isHayabusaDataset(meta);
    const isChainsaw = isChainsawProcessDataset(meta);

    const columns = {
      pid:         userPidCol        || detect([/^ProcessId$/i, /^pid$/i, /^process_id$/i, /^NewProcessId$/i]),
      ppid:        userPpidCol       || detect([/^ParentProcessId$/i, /^ppid$/i, /^parent_process_id$/i, /^parent_pid$/i, /^CreatorProcessId$/i]),
      guid:        userGuidCol       || detect([/^ProcessGuid$/i, /^process_guid$/i]),
      parentGuid:  userParentGuidCol || detect([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
      image:       userImageCol      || detect([/^Image$/i, /^process_name$/i, /^exe$/i, /^FileName$/i, /^ImagePath$/i, /^NewProcessName$/i, ...(isChainsaw ? [/^Event\.EventData\.Image$/i] : [])]),
      // See parentImage rationale in getProcessTree above — broadened to mirror image detection.
      parentImage: detect([/^ParentImage$/i, /^ParentProcessName$/i, /^Parent[_\s]?Process[_\s]?Name$/i, /^parent_image$/i, /^parent_process_name$/i, /^ParentImagePath$/i, /^Parent[_\s]?Image[_\s]?Path$/i, /^ParentExe$/i, /^ParentFileName$/i, /^CreatorProcessName$/i, /^Creator[_\s]?Process[_\s]?Name$/i, ...(isChainsaw ? [/^Event\.EventData\.ParentImage$/i] : [])]),
      cmdLine:     userCmdLineCol    || detect([/^CommandLine$/i, /^command_line$/i, /^cmd$/i, /^cmdline$/i, /^ProcessCommandLine$/i, ...(isChainsaw ? [/^Event\.EventData\.CommandLine$/i] : [])]),
      user:        userUserCol       || detect([/^User$/i, /^UserName$/i, /^user_name$/i, /^SubjectUserName$/i, /^TargetUserName$/i]),
      ts:          userTsCol         || detect([/^UtcTime$/i, /^datetime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
      eventId:     userEventIdCol    || detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsaw ? [/^id$/i] : [])]),
      elevation:   detect([/^TokenElevationType$/i, /^Token_Elevation_Type$/i]),
      integrity:   detect([/^MandatoryLabel$/i, /^Mandatory_Label$/i, /^IntegrityLevel$/i]),
      provider:    userProviderCol || detect([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
      hostname:    detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, /^MachineName$/i, ...(isChainsaw ? [/^computer_name$/i] : [])]),
      hashes:           detect([/^Hashes$/i, /^Hash$/i]),
      originalFileName: detect([/^OriginalFileName$/i, /^Original_?File_?Name$/i]),
      company:          detect([/^Company$/i]),
      signed:           detect([/^Signed$/i]),
      signatureStatus:  detect([/^SignatureStatus$/i, /^Signature_?Status$/i, /^SigStatus$/i]),
      signer:           detect([/^Signer$/i, /^Signature$/i]),
      details:     isHayabusa ? detect([/^Details$/i]) : null,
      extra:       isHayabusa ? detect([/^ExtraFieldInfo$/i]) : null,
    };

    // EvtxECmd overrides (same as getProcessTree L2566-2574)
    if (isEvtxECmd) {
      columns.pid = detect([/^PayloadData1$/i]) || columns.pid;
      columns.ppid = detect([/^PayloadData5$/i]) || columns.ppid;
      columns.guid = detect([/^PayloadData1$/i]) || columns.guid;
      columns.parentGuid = detect([/^PayloadData5$/i]) || columns.parentGuid;
      columns.image = detect([/^ExecutableInfo$/i]) || columns.image;
      columns.cmdLine = detect([/^ExecutableInfo$/i]) || columns.cmdLine;
    } else if (isHayabusa) {
      const detailsCol = detect([/^Details$/i]);
      const extraCol = detect([/^ExtraFieldInfo$/i]);
      columns.pid = detailsCol || columns.pid;
      columns.ppid = extraCol || detailsCol || columns.ppid;
      columns.guid = detailsCol || columns.guid;
      columns.parentGuid = detailsCol || columns.parentGuid;
      columns.image = detailsCol || columns.image;
      columns.parentImage = extraCol || detailsCol || columns.parentImage;
      columns.cmdLine = detailsCol || columns.cmdLine;
      columns.user = extraCol || detailsCol || columns.user;
      columns.elevation = extraCol || detailsCol || columns.elevation;
      columns.integrity = extraCol || detailsCol || columns.integrity;
    }
    columns._isEvtxECmd = isEvtxECmd;
    columns._isHayabusa = isHayabusa;
    columns._isChainsaw = isChainsaw;

    // --- Filter construction ---
    const params = [];
    const whereConditions = [];
    ctx.applyStandardFilters(options, meta, whereConditions, params);
    const wc = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    // --- Cache ---
    const effectiveEventIdValue = eventIdValue == null ? "1,4688" : String(eventIdValue);
    const cacheKey = JSON.stringify([meta.tabId, columns, effectiveEventIdValue, wc, params]);
    if (!ctx.ptPreviewCache) ctx.ptPreviewCache = new Map();
    if (ctx.ptPreviewCache.size > 50) { const first = ctx.ptPreviewCache.keys().next().value; ctx.ptPreviewCache.delete(first); }
    const cached = ctx.ptPreviewCache.get(cacheKey);
    if (cached) return cached;

    // --- Generic process-row fallback ---
    // Some datasets are not EVTX process-create logs, but still contain PID/PPID + image/cmdline
    // columns that Process Inspector can build from. Track those separately so preview does not
    // misleadingly report "0" usable rows just because EID 1/4688 is absent.
    const _nonEmptyText = (expr) => `${expr} IS NOT NULL AND TRIM(CAST(${expr} AS TEXT)) != '' AND CAST(${expr} AS TEXT) != '-'`;
    const _buildCandidateProcessExprs = () => {
      const idExprs = [];
      const parentExprs = [];
      const descExprs = [];
      const seen = { id: new Set(), parent: new Set(), desc: new Set() };
      const addExpr = (bucket, set, expr) => {
        if (!expr || set.has(expr)) return;
        set.add(expr);
        bucket.push(expr);
      };

      if (isEvtxECmd) {
        const pd1Safe = columns.pid && meta.colMap[columns.pid] ? meta.colMap[columns.pid] : (columns.guid && meta.colMap[columns.guid] ? meta.colMap[columns.guid] : null);
        const pd5Safe = columns.ppid && meta.colMap[columns.ppid] ? meta.colMap[columns.ppid] : (columns.parentGuid && meta.colMap[columns.parentGuid] ? meta.colMap[columns.parentGuid] : null);
        if (pd1Safe) addExpr(idExprs, seen.id, `(${pd1Safe} LIKE '%ProcessID:%' OR ${pd1Safe} LIKE '%ProcessGUID:%')`);
        if (pd5Safe) addExpr(parentExprs, seen.parent, `(${pd5Safe} LIKE '%ParentProcessID:%' OR ${pd5Safe} LIKE '%ParentProcessGUID:%')`);
      } else if (isHayabusa) {
        const detailsSafe = columns.details && meta.colMap[columns.details] ? meta.colMap[columns.details] : null;
        const extraSafe = columns.extra && meta.colMap[columns.extra] ? meta.colMap[columns.extra] : null;
        if (detailsSafe) {
          addExpr(idExprs, seen.id, `(${detailsSafe} LIKE '%PID:%' OR ${detailsSafe} LIKE '%PGUID:%' OR ${detailsSafe} LIKE '%ProcessGuid:%')`);
          addExpr(descExprs, seen.desc, `(${detailsSafe} LIKE '%Proc:%' OR ${detailsSafe} LIKE '%Cmdline:%')`);
          addExpr(parentExprs, seen.parent, `(${detailsSafe} LIKE '%ParentPID:%' OR ${detailsSafe} LIKE '%ParentPGUID:%')`);
        }
        if (extraSafe) {
          addExpr(parentExprs, seen.parent, `(${extraSafe} LIKE '%ParentImage:%' OR ${extraSafe} LIKE '%ParentProcessName:%' OR ${extraSafe} LIKE '%ProcessId:%')`);
        }
      } else if (isChainsaw) {
        const eidExprs = [];
        const descExprs = [];
        const seen = { eid: new Set(), desc: new Set() };
        const addExpr = (bucket, set, expr) => {
          if (!expr || set.has(expr)) return;
          set.add(expr);
          bucket.push(expr);
        };
        const eidSafe = columns.eventId && meta.colMap[columns.eventId] ? meta.colMap[columns.eventId] : null;
        if (eidSafe) addExpr(eidExprs, seen.eid, `${eidSafe} IN ('1','4688')`);
        const imageSafe = columns.image && meta.colMap[columns.image] ? meta.colMap[columns.image] : null;
        const cmdSafe = columns.cmdLine && meta.colMap[columns.cmdLine] ? meta.colMap[columns.cmdLine] : null;
        if (imageSafe) addExpr(descExprs, seen.desc, _nonEmptyText(imageSafe));
        if (cmdSafe) addExpr(descExprs, seen.desc, _nonEmptyText(cmdSafe));
        if (eidExprs.length === 0 || descExprs.length === 0) return { candidateExpr: null, linkableExpr: null };
        const candidateExpr = `(${eidExprs.join(" OR ")}) AND (${descExprs.join(" OR ")})`;
        return { candidateExpr, linkableExpr: candidateExpr };
      } else {
        const pidSafe = columns.pid && meta.colMap[columns.pid] ? meta.colMap[columns.pid] : null;
        const guidSafe = columns.guid && meta.colMap[columns.guid] ? meta.colMap[columns.guid] : null;
        const ppidSafe = columns.ppid && meta.colMap[columns.ppid] ? meta.colMap[columns.ppid] : null;
        const parentGuidSafe = columns.parentGuid && meta.colMap[columns.parentGuid] ? meta.colMap[columns.parentGuid] : null;
        if (pidSafe) addExpr(idExprs, seen.id, _nonEmptyText(pidSafe));
        if (guidSafe) addExpr(idExprs, seen.id, _nonEmptyText(guidSafe));
        if (ppidSafe) addExpr(parentExprs, seen.parent, _nonEmptyText(ppidSafe));
        if (parentGuidSafe) addExpr(parentExprs, seen.parent, _nonEmptyText(parentGuidSafe));
      }

      const imageSafe = columns.image && meta.colMap[columns.image] ? meta.colMap[columns.image] : null;
      const cmdSafe = columns.cmdLine && meta.colMap[columns.cmdLine] ? meta.colMap[columns.cmdLine] : null;
      if (imageSafe) addExpr(descExprs, seen.desc, _nonEmptyText(imageSafe));
      if (cmdSafe) addExpr(descExprs, seen.desc, _nonEmptyText(cmdSafe));

      if (idExprs.length === 0 || descExprs.length === 0) return { candidateExpr: null, linkableExpr: null };

      const candidateExpr = `(${idExprs.join(" OR ")}) AND (${descExprs.join(" OR ")})`;
      const linkableExpr = parentExprs.length > 0 ? `${candidateExpr} AND (${parentExprs.join(" OR ")})` : candidateExpr;
      return { candidateExpr, linkableExpr };
    };
    const candidateExprs = _buildCandidateProcessExprs();
    const _candidateProcessStats = (fullScope = false) => {
      if (!candidateExprs.candidateExpr) return { rows: 0, linkableRows: 0 };

      const { candidateExpr, linkableExpr } = candidateExprs;
      const fromScope = fullScope ? "" : ` ${wc}`;
      const bindParams = fullScope ? [] : params;
      const sql = `SELECT
        SUM(CASE WHEN ${candidateExpr} THEN 1 ELSE 0 END) as rows,
        SUM(CASE WHEN ${linkableExpr} THEN 1 ELSE 0 END) as linkableRows
        FROM data${fromScope}`;
      const qr = db.prepare(sql).get(...bindParams);
      return {
        rows: qr?.rows || 0,
        linkableRows: qr?.linkableRows || 0,
      };
    };

    const candidateStats = _candidateProcessStats(false);
    const candidateRows = candidateStats.rows || 0;
    const linkableCandidateRows = candidateStats.linkableRows || 0;
    let fullScopeCandidateRows = 0;
    if (candidateRows === 0) {
      const fullStats = _candidateProcessStats(true);
      fullScopeCandidateRows = fullStats.rows || 0;
    }

    // --- Event counts ---
    const eventCounts = {};
    const fullScopeEventCounts = {};
    let trackedEvents = 0;
    let fullScopeTrackedEvents = 0;
    let providerFallback = false;
    let eidNormalized = false;
    const uiEids = effectiveEventIdValue
      .split(",")
      .map((s) => String(s).trim())
      .filter(Boolean);
    // The Event ID box is a free-text field in the config phase, and these values are
    // INTERPOLATED into the normalization CASE expression below (they cannot be bound
    // there). Anything non-numeric produced either a hard SQL error ("no such column:
    // sysmon") or an injection point, so the interpolated form is integers only.
    const uiEidInts = [...new Set(uiEids.map((e) => parseInt(e, 10)).filter((n) => Number.isSafeInteger(n)))];
    if (uiEids.length > 0 && columns.eventId && meta.colMap[columns.eventId]) {
      const eidSafe = meta.colMap[columns.eventId];
      const eidWhere = wc ? `${wc} AND` : "WHERE";
      // For EvtxECmd, try provider-scoped first (Sysmon + Security), fall back to EID-only
      let provClause = "";
      const hasProvCol = isEvtxECmd && columns.provider && meta.colMap[columns.provider];
      if (hasProvCol) {
        const provSafe = meta.colMap[columns.provider];
        provClause = ` AND (${provSafe} LIKE '%Sysmon%' OR ${provSafe} LIKE '%Security%')`;
      }
      // Normalized EID expression: extracts integer from formats like "4688", "EventID 4688", "4688 - A new process"
      // CAST handles leading-digit values; LIKE fallback catches embedded IDs
      const eidNormExpr = uiEidInts.length > 0
        ? `CASE WHEN CAST(${eidSafe} AS INTEGER) IN (${uiEidInts.join(",")}) THEN CAST(${eidSafe} AS INTEGER) WHEN ${eidSafe} LIKE '%4688%' THEN 4688 WHEN ${eidSafe} LIKE '% 1' OR ${eidSafe} LIKE '% 1 %' OR ${eidSafe} = '1' THEN 1 ELSE NULL END`
        : `CASE WHEN ${eidSafe} LIKE '%4688%' THEN 4688 WHEN ${eidSafe} LIKE '% 1' OR ${eidSafe} LIKE '% 1 %' OR ${eidSafe} = '1' THEN 1 ELSE NULL END`;
      // Phase 1: exact match (fast path for clean data)
      const eidRows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${eidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")})${provClause} GROUP BY ${eidSafe}`).all(...params, ...uiEids);
      for (const r of eidRows) { if (r.eid != null) { const k = String(r.eid).trim(); eventCounts[k] = r.cnt; trackedEvents += r.cnt; } }
      // Phase 2: provider fallback (exact EID, no provider)
      if (trackedEvents === 0 && hasProvCol) {
        const fbRows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${eidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")}) GROUP BY ${eidSafe}`).all(...params, ...uiEids);
        for (const r of fbRows) { if (r.eid != null) { const k = String(r.eid).trim(); eventCounts[k] = r.cnt; trackedEvents += r.cnt; } }
        if (trackedEvents > 0) providerFallback = true;
      }
      // Phase 3: EID normalization fallback (handles non-clean EID values)
      if (trackedEvents === 0) {
        const normRows = db.prepare(`SELECT ${eidNormExpr} as eid, COUNT(*) as cnt FROM data ${eidWhere} ${eidNormExpr} IS NOT NULL${providerFallback ? "" : provClause} GROUP BY 1`).all(...params);
        for (const r of normRows) { if (r.eid != null) { const k = String(r.eid).trim(); eventCounts[k] = (eventCounts[k] || 0) + r.cnt; trackedEvents += r.cnt; } }
        if (trackedEvents > 0) eidNormalized = true;
      }

      // If the current scoped preview yields no process events, compute a lightweight
      // full-tab baseline so the UI can distinguish "no events in scope" from
      // "this dataset has no 1/4688 at all".
      if (trackedEvents === 0) {
        const fullEidWhere = "WHERE";
        const fullProvClause = provClause;
        const fullExactRows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${fullEidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")})${fullProvClause} GROUP BY ${eidSafe}`).all(...uiEids);
        for (const r of fullExactRows) {
          if (r.eid != null) {
            const k = String(r.eid).trim();
            fullScopeEventCounts[k] = (fullScopeEventCounts[k] || 0) + r.cnt;
            fullScopeTrackedEvents += r.cnt;
          }
        }
        if (fullScopeTrackedEvents === 0 && hasProvCol) {
          const fullFbRows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${fullEidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")}) GROUP BY ${eidSafe}`).all(...uiEids);
          for (const r of fullFbRows) {
            if (r.eid != null) {
              const k = String(r.eid).trim();
              fullScopeEventCounts[k] = (fullScopeEventCounts[k] || 0) + r.cnt;
              fullScopeTrackedEvents += r.cnt;
            }
          }
        }
        if (fullScopeTrackedEvents === 0) {
          const fullNormRows = db.prepare(`SELECT ${eidNormExpr} as eid, COUNT(*) as cnt FROM data ${fullEidWhere} ${eidNormExpr} IS NOT NULL GROUP BY 1`).all();
          for (const r of fullNormRows) {
            if (r.eid != null) {
              const k = String(r.eid).trim();
              fullScopeEventCounts[k] = (fullScopeEventCounts[k] || 0) + r.cnt;
              fullScopeTrackedEvents += r.cnt;
            }
          }
        }
      }
    }

    const previewMode = trackedEvents > 0 ? "process-events"
      : candidateRows > 0 ? "candidate-rows"
      : "empty";
    const autoGenericFallback = trackedEvents === 0 && fullScopeTrackedEvents === 0 && candidateRows > 0;
    const useCandidateLinkingPreview = autoGenericFallback && !!candidateExprs.candidateExpr;

    // --- Provider mix ---
    const providerMix = {};
    if (uiEids.length > 0 && columns.provider && meta.colMap[columns.provider] && columns.eventId && meta.colMap[columns.eventId]) {
      const provSafe = meta.colMap[columns.provider];
      const eidSafe = meta.colMap[columns.eventId];
      const pmWhere = wc ? `${wc} AND` : "WHERE";
      if (eidNormalized) {
        const eidNormExpr = `CASE WHEN CAST(${eidSafe} AS INTEGER) IN (${uiEids.join(",")}) THEN CAST(${eidSafe} AS INTEGER) WHEN ${eidSafe} LIKE '%4688%' THEN 4688 WHEN ${eidSafe} LIKE '% 1' OR ${eidSafe} LIKE '% 1 %' OR ${eidSafe} = '1' THEN 1 ELSE NULL END`;
        const pmRows = db.prepare(`SELECT ${provSafe} as prov, COUNT(*) as cnt FROM data ${pmWhere} ${eidNormExpr} IS NOT NULL GROUP BY ${provSafe}`).all(...params);
        for (const r of pmRows) { if (r.prov) providerMix[String(r.prov).trim()] = r.cnt; }
      } else {
        const pmRows = db.prepare(`SELECT ${provSafe} as prov, COUNT(*) as cnt FROM data ${pmWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")}) GROUP BY ${provSafe}`).all(...params, ...uiEids);
        for (const r of pmRows) { if (r.prov) providerMix[String(r.prov).trim()] = r.cnt; }
      }
    }

    // --- Column quality (batched 2000-row sample, same as LM L2871-2903) ---
    const columnQuality = {};
    const qualityKeys = ["pid", "ppid", "guid", "parentGuid", "image", "parentImage", "cmdLine", "user", "ts", "eventId", "elevation", "integrity", "provider", "hostname"];
    const mappedCols = qualityKeys.filter(k => columns[k] && meta.colMap[columns[k]]).map(k => [k, columns[k]]);
    if (mappedCols.length > 0) {
      const caseParts = [];
      for (const [key, cn] of mappedCols) {
        const safe = meta.colMap[cn];
        caseParts.push(`SUM(CASE WHEN ${safe} IS NULL OR TRIM(${safe}) = '' OR ${safe} = '-' THEN 1 ELSE 0 END) as null_${key}`);
      }
      const batchSql = `SELECT COUNT(*) as total, ${caseParts.join(", ")} FROM (SELECT * FROM data ${wc} LIMIT 2000)`;
      const qr = db.prepare(batchSql).get(...params);
      const sampleTotal = qr ? qr.total : 0;
      for (const [key] of mappedCols) {
        const nulls = qr ? (qr[`null_${key}`] || 0) : 0;
        columnQuality[key] = { mapped: true, nullRate: sampleTotal > 0 ? Math.round((nulls / sampleTotal) * 100) : 0 };
      }
      for (const k of qualityKeys) { if (!columnQuality[k]) columnQuality[k] = { mapped: false }; }
    } else {
      for (const k of qualityKeys) columnQuality[k] = { mapped: false };
    }

    // --- Linking quality (PI-unique) ---
    const linkingQuality = { guidCoverage: 0, pidCoverage: 0, parentImageCoverage: 0, cmdLineCoverage: 0 };
    {
      // Build WHERE for process-creation events only — provider is secondary hint, not hard gate
      const lqWhere = [...whereConditions];
      let lqParams;
      if (useCandidateLinkingPreview) {
        lqWhere.push(candidateExprs.candidateExpr);
        lqParams = [...params];
      } else if (uiEids.length > 0 && columns.eventId && meta.colMap[columns.eventId]) {
        const eidSafe = meta.colMap[columns.eventId];
        if (eidNormalized) {
          const eidNormExpr = `CASE WHEN CAST(${eidSafe} AS INTEGER) IN (${uiEids.join(",")}) THEN CAST(${eidSafe} AS INTEGER) WHEN ${eidSafe} LIKE '%4688%' THEN 4688 WHEN ${eidSafe} LIKE '% 1' OR ${eidSafe} LIKE '% 1 %' OR ${eidSafe} = '1' THEN 1 ELSE NULL END`;
          lqWhere.push(`${eidNormExpr} IS NOT NULL`);
          lqParams = [...params];
        } else {
          lqWhere.push(`${eidSafe} IN (${uiEids.map(() => "?").join(",")})`);
          lqParams = [...params, ...uiEids];
        }
      } else {
        lqParams = [...params];
      }
      // Only add provider clause if provider-gated event counts succeeded (not in fallback mode)
      if (!useCandidateLinkingPreview && !providerFallback && !eidNormalized && isEvtxECmd && columns.provider && meta.colMap[columns.provider]) {
        const provSafe = meta.colMap[columns.provider];
        lqWhere.push(`(${provSafe} LIKE '%Sysmon%' OR ${provSafe} LIKE '%Security%')`);
      }
      const lqWc = lqWhere.length > 0 ? `WHERE ${lqWhere.join(" AND ")}` : "";

      const lqParts = ["COUNT(*) as total"];

      // GUID coverage
      if (isEvtxECmd) {
        // EvtxECmd: GUID is embedded in PayloadData1/PayloadData5
        const pd1Safe = columns.guid && meta.colMap[columns.guid] ? meta.colMap[columns.guid] : null;
        const pd5Safe = columns.parentGuid && meta.colMap[columns.parentGuid] ? meta.colMap[columns.parentGuid] : null;
        if (pd1Safe && pd5Safe) {
          lqParts.push(`SUM(CASE WHEN ${pd1Safe} LIKE '%ProcessGUID:%' AND ${pd5Safe} LIKE '%ParentProcessGUID:%' THEN 1 ELSE 0 END) as guid_pairs`);
          lqParts.push(`SUM(CASE WHEN ${pd1Safe} LIKE '%ProcessID:%' AND ${pd5Safe} LIKE '%ParentProcessID:%' THEN 1 ELSE 0 END) as pid_pairs`);
        }
      } else if (isHayabusa) {
        const detailsSafe = columns.details && meta.colMap[columns.details] ? meta.colMap[columns.details] : null;
        const extraSafe = columns.extra && meta.colMap[columns.extra] ? meta.colMap[columns.extra] : null;
        if (detailsSafe) {
          lqParts.push(`SUM(CASE WHEN (${detailsSafe} LIKE '%PGUID:%' OR ${detailsSafe} LIKE '%ProcessGuid:%') AND (${detailsSafe} LIKE '%ParentPGUID:%' OR ${detailsSafe} LIKE '%ParentProcessGuid:%') THEN 1 ELSE 0 END) as guid_pairs`);
          const parentPidExpr = extraSafe
            ? `(${detailsSafe} LIKE '%ParentPID:%' OR ${extraSafe} LIKE '%ProcessId:%')`
            : `(${detailsSafe} LIKE '%ParentPID:%')`;
          lqParts.push(`SUM(CASE WHEN ${detailsSafe} LIKE '%PID:%' AND ${parentPidExpr} THEN 1 ELSE 0 END) as pid_pairs`);
          lqParts.push(`SUM(CASE WHEN ${detailsSafe} LIKE '%Cmdline:%' THEN 1 ELSE 0 END) as has_cmdline`);
        }
        if (extraSafe) {
          lqParts.push(`SUM(CASE WHEN ${extraSafe} LIKE '%ParentImage:%' OR ${extraSafe} LIKE '%ParentProcessName:%' THEN 1 ELSE 0 END) as has_parent_image`);
        }
      } else {
        // Standard columns
        const gSafe = columns.guid && meta.colMap[columns.guid] ? meta.colMap[columns.guid] : null;
        const pgSafe = columns.parentGuid && meta.colMap[columns.parentGuid] ? meta.colMap[columns.parentGuid] : null;
        if (gSafe && pgSafe) {
          lqParts.push(`SUM(CASE WHEN ${gSafe} IS NOT NULL AND TRIM(${gSafe}) != '' AND ${pgSafe} IS NOT NULL AND TRIM(${pgSafe}) != '' THEN 1 ELSE 0 END) as guid_pairs`);
        }
        const pSafe = columns.pid && meta.colMap[columns.pid] ? meta.colMap[columns.pid] : null;
        const ppSafe = columns.ppid && meta.colMap[columns.ppid] ? meta.colMap[columns.ppid] : null;
        if (pSafe && ppSafe) {
          lqParts.push(`SUM(CASE WHEN ${pSafe} IS NOT NULL AND TRIM(${pSafe}) != '' AND ${ppSafe} IS NOT NULL AND TRIM(${ppSafe}) != '' THEN 1 ELSE 0 END) as pid_pairs`);
        }
      }
      // Parent image + command line coverage
      const piSafe = columns.parentImage && meta.colMap[columns.parentImage] ? meta.colMap[columns.parentImage] : null;
      if (piSafe) lqParts.push(`SUM(CASE WHEN ${piSafe} IS NOT NULL AND TRIM(${piSafe}) != '' AND ${piSafe} != '-' THEN 1 ELSE 0 END) as has_parent_image`);
      const clSafe = columns.cmdLine && meta.colMap[columns.cmdLine] ? meta.colMap[columns.cmdLine] : null;
      if (clSafe) lqParts.push(`SUM(CASE WHEN ${clSafe} IS NOT NULL AND TRIM(${clSafe}) != '' AND ${clSafe} != '-' THEN 1 ELSE 0 END) as has_cmdline`);

      const lqSql = `SELECT ${lqParts.join(", ")} FROM (SELECT * FROM data ${lqWc} LIMIT 2000)`;
      const lqr = db.prepare(lqSql).get(...lqParams);
      const total = lqr ? lqr.total : 0;
      if (total > 0) {
        linkingQuality.guidCoverage = lqr.guid_pairs != null ? Math.round((lqr.guid_pairs / total) * 100) : 0;
        linkingQuality.pidCoverage = lqr.pid_pairs != null ? Math.round((lqr.pid_pairs / total) * 100) : 0;
        linkingQuality.parentImageCoverage = lqr.has_parent_image != null ? Math.round((lqr.has_parent_image / total) * 100) : 0;
        linkingQuality.cmdLineCoverage = lqr.has_cmdline != null ? Math.round((lqr.has_cmdline / total) * 100) : 0;
      }
    }

    const linkingMode = linkingQuality.guidCoverage > 50 ? "guid"
      : linkingQuality.pidCoverage > 50 ? "pid-only"
      : "insufficient";

    // --- Top values for critical columns (sampled from first 2000 rows in scope) ---
    const topValues = {};
    const topCols = { eventId: columns.eventId, provider: columns.provider, image: columns.image, cmdLine: columns.cmdLine };
    for (const [key, cn] of Object.entries(topCols)) {
      if (!cn || !meta.colMap[cn]) continue;
      const safe = meta.colMap[cn];
      try {
        const tvRows = db.prepare(`SELECT ${safe} as v, COUNT(*) as cnt FROM (SELECT ${safe} FROM data ${wc} LIMIT 2000) WHERE ${safe} IS NOT NULL AND TRIM(${safe}) != '' GROUP BY ${safe} ORDER BY cnt DESC LIMIT 5`).all(...params);
        topValues[key] = tvRows.map(r => ({ value: String(r.v).substring(0, 120), count: r.cnt }));
      } catch (_) { /* ignore column errors */ }
    }

    // --- Data shape: hosts, users, date span ---
    const dataShape = {};
    try {
      // Host count
      const hostCol = columns.hostname || (isEvtxECmd ? (meta.headers.find(h => /^Computer$/i.test(h)) || null) : null);
      if (hostCol && meta.colMap[hostCol]) {
        const hSafe = meta.colMap[hostCol];
        const hr = db.prepare(`SELECT COUNT(DISTINCT ${hSafe}) as cnt FROM (SELECT ${hSafe} FROM data ${wc} LIMIT 5000)`).get(...params);
        dataShape.hosts = hr ? hr.cnt : 0;
      }
      // User count
      if (columns.user && meta.colMap[columns.user]) {
        const uSafe = meta.colMap[columns.user];
        const ur = db.prepare(`SELECT COUNT(DISTINCT ${uSafe}) as cnt FROM (SELECT ${uSafe} FROM data ${wc} WHERE ${uSafe} IS NOT NULL AND TRIM(${uSafe}) != '' AND ${uSafe} != '-' LIMIT 5000)`).get(...params);
        dataShape.users = ur ? ur.cnt : 0;
      }
      // Date span
      if (columns.ts && meta.colMap[columns.ts]) {
        const tSafe = meta.colMap[columns.ts];
        const dr = db.prepare(`SELECT MIN(${tSafe}) as mn, MAX(${tSafe}) as mx FROM data ${wc}`).get(...params);
        if (dr && dr.mn && dr.mx) { dataShape.dateMin = dr.mn; dataShape.dateMax = dr.mx; }
      }
      // Active filter count (from whereConditions minus the EID/provider auto-filters)
      dataShape.activeFilters = whereConditions.length;
    } catch (_) { /* ignore shape errors */ }

    // --- Sample rows for inline preview (20 rows, critical columns only) ---
    const sampleRows = [];
    try {
      const sampleCols = [];
      const sampleHeaders = [];
      for (const [key, label] of [["eventId", "Event ID"], ["provider", "Provider"], ["image", "Image"], ["cmdLine", "Command Line"], ["pid", "PID"], ["ppid", "PPID"], ["user", "User"], ["ts", "Timestamp"]]) {
        if (columns[key] && meta.colMap[columns[key]]) {
          sampleCols.push({ key, safe: meta.colMap[columns[key]] });
          sampleHeaders.push({ key, label, col: columns[key] });
        }
      }
      if (sampleCols.length > 0) {
        const selParts = sampleCols.map(c => `${c.safe} as [${c.key}]`).join(", ");
        const sRows = db.prepare(`SELECT ${selParts} FROM data ${wc} LIMIT 20`).all(...params);
        for (const r of sRows) {
          const row = {};
          for (const c of sampleCols) { row[c.key] = r[c.key] != null ? String(r[c.key]).substring(0, 200) : null; }
          sampleRows.push(row);
        }
      }
      dataShape.sampleHeaders = sampleHeaders;
    } catch (_) { /* ignore sample errors */ }

    const result = {
      eventCounts,
      fullScopeEventCounts,
      columnQuality,
      linkingQuality,
      linkingMode,
      trackedEvents,
      fullScopeTrackedEvents,
      candidateRows,
      fullScopeCandidateRows,
      linkableCandidateRows,
      previewMode,
      autoGenericFallback,
      providerMix,
      providerFallback,
      eidNormalized,
      topValues,
      dataShape,
      sampleRows,
      resolvedColumns: columns,
      isEvtxECmd,
      isHayabusa,
      isChainsaw,
    };
    ctx.ptPreviewCache.set(cacheKey, result);
    if (columns.eventId) setImmediate(() => { try { ctx.ensureIndex(meta.tabId, columns.eventId); } catch (_) {} });
    return result;
  } catch (e) {
    return { eventCounts: {}, columnQuality: {}, linkingQuality: {}, error: e.message };
  }
}

function getProcessInspectorContext(meta, options = {}, ctx) {
  if (!meta) return { selected: null, timeline: [], groups: [], enrichmentChips: [], error: "No database" };

  const {
    rowId,
    selected = {},
    windowMinutes = 5,
    contextMinutes = 15,
    maxWindowRows = 500,
    maxExactRows = 200,
    maxTimelineRows = 120,
  } = options;

  const detect = (patterns) => {
    for (const pat of patterns) {
      const found = meta.headers.find((h) => pat.test(h));
      if (found) return found;
    }
    return null;
  };

  const isEvtxECmd = meta.headers.some((h) => /^PayloadData1$/i.test(h)) && meta.headers.some((h) => /^ExecutableInfo$/i.test(h));
  const isHayabusa = isHayabusaDataset(meta);
  const isChainsaw = isChainsawDataset(meta);
  const isChainsawProcess = isChainsawProcessDataset(meta);

  const columns = {
    pid: detect([/^ProcessId$/i, /^pid$/i, /^process_id$/i, /^NewProcessId$/i]),
    ppid: detect([/^ParentProcessId$/i, /^ppid$/i, /^parent_process_id$/i, /^parent_pid$/i, /^CreatorProcessId$/i]),
    guid: detect([/^ProcessGuid$/i, /^process_guid$/i]),
    parentGuid: detect([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
    image: detect([/^Image$/i, /^process_name$/i, /^exe$/i, /^FileName$/i, /^ImagePath$/i, /^NewProcessName$/i, ...(isChainsawProcess ? [/^Event\.EventData\.Image$/i] : [])]),
    // See parentImage rationale in getProcessTree above — broadened to mirror image detection.
    parentImage: detect([/^ParentImage$/i, /^ParentProcessName$/i, /^Parent[_\s]?Process[_\s]?Name$/i, /^parent_image$/i, /^parent_process_name$/i, /^ParentImagePath$/i, /^Parent[_\s]?Image[_\s]?Path$/i, /^ParentExe$/i, /^ParentFileName$/i, /^CreatorProcessName$/i, /^Creator[_\s]?Process[_\s]?Name$/i, ...(isChainsawProcess ? [/^Event\.EventData\.ParentImage$/i] : [])]),
    cmdLine: detect([/^CommandLine$/i, /^command_line$/i, /^cmd$/i, /^cmdline$/i, /^ProcessCommandLine$/i, ...(isChainsawProcess ? [/^Event\.EventData\.CommandLine$/i] : [])]),
    user: detect([/^User$/i, /^UserName$/i, /^user_name$/i, /^SubjectUserName$/i, /^TargetUserName$/i, ...(isChainsaw ? [/^target_username$/i] : [])]),
    ts: detect([/^UtcTime$/i, /^datetime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
    eventId: detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsaw ? [/^id$/i] : [])]),
    provider: detect([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
    hostname: detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, /^MachineName$/i, ...(isChainsaw ? [/^computer_name$/i] : [])]),
    details: detect([/^Details$/i]),
    extra: detect([/^ExtraFieldInfo$/i]),
    payload: detect([/^Payload$/i, /^Message$/i, /^RenderedMessage$/i]),
    payload2: detect([/^PayloadData2$/i]),
    payload3: detect([/^PayloadData3$/i]),
    payload4: detect([/^PayloadData4$/i]),
    payload5: detect([/^PayloadData5$/i]),
    payload6: detect([/^PayloadData6$/i]),
    execInfo: detect([/^ExecutableInfo$/i]),
    logonId: detect([/^LogonId$/i, /^SubjectLogonId$/i, /^Subject_Logon_ID$/i, /^TargetLogonId$/i, /^Target_Logon_ID$/i]),
    targetLogonId: detect([/^TargetLogonId$/i, /^Target_Logon_ID$/i]),
    logonType: detect([/^LogonType$/i, /^Logon_Type$/i, ...(isChainsaw ? [/^logon_type$/i] : []), ...(isEvtxECmd ? [/^PayloadData2$/i] : [])]),
    sourceIp: detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^ClientAddress$/i, /^SourceIp$/i, /^src_ip$/i, /^id\.orig_h$/i, ...(isChainsaw ? [/^source_ip$/i] : [])]),
    sourcePort: detect([/^SourcePort$/i, /^SourcePortName$/i, /^src_port$/i, /^id\.orig_p$/i]),
    destIp: detect([/^DestinationIp$/i, /^DestinationIP$/i, /^DestinationAddress$/i, /^DestIp$/i, /^RemoteAddress$/i, /^dst_ip$/i, /^id\.resp_h$/i]),
    destPort: detect([/^DestinationPort$/i, /^DestPort$/i, /^RemotePort$/i, /^dst_port$/i, /^id\.resp_p$/i]),
    queryName: detect([/^QueryName$/i, /^DnsQuery$/i, /^Query$/i, /^query$/i, /^Domain$/i, /^domain$/i]),
    queryStatus: detect([/^QueryStatus$/i, /^DnsStatus$/i, /^rcode$/i, /^ResponseCode$/i]),
    workstation: detect([/^WorkstationName$/i, /^ClientName$/i, /^workstation_name$/i]),
    channel: detect([/^Channel$/i, /^SourceName$/i]),
    ruleId: detect([/^RuleID$/i, /^RuleId$/i, /^rule_id$/i, /^sigma_rule_id$/i]),
    ruleTitle: detect([/^RuleTitle$/i]),
    ruleLevel: detect([/^Level$/i, /^Severity$/i, /^level$/i]),
    detectionRule: detect([/^detection_rules$/i, /^DetectionRule$/i]),
  };

  if (isEvtxECmd) {
    columns.pid = detect([/^PayloadData1$/i]) || columns.pid;
    columns.ppid = detect([/^PayloadData5$/i]) || columns.ppid;
    columns.guid = detect([/^PayloadData1$/i]) || columns.guid;
    columns.parentGuid = detect([/^PayloadData5$/i]) || columns.parentGuid;
    columns.image = detect([/^ExecutableInfo$/i]) || columns.image;
    columns.cmdLine = detect([/^ExecutableInfo$/i]) || columns.cmdLine;
    columns.logonType = detect([/^PayloadData2$/i]) || columns.logonType;
  } else if (isHayabusa) {
    const detailsCol = detect([/^Details$/i]);
    const extraCol = detect([/^ExtraFieldInfo$/i]);
    columns.pid = detailsCol || columns.pid;
    columns.ppid = extraCol || detailsCol || columns.ppid;
    columns.guid = detailsCol || columns.guid;
    columns.parentGuid = detailsCol || columns.parentGuid;
    columns.image = detailsCol || columns.image;
    columns.parentImage = extraCol || detailsCol || columns.parentImage;
    columns.cmdLine = detailsCol || columns.cmdLine;
    columns.user = extraCol || detailsCol || columns.user;
    columns.logonId = extraCol || detailsCol || columns.logonId;
    columns.logonType = extraCol || detailsCol || columns.logonType;
  }

  const selectParts = ["data.rowid as _rowid"];
  const added = new Set();
  for (const [key, colName] of Object.entries(columns)) {
    if (!colName || !meta.colMap[colName] || added.has(colName)) continue;
    selectParts.push(`${meta.colMap[colName]} as [${key}]`);
    added.add(colName);
  }
  // Row-level aliases — see ROW_LEVEL_ALIAS_PATTERNS in getProcessTree. Without
  // them the context window for a Security 4688 was centred on the CREATOR's pid
  // (the tab-wide `pid` column resolves to ProcessId), so the analyst got the
  // parent's neighbourhood instead of the selected process's.
  const ctxRowLevel = {};
  if (!isEvtxECmd && !isHayabusa && !isChainsaw) {
    for (const [alias, pat] of Object.entries({
      _subjectPid: /^ProcessId$/i,
      _newPid: /^NewProcessId$/i,
      _creatorPid: /^CreatorProcessId$/i,
      _newImage: /^NewProcessName$/i,
      _procName: /^ProcessName$/i,
      _parentName: /^ParentProcessName$/i,
    })) {
      const c = detect([pat]);
      if (c && meta.colMap[c]) { ctxRowLevel[alias] = meta.colMap[c]; selectParts.push(`${meta.colMap[c]} as [${alias}]`); }
    }
  }
  const _ctxIsEid = (value, eid) => new RegExp(`(^|\\D)${eid}(\\D|$)`).test(String(value || "").trim());
  const selectSql = selectParts.join(", ");
  const db = meta.db;

  const clean = (value, opts = {}) => cleanWrappedField(value, opts);
  // normalizeHost / normalizeUser / normalizeGuid / normalizePid / normalizeLogonId
  // are imported from electron/utils/forensic-normalize so the inspector context,
  // tree builder, and renderer all share one set of rules. The previous local
  // shadows here drifted from the tree builder's logic and caused brace-wrapped
  // GUIDs and hex logon IDs to silently miss correlation.
  const hexVariants = (value) => {
    const n = Number.parseInt(value, 10);
    if (!Number.isFinite(n) || n < 0) return [];
    return [`0x${n.toString(16)}`, `0X${n.toString(16).toUpperCase()}`];
  };
  const runQuery = (whereSql, params = [], limit = 200, orderSql = "ORDER BY data.rowid ASC") => {
    const capped = Math.max(1, Math.min(Number(limit) || 200, 2000));
    const rows = db.prepare(`SELECT ${selectSql} FROM data ${whereSql} ${orderSql} LIMIT ${capped}`).all(...params);
    return rows;
  };

  const selectedRaw = rowId ? db.prepare(`SELECT ${selectSql} FROM data WHERE data.rowid = ? LIMIT 1`).get(Number(rowId)) : null;

  const normalizeEvent = (row, fallback = {}) => {
    if (!row && !fallback) return null;

    const compact = parseCompactKeyValues(row?.details, row?.extra);
    const haystack = row ? buildEvtxHaystack(row) : "";

    let pid = row?.pid || fallback.pid || "";
    let ppid = row?.ppid || fallback.ppid || "";
    let guid = row?.guid || fallback.guid || "";
    let parentGuid = row?.parentGuid || fallback.parentGuid || "";
    let image = row?.image || fallback.image || "";
    let cmdLine = row?.cmdLine || fallback.cmdLine || "";
    let parentImage = row?.parentImage || fallback.parentImage || "";
    let user = row?.user || fallback.user || "";
    let logonType = row?.logonType || "";
    let logonId = row?.logonId || row?.targetLogonId || "";

    if (isEvtxECmd && row) {
      const pd1 = row.pid || row.guid || "";
      const pd5 = row.ppid || row.parentGuid || "";
      const pidMatch = String(pd1).match(/ProcessID:\s*(\d+)/i);
      const guidMatch = String(pd1).match(/ProcessGUID:\s*([0-9a-f-]+)/i);
      const ppidMatch = String(pd5).match(/ParentProcessID:\s*(\d+)/i);
      const pguidMatch = String(pd5).match(/ParentProcessGUID:\s*([0-9a-f-]+)/i);
      if (pidMatch) pid = pidMatch[1];
      if (guidMatch) guid = guidMatch[1];
      if (ppidMatch) ppid = ppidMatch[1];
      if (pguidMatch) parentGuid = pguidMatch[1];
      const execInfo = row.image || row.cmdLine || row.execInfo || "";
      cmdLine = execInfo || cmdLine;
      if (execInfo) {
        const qm = String(execInfo).match(/^"([^"]+)"/);
        image = qm ? qm[1] : String(execInfo).split(/\s+/)[0];
      }
      if (!logonType && row.logonType) {
        const lt = String(row.logonType).match(/LogonType\s+(\d+)/i);
        if (lt) logonType = lt[1];
      }
    } else if (isHayabusa && row) {
      pid = compactGetInt(compact, "PID", "ProcessId", "NewProcessId") || pid;
      const eventId = String(row.eventId || "").trim();
      ppid = (eventId === "4688"
        ? compactGetInt(compact, "ProcessId", "CreatorProcessId", "ParentPID", "ParentProcessId")
        : compactGetInt(compact, "ParentPID", "ParentProcessId", "CreatorProcessId")) || ppid;
      guid = compactGet(compact, "PGUID", "ProcessGuid", "ProcessGUID") || guid;
      parentGuid = compactGet(compact, "ParentPGUID", "ParentProcessGuid", "ParentProcessGUID") || parentGuid;
      image = compactGet(compact, "Proc", "Image", "NewProcessName", "ProcessName") || image;
      cmdLine = compactGet(compact, "Cmdline", "CommandLine", "ProcessCommandLine") || cmdLine;
      parentImage = compactGet(compact, "ParentImage", "ParentProcessName", "ParentImagePath", "ParentExe", "ParentFileName") || parentImage;
      user = compactGet(compact, "SubjectUserName", "TargetUserName", "TgtUser", "User", "SrcUser") || user;
      logonType = compactGet(compact, "LogonType", "Type") || logonType;
      logonId = compactGet(compact, "SubjectLogonId", "TargetLogonId", "LogonId", "LID", "SessionId", "Session ID") || logonId;
    } else if (isChainsaw && row) {
      pid = extractFirstInteger(row.pid || pid);
      ppid = extractFirstInteger(row.ppid || ppid);
      guid = clean(row.guid || guid);
      parentGuid = clean(row.parentGuid || parentGuid);
      image = clean(row.image || image);
      cmdLine = clean(row.cmdLine || cmdLine);
      parentImage = clean(row.parentImage || parentImage);
      user = clean(row.user || user);
      logonType = extractFirstInteger(row.logonType || logonType) || clean(row.logonType || logonType);
    } else if (row) {
      // Row-level resolution first: a 4688 identifies itself with NewProcessId and
      // its creator with ProcessId; a 4689/4673/4674 uses ProcessId for the subject.
      if (_ctxIsEid(row.eventId, "4688") && row._newPid) {
        pid = row._newPid;
        ppid = row._creatorPid || row._subjectPid || ppid;
        if (!image) image = row._newImage || "";
        if (!parentImage) parentImage = row._parentName || "";
      } else if ((_ctxIsEid(row.eventId, "4689") || _ctxIsEid(row.eventId, "4673") || _ctxIsEid(row.eventId, "4674")) && row._subjectPid) {
        pid = row._subjectPid;
        if (!image) image = row._procName || "";
      }
      pid = normalizePid(pid) || compactGetInt(compact, "PID", "ProcessId", "NewProcessId");
      ppid = normalizePid(ppid) || compactGetInt(compact, "ParentPID", "ParentProcessId", "CreatorProcessId", "ProcessId");
      guid = clean(guid) || compactGet(compact, "PGUID", "ProcessGuid", "ProcessGUID");
      parentGuid = clean(parentGuid) || compactGet(compact, "ParentPGUID", "ParentProcessGuid", "ParentProcessGUID");
      image = clean(image) || compactGet(compact, "Proc", "Image", "NewProcessName", "ProcessName", "Path");
      cmdLine = clean(cmdLine) || compactGet(compact, "Cmdline", "CommandLine", "ProcessCommandLine", "HostApplication");
      parentImage = clean(parentImage) || compactGet(compact, "ParentImage", "ParentProcessName", "ParentImagePath", "ParentExe", "ParentFileName");
      user = clean(user) || compactGet(compact, "SubjectUserName", "TargetUserName", "TgtUser", "User", "SrcUser", "AccountName");
      logonType = extractFirstInteger(logonType) || compactGet(compact, "LogonType", "Type");
      logonId = clean(logonId) || compactGet(compact, "SubjectLogonId", "TargetLogonId", "LogonId", "LID", "SessionId", "Session ID");
    }

    if (!image && cmdLine) {
      const qm = String(cmdLine).match(/^"([^"]+)"/);
      image = qm ? qm[1] : String(cmdLine).split(/\s+/)[0];
    }
    if (!cmdLine && image) cmdLine = image;

    const eventId = extractFirstInteger(row?.eventId || row?.id || fallback.eventId || "");
    const hostname = clean(row?.hostname || fallback.hostname || "");
    const timestamp = clean(row?.ts || fallback.ts || "");
    // Use the canonical normalizer so non-ISO formats (US dates, Excel serials,
    // locale strings) parse correctly. The previous raw new Date(...) call was
    // the root cause of inspector-context windows missing same-host / same-user
    // events on any tab whose timestamps weren't ISO-8601.
    const _tsMsRaw = normalizeTimestamp(timestamp);
    const tsMs = Number.isFinite(_tsMsRaw) ? _tsMsRaw : NaN;
    const procName = clean((image || fallback.processName || "").split(/[\\/]/).pop());
    const parentProcName = clean((parentImage || fallback.parentProcessName || "").split(/[\\/]/).pop());
    const channel = resolveEventChannel({
      eventId,
      provider: row?.provider || row?.channel || fallback.provider || "",
      channel: row?.channel || row?.provider || fallback.provider || "",
      source: row?.sourceIp || row?.payload2 || "",
      workstation: row?.workstation || "",
      user,
      logonType,
    });

    const kvText = (keyNames) => {
      for (const key of keyNames) {
        const escaped = String(key).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const m = haystack.match(new RegExp(`\\b${escaped}\\s*[:=]\\s*([^,;\\r\\n]+)`, "i"));
        if (m?.[1]) return clean(m[1]);
      }
      return "";
    };
    const sourceIp = clean(row?.sourceIp || compactGet(compact, "SourceIp", "SourceIP", "SourceAddress", "SrcIP", "IpAddress", "ClientAddress") || kvText(["SourceIp", "SourceIP", "SourceAddress", "SrcIP", "IpAddress", "ClientAddress"]));
    const sourcePort = clean(row?.sourcePort || compactGet(compact, "SourcePort", "SrcPort") || kvText(["SourcePort", "SrcPort"]));
    const destIp = clean(row?.destIp || compactGet(compact, "DestinationIp", "DestinationIP", "DestinationAddress", "DestIp", "DstIP", "RemoteAddress") || kvText(["DestinationIp", "DestinationIP", "DestinationAddress", "DestIp", "DstIP", "RemoteAddress"]));
    const destPort = clean(row?.destPort || compactGet(compact, "DestinationPort", "DestPort", "DstPort", "RemotePort") || kvText(["DestinationPort", "DestPort", "DstPort", "RemotePort"]));
    const queryName = clean(row?.queryName || compactGet(compact, "QueryName", "Query", "DnsQuery", "Domain") || kvText(["QueryName", "Query", "DnsQuery", "Domain"]));
    const queryStatus = clean(row?.queryStatus || compactGet(compact, "QueryStatus", "Status", "Rcode", "ResponseCode") || kvText(["QueryStatus", "Status", "Rcode", "ResponseCode"]));
    const ruleId = clean(row?.ruleId || compactGet(compact, "RuleID", "RuleId", "SigmaRuleID") || kvText(["RuleID", "RuleId", "SigmaRuleID"]));
    const ruleTitle = clean(row?.ruleTitle || row?.detectionRule || compactGet(compact, "RuleTitle", "Rule", "DetectionRule", "SigmaRuleTitle") || kvText(["RuleTitle", "Rule", "DetectionRule", "SigmaRuleTitle"]));
    const ruleLevel = clean(row?.ruleLevel || compactGet(compact, "Level", "Severity") || kvText(["Level", "Severity"]));

    const telemetryType = (() => {
      if (ruleTitle || ruleId) return "detection";
      if (eventId === "22" || queryName) return "dns";
      if (eventId === "3" || eventId === "5156" || eventId === "5157" || destIp || destPort) return "network";
      return "";
    })();
    const telemetryLabel = (() => {
      if (telemetryType === "detection") return ruleTitle || ruleId || "Detection Rule";
      if (telemetryType === "dns") return queryName ? `DNS ${queryName}` : "DNS Query";
      if (telemetryType === "network") {
        if (eventId === "5157") return `Blocked network ${destIp || "destination"}${destPort ? `:${destPort}` : ""}`;
        return `Network ${destIp || "destination"}${destPort ? `:${destPort}` : ""}`;
      }
      return "";
    })();
    const telemetrySummary = (() => {
      if (telemetryType === "detection") {
        return [ruleLevel ? ruleLevel.toUpperCase() : "", ruleTitle || ruleId, procName || image].filter(Boolean).join(" | ");
      }
      if (telemetryType === "dns") {
        return [queryName || "DNS query", queryStatus ? `status ${queryStatus}` : "", procName || image].filter(Boolean).join(" | ");
      }
      if (telemetryType === "network") {
        const endpoint = `${sourceIp || "?"}${sourcePort ? `:${sourcePort}` : ""} -> ${destIp || "?"}${destPort ? `:${destPort}` : ""}`;
        return [endpoint, procName || image, eventId === "5157" ? "blocked" : ""].filter(Boolean).join(" | ");
      }
      return "";
    })();

    const enrichmentType = (() => {
      if (eventId === "4104") return "powershell";
      if (eventId === "7045" || eventId === "4697") return "service";
      if (eventId === "4698" || eventId === "4702") return "task";
      if (eventId === "4624" || eventId === "4648" || eventId === "4672") return "logon";
      if (eventId === "4689" || (eventId === "5" && channel === "sysmon")) return "terminate";
      return null;
    })();

    const eventLabel = (() => {
      if (eventId === "4104") return "PowerShell 4104";
      if (eventId === "7045") return "Service Install";
      if (eventId === "4697") return "Service Install (Security)";
      if (eventId === "4698") return "Task Created";
      if (eventId === "4702") return "Task Updated";
      if (eventId === "4624") return "Logon Success";
      if (eventId === "4648") return "Explicit Credentials";
      if (eventId === "4672") return "Admin Privileges";
      if (eventId === "4689") return "Process Terminated";
      if (eventId === "5" && channel === "sysmon") return "Sysmon Process Terminated";
      return eventId ? `Event ${eventId}` : "Event";
    })();

    const summary = (() => {
      const parts = [];
      if (enrichmentType === "powershell") {
        const scriptText = compactGet(compact, "ScriptBlockText", "ScriptBlock", "HostApplication");
        if (scriptText) return clean(scriptText, { lineJoiner: " | " }).slice(0, 240);
      }
      if (enrichmentType === "service") {
        const svc = compactGet(compact, "Svc", "ServiceName", "param1");
        const pathValue = compactGet(compact, "Path", "ImagePath", "ServiceFileName");
        if (svc) parts.push(svc);
        if (pathValue) parts.push(pathValue);
      } else if (enrichmentType === "task") {
        const taskName = compactGet(compact, "Task", "TaskName", "Name");
        const action = compactGet(compact, "Command", "Action", "Actions");
        if (taskName) parts.push(taskName);
        if (action) parts.push(action);
      } else if (enrichmentType === "logon") {
        if (user) parts.push(user);
        if (logonType) parts.push(`Type ${logonType}`);
        const src = compactGet(compact, "IpAddress", "SourceNetworkAddress", "ClientAddress", "SrcIP") || clean(row?.sourceIp || "");
        const wk = compactGet(compact, "WorkstationName", "ClientName", "SrcComp") || clean(row?.workstation || "");
        if (src) parts.push(src);
        else if (wk) parts.push(wk);
      } else if (enrichmentType === "terminate") {
        if (procName) parts.push(procName);
        if (image) parts.push(image);
      }
      if (parts.length > 0) return parts.join(" | ").slice(0, 240);
      return clean(cmdLine || image || haystack || procName, { lineJoiner: " | " }).replace(/\s+/g, " ").slice(0, 240);
    })();

    return {
      rowid: Number(row?._rowid || fallback.rowid || 0),
      timestamp,
      tsMs: Number.isFinite(tsMs) ? tsMs : 0,
      hostname,
      normHost: normalizeHost(hostname),
      user: clean(user),
      normUser: normalizeUser(user),
      pid: normalizePid(pid),
      ppid: normalizePid(ppid),
      guid: normalizeGuid(guid),
      parentGuid: normalizeGuid(parentGuid),
      image: clean(image),
      parentImage: clean(parentImage),
      processName: procName || clean(fallback.processName || ""),
      parentProcessName: parentProcName || clean(fallback.parentProcessName || ""),
      cmdLine: clean(cmdLine, { lineJoiner: " | " }),
      provider: clean(row?.provider || row?.channel || fallback.provider || ""),
      channel,
      eventId,
      eventLabel,
      enrichmentType,
      telemetryType,
      telemetryLabel,
      telemetrySummary,
      sourceIp,
      sourcePort,
      destIp,
      destPort,
      queryName,
      queryStatus,
      ruleId,
      ruleTitle,
      ruleLevel,
      evidenceRef: {
        tabId: meta.tabId || ctx?.tabId || null,
        rowId: Number(row?._rowid || fallback.rowid || 0),
      },
      summary,
      logonType: extractFirstInteger(logonType) || clean(logonType),
      logonId: normalizeLogonId(logonId),
      sourceRow: row ? true : false,
    };
  };

  try {
    const selectedEvent = normalizeEvent(selectedRaw, selected);
    if (!selectedEvent) return { selected: null, timeline: [], groups: [], enrichmentChips: [], error: "No selected process" };

    const rowsById = new Map();
    const addRows = (rows) => {
      for (const row of (rows || [])) {
        const rid = Number(row?._rowid || 0);
        if (!rid || rowsById.has(rid)) continue;
        rowsById.set(rid, row);
      }
    };
    if (selectedRaw) addRows([selectedRaw]);

    if (selectedEvent.normHost && selectedEvent.tsMs && columns.hostname && meta.colMap[columns.hostname] && columns.ts && meta.colMap[columns.ts]) {
      const hostSafe = meta.colMap[columns.hostname];
      const tsSafe = meta.colMap[columns.ts];
      const fromIso = new Date(selectedEvent.tsMs - (Math.max(1, Number(windowMinutes) || 5) * 60000)).toISOString();
      const toIso = new Date(selectedEvent.tsMs + (Math.max(1, Number(windowMinutes) || 5) * 60000)).toISOString();
      addRows(runQuery(
        `WHERE norm_host(${hostSafe}) = ? AND sort_datetime(${tsSafe}) >= sort_datetime(?) AND sort_datetime(${tsSafe}) <= sort_datetime(?)`,
        [selectedEvent.normHost, fromIso, toIso],
        maxWindowRows,
        `ORDER BY sort_datetime(${tsSafe}) ASC, data.rowid ASC`
      ));
    }

    if (selectedEvent.normHost && selectedEvent.normUser && selectedEvent.tsMs && columns.hostname && meta.colMap[columns.hostname] && columns.ts && meta.colMap[columns.ts] && columns.user && meta.colMap[columns.user]) {
      const hostSafe = meta.colMap[columns.hostname];
      const tsSafe = meta.colMap[columns.ts];
      const userSafe = meta.colMap[columns.user];
      const fromIso = new Date(selectedEvent.tsMs - (Math.max(1, Number(contextMinutes) || 15) * 60000)).toISOString();
      const toIso = new Date(selectedEvent.tsMs + (Math.max(1, Number(contextMinutes) || 15) * 60000)).toISOString();
      const rawUser = clean(selectedEvent.user || "");
      const baseUser = rawUser.includes("\\") ? rawUser.split("\\").pop() : rawUser;
      const userClauses = [];
      const userParams = [selectedEvent.normHost, fromIso, toIso];
      if (rawUser) {
        userClauses.push(`LOWER(TRIM(CAST(${userSafe} AS TEXT))) = LOWER(?)`);
        userParams.push(rawUser);
      }
      if (baseUser && baseUser.toLowerCase() !== rawUser.toLowerCase()) {
        userClauses.push(`LOWER(TRIM(CAST(${userSafe} AS TEXT))) = LOWER(?)`);
        userParams.push(baseUser);
        userClauses.push(`LOWER(TRIM(CAST(${userSafe} AS TEXT))) LIKE LOWER(?)`);
        userParams.push(`%\\${baseUser}`);
      }
      if (userClauses.length > 0) {
        addRows(runQuery(
          `WHERE norm_host(${hostSafe}) = ? AND sort_datetime(${tsSafe}) >= sort_datetime(?) AND sort_datetime(${tsSafe}) <= sort_datetime(?) AND (${userClauses.join(" OR ")})`,
          userParams,
          maxExactRows,
          `ORDER BY sort_datetime(${tsSafe}) ASC, data.rowid ASC`
        ));
      }
    }

    const pidVariants = selectedEvent.pid ? [selectedEvent.pid, ...hexVariants(selectedEvent.pid)] : [];
    const ppidVariants = selectedEvent.ppid ? [selectedEvent.ppid, ...hexVariants(selectedEvent.ppid)] : [];
    // Host clause uses norm_host UDF — strips UNC prefix and uppercases. Avoids
    // false negatives where one side stores "\\HOST01" and the other "host01".
    const hostClause = selectedEvent.normHost && columns.hostname && meta.colMap[columns.hostname]
      ? ` AND norm_host(${meta.colMap[columns.hostname]}) = ?`
      : "";
    const hostParams = hostClause ? [selectedEvent.normHost] : [];

    if (selectedEvent.guid) {
      if (isEvtxECmd && columns.pid && meta.colMap[columns.pid] && columns.ppid && meta.colMap[columns.ppid]) {
        // Embedded payload — payload string is already brace-free, LIKE on cleaned guid is safe
        addRows(runQuery(
          `WHERE (${meta.colMap[columns.pid]} LIKE ? OR ${meta.colMap[columns.ppid]} LIKE ?)${hostClause}`,
          [`%${selectedEvent.guid}%`, `%${selectedEvent.guid}%`, ...hostParams],
          maxExactRows
        ));
      } else if (isHayabusa && columns.details && meta.colMap[columns.details]) {
        const detailsSafe = meta.colMap[columns.details];
        const extraSafe = columns.extra && meta.colMap[columns.extra] ? meta.colMap[columns.extra] : null;
        addRows(runQuery(
          `WHERE (${detailsSafe} LIKE ?${extraSafe ? ` OR ${extraSafe} LIKE ?` : ""})${hostClause}`,
          extraSafe
            ? [`%${selectedEvent.guid}%`, `%${selectedEvent.guid}%`, ...hostParams]
            : [`%${selectedEvent.guid}%`, ...hostParams],
          maxExactRows
        ));
      } else {
        // Standard columns: norm_guid strips braces / case so Sysmon "{..}" joins Security "..".
        // Previously this used LOWER(TRIM(CAST(...))) which left braces intact and silently dropped events.
        const guidClauses = [];
        const params = [];
        if (columns.guid && meta.colMap[columns.guid]) {
          guidClauses.push(`norm_guid(${meta.colMap[columns.guid]}) = ?`);
          params.push(selectedEvent.guid);
        }
        if (columns.parentGuid && meta.colMap[columns.parentGuid]) {
          guidClauses.push(`norm_guid(${meta.colMap[columns.parentGuid]}) = ?`);
          params.push(selectedEvent.guid);
        }
        if (guidClauses.length > 0) addRows(runQuery(`WHERE (${guidClauses.join(" OR ")})${hostClause}`, [...params, ...hostParams], maxExactRows));
      }
    }

    if ((pidVariants.length > 0 || ppidVariants.length > 0) && (columns.pid || columns.ppid)) {
      if (isEvtxECmd && columns.pid && meta.colMap[columns.pid] && columns.ppid && meta.colMap[columns.ppid]) {
        const pidLikes = [];
        const params = [];
        for (const pv of pidVariants) {
          pidLikes.push(`${meta.colMap[columns.pid]} LIKE ?`);
          params.push(`%ProcessID: ${pv}%`);
          pidLikes.push(`${meta.colMap[columns.ppid]} LIKE ?`);
          params.push(`%ParentProcessID: ${pv}%`);
        }
        for (const pv of ppidVariants) {
          pidLikes.push(`${meta.colMap[columns.pid]} LIKE ?`);
          params.push(`%ProcessID: ${pv}%`);
          pidLikes.push(`${meta.colMap[columns.ppid]} LIKE ?`);
          params.push(`%ParentProcessID: ${pv}%`);
        }
        if (pidLikes.length > 0) addRows(runQuery(`WHERE (${pidLikes.join(" OR ")})${hostClause}`, [...params, ...hostParams], maxExactRows));
      } else if (isHayabusa && columns.details && meta.colMap[columns.details]) {
        const detailsSafe = meta.colMap[columns.details];
        const extraSafe = columns.extra && meta.colMap[columns.extra] ? meta.colMap[columns.extra] : null;
        const pidLikes = [];
        const params = [];
        for (const pv of [...pidVariants, ...ppidVariants]) {
          pidLikes.push(`${detailsSafe} LIKE ?`);
          params.push(`%${pv}%`);
          if (extraSafe) {
            pidLikes.push(`${extraSafe} LIKE ?`);
            params.push(`%${pv}%`);
          }
        }
        if (pidLikes.length > 0) addRows(runQuery(`WHERE (${pidLikes.join(" OR ")})${hostClause}`, [...params, ...hostParams], maxExactRows));
      } else {
        // Standard columns: norm_pid converts hex (Security 4688 "0x1a2c") to decimal so
        // it joins Sysmon's plain integer form. Bind decimal-only values; the UDF normalizes
        // both sides to the same representation.
        const pidClauses = [];
        const params = [];
        const decimalValues = [...new Set([...pidVariants, ...ppidVariants].map(normalizePid).filter(Boolean))];
        const addCanonical = (safeCol) => {
          if (!safeCol || decimalValues.length === 0) return;
          pidClauses.push(`norm_pid(${safeCol}) IN (${decimalValues.map(() => "?").join(",")})`);
          params.push(...decimalValues);
        };
        if (columns.pid && meta.colMap[columns.pid]) addCanonical(meta.colMap[columns.pid]);
        if (columns.ppid && meta.colMap[columns.ppid]) addCanonical(meta.colMap[columns.ppid]);
        if (pidClauses.length > 0) addRows(runQuery(`WHERE (${pidClauses.join(" OR ")})${hostClause}`, [...params, ...hostParams], maxExactRows));
      }
    }

    if (selectedEvent.logonId) {
      if (columns.logonId && meta.colMap[columns.logonId]) {
        // norm_logon_id converts "0x3e7" → "999" so Security 4624 (hex) joins Sysmon (decimal).
        addRows(runQuery(
          `WHERE norm_logon_id(${meta.colMap[columns.logonId]}) = ?${hostClause}`,
          [selectedEvent.logonId, ...hostParams],
          maxExactRows
        ));
      } else if (isHayabusa && columns.details && meta.colMap[columns.details]) {
        const detailsSafe = meta.colMap[columns.details];
        const extraSafe = columns.extra && meta.colMap[columns.extra] ? meta.colMap[columns.extra] : null;
        addRows(runQuery(
          `WHERE (${detailsSafe} LIKE ?${extraSafe ? ` OR ${extraSafe} LIKE ?` : ""})${hostClause}`,
          extraSafe
            ? [`%${selectedEvent.logonId}%`, `%${selectedEvent.logonId}%`, ...hostParams]
            : [`%${selectedEvent.logonId}%`, ...hostParams],
          maxExactRows
        ));
      }
    }

    const events = [...rowsById.values()]
      .map((row) => normalizeEvent(row))
      .filter(Boolean)
      .sort((a, b) => (a.tsMs || Number.MAX_SAFE_INTEGER) - (b.tsMs || Number.MAX_SAFE_INTEGER) || a.rowid - b.rowid);

    const windowMs = Math.max(1, Number(windowMinutes) || 5) * 60000;
    const contextMs = Math.max(1, Number(contextMinutes) || 15) * 60000;
    const selectedHost = selectedEvent.normHost;
    const selectedPid = selectedEvent.pid;
    const selectedPpid = selectedEvent.ppid;
    const selectedGuid = selectedEvent.guid;
    const selectedParentGuid = selectedEvent.parentGuid;
    const selectedUser = selectedEvent.normUser;
    const selectedLogonId = selectedEvent.logonId;

    const relatedEvents = events.filter((evt) => {
      const matchTypes = [];
      if (evt.rowid === selectedEvent.rowid && selectedEvent.rowid) matchTypes.push("selected");
      if (selectedHost && selectedEvent.tsMs && evt.normHost === selectedHost && evt.tsMs && Math.abs(evt.tsMs - selectedEvent.tsMs) <= windowMs) matchTypes.push("hostWindow");
      if (selectedHost && selectedPid && evt.normHost === selectedHost && (evt.pid === selectedPid || evt.ppid === selectedPid)) matchTypes.push("samePid");
      if (selectedHost && selectedPpid && evt.normHost === selectedHost && (evt.pid === selectedPpid || evt.ppid === selectedPpid)) matchTypes.push("samePpid");
      if (selectedGuid && (evt.guid === selectedGuid || evt.parentGuid === selectedGuid)) matchTypes.push("sameGuid");
      if (selectedParentGuid && (evt.guid === selectedParentGuid || evt.parentGuid === selectedParentGuid)) matchTypes.push("sameParentGuid");
      if (selectedHost && selectedUser && evt.normHost === selectedHost && evt.normUser === selectedUser && evt.tsMs && selectedEvent.tsMs && Math.abs(evt.tsMs - selectedEvent.tsMs) <= contextMs) matchTypes.push("sameUser");
      if (selectedLogonId && evt.logonId && evt.logonId === selectedLogonId) matchTypes.push("sameLogon");
      if (evt.enrichmentType && selectedHost && evt.normHost === selectedHost && evt.tsMs && selectedEvent.tsMs && Math.abs(evt.tsMs - selectedEvent.tsMs) <= contextMs) matchTypes.push("enrichment");
      if (evt.telemetryType && selectedHost && evt.normHost === selectedHost && evt.tsMs && selectedEvent.tsMs && Math.abs(evt.tsMs - selectedEvent.tsMs) <= contextMs) matchTypes.push("telemetry");
      if (evt.telemetryType && selectedHost && evt.normHost === selectedHost && selectedEvent.processName && evt.processName && evt.processName.toLowerCase() === selectedEvent.processName.toLowerCase()) matchTypes.push("sameProcessImage");
      evt.matchTypes = [...new Set(matchTypes)];
      evt.isSelected = evt.matchTypes.includes("selected");
      return evt.matchTypes.length > 0;
    });

    const uniqueEvidenceRefs = (refs) => {
      const out = [];
      const seen = new Set();
      for (const ref of refs || []) {
        const rowId = Number(ref?.rowId);
        if (!Number.isInteger(rowId) || rowId <= 0) continue;
        const tabId = ref.tabId || meta.tabId || ctx?.tabId || null;
        const key = `${tabId || ""}:${rowId}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ tabId, rowId });
      }
      return out;
    };

    const buildCrossTelemetry = () => {
      const telemetryEvents = relatedEvents
        .filter((evt) => evt.telemetryType && !evt.isSelected)
        .sort((a, b) => (a.tsMs || Number.MAX_SAFE_INTEGER) - (b.tsMs || Number.MAX_SAFE_INTEGER) || a.rowid - b.rowid);
      const pivots = telemetryEvents.slice(0, 80).map((evt) => {
        const high = evt.matchTypes.includes("sameGuid")
          || evt.matchTypes.includes("sameParentGuid")
          || evt.matchTypes.includes("samePid")
          || evt.matchTypes.includes("samePpid");
        const medium = high
          || evt.matchTypes.includes("sameProcessImage")
          || evt.matchTypes.includes("sameLogon")
          || evt.matchTypes.includes("sameUser");
        const linkage = high ? "same process identity"
          : medium ? "same process/user context"
          : "same host time window";
        const confidence = high ? "high" : medium ? "medium" : "context";
        return {
          id: `${evt.telemetryType}:${evt.rowid}`,
          type: evt.telemetryType,
          label: evt.telemetryLabel || evt.eventLabel || evt.telemetryType,
          summary: evt.telemetrySummary || evt.summary || "",
          timestamp: evt.timestamp || "",
          tsMs: evt.tsMs || 0,
          eventId: evt.eventId || "",
          provider: evt.provider || "",
          rowid: evt.rowid,
          confidence,
          linkage,
          matchTypes: evt.matchTypes.filter((m) => m !== "selected"),
          entities: {
            host: evt.hostname || "",
            user: evt.user || "",
            process: evt.processName || "",
            image: evt.image || "",
            sourceIp: evt.sourceIp || "",
            sourcePort: evt.sourcePort || "",
            destIp: evt.destIp || "",
            destPort: evt.destPort || "",
            domain: evt.queryName || "",
            ruleId: evt.ruleId || "",
            ruleTitle: evt.ruleTitle || "",
            severity: evt.ruleLevel || "",
          },
          evidenceRefs: uniqueEvidenceRefs([evt.evidenceRef]),
        };
      });
      const counts = pivots.reduce((acc, pivot) => {
        acc[pivot.type] = (acc[pivot.type] || 0) + 1;
        return acc;
      }, {});
      const evidenceRefs = uniqueEvidenceRefs([
        selectedEvent.evidenceRef,
        ...pivots.flatMap((pivot) => pivot.evidenceRefs || []),
      ]);
      const processStep = {
        id: "process-anchor",
        type: "process",
        label: selectedEvent.processName || selectedEvent.image || "Selected process",
        summary: selectedEvent.cmdLine || selectedEvent.image || "",
        timestamp: selectedEvent.timestamp || "",
        tsMs: selectedEvent.tsMs || 0,
        rowid: selectedEvent.rowid,
        evidenceRefs: uniqueEvidenceRefs([selectedEvent.evidenceRef]),
      };
      const chain = [processStep, ...pivots]
        .filter((item) => item.type === "process" || item.confidence !== "context" || pivots.length <= 12)
        .sort((a, b) => (a.tsMs || Number.MAX_SAFE_INTEGER) - (b.tsMs || Number.MAX_SAFE_INTEGER) || (a.rowid || 0) - (b.rowid || 0))
        .slice(0, 40);
      return {
        pivots,
        chain,
        evidenceRefs,
        counts,
        stats: {
          total: pivots.length,
          highConfidence: pivots.filter((p) => p.confidence === "high").length,
          mediumConfidence: pivots.filter((p) => p.confidence === "medium").length,
          contextOnly: pivots.filter((p) => p.confidence === "context").length,
          evidenceRows: evidenceRefs.length,
        },
      };
    };

    const crossTelemetry = buildCrossTelemetry();

    const groupDefs = [
      {
        id: "hostWindow",
        label: `Same host +/-${Math.max(1, Number(windowMinutes) || 5)}m`,
        test: (evt) => evt.matchTypes.includes("hostWindow") && !evt.isSelected,
      },
      {
        id: "pidGuid",
        label: "Same PID / PPID / GUID",
        test: (evt) => !evt.isSelected && (
          evt.matchTypes.includes("samePid")
          || evt.matchTypes.includes("samePpid")
          || evt.matchTypes.includes("sameGuid")
          || evt.matchTypes.includes("sameParentGuid")
        ),
      },
      {
        id: "userLogon",
        label: "Same user / logon context",
        test: (evt) => !evt.isSelected && (evt.matchTypes.includes("sameUser") || evt.matchTypes.includes("sameLogon")),
      },
      {
        id: "telemetry",
        label: "Cross telemetry pivots",
        test: (evt) => !evt.isSelected && evt.matchTypes.includes("telemetry"),
      },
    ];

    const groups = groupDefs.map((group) => {
      const matches = relatedEvents.filter(group.test);
      return {
        id: group.id,
        label: group.label,
        count: matches.length,
        rows: matches.slice(0, 12),
      };
    }).filter((group) => group.count > 0);

    const enrichmentCounts = new Map();
    for (const evt of relatedEvents) {
      if (!evt.enrichmentType || evt.isSelected) continue;
      const key = evt.enrichmentType;
      const cur = enrichmentCounts.get(key) || { id: key, label: evt.eventLabel, count: 0 };
      cur.count += 1;
      if (
        key === "service"
        || key === "task"
        || key === "powershell"
        || key === "logon"
        || key === "terminate"
      ) cur.label = {
        powershell: "4104",
        service: "7045 / 4697",
        task: "4698 / 4702",
        logon: "4624 / 4648 / 4672",
        terminate: "4689 / Sysmon 5",
      }[key];
      enrichmentCounts.set(key, cur);
    }

    const timeline = relatedEvents
      .sort((a, b) => (a.tsMs || Number.MAX_SAFE_INTEGER) - (b.tsMs || Number.MAX_SAFE_INTEGER) || a.rowid - b.rowid)
      .slice(0, Math.max(10, Math.min(Number(maxTimelineRows) || 120, 300)));

    return {
      selected: selectedEvent,
      timeline,
      groups,
      enrichmentChips: [...enrichmentCounts.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label)),
      crossTelemetry,
      stats: {
        totalRelated: relatedEvents.filter((evt) => !evt.isSelected).length,
        timelineCount: timeline.length,
        crossTelemetry: crossTelemetry.stats,
      },
      columns: {
        hostname: columns.hostname || null,
        ts: columns.ts || null,
        eventId: columns.eventId || null,
        provider: columns.provider || null,
      },
    };
  } catch (e) {
    return { selected: null, timeline: [], groups: [], enrichmentChips: [], error: e.message };
  }
}

module.exports = { getProcessTree, previewProcessTree, getProcessInspectorContext };
