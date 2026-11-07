const { dbg } = require("../logger");
const { parseTimestampMs } = require("../utils/parse-timestamp");

/**
 * USN Journal Analysis — run targeted forensic queries on $J data within a time window.
 * Covers: renames, deletions, file creation, exfil staging, execution artifacts,
 * persistence paths, and suspicious paths.
 */
function analyzeUsnJournal(meta, { startTime, endTime, analyses, pathFilter, mftTabId }, getDatabaseMeta) {
    const empty = {
      summary: { totalEvents: 0, startTime, endTime, pathFilter: null },
      renames: null, deletions: null, creations: null, exfil: null,
      execution: null, persistence: null, suspiciousPaths: null, securityChanges: null,
      dataOverwrite: null, streamChanges: null, closePatterns: null,
      timeline: [], fileChains: [], directoryIncidents: [], likelyFindings: [], narrative: [], fileReuse: [], masquerade: [], selfDeleted: [], motwStripped: [],
    };
    if (!meta) return empty;

    const db = meta.db;
    const col = (name) => meta.colMap[name];
    const nameCol = col("Name"), extCol = col("Extension"), entryCol = col("EntryNumber");
    const seqCol = col("SequenceNumber");
    const parentPathCol = col("ParentPath"), tsCol = col("UpdateTimestamp");
    const reasonCol = col("UpdateReasons"), attrsCol = col("FileAttributes");
    const usnCol = col("UpdateSequenceNumber");
    const sourceInfoCol = col("SourceInfo");

    if (!nameCol || !tsCol || !reasonCol)
      return { ...empty, error: "Required USN Journal columns not found (Name, UpdateTimestamp, UpdateReasons)." };

    // ── Journal span over the WHOLE tab (independent of the analysis window) ──
    // Drives the coverage/integrity header AND lets startTime DEFAULT to the journal start, so an
    // analyst can run a full-journal pass and SEE where activity is rather than having to already
    // know the incident time. Uses the sort_datetime expression index when present.
    const journalSpan = { start: "", end: "", total: 0, usnMin: null, usnMax: null };
    try {
      const span = db.prepare(
        `SELECT (SELECT ${tsCol} FROM data WHERE ${tsCol} IS NOT NULL AND ${tsCol} != '' ORDER BY sort_datetime(${tsCol}) ASC, rowid LIMIT 1) AS jstart,
                (SELECT ${tsCol} FROM data WHERE ${tsCol} IS NOT NULL AND ${tsCol} != '' ORDER BY sort_datetime(${tsCol}) DESC, rowid LIMIT 1) AS jend,
                COUNT(*) AS jtotal FROM data`
      ).get();
      journalSpan.start = span?.jstart || "";
      journalSpan.end = span?.jend || "";
      journalSpan.total = span?.jtotal || 0;
      if (usnCol) {
        const u = db.prepare(`SELECT MIN(CAST(${usnCol} AS INTEGER)) AS lo, MAX(CAST(${usnCol} AS INTEGER)) AS hi FROM data WHERE ${usnCol} IS NOT NULL AND ${usnCol} != ''`).get();
        journalSpan.usnMin = u?.lo ?? null;
        journalSpan.usnMax = u?.hi ?? null;
      }
    } catch (e) { /* best-effort; coverage degrades gracefully */ }

    // startTime is now OPTIONAL — default to the journal start (full-journal analysis).
    const effectiveStart = startTime || journalSpan.start;
    if (!effectiveStart)
      return { ...empty, error: "USN Journal contains no timestamped records to analyze." };

    // End time is optional — if omitted, use a far-future value
    // Pad end time with .9999999 if no sub-seconds provided, so BETWEEN includes the full second
    let effectiveEnd = endTime || "9999-12-31 23:59:59";
    if (effectiveEnd && !effectiveEnd.includes(".")) effectiveEnd += ".9999999";

    const timeFilter = `sort_datetime(${tsCol}) BETWEEN sort_datetime(?) AND sort_datetime(?)`;

    // Normalize path filter: collapse user-typed double backslashes (e.g.
    // C:\\Users\\Admin) to single. Preserve the leading `\\` of UNC paths
    // (e.g. \\server\share) so they aren't mangled into `\server\share`.
    const normPath = pathFilter
      ? (pathFilter.startsWith("\\\\")
          ? "\\\\" + pathFilter.slice(2).replace(/\\\\/g, "\\")
          : pathFilter.replace(/\\\\/g, "\\"))
      : null;
    const pathLike = normPath ? `AND ${parentPathCol} LIKE ?` : "";
    const baseParams = normPath ? [effectiveStart, effectiveEnd, `%${normPath}%`] : [effectiveStart, effectiveEnd];
    const notDir = attrsCol ? `AND (${attrsCol} IS NULL OR ${attrsCol} NOT LIKE '%Directory%')` : "";
    const REASON_LABELS = {
      rename: "Rename",
      create: "Create",
      delete: "Delete",
      overwrite: "Overwrite",
      "acl-change": "ACL change",
      "stream-change": "ADS/stream change",
      close: "Close",
      metadata: "Metadata change",
      persistence: "Persistence path",
      execution: "Executable/script activity",
      exfil: "Archive staging",
      suspicious: "Suspicious path",
    };
    const EXEC_EXTS = new Set([".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".scr", ".com", ".msi", ".msp", ".cpl", ".sys"]);
    const SHORTCUT_EXTS = new Set([".lnk", ".url"]);
    const EXT_RISK = new Set([...EXEC_EXTS, ...SHORTCUT_EXTS, ".iso", ".img", ".zip", ".rar", ".7z", ".jar", ".reg"]);
    const ARCHIVE_EXTS = new Set([".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".bz2", ".iso", ".img"]);
    const LOW_SIGNAL_EXTS = new Set([".tmp", ".log", ".etl", ".pf", ".db", ".dat", ".evtx", ".blf", ".regtrans-ms", ".chk", ".cat", ".mum", ".manifest", ".mui", ".pnf", ".idx", ".map"]);
    const EZ_TOOL_NORMALIZED_NAMES = new Set([
      "amcacheparser",
      "appcompatcacheparser",
      "bstrings",
      "evtxecmd",
      "ezviewer",
      "getzimmermantools",
      "hasher",
      "iisgeolocate",
      "jlecmd",
      "jumplistexplorer",
      "kape",
      "lecmd",
      "mftecmd",
      "mftexplorer",
      "pecmd",
      "rbcmd",
      "recentfilecacheparser",
      "recmd",
      "registryexplorer",
      "rla",
      "sbecmd",
      "sdbexplorer",
      "shellbagsexplorer",
      "sqlecmd",
      "srumecmd",
      "sumecmd",
      "timeapp",
      "timelineexplorer",
      "vscmount",
      "wxtcmd",
      "xwfim",
    ]);
    const CORTEX_ENDPOINT_NORMALIZED_NAMES = new Set([
      "cortexxdr",
      "cortexxdrhealthhelper",
      "cymemdef",
      "cyopticsruntimedriver",
      "cyprotectdrv",
      "cyverak",
      "cyvrfsfd",
      "cyvrmtgn",
      "pangps",
      "panupdater",
      "tdevflt",
      "tedrdrv",
      "telam",
      "trapssupervisor",
      "xdrcollector",
    ]);
    const OFFLINE_COLLECTOR_SCRIPT_NAMES = new Set([
      "amcache",
      "amcacheparser",
      "anydeskconnectionparser",
      "anydesktraceparser",
      "applicationresourceusage",
      "arpcache",
      "arpcachedef",
      "bamparser",
      "bcfparser",
      "cidsizemruparser",
      "comdlgreg",
      "commonlib",
      "customjumplistparser",
      "dnscache",
      "dnsdef",
      "driversparser",
      "esedbtable",
      "fileretrieval",
      "fileutilswin",
      "filterutil",
      "forensicparser",
      "forensicsearch",
      "handles",
      "hosts",
      "jumplistappids",
      "jumplistparser",
      "knownfolders",
      "knownipinterface",
      "lastvisitedpidmruparser",
      "lnkparser",
      "logmeinparser",
      "netsessions",
      "networkconnectivitydataparser",
      "networkdatausageparser",
      "opensavepidmruparser",
      "parserutils",
      "pathresolver",
      "pathlibimproved",
      "portlisting",
      "prefetch",
      "prefetchhash",
      "prefetchparser",
      "processlisting",
      "psreadline",
      "recentfilesparser",
      "recyclebinparser",
      "regscanner",
      "registry",
      "registrypersistenceparser",
      "reglib",
      "resultset",
      "scheduledtasksparser",
      "services",
      "servicesparser",
      "sevenzipfolderhistory",
      "shellbags",
      "shellbagsbinaryparser",
      "shellbagsparser",
      "shellbagsutils",
      "shellitems",
      "shimdatabasesparser",
      "shimcacheparser",
      "srumdbparser",
      "startupfolderparser",
      "teamviewerparser",
      "triage",
      "typedpathsparser",
      "useraccesslogging",
      "userassistparser",
      "windowstimelineparser",
      "winrararchistory",
      "wmiparser",
      "wordwheelqueryparser",
    ]);
    const SUSP_PATH_PAT = /(\\temp\\|\\tmp\\|\\appdata\\local\\temp\\|\\users\\public\\|\\programdata\\|\\music\\|\\pictures\\|\\videos\\|\$recycle\.bin)/i;
    const STARTUP_PATH_PAT = /\\(?:programdata\\microsoft\\windows\\start menu\\programs\\startup|users\\[^\\]+\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup)(?:\\|$)/i;
    const SCHEDULED_TASK_PATH_PAT = /\\windows\\system32\\tasks(?:\\|$)/i;
    const LEGACY_TASK_PATH_PAT = /\\windows\\tasks(?:\\|$)/i;
    const GPO_SCRIPT_PATH_PAT = /\\windows\\system32\\grouppolicy\\(?:machine|user)\\scripts\\(?:startup|shutdown|logon|logoff)(?:\\|$)/i;
    const WMI_MOF_PATH_PAT = /\\windows\\(?:system32|syswow64)\\wbem\\(?:mof|autorecover)(?:\\|$)/i;
    const TEMP_PATH_PAT = /\\(?:windows\\temp|temp|tmp|appdata\\local\\temp)(?:\\|$)/i;
    const PUBLIC_PATH_PAT = /\\users\\public(?:\\|$)/i;
    const PROGRAMDATA_PATH_PAT = /\\programdata(?:\\|$)/i;
    const RECYCLE_BIN_PATH_PAT = /\\\$recycle\.bin(?:\\|$)/i;
    const MEDIA_PATH_PAT = /\\users\\[^\\]+\\(?:music|pictures|videos)(?:\\|$)/i;
    const RECOVERY_PATH_PAT = /\\(?:recovery|perflogs)(?:\\|$)/i;
    const CORTEX_ENDPOINT_PATH_PAT = /\\(?:program files(?: \(x86\))?\\(?:palo alto networks|cortex xdr)|programdata\\(?:palo alto networks|cortex(?: xdr)?))(?:\\|$)/i;
    const OFFLINE_COLLECTOR_PATH_PAT = /\\(?:u42-?offline triage(?:_x64)?(?: \d+)?|offline triage(?:_x64)?(?: \d+)?|offline[_ -]?collector|xdr[_ -]?collector)(?:\\scripts)?(?:\\|$)/i;
    const DESTRUCTIVE_REASON_BUCKETS = new Set(["overwrite", "rename", "delete", "acl-change", "stream-change"]);
    const BENIGN_NOISE_RULES = [
      { label: "Defender", pattern: /\\programdata\\microsoft\\(?:windows defender|windows defender advanced threat protection|microsoft defender|windows security health)/i },
      { label: "Windows Update", pattern: /\\(?:programdata\\uso(?:shared|private)|windows\\softwaredistribution|windows\\winsxs|windows\\servicing|windows\\installer|programdata\\package cache)/i },
      { label: "OneDrive", pattern: /\\(?:programdata\\microsoft\\onedrive|users\\[^\\]+\\appdata\\local\\microsoft\\onedrive)/i },
      { label: "Office temp", pattern: /\\(?:appdata\\local\\temp\\content\.mso|appdata\\local\\microsoft\\office\\|appdata\\local\\microsoft\\windows\\inetcache\\content\.outlook)/i },
      { label: "Browser cache/update", pattern: /\\(?:users\\[^\\]+\\appdata\\local\\google\\(?:chrome\\user data\\.*\\(?:cache|code cache)|update)|users\\[^\\]+\\appdata\\local\\microsoft\\(?:edge\\user data\\.*\\(?:cache|code cache)|edgeupdate)|users\\[^\\]+\\appdata\\local\\mozilla\\firefox\\profiles\\.*\\(?:cache2?|startupcache))/i },
      { label: "Software deployment", pattern: /\\(?:windows\\ccm(?:cache)?|windows\\imecache|programdata\\microsoft\\intunemanagementextension|programdata\\(?:qualys|tenable|tanium|rapid7|bigfix|flexera|pdq deploy))/i },
    ];
    const BENIGN_TASK_RULES = [
      { label: "Windows built-in task", pattern: /\\windows\\system32\\tasks\\microsoft\\windows\\(?:defrag|diagnosis|diskcleanup|windowsupdate|updateorchestrator|wdi|defender|softwareprotectionplatform|time synchronization|filehistory|chkdsk|maps|pushToInstall|servicing|remediation|rempl|customer experience improvement program|subscription|memorydiagnostic|bitlocker|speech|printing)(?:\\|$)/i },
      { label: "Vendor updater task", pattern: /\\windows\\system32\\tasks\\(?:google|microsoftedgeupdate|adobe|onedrive|zoom|teams|office|citrix|vmware|slack|okta|qualys|tenable|rapid7|tanium|bigfix)(?:\\|$)/i },
    ];
    const TRUST_TIER_META = {
      system: { label: "System", dampening: 5 },
      "program-files": { label: "Program Files", dampening: 4 },
      "enterprise-management": { label: "Enterprise management", dampening: 4 },
      "browser-cache-update": { label: "Browser cache/update", dampening: 5 },
      "office-outlook": { label: "Office/Outlook", dampening: 5 },
      "onedrive-defender-update": { label: "OneDrive/Defender/Update", dampening: 6 },
      "security-tooling": { label: "Security tooling", dampening: 8, allowlist: true },
      "dfir-tooling": { label: "DFIR tooling", dampening: 8, allowlist: true },
    };
    const TWO_SIGNAL_EVENT_CATEGORIES = new Set(["execution", "exfil", "securityChanges", "closePatterns"]);
    const TWO_SIGNAL_REASON_BUCKETS = new Set(["execution", "exfil", "acl-change", "close"]);
    const TWO_SIGNAL_LOCATION_TAGS = new Set(["public-drop", "programdata-drop", "media-folder-payload"]);
    const OUTLIER_TAGS = new Set(["rare-directory", "rare-extension", "rare-reason-mix", "local-burst"]);
    const STRONG_MFT_TAGS = new Set(["downloaded", "timestomp", "deleted-in-mft"]);
    const STRONG_PATH_TAGS = new Set(["startup-folder", "scheduled-task", "gpo-script", "wmi-persistence", "temp-executable", "temp-archive", "temp-tampering", "public-drop", "programdata-drop", "recycle-bin-artifact", "media-folder-payload", "recovery-artifact"]);
    // Existing callers rely on NaN (not null) for unparseable values so
    // arithmetic comparisons short-circuit. Wrap canonical parser to preserve
    // that contract while gaining UTC correctness on naive timestamps.
    const parseTs = (v) => {
      const ms = parseTimestampMs(v);
      return ms == null ? NaN : ms;
    };
    const joinPath = (dir, name) => {
      if (!name) return dir || "";
      if (!dir) return name;
      return dir.endsWith("\\") ? `${dir}${name}` : `${dir}\\${name}`;
    };
    const deriveExtension = (name, extension) => {
      const ext = String(extension || "").trim().toLowerCase();
      if (ext) return ext.startsWith(".") ? ext : `.${ext}`;
      const fileName = String(name || "");
      const idx = fileName.lastIndexOf(".");
      return idx > 0 ? fileName.slice(idx).toLowerCase() : "";
    };
    const normalizeArtifactNameToken = (name) => {
      const fileName = String(name || "").split(/[\\/]/).pop() || "";
      const stem = fileName.replace(/\.[^.]+$/, "");
      return stem.toLowerCase().replace(/[^a-z0-9]+/g, "");
    };
    const classifyTrustedUsnArtifact = ({ name = "", parentPath = "", fullPath = "", extension = "" } = {}) => {
      const candidatePath = String(fullPath || joinPath(parentPath, name) || "");
      const pathLower = candidatePath.toLowerCase();
      const ext = deriveExtension(name || candidatePath.split(/[\\/]/).pop() || "", extension);
      const token = normalizeArtifactNameToken(name || candidatePath);
      const binaryLike = EXEC_EXTS.has(ext) || ARCHIVE_EXTS.has(ext);

      if (token && binaryLike && EZ_TOOL_NORMALIZED_NAMES.has(token)) {
        return {
          key: "dfir-tooling",
          label: "EZTools",
          suppressionReason: "EZTools forensic binary",
        };
      }

      if (token && ext === ".py" && OFFLINE_COLLECTOR_SCRIPT_NAMES.has(token) && OFFLINE_COLLECTOR_PATH_PAT.test(pathLower)) {
        return {
          key: "dfir-tooling",
          label: "Cortex XDR offline collector",
          suppressionReason: "Cortex XDR offline collector script",
        };
      }

      if ((EXEC_EXTS.has(ext) || token === "xdrcollector")
        && (CORTEX_ENDPOINT_PATH_PAT.test(pathLower) || CORTEX_ENDPOINT_NORMALIZED_NAMES.has(token))) {
        return {
          key: "security-tooling",
          label: "Palo Alto Cortex XDR",
          suppressionReason: "Palo Alto / Cortex XDR endpoint binary",
        };
      }

      return null;
    };
    const normalizeUsnReasons = (reasonStr, sectionKey) => {
      const s = String(reasonStr || "");
      const out = [];
      if (/RenameOldName|RenameNewName/i.test(s)) out.push("rename");
      if (/FileCreate/i.test(s)) out.push("create");
      if (/FileDelete/i.test(s)) out.push("delete");
      if (/DataOverwrite|DataExtend|DataTruncation/i.test(s)) out.push("overwrite");
      if (/SecurityChange/i.test(s)) out.push("acl-change");
      if (/StreamChange/i.test(s)) out.push("stream-change");
      if (/BasicInfoChange|FileNameChange|EAChange/i.test(s)) out.push("metadata");
      if (/^Close$/i.test(s) || (!out.length && /Close/i.test(s))) out.push("close");
      if (sectionKey === "persistence") out.push("persistence");
      if (sectionKey === "execution") out.push("execution");
      if (sectionKey === "exfil") out.push("exfil");
      if (sectionKey === "suspiciousPaths") out.push("suspicious");
      return [...new Set(out)];
    };
    const hasInterestingReasons = (reasonBuckets) => (reasonBuckets || []).some((bucket) => DESTRUCTIVE_REASON_BUCKETS.has(bucket));
    const matchRuleLabel = (rules, value) => {
      const candidate = String(value || "");
      for (const rule of rules) {
        if (rule.pattern.test(candidate)) return rule.label;
      }
      return "";
    };
    const summarizeUsnSuppressions = (rows) => {
      const counts = {};
      for (const row of rows || []) {
        const label = row?.suppressionReason || "Other benign churn";
        counts[label] = (counts[label] || 0) + 1;
      }
      return Object.entries(counts)
        .map(([label, count]) => ({ label, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 6);
    };
    const classifyPersistenceRow = (row) => {
      const parentPath = String(row?.parentPath || "");
      const fullPath = joinPath(parentPath, row?.name || "");
      const parentLower = parentPath.toLowerCase();
      const fullLower = fullPath.toLowerCase();
      const name = String(row?.name || "");
      const nameLower = name.toLowerCase();
      const extension = deriveExtension(name, row?.extension);
      const reasonBuckets = normalizeUsnReasons(row?.reasons, "persistence");
      const interestingReasons = hasInterestingReasons(reasonBuckets);
      let category = "";
      let tags = [];
      let heuristicRisk = 0;
      let suppressionReason = "";
      const trustedArtifact = classifyTrustedUsnArtifact({ name, parentPath, fullPath, extension });

      if (trustedArtifact) return { include: false, suppressionReason: trustedArtifact.suppressionReason };

      if (STARTUP_PATH_PAT.test(parentLower)) {
        category = "Startup Folder";
        tags = ["startup-folder"];
        heuristicRisk = 4;
        if (!(EXEC_EXTS.has(extension) || SHORTCUT_EXTS.has(extension) || !extension)) {
          suppressionReason = "Non-startup artifact in Startup folder";
        }
      } else if (SCHEDULED_TASK_PATH_PAT.test(parentLower)) {
        category = "Scheduled Task";
        tags = ["scheduled-task"];
        heuristicRisk = 4;
        const taskRule = matchRuleLabel(BENIGN_TASK_RULES, fullLower);
        if (taskRule && !interestingReasons) suppressionReason = taskRule;
      } else if (LEGACY_TASK_PATH_PAT.test(parentLower)) {
        category = "Legacy Task File";
        tags = ["scheduled-task"];
        heuristicRisk = 3;
        if (extension && extension !== ".job" && !EXEC_EXTS.has(extension) && !SHORTCUT_EXTS.has(extension)) {
          suppressionReason = "Non-task artifact in legacy task path";
        }
      } else if (GPO_SCRIPT_PATH_PAT.test(parentLower)) {
        category = "Group Policy Script";
        tags = ["gpo-script"];
        heuristicRisk = 4;
        if (extension && ![".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf"].includes(extension)) {
          suppressionReason = "Non-script artifact in GPO script path";
        }
      } else if (WMI_MOF_PATH_PAT.test(parentLower)) {
        category = "WMI MOF";
        tags = ["wmi-persistence"];
        heuristicRisk = 4;
        if (![".mof", ".mfl", ".bmf"].includes(extension) && !EXEC_EXTS.has(extension) && !interestingReasons) {
          suppressionReason = "Low-signal WMI file churn";
        }
      } else {
        return { include: false, suppressionReason: "Outside persistence scope" };
      }

      if (!suppressionReason && /^(desktop\.ini|thumbs\.db)$/i.test(nameLower)) suppressionReason = "Shell metadata";
      if (!suppressionReason && LOW_SIGNAL_EXTS.has(extension) && !interestingReasons) suppressionReason = "Low-signal file type";
      if (!suppressionReason) {
        const benignRule = matchRuleLabel(BENIGN_NOISE_RULES, fullLower);
        if (benignRule && !EXEC_EXTS.has(extension) && !SHORTCUT_EXTS.has(extension) && !interestingReasons) suppressionReason = benignRule;
      }

      return {
        include: !suppressionReason,
        suppressionReason,
        category,
        tags,
        heuristicRisk,
      };
    };
    const classifySuspiciousPathRow = (row) => {
      const parentPath = String(row?.parentPath || "");
      const fullPath = joinPath(parentPath, row?.name || "");
      const parentLower = parentPath.toLowerCase();
      const fullLower = fullPath.toLowerCase();
      const name = String(row?.name || "");
      const nameLower = name.toLowerCase();
      const extension = deriveExtension(name, row?.extension);
      const reasonBuckets = normalizeUsnReasons(row?.reasons, "suspiciousPaths");
      const interestingReasons = hasInterestingReasons(reasonBuckets);
      const payloadLike = EXEC_EXTS.has(extension) || SHORTCUT_EXTS.has(extension);
      const archiveLike = ARCHIVE_EXTS.has(extension);
      let category = "";
      let tags = [];
      let heuristicRisk = 0;
      let suppressionReason = "";
      const trustedArtifact = classifyTrustedUsnArtifact({ name, parentPath, fullPath, extension });

      if (trustedArtifact) return { include: false, suppressionReason: trustedArtifact.suppressionReason };

      if (STARTUP_PATH_PAT.test(parentLower) || SCHEDULED_TASK_PATH_PAT.test(parentLower) || LEGACY_TASK_PATH_PAT.test(parentLower) || GPO_SCRIPT_PATH_PAT.test(parentLower) || WMI_MOF_PATH_PAT.test(parentLower)) {
        return { include: false, suppressionReason: "Covered by persistence paths" };
      }
      if (TEMP_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || interestingReasons)) return { include: false, suppressionReason: "Routine temp churn" };
        category = payloadLike ? "Temp Payload" : archiveLike ? "Temp Archive" : "Temp Tampering";
        tags = [payloadLike ? "temp-executable" : archiveLike ? "temp-archive" : "temp-tampering"];
        heuristicRisk = payloadLike ? 4 : archiveLike ? 3 : 2;
      } else if (PUBLIC_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || interestingReasons)) return { include: false, suppressionReason: "Routine Public folder churn" };
        category = payloadLike || SHORTCUT_EXTS.has(extension) ? "Public Path Payload" : archiveLike ? "Public Archive" : "Public Path Tampering";
        tags = ["public-drop"];
        heuristicRisk = payloadLike || SHORTCUT_EXTS.has(extension) ? 4 : 3;
      } else if (RECYCLE_BIN_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || interestingReasons)) return { include: false, suppressionReason: "Routine Recycle Bin churn" };
        category = "Recycle Bin Artifact";
        tags = ["recycle-bin-artifact"];
        heuristicRisk = 4;
      } else if (PROGRAMDATA_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || interestingReasons)) return { include: false, suppressionReason: "Routine ProgramData churn" };
        category = payloadLike || SHORTCUT_EXTS.has(extension) ? "ProgramData Payload" : archiveLike ? "ProgramData Archive" : "ProgramData Tampering";
        tags = ["programdata-drop"];
        heuristicRisk = payloadLike || SHORTCUT_EXTS.has(extension) ? 3 : 2;
      } else if (RECOVERY_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || interestingReasons)) return { include: false, suppressionReason: "System recovery/log churn" };
        category = "Recovery/PerfLogs Artifact";
        tags = ["recovery-artifact"];
        heuristicRisk = 3;
      } else if (MEDIA_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || SHORTCUT_EXTS.has(extension))) return { include: false, suppressionReason: "Regular media file activity" };
        category = "Media Folder Payload";
        tags = ["media-folder-payload"];
        heuristicRisk = 4;
      } else {
        return { include: false, suppressionReason: "Outside suspicious path scope" };
      }

      if (!suppressionReason && /^(desktop\.ini|thumbs\.db)$/i.test(nameLower)) suppressionReason = "Shell metadata";
      if (!suppressionReason && LOW_SIGNAL_EXTS.has(extension) && !interestingReasons && !payloadLike && !archiveLike) suppressionReason = "Low-signal file type";
      if (!suppressionReason) {
        const benignRule = matchRuleLabel(BENIGN_NOISE_RULES, fullLower);
        if (benignRule && !payloadLike && !interestingReasons) suppressionReason = benignRule;
      }

      return {
        include: !suppressionReason,
        suppressionReason,
        category,
        tags,
        heuristicRisk,
      };
    };
    const classifyTrustTier = (fullPath, parentPath) => {
      const trustedArtifact = classifyTrustedUsnArtifact({
        name: String(fullPath || "").split(/[\\/]/).pop() || "",
        parentPath,
        fullPath,
      });
      if (trustedArtifact && TRUST_TIER_META[trustedArtifact.key]) {
        return { key: trustedArtifact.key, ...TRUST_TIER_META[trustedArtifact.key] };
      }
      const candidate = String(fullPath || parentPath || "").toLowerCase();
      if (!candidate) return { key: "", label: "", dampening: 0 };
      const benignLabel = matchRuleLabel(BENIGN_NOISE_RULES, candidate);
      if (benignLabel === "Software deployment") return { key: "enterprise-management", ...TRUST_TIER_META["enterprise-management"] };
      if (benignLabel === "Browser cache/update") return { key: "browser-cache-update", ...TRUST_TIER_META["browser-cache-update"] };
      if (benignLabel === "Office temp") return { key: "office-outlook", ...TRUST_TIER_META["office-outlook"] };
      if (benignLabel === "OneDrive" || benignLabel === "Defender" || benignLabel === "Windows Update") {
        return { key: "onedrive-defender-update", ...TRUST_TIER_META["onedrive-defender-update"] };
      }
      if (/\\program files(?: \(x86\))?(?:\\|$)/i.test(candidate)) return { key: "program-files", ...TRUST_TIER_META["program-files"] };
      if (/\\windows\\(?:system32|syswow64|systemapps|systemresources|inf|fonts)(?:\\|$)/i.test(candidate)) return { key: "system", ...TRUST_TIER_META.system };
      return { key: "", label: "", dampening: 0 };
    };
    const primaryReasonBucket = (buckets) => {
      const order = ["acl-change", "overwrite", "stream-change", "rename", "delete", "create", "persistence", "execution", "exfil", "suspicious", "metadata", "close"];
      return order.find((k) => buckets.includes(k)) || (buckets[0] || "metadata");
    };
    const scoreUsnObservedEvent = (ev) => {
      let score = 0;
      if (ev.reasonBuckets.includes("acl-change")) score += 4;
      if (ev.reasonBuckets.includes("overwrite")) score += 4;
      if (ev.reasonBuckets.includes("stream-change")) score += 3;
      if (ev.reasonBuckets.includes("rename")) score += 2;
      if (ev.reasonBuckets.includes("delete")) score += 2;
      if (ev.reasonBuckets.includes("create")) score += 2;
      if (ev.category === "persistence") score += 3;
      if (ev.category === "execution") score += 3;
      if (ev.category === "exfil") score += 3;
      if (ev.category === "suspiciousPaths") score += 1;
      if (EXT_RISK.has((ev.extension || "").toLowerCase())) score += 2;
      if ((ev.heuristicRisk || 0) >= 4) score += 3;
      else if ((ev.heuristicRisk || 0) >= 2) score += 2;
      else if (SUSP_PATH_PAT.test(ev.parentPath || "")) score += 1;
      if (ev.tags?.includes("downloaded")) score += 2;
      if (ev.tags?.includes("timestomp")) score += 2;
      if (ev.tags?.includes("deleted-in-mft")) score += 2;
      if (ev.tags?.includes("persistence-related")) score += 3;
      if (ev.tags?.includes("executable-or-script")) score += 2;
      if (ev.tags?.includes("archive-staging")) score += 2;
      if (ev.tags?.includes("startup-folder")) score += 3;
      if (ev.tags?.includes("scheduled-task")) score += 3;
      if (ev.tags?.includes("gpo-script")) score += 3;
      if (ev.tags?.includes("wmi-persistence")) score += 3;
      if (ev.tags?.includes("temp-executable")) score += 3;
      if (ev.tags?.includes("public-drop")) score += 2;
      if (ev.tags?.includes("programdata-drop")) score += 2;
      if (ev.tags?.includes("recycle-bin-artifact")) score += 2;
      if (ev.tags?.includes("media-folder-payload")) score += 2;
      if (ev.tags?.includes("recovery-artifact")) score += 2;
      return score;
    };
    const eventNeedsTwoSignals = (ev) => {
      const tags = new Set(ev.tags || []);
      return TWO_SIGNAL_EVENT_CATEGORIES.has(ev.category) || [...TWO_SIGNAL_LOCATION_TAGS].some((tag) => tags.has(tag));
    };
    const deriveEventPromotionSignals = (ev) => {
      const tags = new Set(ev.tags || []);
      const reasons = new Set(ev.reasonBuckets || []);
      const out = new Set();
      const extension = (ev.extension || "").toLowerCase();
      const parentLower = String(ev.parentPath || "").toLowerCase();

      if (tags.has("downloaded")) out.add("downloaded");
      if (tags.has("timestomp")) out.add("timestomp");
      if (tags.has("deleted-in-mft")) out.add("deleted");
      if ([...OUTLIER_TAGS].some((tag) => tags.has(tag))) out.add("outlier");
      if ([...DESTRUCTIVE_REASON_BUCKETS].some((bucket) => reasons.has(bucket))) out.add("destructive");
      if ((ev.reasonBuckets || []).length >= 2) out.add("multi-reason");
      if ([...STRONG_PATH_TAGS].some((tag) => tags.has(tag))) out.add("risky-location");
      if (STARTUP_PATH_PAT.test(parentLower) || SCHEDULED_TASK_PATH_PAT.test(parentLower) || LEGACY_TASK_PATH_PAT.test(parentLower) || GPO_SCRIPT_PATH_PAT.test(parentLower) || WMI_MOF_PATH_PAT.test(parentLower)) out.add("persistence-path");
      if (TEMP_PATH_PAT.test(parentLower) || PUBLIC_PATH_PAT.test(parentLower) || PROGRAMDATA_PATH_PAT.test(parentLower) || RECYCLE_BIN_PATH_PAT.test(parentLower) || MEDIA_PATH_PAT.test(parentLower) || RECOVERY_PATH_PAT.test(parentLower)) out.add("risky-path");
      if ((EXEC_EXTS.has(extension) || SHORTCUT_EXTS.has(extension)) && ev.category !== "execution") out.add("payload-ext");
      if (ARCHIVE_EXTS.has(extension) && ev.category !== "exfil") out.add("archive-ext");
      if ((ev.heuristicRisk || 0) >= 4) out.add("high-risk-heuristic");
      return [...out];
    };
    const evaluateUsnEvent = (ev) => {
      const trustTier = classifyTrustTier(ev.fullPath, ev.parentPath);
      const observedScore = Math.max(0, scoreUsnObservedEvent(ev) - (trustTier.dampening || 0));
      const promotionSignals = deriveEventPromotionSignals(ev);
      if (trustTier.allowlist) {
        return {
          trustTier,
          observedScore,
          promotionSignals,
          requiredSignalCount: Number.MAX_SAFE_INTEGER,
          promotionEligible: false,
          confidence: "trusted",
          riskScore: Math.min(observedScore, 1),
        };
      }
      const gated = eventNeedsTwoSignals(ev);
      const requiredSignalCount = gated ? 2 + (trustTier.key ? 1 : 0) : 1;
      const promotionEligible = promotionSignals.length >= requiredSignalCount;
      let confidence = "observed";
      if (promotionEligible) {
        confidence = promotionSignals.length >= (requiredSignalCount + 1) || promotionSignals.some((sig) => sig === "downloaded" || sig === "timestomp" || sig === "persistence-path")
          ? "high"
          : "medium";
      }
      let riskScore = observedScore;
      if (promotionEligible) riskScore += Math.min(4, promotionSignals.length - requiredSignalCount + 1);
      else riskScore = Math.min(riskScore, gated ? 3 : 4);
      return {
        trustTier,
        observedScore,
        promotionSignals,
        requiredSignalCount,
        promotionEligible,
        confidence,
        riskScore: Math.max(0, riskScore),
      };
    };
    const bucketForDirectory = (ev) => primaryReasonBucket(ev.reasonBuckets);
    const makeIncidentTitle = (bucket, path) => {
      const labels = {
        "acl-change": "Mass permission change",
        overwrite: "Overwrite burst",
        rename: "Rename burst",
        delete: "Deletion burst",
        create: "File creation burst",
        "stream-change": "ADS / stream change burst",
        persistence: "Persistence path activity",
        execution: "Executable drop burst",
        exfil: "Archive staging burst",
        suspicious: "Suspicious path activity",
        metadata: "Metadata change burst",
        close: "Enumeration / close burst",
      };
      return `${labels[bucket] || "USN activity"} in ${path || "(unknown)"}`;
    };

    const correlationLabelMap = {
      downloaded: "ADS download",
      timestomp: "Timestomp indicator",
      "deleted-in-mft": "Deleted in MFT",
      "persistence-related": "Persistence-related",
      "executable-or-script": "Executable/script",
      "archive-staging": "Archive staging",
      "acl-change-burst": "ACL change burst",
      "overwrite-burst": "Overwrite burst",
      "rename-burst": "Rename burst",
      "stream-activity": "ADS/stream activity",
      "startup-folder": "Startup folder",
      "scheduled-task": "Scheduled task",
      "gpo-script": "GPO script",
      "wmi-persistence": "WMI MOF",
      "temp-executable": "Temp payload",
      "temp-archive": "Temp archive",
      "temp-tampering": "Temp tampering",
      "public-drop": "Public path payload",
      "programdata-drop": "ProgramData payload",
      "recycle-bin-artifact": "Recycle Bin artifact",
      "media-folder-payload": "Media folder payload",
      "recovery-artifact": "Recovery/PerfLogs artifact",
      "rare-directory": "Rare directory",
      "rare-extension": "Rare extension",
      "rare-reason-mix": "Rare reason mix",
      "local-burst": "Local burst",
    };
    const correlationWeight = (tag) => ({
      downloaded: 2,
      timestomp: 2,
      "deleted-in-mft": 2,
      "persistence-related": 3,
      "executable-or-script": 2,
      "archive-staging": 2,
      "acl-change-burst": 2,
      "overwrite-burst": 3,
      "rename-burst": 2,
      "stream-activity": 2,
      "startup-folder": 3,
      "scheduled-task": 3,
      "gpo-script": 3,
      "wmi-persistence": 3,
      "temp-executable": 3,
      "temp-archive": 2,
      "temp-tampering": 2,
      "public-drop": 2,
      "programdata-drop": 2,
      "recycle-bin-artifact": 2,
      "media-folder-payload": 2,
      "recovery-artifact": 2,
      "rare-directory": 2,
      "rare-extension": 1,
      "rare-reason-mix": 1,
      "local-burst": 2,
    }[tag] || 0);
    const crossModuleSynergyScore = (tagsLike) => {
      const tags = new Set(tagsLike || []);
      let score = 0;
      if (tags.has("downloaded") && tags.has("executable-or-script")) score += 3;
      if (tags.has("downloaded") && tags.has("persistence-related")) score += 3;
      if (tags.has("downloaded") && (tags.has("temp-executable") || tags.has("public-drop") || tags.has("programdata-drop"))) score += 3;
      if (tags.has("downloaded") && (tags.has("startup-folder") || tags.has("scheduled-task") || tags.has("gpo-script") || tags.has("wmi-persistence"))) score += 4;
      if (tags.has("downloaded") && tags.has("timestomp")) score += 2;
      if (tags.has("persistence-related") && tags.has("timestomp")) score += 3;
      if (tags.has("archive-staging") && tags.has("overwrite-burst")) score += 3;
      if (tags.has("deleted-in-mft") && tags.has("timestomp")) score += 2;
      if (tags.has("deleted-in-mft") && tags.has("archive-staging")) score += 2;
      if (tags.has("rare-directory") && (tags.has("executable-or-script") || tags.has("persistence-related"))) score += 2;
      if (tags.has("rare-extension") && tags.has("downloaded")) score += 2;
      return score;
    };
    const severityForPriority = (score) => score >= 14 ? "critical" : score >= 10 ? "high" : score >= 6 ? "medium" : "low";
    const findingDurationMinutes = (start, end) => {
      const startMs = parseTs(start);
      const endMs = parseTs(end);
      if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) return null;
      return Math.max(1, Math.round((endMs - startMs) / 60000));
    };
    const pushUnique = (arr, value) => {
      if (!value || arr.includes(value)) return;
      arr.push(value);
    };
    const buildEvidenceList = ({ reasonBuckets = [], tags = [], topExtensions = [], categories = [] }) => {
      const out = [];
      reasonBuckets.forEach((bucket) => pushUnique(out, REASON_LABELS[bucket] || ""));
      tags.forEach((tag) => pushUnique(out, correlationLabelMap[tag] || ""));
      topExtensions.forEach((item) => {
        const ext = item?.ext || item;
        if (ext && ext !== "(none)") pushUnique(out, `${ext} activity`);
      });
      categories.forEach((cat) => pushUnique(out, cat));
      return out.slice(0, 4);
    };
    const explainIncidentFinding = (inc) => {
      const tags = new Set(inc.tags || []);
      if (tags.has("overwrite-burst")) return "Mass overwrite activity is consistent with encryption, wiping, or bulk content tampering.";
      if (tags.has("rename-burst")) return "Burst rename activity can indicate staging, masquerading, or ransomware rename phases.";
      if (tags.has("acl-change-burst")) return "Bulk ACL changes can indicate permission tampering or archive extraction staging.";
      if (tags.has("stream-activity")) return "ADS or stream changes clustered in one directory can indicate hidden data or Mark-of-the-Web manipulation.";
      if (tags.has("startup-folder")) return "Writes inside a Startup folder can indicate logon persistence and merit immediate validation.";
      if (tags.has("scheduled-task")) return "Task-definition activity can indicate scheduled-task persistence or task tampering.";
      if (tags.has("gpo-script")) return "Group Policy logon/startup script changes can indicate policy-based persistence.";
      if (tags.has("wmi-persistence")) return "MOF or AutoRecover writes can indicate WMI event-consumer persistence.";
      if (tags.has("temp-executable")) return "Executable/script activity in temp locations is higher signal than routine temporary file churn.";
      if (tags.has("public-drop")) return "Payload-like activity in a Public path is a common staging pattern because the location is broadly writable.";
      if (tags.has("programdata-drop")) return "Payload-like activity in ProgramData can indicate masquerading, service-style staging, or follow-on persistence.";
      if (tags.has("local-burst")) return "This incident spikes above its local baseline in the selected window and should be triaged first.";
      if (inc.reasonFamily === "execution") return "Executable/script activity clustered in one directory can reveal payload staging or tool drops.";
      if (inc.reasonFamily === "persistence") return "Repeated activity in a persistence-related directory can indicate foothold establishment.";
      if (inc.reasonFamily === "close") return "Close-only bursts often reflect rapid file enumeration or reconnaissance.";
      if (inc.reasonFamily === "exfil") return "Archive staging activity can indicate data collection and exfil preparation.";
      return `Clustered ${String(REASON_LABELS[inc.reasonFamily] || inc.reasonFamily || "activity").toLowerCase()} in one directory stands out from routine file churn.`;
    };
    const explainChainFinding = (ch) => {
      const tags = new Set(ch.tags || []);
      const reasons = new Set(ch.reasonBuckets || []);
      if (tags.has("downloaded") && tags.has("executable-or-script")) return "A downloaded executable/script is a strong payload indicator and should be validated first.";
      if (tags.has("downloaded") && tags.has("persistence-related")) return "A downloaded artifact touching persistence locations is a strong foothold indicator.";
      if (tags.has("startup-folder")) return "This file chain touches a Startup folder and may represent logon persistence.";
      if (tags.has("scheduled-task")) return "This file chain touches a scheduled-task path and may represent task-based persistence.";
      if (tags.has("gpo-script")) return "This file chain touches Group Policy script paths and may represent policy-based persistence.";
      if (tags.has("wmi-persistence")) return "This file chain touches WMI MOF paths and may represent event-based persistence.";
      if (tags.has("temp-executable")) return "Payload-like activity in temp paths is stronger signal than generic temp churn and should be triaged early.";
      if (tags.has("public-drop")) return "Payload-like activity in a Public path is a common staging and execution pattern.";
      if (tags.has("programdata-drop")) return "ProgramData payload activity can indicate masquerading or service-style staging.";
      if (tags.has("rare-directory")) return "This artifact appears in a directory that is rare in the selected dataset, which increases triage value.";
      if (tags.has("rare-extension")) return "This extension is unusually rare in the selected dataset and may represent a stand-out artifact.";
      if (tags.has("persistence-related")) return "This artifact touches a persistence-related path and may represent a survival mechanism.";
      if (tags.has("timestomp")) return "MFT metadata indicates timestomping, which is consistent with anti-forensics.";
      if (tags.has("deleted-in-mft")) return "The artifact is already deleted in MFT, which can indicate cleanup after execution.";
      if (tags.has("archive-staging")) return "Archive staging activity can indicate collection and exfil preparation.";
      if (reasons.has("stream-change")) return "ADS or stream changes can indicate hidden data or Mark-of-the-Web manipulation.";
      if (reasons.has("rename") && (ch.pathTransitions?.length || 0) > 1) return "Repeated rename or path transitions can indicate masquerading or staging.";
      if (reasons.has("overwrite")) return "Content overwrite activity against one file chain can indicate payload modification or destructive behavior.";
      return "This file chain combines multiple suspicious changes closely enough to merit immediate review.";
    };
    const dominantTrustTier = (trustTierCounts) => {
      const top = [...(trustTierCounts?.entries?.() || [])].sort((a, b) => b[1] - a[1])[0];
      if (!top || !TRUST_TIER_META[top[0]]) return { key: "", label: "", dampening: 0 };
      return { key: top[0], ...TRUST_TIER_META[top[0]] };
    };
    const aggregateNeedsTwoSignals = ({ categoryKeys = [], reasonFamily = "", tags = [] }) => {
      const tagSet = new Set(tags || []);
      return (categoryKeys || []).some((key) => TWO_SIGNAL_EVENT_CATEGORIES.has(key))
        || (reasonFamily && TWO_SIGNAL_REASON_BUCKETS.has(reasonFamily))
        || [...TWO_SIGNAL_LOCATION_TAGS].some((tag) => tagSet.has(tag));
    };
    const deriveAggregatePromotionSignals = ({ tags = [], reasonBuckets = [], extensions = [], path = "", eventCount = 0, uniqueFiles = 0, promotedEventCount = 0, pathVariants = 0 }) => {
      const tagSet = new Set(tags || []);
      const reasonSet = new Set(reasonBuckets || []);
      const extList = (extensions || []).map((ext) => String(ext || "").toLowerCase());
      const pathLower = String(path || "").toLowerCase();
      const out = new Set();
      if ([...STRONG_MFT_TAGS].some((tag) => tagSet.has(tag))) out.add("mft-corroboration");
      if ([...OUTLIER_TAGS].some((tag) => tagSet.has(tag))) out.add("outlier");
      if ([...STRONG_PATH_TAGS].some((tag) => tagSet.has(tag))) out.add("risky-location");
      if ([...DESTRUCTIVE_REASON_BUCKETS].some((bucket) => reasonSet.has(bucket)) || reasonSet.has("acl-change")) out.add("destructive");
      if (reasonSet.size >= 2) out.add("multi-reason");
      if (STARTUP_PATH_PAT.test(pathLower) || SCHEDULED_TASK_PATH_PAT.test(pathLower) || LEGACY_TASK_PATH_PAT.test(pathLower) || GPO_SCRIPT_PATH_PAT.test(pathLower) || WMI_MOF_PATH_PAT.test(pathLower)) out.add("persistence-path");
      if (TEMP_PATH_PAT.test(pathLower) || PUBLIC_PATH_PAT.test(pathLower) || PROGRAMDATA_PATH_PAT.test(pathLower) || RECYCLE_BIN_PATH_PAT.test(pathLower) || MEDIA_PATH_PAT.test(pathLower) || RECOVERY_PATH_PAT.test(pathLower)) out.add("risky-path");
      if (extList.some((ext) => EXEC_EXTS.has(ext) || SHORTCUT_EXTS.has(ext))) out.add("payload-ext");
      if (extList.some((ext) => ARCHIVE_EXTS.has(ext))) out.add("archive-ext");
      if (promotedEventCount > 0) out.add("event-corroboration");
      if (eventCount >= 8 || uniqueFiles >= 5) out.add("volume");
      if (pathVariants > 1) out.add("path-variation");
      return [...out];
    };
    const evaluateAggregateConfidence = ({ tags = [], categoryKeys = [], reasonFamily = "", trustTierCounts = new Map(), reasonBuckets = [], extensions = [], path = "", eventCount = 0, uniqueFiles = 0, promotedEventCount = 0, pathVariants = 0, observedRiskScore = 0, baseCorrelationScore = 0, baseCrossModuleScore = 0, eventRateScore = 0, fileCountScore = 0, tagCountScore = 0, reasonCountScore = 0 }) => {
      const trustTier = dominantTrustTier(trustTierCounts);
      const promotionSignals = deriveAggregatePromotionSignals({ tags, reasonBuckets, extensions, path, eventCount, uniqueFiles, promotedEventCount, pathVariants });
      const observedPriorityScore = Math.max(0, observedRiskScore) + Math.max(0, baseCorrelationScore) + Math.max(0, baseCrossModuleScore);
      if (trustTier.allowlist) {
        return {
          trustTier,
          promotionSignals,
          requiredSignalCount: Number.MAX_SAFE_INTEGER,
          highConfidence: false,
          confidence: "trusted",
          observedPriorityScore,
          priorityScore: Math.min(observedPriorityScore, 2),
        };
      }
      const gated = aggregateNeedsTwoSignals({ categoryKeys, reasonFamily, tags });
      const requiredSignalCount = gated ? 2 + (trustTier.key ? 1 : 0) : 1;
      const highConfidence = promotionSignals.length >= requiredSignalCount;
      const confidence = highConfidence
        ? (promotionSignals.length >= (requiredSignalCount + 1) || promotionSignals.includes("mft-corroboration") || promotionSignals.includes("persistence-path") ? "high" : "medium")
        : "observed";
      let priorityScore = observedPriorityScore;
      if (highConfidence) {
        priorityScore += eventRateScore + fileCountScore + tagCountScore + reasonCountScore + Math.min(4, promotionSignals.length - requiredSignalCount + 1);
      } else {
        priorityScore = Math.min(observedPriorityScore, gated ? 5 : 6);
      }
      return {
        trustTier,
        promotionSignals,
        requiredSignalCount,
        highConfidence,
        confidence,
        observedPriorityScore,
        priorityScore: Math.max(0, priorityScore),
      };
    };

    const result = { ...empty };

    try {
      // ── Q1: Rename Activity ──
      if (analyses.renames) {
        const renameRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name, ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons,
                 ${usnCol ? usnCol + " as usn" : "rowid as usn"}
          FROM data
          WHERE ${timeFilter}
            AND (${reasonCol} LIKE '%RenameOldName%' OR ${reasonCol} LIKE '%RenameNewName%')
            ${pathLike}
          ORDER BY ${entryCol}, CAST(${usnCol || "rowid"} AS INTEGER), rowid
        `).all(...baseParams);

        const renameGroups = new Map();
        for (const row of renameRows) {
          const refKey = `${String(row.entryNumber || "")}:${String(row.sequenceNumber || "")}`;
          if (!renameGroups.has(refKey)) renameGroups.set(refKey, []);
          renameGroups.get(refKey).push(row);
        }
        const pairs = [];
        let unmatchedOldCount = 0;
        let unmatchedNewCount = 0;
        for (const rows of renameGroups.values()) {
          const pendingOlds = [];
          rows.sort((a, b) => {
            const au = Number(a.usn);
            const bu = Number(b.usn);
            if (Number.isFinite(au) && Number.isFinite(bu) && au !== bu) return au - bu;
            const at = parseTs(a.timestamp);
            const bt = parseTs(b.timestamp);
            if (Number.isFinite(at) && Number.isFinite(bt) && at !== bt) return at - bt;
            return String(a.name || "").localeCompare(String(b.name || ""));
          });
          rows.forEach((row, idx) => {
            const hasOld = /RenameOldName/i.test(row.reasons || "");
            const hasNew = /RenameNewName/i.test(row.reasons || "");
            if (hasOld) {
              pendingOlds.push({
                name: row.name,
                parentPath: row.parentPath || "",
                timestamp: row.timestamp,
                entryNumber: row.entryNumber,
                sequenceNumber: row.sequenceNumber || "",
                usn: row.usn,
                rowIndex: idx,
              });
            }
            if (hasNew) {
              let matchIdx = -1;
              for (let j = pendingOlds.length - 1; j >= 0; j--) {
                const cand = pendingOlds[j];
                if (cand.rowIndex === idx) continue;
                matchIdx = j;
                if ((cand.parentPath || "") === (row.parentPath || "")) break;
              }
              if (matchIdx >= 0) {
                const oldRow = pendingOlds.splice(matchIdx, 1)[0];
                pairs.push({
                  entryNumber: row.entryNumber,
                  sequenceNumber: row.sequenceNumber || oldRow.sequenceNumber || "",
                  timestamp: row.timestamp || oldRow.timestamp,
                  oldName: oldRow.name,
                  newName: row.name,
                  parentPath: row.parentPath || oldRow.parentPath || "",
                });
              } else {
                unmatchedNewCount += 1;
              }
            }
          });
          unmatchedOldCount += pendingOlds.length;
        }
        result.renames = {
          count: pairs.length,
          events: pairs.slice(0, 2000),
          unmatchedCount: unmatchedOldCount + unmatchedNewCount,
          unmatchedOldCount,
          unmatchedNewCount,
        };
      }

      // ── Q2: Deletion Activity ──
      if (analyses.deletions) {
        const deleteRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${attrsCol ? attrsCol + " as fileAttributes" : "'' as fileAttributes"}
          FROM data
          WHERE ${timeFilter}
            AND ${reasonCol} LIKE '%FileDelete%'
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC, rowid
          LIMIT 5000
        `).all(...baseParams);
        result.deletions = { count: deleteRows.length, events: deleteRows };
      }

      // ── Q3: File Creation ──
      if (analyses.creations) {
        const createRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp
          FROM data
          WHERE ${timeFilter}
            AND ${reasonCol} LIKE '%FileCreate%'
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC, rowid
          LIMIT 5000
        `).all(...baseParams);
        result.creations = { count: createRows.length, events: createRows };
      }

      // ── Q4: Data Exfiltration Tracking ──
      if (analyses.exfil) {
        const archiveExts = [".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".bz2"];
        const extPlaceholders = archiveExts.map(() => "?").join(",");
        const archiveRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND (${reasonCol} LIKE '%FileCreate%' OR ${reasonCol} LIKE '%DataExtend%')
            AND LOWER(${extCol || "''"}) IN (${extPlaceholders})
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC, rowid
          LIMIT 1000
        `).all(...baseParams, ...archiveExts);

        // For each unique archive parent path, find child file activity
        const archiveDirs = [...new Set(archiveRows.map((r) => r.parentPath).filter(Boolean))];
        const dirActivity = [];
        for (const dir of archiveDirs.slice(0, 20)) {
          const childRows = db.prepare(`
            SELECT ${nameCol} as name, ${tsCol} as timestamp, ${reasonCol} as reasons
            FROM data
            WHERE ${timeFilter} AND ${parentPathCol} = ?
              AND ${reasonCol} LIKE '%FileCreate%' ${notDir}
            ORDER BY sort_datetime(${tsCol}) ASC, rowid
            LIMIT 100
          `).all(effectiveStart, effectiveEnd, dir);
          dirActivity.push({ directory: dir, fileCount: childRows.length, files: childRows.slice(0, 50) });
        }
        result.exfil = { archiveCount: archiveRows.length, archives: archiveRows, stagingDirectories: dirActivity };
      }

      // ── Q5: Execution Artifacts ──
      if (analyses.execution) {
        const execExts = [".exe", ".dll", ".ps1", ".bat", ".vbs", ".cmd", ".js", ".hta", ".msi", ".scr"];
        const extPlaceholders = execExts.map(() => "?").join(",");
        const execRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND (${reasonCol} LIKE '%FileCreate%' OR ${reasonCol} LIKE '%DataOverwrite%' OR ${reasonCol} LIKE '%DataExtend%')
            AND LOWER(${extCol || "''"}) IN (${extPlaceholders})
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC, rowid
          LIMIT 3000
        `).all(...baseParams, ...execExts);

        const extBreakdown = {};
        for (const r of execRows) {
          const ext = (r.extension || "").toLowerCase();
          extBreakdown[ext] = (extBreakdown[ext] || 0) + 1;
        }
        result.execution = {
          count: execRows.length, events: execRows,
          extensionBreakdown: Object.entries(extBreakdown).map(([ext, count]) => ({ ext, count })).sort((a, b) => b.count - a.count),
        };
      }

      // ── Q6: Persistence Paths ──
      if (analyses.persistence && parentPathCol) {
        const persistPatterns = [
          "%\\Start Menu\\Programs\\Startup%",
          "%\\Windows\\System32\\Tasks%",
          "%\\Windows\\Tasks%",
          "%\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Startup%",
          "%\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Shutdown%",
          "%\\Windows\\System32\\GroupPolicy\\User\\Scripts\\Logon%",
          "%\\Windows\\System32\\GroupPolicy\\User\\Scripts\\Logoff%",
          "%\\Windows\\System32\\wbem\\mof%",
          "%\\Windows\\System32\\wbem\\AutoRecover%",
          "%\\Windows\\SysWOW64\\wbem\\mof%",
          "%\\Windows\\SysWOW64\\wbem\\AutoRecover%",
        ];
        const patternConditions = persistPatterns.map(() => `${parentPathCol} LIKE ?`).join(" OR ");
        const rawPersistRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol} as parentPath,
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND (${patternConditions})
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC, rowid
          LIMIT 3000
        `).all(effectiveStart, effectiveEnd, ...persistPatterns, ...(normPath ? [`%${normPath}%`] : []));

        const persistRows = [];
        const suppressedRows = [];
        const categories = {};
        for (const r of rawPersistRows) {
          const classification = classifyPersistenceRow(r);
          if (!classification.include) {
            if (classification.suppressionReason && classification.suppressionReason !== "Outside persistence scope") {
              suppressedRows.push({ ...r, suppressionReason: classification.suppressionReason });
            }
            continue;
          }
          persistRows.push({
            ...r,
            heuristicCategory: classification.category,
            heuristicTags: classification.tags,
            heuristicRisk: classification.heuristicRisk,
          });
          categories[classification.category] = (categories[classification.category] || 0) + 1;
        }
        result.persistence = {
          count: persistRows.length, events: persistRows,
          categories: Object.entries(categories).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
          suppressedCount: suppressedRows.length,
          suppressedEvents: suppressedRows,
          suppressionSummary: summarizeUsnSuppressions(suppressedRows),
        };
      }

      // ── Q7: Suspicious Paths ──
      if (analyses.suspiciousPaths && parentPathCol) {
        const suspPatterns = [
          "%\\Temp\\%", "%\\Tmp\\%", "%\\PerfLogs\\%", "%\\Public\\%",
          "%$Recycle.Bin%", "%\\Windows\\Temp\\%", "%\\AppData\\Local\\Temp\\%",
          "%\\ProgramData\\%", "%\\Recovery\\%",
          "%\\Videos%", "%\\Music%", "%\\Pictures%",
        ];
        const patternConditions = suspPatterns.map(() => `${parentPathCol} LIKE ?`).join(" OR ");
        const rawSuspRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol} as parentPath,
                 ${tsCol} as timestamp, ${reasonCol} as reasons,
                 ${attrsCol ? attrsCol + " as fileAttributes" : "'' as fileAttributes"}
          FROM data
          WHERE ${timeFilter}
            AND (${patternConditions})
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC, rowid
          LIMIT 3000
        `).all(effectiveStart, effectiveEnd, ...suspPatterns, ...(normPath ? [`%${normPath}%`] : []));

        const suspRows = [];
        const suppressedRows = [];
        const dirCounts = {};
        const categories = {};
        for (const r of rawSuspRows) {
          const classification = classifySuspiciousPathRow(r);
          if (!classification.include) {
            if (classification.suppressionReason && classification.suppressionReason !== "Outside suspicious path scope") {
              suppressedRows.push({ ...r, suppressionReason: classification.suppressionReason });
            }
            continue;
          }
          const enriched = {
            ...r,
            heuristicCategory: classification.category,
            heuristicTags: classification.tags,
            heuristicRisk: classification.heuristicRisk,
          };
          suspRows.push(enriched);
          const pp = r.parentPath || "(unknown)";
          dirCounts[pp] = (dirCounts[pp] || 0) + 1;
          categories[classification.category] = (categories[classification.category] || 0) + 1;
        }
        result.suspiciousPaths = {
          count: suspRows.length, events: suspRows,
          categories: Object.entries(categories).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
          directoryBreakdown: Object.entries(dirCounts).map(([path, count]) => ({ path, count })).sort((a, b) => b.count - a.count).slice(0, 30),
          suppressedCount: suppressedRows.length,
          suppressedEvents: suppressedRows,
          suppressionSummary: summarizeUsnSuppressions(suppressedRows),
        };
      }

      // ── Q8: Security Changes ──
      if (analyses.securityChanges) {
        const secRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons,
                 ${attrsCol ? attrsCol + " as fileAttributes" : "'' as fileAttributes"}
          FROM data
          WHERE ${timeFilter}
            AND ${reasonCol} LIKE '%SecurityChange%'
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC, rowid
          LIMIT 3000
        `).all(...baseParams);

        // Group by directory to find bulk permission changes (TA staging indicator)
        const dirCounts = {};
        const dirFiles = {};
        for (const r of secRows) {
          const pp = r.parentPath || "(unknown)";
          dirCounts[pp] = (dirCounts[pp] || 0) + 1;
          if (!dirFiles[pp]) dirFiles[pp] = new Set();
          dirFiles[pp].add(r.name);
        }
        const directoryBreakdown = Object.entries(dirCounts)
          .map(([path, count]) => ({ path, count, uniqueFiles: dirFiles[path]?.size || 0 }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 30);

        result.securityChanges = {
          count: secRows.length, events: secRows,
          directoryBreakdown,
          hotspotCount: directoryBreakdown.filter((d) => d.uniqueFiles >= 5).length,
        };
      }

      // ── Q9: Data Overwrite (ransomware / wiper indicator) ──
      if (analyses.dataOverwrite) {
        const owRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND (${reasonCol} LIKE '%DataOverwrite%' OR ${reasonCol} LIKE '%DataExtend%')
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC, rowid
          LIMIT 3000
        `).all(...baseParams);

        // Group by extension to detect mass-overwrite patterns
        const extCounts = {};
        const dirCounts = {};
        for (const r of owRows) {
          const ext = (r.extension || "(none)").toLowerCase();
          extCounts[ext] = (extCounts[ext] || 0) + 1;
          const pp = r.parentPath || "(unknown)";
          dirCounts[pp] = (dirCounts[pp] || 0) + 1;
        }
        result.dataOverwrite = {
          count: owRows.length, events: owRows,
          extensionBreakdown: Object.entries(extCounts).map(([ext, count]) => ({ ext, count })).sort((a, b) => b.count - a.count).slice(0, 20),
          directoryBreakdown: Object.entries(dirCounts).map(([path, count]) => ({ path, count })).sort((a, b) => b.count - a.count).slice(0, 20),
        };
      }

      // ── Q10: Stream Changes (ADS modifications) ──
      if (analyses.streamChanges) {
        const stRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND ${reasonCol} LIKE '%StreamChange%'
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC, rowid
          LIMIT 2000
        `).all(...baseParams);

        const dirCounts = {};
        for (const r of stRows) {
          const pp = r.parentPath || "(unknown)";
          dirCounts[pp] = (dirCounts[pp] || 0) + 1;
        }
        result.streamChanges = {
          count: stRows.length, events: stRows,
          directoryBreakdown: Object.entries(dirCounts).map(([path, count]) => ({ path, count })).sort((a, b) => b.count - a.count).slice(0, 20),
        };
      }

      // ── Q11: Close-only Patterns (bulk enumeration / recon fingerprinting) ──
      if (analyses.closePatterns) {
        const clRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND ${reasonCol} = 'Close'
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC, rowid
          LIMIT 3000
        `).all(...baseParams);

        // Directories with high close-only counts = recon/enumeration
        const dirCounts = {};
        for (const r of clRows) {
          const pp = r.parentPath || "(unknown)";
          dirCounts[pp] = (dirCounts[pp] || 0) + 1;
        }
        const directoryBreakdown = Object.entries(dirCounts)
          .map(([path, count]) => ({ path, count }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 30);

        result.closePatterns = {
          count: clRows.length, events: clRows,
          directoryBreakdown,
          hotspotCount: directoryBreakdown.filter((d) => d.count >= 10).length,
        };
      }

      // ── Per-section truncation flags ──
      // The display tables are hard-LIMITed; mark which were capped so the UI can warn
      // "showing first N of more" and the analyst trusts the TRUE volume below instead.
      const SECTION_LIMITS = { renames: 2000, deletions: 5000, creations: 5000, execution: 3000, persistence: 3000, suspiciousPaths: 3000, securityChanges: 3000, dataOverwrite: 3000, streamChanges: 2000, closePatterns: 3000, exfil: 1000 };
      for (const [k, lim] of Object.entries(SECTION_LIMITS)) {
        const sec = result[k];
        if (!sec) continue;
        const shown = (k === "exfil" ? sec.archives?.length : sec.events?.length) || 0;
        sec.shown = shown;
        sec.sectionLimit = lim;
        sec.truncated = shown >= lim;
      }

      // ── Summary + TRUE full-window volume (always) ──
      const totalEvents = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${timeFilter} ${pathLike}`).get(...baseParams)?.cnt || 0;

      // True volume by destructive reason family over the FULL window, computed in ONE pass and
      // EXCLUDING system/replication-driven changes (SourceInfo set) so defrag/FRS/TxF churn does
      // not inflate it. Independent of the per-section LIMITs, so a mass-destruction incident is
      // measured at its TRUE scale even when the displayed tables (and the burst sample derived
      // from them) are capped — this is the fix for severity-inverting under-counts.
      const userCond = sourceInfoCol ? `(${sourceInfoCol} IS NULL OR ${sourceInfoCol} = '')` : "1=1";
      // Match a USN reason flag as a WHOLE token. UpdateReasons is a pipe-joined string in bitmask
      // order, so wrapping it in '|' and matching '|FLAG|' avoids 'DataOverwrite' also matching
      // 'NamedDataOverwrite' (and DataTruncation matching NamedDataTruncation).
      const flagLike = (flag) => `('|' || ${reasonCol} || '|') LIKE '%|${flag}|%'`;
      const destructivePred = `(${flagLike("DataOverwrite")} OR ${flagLike("DataTruncation")} OR ${flagLike("FileDelete")} OR ${flagLike("RenameNewName")})`;
      const volume = { overwrite: 0, truncate: 0, delete: 0, create: 0, rename: 0, streamChange: 0, securityChange: 0, systemDriven: 0, destructiveTotal: 0, peakDestructivePerMinute: 0, topDestructiveExtension: "", topDestructiveExtensionShare: 0 };
      try {
        const vr = db.prepare(
          `SELECT
             SUM(CASE WHEN ${flagLike("DataOverwrite")} AND ${userCond} THEN 1 ELSE 0 END) AS overwrite,
             SUM(CASE WHEN ${flagLike("DataTruncation")} AND ${userCond} THEN 1 ELSE 0 END) AS truncate,
             SUM(CASE WHEN ${flagLike("FileDelete")} AND ${userCond} THEN 1 ELSE 0 END) AS del,
             SUM(CASE WHEN ${flagLike("FileCreate")} AND ${userCond} THEN 1 ELSE 0 END) AS cre,
             SUM(CASE WHEN ${flagLike("RenameNewName")} AND ${userCond} THEN 1 ELSE 0 END) AS ren,
             SUM(CASE WHEN ${flagLike("StreamChange")} AND ${userCond} THEN 1 ELSE 0 END) AS strm,
             SUM(CASE WHEN ${flagLike("SecurityChange")} AND ${userCond} THEN 1 ELSE 0 END) AS sec,
             SUM(CASE WHEN ${destructivePred} AND ${userCond} THEN 1 ELSE 0 END) AS destructive,
             SUM(CASE WHEN ${sourceInfoCol ? `${sourceInfoCol} IS NOT NULL AND ${sourceInfoCol} != ''` : "0"} THEN 1 ELSE 0 END) AS sys
           FROM data WHERE ${timeFilter} ${pathLike} ${notDir}`
        ).get(...baseParams);
        volume.overwrite = vr?.overwrite || 0; volume.truncate = vr?.truncate || 0; volume.delete = vr?.del || 0;
        volume.create = vr?.cre || 0; volume.rename = vr?.ren || 0; volume.streamChange = vr?.strm || 0;
        volume.securityChange = vr?.sec || 0; volume.systemDriven = vr?.sys || 0;
        // Count each destructive RECORD once. USN reason masks are CUMULATIVE — a delete record
        // carries DataExtend|DataTruncation|FileDelete — so summing per-family double-counts.
        volume.destructiveTotal = vr?.destructive || 0;
      } catch (e) { /* keep zeros */ }
      try {
        // Peak destructive events in any single minute — the TRUE burst rate and the PRIMARY
        // ransomware/wiper signal (encryption is fast); not a cumulative count over a long window.
        volume.peakDestructivePerMinute = db.prepare(
          `SELECT COUNT(*) c FROM data WHERE ${timeFilter} ${pathLike} AND ${destructivePred} AND ${userCond} ${notDir}
           GROUP BY substr(${tsCol}, 1, 16) ORDER BY c DESC, substr(${tsCol}, 1, 16) LIMIT 1`
        ).get(...baseParams)?.c || 0;
      } catch (e) { volume.peakDestructivePerMinute = 0; }
      try {
        // Dominant destructive extension + its share. Ransomware renames/overwrites to ONE uniform
        // extension (homogeneous); benign bulk dev/admin churn (build, checkout, uninstall) touches
        // many extensions (diverse). Used to corroborate the mass-activity finding below.
        if (extCol && volume.destructiveTotal > 0) {
          // Share is computed over the EXTENSION-BEARING destructive population (the same population
          // the top group is drawn from) via a window-function total, so numerator and denominator
          // are consistent — otherwise extensionless destructive rows would understate homogeneity.
          const topExt = db.prepare(
            `SELECT lower(${extCol}) AS ext, COUNT(*) c, SUM(COUNT(*)) OVER () AS total FROM data
             WHERE ${timeFilter} ${pathLike} AND ${destructivePred} AND ${userCond} ${notDir} AND ${extCol} IS NOT NULL AND ${extCol} != ''
             GROUP BY lower(${extCol}) ORDER BY c DESC, ext LIMIT 1`
          ).get(...baseParams);
          if (topExt && topExt.total > 0) {
            volume.topDestructiveExtension = topExt.ext || "";
            volume.topDestructiveExtensionShare = (topExt.c || 0) / topExt.total;
          }
        }
      } catch (e) { /* best-effort */ }

      // ── Journal coverage / integrity — "what am I looking at and can I trust it?" ──
      const usnSpan = (journalSpan.usnMin != null && journalSpan.usnMax != null) ? (journalSpan.usnMax - journalSpan.usnMin) : null;
      const avgUsnDelta = (usnSpan != null && journalSpan.total > 1) ? usnSpan / (journalSpan.total - 1) : null;
      const coverage = {
        journalStart: journalSpan.start,
        journalEnd: journalSpan.end,
        journalTotalEvents: journalSpan.total,
        usnMin: journalSpan.usnMin,
        usnMax: journalSpan.usnMax,
        usnSpan,
        avgUsnDelta,
        // Large average USN delta vs a typical ~100-200 byte record => trimmed/wrapped journal or
        // deleted regions. Surfaced as CONTEXT (busy servers wrap fast), not an alarm.
        possibleGaps: avgUsnDelta != null && avgUsnDelta > 4096,
        windowStart: effectiveStart,
        windowEnd: endTime || journalSpan.end,
        windowCoversJournal: !startTime && !endTime,
        windowEventCount: totalEvents,
        mftCorrelated: !!mftTabId,
      };

      // ── Temporal histogram (full-window, auto-scaled buckets) — the canonical first-look view ──
      const histogram = { granularity: "hour", buckets: [] };
      try {
        const startMs = parseTs(effectiveStart);
        const endMs = parseTs(endTime || journalSpan.end);
        const spanMs = (Number.isFinite(startMs) && Number.isFinite(endMs) && endMs > startMs) ? (endMs - startMs) : null;
        // Pick a bucket granularity that keeps the bar count reasonable: minute / hour / day.
        const bucketLen = spanMs == null ? 13 : spanMs <= 2 * 3600 * 1000 ? 16 : spanMs <= 4 * 86400 * 1000 ? 13 : 10;
        histogram.granularity = bucketLen === 16 ? "minute" : bucketLen === 13 ? "hour" : "day";
        // destructive and created are made DISJOINT (created excludes any row already destructive)
        // and both honor userCond (SourceInfo exclusion) so the colored segments match the headline
        // "True File Activity Volume" and partition cleanly (destructive + created + other == total).
        // ORDER BY bucket DESC + reverse keeps the MOST RECENT buckets when capped, not the oldest.
        const hrows = db.prepare(
          `SELECT substr(${tsCol}, 1, ${bucketLen}) AS bucket, COUNT(*) AS total,
                  SUM(CASE WHEN ${destructivePred} AND ${userCond} THEN 1 ELSE 0 END) AS destructive,
                  SUM(CASE WHEN ${flagLike("FileCreate")} AND NOT ${destructivePred} AND ${userCond} THEN 1 ELSE 0 END) AS created
           FROM data WHERE ${timeFilter} ${pathLike} ${notDir} AND ${tsCol} IS NOT NULL AND ${tsCol} != ''
           GROUP BY bucket ORDER BY bucket DESC LIMIT 1000`
        ).all(...baseParams);
        histogram.truncated = hrows.length >= 1000;
        hrows.reverse(); // restore chronological order after the DESC cap
        histogram.buckets = hrows.map((r) => {
          const t = r.total || 0, dst = r.destructive || 0, c = r.created || 0;
          return { bucket: r.bucket, total: t, destructive: dst, created: c, other: Math.max(0, t - dst - c) };
        });
      } catch (e) { /* best-effort */ }

      // ── Breakdowns (full-window, user-driven) — "what file types, and where" at a glance ──
      // Reason-family distribution is reused from `volume` in the UI; here we add the two that need
      // their own GROUP BY: extension distribution and top directories by churn (with a destructive
      // split so the analyst sees where the dangerous activity concentrates).
      const breakdowns = { extensions: [], directories: [] };
      try {
        if (extCol) {
          breakdowns.extensions = db.prepare(
            `SELECT lower(${extCol}) AS ext, COUNT(*) AS count, SUM(CASE WHEN ${destructivePred} THEN 1 ELSE 0 END) AS destructive
             FROM data WHERE ${timeFilter} ${pathLike} ${notDir} AND ${extCol} IS NOT NULL AND ${extCol} != '' AND ${userCond}
             GROUP BY lower(${extCol}) ORDER BY count DESC, ext LIMIT 15`
          ).all(...baseParams).map((r) => ({ ext: r.ext || "", count: r.count || 0, destructive: r.destructive || 0 }));
        }
      } catch (e) { /* best-effort */ }
      try {
        if (parentPathCol) {
          breakdowns.directories = db.prepare(
            `SELECT ${parentPathCol} AS path, COUNT(*) AS count, ${entryCol ? `COUNT(DISTINCT ${entryCol})` : "COUNT(*)"} AS entries, SUM(CASE WHEN ${destructivePred} THEN 1 ELSE 0 END) AS destructive
             FROM data WHERE ${timeFilter} ${pathLike} ${notDir} AND ${parentPathCol} IS NOT NULL AND ${parentPathCol} != '' AND ${userCond}
             GROUP BY ${parentPathCol} ORDER BY count DESC, path LIMIT 15`
          ).all(...baseParams).map((r) => ({ path: r.path || "", count: r.count || 0, entries: r.entries || 0, destructive: r.destructive || 0 }));
        }
      } catch (e) { /* best-effort */ }

      result.summary = { totalEvents, startTime: effectiveStart, endTime, pathFilter: pathFilter || null, volume, coverage, histogram, breakdowns };

      // ── MFT entry+sequence-number REUSE (covert delete + recreate) ──
      // One MFT EntryNumber with MULTIPLE distinct SequenceNumbers = the record was freed and
      // reallocated: a file was deleted and a NEW file took its slot (a way to hide the original
      // file's metadata). Gated to risk-bearing extensions (EXEC/archive/shortcut/registry) so
      // routine temp-slot churn doesn't flood.
      result.fileReuse = [];
      try {
        if (entryCol && seqCol) {
          const reused = db.prepare(
            `SELECT ${entryCol} AS entry, COUNT(DISTINCT ${seqCol}) AS seqCount, COUNT(*) AS events
             FROM data WHERE ${timeFilter} ${pathLike} ${notDir} AND ${entryCol} IS NOT NULL AND ${entryCol} != ''
             GROUP BY ${entryCol} HAVING COUNT(DISTINCT ${seqCol}) > 1
             ORDER BY seqCount DESC, events DESC, entry LIMIT 200`
          ).all(...baseParams);
          if (reused.length > 0) {
            // Fetch every record for the candidate entries in ONE pass (not 200 per-entry queries).
            const entryIds = reused.map((r) => String(r.entry));
            const ph = entryIds.map(() => "?").join(",");
            // Guard optional columns (Extension/ParentPath may be absent on CSV imports) the same
            // way every other query in this file does; ext falls back to name-derived below.
            const gens = db.prepare(
              `SELECT ${entryCol} AS entry, ${seqCol} AS seq, ${nameCol} AS name, ${extCol ? `${extCol} AS ext` : "'' AS ext"}, ${reasonCol} AS reasons, ${parentPathCol ? `${parentPathCol} AS parent` : "'' AS parent"}, ${tsCol} AS ts
               FROM data WHERE ${entryCol} IN (${ph}) AND ${timeFilter} ${pathLike}`
            ).all(...entryIds, ...baseParams);
            const byEntry = new Map();
            for (const g of gens) {
              const e = String(g.entry);
              if (!byEntry.has(e)) byEntry.set(e, new Map());
              const seqMap = byEntry.get(e);
              const s = String(g.seq);
              const tsMs = parseTs(g.ts);
              const prev = seqMap.get(s);
              if (!prev) seqMap.set(s, { seq: s, name: g.name || "", ext: deriveExtension(g.name, g.ext), parent: g.parent || "", reasons: g.reasons || "", firstMs: tsMs });
              else { if (Number.isFinite(tsMs) && (!Number.isFinite(prev.firstMs) || tsMs < prev.firstMs)) prev.firstMs = tsMs; if (!prev.name && g.name) prev.name = g.name; }
            }
            for (const r of reused) {
              const seqMap = byEntry.get(String(r.entry));
              if (!seqMap || seqMap.size < 2) continue;
              const generations = [...seqMap.values()].sort((a, b) => (a.firstMs || 0) - (b.firstMs || 0));
              // Keep only when a risk-bearing extension is involved, else it is temp-slot churn.
              if (!generations.some((g) => EXT_RISK.has(g.ext))) continue;
              const names = generations.map((g) => g.name).filter(Boolean);
              result.fileReuse.push({
                entry: String(r.entry),
                seqCount: r.seqCount,
                hasExecutable: generations.some((g) => EXEC_EXTS.has(g.ext)),
                generations: generations.map((g) => ({ seq: g.seq, name: g.name, ext: g.ext, parent: g.parent, reasons: g.reasons })),
                summary: `MFT entry ${r.entry} reused across ${r.seqCount} files: ${names.slice(0, 4).join(" → ")}${names.length > 4 ? " → …" : ""}`,
              });
              if (result.fileReuse.length >= 30) break;
            }
          }
        }
      } catch (e) { /* best-effort */ }

      // ── Masquerading: payloads disguised as benign files ──
      // Double extension (invoice.pdf.exe), right-to-left/bidi override (U+202E) hiding the real
      // extension, and whitespace padding (report.pdf   .scr). Detected from the USN Name alone — a
      // gap the per-section path heuristics miss. Gated to executable/archive REAL extensions.
      result.masquerade = [];
      try {
        // Payloads worth masquerade-checking: executables, shortcuts (.lnk/.url — a classic phishing
        // vector), .jar, and archives. Double-extension/padding only count for the DIRECTLY dangerous
        // set (a decoy/pad before an archive ext, data.csv.zip, is routine); RTL override flags any.
        const DIRECT_PAYLOAD = new Set([...EXEC_EXTS, ...SHORTCUT_EXTS, ".jar"]);
        const payloadExts = [...DIRECT_PAYLOAD, ...ARCHIVE_EXTS];
        const payloadSet = new Set(payloadExts);
        const extIn = payloadExts.map(() => "?").join(",");
        // When an Extension column exists, pre-filter in SQL by it; otherwise pre-filter by name suffix
        // so the (ordered, capped) candidate set is not starved by .tmp/.log churn.
        const nameLikeFilter = payloadExts.map(() => `lower(${nameCol}) LIKE ?`).join(" OR ");
        const cand = db.prepare(
          `SELECT ${nameCol} AS name, ${extCol ? `${extCol} AS ext` : "'' AS ext"}, ${parentPathCol ? `${parentPathCol} AS parent` : "'' AS parent"}, ${reasonCol} AS reasons, ${tsCol} AS ts
           FROM data WHERE ${timeFilter} ${pathLike} ${notDir}
             AND (${reasonCol} LIKE '%FileCreate%' OR ${reasonCol} LIKE '%RenameNewName%')
             AND ${extCol ? `lower(${extCol}) IN (${extIn})` : `(${nameLikeFilter})`}
           ORDER BY sort_datetime(${tsCol}) DESC, rowid LIMIT 20000`
        ).all(...baseParams, ...(extCol ? payloadExts : payloadExts.map((e) => `%${e}`)));
        result.masqueradeTruncated = cand.length >= 20000;
        // RTL/bidi OVERRIDE + ISOLATE controls (U+202A-202E, U+2066-2069) that actually reorder
        // rendered text to hide an extension. Benign directional marks U+200E/200F (LRM/RLM), common
        // in legitimate RTL-locale filenames, are NOT flagged. Checked by code point.
        const isBidiDisguise = (s) => { for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if ((c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069)) return true; } return false; };
        const DECOY_RE = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|bmp|txt|rtf|csv|html?|one|msg|eml|mp4|mov)$/i;
        const seen = new Set();
        for (const c of cand) {
          const name = String(c.name || "");
          if (!name) continue;
          const ext = deriveExtension(name, c.ext);
          if (!payloadSet.has(ext)) continue;
          const base = name.slice(0, name.length - ext.length);
          const tags = [];
          // Double-extension + padding only count for directly-dangerous real exts (a decoy/pad before
          // an ARCHIVE ext is routine). RTL override is suspicious on any payload.
          if (DECOY_RE.test(base) && DIRECT_PAYLOAD.has(ext)) tags.push("double-extension");
          if (isBidiDisguise(name)) tags.push("rtl-override");
          if (DIRECT_PAYLOAD.has(ext) && /\s\.[^.\s]+$/.test(name)) tags.push("extension-padding");
          if (tags.length === 0) continue;
          const key = `${c.parent}\\${name}`.toLowerCase();
          if (seen.has(key)) continue;
          seen.add(key);
          result.masquerade.push({ name, ext, parent: c.parent || "", reasons: tags, reasonLabel: tags.join(", "), timestamp: c.ts || "" });
          if (result.masquerade.length >= 100) break;
        }
      } catch (e) { /* best-effort */ }

      // ── Self-deletion: a DROPPER created AND deleted in the window (drop + run + cleanup) ──
      // Same (entry, sequence) carrying both FileCreate and FileDelete = one file's whole lifetime in
      // the journal. Gated to DROPPER extensions (excludes .msi/.msp/.cpl/.sys installers, which
      // legitimately create+delete temp binaries) and suppressed under Program Files / Windows
      // servicing paths. Short lifetime (≤24h kept); immediate (≤15min) is the strong cleanup case.
      result.selfDeleted = [];
      try {
        if (entryCol && seqCol) {
          const dropperExts = [...EXEC_EXTS].filter((e) => ![".msi", ".msp", ".cpl", ".sys"].includes(e));
          const dropperSet = new Set(dropperExts);
          const execIn = dropperExts.map(() => "?").join(",");
          const TRUSTED_INSTALL_RE = /\\program files(?: \(x86\))?\\|\\windows\\(?:system32|syswow64|winsxs|installer|servicing|softwaredistribution)\\/i;
          const rows = db.prepare(
            // name/ext/parent come from the group's last record (SQLite's bare-column choice).
            `SELECT ${entryCol} AS entry, ${seqCol} AS seq, arg_max(${nameCol}, rowid) AS name, ${extCol ? `arg_max(${extCol}, rowid) AS ext` : "'' AS ext"}, ${parentPathCol ? `arg_max(${parentPathCol}, rowid) AS parent` : "'' AS parent"},
                    MIN(${tsCol}) AS first, MAX(${tsCol}) AS last,
                    MAX(CASE WHEN ${flagLike("FileCreate")} THEN 1 ELSE 0 END) AS hasCreate,
                    MAX(CASE WHEN ${flagLike("FileDelete")} THEN 1 ELSE 0 END) AS hasDelete
             FROM data WHERE ${timeFilter} ${pathLike} ${notDir} ${extCol ? `AND lower(${extCol}) IN (${execIn})` : ""}
             GROUP BY ${entryCol}, ${seqCol} HAVING hasCreate = 1 AND hasDelete = 1
             ORDER BY (epoch(TRY_CAST(substr(sort_datetime(MAX(${tsCol})), 1, 19) AS TIMESTAMP)) - epoch(TRY_CAST(substr(sort_datetime(MIN(${tsCol})), 1, 19) AS TIMESTAMP))) ASC, entry, seq LIMIT 2000`
          ).all(...baseParams, ...(extCol ? dropperExts : []));
          for (const r of rows) {
            const ext = deriveExtension(r.name, r.ext);
            if (!dropperSet.has(ext)) continue;
            if (TRUSTED_INSTALL_RE.test(String(r.parent || ""))) continue; // legit install/uninstall
            const firstMs = parseTs(r.first), lastMs = parseTs(r.last);
            const lifetimeMin = (Number.isFinite(firstMs) && Number.isFinite(lastMs)) ? Math.max(0, Math.round((lastMs - firstMs) / 60000)) : null;
            if (lifetimeMin == null || lifetimeMin > 1440) continue; // long-lived = not self-delete cleanup
            result.selfDeleted.push({
              entry: String(r.entry), seq: String(r.seq), name: r.name || "", ext, parent: r.parent || "",
              firstSeen: r.first || "", lastSeen: r.last || "", lifetimeMin, immediate: lifetimeMin <= 15,
            });
          }
          // Rank by shortest lifetime FIRST, THEN cap — so the most suspicious survive the cap.
          result.selfDeleted.sort((a, b) => (a.lifetimeMin ?? 1e9) - (b.lifetimeMin ?? 1e9));
          result.selfDeleted = result.selfDeleted.slice(0, 50);
        }
      } catch (e) { /* best-effort */ }

      // ── ADS / stream removal on payloads (possible Mark-of-the-Web stripping) ──
      // HEURISTIC. The $J FileName is the BASE file — it does NOT carry the ":Zone.Identifier" stream
      // name — so we detect by REASON: StreamChange + a truncation (a named stream shrunk/removed) on
      // a SURVIVING executable/archive (NOT a whole-file delete). This catches Unblock-File /
      // Remove-Item -Stream / streams.exe -d. Confirm the actual stream + origin before concluding
      // MOTW removal specifically (a $MFT/$J that surfaces the stream name, or the file's Zone data).
      result.motwStripped = [];
      try {
        const payloadExts = [...EXEC_EXTS, ...ARCHIVE_EXTS];
        const extIn = payloadExts.map(() => "?").join(",");
        const rows = db.prepare(
          `SELECT ${nameCol} AS name, ${extCol ? `${extCol} AS ext` : "'' AS ext"}, ${parentPathCol ? `${parentPathCol} AS parent` : "'' AS parent"}, ${tsCol} AS ts
           FROM data WHERE ${timeFilter} ${pathLike} ${notDir}
             AND ${flagLike("StreamChange")} AND ${flagLike("NamedDataTruncation")} AND NOT ${flagLike("FileDelete")}
             ${extCol ? `AND lower(${extCol}) IN (${extIn})` : ""}
           ORDER BY sort_datetime(${tsCol}) DESC, rowid LIMIT 500`
        ).all(...baseParams, ...(extCol ? payloadExts : []));
        const seen = new Set();
        for (const r of rows) {
          const name = String(r.name || "");
          const ext = deriveExtension(name, r.ext);
          if (!EXEC_EXTS.has(ext) && !ARCHIVE_EXTS.has(ext)) continue;
          const isZoneId = /:zone\.identifier/i.test(name); // strong confirmation IF the dataset carries the stream name
          const base = name.replace(/:zone\.identifier$/i, "");
          const key = `${r.parent}\\${base}`.toLowerCase();
          if (seen.has(key)) continue;
          seen.add(key);
          result.motwStripped.push({ file: base, parent: r.parent || "", ext, isZoneId, timestamp: r.ts || "" });
          if (result.motwStripped.length >= 100) break;
        }
      } catch (e) { /* best-effort */ }

      // ── MFT Cross-Artifact Correlation ──
      if (mftTabId) {
        const mftMeta = getDatabaseMeta(mftTabId);
        if (mftMeta) {
          try {
            const mftDb = mftMeta.db;
            const mc = (name) => mftMeta.colMap[name];
            const mEntry = mc("EntryNumber"), mSeq = mc("SequenceNumber"), mName = mc("FileName"), mSize = mc("FileSize");
            const mInUse = mc("InUse"), mSiFn = mc("SI<FN"), mFlags = mc("SiFlags");
            const mZone = mc("ZoneIdContents"), mCreated = mc("Created0x10");
            const mPath = mc("ParentPath"), mIsDir = mc("IsDirectory"), mExt = mc("Extension");
            // Widened join for real $SI-vs-$FN timestomp triangulation + sub-second-zero signal:
            // pull the $FN (0x30) timestamps alongside the $SI (0x10) set, the MFTECmd uSecZeros flag
            // (manual timestomps zero the sub-seconds even when SI<FN does not fire), and SecurityId.
            const mCreated30 = mc("Created0x30"), mMod10 = mc("LastModified0x10"), mMod30 = mc("LastModified0x30");
            const mRec10 = mc("LastRecordChange0x10"), mUSecZeros = mc("uSecZeros"), mSecId = mc("SecurityId");

            if (mEntry) {
              const categories = ["renames", "deletions", "creations", "exfil", "execution",
                "persistence", "suspiciousPaths", "securityChanges", "dataOverwrite", "streamChanges", "closePatterns"];
              const entryNums = new Set();
              const refMap = new Map();
              const normalizeRef = (entryNumber, sequenceNumber) => {
                const entryStr = entryNumber != null ? String(entryNumber) : "";
                if (!entryStr) return null;
                const seqStr = sequenceNumber != null ? String(sequenceNumber).trim() : "";
                return { entry: entryStr, sequence: seqStr, hasSequence: seqStr !== "" };
              };

              // Collect all unique file references from results
              const registerRef = (ev) => {
                const ref = normalizeRef(ev?.entryNumber, ev?.sequenceNumber);
                if (!ref) return;
                entryNums.add(ref.entry);
                const key = ref.hasSequence ? `${ref.entry}:${ref.sequence}` : `${ref.entry}:`;
                if (!refMap.has(key)) refMap.set(key, ref);
              };

              for (const cat of categories) {
                const sData = result[cat];
                if (!sData) continue;
                const events = cat === "exfil" ? sData.archives : sData.events;
                if (events) for (const ev of events) registerRef(ev);
              }

              const preferMftRow = (current, candidate) => {
                if (!current) return candidate;
                if (candidate.inUse === "True" && current.inUse !== "True") return candidate;
                if (candidate.isDir !== "True" && current.isDir === "True") return candidate;
                if (candidate.zoneId && !current.zoneId) return candidate;
                return current;
              };

              // Query MFT for those entries
              if (entryNums.size > 0) {
                const mftByEntry = new Map();
                const mftByEntrySeq = new Map();

                // Query in batches of 500 to avoid SQL variable limits
                const entryArr = [...entryNums];
                for (let i = 0; i < entryArr.length; i += 500) {
                  const batch = entryArr.slice(i, i + 500);
                  const placeholders = batch.map(() => "?").join(",");
                  const selectCols = [
                    `${mEntry} as entryNumber`,
                    mSeq ? `${mSeq} as sequenceNumber` : "'' as sequenceNumber",
                    mName ? `${mName} as fileName` : "'' as fileName",
                    mSize ? `${mSize} as fileSize` : "'' as fileSize",
                    mInUse ? `${mInUse} as inUse` : "'' as inUse",
                    mSiFn ? `${mSiFn} as siFn` : "'' as siFn",
                    mFlags ? `${mFlags} as siFlags` : "'' as siFlags",
                    mZone ? `${mZone} as zoneId` : "'' as zoneId",
                    mCreated ? `${mCreated} as created` : "'' as created",
                    mCreated30 ? `${mCreated30} as created30` : "'' as created30",
                    mMod10 ? `${mMod10} as modified10` : "'' as modified10",
                    mMod30 ? `${mMod30} as modified30` : "'' as modified30",
                    mRec10 ? `${mRec10} as recChange10` : "'' as recChange10",
                    mUSecZeros ? `${mUSecZeros} as uSecZeros` : "'' as uSecZeros",
                    mSecId ? `${mSecId} as securityId` : "'' as securityId",
                    mPath ? `${mPath} as parentPath` : "'' as parentPath",
                    mIsDir ? `${mIsDir} as isDir` : "'' as isDir",
                    mExt ? `${mExt} as extension` : "'' as extension",
                  ].join(", ");
                  const rows = mftDb.prepare(
                    `SELECT ${selectCols} FROM data WHERE ${mEntry} IN (${placeholders})`
                  ).all(...batch);
                  for (const r of rows) {
                    const entryKey = String(r.entryNumber);
                    const seqKey = r.sequenceNumber != null && String(r.sequenceNumber).trim() !== ""
                      ? `${entryKey}:${String(r.sequenceNumber).trim()}`
                      : null;
                    mftByEntry.set(entryKey, preferMftRow(mftByEntry.get(entryKey), r));
                    if (seqKey) {
                      mftByEntrySeq.set(seqKey, preferMftRow(mftByEntrySeq.get(seqKey), r));
                    }
                  }
                }

                const matchedRefs = new Set();
                const exactMatchedRefs = new Set();
                const fallbackMatchedRefs = new Set();
                const matchedArtifacts = new Map();
                const findMftMatch = (ev) => {
                  const ref = normalizeRef(ev?.entryNumber, ev?.sequenceNumber);
                  if (!ref) return { row: null, mode: null, refKey: null };
                  const refKey = ref.hasSequence ? `${ref.entry}:${ref.sequence}` : `${ref.entry}:`;
                  if (ref.hasSequence && mSeq) {
                    const exact = mftByEntrySeq.get(`${ref.entry}:${ref.sequence}`);
                    return { row: exact || null, mode: exact ? "exact" : null, refKey };
                  }
                  const fallback = mftByEntry.get(ref.entry);
                  return { row: fallback || null, mode: fallback ? "entry-only" : null, refKey };
                };

                // Enrich events with MFT data
                for (const cat of categories) {
                  const sData = result[cat];
                  if (!sData) continue;
                  const events = cat === "exfil" ? sData.archives : sData.events;
                  if (events) for (const ev of events) {
                    const match = findMftMatch(ev);
                    const mft = match.row;
                    if (!mft) continue;
                    matchedRefs.add(match.refKey);
                    if (match.mode === "exact") exactMatchedRefs.add(match.refKey);
                    if (match.mode === "entry-only") fallbackMatchedRefs.add(match.refKey);
                    matchedArtifacts.set(match.mode === "exact"
                      ? `${String(mft.entryNumber)}:${String(mft.sequenceNumber).trim()}`
                      : `${String(mft.entryNumber)}:`, mft);
                    ev._mft = {
                      fileSize: mft.fileSize || "",
                      inUse: mft.inUse || "",
                      siFn: mft.siFn || "",
                      uSecZeros: mft.uSecZeros || "",
                      siFlags: mft.siFlags || "",
                      zoneId: mft.zoneId || "",
                      created: mft.created || "",
                      created30: mft.created30 || "",
                      modified10: mft.modified10 || "",
                      modified30: mft.modified30 || "",
                      recChange10: mft.recChange10 || "",
                      securityId: mft.securityId || "",
                      mftPath: mft.parentPath || "",
                      sequenceNumber: mft.sequenceNumber != null ? String(mft.sequenceNumber) : "",
                      matchMode: match.mode,
                    };
                  }
                }

                // Build correlation summary
                const matchedRows = [...matchedArtifacts.values()];
                result.correlation = {
                  mftTabId,
                  totalUsnEntries: refMap.size,
                  matched: matchedRefs.size,
                  unmatched: Math.max(0, refMap.size - matchedRefs.size),
                  exactMatched: exactMatchedRefs.size,
                  fallbackMatched: fallbackMatchedRefs.size,
                  deleted: matchedRows.filter((r) => r.inUse === "False").length,
                  // Primary timestomp metric stays on the strong $SI<$FN signal (low FP). uSecZeros
                  // (sub-second-zero) is a WEAKER, separately-surfaced indicator — archive extraction
                  // also zeroes sub-seconds — so it is shown but not folded into the primary count.
                  timestomped: matchedRows.filter((r) => r.siFn === "True").length,
                  timestompedUSec: matchedRows.filter((r) => r.uSecZeros === "True").length,
                  downloaded: matchedRows.filter((r) => r.zoneId && r.zoneId.trim()).length,
                };
              }
            }
          } catch (mftErr) {
            result.correlationError = mftErr.message;
          }
        }
      }

      // ── Post-processing: normalized suspicious storyline, file chains, directory incidents ──
      const categoryMeta = {
        renames: "Rename Activity",
        deletions: "Deletion Activity",
        creations: "File Creation",
        exfil: "Data Exfiltration",
        execution: "Execution Artifacts",
        persistence: "Persistence Paths",
        suspiciousPaths: "Suspicious Paths",
        securityChanges: "Security Changes",
        dataOverwrite: "Data Overwrite",
        streamChanges: "Stream Changes",
        closePatterns: "Close Patterns",
      };
      const allEvents = [];
      const addEvent = (secKey, ev, extra = {}) => {
        if (!ev) return;
        const name = extra.name || ev.name || ev.newName || ev.oldName || "";
        const parentPath = extra.parentPath ?? ev.parentPath ?? "";
        const extension = deriveExtension(name, extra.extension ?? ev.extension ?? "");
        const rawReasons = extra.rawReasons ?? ev.reasons ?? "";
        const reasonBuckets = normalizeUsnReasons(rawReasons, secKey);
        const tags = [];
        if (ev._mft?.zoneId?.trim()) tags.push("downloaded");
        if (ev._mft?.siFn === "True") tags.push("timestomp");
        if (ev._mft?.inUse === "False") tags.push("deleted-in-mft");
        if (secKey === "persistence") tags.push("persistence-related");
        if (secKey === "execution") tags.push("executable-or-script");
        if (secKey === "exfil") tags.push("archive-staging");
        for (const tag of ev.heuristicTags || []) {
          if (!tags.includes(tag)) tags.push(tag);
        }
        const normalized = {
          id: `${secKey}:${ev.entryNumber || ""}:${ev.sequenceNumber || ""}:${ev.timestamp || ""}:${ev.usn || ""}:${extra.kind || ""}:${name}`,
          category: secKey,
          categoryLabel: categoryMeta[secKey] || secKey,
          timestamp: ev.timestamp || "",
          tsMs: parseTs(ev.timestamp),
          entryNumber: ev.entryNumber != null ? String(ev.entryNumber) : "",
          sequenceNumber: ev.sequenceNumber != null ? String(ev.sequenceNumber) : "",
          name,
          oldName: ev.oldName || "",
          newName: ev.newName || "",
          parentPath,
          fullPath: joinPath(parentPath, name),
          extension,
          rawReasons,
          reasonBuckets,
          primaryReason: primaryReasonBucket(reasonBuckets),
          reasonLabel: REASON_LABELS[primaryReasonBucket(reasonBuckets)] || "Activity",
          tags,
          heuristicRisk: Number(ev.heuristicRisk || 0),
          heuristicCategory: ev.heuristicCategory || "",
          _mft: ev._mft || null,
          _src: ev,
        };
        normalized.observedScore = scoreUsnObservedEvent(normalized);
        normalized.riskScore = normalized.observedScore;
        normalized.trustTier = { key: "", label: "", dampening: 0 };
        normalized.promotionSignals = [];
        normalized.requiredSignalCount = 1;
        normalized.promotionEligible = false;
        normalized.confidence = "observed";
        allEvents.push(normalized);
      };
      for (const [secKey, secLabel] of Object.entries(categoryMeta)) {
        const sec = result[secKey];
        if (!sec) continue;
        const sourceEvents = secKey === "exfil" ? sec.archives : sec.events;
        if (!Array.isArray(sourceEvents)) continue;
        if (secKey === "renames") {
          for (const ev of sourceEvents) {
            addEvent(secKey, ev, {
              name: ev.newName || ev.oldName || "",
              rawReasons: "RenameOldName|RenameNewName",
              kind: "rename-pair",
            });
          }
        } else {
          for (const ev of sourceEvents) addEvent(secKey, ev);
        }
      }
      allEvents.sort((a, b) => (a.tsMs || 0) - (b.tsMs || 0));

      const outlierHeavyCategories = new Set(["execution", "persistence", "suspiciousPaths", "exfil"]);
      const dirEventCounts = new Map();
      const extEventCounts = new Map();
      const reasonSigCounts = new Map();
      for (const ev of allEvents) {
        const dirKey = ev.parentPath || "(unknown)";
        dirEventCounts.set(dirKey, (dirEventCounts.get(dirKey) || 0) + 1);
        if (ev.extension) extEventCounts.set(ev.extension, (extEventCounts.get(ev.extension) || 0) + 1);
        const reasonSig = [...(ev.reasonBuckets || [])].sort().join("|");
        if (reasonSig) reasonSigCounts.set(reasonSig, (reasonSigCounts.get(reasonSig) || 0) + 1);
      }
      for (const ev of allEvents) {
        const outlierTags = [];
        const dirCount = dirEventCounts.get(ev.parentPath || "(unknown)") || 0;
        const extCount = ev.extension ? (extEventCounts.get(ev.extension) || 0) : 0;
        const reasonSig = [...(ev.reasonBuckets || [])].sort().join("|");
        const reasonSigCount = reasonSig ? (reasonSigCounts.get(reasonSig) || 0) : 0;
        if (ev.parentPath && ev.parentPath !== "(unknown)" && dirCount <= 2 && (outlierHeavyCategories.has(ev.category) || EXT_RISK.has(ev.extension))) {
          outlierTags.push("rare-directory");
        }
        if (ev.extension && extCount > 0 && extCount <= 2 && (EXT_RISK.has(ev.extension) || outlierHeavyCategories.has(ev.category))) {
          outlierTags.push("rare-extension");
        }
        if (reasonSig && reasonSigCount <= 2 && (ev.reasonBuckets.length > 1 || DESTRUCTIVE_REASON_BUCKETS.has(ev.primaryReason) || outlierHeavyCategories.has(ev.category))) {
          outlierTags.push("rare-reason-mix");
        }
        ev.outlierTags = outlierTags;
        outlierTags.forEach((tag) => {
          if (!ev.tags.includes(tag)) ev.tags.push(tag);
        });
        Object.assign(ev, evaluateUsnEvent(ev));
      }

      const fileChainMap = new Map();
      for (const ev of allEvents) {
        const key = ev.entryNumber || `${ev.parentPath}|${ev.name}`;
        if (!fileChainMap.has(key)) {
          fileChainMap.set(key, {
            key,
            entryNumber: ev.entryNumber || "",
            firstSeen: ev.timestamp || "",
            lastSeen: ev.timestamp || "",
            firstTsMs: ev.tsMs,
            lastTsMs: ev.tsMs,
            eventCount: 0,
            paths: new Set(),
            names: new Set(),
            reasonBuckets: new Set(),
            categories: new Set(),
            categoryKeys: new Set(),
            extensions: new Set(),
            tags: new Set(),
            promotionSignals: new Set(),
            trustTierCounts: new Map(),
            parentCounts: new Map(),
            fullPathCounts: new Map(),
            renamePairs: [],
            events: [],
            riskScore: 0,
            observedRiskScore: 0,
            promotedEventCount: 0,
          });
        }
        const chain = fileChainMap.get(key);
        chain.eventCount += 1;
        chain.firstTsMs = Math.min(chain.firstTsMs || ev.tsMs || Infinity, ev.tsMs || Infinity);
        chain.lastTsMs = Math.max(chain.lastTsMs || 0, ev.tsMs || 0);
        chain.firstSeen = chain.firstTsMs === ev.tsMs ? ev.timestamp : chain.firstSeen;
        chain.lastSeen = chain.lastTsMs === ev.tsMs ? ev.timestamp : chain.lastSeen;
        if (ev.fullPath) chain.paths.add(ev.fullPath);
        if (ev.fullPath) chain.fullPathCounts.set(ev.fullPath, (chain.fullPathCounts.get(ev.fullPath) || 0) + 1);
        if (ev.name) chain.names.add(ev.name);
        if (ev.extension) chain.extensions.add(ev.extension);
        if (ev.parentPath) chain.parentCounts.set(ev.parentPath, (chain.parentCounts.get(ev.parentPath) || 0) + 1);
        chain.reasonBuckets.add(ev.primaryReason);
        chain.categories.add(ev.categoryLabel);
        chain.categoryKeys.add(ev.category);
        ev.tags.forEach((t) => chain.tags.add(t));
        (ev.promotionSignals || []).forEach((sig) => chain.promotionSignals.add(sig));
        if (ev.trustTier?.key) chain.trustTierCounts.set(ev.trustTier.key, (chain.trustTierCounts.get(ev.trustTier.key) || 0) + 1);
        chain.riskScore = Math.max(chain.riskScore, ev.riskScore || 0);
        chain.observedRiskScore = Math.max(chain.observedRiskScore, ev.observedScore || ev.riskScore || 0);
        if (ev.promotionEligible) chain.promotedEventCount += 1;
        if (ev.oldName || ev.newName) chain.renamePairs.push({ oldName: ev.oldName, newName: ev.newName, timestamp: ev.timestamp, parentPath: ev.parentPath });
        if (chain.events.length < 200) chain.events.push(ev);
      }
      result.fileChains = [...fileChainMap.values()].map((ch) => {
        const correlationScore = [...ch.tags].reduce((sum, t) => sum + correlationWeight(t), 0);
        const crossModuleScore = crossModuleSynergyScore(ch.tags);
        const primaryDirectory = [...ch.parentCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || "";
        const primaryPath = [...ch.fullPathCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || [...ch.paths][0] || "";
        const pathTransitions = [...new Set((ch.events || []).map((ev) => ev.fullPath).filter(Boolean))];
        const aggregateEval = evaluateAggregateConfidence({
          tags: [...ch.tags],
          categoryKeys: [...ch.categoryKeys],
          reasonBuckets: [...ch.reasonBuckets],
          path: primaryDirectory || primaryPath,
          extensions: [...ch.extensions],
          eventCount: ch.eventCount,
          uniqueFiles: ch.names.size || ch.paths.size || ch.eventCount,
          promotedEventCount: ch.promotedEventCount,
          pathVariants: pathTransitions.length,
          trustTierCounts: ch.trustTierCounts,
          observedRiskScore: ch.observedRiskScore,
          baseCorrelationScore: correlationScore,
          baseCrossModuleScore: crossModuleScore,
          eventRateScore: Math.min(4, ch.eventCount >= 10 ? 4 : Math.floor(ch.eventCount / 3)),
          fileCountScore: Math.min(3, ch.reasonBuckets.size),
        });
        return {
          key: ch.key,
          entryNumber: ch.entryNumber,
          title: [...ch.names][0] || [...ch.paths][0] || "(unknown)",
          firstSeen: ch.firstSeen,
          lastSeen: ch.lastSeen,
          durationMs: Math.max(0, (ch.lastTsMs || 0) - (ch.firstTsMs || 0)),
          eventCount: ch.eventCount,
          paths: [...ch.paths],
          categories: [...ch.categories],
          categoryKeys: [...ch.categoryKeys],
          reasonBuckets: [...ch.reasonBuckets],
          tags: [...ch.tags],
          correlationTags: [...ch.tags].map((t) => ({ key: t, label: correlationLabelMap[t] || t })),
          renamePairs: ch.renamePairs,
          riskScore: ch.riskScore,
          observedRiskScore: ch.observedRiskScore,
          correlationScore,
          crossModuleScore,
          priorityScore: aggregateEval.priorityScore,
          observedPriorityScore: aggregateEval.observedPriorityScore,
          promotionSignals: aggregateEval.promotionSignals,
          requiredSignalCount: aggregateEval.requiredSignalCount,
          promotedEventCount: ch.promotedEventCount,
          highConfidence: aggregateEval.highConfidence,
          confidence: aggregateEval.confidence,
          trustTier: aggregateEval.trustTier,
          primaryDirectory,
          primaryPath,
          events: ch.events.sort((a, b) => (a.tsMs || 0) - (b.tsMs || 0)),
          extensions: [...ch.extensions],
          pathTransitions,
        };
      }).sort((a, b) => (b.priorityScore - a.priorityScore) || (b.riskScore - a.riskScore) || (b.eventCount - a.eventCount) || a.firstSeen.localeCompare(b.firstSeen));

      const chainsByDirectory = new Map();
      for (const ch of result.fileChains) {
        if (!ch.primaryDirectory) continue;
        if (!chainsByDirectory.has(ch.primaryDirectory)) chainsByDirectory.set(ch.primaryDirectory, []);
        chainsByDirectory.get(ch.primaryDirectory).push(ch);
      }
      result.fileChains = result.fileChains.map((ch) => {
        const peers = chainsByDirectory.get(ch.primaryDirectory) || [];
        const siblingArtifacts = peers
          .filter((p) => p.key !== ch.key)
          .sort((a, b) => b.priorityScore - a.priorityScore)
          .slice(0, 5)
          .map((p) => ({
            key: p.key,
            title: p.title,
            eventCount: p.eventCount,
            priorityScore: p.priorityScore,
            tags: p.tags,
          }));
        return {
          ...ch,
          sameDirectoryChainCount: Math.max(0, peers.length - 1),
          siblingArtifacts,
        };
      });

      const DIR_GAP_MS = 5 * 60 * 1000;
      const incidentMap = new Map();
      for (const ev of allEvents) {
        const baseKey = `${ev.parentPath || "(unknown)"}|${bucketForDirectory(ev)}`;
        if (!incidentMap.has(baseKey)) incidentMap.set(baseKey, []);
        const windows = incidentMap.get(baseKey);
        const last = windows[windows.length - 1];
        if (!last || !Number.isFinite(ev.tsMs) || !Number.isFinite(last.lastTsMs) || ev.tsMs - last.lastTsMs > DIR_GAP_MS) {
          windows.push({
            key: `${baseKey}|w${windows.length}`,
            path: ev.parentPath || "(unknown)",
            bucket: bucketForDirectory(ev),
            start: ev.timestamp,
            end: ev.timestamp,
            startTsMs: ev.tsMs,
            lastTsMs: ev.tsMs,
            eventCount: 0,
            files: new Set(),
            reasons: new Set(),
            categories: new Set(),
            categoryKeys: new Set(),
            tags: new Set(),
            promotionSignals: new Set(),
            trustTierCounts: new Map(),
            extensions: new Map(),
            events: [],
            riskScore: 0,
            observedRiskScore: 0,
            promotedEventCount: 0,
          });
        }
        const cur = windows[windows.length - 1];
        cur.eventCount += 1;
        cur.lastTsMs = Math.max(cur.lastTsMs || 0, ev.tsMs || 0);
        cur.end = cur.lastTsMs === ev.tsMs ? ev.timestamp : cur.end;
        if (ev.name) cur.files.add(ev.name);
        cur.reasons.add(ev.reasonLabel);
        cur.categories.add(ev.categoryLabel);
        cur.categoryKeys.add(ev.category);
        ev.tags.forEach((t) => cur.tags.add(t));
        (ev.promotionSignals || []).forEach((sig) => cur.promotionSignals.add(sig));
        if (ev.trustTier?.key) cur.trustTierCounts.set(ev.trustTier.key, (cur.trustTierCounts.get(ev.trustTier.key) || 0) + 1);
        if (ev.extension) cur.extensions.set(ev.extension, (cur.extensions.get(ev.extension) || 0) + 1);
        cur.riskScore = Math.max(cur.riskScore, ev.riskScore || 0);
        cur.observedRiskScore = Math.max(cur.observedRiskScore, ev.observedScore || ev.riskScore || 0);
        if (ev.promotionEligible) cur.promotedEventCount += 1;
        if (cur.events.length < 150) cur.events.push(ev);
      }
      for (const windows of incidentMap.values()) {
        const avgCount = windows.length > 0 ? (windows.reduce((sum, w) => sum + (w.eventCount || 0), 0) / windows.length) : 0;
        for (const win of windows) {
          const peers = windows.filter((other) => other !== win);
          const peerAvg = peers.length > 0 ? (peers.reduce((sum, other) => sum + (other.eventCount || 0), 0) / peers.length) : 0;
          win.localBaselineAvg = avgCount;
          win.localPeerAvg = peerAvg;
          win.localWindowCount = windows.length;
        }
      }
      result.directoryIncidents = [...incidentMap.values()].flat().map((inc) => {
        const durationMin = Math.max(1 / 60, ((inc.lastTsMs || 0) - (inc.startTsMs || 0)) / 60000);
        const eventsPerMinute = inc.eventCount / durationMin;
        const topExtensions = [...inc.extensions.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ext, count]) => ({ ext, count }));
        if (inc.bucket === "acl-change" && inc.files.size >= 5) inc.tags.add("acl-change-burst");
        if (inc.bucket === "overwrite" && inc.files.size >= 5) inc.tags.add("overwrite-burst");
        if (inc.bucket === "rename" && inc.files.size >= 3) inc.tags.add("rename-burst");
        if (inc.bucket === "stream-change") inc.tags.add("stream-activity");
        if ((inc.localWindowCount || 0) > 1) {
          if (inc.eventCount >= Math.max(5, Math.ceil((inc.localPeerAvg || inc.localBaselineAvg || 0) * 2))) inc.tags.add("local-burst");
        } else if (inc.eventCount >= 8 && eventsPerMinute >= 2) {
          inc.tags.add("local-burst");
        }
        const correlationScore = [...inc.tags].reduce((sum, t) => sum + correlationWeight(t), 0);
        const crossModuleScore = crossModuleSynergyScore(inc.tags);
        const aggregateEval = evaluateAggregateConfidence({
          tags: [...inc.tags],
          categoryKeys: [...inc.categoryKeys],
          reasonFamily: inc.bucket,
          reasonBuckets: [inc.bucket],
          path: inc.path,
          extensions: topExtensions.map((item) => item.ext),
          eventCount: inc.eventCount,
          uniqueFiles: inc.files.size,
          promotedEventCount: inc.promotedEventCount,
          trustTierCounts: inc.trustTierCounts,
          observedRiskScore: inc.observedRiskScore,
          baseCorrelationScore: correlationScore,
          baseCrossModuleScore: crossModuleScore,
          eventRateScore: Math.min(5, Math.round(eventsPerMinute)),
          fileCountScore: Math.min(4, inc.files.size >= 10 ? 4 : Math.floor(inc.files.size / 3)),
          tagCountScore: Math.min(3, inc.tags.size),
        });
        return {
          key: inc.key,
          title: makeIncidentTitle(inc.bucket, inc.path),
          path: inc.path,
          reasonFamily: inc.bucket,
          start: inc.start,
          end: inc.end,
          eventCount: inc.eventCount,
          uniqueFiles: inc.files.size,
          eventsPerMinute: Number(eventsPerMinute.toFixed(1)),
          categories: [...inc.categories],
          categoryKeys: [...inc.categoryKeys],
          reasons: [...inc.reasons],
          tags: [...inc.tags],
          correlationTags: [...inc.tags].map((t) => ({ key: t, label: correlationLabelMap[t] || t })),
          topExtensions,
          riskScore: inc.riskScore,
          observedRiskScore: inc.observedRiskScore,
          correlationScore,
          crossModuleScore,
          priorityScore: aggregateEval.priorityScore,
          observedPriorityScore: aggregateEval.observedPriorityScore,
          promotionSignals: aggregateEval.promotionSignals,
          requiredSignalCount: aggregateEval.requiredSignalCount,
          promotedEventCount: inc.promotedEventCount,
          highConfidence: aggregateEval.highConfidence,
          confidence: aggregateEval.confidence,
          trustTier: aggregateEval.trustTier,
          events: inc.events.sort((a, b) => (a.tsMs || 0) - (b.tsMs || 0)),
        };
      }).sort((a, b) => (b.priorityScore - a.priorityScore) || (b.eventCount - a.eventCount));

      result.timeline = allEvents.slice(0, 5000).map((ev) => ({
        key: ev.id,
        category: ev.category,
        categoryLabel: ev.categoryLabel,
        timestamp: ev.timestamp,
        entryNumber: ev.entryNumber,
        name: ev.name,
        displayName: ev.oldName && ev.newName ? `${ev.oldName} → ${ev.newName}` : ev.name,
        parentPath: ev.parentPath,
        fullPath: ev.fullPath,
        reasonLabel: ev.reasonLabel,
        reasonBuckets: ev.reasonBuckets,
        rawReasons: ev.rawReasons,
        tags: ev.tags,
        correlationTags: ev.tags.map((t) => ({ key: t, label: correlationLabelMap[t] || t })),
        riskScore: ev.riskScore,
        observedScore: ev.observedScore,
        promotionEligible: ev.promotionEligible,
        confidence: ev.confidence,
        trustTier: ev.trustTier,
        correlationScore: (ev.tags || []).reduce((sum, t) => sum + correlationWeight(t), 0),
        crossModuleScore: crossModuleSynergyScore(ev.tags || []),
      }));

      const correlationCounts = {};
      for (const ev of allEvents) {
        for (const t of ev.tags || []) correlationCounts[t] = (correlationCounts[t] || 0) + 1;
      }
      result.correlationSummary = Object.entries(correlationCounts)
        .map(([key, count]) => ({ key, label: correlationLabelMap[key] || key, count }))
        .sort((a, b) => b.count - a.count);

      result.sectionStats = {};
      for (const [secKey, secLabel] of Object.entries(categoryMeta)) {
        const secEvents = allEvents.filter((ev) => ev.category === secKey);
        if (secEvents.length === 0) continue;
        const highConfidenceEvents = secEvents.filter((ev) => ev.promotionEligible);
        const uniqueFiles = new Set(secEvents.map((ev) => ev.entryNumber || ev.fullPath || `${ev.parentPath}|${ev.name}`));
        const uniqueDirs = new Set(secEvents.map((ev) => ev.parentPath || "(unknown)"));
        const dirCounts = new Map();
        const reasonCounts = new Map();
        const extCounts = new Map();
        let firstTsMs = Infinity;
        let lastTsMs = 0;
        let maxRisk = 0;
        let maxObservedRisk = 0;
        let corrScore = 0;
        for (const ev of secEvents) {
          const dir = ev.parentPath || "(unknown)";
          dirCounts.set(dir, (dirCounts.get(dir) || 0) + 1);
          reasonCounts.set(ev.reasonLabel, (reasonCounts.get(ev.reasonLabel) || 0) + 1);
          if (ev.extension) extCounts.set(ev.extension, (extCounts.get(ev.extension) || 0) + 1);
          firstTsMs = Math.min(firstTsMs, ev.tsMs || Infinity);
          lastTsMs = Math.max(lastTsMs, ev.tsMs || 0);
          maxRisk = Math.max(maxRisk, ev.riskScore || 0);
          maxObservedRisk = Math.max(maxObservedRisk, ev.observedScore || ev.riskScore || 0);
          corrScore = Math.max(corrScore, (ev.tags || []).reduce((sum, t) => sum + correlationWeight(t), 0) + crossModuleSynergyScore(ev.tags || []));
        }
        const durationMin = Math.max(1 / 60, (lastTsMs - firstTsMs) / 60000 || 1 / 60);
        const eventsPerMinute = secEvents.length / durationMin;
        const topDirectory = [...dirCounts.entries()].sort((a, b) => b[1] - a[1])[0] || ["(unknown)", 0];
        const topReasons = [...reasonCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([label, count]) => ({ label, count }));
        const topExtensions = [...extCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([ext, count]) => ({ ext, count }));
        const sectionIncidents = result.directoryIncidents.filter((inc) => (inc.categories || []).includes(secLabel));
        const strongestIncident = sectionIncidents.sort((a, b) => b.priorityScore - a.priorityScore)[0] || null;
        const corroboratedPriority = Math.max(
          maxRisk + corrScore + Math.min(4, Math.round(eventsPerMinute)) + Math.min(4, Math.floor(uniqueFiles.size / 3)),
          strongestIncident?.priorityScore || 0
        );
        const observedPriority = Math.max(maxObservedRisk + Math.min(2, Math.round(eventsPerMinute)), strongestIncident?.observedPriorityScore || 0);
        const priorityScore = highConfidenceEvents.length > 0 || strongestIncident?.highConfidence ? corroboratedPriority : Math.min(observedPriority, 5);
        const severity = (highConfidenceEvents.length > 0 || strongestIncident?.highConfidence)
          ? (priorityScore >= 10 ? "high" : priorityScore >= 6 ? "medium" : "low")
          : (secEvents.length > 0 ? "low" : "low");
        result.sectionStats[secKey] = {
          key: secKey,
          label: secLabel,
          severity,
          priorityScore,
          observedPriorityScore: observedPriority,
          eventCount: secEvents.length,
          highConfidenceCount: highConfidenceEvents.length,
          uniqueFiles: uniqueFiles.size,
          uniqueDirs: uniqueDirs.size,
          eventsPerMinute: Number(eventsPerMinute.toFixed(1)),
          topDirectory: { path: topDirectory[0], count: topDirectory[1] },
          topReasons,
          topExtensions,
          strongestIncidentKey: strongestIncident?.key || "",
        };
      }

      const incidentFindings = result.directoryIncidents.filter((inc) => inc.highConfidence).slice(0, 4).map((inc) => {
        const durationMin = findingDurationMinutes(inc.start, inc.end);
        const entryNumber = inc.events?.find((ev) => ev.entryNumber)?.entryNumber;
        return {
          key: `incident:${inc.key}`,
          sourceType: "directoryIncident",
          sourceKey: inc.key,
          title: inc.title,
          summary: [
            `${inc.eventCount} events across ${inc.uniqueFiles} files`,
            inc.path && inc.path !== "(unknown)" ? `under ${inc.path}` : "in an unresolved directory",
            durationMin ? `over ${durationMin} minute(s)` : null,
          ].filter(Boolean).join(" "),
          rationale: explainIncidentFinding(inc),
          severity: severityForPriority(inc.priorityScore || inc.riskScore || 0),
          priorityScore: inc.priorityScore || inc.riskScore || 0,
          path: inc.path || "",
          primaryPath: inc.path || "",
          entryNumber: entryNumber != null ? String(entryNumber) : "",
          start: inc.start || "",
          end: inc.end || "",
          eventCount: inc.eventCount || 0,
          uniqueFiles: inc.uniqueFiles || 0,
          reasonFamily: inc.reasonFamily || "",
          categories: inc.categories || [],
          tags: inc.tags || [],
          confidence: inc.confidence || "medium",
          correlationTags: inc.correlationTags || [],
          evidence: buildEvidenceList({
            reasonBuckets: inc.reasonFamily ? [inc.reasonFamily] : [],
            tags: inc.tags || [],
            topExtensions: inc.topExtensions || [],
            categories: inc.categories || [],
          }),
        };
      });
      const chainFindings = result.fileChains.filter((ch) => ch.highConfidence).slice(0, 4).map((ch) => {
        const durationMin = Number.isFinite(ch.durationMs) ? Math.max(1, Math.round(ch.durationMs / 60000)) : null;
        return {
          key: `chain:${ch.key}`,
          sourceType: "fileChain",
          sourceKey: ch.key,
          title: ch.title,
          summary: [
            `${ch.eventCount} events touching ${ch.primaryPath || ch.title || "(unknown)"}`,
            (ch.pathTransitions?.length || 0) > 1 ? `across ${ch.pathTransitions.length} path variants` : null,
            durationMin ? `over ${durationMin} minute(s)` : null,
          ].filter(Boolean).join(" "),
          rationale: explainChainFinding(ch),
          severity: severityForPriority(ch.priorityScore || ch.riskScore || 0),
          priorityScore: ch.priorityScore || ch.riskScore || 0,
          path: ch.primaryDirectory || "",
          primaryPath: ch.primaryPath || "",
          entryNumber: ch.entryNumber != null ? String(ch.entryNumber) : "",
          start: ch.firstSeen || "",
          end: ch.lastSeen || "",
          eventCount: ch.eventCount || 0,
          pathVariants: ch.pathTransitions?.length || 0,
          sameDirectoryChainCount: ch.sameDirectoryChainCount || 0,
          categories: ch.categories || [],
          reasonBuckets: ch.reasonBuckets || [],
          tags: ch.tags || [],
          confidence: ch.confidence || "medium",
          correlationTags: ch.correlationTags || [],
          evidence: buildEvidenceList({
            reasonBuckets: ch.reasonBuckets || [],
            tags: ch.tags || [],
            topExtensions: ch.extensions || [],
            categories: ch.categories || [],
          }),
        };
      });
      // Mass-activity finding from the TRUE full-window volume, so a mass-destruction incident
      // ranks high even when the per-section sample (and the bursts derived from it) is capped.
      const v = result.summary?.volume || {};
      const massActivityFinding = (() => {
        const dt = v.destructiveTotal || 0;
        const peak = v.peakDestructivePerMinute || 0;
        const topExt = v.topDestructiveExtension || ""; // already dot-prefixed, e.g. ".locked"
        // Ransomware overwrites/renames to ONE uniform extension; benign bulk dev/admin churn
        // (npm ci, git checkout, uninstall) touches many — extension homogeneity is the
        // corroborating discriminator. BUT low-signal types (.log/.tmp/.etl/.pf/...) are exactly
        // the analyzer's existing noise class (LOW_SIGNAL_EXTS) — homogeneous log rotation / temp /
        // cache cleanup is NOT a ransomware signature, so it does not count as homogeneous here.
        const homogeneous = (v.topDestructiveExtensionShare || 0) >= 0.5 && !!topExt && !LOW_SIGNAL_EXTS.has(topExt);
        // Fire on a real BURST (encryption/wiping is fast) OR a large homogeneous destructive set
        // (slow/throttled ransomware that still renames everything to one extension). A cumulative
        // count over a long (now default full-journal) window is NOT a severity signal on its own —
        // every real host accumulates thousands of diverse deletes over the journal's retention.
        if (peak < 100 && !(homogeneous && dt >= 1000)) return null;
        const severity = (peak >= 1000 && homogeneous) ? "critical"
          : (peak >= 1000 || (peak >= 300 && homogeneous)) ? "high"
          : (peak >= 300) ? "medium"
          : homogeneous ? "medium" : "low";
        const truncatedSections = ["deletions", "creations", "dataOverwrite", "streamChanges"].filter((k) => result[k]?.truncated);
        return {
          key: "mass-activity",
          sourceType: "volume",
          title: homogeneous ? `Mass file activity — possible ransomware (${topExt})` : "High-rate destructive file activity (burst)",
          summary: `${peak.toLocaleString()} destructive ops/min peak${homogeneous ? `, ${Math.round((v.topDestructiveExtensionShare || 0) * 100)}% to ${topExt}` : ""} (${dt.toLocaleString()} total: ${(v.overwrite || 0).toLocaleString()} overwrite, ${(v.delete || 0).toLocaleString()} delete, ${(v.rename || 0).toLocaleString()} rename)`,
          rationale: homogeneous
            ? `A destructive burst (${peak.toLocaleString()}/min) concentrated on a single extension (${topExt}) is the ransomware encryption/wiping signature${truncatedSections.length ? ` — and the ${truncatedSections.join(", ")} tables below are truncated samples` : ""}. Confirm the responsible process and whether a ransom note was created.`
            : `A high-rate destructive burst (${peak.toLocaleString()}/min) across many extensions. This can be ransomware/wiping OR routine bulk activity (build, checkout, uninstall, sync). Corroborate the dominant extension, paths, and the responsible process before escalating.`,
          severity,
          priorityScore: severity === "critical" ? 16 : severity === "high" ? 11 : severity === "medium" ? 7 : 3,
          eventCount: dt,
          peakPerMinute: peak,
          confidence: "observed",
          tags: ["mass-activity", "burst", ...(homogeneous ? ["uniform-extension"] : [])],
          categories: [],
          evidence: [],
        };
      })();
      // Covert MFT-record-reuse finding (a deleted file replaced in the same slot).
      const reuseFinding = result.fileReuse.length > 0 ? (() => {
        const execReuse = result.fileReuse.filter((r) => r.hasExecutable);
        const n = result.fileReuse.length;
        const severity = execReuse.length > 0 ? "high" : "medium";
        const top = result.fileReuse[0];
        const topParent = top.generations?.find((g) => g.parent)?.parent || "";
        return {
          key: "mft-reuse",
          sourceType: "fileReuse",
          title: "MFT record reuse — covert delete + replace",
          summary: `${n} MFT entr${n === 1 ? "y was" : "ies were"} reused (record freed then reallocated)${execReuse.length ? `, ${execReuse.length} involving executables` : ""}. e.g. ${top.summary}`,
          rationale: "A reused MFT entry means a file was deleted and a NEW file took its slot — a way to hide the original file's metadata from $MFT. Inspect each generation; a deleted executable replaced by another is high-signal.",
          severity,
          priorityScore: severity === "high" ? 10 : 6,
          eventCount: n,
          // Navigation anchors so the existing finding pivots (File Chain / This Directory) work.
          entryNumber: String(top.entry || ""),
          path: topParent,
          primaryPath: topParent,
          confidence: "observed",
          tags: ["mft-reuse", ...(execReuse.length ? ["executable"] : [])],
          categories: [],
          evidence: [],
        };
      })() : null;
      // Masquerading finding (disguised executable/archive payloads).
      const masqFinding = result.masquerade.length > 0 ? (() => {
        const n = result.masquerade.length;
        const top = result.masquerade[0];
        const allTags = [...new Set(result.masquerade.flatMap((m) => m.reasons))];
        return {
          key: "masquerade",
          sourceType: "masquerade",
          title: "Masqueraded payloads (disguised executables)",
          summary: `${n} disguised payload${n === 1 ? "" : "s"} via ${allTags.join(", ")} — e.g. ${top.name}${top.parent ? ` in ${top.parent}` : ""}`,
          rationale: "Executable/archive payloads disguised with a decoy extension (e.g. invoice.pdf.exe), a right-to-left override hiding the real extension, or whitespace padding — a classic social-engineering / defense-evasion technique (MITRE T1036.002 / T1036.007). Inspect the responsible process and origin.",
          severity: "high",
          priorityScore: 12,
          eventCount: n,
          path: top.parent || "",
          primaryPath: top.parent || "",
          confidence: "observed",
          tags: ["masquerade", ...allTags],
          categories: [],
          evidence: [],
        };
      })() : null;
      // Self-deletion finding (executable dropped + removed).
      const selfDeleteFinding = result.selfDeleted.length > 0 ? (() => {
        const n = result.selfDeleted.length;
        const immediate = result.selfDeleted.filter((s) => s.immediate).length;
        const top = result.selfDeleted[0];
        return {
          key: "self-delete", sourceType: "selfDelete",
          title: "Self-deleting executables (drop + cleanup)",
          summary: `${n} executable${n === 1 ? "" : "s"} created then deleted${immediate ? `, ${immediate} within 15 min` : ""} — e.g. ${top.name}${top.lifetimeMin != null ? ` (lived ${top.lifetimeMin} min)` : ""}`,
          rationale: "An executable created and deleted in the window is the classic dropper/cleanup pattern (drop, run, self-delete to evade post-incident recovery). Short-lived ones are high-signal; recover the file from VSS/$MFT/$LogFile if possible.",
          severity: immediate > 0 ? "high" : "medium",
          priorityScore: immediate > 0 ? 12 : 7,
          eventCount: n, path: top.parent || "", primaryPath: top.parent || "", entryNumber: String(top.entry || ""),
          confidence: "observed", tags: ["self-delete", ...(immediate > 0 ? ["immediate"] : [])], categories: [], evidence: [],
        };
      })() : null;
      // MOTW / Zone.Identifier stripping finding.
      const motwFinding = result.motwStripped.length > 0 ? (() => {
        const n = result.motwStripped.length;
        const top = result.motwStripped[0];
        return {
          key: "motw-strip", sourceType: "motwStrip",
          title: "ADS / stream removal on executables (possible MOTW stripping)",
          summary: `${n} payload${n === 1 ? " had" : "s had"} a named stream removed${result.motwStripped.filter((m) => m.isZoneId).length ? ` (${result.motwStripped.filter((m) => m.isZoneId).length} confirmed Zone.Identifier)` : ""} — e.g. ${top.file}${top.parent ? ` in ${top.parent}` : ""}`,
          rationale: "Removing a named data stream from a surviving payload (StreamChange + truncation) is how Mark-of-the-Web is stripped (Unblock-File / Remove-Item -Stream / streams.exe), defeating SmartScreen and Office macro-blocking (MITRE T1070.004 / T1553.005). HEURISTIC from USN reason flags — confirm the stream is Zone.Identifier and the file's origin.",
          severity: "medium", priorityScore: 8, eventCount: n, path: top.parent || "", primaryPath: top.parent || "",
          confidence: "observed", tags: ["motw-strip", "defense-evasion"], categories: [], evidence: [],
        };
      })() : null;
      result.likelyFindings = [...(massActivityFinding ? [massActivityFinding] : []), ...(reuseFinding ? [reuseFinding] : []), ...(masqFinding ? [masqFinding] : []), ...(selfDeleteFinding ? [selfDeleteFinding] : []), ...(motwFinding ? [motwFinding] : []), ...incidentFindings, ...chainFindings]
        .sort((a, b) => (b.priorityScore - a.priorityScore)
          || ((b.eventCount || 0) - (a.eventCount || 0))
          || (a.sourceType === b.sourceType ? 0 : (a.sourceType === "directoryIncident" ? -1 : 1)))
        .slice(0, 8);

      const topIncident = result.directoryIncidents[0];
      const topExec = result.execution?.events?.length || 0;
      const highConfidenceExec = allEvents.filter((ev) => ev.category === "execution" && ev.promotionEligible).length;
      const topExfil = result.exfil?.archives?.length || 0;
      const highConfidenceExfil = allEvents.filter((ev) => ev.category === "exfil" && ev.promotionEligible).length;
      const topPersist = result.persistence?.events?.length || 0;
      const topRename = result.renames?.events?.length || 0;
      result.narrative = [
        massActivityFinding ? `${massActivityFinding.summary} (full-window volume; the section tables below may be truncated samples)` : null,
        topIncident && topIncident.highConfidence ? `${topIncident.uniqueFiles} files had corroborated ${topIncident.reasonFamily.replace("-", " ")} activity under ${topIncident.path} in ${Math.max(1, Math.round((parseTs(topIncident.end) - parseTs(topIncident.start)) / 60000))} minute(s)` : null,
        topExec > 0 ? `${topExec} executable/script artifacts were observed; ${highConfidenceExec} met the corroborated suspicious threshold` : null,
        topExfil > 0 ? `${topExfil} archive artifacts were observed; ${highConfidenceExfil} met the corroborated exfil/staging threshold` : null,
        topPersist > 0 ? `${topPersist} events touched persistence-related paths` : null,
        result.correlationSummary?.length > 0 ? `${result.correlationSummary.slice(0, 3).map((c) => `${c.count} ${c.label.toLowerCase()}`).join(", ")}` : null,
        result.likelyFindings.length === 0 && totalEvents > 0 ? "Observed activity did not produce corroborated high-confidence intrusion findings in this window" : null,
        topRename > 0 ? `${topRename} rename pairs were observed in this window` : "No meaningful rename activity in the selected window",
      ].filter(Boolean);

      return result;
    } catch (err) {
      return { ...empty, error: err.message };
    }
}

/**
 * USN Journal Rewind — resolve ParentPath from the journal's own directory records.
 * Processes directory entries in reverse chronological order (newest first) to build
 * a directory tree, then chain-walks parent references to reconstruct full paths.
 * When mftTabId is provided, uses MFT directory data as fallback for unresolved entries.
 */
function resolveUsnPaths(meta, mftTabId, getDatabaseMeta) {
    if (!meta) return { resolved: 0, total: 0 };

    const col = (name) => meta.colMap[name];
    const nameCol = col("Name");
    const entryCol = col("EntryNumber");
    const seqCol = col("SequenceNumber");
    const parentEntryCol = col("ParentEntryNumber");
    const parentSeqCol = col("ParentSequenceNumber");
    const parentPathCol = col("ParentPath");
    const attrsCol = col("FileAttributes");
    const tsCol = col("UpdateTimestamp");

    if (!nameCol || !entryCol || !parentEntryCol || !parentPathCol || !attrsCol) {
      return { resolved: 0, total: 0, error: "Missing required columns" };
    }

    try {
      // Step 1: Query all directory records, newest first (rewind order)
      let dirRecords;
      try {
        dirRecords = meta.db.prepare(`
          SELECT ${entryCol} as entry, ${seqCol} as seq, ${nameCol} as name,
                 ${parentEntryCol} as parentEntry, ${parentSeqCol} as parentSeq
          FROM data WHERE ${attrsCol} LIKE '%Directory%'
          ORDER BY sort_datetime(${tsCol}) DESC, rowid
        `).all();
      } catch (e) {
        dbg("DB", `USN rewind: $J directory query fallback`, { error: e.message });
        // Fallback: try without ORDER BY (sort_datetime might fail)
        try {
          dirRecords = meta.db.prepare(`
            SELECT ${entryCol} as entry, ${seqCol} as seq, ${nameCol} as name,
                   ${parentEntryCol} as parentEntry, ${parentSeqCol} as parentSeq
            FROM data WHERE ${attrsCol} LIKE '%Directory%'
          `).all();
        } catch (e2) {
          return { resolved: 0, total: 0, error: "$J query failed: " + e2.message };
        }
      }

      // Build dirMap — first seen (= most recent) wins per entry-seq pair
      // Keys must be strings — SQLite may return numbers for numeric values
      const dirMap = new Map();
      for (const r of dirRecords) {
        const key = String(r.entry) + "-" + String(r.seq || 0);
        if (!dirMap.has(key)) {
          dirMap.set(key, {
            name: r.name,
            parentEntry: String(r.parentEntry),
            parentSeq: String(r.parentSeq || 0),
          });
        }
      }

      // Step 2: MFT augmentation (when available — skip if MFT db is busy building indexes)
      const mftPathMap = new Map();
      if (mftTabId) {
        const mftMeta = getDatabaseMeta(mftTabId);
        if (mftMeta && !mftMeta.indexesBuilding) {
          try {
            const mEntry = mftMeta.colMap["EntryNumber"];
            const mName = mftMeta.colMap["FileName"];
            const mPath = mftMeta.colMap["ParentPath"];
            const mIsDir = mftMeta.colMap["IsDirectory"];
            if (mEntry && mName && mPath && mIsDir) {
              const mftDirs = mftMeta.db.prepare(
                `SELECT ${mEntry} as entry, ${mName} as name, ${mPath} as parentPath
                 FROM data WHERE ${mIsDir} = 'True'`
              ).all();
              for (const d of mftDirs) {
                const fullPath = d.parentPath
                  ? d.parentPath + "\\" + d.name
                  : ".\\" + d.name;
                mftPathMap.set(String(d.entry), fullPath);
              }
            }
          } catch (e) {
            dbg("DB", `USN rewind: MFT query skipped`, { error: e.message });
            // Continue without MFT — self-resolution still works
          }
        } else if (mftMeta?.indexesBuilding) {
          dbg("DB", `USN rewind: MFT still building indexes — deferring augmentation`);
        }
      }

      // Step 3: Resolve paths via chain walk
      const pathCache = new Map();
      function resolvePath(entry, seq) {
        const key = String(entry) + "-" + String(seq);
        if (pathCache.has(key)) return pathCache.get(key);

        const parts = [];
        let current = key;
        const visited = new Set();

        while (current) {
          if (visited.has(current)) break;
          visited.add(current);

          const dir = dirMap.get(current);
          if (!dir) {
            // Try MFT fallback for the current entry number
            const entryOnly = current.split("-")[0];
            const mftPath = mftPathMap.get(entryOnly);
            if (mftPath) {
              parts.unshift(mftPath);
            }
            break;
          }

          if (dir.name !== "." && dir.name !== "..") {
            parts.unshift(dir.name);
          }

          // Root directory (entry 5) = NTFS root
          if (dir.parentEntry === "5") break;
          const parentKey = dir.parentEntry + "-" + dir.parentSeq;
          if (parentKey === current) break;
          current = parentKey;
        }

        const resolved = parts.length > 0 ? ".\\" + parts.join("\\") : "";
        pathCache.set(key, resolved);
        return resolved;
      }

      // Step 4: Resolve paths and batch UPDATE
      // We page through rows by rowid (keyset pagination) instead of loading the entire
      // table with .all() — a multi-GB $J can have tens of millions of rows and would OOM
      // the main process. Each page is fully materialized and consumed before its UPDATE
      // runs. Updating ParentPath does not affect the rowid-ordered paging.
      // Each page's resolved paths are loaded into a staging table and applied with one
      // UPDATE … FROM (DuckDB rewrites a column far faster as a set than row by row).
      const PAGE_SIZE = 50000;
      const selectPage = meta.db.prepare(
        `SELECT rowid, ${parentEntryCol} as parentEntry, ${parentSeqCol} as parentSeq
         FROM data WHERE rowid > ? ORDER BY rowid LIMIT ?`
      );
      meta.db.exec("DROP TABLE IF EXISTS _usn_paths; CREATE TABLE _usn_paths (rid BIGINT, path VARCHAR)");
      const pause = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
      const updateBatch = (updates) => {
        meta.db.exec("DELETE FROM _usn_paths");
        meta.db.appendRows("_usn_paths", updates.map((u) => [u.rowid, u.path]));
        // The background sort-key build may be writing this table at the same moment; DuckDB
        // then reports a conflict instead of waiting for the lock as SQLite did. Retry briefly.
        for (let attempt = 0; ; attempt++) {
          try {
            meta.db.exec(`UPDATE data SET ${parentPathCol} = p.path FROM _usn_paths p WHERE data.rowid = p.rid`);
            return;
          } catch (e) {
            if (attempt >= 20 || !/conflict/i.test(e?.message || "")) throw e;
            pause(250);
          }
        }
      };

      let resolved = 0, mftResolved = 0, total = 0;
      let lastRowid = 0;

      for (;;) {
        const page = selectPage.all(lastRowid, PAGE_SIZE);
        if (page.length === 0) break;

        const batch = [];
        for (const row of page) {
          total++;
          lastRowid = row.rowid;
          const pe = String(row.parentEntry);
          const ps = String(row.parentSeq || 0);
          const path = resolvePath(pe, ps);
          if (path) {
            batch.push({ path, rowid: row.rowid });
            resolved++;
            if (!dirMap.has(pe + "-" + ps) && mftPathMap.size > 0) {
              mftResolved++;
            }
          }
        }
        if (batch.length > 0) updateBatch(batch);
      }
      meta.db.exec("DROP TABLE IF EXISTS _usn_paths");

      const stats = {
        resolved,
        total,
        mftResolved,
        selfResolved: resolved - mftResolved,
        unresolved: total - resolved,
        resolvedPercent: total > 0 ? Math.round((resolved / total) * 100) : 0,
        directoriesFound: dirMap.size,
        mftEntriesUsed: mftPathMap.size,
      };
      return stats;
    } catch (err) {
      return { resolved: 0, total: 0, error: err.message };
    }
}

module.exports = { analyzeUsnJournal, resolveUsnPaths };
