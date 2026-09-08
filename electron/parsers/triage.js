/**
 * parsers/triage.js — recognize Windows forensic artifacts in a triage/KAPE collection folder.
 *
 * The strategy: artifacts are INPUTS, detected and routed — not per-artifact menu buttons. This
 * classifies files by name/extension (no content reads, so it's fast over large trees) so the
 * triage orchestrator can run the right parser once per present type and report the rest. Adding
 * a future artifact = one classification rule here, not a new menu item.
 */

const fs = require("fs");
const path = require("path");

// Machine registry hives (browse + persistence + ShimCache). User hives (NTUSER/UsrClass) are a
// separate kind because they additionally feed Shellbags/UserAssist decoders.
const MACHINE_HIVES = new Set(["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "COMPONENTS", "DRIVERS"]);

// A Chromium browser-profile container segment — gates the ambiguous extension-less "History" basename.
// Covers Win/Linux "User Data\<Profile>\" and the vendor\<Profile>\ layouts (Edge/Brave/Opera/Vivaldi,
// incl. macOS "Application Support/<Vendor>/<Profile>/").
const CHROMIUM_PROFILE_RE = /(?:[\\/]User Data[\\/][^\\/]+[\\/])|(?:[\\/](?:Google[\\/]Chrome|Microsoft Edge|BraveSoftware|Chromium|Opera Software|Opera|Vivaldi)[\\/][^\\/]+[\\/])/i;
const GPO_PATH_RE = /[\\/](?:GroupPolicy|GroupPolicyUsers|SYSVOL[\\/].*?[\\/]Policies)[\\/]/i;
const GPO_SCRIPT_RE = /[\\/](?:Machine|User)[\\/]Scripts[\\/](?:Startup|Shutdown|Logon|Logoff)[\\/].+\.(?:ps1|bat|cmd|vbs|vbe|js|jse|wsf|hta)$/i;
const RMM_PATH_RE = /[\\/](?:TeamViewer|AnyDesk|ScreenConnect|ConnectWise(?: Control)?|Splashtop|Atera|RustDesk|N-able|Nable|Kaseya|Datto|Syncro|TacticalRMM|MeshCentral|DWAgent|ZohoAssist|Supremo|LogMeIn|GoToAssist|Bomgar|BeyondTrust)(?:[\\/]|$)/i;
const RMM_FILE_RE = /(?:TeamViewer.*\.log|ad_svc\.trace|ad_.*\.trace|RustDesk.*\.(?:log|toml|conf)|ScreenConnect.*\.(?:log|config)|ConnectWise.*\.(?:log|config)|Splashtop.*\.log|Atera.*\.log)$/i;

// Human labels for the manifest/summary.
const KIND_LABELS = {
  prefetch: "Prefetch", lnk: "LNK shortcuts", jumplist: "Jump Lists", amcache: "Amcache",
  userHive: "User hives (NTUSER/UsrClass)", registryHive: "Registry hives", evtx: "EVTX logs",
  mft: "$MFT", usn: "$J (USN Journal)", rdp: "RDP bitmap cache", recyclebin: "Recycle Bin ($I)",
  kapeCsv: "Parsed EZ-Tools CSVs",
  pcaAppLaunch: "AppCompat PCA (last-launch)", psReadline: "PowerShell console history",
  setupapiDev: "SetupAPI device installs (USB)", chromiumHistory: "Browser History (Chromium)",
  winTimeline: "Windows Timeline (ActivitiesCache)", firefoxHistory: "Browser History (Firefox)",
  chromiumAutofill: "Browser Autofill (Chromium)", mplog: "Defender MPLog (execution/detection)",
  srudb: "SRUM (Resource Usage / SRUDB.dat)",
  scheduledTask: "Scheduled Tasks (XML)",
  defenderDetection: "Defender Detections (MPDetection)",
  eventTranscript: "DiagTrack telemetry (EventTranscript)",
  logFile: "$LogFile (NTFS journal)",
  webcache: "IE/legacy Edge WebCache (WebCacheV01.dat)",
  bits: "BITS transfer queue (qmgr*.dat)",
  windowsSearch: "Windows Search index (Windows.edb / Windows.db)",
  plaso: "Plaso timeline",
  wbemRepository: "WBEM repository (OBJECTS.DATA)",
  wer: "Windows Error Reporting (.wer)",
  groupPolicy: "Group Policy artifacts",
  remoteAdmin: "Remote Admin / RMM logs",
};

// ── KAPE Module-output (EZ-Tools parsed CSV) recognition ──────────────────────────────
//
// A KAPE *Targets* collection holds RAW artifacts (what classifyFile recognizes by name); a KAPE
// *Modules* run executes EZ-Tools and emits already-PARSED CSVs into a `*_M_Out`/ModuleResults
// folder. Those CSVs are timeline-able: the Super Timeline's CSV-explode lane reads EZ-Tools column
// names verbatim. We recognize a CSV by its HEADER signature (authoritative; the EZ-Tools/Collector
// schemas are stable) and map it to one of the worker's CSV kinds. Only KAPE/EZ-named CSVs are
// content-peeked (preserving the "no content read" speed for arbitrary CSV-heavy folders).

// Cheap name pre-filter: a KAPE module CSV either ends in `_Output.csv`, is an SBECmd per-hive
// shellbag CSV (`<user>_UsrClass.csv` / `<user>_NTUSER.csv` — no `_Output` suffix), or carries an
// EZ-Tools token. The header signature remains the authority; this just bounds which CSVs are peeked.
const EZ_CSV_RE = /(?:_Output\.csv$)|(?:_(?:UsrClass|NTUSER)\.csv$)|(?:EvtxECmd|PECmd|LECmd|JLECmd|SBECmd|MFTECmd|RBCmd|RECmd|SrumECmd|Amcache|AppCompatCache|AutomaticDestinations|CustomDestinations|Shellbag|Hayabusa|Chainsaw|WxTCmd|BrowsingHistory|_Timeline)/i;

// Header-column signatures → Super Timeline CSV kind (ordered: most-specific first; jumplist before
// lnk because both carry TargetIDAbsolutePath). v1 covers the kinds the normalizer already maps from
// EZ-Tools columns (prefetch/lnk/jumplist/shellbag) plus the one genuine gap, EvtxECmd event logs.
const KAPE_CSV_SIGNATURES = [
  { kind: "evtxEcmd", test: (h) => h.has("EventId") && h.has("Channel") && (h.has("MapDescription") || h.has("Provider") || h.has("PayloadData1")) },
  { kind: "jumplist", test: (h) => h.has("AppId") && h.has("TargetIDAbsolutePath") },
  { kind: "lnk", test: (h) => h.has("TargetIDAbsolutePath") && h.has("SourceFile") && (h.has("LocalPath") || h.has("RelativePath")) },
  { kind: "prefetch", test: (h) => h.has("ExecutableName") && h.has("RunCount") },
  { kind: "shellbag", test: (h) => h.has("AbsolutePath") && h.has("ShellType") },
  // Filesystem + registry + execution twins (MFTECmd/RBCmd/AmcacheParser/AppCompatCacheParser/RECmd).
  { kind: "mftCsv", test: (h) => h.has("Created0x10") && h.has("LastModified0x10") && h.has("ParentPath") },
  { kind: "usnCsv", test: (h) => h.has("UpdateTimestamp") && h.has("UpdateReasons") },
  { kind: "recyclebinCsv", test: (h) => h.has("DeletedOn") && h.has("FileName") && h.has("SourceName") },
  { kind: "amcacheCsv", test: (h) => h.has("FileKeyLastWriteTimestamp") && h.has("FullPath") },
  { kind: "shimcacheCsv", test: (h) => h.has("LastModifiedTimeUTC") && h.has("Path") },
  { kind: "registryCsv", test: (h) => h.has("KeyPath") && h.has("LastWriteTimestamp") && h.has("HivePath") },
];

/** Read just the header line of a CSV (≤16KB, one fd read) → array of column names. "" on any error. */
function peekCsvColumns(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(16384);
    const bytes = fs.readSync(fd, buf, 0, buf.length, 0);
    let text = buf.toString("utf8", 0, bytes);
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1); // strip UTF-8 BOM
    const nl = text.search(/\r?\n/);
    const headerLine = nl >= 0 ? text.slice(0, nl) : text;
    const delim = (headerLine.match(/\t/g) || []).length > (headerLine.match(/,/g) || []).length ? "\t" : ",";
    return headerLine.split(delim).map((h) => h.trim().replace(/^"|"$/g, ""));
  } catch { return []; } finally { if (fd != null) { try { fs.closeSync(fd); } catch { /* ignore */ } } }
}

/** Map a set of header columns to a Super Timeline CSV kind, or null. Pure (testable without files). */
function classifyKapeCsvColumns(cols) {
  if (!cols || !cols.length) return null;
  const h = new Set(cols);
  for (const sig of KAPE_CSV_SIGNATURES) if (sig.test(h)) return sig.kind;
  return null;
}

/** Classify a parsed EZ-Tools/KAPE CSV file by its header → ST CSV kind (prefetch/lnk/…/evtxEcmd) or null. */
function classifyKapeCsv(filePath) {
  return classifyKapeCsvColumns(peekCsvColumns(filePath));
}

/**
 * Bounded probe used by the zero-result path: does this folder look like KAPE Module output (parsed
 * EZ-Tools CSVs) rather than a raw collection? Walks shallowly, name-pre-filters CSVs, header-peeks
 * the matches. Returns the recognized ST kinds + a sample filename so the UI can guide the user.
 */
function detectModuleOutput(dir, opts = {}) {
  const maxFiles = opts.maxFiles || 5000;
  const maxDepth = opts.maxDepth || 8;
  const kinds = new Set();
  let csvSeen = 0, sampleName = "", scanned = 0;
  const stack = [{ d: dir, depth: 0 }];
  while (stack.length) {
    const { d, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.isDirectory()) { if (!e.isSymbolicLink() && depth < maxDepth) stack.push({ d: path.join(d, e.name), depth: depth + 1 }); continue; }
      if (!e.isFile()) continue;
      if (++scanned > maxFiles) return { isModuleOutput: csvSeen > 0, kinds: [...kinds], sampleName, csvSeen };
      if (path.extname(e.name).toLowerCase() !== ".csv" || !EZ_CSV_RE.test(e.name)) continue;
      csvSeen++;
      if (!sampleName) sampleName = e.name;
      const k = classifyKapeCsv(path.join(d, e.name));
      if (k) kinds.add(k);
    }
  }
  return { isModuleOutput: csvSeen > 0, kinds: [...kinds], sampleName, csvSeen };
}

/** Classify a file path into an artifact kind, or null if unrecognized. */
function classifyFile(filePath) {
  const base = path.basename(filePath);
  const upper = base.toUpperCase();
  const ext = path.extname(filePath).toLowerCase();

  // Recycle Bin `$I` index files live ONLY under $Recycle.Bin\<SID>\ — match the FULL path BEFORE the
  // extension rules, because a deleted .lnk/.pf/.evtx/*.Destinations-ms leaves a $I<id>.<ext> that
  // those rules would otherwise claim (dropping the deletion record). Requiring the $Recycle.Bin\<SID>
  // container also kills false positives (a stray $I…-named file elsewhere) and guarantees the SID is
  // derivable for attribution. The $R<id> content file (not $I) correctly falls through.
  if (/\$Recycle\.Bin[\\/]S-[\d-]+[\\/]\$I[A-Za-z0-9]+(\.[^\\/]*)?$/i.test(filePath)) return "recyclebin";

  // Scheduled-task 2.0 XML lives under \Windows\System32\Tasks\<name> (no extension; the dir holds
  // only task XML + subdirs, so the path is authoritative). Legacy \Windows\Tasks\*.job is binary — skipped.
  if (/[\\/]System32[\\/]Tasks[\\/].+/i.test(filePath)) return "scheduledTask";

  if (ext === ".pf") return "prefetch";
  if (ext === ".lnk") return "lnk";
  if (/\.(automatic|custom)destinations-ms$/i.test(base)) return "jumplist";
  if (upper === "AMCACHE.HVE") return "amcache";
  if (upper === "NTUSER.DAT" || upper === "USRCLASS.DAT") return "userHive";
  if (MACHINE_HIVES.has(upper)) return "registryHive";
  // Lane C plaintext text artifacts (exact basenames; setupapi.dev.log incl. rotated *.YYYYMMDD_*.log).
  if (upper === "PCAAPPLAUNCHDIC.TXT") return "pcaAppLaunch";
  if (upper === "CONSOLEHOST_HISTORY.TXT") return "psReadline";
  if (/^setupapi\.dev.*\.log$/i.test(base)) return "setupapiDev";
  if (/^MPLog-.*\.log$/i.test(base)) return "mplog"; // Defender MPLog-YYMMDD-hhmmss.log
  if (/^MPDetection-.*\.log$/i.test(base)) return "defenderDetection"; // Defender detection log (threats + AV service)
  // Lane B: Chromium "History" SQLite. The basename is extension-less + ambiguous, so REQUIRE a browser
  // profile path segment (…\User Data\<Profile>\ or …\<Browser>\<Profile>\) — a random "History" file
  // elsewhere is not claimed. The SQLITE lane copies the History-wal/-shm sidecars that travel with it.
  if (upper === "HISTORY" && CHROMIUM_PROFILE_RE.test(filePath)) return "chromiumHistory";
  if (upper === "WEB DATA" && CHROMIUM_PROFILE_RE.test(filePath)) return "chromiumAutofill"; // Chromium form autofill
  if (upper === "ACTIVITIESCACHE.DB") return "winTimeline";   // Windows Timeline (unambiguous basename)
  if (upper === "EVENTTRANSCRIPT.DB") return "eventTranscript"; // DiagTrack diagnostics telemetry (unambiguous basename)
  if (upper === "PLACES.SQLITE") return "firefoxHistory";     // Firefox history (unambiguous basename)
  if (upper === "SRUDB.DAT") return "srudb";                  // Lane E — SRUM ESE DB (Windows\System32\sru\SRUDB.dat)
  if (upper === "WEBCACHEV01.DAT") return "webcache";         // IE / legacy Edge ESE web cache
  if (/^QMGR\d*\.DAT$/i.test(base)) return "bits";            // BITS transfer queue ESE stores
  if (upper === "WINDOWS.EDB" || upper === "WINDOWS.DB" || upper === "WINDOWS-GATHER.DB") return "windowsSearch";        // Windows Search ESE index
  if (upper === "OBJECTS.DATA" && /[\\/]WBEM[\\/]Repository[\\/]/i.test(filePath)) return "wbemRepository";
  if (ext === ".wer" || /[\\/]Report(?:Archive|Queue)[\\/].+\.wer$/i.test(filePath)) return "wer";
  if (upper === "REGISTRY.POL" || upper === "GPTTMPL.INF" || upper === "SCRIPTS.INI" || (GPO_PATH_RE.test(filePath) && GPO_SCRIPT_RE.test(filePath))) return "groupPolicy";
  if ((RMM_PATH_RE.test(filePath) && /\.(log|trace|txt|ini|conf|config|toml|json|xml)$/i.test(base)) || RMM_FILE_RE.test(base)) return "remoteAdmin";
  if (ext === ".evtx") return "evtx";
  if (upper === "$MFT" || ext === ".mft") return "mft";
  if (upper === "$LOGFILE") return "logFile"; // NTFS transaction journal ($FILE_NAME file activity)
  if (upper === "$J" || (upper.includes("USNJRNL") && !/\$MAX/i.test(upper) && !/%3A\$MAX/i.test(upper))) return "usn";
  if (ext === ".plaso" || /\.plaso$/i.test(base) || (ext === ".timeline" && /plaso/i.test(base))) return "plaso";
  // RDP bitmap cache: bcache##.bmc / Cache####.bin (bmc-tools input).
  if (/\.bmc$/i.test(base) || /^cache\d{4}\.bin$/i.test(base)) return "rdp";
  // KAPE Module output: an already-parsed EZ-Tools CSV. Gated on EZ/KAPE naming so arbitrary CSVs in
  // a large tree aren't header-peeked (keeps the scan name-only-fast in the common case); the header
  // signature is the authority. This is the ONE classification rule that reads file content.
  if (ext === ".csv" && EZ_CSV_RE.test(base) && classifyKapeCsv(filePath)) return "kapeCsv";
  return null;
}

// Universally high-value EVTX logs (file basenames, upper-cased). When a collection has more EVTX
// files than the path cap, these must NEVER be truncated away — Security is the canonical example
// (it sorts at ~"S", so a naive "first N alphabetically" cap drops it). Kept aligned with
// EVTX_ALLOWLIST in timeline-normalizer.js (the channels the timeline cares about).
const HIGH_VALUE_EVTX = new Set([
  "SECURITY.EVTX", "SYSTEM.EVTX", "APPLICATION.EVTX",
  "MICROSOFT-WINDOWS-SYSMON%4OPERATIONAL.EVTX",
  "MICROSOFT-WINDOWS-POWERSHELL%4OPERATIONAL.EVTX",
  "MICROSOFT-WINDOWS-TASKSCHEDULER%4OPERATIONAL.EVTX",
  "MICROSOFT-WINDOWS-WMI-ACTIVITY%4OPERATIONAL.EVTX",
  "MICROSOFT-WINDOWS-WINDOWS DEFENDER%4OPERATIONAL.EVTX",
  "MICROSOFT-WINDOWS-TERMINALSERVICES-LOCALSESSIONMANAGER%4OPERATIONAL.EVTX",
  "MICROSOFT-WINDOWS-TERMINALSERVICES-REMOTECONNECTIONMANAGER%4OPERATIONAL.EVTX",
  // Lateral-movement additions. WinRM is populated in BOTH demo triage packages yet was
  // absent here, so it could be truncated away by the per-kind path cap.
  "MICROSOFT-WINDOWS-WINRM%4OPERATIONAL.EVTX",
  "MICROSOFT-WINDOWS-SMBSERVER%4SECURITY.EVTX",
  "MICROSOFT-WINDOWS-SMBSERVER%4OPERATIONAL.EVTX",
  "MICROSOFT-WINDOWS-SMBCLIENT%4SECURITY.EVTX",
  "MICROSOFT-WINDOWS-TERMINALSERVICES-RDPCLIENT%4OPERATIONAL.EVTX",
]);

// ── Lateral-movement relevance ────────────────────────────────────────────────────────
//
// Drives which EVTX channels the "Lateral Movement" import lane pre-selects. Separate from
// HIGH_VALUE_EVTX (which is about surviving the path cap) because relevance is graded: an
// analyst wants Security and the TerminalServices pair every time, WinRM/TaskScheduler/SMB
// usually, System occasionally, and the other ~100 channels only on request.
const LM_EVTX_TIERS = [
  [3, /^(?:SECURITY|MICROSOFT-WINDOWS-SYSMON%4OPERATIONAL|MICROSOFT-WINDOWS-TERMINALSERVICES-(?:LOCALSESSIONMANAGER|REMOTECONNECTIONMANAGER)%4OPERATIONAL)\.EVTX$/],
  [2, /^MICROSOFT-WINDOWS-(?:WINRM%4OPERATIONAL|TASKSCHEDULER%4OPERATIONAL|SMB(?:SERVER|CLIENT)%4\w+|TERMINALSERVICES-RDPCLIENT%4OPERATIONAL|REMOTEDESKTOPSERVICES-RDPCORETS%4OPERATIONAL)\.EVTX$/],
  [1, /^SYSTEM\.EVTX$/],
];

/**
 * Lateral-movement relevance of an EVTX file, 0–3 (3 = always want it).
 * @param {string} filePathOrName
 */
function lmEvtxRelevance(filePathOrName) {
  // Split on BOTH separators: path.basename() is platform-specific, so a Windows-style
  // path (which can reach us from stored collection metadata) would come back whole on
  // macOS/Linux and match nothing. The ported classifyFile() is already `[\\/]`-tolerant.
  const s = String(filePathOrName || "");
  const base = s.slice(Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\")) + 1).toUpperCase();
  if (!base.endsWith(".EVTX")) return 0;
  for (const [tier, re] of LM_EVTX_TIERS) if (re.test(base)) return tier;
  return 0;
}

// An EVTX file with a header and a single allocated-but-empty chunk is exactly 69,632 bytes
// (4 KB header + 64 KB chunk). Both demo triage packages contain these: Azeroth's
// TerminalServices/SMB/System logs are all 69,632-byte stubs, which is precisely why its
// Lateral Movement lane must default to Security + WinRM only. Size alone is a heuristic —
// a log can legitimately hold a few records at this size — so callers that care should
// confirm with a header read; for pre-selection it is the right call.
const EMPTY_EVTX_BYTES = 69632;

/** True when an EVTX file is almost certainly empty (see EMPTY_EVTX_BYTES). */
function isLikelyEmptyEvtx(size) {
  return Number(size) > 0 && Number(size) <= EMPTY_EVTX_BYTES;
}
const HV_BOOST = 1e15; // dwarfs any real file size, so high-value EVTX always sort ahead of the rest

/** Per-file priority used to order a kind's paths before the cap truncates them (higher = kept). */
function pathPriority(kind, item) {
  if (kind === "evtx" && HIGH_VALUE_EVTX.has(path.basename(item.p).toUpperCase())) return HV_BOOST + item.size;
  return item.size; // otherwise keep the LARGEST files (the ones with actual data), drop empties
}

/**
 * Recursively scan a folder, classifying files into artifact buckets (no content reads).
 * @param {string} dir
 * @param {{maxFiles?: number, maxDepth?: number, maxPathsPerKind?: number}} opts
 * @returns {{counts, bytes, paths, total, scanned, truncated, pathsTruncated}}
 */
function scanTriageDir(dir, opts = {}) {
  const maxFiles = opts.maxFiles || 1_000_000;
  const maxDepth = opts.maxDepth || 40;
  const maxPathsPerKind = opts.maxPathsPerKind || 64;
  const progressEvery = Number.isFinite(opts.progressEvery) && opts.progressEvery > 0 ? opts.progressEvery : 250;
  const onProgress = typeof opts.onProgress === "function" ? opts.onProgress : null;
  const isCancelled = typeof opts.isCancelled === "function" ? opts.isCancelled : null;

  const counts = {};
  const bytes = {}; // total size per kind (for "heavy" flags in the manifest)
  const matched = {}; // kind -> [{ p, size }] — collected UNCAPPED (classified files are bounded)
  let total = 0, scanned = 0, truncated = false;
  let lastProgress = 0;

  const stack = [{ d: dir, depth: 0 }];
  while (stack.length) {
    if (isCancelled) isCancelled();
    const { d, depth } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (isCancelled) isCancelled();
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!e.isSymbolicLink() && depth < maxDepth) stack.push({ d: full, depth: depth + 1 });
        continue;
      }
      if (!e.isFile()) continue;
      if (++scanned > maxFiles) { truncated = true; break; }
      const kind = classifyFile(full);
      if (!kind) continue;
      counts[kind] = (counts[kind] || 0) + 1;
      let size = 0;
      try { size = fs.statSync(full).size; } catch { /* ignore */ }
      bytes[kind] = (bytes[kind] || 0) + size;
      total++;
      (matched[kind] || (matched[kind] = [])).push({ p: full, size });
      if (onProgress && scanned - lastProgress >= progressEvery) {
        lastProgress = scanned;
        onProgress({ phase: "scanning", scanned, classified: total });
      }
    }
    if (truncated) break;
  }
  if (onProgress) onProgress({ phase: "scanning", scanned, classified: total });

  // Prioritize BEFORE truncating to maxPathsPerKind, so the cap can never discard the files that
  // matter: high-value EVTX channels (Security/System/Sysmon/…) first, then largest-first (most
  // data). A naive first-N-in-directory-order cap silently drops Security.evtx (alphabetically late).
  const paths = {};
  const files = {};
  let pathsTruncated = false;
  for (const kind of Object.keys(matched)) {
    const arr = matched[kind];
    arr.sort((a, b) => pathPriority(kind, b) - pathPriority(kind, a));
    if (arr.length > maxPathsPerKind) pathsTruncated = true;
    const kept = arr.slice(0, maxPathsPerKind);
    paths[kind] = kept.map((x) => x.p);
    // `files` carries the per-file size the manifest needs to render "8.1 MB" and to grey
    // out empty EVTX stubs. `paths` is kept as-is so existing callers are unaffected.
    files[kind] = kept.map((x) => ({ path: x.p, size: x.size }));
  }

  return { counts, bytes, paths, files, total, scanned, truncated, pathsTruncated };
}

module.exports = {
  classifyFile, scanTriageDir, KIND_LABELS, HIGH_VALUE_EVTX, EZ_CSV_RE,
  classifyKapeCsv, classifyKapeCsvColumns, detectModuleOutput,
  lmEvtxRelevance, isLikelyEmptyEvtx, EMPTY_EVTX_BYTES,
};
