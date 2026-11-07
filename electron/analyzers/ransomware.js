const { dbg } = require("../logger");
const { compileSafeRegex } = require("../utils/safe-regex");

// ── Ransomware analysis constants ──────────────────────────────────────────
const RW_COMMON_EXTENSIONS = new Set([
  // Documents
  ".doc",".docx",".docm",".dot",".dotx",".odt",".rtf",".txt",".pdf",".xps",".wpd",".wps",".pages",
  // Spreadsheets
  ".xls",".xlsx",".xlsm",".xlsb",".xlt",".xltx",".ods",".csv",".tsv",".numbers",
  // Presentations
  ".ppt",".pptx",".pptm",".odp",".key",
  // Images
  ".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".svg",".ico",".webp",
  ".psd",".ai",".eps",".indd",".raw",".cr2",".nef",".dng",".heic",
  // Audio/Video
  ".mp3",".wav",".flac",".aac",".ogg",".wma",".mp4",".avi",".mkv",".mov",
  ".wmv",".flv",".webm",".m4v",".m4a",".m4b",".3gp",
  // Archives
  ".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".cab",".iso",".dmg",
  // Code
  ".py",".js",".ts",".jsx",".tsx",".java",".cs",".cpp",".c",".h",".hpp",
  ".go",".rs",".rb",".php",".swift",".kt",".scala",".r",".m",".pl",
  ".sh",".bat",".ps1",".cmd",".vbs",".wsf",
  // Web
  ".html",".htm",".css",".scss",".less",".xml",".json",".yaml",".yml",
  // Config
  ".ini",".cfg",".conf",".config",".reg",".inf",".toml",".env",".properties",
  // Executables & Libraries
  ".exe",".dll",".sys",".drv",".ocx",".cpl",".msi",".msp",".mst",
  ".com",".scr",".pif",".jar",".class",".war",".ear",
  // Database
  ".mdb",".accdb",".sql",".sqlite",".db",".dbf",".mdf",".ndf",".ldf",
  // Email
  ".pst",".ost",".msg",".eml",".mbox",
  // Fonts
  ".ttf",".otf",".woff",".woff2",".eot",
  // VM
  ".vmdk",".vmx",".vhd",".vhdx",".ova",".ovf",".qcow2",".vdi",
  // System
  ".log",".tmp",".bak",".dat",".bin",".manifest",".cat",".mui",
  ".nls",".tlb",".ax",".lnk",".url",".theme",".msstyles",".etl",
  // Certificate
  ".cer",".crt",".pfx",".p12",".pem",".key",".csr",
  // CAD
  ".dwg",".dxf",".dgn",".rvt",".ifc",".step",".stp",".stl",
  // Misc
  ".hta",".chm",".hlp",".man",".info",".md",".rst",".tex",".latex",
  // Forensic / DFIR / system artifacts
  ".map",".mo",".po",".tkape",".time_stamp",".mkape",".mum",".evtx",".pak",".admx",
  // Additional system / resource files
  ".3",".rego",".fon",".cur",".adml",".cdf-ms",".mfl",".resx",".cdxml",
]);

const RW_BUSINESS_IMPACT = {
  "Documents": [".doc",".docx",".docm",".dot",".dotx",".odt",".rtf",".txt",".pdf",".xps",".wpd",".pages"],
  "Spreadsheets": [".xls",".xlsx",".xlsm",".xlsb",".xlt",".xltx",".ods",".csv",".tsv",".numbers"],
  "Presentations": [".ppt",".pptx",".pptm",".odp",".key"],
  "Email & Messaging": [".pst",".ost",".msg",".eml",".mbox",".dbx",".nsf"],
  "Databases": [".mdb",".accdb",".sql",".sqlite",".db",".dbf",".mdf",".ndf",".ldf"],
  "Archives": [".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".cab",".iso"],
  "Source Code": [".py",".js",".ts",".jsx",".tsx",".java",".cs",".cpp",".c",".h",".hpp",".go",".rs",".rb",".php",".swift",".kt",".scala",".sh",".bat",".ps1"],
  "Images & Design": [".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".svg",".psd",".ai",".eps",".indd",".raw",".cr2",".nef",".dng",".heic"],
  "Audio & Video": [".mp3",".wav",".flac",".aac",".mp4",".avi",".mkv",".mov",".wmv",".webm",".m4v"],
  "Virtual Machines": [".vmdk",".vmx",".vhd",".vhdx",".ova",".ovf",".qcow2",".vdi"],
  "Backups & Recovery": [".bak",".bkf",".tib",".mrimg",".spf",".v2i",".spi",".fbk",".trn",".dmp"],
  "CAD & Engineering": [".dwg",".dxf",".dgn",".rvt",".ifc",".step",".stp",".stl"],
};

const RW_BACKUP_RECOVERY = new Map([
  [".bak","Database backup"],[".bkf","Windows backup"],[".tib","Acronis image"],
  [".mrimg","Macrium image"],[".vhdx","Hyper-V disk"],[".vmdk","VMware disk"],
  [".vhd","Virtual hard disk"],[".ova","VM appliance"],[".qcow2","QEMU disk"],
  [".vdi","VirtualBox disk"],[".pst","Outlook archive"],[".ost","Outlook cache"],
  [".mdf","SQL Server data"],[".ldf","SQL Server log"],[".ndf","SQL Server secondary"],
  [".iso","Disk image"],[".spf","ShadowProtect"],[".v2i","Symantec image"],
  [".trn","SQL transaction log"],[".dmp","Memory dump"],[".fbk","Firebird backup"],
]);

// Reverse lookup: extension → business impact category (lazy-initialized)
let _rwExtToCategory = null;
function _getExtToCategory() {
  if (!_rwExtToCategory) {
    const m = new Map();
    for (const [cat, exts] of Object.entries(RW_BUSINESS_IMPACT)) {
      for (const e of exts) if (!m.has(e)) m.set(e, cat);
    }
    _rwExtToCategory = m;
  }
  return _rwExtToCategory;
}

// ── In-place / overwrite encryption detection (a SUSPICION surface, not confirmation) ──────
// Ransomware that overwrites a file's contents WITHOUT renaming it leaves no uncommon extension
// and no deleted-original pair, so the extension-keyed analyzer misses it. A single $MFT snapshot
// carries only the CURRENT size (no before/after), so "the file grew" is unknowable — detection
// rests on a MASS in-place-rewrite BURST: many business-data files whose SI 0x10 Modified is LATER
// than their FN 0x30 Modified (content written after the name was last set = not a rename, not a
// fresh create), clustered tightly across many directories. MFT-only is at most a MEDIUM suspicion;
// USN DataOverwrite-without-rename aligned to the burst elevates it; a dominant benign updater /
// sync / indexer in EVTX overrides it back down.
const RW_INPLACE_CATEGORIES = ["Documents", "Spreadsheets", "Presentations", "Email & Messaging", "Databases", "Images & Design", "CAD & Engineering", "Archives"];
const RW_INPLACE_BUSINESS_EXTS = RW_INPLACE_CATEGORIES.flatMap((c) => RW_BUSINESS_IMPACT[c] || []);
// ParentPath substrings (lowercased) that exclude a file from in-place scanning — OS / software /
// sync / cache / build / DB / log trees where benign mass-modification bursts routinely occur.
// MFT ParentPath is volume-relative (".\Users\…"), so these match as plain substrings.
const RW_INPLACE_PATH_EXCLUDES = [
  "\\windows\\", "\\program files", "\\programdata\\", "\\winsxs\\", "\\system32\\", "\\syswow64\\",
  "\\$recycle.bin", "system volume information", "\\temp\\", "\\temporary internet files",
  "\\inetcache", "\\appdata\\local\\packages", "\\onedrive", "\\dropbox", "\\google drive", "\\box sync",
  "\\node_modules\\", "\\.git\\", "\\bin\\debug", "\\bin\\release", "\\obj\\", "\\target\\", "\\dist\\", "\\.vscode\\",
  "\\microsoft sql server\\", "\\mysql\\", "\\postgresql\\", "\\inetpub\\logs", "\\config\\systemprofile",
  "\\cache\\", "\\caches\\", "\\.cache",
];
// Process images whose dominance in the burst window points to a benign cause (forces a downgrade).
const RW_INPLACE_BENIGN_PROCS = ["tiworker.exe", "trustedinstaller.exe", "msmpeng.exe", "mpcmdrun.exe", "onedrive.exe", "onedrivesetup.exe", "dropbox.exe", "googledrivefs.exe", "backgroundtaskhost.exe", "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe", "sqlservr.exe", "mysqld.exe", "postgres.exe", "w3wp.exe", "msiexec.exe", "wuauclt.exe", "defrag.exe"];
const RW_INPLACE_DISCLAIMER = "Screening lead only: $MFT/USN cannot read file contents or measure size change from a single snapshot, so this flags mass in-place content rewrites consistent with — but not proof of — encryption. Corroborate with file entropy, ransom notes, and process execution.";

/** Business-data category for an extension within the in-place scope, or null. */
function _rwInPlaceCategory(ext) {
  const e = String(ext == null ? "" : ext).toLowerCase().trim();
  const cat = _getExtToCategory().get(e.startsWith(".") ? e : "." + e);
  return RW_INPLACE_CATEGORIES.includes(cat) ? cat : null;
}

/**
 * Find the densest contiguous burst in a minute-bucket histogram. Buckets are
 * [{bucket:"YYYY-MM-DD HH:MM", cnt, dirCount}]; consecutive buckets within `maxGapMin` minutes
 * form one run. Returns the run with the largest total file count, or null if none reaches
 * `minFiles`. Pure — no DB, no clock.
 */
function _rwFindBurst(buckets, opts = {}) {
  const maxGapMs = (opts.maxGapMin == null ? 5 : opts.maxGapMin) * 60000;
  const minFiles = opts.minFiles == null ? 30 : opts.minFiles;
  const pts = (buckets || [])
    .map((b) => ({ ms: _rwBucketMs(b.bucket), bucket: b.bucket, cnt: b.cnt || 0, dirCount: b.dirCount || 0 }))
    .filter((p) => p.ms != null)
    .sort((a, b) => a.ms - b.ms);
  if (!pts.length) return null;
  let best = null;
  const close = (run) => {
    if (!run.length) return;
    const total = run.reduce((s, p) => s + p.cnt, 0);
    if (total < minFiles) return;
    const peak = run.reduce((m, p) => Math.max(m, p.cnt), 0);
    const dirPeak = run.reduce((m, p) => Math.max(m, p.dirCount), 0);
    const cand = {
      startMs: run[0].ms, endMs: run[run.length - 1].ms, total, peak, dirPeak,
      buckets: run.map((p) => ({ bucket: p.bucket, count: p.cnt, dirCount: p.dirCount })),
      durationMinutes: Math.round((run[run.length - 1].ms - run[0].ms) / 60000) + 1,
    };
    if (!best || cand.total > best.total) best = cand;
  };
  let cur = [pts[0]];
  for (let i = 1; i < pts.length; i++) {
    if (pts[i].ms - pts[i - 1].ms <= maxGapMs) cur.push(pts[i]);
    else { close(cur); cur = [pts[i]]; }
  }
  close(cur);
  return best;
}

/**
 * Synthesize the in-place-encryption assessment from query results. Pure & exported for tests.
 * Inputs: { hasFnCol, burst (from _rwFindBurst|null), samples[], extBreakdown[], usnOverwriteNoRename
 * ({total,alignedMinutes}|null), processCorrelation (|null), thresholds }. Returns the
 * `inPlaceEncryption` object. NEVER mutates the copy-delete/rename surface (encryptionMethod).
 */
function _buildInPlaceAssessment(input) {
  const o = input || {};
  const T = { minFiles: 30, minDirs: 3, minMinutes: 3, rate: 10, graceMin: 5, ...(o.thresholds || {}) };
  const base = {
    available: false, reason: null, confidence: "low", isSuspicionOnly: true,
    candidateFileCount: 0, windowStart: null, windowEnd: null, durationMinutes: 0,
    peakFilesPerMinute: 0, directoryCount: 0, extensionBreakdown: [], buckets: [],
    siLaterThanFnCount: 0, usnOverwriteNoRename: o.usnOverwriteNoRename || null,
    evtxDisposition: null, signals: [], samples: [], disclaimer: RW_INPLACE_DISCLAIMER,
  };
  if (!o.hasFnCol) {
    return { ...base, reason: "Requires $MFT FN-modified (LastModified0x30) and SI-created (Created0x10) columns; this export lacks them." };
  }
  const burst = o.burst;
  if (!burst || burst.total < T.minFiles) {
    return { ...base, available: false, reason: "No mass in-place content-rewrite burst detected." };
  }
  const samples = (o.samples || []);
  // S2: a sample "pre-existed" when SI-Created precedes SI-Modified by > grace (not a fresh create).
  const ms = (s) => _rwBucketMs(s);
  const preExisting = samples.filter((s) => { const c = ms(s.created0x10), m = ms(s.lastMod0x10); return c != null && m != null && m - c > T.graceMin * 60000; }).length;
  const preExistingFrac = samples.length ? preExisting / samples.length : 1;
  // Directory spread — best of per-minute peak and distinct dirs seen in the (bounded) sample.
  const sampleDirs = new Set(samples.map((s) => String(s.parentPath || "").toLowerCase())).size;
  const directoryCount = Math.max(burst.dirPeak || 0, sampleDirs);
  // Extension breakdown → business categories.
  const extBreakdown = (o.extBreakdown || []).map((r) => ({ extension: r.extension, category: _rwInPlaceCategory(r.extension) || "Other", count: r.count }))
    .filter((r) => r.count > 0).sort((a, b) => b.count - a.count);
  const categories = new Set(extBreakdown.map((r) => r.category).filter((c) => c && c !== "Other"));
  const peakFilesPerMinute = burst.peak || 0;
  // S3: USN overwrite-without-rename aligned to the burst minutes. DataOverwrite (existing content
  // replaced) is the load-bearing signal; DataExtend alone can be benign append/growth or bulk
  // file CREATION, so it only supports 'medium', never 'high'.
  const usnOW = o.usnOverwriteNoRename || null;
  const s3 = !!(usnOW && usnOW.alignedMinutes > 0);
  const s3strong = !!(usnOW && usnOW.overwriteAligned > 0);
  // S5: EVTX disposition from the already-computed process correlation.
  let evtxDisposition = null;
  const pcProcs = (o.processCorrelation && o.processCorrelation.available && o.processCorrelation.processes) || null;
  if (pcProcs) {
    const lc = (s) => String(s || "").toLowerCase();
    const benign = pcProcs.filter((p) => RW_INPLACE_BENIGN_PROCS.some((b) => lc(p.image).endsWith(b) || _rwBasename(p.image) === b));
    const suspicious = pcProcs.filter((p) => p.evasion || p.risky || p.matchedPayload);
    if (suspicious.length > 0) evtxDisposition = "suspicious-process";
    else if (benign.length > 0) evtxDisposition = "benign-actor";
    else evtxDisposition = "none";
  }
  // S4: automated-sweep shape (sustained + cross-directory + multi-category).
  const s4 = burst.durationMinutes >= T.minMinutes && directoryCount >= T.minDirs && peakFilesPerMinute >= T.rate && categories.size >= 2;
  // Confidence ladder. MFT-only caps at 'medium'; USN DataOverwrite-without-rename → 'high'.
  // Two hard downgrades win last: a dominant benign actor (EVTX), and a burst that is mostly
  // freshly-CREATED files (not pre-existing) — in-place encryption rewrites files that already
  // existed, so a create-heavy burst is bulk file creation, not in-place rewrite.
  let confidence = "low", reason = null;
  if (s4) confidence = "medium";
  if (s3 && confidence === "low") confidence = "medium";       // DataExtend-only aligned → at least medium
  if (s3strong) confidence = "high";                           // true DataOverwrite aligned → high
  if (evtxDisposition === "suspicious-process" && confidence === "medium") confidence = "high";
  if (preExistingFrac < 0.5) { confidence = "low"; reason = "Sampled files were largely created (not pre-existing) in the window — consistent with bulk file creation, not in-place rewrite of existing files."; }
  if (evtxDisposition === "benign-actor") { confidence = "low"; reason = "A known updater / sync / indexer process dominates the window — likely benign mass modification, not encryption."; }
  if (!s4 && confidence !== "high" && !reason) reason = "Limited spread/velocity — could be a single-application refresh; treat as weak.";
  // An UNRECOGNIZED process (present, but neither on the benign list nor flagged suspicious) is NOT
  // downgraded — at high confidence it is more likely the ransomware than a benign tool, and the
  // benign list cannot enumerate every proprietary backup/indexer/ETL tool. Instead surface the
  // uncertainty so the analyst identifies the actor rather than assuming encryption.
  if (evtxDisposition === "none" && (confidence === "medium" || confidence === "high")) {
    const caveat = "An unrecognized process executed in the window — identify the responsible process (a proprietary backup / indexer / ETL tool can produce this same pattern) and check file entropy before concluding encryption.";
    reason = reason ? `${reason} ${caveat}` : caveat;
  }
  const isSuspicionOnly = !(s3strong && evtxDisposition !== "benign-actor" && preExistingFrac >= 0.5);
  const signals = [
    { id: "S1", basis: "mft", fired: true, text: `${burst.total.toLocaleString()} business-data files rewritten in place (SI 0x10 Modified later than FN 0x30) in a ${burst.durationMinutes}-minute burst` },
    { id: "S2", basis: "mft", fired: preExistingFrac >= 0.6, text: `${Math.round(preExistingFrac * 100)}% of sampled files pre-existed the burst (not freshly created)` },
    { id: "S3", basis: "usn", fired: s3strong, text: usnOW ? `${(usnOW.overwriteTotal || 0).toLocaleString()} USN DataOverwrite-without-rename (${usnOW.overwriteAligned || 0} min aligned to burst); ${usnOW.total.toLocaleString()} incl. DataExtend` : "No USN tab correlated (overwrite-without-rename unknown)" },
    { id: "S4", basis: "mft", fired: s4, text: `${peakFilesPerMinute}/min peak across ${directoryCount} director${directoryCount === 1 ? "y" : "ies"}, ${categories.size} data categor${categories.size === 1 ? "y" : "ies"}` },
    { id: "S5", basis: "evtx", fired: evtxDisposition === "suspicious-process", text: evtxDisposition === "suspicious-process" ? "A suspicious / evasion process executed in the window" : evtxDisposition === "benign-actor" ? "A benign updater/sync/indexer dominates the window" : "No process correlation available" },
  ];
  return {
    available: true, reason, confidence, isSuspicionOnly,
    candidateFileCount: burst.total,
    windowStart: burst.buckets[0] ? burst.buckets[0].bucket : null,
    windowEnd: burst.buckets[burst.buckets.length - 1] ? burst.buckets[burst.buckets.length - 1].bucket : null,
    durationMinutes: burst.durationMinutes,
    peakFilesPerMinute, directoryCount,
    extensionBreakdown: extBreakdown.slice(0, 12),
    buckets: burst.buckets,
    siLaterThanFnCount: burst.total,
    usnOverwriteNoRename: usnOW,
    evtxDisposition,
    signals,
    samples: samples.slice(0, 20).map((s) => ({ fileName: s.fileName, parentPath: s.parentPath, extension: s.extension, created0x10: s.created0x10, lastMod0x10: s.lastMod0x10, lastMod0x30: s.lastMod0x30 })),
    disclaimer: RW_INPLACE_DISCLAIMER,
  };
}

/**
 * Group flat directory counts into subtrees using a trie with path compression.
 */
function _groupBySubtree(encDirs, allDirs, maxGroups = 25) {
  const totalMap = new Map(allDirs.map(d => [d.path, d.total]));

  // Build trie
  const root = { children: {}, encCount: 0, totalCount: 0, dirCount: 0 };
  for (const { path, count } of encDirs) {
    const segments = (path || "").replace(/^\.\\/, "").split(/[\\\/]+/).filter(Boolean);
    let node = root;
    for (const seg of segments) {
      if (!node.children[seg]) node.children[seg] = { children: {}, encCount: 0, totalCount: 0, dirCount: 0 };
      node = node.children[seg];
    }
    node.encCount += count;
    node.totalCount += totalMap.get(path) || count;
    node.dirCount += 1;
  }

  // Accumulate subtree counts
  function accumulate(node) {
    let enc = node.encCount, total = node.totalCount, dirs = node.dirCount;
    for (const child of Object.values(node.children)) {
      const c = accumulate(child);
      enc += c.enc; total += c.total; dirs += c.dirs;
    }
    node._subtreeEnc = enc;
    node._subtreeTotal = total;
    node._subtreeDirs = dirs;
    return { enc, total, dirs };
  }
  accumulate(root);

  // Walk trie, path-compress single-child chains, cut at branching points
  const results = [];
  function walk(node, pathSoFar, depth) {
    const childKeys = Object.keys(node.children);
    // Path compress single-child chain
    if (childKeys.length === 1 && depth < 6) {
      const key = childKeys[0];
      walk(node.children[key], pathSoFar ? pathSoFar + "\\" + key : key, depth + 1);
      return;
    }
    // Emit subtree at branching point, leaf, or max depth
    if (node._subtreeEnc > 0 && (childKeys.length >= 2 || childKeys.length === 0 || depth >= 3)) {
      results.push({
        path: ".\\" + (pathSoFar || "(root)"),
        encryptedCount: node._subtreeEnc,
        totalCount: node._subtreeTotal,
        ratio: node._subtreeTotal > 0 ? Math.round((node._subtreeEnc / node._subtreeTotal) * 1000) / 1000 : 0,
        childDirCount: node._subtreeDirs,
      });
      return;
    }
    // Recurse
    for (const [key, child] of Object.entries(node.children)) {
      walk(child, pathSoFar ? pathSoFar + "\\" + key : key, depth + 1);
    }
  }
  walk(root, "", 0);

  return results.sort((a, b) => b.encryptedCount - a.encryptedCount).slice(0, maxGroups);
}

/**
 * Scan MFT for candidate ransomware extensions and ransom note filenames.
 * Returns scored candidates ranked by burst timing, rarity, and file count.
 */
function scanRansomwareExtensions(meta, progressCb) {
  const _p = typeof progressCb === "function" ? progressCb : () => {};
  const empty = { candidates: [], noteCandidates: [] };
  if (!meta) return empty;

  const db = meta.db;
  const col = (name) => meta.colMap[name];
  const ext = col("Extension"), fn = col("FileName"), pp = col("ParentPath"), fs = col("FileSize");
  const lastMod = col("LastModified0x10"), isDir = col("IsDirectory"), created = col("Created0x10");
  if (!ext || !fn || !pp) return empty;

  const notDir = isDir ? `AND (${isDir} IS NULL OR ${isDir} = '' OR ${isDir} = 'False')` : "";

  try {
    // Phase 1: Get all extensions with counts >= 50
    _p({ stage: "extensions", pct: 5, detail: "Scanning extension distribution" });
    const allExts = db.prepare(
      `SELECT LOWER(${ext}) as extension, COUNT(*) as cnt FROM data WHERE ${ext} IS NOT NULL AND ${ext} != '' ${notDir} GROUP BY LOWER(${ext}) HAVING cnt >= 50 ORDER BY cnt DESC, extension LIMIT 200`
    ).all();

    // Filter to non-common extensions
    const rawCandidates = allExts.filter(e => !RW_COMMON_EXTENSIONS.has(e.extension));
    _p({ stage: "extensions", pct: 15, detail: `Found ${rawCandidates.length} uncommon extensions` });

    // Phase 1b: Also try lower threshold (cnt >= 5) if no candidates at >= 50
    if (rawCandidates.length === 0) {
      const lowExts = db.prepare(
        `SELECT LOWER(${ext}) as extension, COUNT(*) as cnt FROM data WHERE ${ext} IS NOT NULL AND ${ext} != '' ${notDir} GROUP BY LOWER(${ext}) HAVING cnt >= 5 ORDER BY cnt DESC, extension LIMIT 200`
      ).all();
      const lowCandidates = lowExts.filter(e => !RW_COMMON_EXTENSIONS.has(e.extension));
      if (lowCandidates.length > 0) rawCandidates.push(...lowCandidates);
    }

    // Normalize count scores (0-1)
    const maxCount = rawCandidates[0]?.cnt || 1;

    // Phase 2: Burst timing + sample paths for top 30
    _p({ stage: "burst", pct: 20, detail: "Analyzing burst timing" });
    const candidates = [];
    const top = rawCandidates.slice(0, 30);
    for (let _ti = 0; _ti < top.length; _ti++) {
      const rc = top[_ti];
      _p({ stage: "burst", pct: 20 + Math.round((_ti / top.length) * 40), detail: `Scoring ${rc.extension} (${_ti + 1}/${top.length})` });
      // Peak minute
      let peakMinute = null, peakMinuteCount = 0, burstScore = 0;
      if (lastMod) {
        const peak = db.prepare(
          `SELECT extract_datetime_minute(${lastMod}) as bucket, COUNT(*) as cnt FROM data WHERE LOWER(${ext}) = LOWER(?) ${notDir} AND ${lastMod} IS NOT NULL AND ${lastMod} != '' GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY cnt DESC, bucket LIMIT 1`
        ).get(rc.extension);
        if (peak) {
          peakMinute = peak.bucket;
          peakMinuteCount = peak.cnt;
          burstScore = peak.cnt / rc.cnt; // concentration in peak minute
        }
      }

      // Sample paths (top 3 directories)
      const pathRows = db.prepare(
        `SELECT ${pp} as path FROM data WHERE LOWER(${ext}) = LOWER(?) ${notDir} GROUP BY ${pp} ORDER BY COUNT(*) DESC, path LIMIT 3`
      ).all(rc.extension);
      const samplePaths = pathRows.map(r => r.path);

      // Rarity / family: an extension matching a known ransomware family is a near-certain
      // signature (rarity 1.0); an unknown uncommon extension is suspicious but weaker (0.6).
      // This makes rarity an actual discriminator instead of a flat constant.
      const family = _familyForExtension(rc.extension);
      const rarityScore = family ? 1.0 : 0.6;

      // Composite score
      const countNorm = rc.cnt / maxCount;
      const score = (countNorm * 0.3) + (burstScore * 0.5) + (rarityScore * 0.2);

      candidates.push({
        extension: rc.extension,
        fileCount: rc.cnt,
        score: Math.round(score * 100) / 100,
        family,
        peakMinute,
        peakMinuteCount,
        samplePaths,
      });
    }

    // Known-family matches first, then by composite score.
    candidates.sort((a, b) => (b.family ? 1 : 0) - (a.family ? 1 : 0) || b.score - a.score);

    // Phase 3: Auto-detect ransom note filenames (runs independently of extension detection)
    _p({ stage: "notes", pct: 65, detail: "Scanning for ransom note patterns" });
    const noteCandidates = [];
    if (fs) {
      // Adaptive threshold: use >= 3 if MFT has < 500 unique directories, else >= 10
      const dirCountRow = db.prepare(`SELECT COUNT(DISTINCT ${pp}) as dc FROM data ${notDir ? "WHERE " + notDir.replace(/^AND /,"") : ""}`).get();
      const noteThreshold = (dirCountRow?.dc || 0) < 500 ? 3 : 10;
      const noteRows = db.prepare(
        `SELECT MIN(${fn}) as fileName, MIN(LOWER(${ext})) as extension, COUNT(DISTINCT ${pp}) as dirCount, COUNT(*) as total FROM data WHERE LOWER(${ext}) IN ('.txt','.html','.htm','.hta','.url','.bmp','.png') AND CAST(${fs} AS REAL) < 102400 ${notDir} GROUP BY LOWER(${fn}) HAVING dirCount >= ${noteThreshold} ORDER BY dirCount DESC, LOWER(${fn}) LIMIT 20`
      ).all();

      const parseTs = (s) => { const m = String(s).match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/); return m ? new Date(Date.UTC(+m[1], m[2]-1, +m[3], +m[4], +m[5], +m[6])) : null; };
      const createdCol = created || lastMod;

      const noteSlice = noteRows.slice(0, 10);
      for (let _ni = 0; _ni < noteSlice.length; _ni++) {
        const nr = noteSlice[_ni];
        _p({ stage: "notes", pct: 65 + Math.round((_ni / noteSlice.length) * 25), detail: `Scoring note: ${nr.fileName} (${_ni + 1}/${noteSlice.length})` });
        let timeSpanMinutes = null;
        if (createdCol) {
          const span = db.prepare(
            `SELECT MIN(sort_datetime(${createdCol})) as earliest, MAX(sort_datetime(${createdCol})) as latest FROM data WHERE LOWER(${fn}) = LOWER(?) ${notDir}`
          ).get(nr.fileName);
          if (span?.earliest && span?.latest) {
            const t1 = parseTs(span.earliest), t2 = parseTs(span.latest);
            if (t1 && t2) timeSpanMinutes = Math.max(1, Math.round((t2 - t1) / 60000));
          }
        }

        // Score: high dirCount + short time span = strong signal
        const dirScore = Math.min(1, nr.dirCount / 100);
        const spanScore = timeSpanMinutes !== null && timeSpanMinutes < 1440 ? 1.0 : timeSpanMinutes !== null && timeSpanMinutes < 10080 ? 0.5 : 0.2;
        const noteScore = (dirScore * 0.6) + (spanScore * 0.4);

        noteCandidates.push({
          fileName: nr.fileName,
          extension: nr.extension,
          dirCount: nr.dirCount,
          totalCount: nr.total,
          timeSpanMinutes,
          score: Math.round(noteScore * 100) / 100,
        });
      }

      noteCandidates.sort((a, b) => b.score - a.score);
    }

    _p({ stage: "done", pct: 100, detail: `Found ${candidates.length} extensions, ${noteCandidates.length} note patterns` });
    return { candidates: candidates.slice(0, 15), noteCandidates };
  } catch (err) {
    return { ...empty, error: err.message };
  }
}

// ── Synthesis helpers (pure — unit-testable without a live DB) ──────────────
// A file is "MFT-resident" when its $DATA fits inside the 1024-byte MFT record;
// the usable resident payload is ~700 bytes after fixed/standard attributes.
const RW_RESIDENT_MAX_BYTES = 700;
function _rwIsResidentSize(v) {
  const n = typeof v === "number" ? v : parseInt(String(v || "").replace(/[^0-9]/g, ""), 10);
  return Number.isFinite(n) && n > 0 && n <= RW_RESIDENT_MAX_BYTES;
}

function _fmtBytes(n) {
  const b = Number(n) || 0;
  if (b < 1024) return `${Math.round(b)} B`;
  const u = ["KB", "MB", "GB", "TB", "PB"];
  let v = b / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 100 ? Math.round(v) : Math.round(v * 10) / 10} ${u[i]}`;
}

function _fmtDurationShort(mins) {
  const m = Math.round(Number(mins) || 0);
  if (m < 1) return "<1m";
  const h = Math.floor(m / 60), r = m % 60;
  return h > 0 ? `${h}h${r > 0 ? `${r}m` : ""}` : `${r}m`;
}

// Infer encryption method from filename-pair signals + throughput.
//  copy-delete : encrypted file is a NEW copy and the original was deleted (a deleted
//                original MFT entry exists) → originals may persist in unallocated/MFT-resident.
//  overwrite   : the original name is simply gone with no deleted counterpart (rename or
//                content overwrite in place) → on-host originals lost; recover from VSS/backup.
function _inferEncryptionMethod(op, encryptedCount, durationMinutes) {
  const filesPerSecond = durationMinutes > 0 ? Math.round((encryptedCount / (durationMinutes * 60)) * 100) / 100 : 0;
  const confirmed = op?.confirmedSampleCount || 0;
  const likely = op?.likelySampleCount || 0;
  const mapped = confirmed + likely;
  if (!op || mapped === 0) {
    return { method: "indeterminate", confidence: "low", filesPerSecond, confirmedFrac: 0,
      basis: "Filename-pair analysis was inconclusive — encrypted names did not map to recoverable originals (e.g. in-place encryption with no rename)." };
  }
  const confirmedFrac = Math.round((confirmed / mapped) * 100) / 100;
  let method, confidence;
  if (confirmedFrac >= 0.5) { method = "copy-delete"; confidence = confirmedFrac >= 0.75 ? "high" : "medium"; }
  else if (confirmedFrac <= 0.2) { method = "overwrite"; confidence = "medium"; }
  else { method = "mixed"; confidence = "low"; }
  return { method, confidence, filesPerSecond, confirmedFrac,
    basis: method === "copy-delete"
      ? "Most encrypted files have a corresponding deleted original (new-copy-then-delete) — originals may persist in unallocated space."
      : method === "overwrite"
      ? "Encrypted files' originals are gone with no deleted counterpart (rename/overwrite in place) — on-host originals overwritten."
      : "A mix of deleted-original (copy-delete) and overwrite-in-place patterns." };
}

// Recovery prospects derived from $MFT allocation / pair signals only.
function _buildRecoveryProspects(op, method, backupRecoveryTotal, antiForensics) {
  const carvableCount = op?.confirmedPairs || 0;     // deleted originals → carvable from unallocated
  const overwrittenCount = op?.likelyPairs || 0;     // original gone, no deleted entry → on-host lost
  const sampled = !!op?.sampled;
  const scale = sampled && op?.sampleSize > 0 ? op.samplePopulation / op.sampleSize : 1;
  const residentRecoverableCount = sampled ? Math.round(((op?.residentSampleCount || 0) * scale) / 100) * 100 : (op?.residentSampleCount || 0);
  const backupsEncrypted = backupRecoveryTotal || 0;
  const mapped = carvableCount + overwrittenCount;
  const carvableShare = mapped > 0 ? carvableCount / mapped : 0;

  let outlook, outlookReason;
  if (method.method === "copy-delete" && carvableShare >= 0.5 && backupsEncrypted === 0) {
    outlook = "Moderate";
    outlookReason = "Copy-then-delete leaves originals in unallocated space — carving is viable if the volume has not been heavily reused since the incident.";
  } else if (method.method === "overwrite" || (backupsEncrypted > 0 && carvableShare <= 0.3)) {
    outlook = "Low";
    outlookReason = backupsEncrypted > 0
      ? "Originals overwritten in place and on-host backups were also encrypted — recovery depends on offline backups or intact Volume Shadow Copies."
      : "Originals overwritten in place — on-host carving will not recover content; rely on offline backups or VSS.";
  } else if (method.method === "indeterminate") {
    outlook = "Indeterminate";
    outlookReason = "Pair analysis was inconclusive — validate recovery method with unallocated-space carving and VSS enumeration.";
  } else {
    outlook = "Moderate";
    outlookReason = "Mixed encryption pattern — some originals are carvable; validate with carving + VSS enumeration.";
  }
  if (residentRecoverableCount > 0 && outlook === "Low") outlook = "Low–Moderate";

  const avenues = [
    { name: "Unallocated-space carving", viability: method.method === "copy-delete" ? "Viable" : method.method === "indeterminate" ? "Verify" : "Limited",
      detail: `${carvableCount.toLocaleString()} originals deleted (copy-then-delete) — carve from unallocated before the disk is reused.` },
    { name: "MFT-resident recovery", viability: residentRecoverableCount > 0 ? "Viable" : "N/A",
      detail: `~${residentRecoverableCount.toLocaleString()} deleted originals small enough to be MFT-resident (≤${RW_RESIDENT_MAX_BYTES}B) — recoverable from the MFT record even if clusters are gone (estimate).` },
    { name: "Volume Shadow Copies (VSS)", viability: "Verify",
      detail: "Cannot be confirmed from $MFT — enumerate shadow copies and check event logs for T1490 (vssadmin / wbadmin) deletion." },
    { name: "Offline / off-host backups", viability: backupsEncrypted > 0 ? "On-host compromised" : "Verify",
      detail: backupsEncrypted > 0
        ? `${backupsEncrypted.toLocaleString()} on-host backup files were also encrypted — use off-host backups.`
        : "Confirm an off-host backup exists and predates the incident." },
  ];

  return {
    outlook, outlookReason, method: method.method,
    carvableCount, overwrittenCount, residentRecoverableCount, backupsEncrypted,
    vssStatus: "unknown", avenues,
    caveat: "Estimates derive from $MFT allocation/pair signals only; actual recoverability depends on disk reuse since the incident and is not guaranteed.",
  };
}

// Incident severity verdict + one-paragraph narrative, from already-computed fields.
function _buildIncidentSummary(o) {
  const enc = o.encryptedCount || 0;
  let score = 0;
  if (enc >= 100000) score += 45; else if (enc >= 25000) score += 38; else if (enc >= 5000) score += 28; else if (enc >= 500) score += 18; else if (enc > 0) score += 8;
  const fpm = o.peakPerMinute || o.filesPerMinute || 0;
  if (fpm >= 500) score += 18; else if (fpm >= 100) score += 12; else if (fpm >= 20) score += 6;
  if (o.backupRecoveryTotal > 0) score += 14;
  if (o.recovery?.outlook === "Low") score += 12; else if (typeof o.recovery?.outlook === "string" && o.recovery.outlook.startsWith("Low")) score += 8;
  if (o.antiForensicsCount > 0) score += 8;
  if (o.ransomNoteCount > 0) score += 5;
  const severity = score >= 75 ? "Critical" : score >= 50 ? "High" : score >= 28 ? "Medium" : "Low";

  const methodLabel = o.method?.method === "copy-delete" ? "copy-then-delete (originals deleted)"
    : o.method?.method === "overwrite" ? "in-place overwrite (originals lost on-host)"
    : o.method?.method === "mixed" ? "mixed (copy-delete + in-place)"
    : "undetermined";
  const noteClause = o.ransomNoteCount > 0 ? ` ${o.ransomNoteCount.toLocaleString()} ransom note${o.ransomNoteCount === 1 ? "" : "s"}${o.notePathCount ? ` across ${o.notePathCount} director${o.notePathCount === 1 ? "y" : "ies"}` : ""} dropped.` : "";
  const backupClause = o.backupRecoveryTotal > 0 ? ` ${o.backupRecoveryTotal.toLocaleString()} on-host backup file${o.backupRecoveryTotal === 1 ? " was" : "s were"} also encrypted.` : "";
  const afClause = o.antiForensicsCount > 0 ? ` ${o.antiForensicsCount} anti-forensic artifact${o.antiForensicsCount === 1 ? "" : "s"} (deletion / timestomping / cleanup) observed.` : "";
  const recoveryClause = o.recovery ? ` Recovery outlook: ${o.recovery.outlook}.` : "";
  const headline = `${severity}: ${enc.toLocaleString()} file${enc === 1 ? "" : "s"} (${_fmtBytes(o.totalEncryptedSizeBytes)}) encrypted over ${_fmtDurationShort(o.durationMinutes)}${o.firstTs ? `, starting ${o.firstTs} UTC` : ""}.`;
  const narrative = `${headline}${fpm ? ` Peak rate ~${Math.round(fpm).toLocaleString()} files/min.` : ""}${noteClause}${backupClause}${afClause} Encryption method: ${methodLabel}.${recoveryClause}`;
  const factors = [
    { label: "Files encrypted", value: enc.toLocaleString() },
    { label: "Peak rate", value: fpm ? `${Math.round(fpm).toLocaleString()}/min` : "—" },
    { label: "Backups hit", value: o.backupRecoveryTotal > 0 ? o.backupRecoveryTotal.toLocaleString() : "none" },
    { label: "Method", value: methodLabel },
    { label: "Recovery", value: o.recovery?.outlook || "—" },
    { label: "Anti-forensics", value: o.antiForensicsCount > 0 ? String(o.antiForensicsCount) : "none" },
  ];
  return { severity, severityScore: score, headline, narrative, method: o.method?.method || null, recoveryOutlook: o.recovery?.outlook || null, factors };
}

// Curated ransomware family catalog (open-source intel — not exhaustive). Attribution is
// best-effort: extPatterns match the encrypted extension (lowercased, leading dot), notePatterns
// match the ransom-note filename (lowercased). Only reasonably family-specific patterns are
// included — generic notes like "readme.txt" are deliberately omitted to avoid false attribution.
const RW_FAMILY_CATALOG = [
  { name: "LockBit", aka: "LockBit 2.0 / 3.0 (Black)", extPatterns: [/^\.lockbit$/, /^\.abcd$/], notePatterns: [/restore-my-files\.txt$/, /lockbit/] },
  { name: "BlackCat", aka: "ALPHV / Noberus", extPatterns: [/^\.alphv$/, /^\.sykffle$/], notePatterns: [/^recover-.+-(files|notes)\.txt$/] },
  { name: "Cl0p", aka: "Clop / TA505", extPatterns: [/^\.clop$/, /^\.cl0p$/, /^\.c_l_o_p$/], notePatterns: [/clop.*readme/, /readme_readme\.txt$/, /!_read_me\.rtf$/] },
  { name: "Conti", aka: "Conti (Ryuk successor)", extPatterns: [/^\.conti$/], notePatterns: [/conti_readme/, /^r3adm3\.txt$/] },
  { name: "Ryuk", extPatterns: [/^\.ryk$/, /^\.rcrypted$/], notePatterns: [/ryukreadme/] },
  { name: "Akira", extPatterns: [/^\.akira$/, /^\.powerranges$/], notePatterns: [/akira_readme/] },
  { name: "Royal", aka: "Royal / BlackSuit", extPatterns: [/^\.royal(_[uw])?$/, /^\.blacksuit$/], notePatterns: [/readme\.royal/] },
  { name: "Play", aka: "PlayCrypt", extPatterns: [/^\.play$/], notePatterns: [] },
  { name: "Black Basta", extPatterns: [/^\.basta$/], notePatterns: [/instructions_read_me\.txt$/] },
  { name: "Hive", extPatterns: [/^\.hive$/], notePatterns: [/how_to_decrypt\.txt$/] },
  { name: "Phobos", aka: "Phobos / 8Base", extPatterns: [/^\.phobos$/, /^\.eking$/, /^\.eight$/, /^\.faust$/, /^\.elbie$/, /^\.8base$/], notePatterns: [/^info\.hta$/, /^info\.txt$/] },
  // Dharma/CrySiS is a long-running RaaS with dozens of appended-extension variants — partial list.
  { name: "Dharma", aka: "CrySiS", extPatterns: [/^\.crysis$/, /^\.dharma$/, /^\.wallet$/, /^\.cezar$/, /^\.combo$/, /^\.java$/, /^\.adobe$/, /^\.arrow$/, /^\.bip$/, /^\.zzzzz$/], notePatterns: [/files encrypted\.txt$/, /how to restore data\.txt$/] },
  { name: "STOP/Djvu", extPatterns: [/^\.djvu$/, /^\.stop$/, /^\.djvuu$/, /^\.djvuq$/], notePatterns: [/^_readme\.txt$/, /^_openme\.txt$/] },
  { name: "WannaCry", extPatterns: [/^\.wn?cry[t]?$/, /^\.wnry$/], notePatterns: [/@please_read_me@/, /wanadecryptor/, /@wanadecryptor@/] },
  { name: "Medusa", extPatterns: [/^\.medusa$/], notePatterns: [/!!!read_me_medusa!!!/] },
  { name: "MedusaLocker", extPatterns: [/^\.bomber$/, /^\.readinstructions$/, /^\.marlock\d*$/], notePatterns: [/how_to_recover_data\.html$/, /recovery_instructions\.html$/] },
  { name: "Rhysida", extPatterns: [/^\.rhysida$/], notePatterns: [/criticalbreachdetected\.pdf$/] },
  { name: "BianLian", extPatterns: [/^\.bianlian$/], notePatterns: [/look at this instruction\.txt$/] },
  { name: "Babuk", extPatterns: [/^\.babyk$/, /^\.babuk$/, /^\.doydo$/], notePatterns: [/how to restore your files\.txt$/] },
  { name: "Zeppelin", extPatterns: [/^\.zeppelin$/], notePatterns: [/all your files are encrypted !!!/] },
  { name: "Snatch", extPatterns: [/^\.snatch$/], notePatterns: [/how to restore your files\.txt$/] },
  { name: "Nefilim", aka: "Nefilim / Nemty", extPatterns: [/^\.nefilim$/, /^\.off$/, /^\.nemty.*$/], notePatterns: [/nefilim-decrypt\.txt$/, /nemty.*recovery/] },
  { name: "Maze", extPatterns: [], notePatterns: [/^decrypt-files\.txt$/] },
  { name: "Egregor", extPatterns: [], notePatterns: [/^recover-files\.txt$/] },
  { name: "HelloKitty", aka: "HelloKitty / FiveHands", extPatterns: [/^\.crypted$/, /^\.kitty$/], notePatterns: [/read_me_lkdtt\.txt$/] },
  { name: "Quantum", aka: "Quantum / Dagon", extPatterns: [], notePatterns: [/readme_to_decrypt\.html$/] },
  { name: "Lorenz", extPatterns: [/^\.lorenz(\.sz40)?$/], notePatterns: [/hello.*\.html$/] },
];

// Best-effort ransomware family attribution from encrypted extension + ransom-note filename.
function _identifyFamily(extensions, ransomNotes) {
  const exts = (extensions || []).map((e) => String(e || "").toLowerCase()).filter(Boolean);
  const notes = (ransomNotes || []).map((n) => String(n?.fileName || "").toLowerCase()).filter(Boolean);
  const scored = [];
  for (const fam of RW_FAMILY_CATALOG) {
    const extHits = exts.filter((e) => (fam.extPatterns || []).some((re) => re.test(e)));
    const noteHits = notes.filter((n) => (fam.notePatterns || []).some((re) => re.test(n)));
    if (extHits.length === 0 && noteHits.length === 0) continue;
    const matchedOn = [];
    if (extHits.length) matchedOn.push("extension");
    if (noteHits.length) matchedOn.push("ransom note");
    // Extensions are family-specific (high); shared notes are weaker on their own (medium); both → confirmed.
    const confidence = (extHits.length && noteHits.length) ? "confirmed" : extHits.length ? "high" : "medium";
    const rank = (extHits.length && noteHits.length) ? 3 : extHits.length ? 2 : 1;
    const evidence = [...new Set([...extHits, ...noteHits])].slice(0, 3);
    scored.push({ name: fam.name, aka: fam.aka || null, confidence, matchedOn, evidence, rank });
  }
  scored.sort((a, b) => b.rank - a.rank);
  const candidates = scored.slice(0, 3).map(({ rank, ...c }) => c);
  return {
    candidates,
    top: candidates[0] || null,
    note: candidates.length === 0
      ? "No known-family signature matched the encrypted extension or note filename — attribute manually from note contents / threat intel."
      : null,
  };
}

// Return the known ransomware family whose catalog extension pattern matches `ext`, or null.
function _familyForExtension(ext) {
  const e = String(ext || "").toLowerCase();
  if (!e) return null;
  for (const fam of RW_FAMILY_CATALOG) {
    if ((fam.extPatterns || []).some((re) => re.test(e))) return fam.name;
  }
  return null;
}

// Map observed filesystem artifacts to MITRE ATT&CK techniques (impact / evasion phase).
function _buildMitreMapping(o) {
  const T = (id, name, basis) => ({ id, name, url: `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`, basis, observed: true });
  const out = [];
  if (o.encryptedCount > 0) out.push(T("T1486", "Data Encrypted for Impact", `${o.encryptedCount.toLocaleString()} files encrypted${o.ransomNoteCount > 0 ? ` + ${o.ransomNoteCount.toLocaleString()} ransom note(s)` : ""}`));
  // T1490 is artifact-based here (on-host backups encrypted). VSS/shadow-copy deletion via
  // vssadmin/wbadmin is NOT visible in $MFT alone — it requires the event-log correlation slice.
  if (o.backupRecoveryTotal > 0) out.push(T("T1490", "Inhibit System Recovery", `${o.backupRecoveryTotal.toLocaleString()} backup/recovery file(s) encrypted`));
  if (o.deletedEncrypted > 0) out.push(T("T1485", "Data Destruction", `${o.deletedEncrypted.toLocaleString()} encrypted file(s) deleted`));
  // T1070.004 is specifically the removal of ATTACKER artifacts (deleted payloads/scripts/logs);
  // deletion of encrypted originals is the impact pattern (T1485 above), not indicator removal.
  const delArtifacts = (o.antiForensics?.cleanup?.length || 0) + (o.antiForensics?.drops?.length || 0);
  if (delArtifacts > 0) out.push(T("T1070.004", "Indicator Removal: File Deletion", `${delArtifacts.toLocaleString()} deleted payload/cleanup artifact(s)`));
  if (o.timestompedCount > 0) out.push(T("T1070.006", "Indicator Removal: Timestomp", `${o.timestompedCount.toLocaleString()} timestomped file(s)`));
  // EVTX-corroborated defense evasion (when an EVTX tab was correlated) — adds/strengthens techniques
  // that $MFT cannot observe (VSS deletion, log clearing, service install).
  const bt = o.evtx && o.evtx.byTechnique;
  if (bt) {
    if (bt["T1490"]) {
      const ex = out.find((t) => t.id === "T1490");
      const basis = `${bt["T1490"]} EVTX shadow-copy/backup-destruction event(s) in window`;
      if (ex) ex.basis += ` · ${basis}`; else out.push(T("T1490", "Inhibit System Recovery", basis));
    }
    if (bt["T1070.001"]) out.push(T("T1070.001", "Indicator Removal: Clear Windows Event Logs", `${bt["T1070.001"]} log-clear event(s) (EVTX)`));
    if (bt["T1569.002"]) out.push(T("T1569.002", "System Services: Service Execution", `${bt["T1569.002"]} service-install event(s) (EVTX)`));
    if (bt["T1562.001"]) out.push(T("T1562.001", "Impair Defenses: Disable or Modify Tools", `${bt["T1562.001"]} defense-evasion indicator(s) (EVTX)`));
  }
  return out;
}

// Parse a minute/second bucket string ("YYYY-MM-DD HH:MM[:SS]") to epoch ms (UTC, naive=UTC).
function _rwBucketMs(s) {
  const m = String(s || "").match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})/);
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], 0) : null;
}

// Fuse the per-stream artifacts into ONE minute-resolution timeline so the dashboard can
// overlay payload drops, ransom-note creation, encryption volume, and USN deletes/overwrites
// on a single shared time axis (with onset / peak / end markers). Pure — unit-tested.
function _buildIncidentTimeline(o) {
  const toBuckets = (arr, key) => (arr || []).map((b) => ({ ms: _rwBucketMs(b && b[key]), count: b && b.count || 0 })).filter((x) => x.ms != null);
  const binTs = (arr, key) => {
    const map = new Map();
    for (const it of arr || []) { const ms = _rwBucketMs(it && it[key]); if (ms == null) continue; map.set(ms, (map.get(ms) || 0) + 1); }
    return [...map.entries()].map(([ms, count]) => ({ ms, count })).sort((a, b) => a.ms - b.ms);
  };
  const byMs = (a, b) => a.ms - b.ms;
  const encryption = toBuckets(o.timeline, "bucket").sort(byMs);
  const notes = binTs(o.ransomNotes, "created");
  const payloads = binTs(o.suspiciousFiles, "created");
  const deletes = toBuckets(o.usnEnrichment && o.usnEnrichment.deleteBuckets, "bucket").sort(byMs);
  const overwrites = toBuckets(o.usnEnrichment && o.usnEnrichment.overwriteBuckets, "bucket").sort(byMs);

  let startMs = Infinity, endMs = -Infinity, peakCount = 0, peakMs = null;
  for (const arr of [encryption, notes, payloads, deletes, overwrites]) {
    for (const x of arr) { if (x.ms < startMs) startMs = x.ms; if (x.ms > endMs) endMs = x.ms; }
  }
  if (!Number.isFinite(startMs)) return null; // no datable events at all
  for (const x of encryption) if (x.count > peakCount) { peakCount = x.count; peakMs = x.ms; }
  const onsetMs = _rwBucketMs(o.preciseStartTime) ?? _rwBucketMs(o.firstTs) ?? (encryption[0] ? encryption[0].ms : startMs);
  const sum = (a) => a.reduce((s, x) => s + x.count, 0);
  return {
    startMs, endMs, onsetMs, peakMs, peakCount,
    endEncMs: encryption.length ? encryption[encryption.length - 1].ms : null,
    encryption, notes, payloads, deletes, overwrites,
    totals: { encryption: sum(encryption), notes: sum(notes), payloads: sum(payloads), deletes: sum(deletes), overwrites: sum(overwrites) },
  };
}

// ── Squarified treemap (Bruls et al.) for the directory blast-radius view ──────────
function _rwWorstAspect(areas, length) {
  let sum = 0, max = -Infinity, min = Infinity;
  for (const a of areas) { sum += a; if (a > max) max = a; if (a < min) min = a; }
  if (sum <= 0 || length <= 0) return Infinity;
  const s2 = sum * sum, l2 = length * length;
  return Math.max((l2 * max) / s2, s2 / (l2 * min));
}
function _squarifyInto(items, areas, x0, y0, w0, h0, out) {
  let x = x0, y = y0, w = w0, h = h0, i = 0;
  const n = items.length;
  while (i < n) {
    const shorter = Math.min(w, h);
    if (shorter <= 0) { for (; i < n; i++) out.push({ ...items[i], x, y, w: 0, h: 0 }); break; }
    const row = [], rowAreas = [];
    let bestWorst = Infinity, j = i;
    while (j < n) {
      const wr = _rwWorstAspect([...rowAreas, areas[j]], shorter);
      if (row.length === 0 || wr <= bestWorst) { row.push(items[j]); rowAreas.push(areas[j]); bestWorst = wr; j++; }
      else break;
    }
    let rowArea = 0; for (const a of rowAreas) rowArea += a;
    const thickness = rowArea / shorter;
    if (w >= h) {
      let cy = y;
      for (let k = 0; k < row.length; k++) { const ih = (rowAreas[k] / rowArea) * h; out.push({ ...row[k], x, y: cy, w: thickness, h: ih }); cy += ih; }
      x += thickness; w -= thickness;
    } else {
      let cx = x;
      for (let k = 0; k < row.length; k++) { const iw = (rowAreas[k] / rowArea) * w; out.push({ ...row[k], x: cx, y, w: iw, h: thickness }); cx += iw; }
      y += thickness; h -= thickness;
    }
    i = j;
  }
  return out;
}
// Build a blast-radius treemap from the affected-directory list (area = files encrypted,
// the UI colors each rect by encryption ratio). Coordinates are in a normalized W×H space.
function _buildBlastTreemap(dirs, W = 1000, H = 400) {
  const items = (dirs || [])
    .map((d) => ({ path: d.path, value: d.encryptedCount || d.count || 0, encryptedCount: d.encryptedCount || d.count || 0, totalCount: d.totalCount || (d.encryptedCount || d.count || 0), ratio: typeof d.ratio === "number" ? d.ratio : null, childDirCount: d.childDirCount || 1 }))
    .filter((it) => it.value > 0)
    .sort((a, b) => b.value - a.value)
    .slice(0, 16);
  if (items.length === 0) return null;
  let total = 0; for (const it of items) total += it.value;
  const scale = (W * H) / total;
  const areas = items.map((it) => it.value * scale);
  const rects = _squarifyInto(items, areas, 0, 0, W, H, []);
  return { width: W, height: H, rects, total, shown: items.length, totalDirs: (dirs || []).length };
}

// Scope the encrypted set by administrative boundary. An MFT is per-volume and its ParentPath
// is relative (".\Users\alice\..."), so there is no drive letter to split on — we break down by
// top-level area (Users / ProgramData / inetpub / …) and by user profile, which ARE in the path.
function _buildScoping(encDirs, encryptedCount) {
  const byUser = new Map(), byArea = new Map();
  let total = 0;
  // Group case-insensitively (Windows paths vary in casing across sources) but keep the
  // first-seen casing for display (usually the canonical "Users" / "ProgramData").
  const add = (map, name, count) => {
    const key = name.toLowerCase();
    const cur = map.get(key);
    if (cur) cur.count += count; else map.set(key, { name, count });
  };
  for (const d of encDirs || []) {
    const count = (d && d.count) || 0;
    if (count <= 0) continue;
    total += count;
    const segs = String((d && d.path) || "").replace(/^\.[\\/]?/, "").split(/[\\/]+/).filter(Boolean);
    add(byArea, segs[0] || "(root)", count);
    const ui = segs.findIndex((s) => /^users$/i.test(s));
    if (ui >= 0 && segs[ui + 1]) {
      const user = segs[ui + 1];
      if (!/^(public|default|defaultuser\d*|all users|default user)$/i.test(user)) add(byUser, user, count);
    }
  }
  if (total === 0) return null;
  const denom = encryptedCount > 0 ? encryptedCount : total;
  const toArr = (m) => [...m.values()].map((v) => ({ name: v.name, count: v.count, pct: Math.round((v.count / denom) * 1000) / 1000 })).sort((a, b) => b.count - a.count);
  const users = toArr(byUser), areas = toArr(byArea);
  let note = null;
  if (users.length === 1) note = `Encryption is concentrated in a single user profile (${users[0].name}) — consistent with targeted or early-stage activity.`;
  else if (users.length >= 5) note = `${users.length} user profiles affected — broad, host-wide impact.`;
  return {
    byUser: users.slice(0, 12), byArea: areas.slice(0, 12),
    userCount: users.length, areaCount: areas.length, total,
    coverage: Math.round((total / denom) * 1000) / 1000, dirsConsidered: (encDirs || []).length, note,
  };
}

// ── Cross-artifact EVTX defense-evasion correlation (optional 2nd tab) ──────────
// Resolve an EVTX-style tab's timestamp / EventID / text columns by header pattern
// (raw EVTX, EvtxECmd, Hayabusa, Chainsaw all differ) → SAFE (c0..cN) column names.
function _rwResolveEvtxCols(meta) {
  const headers = (meta && meta.headers) || [];
  const colMap = (meta && meta.colMap) || {};
  const find = (pats) => { for (const p of pats) { const h = headers.find((x) => p.test(x)); if (h && colMap[h]) return colMap[h]; } return null; };
  const findAll = (pats) => { const out = []; for (const h of headers) { if (pats.some((p) => p.test(h)) && colMap[h]) out.push(colMap[h]); } return out; };
  return {
    ts: find([/^TimeCreated$/i, /^UtcTime$/i, /^datetime$/i, /^Timestamp$/i, /^system_time$/i, /^TimeGenerated$/i]),
    eid: find([/^EventID$/i, /^EventId$/i, /^event_id$/i, /^id$/i]),
    // Provider / channel — used to scope ambiguous EventIDs (EID 1 is reused by many providers;
    // only Sysmon/Operational EID 1 and Security EID 4688 are process-creation events).
    channel: find([/^Channel$/i, /^channel$/i, /^Provider$/i, /^ProviderName$/i, /^SourceName$/i, /^Source$/i]),
    // Distinct process-creation columns when the format explodes EventData (raw EVTX) — bare
    // values with no `label:` prefix, so they must be resolved as their own columns rather than
    // parsed from the text blob. Null for blob formats (EvtxECmd PayloadData / Hayabusa Details).
    proc: {
      image: find([/^Image$/i, /^NewProcessName$/i, /^ProcessName$/i]),
      cmdLine: find([/^CommandLine$/i, /^ProcessCommandLine$/i, /^command_line$/i]),
      parentImage: find([/^ParentImage$/i, /^ParentProcessName$/i]),
      user: find([/^User$/i, /^SubjectUserName$/i, /^TargetUserName$/i]),
    },
    // any column that may carry a command line / message / payload — searched together
    textCols: findAll([/^CommandLine$/i, /^ProcessCommandLine$/i, /^command_line$/i, /^ExecutableInfo$/i, /^Details$/i, /^ExtraFieldInfo$/i, /^Message$/i, /^MapDescription$/i, /^RuleTitle$/i, /^PayloadData[1-6]$/i, /^Payload$/i]),
  };
}
// Is a tab an EVTX event log we can query for defense evasion?
function _rwLooksLikeEvtx(meta) {
  if (!meta) return false;
  if (meta.sourceFormat === "raw-evtx") return true;
  const c = _rwResolveEvtxCols(meta);
  return !!(c.ts && c.eid && c.textCols.length > 0);
}
// Classify a defense-evasion hit (EventID + matched text) → category + MITRE technique.
function _rwCategorizeEvasion(eid, text) {
  const id = String(eid == null ? "" : eid).trim();
  const t = String(text || "").toLowerCase();
  if (id === "1102") return { category: "Security event log cleared", technique: "T1070.001" };
  if (id === "104") return { category: "System/Application event log cleared", technique: "T1070.001" };
  if (/wevtutil\s+(cl|clear-log)\b|clear-eventlog/.test(t)) return { category: "Event log cleared", technique: "T1070.001" };
  if (/vssadmin[^\n]*\bdelete\s+shadows|vssadmin[^\n]*resize\s+shadowstorage|diskshadow|wmic[^\n]*shadowcopy[^\n]*delete|win32_shadowcopy/.test(t)) return { category: "Volume Shadow Copies deleted", technique: "T1490" };
  if (/wbadmin[^\n]*\bdelete\s+(catalog|systemstatebackup|backup)/.test(t)) return { category: "Windows backups deleted", technique: "T1490" };
  if (/bcdedit[^\n]*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/.test(t)) return { category: "Boot recovery disabled", technique: "T1490" };
  if (/cipher\s+\/w/.test(t)) return { category: "Free space wiped (anti-recovery)", technique: "T1490" };
  if (id === "7045") return { category: "Service installed", technique: "T1569.002" };
  // Bare tool references without a destructive verb (e.g. "vssadmin list shadows") are likely
  // benign — surface them for review but do NOT claim a MITRE technique (technique: null), so
  // they don't inflate the T1490 count.
  if (/\b(vssadmin|wbadmin|diskshadow|shadowcopy)\b/.test(t)) return { category: "Shadow/backup tooling referenced", technique: null };
  return { category: "Defense-evasion indicator", technique: null };
}

/**
 * Best-effort process-field extraction from a flattened process-creation event row.
 * Handles the four EVTX representations the app ingests — Sysmon Operational EID 1,
 * Security EID 4688, EvtxECmd CSV, and Hayabusa — all of which flatten to `label:value`
 * blobs but with differing field names and separators (newline / `¦` / `|`). Returns
 * `{ image, cmdLine, parentImage, user }` with nulls for anything unresolved; the caller
 * does NOT rely on these for the execution-confirmation decision (that uses a raw filename
 * match), so partial extraction is acceptable enrichment.
 */
function _rwExtractProcFields(text) {
  const t = String(text == null ? "" : text);
  // A value runs until the next field separator (`¦` / `|` / newline / end) OR the next
  // `FieldName:` label — recognized as whitespace then a ≥2-char CamelCase/CAPS token then a
  // colon/equals. The ≥2-char rule lets drive-letter colons through ("C:\…" never ends a value)
  // while still cutting at the following field even when an UNKNOWN field (FileVersion,
  // SubjectDomainName, …) sits between two recognized ones, so a value never bleeds onward.
  const NEXT = "(?:\\s*[¦|]|\\n|$|(?=\\s+[A-Za-z][A-Za-z0-9_]+\\s*[:=]))";
  const grab = (label) => {
    // Quotes are kept verbatim — stripping a lone leading quote unbalances a quoted command line.
    const m = t.match(new RegExp(`\\b(?:${label})\\s*[:=]\\s*(.*?)${NEXT}`, "i"));
    if (!m) return null;
    const v = m[1].replace(/[\s;,]+$/, "").trim();
    return v || null;
  };
  const parentImage = grab("ParentImage|ParentProcessName");
  const parentCmd = grab("ParentCommandLine|ParentCmdLine|ParentCmdline");
  return {
    image: grab("Image|NewProcessName|ProcessName|Proc"),
    cmdLine: grab("CommandLine|ProcessCommandLine|CmdLine|Cmdline"),
    parentImage: parentImage || parentCmd,
    user: grab("User|SubjectUserName|TargetUserName|AccountName|Account"),
  };
}

/** Lowercased final path component of an image/path string ("C:\\a\\b.exe" → "b.exe"). */
function _rwBasename(p) {
  const s = String(p == null ? "" : p).trim().replace(/^["']+|["']+$/g, "");
  const parts = s.split(/[\\/]/);
  return (parts[parts.length - 1] || "").toLowerCase();
}

/**
 * Does a parsed process event genuinely reference a given payload filename? PRECISE match — NOT
 * a substring of the whole event text (which would confirm a filename merely *mentioned* in a
 * free-form Message/MapDescription, or collide "net.exe"⊂"inet.exe"). A real match means either
 * the process image's basename equals the filename, OR the filename appears in the image/command
 * line as a whole path-component / token (delimiter-bounded on both sides).
 */
function _rwProcMatchesFile(proc, fnameLc) {
  if (!fnameLc) return false;
  const image = String((proc && proc.image) || "");
  if (image && _rwBasename(image) === fnameLc) return true;
  const hay = `${image} ${(proc && proc.cmdLine) || ""}`.toLowerCase();
  if (!hay.includes(fnameLc)) return false;
  const esc = fnameLc.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // bounded by a path separator / whitespace / quote on each side (or string edge)
  return new RegExp(`(?:^|[\\\\/\\s"'])${esc}(?:$|[\\s"';,)])`).test(hay);
}

/**
 * Ransomware MFT Analysis — runs targeted SQL queries to build a comprehensive
 * ransomware impact report from MFT data.
 */
function analyzeRansomware(meta, { encryptedExt, ransomNotePattern, noteMatchMode, usnMeta, evtxMeta, progressCb }) {
  const _p = typeof progressCb === "function" ? progressCb : () => {};
  const empty = { encryptedCount: 0, totalEncryptedSizeBytes: 0, firstEncrypted: null, lastEncrypted: null, durationMinutes: 0, filesPerMinute: 0, ransomNotes: [], ransomNoteCount: 0, timeline: [], topDirectories: [], deletedEncrypted: 0, timestompedCount: 0, suspiciousFiles: [], usnEnrichment: null, evtxEnrichment: null, processCorrelation: null, inPlaceEncryption: null, timingEvidence: null };
  if (!meta) return empty;

  const db = meta.db;
  const col = (name) => meta.colMap[name];
  const parseTs = (s) => {
    const m = String(s || "").match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
    return m ? new Date(Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6])) : null;
  };
  const fmtTs = (d) => {
    if (!(d instanceof Date) || isNaN(d.getTime())) return null;
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  };
  const pickAnchorTs = (row, mode = "start") => {
    const candidates = [row?.recordChange0x10, row?.timestamp, row?.lastMod0x30].map(parseTs).filter(Boolean);
    if (candidates.length === 0) return null;
    const millis = candidates.map((d) => d.getTime());
    return new Date(mode === "end" ? Math.max(...millis) : Math.min(...millis));
  };
  const buildTimingSnapshot = (row, usnTimestamp = null) => {
    const candidates = [
      row?.timestamp ? { key: "timeline", label: "SI Modified", column: "LastModified0x10", timestamp: row.timestamp, basis: "observed", role: "timeline" } : null,
      row?.recordChange0x10 ? { key: "recordChange", label: "Record Change", column: "LastRecordChange0x10", timestamp: row.recordChange0x10, basis: "observed", role: "metadata" } : null,
      row?.lastMod0x30 ? { key: "fnModified", label: "FN Modified", column: "LastModified0x30", timestamp: row.lastMod0x30, basis: "observed", role: "metadata" } : null,
      row?.created0x10 ? { key: "siCreated", label: "SI Created", column: "Created0x10", timestamp: row.created0x10, basis: "observed", role: "context" } : null,
      row?.created0x30 ? { key: "fnCreated", label: "FN Created", column: "Created0x30", timestamp: row.created0x30, basis: "observed", role: "context" } : null,
      usnTimestamp ? { key: "usnRename", label: "USN Rename", column: "UpdateTimestamp", timestamp: usnTimestamp, basis: "observed", role: "journal" } : null,
    ].filter(Boolean);
    const parsed = candidates.map((c) => ({ ...c, parsed: parseTs(c.timestamp) })).filter((c) => c.parsed);
    const earliest = parsed.reduce((best, cur) => (!best || cur.parsed < best.parsed ? cur : best), null);
    const latest = parsed.reduce((best, cur) => (!best || cur.parsed > best.parsed ? cur : best), null);
    const preferred = parsed.find((c) => c.key === "usnRename")
      || parsed.find((c) => c.key === "recordChange")
      || parsed.find((c) => c.key === "timeline")
      || parsed[0]
      || null;
    const pack = (item) => item ? {
      label: item.label,
      column: item.column,
      timestamp: item.timestamp,
      basis: item.basis,
      role: item.role,
    } : null;
    return {
      preferred: pack(preferred),
      earliest: pack(earliest),
      latest: pack(latest),
      skewMinutes: earliest && latest ? Math.round((((latest.parsed - earliest.parsed) / 60000) + Number.EPSILON) * 10) / 10 : 0,
      sources: candidates.map((c) => pack(c)),
    };
  };

  // Validate required MFT columns exist
  const ext = col("Extension"), fn = col("FileName"), pp = col("ParentPath"), fs = col("FileSize");
  const inUse = col("InUse"), isDir = col("IsDirectory"), siFN = col("SI<FN");
  const created = col("Created0x10"), lastMod = col("LastModified0x10"), entry = col("EntryNumber"), zoneId = col("ZoneIdContents");
  const recChange = col("LastRecordChange0x10");
  const created0x30 = col("Created0x30");
  const lastMod0x30 = col("LastModified0x30");
  if (!ext || !fn || !pp || !lastMod || !entry) return { ...empty, error: "MFT columns not found. This feature requires MFT data." };

  // Normalize extensions — support comma-separated multi-extension input
  const extParts = (encryptedExt || "").split(/[,;|]+/).map(s => s.trim()).filter(Boolean).map(s => s.startsWith(".") ? s : "." + s);
  if (extParts.length === 0) return { ...empty, error: "No extension provided." };
  const extWhereAll = `LOWER(${ext}) IN (${extParts.map(() => "LOWER(?)").join(",")})`;
  const coreTsSelect = `${created ? `, ${created} as created0x10` : ""}${recChange ? `, ${recChange} as recordChange0x10` : ""}${created0x30 ? `, ${created0x30} as created0x30` : ""}${lastMod0x30 ? `, ${lastMod0x30} as lastMod0x30` : ""}`;

  const notDir = isDir ? `AND (${isDir} IS NULL OR ${isDir} = '' OR ${isDir} = 'False')` : "";

  try {
    // Q1: Encrypted file stats (multi-extension)
    _p({ stage: "counting", pct: 5, detail: "Counting encrypted files" });
    const q1 = db.prepare(`SELECT COUNT(*) as cnt, SUM(CAST(${fs || "'0'"} AS REAL)) as totalSize FROM data WHERE ${extWhereAll} ${notDir}`).get(...extParts);
    const encryptedCount = q1?.cnt || 0;
    if (encryptedCount === 0) return { ...empty, encryptedCount: 0, extensions: extParts };

    // Q2: First and Last encrypted files
    _p({ stage: "timeline", pct: 10, detail: `${encryptedCount.toLocaleString()} encrypted files found` });
    const firstQ = db.prepare(`SELECT data.rowid as rowId, ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${lastMod} as timestamp${coreTsSelect} FROM data WHERE ${extWhereAll} ${notDir} ORDER BY sort_datetime(${lastMod}) ASC, rowid LIMIT 1`).get(...extParts);
    const lastQ = db.prepare(`SELECT data.rowid as rowId, ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${lastMod} as timestamp${coreTsSelect} FROM data WHERE ${extWhereAll} ${notDir} ORDER BY sort_datetime(${lastMod}) DESC, rowid LIMIT 1`).get(...extParts);
    const startAnchorDt = pickAnchorTs(firstQ, "start") || parseTs(firstQ?.timestamp);
    const endAnchorDt = pickAnchorTs(lastQ, "end") || parseTs(lastQ?.timestamp);

    // Compute duration
    let durationMinutes = 0, filesPerMinute = 0;
    if (startAnchorDt && endAnchorDt) {
      durationMinutes = Math.max(1, Math.round((endAnchorDt - startAnchorDt) / 60000));
      filesPerMinute = encryptedCount / durationMinutes;
    }

    // Q2b: First 50 encrypted files (encryption spread) — with multi-timestamp columns
    const fsSel = fs ? `, ${fs} as fileSize` : "";
    const firstEncryptedFiles = db.prepare(
      `SELECT data.rowid as rowId, ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${lastMod} as timestamp${fsSel}${coreTsSelect} FROM data WHERE ${extWhereAll} ${notDir} ORDER BY sort_datetime(${lastMod}) ASC, rowid LIMIT 50`
    ).all(...extParts);

    // Q3: Ransom notes — multi-mode matching (exact/contains/regex/multi)
    _p({ stage: "notes", pct: 20, detail: "Searching for ransom notes" });
    let ransomNotes = [];
    if (ransomNotePattern && ransomNotePattern.trim()) {
      const noteParam = ransomNotePattern.trim();
      const createdCol = created || lastMod;
      const noteExtraCols = `${lastMod !== createdCol ? `, ${lastMod} as lastModified` : ""}${recChange ? `, ${recChange} as recordChange0x10` : ""}`;
      let noteWhere, noteParams;
      const mode = noteMatchMode || "exact";
      switch (mode) {
        case "contains": {
          const escaped = noteParam.replace(/[%_]/g, c => "\\" + c);
          noteWhere = `LOWER(${fn}) LIKE ? ESCAPE '\\'`;
          noteParams = [`%${escaped.toLowerCase()}%`];
          break;
        }
        case "regex":
          // Pre-filter by note-like extensions for performance, then JS regex post-filter
          noteWhere = `LOWER(${ext}) IN ('.txt','.html','.htm','.hta','.url','.bmp','.png') AND CAST(${fs || "'0'"} AS REAL) < 102400`;
          noteParams = [];
          break;
        case "multi": {
          const names = noteParam.split(/[,;|]+/).map(s => s.trim()).filter(Boolean);
          if (names.length === 0) { noteWhere = "0"; noteParams = []; break; }
          noteWhere = names.map(() => `LOWER(${fn}) = LOWER(?)`).join(" OR ");
          noteParams = names;
          break;
        }
        default:
          noteWhere = `LOWER(${fn}) = LOWER(?)`;
          noteParams = [noteParam];
      }
      ransomNotes = db.prepare(
        `SELECT data.rowid as rowId, ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${createdCol} as created${noteExtraCols} FROM data WHERE (${noteWhere}) ORDER BY sort_datetime(${createdCol}) ASC, rowid LIMIT 1000`
      ).all(...noteParams);
      if (mode === "regex") {
        const compiled = compileSafeRegex(noteParam, "i");
        if (compiled.error) {
          // Reject pathological / malformed pattern silently — analyst sees
          // zero notes rather than the app hanging on backtracking.
          dbg("ransomware: rejecting unsafe regex pattern", { error: compiled.error });
          ransomNotes = [];
        } else {
          ransomNotes = ransomNotes.filter((n) => compiled.test(n.fileName));
        }
      }
    }

    // Q3b: USN Journal enrichment (optional)
    _p({ stage: "usn", pct: 25, detail: "USN Journal correlation" });
    let usnEnrichment = null;
    if (usnMeta && (startAnchorDt || firstQ?.timestamp) && (endAnchorDt || lastQ?.timestamp)) {
      try {
        const uT1 = startAnchorDt || parseTs(firstQ?.timestamp);
        const uT2 = endAnchorDt || parseTs(lastQ?.timestamp);
        if (uT1 && uT2) {
          const usnStart = fmtTs(new Date(uT1.getTime() - 5 * 60000));
          const usnEnd = fmtTs(new Date(uT2.getTime() + 5 * 60000));
          const usnDb = usnMeta.db;
          const usnCol = (name) => usnMeta.colMap[name];
          const usnTs = usnCol("UpdateTimestamp"), usnName = usnCol("Name"), usnReasons = usnCol("UpdateReasons");
          const usnExtC = usnCol("Extension"), usnPp = usnCol("ParentPath");
          if (usnTs && usnName && usnReasons) {
            const usnExtLikes = extParts.map(() => `LOWER(${usnName}) LIKE ?`).join(" OR ");
            const usnExtParams = extParts.map((e) => `%${e.toLowerCase()}`);
            const renameEvents = usnDb.prepare(
              `SELECT ${usnTs} as timestamp, ${usnName} as name${usnExtC ? `, ${usnExtC} as extension` : ""}${usnPp ? `, ${usnPp} as parentPath` : ""}, ${usnReasons} as reasons FROM data WHERE ${usnReasons} LIKE '%RenameNewName%' AND sort_datetime(${usnTs}) BETWEEN sort_datetime(?) AND sort_datetime(?) AND (${usnExtLikes}) ORDER BY sort_datetime(${usnTs}) ASC, rowid LIMIT 500`
            ).all(usnStart, usnEnd, ...usnExtParams);
            const overwriteEvents = usnDb.prepare(
              `SELECT extract_datetime_minute(${usnTs}) as bucket, COUNT(*) as count FROM data WHERE (${usnReasons} LIKE '%DataOverwrite%' OR ${usnReasons} LIKE '%DataExtend%') AND sort_datetime(${usnTs}) BETWEEN sort_datetime(?) AND sort_datetime(?) GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`
            ).all(usnStart, usnEnd);
            const deleteEvents = usnDb.prepare(
              `SELECT extract_datetime_minute(${usnTs}) as bucket, COUNT(*) as count FROM data WHERE ${usnReasons} LIKE '%FileDelete%' AND sort_datetime(${usnTs}) BETWEEN sort_datetime(?) AND sort_datetime(?) GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`
            ).all(usnStart, usnEnd);
            usnEnrichment = {
              renameCount: renameEvents.length,
              renameSamples: renameEvents.slice(0, 20),
              overwriteBuckets: overwriteEvents,
              overwriteTotal: overwriteEvents.reduce((s, b) => s + b.count, 0),
              deleteBuckets: deleteEvents,
              deleteTotal: deleteEvents.reduce((s, b) => s + b.count, 0),
              preciseStartTime: renameEvents.length > 0 ? renameEvents[0].timestamp : null,
              windowStart: usnStart,
              windowEnd: usnEnd,
            };
          }
        }
      } catch { /* USN correlation failed — non-fatal */ }
    }

    // Q3c: EVTX defense-evasion correlation (optional 2nd tab) — completes T1490 (VSS/backup
    // destruction) + T1070.001 (log clearing) + T1569.002 (service install), which $MFT can't see.
    _p({ stage: "evtx", pct: 28, detail: "EVTX defense-evasion correlation" });
    let evtxEnrichment = null;
    if (evtxMeta && evtxMeta.db && (startAnchorDt || firstQ?.timestamp) && (endAnchorDt || lastQ?.timestamp)) {
      try {
        const eT1 = startAnchorDt || parseTs(firstQ?.timestamp);
        const eT2 = endAnchorDt || parseTs(lastQ?.timestamp);
        const cols = _rwResolveEvtxCols(evtxMeta);
        if (eT1 && eT2 && cols.ts && cols.eid && cols.textCols.length) {
          // VSS deletion frequently PRECEDES encryption — widen the look-back.
          const evStart = fmtTs(new Date(eT1.getTime() - 60 * 60000));
          const evEnd = fmtTs(new Date(eT2.getTime() + 10 * 60000));
          const concat = cols.textCols.map((c) => `COALESCE(${c},'')`).join("||' '||");
          const kws = ["vssadmin", "wbadmin", "bcdedit", "cipher /w", "wevtutil", "diskshadow", "shadowcopy", "delete shadows"];
          const kwLikes = kws.map(() => `LOWER(${concat}) LIKE ?`).join(" OR ");
          const kwParams = kws.map((k) => `%${k.toLowerCase()}%`);
          const rows = evtxMeta.db.prepare(
            `SELECT ${cols.ts} as timestamp, ${cols.eid} as eventId, substr(${concat}, 1, 400) as text FROM data WHERE sort_datetime(${cols.ts}) BETWEEN sort_datetime(?) AND sort_datetime(?) AND (CAST(${cols.eid} AS TEXT) IN ('1102','104','7045') OR (${kwLikes})) ORDER BY sort_datetime(${cols.ts}) ASC, rowid LIMIT 300`
          ).all(evStart, evEnd, ...kwParams);
          const byTechnique = {}, byCategory = {}, hits = [];
          for (const r of rows) {
            const cat = _rwCategorizeEvasion(r.eventId, r.text);
            if (cat.technique) byTechnique[cat.technique] = (byTechnique[cat.technique] || 0) + 1;
            byCategory[cat.category] = (byCategory[cat.category] || 0) + 1;
            if (hits.length < 30) hits.push({ timestamp: r.timestamp, eventId: r.eventId, category: cat.category, technique: cat.technique, text: String(r.text || "").trim().slice(0, 200) });
          }
          evtxEnrichment = { available: true, total: rows.length, hits, byTechnique, byCategory, windowStart: evStart, windowEnd: evEnd };
        }
      } catch (e) { dbg("ransomware: EVTX correlation failed", { error: e.message }); }
    }

    // Q4: Timeline buckets (minute-level)
    _p({ stage: "timeline", pct: 30, detail: "Building encryption timeline" });
    const timeline = db.prepare(`SELECT extract_datetime_minute(${lastMod}) as bucket, COUNT(*) as count FROM data WHERE ${extWhereAll} ${notDir} AND ${lastMod} IS NOT NULL AND ${lastMod} != '' GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`).all(...extParts);

    // Q5: Top affected directories — subtree grouped with encrypted/total ratios
    _p({ stage: "directories", pct: 35, detail: "Mapping affected directories" });
    const encDirsRaw = db.prepare(`SELECT ${pp} as path, COUNT(*) as count FROM data WHERE ${extWhereAll} ${notDir} GROUP BY ${pp} ORDER BY count DESC, path LIMIT 500`).all(...extParts);
    const allDirsRaw = db.prepare(`SELECT ${pp} as path, COUNT(*) as total FROM data WHERE ${pp} IN (SELECT DISTINCT ${pp} FROM data WHERE ${extWhereAll} ${notDir}) ${notDir} GROUP BY ${pp}`).all(...extParts);
    const topDirectories = _groupBySubtree(encDirsRaw, allDirsRaw);

    // Q6: Forensic indicators
    let deletedEncrypted = 0, timestompedCount = 0;
    if (inUse) {
      const dq = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${extWhereAll} AND ${inUse} = 'False'`).get(...extParts);
      deletedEncrypted = dq?.cnt || 0;
    }
    if (siFN) {
      const tq = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${extWhereAll} AND ${siFN} = 'True'`).get(...extParts);
      timestompedCount = tq?.cnt || 0;
    }

    // Q7: Suspicious files near infection time (±30 min window) — scored payload candidates
    _p({ stage: "payloads", pct: 45, detail: "Scoring suspicious payloads" });
    let suspiciousFiles = [];
    let windowStart = null, windowEnd = null;
    const suspiciousAnchorDt = parseTs(usnEnrichment?.preciseStartTime) || startAnchorDt || parseTs(firstQ?.timestamp);
    if (suspiciousAnchorDt && created) {
        windowStart = fmtTs(new Date(suspiciousAnchorDt.getTime() - 30 * 60000));
        windowEnd = fmtTs(new Date(suspiciousAnchorDt.getTime() + 30 * 60000));
        const suspExts = [".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".jar",".py",".com"];
        const extPlaceholders = suspExts.map(() => "?").join(",");
        const zoneCol = zoneId || `''`;
        const q7extra = `${inUse ? `, ${inUse} as inUse` : ""}${siFN ? `, ${siFN} as siFN` : ""}${lastMod ? `, ${lastMod} as lastModified` : ""}${recChange ? `, ${recChange} as recordChange0x10` : ""}${created0x30 ? `, ${created0x30} as created0x30` : ""}${lastMod0x30 ? `, ${lastMod0x30} as lastMod0x30` : ""}`;
        suspiciousFiles = db.prepare(
          `SELECT data.rowid as rowId, ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${created} as created, ${ext} as extension, ${zoneCol} as zoneId${q7extra} FROM data WHERE sort_datetime(${created}) BETWEEN sort_datetime(?) AND sort_datetime(?) AND LOWER(${ext}) IN (${extPlaceholders}) ${notDir} ORDER BY sort_datetime(${created}) ASC, rowid LIMIT 200`
        ).all(windowStart, windowEnd, ...suspExts);

        // Score each suspicious file
        const riskyPathRe = /\\(temp|programdata|appdata|public|\$recycle\.bin|downloads|users\\public)/i;
        const firstNoteTs = ransomNotes.length > 0 ? parseTs(ransomNotes[0].created) : null;
        const firstEncTs = suspiciousAnchorDt;
        for (const sf of suspiciousFiles) {
          const signals = [];
          let score = 0;
          const sfTs = parseTs(sf.created);
          if (sfTs && firstEncTs) {
            const deltaMin = Math.abs(sfTs - firstEncTs) / 60000;
            score += Math.max(0, 1 - deltaMin / 60) * 0.4;
            if (deltaMin <= 5) signals.push({ text: `${Math.round(deltaMin)}min from onset`, type: "correlation", basis: "observed" });
            else if (deltaMin <= 15) signals.push({ text: `${Math.round(deltaMin)}min from onset`, type: "correlation", basis: "observed" });
          }
          if (riskyPathRe.test(sf.parentPath)) { score += 0.15; signals.push({ text: "risky-path", type: "context", basis: "observed" }); }
          if (sf.zoneId) { score += 0.2; signals.push({ text: "web-download", type: "execution", basis: "observed" }); }
          if (sf.inUse === "False") { score += 0.1; signals.push({ text: "deleted", type: "execution", basis: "observed" }); }
          if (sf.siFN === "True") { score += 0.1; signals.push({ text: "timestomped", type: "execution", basis: "observed" }); }
          if (firstNoteTs && sfTs) {
            const noteDelta = Math.abs(sfTs - firstNoteTs) / 60000;
            if (noteDelta <= 5) { score += 0.05; signals.push({ text: "near-note-drop", type: "correlation", basis: "inferred" }); }
          }
          sf.score = Math.min(1, Math.round(score * 1000) / 1000);
          sf.signals = signals;
          sf.confidence = sf.score >= 0.6 ? "confirmed" : sf.score >= 0.35 ? "likely" : sf.score >= 0.15 ? "suspicious" : "anomalous";
        }
        suspiciousFiles.sort((a, b) => b.score - a.score);
    }

    // Q7b: Process-execution correlation — which process/parent/user ran in the encryption
    // window, and did any MFT payload candidate actually EXECUTE? Reuses the correlated EVTX
    // tab via the proven multi-tab pattern. Runs AFTER Q7 so it can confirm/boost the scored
    // payload candidates. Non-fatal and bounded: absent EVTX tab leaves this null.
    _p({ stage: "evtx-proc", pct: 50, detail: "Correlating process execution" });
    let processCorrelation = null;
    if (evtxMeta && evtxMeta.db && (startAnchorDt || firstQ?.timestamp)) {
      try {
        const pT1 = parseTs(usnEnrichment?.preciseStartTime) || startAnchorDt || parseTs(firstQ?.timestamp);
        const pT2 = endAnchorDt || parseTs(lastQ?.timestamp) || pT1;
        const cols = _rwResolveEvtxCols(evtxMeta);
        if (pT1 && pT2 && cols.ts && cols.eid && cols.textCols.length) {
          // The launcher (parent) commonly precedes encryption — look back 60 min.
          const pStart = fmtTs(new Date(pT1.getTime() - 60 * 60000));
          const pEnd = fmtTs(new Date(pT2.getTime() + 10 * 60000));
          const concat = cols.textCols.map((c) => `COALESCE(${c},'')`).join("||' '||");
          // Process-creation events: Sysmon Operational EID 1, Security EID 4688. EID 1 is
          // reused by many providers, so when a Channel/Provider column exists we scope to the
          // Sysmon/Security sources — this excludes coincidental EID-1 events (Kernel-General
          // time-change, ETW diagnostics, …) that would otherwise create false confirmations.
          const sel = [`${cols.ts} as timestamp`, `${cols.eid} as eventId`];
          if (cols.proc.image) sel.push(`${cols.proc.image} as pimage`);
          if (cols.proc.cmdLine) sel.push(`${cols.proc.cmdLine} as pcmd`);
          if (cols.proc.parentImage) sel.push(`${cols.proc.parentImage} as pparent`);
          if (cols.proc.user) sel.push(`${cols.proc.user} as puser`);
          sel.push(`substr(${concat}, 1, 600) as text`);
          const chanClause = cols.channel ? ` AND (LOWER(${cols.channel}) LIKE '%sysmon%' OR LOWER(${cols.channel}) LIKE '%sec%')` : "";
          const rows = evtxMeta.db.prepare(
            `SELECT ${sel.join(", ")} FROM data WHERE CAST(${cols.eid} AS TEXT) IN ('1','4688')${chanClause} AND sort_datetime(${cols.ts}) BETWEEN sort_datetime(?) AND sort_datetime(?) ORDER BY sort_datetime(${cols.ts}) ASC, rowid LIMIT 1000`
          ).all(pStart, pEnd);
          const lc = (s) => String(s == null ? "" : s).toLowerCase();
          const nz = (v) => { const s = String(v == null ? "" : v).trim(); return s || null; };
          // Prefer distinct columns (raw EVTX explodes EventData into bare-value columns); fall
          // back to label-parsing the text blob (EvtxECmd PayloadData / Hayabusa Details).
          const procs = rows.map((r) => {
            const f = _rwExtractProcFields(r.text);
            return { timestamp: r.timestamp, eventId: String(r.eventId == null ? "" : r.eventId),
              image: nz(r.pimage) || f.image, cmdLine: nz(r.pcmd) || f.cmdLine,
              parentImage: nz(r.pparent) || f.parentImage, user: nz(r.puser) || f.user };
          });
          // Cross-reference MFT payload candidates: a dropped binary that ALSO has a
          // process-creation event = execution-confirmed, and recovers its parent + user.
          // PRECISE match (basename / path-component), NOT a substring of the whole event text —
          // so "net.exe" can't confirm via "inet.exe" and a filename merely mentioned in a
          // free-form Message/MapDescription field cannot fabricate an execution.
          let confirmedPayloads = 0;
          const confirmedList = [];
          for (const sf of suspiciousFiles) {
            const fn = lc(sf.fileName).trim();
            if (!fn || fn.length < 5) continue; // avoid trivially-short filename collisions
            const hit = procs.find((p) => _rwProcMatchesFile(p, fn));
            if (!hit) continue;
            sf.executionConfirmed = true;
            sf.execContext = { time: hit.timestamp, parentImage: hit.parentImage || null, user: hit.user || null, eventId: hit.eventId };
            if (typeof sf.score === "number") sf.score = Math.min(1, Math.round((sf.score + 0.25) * 1000) / 1000);
            sf.confidence = "confirmed";
            sf.signals = [...(sf.signals || []), { text: "executed (EVTX)", type: "execution", basis: "observed" }];
            confirmedPayloads++;
            confirmedList.push({ fileName: sf.fileName, parentPath: sf.parentPath, ...sf.execContext });
          }
          if (confirmedPayloads > 0) suspiciousFiles.sort((a, b) => b.score - a.score);
          // Surface executed processes (those with a resolvable image or command line),
          // flagging the ones from ransomware-relevant paths / verbs for the analyst.
          const riskyRe = /\\(?:temp|programdata|appdata|public|\$recycle\.bin|downloads|perflogs|users\\public)\\|\\windows\\temp\b/i;
          const evasionRe = /vssadmin|wbadmin|bcdedit|wevtutil|cipher\s+\/w|diskshadow|shadowcopy|wmic[^\n]*shadow|taskkill|net\s+stop|sc\s+(?:stop|config|delete)|-enc(?:odedcommand)?\b|frombase64string/i;
          const confirmedNames = confirmedList.map((c) => lc(c.fileName));
          const observed = procs
            .filter((p) => p.image || p.cmdLine)
            .map((p) => ({ timestamp: p.timestamp, eventId: p.eventId, image: p.image, cmdLine: p.cmdLine ? p.cmdLine.slice(0, 240) : null, parentImage: p.parentImage, user: p.user,
                risky: riskyRe.test(`${p.image || ""} ${p.cmdLine || ""}`), evasion: evasionRe.test(p.cmdLine || ""),
                matchedPayload: confirmedNames.some((fn) => _rwProcMatchesFile(p, fn)) }));
          // Prioritise: payload-matched, then evasion, then risky-path, then chronological.
          observed.sort((a, b) => (Number(b.matchedPayload) - Number(a.matchedPayload)) || (Number(b.evasion) - Number(a.evasion)) || (Number(b.risky) - Number(a.risky)));
          processCorrelation = {
            available: true,
            total: rows.length,
            confirmedPayloads,
            confirmed: confirmedList.slice(0, 20),
            processes: observed.slice(0, 40),
            channelScoped: !!cols.channel,
            windowStart: pStart,
            windowEnd: pEnd,
          };
        }
      } catch (e) { dbg("ransomware: process correlation failed", { error: e.message }); }
    }

    // Q7c: In-place / overwrite encryption detection (a SUSPICION surface — see helpers above).
    // Independent of the extension-keyed surface; never touches encryptionMethod. Runs over the
    // WHOLE MFT (the attacks it catches leave no ransom-extension window to anchor on) but is
    // bounded by HAVING / LIMIT and runs in the analyzer worker thread.
    _p({ stage: "inplace", pct: 52, detail: "Scanning for in-place encryption" });
    let inPlaceEncryption = null;
    {
      const hasFnCol = !!(lastMod0x30 && created && lastMod && ext && pp);
      let burst = null, ipSamples = [], ipExtBreakdown = [], ipUsnOWNR = null;
      if (hasFnCol) {
        try {
          const bizExts = RW_INPLACE_BUSINESS_EXTS;
          const extPlace = bizExts.map(() => "?").join(",");
          const pathExcl = RW_INPLACE_PATH_EXCLUDES.map(() => `LOWER(${pp}) NOT LIKE ?`).join(" AND ");
          const pathParams = RW_INPLACE_PATH_EXCLUDES.map((s) => `%${s}%`);
          // SI 0x10 Modified LATER than FN 0x30 Modified = content written after the name was last
          // set (a rewrite, not a rename and not a fresh create). Computed explicitly — the siFN
          // column is the INVERSE (SI earlier than FN = timestomping) and must NOT be used here.
          const ipWhere = `sort_datetime(${lastMod}) > sort_datetime(${lastMod0x30}) AND LOWER(${ext}) IN (${extPlace}) AND ${pathExcl} ${notDir} AND ${lastMod} IS NOT NULL AND ${lastMod} != '' AND ${lastMod0x30} IS NOT NULL AND ${lastMod0x30} != ''`;
          const bucketRows = db.prepare(
            `SELECT extract_datetime_minute(${lastMod}) as bucket, COUNT(*) as cnt, COUNT(DISTINCT ${pp}) as dirCount FROM data WHERE ${ipWhere} GROUP BY bucket HAVING bucket IS NOT NULL AND cnt >= 3 ORDER BY bucket`
          ).all(...bizExts, ...pathParams);
          burst = _rwFindBurst(bucketRows, { maxGapMin: 5, minFiles: 30 });
          if (burst) {
            const wStart = burst.buckets[0].bucket + ":00";
            const wEnd = burst.buckets[burst.buckets.length - 1].bucket + ":59";
            ipSamples = db.prepare(
              `SELECT ${ext} as extension, ${fn} as fileName, ${pp} as parentPath, ${created} as created0x10, ${lastMod} as lastMod0x10, ${lastMod0x30} as lastMod0x30 FROM data WHERE ${ipWhere} AND sort_datetime(${lastMod}) BETWEEN sort_datetime(?) AND sort_datetime(?) ORDER BY sort_datetime(${lastMod}) ASC, rowid LIMIT 200`
            ).all(...bizExts, ...pathParams, wStart, wEnd);
            ipExtBreakdown = db.prepare(
              `SELECT LOWER(${ext}) as extension, COUNT(*) as count FROM data WHERE ${ipWhere} AND sort_datetime(${lastMod}) BETWEEN sort_datetime(?) AND sort_datetime(?) GROUP BY LOWER(${ext}) ORDER BY count DESC, extension LIMIT 30`
            ).all(...bizExts, ...pathParams, wStart, wEnd);
            // S3: USN DataOverwrite/DataExtend WITHOUT a rename, aligned to the burst minutes.
            if (usnMeta && usnMeta.db) {
              try {
                const ucol = (n) => usnMeta.colMap[n];
                const uTs = ucol("UpdateTimestamp"), uReasons = ucol("UpdateReasons");
                if (uTs && uReasons) {
                  const burstMins = new Set(burst.buckets.map((b) => b.bucket));
                  // Any overwrite/extend without a rename (broad), and DataOverwrite specifically
                  // (the load-bearing in-place signal — DataExtend alone can be benign growth).
                  const owRows = usnMeta.db.prepare(
                    `SELECT extract_datetime_minute(${uTs}) as bucket, COUNT(*) as count FROM data WHERE (${uReasons} LIKE '%DataOverwrite%' OR ${uReasons} LIKE '%DataExtend%') AND ${uReasons} NOT LIKE '%RenameNewName%' AND sort_datetime(${uTs}) BETWEEN sort_datetime(?) AND sort_datetime(?) GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`
                  ).all(wStart, wEnd);
                  const ovRows = usnMeta.db.prepare(
                    `SELECT extract_datetime_minute(${uTs}) as bucket, COUNT(*) as count FROM data WHERE ${uReasons} LIKE '%DataOverwrite%' AND ${uReasons} NOT LIKE '%RenameNewName%' AND sort_datetime(${uTs}) BETWEEN sort_datetime(?) AND sort_datetime(?) GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`
                  ).all(wStart, wEnd);
                  ipUsnOWNR = {
                    total: owRows.reduce((s, b) => s + b.count, 0),
                    alignedMinutes: owRows.filter((b) => burstMins.has(b.bucket)).length,
                    overwriteTotal: ovRows.reduce((s, b) => s + b.count, 0),
                    overwriteAligned: ovRows.filter((b) => burstMins.has(b.bucket)).length,
                    buckets: owRows.slice(0, 60),
                  };
                }
              } catch (e) { dbg("ransomware: in-place USN correlation failed", { error: e.message }); }
            }
          }
        } catch (e) { dbg("ransomware: in-place detection failed", { error: e.message }); }
      }
      inPlaceEncryption = _buildInPlaceAssessment({ hasFnCol, burst, samples: ipSamples, extBreakdown: ipExtBreakdown, usnOverwriteNoRename: ipUsnOWNR, processCorrelation });
    }

    // Q8: File type impact breakdown + business impact + backup/recovery
    _p({ stage: "impact", pct: 55, detail: "Assessing business impact" });
    // e.g. "report.docx.locked" → ".docx", "photo.jpg.encrypted" → ".jpg"
    const rows8 = db.prepare(
      `SELECT ${fn} as fileName, ${ext} as extension FROM data WHERE ${extWhereAll} ${notDir}`
    ).all(...extParts);
    const origCounts = {};
    // Build strip regex that handles any of the encrypted extensions
    const rxExtAlts = extParts.map(e => e.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
    const stripRe = new RegExp("(" + rxExtAlts + ")$", "i");
    for (const r of rows8) {
      const name = (r.fileName || "").replace(stripRe, "");
      const dot = name.lastIndexOf(".");
      const origExt = dot > 0 ? name.slice(dot).toLowerCase() : "(no extension)";
      origCounts[origExt] = (origCounts[origExt] || 0) + 1;
    }
    const fileTypeBreakdown = Object.entries(origCounts)
      .map(([e, count]) => ({ ext: e, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);

    // Business impact categories
    const catCounts = {};
    for (const [e, count] of Object.entries(origCounts)) {
      const cat = _getExtToCategory().get(e) || "Other";
      catCounts[cat] = (catCounts[cat] || 0) + count;
    }
    const businessImpact = Object.entries(catCounts)
      .map(([category, count]) => ({ category, count, percentage: Math.round((count / encryptedCount) * 1000) / 1000 }))
      .sort((a, b) => b.count - a.count);

    // Backup & recovery artifacts
    const backupRecoveryImpact = [];
    for (const [e, count] of Object.entries(origCounts)) {
      const subtype = RW_BACKUP_RECOVERY.get(e);
      if (subtype) backupRecoveryImpact.push({ ext: e, count, subtype });
    }
    backupRecoveryImpact.sort((a, b) => b.count - a.count);
    const backupRecoveryTotal = backupRecoveryImpact.reduce((s, r) => s + r.count, 0);

    // Q9: Original-to-encrypted pair detection (JS-based, single-pass lookup)
    _p({ stage: "pairs", pct: 65, detail: "Detecting original-encrypted pairs" });
    const originalPairs = (() => {
      const pairSampleLimit = 100;
      const sampled = encryptedCount > pairSampleLimit;
      // 1. Fetch sample of encrypted files
      const encSample = db.prepare(
        `SELECT ${entry} as encEntry, ${fn} as encFileName, ${pp} as parentPath FROM data WHERE ${extWhereAll} ${notDir} LIMIT ${pairSampleLimit}`
      ).all(...extParts);
      // 2. Compute expected original filenames in JS
      const candidates = [];
      for (const ef of encSample) {
        let origName = ef.encFileName;
        for (const e of extParts) {
          if (origName.toLowerCase().endsWith(e.toLowerCase())) {
            origName = origName.slice(0, -e.length);
            break;
          }
        }
        if (origName && origName !== ef.encFileName && origName.length > 0) {
          candidates.push({ ...ef, origFileName: origName });
        }
      }
      if (candidates.length === 0) return { confirmedPairs: 0, likelyPairs: 0, pairRate: 0, samplePairs: [], sampled };
      // 3. Single query to check which originals exist (OR-chain, one table scan)
      const origNotDir = isDir ? `AND (${isDir} IS NULL OR ${isDir} = '' OR ${isDir} = 'False')` : "";
      const orClauses = candidates.map(() => `(${fn} = ? AND ${pp} = ?)`).join(" OR ");
      const orParams = candidates.flatMap(c => [c.origFileName, c.parentPath]);
      const foundRows = db.prepare(
        `SELECT ${fn} as fileName, ${pp} as parentPath${inUse ? `, ${inUse} as inUse` : ""}${fs ? `, ${fs} as fileSize` : ""}, ${entry} as entryNumber FROM data WHERE (${orClauses}) ${origNotDir}`
      ).all(...orParams);
      const foundMap = new Map();
      for (const f of foundRows) foundMap.set(`${f.fileName}\0${f.parentPath}`, f);
      // 4. Evaluate pairs
      let confirmed = 0, likely = 0, residentSampleCount = 0;
      const samplePairs = [];
      for (const c of candidates) {
        const orig = foundMap.get(`${c.origFileName}\0${c.parentPath}`);
        if (orig && inUse && orig.inUse === "False") {
          confirmed++;
          // A deleted original small enough to be MFT-resident may still be recoverable
          // from its (deleted) MFT record even if its clusters are gone.
          if (fs && _rwIsResidentSize(orig.fileSize)) residentSampleCount++;
          samplePairs.push({ originalFile: c.origFileName, encryptedFile: c.encFileName, parentPath: c.parentPath, originalDeleted: true, origEntry: orig.entryNumber, encEntry: c.encEntry });
        } else if (!orig) {
          likely++;
          samplePairs.push({ originalFile: c.origFileName, encryptedFile: c.encFileName, parentPath: c.parentPath, originalDeleted: false, origEntry: null, encEntry: c.encEntry });
        }
      }
      const total = confirmed + likely;
      const pairRate = candidates.length > 0 ? Math.round((total / candidates.length) * 1000) / 1000 : 0;
      const scale = sampled ? encryptedCount / pairSampleLimit : 1;
      // When sampling is active, round extrapolated counts to nearest 100 so
      // the UI doesn't display spuriously precise figures (e.g. "100,043 pairs"
      // when the truth is "~100K, ±10K"). Exact counts only when no sampling.
      const roundEst = (n) => sampled ? Math.round((n * scale) / 100) * 100 : n;
      return {
        confirmedPairs: roundEst(confirmed),
        likelyPairs: roundEst(likely),
        // Raw sample counts so the UI can show "X of N sampled encrypted files
        // matched a deleted original" instead of just the extrapolation.
        confirmedSampleCount: confirmed,
        likelySampleCount: likely,
        residentSampleCount,
        sampleSize: candidates.length,
        samplePopulation: encryptedCount,
        pairRate,
        samplePairs: samplePairs.sort((a, b) => (b.originalDeleted ? 1 : 0) - (a.originalDeleted ? 1 : 0)).slice(0, 50),
        sampled,
      };
    })();

    // Q10: Anti-forensics around encryption window
    _p({ stage: "anti-forensics", pct: 75, detail: "Detecting anti-forensics artifacts" });
    let antiForensics = { deletedEncrypted: [], timestomped: [], cleanup: [], drops: [] };
    const antiForensicsStart = parseTs(usnEnrichment?.preciseStartTime) || startAnchorDt || parseTs(firstQ?.timestamp);
    const antiForensicsEnd = endAnchorDt || parseTs(lastQ?.timestamp);
    if (antiForensicsStart && antiForensicsEnd) {
        const afStart = fmtTs(new Date(antiForensicsStart.getTime() - 30 * 60000));
        const afEnd = fmtTs(new Date(antiForensicsEnd.getTime() + 30 * 60000));
        // 10a: Deleted encrypted file details
        if (inUse) {
          antiForensics.deletedEncrypted = db.prepare(
            `SELECT ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${lastMod} as lastModified${created ? `, ${created} as created` : ""} FROM data WHERE ${extWhereAll} AND ${inUse} = 'False' ${notDir} ORDER BY sort_datetime(${lastMod}) ASC, rowid LIMIT 20`
          ).all(...extParts);
        }
        // 10b: Timestomped files in encryption window
        if (siFN) {
          antiForensics.timestomped = db.prepare(
            `SELECT ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${ext} as extension${created ? `, ${created} as created` : ""}, ${lastMod} as lastModified FROM data WHERE ${siFN} = 'True' AND sort_datetime(${lastMod}) BETWEEN sort_datetime(?) AND sort_datetime(?) ${notDir} LIMIT 50`
          ).all(afStart, afEnd);
        }
        // 10c: Cleanup artifacts (deleted executables/scripts/logs near window)
        if (inUse && created) {
          const cleanupExts = [".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".log",".tmp",".dat"];
          const clPh = cleanupExts.map(() => "?").join(",");
          antiForensics.cleanup = db.prepare(
            `SELECT ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${ext} as extension, ${created} as created, ${lastMod} as lastModified FROM data WHERE ${inUse} = 'False' AND LOWER(${ext}) IN (${clPh}) AND sort_datetime(${created}) BETWEEN sort_datetime(?) AND sort_datetime(?) ${notDir} ORDER BY sort_datetime(${created}) ASC, rowid LIMIT 30`
          ).all(...cleanupExts, afStart, afEnd);
        }
        // 10d: Suspicious drops in risky paths during window
        if (created) {
          antiForensics.drops = db.prepare(
            `SELECT ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${ext} as extension, ${created} as created FROM data WHERE sort_datetime(${created}) BETWEEN sort_datetime(?) AND sort_datetime(?) AND (LOWER(${pp}) LIKE '%\\temp\\%' OR LOWER(${pp}) LIKE '%\\programdata\\%' OR LOWER(${pp}) LIKE '%\\appdata\\%' OR LOWER(${pp}) LIKE '%users\\public%' OR LOWER(${pp}) LIKE '%$recycle.bin%') ${notDir} ORDER BY sort_datetime(${created}) ASC, rowid LIMIT 30`
          ).all(afStart, afEnd);
        }
    }

    // Forensic indicators — structured with observed/inferred labels
    _p({ stage: "indicators", pct: 85, detail: "Building forensic indicators" });
    const notePathCount = new Set(ransomNotes.map(n => n.parentPath)).size;
    const forensicIndicators = [
      deletedEncrypted > 0 ? { text: `${deletedEncrypted} deleted encrypted files`, type: "execution", basis: "observed", count: deletedEncrypted } : null,
      timestompedCount > 0 ? { text: `${timestompedCount} timestomped files`, type: "execution", basis: "observed", count: timestompedCount } : null,
      originalPairs.pairRate > 0 ? { text: `${Math.round(originalPairs.pairRate * 100)}% pair rate — ${originalPairs.pairRate >= 0.7 ? "strong encryption pattern" : "partial encryption"}`, type: "correlation", basis: "inferred", count: null } : null,
      ransomNotes.length > 0 ? { text: `${ransomNotes.length} ransom notes across ${notePathCount} directories`, type: "execution", basis: "observed", count: ransomNotes.length } : null,
      (antiForensics.cleanup.length > 0 || antiForensics.drops.length > 0) ? { text: `${antiForensics.cleanup.length + antiForensics.drops.length} anti-forensic artifacts detected`, type: "execution", basis: "inferred", count: antiForensics.cleanup.length + antiForensics.drops.length } : null,
    ].filter(Boolean);

    const filterWindowUsesRecordChange = !!(recChange && firstQ?.recordChange0x10 && lastQ?.recordChange0x10);
    const timingEvidence = {
      timelineBasis: {
        label: "SI Modified",
        column: "LastModified0x10",
        description: "Timeline buckets and first/last encrypted cards are built from this field across the encrypted set.",
      },
      suspiciousWindowBasis: {
        label: usnEnrichment?.preciseStartTime ? "USN Rename" : (recChange ? "Record Change" : "SI Modified"),
        column: usnEnrichment?.preciseStartTime ? "UpdateTimestamp" : (recChange ? "LastRecordChange0x10" : "LastModified0x10"),
        timestamp: usnEnrichment?.preciseStartTime || fmtTs(suspiciousAnchorDt) || firstQ?.timestamp || null,
        description: usnEnrichment?.preciseStartTime
          ? "Payload-candidate timing is anchored to the earliest correlated USN rename event."
          : (recChange ? "Payload-candidate timing is anchored to the earliest MFT metadata-change timestamp for the first encrypted file." : "Payload-candidate timing falls back to SI last-modified time."),
      },
      start: buildTimingSnapshot(firstQ, usnEnrichment?.preciseStartTime || null),
      end: buildTimingSnapshot(lastQ, null),
      filterWindow: {
        column: filterWindowUsesRecordChange ? "LastRecordChange0x10" : "LastModified0x10",
        from: filterWindowUsesRecordChange ? firstQ.recordChange0x10 : (firstQ?.timestamp || null),
        to: filterWindowUsesRecordChange ? lastQ.recordChange0x10 : (lastQ?.timestamp || null),
      },
    };

    // Q11: Synthesis — encryption method, recovery prospects, and incident verdict.
    // Pure derivations from the fields above (also unit-tested independently).
    _p({ stage: "verdict", pct: 94, detail: "Building incident verdict" });
    const peakPerMinute = timeline.reduce((m, b) => Math.max(m, b.count || 0), 0);
    const antiForensicsCount = (antiForensics.cleanup?.length || 0) + (antiForensics.drops?.length || 0)
      + (antiForensics.timestomped?.length || 0) + (antiForensics.deletedEncrypted?.length || 0);
    const encryptionMethod = _inferEncryptionMethod(originalPairs, encryptedCount, durationMinutes);
    const recoveryProspects = _buildRecoveryProspects(originalPairs, encryptionMethod, backupRecoveryTotal, antiForensics);
    const incidentSummary = _buildIncidentSummary({
      encryptedCount,
      totalEncryptedSizeBytes: q1?.totalSize || 0,
      durationMinutes,
      filesPerMinute,
      peakPerMinute,
      firstTs: fmtTs(startAnchorDt) || firstQ?.timestamp || null,
      ransomNoteCount: ransomNotes.length,
      notePathCount,
      backupRecoveryTotal,
      deletedEncrypted,
      timestompedCount,
      antiForensicsCount,
      method: encryptionMethod,
      recovery: recoveryProspects,
      extensions: extParts,
    });
    const familyAttribution = _identifyFamily(extParts, ransomNotes);
    const mitreTechniques = _buildMitreMapping({
      encryptedCount, ransomNoteCount: ransomNotes.length, backupRecoveryTotal,
      deletedEncrypted, timestompedCount, antiForensics, evtx: evtxEnrichment,
    });
    const incidentTimeline = _buildIncidentTimeline({
      timeline, ransomNotes, suspiciousFiles, usnEnrichment,
      preciseStartTime: usnEnrichment?.preciseStartTime || null,
      firstTs: fmtTs(startAnchorDt) || firstQ?.timestamp || null,
    });
    const blastTreemap = _buildBlastTreemap(topDirectories);
    const scoping = _buildScoping(encDirsRaw, encryptedCount);

    return {
      encryptedCount,
      extensions: extParts,
      incidentSummary,
      encryptionMethod,
      recoveryProspects,
      familyAttribution,
      mitreTechniques,
      incidentTimeline,
      blastTreemap,
      scoping,
      totalEncryptedSizeBytes: q1?.totalSize || 0,
      firstEncrypted: firstQ || null,
      lastEncrypted: lastQ || null,
      durationMinutes,
      filesPerMinute,
      ransomNotes,
      ransomNoteCount: ransomNotes.length,
      timeline,
      topDirectories,
      deletedEncrypted,
      timestompedCount,
      suspiciousFiles,
      fileTypeBreakdown,
      firstEncryptedFiles,
      businessImpact,
      backupRecoveryImpact,
      backupRecoveryTotal,
      originalPairs,
      antiForensics,
      forensicIndicators,
      usnEnrichment,
      evtxEnrichment,
      processCorrelation,
      inPlaceEncryption,
      timingEvidence,
    };
  } catch (err) {
    return { ...empty, error: err.message };
  }
}

module.exports = {
  scanRansomwareExtensions, analyzeRansomware,
  // Pure synthesis helpers exported for unit testing.
  _inferEncryptionMethod, _buildRecoveryProspects, _buildIncidentSummary,
  _rwIsResidentSize, _fmtBytes, _fmtDurationShort,
  _identifyFamily, _buildMitreMapping, _familyForExtension,
  _buildIncidentTimeline, _rwBucketMs,
  _buildBlastTreemap, _buildScoping,
  _rwResolveEvtxCols, _rwLooksLikeEvtx, _rwCategorizeEvasion,
  _rwExtractProcFields, _rwBasename, _rwProcMatchesFile,
  _rwFindBurst, _buildInPlaceAssessment, _rwInPlaceCategory,
};
