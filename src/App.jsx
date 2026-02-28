import { useState, useEffect, useRef, useCallback, useMemo, Fragment } from "react";
import { CHAIN_RULE_MAP, SUS_PATHS, SAFE_PROCS, ENCODED_PS, CRED_DUMP_CMD, NTDS_EXTRACT, LSASS_TOOLS, ACCOUNT_MANIP, DEFENSE_EVASION, NETWORK_SCANNERS, AD_RECON_TOOLS, RMM_TOOLS, EXFIL_TOOLS, ARCHIVE_SUSPECT } from "./detection-rules.js";

const ROW_HEIGHT = 26;
const HEADER_HEIGHT = 34;
const FILTER_HEIGHT = 28;
const OVERSCAN = 20;
const VIRTUAL_WINDOW = 10000;   // rows to fetch per SQL query window
const VIRTUAL_AHEAD = 2000;     // trigger re-fetch when within this many rows of edge
const QUERY_DEBOUNCE = 500;
const DETAIL_PANEL_HEIGHT_DEFAULT = 200;
const DETAIL_PANEL_MIN_HEIGHT = 80;
const DETAIL_PANEL_MAX_HEIGHT = 600;
const TAG_COL_WIDTH_DEFAULT = 100;
const TAG_COL_WIDTH_MIN = 60;
const BKMK_COL_WIDTH = 34;

const THEMES = {
  dark: {
    bg: "#0f1114", bgAlt: "#181b20", bgInput: "#12151a", border: "#2a2d33", borderAccent: "#E85D2A",
    text: "#e0ddd8", textDim: "#9a9590", textMuted: "#5c5752", accent: "#E85D2A", accentHover: "#F47B50",
    rowOdd: "#141720", rowEven: "#0f1114", headerBg: "#181b20", headerText: "#E85D2A",
    selection: "rgba(232,93,42,0.14)", bookmark: "rgba(232,93,42,0.06)",
    modalBg: "#181b20", modalBorder: "#333639", overlay: "rgba(5,5,8,0.85)",
    success: "#4ade80", warning: "#E85D2A", danger: "#f85149",
    btnBg: "#22252a", btnBorder: "#333639",
    // Unit 42 extended palette
    panelBg: "#0b0d10", cellBorder: "#12151a", accentSubtle: "rgba(232,93,42,0.12)",
    histBar: "#E85D2A", histBarHover: "#F47B50", histGrid: "#1e2028",
    primaryBtn: "#E85D2A", primaryBtnHover: "#C44D1E",
  },
  light: {
    bg: "#ffffff", bgAlt: "#f7f5f3", bgInput: "#ffffff", border: "#e0dbd6", borderAccent: "#E85D2A",
    text: "#1c1917", textDim: "#6b6560", textMuted: "#a09a94", accent: "#E85D2A", accentHover: "#C44D1E",
    rowOdd: "#faf8f6", rowEven: "#ffffff", headerBg: "#f7f5f3", headerText: "#E85D2A",
    selection: "rgba(232,93,42,0.10)", bookmark: "rgba(232,93,42,0.06)",
    modalBg: "#ffffff", modalBorder: "#e0dbd6", overlay: "rgba(28,25,23,0.5)",
    success: "#16a34a", warning: "#E85D2A", danger: "#dc2626",
    btnBg: "#f0ebe6", btnBorder: "#e0dbd6",
    // Unit 42 extended palette
    panelBg: "#f0ebe6", cellBorder: "#ebe6e0", accentSubtle: "rgba(232,93,42,0.08)",
    histBar: "#E85D2A", histBarHover: "#C44D1E", histGrid: "#e0dbd6",
    primaryBtn: "#E85D2A", primaryBtnHover: "#C44D1E",
  },
};

const DT_FORMATS = [
  { label: "Default (raw)", value: "" },
  { label: "yyyy-MM-dd HH:mm:ss", value: "yyyy-MM-dd HH:mm:ss" },
  { label: "yyyy-MM-dd HH:mm:ss.fff", value: "yyyy-MM-dd HH:mm:ss.fff" },
  { label: "yyyy-MM-dd HH:mm:ss.fffffff", value: "yyyy-MM-dd HH:mm:ss.fffffff" },
  { label: "MM/dd/yyyy HH:mm:ss", value: "MM/dd/yyyy HH:mm:ss" },
  { label: "dd/MM/yyyy HH:mm:ss", value: "dd/MM/yyyy HH:mm:ss" },
  { label: "yyyy-MM-dd", value: "yyyy-MM-dd" },
];

const TIMEZONES = [
  { label: "UTC", value: "UTC" },
  { label: "US/Eastern", value: "America/New_York" },
  { label: "US/Central", value: "America/Chicago" },
  { label: "US/Mountain", value: "America/Denver" },
  { label: "US/Pacific", value: "America/Los_Angeles" },
  { label: "Europe/London", value: "Europe/London" },
  { label: "Europe/Berlin", value: "Europe/Berlin" },
  { label: "Asia/Tokyo", value: "Asia/Tokyo" },
  { label: "Asia/Shanghai", value: "Asia/Shanghai" },
  { label: "Australia/Sydney", value: "Australia/Sydney" },
  { label: "Local (system)", value: "local" },
];

const _dtfCache = {};
function _getCachedDtf(tz) {
  if (!_dtfCache[tz]) {
    _dtfCache[tz] = new Intl.DateTimeFormat("en-US", {
      timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    });
  }
  return _dtfCache[tz];
}

function formatDateTime(raw, fmt, tz) {
  if (!fmt || !raw) return raw || "";
  const d = new Date(raw);
  if (isNaN(d.getTime())) return raw;
  let Y, M, D, h, m, s;
  if (!tz || tz === "local") {
    Y = d.getFullYear(); M = String(d.getMonth() + 1).padStart(2, "0");
    D = String(d.getDate()).padStart(2, "0"); h = String(d.getHours()).padStart(2, "0");
    m = String(d.getMinutes()).padStart(2, "0"); s = String(d.getSeconds()).padStart(2, "0");
  } else {
    const parts = {};
    for (const { type, value } of _getCachedDtf(tz).formatToParts(d)) parts[type] = value;
    Y = parts.year; M = parts.month; D = parts.day;
    h = parts.hour === "24" ? "00" : parts.hour; m = parts.minute; s = parts.second;
  }
  const ms3 = String(d.getMilliseconds()).padStart(3, "0");
  const us7 = ms3 + "0000";
  return fmt
    .replace("yyyy", Y).replace("MM", M).replace("dd", D)
    .replace("HH", h).replace("mm", m).replace("ss", s)
    .replace("fffffff", us7).replace("fff", ms3);
}

// Pre-compile color rules for fast per-row matching (avoids repeated toLowerCase + regex construction)
function compileColorRules(rules) {
  return rules.map((r) => {
    const v = r.value.toLowerCase();
    let test;
    if (r.condition === "contains") test = (cv) => cv.includes(v);
    else if (r.condition === "equals") test = (cv) => cv === v;
    else if (r.condition === "startswith") test = (cv) => cv.startsWith(v);
    else if (r.condition === "regex") {
      try { const re = new RegExp(r.value, "i"); test = (_cv, raw) => re.test(raw); }
      catch { test = () => false; }
    } else test = () => false;
    return { column: r.column, test, bg: r.bgColor, fg: r.fgColor };
  });
}

function applyColors(row, compiledRules) {
  for (const r of compiledRules) {
    const raw = row[r.column] || "";
    if (r.test(raw.toLowerCase(), raw)) return { bg: r.bg, fg: r.fg };
  }
  return null;
}

const BkmkIcon = ({ filled }) => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill={filled ? "#d29922" : "none"} stroke={filled ? "#d29922" : "#484f58"} strokeWidth="2">
    <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
  </svg>
);

const PRESETS = [
  { label: "PowerShell", column: "Process", condition: "contains", value: "powershell", bgColor: "#7f1d1d", fgColor: "#fca5a5" },
  { label: "Mimikatz", column: "Message", condition: "contains", value: "mimikatz", bgColor: "#581c87", fgColor: "#d8b4fe" },
  { label: "PsExec", column: "Process", condition: "contains", value: "psexec", bgColor: "#713f12", fgColor: "#fde68a" },
  { label: "LSASS", column: "Message", condition: "contains", value: "lsass", bgColor: "#064e3b", fgColor: "#6ee7b7" },
  { label: "Critical", column: "Level", condition: "equals", value: "Critical", bgColor: "#991b1b", fgColor: "#ffffff" },
  { label: "Error", column: "Level", condition: "equals", value: "Error", bgColor: "#92400e", fgColor: "#fde68a" },
  { label: "C2 / DNS", column: "Message", condition: "contains", value: "c2.", bgColor: "#1e3a5f", fgColor: "#93c5fd" },
  { label: "Encoded Cmd", column: "Message", condition: "contains", value: "encoded", bgColor: "#4c1d95", fgColor: "#c4b5fd" },
];

const TAG_PRESETS = {
  "Suspicious": "#f85149",
  "Lateral Movement": "#f0883e",
  "Exfiltration": "#a371f7",
  "Persistence": "#58a6ff",
  "C2": "#da3633",
  "Initial Access": "#3fb950",
  "Credential Access": "#d29922",
  "Execution": "#ff7b72",
};

const KAPE_PROFILES = {
  // ── EZ Tools ────────────────────────────────────────────────────
  "MFTECmd ($MFT)": {
    detect: ["EntryNumber", "SequenceNumber", "ParentPath", "FileName", "Created0x10"],
    pinnedColumns: ["FileName", "ParentPath"],
    hiddenColumns: ["UpdateSequenceNumber", "LogfileSequenceNumber", "SecurityId", "NameType", "LoggedUtilStream", "SequenceNumber", "InUse", "ParentSequenceNumber", "ParentEntryNumber", "IsAds", "SiFlags", "FnAttributeId", "OtherAttributeId", "ReferenceCount"],
    columnOrder: ["EntryNumber", "ParentPath", "FileName", "Extension", "IsDirectory", "HasAds", "FileSize", "Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30", "LastRecordChange0x10", "LastAccess0x10", "ZoneIdContents", "Timestomped", "uSecZeros", "Copied"],
  },
  "EvtxECmd (EVTX)": {
    detect: ["RecordNumber", "TimeCreated", "EventId", "Provider", "Channel"],
    pinnedColumns: ["TimeCreated", "EventId"],
    hiddenColumns: ["ChunkNumber", "ExtraDataOffset", "HiddenRecord", "ProcessId", "ThreadId"],
    columnOrder: ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider", "Channel", "Computer", "UserId", "MapDescription", "UserName", "RemoteHost", "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo", "SourceFile", "Payload", "Keywords"],
  },
  "PECmd (Prefetch)": {
    detect: ["ExecutableName", "RunCount", "LastRun", "Volume0Name", "Hash"],
    pinnedColumns: ["ExecutableName", "LastRun"],
    hiddenColumns: ["FileSize", "ParsingError"],
    columnOrder: ["SourceFilename", "SourceCreated", "SourceModified", "SourceAccessed", "ExecutableName", "RunCount", "Hash", "Size", "Version", "LastRun", "PreviousRun0", "PreviousRun1", "PreviousRun2", "PreviousRun3", "Volume0Name", "Volume0Serial", "Volume0Created", "Directories", "FilesLoaded"],
  },
  "LECmd (LNK)": {
    detect: ["SourceFile", "TargetIDAbsolutePath", "HeaderFlags", "DriveType"],
    pinnedColumns: ["SourceFile"],
    columnOrder: ["SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "TargetCreated", "TargetModified", "TargetAccessed", "FileSize", "RelativePath", "WorkingDirectory", "FileAttributes", "HeaderFlags", "LocalPath", "CommonPath", "Arguments", "TargetIDAbsolutePath", "TargetMFTEntryNumber", "MachineID", "MachineMACAddress", "TrackerCreatedOn"],
  },
  "AmcacheParser (Files)": {
    detect: ["ApplicationName", "ProgramId", "FileKeyLastWriteTimestamp", "SHA1"],
    pinnedColumns: ["ApplicationName", "FullPath"],
    hiddenColumns: ["Language", "Usn", "LongPathHash", "BinaryType"],
    columnOrder: ["ApplicationName", "ProgramId", "FileKeyLastWriteTimestamp", "SHA1", "IsOsComponent", "FullPath", "Name", "FileExtension", "LinkDate", "ProductName", "Size", "Version", "ProductVersion", "IsPeFile", "BinFileVersion"],
  },
  "AmcacheParser (Programs)": {
    detect: ["ProgramId", "KeyLastWriteTimestamp", "Publisher", "InstallDate"],
    pinnedColumns: ["ProgramId", "Name"],
    columnOrder: ["ProgramId", "KeyLastWriteTimestamp", "Name", "Version", "Publisher", "InstallDate", "OSVersionAtInstallTime", "BundleManifestPath", "HiddenArp", "InboxModernApp", "MsiPackageCode", "MsiProductCode", "PackageFullName", "RegistryKeyPath", "RootDirPath", "Type", "Source", "UninstallString"],
  },
  "RECmd (Registry)": {
    detect: ["HivePath", "KeyPath", "ValueName", "ValueType", "ValueData"],
    pinnedColumns: ["KeyPath", "ValueName"],
    columnOrder: ["HivePath", "KeyPath", "ValueName", "ValueType", "ValueData", "ValueData2", "ValueData3", "LastWriteTimestamp", "Description", "Category"],
  },
  "SBECmd (ShellBags)": {
    detect: ["AbsolutePath", "BagPath", "ShellType", "Value"],
    pinnedColumns: ["AbsolutePath", "ShellType"],
    columnOrder: ["BagPath", "Slot", "NodeSlot", "MRUPosition", "AbsolutePath", "ShellType", "Value", "ChildBags", "CreatedOn", "ModifiedOn", "AccessedOn", "LastWriteTime", "FirstInteracted", "LastInteracted", "HasExplored"],
  },
  "SrumECmd (SRUM)": {
    detect: ["Timestamp", "ExeInfo", "SidType", "Sid"],
    pinnedColumns: ["Timestamp", "ExeInfo"],
    columnOrder: ["Timestamp", "ExeInfo", "SidType", "Sid", "UserName"],
  },
  "AppCompatcache (Shimcache)": {
    detect: ["ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC", "Executed"],
    pinnedColumns: ["Path", "Executed"],
    hiddenColumns: ["FileSize"],
    columnOrder: ["ControlSet", "Duplicate", "CacheEntryPosition", "Executed", "LastModifiedTimeUTC", "Path", "SourceFile"],
  },
  "JLECmd (Auto Jump Lists)": {
    detect: ["AppId", "AppIdDescription", "EntryName", "TargetIDAbsolutePath"],
    pinnedColumns: ["AppId", "AppIdDescription"],
    columnOrder: ["SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "AppId", "AppIdDescription", "EntryName", "TargetCreated", "TargetModified", "TargetAccessed", "FileSize", "RelativePath", "WorkingDirectory", "LocalPath", "CommonPath", "Arguments", "TargetIDAbsolutePath", "MachineID", "MachineMACAddress", "TrackerCreatedOn", "InteractionCount"],
  },
  // ── Timeline Formats ────────────────────────────────────────────
  "ForensicTimeline": {
    detect: ["DateTime", "TimestampInfo", "ArtifactName", "Tool", "Description"],
    pinnedColumns: ["DateTime", "ArtifactName"],
    columnOrder: ["DateTime", "TimestampInfo", "ArtifactName", "Tool", "Description", "DataDetails", "DataPath", "FileExtension", "EvidencePath", "EventId", "User", "Computer", "FileSize", "IPAddress", "SourceAddress", "DestinationAddress", "SHA1", "Count", "RawData"],
    autoColorColumn: "ArtifactName",
  },
  "SuperTimeline (Plaso)": {
    detect: ["date", "time", "macb", "source", "sourcetype", "type"],
    pinnedColumns: ["date", "sourcetype"],
    columnOrder: ["date", "time", "macb", "source", "sourcetype", "type", "user", "host", "short", "desc", "filename", "inode", "notes", "format", "extra"],
    autoColorColumn: "source",
  },
  "MacTime": {
    detect: ["Timestamp", "Macb", "SourceName", "LongDescription", "FileName"],
    pinnedColumns: ["Timestamp", "FileName"],
    hiddenColumns: ["TimeZone", "Type", "Username", "HostName", "ShortDescription", "Version", "Notes", "Format", "Extra"],
    columnOrder: ["Timestamp", "SourceDescription", "SourceName", "Macb", "LongDescription", "Inode", "FileName"],
    autoColorColumn: "SourceName",
  },
  "KapeMiniTimeline": {
    detect: ["Timestamp", "DataType", "ComputerName", "UserSource", "Message"],
    pinnedColumns: ["Timestamp", "Message"],
    columnOrder: ["Timestamp", "DataType", "ComputerName", "UserSource", "Message"],
    autoColorColumn: "DataType",
  },
  "PsortTimeline (Plaso)": {
    detect: ["Timestamp", "TimestampDescription", "Source", "SourceLong"],
    pinnedColumns: ["Timestamp", "DisplayName"],
    columnOrder: ["Timestamp", "TimestampDescription", "Source", "SourceLong", "Message", "Parser", "DisplayName", "TagInfo"],
    autoColorColumn: "Source",
  },
  // ── Misc Tools ──────────────────────────────────────────────────
  "Hayabusa (Standard)": {
    detect: ["Timestamp", "RuleTitle", "Level", "Channel", "EventId", "RecordId", "Details"],
    pinnedColumns: ["Timestamp", "RuleTitle"],
    columnOrder: ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventId", "RecordId", "Details", "ExtraFieldInfo"],
    autoColorColumn: "Level",
  },
  "Hayabusa (Verbose)": {
    detect: ["Timestamp", "RuleTitle", "Level", "MitreTactics", "MitreTags", "OtherTags"],
    pinnedColumns: ["Timestamp", "RuleTitle"],
    columnOrder: ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventId", "MitreTactics", "MitreTags", "OtherTags", "RecordId", "Details", "ExtraFieldInfo", "RuleFile", "EvtxFile"],
    autoColorColumn: "Level",
  },
  "Chainsaw (Sigma)": {
    detect: ["Timestamp", "RuleTitle", "Level", "Channel", "MitreTactics"],
    pinnedColumns: ["Timestamp", "RuleTitle"],
    columnOrder: ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventId", "MitreTactics", "MitreTags", "OtherTags", "RecordId", "Details", "ExtraFieldInfo", "RuleFile", "EvtxFile"],
    autoColorColumn: "Level",
  },
  "BrowsingHistoryView": {
    detect: ["Url", "Title", "VisitTimeUtc", "WebBrowser", "UserProfile"],
    pinnedColumns: ["Url", "Title"],
    columnOrder: ["Url", "Title", "VisitTimeUtc", "VisitCount", "VisitedFrom", "VisitType", "WebBrowser", "UserProfile", "BrowserProfile", "UrlLength", "TypedCount", "HistoryFile"],
  },
  "KAPE Copy Log": {
    detect: ["CopiedTimestamp", "SourceFile", "DestinationFile", "SourceFileSha1"],
    pinnedColumns: ["SourceFile", "DestinationFile"],
    columnOrder: ["CopiedTimestamp", "SourceFile", "DestinationFile", "FileSize", "SourceFileSha1", "DeferredCopy", "CreatedOnUtc", "ModifiedOnUtc", "LastAccessedOnUtc", "CopyDuration"],
  },
};

// ── Super Timeline auto-color palettes ────────────────────────────
// Assigns consistent colors to unique values in a column for timeline artifact coloring.
// Uses a palette designed for dark and light theme readability.
const TIMELINE_PALETTE = [
  { bg: "#1a3a2a", fg: "#6ee7b7" }, { bg: "#1e3a5f", fg: "#93c5fd" },
  { bg: "#3b1f4b", fg: "#d8b4fe" }, { bg: "#4a2c17", fg: "#fdba74" },
  { bg: "#3b2020", fg: "#fca5a5" }, { bg: "#1a3344", fg: "#67e8f9" },
  { bg: "#3b3417", fg: "#fde68a" }, { bg: "#2d1b3d", fg: "#f0abfc" },
  { bg: "#1b3031", fg: "#5eead4" }, { bg: "#1f2937", fg: "#e5e7eb" },
  { bg: "#312e18", fg: "#d6d3a4" }, { bg: "#1c2b3a", fg: "#7dd3fc" },
  { bg: "#2e1e1e", fg: "#f9a8d4" }, { bg: "#1c331c", fg: "#86efac" },
  { bg: "#332211", fg: "#f5c78e" }, { bg: "#262640", fg: "#a5b4fc" },
];
const TIMELINE_PALETTE_LIGHT = [
  { bg: "#d1fae5", fg: "#065f46" }, { bg: "#dbeafe", fg: "#1e40af" },
  { bg: "#ede9fe", fg: "#5b21b6" }, { bg: "#ffedd5", fg: "#9a3412" },
  { bg: "#fee2e2", fg: "#991b1b" }, { bg: "#cffafe", fg: "#155e75" },
  { bg: "#fef9c3", fg: "#854d0e" }, { bg: "#fae8ff", fg: "#86198f" },
  { bg: "#ccfbf1", fg: "#115e59" }, { bg: "#f3f4f6", fg: "#374151" },
  { bg: "#fef3c7", fg: "#78350f" }, { bg: "#e0f2fe", fg: "#075985" },
  { bg: "#fce7f3", fg: "#9d174d" }, { bg: "#dcfce7", fg: "#166534" },
  { bg: "#fff7ed", fg: "#7c2d12" }, { bg: "#eef2ff", fg: "#3730a3" },
];

function buildTimelineColorRules(rows, colName, isDark) {
  const palette = isDark ? TIMELINE_PALETTE : TIMELINE_PALETTE_LIGHT;
  const seen = new Map();
  for (const row of rows) {
    const val = (row[colName] || "").trim();
    if (val && !seen.has(val)) seen.set(val, seen.size);
  }
  return Array.from(seen.entries()).map(([val, idx]) => {
    const p = palette[idx % palette.length];
    return { column: colName, condition: "equals", value: val, bgColor: p.bg, fgColor: p.fg };
  });
}

function detectKapeProfile(headers) {
  const headerSet = new Set(headers);
  for (const [name, profile] of Object.entries(KAPE_PROFILES)) {
    if (profile.detect.every((col) => headerSet.has(col))) return { name, ...profile };
  }
  return null;
}

// ── IOC Parsing ───────────────────────────────────────────────────
// Order matters — first match wins. More specific patterns must come before broader ones.
const IOC_CATEGORY_PATTERNS = [
  // Hashes — exact-length hex strings
  ["SHA256_Hash",  /^[0-9a-f]{64}$/i],
  ["SHA1_Hash",    /^[0-9a-f]{40}$/i],
  ["MD5_Hash",     /^[0-9a-f]{32}$/i],
  // Network — IP with port
  ["IPv4_Address:Port", /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$/],
  ["IPv6_Address:Port", /^\[?[0-9a-f:]{3,39}\]?:\d{1,5}$/i],
  // Network — plain IPs
  ["IPv4_Address", /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/],
  ["IPv6_Address", /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i],
  // Network — Email
  ["Email_Address", /^[^\s@]+@[^\s@]+\.[^\s@]+$/],
  // Host — Registry keys (HKEY_LOCAL_MACHINE\..., HKLM\..., etc.)
  ["Registry_Key", /^(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)(\\|$)/i],
  // Host — Named pipes (\\.\pipe\...)
  ["Named_Pipe",   /^\\\\\.\\pipe\\/i],
  // Host — Mutex (Global\..., Local\...)
  ["Mutex",        /^(Global\\|Local\\)/],
  // Host — File paths (C:\..., \\server\..., /usr/... — must have separator after root)
  ["File_Path",    /^([A-Za-z]:\\[^\s]|\\\\[^\\]+\\|\/[^\s]+\/)/],
  // Network — Crypto wallets (Bitcoin, Ethereum, Monero)
  ["Crypto_Wallet", /^(1[1-9A-HJ-NP-Za-km-z]{25,34}|3[1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-z0-9]{25,90}|0x[0-9a-fA-F]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})$/],
  // Network — User agent strings
  ["User_Agent_String", /^Mozilla\//i],
  // NOTE: File_Name vs Domain_Name is handled by custom logic in parseIocText (not simple regex order)
  // Fallback — "Other" is assigned if nothing matches (handled in parseIocText)
];

// Auto-defang IOC values: undo common obfuscation used in threat intel feeds
function defangIoc(text) {
  let s = text.trim();
  // Strip protocol first (handles all obfuscated variants):
  // hxxps[://], https[://], hxxps://, https://, hxxp[://], http[://], hxxp://, http://
  s = s.replace(/^h[tx]{2}ps?\s*\[?:\/?\/?\]?\s*/i, "");
  // Also catch plain https?:// and ftp://
  s = s.replace(/^(?:https?|ftp):\/\//i, "");
  // Bracket-dot defanging: [.] [dot] (.) → .
  s = s.replace(/\[\.\]/g, ".").replace(/\[dot\]/gi, ".").replace(/\(\.\)/g, ".");
  // Bracket-colon/at defanging
  s = s.replace(/\[:\]/g, ":").replace(/\[@\]/g, "@");
  // Strip URL path/query/fragment — keep domain (+ optional port)
  // Only if it looks like a domain (contains a dot and slash after it)
  if (/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?[/?#]/i.test(s)) {
    s = s.split(/[/?#]/)[0];
  }
  // Strip trailing dot (FQDN notation)
  s = s.replace(/\.$/, "");
  return s;
}

function parseIocText(rawText) {
  const lines = rawText.split(/\r?\n/);
  const seen = new Set();
  const iocs = [];
  for (const line of lines) {
    const trimmed = line.replace(/#.*$/, "").trim();
    if (!trimmed) continue;
    // Defang before dedup and categorization
    const clean = defangIoc(trimmed);
    if (!clean || seen.has(clean.toLowerCase())) continue;
    seen.add(clean.toLowerCase());
    let category = "Other";
    for (const [cat, re] of IOC_CATEGORY_PATTERNS) {
      if (re.test(clean)) { category = cat; break; }
    }
    // File_Name vs Domain_Name disambiguation (regex order can't solve this alone)
    if (category === "Other") {
      // Extensions that are NEVER TLDs — always a file name
      const fileOnlyRe = /^[^\\/:*?"<>|\s]+\.(exe|dll|bat|cmd|ps1|psm1|psd1|vbs|vbe|jse|wsf|wsh|hta|msi|msp|mst|scr|sys|cpl|ocx|drv|jar|war|pyc|bash|dat|tmp|sqlite|doc[xm]|xls[xm]|ppt[xm]|rtf|tsv|rar|7z|bz2|xz|vhd|vhdx|vmdk|ova|lnk|cfg|conf|yaml|yml|reg|inf|mui|pf|evtx?|dmp|pcap|cap)$/i;
      // Extensions that COULD be TLDs/domains — need to check if it's a multi-segment domain
      const ambiguousRe = /^[^\\/:*?"<>|\s]+\.(com|net|org|io|sh|py|rs|js|rb|cc|im|ai|app|dev|gg|me|tv|co|de|uk|ru|in|br|au|ph|sg|cat|bin|zip|mov|pdf|doc|csv|xml|json|iso|img|log|db|ax|ini|url|gz|tar)$/i;
      const domainRe = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?){1,}$/i;
      if (fileOnlyRe.test(clean)) {
        category = "File_Name";
      } else if (ambiguousRe.test(clean) && domainRe.test(clean)) {
        // Has multiple dot-segments (e.g., update-service-cdn.com) → Domain
        // Single segment + ambiguous ext with no subdomain-like parts → also Domain
        // Only treat as File_Name if it looks like a filename (has underscore, starts with uppercase drive-like)
        const dotCount = (clean.match(/\./g) || []).length;
        if (dotCount === 1 && /^[a-z0-9_-]+\.[a-z]+$/i.test(clean)) {
          // Single dot, looks like either file or domain — check for filename indicators
          if (/[_]/.test(clean.split(".")[0])) {
            category = "File_Name"; // underscores are filename-like (e.g., svchost_update.exe)
          } else {
            category = "Domain_Name"; // no underscores, looks like a domain (e.g., update-service-cdn.com)
          }
        } else {
          category = "Domain_Name";
        }
      } else if (domainRe.test(clean)) {
        category = "Domain_Name";
      }
    }
    iocs.push({ raw: clean, category });
  }
  return iocs;
}

function escapeIocForRegex(ioc) {
  return ioc.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}

function formatNumber(n) {
  return n.toLocaleString();
}

// ── Module-scope utilities (no component state dependency — avoids re-creation per render) ──

const getSusInfo = (node, parentNode) => {
  const n = (node.processName || "").toLowerCase();
  const pn = (parentNode?.processName || "").toLowerCase();
  const cmd = node.cmdLine || "";
  const img = node.image || "";
  const nBase = n.replace(/\.exe$/, "");
  const pnBase = pn.replace(/\.exe$/, "");
  if (pnBase) {
    const chainHit = CHAIN_RULE_MAP.get(pnBase + ":" + nBase);
    if (chainHit) return chainHit;
  }
  if (ENCODED_PS.test(cmd) && /^(powershell|pwsh)(\.exe)?$/i.test(n)) return { level: 3, reason: "Encoded PowerShell [T1059.001]" };
  if (CRED_DUMP_CMD.test(cmd)) return { level: 3, reason: "Credential dumping [T1003]" };
  if (NTDS_EXTRACT.test(cmd)) return { level: 3, reason: "NTDS extraction [T1003.003]" };
  if (DEFENSE_EVASION.test(cmd)) return { level: 2, reason: "Defense evasion [T1070]" };
  if (ACCOUNT_MANIP.test(cmd)) return { level: 2, reason: "Account manipulation [T1136]" };
  if (/wmic.*\/node:/i.test(cmd) || /winrm/i.test(cmd)) return { level: 2, reason: "Lateral movement command [T1021]" };
  if (ARCHIVE_SUSPECT.test(cmd)) return { level: 2, reason: "Suspicious archive operation [T1560.001]" };
  if (LSASS_TOOLS.test(n)) return { level: 3, reason: "LSASS access tool [T1003.001]" };
  if (AD_RECON_TOOLS.test(n)) return { level: 2, reason: "AD recon tool [T1087.002]" };
  if (NETWORK_SCANNERS.test(n)) return { level: 2, reason: "Network scanner [T1046]" };
  if (EXFIL_TOOLS.test(n)) return { level: 2, reason: "Exfiltration tool [T1567]" };
  if (RMM_TOOLS.test(n) && pn && !/^explorer(\.exe)?$/i.test(pn)) return { level: 2, reason: "RMM tool \u2014 unusual parent [T1219]" };
  if (/^(wscript|cscript)(\.exe)?$/i.test(n) && /(\\users\\[^\\]+\\|\\appdata\\)/i.test(img)) return { level: 2, reason: "Script from user profile [T1059.005]" };
  if (SUS_PATHS.test(img) && !SAFE_PROCS.test(n)) return { level: 1, reason: "Suspicious path [T1204]" };
  if (RMM_TOOLS.test(n)) return { level: 1, reason: "Remote management tool [T1219]" };
  return { level: 0, reason: null };
};

const _integrityShort = (raw) => {
  if (!raw) return "";
  if (/16384|System/i.test(raw)) return "System";
  if (/12288|High/i.test(raw)) return "High";
  if (/8192|Medium/i.test(raw)) return "Medium";
  if (/4096|Low/i.test(raw)) return "Low";
  if (/\b0\b|Untrusted/i.test(raw)) return "Untrusted";
  return raw.replace(/^S-1-16-\d+\s*/i, "").replace(/^.*\\/, "") || raw;
};

const _providerShort = (p) => {
  if (!p) return "";
  if (p.includes("Sysmon")) return "Sysmon";
  if (p.includes("Security-Auditing")) return "Security";
  return p.replace(/^Microsoft-Windows-/i, "");
};

const SUS_COLORS = { 3: "#f85149", 2: "#f0883e", 1: "#d29922", 0: null };
const INT_COLOR = { System: "#f85149", High: "#f0883e", Medium: "#d29922", Low: "#8b949e", Untrusted: "#6e40c9" };
const PT_ICON_STYLE = { width: 14, height: 14, verticalAlign: "middle", flexShrink: 0 };

// ── Main App ───────────────────────────────────────────────────────
export default function App() {
  const [tabs, setTabs] = useState([]);
  const [activeTab, setActiveTab] = useState(null);
  const [tabFilter, setTabFilter] = useState("");
  const [modal, setModal] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [selectedRows, setSelectedRows] = useState(new Set());
  const [lastClickedRow, setLastClickedRow] = useState(null);
  const [detailPanelOpen, setDetailPanelOpen] = useState(true);
  const [detailPanelHeight, setDetailPanelHeight] = useState(DETAIL_PANEL_HEIGHT_DEFAULT);
  const detailPanelRef = useRef(null);
  const detailResizeStartY = useRef(0);
  const detailResizeStartH = useRef(0);
  const [copiedMsg, setCopiedMsg] = useState(false);
  const [cellPopup, setCellPopup] = useState(null);
  const [searchMatchIdx, setSearchMatchIdx] = useState(-1);
  const [resizingCol, setResizingCol] = useState(null);
  const [resizeX, setResizeX] = useState(0);
  const [resizeW, setResizeW] = useState(0);
  const justResizedRef = useRef(false);
  const [importingTabs, setImportingTabs] = useState({});
  const [importQueue, setImportQueue] = useState([]);

  // New UI state
  const [filterDropdown, setFilterDropdown] = useState(null);
  const [contextMenu, setContextMenu] = useState(null);
  const [rowContextMenu, setRowContextMenu] = useState(null);
  const [groupDragOver, setGroupDragOver] = useState(false);
  const [groupReorderDrag, setGroupReorderDrag] = useState(null); // col name being dragged within group bar
  const [dateTimeFormat, setDateTimeFormat] = useState("yyyy-MM-dd HH:mm:ss");
  const [timezone, setTimezone] = useState("UTC");
  const [themeName, setThemeName] = useState("dark");
  const [histogramVisible, setHistogramVisible] = useState(false);
  const [histogramCol, setHistogramCol] = useState(null);
  const [histogramData, setHistogramData] = useState([]);
  const histogramCache = useRef({}); // { [tabId]: { sig, data } }
  const searchCache = useRef({}); // { [tabId]: { [sig]: { rows, rowOffset, totalFiltered, bookmarkedSet, rowTags } } }
  const [histogramHeight, setHistogramHeight] = useState(160);
  const histResizeStartY = useRef(0);
  const histResizeStartH = useRef(0);
  const [histGranularity, setHistGranularity] = useState("day");
  const histBrushRef = useRef({ startIdx: null, endIdx: null, active: false });
  const histSvgRectRef = useRef(null);
  const histBrushOverlayRef = useRef(null); // DOM ref for brush overlay rect
  const histBrushLabelRef = useRef(null);   // DOM ref for brush label text
  const histBarGeomRef = useRef({ barW: 1, yAxisW: 44, chartPadT: 4, chartH: 100, len: 0 }); // cached bar geometry for DOM updates
  const [histContainerWidth, setHistContainerWidth] = useState(0);
  const histContainerRef = useRef(null);
  const [crossFind, setCrossFind] = useState(null); // { term, results: [{tabId, name, count}] }
  const [crossTabCounts, setCrossTabCounts] = useState(null); // auto inline: { term, mode, results: [{tabId, name, count}] }
  const [crossTabOpen, setCrossTabOpen] = useState(true);
  const [headerDragOver, setHeaderDragOver] = useState(null);
  const [fontSize, setFontSize] = useState(12);
  const [dateRangeDropdown, setDateRangeDropdown] = useState(null); // { colName, x, y, from, to }
  const [filterPresets, setFilterPresets] = useState([]);
  const [toolsOpen, setToolsOpen] = useState(false);

  // Filter dropdown internal state
  const [fdValues, setFdValues] = useState([]);
  const [fdLoading, setFdLoading] = useState(false);
  const [fdSearch, setFdSearch] = useState("");
  const [fdSelected, setFdSelected] = useState(new Set());
  const [fdRegex, setFdRegex] = useState(false);
  const [proximityFilter, setProximityFilter] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [regexPaletteOpen, setRegexPaletteOpen] = useState(false);
  const [tagColWidth, setTagColWidth] = useState(TAG_COL_WIDTH_DEFAULT);

  const scrollRef = useRef(null);
  const scrollTopRef = useRef(0);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(typeof window !== "undefined" ? window.innerHeight : 800);
  const rafScroll = useRef(null);
  const handleScroll = useCallback((e) => {
    if (rafScroll.current) return;
    const top = e.target.scrollTop;
    scrollTopRef.current = top;
    rafScroll.current = requestAnimationFrame(() => {
      rafScroll.current = null;
      setScrollTop(scrollTopRef.current);
    });
  }, []);

  // Track window resize / zoom changes so the grid adapts
  useEffect(() => {
    const onResize = () => setViewportH(window.innerHeight);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);
  const queryTimer = useRef(null);
  const fetchId = useRef(0); // Monotonic counter to discard stale query results
  const ctRef = useRef(null);
  const tabScrollPos = useRef({}); // Per-tab scroll/selection state
  const displayRowsRef = useRef([]);
  const isGroupedRef = useRef(false);
  const rightClickFired = useRef(false);
  const [pendingRestores, setPendingRestores] = useState({});
  const pendingRestoresRef = useRef({});
  const ptCacheRef = useRef({ flatNodes: [], byKeyMap: new Map(), deps: null });
  const ptScrollRef = useRef(null);
  const ptHeaderRef = useRef(null);
  const ptRafRef = useRef(null);
  const ptResizingRef = useRef(false);
  const [ptScroll, setPtScroll] = useState({ top: 0, h: 600 });

  const ct = tabs.find((t) => t.id === activeTab);
  ctRef.current = ct;
  const tle = typeof window !== "undefined" ? window.tle : null;
  const th = THEMES[themeName];
  const isGrouped = ct?.groupByColumns?.length > 0;

  useEffect(() => { pendingRestoresRef.current = pendingRestores; }, [pendingRestores]);

  // ── Tab updater ──────────────────────────────────────────────────
  const up = useCallback((key, value) => {
    setTabs((prev) => prev.map((t) => (t.id === activeTab ? { ...t, [key]: value } : t)));
  }, [activeTab]);

  // ── Query backend ────────────────────────────────────────────────
  const activeFilters = useCallback((tab) => {
    const dis = tab.disabledFilters || new Set();
    if (dis.size === 0) return { columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters };
    return {
      columnFilters: Object.fromEntries(Object.entries(tab.columnFilters).filter(([k]) => !dis.has(k))),
      checkboxFilters: Object.fromEntries(Object.entries(tab.checkboxFilters).filter(([k]) => !dis.has(k))),
    };
  }, []);

  const fetchData = useCallback(async (tab, centerRow = 0) => {
    if (!tle || !tab) return;
    // Stale request prevention: capture current fetch ID before async work
    const myFetchId = ++fetchId.current;
    // Skip query for single-character searches (too broad, expensive on large datasets)
    const rawSearch = tab.searchHighlight ? "" : tab.searchTerm;
    const effectiveSearch = rawSearch && rawSearch.trim().length < 2 ? "" : rawSearch;
    const { columnFilters, checkboxFilters } = activeFilters(tab);
    // Build cache key for this query configuration
    const cacheKey = `${effectiveSearch}|${tab.searchMode}|${tab.sortCol}|${tab.sortDir}|${tab.showBookmarkedOnly}|${tab.searchCondition || "contains"}|${tab.tagFilter || ""}|${JSON.stringify(tab.dateRangeFilters)}|${JSON.stringify(tab.advancedFilters)}|${JSON.stringify(columnFilters)}|${JSON.stringify(checkboxFilters)}`;
    if (tab.groupByColumns?.length > 0) {
      const groupCol = tab.groupByColumns[0];
      const groupData = await tle.getGroupValues(tab.id, groupCol, {
        searchTerm: effectiveSearch, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters, checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
        parentFilters: [],
      });
      if (fetchId.current !== myFetchId) return; // Stale — newer fetch in flight
      setTabs((prev) => prev.map((t) =>
        t.id === tab.id ? { ...t, groupData: groupData || [], expandedGroups: {}, dataReady: true } : t
      ));
      setSearchLoading(false);
      return;
    }
    // Check search cache (instant FL/HL toggle and tab switching)
    const tabCache = searchCache.current[tab.id];
    if (tabCache && tabCache[cacheKey] && centerRow === 0) {
      const cached = tabCache[cacheKey];
      setTabs((prev) => prev.map((t) =>
        t.id === tab.id ? { ...t, rows: cached.rows, rowOffset: cached.rowOffset, totalFiltered: cached.totalFiltered, bookmarkedSet: cached.bookmarkedSet, rowTags: cached.rowTags, dataReady: true } : t
      ));
      setSearchLoading(false);
      return;
    }
    const fetchOffset = Math.max(0, centerRow - Math.floor(VIRTUAL_WINDOW / 2));
    const result = await tle.queryRows(tab.id, {
      offset: fetchOffset, limit: VIRTUAL_WINDOW,
      sortCol: tab.sortCol, sortDir: tab.sortDir,
      searchTerm: effectiveSearch, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
      columnFilters, checkboxFilters,
      bookmarkedOnly: tab.showBookmarkedOnly,
      tagFilter: (tab.disabledFilters || new Set()).has("__tags__") ? null : (tab.tagFilter || null),
      dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
    });
    if (fetchId.current !== myFetchId) return; // Stale — newer fetch in flight
    // Cache only initial/filter loads (centerRow===0), NOT scroll-driven fetches,
    // to prevent stale offset data from being returned on scroll-back
    if (centerRow === 0) {
      if (!searchCache.current[tab.id]) searchCache.current[tab.id] = {};
      const tc = searchCache.current[tab.id];
      const keys = Object.keys(tc);
      if (keys.length >= 4) delete tc[keys[0]];
      tc[cacheKey] = { rows: result.rows, rowOffset: fetchOffset, totalFiltered: result.totalFiltered, bookmarkedSet: new Set(result.bookmarkedRows), rowTags: result.rowTags || {} };
    }
    setTabs((prev) => prev.map((t) =>
      t.id === tab.id ? { ...t, rows: result.rows, rowOffset: fetchOffset, totalFiltered: result.totalFiltered, bookmarkedSet: new Set(result.bookmarkedRows), rowTags: result.rowTags || {}, dataReady: true } : t
    ));
    setSearchLoading(false);
  }, [tle]);

  const debouncedFetch = useCallback((tab) => {
    if (queryTimer.current) clearTimeout(queryTimer.current);
    queryTimer.current = setTimeout(() => fetchData(tab), QUERY_DEBOUNCE);
  }, [fetchData]);

  // Cleanup debounce timer on unmount to prevent stale callbacks
  useEffect(() => () => {
    if (queryTimer.current) clearTimeout(queryTimer.current);
    if (rafScroll.current) cancelAnimationFrame(rafScroll.current);
  }, []);

  // Debounced deps (typing: search term, column filters) — use useMemo to avoid JSON.stringify per render
  const debouncedDeps = useMemo(() => {
    const cf = ct?.columnFilters;
    return `${ct?.searchTerm}|${ct?.searchMode}|${cf ? Object.keys(cf).sort().map(k => `${k}=${cf[k]}`).join(",") : ""}`;
  }, [ct?.searchTerm, ct?.searchMode, ct?.columnFilters]);
  const prevDebouncedDeps = useRef(debouncedDeps);

  // Immediate deps (discrete actions: sort, bookmark toggle, checkbox filters, grouping, date range, highlight)
  const immediateDeps = useMemo(() => {
    const cbf = ct?.checkboxFilters;
    const cbfSig = cbf ? Object.keys(cbf).sort().map(k => `${k}:${(cbf[k] || []).length}`).join(",") : "";
    const gbSig = ct?.groupByColumns ? ct.groupByColumns.join(",") : "";
    const drSig = ct?.dateRangeFilters ? Object.keys(ct.dateRangeFilters).sort().map(k => { const r = ct.dateRangeFilters[k]; return `${k}=${r.from || ""}-${r.to || ""}`; }).join(",") : "";
    const dfSig = ct?.disabledFilters ? [...ct.disabledFilters].sort().join(",") : "";
    const afSig = ct?.advancedFilters?.map(f => `${f.column}:${f.operator}:${f.value}:${f.logic}`).join(",") || "";
    return `${ct?.sortCol}|${ct?.sortDir}|${ct?.showBookmarkedOnly}|${cbfSig}|${gbSig}|${drSig}|${ct?.searchHighlight}|${ct?.searchCondition}|${dfSig}|${ct?.tagFilter || ""}|${afSig}`;
  }, [ct?.sortCol, ct?.sortDir, ct?.showBookmarkedOnly, ct?.checkboxFilters, ct?.groupByColumns, ct?.dateRangeFilters, ct?.searchHighlight, ct?.searchCondition, ct?.disabledFilters, ct?.tagFilter, ct?.advancedFilters]);

  useEffect(() => {
    if (!ct || !ct.dataReady) return;
    if (prevDebouncedDeps.current !== debouncedDeps) {
      prevDebouncedDeps.current = debouncedDeps;
      setSearchLoading(true);
      debouncedFetch(ct);
    } else {
      if (queryTimer.current) clearTimeout(queryTimer.current);
      setSearchLoading(true);
      fetchData(ct);
    }
  }, [debouncedDeps, immediateDeps]);

  // Histogram data fetch (with per-tab cache for instant tab switching)
  const histogramTimer = useRef(null);
  useEffect(() => {
    if (histogramTimer.current) clearTimeout(histogramTimer.current);
    if (!histogramVisible || !ct?.dataReady || !ct?.tsColumns?.size || !tle) { setHistogramData([]); return; }
    const hCol = histogramCol && ct.tsColumns.has(histogramCol) ? histogramCol : [...ct.tsColumns][0];
    if (!hCol) return;
    const sig = `${ct.id}:${hCol}:${histGranularity}:${ct.totalFiltered}:${ct.searchTerm}:${ct.searchMode}:${ct.showBookmarkedOnly}:${JSON.stringify(ct.dateRangeFilters)}:${JSON.stringify(ct.advancedFilters)}`;
    const cached = histogramCache.current[ct.id];
    if (cached && cached.sig === sig) { setHistogramData(cached.data); return; }
    if (cached) setHistogramData(cached.data); // show stale data while refreshing
    histogramTimer.current = setTimeout(async () => {
      const af = activeFilters(ct);
      const effectiveSearch = ct.searchHighlight ? "" : ct.searchTerm;
      const data = await tle.getHistogramData(ct.id, hCol, {
        searchTerm: effectiveSearch, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
        granularity: histGranularity,
      });
      const result = data || [];
      histogramCache.current[ct.id] = { sig, data: result };
      setHistogramData(result);
    }, 400);
    return () => { if (histogramTimer.current) clearTimeout(histogramTimer.current); };
  }, [histogramVisible, histogramCol, histGranularity, ct?.id, ct?.totalFiltered, ct?.searchTerm, ct?.searchMode, ct?.showBookmarkedOnly, JSON.stringify(ct?.dateRangeFilters), JSON.stringify(ct?.advancedFilters)]); // eslint-disable-line

  // Histogram container width tracking via ResizeObserver
  useEffect(() => {
    const el = histContainerRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w = entry.contentRect.width;
        if (w > 0) setHistContainerWidth(w);
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [histogramVisible]);

  // ── Scroll-driven window fetch (server-side virtual scrolling) ──
  const scrollFetchTimer = useRef(null);
  useEffect(() => {
    if (!ct || !ct.dataReady || isGrouped) return;
    const scrollRow = Math.floor(scrollTop / ROW_HEIGHT);
    const windowEnd = (ct.rowOffset || 0) + (ct.rows?.length || 0);
    const needsFetch = scrollRow < (ct.rowOffset || 0) + VIRTUAL_AHEAD
      || scrollRow + 60 > windowEnd - VIRTUAL_AHEAD;
    // Only fetch if we're actually near the edge of the cached window
    if (!needsFetch || (ct.rows?.length || 0) >= (ct.totalFiltered || 0)) return;
    if (scrollFetchTimer.current) clearTimeout(scrollFetchTimer.current);
    scrollFetchTimer.current = setTimeout(() => fetchData(ct, scrollRow), 50);
  }, [scrollTop, ct?.rowOffset, ct?.rows?.length, ct?.totalFiltered, isGrouped]);

  // ── Group expand/collapse (multi-level) ─────────────────────────
  const expandGroup = useCallback(async (pathKey, parentFilters, depth) => {
    if (!tle || !ctRef.current) return;
    const tab = ctRef.current;
    const groupCols = tab.groupByColumns || [];
    const nextLevel = depth;

    if (nextLevel < groupCols.length) {
      // Expand into sub-groups
      const nextCol = groupCols[nextLevel];
      const af = activeFilters(tab);
      const subGroups = await tle.getGroupValues(tab.id, nextCol, {
        searchTerm: tab.searchHighlight ? "" : tab.searchTerm, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
        parentFilters,
      });
      setTabs((prev) => prev.map((t) => {
        if (t.id !== tab.id) return t;
        return { ...t, expandedGroups: { ...t.expandedGroups, [pathKey]: { subGroups: subGroups || [], depth: nextLevel } } };
      }));
    } else {
      // Leaf level — fetch actual rows (initial batch)
      const af = activeFilters(tab);
      const GROUP_BATCH = 100000;
      const result = await tle.queryRows(tab.id, {
        offset: 0, limit: GROUP_BATCH,
        sortCol: tab.sortCol, sortDir: tab.sortDir,
        searchTerm: tab.searchHighlight ? "" : tab.searchTerm, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
        groupFilters: parentFilters,
      });
      if (!result || result.__ipcError || !Array.isArray(result.rows)) return;
      setTabs((prev) => prev.map((t) => {
        if (t.id !== tab.id) return t;
        const newBm = new Set(t.bookmarkedSet);
        (result.bookmarkedRows || []).forEach((id) => newBm.add(id));
        const newTags = { ...t.rowTags, ...(result.rowTags || {}) };
        return { ...t, bookmarkedSet: newBm, rowTags: newTags, expandedGroups: { ...t.expandedGroups, [pathKey]: { rows: result.rows, totalFiltered: result.totalFiltered, groupFilters: parentFilters } } };
      }));
    }
  }, [tle]);

  // Load more rows for an expanded group (append next batch or load all remaining)
  const loadMoreGroupRows = useCallback(async (pathKey, loadAll) => {
    if (!tle || !ctRef.current) return;
    const tab = ctRef.current;
    const existing = tab.expandedGroups?.[pathKey];
    if (!existing || !existing.rows || !existing.groupFilters) return;
    const GROUP_BATCH = 100000;
    const loaded = existing.rows.length;
    const remaining = existing.totalFiltered - loaded;
    if (remaining <= 0) return;
    const af = activeFilters(tab);
    const result = await tle.queryRows(tab.id, {
      offset: loaded, limit: loadAll ? remaining : GROUP_BATCH,
      sortCol: tab.sortCol, sortDir: tab.sortDir,
      searchTerm: tab.searchHighlight ? "" : tab.searchTerm, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
      columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
      bookmarkedOnly: tab.showBookmarkedOnly,
      dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
      groupFilters: existing.groupFilters,
    });
    if (!result || result.__ipcError || !Array.isArray(result.rows)) return;
    setTabs((prev) => prev.map((t) => {
      if (t.id !== tab.id) return t;
      const eg = t.expandedGroups[pathKey];
      if (!eg) return t;
      const newBm = new Set(t.bookmarkedSet);
      (result.bookmarkedRows || []).forEach((id) => newBm.add(id));
      const newTags = { ...t.rowTags, ...(result.rowTags || {}) };
      return { ...t, bookmarkedSet: newBm, rowTags: newTags, expandedGroups: { ...t.expandedGroups, [pathKey]: { ...eg, rows: [...eg.rows, ...result.rows] } } };
    }));
  }, [tle]);

  const collapseGroup = useCallback((pathKey) => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      // Remove this key and all children
      const eg = {};
      for (const k of Object.keys(t.expandedGroups)) {
        if (k !== pathKey && !k.startsWith(pathKey + "|||")) eg[k] = t.expandedGroups[k];
      }
      return { ...t, expandedGroups: eg };
    }));
  }, [activeTab]);

  // ── Pin/unpin ────────────────────────────────────────────────────
  const pinColumn = useCallback((colName) => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const pinned = t.pinnedColumns || [];
      if (pinned.includes(colName)) return t;
      return { ...t, pinnedColumns: [...pinned, colName] };
    }));
  }, [activeTab]);

  const unpinColumn = useCallback((colName) => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      return { ...t, pinnedColumns: (t.pinnedColumns || []).filter((c) => c !== colName) };
    }));
  }, [activeTab]);

  // ── Group by ─────────────────────────────────────────────────────
  const addGroupBy = useCallback((colName) => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const groups = t.groupByColumns || [];
      if (groups.includes(colName) || groups.length >= 5) return t;
      return { ...t, groupByColumns: [...groups, colName], expandedGroups: {}, groupData: [] };
    }));
  }, [activeTab]);

  const removeGroupBy = useCallback((colName) => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      return { ...t, groupByColumns: (t.groupByColumns || []).filter((c) => c !== colName), expandedGroups: {}, groupData: [] };
    }));
  }, [activeTab]);

  // ── Cross-tab find ─────────────────────────────────────────────
  const handleCrossFind = useCallback(async (term) => {
    if (!tle || !term.trim() || tabs.length === 0) return;
    const results = [];
    for (const tab of tabs) {
      if (!tab.dataReady) continue;
      const count = await tle.searchCount(tab.id, term, "mixed");
      results.push({ tabId: tab.id, name: tab.name, count });
    }
    setCrossFind({ term, results });
  }, [tle, tabs]);

  // Auto cross-tab counts when searching with 2+ tabs
  const crossTabTimer = useRef(null);
  useEffect(() => {
    if (crossTabTimer.current) clearTimeout(crossTabTimer.current);
    const term = ct?.searchTerm?.trim();
    const readyTabs = tabs.filter((t) => t.dataReady);
    if (!term || readyTabs.length < 2 || !tle) { setCrossTabCounts(null); return; }
    setCrossTabOpen(true);
    crossTabTimer.current = setTimeout(async () => {
      const mode = ct?.searchMode || "mixed";
      const cond = ct?.searchCondition || "contains";
      const results = [];
      for (const tab of readyTabs) {
        const count = await tle.searchCount(tab.id, term, mode, cond);
        results.push({ tabId: tab.id, name: tab.name, count });
      }
      setCrossTabCounts({ term, mode, cond, results });
    }, 600);
    return () => { if (crossTabTimer.current) clearTimeout(crossTabTimer.current); };
  }, [ct?.searchTerm, ct?.searchMode, tabs.length, tle]); // eslint-disable-line

  // ── Reset column widths ────────────────────────────────────────
  const resetColumnWidths = useCallback(() => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const cw = {};
      t.headers.forEach((h) => {
        const hLen = h.length * 8 + 36;
        const sample = (t.rows || []).slice(0, 50).map((r) => ((r[h] || "").length * 6.5 + 16));
        cw[h] = Math.max(80, Math.min(Math.max(hLen, ...sample), 450));
      });
      return { ...t, columnWidths: cw };
    }));
  }, [activeTab]);

  // ── Column auto-fit ────────────────────────────────────────────
  const autoFitColumn = useCallback((colName) => {
    if (colName === "__tags__") {
      setTabs((prev) => prev.map((t) => {
        if (t.id !== activeTab) return t;
        const hLen = 4 * 8 + 36; // "Tags"
        const sample = (t.rows || []).slice(0, 200).map((r) => {
          const tags = (t.rowTags || {})[r.__idx] || [];
          return tags.reduce((w, tag) => w + tag.length * 6.5 + 14, 8);
        });
        const best = Math.max(80, Math.min(Math.max(hLen, ...sample), 800));
        setTagColWidth(best);
        return t;
      }));
      return;
    }
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const hLen = colName.length * 8 + 36;
      const sample = (t.rows || []).slice(0, 200).map((r) => ((r[colName] || "").length * 6.5 + 16));
      const best = Math.max(80, Math.min(Math.max(hLen, ...sample), 800));
      return { ...t, columnWidths: { ...t.columnWidths, [colName]: best } };
    }));
  }, [activeTab]);

  const autoFitAllColumns = useCallback(() => {
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const visH = t.headers.filter((h) => !t.hiddenColumns?.has(h));
      const newWidths = { ...t.columnWidths };
      for (const h of visH) {
        const hLen = h.length * 8 + 36;
        const sample = (t.rows || []).slice(0, 200).map((r) => ((r[h] || "").length * 6.5 + 16));
        newWidths[h] = Math.max(80, Math.min(Math.max(hLen, ...sample), 800));
      }
      return { ...t, columnWidths: newWidths };
    }));
  }, [activeTab]);

  // ── Column reorder ─────────────────────────────────────────────
  const reorderColumn = useCallback((dragCol, dropCol) => {
    if (dragCol === dropCol) return;
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const order = t.columnOrder?.length > 0
        ? [...t.columnOrder]
        : [...t.headers];
      const fromIdx = order.indexOf(dragCol);
      const toIdx = order.indexOf(dropCol);
      if (fromIdx === -1 || toIdx === -1) return t;
      order.splice(fromIdx, 1);
      order.splice(toIdx, 0, dragCol);
      return { ...t, columnOrder: order };
    }));
  }, [activeTab]);

  // ── Electron IPC listeners (register once, clean up on unmount) ──
  useEffect(() => {
    if (!tle) return;

    const allChannels = [
      "import-start", "import-progress", "import-complete", "import-error", "import-queue",
      "export-progress", "sheet-selection", "fts-progress", "index-progress",
      "trigger-open", "trigger-export", "trigger-search",
      "trigger-bookmark-toggle", "trigger-column-manager",
      "trigger-color-rules", "trigger-shortcuts",
      "trigger-generate-report",
      "trigger-crossfind", "trigger-save-session", "trigger-load-session",
      "trigger-close-tab", "trigger-close-all-tabs",
      "native-context-menu",
      "set-datetime-format", "set-timezone", "set-font-size",
      "trigger-reset-columns", "set-theme", "trigger-histogram",
    ];

    // Remove any pre-existing listeners to avoid duplicates
    allChannels.forEach((ch) => tle.removeAllListeners(ch));

    tle.onImportStart(({ tabId, fileName, filePath, fileSize }) => {
      setImportingTabs((prev) => ({ ...prev, [tabId]: { fileName, rowsImported: 0, percent: 0, status: "importing", fileSize: fileSize || 0 } }));
      setTabs((prev) => [...prev, {
        id: tabId, name: fileName, filePath, headers: [], rows: [], totalRows: 0, totalFiltered: 0,
        tsColumns: new Set(), numericColumns: new Set(), searchTerm: "", searchMode: "mixed", searchCondition: "contains",
        columnFilters: {}, checkboxFilters: {}, sortCol: null, sortDir: "asc", colorRules: [],
        hiddenColumns: new Set(), bookmarkedSet: new Set(), showBookmarkedOnly: false, rowOffset: 0,
        columnWidths: {}, columnOrder: [], pinnedColumns: [], groupByColumns: [], groupData: [], expandedGroups: {},
        rowTags: {}, tagColors: { ...TAG_PRESETS }, tagFilter: null,
        dateRangeFilters: {}, searchHighlight: false, disabledFilters: new Set(),
        advancedFilters: [],
        importing: true, dataReady: false,
      }]);
      setActiveTab(tabId);
    });
    tle.onImportProgress(({ tabId, rowsImported, percent }) => {
      setImportingTabs((prev) => ({ ...prev, [tabId]: { ...prev[tabId], rowsImported, percent, status: percent >= 100 ? "indexing" : "importing" } }));
    });
    tle.onImportComplete(({ tabId, fileName, headers, rowCount, tsColumns, numericColumns, initialRows, totalFiltered, emptyColumns }) => {
      const cw = {};
      headers.forEach((h) => {
        const hLen = h.length * 8 + 36;
        const sampleRows = initialRows.slice(0, 100);
        const lengths = sampleRows.map((r) => (r[h] || "").length).filter((l) => l > 0);
        const meanLen = lengths.length > 0 ? lengths.reduce((a, b) => a + b, 0) / lengths.length : 0;
        const meanPx = meanLen * 6.5 + 16;
        // Use mean for typical width, but ensure header always fits
        cw[h] = Math.max(80, Math.min(Math.max(hLen, Math.round(meanPx)), 400));
      });
      const saved = pendingRestoresRef.current[tabId];
      setTabs((prev) => prev.map((t) => {
        if (t.id !== tabId) return t;
        const base = { ...t, name: fileName, headers, rows: initialRows, rowOffset: 0, totalRows: rowCount, totalFiltered,
          tsColumns: new Set(tsColumns || []), numericColumns: new Set(numericColumns || []),
          columnWidths: saved ? { ...cw, ...saved.columnWidths } : cw, importing: false, dataReady: true, bookmarkedSet: new Set() };
        if (!saved) {
          const autoHidden = new Set(emptyColumns || []);
          // Auto-detect KAPE/EZ Tools output and apply profile
          const kp = detectKapeProfile(headers);
          if (kp) {
            const order = (kp.columnOrder || []).filter((h) => headers.includes(h));
            const rest = headers.filter((h) => !order.includes(h));
            const autoRules = kp.autoColorColumn && headers.includes(kp.autoColorColumn)
              ? buildTimelineColorRules(initialRows, kp.autoColorColumn, true)
              : [];
            // Merge KAPE hidden columns with auto-detected empty columns
            const kpHidden = (kp.hiddenColumns || []).filter((h) => headers.includes(h));
            kpHidden.forEach((h) => autoHidden.add(h));
            return { ...base, _detectedProfile: kp.name,
              pinnedColumns: [],
              hiddenColumns: autoHidden,
              columnOrder: [...order, ...rest],
              colorRules: autoRules,
            };
          }
          return { ...base, hiddenColumns: autoHidden };
        }
        return { ...base,
          tagColors: saved.tagColors || { ...TAG_PRESETS },
          columnFilters: saved.columnFilters || {},
          checkboxFilters: saved.checkboxFilters || {},
          colorRules: saved.colorRules || [],
          hiddenColumns: new Set(saved.hiddenColumns || []),
          pinnedColumns: saved.pinnedColumns || [], columnOrder: saved.columnOrder || [],
          sortCol: saved.sortCol, sortDir: saved.sortDir || "asc",
          searchTerm: saved.searchTerm || "", searchMode: saved.searchMode || "mixed", searchCondition: saved.searchCondition || "contains",
          groupByColumns: saved.groupByColumns || [],
          showBookmarkedOnly: saved.showBookmarkedOnly || false,
          dateRangeFilters: saved.dateRangeFilters || {},
          advancedFilters: saved.advancedFilters || [],
          searchHighlight: saved.searchHighlight || false,
        };
      }));
      setImportingTabs((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
      // Restore bookmarks and tags from session
      if (saved) {
        (async () => {
          if (saved.bookmarkedRowIds?.length) await tle.setBookmarks(tabId, saved.bookmarkedRowIds, true);
          if (saved.tags && Object.keys(saved.tags).length > 0) await tle.bulkAddTags(tabId, saved.tags);
          setPendingRestores((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
        })().catch((err) => {
          console.error("Session restore error for tab", tabId, err);
          setPendingRestores((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
        });
      }
    });
    tle.onImportQueue(({ pending }) => {
      setImportQueue(pending || []);
    });
    tle.onImportError(({ tabId, error }) => {
      setImportingTabs((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
      setTabs((prev) => prev.filter((t) => t.id !== tabId));
      alert(`Import failed: ${error}`);
    });
    tle.onIndexProgress(({ tabId, built, total, done, currentCol }) => {
      setTabs((prev) => prev.map((t) =>
        t.id === tabId ? { ...t, indexesReady: done, indexesBuilt: built, indexesTotal: total } : t
      ));
    });
    tle.onFtsProgress(({ tabId, indexed, total, done }) => {
      setTabs((prev) => prev.map((t) =>
        t.id === tabId ? { ...t, ftsReady: done, ftsIndexed: indexed, ftsTotal: total } : t
      ));
    });
    tle.onSheetSelection(({ tabId, fileName, filePath, sheets }) => {
      setModal({ type: "sheets", tabId, fileName, filePath, sheets });
    });
    tle.onTriggerOpen(() => tle.openFileDialog());
    tle.onTriggerExport(() => {
      const cur = ctRef.current;
      if (cur) {
        const af = activeFilters(cur);
        tle.exportFiltered(cur.id, {
          searchTerm: cur.searchHighlight ? "" : cur.searchTerm, searchMode: cur.searchMode, searchCondition: cur.searchCondition || "contains",
          columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
          bookmarkedOnly: cur.showBookmarkedOnly, sortCol: cur.sortCol, sortDir: cur.sortDir,
          dateRangeFilters: cur.dateRangeFilters || {},
        });
      }
    });
    tle.onTriggerGenerateReport(() => {
      const cur = ctRef.current;
      if (cur?.dataReady) tle.generateReport(cur.id, cur.name, cur.tagColors || {});
    });
    tle.onTriggerSearch(() => document.getElementById("gs")?.focus());
    tle.onTriggerBookmarkToggle(() => {
      const cur = ctRef.current;
      if (cur) setTabs((prev) => prev.map((t) => t.id === cur.id ? { ...t, showBookmarkedOnly: !t.showBookmarkedOnly } : t));
    });
    tle.onTriggerColumnManager(() => setModal({ type: "columns" }));
    tle.onTriggerColorRules(() => setModal({ type: "colors" }));
    tle.onTriggerShortcuts(() => setModal({ type: "shortcuts" }));
    tle.onTriggerCrossFind(() => setModal({ type: "crossfind" }));
    tle.onTriggerSaveSession(() => handleSaveSession());
    tle.onTriggerLoadSession(() => handleLoadSession());
    tle.onTriggerCloseTab(() => { const cur = ctRef.current; if (cur) closeTab(cur.id); });
    tle.onTriggerCloseAllTabs(() => { setTabs((prev) => { prev.forEach((t) => tle.closeTab(t.id)); return []; }); setActiveTab(null); });

    // Native right-click forwarded from Electron main process via IPC.
    // On macOS with external trackpads, DOM contextmenu events may never reach the renderer,
    // so we use elementFromPoint + data attributes to resolve the target.
    tle.onNativeContextMenu(({ x, y }) => {
      handleNativeRightClick(x, y);
    });

    // Tools menu handlers
    tle.onSetDatetimeFormat((fmt) => setDateTimeFormat(fmt));
    tle.onSetTimezone((tz) => setTimezone(tz));
    tle.onSetFontSize((val) => {
      if (val === "increase") setFontSize((s) => Math.min(18, s + 1));
      else if (val === "decrease") setFontSize((s) => Math.max(9, s - 1));
      else if (typeof val === "number") setFontSize(val);
    });
    tle.onTriggerResetColumns(() => resetColumnWidths());
    tle.onSetTheme((name) => setThemeName(name));
    tle.onTriggerHistogram(() => setHistogramVisible((v) => !v));

    // Load saved filter presets
    tle.loadFilterPresets().then((p) => setFilterPresets(p || [])).catch(() => {});

    return () => {
      allChannels.forEach((ch) => tle.removeAllListeners(ch));
    };
  }, [tle]);

  // Shared handler for right-click from any source (IPC, DOM onContextMenu, or mousedown fallback)
  const handleNativeRightClick = useCallback((x, y) => {
    const el = document.elementFromPoint(x, y);
    if (!el) return;

    // Column header right-click
    const headerEl = el.closest("[data-col-header]");
    if (headerEl) {
      setContextMenu({ x, y, colName: headerEl.dataset.colHeader });
      return;
    }

    // Data row right-click
    const rowEl = el.closest("[data-row-id]");
    if (!rowEl) return;

    const rowId = rowEl.dataset.rowId;
    const rowIndex = parseInt(rowEl.dataset.rowIndex, 10);
    const cellEl = el.closest("[data-cell-col]");
    const cellCol = cellEl ? cellEl.dataset.cellCol : null;

    const tab = ctRef.current;
    if (!tab) return;

    const dRows = displayRowsRef.current;
    const tab2 = ctRef.current;
    const offset = isGroupedRef.current ? 0 : (tab2?.rowOffset || 0);
    const item = dRows[rowIndex - offset];
    if (!item) return;
    const row = isGroupedRef.current ? (item.data || item) : item;
    if (!row || String(row.__idx) !== String(rowId)) return;

    const rTags = (tab.rowTags || {})[row.__idx] || [];
    setRowContextMenu({
      x, y,
      rowId: row.__idx,
      rowIndex,
      currentTags: rTags,
      row,
      cellColumn: cellCol,
      cellValue: cellCol ? (row[cellCol] || "") : "",
    });
  }, []);

  // Fallback: catch right-clicks via DOM mousedown (covers Cmd+Click / Ctrl+Click on macOS and button=2)
  useEffect(() => {
    const handler = (e) => {
      if (e.button === 2 || (e.button === 0 && (e.ctrlKey || e.metaKey))) {
        e.preventDefault();
        rightClickFired.current = true;
        setTimeout(() => { rightClickFired.current = false; }, 50);
        handleNativeRightClick(e.clientX, e.clientY);
      }
    };
    document.addEventListener("mousedown", handler, true);
    return () => document.removeEventListener("mousedown", handler, true);
  }, [handleNativeRightClick]);

  // ── Handlers ─────────────────────────────────────────────────────
  const sortTimerRef = useRef(null);
  const handleSort = (col) => {
    if (justResizedRef.current || !ct) return;
    // Delay sort so double-click (auto-fit) can cancel it
    clearTimeout(sortTimerRef.current);
    sortTimerRef.current = setTimeout(() => {
      if (ct.sortCol === col) up("sortDir", ct.sortDir === "asc" ? "desc" : "asc");
      else { up("sortCol", col); up("sortDir", "asc"); }
    }, 250);
  };
  const handleHeaderDblClick = (col) => {
    clearTimeout(sortTimerRef.current);
    autoFitColumn(col);
  };

  const handleBookmark = async (rowId) => {
    if (!tle || !ct) return;
    const isNowBookmarked = await tle.toggleBookmark(ct.id, rowId);
    const newSet = new Set(ct.bookmarkedSet);
    isNowBookmarked ? newSet.add(rowId) : newSet.delete(rowId);
    up("bookmarkedSet", newSet);
  };

  const handleExport = async () => {
    if (!tle || !ct) return;
    const visHeaders = ct.headers.filter((h) => !ct.hiddenColumns.has(h));
    const af = activeFilters(ct);
    await tle.exportFiltered(ct.id, {
      sortCol: ct.sortCol, sortDir: ct.sortDir, searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
      columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
      bookmarkedOnly: ct.showBookmarkedOnly, visibleHeaders: visHeaders,
      dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
    });
  };

  const closeTab = async (id) => {
    if (tle) await tle.closeTab(id);
    delete histogramCache.current[id];
    delete searchCache.current[id];
    const rem = tabs.filter((t) => t.id !== id);
    setTabs(rem);
    if (activeTab === id) setActiveTab(rem.length ? rem[rem.length - 1].id : null);
  };

  const copyCell = (val) => {
    navigator.clipboard?.writeText(val || "");
    setCopiedMsg(true);
    setTimeout(() => setCopiedMsg(false), 1200);
  };

  // ── Temporal Proximity Search ──────────────────────────────────
  const applyProximity = useCallback((tsCol, pivotRaw, windowMs, label) => {
    const normalized = (pivotRaw || "").replace(" ", "T");
    const pivotMs = Date.parse(normalized);
    if (isNaN(pivotMs)) return;
    const fmt = (ms) => {
      const d = new Date(ms);
      const pad = (n) => String(n).padStart(2, "0");
      return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
    };
    up("dateRangeFilters", { ...(ct?.dateRangeFilters || {}), [tsCol]: { from: fmt(pivotMs - windowMs), to: fmt(pivotMs + windowMs) } });
    setProximityFilter({ tsCol, pivotRaw, windowMs, label });
    setModal(null);
  }, [ct, up]);

  // ── Session save/load ──────────────────────────────────────────
  const handleSaveSession = useCallback(async () => {
    if (!tle || tabs.length === 0) return;
    const sessionTabs = [];
    for (const tab of tabs) {
      if (!tab.dataReady) continue;
      const bookmarkIds = await tle.getBookmarkedIds(tab.id);
      const tagData = await tle.getAllTagData(tab.id);
      const tags = {};
      for (const { rowid, tag } of tagData) {
        if (!tags[rowid]) tags[rowid] = [];
        tags[rowid].push(tag);
      }
      sessionTabs.push({
        filePath: tab.filePath, name: tab.name,
        bookmarkedRowIds: bookmarkIds, tags, tagColors: tab.tagColors || {},
        columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters,
        colorRules: tab.colorRules, hiddenColumns: [...tab.hiddenColumns],
        pinnedColumns: tab.pinnedColumns, columnWidths: tab.columnWidths, columnOrder: tab.columnOrder || [],
        sortCol: tab.sortCol, sortDir: tab.sortDir,
        searchTerm: tab.searchTerm, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        groupByColumns: tab.groupByColumns, showBookmarkedOnly: tab.showBookmarkedOnly,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [], searchHighlight: tab.searchHighlight || false,
      });
    }
    await tle.saveSession({ version: 1, savedAt: new Date().toISOString(), activeTabIndex: tabs.findIndex((t) => t.id === activeTab), tabs: sessionTabs });
  }, [tle, tabs, activeTab]);

  const handleLoadSession = useCallback(async () => {
    if (!tle) return;
    const session = await tle.loadSession();
    if (!session || session.error) {
      if (session?.error) alert(`Failed to load session: ${session.error}`);
      return;
    }
    if (session.version !== 1) { alert("Unsupported session version"); return; }
    for (const tab of tabs) await tle.closeTab(tab.id);
    setTabs([]); setActiveTab(null);
    const restoreMap = {};
    for (const savedTab of session.tabs) {
      const result = await tle.importFileForRestore(savedTab.filePath, savedTab.sheetName);
      if (result.error) { alert(`Skipping "${savedTab.name}": ${result.error}`); continue; }
      restoreMap[result.tabId] = savedTab;
    }
    setPendingRestores(restoreMap);
  }, [tle, tabs]);

  // ── Computed headers ─────────────────────────────────────────────
  const allVisH = useMemo(() => {
    if (!ct) return [];
    const visSet = new Set(ct.headers.filter((h) => !ct.hiddenColumns.has(h)));
    if (ct.columnOrder?.length > 0) {
      const ordered = ct.columnOrder.filter((h) => visSet.has(h));
      const orderSet = new Set(ct.columnOrder);
      const rest = [...visSet].filter((h) => !orderSet.has(h));
      return [...ordered, ...rest];
    }
    return [...visSet];
  }, [ct?.headers, ct?.hiddenColumns, ct?.columnOrder]);

  const pinnedH = useMemo(() => {
    if (!ct) return [];
    const visSet = new Set(allVisH);
    return (ct.pinnedColumns || []).filter((h) => visSet.has(h));
  }, [ct?.pinnedColumns, allVisH]);

  const scrollH = useMemo(() => {
    const pinSet = new Set(pinnedH);
    return allVisH.filter((h) => !pinSet.has(h));
  }, [allVisH, pinnedH]);

  const pinnedOffsets = useMemo(() => {
    const offsets = {};
    let x = BKMK_COL_WIDTH + tagColWidth; // after # column + Tags column
    for (const h of pinnedH) {
      offsets[h] = x;
      x += (ct?.columnWidths[h] || 150);
    }
    return { offsets, totalWidth: x };
  }, [pinnedH, ct?.columnWidths, tagColWidth]);

  // ── Grouped items (multi-level) ─────────────────────────────────
  const groupedItems = useMemo(() => {
    if (!isGrouped || !ct?.groupData?.length) return null;
    const groupCols = ct.groupByColumns;
    const eg = ct.expandedGroups || {};
    const items = [];

    const buildLevel = (groups, depth, parentPath, parentFilters) => {
      const colName = groupCols[depth];
      for (const group of groups) {
        const pathKey = parentPath ? `${parentPath}|||${group.val}` : `${group.val}`;
        const filters = [...parentFilters, { col: colName, value: group.val }];
        items.push({ type: "group", value: group.val, count: group.cnt, depth, pathKey, filters, colName });
        const expanded = eg[pathKey];
        if (expanded) {
          if (expanded.subGroups) {
            // Sub-group level
            buildLevel(expanded.subGroups, depth + 1, pathKey, filters);
          } else if (expanded.rows) {
            // Leaf rows
            for (const row of expanded.rows) items.push({ type: "row", data: row, depth: depth + 1 });
            if (expanded.rows.length < expanded.totalFiltered)
              items.push({ type: "more", pathKey, loaded: expanded.rows.length, total: expanded.totalFiltered, depth: depth + 1 });
          }
        }
      }
    };

    buildLevel(ct.groupData, 0, "", []);
    return items;
  }, [isGrouped, ct?.groupData, ct?.expandedGroups, ct?.groupByColumns]);

  // ── Virtual scroll ───────────────────────────────────────────────
  const rows = ct?.rows || [];
  const displayRows = isGrouped && groupedItems ? groupedItems : rows;
  displayRowsRef.current = displayRows;
  isGroupedRef.current = isGrouped;

  // Get a row by absolute index (accounts for windowed offset in flat mode)
  const getRowAt = useCallback((absIdx) => {
    if (isGrouped) return displayRows[absIdx] || null;
    const localIdx = absIdx - (ct?.rowOffset || 0);
    return (localIdx >= 0 && localIdx < rows.length) ? rows[localIdx] : null;
  }, [isGrouped, displayRows, rows, ct?.rowOffset]);

  // Primary selected row (last clicked) for detail panel
  const selectedRow = lastClickedRow !== null && selectedRows.has(lastClickedRow) ? lastClickedRow : null;

  const selectedRowData = useMemo(() => {
    if (selectedRow === null) return null;
    const item = getRowAt(selectedRow);
    if (!item) return null;
    if (isGrouped) return item.type === "row" ? item.data : null;
    return item;
  }, [selectedRow, getRowAt, isGrouped]);

  const handleRowClick = (ai, e) => {
    // Skip if this click was a Cmd+Click / Ctrl+Click that triggered the context menu
    if (rightClickFired.current) return;
    if (e.shiftKey && lastClickedRow !== null) {
      // Shift+Click: range select
      const from = Math.min(lastClickedRow, ai);
      const to = Math.max(lastClickedRow, ai);
      setSelectedRows((prev) => {
        const next = new Set(prev);
        for (let i = from; i <= to; i++) next.add(i);
        return next;
      });
    } else if (e.metaKey || e.ctrlKey) {
      // Cmd/Ctrl+Click: toggle individual
      setSelectedRows((prev) => {
        const next = new Set(prev);
        if (next.has(ai)) next.delete(ai);
        else next.add(ai);
        return next;
      });
      setLastClickedRow(ai);
    } else {
      // Plain click: single select
      setSelectedRows(new Set([ai]));
      setLastClickedRow(ai);
    }
    setDetailPanelOpen(true);
  };

  const detailVisible = detailPanelOpen && selectedRowData !== null;
  const totalCount = isGrouped ? displayRows.length : (ct?.totalFiltered || 0);
  const rowOffset = ct?.rowOffset || 0;
  const totalH = totalCount * ROW_HEIGHT;
  // Use actual scroll container height when available (adapts to zoom/resize), fall back to estimate
  const vh = (scrollRef.current?.clientHeight || (viewportH - 190)) - (detailVisible ? detailPanelHeight : 0);
  const si = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const ei = Math.min(totalCount, Math.ceil((scrollTop + vh) / ROW_HEIGHT) + OVERSCAN);
  // For grouped mode: direct slice. For flat mode: map to windowed cache via rowOffset.
  const visible = useMemo(() => isGrouped
    ? displayRows.slice(si, ei)
    : rows.slice(Math.max(0, si - rowOffset), Math.max(0, ei - rowOffset)),
    [isGrouped, displayRows, rows, si, ei, rowOffset]);

  // Skeleton rows for positions outside the cached window (shown during fast scroll)
  const skeletonIndices = useMemo(() => {
    if (isGrouped || visible.length >= (ei - si)) return [];
    const cacheStart = rowOffset;
    const cacheEnd = rowOffset + rows.length;
    const indices = [];
    for (let i = si; i < ei; i++) {
      if (i < cacheStart || i >= cacheEnd) indices.push(i);
    }
    return indices;
  }, [isGrouped, visible.length, si, ei, rowOffset, rows.length]);

  const compiledColors = useMemo(() => compileColorRules(ct?.colorRules || []), [ct?.colorRules]);
  const gw = (col) => ct?.columnWidths[col] || 150;
  const fmtCell = (h, val) => (dateTimeFormat && ct?.tsColumns?.has(h)) ? formatDateTime(val, dateTimeFormat, timezone) : (val || "");
  const hlTerm = ct?.searchHighlight && ct?.searchTerm?.trim() ? ct.searchTerm.trim() : null;
  const hlRegex = useMemo(() => {
    if (!hlTerm) return null;
    try {
      if (ct?.searchMode === "regex") return new RegExp(`(${hlTerm})`, "gi");
      // For multi-word mixed/AND, highlight each word separately
      const words = hlTerm.split(/\s+/).filter(Boolean).map((w) =>
        w.replace(/^[+\-"]|"$/g, "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
      ).filter(Boolean);
      if (words.length === 0) return null;
      return new RegExp(`(${words.join("|")})`, "gi");
    } catch { return null; }
  }, [hlTerm, ct?.searchMode]);
  // IOC highlight regex — built from matched IOC values stored after IOC scan
  const iocRegex = useMemo(() => {
    const patterns = ct?.iocHighlights;
    if (!patterns || patterns.length === 0) return null;
    try {
      // Sort longest first so longer IOCs match before shorter substrings
      const sorted = [...patterns].sort((a, b) => b.length - a.length);
      const escaped = sorted.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
      return new RegExp(`(${escaped.join("|")})`, "gi");
    } catch { return null; }
  }, [ct?.iocHighlights]);
  const iocTestRegex = useMemo(() => iocRegex ? new RegExp(iocRegex.source, "i") : null, [iocRegex]);
  // Pre-built combined regex for when both highlight + IOC are active (avoids per-cell RegExp creation)
  const combinedHlRegex = useMemo(() => {
    if (!hlRegex || !iocRegex) return null;
    try { return new RegExp(`${iocRegex.source}|${hlRegex.source}`, "gi"); } catch { return null; }
  }, [hlRegex, iocRegex]);
  const renderCell = (h, val) => {
    const text = fmtCell(h, val);
    if (!text || (!hlRegex && !iocRegex)) return text;
    // Single highlight source — use fast split path
    if (hlRegex && !iocRegex) {
      const splits = text.split(hlRegex);
      if (splits.length <= 1) return text;
      return <>{splits.map((seg, i) => i % 2 === 1
        ? <mark key={i} style={{ background: "rgba(210,153,34,0.5)", color: "inherit", borderRadius: 2, padding: "0 1px" }}>{seg}</mark>
        : seg
      )}</>;
    }
    if (iocRegex && !hlRegex) {
      const splits = text.split(iocRegex);
      if (splits.length <= 1) return text;
      return <>{splits.map((seg, i) => i % 2 === 1
        ? <mark key={i} style={{ background: "rgba(240,136,62,0.45)", color: "inherit", borderRadius: 2, padding: "0 1px", fontWeight: 600 }}>{seg}</mark>
        : seg
      )}</>;
    }
    // Both active — use pre-built combined regex, color by match type
    if (!combinedHlRegex) return text;
    const combined = new RegExp(combinedHlRegex.source, "gi"); // clone to reset lastIndex
    const parts = [];
    let lastIndex = 0;
    let m;
    while ((m = combined.exec(text)) !== null) {
      if (m.index > lastIndex) parts.push(text.slice(lastIndex, m.index));
      const isIoc = iocTestRegex.test(m[0]);
      parts.push(<mark key={m.index} style={{
        background: isIoc ? "rgba(240,136,62,0.45)" : "rgba(210,153,34,0.5)",
        color: "inherit", borderRadius: 2, padding: "0 1px", ...(isIoc ? { fontWeight: 600 } : {}),
      }}>{m[0]}</mark>);
      lastIndex = combined.lastIndex;
      if (m[0].length === 0) { combined.lastIndex++; }
    }
    if (lastIndex === 0) return text;
    if (lastIndex < text.length) parts.push(text.slice(lastIndex));
    return <>{parts}</>;
  };
  const tw = useMemo(
    () => allVisH.reduce((s, h) => s + (ct?.columnWidths?.[h] || 150), 0) + BKMK_COL_WIDTH + tagColWidth,
    [allVisH, ct?.columnWidths, tagColWidth]
  );

  // Reset search match index when search term or results change
  useEffect(() => { setSearchMatchIdx(-1); }, [ct?.searchTerm, ct?.totalFiltered, ct?.searchHighlight]);

  // In highlight mode, compute which visible rows match the search term (client-side on cached window)
  const hlMatchIndices = useMemo(() => {
    if (!ct?.searchHighlight || !ct?.searchTerm?.trim() || isGrouped) return null;
    const term = ct.searchTerm.trim();
    let re;
    try {
      if (ct.searchMode === "regex") { re = new RegExp(term, "i"); }
      else {
        const words = term.split(/\s+/).filter(Boolean).map((w) =>
          w.replace(/^[+\-"]|"$/g, "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
        ).filter(Boolean);
        if (words.length === 0) return null;
        re = new RegExp(words.join("|"), "i");
      }
    } catch { return null; }
    const offset = ct?.rowOffset || 0;
    const indices = [];
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      if (!row || !row.__idx) continue;
      const match = allVisH.some((h) => re.test(row[h] || ""));
      if (match) indices.push(i + offset);
    }
    return indices;
  }, [ct?.searchHighlight, ct?.searchTerm, ct?.searchMode, rows, ct?.rowOffset, isGrouped, allVisH]);

  const scrollToRow = (idx) => {
    if (!scrollRef.current) return;
    const top = idx * ROW_HEIGHT;
    const bot = top + ROW_HEIGHT;
    const curTop = scrollRef.current.scrollTop;
    const viewH = scrollRef.current.clientHeight;
    if (top < curTop) scrollRef.current.scrollTop = top;
    else if (bot > curTop + viewH) scrollRef.current.scrollTop = bot - viewH;
  };

  const navigateSearch = (dir) => {
    const total = ct?.totalFiltered || 0;
    if (!ct?.searchTerm || isGrouped || total === 0) return;
    if (ct.searchHighlight && hlMatchIndices) {
      // Highlight mode: navigate only through matching rows in cached window
      if (hlMatchIndices.length === 0) return;
      let curPos = hlMatchIndices.indexOf(searchMatchIdx);
      if (curPos === -1) curPos = dir === 1 ? -1 : hlMatchIndices.length;
      let nextPos = dir === 1 ? curPos + 1 : curPos - 1;
      if (nextPos >= hlMatchIndices.length) nextPos = 0;
      if (nextPos < 0) nextPos = hlMatchIndices.length - 1;
      const next = hlMatchIndices[nextPos];
      setSearchMatchIdx(next);
      setSelectedRows(new Set([next]));
      setLastClickedRow(next);
      setDetailPanelOpen(true);
      scrollToRow(next);
      return;
    }
    let next;
    if (dir === 1) next = searchMatchIdx < total - 1 ? searchMatchIdx + 1 : 0;
    else next = searchMatchIdx > 0 ? searchMatchIdx - 1 : total - 1;
    setSearchMatchIdx(next);
    setSelectedRows(new Set([next]));
    setLastClickedRow(next);
    setDetailPanelOpen(true);
    scrollToRow(next);
  };

  // ── Column resize ────────────────────────────────────────────────
  useEffect(() => {
    if (!resizingCol || !ct) return;
    const onMove = (e) => {
      const nw = Math.max(60, resizeW + (e.clientX - resizeX));
      up("columnWidths", { ...ct.columnWidths, [resizingCol]: nw });
    };
    const onUp = () => { justResizedRef.current = true; setResizingCol(null); requestAnimationFrame(() => { justResizedRef.current = false; }); };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
  }, [resizingCol, resizeX, resizeW]);

  // ── Detail panel resize (DOM-direct for smooth dragging) ───────
  const onDetailResizeStart = (e) => {
    e.preventDefault();
    const startY = e.clientY;
    const startH = detailPanelHeight;
    detailResizeStartY.current = startY;
    detailResizeStartH.current = startH;
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
    const panel = detailPanelRef.current;
    const scrollEl = scrollRef.current;
    const onMove = (ev) => {
      const delta = detailResizeStartY.current - ev.clientY;
      const newH = Math.min(DETAIL_PANEL_MAX_HEIGHT, Math.max(DETAIL_PANEL_MIN_HEIGHT, detailResizeStartH.current + delta));
      if (panel) panel.style.height = newH + "px";
      if (scrollEl) scrollEl.style.flex = "1";
    };
    const onUp = (ev) => {
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      const delta = detailResizeStartY.current - ev.clientY;
      const finalH = Math.min(DETAIL_PANEL_MAX_HEIGHT, Math.max(DETAIL_PANEL_MIN_HEIGHT, detailResizeStartH.current + delta));
      setDetailPanelHeight(finalH);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  // ── Histogram resize (DOM-direct for smooth dragging) ───────────
  const onHistResizeStart = (e) => {
    e.preventDefault();
    histResizeStartY.current = e.clientY;
    histResizeStartH.current = histogramHeight;
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
    const onMove = (ev) => {
      const delta = ev.clientY - histResizeStartY.current;
      const newH = Math.min(500, Math.max(80, histResizeStartH.current + delta));
      // Direct DOM update for smoothness
      const el = document.getElementById("hist-container");
      if (el) el.style.height = newH + "px";
      const svg = el?.querySelector("svg");
      if (svg) svg.setAttribute("height", newH - 30);
    };
    const onUp = (ev) => {
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      const delta = ev.clientY - histResizeStartY.current;
      const finalH = Math.min(500, Math.max(80, histResizeStartH.current + delta));
      setHistogramHeight(finalH);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  // ── Filter dropdown data ─────────────────────────────────────────
  const loadFilterValues = useCallback(async (colName, searchText, preselectAll, useRegex = false) => {
    const tab = ctRef.current;
    if (!tle || !tab) return;
    setFdLoading(true);
    try {
      const af = activeFilters(tab);
      const result = await tle.getColumnUniqueValues(tab.id, colName, {
        searchTerm: tab.searchHighlight ? "" : tab.searchTerm, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly, filterText: searchText, filterRegex: useRegex,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
      });
      const vals = result || [];
      setFdValues(vals);
      // Pre-select all values when no existing filter (so user unchecks to exclude)
      if (preselectAll) {
        setFdSelected(new Set(vals.map((v) => v.val)));
      } else if (searchText) {
        // When searching, trim selection to only visible values so Apply works correctly
        const visible = new Set(vals.map((v) => v.val));
        setFdSelected((prev) => new Set([...prev].filter((v) => visible.has(v))));
      }
    } catch { setFdValues([]); }
    setFdLoading(false);
  }, [tle]);

  useEffect(() => {
    if (!filterDropdown) { setFdValues([]); setFdSearch(""); setFdSelected(new Set()); setFdRegex(false); return; }
    if (filterDropdown.colName === "__tags__") {
      // Tags filter — load tags from DB
      const existing = ct?.tagFilter;
      // Handle both array tagFilter (checkbox selection) and string tagFilter ("Show Only IOC Matches" button)
      const hasExisting = existing && (Array.isArray(existing) ? existing.length > 0 : typeof existing === "string");
      const existingSet = hasExisting
        ? new Set(Array.isArray(existing) ? existing : [existing])
        : new Set();
      setFdSelected(existingSet);
      setFdSearch("");
      setFdRegex(false);
      (async () => {
        setFdLoading(true);
        const tags = await tle.getAllTags(ct.id);
        const vals = (tags || []).map((t) => ({ val: t.tag, cnt: t.cnt }));
        setFdValues(vals);
        setFdLoading(false);
      })().catch(() => { setFdLoading(false); });
      return;
    }
    const existing = ct?.checkboxFilters?.[filterDropdown.colName];
    const hasExisting = existing?.length > 0;
    setFdSelected(hasExisting ? new Set(existing) : new Set());
    setFdSearch("");
    setFdRegex(false);
    loadFilterValues(filterDropdown.colName, "", !hasExisting, false);
  }, [filterDropdown?.colName]);

  useEffect(() => {
    if (!filterDropdown) return;
    if (filterDropdown.colName === "__tags__") return; // Tags don't support search-while-typing
    const t = setTimeout(() => loadFilterValues(filterDropdown.colName, fdSearch, false, fdRegex), 300);
    return () => clearTimeout(t);
  }, [fdSearch, fdRegex]);

  const applyCheckboxFilter = () => {
    if (!filterDropdown) return;
    const colName = filterDropdown.colName;
    // Tags filter — apply as tagFilter array
    // Unlike regular columns, "all tags selected" still means "show only tagged rows" (not all rows)
    if (colName === "__tags__") {
      setTabs((prev) => prev.map((t) => {
        if (t.id !== activeTab) return t;
        if (fdSelected.size === 0) return { ...t, tagFilter: null };
        return { ...t, tagFilter: [...fdSelected] };
      }));
      setFilterDropdown(null);
      return;
    }
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const newCbf = { ...t.checkboxFilters };
      // "All selected = no filter" only when NOT searching (search narrows the list, so all-checked means the user wants only those values)
      if (fdSelected.size === 0 || (!fdSearch && fdSelected.size === fdValues.length)) delete newCbf[colName];
      else newCbf[colName] = [...fdSelected];
      return { ...t, checkboxFilters: newCbf };
    }));
    setFilterDropdown(null);
  };

  // ── Keyboard shortcuts ───────────────────────────────────────────
  useEffect(() => {
    const h = (e) => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key === "w") { e.preventDefault(); const cur = ctRef.current; if (cur) closeTab(cur.id); return; }
      if (mod && e.key === "s") { e.preventDefault(); handleSaveSession(); }
      if (mod && e.shiftKey && e.key === "O") { e.preventDefault(); handleLoadSession(); }
      if (mod && e.key === "o") { e.preventDefault(); tle?.openFileDialog(); }
      if (mod && e.key === "f" && !e.shiftKey) { e.preventDefault(); document.getElementById("gs")?.focus(); }
      if (mod && e.shiftKey && e.key === "f") { e.preventDefault(); setModal({ type: "crossfind" }); }
      if (mod && e.key === "e") { e.preventDefault(); handleExport(); }
      if (mod && e.key === "b") { e.preventDefault(); if (ct) up("showBookmarkedOnly", !ct.showBookmarkedOnly); }
      if (mod && e.key === "r") { e.preventDefault(); resetColumnWidths(); }
      if (mod && e.key === "c" && selectedRows.size > 0 && ct && !isGrouped) {
        e.preventDefault();
        const hdrs = ct.headers.filter((h) => !ct.hiddenColumns?.has(h));
        const sortedIndices = [...selectedRows].sort((a, b) => a - b);
        const lines = [hdrs.join("\t")];
        for (const idx of sortedIndices) {
          const r = getRowAt(idx);
          if (r) lines.push(hdrs.map((h) => (r[h] || "").replace(/\t/g, " ")).join("\t"));
        }
        navigator.clipboard?.writeText(lines.join("\n"));
        setCopiedMsg(true);
        setTimeout(() => setCopiedMsg(false), 1200);
      }
      if (e.key === "Escape") {
        if (cellPopup) { setCellPopup(null); return; }
        if (modal) { setModal(null); return; }
        if (filterDropdown) { setFilterDropdown(null); return; }
        if (dateRangeDropdown) { setDateRangeDropdown(null); return; }
        if (contextMenu) { setContextMenu(null); return; }
        if (rowContextMenu) { setRowContextMenu(null); return; }
        if (detailPanelOpen && selectedRows.size > 0) { setDetailPanelOpen(false); return; }
        if (selectedRows.size > 0) { setSelectedRows(new Set()); setLastClickedRow(null); return; }
      }
      // Open context menu for selected row (Shift+F10 = standard context menu key)
      if (e.key === "F10" && e.shiftKey && lastClickedRow !== null && ct) {
        e.preventDefault();
        const item = getRowAt(lastClickedRow);
        const row = isGrouped ? (item?.data || item) : item;
        if (row && row.__idx) {
          const rTags = (ct.rowTags || {})[row.__idx] || [];
          // Position near the selected row using the scroll container
          const scrollEl = scrollRef.current;
          const rect = scrollEl ? scrollEl.getBoundingClientRect() : { left: 200, top: 200 };
          const yPos = rect.top + (lastClickedRow * ROW_HEIGHT) - (scrollEl ? scrollEl.scrollTop : 0) + HEADER_HEIGHT + FILTER_HEIGHT + ROW_HEIGHT / 2;
          setRowContextMenu({ x: rect.left + 100, y: Math.min(Math.max(yPos, rect.top + 40), window.innerHeight - 300), rowId: row.__idx, rowIndex: lastClickedRow, currentTags: rTags, row });
        }
      }
      // Find next/prev: Ctrl+Right/Left or F3/Shift+F3
      if ((mod && e.key === "ArrowRight") || (e.key === "F3" && !e.shiftKey)) { e.preventDefault(); navigateSearch(1); }
      if ((mod && e.key === "ArrowLeft") || (e.key === "F3" && e.shiftKey)) { e.preventDefault(); navigateSearch(-1); }
      if (!isGrouped && e.key === "ArrowDown" && lastClickedRow !== null && !mod) {
        e.preventDefault();
        const total = ct?.totalFiltered || rows.length;
        const next = Math.min(total - 1, lastClickedRow + 1);
        setSelectedRows(new Set([next])); setLastClickedRow(next); setDetailPanelOpen(true);
        scrollToRow(next);
      }
      if (!isGrouped && e.key === "ArrowUp" && lastClickedRow !== null && !mod) {
        e.preventDefault();
        const next = Math.max(0, lastClickedRow - 1);
        setSelectedRows(new Set([next])); setLastClickedRow(next); setDetailPanelOpen(true);
        scrollToRow(next);
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [ct, activeTab, selectedRows, lastClickedRow, ct?.totalFiltered, isGrouped, getRowAt, searchMatchIdx, navigateSearch]);


  // ── Modals ───────────────────────────────────────────────────────
  const Overlay = ({ children }) => (
    <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
      <div style={{ background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 24, width: 480, maxWidth: "92vw", maxHeight: "80vh", overflow: "auto", boxShadow: "0 24px 48px rgba(0,0,0,0.5)", WebkitAppRegion: "no-drag" }}>
        {children}
      </div>
    </div>
  );

  const ColorModal = () => {
    const [col, setCol] = useState(ct?.headers[0] || "");
    const [cond, setCond] = useState("contains");
    const [val, setVal] = useState("");
    const [bg, setBg] = useState("#7f1d1d");
    const [fg, setFg] = useState("#fca5a5");
    return (
      <Overlay>
        <h3 style={ms.mh}>Conditional Formatting</h3>
        <div style={ms.fg}><label style={ms.lb}>Column</label>
          <select value={col} onChange={(e) => setCol(e.target.value)} style={ms.sl}>
            {ct.headers.map((h) => <option key={h} value={h}>{h}</option>)}</select></div>
        <div style={ms.fg}><label style={ms.lb}>Condition</label>
          <select value={cond} onChange={(e) => setCond(e.target.value)} style={ms.sl}>
            <option value="contains">Contains</option><option value="equals">Equals</option>
            <option value="startswith">Starts With</option><option value="regex">Regex</option></select></div>
        <div style={ms.fg}><label style={ms.lb}>Value</label>
          <input value={val} onChange={(e) => setVal(e.target.value)} style={ms.ip} placeholder="e.g. powershell.exe" /></div>
        <div style={{ display: "flex", gap: 16 }}>
          <div style={ms.fg}><label style={ms.lb}>Background</label>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <input type="color" value={bg} onChange={(e) => setBg(e.target.value)} style={{ width: 32, height: 24, border: "none", cursor: "pointer", borderRadius: 4 }} />
              <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "monospace" }}>{bg}</span></div></div>
          <div style={ms.fg}><label style={ms.lb}>Text Color</label>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <input type="color" value={fg} onChange={(e) => setFg(e.target.value)} style={{ width: 32, height: 24, border: "none", cursor: "pointer", borderRadius: 4 }} />
              <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "monospace" }}>{fg}</span></div></div>
        </div>
        <div style={{ marginTop: 8 }}><label style={ms.lb}>DFIR Presets</label>
          <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 4 }}>
            {PRESETS.map((p, i) => <button key={i} onClick={() => { setCol(ct.headers.includes(p.column) ? p.column : ct.headers[0]); setCond(p.condition); setVal(p.value); setBg(p.bgColor); setFg(p.fgColor); }}
              style={{ padding: "3px 8px", background: p.bgColor, color: p.fgColor, border: "1px solid rgba(255,255,255,0.1)", borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "inherit" }}>{p.label}</button>)}
          </div></div>
        {ct.colorRules.length > 0 && <div style={{ marginTop: 12 }}><label style={ms.lb}>Active ({ct.colorRules.length})</label>
          <div style={{ maxHeight: 100, overflow: "auto", marginTop: 4 }}>
            {ct.colorRules.map((r, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 0", borderBottom: `1px solid ${th.border}` }}>
                <div style={{ width: 12, height: 12, borderRadius: 3, background: r.bgColor, flexShrink: 0 }} />
                <span style={{ color: th.textDim, fontSize: 11, flex: 1 }}>{r.column} {r.condition} "{r.value}"</span>
                <button onClick={() => up("colorRules", ct.colorRules.filter((_, j) => j !== i))} style={{ background: "none", border: "none", color: th.danger, cursor: "pointer", fontSize: 12 }}>✕</button>
              </div>))}
          </div></div>}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
          <button onClick={() => up("colorRules", [])} style={ms.bs}>Clear All</button>
          <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
          <button disabled={!val} onClick={() => { up("colorRules", [...ct.colorRules, { column: col, condition: cond, value: val, bgColor: bg, fgColor: fg }]); setModal(null); }} style={ms.bp}>Add Rule</button>
        </div>
      </Overlay>
    );
  };

  const ColModal = () => (
    <Overlay>
      <h3 style={ms.mh}>Column Manager</h3>
      <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
        <button onClick={() => up("hiddenColumns", new Set())} style={ms.bsm}>Show All</button>
        <button onClick={() => up("hiddenColumns", new Set(ct.headers))} style={ms.bsm}>Hide All</button>
      </div>
      <div style={{ maxHeight: "55vh", overflow: "auto" }}>
        {ct.headers.map((h) => (
          <label key={h} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0", cursor: "pointer", borderBottom: `1px solid ${th.bgAlt}`, color: th.text, fontSize: 12 }}>
            <input type="checkbox" checked={!ct.hiddenColumns.has(h)} onChange={() => { const s = new Set(ct.hiddenColumns); s.has(h) ? s.delete(h) : s.add(h); up("hiddenColumns", s); }} style={{ accentColor: th.borderAccent }} />
            <span style={{ flex: 1 }}>{h}</span>
            {ct.tsColumns.has(h) && <span style={{ fontSize: 10, color: th.accent }}>⏱</span>}
            {ct.numericColumns?.has(h) && <span style={{ fontSize: 10, color: th.success }}>#</span>}
            {(ct.pinnedColumns || []).includes(h) && <span style={{ fontSize: 10, color: th.warning }}>📌</span>}
          </label>
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
        <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
      </div>
    </Overlay>
  );

  const ShortModal = () => (
    <Overlay>
      <h3 style={ms.mh}>Shortcuts & Search Syntax</h3>
      {[["⌘ O", "Open file"], ["⌘ S", "Save session"], ["⌘⇧O", "Open session"], ["⌘ F", "Focus search"], ["⌘ E", "Export"], ["⌘ B", "Toggle bookmarks"], ["⌘⇧F", "Find in all tabs"], ["⌘ C", "Copy selected rows"], ["↑ / ↓", "Navigate rows"], ["Shift+Click", "Select range"], ["⌘+Click", "Context menu (Copy / Tags)"], ["⌃+Click", "Context menu (alt)"], ["⇧F10", "Context menu (keyboard)"], ["F3 / ⌘→", "Next search match"], ["⇧F3 / ⌘←", "Previous search match"], ["⌘ R", "Reset column widths"], ["FL / HL", "Toggle filter/highlight search mode"], ["A −/+", "Adjust font size"], ["⏱ icon", "Date range filter (timestamp cols)"], ["Dbl-click", "Cell detail popup"], ["Dbl-click border", "Auto-fit column"], ["Drag header", "Group by column"], ["Esc", "Close panel/modal"]].map(([k, d]) => (
        <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", borderBottom: `1px solid ${th.bgAlt}` }}>
          <kbd style={{ background: th.btnBg, color: th.accent, padding: "2px 7px", borderRadius: 4, fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace", border: `1px solid ${th.btnBorder}` }}>{k}</kbd>
          <span style={{ color: th.textDim, fontSize: 12 }}>{d}</span>
        </div>
      ))}
      <h4 style={{ color: th.text, fontSize: 12, marginTop: 12, marginBottom: 6 }}>Mixed Search Syntax</h4>
      {[["word1 word2", "OR"], ["+word", "AND (must include)"], ["-word", "EXCLUDE"], ['"exact phrase"', "Phrase"], ["Column:value", "Column filter"]].map(([s, d]) => (
        <div key={s} style={{ fontSize: 12, color: th.textDim, padding: "2px 0" }}>
          <code style={{ background: th.btnBg, padding: "1px 5px", borderRadius: 3, color: th.accent }}>{s}</code> — {d}
        </div>
      ))}
      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
        <button onClick={() => setModal(null)} style={ms.bp}>Close</button>
      </div>
    </Overlay>
  );

  const SheetModal = () => {
    const data = modal;
    return (
      <Overlay>
        <h3 style={ms.mh}>Select Sheet — {data.fileName}</h3>
        <p style={{ color: th.textDim, fontSize: 12, marginBottom: 12 }}>This workbook has multiple sheets:</p>
        {data.sheets.map((s) => (
          <button key={s.id} onClick={() => { tle.selectSheet({ filePath: data.filePath, tabId: data.tabId, fileName: `${data.fileName} [${s.name}]`, sheetName: s.name }); setModal(null); }}
            style={{ display: "block", width: "100%", textAlign: "left", padding: "10px 14px", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 13, cursor: "pointer", marginBottom: 6, fontFamily: "inherit" }}>
            {s.name} <span style={{ color: th.textMuted, fontSize: 11 }}>({s.rowCount} rows)</span>
          </button>
        ))}
        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 12 }}>
          <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
        </div>
      </Overlay>
    );
  };

  const ImportProgress = ({ info }) => {
    const queueLen = importQueue.length;
    return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", padding: 40 }}>
      {/* Logo + tagline */}
      <svg width="48" height="54" viewBox="0 0 64 72" fill="none" style={{ marginBottom: 12, opacity: 0.85 }}>
        <path d="M32 4L6 16v20c0 16.5 11.2 31.2 26 36 14.8-4.8 26-19.5 26-36V16L32 4z" fill={`${th.accent}18`} stroke={th.accent} strokeWidth="1.8" strokeLinejoin="round" />
        <polyline points="14,40 22,40 25,28 29,48 33,22 37,44 40,34 42,40 50,40" fill="none" stroke={th.accent} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="32" cy="20" r="6" fill="none" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
        <line x1="32" y1="15.5" x2="32" y2="17" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
        <line x1="32" y1="23" x2="32" y2="24.5" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
        <line x1="27.5" y1="20" x2="29" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
        <line x1="35" y1="20" x2="36.5" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
        <line x1="32" y1="20" x2="32" y2="17.5" stroke={th.accent} strokeWidth="1.2" opacity="0.7" strokeLinecap="round" />
        <line x1="32" y1="20" x2="34.5" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.7" strokeLinecap="round" />
      </svg>
      <div style={{ fontSize: 18, fontWeight: 700, color: th.text, fontFamily: "-apple-system, 'SF Pro Display', sans-serif", marginBottom: 2 }}>IRFlow <span style={{ color: th.accent }}>Timeline</span></div>
      <p style={{ color: th.textMuted, fontSize: 12, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 28, fontFamily: "-apple-system, sans-serif" }}>DFIR Timeline Analysis for macOS</p>
      {/* Progress */}
      <div style={{ width: 400, maxWidth: "100%" }}>
        <h3 style={{ color: th.text, fontSize: 16, marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>
          {info.status === "indexing" ? "Finalizing..." : "Importing..."}
        </h3>
        <p style={{ color: th.textDim, fontSize: 13, marginBottom: 16 }}>{info.fileName}</p>
        <div style={{ height: 6, background: th.border, borderRadius: 3, overflow: "hidden", marginBottom: 12 }}>
          <div style={{ height: "100%", width: "100%", background: info.status === "indexing" ? th.warning : th.borderAccent, borderRadius: 3, transformOrigin: "left", transform: `scaleX(${Math.min((info.percent || 0) / 100, 1)})`, transition: "transform 0.3s" }} />
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", color: th.textDim, fontSize: 12 }}>
          <span>{formatNumber(info.rowsImported || 0)} rows imported</span>
          <span>{info.percent || 0}%</span>
        </div>
        {info.fileSize > 3 * 1024 * 1024 * 1024 && (
          <div style={{ marginTop: 16, padding: "10px 14px", background: (th.warning || "#d29922") + "15", border: `1px solid ${(th.warning || "#d29922")}44`, borderRadius: 8, color: th.warning || "#d29922", fontSize: 11, lineHeight: 1.5, fontFamily: "-apple-system, sans-serif" }}>
            <strong>Large file detected ({(info.fileSize / (1024 * 1024 * 1024)).toFixed(1)} GB)</strong> — This may take several minutes. Do not close this window or import additional files until ingestion is complete.
          </div>
        )}
        {queueLen > 0 && (
          <div style={{ marginTop: 20, padding: "12px 14px", background: `${th.accent}08`, border: `1px solid ${th.border}44`, borderRadius: 8 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>
              Queued ({queueLen} file{queueLen > 1 ? "s" : ""} waiting)
            </div>
            {importQueue.map((q, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>
                <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "SF Mono, monospace", minWidth: 16 }}>{i + 1}.</span>
                <span style={{ color: th.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{q.fileName}</span>
                <span style={{ color: th.textDim, fontSize: 10, fontFamily: "SF Mono, monospace", flexShrink: 0 }}>{q.fileSize > 1048576 ? `${(q.fileSize / 1048576).toFixed(1)} MB` : q.fileSize > 1024 ? `${(q.fileSize / 1024).toFixed(0)} KB` : `${q.fileSize} B`}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
    );
  };

  // ── Helper: compute row background ───────────────────────────────
  const getRowBg = (ai, _row, sel, cm, bm) => {
    if (sel) return th.selection;
    if (cm) return cm.bg;
    if (bm) return th.bookmark;
    return ai % 2 === 0 ? th.rowEven : th.rowOdd;
  };

  // ── Themed style constants ───────────────────────────────────────
  const Sdiv = () => <span style={{ width: 1, height: 12, background: th.border, display: "inline-block" }} />;
  const tb = { display: "flex", alignItems: "center", gap: 5, padding: "5px 10px", background: "transparent", color: th.textDim, border: "none", borderRadius: 5, fontSize: 13, fontWeight: 500, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" };
  const tdv = { width: 1, height: 20, background: th.border, margin: "0 4px", display: "inline-block" };
  const ms = {
    mh: { margin: "0 0 14px", fontSize: 16, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" },
    fg: { marginBottom: 10 },
    lb: { display: "block", fontSize: 10, color: th.textDim, marginBottom: 3, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" },
    sl: { width: "100%", padding: "6px 8px", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, outline: "none", fontFamily: "inherit" },
    ip: { width: "100%", padding: "6px 8px", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, outline: "none", fontFamily: "inherit", boxSizing: "border-box" },
    bp: { padding: "6px 16px", background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 6, fontSize: 12, fontWeight: 500, cursor: "pointer", fontFamily: "-apple-system,sans-serif" },
    bs: { padding: "6px 16px", background: th.btnBg, color: th.text, border: `1px solid ${th.btnBorder}`, borderRadius: 6, fontSize: 12, cursor: "pointer", fontFamily: "-apple-system,sans-serif" },
    bsm: { padding: "3px 8px", background: th.btnBg, color: th.text, border: `1px solid ${th.btnBorder}`, borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system,sans-serif" },
  };

  // ── Empty state ──────────────────────────────────────────────────
  if (tabs.length === 0) {
    return (
      <div onContextMenu={(e) => e.preventDefault()} style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: th.bg, fontFamily: "'SF Mono',Menlo,monospace", WebkitAppRegion: "drag" }}
        onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => { e.preventDefault(); setDragOver(false); const files = [...e.dataTransfer.files]; if (files.length > 0 && tle) { const paths = files.map((f) => tle.getPathForFile(f)).filter(Boolean); if (paths.length > 0) tle.importFiles(paths); } }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "80px 120px", minWidth: 600, border: `2px dashed ${dragOver ? th.borderAccent : th.border}`, borderRadius: 20, transition: "all 0.2s", background: dragOver ? th.selection : "transparent" }}>
          {/* IRFlow Logo — shield with timeline pulse */}
          <svg width="88" height="100" viewBox="0 0 64 72" fill="none" style={{ marginBottom: 24 }}>
            {/* Shield body */}
            <path d="M32 4L6 16v20c0 16.5 11.2 31.2 26 36 14.8-4.8 26-19.5 26-36V16L32 4z" fill={`${th.accent}18`} stroke={th.accent} strokeWidth="1.8" strokeLinejoin="round" />
            {/* Timeline pulse across shield */}
            <polyline points="14,40 22,40 25,28 29,48 33,22 37,44 40,34 42,40 50,40" fill="none" stroke={th.accent} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
            {/* Clock tick marks at top of shield */}
            <circle cx="32" cy="20" r="6" fill="none" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="32" y1="15.5" x2="32" y2="17" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="32" y1="23" x2="32" y2="24.5" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="27.5" y1="20" x2="29" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            <line x1="35" y1="20" x2="36.5" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.5" />
            {/* Clock hands */}
            <line x1="32" y1="20" x2="32" y2="17.5" stroke={th.accent} strokeWidth="1.2" opacity="0.7" strokeLinecap="round" />
            <line x1="32" y1="20" x2="34.5" y2="20" stroke={th.accent} strokeWidth="1.2" opacity="0.7" strokeLinecap="round" />
          </svg>
          <h1 style={{ fontSize: 34, fontWeight: 700, color: th.text, margin: 0, fontFamily: "-apple-system, 'SF Pro Display', sans-serif" }}>IRFlow <span style={{ color: th.accent }}>Timeline</span></h1>
          <p style={{ color: th.textDim, fontSize: 14, letterSpacing: "0.14em", textTransform: "uppercase", margin: "10px 0 6px", fontWeight: 600 }}>DFIR Timeline Analysis for macOS</p>
          <p style={{ color: th.textMuted, fontSize: 12, margin: "0 0 32px" }}>SQLite-backed · Handles large files for timeline analysis · CSV / TSV / XLSX / EVTX / Plaso</p>
          <button onClick={() => tle?.openFileDialog()} style={{ padding: "14px 48px", background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 8, fontSize: 16, fontWeight: 600, cursor: "pointer", fontFamily: "-apple-system, sans-serif", WebkitAppRegion: "no-drag" }}>Open File</button>
          <p style={{ color: th.textMuted, fontSize: 12, marginTop: 28 }}>⌘O open · ⌘F search · ⌘B bookmarks · ⌘E export</p>
          <p style={{ color: th.textMuted, fontSize: 11, marginTop: 28, fontFamily: "-apple-system, sans-serif" }}>Created by <span style={{ color: th.textDim }}>Renzon Cruz</span> | <span style={{ color: th.accent }}>@r3nzsec</span></p>
        </div>
      </div>
    );
  }

  // ── Main render ──────────────────────────────────────────────────
  const isImporting = ct?.importing && importingTabs[ct?.id];
  const activeCheckboxCount = ct ? Object.keys(ct.checkboxFilters || {}).filter(k => ct.checkboxFilters[k]?.length > 0).length : 0;
  const activeColumnFilterCount = ct ? Object.values(ct.columnFilters || {}).filter(Boolean).length : 0;
  const activeDateFilterCount = ct ? Object.keys(ct.dateRangeFilters || {}).length : 0;
  const activeAdvFilterCount = ct?.advancedFilters?.length || 0;
  const hasSearch = ct?.searchTerm?.trim() && !ct?.searchHighlight;
  const hasBookmarkFilter = !!ct?.showBookmarkedOnly;
  const hasTagFilter = !!ct?.tagFilter;
  const totalActiveFilters = activeCheckboxCount + activeColumnFilterCount + activeDateFilterCount + activeAdvFilterCount + (hasSearch ? 1 : 0) + (hasBookmarkFilter ? 1 : 0) + (hasTagFilter ? 1 : 0);
  const clearAllFilters = () => {
    setTabs((prev) => prev.map((t) => t.id !== ct.id ? t : {
      ...t, searchTerm: "", columnFilters: {}, checkboxFilters: {},
      dateRangeFilters: {}, advancedFilters: [], showBookmarkedOnly: false,
      tagFilter: null, searchHighlight: false, disabledFilters: new Set(),
    }));
  };

  return (
    <div onContextMenu={(e) => e.preventDefault()}
      onDragOver={(e) => { if (!e.dataTransfer.types.includes("Files")) return; e.preventDefault(); e.dataTransfer.dropEffect = "copy"; setDragOver(true); }}
      onDragLeave={(e) => { if (e.currentTarget.contains(e.relatedTarget)) return; setDragOver(false); }}
      onDrop={(e) => { if (!e.dataTransfer.types.includes("Files")) return; e.preventDefault(); setDragOver(false); const files = [...e.dataTransfer.files]; if (files.length > 0 && tle) { const paths = files.map((f) => tle.getPathForFile(f)).filter(Boolean); if (paths.length > 0) tle.importFiles(paths); } }}
      style={{ display: "flex", flexDirection: "column", height: "100vh", background: th.bg, color: th.text, fontFamily: "'SF Mono','Fira Code',Menlo,monospace", fontSize: fontSize, overflow: "hidden" }}>
      <style>{`
        @keyframes tle-spin { to { transform: rotate(360deg) } }
        @keyframes tle-pulse { 0%,100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.6; transform: scale(0.95); } }
        ::-webkit-scrollbar { width: 14px; height: 14px; }
        ::-webkit-scrollbar-track { background: ${th.bg}; }
        ::-webkit-scrollbar-thumb { background: ${th.textMuted}; border-radius: 7px; border: 3px solid ${th.bg}; }
        ::-webkit-scrollbar-thumb:hover { background: ${th.textDim}; }
        ::-webkit-scrollbar-corner { background: ${th.bg}; }
      `}</style>

      {/* Drop overlay — shown when dragging files over the app */}
      {dragOver && (
        <div style={{ position: "fixed", inset: 0, zIndex: 9999, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", pointerEvents: "none" }}>
          <div style={{ padding: "40px 60px", border: `3px dashed ${th.accent}`, borderRadius: 16, background: `${th.bg}DD`, textAlign: "center" }}>
            <div style={{ fontSize: 32, marginBottom: 8 }}>+</div>
            <div style={{ color: th.accent, fontSize: 16, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Drop files to import</div>
            <div style={{ color: th.textMuted, fontSize: 11, marginTop: 4, fontFamily: "-apple-system, sans-serif" }}>CSV, TSV, XLSX, EVTX, Plaso</div>
          </div>
        </div>
      )}

      {/* Toolbar — draggable title bar region */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "4px 10px 4px 84px", background: th.bgAlt, borderBottom: `1px solid ${th.border}`, gap: 8, flexShrink: 0, WebkitAppRegion: "drag" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 2, WebkitAppRegion: "no-drag" }}>
          <button onClick={() => tle?.openFileDialog()} style={tb}>Open</button>
          <button onClick={handleExport} style={tb}>Export</button>
          <div style={tdv} />
          <button onClick={() => ct && up("showBookmarkedOnly", !ct.showBookmarkedOnly)} style={{ ...tb, color: ct?.showBookmarkedOnly ? th.warning : th.textDim }}>{ct?.showBookmarkedOnly ? "★" : "☆"} Flagged</button>
          <button onClick={() => { if (ct?.dataReady) setModal({ type: "bulkActions", tagName: "", tagColor: "#E85D2A", result: null }); }} style={{ ...tb, opacity: ct?.dataReady ? 1 : 0.4 }} disabled={!ct?.dataReady}>Bulk Actions</button>
          <div style={{ position: "relative" }}>
            <button onClick={() => setToolsOpen((v) => !v)} style={{ ...tb, color: toolsOpen ? th.accent : th.textDim }}>Tools ▾</button>
            {toolsOpen && (<>
              <div onClick={() => setToolsOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 149 }} />
              <div style={{ position: "absolute", top: "100%", left: 0, marginTop: 4, background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 10, padding: "6px 0", zIndex: 150, boxShadow: `0 12px 40px rgba(0,0,0,0.5), 0 0 0 1px ${th.border}33`, minWidth: 240, whiteSpace: "nowrap" }}>
                {(() => {
                  const ic = (d, color) => <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke={color || th.accent} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>{d}</svg>;
                  const items = [
                    { section: "View" },
                    { label: "Columns", icon: ic(<><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>), action: () => setModal({ type: "columns" }) },
                    { label: "Color Rules", icon: ic(<><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18" fill={th.accent} opacity="0.3"/></>), action: () => setModal({ type: "colors" }) },
                    { label: "Tags", icon: ic(<><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><circle cx="7" cy="7" r="1" fill={th.accent}/></>), action: () => setModal({ type: "tags" }) },
                    { label: "Filter Presets", icon: ic(<><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></>), action: () => setModal({ type: "presets" }) },
                    { label: "Edit Filter", icon: ic(<><rect x="3" y="4" width="18" height="16" rx="2" fill="none"/><line x1="7" y1="9" x2="17" y2="9"/><line x1="7" y1="13" x2="14" y2="13"/><line x1="7" y1="17" x2="11" y2="17"/></>), action: () => {
                      if (ct?.dataReady) setModal({ type: "editFilter" });
                    }, disabled: !ct?.dataReady },
                    { label: "Merge Tabs", icon: ic(<><rect x="4" y="4" width="16" height="6" rx="1"/><rect x="4" y="14" width="16" height="6" rx="1"/><line x1="12" y1="10" x2="12" y2="14" strokeDasharray="2,1"/></>), action: () => {
                      const ready = tabs.filter((t) => t.dataReady && !t.importing);
                      if (ready.length < 2) return;
                      setModal({ type: "mergeTabs", tabOptions: ready.map((t) => ({
                        tabId: t.id, tabName: t.name, rowCount: t.totalRows,
                        tsColumns: [...(t.tsColumns || new Set())],
                        selectedTsCol: [...(t.tsColumns || new Set())][0] || "",
                        checked: true,
                      }))});
                    }, disabled: tabs.filter((t) => t.dataReady && !t.importing).length < 2 },
                    { section: "Analysis" },
                    { label: "Stack Values", icon: ic(<><line x1="4" y1="6" x2="16" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="12" y2="18"/></>), action: () => {
                      if (!ct?.headers?.length) return;
                      const colName = ct.sortCol || ct.headers[0];
                      setModal({ type: "stacking", colName, data: null, loading: true, filterText: "", sortBy: "count" });
                      const af = activeFilters(ct);
                      tle.getStackingData(ct.id, colName, {
                        searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
                        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
                        bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
                        sortBy: "count",
                      }).then((result) => setModal((p) => p?.type === "stacking" ? { ...p, data: result, loading: false } : p))
                        .catch(() => setModal((p) => p?.type === "stacking" ? { ...p, loading: false, data: { entries: [], totalUnique: 0, totalRows: 0 } } : p));
                    }},
                    { label: "IOC Matching", icon: ic(<><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></>, th.warning), action: () => { if (ct?.dataReady) setModal({ type: "ioc", phase: "load", iocText: "", iocName: "", parsedIocs: [], fileName: null }); }, disabled: !ct?.dataReady },
                    { label: "Gap Analysis", icon: ic(<><circle cx="12" cy="12" r="9"/><polyline points="12 6 12 12 16 14"/></>, th.textDim), action: () => { if (ct?.dataReady && ct?.tsColumns?.size) setModal({ type: "gapAnalysis", phase: "config", colName: [...ct.tsColumns][0], gapThreshold: 60, data: null, loading: false }); }, disabled: !ct?.dataReady || !ct?.tsColumns?.size },
                    { label: "Log Sources", icon: ic(<><rect x="2" y="3" width="20" height="4" rx="1"/><rect x="2" y="10" width="20" height="4" rx="1"/><rect x="2" y="17" width="20" height="4" rx="1"/><circle cx="18" cy="5" r="1" fill={th.accent}/><circle cx="14" cy="12" r="1" fill={th.accent}/><circle cx="18" cy="19" r="1" fill={th.accent}/></>), action: () => {
                      if (!ct?.dataReady) return;
                      const sourcePatterns = /^(Provider|Channel|source|data_type|parser|log_source|EventLog|SourceName|Source|_Source|DataType|ArtifactName|sourcetype|SourceLong|SourceDescription)$/i;
                      const sourceCols = ct.headers.filter((h) => sourcePatterns.test(h));
                      const defaultSourceCol = sourceCols.length > 0 ? sourceCols[0] : ct.headers.find((h) => !ct.tsColumns?.has(h)) || ct.headers[0];
                      const defaultTsCol = ct.tsColumns?.size ? [...ct.tsColumns][0] : null;
                      if (!defaultTsCol) return;
                      setModal({ type: "logSourceCoverage", phase: "config", sourceCol: defaultSourceCol, tsCol: defaultTsCol, sourceCols, data: null, loading: false });
                    }, disabled: !ct?.dataReady || !ct?.tsColumns?.size },
                    { label: "Burst Detection", icon: ic(<><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" fill={th.accent+"33"}/></>, th.danger || "#f85149"), action: () => {
                      if (ct?.dataReady && ct?.tsColumns?.size) setModal({ type: "burstAnalysis", phase: "config", colName: [...ct.tsColumns][0], windowMinutes: 5, thresholdMultiplier: 5, data: null, loading: false });
                    }, disabled: !ct?.dataReady || !ct?.tsColumns?.size },
                    { label: "Process Inspector", icon: ic(<><circle cx="10" cy="10" r="6" fill={(th.accent||"#E85D2A")+"14"} stroke={th.accent||"#E85D2A"} strokeWidth="1.5"/><line x1="14.5" y1="14.5" x2="20" y2="20" stroke={th.accent||"#E85D2A"} strokeWidth="2" strokeLinecap="round"/><path d="M8 8v4M8 10h4" stroke={th.accent||"#E85D2A"} strokeWidth="1.5" strokeLinecap="round"/></>, th.accent || "#E85D2A"), action: () => {
                      if (!ct?.dataReady) return;
                      const det = (pats) => { for (const p of pats) { const f = ct.headers.find((h) => p.test(h)); if (f) return f; } return null; };
                      const isEvtxECmdPT = ct.headers.some((h) => /^PayloadData1$/i.test(h)) && ct.headers.some((h) => /^ExecutableInfo$/i.test(h));
                      // Security 4688: ProcessId = parent PID, NewProcessId = child PID (opposite of Sysmon)
                      const isSec4688 = !isEvtxECmdPT && ct.headers.some((h) => /^NewProcess(Name|Id)$/i.test(h));
                      const cols = isEvtxECmdPT ? {
                        // EvtxECmd: CSV ProcessId is the logging service PID, NOT the created process PID
                        pid: det([/^PayloadData1$/i]),
                        ppid: det([/^PayloadData5$/i]),
                        guid: det([/^PayloadData1$/i]),       // GUID parsed from same field in post-processing
                        parentGuid: det([/^PayloadData5$/i]), // parent GUID parsed from same field
                        image: det([/^ExecutableInfo$/i]),     // image extracted from command line
                        cmdLine: det([/^ExecutableInfo$/i]),
                        user: det([/^UserName$/i, /^User$/i]),
                        ts: det([/^TimeCreated$/i, /^datetime$/i]),
                        eventId: det([/^EventId$/i, /^EventID$/i]),
                        provider: det([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
                      } : isSec4688 ? (() => {
                        // Security 4688: ProcessId is the PARENT, NewProcessId is the CHILD
                        const hasNewPid = ct.headers.some((h) => /^NewProcessId$/i.test(h));
                        return {
                        pid: hasNewPid ? det([/^NewProcessId$/i]) : det([/^ProcessId$/i]),
                        ppid: hasNewPid ? det([/^ProcessId$/i, /^CreatorProcessId$/i]) : det([/^CreatorProcessId$/i]),
                        guid: det([/^ProcessGuid$/i, /^process_guid$/i]),
                        parentGuid: det([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
                        image: det([/^NewProcessName$/i, /^Image$/i]),
                        parentImage: det([/^ParentProcessName$/i, /^ParentImage$/i]),
                        cmdLine: det([/^CommandLine$/i, /^command_line$/i, /^cmdline$/i, /^ProcessCommandLine$/i]),
                        user: det([/^TargetUserName$/i, /^User$/i, /^UserName$/i]),
                        ts: det([/^datetime$/i, /^TimeCreated$/i, /^UtcTime$/i]),
                        eventId: det([/^EventID$/i, /^event_id$/i, /^EventId$/]),
                        elevation: det([/^TokenElevationType$/i]),
                        integrity: det([/^MandatoryLabel$/i, /^IntegrityLevel$/i]),
                        provider: det([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
                      }; })() : {
                        pid: det([/^ProcessId$/i, /^pid$/i, /^process_id$/i, /^NewProcessId$/i]),
                        ppid: det([/^ParentProcessId$/i, /^ppid$/i, /^parent_process_id$/i, /^CreatorProcessId$/i]),
                        guid: det([/^ProcessGuid$/i, /^process_guid$/i]),
                        parentGuid: det([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
                        image: det([/^Image$/i, /^process_name$/i, /^exe$/i, /^NewProcessName$/i]),
                        parentImage: det([/^ParentImage$/i, /^ParentProcessName$/i]),
                        cmdLine: det([/^CommandLine$/i, /^command_line$/i, /^cmdline$/i, /^ProcessCommandLine$/i]),
                        user: det([/^User$/i, /^UserName$/i, /^TargetUserName$/i]),
                        ts: det([/^UtcTime$/i, /^datetime$/i, /^TimeCreated$/i]),
                        eventId: det([/^EventID$/i, /^event_id$/i, /^EventId$/]),
                        elevation: det([/^TokenElevationType$/i]),
                        integrity: det([/^MandatoryLabel$/i, /^IntegrityLevel$/i]),
                        provider: det([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
                      };
                      setModal({ type: "processTree", phase: "config", columns: cols, eventIdValue: "1,4688", data: null, loading: false, expandedNodes: {}, searchText: "", error: null });
                    }, disabled: !ct?.dataReady },
                    { label: "Lateral Movement Tracker", icon: ic(<><circle cx="5" cy="12" r="2.5" fill={(th.danger||"#f85149")+"33"}/><circle cx="19" cy="5" r="2.5" fill={(th.danger||"#f85149")+"33"}/><circle cx="19" cy="19" r="2.5" fill={(th.danger||"#f85149")+"33"}/><line x1="7.5" y1="11" x2="16.5" y2="6"/><line x1="7.5" y1="13" x2="16.5" y2="18"/><circle cx="12" cy="12" r="1.5" fill={(th.danger||"#f85149")+"55"}/></>, th.danger || "#f85149"), action: () => {
                      if (!ct?.dataReady) return;
                      const det = (pats) => { for (const p of pats) { const f = ct.headers.find((h) => p.test(h)); if (f) return f; } return null; };
                      const isEvtxECmd = ct.headers.some((h) => /^RemoteHost$/i.test(h)) && ct.headers.some((h) => /^PayloadData1$/i.test(h));
                      const cols = {
                        source: det([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^RemoteHost$/i]),
                        target: det([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i]),
                        user: det([/^TargetUserName$/i, /^Target_User_Name$/i, /^UserName$/i, ...(isEvtxECmd ? [/^PayloadData1$/i] : [])]),
                        logonType: det([/^LogonType$/i, /^Logon_Type$/i, ...(isEvtxECmd ? [/^PayloadData2$/i] : [])]),
                        eventId: det([/^EventID$/i, /^event_id$/i, /^EventId$/]),
                        ts: det([/^datetime$/i, /^UtcTime$/i, /^TimeCreated$/i]),
                        domain: det([/^TargetDomainName$/i]),
                      };
                      setModal({ type: "lateralMovement", phase: "config", columns: cols, excludeLocal: true, excludeService: true, lmDisabledRules: new Set(), lmCustomRules: [], showLmRules: false, data: null, loading: false, error: null, selectedNode: null, selectedEdge: null, viewTab: "graph", positions: null });
                    }, disabled: !ct?.dataReady },
                    { label: "Persistence Analyzer", icon: ic(<><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill={(th.danger||"#f85149")+"22"} stroke={th.danger||"#f85149"}/><path d="M12 8v4M12 16h.01" stroke={th.danger||"#f85149"}/></>, th.danger || "#f85149"), action: () => {
                      if (!ct?.dataReady) return;
                      const det = (pats) => { for (const p of pats) { const f = ct.headers.find((h) => p.test(h)); if (f) return f; } return null; };
                      const hasKeyPath = det([/^KeyPath$/i, /^Key ?Path$/i]);
                      const hasValueName = det([/^ValueName$/i, /^Value ?Name$/i]);
                      const hasEventId = det([/^EventI[dD]$/i, /^event_id$/i]);
                      const autoMode = (hasKeyPath && hasValueName) ? "registry" : hasEventId ? "evtx" : "auto";
                      setModal({ type: "persistence", phase: "config", mode: autoMode, columns: {}, data: null, loading: false, error: null, viewTab: "grouped", searchText: "", severityFilter: "all", categoryFilter: "all", disabledRules: new Set(), customRules: [], showRules: false, addingRule: false, newRule: {}, modalW: 1100 });
                    }, disabled: !ct?.dataReady },
                    { section: "Export" },
                    { label: "Generate Report", icon: ic(<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="15" y2="17"/></>, th.success || "#3fb950"), action: async () => { if (ct?.dataReady) await tle.generateReport(ct.id, ct.name, ct.tagColors || {}); }, disabled: !ct?.dataReady },
                    { section: "Help" },
                    { label: "Keyboard Shortcuts", icon: ic(<><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M6 8h.01M10 8h.01M14 8h.01M18 8h.01M6 12h.01M18 12h.01M8 16h8"/></>), action: () => setModal({ type: "shortcuts" }) },
                  ];
                  return items.map((item, i) => item.section ? (
                    <div key={item.section} style={{ padding: i === 0 ? "2px 14px 4px" : "6px 14px 4px", borderTop: i === 0 ? "none" : `1px solid ${th.border}33`, marginTop: i === 0 ? 0 : 2 }}>
                      <span style={{ fontSize: 9, fontWeight: 700, color: th.accent, textTransform: "uppercase", letterSpacing: "0.1em", fontFamily: "-apple-system, sans-serif" }}>{item.section}</span>
                    </div>
                  ) : (
                    <button key={item.label} onClick={() => { setToolsOpen(false); item.action(); }} disabled={item.disabled}
                      onMouseEnter={(e) => { if (!item.disabled) { e.currentTarget.style.background = `${th.accent}15`; e.currentTarget.style.borderLeft = `2px solid ${th.accent}`; e.currentTarget.style.paddingLeft = "12px"; } }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.borderLeft = "2px solid transparent"; e.currentTarget.style.paddingLeft = "12px"; }}
                      style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "7px 14px 7px 12px", background: "none", border: "none", borderLeft: "2px solid transparent", color: item.disabled ? th.textMuted : th.text, fontSize: 13, cursor: item.disabled ? "default" : "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif", opacity: item.disabled ? 0.4 : 1, transition: "all 0.1s" }}>
                      {item.icon}
                      {item.label}
                    </button>
                  ));
                })()}
              </div>
            </>)}
          </div>
          <div style={tdv} />
          <span style={{ color: th.textMuted, fontSize: 10 }}>⏱</span>
          <select value={dateTimeFormat} onChange={(e) => setDateTimeFormat(e.target.value)} style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, color: th.textDim, fontSize: 10, padding: "3px 5px", borderRadius: 4, cursor: "pointer", outline: "none" }}>
            {DT_FORMATS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
          </select>
          <select value={timezone} onChange={(e) => setTimezone(e.target.value)} style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, color: th.textDim, fontSize: 10, padding: "3px 5px", borderRadius: 4, cursor: "pointer", outline: "none" }}>
            {TIMEZONES.map((tz) => <option key={tz.value} value={tz.value}>{tz.label}</option>)}
          </select>
          <div style={tdv} />
          <button onClick={() => setThemeName((p) => p === "dark" ? "light" : "dark")} style={tb} title="Toggle theme">{themeName === "dark" ? "☀" : "🌙"}</button>
          <div style={tdv} />
          <span style={{ color: th.textMuted, fontSize: 10 }}>A</span>
          <button onClick={() => setFontSize((s) => Math.max(9, s - 1))} style={{ ...tb, fontSize: 11, padding: "3px 5px" }} title="Decrease font size">−</button>
          <span style={{ color: th.textDim, fontSize: 10, minWidth: 18, textAlign: "center" }}>{fontSize}</span>
          <button onClick={() => setFontSize((s) => Math.min(18, s + 1))} style={{ ...tb, fontSize: 11, padding: "3px 5px" }} title="Increase font size">+</button>
          <div style={tdv} />
          <button onClick={() => setHistogramVisible((v) => !v)} style={{ ...tb, color: histogramVisible ? th.accent : th.textDim }} title="Toggle timeline histogram">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="12" width="4" height="9" rx="1" /><rect x="10" y="6" width="4" height="15" rx="1" /><rect x="17" y="3" width="4" height="18" rx="1" /></svg>
          </button>
          {proximityFilter && ct?.dateRangeFilters?.[proximityFilter.tsCol] && (<>
            <div style={tdv} />
            <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "3px 8px", background: `${th.warning}22`, border: `1px solid ${th.warning}4D`, borderRadius: 10, color: th.warning, fontSize: 10, fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}
              title={`Proximity: ±${proximityFilter.label} around ${proximityFilter.pivotRaw}`}>
              ⏱ ±{proximityFilter.label}
              <span style={{ color: th.textMuted, maxWidth: 80, overflow: "hidden", textOverflow: "ellipsis" }}>{" near "}{(proximityFilter.pivotRaw || "").slice(11, 19)}</span>
              <button onClick={() => { const next = { ...(ct?.dateRangeFilters || {}) }; delete next[proximityFilter.tsCol]; up("dateRangeFilters", next); setProximityFilter(null); }}
                style={{ background: "none", border: "none", color: th.warning, cursor: "pointer", fontSize: 10, padding: "0 0 0 2px", lineHeight: 1 }} title="Clear proximity filter">✕</button>
            </span>
          </>)}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6, flex: 1, maxWidth: 560, background: th.bgInput, border: `1px solid ${th.border}`, borderRadius: 6, padding: "0 8px", WebkitAppRegion: "no-drag" }}>
          {searchLoading && ct?.searchTerm ? (
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2.5" style={{ animation: "tle-spin 0.8s linear infinite", flexShrink: 0 }}>
              <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" /></svg>
          ) : (
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2" style={{ flexShrink: 0 }}><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>
          )}
          <input id="gs" value={ct?.searchTerm || ""} onChange={(e) => up("searchTerm", e.target.value)} placeholder='Search: terms, +AND, -NOT, "phrase", Col:val'
            style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: th.text, fontSize: 12, padding: "6px 0", fontFamily: "inherit" }} />
          <select value={ct?.searchMode || "mixed"} onChange={(e) => up("searchMode", e.target.value)} style={{ background: th.btnBg, border: "none", color: th.textDim, fontSize: 10, padding: "2px 5px", borderRadius: 3, cursor: "pointer", outline: "none" }}>
            <option value="mixed">Mixed</option><option value="or">OR</option><option value="and">AND</option><option value="exact">Exact</option><option value="regex">Regex</option>
          </select>
          <button onClick={() => ct && up("searchHighlight", !ct.searchHighlight)}
            title={ct?.searchHighlight ? "Highlight mode (showing all rows, highlighting matches)" : "Filter mode (hiding non-matching rows)"}
            style={{ background: ct?.searchHighlight ? `${th.warning}33` : "none", border: ct?.searchHighlight ? `1px solid ${th.warning}66` : "1px solid transparent", color: ct?.searchHighlight ? th.warning : th.textMuted, cursor: "pointer", fontSize: 10, padding: "1px 5px", borderRadius: 3, fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
            {ct?.searchHighlight ? "HL" : "FL"}
          </button>
          {ct?.searchTerm && !isGrouped && (
            searchLoading ? (
              <span style={{ color: th.accent, fontSize: 10, whiteSpace: "nowrap", fontStyle: "italic" }}>Searching...</span>
            ) : (
              <>
                <span style={{ color: th.textDim, fontSize: 10, whiteSpace: "nowrap" }}>
                  {ct.searchHighlight && hlMatchIndices
                    ? `${hlMatchIndices.indexOf(searchMatchIdx) >= 0 ? hlMatchIndices.indexOf(searchMatchIdx) + 1 : 0}/${hlMatchIndices.length}`
                    : (ct?.totalFiltered || 0) > 0 ? `${searchMatchIdx >= 0 ? searchMatchIdx + 1 : 0}/${formatNumber(ct.totalFiltered)}` : "0"}
                </span>
                <button onClick={() => navigateSearch(-1)} style={{ background: "none", border: "none", color: th.textDim, cursor: "pointer", fontSize: 12, padding: "0 2px", lineHeight: 1 }} title="Previous match (Shift+F3)">▲</button>
                <button onClick={() => navigateSearch(1)} style={{ background: "none", border: "none", color: th.textDim, cursor: "pointer", fontSize: 12, padding: "0 2px", lineHeight: 1 }} title="Next match (F3)">▼</button>
              </>
            )
          )}
          {ct?.searchTerm && <button onClick={() => up("searchTerm", "")} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 11 }}>✕</button>}
          {/* Regex Pattern Palette */}
          <div style={{ position: "relative" }}>
            <button onClick={() => setRegexPaletteOpen((v) => !v)}
              title="Regex Pattern Palette — quick-insert common forensic patterns"
              style={{ background: regexPaletteOpen ? `${th.accent}22` : "none", border: regexPaletteOpen ? `1px solid ${th.accent}66` : "1px solid transparent", color: regexPaletteOpen ? th.accent : th.textMuted, cursor: "pointer", fontSize: 10, padding: "1px 5px", borderRadius: 3, fontFamily: "'SF Mono',Menlo,monospace", fontWeight: 700, whiteSpace: "nowrap", lineHeight: "16px" }}>Rx</button>
            {regexPaletteOpen && (<>
              <div onClick={() => setRegexPaletteOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 149 }} />
              <div style={{ position: "absolute", top: "100%", right: 0, marginTop: 6, background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 8, padding: "6px 0", zIndex: 150, boxShadow: "0 8px 24px rgba(0,0,0,0.4)", minWidth: 260, maxHeight: "70vh", overflow: "auto" }}>
                <div style={{ padding: "4px 12px 6px", borderBottom: `1px solid ${th.border}`, marginBottom: 4 }}>
                  <span style={{ fontSize: 10, fontWeight: 600, color: th.textDim, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>Forensic Regex Patterns</span>
                </div>
                {[
                  { label: "IPv4 Address", pattern: "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b", icon: "IP" },
                  { label: "IPv6 Address", pattern: "\\b[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){2,7}\\b", icon: "v6" },
                  { label: "Domain Name", pattern: "\\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z]{2,})+\\b", icon: "DN" },
                  { label: "Email Address", pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", icon: "@" },
                  { label: "sep" },
                  { label: "MD5 Hash", pattern: "\\b[a-fA-F0-9]{32}\\b", icon: "M5" },
                  { label: "SHA1 Hash", pattern: "\\b[a-fA-F0-9]{40}\\b", icon: "S1" },
                  { label: "SHA256 Hash", pattern: "\\b[a-fA-F0-9]{64}\\b", icon: "S2" },
                  { label: "sep" },
                  { label: "Base64 Blob", pattern: "[A-Za-z0-9+/]{20,}={0,2}", icon: "B6" },
                  { label: "Windows SID", pattern: "S-1-[0-9](-[0-9]+){1,}", icon: "SI" },
                  { label: "UNC Path", pattern: "\\\\\\\\[a-zA-Z0-9._-]+\\\\[a-zA-Z0-9._$\\\\-]+", icon: "\\\\" },
                  { label: "Windows File Path", pattern: "[A-Za-z]:\\\\[^\\s\"'<>|]+", icon: "C:" },
                  { label: "Unix File Path", pattern: "/[a-zA-Z0-9._/-]{2,}", icon: "/" },
                  { label: "sep" },
                  { label: "URL (http/https)", pattern: "https?://[^\\s\"'<>]+", icon: "://" },
                  { label: "Registry Key", pattern: "(HKLM|HKCU|HKU|HKCR|HKCC)\\\\[^\\s\"]+", icon: "HK" },
                  { label: "MAC Address", pattern: "\\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b", icon: "MA" },
                ].map((item, i) => item.label === "sep" ? (
                  <div key={i} style={{ height: 1, background: th.border, margin: "4px 0" }} />
                ) : (
                  <button key={item.label} onClick={() => {
                    up("searchTerm", item.pattern);
                    up("searchMode", "regex");
                    setRegexPaletteOpen(false);
                    setTimeout(() => document.getElementById("gs")?.focus(), 50);
                  }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                    style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "5px 12px", background: "none", border: "none", color: th.text, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                    <span style={{ width: 22, textAlign: "center", fontSize: 9, fontWeight: 700, color: th.accent, fontFamily: "'SF Mono',Menlo,monospace", flexShrink: 0 }}>{item.icon}</span>
                    <span style={{ flex: 1 }}>{item.label}</span>
                    <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "'SF Mono',Menlo,monospace", maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={item.pattern}>{item.pattern.length > 18 ? item.pattern.slice(0, 18) + "..." : item.pattern}</span>
                  </button>
                ))}
              </div>
            </>)}
          </div>
        </div>
        {/* Background indexing indicator — column indexes + FTS run in parallel */}
        {ct && ct.dataReady && (!ct.indexesReady || (!ct.ftsReady && ct.ftsTotal > 0)) && (
          <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 6px", flexShrink: 0 }}>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={th.warning} strokeWidth="2.5" style={{ animation: "tle-spin 1s linear infinite", flexShrink: 0 }}>
              <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" /></svg>
            <span style={{ color: th.warning, fontSize: 9, fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
              {!ct.indexesReady && (!ct.ftsReady && ct.ftsTotal > 0)
                ? `Indexing cols ${ct.indexesBuilt || 0}/${ct.indexesTotal || "..."} + search ${Math.round((ct.ftsIndexed / ct.ftsTotal) * 100)}%`
                : !ct.indexesReady
                ? `Indexing columns ${ct.indexesBuilt || 0}/${ct.indexesTotal || "..."}`
                : `Indexing search ${Math.round((ct.ftsIndexed / ct.ftsTotal) * 100)}%`}
            </span>
          </div>
        )}
      </div>

      {/* Search Options Bar (Windows TLE parity) */}
      {ct && ct.searchTerm && (
        <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "3px 12px", background: th.panelBg, borderBottom: `1px solid ${th.border}`, flexShrink: 0 }}>
          <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>Condition:</span>
          {[["contains", "Contains"], ["fuzzy", "Fuzzy"], ["startswith", "Starts with"], ["like", "Like"], ["equals", "Equals"]].map(([v, l]) => (
            <label key={v} style={{ display: "flex", alignItems: "center", gap: 3, cursor: "pointer" }}>
              <input type="radio" name="searchCondition" value={v} checked={(ct.searchCondition || "contains") === v}
                onChange={() => up("searchCondition", v)} style={{ margin: 0, accentColor: th.accent }} />
              <span style={{ color: (ct.searchCondition || "contains") === v ? th.accent : th.textDim, fontSize: 10 }}>{l}</span>
            </label>
          ))}
          <div style={{ width: 1, height: 14, background: th.border }} />
          <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>Match:</span>
          <select value={ct.searchMode || "mixed"} onChange={(e) => up("searchMode", e.target.value)}
            style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, color: th.textDim, fontSize: 10, padding: "2px 5px", borderRadius: 3, cursor: "pointer", outline: "none" }}>
            <option value="mixed">Mixed</option><option value="or">OR</option><option value="and">AND</option><option value="exact">Exact</option><option value="regex">Regex</option>
          </select>
          <div style={{ width: 1, height: 14, background: th.border }} />
          <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>Behavior:</span>
          <button onClick={() => up("searchHighlight", false)}
            style={{ fontSize: 10, color: !ct.searchHighlight ? th.accent : th.textDim, background: !ct.searchHighlight ? `${th.accent}22` : "none", border: `1px solid ${!ct.searchHighlight ? th.accent + "4D" : "transparent"}`, borderRadius: 3, padding: "1px 6px", cursor: "pointer" }}>Filter</button>
          <button onClick={() => up("searchHighlight", true)}
            style={{ fontSize: 10, color: ct.searchHighlight ? th.warning : th.textDim, background: ct.searchHighlight ? `${th.warning}22` : "none", border: `1px solid ${ct.searchHighlight ? th.warning + "4D" : "transparent"}`, borderRadius: 3, padding: "1px 6px", cursor: "pointer" }}>Highlight</button>
        </div>
      )}

      {/* Cross-tab search results (auto-shown with 2+ tabs and active search) */}
      {crossTabCounts && crossTabOpen && crossTabCounts.results.length > 0 && (
        <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 12px", background: th.panelBg, borderBottom: `1px solid ${th.border}`, flexShrink: 0, overflowX: "auto" }}>
          <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap", marginRight: 4 }}>Across tabs:</span>
          {crossTabCounts.results.map((r) => (
            <button key={r.tabId} onClick={() => { if (r.count > 0) { setActiveTab(r.tabId); setTabs((prev) => prev.map((t) => t.id === r.tabId ? { ...t, searchTerm: crossTabCounts.term, searchMode: crossTabCounts.mode } : t)); } }}
              style={{ display: "flex", alignItems: "center", gap: 3, padding: "1px 8px", borderRadius: 10, border: `1px solid ${r.count > 0 ? th.borderAccent + "66" : th.border}`, background: r.tabId === activeTab ? th.selection : "transparent", cursor: r.count > 0 ? "pointer" : "default", fontSize: 10, color: r.count > 0 ? th.text : th.textMuted, whiteSpace: "nowrap" }}>
              <span style={{ maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis" }}>{r.name}</span>
              <span style={{ color: r.count > 0 ? th.success : th.textMuted, fontWeight: 600 }}>{formatNumber(r.count)}</span>
            </button>
          ))}
          <span style={{ color: th.textMuted, fontSize: 10, marginLeft: 4 }}>
            Total: {formatNumber(crossTabCounts.results.reduce((s, r) => s + r.count, 0))}
          </span>
          <button onClick={() => setCrossTabOpen(false)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 10, marginLeft: "auto", padding: "0 4px" }}>✕</button>
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: "flex", background: th.panelBg, borderBottom: `1px solid ${th.border}`, overflowX: "auto", flexShrink: 0 }}>
        {tabs.filter((t) => !tabFilter || t.name.toLowerCase().includes(tabFilter.toLowerCase())).map((t) => (
          <div key={t.id} onClick={() => {
            if (activeTab) tabScrollPos.current[activeTab] = { scrollTop, selectedRows, lastClickedRow };
            const saved = tabScrollPos.current[t.id];
            setActiveTab(t.id);
            setScrollTop(saved?.scrollTop || 0);
            setSelectedRows(saved?.selectedRows || new Set());
            setLastClickedRow(saved?.lastClickedRow ?? null);
            setProximityFilter(null);
            if (saved?.scrollTop && scrollRef.current) {
              requestAnimationFrame(() => { if (scrollRef.current) scrollRef.current.scrollTop = saved.scrollTop; });
            }
          }}
            style={{ display: "flex", alignItems: "center", gap: 5, padding: "6px 12px", cursor: "pointer", borderRight: `1px solid ${th.border}`, color: t.id === activeTab ? th.text : th.textDim, fontSize: 11, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", background: t.id === activeTab ? th.bgAlt : th.panelBg, borderBottom: t.id === activeTab ? `2px solid ${th.borderAccent}` : "2px solid transparent", borderTop: t.id === activeTab ? `2px solid ${th.borderAccent}` : "2px solid transparent" }}>
            {t.importing && <span style={{ color: th.warning }}>⏳</span>}
            <span style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>{t.name}</span>
            <span style={{ color: th.textMuted, fontSize: 10 }}>({formatNumber(t.totalRows || 0)})</span>
            <button onClick={(e) => { e.stopPropagation(); closeTab(t.id); }} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 10, padding: "0 2px" }}>✕</button>
          </div>
        ))}
        {tabs.length >= 3 && (
          <div style={{ display: "flex", alignItems: "center", marginLeft: "auto", flexShrink: 0, padding: "0 8px" }}>
            <input value={tabFilter} onChange={(e) => setTabFilter(e.target.value)}
              placeholder="Filter tabs..."
              style={{ width: 110, padding: "2px 6px", background: th.bgInput, border: `1px solid ${th.border}`, borderRadius: 4, color: th.text, fontSize: 10, outline: "none", fontFamily: "-apple-system, sans-serif" }} />
            {tabFilter && <button onClick={() => setTabFilter("")} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 10, padding: "0 3px", marginLeft: 2 }}>✕</button>}
          </div>
        )}
      </div>

      {/* Group Panel */}
      {ct && ct.dataReady && (
        <div
          onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; setGroupDragOver(true); }}
          onDragLeave={() => setGroupDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setGroupDragOver(false); const col = e.dataTransfer.getData("text/column-name"); if (col) addGroupBy(col); }}
          style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 12px",
            background: groupDragOver ? th.accentSubtle : th.panelBg,
            borderBottom: `1px solid ${th.border}`, minHeight: 28, flexShrink: 0, transition: "background 0.15s",
            border: groupDragOver ? `1px dashed ${th.accent}` : undefined,
            borderRadius: groupDragOver ? 4 : 0, margin: groupDragOver ? "2px 4px" : 0 }}>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={groupDragOver ? th.accent : isGrouped ? th.accent : th.textMuted} strokeWidth="2" style={{ flexShrink: 0 }}>
            <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" />
          </svg>
          {groupDragOver && !isGrouped ? (
            <span style={{ color: th.accent, fontSize: 10, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Drop here to group by column</span>
          ) : isGrouped ? (<>
            {(ct.groupByColumns || []).map((col, i) => (
              <span key={col} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                {i > 0 && <span style={{ color: th.textMuted, fontSize: 9 }}>›</span>}
                <span draggable
                  onDragStart={(e) => { e.stopPropagation(); e.dataTransfer.setData("text/group-reorder", col); setGroupReorderDrag(col); }}
                  onDragEnd={() => setGroupReorderDrag(null)}
                  onDragOver={(e) => { if (groupReorderDrag && groupReorderDrag !== col) { e.preventDefault(); e.dataTransfer.dropEffect = "move"; } }}
                  onDrop={(e) => { e.preventDefault(); e.stopPropagation(); const dragCol = e.dataTransfer.getData("text/group-reorder"); if (dragCol && dragCol !== col) { setTabs((prev) => prev.map((t) => { if (t.id !== ct.id) return t; const cols = [...(t.groupByColumns || [])]; const fromIdx = cols.indexOf(dragCol); const toIdx = cols.indexOf(col); if (fromIdx < 0 || toIdx < 0) return t; cols.splice(fromIdx, 1); cols.splice(toIdx, 0, dragCol); return { ...t, groupByColumns: cols, expandedGroups: {}, groupData: [] }; })); setGroupReorderDrag(null); } }}
                  style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", background: groupReorderDrag === col ? `${th.accent}44` : `${th.accent}22`, border: `1px solid ${th.accent}4D`, borderRadius: 4, color: th.accent, fontSize: 10, fontWeight: 500, fontFamily: "-apple-system, sans-serif", cursor: "grab" }}>
                  {col}
                  <button onClick={() => removeGroupBy(col)} style={{ background: "none", border: "none", color: th.accent, cursor: "pointer", fontSize: 9, padding: 0, lineHeight: 1, opacity: 0.7 }} title={`Remove ${col} grouping`}>✕</button>
                </span>
              </span>
            ))}
            <button onClick={() => setTabs((prev) => prev.map((t) => t.id === ct.id ? { ...t, groupByColumns: [], expandedGroups: {}, groupData: [] } : t))} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 9, padding: "1px 4px", fontFamily: "-apple-system, sans-serif" }} title="Clear all grouping">Clear</button>
          </>) : (
            <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>Drag a column header here to group</span>
          )}
          {totalActiveFilters > 0 && (
            <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 8, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>
              <span style={{ color: th.borderAccent }}>
                {totalActiveFilters} filter{totalActiveFilters > 1 ? "s" : ""} active
                {activeCheckboxCount > 0 ? ` (${activeCheckboxCount} value)` : ""}
              </span>
              <button onClick={clearAllFilters} style={{ background: (th.danger || "#f85149") + "18", border: `1px solid ${(th.danger || "#f85149")}55`, borderRadius: 4, color: th.danger || "#f85149", cursor: "pointer", fontSize: 10, padding: "1px 8px", fontFamily: "-apple-system, sans-serif", fontWeight: 600 }}>Clear All</button>
            </span>
          )}
        </div>
      )}

      {/* Timeline Histogram — glass, brush-select, hourly toggle */}
      {histogramVisible && ct?.dataReady && ct?.tsColumns?.size > 0 && (() => {
        const effectiveHistCol = histogramCol && ct.tsColumns.has(histogramCol) ? histogramCol : [...ct.tsColumns][0];
        const HIST_H = histogramHeight, Y_AXIS_W = 44, X_AXIS_H = 18, CHART_PAD_T = 4, HEADER_BAR = 28;
        const svgH = HIST_H - HEADER_BAR;
        const chartH = svgH - X_AXIS_H - CHART_PAD_T;
        const isHourly = histGranularity === "hour";
        const bucketLabel = isHourly ? "hour" : "day";
        // Brush helpers — DOM-only during drag for zero-rerender performance
        const getBarIdx = (e) => {
          const r = histSvgRectRef.current || (e.currentTarget || e.target?.closest?.("svg"))?.getBoundingClientRect();
          if (!r) return 0;
          const cw = r.width - Y_AXIS_W;
          const bw = cw / (histogramData.length || 1);
          return Math.max(0, Math.min(histogramData.length - 1, Math.floor((e.clientX - r.left - Y_AXIS_W) / bw)));
        };
        const brushFrom = (d) => isHourly ? d + ":00:00" : d + " 00:00:00";
        const brushTo = (d) => isHourly ? d + ":59:59" : d + " 23:59:59";
        // Update brush overlay position via direct DOM (no React re-render)
        const updateBrushDOM = (lo, hi) => {
          const g = histBarGeomRef.current;
          const overlay = histBrushOverlayRef.current;
          const label = histBrushLabelRef.current;
          if (overlay) {
            const bx = g.yAxisW + lo * g.barW;
            const bw = (hi - lo + 1) * g.barW;
            overlay.setAttribute("x", bx);
            overlay.setAttribute("width", bw);
            overlay.setAttribute("y", g.chartPadT);
            overlay.setAttribute("height", g.chartH);
            overlay.style.display = "";
          }
          if (label) {
            const bx = g.yAxisW + lo * g.barW;
            const bw = (hi - lo + 1) * g.barW;
            label.setAttribute("x", bx + bw / 2);
            label.setAttribute("y", g.chartPadT - 3);
            label.textContent = (histogramData[lo]?.day || "") + (lo !== hi ? ` \u2014 ${histogramData[hi]?.day || ""}` : "");
            label.style.display = "";
          }
        };
        const hideBrushDOM = () => {
          if (histBrushOverlayRef.current) histBrushOverlayRef.current.style.display = "none";
          if (histBrushLabelRef.current) histBrushLabelRef.current.style.display = "none";
        };
        const onSvgDown = (e) => {
          if (e.button !== 0 || !histogramData.length) return;
          if (e.currentTarget) histSvgRectRef.current = e.currentTarget.getBoundingClientRect();
          const idx = getBarIdx(e);
          histBrushRef.current = { startIdx: idx, endIdx: idx, active: true };
          updateBrushDOM(idx, idx);
          e.currentTarget.style.cursor = "col-resize";
        };
        const onSvgMove = (e) => {
          if (!histBrushRef.current.active) return;
          const idx = getBarIdx(e);
          if (idx === histBrushRef.current.endIdx) return; // skip if same bar
          histBrushRef.current = { ...histBrushRef.current, endIdx: idx };
          const lo = Math.min(histBrushRef.current.startIdx, idx);
          const hi = Math.max(histBrushRef.current.startIdx, idx);
          updateBrushDOM(lo, hi);
        };
        const onSvgUp = (e) => {
          if (!histBrushRef.current.active || !histogramData.length) return;
          const end = getBarIdx(e);
          const lo = Math.min(histBrushRef.current.startIdx, end), hi = Math.max(histBrushRef.current.startIdx, end);
          if (lo === hi) {
            const d = histogramData[lo];
            if (d) up("dateRangeFilters", { ...(ct.dateRangeFilters || {}), [effectiveHistCol]: { from: brushFrom(d.day), to: brushTo(d.day) } });
          } else {
            const dLo = histogramData[lo], dHi = histogramData[hi];
            if (dLo && dHi) up("dateRangeFilters", { ...(ct.dateRangeFilters || {}), [effectiveHistCol]: { from: brushFrom(dLo.day), to: brushTo(dHi.day) } });
          }
          histBrushRef.current = { startIdx: null, endIdx: null, active: false };
          hideBrushDOM();
          histSvgRectRef.current = null;
          if (e.currentTarget) e.currentTarget.style.cursor = "crosshair";
        };
        return (
          <div id="hist-container" ref={histContainerRef} style={{ height: HIST_H, padding: "4px 12px 0", background: `linear-gradient(180deg, ${th.panelBg}ee, ${th.panelBg}cc)`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", borderBottom: `1px solid ${th.border}44`, flexShrink: 0, position: "relative", overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3, height: HEADER_BAR - 6 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "2px 8px", background: `${th.panelBg}88`, borderRadius: 6, border: `1px solid ${th.border}33` }}>
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2"><rect x="3" y="12" width="4" height="9" rx="1" /><rect x="10" y="6" width="4" height="15" rx="1" /><rect x="17" y="3" width="4" height="18" rx="1" /></svg>
                <span style={{ color: th.textDim, fontSize: 10, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Timeline</span>
              </div>
              <select value={effectiveHistCol || ""} onChange={(e) => { setHistogramCol(e.target.value); histBrushRef.current = { startIdx: null, endIdx: null, active: false }; hideBrushDOM(); }}
                style={{ background: th.bgInput, border: `1px solid ${th.btnBorder}`, color: th.textDim, fontSize: 10, padding: "2px 6px", borderRadius: 4, cursor: "pointer", outline: "none" }}>
                {[...ct.tsColumns].map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
              {/* Granularity toggle */}
              <div style={{ display: "flex", background: th.btnBg, borderRadius: 5, border: `1px solid ${th.btnBorder}`, overflow: "hidden" }}>
                {["day", "hour"].map((g) => (
                  <button key={g} onClick={() => { setHistGranularity(g); histBrushRef.current = { startIdx: null, endIdx: null, active: false }; hideBrushDOM(); }}
                    style={{ padding: "2px 8px", fontSize: 9, fontWeight: histGranularity === g ? 600 : 400, background: histGranularity === g ? th.accent + "22" : "transparent", color: histGranularity === g ? th.accent : th.textMuted, border: "none", cursor: "pointer", fontFamily: "-apple-system,sans-serif", textTransform: "capitalize" }}>{g}</button>
                ))}
              </div>
              {histogramData.length > 0 && (
                <span style={{ color: th.textMuted, fontSize: 9, fontFamily: "-apple-system, sans-serif" }}>
                  {histogramData[0]?.day} — {histogramData[histogramData.length - 1]?.day} ({histogramData.length} {bucketLabel}{histogramData.length !== 1 ? "s" : ""})
                </span>
              )}
              {ct.dateRangeFilters?.[effectiveHistCol] && (
                <button onClick={() => {
                  const next = { ...(ct.dateRangeFilters || {}) };
                  delete next[effectiveHistCol];
                  up("dateRangeFilters", next);
                }} style={{ background: `${th.warning}22`, border: `1px solid ${th.warning}4D`, color: th.warning, cursor: "pointer", fontSize: 9, padding: "1px 8px", borderRadius: 3, marginLeft: "auto", fontFamily: "-apple-system,sans-serif" }}>
                  Clear filter
                </button>
              )}
              <button onClick={() => setHistogramVisible(false)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 10, marginLeft: ct.dateRangeFilters?.[effectiveHistCol] ? 4 : "auto", padding: "0 4px" }}>{"\u2715"}</button>
            </div>
            {histogramData.length > 0 ? (
              <svg width="100%" height={svgH} style={{ display: "block", overflow: "visible", cursor: "crosshair", userSelect: "none" }}
                onMouseDown={onSvgDown} onMouseMove={onSvgMove} onMouseUp={onSvgUp} onMouseLeave={(e) => { if (histBrushRef.current.active) { histBrushRef.current = { startIdx: null, endIdx: null, active: false }; hideBrushDOM(); if (e.currentTarget) e.currentTarget.style.cursor = "crosshair"; } }}>
                {(() => {
                  const maxCnt = Math.max(...histogramData.map((d) => d.cnt), 1);
                  const rawStep = maxCnt / 4;
                  const mag = Math.pow(10, Math.floor(Math.log10(rawStep || 1)));
                  const step = Math.ceil(rawStep / mag) * mag || 1;
                  const yTicks = [];
                  for (let v = 0; v <= maxCnt; v += step) yTicks.push(v);
                  if (yTicks[yTicks.length - 1] < maxCnt) yTicks.push(yTicks[yTicks.length - 1] + step);
                  const yMax = yTicks[yTicks.length - 1] || 1;
                  const chartW = Math.max(200, (histContainerWidth || (typeof window !== "undefined" ? window.innerWidth : 800)) - 24 - Y_AXIS_W);
                  const barW = Math.max(1, chartW / histogramData.length);
                  const gap = barW > 4 ? 1 : 0;
                  const maxLabels = Math.floor(chartW / (isHourly ? 90 : 70));
                  const labelStep = Math.max(1, Math.ceil(histogramData.length / maxLabels));
                  const gridColor = th.histGrid;
                  const textColor = th.textMuted;
                  // Cache bar geometry for DOM-based brush updates (no re-renders during drag)
                  histBarGeomRef.current = { barW, yAxisW: Y_AXIS_W, chartPadT: CHART_PAD_T, chartH, len: histogramData.length };
                  const heatColor = (ratio) => {
                    const t = Math.max(0, Math.min(1, ratio));
                    return `rgb(${Math.round(30 + t * 202)},${Math.round(40 + t * 53)},${Math.round(56 - t * 14)})`;
                  };
                  // Active date filter check
                  const activeFilter = ct.dateRangeFilters?.[effectiveHistCol];
                  const filterFrom = activeFilter?.from?.slice(0, isHourly ? 13 : 10);
                  const filterTo = activeFilter?.to?.slice(0, isHourly ? 13 : 10);

                  return (<>
                    {yTicks.map((v) => {
                      const y = CHART_PAD_T + chartH - (v / yMax) * chartH;
                      return <g key={`y-${v}`}>
                        <line x1={Y_AXIS_W} y1={y} x2={Y_AXIS_W + chartW} y2={y} stroke={gridColor} strokeWidth={1} strokeOpacity={0.6} />
                        <text x={Y_AXIS_W - 4} y={y + 3} textAnchor="end" fill={textColor} fontSize={9} fontFamily="-apple-system,sans-serif">{v >= 1000 ? `${(v/1000).toFixed(v >= 10000 ? 0 : 1)}k` : v}</text>
                      </g>;
                    })}
                    {histogramData.map((d, i) => {
                      const h = Math.max(1, (d.cnt / yMax) * chartH);
                      const x = Y_AXIS_W + i * barW + gap;
                      const y = CHART_PAD_T + chartH - h;
                      const isFiltered = filterFrom && filterTo && d.day >= filterFrom && d.day <= filterTo;
                      const ratio = d.cnt / maxCnt;
                      const fill = isFiltered ? th.warning : heatColor(ratio);
                      return <rect key={i} x={x} y={y} width={Math.max(1, barW - gap * 2)} height={h}
                        fill={fill} rx={barW > 6 ? 2 : 0}
                        style={{ transition: "fill 0.1s", pointerEvents: "none" }}>
                        <title>{d.day}: {d.cnt.toLocaleString()} events</title>
                      </rect>;
                    })}
                    {/* Brush selection overlay — positioned via DOM refs for zero-rerender drag */}
                    <rect ref={histBrushOverlayRef} x={0} y={CHART_PAD_T} width={0} height={chartH}
                      fill={th.accent + "15"} stroke={th.accent} strokeWidth={1} strokeDasharray="3 2" rx={2}
                      style={{ pointerEvents: "none", display: "none" }} />
                    <text ref={histBrushLabelRef} x={0} y={CHART_PAD_T - 3} textAnchor="middle"
                      fill={th.accent} fontSize={8} fontWeight="600" fontFamily="-apple-system,sans-serif"
                      style={{ pointerEvents: "none", display: "none" }} />
                    <line x1={Y_AXIS_W} y1={CHART_PAD_T + chartH} x2={Y_AXIS_W + chartW} y2={CHART_PAD_T + chartH} stroke={gridColor} strokeWidth={1} />
                    {histogramData.map((d, i) => {
                      if (i % labelStep !== 0 && i !== histogramData.length - 1) return null;
                      const x = Y_AXIS_W + i * barW + barW / 2;
                      if (isHourly) {
                        const p = d.day.split(" ");
                        const dateParts = (p[0] || "").split("-");
                        const label = dateParts.length === 3 ? `${dateParts[1]}/${dateParts[2]} ${p[1] || ""}:00` : d.day;
                        return <text key={`xl-${i}`} x={x} y={svgH - 2} textAnchor="middle" fill={textColor} fontSize={7} fontFamily="-apple-system,sans-serif">{label}</text>;
                      }
                      const parts = d.day.split("-");
                      const label = parts.length === 3 ? `${parts[1]}/${parts[2]}` : d.day;
                      return <text key={`xl-${i}`} x={x} y={svgH - 2} textAnchor="middle" fill={textColor} fontSize={8} fontFamily="-apple-system,sans-serif">{label}</text>;
                    })}
                  </>);
                })()}
              </svg>
            ) : (
              <div style={{ height: svgH, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>Loading histogram...</span>
              </div>
            )}
            {/* Drag handle */}
            <div onMouseDown={onHistResizeStart} style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: 6, cursor: "row-resize", zIndex: 2 }}>
              <div style={{ width: 36, height: 3, borderRadius: 2, background: th.textMuted + "55", margin: "2px auto 0" }} />
            </div>
          </div>
        );
      })()}

      {/* Content area */}
      {isImporting ? (
        <ImportProgress info={importingTabs[ct.id]} />
      ) : ct && ct.dataReady ? (
        <>
          {/* Grid */}
          <div style={{ flex: 1, overflow: "auto", position: "relative", WebkitAppRegion: "no-drag", contain: "layout style paint", willChange: "transform" }} ref={scrollRef} onScroll={handleScroll}>
            {/* Indexing overlay — blocks interaction while column/search indexes build */}
            {ct && ct.dataReady && !ct.indexesReady && (
              <div style={{ position: "absolute", inset: 0, zIndex: 50, background: (th.bg || "#0d1117") + "e6", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, backdropFilter: "blur(6px)", WebkitBackdropFilter: "blur(6px)" }}
                onClick={(e) => e.stopPropagation()} onMouseDown={(e) => e.stopPropagation()}>
                {/* Animated shield icon */}
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke={th.accent || "#58a6ff"} strokeWidth="1.5" style={{ animation: "tle-pulse 2s ease-in-out infinite" }}>
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill={(th.accent || "#58a6ff") + "18"} />
                  <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                <div style={{ color: th.text, fontSize: 15, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>
                  Building Indexes
                </div>
                <div style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif", textAlign: "center", maxWidth: 320, lineHeight: 1.5 }}>
                  {ct.indexesTotal
                    ? `Column indexes: ${ct.indexesBuilt || 0} / ${ct.indexesTotal}`
                    : "Preparing column indexes..."}
                </div>
                {/* Progress bar */}
                {ct.indexesTotal > 0 && (
                  <div style={{ width: 220, height: 4, borderRadius: 2, background: (th.textMuted || "#484f58") + "33", overflow: "hidden" }}>
                    <div style={{ height: "100%", borderRadius: 2, background: th.accent || "#58a6ff", transition: "width 0.3s ease", width: `${Math.round(((ct.indexesBuilt || 0) / ct.indexesTotal) * 100)}%` }} />
                  </div>
                )}
                <div style={{ color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif", marginTop: 4 }}>
                  Search index will build next. Please wait...
                </div>
              </div>
            )}
            {/* FTS overlay — shown after column indexes finish, while search index builds */}
            {ct && ct.dataReady && ct.indexesReady && ct.ftsTotal > 0 && !ct.ftsReady && (
              <div style={{ position: "absolute", inset: 0, zIndex: 50, background: (th.bg || "#0d1117") + "e6", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, backdropFilter: "blur(6px)", WebkitBackdropFilter: "blur(6px)" }}
                onClick={(e) => e.stopPropagation()} onMouseDown={(e) => e.stopPropagation()}>
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke={th.accent || "#58a6ff"} strokeWidth="1.5" style={{ animation: "tle-pulse 2s ease-in-out infinite" }}>
                  <circle cx="11" cy="11" r="8" fill={(th.accent || "#58a6ff") + "18"} />
                  <path d="M21 21l-4.35-4.35" strokeLinecap="round" />
                </svg>
                <div style={{ color: th.text, fontSize: 15, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>
                  Building Search Index
                </div>
                <div style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif", textAlign: "center", maxWidth: 320, lineHeight: 1.5 }}>
                  {`${Math.round((ct.ftsIndexed / ct.ftsTotal) * 100)}% — ${(ct.ftsIndexed || 0).toLocaleString()} / ${ct.ftsTotal.toLocaleString()} rows`}
                </div>
                <div style={{ width: 220, height: 4, borderRadius: 2, background: (th.textMuted || "#484f58") + "33", overflow: "hidden" }}>
                  <div style={{ height: "100%", borderRadius: 2, background: th.accent || "#58a6ff", transition: "width 0.3s ease", width: `${Math.round(((ct.ftsIndexed || 0) / ct.ftsTotal) * 100)}%` }} />
                </div>
                <div style={{ color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif", marginTop: 4 }}>
                  Almost there...
                </div>
              </div>
            )}
            <div style={{ minWidth: tw }}>
              {/* Header */}
              <div style={{ display: "flex", position: "sticky", top: 0, zIndex: 10, background: th.headerBg, borderBottom: `2px solid ${th.borderAccent}` }}>
                {/* # column - always sticky */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: BKMK_COL_WIDTH, minWidth: BKMK_COL_WIDTH, height: HEADER_HEIGHT, color: th.textMuted, fontSize: 10, fontWeight: 600, position: "sticky", left: 0, zIndex: 13, background: th.headerBg }}>#</div>
                {/* Tags column header — sticky, resizable, standard style */}
                <div
                  onClick={(e) => { if (e.metaKey || e.ctrlKey) { e.preventDefault(); e.stopPropagation(); setContextMenu({ x: e.clientX, y: e.clientY, colName: "__tags__" }); return; } handleSort("__tags__"); }}
                  onDoubleClick={() => { clearTimeout(sortTimerRef.current); }}
                  onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); setContextMenu({ x: e.clientX, y: e.clientY, colName: "__tags__" }); }}
                  style={{ display: "flex", alignItems: "center", height: HEADER_HEIGHT, width: tagColWidth, minWidth: tagColWidth, boxSizing: "border-box", padding: "0 8px", cursor: "pointer", userSelect: "none", fontWeight: 600, color: th.headerText, fontSize: 11, borderRight: `1px solid ${th.border}`, position: "sticky", left: BKMK_COL_WIDTH, zIndex: 12, background: th.headerBg, overflow: "hidden" }}>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>Tags</span>
                  {ct.sortCol === "__tags__" && <span style={{ fontSize: 9, color: th.accent, marginLeft: 3 }}>{ct.sortDir === "asc" ? "▲" : "▼"}</span>}
                  <div onMouseDown={(e) => {
                    e.preventDefault(); e.stopPropagation();
                    const startX = e.clientX, startW = tagColWidth;
                    const onMove = (ev) => setTagColWidth(Math.max(TAG_COL_WIDTH_MIN, startW + ev.clientX - startX));
                    const onUp = () => { document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
                    document.addEventListener("mousemove", onMove);
                    document.addEventListener("mouseup", onUp);
                  }}
                    onDoubleClick={(e) => { e.preventDefault(); e.stopPropagation(); }}
                    style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize" }} />
                </div>
                {/* Pinned columns */}
                {pinnedH.map((h) => (
                  <div key={h} data-col-header={h} draggable onDragStart={(e) => { if (e.button === 2) { e.preventDefault(); return; } e.dataTransfer.setData("text/column-name", h); e.dataTransfer.effectAllowed = "move"; }}
                    onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; setHeaderDragOver(h); }}
                    onDragLeave={() => setHeaderDragOver((prev) => prev === h ? null : prev)}
                    onDrop={(e) => { e.preventDefault(); e.stopPropagation(); setHeaderDragOver(null); const src = e.dataTransfer.getData("text/column-name"); if (src && src !== h) reorderColumn(src, h); }}
                    onClick={(e) => { if (e.metaKey || e.ctrlKey) { e.preventDefault(); e.stopPropagation(); setContextMenu({ x: e.clientX, y: e.clientY, colName: h }); return; } handleSort(h); }}
                    onDoubleClick={() => handleHeaderDblClick(h)}
                    onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); setContextMenu({ x: e.clientX, y: e.clientY, colName: h }); }}
                    style={{ display: "flex", alignItems: "center", height: HEADER_HEIGHT, width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 8px", cursor: "pointer", userSelect: "none", fontWeight: 600, color: th.headerText, fontSize: 11, borderRight: h === pinnedH[pinnedH.length - 1] ? `2px solid ${th.borderAccent}` : `1px solid ${th.border}`, position: "sticky", left: pinnedOffsets.offsets[h], zIndex: 12, background: headerDragOver === h ? th.selection : th.headerBg, overflow: "hidden" }}>
                    <span onClick={(e) => { e.stopPropagation(); unpinColumn(h); }} style={{ fontSize: 8, marginRight: 3, cursor: "pointer", opacity: 0.7, flexShrink: 0 }} title="Unpin">📌</span>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{h}</span>
                    {ct.tsColumns.has(h) && <span style={{ fontSize: 8, marginRight: 2, opacity: 0.7 }}>⏱</span>}
                    {ct.sortCol === h && <span style={{ fontSize: 9, color: th.accent, marginLeft: 3 }}>{ct.sortDir === "asc" ? "▲" : "▼"}</span>}
                    <div onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); setResizingCol(h); setResizeX(e.clientX); setResizeW(gw(h)); }}
                      onDoubleClick={(e) => { e.preventDefault(); e.stopPropagation(); autoFitColumn(h); }}
                      style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize", background: resizingCol === h ? th.borderAccent : "transparent" }} />
                  </div>
                ))}
                {/* Scrollable columns */}
                {scrollH.map((h) => (
                  <div key={h} data-col-header={h} draggable onDragStart={(e) => { if (e.button === 2) { e.preventDefault(); return; } e.dataTransfer.setData("text/column-name", h); e.dataTransfer.effectAllowed = "move"; }}
                    onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; setHeaderDragOver(h); }}
                    onDragLeave={() => setHeaderDragOver((prev) => prev === h ? null : prev)}
                    onDrop={(e) => { e.preventDefault(); e.stopPropagation(); setHeaderDragOver(null); const src = e.dataTransfer.getData("text/column-name"); if (src && src !== h) reorderColumn(src, h); }}
                    onClick={(e) => { if (e.metaKey || e.ctrlKey) { e.preventDefault(); e.stopPropagation(); setContextMenu({ x: e.clientX, y: e.clientY, colName: h }); return; } handleSort(h); }}
                    onDoubleClick={() => handleHeaderDblClick(h)}
                    onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); setContextMenu({ x: e.clientX, y: e.clientY, colName: h }); }}
                    style={{ display: "flex", alignItems: "center", height: HEADER_HEIGHT, width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 8px", cursor: "pointer", userSelect: "none", fontWeight: 600, color: th.headerText, fontSize: 11, borderRight: `1px solid ${th.border}`, position: "relative", overflow: "hidden", background: headerDragOver === h ? th.selection : undefined }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{h}</span>
                    {ct.tsColumns.has(h) && <span style={{ fontSize: 8, marginRight: 2, opacity: 0.7 }}>⏱</span>}
                    {ct.sortCol === h && <span style={{ fontSize: 9, color: th.accent, marginLeft: 3 }}>{ct.sortDir === "asc" ? "▲" : "▼"}</span>}
                    <div onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); setResizingCol(h); setResizeX(e.clientX); setResizeW(gw(h)); }}
                      onDoubleClick={(e) => { e.preventDefault(); e.stopPropagation(); autoFitColumn(h); }}
                      style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize", background: resizingCol === h ? th.borderAccent : "transparent" }} />
                  </div>
                ))}
              </div>

              {/* Filters */}
              <div style={{ display: "flex", position: "sticky", top: HEADER_HEIGHT, zIndex: 10, background: th.bg, borderBottom: `1px solid ${th.border}` }}>
                {/* # filter placeholder */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: BKMK_COL_WIDTH, minWidth: BKMK_COL_WIDTH, height: FILTER_HEIGHT, position: "sticky", left: 0, zIndex: 11, background: th.bg }}>
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" /></svg>
                </div>
                {/* Tags filter cell — standard layout with text input + dropdown */}
                {(() => {
                  const hasCbf = ct.tagFilter && (Array.isArray(ct.tagFilter) ? ct.tagFilter.length > 0 : true);
                  const hasTextFilter = !!(ct.columnFilters["__tags__"]);
                  const hasFilter = !!(hasTextFilter || hasCbf);
                  const isDis = ct.disabledFilters?.has("__tags__");
                  return (
                    <div style={{ width: tagColWidth, minWidth: tagColWidth, boxSizing: "border-box", padding: "0 2px", display: "flex", alignItems: "center", height: FILTER_HEIGHT, borderRight: `1px solid ${th.border}`, position: "sticky", left: BKMK_COL_WIDTH, zIndex: 11, background: th.bg }}>
                      {hasFilter && <button onClick={() => { const s = new Set(ct.disabledFilters || []); if (s.has("__tags__")) s.delete("__tags__"); else s.add("__tags__"); up("disabledFilters", s); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "1px 2px", color: isDis ? th.danger : th.success, fontSize: 9, flexShrink: 0, lineHeight: 1, opacity: 0.8 }} title={isDis ? "Enable filter" : "Disable filter"}>{isDis ? "⊘" : "⊙"}</button>}
                      <input value={ct.columnFilters["__tags__"] || ""} onChange={(e) => up("columnFilters", { ...ct.columnFilters, "__tags__": e.target.value })} placeholder="Filter..."
                        style={{ flex: 1, background: th.bgInput, border: `1px solid ${hasCbf ? th.borderAccent : th.border}`, borderRadius: 3, color: th.text, fontSize: 10, padding: "2px 4px", outline: "none", fontFamily: "inherit", minWidth: 0, opacity: isDis ? 0.4 : 1, textDecoration: isDis ? "line-through" : "none" }} />
                      <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setFilterDropdown(filterDropdown?.colName === "__tags__" ? null : { colName: "__tags__", x: rect.left, y: rect.bottom + 2 }); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 3px", color: hasCbf ? th.borderAccent : th.textDim, fontSize: 12, flexShrink: 0, lineHeight: 1 }} title="Filter by tags">▼</button>
                    </div>
                  );
                })()}
                {/* Pinned filter cells */}
                {pinnedH.map((h) => {
                  const hasCbf = ct.checkboxFilters?.[h]?.length > 0;
                  const isTs = ct.tsColumns?.has(h);
                  const hasDr = ct.dateRangeFilters?.[h];
                  const hasFilter = !!(ct.columnFilters[h] || hasCbf);
                  const isDis = ct.disabledFilters?.has(h);
                  return (
                    <div key={h} style={{ width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 2px", display: "flex", alignItems: "center", height: FILTER_HEIGHT, borderRight: h === pinnedH[pinnedH.length - 1] ? `2px solid ${th.borderAccent}` : `1px solid ${th.border}`, position: "sticky", left: pinnedOffsets.offsets[h], zIndex: 11, background: th.bg }}>
                      {hasFilter && <button onClick={() => { const s = new Set(ct.disabledFilters || []); if (s.has(h)) s.delete(h); else s.add(h); up("disabledFilters", s); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "1px 2px", color: isDis ? th.danger : th.success, fontSize: 9, flexShrink: 0, lineHeight: 1, opacity: 0.8 }} title={isDis ? "Enable filter" : "Disable filter"}>{isDis ? "⊘" : "⊙"}</button>}
                      <input value={ct.columnFilters[h] || ""} onChange={(e) => up("columnFilters", { ...ct.columnFilters, [h]: e.target.value })} placeholder="Filter..."
                        style={{ flex: 1, background: th.bgInput, border: `1px solid ${hasCbf ? th.borderAccent : th.border}`, borderRadius: 3, color: th.text, fontSize: 10, padding: "2px 4px", outline: "none", fontFamily: "inherit", minWidth: 0, opacity: isDis ? 0.4 : 1, textDecoration: isDis ? "line-through" : "none" }} />
                      {isTs && <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setDateRangeDropdown(dateRangeDropdown?.colName === h ? null : { colName: h, x: rect.left, y: rect.bottom + 2, from: hasDr?.from || "", to: hasDr?.to || "" }); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 2px", color: hasDr ? th.warning : th.textMuted, fontSize: 9, flexShrink: 0, lineHeight: 1 }} title="Date range filter">⏱</button>}
                      <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setFilterDropdown(filterDropdown?.colName === h ? null : { colName: h, x: rect.left, y: rect.bottom + 2 }); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 3px", color: hasCbf ? th.borderAccent : th.textDim, fontSize: 12, flexShrink: 0, lineHeight: 1 }} title="Filter by values">▼</button>
                    </div>
                  );
                })}
                {/* Scrollable filter cells */}
                {scrollH.map((h) => {
                  const hasCbf = ct.checkboxFilters?.[h]?.length > 0;
                  const isTs = ct.tsColumns?.has(h);
                  const hasDr = ct.dateRangeFilters?.[h];
                  const hasFilter = !!(ct.columnFilters[h] || hasCbf);
                  const isDis = ct.disabledFilters?.has(h);
                  return (
                    <div key={h} style={{ width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 2px", display: "flex", alignItems: "center", height: FILTER_HEIGHT, borderRight: `1px solid ${th.border}` }}>
                      {hasFilter && <button onClick={() => { const s = new Set(ct.disabledFilters || []); if (s.has(h)) s.delete(h); else s.add(h); up("disabledFilters", s); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "1px 2px", color: isDis ? th.danger : th.success, fontSize: 9, flexShrink: 0, lineHeight: 1, opacity: 0.8 }} title={isDis ? "Enable filter" : "Disable filter"}>{isDis ? "⊘" : "⊙"}</button>}
                      <input value={ct.columnFilters[h] || ""} onChange={(e) => up("columnFilters", { ...ct.columnFilters, [h]: e.target.value })} placeholder="Filter..."
                        style={{ flex: 1, background: th.bgInput, border: `1px solid ${hasCbf ? th.borderAccent : th.border}`, borderRadius: 3, color: th.text, fontSize: 10, padding: "2px 4px", outline: "none", fontFamily: "inherit", minWidth: 0, opacity: isDis ? 0.4 : 1, textDecoration: isDis ? "line-through" : "none" }} />
                      {isTs && <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setDateRangeDropdown(dateRangeDropdown?.colName === h ? null : { colName: h, x: rect.left, y: rect.bottom + 2, from: hasDr?.from || "", to: hasDr?.to || "" }); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 2px", color: hasDr ? th.warning : th.textMuted, fontSize: 9, flexShrink: 0, lineHeight: 1 }} title="Date range filter">⏱</button>}
                      <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setFilterDropdown(filterDropdown?.colName === h ? null : { colName: h, x: rect.left, y: rect.bottom + 2 }); }}
                        style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 3px", color: hasCbf ? th.borderAccent : th.textDim, fontSize: 12, flexShrink: 0, lineHeight: 1 }} title="Filter by values">▼</button>
                    </div>
                  );
                })}
              </div>

              {/* Virtual rows */}
              <div style={{ height: totalH, position: "relative" }}>
                {visible.map((item, vi) => {
                  const ai = si + vi;

                  // ── Grouped mode: group header ──
                  if (isGrouped && item.type === "group") {
                    const isExpanded = ct.expandedGroups?.[item.pathKey] !== undefined;
                    const indent = (item.depth || 0) * 20 + 12;
                    return (
                      <div key={`g-${item.pathKey}`} onClick={() => isExpanded ? collapseGroup(item.pathKey) : expandGroup(item.pathKey, item.filters, item.depth + 1)}
                        style={{ display: "flex", alignItems: "center", height: ROW_HEIGHT, position: "absolute", top: ai * ROW_HEIGHT, width: tw, background: th.bgAlt, cursor: "pointer", borderBottom: `1px solid ${th.border}`, paddingLeft: indent, gap: 8 }}>
                        <span style={{ color: th.accent, fontSize: 10, width: 14, textAlign: "center", flexShrink: 0 }}>{isExpanded ? "▼" : "▶"}</span>
                        <span style={{ color: th.text, fontSize: 12, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{item.colName}:</span>
                        <span style={{ color: th.text, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>{item.value || "(empty)"}</span>
                        <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>— {formatNumber(item.count)} rows</span>
                      </div>
                    );
                  }

                  // ── Grouped mode: "load more" indicator ──
                  if (isGrouped && item.type === "more") {
                    const indent = (item.depth || 0) * 20 + 32;
                    const remaining = item.total - item.loaded;
                    return (
                      <div key={`m-${item.pathKey}`} style={{ height: ROW_HEIGHT, position: "absolute", top: ai * ROW_HEIGHT, display: "flex", alignItems: "center", paddingLeft: indent, color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif", gap: 8 }}>
                        <span style={{ fontStyle: "italic" }}>Showing {formatNumber(item.loaded)} of {formatNumber(item.total)}</span>
                        <button onClick={() => loadMoreGroupRows(item.pathKey, false)}
                          style={{ background: th.accent + "22", color: th.accent, border: `1px solid ${th.accent}44`, borderRadius: 3, padding: "1px 8px", fontSize: 10, cursor: "pointer", fontFamily: "inherit" }}>
                          Load more ({formatNumber(Math.min(remaining, 100000))})</button>
                        {remaining > 100000 && <button onClick={() => loadMoreGroupRows(item.pathKey, true)}
                          style={{ background: th.warning + "22", color: th.warning, border: `1px solid ${th.warning}44`, borderRadius: 3, padding: "1px 8px", fontSize: 10, cursor: "pointer", fontFamily: "inherit" }}>
                          Load all ({formatNumber(remaining)})</button>}
                      </div>
                    );
                  }

                  // ── Data row (both grouped and ungrouped) ──
                  const rowDepth = isGrouped ? (item.depth || 0) : 0;
                  const row = isGrouped ? item.data : item;
                  if (!row || !row.__idx) return null;
                  const rTags = ct.rowTags[row.__idx] || [];
                  const cm = applyColors(row, compiledColors);
                  const bm = ct.bookmarkedSet?.has(row.__idx);
                  const sel = selectedRows.has(ai);
                  const rowBg = getRowBg(ai, row, sel, cm, bm);

                  // Opaque base for sticky cells (selection/bookmark overlays are semi-transparent)
                  const stickyBase = cm ? cm.bg : (ai % 2 === 0 ? th.rowEven : th.rowOdd);
                  const stickyOverlay = sel ? `inset 0 0 0 9999px ${th.selection}` : bm ? `inset 0 0 0 9999px ${th.bookmark}` : "none";

                  return (
                    <div key={row.__idx} data-row-id={row.__idx} data-row-index={ai} onClick={(e) => handleRowClick(ai, e)}
                      onContextMenu={(e) => { e.preventDefault(); setRowContextMenu({ x: e.clientX, y: e.clientY, rowId: row.__idx, rowIndex: ai, currentTags: rTags, row }); }}
                      style={{ display: "flex", height: ROW_HEIGHT, position: "absolute", top: ai * ROW_HEIGHT, width: tw,
                        background: rowBg, color: cm ? cm.fg : th.text, borderBottom: `1px solid ${th.cellBorder}`,
                        boxShadow: sel ? `inset 2px 0 0 0 ${th.borderAccent}` : "none", cursor: "default",
                        paddingLeft: isGrouped ? rowDepth * 20 + 16 : 0 }}>
                      {/* Bookmark - always sticky */}
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: isGrouped ? 26 : BKMK_COL_WIDTH, minWidth: isGrouped ? 26 : BKMK_COL_WIDTH, cursor: "pointer", position: "sticky", left: isGrouped ? 16 : 0, zIndex: 3, background: stickyBase, boxShadow: stickyOverlay }}
                        onClick={(e) => { e.stopPropagation(); handleBookmark(row.__idx); }}>
                        <BkmkIcon filled={bm} />
                      </div>
                      {/* Tags cell — sticky */}
                      <div style={{ display: "flex", alignItems: "center", gap: 2, width: tagColWidth, minWidth: tagColWidth, padding: "0 4px", overflow: "hidden", borderRight: `1px solid ${th.cellBorder}`, position: "sticky", left: isGrouped ? 42 : BKMK_COL_WIDTH, zIndex: 2, background: stickyBase, boxShadow: stickyOverlay }}>
                        {rTags.map((tag) => (
                          <span key={tag} style={{ padding: "0 4px", borderRadius: 3, fontSize: 9, background: ((ct.tagColors || {})[tag] || th.textMuted) + "33", color: (ct.tagColors || {})[tag] || th.textDim, whiteSpace: "nowrap", lineHeight: "16px" }}>{tag}</span>
                        ))}
                      </div>
                      {/* Pinned data cells */}
                      {pinnedH.map((h) => (
                        <div key={h} data-cell-col={h} onDoubleClick={() => setCellPopup({ column: h, value: row[h] || "" })} title={fmtCell(h, row[h])}
                          onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); setRowContextMenu({ x: e.clientX, y: e.clientY, rowId: row.__idx, rowIndex: ai, currentTags: rTags, row, cellColumn: h, cellValue: row[h] || "" }); }}
                          style={{ width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 8px", display: "flex", alignItems: "center", overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", borderRight: h === pinnedH[pinnedH.length - 1] ? `2px solid ${th.borderAccent}44` : `1px solid ${th.cellBorder}`, fontSize: fontSize - 0.5, position: "sticky", left: pinnedOffsets.offsets[h], zIndex: 2, background: stickyBase, boxShadow: stickyOverlay }}>
                          {renderCell(h, row[h])}
                        </div>
                      ))}
                      {/* Scrollable data cells */}
                      {scrollH.map((h) => (
                        <div key={h} data-cell-col={h} onDoubleClick={() => setCellPopup({ column: h, value: row[h] || "" })} title={fmtCell(h, row[h])}
                          onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); setRowContextMenu({ x: e.clientX, y: e.clientY, rowId: row.__idx, rowIndex: ai, currentTags: rTags, row, cellColumn: h, cellValue: row[h] || "" }); }}
                          style={{ width: gw(h), minWidth: gw(h), boxSizing: "border-box", padding: "0 8px", display: "flex", alignItems: "center", overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", borderRight: `1px solid ${th.cellBorder}`, fontSize: fontSize - 0.5 }}>
                          {renderCell(h, row[h])}
                        </div>
                      ))}
                    </div>
                  );
                })}
                {/* Skeleton placeholder rows shown during fast scroll when data is loading */}
                {skeletonIndices.length > 0 && skeletonIndices.map((ai) => (
                  <div key={`sk-${ai}`} style={{ display: "flex", alignItems: "center", height: ROW_HEIGHT, position: "absolute", top: ai * ROW_HEIGHT, width: tw, borderBottom: `1px solid ${th.cellBorder}`, background: ai % 2 === 0 ? th.rowEven : th.rowOdd, gap: 12, paddingLeft: BKMK_COL_WIDTH + tagColWidth + 8 }}>
                    <div style={{ width: 50, height: 8, background: th.border, borderRadius: 3 }} />
                    <div style={{ width: 130, height: 8, background: th.border, borderRadius: 3 }} />
                    <div style={{ width: 40, height: 8, background: th.border, borderRadius: 3 }} />
                    <div style={{ width: 90, height: 8, background: th.border, borderRadius: 3 }} />
                    <div style={{ width: 70, height: 8, background: th.border, borderRadius: 3 }} />
                    <div style={{ width: 180, height: 8, background: th.border, borderRadius: 3 }} />
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Row Detail Panel */}
          {detailVisible && (
            <div ref={detailPanelRef} style={{ height: detailPanelHeight, borderTop: `2px solid ${th.borderAccent}`, background: th.bg, display: "flex", flexDirection: "column", flexShrink: 0, position: "relative" }}>
              {/* Drag handle for resizing */}
              <div onMouseDown={onDetailResizeStart} style={{ position: "absolute", top: -4, left: 0, right: 0, height: 8, cursor: "row-resize", zIndex: 20 }} />
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "4px 12px", background: th.bgAlt, borderBottom: `1px solid ${th.border}`, flexShrink: 0 }}>
                <span style={{ color: th.accent, fontSize: 11, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>
                  Row Detail — Row {selectedRow + 1} (ID: {selectedRowData.__idx})
                </span>
                <button onClick={() => setDetailPanelOpen(false)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13, padding: "2px 6px" }}>✕</button>
              </div>
              <div style={{ flex: 1, overflow: "auto", padding: "4px 12px" }}>
                {ct.headers.map((h) => (
                  <div key={h} style={{ display: "flex", gap: 12, padding: "3px 0", borderBottom: `1px solid ${th.bgAlt}`, alignItems: "flex-start" }}>
                    <span style={{ width: 180, minWidth: 180, fontWeight: 600, color: ct.hiddenColumns.has(h) ? th.textMuted : th.textDim, fontSize: 11, flexShrink: 0, fontFamily: "-apple-system, sans-serif" }}>
                      {h}{ct.hiddenColumns.has(h) && <span style={{ fontSize: 9, marginLeft: 4, color: th.textMuted }}>(hidden)</span>}
                    </span>
                    <span style={{ flex: 1, color: th.text, fontSize: 11, fontFamily: "'SF Mono', Menlo, monospace", wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
                      {selectedRowData[h] || ""}
                    </span>
                    <button onClick={() => copyCell(selectedRowData[h])} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 10, flexShrink: 0, padding: "1px 4px" }} title="Copy value">
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Warning placeholder removed — no row cap */}
        </>
      ) : (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: th.textMuted }}>Loading...</div>
      )}

      {/* Status bar */}
      {ct && ct.dataReady && (
        <div style={{ display: "flex", justifyContent: "space-between", padding: "3px 12px", background: th.bgAlt, borderTop: `1px solid ${th.border}`, fontSize: 11, color: th.textDim, flexShrink: 0, fontFamily: "-apple-system, sans-serif" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ color: th.accent, fontWeight: 500, cursor: "pointer" }}
              title={ct.filePath ? `Double-click to copy: ${ct.filePath}` : ct.name}
              onDoubleClick={() => { if (ct.filePath) { navigator.clipboard.writeText(ct.filePath); setCopiedMsg(true); setTimeout(() => setCopiedMsg(false), 1200); } }}>
              {ct.name}
            </span>
            <Sdiv /><span>Total: <b>{formatNumber(ct.totalRows)}</b></span>
            {!isGrouped && <><Sdiv /><span>Filtered: <b style={{ color: ct.totalFiltered < ct.totalRows ? th.warning : th.success, opacity: searchLoading ? 0.5 : 1, transition: "opacity 0.15s" }}>{formatNumber(ct.totalFiltered)}</b>{searchLoading && <span style={{ color: th.accent, marginLeft: 3 }}>...</span>}</span></>}
            {!isGrouped && <><Sdiv /><span>Showing: <b>{formatNumber(ct.totalFiltered)}</b></span></>}
            {isGrouped && <><Sdiv /><span>Groups: <b style={{ color: th.accent }}>{ct.groupData?.length || 0}</b></span></>}
            {ct.bookmarkedSet?.size > 0 && <><Sdiv /><span>Flagged: <b style={{ color: th.warning }}>{ct.bookmarkedSet.size}</b></span></>}
            {ct.sortCol && ct.sortCol !== "__tags__" && <><Sdiv /><span>Sort: {ct.sortCol} {ct.sortDir === "asc" ? "↑" : "↓"}</span></>}
            {selectedRows.size > 0 && !isGrouped && <><Sdiv /><span>{selectedRows.size === 1 ? `Row: ${(lastClickedRow ?? 0) + 1}` : `${selectedRows.size} rows selected`}</span></>}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {copiedMsg && <span style={{ color: th.success }}>Copied!</span>}
            {pinnedH.length > 0 && <span>📌 {pinnedH.length}</span>}
            <span>{allVisH.length}/{ct.headers.length} cols</span>
            {ct.colorRules.length > 0 && <span>{ct.colorRules.length} color rule{ct.colorRules.length > 1 ? "s" : ""}</span>}
            {activeCheckboxCount > 0 && <span style={{ color: th.borderAccent }}>{activeCheckboxCount} value filter{activeCheckboxCount > 1 ? "s" : ""}</span>}
            {ct.tagFilter && <span style={{ color: th.danger }}>Tag filter ({Array.isArray(ct.tagFilter) ? ct.tagFilter.length : 1})</span>}
            {Object.keys(ct.dateRangeFilters || {}).length > 0 && <span style={{ color: th.warning }}>{Object.keys(ct.dateRangeFilters).length} date filter{Object.keys(ct.dateRangeFilters).length > 1 ? "s" : ""}</span>}
            {(ct.advancedFilters?.length > 0) && <span style={{ color: th.accent }}>{ct.advancedFilters.length} advanced filter{ct.advancedFilters.length > 1 ? "s" : ""}</span>}
            {ct.searchHighlight && ct.searchTerm && <span style={{ color: th.warning }}>Highlight mode</span>}
            {ct.iocHighlights?.length > 0 && <span onClick={() => up("iocHighlights", null)} style={{ color: "#f0883e", cursor: "pointer" }} title="IOC matches are highlighted — click to clear">IOC Highlights ({ct.iocHighlights.length}) ✕</span>}
            {ct._detectedProfile && <span style={{ color: th.success }}>{ct._detectedProfile}</span>}
            {totalActiveFilters > 0 && <span onClick={clearAllFilters} style={{ cursor: "pointer", color: th.danger || "#f85149", fontWeight: 600, textDecoration: "underline", textDecorationStyle: "dotted" }} title={`Clear all ${totalActiveFilters} active filter${totalActiveFilters > 1 ? "s" : ""}`}>Clear All ({totalActiveFilters})</span>}
            <span onClick={() => { if (ct?.dataReady) setModal({ type: "editFilter" }); }} style={{ cursor: ct?.dataReady ? "pointer" : "default", color: ct?.advancedFilters?.length > 0 ? th.accent : th.textMuted, textDecoration: ct?.dataReady ? "underline" : "none" }}>Edit Filter</span>
            <span style={{ color: th.textMuted }}>SQLite-backed</span>
          </div>
        </div>
      )}

      {/* Modals */}
      {/* Stacking / Value Frequency Analysis */}
      {modal?.type === "stacking" && ct && (() => {
        const colName = modal.colName;
        const data = modal.data || { totalRows: 0, totalUnique: 0, values: [] };
        const filterText = modal.filterText || "";
        const sortBy = modal.sortBy || "count";
        const mw = modal.modalWidth || 860;
        const vw = modal.valueColW || 420;
        const maxCnt = data.values.length > 0 ? (sortBy === "count" ? (data.values[0]?.cnt || 1) : Math.max(...data.values.map((d) => d.cnt), 1)) : 1;
        const displayed = filterText
          ? data.values.filter((v) => String(v.val ?? "").toLowerCase().includes(filterText.toLowerCase()))
          : data.values;
        // Drag helpers for column and modal resize
        const onValColResize = (e) => {
          e.preventDefault();
          const startX = e.clientX, startW = vw;
          document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
          const onMove = (ev) => { setModal((p) => p?.type === "stacking" ? { ...p, valueColW: Math.max(120, startW + ev.clientX - startX) } : p); };
          const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };
        const onModalResize = (e) => {
          e.preventDefault(); e.stopPropagation();
          const startX = e.clientX, startW = mw;
          document.body.style.cursor = "ew-resize"; document.body.style.userSelect = "none";
          const el = document.getElementById("stacking-modal");
          const onMove = (ev) => { const nw = Math.max(500, Math.min(window.innerWidth - 40, startW + (ev.clientX - startX) * 2)); if (el) el.style.width = nw + "px"; };
          const onUp = (ev) => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); const nw = Math.max(500, Math.min(window.innerWidth - 40, startW + (ev.clientX - startX) * 2)); setModal((p) => p?.type === "stacking" ? { ...p, modalWidth: nw } : p); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };
        const reloadStack = (col, sort) => {
          const af = activeFilters(ct);
          tle.getStackingData(ct.id, col, {
            searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
            columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
            bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
            sortBy: sort,
          }).then((result) => setModal((p) => p?.type === "stacking" ? { ...p, data: result, loading: false } : p))
            .catch(() => setModal((p) => p?.type === "stacking" ? { ...p, loading: false, data: { values: [], totalUnique: 0, totalRows: 0 } } : p));
        };
        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div id="stacking-modal" style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: mw, maxWidth: "96vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)", position: "relative" }}>
              {/* Right edge resize handle */}
              <div onMouseDown={onModalResize} style={{ position: "absolute", top: 12, bottom: 12, right: -3, width: 6, cursor: "ew-resize", zIndex: 1 }} />
              {/* Header — glass */}
              <div style={{ padding: "16px 20px 14px", borderBottom: `1px solid ${th.border}22`, flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}11)`, border: `1px solid ${th.accent}33`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.5" strokeLinecap="round"><line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="16" y2="12"/><line x1="4" y1="18" x2="10" y2="18"/></svg>
                    </div>
                    <div>
                      <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.3px" }}>Value Frequency Analysis</h3>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 2 }}>
                        <select value={colName} onChange={(e) => {
                          setModal((p) => ({ ...p, colName: e.target.value, loading: true, filterText: "" }));
                          reloadStack(e.target.value, sortBy);
                        }} style={{ background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.textDim, fontSize: 11, padding: "2px 6px", cursor: "pointer", outline: "none" }}>
                          {ct.headers.filter((h) => !ct.hiddenColumns?.has?.(h)).map((h) => <option key={h} value={h}>{h}</option>)}
                        </select>
                      </div>
                    </div>
                  </div>
                  <button onClick={() => setModal(null)} style={{ width: 24, height: 24, borderRadius: 12, background: th.textMuted + "15", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.15s" }}
                    onMouseEnter={(ev) => { ev.currentTarget.style.background = (th.danger || "#f85149") + "33"; ev.currentTarget.style.color = th.danger || "#f85149"; }}
                    onMouseLeave={(ev) => { ev.currentTarget.style.background = th.textMuted + "15"; ev.currentTarget.style.color = th.textMuted; }}>{"\u2715"}</button>
                </div>
                {/* Stats cards */}
                <div style={{ display: "flex", gap: 6, marginBottom: 12 }}>
                  {[
                    { val: data.totalUnique, label: "unique values", color: th.accent, icon: "M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2M9 5a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2M9 5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2" },
                    { val: data.totalRows, label: "total events", color: th.success || "#3fb950", icon: "M4 7h16M4 12h16M4 17h10" },
                  ].map((s, i) => (
                    <div key={i} style={{ flex: 1, padding: "10px 12px", borderRadius: 8, background: `radial-gradient(ellipse at 30% 0%, ${s.color}11, transparent 70%)`, border: `1px solid ${s.color}22`, position: "relative", overflow: "hidden" }}>
                      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg, transparent, ${s.color}33, transparent)` }} />
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={s.color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.6, flexShrink: 0 }}><path d={s.icon}/></svg>
                        <div>
                          <div style={{ fontSize: 16, fontWeight: 600, color: th.text, fontFamily: "'SF Mono',Menlo,monospace", letterSpacing: "-0.5px" }}>{formatNumber(s.val)}</div>
                          <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>{s.label}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                {/* Controls pill */}
                <div style={{ display: "flex", gap: 6, alignItems: "center", padding: "6px 10px", background: `${th.panelBg}88`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", borderRadius: 8, border: `1px solid ${th.border}33` }}>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2" strokeLinecap="round" style={{ flexShrink: 0 }}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                  <input autoFocus placeholder="Filter values..." value={filterText} onChange={(e) => setModal((p) => ({ ...p, filterText: e.target.value }))}
                    style={{ flex: 1, padding: "4px 6px", background: "transparent", border: "none", color: th.text, fontSize: 12, outline: "none", fontFamily: "inherit" }} />
                  <div style={{ width: 1, height: 16, background: th.border + "44" }} />
                  <button onClick={() => {
                    const ns = sortBy === "count" ? "value" : "count";
                    setModal((p) => ({ ...p, sortBy: ns, loading: true }));
                    reloadStack(colName, ns);
                  }} style={{ padding: "3px 10px", background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.textDim, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
                    {sortBy === "count" ? "Count \u2193" : "A\u2192Z"}
                  </button>
                  <button onClick={() => {
                    const lines = ["Value\tCount\tPercent"];
                    for (const v of displayed) {
                      const p = data.totalRows > 0 ? ((v.cnt / data.totalRows) * 100).toFixed(2) : "0";
                      lines.push(`${v.val ?? "(empty)"}\t${v.cnt}\t${p}%`);
                    }
                    navigator.clipboard.writeText(lines.join("\n"));
                  }} style={{ padding: "3px 10px", background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.textDim, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
                    Copy
                  </button>
                </div>
              </div>
              {/* Table header */}
              <div style={{ display: "flex", padding: "6px 20px", borderBottom: `1px solid ${th.border}33`, background: `${th.bgAlt}cc`, fontSize: 9, color: th.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system,sans-serif" }}>
                <span style={{ width: 40, flexShrink: 0, textAlign: "right", paddingRight: 10 }}>#</span>
                <span style={{ width: vw, flexShrink: 0, position: "relative" }}>
                  Value
                  <div onMouseDown={onValColResize} style={{ position: "absolute", right: -4, top: 0, bottom: 0, width: 8, cursor: "col-resize" }}>
                    <div style={{ position: "absolute", right: 3, top: 2, bottom: 2, width: 2, background: th.border, borderRadius: 1 }} />
                  </div>
                </span>
                <span style={{ width: 90, flexShrink: 0, textAlign: "right" }}>Count</span>
                <span style={{ width: 50, flexShrink: 0, textAlign: "right" }}>%</span>
                <span style={{ flex: 1, paddingLeft: 12 }}>Distribution</span>
              </div>
              {/* Scrollable rows */}
              <div style={{ flex: 1, overflow: "auto", minHeight: 0 }}>
                {modal.loading ? (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 40, flexDirection: "column", gap: 8 }}>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.5" strokeLinecap="round"><line x1="4" y1="6" x2="20" y2="6" opacity="0.3"/><line x1="4" y1="12" x2="16" y2="12" opacity="0.5"/><line x1="4" y1="18" x2="10" y2="18" opacity="0.7"/></svg>
                    <span style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>Loading...</span>
                  </div>
                ) : displayed.length === 0 ? (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 40 }}>
                    <span style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>{filterText ? "No matching values" : "No data"}</span>
                  </div>
                ) : displayed.map((v, i) => {
                  const pct = data.totalRows > 0 ? (v.cnt / data.totalRows) * 100 : 0;
                  const barPct = sortBy === "count" ? (v.cnt / maxCnt) * 100 : pct;
                  const valStr = v.val == null || v.val === "" ? "(empty)" : String(v.val);
                  const isRare = pct < 1;
                  return (
                    <div key={i}
                      onClick={() => {
                        const val = v.val == null || v.val === "" ? "" : String(v.val);
                        const existing = { ...(ct.checkboxFilters || {}) };
                        existing[colName] = [val];
                        up("checkboxFilters", existing);
                        setModal(null);
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg + "88"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                      style={{ display: "flex", alignItems: "center", padding: "5px 20px", cursor: "pointer", borderBottom: `1px solid ${th.border}15`, fontSize: 12, transition: "background 0.1s" }}>
                      <span style={{ width: 40, flexShrink: 0, textAlign: "right", paddingRight: 10, color: th.textMuted, fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>{i + 1}</span>
                      <span style={{ width: vw, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: isRare ? th.accent : th.text, fontWeight: isRare ? 500 : 400 }} title={valStr}>{valStr}</span>
                      <span style={{ width: 90, flexShrink: 0, textAlign: "right", color: th.text, fontWeight: 500, fontFamily: "'SF Mono',Menlo,monospace", fontSize: 11 }}>{formatNumber(v.cnt)}</span>
                      <span style={{ width: 50, flexShrink: 0, textAlign: "right", color: th.textDim, fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>{pct.toFixed(1)}%</span>
                      <div style={{ flex: 1, paddingLeft: 12 }}>
                        <div style={{ height: 12, background: th.border + "22", borderRadius: 6, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${Math.max(1, barPct)}%`, background: isRare ? `linear-gradient(90deg, ${th.danger || "#f85149"}CC, ${th.danger || "#f85149"}88)` : `linear-gradient(90deg, ${th.accent}BB, ${th.accent}66)`, borderRadius: 6, transition: "width 0.2s", boxShadow: isRare ? `0 0 6px ${th.danger || "#f85149"}33` : "none" }} />
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
              {/* Footer — glass */}
              <div style={{ padding: "10px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)", fontSize: 11, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                <span>{filterText ? `${formatNumber(displayed.length)} of ${formatNumber(data.totalUnique)} values shown` : `${formatNumber(data.totalUnique)} unique values`}{data.truncated ? <span style={{ color: th.warning, marginLeft: 6 }}>(top 10k)</span> : ""}</span>
                <span style={{ color: th.textDim, fontSize: 10 }}>Click row to filter</span>
              </div>
            </div>
          </div>
        );
      })()}
      {/* Column Stats Modal */}
      {modal?.type === "columnStats" && ct && (() => {
        const colName = modal.colName;
        const data = modal.data;
        const isTs = ct.tsColumns?.has(colName);
        const isNum = ct.numericColumns?.has(colName);
        const fmtSpan = (ms) => {
          if (ms == null) return "";
          const s = Math.floor(ms / 1000);
          const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
          if (d > 0) return `${d}d ${h}h ${m}m`;
          if (h > 0) return `${h}h ${m}m`;
          return `${m}m`;
        };
        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 520, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
              <div style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Column Statistics</h3>
                  <span style={{ color: th.accent, fontSize: 12 }}>{colName}</span>
                  {isTs && <span style={{ marginLeft: 6, fontSize: 9, color: th.textMuted, textTransform: "uppercase" }}>Timestamp</span>}
                  {isNum && <span style={{ marginLeft: 6, fontSize: 9, color: th.textMuted, textTransform: "uppercase" }}>Numeric</span>}
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px" }}>{"\u2715"}</button>
              </div>
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
                {modal.loading ? (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 40, color: th.textMuted, fontSize: 12 }}>Calculating...</div>
                ) : data && (<>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 16 }}>
                    {[
                      { label: "Total", value: formatNumber(data.totalRows) },
                      { label: "Unique", value: formatNumber(data.uniqueCount) },
                      { label: "Empty", value: formatNumber(data.emptyCount) },
                      { label: "Fill Rate", value: `${data.fillRate}%` },
                    ].map((c) => (
                      <div key={c.label} style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 8, padding: "10px 12px", textAlign: "center" }}>
                        <div style={{ fontSize: 18, fontWeight: 700, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{c.value}</div>
                        <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginTop: 2, fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
                      </div>
                    ))}
                  </div>
                  {isTs && data.tsStats && (
                    <div style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 8, padding: "10px 14px", marginBottom: 12 }}>
                      <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", marginBottom: 6 }}>Time Range</div>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>
                        <span>{data.tsStats.earliest}</span>
                        <span style={{ color: th.textDim }}>to</span>
                        <span>{data.tsStats.latest}</span>
                      </div>
                      {data.tsStats.timespanMs != null && (
                        <div style={{ fontSize: 11, color: th.accent, marginTop: 4, textAlign: "center" }}>Span: {fmtSpan(data.tsStats.timespanMs)}</div>
                      )}
                    </div>
                  )}
                  {isNum && data.numStats && (
                    <div style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 8, padding: "10px 14px", marginBottom: 12 }}>
                      <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", marginBottom: 6 }}>Numeric Range</div>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, textAlign: "center" }}>
                        {[{ label: "Min", value: data.numStats.min }, { label: "Avg", value: data.numStats.avg }, { label: "Max", value: data.numStats.max }].map((s) => (
                          <div key={s.label}>
                            <div style={{ fontSize: 14, fontWeight: 600, color: th.text, fontFamily: "'SF Mono',Menlo,monospace" }}>{s.value}</div>
                            <div style={{ fontSize: 9, color: th.textMuted }}>{s.label}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", marginBottom: 6 }}>Top {data.topValues.length} Values</div>
                  {data.topValues.map((v, i) => {
                    const pct = data.totalRows > 0 ? (v.cnt / data.totalRows) * 100 : 0;
                    const maxCnt = data.topValues[0]?.cnt || 1;
                    const barPct = (v.cnt / maxCnt) * 100;
                    return (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", fontSize: 11 }}>
                        <span style={{ width: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, flexShrink: 0 }} title={v.val}>{v.val || "(empty)"}</span>
                        <div style={{ flex: 1, height: 14, background: th.border + "44", borderRadius: 3, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${Math.max(1, barPct)}%`, background: th.accent + "99", borderRadius: 3 }} />
                        </div>
                        <span style={{ width: 60, textAlign: "right", color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", flexShrink: 0 }}>{formatNumber(v.cnt)}</span>
                        <span style={{ width: 48, textAlign: "right", color: th.textMuted, fontSize: 10, flexShrink: 0 }}>{pct.toFixed(1)}%</span>
                      </div>
                    );
                  })}
                </>)}
              </div>
              <div style={{ padding: "10px 20px", borderTop: `1px solid ${th.border}`, display: "flex", justifyContent: "flex-end" }}>
                <button onClick={() => setModal(null)} style={ms.bs}>Close</button>
              </div>
            </div>
          </div>
        );
      })()}
      {/* Filter Presets Modal */}
      {modal?.type === "presets" && ct && (() => {
        const BUILTIN_PRESETS = [
          { name: "Lateral Movement", builtin: true, searchTerm: "psexec OR wmi OR schtasks OR winrm OR rdp", searchMode: "or" },
          { name: "Persistence Mechanisms", builtin: true, searchTerm: "Run OR RunOnce OR schtasks OR service OR Startup", searchMode: "or" },
          { name: "Credential Access", builtin: true, searchTerm: "mimikatz OR lsass OR credential OR sekurlsa OR kerberos", searchMode: "or" },
          { name: "Encoded Commands", builtin: true, searchTerm: "-encodedcommand OR -enc OR FromBase64", searchMode: "or" },
          { name: "Suspicious Execution", builtin: true, searchTerm: "powershell OR cmd.exe OR wscript OR cscript OR mshta OR certutil OR bitsadmin", searchMode: "or" },
          { name: "Data Exfiltration", builtin: true, searchTerm: "ftp OR curl OR wget OR Invoke-WebRequest OR compress OR archive OR rar", searchMode: "or" },
          { name: "Defense Evasion", builtin: true, searchTerm: "del OR wevtutil OR Clear-EventLog OR Disable-WindowsOptionalFeature OR Set-MpPreference", searchMode: "or" },
          { name: "Discovery", builtin: true, searchTerm: "whoami OR ipconfig OR net user OR systeminfo OR nltest OR tasklist OR netstat", searchMode: "or" },
        ];
        const presetSummary = (p) => {
          const parts = [];
          if (p.searchTerm) parts.push(`search: "${p.searchTerm.length > 40 ? p.searchTerm.slice(0, 40) + "..." : p.searchTerm}"`);
          const cf = Object.keys(p.columnFilters || {}).filter((k) => p.columnFilters[k]);
          if (cf.length) parts.push(`${cf.length} col filter${cf.length > 1 ? "s" : ""}`);
          const cb = Object.keys(p.checkboxFilters || {}).filter((k) => p.checkboxFilters[k]?.length);
          if (cb.length) parts.push(`${cb.length} value filter${cb.length > 1 ? "s" : ""}`);
          const dr = Object.keys(p.dateRangeFilters || {}).length;
          if (dr) parts.push(`${dr} date range${dr > 1 ? "s" : ""}`);
          if (p.showBookmarkedOnly) parts.push("flagged only");
          const af = (p.advancedFilters || []).length;
          if (af) parts.push(`${af} advanced filter${af > 1 ? "s" : ""}`);
          if (p.sortCol) parts.push(`sort: ${p.sortCol} ${p.sortDir || "asc"}`);
          if (p.searchHighlight) parts.push("highlight mode");
          return parts.join(" · ") || "no filters";
        };
        const applyPreset = (preset) => {
          if (preset.searchTerm !== undefined) up("searchTerm", preset.searchTerm);
          if (preset.searchMode) up("searchMode", preset.searchMode);
          if (preset.searchCondition) up("searchCondition", preset.searchCondition);
          if (preset.searchHighlight !== undefined) up("searchHighlight", preset.searchHighlight);
          if (preset.columnFilters) up("columnFilters", preset.columnFilters);
          if (preset.checkboxFilters) up("checkboxFilters", preset.checkboxFilters);
          if (preset.dateRangeFilters) up("dateRangeFilters", preset.dateRangeFilters);
          if (preset.showBookmarkedOnly !== undefined) up("showBookmarkedOnly", preset.showBookmarkedOnly);
          if (preset.sortCol !== undefined) up("sortCol", preset.sortCol);
          if (preset.sortDir) up("sortDir", preset.sortDir);
          if (preset.tagFilter !== undefined) up("tagFilter", preset.tagFilter);
          if (preset.advancedFilters) up("advancedFilters", preset.advancedFilters);
          setModal(null);
        };
        const savePreset = (name) => {
          if (!name.trim()) return;
          const preset = {
            name: name.trim(), savedAt: new Date().toISOString(),
            searchTerm: ct.searchTerm || "", searchMode: ct.searchMode || "mixed",
            searchCondition: ct.searchCondition || "contains", searchHighlight: ct.searchHighlight || false,
            columnFilters: ct.columnFilters || {}, checkboxFilters: ct.checkboxFilters || {},
            dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [], showBookmarkedOnly: ct.showBookmarkedOnly || false,
            sortCol: ct.sortCol || null, sortDir: ct.sortDir || "asc", tagFilter: ct.tagFilter || null,
          };
          const updated = [...filterPresets, preset];
          setFilterPresets(updated);
          tle.saveFilterPresets(updated);
        };
        const deletePreset = (idx) => {
          const updated = filterPresets.filter((_, i) => i !== idx);
          setFilterPresets(updated);
          tle.saveFilterPresets(updated);
        };
        const clearFilters = () => {
          up("searchTerm", ""); up("searchMode", "mixed"); up("searchCondition", "contains");
          up("searchHighlight", false); up("columnFilters", {}); up("checkboxFilters", {});
          up("dateRangeFilters", {}); up("showBookmarkedOnly", false);
          up("sortCol", null); up("sortDir", "asc"); up("tagFilter", null);
          up("disabledFilters", new Set()); up("advancedFilters", []);
          setModal(null);
        };
        return (
          <Overlay>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Filter Presets</h3>
              <button onClick={clearFilters}
                style={{ padding: "4px 10px", background: th.danger + "22", border: `1px solid ${th.danger}44`, color: th.danger, borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system,sans-serif" }}>
                Clear All Filters
              </button>
            </div>
            {/* Save current */}
            <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
              <input id="preset-name-input" placeholder="Save current filters as..."
                onKeyDown={(e) => { if (e.key === "Enter" && e.target.value.trim()) { savePreset(e.target.value); e.target.value = ""; } }}
                style={{ flex: 1, padding: "7px 10px", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, outline: "none", fontFamily: "inherit" }} />
              <button onClick={() => {
                const inp = document.getElementById("preset-name-input");
                if (inp?.value?.trim()) { savePreset(inp.value); inp.value = ""; }
              }} style={ms.bp}>Save</button>
            </div>
            {/* User presets */}
            {filterPresets.length > 0 && (
              <>
                <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system,sans-serif" }}>Saved Presets</div>
                <div style={{ maxHeight: "30vh", overflow: "auto", marginBottom: 14 }}>
                  {filterPresets.map((p, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 0", borderBottom: `1px solid ${th.border}33` }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ color: th.text, fontSize: 12, fontWeight: 500 }}>{p.name}</div>
                        <div style={{ color: th.textMuted, fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{presetSummary(p)}</div>
                      </div>
                      <button onClick={() => applyPreset(p)}
                        style={{ padding: "3px 10px", background: th.accent + "22", border: `1px solid ${th.accent}44`, color: th.accent, borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
                        Apply
                      </button>
                      <button onClick={() => deletePreset(i)}
                        style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 12, padding: "0 4px" }}>✕</button>
                    </div>
                  ))}
                </div>
              </>
            )}
            {/* Built-in DFIR presets */}
            <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system,sans-serif" }}>DFIR Quick Filters</div>
            <div style={{ maxHeight: "30vh", overflow: "auto" }}>
              {BUILTIN_PRESETS.map((p, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 0", borderBottom: `1px solid ${th.border}22` }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ color: th.text, fontSize: 12, fontWeight: 500 }}>{p.name}</div>
                    <div style={{ color: th.textMuted, fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{presetSummary(p)}</div>
                  </div>
                  <button onClick={() => applyPreset(p)}
                    style={{ padding: "3px 10px", background: th.accent + "22", border: `1px solid ${th.accent}44`, color: th.accent, borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
                    Apply
                  </button>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
              <button onClick={() => setModal(null)} style={ms.bs}>Close</button>
            </div>
          </Overlay>
        );
      })()}
      {modal?.type === "colors" && ct && <ColorModal />}
      {modal?.type === "columns" && ct && <ColModal />}
      {modal?.type === "shortcuts" && <ShortModal />}
      {modal?.type === "sheets" && <SheetModal />}
      {modal?.type === "tags" && ct && (
        <Overlay>
          <h3 style={ms.mh}>Manage Tags</h3>
          <div style={{ maxHeight: "50vh", overflow: "auto", marginBottom: 12 }}>
            {Object.entries(ct.tagColors || {}).map(([tag, color]) => (
              <div key={tag} style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 0", borderBottom: `1px solid ${th.bgAlt}` }}>
                <input type="color" value={color} onChange={(e) => up("tagColors", { ...ct.tagColors, [tag]: e.target.value })}
                  style={{ width: 20, height: 16, border: "none", cursor: "pointer", borderRadius: 3, padding: 0 }} />
                <span style={{ flex: 1, color: th.text, fontSize: 12 }}>{tag}</span>
                <button onClick={() => { const tc = { ...ct.tagColors }; delete tc[tag]; up("tagColors", tc); }}
                  style={{ background: "none", border: "none", color: th.danger, cursor: "pointer", fontSize: 12 }}>✕</button>
              </div>
            ))}
          </div>
          <div style={{ display: "flex", gap: 6 }}>
            <input id="new-tag-input" placeholder="New tag name..." style={ms.ip} onKeyDown={(e) => {
              if (e.key === "Enter" && e.target.value.trim()) {
                const name = e.target.value.trim();
                if (!ct.tagColors[name]) up("tagColors", { ...ct.tagColors, [name]: "#8b949e" });
                e.target.value = "";
              }
            }} />
            <button onClick={() => {
              const inp = document.getElementById("new-tag-input");
              const name = inp?.value?.trim();
              if (name && !ct.tagColors[name]) { up("tagColors", { ...ct.tagColors, [name]: "#8b949e" }); inp.value = ""; }
            }} style={ms.bp}>Add</button>
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
            <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
          </div>
        </Overlay>
      )}

      {/* Cross-tab Find */}
      {modal?.type === "crossfind" && (
        <Overlay>
          <h3 style={ms.mh}>Find Across All Tabs</h3>
          <div style={{ display: "flex", gap: 6, marginBottom: 12 }}>
            <input id="cf-input" autoFocus defaultValue={crossFind?.term || ""} placeholder="Search term..."
              onKeyDown={(e) => { if (e.key === "Enter") handleCrossFind(e.target.value); }}
              style={{ flex: 1, background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, padding: "8px 10px", outline: "none", fontFamily: "inherit" }} />
            <button onClick={() => { const v = document.getElementById("cf-input")?.value; if (v) handleCrossFind(v); }}
              style={ms.bp}>Search</button>
          </div>
          {crossFind?.results && (
            <div style={{ maxHeight: "50vh", overflow: "auto" }}>
              {crossFind.results.length === 0 && <p style={{ color: th.textMuted, fontSize: 12 }}>No tabs open</p>}
              {crossFind.results.map((r) => (
                <div key={r.tabId}
                  onClick={() => {
                    if (r.count > 0) {
                      setActiveTab(r.tabId);
                      setTabs((prev) => prev.map((t) => t.id === r.tabId ? { ...t, searchTerm: crossFind.term, searchMode: "mixed" } : t));
                      setModal(null);
                    }
                  }}
                  style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 10px", borderBottom: `1px solid ${th.bgAlt}`,
                    cursor: r.count > 0 ? "pointer" : "default", borderRadius: 4 }}
                  onMouseEnter={(e) => { if (r.count > 0) e.currentTarget.style.background = th.btnBg; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
                  <span style={{ color: r.count > 0 ? th.text : th.textMuted, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 300 }}>{r.name}</span>
                  <span style={{ color: r.count > 0 ? th.success : th.textMuted, fontSize: 12, fontWeight: 600, flexShrink: 0, marginLeft: 12 }}>
                    {r.count > 0 ? `${formatNumber(r.count)} hits` : "0"}
                  </span>
                </div>
              ))}
              <div style={{ marginTop: 8, color: th.textMuted, fontSize: 11 }}>
                Total: {formatNumber(crossFind.results.reduce((s, r) => s + r.count, 0))} matches across {crossFind.results.filter((r) => r.count > 0).length} tab{crossFind.results.filter((r) => r.count > 0).length !== 1 ? "s" : ""}
              </div>
            </div>
          )}
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
            <button onClick={() => setModal(null)} style={ms.bs}>Close</button>
          </div>
        </Overlay>
      )}

      {/* Temporal Proximity Search Modal */}
      {modal?.type === "proximity" && ct && (() => {
        const { pivotRow, pivotCol } = modal;
        const tsCols = [...(ct.tsColumns || new Set())];
        const selCol = modal.selCol ?? pivotCol ?? tsCols[0];
        const customN = modal.customN ?? 5;
        const customU = modal.customU ?? "m";
        const pivotVal = pivotRow?.[selCol] ?? "";
        const PROX_PRESETS = [
          { label: "±30s", ms: 30_000, short: "30s" },
          { label: "±1m", ms: 60_000, short: "1m" },
          { label: "±5m", ms: 300_000, short: "5m" },
          { label: "±15m", ms: 900_000, short: "15m" },
          { label: "±30m", ms: 1_800_000, short: "30m" },
          { label: "±1h", ms: 3_600_000, short: "1h" },
          { label: "±4h", ms: 14_400_000, short: "4h" },
          { label: "±1d", ms: 86_400_000, short: "1d" },
        ];
        const unitMs = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
        const customMs = (Number(customN) || 0) * (unitMs[customU] || 60_000);
        return (
          <Overlay>
            <h3 style={ms.mh}>Find Nearby Events</h3>
            <div style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 6, padding: "8px 10px", marginBottom: 12 }}>
              <div style={{ ...ms.lb, marginBottom: 2 }}>Pivot Timestamp</div>
              <div style={{ color: th.text, fontSize: 12, fontFamily: "'SF Mono',Menlo,monospace", wordBreak: "break-all" }}>
                {pivotVal || <span style={{ color: th.textMuted, fontStyle: "italic" }}>(empty — select a timestamp column)</span>}
              </div>
            </div>
            {tsCols.length > 1 && (
              <div style={ms.fg}>
                <label style={ms.lb}>Timestamp Column</label>
                <select value={selCol} onChange={(e) => setModal((p) => ({ ...p, selCol: e.target.value }))} style={ms.sl}>
                  {tsCols.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
            )}
            <div style={ms.fg}>
              <label style={ms.lb}>Time Window</label>
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 4 }}>
                {PROX_PRESETS.map((p) => (
                  <button key={p.label} disabled={!pivotVal}
                    onClick={() => applyProximity(selCol, pivotVal, p.ms, p.short)}
                    onMouseEnter={(e) => { if (pivotVal) e.currentTarget.style.borderColor = th.accent; }}
                    onMouseLeave={(e) => { e.currentTarget.style.borderColor = th.btnBorder; }}
                    style={{ padding: "5px 12px", background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 5, color: pivotVal ? th.text : th.textMuted, fontSize: 12, cursor: pivotVal ? "pointer" : "not-allowed", fontFamily: "-apple-system,sans-serif", transition: "border-color 0.15s" }}>
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
            <div style={ms.fg}>
              <label style={ms.lb}>Custom Window</label>
              <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 4 }}>
                <span style={{ color: th.textDim, fontSize: 12 }}>±</span>
                <input type="number" min="1" value={customN}
                  onChange={(e) => setModal((p) => ({ ...p, customN: e.target.value }))}
                  style={{ ...ms.ip, width: 70 }} />
                <select value={customU} onChange={(e) => setModal((p) => ({ ...p, customU: e.target.value }))} style={{ ...ms.sl, width: 100 }}>
                  <option value="s">seconds</option>
                  <option value="m">minutes</option>
                  <option value="h">hours</option>
                  <option value="d">days</option>
                </select>
                <button disabled={!pivotVal || customMs <= 0}
                  onClick={() => applyProximity(selCol, pivotVal, customMs, `${customN}${customU}`)}
                  style={{ ...ms.bp, opacity: (!pivotVal || customMs <= 0) ? 0.5 : 1, cursor: (!pivotVal || customMs <= 0) ? "not-allowed" : "pointer" }}>
                  Apply
                </button>
              </div>
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 6 }}>
              <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
            </div>
          </Overlay>
        );
      })()}

      {/* Known-Bad IOC Matching Modal */}
      {modal?.type === "ioc" && ct && (() => {
        const phase = modal.phase || "load";
        const iocText = modal.iocText || "";
        const iocName = modal.iocName || "";
        const parsedIocs = modal.parsedIocs || [];
        const fileName = modal.fileName || null;
        const loading = modal.loading || false;
        const results = modal.results || null;
        const error = modal.error || null;
        const scanProgress = modal.scanProgress || null; // { stage, current, total, label }

        const categories = parsedIocs.reduce((acc, ioc) => { acc[ioc.category] = (acc[ioc.category] || 0) + 1; return acc; }, {});
        const defaultName = fileName ? fileName.replace(/\.(txt|csv|ioc|tsv|xlsx|xls)$/i, "") : "IOC Match";
        const effectiveName = (iocName || defaultName || "IOC Match").trim();
        const tagName = `IOC: ${effectiveName}`;

        const handleLoadFile = async () => {
          const result = await tle.loadIocFile();
          if (!result || result.error) return;
          const parsed = parseIocText(result.content);
          // Show defanged IOCs in textarea so analyst can verify
          const defangedText = parsed.map((i) => i.raw).join("\n");
          setModal((p) => ({ ...p, iocText: defangedText, fileName: result.fileName,
            iocName: p.iocName || result.fileName.replace(/\.(txt|csv|ioc|tsv|xlsx|xls)$/i, ""), parsedIocs: parsed }));
        };

        const handlePasteChange = (text) => {
          const parsed = parseIocText(text);
          setModal((p) => ({ ...p, iocText: text, parsedIocs: parsed }));
        };

        const handleScan = async () => {
          if (parsedIocs.length === 0 || !ct) return;
          setModal((p) => ({ ...p, loading: true, error: null, scanProgress: { stage: "scan", current: 0, total: parsedIocs.length, label: "Scanning database..." } }));
          try {
            const escapedPatterns = parsedIocs.map((ioc) => escapeIocForRegex(ioc.raw));

            // Batch IOC scanning for progress — process in chunks of 20 for smoother updates
            const BATCH = 20;
            const mergedRowIds = new Set();
            const mergedPerIocCounts = {};
            const mergedPerRowIocs = {};
            const totalBatches = Math.ceil(escapedPatterns.length / BATCH);

            for (let b = 0; b < totalBatches; b++) {
              const start = b * BATCH;
              const batchPatterns = escapedPatterns.slice(start, start + BATCH);
              const batchParsed = parsedIocs.slice(start, start + BATCH);

              setModal((p) => p?.type === "ioc" ? ({ ...p, scanProgress: { stage: "scan", current: Math.min(start + BATCH, escapedPatterns.length), total: escapedPatterns.length, label: `Scanning IOCs ${start + 1}–${Math.min(start + BATCH, escapedPatterns.length)} of ${escapedPatterns.length}...` } }) : p);

              // Yield to UI so progress bar re-renders
              await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));

              const { matchedRowIds, perIocCounts, perRowIocs } = await tle.matchIocs(ct.id, batchPatterns, 200);
              for (const id of matchedRowIds) mergedRowIds.add(id);
              for (let i = 0; i < batchPatterns.length; i++) {
                mergedPerIocCounts[escapedPatterns[start + i]] = perIocCounts[batchPatterns[i]] || 0;
              }
              for (const [rowId, indices] of Object.entries(perRowIocs || {})) {
                if (!mergedPerRowIocs[rowId]) mergedPerRowIocs[rowId] = [];
                // Remap batch-local indices to global indices
                for (const li of indices) mergedPerRowIocs[rowId].push(start + li);
              }
            }

            const allMatchedRowIds = [...mergedRowIds];

            // Phase 2: Tagging
            setModal((p) => p?.type === "ioc" ? ({ ...p, scanProgress: { stage: "tag", current: 0, total: 1, label: `Tagging ${allMatchedRowIds.length} matched rows...` } }) : p);
            await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));

            const allIocTags = new Set();
            if (allMatchedRowIds.length > 0) {
              const tagMap = {};
              const newTagColors = { ...ct.tagColors };
              for (const [rowIdStr, iocIndices] of Object.entries(mergedPerRowIocs || {})) {
                const rowId = Number(rowIdStr);
                tagMap[rowId] = iocIndices.map((i) => {
                  const iocTag = `IOC: ${parsedIocs[i].raw}`;
                  allIocTags.add(iocTag);
                  if (!newTagColors[iocTag]) newTagColors[iocTag] = "#f0883e";
                  return iocTag;
                });
              }
              await tle.bulkAddTags(ct.id, tagMap);
              up("tagColors", newTagColors);
            }

            // Phase 3: Highlights + refresh
            setModal((p) => p?.type === "ioc" ? ({ ...p, scanProgress: { stage: "refresh", current: 0, total: 1, label: "Refreshing data..." } }) : p);
            await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));

            const hitIocs = parsedIocs.filter((ioc, i) => (mergedPerIocCounts[escapedPatterns[i]] || 0) > 0).map((ioc) => ioc.raw);
            if (hitIocs.length > 0) {
              const prev = ct.iocHighlights || [];
              up("iocHighlights", [...new Set([...prev, ...hitIocs])]);
            }

            await fetchData(ct);

            const perIocResults = parsedIocs.map((ioc, i) => ({
              raw: ioc.raw, category: ioc.category, hits: mergedPerIocCounts[escapedPatterns[i]] || 0,
            })).sort((a, b) => b.hits - a.hits);

            setModal((p) => p?.type === "ioc" ? ({ ...p, phase: "results", loading: false, scanProgress: null,
              results: { matchedRowIds: allMatchedRowIds, matchedCount: allMatchedRowIds.length, tagName, allIocTags: [...allIocTags], perIocResults } }) : p);
          } catch (e) {
            setModal((p) => p?.type === "ioc" ? ({ ...p, loading: false, scanProgress: null, error: e.message }) : p);
          }
        };

        const foundCount = results ? results.perIocResults.filter((r) => r.hits > 0).length : 0;
        const missedCount = results ? results.perIocResults.filter((r) => r.hits === 0).length : 0;

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 580, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
              {/* Header */}
              <div style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Known-Bad IOC Matching</h3>
                  <p style={{ margin: "3px 0 0", color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>Load an IOC list and auto-tag every matching row</p>
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px" }}>✕</button>
              </div>

              {/* Body */}
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px", display: "flex", flexDirection: "column", gap: 14 }}>
                {phase === "load" && (<>
                  <div style={ms.fg}>
                    <label style={ms.lb}>IOC Set Name</label>
                    <input value={iocName} onChange={(e) => setModal((p) => ({ ...p, iocName: e.target.value }))} placeholder={defaultName} style={ms.ip} />
                    <span style={{ color: th.textMuted, fontSize: 10, marginTop: 3, display: "block" }}>Each matched IOC gets its own tag, e.g. <code style={{ color: th.accent }}>IOC: cmd.exe</code></span>
                  </div>
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <button onClick={handleLoadFile} style={ms.bp}>Load File (.txt / .csv / .xlsx / .tsv)</button>
                    <span style={{ color: th.textMuted, fontSize: 11 }}>or paste below</span>
                  </div>
                  <div style={ms.fg}>
                    <label style={ms.lb}>IOC List — one per line, # for comments{parsedIocs.length > 0 && <span style={{ color: th.success, marginLeft: 6 }}>{parsedIocs.length} IOCs parsed</span>}</label>
                    <textarea value={iocText} onChange={(e) => handlePasteChange(e.target.value)}
                      placeholder={"# Paste IOCs here — one per line\n192.168.1.1\nevil.example.com\nabc123def456...sha256hash\nC:\\malware\\payload.exe"} rows={10}
                      style={{ ...ms.ip, resize: "vertical", fontFamily: "'SF Mono', Menlo, monospace", fontSize: 11, lineHeight: 1.5 }} />
                  </div>
                  {parsedIocs.length > 0 && (
                    <div style={{ background: th.bgAlt, borderRadius: 6, padding: "10px 12px" }}>
                      <div style={{ ...ms.lb, marginBottom: 6 }}>Category Breakdown ({parsedIocs.length} unique)</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {Object.entries(categories).map(([cat, count]) => {
                          const clr = /^(IPv[46]|Domain|Email|URL|Crypto|User_Agent|Phone|Payment)/.test(cat) ? th.accent : /^(SHA|MD5)/.test(cat) ? th.warning : cat === "Other" ? th.textMuted : "#a78bfa";
                          return <span key={cat} style={{ padding: "2px 8px", background: `${clr}22`, border: `1px solid ${clr}44`, borderRadius: 4, fontSize: 11, color: clr, fontFamily: "-apple-system, sans-serif" }}>{cat.replace(/_/g, " ")}: {count}</span>;
                        })}
                      </div>
                    </div>
                  )}
                  {error && <div style={{ padding: "8px 12px", background: `${th.danger}22`, border: `1px solid ${th.danger}44`, borderRadius: 6, color: th.danger, fontSize: 12 }}>Error: {error}</div>}
                  {loading && scanProgress && (() => {
                    const pct = scanProgress.stage === "scan" ? Math.round((scanProgress.current / scanProgress.total) * 80)
                      : scanProgress.stage === "tag" ? 90 : 95;
                    return (
                    <div style={{ padding: "16px 0 8px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                        <span style={{ fontSize: 12, color: th.text, fontWeight: 500 }}>{scanProgress.label}</span>
                        <span style={{ fontSize: 11, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>
                          {scanProgress.stage === "scan" ? `${scanProgress.current}/${scanProgress.total}` : `${pct}%`}
                        </span>
                      </div>
                      <div style={{ width: "100%", height: 8, background: th.bgAlt, borderRadius: 4, overflow: "hidden", position: "relative" }}>
                        <div style={{
                          height: "100%", borderRadius: 4, transition: "width 0.3s ease-out",
                          width: `${pct}%`, position: "relative", overflow: "hidden",
                          background: `linear-gradient(90deg, ${th.accent}, ${th.warning})`,
                        }}>
                          {/* Animated shimmer overlay */}
                          <div style={{
                            position: "absolute", inset: 0,
                            background: "linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.25) 50%, transparent 100%)",
                            backgroundSize: "200% 100%",
                            animation: "iocShimmer 1.2s ease-in-out infinite",
                          }} />
                        </div>
                      </div>
                      <style>{`@keyframes iocShimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }`}</style>
                      <div style={{ display: "flex", justifyContent: "center", gap: 16, marginTop: 10 }}>
                        {["Scanning", "Tagging", "Refreshing"].map((step, i) => {
                          const stages = ["scan", "tag", "refresh"];
                          const si = stages.indexOf(scanProgress.stage);
                          const done = i < si;
                          const active = i === si;
                          return <span key={step} style={{ fontSize: 10, color: done ? th.success : active ? th.accent : th.textDim, fontWeight: active ? 600 : 400, transition: "color 0.3s" }}>{done ? "\u2713 " : active ? "\u25CF " : "\u25CB "}{step}</span>;
                        })}
                      </div>
                    </div>);
                  })()}
                </>)}

                {phase === "results" && results && (<>
                  <div style={{ display: "flex", gap: 8 }}>
                    <div style={{ flex: 1, padding: "10px 14px", background: results.matchedCount > 0 ? `${th.danger}22` : th.bgAlt, border: `1px solid ${results.matchedCount > 0 ? th.danger + "44" : th.border}`, borderRadius: 8, textAlign: "center" }}>
                      <div style={{ fontSize: 22, fontWeight: 700, color: results.matchedCount > 0 ? th.danger : th.textDim }}>{formatNumber(results.matchedCount)}</div>
                      <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>matching rows</div>
                    </div>
                    <div style={{ flex: 1, padding: "10px 14px", background: foundCount > 0 ? `${th.warning}22` : th.bgAlt, border: `1px solid ${foundCount > 0 ? th.warning + "44" : th.border}`, borderRadius: 8, textAlign: "center" }}>
                      <div style={{ fontSize: 22, fontWeight: 700, color: foundCount > 0 ? th.warning : th.textDim }}>{foundCount}</div>
                      <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>IOCs hit</div>
                    </div>
                    <div style={{ flex: 1, padding: "10px 14px", background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 8, textAlign: "center" }}>
                      <div style={{ fontSize: 22, fontWeight: 700, color: th.textDim }}>{missedCount}</div>
                      <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>IOCs not found</div>
                    </div>
                  </div>
                  {results.matchedCount > 0 && (
                    <div style={{ padding: "8px 12px", background: `${th.success}15`, border: `1px solid ${th.success}33`, borderRadius: 6, fontSize: 12, color: th.success }}>
                      Tagged {formatNumber(results.matchedCount)} rows with {results.allIocTags?.length || 0} per-IOC tags (e.g. <code style={{ background: `${th.success}22`, padding: "0 5px", borderRadius: 3 }}>IOC: {results.perIocResults?.find(r => r.hits > 0)?.raw || "..."}</code>)
                    </div>
                  )}
                  <div>
                    <div style={{ ...ms.lb, marginBottom: 6 }}>Per-IOC Results ({results.perIocResults.length} IOCs)</div>
                    <div style={{ maxHeight: 260, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                      {results.perIocResults.map((ioc, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 10px", borderBottom: `1px solid ${th.border}22`, background: i % 2 === 0 ? "transparent" : `${th.bgAlt}44` }}>
                          <span style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: ioc.hits > 0 ? th.danger : th.textMuted, opacity: ioc.hits > 0 ? 1 : 0.4 }} />
                          <span style={{ flex: 1, fontFamily: "'SF Mono', Menlo, monospace", fontSize: 11, color: ioc.hits > 0 ? th.text : th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={ioc.raw}>{ioc.raw}</span>
                          <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 3, flexShrink: 0, fontFamily: "-apple-system, sans-serif",
                            background: /^(IPv[46]|Domain|Email|URL|Crypto|User_Agent|Phone|Payment)/.test(ioc.category) ? `${th.accent}20` : /^(SHA|MD5)/.test(ioc.category) ? `${th.warning}20` : ioc.category === "Other" ? `${th.textMuted}20` : `#8b5cf620`,
                            color: /^(IPv[46]|Domain|Email|URL|Crypto|User_Agent|Phone|Payment)/.test(ioc.category) ? th.accent : /^(SHA|MD5)/.test(ioc.category) ? th.warning : ioc.category === "Other" ? th.textMuted : "#a78bfa",
                          }}>{ioc.category.replace(/_/g, " ")}</span>
                          <span style={{ fontWeight: 600, fontSize: 12, color: ioc.hits > 0 ? th.danger : th.textMuted, flexShrink: 0, minWidth: 40, textAlign: "right", fontFamily: "'SF Mono', Menlo, monospace" }}>{ioc.hits > 0 ? `+${formatNumber(ioc.hits)}` : "—"}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </>)}
              </div>

              {/* Footer */}
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                {phase === "load" && (<>
                  <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
                  <button disabled={parsedIocs.length === 0 || loading} onClick={handleScan}
                    style={{ ...ms.bp, opacity: parsedIocs.length === 0 || loading ? 0.5 : 1, cursor: parsedIocs.length === 0 || loading ? "not-allowed" : "pointer" }}>
                    {loading && scanProgress ? `${scanProgress.stage === "scan" ? Math.round((scanProgress.current / scanProgress.total) * 100) : scanProgress.stage === "tag" ? 90 : 95}% — ${scanProgress.label}` : loading ? `Scanning...` : `Scan ${parsedIocs.length > 0 ? parsedIocs.length + " IOCs" : ""}`}
                  </button>
                </>)}
                {phase === "results" && results && (<>
                  <button onClick={() => setModal((p) => ({ ...p, phase: "load" }))} style={ms.bs}>Back / Re-scan</button>
                  <div style={{ display: "flex", gap: 6 }}>
                    {results.matchedCount > 0 && (
                      <button onClick={() => { up("tagFilter", results.allIocTags || []); setModal(null); }} style={{ ...ms.bs, color: th.accent, borderColor: th.accent + "66" }}>Show Only IOC Matches</button>
                    )}
                    <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
                  </div>
                </>)}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Gap Analysis Modal */}
      {modal?.type === "gapAnalysis" && ct && (() => {
        const { phase, colName, gapThreshold, data } = modal;
        const tsCols = [...(ct.tsColumns || [])];

        const handleAnalyze = async () => {
          setModal((p) => ({ ...p, phase: "loading", loading: true, error: null }));
          try {
            const af = activeFilters(ct);
            const result = await tle.getGapAnalysis(ct.id, colName, gapThreshold, {
              searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
              searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
              columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
              bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
            });
            setModal((p) => p?.type === "gapAnalysis" ? ({ ...p, phase: "results", loading: false, data: result }) : p);
          } catch (e) {
            setModal((p) => p?.type === "gapAnalysis" ? ({ ...p, phase: "config", loading: false, error: e.message }) : p);
          }
        };

        const handleTagSessions = async () => {
          if (!data?.sessions?.length) return;
          setModal((p) => ({ ...p, tagging: true }));
          try {
            const ranges = data.sessions.map((s) => ({ from: s.from, to: s.to, tag: `Session ${s.idx}` }));
            const result = await tle.bulkTagByTimeRange(ct.id, colName, ranges);
            const sessionColors = ["#58a6ff", "#3fb950", "#a371f7", "#f0883e", "#d29922", "#da3633", "#f85149", "#8b949e"];
            const newTagColors = { ...ct.tagColors };
            for (const s of data.sessions) {
              const tag = `Session ${s.idx}`;
              if (!newTagColors[tag]) newTagColors[tag] = sessionColors[(s.idx - 1) % sessionColors.length];
            }
            up("tagColors", newTagColors);
            await fetchData(ct);
            setModal((p) => p?.type === "gapAnalysis" ? ({ ...p, tagging: false, tagged: true, taggedCount: result.taggedCount }) : p);
          } catch {
            setModal((p) => p?.type === "gapAnalysis" ? ({ ...p, tagging: false }) : p);
          }
        };

        const zoomTo = (from, to) => {
          const fromTs = from.length === 16 ? from + ":00" : from;
          const toTs = to.length === 16 ? to + ":59" : to;
          up("dateRangeFilters", { ...(ct.dateRangeFilters || {}), [colName]: { from: fromTs, to: toTs } });
          setModal(null);
        };

        const fmtDur = (mins) => {
          if (mins < 60) return `${mins}m`;
          if (mins < 1440) return `${Math.floor(mins / 60)}h ${mins % 60}m`;
          return `${Math.floor(mins / 1440)}d ${Math.floor((mins % 1440) / 60)}h`;
        };

        const rowStyle = (i) => ({
          display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 11,
          background: i % 2 === 0 ? "transparent" : th.rowAlt, cursor: "pointer",
          borderBottom: `1px solid ${th.border}22`, fontFamily: "'SF Mono',Menlo,monospace",
        });

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 600, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
              {/* Header */}
              <div style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Timeline Gap Analysis</h3>
                  <p style={{ margin: "3px 0 0", color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>Detect activity bursts and quiet periods</p>
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px" }}>✕</button>
              </div>

              {/* Body */}
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
                {/* Config phase */}
                {phase === "config" && (<>
                  <div style={ms.fg}>
                    <label style={ms.lb}>Timestamp Column</label>
                    <select value={colName} onChange={(e) => setModal((p) => ({ ...p, colName: e.target.value }))} style={ms.sl}>
                      {tsCols.map((c) => <option key={c} value={c}>{c}</option>)}
                    </select>
                  </div>
                  <div style={ms.fg}>
                    <label style={ms.lb}>Gap Threshold</label>
                    <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                      {[15, 30, 60, 120, 480].map((v) => (
                        <button key={v} onClick={() => setModal((p) => ({ ...p, gapThreshold: v }))}
                          style={{ padding: "5px 12px", background: gapThreshold === v ? th.accent : th.btnBg, color: gapThreshold === v ? "#fff" : th.text, border: `1px solid ${gapThreshold === v ? th.accent : th.btnBorder}`, borderRadius: 5, fontSize: 12, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>
                          {v < 60 ? `${v}m` : `${v / 60}h`}
                        </button>
                      ))}
                      <input type="number" min="1" value={gapThreshold} onChange={(e) => setModal((p) => ({ ...p, gapThreshold: Math.max(1, Number(e.target.value) || 60) }))}
                        style={{ ...ms.ip, width: 70 }} />
                      <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>minutes</span>
                    </div>
                  </div>
                  {modal.error && <div style={{ color: th.danger, fontSize: 11, padding: "8px 10px", background: `${th.danger}15`, borderRadius: 6, marginBottom: 10 }}>Error: {modal.error}</div>}
                </>)}

                {/* Loading phase */}
                {phase === "loading" && (
                  <div style={{ textAlign: "center", padding: 40 }}>
                    <div style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>Analyzing timeline for gaps &gt;{gapThreshold}m...</div>
                  </div>
                )}

                {/* Results phase */}
                {phase === "results" && data && (<>
                  {/* Summary cards */}
                  <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                    {[
                      { val: data.sessions.length, label: "sessions", color: th.accent },
                      { val: data.gaps.length, label: "gaps detected", color: th.warning || "#d29922" },
                      { val: data.totalEvents.toLocaleString(), label: "total events", color: th.textDim },
                    ].map((c, i) => (
                      <div key={i} style={{ flex: 1, textAlign: "center", padding: "12px 8px", background: th.panelBg, borderRadius: 8, border: `1px solid ${th.border}` }}>
                        <div style={{ fontSize: 22, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif" }}>{c.val}</div>
                        <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2, fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
                      </div>
                    ))}
                  </div>

                  {/* Sessions list */}
                  <div style={{ marginBottom: 14 }}>
                    <div style={ms.lb}>Sessions ({data.sessions.length})</div>
                    <div style={{ maxHeight: 200, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                      {data.sessions.map((s, i) => (
                        <div key={s.idx} style={rowStyle(i)} onClick={() => zoomTo(s.from, s.to)}
                          onMouseEnter={(e) => e.currentTarget.style.background = th.rowHover}
                          onMouseLeave={(e) => e.currentTarget.style.background = i % 2 === 0 ? "transparent" : th.rowAlt}>
                          <span style={{ padding: "1px 8px", borderRadius: 3, fontSize: 10, fontWeight: 600, color: "#fff", background: ["#58a6ff", "#3fb950", "#a371f7", "#f0883e", "#d29922", "#da3633", "#f85149", "#8b949e"][(s.idx - 1) % 8], fontFamily: "-apple-system, sans-serif" }}>Session {s.idx}</span>
                          <span style={{ color: th.textDim, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.from} — {s.to}</span>
                          <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{s.eventCount.toLocaleString()} events</span>
                          <span style={{ color: th.accent, fontSize: 10, fontWeight: 600, whiteSpace: "nowrap" }}>{fmtDur(s.durationMinutes)}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Gaps list */}
                  {data.gaps.length > 0 && (
                    <div style={{ marginBottom: 14 }}>
                      <div style={ms.lb}>Gaps ({data.gaps.length})</div>
                      <div style={{ maxHeight: 180, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                        {data.gaps.map((g, i) => (
                          <div key={i} style={rowStyle(i)} onClick={() => zoomTo(g.from, g.to)}
                            onMouseEnter={(e) => e.currentTarget.style.background = th.rowHover}
                            onMouseLeave={(e) => e.currentTarget.style.background = i % 2 === 0 ? "transparent" : th.rowAlt}>
                            <span style={{ color: th.danger || "#da3633", fontSize: 13 }}>&#x23F8;</span>
                            <span style={{ color: th.textDim, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{g.from} — {g.to}</span>
                            <span style={{ color: th.warning || "#d29922", fontSize: 11, fontWeight: 600, whiteSpace: "nowrap" }}>{fmtDur(g.durationMinutes)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Tagged confirmation */}
                  {modal.tagged && (
                    <div style={{ padding: "8px 12px", background: `${th.success || "#3fb950"}15`, border: `1px solid ${th.success || "#3fb950"}33`, borderRadius: 6, color: th.success || "#3fb950", fontSize: 11, fontFamily: "-apple-system, sans-serif", marginBottom: 10 }}>
                      Tagged {modal.taggedCount?.toLocaleString()} rows across {data.sessions.length} sessions
                    </div>
                  )}
                </>)}
              </div>

              {/* Footer */}
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                {phase === "config" && (<>
                  <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
                  <button onClick={handleAnalyze} style={ms.bp}>Analyze</button>
                </>)}
                {phase === "loading" && <span style={{ color: th.textMuted, fontSize: 11 }}>Scanning...</span>}
                {phase === "results" && (<>
                  <button onClick={() => setModal((p) => ({ ...p, phase: "config", data: null, tagged: false, taggedCount: 0 }))} style={ms.bs}>Back</button>
                  <div style={{ display: "flex", gap: 6 }}>
                    {!modal.tagged && data.sessions.length > 0 && (
                      <button onClick={handleTagSessions} disabled={modal.tagging} style={{ ...ms.bp, background: th.success || "#3fb950" }}>
                        {modal.tagging ? "Tagging..." : `Tag ${data.sessions.length} Sessions`}
                      </button>
                    )}
                    {modal.tagged && (
                      <button onClick={() => { up("tagFilter", "Session 1"); setModal(null); }}
                        style={{ ...ms.bs, color: th.accent, borderColor: th.accent + "66" }}>Show Session 1</button>
                    )}
                    <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
                  </div>
                </>)}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Cell Detail Popup */}
      {cellPopup && (
        <div onClick={() => setCellPopup(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, backdropFilter: "blur(4px)" }}>
          <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 560, maxWidth: "92vw", maxHeight: "80vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: `1px solid ${th.border}` }}>
              <span style={{ color: th.textDim, fontSize: 12, fontWeight: 600 }}>{cellPopup.column}</span>
              <div style={{ display: "flex", gap: 6 }}>
                <button onClick={() => copyCell(cellPopup.value)} style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 11, padding: "4px 10px", cursor: "pointer", display: "flex", alignItems: "center", gap: 4 }}>
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                  Copy
                </button>
                <button onClick={() => setCellPopup(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px", lineHeight: 1 }}>✕</button>
              </div>
            </div>
            <div style={{ padding: "16px", overflow: "auto", maxHeight: "calc(80vh - 50px)" }}>
              <pre style={{ color: th.text, fontSize: 12, fontFamily: "'SF Mono', Menlo, monospace", whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0, lineHeight: 1.5 }}>{cellPopup.value || <span style={{ color: th.textMuted, fontStyle: "italic" }}>(empty)</span>}</pre>
            </div>
          </div>
        </div>
      )}

      {/* Filter Dropdown */}
      {filterDropdown && (
        <>
          <div onClick={() => setFilterDropdown(null)} style={{ position: "fixed", inset: 0, zIndex: 199 }} />
          <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "fixed", left: filterDropdown.dx ?? Math.min(filterDropdown.x, window.innerWidth - 400), top: filterDropdown.dy ?? Math.min(filterDropdown.y, window.innerHeight - 440), width: 380, height: 420, minWidth: 260, minHeight: 200, maxWidth: "90vw", maxHeight: "90vh", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 8, boxShadow: "0 12px 28px rgba(0,0,0,0.5)", zIndex: 200, display: "flex", flexDirection: "column", overflow: "hidden", resize: "both" }}>
            <div style={{ padding: "4px 8px", flexShrink: 0, display: "flex", alignItems: "center", gap: 6, borderBottom: `1px solid ${th.border}`, cursor: "grab", userSelect: "none" }}
              onMouseDown={(e) => {
                if (e.button !== 0) return;
                e.preventDefault();
                const panel = e.currentTarget.parentElement;
                const rect = panel.getBoundingClientRect();
                const ox = e.clientX - rect.left, oy = e.clientY - rect.top;
                const onMove = (ev) => { setFilterDropdown((p) => p ? { ...p, dx: ev.clientX - ox, dy: ev.clientY - oy } : p); };
                const onUp = () => { document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
                document.addEventListener("mousemove", onMove);
                document.addEventListener("mouseup", onUp);
              }}>
              <span style={{ color: th.textDim, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif", flex: 1 }}>Filter — {filterDropdown.colName === "__tags__" ? "Tags" : filterDropdown.colName}</span>
              <button onClick={() => setFilterDropdown(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13, padding: "0 2px", lineHeight: 1 }}>✕</button>
            </div>
            <div style={{ padding: "8px 8px 4px", flexShrink: 0, display: "flex", gap: 4 }}>
              <input value={fdSearch} onChange={(e) => setFdSearch(e.target.value)} placeholder={fdRegex ? "Regex pattern..." : "Search values..."} autoFocus
                style={{ flex: 1, background: th.bgInput, border: `1px solid ${fdRegex && fdSearch ? (() => { try { new RegExp(fdSearch); return th.btnBorder; } catch { return th.danger; } })() : th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "5px 8px", outline: "none", fontFamily: "inherit", boxSizing: "border-box" }} />
              <button onClick={() => setFdRegex((v) => !v)} title="Toggle regex mode"
                style={{ padding: "3px 7px", background: fdRegex ? th.accentSubtle : th.btnBg, border: `1px solid ${fdRegex ? th.accent : th.btnBorder}`, borderRadius: 4, color: fdRegex ? th.accent : th.textMuted, fontSize: 11, cursor: "pointer", fontFamily: "monospace", fontWeight: 600, flexShrink: 0 }}>.*</button>
            </div>
            <div style={{ display: "flex", gap: 4, padding: "2px 8px 4px", flexShrink: 0 }}>
              <button onClick={() => setFdSelected(new Set(fdValues.map((v) => v.val)))} style={ms.bsm}>Select All</button>
              <button onClick={() => setFdSelected(new Set())} style={ms.bsm}>Clear</button>
              <span style={{ flex: 1 }} />
              <span style={{ color: th.textMuted, fontSize: 10, alignSelf: "center" }}>{fdValues.length} values</span>
            </div>
            <div style={{ flex: 1, overflow: "auto", padding: "0 4px" }}>
              {fdLoading ? (
                <div style={{ padding: 16, textAlign: "center", color: th.textMuted, fontSize: 11 }}>Loading...</div>
              ) : fdValues.length === 0 ? (
                <div style={{ padding: 16, textAlign: "center", color: th.textMuted, fontSize: 11 }}>No values found</div>
              ) : (
                fdValues.map((v) => (
                  <label key={v.val ?? "__empty"} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 4px", cursor: "pointer", borderRadius: 3, fontSize: 11, color: th.text }}>
                    <input type="checkbox" checked={fdSelected.has(v.val)} onChange={() => { const s = new Set(fdSelected); s.has(v.val) ? s.delete(v.val) : s.add(v.val); setFdSelected(s); }}
                      style={{ accentColor: th.borderAccent, flexShrink: 0 }} />
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.val || "(empty)"}</span>
                    <span style={{ color: th.textMuted, fontSize: 10, flexShrink: 0 }}>{formatNumber(v.cnt)}</span>
                  </label>
                ))
              )}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, padding: "6px 8px", borderTop: `1px solid ${th.border}` }}>
              <button onClick={() => {
                if (filterDropdown.colName === "__tags__") { up("tagFilter", null); setFilterDropdown(null); return; }
                const newCbf = { ...ct.checkboxFilters }; delete newCbf[filterDropdown.colName]; up("checkboxFilters", newCbf); setFilterDropdown(null);
              }} style={ms.bsm}>Reset</button>
              <button onClick={() => setFilterDropdown(null)} style={ms.bsm}>Cancel</button>
              <button onClick={applyCheckboxFilter} style={{ padding: "3px 10px", background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Apply</button>
            </div>
          </div>
        </>
      )}

      {/* Date Range Dropdown */}
      {dateRangeDropdown && (
        <>
          <div onClick={() => setDateRangeDropdown(null)} style={{ position: "fixed", inset: 0, zIndex: 199 }} />
          <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "fixed", left: Math.min(dateRangeDropdown.x, window.innerWidth - 300), top: Math.min(dateRangeDropdown.y, window.innerHeight - 220), width: 290, background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 8, boxShadow: "0 12px 28px rgba(0,0,0,0.5)", zIndex: 200, padding: 12 }}>
            <div style={{ color: th.textDim, fontSize: 10, marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" }}>Date Range — {dateRangeDropdown.colName}</div>
            <div style={{ marginBottom: 8 }}>
              <label style={{ display: "block", color: th.textMuted, fontSize: 10, marginBottom: 2, fontFamily: "-apple-system, sans-serif" }}>From</label>
              <input type="datetime-local" value={dateRangeDropdown.from} onChange={(e) => setDateRangeDropdown({ ...dateRangeDropdown, from: e.target.value })}
                style={{ width: "100%", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "4px 6px", outline: "none", fontFamily: "inherit", boxSizing: "border-box", colorScheme: themeName }} />
            </div>
            <div style={{ marginBottom: 10 }}>
              <label style={{ display: "block", color: th.textMuted, fontSize: 10, marginBottom: 2, fontFamily: "-apple-system, sans-serif" }}>To</label>
              <input type="datetime-local" value={dateRangeDropdown.to} onChange={(e) => setDateRangeDropdown({ ...dateRangeDropdown, to: e.target.value })}
                style={{ width: "100%", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "4px 6px", outline: "none", fontFamily: "inherit", boxSizing: "border-box", colorScheme: themeName }} />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 6 }}>
              <button onClick={() => {
                const newDrf = { ...ct.dateRangeFilters };
                delete newDrf[dateRangeDropdown.colName];
                up("dateRangeFilters", newDrf);
                setDateRangeDropdown(null);
              }} style={ms.bsm}>Clear</button>
              <button onClick={() => setDateRangeDropdown(null)} style={ms.bsm}>Cancel</button>
              <button onClick={() => {
                const newDrf = { ...ct.dateRangeFilters };
                if (dateRangeDropdown.from || dateRangeDropdown.to) {
                  newDrf[dateRangeDropdown.colName] = {};
                  if (dateRangeDropdown.from) newDrf[dateRangeDropdown.colName].from = dateRangeDropdown.from;
                  if (dateRangeDropdown.to) newDrf[dateRangeDropdown.colName].to = dateRangeDropdown.to;
                } else {
                  delete newDrf[dateRangeDropdown.colName];
                }
                up("dateRangeFilters", newDrf);
                setDateRangeDropdown(null);
              }} style={{ padding: "3px 10px", background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Apply</button>
            </div>
          </div>
        </>
      )}

      {/* Log Source Coverage Map Modal */}
      {modal?.type === "logSourceCoverage" && ct && (() => {
        const { phase, sourceCol, tsCol, data } = modal;
        const tsCols = [...(ct.tsColumns || [])];
        const sourcePatterns = /^(Provider|Channel|source|data_type|parser|log_source|EventLog|SourceName|Source|_Source|DataType|ArtifactName|sourcetype|SourceLong|SourceDescription)$/i;
        const knownSourceCols = ct.headers.filter((h) => sourcePatterns.test(h));
        const otherCols = ct.headers.filter((h) => !sourcePatterns.test(h) && !ct.tsColumns?.has(h));

        const handleAnalyze = async () => {
          setModal((p) => ({ ...p, phase: "loading", loading: true, error: null }));
          try {
            const af = activeFilters(ct);
            const result = await tle.getLogSourceCoverage(ct.id, sourceCol, tsCol, {
              searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
              searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
              columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
              bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
            });
            setModal((p) => p?.type === "logSourceCoverage" ? ({ ...p, phase: "results", loading: false, data: result, sortBy: "count" }) : p);
          } catch (e) {
            setModal((p) => p?.type === "logSourceCoverage" ? ({ ...p, phase: "config", loading: false, error: e.message }) : p);
          }
        };

        const filterBySource = (sourceValue) => {
          const existing = { ...(ct.checkboxFilters || {}) };
          existing[sourceCol] = [sourceValue];
          up("checkboxFilters", existing);
          setModal(null);
        };

        const parseTs = (ts) => {
          if (!ts) return NaN;
          const s = String(ts).trim();
          // Try ISO-like: "2024-11-05 18:31" → "2024-11-05T18:31"
          let d = new Date(s.replace(" ", "T"));
          if (!isNaN(d.getTime())) return d.getTime();
          // Try as-is
          d = new Date(s);
          if (!isNaN(d.getTime())) return d.getTime();
          // Try numeric epoch (seconds or ms)
          const n = Number(s);
          if (!isNaN(n) && n > 946684800) return n > 1e12 ? n : n * 1000;
          return NaN;
        };
        const fmtDur = (ms) => {
          if (!ms || isNaN(ms) || !isFinite(ms) || ms <= 0) return "\u2014";
          const mins = Math.round(ms / 60000);
          if (mins < 1) return "<1m";
          if (mins < 60) return `${mins}m`;
          if (mins < 1440) return `${Math.floor(mins / 60)}h ${mins % 60}m`;
          return `${Math.floor(mins / 1440)}d ${Math.floor((mins % 1440) / 60)}h`;
        };

        const rowStyle = (i) => ({
          display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 11,
          background: i % 2 === 0 ? "transparent" : `${th.border}15`, cursor: "pointer",
          borderBottom: `1px solid ${th.border}22`, fontFamily: "'SF Mono',Menlo,monospace",
        });

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 700, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
              {/* Header */}
              <div style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Log Source Coverage Map</h3>
                  <p style={{ margin: "3px 0 0", color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>Visualize evidence coverage across log sources</p>
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px" }}>✕</button>
              </div>

              {/* Body */}
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
                {phase === "config" && (<>
                  <div style={ms.fg}>
                    <label style={ms.lb}>Source Column</label>
                    <select value={sourceCol} onChange={(e) => setModal((p) => ({ ...p, sourceCol: e.target.value }))} style={ms.sl}>
                      {knownSourceCols.length > 0 && (
                        <optgroup label="Detected Source Columns">
                          {knownSourceCols.map((c) => <option key={c} value={c}>{c}</option>)}
                        </optgroup>
                      )}
                      <optgroup label={knownSourceCols.length > 0 ? "Other Columns" : "All Columns"}>
                        {otherCols.map((c) => <option key={c} value={c}>{c}</option>)}
                      </optgroup>
                    </select>
                  </div>
                  <div style={ms.fg}>
                    <label style={ms.lb}>Timestamp Column</label>
                    <select value={tsCol} onChange={(e) => setModal((p) => ({ ...p, tsCol: e.target.value }))} style={ms.sl}>
                      {tsCols.map((c) => <option key={c} value={c}>{c}</option>)}
                    </select>
                  </div>
                  {modal.error && <div style={{ color: th.danger, fontSize: 11, padding: "8px 10px", background: `${th.danger}15`, borderRadius: 6, marginBottom: 10 }}>Error: {modal.error}</div>}
                </>)}

                {phase === "loading" && (
                  <div style={{ textAlign: "center", padding: 40 }}>
                    <div style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>Analyzing log source coverage...</div>
                  </div>
                )}

                {phase === "results" && data && (() => {
                  const sortBy = modal.sortBy || "count";
                  const sorted = [...data.sources].sort((a, b) => {
                    if (sortBy === "name") return (a.source || "").localeCompare(b.source || "");
                    if (sortBy === "earliest") return (a.earliest || "").localeCompare(b.earliest || "");
                    if (sortBy === "duration") {
                      const durA = parseTs(a.latest) - parseTs(a.earliest);
                      const durB = parseTs(b.latest) - parseTs(b.earliest);
                      return durB - durA;
                    }
                    return b.cnt - a.cnt;
                  });

                  const gStart = parseTs(data.globalEarliest);
                  const gEnd = parseTs(data.globalLatest);
                  const gSpan = gEnd - gStart || 1;
                  const maxCnt = Math.max(...data.sources.map((s) => s.cnt), 1);
                  const BAR_H = 16;

                  const heatColor = (ratio) => {
                    const t = Math.max(0, Math.min(1, ratio));
                    const r = Math.round(30 + t * 202);
                    const g = Math.round(40 + t * 53);
                    const b = Math.round(56 - t * 14);
                    return `rgb(${r},${g},${b})`;
                  };

                  return (<>
                    {/* Summary cards */}
                    <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                      {[
                        { val: data.totalSources, label: "log sources", color: th.accent },
                        { val: formatNumber(data.totalEvents), label: "total events", color: th.textDim },
                        { val: fmtDur(gEnd - gStart), label: "time span", color: th.textDim },
                      ].map((c, i) => (
                        <div key={i} style={{ flex: 1, textAlign: "center", padding: "12px 8px", background: th.panelBg, borderRadius: 8, border: `1px solid ${th.border}` }}>
                          <div style={{ fontSize: 22, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif" }}>{c.val}</div>
                          <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2, fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
                        </div>
                      ))}
                    </div>

                    {/* Gantt chart */}
                    <div style={{ marginBottom: 14 }}>
                      <div style={ms.lb}>Coverage Timeline</div>
                      <div style={{ border: `1px solid ${th.border}`, borderRadius: 6, overflow: "hidden" }}>
                        {/* Time axis header */}
                        <div style={{ display: "flex", padding: "4px 10px", borderBottom: `1px solid ${th.border}`, fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
                          <span style={{ width: 160, flexShrink: 0 }}>Source</span>
                          <span style={{ flex: 1, display: "flex", justifyContent: "space-between" }}>
                            <span>{data.globalEarliest?.slice(0, 16)}</span>
                            <span>{data.globalLatest?.slice(0, 16)}</span>
                          </span>
                          <span style={{ width: 60, flexShrink: 0 }}></span>
                        </div>
                        {/* Scrollable rows */}
                        <div style={{ maxHeight: 300, overflow: "auto" }}>
                          {sorted.map((s, i) => {
                            const sStart = parseTs(s.earliest);
                            const sEnd = parseTs(s.latest);
                            const leftPct = ((sStart - gStart) / gSpan) * 100;
                            const widthPct = Math.max(0.5, ((sEnd - sStart) / gSpan) * 100);
                            const ratio = s.cnt / maxCnt;
                            return (
                              <div key={s.source} style={rowStyle(i)} onClick={() => filterBySource(s.source)}
                                onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                                onMouseLeave={(e) => { e.currentTarget.style.background = i % 2 === 0 ? "transparent" : `${th.border}15`; }}>
                                <span style={{ width: 160, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text, fontSize: 10 }} title={s.source}>{s.source}</span>
                                <div style={{ flex: 1, height: BAR_H, position: "relative", background: th.border + "22", borderRadius: 3 }}>
                                  <div style={{
                                    position: "absolute", left: `${leftPct}%`, width: `${widthPct}%`,
                                    height: "100%", background: heatColor(ratio), borderRadius: 3, minWidth: 2,
                                  }} title={`${s.source}: ${formatNumber(s.cnt)} events\n${s.earliest} — ${s.latest}`} />
                                </div>
                                <span style={{ width: 60, flexShrink: 0, textAlign: "right", color: th.textMuted, fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>{formatNumber(s.cnt)}</span>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>

                    {/* Sort controls */}
                    <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
                      <span style={{ color: th.textMuted, fontSize: 10, alignSelf: "center", fontFamily: "-apple-system, sans-serif" }}>Sort:</span>
                      {["count", "name", "earliest", "duration"].map((s) => (
                        <button key={s} onClick={() => setModal((p) => ({ ...p, sortBy: s }))}
                          style={{ padding: "3px 10px", background: sortBy === s ? th.accent : th.btnBg, color: sortBy === s ? "#fff" : th.text, border: `1px solid ${sortBy === s ? th.accent : th.btnBorder}`, borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>
                          {s.charAt(0).toUpperCase() + s.slice(1)}
                        </button>
                      ))}
                    </div>

                    {/* Detail list */}
                    <div style={{ marginBottom: 14 }}>
                      <div style={ms.lb}>Source Details ({data.totalSources})</div>
                      <div style={{ maxHeight: 200, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                        {sorted.map((s, i) => {
                          const dur = parseTs(s.latest) - parseTs(s.earliest);
                          return (
                            <div key={s.source} style={rowStyle(i)} onClick={() => filterBySource(s.source)}
                              onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                              onMouseLeave={(e) => { e.currentTarget.style.background = i % 2 === 0 ? "transparent" : `${th.border}15`; }}>
                              <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.text }} title={s.source}>{s.source}</span>
                              <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{formatNumber(s.cnt)} events</span>
                              <span style={{ color: th.textDim, fontSize: 10, whiteSpace: "nowrap" }}>{s.earliest?.slice(0, 16)}</span>
                              <span style={{ color: th.textMuted, fontSize: 10 }}>—</span>
                              <span style={{ color: th.textDim, fontSize: 10, whiteSpace: "nowrap" }}>{s.latest?.slice(0, 16)}</span>
                              <span style={{ color: th.accent, fontSize: 10, fontWeight: 600, whiteSpace: "nowrap" }}>{fmtDur(dur)}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </>);
                })()}
              </div>

              {/* Footer */}
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                {phase === "config" && (<>
                  <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
                  <button onClick={handleAnalyze} style={ms.bp}>Analyze</button>
                </>)}
                {phase === "loading" && <span style={{ color: th.textMuted, fontSize: 11 }}>Scanning...</span>}
                {phase === "results" && (<>
                  <button onClick={() => setModal((p) => ({ ...p, phase: "config", data: null }))} style={ms.bs}>Back</button>
                  <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
                </>)}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Burst Detection Modal */}
      {modal?.type === "burstAnalysis" && ct && (() => {
        const { phase, colName, windowMinutes, thresholdMultiplier, data } = modal;
        const tsCols = [...(ct.tsColumns || [])];

        const handleAnalyze = async () => {
          setModal((p) => ({ ...p, phase: "loading", loading: true, error: null }));
          try {
            const af = activeFilters(ct);
            const result = await tle.getBurstAnalysis(ct.id, colName, windowMinutes, thresholdMultiplier, {
              searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
              searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
              columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
              bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
            });
            setModal((p) => p?.type === "burstAnalysis" ? ({ ...p, phase: "results", loading: false, data: result }) : p);
          } catch (e) {
            setModal((p) => p?.type === "burstAnalysis" ? ({ ...p, phase: "config", loading: false, error: e.message }) : p);
          }
        };

        const handleTagBursts = async () => {
          if (!data?.bursts?.length) return;
          setModal((p) => ({ ...p, tagging: true }));
          try {
            const ranges = data.bursts.map((b, i) => ({ from: b.from, to: b.to, tag: `Burst ${i + 1}` }));
            const result = await tle.bulkTagByTimeRange(ct.id, colName, ranges);
            const burstColors = ["#f85149", "#f0883e", "#d29922", "#e3b341", "#da3633", "#ff7b72", "#ffa657", "#d2a8ff"];
            const newTagColors = { ...ct.tagColors };
            for (let i = 0; i < data.bursts.length; i++) {
              const tag = `Burst ${i + 1}`;
              if (!newTagColors[tag]) newTagColors[tag] = burstColors[i % burstColors.length];
            }
            up("tagColors", newTagColors);
            await fetchData(ct);
            setModal((p) => p?.type === "burstAnalysis" ? ({ ...p, tagging: false, tagged: true, taggedCount: result.taggedCount }) : p);
          } catch {
            setModal((p) => p?.type === "burstAnalysis" ? ({ ...p, tagging: false }) : p);
          }
        };

        const zoomTo = (from, to) => {
          const fromTs = from.length === 16 ? from + ":00" : from;
          const toTs = to.length === 16 ? to + ":59" : to;
          up("dateRangeFilters", { ...(ct.dateRangeFilters || {}), [colName]: { from: fromTs, to: toTs } });
          setModal(null);
        };

        const fmtDur = (mins) => {
          if (mins < 60) return `${mins}m`;
          if (mins < 1440) return `${Math.floor(mins / 60)}h ${mins % 60}m`;
          return `${Math.floor(mins / 1440)}d ${Math.floor((mins % 1440) / 60)}h`;
        };

        const rowStyle = (i) => ({
          display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", fontSize: 11,
          background: i % 2 === 0 ? "transparent" : `${th.border}15`, cursor: "pointer",
          borderBottom: `1px solid ${th.border}22`, fontFamily: "'SF Mono',Menlo,monospace",
        });

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 650, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
              {/* Header */}
              <div style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Event Burst Detection</h3>
                  <p style={{ margin: "3px 0 0", color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>Find windows with abnormally high event density</p>
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px" }}>✕</button>
              </div>

              {/* Body */}
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
                {/* Config phase */}
                {phase === "config" && (<>
                  <div style={ms.fg}>
                    <label style={ms.lb}>Timestamp Column</label>
                    <select value={colName} onChange={(e) => setModal((p) => ({ ...p, colName: e.target.value }))} style={ms.sl}>
                      {tsCols.map((c) => <option key={c} value={c}>{c}</option>)}
                    </select>
                  </div>
                  <div style={ms.fg}>
                    <label style={ms.lb}>Window Size</label>
                    <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                      {[{v: 1, l: "1m"}, {v: 5, l: "5m"}, {v: 15, l: "15m"}, {v: 30, l: "30m"}, {v: 60, l: "1h"}].map(({v, l}) => (
                        <button key={v} onClick={() => setModal((p) => ({ ...p, windowMinutes: v }))}
                          style={{ padding: "5px 12px", background: windowMinutes === v ? th.accent : th.btnBg, color: windowMinutes === v ? "#fff" : th.text, border: `1px solid ${windowMinutes === v ? th.accent : th.btnBorder}`, borderRadius: 5, fontSize: 12, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>
                          {l}
                        </button>
                      ))}
                      <input type="number" min="1" value={windowMinutes} onChange={(e) => setModal((p) => ({ ...p, windowMinutes: Math.max(1, Number(e.target.value) || 5) }))}
                        style={{ ...ms.ip, width: 60 }} />
                      <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>minutes</span>
                    </div>
                  </div>
                  <div style={ms.fg}>
                    <label style={ms.lb}>Threshold Multiplier</label>
                    <p style={{ color: th.textMuted, fontSize: 10, margin: "0 0 6px", fontFamily: "-apple-system, sans-serif" }}>Flag windows with N times the median baseline event rate</p>
                    <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                      {[3, 5, 10, 20].map((v) => (
                        <button key={v} onClick={() => setModal((p) => ({ ...p, thresholdMultiplier: v }))}
                          style={{ padding: "5px 12px", background: thresholdMultiplier === v ? th.accent : th.btnBg, color: thresholdMultiplier === v ? "#fff" : th.text, border: `1px solid ${thresholdMultiplier === v ? th.accent : th.btnBorder}`, borderRadius: 5, fontSize: 12, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>
                          {v}×
                        </button>
                      ))}
                      <input type="number" min="1" step="0.5" value={thresholdMultiplier} onChange={(e) => setModal((p) => ({ ...p, thresholdMultiplier: Math.max(1, Number(e.target.value) || 5) }))}
                        style={{ ...ms.ip, width: 60 }} />
                      <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>× baseline</span>
                    </div>
                  </div>
                  {modal.error && <div style={{ color: th.danger, fontSize: 11, padding: "8px 10px", background: `${th.danger}15`, borderRadius: 6, marginBottom: 10 }}>Error: {modal.error}</div>}
                </>)}

                {/* Loading phase */}
                {phase === "loading" && (
                  <div style={{ textAlign: "center", padding: 40 }}>
                    <div style={{ color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>Analyzing event density ({windowMinutes}m windows, {thresholdMultiplier}× threshold)...</div>
                  </div>
                )}

                {/* Results phase */}
                {phase === "results" && data && (<>
                  {/* Summary cards */}
                  <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                    {[
                      { val: data.bursts.length, label: "bursts detected", color: data.bursts.length > 0 ? th.danger : th.textDim },
                      { val: data.baseline, label: `baseline /${windowMinutes}m`, color: th.textDim },
                      { val: data.peakRate, label: `peak /${windowMinutes}m`, color: th.accent },
                      { val: formatNumber(data.totalEvents), label: "total events", color: th.textDim },
                    ].map((c, i) => (
                      <div key={i} style={{ flex: 1, textAlign: "center", padding: "12px 8px", background: th.panelBg, borderRadius: 8, border: `1px solid ${th.border}` }}>
                        <div style={{ fontSize: 22, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif" }}>{c.val}</div>
                        <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2, fontFamily: "-apple-system, sans-serif" }}>{c.label}</div>
                      </div>
                    ))}
                  </div>

                  {/* Sparkline chart */}
                  {data.sparkline && data.sparkline.length > 0 && (() => {
                    const SPARK_H = 80;
                    const maxSpk = Math.max(...data.sparkline.map((s) => s.cnt), 1);
                    return (
                      <div style={{ marginBottom: 14 }}>
                        <div style={ms.lb}>Event Rate Over Time</div>
                        <div style={{ border: `1px solid ${th.border}`, borderRadius: 6, overflow: "hidden", padding: "8px 4px" }}>
                          <svg width="100%" height={SPARK_H} viewBox={`0 0 ${data.sparkline.length} ${SPARK_H}`} preserveAspectRatio="none" style={{ display: "block" }}>
                            {/* Threshold line */}
                            <line x1="0" y1={SPARK_H - (data.threshold / maxSpk) * SPARK_H} x2={data.sparkline.length} y2={SPARK_H - (data.threshold / maxSpk) * SPARK_H}
                              stroke={th.danger || "#f85149"} strokeWidth="0.3" strokeDasharray="2,2" opacity="0.6" />
                            {/* Bars */}
                            {data.sparkline.map((s, i) => {
                              const h = Math.max(0.5, (s.cnt / maxSpk) * (SPARK_H - 4));
                              return <rect key={i} x={i} y={SPARK_H - h} width={0.8} height={h}
                                fill={s.isBurst ? (th.danger || "#f85149") : th.accent + "66"} />;
                            })}
                          </svg>
                          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: th.textMuted, marginTop: 4, padding: "0 2px", fontFamily: "-apple-system, sans-serif" }}>
                            <span>{data.sparkline[0]?.ts?.slice(0, 16)}</span>
                            <span style={{ color: th.danger || "#f85149", fontSize: 8 }}>--- threshold ({data.threshold}/{windowMinutes}m)</span>
                            <span>{data.sparkline[data.sparkline.length - 1]?.ts?.slice(0, 16)}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })()}

                  {/* Bursts list */}
                  {data.bursts.length > 0 ? (
                    <div style={{ marginBottom: 14 }}>
                      <div style={ms.lb}>Bursts ({data.bursts.length})</div>
                      <div style={{ maxHeight: 240, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                        {data.bursts.map((b, i) => (
                          <div key={i} style={rowStyle(i)} onClick={() => zoomTo(b.from, b.to)}
                            onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                            onMouseLeave={(e) => { e.currentTarget.style.background = i % 2 === 0 ? "transparent" : `${th.border}15`; }}>
                            <span style={{ padding: "1px 8px", borderRadius: 3, fontSize: 10, fontWeight: 600, color: "#fff", background: th.danger || "#f85149", fontFamily: "-apple-system, sans-serif" }}>Burst {i + 1}</span>
                            <span style={{ color: th.textDim, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{b.from} — {b.to}</span>
                            <span style={{ color: th.textMuted, fontSize: 10, whiteSpace: "nowrap" }}>{formatNumber(b.eventCount)} events</span>
                            <span style={{ color: th.danger || "#f85149", fontSize: 10, fontWeight: 700, whiteSpace: "nowrap" }}>{b.burstFactor}×</span>
                            <span style={{ color: th.accent, fontSize: 10, fontWeight: 600, whiteSpace: "nowrap" }}>{fmtDur(b.durationMinutes)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div style={{ padding: "20px 0", textAlign: "center", color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>
                      No bursts detected above {thresholdMultiplier}× baseline. Try lowering the threshold or adjusting the window size.
                    </div>
                  )}

                  {/* Tagged confirmation */}
                  {modal.tagged && (
                    <div style={{ padding: "8px 12px", background: `${th.success || "#3fb950"}15`, border: `1px solid ${th.success || "#3fb950"}33`, borderRadius: 6, color: th.success || "#3fb950", fontSize: 11, fontFamily: "-apple-system, sans-serif", marginBottom: 10 }}>
                      Tagged {modal.taggedCount?.toLocaleString()} rows across {data.bursts.length} burst periods
                    </div>
                  )}
                </>)}
              </div>

              {/* Footer */}
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                {phase === "config" && (<>
                  <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
                  <button onClick={handleAnalyze} style={ms.bp}>Analyze</button>
                </>)}
                {phase === "loading" && <span style={{ color: th.textMuted, fontSize: 11 }}>Scanning...</span>}
                {phase === "results" && (<>
                  <button onClick={() => setModal((p) => ({ ...p, phase: "config", data: null, tagged: false, taggedCount: 0 }))} style={ms.bs}>Back</button>
                  <div style={{ display: "flex", gap: 6 }}>
                    {!modal.tagged && data.bursts.length > 0 && (
                      <button onClick={handleTagBursts} disabled={modal.tagging} style={{ ...ms.bp, background: th.danger || "#f85149" }}>
                        {modal.tagging ? "Tagging..." : `Tag ${data.bursts.length} Burst${data.bursts.length !== 1 ? "s" : ""}`}
                      </button>
                    )}
                    <button onClick={() => setModal(null)} style={ms.bp}>Done</button>
                  </div>
                </>)}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Merge Tabs Modal */}
      {modal?.type === "mergeTabs" && (() => {
        const tabOptions = modal.tabOptions || [];
        const checkedTabs = tabOptions.filter((t) => t.checked);
        const totalMergeRows = checkedTabs.reduce((s, t) => s + t.rowCount, 0);
        const canMerge = checkedTabs.length >= 2 && checkedTabs.every((t) => t.selectedTsCol);
        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 560, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
              <div style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Merge Tabs</h3>
                  <p style={{ margin: "3px 0 0", color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>
                    Combine {checkedTabs.length} tab{checkedTabs.length !== 1 ? "s" : ""} into a unified timeline ({formatNumber(totalMergeRows)} rows)
                  </p>
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px" }}>{"\u2715"}</button>
              </div>
              <div style={{ flex: 1, overflow: "auto", padding: "12px 20px" }}>
                {tabOptions.map((t, i) => (
                  <div key={t.tabId} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 0", borderBottom: `1px solid ${th.border}22` }}>
                    <input type="checkbox" checked={t.checked}
                      onChange={() => setModal((p) => {
                        const opts = [...p.tabOptions];
                        opts[i] = { ...opts[i], checked: !opts[i].checked };
                        return { ...p, tabOptions: opts };
                      })}
                      style={{ accentColor: th.accent }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12, color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.tabName}</div>
                      <div style={{ fontSize: 10, color: th.textMuted }}>{formatNumber(t.rowCount)} rows</div>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                      <span style={{ fontSize: 10, color: th.textMuted }}>Timestamp:</span>
                      <select value={t.selectedTsCol}
                        onChange={(e) => setModal((p) => {
                          const opts = [...p.tabOptions];
                          opts[i] = { ...opts[i], selectedTsCol: e.target.value };
                          return { ...p, tabOptions: opts };
                        })}
                        disabled={!t.checked}
                        style={{ background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.text, fontSize: 11, padding: "2px 6px", outline: "none", maxWidth: 160 }}>
                        {t.tsColumns.length === 0 && <option value="">No timestamp columns</option>}
                        {t.tsColumns.map((c) => <option key={c} value={c}>{c}</option>)}
                      </select>
                    </div>
                  </div>
                ))}
                {checkedTabs.length < 2 && (
                  <div style={{ padding: "12px 0", color: th.warning, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>
                    Select at least 2 tabs to merge.
                  </div>
                )}
              </div>
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <button onClick={() => setModal(null)} style={ms.bs}>Cancel</button>
                <button disabled={!canMerge} onClick={async () => {
                  setModal(null);
                  const mergedTabId = `tab_merged_${Date.now()}`;
                  const srcs = checkedTabs.map((t) => ({ tabId: t.tabId, tabName: t.tabName, tsCol: t.selectedTsCol }));
                  await tle.mergeTabs(mergedTabId, srcs);
                }}
                  style={{ ...ms.bp, opacity: canMerge ? 1 : 0.5, cursor: canMerge ? "pointer" : "not-allowed" }}>
                  Merge {checkedTabs.length} Tabs ({formatNumber(totalMergeRows)} rows)
                </button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Edit Filter Modal */}
      {modal?.type === "editFilter" && ct && (() => {
        const OPERATORS = [
          { value: "contains", label: "Contains" },
          { value: "not_contains", label: "Does not contain" },
          { value: "equals", label: "Equals" },
          { value: "not_equals", label: "Does not equal" },
          { value: "starts_with", label: "Starts with" },
          { value: "ends_with", label: "Ends with" },
          { value: "greater_than", label: "Greater than" },
          { value: "less_than", label: "Less than" },
          { value: "is_empty", label: "Is empty" },
          { value: "is_not_empty", label: "Is not empty" },
          { value: "regex", label: "Matches regex" },
        ];
        const noValueOps = new Set(["is_empty", "is_not_empty"]);
        const existing = ct.advancedFilters || [];
        const initConditions = existing.length > 0
          ? existing.map((f, i) => ({ ...f, id: i + 1 }))
          : [{ id: 1, column: "", operator: "contains", value: "", logic: "AND" }];

        // Use modal state for conditions
        const conditions = modal.conditions || initConditions;
        const nextId = modal.nextId || (initConditions.length > 0 ? Math.max(...initConditions.map(c => c.id)) + 1 : 2);

        const setConditions = (newConds) => setModal((p) => p?.type === "editFilter" ? { ...p, conditions: newConds } : p);
        const setNextId = (nid) => setModal((p) => p?.type === "editFilter" ? { ...p, nextId: nid } : p);

        const updateCondition = (id, field, val) => {
          setConditions(conditions.map((c) => c.id === id ? { ...c, [field]: val } : c));
        };
        const removeCondition = (id) => {
          const newC = conditions.filter((c) => c.id !== id);
          if (newC.length === 0) newC.push({ id: nextId, column: "", operator: "contains", value: "", logic: "AND" });
          setConditions(newC);
          if (newC.length === 0) setNextId(nextId + 1);
        };
        const addCondition = () => {
          setConditions([...conditions, { id: nextId, column: "", operator: "contains", value: "", logic: "AND" }]);
          setNextId(nextId + 1);
        };

        // Build preview expression
        const buildPreview = () => {
          const valid = conditions.filter((c) => c.column && c.operator && (noValueOps.has(c.operator) || c.value));
          if (valid.length === 0) return "No conditions defined";
          const opLabel = (op) => OPERATORS.find(o => o.value === op)?.label || op;
          // Group by AND/OR for parenthesized display
          const groups = [];
          let currentGroup = [valid[0]];
          for (let i = 1; i < valid.length; i++) {
            if (valid[i].logic === "OR") {
              groups.push(currentGroup);
              currentGroup = [valid[i]];
            } else {
              currentGroup.push(valid[i]);
            }
          }
          groups.push(currentGroup);
          return groups.map((g) => {
            const expr = g.map((c) => {
              if (noValueOps.has(c.operator)) return `${c.column} ${opLabel(c.operator).toUpperCase()}`;
              return `${c.column} ${opLabel(c.operator).toUpperCase()} "${c.value}"`;
            }).join(" AND ");
            return g.length > 1 ? `(${expr})` : expr;
          }).join(" OR ");
        };

        const handleApply = () => {
          const valid = conditions.filter((c) => c.column && c.operator && (noValueOps.has(c.operator) || c.value));
          up("advancedFilters", valid.map(({ id, ...rest }) => rest));
          setModal(null);
        };

        const handleClear = () => {
          up("advancedFilters", []);
          setModal(null);
        };

        const selectStyle = { background: th.bgInput, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, padding: "5px 8px", fontSize: 12, fontFamily: "-apple-system, sans-serif", outline: "none" };
        const inputStyle = { ...selectStyle, flex: 1, minWidth: 80 };

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 720, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
              {/* Header */}
              <div style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Edit Filter</h3>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textDim, fontSize: 18, cursor: "pointer", padding: "2px 6px" }}>✕</button>
              </div>

              {/* Condition Rows */}
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
                {conditions.map((c, idx) => (
                  <div key={c.id} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                    {/* Logic (AND/OR) */}
                    {idx === 0 ? (
                      <span style={{ width: 56, fontSize: 11, color: th.textDim, textAlign: "center", flexShrink: 0 }}>Where</span>
                    ) : (
                      <select value={c.logic} onChange={(e) => updateCondition(c.id, "logic", e.target.value)} style={{ ...selectStyle, width: 56, flexShrink: 0, textAlign: "center" }}>
                        <option value="AND">AND</option>
                        <option value="OR">OR</option>
                      </select>
                    )}

                    {/* Column */}
                    <select value={c.column} onChange={(e) => updateCondition(c.id, "column", e.target.value)} style={{ ...selectStyle, minWidth: 120, maxWidth: 180 }}>
                      <option value="">-- Column --</option>
                      {ct.headers.map((h) => <option key={h} value={h}>{h}</option>)}
                    </select>

                    {/* Operator */}
                    <select value={c.operator} onChange={(e) => updateCondition(c.id, "operator", e.target.value)} style={{ ...selectStyle, minWidth: 130 }}>
                      {OPERATORS.map((op) => <option key={op.value} value={op.value}>{op.label}</option>)}
                    </select>

                    {/* Value */}
                    {!noValueOps.has(c.operator) ? (
                      <input type="text" value={c.value} onChange={(e) => updateCondition(c.id, "value", e.target.value)}
                        onKeyDown={(e) => { if (e.key === "Enter") handleApply(); }}
                        placeholder="Value..." style={inputStyle} />
                    ) : (
                      <div style={{ flex: 1 }} />
                    )}

                    {/* Delete */}
                    <button onClick={() => removeCondition(c.id)} style={{ background: "none", border: "none", color: th.textDim, fontSize: 14, cursor: "pointer", padding: "2px 6px", flexShrink: 0 }} title="Remove condition">✕</button>
                  </div>
                ))}

                {/* Add Condition */}
                <button onClick={addCondition} style={{ background: "none", border: `1px dashed ${th.border}`, borderRadius: 4, color: th.accent, fontSize: 12, padding: "6px 12px", cursor: "pointer", marginTop: 4, fontFamily: "-apple-system, sans-serif" }}>
                  + Add Condition
                </button>

                {/* Preview */}
                <div style={{ marginTop: 16, padding: "10px 12px", background: th.bgInput, border: `1px solid ${th.border}`, borderRadius: 6, fontSize: 11, fontFamily: "'SF Mono', 'Fira Code', Menlo, monospace", color: th.textDim, wordBreak: "break-word", lineHeight: 1.6 }}>
                  {buildPreview()}
                </div>
              </div>

              {/* Footer */}
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}`, display: "flex", justifyContent: "flex-end", gap: 8 }}>
                <button onClick={handleClear} style={{ background: "none", border: `1px solid ${th.border}`, borderRadius: 6, padding: "6px 14px", color: th.danger || "#f85149", fontSize: 12, cursor: "pointer", fontFamily: "-apple-system, sans-serif", marginRight: "auto" }}>Clear All</button>
                <button onClick={() => setModal(null)} style={{ background: "none", border: `1px solid ${th.border}`, borderRadius: 6, padding: "6px 14px", color: th.textDim, fontSize: 12, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Cancel</button>
                <button onClick={handleApply} style={{ background: th.accent, border: "none", borderRadius: 6, padding: "6px 14px", color: "#fff", fontSize: 12, cursor: "pointer", fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Apply</button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Bulk Actions Modal */}
      {modal?.type === "bulkActions" && ct && (() => {
        const af = activeFilters(ct);
        const filterOpts = {
          searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
          searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
          columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
          bookmarkedOnly: ct.showBookmarkedOnly, tagFilter: ct.tagFilter || null,
          dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
        };
        const tagName = modal.tagName || "";
        const tagColor = modal.tagColor || "#E85D2A";
        const result = modal.result;
        const busy = modal.busy || false;
        const existingTags = Object.keys(ct.tagColors || {});

        const handleTag = async () => {
          if (!tagName.trim() || busy) return;
          setModal((p) => p?.type === "bulkActions" ? { ...p, busy: true, result: null } : p);
          try {
            const res = await tle.bulkTagFiltered(ct.id, tagName.trim(), filterOpts);
            up("tagColors", { ...(ct.tagColors || {}), [tagName.trim()]: tagColor });
            await fetchData(ct);
            setModal((p) => p?.type === "bulkActions" ? { ...p, busy: false, result: { type: "success", msg: `Tagged ${formatNumber(res.tagged)} rows as "${tagName.trim()}"` } } : p);
          } catch (e) {
            setModal((p) => p?.type === "bulkActions" ? { ...p, busy: false, result: { type: "error", msg: e.message } } : p);
          }
        };
        const handleBookmark = async (add) => {
          if (busy) return;
          setModal((p) => p?.type === "bulkActions" ? { ...p, busy: true, result: null } : p);
          try {
            const res = await tle.bulkBookmarkFiltered(ct.id, add, filterOpts);
            await fetchData(ct);
            const msg = add ? `Bookmarked ${formatNumber(res.affected)} rows` : `Removed bookmarks from ${formatNumber(res.affected)} rows`;
            setModal((p) => p?.type === "bulkActions" ? { ...p, busy: false, result: { type: "success", msg } } : p);
          } catch (e) {
            setModal((p) => p?.type === "bulkActions" ? { ...p, busy: false, result: { type: "error", msg: e.message } } : p);
          }
        };

        const sectionStyle = { background: th.bgInput, border: `1px solid ${th.border}`, borderRadius: 8, padding: "12px 14px", marginBottom: 12 };
        const labelStyle = { fontSize: 11, color: th.textDim, marginBottom: 6, fontWeight: 500 };
        const btnStyle = { padding: "6px 14px", borderRadius: 6, fontSize: 12, cursor: busy ? "wait" : "pointer", fontFamily: "-apple-system, sans-serif", border: "none" };

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 480, maxWidth: "94vw", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
              {/* Header */}
              <div style={{ padding: "16px 20px 8px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Bulk Actions</h3>
                  <div style={{ fontSize: 11, color: th.textDim, marginTop: 2, fontFamily: "-apple-system, sans-serif" }}>
                    Applies to <b style={{ color: ct.totalFiltered < ct.totalRows ? th.warning : th.text }}>{formatNumber(ct.totalFiltered)}</b> filtered rows
                  </div>
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textDim, fontSize: 18, cursor: "pointer", padding: "2px 6px" }}>✕</button>
              </div>

              <div style={{ padding: "12px 20px 16px" }}>
                {/* Tag section */}
                <div style={sectionStyle}>
                  <div style={labelStyle}>Tag Filtered Rows</div>
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <input type="text" value={tagName} onChange={(e) => setModal((p) => p?.type === "bulkActions" ? { ...p, tagName: e.target.value } : p)}
                      onKeyDown={(e) => { if (e.key === "Enter") handleTag(); }}
                      placeholder="Tag name..." list="bulk-tag-suggestions"
                      style={{ flex: 1, background: th.modalBg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, padding: "6px 8px", fontSize: 12, outline: "none", fontFamily: "-apple-system, sans-serif" }} />
                    <datalist id="bulk-tag-suggestions">
                      {existingTags.map((t) => <option key={t} value={t} />)}
                    </datalist>
                    <input type="color" value={tagColor} onChange={(e) => setModal((p) => p?.type === "bulkActions" ? { ...p, tagColor: e.target.value } : p)}
                      title="Tag color" style={{ width: 30, height: 30, border: `1px solid ${th.border}`, borderRadius: 4, padding: 0, cursor: "pointer", background: "none" }} />
                    <button onClick={handleTag} disabled={!tagName.trim() || busy}
                      style={{ ...btnStyle, background: tagName.trim() && !busy ? th.accent : th.btnBg, color: tagName.trim() && !busy ? "#fff" : th.textMuted, fontWeight: 600 }}>
                      {busy ? "..." : "Apply Tag"}
                    </button>
                  </div>
                </div>

                {/* Bookmark section */}
                <div style={sectionStyle}>
                  <div style={labelStyle}>Bookmark Filtered Rows</div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <button onClick={() => handleBookmark(true)} disabled={busy}
                      style={{ ...btnStyle, background: busy ? th.btnBg : th.accent + "22", color: busy ? th.textMuted : th.accent, border: `1px solid ${busy ? th.border : th.accent}44`, flex: 1, fontWeight: 500 }}>
                      ★ Bookmark All
                    </button>
                    <button onClick={() => handleBookmark(false)} disabled={busy}
                      style={{ ...btnStyle, background: busy ? th.btnBg : (th.danger || "#f85149") + "18", color: busy ? th.textMuted : (th.danger || "#f85149"), border: `1px solid ${busy ? th.border : (th.danger || "#f85149")}44`, flex: 1, fontWeight: 500 }}>
                      ☆ Remove Bookmarks
                    </button>
                  </div>
                </div>

                {/* Result message */}
                {result && (
                  <div style={{ padding: "8px 12px", borderRadius: 6, fontSize: 12, fontFamily: "-apple-system, sans-serif",
                    background: result.type === "success" ? (th.success + "18") : (th.danger + "18"),
                    color: result.type === "success" ? th.success : (th.danger || "#f85149"),
                    border: `1px solid ${result.type === "success" ? th.success : (th.danger || "#f85149")}44` }}>
                    {result.type === "success" ? "✓ " : "✗ "}{result.msg}
                  </div>
                )}
              </div>

              {/* Footer */}
              <div style={{ padding: "10px 20px", borderTop: `1px solid ${th.border}`, display: "flex", justifyContent: "flex-end" }}>
                <button onClick={() => setModal(null)} style={{ ...btnStyle, background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}` }}>Close</button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Process Tree Modal */}
      {modal?.type === "processTree" && ct && (() => {
        const { phase, columns: cols, eventIdValue, data, expandedNodes, searchText } = modal;
        const hasCols = (cols.pid && cols.ppid) || (cols.guid && cols.parentGuid);

        // Process type icons — inline 14x14 SVGs (uses hoisted PT_ICON_STYLE)
        const ptIcon = (name) => {
          const n = (name || "").toLowerCase();
          if (/^explorer/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><path d="M2 3h12v2H2zm0 3h12v7H2z" fill={th.accent + "66"} stroke={th.accent} strokeWidth="1"/></svg>;
          if (/^(winword|excel|powerpnt|outlook|onenote|msaccess|acrobat|acrord32)/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><path d="M4 1h5l4 4v10H4z" fill="#4493f8" fillOpacity=".2" stroke="#4493f8" strokeWidth="1"/><path d="M9 1v4h4" stroke="#4493f8" strokeWidth="1"/></svg>;
          if (/^(cmd|powershell|pwsh|bash|sh|conhost)(\.exe)?$/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><rect x="1" y="2" width="14" height="12" rx="2" fill={th.text + "11"} stroke={th.textDim} strokeWidth="1"/><path d="M4 6l3 2.5L4 11" stroke={th.accent} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><line x1="9" y1="11" x2="12" y2="11" stroke={th.textDim} strokeWidth="1.5" strokeLinecap="round"/></svg>;
          if (/^(svchost|services|lsass|csrss|smss|wininit|winlogon|spoolsv|lsm)(\.exe)?$/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="5" fill={th.textDim + "22"} stroke={th.textDim} strokeWidth="1"/><circle cx="8" cy="8" r="1.5" fill={th.textDim}/><path d="M8 2v2M8 12v2M2 8h2M12 8h2M3.8 3.8l1.4 1.4M10.8 10.8l1.4 1.4M3.8 12.2l1.4-1.4M10.8 5.2l1.4-1.4" stroke={th.textDim} strokeWidth="1"/></svg>;
          if (/^(chrome|firefox|msedge|iexplore|opera|brave|safari)(\.exe)?$/i.test(n)) return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" fill="#58a6ff22" stroke="#58a6ff" strokeWidth="1"/><ellipse cx="8" cy="8" rx="2.5" ry="6" stroke="#58a6ff" strokeWidth=".7"/><line x1="2" y1="6" x2="14" y2="6" stroke="#58a6ff" strokeWidth=".7"/><line x1="2" y1="10" x2="14" y2="10" stroke="#58a6ff" strokeWidth=".7"/></svg>;
          return <svg style={PT_ICON_STYLE} viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="3" fill={th.textDim + "33"} stroke={th.textDim} strokeWidth="1"/></svg>;
        };

        // Process tree column configuration
        const ptHeaders = ["Timestamp", "Detection", "Provider", "Event ID", "Parent Process", "Process", "PID", "PPID", "User", "Command Line", "Integrity"];
        const ptDefWidths = { Timestamp: 195, Provider: 100, "Event ID": 65, "Parent Process": 170, Process: 280, Detection: 240, PID: 75, PPID: 75, User: 150, "Command Line": 300, Integrity: 80 };
        const ptColWidths = modal.ptColWidths || ptDefWidths;
        const ptSortCol = modal.ptSortCol || "Timestamp";
        const ptSortDir = modal.ptSortDir || "asc";
        const ptColFilters = modal.ptColFilters || {};
        // Pre-compute detection results for all processes (cached — only rebuilt when data changes)
        const _ptDetMap = (() => {
          const c = ptCacheRef.current;
          if (c.detMapData === data) return c.detMap;
          if (!data?.processes?.length) { c.detMap = new Map(); c.detMapData = data; return c.detMap; }
          const byK = new Map(data.processes.map((p) => [p.key, p]));
          const m = new Map();
          for (const p of data.processes) {
            const parent = byK.get(p.parentKey);
            m.set(p.key, getSusInfo(p, parent));
          }
          c.detMap = m;
          c.detMapData = data;
          return m;
        })();
        const ptCellVal = (node, col) => {
          if (col === "Parent Process") return node.parentProcessName || "";
          if (col === "Process") return node.processName || "";
          if (col === "PID") return node.pid || "";
          if (col === "PPID") return node.ppid || "";
          if (col === "User") return node.user || "";
          if (col === "Timestamp") return node.ts || "";
          if (col === "Command Line") return node.cmdLine || "";
          if (col === "Provider") return node.provider || "";
          if (col === "Event ID") return node.eventId || "";
          if (col === "Integrity") return _integrityShort(node.integrity);
          if (col === "Detection") return (_ptDetMap.get(node.key) || {}).reason || "";
          return "";
        };
        const ptSortKey = (node, col) => {
          if (col === "PID") return parseInt(node.pid) || 0;
          if (col === "PPID") return parseInt(node.ppid) || 0;
          if (col === "Event ID") return parseInt(node.eventId) || 0;
          if (col === "Detection") return (_ptDetMap.get(node.key) || {}).level || 0;
          return ptCellVal(node, col);
        };
        const togglePtSort = (col) => {
          if (ptResizingRef.current) return;  // skip sort if column was just resized
          setModal((p) => {
            if ((p.ptSortCol || "Timestamp") === col) return { ...p, ptSortDir: (p.ptSortDir || "asc") === "asc" ? "desc" : "asc" };
            // Detection defaults to descending (critical first)
            return { ...p, ptSortCol: col, ptSortDir: col === "Detection" ? "desc" : "asc" };
          });
        };
        const onPtResizeStart = (colName, e) => {
          e.preventDefault(); e.stopPropagation();
          ptResizingRef.current = true;
          const startX = e.clientX;
          const startW = ptColWidths[colName] || ptDefWidths[colName];
          document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
          const move = (ev) => {
            const newW = Math.max(40, startW + ev.clientX - startX);
            setModal((p) => ({ ...p, ptColWidths: { ...(p.ptColWidths || ptDefWidths), [colName]: newW } }));
          };
          const up = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); setTimeout(() => { ptResizingRef.current = false; }, 0); };
          document.addEventListener("mousemove", move); document.addEventListener("mouseup", up);
        };
        const openPtFilter = (colName, e) => {
          e.stopPropagation();
          const rect = e.currentTarget.getBoundingClientRect();
          const counts = {};
          for (const p of (data?.processes || [])) { const v = ptCellVal(p, colName); counts[v] = (counts[v] || 0) + 1; }
          const allVals = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
          const current = ptColFilters[colName];
          const selected = new Set(current && current.length > 0 ? current : allVals);
          setModal((p) => ({ ...p, ptFilterOpen: colName, ptFilterPos: { x: rect.left, y: rect.bottom + 2 }, ptFilterVals: allVals, ptFilterCounts: counts, ptFilterSel: selected, ptFilterSearch: "" }));
        };
        const ptFilterOpen = modal.ptFilterOpen;
        const ptFilterPos = modal.ptFilterPos || {};
        const ptFilterVals = modal.ptFilterVals || [];
        const ptFilterCounts = modal.ptFilterCounts || {};
        const ptFilterSel = modal.ptFilterSel || new Set();
        const ptFilterSearch = modal.ptFilterSearch || "";
        const ptFilterDisplay = ptFilterSearch ? ptFilterVals.filter((v) => v.toLowerCase().includes(ptFilterSearch.toLowerCase())) : ptFilterVals;
        const ptActiveFilterCount = Object.values(ptColFilters).filter((v) => v && v.length > 0).length;
        const PT_CHK_W = 32;
        const totalPtW = PT_CHK_W + ptHeaders.reduce((s, h) => s + (ptColWidths[h] || ptDefWidths[h]), 0) + 50;
        const ptChecked = modal.ptChecked || new Set();
        const ptCheckedCount = ptChecked.size;

        const handleBuild = async () => {
          const t0 = Date.now();
          const ptPhases = ["Querying database...", "Parsing process events...", "Building parent-child relationships...", "Computing tree depth...", "Finalizing...", "Complete"];
          const progInt = setInterval(() => {
            setModal((p) => {
              if (!p || p.type !== "processTree" || p.phase !== "loading") { clearInterval(progInt); return p; }
              const el = (Date.now() - t0) / 1000;
              const prog = Math.min(92, 90 * (1 - Math.exp(-el / 6)));
              const pi = prog < 10 ? 0 : prog < 30 ? 1 : prog < 55 ? 2 : prog < 75 ? 3 : 4;
              return { ...p, ptProgress: prog, ptPhaseIdx: pi };
            });
          }, 120);
          setModal((p) => ({ ...p, phase: "loading", loading: true, error: null, ptProgress: 0, ptPhaseIdx: 0, _cancelled: false }));
          try {
            const af = activeFilters(ct);
            const result = await tle.getProcessTree(ct.id, {
              pidCol: cols.pid, ppidCol: cols.ppid, guidCol: cols.guid, parentGuidCol: cols.parentGuid,
              imageCol: cols.image, cmdLineCol: cols.cmdLine, userCol: cols.user, tsCol: cols.ts, eventIdCol: cols.eventId, providerCol: cols.provider,
              eventIdValue: eventIdValue || null,
              searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
              searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
              columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
              bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
              maxRows: modal.maxRows || 200000,
            });
            clearInterval(progInt);
            if (result.error) {
              setModal((p) => p?.type === "processTree" && !p._cancelled ? { ...p, phase: "config", loading: false, error: result.error, ptProgress: 0 } : p);
            } else {
              setModal((p) => p?.type === "processTree" && !p._cancelled ? { ...p, ptProgress: 100, ptPhaseIdx: 5 } : p);
              await new Promise((r) => setTimeout(r, 250));
              setModal((p) => p?.type === "processTree" && !p._cancelled ? { ...p, phase: "results", loading: false, data: result, expandedNodes: {}, searchText: "" } : p);
            }
          } catch (e) {
            clearInterval(progInt);
            setModal((p) => p?.type === "processTree" && !p._cancelled ? { ...p, phase: "config", loading: false, error: e.message, ptProgress: 0 } : p);
          }
        };

        // Cached childMap + byKey — shared across buildFlat, expand helpers, detail panel
        const _cachedChildMap = (() => {
          const c = ptCacheRef.current;
          if (c.childMapData === data) return c.childMap;
          if (!data?.processes?.length) { c.childMap = new Map(); c.childMapData = data; return c.childMap; }
          const m = new Map();
          for (const p of data.processes) {
            if (!m.has(p.parentKey)) m.set(p.parentKey, []);
            m.get(p.parentKey).push(p.key);
          }
          c.childMap = m;
          c.childMapData = data;
          return m;
        })();
        const _cachedByKey = (() => {
          const c = ptCacheRef.current;
          if (c.byKeyData === data) return c.byKeyMap;
          if (!data?.processes?.length) { c.byKeyMap = new Map(); c.byKeyData = data; return c.byKeyMap; }
          const m = new Map(data.processes.map((p) => [p.key, p]));
          c.byKeyMap = m;
          c.byKeyData = data;
          return m;
        })();

        // Build flat visible list from tree data, with connector metadata
        const buildFlat = () => {
          if (!data?.processes?.length) return [];
          const procs = data.processes;
          const byKey = _cachedByKey;
          const childMap = _cachedChildMap;
          const st = (searchText || "").toLowerCase();
          const susOnly = !!modal.susOnlyFilter;
          const hasColFilters = Object.values(ptColFilters).some((v) => v && v.length > 0);
          const siblingSort = (a, b) => {
            const av = ptSortKey(a, ptSortCol), bv = ptSortKey(b, ptSortCol);
            const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
            return ptSortDir === "asc" ? cmp : -cmp;
          };
          // Flat mode when search, column filters, suspicious-only, or sorting by Detection
          const flatSort = ptSortCol === "Detection";
          if (st || hasColFilters || susOnly || flatSort) {
            let filtered = [...procs];
            if (hasColFilters) {
              filtered = filtered.filter((p) => {
                for (const [col, vals] of Object.entries(ptColFilters)) {
                  if (!vals || vals.length === 0) continue;
                  if (!vals.includes(ptCellVal(p, col))) return false;
                }
                return true;
              });
            }
            if (st) {
              filtered = filtered.filter((p) =>
                (p.processName || "").toLowerCase().includes(st) ||
                (p.pid || "").toLowerCase().includes(st) ||
                (p.cmdLine || "").toLowerCase().includes(st) ||
                (p.user || "").toLowerCase().includes(st)
              );
            }
            if (susOnly) {
              filtered = filtered.filter((p) => (_ptDetMap.get(p.key) || { level: 0 }).level > 0);
            }
            filtered.sort(siblingSort);
            return filtered.map((p) => ({ ...p, depth: 0, connectors: [], isLast: false }));
          }
          const roots = procs.filter((p) => !byKey.has(p.parentKey));
          const flat = [];
          const activeLines = {};
          const visited = new Set();
          const MAX_DEPTH = 100;
          const dfs = (keys, depth) => {
            if (depth > MAX_DEPTH) return;
            const sorted = keys.map((k) => byKey.get(k)).filter(Boolean);
            sorted.sort(siblingSort);
            for (let si = 0; si < sorted.length; si++) {
              const node = sorted[si];
              if (visited.has(node.key)) continue;
              visited.add(node.key);
              const isLast = si === sorted.length - 1;
              const connectors = [];
              for (let d = 0; d < depth; d++) connectors.push(!!activeLines[d]);
              flat.push({ ...node, depth, connectors, isLast: depth > 0 && isLast });
              if (expandedNodes[node.key]) {
                activeLines[depth] = !isLast;
                dfs(childMap.get(node.key) || [], depth + 1);
                delete activeLines[depth];
              }
            }
          };
          dfs(roots.map((r) => r.key), 0);
          return flat;
        };

        // Cached flat list + byKeyMap — only recompute when deps actually change (not on selectedKey click)
        const flatNodes = (() => {
          if (phase !== "results") return [];
          const c = ptCacheRef.current;
          const susOnly = !!modal.susOnlyFilter;
          if (c.data === data && c.expandedNodes === expandedNodes && c.searchText === searchText &&
              c.ptColFilters === ptColFilters && c.ptSortCol === ptSortCol && c.ptSortDir === ptSortDir && c.susOnly === susOnly) {
            return c.flatNodes;
          }
          const result = buildFlat();
          Object.assign(c, { flatNodes: result, data, expandedNodes, searchText, ptColFilters, ptSortCol, ptSortDir, susOnly });
          return result;
        })();
        const byKeyMap = _cachedByKey;
        const childMap = _cachedChildMap;

        // Chain highlight: walk from selected node to root (cycle-safe)
        const selectedKey = modal.selectedKey || null;
        const chainKeys = new Set();
        if (selectedKey && byKeyMap.size > 0) {
          let cur = selectedKey;
          while (cur && !chainKeys.has(cur)) {
            chainKeys.add(cur);
            const node = byKeyMap.get(cur);
            if (!node || !byKeyMap.has(node.parentKey)) break;
            cur = node.parentKey;
          }
        }
        const expandAll = () => {
          const en = {};
          for (const p of (data?.processes || [])) { if (p.childCount > 0) en[p.key] = true; }
          setModal((p) => p ? { ...p, expandedNodes: en } : p);
        };
        const collapseAll = () => setModal((p) => p ? { ...p, expandedNodes: {} } : p);
        const expandToDepth = (maxD) => {
          const en = {};
          for (const p of (data?.processes || [])) { if (p.childCount > 0 && p.depth < maxD) en[p.key] = true; }
          setModal((p) => p ? { ...p, expandedNodes: en } : p);
        };

        const selStyle = { background: th.bgInput, color: th.text, border: `1px solid ${th.border}`, borderRadius: 5, padding: "4px 8px", fontSize: 12, fontFamily: "monospace" };

        // Draggable + resizable panel state
        const pw = modal.ptW || Math.round(window.innerWidth * 0.92), ph_ = modal.ptH || Math.round(window.innerHeight * 0.88);
        const px = modal.ptX ?? Math.round((window.innerWidth - pw) / 2);
        const py = modal.ptY ?? Math.round((window.innerHeight - ph_) / 2);

        const startDrag = (e) => {
          e.preventDefault();
          const sx = e.clientX - px, sy = e.clientY - py;
          const onMove = (ev) => setModal((p) => p ? { ...p, ptX: Math.max(0, Math.min(window.innerWidth - 100, ev.clientX - sx)), ptY: Math.max(0, Math.min(window.innerHeight - 40, ev.clientY - sy)) } : p);
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const startResize = (e, edge) => {
          e.preventDefault(); e.stopPropagation();
          const sx = e.clientX, sy = e.clientY, sw = pw, sh = ph_, sleft = px, stop = py;
          const onMove = (ev) => {
            const dx = ev.clientX - sx, dy = ev.clientY - sy;
            setModal((p) => {
              if (!p) return p;
              let nw = sw, nh = sh, nx = sleft, ny = stop;
              if (edge.includes("r")) nw = Math.max(480, sw + dx);
              if (edge.includes("b")) nh = Math.max(300, sh + dy);
              if (edge.includes("l")) { nw = Math.max(480, sw - dx); nx = sleft + sw - nw; }
              if (edge.includes("t")) { nh = Math.max(300, sh - dy); ny = stop + sh - nh; }
              return { ...p, ptW: nw, ptH: nh, ptX: nx, ptY: ny };
            });
          };
          const onUp = () => { window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const edgeStyle = (cursor, pos) => ({ position: "absolute", ...pos, zIndex: 2, cursor });

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, zIndex: 100, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", WebkitAppRegion: "drag" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ WebkitAppRegion: "no-drag", position: "absolute", left: px, top: py, width: pw, height: ph_, background: th.modalBg + "f2", border: `1px solid ${th.modalBorder}88`, borderRadius: 14, padding: 0, display: "flex", flexDirection: "column", boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset", overflow: "hidden", backdropFilter: "blur(40px) saturate(1.6)", WebkitBackdropFilter: "blur(40px) saturate(1.6)" }}>
              {/* Resize handles — edges */}
              <div onMouseDown={(e) => startResize(e, "t")} style={edgeStyle("ns-resize", { top: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startResize(e, "b")} style={edgeStyle("ns-resize", { bottom: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startResize(e, "l")} style={edgeStyle("ew-resize", { left: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startResize(e, "r")} style={edgeStyle("ew-resize", { right: 0, top: 8, bottom: 8, width: 5 })} />
              {/* Resize handles — corners */}
              <div onMouseDown={(e) => startResize(e, "tl")} style={edgeStyle("nwse-resize", { top: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "tr")} style={edgeStyle("nesw-resize", { top: 0, right: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "bl")} style={edgeStyle("nesw-resize", { bottom: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startResize(e, "br")} style={edgeStyle("nwse-resize", { bottom: 0, right: 0, width: 10, height: 10 })} />

              {/* Header — draggable, gradient glass */}
              <div onMouseDown={startDrag} style={{ padding: "14px 20px 10px", borderBottom: `1px solid ${th.border}66`, cursor: "move", flexShrink: 0, userSelect: "none", background: `linear-gradient(180deg, ${th.headerBg}ee 0%, ${th.modalBg}cc 100%)`, backdropFilter: "blur(20px) saturate(1.4)", WebkitBackdropFilter: "blur(20px) saturate(1.4)" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                    <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.accent} 0%, ${th.accentHover || th.accent} 100%)`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, fontWeight: 700, color: "#fff", boxShadow: `0 2px 8px ${th.accent}44`, flexShrink: 0 }}>{"\u25B3"}</div>
                    <div>
                      <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.01em" }}>
                        <span style={{ color: th.accent }}>IRFlow</span> {"\u2014"} Process Inspector
                      </h3>
                      {phase === "results" && data?.stats && (() => {
                        const hostname = (() => { const p0 = data?.processes?.[0]; if (!p0) return ""; if (p0.hostname) return p0.hostname; const u = p0.user || ""; const d = u.split("\\")[0]; return d && d !== "-" && d !== u ? d : ""; })();
                        const providers = [...new Set((data?.processes || []).map(p => _providerShort(p.provider)).filter(Boolean))].join(", ");
                        const eids = [...new Set((data?.processes || []).map(p => p.eventId).filter(Boolean))].sort().join(", ");
                        const dateRange = (() => { const ts = (data?.processes || []).filter(p => p.ts).map(p => p.ts).sort(); if (!ts.length) return ""; const first = (ts[0] || "").split(" ")[0]; const last = (ts[ts.length - 1] || "").split(" ")[0]; return first === last ? first : `${first} \u2192 ${last}`; })();
                        return (
                          <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", marginTop: 2, display: "flex", flexWrap: "wrap", gap: 4 }}>
                            {hostname && <span style={{ color: th.text, fontWeight: 500 }}>{hostname}</span>}
                            {hostname && providers && <span>{"\u00B7"}</span>}
                            {providers && <span>{providers}</span>}
                            {eids && <span>{"\u00B7"} EID {eids}</span>}
                            <span>{"\u00B7"} {data.stats.totalProcesses.toLocaleString()} events</span>
                            {dateRange && <span>{"\u00B7"} {dateRange}</span>}
                            {data.useGuid && <span style={{ color: th.success || "#3fb950" }}>{"\u00B7"} GUID-linked</span>}
                            {data.stats.truncated && <span style={{ color: th.danger || "#f85149" }}>{"\u00B7"} Truncated at {(data.stats.totalProcesses || 0).toLocaleString()} {"\u2014"} increase limit</span>}
                          </div>
                        );
                      })()}
                    </div>
                  </div>
                  <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textDim, fontSize: 18, cursor: "pointer", padding: "0 4px", lineHeight: 1 }}>{"\u00D7"}</button>
                </div>
              </div>

              {/* Config phase */}
              {phase === "config" && (
                <div style={{ padding: 20, overflowY: "auto", flex: 1, minHeight: 0 }}>
                  <div style={{ fontSize: 12, color: th.textDim, marginBottom: 12, fontFamily: "-apple-system, sans-serif" }}>Map columns for process tree reconstruction. Auto-detected from headers.</div>
                  <div style={{ display: "grid", gridTemplateColumns: "130px 1fr 130px 1fr", gap: "8px 12px", alignItems: "center", fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>
                    {[["Process ID", "pid"], ["Parent Process ID", "ppid"], ["Process GUID", "guid"], ["Parent GUID", "parentGuid"],
                      ["Image / Exe", "image"], ["Parent Image", "parentImage"], ["Command Line", "cmdLine"], ["User", "user"],
                      ["Timestamp", "ts"], ["Event ID", "eventId"], ["Token Elevation", "elevation"], ["Integrity Level", "integrity"],
                      ["Provider", "provider"]].map(([label, key]) => (
                      <div key={key} style={{ display: "contents" }}>
                        <label style={{ color: th.textDim, textAlign: "right" }}>{label}:</label>
                        <select value={cols[key] || ""} onChange={(e) => setModal((p) => ({ ...p, columns: { ...p.columns, [key]: e.target.value || null } }))} style={selStyle}>
                          <option value="">— none —</option>
                          {ct.headers.map((h) => <option key={h} value={h}>{h}</option>)}
                        </select>
                      </div>
                    ))}
                    <label style={{ color: th.textDim, textAlign: "right" }}>EventID values:</label>
                    <input value={eventIdValue || ""} onChange={(e) => setModal((p) => ({ ...p, eventIdValue: e.target.value }))} placeholder="1,4688 (comma-separated, blank = all)" style={{ ...selStyle, width: 180 }} />
                    <label style={{ color: th.textDim, textAlign: "right" }}>Max processes:</label>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <input type="number" value={modal.maxRows ?? 200000} onChange={(e) => setModal((p) => ({ ...p, maxRows: Math.max(1000, parseInt(e.target.value) || 200000) }))} style={{ ...selStyle, width: 100 }} min="1000" step="50000" />
                      <span style={{ fontSize: 10, color: th.textMuted }}>default: 200,000</span>
                    </div>
                  </div>

                  {/* Info box */}
                  <div style={{ padding: "12px 14px", background: `${th.accent}08`, borderRadius: 10, border: `1px solid ${th.accent}15`, marginTop: 16, marginBottom: 12 }}>
                    <div style={{ fontSize: 11, color: th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>
                      <b style={{ color: th.text }}>Process Inspector</b> reconstructs parent-child process trees from Sysmon (EID 1) and Security (EID 4688) logs using PID/PPID or ProcessGUID linking. Runs 344 chain-based detection rules (e.g. Word{"\u2192"}cmd, svchost{"\u2192"}PS) plus standalone detections for encoded PowerShell, credential dumping, LSASS tools, defense evasion, lateral movement commands, AD recon tools, RMM tools, exfiltration utilities, and suspicious execution paths. All detections are mapped to MITRE ATT&CK techniques.
                    </div>
                  </div>

                  {/* Customize Rules Section */}
                  {(() => {
                    const PI_RULES = [
                      { cat: "Execution", name: "Office \u2192 Shell (Word/Excel/PPT/Outlook/OneNote/Access/Publisher)", sev: "critical", count: 28, technique: "T1204.002, T1059",
                        logic: [
                          { label: "Type", value: "Parent \u2192 Child chain (28 rules)" },
                          { label: "Parents", value: "winword, excel, powerpnt, outlook, onenote, msaccess, mspub" },
                          { label: "Children", value: "cmd, powershell, wscript, cscript, msdt, bash, mshta, regsvr32, rundll32, certutil" },
                          { label: "Condition", value: "Parent process spawns child process directly" },
                          { label: "Example", value: "winword.exe \u2192 powershell.exe = macro execution" },
                        ] },
                      { cat: "Execution", name: "Script Engine Chains (WScript/CScript/PS/cmd)", sev: "high", count: 14, technique: "T1059.001, T1059.005",
                        logic: [
                          { label: "Type", value: "Parent \u2192 Child chain (14 rules)" },
                          { label: "Chains", value: "wscript\u2192cmd, wscript\u2192powershell, cscript\u2192cmd, ps\u2192ps (double-hop), cmd\u2192ps, ps\u2192wscript, ps\u2192bash" },
                          { label: "Condition", value: "Script interpreter spawns another interpreter \u2014 multi-stage execution" },
                        ] },
                      { cat: "Execution", name: "Service-Based Execution (svchost/WMI/Task Scheduler)", sev: "high", count: 18, technique: "T1047, T1569.002",
                        logic: [
                          { label: "Type", value: "Parent \u2192 Child chain (18 rules)" },
                          { label: "Parents", value: "svchost, wmiprvse, taskeng, taskhostw, wsmprovhost, dllhost, mmc" },
                          { label: "Children", value: "cmd, powershell, wscript, cscript, mshta, rundll32, regsvr32" },
                          { label: "Condition", value: "Windows service host or WMI provider spawns shell/script" },
                        ] },
                      { cat: "Execution", name: "Encoded PowerShell (-enc / -e flags)", sev: "critical", standalone: true, technique: "T1059.001",
                        logic: [
                          { label: "Process", value: "powershell.exe OR pwsh.exe" },
                          { label: "CommandLine", value: "regex: \\s+(-e\\s|-enc\\s|-encodedcommand\\s|-en\\s|-ec\\s)" },
                          { label: "Condition", value: "Both process name AND command line must match" },
                        ] },
                      { cat: "Credential Access", name: "Credential Dumping Commands (comsvcs/sekurlsa/mimikatz)", sev: "critical", standalone: true, technique: "T1003",
                        logic: [
                          { label: "CommandLine", value: "regex: comsvcs\\.dll | sekurlsa | lsadump | procdump.*lsass | mimikatz | pypykatz | nanodump" },
                          { label: "Condition", value: "Any process with matching command line argument" },
                        ] },
                      { cat: "Credential Access", name: "NTDS Extraction (ntdsutil/secretsdump)", sev: "critical", standalone: true, technique: "T1003.003",
                        logic: [
                          { label: "CommandLine", value: "regex: ntdsutil.*ifm | wbadmin.*ntds | secretsdump | ntds\\.dit" },
                          { label: "Condition", value: "Any process attempting Active Directory database extraction" },
                        ] },
                      { cat: "Credential Access", name: "LSASS Access Tools (procdump/processhacker)", sev: "critical", standalone: true, technique: "T1003.001",
                        logic: [
                          { label: "Process", value: "regex: ^(processhacker|procdump|sqldumper|avdump|handlekatz)(\\.exe)?$" },
                          { label: "Condition", value: "Process name matches known LSASS dumping tools" },
                        ] },
                      { cat: "Defense Evasion", name: "Shadow Copy Deletion / Log Clearing / SafeBoot", sev: "high", standalone: true, technique: "T1070",
                        logic: [
                          { label: "CommandLine", value: "regex: vssadmin.*delete | wevtutil\\s+cl | bcdedit.*safeboot | bcdedit.*recoveryenabled" },
                          { label: "Condition", value: "Any process with anti-forensic or recovery-disabling commands" },
                        ] },
                      { cat: "Persistence", name: "Account Manipulation (net user/group /add)", sev: "high", standalone: true, technique: "T1136",
                        logic: [
                          { label: "CommandLine", value: "regex: net\\s+(user|group|localgroup)\\s+.*/add" },
                          { label: "Condition", value: "Account or group creation via net.exe commands" },
                        ] },
                      { cat: "Lateral Movement", name: "WMI/WinRM Remote Commands", sev: "high", standalone: true, technique: "T1021",
                        logic: [
                          { label: "CommandLine", value: "regex: wmic.*/node: | winrm" },
                          { label: "Condition", value: "Remote execution via WMI or WinRM protocols" },
                        ] },
                      { cat: "Discovery", name: "AD Recon Tools (BloodHound/SharpHound/ADFind/Rubeus)", sev: "high", standalone: true, technique: "T1087.002",
                        logic: [
                          { label: "Process", value: "regex: ^(adfind|sharphound|bloodhound|sharpview|seatbelt|rubeus|certify|certipy)(\\.exe)?$" },
                          { label: "Condition", value: "Process name matches known Active Directory enumeration tools" },
                        ] },
                      { cat: "Discovery", name: "Network Scanners (netscan/masscan/rustscan)", sev: "high", standalone: true, technique: "T1046",
                        logic: [
                          { label: "Process", value: "regex: ^(netscan|netscan64|advanced_ip_scanner|rustscan|masscan|angry_ip_scanner|nbtscan)(\\.exe)?$" },
                          { label: "Condition", value: "Process name matches known network scanning tools" },
                        ] },
                      { cat: "Command & Control", name: "RMM Tools \u2014 Unusual Parent (AnyDesk/TeamViewer/RustDesk)", sev: "high", standalone: true, technique: "T1219",
                        logic: [
                          { label: "Process", value: "regex: ^(anydesk|splashtop|rustdesk|atera|screenconnect|teamviewer|supremo)(\\.exe)?$" },
                          { label: "Parent", value: "NOT explorer.exe (unusual parent = potentially injected or staged)" },
                          { label: "Condition", value: "RMM tool launched from non-standard parent process" },
                        ] },
                      { cat: "Exfiltration", name: "Exfiltration Tools (rclone/WinSCP/MegaSync)", sev: "high", standalone: true, technique: "T1567",
                        logic: [
                          { label: "Process", value: "regex: ^(rclone|filezilla|winscp|megasync|megacmd)(\\.exe)?$" },
                          { label: "Condition", value: "Process name matches known data transfer/sync tools" },
                        ] },
                      { cat: "Collection", name: "Suspicious Archive Operations (7z/rar with password)", sev: "high", standalone: true, technique: "T1560.001",
                        logic: [
                          { label: "CommandLine", value: "regex: \\b(7z|7za|winrar|rar)\\b.*(-p| a .*\\.(7z|zip|rar))" },
                          { label: "Condition", value: "Archive tool used with password flag or creating archive \u2014 potential data staging" },
                        ] },
                      { cat: "Execution", name: "Script from User Profile Path", sev: "high", standalone: true, technique: "T1059.005",
                        logic: [
                          { label: "Process", value: "wscript.exe OR cscript.exe" },
                          { label: "Image Path", value: "regex: \\\\users\\\\[^\\\\]+\\\\ OR \\\\appdata\\\\" },
                          { label: "Condition", value: "Script engine executing from user-writable profile directory" },
                        ] },
                      { cat: "Execution", name: "Suspicious Execution Path (temp/appdata/downloads)", sev: "medium", standalone: true, technique: "T1204",
                        logic: [
                          { label: "Image Path", value: "regex: \\\\temp\\\\ | \\\\tmp\\\\ | \\\\appdata\\\\ | \\\\downloads\\\\ | \\\\public\\\\ | \\\\recycle | \\\\perflogs\\\\" },
                          { label: "Exclusions", value: "Safe processes: mpcmdrun, msmpeng, tiworker, trustedinstaller, msiexec, etc." },
                          { label: "Condition", value: "Non-whitelisted process executing from user-writable or staging directory" },
                        ] },
                      { cat: "Command & Control", name: "RMM Tools \u2014 Normal Parent", sev: "low", standalone: true, technique: "T1219",
                        logic: [
                          { label: "Process", value: "regex: ^(anydesk|splashtop|rustdesk|atera|screenconnect|teamviewer|supremo)(\\.exe)?$" },
                          { label: "Parent", value: "explorer.exe (normal user-launched)" },
                          { label: "Condition", value: "RMM tool present on system \u2014 informational, may be legitimate" },
                        ] },
                      { cat: "Execution", name: "Parent-Child Chain Rules (344 rules)", sev: "high", count: 344, technique: "Multiple",
                        logic: [
                          { label: "Type", value: "344 parent\u2192child process chain rules across 12 ATT&CK tactics" },
                          { label: "Tactics", value: "Execution, Defense Evasion, Persistence, Privilege Escalation, Credential Access, Lateral Movement, Discovery, Collection, C2, Exfiltration, Impact, Initial Access" },
                          { label: "Parents", value: "Office apps, script engines, service hosts, shells, browsers, system processes, management tools, remote access" },
                          { label: "Severity", value: "Level 3 (critical): direct malware indicators. Level 2 (high): likely malicious. Level 1 (medium): suspicious, needs context. Level 0 (low): informational" },
                          { label: "Condition", value: "Exact parent\u2192child process name match (case-insensitive, .exe stripped). Highest severity wins if multiple rules match." },
                        ] },
                    ];
                    const PI_SEV_COLORS = { critical: "#f85149", high: "#f0883e", medium: "#d29922", low: "#8b949e" };
                    const piDisabledSet = modal.ptDisabledRules || new Set();
                    const piActiveCount = PI_RULES.length - [...piDisabledSet].filter((k) => k.startsWith("pi-")).length;
                    const piCustomCount = (modal.ptCustomRules || []).length;
                    const togglePiRule = (key) => setModal((p) => { const s = new Set(p.ptDisabledRules || []); s.has(key) ? s.delete(key) : s.add(key); return { ...p, ptDisabledRules: s }; });
                    const togglePiExpand = (key) => setModal((p) => ({ ...p, ptExpandedRule: p.ptExpandedRule === key ? null : key }));
                    const addPiCustomRule = () => {
                      const nr = modal.ptNewRule || {};
                      if (!nr.name) return;
                      setModal((p) => ({ ...p, ptCustomRules: [...(p.ptCustomRules || []), { ...nr }], ptAddingRule: false, ptNewRule: {} }));
                    };
                    const deletePiCustomRule = (idx) => setModal((p) => { const arr = [...(p.ptCustomRules || [])]; arr.splice(idx, 1); return { ...p, ptCustomRules: arr }; });

                    return (
                      <div style={{ marginTop: 4 }}>
                        <button onClick={() => setModal((p) => ({ ...p, showPtRules: !p.showPtRules }))}
                          style={{ width: "100%", padding: "10px 14px", background: `${th.accent}08`, border: `1px solid ${th.border}33`, borderRadius: 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "space-between", transition: "all 0.15s" }}>
                          <span style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                            Customize Rules
                          </span>
                          <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
                            <span>{piActiveCount}/{PI_RULES.length} rules{piCustomCount > 0 ? `, ${piCustomCount} custom` : ""}</span>
                            <span style={{ transform: modal.showPtRules ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.2s", fontSize: 12 }}>{"\u25BE"}</span>
                          </span>
                        </button>

                        {modal.showPtRules && (
                          <div style={{ padding: "10px 14px", borderLeft: `1px solid ${th.border}33`, borderRight: `1px solid ${th.border}33`, borderBottom: `1px solid ${th.border}33`, borderRadius: "0 0 10px 10px", background: `${th.panelBg}55` }}>
                            <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>
                              Detection Rules ({piActiveCount}/{PI_RULES.length})
                            </div>
                            {PI_RULES.map((r, i) => {
                              const key = `pi-${i}`;
                              const off = piDisabledSet.has(key);
                              const expanded = modal.ptExpandedRule === key;
                              return (
                                <div key={key}>
                                  <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", cursor: "pointer", opacity: off ? 0.45 : 1, transition: "opacity 0.15s" }}>
                                    <input type="checkbox" checked={!off} onChange={() => togglePiRule(key)} style={{ accentColor: th.accent, margin: 0, flexShrink: 0 }} />
                                    <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: PI_SEV_COLORS[r.sev] + "22", color: PI_SEV_COLORS[r.sev], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 52, textAlign: "center", textTransform: "uppercase" }}>{r.sev}</span>
                                    <span onClick={() => togglePiExpand(key)} style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1, cursor: "pointer" }}>{r.cat} {"\u2014"} {r.name}</span>
                                    <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{r.technique}</span>
                                    <span onClick={() => togglePiExpand(key)} style={{ fontSize: 9, color: expanded ? th.accent : th.textMuted, cursor: "pointer", padding: "0 2px", transform: expanded ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.2s", flexShrink: 0 }}>{"\u25BE"}</span>
                                  </div>
                                  {expanded && r.logic && (
                                    <div style={{ margin: "2px 0 6px 28px", padding: "8px 12px", background: `${th.accent}06`, border: `1px solid ${th.accent}18`, borderRadius: 6 }}>
                                      <div style={{ display: "grid", gridTemplateColumns: "90px 1fr", gap: "3px 10px", fontSize: 10, fontFamily: "'SF Mono', Menlo, monospace" }}>
                                        {r.logic.map((l, li) => (
                                          <div key={li} style={{ display: "contents" }}>
                                            <span style={{ color: th.textMuted, textTransform: "uppercase", fontSize: 9, fontWeight: 600, letterSpacing: "0.04em", paddingTop: 1 }}>{l.label}</span>
                                            <span style={{ color: th.text, lineHeight: 1.5, wordBreak: "break-word" }}>{l.value}</span>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              );
                            })}

                            {/* Custom rules */}
                            {(modal.ptCustomRules || []).length > 0 && (
                              <div style={{ marginTop: 10 }}>
                                <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Custom Rules</div>
                                {(modal.ptCustomRules || []).map((cr, i) => (
                                  <div key={`custom-${i}`} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0" }}>
                                    <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: PI_SEV_COLORS[cr.severity || "medium"] + "22", color: PI_SEV_COLORS[cr.severity || "medium"], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 52, textAlign: "center", textTransform: "uppercase" }}>{cr.severity || "med"}</span>
                                    <span style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{cr.category || "Custom"} {"\u2014"} {cr.name || "Custom Rule"}</span>
                                    <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{cr.technique || ""}</span>
                                    <button onClick={() => deletePiCustomRule(i)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "0 4px", lineHeight: 1 }} onMouseEnter={(e) => e.currentTarget.style.color = th.danger || "#f85149"} onMouseLeave={(e) => e.currentTarget.style.color = th.textMuted}>{"\u00D7"}</button>
                                  </div>
                                ))}
                              </div>
                            )}

                            {/* Add custom rule */}
                            {!modal.ptAddingRule ? (
                              <button onClick={() => setModal((p) => ({ ...p, ptAddingRule: true, ptNewRule: {} }))}
                                style={{ ...ms.bsm, marginTop: 8, display: "flex", alignItems: "center", gap: 4 }}>
                                <span style={{ fontSize: 13, lineHeight: 1 }}>+</span> Add Custom Rule
                              </button>
                            ) : (
                              <div style={{ marginTop: 8, padding: "10px 12px", background: `${th.accent}08`, border: `1px solid ${th.accent}22`, borderRadius: 8 }}>
                                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
                                  <input value={(modal.ptNewRule || {}).category || ""} onChange={(e) => setModal((p) => ({ ...p, ptNewRule: { ...p.ptNewRule, category: e.target.value } }))} placeholder="Category (e.g. Execution)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                  <input value={(modal.ptNewRule || {}).name || ""} onChange={(e) => setModal((p) => ({ ...p, ptNewRule: { ...p.ptNewRule, name: e.target.value } }))} placeholder="Rule Name" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                  <input value={(modal.ptNewRule || {}).technique || ""} onChange={(e) => setModal((p) => ({ ...p, ptNewRule: { ...p.ptNewRule, technique: e.target.value } }))} placeholder="MITRE Technique (e.g. T1059)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                  <select value={(modal.ptNewRule || {}).severity || "medium"} onChange={(e) => setModal((p) => ({ ...p, ptNewRule: { ...p.ptNewRule, severity: e.target.value } }))}
                                    style={{ ...ms.sl, fontSize: 11, padding: "4px 8px" }}>
                                    <option value="critical">Critical</option>
                                    <option value="high">High</option>
                                    <option value="medium">Medium</option>
                                    <option value="low">Low</option>
                                  </select>
                                  <input value={(modal.ptNewRule || {}).pattern || ""} onChange={(e) => setModal((p) => ({ ...p, ptNewRule: { ...p.ptNewRule, pattern: e.target.value } }))} placeholder="Regex pattern for process/cmdline (optional)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px", gridColumn: "1 / -1" }} />
                                </div>
                                <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginTop: 8 }}>
                                  <button onClick={() => setModal((p) => ({ ...p, ptAddingRule: false, ptNewRule: {} }))} style={ms.bsm}>Cancel</button>
                                  <button onClick={addPiCustomRule} style={{ ...ms.bsm, background: th.primaryBtn || th.accent, color: "#fff", border: "none" }}>Add Rule</button>
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })()}

                  {modal.error && <div style={{ marginTop: 12, padding: "8px 12px", background: (th.danger || "#f85149") + "22", borderRadius: 6, fontSize: 12, color: th.danger || "#f85149" }}>{modal.error}</div>}
                  <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
                    <button onClick={() => setModal(null)} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif" }}>Cancel</button>
                    <button onClick={handleBuild} disabled={!hasCols} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, cursor: hasCols ? "pointer" : "not-allowed", background: hasCols ? (th.accent) : th.border, color: "#fff", border: "none", fontFamily: "-apple-system, sans-serif" }}>Build Tree</button>
                  </div>
                </div>
              )}

              {/* Loading phase */}
              {phase === "loading" && (() => {
                const prog = modal.ptProgress || 0;
                const pi = modal.ptPhaseIdx || 0;
                const ptPhases = ["Querying database...", "Parsing process events...", "Building parent-child relationships...", "Computing tree depth...", "Finalizing...", "Complete"];
                return (
                  <div style={{ padding: "50px 40px 40px", textAlign: "center", flex: 1 }}>
                    <style>{`@keyframes ptPulse{0%,100%{opacity:.35}50%{opacity:1}}`}</style>
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.5" strokeLinecap="round" style={{ marginBottom: 16, animation: "ptPulse 1.5s ease-in-out infinite" }}>
                      <rect x="3" y="10" width="5" height="5" rx="1" fill={th.accent + "33"} />
                      <rect x="14" y="3" width="5" height="5" rx="1" fill={th.accent + "33"} />
                      <rect x="14" y="16" width="5" height="5" rx="1" fill={th.accent + "33"} />
                      <path d="M8 12.5h3v-7h3M11 12.5v5.5h3" />
                    </svg>
                    <div style={{ marginBottom: 20 }}>
                      <div style={{ fontSize: 14, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", marginBottom: 4 }}>Building Process Tree</div>
                      <div style={{ fontSize: 11, color: th.accent, fontFamily: "-apple-system, sans-serif", height: 16 }}>{ptPhases[pi]}</div>
                    </div>
                    <div style={{ width: 280, margin: "0 auto", height: 6, background: th.border + "33", borderRadius: 3, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${prog}%`, background: `linear-gradient(90deg, ${th.accent}, ${th.accent}cc)`, borderRadius: 3, transition: "width 0.3s ease-out" }} />
                    </div>
                    <div style={{ fontSize: 11, color: th.textMuted, marginTop: 8, fontFamily: "SF Mono, Menlo, monospace" }}>{Math.round(prog)}%</div>
                    <div style={{ marginTop: 24 }}>
                      <button onClick={() => setModal((p) => ({ ...p, phase: "config", loading: false, ptProgress: 0, _cancelled: true }))}
                        style={{ padding: "4px 16px", fontSize: 11, background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, borderRadius: 6, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Cancel</button>
                    </div>
                  </div>
                );
              })()}

              {/* Results phase */}
              {phase === "results" && data && (
                <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
                  {/* Toolbar: search + expand/collapse */}
                  <div style={{ padding: "8px 20px", borderBottom: `1px solid ${th.border}55`, flexShrink: 0, display: "flex", alignItems: "center", gap: 8, background: `${th.headerBg}88`, backdropFilter: "blur(12px) saturate(1.3)", WebkitBackdropFilter: "blur(12px) saturate(1.3)" }}>
                    <input value={searchText || ""} onChange={(e) => setModal((p) => ({ ...p, searchText: e.target.value }))} placeholder="Search by process name, PID, command line, or user..." style={{ flex: 1, background: th.bgInput, color: th.text, border: `1px solid ${th.border}`, borderRadius: 5, padding: "6px 10px", fontSize: 12, fontFamily: "monospace", outline: "none", boxSizing: "border-box" }} />
                    <button onClick={expandAll} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }} title="Expand all nodes">Expand All</button>
                    <button onClick={collapseAll} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }} title="Collapse all nodes">Collapse</button>
                    <select onChange={(e) => { if (e.target.value) expandToDepth(parseInt(e.target.value)); }} value="" style={{ padding: "4px 4px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.bgInput, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>
                      <option value="">Depth...</option>
                      {[1, 2, 3, 4, 5].filter((d) => d <= (data.stats.maxDepth || 5)).map((d) => <option key={d} value={d}>Depth {d}</option>)}
                    </select>
                    {/* Suspicious Only toggle */}
                    <button onClick={() => setModal((p) => p ? { ...p, susOnlyFilter: !p.susOnlyFilter } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: modal.susOnlyFilter ? (th.danger || "#f85149") + "22" : th.btnBg, color: modal.susOnlyFilter ? (th.danger || "#f85149") : th.textDim, border: `1px solid ${modal.susOnlyFilter ? (th.danger || "#f85149") + "55" : th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: modal.susOnlyFilter ? 600 : 400 }} title="Show only suspicious processes">{modal.susOnlyFilter ? "\u26A0 Suspicious Only" : "Suspicious Only"}</button>
                    {selectedKey && <button onClick={() => setModal((p) => p ? { ...p, selectedKey: null } : p)} style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: (th.accent || "#58a6ff") + "22", color: th.accent || "#58a6ff", border: `1px solid ${(th.accent || "#58a6ff")}55`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Clear Chain</button>}
                    {/* Separator */}
                    <div style={{ width: 1, height: 16, background: th.border, flexShrink: 0 }} />
                    {/* Copy Chain — ancestry from selected node to root */}
                    {selectedKey && <button onClick={() => {
                      const lines = [];
                      const chain = [];
                      let cur = selectedKey;
                      while (cur && byKeyMap.has(cur)) { chain.unshift(byKeyMap.get(cur)); cur = byKeyMap.get(cur).parentKey; }
                      chain.forEach((n, i) => {
                        const indent = "  ".repeat(i);
                        const prefix = i === 0 ? "" : "\u2514\u2500 ";
                        lines.push(`${indent}${prefix}${n.processName} (PID: ${n.pid}${n.user ? ", " + n.user : ""}${n.ts ? ", " + n.ts : ""})`);
                        if (n.cmdLine) lines.push(`${indent}   ${n.cmdLine}`);
                      });
                      navigator.clipboard.writeText(lines.join("\n"));
                    }} title="Copy ancestry chain to clipboard" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.accent || "#58a6ff", border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Copy Chain</button>}
                    {/* Copy Tree — all visible nodes as indented text */}
                    <button onClick={() => {
                      const lines = [];
                      flatNodes.forEach((n) => {
                        const indent = "  ".repeat(n.depth);
                        const connector = n.depth > 0 ? (n.isLast ? "\u2514\u2500 " : "\u251C\u2500 ") : "";
                        lines.push(`${indent}${connector}${n.processName} (PID: ${n.pid}, PPID: ${n.ppid}${n.user ? ", " + n.user : ""}${n.ts ? ", " + n.ts : ""})`);
                        if (n.cmdLine) lines.push(`${indent}${n.depth > 0 ? "   " : ""}  ${n.cmdLine}`);
                      });
                      navigator.clipboard.writeText(lines.join("\n"));
                    }} title="Copy visible tree as text" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Copy Tree</button>
                    {/* Copy CSV — tab-separated for spreadsheets */}
                    <button onClick={() => {
                      const header = ["Hostname", "ParentProcessName", "ProcessName", "PID", "PPID", "User", "Timestamp", "ImagePath", "CommandLine", "Provider", "EventID", "Elevation", "Integrity", "Depth"].join("\t");
                      const rows = flatNodes.map((n) => [
                        n.hostname || "", n.parentProcessName || "", n.processName, n.pid, n.ppid, n.user || "", n.ts || "", n.image || "", n.cmdLine || "",
                        n.provider || "", n.eventId || "", n.elevation || "", n.integrity || "", n.depth
                      ].join("\t"));
                      navigator.clipboard.writeText([header, ...rows].join("\n"));
                    }} title="Copy as tab-separated CSV" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0 }}>Copy CSV</button>
                    {/* Copy Selected — only checked rows */}
                    {ptCheckedCount > 0 && <button onClick={() => {
                      const header = ["Timestamp", "Detection", "Provider", "EventID", "ParentProcess", "Process", "PID", "PPID", "User", "CommandLine", "ImagePath", "Integrity"].join("\t");
                      const rows = flatNodes.filter((n) => ptChecked.has(n.key)).map((n) => {
                        const det = (_ptDetMap.get(n.key) || {}).reason || "";
                        return [n.ts || "", det, _providerShort(n.provider), n.eventId || "", n.parentProcessName || "", n.processName, n.pid, n.ppid, n.user || "", n.cmdLine || "", n.image || "", _integrityShort(n.integrity)].join("\t");
                      });
                      navigator.clipboard.writeText([header, ...rows].join("\n"));
                    }} title="Copy selected rows as tab-separated" style={{ padding: "4px 8px", borderRadius: 4, fontSize: 10, cursor: "pointer", background: (th.accent) + "22", color: th.accent, border: `1px solid ${th.accent}55`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", flexShrink: 0, fontWeight: 600 }}>Copy Selected ({ptCheckedCount})</button>}
                  </div>

                  {/* Event Timeline — interactive dots */}
                  {(() => {
                    const times = flatNodes.filter(n => n.ts).map(n => ({ t: new Date(n.ts).getTime(), key: n.key })).filter(d => !isNaN(d.t));
                    if (times.length < 2) return null;
                    const tVals = times.map(d => d.t);
                    const tMin = Math.min(...tVals.slice(0, 10000));
                    const tMax = Math.max(...tVals.slice(0, 10000));
                    if (tMin === tMax) return null;
                    const range = tMax - tMin || 1;
                    // Limit dots to first 500 for rendering performance
                    const dotEvents = times.slice(0, 500);
                    return (
                      <div style={{ padding: "8px 20px 4px", borderBottom: `1px solid ${th.border}44`, background: `${th.modalBg}99`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", flexShrink: 0 }}>
                        <div style={{ fontSize: 9, color: th.textMuted, marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.08em", fontFamily: "'SF Mono', Menlo, monospace" }}>Event Timeline</div>
                        <div style={{ position: "relative", height: 40, background: `${th.bgInput}99`, borderRadius: 6, overflow: "hidden", border: `1px solid ${th.border}55` }}>
                          {/* Time axis labels */}
                          {[0, 0.25, 0.5, 0.75, 1].map((pct) => {
                            const t = new Date(tMin + range * pct);
                            return <span key={pct} style={{ position: "absolute", bottom: 2, left: `${pct * 100}%`, transform: "translateX(-50%)", fontSize: 8, color: th.textMuted + "88", fontFamily: "'SF Mono', Menlo, monospace", whiteSpace: "nowrap" }}>{t.toISOString().substr(11, 8)}</span>;
                          })}
                          {/* Event dots */}
                          {dotEvents.map((d) => {
                            const left = ((d.t - tMin) / range) * 100;
                            const nd = byKeyMap.get(d.key);
                            const pnd = nd ? byKeyMap.get(nd.parentKey) : null;
                            const isSus = nd && pnd ? getSusInfo(nd, pnd).level > 0 : false;
                            const isSel = d.key === selectedKey;
                            return <div key={d.key} onClick={(e) => { e.stopPropagation(); setModal((p) => p ? { ...p, selectedKey: d.key } : p); }}
                              title={nd ? `${nd.processName} (PID: ${nd.pid}) \u2014 ${nd.ts}` : ""}
                              style={{ position: "absolute", left: `${left}%`, top: "38%", transform: "translate(-50%, -50%)", width: isSel ? 12 : 8, height: isSel ? 12 : 8, borderRadius: "50%", background: isSus ? (th.danger || "#f85149") : isSel ? (th.accent) : (th.success || "#3fb950"), border: isSel ? "2px solid #fff" : `1px solid rgba(255,255,255,0.2)`, cursor: "pointer", transition: "all 0.15s ease", boxShadow: isSus ? `0 0 8px ${th.danger || "#f85149"}66` : isSel ? `0 0 8px ${th.accent}55` : "none", zIndex: isSel ? 10 : isSus ? 5 : 1 }} />;
                          })}
                        </div>
                      </div>
                    );
                  })()}

                  {/* Main content: tree + optional right detail panel */}
                  <div style={{ display: "flex", flex: 1, minHeight: 0 }}>

                  {/* Column headers + Tree — virtualized */}
                  {(() => {
                    const PT_ROW_H = 32, OVERSCAN = 8;
                    const ptST = ptScroll.top;
                    const ptCH = ptScroll.h;
                    const totalRows = flatNodes.length;
                    const totalH = totalRows * PT_ROW_H;
                    const startIdx = Math.max(0, Math.floor(ptST / PT_ROW_H) - OVERSCAN);
                    const endIdx = Math.min(totalRows, Math.ceil((ptST + ptCH) / PT_ROW_H) + OVERSCAN);
                    const visibleSlice = flatNodes.slice(startIdx, endIdx);

                    return (
                      <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0, minWidth: 0, overflow: "hidden" }}>
                        {/* Fixed column header — OUTSIDE scroll container to prevent overlap */}
                        <div ref={ptHeaderRef} style={{ flexShrink: 0, overflowX: "hidden", backgroundColor: th.modalBg, backgroundImage: `linear-gradient(180deg, ${th.accent}22 0%, transparent 100%)`, borderBottom: `2px solid ${th.accent}55`, boxShadow: `0 2px 8px ${th.accent}18` }}>
                          {/* Filter active indicator */}
                          {ptActiveFilterCount > 0 && (
                            <div style={{ padding: "4px 12px", display: "flex", alignItems: "center", gap: 8, borderBottom: `1px solid ${th.border}33`, borderLeft: `3px solid ${th.accent || "#58a6ff"}`, minWidth: totalPtW }}>
                              <span style={{ fontSize: 10, fontWeight: 600, color: th.accent || "#58a6ff", fontFamily: "-apple-system, sans-serif" }}>Filter active ({ptActiveFilterCount} column{ptActiveFilterCount > 1 ? "s" : ""})</span>
                              <span style={{ fontSize: 10, color: th.textDim }}>{"\u2014"} {flatNodes.length} of {data.stats.totalProcesses} processes</span>
                              <button onClick={() => setModal((p) => ({ ...p, ptColFilters: {} }))} style={{ padding: "1px 8px", fontSize: 9, background: th.accent || "#58a6ff", color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>Clear All</button>
                            </div>
                          )}
                          {/* Column header row */}
                          <div style={{ display: "flex", minWidth: totalPtW }}>
                            {/* Select-all checkbox */}
                            <div style={{ width: PT_CHK_W, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", boxSizing: "border-box" }}>
                              <input type="checkbox" checked={flatNodes.length > 0 && ptCheckedCount === flatNodes.length} ref={(el) => { if (el) el.indeterminate = ptCheckedCount > 0 && ptCheckedCount < flatNodes.length; }}
                                onChange={() => { setModal((p) => { if (!p) return p; const cur = p.ptChecked || new Set(); if (cur.size === flatNodes.length) return { ...p, ptChecked: new Set() }; return { ...p, ptChecked: new Set(flatNodes.map((n) => n.key)) }; }); }}
                                style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} title="Select all" />
                            </div>
                            {ptHeaders.map((h) => (
                              <div key={h} onClick={() => togglePtSort(h)} style={{ width: ptColWidths[h] || ptDefWidths[h], flexShrink: 0, padding: "9px 8px", fontSize: 11, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, color: (ptSortCol || "Timestamp") === h ? th.accent : `${th.accent}99`, textTransform: "uppercase", letterSpacing: "0.08em", whiteSpace: "nowrap", overflow: "hidden", userSelect: "none", position: "relative", boxSizing: "border-box", cursor: "pointer" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 3 }}>
                                  <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{h}</span>
                                  {(ptSortCol || "Timestamp") === h && <span style={{ fontSize: 7, color: th.accent || "#58a6ff" }}>{(ptSortDir || "asc") === "asc" ? "\u25B2" : "\u25BC"}</span>}
                                  <span onClick={(e) => { e.stopPropagation(); openPtFilter(h, e); }} style={{ cursor: "pointer", fontSize: 7, color: ptColFilters[h] ? (th.accent || "#58a6ff") : (th.textDim) + "66", flexShrink: 0, marginLeft: "auto", paddingRight: 8 }}>{"\u25BC"}</span>
                                  <div onMouseDown={(e) => { e.stopPropagation(); onPtResizeStart(h, e); }} style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 6, cursor: "col-resize" }}>
                                    <div style={{ position: "absolute", right: 2, top: 4, bottom: 4, width: 1, background: `${th.accent}44` }} />
                                  </div>
                                </div>
                              </div>
                            ))}
                            <div style={{ width: 50, flexShrink: 0, padding: "6px 4px", fontSize: 9, fontFamily: "-apple-system, sans-serif", color: th.textDim, userSelect: "none" }} />
                          </div>
                        </div>
                        {/* Scrollable rows — header stays fixed above */}
                        <div ref={ptScrollRef} onScroll={(e) => {
                          const el = e.currentTarget;
                          const st = el.scrollTop;
                          const ch = el.clientHeight;
                          if (ptHeaderRef.current) ptHeaderRef.current.scrollLeft = el.scrollLeft;
                          if (ptRafRef.current) cancelAnimationFrame(ptRafRef.current);
                          ptRafRef.current = requestAnimationFrame(() => {
                            setPtScroll((p) => {
                              const oldStart = Math.floor(p.top / PT_ROW_H);
                              const newStart = Math.floor(st / PT_ROW_H);
                              if (newStart === oldStart && p.h === ch) return p;
                              return { top: st, h: ch };
                            });
                          });
                        }} style={{ flex: 1, overflowY: "auto", overflowX: "auto", minHeight: 0, contain: "strict", willChange: "transform" }}>
                        {/* Virtualized tree rows */}
                        {flatNodes.length === 0 && (
                          <div style={{ padding: 20, textAlign: "center", color: th.textDim, fontSize: 12 }}>{searchText ? "No matching processes" : "No process creation events found"}</div>
                        )}
                        {flatNodes.length > 0 && (
                          <div style={{ height: totalH, position: "relative", minWidth: totalPtW, contain: "layout size" }}>
                            <div style={{ position: "absolute", top: startIdx * PT_ROW_H, left: 0, right: 0 }}>
                              {visibleSlice.map((node, vi) => {
                                const i = startIdx + vi;
                                const susInfo = _ptDetMap.get(node.key) || { level: 0, reason: null };
                                const sus = susInfo.level;
                                const susColor = SUS_COLORS[sus];
                                const hasChildren = node.childCount > 0;
                                const isExpanded = !!expandedNodes[node.key];
                                const tsDisplay = (node.ts || "").replace("T", " ").substring(0, 19);
                                const inChain = chainKeys.has(node.key);
                                const isSelected = node.key === selectedKey;
                                const lineColor = th.textMuted || th.textDim || "#888";
                                const chainColor = th.accent || "#58a6ff";
                                const INDENT = 20, LEFT_PAD = 16;

                                return (
                                  <div key={node.key + ":" + i}
                                    onClick={() => setModal((p) => p ? { ...p, selectedKey: p.selectedKey === node.key ? null : node.key } : p)}
                                    className={isSelected ? "pt-row pt-sel" : "pt-row"}
                                    style={{ display: "flex", height: PT_ROW_H, fontSize: 12.5, fontFamily: "'SF Mono', Menlo, monospace", cursor: "pointer", background: isSelected ? (th.accent) + "10" : susColor && !inChain ? susColor + "06" : "transparent", borderBottom: `1px solid ${th.border}18`, borderLeft: isSelected ? `2px solid ${chainColor}` : susColor ? `2px solid ${susColor}55` : "2px solid transparent", alignItems: "center", minHeight: 34, contain: "layout style" }}>

                                    {/* Row checkbox */}
                                    <div style={{ width: PT_CHK_W, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", boxSizing: "border-box" }}>
                                      <input type="checkbox" checked={ptChecked.has(node.key)}
                                        onClick={(e) => e.stopPropagation()}
                                        onChange={() => { setModal((p) => { if (!p) return p; const s = new Set(p.ptChecked || []); if (s.has(node.key)) s.delete(node.key); else s.add(node.key); return { ...p, ptChecked: s }; }); }}
                                        style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                                    </div>

                                    {/* Timestamp column */}
                                    <div style={{ width: ptColWidths.Timestamp || ptDefWidths.Timestamp, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                                      <span style={{ fontFamily: "monospace", color: th.textDim, fontSize: 12.5, whiteSpace: "nowrap" }}>{tsDisplay}</span>
                                    </div>

                                    {/* Detection column */}
                                    <div style={{ width: ptColWidths.Detection || ptDefWidths.Detection, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                                      {susInfo.reason && <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 4, background: susColor + "22", color: susColor, border: `1px solid ${susColor}44`, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={susInfo.reason}>{susInfo.reason}</span>}
                                    </div>

                                    {/* Provider column */}
                                    <div style={{ width: ptColWidths.Provider || ptDefWidths.Provider, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                                      <span style={{ fontSize: 12, color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{_providerShort(node.provider)}</span>
                                    </div>

                                    {/* Event ID column */}
                                    <div style={{ width: ptColWidths["Event ID"] || ptDefWidths["Event ID"], flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                                      <span style={{ fontFamily: "monospace", color: th.textDim, fontSize: 12, whiteSpace: "nowrap" }}>{node.eventId || ""}</span>
                                    </div>

                                    {/* Parent Process column */}
                                    <div style={{ width: ptColWidths["Parent Process"] || ptDefWidths["Parent Process"], flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                                      <span style={{ color: th.textDim, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={node.parentImage}>{node.parentProcessName || ""}</span>
                                    </div>

                                    {/* Process column */}
                                    <div style={{ width: ptColWidths.Process || ptDefWidths.Process, flexShrink: 0, position: "relative", display: "flex", alignItems: "center", gap: 4, overflow: "hidden", boxSizing: "border-box" }}>
                                      {node.depth > 0 && (node.connectors || []).map((active, d) => (
                                        active ? <div key={`vl${d}`} style={{ position: "absolute", left: LEFT_PAD + d * INDENT + INDENT / 2, top: 0, bottom: 0, width: 1, background: inChain && d >= 0 ? chainColor + "66" : lineColor + "44" }} /> : null
                                      ))}
                                      {node.depth > 0 && (
                                        <>
                                          <div style={{ position: "absolute", left: LEFT_PAD + (node.depth - 1) * INDENT + INDENT / 2, top: 0, height: node.isLast ? PT_ROW_H / 2 : PT_ROW_H, width: 1, background: inChain ? chainColor + "88" : lineColor + "44" }} />
                                          <div style={{ position: "absolute", left: LEFT_PAD + (node.depth - 1) * INDENT + INDENT / 2, top: PT_ROW_H / 2, width: INDENT / 2 + 2, height: 1, background: inChain ? chainColor + "88" : lineColor + "44" }} />
                                        </>
                                      )}
                                      <div style={{ width: LEFT_PAD + node.depth * INDENT, minWidth: LEFT_PAD + node.depth * INDENT, flexShrink: 0 }} />
                                      <span onClick={(e) => { e.stopPropagation(); if (hasChildren) setModal((p) => { const en = { ...p.expandedNodes }; if (en[node.key]) delete en[node.key]; else en[node.key] = true; return { ...p, expandedNodes: en }; }); }}
                                        style={{ width: 14, textAlign: "center", color: hasChildren ? (inChain ? chainColor : th.textDim) : "transparent", fontSize: 11, flexShrink: 0, userSelect: "none" }}>
                                        {hasChildren ? (isExpanded ? "\u25BC" : "\u25B6") : "\u00B7"}
                                      </span>
                                      {inChain && <div style={{ width: 6, height: 6, borderRadius: "50%", background: chainColor, flexShrink: 0 }} />}
                                      {ptIcon(node.processName)}
                                      <span style={{ fontWeight: 600, color: isSelected ? chainColor : susColor || th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0 }} title={node.image}>{node.processName}</span>
                                      {node.childCount > 0 && <span style={{ fontSize: 11, color: th.accent, flexShrink: 0, paddingRight: 4 }}>({node.childCount})</span>}
                                    </div>

                                    {/* PID column */}
                                    <div style={{ width: ptColWidths.PID || ptDefWidths.PID, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                                      <span style={{ fontFamily: "monospace", color: inChain ? chainColor + "cc" : th.textDim, fontSize: 12.5, whiteSpace: "nowrap" }}>{node.pid}</span>
                                    </div>

                                    {/* PPID column */}
                                    <div style={{ width: ptColWidths.PPID || ptDefWidths.PPID, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                                      <span style={{ fontFamily: "monospace", color: th.textDim, fontSize: 12.5, whiteSpace: "nowrap" }}>{node.ppid || ""}</span>
                                    </div>

                                    {/* User column */}
                                    <div style={{ width: ptColWidths.User || ptDefWidths.User, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                                      <span style={{ color: th.textDim, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{node.user || ""}</span>
                                    </div>

                                    {/* Command Line column */}
                                    <div style={{ width: ptColWidths["Command Line"] || ptDefWidths["Command Line"], flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                                      <span style={{ color: th.textDim, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={node.cmdLine}>{node.cmdLine}</span>
                                    </div>

                                    {/* Integrity column */}
                                    <div style={{ width: ptColWidths.Integrity || ptDefWidths.Integrity, flexShrink: 0, display: "flex", alignItems: "center", padding: "0 8px", overflow: "hidden", boxSizing: "border-box" }}>
                                      {(() => { const il = _integrityShort(node.integrity); const ic = INT_COLOR[il]; return il ? <span style={{ fontSize: 11, padding: "2px 6px", borderRadius: 3, background: (ic || th.textDim) + "18", color: ic || th.textDim, fontWeight: 500, whiteSpace: "nowrap" }}>{il}</span> : null; })()}
                                    </div>

                                    {/* Filter grid button */}
                                    <div style={{ width: 50, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
                                      <button onClick={(e) => {
                                        e.stopPropagation();
                                        if (cols.pid && node.pid) {
                                          const cbf = { ...(ct.checkboxFilters || {}) };
                                          cbf[cols.pid] = [node.pid];
                                          if (cols.eventId) delete cbf[cols.eventId];
                                          up("checkboxFilters", cbf);
                                        }
                                        setModal(null);
                                      }} title="Filter grid to this process" style={{ background: "none", border: `1px solid ${th.border}`, borderRadius: 4, color: th.textDim, fontSize: 10, padding: "2px 6px", cursor: "pointer" }}>Filter</button>
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}
                      </div>
                      </div>
                    );
                  })()}

                  {/* Column filter dropdown popup */}
                  {ptFilterOpen && (
                    <>
                      <div style={{ position: "fixed", inset: 0, zIndex: 998 }} onClick={() => setModal((p) => ({ ...p, ptFilterOpen: null }))} />
                      <div style={{ position: "fixed", left: modal.ptFilterX ?? Math.min(ptFilterPos.x || 0, window.innerWidth - 340), top: modal.ptFilterY ?? Math.min(ptFilterPos.y || 0, window.innerHeight - 440), width: modal.ptFilterW || 320, height: modal.ptFilterH || 420, background: th.modalBg, border: `1px solid ${th.border}`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 999, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                        <div style={{ padding: "8px 10px", borderBottom: `1px solid ${th.border}33`, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "grab", userSelect: "none", flexShrink: 0 }}
                          onMouseDown={(e) => {
                            e.preventDefault();
                            const startX = e.clientX, startY = e.clientY;
                            const startLeft = modal.ptFilterX ?? Math.min(ptFilterPos.x || 0, window.innerWidth - 340);
                            const startTop = modal.ptFilterY ?? Math.min(ptFilterPos.y || 0, window.innerHeight - 440);
                            document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                            const onMove = (ev) => setModal((p) => ({ ...p, ptFilterX: startLeft + ev.clientX - startX, ptFilterY: startTop + ev.clientY - startY }));
                            const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                            window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                          }}>
                          <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "SF Mono, Menlo, monospace" }}>FILTER {"\u2014"} {(ptFilterOpen || "").toUpperCase()}</span>
                          <span style={{ cursor: "pointer", color: th.textDim, fontSize: 14, lineHeight: 1 }} onClick={() => setModal((p) => ({ ...p, ptFilterOpen: null }))}>{"\u00D7"}</span>
                        </div>
                        <div style={{ padding: "6px 10px", flexShrink: 0 }}>
                          <input type="text" placeholder="Search values..." value={ptFilterSearch} onChange={(e) => setModal((p) => ({ ...p, ptFilterSearch: e.target.value }))}
                            style={{ width: "100%", boxSizing: "border-box", padding: "5px 8px", fontSize: 11, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}55`, borderRadius: 4, color: th.text, outline: "none", fontFamily: "SF Mono, Menlo, monospace" }}
                            autoFocus />
                        </div>
                        <div style={{ padding: "2px 10px 6px", display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                          <button onClick={() => setModal((p) => ({ ...p, ptFilterSel: new Set(ptFilterVals) }))} style={{ padding: "2px 8px", fontSize: 10, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                          <button onClick={() => setModal((p) => ({ ...p, ptFilterSel: new Set() }))} style={{ padding: "2px 8px", fontSize: 10, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                          <span style={{ fontSize: 9, color: th.textDim, marginLeft: "auto" }}>{ptFilterSel.size} of {ptFilterVals.length}</span>
                        </div>
                        <div style={{ flex: 1, overflowY: "auto", minHeight: 0, padding: "0 4px" }}>
                          {ptFilterDisplay.map((val) => (
                            <label key={val} style={{ display: "flex", alignItems: "center", gap: 6, padding: "2px 6px", cursor: "pointer", fontSize: 11, fontFamily: "SF Mono, Menlo, monospace", color: th.text, borderRadius: 3 }}
                              onMouseEnter={(e) => e.currentTarget.style.background = th.bgHover || th.border + "22"}
                              onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                              <input type="checkbox" checked={ptFilterSel.has(val)} onChange={() => setModal((p) => {
                                const s = new Set(p.ptFilterSel || []);
                                if (s.has(val)) s.delete(val); else s.add(val);
                                return { ...p, ptFilterSel: s };
                              })} style={{ width: 13, height: 13, accentColor: th.accent || "#58a6ff" }} />
                              <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{val || "(empty)"}</span>
                              <span style={{ fontSize: 9, color: th.textDim, flexShrink: 0 }}>{ptFilterCounts[val] || 0}</span>
                            </label>
                          ))}
                        </div>
                        <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}33`, display: "flex", gap: 6, justifyContent: "flex-end", flexShrink: 0 }}>
                          <button onClick={() => setModal((p) => ({ ...p, ptFilterOpen: null }))} style={{ padding: "4px 12px", fontSize: 10, background: th.bgInput || th.panelBg, border: `1px solid ${th.border}`, borderRadius: 4, color: th.textDim, cursor: "pointer" }}>Cancel</button>
                          <button onClick={() => {
                            const selected = [...ptFilterSel];
                            const all = ptFilterVals;
                            setModal((p) => {
                              const filters = { ...(p.ptColFilters || {}) };
                              if (selected.length === 0 || selected.length === all.length) { delete filters[ptFilterOpen]; }
                              else { filters[ptFilterOpen] = selected; }
                              return { ...p, ptColFilters: filters, ptFilterOpen: null };
                            });
                          }} style={{ padding: "4px 12px", fontSize: 10, background: th.accent || "#58a6ff", color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600 }}>Apply</button>
                          <button onClick={() => {
                            setModal((p) => {
                              const filters = { ...(p.ptColFilters || {}) };
                              delete filters[ptFilterOpen];
                              return { ...p, ptColFilters: filters, ptFilterOpen: null };
                            });
                          }} style={{ padding: "4px 12px", fontSize: 10, background: "transparent", border: `1px solid ${th.border}`, borderRadius: 4, color: th.textDim, cursor: "pointer" }}>Reset</button>
                        </div>
                        {/* Resize grip */}
                        <div onMouseDown={(e) => {
                          e.preventDefault(); e.stopPropagation();
                          const startX = e.clientX, startY = e.clientY;
                          const startW = modal.ptFilterW || 320, startH = modal.ptFilterH || 420;
                          document.body.style.cursor = "nwse-resize"; document.body.style.userSelect = "none";
                          const onMove = (ev) => setModal((p) => ({ ...p, ptFilterW: Math.max(200, startW + ev.clientX - startX), ptFilterH: Math.max(200, startH + ev.clientY - startY) }));
                          const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                        }} style={{ position: "absolute", right: 0, bottom: 0, width: 16, height: 16, cursor: "nwse-resize" }}>
                          <svg width="16" height="16" viewBox="0 0 16 16" style={{ position: "absolute", right: 2, bottom: 2 }}>
                            <line x1="12" y1="4" x2="4" y2="12" stroke={th.textDim} strokeWidth="1" />
                            <line x1="12" y1="8" x2="8" y2="12" stroke={th.textDim} strokeWidth="1" />
                          </svg>
                        </div>
                      </div>
                    </>
                  )}

                  {/* Right-side Detail Panel — prototype grid layout, resizable */}
                  {(() => {
                    const detailW = modal.ptDetailW || 380;
                    const detailResizeHandle = (
                      <div onMouseDown={(e) => {
                        e.preventDefault(); e.stopPropagation();
                        const startX = e.clientX;
                        const startW = modal.ptDetailW || 380;
                        document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
                        const onMove = (ev) => { const newW = Math.max(240, Math.min(700, startW - (ev.clientX - startX))); setModal((p) => p ? { ...p, ptDetailW: newW } : p); };
                        const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                        window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                      }} style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 5, cursor: "col-resize", zIndex: 3 }}>
                        <div style={{ position: "absolute", left: 2, top: "50%", transform: "translateY(-50%)", width: 3, height: 40, borderRadius: 2, background: th.textMuted + "44", transition: "background 0.15s" }}
                          onMouseEnter={(e) => e.currentTarget.style.background = th.accent}
                          onMouseLeave={(e) => e.currentTarget.style.background = (th.textMuted || "#888") + "44"} />
                      </div>
                    );
                    const selNode = selectedKey ? byKeyMap.get(selectedKey) : null;
                    if (!selNode) return (
                      <div style={{ width: detailW, position: "relative", borderLeft: `1px solid ${th.border}44`, background: `${th.modalBg}cc`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", flexShrink: 0, display: "flex", flexDirection: "column" }}>
                        {detailResizeHandle}
                        <div style={{ padding: "10px 16px 8px", borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}88`, fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, fontFamily: "'SF Mono', Menlo, monospace" }}>Event Details</div>
                        <div style={{ padding: 40, textAlign: "center", color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace", fontSize: 12 }}>Select a process node to view details</div>
                      </div>
                    );
                    const parentNode = byKeyMap.get(selNode.parentKey);
                    const selSusInfo = getSusInfo(selNode, parentNode);
                    const selSus = selSusInfo.level;
                    const selSusColor = SUS_COLORS[selSus];
                    const children = (childMap.get(selectedKey) || []).map((k) => byKeyMap.get(k)).filter(Boolean);
                    const elevMap = { "%%1936": "Full (elevated)", "%%1937": "Limited (not elevated)", "%%1938": "Default" };
                    const elevLabel = elevMap[selNode.elevation] || selNode.elevation || "";
                    const integrityLabel = _integrityShort(selNode.integrity);
                    const intCol = INT_COLOR[integrityLabel];
                    const copyDetails = () => {
                      const lines = [
                        `Process: ${selNode.processName}`, `PID: ${selNode.pid}`, `PPID: ${selNode.ppid}`,
                        selNode.user ? `User: ${selNode.user}` : null, selNode.ts ? `Timestamp: ${selNode.ts.replace("T", " ").substring(0, 19)}` : null,
                        selNode.image ? `Image: ${selNode.image}` : null, selNode.cmdLine ? `Command Line: ${selNode.cmdLine}` : null,
                        selNode.parentImage ? `Parent Image: ${selNode.parentImage}` : null,
                        parentNode ? `Parent: ${parentNode.processName} (PID ${parentNode.pid})` : null,
                        elevLabel ? `Elevation: ${elevLabel}` : null, integrityLabel ? `Integrity: ${integrityLabel}` : null,
                        selSus > 0 ? `Suspicious: ${selSusInfo.reason}` : null,
                        children.length > 0 ? `Children (${children.length}): ${children.map((c) => `${c.processName} (${c.pid})`).join(", ")}` : null,
                      ].filter(Boolean);
                      navigator.clipboard.writeText(lines.join("\n"));
                    };
                    const gLbl = { fontFamily: "'SF Mono', Menlo, monospace", fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em", paddingTop: 2 };
                    const gVal = { fontFamily: "'SF Mono', Menlo, monospace", fontSize: 11.5, color: th.text, wordBreak: "break-all", lineHeight: 1.5 };
                    const fields = [
                      ["Timestamp", selNode.ts ? selNode.ts.replace("T", " ").substring(0, 19) : ""],
                      ["Process", selNode.processName],
                      ["Full Path", selNode.image],
                      ["PID", selNode.pid],
                      ["PPID", selNode.ppid],
                      ["Parent", parentNode ? parentNode.processName : ""],
                      ["Parent Path", selNode.parentImage],
                      ["User", selNode.user],
                      ["Integrity", integrityLabel],
                      ["Elevation", elevLabel],
                      ["Command Line", selNode.cmdLine],
                      ["Provider", _providerShort(selNode.provider)],
                      ["Event ID", selNode.eventId],
                    ].filter(([, v]) => v);
                    return (
                      <div style={{ width: detailW, position: "relative", borderLeft: `1px solid ${th.border}44`, background: `${th.modalBg}cc`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", flexShrink: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                        {detailResizeHandle}
                        {/* EVENT DETAILS header bar */}
                        <div style={{ padding: "10px 16px 8px", borderBottom: `1px solid ${th.border}44`, background: `${th.headerBg}aa`, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, fontFamily: "'SF Mono', Menlo, monospace", flexShrink: 0 }}>Event Details</div>
                        {/* Process header + badges */}
                        <div style={{ padding: "12px 16px 8px", borderBottom: `1px solid ${th.border}33`, flexShrink: 0 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                            {ptIcon(selNode.processName)}
                            <span style={{ fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 700, fontSize: 15, color: selSusColor || th.text }}>{selNode.processName}</span>
                            <span style={{ fontFamily: "'SF Mono', Menlo, monospace", fontSize: 11, color: th.textMuted, marginLeft: 4 }}>PID {selNode.pid}</span>
                          </div>
                          {selSusInfo.reason && <div style={{ marginBottom: 6 }}><span style={{ display: "inline-flex", alignItems: "center", gap: 4, background: `${selSusColor}22`, color: selSusColor, padding: "2px 8px", borderRadius: 3, fontSize: 10, fontFamily: "'SF Mono', Menlo, monospace", fontWeight: 600, border: `1px solid ${selSusColor}44`, letterSpacing: "0.02em" }}>{"\u26A0"} {selSusInfo.reason}</span></div>}
                          <button onClick={copyDetails} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 9, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}66`, fontFamily: "'SF Mono', Menlo, monospace" }}>Copy Details</button>
                        </div>
                        {/* Grid fields — matching prototype */}
                        <div style={{ overflow: "auto", flex: 1, padding: 16 }}>
                          <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                            {fields.map(([label, value]) => (
                              <div key={label} style={{ display: "grid", gridTemplateColumns: "110px 1fr", padding: "6px 0", borderBottom: `1px solid ${th.border}22` }}>
                                <span style={gLbl}>{label}</span>
                                <span style={{ ...gVal, color: label === "Command Line" ? (th.danger || "#ff7b72") : label === "Parent" ? (th.accent) : label === "Integrity" ? (intCol || th.text) : th.text, background: label === "Command Line" ? `${th.accent}08` : "transparent", padding: label === "Command Line" ? "4px 6px" : "0", borderRadius: label === "Command Line" ? 3 : 0, cursor: label === "Parent" && parentNode ? "pointer" : "default" }}
                                  onClick={label === "Parent" && parentNode ? () => {
                                    const en = { ...(modal.expandedNodes || {}) };
                                    let cur = parentNode.parentKey;
                                    while (cur && byKeyMap.has(cur)) { en[cur] = true; cur = byKeyMap.get(cur).parentKey; }
                                    setModal((p) => p ? { ...p, selectedKey: parentNode.key, expandedNodes: en } : p);
                                  } : undefined}>{value || "\u2014"}</span>
                              </div>
                            ))}
                          </div>
                          {/* Children chips */}
                          {children.length > 0 && <div style={{ marginTop: 12 }}>
                            <div style={{ ...gLbl, marginBottom: 6 }}>Children ({children.length})</div>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                              {children.slice(0, 20).map((c) => {
                                const cSusInfo = getSusInfo(c, selNode);
                                const cColor = SUS_COLORS[cSusInfo.level];
                                return <span key={c.key} onClick={() => { const en = { ...(modal.expandedNodes || {}), [selectedKey]: true }; setModal((p) => p ? { ...p, selectedKey: c.key, expandedNodes: en } : p); }}
                                  style={{ padding: "2px 8px", borderRadius: 4, background: (cColor || th.accent) + "14", color: cColor || th.textDim, fontSize: 10, cursor: "pointer", border: `1px solid ${(cColor || th.border)}33`, fontFamily: "'SF Mono', Menlo, monospace" }}>{c.processName} ({c.pid})</span>;
                              })}
                              {children.length > 20 && <span style={{ fontSize: 9, color: th.textDim }}>+{children.length - 20} more</span>}
                            </div>
                          </div>}
                        </div>
                      </div>
                    );
                  })()}
                  </div>{/* End flex row: tree + detail panel */}

                  {/* Footer */}
                  {(() => {
                    const susCountFooter = flatNodes.filter(n => (_ptDetMap.get(n.key) || { level: 0 }).level > 0).length;
                    let treeDepth = 0;
                    for (const n of flatNodes) if ((n.depth || 0) > treeDepth) treeDepth = n.depth;
                    const fProviders = [...new Set((data?.processes || []).map(p => _providerShort(p.provider)).filter(Boolean))].join(", ");
                    const fEids = [...new Set((data?.processes || []).map(p => p.eventId).filter(Boolean))].sort().join(", ");
                    return (
                  <div style={{ padding: "8px 20px", borderTop: `1px solid ${th.border}44`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, fontSize: 10, color: th.textDim, background: `${th.headerBg}cc`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", fontFamily: "'SF Mono', Menlo, monospace" }}>
                    <span>
                      {flatNodes.length.toLocaleString()} visible · {susCountFooter} suspicious · Tree depth: {treeDepth}
                      {selectedKey && ` · Chain: ${chainKeys.size}`}
                    </span>
                    <span style={{ opacity: 0.7 }}>
                      Data: {fProviders || "Events"} EID {fEids || "—"} {"\u2192"} ProcessEvent {"\u2192"} Tree Index by PID/PPID
                    </span>
                  </div>
                    );
                  })()}
                </div>
              )}
            </div>
          </div>
        );
      })()}

      {/* Lateral Movement Modal */}
      {modal?.type === "lateralMovement" && ct && (() => {
        const { phase, columns: cols, data, excludeLocal, excludeService } = modal;
        const viewTab = modal.viewTab || "graph";
        const selectedNode = modal.selectedNode;
        const selectedEdge = modal.selectedEdge;
        const positions = modal.positions || {};

        const computeForceLayout = (nodes, edges) => {
          if (nodes.length === 0) return {};
          const N = nodes.length;
          const W = 700, H = 450, CX = W / 2, CY = H / 2;
          const pos = {};
          // Smarter initial placement: connected components in clusters
          const adj = new Map();
          for (const e of edges) {
            if (!adj.has(e.source)) adj.set(e.source, []);
            if (!adj.has(e.target)) adj.set(e.target, []);
            adj.get(e.source).push(e.target);
            adj.get(e.target).push(e.source);
          }
          const visited = new Set();
          const components = [];
          for (const n of nodes) {
            if (visited.has(n.id)) continue;
            const comp = [];
            const q = [n.id];
            visited.add(n.id);
            while (q.length) {
              const c = q.shift();
              comp.push(c);
              for (const nb of (adj.get(c) || [])) {
                if (!visited.has(nb)) { visited.add(nb); q.push(nb); }
              }
            }
            components.push(comp);
          }
          // Place each component in a grid cell, nodes in a circle within
          const gridCols = Math.ceil(Math.sqrt(components.length));
          const cellW = W / gridCols, cellH = H / Math.ceil(components.length / gridCols);
          components.forEach((comp, ci) => {
            const col = ci % gridCols, row = Math.floor(ci / gridCols);
            const cx = cellW * (col + 0.5), cy = cellH * (row + 0.5);
            const r = Math.min(cellW, cellH) * 0.35;
            comp.forEach((id, i) => {
              const angle = (2 * Math.PI * i) / comp.length;
              pos[id] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle), vx: 0, vy: 0 };
            });
          });
          // Scale iterations and repulsion based on node count
          const ITER = N > 200 ? 40 : N > 100 ? 55 : 80;
          const REP = N > 200 ? 4000 : 8000;
          const ATT = 0.005, IDEAL = N > 200 ? 80 : 120, CENTER = 0.01, DAMP = 0.85, MAX_D = 40;
          // For large graphs, use grid-based repulsion approximation
          const useGrid = N > 100;
          const GRID_SIZE = 80;
          for (let it = 0; it < ITER; it++) {
            const cool = 1 - it / ITER;
            if (useGrid) {
              // Grid-based approximate repulsion O(n * k) instead of O(n²)
              const cells = new Map();
              for (const n of nodes) {
                const p = pos[n.id];
                const gx = Math.floor(p.x / GRID_SIZE), gy = Math.floor(p.y / GRID_SIZE);
                for (let dx = -1; dx <= 1; dx++) for (let dy = -1; dy <= 1; dy++) {
                  const key = `${gx + dx},${gy + dy}`;
                  if (!cells.has(key)) cells.set(key, []);
                }
                const key = `${gx},${gy}`;
                cells.get(key).push(n.id);
              }
              for (const n of nodes) {
                const p = pos[n.id];
                const gx = Math.floor(p.x / GRID_SIZE), gy = Math.floor(p.y / GRID_SIZE);
                for (let dx = -1; dx <= 1; dx++) for (let dy = -1; dy <= 1; dy++) {
                  const key = `${gx + dx},${gy + dy}`;
                  const cell = cells.get(key);
                  if (!cell) continue;
                  for (const oid of cell) {
                    if (oid <= n.id) continue;
                    const b = pos[oid];
                    let ddx = p.x - b.x, ddy = p.y - b.y;
                    const dist = Math.sqrt(ddx * ddx + ddy * ddy) || 1;
                    const f = REP / (dist * dist) * cool;
                    const fx = (ddx / dist) * f, fy = (ddy / dist) * f;
                    p.vx += fx; p.vy += fy; b.vx -= fx; b.vy -= fy;
                  }
                }
              }
            } else {
              for (let i = 0; i < N; i++) {
                for (let j = i + 1; j < N; j++) {
                  const a = pos[nodes[i].id], b = pos[nodes[j].id];
                  let dx = a.x - b.x, dy = a.y - b.y;
                  const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                  const f = REP / (dist * dist) * cool;
                  const fx = (dx / dist) * f, fy = (dy / dist) * f;
                  a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
                }
              }
            }
            for (const edge of edges) {
              const a = pos[edge.source], b = pos[edge.target];
              if (!a || !b) continue;
              const dx = b.x - a.x, dy = b.y - a.y;
              const dist = Math.sqrt(dx * dx + dy * dy) || 1;
              const disp = dist - IDEAL;
              const w = Math.min(3, 1 + Math.log2(edge.count || 1) * 0.3);
              const f = ATT * disp * cool * w;
              const fx = (dx / dist) * f, fy = (dy / dist) * f;
              a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
            }
            for (const n of nodes) {
              const p = pos[n.id];
              p.vx += (CX - p.x) * CENTER; p.vy += (CY - p.y) * CENTER;
              p.vx *= DAMP; p.vy *= DAMP;
              const spd = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
              const md = MAX_D * cool;
              if (spd > md) { p.vx = (p.vx / spd) * md; p.vy = (p.vy / spd) * md; }
              p.x += p.vx; p.y += p.vy;
              p.x = Math.max(40, Math.min(W - 40, p.x));
              p.y = Math.max(40, Math.min(H - 40, p.y));
            }
          }
          const result = {};
          for (const n of nodes) result[n.id] = { x: pos[n.id].x, y: pos[n.id].y };
          return result;
        };

        const LM_RULES = [
          { cat: "RDP Session", name: "Network Authentication", sev: "high", eids: ["1149"], hint: "RemoteConnectionManager" },
          { cat: "RDP Session", name: "Session Logon", sev: "medium", eids: ["21"], hint: "LocalSessionManager" },
          { cat: "RDP Session", name: "Shell Start Notification", sev: "low", eids: ["22"], hint: "LocalSessionManager" },
          { cat: "RDP Session", name: "Session Logoff", sev: "low", eids: ["23"], hint: "LocalSessionManager" },
          { cat: "RDP Session", name: "Session Disconnected", sev: "low", eids: ["24"], hint: "LocalSessionManager" },
          { cat: "RDP Session", name: "Session Reconnected", sev: "medium", eids: ["25"], hint: "LocalSessionManager" },
          { cat: "RDP Session", name: "Disconnect by Other / Reason", sev: "low", eids: ["39", "40"], hint: "LocalSessionManager" },
          { cat: "Security Logon", name: "Successful Logon", sev: "high", eids: ["4624"], hint: "Types 2,3,7,8,9,10,11,12" },
          { cat: "Security Logon", name: "Failed Logon", sev: "high", eids: ["4625"], hint: "All logon types" },
          { cat: "Security Logon", name: "Explicit Credentials (RunAs)", sev: "high", eids: ["4648"], hint: "Alternate credential usage" },
          { cat: "Privileges", name: "Admin Privileges Assigned", sev: "high", eids: ["4672"], hint: "Special privileges at logon" },
          { cat: "Session Lifecycle", name: "Session Reconnect / Disconnect", sev: "medium", eids: ["4778", "4779"], hint: "Window Station events" },
          { cat: "Session Lifecycle", name: "Account Logoff", sev: "low", eids: ["4634", "4647"], hint: "Logoff / user-initiated logoff" },
        ];
        const LM_SEV_COLORS = { critical: "#f85149", high: "#f0883e", medium: "#d29922", low: "#8b949e" };
        const lmDisabledSet = modal.lmDisabledRules || new Set();
        const lmActiveCount = LM_RULES.length - [...lmDisabledSet].filter((k) => k.startsWith("lm-")).length;
        const lmCustomCount = (modal.lmCustomRules || []).length;
        const toggleLmRule = (key) => setModal((p) => { const s = new Set(p.lmDisabledRules || []); s.has(key) ? s.delete(key) : s.add(key); return { ...p, lmDisabledRules: s }; });
        const deleteLmCustomRule = (idx) => setModal((p) => ({ ...p, lmCustomRules: (p.lmCustomRules || []).filter((_, i) => i !== idx) }));
        const addLmCustomRule = () => {
          const nr = modal.lmNewRule || {};
          if (!nr.name && !nr.eventIds) return;
          setModal((p) => ({ ...p, lmCustomRules: [...(p.lmCustomRules || []), { ...nr }], lmAddingRule: false, lmNewRule: {} }));
        };

        const handleAnalyze = async () => {
          const t0 = Date.now();
          const pInt = setInterval(() => {
            setModal((p) => {
              if (!p || p.type !== "lateralMovement" || p.phase !== "loading") { clearInterval(pInt); return p; }
              const el = (Date.now() - t0) / 1000;
              const prog = Math.min(92, 90 * (1 - Math.exp(-el / 8)));
              const pi = prog < 10 ? 0 : prog < 35 ? 1 : prog < 60 ? 2 : prog < 80 ? 3 : 4;
              return { ...p, lmProgress: prog, lmPhaseIdx: pi };
            });
          }, 150);
          setModal((p) => ({ ...p, phase: "loading", loading: true, error: null, lmProgress: 0, lmPhaseIdx: 0, _cancelled: false }));
          try {
            const af = activeFilters(ct);
            // Compute event IDs from enabled rules + custom rules
            const enabledEids = new Set();
            LM_RULES.forEach((r, i) => { if (!lmDisabledSet.has(`lm-${i}`)) r.eids.forEach((id) => enabledEids.add(id)); });
            (modal.lmCustomRules || []).forEach((cr) => { (cr.eventIds || "").split(",").map((s) => s.trim()).filter(Boolean).forEach((id) => enabledEids.add(id)); });
            const eids = [...enabledEids];
            const result = await tle.getLateralMovement(ct.id, {
              sourceCol: cols.source, targetCol: cols.target, userCol: cols.user,
              logonTypeCol: cols.logonType, eventIdCol: cols.eventId, tsCol: cols.ts, domainCol: cols.domain,
              eventIds: eids, excludeLocalLogons: modal.excludeLocal, excludeServiceAccounts: modal.excludeService,
              searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
              columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
              bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
            });
            clearInterval(pInt);
            if (result.error) {
              setModal((p) => p?.type === "lateralMovement" && !p._cancelled ? { ...p, phase: "config", loading: false, error: result.error, lmProgress: 0 } : p);
            } else {
              setModal((p) => p?.type === "lateralMovement" && !p._cancelled ? { ...p, lmProgress: 100, lmPhaseIdx: 5 } : p);
              await new Promise((r) => setTimeout(r, 300));
              const layoutNodes = result.nodes.length > 500 ? result.nodes.sort((a, b) => b.eventCount - a.eventCount).slice(0, 500) : result.nodes;
              const layoutIds = new Set(layoutNodes.map((n) => n.id));
              const layoutEdges = result.edges.filter((e) => layoutIds.has(e.source) && layoutIds.has(e.target));
              const pos = computeForceLayout(layoutNodes, layoutEdges);
              setModal((p) => p?.type === "lateralMovement" && !p._cancelled ? { ...p, phase: "results", loading: false, data: result, positions: pos, selectedNode: null, selectedEdge: null, viewTab: "graph", truncatedGraph: result.nodes.length > 500 } : p);
            }
          } catch (e) {
            clearInterval(pInt);
            setModal((p) => p?.type === "lateralMovement" && !p._cancelled ? { ...p, phase: "config", loading: false, error: e.message } : p);
          }
        };

        const logonColor = (types) => {
          const t = new Set(types.map(String));
          if (t.has("10") || t.has("12")) return "#58a6ff";  // RDP / Cached RDP
          if (t.has("8")) return "#f85149";                    // Network Cleartext (dangerous!)
          if (t.has("3")) return "#3fb950";                    // Network
          if (t.has("2")) return "#d29922";                    // Interactive
          if (t.has("7") || t.has("13")) return "#a371f7";    // Unlock / Cached Unlock
          if (t.has("9")) return "#f0883e";                    // RunAs
          if (t.has("4")) return "#d29922";                    // Batch
          if (t.has("5")) return "#8b949e";                    // Service
          if (t.has("11")) return "#d2a8ff";                   // Cached Credentials
          return th.textDim || "#888";
        };
        const edgeWidth = (count) => Math.max(1, Math.min(6, 1 + Math.log2(count)));
        const nodeRadius = (eventCount) => Math.max(6, Math.min(20, 6 + Math.log2(eventCount + 1) * 2));
        // Suspicious hostname patterns (VPS/random machine names seen in 4/11 DFIR reports)
        const SUS_HOSTNAME = /^(VPS|DESKTOP-[A-Z0-9]{7}$|WIN-[A-Z0-9]{8,}$|WINVM)/i;
        const isSusHost = (name) => SUS_HOSTNAME.test(name);
        const nodeColor = (node) => {
          if (selectedNode === node.id) return th.accent;
          if (node.isOutlier) return th.danger || "#f85149";
          if (isSusHost(node.id)) return "#f0883e";
          if (node.isBoth) return "#a371f7";
          if (node.isSource && !node.isTarget) return "#3fb950";
          return "#58a6ff";
        };
        const isEdgeHL = (e) => {
          if (selectedEdge && e.source === selectedEdge.source && e.target === selectedEdge.target) return true;
          if (selectedNode && (e.source === selectedNode || e.target === selectedNode)) return true;
          return false;
        };

        const lmW = modal.lmW || Math.round(window.innerWidth * 0.92), lmH = modal.lmH || Math.round(window.innerHeight * 0.88);
        const lmX = modal.lmX ?? Math.round((window.innerWidth - lmW) / 2);
        const lmY = modal.lmY ?? Math.round((window.innerHeight - lmH) / 2);

        const startLmDrag = (e) => {
          e.preventDefault();
          const sx = e.clientX - lmX, sy = e.clientY - lmY;
          document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
          const onMove = (ev) => setModal((p) => p ? { ...p, lmX: Math.max(0, Math.min(window.innerWidth - 100, ev.clientX - sx)), lmY: Math.max(0, Math.min(window.innerHeight - 40, ev.clientY - sy)) } : p);
          const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const startLmResize = (e, edge) => {
          e.preventDefault(); e.stopPropagation();
          const sx = e.clientX, sy = e.clientY, sw = lmW, sh = lmH, sleft = lmX, stop = lmY;
          document.body.style.userSelect = "none";
          const onMove = (ev) => {
            const dx = ev.clientX - sx, dy = ev.clientY - sy;
            setModal((p) => {
              if (!p) return p;
              let nw = sw, nh = sh, nx = sleft, ny = stop;
              if (edge.includes("r")) nw = Math.max(600, sw + dx);
              if (edge.includes("b")) nh = Math.max(400, sh + dy);
              if (edge.includes("l")) { nw = Math.max(600, sw - dx); nx = sleft + sw - nw; }
              if (edge.includes("t")) { nh = Math.max(400, sh - dy); ny = stop + sh - nh; }
              return { ...p, lmW: nw, lmH: nh, lmX: nx, lmY: ny };
            });
          };
          const onUp = () => { document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const lmEdge = (cursor, pos) => ({ position: "absolute", ...pos, zIndex: 2, cursor });

        return (
          <div style={{ position: "fixed", inset: 0, background: th.overlay, zIndex: 100, backdropFilter: "blur(4px)", WebkitAppRegion: "drag" }}>
            <div style={{ WebkitAppRegion: "no-drag", position: "absolute", left: lmX, top: lmY, width: lmW, height: lmH, background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)", overflow: "hidden" }}>
              {/* Resize handles */}
              <div onMouseDown={(e) => startLmResize(e, "t")} style={lmEdge("ns-resize", { top: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startLmResize(e, "b")} style={lmEdge("ns-resize", { bottom: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startLmResize(e, "l")} style={lmEdge("ew-resize", { left: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startLmResize(e, "r")} style={lmEdge("ew-resize", { right: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startLmResize(e, "tl")} style={lmEdge("nwse-resize", { top: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startLmResize(e, "tr")} style={lmEdge("nesw-resize", { top: 0, right: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startLmResize(e, "bl")} style={lmEdge("nesw-resize", { bottom: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startLmResize(e, "br")} style={lmEdge("nwse-resize", { bottom: 0, right: 0, width: 10, height: 10 })} />
              {/* Header — draggable */}
              <div onMouseDown={startLmDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)", cursor: "grab" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <div style={{ width: 32, height: 32, borderRadius: 8, background: `linear-gradient(135deg, ${th.danger || "#f85149"}33, ${th.danger || "#f85149"}11)`, border: `1px solid ${th.danger || "#f85149"}33`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={th.danger || "#f85149"} strokeWidth="1.5" strokeLinecap="round"><circle cx="5" cy="12" r="2.5" fill={`${th.danger || "#f85149"}33`}/><circle cx="19" cy="5" r="2.5" fill={`${th.danger || "#f85149"}33`}/><circle cx="19" cy="19" r="2.5" fill={`${th.danger || "#f85149"}33`}/><line x1="7.5" y1="11" x2="16.5" y2="6"/><line x1="7.5" y1="13" x2="16.5" y2="18"/></svg>
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.3px" }}>Lateral Movement Tracker</h3>
                    <p style={{ margin: "2px 0 0", color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>Network graph of host-to-host logon events</p>
                  </div>
                </div>
                <button onClick={() => setModal(null)} style={{ width: 24, height: 24, borderRadius: 12, background: th.textMuted + "15", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.15s" }}
                  onMouseEnter={(ev) => { ev.currentTarget.style.background = th.danger + "33"; ev.currentTarget.style.color = th.danger || "#f85149"; }}
                  onMouseLeave={(ev) => { ev.currentTarget.style.background = th.textMuted + "15"; ev.currentTarget.style.color = th.textMuted; }}>{"\u2715"}</button>
              </div>

              {/* Body */}
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>
                {/* Config phase */}
                {phase === "config" && (
                  <div>
                    {modal.error && <div style={{ padding: "8px 12px", background: (th.danger || "#f85149") + "15", border: `1px solid ${th.danger || "#f85149"}33`, borderRadius: 6, color: th.danger || "#f85149", fontSize: 11, marginBottom: 12 }}>{modal.error}</div>}
                    <div style={ms.fg}>
                      <label style={ms.lb}>Column Mapping</label>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                        {[
                          ["source", "Source Host (IpAddress)"],
                          ["target", "Target Host (Computer)"],
                          ["user", "User (TargetUserName)"],
                          ["logonType", "Logon Type"],
                          ["eventId", "Event ID"],
                          ["ts", "Timestamp"],
                        ].map(([key, label]) => (
                          <div key={key}>
                            <label style={{ ...ms.lb, fontSize: 9 }}>{label}</label>
                            <select value={cols[key] || ""} onChange={(e) => setModal((p) => ({ ...p, columns: { ...p.columns, [key]: e.target.value || null } }))} style={ms.sl}>
                              <option value="">-- auto --</option>
                              {ct.headers.map((h) => <option key={h} value={h}>{h}</option>)}
                            </select>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div style={{ display: "flex", gap: 16, marginBottom: 10 }}>
                      <label style={{ fontSize: 11, color: th.textDim, cursor: "pointer", display: "flex", alignItems: "center", gap: 4, fontFamily: "-apple-system, sans-serif" }}>
                        <input type="checkbox" checked={excludeLocal} onChange={() => setModal((p) => ({ ...p, excludeLocal: !p.excludeLocal }))} /> Exclude local logons
                      </label>
                      <label style={{ fontSize: 11, color: th.textDim, cursor: "pointer", display: "flex", alignItems: "center", gap: 4, fontFamily: "-apple-system, sans-serif" }}>
                        <input type="checkbox" checked={excludeService} onChange={() => setModal((p) => ({ ...p, excludeService: !p.excludeService }))} /> Exclude service accounts
                      </label>
                    </div>

                    {/* Info box */}
                    <div style={{ padding: "12px 14px", background: `${th.accent}08`, borderRadius: 10, border: `1px solid ${th.accent}15`, marginBottom: 12 }}>
                      <div style={{ fontSize: 11, color: th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>
                        <b style={{ color: th.text }}>Lateral Movement mode</b> tracks 16 event IDs across Security (4624/4625/4634/4647/4648/4672/4778/4779) and TerminalServices (1149, 21-25, 39, 40) channels. Correlates RDP session lifecycles into connected chains (1149{"\u2192"}4624{"\u2192"}21{"\u2192"}22). Flags cleartext logons (Type 8), admin privilege assignments (4672), and explicit credential usage (4648). Builds network graph of host-to-host connections and detects multi-hop lateral movement chains.
                      </div>
                    </div>

                    {/* Customize Rules Section */}
                    <div style={{ marginTop: 4 }}>
                      <button onClick={() => setModal((p) => ({ ...p, showLmRules: !p.showLmRules }))}
                        style={{ width: "100%", padding: "10px 14px", background: `${th.accent}08`, border: `1px solid ${th.border}33`, borderRadius: 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "space-between", transition: "all 0.15s" }}>
                        <span style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                          Customize Rules
                        </span>
                        <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
                          <span>{lmActiveCount}/{LM_RULES.length} rules{lmCustomCount > 0 ? `, ${lmCustomCount} custom` : ""}</span>
                          <span style={{ transform: modal.showLmRules ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.2s", fontSize: 12 }}>{"\u25BE"}</span>
                        </span>
                      </button>

                      {modal.showLmRules && (
                        <div style={{ padding: "10px 14px", borderLeft: `1px solid ${th.border}33`, borderRight: `1px solid ${th.border}33`, borderBottom: `1px solid ${th.border}33`, borderRadius: "0 0 10px 10px", background: `${th.panelBg}55` }}>
                          {/* Built-in rules */}
                          <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>
                            Detection Rules ({lmActiveCount}/{LM_RULES.length})
                          </div>
                          {LM_RULES.map((r, i) => {
                            const key = `lm-${i}`;
                            const off = lmDisabledSet.has(key);
                            return (
                              <label key={key} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", cursor: "pointer", opacity: off ? 0.45 : 1, transition: "opacity 0.15s" }}>
                                <input type="checkbox" checked={!off} onChange={() => toggleLmRule(key)} style={{ accentColor: th.accent, margin: 0, flexShrink: 0 }} />
                                <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: LM_SEV_COLORS[r.sev] + "22", color: LM_SEV_COLORS[r.sev], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 42, textAlign: "center", textTransform: "uppercase" }}>{r.sev}</span>
                                <span style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{r.cat} {"\u2014"} {r.name}</span>
                                <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>EID {r.eids.join(",")}</span>
                              </label>
                            );
                          })}

                          {/* Custom rules */}
                          {(modal.lmCustomRules || []).length > 0 && (
                            <div style={{ marginTop: 10 }}>
                              <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Custom Rules</div>
                              {(modal.lmCustomRules || []).map((cr, i) => (
                                <div key={`custom-${i}`} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0" }}>
                                  <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: LM_SEV_COLORS[cr.severity || "medium"] + "22", color: LM_SEV_COLORS[cr.severity || "medium"], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 42, textAlign: "center", textTransform: "uppercase" }}>{cr.severity || "med"}</span>
                                  <span style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{cr.category || "Custom"} {"\u2014"} {cr.name || "Custom Rule"}</span>
                                  <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>EID {cr.eventIds || ""}</span>
                                  <button onClick={() => deleteLmCustomRule(i)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "0 4px", lineHeight: 1 }} onMouseEnter={(e) => e.currentTarget.style.color = th.danger || "#f85149"} onMouseLeave={(e) => e.currentTarget.style.color = th.textMuted}>{"\u00D7"}</button>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Add custom rule */}
                          {!modal.lmAddingRule ? (
                            <button onClick={() => setModal((p) => ({ ...p, lmAddingRule: true, lmNewRule: {} }))}
                              style={{ ...ms.bsm, marginTop: 8, display: "flex", alignItems: "center", gap: 4 }}>
                              <span style={{ fontSize: 13, lineHeight: 1 }}>+</span> Add Custom Rule
                            </button>
                          ) : (
                            <div style={{ marginTop: 8, padding: "10px 12px", background: `${th.accent}08`, border: `1px solid ${th.accent}22`, borderRadius: 8 }}>
                              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
                                <input value={(modal.lmNewRule || {}).category || ""} onChange={(e) => setModal((p) => ({ ...p, lmNewRule: { ...p.lmNewRule, category: e.target.value } }))} placeholder="Category" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                <input value={(modal.lmNewRule || {}).name || ""} onChange={(e) => setModal((p) => ({ ...p, lmNewRule: { ...p.lmNewRule, name: e.target.value } }))} placeholder="Rule Name" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                <input value={(modal.lmNewRule || {}).eventIds || ""} onChange={(e) => setModal((p) => ({ ...p, lmNewRule: { ...p.lmNewRule, eventIds: e.target.value } }))} placeholder="Event IDs (e.g. 7045,4697)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                <select value={(modal.lmNewRule || {}).severity || "medium"} onChange={(e) => setModal((p) => ({ ...p, lmNewRule: { ...p.lmNewRule, severity: e.target.value } }))}
                                  style={{ ...ms.sl, fontSize: 11, padding: "4px 8px" }}>
                                  <option value="critical">Critical</option>
                                  <option value="high">High</option>
                                  <option value="medium">Medium</option>
                                  <option value="low">Low</option>
                                </select>
                                <input value={(modal.lmNewRule || {}).payloadFilter || ""} onChange={(e) => setModal((p) => ({ ...p, lmNewRule: { ...p.lmNewRule, payloadFilter: e.target.value } }))} placeholder="Payload regex filter (optional)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px", gridColumn: "1 / -1" }} />
                              </div>
                              <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginTop: 8 }}>
                                <button onClick={() => setModal((p) => ({ ...p, lmAddingRule: false, lmNewRule: {} }))} style={ms.bsm}>Cancel</button>
                                <button onClick={addLmCustomRule} style={{ ...ms.bsm, background: th.primaryBtn, color: "#fff", border: "none" }}>Add Rule</button>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Loading phase */}
                {phase === "loading" && (() => {
                  const prog = modal.lmProgress || 0;
                  const pi = modal.lmPhaseIdx || 0;
                  const plabels = ["Querying database...", "Processing logon events...", "Building host connections...", "Detecting lateral chains...", "Computing graph layout...", "Complete"];
                  return (
                    <div style={{ padding: "50px 40px 40px", textAlign: "center" }}>
                      <style>{`@keyframes lmPulse{0%,100%{opacity:.35}50%{opacity:1}}`}</style>
                      <div style={{ marginBottom: 22 }}>
                        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" strokeWidth="1.5" strokeLinecap="round">
                          <circle cx="5" cy="12" r="2.5" fill={th.accent+"33"} stroke={th.accent} style={{ animation: "lmPulse 1.5s ease-in-out infinite" }} />
                          <circle cx="19" cy="5" r="2.5" fill={(th.danger||"#f85149")+"33"} stroke={th.danger||"#f85149"} style={{ animation: "lmPulse 1.5s ease-in-out infinite .3s" }} />
                          <circle cx="19" cy="19" r="2.5" fill={(th.danger||"#f85149")+"33"} stroke={th.danger||"#f85149"} style={{ animation: "lmPulse 1.5s ease-in-out infinite .6s" }} />
                          <line x1="7.5" y1="11" x2="16.5" y2="6" stroke={th.accent} strokeDasharray="3 3" />
                          <line x1="7.5" y1="13" x2="16.5" y2="18" stroke={th.accent} strokeDasharray="3 3" />
                        </svg>
                      </div>
                      <div style={{ color: th.text, fontSize: 13, fontWeight: 500, marginBottom: 6, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.2px" }}>{plabels[pi]}</div>
                      <div style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif", marginBottom: 24 }}>This may take a moment for large datasets</div>
                      <div style={{ position: "relative", height: 4, background: th.border + "22", borderRadius: 2, overflow: "hidden", maxWidth: 360, margin: "0 auto 12px" }}>
                        <div style={{ position: "absolute", left: 0, top: 0, height: "100%", width: `${prog}%`, background: `linear-gradient(90deg, ${th.accent}, ${th.danger || "#f85149"})`, borderRadius: 2, transition: "width 0.25s ease-out", boxShadow: `0 0 12px ${th.accent}44` }} />
                      </div>
                      <div style={{ color: th.textDim, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>{Math.round(prog)}%</div>
                    </div>
                  );
                })()}

                {/* Results phase */}
                {phase === "results" && data && (
                  <div>
                    {/* Stats cards — glass morphism */}
                    <div style={{ display: "flex", gap: 6, marginBottom: 14 }}>
                      {[
                        { val: data.stats.uniqueHosts, label: "unique hosts", color: th.accent, icon: "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" },
                        { val: data.stats.uniqueConnections, label: "connections", color: "#58a6ff", icon: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3" },
                        { val: data.stats.uniqueUsers, label: "users", color: "#d2a8ff", icon: "M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8" },
                        { val: data.stats.rdpSessionCount || 0, label: "rdp sessions", color: "#58a6ff", icon: "M2 3h20v14H2zM8 21h8M12 17v4" },
                        { val: data.stats.longestChain, label: "longest chain", color: "#d29922", icon: "M13 17l5-5-5-5M6 17l5-5-5-5" },
                        { val: data.nodes.filter(n => n.isOutlier).length, label: "outliers", color: th.danger || "#f85149", icon: "M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01" },
                        { val: data.stats.totalEvents?.toLocaleString(), label: "logon events", color: "#3fb950", icon: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8M10 9H8" },
                      ].map((c, i) => {
                        const isOutlierCard = c.label === "outliers" && Number(c.val) > 0;
                        return (
                        <div key={i} onClick={isOutlierCard ? () => {
                          // Switch to graph view and zoom to first outlier
                          const outlierNode = data.nodes.find(n => n.isOutlier);
                          if (outlierNode && positions && positions[outlierNode.id]) {
                            const p = positions[outlierNode.id];
                            setModal((prev) => ({ ...prev, viewTab: "graph", selectedNode: outlierNode.id, selectedEdge: null, viewBox: { x: p.x - 90, y: p.y - 60, w: 180, h: 120 }, lmFlagIdx: 1 }));
                          }
                        } : undefined} style={{ flex: 1, textAlign: "center", padding: "10px 6px 8px", background: `linear-gradient(160deg, ${c.color}08, ${c.color}03)`, borderRadius: 10, border: `1px solid ${c.color}20`, position: "relative", overflow: "hidden", cursor: isOutlierCard ? "pointer" : "default", transition: "border-color 0.15s" }}
                          onMouseEnter={isOutlierCard ? (e) => e.currentTarget.style.borderColor = c.color + "60" : undefined}
                          onMouseLeave={isOutlierCard ? (e) => e.currentTarget.style.borderColor = c.color + "20" : undefined}>
                          <div style={{ position: "absolute", top: -8, right: -8, width: 40, height: 40, borderRadius: 20, background: `radial-gradient(circle, ${c.color}12, transparent)` }} />
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={c.color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.5, marginBottom: 2 }}><path d={c.icon}/></svg>
                          <div style={{ fontSize: 22, fontWeight: 700, color: c.color, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.5px", lineHeight: 1 }}>{c.val}</div>
                          <div style={{ fontSize: 9, color: th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 500 }}>{c.label}{isOutlierCard && " ▸"}</div>
                        </div>
                        );
                      })}
                    </div>

                    {modal.truncatedGraph && <div style={{ padding: "6px 10px", background: th.warning + "15", border: `1px solid ${th.warning}33`, borderRadius: 6, color: th.warning, fontSize: 10, marginBottom: 10, fontFamily: "-apple-system, sans-serif" }}>Graph showing top 500 hosts by activity. {data.nodes.length} total hosts detected.</div>}

                    {/* Tab switcher — macOS segmented control */}
                    <div style={{ display: "inline-flex", background: th.panelBg, borderRadius: 8, padding: 2, marginBottom: 12, border: `1px solid ${th.border}44`, gap: 1 }}>
                      {[
                        { id: "graph", label: "Network Graph", icon: "M22 12h-4l-3 9L9 3l-3 9H2" },
                        { id: "rdp", label: `RDP Sessions (${data.rdpSessions?.length || 0})`, icon: "M2 3h20v14H2zM8 21h8M12 17v4" },
                        { id: "chains", label: `Chains (${data.chains.length})`, icon: "M13 17l5-5-5-5M6 17l5-5-5-5" },
                        { id: "table", label: `Connections (${data.edges.length})`, icon: "M3 3h18v18H3zM3 9h18M3 15h18M9 3v18M15 3v18" },
                      ].map((tab) => (
                        <button key={tab.id} onClick={() => setModal((p) => ({ ...p, viewTab: tab.id, selectedNode: null, selectedEdge: null }))}
                          style={{ padding: "5px 12px", background: viewTab === tab.id ? `linear-gradient(180deg, ${th.accent}ee, ${th.accent})` : "transparent", color: viewTab === tab.id ? "#fff" : th.textDim, border: "none", borderRadius: 6, fontSize: 11, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: viewTab === tab.id ? 600 : 400, transition: "all 0.15s", display: "flex", alignItems: "center", gap: 5, boxShadow: viewTab === tab.id ? `0 1px 4px ${th.accent}44` : "none" }}
                          onMouseEnter={(ev) => { if (viewTab !== tab.id) ev.currentTarget.style.background = th.textMuted + "11"; }}
                          onMouseLeave={(ev) => { if (viewTab !== tab.id) ev.currentTarget.style.background = "transparent"; }}>
                          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d={tab.icon}/></svg>
                          {tab.label}
                        </button>
                      ))}
                    </div>

                    {/* Graph tab */}
                    {viewTab === "graph" && (() => {
                      const W = 700, H = 450;
                      const graphNodes = data.nodes.length > 500 ? data.nodes.sort((a, b) => b.eventCount - a.eventCount).slice(0, 500) : data.nodes;
                      const graphIds = new Set(graphNodes.map((n) => n.id));
                      const graphEdges = data.edges.filter((e) => graphIds.has(e.source) && graphIds.has(e.target));
                      const vb = modal.viewBox || { x: 0, y: 0, w: W, h: H };
                      const isIP = (s) => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s);
                      const isDC = (s) => /DC\d*$/i.test(s) || /domain.controller/i.test(s);
                      const logonLabel = (types) => { const t = types.map(String); if (t.includes("10")) return "RDP"; if (t.includes("12")) return "Cached RDP"; if (t.includes("8")) return "Cleartext"; if (t.includes("3")) return "Net"; if (t.includes("4")) return "Batch"; if (t.includes("5")) return "Service"; if (t.includes("2")) return "Local"; if (t.includes("7")) return "Unlock"; if (t.includes("9")) return "RunAs"; if (t.includes("11")) return "Cached"; if (t.includes("13")) return "Cached Unlock"; return t.join(","); };
                      const tbtn = { padding: "4px 10px", background: `${th.panelBg}cc`, color: th.textDim, border: `1px solid ${th.border}44`, borderRadius: 6, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 4, backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", transition: "all 0.15s", fontWeight: 500 };

                      const svgToWorld = (clientX, clientY, svgEl) => {
                        if (!svgEl) return { x: 0, y: 0 };
                        const rect = svgEl.getBoundingClientRect();
                        const sx = (clientX - rect.left) / rect.width;
                        const sy = (clientY - rect.top) / rect.height;
                        return { x: vb.x + sx * vb.w, y: vb.y + sy * vb.h };
                      };

                      const onWheel = (ev) => {
                        if (selectedNode || selectedEdge) return; // Allow page scroll when node/edge selected
                        ev.preventDefault();
                        const svg = ev.currentTarget;
                        const pt = svgToWorld(ev.clientX, ev.clientY, svg);
                        const factor = ev.deltaY > 0 ? 1.15 : 1 / 1.15;
                        const nw = Math.max(100, Math.min(W * 4, vb.w * factor));
                        const nh = Math.max(65, Math.min(H * 4, vb.h * factor));
                        const nx = pt.x - (pt.x - vb.x) * (nw / vb.w);
                        const ny = pt.y - (pt.y - vb.y) * (nh / vb.h);
                        setModal((p) => ({ ...p, viewBox: { x: nx, y: ny, w: nw, h: nh } }));
                      };

                      const onPanStart = (ev) => {
                        if (ev.button !== 0) return;
                        const svg = ev.currentTarget;
                        const startPt = svgToWorld(ev.clientX, ev.clientY, svg);
                        const startVb = { ...vb };
                        const onMove = (me) => {
                          const cur = svgToWorld(me.clientX, me.clientY, svg);
                          // Use ratio-based delta since viewBox may have changed
                          const rect = svg.getBoundingClientRect();
                          const dx = ((me.clientX - ev.clientX) / rect.width) * startVb.w;
                          const dy = ((me.clientY - ev.clientY) / rect.height) * startVb.h;
                          setModal((p) => ({ ...p, viewBox: { ...startVb, x: startVb.x - dx, y: startVb.y - dy } }));
                        };
                        const onUp = () => { document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
                        document.addEventListener("mousemove", onMove);
                        document.addEventListener("mouseup", onUp);
                      };

                      const onNodeDragStart = (ev, nodeId) => {
                        ev.stopPropagation();
                        if (ev.button !== 0) return;
                        const svg = ev.currentTarget.closest("svg");
                        const startWorld = svgToWorld(ev.clientX, ev.clientY, svg);
                        const startPos = positions[nodeId];
                        if (!startPos) return;
                        let moved = false;
                        const onMove = (me) => {
                          moved = true;
                          const curWorld = svgToWorld(me.clientX, me.clientY, svg);
                          const dx = curWorld.x - startWorld.x, dy = curWorld.y - startWorld.y;
                          setModal((p) => ({ ...p, positions: { ...p.positions, [nodeId]: { x: startPos.x + dx, y: startPos.y + dy } } }));
                        };
                        const onUp = () => {
                          document.removeEventListener("mousemove", onMove);
                          document.removeEventListener("mouseup", onUp);
                          if (!moved) setModal((p) => ({ ...p, selectedNode: p.selectedNode === nodeId ? null : nodeId, selectedEdge: null }));
                        };
                        document.addEventListener("mousemove", onMove);
                        document.addEventListener("mouseup", onUp);
                      };

                      const zoomBy = (factor) => {
                        const cx = vb.x + vb.w / 2, cy = vb.y + vb.h / 2;
                        const nw = Math.max(100, Math.min(W * 4, vb.w * factor));
                        const nh = Math.max(65, Math.min(H * 4, vb.h * factor));
                        setModal((p) => ({ ...p, viewBox: { x: cx - nw / 2, y: cy - nh / 2, w: nw, h: nh } }));
                      };

                      return (
                        <div>
                          {/* Toolbar */}
                          <div style={{ display: "flex", gap: 3, marginBottom: 8, alignItems: "center", padding: "4px 6px", background: `${th.panelBg}88`, borderRadius: 8, border: `1px solid ${th.border}22` }}>
                            <button onClick={() => zoomBy(1 / 1.3)} style={tbtn} title="Zoom In">
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
                            </button>
                            <button onClick={() => zoomBy(1.3)} style={tbtn} title="Zoom Out">
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
                            </button>
                            <button onClick={() => setModal((p) => ({ ...p, viewBox: { x: 0, y: 0, w: W, h: H } }))} style={tbtn} title="Reset View">
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                              Reset
                            </button>
                            <button onClick={() => {
                              const layoutNodes = data.nodes.length > 500 ? data.nodes.sort((a, b) => b.eventCount - a.eventCount).slice(0, 500) : data.nodes;
                              const ids = new Set(layoutNodes.map((n) => n.id));
                              const le = data.edges.filter((e) => ids.has(e.source) && ids.has(e.target));
                              const pos = computeForceLayout(layoutNodes, le);
                              setModal((p) => ({ ...p, positions: pos, viewBox: { x: 0, y: 0, w: W, h: H } }));
                            }} style={tbtn} title="Redraw Layout">
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2"><polyline points="1 4 1 10 7 10"/><polyline points="23 20 23 14 17 14"/><path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"/></svg>
                              Redraw
                            </button>
                            <button onClick={() => {
                              const svgEl = document.querySelector("[data-lm-graph]");
                              if (!svgEl) return;
                              const clone = svgEl.cloneNode(true);
                              clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
                              clone.style.background = th.panelBg;
                              const svgData = new XMLSerializer().serializeToString(clone);
                              const canvas = document.createElement("canvas");
                              const svgBlob = new Blob([svgData], { type: "image/svg+xml;charset=utf-8" });
                              const url = URL.createObjectURL(svgBlob);
                              const img = new Image();
                              img.onload = () => {
                                canvas.width = img.width * 2;
                                canvas.height = img.height * 2;
                                const ctx = canvas.getContext("2d");
                                ctx.scale(2, 2);
                                ctx.fillStyle = th.panelBg;
                                ctx.fillRect(0, 0, img.width, img.height);
                                ctx.drawImage(img, 0, 0);
                                URL.revokeObjectURL(url);
                                canvas.toBlob((blob) => {
                                  const a = document.createElement("a");
                                  a.href = URL.createObjectURL(blob);
                                  a.download = "lateral-movement-graph.png";
                                  a.click();
                                  URL.revokeObjectURL(a.href);
                                }, "image/png");
                              };
                              img.src = url;
                            }} style={tbtn} title="Export as PNG">
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                              Export
                            </button>
                            {(() => {
                              const outliers = graphNodes.filter(n => n.isOutlier);
                              const susHosts = graphNodes.filter(n => isSusHost(n.id) && !n.isOutlier);
                              const flagged = [...outliers, ...susHosts];
                              if (flagged.length === 0) return null;
                              const curIdx = modal.lmFlagIdx || 0;
                              return (
                                <>
                                  <div style={{ width: 1, height: 16, background: th.border + "44", margin: "0 2px" }} />
                                  <button onClick={() => {
                                    const node = flagged[curIdx % flagged.length];
                                    const p = positions[node.id];
                                    if (p) {
                                      const zoomW = 180, zoomH = 120;
                                      setModal((prev) => ({ ...prev, selectedNode: node.id, selectedEdge: null, viewBox: { x: p.x - zoomW / 2, y: p.y - zoomH / 2, w: zoomW, h: zoomH }, lmFlagIdx: (curIdx + 1) % flagged.length }));
                                    }
                                  }} style={{ ...tbtn, background: `${(th.danger || "#f85149")}15`, color: th.danger || "#f85149", border: `1px solid ${(th.danger || "#f85149")}33` }} title={`${outliers.length} outlier(s), ${susHosts.length} suspicious host(s) — click to cycle through`}>
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.danger || "#f85149"} strokeWidth="2"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                                    Find Flagged ({flagged.length})
                                  </button>
                                </>
                              );
                            })()}
                            <div style={{ flex: 1 }} />
                            <span style={{ fontSize: 9, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>{selectedNode || selectedEdge ? "Zoom locked \u00B7 Click background to deselect & unlock" : "Scroll to zoom \u00B7 Drag background to pan \u00B7 Drag nodes to reposition"}</span>
                          </div>

                          <svg data-lm-graph="1" width="100%" height={480} viewBox={`${vb.x} ${vb.y} ${vb.w} ${vb.h}`}
                            style={{ background: th.panelBg, borderRadius: 6, border: `1px solid ${th.border}`, cursor: modal.draggingNode ? "grabbing" : "grab", display: "block", userSelect: "none" }}
                            onWheel={onWheel}
                            onMouseDown={(ev) => { if (ev.target === ev.currentTarget || ev.target.tagName === "rect") { onPanStart(ev); setModal((p) => ({ ...p, selectedNode: null, selectedEdge: null })); } }}>

                            {/* SVG defs — gradients, filters, grid */}
                            <defs>
                              <pattern id="lm-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                                <circle cx="20" cy="20" r="0.6" fill={th.textMuted + "18"} />
                              </pattern>
                              <filter id="lm-glow" x="-50%" y="-50%" width="200%" height="200%">
                                <feGaussianBlur stdDeviation="3" result="blur"/>
                                <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                              </filter>
                              <filter id="lm-shadow" x="-20%" y="-20%" width="140%" height="140%">
                                <feDropShadow dx="0" dy="1" stdDeviation="2" floodOpacity="0.25"/>
                              </filter>
                              <radialGradient id="lm-grad-green" cx="35%" cy="35%"><stop offset="0%" stopColor="#3fb950" stopOpacity="0.35"/><stop offset="100%" stopColor="#3fb950" stopOpacity="0.08"/></radialGradient>
                              <radialGradient id="lm-grad-blue" cx="35%" cy="35%"><stop offset="0%" stopColor="#58a6ff" stopOpacity="0.35"/><stop offset="100%" stopColor="#58a6ff" stopOpacity="0.08"/></radialGradient>
                              <radialGradient id="lm-grad-purple" cx="35%" cy="35%"><stop offset="0%" stopColor="#d2a8ff" stopOpacity="0.35"/><stop offset="100%" stopColor="#d2a8ff" stopOpacity="0.08"/></radialGradient>
                              <radialGradient id="lm-grad-accent" cx="35%" cy="35%"><stop offset="0%" stopColor={th.accent} stopOpacity="0.4"/><stop offset="100%" stopColor={th.accent} stopOpacity="0.1"/></radialGradient>
                              <radialGradient id="lm-grad-red" cx="35%" cy="35%"><stop offset="0%" stopColor={th.danger || "#f85149"} stopOpacity="0.45"/><stop offset="100%" stopColor={th.danger || "#f85149"} stopOpacity="0.12"/></radialGradient>
                            </defs>
                            <rect x={vb.x - 200} y={vb.y - 200} width={vb.w + 400} height={vb.h + 400} fill="url(#lm-grid)" />

                            {/* Edges */}
                            {graphEdges.map((e, i) => {
                              const from = positions[e.source], to = positions[e.target];
                              if (!from || !to) return null;
                              const hl = isEdgeHL(e);
                              const op = selectedNode || selectedEdge ? (hl ? 0.9 : 0.1) : 0.6;
                              const col = e.hasFailures ? (th.danger || "#f85149") : logonColor(e.logonTypes);
                              const dx = to.x - from.x, dy = to.y - from.y;
                              const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                              const toR = nodeRadius((graphNodes.find((n) => n.id === e.target) || {}).eventCount || 1) + 2;
                              const fromR = nodeRadius((graphNodes.find((n) => n.id === e.source) || {}).eventCount || 1) + 2;
                              const ux = dx / dist, uy = dy / dist;
                              const x1 = from.x + ux * fromR, y1 = from.y + uy * fromR;
                              const x2 = to.x - ux * toR, y2 = to.y - uy * toR;
                              const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
                              const ang = Math.atan2(dy, dx) * 180 / Math.PI;
                              const perpX = -uy * 4, perpY = ux * 4;
                              return (
                                <g key={`e-${i}`} style={{ cursor: "pointer" }} opacity={op}>
                                  <line x1={x1} y1={y1} x2={x2} y2={y2} stroke={col} strokeWidth={edgeWidth(e.count)} strokeDasharray={e.hasFailures ? "4,3" : "none"} />
                                  <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="transparent" strokeWidth={12} onClick={(ev) => { ev.stopPropagation(); setModal((p) => ({ ...p, selectedEdge: e, selectedNode: null })); }} />
                                  <polygon points="-5,-4 5,0 -5,4" transform={`translate(${x2},${y2}) rotate(${ang})`} fill={col} />
                                  {/* Edge label */}
                                  <g transform={`translate(${mx + perpX}, ${my + perpY})`}>
                                    <rect x={-14} y={-7} width={28} height={14} rx={7} fill={th.panelBg} fillOpacity={0.9} stroke={col} strokeWidth={0.4} strokeOpacity={0.3} />
                                    <text textAnchor="middle" dy="3.5" fill={col} fontSize={7.5} fontWeight={600} fontFamily="-apple-system,sans-serif" fillOpacity={0.9}>
                                      {e.count > 999 ? Math.round(e.count / 1000) + "k" : e.count}
                                    </text>
                                  </g>
                                </g>
                              );
                            })}

                            {/* Nodes */}
                            {graphNodes.map((n) => {
                              const p = positions[n.id];
                              if (!p) return null;
                              const r = nodeRadius(n.eventCount);
                              const dimmed = selectedNode && selectedNode !== n.id && !graphEdges.some((e) => (e.source === selectedNode && e.target === n.id) || (e.target === selectedNode && e.source === n.id));
                              const op = selectedNode ? (dimmed ? 0.12 : 1) : 1;
                              const col = nodeColor(n);
                              const ip = isIP(n.id);
                              const dc = isDC(n.id);
                              const dangerCol = th.danger || "#f85149";
                              const gradId = col === dangerCol ? "lm-grad-red" : col === "#3fb950" ? "lm-grad-green" : col === "#58a6ff" ? "lm-grad-blue" : col === "#d2a8ff" ? "lm-grad-purple" : "lm-grad-accent";
                              const labelText = n.label.length > 20 ? n.label.slice(0, 18) + "\u2026" : n.label;
                              const labelW = labelText.length * 5.5 + 12;
                              const isSel = selectedNode === n.id;
                              return (
                                <g key={`n-${n.id}`} opacity={op} style={{ cursor: "grab" }}
                                  onMouseDown={(ev) => onNodeDragStart(ev, n.id)} filter={isSel ? "url(#lm-glow)" : undefined}>
                                  {/* Ambient glow behind node */}
                                  <circle cx={p.x} cy={p.y} r={r + 4} fill={col} fillOpacity={isSel ? 0.12 : 0.04} />
                                  {/* Node shape */}
                                  {ip ? (
                                    <g>
                                      <circle cx={p.x} cy={p.y} r={r} fill={`url(#${gradId})`} stroke={col} strokeWidth={1.2} strokeDasharray="4,2.5" strokeOpacity={0.7} />
                                      <circle cx={p.x - r * 0.25} cy={p.y - r * 0.25} r={r * 0.15} fill={col} fillOpacity={0.15} />
                                    </g>
                                  ) : dc ? (
                                    <g>
                                      <rect x={p.x - r} y={p.y - r} width={r * 2} height={r * 2} rx={4} fill={`url(#${gradId})`} stroke={col} strokeWidth={1.5} />
                                      <line x1={p.x - r * 0.6} y1={p.y - r * 0.35} x2={p.x + r * 0.6} y2={p.y - r * 0.35} stroke={col} strokeWidth={0.8} strokeOpacity={0.3} />
                                      <line x1={p.x - r * 0.6} y1={p.y} x2={p.x + r * 0.6} y2={p.y} stroke={col} strokeWidth={0.8} strokeOpacity={0.3} />
                                      <line x1={p.x - r * 0.6} y1={p.y + r * 0.35} x2={p.x + r * 0.6} y2={p.y + r * 0.35} stroke={col} strokeWidth={0.8} strokeOpacity={0.3} />
                                    </g>
                                  ) : (
                                    <g>
                                      <rect x={p.x - r} y={p.y - r * 0.7} width={r * 2} height={r * 1.4} rx={5} fill={`url(#${gradId})`} stroke={col} strokeWidth={1.2} />
                                      {/* Monitor stand */}
                                      <line x1={p.x} y1={p.y + r * 0.7} x2={p.x} y2={p.y + r * 0.95} stroke={col} strokeWidth={0.8} strokeOpacity={0.35} />
                                      <line x1={p.x - r * 0.25} y1={p.y + r * 0.95} x2={p.x + r * 0.25} y2={p.y + r * 0.95} stroke={col} strokeWidth={0.8} strokeOpacity={0.35} />
                                      {/* Screen shine */}
                                      <rect x={p.x - r * 0.7} y={p.y - r * 0.5} width={r * 0.4} height={r * 0.2} rx={1} fill={col} fillOpacity={0.08} />
                                    </g>
                                  )}
                                  {/* Selection ring */}
                                  {isSel && <circle cx={p.x} cy={p.y} r={r + 6} fill="none" stroke={th.accent} strokeWidth={1.5} strokeOpacity={0.5} strokeDasharray="4,3" />}
                                  {/* Outlier pulse ring */}
                                  {n.isOutlier && <circle cx={p.x} cy={p.y} r={r + 4} fill="none" stroke={dangerCol} strokeWidth={1.2} strokeOpacity={0.6} strokeDasharray="3,2" style={{ animation: "tle-pulse 2s ease-in-out infinite" }}><title>{n.outlierReason}</title></circle>}
                                  {/* Suspicious hostname indicator */}
                                  {isSusHost(n.id) && <g transform={`translate(${p.x + r - 2}, ${p.y - r - 2})`}><polygon points="0,-6 5.2,3 -5.2,3" fill="#f0883e" stroke={th.modalBg} strokeWidth={1} /><text x={0} y={1.5} textAnchor="middle" fill={th.modalBg} fontSize={6} fontWeight={700}>!</text><title>Suspicious hostname pattern — possible threat actor workstation</title></g>}
                                  {/* Inner icon text */}
                                  {ip ? (
                                    <text x={p.x} y={p.y + 1} textAnchor="middle" dominantBaseline="middle" fill={col} fontSize={r * 0.6} fontWeight={600} fontFamily="-apple-system,sans-serif" fillOpacity={0.7}>IP</text>
                                  ) : dc ? (
                                    <text x={p.x} y={p.y + r * 0.7} textAnchor="middle" fill={col} fontSize={r * 0.5} fontWeight={600} fontFamily="-apple-system,sans-serif" fillOpacity={0.7}>DC</text>
                                  ) : null}
                                  {/* Label with glass pill */}
                                  <g transform={`translate(${p.x}, ${p.y + r + 14})`}>
                                    <rect x={-labelW / 2} y={-8} width={labelW} height={15} rx={7} fill={th.panelBg} fillOpacity={0.85} stroke={col} strokeWidth={0.4} strokeOpacity={0.3} />
                                    <text textAnchor="middle" dy="3" fill={th.text} fontSize={8.5} fontWeight={500} fontFamily="-apple-system,sans-serif">{labelText}</text>
                                  </g>
                                </g>
                              );
                            })}

                            {/* Legend — glass panel (draggable, fixed in viewport) */}
                            <g transform={`translate(${vb.x + (modal.legendOffX ?? 10)}, ${vb.y + (modal.legendOffY ?? 10)})`} style={{ cursor: "grab" }}
                              onMouseDown={(ev) => {
                                ev.stopPropagation(); ev.preventDefault();
                                const svg = ev.currentTarget.closest("svg");
                                const rect = svg.getBoundingClientRect();
                                const startX = ev.clientX, startY = ev.clientY;
                                const startOx = modal.legendOffX ?? 10, startOy = modal.legendOffY ?? 10;
                                document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                                const onMove = (me) => {
                                  const dx = ((me.clientX - startX) / rect.width) * vb.w;
                                  const dy = ((me.clientY - startY) / rect.height) * vb.h;
                                  setModal((p) => ({ ...p, legendOffX: startOx + dx, legendOffY: startOy + dy }));
                                };
                                const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
                                document.addEventListener("mousemove", onMove); document.addEventListener("mouseup", onUp);
                              }}>
                              <rect x={-6} y={-6} width={155} height={180} rx={8} fill={th.panelBg} fillOpacity={0.88} stroke={th.border} strokeWidth={0.5} strokeOpacity={0.3} />
                              <text x={0} y={6} fill={th.textMuted} fontSize={7.5} fontWeight={600} fontFamily="-apple-system,sans-serif" letterSpacing="0.08em" textTransform="uppercase">CONNECTIONS</text>
                              {[
                                { color: "#58a6ff", label: "RDP (type 10/12)" },
                                { color: "#3fb950", label: "Network (type 3)" },
                                { color: "#d29922", label: "Interactive (type 2)" },
                                { color: "#f0883e", label: "RunAs (type 9)" },
                                { color: "#8b949e", label: "Service (type 5)" },
                                { color: "#f85149", label: "Cleartext (type 8)" },
                                { color: th.danger || "#f85149", label: "Failed logon", dashed: true },
                              ].map((item, i) => (
                                <g key={i} transform={`translate(4, ${i * 14 + 18})`}>
                                  <line x1={0} y1={0} x2={14} y2={0} stroke={item.color} strokeWidth={2} strokeLinecap="round" strokeDasharray={item.dashed ? "3,2" : "none"} />
                                  <circle cx={14} cy={0} r={1.5} fill={item.color} />
                                  <text x={20} y={3} fill={th.textMuted} fontSize={7} fontFamily="-apple-system,sans-serif">{item.label}</text>
                                </g>
                              ))}
                              <line x1={0} y1={118} x2={140} y2={118} stroke={th.border} strokeWidth={0.3} strokeOpacity={0.5} />
                              <text x={0} y={130} fill={th.textMuted} fontSize={7.5} fontWeight={600} fontFamily="-apple-system,sans-serif" letterSpacing="0.08em">NODES</text>
                              <g transform="translate(4, 140)">
                                <circle cx={4} cy={0} r={3.5} fill="url(#lm-grad-green)" stroke="#3fb950" strokeWidth={0.8} strokeDasharray="2.5,1.5" />
                                <text x={14} y={3} fill={th.textMuted} fontSize={7.5} fontFamily="-apple-system,sans-serif">IP</text>
                              </g>
                              <g transform="translate(38, 140)">
                                <rect x={0} y={-4} width={8} height={8} rx={2} fill="url(#lm-grad-blue)" stroke="#58a6ff" strokeWidth={0.8} />
                                <text x={14} y={3} fill={th.textMuted} fontSize={7.5} fontFamily="-apple-system,sans-serif">DC</text>
                              </g>
                              <g transform="translate(68, 140)">
                                <rect x={0} y={-3} width={9} height={6} rx={2} fill="url(#lm-grad-purple)" stroke="#d2a8ff" strokeWidth={0.8} />
                                <text x={15} y={3} fill={th.textMuted} fontSize={7.5} fontFamily="-apple-system,sans-serif">Host</text>
                              </g>
                              <g transform="translate(4, 155)">
                                <rect x={0} y={-3} width={9} height={6} rx={2} fill="url(#lm-grad-red)" stroke={th.danger || "#f85149"} strokeWidth={0.8} strokeDasharray="2,1.5" />
                                <text x={15} y={3} fill={th.danger || "#f85149"} fontSize={7.5} fontWeight={600} fontFamily="-apple-system,sans-serif">Outlier</text>
                              </g>
                              <g transform="translate(68, 155)">
                                <polygon points="4,-5 8.2,2 -0.2,2" fill="#f0883e" />
                                <text x={14} y={3} fill="#f0883e" fontSize={7.5} fontWeight={500} fontFamily="-apple-system,sans-serif">Sus Host</text>
                              </g>
                            </g>
                          </svg>

                          {/* Node detail panel — glass card */}
                          {selectedNode && (() => {
                            const node = data.nodes.find((n) => n.id === selectedNode);
                            const inbound = data.edges.filter((e) => e.target === selectedNode);
                            const outbound = data.edges.filter((e) => e.source === selectedNode);
                            const nc = nodeColor(node || {});
                            return (
                              <div style={{ marginTop: 10, padding: 14, background: `linear-gradient(135deg, ${nc}08, ${th.panelBg}ee)`, borderRadius: 10, border: `1px solid ${nc}22`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                                  <span style={{ padding: "3px 10px", background: `linear-gradient(135deg, ${nc}33, ${nc}15)`, color: nc, borderRadius: 6, fontSize: 10, fontWeight: 600, fontFamily: "-apple-system, sans-serif", letterSpacing: "0.03em" }}>{isIP(selectedNode) ? "IP Address" : isDC(selectedNode) ? "Domain Controller" : "Workstation"}</span>
                                  <span style={{ fontWeight: 600, fontSize: 13, color: th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.2px" }}>{selectedNode}</span>
                                </div>
                                <div style={{ display: "flex", gap: 12, fontSize: 11, color: th.textDim, marginBottom: 10, fontFamily: "-apple-system, sans-serif", alignItems: "center" }}>
                                  <span style={{ display: "flex", alignItems: "center", gap: 4 }}><span style={{ width: 6, height: 6, borderRadius: 3, background: "#58a6ff", display: "inline-block" }} /> {inbound.length} inbound</span>
                                  <span style={{ display: "flex", alignItems: "center", gap: 4 }}><span style={{ width: 6, height: 6, borderRadius: 3, background: "#3fb950", display: "inline-block" }} /> {outbound.length} outbound</span>
                                  <span style={{ color: th.textMuted }}>{node?.eventCount} events</span>
                                  <button onClick={() => {
                                    const cols = modal.columns || {};
                                    const srcCol = cols.source || cols.workstation;
                                    const tgtCol = cols.target;
                                    if (srcCol || tgtCol) {
                                      const cf = { ...(ct.columnFilters || {}) };
                                      if (srcCol && tgtCol) cf[srcCol] = selectedNode;
                                      else if (tgtCol) cf[tgtCol] = selectedNode;
                                      up("columnFilters", cf);
                                    }
                                    setModal(null);
                                  }} style={{ marginLeft: "auto", padding: "4px 12px", fontSize: 10, background: `linear-gradient(135deg, ${th.accent}33, ${th.accent}18)`, color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 6, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 600, transition: "all 0.15s" }}
                                    onMouseEnter={(ev) => { ev.currentTarget.style.background = th.accent + "44"; ev.currentTarget.style.boxShadow = `0 2px 8px ${th.accent}22`; }}
                                    onMouseLeave={(ev) => { ev.currentTarget.style.background = `linear-gradient(135deg, ${th.accent}33, ${th.accent}18)`; ev.currentTarget.style.boxShadow = "none"; }}>
                                    Filter Grid
                                  </button>
                                </div>
                                <div style={{ maxHeight: 120, overflow: "auto" }}>
                                  {[...inbound.map((e) => ({ ...e, dir: "in" })), ...outbound.map((e) => ({ ...e, dir: "out" }))].map((e, i) => (
                                    <div key={i} style={{ fontSize: 10, padding: "4px 0", color: th.textDim, fontFamily: "monospace", display: "flex", alignItems: "center", gap: 6, borderBottom: `1px solid ${th.border}22` }}>
                                      <span style={{ padding: "1px 4px", background: e.dir === "in" ? "#58a6ff22" : "#3fb95022", color: e.dir === "in" ? "#58a6ff" : "#3fb950", borderRadius: 2, fontSize: 8, fontWeight: 600 }}>{e.dir === "in" ? "IN" : "OUT"}</span>
                                      <span>{e.source}{isSusHost(e.source) && <span title="Suspicious hostname" style={{ fontSize: 7, color: "#f0883e", marginLeft: 2 }}>&#9888;</span>} {"\u2192"} {e.target}{isSusHost(e.target) && <span title="Suspicious hostname" style={{ fontSize: 7, color: "#f0883e", marginLeft: 2 }}>&#9888;</span>}</span>
                                      <span style={{ color: th.accent }}>{e.count}x</span>
                                      <span style={{ color: th.textMuted }}>{e.users.join(", ")}</span>
                                      <span style={{ color: logonColor(e.logonTypes), fontSize: 9 }}>{logonLabel(e.logonTypes)}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            );
                          })()}

                          {/* Edge detail panel — glass card */}
                          {selectedEdge && (() => {
                            const ec = selectedEdge.hasFailures ? (th.danger || "#f85149") : logonColor(selectedEdge.logonTypes);
                            return (
                              <div style={{ marginTop: 10, padding: 14, background: `linear-gradient(135deg, ${ec}06, ${th.panelBg}ee)`, borderRadius: 10, border: `1px solid ${ec}22`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                                  <span style={{ fontWeight: 600, fontSize: 12, color: th.text, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
                                    <span style={{ padding: "2px 8px", background: isSusHost(selectedEdge.source) ? "#f0883e18" : "#3fb95018", color: isSusHost(selectedEdge.source) ? "#f0883e" : "#3fb950", borderRadius: 5, fontSize: 10 }}>{selectedEdge.source}{isSusHost(selectedEdge.source) && " \u26a0"}</span>
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={ec} strokeWidth="2" strokeLinecap="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
                                    <span style={{ padding: "2px 8px", background: isSusHost(selectedEdge.target) ? "#f0883e18" : "#58a6ff18", color: isSusHost(selectedEdge.target) ? "#f0883e" : "#58a6ff", borderRadius: 5, fontSize: 10 }}>{selectedEdge.target}{isSusHost(selectedEdge.target) && " \u26a0"}</span>
                                  </span>
                                  {selectedEdge.hasFailures && <span style={{ padding: "2px 8px", background: (th.danger || "#f85149") + "18", color: th.danger || "#f85149", borderRadius: 5, fontSize: 9, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>FAILED</span>}
                                </div>
                                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, fontSize: 11, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>
                                  <div><span style={{ fontSize: 8, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Events</span><div style={{ fontWeight: 700, color: th.text, fontSize: 16, marginTop: 1 }}>{selectedEdge.count}</div></div>
                                  <div><span style={{ fontSize: 8, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Users</span><div style={{ marginTop: 2 }}>{selectedEdge.users.join(", ")}</div></div>
                                  <div><span style={{ fontSize: 8, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Logon Type</span><div style={{ color: logonColor(selectedEdge.logonTypes), marginTop: 2 }}>{logonLabel(selectedEdge.logonTypes)} ({selectedEdge.logonTypes.join(",")}){selectedEdge.logonTypes.includes("8") && <span style={{ marginLeft: 4, padding: "1px 5px", background: "#f8514922", color: "#f85149", borderRadius: 3, fontSize: 8, fontWeight: 700 }}>CLEARTEXT</span>}</div></div>
                                  <div><span style={{ fontSize: 8, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>First Seen</span><div style={{ marginTop: 2, fontFamily: "monospace", fontSize: 10 }}>{selectedEdge.firstSeen?.slice(0, 19)}</div></div>
                                  <div><span style={{ fontSize: 8, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Last Seen</span><div style={{ marginTop: 2, fontFamily: "monospace", fontSize: 10 }}>{selectedEdge.lastSeen?.slice(0, 19)}</div></div>
                                </div>
                                {selectedEdge.eventBreakdown && Object.keys(selectedEdge.eventBreakdown).length > 0 && (
                                  <div style={{ marginTop: 10, paddingTop: 8, borderTop: `1px solid ${th.border}22` }}>
                                    <span style={{ fontSize: 8, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Event Breakdown</span>
                                    <div style={{ display: "flex", gap: 5, marginTop: 4, flexWrap: "wrap" }}>
                                      {Object.entries(selectedEdge.eventBreakdown).sort((a, b) => b[1] - a[1]).map(([eid, count]) => (
                                        <span key={eid} style={{ padding: "2px 7px", background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, fontSize: 10, fontFamily: "monospace" }}>
                                          <span style={{ color: th.accent, fontWeight: 600 }}>{eid}</span>
                                          <span style={{ color: th.textMuted, marginLeft: 3 }}>{"\u00D7"}{count}</span>
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            );
                          })()}
                        </div>
                      );
                    })()}

                    {/* Chains tab */}
                    {viewTab === "chains" && (
                      <div>
                        {data.chains.length === 0 ? (
                          <div style={{ textAlign: "center", padding: 30, color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>No multi-hop lateral movement chains detected</div>
                        ) : (
                          <div style={{ maxHeight: 350, overflow: "auto" }}>
                            {data.chains.map((chain, ci) => (
                              <div key={ci} style={{ padding: "10px 12px", marginBottom: 8, background: th.panelBg, borderRadius: 6, border: `1px solid ${th.border}` }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                                  <span style={{ padding: "2px 8px", background: (th.danger || "#f85149") + "22", color: th.danger || "#f85149", borderRadius: 3, fontSize: 10, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{chain.hops} hops</span>
                                  <span style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>Users: {chain.users.join(", ") || "(unknown)"}</span>
                                </div>
                                <div style={{ display: "flex", alignItems: "center", gap: 4, flexWrap: "wrap" }}>
                                  {chain.path.map((host, hi) => (
                                    <span key={hi} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                                      <span style={{ padding: "3px 8px", background: hi === 0 ? "#3fb95022" : hi === chain.path.length - 1 ? (th.danger || "#f85149") + "22" : th.btnBg, color: hi === 0 ? "#3fb950" : hi === chain.path.length - 1 ? (th.danger || "#f85149") : th.text, borderRadius: 4, fontSize: 10, fontFamily: "monospace", border: `1px solid ${th.border}` }}>{host}</span>
                                      {hi < chain.path.length - 1 && <span style={{ color: th.textMuted, fontSize: 10 }}>{"\u2192"}</span>}
                                    </span>
                                  ))}
                                </div>
                                <div style={{ fontSize: 9, color: th.textMuted, marginTop: 4, fontFamily: "monospace" }}>
                                  {chain.timestamps.filter(Boolean).map((t) => t.slice(0, 19)).join(" \u2192 ")}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {/* RDP Sessions tab */}
                    {viewTab === "rdp" && (() => {
                      const sessions = data.rdpSessions || [];
                      if (sessions.length === 0) {
                        return <div style={{ textAlign: "center", padding: 30, color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>No RDP sessions detected. Ensure TerminalServices event logs (LocalSessionManager, RemoteConnectionManager) are included in your data.</div>;
                      }
                      const rdpHeaders = ["Status", "Source", "Target", "User", "Session ID", "Events", "Start Time", "End Time", "Duration", "Flags"];
                      const rdpDefWidths = { Status: 95, Source: 130, Target: 130, User: 130, "Session ID": 78, Events: 55, "Start Time": 145, "End Time": 145, Duration: 75, Flags: 105 };
                      const rdpColWidths = modal.rdpColWidths || rdpDefWidths;
                      const rdpSortCol = modal.rdpSortCol || "Start Time";
                      const rdpSortDir = modal.rdpSortDir || "desc";

                      const statusStyle = (status) => {
                        const map = {
                          "active": { bg: "#3fb95022", color: "#3fb950", label: "ACTIVE" },
                          "active (no logoff)": { bg: "#f0883e22", color: "#f0883e", label: "NO LOGOFF" },
                          "disconnected": { bg: "#d2992222", color: "#d29922", label: "DISCONNECTED" },
                          "ended": { bg: `${th.textMuted}15`, color: th.textMuted, label: "ENDED" },
                          "failed": { bg: "#f8514922", color: "#f85149", label: "FAILED" },
                          "connecting": { bg: "#58a6ff22", color: "#58a6ff", label: "CONNECTING" },
                          "incomplete": { bg: `${th.textMuted}15`, color: th.textMuted, label: "INCOMPLETE" },
                        };
                        return map[status] || map["incomplete"];
                      };
                      const fmtDur = (s, e) => {
                        if (!s || !e) return "\u2014";
                        const ms = new Date(e) - new Date(s);
                        if (ms <= 0) return "\u2014";
                        const sec = Math.floor(ms / 1000), min = Math.floor(sec / 60), hr = Math.floor(min / 60), dy = Math.floor(hr / 24);
                        const rh = hr % 24, rm = min % 60;
                        if (dy > 0 && rh > 0) return `${dy}d ${rh}h`;
                        if (dy > 0) return `${dy}d`;
                        if (hr > 0 && rm > 0) return `${hr}h ${rm}m`;
                        if (hr > 0) return `${hr}h`;
                        if (min > 0) return `${min}m`;
                        return `${sec}s`;
                      };
                      const rdpDurMs = (s) => {
                        if (!s.startTime || !s.endTime) return 0;
                        const d = new Date(s.endTime) - new Date(s.startTime);
                        return isNaN(d) ? 0 : Math.max(0, d);
                      };
                      const flagsStr = (s) => { const f = []; if (s.hasAdmin) f.push("ADMIN"); if (s.isReconnect) f.push("RECONNECT"); return f.join(", "); };

                      const rdpCellVal = (s, h) => {
                        if (h === "Status") return statusStyle(s.status).label;
                        if (h === "Source") return s.source || "\u2014";
                        if (h === "Target") return s.target || "\u2014";
                        if (h === "User") return s.user || "(unknown)";
                        if (h === "Session ID") return s.sessionId != null ? String(s.sessionId) : "\u2014";
                        if (h === "Events") return String((s.events || []).length);
                        if (h === "Start Time") return s.startTime?.slice(0, 19) || "";
                        if (h === "End Time") return s.endTime?.slice(0, 19) || "";
                        if (h === "Duration") return fmtDur(s.startTime, s.endTime);
                        if (h === "Flags") return flagsStr(s);
                        return "";
                      };
                      const rdpSortKey = (s, col) => {
                        if (col === "Status") return statusStyle(s.status).label;
                        if (col === "Source") return s.source || "";
                        if (col === "Target") return s.target || "";
                        if (col === "User") return s.user || "";
                        if (col === "Session ID") return s.sessionId != null ? s.sessionId : -1;
                        if (col === "Events") return (s.events || []).length;
                        if (col === "Start Time") return s.startTime || "";
                        if (col === "End Time") return s.endTime || "";
                        if (col === "Duration") return rdpDurMs(s);
                        if (col === "Flags") return flagsStr(s);
                        return "";
                      };

                      // Column filters
                      const rdpColFilters = modal.rdpColFilters || {};
                      const filteredSessions = sessions.filter((s) => {
                        for (const [col, allowed] of Object.entries(rdpColFilters)) {
                          if (!allowed || allowed.length === 0) continue;
                          const val = rdpCellVal(s, col);
                          if (!allowed.includes(val)) return false;
                        }
                        return true;
                      });
                      const sortedSessions = [...filteredSessions].sort((a, b) => {
                        const av = rdpSortKey(a, rdpSortCol), bv = rdpSortKey(b, rdpSortCol);
                        const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
                        return rdpSortDir === "asc" ? cmp : -cmp;
                      });
                      const toggleRdpSort = (col) => {
                        setModal((p) => ({ ...p, rdpSortCol: col, rdpSortDir: p.rdpSortCol === col && p.rdpSortDir === "asc" ? "desc" : "asc" }));
                      };

                      // Checkbox state
                      const rdpChecked = modal.rdpCheckedRows || new Set();
                      const rdpRowKey = (s) => `${s.source}|${s.target}|${s.user}|${s.startTime}`;
                      const isRdpChecked = (s) => rdpChecked.has(rdpRowKey(s));
                      const toggleRdpCheck = (s, ev) => {
                        ev.stopPropagation();
                        const k = rdpRowKey(s);
                        setModal((p) => { const set = new Set(p.rdpCheckedRows || []); set.has(k) ? set.delete(k) : set.add(k); return { ...p, rdpCheckedRows: set }; });
                      };
                      const rdpAllChecked = sortedSessions.length > 0 && sortedSessions.every((s) => isRdpChecked(s));
                      const toggleAllRdp = (ev) => {
                        ev.stopPropagation();
                        setModal((p) => {
                          if (rdpAllChecked) return { ...p, rdpCheckedRows: new Set() };
                          return { ...p, rdpCheckedRows: new Set(sortedSessions.map(rdpRowKey)) };
                        });
                      };
                      const rdpCheckedCount = sortedSessions.filter((s) => isRdpChecked(s)).length;

                      // Copy (selected or all)
                      const copyRdp = () => {
                        const headerLine = rdpHeaders.join("\t");
                        const selected = sortedSessions.filter((s) => isRdpChecked(s));
                        const toCopy = selected.length > 0 ? selected : sortedSessions;
                        const lines = toCopy.map((s) => rdpHeaders.map((h) => rdpCellVal(s, h)).join("\t"));
                        navigator.clipboard.writeText([headerLine, ...lines].join("\n"));
                      };

                      // Resize
                      const onRdpResizeStart = (colName, e) => {
                        e.preventDefault(); e.stopPropagation();
                        const startX = e.clientX;
                        const startW = rdpColWidths[colName] || rdpDefWidths[colName];
                        document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
                        const move = (ev) => {
                          const newW = Math.max(40, startW + ev.clientX - startX);
                          setModal((p) => ({ ...p, rdpColWidths: { ...(p.rdpColWidths || rdpDefWidths), [colName]: newW } }));
                        };
                        const up = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); };
                        document.addEventListener("mousemove", move);
                        document.addEventListener("mouseup", up);
                      };

                      // Column filter dropdown
                      const openRdpFilter = (colName, e) => {
                        e.stopPropagation();
                        const rect = e.currentTarget.getBoundingClientRect();
                        const counts = {};
                        for (const s of sessions) { const v = rdpCellVal(s, colName); counts[v] = (counts[v] || 0) + 1; }
                        const allVals = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
                        const current = rdpColFilters[colName];
                        const selected = new Set(current && current.length > 0 ? current : allVals);
                        setModal((p) => ({ ...p, rdpFilterOpen: colName, rdpFilterPos: { x: rect.left, y: rect.bottom + 2 }, rdpFilterVals: allVals, rdpFilterCounts: counts, rdpFilterSel: selected, rdpFilterSearch: "", rdpFilterX: null, rdpFilterY: null }));
                      };
                      const rdpFilterOpen = modal.rdpFilterOpen;
                      const rdpFilterPos = modal.rdpFilterPos || {};
                      const rdpFilterVals = modal.rdpFilterVals || [];
                      const rdpFilterCounts = modal.rdpFilterCounts || {};
                      const rdpFilterSel = modal.rdpFilterSel || new Set();
                      const rdpFilterSearch = modal.rdpFilterSearch || "";
                      const rdpDisplayVals = rdpFilterSearch ? rdpFilterVals.filter((v) => v.toLowerCase().includes(rdpFilterSearch.toLowerCase())) : rdpFilterVals;
                      const rdpActiveFilterCount = Object.values(rdpColFilters).filter((v) => v && v.length > 0).length;
                      const rdpTotalTableW = 30 + rdpHeaders.reduce((acc, h) => acc + (rdpColWidths[h] || rdpDefWidths[h]), 0);
                      const expandedIdx = modal.expandedSession;

                      return (
                        <div>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6, marginBottom: 6 }}>
                            {rdpActiveFilterCount > 0 && (
                              <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", background: `${th.accent}11`, borderRadius: 6, fontSize: 10, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>
                                <span style={{ fontWeight: 600 }}>Filter active ({rdpActiveFilterCount} column{rdpActiveFilterCount > 1 ? "s" : ""})</span>
                                <span style={{ fontSize: 10, color: th.textMuted }}>{"\u2014"} {filteredSessions.length} of {sessions.length} sessions</span>
                                <button onClick={() => setModal((p) => ({ ...p, rdpColFilters: {} }))} style={{ padding: "1px 8px", fontSize: 9, background: th.accent, color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600 }}>Clear All</button>
                              </div>
                            )}
                            <div style={{ display: "flex", gap: 6, marginLeft: "auto" }}>
                              <button onClick={copyRdp} style={{ padding: "3px 10px", fontSize: 10, background: th.btnBg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}
                                onMouseEnter={(ev) => { ev.currentTarget.style.background = th.accent + "22"; }} onMouseLeave={(ev) => { ev.currentTarget.style.background = th.btnBg; }}>
                                {rdpCheckedCount > 0 ? `Copy Selected (${rdpCheckedCount})` : `Copy All (${sortedSessions.length})`}
                              </button>
                            </div>
                          </div>
                          <div style={{ maxHeight: 400, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                            <table style={{ borderCollapse: "collapse", fontSize: 10, fontFamily: "monospace", tableLayout: "fixed", width: rdpTotalTableW }}>
                              <thead>
                                <tr>
                                  <th style={{ position: "sticky", top: 0, width: 30, background: th.headerBg || th.panelBg, borderBottom: `1px solid ${th.border}`, zIndex: 2, textAlign: "center", padding: "6px 4px" }}>
                                    <input type="checkbox" checked={rdpAllChecked} onChange={toggleAllRdp} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                                  </th>
                                  {rdpHeaders.map((h) => (
                                    <th key={h} style={{ position: "sticky", top: 0, width: rdpColWidths[h] || rdpDefWidths[h], minWidth: 40, background: th.headerBg || th.panelBg, color: rdpSortCol === h ? th.text : th.accent, padding: "6px 8px", textAlign: "left", fontSize: 9, borderBottom: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", overflow: "hidden", boxSizing: "border-box", userSelect: "none", zIndex: 2 }}>
                                      <div style={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
                                        <span onClick={() => toggleRdpSort(h)} style={{ cursor: "pointer", overflow: "hidden", textOverflow: "ellipsis" }}>{h}</span>
                                        {rdpSortCol === h && <span style={{ fontSize: 7, color: th.accent }}>{rdpSortDir === "asc" ? "\u25B2" : "\u25BC"}</span>}
                                        <span onClick={(e) => openRdpFilter(h, e)} style={{ cursor: "pointer", fontSize: 7, color: rdpColFilters[h] ? th.accent : th.textMuted + "66", flexShrink: 0, marginLeft: "auto", paddingRight: 8 }}>{"\u25BC"}</span>
                                        <div onMouseDown={(e) => onRdpResizeStart(h, e)} style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 6, cursor: "col-resize" }}>
                                          <div style={{ position: "absolute", right: 2, top: 2, bottom: 2, width: 1, background: th.border }} />
                                        </div>
                                      </div>
                                    </th>
                                  ))}
                                </tr>
                              </thead>
                              <tbody>
                                {sortedSessions.map((s, i) => {
                                  const st = statusStyle(s.status);
                                  const dur = fmtDur(s.startTime, s.endTime);
                                  const durMs = rdpDurMs(s);
                                  const expanded = expandedIdx === i;
                                  return (
                                    <Fragment key={i}>
                                      <tr onClick={() => setModal((p) => ({ ...p, expandedSession: expanded ? null : i }))}
                                        style={{ background: isRdpChecked(s) ? `${th.accent}0a` : i % 2 === 0 ? "transparent" : (th.rowAlt || th.panelBg + "44"), cursor: "pointer" }}>
                                        <td style={{ padding: "4px 4px", textAlign: "center" }}>
                                          <input type="checkbox" checked={isRdpChecked(s)} onChange={(ev) => toggleRdpCheck(s, ev)} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                                        </td>
                                        <td style={{ padding: "4px 8px" }}>
                                          <span style={{ padding: "2px 7px", background: st.bg, color: st.color, borderRadius: 4, fontSize: 8, fontWeight: 700, fontFamily: "-apple-system, sans-serif" }}>{st.label}</span>
                                        </td>
                                        <td style={{ padding: "4px 8px", color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.source || "\u2014"}</td>
                                        <td style={{ padding: "4px 8px", color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.target || "\u2014"}</td>
                                        <td style={{ padding: "4px 8px", color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.user || "(unknown)"}</td>
                                        <td style={{ padding: "4px 8px", color: th.textDim, textAlign: "center" }}>{s.sessionId != null ? s.sessionId : "\u2014"}</td>
                                        <td style={{ padding: "4px 8px", fontWeight: 600, color: th.text, textAlign: "center" }}>{(s.events || []).length}</td>
                                        <td style={{ padding: "4px 8px", color: th.textDim, whiteSpace: "nowrap" }}>{s.startTime?.slice(0, 19)}</td>
                                        <td style={{ padding: "4px 8px", color: th.textDim, whiteSpace: "nowrap" }}>{s.endTime?.slice(0, 19)}</td>
                                        <td style={{ padding: "4px 8px", whiteSpace: "nowrap", color: durMs >= 86400000 ? (th.danger || "#f85149") : durMs >= 3600000 ? "#f0883e" : th.textDim, fontWeight: durMs >= 86400000 ? 600 : 400 }}>{dur}</td>
                                        <td style={{ padding: "4px 8px" }}>
                                          <div style={{ display: "flex", gap: 3 }}>
                                            {s.hasAdmin && <span style={{ padding: "1px 5px", background: "#f8514918", color: "#f85149", borderRadius: 3, fontSize: 8, fontWeight: 700, fontFamily: "-apple-system, sans-serif" }}>ADMIN</span>}
                                            {s.isReconnect && <span style={{ padding: "1px 5px", background: "#a371f718", color: "#a371f7", borderRadius: 3, fontSize: 8, fontFamily: "-apple-system, sans-serif" }}>RECONNECT</span>}
                                          </div>
                                        </td>
                                      </tr>
                                      {expanded && (
                                        <tr>
                                          <td colSpan={rdpHeaders.length + 1} style={{ padding: "0 12px 10px 48px", borderTop: `1px solid ${th.border}22`, background: `${st.color}04` }}>
                                            <div style={{ position: "relative", paddingLeft: 18, marginTop: 8 }}>
                                              <div style={{ position: "absolute", left: 4, top: 2, bottom: 2, width: 1, background: `${st.color}44` }} />
                                              {(s.events || []).map((evt, ei) => {
                                                const dotColor = evt.eventId === "4625" ? "#f85149" : evt.eventId === "4672" ? "#f0883e" : evt.eventId === "4624" ? "#58a6ff" : ["21","22","25","1149"].includes(evt.eventId) ? "#3fb950" : ["23","4634","4647"].includes(evt.eventId) ? th.textMuted : ["24","39","40","4779"].includes(evt.eventId) ? "#d29922" : st.color;
                                                return (
                                                  <div key={ei} style={{ position: "relative", paddingLeft: 18, paddingBottom: 6, fontSize: 10, display: "flex", alignItems: "center", gap: 8 }}>
                                                    <div style={{ position: "absolute", left: 0, top: 4, width: 9, height: 9, borderRadius: "50%", background: dotColor, border: `2px solid ${th.panelBg}`, boxShadow: `0 0 0 1px ${dotColor}44` }} />
                                                    <span style={{ padding: "1px 5px", background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 3, fontSize: 9, fontFamily: "monospace", color: th.accent, minWidth: 32, textAlign: "center", fontWeight: 600 }}>{evt.eventId}</span>
                                                    <span style={{ color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>{evt.description}</span>
                                                    <span style={{ marginLeft: "auto", color: th.textMuted, fontFamily: "monospace", fontSize: 9 }}>{evt.ts?.slice(11, 23) || ""}</span>
                                                  </div>
                                                );
                                              })}
                                            </div>
                                          </td>
                                        </tr>
                                      )}
                                    </Fragment>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                          {/* RDP Column filter dropdown popup */}
                          {rdpFilterOpen && (
                            <>
                              <div style={{ position: "fixed", inset: 0, zIndex: 998 }} onClick={() => setModal((p) => ({ ...p, rdpFilterOpen: null }))} />
                              <div style={{ position: "fixed", left: modal.rdpFilterX ?? Math.min(rdpFilterPos.x || 0, window.innerWidth - 340), top: modal.rdpFilterY ?? Math.min(rdpFilterPos.y || 0, window.innerHeight - 440), width: modal.rdpFilterW || 320, height: modal.rdpFilterH || 420, background: th.modalBg, border: `1px solid ${th.border}`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 999, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                                <div style={{ padding: "8px 10px", borderBottom: `1px solid ${th.border}33`, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "grab", userSelect: "none", flexShrink: 0 }}
                                  onMouseDown={(e) => {
                                    e.preventDefault();
                                    const startX = e.clientX, startY = e.clientY;
                                    const startLeft = modal.rdpFilterX ?? Math.min(rdpFilterPos.x || 0, window.innerWidth - 340);
                                    const startTop = modal.rdpFilterY ?? Math.min(rdpFilterPos.y || 0, window.innerHeight - 440);
                                    document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                                    const onMove = (ev) => setModal((p) => ({ ...p, rdpFilterX: startLeft + ev.clientX - startX, rdpFilterY: startTop + ev.clientY - startY }));
                                    const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                                    window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                                  }}>
                                  <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "SF Mono, Menlo, monospace" }}>FILTER {"\u2014"} {rdpFilterOpen.toUpperCase()}</span>
                                  <span style={{ cursor: "pointer", color: th.textMuted, fontSize: 14, lineHeight: 1 }} onClick={() => setModal((p) => ({ ...p, rdpFilterOpen: null }))}>{"\u00D7"}</span>
                                </div>
                                <div style={{ padding: "6px 10px", flexShrink: 0 }}>
                                  <input type="text" placeholder="Search values..." value={rdpFilterSearch} onChange={(e) => setModal((p) => ({ ...p, rdpFilterSearch: e.target.value }))}
                                    style={{ width: "100%", boxSizing: "border-box", padding: "5px 8px", fontSize: 11, background: th.panelBg, border: `1px solid ${th.border}55`, borderRadius: 4, color: th.text, outline: "none", fontFamily: "SF Mono, Menlo, monospace" }}
                                    autoFocus />
                                </div>
                                <div style={{ padding: "2px 10px 6px", display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                                  <button onClick={() => setModal((p) => ({ ...p, rdpFilterSel: new Set(rdpFilterVals) }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                                  <button onClick={() => setModal((p) => ({ ...p, rdpFilterSel: new Set() }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                                  <span style={{ marginLeft: "auto", fontSize: 10, color: th.textMuted }}>{rdpFilterVals.length} values</span>
                                </div>
                                <div style={{ flex: 1, overflow: "auto", padding: "0 6px", minHeight: 0 }}>
                                  {rdpDisplayVals.slice(0, 1000).map((v) => (
                                    <div key={v} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 4px", borderRadius: 3, cursor: "pointer" }}
                                      onClick={() => setModal((p) => { const set = new Set(p.rdpFilterSel || []); set.has(v) ? set.delete(v) : set.add(v); return { ...p, rdpFilterSel: set }; })}
                                      onMouseEnter={(e) => e.currentTarget.style.background = `${th.accent}0a`}
                                      onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                                      <input type="checkbox" checked={rdpFilterSel.has(v)} readOnly style={{ width: 13, height: 13, accentColor: th.accent, cursor: "pointer", flexShrink: 0 }} />
                                      <span style={{ fontSize: 11, color: th.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "SF Mono, Menlo, monospace" }}>{v || "(empty)"}</span>
                                      <span style={{ fontSize: 10, color: th.textMuted, flexShrink: 0 }}>{rdpFilterCounts[v]}</span>
                                    </div>
                                  ))}
                                </div>
                                <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}33`, display: "flex", gap: 6, justifyContent: "flex-end", flexShrink: 0 }}>
                                  <button onClick={() => setModal((p) => { const cf = { ...(p.rdpColFilters || {}) }; delete cf[rdpFilterOpen]; return { ...p, rdpColFilters: cf, rdpFilterOpen: null }; })}
                                    style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Reset</button>
                                  <button onClick={() => setModal((p) => ({ ...p, rdpFilterOpen: null }))}
                                    style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Cancel</button>
                                  <button onClick={() => setModal((p) => ({ ...p, rdpColFilters: { ...(p.rdpColFilters || {}), [rdpFilterOpen]: [...(p.rdpFilterSel || [])] }, rdpFilterOpen: null }))}
                                    style={{ padding: "4px 12px", fontSize: 10, background: th.accent, border: "none", borderRadius: 4, color: "#fff", cursor: "pointer", fontWeight: 600 }}>Apply</button>
                                </div>
                                <div onMouseDown={(e) => {
                                  e.preventDefault(); e.stopPropagation();
                                  const startX = e.clientX, startY = e.clientY, startW = modal.rdpFilterW || 320, startH = modal.rdpFilterH || 420;
                                  document.body.style.cursor = "nwse-resize"; document.body.style.userSelect = "none";
                                  const onMove = (ev) => setModal((p) => ({ ...p, rdpFilterW: Math.max(240, startW + ev.clientX - startX), rdpFilterH: Math.max(250, startH + ev.clientY - startY) }));
                                  const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                                  window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                                }} style={{ position: "absolute", bottom: 0, right: 0, width: 14, height: 14, cursor: "nwse-resize" }}>
                                  <svg width="10" height="10" viewBox="0 0 10 10" style={{ position: "absolute", bottom: 2, right: 2 }}>
                                    <path d="M8 2L2 8M8 5L5 8M8 8L8 8" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" />
                                  </svg>
                                </div>
                              </div>
                            </>
                          )}
                        </div>
                      );
                    })()}

                    {/* Connections table tab */}
                    {viewTab === "table" && (() => {
                      const lmHeaders = ["Source", "Target", "Count", "Users", "Logon Types", "Client Name", "Client Address", "First Seen", "Last Seen", "Duration"];
                      const lmDefWidths = { Source: 130, Target: 130, Count: 60, Users: 180, "Logon Types": 90, "Client Name": 140, "Client Address": 120, "First Seen": 150, "Last Seen": 150, Duration: 130 };
                      const lmColWidths = modal.colWidths || lmDefWidths;
                      const lmSortCol = modal.tableSortCol || "Count";
                      const lmSortDir = modal.tableSortDir || "desc";

                      const durationMs = (e) => {
                        if (!e.firstSeen || !e.lastSeen) return 0;
                        const a = new Date(e.firstSeen), b = new Date(e.lastSeen);
                        return isNaN(a) || isNaN(b) ? 0 : Math.max(0, b - a);
                      };
                      const formatDuration = (ms) => {
                        if (ms <= 0) return "\u2014";
                        const s = Math.floor(ms / 1000), m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
                        const rh = h % 24, rm = m % 60;
                        if (d > 0 && rh > 0) return `${d}d ${rh}h`;
                        if (d > 0) return `${d}d`;
                        if (h > 0 && rm > 0) return `${h}h ${rm}m`;
                        if (h > 0) return `${h}h`;
                        if (m > 0) return `${m}m`;
                        return `${s}s`;
                      };

                      const lmSortKey = (e, col) => {
                        if (col === "Count") return e.count;
                        if (col === "Source") return e.source;
                        if (col === "Target") return e.target;
                        if (col === "Users") return e.users.join(", ");
                        if (col === "Logon Types") return e.logonTypes.join(", ");
                        if (col === "Client Name") return (e.clientNames || []).join(", ");
                        if (col === "Client Address") return (e.clientAddresses || []).join(", ");
                        if (col === "First Seen") return e.firstSeen || "";
                        if (col === "Last Seen") return e.lastSeen || "";
                        if (col === "Duration") return durationMs(e);
                        return "";
                      };

                      const lmCellVal = (e, h) => {
                        if (h === "Source") return e.source;
                        if (h === "Target") return e.target;
                        if (h === "Count") return String(e.count);
                        if (h === "Users") return e.users.join(", ");
                        if (h === "Logon Types") return e.logonTypes.join(", ");
                        if (h === "Client Name") return (e.clientNames || []).join(", ");
                        if (h === "Client Address") return (e.clientAddresses || []).join(", ");
                        if (h === "First Seen") return e.firstSeen?.slice(0, 19) || "";
                        if (h === "Last Seen") return e.lastSeen?.slice(0, 19) || "";
                        if (h === "Duration") return formatDuration(durationMs(e));
                        return "";
                      };

                      // Column filters
                      const lmColFilters = modal.lmColFilters || {};
                      const filteredEdges = data.edges.filter((e) => {
                        for (const [col, allowed] of Object.entries(lmColFilters)) {
                          if (!allowed || allowed.length === 0) continue;
                          const val = lmCellVal(e, col);
                          if (!allowed.includes(val)) return false;
                        }
                        return true;
                      });

                      const sortedEdges = [...filteredEdges].sort((a, b) => {
                        const av = lmSortKey(a, lmSortCol), bv = lmSortKey(b, lmSortCol);
                        const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
                        return lmSortDir === "asc" ? cmp : -cmp;
                      });
                      const toggleSort = (col) => {
                        setModal((p) => ({
                          ...p,
                          tableSortCol: col,
                          tableSortDir: p.tableSortCol === col && p.tableSortDir === "asc" ? "desc" : "asc",
                        }));
                      };

                      // Checkbox state
                      const lmChecked = modal.lmCheckedRows || new Set();
                      const rowKey = (e) => `${e.source}|${e.target}|${e.firstSeen}`;
                      const isLmChecked = (e) => lmChecked.has(rowKey(e));
                      const toggleLmCheck = (e, ev) => {
                        ev.stopPropagation();
                        const k = rowKey(e);
                        setModal((p) => {
                          const s = new Set(p.lmCheckedRows || []);
                          s.has(k) ? s.delete(k) : s.add(k);
                          return { ...p, lmCheckedRows: s };
                        });
                      };
                      const allChecked = sortedEdges.length > 0 && sortedEdges.every((e) => isLmChecked(e));
                      const toggleAllLm = (ev) => {
                        ev.stopPropagation();
                        setModal((p) => {
                          if (allChecked) return { ...p, lmCheckedRows: new Set() };
                          return { ...p, lmCheckedRows: new Set(sortedEdges.map(rowKey)) };
                        });
                      };
                      const checkedCount = sortedEdges.filter((e) => isLmChecked(e)).length;

                      // Copy (selected or all)
                      const copyAll = () => {
                        const headerLine = lmHeaders.join("\t");
                        const selected = sortedEdges.filter((e) => isLmChecked(e));
                        const toCopy = selected.length > 0 ? selected : sortedEdges;
                        const lines = toCopy.map((e) => lmHeaders.map((h) => lmCellVal(e, h)).join("\t"));
                        navigator.clipboard.writeText([headerLine, ...lines].join("\n"));
                      };

                      // Resize
                      const onResizeStart = (colName, e) => {
                        e.preventDefault(); e.stopPropagation();
                        const startX = e.clientX;
                        const startW = lmColWidths[colName] || lmDefWidths[colName];
                        document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
                        const move = (ev) => {
                          const newW = Math.max(40, startW + ev.clientX - startX);
                          setModal((p) => ({ ...p, colWidths: { ...(p.colWidths || lmDefWidths), [colName]: newW } }));
                        };
                        const up = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); };
                        document.addEventListener("mousemove", move);
                        document.addEventListener("mouseup", up);
                      };

                      // Column filter dropdown
                      const openLmFilter = (colName, e) => {
                        e.stopPropagation();
                        const rect = e.currentTarget.getBoundingClientRect();
                        const counts = {};
                        for (const edge of data.edges) { const v = lmCellVal(edge, colName); counts[v] = (counts[v] || 0) + 1; }
                        const allVals = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
                        const current = lmColFilters[colName];
                        const selected = new Set(current && current.length > 0 ? current : allVals);
                        setModal((p) => ({ ...p, lmFilterOpen: colName, lmFilterPos: { x: rect.left, y: rect.bottom + 2 }, lmFilterVals: allVals, lmFilterCounts: counts, lmFilterSel: selected, lmFilterSearch: "", lmFilterX: null, lmFilterY: null }));
                      };
                      const filterOpen = modal.lmFilterOpen;
                      const filterPos = modal.lmFilterPos || {};
                      const filterVals = modal.lmFilterVals || [];
                      const filterCounts = modal.lmFilterCounts || {};
                      const filterSel = modal.lmFilterSel || new Set();
                      const filterSearch = modal.lmFilterSearch || "";
                      const displayVals = filterSearch ? filterVals.filter((v) => v.toLowerCase().includes(filterSearch.toLowerCase())) : filterVals;
                      const activeFilterCount = Object.values(lmColFilters).filter((v) => v && v.length > 0).length;
                      const totalTableW = 30 + lmHeaders.reduce((s, h) => s + (lmColWidths[h] || lmDefWidths[h]), 0);

                      return (
                        <div>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6, marginBottom: 6 }}>
                            {activeFilterCount > 0 && (
                              <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", background: `${th.accent}11`, borderRadius: 6, fontSize: 10, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>
                                <span style={{ fontWeight: 600 }}>Filter active ({activeFilterCount} column{activeFilterCount > 1 ? "s" : ""})</span>
                                <span style={{ fontSize: 10, color: th.textMuted }}>{"\u2014"} {filteredEdges.length} of {data.edges.length} connections</span>
                                <button onClick={() => setModal((p) => ({ ...p, lmColFilters: {} }))} style={{ padding: "1px 8px", fontSize: 9, background: th.accent, color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600 }}>Clear All</button>
                              </div>
                            )}
                            <div style={{ display: "flex", gap: 6, marginLeft: "auto" }}>
                              <button onClick={copyAll} style={{ padding: "3px 10px", fontSize: 10, background: th.btnBg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}
                                onMouseEnter={(ev) => { ev.currentTarget.style.background = th.accent + "22"; }} onMouseLeave={(ev) => { ev.currentTarget.style.background = th.btnBg; }}>
                                {checkedCount > 0 ? `Copy Selected (${checkedCount})` : `Copy All (${sortedEdges.length})`}
                              </button>
                            </div>
                          </div>
                          <div style={{ maxHeight: 360, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                            <table style={{ borderCollapse: "collapse", fontSize: 10, fontFamily: "monospace", tableLayout: "fixed", width: totalTableW }}>
                              <thead>
                                <tr>
                                  <th style={{ position: "sticky", top: 0, width: 30, background: th.headerBg || th.panelBg, borderBottom: `1px solid ${th.border}`, zIndex: 2, textAlign: "center", padding: "6px 4px" }}>
                                    <input type="checkbox" checked={allChecked} onChange={toggleAllLm} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                                  </th>
                                  {lmHeaders.map((h) => (
                                    <th key={h} style={{ position: "sticky", top: 0, width: lmColWidths[h] || lmDefWidths[h], minWidth: 40, background: th.headerBg || th.panelBg, color: lmSortCol === h ? th.text : th.accent, padding: "6px 8px", textAlign: "left", fontSize: 9, borderBottom: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif", whiteSpace: "nowrap", overflow: "hidden", boxSizing: "border-box", userSelect: "none", zIndex: 2 }}>
                                      <div style={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
                                        <span onClick={() => toggleSort(h)} style={{ cursor: "pointer", overflow: "hidden", textOverflow: "ellipsis" }}>{h}</span>
                                        {lmSortCol === h && <span style={{ fontSize: 7, color: th.accent }}>{lmSortDir === "asc" ? "\u25B2" : "\u25BC"}</span>}
                                        <span onClick={(e) => openLmFilter(h, e)} style={{ cursor: "pointer", fontSize: 7, color: lmColFilters[h] ? th.accent : th.textMuted + "66", flexShrink: 0, marginLeft: "auto", paddingRight: 8 }}>{"\u25BC"}</span>
                                        <div onMouseDown={(e) => onResizeStart(h, e)} style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 6, cursor: "col-resize" }}>
                                          <div style={{ position: "absolute", right: 2, top: 2, bottom: 2, width: 1, background: th.border }} />
                                        </div>
                                      </div>
                                    </th>
                                  ))}
                                </tr>
                              </thead>
                              <tbody>
                                {sortedEdges.map((e, i) => (
                                  <tr key={i} style={{ background: isLmChecked(e) ? `${th.accent}0a` : i % 2 === 0 ? "transparent" : (th.rowAlt || th.panelBg + "44") }}>
                                    <td style={{ padding: "4px 4px", textAlign: "center" }}>
                                      <input type="checkbox" checked={isLmChecked(e)} onChange={(ev) => toggleLmCheck(e, ev)} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                                    </td>
                                    <td style={{ padding: "4px 8px", color: isSusHost(e.source) ? "#f0883e" : th.text, fontWeight: isSusHost(e.source) ? 600 : 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.source}{isSusHost(e.source) && <span title="Suspicious hostname pattern" style={{ marginLeft: 4, fontSize: 9 }}>&#9888;</span>}</td>
                                    <td style={{ padding: "4px 8px", color: isSusHost(e.target) ? "#f0883e" : th.text, fontWeight: isSusHost(e.target) ? 600 : 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.target}{isSusHost(e.target) && <span title="Suspicious hostname pattern" style={{ marginLeft: 4, fontSize: 9 }}>&#9888;</span>}</td>
                                    <td style={{ padding: "4px 8px", fontWeight: 600, color: th.text }}>{e.count}</td>
                                    <td style={{ padding: "4px 8px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: th.textDim }}>{e.users.join(", ")}</td>
                                    <td style={{ padding: "4px 8px", color: th.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.logonTypes.join(", ")}</td>
                                    <td style={{ padding: "4px 8px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: (e.clientNames || []).length > 0 ? "#d2a8ff" : th.textDim, fontWeight: (e.clientNames || []).length > 0 ? 600 : 400 }}>{(e.clientNames || []).join(", ")}</td>
                                    <td style={{ padding: "4px 8px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: (e.clientAddresses || []).length > 0 ? "#d2a8ff" : th.textDim }}>{(e.clientAddresses || []).join(", ")}</td>
                                    <td style={{ padding: "4px 8px", color: th.textDim, whiteSpace: "nowrap" }}>{e.firstSeen?.slice(0, 19)}</td>
                                    <td style={{ padding: "4px 8px", color: th.textDim, whiteSpace: "nowrap" }}>{e.lastSeen?.slice(0, 19)}</td>
                                    <td style={{ padding: "4px 8px", whiteSpace: "nowrap", color: durationMs(e) >= 86400000 ? (th.danger || "#f85149") : durationMs(e) >= 3600000 ? "#f0883e" : th.textDim, fontWeight: durationMs(e) >= 86400000 ? 600 : 400 }}>{formatDuration(durationMs(e))}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          {/* Column filter dropdown popup */}
                          {filterOpen && (
                            <>
                              <div style={{ position: "fixed", inset: 0, zIndex: 998 }} onClick={() => setModal((p) => ({ ...p, lmFilterOpen: null }))} />
                              <div style={{ position: "fixed", left: modal.lmFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340), top: modal.lmFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440), width: modal.lmFilterW || 320, height: modal.lmFilterH || 420, background: th.modalBg, border: `1px solid ${th.border}`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 999, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                                <div style={{ padding: "8px 10px", borderBottom: `1px solid ${th.border}33`, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "grab", userSelect: "none", flexShrink: 0 }}
                                  onMouseDown={(e) => {
                                    e.preventDefault();
                                    const startX = e.clientX, startY = e.clientY;
                                    const startLeft = modal.lmFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340);
                                    const startTop = modal.lmFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440);
                                    document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                                    const onMove = (ev) => setModal((p) => ({ ...p, lmFilterX: startLeft + ev.clientX - startX, lmFilterY: startTop + ev.clientY - startY }));
                                    const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                                    window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                                  }}>
                                  <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "SF Mono, Menlo, monospace" }}>FILTER {"\u2014"} {filterOpen.toUpperCase()}</span>
                                  <span style={{ cursor: "pointer", color: th.textMuted, fontSize: 14, lineHeight: 1 }} onClick={() => setModal((p) => ({ ...p, lmFilterOpen: null }))}>{"\u00D7"}</span>
                                </div>
                                <div style={{ padding: "6px 10px", flexShrink: 0 }}>
                                  <input type="text" placeholder="Search values..." value={filterSearch} onChange={(e) => setModal((p) => ({ ...p, lmFilterSearch: e.target.value }))}
                                    style={{ width: "100%", boxSizing: "border-box", padding: "5px 8px", fontSize: 11, background: th.panelBg, border: `1px solid ${th.border}55`, borderRadius: 4, color: th.text, outline: "none", fontFamily: "SF Mono, Menlo, monospace" }}
                                    autoFocus />
                                </div>
                                <div style={{ padding: "2px 10px 6px", display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                                  <button onClick={() => setModal((p) => ({ ...p, lmFilterSel: new Set(filterVals) }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                                  <button onClick={() => setModal((p) => ({ ...p, lmFilterSel: new Set() }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                                  <span style={{ marginLeft: "auto", fontSize: 10, color: th.textMuted }}>{filterVals.length} values</span>
                                </div>
                                <div style={{ flex: 1, overflow: "auto", padding: "0 6px", minHeight: 0 }}>
                                  {displayVals.slice(0, 1000).map((v) => (
                                    <div key={v} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 4px", borderRadius: 3, cursor: "pointer" }}
                                      onClick={() => setModal((p) => { const s = new Set(p.lmFilterSel || []); s.has(v) ? s.delete(v) : s.add(v); return { ...p, lmFilterSel: s }; })}
                                      onMouseEnter={(e) => e.currentTarget.style.background = `${th.accent}0a`}
                                      onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                                      <input type="checkbox" checked={filterSel.has(v)} readOnly style={{ width: 13, height: 13, accentColor: th.accent, cursor: "pointer", flexShrink: 0 }} />
                                      <span style={{ fontSize: 11, color: th.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "SF Mono, Menlo, monospace" }}>{v || "(empty)"}</span>
                                      <span style={{ fontSize: 10, color: th.textMuted, flexShrink: 0 }}>{filterCounts[v]}</span>
                                    </div>
                                  ))}
                                </div>
                                <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}33`, display: "flex", gap: 6, justifyContent: "flex-end", flexShrink: 0 }}>
                                  <button onClick={() => setModal((p) => { const cf = { ...(p.lmColFilters || {}) }; delete cf[filterOpen]; return { ...p, lmColFilters: cf, lmFilterOpen: null }; })}
                                    style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Reset</button>
                                  <button onClick={() => setModal((p) => ({ ...p, lmFilterOpen: null }))}
                                    style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Cancel</button>
                                  <button onClick={() => setModal((p) => ({ ...p, lmColFilters: { ...(p.lmColFilters || {}), [filterOpen]: [...(p.lmFilterSel || [])] }, lmFilterOpen: null }))}
                                    style={{ padding: "4px 12px", fontSize: 10, background: th.accent, border: "none", borderRadius: 4, color: "#fff", cursor: "pointer", fontWeight: 600 }}>Apply</button>
                                </div>
                                <div onMouseDown={(e) => {
                                  e.preventDefault(); e.stopPropagation();
                                  const startX = e.clientX, startY = e.clientY, startW = modal.lmFilterW || 320, startH = modal.lmFilterH || 420;
                                  document.body.style.cursor = "nwse-resize"; document.body.style.userSelect = "none";
                                  const onMove = (ev) => setModal((p) => ({ ...p, lmFilterW: Math.max(240, startW + ev.clientX - startX), lmFilterH: Math.max(250, startH + ev.clientY - startY) }));
                                  const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                                  window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                                }} style={{ position: "absolute", bottom: 0, right: 0, width: 14, height: 14, cursor: "nwse-resize" }}>
                                  <svg width="10" height="10" viewBox="0 0 10 10" style={{ position: "absolute", bottom: 2, right: 2 }}>
                                    <path d="M8 2L2 8M8 5L5 8M8 8L8 8" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round" />
                                  </svg>
                                </div>
                              </div>
                            </>
                          )}
                        </div>
                      );
                    })()}
                  </div>
                )}
              </div>

              {/* Footer — glass bar */}
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                {phase === "config" && (
                  <div style={{ display: "flex", justifyContent: "space-between", width: "100%" }}>
                    <button onClick={() => setModal(null)} style={{ ...ms.bs, borderRadius: 8 }}>Cancel</button>
                    <button onClick={handleAnalyze} style={{ ...ms.bp, borderRadius: 8, boxShadow: `0 2px 8px ${th.accent}33` }}>Analyze</button>
                  </div>
                )}
                {phase === "loading" && (
                  <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
                    <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>{Math.round(modal.lmProgress || 0)}% complete</span>
                    <button onClick={() => setModal((p) => ({ ...p, phase: "config", loading: false, lmProgress: 0, _cancelled: true }))} style={{ ...ms.bs, borderRadius: 8 }}>Cancel</button>
                  </div>
                )}
                {phase === "results" && (
                  <div style={{ display: "flex", justifyContent: "space-between", width: "100%" }}>
                    <button onClick={() => setModal((p) => ({ ...p, phase: "config", data: null, positions: null }))} style={{ ...ms.bs, borderRadius: 8 }}>Back</button>
                    <button onClick={() => setModal(null)} style={{ ...ms.bp, borderRadius: 8, boxShadow: `0 2px 8px ${th.accent}33` }}>Done</button>
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Persistence Analyzer Modal */}
      {modal?.type === "persistence" && ct && (() => {
        const { phase, data, mode: pMode } = modal;
        const viewTab = modal.viewTab || "grouped";
        const searchText = modal.searchText || "";
        const severityFilter = modal.severityFilter || "all";
        const categoryFilter = modal.categoryFilter || "all";

        const SEVERITY_COLORS = { critical: "#f85149", high: "#f0883e", medium: "#d29922", low: "#8b949e" };
        const checkedItems = modal.checkedItems || new Set();
        const isChecked = (item) => checkedItems.has(item.rowid + "|" + item.name + "|" + item.timestamp);
        const toggleCheck = (item, e) => {
          e.stopPropagation();
          const key = item.rowid + "|" + item.name + "|" + item.timestamp;
          setModal((p) => {
            const s = new Set(p.checkedItems || []);
            s.has(key) ? s.delete(key) : s.add(key);
            return { ...p, checkedItems: s };
          });
        };
        const persistItemKey = (item) => item.rowid + "|" + item.name + "|" + item.timestamp;
        const itemForKey = (key) => {
          const items = data?.items || [];
          return items.find((i) => persistItemKey(i) === key);
        };
        const selectedPersistKey = modal.selectedPersistKey || null;
        const isSelPersist = (item) => selectedPersistKey === persistItemKey(item);
        const toggleSelPersist = (item) => {
          const k = persistItemKey(item);
          setModal((p) => ({ ...p, selectedPersistKey: p.selectedPersistKey === k ? null : k }));
        };
        const formatItemText = (i) => `[${i.severity.toUpperCase()}] ${i.name}\t${i.detailsSummary}\t${i.timestamp || "N/A"}\t${i.computer || "N/A"}\t${i.user || "N/A"}\t${i.source}\t${i.riskScore}/10`;

        // Rule summaries for display (source of truth is in db.js)
        const EVTX_SUMMARIES = [
          { cat: "Services", name: "Service Installed", sev: "high", hint: "7045" },
          { cat: "Services", name: "Service Installed (Security)", sev: "high", hint: "4697" },
          { cat: "Scheduled Tasks", name: "Task Created", sev: "high", hint: "4698" },
          { cat: "Scheduled Tasks", name: "Task Deleted", sev: "medium", hint: "4699" },
          { cat: "Scheduled Tasks", name: "Task Registered", sev: "medium", hint: "106" },
          { cat: "Scheduled Tasks", name: "Task Updated", sev: "medium", hint: "140" },
          { cat: "Scheduled Tasks", name: "Task Process Created", sev: "high", hint: "129" },
          { cat: "Scheduled Tasks", name: "Task Action Started", sev: "medium", hint: "200" },
          { cat: "WMI Persistence", name: "WMI Event Subscription", sev: "critical", hint: "5861" },
          { cat: "WMI Persistence", name: "WMI EventFilter Created", sev: "critical", hint: "19" },
          { cat: "WMI Persistence", name: "WMI EventConsumer Created", sev: "critical", hint: "20" },
          { cat: "WMI Persistence", name: "WMI Binding Created", sev: "critical", hint: "21" },
          { cat: "Registry Autorun", name: "Registry Value Set", sev: "high", hint: "13" },
          { cat: "Registry Modification", name: "Registry Key Created/Deleted", sev: "medium", hint: "12" },
          { cat: "Registry Rename", name: "Registry Key/Value Renamed", sev: "medium", hint: "14" },
          { cat: "Startup Folder", name: "File Created in Startup", sev: "high", hint: "11" },
          { cat: "DLL Hijacking", name: "Unsigned DLL Loaded", sev: "medium", hint: "7" },
          { cat: "Driver Loading", name: "Suspicious Driver Loaded", sev: "critical", hint: "6" },
          { cat: "Process Tampering", name: "Process Tampering Detected", sev: "critical", hint: "25" },
          { cat: "Scheduled Tasks", name: "Task Deleted", sev: "high", hint: "141" },
          { cat: "Scheduled Tasks", name: "Boot Trigger Fired", sev: "medium", hint: "118" },
          { cat: "Scheduled Tasks", name: "Logon Trigger Fired", sev: "medium", hint: "119" },
        ];
        const REG_SUMMARIES = [
          { cat: "Run Keys", name: "Run/RunOnce Autostart", sev: "high", hint: "Run, RunOnce" },
          { cat: "Services", name: "Service ImagePath/ServiceDll", sev: "high", hint: "Services\\" },
          { cat: "Winlogon", name: "Winlogon Shell/Userinit", sev: "critical", hint: "Winlogon" },
          { cat: "AppInit DLLs", name: "AppInit_DLLs", sev: "critical", hint: "AppInit_DLLs" },
          { cat: "IFEO", name: "IFEO Debugger", sev: "critical", hint: "Image File Exec Opts" },
          { cat: "COM Hijacking", name: "COM Object Server", sev: "high", hint: "InprocServer32" },
          { cat: "Shell Extensions", name: "Shell Extension Handler", sev: "medium", hint: "Shell handlers" },
          { cat: "Boot Execute", name: "Session Manager BootExecute", sev: "critical", hint: "Session Manager" },
          { cat: "BHO", name: "Browser Helper Object", sev: "medium", hint: "Browser Helper" },
          { cat: "LSA", name: "LSA Security/Auth Packages", sev: "critical", hint: "Lsa" },
          { cat: "Print Monitors", name: "Print Monitor DLL", sev: "high", hint: "Print\\Monitors" },
          { cat: "Active Setup", name: "Active Setup StubPath", sev: "high", hint: "Active Setup" },
          { cat: "Startup Folder", name: "Startup Folder Registry Path", sev: "high", hint: "Shell Folders" },
          { cat: "Scheduled Tasks (Reg)", name: "Scheduled Task in Registry", sev: "medium", hint: "TaskCache" },
          { cat: "Network Providers", name: "Network Provider Order", sev: "high", hint: "NetworkProvider" },
        ];
        const toggleRule = (key) => setModal((p) => { const s = new Set(p.disabledRules || []); s.has(key) ? s.delete(key) : s.add(key); return { ...p, disabledRules: s }; });
        const deleteCustomRule = (idx) => setModal((p) => ({ ...p, customRules: (p.customRules || []).filter((_, i) => i !== idx) }));
        const addCustomRule = () => {
          const nr = modal.newRule || {};
          if (!nr.name && !nr.eventIds && !nr.keyPathPattern) return;
          setModal((p) => ({ ...p, customRules: [...(p.customRules || []), { ...nr, type: p.addingRule }], addingRule: false, newRule: {} }));
        };
        const disabledSet = modal.disabledRules || new Set();
        const evtxActive = EVTX_SUMMARIES.length - [...disabledSet].filter((k) => k.startsWith("evtx-")).length;
        const regActive = REG_SUMMARIES.length - [...disabledSet].filter((k) => k.startsWith("reg-")).length;
        const customCount = (modal.customRules || []).length;

        const handleAnalyze = async () => {
          const t0 = Date.now();
          const pInt = setInterval(() => {
            setModal((p) => {
              if (!p || p.type !== "persistence" || p.phase !== "loading") { clearInterval(pInt); return p; }
              const el = (Date.now() - t0) / 1000;
              const prog = Math.min(92, 90 * (1 - Math.exp(-el / 6)));
              const pi = prog < 15 ? 0 : prog < 50 ? 1 : prog < 80 ? 2 : 3;
              return { ...p, progress: prog, phaseIdx: pi };
            });
          }, 150);
          setModal((p) => ({ ...p, phase: "loading", loading: true, error: null, progress: 0, phaseIdx: 0, _cancelled: false }));
          try {
            const af = activeFilters(ct);
            const result = await tle.getPersistenceAnalysis(ct.id, {
              mode: pMode === "auto" ? "auto" : pMode,
              columns: modal.columns || {},
              searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
              columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
              bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
              disabledRules: [...(modal.disabledRules || [])],
              customRules: modal.customRules || [],
            });
            clearInterval(pInt);
            if (result.error) {
              setModal((p) => p?.type === "persistence" && !p._cancelled ? { ...p, phase: "config", loading: false, error: result.error, progress: 0 } : p);
            } else {
              setModal((p) => p?.type === "persistence" && !p._cancelled ? { ...p, progress: 100, phaseIdx: 3 } : p);
              await new Promise((r) => setTimeout(r, 250));
              setModal((p) => p?.type === "persistence" && !p._cancelled ? { ...p, phase: "results", data: result, loading: false } : p);
            }
          } catch (e) {
            clearInterval(pInt);
            setModal((p) => p?.type === "persistence" ? { ...p, phase: "config", loading: false, error: e.message, progress: 0 } : p);
          }
        };

        // Filtered items for results
        const filteredItems = data?.items?.filter((item) => {
          if (severityFilter !== "all" && item.severity !== severityFilter) return false;
          if (categoryFilter !== "all" && item.category !== categoryFilter) return false;
          if (searchText) {
            const s = searchText.toLowerCase();
            const blob = `${item.name} ${item.detailsSummary} ${item.computer} ${item.user} ${item.source} ${item.category}`.toLowerCase();
            if (!blob.includes(s)) return false;
          }
          return true;
        }) || [];

        // Group items by category
        const grouped = {};
        for (const item of filteredItems) {
          if (!grouped[item.category]) grouped[item.category] = [];
          grouped[item.category].push(item);
        }

        const categories = Object.keys(grouped).sort();
        const allCategories = data?.stats?.byCategory ? Object.keys(data.stats.byCategory).sort() : [];
        const collapsedCats = modal.collapsedCats || new Set();

        const paW = modal.modalW || Math.round(window.innerWidth * 0.92), paH = modal.modalH || Math.round(window.innerHeight * 0.88);
        const paX = modal.paX ?? Math.round((window.innerWidth - paW) / 2);
        const paY = modal.paY ?? Math.round((window.innerHeight - paH) / 2);

        const startPaDrag = (e) => {
          e.preventDefault();
          const sx = e.clientX - paX, sy = e.clientY - paY;
          document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
          const onMove = (ev) => setModal((p) => p ? { ...p, paX: Math.max(0, Math.min(window.innerWidth - 100, ev.clientX - sx)), paY: Math.max(0, Math.min(window.innerHeight - 40, ev.clientY - sy)) } : p);
          const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const startPaResize = (e, edge) => {
          e.preventDefault(); e.stopPropagation();
          const sx = e.clientX, sy = e.clientY, sw = paW, sh = paH, sleft = paX, stop = paY;
          document.body.style.userSelect = "none";
          const onMove = (ev) => {
            const dx = ev.clientX - sx, dy = ev.clientY - sy;
            setModal((p) => {
              if (!p) return p;
              let nw = sw, nh = sh, nx = sleft, ny = stop;
              if (edge.includes("r")) nw = Math.max(600, sw + dx);
              if (edge.includes("b")) nh = Math.max(400, sh + dy);
              if (edge.includes("l")) { nw = Math.max(600, sw - dx); nx = sleft + sw - nw; }
              if (edge.includes("t")) { nh = Math.max(400, sh - dy); ny = stop + sh - nh; }
              return { ...p, modalW: nw, modalH: nh, paX: nx, paY: ny };
            });
          };
          const onUp = () => { document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
          window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
        };

        const paEdge = (cursor, pos) => ({ position: "absolute", ...pos, zIndex: 10, cursor });

        return (
          <div style={{ position: "fixed", inset: 0, zIndex: 200, background: "rgba(0,0,0,0.55)", backdropFilter: "blur(8px)", WebkitBackdropFilter: "blur(8px)", WebkitAppRegion: "drag" }}>
            <div style={{ WebkitAppRegion: "no-drag", position: "absolute", left: paX, top: paY, width: paW, height: paH, display: "flex", flexDirection: "column", background: `linear-gradient(160deg, ${th.modalBg}, ${th.panelBg})`, borderRadius: 16, border: `1px solid ${th.modalBorder}44`, boxShadow: `0 25px 60px rgba(0,0,0,0.5), 0 0 0 1px ${th.border}22`, overflow: "hidden" }}>
              {/* Resize handles */}
              <div onMouseDown={(e) => startPaResize(e, "t")} style={paEdge("ns-resize", { top: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startPaResize(e, "b")} style={paEdge("ns-resize", { bottom: 0, left: 8, right: 8, height: 5 })} />
              <div onMouseDown={(e) => startPaResize(e, "l")} style={paEdge("ew-resize", { left: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startPaResize(e, "r")} style={paEdge("ew-resize", { right: 0, top: 8, bottom: 8, width: 5 })} />
              <div onMouseDown={(e) => startPaResize(e, "tl")} style={paEdge("nwse-resize", { top: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startPaResize(e, "tr")} style={paEdge("nesw-resize", { top: 0, right: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startPaResize(e, "bl")} style={paEdge("nesw-resize", { bottom: 0, left: 0, width: 10, height: 10 })} />
              <div onMouseDown={(e) => startPaResize(e, "br")} style={paEdge("nwse-resize", { bottom: 0, right: 0, width: 10, height: 10 })} />

              {/* Header — draggable */}
              <div onMouseDown={startPaDrag} style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)", flexShrink: 0, cursor: "grab" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill={(th.danger||"#f85149")+"22"} stroke={th.danger||"#f85149"} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/></svg>
                  <div>
                    <div style={{ fontSize: 15, fontWeight: 700, color: th.text, letterSpacing: "-0.3px", fontFamily: "-apple-system, sans-serif" }}>Persistence Analyzer</div>
                    <div style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", marginTop: 1 }}>
                      {phase === "results" && data ? `${data.stats.total} mechanisms found | ${data.stats.bySeverity?.critical || 0} critical | ${data.detectedMode?.toUpperCase()} mode` : "Automated persistence mechanism detection"}
                    </div>
                  </div>
                </div>
                <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", padding: 4, borderRadius: 6, fontSize: 18, lineHeight: 1 }} onMouseEnter={(e) => e.currentTarget.style.color = th.text} onMouseLeave={(e) => e.currentTarget.style.color = th.textMuted}>&times;</button>
              </div>

              {/* Body — scrollable */}
              <div style={{ flex: 1, overflow: "auto", padding: "16px 20px" }}>

                {/* Config phase */}
                {phase === "config" && (
                  <div>
                    {modal.error && <div style={{ padding: "10px 14px", marginBottom: 14, background: `${(th.danger||"#f85149")}15`, border: `1px solid ${(th.danger||"#f85149")}33`, borderRadius: 8, color: th.danger||"#f85149", fontSize: 12, fontFamily: "-apple-system, sans-serif" }}>{modal.error}</div>}

                    <div style={{ fontSize: 12, fontWeight: 600, color: th.text, marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>Data Source</div>
                    <div style={{ display: "flex", gap: 6, marginBottom: 18 }}>
                      {[
                        { key: "auto", label: "Auto-detect", desc: "Recommended" },
                        { key: "evtx", label: "EVTX Logs", desc: "EvtxECmd / Hayabusa" },
                        { key: "registry", label: "Registry Export", desc: "RECmd / Registry Explorer" },
                      ].map((opt) => (
                        <button key={opt.key} onClick={() => setModal((p) => ({ ...p, mode: opt.key }))}
                          style={{ flex: 1, padding: "10px 12px", borderRadius: 10, border: `1px solid ${pMode === opt.key ? th.accent : th.border}44`, background: pMode === opt.key ? `${th.accent}15` : "transparent", cursor: "pointer", textAlign: "center", transition: "all 0.15s" }}>
                          <div style={{ fontSize: 12, fontWeight: 600, color: pMode === opt.key ? th.accent : th.text, fontFamily: "-apple-system, sans-serif" }}>{opt.label}</div>
                          <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2, fontFamily: "-apple-system, sans-serif" }}>{opt.desc}</div>
                        </button>
                      ))}
                    </div>

                    {pMode !== "auto" && (
                      <>
                        <div style={{ fontSize: 12, fontWeight: 600, color: th.text, marginBottom: 8, fontFamily: "-apple-system, sans-serif" }}>Column Mapping {pMode === "evtx" ? "(EVTX)" : "(Registry)"}</div>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px 12px", marginBottom: 8 }}>
                          {(pMode === "evtx"
                            ? [["eventId","Event ID"],["channel","Channel"],["ts","Timestamp"],["computer","Computer"],["user","User"]]
                            : [["keyPath","Key Path"],["valueName","Value Name"],["valueData","Value Data"],["hivePath","Hive Path"],["ts","Timestamp"]]
                          ).map(([key, label]) => (
                            <div key={key}>
                              <div style={{ fontSize: 10, color: th.textMuted, marginBottom: 3, fontFamily: "-apple-system, sans-serif" }}>{label}</div>
                              <select value={modal.columns?.[key] || ""} onChange={(e) => setModal((p) => ({ ...p, columns: { ...p.columns, [key]: e.target.value || undefined } }))}
                                style={{ ...ms.sl, width: "100%", fontSize: 11, padding: "5px 8px" }}>
                                <option value="">-- auto --</option>
                                {(ct?.headers || []).map((h) => <option key={h} value={h}>{h}</option>)}
                              </select>
                            </div>
                          ))}
                        </div>
                      </>
                    )}

                    <div style={{ padding: "12px 14px", background: `${th.accent}08`, borderRadius: 10, border: `1px solid ${th.accent}15`, marginTop: 12 }}>
                      <div style={{ fontSize: 11, color: th.textMuted, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>
                        <b style={{ color: th.text }}>EVTX mode</b> scans 22 persistence indicators: Services (7045/4697), Scheduled Tasks (4698/4699/106/129/140/200 + deletion 141, boot/logon triggers 118/119), WMI subscriptions (5861, Sysmon 19/20/21), Registry autorun (Sysmon 12/13/14), Startup folder drops (Sysmon 11), DLL hijacking (Sysmon 7), Driver loading (Sysmon 6), Process tampering (Sysmon 25). Suspicious items flagged with risk boost for non-Microsoft paths, GUID tasks, LOLBin execution, user-writable paths.
                        <br/><b style={{ color: th.text }}>Registry mode</b> scans 15 persistence locations: Run/RunOnce keys, Services, Winlogon, AppInit_DLLs, IFEO, COM objects, Shell extensions, Boot Execute, BHO, LSA packages, Print Monitors, Active Setup, Startup folders, Scheduled Tasks, Network Providers.
                      </div>
                    </div>

                    {/* Customize Rules Section */}
                    <div style={{ marginTop: 14 }}>
                      <button onClick={() => setModal((p) => ({ ...p, showRules: !p.showRules }))}
                        style={{ width: "100%", padding: "10px 14px", background: `${th.accent}08`, border: `1px solid ${th.border}33`, borderRadius: 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "space-between", transition: "all 0.15s" }}>
                        <span style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textMuted} strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                          Customize Rules
                        </span>
                        <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", display: "flex", alignItems: "center", gap: 6 }}>
                          <span>{evtxActive}/{EVTX_SUMMARIES.length} EVTX, {regActive}/{REG_SUMMARIES.length} Reg{customCount > 0 ? `, ${customCount} custom` : ""}</span>
                          <span style={{ transform: modal.showRules ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.2s", fontSize: 12 }}>&#9662;</span>
                        </span>
                      </button>

                      {modal.showRules && (
                        <div style={{ marginTop: 8, padding: "10px 12px", background: `${th.panelBg}88`, border: `1px solid ${th.border}22`, borderRadius: 10, maxHeight: 320, overflowY: "auto" }}>

                          {/* EVTX Rules */}
                          {(pMode === "evtx" || pMode === "auto") && (
                            <div style={{ marginBottom: 10 }}>
                              <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>
                                EVTX Rules ({evtxActive}/{EVTX_SUMMARIES.length})
                              </div>
                              {EVTX_SUMMARIES.map((r, i) => {
                                const key = `evtx-${i}`;
                                const off = disabledSet.has(key);
                                return (
                                  <label key={key} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", cursor: "pointer", opacity: off ? 0.45 : 1, transition: "opacity 0.15s" }}>
                                    <input type="checkbox" checked={!off} onChange={() => toggleRule(key)} style={{ accentColor: th.accent, margin: 0, flexShrink: 0 }} />
                                    <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: SEVERITY_COLORS[r.sev] + "22", color: SEVERITY_COLORS[r.sev], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 42, textAlign: "center", textTransform: "uppercase" }}>{r.sev}</span>
                                    <span style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{r.cat} — {r.name}</span>
                                    <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>EID {r.hint}</span>
                                  </label>
                                );
                              })}
                            </div>
                          )}

                          {/* Registry Rules */}
                          {(pMode === "registry" || pMode === "auto") && (
                            <div style={{ marginBottom: 10 }}>
                              <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>
                                Registry Rules ({regActive}/{REG_SUMMARIES.length})
                              </div>
                              {REG_SUMMARIES.map((r, i) => {
                                const key = `reg-${i}`;
                                const off = disabledSet.has(key);
                                return (
                                  <label key={key} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0", cursor: "pointer", opacity: off ? 0.45 : 1, transition: "opacity 0.15s" }}>
                                    <input type="checkbox" checked={!off} onChange={() => toggleRule(key)} style={{ accentColor: th.accent, margin: 0, flexShrink: 0 }} />
                                    <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: SEVERITY_COLORS[r.sev] + "22", color: SEVERITY_COLORS[r.sev], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 42, textAlign: "center", textTransform: "uppercase" }}>{r.sev}</span>
                                    <span style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{r.cat} — {r.name}</span>
                                    <span style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, monospace" }}>{r.hint}</span>
                                  </label>
                                );
                              })}
                            </div>
                          )}

                          {/* Custom Rules */}
                          {(modal.customRules || []).length > 0 && (
                            <div style={{ marginBottom: 10 }}>
                              <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontFamily: "-apple-system, sans-serif" }}>Custom Rules</div>
                              {(modal.customRules || []).map((cr, i) => (
                                <div key={`custom-${i}`} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0" }}>
                                  <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: SEVERITY_COLORS[cr.severity || "medium"] + "22", color: SEVERITY_COLORS[cr.severity || "medium"], fontWeight: 600, fontFamily: "-apple-system, sans-serif", minWidth: 42, textAlign: "center", textTransform: "uppercase" }}>{cr.severity || "med"}</span>
                                  <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: `${th.accent}22`, color: th.accent, fontWeight: 600, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase" }}>{cr.type}</span>
                                  <span style={{ fontSize: 11, color: th.text, fontFamily: "-apple-system, sans-serif", flex: 1 }}>{cr.category || "Custom"} — {cr.name || "Custom Rule"}</span>
                                  <button onClick={() => deleteCustomRule(i)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "0 4px", lineHeight: 1 }} onMouseEnter={(e) => e.currentTarget.style.color = th.danger || "#f85149"} onMouseLeave={(e) => e.currentTarget.style.color = th.textMuted}>&times;</button>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Add Custom Rule */}
                          {!modal.addingRule ? (
                            <button onClick={() => setModal((p) => ({ ...p, addingRule: pMode === "registry" ? "registry" : "evtx", newRule: {} }))}
                              style={{ ...ms.bsm, marginTop: 4, display: "flex", alignItems: "center", gap: 4 }}>
                              <span style={{ fontSize: 13, lineHeight: 1 }}>+</span> Add Custom Rule
                            </button>
                          ) : (
                            <div style={{ marginTop: 8, padding: "10px 12px", background: `${th.accent}08`, border: `1px solid ${th.accent}22`, borderRadius: 8 }}>
                              <div style={{ display: "flex", gap: 6, marginBottom: 8 }}>
                                {["evtx", "registry"].map((t) => (
                                  <button key={t} onClick={() => setModal((p) => ({ ...p, addingRule: t, newRule: { ...(p.newRule || {}), type: t } }))}
                                    style={{ padding: "3px 10px", borderRadius: 4, border: `1px solid ${modal.addingRule === t ? th.accent : th.border}44`, background: modal.addingRule === t ? `${th.accent}15` : "transparent", color: modal.addingRule === t ? th.accent : th.textMuted, fontSize: 10, fontWeight: 600, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>
                                    {t.toUpperCase()}
                                  </button>
                                ))}
                              </div>
                              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
                                <input value={(modal.newRule || {}).category || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, category: e.target.value } }))} placeholder="Category" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                <input value={(modal.newRule || {}).name || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, name: e.target.value } }))} placeholder="Rule Name" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                {modal.addingRule === "evtx" ? (
                                  <>
                                    <input value={(modal.newRule || {}).eventIds || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, eventIds: e.target.value } }))} placeholder="Event IDs (e.g. 7045,4697)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                    <input value={(modal.newRule || {}).channels || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, channels: e.target.value } }))} placeholder="Channels (e.g. system,security)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                  </>
                                ) : (
                                  <>
                                    <input value={(modal.newRule || {}).keyPathPattern || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, keyPathPattern: e.target.value } }))} placeholder="Key Path Pattern (regex)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                    <input value={(modal.newRule || {}).valueNameFilter || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, valueNameFilter: e.target.value } }))} placeholder="Value Name Filter (regex, optional)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                  </>
                                )}
                                <select value={(modal.newRule || {}).severity || "medium"} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, severity: e.target.value } }))}
                                  style={{ ...ms.sl, fontSize: 11, padding: "4px 8px" }}>
                                  <option value="critical">Critical</option>
                                  <option value="high">High</option>
                                  <option value="medium">Medium</option>
                                  <option value="low">Low</option>
                                </select>
                                {modal.addingRule === "evtx" && (
                                  <input value={(modal.newRule || {}).payloadFilter || ""} onChange={(e) => setModal((p) => ({ ...p, newRule: { ...p.newRule, payloadFilter: e.target.value } }))} placeholder="Payload regex filter (optional)" style={{ ...ms.ip, fontSize: 11, padding: "4px 8px" }} />
                                )}
                              </div>
                              <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginTop: 8 }}>
                                <button onClick={() => setModal((p) => ({ ...p, addingRule: false, newRule: {} }))} style={ms.bsm}>Cancel</button>
                                <button onClick={addCustomRule} style={{ ...ms.bsm, background: th.primaryBtn, color: "#fff", border: "none" }}>Add Rule</button>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Loading phase */}
                {phase === "loading" && (() => {
                  const prog = modal.progress || 0;
                  const pi = modal.phaseIdx || 0;
                  const plabels = ["Querying database...", "Scanning for persistence mechanisms...", "Scoring risk levels...", "Complete"];
                  return (
                    <div style={{ padding: "50px 40px 40px", textAlign: "center" }}>
                      <style>{`@keyframes paPulse{0%,100%{opacity:.35}50%{opacity:1}}`}</style>
                      <div style={{ marginBottom: 22 }}>
                        <svg width="36" height="36" viewBox="0 0 24 24" fill={(th.danger||"#f85149")+"22"} stroke={th.danger||"#f85149"} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ animation: "paPulse 1.5s ease-in-out infinite" }}>
                          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/>
                        </svg>
                      </div>
                      <div style={{ color: th.text, fontSize: 13, fontWeight: 500, marginBottom: 6, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.2px" }}>{plabels[pi]}</div>
                      <div style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif", marginBottom: 24 }}>This may take a moment for large datasets</div>
                      <div style={{ position: "relative", height: 4, background: th.border + "22", borderRadius: 2, overflow: "hidden", maxWidth: 360, margin: "0 auto 12px" }}>
                        <div style={{ position: "absolute", left: 0, top: 0, height: "100%", width: `${prog}%`, background: `linear-gradient(90deg, ${th.accent}, ${th.danger || "#f85149"})`, borderRadius: 2, transition: "width 0.25s ease-out", boxShadow: `0 0 12px ${th.accent}44` }} />
                      </div>
                      <div style={{ color: th.textDim, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>{Math.round(prog)}%</div>
                    </div>
                  );
                })()}

                {/* Results phase */}
                {phase === "results" && data && (
                  <div>
                    {/* Stats cards — uniform glass */}
                    <div style={{ display: "flex", gap: 6, marginBottom: 14 }}>
                      {[
                        { val: data.stats.total, label: "total found" },
                        { val: data.stats.bySeverity?.critical || 0, label: "critical" },
                        { val: data.stats.bySeverity?.high || 0, label: "high" },
                        { val: data.stats.suspicious || 0, label: "suspicious", danger: true },
                        { val: data.stats.categoriesFound || 0, label: "categories" },
                      ].map((c, i) => (
                        <div key={i} style={{ flex: 1, textAlign: "center", padding: "10px 6px 8px", background: `linear-gradient(160deg, ${th.panelBg}cc, ${th.modalBg}88)`, backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)", borderRadius: 10, border: `1px solid ${th.border}33` }}>
                          <div style={{ fontSize: 22, fontWeight: 700, color: c.danger && c.val > 0 ? (th.danger || "#f85149") : th.text, fontFamily: "-apple-system, sans-serif", letterSpacing: "-0.5px", lineHeight: 1 }}>{c.val}</div>
                          <div style={{ fontSize: 9, color: c.danger && c.val > 0 ? (th.danger || "#f85149") + "bb" : th.textMuted, marginTop: 3, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 500 }}>{c.label}</div>
                        </div>
                      ))}
                    </div>

                    {/* Filter bar */}
                    <div style={{ display: "flex", gap: 8, marginBottom: 12, alignItems: "center" }}>
                      <input type="text" placeholder="Search results..." value={searchText} onChange={(e) => setModal((p) => ({ ...p, searchText: e.target.value }))}
                        style={{ ...ms.si, flex: 1, fontSize: 11, padding: "5px 10px" }} />
                      <select value={severityFilter} onChange={(e) => setModal((p) => ({ ...p, severityFilter: e.target.value }))}
                        style={{ ...ms.sl, fontSize: 11, padding: "5px 8px", minWidth: 90 }}>
                        <option value="all">All Severity</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                      </select>
                      <select value={categoryFilter} onChange={(e) => setModal((p) => ({ ...p, categoryFilter: e.target.value }))}
                        style={{ ...ms.sl, fontSize: 11, padding: "5px 8px", minWidth: 120 }}>
                        <option value="all">All Categories</option>
                        {allCategories.map((c) => <option key={c} value={c}>{c}</option>)}
                      </select>
                    </div>

                    {/* View tabs */}
                    <div style={{ display: "flex", gap: 8, marginBottom: 14, alignItems: "center" }}>
                      <div style={{ display: "flex", gap: 0, background: th.border + "22", borderRadius: 8, padding: 2, width: "fit-content" }}>
                        {["grouped", "timeline", "table"].map((tab) => (
                          <button key={tab} onClick={() => setModal((p) => ({ ...p, viewTab: tab }))}
                            style={{ padding: "5px 16px", fontSize: 11, fontWeight: viewTab === tab ? 600 : 400, fontFamily: "-apple-system, sans-serif", background: viewTab === tab ? th.accent + "20" : "transparent", color: viewTab === tab ? th.accent : th.textMuted, border: "none", borderRadius: 6, cursor: "pointer", textTransform: "capitalize", transition: "all 0.15s" }}>{tab}</button>
                        ))}
                      </div>
                      <div style={{ display: "flex", gap: 4, marginLeft: "auto", alignItems: "center" }}>
                        <button onClick={() => {
                          setModal((p) => {
                            const s = new Set(p.checkedItems || []);
                            filteredItems.forEach((i) => s.add(persistItemKey(i)));
                            return { ...p, checkedItems: s };
                          });
                        }} style={{ padding: "3px 8px", fontSize: 10, background: "transparent", color: th.accent, border: `1px solid ${th.accent}33`, borderRadius: 5, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Select All ({filteredItems.length})</button>
                        {checkedItems.size > 0 && <button onClick={() => setModal((p) => ({ ...p, checkedItems: new Set() }))} style={{ padding: "3px 8px", fontSize: 10, background: "transparent", color: th.textMuted, border: `1px solid ${th.border}`, borderRadius: 5, cursor: "pointer", fontFamily: "-apple-system, sans-serif" }}>Clear ({checkedItems.size})</button>}
                      </div>
                    </div>

                    {filteredItems.length === 0 && (
                      <div style={{ textAlign: "center", padding: "40px 20px", color: th.textMuted, fontSize: 13, fontFamily: "-apple-system, sans-serif" }}>
                        No persistence mechanisms found{searchText || severityFilter !== "all" || categoryFilter !== "all" ? " matching filters" : ""}
                      </div>
                    )}

                    {/* Grouped view */}
                    {viewTab === "grouped" && categories.map((cat) => (
                      <div key={cat} style={{ marginBottom: 10 }}>
                        <button onClick={() => setModal((p) => {
                          const s = new Set(p.collapsedCats || []);
                          s.has(cat) ? s.delete(cat) : s.add(cat);
                          return { ...p, collapsedCats: s };
                        })} style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "8px 12px", background: `linear-gradient(135deg, ${th.panelBg}, ${th.modalBg})`, border: `1px solid ${th.border}33`, borderRadius: 8, cursor: "pointer", color: th.text }}>
                          <span style={{ fontSize: 10, color: th.textMuted, transition: "transform 0.2s", transform: collapsedCats.has(cat) ? "rotate(-90deg)" : "rotate(0deg)" }}>&#9660;</span>
                          <span style={{ fontSize: 12, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{cat}</span>
                          <span style={{ fontSize: 10, padding: "1px 8px", borderRadius: 10, background: th.accent + "20", color: th.accent, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{grouped[cat].length}</span>
                        </button>
                        {!collapsedCats.has(cat) && (
                          <div style={{ marginTop: 4, display: "flex", flexDirection: "column", gap: 3 }}>
                            {grouped[cat].slice(0, 200).map((item, idx) => (
                              <div key={idx} onClick={() => {
                                if (item.rowid && data.columns) {
                                  const eidCol = data.columns.eventId || data.columns.keyPath;
                                  if (eidCol) {
                                    const cf = { ...(ct.columnFilters || {}) };
                                    if (item.mode === "evtx") { const eid = item.source.match(/EventID (\d+)/)?.[1]; if (eid) cf[eidCol] = eid; }
                                    else if (item.details?.keyPath) { const kpCol = data.columns.keyPath; if (kpCol) cf[kpCol] = item.details.keyPath.split("\\").pop(); }
                                    up("columnFilters", cf);
                                  }
                                }
                                setModal(null);
                              }}
                                style={{ display: "flex", alignItems: "flex-start", gap: 8, padding: "8px 12px", borderRadius: 8, border: `1px solid ${th.border}22`, borderLeft: `3px solid ${SEVERITY_COLORS[item.severity] || th.textMuted}`, cursor: "pointer", transition: "background 0.1s", background: "transparent" }}
                                onMouseEnter={(e) => e.currentTarget.style.background = `${th.accent}08`}
                                onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                                <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 4, background: (SEVERITY_COLORS[item.severity] || th.textMuted) + "20", color: SEVERITY_COLORS[item.severity] || th.textMuted, fontWeight: 700, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", flexShrink: 0, marginTop: 1 }}>{item.severity}</span>
                                {item.isSuspicious && <span title={item.suspiciousReasons?.join(", ")} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.danger || "#f85149"}22`, color: th.danger || "#f85149", fontWeight: 700, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", flexShrink: 0, marginTop: 1 }}>SUSPICIOUS</span>}
                                {item.rmmTool && <span title="Remote Management tool installed — commonly used for persistence by threat actors (seen in 7/11 recent DFIR reports)" style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: "#f0883e22", color: "#f0883e", fontWeight: 700, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", flexShrink: 0, marginTop: 1 }}>RMM</span>}
                                <div style={{ flex: 1, minWidth: 0 }}>
                                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                                    <span style={{ fontSize: 12, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{item.name}</span>
                                    <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "SF Mono, Menlo, monospace", flexShrink: 0 }}>{item.timestamp ? String(item.timestamp).substring(0, 19) : ""}</span>
                                  </div>
                                  {/* Artifact + Command as prominent fields */}
                                  {(item.artifact || item.command) && (
                                    <div style={{ marginTop: 3, display: "flex", flexDirection: "column", gap: 1 }}>
                                      {item.artifact && <div style={{ fontSize: 10, fontFamily: "SF Mono, Menlo, monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}><span style={{ color: th.accent, fontWeight: 600 }}>artifact: </span><span style={{ color: item.isSuspicious ? (th.danger || "#f85149") : th.text, fontWeight: item.isSuspicious ? 600 : 400 }}>{item.artifact}</span></div>}
                                      {item.command && <div style={{ fontSize: 10, fontFamily: "SF Mono, Menlo, monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}><span style={{ color: th.accent, fontWeight: 600 }}>command: </span><span style={{ color: th.textMuted }}>{item.command}</span></div>}
                                    </div>
                                  )}
                                  {/* Additional extracted details */}
                                  {item.details && Object.keys(item.details).length > 0 && (
                                    <div style={{ marginTop: 2, display: "flex", flexWrap: "wrap", gap: "1px 10px" }}>
                                      {Object.entries(item.details).filter(([k, v]) => v && !["taskName","serviceName","targetObject","targetFilename","name","imageLoaded","executable","command","serviceFile","imagePath","image","query","destination","details","keyPath","valueData"].includes(k)).slice(0, 3).map(([k, v]) => (
                                        <div key={k} style={{ fontSize: 10, fontFamily: "SF Mono, Menlo, monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "100%" }}>
                                          <span style={{ color: th.accent + "aa", fontWeight: 500 }}>{k}: </span>
                                          <span style={{ color: th.textDim }}>{String(v).substring(0, 120)}</span>
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                  {(item.computer || item.user || item.source) && <div style={{ fontSize: 10, color: th.textDim, fontFamily: "-apple-system, sans-serif", marginTop: 2 }}>{[item.computer, item.user, item.source, item.isSuspicious ? item.suspiciousReasons.join(", ") : null].filter(Boolean).join(" | ")}</div>}
                                </div>
                                <span style={{ fontSize: 10, fontWeight: 700, color: item.riskScore >= 8 ? "#f85149" : item.riskScore >= 6 ? "#f0883e" : th.textMuted, fontFamily: "-apple-system, sans-serif", flexShrink: 0, marginTop: 1 }}>{item.riskScore}/10</span>
                                <input type="checkbox" checked={isChecked(item)} onChange={(e) => toggleCheck(item, e)} onClick={(e) => e.stopPropagation()}
                                  style={{ width: 14, height: 14, flexShrink: 0, marginTop: 2, cursor: "pointer", accentColor: th.accent }} />
                              </div>
                            ))}
                            {grouped[cat].length > 200 && <div style={{ padding: "6px 12px", fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif", fontStyle: "italic" }}>...and {grouped[cat].length - 200} more</div>}
                          </div>
                        )}
                      </div>
                    ))}

                    {/* Timeline view */}
                    {viewTab === "timeline" && (() => {
                      const tlCols = [
                        { key: "timestamp", label: "Timestamp", dw: 160 },
                        { key: "severity", label: "Severity", dw: 75 },
                        { key: "name", label: "Detection", dw: 170 },
                        { key: "artifact", label: "Artifact", dw: 250 },
                        { key: "command", label: "Command/Path", dw: 450 },
                      ];
                      const tlWidths = modal.tlColWidths || {};
                      const gtlw = (k) => tlWidths[k] || tlCols.find((c) => c.key === k)?.dw || 120;
                      const onTlResize = (colKey, e) => {
                        e.preventDefault(); e.stopPropagation();
                        const startX = e.clientX, startW = gtlw(colKey);
                        document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
                        const onMove = (ev) => setModal((p) => ({ ...p, tlColWidths: { ...(p.tlColWidths || {}), [colKey]: Math.max(50, startW + ev.clientX - startX) } }));
                        const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                        window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                      };
                      // Sort (default by timestamp asc, click header to change)
                      const tlSortCol = modal.tlSortCol || "timestamp";
                      const tlSortDir = modal.tlSortDir || "asc";
                      const toggleTlSort = (col) => setModal((p) => ({ ...p, tlSortCol: col, tlSortDir: p.tlSortCol === col && p.tlSortDir === "asc" ? "desc" : "asc" }));
                      // Column filters (shared tableColFilters state)
                      const colFilters = modal.tableColFilters || {};
                      const tlFiltered = filteredItems.filter((item) => {
                        for (const [col, allowed] of Object.entries(colFilters)) {
                          if (!allowed || allowed.length === 0) continue;
                          const val = String(item[col] ?? "");
                          if (!allowed.includes(val)) return false;
                        }
                        return true;
                      });
                      const sorted = [...tlFiltered].sort((a, b) => {
                        const av = a[tlSortCol] ?? "", bv = b[tlSortCol] ?? "";
                        const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
                        return tlSortDir === "desc" ? -cmp : cmp;
                      });
                      const openTlFilter = (colKey, e) => {
                        e.stopPropagation();
                        const rect = e.currentTarget.getBoundingClientRect();
                        const counts = {};
                        for (const item of filteredItems) { const v = String(item[colKey] ?? ""); counts[v] = (counts[v] || 0) + 1; }
                        const allVals = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
                        const current = colFilters[colKey];
                        const selected = new Set(current && current.length > 0 ? current : allVals);
                        setModal((p) => ({ ...p, colFilterOpen: colKey, colFilterPos: { x: rect.left, y: rect.bottom + 2 }, colFilterVals: allVals, colFilterCounts: counts, colFilterSel: selected, colFilterSearch: "", colFilterX: null, colFilterY: null }));
                      };
                      const filterOpen = modal.colFilterOpen;
                      const filterPos = modal.colFilterPos || {};
                      const filterVals = modal.colFilterVals || [];
                      const filterCounts = modal.colFilterCounts || {};
                      const filterSel = modal.colFilterSel || new Set();
                      const filterSearch = modal.colFilterSearch || "";
                      const displayVals = filterSearch ? filterVals.filter((v) => v.toLowerCase().includes(filterSearch.toLowerCase())) : filterVals;
                      const tlTotalW = 20 + 26 + tlCols.reduce((s, c) => s + gtlw(c.key), 0) + tlCols.length * 8;
                      const activeFilterCount = Object.values(colFilters).filter((v) => v && v.length > 0).length;
                      return (
                      <div style={{ position: "relative", paddingLeft: 20 }}>
                        <div style={{ position: "absolute", left: 6, top: 0, bottom: 0, width: 2, background: th.border + "33" }} />
                        {/* Active filter indicator */}
                        {activeFilterCount > 0 && (
                          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", marginBottom: 6, background: `${th.accent}11`, borderRadius: 6, fontSize: 10, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>
                            <span style={{ fontWeight: 600 }}>Filter active ({activeFilterCount} column{activeFilterCount > 1 ? "s" : ""})</span>
                            <span style={{ fontSize: 10, color: th.textMuted }}>— {tlFiltered.length} of {filteredItems.length} items</span>
                            <button onClick={() => setModal((p) => ({ ...p, tableColFilters: {} }))} style={{ marginLeft: "auto", padding: "1px 8px", fontSize: 9, background: th.accent, color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600 }}>Clear All</button>
                          </div>
                        )}
                        {/* Header */}
                        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0", borderBottom: `1px solid ${th.border}`, marginBottom: 2, position: "sticky", top: 0, zIndex: 2, background: th.modalBg, minWidth: tlTotalW }}>
                          <input type="checkbox" checked={sorted.length > 0 && sorted.slice(0, 500).every((i) => isChecked(i))} onChange={() => {
                            const visible = sorted.slice(0, 500);
                            const allChecked = visible.every((i) => isChecked(i));
                            setModal((p) => {
                              const s = new Set(p.checkedItems || []);
                              if (allChecked) { visible.forEach((i) => s.delete(persistItemKey(i))); }
                              else { visible.forEach((i) => s.add(persistItemKey(i))); }
                              return { ...p, checkedItems: s };
                            });
                          }} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent, flexShrink: 0 }} title={sorted.length > 0 && sorted.slice(0, 500).every((i) => isChecked(i)) ? "Deselect all" : "Select all visible"} />
                          {tlCols.map((col) => (
                            <div key={col.key} style={{ width: gtlw(col.key), minWidth: 50, flexShrink: 0, display: "flex", alignItems: "center", position: "relative", userSelect: "none", gap: 3 }}>
                              <span onClick={() => toggleTlSort(col.key)} style={{ fontSize: 10, fontWeight: 600, color: tlSortCol === col.key ? th.accent : th.textMuted, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: 0.5, cursor: "pointer", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                {col.label}{tlSortCol === col.key ? (tlSortDir === "asc" ? " ▲" : " ▼") : ""}
                              </span>
                              <span style={{ cursor: "pointer", fontSize: 7, color: colFilters[col.key] ? th.accent : th.textMuted + "66", flexShrink: 0, marginLeft: "auto", paddingRight: 8 }}
                                onClick={(e) => openTlFilter(col.key, e)}>▼</span>
                              <div onMouseDown={(e) => onTlResize(col.key, e)} style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 6, cursor: "col-resize" }}>
                                <div style={{ position: "absolute", right: 2, top: 2, bottom: 2, width: 1, background: th.border }} />
                              </div>
                            </div>
                          ))}
                        </div>
                        {/* Rows */}
                        {sorted.slice(0, 500).map((item, idx) => (
                          <div key={idx} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0", cursor: "pointer", position: "relative", background: isSelPersist(item) ? `${th.accent}14` : isChecked(item) ? `${th.accent}0a` : "transparent", minWidth: tlTotalW }}
                            onClick={() => toggleSelPersist(item)}
                            onMouseEnter={(e) => { if (!isSelPersist(item) && !isChecked(item)) e.currentTarget.style.background = `${th.accent}08`; }}
                            onMouseLeave={(e) => { if (!isSelPersist(item)) e.currentTarget.style.background = isChecked(item) ? `${th.accent}0a` : "transparent"; }}>
                            <div style={{ position: "absolute", left: -17, width: 8, height: 8, borderRadius: 4, background: SEVERITY_COLORS[item.severity] || th.textMuted, border: `2px solid ${th.modalBg}`, zIndex: 1 }} />
                            <input type="checkbox" checked={isChecked(item)} onChange={(e) => toggleCheck(item, e)} onClick={(e) => e.stopPropagation()} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent, flexShrink: 0 }} />
                            <span style={{ width: gtlw("timestamp"), minWidth: 50, fontSize: 10, color: th.textMuted, fontFamily: "SF Mono, Menlo, monospace", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.timestamp ? String(item.timestamp).substring(0, 19) : "—"}</span>
                            <span style={{ width: gtlw("severity"), minWidth: 50, fontSize: 9, flexShrink: 0 }}>
                              <span style={{ padding: "1px 5px", borderRadius: 3, background: (SEVERITY_COLORS[item.severity] || th.textMuted) + "20", color: SEVERITY_COLORS[item.severity] || th.textMuted, fontWeight: 700, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase" }}>{item.severity.substring(0, 4)}</span>
                            </span>
                            <span style={{ width: gtlw("name"), minWidth: 50, fontSize: 11, fontWeight: 500, color: th.text, fontFamily: "-apple-system, sans-serif", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              {item.name}{item.isSuspicious && <span style={{ fontSize: 7, padding: "1px 4px", marginLeft: 4, borderRadius: 2, background: `${th.danger || "#f85149"}22`, color: th.danger || "#f85149", fontWeight: 700, textTransform: "uppercase" }}>!</span>}{item.rmmTool && <span title="Remote Management tool — common persistence mechanism" style={{ fontSize: 7, padding: "1px 4px", marginLeft: 4, borderRadius: 2, background: "#f0883e22", color: "#f0883e", fontWeight: 700, textTransform: "uppercase" }}>RMM</span>}
                            </span>
                            <span title={item.artifact || ""} style={{ width: gtlw("artifact"), minWidth: 50, fontSize: 10, color: item.isSuspicious ? (th.danger || "#f85149") : th.textMuted, fontWeight: item.isSuspicious ? 500 : 400, fontFamily: "SF Mono, Menlo, monospace", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.artifact || ""}</span>
                            <span title={item.command || item.detailsSummary || ""} style={{ width: gtlw("command"), minWidth: 50, fontSize: 10, color: th.textDim, fontFamily: "SF Mono, Menlo, monospace", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.command || item.detailsSummary || ""}</span>
                          </div>
                        ))}
                        {sorted.length > 500 && <div style={{ padding: "8px 0 4px 10px", fontSize: 10, color: th.textMuted, fontStyle: "italic" }}>Showing first 500 of {sorted.length}</div>}
                        {sorted.length === 0 && <div style={{ padding: "20px 10px", fontSize: 11, color: th.textMuted, textAlign: "center", fontFamily: "-apple-system, sans-serif" }}>No items match current filters</div>}
                        {/* Column filter dropdown popup */}
                        {filterOpen && (
                          <>
                            <div style={{ position: "fixed", inset: 0, zIndex: 998 }} onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))} />
                            <div style={{ position: "fixed", left: modal.colFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340), top: modal.colFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440), width: modal.colFilterW || 320, height: modal.colFilterH || 420, background: th.modalBg, border: `1px solid ${th.border}`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 999, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                              <div style={{ padding: "8px 10px", borderBottom: `1px solid ${th.border}33`, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "grab", userSelect: "none", flexShrink: 0 }}
                                onMouseDown={(e) => {
                                  e.preventDefault();
                                  const startX = e.clientX, startY = e.clientY;
                                  const startLeft = modal.colFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340);
                                  const startTop = modal.colFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440);
                                  document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                                  const onMove = (ev) => setModal((p) => ({ ...p, colFilterX: startLeft + ev.clientX - startX, colFilterY: startTop + ev.clientY - startY }));
                                  const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                                  window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                                }}>
                                <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "SF Mono, Menlo, monospace" }}>FILTER — {(tlCols.find((c) => c.key === filterOpen)?.label || filterOpen).toUpperCase()}</span>
                                <span style={{ cursor: "pointer", color: th.textMuted, fontSize: 14, lineHeight: 1 }} onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))}>×</span>
                              </div>
                              <div style={{ padding: "6px 10px", flexShrink: 0 }}>
                                <input type="text" placeholder="Search values..." value={filterSearch} onChange={(e) => setModal((p) => ({ ...p, colFilterSearch: e.target.value }))}
                                  style={{ width: "100%", boxSizing: "border-box", padding: "5px 8px", fontSize: 11, background: th.panelBg, border: `1px solid ${th.border}55`, borderRadius: 4, color: th.text, outline: "none", fontFamily: "SF Mono, Menlo, monospace" }}
                                  autoFocus />
                              </div>
                              <div style={{ padding: "2px 10px 6px", display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                                <button onClick={() => setModal((p) => ({ ...p, colFilterSel: new Set(filterVals) }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                                <button onClick={() => setModal((p) => ({ ...p, colFilterSel: new Set() }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                                <span style={{ marginLeft: "auto", fontSize: 10, color: th.textMuted }}>{filterVals.length} values</span>
                              </div>
                              <div style={{ flex: 1, overflow: "auto", padding: "0 6px", minHeight: 0 }}>
                                {displayVals.slice(0, 1000).map((v) => (
                                  <div key={v} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 4px", borderRadius: 3, cursor: "pointer" }}
                                    onClick={() => setModal((p) => { const s = new Set(p.colFilterSel || []); s.has(v) ? s.delete(v) : s.add(v); return { ...p, colFilterSel: s }; })}
                                    onMouseEnter={(e) => e.currentTarget.style.background = `${th.accent}0a`}
                                    onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                                    <input type="checkbox" checked={filterSel.has(v)} readOnly style={{ width: 13, height: 13, accentColor: th.accent, cursor: "pointer", flexShrink: 0 }} />
                                    <span style={{ fontSize: 11, color: th.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "SF Mono, Menlo, monospace" }}>{v || "(empty)"}</span>
                                    <span style={{ fontSize: 10, color: th.textMuted, flexShrink: 0 }}>{filterCounts[v]}</span>
                                  </div>
                                ))}
                              </div>
                              <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}33`, display: "flex", gap: 6, justifyContent: "flex-end", flexShrink: 0 }}>
                                <button onClick={() => setModal((p) => { const cf = { ...(p.tableColFilters || {}) }; delete cf[filterOpen]; return { ...p, tableColFilters: cf, colFilterOpen: null }; })}
                                  style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Reset</button>
                                <button onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))}
                                  style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Cancel</button>
                                <button onClick={() => setModal((p) => ({ ...p, tableColFilters: { ...(p.tableColFilters || {}), [filterOpen]: [...(p.colFilterSel || [])] }, colFilterOpen: null }))}
                                  style={{ padding: "4px 12px", fontSize: 10, background: th.accent, border: "none", borderRadius: 4, color: "#fff", cursor: "pointer", fontWeight: 600 }}>Apply</button>
                              </div>
                              <div onMouseDown={(e) => {
                                e.preventDefault(); e.stopPropagation();
                                const startX = e.clientX, startY = e.clientY, startW = modal.colFilterW || 320, startH = modal.colFilterH || 420;
                                document.body.style.cursor = "nwse-resize"; document.body.style.userSelect = "none";
                                const onMove = (ev) => setModal((p) => ({ ...p, colFilterW: Math.max(240, startW + ev.clientX - startX), colFilterH: Math.max(250, startH + ev.clientY - startY) }));
                                const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                                window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                              }} style={{ position: "absolute", right: 0, bottom: 0, width: 16, height: 16, cursor: "nwse-resize", zIndex: 2 }}>
                                <svg width="8" height="8" viewBox="0 0 10 10" style={{ position: "absolute", right: 3, bottom: 3, opacity: 0.3 }}><path d="M9 1L1 9M9 5L5 9M9 9L9 9" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round"/></svg>
                              </div>
                            </div>
                          </>
                        )}
                      </div>
                    ); })()}

                    {/* Table view */}
                    {viewTab === "table" && (() => {
                      const sortCol = modal.sortCol || "riskScore";
                      const sortDir = modal.sortDir || "desc";
                      const colFilters = modal.tableColFilters || {};
                      // Apply per-column checkbox filters
                      const tableFiltered = filteredItems.filter((item) => {
                        for (const [col, allowed] of Object.entries(colFilters)) {
                          if (!allowed || allowed.length === 0) continue;
                          const val = String(item[col] ?? "");
                          if (!allowed.includes(val)) return false;
                        }
                        return true;
                      });
                      const sorted = [...tableFiltered].sort((a, b) => {
                        const av = a[sortCol] ?? "", bv = b[sortCol] ?? "";
                        const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
                        return sortDir === "desc" ? -cmp : cmp;
                      });
                      const toggleSort = (col) => setModal((p) => ({ ...p, sortCol: col, sortDir: p.sortCol === col && p.sortDir === "asc" ? "desc" : "asc" }));
                      const cw = modal.colWidths || {};
                      const colDefs = [
                        { key: "riskScore", label: "Risk", dw: 50 },
                        { key: "severity", label: "Severity", dw: 70 },
                        { key: "category", label: "Category", dw: 110 },
                        { key: "name", label: "Detection", dw: 140 },
                        { key: "artifact", label: "Artifact", dw: 170 },
                        { key: "command", label: "Command/Path", dw: 180 },
                        { key: "timestamp", label: "Timestamp", dw: 145 },
                        { key: "computer", label: "Computer", dw: 90 },
                        { key: "user", label: "User", dw: 90 },
                        { key: "source", label: "Source", dw: 80 },
                      ];
                      const gw = (k) => cw[k] || colDefs.find((c) => c.key === k)?.dw || 100;
                      // Column ordering via drag-and-drop
                      const savedOrder = modal.colOrder || colDefs.map((c) => c.key);
                      // Ensure all colDefs are present (append any missing)
                      const colOrder = [...savedOrder.filter((k) => colDefs.some((c) => c.key === k)), ...colDefs.filter((c) => !savedOrder.includes(c.key)).map((c) => c.key)];
                      const orderedCols = colOrder.map((k) => colDefs.find((c) => c.key === k)).filter(Boolean);
                      const onColDragStart = (e, key) => { e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", key); setModal((p) => ({ ...p, dragCol: key })); };
                      const onColDrop = (e, targetKey) => {
                        e.preventDefault();
                        const fromKey = e.dataTransfer.getData("text/plain");
                        if (fromKey && fromKey !== targetKey) {
                          setModal((p) => {
                            const order = [...(p.colOrder || colDefs.map((c) => c.key))];
                            const fi = order.indexOf(fromKey), ti = order.indexOf(targetKey);
                            if (fi >= 0 && ti >= 0) { order.splice(fi, 1); order.splice(ti, 0, fromKey); }
                            return { ...p, colOrder: order, dragCol: null };
                          });
                        }
                      };
                      const onColResize = (colKey, e) => {
                        e.preventDefault(); e.stopPropagation();
                        const startX = e.clientX, startW = gw(colKey);
                        document.body.style.cursor = "col-resize"; document.body.style.userSelect = "none";
                        const onMove = (ev) => setModal((p) => ({ ...p, colWidths: { ...(p.colWidths || {}), [colKey]: Math.max(40, startW + ev.clientX - startX) } }));
                        const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                        window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                      };
                      // Column filter dropdown
                      const openColFilter = (colKey, e) => {
                        e.stopPropagation();
                        const rect = e.currentTarget.getBoundingClientRect();
                        // Compute unique values with counts from filteredItems (before column filters)
                        const counts = {};
                        for (const item of filteredItems) {
                          const v = String(item[colKey] ?? "");
                          counts[v] = (counts[v] || 0) + 1;
                        }
                        const allVals = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
                        const current = colFilters[colKey];
                        const selected = new Set(current && current.length > 0 ? current : allVals);
                        setModal((p) => ({ ...p, colFilterOpen: colKey, colFilterPos: { x: rect.left, y: rect.bottom + 2 }, colFilterVals: allVals, colFilterCounts: counts, colFilterSel: selected, colFilterSearch: "" }));
                      };
                      const renderCell = (item, col) => {
                        if (col.key === "riskScore") return <span style={{ fontWeight: 700, color: item.riskScore >= 8 ? "#f85149" : item.riskScore >= 6 ? "#f0883e" : th.textMuted, display: "flex", alignItems: "center", gap: 3 }}>{item.riskScore}{item.isSuspicious && <span title={item.suspiciousReasons?.join(", ")} style={{ fontSize: 8, color: "#f85149" }}>!</span>}</span>;
                        if (col.key === "severity") return <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 3, background: (SEVERITY_COLORS[item.severity] || th.textMuted) + "20", color: SEVERITY_COLORS[item.severity] || th.textMuted, fontWeight: 700, textTransform: "uppercase" }}>{item.severity}</span>;
                        if (col.key === "name") return <span style={{ display: "flex", alignItems: "center", gap: 4 }}>{item.name}{item.rmmTool && <span title="Remote Management tool — common persistence mechanism" style={{ fontSize: 7, padding: "1px 4px", borderRadius: 2, background: "#f0883e22", color: "#f0883e", fontWeight: 700, textTransform: "uppercase" }}>RMM</span>}</span>;
                        if (col.key === "timestamp") return item.timestamp ? String(item.timestamp).substring(0, 19) : "";
                        return item[col.key] || "";
                      };
                      const filterOpen = modal.colFilterOpen;
                      const filterPos = modal.colFilterPos || {};
                      const filterVals = modal.colFilterVals || [];
                      const filterCounts = modal.colFilterCounts || {};
                      const filterSel = modal.colFilterSel || new Set();
                      const filterSearch = modal.colFilterSearch || "";
                      const displayVals = filterSearch ? filterVals.filter((v) => v.toLowerCase().includes(filterSearch.toLowerCase())) : filterVals;
                      return (
                        <div style={{ border: `1px solid ${th.border}22`, borderRadius: 8, overflow: "hidden", position: "relative" }}>
                          <div style={{ overflow: "auto", maxHeight: 440 }}>
                            <div style={{ minWidth: "fit-content" }}>
                              <div style={{ display: "flex", background: th.panelBg, borderBottom: `1px solid ${th.border}33`, position: "sticky", top: 0, zIndex: 2 }}>
                                <div style={{ width: 30, flexShrink: 0, padding: "6px 8px", display: "flex", alignItems: "center" }}>
                                  <input type="checkbox" checked={sorted.length > 0 && sorted.slice(0, 500).every((i) => isChecked(i))} onChange={(e) => {
                                    e.stopPropagation();
                                    setModal((p) => {
                                      const s = new Set(p.checkedItems || []);
                                      const allChecked = sorted.slice(0, 500).every((i) => s.has(i.rowid + "|" + i.name + "|" + i.timestamp));
                                      sorted.slice(0, 500).forEach((i) => { const k = i.rowid + "|" + i.name + "|" + i.timestamp; allChecked ? s.delete(k) : s.add(k); });
                                      return { ...p, checkedItems: s };
                                    });
                                  }} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                                </div>
                                {orderedCols.map((c) => (
                                  <div key={c.key} draggable onDragStart={(e) => onColDragStart(e, c.key)} onDragOver={(e) => e.preventDefault()} onDrop={(e) => onColDrop(e, c.key)} onDragEnd={() => setModal((p) => ({ ...p, dragCol: null }))}
                                    style={{ width: gw(c.key), flexShrink: 0, padding: "6px 8px", fontSize: 10, fontWeight: 600, color: sortCol === c.key ? th.accent : th.textMuted, cursor: "grab", fontFamily: "-apple-system, sans-serif", userSelect: "none", position: "relative", opacity: modal.dragCol === c.key ? 0.4 : 1, transition: "opacity 0.15s", display: "flex", alignItems: "center", gap: 2 }}>
                                    <span onClick={() => toggleSort(c.key)} style={{ cursor: "pointer", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                      {c.label}{sortCol === c.key ? (sortDir === "asc" ? " ▲" : " ▼") : ""}
                                    </span>
                                    <span style={{ cursor: "pointer", fontSize: 7, color: colFilters[c.key] ? th.accent : th.textMuted + "66", flexShrink: 0, marginLeft: "auto" }}
                                      onClick={(e) => { e.stopPropagation(); openColFilter(c.key, e); }}>▼</span>
                                    <div onMouseDown={(e) => onColResize(c.key, e)} style={{ position: "absolute", right: -3, top: 0, bottom: 0, width: 6, cursor: "col-resize", zIndex: 2 }}
                                      onClick={(e) => e.stopPropagation()}>
                                      <div style={{ position: "absolute", right: 2, top: 4, bottom: 4, width: 2, borderRadius: 1, background: th.border + "55", transition: "background 0.15s" }}
                                        onMouseEnter={(e) => e.currentTarget.style.background = th.accent}
                                        onMouseLeave={(e) => e.currentTarget.style.background = th.border + "55"} />
                                    </div>
                                  </div>
                                ))}
                              </div>
                              {sorted.slice(0, 500).map((item, idx) => {
                                const isSelItem = isSelPersist(item);
                                return (
                                <div key={idx} style={{ display: "flex", borderBottom: `1px solid ${th.border}11`, borderLeft: item.isSuspicious ? `3px solid ${th.danger || "#f85149"}` : "3px solid transparent", transition: "background 0.1s", background: isSelItem ? `${th.accent}14` : isChecked(item) ? `${th.accent}0a` : item.isSuspicious ? `${(th.danger || "#f85149")}06` : "transparent", cursor: "pointer" }}
                                  onClick={() => toggleSelPersist(item)}
                                  onMouseEnter={(e) => { if (!isSelItem && !isChecked(item)) e.currentTarget.style.background = `${th.accent}06`; }}
                                  onMouseLeave={(e) => { if (!isSelItem) e.currentTarget.style.background = isChecked(item) ? `${th.accent}0a` : item.isSuspicious ? `${(th.danger || "#f85149")}06` : "transparent"; }}>
                                  <div style={{ width: 30, flexShrink: 0, padding: "5px 8px", display: "flex", alignItems: "center" }}>
                                    <input type="checkbox" checked={isChecked(item)} onChange={(e) => toggleCheck(item, e)} style={{ width: 13, height: 13, cursor: "pointer", accentColor: th.accent }} />
                                  </div>
                                  {orderedCols.map((col) => (
                                    <div key={col.key} title={col.key === "artifact" && item.isSuspicious ? item.suspiciousReasons?.join(", ") : undefined} style={{ width: gw(col.key), flexShrink: 0, padding: "5px 8px", fontSize: col.key === "riskScore" ? 11 : 10, color: col.key === "name" || col.key === "category" ? th.text : col.key === "artifact" && item.isSuspicious ? (th.danger || "#f85149") : th.textMuted, fontWeight: col.key === "name" ? 500 : col.key === "artifact" && item.isSuspicious ? 600 : 400, fontFamily: col.key === "artifact" || col.key === "command" || col.key === "timestamp" ? "SF Mono, Menlo, monospace" : "-apple-system, sans-serif", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                      {renderCell(item, col)}
                                    </div>
                                  ))}
                                </div>
                              ); })}
                            </div>
                          </div>
                          {sorted.length > 500 && <div style={{ padding: "6px 10px", fontSize: 10, color: th.textMuted, fontStyle: "italic", borderTop: `1px solid ${th.border}11` }}>Showing first 500 of {sorted.length}</div>}
                          {/* Column filter dropdown popup */}
                          {filterOpen && (
                            <>
                              <div style={{ position: "fixed", inset: 0, zIndex: 998 }} onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))} />
                              <div style={{ position: "fixed", left: modal.colFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340), top: modal.colFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440), width: modal.colFilterW || 320, height: modal.colFilterH || 420, background: th.modalBg, border: `1px solid ${th.border}`, borderRadius: 8, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", zIndex: 999, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                                {/* Draggable header */}
                                <div style={{ padding: "8px 10px", borderBottom: `1px solid ${th.border}33`, display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "grab", userSelect: "none", flexShrink: 0 }}
                                  onMouseDown={(e) => {
                                    e.preventDefault();
                                    const startX = e.clientX, startY = e.clientY;
                                    const startLeft = modal.colFilterX ?? Math.min(filterPos.x || 0, window.innerWidth - 340);
                                    const startTop = modal.colFilterY ?? Math.min(filterPos.y || 0, window.innerHeight - 440);
                                    document.body.style.cursor = "grabbing"; document.body.style.userSelect = "none";
                                    const onMove = (ev) => setModal((p) => ({ ...p, colFilterX: startLeft + ev.clientX - startX, colFilterY: startTop + ev.clientY - startY }));
                                    const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                                    window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                                  }}>
                                  <span style={{ fontSize: 11, fontWeight: 600, color: th.text, fontFamily: "SF Mono, Menlo, monospace" }}>FILTER — {(colDefs.find((c) => c.key === filterOpen)?.label || filterOpen).toUpperCase()}</span>
                                  <span style={{ cursor: "pointer", color: th.textMuted, fontSize: 14, lineHeight: 1 }} onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))}>×</span>
                                </div>
                                <div style={{ padding: "6px 10px", flexShrink: 0 }}>
                                  <input type="text" placeholder="Search values..." value={filterSearch} onChange={(e) => setModal((p) => ({ ...p, colFilterSearch: e.target.value }))}
                                    style={{ width: "100%", boxSizing: "border-box", padding: "5px 8px", fontSize: 11, background: th.panelBg, border: `1px solid ${th.border}55`, borderRadius: 4, color: th.text, outline: "none", fontFamily: "SF Mono, Menlo, monospace" }}
                                    autoFocus />
                                </div>
                                <div style={{ padding: "2px 10px 6px", display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                                  <button onClick={() => setModal((p) => ({ ...p, colFilterSel: new Set(filterVals) }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Select All</button>
                                  <button onClick={() => setModal((p) => ({ ...p, colFilterSel: new Set() }))} style={{ padding: "2px 8px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Clear</button>
                                  <span style={{ marginLeft: "auto", fontSize: 10, color: th.textMuted }}>{filterVals.length} values</span>
                                </div>
                                <div style={{ flex: 1, overflow: "auto", padding: "0 6px", minHeight: 0 }}>
                                  {displayVals.slice(0, 1000).map((v) => (
                                    <div key={v} style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 4px", borderRadius: 3, cursor: "pointer" }}
                                      onClick={() => setModal((p) => { const s = new Set(p.colFilterSel || []); s.has(v) ? s.delete(v) : s.add(v); return { ...p, colFilterSel: s }; })}
                                      onMouseEnter={(e) => e.currentTarget.style.background = `${th.accent}0a`}
                                      onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                                      <input type="checkbox" checked={filterSel.has(v)} readOnly style={{ width: 13, height: 13, accentColor: th.accent, cursor: "pointer", flexShrink: 0 }} />
                                      <span style={{ fontSize: 11, color: th.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "SF Mono, Menlo, monospace" }}>{v || "(empty)"}</span>
                                      <span style={{ fontSize: 10, color: th.textMuted, flexShrink: 0 }}>{filterCounts[v]}</span>
                                    </div>
                                  ))}
                                </div>
                                <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}33`, display: "flex", gap: 6, justifyContent: "flex-end", flexShrink: 0 }}>
                                  <button onClick={() => setModal((p) => { const cf = { ...(p.tableColFilters || {}) }; delete cf[filterOpen]; return { ...p, tableColFilters: cf, colFilterOpen: null }; })}
                                    style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Reset</button>
                                  <button onClick={() => setModal((p) => ({ ...p, colFilterOpen: null }))}
                                    style={{ padding: "4px 12px", fontSize: 10, background: th.panelBg, border: `1px solid ${th.border}44`, borderRadius: 4, color: th.text, cursor: "pointer" }}>Cancel</button>
                                  <button onClick={() => setModal((p) => ({ ...p, tableColFilters: { ...(p.tableColFilters || {}), [filterOpen]: [...(p.colFilterSel || [])] }, colFilterOpen: null }))}
                                    style={{ padding: "4px 12px", fontSize: 10, background: th.accent, border: "none", borderRadius: 4, color: "#fff", cursor: "pointer", fontWeight: 600 }}>Apply</button>
                                </div>
                                {/* Resize handle */}
                                <div onMouseDown={(e) => {
                                  e.preventDefault(); e.stopPropagation();
                                  const startX = e.clientX, startY = e.clientY, startW = modal.colFilterW || 320, startH = modal.colFilterH || 420;
                                  document.body.style.cursor = "nwse-resize"; document.body.style.userSelect = "none";
                                  const onMove = (ev) => setModal((p) => ({ ...p, colFilterW: Math.max(240, startW + ev.clientX - startX), colFilterH: Math.max(250, startH + ev.clientY - startY) }));
                                  const onUp = () => { document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
                                  window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
                                }} style={{ position: "absolute", right: 0, bottom: 0, width: 16, height: 16, cursor: "nwse-resize", zIndex: 2 }}>
                                  <svg width="8" height="8" viewBox="0 0 10 10" style={{ position: "absolute", right: 3, bottom: 3, opacity: 0.3 }}><path d="M9 1L1 9M9 5L5 9M9 9L9 9" stroke={th.textMuted} strokeWidth="1.5" strokeLinecap="round"/></svg>
                                </div>
                              </div>
                            </>
                          )}
                        </div>
                      );
                    })()}
                  </div>
                )}
              </div>

              {/* Event Detail Panel — shared across all views */}
              {phase === "results" && selectedPersistKey && (() => {
                const selItem = itemForKey(selectedPersistKey);
                if (!selItem) return null;
                const sevCol = SEVERITY_COLORS[selItem.severity] || th.textMuted;
                return (
                  <div style={{ borderTop: `2px solid ${sevCol}44`, background: `linear-gradient(135deg, ${sevCol}06, ${th.panelBg}ee)`, padding: "14px 16px", display: "flex", flexDirection: "column", gap: 10, flexShrink: 0, maxHeight: 280, overflow: "auto" }}>
                    {/* Header row */}
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 4, background: sevCol + "20", color: sevCol, fontWeight: 700, textTransform: "uppercase" }}>{selItem.severity}</span>
                      {selItem.isSuspicious && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.danger || "#f85149"}22`, color: th.danger || "#f85149", fontWeight: 700, textTransform: "uppercase" }}>SUSPICIOUS</span>}
                      {selItem.rmmTool && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: "#f0883e22", color: "#f0883e", fontWeight: 700, textTransform: "uppercase" }}>RMM</span>}
                      {(selItem.tags || []).filter(t => t !== "RMM Tool").map((t, i) => <span key={i} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: `${th.accent}22`, color: th.accent, fontWeight: 600, textTransform: "uppercase" }}>{t}</span>)}
                      <span style={{ fontSize: 13, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{selItem.name}</span>
                      <span style={{ fontSize: 10, color: th.textMuted, marginLeft: "auto" }}>Risk Score: <span style={{ fontWeight: 700, color: selItem.riskScore >= 8 ? "#f85149" : selItem.riskScore >= 6 ? "#f0883e" : th.textMuted }}>{selItem.riskScore}/10</span></span>
                      <button onClick={() => setModal((p) => ({ ...p, selectedPersistKey: null }))} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 14, padding: "0 4px", lineHeight: 1 }} title="Close">&times;</button>
                    </div>
                    {/* Info grid */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: "6px 16px" }}>
                      {[
                        { label: "Category", value: selItem.category },
                        { label: "Source", value: selItem.source },
                        { label: "Timestamp", value: selItem.timestamp ? String(selItem.timestamp).substring(0, 23) : "" },
                        { label: "Computer", value: selItem.computer },
                        { label: "User", value: selItem.user },
                      ].filter(f => f.value).map((f, i) => (
                        <div key={i} style={{ display: "flex", gap: 6, alignItems: "baseline" }}>
                          <span style={{ fontSize: 10, color: th.accent, fontWeight: 600, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{f.label}:</span>
                          <span style={{ fontSize: 10, color: th.text, fontFamily: "SF Mono, Menlo, monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.value}</span>
                        </div>
                      ))}
                    </div>
                    {/* Artifact + Command */}
                    {selItem.artifact && (
                      <div style={{ display: "flex", gap: 6, alignItems: "baseline" }}>
                        <span style={{ fontSize: 10, color: th.accent, fontWeight: 600, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>Artifact:</span>
                        <span style={{ fontSize: 10, color: selItem.isSuspicious ? (th.danger || "#f85149") : th.text, fontWeight: selItem.isSuspicious ? 600 : 400, fontFamily: "SF Mono, Menlo, monospace", wordBreak: "break-all" }}>{selItem.artifact}</span>
                      </div>
                    )}
                    {selItem.command && (
                      <div style={{ display: "flex", gap: 6, alignItems: "baseline" }}>
                        <span style={{ fontSize: 10, color: th.accent, fontWeight: 600, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>Command:</span>
                        <span style={{ fontSize: 10, color: th.text, fontFamily: "SF Mono, Menlo, monospace", wordBreak: "break-all", maxHeight: 60, overflow: "auto" }}>{selItem.command}</span>
                      </div>
                    )}
                    {/* All extracted details */}
                    {selItem.details && Object.keys(selItem.details).length > 0 && (
                      <div style={{ background: `${th.modalBg}cc`, borderRadius: 6, padding: "8px 10px", border: `1px solid ${th.border}22` }}>
                        <div style={{ fontSize: 9, color: th.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 4, fontFamily: "-apple-system, sans-serif" }}>Extracted Fields</div>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(250px, 1fr))", gap: "3px 16px" }}>
                          {Object.entries(selItem.details).map(([k, v]) => (
                            <div key={k} style={{ display: "flex", gap: 6, alignItems: "baseline" }}>
                              <span style={{ fontSize: 10, color: th.accent + "cc", fontWeight: 500, fontFamily: "-apple-system, sans-serif", flexShrink: 0 }}>{k}:</span>
                              <span style={{ fontSize: 10, color: th.text, fontFamily: "SF Mono, Menlo, monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={v}>{v}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {/* Suspicious reasons */}
                    {selItem.isSuspicious && selItem.suspiciousReasons?.length > 0 && (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                        {selItem.suspiciousReasons.map((r, i) => (
                          <span key={i} style={{ fontSize: 9, padding: "2px 6px", borderRadius: 4, background: `${th.danger || "#f85149"}15`, color: th.danger || "#f85149", fontFamily: "-apple-system, sans-serif" }}>{r}</span>
                        ))}
                      </div>
                    )}
                    {/* Copy button */}
                    <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                      <button onClick={() => {
                        const lines = [`[${selItem.severity.toUpperCase()}] ${selItem.name}`, `Category: ${selItem.category}`, `Source: ${selItem.source}`, `Timestamp: ${selItem.timestamp}`, `Computer: ${selItem.computer}`, `User: ${selItem.user}`];
                        if (selItem.artifact) lines.push(`Artifact: ${selItem.artifact}`);
                        if (selItem.command) lines.push(`Command: ${selItem.command}`);
                        if (selItem.details) { for (const [k, v] of Object.entries(selItem.details)) lines.push(`  ${k}: ${v}`); }
                        if (selItem.suspiciousReasons?.length) lines.push(`Suspicious: ${selItem.suspiciousReasons.join("; ")}`);
                        lines.push(`Risk Score: ${selItem.riskScore}/10`);
                        navigator.clipboard.writeText(lines.join("\n"));
                      }} style={{ fontSize: 10, padding: "3px 10px", borderRadius: 5, background: th.accent + "18", color: th.accent, border: `1px solid ${th.accent}33`, cursor: "pointer", fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>Copy Details</button>
                    </div>
                  </div>
                );
              })()}

              {/* Footer */}
              <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}22`, display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
                {phase === "config" && (
                  <div style={{ display: "flex", justifyContent: "space-between", width: "100%" }}>
                    <button onClick={() => setModal(null)} style={{ ...ms.bs, borderRadius: 8 }}>Cancel</button>
                    <button onClick={handleAnalyze} style={{ ...ms.bp, borderRadius: 8, boxShadow: `0 2px 8px ${th.accent}33` }}>Analyze</button>
                  </div>
                )}
                {phase === "loading" && (
                  <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
                    <span style={{ color: th.textMuted, fontSize: 11, fontFamily: "-apple-system, sans-serif" }}>{Math.round(modal.progress || 0)}% complete</span>
                    <button onClick={() => setModal((p) => ({ ...p, phase: "config", loading: false, progress: 0, _cancelled: true }))} style={{ ...ms.bs, borderRadius: 8 }}>Cancel</button>
                  </div>
                )}
                {phase === "results" && (
                  <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
                    <button onClick={() => setModal((p) => ({ ...p, phase: "config", data: null }))} style={{ ...ms.bs, borderRadius: 8 }}>Back</button>
                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                      {checkedItems.size > 0 && (
                        <>
                          <span style={{ fontSize: 11, color: th.accent, fontFamily: "-apple-system, sans-serif", fontWeight: 500 }}>{checkedItems.size} selected</span>
                          <button onClick={() => {
                            const hdr = "Severity\tDetection\tDetails\tTimestamp\tComputer\tUser\tSource\tRisk\n";
                            const body = [...checkedItems].map((key) => itemForKey(key)).filter(Boolean).map((i) => formatItemText(i)).join("\n");
                            navigator.clipboard.writeText(hdr + body);
                          }} style={{ ...ms.bp, borderRadius: 8, boxShadow: `0 2px 8px ${th.accent}33` }}>Copy Selected ({checkedItems.size})</button>
                          <button onClick={() => setModal((p) => ({ ...p, checkedItems: new Set() }))} style={{ ...ms.bs, borderRadius: 8 }}>Clear</button>
                        </>
                      )}
                      <button onClick={() => {
                        const hdr = "Risk\tSeverity\tCategory\tDetection\tArtifact\tCommand/Path\tDetails\tTimestamp\tComputer\tUser\tSource\tSuspicious\n";
                        const body = filteredItems.map((i) => `${i.riskScore}\t${i.severity}\t${i.category}\t${i.name}\t${i.artifact || ""}\t${i.command || ""}\t${i.detailsSummary}\t${i.timestamp}\t${i.computer}\t${i.user}\t${i.source}\t${i.suspiciousReasons?.join("; ") || ""}`).join("\n");
                        navigator.clipboard.writeText(hdr + body);
                      }} style={{ ...ms.bs, borderRadius: 8 }}>Copy All</button>
                      <button onClick={() => setModal(null)} style={{ ...ms.bp, borderRadius: 8, boxShadow: `0 2px 8px ${th.accent}33` }}>Done</button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Context Menu */}
      {contextMenu && (
        <>
          <div onMouseDown={(e) => { if (e.button === 0) setContextMenu(null); }} onContextMenu={(e) => { e.preventDefault(); }} style={{ position: "fixed", inset: 0, zIndex: 299 }} />
          <div style={{ position: "fixed", left: contextMenu.x, top: contextMenu.y, background: themeName === "dark" ? "rgba(30,33,38,0.82)" : "rgba(255,255,255,0.88)", backdropFilter: "blur(20px) saturate(180%)", WebkitBackdropFilter: "blur(20px) saturate(180%)", border: `1px solid ${themeName === "dark" ? "rgba(255,255,255,0.12)" : "rgba(0,0,0,0.12)"}`, borderRadius: 10, padding: "5px 0", zIndex: 300, boxShadow: themeName === "dark" ? "0 12px 40px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.06) inset" : "0 12px 40px rgba(0,0,0,0.18), 0 0 0 0.5px rgba(255,255,255,0.5) inset", minWidth: 200 }}>
            {[
              ...(contextMenu.colName !== "__tags__" ? [
                { label: (ct?.pinnedColumns || []).includes(contextMenu.colName) ? "Unpin Column" : "Pin Column",
                  icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><path d="M12 17v5M9 11l-4 4h14l-4-4V5a2 2 0 0 0-2-2h-2a2 2 0 0 0-2 2v6z"/></svg>,
                  action: () => (ct?.pinnedColumns || []).includes(contextMenu.colName) ? unpinColumn(contextMenu.colName) : pinColumn(contextMenu.colName) },
                { label: "Hide Column",
                  icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>,
                  action: () => up("hiddenColumns", new Set([...(ct?.hiddenColumns || []), contextMenu.colName])) },
                null,
              ] : []),
              { label: "Best Fit",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><path d="M21 12H3M21 12l-4-4M21 12l-4 4M3 12l4-4M3 12l4 4"/></svg>,
                action: () => autoFitColumn(contextMenu.colName) },
              { label: "Best Fit (All Columns)",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><path d="M22 12H2M22 12l-3-3M22 12l-3 3M2 12l3-3M2 12l3 3M12 2v20"/></svg>,
                action: () => autoFitAllColumns() },
              { label: "Reset Column Widths",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.textDim} strokeWidth="2" strokeLinecap="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>,
                action: () => resetColumnWidths() },
              null,
              { label: "Sort Ascending",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><path d="M12 19V5M5 12l7-7 7 7"/></svg>,
                action: () => { up("sortCol", contextMenu.colName); up("sortDir", "asc"); } },
              { label: "Sort Descending",
                icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><path d="M12 5v14M19 12l-7 7-7-7"/></svg>,
                action: () => { up("sortCol", contextMenu.colName); up("sortDir", "desc"); } },
              null,
              { label: "Stack Values", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><rect x="3" y="3" width="18" height="4" rx="1"/><rect x="3" y="10" width="14" height="4" rx="1"/><rect x="3" y="17" width="8" height="4" rx="1"/></svg>, action: () => {
                setModal({ type: "stacking", colName: contextMenu.colName, data: null, loading: true, filterText: "", sortBy: "count" });
                const af = activeFilters(ct);
                tle.getStackingData(ct.id, contextMenu.colName, {
                  searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
                  columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
                  bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
                  sortBy: "count",
                }).then((result) => setModal((p) => p?.type === "stacking" ? { ...p, data: result, loading: false } : p))
                  .catch(() => setModal((p) => p?.type === "stacking" ? { ...p, loading: false, data: { entries: [], totalUnique: 0, totalRows: 0 } } : p));
              }},
              null,
              { label: "Column Stats", icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round"><rect x="3" y="12" width="4" height="9" rx="1"/><rect x="10" y="6" width="4" height="15" rx="1"/><rect x="17" y="3" width="4" height="18" rx="1"/></svg>, action: () => {
                setModal({ type: "columnStats", colName: contextMenu.colName, data: null, loading: true });
                const af = activeFilters(ct);
                tle.getColumnStats(ct.id, contextMenu.colName, {
                  searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
                  columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
                  bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
                }).then((result) => setModal((p) => p?.type === "columnStats" ? { ...p, data: result, loading: false } : p))
                  .catch(() => setModal((p) => p?.type === "columnStats" ? { ...p, loading: false, data: null } : p));
              }},
            ].map((item, i) =>
              item === null ? (
                <div key={i} style={{ height: 1, background: themeName === "dark" ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)", margin: "4px 8px" }} />
              ) : (
                <button key={i} onClick={() => { item.action(); setContextMenu(null); }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = `${th.accent}22`; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: "6px 14px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", borderRadius: 5, margin: "0 4px", maxWidth: "calc(100% - 8px)", letterSpacing: "-0.01em" }}>
                  <span style={{ width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{item.icon}</span>
                  {item.label}
                </button>
              )
            )}
          </div>
        </>
      )}

      {/* Row Context Menu (for tagging) */}
      {rowContextMenu && (
        <>
          <div onMouseDown={(e) => { if (e.button === 0) setRowContextMenu(null); }} onContextMenu={(e) => { e.preventDefault(); }} style={{ position: "fixed", inset: 0, zIndex: 299 }} />
          <div style={{ position: "fixed", left: Math.min(rowContextMenu.x, window.innerWidth - 220), top: Math.min(rowContextMenu.y, window.innerHeight - 400), background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 6, padding: "4px 0", zIndex: 300, boxShadow: "0 8px 24px rgba(0,0,0,0.4)", minWidth: 200 }}>
            {rowContextMenu.cellColumn && (
              <button onClick={() => { copyCell(rowContextMenu.cellValue); setRowContextMenu(null); }}
                onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>📋</span>
                Copy Cell <span style={{ color: th.textMuted, fontSize: 10, marginLeft: "auto", maxWidth: 80, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{rowContextMenu.cellColumn}</span>
              </button>
            )}
            <button onClick={() => {
              if (rowContextMenu.row && ct) {
                const hdrs = ct.headers.filter((h) => !ct.hiddenColumns?.has(h));
                const line = hdrs.map((h) => (rowContextMenu.row[h] || "").replace(/\t/g, " ")).join("\t");
                navigator.clipboard?.writeText(hdrs.join("\t") + "\n" + line);
                setCopiedMsg(true); setTimeout(() => setCopiedMsg(false), 1200);
              }
              setRowContextMenu(null);
            }}
              onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
              <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>📄</span>
              Copy Row
            </button>
            <div style={{ height: 1, background: th.border, margin: "4px 0" }} />
            <div style={{ padding: "4px 12px", color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif", textTransform: "uppercase", letterSpacing: "0.06em" }}>Tags</div>
            {Object.entries(ct?.tagColors || {}).map(([tag, color]) => {
              const hasTg = rowContextMenu.currentTags.includes(tag);
              return (
                <button key={tag} onClick={async () => {
                  if (hasTg) await tle.removeTag(ct.id, rowContextMenu.rowId, tag);
                  else await tle.addTag(ct.id, rowContextMenu.rowId, tag);
                  const newTags = { ...ct.rowTags };
                  const list = [...(newTags[rowContextMenu.rowId] || [])];
                  if (hasTg) newTags[rowContextMenu.rowId] = list.filter((t) => t !== tag);
                  else { list.push(tag); newTags[rowContextMenu.rowId] = list; }
                  up("rowTags", newTags);
                  setRowContextMenu(null);
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "5px 12px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                  <span style={{ color, fontSize: 14 }}>{hasTg ? "●" : "○"}</span>
                  <span>{tag}</span>
                </button>
              );
            })}
            <div style={{ height: 1, background: th.border, margin: "4px 0" }} />
            <button onClick={() => { setRowContextMenu(null); setModal({ type: "tags" }); }}
              onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "5px 12px", background: "none", border: "none", color: th.textDim, fontSize: 11, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
              Manage Tags...
            </button>
            {ct?.tsColumns?.size > 0 && (<>
              <div style={{ height: 1, background: th.border, margin: "4px 0" }} />
              <button onClick={() => {
                const tsCols = [...(ct?.tsColumns || new Set())];
                const autoCol = (ct?.sortCol && ct.tsColumns.has(ct.sortCol)) ? ct.sortCol : tsCols[0];
                setRowContextMenu(null);
                setModal({ type: "proximity", pivotRow: rowContextMenu.row, pivotCol: autoCol });
              }}
                onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                <span style={{ width: 16, textAlign: "center", fontSize: 11 }}>⏱</span>
                Find Nearby Events...
              </button>
            </>)}
          </div>
        </>
      )}
    </div>
  );
}

