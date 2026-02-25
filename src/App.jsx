import { useState, useEffect, useRef, useCallback, useMemo } from "react";

const ROW_HEIGHT = 26;
const HEADER_HEIGHT = 34;
const FILTER_HEIGHT = 28;
const OVERSCAN = 20;
const VIRTUAL_WINDOW = 5000;    // rows to fetch per SQL query window
const VIRTUAL_AHEAD = 1000;     // trigger re-fetch when within this many rows of edge
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
const IOC_CATEGORY_PATTERNS = {
  "IPv4": /^(\d{1,3}\.){3}\d{1,3}(\/\d+)?$/,
  "IPv6": /^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/,
  "Domain": /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/,
  "MD5": /^[0-9a-fA-F]{32}$/,
  "SHA1": /^[0-9a-fA-F]{40}$/,
  "SHA256": /^[0-9a-fA-F]{64}$/,
  "URL": /^https?:\/\//i,
  "Email": /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  "File Path": /^([A-Za-z]:\\|\/)[^\n]+/,
};

function parseIocText(rawText) {
  const lines = rawText.split(/\r?\n/);
  const seen = new Set();
  const iocs = [];
  for (const line of lines) {
    const trimmed = line.replace(/#.*$/, "").trim();
    if (!trimmed || seen.has(trimmed.toLowerCase())) continue;
    seen.add(trimmed.toLowerCase());
    let category = "Other";
    for (const [cat, re] of Object.entries(IOC_CATEGORY_PATTERNS)) {
      if (re.test(trimmed)) { category = cat; break; }
    }
    iocs.push({ raw: trimmed, category });
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

  // New UI state
  const [filterDropdown, setFilterDropdown] = useState(null);
  const [contextMenu, setContextMenu] = useState(null);
  const [rowContextMenu, setRowContextMenu] = useState(null);
  const [groupDragOver, setGroupDragOver] = useState(false);
  const [dateTimeFormat, setDateTimeFormat] = useState("yyyy-MM-dd HH:mm:ss");
  const [timezone, setTimezone] = useState("UTC");
  const [themeName, setThemeName] = useState("dark");
  const [histogramVisible, setHistogramVisible] = useState(false);
  const [histogramCol, setHistogramCol] = useState(null);
  const [histogramData, setHistogramData] = useState([]);
  const histogramCache = useRef({}); // { [tabId]: { sig, data } }
  const [histogramHeight, setHistogramHeight] = useState(160);
  const histResizeStartY = useRef(0);
  const histResizeStartH = useRef(0);
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
  const [scrollTop, setScrollTop] = useState(0);
  const queryTimer = useRef(null);
  const fetchId = useRef(0); // Monotonic counter to discard stale query results
  const ctRef = useRef(null);
  const displayRowsRef = useRef([]);
  const isGroupedRef = useRef(false);
  const rightClickFired = useRef(false);
  const [pendingRestores, setPendingRestores] = useState({});
  const pendingRestoresRef = useRef({});

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
    const fetchOffset = Math.max(0, centerRow - Math.floor(VIRTUAL_WINDOW / 2));
    const result = await tle.queryRows(tab.id, {
      offset: fetchOffset, limit: VIRTUAL_WINDOW,
      sortCol: tab.sortCol, sortDir: tab.sortDir,
      searchTerm: effectiveSearch, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
      columnFilters, checkboxFilters,
      bookmarkedOnly: tab.showBookmarkedOnly,
      tagFilter: tab.tagFilter || null,
      dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
    });
    if (fetchId.current !== myFetchId) return; // Stale — newer fetch in flight
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
  useEffect(() => () => { if (queryTimer.current) clearTimeout(queryTimer.current); }, []);

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
    const sig = `${ct.id}:${hCol}:${ct.totalFiltered}:${ct.searchTerm}:${ct.searchMode}:${ct.showBookmarkedOnly}:${JSON.stringify(ct.dateRangeFilters)}:${JSON.stringify(ct.advancedFilters)}`;
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
      });
      const result = data || [];
      histogramCache.current[ct.id] = { sig, data: result };
      setHistogramData(result);
    }, 400);
    return () => { if (histogramTimer.current) clearTimeout(histogramTimer.current); };
  }, [histogramVisible, histogramCol, ct?.id, ct?.totalFiltered, ct?.searchTerm, ct?.searchMode, ct?.showBookmarkedOnly, JSON.stringify(ct?.dateRangeFilters), JSON.stringify(ct?.advancedFilters)]); // eslint-disable-line

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
      // Leaf level — fetch actual rows
      const af = activeFilters(tab);
      const result = await tle.queryRows(tab.id, {
        offset: 0, limit: 50000,
        sortCol: tab.sortCol, sortDir: tab.sortDir,
        searchTerm: tab.searchHighlight ? "" : tab.searchTerm, searchMode: tab.searchMode, searchCondition: tab.searchCondition || "contains",
        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
        bookmarkedOnly: tab.showBookmarkedOnly,
        dateRangeFilters: tab.dateRangeFilters || {}, advancedFilters: tab.advancedFilters || [],
        groupFilters: parentFilters,
      });
      setTabs((prev) => prev.map((t) => {
        if (t.id !== tab.id) return t;
        const newBm = new Set(t.bookmarkedSet);
        (result.bookmarkedRows || []).forEach((id) => newBm.add(id));
        const newTags = { ...t.rowTags, ...(result.rowTags || {}) };
        return { ...t, bookmarkedSet: newBm, rowTags: newTags, expandedGroups: { ...t.expandedGroups, [pathKey]: { rows: result.rows, totalFiltered: result.totalFiltered } } };
      }));
    }
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
      "import-start", "import-progress", "import-complete", "import-error",
      "export-progress", "sheet-selection", "fts-progress",
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

    tle.onImportStart(({ tabId, fileName, filePath }) => {
      setImportingTabs((prev) => ({ ...prev, [tabId]: { fileName, rowsImported: 0, percent: 0, status: "importing" } }));
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
              pinnedColumns: (kp.pinnedColumns || []).filter((h) => headers.includes(h)),
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
    tle.onImportError(({ tabId, error }) => {
      setImportingTabs((prev) => { const next = { ...prev }; delete next[tabId]; return next; });
      setTabs((prev) => prev.filter((t) => t.id !== tabId));
      alert(`Import failed: ${error}`);
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
    if (justResizedRef.current) return;
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
    if (!tle) return;
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
    const visible = ct.headers.filter((h) => !ct.hiddenColumns.has(h));
    if (ct.columnOrder?.length > 0) {
      const orderSet = new Set(ct.columnOrder);
      const ordered = ct.columnOrder.filter((h) => visible.includes(h));
      const rest = visible.filter((h) => !orderSet.has(h));
      return [...ordered, ...rest];
    }
    return visible;
  }, [ct?.headers, ct?.hiddenColumns, ct?.columnOrder]);

  const pinnedH = useMemo(() => {
    if (!ct) return [];
    return (ct.pinnedColumns || []).filter((h) => allVisH.includes(h));
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
  const vh = (typeof window !== "undefined" ? window.innerHeight - 190 : 600) - (detailVisible ? detailPanelHeight : 0);
  const si = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const ei = Math.min(totalCount, Math.ceil((scrollTop + vh) / ROW_HEIGHT) + OVERSCAN);
  // For grouped mode: direct slice. For flat mode: map to windowed cache via rowOffset.
  const visible = useMemo(() => isGrouped
    ? displayRows.slice(si, ei)
    : rows.slice(Math.max(0, si - rowOffset), Math.max(0, ei - rowOffset)),
    [isGrouped, displayRows, rows, si, ei, rowOffset]);
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
  const renderCell = (h, val) => {
    const text = fmtCell(h, val);
    if (!hlRegex || !text) return text;
    const splits = text.split(hlRegex);
    if (splits.length <= 1) return text;
    return <>{splits.map((seg, i) => i % 2 === 1
      ? <mark key={i} style={{ background: "rgba(210,153,34,0.5)", color: "inherit", borderRadius: 2, padding: "0 1px" }}>{seg}</mark>
      : seg
    )}</>;
  };
  const tw = allVisH.reduce((s, h) => s + gw(h), 0) + BKMK_COL_WIDTH + tagColWidth;

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
    if (!resizingCol) return;
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
      if (preselectAll) setFdSelected(new Set(vals.map((v) => v.val)));
    } catch { setFdValues([]); }
    setFdLoading(false);
  }, [tle]);

  useEffect(() => {
    if (!filterDropdown) { setFdValues([]); setFdSearch(""); setFdSelected(new Set()); setFdRegex(false); return; }
    if (filterDropdown.colName === "__tags__") {
      // Tags filter — load tags from DB
      const existing = ct?.tagFilter;
      const hasExisting = Array.isArray(existing) && existing.length > 0;
      setFdSelected(hasExisting ? new Set(existing) : new Set());
      setFdSearch("");
      setFdRegex(false);
      (async () => {
        setFdLoading(true);
        const tags = await tle.getAllTags(ct.id);
        const vals = (tags || []).map((t) => ({ val: t.tag, cnt: t.cnt }));
        setFdValues(vals);
        if (!hasExisting) setFdSelected(new Set(vals.map((v) => v.val)));
        setFdLoading(false);
      })();
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
    if (colName === "__tags__") {
      setTabs((prev) => prev.map((t) => {
        if (t.id !== activeTab) return t;
        if (fdSelected.size === 0 || fdSelected.size === fdValues.length) return { ...t, tagFilter: null };
        return { ...t, tagFilter: [...fdSelected] };
      }));
      setFilterDropdown(null);
      return;
    }
    setTabs((prev) => prev.map((t) => {
      if (t.id !== activeTab) return t;
      const newCbf = { ...t.checkboxFilters };
      if (fdSelected.size === 0 || fdSelected.size === fdValues.length) delete newCbf[colName];
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
    <div onClick={() => setModal(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)" }}>
      <div onClick={(e) => e.stopPropagation()} style={{ background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 24, width: 480, maxWidth: "92vw", maxHeight: "80vh", overflow: "auto", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
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

  const ImportProgress = ({ info }) => (
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
          {info.status === "indexing" ? "Building search index..." : "Importing..."}
        </h3>
        <p style={{ color: th.textDim, fontSize: 13, marginBottom: 16 }}>{info.fileName}</p>
        <div style={{ height: 6, background: th.border, borderRadius: 3, overflow: "hidden", marginBottom: 12 }}>
          <div style={{ height: "100%", width: `${Math.min(info.percent || 0, 100)}%`, background: info.status === "indexing" ? th.warning : th.borderAccent, borderRadius: 3, transition: "width 0.3s" }} />
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", color: th.textDim, fontSize: 12 }}>
          <span>{formatNumber(info.rowsImported || 0)} rows imported</span>
          <span>{info.percent || 0}%</span>
        </div>
      </div>
    </div>
  );

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
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: 60, border: `2px dashed ${dragOver ? th.borderAccent : th.border}`, borderRadius: 16, transition: "all 0.2s", background: dragOver ? th.selection : "transparent" }}>
          {/* IRFlow Logo — shield with timeline pulse */}
          <svg width="64" height="72" viewBox="0 0 64 72" fill="none" style={{ marginBottom: 18 }}>
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
          <h1 style={{ fontSize: 26, fontWeight: 700, color: th.text, margin: 0, fontFamily: "-apple-system, 'SF Pro Display', sans-serif" }}>IRFlow <span style={{ color: th.accent }}>Timeline</span></h1>
          <p style={{ color: th.textDim, fontSize: 13, letterSpacing: "0.12em", textTransform: "uppercase", margin: "6px 0 4px", fontWeight: 600 }}>DFIR Timeline Analysis for macOS</p>
          <p style={{ color: th.textMuted, fontSize: 11, margin: "0 0 24px" }}>SQLite-backed · Handles large files for timeline analysis · CSV / TSV / XLSX / EVTX / Plaso</p>
          <button onClick={() => tle?.openFileDialog()} style={{ padding: "10px 32px", background: th.primaryBtn, color: "#fff", border: "none", borderRadius: 6, fontSize: 14, fontWeight: 600, cursor: "pointer", fontFamily: "-apple-system, sans-serif", WebkitAppRegion: "no-drag" }}>Open File</button>
          <p style={{ color: th.textMuted, fontSize: 11, marginTop: 20 }}>⌘O open · ⌘F search · ⌘B bookmarks · ⌘E export</p>
          <p style={{ color: th.textMuted, fontSize: 10, marginTop: 24, fontFamily: "-apple-system, sans-serif" }}>Created by <span style={{ color: th.textDim }}>Renzon Cruz</span> | <span style={{ color: th.accent }}>@r3nzsec</span></p>
        </div>
      </div>
    );
  }

  // ── Main render ──────────────────────────────────────────────────
  const isImporting = ct?.importing && importingTabs[ct?.id];
  const activeCheckboxCount = ct ? Object.keys(ct.checkboxFilters || {}).filter(k => ct.checkboxFilters[k]?.length > 0).length : 0;

  return (
    <div onContextMenu={(e) => e.preventDefault()}
      onDragOver={(e) => { if (!e.dataTransfer.types.includes("Files")) return; e.preventDefault(); e.dataTransfer.dropEffect = "copy"; setDragOver(true); }}
      onDragLeave={(e) => { if (e.currentTarget.contains(e.relatedTarget)) return; setDragOver(false); }}
      onDrop={(e) => { if (!e.dataTransfer.types.includes("Files")) return; e.preventDefault(); setDragOver(false); const files = [...e.dataTransfer.files]; if (files.length > 0 && tle) { const paths = files.map((f) => tle.getPathForFile(f)).filter(Boolean); if (paths.length > 0) tle.importFiles(paths); } }}
      style={{ display: "flex", flexDirection: "column", height: "100vh", background: th.bg, color: th.text, fontFamily: "'SF Mono','Fira Code',Menlo,monospace", fontSize: fontSize, overflow: "hidden" }}>
      <style>{`
        @keyframes tle-spin { to { transform: rotate(360deg) } }
        ::-webkit-scrollbar { width: 10px; height: 10px; }
        ::-webkit-scrollbar-track { background: ${th.bg}; }
        ::-webkit-scrollbar-thumb { background: ${th.border}; border-radius: 5px; border: 2px solid ${th.bg}; }
        ::-webkit-scrollbar-thumb:hover { background: ${th.accent}; }
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
          <button onClick={() => setHistogramVisible((v) => !v)} style={{ ...tb, color: histogramVisible ? th.accent : undefined }} title="Toggle timeline histogram">
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
        {/* FTS indexing indicator — shown while background search index is building */}
        {ct && ct.dataReady && !ct.ftsReady && ct.ftsTotal > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 6px", flexShrink: 0 }}>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={th.warning} strokeWidth="2.5" style={{ animation: "tle-spin 1s linear infinite", flexShrink: 0 }}>
              <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" /></svg>
            <span style={{ color: th.warning, fontSize: 9, fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
              Indexing {Math.round((ct.ftsIndexed / ct.ftsTotal) * 100)}%
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
          <div key={t.id} onClick={() => { setActiveTab(t.id); setScrollTop(0); setSelectedRows(new Set()); setLastClickedRow(null); setProximityFilter(null); }}
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
                <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", background: `${th.accent}22`, border: `1px solid ${th.accent}4D`, borderRadius: 4, color: th.accent, fontSize: 10, fontWeight: 500, fontFamily: "-apple-system, sans-serif" }}>
                  {col}
                  <button onClick={() => removeGroupBy(col)} style={{ background: "none", border: "none", color: th.accent, cursor: "pointer", fontSize: 9, padding: 0, lineHeight: 1, opacity: 0.7 }} title={`Remove ${col} grouping`}>✕</button>
                </span>
              </span>
            ))}
            <button onClick={() => setTabs((prev) => prev.map((t) => t.id === ct.id ? { ...t, groupByColumns: [], expandedGroups: {}, groupData: [] } : t))} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 9, padding: "1px 4px", fontFamily: "-apple-system, sans-serif" }} title="Clear all grouping">Clear</button>
          </>) : (
            <span style={{ color: th.textMuted, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>Drag a column header here to group</span>
          )}
          {activeCheckboxCount > 0 && (
            <span style={{ marginLeft: "auto", color: th.borderAccent, fontSize: 10, fontFamily: "-apple-system, sans-serif" }}>
              {activeCheckboxCount} value filter{activeCheckboxCount > 1 ? "s" : ""} active
            </span>
          )}
        </div>
      )}

      {/* Timeline Histogram (Kibana-style with axes, resizable) */}
      {histogramVisible && ct?.dataReady && ct?.tsColumns?.size > 0 && (() => {
        const effectiveHistCol = histogramCol && ct.tsColumns.has(histogramCol) ? histogramCol : [...ct.tsColumns][0];
        const HIST_H = histogramHeight, Y_AXIS_W = 44, X_AXIS_H = 18, CHART_PAD_T = 4, HEADER_BAR = 26;
        const svgH = HIST_H - HEADER_BAR;
        const chartH = svgH - X_AXIS_H - CHART_PAD_T;
        return (
          <div id="hist-container" style={{ height: HIST_H, padding: "4px 12px 0", background: th.panelBg, borderBottom: `1px solid ${th.border}`, flexShrink: 0, position: "relative", overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3, height: HEADER_BAR - 6 }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2"><rect x="3" y="12" width="4" height="9" rx="1" /><rect x="10" y="6" width="4" height="15" rx="1" /><rect x="17" y="3" width="4" height="18" rx="1" /></svg>
              <span style={{ color: th.textDim, fontSize: 10, fontWeight: 600 }}>Timeline</span>
              <select value={effectiveHistCol || ""} onChange={(e) => setHistogramCol(e.target.value)}
                style={{ background: th.btnBg, border: `1px solid ${th.btnBorder}`, color: th.textDim, fontSize: 10, padding: "2px 6px", borderRadius: 4, cursor: "pointer", outline: "none" }}>
                {[...ct.tsColumns].map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
              {histogramData.length > 0 && (
                <span style={{ color: th.textMuted, fontSize: 9 }}>
                  {histogramData[0]?.day} — {histogramData[histogramData.length - 1]?.day} ({histogramData.length} day{histogramData.length !== 1 ? "s" : ""})
                </span>
              )}
              {ct.dateRangeFilters?.[effectiveHistCol] && (
                <button onClick={() => {
                  const next = { ...(ct.dateRangeFilters || {}) };
                  delete next[effectiveHistCol];
                  up("dateRangeFilters", next);
                }} style={{ background: `${th.warning}22`, border: `1px solid ${th.warning}4D`, color: th.warning, cursor: "pointer", fontSize: 9, padding: "1px 8px", borderRadius: 3, marginLeft: "auto" }}>
                  Clear {ct.dateRangeFilters[effectiveHistCol].from?.slice(0, 10)} filter
                </button>
              )}
              <button onClick={() => setHistogramVisible(false)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 10, marginLeft: ct.dateRangeFilters?.[effectiveHistCol] ? 4 : "auto", padding: "0 4px" }}>✕</button>
            </div>
            {histogramData.length > 0 ? (
              <svg width="100%" height={svgH} style={{ display: "block", overflow: "visible" }}>
                {(() => {
                  const maxCnt = Math.max(...histogramData.map((d) => d.cnt), 1);
                  // Nice Y-axis ticks
                  const rawStep = maxCnt / 4;
                  const mag = Math.pow(10, Math.floor(Math.log10(rawStep || 1)));
                  const step = Math.ceil(rawStep / mag) * mag || 1;
                  const yTicks = [];
                  for (let v = 0; v <= maxCnt; v += step) yTicks.push(v);
                  if (yTicks[yTicks.length - 1] < maxCnt) yTicks.push(yTicks[yTicks.length - 1] + step);
                  const yMax = yTicks[yTicks.length - 1] || 1;

                  const chartW = Math.max(200, (typeof window !== "undefined" ? window.innerWidth : 800) - 24 - Y_AXIS_W);
                  const barW = Math.max(1, chartW / histogramData.length);
                  const gap = barW > 4 ? 1 : 0;

                  // X-axis: show labels at regular intervals
                  const maxLabels = Math.floor(chartW / 70);
                  const labelStep = Math.max(1, Math.ceil(histogramData.length / maxLabels));

                  const gridColor = th.histGrid;
                  const textColor = th.textMuted;
                  // Heatmap: interpolate cool→hot based on event density
                  const heatColor = (ratio) => {
                    const t = Math.max(0, Math.min(1, ratio));
                    const r = Math.round(30 + t * 202);  // #1e → #E8
                    const g = Math.round(40 + t * 53);   // #28 → #5D
                    const b = Math.round(56 - t * 14);   // #38 → #2A
                    return `rgb(${r},${g},${b})`;
                  };
                  const heatHover = (ratio) => {
                    const t = Math.max(0, Math.min(1, ratio));
                    const r = Math.min(255, Math.round(50 + t * 194));
                    const g = Math.min(255, Math.round(60 + t * 63));
                    const b = Math.min(255, Math.round(70 - t * 6));
                    return `rgb(${r},${g},${b})`;
                  };

                  return (<>
                    {/* Y-axis grid lines and labels */}
                    {yTicks.map((v) => {
                      const y = CHART_PAD_T + chartH - (v / yMax) * chartH;
                      return <g key={`y-${v}`}>
                        <line x1={Y_AXIS_W} y1={y} x2={Y_AXIS_W + chartW} y2={y} stroke={gridColor} strokeWidth={1} />
                        <text x={Y_AXIS_W - 4} y={y + 3} textAnchor="end" fill={textColor} fontSize={9} fontFamily="-apple-system,sans-serif">{v >= 1000 ? `${(v/1000).toFixed(v >= 10000 ? 0 : 1)}k` : v}</text>
                      </g>;
                    })}
                    {/* Bars — heatmap colored by density */}
                    {histogramData.map((d, i) => {
                      const h = Math.max(1, (d.cnt / yMax) * chartH);
                      const x = Y_AXIS_W + i * barW + gap;
                      const y = CHART_PAD_T + chartH - h;
                      const isFiltered = ct.dateRangeFilters?.[effectiveHistCol]?.from?.slice(0, 10) === d.day;
                      const ratio = d.cnt / maxCnt;
                      return <rect key={i} x={x} y={y} width={Math.max(1, barW - gap * 2)} height={h}
                        fill={isFiltered ? th.warning : heatColor(ratio)} rx={barW > 8 ? 1 : 0}
                        style={{ cursor: "pointer", transition: "fill 0.1s" }}
                        onMouseEnter={(e) => { if (!isFiltered) e.currentTarget.setAttribute("fill", heatHover(ratio)); }}
                        onMouseLeave={(e) => { if (!isFiltered) e.currentTarget.setAttribute("fill", heatColor(ratio)); }}
                        onClick={() => {
                          const from = d.day + " 00:00:00";
                          const to = d.day + " 23:59:59";
                          up("dateRangeFilters", { ...(ct.dateRangeFilters || {}), [effectiveHistCol]: { from, to } });
                        }}>
                        <title>{d.day}: {d.cnt.toLocaleString()} events</title>
                      </rect>;
                    })}
                    {/* X-axis line */}
                    <line x1={Y_AXIS_W} y1={CHART_PAD_T + chartH} x2={Y_AXIS_W + chartW} y2={CHART_PAD_T + chartH} stroke={gridColor} strokeWidth={1} />
                    {/* X-axis date labels */}
                    {histogramData.map((d, i) => {
                      if (i % labelStep !== 0 && i !== histogramData.length - 1) return null;
                      const x = Y_AXIS_W + i * barW + barW / 2;
                      const parts = d.day.split("-");
                      const label = parts.length === 3 ? `${parts[1]}/${parts[2]}` : d.day;
                      return <text key={`xl-${i}`} x={x} y={svgH - 2} textAnchor="middle" fill={textColor} fontSize={8} fontFamily="-apple-system,sans-serif">{label}</text>;
                    })}
                  </>);
                })()}
              </svg>
            ) : (
              <div style={{ height: svgH, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <span style={{ color: th.textMuted, fontSize: 10 }}>Loading histogram...</span>
              </div>
            )}
            {/* Drag handle for resizing */}
            <div onMouseDown={onHistResizeStart} style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: 5, cursor: "row-resize", zIndex: 2 }}>
              <div style={{ width: 40, height: 3, borderRadius: 2, background: th.textMuted + "66", margin: "1px auto 0" }} />
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
          <div style={{ flex: 1, overflow: "auto", position: "relative", WebkitAppRegion: "no-drag" }} ref={scrollRef} onScroll={(e) => setScrollTop(e.target.scrollTop)}>
            <div style={{ minWidth: tw }}>
              {/* Header */}
              <div style={{ display: "flex", position: "sticky", top: 0, zIndex: 10, background: th.headerBg, borderBottom: `2px solid ${th.borderAccent}` }}>
                {/* # column - always sticky */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: BKMK_COL_WIDTH, minWidth: BKMK_COL_WIDTH, height: HEADER_HEIGHT, color: th.textMuted, fontSize: 10, fontWeight: 600, position: "sticky", left: 0, zIndex: 13, background: th.headerBg }}>#</div>
                {/* Tags column header — sticky, resizable */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: tagColWidth, minWidth: tagColWidth, height: HEADER_HEIGHT, color: th.textMuted, fontSize: 10, fontWeight: 600, borderRight: `1px solid ${th.border}`, background: th.headerBg, position: "sticky", left: BKMK_COL_WIDTH, zIndex: 12, userSelect: "none" }}>
                  Tags
                  <div onMouseDown={(e) => {
                    e.preventDefault();
                    const startX = e.clientX, startW = tagColWidth;
                    const onMove = (ev) => setTagColWidth(Math.max(TAG_COL_WIDTH_MIN, startW + ev.clientX - startX));
                    const onUp = () => { document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
                    document.addEventListener("mousemove", onMove);
                    document.addEventListener("mouseup", onUp);
                  }} style={{ position: "absolute", right: 0, top: 0, bottom: 0, width: 4, cursor: "col-resize" }} />
                </div>
                {/* Pinned columns */}
                {pinnedH.map((h) => (
                  <div key={h} data-col-header={h} draggable onDragStart={(e) => { if (e.button === 2) { e.preventDefault(); return; } e.dataTransfer.setData("text/column-name", h); e.dataTransfer.effectAllowed = "move"; }}
                    onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; setHeaderDragOver(h); }}
                    onDragLeave={() => setHeaderDragOver((prev) => prev === h ? null : prev)}
                    onDrop={(e) => { e.preventDefault(); e.stopPropagation(); setHeaderDragOver(null); const src = e.dataTransfer.getData("text/column-name"); if (src && src !== h) reorderColumn(src, h); }}
                    onClick={() => handleSort(h)}
                    onDoubleClick={() => handleHeaderDblClick(h)}
                    onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); setContextMenu({ x: e.clientX, y: e.clientY, colName: h }); }}
                    style={{ display: "flex", alignItems: "center", height: HEADER_HEIGHT, width: gw(h), minWidth: gw(h), padding: "0 8px", cursor: "pointer", userSelect: "none", fontWeight: 600, color: th.headerText, fontSize: 11, borderRight: h === pinnedH[pinnedH.length - 1] ? `2px solid ${th.borderAccent}` : `1px solid ${th.border}`, position: "sticky", left: pinnedOffsets.offsets[h], zIndex: 12, background: headerDragOver === h ? th.selection : th.headerBg, overflow: "hidden" }}>
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
                    onClick={() => handleSort(h)}
                    onDoubleClick={() => handleHeaderDblClick(h)}
                    onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); setContextMenu({ x: e.clientX, y: e.clientY, colName: h }); }}
                    style={{ display: "flex", alignItems: "center", height: HEADER_HEIGHT, width: gw(h), minWidth: gw(h), padding: "0 8px", cursor: "pointer", userSelect: "none", fontWeight: 600, color: th.headerText, fontSize: 11, borderRight: `1px solid ${th.border}`, position: "relative", overflow: "hidden", background: headerDragOver === h ? th.selection : undefined }}>
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
                {/* Tags filter cell — uses same checkbox filter dropdown as columns */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: tagColWidth, minWidth: tagColWidth, height: FILTER_HEIGHT, borderRight: `1px solid ${th.border}`, background: th.bg, position: "sticky", left: BKMK_COL_WIDTH, zIndex: 11 }}>
                  {ct.tagFilter ? (
                    <button onClick={() => up("tagFilter", null)} style={{ padding: "1px 5px", background: "rgba(248,81,73,0.15)", border: "1px solid rgba(248,81,73,0.3)", borderRadius: 3, color: th.danger, fontSize: 8, cursor: "pointer", fontFamily: "-apple-system,sans-serif", maxWidth: tagColWidth - 8, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                      title={`Tag filter active — click to clear`}>
                      {Array.isArray(ct.tagFilter) ? `${ct.tagFilter.length} tags` : ct.tagFilter} ✕
                    </button>
                  ) : (
                    <button onClick={(e) => { e.stopPropagation(); const rect = e.currentTarget.getBoundingClientRect(); setFilterDropdown(filterDropdown?.colName === "__tags__" ? null : { colName: "__tags__", x: rect.left, y: rect.bottom + 2 }); }}
                      style={{ background: "none", border: "none", color: th.textMuted, fontSize: 9, cursor: "pointer", padding: "2px 4px" }} title="Filter by tag">
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" /></svg>
                    </button>
                  )}
                </div>
                {/* Pinned filter cells */}
                {pinnedH.map((h) => {
                  const hasCbf = ct.checkboxFilters?.[h]?.length > 0;
                  const isTs = ct.tsColumns?.has(h);
                  const hasDr = ct.dateRangeFilters?.[h];
                  const hasFilter = !!(ct.columnFilters[h] || hasCbf);
                  const isDis = ct.disabledFilters?.has(h);
                  return (
                    <div key={h} style={{ width: gw(h), minWidth: gw(h), padding: "0 2px", display: "flex", alignItems: "center", height: FILTER_HEIGHT, borderRight: h === pinnedH[pinnedH.length - 1] ? `2px solid ${th.borderAccent}` : `1px solid ${th.border}`, position: "sticky", left: pinnedOffsets.offsets[h], zIndex: 11, background: th.bg }}>
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
                    <div key={h} style={{ width: gw(h), minWidth: gw(h), padding: "0 2px", display: "flex", alignItems: "center", height: FILTER_HEIGHT, borderRight: `1px solid ${th.border}` }}>
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
                    return (
                      <div key={`m-${item.pathKey}`} style={{ height: ROW_HEIGHT, position: "absolute", top: ai * ROW_HEIGHT, display: "flex", alignItems: "center", paddingLeft: indent, color: th.textMuted, fontSize: 11, fontStyle: "italic", fontFamily: "-apple-system, sans-serif" }}>
                        Showing {formatNumber(item.loaded)} of {formatNumber(item.total)} rows in this group
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
                          style={{ width: gw(h), minWidth: gw(h), padding: "0 8px", display: "flex", alignItems: "center", overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", borderRight: h === pinnedH[pinnedH.length - 1] ? `2px solid ${th.borderAccent}44` : `1px solid ${th.cellBorder}`, fontSize: fontSize - 0.5, position: "sticky", left: pinnedOffsets.offsets[h], zIndex: 2, background: stickyBase, boxShadow: stickyOverlay }}>
                          {renderCell(h, row[h])}
                        </div>
                      ))}
                      {/* Scrollable data cells */}
                      {scrollH.map((h) => (
                        <div key={h} data-cell-col={h} onDoubleClick={() => setCellPopup({ column: h, value: row[h] || "" })} title={fmtCell(h, row[h])}
                          onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); setRowContextMenu({ x: e.clientX, y: e.clientY, rowId: row.__idx, rowIndex: ai, currentTags: rTags, row, cellColumn: h, cellValue: row[h] || "" }); }}
                          style={{ width: gw(h), minWidth: gw(h), padding: "0 8px", display: "flex", alignItems: "center", overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", borderRight: `1px solid ${th.cellBorder}`, fontSize: fontSize - 0.5 }}>
                          {renderCell(h, row[h])}
                        </div>
                      ))}
                    </div>
                  );
                })}
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
            {!isGrouped && <><Sdiv /><span>Filtered: <b style={{ color: ct.totalFiltered < ct.totalRows ? th.warning : th.success }}>{formatNumber(ct.totalFiltered)}</b></span></>}
            {!isGrouped && <><Sdiv /><span>Showing: <b>{formatNumber(ct.totalFiltered)}</b></span></>}
            {isGrouped && <><Sdiv /><span>Groups: <b style={{ color: th.accent }}>{ct.groupData?.length || 0}</b></span></>}
            {ct.bookmarkedSet?.size > 0 && <><Sdiv /><span>Flagged: <b style={{ color: th.warning }}>{ct.bookmarkedSet.size}</b></span></>}
            {ct.sortCol && <><Sdiv /><span>Sort: {ct.sortCol} {ct.sortDir === "asc" ? "↑" : "↓"}</span></>}
            {selectedRows.size > 0 && !isGrouped && <><Sdiv /><span>{selectedRows.size === 1 ? `Row: ${(lastClickedRow ?? 0) + 1}` : `${selectedRows.size} rows selected`}</span></>}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {copiedMsg && <span style={{ color: th.success }}>Copied!</span>}
            {pinnedH.length > 0 && <span>📌 {pinnedH.length}</span>}
            <span>{allVisH.length}/{ct.headers.length} cols</span>
            {ct.colorRules.length > 0 && <span>{ct.colorRules.length} color rule{ct.colorRules.length > 1 ? "s" : ""}</span>}
            {activeCheckboxCount > 0 && <span style={{ color: th.borderAccent }}>{activeCheckboxCount} value filter{activeCheckboxCount > 1 ? "s" : ""}</span>}
            {ct.tagFilter && <span style={{ color: th.danger }}>Tag: {Array.isArray(ct.tagFilter) ? ct.tagFilter.join(", ") : ct.tagFilter}</span>}
            {Object.keys(ct.dateRangeFilters || {}).length > 0 && <span style={{ color: th.warning }}>{Object.keys(ct.dateRangeFilters).length} date filter{Object.keys(ct.dateRangeFilters).length > 1 ? "s" : ""}</span>}
            {(ct.advancedFilters?.length > 0) && <span style={{ color: th.accent }}>{ct.advancedFilters.length} advanced filter{ct.advancedFilters.length > 1 ? "s" : ""}</span>}
            {ct.searchHighlight && ct.searchTerm && <span style={{ color: th.warning }}>Highlight mode</span>}
            {ct._detectedProfile && <span style={{ color: th.success }}>{ct._detectedProfile}</span>}
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
        return (
          <div onClick={() => setModal(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)" }}>
            <div id="stacking-modal" onClick={(e) => e.stopPropagation()} style={{ background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: mw, maxWidth: "96vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)", position: "relative" }}>
              {/* Right edge resize handle */}
              <div onMouseDown={onModalResize} style={{ position: "absolute", top: 12, bottom: 12, right: -3, width: 6, cursor: "ew-resize", zIndex: 1 }} />
              {/* Header */}
              <div style={{ padding: "16px 20px 12px", borderBottom: `1px solid ${th.border}` }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Value Frequency Analysis</h3>
                    <select value={colName} onChange={(e) => {
                      const newCol = e.target.value;
                      setModal((p) => ({ ...p, colName: newCol, loading: true, filterText: "" }));
                      const af = activeFilters(ct);
                      tle.getStackingData(ct.id, newCol, {
                        searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
                        columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
                        bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
                        sortBy: sortBy,
                      }).then((result) => setModal((p) => p?.type === "stacking" ? { ...p, data: result, loading: false } : p))
                        .catch(() => setModal((p) => p?.type === "stacking" ? { ...p, loading: false, data: { entries: [], totalUnique: 0, totalRows: 0 } } : p));
                    }} style={{ background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 4, color: th.textDim, fontSize: 11, padding: "2px 6px", cursor: "pointer", outline: "none" }}>
                      {ct.headers.filter((h) => !ct.hiddenColumns?.has?.(h)).map((h) => <option key={h} value={h}>{h}</option>)}
                    </select>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 10, color: th.textMuted }}>{formatNumber(data.totalUnique)} unique / {formatNumber(data.totalRows)} rows</span>
                    <button onClick={() => setModal(null)} style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "0 4px" }}>✕</button>
                  </div>
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <input autoFocus placeholder="Filter values..." value={filterText} onChange={(e) => setModal((p) => ({ ...p, filterText: e.target.value }))}
                    style={{ flex: 1, padding: "6px 10px", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, outline: "none", fontFamily: "inherit" }} />
                  <button onClick={() => {
                    const newSort = sortBy === "count" ? "value" : "count";
                    setModal((p) => ({ ...p, sortBy: newSort, loading: true }));
                    const af = activeFilters(ct);
                    tle.getStackingData(ct.id, colName, {
                      searchTerm: ct.searchHighlight ? "" : ct.searchTerm, searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
                      columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
                      bookmarkedOnly: ct.showBookmarkedOnly, dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
                      sortBy: newSort,
                    }).then((result) => setModal((p) => p?.type === "stacking" ? { ...p, data: result, loading: false } : p))
                      .catch(() => setModal((p) => p?.type === "stacking" ? { ...p, loading: false, data: { entries: [], totalUnique: 0, totalRows: 0 } } : p));
                  }} style={{ padding: "6px 12px", background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.textDim, fontSize: 11, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
                    Sort: {sortBy === "count" ? "Count" : "Value"} {sortBy === "count" ? "↓" : "A→Z"}
                  </button>
                  <button onClick={() => {
                    const lines = ["Value\tCount\tPercent"];
                    for (const v of displayed) {
                      const pct = data.totalRows > 0 ? ((v.cnt / data.totalRows) * 100).toFixed(2) : "0";
                      lines.push(`${v.val ?? "(empty)"}\t${v.cnt}\t${pct}%`);
                    }
                    navigator.clipboard.writeText(lines.join("\n"));
                  }} style={{ padding: "6px 12px", background: th.btnBg, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.textDim, fontSize: 11, cursor: "pointer", fontFamily: "-apple-system,sans-serif", whiteSpace: "nowrap" }}>
                    Copy TSV
                  </button>
                </div>
              </div>
              {/* Table header */}
              <div style={{ display: "flex", padding: "6px 20px", borderBottom: `1px solid ${th.border}`, background: th.bgAlt, fontSize: 10, color: th.textMuted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "-apple-system,sans-serif" }}>
                <span style={{ width: 48, flexShrink: 0, textAlign: "right", paddingRight: 12 }}>#</span>
                <span style={{ width: vw, flexShrink: 0, position: "relative" }}>
                  Value
                  <div onMouseDown={onValColResize} style={{ position: "absolute", right: -4, top: 0, bottom: 0, width: 8, cursor: "col-resize" }}>
                    <div style={{ position: "absolute", right: 3, top: 2, bottom: 2, width: 2, background: th.border, borderRadius: 1 }} />
                  </div>
                </span>
                <span style={{ width: 100, flexShrink: 0, textAlign: "right" }}>Count</span>
                <span style={{ width: 60, flexShrink: 0, textAlign: "right" }}>%</span>
                <span style={{ flex: 1, paddingLeft: 12 }}>Distribution</span>
              </div>
              {/* Scrollable rows */}
              <div style={{ flex: 1, overflow: "auto", minHeight: 0 }}>
                {modal.loading ? (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 40 }}>
                    <span style={{ color: th.textMuted, fontSize: 12 }}>Loading...</span>
                  </div>
                ) : displayed.length === 0 ? (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 40 }}>
                    <span style={{ color: th.textMuted, fontSize: 12 }}>{filterText ? "No matching values" : "No data"}</span>
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
                      onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                      style={{ display: "flex", alignItems: "center", padding: "5px 20px", cursor: "pointer", borderBottom: `1px solid ${th.border}22`, fontSize: 12 }}>
                      <span style={{ width: 48, flexShrink: 0, textAlign: "right", paddingRight: 12, color: th.textMuted, fontSize: 10 }}>{i + 1}</span>
                      <span style={{ width: vw, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: isRare ? th.accent : th.text, fontWeight: isRare ? 500 : 400 }} title={valStr}>{valStr}</span>
                      <span style={{ width: 100, flexShrink: 0, textAlign: "right", color: th.text, fontWeight: 500, fontFamily: "'SF Mono',Menlo,monospace" }}>{formatNumber(v.cnt)}</span>
                      <span style={{ width: 60, flexShrink: 0, textAlign: "right", color: th.textDim, fontSize: 11 }}>{pct.toFixed(1)}%</span>
                      <div style={{ flex: 1, paddingLeft: 12 }}>
                        <div style={{ height: 14, background: th.border + "44", borderRadius: 3, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${Math.max(1, barPct)}%`, background: isRare ? th.danger + "CC" : th.accent + "99", borderRadius: 3, transition: "width 0.2s" }} />
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
              {/* Footer */}
              <div style={{ padding: "10px 20px", borderTop: `1px solid ${th.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 11, color: th.textMuted }}>
                <span>{filterText ? `${formatNumber(displayed.length)} of ${formatNumber(data.totalUnique)} values shown` : `${formatNumber(data.totalUnique)} unique values`}{data.truncated ? <span style={{ color: th.warning, marginLeft: 6 }}>(showing top 10,000)</span> : ""}</span>
                <span style={{ color: th.textDim }}>Click a row to filter · Drag column border to resize</span>
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
          <div onClick={() => setModal(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 520, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
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

        const categories = parsedIocs.reduce((acc, ioc) => { acc[ioc.category] = (acc[ioc.category] || 0) + 1; return acc; }, {});
        const defaultName = fileName ? fileName.replace(/\.(txt|csv|ioc)$/i, "") : "IOC Match";
        const effectiveName = (iocName || defaultName || "IOC Match").trim();
        const tagName = `IOC: ${effectiveName}`;

        const handleLoadFile = async () => {
          const result = await tle.loadIocFile();
          if (!result || result.error) return;
          const parsed = parseIocText(result.content);
          setModal((p) => ({ ...p, iocText: result.content, fileName: result.fileName,
            iocName: p.iocName || result.fileName.replace(/\.(txt|csv|ioc)$/i, ""), parsedIocs: parsed }));
        };

        const handlePasteChange = (text) => {
          const parsed = parseIocText(text);
          setModal((p) => ({ ...p, iocText: text, parsedIocs: parsed }));
        };

        const handleScan = async () => {
          if (parsedIocs.length === 0 || !ct) return;
          setModal((p) => ({ ...p, loading: true, error: null }));
          try {
            const escapedPatterns = parsedIocs.map((ioc) => escapeIocForRegex(ioc.raw));
            const { matchedRowIds, perIocCounts } = await tle.matchIocs(ct.id, escapedPatterns, 200);

            if (matchedRowIds.length > 0) {
              const tagMap = {};
              for (const rowId of matchedRowIds) tagMap[rowId] = [tagName];
              await tle.bulkAddTags(ct.id, tagMap);
              if (!ct.tagColors[tagName]) up("tagColors", { ...ct.tagColors, [tagName]: "#f0883e" });
            }

            await fetchData(ct);

            const perIocResults = parsedIocs.map((ioc, i) => ({
              raw: ioc.raw, category: ioc.category, hits: perIocCounts[escapedPatterns[i]] || 0,
            })).sort((a, b) => b.hits - a.hits);

            setModal((p) => p?.type === "ioc" ? ({ ...p, phase: "results", loading: false,
              results: { matchedRowIds, matchedCount: matchedRowIds.length, tagName, perIocResults } }) : p);
          } catch (e) {
            setModal((p) => p?.type === "ioc" ? ({ ...p, loading: false, error: e.message }) : p);
          }
        };

        const foundCount = results ? results.perIocResults.filter((r) => r.hits > 0).length : 0;
        const missedCount = results ? results.perIocResults.filter((r) => r.hits === 0).length : 0;

        return (
          <div onClick={() => setModal(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 580, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
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
                    <label style={ms.lb}>IOC Set Name (becomes tag label)</label>
                    <input value={iocName} onChange={(e) => setModal((p) => ({ ...p, iocName: e.target.value }))} placeholder={defaultName} style={ms.ip} />
                    {(iocName || defaultName) && <span style={{ color: th.textMuted, fontSize: 10, marginTop: 3, display: "block" }}>Tag: <code style={{ color: th.accent }}>{tagName}</code></span>}
                  </div>
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <button onClick={handleLoadFile} style={ms.bp}>Load File (.txt / .csv)</button>
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
                        {Object.entries(categories).map(([cat, count]) => (
                          <span key={cat} style={{ padding: "2px 8px", background: `${th.accent}22`, border: `1px solid ${th.accent}44`, borderRadius: 4, fontSize: 11, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>{cat}: {count}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {error && <div style={{ padding: "8px 12px", background: `${th.danger}22`, border: `1px solid ${th.danger}44`, borderRadius: 6, color: th.danger, fontSize: 12 }}>Error: {error}</div>}
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
                      Tagged {formatNumber(results.matchedCount)} rows with <code style={{ background: `${th.success}22`, padding: "0 5px", borderRadius: 3 }}>{results.tagName}</code>
                    </div>
                  )}
                  <div>
                    <div style={{ ...ms.lb, marginBottom: 6 }}>Per-IOC Results ({results.perIocResults.length} IOCs)</div>
                    <div style={{ maxHeight: 260, overflow: "auto", border: `1px solid ${th.border}`, borderRadius: 6 }}>
                      {results.perIocResults.map((ioc, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 10px", borderBottom: `1px solid ${th.border}22`, background: i % 2 === 0 ? "transparent" : `${th.bgAlt}44` }}>
                          <span style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: ioc.hits > 0 ? th.danger : th.textMuted, opacity: ioc.hits > 0 ? 1 : 0.4 }} />
                          <span style={{ flex: 1, fontFamily: "'SF Mono', Menlo, monospace", fontSize: 11, color: ioc.hits > 0 ? th.text : th.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={ioc.raw}>{ioc.raw}</span>
                          <span style={{ fontSize: 10, color: th.textMuted, flexShrink: 0, fontFamily: "-apple-system, sans-serif" }}>{ioc.category}</span>
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
                    {loading ? `Scanning ${parsedIocs.length} IOCs...` : `Scan ${parsedIocs.length > 0 ? parsedIocs.length + " IOCs" : ""}`}
                  </button>
                </>)}
                {phase === "results" && results && (<>
                  <button onClick={() => setModal((p) => ({ ...p, phase: "load" }))} style={ms.bs}>Back / Re-scan</button>
                  <div style={{ display: "flex", gap: 6 }}>
                    {results.matchedCount > 0 && (
                      <button onClick={() => { up("tagFilter", results.tagName); setModal(null); }} style={{ ...ms.bs, color: th.accent, borderColor: th.accent + "66" }}>Show Only IOC Matches</button>
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
          <div onClick={() => setModal(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 600, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
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
          <div onClick={(e) => e.stopPropagation()} style={{ background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 560, maxWidth: "92vw", maxHeight: "80vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
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
          <div onClick={(e) => e.stopPropagation()} style={{ position: "fixed", left: filterDropdown.dx ?? Math.min(filterDropdown.x, window.innerWidth - 400), top: filterDropdown.dy ?? Math.min(filterDropdown.y, window.innerHeight - 440), width: 380, height: 420, minWidth: 260, minHeight: 200, maxWidth: "90vw", maxHeight: "90vh", background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 8, boxShadow: "0 12px 28px rgba(0,0,0,0.5)", zIndex: 200, display: "flex", flexDirection: "column", overflow: "hidden", resize: "both" }}>
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
          <div onClick={(e) => e.stopPropagation()} style={{ position: "fixed", left: Math.min(dateRangeDropdown.x, window.innerWidth - 300), top: Math.min(dateRangeDropdown.y, window.innerHeight - 220), width: 290, background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 8, boxShadow: "0 12px 28px rgba(0,0,0,0.5)", zIndex: 200, padding: 12 }}>
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

        const parseTs = (ts) => new Date((ts || "").replace(" ", "T")).getTime();
        const fmtDur = (ms) => {
          const mins = Math.round(ms / 60000);
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
          <div onClick={() => setModal(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 700, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
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
          <div onClick={() => setModal(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 650, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
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
          <div onClick={() => setModal(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 560, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
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

        const selectStyle = { background: th.inputBg, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, padding: "5px 8px", fontSize: 12, fontFamily: "-apple-system, sans-serif", outline: "none" };
        const inputStyle = { ...selectStyle, flex: 1, minWidth: 80 };

        return (
          <div onClick={() => setModal(null)} style={{ position: "fixed", inset: 0, background: th.overlay, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100, backdropFilter: "blur(4px)" }}>
            <div onClick={(e) => e.stopPropagation()} style={{ background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 12, padding: 0, width: 720, maxWidth: "94vw", maxHeight: "88vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 48px rgba(0,0,0,0.5)" }}>
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
                <div style={{ marginTop: 16, padding: "10px 12px", background: th.inputBg, border: `1px solid ${th.border}`, borderRadius: 6, fontSize: 11, fontFamily: "'SF Mono', 'Fira Code', Menlo, monospace", color: th.textDim, wordBreak: "break-word", lineHeight: 1.6 }}>
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

      {/* Context Menu */}
      {contextMenu && (
        <>
          <div onMouseDown={(e) => { if (e.button === 0) setContextMenu(null); }} onContextMenu={(e) => { e.preventDefault(); }} style={{ position: "fixed", inset: 0, zIndex: 299 }} />
          <div style={{ position: "fixed", left: contextMenu.x, top: contextMenu.y, background: th.modalBg, border: `1px solid ${th.modalBorder}`, borderRadius: 6, padding: "4px 0", zIndex: 300, boxShadow: "0 8px 24px rgba(0,0,0,0.4)", minWidth: 180 }}>
            {[
              { label: (ct?.pinnedColumns || []).includes(contextMenu.colName) ? "Unpin Column" : "Pin Column", icon: "📌",
                action: () => (ct?.pinnedColumns || []).includes(contextMenu.colName) ? unpinColumn(contextMenu.colName) : pinColumn(contextMenu.colName) },
              { label: "Hide Column", icon: "👁", action: () => up("hiddenColumns", new Set([...(ct?.hiddenColumns || []), contextMenu.colName])) },
              null,
              { label: (ct?.groupByColumns || []).includes(contextMenu.colName) ? "Remove Grouping" : "Group by this Column", icon: "▤",
                action: () => (ct?.groupByColumns || []).includes(contextMenu.colName) ? removeGroupBy(contextMenu.colName) : addGroupBy(contextMenu.colName) },
              null,
              { label: "Best Fit", icon: "↔", action: () => autoFitColumn(contextMenu.colName) },
              { label: "Best Fit (All Columns)", icon: "⇔", action: () => autoFitAllColumns() },
              null,
              { label: "Sort Ascending", icon: "▲", action: () => { up("sortCol", contextMenu.colName); up("sortDir", "asc"); } },
              { label: "Sort Descending", icon: "▼", action: () => { up("sortCol", contextMenu.colName); up("sortDir", "desc"); } },
              null,
              { label: "Stack Values", icon: "≡", action: () => {
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
              { label: "Column Stats", icon: "📊", action: () => {
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
                <div key={i} style={{ height: 1, background: th.border, margin: "4px 0" }} />
              ) : (
                <button key={i} onClick={() => { item.action(); setContextMenu(null); }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = th.btnBg; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "6px 12px", background: "none", border: "none", color: th.text, fontSize: 12, cursor: "pointer", textAlign: "left", fontFamily: "-apple-system, sans-serif" }}>
                  <span style={{ width: 16, textAlign: "center" }}>{item.icon}</span>
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

